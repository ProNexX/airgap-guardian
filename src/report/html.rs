use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::models::{AssetInfo, CertificateInfo, CertificateStatus, FindingSeverity, ScanResult};
use crate::policy::Policy;
use crate::report::{expiration_note, has_issues};

pub fn write(result: &ScanResult, policy: &Policy, path: &Path) -> Result<()> {
    let html = render(result, policy, Utc::now());
    fs::write(path, html).with_context(|| format!("cannot write HTML report to {}", path.display()))
}

pub fn render(result: &ScanResult, policy: &Policy, generated_at: DateTime<Utc>) -> String {
    let mut body = String::new();
    push_header(&mut body, generated_at);
    push_summary_cards(&mut body, result);
    push_policy(&mut body, policy);
    push_certificate_table(&mut body, result);
    push_findings(&mut body, result);
    push_asset_table(&mut body, result);
    push_asset_findings(&mut body, result);
    push_errors(&mut body, result);
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Airgap Guardian Report</title>\n<style>{STYLE}</style>\n</head>\n\
         <body>\n<main>\n{body}</main>\n</body>\n</html>\n"
    )
}

fn push_header(out: &mut String, generated_at: DateTime<Utc>) {
    let _ = writeln!(
        out,
        "<header><h1>Airgap Guardian</h1>\
         <p class=\"subtitle\">Offline certificate security report &middot; \
         generated {}</p></header>",
        generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn push_summary_cards(out: &mut String, result: &ScanResult) {
    let s = &result.summary;
    let cards = [
        ("Certificates", s.total, "total"),
        ("OK", s.ok, "ok"),
        ("Warning", s.warning, "warning"),
        ("Critical", s.critical, "critical"),
        ("Expired", s.expired, "expired"),
        ("Assets", s.assets, "total"),
        ("Asset warnings", s.asset_warning, "warning"),
        ("Asset critical", s.asset_critical, "critical"),
        ("Parse errors", s.parse_errors, "error"),
    ];
    out.push_str("<section class=\"cards\">\n");
    for (label, count, class) in cards {
        let _ = writeln!(
            out,
            "<div class=\"card card-{class}\"><span class=\"card-value\">{count}</span>\
             <span class=\"card-label\">{label}</span></div>"
        );
    }
    out.push_str("</section>\n");
}

fn push_policy(out: &mut String, policy: &Policy) {
    let yes_no = |flag: bool| if flag { "yes" } else { "no" };
    let algorithms = policy
        .allowed_signature_algorithms
        .iter()
        .map(|a| format!("<code>{}</code>", escape(a)))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = [
        ("Warning threshold", format!("{} days", policy.warning_days)),
        (
            "Critical threshold",
            format!("{} days", policy.critical_days),
        ),
        (
            "Minimum RSA key size",
            format!("{} bits", policy.min_rsa_key_size),
        ),
        (
            "Maximum certificate lifetime",
            format!("{} days", policy.max_certificate_lifetime_days),
        ),
        (
            "Allow self-signed",
            yes_no(policy.allow_self_signed).to_string(),
        ),
        (
            "Require Subject Alternative Name",
            yes_no(policy.required_subject_alternative_name).to_string(),
        ),
        ("Allowed signature algorithms", algorithms),
    ];
    out.push_str("<section><h2>Scan Policy</h2>\n<div class=\"table-wrap\"><table class=\"policy\">\n<tbody>\n");
    for (label, value) in rows {
        let _ = writeln!(out, "<tr><th>{label}</th><td>{value}</td></tr>");
    }
    out.push_str("</tbody>\n</table></div></section>\n");
}

fn push_certificate_table(out: &mut String, result: &ScanResult) {
    if result.certificates.is_empty() {
        out.push_str("<p class=\"empty\">No certificates found.</p>\n");
        return;
    }
    out.push_str(
        "<section><h2>Certificates</h2>\n<div class=\"table-wrap\"><table>\n\
         <thead><tr><th>File</th><th>Status</th><th>Risk</th>\
         <th>Remaining</th><th>Expires</th><th>Findings</th></tr></thead>\n<tbody>\n",
    );
    for cert in &result.certificates {
        push_certificate_row(out, cert);
    }
    out.push_str("</tbody>\n</table></div></section>\n");
}

fn push_certificate_row(out: &mut String, cert: &CertificateInfo) {
    let row_class = if cert.findings.is_empty() {
        ""
    } else {
        " class=\"flagged\""
    };
    let _ = writeln!(
        out,
        "<tr{row_class}><td>{path}</td>\
         <td><span class=\"badge badge-{status_class}\">{status}</span></td>\
         <td><span class=\"risk risk-{risk_class}\">{risk}</span></td>\
         <td>{remaining} days</td><td>{expires}</td><td>{findings}</td></tr>",
        path = escape(&cert.path),
        status_class = status_class(cert.status),
        status = cert.status,
        risk_class = risk_class(cert.risk_score.value()),
        risk = cert.risk_score,
        remaining = cert.days_remaining,
        expires = cert.not_after.format("%Y-%m-%d"),
        findings = cert.findings.len(),
    );
}

fn push_findings(out: &mut String, result: &ScanResult) {
    let flagged: Vec<&CertificateInfo> = result
        .certificates
        .iter()
        .filter(|c| has_issues(c))
        .collect();
    if flagged.is_empty() {
        return;
    }
    out.push_str("<section><h2>Findings</h2>\n");
    for cert in flagged {
        push_finding_card(out, cert);
    }
    out.push_str("</section>\n");
}

fn push_finding_card(out: &mut String, cert: &CertificateInfo) {
    let _ = write!(
        out,
        "<article class=\"finding-card\"><h3>{path}</h3>\
         <p><span class=\"badge badge-{status_class}\">{status}</span> \
         <span class=\"risk risk-{risk_class}\">Risk {risk}</span></p>\n<ul>\n",
        path = escape(&cert.path),
        status_class = status_class(cert.status),
        status = cert.status,
        risk_class = risk_class(cert.risk_score.value()),
        risk = cert.risk_score,
    );
    for finding in &cert.findings {
        let _ = writeln!(
            out,
            "<li><span class=\"badge badge-{class}\">{severity}</span> {message}</li>",
            class = severity_class(finding.severity),
            severity = finding.severity,
            message = escape(&finding.message),
        );
    }
    if let Some(note) = expiration_note(cert) {
        let _ = writeln!(
            out,
            "<li><span class=\"badge badge-{class}\">{status}</span> {note}</li>",
            class = status_class(cert.status),
            status = cert.status,
        );
    }
    out.push_str("</ul></article>\n");
}

fn push_asset_table(out: &mut String, result: &ScanResult) {
    if result.assets.is_empty() {
        return;
    }
    out.push_str(
        "<section><h2>Assets</h2>\n<div class=\"table-wrap\"><table>\n\
         <thead><tr><th>File</th><th>Type</th><th>Asset</th>\
         <th>Risk</th><th>Findings</th></tr></thead>\n<tbody>\n",
    );
    for asset in &result.assets {
        let row_class = if asset.findings.is_empty() {
            ""
        } else {
            " class=\"flagged\""
        };
        let _ = writeln!(
            out,
            "<tr{row_class}><td>{path}</td><td>{asset_type}</td><td>{description}</td>\
             <td><span class=\"risk risk-{risk_class}\">{risk}</span></td><td>{findings}</td></tr>",
            path = escape(&asset.path),
            asset_type = asset.asset_type,
            description = escape(&asset.description),
            risk_class = risk_class(asset.risk_score.value()),
            risk = asset.risk_score,
            findings = asset.findings.len(),
        );
    }
    out.push_str("</tbody>\n</table></div></section>\n");
}

fn push_asset_findings(out: &mut String, result: &ScanResult) {
    let flagged: Vec<&AssetInfo> = result
        .assets
        .iter()
        .filter(|a| !a.findings.is_empty())
        .collect();
    if flagged.is_empty() {
        return;
    }
    out.push_str("<section><h2>Asset Findings</h2>\n");
    for asset in flagged {
        let _ = write!(
            out,
            "<article class=\"finding-card\"><h3>{path}</h3>\
             <p>{description} \
             <span class=\"risk risk-{risk_class}\">Risk {risk}</span></p>\n<ul>\n",
            path = escape(&asset.path),
            description = escape(&asset.description),
            risk_class = risk_class(asset.risk_score.value()),
            risk = asset.risk_score,
        );
        for finding in &asset.findings {
            let _ = writeln!(
                out,
                "<li><span class=\"badge badge-{class}\">{severity}</span> {message}</li>",
                class = severity_class(finding.severity),
                severity = finding.severity,
                message = escape(&finding.message),
            );
        }
        out.push_str("</ul></article>\n");
    }
    out.push_str("</section>\n");
}

fn push_errors(out: &mut String, result: &ScanResult) {
    if result.errors.is_empty() {
        return;
    }
    out.push_str("<section><h2>Parse errors</h2>\n<ul class=\"errors\">\n");
    for failure in &result.errors {
        let _ = writeln!(
            out,
            "<li><strong>{}</strong>: {}</li>",
            escape(&failure.path),
            escape(&failure.error)
        );
    }
    out.push_str("</ul></section>\n");
}

fn status_class(status: CertificateStatus) -> &'static str {
    match status {
        CertificateStatus::Ok => "ok",
        CertificateStatus::Warning => "warning",
        CertificateStatus::Critical => "critical",
        CertificateStatus::Expired => "expired",
    }
}

fn severity_class(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Critical => "critical",
    }
}

fn risk_class(score: u8) -> &'static str {
    match score {
        0..=19 => "low",
        20..=49 => "medium",
        _ => "high",
    }
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

const STYLE: &str = "\
:root{--bg:#f4f6f9;--surface:#fff;--text:#1c2333;--muted:#5b6577;--border:#e2e6ee;\
--ok:#1a7f4b;--warning:#a86500;--critical:#c22f2f;--expired:#8a1f1f;--info:#1f5fa8;\
--ok-bg:#e3f4ea;--warning-bg:#fcf0dc;--critical-bg:#fbe3e3;--expired-bg:#f3dcdc;--info-bg:#e2edf9}\
*{box-sizing:border-box}\
body{margin:0;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;\
background:var(--bg);color:var(--text);line-height:1.5}\
main{max-width:1100px;margin:0 auto;padding:2rem 1rem}\
header h1{margin:0;font-size:1.8rem}\
.subtitle{margin:.25rem 0 1.5rem;color:var(--muted)}\
h2{font-size:1.2rem;margin:2rem 0 .75rem}\
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem}\
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;\
padding:1rem;display:flex;flex-direction:column;gap:.25rem}\
.card-value{font-size:1.6rem;font-weight:700}\
.card-label{color:var(--muted);font-size:.85rem}\
.card-ok .card-value{color:var(--ok)}\
.card-warning .card-value{color:var(--warning)}\
.card-critical .card-value{color:var(--critical)}\
.card-expired .card-value{color:var(--expired)}\
.card-error .card-value{color:var(--critical)}\
.table-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);\
border-radius:10px}\
table{width:100%;border-collapse:collapse;font-size:.9rem}\
th,td{text-align:left;padding:.6rem .9rem;border-bottom:1px solid var(--border);\
white-space:nowrap}\
td:first-child{white-space:normal;word-break:break-all}\
tbody tr:last-child td{border-bottom:none}\
tr.flagged{background:var(--warning-bg)}\
table.policy th{width:16rem;color:var(--muted);font-weight:600;vertical-align:top}\
table.policy td{white-space:normal}\
code{background:var(--bg);border:1px solid var(--border);border-radius:4px;\
padding:.05rem .35rem;font-size:.85em}\
.badge{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.78rem;\
font-weight:600}\
.badge-ok{background:var(--ok-bg);color:var(--ok)}\
.badge-warning{background:var(--warning-bg);color:var(--warning)}\
.badge-critical{background:var(--critical-bg);color:var(--critical)}\
.badge-expired{background:var(--expired-bg);color:var(--expired)}\
.badge-info{background:var(--info-bg);color:var(--info)}\
.risk{font-weight:700}\
.risk-low{color:var(--ok)}\
.risk-medium{color:var(--warning)}\
.risk-high{color:var(--critical)}\
.finding-card{background:var(--surface);border:1px solid var(--border);\
border-left:4px solid var(--critical);border-radius:10px;padding:1rem 1.25rem;\
margin-bottom:.75rem}\
.finding-card h3{margin:0 0 .5rem;font-size:1rem;word-break:break-all}\
.finding-card ul{margin:.5rem 0 0;padding-left:1.1rem}\
.finding-card li{margin:.3rem 0}\
.errors{background:var(--surface);border:1px solid var(--border);border-radius:10px;\
padding:1rem 1rem 1rem 2rem;margin:0}\
.errors li{margin:.3rem 0;word-break:break-all}\
.empty{color:var(--muted)}\
@media (max-width:600px){main{padding:1rem .75rem}header h1{font-size:1.4rem}}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::models::{AssetDetails, AssetType, ParseFailure, days_remaining};
    use chrono::Duration;

    fn policy() -> Policy {
        Policy::default()
    }

    fn sample_result() -> ScanResult {
        let now = Utc::now();
        let not_after = now + Duration::days(2);
        let mut cert = CertificateInfo {
            asset_type: AssetType::Cert,
            path: "certs/vpn.crt".into(),
            subject: "CN=vpn".into(),
            issuer: "CN=issuer".into(),
            serial_number: "01".into(),
            fingerprint_sha256: "00".repeat(32),
            not_before: now - Duration::days(30),
            not_after,
            days_remaining: days_remaining(not_after, now),
            status: CertificateStatus::evaluate(not_after, now),
            signature_algorithm: "sha1WithRSAEncryption".into(),
            public_key_algorithm: "rsaEncryption".into(),
            key_size: Some(1024),
            is_ca: false,
            has_san: true,
            risk_score: Default::default(),
            findings: Vec::new(),
        };
        cert.findings = analysis::evaluate(&cert, &policy());
        cert.risk_score = analysis::risk_score(cert.status, &cert.findings);
        let mut asset = AssetInfo {
            asset_type: AssetType::Secret,
            path: "config/app.env".into(),
            description: "AWS access key".into(),
            details: AssetDetails::Secret {
                rule: analysis::rules::SECRET_AWS_ACCESS_KEY.into(),
                line: 3,
                preview: "AKIA****MPLE".into(),
            },
            risk_score: Default::default(),
            findings: Vec::new(),
        };
        asset.findings = analysis::evaluate_asset(&asset, &policy(), now);
        asset.risk_score = analysis::asset_risk_score(&asset.findings);
        let errors = vec![ParseFailure {
            path: "certs/bad.pem".into(),
            error: "invalid <PEM>".into(),
        }];
        ScanResult::new(vec![cert], vec![asset], errors)
    }

    #[test]
    fn renders_standalone_report() {
        let html = render(&sample_result(), &policy(), Utc::now());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn report_contains_summary_certificates_and_findings() {
        let html = render(&sample_result(), &policy(), Utc::now());
        assert!(html.contains("certs/vpn.crt"));
        assert!(html.contains("badge-critical"));
        assert!(html.contains(">85<") || html.contains("Risk 85"));
        assert!(html.contains("RSA key is only 1024 bits"));
        assert!(
            html.contains("Signature algorithm sha1WithRSAEncryption is not allowed by policy.")
        );
        assert!(html.contains("class=\"flagged\""));
        assert!(html.contains("Parse errors"));
    }

    #[test]
    fn report_contains_assets_and_asset_findings() {
        let html = render(&sample_result(), &policy(), Utc::now());
        assert!(html.contains("<h2>Assets</h2>"));
        assert!(html.contains("config/app.env"));
        assert!(html.contains("AWS access key"));
        assert!(html.contains("<h2>Asset Findings</h2>"));
        assert!(html.contains("AWS access key detected on line 3."));
    }

    #[test]
    fn report_shows_scan_policy_section() {
        let custom = Policy {
            warning_days: 60,
            min_rsa_key_size: 4096,
            ..Policy::default()
        };
        let html = render(&sample_result(), &custom, Utc::now());
        assert!(html.contains("Scan Policy"));
        assert!(html.contains("60 days"));
        assert!(html.contains("4096 bits"));
        assert!(html.contains("<code>sha256WithRSAEncryption</code>"));
        assert!(html.contains("Require Subject Alternative Name"));
    }

    #[test]
    fn report_includes_generation_timestamp() {
        let generated_at = DateTime::parse_from_rfc3339("2026-07-04T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let html = render(&sample_result(), &policy(), generated_at);
        assert!(html.contains("2026-07-04 10:30:00 UTC"));
    }

    #[test]
    fn escapes_html_in_untrusted_fields() {
        let html = render(&sample_result(), &policy(), Utc::now());
        assert!(html.contains("invalid &lt;PEM&gt;"));
        assert_eq!(escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn write_creates_report_file() {
        let dir = std::env::temp_dir().join("airgap-guardian-html-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.html");
        write(&sample_result(), &policy(), &path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Airgap Guardian"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
