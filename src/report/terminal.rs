use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

use crate::models::{AssetInfo, CertificateInfo, CertificateStatus, FindingSeverity, ScanResult};
use crate::report::{expiration_note, has_issues};

pub fn print(result: &ScanResult) {
    if result.certificates.is_empty() {
        println!("No certificates found.");
    } else {
        println!("{}", build_table(&result.certificates));
    }
    print_findings(result);
    print_assets(result);
    print_errors(result);
    print_summary(result);
}

fn build_table(certificates: &[CertificateInfo]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["File", "Status", "Risk", "Remaining", "Expires"]);
    for cert in certificates {
        table.add_row(vec![
            Cell::new(&cert.path),
            status_cell(cert.status),
            Cell::new(cert.risk_score),
            Cell::new(format!("{} days", cert.days_remaining)),
            Cell::new(cert.not_after.format("%Y-%m-%d")),
        ]);
    }
    table
}

fn print_findings(result: &ScanResult) {
    for cert in result.certificates.iter().filter(|c| has_issues(c)) {
        println!();
        println!("{}", cert.path.bold());
        println!("  Status: {}", cert.status);
        println!("  Risk: {}", cert.risk_score);
        println!("  Findings:");
        for finding in &cert.findings {
            println!(
                "    - [{}] {}",
                severity_label(finding.severity),
                finding.message
            );
        }
        if let Some(note) = expiration_note(cert) {
            println!("    - {note}");
        }
    }
}

fn print_assets(result: &ScanResult) {
    if result.assets.is_empty() {
        return;
    }
    println!();
    println!("{}", build_asset_table(&result.assets));
    for asset in result.assets.iter().filter(|a| !a.findings.is_empty()) {
        println!();
        println!("{} ({})", asset.path.bold(), asset.asset_type);
        println!("  Asset: {}", asset.description);
        println!("  Risk: {}", asset.risk_score);
        println!("  Findings:");
        for finding in &asset.findings {
            println!(
                "    - [{}] {}",
                severity_label(finding.severity),
                finding.message
            );
        }
    }
}

fn build_asset_table(assets: &[AssetInfo]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["File", "Type", "Asset", "Risk", "Findings"]);
    for asset in assets {
        table.add_row(vec![
            Cell::new(&asset.path),
            Cell::new(asset.asset_type),
            Cell::new(&asset.description),
            Cell::new(asset.risk_score),
            Cell::new(asset.findings.len()),
        ]);
    }
    table
}

fn severity_label(severity: FindingSeverity) -> String {
    match severity {
        FindingSeverity::Info => severity.cyan().to_string(),
        FindingSeverity::Warning => severity.yellow().to_string(),
        FindingSeverity::Critical => severity.red().to_string(),
    }
}

// comfy-table (crossterm) naming: `DarkRed` is standard red, `Red` is bright red.
fn status_cell(status: CertificateStatus) -> Cell {
    let color = match status {
        CertificateStatus::Ok => Color::DarkGreen,
        CertificateStatus::Warning => Color::DarkYellow,
        CertificateStatus::Critical => Color::DarkRed,
        CertificateStatus::Expired => Color::Red,
    };
    Cell::new(status).fg(color)
}

fn print_errors(result: &ScanResult) {
    if result.errors.is_empty() {
        return;
    }
    println!();
    println!("Parse errors:");
    for failure in &result.errors {
        println!("  {}: {}", failure.path.bright_red(), failure.error);
    }
}

fn print_summary(result: &ScanResult) {
    let s = &result.summary;
    println!();
    println!("Certificates scanned: {}", s.total);
    println!("OK: {}", s.ok);
    println!("Warning: {}", s.warning);
    println!("Critical: {}", s.critical);
    println!("Expired: {}", s.expired);
    println!("Assets discovered: {}", s.assets);
    println!("Asset warnings: {}", s.asset_warning);
    println!("Asset critical: {}", s.asset_critical);
    println!("Parse errors: {}", s.parse_errors);
}
