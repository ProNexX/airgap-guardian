use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;

pub const WARNING_THRESHOLD_DAYS: i64 = 30;
pub const CRITICAL_THRESHOLD_DAYS: i64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CertificateStatus {
    #[serde(rename = "OK")]
    Ok,
    Warning,
    Critical,
    Expired,
}

impl CertificateStatus {
    pub fn evaluate(not_after: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        Self::with_thresholds(
            not_after,
            now,
            WARNING_THRESHOLD_DAYS,
            CRITICAL_THRESHOLD_DAYS,
        )
    }

    pub fn with_thresholds(
        not_after: DateTime<Utc>,
        now: DateTime<Utc>,
        warning_days: i64,
        critical_days: i64,
    ) -> Self {
        if not_after < now {
            return Self::Expired;
        }
        match days_remaining(not_after, now) {
            d if d <= critical_days => Self::Critical,
            d if d <= warning_days => Self::Warning,
            _ => Self::Ok,
        }
    }
}

impl fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Ok => "OK",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
            Self::Expired => "Expired",
        };
        f.write_str(label)
    }
}

pub fn days_remaining(not_after: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    (not_after - now).num_days()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FindingSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub rule: String,
    pub message: String,
}

impl Finding {
    pub fn new(severity: FindingSeverity, rule: &str, message: impl Into<String>) -> Self {
        Self {
            severity,
            rule: rule.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RiskScore(u8);

impl RiskScore {
    pub const MAX: u8 = 100;

    pub fn from_points(points: u32) -> Self {
        Self(points.min(u32::from(Self::MAX)) as u8)
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for RiskScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Cert,
    Ssh,
    Secret,
    Jwt,
}

impl fmt::Display for AssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Cert => "cert",
            Self::Ssh => "ssh",
            Self::Secret => "secret",
            Self::Jwt => "jwt",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SshPublicKeyEntry {
    pub line: usize,
    pub algorithm: String,
    pub key_bits: Option<usize>,
    pub comment: Option<String>,
    pub duplicate_of_line: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssetDetails {
    SshPrivateKey {
        algorithm: String,
        key_bits: Option<usize>,
        encrypted: bool,
    },
    SshAuthorizedKeys {
        keys: Vec<SshPublicKeyEntry>,
    },
    SshKnownHosts {
        entries: usize,
    },
    Secret {
        rule: String,
        line: usize,
        preview: String,
    },
    Jwt {
        algorithm: String,
        expires_at: Option<DateTime<Utc>>,
        issuer: Option<String>,
        audience: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetInfo {
    pub asset_type: AssetType,
    pub path: String,
    pub description: String,
    pub details: AssetDetails,
    pub risk_score: RiskScore,
    pub findings: Vec<Finding>,
}

impl AssetInfo {
    pub fn worst_severity(&self) -> Option<FindingSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub asset_type: AssetType,
    pub path: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_remaining: i64,
    pub status: CertificateStatus,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub key_size: Option<usize>,
    pub is_ca: bool,
    pub has_san: bool,
    pub risk_score: RiskScore,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParseFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub total: usize,
    pub ok: usize,
    pub warning: usize,
    pub critical: usize,
    pub expired: usize,
    pub parse_errors: usize,
    pub assets: usize,
    pub asset_warning: usize,
    pub asset_critical: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub certificates: Vec<CertificateInfo>,
    pub assets: Vec<AssetInfo>,
    pub errors: Vec<ParseFailure>,
}

impl ScanResult {
    pub fn new(
        certificates: Vec<CertificateInfo>,
        assets: Vec<AssetInfo>,
        errors: Vec<ParseFailure>,
    ) -> Self {
        let summary = summarize(&certificates, &assets, errors.len());
        Self {
            summary,
            certificates,
            assets,
            errors,
        }
    }

    pub fn recompute_summary(&mut self) {
        self.summary = summarize(&self.certificates, &self.assets, self.errors.len());
    }
}

fn summarize(
    certificates: &[CertificateInfo],
    assets: &[AssetInfo],
    parse_errors: usize,
) -> ScanSummary {
    let count = |status| certificates.iter().filter(|c| c.status == status).count();
    let count_worst = |severity| {
        assets
            .iter()
            .filter(|a| a.worst_severity() == Some(severity))
            .count()
    };
    ScanSummary {
        total: certificates.len(),
        ok: count(CertificateStatus::Ok),
        warning: count(CertificateStatus::Warning),
        critical: count(CertificateStatus::Critical),
        expired: count(CertificateStatus::Expired),
        parse_errors,
        assets: assets.len(),
        asset_warning: count_worst(FindingSeverity::Warning),
        asset_critical: count_worst(FindingSeverity::Critical),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn days_remaining_in_future() {
        let now = now();
        assert_eq!(days_remaining(now + Duration::days(182), now), 182);
    }

    #[test]
    fn days_remaining_in_past_is_negative() {
        let now = now();
        assert_eq!(days_remaining(now - Duration::days(5), now), -5);
    }

    #[test]
    fn status_expired_when_not_after_in_past() {
        let now = now();
        let status = CertificateStatus::evaluate(now - Duration::seconds(1), now);
        assert_eq!(status, CertificateStatus::Expired);
    }

    #[test]
    fn status_critical_at_threshold() {
        let now = now();
        let status =
            CertificateStatus::evaluate(now + Duration::days(CRITICAL_THRESHOLD_DAYS), now);
        assert_eq!(status, CertificateStatus::Critical);
    }

    #[test]
    fn status_warning_between_thresholds() {
        let now = now();
        let status = CertificateStatus::evaluate(now + Duration::days(14), now);
        assert_eq!(status, CertificateStatus::Warning);

        let status = CertificateStatus::evaluate(now + Duration::days(WARNING_THRESHOLD_DAYS), now);
        assert_eq!(status, CertificateStatus::Warning);
    }

    #[test]
    fn status_ok_beyond_warning_threshold() {
        let now = now();
        let status =
            CertificateStatus::evaluate(now + Duration::days(WARNING_THRESHOLD_DAYS + 1), now);
        assert_eq!(status, CertificateStatus::Ok);
    }

    #[test]
    fn risk_score_is_capped_at_100() {
        assert_eq!(RiskScore::from_points(45).value(), 45);
        assert_eq!(RiskScore::from_points(100).value(), 100);
        assert_eq!(RiskScore::from_points(180).value(), 100);
    }

    #[test]
    fn summary_counts_by_status() {
        let now = now();
        let cert = |status, not_after: DateTime<Utc>| CertificateInfo {
            asset_type: AssetType::Cert,
            path: "test.pem".into(),
            subject: "CN=test".into(),
            issuer: "CN=test".into(),
            serial_number: "01".into(),
            not_before: now,
            not_after,
            days_remaining: days_remaining(not_after, now),
            status,
            signature_algorithm: "sha256WithRSAEncryption".into(),
            public_key_algorithm: "rsaEncryption".into(),
            key_size: Some(2048),
            is_ca: false,
            has_san: true,
            risk_score: RiskScore::default(),
            findings: Vec::new(),
        };
        let certificates = vec![
            cert(CertificateStatus::Ok, now + Duration::days(100)),
            cert(CertificateStatus::Warning, now + Duration::days(14)),
            cert(CertificateStatus::Expired, now - Duration::days(5)),
        ];
        let errors = vec![ParseFailure {
            path: "bad.pem".into(),
            error: "invalid".into(),
        }];

        let result = ScanResult::new(certificates, Vec::new(), errors);
        assert_eq!(result.summary.total, 3);
        assert_eq!(result.summary.ok, 1);
        assert_eq!(result.summary.warning, 1);
        assert_eq!(result.summary.critical, 0);
        assert_eq!(result.summary.expired, 1);
        assert_eq!(result.summary.parse_errors, 1);
        assert_eq!(result.summary.assets, 0);
    }

    #[test]
    fn summary_counts_assets_by_worst_severity() {
        let asset = |findings: Vec<Finding>| AssetInfo {
            asset_type: AssetType::Secret,
            path: "config.env".into(),
            description: "AWS access key".into(),
            details: AssetDetails::Secret {
                rule: "aws_access_key".into(),
                line: 1,
                preview: "AKIA****".into(),
            },
            risk_score: RiskScore::default(),
            findings,
        };
        let assets = vec![
            asset(Vec::new()),
            asset(vec![Finding::new(FindingSeverity::Warning, "r", "w")]),
            asset(vec![
                Finding::new(FindingSeverity::Warning, "r", "w"),
                Finding::new(FindingSeverity::Critical, "r", "c"),
            ]),
        ];

        let result = ScanResult::new(Vec::new(), assets, Vec::new());
        assert_eq!(result.summary.assets, 3);
        assert_eq!(result.summary.asset_warning, 1);
        assert_eq!(result.summary.asset_critical, 1);
    }
}
