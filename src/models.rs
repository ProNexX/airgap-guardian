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
        if not_after < now {
            return Self::Expired;
        }
        match days_remaining(not_after, now) {
            d if d <= CRITICAL_THRESHOLD_DAYS => Self::Critical,
            d if d <= WARNING_THRESHOLD_DAYS => Self::Warning,
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

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
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
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub certificates: Vec<CertificateInfo>,
    pub errors: Vec<ParseFailure>,
}

impl ScanResult {
    pub fn new(certificates: Vec<CertificateInfo>, errors: Vec<ParseFailure>) -> Self {
        let count = |status| certificates.iter().filter(|c| c.status == status).count();
        let summary = ScanSummary {
            total: certificates.len(),
            ok: count(CertificateStatus::Ok),
            warning: count(CertificateStatus::Warning),
            critical: count(CertificateStatus::Critical),
            expired: count(CertificateStatus::Expired),
            parse_errors: errors.len(),
        };
        Self {
            summary,
            certificates,
            errors,
        }
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
    fn summary_counts_by_status() {
        let now = now();
        let cert = |status, not_after: DateTime<Utc>| CertificateInfo {
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

        let result = ScanResult::new(certificates, errors);
        assert_eq!(result.summary.total, 3);
        assert_eq!(result.summary.ok, 1);
        assert_eq!(result.summary.warning, 1);
        assert_eq!(result.summary.critical, 0);
        assert_eq!(result.summary.expired, 1);
        assert_eq!(result.summary.parse_errors, 1);
    }
}
