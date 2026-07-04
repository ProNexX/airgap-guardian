pub mod html;
pub mod json;
pub mod terminal;

use crate::models::{CertificateInfo, CertificateStatus};

pub(crate) fn has_issues(cert: &CertificateInfo) -> bool {
    !cert.findings.is_empty() || cert.status != CertificateStatus::Ok
}

pub(crate) fn expiration_note(cert: &CertificateInfo) -> Option<String> {
    match cert.status {
        CertificateStatus::Ok => None,
        CertificateStatus::Expired => Some(format!("Expired {} days ago", -cert.days_remaining)),
        CertificateStatus::Warning | CertificateStatus::Critical => {
            Some(format!("Expires in {} days", cert.days_remaining))
        }
    }
}
