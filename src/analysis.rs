use chrono::Utc;

use crate::models::{
    CertificateInfo, CertificateStatus, Finding, FindingSeverity, RiskScore, ScanResult,
};
use crate::policy::Policy;

pub mod rules {
    pub const WEAK_SIGNATURE: &str = "weak_signature";
    pub const WEAK_RSA: &str = "weak_rsa";
    pub const SELF_SIGNED: &str = "self_signed";
    pub const INVALID_VALIDITY: &str = "invalid_validity";
    pub const LONG_VALIDITY: &str = "long_validity";
    pub const MISSING_SAN: &str = "missing_san";
}

pub fn analyze(result: &mut ScanResult, policy: &Policy) {
    let now = Utc::now();
    for cert in &mut result.certificates {
        cert.status = CertificateStatus::with_thresholds(
            cert.not_after,
            now,
            policy.warning_days,
            policy.critical_days,
        );
        cert.findings = evaluate(cert, policy);
        cert.risk_score = risk_score(cert.status, &cert.findings);
    }
    result.recompute_summary();
}

pub fn evaluate(cert: &CertificateInfo, policy: &Policy) -> Vec<Finding> {
    [
        check_signature_algorithm(cert, policy),
        check_rsa_key(cert, policy),
        check_self_signed(cert, policy),
        check_validity_period(cert),
        check_lifetime(cert, policy),
        check_san(cert, policy),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub fn risk_score(status: CertificateStatus, findings: &[Finding]) -> RiskScore {
    let points = status_points(status) + findings.iter().map(|f| rule_points(&f.rule)).sum::<u32>();
    RiskScore::from_points(points)
}

fn status_points(status: CertificateStatus) -> u32 {
    match status {
        CertificateStatus::Ok => 0,
        CertificateStatus::Warning => 20,
        CertificateStatus::Critical => 40,
        CertificateStatus::Expired => 50,
    }
}

fn rule_points(rule: &str) -> u32 {
    match rule {
        rules::WEAK_SIGNATURE => 20,
        rules::WEAK_RSA => 25,
        rules::SELF_SIGNED => 10,
        rules::INVALID_VALIDITY => 50,
        rules::LONG_VALIDITY => 5,
        rules::MISSING_SAN => 10,
        _ => 0,
    }
}

fn check_signature_algorithm(cert: &CertificateInfo, policy: &Policy) -> Option<Finding> {
    (!policy.allows_signature_algorithm(&cert.signature_algorithm)).then(|| {
        Finding::new(
            FindingSeverity::Warning,
            rules::WEAK_SIGNATURE,
            format!(
                "Signature algorithm {} is not allowed by policy.",
                cert.signature_algorithm
            ),
        )
    })
}

fn check_rsa_key(cert: &CertificateInfo, policy: &Policy) -> Option<Finding> {
    if !cert
        .public_key_algorithm
        .to_ascii_lowercase()
        .contains("rsa")
    {
        return None;
    }
    let bits = cert.key_size?;
    (bits < policy.min_rsa_key_size).then(|| {
        Finding::new(
            FindingSeverity::Critical,
            rules::WEAK_RSA,
            format!(
                "RSA key is only {bits} bits (policy requires at least {}).",
                policy.min_rsa_key_size
            ),
        )
    })
}

fn check_self_signed(cert: &CertificateInfo, policy: &Policy) -> Option<Finding> {
    if policy.allow_self_signed || cert.subject != cert.issuer {
        return None;
    }
    let (severity, message) = if cert.is_ca {
        (FindingSeverity::Info, "Self-signed CA certificate.")
    } else {
        (
            FindingSeverity::Warning,
            "Certificate is self-signed (subject equals issuer).",
        )
    };
    Some(Finding::new(severity, rules::SELF_SIGNED, message))
}

fn check_validity_period(cert: &CertificateInfo) -> Option<Finding> {
    (cert.not_before > cert.not_after).then(|| {
        Finding::new(
            FindingSeverity::Critical,
            rules::INVALID_VALIDITY,
            "Invalid validity period (Not Before is after Not After).",
        )
    })
}

fn check_lifetime(cert: &CertificateInfo, policy: &Policy) -> Option<Finding> {
    let days = (cert.not_after - cert.not_before).num_days();
    (days > policy.max_certificate_lifetime_days).then(|| {
        Finding::new(
            FindingSeverity::Warning,
            rules::LONG_VALIDITY,
            format!(
                "Certificate lifetime of {days} days exceeds {} days.",
                policy.max_certificate_lifetime_days
            ),
        )
    })
}

fn check_san(cert: &CertificateInfo, policy: &Policy) -> Option<Finding> {
    (policy.required_subject_alternative_name && !cert.has_san).then(|| {
        Finding::new(
            FindingSeverity::Warning,
            rules::MISSING_SAN,
            "Certificate has no Subject Alternative Name.",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::days_remaining;
    use chrono::{DateTime, Duration, Utc};

    fn cert(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> CertificateInfo {
        let now = Utc::now();
        CertificateInfo {
            path: "test.pem".into(),
            subject: "CN=test".into(),
            issuer: "CN=issuer".into(),
            serial_number: "01".into(),
            not_before,
            not_after,
            days_remaining: days_remaining(not_after, now),
            status: CertificateStatus::evaluate(not_after, now),
            signature_algorithm: "sha256WithRSAEncryption".into(),
            public_key_algorithm: "rsaEncryption".into(),
            key_size: Some(2048),
            is_ca: false,
            has_san: true,
            risk_score: RiskScore::default(),
            findings: Vec::new(),
        }
    }

    fn healthy_cert() -> CertificateInfo {
        let now = Utc::now();
        cert(now - Duration::days(30), now + Duration::days(300))
    }

    fn rules_of(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    fn default_policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn healthy_certificate_has_no_findings() {
        assert!(evaluate(&healthy_cert(), &default_policy()).is_empty());
    }

    #[test]
    fn detects_weak_rsa_key() {
        let mut cert = healthy_cert();
        cert.key_size = Some(1024);
        let findings = evaluate(&cert, &default_policy());
        assert_eq!(rules_of(&findings), [rules::WEAK_RSA]);
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
        assert!(findings[0].message.contains("1024"));
    }

    #[test]
    fn respects_custom_min_rsa_key_size() {
        let policy = Policy {
            min_rsa_key_size: 4096,
            ..default_policy()
        };
        let findings = evaluate(&healthy_cert(), &policy);
        assert_eq!(rules_of(&findings), [rules::WEAK_RSA]);
        assert!(findings[0].message.contains("4096"));
    }

    #[test]
    fn accepts_rsa_2048_and_ignores_non_rsa_keys() {
        assert!(evaluate(&healthy_cert(), &default_policy()).is_empty());

        let mut cert = healthy_cert();
        cert.public_key_algorithm = "id-ecPublicKey".into();
        cert.key_size = Some(256);
        assert!(evaluate(&cert, &default_policy()).is_empty());
    }

    #[test]
    fn flags_signature_algorithms_outside_allowed_list() {
        for algorithm in ["sha1WithRSAEncryption", "md5WithRSAEncryption", "RSA-SHA1"] {
            let mut cert = healthy_cert();
            cert.signature_algorithm = algorithm.into();
            let findings = evaluate(&cert, &default_policy());
            assert_eq!(rules_of(&findings), [rules::WEAK_SIGNATURE], "{algorithm}");
            assert_eq!(findings[0].severity, FindingSeverity::Warning);
        }
    }

    #[test]
    fn custom_allowed_signature_algorithms_are_enforced() {
        let policy = Policy {
            allowed_signature_algorithms: vec!["ecdsa-with-SHA256".into()],
            ..default_policy()
        };
        let findings = evaluate(&healthy_cert(), &policy);
        assert_eq!(rules_of(&findings), [rules::WEAK_SIGNATURE]);

        let mut cert = healthy_cert();
        cert.signature_algorithm = "ecdsa-with-SHA256".into();
        assert!(evaluate(&cert, &policy).is_empty());
    }

    #[test]
    fn detects_self_signed_certificate() {
        let mut cert = healthy_cert();
        cert.issuer = cert.subject.clone();
        let findings = evaluate(&cert, &default_policy());
        assert_eq!(rules_of(&findings), [rules::SELF_SIGNED]);
        assert_eq!(findings[0].severity, FindingSeverity::Warning);
    }

    #[test]
    fn self_signed_ca_is_informational() {
        let mut cert = healthy_cert();
        cert.issuer = cert.subject.clone();
        cert.is_ca = true;
        let findings = evaluate(&cert, &default_policy());
        assert_eq!(rules_of(&findings), [rules::SELF_SIGNED]);
        assert_eq!(findings[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn policy_can_allow_self_signed_certificates() {
        let policy = Policy {
            allow_self_signed: true,
            ..default_policy()
        };
        let mut cert = healthy_cert();
        cert.issuer = cert.subject.clone();
        assert!(evaluate(&cert, &policy).is_empty());
    }

    #[test]
    fn detects_invalid_validity_period() {
        let now = Utc::now();
        let cert = cert(now + Duration::days(365), now + Duration::days(200));
        let findings = evaluate(&cert, &default_policy());
        assert!(rules_of(&findings).contains(&rules::INVALID_VALIDITY));
        let invalid = findings
            .iter()
            .find(|f| f.rule == rules::INVALID_VALIDITY)
            .unwrap();
        assert_eq!(invalid.severity, FindingSeverity::Critical);
    }

    #[test]
    fn detects_long_lifetime() {
        let now = Utc::now();
        let policy = default_policy();
        let max_days = policy.max_certificate_lifetime_days;
        let cert = cert(now - Duration::days(1), now + Duration::days(max_days));
        let findings = evaluate(&cert, &policy);
        assert_eq!(rules_of(&findings), [rules::LONG_VALIDITY]);
        assert_eq!(findings[0].severity, FindingSeverity::Warning);

        let at_limit = self::cert(now, now + Duration::days(max_days));
        assert!(evaluate(&at_limit, &policy).is_empty());
    }

    #[test]
    fn respects_custom_max_lifetime() {
        let policy = Policy {
            max_certificate_lifetime_days: 90,
            ..default_policy()
        };
        let findings = evaluate(&healthy_cert(), &policy);
        assert_eq!(rules_of(&findings), [rules::LONG_VALIDITY]);
        assert!(findings[0].message.contains("90"));
    }

    #[test]
    fn detects_missing_san() {
        let mut cert = healthy_cert();
        cert.has_san = false;
        let findings = evaluate(&cert, &default_policy());
        assert_eq!(rules_of(&findings), [rules::MISSING_SAN]);
        assert_eq!(findings[0].severity, FindingSeverity::Warning);
    }

    #[test]
    fn policy_can_make_san_optional() {
        let policy = Policy {
            required_subject_alternative_name: false,
            ..default_policy()
        };
        let mut cert = healthy_cert();
        cert.has_san = false;
        assert!(evaluate(&cert, &policy).is_empty());
    }

    #[test]
    fn risk_score_adds_status_and_finding_points() {
        let findings = vec![
            Finding::new(FindingSeverity::Critical, rules::WEAK_RSA, "weak"),
            Finding::new(FindingSeverity::Warning, rules::WEAK_SIGNATURE, "sha1"),
        ];
        assert_eq!(
            risk_score(CertificateStatus::Critical, &findings).value(),
            85
        );
        assert_eq!(risk_score(CertificateStatus::Ok, &[]).value(), 0);
        assert_eq!(risk_score(CertificateStatus::Warning, &[]).value(), 20);
        assert_eq!(risk_score(CertificateStatus::Expired, &[]).value(), 50);
    }

    #[test]
    fn risk_score_is_capped() {
        let findings = vec![
            Finding::new(FindingSeverity::Critical, rules::WEAK_RSA, ""),
            Finding::new(FindingSeverity::Warning, rules::WEAK_SIGNATURE, ""),
            Finding::new(FindingSeverity::Critical, rules::INVALID_VALIDITY, ""),
        ];
        assert_eq!(
            risk_score(CertificateStatus::Expired, &findings).value(),
            RiskScore::MAX
        );
    }

    #[test]
    fn analyze_populates_findings_and_risk_score() {
        let mut weak = healthy_cert();
        weak.key_size = Some(1024);
        let mut result = ScanResult::new(vec![healthy_cert(), weak], Vec::new());

        analyze(&mut result, &default_policy());

        assert!(result.certificates[0].findings.is_empty());
        assert_eq!(result.certificates[0].risk_score.value(), 0);
        assert_eq!(
            rules_of(&result.certificates[1].findings),
            [rules::WEAK_RSA]
        );
        assert_eq!(result.certificates[1].risk_score.value(), 25);
    }

    #[test]
    fn analyze_applies_custom_expiration_thresholds() {
        let now = Utc::now();
        let cert = cert(now - Duration::days(10), now + Duration::days(60));
        let mut result = ScanResult::new(vec![cert], Vec::new());

        let policy = Policy {
            warning_days: 90,
            critical_days: 75,
            ..default_policy()
        };
        analyze(&mut result, &policy);

        assert_eq!(result.certificates[0].status, CertificateStatus::Critical);
        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.ok, 0);
    }
}
