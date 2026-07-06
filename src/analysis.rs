use chrono::{DateTime, Duration, Utc};

use crate::models::{
    AssetDetails, AssetInfo, CertificateInfo, CertificateStatus, Finding, FindingSeverity,
    RiskScore, ScanResult, SshPublicKeyEntry,
};
use crate::policy::Policy;

pub mod rules {
    pub const WEAK_SIGNATURE: &str = "weak_signature";
    pub const WEAK_RSA: &str = "weak_rsa";
    pub const SELF_SIGNED: &str = "self_signed";
    pub const INVALID_VALIDITY: &str = "invalid_validity";
    pub const LONG_VALIDITY: &str = "long_validity";
    pub const MISSING_SAN: &str = "missing_san";
    pub const SSH_WEAK_RSA: &str = "ssh_weak_rsa";
    pub const SSH_UNENCRYPTED_KEY: &str = "ssh_unencrypted_key";
    pub const SSH_WEAK_ALGORITHM: &str = "ssh_weak_algorithm";
    pub const SSH_DUPLICATE_KEY: &str = "ssh_duplicate_key";
    pub const SECRET_AWS_ACCESS_KEY: &str = "aws_access_key";
    pub const SECRET_GITHUB_TOKEN: &str = "github_token";
    pub const SECRET_PRIVATE_KEY: &str = "private_key";
    pub const SECRET_GENERIC_API_KEY: &str = "generic_api_key";
    pub const SECRET_JWT_TOKEN: &str = "jwt_token";
    pub const JWT_ALG_NONE: &str = "jwt_alg_none";
    pub const JWT_EXPIRED: &str = "jwt_expired";
    pub const JWT_LONG_LIVED: &str = "jwt_long_lived";
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
    for asset in &mut result.assets {
        let findings = evaluate_asset(asset, policy, now);
        asset.risk_score = asset_risk_score(&findings);
        asset.findings = findings;
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
        rules::SSH_WEAK_RSA => 25,
        rules::SSH_UNENCRYPTED_KEY => 30,
        rules::SSH_WEAK_ALGORITHM => 15,
        rules::SSH_DUPLICATE_KEY => 10,
        rules::SECRET_AWS_ACCESS_KEY | rules::SECRET_GENERIC_API_KEY => 40,
        rules::SECRET_PRIVATE_KEY => 50,
        rules::SECRET_GITHUB_TOKEN | rules::SECRET_JWT_TOKEN => 30,
        rules::JWT_ALG_NONE => 60,
        rules::JWT_EXPIRED => 30,
        rules::JWT_LONG_LIVED => 15,
        _ => 0,
    }
}

pub fn asset_risk_score(findings: &[Finding]) -> RiskScore {
    RiskScore::from_points(findings.iter().map(|f| rule_points(&f.rule)).sum())
}

pub fn evaluate_asset(asset: &AssetInfo, policy: &Policy, now: DateTime<Utc>) -> Vec<Finding> {
    match &asset.details {
        AssetDetails::SshPrivateKey {
            algorithm,
            key_bits,
            encrypted,
            ..
        } => ssh_private_key_findings(algorithm, *key_bits, *encrypted, policy),
        AssetDetails::SshAuthorizedKeys { keys } => authorized_keys_findings(keys, policy),
        AssetDetails::SshKnownHosts { .. } => Vec::new(),
        AssetDetails::Secret { rule, line, .. } => vec![Finding::new(
            secret_severity(rule),
            rule,
            format!("{} detected on line {line}.", asset.description),
        )],
        AssetDetails::Jwt {
            algorithm,
            expires_at,
            ..
        } => jwt_findings(algorithm, *expires_at, policy, now),
    }
}

fn ssh_private_key_findings(
    algorithm: &str,
    key_bits: Option<usize>,
    encrypted: bool,
    policy: &Policy,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if algorithm.eq_ignore_ascii_case("rsa")
        && let Some(bits) = key_bits
        && bits < policy.min_rsa_key_size
    {
        findings.push(Finding::new(
            FindingSeverity::Critical,
            rules::SSH_WEAK_RSA,
            format!(
                "RSA key is only {bits} bits (policy requires at least {}).",
                policy.min_rsa_key_size
            ),
        ));
    }
    if !encrypted {
        findings.push(Finding::new(
            FindingSeverity::Warning,
            rules::SSH_UNENCRYPTED_KEY,
            "Private key is not protected by a passphrase.",
        ));
    }
    findings
}

fn authorized_keys_findings(keys: &[SshPublicKeyEntry], policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();
    for key in keys {
        if matches!(key.algorithm.as_str(), "ssh-rsa" | "ssh-dss") {
            findings.push(Finding::new(
                FindingSeverity::Warning,
                rules::SSH_WEAK_ALGORITHM,
                format!(
                    "Key on line {} uses weak algorithm {}.",
                    key.line, key.algorithm
                ),
            ));
        }
        if key.algorithm == "ssh-rsa"
            && let Some(bits) = key.key_bits
            && bits < policy.min_rsa_key_size
        {
            findings.push(Finding::new(
                FindingSeverity::Critical,
                rules::SSH_WEAK_RSA,
                format!(
                    "RSA key on line {} is only {bits} bits (policy requires at least {}).",
                    key.line, policy.min_rsa_key_size
                ),
            ));
        }
        if let Some(original) = key.duplicate_of_line {
            findings.push(Finding::new(
                FindingSeverity::Warning,
                rules::SSH_DUPLICATE_KEY,
                format!("Key on line {} duplicates line {original}.", key.line),
            ));
        }
    }
    findings
}

fn secret_severity(rule: &str) -> FindingSeverity {
    match rule {
        rules::SECRET_AWS_ACCESS_KEY | rules::SECRET_GITHUB_TOKEN | rules::SECRET_PRIVATE_KEY => {
            FindingSeverity::Critical
        }
        _ => FindingSeverity::Warning,
    }
}

fn jwt_findings(
    algorithm: &str,
    expires_at: Option<DateTime<Utc>>,
    policy: &Policy,
    now: DateTime<Utc>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if algorithm.eq_ignore_ascii_case("none") {
        findings.push(Finding::new(
            FindingSeverity::Critical,
            rules::JWT_ALG_NONE,
            "Token uses the \"none\" algorithm (no signature).",
        ));
    }
    if let Some(expires_at) = expires_at {
        if expires_at < now {
            findings.push(Finding::new(
                FindingSeverity::Warning,
                rules::JWT_EXPIRED,
                format!("Token expired {} days ago.", (now - expires_at).num_days()),
            ));
        } else if expires_at > now + Duration::days(policy.max_certificate_lifetime_days) {
            findings.push(Finding::new(
                FindingSeverity::Warning,
                rules::JWT_LONG_LIVED,
                format!(
                    "Token is valid for {} more days (policy allows {}).",
                    (expires_at - now).num_days(),
                    policy.max_certificate_lifetime_days
                ),
            ));
        }
    }
    findings
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
    use crate::models::{AssetType, days_remaining};
    use chrono::{DateTime, Duration, Utc};

    fn cert(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> CertificateInfo {
        let now = Utc::now();
        CertificateInfo {
            asset_type: AssetType::Cert,
            path: "test.pem".into(),
            subject: "CN=test".into(),
            issuer: "CN=issuer".into(),
            serial_number: "01".into(),
            fingerprint_sha256: "00".repeat(32),
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
        let mut result = ScanResult::new(vec![healthy_cert(), weak], Vec::new(), Vec::new());

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
        let mut result = ScanResult::new(vec![cert], Vec::new(), Vec::new());

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

    fn asset(asset_type: AssetType, description: &str, details: AssetDetails) -> AssetInfo {
        AssetInfo {
            asset_type,
            path: "some/file".into(),
            description: description.into(),
            details,
            risk_score: RiskScore::default(),
            findings: Vec::new(),
        }
    }

    fn evaluate_now(asset: &AssetInfo) -> Vec<Finding> {
        evaluate_asset(asset, &default_policy(), Utc::now())
    }

    #[test]
    fn flags_weak_unencrypted_ssh_private_key() {
        let key = asset(
            AssetType::Ssh,
            "RSA private key",
            AssetDetails::SshPrivateKey {
                algorithm: "RSA".into(),
                key_bits: Some(1024),
                encrypted: false,
                fingerprint: None,
            },
        );
        let findings = evaluate_now(&key);
        assert_eq!(
            rules_of(&findings),
            [rules::SSH_WEAK_RSA, rules::SSH_UNENCRYPTED_KEY]
        );
        assert_eq!(asset_risk_score(&findings).value(), 55);

        let strong = asset(
            AssetType::Ssh,
            "ED25519 private key",
            AssetDetails::SshPrivateKey {
                algorithm: "ED25519".into(),
                key_bits: Some(256),
                encrypted: true,
                fingerprint: None,
            },
        );
        assert!(evaluate_now(&strong).is_empty());
    }

    #[test]
    fn flags_weak_and_duplicate_authorized_keys() {
        let entry = |line, algorithm: &str, key_bits, duplicate_of_line| SshPublicKeyEntry {
            line,
            algorithm: algorithm.into(),
            key_bits,
            comment: None,
            duplicate_of_line,
        };
        let file = asset(
            AssetType::Ssh,
            "authorized_keys",
            AssetDetails::SshAuthorizedKeys {
                keys: vec![
                    entry(1, "ssh-rsa", Some(1024), None),
                    entry(2, "ssh-ed25519", Some(256), None),
                    entry(3, "ssh-ed25519", Some(256), Some(2)),
                ],
            },
        );
        let findings = evaluate_now(&file);
        assert_eq!(
            rules_of(&findings),
            [
                rules::SSH_WEAK_ALGORITHM,
                rules::SSH_WEAK_RSA,
                rules::SSH_DUPLICATE_KEY
            ]
        );
    }

    #[test]
    fn secret_severity_depends_on_rule() {
        let secret = |rule: &str, description: &str| {
            asset(
                AssetType::Secret,
                description,
                AssetDetails::Secret {
                    rule: rule.into(),
                    line: 3,
                    preview: "****".into(),
                },
            )
        };
        let aws = evaluate_now(&secret(rules::SECRET_AWS_ACCESS_KEY, "AWS access key"));
        assert_eq!(aws[0].severity, FindingSeverity::Critical);
        assert!(aws[0].message.contains("line 3"));
        assert_eq!(asset_risk_score(&aws).value(), 40);

        let generic = evaluate_now(&secret(rules::SECRET_GENERIC_API_KEY, "Generic API key"));
        assert_eq!(generic[0].severity, FindingSeverity::Warning);

        let key = evaluate_now(&secret(rules::SECRET_PRIVATE_KEY, "Private key material"));
        assert_eq!(asset_risk_score(&key).value(), 50);
    }

    #[test]
    fn flags_jwt_alg_none_expired_and_long_lived() {
        let now = Utc::now();
        let jwt = |algorithm: &str, expires_at| {
            asset(
                AssetType::Jwt,
                "JWT",
                AssetDetails::Jwt {
                    algorithm: algorithm.into(),
                    expires_at,
                    issuer: None,
                    audience: None,
                },
            )
        };

        let none = evaluate_now(&jwt("none", Some(now - Duration::days(5))));
        assert_eq!(rules_of(&none), [rules::JWT_ALG_NONE, rules::JWT_EXPIRED]);
        assert_eq!(none[0].severity, FindingSeverity::Critical);
        assert_eq!(asset_risk_score(&none).value(), 90);

        let policy = default_policy();
        let long_lived = evaluate_now(&jwt(
            "HS256",
            Some(now + Duration::days(policy.max_certificate_lifetime_days + 10)),
        ));
        assert_eq!(rules_of(&long_lived), [rules::JWT_LONG_LIVED]);

        let healthy = evaluate_now(&jwt("RS256", Some(now + Duration::days(30))));
        assert!(healthy.is_empty());

        let no_expiry = evaluate_now(&jwt("HS256", None));
        assert!(no_expiry.is_empty());
    }

    #[test]
    fn analyze_populates_asset_findings_and_summary() {
        let secret = asset(
            AssetType::Secret,
            "AWS access key",
            AssetDetails::Secret {
                rule: rules::SECRET_AWS_ACCESS_KEY.into(),
                line: 1,
                preview: "****".into(),
            },
        );
        let mut result = ScanResult::new(Vec::new(), vec![secret], Vec::new());

        analyze(&mut result, &default_policy());

        assert_eq!(result.assets[0].risk_score.value(), 40);
        assert_eq!(result.summary.assets, 1);
        assert_eq!(result.summary.asset_critical, 1);
        assert_eq!(result.summary.asset_warning, 0);
    }
}
