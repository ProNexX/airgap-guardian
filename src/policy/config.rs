use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::PolicyError;
use crate::models::{CRITICAL_THRESHOLD_DAYS, WARNING_THRESHOLD_DAYS};

pub const DEFAULT_MIN_RSA_KEY_SIZE: usize = 2048;
pub const DEFAULT_MAX_CERTIFICATE_LIFETIME_DAYS: i64 = 398;

const DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS: [&str; 6] = [
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "ecdsa-with-SHA512",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub warning_days: i64,
    pub critical_days: i64,
    pub min_rsa_key_size: usize,
    pub max_certificate_lifetime_days: i64,
    pub allow_self_signed: bool,
    pub required_subject_alternative_name: bool,
    pub allowed_signature_algorithms: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            warning_days: WARNING_THRESHOLD_DAYS,
            critical_days: CRITICAL_THRESHOLD_DAYS,
            min_rsa_key_size: DEFAULT_MIN_RSA_KEY_SIZE,
            max_certificate_lifetime_days: DEFAULT_MAX_CERTIFICATE_LIFETIME_DAYS,
            allow_self_signed: false,
            required_subject_alternative_name: true,
            allowed_signature_algorithms: DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let contents = fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let policy = Self::parse(&contents).map_err(|source| PolicyError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        policy.validated()
    }

    pub fn parse(toml: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml)
    }

    pub fn validated(self) -> Result<Self, PolicyError> {
        super::validation::validate(&self)?;
        Ok(self)
    }

    pub fn allows_signature_algorithm(&self, algorithm: &str) -> bool {
        self.allowed_signature_algorithms
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(algorithm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_matches_builtin_thresholds() {
        let policy = Policy::default();
        assert_eq!(policy.warning_days, 30);
        assert_eq!(policy.critical_days, 7);
        assert_eq!(policy.min_rsa_key_size, 2048);
        assert_eq!(policy.max_certificate_lifetime_days, 398);
        assert!(!policy.allow_self_signed);
        assert!(policy.required_subject_alternative_name);
        assert!(policy.allows_signature_algorithm("sha256WithRSAEncryption"));
        assert!(!policy.allows_signature_algorithm("sha1WithRSAEncryption"));
    }

    #[test]
    fn default_policy_is_valid() {
        assert!(Policy::default().validated().is_ok());
    }

    #[test]
    fn parses_full_policy_file() {
        let policy = Policy::parse(
            r#"
            warning_days = 60
            critical_days = 14
            min_rsa_key_size = 4096
            max_certificate_lifetime_days = 90
            allow_self_signed = true
            required_subject_alternative_name = false
            allowed_signature_algorithms = ["ecdsa-with-SHA256"]
            "#,
        )
        .expect("policy should parse");
        assert_eq!(policy.warning_days, 60);
        assert_eq!(policy.critical_days, 14);
        assert_eq!(policy.min_rsa_key_size, 4096);
        assert_eq!(policy.max_certificate_lifetime_days, 90);
        assert!(policy.allow_self_signed);
        assert!(!policy.required_subject_alternative_name);
        assert_eq!(policy.allowed_signature_algorithms, ["ecdsa-with-SHA256"]);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let policy = Policy::parse("warning_days = 45").expect("policy should parse");
        assert_eq!(policy.warning_days, 45);
        assert_eq!(policy.critical_days, Policy::default().critical_days);
        assert_eq!(
            policy.allowed_signature_algorithms,
            Policy::default().allowed_signature_algorithms
        );
    }

    #[test]
    fn empty_file_equals_default_policy() {
        assert_eq!(Policy::parse("").unwrap(), Policy::default());
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(Policy::parse("warning_days = ").is_err());
        assert!(Policy::parse("warning_days = \"thirty\"").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Policy::parse("warnign_days = 30").is_err());
    }

    #[test]
    fn signature_algorithm_matching_is_case_insensitive() {
        let policy = Policy::default();
        assert!(policy.allows_signature_algorithm("SHA256WITHRSAENCRYPTION"));
    }

    #[test]
    fn load_reports_missing_file() {
        let err = Policy::load(Path::new("/nonexistent/policy.toml")).unwrap_err();
        assert!(err.to_string().contains("policy.toml"));
    }

    #[test]
    fn load_reads_and_validates_custom_file() {
        let dir = std::env::temp_dir().join("airgap-guardian-policy-test");
        std::fs::create_dir_all(&dir).unwrap();

        let valid = dir.join("valid.toml");
        std::fs::write(&valid, "min_rsa_key_size = 4096\n").unwrap();
        assert_eq!(Policy::load(&valid).unwrap().min_rsa_key_size, 4096);

        let invalid = dir.join("invalid.toml");
        std::fs::write(&invalid, "critical_days = -1\n").unwrap();
        assert!(Policy::load(&invalid).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
