use crate::errors::PolicyError;
use crate::policy::Policy;

const MIN_SUPPORTED_RSA_KEY_SIZE: usize = 1024;

pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    let mut violations = Vec::new();

    if policy.critical_days < 0 {
        violations.push(format!(
            "critical_days must be >= 0 (got {})",
            policy.critical_days
        ));
    }
    if policy.warning_days < policy.critical_days {
        violations.push(format!(
            "warning_days ({}) must be >= critical_days ({})",
            policy.warning_days, policy.critical_days
        ));
    }
    if policy.min_rsa_key_size < MIN_SUPPORTED_RSA_KEY_SIZE {
        violations.push(format!(
            "min_rsa_key_size must be >= {MIN_SUPPORTED_RSA_KEY_SIZE} (got {})",
            policy.min_rsa_key_size
        ));
    }
    if policy.max_certificate_lifetime_days <= 0 {
        violations.push(format!(
            "max_certificate_lifetime_days must be > 0 (got {})",
            policy.max_certificate_lifetime_days
        ));
    }
    if policy.allowed_signature_algorithms.is_empty() {
        violations.push("allowed_signature_algorithms must not be empty".to_string());
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::Invalid(violations.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_default_policy() {
        assert!(validate(&Policy::default()).is_ok());
    }

    #[test]
    fn rejects_negative_critical_days() {
        let policy = Policy {
            critical_days: -1,
            ..Policy::default()
        };
        let err = validate(&policy).unwrap_err();
        assert!(err.to_string().contains("critical_days"));
    }

    #[test]
    fn rejects_warning_below_critical() {
        let policy = Policy {
            warning_days: 5,
            critical_days: 7,
            ..Policy::default()
        };
        let err = validate(&policy).unwrap_err();
        assert!(err.to_string().contains("warning_days"));
    }

    #[test]
    fn rejects_too_small_rsa_key_size() {
        let policy = Policy {
            min_rsa_key_size: 512,
            ..Policy::default()
        };
        let err = validate(&policy).unwrap_err();
        assert!(err.to_string().contains("min_rsa_key_size"));
    }

    #[test]
    fn rejects_non_positive_lifetime() {
        let policy = Policy {
            max_certificate_lifetime_days: 0,
            ..Policy::default()
        };
        let err = validate(&policy).unwrap_err();
        assert!(err.to_string().contains("max_certificate_lifetime_days"));
    }

    #[test]
    fn rejects_empty_signature_algorithm_list() {
        let policy = Policy {
            allowed_signature_algorithms: Vec::new(),
            ..Policy::default()
        };
        let err = validate(&policy).unwrap_err();
        assert!(err.to_string().contains("allowed_signature_algorithms"));
    }

    #[test]
    fn reports_all_violations_at_once() {
        let policy = Policy {
            critical_days: -1,
            min_rsa_key_size: 0,
            allowed_signature_algorithms: Vec::new(),
            ..Policy::default()
        };
        let message = validate(&policy).unwrap_err().to_string();
        assert!(message.contains("critical_days"));
        assert!(message.contains("min_rsa_key_size"));
        assert!(message.contains("allowed_signature_algorithms"));
    }
}
