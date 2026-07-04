use anyhow::{Context, Result};
use serde::Serialize;

use crate::models::ScanResult;
use crate::policy::Policy;

#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(flatten)]
    result: &'a ScanResult,
    policy: &'a Policy,
}

pub fn print(result: &ScanResult, policy: &Policy) -> Result<()> {
    let report = JsonReport { result, policy };
    let output =
        serde_json::to_string_pretty(&report).context("failed to serialize scan result")?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_report_includes_policy_and_scan_fields() {
        let result = ScanResult::new(Vec::new(), Vec::new());
        let policy = Policy::default();
        let report = JsonReport {
            result: &result,
            policy: &policy,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert!(value.get("summary").is_some());
        assert!(value.get("certificates").is_some());
        assert_eq!(value["policy"]["warning_days"], 30);
        assert_eq!(value["policy"]["critical_days"], 7);
        assert_eq!(value["policy"]["min_rsa_key_size"], 2048);
    }
}
