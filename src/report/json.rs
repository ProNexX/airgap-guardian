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
        let result = ScanResult::new(Vec::new(), Vec::new(), Vec::new());
        let policy = Policy::default();
        let report = JsonReport {
            result: &result,
            policy: &policy,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert!(value.get("summary").is_some());
        assert!(value.get("certificates").is_some());
        assert!(value.get("assets").is_some());
        assert_eq!(value["summary"]["assets"], 0);
        assert_eq!(value["policy"]["warning_days"], 30);
        assert_eq!(value["policy"]["critical_days"], 7);
        assert_eq!(value["policy"]["min_rsa_key_size"], 2048);
    }

    #[test]
    fn json_assets_carry_asset_type_tag() {
        use crate::models::{AssetDetails, AssetInfo, AssetType, RiskScore};

        let asset = AssetInfo {
            asset_type: AssetType::Jwt,
            path: "tokens.txt".into(),
            description: "JWT (alg none)".into(),
            details: AssetDetails::Jwt {
                algorithm: "none".into(),
                expires_at: None,
                issuer: None,
                audience: None,
            },
            risk_score: RiskScore::default(),
            findings: Vec::new(),
        };
        let result = ScanResult::new(Vec::new(), vec![asset], Vec::new());
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["assets"][0]["asset_type"], "jwt");
        assert_eq!(value["assets"][0]["details"]["kind"], "jwt");
        assert_eq!(value["assets"][0]["details"]["algorithm"], "none");
    }
}
