use anyhow::{Context, Result};
use serde::Serialize;

use crate::inventory::Inventory;
use crate::models::ScanResult;
use crate::policy::Policy;

#[derive(Serialize)]
struct InventoryInfo {
    source: String,
    targets: usize,
}

impl InventoryInfo {
    fn new(inventory: &Inventory) -> Self {
        Self {
            source: inventory.source().display().to_string(),
            targets: inventory.target_count(),
        }
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(flatten)]
    result: &'a ScanResult,
    policy: &'a Policy,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory: Option<InventoryInfo>,
}

pub fn print(result: &ScanResult, policy: &Policy, inventory: Option<&Inventory>) -> Result<()> {
    let report = JsonReport {
        result,
        policy,
        inventory: inventory.map(InventoryInfo::new),
    };
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
            inventory: None,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert!(value.get("summary").is_some());
        assert!(value.get("certificates").is_some());
        assert!(value.get("assets").is_some());
        assert_eq!(value["summary"]["assets"], 0);
        assert_eq!(value["policy"]["warning_days"], 30);
        assert_eq!(value["policy"]["critical_days"], 7);
        assert_eq!(value["policy"]["min_rsa_key_size"], 2048);
        assert!(value.get("inventory").is_none());
    }

    #[test]
    fn json_report_embeds_inventory_info_with_policy() {
        let result = ScanResult::new(Vec::new(), Vec::new(), Vec::new());
        let policy = Policy {
            min_rsa_key_size: 4096,
            ..Policy::default()
        };
        let report = JsonReport {
            result: &result,
            policy: &policy,
            inventory: Some(InventoryInfo {
                source: "inventory.toml".into(),
                targets: 12,
            }),
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["inventory"]["source"], "inventory.toml");
        assert_eq!(value["inventory"]["targets"], 12);
        assert_eq!(value["policy"]["min_rsa_key_size"], 4096);
        assert!(value.get("summary").is_some());
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
