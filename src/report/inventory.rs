use std::fmt::Display;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::models::{
    AssetDetails, AssetInfo, AssetType, CertificateInfo, ParseFailure, ScanResult,
};

#[derive(Debug, Serialize)]
pub struct InventorySummary {
    pub certificates: usize,
    pub ssh_keys: usize,
    pub secrets: usize,
    pub jwt: usize,
}

#[derive(Debug, Serialize)]
pub struct InventoryReport<'a> {
    pub summary: InventorySummary,
    pub certificates: &'a [CertificateInfo],
    pub ssh: Vec<&'a AssetInfo>,
    pub secrets: Vec<&'a AssetInfo>,
    pub jwt: Vec<&'a AssetInfo>,
    pub errors: &'a [ParseFailure],
}

impl<'a> InventoryReport<'a> {
    pub fn new(result: &'a ScanResult) -> Self {
        let of_type = |kind| {
            result
                .assets
                .iter()
                .filter(|a| a.asset_type == kind)
                .collect::<Vec<_>>()
        };
        let ssh = of_type(AssetType::Ssh);
        let secrets = of_type(AssetType::Secret);
        let jwt = of_type(AssetType::Jwt);
        Self {
            summary: InventorySummary {
                certificates: result.certificates.len(),
                ssh_keys: ssh.len(),
                secrets: secrets.len(),
                jwt: jwt.len(),
            },
            certificates: &result.certificates,
            ssh,
            secrets,
            jwt,
            errors: &result.errors,
        }
    }
}

pub fn print_json(result: &ScanResult) -> Result<()> {
    let report = InventoryReport::new(result);
    let output = serde_json::to_string_pretty(&report).context("failed to serialize inventory")?;
    println!("{output}");
    Ok(())
}

pub fn print(result: &ScanResult) {
    let report = InventoryReport::new(result);
    println!("Asset Inventory");

    if !report.certificates.is_empty() {
        section("Certificates");
        for cert in report.certificates {
            entry_header(&cert.path);
            field("Subject", &cert.subject);
            field("Issuer", &cert.issuer);
            field("Serial", &cert.serial_number);
            field("Fingerprint", format!("SHA256:{}", cert.fingerprint_sha256));
            field("Algorithm", &cert.signature_algorithm);
            if let Some(bits) = cert.key_size {
                field("Key size", format!("{bits} bits"));
            }
            field("Valid from", cert.not_before.format("%Y-%m-%d"));
            field(
                "Expires",
                format!("{} ({})", cert.not_after.format("%Y-%m-%d"), cert.status),
            );
            field("CA", yes_no(cert.is_ca));
            field("Self-signed", yes_no(cert.subject == cert.issuer));
            field("Risk", cert.risk_score);
        }
    }

    if !report.ssh.is_empty() {
        section("SSH Keys");
        for asset in &report.ssh {
            entry_header(&asset.path);
            print_ssh_details(&asset.details);
            field("Risk", asset.risk_score);
        }
    }

    if !report.secrets.is_empty() {
        section("Secrets");
        for asset in &report.secrets {
            entry_header(&asset.path);
            if let AssetDetails::Secret {
                rule,
                line,
                preview,
            } = &asset.details
            {
                field("Rule", format!("{} ({rule})", asset.description));
                field("Line", line);
                field("Preview", preview);
            }
            field("Risk", asset.risk_score);
        }
    }

    if !report.jwt.is_empty() {
        section("JWT Tokens");
        for asset in &report.jwt {
            entry_header(&asset.path);
            if let AssetDetails::Jwt {
                algorithm,
                expires_at,
                issuer,
                audience,
            } = &asset.details
            {
                field("Algorithm", algorithm);
                if let Some(issuer) = issuer {
                    field("Issuer", issuer);
                }
                if let Some(audience) = audience {
                    field("Audience", audience);
                }
                if let Some(expires_at) = expires_at {
                    field("Expires", expires_at.format("%Y-%m-%d"));
                }
            }
            field("Risk", asset.risk_score);
        }
    }

    if !report.errors.is_empty() {
        section("Parse errors");
        for failure in report.errors {
            println!("  {}: {}", failure.path.bright_red(), failure.error);
        }
    }

    section("Summary");
    println!();
    println!("Certificates      {}", report.summary.certificates);
    println!("SSH Keys          {}", report.summary.ssh_keys);
    println!("Secrets           {}", report.summary.secrets);
    println!("JWT Tokens        {}", report.summary.jwt);
    println!("Parse errors      {}", report.errors.len());
}

fn print_ssh_details(details: &AssetDetails) {
    match details {
        AssetDetails::SshPrivateKey {
            algorithm,
            key_bits,
            encrypted,
            fingerprint,
        } => {
            field("Type", algorithm);
            if let Some(bits) = key_bits {
                field("Bits", bits);
            }
            field("Encrypted", yes_no(*encrypted));
            if let Some(fingerprint) = fingerprint {
                field("Fingerprint", fingerprint);
            }
        }
        AssetDetails::SshAuthorizedKeys { keys } => {
            field("Keys", keys.len());
            for key in keys {
                let bits = key
                    .key_bits
                    .map_or_else(String::new, |b| format!(" ({b} bits)"));
                println!("    line {:<4} {}{bits}", key.line, key.algorithm);
            }
        }
        AssetDetails::SshKnownHosts { entries } => field("Entries", entries),
        _ => {}
    }
}

fn section(title: &str) {
    println!();
    println!("{title}");
}

fn entry_header(path: &str) {
    println!();
    println!("{}", path.bold());
}

fn field(name: &str, value: impl Display) {
    println!("  {name:<12} {value}");
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AssetDetails, AssetInfo, RiskScore};

    fn asset(kind: AssetType, path: &str, details: AssetDetails) -> AssetInfo {
        AssetInfo {
            asset_type: kind,
            path: path.into(),
            description: "test asset".into(),
            details,
            risk_score: RiskScore::default(),
            findings: Vec::new(),
        }
    }

    fn sample_result() -> ScanResult {
        let assets = vec![
            asset(
                AssetType::Ssh,
                "id_rsa",
                AssetDetails::SshPrivateKey {
                    algorithm: "RSA".into(),
                    key_bits: Some(4096),
                    encrypted: true,
                    fingerprint: None,
                },
            ),
            asset(
                AssetType::Secret,
                ".env",
                AssetDetails::Secret {
                    rule: "aws_access_key".into(),
                    line: 18,
                    preview: "AKIA****MPLE".into(),
                },
            ),
            asset(
                AssetType::Jwt,
                "config.json",
                AssetDetails::Jwt {
                    algorithm: "RS256".into(),
                    expires_at: None,
                    issuer: None,
                    audience: None,
                },
            ),
        ];
        ScanResult::new(Vec::new(), assets, Vec::new())
    }

    #[test]
    fn partitions_assets_by_type() {
        let result = sample_result();
        let report = InventoryReport::new(&result);
        assert_eq!(report.summary.certificates, 0);
        assert_eq!(report.summary.ssh_keys, 1);
        assert_eq!(report.summary.secrets, 1);
        assert_eq!(report.summary.jwt, 1);
        assert_eq!(report.ssh[0].path, "id_rsa");
        assert_eq!(report.secrets[0].path, ".env");
        assert_eq!(report.jwt[0].path, "config.json");
    }

    #[test]
    fn json_report_has_expected_shape() {
        let result = sample_result();
        let value = serde_json::to_value(InventoryReport::new(&result)).unwrap();
        assert_eq!(value["summary"]["certificates"], 0);
        assert_eq!(value["summary"]["ssh_keys"], 1);
        assert_eq!(value["summary"]["secrets"], 1);
        assert_eq!(value["summary"]["jwt"], 1);
        assert!(value["certificates"].as_array().unwrap().is_empty());
        assert_eq!(value["ssh"][0]["details"]["kind"], "ssh_private_key");
        assert_eq!(value["secrets"][0]["details"]["line"], 18);
        assert_eq!(value["jwt"][0]["details"]["algorithm"], "RS256");
        assert!(value["errors"].as_array().unwrap().is_empty());
    }
}
