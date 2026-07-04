use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use regex::bytes::Regex;

use crate::models::{AssetDetails, AssetInfo, AssetType, RiskScore};
use crate::scanner::{ScanItem, Scanner, ssh};

pub const MAX_FILE_SIZE: u64 = 1024 * 1024;
const BINARY_PROBE_SIZE: usize = 8192;

pub struct SecretRule {
    pub name: &'static str,
    pub label: &'static str,
    pattern: &'static str,
}

pub const RULES: [SecretRule; 5] = [
    SecretRule {
        name: "aws_access_key",
        label: "AWS access key",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    },
    SecretRule {
        name: "github_token",
        label: "GitHub token",
        pattern: r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b",
    },
    SecretRule {
        name: "private_key",
        label: "Private key material",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    },
    SecretRule {
        name: "generic_api_key",
        label: "Generic API key",
        pattern: r#"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_/+=\-]{16,}"#,
    },
    SecretRule {
        name: "jwt_token",
        label: "JWT token",
        pattern: r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
    },
];

static COMPILED_RULES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|rule| Regex::new(rule.pattern).expect("secret rule pattern must be valid"))
        .collect()
});

pub struct SecretsScanner;

impl Scanner for SecretsScanner {
    fn can_scan(&self, path: &Path, size: u64) -> bool {
        size <= MAX_FILE_SIZE && !ssh::is_ssh_file(path)
    }

    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ScanItem>> {
        if is_binary(data) {
            return Ok(Vec::new());
        }
        let mut assets = Vec::new();
        let mut seen: Vec<(&'static str, &[u8])> = Vec::new();
        for (rule, regex) in RULES.iter().zip(COMPILED_RULES.iter()) {
            for found in regex.find_iter(data) {
                if seen.contains(&(rule.name, found.as_bytes())) {
                    continue;
                }
                seen.push((rule.name, found.as_bytes()));
                assets.push(ScanItem::Asset(AssetInfo {
                    asset_type: AssetType::Secret,
                    path: path.display().to_string(),
                    description: rule.label.to_string(),
                    details: AssetDetails::Secret {
                        rule: rule.name.to_string(),
                        line: line_number(data, found.start()),
                        preview: redact(found.as_bytes()),
                    },
                    risk_score: RiskScore::default(),
                    findings: Vec::new(),
                }));
            }
        }
        Ok(assets)
    }
}

fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(BINARY_PROBE_SIZE)].contains(&0)
}

fn line_number(data: &[u8], offset: usize) -> usize {
    data[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

fn redact(matched: &[u8]) -> String {
    let text = String::from_utf8_lossy(matched);
    if text.starts_with("-----BEGIN") {
        return text.into_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 8 {
        return "****".into();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(content: &[u8]) -> Vec<AssetInfo> {
        SecretsScanner
            .scan_file(Path::new("config.env"), content)
            .expect("scan should succeed")
            .into_iter()
            .map(|item| match item {
                ScanItem::Asset(asset) => asset,
                ScanItem::Certificate(_) => panic!("unexpected certificate"),
            })
            .collect()
    }

    fn rules_of(assets: &[AssetInfo]) -> Vec<&str> {
        assets
            .iter()
            .map(|a| match &a.details {
                AssetDetails::Secret { rule, .. } => rule.as_str(),
                _ => panic!("expected secret details"),
            })
            .collect()
    }

    #[test]
    fn detects_aws_access_key() {
        let assets = scan(b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
        assert_eq!(rules_of(&assets), ["aws_access_key"]);
        let AssetDetails::Secret { line, preview, .. } = &assets[0].details else {
            unreachable!();
        };
        assert_eq!(*line, 1);
        assert_eq!(preview, "AKIA****MPLE");
        assert!(!preview.contains("IOSFODNN"));
    }

    #[test]
    fn detects_github_token() {
        let assets = scan(b"token: ghp_0123456789abcdefghijABCDEFGHIJ123456\n");
        assert_eq!(rules_of(&assets), ["github_token"]);
    }

    #[test]
    fn detects_pem_private_key_block() {
        let assets =
            scan(b"-----BEGIN OPENSSH PRIVATE KEY-----\nZm9v\n-----END OPENSSH PRIVATE KEY-----\n");
        assert_eq!(rules_of(&assets), ["private_key"]);
    }

    #[test]
    fn detects_generic_api_key_and_jwt() {
        let assets = scan(
            b"api_key = \"sk1234567890abcdef\"\njwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\n",
        );
        assert_eq!(rules_of(&assets), ["generic_api_key", "jwt_token"]);
    }

    #[test]
    fn reports_line_numbers_and_dedupes_repeats() {
        let assets = scan(b"first\nAKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE\n");
        assert_eq!(assets.len(), 1);
        let AssetDetails::Secret { line, .. } = assets[0].details else {
            unreachable!();
        };
        assert_eq!(line, 2);
    }

    #[test]
    fn suppresses_false_positives() {
        let clean = b"AKIA too short\nakiaiosfodnn7example lowercase\n\
                      api_key = short\nghp_tooshort\nplain prose about keys\n";
        assert!(scan(clean).is_empty());
    }

    #[test]
    fn skips_binary_files() {
        let mut data = b"AKIAIOSFODNN7EXAMPLE".to_vec();
        data.insert(0, 0u8);
        assert!(scan(&data).is_empty());
    }

    #[test]
    fn skips_large_and_ssh_files() {
        let scanner = SecretsScanner;
        assert!(!scanner.can_scan(Path::new("config.env"), MAX_FILE_SIZE + 1));
        assert!(!scanner.can_scan(Path::new("/home/user/.ssh/id_rsa"), 100));
        assert!(scanner.can_scan(Path::new("config.env"), 100));
    }
}
