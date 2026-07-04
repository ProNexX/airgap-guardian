use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;

use crate::models::{AssetDetails, AssetInfo, AssetType, RiskScore};
use crate::scanner::{ScanItem, Scanner, decode_base64url, secrets, ssh};

static TOKEN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
        .expect("JWT pattern must be valid")
});

pub struct JwtScanner;

impl Scanner for JwtScanner {
    fn can_scan(&self, path: &Path, size: u64) -> bool {
        size <= secrets::MAX_FILE_SIZE && !ssh::is_ssh_file(path)
    }

    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ScanItem>> {
        let Ok(text) = std::str::from_utf8(data) else {
            return Ok(Vec::new());
        };
        let mut assets = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for found in TOKEN_PATTERN.find_iter(text) {
            let token = found.as_str();
            if seen.contains(&token) {
                continue;
            }
            seen.push(token);
            let Some(claims) = parse_token(token) else {
                continue;
            };
            assets.push(ScanItem::Asset(AssetInfo {
                asset_type: AssetType::Jwt,
                path: path.display().to_string(),
                description: format!("JWT (alg {})", claims.algorithm),
                details: AssetDetails::Jwt {
                    algorithm: claims.algorithm,
                    expires_at: claims.expires_at,
                    issuer: claims.issuer,
                    audience: claims.audience,
                },
                risk_score: RiskScore::default(),
                findings: Vec::new(),
            }));
        }
        Ok(assets)
    }
}

struct JwtClaims {
    algorithm: String,
    expires_at: Option<DateTime<Utc>>,
    issuer: Option<String>,
    audience: Option<String>,
}

fn parse_token(token: &str) -> Option<JwtClaims> {
    let mut parts = token.splitn(3, '.');
    let header = decode_json(parts.next()?)?;
    let payload = decode_json(parts.next()?)?;
    parts.next()?;

    let algorithm = header.get("alg")?.as_str()?.to_string();
    let expires_at = payload
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|ts| DateTime::from_timestamp(ts, 0));
    Some(JwtClaims {
        algorithm,
        expires_at,
        issuer: string_claim(&payload, "iss"),
        audience: string_claim(&payload, "aud"),
    })
}

fn decode_json(part: &str) -> Option<Value> {
    let bytes = decode_base64url(part)?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

fn string_claim(payload: &Value, name: &str) -> Option<String> {
    match payload.get(name)? {
        Value::String(s) => Some(s.clone()),
        Value::Array(values) => {
            let items: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
            (!items.is_empty()).then(|| items.join(", "))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn encode_token(header: &str, payload: &str, signature: &str) -> String {
    let encode = |data: &str| {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.as_bytes().chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let bits =
                u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
            for i in 0..(chunk.len() + 1) {
                out.push(ALPHABET[(bits >> (18 - 6 * i) & 0x3f) as usize] as char);
            }
        }
        out
    };
    format!("{}.{}.{signature}", encode(header), encode(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(content: &str) -> Vec<AssetInfo> {
        JwtScanner
            .scan_file(Path::new("tokens.txt"), content.as_bytes())
            .expect("scan should succeed")
            .into_iter()
            .map(|item| match item {
                ScanItem::Asset(asset) => asset,
                ScanItem::Certificate(_) => panic!("unexpected certificate"),
            })
            .collect()
    }

    #[test]
    fn parses_valid_jwt_claims() {
        let token = encode_token(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"iss":"issuer.test","aud":"api.test","exp":1893456000}"#,
            "signature",
        );
        let assets = scan(&format!("token={token}\n"));
        assert_eq!(assets.len(), 1);
        let AssetDetails::Jwt {
            algorithm,
            expires_at,
            issuer,
            audience,
        } = &assets[0].details
        else {
            panic!("expected JWT details");
        };
        assert_eq!(algorithm, "HS256");
        assert_eq!(issuer.as_deref(), Some("issuer.test"));
        assert_eq!(audience.as_deref(), Some("api.test"));
        assert_eq!(expires_at.unwrap().timestamp(), 1_893_456_000);
    }

    #[test]
    fn detects_alg_none_with_empty_signature() {
        let token = encode_token(r#"{"alg":"none"}"#, r#"{"sub":"admin"}"#, "");
        let assets = scan(&token);
        assert_eq!(assets.len(), 1);
        let AssetDetails::Jwt { algorithm, .. } = &assets[0].details else {
            panic!("expected JWT details");
        };
        assert_eq!(algorithm, "none");
    }

    #[test]
    fn ignores_malformed_tokens() {
        assert!(scan("eyJnb3RjaGEhIQ.eyJub3Rqc29u.sig").is_empty());
        assert!(scan("just some text").is_empty());
        assert!(scan("eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24tZGF0YQ.sig").is_empty());
    }

    #[test]
    fn handles_binary_and_dedupes() {
        let scanner = JwtScanner;
        assert!(
            scanner
                .scan_file(Path::new("blob.bin"), &[0xff, 0xfe, 0x00])
                .unwrap()
                .is_empty()
        );
        let token = encode_token(r#"{"alg":"HS256"}"#, r#"{"sub":"x"}"#, "sig");
        assert_eq!(scan(&format!("{token} {token}")).len(), 1);
    }
}
