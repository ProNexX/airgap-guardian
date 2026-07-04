pub mod cert;
pub mod jwt;
pub mod secrets;
pub mod ssh;

use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

use crate::errors::ScanError;
use crate::models::{AssetInfo, CertificateInfo, ParseFailure, ScanResult};

pub enum ScanItem {
    Certificate(CertificateInfo),
    Asset(AssetInfo),
}

pub trait Scanner {
    fn can_scan(&self, path: &Path, size: u64) -> bool;
    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ScanItem>>;
}

pub fn scan_directory(root: &Path, scanners: &[Box<dyn Scanner>]) -> Result<ScanResult> {
    validate_root(root)?;

    let mut certificates = Vec::new();
    let mut assets = Vec::new();
    let mut errors = Vec::new();

    for entry in WalkDir::new(root).follow_links(true) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                let path = e
                    .path()
                    .map_or_else(|| root.display().to_string(), |p| p.display().to_string());
                errors.push(ParseFailure {
                    path,
                    error: e.to_string(),
                });
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let size = entry.metadata().map_or(0, |m| m.len());
        let applicable: Vec<&dyn Scanner> = scanners
            .iter()
            .map(Box::as_ref)
            .filter(|s| s.can_scan(path, size))
            .collect();
        if applicable.is_empty() {
            continue;
        }
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) => {
                errors.push(ParseFailure {
                    path: path.display().to_string(),
                    error: format!("cannot read file: {e}"),
                });
                continue;
            }
        };
        for scanner in applicable {
            match scanner.scan_file(path, &data) {
                Ok(items) => {
                    for item in items {
                        match item {
                            ScanItem::Certificate(cert) => certificates.push(cert),
                            ScanItem::Asset(asset) => assets.push(asset),
                        }
                    }
                }
                Err(e) => errors.push(ParseFailure {
                    path: path.display().to_string(),
                    error: format!("{e:#}"),
                }),
            }
        }
    }

    certificates.sort_by(|a, b| a.path.cmp(&b.path));
    assets.sort_by(|a, b| a.path.cmp(&b.path));
    errors.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ScanResult::new(certificates, assets, errors))
}

fn validate_root(root: &Path) -> Result<()> {
    match fs::metadata(root) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(ScanError::NotADirectory(root.to_path_buf()).into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(ScanError::DirectoryNotFound(root.to_path_buf()).into())
        }
        Err(e) => Err(anyhow!(e).context(format!("cannot access {}", root.display()))),
    }
}

pub(crate) fn decode_base64(input: &str) -> Option<Vec<u8>> {
    decode_sextets(input, |b| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    })
}

pub(crate) fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    decode_sextets(input, |b| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    })
}

fn decode_sextets(input: &str, value_of: fn(u8) -> Option<u8>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &byte in input.as_bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | u32::from(value_of(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
pub(crate) fn testdata_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVs\nbG8=").unwrap(), b"hello");
        assert!(decode_base64("aGV$bG8=").is_none());
    }

    #[test]
    fn decodes_base64url_without_padding() {
        assert_eq!(decode_base64url("eyJhIjoxfQ").unwrap(), br#"{"a":1}"#);
        assert!(decode_base64url("ey+J").is_none());
    }

    #[test]
    fn pipeline_runs_all_scanners_over_one_walk() {
        use crate::models::AssetType;

        let scanners: Vec<Box<dyn Scanner>> = vec![
            Box::new(cert::CertificateScanner::new()),
            Box::new(ssh::SshScanner),
            Box::new(secrets::SecretsScanner),
            Box::new(jwt::JwtScanner),
        ];
        let result = scan_directory(&testdata_dir(), &scanners).expect("scan should succeed");

        assert_eq!(result.summary.total, 4);
        assert!(result.errors.iter().any(|e| e.path.ends_with("bad.pem")));

        let of_type = |t| {
            result
                .assets
                .iter()
                .filter(move |a| a.asset_type == t)
                .count()
        };
        assert_eq!(of_type(AssetType::Ssh), 4);
        assert!(of_type(AssetType::Secret) >= 2);
        assert_eq!(of_type(AssetType::Jwt), 1);
        assert_eq!(result.summary.assets, result.assets.len());
    }

    #[test]
    fn missing_directory_is_an_error() {
        let err = scan_directory(&testdata_dir().join("does-not-exist"), &[])
            .expect_err("scan should fail");
        assert!(matches!(
            err.downcast_ref::<ScanError>(),
            Some(ScanError::DirectoryNotFound(_))
        ));
    }
}
