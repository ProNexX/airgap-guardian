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

    for entry in walk(root, true, None) {
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

pub(crate) fn walk(root: &Path, follow_links: bool, max_depth: Option<usize>) -> WalkDir {
    let walker = WalkDir::new(root).follow_links(follow_links);
    match max_depth {
        Some(depth) => walker.max_depth(depth),
        None => walker,
    }
}

pub(crate) fn validate_root(root: &Path) -> Result<()> {
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

pub(crate) fn encode_base64_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(bits >> (18 - 6 * i) & 0x3f) as usize] as char);
        }
    }
    out
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());

    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().expect("chunk is 4 bytes"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
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
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex_lower(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_lower(&sha256(&[0x55u8; 200])),
            "8d0da01949ca937fe72102d511382e10828dd39eefdf8c2601cc5f909cbeb969"
        );
    }

    #[test]
    fn encodes_base64_without_padding() {
        assert_eq!(encode_base64_nopad(b""), "");
        assert_eq!(encode_base64_nopad(b"f"), "Zg");
        assert_eq!(encode_base64_nopad(b"fo"), "Zm8");
        assert_eq!(encode_base64_nopad(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
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
