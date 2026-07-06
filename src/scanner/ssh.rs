use std::path::Path;

use anyhow::{Result, bail};

use crate::models::{AssetDetails, AssetInfo, AssetType, RiskScore, SshPublicKeyEntry};
use crate::scanner::{ScanItem, Scanner, decode_base64, encode_base64_nopad, sha256};

const PRIVATE_KEY_FILES: [&str; 3] = ["id_rsa", "id_ecdsa", "id_ed25519"];
const AUTHORIZED_KEYS: &str = "authorized_keys";
const KNOWN_HOSTS: &str = "known_hosts";

const PUBLIC_KEY_ALGORITHMS: [&str; 8] = [
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

pub struct SshScanner;

pub(crate) fn is_ssh_file(path: &Path) -> bool {
    file_name(path).is_some_and(|name| {
        PRIVATE_KEY_FILES.contains(&name) || name == AUTHORIZED_KEYS || name == KNOWN_HOSTS
    })
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

impl Scanner for SshScanner {
    fn can_scan(&self, path: &Path, _size: u64) -> bool {
        is_ssh_file(path)
    }

    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ScanItem>> {
        let Ok(text) = std::str::from_utf8(data) else {
            bail!("not a text file");
        };
        let asset = match file_name(path) {
            Some(AUTHORIZED_KEYS) => parse_authorized_keys(path, text),
            Some(KNOWN_HOSTS) => parse_known_hosts(path, text),
            _ => parse_private_key(path, text)?,
        };
        Ok(vec![ScanItem::Asset(asset)])
    }
}

fn asset(path: &Path, description: String, details: AssetDetails) -> AssetInfo {
    AssetInfo {
        asset_type: AssetType::Ssh,
        path: path.display().to_string(),
        description,
        details,
        risk_score: RiskScore::default(),
        findings: Vec::new(),
    }
}

struct PrivateKey {
    algorithm: String,
    key_bits: Option<usize>,
    encrypted: bool,
    fingerprint: Option<String>,
}

impl PrivateKey {
    fn new(algorithm: &str, key_bits: Option<usize>, encrypted: bool) -> Self {
        Self {
            algorithm: algorithm.into(),
            key_bits,
            encrypted,
            fingerprint: None,
        }
    }
}

fn public_key_fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", encode_base64_nopad(&sha256(blob)))
}

fn parse_private_key(path: &Path, text: &str) -> Result<AssetInfo> {
    let Some(block) = PemBlock::find(text) else {
        bail!("no private key block found");
    };
    let key = match block.label {
        "OPENSSH PRIVATE KEY" => {
            let body = decode_base64(&block.body)
                .ok_or_else(|| anyhow::anyhow!("invalid base64 in OpenSSH private key"))?;
            parse_openssh_private_key(&body)
                .ok_or_else(|| anyhow::anyhow!("invalid OpenSSH private key"))?
        }
        "RSA PRIVATE KEY" => {
            let encrypted = block.encrypted_headers;
            let key_bits = if encrypted {
                None
            } else {
                decode_base64(&block.body).and_then(|der| pkcs1_modulus_bits(&der))
            };
            PrivateKey::new("RSA", key_bits, encrypted)
        }
        "EC PRIVATE KEY" => PrivateKey::new("ECDSA", None, block.encrypted_headers),
        "DSA PRIVATE KEY" => PrivateKey::new("DSA", None, block.encrypted_headers),
        "ENCRYPTED PRIVATE KEY" => PrivateKey::new("unknown", None, true),
        "PRIVATE KEY" => PrivateKey::new("unknown", None, false),
        label => bail!("unsupported PEM block: {label}"),
    };

    let bits = key
        .key_bits
        .map_or_else(String::new, |b| format!(" ({b} bits)"));
    let protection = if key.encrypted {
        "encrypted"
    } else {
        "unencrypted"
    };
    let description = format!("{} private key{bits}, {protection}", key.algorithm);
    Ok(asset(
        path,
        description,
        AssetDetails::SshPrivateKey {
            algorithm: key.algorithm,
            key_bits: key.key_bits,
            encrypted: key.encrypted,
            fingerprint: key.fingerprint,
        },
    ))
}

struct PemBlock<'a> {
    label: &'a str,
    body: String,
    encrypted_headers: bool,
}

impl<'a> PemBlock<'a> {
    fn find(text: &'a str) -> Option<Self> {
        let mut label = None;
        let mut body = String::new();
        let mut encrypted_headers = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("-----BEGIN ") {
                label = rest.strip_suffix("-----");
                continue;
            }
            if label.is_none() {
                continue;
            }
            if line.starts_with("-----END ") {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("Proc-Type") && value.contains("ENCRYPTED") {
                    encrypted_headers = true;
                }
                continue;
            }
            body.push_str(line);
        }
        label.map(|label| Self {
            label,
            body,
            encrypted_headers,
        })
    }
}

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

fn parse_openssh_private_key(data: &[u8]) -> Option<PrivateKey> {
    let rest = data.strip_prefix(OPENSSH_MAGIC)?;
    let mut reader = WireReader::new(rest);
    let cipher = reader.string()?;
    let _kdf_name = reader.string()?;
    let _kdf_options = reader.string()?;
    let _key_count = reader.u32()?;
    let public_key_blob = reader.string()?;
    let (algorithm, key_bits) = parse_public_key_blob(public_key_blob)?;
    Some(PrivateKey {
        algorithm: display_algorithm(&algorithm),
        key_bits,
        encrypted: cipher != b"none",
        fingerprint: Some(public_key_fingerprint(public_key_blob)),
    })
}

fn parse_public_key_blob(blob: &[u8]) -> Option<(String, Option<usize>)> {
    let mut reader = WireReader::new(blob);
    let algorithm = std::str::from_utf8(reader.string()?).ok()?.to_string();
    let key_bits = match algorithm.as_str() {
        "ssh-rsa" => {
            let _exponent = reader.string()?;
            Some(mpint_bits(reader.string()?))
        }
        "ssh-dss" => Some(mpint_bits(reader.string()?)),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => Some(256),
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
        "ecdsa-sha2-nistp384" => Some(384),
        "ecdsa-sha2-nistp521" => Some(521),
        _ => None,
    };
    Some((algorithm, key_bits))
}

fn display_algorithm(wire_name: &str) -> String {
    match wire_name {
        "ssh-rsa" => "RSA".into(),
        "ssh-dss" => "DSA".into(),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => "ED25519".into(),
        name if name.starts_with("ecdsa-") || name.starts_with("sk-ecdsa-") => "ECDSA".into(),
        name => name.into(),
    }
}

fn mpint_bits(mpint: &[u8]) -> usize {
    let significant = match mpint.iter().position(|&b| b != 0) {
        Some(index) => &mpint[index..],
        None => return 0,
    };
    significant.len() * 8 - significant[0].leading_zeros() as usize
}

struct WireReader<'a> {
    data: &'a [u8],
}

impl<'a> WireReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.data.split_first_chunk::<4>()?;
        self.data = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > self.data.len() {
            return None;
        }
        let (head, rest) = self.data.split_at(len);
        self.data = rest;
        Some(head)
    }
}

fn pkcs1_modulus_bits(der: &[u8]) -> Option<usize> {
    let (sequence, _) = der_element(der)?;
    let (version, after_version) = der_element(sequence)?;
    if version != [0] {
        return None;
    }
    let (modulus, _) = der_element(after_version)?;
    Some(mpint_bits(modulus))
}

fn der_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&first_length_byte, rest) = data.get(1..)?.split_first()?;
    let (length, rest) = if first_length_byte < 0x80 {
        (first_length_byte as usize, rest)
    } else {
        let count = (first_length_byte & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let mut length = 0usize;
        for &byte in &rest[..count] {
            length = (length << 8) | byte as usize;
        }
        (length, &rest[count..])
    };
    if length > rest.len() {
        return None;
    }
    Some(rest.split_at(length))
}

fn parse_authorized_keys(path: &Path, text: &str) -> AssetInfo {
    let mut keys = Vec::new();
    let mut seen: Vec<(&str, usize)> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((algorithm, blob, comment)) = split_public_key_line(line) else {
            continue;
        };
        let line_number = index + 1;
        let key_bits = decode_base64(blob)
            .and_then(|decoded| parse_public_key_blob(&decoded))
            .and_then(|(_, bits)| bits);
        let duplicate_of_line = seen
            .iter()
            .find(|(known, _)| *known == blob)
            .map(|&(_, line)| line);
        if duplicate_of_line.is_none() {
            seen.push((blob, line_number));
        }
        keys.push(SshPublicKeyEntry {
            line: line_number,
            algorithm: algorithm.to_string(),
            key_bits,
            comment: (!comment.is_empty()).then(|| comment.to_string()),
            duplicate_of_line,
        });
    }
    let description = format!("authorized_keys ({} keys)", keys.len());
    asset(path, description, AssetDetails::SshAuthorizedKeys { keys })
}

fn split_public_key_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut tokens = line.split_whitespace();
    let mut first = tokens.next()?;
    if !PUBLIC_KEY_ALGORITHMS.contains(&first) {
        first = tokens.next()?;
        if !PUBLIC_KEY_ALGORITHMS.contains(&first) {
            return None;
        }
    }
    let blob = tokens.next()?;
    let comment = tokens.next().unwrap_or("");
    Some((first, blob, comment))
}

fn parse_known_hosts(path: &Path, text: &str) -> AssetInfo {
    let entries = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    let description = format!("known_hosts ({entries} entries)");
    asset(path, description, AssetDetails::SshKnownHosts { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{scan_directory, testdata_dir};

    fn scan_ssh_testdata() -> Vec<AssetInfo> {
        scan_directory(&testdata_dir().join("ssh"), &[Box::new(SshScanner)])
            .expect("scan should succeed")
            .assets
    }

    fn find<'a>(assets: &'a [AssetInfo], suffix: &str) -> &'a AssetInfo {
        assets
            .iter()
            .find(|a| a.path.ends_with(suffix))
            .unwrap_or_else(|| panic!("{suffix} should be scanned"))
    }

    #[test]
    fn detects_weak_unencrypted_rsa_private_key() {
        let assets = scan_ssh_testdata();
        let key = find(&assets, "id_rsa");
        assert_eq!(key.asset_type, AssetType::Ssh);
        let AssetDetails::SshPrivateKey {
            algorithm,
            key_bits,
            encrypted,
            ..
        } = &key.details
        else {
            panic!("expected private key details");
        };
        assert_eq!(algorithm, "RSA");
        assert_eq!(*key_bits, Some(1024));
        assert!(!encrypted);
    }

    #[test]
    fn detects_ed25519_private_key() {
        let assets = scan_ssh_testdata();
        let key = find(&assets, "id_ed25519");
        let AssetDetails::SshPrivateKey {
            algorithm,
            key_bits,
            encrypted,
            fingerprint,
        } = &key.details
        else {
            panic!("expected private key details");
        };
        assert_eq!(algorithm, "ED25519");
        assert_eq!(*key_bits, Some(256));
        assert!(!encrypted);
        assert_eq!(
            fingerprint.as_deref(),
            Some("SHA256:dhUpLPkA4qqwY4+kHeL5LcCYDfhLf42062qgdhJVUic")
        );
    }

    #[test]
    fn parses_authorized_keys_with_duplicates() {
        let assets = scan_ssh_testdata();
        let file = find(&assets, "authorized_keys");
        let AssetDetails::SshAuthorizedKeys { keys } = &file.details else {
            panic!("expected authorized_keys details");
        };
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].algorithm, "ssh-rsa");
        assert_eq!(keys[0].key_bits, Some(1024));
        assert_eq!(keys[1].algorithm, "ssh-ed25519");
        assert_eq!(keys[2].duplicate_of_line, Some(keys[0].line));
    }

    #[test]
    fn parses_known_hosts_entries() {
        let assets = scan_ssh_testdata();
        let file = find(&assets, "known_hosts");
        let AssetDetails::SshKnownHosts { entries } = file.details else {
            panic!("expected known_hosts details");
        };
        assert_eq!(entries, 2);
    }

    #[test]
    fn encrypted_pem_key_is_detected_via_headers() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\n\
                    Proc-Type: 4,ENCRYPTED\n\
                    DEK-Info: AES-128-CBC,ABCDEF\n\
                    \n\
                    Zm9vYmFy\n\
                    -----END RSA PRIVATE KEY-----\n";
        let asset = parse_private_key(Path::new("id_rsa"), text).unwrap();
        let AssetDetails::SshPrivateKey {
            algorithm,
            key_bits,
            encrypted,
            fingerprint,
        } = asset.details
        else {
            panic!("expected private key details");
        };
        assert_eq!(algorithm, "RSA");
        assert_eq!(key_bits, None);
        assert!(encrypted);
        assert_eq!(fingerprint, None);
    }

    #[test]
    fn garbage_private_key_is_an_error() {
        assert!(parse_private_key(Path::new("id_rsa"), "not a key").is_err());
        let scanner = SshScanner;
        assert!(
            scanner
                .scan_file(Path::new("id_rsa"), &[0xff, 0xfe])
                .is_err()
        );
    }

    #[test]
    fn only_ssh_file_names_are_scanned() {
        assert!(is_ssh_file(Path::new("/home/user/.ssh/id_rsa")));
        assert!(is_ssh_file(Path::new("id_ed25519")));
        assert!(is_ssh_file(Path::new("id_ecdsa")));
        assert!(is_ssh_file(Path::new("authorized_keys")));
        assert!(is_ssh_file(Path::new("known_hosts")));
        assert!(!is_ssh_file(Path::new("id_rsa.pub")));
        assert!(!is_ssh_file(Path::new("config")));
    }

    #[test]
    fn mpint_bit_length_ignores_leading_zeros() {
        assert_eq!(mpint_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(mpint_bits(&[0x01, 0x00]), 9);
        assert_eq!(mpint_bits(&[0x00, 0x00]), 0);
    }
}
