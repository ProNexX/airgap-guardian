use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use walkdir::WalkDir;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::Oid;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

use crate::errors::ScanError;
use crate::models::{
    CertificateInfo, CertificateStatus, ParseFailure, RiskScore, ScanResult, days_remaining,
};
use crate::scanner::Scanner;

const SUPPORTED_EXTENSIONS: [&str; 4] = ["pem", "crt", "cer", "der"];

pub struct CertificateScanner {
    root: PathBuf,
}

impl CertificateScanner {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn validate_root(&self) -> Result<()> {
        match fs::metadata(&self.root) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(ScanError::NotADirectory(self.root.clone()).into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ScanError::DirectoryNotFound(self.root.clone()).into())
            }
            Err(e) => Err(anyhow!(e).context(format!("cannot access {}", self.root.display()))),
        }
    }
}

impl Scanner for CertificateScanner {
    fn scan(&self) -> Result<ScanResult> {
        self.validate_root()?;

        let now = Utc::now();
        let mut certificates = Vec::new();
        let mut errors = Vec::new();

        for entry in WalkDir::new(&self.root).follow_links(true) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let path = e.path().map_or_else(
                        || self.root.display().to_string(),
                        |p| p.display().to_string(),
                    );
                    errors.push(ParseFailure {
                        path,
                        error: e.to_string(),
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() || !has_supported_extension(entry.path()) {
                continue;
            }
            match process_file(entry.path(), now) {
                Ok(mut certs) => certificates.append(&mut certs),
                Err(e) => errors.push(ParseFailure {
                    path: entry.path().display().to_string(),
                    error: format!("{e:#}"),
                }),
            }
        }

        certificates.sort_by(|a, b| a.path.cmp(&b.path));
        errors.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(ScanResult::new(certificates, errors))
    }
}

fn has_supported_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            SUPPORTED_EXTENSIONS
                .iter()
                .any(|s| ext.eq_ignore_ascii_case(s))
        })
}

fn process_file(path: &Path, now: DateTime<Utc>) -> Result<Vec<CertificateInfo>> {
    let data = fs::read(path).context("cannot read file")?;
    parse_certificates(path, &data, now)
}

fn parse_certificates(
    path: &Path,
    data: &[u8],
    now: DateTime<Utc>,
) -> Result<Vec<CertificateInfo>> {
    if looks_like_pem(data) {
        parse_pem(path, data, now)
    } else {
        parse_der(path, data, now)
    }
}

fn looks_like_pem(data: &[u8]) -> bool {
    const MARKER: &[u8] = b"-----BEGIN";
    data.windows(MARKER.len()).any(|w| w == MARKER)
}

fn parse_pem(path: &Path, data: &[u8], now: DateTime<Utc>) -> Result<Vec<CertificateInfo>> {
    let mut certificates = Vec::new();
    for (index, pem) in Pem::iter_from_buffer(data).enumerate() {
        let pem = pem.with_context(|| format!("invalid PEM block {index}"))?;
        if pem.label != "CERTIFICATE" {
            continue;
        }
        let cert = pem
            .parse_x509()
            .with_context(|| format!("invalid certificate in PEM block {index}"))?;
        certificates.push(extract_info(path, &cert, now)?);
    }
    if certificates.is_empty() {
        bail!("no CERTIFICATE blocks found in PEM file");
    }
    Ok(certificates)
}

fn parse_der(path: &Path, data: &[u8], now: DateTime<Utc>) -> Result<Vec<CertificateInfo>> {
    let (_, cert) =
        X509Certificate::from_der(data).map_err(|e| anyhow!("invalid DER certificate: {e}"))?;
    Ok(vec![extract_info(path, &cert, now)?])
}

fn extract_info(
    path: &Path,
    cert: &X509Certificate,
    now: DateTime<Utc>,
) -> Result<CertificateInfo> {
    let not_before = to_datetime(&cert.validity().not_before)?;
    let not_after = to_datetime(&cert.validity().not_after)?;
    let public_key = cert.public_key();
    Ok(CertificateInfo {
        path: path.display().to_string(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial_number: cert.raw_serial_as_string(),
        not_before,
        not_after,
        days_remaining: days_remaining(not_after, now),
        status: CertificateStatus::evaluate(not_after, now),
        signature_algorithm: oid_name(&cert.signature_algorithm.algorithm),
        public_key_algorithm: oid_name(&public_key.algorithm.algorithm),
        key_size: key_size_bits(cert),
        is_ca: cert.is_ca(),
        has_san: has_subject_alternative_name(cert),
        risk_score: RiskScore::default(),
        findings: Vec::new(),
    })
}

fn has_subject_alternative_name(cert: &X509Certificate) -> bool {
    cert.subject_alternative_name()
        .is_ok_and(|san| san.is_some())
}

fn to_datetime(time: &ASN1Time) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(time.timestamp(), 0)
        .ok_or_else(|| anyhow!("certificate validity date out of range"))
}

fn oid_name(oid: &Oid) -> String {
    oid2sn(oid, oid_registry())
        .map(str::to_string)
        .unwrap_or_else(|_| oid.to_id_string())
}

fn key_size_bits(cert: &X509Certificate) -> Option<usize> {
    let key = cert.public_key().parsed().ok()?;
    let bits = match key {
        PublicKey::RSA(rsa) => rsa.key_size(),
        PublicKey::EC(ec) => ec.key_size(),
        PublicKey::DSA(y) | PublicKey::GostR3410(y) => y.len() * 8,
        _ => 0,
    };
    (bits > 0).then_some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
    }

    fn scan_testdata() -> ScanResult {
        CertificateScanner::new(testdata())
            .scan()
            .expect("scan should succeed")
    }

    #[test]
    fn discovers_certificates_recursively() {
        let result = scan_testdata();
        let paths: Vec<&str> = result
            .certificates
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        assert!(paths.iter().any(|p| p.ends_with("api.pem")));
        assert!(paths.iter().any(|p| p.ends_with("nested/ldap.crt")));
        assert!(paths.iter().any(|p| p.ends_with("nested/vpn.der")));
        assert_eq!(result.summary.total, 4);
    }

    #[test]
    fn follows_symlinked_certificates() {
        let result = scan_testdata();
        assert!(
            result
                .certificates
                .iter()
                .any(|c| c.path.ends_with("link.pem"))
        );
    }

    #[test]
    fn ignores_unsupported_extensions() {
        let result = scan_testdata();
        assert!(
            !result
                .certificates
                .iter()
                .chain(result.certificates.iter())
                .any(|c| c.path.ends_with(".txt"))
        );
        assert!(!result.errors.iter().any(|e| e.path.ends_with(".txt")));
    }

    #[test]
    fn invalid_certificate_is_reported_without_aborting() {
        let result = scan_testdata();
        assert_eq!(result.summary.parse_errors, 1);
        assert!(result.errors[0].path.ends_with("bad.pem"));
        assert_eq!(result.summary.total, 4);
    }

    #[test]
    fn invalid_bytes_fail_to_parse() {
        let now = Utc::now();
        assert!(parse_certificates(Path::new("garbage.der"), b"not a certificate", now).is_err());
        assert!(
            parse_certificates(
                Path::new("garbage.pem"),
                b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
                now
            )
            .is_err()
        );
    }

    #[test]
    fn missing_directory_is_an_error() {
        let err = CertificateScanner::new(testdata().join("does-not-exist"))
            .scan()
            .expect_err("scan should fail");
        assert!(matches!(
            err.downcast_ref::<ScanError>(),
            Some(ScanError::DirectoryNotFound(_))
        ));
    }

    #[test]
    fn extension_filter() {
        assert!(has_supported_extension(Path::new("a.pem")));
        assert!(has_supported_extension(Path::new("a.CRT")));
        assert!(has_supported_extension(Path::new("a.cer")));
        assert!(has_supported_extension(Path::new("a.der")));
        assert!(!has_supported_extension(Path::new("a.txt")));
        assert!(!has_supported_extension(Path::new("pem")));
    }

    #[test]
    fn extracts_certificate_fields() {
        let result = scan_testdata();
        let cert = result
            .certificates
            .iter()
            .find(|c| c.path.ends_with("api.pem"))
            .expect("api.pem should be scanned");
        assert!(cert.subject.contains("api.example.test"));
        assert!(!cert.serial_number.is_empty());
        assert_eq!(cert.key_size, Some(2048));
        assert_eq!(cert.status, CertificateStatus::Ok);
        assert!(cert.days_remaining > 30);
    }
}
