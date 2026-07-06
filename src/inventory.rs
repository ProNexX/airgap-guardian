use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::errors::InventoryError;
use crate::models::{AssetType, ParseFailure, ScanResult};
use crate::scanner;

pub const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub path: PathBuf,
    pub scanners: Vec<AssetType>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    version: u32,
    #[serde(default)]
    scan: Vec<Target>,
}

pub fn to_toml(targets: Vec<Target>) -> Result<String> {
    toml::to_string(&InventoryFile {
        version: VERSION,
        scan: targets,
    })
    .map_err(|e| anyhow!(e).context("failed to serialize inventory"))
}

#[derive(Debug)]
pub struct Inventory {
    source: PathBuf,
    targets: BTreeMap<PathBuf, BTreeSet<AssetType>>,
}

impl Inventory {
    pub fn load(path: &Path) -> Result<Self, InventoryError> {
        let content = fs::read_to_string(path).map_err(|source| InventoryError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(path, &content)
    }

    pub(crate) fn parse(source: &Path, content: &str) -> Result<Self, InventoryError> {
        let file: InventoryFile = toml::from_str(content).map_err(|e| InventoryError::Parse {
            path: source.to_path_buf(),
            source: e,
        })?;

        let mut violations = Vec::new();
        if file.version != VERSION {
            violations.push(format!(
                "unsupported version {} (supported: {VERSION})",
                file.version
            ));
        }
        if file.scan.is_empty() {
            violations.push("no scan entries defined".to_string());
        }

        let mut seen: Vec<(PathBuf, BTreeSet<AssetType>)> = Vec::new();
        let mut targets: BTreeMap<PathBuf, BTreeSet<AssetType>> = BTreeMap::new();
        for (index, entry) in file.scan.iter().enumerate() {
            let entry_number = index + 1;
            if entry.path.as_os_str().is_empty() {
                violations.push(format!("scan entry {entry_number}: path is empty"));
                continue;
            }
            if entry.scanners.is_empty() {
                violations.push(format!(
                    "scan entry {entry_number} ({}): scanners list is empty",
                    entry.path.display()
                ));
                continue;
            }
            let path = normalize(&entry.path);
            let kinds: BTreeSet<AssetType> = entry.scanners.iter().copied().collect();
            if seen.iter().any(|(p, k)| *p == path && *k == kinds) {
                violations.push(format!(
                    "scan entry {entry_number}: duplicate entry for {}",
                    path.display()
                ));
                continue;
            }
            targets
                .entry(path.clone())
                .or_default()
                .extend(kinds.iter().copied());
            seen.push((path, kinds));
        }

        if violations.is_empty() {
            Ok(Self {
                source: source.to_path_buf(),
                targets,
            })
        } else {
            Err(InventoryError::Invalid(violations.join("; ")))
        }
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn targets(&self) -> impl Iterator<Item = (&Path, &BTreeSet<AssetType>)> {
        self.targets
            .iter()
            .map(|(path, kinds)| (path.as_path(), kinds))
    }

    pub fn scan(&self) -> ScanResult {
        let mut certificates = Vec::new();
        let mut assets = Vec::new();
        let mut errors = Vec::new();
        for (path, kinds) in &self.targets {
            let scanners = scanner::build_scanners(kinds.iter().copied());
            match scanner::scan_directory(path, &scanners) {
                Ok(result) => {
                    certificates.extend(result.certificates);
                    assets.extend(result.assets);
                    errors.extend(result.errors);
                }
                Err(e) => errors.push(ParseFailure {
                    path: path.display().to_string(),
                    error: format!("{e:#}"),
                }),
            }
        }
        certificates.sort_by(|a, b| a.path.cmp(&b.path));
        assets.sort_by(|a, b| a.path.cmp(&b.path));
        errors.sort_by(|a, b| a.path.cmp(&b.path));
        ScanResult::new(certificates, assets, errors)
    }
}

fn normalize(path: &Path) -> PathBuf {
    let normalized: PathBuf = path
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::testdata_dir;

    fn parse(content: &str) -> Result<Inventory, InventoryError> {
        Inventory::parse(Path::new("inventory.toml"), content)
    }

    fn entry(path: &Path, scanners: &str) -> String {
        format!(
            "[[scan]]\npath = \"{}\"\nscanners = [{scanners}]\n",
            path.display()
        )
    }

    #[test]
    fn parses_single_target() {
        let inventory =
            parse("version = 1\n\n[[scan]]\npath = \"/etc/ssl\"\nscanners = [\"cert\"]\n")
                .expect("inventory should parse");
        assert_eq!(inventory.target_count(), 1);
        let (path, kinds) = inventory.targets().next().unwrap();
        assert_eq!(path, Path::new("/etc/ssl"));
        assert_eq!(kinds.iter().copied().collect::<Vec<_>>(), [AssetType::Cert]);
        assert_eq!(inventory.source(), Path::new("inventory.toml"));
    }

    #[test]
    fn merges_entries_with_same_path() {
        let inventory = parse(
            "version = 1\n\
             [[scan]]\npath = \"/etc\"\nscanners = [\"cert\"]\n\
             [[scan]]\npath = \"/etc/\"\nscanners = [\"ssh\"]\n",
        )
        .expect("inventory should parse");
        assert_eq!(inventory.target_count(), 1);
        let (path, kinds) = inventory.targets().next().unwrap();
        assert_eq!(path, Path::new("/etc"));
        assert_eq!(
            kinds.iter().copied().collect::<Vec<_>>(),
            [AssetType::Cert, AssetType::Ssh]
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let err =
            parse("version = 2\n[[scan]]\npath = \"/etc\"\nscanners = [\"cert\"]\n").unwrap_err();
        assert!(err.to_string().contains("unsupported version 2"));
    }

    #[test]
    fn rejects_missing_version() {
        let err = parse("[[scan]]\npath = \"/etc\"\nscanners = [\"cert\"]\n").unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }));
    }

    #[test]
    fn rejects_empty_inventory() {
        assert!(
            parse("version = 1\n")
                .unwrap_err()
                .to_string()
                .contains("no scan entries")
        );
    }

    #[test]
    fn rejects_empty_scanner_list_and_empty_path() {
        let err = parse(
            "version = 1\n\
             [[scan]]\npath = \"/etc\"\nscanners = []\n\
             [[scan]]\npath = \"\"\nscanners = [\"cert\"]\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("scanners list is empty"));
        assert!(message.contains("path is empty"));
    }

    #[test]
    fn rejects_unknown_scanner_name() {
        let err =
            parse("version = 1\n[[scan]]\npath = \"/etc\"\nscanners = [\"nmap\"]\n").unwrap_err();
        let InventoryError::Parse { source, .. } = err else {
            panic!("expected parse error");
        };
        assert!(source.to_string().contains("unknown variant"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let top_level =
            parse("version = 1\nextra = true\n[[scan]]\npath = \"/etc\"\nscanners = [\"cert\"]\n");
        assert!(matches!(top_level, Err(InventoryError::Parse { .. })));
        let in_entry = parse(
            "version = 1\n[[scan]]\npath = \"/etc\"\nscanners = [\"cert\"]\nrecursive = true\n",
        );
        assert!(matches!(in_entry, Err(InventoryError::Parse { .. })));
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(matches!(
            parse("version = ["),
            Err(InventoryError::Parse { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_entries() {
        let err = parse(
            "version = 1\n\
             [[scan]]\npath = \"/etc\"\nscanners = [\"cert\", \"ssh\"]\n\
             [[scan]]\npath = \"/etc/.\"\nscanners = [\"ssh\", \"cert\"]\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate entry for /etc"));
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Inventory::load(&testdata_dir().join("does-not-exist.toml")).unwrap_err();
        assert!(matches!(err, InventoryError::Read { .. }));
    }

    #[test]
    fn loads_inventory_from_file() {
        let path = std::env::temp_dir().join(format!(
            "airgap-guardian-inventory-{}.toml",
            std::process::id()
        ));
        fs::write(
            &path,
            "version = 1\n[[scan]]\npath = \"/etc/ssl\"\nscanners = [\"cert\"]\n",
        )
        .unwrap();
        let inventory = Inventory::load(&path).expect("inventory should load");
        assert_eq!(inventory.target_count(), 1);
        assert_eq!(inventory.source(), path);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn round_trips_through_to_toml() {
        let toml = to_toml(vec![Target {
            path: PathBuf::from("/etc/ssl"),
            scanners: vec![AssetType::Cert, AssetType::Jwt],
        }])
        .unwrap();
        let inventory = parse(&toml).expect("generated inventory should parse");
        assert_eq!(inventory.target_count(), 1);
    }

    #[test]
    fn scans_single_target_with_selected_scanners_only() {
        let content = format!(
            "version = 1\n{}",
            entry(&testdata_dir().join("ssh"), "\"ssh\"")
        );
        let result = parse(&content).unwrap().scan();
        assert_eq!(result.summary.total, 0);
        assert_eq!(result.summary.assets, 4);
        assert!(result.assets.iter().all(|a| a.asset_type == AssetType::Ssh));
    }

    #[test]
    fn scans_multiple_targets_and_merges_results() {
        let content = format!(
            "version = 1\n{}{}",
            entry(&testdata_dir().join("nested"), "\"cert\""),
            entry(&testdata_dir().join("ssh"), "\"ssh\"")
        );
        let result = parse(&content).unwrap().scan();
        assert_eq!(result.summary.total, 2);
        assert_eq!(result.summary.assets, 4);
        let paths: Vec<&str> = result
            .certificates
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        assert!(paths.iter().any(|p| p.ends_with("ldap.crt")));
        assert!(paths.iter().any(|p| p.ends_with("vpn.der")));
    }

    #[test]
    fn merges_duplicate_paths_into_one_walk() {
        let secrets_dir = testdata_dir().join("secrets");
        let content = format!(
            "version = 1\n{}{}",
            entry(&secrets_dir, "\"secret\""),
            entry(&secrets_dir, "\"jwt\"")
        );
        let inventory = parse(&content).unwrap();
        assert_eq!(inventory.target_count(), 1);
        let result = inventory.scan();
        assert!(
            result
                .assets
                .iter()
                .any(|a| a.asset_type == AssetType::Secret)
        );
        assert!(result.assets.iter().any(|a| a.asset_type == AssetType::Jwt));
    }

    #[test]
    fn missing_target_is_recorded_and_scan_continues() {
        let content = format!(
            "version = 1\n{}{}",
            entry(&testdata_dir().join("missing"), "\"cert\""),
            entry(&testdata_dir().join("nested"), "\"cert\"")
        );
        let result = parse(&content).unwrap().scan();
        assert_eq!(result.summary.total, 2);
        assert_eq!(result.summary.parse_errors, 1);
        assert!(result.errors[0].path.ends_with("missing"));
        assert!(result.errors[0].error.contains("directory not found"));
    }
}
