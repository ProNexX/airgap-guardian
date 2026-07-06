use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use walkdir::DirEntry;

use crate::models::{AssetType, ParseFailure};
use crate::scanner::{jwt, secrets, ssh, validate_root, walk};

pub const INVENTORY_VERSION: u32 = 1;

const CERT_EXTENSIONS: [&str; 8] = ["pem", "crt", "cer", "der", "p7b", "p7c", "p12", "pfx"];
const SSH_DIR_NAME: &str = ".ssh";
const SECRET_DIR_NAMES: [&str; 5] = ["config", "configs", "conf", "etc", "secrets"];
const SECRET_FILE_NAMES: [&str; 7] = [
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.json",
    "settings.toml",
    "docker-compose.yml",
    "kubeconfig",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub follow_symlinks: bool,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Default)]
pub struct Discovery {
    targets: BTreeMap<PathBuf, BTreeSet<AssetType>>,
    pub errors: Vec<ParseFailure>,
}

#[derive(Debug, Serialize)]
pub struct Target {
    pub path: String,
    pub scanners: Vec<AssetType>,
}

#[derive(Serialize)]
struct InventoryFile {
    version: u32,
    scan: Vec<Target>,
}

#[derive(Serialize)]
struct JsonReport {
    version: u32,
    targets: Vec<Target>,
}

impl Discovery {
    fn add(&mut self, directory: &Path, kind: AssetType) {
        self.targets
            .entry(directory.to_path_buf())
            .or_default()
            .insert(kind);
    }

    pub fn targets(&self) -> Vec<Target> {
        self.targets
            .iter()
            .map(|(path, kinds)| Target {
                path: path.display().to_string(),
                scanners: kinds.iter().copied().collect(),
            })
            .collect()
    }

    pub fn locations(&self, kind: AssetType) -> impl Iterator<Item = &Path> {
        self.targets
            .iter()
            .filter(move |(_, kinds)| kinds.contains(&kind))
            .map(|(path, _)| path.as_path())
    }
}

pub fn discover(root: &Path, options: &Options) -> Result<Discovery> {
    validate_root(root)?;
    let root = fs::canonicalize(root)
        .with_context(|| format!("cannot resolve directory {}", root.display()))?;

    let mut discovery = Discovery::default();
    for entry in walk(&root, options.follow_symlinks, options.max_depth) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                let path = e
                    .path()
                    .map_or_else(|| root.display().to_string(), |p| p.display().to_string());
                discovery.errors.push(ParseFailure {
                    path,
                    error: e.to_string(),
                });
                continue;
            }
        };
        if entry.file_type().is_dir() {
            classify_directory(entry.path(), &mut discovery);
        } else if entry.file_type().is_file() {
            classify_file(&entry, &mut discovery);
        }
    }
    Ok(discovery)
}

fn classify_directory(path: &Path, discovery: &mut Discovery) {
    let Some(name) = file_name(path) else {
        return;
    };
    if name == SSH_DIR_NAME {
        discovery.add(path, AssetType::Ssh);
    } else if SECRET_DIR_NAMES.contains(&name) {
        discovery.add(path, AssetType::Secret);
    }
}

fn classify_file(entry: &DirEntry, discovery: &mut Discovery) {
    let path = entry.path();
    let (Some(parent), Some(name)) = (path.parent(), file_name(path)) else {
        return;
    };
    let is_cert = has_cert_extension(path);
    let is_ssh = ssh::is_ssh_file(path);
    if is_cert {
        discovery.add(parent, AssetType::Cert);
    }
    if is_ssh {
        discovery.add(parent, AssetType::Ssh);
    }
    if is_secret_file(name) {
        discovery.add(parent, AssetType::Secret);
    }
    let size = entry.metadata().map_or(u64::MAX, |m| m.len());
    if !is_cert && !is_ssh && size < secrets::MAX_FILE_SIZE && probe_jwt(path, discovery) {
        discovery.add(parent, AssetType::Jwt);
    }
}

fn probe_jwt(path: &Path, discovery: &mut Discovery) -> bool {
    match fs::read(path) {
        Ok(data) => std::str::from_utf8(&data).is_ok_and(jwt::contains_token),
        Err(e) => {
            discovery.errors.push(ParseFailure {
                path: path.display().to_string(),
                error: format!("cannot read file: {e}"),
            });
            false
        }
    }
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

fn has_cert_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| CERT_EXTENSIONS.iter().any(|c| ext.eq_ignore_ascii_case(c)))
}

fn is_secret_file(name: &str) -> bool {
    name.ends_with(".env") || SECRET_FILE_NAMES.contains(&name)
}

pub fn to_toml(discovery: &Discovery) -> Result<String> {
    toml::to_string(&InventoryFile {
        version: INVENTORY_VERSION,
        scan: discovery.targets(),
    })
    .map_err(|e| anyhow!(e).context("failed to serialize inventory"))
}

pub fn to_json(discovery: &Discovery) -> Result<String> {
    serde_json::to_string_pretty(&JsonReport {
        version: INVENTORY_VERSION,
        targets: discovery.targets(),
    })
    .context("failed to serialize discovery result")
}

const SECTIONS: [(AssetType, &str); 4] = [
    (AssetType::Cert, "Certificates"),
    (AssetType::Ssh, "SSH"),
    (AssetType::Secret, "Secrets"),
    (AssetType::Jwt, "JWT"),
];

pub fn print_terminal(discovery: &Discovery) {
    println!("Discovered Scan Targets");
    for (kind, title) in SECTIONS {
        let mut locations = discovery.locations(kind).peekable();
        if locations.peek().is_none() {
            continue;
        }
        println!();
        println!("{title}");
        for path in locations {
            println!("  {}", path.display());
        }
    }
    println!();
    println!("Summary");
    println!();
    println!(
        "Certificate locations : {}",
        discovery.locations(AssetType::Cert).count()
    );
    println!(
        "SSH locations         : {}",
        discovery.locations(AssetType::Ssh).count()
    );
    println!(
        "Secret locations      : {}",
        discovery.locations(AssetType::Secret).count()
    );
    println!(
        "JWT locations         : {}",
        discovery.locations(AssetType::Jwt).count()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::testdata_dir;

    fn discover_testdata() -> Discovery {
        discover(&testdata_dir(), &Options::default()).expect("discover should succeed")
    }

    fn scanners_for<'a>(targets: &'a [Target], dir_suffix: &str) -> &'a [AssetType] {
        &targets
            .iter()
            .find(|t| t.path.ends_with(dir_suffix))
            .unwrap_or_else(|| panic!("{dir_suffix} should be a target"))
            .scanners
    }

    #[test]
    fn discovers_targets_by_asset_type() {
        let discovery = discover_testdata();
        let targets = discovery.targets();

        assert_eq!(scanners_for(&targets, "testdata"), [AssetType::Cert]);
        assert_eq!(scanners_for(&targets, "testdata/nested"), [AssetType::Cert]);
        assert_eq!(scanners_for(&targets, "testdata/ssh"), [AssetType::Ssh]);
        assert_eq!(
            scanners_for(&targets, "testdata/secrets"),
            [AssetType::Secret, AssetType::Jwt]
        );
    }

    #[test]
    fn targets_are_sorted_and_unique() {
        let targets = discover_testdata().targets();
        let paths: Vec<&str> = targets.iter().map(|t| t.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(paths, sorted);
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn max_depth_limits_discovery() {
        let discovery = discover(
            &testdata_dir(),
            &Options {
                follow_symlinks: false,
                max_depth: Some(1),
            },
        )
        .expect("discover should succeed");
        let targets = discovery.targets();
        assert!(!targets.iter().any(|t| t.path.ends_with("nested")));
        assert!(targets.iter().any(|t| t.path.ends_with("testdata")));
    }

    #[test]
    fn classifies_ssh_and_secret_directories_by_name() {
        let mut discovery = Discovery::default();
        classify_directory(Path::new("/home/alice/.ssh"), &mut discovery);
        classify_directory(Path::new("/opt/app/secrets"), &mut discovery);
        classify_directory(Path::new("/opt/app/src"), &mut discovery);
        let targets = discovery.targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, "/home/alice/.ssh");
        assert_eq!(targets[0].scanners, [AssetType::Ssh]);
        assert_eq!(targets[1].path, "/opt/app/secrets");
        assert_eq!(targets[1].scanners, [AssetType::Secret]);
    }

    #[test]
    fn recognizes_secret_file_names() {
        assert!(is_secret_file(".env"));
        assert!(is_secret_file("production.env"));
        assert!(is_secret_file("config.json"));
        assert!(is_secret_file("docker-compose.yml"));
        assert!(is_secret_file("kubeconfig"));
        assert!(!is_secret_file("main.rs"));
        assert!(!is_secret_file("environment"));
    }

    #[test]
    fn recognizes_certificate_extensions() {
        for name in ["a.pem", "a.CRT", "a.p7b", "a.p7c", "a.p12", "a.PFX"] {
            assert!(has_cert_extension(Path::new(name)), "{name}");
        }
        assert!(!has_cert_extension(Path::new("a.txt")));
        assert!(!has_cert_extension(Path::new("pem")));
    }

    #[test]
    fn serializes_inventory_toml() {
        let mut discovery = Discovery::default();
        discovery.add(Path::new("/opt/app"), AssetType::Jwt);
        discovery.add(Path::new("/opt/app"), AssetType::Cert);
        discovery.add(Path::new("/etc/ssl"), AssetType::Cert);
        let toml = to_toml(&discovery).expect("serialization should succeed");
        assert_eq!(
            toml,
            "version = 1\n\n\
             [[scan]]\n\
             path = \"/etc/ssl\"\n\
             scanners = [\"cert\"]\n\n\
             [[scan]]\n\
             path = \"/opt/app\"\n\
             scanners = [\"cert\", \"jwt\"]\n"
        );
    }

    #[test]
    fn serializes_discovery_json() {
        let mut discovery = Discovery::default();
        discovery.add(Path::new("/etc/ssl"), AssetType::Cert);
        let json = to_json(&discovery).expect("serialization should succeed");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["targets"][0]["path"], "/etc/ssl");
        assert_eq!(value["targets"][0]["scanners"][0], "cert");
    }

    #[test]
    fn missing_directory_is_an_error() {
        assert!(discover(&testdata_dir().join("does-not-exist"), &Options::default()).is_err());
    }
}
