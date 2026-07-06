use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("directory not found: {}", .0.display())]
    DirectoryNotFound(PathBuf),
    #[error("not a directory: {}", .0.display())]
    NotADirectory(PathBuf),
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("cannot read inventory file {}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid inventory file {}", .path.display())]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid inventory: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("cannot read policy file {}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid policy file {}", .path.display())]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid policy: {0}")]
    Invalid(String),
}
