use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("directory not found: {}", .0.display())]
    DirectoryNotFound(PathBuf),
    #[error("not a directory: {}", .0.display())]
    NotADirectory(PathBuf),
}
