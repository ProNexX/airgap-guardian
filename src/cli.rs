use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "airgap-guardian",
    about = "Offline-first security scanner for air-gapped environments",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a directory for certificates, SSH keys, secrets, and JWT tokens
    Scan {
        /// Directory to scan recursively
        directory: PathBuf,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        /// Write a standalone HTML report to the given file
        #[arg(long, value_name = "FILE")]
        html: Option<PathBuf>,
        /// TOML policy file with security thresholds (built-in defaults if omitted)
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Comma-separated list of scanners to run (default: all)
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        scanners: Vec<ScannerKind>,
    },
    /// Print version information
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScannerKind {
    Cert,
    Ssh,
    Secrets,
    Jwt,
}

impl ScannerKind {
    pub const ALL: [Self; 4] = [Self::Cert, Self::Ssh, Self::Secrets, Self::Jwt];
}
