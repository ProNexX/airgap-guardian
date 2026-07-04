use clap::{Parser, Subcommand};
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
    /// Scan a directory for X.509 certificates and report expiration status
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
    },
    /// Print version information
    Version,
}
