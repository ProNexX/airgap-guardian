mod cli;
mod errors;
mod models;
mod report;
mod scanner;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use cli::{Cli, Command};
use errors::ScanError;
use models::ScanResult;
use scanner::Scanner;
use scanner::cert::CertificateScanner;

const EXIT_OK: u8 = 0;
const EXIT_WARNING: u8 = 1;
const EXIT_CRITICAL: u8 = 2;
const EXIT_EXPIRED: u8 = 3;
const EXIT_USAGE: u8 = 4;
const EXIT_DIRECTORY_NOT_FOUND: u8 = 5;
const EXIT_RUNTIME_ERROR: u8 = 6;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => EXIT_OK,
                _ => EXIT_USAGE,
            };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };

    match cli.command {
        Command::Scan { directory, json } => run_scan(directory, json),
        Command::Version => {
            println!("airgap-guardian {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(EXIT_OK)
        }
    }
}

fn run_scan(directory: PathBuf, json: bool) -> ExitCode {
    let result = match CertificateScanner::new(directory).scan() {
        Ok(result) => result,
        Err(e) => return report_failure(&e),
    };

    if json {
        if let Err(e) = report::json::print(&result) {
            return report_failure(&e);
        }
    } else {
        report::terminal::print(&result);
    }

    ExitCode::from(severity_exit_code(&result))
}

fn report_failure(error: &anyhow::Error) -> ExitCode {
    eprintln!("Error: {error:#}");
    let code = match error.downcast_ref::<ScanError>() {
        Some(ScanError::DirectoryNotFound(_) | ScanError::NotADirectory(_)) => {
            EXIT_DIRECTORY_NOT_FOUND
        }
        None => EXIT_RUNTIME_ERROR,
    };
    ExitCode::from(code)
}

fn severity_exit_code(result: &ScanResult) -> u8 {
    let s = &result.summary;
    if s.expired > 0 {
        EXIT_EXPIRED
    } else if s.critical > 0 {
        EXIT_CRITICAL
    } else if s.warning > 0 || s.parse_errors > 0 {
        EXIT_WARNING
    } else {
        EXIT_OK
    }
}
