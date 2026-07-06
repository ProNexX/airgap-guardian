mod analysis;
mod cli;
mod discover;
mod errors;
mod inventory;
mod models;
mod policy;
mod report;
mod scanner;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use cli::{Cli, Command, ScannerKind};
use errors::{InventoryError, PolicyError, ScanError};
use inventory::Inventory;
use models::ScanResult;
use policy::Policy;
use scanner::Scanner;

const EXIT_OK: u8 = 0;
const EXIT_WARNING: u8 = 1;
const EXIT_CRITICAL: u8 = 2;
const EXIT_EXPIRED: u8 = 3;
const EXIT_USAGE: u8 = 4;
const EXIT_DIRECTORY_NOT_FOUND: u8 = 5;
const EXIT_RUNTIME_ERROR: u8 = 6;
const EXIT_POLICY_ERROR: u8 = 7;

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
        Command::Scan {
            directory,
            inventory,
            json,
            html,
            policy,
            scanners,
        } => run_scan(directory, inventory, json, html, policy, &scanners),
        Command::Discover {
            directory,
            output,
            json,
            follow_symlinks,
            max_depth,
        } => run_discover(directory, output, json, follow_symlinks, max_depth),
        Command::Inventory {
            directory,
            json,
            html,
        } => run_inventory(directory, json, html),
        Command::Version => {
            println!("airgap-guardian {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(EXIT_OK)
        }
    }
}

fn run_scan(
    directory: Option<PathBuf>,
    inventory_file: Option<PathBuf>,
    json: bool,
    html: Option<PathBuf>,
    policy_file: Option<PathBuf>,
    scanner_kinds: &[ScannerKind],
) -> ExitCode {
    let policy = match load_policy(policy_file.as_deref()) {
        Ok(policy) => policy,
        Err(e) => return report_failure(&e.into()),
    };

    let (mut result, inventory) = if let Some(file) = inventory_file {
        let inventory = match Inventory::load(&file) {
            Ok(inventory) => inventory,
            Err(e) => return report_failure(&e.into()),
        };
        (inventory.scan(), Some(inventory))
    } else if let Some(directory) = directory {
        let scanners = build_scanners(scanner_kinds);
        match scanner::scan_directory(&directory, &scanners) {
            Ok(result) => (result, None),
            Err(e) => return report_failure(&e),
        }
    } else {
        unreachable!("clap requires either a directory or --inventory");
    };
    analysis::analyze(&mut result, &policy);

    if json {
        if let Err(e) = report::json::print(&result, &policy, inventory.as_ref()) {
            return report_failure(&e);
        }
    } else {
        if let Some(inventory) = &inventory {
            println!("Loaded inventory: {}", inventory.source().display());
            println!("Targets: {}", inventory.target_count());
            println!();
        }
        report::terminal::print(&result);
    }

    if let Some(path) = html {
        if let Err(e) = report::html::write(&result, &policy, inventory.as_ref(), &path) {
            return report_failure(&e);
        }
        eprintln!("HTML report written to {}", path.display());
    }

    ExitCode::from(severity_exit_code(&result))
}

fn run_discover(
    directory: PathBuf,
    output: PathBuf,
    json: bool,
    follow_symlinks: bool,
    max_depth: Option<usize>,
) -> ExitCode {
    let options = discover::Options {
        follow_symlinks,
        max_depth,
    };
    let discovery = match discover::discover(&directory, &options) {
        Ok(discovery) => discovery,
        Err(e) => return report_failure(&e),
    };
    for failure in &discovery.errors {
        eprintln!("Warning: {}: {}", failure.path, failure.error);
    }

    if json {
        match discover::to_json(&discovery) {
            Ok(report) => println!("{report}"),
            Err(e) => return report_failure(&e),
        }
    } else {
        discover::print_terminal(&discovery);
    }

    let inventory = match discover::to_toml(&discovery) {
        Ok(inventory) => inventory,
        Err(e) => return report_failure(&e),
    };
    if let Err(e) = std::fs::write(&output, inventory) {
        let error = anyhow::Error::new(e)
            .context(format!("cannot write inventory file {}", output.display()));
        return report_failure(&error);
    }
    eprintln!("Inventory written to {}", output.display());
    ExitCode::from(EXIT_OK)
}

fn run_inventory(directory: PathBuf, json: bool, html: Option<PathBuf>) -> ExitCode {
    let policy = Policy::default();
    let scanners = build_scanners(&[]);
    let mut result = match scanner::scan_directory(&directory, &scanners) {
        Ok(result) => result,
        Err(e) => return report_failure(&e),
    };
    analysis::analyze(&mut result, &policy);

    if json {
        if let Err(e) = report::inventory::print_json(&result) {
            return report_failure(&e);
        }
    } else {
        report::inventory::print(&result);
    }

    if let Some(path) = html {
        if let Err(e) = report::html::write(&result, &policy, None, &path) {
            return report_failure(&e);
        }
        eprintln!("HTML report written to {}", path.display());
    }

    ExitCode::from(EXIT_OK)
}

fn build_scanners(kinds: &[ScannerKind]) -> Vec<Box<dyn Scanner>> {
    let kinds = if kinds.is_empty() {
        &ScannerKind::ALL[..]
    } else {
        kinds
    };
    scanner::build_scanners(kinds.iter().map(|kind| kind.asset_type()))
}

fn load_policy(path: Option<&std::path::Path>) -> Result<Policy, PolicyError> {
    match path {
        Some(path) => Policy::load(path),
        None => Ok(Policy::default()),
    }
}

fn report_failure(error: &anyhow::Error) -> ExitCode {
    eprintln!("Error: {error:#}");
    let code = if let Some(scan_error) = error.downcast_ref::<ScanError>() {
        match scan_error {
            ScanError::DirectoryNotFound(_) | ScanError::NotADirectory(_) => {
                EXIT_DIRECTORY_NOT_FOUND
            }
        }
    } else if error.downcast_ref::<PolicyError>().is_some()
        || error.downcast_ref::<InventoryError>().is_some()
    {
        EXIT_POLICY_ERROR
    } else {
        EXIT_RUNTIME_ERROR
    };
    ExitCode::from(code)
}

fn severity_exit_code(result: &ScanResult) -> u8 {
    let s = &result.summary;
    if s.expired > 0 {
        EXIT_EXPIRED
    } else if s.critical > 0 || s.asset_critical > 0 {
        EXIT_CRITICAL
    } else if s.warning > 0 || s.asset_warning > 0 || s.parse_errors > 0 {
        EXIT_WARNING
    } else {
        EXIT_OK
    }
}
