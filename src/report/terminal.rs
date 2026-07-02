use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

use crate::models::{CertificateInfo, CertificateStatus, ScanResult};

pub fn print(result: &ScanResult) {
    if result.certificates.is_empty() {
        println!("No certificates found.");
    } else {
        println!("{}", build_table(&result.certificates));
    }
    print_errors(result);
    print_summary(result);
}

fn build_table(certificates: &[CertificateInfo]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["File", "Status", "Remaining", "Expires"]);
    for cert in certificates {
        table.add_row(vec![
            Cell::new(&cert.path),
            status_cell(cert.status),
            Cell::new(format!("{} days", cert.days_remaining)),
            Cell::new(cert.not_after.format("%Y-%m-%d")),
        ]);
    }
    table
}

// comfy-table (crossterm) naming: `DarkRed` is standard red, `Red` is bright red.
fn status_cell(status: CertificateStatus) -> Cell {
    let color = match status {
        CertificateStatus::Ok => Color::DarkGreen,
        CertificateStatus::Warning => Color::DarkYellow,
        CertificateStatus::Critical => Color::DarkRed,
        CertificateStatus::Expired => Color::Red,
    };
    Cell::new(status).fg(color)
}

fn print_errors(result: &ScanResult) {
    if result.errors.is_empty() {
        return;
    }
    println!();
    println!("Parse errors:");
    for failure in &result.errors {
        println!("  {}: {}", failure.path.bright_red(), failure.error);
    }
}

fn print_summary(result: &ScanResult) {
    let s = &result.summary;
    println!();
    println!("Certificates scanned: {}", s.total);
    println!("OK: {}", s.ok);
    println!("Warning: {}", s.warning);
    println!("Critical: {}", s.critical);
    println!("Expired: {}", s.expired);
    println!("Parse errors: {}", s.parse_errors);
}
