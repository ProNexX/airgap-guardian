use anyhow::{Context, Result};

use crate::models::ScanResult;

pub fn print(result: &ScanResult) -> Result<()> {
    let output = serde_json::to_string_pretty(result).context("failed to serialize scan result")?;
    println!("{output}");
    Ok(())
}
