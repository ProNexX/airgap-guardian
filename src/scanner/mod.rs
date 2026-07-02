pub mod cert;

use crate::models::ScanResult;
use anyhow::Result;

pub trait Scanner {
    fn scan(&self) -> Result<ScanResult>;
}
