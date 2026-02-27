use std::path::PathBuf;
use std::time::SystemTime;

mod privilege;

pub use privilege::require_root;

#[derive(Debug, Clone)]
pub struct DefenderContext {
    pub report_file: PathBuf,
    pub start_time: SystemTime,
    pub verbose: bool,
}

impl DefenderContext {
    pub fn new(report_file: PathBuf, verbose: bool) -> Self {
        Self {
            report_file,
            start_time: SystemTime::now(),
            verbose,
        }
    }
}