//! Per-run state.
//!
//! One [`DefenderContext`] is built in `main` and handed to every check. It
//! carries the report file each check appends to, when the run began, and
//! whether the operator asked for verbose output.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::Result;

/// State shared by every check in a single run.
#[derive(Debug, Clone)]
pub struct DefenderContext {
    /// File each check appends its result to.
    pub report_file: PathBuf,
    /// When the run began, used for the elapsed-time summary.
    pub start_time: SystemTime,
    /// Whether `--verbose` was passed.
    pub verbose: bool,
}

impl DefenderContext {
    /// Build a context, stamping the start time as now.
    pub fn new(report_file: PathBuf, verbose: bool) -> Self {
        Self {
            report_file,
            start_time: SystemTime::now(),
            verbose,
        }
    }

    /// Append a line to the run's report file.
    pub fn log(&self, message: &str) -> Result {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.report_file)?;
        writeln!(file, "{}", message)?;
        Ok(())
    }

    /// Print only when running with `--verbose`.
    pub fn debug(&self, message: &str) {
        if self.verbose {
            println!("[debug] {}", message);
        }
    }

    /// Wall-clock time since the run began.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed().unwrap_or(Duration::ZERO)
    }
}
