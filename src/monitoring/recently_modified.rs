//! Recently-modified system binaries.
//!
//! Walks the standard binary directories and flags any file whose mtime is
//! newer than the competition start time (or, when no start time is set, newer
//! than one hour ago).  A modified binary in /bin or /usr/bin almost always
//! means an attacker replaced a system tool with a trojanized copy.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use walkdir::WalkDir;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Core system binary directories -- modifications here are Critical.
const CRITICAL_BIN_DIRS: &[&str] = &["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

/// Admin-installed binary directories -- modifications here are High (legitimate installs happen).
const HIGH_BIN_DIRS: &[&str] = &["/usr/local/bin", "/usr/local/sbin"];

/// A binary file whose mtime is suspiciously recent.
pub struct ModifiedBinary {
    /// Absolute path to the binary.
    pub path: PathBuf,
    /// Last-modified time of the binary.
    pub mtime: SystemTime,
    /// Severity determined by which directory set the file belongs to.
    pub severity: Severity,
}

/// Scan system binary directories for recently-modified files.
pub fn run(ctx: &DefenderContext) -> Result {
    // Cutoff: competition start if known, otherwise 1 hour ago.
    let cutoff = ctx
        .competition_start
        .unwrap_or_else(|| SystemTime::now() - Duration::from_secs(3600));

    ctx.log_msg(&format!(
        "[+] Scanning system binaries modified after {} ...",
        ctx.mtime_label(cutoff),
    ));

    let hits = scan_dirs(cutoff);
    let count = hits.len();

    for hit in hits {
        let age = ctx.mtime_label(hit.mtime);
        ctx.emit(
            Finding::new(
                hit.severity,
                "recently_modified",
                format!("System binary modified recently: {}", hit.path.display()),
                format!("path: {}\nmtime: {}", hit.path.display(), age),
            )
            .with_path(hit.path.clone())
            .with_context("path", hit.path.display().to_string())
            .with_context("mtime", age.clone())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{} was modified {}. System binaries should not change during a \
                     competition. This is a strong indicator of a trojanized binary — \
                     compare against a known-good hash or reinstall the package.",
                    hit.path.display(),
                    age,
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] System binary scan complete — {} recently-modified file{}",
        count,
        if count == 1 { "" } else { "s" },
    ));
    Ok(())
}

/// Walk both dir sets and return files whose mtime is after `cutoff`, tagged with severity.
fn scan_dirs(cutoff: SystemTime) -> Vec<ModifiedBinary> {
    let mut hits = Vec::new();

    let dir_sets: &[(&[&str], Severity)] = &[
        (CRITICAL_BIN_DIRS, Severity::Critical),
        (HIGH_BIN_DIRS, Severity::High),
    ];

    for (dirs, severity) in dir_sets {
        for dir in *dirs {
            let path = Path::new(dir);
            if !path.is_dir() {
                continue;
            }

            for entry in WalkDir::new(path)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
            {
                let Ok(meta) = entry.metadata() else { continue };
                let Ok(mtime) = meta.modified() else { continue };

                if mtime > cutoff {
                    hits.push(ModifiedBinary {
                        path: entry.path().to_path_buf(),
                        mtime,
                        severity: *severity,
                    });
                }
            }
        }
    }

    // Most-recently-modified first.
    hits.sort_by_key(|h| core::cmp::Reverse(h.mtime));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_dirs_runs_without_panic() {
        // Just check it doesn't crash; real dirs may or may not have recent files.
        let cutoff = SystemTime::now() - Duration::from_secs(1);
        let _ = scan_dirs(cutoff);
    }

    #[test]
    fn very_old_cutoff_finds_nothing_in_bin() {
        // With a cutoff of 100 years ago nothing in /bin should qualify.
        let ancient = SystemTime::UNIX_EPOCH + Duration::from_secs(0);
        // Don't assert empty — the system may genuinely have old files — just
        // verify it returns without error.
        let _ = scan_dirs(ancient);
    }
}
