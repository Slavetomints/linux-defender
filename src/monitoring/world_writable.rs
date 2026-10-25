//! World-writable directories and files outside the expected locations.
//!
//! World-writable paths outside `/tmp`, `/var/tmp`, and `/dev/shm` are almost
//! always misconfigurations or attacker staging areas.  World-writable
//! *executables* or SUID binaries are immediate escalation vectors.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict};

/// Directories that are expected to be world-writable — skip them.
const EXPECTED_WRITABLE: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/shm",
    "/var/crash", // crash dumps
    "/var/metrics",
];

/// Roots to walk when searching for unexpected world-writable paths.
const SCAN_ROOTS: &[&str] = &[
    "/etc", "/bin", "/sbin", "/usr", "/opt", "/var/www", "/srv", "/home",
];

/// Scan for world-writable files and directories that could be abused by attackers.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for world-writable files and directories...");

    let (dirs, files) = scan();
    let total = dirs.len() + files.len();

    for path in &dirs {
        let is_root_owned = is_owned_by_root(path);
        let severity = if is_root_owned {
            Severity::High
        } else {
            Severity::Medium
        };
        ctx.emit(
            Finding::new(
                severity,
                "world_writable",
                format!("World-writable directory: {}", path.display()),
                format!("path: {}\nroot_owned: {}", path.display(), is_root_owned),
            )
            .with_path(path.clone())
            .with_context("path", path.display().to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{} is world-writable outside an expected temp directory. \
                     Attackers use these as staging areas. \
                     Check for recently-added files and restrict permissions with: \
                     chmod o-w {}",
                    path.display(),
                    path.display(),
                ),
            )
            .with_action(Action::Manual(format!("chmod o-w {}", path.display()))),
        );
    }

    for path in &files {
        let mode = file_mode(path);
        let is_suid = mode & 0o4000 != 0;
        let severity = if is_suid {
            Severity::Critical
        } else {
            Severity::High
        };

        let summary = if is_suid {
            format!("World-writable SUID file: {}", path.display())
        } else {
            format!("World-writable file: {}", path.display())
        };

        let recommendation = if is_suid {
            format!(
                "{} is both world-writable AND has the SUID bit set. An attacker can \
                 overwrite it with a malicious binary that runs as root. Remove the SUID \
                 bit and restrict write access immediately.",
                path.display()
            )
        } else {
            format!(
                "{} is world-writable. Anyone on the system can modify it. \
                 Restrict with: chmod o-w {}",
                path.display(),
                path.display()
            )
        };

        ctx.emit(
            Finding::new(
                severity,
                "world_writable",
                summary,
                format!("path: {}\nmode: {:04o}", path.display(), mode),
            )
            .with_path(path.clone())
            .with_context("path", path.display().to_string())
            .with_context("mode", format!("{:04o}", mode))
            .with_verdict(Verdict::Investigate, recommendation)
            .with_action(Action::Manual(format!(
                "chmod o-w {} && chmod -s {}",
                path.display(),
                path.display()
            ))),
        );
    }

    ctx.log_msg(&format!(
        "[✓] World-writable scan complete — {} unexpected path{}",
        total,
        if total == 1 { "" } else { "s" },
    ));
    Ok(())
}

/// Returns (world-writable dirs, world-writable files) outside expected locations.
fn scan() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut dirs = Vec::new();
    let mut files = Vec::new();

    for root in SCAN_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }

        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip expected world-writable locations and their contents.
            if EXPECTED_WRITABLE.iter().any(|e| path.starts_with(e)) {
                continue;
            }

            let Ok(meta) = entry.metadata() else { continue };
            let mode = meta.permissions().mode();
            let world_write = mode & 0o002 != 0;

            if !world_write {
                continue;
            }

            if meta.is_dir() {
                dirs.push(path.to_path_buf());
            } else if meta.is_file() {
                files.push(path.to_path_buf());
            }
        }
    }

    (dirs, files)
}

/// Return the raw permission bits for `path`, or 0 if metadata is unavailable.
fn file_mode(path: &Path) -> u32 {
    path.metadata().map(|m| m.permissions().mode()).unwrap_or(0)
}

/// Return true if `path` is owned by root (UID 0).
fn is_owned_by_root(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.metadata().map(|m| m.uid() == 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_runs_without_panic() {
        let _ = scan();
    }

    #[test]
    fn expected_writable_tmp_is_skipped() {
        let tmp = PathBuf::from("/tmp");
        assert!(EXPECTED_WRITABLE.iter().any(|e| tmp.starts_with(e)));
    }
}
