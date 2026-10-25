//! Systemd unit files with suspicious `ExecStart` paths.
//!
//! Flags services whose executable lives in a world-writable directory
//! (`/tmp`, `/dev/shm`, `/var/tmp`, `/home`), points to a non-existent path,
//! or contains patterns from the global suspicious-pattern list.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::scan::SUSPICIOUS_PATTERNS;
use crate::core::{DefenderContext, Finding, Result, Severity};

/// Systemd unit directories searched for service files.
const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
];

/// Directories whose presence in an `ExecStart` path is immediately suspicious.
const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/home/"];

/// A systemd unit whose `ExecStart` looks suspicious.
pub struct SuspiciousService {
    /// Path to the `.service` file.
    pub unit_file: PathBuf,
    /// The resolved `ExecStart` binary path.
    pub exec_start: String,
    /// Human-readable explanation of why it was flagged.
    pub reason: String,
}

/// Emit a finding for each systemd unit with a suspicious `ExecStart`.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning systemd unit files for suspicious ExecStart paths...");
    let found = scan_units();
    let count = found.len();

    for s in found {
        let severity = if SUSPICIOUS_DIRS.iter().any(|d| s.exec_start.starts_with(d)) {
            Severity::Critical
        } else {
            Severity::High
        };

        ctx.emit(
            Finding::new(
                severity,
                "suspicious_services",
                format!(
                    "Suspicious service in {}: ExecStart={}",
                    s.unit_file
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    s.exec_start
                ),
                format!(
                    "unit: {}\nExecStart: {}\nreason: {}",
                    s.unit_file.display(),
                    s.exec_start,
                    s.reason
                ),
            )
            .with_path(s.unit_file),
        );
    }

    ctx.log_msg(&format!(
        "[✓] Suspicious service scan complete — {} finding(s)",
        count
    ));
    Ok(())
}

/// Walk all systemd unit directories and collect suspicious service definitions.
pub fn scan_units() -> Vec<SuspiciousService> {
    let mut out = Vec::new();

    for dir in UNIT_DIRS {
        let base = Path::new(dir);
        if !base.exists() {
            continue;
        }

        for entry in WalkDir::new(base)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.ends_with(".service") {
                continue;
            }

            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };

            for exec in parse_exec_starts(&content) {
                if let Some(reason) = classify_exec(&exec, &content) {
                    out.push(SuspiciousService {
                        unit_file: path.to_path_buf(),
                        exec_start: exec,
                        reason,
                    });
                }
            }
        }
    }

    out
}

/// Extract the executable path from each `ExecStart=` line in a unit file.
fn parse_exec_starts(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("ExecStart=").map(|rest| {
                // Strip exec-specifier prefixes: -, @, +, !, !!
                let rest = rest.trim_start_matches(['-', '@', '+', '!']);
                rest.split_whitespace().next().unwrap_or("").to_string()
            })
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Return a human-readable reason string if `exec` is suspicious, otherwise `None`.
fn classify_exec(exec: &str, unit_content: &str) -> Option<String> {
    if exec.is_empty() {
        return None;
    }

    if SUSPICIOUS_DIRS.iter().any(|d| exec.starts_with(d)) {
        return Some(format!("executable in world-writable directory: {}", exec));
    }

    if !Path::new(exec).exists() {
        return Some(format!("executable does not exist on disk: {}", exec));
    }

    let reasons: Vec<&str> = SUSPICIOUS_PATTERNS
        .iter()
        .filter(|(needle, _)| unit_content.to_lowercase().contains(*needle))
        .map(|(_, why)| *why)
        .collect();

    if !reasons.is_empty() {
        return Some(format!(
            "suspicious patterns in unit: {}",
            reasons.join(", ")
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_start_simple() {
        let content = "[Service]\nExecStart=/usr/bin/sshd -D\n";
        let execs = parse_exec_starts(content);
        assert_eq!(execs, vec!["/usr/bin/sshd"]);
    }

    #[test]
    fn strips_exec_specifier_prefix() {
        let content = "ExecStart=-/usr/bin/optional\n";
        let execs = parse_exec_starts(content);
        assert_eq!(execs, vec!["/usr/bin/optional"]);
    }

    #[test]
    fn flags_tmp_exec() {
        let reason = classify_exec("/tmp/backdoor", "").unwrap();
        assert!(reason.contains("world-writable"));
    }

    #[test]
    fn flags_missing_binary() {
        let reason = classify_exec("/usr/local/bin/definitely_not_installed_xyz_abc", "").unwrap();
        assert!(reason.contains("does not exist"));
    }

    #[test]
    fn clean_binary_returns_none_when_it_exists() {
        // /bin/sh exists on any POSIX system and has no suspicious patterns.
        let result = classify_exec("/bin/sh", "[Service]\nExecStart=/bin/sh\n");
        assert!(result.is_none());
    }
}
