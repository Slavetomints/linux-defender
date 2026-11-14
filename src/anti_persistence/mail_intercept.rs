//! Mail intercept detection.
//!
//! Detects a Postfix content_filter intercept attack. Indicators:
//!
//! - Hidden files or directories under `/usr/local/lib/` -- filter scripts
//!   and mail archive directories dropped by the attacker
//! - Any non-empty `content_filter` in `/etc/postfix/main.cf`
//! - Any `pipe` transport in `master.cf` whose `argv=` path is a hidden file
//!   or is in a suspicious directory
//! - Immutable flags on postfix config files blocking repair
//!
//! Detection is behavioral: we do not match on specific file names. Any hidden
//! script in `/usr/local/lib/` wired into Postfix is suspicious.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::core::{Action, DefenderContext, Finding, Result, Severity, try_clear_immutable};

/// Path to the Postfix main configuration file.
const POSTFIX_MAIN: &str = "/etc/postfix/main.cf";
/// Path to the Postfix master process configuration.
const POSTFIX_MASTER: &str = "/etc/postfix/master.cf";

/// Directories where attackers drop filter scripts and mail archive stores.
const INTERCEPT_SCAN_DIRS: &[&str] = &["/usr/local/lib", "/usr/lib", "/var/lib", "/opt"];

/// Detect and remediate the postfix mail intercept attack.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking for mail intercept artifacts...");

    check_hidden_intercept_files(ctx);
    check_postfix_content_filter(ctx);
    check_postfix_master(ctx);
    check_postfix_immutable(ctx);

    ctx.log_msg("[✓] Mail intercept check complete");
    Ok(())
}

/// Scan for hidden files and directories that could be filter scripts or mail archives.
///
/// Any dot-file or dot-directory in a system lib directory has no legitimate
/// purpose. We remove them and flag them regardless of their name.
fn check_hidden_intercept_files(ctx: &DefenderContext) {
    for dir in INTERCEPT_SCAN_DIRS {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !name.starts_with('.') {
                continue;
            }

            ctx.log_evidence_file(&path);
            try_clear_immutable(&path);

            let msg_count = if path.is_dir() {
                fs::read_dir(&path)
                    .map(|d| d.filter_map(|e| e.ok()).count())
                    .unwrap_or(0)
            } else {
                0
            };
            let removed = ctx.remove_path_logged(&path);

            let detail = if path.is_dir() || msg_count > 0 {
                format!(
                    "path: {}\nitems: {}\nremoved: {}",
                    path.display(),
                    msg_count,
                    removed
                )
            } else {
                format!("path: {}\nremoved: {}", path.display(), removed)
            };

            ctx.emit(
                Finding::new(
                    Severity::Critical,
                    "mail_intercept",
                    format!(
                        "Hidden {} in {} {} — suspected mail intercept artifact",
                        if path.is_dir() { "directory" } else { "file" },
                        dir,
                        if removed { "REMOVED" } else { "FOUND" },
                    ),
                    detail,
                )
                .with_path(path.clone())
                .with_context("removed", removed.to_string())
                .with_action(Action::Manual(format!("rm -rf {}", path.display()))),
            );
        }
    }
}

/// Flag any non-empty `content_filter` wired into main.cf.
fn check_postfix_content_filter(ctx: &DefenderContext) {
    // Try postconf first; fall back to grepping main.cf directly.
    let value = Command::new("postconf")
        .args(["-h", "content_filter"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let value = if value.is_empty() {
        // Fallback: grep main.cf
        fs::read_to_string(POSTFIX_MAIN)
            .unwrap_or_default()
            .lines()
            .find(|l| l.trim_start().starts_with("content_filter"))
            .map(|l| {
                l.split_once('=')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default()
    } else {
        value
    };

    if value.is_empty() || value == "(empty)" {
        ctx.log_msg("[✓] postfix content_filter is not set");
        return;
    }

    ctx.emit(
        Finding::new(
            Severity::Critical,
            "mail_intercept",
            format!(
                "postfix content_filter is set: '{}' — all mail is being intercepted",
                value
            ),
            format!(
                "content_filter: {}\n\nEvery message postfix receives is passed to this filter. \
                 Clear it with: postconf -e 'content_filter=' && postfix reload",
                value
            ),
        )
        .with_context("content_filter", value)
        .with_action(Action::Manual(
            "postconf -e 'content_filter=' && postfix reload".to_string(),
        )),
    );
}

/// Suspicious path prefixes in a postfix pipe transport argv.
const SUSPICIOUS_PIPE_PREFIXES: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/opt/",
    "/usr/local/lib/.",
    "/usr/lib/.",
];

/// Flag suspicious pipe transports in master.cf.
fn check_postfix_master(ctx: &DefenderContext) {
    let path = Path::new(POSTFIX_MASTER);
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };

    // Look for pipe transports whose argv= points to a suspicious location.
    // We don't match on specific transport names -- any pipe to a hidden or
    // temp-dir script is a mail intercept regardless of what it's called.
    let mut suspicious_lines: Vec<String> = Vec::new();
    let mut in_pipe_service = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        // A service line (not indented) resets context.
        if !line.starts_with(' ')
            && !line.starts_with('\t')
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
        {
            in_pipe_service = trimmed
                .split_whitespace()
                .nth(7)
                .map(|t| t == "pipe")
                .unwrap_or(false);
        }
        if in_pipe_service && trimmed.contains("argv=") {
            let after_argv = trimmed.split("argv=").nth(1).unwrap_or("");
            let prefix_hit = SUSPICIOUS_PIPE_PREFIXES
                .iter()
                .any(|p| after_argv.contains(p));
            // Also flag any pipe argv whose executable basename starts with '.' --
            // that's a hidden file regardless of which directory it's in.
            let hidden_basename = after_argv
                .split_whitespace()
                .next()
                .map(|exe| {
                    exe.rsplit('/')
                        .next()
                        .map(|b| b.starts_with('.') && b.len() > 1)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if prefix_hit || hidden_basename {
                suspicious_lines.push(line.to_string());
            }
        }
    }

    if suspicious_lines.is_empty() {
        ctx.log_msg("[✓] postfix master.cf: no suspicious pipe transports");
        return;
    }

    for line in &suspicious_lines {
        ctx.log_evidence_line(POSTFIX_MASTER, line);
    }

    ctx.emit(
        Finding::new(
            Severity::Critical,
            "mail_intercept",
            format!(
                "postfix master.cf: {} suspicious pipe transport(s) pointing to hidden/temp paths",
                suspicious_lines.len()
            ),
            format!(
                "file: {}\nlines:\n  {}\n\nRemove these transport entries from master.cf, then: postfix reload",
                POSTFIX_MASTER,
                suspicious_lines.join("\n  ")
            ),
        )
        .with_path(path.to_path_buf())
        .with_action(Action::Manual(
            "Edit /etc/postfix/master.cf and remove suspicious pipe transport entries, then: postfix reload"
                .to_string(),
        )),
    );
}

/// Clear and report immutable flags on Postfix configs.
fn check_postfix_immutable(ctx: &DefenderContext) {
    for config in [POSTFIX_MAIN, POSTFIX_MASTER] {
        let path = Path::new(config);
        if !path.exists() {
            continue;
        }

        let lsattr = Command::new("lsattr")
            .arg(config)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let is_immutable = lsattr
            .split_whitespace()
            .next()
            .map(|flags| flags.contains('i'))
            .unwrap_or(false);

        if !is_immutable {
            continue;
        }

        try_clear_immutable(path);

        ctx.emit(
            Finding::new(
                Severity::High,
                "mail_intercept",
                format!(
                    "postfix config {} is immutable (+i) — blocks mail intercept repair",
                    config
                ),
                format!(
                    "file: {}\n\nThe immutable flag prevents editing the postfix configuration \
                     to remove the content_filter. Cleared with chattr -i.",
                    config
                ),
            )
            .with_path(path.to_path_buf())
            .with_action(Action::Manual(format!("chattr -i {}", config))),
        );
    }
}
