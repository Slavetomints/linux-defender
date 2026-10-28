//! Deploy hardened system configurations.
//!
//! Applies targeted changes to `sshd_config`, kernel parameters via `sysctl`,
//! and cron access controls. Every change is logged before and after so the
//! operator can verify what happened and roll back if needed.

use std::path::Path;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Hardened sshd_config key-value pairs to enforce.
const SSH_SETTINGS: &[(&str, &str)] = &[
    ("PermitRootLogin", "no"),
    ("MaxAuthTries", "3"),
    ("LoginGraceTime", "30"),
    ("X11Forwarding", "no"),
    ("AllowAgentForwarding", "no"),
];

/// Kernel hardening parameters written as a sysctl drop-in.
const SYSCTL_CONF: &str = "net.ipv4.tcp_syncookies = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
kernel.dmesg_restrict = 1\n\
fs.protected_hardlinks = 1\n\
fs.protected_symlinks = 1\n\
kernel.yama.ptrace_scope = 1\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv6.conf.all.accept_redirects = 0\n";

/// Path to the main SSH daemon configuration file.
const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";

/// Path for the sysctl hardening drop-in file.
const SYSCTL_CONF_PATH: &str = "/etc/sysctl.d/99-defender-hardening.conf";

/// Apply or update a single `key value` directive in an sshd_config-format string.
///
/// If a line matching `key` already exists (commented out or active), it is
/// replaced with the new directive. If no such line exists, the directive is
/// appended. Duplicate occurrences after the first are silently dropped.
pub(crate) fn apply_ssh_setting(contents: &str, key: &str, value: &str) -> String {
    let directive = format!("{} {}", key, value);
    let mut found = false;
    let mut output = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        let stripped = trimmed.trim_start_matches('#').trim();
        // Match both active and commented-out versions of this directive.
        // Check that the next character after the key is a delimiter (space, =, or EOL)
        // so we don't match "PermitRootLoginWithCert" when seeking "PermitRootLogin".
        if let Some(rest) = stripped.strip_prefix(key) {
            let is_this_key =
                rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace() || c == '=');
            if is_this_key {
                if !found {
                    output.push_str(&directive);
                    output.push('\n');
                    found = true;
                }
                // Drop duplicate occurrences.
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }

    if !found {
        output.push_str(&directive);
        output.push('\n');
    }

    output
}

/// Apply all SSH hardening settings from [`SSH_SETTINGS`] to a config string.
pub(crate) fn apply_all_ssh_settings(contents: &str) -> String {
    let mut result = contents.to_string();
    for &(key, value) in SSH_SETTINGS {
        result = apply_ssh_setting(&result, key, value);
    }
    result
}

/// Harden `/etc/ssh/sshd_config` and reload the SSH daemon.
fn harden_sshd(ctx: &DefenderContext) {
    ctx.log_msg("[+] Hardening sshd_config...");

    let path = Path::new(SSHD_CONFIG_PATH);
    let Ok(original) = std::fs::read_to_string(path) else {
        ctx.log_msg("[!] Could not read /etc/ssh/sshd_config — skipping SSH hardening");
        return;
    };

    ctx.log_evidence_line(
        SSHD_CONFIG_PATH,
        "(original config captured before hardening)",
    );

    let hardened = apply_all_ssh_settings(&original);

    if hardened == original {
        ctx.emit(Finding::new(
            Severity::Info,
            "configs",
            "sshd_config already has all hardened settings",
            "No changes were needed.",
        ));
        return;
    }

    ctx.log_evidence_line(SSHD_CONFIG_PATH, "(writing hardened config)");

    if let Err(e) = std::fs::write(path, &hardened) {
        ctx.log_msg(&format!("[!] Failed to write {}: {}", SSHD_CONFIG_PATH, e));
        return;
    }
    ctx.log_msg(&format!("[+] Wrote hardened {}", SSHD_CONFIG_PATH));

    // Reload — the daemon may be named sshd or ssh depending on the distro.
    let reloaded = ctx.run_remediation(&["systemctl", "reload", "sshd"])
        || ctx.run_remediation(&["systemctl", "reload", "ssh"]);

    let applied_settings: Vec<String> = SSH_SETTINGS
        .iter()
        .map(|(k, v)| format!("{} {}", k, v))
        .collect();

    ctx.emit(
        Finding::new(
            Severity::High,
            "configs",
            format!(
                "Hardened sshd_config ({} settings applied)",
                SSH_SETTINGS.len()
            ),
            format!(
                "Applied: {}\nSSH daemon reload: {}",
                applied_settings.join(", "),
                if reloaded {
                    "OK"
                } else {
                    "failed — restart sshd manually"
                }
            ),
        )
        .with_context("path", SSHD_CONFIG_PATH)
        .with_context("reloaded", if reloaded { "true" } else { "false" }),
    );
}

/// Write the sysctl hardening drop-in and apply it immediately.
fn harden_sysctl(ctx: &DefenderContext) {
    ctx.log_msg("[+] Writing sysctl hardening configuration...");

    let path = Path::new(SYSCTL_CONF_PATH);
    if let Err(e) = std::fs::write(path, SYSCTL_CONF) {
        ctx.log_msg(&format!("[!] Failed to write {}: {}", SYSCTL_CONF_PATH, e));
        return;
    }
    ctx.log_msg(&format!("[+] Wrote {}", SYSCTL_CONF_PATH));

    let applied = ctx.run_remediation(&["sysctl", "-p", SYSCTL_CONF_PATH]);

    ctx.emit(
        Finding::new(
            Severity::High,
            "configs",
            format!("Deployed sysctl hardening to {}", SYSCTL_CONF_PATH),
            format!(
                "Wrote kernel hardening parameters (syncookies, rp_filter, ptrace_scope, etc.). \
                 Applied immediately: {}",
                if applied {
                    "yes"
                } else {
                    "no — run `sysctl -p` manually"
                }
            ),
        )
        .with_context("path", SYSCTL_CONF_PATH)
        .with_context("applied", if applied { "true" } else { "false" }),
    );
}

/// Restrict cron access so only root can schedule jobs.
fn harden_cron(ctx: &DefenderContext) {
    ctx.log_msg("[+] Hardening cron access control...");

    let allow_path = Path::new("/etc/cron.allow");
    if !allow_path.exists() {
        match std::fs::write(allow_path, "root\n") {
            Ok(()) => {
                ctx.log_msg("[+] Created /etc/cron.allow with 'root'");
                ctx.emit(Finding::new(
                    Severity::High,
                    "configs",
                    "Created /etc/cron.allow — only root may schedule cron jobs",
                    "When cron.allow exists, only listed users can use crontab. \
                     Restricting to root-only prevents attacker-scheduled persistence.",
                ));
            }
            Err(e) => {
                ctx.log_msg(&format!("[!] Failed to write /etc/cron.allow: {}", e));
            }
        }
    } else {
        ctx.emit(Finding::new(
            Severity::Info,
            "configs",
            "/etc/cron.allow already exists — no change made",
            "Review the file to ensure only expected users are listed.",
        ));
    }

    // Truncate /etc/cron.deny if it exists and is non-empty.
    // Deleting it would change semantics (absent deny = deny none).
    let deny_path = Path::new("/etc/cron.deny");
    if deny_path.exists() {
        let content = std::fs::read_to_string(deny_path).unwrap_or_default();
        if !content.trim().is_empty() {
            ctx.log_evidence_line(
                "/etc/cron.deny",
                &format!("(original content before truncation: {})", content.trim()),
            );
            match std::fs::write(deny_path, "") {
                Ok(()) => {
                    ctx.log_msg("[+] Truncated /etc/cron.deny (cron.allow takes precedence)");
                    ctx.emit(Finding::new(
                        Severity::High,
                        "configs",
                        "Truncated /etc/cron.deny",
                        "cron.deny was non-empty. Truncated (not deleted) since cron.allow \
                         now controls access. Deleting cron.deny would change its semantics.",
                    ));
                }
                Err(e) => {
                    ctx.log_msg(&format!("[!] Failed to truncate /etc/cron.deny: {}", e));
                }
            }
        }
    }
}

/// Deploy hardened configurations for SSH, sysctl, and cron.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Deploying hardened configurations...");
    harden_sshd(ctx);
    harden_sysctl(ctx);
    harden_cron(ctx);
    ctx.log_msg("[✓] Configuration hardening complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal sshd_config with default (insecure) values for all hardened keys.
    const SAMPLE_SSHD_CONFIG: &str = "# OpenSSH server configuration\n\
Port 22\n\
AddressFamily any\n\
ListenAddress 0.0.0.0\n\
\n\
PermitRootLogin yes\n\
MaxAuthTries 6\n\
LoginGraceTime 120\n\
X11Forwarding yes\n\
AllowAgentForwarding yes\n";

    #[test]
    fn apply_ssh_setting_replaces_active_value() {
        let result = apply_ssh_setting(SAMPLE_SSHD_CONFIG, "PermitRootLogin", "no");
        assert!(result.contains("PermitRootLogin no"));
        assert!(!result.contains("PermitRootLogin yes"));
    }

    #[test]
    fn apply_ssh_setting_replaces_commented_out_directive() {
        let config = "# PermitRootLogin yes\nPort 22\n";
        let result = apply_ssh_setting(config, "PermitRootLogin", "no");
        assert!(result.contains("PermitRootLogin no"));
        assert!(!result.contains("# PermitRootLogin"));
    }

    #[test]
    fn apply_ssh_setting_appends_when_absent() {
        let config = "Port 22\n";
        let result = apply_ssh_setting(config, "PermitRootLogin", "no");
        assert!(result.contains("PermitRootLogin no"));
        assert!(result.contains("Port 22"));
    }

    #[test]
    fn apply_all_ssh_settings_applies_every_key() {
        let result = apply_all_ssh_settings(SAMPLE_SSHD_CONFIG);
        assert!(result.contains("PermitRootLogin no"));
        assert!(result.contains("MaxAuthTries 3"));
        assert!(result.contains("LoginGraceTime 30"));
        assert!(result.contains("X11Forwarding no"));
        assert!(result.contains("AllowAgentForwarding no"));
    }

    #[test]
    fn apply_all_ssh_settings_preserves_unrelated_directives() {
        let result = apply_all_ssh_settings(SAMPLE_SSHD_CONFIG);
        assert!(result.contains("Port 22"));
        assert!(result.contains("ListenAddress 0.0.0.0"));
        assert!(result.contains("AddressFamily any"));
    }

    #[test]
    fn apply_ssh_setting_idempotent() {
        // Applying the same setting twice must not create duplicate lines.
        let config = "PermitRootLogin yes\n";
        let once = apply_ssh_setting(config, "PermitRootLogin", "no");
        let twice = apply_ssh_setting(&once, "PermitRootLogin", "no");
        let count = twice
            .lines()
            .filter(|l| l.contains("PermitRootLogin"))
            .count();
        assert_eq!(
            count, 1,
            "expected exactly one PermitRootLogin line, got:\n{}",
            twice
        );
    }

    #[test]
    fn apply_ssh_setting_on_empty_config() {
        let result = apply_ssh_setting("", "PermitRootLogin", "no");
        assert!(result.contains("PermitRootLogin no"));
    }

    #[test]
    fn sysctl_conf_contains_all_expected_parameters() {
        assert!(SYSCTL_CONF.contains("tcp_syncookies"));
        assert!(SYSCTL_CONF.contains("rp_filter"));
        assert!(SYSCTL_CONF.contains("ptrace_scope"));
        assert!(SYSCTL_CONF.contains("dmesg_restrict"));
        assert!(SYSCTL_CONF.contains("accept_redirects"));
        assert!(SYSCTL_CONF.contains("protected_hardlinks"));
        assert!(SYSCTL_CONF.contains("protected_symlinks"));
    }

    #[test]
    fn apply_ssh_setting_does_not_match_prefix_of_longer_key() {
        // "PermitRootLogin" must not accidentally match "PermitRootLoginWithCert".
        let config = "PermitRootLoginWithCert yes\nPort 22\n";
        let result = apply_ssh_setting(config, "PermitRootLogin", "no");
        // The longer key must be preserved unchanged.
        assert!(result.contains("PermitRootLoginWithCert yes"));
        // The target key must be appended (it was absent).
        assert!(result.contains("PermitRootLogin no"));
    }
}
