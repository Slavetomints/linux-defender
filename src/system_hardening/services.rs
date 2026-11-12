//! Service allow-listing and bulk-disable hardening.
//!
//! Detects which services are enabled, compares them against a per-box-type
//! allow-list, and disables anything that should not be running. Each
//! disable is prompted and verified with `systemctl is-active`.
//!
//! # Allow-lists
//!
//! All box types share a baseline: ssh/sshd, cron/crond, atd, nftables/ufw/iptables/firewalld,
//! rsyslog/syslog, auditd, fail2ban, apparmor, dbus, and all systemd-* units.
//!
//! Box-specific additions:
//! | Box type | Additional allowed services |
//! |----------|-----------------------------|
//! | Web      | nginx, apache2, httpd, php-fpm |
//! | Mail     | postfix, dovecot, roundcubemail, apache2/nginx, php-fpm, spamassassin, amavis |
//! | Splunk   | splunk, SplunkForwarder |
//! | General  | mysql/mariadb/postgresql, named/bind9 |

use std::process::Command;

use crate::core::{
    Action, BoxType, DefenderContext, DefenderError, Finding, Result, Severity, Verdict,
    detect_box_type, require_root,
};

/// Services that must never be disabled regardless of box type.
/// Disabling these would kill logging, the firewall, or audit trails mid-competition.
const BASELINE_ALLOW: &[&str] = &[
    // remote access
    "ssh", "sshd",
    // scheduling
    "cron", "crond", "atd",
    // firewall — NEVER disable; nftbuild writes rules then exits, the service keeps them loaded
    "nftables", "iptables", "ip6tables", "firewalld", "ufw",
    // logging
    "rsyslog", "syslog", "syslog-ng",
    // audit
    "auditd",
    // intrusion detection
    "fail2ban",
    // mandatory access control
    "apparmor", "selinux",
    // dbus (required by many systemd units)
    "dbus",
];

/// Services allowed on a Web box.
const WEB_ALLOW: &[&str] = &["nginx", "apache2", "httpd", "php-fpm", "php8.1-fpm", "php8.2-fpm"];

/// Services allowed on a Mail box.
const MAIL_ALLOW: &[&str] = &[
    "postfix",
    "dovecot",
    "roundcubemail",
    // roundcube needs a web server
    "apache2", "nginx", "httpd",
    "php-fpm", "php8.1-fpm", "php8.2-fpm",
    // spamassassin / amavis common on mail boxes
    "spamassassin", "amavis", "amavisd",
    // DNS resolver sometimes local on mail boxes for SPF checks
    "named", "bind9",
];

/// Services allowed on a Splunk box.
const SPLUNK_ALLOW: &[&str] = &["splunk", "SplunkForwarder"];

/// Services allowed on a General-purpose box.
const GENERAL_ALLOW: &[&str] = &[
    // common scored services that might appear on a general box
    "mysql", "mariadb", "postgresql", "mongod",
    "named", "bind9",
];

/// Return the allow-list for the given `box_type`.
pub fn allow_list(box_type: BoxType) -> &'static [&'static str] {
    match box_type {
        BoxType::Web => WEB_ALLOW,
        BoxType::Mail => MAIL_ALLOW,
        BoxType::Splunk => SPLUNK_ALLOW,
        BoxType::General => GENERAL_ALLOW,
    }
}

/// Return `true` when `service_name` is allowed on `box_type`.
pub fn is_allowed(service_name: &str, box_type: BoxType) -> bool {
    // Core systemd units are always kept on every box.
    if service_name.starts_with("systemd-") {
        return true;
    }
    // Baseline services that must never be disabled regardless of box type.
    if BASELINE_ALLOW.contains(&service_name) {
        return true;
    }
    // Box-specific services.
    allow_list(box_type).contains(&service_name)
}

/// Disable services that are not on the allow-list for this box's type.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if !ctx.in_tui() {
            eprintln!("[!] Not running as root — services hardening skipped");
        }
        ctx.emit(Finding::new(
            Severity::Medium,
            "services",
            "Not running as root — services hardening skipped",
            "Run as root to disable unnecessary services.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Hardening enabled services...");

    let box_type = detect_box_type();
    ctx.log_msg(&format!(
        "[+] Detected box type: {} — using {} allow-list",
        box_type.label(),
        box_type.label()
    ));

    let enabled = list_enabled_services(ctx)?;
    ctx.log_msg(&format!(
        "[+] {} enabled service units found",
        enabled.len()
    ));

    for svc in &enabled {
        if is_allowed(svc, box_type) {
            ctx.emit(Finding::new(
                Severity::Info,
                "services",
                format!("Service '{}' is on the allow-list — keeping", svc),
                format!("service: {}\nbox_type: {}", svc, box_type.label()),
            ));
            continue;
        }

        // Log the service name as evidence before acting.
        ctx.log_evidence_line("systemctl list-unit-files", svc);

        let disabled = ctx.run_remediation(&["systemctl", "disable", "--now", svc]);

        // Verify: check whether the service is still active.
        let still_active = check_active(svc);
        ctx.log_msg(&format!("PROOF: {} still active: {}", svc, still_active));

        ctx.emit(
            Finding::new(
                Severity::High,
                "services",
                format!("Service '{}' is not on the allow-list — disabled", svc),
                format!(
                    "service: {}\ndisabled: {}\nstill_active: {}",
                    svc, disabled, still_active
                ),
            )
            .with_context("service", svc.as_str())
            .with_context("box_type", box_type.label())
            .with_context("disabled", disabled.to_string())
            .with_context("still_active", still_active.to_string())
            .with_verdict(
                Verdict::Disable,
                format!(
                    "Service '{}' is not required on a {} box. \
                     It has been disabled. Confirm with `systemctl status {}`.",
                    svc,
                    box_type.label(),
                    svc
                ),
            )
            .with_action(Action::Manual(format!("systemctl disable --now {}", svc))),
        );
    }

    ctx.log_msg("[✓] Service hardening complete");
    Ok(())
}

/// Return the list of enabled service *base names* (without the `.service` suffix)
/// by running `systemctl list-unit-files`.
fn list_enabled_services(ctx: &DefenderContext) -> Result<Vec<String>> {
    let output = Command::new("systemctl")
        .args([
            "list-unit-files",
            "--state=enabled",
            "--no-legend",
            "--plain",
        ])
        .output();

    match output {
        Err(e) => {
            ctx.log_msg(&format!("[!] Could not run systemctl: {}", e));
            Ok(Vec::new())
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let services = stdout.lines().filter_map(parse_unit_line).collect();
            Ok(services)
        }
    }
}

/// Parse one line from `systemctl list-unit-files --no-legend --plain`.
///
/// Lines look like `sshd.service   enabled   enabled`.  Returns the base name
/// (e.g. `sshd`) or `None` if the line does not name a `.service` unit.
fn parse_unit_line(line: &str) -> Option<String> {
    let unit = line.split_whitespace().next()?;
    let name = unit.strip_suffix(".service")?;
    Some(name.to_string())
}

/// Return `true` if `service` is currently active according to systemctl.
fn check_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_allow_list_contains_expected_services() {
        assert!(is_allowed("nginx", BoxType::Web));
        assert!(is_allowed("apache2", BoxType::Web));
        assert!(is_allowed("ssh", BoxType::Web));
        assert!(is_allowed("sshd", BoxType::Web));
        assert!(is_allowed("cron", BoxType::Web));
    }

    #[test]
    fn mail_allow_list_contains_expected_services() {
        assert!(is_allowed("postfix", BoxType::Mail));
        assert!(is_allowed("dovecot", BoxType::Mail));
        assert!(is_allowed("roundcubemail", BoxType::Mail));
        assert!(is_allowed("sshd", BoxType::Mail));
    }

    #[test]
    fn splunk_allow_list_contains_expected_services() {
        assert!(is_allowed("splunk", BoxType::Splunk));
        assert!(is_allowed("ssh", BoxType::Splunk));
        assert!(is_allowed("cron", BoxType::Splunk));
    }

    #[test]
    fn general_allow_list_contains_base_services() {
        assert!(is_allowed("ssh", BoxType::General));
        assert!(is_allowed("sshd", BoxType::General));
        assert!(is_allowed("cron", BoxType::General));
        assert!(is_allowed("crond", BoxType::General));
    }

    #[test]
    fn baseline_services_allowed_on_all_box_types() {
        for box_type in [BoxType::Web, BoxType::Mail, BoxType::Splunk, BoxType::General] {
            assert!(is_allowed("nftables", box_type), "nftables must be allowed on {:?}", box_type);
            assert!(is_allowed("rsyslog", box_type), "rsyslog must be allowed on {:?}", box_type);
            assert!(is_allowed("auditd", box_type), "auditd must be allowed on {:?}", box_type);
            assert!(is_allowed("fail2ban", box_type), "fail2ban must be allowed on {:?}", box_type);
            assert!(is_allowed("apparmor", box_type), "apparmor must be allowed on {:?}", box_type);
            assert!(is_allowed("atd", box_type), "atd must be allowed on {:?}", box_type);
        }
    }

    #[test]
    fn is_allowed_returns_true_for_listed_service() {
        assert!(is_allowed("nginx", BoxType::Web));
        assert!(is_allowed("postfix", BoxType::Mail));
        assert!(is_allowed("splunk", BoxType::Splunk));
        assert!(is_allowed("sshd", BoxType::General));
    }

    #[test]
    fn is_allowed_returns_false_for_unlisted_service() {
        assert!(!is_allowed("telnet", BoxType::Web));
        assert!(!is_allowed("nc", BoxType::Mail));
        assert!(!is_allowed("rsyncd", BoxType::Splunk));
        assert!(!is_allowed("cups", BoxType::General));
    }

    #[test]
    fn systemd_prefix_always_allowed() {
        assert!(is_allowed("systemd-journald", BoxType::Web));
        assert!(is_allowed("systemd-networkd", BoxType::Mail));
        assert!(is_allowed("systemd-resolved", BoxType::Splunk));
        assert!(is_allowed("systemd-logind", BoxType::General));
    }

    #[test]
    fn parse_unit_line_extracts_service_name() {
        assert_eq!(
            parse_unit_line("sshd.service                       enabled  enabled"),
            Some("sshd".to_string())
        );
        assert_eq!(
            parse_unit_line("nginx.service                      enabled  enabled"),
            Some("nginx".to_string())
        );
    }

    #[test]
    fn parse_unit_line_ignores_non_service_units() {
        assert_eq!(parse_unit_line("sshd.socket    enabled  enabled"), None);
        assert_eq!(
            parse_unit_line("multi-user.target    enabled  enabled"),
            None
        );
        assert_eq!(parse_unit_line(""), None);
    }

    #[test]
    fn parse_unit_line_handles_no_suffix() {
        assert_eq!(parse_unit_line("bare-name"), None);
    }

    #[test]
    fn nginx_not_allowed_on_splunk_box() {
        assert!(!is_allowed("nginx", BoxType::Splunk));
    }

    #[test]
    fn postfix_not_allowed_on_web_box() {
        assert!(!is_allowed("postfix", BoxType::Web));
    }
}
