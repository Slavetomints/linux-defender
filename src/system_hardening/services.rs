//! Service allow-listing and bulk-disable hardening.
//!
//! Detects which services are enabled, compares them against a per-box-type
//! allow-list, and disables anything that should not be running. Each
//! disable is prompted and verified with `systemctl is-active`.
//!
//! # Allow-lists
//!
//! | Box type | Allowed services |
//! |----------|-----------------|
//! | Web      | ssh/sshd, nginx, apache2, httpd, cron/crond |
//! | Mail     | ssh/sshd, postfix, dovecot, roundcubemail, cron/crond |
//! | Splunk   | ssh/sshd, splunk, cron/crond |
//! | General  | ssh/sshd, cron/crond, systemd-\* |

use std::process::Command;

use crate::core::{
    Action, BoxType, DefenderContext, DefenderError, Finding, Result, Severity, Verdict,
    detect_box_type, require_root,
};

/// Services allowed on a Web box.
const WEB_ALLOW: &[&str] = &["ssh", "sshd", "nginx", "apache2", "httpd", "cron", "crond"];

/// Services allowed on a Mail box.
const MAIL_ALLOW: &[&str] = &[
    "ssh",
    "sshd",
    "postfix",
    "dovecot",
    "roundcubemail",
    "cron",
    "crond",
];

/// Services allowed on a Splunk box.
const SPLUNK_ALLOW: &[&str] = &["ssh", "sshd", "splunk", "cron", "crond"];

/// Services allowed on a General-purpose box.
///
/// The empty `""` entry acts as a sentinel; the real handling for `systemd-*`
/// names is done inside [`is_allowed`].
const GENERAL_ALLOW: &[&str] = &["ssh", "sshd", "cron", "crond"];

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
///
/// On [`BoxType::General`] boxes all `systemd-*` units are additionally
/// allowed, because they are part of the base OS and should never be disabled.
pub fn is_allowed(service_name: &str, box_type: BoxType) -> bool {
    let list = allow_list(box_type);
    if list.contains(&service_name) {
        return true;
    }
    // Always permit core systemd units on every box type.
    if service_name.starts_with("systemd-") {
        return true;
    }
    false
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
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_allow_list_contains_expected_services() {
        let list = allow_list(BoxType::Web);
        assert!(list.contains(&"nginx"));
        assert!(list.contains(&"ssh"));
        assert!(list.contains(&"sshd"));
        assert!(list.contains(&"cron"));
    }

    #[test]
    fn mail_allow_list_contains_expected_services() {
        let list = allow_list(BoxType::Mail);
        assert!(list.contains(&"postfix"));
        assert!(list.contains(&"dovecot"));
        assert!(list.contains(&"roundcubemail"));
        assert!(list.contains(&"sshd"));
    }

    #[test]
    fn splunk_allow_list_contains_expected_services() {
        let list = allow_list(BoxType::Splunk);
        assert!(list.contains(&"splunk"));
        assert!(list.contains(&"ssh"));
        assert!(list.contains(&"cron"));
    }

    #[test]
    fn general_allow_list_contains_base_services() {
        let list = allow_list(BoxType::General);
        assert!(list.contains(&"ssh"));
        assert!(list.contains(&"sshd"));
        assert!(list.contains(&"cron"));
        assert!(list.contains(&"crond"));
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
