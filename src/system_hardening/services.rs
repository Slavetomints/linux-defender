//! Service allow-listing and bulk-disable hardening.
//!
//! Detects which services are enabled, compares them against a per-box-type
//! allow-list, and disables anything that should not be running. Each
//! disable is prompted and verified with `systemctl is-active`.
//!
//! # Allow-lists
//!
//! All box types share a baseline: ssh/sshd, cron/crond, atd, nftables/ufw/iptables/firewalld,
//! rsyslog/syslog, auditd, fail2ban, apparmor, dbus/dbus-broker, getty (console
//! login), time sync, hypervisor guest agents, container runtimes, AD helpers,
//! storage/boot plumbing, and all systemd-* units. Anything that would take the
//! console, the clock, or the VM tooling away from the operator stays enabled.
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
    detect_box_type, is_scored_unit, require_root,
};

/// Services that must never be disabled regardless of box type.
/// Disabling these would kill logging, the firewall, or audit trails mid-competition.
const BASELINE_ALLOW: &[&str] = &[
    // remote access
    "ssh",
    "sshd",
    // scheduling
    "cron",
    "crond",
    "atd",
    // firewall — NEVER disable; nftbuild writes rules then exits, the service keeps them loaded
    "nftables",
    "iptables",
    "ip6tables",
    "firewalld",
    "ufw",
    // logging
    "rsyslog",
    "syslog",
    "syslog-ng",
    // audit
    "auditd",
    // intrusion detection
    "fail2ban",
    // mandatory access control
    "apparmor",
    "selinux",
    // dbus (required by many systemd units); Rocky/Fedora ship dbus-broker
    "dbus",
    "dbus-broker",
    "dbus-daemon",
    "polkit",
    // console and serial logins: the fallback when SSH is lost
    "getty",
    "serial-getty",
    "autovt",
    "console-getty",
    "container-getty",
    // SSH host key generation (RHEL family)
    "sshd-keygen",
    // time sync: clock skew breaks Kerberos/AD auth and TLS
    "chronyd",
    "chrony",
    "ntpd",
    "ntp",
    "ntpsec",
    // hypervisor guest agents: the competition boxes are VMs
    "vmtoolsd",
    "open-vm-tools",
    "vgauthd",
    "qemu-guest-agent",
    "vboxadd",
    "vboxadd-service",
    "hv-kvp-daemon",
    "hv-vss-daemon",
    "hv-fcopy-daemon",
    "xe-linux-distribution",
    "cloud-init",
    "cloud-init-local",
    "cloud-config",
    "cloud-final",
    // container runtimes: scored services may live in containers
    "docker",
    "containerd",
    "podman",
    "podman-restart",
    "crio",
    // caches and queues commonly backing the web store or webmail
    "redis",
    "redis-server",
    "memcached",
    "valkey",
    // AD / directory helpers (home dir creation, realm join, name caching)
    "oddjobd",
    "realmd",
    "nscd",
    // storage and boot plumbing
    "lvm2-monitor",
    "lvm2-lvmpolld",
    "multipathd",
    "mdmonitor",
    "blk-availability",
    "dm-event",
    "iscsid",
    "open-iscsi",
    "irqbalance",
    "kdump",
    "tuned",
    "rngd",
    "haveged",
    "selinux-autorelabel-mark",
    "e2scrub_reap",
    "grub-common",
    "kmod-static-nodes",
    "keyboard-setup",
    "console-setup",
    "setvtrgb",
    "ifupdown-pre",
    "networkd-dispatcher",
    "networkmanager-dispatcher",
    "networkmanager-wait-online",
    "nis-domainname",
    "import-state",
    "loadmodules",
    "microcode",
];

/// Services allowed on a Web box.
const WEB_ALLOW: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "php8.1-fpm",
    "php8.2-fpm",
];

/// Services allowed on a Mail box.
const MAIL_ALLOW: &[&str] = &[
    "postfix",
    "dovecot",
    "roundcubemail",
    // roundcube needs a web server
    "apache2",
    "nginx",
    "httpd",
    "php-fpm",
    "php8.1-fpm",
    "php8.2-fpm",
    // spamassassin / amavis common on mail boxes
    "spamassassin",
    "amavis",
    "amavisd",
    // DNS resolver sometimes local on mail boxes for SPF checks
    "named",
    "bind9",
];

/// Services allowed on a Splunk box.
const SPLUNK_ALLOW: &[&str] = &["splunk", "SplunkForwarder"];

/// Services allowed on a General-purpose box.
const GENERAL_ALLOW: &[&str] = &[
    // common scored services that might appear on a general box
    "mysql",
    "mariadb",
    "postgresql",
    "mongod",
    "named",
    "bind9",
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
    // Scored services and their dependencies (Splunkd, mariadb, NetworkManager,
    // sssd, ...) are never disabled, whatever box type we think this is.
    if is_scored_unit(service_name) {
        return true;
    }
    // `systemctl list-unit-files` reports templates as `getty@` and instances
    // as `getty@tty1`; match both on the template name. Compare lowercased so
    // `NetworkManager-dispatcher` matches its entry.
    let lower = service_name.to_ascii_lowercase();
    let base = lower.split('@').next().unwrap_or(&lower);
    // Baseline services that must never be disabled regardless of box type.
    if BASELINE_ALLOW.contains(&base) {
        return true;
    }
    // Box-specific services.
    allow_list(box_type)
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(base))
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

    check_masked_scored_units(ctx);

    ctx.log_msg("[✓] Service hardening complete");
    Ok(())
}

/// Detect scored services that have been masked and unmask them.
///
/// `systemctl mask <svc>` symlinks the unit to /dev/null, so the service can't
/// start and never shows up as "enabled". It's a one-command way to take a
/// scored service offline, and nothing else in the hardening loop catches it
/// (masked units aren't enabled). We list masked units, and for any that back a
/// scored service we unmask it and flag Critical.
fn check_masked_scored_units(ctx: &DefenderContext) {
    ctx.log_msg("[+] Checking for masked scored services...");
    let output = Command::new("systemctl")
        .args([
            "list-unit-files",
            "--state=masked",
            "--no-legend",
            "--plain",
        ])
        .output();

    let Ok(out) = output else {
        ctx.log_msg("[!] Could not list masked units");
        return;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);

    for svc in stdout.lines().filter_map(parse_unit_line) {
        if !is_scored_unit(&svc) {
            continue;
        }
        ctx.log_evidence_line("systemctl list-unit-files --state=masked", &svc);
        let unmasked = ctx.run_remediation(&["systemctl", "unmask", &svc]);
        // Bring it back up after unmasking.
        let started = unmasked && ctx.run_remediation(&["systemctl", "enable", "--now", &svc]);
        let still_active = check_active(&svc);
        ctx.log_msg(&format!(
            "PROOF: {} unmasked: {}, active after restart: {}",
            svc, unmasked, still_active
        ));

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "services",
                format!(
                    "Scored service '{}' was MASKED — unmasked and restarted",
                    svc
                ),
                format!(
                    "service: {}\nwas: masked (unit symlinked to /dev/null)\nunmasked: {}\n\
                     restarted: {}\nactive_now: {}",
                    svc, unmasked, started, still_active
                ),
            )
            .with_context("service", svc.as_str())
            .with_context("unmasked", unmasked.to_string())
            .with_context("active_now", still_active.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "'{}' backs a scored service and had been masked, which takes it offline \
                     and blocks restart. It has been unmasked and started. Confirm with \
                     `systemctl status {}` and investigate who masked it.",
                    svc, svc
                ),
            )
            .with_action(Action::Manual(format!(
                "systemctl unmask {} && systemctl enable --now {}",
                svc, svc
            ))),
        );
    }
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
        for box_type in [
            BoxType::Web,
            BoxType::Mail,
            BoxType::Splunk,
            BoxType::General,
        ] {
            assert!(
                is_allowed("nftables", box_type),
                "nftables must be allowed on {:?}",
                box_type
            );
            assert!(
                is_allowed("rsyslog", box_type),
                "rsyslog must be allowed on {:?}",
                box_type
            );
            assert!(
                is_allowed("auditd", box_type),
                "auditd must be allowed on {:?}",
                box_type
            );
            assert!(
                is_allowed("fail2ban", box_type),
                "fail2ban must be allowed on {:?}",
                box_type
            );
            assert!(
                is_allowed("apparmor", box_type),
                "apparmor must be allowed on {:?}",
                box_type
            );
            assert!(
                is_allowed("atd", box_type),
                "atd must be allowed on {:?}",
                box_type
            );
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
    fn console_dbus_time_and_vm_services_are_never_disabled() {
        for svc in [
            "getty@",
            "getty@tty1",
            "serial-getty@",
            "dbus-broker",
            "chronyd",
            "vmtoolsd",
            "qemu-guest-agent",
            "docker",
            "containerd",
            "redis-server",
            "memcached",
            "oddjobd",
            "NetworkManager-dispatcher",
            "sshd-keygen@",
            "lvm2-monitor",
        ] {
            for box_type in BoxType::ALL {
                assert!(
                    is_allowed(svc, *box_type),
                    "{svc} must be allowed on {box_type:?}"
                );
            }
        }
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
    fn scored_units_are_never_disabled_on_any_box() {
        for box_type in BoxType::ALL {
            for svc in [
                "Splunkd",
                "mariadb",
                "mysql",
                "NetworkManager",
                "networking",
                "sssd",
                "php8.1-fpm",
            ] {
                assert!(
                    is_allowed(svc, *box_type),
                    "{} disabled on {:?}",
                    svc,
                    box_type
                );
            }
        }
    }

    #[test]
    fn cups_not_allowed_on_splunk_box() {
        assert!(!is_allowed("cups", BoxType::Splunk));
    }

    #[test]
    fn avahi_not_allowed_on_web_box() {
        assert!(!is_allowed("avahi-daemon", BoxType::Web));
    }
}
