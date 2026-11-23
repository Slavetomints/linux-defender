#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use crate::score_check::{GENERAL_CHECKS, MAIL_CHECKS, SPLUNK_CHECKS, ServiceCheck, WEB_CHECKS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoxType {
    Web,
    Mail,
    Splunk,
    General,
    Router,
}

impl BoxType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Web => "Web",
            Self::Mail => "Mail",
            Self::Splunk => "Splunk",
            Self::General => "General/Workstation",
            Self::Router => "Router",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Web => "Rocky Ecom — HTTP :80  HTTPS :443  SSH :22",
            Self::Mail => {
                "Ubuntu Email — SMTP :25/:587  IMAP :143/:993  POP3 :110/:995  Webmail :80  SSH :22"
            }
            Self::Splunk => "Debian Splunk — Web :8000  Mgmt :8089  SSH :22",
            Self::General => "SSH :22 + general system services + Palo Alto XML audit",
            Self::Router => "VyOS 1.4 Router — Routes, NAT, Host Firewall",
        }
    }

    pub fn services(self) -> &'static [ServiceConfig] {
        match self {
            Self::Web => &[
                ServiceConfig {
                    name: "HTTP",
                    port: 80,
                },
                ServiceConfig {
                    name: "HTTPS",
                    port: 443,
                },
                ServiceConfig {
                    name: "SSH",
                    port: 22,
                },
            ],
            Self::Mail => &[
                ServiceConfig {
                    name: "Postfix SMTP",
                    port: 25,
                },
                ServiceConfig {
                    name: "Postfix Subm",
                    port: 587,
                },
                ServiceConfig {
                    name: "Dovecot IMAP",
                    port: 143,
                },
                ServiceConfig {
                    name: "Dovecot IMAPS",
                    port: 993,
                },
                ServiceConfig {
                    name: "Roundcube",
                    port: 80,
                },
                ServiceConfig {
                    name: "SSH",
                    port: 22,
                },
            ],
            Self::Splunk => &[
                ServiceConfig {
                    name: "Splunk Web",
                    port: 8000,
                },
                ServiceConfig {
                    name: "Splunk Mgmt",
                    port: 8089,
                },
                ServiceConfig {
                    name: "SSH",
                    port: 22,
                },
            ],
            Self::General | Self::Router => &[ServiceConfig {
                name: "SSH",
                port: 22,
            }],
        }
    }

    pub const ALL: &'static [BoxType] = &[
        Self::Web,
        Self::Mail,
        Self::Splunk,
        Self::General,
        Self::Router,
    ];

    /// Rich service check definitions for this box type.
    pub fn checks(self) -> &'static [ServiceCheck] {
        match self {
            Self::Web => WEB_CHECKS,
            Self::Mail => MAIL_CHECKS,
            Self::Splunk => SPLUNK_CHECKS,
            Self::General | Self::Router => GENERAL_CHECKS,
        }
    }

    /// Backup operations available for this box type: `(step_id, display_label)`.
    ///
    /// On [`BoxType::Router`], server stacks (mail, splunk, ecomm) are strictly omitted,
    /// exposing only router-relevant backups (`router`, `users`, `all`).
    /// On non-router systems, standard server stacks are exposed and `router` is hidden.
    pub fn backup_steps(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Router => &[
                ("router", "Router Config (/config/config.boot)"),
                ("users", "User/Group/Shadow DBs"),
                ("all", "Full Config Backup"),
            ],
            _ => &[
                ("all", "Full Config Backup"),
                ("mail", "Mail Stack"),
                ("splunk", "Splunk Config"),
                ("users", "User/Group/Shadow DBs"),
                ("ecomm", "E-Commerce Stack"),
            ],
        }
    }

    /// Hardening operations available for this box type: `(step_id, display_label)`.
    pub fn hardening_steps(self) -> &'static [(&'static str, &'static str)] {
        &[
            ("user_permissions", "User & File Permissions"),
            ("services", "Disable Unnecessary Services"),
            ("programs", "Restrict Dangerous Programs"),
            ("configs", "Deploy Hardened Configs"),
        ]
    }

    /// Audit and scan modules available for this box type: `(id, display_label, is_anti_persistence, interval)`.
    ///
    /// On [`BoxType::Router`], returns the 8 dedicated VyOS audit modules grounded in router topology.
    /// On other box types, returns standard Linux anti-persistence and monitoring modules.
    pub fn scan_modules(self) -> &'static [(&'static str, &'static str, bool, ScanInterval)] {
        match self {
            Self::Router => ROUTER_SCAN_MODULES,
            _ => STANDARD_SCAN_MODULES,
        }
    }
}

/// How often a module runs in auto-scan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanInterval {
    /// Re-runs every 30 seconds — ephemeral state an attacker can change in real time.
    Continuous,
    /// Re-runs every 5 minutes — filesystem changes that take time to appear.
    Frequent,
    /// Manual only — expensive filesystem walks or rarely-changing config.
    OnDemand,
}

/// Dedicated VyOS audit modules for `BoxType::Router`.
pub const ROUTER_SCAN_MODULES: &[(&str, &str, bool, ScanInterval)] = &[
    (
        "router_version",
        "1. System Version & Identity",
        false,
        ScanInterval::Frequent,
    ),
    (
        "router_boot_hooks",
        "2. /config/scripts/ Boot Hooks",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "router_commit_hooks",
        "3. Commit Hooks (High Risk)",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "router_task_scheduler",
        "4. Task Scheduler & Linux Cron",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "router_users",
        "5. Login Accounts & SSH Keys",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "router_interfaces",
        "6. Interfaces, Tunnels & VPNs",
        false,
        ScanInterval::Frequent,
    ),
    (
        "router_containers",
        "7. Containers (Podman)",
        false,
        ScanInterval::Frequent,
    ),
    (
        "router_services_config",
        "8. Configured System Services",
        false,
        ScanInterval::Frequent,
    ),
    (
        "router_listening_sockets",
        "9. Listening Sockets & Conns",
        false,
        ScanInterval::Continuous,
    ),
    (
        "router_dyn_linker",
        "10. Linker & Systemd Overrides",
        true,
        ScanInterval::Continuous,
    ),
    (
        "router_suid_files",
        "11. SUID & Modified System Files",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "router_commit_history",
        "12. Commit History & Revisions",
        false,
        ScanInterval::OnDemand,
    ),
    (
        "router_nat",
        "13. NAT Configuration (IP Baseline)",
        false,
        ScanInterval::Frequent,
    ),
    (
        "router_services_whitelist",
        "14. Services vs ROUTER_ALLOW",
        false,
        ScanInterval::Continuous,
    ),
];

/// Standard scan modules for non-router Linux boxes.
pub const STANDARD_SCAN_MODULES: &[(&str, &str, bool, ScanInterval)] = &[
    // ── Anti-persistence ─────────────────────────────────────────────────
    (
        "ssh_keys",
        "SSH authorized_keys",
        true,
        ScanInterval::OnDemand,
    ),
    ("cron", "Cron jobs", true, ScanInterval::OnDemand),
    ("at_jobs", "AT job queue", true, ScanInterval::OnDemand),
    ("users", "User accounts", true, ScanInterval::OnDemand),
    (
        "webshells",
        "Web shells (PHP/ASP/ASPX/Python/Ruby)",
        true,
        ScanInterval::OnDemand,
    ),
    ("suid", "SUID binaries", true, ScanInterval::OnDemand),
    (
        "capabilities",
        "Binary capabilities",
        true,
        ScanInterval::OnDemand,
    ),
    ("systemd", "Systemd services", true, ScanInterval::OnDemand),
    (
        "kernel_modules",
        "Kernel modules",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "ld_preload",
        "LD_PRELOAD hijacking",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "immutable",
        "Immutable file flags",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "startup_scripts",
        "Startup scripts + skel",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "rc_local",
        "rc.local / rc.d scripts",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "prompt_command",
        "PROMPT_COMMAND backdoors",
        true,
        ScanInterval::Frequent,
    ),
    ("pam", "PAM configuration", true, ScanInterval::OnDemand),
    ("grub", "GRUB bootloader", true, ScanInterval::OnDemand),
    (
        "initramfs",
        "initramfs integrity",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "logrotate",
        "logrotate scripts",
        true,
        ScanInterval::OnDemand,
    ),
    ("udev", "udev rules", true, ScanInterval::OnDemand),
    (
        "xdg_autostart",
        "XDG autostart entries",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "ssh_config",
        "sshd_config audit",
        true,
        ScanInterval::Frequent,
    ),
    ("sudoers", "sudoers audit", true, ScanInterval::Frequent),
    (
        "cron_system",
        "System cron dirs",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "systemd_timers",
        "Systemd timers",
        true,
        ScanInterval::OnDemand,
    ),
    (
        "shell_aliases",
        "Shell alias backdoors",
        true,
        ScanInterval::OnDemand,
    ),
    ("polkit", "polkit rules audit", true, ScanInterval::OnDemand),
    (
        "mail_intercept",
        "Mail intercept (postfix)",
        true,
        ScanInterval::OnDemand,
    ),
    // ── Monitoring ─────────────────────────────────────────────────────────
    (
        "hidden_elf",
        "Hidden ELF binaries",
        false,
        ScanInterval::Frequent,
    ),
    (
        "deleted_binaries",
        "Deleted running binaries",
        false,
        ScanInterval::Continuous,
    ),
    (
        "suspicious_services",
        "Suspicious service units",
        false,
        ScanInterval::OnDemand,
    ),
    (
        "auth_log",
        "Auth log analysis",
        false,
        ScanInterval::Frequent,
    ),
    (
        "process_tree",
        "Process tree anomalies",
        false,
        ScanInterval::Continuous,
    ),
    (
        "recently_modified",
        "Recently-modified binaries",
        false,
        ScanInterval::Frequent,
    ),
    (
        "world_writable",
        "World-writable paths",
        false,
        ScanInterval::Frequent,
    ),
    (
        "outbound_connections",
        "Outbound svc-acct connections",
        false,
        ScanInterval::Continuous,
    ),
    ("fail2ban", "Fail2ban status", false, ScanInterval::Frequent),
    (
        "ai_artifacts",
        "AI-generated script tells",
        false,
        ScanInterval::Frequent,
    ),
    (
        "elf_disguise",
        "ELF/script disguise check",
        false,
        ScanInterval::Frequent,
    ),
    (
        "perm_anomalies",
        "Permission/ownership anomalies",
        false,
        ScanInterval::OnDemand,
    ),
    (
        "attacker_tools",
        "Attacker tool detection",
        false,
        ScanInterval::Frequent,
    ),
    (
        "c2_detection",
        "C2/implant detection",
        false,
        ScanInterval::Continuous,
    ),
    (
        "rootkit_cross_check",
        "Rootkit PID/port cross-check",
        false,
        ScanInterval::Continuous,
    ),
    (
        "proc_maps",
        "RWX anonymous memory maps",
        false,
        ScanInterval::Frequent,
    ),
    (
        "binary_integrity",
        "Binary integrity baseline",
        false,
        ScanInterval::OnDemand,
    ),
    (
        "git_hooks",
        "Malicious git hooks",
        false,
        ScanInterval::OnDemand,
    ),
    (
        "webserver_config",
        "Webserver config audit",
        false,
        ScanInterval::Frequent,
    ),
    (
        "apt_sources",
        "APT source integrity",
        false,
        ScanInterval::Frequent,
    ),
    (
        "bind_mounts",
        "Bind/overlay mount detection",
        false,
        ScanInterval::Continuous,
    ),
    (
        "malicious_binaries",
        "Malicious/modified binaries",
        false,
        ScanInterval::OnDemand,
    ),
];

#[derive(Debug, Clone, Copy)]
pub struct ServiceConfig {
    pub name: &'static str,
    pub port: u16,
}

impl ServiceConfig {
    pub fn is_up(self) -> bool {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
    }
}

/// Units that back a scored service, or that a scored service depends on.
/// Lowercase, without `.service`. Checked on every box type: no module may
/// automatically stop, disable, or delete one of these. A backdoored scored
/// unit gets flagged for a human to repair, never nuked.
const SCORED_UNITS: &[&str] = &[
    // SSH (scored everywhere)
    "ssh",
    "sshd",
    // Web / webmail
    "nginx",
    "httpd",
    "apache2",
    "php-fpm",
    // Databases behind the ecom store and Roundcube
    "mariadb",
    "mysql",
    "mysqld",
    "postgresql",
    // FTP (possibly scored on Web)
    "vsftpd",
    "proftpd",
    "pure-ftpd",
    // Mail
    "postfix",
    "dovecot",
    "roundcubemail",
    // AD auth behind postfix/dovecot
    "sssd",
    "winbind",
    "nslcd",
    "krb5kdc",
    // Splunk (unit is Splunkd.service by default)
    "splunkd",
    "splunk",
    "splunkforwarder",
    // Networking: losing this loses every scored service at once
    "networkmanager",
    "networking",
    "systemd-networkd",
    "systemd-resolved",
];

/// True when `unit` (e.g. `Splunkd.service`, `php8.1-fpm`, `postfix@-.service`)
/// backs a scored service and must never be auto-remediated.
pub fn is_scored_unit(unit: &str) -> bool {
    let lower = unit.to_ascii_lowercase();
    let name = lower.strip_suffix(".service").unwrap_or(&lower);

    // Template instances are only accepted in the forms the real packages
    // use; otherwise an implant named `sshd@backdoor.service` would inherit
    // sshd's protection.
    if let Some((template, instance)) = name.split_once('@') {
        return match template {
            // Debian's multi-instance postfix: postfix@-, postfix@postfix-out
            "postfix" => true,
            // Socket-activated per-connection instances: sshd@3-10.0.0.1:22-10.0.0.5:51234
            "ssh" | "sshd" => is_socket_connection_instance(instance),
            _ => false,
        };
    }

    SCORED_UNITS.contains(&name) || is_php_fpm_unit(name)
}

/// `N-<local>-<remote>` instance names systemd gives per-connection units.
fn is_socket_connection_instance(instance: &str) -> bool {
    let Some((n, rest)) = instance.split_once('-') else {
        return false;
    };
    !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) && rest.contains('-')
}

/// Real PHP-FPM unit names: `php-fpm`, `php8.1-fpm` (Debian/Ubuntu),
/// `php-fpm8.2`, and Remi's `php82-php-fpm`. Not "anything with php and fpm in
/// it", which an implant could pick.
fn is_php_fpm_unit(name: &str) -> bool {
    let is_version = |v: &str| {
        !v.is_empty()
            && v.split('.').count() <= 2
            && v.split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    if name == "php-fpm" {
        return true;
    }
    if let Some(v) = name
        .strip_prefix("php")
        .and_then(|r| r.strip_suffix("-fpm"))
        && is_version(v)
    {
        return true;
    }
    if let Some(v) = name.strip_prefix("php-fpm")
        && is_version(v)
    {
        return true;
    }
    if let Some(v) = name
        .strip_prefix("php")
        .and_then(|r| r.strip_suffix("-php-fpm"))
        && !v.is_empty()
        && v.chars().all(|c| c.is_ascii_digit())
    {
        return true;
    }
    false
}

/// Probe the filesystem to guess what kind of box this is.
pub fn detect_box_type() -> BoxType {
    if Path::new("/opt/vyatta").exists()
        || Path::new("/config/config.boot").exists()
        || std::fs::read_to_string("/etc/os-release")
            .map(|s| s.contains("VyOS"))
            .unwrap_or(false)
    {
        return BoxType::Router;
    }
    // Only Splunk Enterprise makes this the Splunk box. The universal
    // forwarder (/opt/splunkforwarder) gets installed on every box we want
    // logs from, and treating those as Splunk boxes picks the wrong firewall
    // profile and service allow-list.
    if Path::new("/opt/splunk/bin/splunk").exists() || Path::new("/opt/splunk/etc").is_dir() {
        return BoxType::Splunk;
    }
    let has_postfix = Path::new("/usr/sbin/postfix").exists() || Path::new("/etc/postfix").exists();
    let has_dovecot = Path::new("/usr/sbin/dovecot").exists() || Path::new("/etc/dovecot").exists();
    if has_postfix || has_dovecot {
        return BoxType::Mail;
    }
    if Path::new("/etc/nginx").exists()
        || Path::new("/etc/apache2").exists()
        || Path::new("/etc/httpd").exists()
    {
        return BoxType::Web;
    }
    BoxType::General
}

#[cfg(test)]
mod scored_unit_tests {
    use super::is_scored_unit;

    #[test]
    fn scored_units_match_real_unit_names() {
        for u in [
            "Splunkd.service",
            "SplunkForwarder.service",
            "sshd.service",
            "ssh",
            "postfix@-.service",
            "dovecot",
            "mariadb.service",
            "php8.1-fpm.service",
            "php-fpm",
            "NetworkManager.service",
            "networking.service",
            "httpd",
        ] {
            assert!(is_scored_unit(u), "{} should be protected", u);
        }
    }

    #[test]
    fn spoofed_template_and_php_names_are_not_scored() {
        for u in [
            "sshd@backdoor.service",
            "ssh@x",
            "dovecot@evil.service",
            "php-fpm-backdoor.service",
            "phpfpm",
            "php-evil-fpm-loader",
            "php8.1-fpm-helper",
            "php-fpm..1",
        ] {
            assert!(!is_scored_unit(u), "{} must not be protected", u);
        }
        for u in [
            "sshd@3-10.0.0.1:22-10.0.0.5:51234.service",
            "postfix@postfix-out.service",
            "php-fpm8.2",
            "php82-php-fpm.service",
            "php7.4-fpm",
        ] {
            assert!(is_scored_unit(u), "{} should be protected", u);
        }
    }

    #[test]
    fn random_units_are_not_scored() {
        for u in [
            "kworkerd.service",
            "dbus-update.service",
            "sshd-backdoor.service",
            "cups",
        ] {
            assert!(!is_scored_unit(u), "{} should not be protected", u);
        }
    }

    /// Router backup steps must include router, users, and all, and exclude server stacks.
    #[test]
    fn router_backup_steps_scoping() {
        let steps = BoxType::Router.backup_steps();
        let ids: Vec<&str> = steps.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec!["router", "users", "all"]);
        assert!(!ids.contains(&"mail"));
        assert!(!ids.contains(&"splunk"));
        assert!(!ids.contains(&"ecomm"));
        assert_eq!(steps.len(), 3);
    }

    /// Non-router backup steps must contain standard server stacks and exclude router.
    #[test]
    fn non_router_backup_steps_scoping() {
        for bt in [
            BoxType::Web,
            BoxType::Mail,
            BoxType::Splunk,
            BoxType::General,
        ] {
            let steps = bt.backup_steps();
            let ids: Vec<&str> = steps.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids, vec!["all", "mail", "splunk", "users", "ecomm"]);
            assert!(
                !ids.contains(&"router"),
                "non-router {:?} must not contain router backup",
                bt
            );
            assert_eq!(steps.len(), 5);
        }
    }

    /// Hardening steps must be defined and non-empty for all box types.
    #[test]
    fn hardening_steps_defined_for_all_box_types() {
        for bt in BoxType::ALL {
            let steps = bt.hardening_steps();
            assert!(!steps.is_empty());
        }
    }

    /// Router scan modules must contain exactly the 14 dedicated VyOS audit modules.
    #[test]
    fn router_scan_modules_scoping() {
        let modules = BoxType::Router.scan_modules();
        assert_eq!(modules.len(), 14);
        let ids: Vec<&str> = modules.iter().map(|(id, _, _, _)| *id).collect();
        assert!(ids.contains(&"router_version"));
        assert!(ids.contains(&"router_boot_hooks"));
        assert!(ids.contains(&"router_commit_hooks"));
        assert!(ids.contains(&"router_task_scheduler"));
        assert!(ids.contains(&"router_users"));
        assert!(ids.contains(&"router_interfaces"));
        assert!(ids.contains(&"router_containers"));
        assert!(ids.contains(&"router_services_config"));
        assert!(ids.contains(&"router_listening_sockets"));
        assert!(ids.contains(&"router_dyn_linker"));
        assert!(ids.contains(&"router_suid_files"));
        assert!(ids.contains(&"router_commit_history"));
        assert!(ids.contains(&"router_nat"));
        assert!(ids.contains(&"router_services_whitelist"));
    }
}
