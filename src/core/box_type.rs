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
            Self::General => "General",
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
            Self::General => "SSH :22 + general system services",
            Self::Router => "VyOS 1.4 Router — SSH :22, Control Plane & Transit Firewall",
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
}

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
    let base = lower.strip_suffix(".service").unwrap_or(&lower);
    // Template instances: postfix@-  ->  postfix
    let base = base.split('@').next().unwrap_or(base);
    if SCORED_UNITS.contains(&base) {
        return true;
    }
    // Versioned PHP-FPM units: php8.1-fpm, php-fpm8.2, php82-php-fpm
    base.starts_with("php") && base.contains("fpm")
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
    if Path::new("/opt/splunk").exists() || Path::new("/opt/splunkforwarder").exists() {
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
}
