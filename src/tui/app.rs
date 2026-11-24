use std::collections::{HashMap, HashSet};
use std::io::Stdout;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use anyhow::Context;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use chrono::Local;

use crate::core::{
    BoxType, DefenderContext, Finding, ScanInterval, Severity, detect_box_type, execute_action,
    strip_ansi,
};
use crate::score_check::{ServiceHistory, build_histories, poll_all};
use crate::tui::logs::dashboard::LogDashboard as LogDash;

use super::dashboard::{SessionInfo, poll_auth_events, poll_sessions, render as render_dashboard};
use super::logs::preserve;

/// Which pane of the Scan tab currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFocus {
    /// The module checklist on the left.
    Modules,
    /// The findings list on the right.
    Findings,
}

/// Which pane of the Router tab currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterFocus {
    /// Left pane: Operations list
    Operations,
    /// Right pane: Output log
    Log,
}

/// Which pane of the Palo Alto tab currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaloFocus {
    /// Left pane: Findings list
    Findings,
    /// Right pane: Configuration inputs and action controls
    Controls,
}

/// Registry of monitoring modules available from the Monitor tab: (id, display label).
const MONITOR_MODULES: &[(&str, &str)] = &[
    ("access_log", "Access log analysis"),
    ("error_log", "Error log analysis"),
    ("auth_log_watch", "Auth log watch (1h)"),
    ("pspy", "Process spy"),
    ("network_watch", "Network snapshot"),
    ("auth_log", "Auth log brute-force analysis"),
    ("hidden_elf", "Hidden ELF binaries"),
    ("deleted_binaries", "Deleted running binaries"),
    ("process_tree", "Process tree anomalies"),
    ("recently_modified", "Recently-modified binaries"),
    ("suspicious_services", "Suspicious service units"),
    ("world_writable", "World-writable paths"),
    ("outbound_connections", "Outbound svc-acct connections"),
    ("fail2ban", "Fail2ban status"),
    ("ai_artifacts", "AI-generated script tells"),
    ("elf_disguise", "ELF/script disguise check"),
    ("perm_anomalies", "Permission/ownership anomalies"),
    ("attacker_tools", "Attacker tool detection"),
    ("c2_detection", "C2/implant detection"),
    ("rootkit_cross_check", "Rootkit PID/port cross-check"),
    ("proc_maps", "RWX anonymous memory maps"),
    ("binary_integrity", "Binary integrity baseline"),
    ("git_hooks", "Malicious git hooks"),
    ("webserver_config", "Webserver config audit"),
    ("apt_sources", "APT source integrity"),
    ("bind_mounts", "Bind/overlay mount detection"),
];

/// Service restore operations: (id, display label).
const RESTORE_SERVICES: &[(&str, &str)] = &[
    ("postfix", "Postfix (SMTP)"),
    ("dovecot", "Dovecot (IMAP/POP3)"),
    ("roundcube", "Roundcube (Webmail)"),
    ("splunk", "Splunk"),
    ("opencart", "OpenCart"),
    ("prestashop", "PrestaShop"),
];

/// Registry of all scan modules: (id, display label, is_anti_persistence, auto-scan interval).
///
/// Modules that change the system (quarantine files, rewrite crontabs or rc
/// files, stop units) are `OnDemand`: they only run when the operator starts a
/// scan, never from the background auto-scan. See `REMEDIATING_MODULES`.
pub const SCAN_MODULES: &[(&str, &str, bool, ScanInterval)] = crate::core::STANDARD_SCAN_MODULES;

/// Hardening steps with their IDs and display labels.
const HARDENING_STEPS: &[(&str, &str)] = &[
    ("user_permissions", "User & File Permissions"),
    ("services", "Disable Unnecessary Services"),
    ("programs", "Restrict Dangerous Programs"),
    ("configs", "Deploy Hardened Configs"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Logs,
    Scan,
    Hardening,
    Backups,
    Monitor,
    Tools,
    ServiceRestore,
    Router,
    PaloAlto,
}

impl Tab {
    /// All tabs for non-router server boxes (Web, Mail, Splunk):
    /// Router and PaloAlto tabs are omitted, leaving 8 active tabs with Svc Restore.
    pub const NON_ROUTER: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Logs,
        Tab::Scan,
        Tab::Hardening,
        Tab::Backups,
        Tab::Monitor,
        Tab::Tools,
        Tab::ServiceRestore,
    ];

    /// All tabs for Workstation (General):
    /// Svc Restore is replaced with dedicated Palo Alto audit scan tab.
    pub const WORKSTATION: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Logs,
        Tab::Scan,
        Tab::Hardening,
        Tab::Backups,
        Tab::Monitor,
        Tab::Tools,
        Tab::PaloAlto,
    ];

    /// All tabs for Router box type:
    /// Router is placed at tab 4 (matching Hardening on other boxes), and Svc Restore is omitted,
    /// giving the router exactly 7 streamlined tabs.
    pub const ROUTER: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Logs,
        Tab::Scan,
        Tab::Router,
        Tab::Backups,
        Tab::Monitor,
        Tab::Tools,
    ];

    /// All tabs in default display order — used as a complete list of known tabs.
    pub const ALL: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Logs,
        Tab::Scan,
        Tab::Hardening,
        Tab::Backups,
        Tab::Monitor,
        Tab::Tools,
        Tab::ServiceRestore,
        Tab::Router,
        Tab::PaloAlto,
    ];

    /// Return the slice of tabs displayed for the given box type.
    pub fn for_box_type(box_type: BoxType) -> &'static [Tab] {
        match box_type {
            BoxType::Router => Self::ROUTER,
            BoxType::General => Self::WORKSTATION,
            _ => Self::NON_ROUTER,
        }
    }

    /// Human-readable name shown in the tab bar.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Logs => "Logs",
            Tab::Scan => "Scan",
            Tab::Hardening => "Hardening",
            Tab::Backups => "Backups",
            Tab::Monitor => "Monitor",
            Tab::Tools => "Tools",
            Tab::ServiceRestore => "Svc Restore",
            Tab::Router => "Router",
            Tab::PaloAlto => "Palo Alto",
        }
    }

    /// Map a `1`–`9` digit keypress to the corresponding tab for the given box type, or `None` if out of range.
    pub fn from_digit(d: char, box_type: BoxType) -> Option<Tab> {
        let tabs = Self::for_box_type(box_type);
        let idx = d.to_digit(10)?.checked_sub(1)? as usize;
        tabs.get(idx).copied()
    }

    /// Return the single digit key character ('1'..'9') that activates this tab for the given box type.
    pub fn digit_for(self, box_type: BoxType) -> Option<char> {
        let tabs = Self::for_box_type(box_type);
        let idx = tabs.iter().position(|&t| t == self)?;
        char::from_digit((idx + 1) as u32, 10)
    }
}

/// Which service is waiting for credential input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreCredService {
    /// Splunk Enterprise.
    Splunk,
    /// OpenCart web storefront.
    OpenCart,
    /// PrestaShop web storefront.
    PrestaShop,
}

/// Which field is currently focused in the credential dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreCredField {
    /// Field index 0.
    F0,
    /// Field index 1.
    F1,
    /// Field index 2.
    F2,
    /// Field index 3.
    F3,
    /// Field index 4.
    F4,
    /// Field index 5.
    F5,
    /// Field index 6.
    F6,
    /// Field index 7.
    F7,
    /// Field index 8.
    F8,
}

impl RestoreCredField {
    /// Advance to the next field, clamping at the last field for the given service.
    fn next(self, service: RestoreCredService) -> Self {
        let max = match service {
            RestoreCredService::Splunk => 1,
            RestoreCredService::OpenCart => 8,
            RestoreCredService::PrestaShop => 6,
        };
        let idx = (self as usize + 1).min(max);
        Self::from_idx(idx)
    }
    /// Move to the previous field, stopping at F0.
    fn prev(self) -> Self {
        let idx = (self as usize).saturating_sub(1);
        Self::from_idx(idx)
    }
    /// Convert a numeric index to the corresponding variant, clamping at F8.
    fn from_idx(idx: usize) -> Self {
        match idx {
            0 => Self::F0,
            1 => Self::F1,
            2 => Self::F2,
            3 => Self::F3,
            4 => Self::F4,
            5 => Self::F5,
            6 => Self::F6,
            7 => Self::F7,
            _ => Self::F8,
        }
    }
}

/// State for the credential-input modal shown before a web-app restore.
pub(crate) struct RestoreCredDialog {
    /// Which service these credentials are for.
    service: RestoreCredService,
    /// Input buffer for each form field; length is always 9 (unused slots stay empty).
    fields: [String; 9],
    /// Which field currently has keyboard focus.
    focused: RestoreCredField,
}

/// Return `http://<primary-ip>/` using `hostname -I`, falling back to `localhost`.
fn detect_http_base_url() -> String {
    use std::process::Command;
    let out = Command::new("hostname").arg("-I").output().ok();
    if let Some(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Some(ip) = s.split_whitespace().next() {
            return format!("http://{ip}/");
        }
    }
    "http://localhost/".into()
}

impl RestoreCredDialog {
    /// Build a new dialog pre-populated with sensible defaults for `service`.
    fn new(service: RestoreCredService) -> Self {
        // Fields are indexed 0..=8 and must match field_label() and into_credentials() exactly.
        let fields = match service {
            RestoreCredService::Splunk => [
                "admin".into(), // 0  Admin Username
                String::new(),  // 1  Admin Password
                String::new(),  // 2  (unused)
                String::new(),  // 3  (unused)
                String::new(),  // 4  (unused)
                String::new(),  // 5  (unused)
                String::new(),  // 6  (unused)
                String::new(),  // 7  (unused)
                String::new(),  // 8  (unused)
            ],
            RestoreCredService::OpenCart => [
                "localhost".into(),         // 0  DB Hostname
                "root".into(),              // 1  DB Username
                String::new(),              // 2  DB Password
                "opencart".into(),          // 3  DB Name
                "3306".into(),              // 4  DB Port
                detect_http_base_url(),     // 5  HTTP base URL
                "admin".into(),             // 6  Admin Username
                String::new(),              // 7  Admin Password
                "admin@example.com".into(), // 8  Admin Email
            ],
            RestoreCredService::PrestaShop => [
                "localhost".into(),         // 0  Shop Domain
                "localhost".into(),         // 1  DB Server
                "prestashop".into(),        // 2  DB Name
                "root".into(),              // 3  DB Username
                String::new(),              // 4  DB Password
                "admin@example.com".into(), // 5  Admin Email
                String::new(),              // 6  Admin Password
                String::new(),              // 7  (unused)
                String::new(),              // 8  (unused)
            ],
        };
        Self {
            service,
            fields,
            focused: RestoreCredField::F0,
        }
    }

    /// Labels for each field depending on the service.
    fn field_label(&self, idx: usize) -> &'static str {
        match self.service {
            RestoreCredService::Splunk => match idx {
                0 => "Admin Username",
                1 => "Admin Password",
                _ => "",
            },
            RestoreCredService::OpenCart => match idx {
                0 => "DB Hostname",
                1 => "DB Username",
                2 => "DB Password",
                3 => "DB Name",
                4 => "DB Port",
                5 => "HTTP base URL",
                6 => "Admin Username",
                7 => "Admin Password",
                8 => "Admin Email",
                _ => "",
            },
            RestoreCredService::PrestaShop => match idx {
                0 => "Shop Domain (no http://)",
                1 => "DB Server",
                2 => "DB Name",
                3 => "DB Username",
                4 => "DB Password",
                5 => "Admin Email",
                6 => "Admin Password",
                _ => "",
            },
        }
    }

    /// Number of active fields for this service (unused trailing slots are hidden).
    fn field_count(&self) -> usize {
        match self.service {
            RestoreCredService::Splunk => 2,
            RestoreCredService::OpenCart => 9,
            RestoreCredService::PrestaShop => 7,
        }
    }

    /// Consume the dialog and return typed credentials ready for the restore thread.
    fn into_credentials(self) -> crate::service_restore::RestoreCredentials {
        let [f0, f1, f2, f3, f4, f5, f6, f7, f8] = self.fields;
        match self.service {
            RestoreCredService::Splunk => crate::service_restore::RestoreCredentials {
                splunk: Some(crate::service_restore::splunk::SplunkCredentials {
                    admin_user: f0,
                    admin_pass: f1,
                }),
                opencart: None,
                prestashop: None,
            },
            RestoreCredService::OpenCart => crate::service_restore::RestoreCredentials {
                splunk: None,
                opencart: Some(crate::service_restore::opencart::OpenCartCredentials {
                    db_host: f0,
                    db_user: f1,
                    db_pass: f2,
                    db_name: f3,
                    db_port: f4,
                    http_server: f5,
                    admin_user: f6,
                    admin_pass: f7,
                    admin_email: f8,
                }),
                prestashop: None,
            },
            RestoreCredService::PrestaShop => crate::service_restore::RestoreCredentials {
                splunk: None,
                opencart: None,
                prestashop: Some(crate::service_restore::prestashop::PrestaShopCredentials {
                    domain: f0,
                    db_server: f1,
                    db_name: f2,
                    db_user: f3,
                    db_pass: f4,
                    admin_email: f5,
                    admin_pass: f6,
                }),
            },
        }
    }
}

/// How long the second `r` press that confirms nftbuild may take.
const NFTBUILD_CONFIRM_WINDOW: Duration = Duration::from_secs(5);

/// What one background poll of services, sessions and the auth log found.
struct PollResult {
    /// Service histories with this poll's results appended.
    services: Vec<ServiceHistory>,
    /// Current logged-in sessions.
    sessions: Vec<SessionInfo>,
    /// Latest relevant auth log lines.
    auth_events: Vec<String>,
}

/// Which router phase the configuration dialog is prompting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterDialogStep {
    /// Phase 1 hardening: rotate admin password, harden SSH, apply control plane firewall.
    Harden,
    /// Phase 2 console lockdown: disable SSH entirely and terminate active sessions.
    ConsoleLockdown,
    /// Restore CCDC DNAT Rules 10-14 & configure outbound PAT.
    RestoreNat,
    /// Separately rotate vyos and root passwords; sanitize authorized_keys.
    RotatePasswords,
}

/// Modal configuration dialog for Router Phase 1 & Phase 2 operations.
pub(crate) struct RouterConfigDialog {
    /// Active router operation step being configured.
    step: RouterDialogStep,
    /// Input field string values.
    fields: [String; 4],
    /// Index of the currently focused input field.
    focused: usize,
}

/// Auto-detect CCDC team number from WAN interface IP `172.31.{20+T}.2/29` or practice `172.31.40.2/29`.
fn detect_vyos_team_number() -> Option<u8> {
    use std::process::Command;
    let out = Command::new("ip")
        .args(["-4", "addr", "show"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for word in text.split_whitespace() {
        if let Some(ip) = word.split('/').next() {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4
                && parts[0] == "172"
                && parts[1] == "31"
                && let Ok(octet) = parts[2].parse::<u8>()
            {
                if octet == 40 {
                    // Practice Environment WAN IP is 172.31.40.2/29
                    return Some(0);
                } else if (21..=39).contains(&octet) {
                    // Competition teams 1..19
                    return Some(octet - 20);
                }
            }
        }
    }
    None
}

impl RouterConfigDialog {
    /// Create a new modal configuration dialog for the given step with sensible defaults.
    fn new(step: RouterDialogStep, default_team: Option<u8>) -> Self {
        let team_str = default_team
            .or_else(detect_vyos_team_number)
            .map(|t| t.to_string())
            .unwrap_or_default();

        let fields = match step {
            RouterDialogStep::Harden => [
                team_str,
                String::new(),
                "172.17.0.0/24".into(),
                String::new(),
            ],
            RouterDialogStep::ConsoleLockdown => {
                [String::new(), "no".into(), String::new(), String::new()]
            }
            RouterDialogStep::RestoreNat => {
                [team_str, "private".into(), "baseline".into(), "no".into()]
            }
            RouterDialogStep::RotatePasswords => {
                [String::new(), String::new(), "yes".into(), String::new()]
            }
        };
        Self {
            step,
            fields,
            focused: 0,
        }
    }

    /// Return the number of input fields used by the current dialog step.
    fn field_count(&self) -> usize {
        match self.step {
            RouterDialogStep::Harden => 4,
            RouterDialogStep::ConsoleLockdown => 2,
            RouterDialogStep::RestoreNat => 4,
            RouterDialogStep::RotatePasswords => 3,
        }
    }

    /// Return the display label for an input field at `idx`.
    fn field_label(&self, idx: usize) -> &'static str {
        match self.step {
            RouterDialogStep::Harden => match idx {
                0 => "CCDC Team Number [0-20]",
                1 => "New 'vyos' Admin Password",
                2 => "Management Subnet (wkst)",
                3 => "SSH Public Key (optional)",
                _ => "",
            },
            RouterDialogStep::ConsoleLockdown => match idx {
                0 => "New 'vyos' Console Password",
                1 => "Force Override Active SSH Check? (yes/no)",
                _ => "",
            },
            RouterDialogStep::RestoreNat => match idx {
                0 => "CCDC Team Number [0-20]",
                1 => "DNAT Target [private / public]",
                2 => "Restore Mode [baseline / detected / backup]",
                3 => "Enable Outbound PAT? [yes / no]",
                _ => "",
            },
            RouterDialogStep::RotatePasswords => match idx {
                0 => "New Password for 'vyos' (Operator)",
                1 => "New Password for Linux 'root' (Superuser)",
                2 => "Sanitize authorized_keys? [yes / no]",
                _ => "",
            },
        }
    }

    /// Convert dialog form inputs into a step identifier and CLI arguments.
    fn into_cli_args(self) -> (&'static str, crate::router::CliArgs) {
        match self.step {
            RouterDialogStep::Harden => {
                let team: Option<u8> = self.fields[0].trim().parse().ok();
                let pass = self.fields[1].clone();
                let mgmt = if self.fields[2].trim().is_empty() {
                    "172.17.0.0/24".to_string()
                } else {
                    self.fields[2].trim().to_string()
                };
                let ssh_key = if self.fields[3].trim().is_empty() {
                    None
                } else {
                    Some(self.fields[3].trim().to_string())
                };
                (
                    "harden",
                    crate::router::CliArgs {
                        harden: true,
                        team,
                        pass: Some(pass),
                        mgmt_subnet: Some(mgmt),
                        ssh_key,
                        ..Default::default()
                    },
                )
            }
            RouterDialogStep::ConsoleLockdown => {
                let pass = self.fields[0].clone();
                let force = self.fields[1].trim().eq_ignore_ascii_case("yes");
                (
                    "console_lockdown",
                    crate::router::CliArgs {
                        console_lockdown: true,
                        pass: Some(pass),
                        force,
                        ..Default::default()
                    },
                )
            }
            RouterDialogStep::RestoreNat => {
                let team: Option<u8> = self.fields[0].trim().parse().ok();
                let dnat_target = if self.fields[1].trim().is_empty() {
                    Some("private".to_string())
                } else {
                    Some(self.fields[1].trim().to_string())
                };
                let restore_mode = if self.fields[2].trim().is_empty() {
                    Some("baseline".to_string())
                } else {
                    Some(self.fields[2].trim().to_string())
                };
                let enable_outbound_pat = self.fields[3].trim().eq_ignore_ascii_case("yes");
                (
                    "router_nat",
                    crate::router::CliArgs {
                        restore_nat: true,
                        team,
                        dnat_target,
                        restore_mode,
                        enable_outbound_pat,
                        ..Default::default()
                    },
                )
            }
            RouterDialogStep::RotatePasswords => {
                let vyos_pass = self.fields[0].clone();
                let root_pass = self.fields[1].clone();
                (
                    "rotate_passwords",
                    crate::router::CliArgs {
                        rotate_passwords: true,
                        user: Some("vyos".into()),
                        pass: Some(vyos_pass.clone()),
                        vyos_pass: Some(vyos_pass),
                        root_pass: Some(root_pass),
                        ..Default::default()
                    },
                )
            }
        }
    }
}

pub struct App {
    pub box_type: BoxType,
    pub team: Option<u8>,
    pub tab: Tab,
    pub findings: Vec<Finding>,
    /// Scored-service check histories (latency, uptime %, last result).
    pub services: Vec<ServiceHistory>,
    pub log_dashboard: LogDash,
    pub finding_tx: Sender<Finding>,
    pub finding_rx: Receiver<Finding>,
    pub last_service_check: Instant,
    /// Results of the in-flight background poll, if one is running.
    poll_rx: Option<Receiver<PollResult>>,
    // Scan tab state
    pub scan_running: bool,
    pub scan_progress: String,
    pub scan_progress_rx: Receiver<String>,
    pub scan_progress_tx: Sender<String>,
    pub scan_selected: Vec<bool>,
    pub scan_cursor: usize,
    /// Which pane in the Scan tab currently has keyboard focus.
    pub(crate) scan_focus: ScanFocus,
    pub findings_cursor: usize,
    pub show_finding_detail: bool,
    pub action_feedback: Option<String>,
    /// Generated nftables config from nftbuild (not yet applied).
    pub nft_config: Option<String>,
    /// When `r` was first pressed on nftbuild; a second press within
    /// [`NFTBUILD_CONFIRM_WINDOW`] applies the rules.
    nftbuild_confirm_at: Option<Instant>,
    /// Status message shown in the Tools tab during downloads.
    pub download_status: Option<String>,
    /// Receives the result string from a background download thread.
    download_result_rx: Receiver<String>,
    /// Receives the result from a background nftbuild thread (Ok=config, Err=message).
    nftbuild_result_rx: Receiver<Result<String, String>>,
    /// Flat cursor in the Tools tab (binaries first, then wizards).
    pub tools_cursor: usize,
    /// Vertical scroll offset for active nftables configuration in the Tools tab.
    pub tools_nft_scroll: usize,
    /// Currently open TUI wizard overlay, if any.
    pub active_wizard: Option<crate::wizards::ActiveWizard>,
    /// Currently logged-in sessions, polled every 5s.
    pub sessions: Vec<SessionInfo>,
    /// Recent auth log events, polled every 5s.
    pub auth_events: Vec<String>,
    /// Whether auto-scan (continuous + frequent) is running in the background.
    pub auto_scan_enabled: bool,
    /// When each module was last auto-scanned.
    pub auto_scan_last_run: HashMap<&'static str, Instant>,
    /// Module IDs currently being scanned in a background auto-scan thread.
    pub auto_scan_running: HashSet<&'static str>,
    /// Channel used by background auto-scan threads to signal completion.
    auto_scan_done_tx: Sender<&'static str>,
    /// Receiver end of the auto-scan completion channel.
    auto_scan_done_rx: Receiver<&'static str>,
    /// Automatically restart scored services that go down.
    pub watchdog_enabled: bool,
    /// How many times we have already restarted each service this session.
    pub watchdog_restart_count: HashMap<&'static str, u32>,
    /// Usernames that are permitted to be logged in (not flagged in Sessions pane).
    pub authorized_users: Vec<String>,
    /// True while the "add authorized user" text-input overlay is showing.
    pub user_input_active: bool,
    /// Buffer for the in-progress username being typed.
    pub user_input_buf: String,
    // ── Hardening tab state ──────────────────────────────────────────────────
    /// Cursor position in the hardening step list.
    pub hardening_cursor: usize,
    /// True while a hardening step is running in the background.
    pub hardening_running: bool,
    /// Output lines from the last/current hardening run.
    pub hardening_log: Vec<String>,
    /// How many lines the hardening output panel is scrolled up from the bottom.
    pub hardening_log_scroll: usize,
    /// Findings emitted by hardening modules (separate from scan findings).
    hardening_finding_tx: Sender<Finding>,
    /// Receiver end of the hardening findings channel.
    hardening_finding_rx: Receiver<Finding>,
    /// Signal channel: empty string = done, non-empty = progress label.
    hardening_progress_tx: Sender<String>,
    /// Receiver end of the hardening progress channel.
    hardening_progress_rx: Receiver<String>,
    // ── Monitor tab state ────────────────────────────────────────────────────
    /// Cursor position in the monitor module list.
    pub monitor_cursor: usize,
    /// True while a monitor module is running in the background.
    pub monitor_running: bool,
    /// Output lines from the last/current monitor run.
    pub monitor_log: Vec<String>,
    /// How many lines the monitor output panel is scrolled up from the bottom.
    pub monitor_log_scroll: usize,
    /// Signal channel: empty string = done, non-empty = log line.
    monitor_progress_tx: Sender<String>,
    /// Receiver end of the monitor progress channel.
    monitor_progress_rx: Receiver<String>,
    // ── Backups tab state ────────────────────────────────────────────────────
    /// Cursor position in the backup step list.
    pub backups_cursor: usize,
    /// True while a backup operation is running in the background.
    pub backups_running: bool,
    /// Output lines from the last/current backup run.
    pub backups_log: Vec<String>,
    /// How many lines the backup output panel is scrolled up from the bottom.
    pub backups_log_scroll: usize,
    /// Signal channel: empty string = done, non-empty = log line.
    backups_progress_tx: Sender<String>,
    /// Receiver end of the backups progress channel.
    backups_progress_rx: Receiver<String>,
    // ── Service Restore tab state ────────────────────────────────────────────
    /// Cursor position in the service restore list.
    pub restore_cursor: usize,
    /// True while a service restore is running in the background.
    pub restore_running: bool,
    /// Output lines from the last/current restore run.
    pub restore_log: Vec<String>,
    /// How many lines the restore output panel is scrolled up from the bottom.
    pub restore_log_scroll: usize,
    /// Signal channel: empty string = done, non-empty = log line.
    restore_progress_tx: Sender<String>,
    /// Receiver end of the service restore progress channel.
    restore_progress_rx: Receiver<String>,
    /// True if at least one backup directory exists under the known backup roots.
    pub baseline_present: bool,
    /// Credential input dialog shown before OpenCart / PrestaShop restore.
    restore_cred_dialog: Option<RestoreCredDialog>,
    // ── Router tab state ─────────────────────────────────────────────────────
    /// Which pane of the Router tab currently has keyboard focus.
    pub(crate) router_focus: RouterFocus,
    /// Cursor position in the router step list.
    pub router_cursor: usize,
    /// True while a router operation is running in the background.
    pub router_running: bool,
    /// Output lines from the last/current router run.
    pub router_log: Vec<String>,
    /// How many lines the router output panel is scrolled up from the bottom.
    pub router_log_scroll: usize,
    /// Signal channel: empty string = done, non-empty = log line.
    router_progress_tx: Sender<String>,
    /// Receiver end of the router progress channel.
    router_progress_rx: Receiver<String>,
    /// Modal dialog for collecting Phase 1/2 router credentials.
    pub(crate) router_config_dialog: Option<RouterConfigDialog>,
    /// Active pending commit-confirm state on the router, if any.
    pub(crate) router_pending_confirm: Option<RouterPendingConfirm>,
    /// Step ID of the currently active router background run.
    pub(crate) router_active_step: Option<&'static str>,
    /// CliArgs of the currently active router background run.
    pub(crate) router_active_args: Option<crate::router::CliArgs>,
    // ── Palo Alto tab state (Workstation BoxType::General) ───────────────────
    /// Full path to running-config.xml.
    pub palo_config_path: String,
    /// Optional full path to baseline XML for drift comparison.
    pub palo_baseline_path: String,
    /// Optional CCDC team number (1-20 or 0).
    pub palo_team: String,
    /// Which pane currently has keyboard focus on the Palo Alto tab.
    pub palo_focus: PaloFocus,
    /// Cursor index among right-pane controls (0-2: fields, 3-5: buttons).
    pub palo_control_cursor: usize,
    /// Core findings produced by the Palo Alto audit engine.
    pub palo_findings: Vec<Finding>,
    /// Raw audit findings with remediation commands for script generation.
    pub palo_findings_raw: Vec<crate::tools::palo_alto::PaloAltoFinding>,
    /// Cursor position in the findings list.
    pub palo_findings_cursor: usize,
    /// Whether the full finding detail overlay is visible.
    pub palo_show_finding_detail: bool,
    /// Path of the last exported remediation script, if any.
    pub palo_last_export: Option<String>,
    /// Status message displayed in the diagnostics box: (text, is_error).
    pub palo_status_msg: Option<(String, bool)>,
}

/// State for tracking a pending VyOS commit-confirm rollback window.
#[derive(Debug, Clone)]
pub(crate) struct RouterPendingConfirm {
    /// Instant when the commit-confirm will automatically roll back if not confirmed.
    pub(crate) deadline: Instant,
    /// Whether the confirmation modal dialog is currently visible.
    pub(crate) modal_open: bool,
}

impl App {
    /// Construct a new [`App`] with the given box type and channel endpoints.
    fn new(
        box_type: BoxType,
        log_dashboard: LogDash,
        finding_tx: Sender<Finding>,
        finding_rx: Receiver<Finding>,
        nft_config: Option<String>,
        team: Option<u8>,
    ) -> Self {
        if box_type == BoxType::Mail {
            crate::score_check::ensure_mail_test_account();
        }
        let services = build_histories(box_type.checks());
        let (scan_progress_tx, scan_progress_rx) = mpsc::channel();
        let (auto_scan_done_tx, auto_scan_done_rx) = mpsc::channel::<&'static str>();
        let (hardening_finding_tx, hardening_finding_rx) = mpsc::channel::<Finding>();
        let (hardening_progress_tx, hardening_progress_rx) = mpsc::channel::<String>();
        let (monitor_progress_tx, monitor_progress_rx) = mpsc::channel::<String>();
        let (backups_progress_tx, backups_progress_rx) = mpsc::channel::<String>();
        let (restore_progress_tx, restore_progress_rx) = mpsc::channel::<String>();
        let (router_progress_tx, router_progress_rx) = mpsc::channel::<String>();
        let (_download_result_tx_placeholder, download_result_rx) = mpsc::channel::<String>();
        let (_nftbuild_result_tx_placeholder, nftbuild_result_rx) =
            mpsc::channel::<Result<String, String>>();
        let scan_selected = vec![true; box_type.scan_modules().len()];
        let authorized_users = vec!["root".to_string()];
        let sessions = poll_sessions(&authorized_users);
        Self {
            box_type,
            team,
            tab: Tab::Dashboard,
            findings: Vec::new(),
            services,
            log_dashboard,
            finding_tx,
            finding_rx,
            last_service_check: Instant::now(),
            poll_rx: None,
            scan_running: false,
            scan_progress: String::new(),
            scan_progress_rx,
            scan_progress_tx,
            scan_selected,
            scan_cursor: 0,
            scan_focus: ScanFocus::Modules,
            findings_cursor: 0,
            show_finding_detail: false,
            action_feedback: None,
            nft_config,
            nftbuild_confirm_at: None,
            download_status: None,
            download_result_rx,
            nftbuild_result_rx,
            tools_cursor: 0,
            tools_nft_scroll: 0,
            active_wizard: None,
            sessions,
            auth_events: poll_auth_events(),
            auto_scan_enabled: false,
            auto_scan_last_run: HashMap::new(),
            auto_scan_running: HashSet::new(),
            auto_scan_done_tx,
            auto_scan_done_rx,
            watchdog_enabled: false,
            watchdog_restart_count: HashMap::new(),
            authorized_users,
            user_input_active: false,
            user_input_buf: String::new(),
            hardening_cursor: 0,
            hardening_running: false,
            hardening_log: Vec::new(),
            hardening_log_scroll: 0,
            hardening_finding_tx,
            hardening_finding_rx,
            hardening_progress_tx,
            hardening_progress_rx,
            monitor_cursor: 0,
            monitor_running: false,
            monitor_log: Vec::new(),
            monitor_log_scroll: 0,
            monitor_progress_tx,
            monitor_progress_rx,
            backups_cursor: 0,
            backups_running: false,
            backups_log: Vec::new(),
            backups_log_scroll: 0,
            backups_progress_tx,
            backups_progress_rx,
            restore_cursor: 0,
            restore_running: false,
            restore_log: Vec::new(),
            restore_log_scroll: 0,
            restore_progress_tx,
            restore_progress_rx,
            baseline_present: Self::detect_baseline(),
            restore_cred_dialog: None,
            router_focus: RouterFocus::Operations,
            router_cursor: 0,
            router_running: false,
            router_log: Vec::new(),
            router_log_scroll: 0,
            router_progress_tx,
            router_progress_rx,
            router_config_dialog: None,
            router_pending_confirm: None,
            router_active_step: None,
            router_active_args: None,
            palo_config_path: if std::path::Path::new("/etc/defender/palo-alto/running-config.xml").exists() {
                "/etc/defender/palo-alto/running-config.xml".to_string()
            } else {
                String::new()
            },
            palo_baseline_path: String::new(),
            palo_team: team.map(|t| t.to_string()).unwrap_or_default(),
            palo_focus: PaloFocus::Controls,
            palo_control_cursor: 0,
            palo_findings: Vec::new(),
            palo_findings_raw: Vec::new(),
            palo_findings_cursor: 0,
            palo_show_finding_detail: false,
            palo_last_export: None,
            palo_status_msg: None,
        }
    }

    /// Return the slice of active tabs for this app instance based on its box type.
    pub fn tabs(&self) -> &'static [Tab] {
        Tab::for_box_type(self.box_type)
    }

    /// Return true if any backup directory exists under the known roots.
    fn detect_baseline() -> bool {
        let roots = ["/root/baseline", "/etc/linux-defender/baseline"];
        for root in &roots {
            if std::path::Path::new(root).exists() {
                return true;
            }
        }
        // also check for any ccdc-b@ckup-* directory under /etc
        if let Ok(entries) = std::fs::read_dir("/etc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("ccdc-b") {
                    return true;
                }
            }
        }
        false
    }

    /// Findings visible in the Scan tab -- excludes diagnostic "log" module entries from ctx.log_msg().
    fn display_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.module != "log").collect()
    }

    /// Process all pending channel messages and trigger periodic service/session polling.
    fn tick(&mut self) {
        while let Ok(f) = self.finding_rx.try_recv() {
            let is_dup = self.findings.iter().rev().take(50).any(|existing| {
                existing.module == f.module
                    && existing.summary == f.summary
                    && existing
                        .timestamp
                        .signed_duration_since(f.timestamp)
                        .num_seconds()
                        .abs()
                        < 120
            });
            if !is_dup {
                self.findings.push(f);
            }
        }
        let display_len = self.display_findings().len();
        if display_len > 0 && self.findings_cursor >= display_len {
            self.findings_cursor = display_len - 1;
        } else if display_len == 0 {
            self.findings_cursor = 0;
        }
        for pane in &mut self.log_dashboard.panes {
            pane.drain();
        }
        while let Ok(p) = self.scan_progress_rx.try_recv() {
            if p.is_empty() {
                self.scan_running = false;
                self.scan_progress.clear();
            } else {
                self.scan_progress = p;
            }
        }
        // Drain hardening findings into the hardening log.
        while let Ok(f) = self.hardening_finding_rx.try_recv() {
            self.hardening_log.push(strip_ansi(&format!(
                "[{}] {} — {}",
                f.severity.label().trim(),
                f.module,
                f.summary
            )));
        }
        // Drain hardening progress: empty string = done, non-empty = step label.
        while let Ok(p) = self.hardening_progress_rx.try_recv() {
            if p.is_empty() {
                self.hardening_running = false;
                self.hardening_log.push("Done.".to_string());
            } else {
                self.hardening_log
                    .push(strip_ansi(&format!("Running: {}…", p)));
            }
        }
        // Drain monitor progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.monitor_progress_rx.try_recv() {
            if p.is_empty() {
                self.monitor_running = false;
            } else {
                self.monitor_log.push(strip_ansi(&p));
            }
        }
        // Drain backups progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.backups_progress_rx.try_recv() {
            if p.is_empty() {
                self.backups_running = false;
                self.baseline_present = true;
            } else {
                self.backups_log.push(strip_ansi(&p));
            }
        }
        // Drain service restore progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.restore_progress_rx.try_recv() {
            if p.is_empty() {
                self.restore_running = false;
            } else {
                self.restore_log.push(strip_ansi(&p));
            }
        }
        // Drain router progress: sentinels = done, non-empty = log line.
        while let Ok(p) = self.router_progress_rx.try_recv() {
            if p == crate::router::ROUTER_PROGRESS_DONE_OK {
                self.router_running = false;
                self.handle_router_completion(true);
            } else if p == crate::router::ROUTER_PROGRESS_DONE_ERROR {
                self.router_running = false;
                self.handle_router_completion(false);
            } else if p.is_empty() {
                self.router_running = false;
                self.handle_router_completion(true);
            } else {
                self.router_log.push(p);
            }
        }
        if let Some(ref pending) = self.router_pending_confirm
            && crate::router::is_pending_expired(Instant::now(), pending.deadline)
        {
            self.router_pending_confirm = None;
            self.router_log.push(
                "✗ Commit-confirm deadline expired! VyOS has rolled back the changes. Phase 1 must be run again."
                    .to_string(),
            );
        }
        // Drain completed auto-scan threads.
        while let Ok(id) = self.auto_scan_done_rx.try_recv() {
            self.auto_scan_running.remove(id);
        }
        // Pick up download result when the background thread finishes.
        if let Ok(msg) = self.download_result_rx.try_recv() {
            self.download_status = Some(msg);
        }
        // Pick up nftbuild result when the background thread finishes.
        if let Ok(result) = self.nftbuild_result_rx.try_recv() {
            match result {
                Ok(config) => {
                    self.nft_config = Some(config);
                    self.action_feedback = Some("nftbuild applied — ruleset is now active".into());
                }
                Err(e) => {
                    self.action_feedback = Some(format!("nftbuild failed: {}", e));
                }
            }
        }
        if self.auto_scan_enabled {
            self.tick_auto_scan();
        }
        // Service checks block for seconds when services are down, which is
        // exactly when the operator needs the UI. They run on a background
        // thread; the UI applies the results when they arrive.
        if let Some(rx) = &self.poll_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.poll_rx = None;
                    self.services = result.services;
                    self.sessions = result.sessions;
                    self.auth_events = result.auth_events;
                    self.run_watchdog();
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => self.poll_rx = None,
            }
        } else if self.last_service_check.elapsed() >= Duration::from_secs(5) {
            self.last_service_check = Instant::now();
            let mut services = self.services.clone();
            let authorized = self.authorized_users.clone();
            let (tx, rx) = mpsc::channel();
            self.poll_rx = Some(rx);
            std::thread::spawn(move || {
                poll_all(&mut services);
                let _ = tx.send(PollResult {
                    services,
                    sessions: poll_sessions(&authorized),
                    auth_events: poll_auth_events(),
                });
            });
        }
    }

    /// Restart scored services that the latest poll found down (at most three
    /// attempts each), when the watchdog is enabled.
    fn run_watchdog(&mut self) {
        if self.watchdog_enabled {
            let down: Vec<crate::score_check::ServiceCheck> = self
                .services
                .iter()
                .filter(|h| !h.is_up())
                .map(|h| h.check.clone())
                .collect();
            for check in down {
                let name = check.name;
                let count = self.watchdog_restart_count.get(name).copied().unwrap_or(0);
                if count < 3 {
                    *self.watchdog_restart_count.entry(name).or_insert(0) += 1;
                    // `name` is a display label; restart the systemd
                    // unit(s) that actually provide the service.
                    self.action_feedback = Some(format!(
                        "Watchdog: {} is down — restarting {}…",
                        name,
                        check.units.join("/")
                    ));
                    std::thread::spawn(move || {
                        let _ = crate::score_check::restart_service_units(&check);
                    });
                }
            }
        }
    }

    /// Spawn background threads for any auto-scan module that is now due.
    fn tick_auto_scan(&mut self) {
        let box_type = self.box_type;
        for (id, _, is_ap, interval) in self.box_type.scan_modules() {
            let threshold = match interval {
                ScanInterval::Continuous => Duration::from_secs(30),
                ScanInterval::Frequent => Duration::from_secs(300),
                ScanInterval::OnDemand => continue,
            };
            if REMEDIATING_MODULES.contains(id) {
                continue;
            }
            if self.auto_scan_running.contains(id) {
                continue;
            }
            let due = self
                .auto_scan_last_run
                .get(id)
                .map(|t| t.elapsed() >= threshold)
                .unwrap_or(true);
            if !due {
                continue;
            }
            self.auto_scan_last_run.insert(id, Instant::now());
            self.auto_scan_running.insert(id);

            let finding_tx = self.finding_tx.clone();
            let done_tx = self.auto_scan_done_tx.clone();
            let id_str: &'static str = id;
            let is_ap = *is_ap;

            std::thread::spawn(move || {
                let report = crate::core::log_path("autoscan.log");
                let mut ctx = DefenderContext::new(report, false).with_silent_progress();
                ctx.finding_tx = Some(finding_tx);
                run_scan_module(id_str, is_ap, &ctx, box_type);
                let _ = done_tx.send(id_str);
            });
        }
    }

    /// Spawn a background thread that runs every selected scan module in sequence.
    fn start_scan(&mut self) {
        if self.scan_running {
            return;
        }

        let selected: Vec<(&'static str, bool)> = self
            .box_type
            .scan_modules()
            .iter()
            .enumerate()
            .filter(|(i, _)| self.scan_selected.get(*i).copied().unwrap_or(false))
            .map(|(_, (id, _, is_ap, _))| (*id, *is_ap))
            .collect();

        if selected.is_empty() {
            return;
        }

        self.scan_running = true;
        self.findings.clear();
        self.findings_cursor = 0;
        self.show_finding_detail = false;
        self.action_feedback = None;

        let finding_tx = self.finding_tx.clone();
        let progress_tx = self.scan_progress_tx.clone();
        let box_type = self.box_type;

        std::thread::spawn(move || {
            let report = crate::core::log_path("scan.log");
            let mut ctx = DefenderContext::new(report, false).with_silent_progress();
            ctx.finding_tx = Some(finding_tx);

            for (id, is_ap) in selected {
                let _ = progress_tx.send(id.to_string());
                run_scan_module(id, is_ap, &ctx, box_type);
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
    }

    /// Execute the Palo Alto XML audit scan on the workstation.
    pub fn run_palo_scan(&mut self) {
        let path = self.palo_config_path.trim();
        if path.is_empty() {
            self.palo_status_msg = Some(("Config XML path is required".to_string(), true));
            return;
        }
        let config_str = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                self.palo_status_msg = Some((format!("Failed to read config XML: {}", e), true));
                return;
            }
        };
        let root = match crate::tools::palo_alto::XmlNode::parse(&config_str) {
            Ok(r) => r,
            Err(e) => {
                self.palo_status_msg = Some((format!("Failed to parse config XML: {}", e), true));
                return;
            }
        };

        let team_num: Option<u8> = self.palo_team.trim().parse().ok().or(self.team);

        let mut all_raw = crate::tools::palo_alto::audit_config(&root, team_num);

        // Baseline diff if provided
        let b_path = self.palo_baseline_path.trim();
        if !b_path.is_empty() {
            match std::fs::read_to_string(b_path) {
                Ok(b_str) => match crate::tools::palo_alto::XmlNode::parse(&b_str) {
                    Ok(b_root) => {
                        let diff_findings = crate::tools::palo_alto::diff_baseline(&root, &b_root);
                        all_raw.extend(diff_findings);
                    }
                    Err(e) => {
                        self.palo_status_msg = Some((format!("Failed to parse baseline XML: {}", e), true));
                        return;
                    }
                },
                Err(e) => {
                    self.palo_status_msg = Some((format!("Failed to read baseline XML: {}", e), true));
                    return;
                }
            }
        }

        let converted: Vec<Finding> = all_raw.iter().map(|f| f.to_core_finding()).collect();
        self.palo_findings_raw = all_raw;
        self.palo_findings = converted.clone();
        self.palo_findings_cursor = 0;

        // Synchronize into main app findings: remove any old palo-alto findings, then append new ones
        self.findings.retain(|f| f.module != "palo-alto");
        self.findings.extend(converted);

        let crit = self.palo_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = self.palo_findings.iter().filter(|f| f.severity == Severity::High).count();
        self.palo_status_msg = Some((
            format!("Audit complete: {} findings ({} critical, {} high)", self.palo_findings.len(), crit, high),
            false,
        ));
        self.palo_focus = PaloFocus::Findings;
    }

    /// Export the PAN-OS CLI remediation script generated from current findings.
    pub fn export_palo_remediation(&mut self) {
        if self.palo_findings_raw.is_empty() {
            self.palo_status_msg = Some(("No audit findings to generate remediation from".to_string(), true));
            return;
        }

        let mut script = crate::tools::palo_alto::RemediationScript::new();
        for f in &self.palo_findings_raw {
            for cmd in &f.remediation {
                script.add(cmd.clone());
            }
        }

        if script.commands.is_empty() {
            self.palo_status_msg = Some(("All findings are informational or require manual review; no automated commands".to_string(), false));
            return;
        }

        let out_dir = std::path::Path::new("/etc/defender/palo-alto");
        if let Err(_) = std::fs::create_dir_all(out_dir) {
            let fallback_dir = std::path::Path::new("tmp/palo-alto");
            let _ = std::fs::create_dir_all(fallback_dir);
        }

        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let primary_path = format!("/etc/defender/palo-alto/remediation_{}.set", timestamp);
        let rendered = script.render();

        let final_path = match std::fs::write(&primary_path, &rendered) {
            Ok(_) => primary_path,
            Err(_) => {
                let fallback_path = format!("tmp/palo-alto/remediation_{}.set", timestamp);
                match std::fs::write(&fallback_path, &rendered) {
                    Ok(_) => fallback_path,
                    Err(e) => {
                        self.palo_status_msg = Some((format!("Failed to write remediation script: {}", e), true));
                        return;
                    }
                }
            }
        };

        self.palo_last_export = Some(final_path.clone());
        self.palo_status_msg = Some((format!("Remediation script exported ({})", final_path), false));
    }

    /// Spawn a background thread to run the selected hardening step.
    fn start_hardening(&mut self, step_id: &'static str) {
        if self.hardening_running {
            return;
        }
        self.hardening_running = true;
        self.hardening_log.clear();
        self.hardening_log_scroll = 0;

        let finding_tx = self.hardening_finding_tx.clone();
        let progress_tx = self.hardening_progress_tx.clone();
        let box_type = self.box_type;

        std::thread::spawn(move || {
            let report = crate::core::log_path("hardening.log");
            let mut ctx = DefenderContext::new(report, false)
                .with_progress(progress_tx.clone())
                .with_box_type(box_type);
            ctx.finding_tx = Some(finding_tx);

            let args = crate::system_hardening::CliArgs {
                user_permissions: step_id == "user_permissions",
                services: step_id == "services",
                programs: step_id == "programs",
                configs: step_id == "configs",
                install_tools: false,
            };

            let _ = progress_tx.send(step_id.to_string());
            if let Err(e) = crate::system_hardening::run(&ctx, &args) {
                let _ = progress_tx.send(format!("ERROR: {}", e));
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
    }

    /// Spawn a background thread to run a single monitoring module.
    fn start_monitor(&mut self, module_id: &'static str) {
        if self.monitor_running {
            return;
        }
        self.monitor_running = true;
        self.monitor_log.clear();
        self.monitor_log_scroll = 0;

        let finding_tx = self.finding_tx.clone();
        let progress_tx = self.monitor_progress_tx.clone();

        std::thread::spawn(move || {
            let _ = progress_tx.send(format!("Running {}…", module_id));
            let report = crate::core::log_path("monitor.log");
            let mut ctx = DefenderContext::new(report, false).with_progress(progress_tx.clone());
            ctx.finding_tx = Some(finding_tx);
            match crate::monitoring::run_module(module_id, &ctx) {
                Ok(()) => {
                    let _ = progress_tx.send(format!("Done: {}", module_id));
                }
                Err(e) => {
                    let _ = progress_tx.send(format!("Error: {}", e));
                }
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
    }

    /// Spawn a background thread to run the selected backup operation.
    fn start_backup(&mut self, step_id: &'static str) {
        if self.backups_running {
            return;
        }
        self.backups_running = true;
        self.backups_log.clear();
        self.backups_log_scroll = 0;

        let progress_tx = self.backups_progress_tx.clone();
        let label = self
            .box_type
            .backup_steps()
            .iter()
            .find(|(id, _)| *id == step_id)
            .map(|(_, l)| *l)
            .unwrap_or(step_id);

        std::thread::spawn(move || {
            let _ = progress_tx.send(format!("Starting: {}…", label));
            let report = crate::core::log_path("backup.log");
            let ctx = DefenderContext::new(report, false).with_progress(progress_tx.clone());
            let mut args = crate::backups::CliArgs {
                all: false,
                compare_hashes: false,
                custom: None,
                ecomm: false,
                mail: false,
                restore: false,
                splunk: false,
                users: false,
                router: step_id == "router",
                save_location: None,
            };
            match step_id {
                "all" => args.all = true,
                "mail" => args.mail = true,
                "splunk" => args.splunk = true,
                "users" => args.users = true,
                "ecomm" => args.ecomm = true,
                "router" => args.router = true,
                _ => {}
            }
            match crate::backups::run(&ctx, &args) {
                Ok(()) => {
                    let _ = progress_tx.send(format!("✓ {} complete", label));
                }
                Err(e) => {
                    let _ = progress_tx.send(format!("✗ Error: {}", e));
                }
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
    }

    /// Spawn a background thread to restore a selected service.
    fn start_restore(
        &mut self,
        service_id: &'static str,
        creds: Option<crate::service_restore::RestoreCredentials>,
    ) {
        if self.restore_running {
            return;
        }
        self.restore_running = true;
        self.restore_log.clear();
        self.restore_log_scroll = 0;

        let progress_tx = self.restore_progress_tx.clone();
        let label = RESTORE_SERVICES
            .iter()
            .find(|(id, _)| *id == service_id)
            .map(|(_, l)| *l)
            .unwrap_or(service_id);

        std::thread::spawn(move || {
            let _ = progress_tx.send(format!("Restoring: {}…", label));
            let report = crate::core::log_path("restore.log");
            let ctx = DefenderContext::new(report, false).with_progress(progress_tx.clone());
            let mut args = crate::service_restore::CliArgs {
                ssh: false,
                postfix: false,
                dovecot: false,
                roundcube: false,
                splunk: false,
                splunk_url: None,
                opencart: false,
                opencart_path: PathBuf::from("/var/www/html"),
                opencart_url: None,
                prestashop: false,
                prestashop_path: PathBuf::from("/var/www/html"),
                prestashop_url: None,
            };
            match service_id {
                "ssh" => args.ssh = true,
                "postfix" => args.postfix = true,
                "dovecot" => args.dovecot = true,
                "roundcube" => args.roundcube = true,
                "splunk" => args.splunk = true,
                "opencart" => args.opencart = true,
                "prestashop" => args.prestashop = true,
                _ => {}
            }
            match crate::service_restore::run(&ctx, &args, creds.as_ref()) {
                Ok(()) => {
                    let _ = progress_tx.send(format!("✓ {} restored", label));
                }
                Err(e) => {
                    let _ = progress_tx.send(format!("✗ Error: {}", e));
                }
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
    }

    /// Spawn a background thread to run the selected router operation.
    fn start_router(&mut self, step_id: &'static str, custom_args: Option<crate::router::CliArgs>) {
        if self.router_running {
            return;
        }
        if self.router_pending_confirm.is_some()
            && (step_id == "harden" || step_id == "console_lockdown")
        {
            self.router_log.push(
                "[WARN] Cannot start Phase 1 or Phase 2 while confirmation is pending.".to_string(),
            );
            return;
        }
        self.router_running = true;
        let label = match step_id {
            "confirm" => "Confirm Changes (confirm + save)",
            other => crate::router::ROUTER_STEPS
                .iter()
                .find(|s| s.id == other)
                .map(|s| s.label)
                .unwrap_or(other),
        };

        self.router_log = vec![format!("Starting: {}…", label)];
        self.router_log_scroll = 0;

        let progress_tx = self.router_progress_tx.clone();
        let args = custom_args.unwrap_or_else(|| crate::router::CliArgs {
            audit: step_id == "audit",
            diff: if step_id == "diff" { Some(None) } else { None },
            harden: step_id == "harden",
            restore_nat: matches!(step_id, "router_nat" | "restore_nat"),
            rotate_passwords: step_id == "rotate_passwords",
            sanitize_hooks: step_id == "sanitize_hooks",
            sanitize_cron: step_id == "sanitize_cron",
            clean_rootkits: step_id == "clean_rootkits",
            purge_containers: step_id == "purge_containers",
            console_lockdown: step_id == "console_lockdown",
            confirm: step_id == "confirm",
            team: self.team,
            ..Default::default()
        });

        self.router_active_step = Some(step_id);
        self.router_active_args = Some(args.clone());

        let finding_tx = self.finding_tx.clone();
        let box_type = self.box_type;
        std::thread::spawn(move || {
            let report = PathBuf::from("/tmp/defender-router.log");
            let mut ctx = DefenderContext::new(report, false)
                .with_progress(progress_tx.clone())
                .with_box_type(box_type);
            ctx.finding_tx = Some(finding_tx);

            if step_id == "services" || step_id == "user_permissions" {
                let hardening_args = crate::system_hardening::CliArgs {
                    user_permissions: step_id == "user_permissions",
                    services: step_id == "services",
                    programs: false,
                    configs: false,
                    install_tools: false,
                };
                if let Err(e) = crate::system_hardening::run(&ctx, &hardening_args) {
                    let _ = progress_tx.send(format!("ERROR: {}", e));
                    let _ = progress_tx.send(crate::router::ROUTER_PROGRESS_DONE_ERROR.to_string());
                } else {
                    let _ = progress_tx.send(crate::router::ROUTER_PROGRESS_DONE_OK.to_string());
                }
            } else {
                if let Err(e) = crate::router::run(&ctx, &args) {
                    let _ = progress_tx.send(format!("ERROR: {}", e));
                    let _ = progress_tx.send(crate::router::ROUTER_PROGRESS_DONE_ERROR.to_string());
                } else {
                    let _ = progress_tx.send(crate::router::ROUTER_PROGRESS_DONE_OK.to_string());
                }
            }
        });
    }

    /// Handle completion of a background router operation.
    fn handle_router_completion(&mut self, success: bool) {
        let step_id = self.router_active_step.take();
        let args = self.router_active_args.take();

        if let Some(id) = step_id {
            if crate::router::should_enter_pending_state(
                id,
                args.as_ref().is_some_and(|a| a.no_confirm),
                success,
            ) {
                let timeout_mins = args
                    .as_ref()
                    .and_then(|a| a.commit_timeout)
                    .unwrap_or(crate::router::DEFAULT_COMMIT_TIMEOUT_MINUTES);
                let duration = Duration::from_secs(u64::from(timeout_mins) * 60);
                let deadline = Instant::now() + duration;
                self.router_pending_confirm = Some(RouterPendingConfirm {
                    deadline,
                    modal_open: true,
                });
            } else if id == "confirm" && success {
                self.router_pending_confirm = None;
                self.router_log
                    .push("✓ VyOS configuration confirmed and saved permanently.".to_string());
                // When confirm fails, keep the pending state so the operator can retry.
                // The error line is already recorded in router_log.
            }

            if success && matches!(
                id,
                "harden"
                    | "router_nat"
                    | "restore_nat"
                    | "confirm"
                    | "sanitize_hooks"
                    | "sanitize_cron"
                    | "rotate_passwords"
                    | "clean_rootkits"
                    | "services"
            ) {
                // Clear stale findings so fresh post-remediation audit findings populate
                self.findings.retain(|f| match id {
                    "sanitize_hooks" => f.module != "router_boot_hooks" && f.module != "router_commit_hooks",
                    "sanitize_cron" => f.module != "router_task_scheduler",
                    "rotate_passwords" => f.module != "router_users",
                    "clean_rootkits" => f.module != "router_dyn_linker",
                    "services" => f.module != "router_services_whitelist",
                    _ => f.module != "router_nat" && f.module != "router_interfaces",
                });

                let finding_tx = self.finding_tx.clone();
                let box_type = self.box_type;
                let step_id_owned = id.to_string();
                std::thread::spawn(move || {
                    let report = crate::core::log_path("router_remediation_refresh.log");
                    let mut ctx = DefenderContext::new(report, false)
                        .with_box_type(box_type)
                        .with_silent_progress();
                    ctx.finding_tx = Some(finding_tx);
                    match step_id_owned.as_str() {
                        "sanitize_hooks" => {
                            crate::router::scan::run_module("router_boot_hooks", &ctx);
                            crate::router::scan::run_module("router_commit_hooks", &ctx);
                        }
                        "sanitize_cron" => {
                            crate::router::scan::run_module("router_task_scheduler", &ctx);
                        }
                        "rotate_passwords" => {
                            crate::router::scan::run_module("router_users", &ctx);
                        }
                        "clean_rootkits" => {
                            crate::router::scan::run_module("router_dyn_linker", &ctx);
                        }
                        "services" => {
                            crate::router::scan::run_module("router_services_whitelist", &ctx);
                        }
                        _ => {
                            crate::router::scan::run_module("router_nat", &ctx);
                            crate::router::scan::run_module("router_interfaces", &ctx);
                        }
                    }
                });
            }
        }
    }

    /// Export the current findings as a timestamped IR report.
    /// Returns the path written on success, or an error string.
    fn export_ir_report(&self) -> Result<String, String> {
        let now = Local::now();
        let ts = now.format("%Y%m%d_%H%M%S").to_string();

        let path = if nix::unistd::geteuid().is_root() {
            let dir = std::path::Path::new("/etc/linux-defender/reports");
            std::fs::create_dir_all(dir).map_err(|e| format!("mkdir failed: {}", e))?;
            dir.join(format!("ir-report-{}.txt", ts))
        } else {
            std::path::PathBuf::from(format!("ir-report-{}.txt", ts))
        };

        let active: Vec<&Finding> = self.findings.iter().filter(|f| !f.resolved).collect();
        let crit = active
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = active
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let med = active
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let info = active
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        let div = "═".repeat(70);
        let div2 = "─".repeat(70);

        let mut r = String::new();
        r.push_str(&format!("{div}\n"));
        r.push_str("  INCIDENT RESPONSE REPORT — CCDC 2026\n");
        r.push_str(&format!("{div}\n\n"));
        r.push_str(&format!(
            "  Date/Time : {}\n",
            now.format("%Y-%m-%d %H:%M:%S %Z")
        ));
        r.push_str(&format!("  Box Type  : {}\n", self.box_type.label()));
        r.push_str(&format!("  Box Desc  : {}\n", self.box_type.description()));
        r.push_str(&format!(
            "  Baseline  : {}\n\n",
            if self.baseline_present {
                "present"
            } else {
                "NOT TAKEN"
            }
        ));
        r.push_str(&format!("{div2}\n"));
        r.push_str("  EXECUTIVE SUMMARY\n");
        r.push_str(&format!("{div2}\n\n"));
        r.push_str(&format!(
            "  Total active findings : {}\n  Critical : {}  High : {}  Medium : {}  Info : {}\n\n",
            active.len(),
            crit,
            high,
            med,
            info
        ));

        for &(label, sev) in &[
            ("CRITICAL", Severity::Critical),
            ("HIGH", Severity::High),
            ("MEDIUM", Severity::Medium),
            ("INFO", Severity::Info),
        ] {
            let section: Vec<&&Finding> = active.iter().filter(|f| f.severity == sev).collect();
            if section.is_empty() {
                continue;
            }
            r.push_str(&format!(
                "{div2}\n  {label} ({} finding{})\n{div2}\n\n",
                section.len(),
                if section.len() == 1 { "" } else { "s" }
            ));
            for (i, f) in section.iter().enumerate() {
                r.push_str(&format!("  [{:02}] Module  : {}\n", i + 1, f.module));
                r.push_str(&format!("       Verdict : {}\n", f.verdict.label()));
                r.push_str(&format!("       Summary : {}\n", f.summary));
                if let Some(ref p) = f.path {
                    r.push_str(&format!("       Path    : {}\n", p.display()));
                }
                if !f.detail.is_empty() {
                    r.push_str(&format!("       Detail  : {}\n", f.detail));
                }
                for (key, val) in &f.context {
                    r.push_str(&format!("       {key:<8}: {val}\n"));
                }
                r.push('\n');
            }
        }

        r.push_str(&format!("{div}\n  END OF REPORT\n{div}\n"));

        let path_str = path.to_string_lossy().to_string();
        std::fs::write(&path, r).map_err(|e| format!("write failed: {}", e))?;
        Ok(path_str)
    }
}

pub fn run() -> anyhow::Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Only a panic on the UI thread ends the program. Worker-thread panics
        // are contained by `run_scan_module` and reported as findings; tearing
        // the terminal down (or printing) for them would wreck a live UI.
        if std::thread::current().name() != Some("main") {
            return;
        }
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let result = run_inner(&mut terminal);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

/// Scan modules that modify the system when they find something. They must
/// never be scheduled by the background auto-scan.
const REMEDIATING_MODULES: &[&str] = &[
    "ssh_keys",
    "cron",
    "at_jobs",
    "users",
    "webshells",
    "systemd",
    "ld_preload",
    "immutable",
    "startup_scripts",
    "rc_local",
    "pam",
    "mail_intercept",
    "cron_system",
    "systemd_timers",
    "shell_aliases",
    "xdg_autostart",
    "git_hooks",
];

/// Run one scan module on a worker thread, containing any panic.
///
/// Scan modules parse attacker-shaped input (logs, crontabs, unit files). If
/// one panics, the worker must still reach its "done" signal, otherwise the
/// scan stays marked as running forever and an auto-scan module never runs
/// again. The crash is surfaced as a finding instead.
fn run_scan_module(
    id: &'static str,
    is_anti_persistence: bool,
    ctx: &DefenderContext,
    box_type: BoxType,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if box_type == BoxType::Router {
            crate::router::scan::run_module(id, ctx);
        } else if is_anti_persistence {
            let _ = crate::anti_persistence::run_module(id, ctx);
        } else {
            let _ = crate::monitoring::run_module(id, ctx);
        }
    }));
    if outcome.is_err() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "scan",
            format!("Module {} crashed while scanning and was skipped", id),
            "The module panicked on its input. Its results for this run are incomplete; \
             treat that as suspicious and inspect the data it reads by hand.",
        ));
    }
}

/// Inner event loop — runs after the terminal is already in raw/alternate-screen mode.
fn run_inner(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    let detected = detect_box_type();
    let box_type = select_box_type(terminal, detected)?;

    let detected_team = detect_vyos_team_number();
    let team = if box_type == BoxType::Router {
        Some(prompt_team_number(terminal, detected_team)?)
    } else {
        detected_team
    };

    let source_paths = LogDash::source_paths(box_type);
    let source_refs: Vec<&str> = source_paths.iter().map(|s| s.as_str()).collect();
    let preserve_cfg = if nix::unistd::geteuid().is_root() {
        Some(preserve::setup(&source_refs))
    } else {
        None
    };

    let log_dashboard = LogDash::build(box_type, preserve_cfg.as_ref());

    let (finding_tx, finding_rx) = mpsc::channel::<Finding>();
    // nft_config starts empty — populated only after explicit operator action in Tools tab
    let mut app = App::new(box_type, log_dashboard, finding_tx, finding_rx, None, team);

    loop {
        app.tick();
        terminal.draw(|f| render(f, &mut app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // When the "add user" modal is open, route all keys to it.
            if app.user_input_active {
                match key.code {
                    KeyCode::Esc => {
                        app.user_input_active = false;
                        app.user_input_buf.clear();
                    }
                    KeyCode::Enter => {
                        let username = app.user_input_buf.trim().to_string();
                        if !username.is_empty() && !app.authorized_users.contains(&username) {
                            app.authorized_users.push(username);
                        }
                        app.user_input_active = false;
                        app.user_input_buf.clear();
                    }
                    KeyCode::Backspace => {
                        app.user_input_buf.pop();
                    }
                    KeyCode::Char(c) => {
                        app.user_input_buf.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            // When a wizard is open, route all keys to it; Esc always closes.
            if let Some(ref mut wizard) = app.active_wizard {
                match key.code {
                    KeyCode::Esc => {
                        app.active_wizard = None;
                    }
                    _ => {
                        if let crate::wizards::WizardAction::Close = wizard.handle_key(key.code) {
                            app.active_wizard = None;
                        }
                    }
                }
                continue;
            }

            // Credential input dialog for OpenCart / PrestaShop restores.
            if app.restore_cred_dialog.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        app.restore_cred_dialog = None;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        if let Some(ref mut dlg) = app.restore_cred_dialog {
                            let svc = dlg.service;
                            dlg.focused = dlg.focused.next(svc);
                        }
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        if let Some(ref mut dlg) = app.restore_cred_dialog {
                            dlg.focused = dlg.focused.prev();
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(ref dlg) = app.restore_cred_dialog {
                            let svc = dlg.service;
                            let max_field = dlg.field_count() - 1;
                            if dlg.focused as usize == max_field {
                                // Validate required fields before submitting.
                                let missing = match svc {
                                    // Splunk: admin pass(1)
                                    RestoreCredService::Splunk => {
                                        [1].iter().any(|&i| dlg.fields[i].trim().is_empty())
                                    }
                                    // OpenCart: DB user(1), DB pass(2), admin pass(7)
                                    RestoreCredService::OpenCart => {
                                        [1, 2, 7].iter().any(|&i| dlg.fields[i].trim().is_empty())
                                    }
                                    // PrestaShop: DB user(3), DB pass(4), admin pass(6)
                                    RestoreCredService::PrestaShop => {
                                        [3, 4, 6].iter().any(|&i| dlg.fields[i].trim().is_empty())
                                    }
                                };
                                if missing {
                                    // Required field empty: stay on the dialog. `return` here
                                    // would exit the whole TUI.
                                    continue;
                                }
                                // Last field confirmed — start restore.
                                let dialog = app.restore_cred_dialog.take().unwrap();
                                let service_id = match svc {
                                    RestoreCredService::Splunk => "splunk",
                                    RestoreCredService::OpenCart => "opencart",
                                    RestoreCredService::PrestaShop => "prestashop",
                                };
                                let creds = dialog.into_credentials();
                                app.start_restore(service_id, Some(creds));
                            } else {
                                // Advance to next field.
                                if let Some(ref mut dlg) = app.restore_cred_dialog {
                                    dlg.focused = dlg.focused.next(svc);
                                }
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(ref mut dlg) = app.restore_cred_dialog {
                            let idx = dlg.focused as usize;
                            dlg.fields[idx].pop();
                        }
                    }
                    KeyCode::Char(c) => {
                        if let Some(ref mut dlg) = app.restore_cred_dialog {
                            let idx = dlg.focused as usize;
                            dlg.fields[idx].push(c);
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(ref mut dlg) = app.router_config_dialog {
                match key.code {
                    KeyCode::Esc => {
                        app.router_config_dialog = None;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        dlg.focused = (dlg.focused + 1).min(dlg.field_count() - 1);
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        dlg.focused = dlg.focused.saturating_sub(1);
                    }
                    KeyCode::Enter => {
                        let max_field = dlg.field_count() - 1;
                        if dlg.focused == max_field {
                            let valid = match dlg.step {
                                RouterDialogStep::Harden => !dlg.fields[1].trim().is_empty(),
                                RouterDialogStep::ConsoleLockdown => {
                                    !dlg.fields[0].trim().is_empty()
                                }
                                RouterDialogStep::RestoreNat => !dlg.fields[0].trim().is_empty(),
                                RouterDialogStep::RotatePasswords => {
                                    !dlg.fields[0].trim().is_empty()
                                        && !dlg.fields[1].trim().is_empty()
                                }
                            };
                            if !valid {
                                // Required fields are empty; stay on dialog
                                continue;
                            }
                            let dialog = app.router_config_dialog.take().unwrap();
                            let (step_id, cli_args) = dialog.into_cli_args();
                            app.start_router(step_id, Some(cli_args));
                        } else {
                            dlg.focused += 1;
                        }
                    }
                    KeyCode::Backspace => {
                        let idx = dlg.focused;
                        dlg.fields[idx].pop();
                    }
                    KeyCode::Char(c) => {
                        let idx = dlg.focused;
                        dlg.fields[idx].push(c);
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(ref mut pending) = app.router_pending_confirm
                && pending.modal_open
            {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if !app.router_running {
                            pending.modal_open = false;
                            app.start_router(
                                "confirm",
                                Some(crate::router::CliArgs {
                                    confirm: true,
                                    ..Default::default()
                                }),
                            );
                        }
                    }
                    KeyCode::Esc => {
                        pending.modal_open = false;
                    }
                    _ => {}
                }
                continue;
            }

            // Palo Alto tab text field editing (when cursor is on fields 0..=2)
            if app.tab == Tab::PaloAlto
                && app.palo_focus == PaloFocus::Controls
                && app.palo_control_cursor < 3
                && !app.palo_show_finding_detail
            {
                match key.code {
                    KeyCode::Esc => {
                        app.palo_focus = PaloFocus::Findings;
                        continue;
                    }
                    KeyCode::Tab | KeyCode::Down => {
                        app.palo_control_cursor = (app.palo_control_cursor + 1) % 6;
                        continue;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        app.palo_control_cursor =
                            app.palo_control_cursor.checked_sub(1).unwrap_or(5);
                        continue;
                    }
                    KeyCode::Enter => {
                        if app.palo_control_cursor < 2 {
                            app.palo_control_cursor += 1;
                        } else {
                            app.palo_control_cursor = 3;
                        }
                        continue;
                    }
                    KeyCode::Backspace => {
                        match app.palo_control_cursor {
                            0 => {
                                app.palo_config_path.pop();
                            }
                            1 => {
                                app.palo_baseline_path.pop();
                            }
                            2 => {
                                app.palo_team.pop();
                            }
                            _ => {}
                        }
                        continue;
                    }
                    KeyCode::Char(c) => {
                        match app.palo_control_cursor {
                            0 => {
                                app.palo_config_path.push(c);
                            }
                            1 => {
                                app.palo_baseline_path.push(c);
                            }
                            2 => {
                                if c.is_ascii_digit() {
                                    app.palo_team.push(c);
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }
                    _ => {}
                }
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char(d @ '1'..='9') => {
                    if let Some(tab) = Tab::from_digit(d, app.box_type) {
                        app.tab = tab;
                    }
                }
                KeyCode::Esc => {
                    if app.show_finding_detail {
                        app.show_finding_detail = false;
                        app.action_feedback = None;
                    } else if app.palo_show_finding_detail {
                        app.palo_show_finding_detail = false;
                    }
                }
                KeyCode::Up => match app.tab {
                    Tab::Tools => {
                        use crate::tui::tools_view::SelectedTool;
                        let total = SelectedTool::total(app.box_type);
                        if total > 0 {
                            app.tools_cursor = app.tools_cursor.checked_sub(1).unwrap_or(total - 1);
                        }
                    }
                    Tab::Logs => {
                        if let Some(p) = app.log_dashboard.active_pane_mut() {
                            p.scroll_up();
                        }
                    }
                    Tab::Scan => match app.scan_focus {
                        ScanFocus::Modules => {
                            let len = app.box_type.scan_modules().len();
                            app.scan_cursor = app
                                .scan_cursor
                                .checked_sub(1)
                                .unwrap_or(len.saturating_sub(1));
                        }
                        ScanFocus::Findings => {
                            let n = app.display_findings().len();
                            if n > 0 {
                                app.findings_cursor =
                                    app.findings_cursor.checked_sub(1).unwrap_or(n - 1);
                            }
                        }
                    },
                    Tab::Hardening => {
                        app.hardening_cursor = app
                            .hardening_cursor
                            .checked_sub(1)
                            .unwrap_or(HARDENING_STEPS.len() - 1);
                    }
                    Tab::Monitor => {
                        if app.monitor_running {
                            // Scroll output log up (toward older lines)
                            app.monitor_log_scroll = app.monitor_log_scroll.saturating_add(1);
                        } else if !MONITOR_MODULES.is_empty() {
                            app.monitor_cursor = app
                                .monitor_cursor
                                .checked_sub(1)
                                .unwrap_or(MONITOR_MODULES.len() - 1);
                        }
                    }
                    Tab::Backups => {
                        let steps = app.box_type.backup_steps();
                        if !steps.is_empty() {
                            app.backups_cursor =
                                app.backups_cursor.checked_sub(1).unwrap_or(steps.len() - 1);
                        }
                    }
                    Tab::ServiceRestore => {
                        app.restore_cursor = app
                            .restore_cursor
                            .checked_sub(1)
                            .unwrap_or(RESTORE_SERVICES.len() - 1);
                    }
                    Tab::Router => match app.router_focus {
                        RouterFocus::Operations => {
                            app.router_cursor = app
                                .router_cursor
                                .checked_sub(1)
                                .unwrap_or(crate::router::ROUTER_STEPS.len() - 1);
                        }
                        RouterFocus::Log => {
                            let max = app.router_log.len().saturating_sub(1);
                            app.router_log_scroll = (app.router_log_scroll + 1).min(max);
                        }
                    },
                    Tab::PaloAlto => match app.palo_focus {
                        PaloFocus::Findings => {
                            let n = app.palo_findings.len();
                            if n > 0 {
                                app.palo_findings_cursor =
                                    app.palo_findings_cursor.checked_sub(1).unwrap_or(n - 1);
                            }
                        }
                        PaloFocus::Controls => {
                            app.palo_control_cursor =
                                app.palo_control_cursor.checked_sub(1).unwrap_or(5);
                        }
                    },
                    _ => {}
                },
                KeyCode::Down => match app.tab {
                    Tab::Tools => {
                        use crate::tui::tools_view::SelectedTool;
                        let total = SelectedTool::total(app.box_type);
                        if total > 0 {
                            app.tools_cursor = (app.tools_cursor + 1) % total;
                        }
                    }
                    Tab::Logs => {
                        if let Some(p) = app.log_dashboard.active_pane_mut() {
                            p.scroll_down();
                        }
                    }
                    Tab::Scan => match app.scan_focus {
                        ScanFocus::Modules => {
                            let len = app.box_type.scan_modules().len();
                            if len > 0 {
                                app.scan_cursor = (app.scan_cursor + 1) % len;
                            }
                        }
                        ScanFocus::Findings => {
                            let n = app.display_findings().len();
                            if n > 0 {
                                app.findings_cursor = (app.findings_cursor + 1) % n;
                            }
                        }
                    },
                    Tab::Hardening => {
                        app.hardening_cursor = (app.hardening_cursor + 1) % HARDENING_STEPS.len();
                    }
                    Tab::Monitor => {
                        if app.monitor_running {
                            // Scroll output log down (toward newer lines); 0 = bottom
                            app.monitor_log_scroll = app.monitor_log_scroll.saturating_sub(1);
                        } else if !MONITOR_MODULES.is_empty() {
                            app.monitor_cursor = (app.monitor_cursor + 1) % MONITOR_MODULES.len();
                        }
                    }
                    Tab::Backups => {
                        let steps = app.box_type.backup_steps();
                        if !steps.is_empty() {
                            app.backups_cursor = (app.backups_cursor + 1) % steps.len();
                        }
                    }
                    Tab::ServiceRestore => {
                        app.restore_cursor = (app.restore_cursor + 1) % RESTORE_SERVICES.len();
                    }
                    Tab::Router => match app.router_focus {
                        RouterFocus::Operations => {
                            app.router_cursor =
                                (app.router_cursor + 1) % crate::router::ROUTER_STEPS.len();
                        }
                        RouterFocus::Log => {
                            app.router_log_scroll = app.router_log_scroll.saturating_sub(1);
                        }
                    },
                    Tab::PaloAlto => match app.palo_focus {
                        PaloFocus::Findings => {
                            let n = app.palo_findings.len();
                            if n > 0 {
                                app.palo_findings_cursor = (app.palo_findings_cursor + 1) % n;
                            }
                        }
                        PaloFocus::Controls => {
                            app.palo_control_cursor = (app.palo_control_cursor + 1) % 6;
                        }
                    },
                    _ => {}
                },
                KeyCode::Enter => {
                    if app.tab == Tab::Scan
                        && app.scan_focus == ScanFocus::Findings
                        && !app.findings.is_empty()
                    {
                        app.show_finding_detail = !app.show_finding_detail;
                        app.action_feedback = None;
                    } else if app.tab == Tab::Hardening && !app.hardening_running {
                        let step_id = HARDENING_STEPS[app.hardening_cursor].0;
                        app.start_hardening(step_id);
                    } else if app.tab == Tab::Monitor && !app.monitor_running {
                        let module_id = MONITOR_MODULES[app.monitor_cursor].0;
                        app.start_monitor(module_id);
                    } else if app.tab == Tab::Backups && !app.backups_running {
                        let steps = app.box_type.backup_steps();
                        if let Some(&(step_id, _)) = steps.get(app.backups_cursor) {
                            app.start_backup(step_id);
                        }
                    } else if app.tab == Tab::ServiceRestore && !app.restore_running {
                        let service_id = RESTORE_SERVICES[app.restore_cursor].0;
                        match service_id {
                            "splunk" => {
                                app.restore_cred_dialog =
                                    Some(RestoreCredDialog::new(RestoreCredService::Splunk));
                            }
                            "opencart" => {
                                app.restore_cred_dialog =
                                    Some(RestoreCredDialog::new(RestoreCredService::OpenCart));
                            }
                            "prestashop" => {
                                app.restore_cred_dialog =
                                    Some(RestoreCredDialog::new(RestoreCredService::PrestaShop));
                            }
                            _ => app.start_restore(service_id, None),
                        }
                    } else if app.tab == Tab::Router && !app.router_running {
                        let step_id = crate::router::ROUTER_STEPS[app.router_cursor].id;
                        if app.router_pending_confirm.is_some()
                            && (step_id == "harden"
                                || step_id == "console_lockdown"
                                || step_id == "router_nat")
                        {
                            app.router_log.push(
                                "[WARN] Cannot start configuration while confirmation is pending. Press 'c' to confirm or wait for rollback."
                                    .to_string(),
                            );
                            continue;
                        }
                        match step_id {
                            "harden" => {
                                app.router_config_dialog = Some(RouterConfigDialog::new(
                                    RouterDialogStep::Harden,
                                    app.team,
                                ));
                            }
                            "console_lockdown" => {
                                app.router_config_dialog = Some(RouterConfigDialog::new(
                                    RouterDialogStep::ConsoleLockdown,
                                    app.team,
                                ));
                            }
                            "router_nat" => {
                                app.router_config_dialog = Some(RouterConfigDialog::new(
                                    RouterDialogStep::RestoreNat,
                                    app.team,
                                ));
                            }
                            "rotate_passwords" => {
                                app.router_config_dialog = Some(RouterConfigDialog::new(
                                    RouterDialogStep::RotatePasswords,
                                    app.team,
                                ));
                            }
                            "confirm" => {
                                app.start_router(
                                    "confirm",
                                    Some(crate::router::CliArgs {
                                        confirm: true,
                                        ..Default::default()
                                    }),
                                );
                            }
                            _ => {
                                app.start_router(step_id, None);
                            }
                        }
                    } else if app.tab == Tab::Tools {
                        use crate::tui::tools_view::SelectedTool;
                        if let SelectedTool::Wizard(idx) =
                            SelectedTool::from_cursor(app.tools_cursor)
                        {
                            let wizards = crate::tools::catalog::wizards_for_box_type(app.box_type);
                            if let Some(w_def) = wizards.get(idx) {
                                if w_def.name == "palo_alto_audit" && app.box_type == BoxType::General {
                                    app.tab = Tab::PaloAlto;
                                    app.palo_focus = PaloFocus::Controls;
                                    app.action_feedback = Some("Switched to Palo Alto Audit tab [8]".into());
                                    continue;
                                }
                            }
                            if let Some(w) =
                                crate::wizards::ActiveWizard::new(idx, app.box_type)
                            {
                                app.active_wizard = Some(w);
                            }
                        }
                    } else if app.tab == Tab::PaloAlto {
                        if app.palo_show_finding_detail {
                            app.palo_show_finding_detail = false;
                        } else {
                            match app.palo_focus {
                                PaloFocus::Findings => {
                                    if !app.palo_findings.is_empty() {
                                        app.palo_show_finding_detail = true;
                                    }
                                }
                                PaloFocus::Controls => {
                                    match app.palo_control_cursor {
                                        0 | 1 => {
                                            app.palo_control_cursor += 1;
                                        }
                                        2 => {
                                            app.palo_control_cursor = 3;
                                        }
                                        3 => {
                                            app.run_palo_scan();
                                        }
                                        4 => {
                                            app.export_palo_remediation();
                                        }
                                        5 => {
                                            app.active_wizard = Some(
                                                crate::wizards::ActiveWizard::PaloAlto(
                                                    crate::wizards::palo_alto::PaloAltoWizard::new(),
                                                ),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                KeyCode::Char('x') => {
                    if app.tab == Tab::Scan && app.show_finding_detail {
                        let cursor = app.findings_cursor;
                        // Resolve cursor against display_findings (log findings excluded)
                        if let Some(action) = app
                            .display_findings()
                            .get(cursor)
                            .and_then(|f| f.actions.first())
                            .cloned()
                        {
                            match execute_action(&action) {
                                Ok(msg) => {
                                    app.action_feedback = Some(format!("Done: {}", msg));
                                    // Find and mark the same finding resolved in the full list
                                    if let Some(f) = app
                                        .findings
                                        .iter_mut()
                                        .filter(|f| f.module != "log")
                                        .nth(cursor)
                                    {
                                        f.resolved = true;
                                    }
                                }
                                Err(e) => {
                                    app.action_feedback = Some(format!("Failed: {}", e));
                                }
                            }
                        }
                    }
                }
                KeyCode::Char(' ') => {
                    if app.tab == Tab::Scan
                        && !app.scan_running
                        && app.scan_focus == ScanFocus::Modules
                    {
                        let i = app.scan_cursor;
                        app.scan_selected[i] = !app.scan_selected[i];
                    }
                }
                KeyCode::Char('s') => {
                    if app.tab == Tab::Scan && app.scan_focus == ScanFocus::Modules {
                        app.start_scan();
                    } else if app.tab == Tab::PaloAlto {
                        app.run_palo_scan();
                    }
                }
                KeyCode::Char('S') => {
                    if app.tab == Tab::Scan
                        && !app.scan_running
                        && app.scan_focus == ScanFocus::Modules
                    {
                        app.scan_selected.fill(true);
                        app.start_scan();
                    }
                }
                KeyCode::Char('a') => {
                    if app.tab == Tab::Scan
                        && !app.scan_running
                        && app.scan_focus == ScanFocus::Modules
                    {
                        let all_on = app.scan_selected.iter().all(|&b| b);
                        app.scan_selected.fill(!all_on);
                    }
                }
                KeyCode::Char('w') => {
                    if app.tab == Tab::Scan {
                        app.auto_scan_enabled = !app.auto_scan_enabled;
                        if app.auto_scan_enabled {
                            // Clear last-run times so all due modules start immediately.
                            app.auto_scan_last_run.clear();
                        }
                    } else if app.tab == Tab::Dashboard {
                        app.watchdog_enabled = !app.watchdog_enabled;
                        if app.watchdog_enabled {
                            // Reset restart counts when watchdog is freshly enabled.
                            app.watchdog_restart_count.clear();
                        }
                    } else if app.tab == Tab::PaloAlto {
                        app.active_wizard = Some(
                            crate::wizards::ActiveWizard::PaloAlto(
                                crate::wizards::palo_alto::PaloAltoWizard::new(),
                            ),
                        );
                    }
                }
                KeyCode::Char('u') => {
                    if app.tab == Tab::Dashboard {
                        app.user_input_active = true;
                        app.user_input_buf.clear();
                    }
                }
                KeyCode::Char('b') => {
                    if app.tab == Tab::Dashboard {
                        // Jump straight to Backups and queue an --all run
                        app.tab = Tab::Backups;
                        app.start_backup("all");
                    }
                }
                KeyCode::Char('c') => {
                    if app.tab == Tab::Router
                        && let Some(ref mut pending) = app.router_pending_confirm
                    {
                        pending.modal_open = true;
                    }
                }
                KeyCode::Char('e') => {
                    if app.tab == Tab::Scan && app.scan_focus == ScanFocus::Findings {
                        match app.export_ir_report() {
                            Ok(path) => app.action_feedback = Some(format!("Exported: {}", path)),
                            Err(e) => app.action_feedback = Some(format!("Export failed: {}", e)),
                        }
                    } else if app.tab == Tab::PaloAlto {
                        app.export_palo_remediation();
                    }
                }
                KeyCode::Char('d') => {
                    if app.tab == Tab::Tools {
                        use crate::tui::tools_view::SelectedTool;
                        if let SelectedTool::Binary(_) = SelectedTool::from_cursor(app.tools_cursor)
                        {
                            use crate::tools::catalog::NFTBUILD;
                            app.download_status = Some("nftbuild: downloading…".into());
                            let tool = NFTBUILD.clone();
                            let (dl_tx, dl_rx) = mpsc::channel::<String>();
                            app.download_result_rx = dl_rx;
                            std::thread::spawn(move || {
                                let msg = match crate::tools::downloader::download(&tool) {
                                    Ok(result) => {
                                        format!("nftbuild: downloaded to {}", result.path.display())
                                    }
                                    Err(e) => format!("nftbuild: download failed — {}", e),
                                };
                                let _ = dl_tx.send(msg);
                            });
                        }
                    }
                }
                KeyCode::Char('r') => {
                    if app.tab == Tab::Tools {
                        use crate::tui::tools_view::SelectedTool;
                        match SelectedTool::from_cursor(app.tools_cursor) {
                            SelectedTool::Binary(_) => {
                                // nftbuild applies rules immediately and can cut
                                // scored services off: require a second press.
                                let confirmed = app
                                    .nftbuild_confirm_at
                                    .is_some_and(|t| t.elapsed() <= NFTBUILD_CONFIRM_WINDOW);
                                if !confirmed {
                                    app.nftbuild_confirm_at = Some(Instant::now());
                                    app.action_feedback = Some(format!(
                                        "nftbuild APPLIES {} firewall rules NOW and may drop scored \
                                         services. Press r again within {}s to confirm.",
                                        app.box_type.label(),
                                        NFTBUILD_CONFIRM_WINDOW.as_secs()
                                    ));
                                    continue;
                                }
                                app.nftbuild_confirm_at = None;
                                // Run nftbuild in background — avoids blocking the TUI event loop
                                let box_type = app.box_type;
                                let opts = crate::tools::nftbuild::RunOptions::default();
                                let (nft_tx, nft_rx) = mpsc::channel::<Result<String, String>>();
                                app.nftbuild_result_rx = nft_rx;
                                app.action_feedback = Some("nftbuild: running…".into());
                                std::thread::spawn(move || {
                                    let result = match crate::tools::nftbuild::run(box_type, &opts)
                                    {
                                        Ok(r) => Ok(r.config),
                                        Err(e) => Err(e.to_string()),
                                    };
                                    let _ = nft_tx.send(result);
                                });
                            }
                            SelectedTool::Wizard(idx) => {
                                let wizards = crate::tools::catalog::wizards_for_box_type(app.box_type);
                                if let Some(w_def) = wizards.get(idx) {
                                    if w_def.name == "palo_alto_audit" && app.box_type == BoxType::General {
                                        app.tab = Tab::PaloAlto;
                                        app.palo_focus = PaloFocus::Controls;
                                        app.action_feedback = Some("Switched to Palo Alto Audit tab [8]".into());
                                        continue;
                                    }
                                }
                                if let Some(w) =
                                    crate::wizards::ActiveWizard::new(idx, app.box_type)
                                {
                                    app.active_wizard = Some(w);
                                }
                            }
                        }
                    }
                }
                KeyCode::PageUp | KeyCode::Char('[') => match app.tab {
                    Tab::Hardening => {
                        let max = app.hardening_log.len().saturating_sub(1);
                        app.hardening_log_scroll = (app.hardening_log_scroll + 5).min(max);
                    }
                    Tab::Backups => {
                        let max = app.backups_log.len().saturating_sub(1);
                        app.backups_log_scroll = (app.backups_log_scroll + 5).min(max);
                    }
                    Tab::ServiceRestore => {
                        let max = app.restore_log.len().saturating_sub(1);
                        app.restore_log_scroll = (app.restore_log_scroll + 5).min(max);
                    }
                    Tab::Router => {
                        let max = app.router_log.len().saturating_sub(1);
                        app.router_log_scroll = (app.router_log_scroll + 5).min(max);
                    }
                    Tab::Tools => {
                        app.tools_nft_scroll = app.tools_nft_scroll.saturating_sub(5);
                    }
                    _ => {}
                },
                KeyCode::PageDown | KeyCode::Char(']') => match app.tab {
                    Tab::Hardening => {
                        app.hardening_log_scroll = app.hardening_log_scroll.saturating_sub(5);
                    }
                    Tab::Backups => {
                        app.backups_log_scroll = app.backups_log_scroll.saturating_sub(5);
                    }
                    Tab::ServiceRestore => {
                        app.restore_log_scroll = app.restore_log_scroll.saturating_sub(5);
                    }
                    Tab::Router => {
                        app.router_log_scroll = app.router_log_scroll.saturating_sub(5);
                    }
                    Tab::Tools => {
                        app.tools_nft_scroll = app.tools_nft_scroll.saturating_add(5);
                    }
                    _ => {}
                },
                KeyCode::Home => {
                    if app.tab == Tab::Router {
                        app.router_log_scroll = app.router_log.len().saturating_sub(1);
                    }
                }
                KeyCode::End => {
                    if app.tab == Tab::Logs
                        && let Some(p) = app.log_dashboard.active_pane_mut()
                    {
                        p.scroll_to_bottom();
                    } else if app.tab == Tab::Router {
                        app.router_log_scroll = 0;
                    }
                }
                KeyCode::Tab => {
                    if app.tab == Tab::Logs {
                        app.log_dashboard.next_pane();
                    } else if app.tab == Tab::Scan {
                        app.scan_focus = match app.scan_focus {
                            ScanFocus::Modules => ScanFocus::Findings,
                            ScanFocus::Findings => ScanFocus::Modules,
                        };
                    } else if app.tab == Tab::Router {
                        app.router_focus = match app.router_focus {
                            RouterFocus::Operations => RouterFocus::Log,
                            RouterFocus::Log => RouterFocus::Operations,
                        };
                    } else if app.tab == Tab::PaloAlto {
                        app.palo_focus = match app.palo_focus {
                            PaloFocus::Findings => PaloFocus::Controls,
                            PaloFocus::Controls => PaloFocus::Findings,
                        };
                    }
                }
                KeyCode::BackTab => {
                    if app.tab == Tab::Logs {
                        app.log_dashboard.prev_pane();
                    } else if app.tab == Tab::PaloAlto {
                        app.palo_focus = match app.palo_focus {
                            PaloFocus::Findings => PaloFocus::Controls,
                            PaloFocus::Controls => PaloFocus::Findings,
                        };
                    }
                }
                KeyCode::Char('p') if app.tab == Tab::Logs => {
                    if let Some(p) = app.log_dashboard.active_pane_mut() {
                        p.paused = !p.paused;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Top-level render function: draws the tab bar, active tab content, and status bar.
fn render(f: &mut ratatui::Frame, app: &mut App) {
    let size = f.area();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(size);

    let sessions_flagged = app.sessions.iter().any(|s| s.flagged);
    render_tabbar(
        f,
        rows[0],
        app.tab,
        &app.findings,
        sessions_flagged,
        app.tabs(),
    );

    match app.tab {
        Tab::Dashboard => {
            render_dashboard(
                f,
                rows[1],
                app.box_type,
                &app.services,
                &app.findings,
                app.nft_config.as_deref(),
                &app.sessions,
                &app.auth_events,
                &app.authorized_users,
            );
        }
        Tab::Logs => {
            render_logs(f, rows[1], app);
        }
        Tab::Scan => {
            render_scan(f, rows[1], app);
        }
        Tab::Hardening => {
            render_hardening(f, rows[1], app);
        }
        Tab::Monitor => {
            render_monitor(f, rows[1], app);
        }
        Tab::Tools => {
            use crate::tui::tools_view::SelectedTool;
            let selected = SelectedTool::from_cursor(app.tools_cursor);
            crate::tui::tools_view::render(
                f,
                rows[1],
                selected,
                app.download_status.as_deref(),
                app.nft_config.as_deref(),
                app.tools_nft_scroll,
                app.box_type,
            );
        }
        Tab::Backups => {
            render_backups(f, rows[1], app);
        }
        Tab::ServiceRestore => {
            render_service_restore(f, rows[1], app);
        }
        Tab::Router => {
            render_router(f, rows[1], app);
        }
        Tab::PaloAlto => {
            crate::tui::palo_view::render(f, rows[1], app);
        }
    }

    // Wizard overlay renders on top of the full terminal area.
    if let Some(ref wizard) = app.active_wizard {
        wizard.render(f, size);
    }

    // Credential dialog renders on top of the service restore tab.
    if let Some(ref dlg) = app.restore_cred_dialog {
        render_restore_cred_dialog(f, size, dlg);
    }

    // Router configuration dialog renders on top of the router tab.
    if let Some(ref dlg) = app.router_config_dialog {
        render_router_config_dialog(f, size, dlg);
    }

    // Router pending confirmation modal renders on top of the router tab.
    if let Some(ref pending) = app.router_pending_confirm
        && pending.modal_open
    {
        render_router_confirm_modal(f, size, pending);
    }

    // User input modal renders on top of everything.
    if app.user_input_active {
        render_user_input_modal(f, size, &app.user_input_buf);
    }

    // Palo Alto finding detail overlay
    if app.tab == Tab::PaloAlto && app.palo_show_finding_detail {
        if let Some(finding) = app.palo_findings.get(app.palo_findings_cursor) {
            render_finding_detail(f, rows[1], finding, app.action_feedback.as_deref());
        }
    }

    render_statusbar(f, rows[2], app);
}

/// Render the one-line tab bar at the top of the terminal.
fn render_tabbar(
    f: &mut ratatui::Frame,
    area: Rect,
    active: Tab,
    findings: &[Finding],
    sessions_flagged: bool,
    tabs: &[Tab],
) {
    let crit_count = findings
        .iter()
        .filter(|f| !f.resolved && f.severity == Severity::Critical)
        .count();

    let spans: Vec<Span> = tabs
        .iter()
        .enumerate()
        .flat_map(|(i, &tab)| {
            let base_label = format!(" [{}] {} ", i + 1, tab.label());
            let base_style = if tab == active {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let mut parts: Vec<Span> = vec![Span::styled(base_label, base_style)];

            if tab == Tab::Dashboard && sessions_flagged {
                parts.push(Span::styled(
                    "⚠",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            } else if tab == Tab::Scan && crit_count > 0 {
                parts.push(Span::styled(
                    format!("✖{}", crit_count),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }

            parts.push(Span::raw(" "));
            parts
        })
        .collect();

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::Black)),
        area,
    );
}

/// Render the one-line status bar at the bottom of the terminal.
fn render_statusbar(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let bg = Color::DarkGray;
    let key_color = Color::Cyan;
    let sep_color = Color::Gray;
    let alert_color = Color::Red;
    let ok_color = Color::Green;
    let warn_color = Color::Yellow;

    /// Build `[key] desc` span pair in the key/description style.
    fn kb(key: &'static str, desc: &'static str, kc: Color) -> Vec<Span<'static>> {
        vec![
            Span::styled(
                format!("[{key}]"),
                Style::default().fg(kc).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {desc}  ")),
        ]
    }

    // ── LEFT: status indicators ──────────────────────────────────────────────
    let down = app.services.iter().filter(|h| !h.is_up()).count();

    let mut left: Vec<Span> = Vec::new();

    // box type
    left.push(Span::raw(" "));
    left.push(Span::styled(
        app.box_type.label(),
        Style::default().fg(key_color).add_modifier(Modifier::BOLD),
    ));
    left.push(Span::styled("  │  ", Style::default().fg(sep_color)));

    // findings count
    let findings_color = if app.findings.is_empty() {
        ok_color
    } else {
        warn_color
    };
    left.push(Span::styled(
        format!("{} findings", app.findings.len()),
        Style::default().fg(findings_color),
    ));

    // services down
    if down > 0 {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled(
            format!("⚠ {down} DOWN"),
            Style::default()
                .fg(alert_color)
                .add_modifier(Modifier::BOLD),
        ));
    }

    // scan / auto-scan status
    if app.scan_running {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled(
            format!("scanning: {}", app.scan_progress),
            Style::default().fg(warn_color),
        ));
    } else if app.auto_scan_enabled {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        let n = app.auto_scan_running.len();
        let label = if n > 0 {
            format!("AUTO ↻{n}")
        } else {
            "AUTO".to_string()
        };
        left.push(Span::styled(label, Style::default().fg(ok_color)));
    }

    // watchdog
    if app.watchdog_enabled {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled("WATCHDOG", Style::default().fg(ok_color)));
    }

    // baseline missing
    if !app.baseline_present {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled(
            "⚠ NO BASELINE",
            Style::default().fg(warn_color).add_modifier(Modifier::BOLD),
        ));
    }

    // paused log pane
    let paused = app.tab == Tab::Logs
        && app
            .log_dashboard
            .panes
            .get(app.log_dashboard.active)
            .is_some_and(|p| p.paused);
    if paused {
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled(
            "PAUSED",
            Style::default().fg(warn_color).add_modifier(Modifier::BOLD),
        ));
    }

    // router pending confirmation indicator
    if let Some(ref pending) = app.router_pending_confirm {
        let remaining = pending
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let countdown = crate::router::format_countdown(remaining);
        left.push(Span::styled("  │  ", Style::default().fg(sep_color)));
        left.push(Span::styled(
            format!("⚠ PENDING CONFIRM ({})", countdown),
            Style::default().fg(warn_color).add_modifier(Modifier::BOLD),
        ));
    }

    // ── RIGHT: context keybinds ──────────────────────────────────────────────
    let mut right: Vec<Span> = Vec::new();

    // global quit + tab switch always shown
    right.extend(kb("q", "quit", key_color));
    let tab_hint: Option<&'static str> = match app.tabs().len() {
        0 => None,
        1 => Some("1"),
        2 => Some("1-2"),
        3 => Some("1-3"),
        4 => Some("1-4"),
        5 => Some("1-5"),
        6 => Some("1-6"),
        7 => Some("1-7"),
        8 => Some("1-8"),
        9 => Some("1-9"),
        _ => Some("1-9"),
    };
    if let Some(hint) = tab_hint {
        right.extend(kb(hint, "tabs", key_color));
    }

    // tab-specific binds
    match app.tab {
        Tab::Dashboard => {
            if !app.baseline_present {
                right.extend(kb("b", "take baseline", Color::Yellow));
            }
            right.extend(kb("w", "watchdog", key_color));
            right.extend(kb("u", "users", key_color));
        }
        Tab::Logs => {
            right.extend(kb("Tab", "pane", key_color));
            right.extend(kb("p", "pause", key_color));
            right.extend(kb("↑↓", "scroll", key_color));
        }
        Tab::Scan if app.show_finding_detail => {
            right.extend(kb("x", "execute", key_color));
            right.extend(kb("Esc", "back", key_color));
        }
        Tab::Scan => match app.scan_focus {
            ScanFocus::Modules => {
                right.extend(kb("Tab", "→ findings", key_color));
                right.extend(kb("↑↓", "move", key_color));
                right.extend(kb("Space", "toggle", key_color));
                right.extend(kb("s", "scan", key_color));
                right.extend(kb("S", "scan all", key_color));
                right.extend(kb("w", "auto", key_color));
            }
            ScanFocus::Findings => {
                right.extend(kb("Tab", "→ modules", key_color));
                right.extend(kb("↑↓", "move", key_color));
                right.extend(kb("Enter", "detail", key_color));
                right.extend(kb("e", "export", key_color));
            }
        },
        Tab::Hardening => {
            if app.hardening_running {
                right.push(Span::styled("running…", Style::default().fg(warn_color)));
            } else {
                right.extend(kb("↑↓", "select", key_color));
                right.extend(kb("Enter", "run step", key_color));
            }
        }
        Tab::Monitor => {
            if app.monitor_running {
                right.push(Span::styled("running…", Style::default().fg(warn_color)));
            } else {
                right.extend(kb("↑↓", "select", key_color));
                right.extend(kb("Enter", "run module", key_color));
            }
        }
        Tab::Tools => {
            right.extend(kb("↑↓", "navigate", key_color));
            right.extend(kb("d", "download", key_color));
            right.extend(kb("r", "run", key_color));
        }
        Tab::Backups => {
            if app.backups_running {
                right.push(Span::styled("running…", Style::default().fg(warn_color)));
            } else {
                right.extend(kb("↑↓", "select", key_color));
                right.extend(kb("Enter", "run backup", key_color));
            }
        }
        Tab::ServiceRestore => {
            if app.restore_running {
                right.push(Span::styled("restoring…", Style::default().fg(warn_color)));
            } else {
                right.extend(kb("↑↓", "select", key_color));
                right.extend(kb("Enter", "restore", key_color));
            }
        }
        Tab::Router => match app.router_focus {
            RouterFocus::Operations => {
                if app.router_running {
                    right.push(Span::styled("running…", Style::default().fg(warn_color)));
                } else {
                    right.extend(kb("Tab", "→ log", key_color));
                    right.extend(kb("↑↓", "select", key_color));
                    right.extend(kb("Enter", "run", key_color));
                }
                if app.router_pending_confirm.is_some() {
                    right.extend(kb("c", "confirm dialog", Color::Yellow));
                }
            }
            RouterFocus::Log => {
                right.extend(kb("Tab", "→ ops", key_color));
                right.extend(kb("↑↓", "scroll", key_color));
                right.extend(kb("End", "bottom", key_color));
                if app.router_pending_confirm.is_some() {
                    right.extend(kb("c", "confirm dialog", Color::Yellow));
                }
            }
        },
        Tab::PaloAlto if app.palo_show_finding_detail => {
            right.extend(kb("Esc", "close", key_color));
        }
        Tab::PaloAlto => match app.palo_focus {
            PaloFocus::Findings => {
                right.extend(kb("Tab", "→ config", key_color));
                right.extend(kb("↑↓", "select", key_color));
                right.extend(kb("Enter", "detail", key_color));
                right.extend(kb("s", "scan", key_color));
                right.extend(kb("e", "export", key_color));
                right.extend(kb("w", "wizard", key_color));
            }
            PaloFocus::Controls => {
                right.extend(kb("Tab", "→ findings", key_color));
                right.extend(kb("↑↓", "field", key_color));
                right.extend(kb("Enter", "action/next", key_color));
                right.extend(kb("s", "scan", key_color));
                right.extend(kb("e", "export", key_color));
            }
        },
    }

    // ── Layout: left flush, right flush ──────────────────────────────────────
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let base = Style::default().bg(bg).fg(Color::White);
    f.render_widget(Paragraph::new(Line::from(left)).style(base), cols[0]);
    f.render_widget(
        Paragraph::new(Line::from(right))
            .style(base)
            .alignment(ratatui::layout::Alignment::Right),
        cols[1],
    );
}

/// Render the Scan tab: module checklist on the left, findings list on the right.
fn render_scan(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: module checklist
    let modules_focused = app.scan_focus == ScanFocus::Modules && !app.show_finding_detail;
    let title = if app.scan_running {
        format!(" Scan — {} ", app.scan_progress)
    } else if app.auto_scan_enabled {
        " Scan Modules [AUTO ●30s ◑5m] ".to_string()
    } else {
        " Scan Modules ".to_string()
    };

    let items: Vec<ListItem> = app
        .box_type
        .scan_modules()
        .iter()
        .enumerate()
        .map(|(i, (id, label, _, interval))| {
            let checked = app.scan_selected[i];
            let is_cursor = modules_focused && i == app.scan_cursor;
            let checkbox = if checked { "[✓]" } else { "[ ]" };
            let interval_tag = if app.auto_scan_enabled {
                match interval {
                    ScanInterval::Continuous => " ●",
                    ScanInterval::Frequent => " ◑",
                    ScanInterval::OnDemand => "",
                }
            } else {
                ""
            };
            let running_tag = if app.auto_scan_running.contains(id) {
                " ↻"
            } else {
                ""
            };
            let line_style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if app.auto_scan_running.contains(id) {
                Style::default().fg(Color::Cyan)
            } else if checked {
                Style::default()
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(Span::styled(
                format!("{} {}{}{}", checkbox, label, interval_tag, running_tag),
                line_style,
            )))
        })
        .collect();

    let modules_border = if modules_focused {
        Style::default().fg(Color::Yellow)
    } else if app.scan_running {
        Style::default().fg(Color::LightYellow)
    } else {
        Style::default().fg(Color::Blue)
    };

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(modules_border),
        ),
        cols[0],
    );

    // Right: findings list (log-module diagnostic findings are suppressed)
    let findings_focused = app.scan_focus == ScanFocus::Findings && !app.show_finding_detail;
    let display_findings = app.display_findings();
    let findings_title = format!(" Findings ({}) ", display_findings.len());
    let findings_border = if findings_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    let findings_block = Block::default()
        .title(findings_title)
        .borders(Borders::ALL)
        .border_style(findings_border);

    if display_findings.is_empty() {
        let msg = if app.scan_running {
            "Scanning…"
        } else {
            "No findings — [Tab] to module list, [s] to start scan"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(findings_block)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let inner = findings_block.inner(cols[1]);
        f.render_widget(findings_block, cols[1]);

        let visible = inner.height as usize;
        // scroll so the cursor stays in view
        let start = if app.findings_cursor >= visible {
            app.findings_cursor + 1 - visible
        } else {
            0
        };

        let finding_items: Vec<ListItem> = display_findings
            .into_iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, finding)| {
                let is_cursor = findings_focused && i == app.findings_cursor;
                let resolved_mark = if finding.resolved { "✓ " } else { "" };
                let base_style = if is_cursor {
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let module_prefix =
                    format!("{:<10}", crate::core::truncate_chars(finding.module, 10));
                let line = Line::from(vec![
                    Span::styled(
                        format!("[{}]", finding.severity.label()),
                        base_style
                            .fg(finding.severity.color())
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" ", base_style),
                    Span::styled(module_prefix, base_style.fg(Color::DarkGray)),
                    Span::styled(" ", base_style),
                    Span::styled(
                        format!("{:<7}", finding.verdict.label()),
                        base_style.fg(finding.verdict.color()),
                    ),
                    Span::styled(format!(" {}{}", resolved_mark, finding.summary), base_style),
                ]);
                ListItem::new(line)
            })
            .collect();

        f.render_widget(List::new(finding_items), inner);
    }

    // Detail overlay — drawn on top of the full scan area
    if app.show_finding_detail
        && let Some(finding) = app.display_findings().get(app.findings_cursor).copied()
    {
        render_finding_detail(f, area, finding, app.action_feedback.as_deref());
    }
}

/// Render a centred floating overlay with full details for the selected finding.
fn render_finding_detail(
    f: &mut ratatui::Frame,
    area: Rect,
    finding: &Finding,
    feedback: Option<&str>,
) {
    // Floating panel: 90% of the scan area, centred.
    let w = (area.width * 9 / 10).max(40);
    let h = (area.height * 9 / 10).max(10);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup = Rect::new(x, y, w, h);

    f.render_widget(Clear, popup);

    let title = format!(
        " [{}] {} — {} ",
        finding.severity.label(),
        finding.verdict.label(),
        finding.module
    );
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(finding.verdict.color())
                .add_modifier(Modifier::BOLD),
        );
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    // Build the content lines
    let mut lines: Vec<Line> = Vec::new();

    // Summary
    lines.push(Line::from(Span::styled(
        finding.summary.clone(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    // Timestamp
    {
        let label_width = 16usize;
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<width$}", "found", width = label_width),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                finding.timestamp.format("%H:%M:%S").to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    lines.push(Line::from(""));

    // Path (if present) -- shown before detail so operators can copy it quickly
    if let Some(path) = &finding.path {
        let label_width = 16usize;
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<width$}", "path", width = label_width),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(path.display().to_string(), Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(""));
    }

    // Detail (extended narrative written by the detecting module)
    if !finding.detail.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Detail ───────────────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )));
        let wrap_width = inner.width.saturating_sub(4) as usize;
        for chunk in wrap_text(&finding.detail, wrap_width) {
            lines.push(Line::from(format!("  {}", chunk)));
        }
        lines.push(Line::from(""));
    }

    // Context rows
    if !finding.context.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Context ──────────────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )));
        for (label, value) in &finding.context {
            let label_width = 16usize;
            let val_lines: Vec<&str> = value.split('\n').collect();
            if let Some((first, rest)) = val_lines.split_first() {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<width$}", label, width = label_width),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(*first),
                ]));
                let indent = " ".repeat(label_width + 2);
                for r in rest {
                    lines.push(Line::from(vec![
                        Span::raw(indent.clone()),
                        Span::raw(*r),
                    ]));
                }
            }
        }
        lines.push(Line::from(""));
    }

    // Recommendation
    if !finding.recommendation.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Recommendation ───────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )));
        // word-wrap to panel width
        let wrap_width = inner.width.saturating_sub(4) as usize;
        for chunk in wrap_text(&finding.recommendation, wrap_width) {
            lines.push(Line::from(format!("  {}", chunk)));
        }
        lines.push(Line::from(""));
    }

    // Actions
    if !finding.actions.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Actions ──────────────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )));
        for action in &finding.actions {
            lines.push(Line::from(vec![
                Span::styled(
                    "  [x] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(action.description()),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Feedback from last execution
    if let Some(fb) = feedback {
        let color = if fb.starts_with("Done") {
            Color::Green
        } else {
            Color::Red
        };
        lines.push(Line::from(Span::styled(
            fb.to_string(),
            Style::default().fg(color),
        )));
        lines.push(Line::from(""));
    }

    // Footer
    let resolved_str = if finding.resolved {
        "✓ Resolved"
    } else {
        "○ Not resolved"
    };
    lines.push(Line::from(vec![
        Span::styled(
            resolved_str,
            Style::default().fg(if finding.resolved {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw("    "),
        Span::styled("[Esc] back", Style::default().fg(Color::DarkGray)),
        if !finding.actions.is_empty() {
            Span::styled("  [x] execute", Style::default().fg(Color::Yellow))
        } else {
            Span::raw("")
        },
    ]));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// Very simple word-wrapper: splits on spaces, respects `width`.
fn wrap_text(s: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![s.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Render the Logs tab: tiled panes each showing a live-tailed log file.
fn render_logs(f: &mut ratatui::Frame, area: Rect, app: &mut App) {
    let pane_count = app.log_dashboard.panes.len();
    if pane_count == 0 {
        let p = Paragraph::new("No log sources found for this box type.")
            .block(Block::default().borders(Borders::ALL).title(" Logs "));
        f.render_widget(p, area);
        return;
    }

    let cols_per_row = if app.box_type == BoxType::Router || area.width <= 140 {
        1
    } else if area.width > 180 {
        3
    } else {
        2
    };

    let rows_needed = pane_count.div_ceil(cols_per_row);
    let row_height = (area.height / rows_needed as u16).max(1);

    let row_constraints: Vec<Constraint> = (0..rows_needed)
        .map(|_| Constraint::Length(row_height))
        .collect();

    let row_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(area);

    let col_constraints: Vec<Constraint> = (0..cols_per_row)
        .map(|_| Constraint::Ratio(1, cols_per_row as u32))
        .collect();

    let active_idx = app.log_dashboard.active;

    for (row_idx, row_area) in row_areas.iter().enumerate() {
        let col_areas = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints.clone())
            .split(*row_area);

        for col_idx in 0..cols_per_row {
            let pane_idx = row_idx * cols_per_row + col_idx;
            if pane_idx >= pane_count {
                break;
            }
            let pane = &app.log_dashboard.panes[pane_idx];
            let cell = col_areas[col_idx];

            let is_active = pane_idx == active_idx;
            let border_style = if is_active {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Blue)
            };

            let status = pane.active_path.as_deref().unwrap_or("(not found)");
            let paused_tag = if pane.paused { " [PAUSED]" } else { "" };
            let title = format!(" {} — {}{} ", pane.title, status, paused_tag);

            let block = Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style);

            let inner = block.inner(cell);
            f.render_widget(block, cell);

            let visible_height = inner.height as usize;
            let total = pane.lines.len();
            let start = if total > visible_height {
                let auto_bottom = total.saturating_sub(visible_height);
                if pane.scroll == 0 || pane.scroll >= auto_bottom {
                    auto_bottom
                } else {
                    pane.scroll
                }
            } else {
                0
            };

            let lines: Vec<Line> = pane
                .lines
                .iter()
                .skip(start)
                .take(visible_height)
                .map(|ll| Line::from(Span::styled(ll.text.clone(), ll.style)))
                .collect();

            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
    }
}

/// Render the Hardening tab: step list on the left, output log on the right.
fn render_hardening(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left pane: step list
    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(cols[0]);

    let root_notice = Paragraph::new(Line::from(vec![Span::styled(
        "[!] Steps 1-2 require root",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(root_notice, left_rows[0]);

    let items: Vec<ListItem> = HARDENING_STEPS
        .iter()
        .enumerate()
        .map(|(i, (_, label))| {
            let is_cursor = i == app.hardening_cursor;
            let needs_root = i < 2;
            let prefix = if is_cursor { "▶ " } else { "  " };
            let root_tag = if needs_root { " [root]" } else { "" };
            let running_tag = if app.hardening_running && is_cursor {
                " ↻"
            } else {
                ""
            };
            let style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(
                format!("{}{}{}{}", prefix, label, root_tag, running_tag),
                style,
            )))
        })
        .collect();

    let list_title = if app.hardening_running {
        " Hardening Steps — running… "
    } else {
        " Hardening Steps "
    };
    let list_border = if app.hardening_running {
        Style::default().fg(Color::LightYellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(list_border),
        ),
        left_rows[1],
    );

    // Right pane: output log
    let log_block = Block::default()
        .title(" Output ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    let inner = log_block.inner(cols[1]);
    f.render_widget(log_block, cols[1]);

    if app.hardening_log.is_empty() {
        f.render_widget(
            Paragraph::new("Select a step and press [Enter] to run.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
    } else {
        let visible = inner.height as usize;
        let total = app.hardening_log.len();
        let start = total.saturating_sub(visible + app.hardening_log_scroll);
        let lines: Vec<Line> = app
            .hardening_log
            .iter()
            .skip(start)
            .take(visible)
            .map(|s| {
                let style = if s.starts_with("[CRIT") || s.starts_with("[HIGH") {
                    Style::default().fg(Color::Red)
                } else if s.starts_with("[MED") {
                    Style::default().fg(Color::Yellow)
                } else if s.starts_with("ERROR") {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if s.starts_with("Done") {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(s.clone(), style))
            })
            .collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// Render the Monitor tab: module list on the left, output log on the right.
fn render_monitor(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: module list
    let list_title = if app.monitor_running {
        " Monitor — running… "
    } else {
        " Monitor Modules "
    };
    let list_border = if app.monitor_running {
        Style::default().fg(Color::LightYellow)
    } else {
        Style::default().fg(Color::Blue)
    };

    let items: Vec<ListItem> = MONITOR_MODULES
        .iter()
        .enumerate()
        .map(|(i, (_id, label))| {
            let is_cursor = i == app.monitor_cursor;
            let style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if is_cursor { "▶ " } else { "  " };
            ListItem::new(Line::from(Span::styled(
                format!("{}{}", prefix, label),
                style,
            )))
        })
        .collect();

    // Scroll to keep cursor in view
    let left_inner = Block::default()
        .title(list_title)
        .borders(Borders::ALL)
        .border_style(list_border)
        .inner(cols[0]);

    let visible_left = left_inner.height as usize;
    let left_start = if app.monitor_cursor >= visible_left {
        app.monitor_cursor + 1 - visible_left
    } else {
        0
    };

    let visible_items: Vec<ListItem> = items.into_iter().skip(left_start).collect();

    f.render_widget(
        List::new(visible_items).block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(list_border),
        ),
        cols[0],
    );

    // Right: output log
    let log_border = Style::default().fg(Color::Blue);
    let log_block = Block::default()
        .title(" Output ")
        .borders(Borders::ALL)
        .border_style(log_border);

    if app.monitor_log.is_empty() {
        let msg = if app.monitor_running {
            "Running…"
        } else {
            "Select a module and press [Enter] to run it"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(log_block)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let inner = log_block.inner(cols[1]);
        f.render_widget(log_block, cols[1]);

        let visible = inner.height as usize;
        let total = app.monitor_log.len();
        let start = if app.monitor_log_scroll > 0 {
            total
                .saturating_sub(visible)
                .saturating_sub(app.monitor_log_scroll)
        } else {
            total.saturating_sub(visible)
        };

        let lines: Vec<Line> = app
            .monitor_log
            .iter()
            .skip(start)
            .take(visible)
            .map(|l| {
                let lower = l.to_lowercase();
                let style = if l.starts_with("[CRIT") || l.starts_with("[HIGH") {
                    Style::default().fg(Color::Red)
                } else if l.starts_with("[MED") {
                    Style::default().fg(Color::Yellow)
                } else if lower.contains("error") || lower.contains("fail") {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if lower.contains("warn") {
                    Style::default().fg(Color::Yellow)
                } else if l.starts_with("[✓]")
                    || lower.contains("done")
                    || lower.contains("complete")
                    || lower.contains("success")
                {
                    Style::default().fg(Color::Green)
                } else if l.starts_with("[+]") {
                    Style::default().fg(Color::Cyan)
                } else if l.starts_with("[!]") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(l.clone(), style))
            })
            .collect();

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// Render the Backups tab: backup options on the left, output log on the right.
fn render_backups(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: backup step list
    let list_title = if app.backups_running {
        " Backups — running… "
    } else {
        " Backup Operations "
    };
    let list_border = if app.backups_running {
        Style::default().fg(Color::LightYellow)
    } else {
        Style::default().fg(Color::Blue)
    };

    let items: Vec<ListItem> = app
        .box_type
        .backup_steps()
        .iter()
        .enumerate()
        .map(|(i, (_id, label))| {
            let is_cursor = i == app.backups_cursor;
            let running_tag = if app.backups_running && is_cursor {
                " ↻"
            } else {
                ""
            };
            let style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if is_cursor { "▶ " } else { "  " };
            ListItem::new(Line::from(Span::styled(
                format!("{}{}{}", prefix, label, running_tag),
                style,
            )))
        })
        .collect();

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(list_border),
        ),
        cols[0],
    );

    // Right: output log
    let log_block = Block::default()
        .title(" Output ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    if app.backups_log.is_empty() {
        let msg = if app.backups_running {
            "Running…"
        } else {
            "Select a backup operation and press [Enter] to run"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(log_block)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let inner = log_block.inner(cols[1]);
        f.render_widget(log_block, cols[1]);

        let visible = inner.height as usize;
        let total = app.backups_log.len();
        let start = total.saturating_sub(visible + app.backups_log_scroll);

        let lines: Vec<Line> = app
            .backups_log
            .iter()
            .skip(start)
            .take(visible)
            .map(|s| {
                let style = if s.starts_with('✓') {
                    Style::default().fg(Color::Green)
                } else if s.starts_with('✗') || s.starts_with("Error") {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(s.clone(), style))
            })
            .collect();

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// Render the Service Restore tab: service list on the left, output log on the right.
fn render_service_restore(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: service list
    let list_title = if app.restore_running {
        " Service Restore — running… "
    } else {
        " Service Restore "
    };
    let list_border = if app.restore_running {
        Style::default().fg(Color::LightYellow)
    } else {
        Style::default().fg(Color::Blue)
    };

    let items: Vec<ListItem> = RESTORE_SERVICES
        .iter()
        .enumerate()
        .map(|(i, (_id, label))| {
            let is_cursor = i == app.restore_cursor;
            let running_tag = if app.restore_running && is_cursor {
                " ↻"
            } else {
                ""
            };
            let style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if is_cursor { "▶ " } else { "  " };
            ListItem::new(Line::from(Span::styled(
                format!("{}{}{}", prefix, label, running_tag),
                style,
            )))
        })
        .collect();

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(list_border),
        ),
        cols[0],
    );

    // Right: output log
    let log_block = Block::default()
        .title(" Output ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    if app.restore_log.is_empty() {
        let msg = if app.restore_running {
            "Restoring…"
        } else {
            "Select a service and press [Enter] to restore it"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(log_block)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let inner = log_block.inner(cols[1]);
        f.render_widget(log_block, cols[1]);

        let visible = inner.height as usize;
        let total = app.restore_log.len();
        let start = total.saturating_sub(visible + app.restore_log_scroll);

        let lines: Vec<Line> = app
            .restore_log
            .iter()
            .skip(start)
            .take(visible)
            .map(|s| {
                let style = if s.starts_with('✓') {
                    Style::default().fg(Color::Green)
                } else if s.starts_with('✗') || s.starts_with("Error") {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(s.clone(), style))
            })
            .collect();

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// Render the "Add Authorized User" text-input modal overlay.
fn render_user_input_modal(f: &mut ratatui::Frame, area: Rect, buf: &str) {
    let w = 44u16.min(area.width.saturating_sub(4));
    let h = 5u16;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup = Rect::new(x, y, w, h);

    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Add Authorized User ")
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let lines = vec![
        Line::from(Span::styled(
            "Username:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("> {}_", buf),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "[Enter] confirm  [Esc] cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// Run an interactive selection loop to pick the competition box type.
fn select_box_type(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    detected: BoxType,
) -> anyhow::Result<BoxType> {
    let options = BoxType::ALL;
    let mut selected = options.iter().position(|&b| b == detected).unwrap_or(3);

    loop {
        terminal.draw(|f| draw_box_select(f, options, selected, detected))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Up => {
                    selected = selected.checked_sub(1).unwrap_or(options.len() - 1);
                }
                KeyCode::Down => {
                    selected = (selected + 1) % options.len();
                }
                KeyCode::Enter => return Ok(options[selected]),
                KeyCode::Char('q') => {
                    return Err(anyhow::anyhow!("Quit before selecting box type"));
                }
                _ => {}
            }
        }
    }
}

/// Interactive modal dialog prompting for CCDC team number [0-20] at startup.
fn prompt_team_number(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    detected_team: Option<u8>,
) -> anyhow::Result<u8> {
    let default_val = detected_team.unwrap_or(0).to_string();
    let mut input = default_val;
    let mut error_msg: Option<String> = None;

    loop {
        terminal.draw(|f| {
            let area = f.area();
            let inner = crate::wizards::modal_popup(f, area, 50, 25, " CCDC Team Number Setup ");
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(3),
                    Constraint::Length(2),
                    Constraint::Length(1),
                ])
                .split(inner);

            f.render_widget(
                Paragraph::new("Enter Team Number [0-20] (0 = Practice, 1-20 = Competition):")
                    .style(Style::default().fg(Color::Cyan)),
                rows[0],
            );

            let border_style = if error_msg.is_some() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Yellow)
            };
            f.render_widget(
                Paragraph::new(input.as_str()).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style),
                ),
                rows[1],
            );

            if let Some(ref err) = error_msg {
                f.render_widget(
                    Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
                    rows[2],
                );
            }

            f.render_widget(
                Paragraph::new("[Enter] Confirm   [Backspace] Edit")
                    .style(Style::default().fg(Color::DarkGray)),
                rows[3],
            );
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Enter => {
                        if let Ok(t) = input.trim().parse::<u8>()
                            && t <= 20
                        {
                            return Ok(t);
                        } else {
                            error_msg = Some("Invalid team! Must be 0 to 20.".into());
                        }
                    }
                    KeyCode::Backspace => {
                        input.pop();
                        error_msg = None;
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        if input.len() < 3 {
                            input.push(c);
                            error_msg = None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Draw the box-type selection overlay on `f`.
fn draw_box_select(
    f: &mut ratatui::Frame,
    options: &[BoxType],
    selected: usize,
    detected: BoxType,
) {
    let size = f.area();

    f.render_widget(
        Paragraph::new("").style(Style::default().bg(Color::Black)),
        size,
    );

    let dialog_width = 64u16.min(size.width.saturating_sub(4));
    let dialog_height = (options.len() as u16 + 6).min(size.height.saturating_sub(4));
    let x = (size.width.saturating_sub(dialog_width)) / 2;
    let y = (size.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let block = Block::default()
        .title(" Select Box Type ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(dialog_area);
    f.render_widget(block, dialog_area);

    let inner_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    let detected_line = Line::from(vec![
        Span::styled("Detected: ", Style::default().fg(Color::DarkGray)),
        Span::styled(detected.label(), Style::default().fg(Color::Cyan)),
    ]);
    f.render_widget(Paragraph::new(detected_line), inner_rows[0]);

    let items: Vec<ListItem> = options
        .iter()
        .enumerate()
        .map(|(i, &bt)| {
            let is_sel = i == selected;
            let is_det = bt == detected;
            let prefix = if is_sel { "▶ " } else { "  " };
            let det_tag = if is_det { " (detected)" } else { "" };
            let label = format!(
                "{}{:<8}  {}{}",
                prefix,
                bt.label(),
                bt.description(),
                det_tag
            );
            let style = if is_sel {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    f.render_widget(List::new(items), inner_rows[2]);

    let help = Paragraph::new("[↑↓] select   [Enter] confirm   [q] quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, inner_rows[4]);
}

/// Render the credential input dialog for web-app restores.
fn render_restore_cred_dialog(f: &mut ratatui::Frame, area: Rect, dlg: &RestoreCredDialog) {
    use crate::wizards::modal_popup;

    let title = match dlg.service {
        RestoreCredService::Splunk => " Splunk Admin Credentials ",
        RestoreCredService::OpenCart => " OpenCart Credentials ",
        RestoreCredService::PrestaShop => " PrestaShop Credentials ",
    };
    let inner = modal_popup(f, area, 60, 80, title);

    let n = dlg.field_count();
    let mut constraints: Vec<Constraint> = (0..n).map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Min(0));
    constraints.push(Constraint::Length(2));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let focused_idx = dlg.focused as usize;
    for i in 0..n {
        let is_focused = i == focused_idx;
        let label = dlg.field_label(i);
        let value = &dlg.fields[i];
        // Mask password fields (indices with "Password" in the label).
        let display = if label.to_lowercase().contains("password") {
            "*".repeat(value.len())
        } else {
            value.clone()
        };
        let border_style = if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let text = if is_focused {
            format!("{}_", display)
        } else {
            display
        };
        f.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .title(format!(" {} ", label))
                    .borders(Borders::ALL)
                    .border_style(border_style),
            ),
            rows[i],
        );
    }

    let hint = if focused_idx == n - 1 {
        "[Tab/↓] prev field   [Enter] start restore   [Esc] cancel"
    } else {
        "[Tab/↓] next field   [↑] prev field   [Enter] advance   [Esc] cancel"
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        rows[n + 1],
    );
}

/// Render the configuration input dialog for router Phase 1 / Phase 2 operations.
fn render_router_config_dialog(f: &mut ratatui::Frame, area: Rect, dlg: &RouterConfigDialog) {
    use crate::wizards::modal_popup;

    let title = match dlg.step {
        RouterDialogStep::Harden => " Phase 1: Router Hardening Configuration ",
        RouterDialogStep::ConsoleLockdown => " Phase 2: Console Lockdown (Nuke SSH) ",
        RouterDialogStep::RestoreNat => " Restore NAT Baseline on Router ",
        RouterDialogStep::RotatePasswords => " Dual Password Rotation & SSH Key Sanitization ",
    };
    let inner = modal_popup(f, area, 65, 75, title);

    let n = dlg.field_count();
    let mut constraints: Vec<Constraint> = (0..n).map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Min(0));
    constraints.push(Constraint::Length(2));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for i in 0..n {
        let is_focused = i == dlg.focused;
        let label = dlg.field_label(i);
        let value = &dlg.fields[i];
        let display = if label.to_lowercase().contains("password") {
            "*".repeat(value.len())
        } else {
            value.clone()
        };
        let border_style = if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let text = if is_focused {
            format!("{}_", display)
        } else {
            display
        };
        f.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .title(format!(" {} ", label))
                    .borders(Borders::ALL)
                    .border_style(border_style),
            ),
            rows[i],
        );
    }

    let hint = if dlg.focused == n - 1 {
        "[Tab/↓] prev field   [Enter] apply & run   [Esc] cancel"
    } else {
        "[Tab/↓] next field   [↑] prev field   [Enter] advance   [Esc] cancel"
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        rows[n + 1],
    );
}

/// Render the commit-confirm pending modal dialog.
fn render_router_confirm_modal(f: &mut ratatui::Frame, area: Rect, pending: &RouterPendingConfirm) {
    use crate::wizards::modal_popup;

    let remaining_secs = pending
        .deadline
        .saturating_duration_since(Instant::now())
        .as_secs();
    let countdown = crate::router::format_countdown(remaining_secs);

    let title = format!(" VyOS Confirmation Required [Rollback in {}] ", countdown);
    let inner = modal_popup(f, area, 65, 55, &title);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Warning banner
            Constraint::Length(5), // Verification instructions
            Constraint::Length(3), // Countdown box
            Constraint::Min(1),    // Spacing
            Constraint::Length(2), // Action keys hint
        ])
        .split(inner);

    let warning_lines = vec![
        Line::from(vec![
            Span::styled(
                "⚠ WARNING: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Phase 1 changes are applied, but "),
            Span::styled(
                "NOT permanent!",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from("VyOS will automatically roll back to previous settings unless confirmed."),
    ];
    f.render_widget(Paragraph::new(warning_lines), chunks[0]);

    let instructions = vec![
        Line::from(Span::styled(
            "Verification steps:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  1. Open a separate terminal window now."),
        Line::from("  2. Verify you can SSH into the router with the NEW password:"),
        Line::from(Span::styled(
            "     ssh vyos@172.17.0.1",
            Style::default().fg(Color::Cyan),
        )),
        Line::from("  3. Only confirm if login succeeds and access is verified!"),
    ];
    f.render_widget(Paragraph::new(instructions), chunks[1]);

    let timer_color = if remaining_secs < 60 {
        Color::Red
    } else {
        Color::Yellow
    };
    let timer_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(timer_color))
        .title(" Rollback Timer ");
    let timer_text = vec![Line::from(vec![
        Span::raw(" Time Remaining: "),
        Span::styled(
            format!("{} (mm:ss)", countdown),
            Style::default()
                .fg(timer_color)
                .add_modifier(Modifier::BOLD),
        ),
    ])];
    f.render_widget(Paragraph::new(timer_text).block(timer_block), chunks[2]);

    let hint = Line::from(vec![
        Span::styled(
            "[y] ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("keep changes (confirm + save)   "),
        Span::styled(
            "[Esc] ",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("hide dialog"),
    ]);
    f.render_widget(Paragraph::new(hint), chunks[4]);
}

/// Render the Router tab: operations list on the left, output log on the right.
fn render_router(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let ratio = if area.width <= 130 {
        [Constraint::Percentage(32), Constraint::Percentage(68)]
    } else {
        [Constraint::Percentage(38), Constraint::Percentage(62)]
    };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(ratio)
        .split(area);

    let (list_title, list_border) = if app.router_running {
        (
            " VyOS Operations — running… ".to_string(),
            Style::default().fg(Color::Yellow),
        )
    } else if let Some(ref pending) = app.router_pending_confirm {
        let remaining = pending
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let countdown = crate::router::format_countdown(remaining);
        (
            format!(" VyOS Operations [⚠ PENDING: {} — press 'c'] ", countdown),
            Style::default().fg(Color::Yellow),
        )
    } else if app.router_focus == RouterFocus::Operations {
        (
            " VyOS Operations ".to_string(),
            Style::default().fg(Color::Yellow),
        )
    } else {
        (
            " VyOS Operations ".to_string(),
            Style::default().fg(Color::Cyan),
        )
    };

    let items: Vec<ListItem> = crate::router::ROUTER_STEPS
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let is_cursor = i == app.router_cursor;
            let running_tag = if app.router_running && is_cursor {
                " ↻"
            } else {
                ""
            };
            let blocked_tag = if app.router_pending_confirm.is_some()
                && (step.id == "harden" || step.id == "console_lockdown")
            {
                " [BLOCKED - pending confirmation]"
            } else {
                ""
            };
            let style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if is_cursor { "▶ " } else { "  " };
            ListItem::new(vec![
                Line::from(Span::styled(
                    format!("{}{}{}", prefix, step.label, running_tag),
                    style,
                )),
                Line::from(Span::styled(
                    format!("    {}{}", step.description, blocked_tag),
                    if blocked_tag.is_empty() {
                        Style::default().fg(Color::DarkGray)
                    } else {
                        Style::default().fg(Color::Yellow)
                    },
                )),
            ])
        })
        .collect();

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(list_title.as_str())
                .borders(Borders::ALL)
                .border_style(list_border),
        ),
        cols[0],
    );

    // Right: output log
    let log_title = if app.router_log_scroll > 0 {
        format!(
            " Output [Scrolled +{}] (↑↓: scroll, End: bottom) ",
            app.router_log_scroll
        )
    } else if app.router_focus == RouterFocus::Log {
        " Output [↑↓: scroll, End: bottom] ".to_string()
    } else {
        " Output ".to_string()
    };
    let log_border = if app.router_focus == RouterFocus::Log {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let log_block = Block::default()
        .title(log_title)
        .borders(Borders::ALL)
        .border_style(log_border);

    if app.router_log.is_empty() {
        let msg = if app.router_running {
            "Running…"
        } else {
            "Select a VyOS operation and press [Enter] to run"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(log_block)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false }),
            cols[1],
        );
    } else {
        let inner = log_block.inner(cols[1]);
        f.render_widget(log_block, cols[1]);

        let visible = inner.height as usize;
        let total = app.router_log.len();
        let start = total.saturating_sub(visible + app.router_log_scroll);

        let lines: Vec<Line> = app
            .router_log
            .iter()
            .skip(start)
            .take(visible)
            .map(|s| {
                let style = if s.starts_with('✓') || s.contains("[ OK ]") || s.contains("PROOF:") {
                    Style::default().fg(Color::Green)
                } else if s.starts_with('✗') || s.contains("[ERR ]") || s.contains("ERROR") {
                    Style::default().fg(Color::Red)
                } else if s.starts_with('→') || s.contains("[INFO]") || s.contains("[RESTORE]") {
                    Style::default().fg(Color::Cyan)
                } else if s.contains("[CMD]") {
                    Style::default().fg(Color::Magenta)
                } else if s.contains("[WARN]") || s.contains("[!]") {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(s.clone(), style))
            })
            .collect();

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BoxType;

    #[test]
    fn server_tabs_include_service_restore() {
        for bt in [
            BoxType::Web,
            BoxType::Mail,
            BoxType::Splunk,
        ] {
            let tabs = Tab::for_box_type(bt);
            assert_eq!(tabs.len(), 8, "Expected 8 tabs for {:?}", bt);
            assert_eq!(
                tabs,
                &[
                    Tab::Dashboard,
                    Tab::Logs,
                    Tab::Scan,
                    Tab::Hardening,
                    Tab::Backups,
                    Tab::Monitor,
                    Tab::Tools,
                    Tab::ServiceRestore,
                ]
            );
            assert!(!tabs.contains(&Tab::Router));
            assert!(!tabs.contains(&Tab::PaloAlto));
            assert_eq!(tabs[0], Tab::Dashboard);
            assert_eq!(tabs[1], Tab::Logs);
            assert_eq!(tabs[7], Tab::ServiceRestore);

            assert_eq!(Tab::from_digit('1', bt), Some(Tab::Dashboard));
            assert_eq!(Tab::from_digit('2', bt), Some(Tab::Logs));
            assert_eq!(Tab::from_digit('3', bt), Some(Tab::Scan));
            assert_eq!(Tab::from_digit('4', bt), Some(Tab::Hardening));
            assert_eq!(Tab::from_digit('5', bt), Some(Tab::Backups));
            assert_eq!(Tab::from_digit('6', bt), Some(Tab::Monitor));
            assert_eq!(Tab::from_digit('7', bt), Some(Tab::Tools));
            assert_eq!(Tab::from_digit('8', bt), Some(Tab::ServiceRestore));
            assert_eq!(Tab::from_digit('9', bt), None);
            assert_eq!(Tab::from_digit('0', bt), None);
        }
    }

    #[test]
    fn workstation_tabs_replace_service_restore_with_palo_alto() {
        let ws_tabs = Tab::for_box_type(BoxType::General);
        assert_eq!(ws_tabs.len(), 8, "Expected 8 tabs for General/Workstation");
        assert_eq!(
            ws_tabs,
            &[
                Tab::Dashboard,
                Tab::Logs,
                Tab::Scan,
                Tab::Hardening,
                Tab::Backups,
                Tab::Monitor,
                Tab::Tools,
                Tab::PaloAlto,
            ]
        );
        assert!(!ws_tabs.contains(&Tab::ServiceRestore));
        assert!(!ws_tabs.contains(&Tab::Router));
        assert_eq!(ws_tabs[0], Tab::Dashboard);
        assert_eq!(ws_tabs[1], Tab::Logs);
        assert_eq!(ws_tabs[7], Tab::PaloAlto);

        assert_eq!(Tab::from_digit('1', BoxType::General), Some(Tab::Dashboard));
        assert_eq!(Tab::from_digit('8', BoxType::General), Some(Tab::PaloAlto));
        assert_eq!(Tab::from_digit('9', BoxType::General), None);

        assert_eq!(Tab::digit_for(Tab::PaloAlto, BoxType::General), Some('8'));
        assert_eq!(Tab::digit_for(Tab::ServiceRestore, BoxType::General), None);
        assert_eq!(Tab::digit_for(Tab::PaloAlto, BoxType::Web), None);
        assert_eq!(Tab::digit_for(Tab::PaloAlto, BoxType::Router), None);
    }

    #[test]
    fn router_tabs_move_router_to_tab_4_and_hide_service_restore() {
        let tabs = Tab::for_box_type(BoxType::Router);
        assert_eq!(tabs.len(), 7, "Router should have 7 total accessible tabs");
        assert_eq!(
            tabs,
            &[
                Tab::Dashboard,
                Tab::Logs,
                Tab::Scan,
                Tab::Router,
                Tab::Backups,
                Tab::Monitor,
                Tab::Tools,
            ]
        );
        assert!(!tabs.contains(&Tab::ServiceRestore));
        assert!(!tabs.contains(&Tab::Hardening));
        assert_eq!(tabs[0], Tab::Dashboard);
        assert_eq!(tabs[1], Tab::Logs);
        assert_eq!(tabs[2], Tab::Scan);
        assert_eq!(tabs[3], Tab::Router);
        assert_eq!(tabs[6], Tab::Tools);

        assert_eq!(Tab::from_digit('1', BoxType::Router), Some(Tab::Dashboard));
        assert_eq!(Tab::from_digit('2', BoxType::Router), Some(Tab::Logs));
        assert_eq!(Tab::from_digit('3', BoxType::Router), Some(Tab::Scan));
        assert_eq!(Tab::from_digit('4', BoxType::Router), Some(Tab::Router));
        assert_eq!(Tab::from_digit('5', BoxType::Router), Some(Tab::Backups));
        assert_eq!(Tab::from_digit('6', BoxType::Router), Some(Tab::Monitor));
        assert_eq!(Tab::from_digit('7', BoxType::Router), Some(Tab::Tools));
        assert_eq!(Tab::from_digit('8', BoxType::Router), None);
        assert_eq!(Tab::from_digit('9', BoxType::Router), None);
        assert_eq!(Tab::from_digit('0', BoxType::Router), None);

        assert_eq!(Tab::digit_for(Tab::Dashboard, BoxType::Router), Some('1'));
        assert_eq!(Tab::digit_for(Tab::Logs, BoxType::Router), Some('2'));
        assert_eq!(Tab::digit_for(Tab::Scan, BoxType::Router), Some('3'));
        assert_eq!(Tab::digit_for(Tab::Router, BoxType::Router), Some('4'));
        assert_eq!(Tab::digit_for(Tab::Backups, BoxType::Router), Some('5'));
        assert_eq!(Tab::digit_for(Tab::Monitor, BoxType::Router), Some('6'));
        assert_eq!(Tab::digit_for(Tab::Tools, BoxType::Router), Some('7'));
        assert_eq!(Tab::digit_for(Tab::Hardening, BoxType::Router), None);
        assert_eq!(Tab::digit_for(Tab::ServiceRestore, BoxType::Router), None);

        assert_eq!(Tab::digit_for(Tab::Scan, BoxType::Web), Some('3'));
        assert_eq!(Tab::digit_for(Tab::Hardening, BoxType::Web), Some('4'));
    }

    #[test]
    fn general_box_tools_wizard_selection_identifies_palo_alto() {
        let wizards = crate::tools::catalog::wizards_for_box_type(BoxType::General);
        let pa_idx = wizards.iter().position(|w| w.name == "palo_alto_audit");
        assert!(pa_idx.is_some(), "Palo Alto wizard should exist for General");
        let idx = pa_idx.unwrap();
        assert_eq!(wizards[idx].name, "palo_alto_audit");
    }
}

#[cfg(test)]
mod auto_scan_tests {
    use super::*;

    #[test]
    fn remediating_modules_are_never_auto_scanned() {
        for (id, _, _, interval) in SCAN_MODULES {
            if REMEDIATING_MODULES.contains(id) {
                assert!(
                    matches!(interval, ScanInterval::OnDemand),
                    "{id} changes the system and must be on-demand only"
                );
            }
        }
    }
}
