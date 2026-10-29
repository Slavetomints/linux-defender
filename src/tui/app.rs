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
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};

use chrono::Local;

use crate::core::{BoxType, DefenderContext, Finding, Severity, detect_box_type, execute_action};
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

/// How often a module runs in auto-scan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanInterval {
    /// Re-runs every 30 seconds — ephemeral state an attacker can change in real time.
    Continuous,
    /// Re-runs every 5 minutes — filesystem changes that take time to appear.
    Frequent,
    /// Manual only — expensive filesystem walks or rarely-changing config.
    OnDemand,
}

/// Registry of monitoring modules available from the Monitor tab: (id, display label).
const MONITOR_MODULES: &[(&str, &str)] = &[
    ("access_log", "Access log analysis"),
    ("error_log", "Error log analysis"),
    ("auth_log_watch", "Auth log watch (1h)"),
    ("pspy", "Process spy"),
    ("network_watch", "Network snapshot"),
    ("auth_log", "Auth log brute-force analysis"),
    ("port_map", "Listening port map"),
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
    ("bind_mounts", "Bind/overlay mount detection"),
];

/// Backup operations: (id, display label).
const BACKUP_STEPS: &[(&str, &str)] = &[
    ("all", "Full Config Backup"),
    ("mail", "Mail Stack"),
    ("splunk", "Splunk Config"),
    ("users", "User/Group/Shadow DBs"),
    ("ecomm", "E-Commerce Stack"),
];

/// Service restore operations: (id, display label).
const RESTORE_SERVICES: &[(&str, &str)] = &[
    ("postfix", "Postfix (SMTP)"),
    ("dovecot", "Dovecot (IMAP/POP3)"),
    ("splunk", "Splunk"),
    ("opencart", "OpenCart"),
    ("prestashop", "PrestaShop"),
];

/// Registry of all scan modules: (id, display label, is_anti_persistence, auto-scan interval).
const SCAN_MODULES: &[(&str, &str, bool, ScanInterval)] = &[
    // ── Anti-persistence ─────────────────────────────────────────────────
    (
        "ssh_keys",
        "SSH authorized_keys",
        true,
        ScanInterval::Continuous,
    ),
    ("cron", "Cron jobs", true, ScanInterval::Continuous),
    ("at_jobs", "AT job queue", true, ScanInterval::OnDemand),
    ("users", "User accounts", true, ScanInterval::OnDemand),
    ("php_shells", "PHP web shells", true, ScanInterval::Frequent),
    ("suid", "SUID binaries", true, ScanInterval::OnDemand),
    (
        "capabilities",
        "Binary capabilities",
        true,
        ScanInterval::OnDemand,
    ),
    ("systemd", "Systemd services", true, ScanInterval::Frequent),
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
        ScanInterval::Frequent,
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
        ScanInterval::Frequent,
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
        ScanInterval::Continuous,
    ),
    (
        "systemd_timers",
        "Systemd timers",
        true,
        ScanInterval::Frequent,
    ),
    (
        "shell_aliases",
        "Shell alias backdoors",
        true,
        ScanInterval::Frequent,
    ),
    ("polkit", "polkit rules audit", true, ScanInterval::OnDemand),
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
        "port_map",
        "Listening port map",
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
        ScanInterval::Frequent,
    ),
    (
        "webserver_config",
        "Webserver config audit",
        false,
        ScanInterval::Frequent,
    ),
    (
        "bind_mounts",
        "Bind/overlay mount detection",
        false,
        ScanInterval::Continuous,
    ),
];

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
}

impl Tab {
    /// All tabs in display order — used to render the tab bar.
    const ALL: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Logs,
        Tab::Scan,
        Tab::Hardening,
        Tab::Backups,
        Tab::Monitor,
        Tab::Tools,
        Tab::ServiceRestore,
    ];

    /// Human-readable name shown in the tab bar.
    fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Logs => "Logs",
            Tab::Scan => "Scan",
            Tab::Hardening => "Hardening",
            Tab::Backups => "Backups",
            Tab::Monitor => "Monitor",
            Tab::Tools => "Tools",
            Tab::ServiceRestore => "Svc Restore",
        }
    }

    /// Map a `1`–`8` digit keypress to the corresponding tab, or `None` for anything else.
    fn from_digit(d: char) -> Option<Tab> {
        match d {
            '1' => Some(Tab::Dashboard),
            '2' => Some(Tab::Logs),
            '3' => Some(Tab::Scan),
            '4' => Some(Tab::Hardening),
            '5' => Some(Tab::Backups),
            '6' => Some(Tab::Monitor),
            '7' => Some(Tab::Tools),
            '8' => Some(Tab::ServiceRestore),
            _ => None,
        }
    }
}

/// Which service is waiting for credential input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreCredService {
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
        let max = if service == RestoreCredService::OpenCart {
            8
        } else {
            6
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

impl RestoreCredDialog {
    /// Build a new dialog pre-populated with sensible defaults for `service`.
    fn new(service: RestoreCredService) -> Self {
        // Fields are indexed 0..=8 and must match field_label() and into_credentials() exactly.
        let fields = match service {
            RestoreCredService::OpenCart => [
                "localhost".into(),         // 0  DB Hostname
                "root".into(),              // 1  DB Username
                String::new(),              // 2  DB Password
                "opencart".into(),          // 3  DB Name
                "3306".into(),              // 4  DB Port
                "http://localhost/".into(), // 5  HTTP base URL
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
            RestoreCredService::OpenCart => 9,
            RestoreCredService::PrestaShop => 7,
        }
    }

    /// Consume the dialog and return typed credentials ready for the restore thread.
    fn into_credentials(self) -> crate::service_restore::RestoreCredentials {
        let [f0, f1, f2, f3, f4, f5, f6, f7, f8] = self.fields;
        match self.service {
            RestoreCredService::OpenCart => crate::service_restore::RestoreCredentials {
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

pub struct App {
    pub box_type: BoxType,
    pub tab: Tab,
    pub findings: Vec<Finding>,
    /// Scored-service check histories (latency, uptime %, last result).
    pub services: Vec<ServiceHistory>,
    pub log_dashboard: LogDash,
    pub finding_tx: Sender<Finding>,
    pub finding_rx: Receiver<Finding>,
    pub last_service_check: Instant,
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
    /// Status message shown in the Tools tab during downloads.
    pub download_status: Option<String>,
    /// Flat cursor in the Tools tab (binaries first, then wizards).
    pub tools_cursor: usize,
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
}

impl App {
    /// Construct a new [`App`] with the given box type and channel endpoints.
    fn new(
        box_type: BoxType,
        log_dashboard: LogDash,
        finding_tx: Sender<Finding>,
        finding_rx: Receiver<Finding>,
        nft_config: Option<String>,
    ) -> Self {
        let services = build_histories(box_type.checks());
        let (scan_progress_tx, scan_progress_rx) = mpsc::channel();
        let (auto_scan_done_tx, auto_scan_done_rx) = mpsc::channel::<&'static str>();
        let (hardening_finding_tx, hardening_finding_rx) = mpsc::channel::<Finding>();
        let (hardening_progress_tx, hardening_progress_rx) = mpsc::channel::<String>();
        let (monitor_progress_tx, monitor_progress_rx) = mpsc::channel::<String>();
        let (backups_progress_tx, backups_progress_rx) = mpsc::channel::<String>();
        let (restore_progress_tx, restore_progress_rx) = mpsc::channel::<String>();
        let scan_selected = vec![true; SCAN_MODULES.len()];
        let authorized_users = vec!["root".to_string()];
        let sessions = poll_sessions(&authorized_users);
        Self {
            box_type,
            tab: Tab::Dashboard,
            findings: Vec::new(),
            services,
            log_dashboard,
            finding_tx,
            finding_rx,
            last_service_check: Instant::now(),
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
            download_status: None,
            tools_cursor: 0,
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
        }
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
        if !self.findings.is_empty() && self.findings_cursor >= self.findings.len() {
            self.findings_cursor = self.findings.len() - 1;
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
            self.hardening_log.push(format!(
                "[{}] {} — {}",
                f.severity.label().trim(),
                f.module,
                f.summary
            ));
        }
        // Drain hardening progress: empty string = done, non-empty = step label.
        while let Ok(p) = self.hardening_progress_rx.try_recv() {
            if p.is_empty() {
                self.hardening_running = false;
                self.hardening_log.push("Done.".to_string());
            } else {
                self.hardening_log.push(format!("Running: {}…", p));
            }
        }
        // Drain monitor progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.monitor_progress_rx.try_recv() {
            if p.is_empty() {
                self.monitor_running = false;
            } else {
                self.monitor_log.push(p);
            }
        }
        // Drain backups progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.backups_progress_rx.try_recv() {
            if p.is_empty() {
                self.backups_running = false;
                self.baseline_present = true;
            } else {
                self.backups_log.push(p);
            }
        }
        // Drain service restore progress: empty string = done, non-empty = log line.
        while let Ok(p) = self.restore_progress_rx.try_recv() {
            if p.is_empty() {
                self.restore_running = false;
            } else {
                self.restore_log.push(p);
            }
        }
        // Drain completed auto-scan threads.
        while let Ok(id) = self.auto_scan_done_rx.try_recv() {
            self.auto_scan_running.remove(id);
        }
        if self.auto_scan_enabled {
            self.tick_auto_scan();
        }
        if self.last_service_check.elapsed() >= Duration::from_secs(5) {
            poll_all(&mut self.services);
            self.sessions = poll_sessions(&self.authorized_users);
            self.auth_events = poll_auth_events();
            self.last_service_check = Instant::now();
            // Watchdog: automatically restart scored services that have gone down.
            if self.watchdog_enabled {
                let down: Vec<&'static str> = self
                    .services
                    .iter()
                    .filter_map(|h| if !h.is_up() { Some(h.check.name) } else { None })
                    .collect();
                for name in down {
                    let count = self.watchdog_restart_count.get(name).copied().unwrap_or(0);
                    if count < 3 {
                        *self.watchdog_restart_count.entry(name).or_insert(0) += 1;
                        let name_owned = name.to_string();
                        std::thread::spawn(move || {
                            let _ = std::process::Command::new("systemctl")
                                .args(["restart", &name_owned])
                                .output();
                        });
                        self.action_feedback = Some(format!("Watchdog: restarting {}…", name));
                    }
                }
            }
        }
    }

    /// Spawn background threads for any auto-scan module that is now due.
    fn tick_auto_scan(&mut self) {
        for (id, _, is_ap, interval) in SCAN_MODULES {
            let threshold = match interval {
                ScanInterval::Continuous => Duration::from_secs(30),
                ScanInterval::Frequent => Duration::from_secs(300),
                ScanInterval::OnDemand => continue,
            };
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
                let report = PathBuf::from("/tmp/defender-autoscan.log");
                let mut ctx = DefenderContext::new(report, false);
                ctx.finding_tx = Some(finding_tx);
                if is_ap {
                    let _ = crate::anti_persistence::run_module(id_str, &ctx);
                } else {
                    let _ = crate::monitoring::run_module(id_str, &ctx);
                }
                let _ = done_tx.send(id_str);
            });
        }
    }

    /// Spawn a background thread that runs every selected scan module in sequence.
    fn start_scan(&mut self) {
        if self.scan_running {
            return;
        }

        let selected: Vec<(&'static str, bool)> = SCAN_MODULES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.scan_selected[*i])
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

        std::thread::spawn(move || {
            let report = PathBuf::from("/tmp/defender-scan.log");
            let mut ctx = DefenderContext::new(report, false);
            ctx.finding_tx = Some(finding_tx);

            for (id, is_ap) in selected {
                let _ = progress_tx.send(id.to_string());
                if is_ap {
                    let _ = crate::anti_persistence::run_module(id, &ctx);
                } else {
                    let _ = crate::monitoring::run_module(id, &ctx);
                }
            }
            let _ = progress_tx.send(String::new()); // signal done
        });
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

        std::thread::spawn(move || {
            let report = PathBuf::from("/tmp/defender-hardening.log");
            let mut ctx = DefenderContext::new(report, false);
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
            let report = PathBuf::from("/tmp/defender-monitor.log");
            let mut ctx = DefenderContext::new(report, false);
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
        let label = BACKUP_STEPS
            .iter()
            .find(|(id, _)| *id == step_id)
            .map(|(_, l)| *l)
            .unwrap_or(step_id);

        std::thread::spawn(move || {
            let _ = progress_tx.send(format!("Starting: {}…", label));
            let report = PathBuf::from("/tmp/defender-backup.log");
            let ctx = DefenderContext::new(report, false);
            let mut args = crate::backups::CliArgs {
                all: false,
                compare_hashes: false,
                custom: None,
                ecomm: false,
                mail: false,
                restore: false,
                splunk: false,
                users: false,
                save_location: None,
            };
            match step_id {
                "all" => args.all = true,
                "mail" => args.mail = true,
                "splunk" => args.splunk = true,
                "users" => args.users = true,
                "ecomm" => args.ecomm = true,
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
            let report = PathBuf::from("/tmp/defender-restore.log");
            let ctx = DefenderContext::new(report, false).with_progress(progress_tx.clone());
            let mut args = crate::service_restore::CliArgs {
                postfix: false,
                dovecot: false,
                splunk: false,
                opencart: false,
                opencart_path: PathBuf::from("/var/www/html"),
                opencart_url: None,
                prestashop: false,
                prestashop_path: PathBuf::from("/var/www/html"),
                prestashop_url: None,
            };
            match service_id {
                "postfix" => args.postfix = true,
                "dovecot" => args.dovecot = true,
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

/// Inner event loop — runs after the terminal is already in raw/alternate-screen mode.
fn run_inner(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    let detected = detect_box_type();
    let box_type = select_box_type(terminal, detected)?;

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
    let mut app = App::new(box_type, log_dashboard, finding_tx, finding_rx, None);

    loop {
        app.tick();
        terminal.draw(|f| render(f, &mut app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
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
                            if let crate::wizards::WizardAction::Close = wizard.handle_key(key.code)
                            {
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
                                        // OpenCart: DB user(1), DB pass(2), admin pass(7)
                                        RestoreCredService::OpenCart => [1, 2, 7]
                                            .iter()
                                            .any(|&i| dlg.fields[i].trim().is_empty()),
                                        // PrestaShop: DB user(3), DB pass(4), admin pass(6)
                                        RestoreCredService::PrestaShop => [3, 4, 6]
                                            .iter()
                                            .any(|&i| dlg.fields[i].trim().is_empty()),
                                    };
                                    if missing {
                                        // Required field empty — stay on dialog, do nothing.
                                        return Ok(());
                                    }
                                    // Last field confirmed — start restore.
                                    let dialog = app.restore_cred_dialog.take().unwrap();
                                    let service_id = match svc {
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

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char(d @ '1'..='8') => {
                        if let Some(tab) = Tab::from_digit(d) {
                            app.tab = tab;
                        }
                    }
                    KeyCode::Esc => {
                        if app.show_finding_detail {
                            app.show_finding_detail = false;
                            app.action_feedback = None;
                        }
                    }
                    KeyCode::Up => match app.tab {
                        Tab::Tools => {
                            use crate::tui::tools_view::SelectedTool;
                            let total = SelectedTool::total();
                            if total > 0 {
                                app.tools_cursor =
                                    app.tools_cursor.checked_sub(1).unwrap_or(total - 1);
                            }
                        }
                        Tab::Logs => {
                            if let Some(p) = app.log_dashboard.active_pane_mut() {
                                p.scroll_up();
                            }
                        }
                        Tab::Scan => match app.scan_focus {
                            ScanFocus::Modules => {
                                app.scan_cursor = app
                                    .scan_cursor
                                    .checked_sub(1)
                                    .unwrap_or(SCAN_MODULES.len() - 1);
                            }
                            ScanFocus::Findings => {
                                if !app.findings.is_empty() {
                                    app.findings_cursor = app
                                        .findings_cursor
                                        .checked_sub(1)
                                        .unwrap_or(app.findings.len() - 1);
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
                            if !MONITOR_MODULES.is_empty() {
                                app.monitor_cursor = app
                                    .monitor_cursor
                                    .checked_sub(1)
                                    .unwrap_or(MONITOR_MODULES.len() - 1);
                            }
                        }
                        Tab::Backups => {
                            app.backups_cursor = app
                                .backups_cursor
                                .checked_sub(1)
                                .unwrap_or(BACKUP_STEPS.len() - 1);
                        }
                        Tab::ServiceRestore => {
                            app.restore_cursor = app
                                .restore_cursor
                                .checked_sub(1)
                                .unwrap_or(RESTORE_SERVICES.len() - 1);
                        }
                        _ => {}
                    },
                    KeyCode::Down => match app.tab {
                        Tab::Tools => {
                            use crate::tui::tools_view::SelectedTool;
                            let total = SelectedTool::total();
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
                                app.scan_cursor = (app.scan_cursor + 1) % SCAN_MODULES.len();
                            }
                            ScanFocus::Findings => {
                                if !app.findings.is_empty() {
                                    app.findings_cursor =
                                        (app.findings_cursor + 1) % app.findings.len();
                                }
                            }
                        },
                        Tab::Hardening => {
                            app.hardening_cursor =
                                (app.hardening_cursor + 1) % HARDENING_STEPS.len();
                        }
                        Tab::Monitor => {
                            if !MONITOR_MODULES.is_empty() {
                                app.monitor_cursor =
                                    (app.monitor_cursor + 1) % MONITOR_MODULES.len();
                            }
                        }
                        Tab::Backups => {
                            app.backups_cursor = (app.backups_cursor + 1) % BACKUP_STEPS.len();
                        }
                        Tab::ServiceRestore => {
                            app.restore_cursor = (app.restore_cursor + 1) % RESTORE_SERVICES.len();
                        }
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
                            let step_id = BACKUP_STEPS[app.backups_cursor].0;
                            app.start_backup(step_id);
                        } else if app.tab == Tab::ServiceRestore && !app.restore_running {
                            let service_id = RESTORE_SERVICES[app.restore_cursor].0;
                            match service_id {
                                "opencart" => {
                                    app.restore_cred_dialog =
                                        Some(RestoreCredDialog::new(RestoreCredService::OpenCart));
                                }
                                "prestashop" => {
                                    app.restore_cred_dialog = Some(RestoreCredDialog::new(
                                        RestoreCredService::PrestaShop,
                                    ));
                                }
                                _ => app.start_restore(service_id, None),
                            }
                        }
                    }
                    KeyCode::Char('x') => {
                        if app.tab == Tab::Scan && app.show_finding_detail {
                            let cursor = app.findings_cursor;
                            if let Some(finding) = app.findings.get(cursor) {
                                if let Some(action) = finding.actions.first().cloned() {
                                    match execute_action(&action) {
                                        Ok(msg) => {
                                            app.action_feedback = Some(format!("Done: {}", msg));
                                            if let Some(f) = app.findings.get_mut(cursor) {
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
                    KeyCode::Char('e') => {
                        if app.tab == Tab::Scan && app.scan_focus == ScanFocus::Findings {
                            match app.export_ir_report() {
                                Ok(path) => {
                                    app.action_feedback = Some(format!("Exported: {}", path))
                                }
                                Err(e) => {
                                    app.action_feedback = Some(format!("Export failed: {}", e))
                                }
                            }
                        }
                    }
                    KeyCode::Char('d') => {
                        if app.tab == Tab::Tools {
                            use crate::tui::tools_view::SelectedTool;
                            if let SelectedTool::Binary(_) =
                                SelectedTool::from_cursor(app.tools_cursor)
                            {
                                use crate::tools::catalog::NFTBUILD;
                                app.download_status = Some("nftbuild: downloading…".into());
                                let tool = NFTBUILD.clone();
                                std::thread::spawn(move || {
                                    let _ = crate::tools::downloader::download(&tool);
                                });
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        if app.tab == Tab::Tools {
                            use crate::tui::tools_view::SelectedTool;
                            match SelectedTool::from_cursor(app.tools_cursor) {
                                SelectedTool::Binary(_) => {
                                    // Run nftbuild — applies firewall rules immediately
                                    let box_type = app.box_type;
                                    let opts = crate::tools::nftbuild::RunOptions::default();
                                    match crate::tools::nftbuild::run(box_type, &opts) {
                                        Ok(result) => {
                                            app.nft_config = Some(result.config);
                                            app.action_feedback = Some(
                                                "nftbuild applied — ruleset is now active".into(),
                                            );
                                        }
                                        Err(e) => {
                                            app.action_feedback =
                                                Some(format!("nftbuild failed: {}", e));
                                        }
                                    }
                                }
                                SelectedTool::Wizard(idx) => {
                                    if let Some(w) =
                                        crate::wizards::ActiveWizard::new(idx, app.box_type)
                                    {
                                        app.active_wizard = Some(w);
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::End => {
                        if app.tab == Tab::Logs {
                            if let Some(p) = app.log_dashboard.active_pane_mut() {
                                p.scroll_to_bottom();
                            }
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
                        }
                    }
                    KeyCode::BackTab => {
                        if app.tab == Tab::Logs {
                            app.log_dashboard.prev_pane();
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
    render_tabbar(f, rows[0], app.tab, &app.findings, sessions_flagged);

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
            );
        }
        Tab::Backups => {
            render_backups(f, rows[1], app);
        }
        Tab::ServiceRestore => {
            render_service_restore(f, rows[1], app);
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

    // User input modal renders on top of everything.
    if app.user_input_active {
        render_user_input_modal(f, size, &app.user_input_buf);
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
) {
    let crit_count = findings
        .iter()
        .filter(|f| !f.resolved && f.severity == Severity::Critical)
        .count();

    let spans: Vec<Span> = Tab::ALL
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

    // ── RIGHT: context keybinds ──────────────────────────────────────────────
    let mut right: Vec<Span> = Vec::new();

    // global quit + tab switch always shown
    right.extend(kb("q", "quit", key_color));
    right.extend(kb("1-8", "tabs", key_color));

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

    let items: Vec<ListItem> = SCAN_MODULES
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

    // Right: findings list
    let findings_focused = app.scan_focus == ScanFocus::Findings && !app.show_finding_detail;
    let findings_title = format!(" Findings ({}) ", app.findings.len());
    let findings_border = if findings_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    let findings_block = Block::default()
        .title(findings_title)
        .borders(Borders::ALL)
        .border_style(findings_border);

    if app.findings.is_empty() {
        let msg = if app.scan_running {
            "Scanning…"
        } else {
            "No findings — [Tab] to module list, [s] to start scan"
        };
        f.render_widget(
            Paragraph::new(msg)
                .block(findings_block)
                .style(Style::default().fg(Color::DarkGray)),
            cols[1],
        );
    } else {
        let inner = findings_block.inner(cols[1]);
        f.render_widget(findings_block, cols[1]);

        let visible = inner.height as usize;
        let _total = app.findings.len();
        // scroll so the cursor stays in view
        let start = if app.findings_cursor >= visible {
            app.findings_cursor + 1 - visible
        } else {
            0
        };

        let finding_items: Vec<ListItem> = app
            .findings
            .iter()
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
                let line = Line::from(vec![
                    Span::styled(
                        format!("[{}]", finding.severity.label()),
                        base_style
                            .fg(finding.severity.color())
                            .add_modifier(Modifier::BOLD),
                    ),
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
    if app.show_finding_detail {
        if let Some(finding) = app.findings.get(app.findings_cursor) {
            render_finding_detail(f, area, finding, app.action_feedback.as_deref());
        }
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

    // Context rows
    if !finding.context.is_empty() {
        lines.push(Line::from(Span::styled(
            "── Context ──────────────────────────────────────────────",
            Style::default().fg(Color::DarkGray),
        )));
        for (label, value) in &finding.context {
            let label_width = 16usize;
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<width$}", label, width = label_width),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(value),
            ]));
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

    f.render_widget(Paragraph::new(lines), inner);
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

    let cols_per_row = if area.width > 180 {
        3
    } else if area.width > 120 {
        2
    } else {
        1
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

            f.render_widget(Paragraph::new(lines), inner);
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
        f.render_widget(Paragraph::new(lines), inner);
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
                .style(Style::default().fg(Color::DarkGray)),
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
            .map(|l| Line::from(Span::raw(l.clone())))
            .collect();

        f.render_widget(Paragraph::new(lines), inner);
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

    let items: Vec<ListItem> = BACKUP_STEPS
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
                .style(Style::default().fg(Color::DarkGray)),
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

        f.render_widget(Paragraph::new(lines), inner);
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
                .style(Style::default().fg(Color::DarkGray)),
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

        f.render_widget(Paragraph::new(lines), inner);
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
    f.render_widget(Paragraph::new(lines), inner);
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

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
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
