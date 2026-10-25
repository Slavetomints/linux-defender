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
use crate::tui::logs::dashboard::LogDashboard as LogDash;

use super::dashboard::{
    SessionInfo, poll_auth_events, poll_services, poll_sessions, render as render_dashboard,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Logs,
    Scan,
    Hardening,
    Backups,
    Monitor,
    Tools,
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
        }
    }

    /// Map a `1`–`7` digit keypress to the corresponding tab, or `None` for anything else.
    fn from_digit(d: char) -> Option<Tab> {
        match d {
            '1' => Some(Tab::Dashboard),
            '2' => Some(Tab::Logs),
            '3' => Some(Tab::Scan),
            '4' => Some(Tab::Hardening),
            '5' => Some(Tab::Backups),
            '6' => Some(Tab::Monitor),
            '7' => Some(Tab::Tools),
            _ => None,
        }
    }
}

pub struct App {
    pub box_type: BoxType,
    pub tab: Tab,
    pub findings: Vec<Finding>,
    pub services: Vec<(&'static str, u16, bool)>,
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
        let services = poll_services(box_type.services());
        let (scan_progress_tx, scan_progress_rx) = mpsc::channel();
        let (auto_scan_done_tx, auto_scan_done_rx) = mpsc::channel::<&'static str>();
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
        }
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
        // Drain completed auto-scan threads.
        while let Ok(id) = self.auto_scan_done_rx.try_recv() {
            self.auto_scan_running.remove(id);
        }
        if self.auto_scan_enabled {
            self.tick_auto_scan();
        }
        if self.last_service_check.elapsed() >= Duration::from_secs(5) {
            self.services = poll_services(self.box_type.services());
            self.sessions = poll_sessions(&self.authorized_users);
            self.auth_events = poll_auth_events();
            self.last_service_check = Instant::now();
            // Watchdog: automatically restart scored services that have gone down.
            if self.watchdog_enabled {
                let down: Vec<&'static str> = self
                    .services
                    .iter()
                    .filter_map(|&(name, _port, up)| if !up { Some(name) } else { None })
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

    /// Export the current findings as a timestamped IR report.
    /// Returns the path written on success, or an error string.
    fn export_ir_report(&self) -> Result<String, String> {
        let now = Local::now();
        let ts = now.format("%Y%m%d_%H%M%S").to_string();

        let path = if nix::unistd::geteuid().is_root() {
            let dir = std::path::Path::new("/etc/linux-defender/reports");
            std::fs::create_dir_all(dir).map_err(|e| format!("mkdir failed: {}", e))?;
            dir.join(format!("{}.txt", ts))
        } else {
            std::path::PathBuf::from(format!("/tmp/defender-report-{}.txt", ts))
        };

        let crit = self
            .findings
            .iter()
            .filter(|f| !f.resolved && f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| !f.resolved && f.severity == Severity::High)
            .count();
        let med = self
            .findings
            .iter()
            .filter(|f| !f.resolved && f.severity == Severity::Medium)
            .count();

        let mut report = format!(
            "LINUX-DEFENDER IR REPORT\nGenerated: {}\nBox type: {}\nTotal findings: {} (Critical: {}, High: {}, Medium: {})\n{}\n\n",
            now.format("%Y-%m-%d %H:%M:%S"),
            self.box_type.label(),
            self.findings.len(),
            crit,
            high,
            med,
            "=".repeat(40),
        );

        for finding in &self.findings {
            report.push_str(&format!(
                "[{}] {}  {}\n  {}\n",
                finding.severity.label().trim(),
                finding.verdict.label(),
                finding.module,
                finding.summary,
            ));
            if let Some(ref p) = finding.path {
                report.push_str(&format!("  path: {}\n", p.display()));
            }
            if !finding.detail.is_empty() {
                report.push_str(&format!("  {}\n", finding.detail));
            }
            for (label, value) in &finding.context {
                report.push_str(&format!("  {}: {}\n", label, value));
            }
            report.push('\n');
        }

        let path_str = path.to_string_lossy().to_string();
        std::fs::write(&path, report).map_err(|e| format!("write failed: {}", e))?;
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

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char(d @ '1'..='7') => {
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
                        _ => {}
                    },
                    KeyCode::Enter => {
                        if app.tab == Tab::Scan
                            && app.scan_focus == ScanFocus::Findings
                            && !app.findings.is_empty()
                        {
                            app.show_finding_detail = !app.show_finding_detail;
                            app.action_feedback = None;
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
        Tab::Tools => {
            use crate::tui::tools_view::SelectedTool;
            let selected = SelectedTool::from_cursor(app.tools_cursor);
            crate::tui::tools_view::render(f, rows[1], selected, app.download_status.as_deref());
        }
        _ => {
            render_placeholder(f, rows[1], app.tab.label());
        }
    }

    // Wizard overlay renders on top of the full terminal area.
    if let Some(ref wizard) = app.active_wizard {
        wizard.render(f, size);
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
    let down = app.services.iter().filter(|(_, _, up)| !up).count();
    let down_str = if down > 0 {
        format!("  ⚠ {} DOWN", down)
    } else {
        String::new()
    };

    let scan_str = if app.scan_running {
        format!("  scanning: {}", app.scan_progress)
    } else if app.auto_scan_enabled {
        let n = app.auto_scan_running.len();
        if n > 0 {
            format!("  AUTO ↻{}", n)
        } else {
            "  AUTO".to_string()
        }
    } else {
        String::new()
    };

    let paused = app.tab == Tab::Logs
        && app
            .log_dashboard
            .panes
            .get(app.log_dashboard.active)
            .is_some_and(|p| p.paused);
    let pause_str = if paused { "  [PAUSED]" } else { "" };

    let watchdog_str = if app.watchdog_enabled {
        "  WATCHDOG"
    } else {
        ""
    };

    let hint = match app.tab {
        Tab::Dashboard => "  [w] watchdog  [u] users",
        Tab::Logs => "  [Tab] pane  [p] pause  [↑↓] scroll",
        Tab::Scan if app.show_finding_detail => "  [x] execute  [Esc] back",
        Tab::Scan => match app.scan_focus {
            ScanFocus::Modules => {
                "  [Tab] → findings  [↑↓] move  [Space] toggle  [a] all  [s] scan  [w] auto"
            }
            ScanFocus::Findings => "  [Tab] → modules  [↑↓] move  [Enter] detail  [e] export",
        },
        Tab::Tools => "  [↑↓] navigate   [d] download (binary)   [r] run selected tool/script",
        _ => "",
    };

    let text = format!(
        " box:{box}  findings:{n}{down}{scan}{watchdog}{pause}  [q]uit  [1-7] tabs{hint}",
        box = app.box_type.label(),
        n = app.findings.len(),
        down = down_str,
        scan = scan_str,
        watchdog = watchdog_str,
        pause = pause_str,
    );

    let style = if down > 0 {
        Style::default().bg(Color::DarkGray).fg(Color::Red)
    } else {
        Style::default().bg(Color::DarkGray).fg(Color::White)
    };

    f.render_widget(Paragraph::new(text).style(style), area);
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

/// Render a "coming soon" placeholder for tabs that are not yet implemented.
fn render_placeholder(f: &mut ratatui::Frame, area: Rect, name: &str) {
    let block = Block::default()
        .title(format!(" {} ", name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    let p = Paragraph::new(format!("{} — coming soon", name))
        .block(block)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
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
