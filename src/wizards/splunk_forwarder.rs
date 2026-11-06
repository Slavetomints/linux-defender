/// Splunk Universal Forwarder deployment wizard.
///
/// Steps: check install → package path (if needed) → indexer IP/port →
///        box type → summary → execute.
use std::sync::{Arc, Mutex};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::core::BoxType;

use super::WizardAction;

/// Path to the Splunk Universal Forwarder binary.
const SPLUNK_BIN: &str = "/opt/splunkforwarder/bin/splunk";
/// Path to the Splunk forwarder local configuration directory.
const SPLUNK_LOCAL: &str = "/opt/splunkforwarder/etc/system/local";

/// Competition box type used to select default Splunk monitored log paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SplunkBoxType {
    /// Web server box.
    Web,
    /// Mail server box.
    Mail,
    /// Splunk indexer box.
    Splunk,
    /// General workstation box.
    General,
}

impl SplunkBoxType {
    /// Human-readable label for the box type.
    fn label(self) -> &'static str {
        match self {
            SplunkBoxType::Web => "web",
            SplunkBoxType::Mail => "mail",
            SplunkBoxType::Splunk => "splunk (indexer)",
            SplunkBoxType::General => "general",
        }
    }
    /// Map a `BoxType` to the corresponding `SplunkBoxType`.
    fn from_box_type(bt: BoxType) -> Self {
        match bt {
            BoxType::Web => SplunkBoxType::Web,
            BoxType::Mail => SplunkBoxType::Mail,
            BoxType::Splunk => SplunkBoxType::Splunk,
            BoxType::General | BoxType::Router => SplunkBoxType::General,
        }
    }
    /// All box types in display order.
    const ALL: &'static [SplunkBoxType] = &[
        SplunkBoxType::Web,
        SplunkBoxType::Mail,
        SplunkBoxType::Splunk,
        SplunkBoxType::General,
    ];
}

/// Wizard progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Checking whether Splunk is already installed.
    CheckInstall,
    /// Selecting the `.tgz` / `.deb` / `.rpm` package path.
    PackagePath,
    /// Entering the indexer IP and port.
    IndexerConfig,
    /// Selecting the competition box type.
    BoxTypeSelect,
    /// Reviewing the configuration before execution.
    Summary,
    /// Running the install/configure commands.
    Executing,
}

/// Splunk Universal Forwarder deployment wizard state.
pub struct SplunkForwarderWizard {
    /// Current wizard step.
    step: Step,
    /// True if the Splunk forwarder binary is already present on disk.
    already_installed: bool,
    /// Manually entered package path (used when no package is auto-detected).
    package_path: String,
    /// Auto-detected `.tgz`/`.deb`/`.rpm` packages found on disk.
    found_packages: Vec<String>,
    /// Index of the highlighted package in `found_packages`.
    pkg_cursor: usize,
    /// Indexer IP address entered by the user.
    indexer_ip: String,
    /// Indexer receiving port (default `"9997"`).
    indexer_port: String,
    /// Which indexer field is focused: 0 = IP, 1 = port.
    indexer_field: usize,
    /// Competition box type, determines which log paths are monitored.
    box_type: SplunkBoxType,
    /// Index of the highlighted box type row.
    box_cursor: usize,
    /// Shared log lines streamed from the background thread.
    exec_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Set to `true` by the background thread when execution finishes.
    exec_done: Arc<Mutex<bool>>,
    /// Scroll offset for the execution log.
    log_scroll: usize,
}

impl SplunkForwarderWizard {
    /// Create a new wizard. Detects install status and auto-fills box type.
    pub fn new(box_type: BoxType) -> Self {
        let already_installed = std::path::Path::new(SPLUNK_BIN).exists();
        let found_packages = find_packages();
        let sbt = SplunkBoxType::from_box_type(box_type);
        let box_cursor = SplunkBoxType::ALL
            .iter()
            .position(|&b| b == sbt)
            .unwrap_or(3);
        Self {
            step: Step::CheckInstall,
            already_installed,
            package_path: String::new(),
            found_packages,
            pkg_cursor: 0,
            indexer_ip: String::new(),
            indexer_port: "9997".into(),
            indexer_field: 0,
            box_type: sbt,
            box_cursor,
            exec_log: None,
            exec_done: Arc::new(Mutex::new(false)),
            log_scroll: 0,
        }
    }

    /// Render the wizard modal over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let inner = super::modal_popup(f, area, 75, 85, " Splunk Universal Forwarder Deployment ");
        match self.step {
            Step::CheckInstall => self.render_check(f, inner),
            Step::PackagePath => self.render_package(f, inner),
            Step::IndexerConfig => self.render_indexer(f, inner),
            Step::BoxTypeSelect => self.render_box_type(f, inner),
            Step::Summary => self.render_summary(f, inner),
            Step::Executing => self.render_executing(f, inner),
        }
    }

    /// Render step 1: display install-check result.
    fn render_check(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let status_sym = if self.already_installed { "✓" } else { "✗" };
        let status_style = if self.already_installed {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };
        let next_step = if self.already_installed {
            "  → Will reconfigure existing installation"
        } else {
            "  → Will install from package you provide"
        };

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {} Splunk Universal Forwarder", status_sym),
                    status_style.add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    if self.already_installed {
                        format!("  ({})", SPLUNK_BIN)
                    } else {
                        format!("  (not found at {})", SPLUNK_BIN)
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                next_step,
                Style::default().fg(Color::DarkGray),
            )),
        ];

        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Step 1/6 — Installation Status ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [Enter] continue  [Esc] cancel")
                .style(Style::default().fg(Color::DarkGray)),
            rows[1],
        );
    }

    /// Render step 2: package selection or manual path input.
    fn render_package(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(2),
            ])
            .split(area);

        // Found packages list
        let items: Vec<ListItem> = if self.found_packages.is_empty() {
            vec![ListItem::new(Line::from(Span::styled(
                "  (no packages found automatically)",
                Style::default().fg(Color::DarkGray),
            )))]
        } else {
            self.found_packages
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let is_cur = i == self.pkg_cursor;
                    let style = if is_cur {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    ListItem::new(Line::from(Span::styled(
                        format!(" {} {}", if is_cur { "▶" } else { " " }, p),
                        style,
                    )))
                })
                .collect()
        };

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(" Step 2/6 — Found packages (↑↓ select) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );

        // Manual path input
        f.render_widget(
            Paragraph::new(format!(" {}_", self.package_path)).block(
                Block::default()
                    .title(" Or type a custom path ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            rows[1],
        );

        f.render_widget(
            Paragraph::new(
                " [↑↓] select found package  [type] custom path  [Enter] next  [Esc] cancel",
            )
            .style(Style::default().fg(Color::DarkGray)),
            rows[2],
        );
    }

    /// Render step 3: indexer IP and port entry.
    fn render_indexer(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(2),
            ])
            .split(area);

        let fields = [
            ("Indexer IP address (required)", &self.indexer_ip, 0usize),
            ("Indexer port", &self.indexer_port, 1),
        ];

        for (label, val, idx) in &fields {
            let active = self.indexer_field == *idx;
            let disp = if active {
                format!(" {}_", val)
            } else {
                format!(" {}", val)
            };
            f.render_widget(
                Paragraph::new(disp).block(
                    Block::default()
                        .title(*label)
                        .borders(Borders::ALL)
                        .border_style(if active {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Blue)
                        }),
                ),
                rows[*idx],
            );
        }

        f.render_widget(
            Paragraph::new(" Step 3/6 — Indexer  |  [Tab/↑↓] switch  [Enter] next  [Esc] cancel")
                .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );
    }

    /// Render step 4: box-type selection list.
    fn render_box_type(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let items: Vec<ListItem> = SplunkBoxType::ALL
            .iter()
            .enumerate()
            .map(|(i, bt)| {
                let is_cur = i == self.box_cursor;
                let style = if is_cur {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!(" {} {}", if is_cur { "▶" } else { " " }, bt.label()),
                    style,
                )))
            })
            .collect();

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(" Step 4/6 — Box type (determines which logs to forward) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [↑↓] select  [Enter] next  [Esc] cancel")
                .style(Style::default().fg(Color::DarkGray)),
            rows[1],
        );
    }

    /// Render step 5: review configuration before execution.
    fn render_summary(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let install_note = if self.already_installed {
            "reconfigure existing".into()
        } else {
            format!(
                "install from: {}",
                self.effective_package_path()
                    .unwrap_or_else(|| "(no path set)".into())
            )
        };

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Action:    ", Style::default().fg(Color::DarkGray)),
                Span::raw(install_note),
            ]),
            Line::from(vec![
                Span::styled("  Indexer:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{}:{}", self.indexer_ip, self.indexer_port)),
            ]),
            Line::from(vec![
                Span::styled("  Box type:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(SplunkBoxType::ALL[self.box_cursor].label()),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  This will write outputs.conf + inputs.conf, enable",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  boot-start, and restart the forwarder.",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Step 5/6 — Review ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [Enter] execute  [Esc] cancel")
                .style(Style::default().fg(Color::Yellow)),
            rows[1],
        );
    }

    /// Render step 6: live execution log.
    fn render_executing(&self, f: &mut Frame, area: Rect) {
        if let Some(ref log) = self.exec_log {
            let done = *self.exec_done.lock().unwrap();
            super::render_exec_log(f, area, log, done, self.log_scroll);
        }
    }

    /// Handle a keypress and return whether the wizard should close.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self.step {
            Step::CheckInstall => {
                if key == KeyCode::Enter {
                    self.step = if self.already_installed {
                        Step::IndexerConfig
                    } else {
                        Step::PackagePath
                    };
                }
            }
            Step::PackagePath => match key {
                KeyCode::Up => {
                    if !self.found_packages.is_empty() {
                        self.pkg_cursor = self
                            .pkg_cursor
                            .checked_sub(1)
                            .unwrap_or(self.found_packages.len() - 1);
                        self.package_path.clear();
                    }
                }
                KeyCode::Down => {
                    if !self.found_packages.is_empty() {
                        self.pkg_cursor = (self.pkg_cursor + 1) % self.found_packages.len();
                        self.package_path.clear();
                    }
                }
                KeyCode::Char(c) => {
                    if self.package_path.len() < 256 {
                        self.package_path.push(c);
                    }
                }
                KeyCode::Backspace => {
                    self.package_path.pop();
                }
                KeyCode::Enter => {
                    self.step = Step::IndexerConfig;
                }
                _ => {}
            },
            Step::IndexerConfig => match key {
                KeyCode::Tab | KeyCode::Down => {
                    self.indexer_field = (self.indexer_field + 1) % 2;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    self.indexer_field = if self.indexer_field == 0 { 1 } else { 0 };
                }
                KeyCode::Char(c) => {
                    if self.indexer_field == 0 && self.indexer_ip.len() < 45 {
                        self.indexer_ip.push(c);
                    } else if self.indexer_field == 1
                        && self.indexer_port.len() < 5
                        && c.is_ascii_digit()
                    {
                        self.indexer_port.push(c);
                    }
                }
                KeyCode::Backspace => {
                    if self.indexer_field == 0 {
                        self.indexer_ip.pop();
                    } else {
                        self.indexer_port.pop();
                    }
                }
                KeyCode::Enter if !self.indexer_ip.is_empty() => {
                    self.box_type = SplunkBoxType::ALL[self.box_cursor];
                    self.step = Step::BoxTypeSelect;
                }
                _ => {}
            },
            Step::BoxTypeSelect => match key {
                KeyCode::Up => {
                    self.box_cursor = self
                        .box_cursor
                        .checked_sub(1)
                        .unwrap_or(SplunkBoxType::ALL.len() - 1);
                }
                KeyCode::Down => {
                    self.box_cursor = (self.box_cursor + 1) % SplunkBoxType::ALL.len();
                }
                KeyCode::Enter => {
                    self.box_type = SplunkBoxType::ALL[self.box_cursor];
                    self.step = Step::Summary;
                }
                _ => {}
            },
            Step::Summary => {
                if key == KeyCode::Enter {
                    self.start_execution();
                    self.step = Step::Executing;
                }
            }
            Step::Executing => {
                let done = *self.exec_done.lock().unwrap();
                match key {
                    KeyCode::Up => {
                        if self.log_scroll > 0 {
                            self.log_scroll -= 1;
                        }
                    }
                    KeyCode::Down => {
                        self.log_scroll += 1;
                    }
                    _ if done => {
                        return WizardAction::Close;
                    }
                    _ => {}
                }
            }
        }
        WizardAction::Continue
    }

    /// Return the package path to install from: selected auto-detected path or manually entered path.
    fn effective_package_path(&self) -> Option<String> {
        if !self.package_path.is_empty() {
            Some(self.package_path.clone())
        } else {
            self.found_packages.get(self.pkg_cursor).cloned()
        }
    }

    /// Spawn a background thread that installs/configures the Splunk forwarder and streams output.
    fn start_execution(&mut self) {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::clone(&self.exec_done);
        let lc = Arc::clone(&log);

        let already_installed = self.already_installed;
        let pkg_path = self.effective_package_path().unwrap_or_default();
        let ip = self.indexer_ip.clone();
        let port = self.indexer_port.clone();
        let bt = self.box_type;

        std::thread::spawn(move || {
            macro_rules! push {
                ($s:expr) => {{
                    lc.lock().unwrap().push($s.to_string());
                }};
            }

            if !already_installed {
                push!("→ Installing Splunk Universal Forwarder…");
                if pkg_path.is_empty() {
                    push!("  ERROR: no package path provided");
                    *done.lock().unwrap() = true;
                    return;
                }
                if !std::path::Path::new(&pkg_path).exists() {
                    push!(format!("  ERROR: package not found: {}", pkg_path));
                    *done.lock().unwrap() = true;
                    return;
                }
                if pkg_path.ends_with(".deb") {
                    super::run_cmd_to_log(&["dpkg", "-i", &pkg_path], &lc);
                } else if pkg_path.ends_with(".rpm") {
                    if super::cmd_succeeds("which dnf") {
                        super::run_cmd_to_log(&["dnf", "install", "-y", &pkg_path], &lc);
                    } else {
                        super::run_cmd_to_log(&["rpm", "-ivh", &pkg_path], &lc);
                    }
                } else {
                    push!(format!("  ERROR: unknown package format: {}", pkg_path));
                    *done.lock().unwrap() = true;
                    return;
                }
                if !std::path::Path::new(SPLUNK_BIN).exists() {
                    push!(format!("  ERROR: {} not found after install", SPLUNK_BIN));
                    *done.lock().unwrap() = true;
                    return;
                }
                push!("  ✓ Splunk UF installed");
            } else {
                push!("→ Using existing Splunk installation");
            }

            push!("→ Writing outputs.conf…");
            if let Err(e) = std::fs::create_dir_all(SPLUNK_LOCAL) {
                push!(format!("  ERROR creating {}: {}", SPLUNK_LOCAL, e));
                *done.lock().unwrap() = true;
                return;
            }
            let outputs = format!(
                "[tcpout]\ndefaultGroup = indexers\n\n[tcpout:indexers]\nserver = {}:{}\n",
                ip, port
            );
            match std::fs::write(format!("{}/outputs.conf", SPLUNK_LOCAL), &outputs) {
                Ok(_) => push!("  ✓ outputs.conf written"),
                Err(e) => {
                    push!(format!("  ERROR: {}", e));
                    *done.lock().unwrap() = true;
                    return;
                }
            }

            push!("→ Writing inputs.conf…");
            let inputs = build_inputs_conf(bt);
            match std::fs::write(format!("{}/inputs.conf", SPLUNK_LOCAL), &inputs) {
                Ok(_) => push!("  ✓ inputs.conf written"),
                Err(e) => {
                    push!(format!("  ERROR: {}", e));
                    *done.lock().unwrap() = true;
                    return;
                }
            }

            push!("→ Enabling boot-start…");
            super::run_cmd_to_log(
                &[
                    SPLUNK_BIN,
                    "enable",
                    "boot-start",
                    "--accept-license",
                    "--answer-yes",
                    "--no-prompt",
                ],
                &lc,
            );

            push!("→ Restarting Splunk forwarder…");
            super::run_cmd_to_log(
                &[
                    SPLUNK_BIN,
                    "restart",
                    "--accept-license",
                    "--answer-yes",
                    "--no-prompt",
                ],
                &lc,
            );

            push!("→ Status check:");
            super::run_cmd_to_log(
                &[
                    SPLUNK_BIN,
                    "status",
                    "--accept-license",
                    "--answer-yes",
                    "--no-prompt",
                ],
                &lc,
            );

            push!("");
            push!("══ Done — press any key to close ══");
            *done.lock().unwrap() = true;
        });

        self.exec_log = Some(log);
    }
}

/// Build an `inputs.conf` content string with log monitors appropriate for `bt`.
fn build_inputs_conf(bt: SplunkBoxType) -> String {
    let mut out = String::new();
    macro_rules! monitor {
        ($path:expr, $stype:expr) => {
            out.push_str(&format!(
                "[monitor://{}]\nindex = main\nsourcetype = {}\n\n",
                $path, $stype
            ));
        };
    }
    match bt {
        SplunkBoxType::Web => {
            // Apache
            if std::path::Path::new("/var/log/apache2").exists() {
                monitor!("/var/log/apache2/access.log", "access_combined");
                monitor!("/var/log/apache2/error.log", "apache_error");
            }
            if std::path::Path::new("/var/log/httpd").exists() {
                monitor!("/var/log/httpd/access_log", "access_combined");
                monitor!("/var/log/httpd/error_log", "apache_error");
            }
            if std::path::Path::new("/var/log/nginx").exists() {
                monitor!("/var/log/nginx/access.log", "nginx_access");
                monitor!("/var/log/nginx/error.log", "nginx_error");
            }
            monitor!("/var/log/auth.log", "linux_secure");
            monitor!("/var/log/syslog", "syslog");
        }
        SplunkBoxType::Mail => {
            monitor!("/var/log/mail.log", "syslog");
            monitor!("/var/log/auth.log", "linux_secure");
            monitor!("/var/log/syslog", "syslog");
            if std::path::Path::new("/var/log/maillog").exists() {
                monitor!("/var/log/maillog", "syslog");
            }
            for rc in &[
                "/var/log/roundcube/errors.log",
                "/var/log/roundcubemail/errors.log",
            ] {
                if std::path::Path::new(rc).exists() {
                    monitor!(rc, "php");
                }
            }
        }
        SplunkBoxType::Splunk => {
            monitor!("/opt/splunk/var/log/splunk/splunkd.log", "splunk_splunkd");
            monitor!(
                "/opt/splunk/var/log/splunk/web_access.log",
                "splunk_web_access"
            );
            monitor!("/opt/splunk/var/log/splunk/metrics.log", "splunk_metrics");
            monitor!("/var/log/auth.log", "linux_secure");
        }
        SplunkBoxType::General => {
            monitor!("/var/log/auth.log", "linux_secure");
            monitor!("/var/log/syslog", "syslog");
            monitor!("/var/log/kern.log", "syslog");
            if std::path::Path::new("/var/log/secure").exists() {
                monitor!("/var/log/secure", "linux_secure");
            }
            if std::path::Path::new("/var/log/messages").exists() {
                monitor!("/var/log/messages", "syslog");
            }
        }
    }
    out
}

/// Search common locations for Splunk `.tgz`, `.deb`, and `.rpm` packages.
fn find_packages() -> Vec<String> {
    let search_dirs = ["/tmp", "/root", "/var/cache/apt/archives"];
    let mut found = Vec::new();
    for dir in &search_dirs {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if (name.starts_with("splunk") || name.starts_with("splunkforwarder"))
                    && (name.ends_with(".deb") || name.ends_with(".rpm"))
                {
                    if let Ok(path) = entry.path().canonicalize() {
                        found.push(path.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    found.sort();
    found
}
