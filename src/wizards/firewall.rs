/// Firewall assessment and hardening wizard.
///
/// Steps: detect current state → choose profile → confirm → execute nftbuild.
use std::sync::{Arc, Mutex};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::core::BoxType;

use super::WizardAction;

/// nftbuild firewall profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// Web server profile (HTTP/HTTPS).
    Web,
    /// Mail server profile (SMTP/IMAP/POP3).
    Mail,
    /// Splunk forwarder profile.
    Splunk,
    /// General workstation profile.
    General,
}

impl Profile {
    /// Human-readable label for the profile.
    fn label(self) -> &'static str {
        match self {
            Profile::Web => "web",
            Profile::Mail => "mail",
            Profile::Splunk => "splunk",
            Profile::General => "general (workstation)",
        }
    }
    /// The `--profile` flag value passed to `nftbuild`.
    fn nftbuild_flag(self) -> &'static str {
        match self {
            Profile::Web => "webserver",
            Profile::Mail => "mail",
            Profile::Splunk => "splunk",
            Profile::General => "wrkstn",
        }
    }
    /// Map a `BoxType` to the corresponding firewall profile.
    fn from_box_type(bt: BoxType) -> Self {
        match bt {
            BoxType::Web => Profile::Web,
            BoxType::Mail => Profile::Mail,
            BoxType::Splunk => Profile::Splunk,
            BoxType::General => Profile::General,
        }
    }
    /// All available profiles in display order.
    const ALL: &'static [Profile] = &[
        Profile::Web,
        Profile::Mail,
        Profile::Splunk,
        Profile::General,
    ];
}

/// Wizard progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Detecting current firewall state before any changes.
    Detect,
    /// Choosing the nftbuild profile to apply.
    Profile,
    /// Confirming the planned changes before execution.
    Confirm,
    /// Running nftbuild and streaming output.
    Executing,
}

/// Firewall assessment and hardening wizard state.
pub struct FirewallWizard {
    /// Current wizard step.
    step: Step,
    /// Lines from the firewall-state detection output shown on step 1.
    detect_lines: Vec<String>,
    /// The nftbuild profile selected by the user.
    profile: Profile,
    /// Index of the highlighted profile row.
    profile_cursor: usize,
    /// Whether to keep SSH (port 22) open in the generated ruleset.
    ssh_open: bool,
    /// Shared log lines streamed from the background execution thread.
    exec_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Set to `true` by the background thread when execution finishes.
    exec_done: Arc<Mutex<bool>>,
    /// Scroll offset for the execution log.
    log_scroll: usize,
}

impl FirewallWizard {
    /// Create a new wizard, pre-selecting `box_type`'s profile.
    pub fn new(box_type: BoxType) -> Self {
        let profile = Profile::from_box_type(box_type);
        let cursor = Profile::ALL.iter().position(|&p| p == profile).unwrap_or(3);
        let detect_lines = detect_firewall_state();
        Self {
            step: Step::Detect,
            detect_lines,
            profile,
            profile_cursor: cursor,
            ssh_open: true,
            exec_log: None,
            exec_done: Arc::new(Mutex::new(false)),
            log_scroll: 0,
        }
    }

    /// Render the wizard modal over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let inner = super::modal_popup(f, area, 75, 80, " Firewall Assessment & Hardening ");
        match self.step {
            Step::Detect => self.render_detect(f, inner),
            Step::Profile => self.render_profile(f, inner),
            Step::Confirm => self.render_confirm(f, inner),
            Step::Executing => self.render_executing(f, inner),
        }
    }

    /// Render step 1: detected firewall state.
    fn render_detect(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let items: Vec<ListItem> = self
            .detect_lines
            .iter()
            .map(|line| {
                let style = if line.starts_with("✓") {
                    Style::default().fg(Color::Green)
                } else if line.starts_with("✗") || line.starts_with("!") {
                    Style::default().fg(Color::Red)
                } else if line.starts_with("──") {
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(Line::from(Span::styled(line.clone(), style)))
            })
            .collect();

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(" Step 1/4 — Current Firewall State ")
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

    /// Render step 2: profile selection list.
    fn render_profile(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(2),
            ])
            .split(area);

        let items: Vec<ListItem> = Profile::ALL
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let is_cur = i == self.profile_cursor;
                let sel = if is_cur { "▶" } else { " " };
                let style = if is_cur {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!(" {} {}", sel, p.label()),
                    style,
                )))
            })
            .collect();

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(" Step 2/4 — Select nftbuild profile ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );

        let ssh_label = if self.ssh_open {
            "[✓] Keep SSH port open"
        } else {
            "[ ] Keep SSH port open"
        };
        let ssh_style = if self.ssh_open {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };
        f.render_widget(
            Paragraph::new(Span::styled(format!(" {}", ssh_label), ssh_style)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[1],
        );

        f.render_widget(
            Paragraph::new(" [↑↓] profile  [s] toggle SSH  [Enter] next  [Esc] cancel")
                .style(Style::default().fg(Color::DarkGray)),
            rows[2],
        );
    }

    /// Render step 3: review and confirm.
    fn render_confirm(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let profile = Profile::ALL[self.profile_cursor];
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Profile:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(profile.label(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("  SSH open: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    if self.ssh_open { "yes" } else { "no" },
                    if self.ssh_open {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::Red)
                    },
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  ⚠  WARNING",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  nftbuild APPLIES RULES IMMEDIATELY by restarting",
                Style::default().fg(Color::Red),
            )),
            Line::from(Span::styled(
                "  the nftables service. Scored services may be affected.",
                Style::default().fg(Color::Red),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Command: nftbuild -sys <profile> [-ssh]",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Step 3/4 — Review (READ THE WARNING) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [Enter] APPLY RULES NOW  [Esc] cancel")
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            rows[1],
        );
    }

    /// Render step 4: live execution log.
    fn render_executing(&self, f: &mut Frame, area: Rect) {
        if let Some(ref log) = self.exec_log {
            let done = *self.exec_done.lock().unwrap();
            super::render_exec_log(f, area, log, done, self.log_scroll);
        }
    }

    /// Handle a keypress and return whether the wizard should close.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self.step {
            Step::Detect => {
                if key == KeyCode::Enter {
                    self.step = Step::Profile;
                }
            }
            Step::Profile => match key {
                KeyCode::Up => {
                    self.profile_cursor = self
                        .profile_cursor
                        .checked_sub(1)
                        .unwrap_or(Profile::ALL.len() - 1);
                }
                KeyCode::Down => {
                    self.profile_cursor = (self.profile_cursor + 1) % Profile::ALL.len();
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.ssh_open = !self.ssh_open;
                }
                KeyCode::Enter => {
                    self.profile = Profile::ALL[self.profile_cursor];
                    self.step = Step::Confirm;
                }
                _ => {}
            },
            Step::Confirm => {
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

    /// Spawn a background thread that runs nftbuild and streams output.
    fn start_execution(&mut self) {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::clone(&self.exec_done);
        let lc = Arc::clone(&log);

        let sys_flag = self.profile.nftbuild_flag().to_string();
        let ssh = self.ssh_open;

        std::thread::spawn(move || {
            macro_rules! push {
                ($s:expr) => {{
                    lc.lock().unwrap().push($s.to_string());
                }};
            }

            push!("→ Checking nftbuild binary…");
            if !super::cmd_succeeds("which nftbuild") {
                push!("  ✗ nftbuild not found in PATH");
                push!("    Download it first in the Tools tab ([d] to download)");
                push!("");
                push!("══ Aborted — press any key to close ══");
                *done.lock().unwrap() = true;
                return;
            }
            push!("  ✓ nftbuild found");

            push!(format!(
                "→ Running: nftbuild -sys {}{}",
                sys_flag,
                if ssh { " -ssh" } else { "" }
            ));

            let mut args = vec!["nftbuild", "-sys", sys_flag.as_str()];
            if ssh {
                args.push("-ssh");
            }
            super::run_cmd_to_log(&args, &lc);

            push!("→ Checking nftables service…");
            super::run_cmd_to_log(&["systemctl", "is-active", "nftables"], &lc);

            push!("→ Showing active ruleset:");
            super::run_cmd_to_log(&["nft", "list", "ruleset"], &lc);

            push!("");
            push!("══ Done — press any key to close ══");
            *done.lock().unwrap() = true;
        });

        self.exec_log = Some(log);
    }
}

/// Probe the running firewall and return human-readable status lines.
fn detect_firewall_state() -> Vec<String> {
    let mut lines = Vec::new();

    lines.push("── Active firewall services ─────────────────────".into());

    for svc in &["nftables", "iptables", "firewalld", "ufw"] {
        let active = super::cmd_succeeds(&format!("systemctl is-active --quiet {}", svc));
        let enabled = super::cmd_succeeds(&format!("systemctl is-enabled --quiet {}", svc));
        let sym = if active { "✓" } else { "✗" };
        lines.push(format!(
            "{} {:12}  active={} enabled={}",
            sym,
            svc,
            if active { "yes" } else { "no " },
            if enabled { "yes" } else { "no " }
        ));
    }

    lines.push("".into());
    lines.push("── nftbuild binary ──────────────────────────────".into());
    if super::cmd_succeeds("which nftbuild") {
        lines.push("✓ nftbuild installed in PATH".into());
    } else {
        lines.push("! nftbuild NOT installed — download it in the Tools tab".into());
    }

    lines.push("".into());
    lines.push("── Quick rule summary ───────────────────────────".into());
    let nft_out = super::cmd_output(&["nft", "list", "tables"]);
    if nft_out.trim().is_empty() {
        lines.push("  (no nft tables — nftables may not be active)".into());
    } else {
        for line in nft_out.lines().take(8) {
            lines.push(format!("  {}", line));
        }
    }

    lines
}
