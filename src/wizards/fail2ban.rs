/// fail2ban deployment wizard.
///
/// Steps: service selection → timing config → summary → execute.
use std::sync::{Arc, Mutex};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use super::WizardAction;

const SERVICES: &[(&str, &str)] = &[
    ("sshd", "SSH daemon"),
    ("apache2", "Apache HTTP server"),
    ("nginx", "Nginx HTTP server"),
    ("postfix", "Postfix SMTP"),
    ("dovecot", "Dovecot IMAP/POP3"),
    ("vsftpd", "vsftpd FTP"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    ServiceSelect,
    TimingConfig,
    Summary,
    Executing,
}

/// fail2ban deployment wizard state.
pub struct Fail2BanWizard {
    step: Step,
    services: Vec<bool>,
    service_cursor: usize,
    maxretry: String,
    bantime: String,
    findtime: String,
    timing_cursor: usize,
    exec_log: Option<Arc<Mutex<Vec<String>>>>,
    exec_done: Arc<Mutex<bool>>,
    log_scroll: usize,
}

impl Fail2BanWizard {
    /// Create a new wizard with sshd selected by default.
    pub fn new() -> Self {
        let mut services = vec![false; SERVICES.len()];
        services[0] = true;
        Self {
            step: Step::ServiceSelect,
            services,
            service_cursor: 0,
            maxretry: "5".into(),
            bantime: "3600".into(),
            findtime: "600".into(),
            timing_cursor: 0,
            exec_log: None,
            exec_done: Arc::new(Mutex::new(false)),
            log_scroll: 0,
        }
    }

    /// Render the wizard modal over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let inner = super::modal_popup(f, area, 70, 80, " Deploy fail2ban ");
        match self.step {
            Step::ServiceSelect => self.render_service_select(f, inner),
            Step::TimingConfig => self.render_timing(f, inner),
            Step::Summary => self.render_summary(f, inner),
            Step::Executing => self.render_executing(f, inner),
        }
    }

    fn render_service_select(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let items: Vec<ListItem> = SERVICES
            .iter()
            .enumerate()
            .map(|(i, (id, desc))| {
                let on = self.services[i];
                let is_cur = i == self.service_cursor;
                let cb = if on { "[✓]" } else { "[ ]" };
                let style = if is_cur {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else if on {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!(" {} {:<10}  {}", cb, id, desc),
                    style,
                )))
            })
            .collect();

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(" Step 1/4 — Select services to protect ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(" [↑↓] move  [Space] toggle  [Enter] next  [Esc] cancel")
                .style(Style::default().fg(Color::DarkGray)),
            rows[1],
        );
    }

    fn render_timing(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(2),
            ])
            .split(area);

        let fields: [(&str, &str, usize); 3] = [
            ("Max retry (attempts before ban)", &self.maxretry, 0),
            ("Ban time (seconds)", &self.bantime, 1),
            ("Find time window (seconds)", &self.findtime, 2),
        ];

        for (label, val, idx) in &fields {
            let active = *idx == self.timing_cursor;
            let disp = if active {
                format!("{}_", val)
            } else {
                val.to_string()
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
            Paragraph::new(
                " Step 2/4 — Timing  |  [Tab/↑↓] switch  [0-9] type  [Backspace] delete  [Enter] next",
            )
            .style(Style::default().fg(Color::DarkGray)),
            rows[4],
        );
    }

    fn render_summary(&self, f: &mut Frame, area: Rect) {
        let enabled: Vec<&str> = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, on)| **on)
            .map(|(i, _)| SERVICES[i].0)
            .collect();

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Services:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    if enabled.is_empty() {
                        "(none selected)".into()
                    } else {
                        enabled.join(", ")
                    },
                    Style::default(),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Max retry:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(self.maxretry.clone()),
            ]),
            Line::from(vec![
                Span::styled("  Ban time:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{}s", self.bantime)),
            ]),
            Line::from(vec![
                Span::styled("  Find time:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{}s", self.findtime)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  This will:",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from("    • install fail2ban if not present"),
            Line::from("    • write /etc/fail2ban/jail.local"),
            Line::from("    • restart fail2ban service"),
        ];

        f.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Step 3/4 — Review and confirm ")
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

    fn render_executing(&self, f: &mut Frame, area: Rect) {
        if let Some(ref log) = self.exec_log {
            let done = *self.exec_done.lock().unwrap();
            super::render_exec_log(f, area, log, done, self.log_scroll);
        }
    }

    /// Handle a keypress and return whether the wizard should close.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self.step {
            Step::ServiceSelect => match key {
                KeyCode::Up => {
                    self.service_cursor = self
                        .service_cursor
                        .checked_sub(1)
                        .unwrap_or(SERVICES.len() - 1);
                }
                KeyCode::Down => {
                    self.service_cursor = (self.service_cursor + 1) % SERVICES.len();
                }
                KeyCode::Char(' ') => {
                    self.services[self.service_cursor] ^= true;
                }
                KeyCode::Enter => {
                    self.step = Step::TimingConfig;
                }
                _ => {}
            },
            Step::TimingConfig => match key {
                KeyCode::Up | KeyCode::BackTab => {
                    self.timing_cursor = self.timing_cursor.checked_sub(1).unwrap_or(2);
                }
                KeyCode::Down | KeyCode::Tab => {
                    self.timing_cursor = (self.timing_cursor + 1) % 3;
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let f = self.active_timing_field();
                    if f.len() < 7 {
                        f.push(c);
                    }
                }
                KeyCode::Backspace => {
                    self.active_timing_field().pop();
                }
                KeyCode::Enter => {
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

    fn active_timing_field(&mut self) -> &mut String {
        match self.timing_cursor {
            0 => &mut self.maxretry,
            1 => &mut self.bantime,
            _ => &mut self.findtime,
        }
    }

    fn start_execution(&mut self) {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::clone(&self.exec_done);
        let lc = Arc::clone(&log);

        let enabled: Vec<String> = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, on)| **on)
            .map(|(i, _)| SERVICES[i].0.to_string())
            .collect();
        let maxretry = self.maxretry.clone();
        let bantime = self.bantime.clone();
        let findtime = self.findtime.clone();

        std::thread::spawn(move || {
            macro_rules! push {
                ($s:expr) => {{
                    lc.lock().unwrap().push($s.to_string());
                }};
            }

            push!("→ Checking fail2ban installation…");
            if super::cmd_succeeds("which fail2ban-client") {
                push!("  ✓ fail2ban is installed");
            } else {
                push!("  Not found — attempting install…");
                if super::cmd_succeeds("which apt-get") {
                    super::run_cmd_to_log(
                        &["apt-get", "install", "-y", "fail2ban"],
                        &lc,
                    );
                } else if super::cmd_succeeds("which dnf") {
                    super::run_cmd_to_log(&["dnf", "install", "-y", "fail2ban"], &lc);
                } else if super::cmd_succeeds("which yum") {
                    super::run_cmd_to_log(&["yum", "install", "-y", "fail2ban"], &lc);
                } else {
                    push!("  ERROR: no package manager found (apt-get/dnf/yum)");
                    *done.lock().unwrap() = true;
                    return;
                }
            }

            push!("→ Writing /etc/fail2ban/jail.local…");
            let config = build_jail_config(&enabled, &maxretry, &bantime, &findtime);
            match std::fs::write("/etc/fail2ban/jail.local", &config) {
                Ok(_) => push!("  ✓ Written"),
                Err(e) => {
                    push!(format!("  ERROR: {}", e));
                    *done.lock().unwrap() = true;
                    return;
                }
            }

            push!("→ Restarting fail2ban…");
            super::run_cmd_to_log(&["systemctl", "restart", "fail2ban"], &lc);

            push!("→ Service status:");
            super::run_cmd_to_log(&["systemctl", "is-active", "fail2ban"], &lc);

            push!("");
            push!("══ Done — press any key to close ══");
            *done.lock().unwrap() = true;
        });

        self.exec_log = Some(log);
    }
}

fn build_jail_config(
    services: &[String],
    maxretry: &str,
    bantime: &str,
    findtime: &str,
) -> String {
    let mut out = format!(
        "[DEFAULT]\nmaxretry = {}\nbantime  = {}\nfindtime = {}\n\n",
        maxretry.parse::<u32>().unwrap_or(5),
        bantime.parse::<u32>().unwrap_or(3600),
        findtime.parse::<u32>().unwrap_or(600),
    );
    for svc in services {
        match svc.as_str() {
            "sshd" => out.push_str("[sshd]\nenabled = true\n\n"),
            "apache2" => out.push_str(
                "[apache-auth]\nenabled = true\n\n[apache-badbots]\nenabled = true\n\n",
            ),
            "nginx" => out.push_str("[nginx-http-auth]\nenabled = true\n\n"),
            "postfix" => out.push_str("[postfix]\nenabled = true\n\n"),
            "dovecot" => out.push_str("[dovecot]\nenabled = true\n\n"),
            "vsftpd" => out.push_str("[vsftpd]\nenabled = true\n\n"),
            _ => {}
        }
    }
    out
}
