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

/// Service id/description pairs the wizard lets the user protect with fail2ban.
const SERVICES: &[(&str, &str)] = &[
    ("sshd", "SSH daemon"),
    ("apache2", "Apache HTTP server"),
    ("nginx", "Nginx HTTP server"),
    ("postfix", "Postfix SMTP"),
    ("dovecot", "Dovecot IMAP/POP3"),
    ("vsftpd", "vsftpd FTP"),
];

/// Wizard progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Step 1: choose which services to protect.
    ServiceSelect,
    /// Step 2: configure timing parameters (maxretry, bantime, findtime).
    TimingConfig,
    /// Step 3: review the configuration before executing.
    Summary,
    /// Step 4: running the deployment commands and streaming output.
    Executing,
}

/// fail2ban deployment wizard state.
pub struct Fail2BanWizard {
    /// Current wizard step.
    step: Step,
    /// Selection state for each service in `SERVICES`.
    services: Vec<bool>,
    /// Index of the highlighted service row.
    service_cursor: usize,
    /// Maximum failed attempts before banning.
    maxretry: String,
    /// Duration to keep an IP banned (seconds).
    bantime: String,
    /// Window in which `maxretry` failures trigger a ban (seconds).
    findtime: String,
    /// Addresses fail2ban must never ban (`ignoreip`), space separated.
    ignoreip: String,
    /// Index of the active field (0=maxretry, 1=bantime, 2=findtime, 3=ignoreip).
    timing_cursor: usize,
    /// Shared execution log lines streamed from the background thread.
    exec_log: Option<Arc<Mutex<Vec<String>>>>,
    /// Set to `true` by the background thread when execution finishes.
    exec_done: Arc<Mutex<bool>>,
    /// Scroll offset for the execution log.
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
            ignoreip: default_ignoreip(),
            timing_cursor: 0,
            exec_log: None,
            exec_done: Arc::new(Mutex::new(false)),
            log_scroll: 0,
        }
    }
}

impl Default for Fail2BanWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl Fail2BanWizard {
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

    /// Render step 1: the service-selection list.
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

    /// Render step 2: the timing configuration fields.
    fn render_timing(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(2),
            ])
            .split(area);

        let fields: [(&str, &str, usize); 4] = [
            ("Max retry (attempts before ban)", &self.maxretry, 0),
            ("Ban time (seconds)", &self.bantime, 1),
            ("Find time window (seconds)", &self.findtime, 2),
            (
                "Never ban (ignoreip) — add the scoring engine's address",
                &self.ignoreip,
                3,
            ),
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
            rows[5],
        );
    }

    /// Render step 3: the review-and-confirm summary.
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
            Line::from(vec![
                Span::styled("  Never ban:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(self.ignoreip.clone()),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  This will:",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from("    • install fail2ban if not present"),
            Line::from("    • save any existing jail.local to quarantine, then write a new one"),
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

    /// Render step 4: the live execution log.
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
                    self.timing_cursor = self.timing_cursor.checked_sub(1).unwrap_or(3);
                }
                KeyCode::Down | KeyCode::Tab => {
                    self.timing_cursor = (self.timing_cursor + 1) % 4;
                }
                KeyCode::Char(c) if self.timing_cursor < 3 && c.is_ascii_digit() => {
                    let f = self.active_timing_field();
                    if f.len() < 7 {
                        f.push(c);
                    }
                }
                KeyCode::Char(c)
                    if self.timing_cursor == 3
                        && (c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/' | ' ')) =>
                {
                    let f = self.active_timing_field();
                    if f.len() < 400 {
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

    /// Return a mutable reference to the currently focused timing field string.
    fn active_timing_field(&mut self) -> &mut String {
        match self.timing_cursor {
            0 => &mut self.maxretry,
            1 => &mut self.bantime,
            2 => &mut self.findtime,
            _ => &mut self.ignoreip,
        }
    }

    /// Spawn a background thread that installs/configures fail2ban and streams log output.
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
        let ignoreip = self.ignoreip.clone();

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
                    super::run_cmd_to_log(&["apt-get", "install", "-y", "fail2ban"], &lc);
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

            let jail_local = std::path::Path::new("/etc/fail2ban/jail.local");
            if jail_local.exists() {
                match crate::core::context::quarantine_copy(jail_local) {
                    Ok(saved) => push!(format!(
                        "  ✓ Existing jail.local saved to {}",
                        saved.display()
                    )),
                    Err(e) => {
                        push!(format!(
                            "  ERROR: could not back up jail.local ({e}); not overwriting it"
                        ));
                        *done.lock().unwrap() = true;
                        return;
                    }
                }
            }

            push!("→ Writing /etc/fail2ban/jail.local…");
            let _ = std::fs::create_dir_all("/etc/fail2ban");
            let journal_only: Vec<&str> = ["sshd", "postfix", "dovecot"]
                .into_iter()
                .filter(|svc| needs_systemd_backend(svc, |p| std::path::Path::new(p).exists()))
                .collect();
            let config = build_jail_config(
                &enabled,
                &maxretry,
                &bantime,
                &findtime,
                &ignoreip,
                &journal_only,
            );
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

/// Build a `jail.local` config string for the selected services and timing values.
fn build_jail_config(
    services: &[String],
    maxretry: &str,
    bantime: &str,
    findtime: &str,
    ignoreip: &str,
    journal_only: &[&str],
) -> String {
    // Always keep loopback, then whatever the operator listed, filtered to
    // address-like tokens so nothing else can be smuggled into the INI file.
    let mut ignore: Vec<String> = vec!["127.0.0.1/8".into(), "::1".into()];
    for tok in ignoreip.split_whitespace() {
        let ok = tok
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'));
        if ok && !ignore.iter().any(|t| t == tok) {
            ignore.push(tok.to_string());
        }
    }
    let mut out = format!(
        "[DEFAULT]\nignoreip = {}\nmaxretry = {}\nbantime  = {}\nfindtime = {}\n\n",
        ignore.join(" "),
        maxretry.parse::<u32>().unwrap_or(5),
        bantime.parse::<u32>().unwrap_or(3600),
        findtime.parse::<u32>().unwrap_or(600),
    );
    let jail = |name: &str, svc: &str| {
        if journal_only.contains(&svc) {
            format!("[{name}]\nenabled = true\nbackend = systemd\n\n")
        } else {
            format!("[{name}]\nenabled = true\n\n")
        }
    };
    for svc in services {
        match svc.as_str() {
            "sshd" => out.push_str(&jail("sshd", "sshd")),
            "apache2" => out
                .push_str("[apache-auth]\nenabled = true\n\n[apache-badbots]\nenabled = true\n\n"),
            "nginx" => out.push_str("[nginx-http-auth]\nenabled = true\n\n"),
            "postfix" => out.push_str(&jail("postfix", "postfix")),
            "dovecot" => out.push_str(&jail("dovecot", "dovecot")),
            "vsftpd" => out.push_str("[vsftpd]\nenabled = true\n\n"),
            _ => {}
        }
    }
    out
}

/// Whether `service`'s jail must read the systemd journal because the log
/// file fail2ban defaults to is absent (Debian 12 and later ship no
/// auth.log or mail.log without rsyslog). A jail pointed at a missing file
/// makes fail2ban refuse to start.
fn needs_systemd_backend(service: &str, exists: impl Fn(&str) -> bool) -> bool {
    let logs: &[&str] = match service {
        "sshd" => &["/var/log/auth.log", "/var/log/secure"],
        "postfix" | "dovecot" => &["/var/log/mail.log", "/var/log/maillog"],
        _ => return false,
    };
    !logs.iter().any(|l| exists(l)) && exists("/run/systemd/journal")
}

/// Starting `ignoreip` value: this box's directly connected IPv4 networks plus
/// anything listed in `/etc/linux-defender/fail2ban-ignoreip`. Loopback is
/// always added by [`build_jail_config`].
fn default_ignoreip() -> String {
    let mut parts: Vec<String> = Vec::new();
    let out = super::cmd_output(&["ip", "-o", "-4", "addr", "show", "scope", "global"]);
    for net in parse_connected_networks(&out) {
        if !parts.contains(&net) {
            parts.push(net);
        }
    }
    if let Ok(extra) = std::fs::read_to_string("/etc/linux-defender/fail2ban-ignoreip") {
        for tok in extra.split_whitespace().filter(|t| !t.starts_with('#')) {
            if !parts.iter().any(|p| p == tok) {
                parts.push(tok.to_string());
            }
        }
    }
    parts.join(" ")
}

/// Network addresses (`10.0.1.0/24`) from `ip -o -4 addr` output.
fn parse_connected_networks(ip_output: &str) -> Vec<String> {
    ip_output
        .lines()
        .filter_map(|line| {
            let mut toks = line.split_whitespace();
            toks.find(|t| *t == "inet")?;
            let (addr, prefix) = toks.next()?.split_once('/')?;
            let addr: std::net::Ipv4Addr = addr.parse().ok()?;
            let prefix: u32 = prefix.parse().ok().filter(|p| *p <= 32)?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let net = std::net::Ipv4Addr::from(u32::from(addr) & mask);
            Some(format!("{net}/{prefix}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_config_always_ignores_loopback_and_listed_addresses() {
        let cfg = build_jail_config(
            &["sshd".into()],
            "5",
            "3600",
            "600",
            "10.0.1.0/24 192.168.5.20 bad;value",
            &[],
        );
        assert!(cfg.contains("ignoreip = 127.0.0.1/8 ::1 10.0.1.0/24 192.168.5.20\n"));
        assert!(!cfg.contains("bad;value"));
    }

    #[test]
    fn journal_only_jails_use_the_systemd_backend() {
        let cfg = build_jail_config(
            &["sshd".into(), "postfix".into()],
            "5",
            "3600",
            "600",
            "",
            &["sshd"],
        );
        assert!(cfg.contains("[sshd]\nenabled = true\nbackend = systemd\n"));
        assert!(cfg.contains("[postfix]\nenabled = true\n\n"));
    }

    #[test]
    fn systemd_backend_only_when_the_log_file_is_missing() {
        let debian12 = |p: &str| p == "/run/systemd/journal";
        assert!(needs_systemd_backend("sshd", debian12));
        let rocky = |p: &str| p == "/var/log/secure" || p == "/run/systemd/journal";
        assert!(!needs_systemd_backend("sshd", rocky));
        assert!(!needs_systemd_backend("nginx", debian12));
    }

    #[test]
    fn connected_networks_are_reduced_to_network_addresses() {
        let out = "2: eth0    inet 10.0.1.57/24 brd 10.0.1.255 scope global eth0\\       valid_lft forever\n\
                   3: eth1    inet 172.16.4.9/16 brd 172.16.255.255 scope global eth1\n";
        assert_eq!(
            parse_connected_networks(out),
            vec!["10.0.1.0/24".to_string(), "172.16.0.0/16".to_string()]
        );
    }
}
