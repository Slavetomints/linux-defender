/// TUI-native wizard framework.
///
/// Each wizard is a multi-step modal that stays inside ratatui's alternate
/// screen. No shell escape, no subprocess bash.
pub mod fail2ban;
/// Firewall assessment and hardening wizard.
pub mod firewall;
/// IPv6 static address configuration wizard.
pub mod ipv6;
/// Splunk Universal Forwarder deployment wizard.
pub mod splunk_forwarder;

use std::sync::{Arc, Mutex};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};

use crate::core::BoxType;

/// What the app should do after a wizard processes a keypress.
pub enum WizardAction {
    /// Keep the wizard open.
    Continue,
    /// Close the wizard and return to the Tools tab.
    Close,
}

/// Dispatcher enum over all available wizards.
pub enum ActiveWizard {
    /// fail2ban deployment wizard.
    Fail2Ban(fail2ban::Fail2BanWizard),
    /// Firewall assessment and hardening wizard.
    Firewall(firewall::FirewallWizard),
    /// IPv6 static address configuration wizard.
    Ipv6(ipv6::Ipv6Wizard),
    /// Splunk Universal Forwarder deployment wizard.
    SplunkForwarder(splunk_forwarder::SplunkForwarderWizard),
}

impl ActiveWizard {
    /// Instantiate the wizard at `idx` in `ALL_WIZARDS`.
    pub fn new(idx: usize, box_type: BoxType) -> Option<Self> {
        match idx {
            0 => Some(ActiveWizard::Fail2Ban(fail2ban::Fail2BanWizard::new())),
            1 => Some(ActiveWizard::Firewall(firewall::FirewallWizard::new(box_type))),
            2 => Some(ActiveWizard::Ipv6(ipv6::Ipv6Wizard::new())),
            3 => Some(ActiveWizard::SplunkForwarder(
                splunk_forwarder::SplunkForwarderWizard::new(box_type),
            )),
            _ => None,
        }
    }

    /// Render the wizard as a modal overlay over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        match self {
            ActiveWizard::Fail2Ban(w) => w.render(f, area),
            ActiveWizard::Firewall(w) => w.render(f, area),
            ActiveWizard::Ipv6(w) => w.render(f, area),
            ActiveWizard::SplunkForwarder(w) => w.render(f, area),
        }
    }

    /// Forward a key event to the active wizard.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self {
            ActiveWizard::Fail2Ban(w) => w.handle_key(key),
            ActiveWizard::Firewall(w) => w.handle_key(key),
            ActiveWizard::Ipv6(w) => w.handle_key(key),
            ActiveWizard::SplunkForwarder(w) => w.handle_key(key),
        }
    }
}

// ── Shared rendering helpers ──────────────────────────────────────────────────

/// Clear, draw a bordered modal, and return its inner content area.
pub(crate) fn modal_popup(
    f: &mut Frame,
    area: Rect,
    width_pct: u16,
    height_pct: u16,
    title: &str,
) -> Rect {
    let w = (area.width.saturating_mul(width_pct) / 100)
        .max(40)
        .min(area.width);
    let h = (area.height.saturating_mul(height_pct) / 100)
        .max(10)
        .min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    let popup = Rect::new(x, y, w, h);

    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(title.to_string())
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let inner = block.inner(popup);
    f.render_widget(block, popup);
    inner
}

/// Render a scrollable execution log pane inside `area`.
pub(crate) fn render_exec_log(
    f: &mut Frame,
    area: Rect,
    log: &Arc<Mutex<Vec<String>>>,
    done: bool,
    scroll: usize,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(area);

    let lines = log.lock().unwrap();
    let total = lines.len();
    let visible = rows[0].height as usize;
    let max_scroll = total.saturating_sub(visible);
    let start = scroll.min(max_scroll);

    let items: Vec<ListItem> = lines
        .iter()
        .skip(start)
        .take(visible)
        .map(|line| {
            let style = if line.starts_with("  ✓") || line.starts_with("══") {
                Style::default().fg(Color::Green)
            } else if line.starts_with("  ✗") || line.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if line.starts_with("→") {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(Span::styled(line.clone(), style)))
        })
        .collect();
    drop(lines);

    let (title, border_style) = if done {
        (
            " Output (done) ",
            Style::default().fg(Color::Green),
        )
    } else {
        (
            " Output (running…) ",
            Style::default().fg(Color::Yellow),
        )
    };

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        ),
        rows[0],
    );

    let help = if done {
        " ══ Execution complete — press any key to close ══"
    } else {
        " [↑↓] scroll  [Esc] cancel"
    };
    f.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        rows[1],
    );
}

// ── Shared execution helpers ──────────────────────────────────────────────────

/// Run a command and append its stdout/stderr lines + exit status to `log`.
pub(crate) fn run_cmd_to_log(args: &[&str], log: &Arc<Mutex<Vec<String>>>) {
    if args.is_empty() {
        return;
    }
    match std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
    {
        Ok(out) => {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if !line.trim().is_empty() {
                    log.lock().unwrap().push(format!("  {}", line));
                }
            }
            for line in String::from_utf8_lossy(&out.stderr).lines() {
                if !line.trim().is_empty() {
                    log.lock().unwrap().push(format!("  [err] {}", line));
                }
            }
            let sym = if out.status.success() { "✓" } else { "✗" };
            let code = out.status.code().unwrap_or(-1);
            log.lock().unwrap().push(format!("  {} exit {}", sym, code));
        }
        Err(e) => {
            log.lock().unwrap().push(format!("  ERROR: {}", e));
        }
    }
}

/// Return `true` if a simple shell command exits 0.
pub(crate) fn cmd_succeeds(cmd: &str) -> bool {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return false;
    }
    std::process::Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command silently and return its stdout.
pub(crate) fn cmd_output(args: &[&str]) -> String {
    if args.is_empty() {
        return String::new();
    }
    std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
