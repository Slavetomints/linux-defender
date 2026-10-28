use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::core::{BoxType, Finding, Severity};
use crate::score_check::ServiceHistory;

/// One logged-in user session from `who`.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub username: String,
    pub tty: String,
    pub login_time: String,
    pub source: String,
    /// Seconds since the user logged in (0 if unknown).
    pub duration_secs: u64,
    /// True if non-root OR session older than 60 seconds.
    pub flagged: bool,
}

/// Render the dashboard.
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    box_type: BoxType,
    services: &[ServiceHistory],
    findings: &[Finding],
    nft_config: Option<&str>,
    sessions: &[SessionInfo],
    auth_events: &[String],
    authorized_users: &[String],
) {
    let (top_area, firewall_area) = if nft_config.is_some() {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(14)])
            .split(area);
        (rows[0], Some(rows[1]))
    } else {
        (area, None)
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(44),
            Constraint::Percentage(28),
        ])
        .split(top_area);

    // Left column: services (top) + sessions (bottom)
    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[0]);

    // Right column: sysinfo (top) + auth events (bottom)
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(cols[2]);

    render_services(f, left_rows[0], box_type, services);
    render_sessions(f, left_rows[1], sessions, authorized_users);
    render_findings(f, cols[1], findings);
    render_sysinfo(f, right_rows[0]);
    render_auth_events(f, right_rows[1], auth_events);

    if let (Some(area), Some(config)) = (firewall_area, nft_config) {
        render_firewall(f, area, config);
    }
}

/// Render the service health list panel.
fn render_services(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    box_type: BoxType,
    services: &[ServiceHistory],
) {
    let items: Vec<ListItem> = services
        .iter()
        .map(|h| {
            let up = h.is_up();
            let (symbol, color) = if up {
                ("●", Color::Green)
            } else {
                ("✖", Color::Red)
            };
            let uptime = h
                .uptime_fraction()
                .map(|f| format!(" {:>3.0}%", f * 100.0))
                .unwrap_or_else(|| "  -- ".into());
            let latency = h
                .avg_latency_ms()
                .map(|ms| format!(" {:>4}ms", ms))
                .unwrap_or_else(|| "   ---".into());
            let line = Line::from(vec![
                Span::styled(symbol, Style::default().fg(color)),
                Span::raw(format!(" {:<14} :{:<6}", h.check.name, h.check.port)),
                Span::styled(
                    uptime,
                    Style::default().fg(if up { Color::Green } else { Color::Red }),
                ),
                Span::styled(latency, Style::default().fg(Color::DarkGray)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let title = format!(" Scored Services — {} ", box_type.label());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

/// Render the active login sessions panel.
fn render_sessions(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    sessions: &[SessionInfo],
    _authorized_users: &[String],
) {
    let any_flagged = sessions.iter().any(|s| s.flagged);
    let border_color = if any_flagged { Color::Red } else { Color::Blue };
    let title = format!(" Active Sessions ({}) ", sessions.len());

    let items: Vec<ListItem> = if sessions.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no active sessions",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        sessions
            .iter()
            .map(|s| {
                let dur = format_duration(s.duration_secs);
                let src = if s.source.is_empty() {
                    "local".to_string()
                } else {
                    s.source.clone()
                };
                let flag = if s.flagged { "⚠ " } else { "  " };
                let flag_color = if s.flagged { Color::Red } else { Color::Green };
                let line = Line::from(vec![
                    Span::styled(
                        flag,
                        Style::default().fg(flag_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<10}", s.username),
                        Style::default().fg(if s.flagged { Color::Red } else { Color::White }),
                    ),
                    Span::styled(
                        format!(" {:<8}", s.tty),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!(" {:>6}", dur),
                        Style::default().fg(if s.duration_secs > 15 {
                            Color::Yellow
                        } else {
                            Color::White
                        }),
                    ),
                    Span::styled(format!(" {}", src), Style::default().fg(Color::Cyan)),
                ]);
                ListItem::new(line)
            })
            .collect()
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

/// Render the findings summary panel with severity counts.
fn render_findings(f: &mut Frame, area: ratatui::layout::Rect, findings: &[Finding]) {
    let crit = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let med = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();

    let recent: Vec<&Finding> = findings.iter().rev().take(20).collect();

    let mut items: Vec<ListItem> = Vec::new();

    // Severity summary header
    if !findings.is_empty() {
        let summary = Line::from(vec![
            Span::styled(
                format!(" ✖{} ", crit),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("▲{} ", high), Style::default().fg(Color::LightRed)),
            Span::styled(format!("◆{} ", med), Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("({} total)", findings.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        items.push(ListItem::new(summary));
    }

    for finding in recent.iter() {
        let resolved_mark = if finding.resolved { "✓ " } else { "" };
        let line = Line::from(vec![
            Span::styled(
                format!("[{}]", finding.severity.label()),
                Style::default()
                    .fg(finding.severity.color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{:<7}", finding.verdict.label()),
                Style::default()
                    .fg(finding.verdict.color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {}{}", resolved_mark, finding.summary)),
        ]);
        items.push(ListItem::new(line));
    }

    let border_color = if crit > 0 {
        Color::Red
    } else if high > 0 {
        Color::LightRed
    } else {
        Color::Blue
    };

    let title = format!(" Findings ({}) ", findings.len());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    if items.is_empty() {
        let p = Paragraph::new("No findings yet — run a scan with [3]")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, area);
    } else {
        let list = List::new(items).block(block);
        f.render_widget(list, area);
    }
}

/// Render the system information panel (hostname, uptime, kernel).
fn render_sysinfo(f: &mut Frame, area: ratatui::layout::Rect) {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| {
            let d = (secs / 86400.0) as u64;
            let h = ((secs % 86400.0) / 3600.0) as u64;
            let m = ((secs % 3600.0) / 60.0) as u64;
            format!("{}d {}h {}m", d, h, m)
        })
        .unwrap_or_else(|| "unknown".into());

    let load = std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_else(|_| "? ? ?".into())
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join("  ");

    let lines = vec![
        Line::from(vec![
            Span::styled("host  ", Style::default().fg(Color::DarkGray)),
            Span::raw(&hostname),
        ]),
        Line::from(vec![
            Span::styled("up    ", Style::default().fg(Color::DarkGray)),
            Span::raw(&uptime),
        ]),
        Line::from(vec![
            Span::styled("load  ", Style::default().fg(Color::DarkGray)),
            Span::raw(&load),
        ]),
    ];

    let block = Block::default()
        .title(" System ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

/// Render the recent authentication events panel.
fn render_auth_events(f: &mut Frame, area: ratatui::layout::Rect, events: &[String]) {
    let items: Vec<ListItem> = if events.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no recent auth events",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        events
            .iter()
            .map(|line| {
                let is_fail = line.contains("Failed")
                    || line.contains("Invalid")
                    || line.contains("BREAK-IN");
                let is_ok = line.contains("Accepted") || line.contains("session opened");
                let color = if is_fail {
                    Color::Red
                } else if is_ok {
                    Color::Green
                } else {
                    Color::White
                };
                ListItem::new(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(color),
                )))
            })
            .collect()
    };

    let has_failures = events
        .iter()
        .any(|l| l.contains("Failed") || l.contains("Invalid"));
    let border_color = if has_failures {
        Color::Red
    } else {
        Color::Blue
    };

    let block = Block::default()
        .title(" Auth Events ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

/// Render a preview of the active firewall (nftables) ruleset.
fn render_firewall(f: &mut Frame, area: ratatui::layout::Rect, config: &str) {
    let preview_lines = 10usize;
    let lines: Vec<ratatui::text::Line> = config
        .lines()
        .take(preview_lines)
        .map(|l| {
            ratatui::text::Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(Color::Cyan),
            ))
        })
        .collect();

    let total = config.lines().count();
    let more = total.saturating_sub(preview_lines);
    let title = format!(
        " Firewall config — nftbuild applied ({} lines) — /etc/nftables.conf ",
        total
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut display = lines;
    if more > 0 {
        display.push(ratatui::text::Line::from(Span::styled(
            format!(
                "  … {} more lines — see /etc/nftables.conf for full ruleset",
                more
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(Paragraph::new(display), inner);
}

/// Read currently logged-in sessions from `who`.
pub fn poll_sessions(authorized_users: &[String]) -> Vec<SessionInfo> {
    let Ok(out) = Command::new("who").output() else {
        return vec![];
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    stdout
        .lines()
        .filter_map(|line| parse_who_line(line, now_secs, authorized_users))
        .collect()
}

/// Parse one line of `who` output into a `SessionInfo`, returning `None` on parse failure.
fn parse_who_line(line: &str, now_secs: u64, authorized_users: &[String]) -> Option<SessionInfo> {
    // Format: "user  tty  YYYY-MM-DD HH:MM  (source)"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let username = parts[0].to_string();
    let tty = parts[1].to_string();
    let date_str = parts[2];
    let time_str = parts[3];
    let source = parts
        .get(4)
        .map(|s| s.trim_matches(|c| c == '(' || c == ')').to_string())
        .unwrap_or_default();

    let login_str = format!("{} {}", date_str, time_str);
    let duration_secs = login_timestamp_secs(&login_str)
        .map(|ts| now_secs.saturating_sub(ts))
        .unwrap_or(0);

    // Authorized users (root by default, configurable) are only flagged if their session
    // exceeds 15 seconds. Any other user is always flagged — they should not be logged in.
    let authorized = authorized_users.contains(&username);
    let flagged = if authorized { duration_secs > 15 } else { true };

    Some(SessionInfo {
        username,
        tty,
        login_time: login_str,
        source,
        duration_secs,
        flagged,
    })
}

/// Shell out to `date -d` to parse a login datetime into a Unix timestamp.
fn login_timestamp_secs(datetime: &str) -> Option<u64> {
    let out = Command::new("date")
        .args(["-d", datetime, "+%s"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Read the last N relevant auth log lines from auth.log or secure.
pub fn poll_auth_events() -> Vec<String> {
    let log_path = ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied();
    let Some(path) = log_path else { return vec![] };

    let Ok(contents) = std::fs::read_to_string(path) else {
        return vec![];
    };

    let keywords = [
        "Failed",
        "Accepted",
        "Invalid user",
        "session opened",
        "session closed",
        "BREAK-IN",
    ];

    let matching: Vec<&str> = contents
        .lines()
        .filter(|l| keywords.iter().any(|kw| l.contains(kw)))
        .collect();

    matching
        .iter()
        .rev()
        .take(10)
        .map(|l| {
            // Strip syslog prefix: "Jan 15 14:30:01 hostname sshd[123]: ..." → "sshd[123]: ..."
            let trimmed = l.splitn(5, ' ').nth(4).unwrap_or(l);
            trimmed.to_string()
        })
        .rev()
        .collect()
}

/// Format a duration in seconds as a human-readable string (e.g. `"2h 5m"`).
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}
