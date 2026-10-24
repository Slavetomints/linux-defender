use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::core::{BoxType, Finding, ServiceConfig};

/// Render the dashboard. `nft_config` is the generated ruleset text, if any.
pub fn render(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    box_type: BoxType,
    services: &[(&'static str, u16, bool)],
    findings: &[Finding],
    nft_config: Option<&str>,
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
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .split(top_area);

    render_services(f, cols[0], box_type, services);
    render_findings(f, cols[1], findings);
    render_sysinfo(f, cols[2]);

    if let (Some(area), Some(config)) = (firewall_area, nft_config) {
        render_firewall(f, area, config);
    }
}

fn render_services(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    box_type: BoxType,
    services: &[(&'static str, u16, bool)],
) {
    let items: Vec<ListItem> = services
        .iter()
        .map(|(name, port, up)| {
            let (symbol, color) = if *up {
                ("●", Color::Green)
            } else {
                ("✖", Color::Red)
            };
            let line = Line::from(vec![
                Span::styled(symbol, Style::default().fg(color)),
                Span::raw(format!(" {:<14} :{}", name, port)),
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

fn render_findings(f: &mut Frame, area: ratatui::layout::Rect, findings: &[Finding]) {
    let recent: Vec<&Finding> = findings.iter().rev().take(8).collect();
    let items: Vec<ListItem> = recent
        .iter()
        .map(|finding| {
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
            ListItem::new(line)
        })
        .collect();

    let title = format!(" Findings ({}) ", findings.len());
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

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

fn render_firewall(f: &mut Frame, area: ratatui::layout::Rect, config: &str) {
    let preview_lines = 10usize;
    let lines: Vec<ratatui::text::Line> = config
        .lines()
        .take(preview_lines)
        .map(|l| ratatui::text::Line::from(Span::styled(
            l.to_string(),
            Style::default().fg(Color::Cyan),
        )))
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
            format!("  … {} more lines — see /etc/nftables.conf for full ruleset", more),
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(
        Paragraph::new(display),
        inner,
    );
}

/// Build the service status vec from a BoxType's ServiceConfig list.
pub fn poll_services(configs: &'static [ServiceConfig]) -> Vec<(&'static str, u16, bool)> {
    configs
        .iter()
        .map(|s| (s.name, s.port, s.is_up()))
        .collect()
}
