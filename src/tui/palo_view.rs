//! Workstation Palo Alto audit tab view.
//!
//! Renders a dedicated two-pane scan interface for PAN-OS firewall auditing on Workstations:
//! - Left Pane (60%): Findings list matching traditional scan findings styling.
//! - Right Pane (40%): Configuration input prompts, audit action triggers, and status diagnostics.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::tui::app::{App, PaloFocus};

/// Render the Palo Alto Workstation tab.
pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_findings_pane(f, cols[0], app);
    render_controls_pane(f, cols[1], app);
}

/// Render the findings list on the left pane.
fn render_findings_pane(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.palo_focus == PaloFocus::Findings && !app.palo_show_finding_detail;
    let title = format!(" Palo Alto Audit Findings ({}) ", app.palo_findings.len());
    let border_style = if is_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    if app.palo_findings.is_empty() {
        let msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No Palo Alto findings loaded.",
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  - [Tab] switch between Findings and Configuration pane",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  - Enter path to exported running-config.xml on the right",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  - Press [Enter] on [Run Palo Audit] or press [s] from anywhere",
                Style::default().fg(Color::Cyan),
            )),
            Line::from(Span::styled(
                "  - Press [e] to export generated PAN-OS CLI remediation script",
                Style::default().fg(Color::Green),
            )),
            Line::from(Span::styled(
                "  - Press [w] to open the guided modal wizard",
                Style::default().fg(Color::Yellow),
            )),
        ];
        f.render_widget(Paragraph::new(msg).block(block), area);
        return;
    }

    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let start = if app.palo_findings_cursor >= visible {
        app.palo_findings_cursor + 1 - visible
    } else {
        0
    };

    let finding_items: Vec<ListItem> = app
        .palo_findings
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, finding)| {
            let is_cursor = is_focused && i == app.palo_findings_cursor;
            let resolved_mark = if finding.resolved { "[OK] " } else { "" };
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

/// Render the configuration inputs, action triggers, and status diagnostics on the right pane.
fn render_controls_pane(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.palo_focus == PaloFocus::Controls && !app.palo_show_finding_detail;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Config XML path
            Constraint::Length(3), // Baseline XML path
            Constraint::Length(3), // Team number
            Constraint::Length(7), // Action Buttons
            Constraint::Min(0),   // Results / Status box
        ])
        .split(area);

    // 1. Config XML path input
    let c0_active = is_focused && app.palo_control_cursor == 0;
    let disp_config = if c0_active {
        format!("{}_", app.palo_config_path)
    } else if app.palo_config_path.is_empty() {
        "  (enter full path to running-config.xml)".to_string()
    } else {
        app.palo_config_path.clone()
    };
    let c0_border = if c0_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    f.render_widget(
        Paragraph::new(disp_config).block(
            Block::default()
                .title(" PAN-OS XML Config File ")
                .borders(Borders::ALL)
                .border_style(c0_border),
        ),
        rows[0],
    );

    // 2. Baseline XML path input
    let c1_active = is_focused && app.palo_control_cursor == 1;
    let disp_baseline = if c1_active {
        format!("{}_", app.palo_baseline_path)
    } else if app.palo_baseline_path.is_empty() {
        "  (optional baseline XML for drift comparison)".to_string()
    } else {
        app.palo_baseline_path.clone()
    };
    let c1_border = if c1_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    f.render_widget(
        Paragraph::new(disp_baseline).block(
            Block::default()
                .title(" Baseline XML (Optional Drift) ")
                .borders(Borders::ALL)
                .border_style(c1_border),
        ),
        rows[1],
    );

    // 3. Team Number input
    let c2_active = is_focused && app.palo_control_cursor == 2;
    let disp_team = if c2_active {
        format!("{}_", app.palo_team)
    } else if app.palo_team.is_empty() {
        "  (optional team 1-20 or 0 for practice)".to_string()
    } else {
        app.palo_team.clone()
    };
    let c2_border = if c2_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Blue)
    };
    f.render_widget(
        Paragraph::new(disp_team).block(
            Block::default()
                .title(" CCDC Team Number ")
                .borders(Borders::ALL)
                .border_style(c2_border),
        ),
        rows[2],
    );

    // 4. Action Buttons Box
    let actions_block = Block::default()
        .title(" Actions ")
        .borders(Borders::ALL)
        .border_style(if is_focused && app.palo_control_cursor >= 3 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Blue)
        });

    let btn_style = |idx: usize| {
        if is_focused && app.palo_control_cursor == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        }
    };

    let b3_mark = if is_focused && app.palo_control_cursor == 3 { "> " } else { "  " };
    let b4_mark = if is_focused && app.palo_control_cursor == 4 { "> " } else { "  " };
    let b5_mark = if is_focused && app.palo_control_cursor == 5 { "> " } else { "  " };

    let action_lines = vec![
        Line::from(vec![
            Span::styled(b3_mark, Style::default().fg(Color::Yellow)),
            Span::styled("[ Run Palo Audit Scan ]", btn_style(3)),
            Span::styled("        hotkey: [s]", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(b4_mark, Style::default().fg(Color::Yellow)),
            Span::styled("[ Export Remediation Script ]", btn_style(4)),
            Span::styled("  hotkey: [e]", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(b5_mark, Style::default().fg(Color::Yellow)),
            Span::styled("[ Open Guided Wizard Modal ]", btn_style(5)),
            Span::styled("   hotkey: [w]", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  [Tab] Switch Pane  [Up/Down] Select Action/Field  [Enter] Execute",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(Paragraph::new(action_lines).block(actions_block), rows[3]);

    // 5. Results & Status Panel
    let crit = app
        .palo_findings
        .iter()
        .filter(|f| f.severity == crate::core::finding::Severity::Critical)
        .count();
    let high = app
        .palo_findings
        .iter()
        .filter(|f| f.severity == crate::core::finding::Severity::High)
        .count();
    let med = app
        .palo_findings
        .iter()
        .filter(|f| f.severity == crate::core::finding::Severity::Medium)
        .count();
    let info = app
        .palo_findings
        .iter()
        .filter(|f| f.severity == crate::core::finding::Severity::Info)
        .count();

    let mut status_lines = Vec::new();
    status_lines.push(Line::from(""));

    if !app.palo_findings.is_empty() {
        status_lines.push(Line::from(vec![
            Span::styled("  Findings: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{} CRITICAL  ", crit),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} HIGH  ", high),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} MED  ", med),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(format!("{} INFO", info), Style::default().fg(Color::DarkGray)),
        ]));
    } else {
        status_lines.push(Line::from(Span::styled(
            "  Audit Status: Idle / Ready to scan",
            Style::default().fg(Color::DarkGray),
        )));
    }

    if let Some((ref msg, is_error)) = app.palo_status_msg {
        status_lines.push(Line::from(""));
        if is_error {
            status_lines.push(Line::from(Span::styled(
                format!("  ERROR: {}", msg),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        } else {
            status_lines.push(Line::from(Span::styled(
                format!("  [OK] {}", msg),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )));
        }
    }

    if let Some(ref path) = app.palo_last_export {
        status_lines.push(Line::from(""));
        status_lines.push(Line::from(Span::styled(
            format!("  Remediation Script: {}", path),
            Style::default().fg(Color::Cyan),
        )));
    }

    f.render_widget(
        Paragraph::new(status_lines)
            .block(
                Block::default()
                    .title(" Audit Diagnostics & Status ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false }),
        rows[4],
    );
}
