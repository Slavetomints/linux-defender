/// Renders the Tools tab — downloadable binaries and TUI-native wizards.
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::tools::catalog::{ALL_TOOLS, ALL_WIZARDS};
use crate::tools::downloader::{is_installed, stored_sha256};

/// Which item the cursor is on in the Tools tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedTool {
    /// Index into `ALL_TOOLS`.
    Binary(usize),
    /// Index into `ALL_WIZARDS`.
    Wizard(usize),
}

impl SelectedTool {
    /// Total navigable rows: binaries + wizards.
    pub fn total() -> usize {
        ALL_TOOLS.len() + ALL_WIZARDS.len()
    }

    /// Build from a flat cursor position (binaries first, then wizards).
    pub fn from_cursor(cursor: usize) -> Self {
        if cursor < ALL_TOOLS.len() {
            SelectedTool::Binary(cursor)
        } else {
            SelectedTool::Wizard(cursor - ALL_TOOLS.len())
        }
    }

    /// Flat cursor position.
    pub fn to_cursor(self) -> usize {
        match self {
            SelectedTool::Binary(i) => i,
            SelectedTool::Wizard(i) => ALL_TOOLS.len() + i,
        }
    }
}

/// Render the tools tab into `area`.
pub fn render(
    f: &mut Frame,
    area: Rect,
    selected: SelectedTool,
    download_status: Option<&str>,
    nft_config: Option<&str>,
) {
    // When a firewall config exists, split horizontally: tool list on left, config on right.
    let (list_area, config_area) = if nft_config.is_some() {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(area);
        (cols[0], Some(cols[1]))
    } else {
        (area, None)
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(list_area);

    render_tool_list(f, rows[0], selected, download_status);
    render_help(f, rows[1], selected);

    if let (Some(cfg_area), Some(cfg)) = (config_area, nft_config) {
        render_nft_config(f, cfg_area, cfg);
    }
}

/// Render the list of downloadable tools with download-status annotation.
fn render_tool_list(
    f: &mut Frame,
    area: Rect,
    selected: SelectedTool,
    download_status: Option<&str>,
) {
    let mut items: Vec<ListItem> = Vec::new();

    // ── Binary tools ──────────────────────────────────────────────────────────
    items.push(ListItem::new(Line::from(Span::styled(
        " ── Downloadable Binaries ───────────────────────────────",
        Style::default().fg(Color::DarkGray),
    ))));

    for (idx, tool) in ALL_TOOLS.iter().enumerate() {
        let is_sel = selected == SelectedTool::Binary(idx);
        let installed = is_installed(tool.name);
        let status_sym = if installed { "✓" } else { "✗" };
        let status_color = if installed { Color::Green } else { Color::Red };

        let stored = stored_sha256(tool.name).unwrap_or_else(|| "—".into());
        let hash_short = if stored == "—" {
            stored.clone()
        } else {
            stored.chars().take(12).collect::<String>() + "…"
        };
        let hash_ok = tool.known_sha256.is_some_and(|k| stored == k);
        let hash_tag = if stored == "—" {
            Span::styled(" hash:—", Style::default().fg(Color::DarkGray))
        } else if hash_ok {
            Span::styled(" hash:ok", Style::default().fg(Color::Green))
        } else {
            Span::styled(
                " hash:MISMATCH",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        };

        if let Some(status) = download_status {
            if status.starts_with(tool.name) {
                let line = Line::from(vec![
                    Span::styled(
                        " […] ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<12}", tool.name),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("  {}", status), Style::default().fg(Color::Yellow)),
                ]);
                items.push(maybe_highlight(ListItem::new(line), is_sel));
                continue;
            }
        }

        let base = if is_sel {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let line = Line::from(vec![
            Span::styled(
                format!(" [{}] ", status_sym),
                base.fg(status_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<14}", tool.name),
                base.add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("sha256:{}", hash_short), base.fg(Color::DarkGray)),
            hash_tag,
            Span::styled(format!("  {}", tool.description), base.fg(Color::DarkGray)),
        ]);
        items.push(maybe_highlight(ListItem::new(line), is_sel));
    }

    // ── TUI wizards ───────────────────────────────────────────────────────────
    items.push(ListItem::new(Line::from(Span::styled(
        " ── Interactive Wizards ─────────────────────────────────",
        Style::default().fg(Color::DarkGray),
    ))));

    for (idx, wizard) in ALL_WIZARDS.iter().enumerate() {
        let is_sel = selected == SelectedTool::Wizard(idx);
        let base = if is_sel {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let line = Line::from(vec![
            Span::styled(" [wiz] ", base.fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{:<24}", wizard.name),
                base.add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}", wizard.description),
                base.fg(Color::DarkGray),
            ),
        ]);
        items.push(maybe_highlight(ListItem::new(line), is_sel));
    }

    let block = Block::default()
        .title(" Tools ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    f.render_widget(List::new(items).block(block), area);
}

/// Apply a highlight background to `item` if `selected` is true.
fn maybe_highlight(item: ListItem, selected: bool) -> ListItem {
    if selected {
        item.style(Style::default().bg(Color::DarkGray))
    } else {
        item
    }
}

/// Render contextual key-binding help for the currently selected tool.
fn render_help(f: &mut Frame, area: Rect, selected: SelectedTool) {
    let lines = match selected {
        SelectedTool::Binary(_) => vec![Line::from(vec![
            Span::styled(
                " [↑↓] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("navigate   ", Style::default().fg(Color::White)),
            Span::styled(
                "[d] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("download/update   ", Style::default().fg(Color::White)),
            Span::styled(
                "[r] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "run nftbuild  ⚠ APPLIES FIREWALL RULES IMMEDIATELY",
                Style::default().fg(Color::Red),
            ),
        ])],
        SelectedTool::Wizard(_) => vec![Line::from(vec![
            Span::styled(
                " [↑↓] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("navigate   ", Style::default().fg(Color::White)),
            Span::styled(
                "[r] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "open wizard (interactive, stays in TUI)",
                Style::default().fg(Color::White),
            ),
        ])],
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Render the applied nftables ruleset in the right pane.
fn render_nft_config(f: &mut Frame, area: Rect, config: &str) {
    let lines: Vec<Line> = config
        .lines()
        .map(|l| {
            let color = if l.trim_start().starts_with('#') {
                Color::DarkGray
            } else if l.contains("drop") || l.contains("reject") {
                Color::Red
            } else if l.contains("accept") {
                Color::Green
            } else if l.contains("table") || l.contains("chain") {
                Color::Cyan
            } else {
                Color::White
            };
            Line::from(Span::styled(l.to_string(), Style::default().fg(color)))
        })
        .collect();

    let block = Block::default()
        .title(" Firewall Ruleset (active) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    f.render_widget(Paragraph::new(lines).block(block), area);
}
