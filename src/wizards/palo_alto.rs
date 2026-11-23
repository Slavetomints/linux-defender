/// Palo Alto PAN-OS XML configuration audit wizard.
///
/// Steps: enter XML path → optional baseline path → optional team number →
///        run audit → review findings → export remediation script.
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::tools::palo_alto::{
    PaloAltoFinding, RemediationScript, XmlNode, audit_config, diff_baseline,
};

use super::WizardAction;

/// Fixed output directory for Palo Alto audit artifacts.
pub const PA_AUDIT_DIR: &str = "/etc/defender/palo-alto";

/// Wizard progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Step 1: enter path to PAN-OS running-config.xml file.
    ConfigPath,
    /// Step 2: optional baseline XML for drift comparison.
    BaselinePath,
    /// Step 3: optional team number for public subnet calculation.
    TeamNumber,
    /// Step 4: running the audit engine and displaying findings.
    ReviewFindings,
    /// Step 5: export remediation script complete.
    ExportDone,
}

/// Which form field has focus in steps 1-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormField {
    /// XML config file path.
    ConfigPath,
    /// Baseline XML path (optional).
    BaselinePath,
    /// Team number (optional).
    TeamNumber,
}

impl FormField {
    /// All form fields in display order.
    const ALL: &'static [FormField] = &[
        FormField::ConfigPath,
        FormField::BaselinePath,
        FormField::TeamNumber,
    ];

    /// Label for display.
    fn label(self) -> &'static str {
        match self {
            FormField::ConfigPath => "PAN-OS XML Config File (full path)",
            FormField::BaselinePath => "Baseline XML for Drift Comparison (optional, full path)",
            FormField::TeamNumber => "CCDC Team Number (1-20, or 0 for practice — optional)",
        }
    }

    /// Index of the field.
    fn idx(self) -> usize {
        match self {
            FormField::ConfigPath => 0,
            FormField::BaselinePath => 1,
            FormField::TeamNumber => 2,
        }
    }
}

/// Palo Alto PAN-OS XML audit wizard state.
pub struct PaloAltoWizard {
    /// Current wizard step.
    step: Step,
    /// Content of each form field.
    fields: [String; 3],
    /// Currently focused form field index.
    field_cursor: usize,
    /// Findings produced by the audit engine.
    findings: Vec<PaloAltoFinding>,
    /// Scroll position within the findings list.
    findings_scroll: usize,
    /// Path where the remediation script was written.
    export_path: String,
    /// Error message to display, if any.
    error_msg: Option<String>,
}

impl PaloAltoWizard {
    /// Create a new Palo Alto audit wizard.
    pub fn new() -> Self {
        Self {
            step: Step::ConfigPath,
            fields: [String::new(), String::new(), String::new()],
            field_cursor: 0,
            findings: Vec::new(),
            findings_scroll: 0,
            export_path: String::new(),
            error_msg: None,
        }
    }
}

impl Default for PaloAltoWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl PaloAltoWizard {
    /// Render the wizard modal over `area`.
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let inner = super::modal_popup(f, area, 80, 85, " Palo Alto PAN-OS XML Audit ");
        match self.step {
            Step::ConfigPath | Step::BaselinePath | Step::TeamNumber => {
                self.render_form(f, inner);
            }
            Step::ReviewFindings => self.render_findings(f, inner),
            Step::ExportDone => self.render_export_done(f, inner),
        }
    }

    /// Render the multi-field input form (steps 1-3 on one screen).
    fn render_form(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // config path
                Constraint::Length(3), // baseline path
                Constraint::Length(3), // team number
                Constraint::Min(0),   // instructions / error
                Constraint::Length(2), // keybinds
            ])
            .split(area);

        for field in FormField::ALL {
            let idx = field.idx();
            let active = idx == self.field_cursor;
            let val = &self.fields[idx];
            let disp = if active {
                format!("{}_", val)
            } else {
                val.to_string()
            };
            f.render_widget(
                Paragraph::new(disp).block(
                    Block::default()
                        .title(field.label())
                        .borders(Borders::ALL)
                        .border_style(if active {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Blue)
                        }),
                ),
                rows[idx],
            );
        }

        // Instructions / error area
        let info_lines = if let Some(ref err) = self.error_msg {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  ERROR: {}", err),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Fix the path and press [Enter] to retry.",
                    Style::default().fg(Color::Yellow),
                )),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Enter the full path to the exported PAN-OS running-config.xml.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Baseline path is optional — leave blank to skip drift comparison.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Team number is optional — used only for public subnet calculation.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  Remediation script will be written to: {}/",
                        PA_AUDIT_DIR
                    ),
                    Style::default().fg(Color::Cyan),
                )),
            ]
        };
        f.render_widget(
            Paragraph::new(info_lines).block(
                Block::default()
                    .title(" Palo Alto XML Audit — Configuration ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            rows[3],
        );

        f.render_widget(
            Paragraph::new(
                " [Tab/↑↓] switch field  [type] enter path  [Backspace] delete  [Enter] run audit  [Esc] cancel",
            )
            .style(Style::default().fg(Color::DarkGray)),
            rows[4],
        );
    }

    /// Render the findings review screen.
    fn render_findings(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // summary bar
                Constraint::Min(0),   // findings list
                Constraint::Length(2), // keybinds
            ])
            .split(area);

        // Summary bar
        let crit = self
            .findings
            .iter()
            .filter(|f| f.severity == crate::core::finding::Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == crate::core::finding::Severity::High)
            .count();
        let med = self
            .findings
            .iter()
            .filter(|f| f.severity == crate::core::finding::Severity::Medium)
            .count();
        let info = self
            .findings
            .iter()
            .filter(|f| f.severity == crate::core::finding::Severity::Info)
            .count();

        let summary = if self.findings.is_empty() {
            Line::from(Span::styled(
                " ✓ CLEAN — no findings detected. Configuration passes all audit checks.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))
        } else {
            Line::from(vec![
                Span::styled(
                    format!(" {} findings: ", self.findings.len()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} CRITICAL  ", crit),
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} HIGH  ", high),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("{} MEDIUM  ", med),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(format!("{} INFO", info), Style::default().fg(Color::DarkGray)),
            ])
        };
        f.render_widget(
            Paragraph::new(summary).block(
                Block::default()
                    .title(" PAN-OS Audit Results ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            ),
            rows[0],
        );

        // Findings list (scrollable)
        let visible_height = rows[1].height.saturating_sub(2) as usize;
        let total_items = self.findings.len();
        let max_scroll = total_items.saturating_sub(visible_height / 3); // ~3 lines per finding
        let scroll = self.findings_scroll.min(max_scroll);

        let items: Vec<ListItem> = self
            .findings
            .iter()
            .enumerate()
            .skip(scroll)
            .map(|(idx, finding)| {
                let sev_color = match finding.severity {
                    crate::core::finding::Severity::Critical => Color::Red,
                    crate::core::finding::Severity::High => Color::Yellow,
                    crate::core::finding::Severity::Medium => Color::Cyan,
                    crate::core::finding::Severity::Info => Color::DarkGray,
                };
                let sev_label = match finding.severity {
                    crate::core::finding::Severity::Critical => "CRIT",
                    crate::core::finding::Severity::High => "HIGH",
                    crate::core::finding::Severity::Medium => "MED ",
                    crate::core::finding::Severity::Info => "INFO",
                };

                let mut lines = vec![Line::from(vec![
                    Span::styled(
                        format!(" [{:02}] ", idx + 1),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("[{}] ", sev_label),
                        Style::default()
                            .fg(sev_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{}: {}", finding.check_id, finding.target),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ])];
                // Truncate message to avoid very long lines
                let msg = if finding.message.len() > 120 {
                    format!("{}…", &finding.message[..120])
                } else {
                    finding.message.clone()
                };
                lines.push(Line::from(Span::styled(
                    format!("      {}", msg),
                    Style::default().fg(Color::DarkGray),
                )));
                if !finding.remediation.is_empty() {
                    lines.push(Line::from(Span::styled(
                        format!("      ⤷ {}", finding.remediation.join("; ")),
                        Style::default().fg(Color::Green),
                    )));
                }
                ListItem::new(lines)
            })
            .collect();

        let scroll_tag = if total_items > 0 {
            format!(
                " Findings [{}-{}/{}] ",
                scroll + 1,
                (scroll + visible_height / 3).min(total_items),
                total_items,
            )
        } else {
            " Findings ".to_string()
        };

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(scroll_tag)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            ),
            rows[1],
        );

        f.render_widget(
            Paragraph::new(
                " [↑↓] scroll  [E] export remediation script  [Esc] close",
            )
            .style(Style::default().fg(Color::Yellow)),
            rows[2],
        );
    }

    /// Render the export completion screen.
    fn render_export_done(&self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(2)])
            .split(area);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                " ✓ Remediation script exported successfully!",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("   Written to: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    self.export_path.clone(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "   The script is formatted for copy-paste into a PAN-OS SSH session.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "   It enters configure mode, applies all fixes, commits, then exits.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("   Total findings: {}", self.findings.len()),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "   Remediation commands: {}",
                    self.findings
                        .iter()
                        .map(|f| f.remediation.len())
                        .sum::<usize>()
                ),
                Style::default(),
            )),
        ];

        f.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .title(" Export Complete ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green)),
                )
                .wrap(Wrap { trim: false }),
            rows[0],
        );

        f.render_widget(
            Paragraph::new(" Press any key to close")
                .style(Style::default().fg(Color::DarkGray)),
            rows[1],
        );
    }

    /// Handle a keypress and return whether the wizard should close.
    pub fn handle_key(&mut self, key: KeyCode) -> WizardAction {
        match self.step {
            Step::ConfigPath | Step::BaselinePath | Step::TeamNumber => {
                self.handle_form_key(key)
            }
            Step::ReviewFindings => self.handle_findings_key(key),
            Step::ExportDone => {
                // Any key closes the wizard.
                WizardAction::Close
            }
        }
    }

    /// Handle keypress in the form input steps.
    fn handle_form_key(&mut self, key: KeyCode) -> WizardAction {
        match key {
            KeyCode::Tab | KeyCode::Down => {
                self.field_cursor = (self.field_cursor + 1) % FormField::ALL.len();
                self.step = match self.field_cursor {
                    0 => Step::ConfigPath,
                    1 => Step::BaselinePath,
                    _ => Step::TeamNumber,
                };
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.field_cursor = if self.field_cursor == 0 {
                    FormField::ALL.len() - 1
                } else {
                    self.field_cursor - 1
                };
                self.step = match self.field_cursor {
                    0 => Step::ConfigPath,
                    1 => Step::BaselinePath,
                    _ => Step::TeamNumber,
                };
            }
            KeyCode::Char(c) => {
                if self.field_cursor == 2 {
                    // Team number: digits only
                    if c.is_ascii_digit() && self.fields[2].len() < 2 {
                        self.fields[2].push(c);
                    }
                } else {
                    // Path fields: allow printable characters
                    if self.fields[self.field_cursor].len() < 512 {
                        self.fields[self.field_cursor].push(c);
                    }
                }
                self.error_msg = None;
            }
            KeyCode::Backspace => {
                self.fields[self.field_cursor].pop();
                self.error_msg = None;
            }
            KeyCode::Enter => {
                self.run_audit();
            }
            KeyCode::Esc => return WizardAction::Close,
            _ => {}
        }
        WizardAction::Continue
    }

    /// Handle keypress in the findings review screen.
    fn handle_findings_key(&mut self, key: KeyCode) -> WizardAction {
        match key {
            KeyCode::Up => {
                self.findings_scroll = self.findings_scroll.saturating_sub(1);
            }
            KeyCode::Down => {
                self.findings_scroll += 1;
            }
            KeyCode::PageUp => {
                self.findings_scroll = self.findings_scroll.saturating_sub(5);
            }
            KeyCode::PageDown => {
                self.findings_scroll += 5;
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                self.export_remediation();
            }
            KeyCode::Esc => return WizardAction::Close,
            _ => {}
        }
        WizardAction::Continue
    }

    /// Parse the XML and run the audit engine.
    fn run_audit(&mut self) {
        let config_path = self.fields[0].trim().to_string();
        if config_path.is_empty() {
            self.error_msg = Some("Config file path is required.".to_string());
            return;
        }

        let xml_content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                self.error_msg = Some(format!("Cannot read '{}': {}", config_path, e));
                return;
            }
        };

        let root = match XmlNode::parse(&xml_content) {
            Ok(r) => r,
            Err(e) => {
                self.error_msg = Some(format!("XML parse error: {}", e));
                return;
            }
        };

        let team: Option<u8> = if self.fields[2].trim().is_empty() {
            None
        } else {
            self.fields[2].trim().parse().ok()
        };

        let mut findings = audit_config(&root, team);

        // Optional baseline diff
        let baseline_path = self.fields[1].trim().to_string();
        if !baseline_path.is_empty() {
            match std::fs::read_to_string(&baseline_path) {
                Ok(base_content) => match XmlNode::parse(&base_content) {
                    Ok(base_root) => {
                        let diff_findings = diff_baseline(&root, &base_root);
                        findings.extend(diff_findings);
                    }
                    Err(e) => {
                        self.error_msg = Some(format!("Baseline XML parse error: {}", e));
                        return;
                    }
                },
                Err(e) => {
                    self.error_msg = Some(format!("Cannot read baseline '{}': {}", baseline_path, e));
                    return;
                }
            }
        }

        self.findings = findings;
        self.findings_scroll = 0;
        self.error_msg = None;
        self.step = Step::ReviewFindings;
    }

    /// Export the remediation script to the well-known output directory.
    fn export_remediation(&mut self) {
        // Create output directory
        if let Err(e) = std::fs::create_dir_all(PA_AUDIT_DIR) {
            self.error_msg = Some(format!("Cannot create {}: {}", PA_AUDIT_DIR, e));
            return;
        }

        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let script_path = format!("{}/pa_remediation_{}.txt", PA_AUDIT_DIR, ts);

        let mut script = RemediationScript::new();
        for f in &self.findings {
            for cmd in &f.remediation {
                script.add(cmd.clone());
            }
        }
        let rendered = script.render();

        match std::fs::write(&script_path, &rendered) {
            Ok(_) => {
                self.export_path = script_path;
                self.step = Step::ExportDone;
            }
            Err(e) => {
                self.error_msg = Some(format!("Failed to write {}: {}", script_path, e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wizard_defaults() {
        let wiz = PaloAltoWizard::new();
        assert_eq!(wiz.step, Step::ConfigPath);
        assert_eq!(wiz.field_cursor, 0);
        assert!(wiz.findings.is_empty());
        assert_eq!(PA_AUDIT_DIR, "/etc/defender/palo-alto");
    }

    #[test]
    fn form_field_tab_cycling() {
        let mut wiz = PaloAltoWizard::new();
        assert_eq!(wiz.field_cursor, 0);

        wiz.handle_key(KeyCode::Tab);
        assert_eq!(wiz.field_cursor, 1);
        assert_eq!(wiz.step, Step::BaselinePath);

        wiz.handle_key(KeyCode::Tab);
        assert_eq!(wiz.field_cursor, 2);
        assert_eq!(wiz.step, Step::TeamNumber);

        wiz.handle_key(KeyCode::Tab);
        assert_eq!(wiz.field_cursor, 0);
        assert_eq!(wiz.step, Step::ConfigPath);

        wiz.handle_key(KeyCode::BackTab);
        assert_eq!(wiz.field_cursor, 2);
    }

    #[test]
    fn audit_empty_path_sets_error() {
        let mut wiz = PaloAltoWizard::new();
        wiz.handle_key(KeyCode::Enter);
        assert!(wiz.error_msg.is_some());
        assert_eq!(wiz.step, Step::ConfigPath);
    }
}
