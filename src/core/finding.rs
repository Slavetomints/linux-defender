#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::path::PathBuf;

use chrono::{DateTime, Local};
use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Info => "INFO",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Info => Color::Cyan,
        }
    }
}

/// The tool's recommended course of action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Tool recommends removing or deleting this artifact.
    Remove,
    /// Tool recommends disabling (service, cron entry, account, etc.).
    Disable,
    /// Ambiguous — needs operator judgment.
    Investigate,
    /// Looks legitimate; surfaced for visibility only.
    Info,
}

impl Verdict {
    /// Short display label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Remove => "REMOVE",
            Verdict::Disable => "DISABLE",
            Verdict::Investigate => "INVEST.",
            Verdict::Info => "INFO",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Verdict::Remove => Color::Red,
            Verdict::Disable => Color::Yellow,
            Verdict::Investigate => Color::Cyan,
            Verdict::Info => Color::DarkGray,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Delete(PathBuf),
    RemoveImmutable(PathBuf),
    RestartService(String),
    Manual(String),
}

impl Action {
    /// Human-readable description of what executing this action does.
    pub fn description(&self) -> String {
        match self {
            Action::Delete(p) => format!("Quarantine {}", p.display()),
            Action::RemoveImmutable(p) => format!("chattr -i {}", p.display()),
            Action::RestartService(s) => format!("systemctl restart {}", s),
            Action::Manual(s) => format!("Manual: {}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub module: &'static str,
    pub summary: String,
    pub detail: String,
    /// Structured context rows shown in the detail pane (label, value).
    pub context: Vec<(&'static str, String)>,
    /// One-paragraph justification of the verdict.
    pub recommendation: String,
    /// What the tool recommends doing.
    pub verdict: Verdict,
    pub path: Option<PathBuf>,
    pub actions: Vec<Action>,
    pub timestamp: DateTime<Local>,
    /// Whether the operator has already acted on this finding.
    pub resolved: bool,
}

impl Finding {
    pub fn new(
        severity: Severity,
        module: &'static str,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            module,
            summary: summary.into(),
            detail: detail.into(),
            context: Vec::new(),
            recommendation: String::new(),
            verdict: Verdict::Investigate,
            path: None,
            actions: Vec::new(),
            timestamp: Local::now(),
            resolved: false,
        }
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    pub fn with_action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_context(mut self, label: &'static str, value: impl Into<String>) -> Self {
        self.context.push((label, value.into()));
        self
    }

    pub fn with_verdict(mut self, verdict: Verdict, recommendation: impl Into<String>) -> Self {
        self.verdict = verdict;
        self.recommendation = recommendation.into();
        self
    }
}
