use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};

use ratatui::style::{Color, Style};

pub const MAX_LINES: usize = 500;

#[derive(Debug, Clone)]
pub struct LogLine {
    pub text: String,
    pub style: Style,
}

/// Source path candidates — first existing path wins.
#[derive(Debug, Clone)]
pub struct PaneSource {
    pub paths: Vec<String>,
    pub filter: Option<String>,
}

pub struct LogPane {
    pub title: &'static str,
    pub source: PaneSource,
    pub lines: VecDeque<LogLine>,
    pub scroll: usize,
    pub paused: bool,
    pub active_path: Option<String>,
    pub rx: Receiver<String>,
    pub tx: Sender<String>,
}

impl LogPane {
    pub fn new(title: &'static str, source: PaneSource) -> Self {
        let (tx, rx) = mpsc::channel();
        let active_path = source
            .paths
            .iter()
            .find(|p| std::path::Path::new(p.as_str()).exists())
            .cloned();
        Self {
            title,
            source,
            lines: VecDeque::new(),
            scroll: 0,
            paused: false,
            active_path,
            rx,
            tx,
        }
    }

    pub fn drain(&mut self) {
        if self.paused {
            return;
        }
        while let Ok(raw) = self.rx.try_recv() {
            if let Some(f) = &self.source.filter {
                if !raw.to_lowercase().contains(f.as_str()) {
                    continue;
                }
            }
            let style = classify_line(&raw);
            self.lines.push_back(LogLine { text: raw, style });
            if self.lines.len() > MAX_LINES {
                self.lines.pop_front();
                if self.scroll > 0 {
                    self.scroll = self.scroll.saturating_sub(1);
                }
            }
        }
    }

    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        if self.scroll + 1 < self.lines.len() {
            self.scroll += 1;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll = self.lines.len().saturating_sub(1);
    }
}

fn classify_line(line: &str) -> Style {
    let l = line.to_lowercase();
    if l.contains("error") || l.contains("crit") || l.contains("emerg") || l.contains("fail") {
        Style::default().fg(Color::Red)
    } else if l.contains("warn") {
        Style::default().fg(Color::Yellow)
    } else if l.contains("accept") || l.contains("started") || l.contains("success") {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    }
}
