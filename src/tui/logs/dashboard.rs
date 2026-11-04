use crate::core::BoxType;

use super::pane::{LogPane, PaneSource};
use super::preserve::PreserveConfig;
use super::tail::spawn_tail;

pub struct LogDashboard {
    pub box_type: BoxType,
    pub panes: Vec<LogPane>,
    pub active: usize,
}

impl LogDashboard {
    pub fn build(box_type: BoxType, preserve: Option<&PreserveConfig>) -> Self {
        let configs = pane_configs(box_type);
        let mut panes: Vec<LogPane> = configs
            .into_iter()
            .map(|(title, source)| LogPane::new(title, source))
            .collect();

        for pane in &mut panes {
            if let Some(path) = &pane.active_path {
                let preserve_path = preserve.map(|p| p.live_path_for(path));
                spawn_tail(path.clone(), pane.tx.clone(), preserve_path);
            }
        }

        Self {
            box_type,
            panes,
            active: 0,
        }
    }

    pub fn active_pane_mut(&mut self) -> Option<&mut LogPane> {
        self.panes.get_mut(self.active)
    }

    pub fn next_pane(&mut self) {
        if !self.panes.is_empty() {
            self.active = (self.active + 1) % self.panes.len();
        }
    }

    pub fn prev_pane(&mut self) {
        if !self.panes.is_empty() {
            self.active = self.active.checked_sub(1).unwrap_or(self.panes.len() - 1);
        }
    }

    /// All log source paths used by this dashboard (for snapshot/preserve setup).
    pub fn source_paths(box_type: BoxType) -> Vec<String> {
        pane_configs(box_type)
            .into_iter()
            .flat_map(|(_, s)| s.paths)
            .collect()
    }
}

/// Return the log pane titles and their source paths for the given `box_type`.
fn pane_configs(box_type: BoxType) -> Vec<(&'static str, PaneSource)> {
    match box_type {
        BoxType::Web => vec![
            (
                "errors",
                PaneSource {
                    paths: vec![
                        "/var/log/nginx/error.log".into(),
                        "/var/log/apache2/error.log".into(),
                    ],
                    filters: vec![],
                },
            ),
            (
                "access",
                PaneSource {
                    paths: vec![
                        "/var/log/nginx/access.log".into(),
                        "/var/log/apache2/access.log".into(),
                    ],
                    filters: vec![],
                },
            ),
            (
                "auth",
                PaneSource {
                    paths: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
                    filters: vec![],
                },
            ),
            (
                "syslog",
                PaneSource {
                    paths: vec!["/var/log/syslog".into(), "/var/log/messages".into()],
                    filters: vec![],
                },
            ),
        ],
        BoxType::Mail => vec![
            (
                "mail",
                PaneSource {
                    paths: vec!["/var/log/mail.log".into(), "/var/log/maillog".into()],
                    filters: vec![],
                },
            ),
            (
                "auth",
                PaneSource {
                    paths: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
                    filters: vec![
                        "sasl".into(),
                        "imap".into(),
                        "smtp".into(),
                        "dovecot".into(),
                    ],
                },
            ),
            (
                "roundcube",
                PaneSource {
                    paths: vec![
                        "/var/log/roundcube/errors.log".into(),
                        "/var/log/roundcube/errors".into(),
                    ],
                    filters: vec![],
                },
            ),
            (
                "syslog",
                PaneSource {
                    paths: vec!["/var/log/syslog".into(), "/var/log/messages".into()],
                    filters: vec![],
                },
            ),
        ],
        BoxType::Splunk => vec![
            (
                "splunkd",
                PaneSource {
                    paths: vec![
                        "/opt/splunk/var/log/splunk/splunkd.log".into(),
                        "/opt/splunkforwarder/var/log/splunk/splunkd.log".into(),
                    ],
                    filters: vec![],
                },
            ),
            (
                "splunk-web",
                PaneSource {
                    paths: vec!["/opt/splunk/var/log/splunk/web_access.log".into()],
                    filters: vec![],
                },
            ),
            (
                "auth",
                PaneSource {
                    paths: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
                    filters: vec![],
                },
            ),
            (
                "metrics",
                PaneSource {
                    paths: vec!["/opt/splunk/var/log/splunk/metrics.log".into()],
                    filters: vec![],
                },
            ),
        ],
        BoxType::General | BoxType::Router => vec![
            (
                "auth",
                PaneSource {
                    paths: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
                    filters: vec![],
                },
            ),
            (
                "syslog",
                PaneSource {
                    paths: vec!["/var/log/syslog".into(), "/var/log/messages".into()],
                    filters: vec![],
                },
            ),
            (
                "kern",
                PaneSource {
                    paths: vec!["/var/log/kern.log".into()],
                    filters: vec![],
                },
            ),
            (
                "journal",
                PaneSource {
                    paths: vec!["/var/log/syslog".into(), "/var/log/messages".into()],
                    filters: vec![],
                },
            ),
        ],
    }
}
