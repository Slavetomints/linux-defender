//! Recent auth log window analysis.
//!
//! Scans the last hour of `/var/log/auth.log` (or `/var/log/secure`) for
//! high-value events that indicate live attacker activity: account creation or
//! deletion, password changes, new `sudo`/`su` commands, and fresh SSH logins.
//!
//! This module is distinct from [`super::auth_log`], which does a full
//! historical brute-force and credential-stuffing analysis.  This module is
//! optimised for the "what happened in the last 60 minutes?" question.

use std::path::Path;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Candidate auth log paths, tried in order.
const AUTH_LOG_CANDIDATES: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/auth.log.1",
];

/// How far back to look, in seconds.
const WINDOW_SECS: u64 = 3600;

/// A recent auth event of interest.
pub struct RecentEvent {
    /// Severity tier for this event.
    pub severity: Severity,
    /// Short summary for the finding.
    pub summary: String,
    /// Detail block.
    pub detail: String,
}

/// Derive the current year as a string for timestamp parsing.
fn current_year() -> String {
    // Rely on the system clock; avoids a heavy date library dependency.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Rough year calculation (good enough for log timestamp matching)
    let year = 1970 + now / 31_557_600;
    year.to_string()
}

/// Parse a syslog-style `"Mon DD HH:MM:SS"` timestamp from the start of a
/// line and return the number of seconds since Unix epoch, or `None`.
///
/// This handles the ambiguity of syslog timestamps that omit the year by
/// assuming the current year.
pub fn parse_syslog_timestamp(line: &str, year: &str) -> Option<u64> {
    // Syslog: "Jan  1 00:00:00" or "Jan 10 12:34:56"
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = line.splitn(5, ' ').collect();
    if parts.len() < 3 {
        return None;
    }
    let month_idx = months.iter().position(|m| *m == parts[0])? as u64;
    let day: u64 = parts[1].trim().parse().ok()?;
    let time_parts: Vec<&str> = parts[2].splitn(3, ':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;
    let year_n: u64 = year.parse().ok()?;

    // Days elapsed to start of this month (approximate, ignores leap years for simplicity)
    let days_per_month = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let days_in_year: u64 = days_per_month[..month_idx as usize].iter().sum();
    let total_days = (year_n - 1970) * 365 + days_in_year + (day - 1);

    Some(total_days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Return `true` if `line` is within the specified window relative to `now`.
pub fn is_within_window(line: &str, now_secs: u64, window_secs: u64, year: &str) -> bool {
    match parse_syslog_timestamp(line, year) {
        Some(ts) => ts >= now_secs.saturating_sub(window_secs),
        None => false,
    }
}

/// Classify one auth log line, returning a [`RecentEvent`] if it matches a
/// high-value pattern.
pub fn classify_line(line: &str) -> Option<RecentEvent> {
    // Account creation
    if line.contains("useradd") || line.contains("adduser") {
        return Some(RecentEvent {
            severity: Severity::High,
            summary: format!("Account created: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    // Account deletion
    if line.contains("userdel") {
        return Some(RecentEvent {
            severity: Severity::High,
            summary: format!("Account deleted: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    // Password change
    if line.contains("password changed") || (line.contains("passwd") && line.contains("changed")) {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!("Password changed: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    // sudo command
    if line.contains("sudo:") && line.contains("COMMAND=") {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!("sudo command: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    // su session
    if line.contains("su:") && (line.contains("session opened") || line.contains("Successful su")) {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!("su session: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    // New SSH login
    if line.contains("Accepted") && (line.contains("password") || line.contains("publickey")) {
        return Some(RecentEvent {
            severity: Severity::Info,
            summary: format!("SSH login: {}", &line[..line.len().min(150)]),
            detail: format!("line: {}", line),
        });
    }
    None
}

/// Scan `contents` for recent high-value events within `window_secs` of `now_secs`.
pub fn analyse(contents: &str, now_secs: u64, window_secs: u64, year: &str) -> Vec<RecentEvent> {
    contents
        .lines()
        .filter(|line| is_within_window(line, now_secs, window_secs, year))
        .filter_map(classify_line)
        .collect()
}

/// Run recent auth log analysis and emit findings via `ctx`.
pub fn run(ctx: &DefenderContext) -> Result {
    let log_path = AUTH_LOG_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .copied();

    let Some(path) = log_path else {
        ctx.log_msg("[!] No auth log found — skipping auth_log_watch");
        return Ok(());
    };

    ctx.log_msg(&format!("[+] Scanning last hour of {}...", path));

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            ctx.log_msg(&format!("[!] Cannot read {}: {} — skipping", path, e));
            return Ok(());
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let year = current_year();
    let events = analyse(&contents, now_secs, WINDOW_SECS, &year);
    let count = events.len();

    for ev in events {
        ctx.emit(Finding::new(
            ev.severity,
            "auth_log_watch",
            ev.summary,
            ev.detail,
        ));
    }

    ctx.log_msg(&format!(
        "[✓] Auth log watch complete — {} recent event(s) in last hour",
        count
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A timestamp for "Jan 10 12:00:00 <year>" as seconds since epoch (approximate).
    fn jan10_noon(year: u64) -> u64 {
        // 9 full days of January + 12 hours
        let days_since_1970 = (year - 1970) * 365 + 9;
        days_since_1970 * 86400 + 12 * 3600
    }

    #[test]
    fn classify_useradd_is_high() {
        let line = "Jan 10 12:00:01 host useradd[1234]: new user: name=evil";
        let ev = classify_line(line).unwrap();
        assert!(matches!(ev.severity, Severity::High));
        assert!(ev.summary.contains("created"));
    }

    #[test]
    fn classify_userdel_is_high() {
        let line = "Jan 10 12:00:01 host userdel[1234]: delete user 'alice'";
        let ev = classify_line(line).unwrap();
        assert!(matches!(ev.severity, Severity::High));
        assert!(ev.summary.contains("deleted"));
    }

    #[test]
    fn classify_sudo_command_is_medium() {
        let line =
            "Jan 10 12:00:01 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; COMMAND=/bin/bash";
        let ev = classify_line(line).unwrap();
        assert!(matches!(ev.severity, Severity::Medium));
    }

    #[test]
    fn classify_ssh_accepted_is_info() {
        let line =
            "Jan 10 12:00:01 host sshd[100]: Accepted publickey for alice from 1.2.3.4 port 22";
        let ev = classify_line(line).unwrap();
        assert!(matches!(ev.severity, Severity::Info));
    }

    #[test]
    fn classify_unrelated_line_returns_none() {
        let line = "Jan 10 12:00:01 host systemd[1]: Started SSH daemon";
        assert!(classify_line(line).is_none());
    }

    #[test]
    fn parse_syslog_timestamp_basic() {
        // Jan 10 12:00:00 of a known year
        let line = "Jan 10 12:00:00 host sshd[1]: blah";
        let ts = parse_syslog_timestamp(line, "2024").unwrap();
        // Just verify it's a plausible unix timestamp in 2024
        assert!(ts > 1_700_000_000, "timestamp should be in 2024 range");
    }

    #[test]
    fn parse_syslog_timestamp_bad_line_returns_none() {
        assert!(parse_syslog_timestamp("not a syslog line", "2024").is_none());
    }

    #[test]
    fn is_within_window_recent_line() {
        let year = 2025u64;
        let now = jan10_noon(year) + 100; // 100 seconds after noon
        let line = "Jan 10 12:00:00 host sshd[1]: test";
        // The line is 100 seconds old — within 1 hour
        assert!(is_within_window(line, now, WINDOW_SECS, &year.to_string()));
    }

    #[test]
    fn is_within_window_old_line_excluded() {
        let year = 2025u64;
        let now = jan10_noon(year) + 7200; // 2 hours after noon
        let line = "Jan 10 12:00:00 host sshd[1]: test";
        // The line is 2 hours old — outside the 1-hour window
        assert!(!is_within_window(line, now, WINDOW_SECS, &year.to_string()));
    }

    #[test]
    fn analyse_empty_returns_nothing() {
        let results = analyse("", 0, WINDOW_SECS, "2024");
        assert!(results.is_empty());
    }

    #[test]
    fn analyse_filters_to_window() {
        // Two useradd lines: one recent, one old.
        // We pass a fake "now" so both are in 2025.
        let year = 2025u64;
        let noon = jan10_noon(year);
        let log = "Jan 10 12:00:00 host useradd[1]: new user: name=recent\n\
             Jan  1 00:00:00 host useradd[2]: new user: name=old\n";
        // now = noon + 30 minutes — recent is in window, Jan 1 is not
        let results = analyse(log, noon + 1800, WINDOW_SECS, &year.to_string());
        assert_eq!(results.len(), 1);
        assert!(results[0].summary.contains("recent"));
    }

    #[test]
    fn window_secs_is_one_hour() {
        #[allow(clippy::assertions_on_constants)]
        {
            assert_eq!(WINDOW_SECS, 3600);
        }
    }
}
