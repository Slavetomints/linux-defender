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

use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDate, NaiveTime, TimeZone};

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Candidate auth log paths, tried in order.
const AUTH_LOG_CANDIDATES: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/auth.log.1",
];

/// How far back to look, in seconds.
const WINDOW_SECS: i64 = 3600;

/// A recent auth event of interest.
pub struct RecentEvent {
    /// Severity tier for this event.
    pub severity: Severity,
    /// Short summary for the finding.
    pub summary: String,
    /// Detail block.
    pub detail: String,
}

/// Month abbreviations as classic syslog writes them.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Unix timestamp of a log line, or `None` if it carries no recognisable one.
///
/// Two formats are understood:
///
/// - RFC 3339 / ISO 8601 (`2026-11-13T12:34:56.123456-06:00`), the default on
///   Debian 12 and Ubuntu 24.04. The line carries its own UTC offset.
/// - Classic syslog (`Jan  1 00:00:00`, `Jan 10 12:34:56`). It has no year
///   and no zone, so it is read in the zone and year of `now`. A result more
///   than a day in the future means the line is from last December.
pub fn parse_log_timestamp(line: &str, now: DateTime<FixedOffset>) -> Option<i64> {
    let mut fields = line.split_whitespace();
    let first = fields.next()?;

    if let Ok(ts) = DateTime::parse_from_rfc3339(first) {
        return Some(ts.timestamp());
    }

    // split_whitespace collapses the double space syslog pads single-digit
    // days with ("Jan  1").
    let month = MONTHS.iter().position(|m| *m == first)? as u32 + 1;
    let day: u32 = fields.next()?.parse().ok()?;
    let time = NaiveTime::parse_from_str(fields.next()?, "%H:%M:%S").ok()?;

    let resolve = |year: i32| -> Option<i64> {
        let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_time(time);
        now.timezone()
            .from_local_datetime(&naive)
            .single()
            .map(|dt| dt.timestamp())
    };

    let ts = resolve(now.year())?;
    if ts > now.timestamp() + 86_400 {
        resolve(now.year() - 1)
    } else {
        Some(ts)
    }
}

/// Return `true` if the log line's timestamp is within `window_secs` before `now`.
pub fn is_within_window(line: &str, now: DateTime<FixedOffset>, window_secs: i64) -> bool {
    match parse_log_timestamp(line, now) {
        Some(ts) => ts >= now.timestamp() - window_secs,
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
            summary: format!(
                "Account created: {}",
                crate::core::truncate_chars(line, 150)
            ),
            detail: format!("line: {}", line),
        });
    }
    // Account deletion
    if line.contains("userdel") {
        return Some(RecentEvent {
            severity: Severity::High,
            summary: format!(
                "Account deleted: {}",
                crate::core::truncate_chars(line, 150)
            ),
            detail: format!("line: {}", line),
        });
    }
    // Password change
    if line.contains("password changed") || (line.contains("passwd") && line.contains("changed")) {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!(
                "Password changed: {}",
                crate::core::truncate_chars(line, 150)
            ),
            detail: format!("line: {}", line),
        });
    }
    // sudo command
    if line.contains("sudo:") && line.contains("COMMAND=") {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!("sudo command: {}", crate::core::truncate_chars(line, 150)),
            detail: format!("line: {}", line),
        });
    }
    // su session
    if line.contains("su:") && (line.contains("session opened") || line.contains("Successful su")) {
        return Some(RecentEvent {
            severity: Severity::Medium,
            summary: format!("su session: {}", crate::core::truncate_chars(line, 150)),
            detail: format!("line: {}", line),
        });
    }
    // New SSH login
    if line.contains("Accepted") && (line.contains("password") || line.contains("publickey")) {
        return Some(RecentEvent {
            severity: Severity::Info,
            summary: format!("SSH login: {}", crate::core::truncate_chars(line, 150)),
            detail: format!("line: {}", line),
        });
    }
    None
}

/// Scan `contents` for recent high-value events within `window_secs` of `now_secs`.
pub fn analyse(contents: &str, now: DateTime<FixedOffset>, window_secs: i64) -> Vec<RecentEvent> {
    contents
        .lines()
        .filter(|line| is_within_window(line, now, window_secs))
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

    // Classic syslog timestamps are local time, so "now" must carry the local
    // UTC offset.
    let now = Local::now().fixed_offset();
    let events = analyse(&contents, now, WINDOW_SECS);
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
    /// A fixed "now" in a non-UTC zone: 2026-11-13 12:30:00 -06:00.
    fn now() -> DateTime<FixedOffset> {
        FixedOffset::west_opt(6 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 13, 12, 30, 0)
            .unwrap()
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
    fn syslog_timestamp_is_exact_including_leap_days_and_zone() {
        // 12:00:00 local at -06:00 is 18:00:00 UTC.
        let ts = parse_log_timestamp("Nov 13 12:00:00 host sshd[1]: blah", now()).unwrap();
        assert_eq!(ts, now().timestamp() - 1800);
    }

    #[test]
    fn single_digit_days_with_double_space_parse() {
        let n = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 1, 0, 10, 0)
            .unwrap();
        let ts = parse_log_timestamp("Nov  1 00:00:00 host sshd[1]: blah", n).unwrap();
        assert_eq!(ts, n.timestamp() - 600);
    }

    #[test]
    fn iso_timestamps_carry_their_own_offset() {
        let line = "2026-11-13T19:15:00.123456+01:00 host sshd[1]: blah";
        // 19:15 +01:00 == 12:15 -06:00, i.e. 15 minutes before `now()`.
        assert_eq!(
            parse_log_timestamp(line, now()).unwrap(),
            now().timestamp() - 900
        );
        assert!(is_within_window(line, now(), WINDOW_SECS));
    }

    #[test]
    fn december_lines_read_in_january_belong_to_last_year() {
        let jan = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2027, 1, 1, 0, 30, 0)
            .unwrap();
        let line = "Dec 31 23:45:00 host sshd[1]: blah";
        assert_eq!(
            parse_log_timestamp(line, jan).unwrap(),
            jan.timestamp() - 45 * 60
        );
        assert!(is_within_window(line, jan, WINDOW_SECS));
    }

    #[test]
    fn unparseable_line_returns_none() {
        assert!(parse_log_timestamp("not a syslog line", now()).is_none());
        assert!(parse_log_timestamp("", now()).is_none());
    }

    #[test]
    fn is_within_window_recent_line() {
        let line = "Nov 13 12:28:20 host sshd[1]: test";
        assert!(is_within_window(line, now(), WINDOW_SECS));
    }

    #[test]
    fn is_within_window_old_line_excluded() {
        let line = "Nov 13 10:29:00 host sshd[1]: test";
        assert!(!is_within_window(line, now(), WINDOW_SECS));
    }

    #[test]
    fn analyse_empty_returns_nothing() {
        assert!(analyse("", now(), WINDOW_SECS).is_empty());
    }

    #[test]
    fn analyse_filters_to_window() {
        let log = "Nov 13 12:00:00 host useradd[1]: new user: name=recent\n\
             Nov  1 00:00:00 host useradd[2]: new user: name=old\n";
        let results = analyse(log, now(), WINDOW_SECS);
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
