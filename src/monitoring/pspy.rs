//! Short-lived and deleted-binary process scanner.
//!
//! Walks `/proc` once to snapshot all running processes, computes each
//! process's age from `/proc/<pid>/stat` and `/proc/uptime`, then flags:
//!
//! - Any process whose on-disk executable has been deleted (attacker
//!   executed-from-memory pattern).
//! - Any process younger than 300 seconds whose exe name matches a
//!   suspicious pattern (interpreter or network tool running briefly).
//! - Everything else started within the window gets an Info finding so the
//!   operator has a complete picture of recent process activity.

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Processes younger than this many seconds are included in the scan.
const RECENT_SECS: f64 = 300.0;

/// Clock ticks per second assumed when the kernel does not expose it.
///
/// Linux universally uses 100 HZ for the `/proc/stat` accounting fields, so
/// hardcoding 100 is correct on virtually every real machine. Using
/// `libc::sysconf(_SC_CLK_TCK)` would be more portable but adds unsafe code
/// for a value that never changes in practice.
const CLOCK_TICKS_PER_SEC: f64 = 100.0;

/// Exe names that are suspicious when they appear as short-lived processes.
const SUSPICIOUS_NAMES: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "bash", "sh", "dash", "nc", "ncat", "nmap",
    "curl", "wget", "socat",
];

/// One process snapshot extracted from `/proc`.
struct ProcEntry {
    /// Numeric process ID.
    pid: u32,
    /// Full path from `/proc/<pid>/exe` symlink (may end with ` (deleted)`).
    exe_path: String,
    /// Basename of `exe_path`, stripped of the ` (deleted)` suffix.
    exe_name: String,
    /// Whether the on-disk executable has been deleted.
    deleted: bool,
    /// Process age in seconds at the time of the snapshot.
    age_secs: f64,
}

/// Read `/proc/uptime` and return the system uptime in seconds.
fn read_uptime() -> Option<f64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
}

/// Read field 22 (start-time, 0-indexed 21) from `/proc/<pid>/stat` in ticks.
fn read_starttime_ticks(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // The comm field `(name)` may contain spaces; find the last `)` to skip it.
    let after_comm = stat.rfind(')')?.checked_add(1)?;
    let rest = stat[after_comm..].trim_start();
    // Fields after comm: state ppid pgroup session tty_nr tpgid flags
    // minflt cminflt majflt cmajflt utime stime cutime cstime priority
    // nice num_threads itrealvalue starttime  <-- index 19 (0-based after state)
    rest.split_whitespace().nth(19)?.parse::<f64>().ok()
}

/// Resolve `/proc/<pid>/exe` to a path string.
fn read_exe_path(pid: u32) -> Option<String> {
    // read_link on a missing or unreadable symlink returns Err — that's fine.
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Extract the basename of `path`, stripping any ` (deleted)` suffix.
pub fn exe_basename(path: &str) -> &str {
    let stripped = path.trim_end_matches(" (deleted)");
    stripped.rsplit('/').next().unwrap_or(stripped)
}

/// Return `true` if `name` matches any entry in the suspicious-names list.
///
/// The match checks whether the exe basename *starts with* any of the
/// patterns, so `python3.11` still matches `python`.
pub fn is_suspicious_name(name: &str) -> bool {
    SUSPICIOUS_NAMES.iter().any(|&pat| name.starts_with(pat))
}

/// Snapshot all readable processes from `/proc`.
fn collect_processes(uptime: f64) -> Vec<ProcEntry> {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut entries = Vec::new();

    for dir_entry in proc_dir.flatten() {
        let Ok(pid) = dir_entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let exe_path = match read_exe_path(pid) {
            Some(p) => p,
            None => continue, // kernel threads / vanished processes
        };

        let deleted = exe_path.ends_with(" (deleted)");
        let exe_name = exe_basename(&exe_path).to_string();

        let ticks = match read_starttime_ticks(pid) {
            Some(t) => t,
            None => continue,
        };

        let start_secs = ticks / CLOCK_TICKS_PER_SEC;
        let age_secs = (uptime - start_secs).max(0.0);

        entries.push(ProcEntry {
            pid,
            exe_path,
            exe_name,
            deleted,
            age_secs,
        });
    }

    entries
}

/// Snapshot running processes and flag recently-started or deleted-exe entries.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for short-lived and deleted-binary processes...");

    let uptime = read_uptime().unwrap_or(0.0);
    let procs = collect_processes(uptime);
    let mut flagged = 0usize;

    for p in &procs {
        if p.deleted {
            ctx.emit(Finding::new(
                Severity::High,
                "pspy",
                format!("PID {} running from deleted binary: {}", p.pid, p.exe_path),
                format!(
                    "pid: {}\nexe: {}\nage: {:.0}s\nstatus: deleted on disk",
                    p.pid, p.exe_path, p.age_secs
                ),
            ));
            flagged += 1;
        } else if p.age_secs < RECENT_SECS {
            if is_suspicious_name(&p.exe_name) {
                ctx.emit(Finding::new(
                    Severity::Medium,
                    "pspy",
                    format!(
                        "Suspicious short-lived process: {} (PID {}, {:.0}s old)",
                        p.exe_name, p.pid, p.age_secs
                    ),
                    format!(
                        "pid: {}\nexe: {}\nage: {:.0}s",
                        p.pid, p.exe_path, p.age_secs
                    ),
                ));
                flagged += 1;
            } else {
                ctx.emit(Finding::new(
                    Severity::Info,
                    "pspy",
                    format!(
                        "Recent process: {} (PID {}, {:.0}s old)",
                        p.exe_name, p.pid, p.age_secs
                    ),
                    format!(
                        "pid: {}\nexe: {}\nage: {:.0}s",
                        p.pid, p.exe_path, p.age_secs
                    ),
                ));
            }
        }
    }

    ctx.log_msg(&format!(
        "[✓] pspy scan complete — {} suspicious finding(s) across {} processes",
        flagged,
        procs.len()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_names_match() {
        assert!(is_suspicious_name("bash"));
        assert!(is_suspicious_name("python3.11"));
        assert!(is_suspicious_name("python"));
        assert!(is_suspicious_name("nc"));
        assert!(is_suspicious_name("ncat"));
        assert!(is_suspicious_name("wget"));
        assert!(is_suspicious_name("socat"));
    }

    #[test]
    fn benign_names_do_not_match() {
        assert!(!is_suspicious_name("sshd"));
        assert!(!is_suspicious_name("nginx"));
        assert!(!is_suspicious_name("systemd"));
        assert!(!is_suspicious_name("chronyd"));
        assert!(!is_suspicious_name("postgres"));
    }

    #[test]
    fn exe_basename_strips_deleted() {
        assert_eq!(exe_basename("/usr/bin/python3 (deleted)"), "python3");
        assert_eq!(exe_basename("/usr/sbin/sshd"), "sshd");
        assert_eq!(exe_basename("sshd"), "sshd");
    }

    #[test]
    fn exe_basename_handles_root_path() {
        assert_eq!(exe_basename("/bin/sh"), "sh");
    }

    #[test]
    fn run_does_not_panic() {
        use crate::core::DefenderContext;
        use std::path::PathBuf;
        let ctx = DefenderContext::new(PathBuf::from("/dev/null"), false);
        let _ = run(&ctx);
    }
}
