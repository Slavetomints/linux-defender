//! One-shot jobs queued with `at`.
//!
//! `atd` runs each queued job once at a scheduled time, which makes the queue
//! a convenient place to park a payload that fires long after the defenders
//! have moved on. The queue is empty on a normal system.

use std::process::{Command, Stdio};

use crate::core::scan::suspicious_matches;
use crate::core::{Action, DefenderContext, DefenderError, Finding, Result, Severity, require_root};

/// At spool directories to scan for immutable spool files.
const AT_SPOOL_DIRS: &[&str] = &[
    "/var/spool/at",
    "/var/spool/cron/atjobs",
];

/// Clear immutable flags on all files in known at spool directories so atrm can remove them.
fn clear_spool_immutable(ctx: &DefenderContext) {
    for dir in AT_SPOOL_DIRS {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = Command::new("chattr")
                    .args(["-i", &path.to_string_lossy()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                ctx.debug(&format!("chattr -i {}", path.display()));
            }
        }
    }
}

/// Remove every queued `at` job unconditionally.
///
/// Any at job on a competition box is assumed hostile; the queue should be empty
/// on a clean system. Logic-bomb jobs (referencing known payloads) are flagged
/// Critical; all others are High. No prompt -- everything gets atrm'd.
/// If atrm fails (e.g. chattr +i on spool files), falls back to direct spool removal.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        ctx.log_msg("[!] Not running as root - stopping at_jobs check.");
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking for at jobs");

    // Pre-clear immutable flags on spool files so atrm can unlink them.
    clear_spool_immutable(ctx);

    let output = Command::new("atq")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| DefenderError::Command(format!("atq: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let jobs: Vec<String> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();

    if jobs.is_empty() {
        ctx.log_msg("[+] No at jobs found");
        return Ok(());
    }

    ctx.log_msg(&format!("[!] Found {} at job(s) -- nuking all", jobs.len()));

    for job in &jobs {
        let Some(job_id) = job.split_whitespace().next() else {
            continue;
        };

        ctx.debug(&format!("at job line: {}", job));

        let content = Command::new("at")
            .args(["-c", job_id])
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        // Score the job content behaviorally -- same patterns used for cron/webshells.
        let hits: Vec<String> = content
            .lines()
            .flat_map(|line| suspicious_matches(line).into_iter().map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let severity = if !hits.is_empty() { Severity::Critical } else { Severity::High };
        let summary = if !hits.is_empty() {
            format!("at job {} REMOVED: suspicious content [{}]", job_id, hits.join(", "))
        } else {
            format!("at job {} REMOVED: {}", job_id, job)
        };

        ctx.log_evidence_line("atq", job);

        // Run atrm with stderr captured so it never bleeds into the TUI.
        let atrm_out = Command::new("atrm")
            .arg(job_id)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();

        let removed = match atrm_out {
            Ok(ref o) => o.status.success(),
            Err(_) => false,
        };

        // If atrm still failed, try direct spool file removal as fallback.
        let removed = if !removed {
            let err = atrm_out
                .as_ref()
                .ok()
                .and_then(|o| String::from_utf8(o.stderr.clone()).ok())
                .unwrap_or_default();
            ctx.debug(&format!("atrm {} stderr: {}", job_id, err.trim()));
            remove_spool_file_for_job(ctx, job_id)
        } else {
            removed
        };

        ctx.log_msg(&format!(
            "[{}] atrm {} -- {}",
            if removed { "+" } else { "!" },
            job_id,
            if removed { "removed" } else { "FAILED" }
        ));

        ctx.emit(
            Finding::new(
                severity,
                "at_jobs",
                summary,
                format!(
                    "Job ID: {}\nremoved: {}\npatterns: {}",
                    job_id,
                    status_str(removed),
                    if hits.is_empty() { "(none)".to_string() } else { hits.join(", ") },
                ),
            )
            .with_action(Action::Manual(format!("atrm {}", job_id))),
        );
    }

    ctx.log_msg("[+] at job cleanup complete");
    Ok(())
}

/// Try to remove the spool file for a given job ID directly.
///
/// At spool files are named `a<5-hex-digits><...>` where the first 5 hex digits
/// encode the job ID. This is the fallback when `atrm` itself fails.
fn remove_spool_file_for_job(ctx: &DefenderContext, job_id: &str) -> bool {
    let Ok(id_num) = job_id.parse::<u32>() else {
        return false;
    };
    let prefix = format!("a{:05x}", id_num);

    for dir in AT_SPOOL_DIRS {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.starts_with(&prefix) {
                let _ = Command::new("chattr").args(["-i", &path.to_string_lossy()])
                    .stdout(Stdio::null()).stderr(Stdio::null()).status();
                if std::fs::remove_file(&path).is_ok() {
                    ctx.log_msg(&format!("[+] Directly removed spool file: {}", path.display()));
                    return true;
                }
            }
        }
    }
    false
}

fn status_str(ok: bool) -> &'static str {
    if ok { "true" } else { "false" }
}
