//! One-shot jobs queued with `at`.
//!
//! `atd` runs each queued job once at a scheduled time, which makes the queue
//! a convenient place to park a payload that fires long after the defenders
//! have moved on. The queue is empty on a normal system.

use std::process::{Command, Stdio};

use crate::core::{Action, DefenderContext, DefenderError, Finding, Result, Severity, prompt_yes,
    require_root};

/// Review every queued `at` job and remove the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if !ctx.in_tui() {
            eprintln!("[!] Not running as root - stopping at_jobs check.");
        }
        return Err(DefenderError::NotRoot);
    }

    if !ctx.in_tui() {
        println!("[+] Checking for at jobs");
    }

    let output = Command::new("atq")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| DefenderError::Command(format!("atq: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let jobs: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();

    if jobs.is_empty() {
        if !ctx.in_tui() {
            println!("[+] No at jobs found");
        }
        return Ok(());
    }

    if !ctx.in_tui() {
        println!("[+] Found {} at job(s)", jobs.len());
    }

    for job in jobs {
        let Some(job_id) = job.split_whitespace().next() else {
            continue;
        };

        ctx.debug(&format!("at job line: {}", job));

        if ctx.in_tui() {
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "at_jobs",
                    format!("Queued at job: {}", job),
                    format!("Job ID: {}", job_id),
                )
                .with_action(Action::Manual(format!("atrm {}", job_id))),
            );
            continue;
        }

        println!("[!] at job: {}", job);

        if !prompt_yes("[?] Remove this at job? (y/N)")? {
            continue;
        }

        let status = Command::new("atrm")
            .arg(job_id)
            .status()
            .map_err(|e| DefenderError::Command(format!("atrm {}: {}", job_id, e)))?;

        if status.success() {
            println!("[+] Removed at job {}", job_id);
        } else {
            eprintln!("[!] Failed to remove job {}", job_id);
        }
    }

    if !ctx.in_tui() {
        println!("[+] at job cleanup complete");
    }
    Ok(())
}
