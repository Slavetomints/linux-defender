//! One-shot jobs queued with `at`.
//!
//! `atd` runs each queued job once at a scheduled time, which makes the queue
//! a convenient place to park a payload that fires long after the defenders
//! have moved on. The queue is empty on a normal system.

use std::process::{Command, Stdio};

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes, require_root};

/// Review every queued `at` job and remove the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        eprintln!("[!] Not running as root - stopping at_jobs check.");
        return Err(DefenderError::NotRoot);
    }

    println!("[+] Checking for at jobs");

    let output = Command::new("atq")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| DefenderError::Command(format!("atq: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let jobs: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();

    if jobs.is_empty() {
        println!("[+] No at jobs found");
        return Ok(());
    }

    println!("[+] Found {} at job(s)", jobs.len());

    for job in jobs {
        let Some(job_id) = job.split_whitespace().next() else {
            continue;
        };

        ctx.debug(&format!("at job line: {}", job));
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

    println!("[+] at job cleanup complete");
    Ok(())
}
