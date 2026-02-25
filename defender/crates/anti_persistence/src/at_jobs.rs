use std::process::{Command, Stdio};

use defender_core::{DefenderContext, require_root};

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    if require_root().is_err() {
        println!("[!] Not running as root - stopping crontab check.");
        return Err("[X] Must run as root to inspect user crontabs".into());
    }
    println!("[+] Checking for at jobs");

    let output = Command::new("atq")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("[X] Failed to run atq: {}", e))?;

    // If atq exits non-zero but no output, it usually just means no jobs
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        println!("[+] No at jobs found");
        return Ok(());
    }

    let mut job_ids = Vec::new();

    for line in stdout.lines() {
        if let Some(job_id) = line.split_whitespace().next() {
            job_ids.push(job_id.to_string());
        }
    }

    println!("[+] Found {} at job(s)", job_ids.len());

    for job_id in job_ids {
        println!("[+] Removing at job {}", job_id);

        let status = Command::new("atrm")
            .arg(&job_id)
            .status()
            .map_err(|e| format!("[X] Failed to remove job {}: {}", job_id, e))?;

        if !status.success() {
            eprintln!("[!] Failed to remove job {}", job_id);
        }
    }

    println!("[+] at job cleanup complete");

    Ok(())
}