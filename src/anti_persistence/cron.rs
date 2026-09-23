//! Scheduled jobs in user crontabs.
//!
//! The most common persistence mechanism there is: a job that re-establishes
//! a foothold every minute survives any cleanup that does not look here. Each
//! user's crontab is reviewed line by line and rewritten containing only the
//! entries the operator chose to keep.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::core::{
    DefenderContext, DefenderError, Result, collect_users, prompt_yes, require_root,
};

/// Walk every user's crontab, entry by entry, and rewrite it without the flagged lines.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        eprintln!("[!] Not running as root - stopping cron check.");
        return Err(DefenderError::NotRoot);
    }

    println!("[+] Collecting users...");
    let users = collect_users()?;
    println!("[✓] Users collected.");

    for user in users {
        ctx.debug(&format!("Checking cronjobs for {}", user));

        let cronjobs = get_cronjobs(&user)?;
        if cronjobs.is_empty() {
            continue;
        }

        println!("[+] {} - Filtering {} cronjob(s)...", user, cronjobs.len());
        let good_jobs = filter_jobs(&cronjobs)?;

        if good_jobs.len() != cronjobs.len() {
            println!("[+] {} - Writing good cronjobs to disk...", user);
            write_good_jobs(&good_jobs, &user)?;
            println!("[✓] {} - Good cronjobs written to disk", user);
        }
    }

    println!("[✓] All cronjobs checked!");
    Ok(())
}

/// Every line of one user's crontab, or empty if they have none.
fn get_cronjobs(user: &str) -> Result<Vec<String>> {
    let output = Command::new("crontab")
        .args(["-l", "-u", user])
        .output()
        .map_err(|e| DefenderError::Command(format!("crontab -l -u {}: {}", user, e)))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(str::to_string).collect())
}

/// Ask about each real job, keeping comments and blanks untouched.
fn filter_jobs(cronjobs: &[String]) -> Result<Vec<String>> {
    let mut good_jobs = Vec::new();

    for cronjob in cronjobs {
        let trimmed = cronjob.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            good_jobs.push(cronjob.clone());
            continue;
        }

        if !prompt_yes(&format!("[?] Is this malicious? (y/N) {}", cronjob))? {
            good_jobs.push(cronjob.clone());
        }
    }

    Ok(good_jobs)
}

/// Pipe the kept lines back through `crontab -` for this user.
fn write_good_jobs(good_jobs: &[String], user: &str) -> Result {
    let new_cron = good_jobs.join("\n");

    let mut child = Command::new("crontab")
        .args(["-", "-u", user])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| DefenderError::Command(format!("spawn crontab for {}: {}", user, e)))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| DefenderError::Command("failed to open crontab stdin".into()))?;
    stdin.write_all(new_cron.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        return Err(DefenderError::Command(format!(
            "crontab write for {} exited with {}",
            user, status
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blanks_are_always_kept() {
        let jobs = vec!["# a comment".to_string(), "   ".to_string()];
        // No prompt is issued for these, so this does not block on stdin.
        let kept = filter_jobs(&jobs).unwrap();
        assert_eq!(kept.len(), 2);
    }
}
