//! Fail2ban status: is it running, what jails are active, recent bans.
//!
//! Runs `fail2ban-client status` and then queries each discovered jail.
//! Surfaces findings when fail2ban is not running, when no jails are active,
//! or (informational) when bans have been issued recently.

use std::process::Command;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking fail2ban status...");

    // Is fail2ban-client available?
    let client = which_fail2ban();
    if client.is_none() {
        ctx.emit(
            Finding::new(
                Severity::High,
                "fail2ban",
                "fail2ban is not installed".to_string(),
                "fail2ban-client not found in PATH".to_string(),
            )
            .with_verdict(
                Verdict::Investigate,
                "fail2ban is not installed. Without it, SSH brute-force and web attacks \
                 are unrestricted. Install it with: apt install fail2ban (Debian/Ubuntu) \
                 or dnf install fail2ban (RHEL/Fedora)."
                .to_string(),
            ),
        );
        return Ok(());
    }

    // Is the daemon running?
    let not_running = match run_command("fail2ban-client", &["ping"]) {
        Err(_) => true,
        Ok(ref s) => s.contains("ERROR") || !s.contains("pong"),
    };
    if not_running {
        ctx.emit(
            Finding::new(
                Severity::High,
                "fail2ban",
                "fail2ban daemon is not running".to_string(),
                "fail2ban-client ping did not return 'pong'".to_string(),
            )
            .with_verdict(
                Verdict::Investigate,
                "fail2ban is installed but not running. Start it: \
                 systemctl enable --now fail2ban"
                .to_string(),
            ),
        );
        return Ok(());
    }

    // Get jail list
    let status = run_command("fail2ban-client", &["status"])?;
    let jails = parse_jail_list(&status);

    if jails.is_empty() {
        ctx.emit(
            Finding::new(
                Severity::Medium,
                "fail2ban",
                "fail2ban is running but no jails are active".to_string(),
                format!("status output: {}", status),
            )
            .with_verdict(
                Verdict::Investigate,
                "fail2ban has no configured jails. Brute-force protection is not \
                 active. Enable at minimum the sshd jail."
                .to_string(),
            ),
        );
        return Ok(());
    }

    ctx.log_msg(&format!("[+] Active jails: {}", jails.join(", ")));

    // Per-jail stats
    let mut total_bans = 0u64;
    for jail in &jails {
        if let Ok(detail) = run_command("fail2ban-client", &["status", jail]) {
            let currently_banned = parse_count(&detail, "Currently banned:");
            let total_banned = parse_count(&detail, "Total banned:");
            total_bans += total_banned;

            if currently_banned > 0 {
                ctx.log_msg(&format!(
                    "  jail '{}': {} currently banned, {} total",
                    jail, currently_banned, total_banned
                ));
            }
        }
    }

    ctx.log_msg(&format!(
        "[✓] fail2ban OK — {} jail{}, {} total bans",
        jails.len(),
        if jails.len() == 1 { "" } else { "s" },
        total_bans,
    ));
    Ok(())
}

fn which_fail2ban() -> Option<()> {
    Command::new("which")
        .arg("fail2ban-client")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| ())
}

fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| crate::core::DefenderError::Io(e))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse "Jail list: sshd, nginx-http-auth, postfix" → vec of names.
/// Handles fail2ban's tree-decorated output (lines like `` `- Jail list:   sshd ``).
fn parse_jail_list(status: &str) -> Vec<String> {
    for line in status.lines() {
        if let Some(idx) = line.find("Jail list:") {
            let rest = &line[idx + "Jail list:".len()..];
            return rest
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![]
}

/// Parse "Currently banned:\t3" → 3.
/// Handles fail2ban's tree-decorated output (indented lines like `   |- Currently banned:  3`).
fn parse_count(text: &str, label: &str) -> u64 {
    for line in text.lines() {
        if let Some(idx) = line.find(label) {
            let rest = &line[idx + label.len()..];
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jail_list() {
        let status = "Status\n|- Number of jail:   2\n`- Jail list:   sshd, nginx-http-auth\n";
        let jails = parse_jail_list(status);
        assert_eq!(jails, vec!["sshd", "nginx-http-auth"]);
    }

    #[test]
    fn parses_empty_jail_list() {
        let status = "Status\n|- Number of jail:   0\n`- Jail list:\n";
        let jails = parse_jail_list(status);
        assert!(jails.is_empty());
    }

    #[test]
    fn parses_count() {
        let detail = "|- Filter\n|  |- Currently failed: 5\n|  `- Total failed: 42\n`- Actions\n   |- Currently banned:  3\n   `- Total banned:   18\n";
        assert_eq!(parse_count(detail, "Currently banned:"), 3);
        assert_eq!(parse_count(detail, "Total banned:"), 18);
    }
}
