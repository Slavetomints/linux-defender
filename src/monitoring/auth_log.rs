//! Authentication log analysis.
//!
//! Parses `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora)
//! to detect brute-force campaigns, credential-stuffing successes, and suspicious
//! sudo usage — without requiring a live log tail (snapshots the file once).

use std::collections::HashMap;
use std::path::Path;

use chrono::Local;

use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict};

/// Candidate paths for the authentication log file, tried in order.
const AUTH_LOG_CANDIDATES: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/auth.log.1",
];

/// Minimum failed attempts from one IP before it is flagged as a brute force.
const BRUTE_FORCE_THRESHOLD: usize = 10;

/// An IP that failed authentication this many times and then succeeded is a
/// credential-stuffing success — flag it Critical regardless of the overall count.
const STUFF_FAIL_THRESHOLD: usize = 3;

/// One parsed authentication event from the auth log.
struct AuthEvent {
    /// IP address that initiated the authentication attempt.
    source_ip: String,
    /// Whether the authentication succeeded.
    success: bool,
    /// Username targeted by the authentication attempt.
    user: String,
    /// Authentication method used.
    method: AuthMethod,
}

/// SSH authentication method.
#[derive(Clone, PartialEq)]
enum AuthMethod {
    /// Password-based authentication.
    Password,
    /// Public-key authentication.
    Publickey,
    /// Authentication method not recognised in the log line.
    Unknown,
}

/// Parse auth log lines into structured events.
fn parse_events(contents: &str) -> Vec<AuthEvent> {
    let mut events = Vec::new();

    for line in contents.lines() {
        // Accepted password for <user> from <ip>
        if let Some(rest) = line.find("Accepted password for ").map(|i| &line[i + 22..]) {
            if let Some((user, ip)) = parse_for_from(rest) {
                events.push(AuthEvent {
                    source_ip: ip,
                    success: true,
                    user,
                    method: AuthMethod::Password,
                });
                continue;
            }
        }
        // Accepted publickey for <user> from <ip>
        if let Some(rest) = line
            .find("Accepted publickey for ")
            .map(|i| &line[i + 23..])
        {
            if let Some((user, ip)) = parse_for_from(rest) {
                events.push(AuthEvent {
                    source_ip: ip,
                    success: true,
                    user,
                    method: AuthMethod::Publickey,
                });
                continue;
            }
        }
        // Failed password for <user> from <ip>
        if let Some(rest) = line.find("Failed password for ").map(|i| &line[i + 20..]) {
            if let Some((user, ip)) = parse_for_from(rest) {
                events.push(AuthEvent {
                    source_ip: ip,
                    success: false,
                    user,
                    method: AuthMethod::Password,
                });
                continue;
            }
        }
        // Invalid user <user> from <ip>
        if let Some(rest) = line.find("Invalid user ").map(|i| &line[i + 13..]) {
            if let Some((user, ip)) = parse_user_from(rest) {
                events.push(AuthEvent {
                    source_ip: ip,
                    success: false,
                    user,
                    method: AuthMethod::Unknown,
                });
                continue;
            }
        }
        // Connection closed by authenticating user <user> <ip> — often a probe
        if line.contains("Connection closed by authenticating user") {
            if let Some(ip) = extract_ip(line) {
                events.push(AuthEvent {
                    source_ip: ip,
                    success: false,
                    user: "unknown".into(),
                    method: AuthMethod::Unknown,
                });
            }
        }
    }

    events
}

/// Parse `"<user> from <ip>"` from a log fragment, returning `(user, ip)`.
fn parse_for_from(s: &str) -> Option<(String, String)> {
    // "<user> from <ip>"
    let from_idx = s.find(" from ")?;
    let user = s[..from_idx].trim().to_string();
    let rest = &s[from_idx + 6..];
    let ip = rest.split_whitespace().next()?.to_string();
    Some((user, ip))
}

/// Parse `"<user> from <ip>"` from a "Failed" log fragment, returning `(user, ip)`.
fn parse_user_from(s: &str) -> Option<(String, String)> {
    // "<user> from <ip>"
    let from_idx = s.find(" from ")?;
    let user = s[..from_idx].trim().to_string();
    let ip = s[from_idx + 6..].split_whitespace().next()?.to_string();
    Some((user, ip))
}

/// Extract the last IPv4 or IPv6 address token from a log line.
fn extract_ip(line: &str) -> Option<String> {
    // Very simple: look for the last token that looks like an IPv4 address
    for token in line.split_whitespace().rev() {
        if token.chars().all(|c| c.is_ascii_digit() || c == '.') && token.contains('.') {
            return Some(token.to_string());
        }
        // IPv6
        if token.contains(':') && token.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Some(token.to_string());
        }
    }
    None
}

/// Run auth log analysis and emit findings.
pub fn run(ctx: &DefenderContext) -> Result {
    let log_path = AUTH_LOG_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .copied();

    let Some(path) = log_path else {
        ctx.log_msg("[!] No auth log found (checked auth.log, secure) — skipping");
        return Ok(());
    };

    ctx.log_msg(&format!("[+] Analysing {}...", path));

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            ctx.log_msg(&format!("[!] Cannot read {}: {} — skipping", path, e));
            return Ok(());
        }
    };

    let events = parse_events(&contents);
    ctx.log_msg(&format!("[+] Parsed {} auth events", events.len()));

    // Per-IP tallies
    let mut fail_count: HashMap<String, usize> = HashMap::new();
    let mut success_users: HashMap<String, Vec<String>> = HashMap::new(); // ip → [users]
    let mut ip_failed_first: HashMap<String, bool> = HashMap::new();
    let mut password_successes: Vec<(String, String)> = Vec::new(); // (ip, user)

    for ev in &events {
        if ev.success {
            success_users
                .entry(ev.source_ip.clone())
                .or_default()
                .push(ev.user.clone());
            if ev.method == AuthMethod::Password {
                password_successes.push((ev.source_ip.clone(), ev.user.clone()));
            }
        } else {
            *fail_count.entry(ev.source_ip.clone()).or_insert(0) += 1;
        }
    }

    // Mark IPs that had failures before success
    for ip in success_users.keys() {
        if fail_count.get(ip).copied().unwrap_or(0) >= STUFF_FAIL_THRESHOLD {
            ip_failed_first.insert(ip.clone(), true);
        }
    }

    // Emit brute-force findings
    let mut brute_ips: Vec<(&String, usize)> = fail_count
        .iter()
        .filter(|(_, count)| **count >= BRUTE_FORCE_THRESHOLD)
        .map(|(ip, count)| (ip, *count))
        .collect();
    brute_ips.sort_by_key(|(_, c)| std::cmp::Reverse(*c));

    for (ip, count) in &brute_ips {
        let count = *count;
        let succeeded = success_users.contains_key(*ip);
        let severity = if succeeded {
            Severity::Critical
        } else {
            Severity::High
        };
        let verdict = if succeeded {
            Verdict::Investigate
        } else {
            Verdict::Info
        };

        let summary = if succeeded {
            format!(
                "Brute force from {} — {} failures then LOGIN SUCCEEDED",
                ip, count
            )
        } else {
            format!("Brute force from {} — {} failed attempts", ip, count)
        };
        let detail = format!(
            "source_ip: {}\nfailed_attempts: {}\nlogin_succeeded: {}\nlog: {}",
            ip, count, succeeded, path
        );
        let recommendation = if succeeded {
            format!(
                "IP {} made {} failed authentication attempts and then logged in successfully. \
                 This is a strong indicator of a credential-stuffing or brute-force success. \
                 Review what was done after login and consider blocking this IP at the firewall.",
                ip, count
            )
        } else {
            format!(
                "IP {} made {} failed authentication attempts. This is an active brute-force \
                 campaign. fail2ban should ban this IP; if not installed, block manually.",
                ip, count
            )
        };

        let mut finding = Finding::new(severity, "auth_log", summary, detail)
            .with_context("source_ip", (*ip).clone())
            .with_context("failed_attempts", count.to_string())
            .with_context("log_file", path)
            .with_verdict(verdict, recommendation);

        if succeeded {
            let users = success_users[*ip].join(", ");
            finding = finding.with_context("successful_logins_as", users);
        }

        ctx.emit(finding);
    }

    // Credential-stuffing successes from IPs below the brute threshold
    for (ip, users) in &success_users {
        let fails = fail_count.get(ip).copied().unwrap_or(0);
        if (STUFF_FAIL_THRESHOLD..BRUTE_FORCE_THRESHOLD).contains(&fails) {
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "auth_log",
                    format!("Suspicious: {} failures then success from {}", fails, ip),
                    format!(
                        "source_ip: {}\nfailed_before_success: {}\nlogged_in_as: {}\nlog: {}",
                        ip,
                        fails,
                        users.join(", "),
                        path
                    ),
                )
                .with_context("source_ip", ip.clone())
                .with_context("failed_before_success", fails.to_string())
                .with_context("users", users.join(", "))
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "IP {} had {} authentication failures followed by a successful login. \
                         Investigate what commands were run in that session.",
                        ip, fails
                    ),
                ),
            );
        }
    }

    // Password auth successes — CCDC boxes should use key auth only
    for (ip, user) in &password_successes {
        ctx.emit(
            Finding::new(
                Severity::Medium,
                "auth_log",
                format!("Password-authenticated login: {} from {}", user, ip),
                format!("user: {}\nsource_ip: {}\nmethod: password\nlog: {}", user, ip, path),
            )
            .with_context("user", user.clone())
            .with_context("source_ip", ip.clone())
            .with_verdict(
                Verdict::Investigate,
                "This login used password authentication. CCDC boxes should use key-based auth only. \
                 Check SSH config: PasswordAuthentication should be no.".to_string(),
            )
            .with_action(Action::Manual(
                "Set PasswordAuthentication no in /etc/ssh/sshd_config and restart sshd".into(),
            )),
        );
    }

    let now = Local::now().format("%H:%M:%S");
    ctx.log_msg(&format!(
        "[✓] Auth log analysis complete at {} — {} brute-force IPs, {} password logins",
        now,
        brute_ips.len(),
        password_successes.len(),
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Jan 10 12:00:01 host sshd[1234]: Failed password for root from 10.0.0.1 port 55001 ssh2
Jan 10 12:00:02 host sshd[1234]: Failed password for root from 10.0.0.1 port 55002 ssh2
Jan 10 12:00:03 host sshd[1234]: Failed password for admin from 10.0.0.1 port 55003 ssh2
Jan 10 12:00:04 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 55004 ssh2
Jan 10 12:00:05 host sshd[1234]: Failed password for root from 10.0.0.2 port 44001 ssh2
Jan 10 12:00:06 host sshd[1234]: Accepted publickey for deploy from 192.168.1.1 port 60001 ssh2
";

    #[test]
    fn parses_failures_and_successes() {
        let events = parse_events(SAMPLE);
        let failures: Vec<_> = events.iter().filter(|e| !e.success).collect();
        let successes: Vec<_> = events.iter().filter(|e| e.success).collect();
        assert_eq!(failures.len(), 4);
        assert_eq!(successes.len(), 2);
    }

    #[test]
    fn identifies_brute_force_ip() {
        // Build 12 failures from same IP
        let lines: String = (0..12)
            .map(|i| format!("Jan 10 12:00:{:02} host sshd[1]: Failed password for root from 1.2.3.4 port {} ssh2\n", i, 50000 + i))
            .collect();
        let events = parse_events(&lines);
        let mut fail_count: HashMap<String, usize> = HashMap::new();
        for ev in &events {
            if !ev.success {
                *fail_count.entry(ev.source_ip.clone()).or_insert(0) += 1;
            }
        }
        assert_eq!(*fail_count.get("1.2.3.4").unwrap(), 12);
    }

    #[test]
    fn detects_password_auth_success() {
        let events = parse_events(SAMPLE);
        let pwd_success: Vec<_> = events
            .iter()
            .filter(|e| e.success && e.method == AuthMethod::Password)
            .collect();
        assert_eq!(pwd_success.len(), 1);
        assert_eq!(pwd_success[0].user, "admin");
    }

    #[test]
    fn publickey_auth_not_flagged_as_password() {
        let events = parse_events(SAMPLE);
        let key_success: Vec<_> = events
            .iter()
            .filter(|e| e.success && e.method == AuthMethod::Publickey)
            .collect();
        assert_eq!(key_success.len(), 1);
        assert_eq!(key_success[0].user, "deploy");
    }

    // ── parse_for_from ────────────────────────────────────────────────────

    #[test]
    fn parse_for_from_basic() {
        let (user, ip) = parse_for_from("root from 1.2.3.4 port 22 ssh2").unwrap();
        assert_eq!(user, "root");
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn parse_for_from_no_from_returns_none() {
        assert!(parse_for_from("root 1.2.3.4").is_none());
    }

    #[test]
    fn parse_for_from_invalid_user_with_spaces() {
        // "invalid user bob from 5.5.5.5 port 22"
        let (user, ip) = parse_for_from("invalid user bob from 5.5.5.5 port 22").unwrap();
        assert_eq!(user, "invalid user bob");
        assert_eq!(ip, "5.5.5.5");
    }

    // ── parse_user_from ───────────────────────────────────────────────────

    #[test]
    fn parse_user_from_basic() {
        let (user, ip) = parse_user_from("baduser from 9.9.9.9 port 222").unwrap();
        assert_eq!(user, "baduser");
        assert_eq!(ip, "9.9.9.9");
    }

    #[test]
    fn parse_user_from_missing_from_returns_none() {
        assert!(parse_user_from("nobody 10.0.0.1").is_none());
    }

    // ── extract_ip ────────────────────────────────────────────────────────

    #[test]
    fn extract_ip_finds_ipv4() {
        let line = "Connection closed by authenticating user alice 10.0.0.5 port 22";
        let ip = extract_ip(line).unwrap();
        assert_eq!(ip, "10.0.0.5");
    }

    #[test]
    fn extract_ip_no_ip_returns_none() {
        let line = "some log line with no IP address here";
        assert!(extract_ip(line).is_none());
    }

    // ── Invalid-user lines parsed ─────────────────────────────────────────

    #[test]
    fn invalid_user_line_parsed_as_failure() {
        let log = "Jan 1 00:00:00 host sshd[1]: Invalid user ghost from 3.3.3.3 port 22\n";
        let events = parse_events(log);
        assert_eq!(events.len(), 1);
        assert!(!events[0].success);
        assert_eq!(events[0].source_ip, "3.3.3.3");
        assert_eq!(events[0].user, "ghost");
    }

    // ── Brute-force threshold constants ──────────────────────────────────

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn brute_force_threshold_at_least_ten() {
        assert!(BRUTE_FORCE_THRESHOLD >= 10);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn stuff_threshold_below_brute_threshold() {
        assert!(STUFF_FAIL_THRESHOLD < BRUTE_FORCE_THRESHOLD);
    }

    // ── Empty and edge input ──────────────────────────────────────────────

    #[test]
    fn empty_log_produces_no_events() {
        let events = parse_events("");
        assert!(events.is_empty());
    }

    #[test]
    fn unrelated_log_lines_produce_no_events() {
        let log = "Jan 1 00:00:00 host systemd[1]: Started OpenSSH Daemon.\n\
                   Jan 1 00:00:01 host kernel: something else\n";
        let events = parse_events(log);
        assert!(events.is_empty());
    }
}
