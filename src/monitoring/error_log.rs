//! Web server error log analysis.
//!
//! Parses Nginx or Apache error logs to surface exploitation indicators: CGI
//! code-execution attempts, directory traversal via error messages, paths
//! outside the web root being probed, and repeat offenders.  Reads the last
//! 5000 lines only.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Candidate error log paths, tried in order.
const ERROR_LOG_CANDIDATES: &[&str] = &[
    "/var/log/nginx/error.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
];

/// Number of recent lines to analyse.
const MAX_LINES: usize = 5000;

/// Number of error lines from one IP that triggers a repeat-offender finding.
const REPEAT_OFFENDER_THRESHOLD: usize = 50;

/// Patterns that indicate code execution through a CGI or PHP interpreter.
const CODE_EXEC_PATTERNS: &[&str] = &["FastCGI", "PHP", "eval("];

/// Substrings indicating a sensitive path was probed via an error.
const SENSITIVE_PATH_PREFIXES: &[&str] = &["/etc/", "/root/"];

/// Substrings indicating WAF triggered — useful situational awareness.
const WAF_PATTERNS: &[&str] = &["mod_security", "modsecurity"];

/// Return `true` if the error line indicates a code-execution attempt.
pub fn is_code_exec(line: &str) -> bool {
    CODE_EXEC_PATTERNS.iter().any(|p| line.contains(p))
}

/// Return `true` if the error line indicates a permission-denied read of a
/// sensitive path (`/etc/` or `/root/`).
pub fn is_sensitive_path_probe(line: &str) -> bool {
    line.contains("Permission denied")
        && SENSITIVE_PATH_PREFIXES
            .iter()
            .any(|prefix| line.contains(prefix))
}

/// Return `true` if the error line contains a directory-traversal marker.
pub fn is_traversal_error(line: &str) -> bool {
    line.to_lowercase().contains("invalid uri") && line.contains("../")
}

/// Return `true` if the error line shows a WAF rule triggered.
pub fn is_waf_triggered(line: &str) -> bool {
    let lower = line.to_lowercase();
    WAF_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Extract a client IP from a Nginx or Apache error line, if present.
///
/// Nginx format:  `... client: 1.2.3.4, ...`
/// Apache format: `[client 1.2.3.4] ...`
pub fn extract_client_ip(line: &str) -> Option<String> {
    // Nginx: "client: 1.2.3.4,"
    if let Some(idx) = line.find("client: ") {
        let rest = &line[idx + 8..];
        let ip = rest.split([',', ' ', ']']).next()?;
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }
    // Apache: "[client 1.2.3.4]"
    if let Some(idx) = line.find("[client ") {
        let rest = &line[idx + 8..];
        let ip = rest.split([']', ' ']).next()?;
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }
    None
}

/// Analyse error log contents and return structured findings.
pub fn analyse(contents: &str) -> Vec<(Severity, String, String)> {
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(MAX_LINES);
    let recent = &lines[start..];

    let mut findings: Vec<(Severity, String, String)> = Vec::new();
    let mut errors_by_ip: HashMap<String, usize> = HashMap::new();

    for line in recent {
        // Track per-IP error counts
        if let Some(ip) = extract_client_ip(line) {
            *errors_by_ip.entry(ip).or_insert(0) += 1;
        }

        if is_code_exec(line) {
            findings.push((
                Severity::High,
                format!(
                    "CGI/PHP error — possible code execution: {}",
                    crate::core::truncate_chars(line, 120)
                ),
                format!("line: {}", line),
            ));
        } else if is_sensitive_path_probe(line) {
            findings.push((
                Severity::High,
                format!(
                    "Permission denied on sensitive path: {}",
                    crate::core::truncate_chars(line, 120)
                ),
                format!("line: {}", line),
            ));
        } else if is_traversal_error(line) {
            findings.push((
                Severity::High,
                format!(
                    "Traversal attempt in error log: {}",
                    crate::core::truncate_chars(line, 120)
                ),
                format!("line: {}", line),
            ));
        } else if is_waf_triggered(line) {
            findings.push((
                Severity::Medium,
                format!(
                    "WAF rule triggered: {}",
                    crate::core::truncate_chars(line, 120)
                ),
                format!("line: {}", line),
            ));
        }
    }

    // Repeat offenders
    let mut repeat: Vec<(&String, usize)> = errors_by_ip
        .iter()
        .filter(|(_, count)| **count >= REPEAT_OFFENDER_THRESHOLD)
        .map(|(ip, count)| (ip, *count))
        .collect();
    repeat.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    for (ip, count) in repeat {
        findings.push((
            Severity::Medium,
            format!(
                "Repeat error source: {} generated {} error lines",
                ip, count
            ),
            format!("ip: {}\nerror_count: {}", ip, count),
        ));
    }

    findings
}

/// Run error log analysis and emit findings via `ctx`.
pub fn run(ctx: &DefenderContext) -> Result {
    let log_path = ERROR_LOG_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .copied();

    let Some(path) = log_path else {
        ctx.log_msg("[!] No web error log found — skipping");
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

    let results = analyse(&contents);
    let count = results.len();
    for (severity, summary, detail) in results {
        ctx.emit(Finding::new(severity, "error_log", summary, detail));
    }

    ctx.log_msg(&format!(
        "[✓] Error log analysis complete — {} finding(s)",
        count
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_code_exec_detects_fastcgi() {
        assert!(is_code_exec(
            "2024/01/01 00:00:00 [error] recv() failed: FastCGI timeout"
        ));
    }

    #[test]
    fn is_code_exec_detects_php() {
        assert!(is_code_exec(
            "PHP Fatal error: Uncaught Error: Call to undefined function"
        ));
    }

    #[test]
    fn is_code_exec_does_not_match_harmless() {
        assert!(!is_code_exec("connection timed out from 1.2.3.4"));
    }

    #[test]
    fn is_sensitive_path_probe_etc() {
        assert!(is_sensitive_path_probe(
            "[client 1.2.3.4] Permission denied: /etc/shadow"
        ));
    }

    #[test]
    fn is_sensitive_path_probe_root() {
        assert!(is_sensitive_path_probe(
            "[client 1.2.3.4] Permission denied: /root/.ssh/id_rsa"
        ));
    }

    #[test]
    fn is_sensitive_path_probe_no_match_without_permission_denied() {
        assert!(!is_sensitive_path_probe("file not found /etc/nginx.conf"));
    }

    #[test]
    fn is_traversal_error_matches() {
        assert!(is_traversal_error(
            "invalid URI: /../../etc/passwd is invalid"
        ));
    }

    #[test]
    fn is_traversal_error_no_dotdot() {
        assert!(!is_traversal_error("invalid URI format"));
    }

    #[test]
    fn is_waf_triggered_lowercase() {
        assert!(is_waf_triggered("ModSecurity: Access denied"));
    }

    #[test]
    fn is_waf_triggered_no_match() {
        assert!(!is_waf_triggered("normal 404 not found"));
    }

    #[test]
    fn extract_client_ip_nginx_format() {
        let line = "2024/01/01 00:00:00 [error] 123#0: *1 ... client: 10.0.0.1, server:";
        assert_eq!(extract_client_ip(line).unwrap(), "10.0.0.1");
    }

    #[test]
    fn extract_client_ip_apache_format() {
        let line = "[Mon Jan 01 00:00:00 2024] [error] [client 192.168.1.5] File not found";
        assert_eq!(extract_client_ip(line).unwrap(), "192.168.1.5");
    }

    #[test]
    fn extract_client_ip_no_ip() {
        assert!(extract_client_ip("no client info here").is_none());
    }

    #[test]
    fn analyse_flags_high_findings() {
        let log = concat!(
            "2024/01/01 [error] FastCGI upstream timed out\n",
            "[Mon Jan 01] [error] [client 1.2.3.4] Permission denied: /etc/shadow\n",
            "2024/01/01 [error] invalid URI: /../../etc/passwd is invalid\n",
        );
        let results = analyse(log);
        let highs: Vec<_> = results
            .iter()
            .filter(|(s, _, _)| matches!(s, Severity::High))
            .collect();
        assert_eq!(highs.len(), 3);
    }

    #[test]
    fn analyse_empty_log_returns_no_findings() {
        assert!(analyse("").is_empty());
    }

    #[test]
    fn analyse_repeat_offender_flagged() {
        let lines: String = (0..60)
            .map(|_| "[Mon Jan 01] [error] [client 9.9.9.9] something failed\n".to_string())
            .collect();
        let results = analyse(&lines);
        assert!(
            results.iter().any(|(_, s, _)| s.contains("Repeat")),
            "repeat offender should be flagged"
        );
    }

    #[test]
    fn repeat_offender_threshold_reasonable() {
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(REPEAT_OFFENDER_THRESHOLD >= 20);
        }
    }
}
