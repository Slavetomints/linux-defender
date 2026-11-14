//! Web server access log analysis.
//!
//! Parses Nginx or Apache Combined Log Format access logs to detect directory
//! traversal attempts, webshell parameter access, known scanner user-agents,
//! script downloads, and 404-storm scanners.  Reads the last 5000 lines only.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Candidate access log paths, tried in order.
const ACCESS_LOG_CANDIDATES: &[&str] = &[
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
];

/// Number of recent lines to analyse.
const MAX_LINES: usize = 5000;

/// Number of 404 responses from one IP that constitutes a scanner.
const SCANNER_404_THRESHOLD: usize = 20;

/// Query-string parameter names that indicate webshell execution attempts.
const WEBSHELL_PARAMS: &[&str] = &["cmd=", "exec=", "system=", "passthru=", "shell_exec="];

/// User-agent substrings that identify known scanning tools.
const SCANNER_UA: &[&str] = &["sqlmap", "nikto", "nessus", "masscan", "zaproxy", "burp"];

/// File extensions that suggest a script was served to the attacker.
const SCRIPT_EXTENSIONS: &[&str] = &[".sh", ".bash", ".py", ".pl", ".rb"];

/// A single parsed access log entry.
pub struct AccessEntry {
    /// Source IP address.
    pub ip: String,
    /// HTTP method (GET, POST, …).
    pub method: String,
    /// Request path, without query string.
    pub path: String,
    /// Full request URI including query string.
    pub uri: String,
    /// HTTP response status code.
    pub status: u16,
    /// User-agent string, or empty.
    pub ua: String,
}

/// Parse one Combined Log Format line into an [`AccessEntry`].
///
/// Returns `None` for lines that do not match the expected format.
pub fn parse_line(line: &str) -> Option<AccessEntry> {
    // Combined Log Format:
    // IP - ident [timestamp] "METHOD URI HTTP/x.x" status bytes "referer" "ua"
    let ip = line.split_whitespace().next()?.to_string();

    // Find the quoted request field
    let req_start = line.find('"')?;
    let req_end = line[req_start + 1..].find('"')? + req_start + 1;
    let request = &line[req_start + 1..req_end];

    let mut req_parts = request.splitn(3, ' ');
    let method = req_parts.next()?.to_string();
    let uri = req_parts.next()?.to_string();

    let (path, _query) = if let Some(q) = uri.find('?') {
        (&uri[..q], &uri[q + 1..])
    } else {
        (uri.as_str(), "")
    };

    // Status code comes after the closing quote + space + space
    let after_request = &line[req_end + 1..].trim_start();
    let status: u16 = after_request.split_whitespace().next()?.parse().ok()?;

    // User-agent is the last quoted field
    let ua = {
        let mut last_quote_start = None;
        let mut pos = line.len();
        // Walk backwards: find the last '"…"' pair
        if line.ends_with('"') {
            pos -= 1;
            if let Some(start) = line[..pos].rfind('"') {
                last_quote_start = Some(&line[start + 1..pos]);
            }
        }
        last_quote_start.map(|s| s.to_string()).unwrap_or_default()
    };

    Some(AccessEntry {
        ip,
        method,
        path: path.to_string(),
        uri: uri.clone(),
        status,
        ua,
    })
}

/// Return `true` if the path/URI suggests a directory traversal attempt.
pub fn is_traversal(uri: &str) -> bool {
    uri.contains("..")
}

/// Return `true` if the request looks like a webshell parameter probe.
pub fn is_webshell_probe(entry: &AccessEntry) -> bool {
    if !entry.path.contains(".php") {
        return false;
    }
    let uri_lower = entry.uri.to_lowercase();
    WEBSHELL_PARAMS.iter().any(|p| uri_lower.contains(p))
}

/// Return `true` if the user-agent matches a known scanner.
pub fn is_scanner_ua(ua: &str) -> bool {
    let lower = ua.to_lowercase();
    SCANNER_UA.iter().any(|s| lower.contains(s))
}

/// Return `true` if a 200-OK response served a script file.
pub fn is_script_download(entry: &AccessEntry) -> bool {
    entry.status == 200
        && SCRIPT_EXTENSIONS
            .iter()
            .any(|ext| entry.path.ends_with(ext))
}

/// Analyse access log contents and return structured findings.
pub fn analyse(contents: &str) -> Vec<(Severity, String, String)> {
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(MAX_LINES);
    let recent = &lines[start..];

    let mut findings: Vec<(Severity, String, String)> = Vec::new();
    let mut not_found_by_ip: HashMap<String, usize> = HashMap::new();

    for line in recent {
        let Some(entry) = parse_line(line) else {
            continue;
        };

        if is_traversal(&entry.uri) {
            findings.push((
                Severity::High,
                format!(
                    "Directory traversal: {} {} ({})",
                    entry.method, entry.uri, entry.ip
                ),
                format!(
                    "ip: {}\nmethod: {}\nuri: {}\nstatus: {}",
                    entry.ip, entry.method, entry.uri, entry.status
                ),
            ));
        } else if is_webshell_probe(&entry) {
            findings.push((
                Severity::High,
                format!(
                    "Webshell probe: {} {} ({})",
                    entry.method, entry.uri, entry.ip
                ),
                format!(
                    "ip: {}\nmethod: {}\nuri: {}\nstatus: {}",
                    entry.ip, entry.method, entry.uri, entry.status
                ),
            ));
        } else if is_scanner_ua(&entry.ua) {
            findings.push((
                Severity::High,
                format!(
                    "Scanner UA from {}: {}",
                    entry.ip,
                    crate::core::truncate_chars(&entry.ua, 80)
                ),
                format!(
                    "ip: {}\nua: {}\nuri: {}\nstatus: {}",
                    entry.ip, entry.ua, entry.uri, entry.status
                ),
            ));
        } else if is_script_download(&entry) {
            findings.push((
                Severity::Medium,
                format!(
                    "Script download: {} {} ({})",
                    entry.method, entry.path, entry.ip
                ),
                format!(
                    "ip: {}\npath: {}\nstatus: {}\nmethod: {}",
                    entry.ip, entry.path, entry.status, entry.method
                ),
            ));
        }

        if entry.status == 404 {
            *not_found_by_ip.entry(entry.ip.clone()).or_insert(0) += 1;
        }
    }

    // 404-storm scanners
    let mut scanner_ips: Vec<(&String, usize)> = not_found_by_ip
        .iter()
        .filter(|(_, count)| **count >= SCANNER_404_THRESHOLD)
        .map(|(ip, count)| (ip, *count))
        .collect();
    scanner_ips.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    for (ip, count) in scanner_ips {
        findings.push((
            Severity::Medium,
            format!(
                "404 scanner: {} generated {} not-found responses",
                ip, count
            ),
            format!("ip: {}\nnot_found_count: {}", ip, count),
        ));
    }

    findings
}

/// Run access log analysis and emit findings via `ctx`.
pub fn run(ctx: &DefenderContext) -> Result {
    let log_path = ACCESS_LOG_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .copied();

    let Some(path) = log_path else {
        ctx.log_msg("[!] No web access log found — skipping");
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
        ctx.emit(Finding::new(severity, "access_log", summary, detail));
    }

    ctx.log_msg(&format!(
        "[✓] Access log analysis complete — {} finding(s)",
        count
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Combined Log Format lines for testing.
    const SAMPLE: &str = concat!(
        r#"10.0.0.1 - - [01/Jan/2024:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0""#,
        "\n",
        r#"10.0.0.2 - - [01/Jan/2024:00:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 200 0 "-" "curl/7.68""#,
        "\n",
        r#"10.0.0.3 - - [01/Jan/2024:00:00:03 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 10 "-" "python-requests""#,
        "\n",
        r#"10.0.0.4 - - [01/Jan/2024:00:00:04 +0000] "GET /download.sh HTTP/1.1" 200 1000 "-" "wget/1.21""#,
        "\n",
        r#"10.0.0.5 - - [01/Jan/2024:00:00:05 +0000] "GET /robots.txt HTTP/1.1" 200 50 "-" "sqlmap/1.7""#,
        "\n",
    );

    #[test]
    fn parse_line_basic() {
        let line =
            r#"1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] "GET /foo HTTP/1.1" 200 100 "-" "Mozilla""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "1.2.3.4");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/foo");
        assert_eq!(entry.status, 200);
    }

    #[test]
    fn parse_line_with_query_string() {
        let line = r#"1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] "GET /search?q=foo HTTP/1.1" 200 100 "-" "Agent""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.path, "/search");
        assert_eq!(entry.uri, "/search?q=foo");
    }

    #[test]
    fn parse_line_garbage_returns_none() {
        assert!(parse_line("this is not a log line").is_none());
    }

    #[test]
    fn is_traversal_detects_dotdot() {
        assert!(is_traversal("/../../etc/passwd"));
        assert!(!is_traversal("/normal/path"));
    }

    #[test]
    fn is_webshell_probe_detects_cmd_param() {
        let entry = AccessEntry {
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/shell.php".into(),
            uri: "/shell.php?cmd=whoami".into(),
            status: 200,
            ua: "curl".into(),
        };
        assert!(is_webshell_probe(&entry));
    }

    #[test]
    fn is_webshell_probe_ignores_non_php() {
        let entry = AccessEntry {
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/page.html".into(),
            uri: "/page.html?cmd=foo".into(),
            status: 200,
            ua: "curl".into(),
        };
        assert!(!is_webshell_probe(&entry));
    }

    #[test]
    fn is_scanner_ua_matches_known_tools() {
        assert!(is_scanner_ua("sqlmap/1.7"));
        assert!(is_scanner_ua("Mozilla Nikto/2.1"));
        assert!(!is_scanner_ua("Mozilla/5.0 Firefox"));
    }

    #[test]
    fn is_script_download_detects_sh() {
        let entry = AccessEntry {
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/evil.sh".into(),
            uri: "/evil.sh".into(),
            status: 200,
            ua: "curl".into(),
        };
        assert!(is_script_download(&entry));
    }

    #[test]
    fn is_script_download_ignores_404() {
        let entry = AccessEntry {
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/evil.sh".into(),
            uri: "/evil.sh".into(),
            status: 404,
            ua: "curl".into(),
        };
        assert!(!is_script_download(&entry));
    }

    #[test]
    fn analyse_sample_finds_traversal_and_webshell() {
        let results = analyse(SAMPLE);
        let severities: Vec<Severity> = results.iter().map(|(s, _, _)| *s).collect();
        let summaries: Vec<&str> = results.iter().map(|(_, s, _)| s.as_str()).collect();
        assert!(
            summaries.iter().any(|s| s.contains("traversal")),
            "should flag traversal"
        );
        assert!(
            summaries.iter().any(|s| s.contains("Webshell")),
            "should flag webshell"
        );
        assert!(
            summaries.iter().any(|s| s.contains("Scanner UA")),
            "should flag scanner UA"
        );
        assert!(
            summaries.iter().any(|s| s.contains("Script")),
            "should flag script download"
        );
        assert!(severities.iter().any(|s| matches!(s, Severity::High)));
    }

    #[test]
    fn analyse_empty_log_returns_no_findings() {
        let results = analyse("");
        assert!(results.is_empty());
    }

    #[test]
    fn analyse_404_storm_flagged() {
        let lines: String = (0..25)
            .map(|i| {
                format!(
                    r#"5.5.5.5 - - [01/Jan/2024:00:00:{:02} +0000] "GET /probe{} HTTP/1.1" 404 0 "-" "curl""#,
                    i % 60,
                    i
                ) + "\n"
            })
            .collect();
        let results = analyse(&lines);
        assert!(
            results.iter().any(|(_, s, _)| s.contains("404 scanner")),
            "should flag 404 scanner"
        );
    }

    #[test]
    fn scanner_404_threshold_reasonable() {
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(SCANNER_404_THRESHOLD >= 10);
        }
    }
}
