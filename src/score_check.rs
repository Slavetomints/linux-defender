//! Scored-service health checking.
//!
//! Polls each service every few seconds, verifies both connectivity and correct
//! protocol response (not just TCP open), tracks latency and uptime history,
//! and feeds the TUI dashboard pane.
//!
//! Check kinds:
//! - [`CheckKind::Tcp`] — TCP connect only (fast fallback)
//! - [`CheckKind::Http`] — send a raw HTTP/1.0 GET, verify the status code
//! - [`CheckKind::HttpCurl`] — `curl` over plain HTTP with redirect following (`-L`)
//! - [`CheckKind::Https`] — `curl` subprocess with SNI, verify status code
//! - [`CheckKind::Smtp`] — connect and read the greeting banner (`220 …`)
//! - [`CheckKind::Imap`] — connect and read the greeting banner (`* OK …`)
//! - [`CheckKind::Pop3`] — connect and read the greeting banner (`+OK …`)
//! - [`CheckKind::Dns`] — `dig` query, check for an ANSWER section

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

/// Path where score-check results are logged for post-mortem debugging.
pub const SCORE_LOG: &str = "/tmp/defender-score.log";

/// How the check verifies the service.
#[derive(Debug, Clone)]
pub enum CheckKind {
    /// TCP three-way handshake only.
    Tcp,
    /// Plain HTTP GET `path`; expects `expected_status`.
    Http {
        /// URL path to request, e.g. `"/"`.
        path: &'static str,
        /// HTTP status code that counts as "up", e.g. `200`.
        expected_status: u16,
    },
    /// Plain HTTP via `curl` with redirect following (`-L`); expects `expected_status`
    /// after all redirects. Use this instead of `Http` when the service redirects.
    HttpCurl {
        /// URL path to request.
        path: &'static str,
        /// HTTP status code that counts as "up" (final, after redirects).
        expected_status: u16,
    },
    /// HTTPS via `curl`; expects `expected_status`.
    Https {
        /// URL path to request.
        path: &'static str,
        /// HTTP status code that counts as "up".
        expected_status: u16,
    },
    /// SMTP: connect and expect a `220` greeting banner.
    Smtp,
    /// IMAP: connect and expect a `* OK` untagged greeting.
    Imap,
    /// POP3: connect and expect a `+OK` greeting.
    Pop3,
    /// DNS: run `dig @host query` and expect an ANSWER section.
    Dns {
        /// Query name, e.g. `"example.com"`.
        query: &'static str,
    },
}

/// One scored service to monitor.
#[derive(Debug, Clone)]
pub struct ServiceCheck {
    /// Short display name, e.g. `"HTTP"`.
    pub name: &'static str,
    /// IP or hostname to probe. Usually `"127.0.0.1"`.
    pub host: &'static str,
    /// Port to connect to.
    pub port: u16,
    /// How to verify the service is working.
    pub kind: CheckKind,
}

/// Result of a single poll of one service.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// True if the service responded correctly.
    pub up: bool,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Short human-readable detail: status code, banner excerpt, or error.
    pub detail: String,
    /// Wall time when the check ran.
    pub checked_at: SystemTime,
}

/// Running history for one service: the last 20 results.
pub struct ServiceHistory {
    /// The check definition.
    pub check: ServiceCheck,
    /// Circular buffer, newest last.
    results: VecDeque<CheckResult>,
}

/// Number of results kept per service.
const HISTORY_LEN: usize = 20;

/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Overall check timeout (read + connect).
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);

impl ServiceHistory {
    /// Create a new history with no results yet.
    pub fn new(check: ServiceCheck) -> Self {
        Self {
            check,
            results: VecDeque::with_capacity(HISTORY_LEN),
        }
    }

    /// Run the check now and record the result.
    pub fn poll(&mut self) {
        let result = run_check(&self.check);
        if self.results.len() >= HISTORY_LEN {
            self.results.pop_front();
        }
        self.results.push_back(result);
    }

    /// Fraction of recorded checks that were up (0.0–1.0).  Returns `None` if
    /// no checks have been run yet.
    pub fn uptime_fraction(&self) -> Option<f64> {
        if self.results.is_empty() {
            return None;
        }
        let up = self.results.iter().filter(|r| r.up).count();
        Some(up as f64 / self.results.len() as f64)
    }

    /// Average latency in ms across recorded checks.  Returns `None` when
    /// there are no results.
    pub fn avg_latency_ms(&self) -> Option<u64> {
        if self.results.is_empty() {
            return None;
        }
        let sum: u64 = self.results.iter().map(|r| r.latency_ms).sum();
        Some(sum / self.results.len() as u64)
    }

    /// The most recent result, or `None` if no check has run yet.
    pub fn last(&self) -> Option<&CheckResult> {
        self.results.back()
    }

    /// True if the last recorded result was up.
    pub fn is_up(&self) -> bool {
        self.last().map(|r| r.up).unwrap_or(false)
    }

    /// How many seconds ago the last check ran, or `None` if none has run.
    pub fn secs_since_last_check(&self) -> Option<u64> {
        let checked_at = self.last()?.checked_at;
        SystemTime::now()
            .duration_since(checked_at)
            .ok()
            .map(|d| d.as_secs())
    }
}

/// Build a `ServiceHistory` list from a slice of check definitions.
pub fn build_histories(checks: &[ServiceCheck]) -> Vec<ServiceHistory> {
    checks
        .iter()
        .map(|c| ServiceHistory::new(c.clone()))
        .collect()
}

/// Poll all histories and return a `(name, port, up)` summary compatible with
/// the legacy dashboard tuple.
pub fn poll_all(histories: &mut [ServiceHistory]) -> Vec<(&'static str, u16, bool)> {
    for h in histories.iter_mut() {
        h.poll();
    }
    histories
        .iter()
        .map(|h| (h.check.name, h.check.port, h.is_up()))
        .collect()
}

// ── Check dispatch ────────────────────────────────────────────────────────────

/// Run a single check and return its result.
fn run_check(svc: &ServiceCheck) -> CheckResult {
    let start = Instant::now();
    let (up, detail) = match &svc.kind {
        CheckKind::Tcp => check_tcp(svc.host, svc.port),
        CheckKind::Http {
            path,
            expected_status,
        } => check_http(svc.host, svc.port, path, *expected_status),
        CheckKind::HttpCurl {
            path,
            expected_status,
        } => check_http_curl(svc.host, svc.port, path, *expected_status),
        CheckKind::Https {
            path,
            expected_status,
        } => check_https(svc.host, svc.port, path, *expected_status),
        CheckKind::Smtp => check_smtp(svc.host, svc.port),
        CheckKind::Imap => check_imap(svc.host, svc.port),
        CheckKind::Pop3 => check_pop3(svc.host, svc.port),
        CheckKind::Dns { query } => check_dns(svc.host, svc.port, query),
    };
    let latency_ms = start.elapsed().as_millis() as u64;
    log_check_result(svc, up, latency_ms, &detail);
    CheckResult {
        up,
        latency_ms,
        detail,
        checked_at: SystemTime::now(),
    }
}

/// Append one line to [`SCORE_LOG`] for every check result so failures can be
/// diagnosed without needing to read TUI detail (which isn't rendered).
fn log_check_result(svc: &ServiceCheck, up: bool, latency_ms: u64, detail: &str) {
    use std::time::UNIX_EPOCH;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let status = if up { "UP  " } else { "DOWN" };
    let line = format!(
        "[{ts}] {status} {name:<16} :{port:<5} {latency_ms:>4}ms  {detail}\n",
        name = svc.name,
        port = svc.port,
    );
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(SCORE_LOG) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// TCP connect only.
fn check_tcp(host: &str, port: u16) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    match addr.parse::<SocketAddr>() {
        Ok(sa) => match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
            Ok(_) => (true, "TCP OK".into()),
            Err(e) => (false, format!("TCP error: {}", e)),
        },
        Err(_) => {
            // host might be a hostname — fall back to std connect
            match TcpStream::connect(&addr as &str) {
                Ok(_) => (true, "TCP OK".into()),
                Err(e) => (false, format!("TCP error: {}", e)),
            }
        }
    }
}

/// Raw HTTP/1.0 GET over plain TCP.
fn check_http(host: &str, port: u16, path: &str, expected: u16) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return (false, "write failed".into());
    }
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    let status = parse_http_status(&resp);
    match status {
        Some(code) => (code == expected, format!("HTTP {}", code)),
        None => (
            false,
            format!(
                "bad response: {}",
                resp.chars().take(40).collect::<String>()
            ),
        ),
    }
}

/// Plain HTTP GET with redirect following (up to 5 hops), pure Rust — no curl.
///
/// Used for services that redirect on the root path (e.g. Splunk web on port 8000:
/// `GET /` → 303 → `/en-US/` → 303 → `/en-US/account/login` → 200).
fn check_http_curl(host: &str, port: u16, path: &str, expected: u16) -> (bool, String) {
    let mut cur_host = host.to_string();
    let mut cur_port = port;
    let mut cur_path = path.to_string();

    for _ in 0..5 {
        let addr = format!("{}:{}", cur_host, cur_port);
        let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
            Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
            Err(_) => TcpStream::connect(&addr as &str),
        }) else {
            return (false, format!("TCP connect failed ({}:{})", cur_host, cur_port));
        };
        let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
        let request = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            cur_path, cur_host
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return (false, "write failed".into());
        }
        // 4 KiB is enough to capture all response headers.
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        let resp = String::from_utf8_lossy(&buf[..n]);
        let status = match parse_http_status(&resp) {
            Some(s) => s,
            None => {
                return (
                    false,
                    format!("bad response: {}", resp.chars().take(40).collect::<String>()),
                )
            }
        };

        if (300..400).contains(&status) {
            if let Some(loc) = parse_location_header(&resp) {
                if let Some((h, p, pth)) = parse_http_url(&loc, &cur_host, cur_port) {
                    cur_host = h;
                    cur_port = p;
                    cur_path = pth;
                    continue;
                }
            }
            return (false, format!("HTTP {} (no Location)", status));
        }

        return (status == expected, format!("HTTP {}", status));
    }

    (false, "too many redirects".into())
}

/// Extract the value of the `Location:` header from a raw HTTP response.
fn parse_location_header(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("location:") {
            Some(line[9..].trim().to_string())
        } else {
            None
        }
    })
}

/// Parse an HTTP URL (absolute or root-relative) into `(host, port, path)`.
///
/// Absolute `https://` URLs are rejected — we only follow plain HTTP redirects.
/// Relative paths (starting with `/`) reuse the caller's host and port.
fn parse_http_url(url: &str, default_host: &str, default_port: u16) -> Option<(String, u16, String)> {
    if url.starts_with('/') {
        return Some((default_host.to_string(), default_port, url.to_string()));
    }
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest
        .find('/')
        .map(|i| (&rest[..i], rest[i..].to_string()))
        .unwrap_or((rest, "/".to_string()));
    let (host, port) = if let Some(colon) = authority.rfind(':') {
        let port_str = &authority[colon + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            (&authority[..colon], p)
        } else {
            (authority, 80u16)
        }
    } else {
        (authority, 80u16)
    };
    Some((host.to_string(), port, path))
}

/// HTTPS check via `curl`.
fn check_https(host: &str, port: u16, path: &str, expected: u16) -> (bool, String) {
    let url = format!("https://{}:{}{}", host, port, path);
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-L",            // follow redirects (Splunk 303 → /en-US/account/login)
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "3",
            "--insecure", // competition certs are self-signed
            &url,
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let code_str = String::from_utf8_lossy(&o.stdout);
            let code: u16 = code_str.trim().parse().unwrap_or(0);
            (code == expected, format!("HTTPS {}", code))
        }
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            (
                false,
                format!("curl error: {}", msg.chars().take(40).collect::<String>()),
            )
        }
        Err(e) => (false, format!("curl not found: {}", e)),
    }
}

/// SMTP banner check: connect and expect `220 `.
fn check_smtp(host: &str, port: u16) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);
    let first_line = banner.lines().next().unwrap_or("").trim();
    if first_line.starts_with("220") {
        (true, first_line.chars().take(50).collect())
    } else {
        (
            false,
            format!(
                "unexpected banner: {}",
                first_line.chars().take(40).collect::<String>()
            ),
        )
    }
}

/// IMAP greeting check: connect and expect `* OK`.
fn check_imap(host: &str, port: u16) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);
    let first = banner.lines().next().unwrap_or("").trim();
    if first.starts_with("* OK") {
        (true, first.chars().take(50).collect())
    } else {
        (
            false,
            format!(
                "unexpected banner: {}",
                first.chars().take(40).collect::<String>()
            ),
        )
    }
}

/// POP3 greeting check: connect and expect `+OK`.
fn check_pop3(host: &str, port: u16) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);
    let first = banner.lines().next().unwrap_or("").trim();
    if first.starts_with("+OK") {
        (true, first.chars().take(50).collect())
    } else {
        (
            false,
            format!(
                "unexpected banner: {}",
                first.chars().take(40).collect::<String>()
            ),
        )
    }
}

/// DNS check via `dig @host query`. Passes if the reply contains `ANSWER SECTION`.
fn check_dns(host: &str, port: u16, query: &str) -> (bool, String) {
    let server = format!("@{}:{}", host, port);
    let out = std::process::Command::new("dig")
        .args([&server, query, "+time=2", "+tries=1"])
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("ANSWER SECTION") {
                (true, "DNS ANSWER".into())
            } else if stdout.contains("NXDOMAIN") {
                (false, "NXDOMAIN".into())
            } else {
                (false, "no answer section".into())
            }
        }
        Err(e) => (false, format!("dig not found: {}", e)),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse the HTTP status code from the first line of a response.
/// Returns `None` if the line is not a valid HTTP status line.
pub fn parse_http_status(response: &str) -> Option<u16> {
    // "HTTP/1.x NNN …"
    let first = response.lines().next()?;
    let mut parts = first.splitn(3, ' ');
    parts.next()?; // "HTTP/1.x"
    parts.next()?.parse().ok()
}

// ── Default service lists by BoxType ─────────────────────────────────────────

/// Scored services for a web box.
pub const WEB_CHECKS: &[ServiceCheck] = &[
    ServiceCheck {
        name: "HTTP",
        host: "127.0.0.1",
        port: 80,
        kind: CheckKind::Http {
            path: "/",
            expected_status: 200,
        },
    },
    ServiceCheck {
        name: "HTTPS",
        host: "127.0.0.1",
        port: 443,
        kind: CheckKind::Https {
            path: "/",
            expected_status: 200,
        },
    },
    ServiceCheck {
        name: "SSH",
        host: "127.0.0.1",
        port: 22,
        kind: CheckKind::Tcp,
    },
];

/// Scored services for a mail box.
pub const MAIL_CHECKS: &[ServiceCheck] = &[
    ServiceCheck {
        name: "Postfix SMTP",
        host: "127.0.0.1",
        port: 25,
        kind: CheckKind::Smtp,
    },
    ServiceCheck {
        name: "Postfix Subm",
        host: "127.0.0.1",
        port: 587,
        kind: CheckKind::Smtp,
    },
    ServiceCheck {
        name: "Dovecot IMAP",
        host: "127.0.0.1",
        port: 143,
        kind: CheckKind::Imap,
    },
    ServiceCheck {
        name: "Dovecot IMAPS",
        host: "127.0.0.1",
        port: 993,
        kind: CheckKind::Imap,
    },
    ServiceCheck {
        name: "Dovecot POP3",
        host: "127.0.0.1",
        port: 110,
        kind: CheckKind::Pop3,
    },
    ServiceCheck {
        name: "Dovecot POP3S",
        host: "127.0.0.1",
        port: 995,
        kind: CheckKind::Pop3,
    },
    ServiceCheck {
        name: "Roundcube",
        host: "127.0.0.1",
        port: 80,
        kind: CheckKind::Http {
            path: "/",
            expected_status: 200,
        },
    },
    ServiceCheck {
        name: "SSH",
        host: "127.0.0.1",
        port: 22,
        kind: CheckKind::Tcp,
    },
];

/// Scored services for a Splunk box.
pub const SPLUNK_CHECKS: &[ServiceCheck] = &[
    ServiceCheck {
        name: "Splunk Web",
        host: "127.0.0.1",
        port: 8000,
        // Splunk web is plain HTTP (not HTTPS) on port 8000.
        // GET / → 303 → /en-US/ → 303 → /en-US/account/login → 200.
        // HttpCurl follows the redirect chain with curl -L over http://.
        kind: CheckKind::HttpCurl {
            path: "/",
            expected_status: 200,
        },
    },
    ServiceCheck {
        name: "Splunk Mgmt",
        host: "127.0.0.1",
        port: 8089,
        kind: CheckKind::Tcp,
    },
    ServiceCheck {
        name: "SSH",
        host: "127.0.0.1",
        port: 22,
        kind: CheckKind::Tcp,
    },
];

/// Scored services for a general-purpose box.
pub const GENERAL_CHECKS: &[ServiceCheck] = &[ServiceCheck {
    name: "SSH",
    host: "127.0.0.1",
    port: 22,
    kind: CheckKind::Tcp,
}];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_200() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK\r\n"), Some(200));
    }

    #[test]
    fn parse_http_status_404() {
        assert_eq!(parse_http_status("HTTP/1.0 404 Not Found\r\n"), Some(404));
    }

    #[test]
    fn parse_http_status_empty() {
        assert_eq!(parse_http_status(""), None);
    }

    #[test]
    fn parse_http_status_garbage() {
        assert_eq!(parse_http_status("not http"), None);
    }

    #[test]
    fn service_history_starts_empty() {
        let h = ServiceHistory::new(ServiceCheck {
            name: "test",
            host: "127.0.0.1",
            port: 9,
            kind: CheckKind::Tcp,
        });
        assert!(h.last().is_none());
        assert!(h.uptime_fraction().is_none());
        assert!(h.avg_latency_ms().is_none());
        assert!(!h.is_up());
    }

    #[test]
    fn uptime_fraction_all_up() {
        let mut h = ServiceHistory::new(ServiceCheck {
            name: "test",
            host: "127.0.0.1",
            port: 9,
            kind: CheckKind::Tcp,
        });
        for _ in 0..4 {
            h.results.push_back(CheckResult {
                up: true,
                latency_ms: 10,
                detail: "OK".into(),
                checked_at: SystemTime::now(),
            });
        }
        assert_eq!(h.uptime_fraction(), Some(1.0));
    }

    #[test]
    fn uptime_fraction_half() {
        let mut h = ServiceHistory::new(ServiceCheck {
            name: "test",
            host: "127.0.0.1",
            port: 9,
            kind: CheckKind::Tcp,
        });
        for i in 0..4 {
            h.results.push_back(CheckResult {
                up: i % 2 == 0,
                latency_ms: 5,
                detail: "x".into(),
                checked_at: SystemTime::now(),
            });
        }
        assert_eq!(h.uptime_fraction(), Some(0.5));
    }

    #[test]
    fn history_ring_buffer_caps_at_history_len() {
        let mut h = ServiceHistory::new(ServiceCheck {
            name: "test",
            host: "127.0.0.1",
            port: 9,
            kind: CheckKind::Tcp,
        });
        for _ in 0..(HISTORY_LEN + 5) {
            h.results.push_back(CheckResult {
                up: true,
                latency_ms: 1,
                detail: "x".into(),
                checked_at: SystemTime::now(),
            });
            if h.results.len() > HISTORY_LEN {
                h.results.pop_front();
            }
        }
        assert_eq!(h.results.len(), HISTORY_LEN);
    }

    #[test]
    fn build_histories_creates_one_per_check() {
        let checks = WEB_CHECKS;
        let histories = build_histories(checks);
        assert_eq!(histories.len(), checks.len());
        assert!(histories.iter().all(|h| h.last().is_none()));
    }

    #[test]
    fn check_constants_cover_all_box_types() {
        assert!(!WEB_CHECKS.is_empty());
        assert!(!MAIL_CHECKS.is_empty());
        assert!(!SPLUNK_CHECKS.is_empty());
        assert!(!GENERAL_CHECKS.is_empty());
        // SSH is always present
        assert!(WEB_CHECKS.iter().any(|c| c.port == 22));
        assert!(MAIL_CHECKS.iter().any(|c| c.port == 22));
        assert!(SPLUNK_CHECKS.iter().any(|c| c.port == 22));
        assert!(GENERAL_CHECKS.iter().any(|c| c.port == 22));
    }
}
