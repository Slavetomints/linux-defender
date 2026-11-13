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
//! - [`CheckKind::SmtpSend`] — full EHLO + MAIL FROM + RCPT TO transaction
//! - [`CheckKind::Imap`] — connect and read the greeting banner (`* OK …`)
//! - [`CheckKind::ImapLogin`] — full IMAP LOGIN and SELECT INBOX
//! - [`CheckKind::Pop3`] — connect and read the greeting banner (`+OK …`)
//! - [`CheckKind::Pop3Login`] — full POP3 USER/PASS login and STAT
//! - [`CheckKind::Dns`] — `dig` query, check for an ANSWER section

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

/// Path where score-check results are logged for post-mortem debugging.
pub const SCORE_LOG: &str = "/tmp/defender-score.log";

/// Which external HTTP client is available on this machine.
enum ExtHttpClient {
    /// The `curl` HTTP client.
    Curl,
    /// The `wget` HTTP client.
    Wget,
    /// No HTTP client is available.
    None,
}

/// Detect curl → wget → neither, cached for the process lifetime.
fn ext_http_client() -> &'static ExtHttpClient {
    static CLIENT: OnceLock<ExtHttpClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        if cmd_exists("curl") {
            ExtHttpClient::Curl
        } else if cmd_exists("wget") {
            ExtHttpClient::Wget
        } else {
            ExtHttpClient::None
        }
    })
}

/// True if `name` resolves to an executable via PATH.
fn cmd_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

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
    /// SMTP functional: EHLO → MAIL FROM → RCPT TO → QUIT (no auth required).
    SmtpSend {
        /// Envelope sender, e.g. `"scorer@localhost"`.
        from: &'static str,
        /// Envelope recipient, e.g. `"sysadmin@localhost"`.
        to: &'static str,
    },
    /// IMAP: connect and expect a `* OK` untagged greeting.
    Imap,
    /// IMAP functional: LOGIN then SELECT INBOX (password from [`mail_check_pass`]).
    ImapLogin {
        /// System account username to log in as.
        user: &'static str,
    },
    /// POP3: connect and expect a `+OK` greeting.
    Pop3,
    /// POP3 functional: USER + PASS login then STAT (password from [`mail_check_pass`]).
    Pop3Login {
        /// System account username to log in as.
        user: &'static str,
    },
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

/// Create (or reset) the dedicated mail-check account so IMAP/POP3 functional
/// checks always have a working set of credentials.  Safe to call repeatedly —
/// it is a no-op if the account already exists with the right password.
pub fn ensure_mail_test_account() {
    // Create the user if absent (no home dir needed; /sbin/nologin shell).
    let exists = std::process::Command::new("id")
        .arg(MAIL_TEST_USER)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !exists {
        let _ = std::process::Command::new("useradd")
            .args(["-m", "-s", "/sbin/nologin", MAIL_TEST_USER])
            .output();
    } else {
        // User already exists — ensure the home directory is present.
        // Dovecot needs it to create the Maildir on first login.
        let home = format!("/home/{MAIL_TEST_USER}");
        if !std::path::Path::new(&home).exists()
            && std::process::Command::new("mkhomedir_helper")
                .arg(MAIL_TEST_USER)
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(true)
        {
            // mkhomedir_helper not available — create manually.
            let _ = std::fs::create_dir_all(&home);
            let _ = std::process::Command::new("chown")
                .args([&format!("{MAIL_TEST_USER}:{MAIL_TEST_USER}"), &home])
                .output();
        }
    }

    // Always (re-)set the password so it matches the persisted config value.
    let chpasswd_input = format!("{MAIL_TEST_USER}:{}\n", mail_check_pass());
    if let Ok(mut child) = std::process::Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = std::io::Write::write_all(stdin, chpasswd_input.as_bytes());
        }
        let _ = child.wait();
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
        CheckKind::SmtpSend { from, to } => check_smtp_send(svc.host, svc.port, from, to),
        CheckKind::Imap => check_imap(svc.host, svc.port),
        CheckKind::ImapLogin { user } => check_imap_login(svc.host, svc.port, user),
        CheckKind::Pop3 => check_pop3(svc.host, svc.port),
        CheckKind::Pop3Login { user } => check_pop3_login(svc.host, svc.port, user),
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

/// Plain HTTP GET with redirect following.  Tries curl → wget → pure Rust.
///
/// Used for services that redirect on the root path (e.g. Splunk web on port 8000:
/// `GET /` → 303 → `/en-US/` → 303 → `/en-US/account/login` → 200).
fn check_http_curl(host: &str, port: u16, path: &str, expected: u16) -> (bool, String) {
    let url = format!("http://{}:{}{}", host, port, path);
    match ext_http_client() {
        ExtHttpClient::Curl => {
            let out = std::process::Command::new("curl")
                .args([
                    "-s",
                    "-L",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--max-time",
                    "3",
                    &url,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output();
            if let Ok(o) = out {
                let code: u16 = String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(0);
                return (code == expected, format!("HTTP {} (curl)", code));
            }
        }
        ExtHttpClient::Wget => {
            // wget -S writes headers to stderr; -O /dev/null discards body.
            let out = std::process::Command::new("wget")
                .args(["-q", "--max-redirect=10", "-O", "/dev/null", "-S", &url])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output();
            if let Ok(o) = out {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // Last "HTTP/x.x NNN" line is the final status after redirects.
                let code: u16 = stderr
                    .lines()
                    .filter_map(|l| {
                        let t = l.trim();
                        if t.starts_with("HTTP/") {
                            parse_http_status(t)
                        } else {
                            None
                        }
                    })
                    .next_back()
                    .unwrap_or(0);
                return (code == expected, format!("HTTP {} (wget)", code));
            }
        }
        ExtHttpClient::None => {}
    }
    // Pure-Rust fallback: follow redirects in-process via TCP.
    let mut cur_host = host.to_string();
    let mut cur_port = port;
    let mut cur_path = path.to_string();

    for _ in 0..5 {
        let addr = format!("{}:{}", cur_host, cur_port);
        let Ok(mut stream) = (match addr.parse::<SocketAddr>() {
            Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
            Err(_) => TcpStream::connect(&addr as &str),
        }) else {
            return (
                false,
                format!("TCP connect failed ({}:{})", cur_host, cur_port),
            );
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
                    format!(
                        "bad response: {}",
                        resp.chars().take(40).collect::<String>()
                    ),
                );
            }
        };

        if (300..400).contains(&status) {
            if let Some(loc) = parse_location_header(&resp)
                && let Some((h, p, pth)) = parse_http_url(&loc, &cur_host, cur_port)
            {
                cur_host = h;
                cur_port = p;
                cur_path = pth;
                continue;
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
fn parse_http_url(
    url: &str,
    default_host: &str,
    default_port: u16,
) -> Option<(String, u16, String)> {
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

/// HTTPS check.  Tries curl → wget → TCP-only fallback (port open = up).
fn check_https(host: &str, port: u16, path: &str, expected: u16) -> (bool, String) {
    let url = format!("https://{}:{}{}", host, port, path);
    match ext_http_client() {
        ExtHttpClient::Curl => {
            let out = std::process::Command::new("curl")
                .args([
                    "-s",
                    "-L",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--max-time",
                    "3",
                    "--insecure", // competition certs are self-signed
                    &url,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output();
            if let Ok(o) = out {
                let code: u16 = String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(0);
                return (code == expected, format!("HTTPS {} (curl)", code));
            }
        }
        ExtHttpClient::Wget => {
            let out = std::process::Command::new("wget")
                .args([
                    "-q",
                    "--no-check-certificate",
                    "--max-redirect=10",
                    "-O",
                    "/dev/null",
                    "-S",
                    &url,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output();
            if let Ok(o) = out {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let code: u16 = stderr
                    .lines()
                    .filter_map(|l| {
                        let t = l.trim();
                        if t.starts_with("HTTP/") {
                            parse_http_status(t)
                        } else {
                            None
                        }
                    })
                    .next_back()
                    .unwrap_or(0);
                return (code == expected, format!("HTTPS {} (wget)", code));
            }
        }
        ExtHttpClient::None => {}
    }
    // No TLS client available — fall back to TCP connect only.
    check_tcp(host, port)
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Open a TCP connection to an SMTP server.
fn smtp_connect(host: &str, port: u16) -> Option<TcpStream> {
    let addr = format!("{host}:{port}");
    let stream = match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }
    .ok()?;
    let _ = stream.set_read_timeout(Some(CHECK_TIMEOUT));
    Some(stream)
}

/// Read one CRLF-terminated line from an SMTP stream.
fn smtp_readline(stream: &mut TcpStream) -> String {
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// SMTP functional: EHLO → MAIL FROM → RCPT TO → QUIT.
fn check_smtp_send(host: &str, port: u16, from: &str, to: &str) -> (bool, String) {
    let Some(mut s) = smtp_connect(host, port) else {
        return (false, "TCP connect failed".into());
    };
    // Drain the greeting
    let banner = smtp_readline(&mut s);
    if !banner.starts_with("220") {
        return (
            false,
            format!("no 220 banner: {}", &banner[..banner.len().min(40)]),
        );
    }
    let cmds = [
        ("EHLO localhost\r\n".to_string(), "250"),
        (format!("MAIL FROM:<{from}>\r\n"), "250"),
        (format!("RCPT TO:<{to}>\r\n"), "250"),
        ("QUIT\r\n".into(), "221"),
    ];
    for (cmd, expect) in &cmds {
        let _ = s.write_all(cmd.as_bytes());
        let resp = smtp_readline(&mut s);
        if !resp.starts_with(expect) {
            return (
                false,
                format!("cmd {:?} → {:?}", cmd.trim(), &resp[..resp.len().min(50)]),
            );
        }
    }
    (true, format!("SMTP send path OK ({from} → {to})"))
}

/// IMAP functional: LOGIN then SELECT INBOX.
fn check_imap_login(host: &str, port: u16, user: &str) -> (bool, String) {
    let pass_owned = mail_check_pass();
    let pass: &str = pass_owned;
    let addr = format!("{host}:{port}");
    let Ok(mut s) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = s.set_read_timeout(Some(CHECK_TIMEOUT));
    let mut buf = [0u8; 512];

    // Greeting
    let n = s.read(&mut buf).unwrap_or(0);
    let greeting = String::from_utf8_lossy(&buf[..n]);
    if !greeting.contains("* OK") {
        return (false, "no IMAP greeting".into());
    }

    let steps: &[(&str, &str)] = &[
        ("A1 LOGIN {user} {pass}\r\n", "A1 OK"),
        ("A2 SELECT INBOX\r\n", "A2 OK"),
        ("A3 LOGOUT\r\n", "A3 OK"),
    ];
    for (template, expect) in steps {
        let cmd = template.replace("{user}", user).replace("{pass}", pass);
        let _ = s.write_all(cmd.as_bytes());
        // Read until we see the tagged response (may need multiple reads)
        let mut resp = String::new();
        for _ in 0..8 {
            let n = s.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
            if resp.contains(expect) || resp.contains("NO ") || resp.contains("BAD ") {
                break;
            }
        }
        if !resp.contains(expect) {
            let snippet: String = resp.lines().last().unwrap_or("").chars().take(60).collect();
            return (
                false,
                format!(
                    "{}: {snippet}",
                    template.split_whitespace().next().unwrap_or("")
                ),
            );
        }
    }
    (true, format!("IMAP login + SELECT INBOX OK ({user})"))
}

/// POP3 functional: USER + PASS then STAT.
fn check_pop3_login(host: &str, port: u16, user: &str) -> (bool, String) {
    let pass_owned = mail_check_pass();
    let pass: &str = pass_owned;
    let addr = format!("{host}:{port}");
    let Ok(mut s) = (match addr.parse::<SocketAddr>() {
        Ok(sa) => TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT),
        Err(_) => TcpStream::connect(&addr as &str),
    }) else {
        return (false, "TCP connect failed".into());
    };
    let _ = s.set_read_timeout(Some(CHECK_TIMEOUT));
    let mut buf = [0u8; 256];

    // Greeting
    let n = s.read(&mut buf).unwrap_or(0);
    let greeting = String::from_utf8_lossy(&buf[..n]);
    if !greeting.contains("+OK") {
        return (false, "no POP3 greeting".into());
    }

    let steps: &[(&str, &str)] = &[
        ("USER {user}\r\n", "+OK"),
        ("PASS {pass}\r\n", "+OK"),
        ("STAT\r\n", "+OK"),
        ("QUIT\r\n", "+OK"),
    ];
    for (template, expect) in steps {
        let cmd = template.replace("{user}", user).replace("{pass}", pass);
        let _ = s.write_all(cmd.as_bytes());
        let n = s.read(&mut buf).unwrap_or(0);
        let resp = String::from_utf8_lossy(&buf[..n]);
        let first = resp.lines().next().unwrap_or("").trim();
        if !first.starts_with(expect) {
            return (
                false,
                format!("{}: {}", template.trim(), &first[..first.len().min(50)]),
            );
        }
    }
    (true, format!("POP3 login + STAT OK ({user})"))
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

/// Dedicated local account used for functional mail checks (IMAP LOGIN, POP3 USER/PASS).
/// Call [`ensure_mail_test_account`] on startup to create/maintain the account.
const MAIL_TEST_USER: &str = "scorecheck";

/// Path where the generated mail-check password is persisted across runs.
const MAIL_CHECK_CONF: &str = "/etc/linux-defender/mail-check.conf";

/// Cached runtime password for the mail test account.
static MAIL_CHECK_PASS: OnceLock<String> = OnceLock::new();

/// Return the mail-check account password, loading it from config or generating
/// a fresh random one (and saving it) on the first call.
pub fn mail_check_pass() -> &'static str {
    MAIL_CHECK_PASS.get_or_init(|| {
        // Try to load from the persisted config file.
        if let Ok(text) = std::fs::read_to_string(MAIL_CHECK_CONF) {
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        // Generate a random 32-char hex password from /dev/urandom.
        let pass = gen_random_hex(16);
        // Persist it so future runs (and the next `ensure_mail_test_account` call)
        // use the same password.
        let _ = std::fs::create_dir_all("/etc/linux-defender");
        let _ = std::fs::write(MAIL_CHECK_CONF, &pass);
        pass
    })
}

/// Read `n` bytes from `/dev/urandom` and return them as a lowercase hex string.
fn gen_random_hex(n: usize) -> String {
    use std::fs::File;
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = std::io::Read::read(&mut f, &mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Scored services for a mail box.
pub const MAIL_CHECKS: &[ServiceCheck] = &[
    ServiceCheck {
        name: "Postfix SMTP",
        host: "127.0.0.1",
        port: 25,
        kind: CheckKind::SmtpSend {
            from: "scorer@localhost",
            to: "scorecheck@localhost",
        },
    },
    ServiceCheck {
        name: "Dovecot IMAP",
        host: "127.0.0.1",
        port: 143,
        kind: CheckKind::ImapLogin {
            user: MAIL_TEST_USER,
        },
    },
    ServiceCheck {
        name: "Dovecot POP3",
        host: "127.0.0.1",
        port: 110,
        kind: CheckKind::Pop3Login {
            user: MAIL_TEST_USER,
        },
    },
    ServiceCheck {
        name: "Roundcube",
        host: "127.0.0.1",
        port: 80,
        kind: CheckKind::Http {
            path: "/roundcube/",
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
