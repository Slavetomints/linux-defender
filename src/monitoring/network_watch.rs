//! One-shot network connection snapshot.
//!
//! Runs `ss -tunap` (falling back to `netstat -tunap` if `ss` is not found)
//! and parses each connection into a structured record. Findings:
//!
//! - **High** — established connection to a public (non-RFC-1918/loopback) IP.
//! - **Medium** — LISTEN port whose associated process name matches
//!   a set of suspicious process names.

use std::process::Command;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Process names that are suspicious when found behind a LISTEN socket.
const SUSPICIOUS_NAMES: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "bash", "sh", "dash", "nc", "ncat", "nmap",
    "curl", "wget", "socat",
];

/// One parsed network connection.
pub struct Connection {
    /// Protocol string, e.g. `"tcp"` or `"udp"`.
    pub proto: String,
    /// Connection state, e.g. `"ESTAB"`, `"LISTEN"`, `"TIME-WAIT"`.
    pub state: String,
    /// Local address and port as a string, e.g. `"0.0.0.0:22"`.
    pub local: String,
    /// Remote (peer) address and port, e.g. `"10.0.0.5:54321"`.
    pub remote: String,
    /// Process name extracted from the `users:((...))` column, if present.
    pub process_name: String,
    /// PID extracted from the `users:((...))` column, or 0 if not available.
    pub pid: u32,
}

/// Run `ss -tunap` and return its stdout, or fall back to `netstat -tunap`.
fn capture_ss() -> String {
    // Try `ss` first (iproute2, present on all modern Linux distros).
    if let Ok(out) = Command::new("ss").args(["-tunap"]).output() {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).into_owned();
        }
    }
    // Fall back to `netstat` for older systems.
    Command::new("netstat")
        .args(["-tunap"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Extract process name and PID from a `users:(("name",pid=N,fd=M))` field.
///
/// Returns `(name, pid)`, or `("", 0)` if the field is absent or unparsable.
pub fn parse_users_field(users: &str) -> (String, u32) {
    // Expected form: users:(("name",pid=1234,fd=5))
    // We need the first quoted name and the pid= value.
    let inner = users
        .strip_prefix("users:((\"")
        .and_then(|s| s.split_once('"'));

    let Some((name, rest)) = inner else {
        return (String::new(), 0);
    };

    let pid = rest
        .split(',')
        .find_map(|tok| tok.strip_prefix("pid="))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    (name.to_string(), pid)
}

/// Parse one line of `ss -tunap` output into a [`Connection`].
///
/// `ss` output columns: `Netid  State  Recv-Q  Send-Q  Local  Peer  [Process]`
/// The Process column is optional (present only for sockets owned by the
/// running user or root).
pub fn parse_ss_line(line: &str) -> Option<Connection> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // Minimum: proto state recv-q send-q local peer
    if fields.len() < 6 {
        return None;
    }
    let proto = fields[0].to_lowercase();
    if !matches!(proto.as_str(), "tcp" | "udp" | "tcp6" | "udp6") {
        return None;
    }
    let state = fields[1].to_string();
    // recv-q and send-q are fields[2] and [3]; local is [4], peer is [5].
    let local = fields[4].to_string();
    let remote = fields[5].to_string();

    let users_field = fields.get(6).copied().unwrap_or("");
    let (process_name, pid) = parse_users_field(users_field);

    Some(Connection {
        proto,
        state,
        local,
        remote,
        process_name,
        pid,
    })
}

/// Return `true` if `addr` resolves to a private, loopback, or link-local IP.
///
/// Covers:
/// - `127.0.0.0/8` — IPv4 loopback
/// - `10.0.0.0/8` — RFC-1918
/// - `172.16.0.0/12` — RFC-1918
/// - `192.168.0.0/16` — RFC-1918
/// - `::1` — IPv6 loopback
/// - `fe80::/10` — IPv6 link-local
/// - `*`, `0.0.0.0`, `[::]` — wildcard listeners
pub fn is_private_or_local(addr: &str) -> bool {
    // Quick checks for bare IPv6 literals passed without a port.
    if matches!(addr, "*" | "0.0.0.0" | "[::]" | "::" | "::1") {
        return true;
    }
    if addr.starts_with("fe80") {
        return true;
    }

    // Strip port: `addr` is `ip:port` or `[ipv6]:port`.
    let ip = if addr.starts_with('[') {
        // IPv6 bracket notation [addr]:port
        addr.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(addr)
    } else if addr.contains(':') && addr.matches(':').count() > 1 {
        // Bare IPv6 with multiple colons — no port, use as-is
        addr
    } else {
        addr.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(addr)
    };

    if matches!(ip, "*" | "0.0.0.0" | "[::]" | "::") {
        return true;
    }
    if ip == "::1" || ip.starts_with("fe80") {
        return true;
    }
    // Parse as IPv4 octets for RFC-1918/loopback checks.
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse::<u8>().ok()).collect();

    if octets.len() != 4 {
        return false; // IPv6 other than the above — treat as public
    }

    matches!(
        (octets[0], octets[1]),
        (127, _)                                    // 127.0.0.0/8
        | (10, _)                                   // 10.0.0.0/8
        | (192, 168)                                // 192.168.0.0/16
        | (172, 16..=31) // 172.16.0.0/12
    )
}

/// Return `true` if `name` matches any suspicious process name pattern.
pub fn is_suspicious_name(name: &str) -> bool {
    SUSPICIOUS_NAMES.iter().any(|&pat| name.starts_with(pat))
}

/// Snapshot network connections and emit findings.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Snapshotting network connections...");

    let raw = capture_ss();
    let conns: Vec<Connection> = raw.lines().filter_map(parse_ss_line).collect();

    let mut public_count = 0usize;

    for c in &conns {
        let is_listen = c.state.eq_ignore_ascii_case("listen");
        let is_established =
            c.state.eq_ignore_ascii_case("estab") || c.state.eq_ignore_ascii_case("established");

        if is_established && !is_private_or_local(&c.remote) {
            ctx.emit(Finding::new(
                Severity::High,
                "network_watch",
                format!(
                    "Public connection: {} → {} ({})",
                    c.local, c.remote, c.process_name
                ),
                format!(
                    "proto: {}\nstate: {}\nlocal: {}\nremote: {}\nprocess: {}\npid: {}",
                    c.proto, c.state, c.local, c.remote, c.process_name, c.pid
                ),
            ));
            public_count += 1;
        } else if is_listen && is_suspicious_name(&c.process_name) {
            ctx.emit(Finding::new(
                Severity::Medium,
                "network_watch",
                format!(
                    "Suspicious listener: {} on {} (PID {})",
                    c.process_name, c.local, c.pid
                ),
                format!(
                    "proto: {}\nstate: {}\nlocal: {}\nprocess: {}\npid: {}",
                    c.proto, c.state, c.local, c.process_name, c.pid
                ),
            ));
        }
    }

    ctx.log_msg(&format!(
        "[✓] Network snapshot complete — {} connection(s), {} public",
        conns.len(),
        public_count,
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ips_are_local() {
        assert!(is_private_or_local("127.0.0.1:22"));
        assert!(is_private_or_local("10.0.0.1:443"));
        assert!(is_private_or_local("192.168.1.100:80"));
        assert!(is_private_or_local("172.16.0.1:8080"));
        assert!(is_private_or_local("172.31.255.255:9000"));
        assert!(is_private_or_local("::1"));
        assert!(is_private_or_local("[::1]:22"));
        assert!(is_private_or_local("0.0.0.0:22"));
        assert!(is_private_or_local("*:22"));
    }

    #[test]
    fn public_ips_are_not_local() {
        assert!(!is_private_or_local("8.8.8.8:53"));
        assert!(!is_private_or_local("1.1.1.1:443"));
        assert!(!is_private_or_local("203.0.113.5:80"));
        assert!(!is_private_or_local("172.32.0.1:80")); // outside 172.16-31
    }

    #[test]
    fn parse_users_extracts_name_and_pid() {
        let (name, pid) = parse_users_field("users:((\"curl\",pid=1234,fd=5))");
        assert_eq!(name, "curl");
        assert_eq!(pid, 1234);
    }

    #[test]
    fn parse_users_handles_missing_field() {
        let (name, pid) = parse_users_field("");
        assert_eq!(name, "");
        assert_eq!(pid, 0);
    }

    #[test]
    fn parse_ss_line_established() {
        let line =
            "tcp   ESTAB  0  0  192.168.1.1:54321  10.0.0.1:443  users:((\"curl\",pid=99,fd=3))";
        let c = parse_ss_line(line).unwrap();
        assert_eq!(c.proto, "tcp");
        assert_eq!(c.state, "ESTAB");
        assert_eq!(c.remote, "10.0.0.1:443");
        assert_eq!(c.process_name, "curl");
        assert_eq!(c.pid, 99);
    }

    #[test]
    fn parse_ss_line_listen_no_process() {
        let line = "tcp   LISTEN  0  128  0.0.0.0:22  0.0.0.0:*";
        let c = parse_ss_line(line).unwrap();
        assert_eq!(c.state, "LISTEN");
        assert_eq!(c.process_name, "");
        assert_eq!(c.pid, 0);
    }

    #[test]
    fn parse_ss_line_skips_header() {
        assert!(parse_ss_line("Netid  State  Recv-Q  Send-Q  Local  Peer  Process").is_none());
    }

    #[test]
    fn suspicious_listener_names() {
        assert!(is_suspicious_name("nc"));
        assert!(is_suspicious_name("python3"));
        assert!(!is_suspicious_name("nginx"));
        assert!(!is_suspicious_name("sshd"));
    }

    #[test]
    fn run_does_not_panic() {
        use crate::core::DefenderContext;
        use std::path::PathBuf;
        let ctx = DefenderContext::new(PathBuf::from("/dev/null"), false);
        let _ = run(&ctx);
    }
}
