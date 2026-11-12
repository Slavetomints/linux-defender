//! Outbound TCP connections from service accounts.
//!
//! Reads `/proc/net/tcp\[6\]` for ESTABLISHED connections, maps each socket to
//! its owning process and UID, then flags any established outbound connection
//! owned by a service account (www-data, postfix, mysql, etc.).  A web server
//! process dialling out on port 4444 is almost certainly a C2 beacon.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// UIDs below this that are not root are considered service accounts.
const SERVICE_UID_MAX: u32 = 1000;

/// Destination ports considered legitimate for any service
/// (NTP, SMTP-out, HTTPS package repos, etc.).
/// Port 53 is NOT here — DNS is allowed per-process via KNOWN_DNS_PROCS to catch DNS tunneling.
const EXPECTED_OUTBOUND_PORTS: &[u16] = &[
    22,   // SSH (e.g., git fetch)
    25,   // SMTP relay out
    80,   // HTTP (package downloads)
    123,  // NTP
    443,  // HTTPS (package downloads, APIs)
    587,  // SMTP submission
    636,  // LDAPS
    9997, // Splunk forwarder
    8089, // Splunk management
];

/// DNS processes allowed to make port-53 connections -- anything else on 53 is C2 candidate.
const KNOWN_DNS_PROCS: &[&str] = &["named", "dnsmasq", "systemd-resolved", "unbound", "bind"];

/// TCP state 01 = ESTABLISHED.
const TCP_ESTABLISHED: &str = "01";

/// One established TCP connection read from `/proc/net/tcp\[6\]`.
#[derive(Debug)]
struct Conn {
    /// Local port of this side of the connection.
    local_port: u16,
    /// Remote IP address.
    remote_addr: IpAddr,
    /// Remote port.
    remote_port: u16,
    /// Socket inode used to map the connection back to a PID.
    inode: u64,
}

/// Parse established (state=01) connections from a /proc/net/tcp\[6\] file.
fn parse_established(contents: &str, is_v6: bool) -> Vec<Conn> {
    let mut out = Vec::new();

    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if fields[3] != TCP_ESTABLISHED {
            continue;
        }

        let local_port = parse_hex_port(fields[1]).unwrap_or(0);
        let (remote_addr, remote_port) = if is_v6 {
            parse_hex_addr_v6(fields[2])
        } else {
            parse_hex_addr_v4(fields[2])
        };

        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }

        // Skip connections where remote is loopback — those are internal IPC.
        if is_loopback(&remote_addr) {
            continue;
        }

        out.push(Conn {
            local_port,
            remote_addr,
            remote_port,
            inode,
        });
    }

    out
}

/// Parse the port from a `<hex_ip>:<hex_port>` field in `/proc/net/tcp`.
fn parse_hex_port(addr: &str) -> Option<u16> {
    u16::from_str_radix(addr.split(':').nth(1)?, 16).ok()
}

/// Decode a little-endian hex IPv4 address and port from `/proc/net/tcp`.
fn parse_hex_addr_v4(addr: &str) -> (IpAddr, u16) {
    let mut parts = addr.splitn(2, ':');
    let ip_hex = parts.next().unwrap_or("00000000");
    let port_hex = parts.next().unwrap_or("0000");

    // /proc/net/tcp stores IPv4 in little-endian hex: "0100007F" = 127.0.0.1
    let raw = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
    let ip = Ipv4Addr::from(raw.to_be());
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    (IpAddr::V4(ip), port)
}

/// Decode a little-endian hex IPv6 address and port from `/proc/net/tcp6`.
fn parse_hex_addr_v6(addr: &str) -> (IpAddr, u16) {
    let mut parts = addr.splitn(2, ':');
    let zero_padding = "0".repeat(32);
    let ip_hex = parts.next().unwrap_or(&zero_padding);
    let port_hex = parts.next().unwrap_or("0000");

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

    // 32 hex chars = 16 bytes; stored as 4 little-endian 32-bit words
    if ip_hex.len() < 32 {
        return (IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    }

    let mut octets = [0u8; 16];
    for (chunk_idx, chunk) in ip_hex.as_bytes().chunks(8).enumerate() {
        let word_hex = std::str::from_utf8(chunk).unwrap_or("00000000");
        let word = u32::from_str_radix(word_hex, 16).unwrap_or(0).to_be();
        let base = chunk_idx * 4;
        octets[base..base + 4].copy_from_slice(&word.to_be_bytes());
    }

    (IpAddr::V6(Ipv6Addr::from(octets)), port)
}

/// Return true if `addr` is a loopback address.
fn is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback(),
    }
}

/// Build inode → pid map from /proc/*/fd.
fn inode_to_pid(target_inodes: &HashMap<u64, ()>) -> HashMap<u64, u32> {
    let mut result = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return result;
    };

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };

        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let s = link.to_string_lossy();
            if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    if target_inodes.contains_key(&inode) {
                        result.insert(inode, pid);
                    }
                }
            }
        }
    }
    result
}

/// Get UID and process name for a PID from `/proc/<pid>/status`.
fn proc_uid_name(pid: u32) -> (u32, String) {
    let path = format!("/proc/{}/status", pid);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return (u32::MAX, "unknown".into());
    };

    let mut uid = u32::MAX;
    let mut name = String::from("unknown");

    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("Uid:\t") {
            uid = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u32::MAX);
        } else if let Some(v) = line.strip_prefix("Name:\t") {
            name = v.trim().to_string();
        }
    }
    (uid, name)
}

/// Map UID to username via /etc/passwd.
fn uid_to_username(uid: u32) -> Option<String> {
    let contents = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[2].parse::<u32>().ok() == Some(uid) {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// Scan for outbound network connections initiated by service accounts.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for outbound connections from service accounts...");

    let mut conns: Vec<Conn> = Vec::new();

    for (path, is_v6) in &[("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            conns.extend(parse_established(&contents, *is_v6));
        }
    }

    if conns.is_empty() {
        ctx.log_msg("[✓] No established outbound connections found");
        return Ok(());
    }

    // Build inode set for efficient lookup
    let inode_set: HashMap<u64, ()> = conns.iter().map(|c| (c.inode, ())).collect();
    let inode_pid = inode_to_pid(&inode_set);

    let mut findings = 0;

    for conn in &conns {
        let Some(&pid) = inode_pid.get(&conn.inode) else {
            continue;
        };
        let (uid, proc_name) = proc_uid_name(pid);

        // Only flag service accounts (non-root, UID < 1000)
        if uid == 0 || uid >= SERVICE_UID_MAX || uid == u32::MAX {
            continue;
        }

        // Skip expected outbound ports
        if EXPECTED_OUTBOUND_PORTS.contains(&conn.remote_port) {
            continue;
        }

        // Allow port-53 connections from known DNS daemon processes
        if conn.remote_port == 53 && KNOWN_DNS_PROCS.iter().any(|&d| proc_name.contains(d)) {
            continue;
        }

        let username = uid_to_username(uid).unwrap_or_else(|| format!("uid:{}", uid));

        findings += 1;

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "outbound_connections",
                format!(
                    "{} ({}) connecting out to {}:{} — possible C2 beacon",
                    proc_name, username, conn.remote_addr, conn.remote_port
                ),
                format!(
                    "process: {}\npid: {}\nuid: {} ({})\nlocal_port: {}\nremote: {}:{}",
                    proc_name, pid, uid, username,
                    conn.local_port, conn.remote_addr, conn.remote_port
                ),
            )
            .with_context("process", proc_name.clone())
            .with_context("pid", pid.to_string())
            .with_context("uid", format!("{} ({})", uid, username))
            .with_context("remote", format!("{}:{}", conn.remote_addr, conn.remote_port))
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "Service account '{}' (uid {}) has an established TCP connection to \
                     {}:{} which is not a standard service port. This is a strong indicator \
                     of a C2 beacon or reverse shell. Kill PID {} and block this IP at the firewall.",
                    username, uid, conn.remote_addr, conn.remote_port, pid,
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] Outbound connection scan complete — {} suspicious connection{}",
        findings,
        if findings == 1 { "" } else { "s" },
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // /proc/net/tcp stores IPv4 in little-endian hex: 127.0.0.1 = 0100007F
    const SAMPLE_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0101A8C0:C3A0 0202A8C0:1194 01 00000000:00000000 00:00000000 00000000    33        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0101A8C0:D4B1 0303A8C0:115C 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0101A8C0:E5C2 0100007F:0035 01 00000000:00000000 00:00000000 00000000    33        0 12347 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_established_connections() {
        let conns = parse_established(SAMPLE_TCP, false);
        // Third entry is loopback (127.0.0.1) — should be skipped
        assert_eq!(conns.len(), 2);
    }

    #[test]
    fn loopback_is_skipped() {
        let conns = parse_established(SAMPLE_TCP, false);
        for c in &conns {
            assert!(!is_loopback(&c.remote_addr));
        }
    }

    #[test]
    fn scan_runs_without_panic() {
        // Just verify no panic on a real system
        let _ = inode_to_pid(&HashMap::new());
    }
}
