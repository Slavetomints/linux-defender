//! Map listening TCP ports to the binaries that own them.
//!
//! Reads `/proc/net/tcp` and `/proc/net/tcp6`, identifies LISTEN sockets, then
//! walks `/proc/*/fd` symlinks to find which process holds each socket inode.
//! The result lets an operator quickly spot unexpected listeners
//! (e.g., `bash` on `:31337`).

use std::collections::HashMap;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// A TCP port in the LISTEN state, mapped to the process that owns it.
pub struct ListeningPort {
    /// The local port number.
    pub port: u16,
    /// PID of the process holding the socket.
    pub pid: u32,
    /// Binary name (last path component of `/proc/<pid>/exe`).
    pub exe: String,
    /// First 80 chars of the process command line.
    pub cmdline: String,
}

/// Emit one Info finding per listening port so the operator can spot surprises.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Building listening port map...");
    let ports = collect_listening_ports();

    for lp in &ports {
        ctx.emit(Finding::new(
            Severity::Info,
            "port_map",
            format!(":{} — {} (PID {})", lp.port, lp.exe, lp.pid),
            format!(
                "port: {}\npid: {}\nexe: {}\ncmdline: {}",
                lp.port, lp.pid, lp.exe, lp.cmdline
            ),
        ));
    }

    ctx.log_msg(&format!(
        "[✓] Port map complete — {} listener(s)",
        ports.len()
    ));
    Ok(())
}

/// Read `/proc/net/tcp[6]` and resolve each LISTEN socket to its owning process.
pub fn collect_listening_ports() -> Vec<ListeningPort> {
    // (inode -> port) for all LISTEN sockets
    let mut inode_port: HashMap<u64, u16> = HashMap::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for (port, inode) in parse_listen_sockets(&contents) {
                inode_port.insert(inode, port);
            }
        }
    }

    if inode_port.is_empty() {
        return Vec::new();
    }

    // (inode -> pid) from /proc/*/fd
    let inode_pid = build_inode_pid_map(&inode_port);

    inode_port
        .iter()
        .filter_map(|(inode, &port)| {
            let pid = *inode_pid.get(inode)?;
            Some(ListeningPort {
                port,
                pid,
                exe: read_exe(pid),
                cmdline: read_cmdline(pid),
            })
        })
        .collect()
}

/// Parse LISTEN socket entries from `/proc/net/tcp[6]`.
/// Returns `(port, inode)` pairs.
fn parse_listen_sockets(contents: &str) -> Vec<(u16, u64)> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... inode
        if fields.len() < 10 {
            continue;
        }
        if fields[3] != "0A" {
            continue; // only LISTEN
        }
        let Some(port) = parse_hex_port(fields[1]) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        out.push((port, inode));
    }
    out
}

/// Parse the port half of a `<hex_ip>:<hex_port>` field from `/proc/net/tcp`.
fn parse_hex_port(addr: &str) -> Option<u16> {
    u16::from_str_radix(addr.split(':').nth(1)?, 16).ok()
}

/// Walk `/proc/*/fd` to build a map of socket inode → pid.
fn build_inode_pid_map(target_inodes: &HashMap<u64, u16>) -> HashMap<u64, u32> {
    let mut result: HashMap<u64, u32> = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return result;
    };

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(fd_dir) else {
            continue;
        };
        for fd_entry in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            let link_str = link.to_string_lossy();
            // socket:[<inode>]
            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode_str.parse::<u64>()
                && target_inodes.contains_key(&inode)
            {
                result.insert(inode, pid);
            }
        }
    }

    result
}

/// Return the basename of the executable for `pid` by reading `/proc/<pid>/exe`.
fn read_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .split('/')
                .next_back()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|_| "unknown".into())
}

/// Return a truncated command line string for `pid` from `/proc/<pid>/cmdline`.
fn read_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .chars()
                .take(80)
                .collect()
        })
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_socket_line() {
        // state 0A = LISTEN, inode field [9]; include a header line since the
        // parser always skips line 0.
        let line = "  sl  local_address rem_address   st\n  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let pairs = parse_listen_sockets(line);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, 22); // port 22
        assert_eq!(pairs[0].1, 12345); // inode
    }

    #[test]
    fn skips_non_listen_state() {
        let line = "  1: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000\n";
        assert!(parse_listen_sockets(line).is_empty());
    }

    #[test]
    fn collect_runs_without_panic() {
        let _ = collect_listening_ports();
    }
}
