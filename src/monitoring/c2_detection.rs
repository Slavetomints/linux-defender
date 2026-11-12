//! C2 implant and beacon detection.
//!
//! Implements five independent checks:
//!
//! 1. **memfd execution** — processes running from anonymous memory (`/memfd:` exe path).
//! 2. **Deleted-from-temp executables** — processes that launched from a temp path that
//!    was subsequently deleted.
//! 3. **C2 signature ports** — ESTABLISHED connections to known C2 framework ports.
//! 4. **Go binary fingerprinting** — processes carrying Go runtime strings outside
//!    known-good system locations.
//! 5. **High-entropy process names** — processes with an empty cmdline and an exe path
//!    outside standard system directories.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

// ─── Known C2 ports ──────────────────────────────────────────────────────────

/// TCP ports associated with known C2 frameworks.
/// C2 ports to watch. This is a quick-win hint list; behavioral checks (Go ELF
/// fingerprint, deleted exe, temp-dir process) catch C2 on any port.
const C2_PORTS: &[u16] = &[
    53,    // DNS tunneling (MWCCDC red team has used this historically)
    50050, // Cobalt Strike team server
    4444,  // Metasploit / generic reverse shell
    8888,  // Various C2 frameworks
    9001,  // Tor / various C2
    9002,  // Various C2
    1337,  // Common attacker "elite" port
    31337, // Back Orifice / elite port
    4443,  // Reverse HTTPS C2
    8443,  // Alt-HTTPS C2
    2222,  // Alt-SSH / C2
    7777,  // Various C2
];

/// Process names that are legitimate owners of port-53 connections.
/// Port 53 is only suspicious when held by something other than a DNS daemon.
const KNOWN_DNS_PROCS: &[&str] = &["named", "dnsmasq", "systemd-resolved", "unbound", "bind"];

/// Temp directories from which running executables are suspicious when deleted.
const TEMP_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"];

/// Known-good locations for Go binaries.
const KNOWN_GOOD_GO_PATHS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/snap/"];

/// Known-good locations for general processes (used in argv check).
const KNOWN_GOOD_PATHS: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/snap/"];

/// Strings present in all Go-compiled binaries.
const GO_BINARY_STRINGS: &[&str] = &["Go build ID:", "runtime.gopanic"];

/// Maximum bytes to read from a binary for Go fingerprinting.
const GO_SCAN_LIMIT: usize = 1024 * 1024; // 1 MB

/// TCP state 01 = ESTABLISHED.
const TCP_ESTABLISHED: &str = "01";

// ─── /proc helpers ───────────────────────────────────────────────────────────

/// Read `/proc/<pid>/cmdline`, split on NUL, return up to `max_args` args.
fn read_cmdline_args(pid: u32, max_args: usize) -> Vec<String> {
    let Ok(bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) else {
        return Vec::new();
    };
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .take(max_args)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Return (Name, Uid) from `/proc/<pid>/status`.
fn proc_name_uid(pid: u32) -> (String, u32) {
    let path = format!("/proc/{}/status", pid);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return ("unknown".into(), u32::MAX);
    };
    let mut name = "unknown".to_string();
    let mut uid = u32::MAX;
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("Name:\t") {
            name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Uid:\t") {
            uid = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u32::MAX);
        }
    }
    (name, uid)
}

/// Format the first few cmdline args for use in a Finding detail.
fn fmt_cmdline(args: &[String]) -> String {
    if args.is_empty() {
        "<empty>".to_string()
    } else {
        args.join(" ")
    }
}

// ─── /proc/net/tcp helpers (mirrored from outbound_connections) ──────────────

/// An established TCP connection read from `/proc/net/tcp[6]`.
#[derive(Debug)]
struct Conn {
    /// Remote IP address.
    remote_addr: IpAddr,
    /// Remote port number.
    remote_port: u16,
    /// Socket inode number used to map back to a PID.
    inode: u64,
}

/// Parse a `<hex_ip>:<hex_port>` entry from `/proc/net/tcp` into an `(IpAddr, port)`.
fn parse_hex_addr_v4(addr: &str) -> (IpAddr, u16) {
    let mut parts = addr.splitn(2, ':');
    let ip_hex = parts.next().unwrap_or("00000000");
    let port_hex = parts.next().unwrap_or("0000");
    let raw = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
    let ip = Ipv4Addr::from(raw.to_be());
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    (IpAddr::V4(ip), port)
}

/// Parse a `<hex_ip6>:<hex_port>` entry from `/proc/net/tcp6` into an `(IpAddr, port)`.
fn parse_hex_addr_v6(addr: &str) -> (IpAddr, u16) {
    let mut parts = addr.splitn(2, ':');
    let zero_padding = "0".repeat(32);
    let ip_hex = parts.next().unwrap_or(&zero_padding);
    let port_hex = parts.next().unwrap_or("0000");
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
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

/// Parse ESTABLISHED connections from a `/proc/net/tcp[6]` file, keeping only
/// connections to known C2 ports.
fn parse_c2_connections(contents: &str, is_v6: bool) -> Vec<Conn> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if fields[3] != TCP_ESTABLISHED {
            continue;
        }
        let (remote_addr, remote_port) = if is_v6 {
            parse_hex_addr_v6(fields[2])
        } else {
            parse_hex_addr_v4(fields[2])
        };
        if !C2_PORTS.contains(&remote_port) {
            continue;
        }
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        out.push(Conn {
            remote_addr,
            remote_port,
            inode,
        });
    }
    out
}

/// Build inode → pid map from `/proc/*/fd`.
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

// ─── Check 1: memfd execution ────────────────────────────────────────────────

/// Check `/proc/*/exe` for processes whose executable path starts with `memfd:`.
fn check_memfd(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning for memfd-executed processes...");
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut count = 0u32;

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(&exe_link) else {
            continue;
        };
        let exe_str = exe_path.to_string_lossy().into_owned();

        if !exe_str.starts_with("/memfd:") {
            continue;
        }

        count += 1;
        let (name, uid) = proc_name_uid(pid);
        let args = read_cmdline_args(pid, 3);
        let cmdline = fmt_cmdline(&args);

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "c2_detection",
                format!(
                    "PID {} ({}) running from anonymous memory — memfd implant",
                    pid, name
                ),
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}\ncmdline: {}",
                    pid, name, uid, exe_str, cmdline
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", name.clone())
            .with_context("exe", exe_str.clone())
            .with_context("uid", uid.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} ({}) has its executable mapped entirely in anonymous memory \
                     (path begins with '/memfd:'). This is characteristic of fileless \
                     implants such as Sliver and Mettle that execute entirely from RAM \
                     to avoid leaving traces on disk. Kill PID {} immediately and \
                     investigate how it was injected.",
                    pid, name, pid
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] memfd scan complete — {} process{}",
        count,
        if count == 1 { "" } else { "es" }
    ));
}

// ─── Check 2: deleted-from-temp executables ──────────────────────────────────

/// Check `/proc/*/exe` for processes running from deleted files in temp directories.
fn check_deleted_temp(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning for processes run from deleted temp files...");
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut count = 0u32;

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(&exe_link) else {
            continue;
        };
        let exe_str = exe_path.to_string_lossy().into_owned();

        if !exe_str.ends_with(" (deleted)") {
            continue;
        }
        if !TEMP_DIRS.iter().any(|prefix| exe_str.contains(prefix)) {
            continue;
        }

        count += 1;
        let (name, uid) = proc_name_uid(pid);
        let args = read_cmdline_args(pid, 3);
        let cmdline = fmt_cmdline(&args);

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "c2_detection",
                format!(
                    "PID {} ({}) executed from temp path that was deleted: {}",
                    pid, name, exe_str
                ),
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}\ncmdline: {}",
                    pid, name, uid, exe_str, cmdline
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", name.clone())
            .with_context("exe", exe_str.clone())
            .with_context("uid", uid.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} ({}) launched from a temp directory and the on-disk file was \
                     subsequently deleted. This is a common attacker technique to hide \
                     tooling: drop to /tmp or /dev/shm, execute, then unlink the file. \
                     The process continues running from the open inode. Kill PID {} and \
                     investigate how it was placed.",
                    pid, name, pid
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] Deleted-temp scan complete — {} process{}",
        count,
        if count == 1 { "" } else { "es" }
    ));
}

// ─── Check 3: C2 signature ports ─────────────────────────────────────────────

/// Scan established connections for ports associated with known C2 frameworks.
fn check_c2_ports(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning for connections to known C2 ports...");

    let mut conns: Vec<Conn> = Vec::new();
    for (path, is_v6) in &[("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            conns.extend(parse_c2_connections(&contents, *is_v6));
        }
    }

    if conns.is_empty() {
        ctx.log_msg("[✓] No connections to C2 signature ports found");
        return;
    }

    let inode_set: HashMap<u64, ()> = conns.iter().map(|c| (c.inode, ())).collect();
    let inode_pid = inode_to_pid(&inode_set);

    let mut count = 0u32;
    for conn in &conns {
        let pid =
            match inode_pid.get(&conn.inode) {
                Some(&p) => p,
                None => {
                    // Could not resolve inode → pid; still emit a finding with
                    // what we know.
                    ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "c2_detection",
                        format!(
                            "ESTABLISHED connection to C2 port {} at {} (owner process unknown)",
                            conn.remote_port, conn.remote_addr
                        ),
                        format!(
                            "remote: {}:{}\ninode: {}\npid: unknown",
                            conn.remote_addr, conn.remote_port, conn.inode
                        ),
                    )
                    .with_context("remote", format!("{}:{}", conn.remote_addr, conn.remote_port))
                    .with_context("inode", conn.inode.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "An ESTABLISHED TCP connection to {} (port {}), a known C2 \
                             framework port, was found but the owning process could not be \
                             resolved. Inspect socket inodes manually with ss -tlnp or \
                             netstat -tnp and block this IP at the firewall.",
                            conn.remote_addr, conn.remote_port
                        ),
                    ),
                );
                    count += 1;
                    continue;
                }
            };

        count += 1;
        let (name, uid) = proc_name_uid(pid);
        // Port 53 is legitimate for DNS daemons; skip those to avoid noise.
        if conn.remote_port == 53 && KNOWN_DNS_PROCS.iter().any(|&d| name.contains(d)) {
            count -= 1;
            continue;
        }
        let args = read_cmdline_args(pid, 3);
        let cmdline = fmt_cmdline(&args);
        let exe_str = std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into());

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "c2_detection",
                format!(
                    "PID {} ({}) has ESTABLISHED connection to C2 port {}:{} ",
                    pid, name, conn.remote_addr, conn.remote_port
                ),
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}\ncmdline: {}\nremote: {}:{}",
                    pid, name, uid, exe_str, cmdline, conn.remote_addr, conn.remote_port
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", name.clone())
            .with_context("exe", exe_str.clone())
            .with_context(
                "remote",
                format!("{}:{}", conn.remote_addr, conn.remote_port),
            )
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} ({}) has an ESTABLISHED TCP connection to {}:{}, which is a \
                     known C2 framework port. This is a strong indicator of an active C2 \
                     beacon or reverse shell. Kill PID {} immediately and block {}:{} at \
                     the firewall.",
                    pid,
                    name,
                    conn.remote_addr,
                    conn.remote_port,
                    pid,
                    conn.remote_addr,
                    conn.remote_port
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] C2 port scan complete — {} connection{}",
        count,
        if count == 1 { "" } else { "s" }
    ));
}

// ─── Check 4: Go binary fingerprinting ───────────────────────────────────────

/// Scan running process binaries for Go runtime string signatures indicating compiled implants.
fn check_go_binaries(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning running processes for Go-compiled implants...");
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut count = 0u32;

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(&exe_link) else {
            continue;
        };
        let exe_str = exe_path.to_string_lossy().into_owned();

        // Skip known-good system paths
        if KNOWN_GOOD_GO_PATHS
            .iter()
            .any(|prefix| exe_str.starts_with(prefix))
        {
            continue;
        }

        // Read up to GO_SCAN_LIMIT bytes of the binary
        let bytes = match std::fs::read(&exe_path) {
            Ok(b) => b,
            Err(_) => {
                // Try reading via /proc/<pid>/exe fd (may fail for deleted binaries)
                match std::fs::read(format!("/proc/{}/exe", pid)) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            }
        };
        let slice = if bytes.len() > GO_SCAN_LIMIT {
            &bytes[..GO_SCAN_LIMIT]
        } else {
            &bytes
        };

        // Search for Go runtime strings
        let found_go = GO_BINARY_STRINGS
            .iter()
            .any(|sig| contains_bytes(slice, sig.as_bytes()));

        if !found_go {
            continue;
        }

        count += 1;
        let (name, uid) = proc_name_uid(pid);

        ctx.emit(
            Finding::new(
                Severity::High,
                "c2_detection",
                format!(
                    "PID {} ({}) is a Go-compiled binary outside known system paths — possible implant",
                    pid, name
                ),
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}",
                    pid, name, uid, exe_str
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", name.clone())
            .with_context("exe", exe_str.clone())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} ({}) at path '{}' contains Go runtime strings ('Go build ID:' \
                     and/or 'runtime.gopanic') and is located outside standard system \
                     binary paths. Go is the dominant language for C2 implants (Sliver, \
                     Havoc, Merlin, Ligolo-ng). Investigate this binary's origin and kill \
                     PID {} if unexpected.",
                    pid, name, exe_str, pid
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] Go binary scan complete — {} suspicious process{}",
        count,
        if count == 1 { "" } else { "es" }
    ));
}

/// Naive byte-substring search (avoids pulling in memchr dependency).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── Check 5: high-entropy / cleared argv processes ──────────────────────────

/// Flag processes that have cleared their argv (empty `/proc/<pid>/cmdline`) to hide activity.
fn check_empty_cmdline(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning for processes with cleared argv...");
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut count = 0u32;

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        // Check cmdline — implants often clear argv entirely (empty or single NUL)
        let cmdline_bytes = match std::fs::read(format!("/proc/{}/cmdline", pid)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Non-empty cmdline: skip
        let is_empty = cmdline_bytes.is_empty() || cmdline_bytes.iter().all(|&b| b == 0);
        if !is_empty {
            continue;
        }

        // Must have a resolvable exe (kernel threads don't have a readable /proc/<pid>/exe)
        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(&exe_link) else {
            continue;
        };
        let exe_str = exe_path.to_string_lossy().into_owned();

        // Skip kernel threads (exe link resolves to nothing useful, but
        // read_link itself succeeds on some systems — filter them out by path)
        if exe_str.is_empty() {
            continue;
        }

        // Skip known-good system paths
        if KNOWN_GOOD_PATHS
            .iter()
            .any(|prefix| exe_str.starts_with(prefix))
        {
            continue;
        }

        count += 1;
        let (name, uid) = proc_name_uid(pid);

        ctx.emit(
            Finding::new(
                Severity::Medium,
                "c2_detection",
                format!(
                    "PID {} ({}) has empty cmdline outside system paths — possible implant",
                    pid, name
                ),
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}\ncmdline: <empty>",
                    pid, name, uid, exe_str
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", name.clone())
            .with_context("exe", exe_str.clone())
            .with_context("uid", uid.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} ({}) at path '{}' has an empty /proc/cmdline (no argv) and is \
                     not in a standard system directory. Many C2 implants deliberately clear \
                     their process arguments to avoid appearing in 'ps aux' with suspicious \
                     command lines. Investigate this process and kill PID {} if it is not \
                     expected.",
                    pid, name, exe_str, pid
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[✓] Empty-cmdline scan complete — {} suspicious process{}",
        count,
        if count == 1 { "" } else { "es" }
    ));
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Detect C2 implants and beacons running on the host.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[*] Starting C2 implant / beacon detection...");
    check_memfd(ctx);
    check_deleted_temp(ctx);
    check_c2_ports(ctx);
    check_go_binaries(ctx);
    check_empty_cmdline(ctx);
    ctx.log_msg("[✓] C2 detection complete");
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── memfd path detection ──────────────────────────────────────────────

    #[test]
    fn memfd_path_starts_with_memfd() {
        let path = "/memfd:implant (deleted)";
        assert!(path.starts_with("/memfd:"));
    }

    #[test]
    fn normal_path_is_not_memfd() {
        let path = "/usr/bin/python3";
        assert!(!path.starts_with("/memfd:"));
    }

    // ── Deleted-temp path detection ───────────────────────────────────────

    #[test]
    fn deleted_tmp_is_flagged() {
        let path = "/tmp/agent (deleted)";
        assert!(path.ends_with(" (deleted)"));
        assert!(TEMP_DIRS.iter().any(|p| path.contains(p)));
    }

    #[test]
    fn deleted_dev_shm_is_flagged() {
        let path = "/dev/shm/.x (deleted)";
        assert!(path.ends_with(" (deleted)"));
        assert!(TEMP_DIRS.iter().any(|p| path.contains(p)));
    }

    #[test]
    fn deleted_home_is_not_flagged() {
        // A deleted binary from /home is suspicious but not this check
        let path = "/home/user/tool (deleted)";
        assert!(path.ends_with(" (deleted)"));
        assert!(!TEMP_DIRS.iter().any(|p| path.contains(p)));
    }

    #[test]
    fn non_deleted_tmp_binary_not_flagged() {
        let path = "/tmp/my_script";
        // Does not end with " (deleted)"
        assert!(!path.ends_with(" (deleted)"));
    }

    // ── C2 port list coverage ─────────────────────────────────────────────

    #[test]
    fn cobalt_strike_port_in_list() {
        assert!(C2_PORTS.contains(&50050));
    }

    #[test]
    fn metasploit_port_in_list() {
        assert!(C2_PORTS.contains(&4444));
    }

    #[test]
    fn elite_port_in_list() {
        assert!(C2_PORTS.contains(&31337));
    }

    #[test]
    fn https_port_not_in_c2_list() {
        // 443 is standard HTTPS, must not be in the C2 list
        assert!(!C2_PORTS.contains(&443));
    }

    #[test]
    fn ssh_port_not_in_c2_list() {
        assert!(!C2_PORTS.contains(&22));
    }

    #[test]
    fn all_c2_ports_present() {
        let expected: &[u16] = &[
            50050, 4444, 8888, 9001, 9002, 1337, 31337, 4443, 8443, 2222, 7777,
        ];
        for port in expected {
            assert!(C2_PORTS.contains(port), "missing C2 port {}", port);
        }
    }

    // ── Go binary fingerprinting (string matching) ────────────────────────

    #[test]
    fn go_build_id_string_detected() {
        let fake_binary = b"ELF\x7f...Go build ID: abc123...some code";
        assert!(contains_bytes(fake_binary, b"Go build ID:"));
    }

    #[test]
    fn gopanic_string_detected() {
        let fake_binary = b"ELF\x7f...runtime.gopanic...more code";
        assert!(contains_bytes(fake_binary, b"runtime.gopanic"));
    }

    #[test]
    fn non_go_binary_not_flagged() {
        let fake_binary = b"ELF\x7f...main...some_function...";
        let found_go = GO_BINARY_STRINGS
            .iter()
            .any(|sig| contains_bytes(fake_binary, sig.as_bytes()));
        assert!(!found_go);
    }

    #[test]
    fn go_binary_in_usr_bin_is_known_good() {
        let exe = "/usr/bin/go";
        assert!(KNOWN_GOOD_GO_PATHS.iter().any(|p| exe.starts_with(p)));
    }

    #[test]
    fn go_binary_in_tmp_is_suspicious() {
        let exe = "/tmp/c2agent";
        assert!(!KNOWN_GOOD_GO_PATHS.iter().any(|p| exe.starts_with(p)));
    }

    // ── IPv4 byte-order parsing ───────────────────────────────────────────

    #[test]
    fn parse_loopback_hex() {
        // 0100007F = 127.0.0.1 in little-endian
        let (addr, _port) = parse_hex_addr_v4("0100007F:1234");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn c2_connection_parsed_from_proc_net_tcp() {
        // A synthetic /proc/net/tcp line with remote port 50050 (0xC382)
        // 50050 decimal = 0xC382
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0101A8C0:1234 0202A8C0:C382 01 00000000:00000000 00:00000000 00000000    33        0 99999 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_c2_connections(sample, false);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].remote_port, 50050);
    }

    #[test]
    fn non_c2_connection_not_parsed() {
        // Remote port 443 = 0x01BB — not in C2_PORTS
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0101A8C0:1234 0202A8C0:01BB 01 00000000:00000000 00:00000000 00000000    33        0 88888 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_c2_connections(sample, false);
        assert_eq!(conns.len(), 0);
    }

    // ── Empty cmdline path filtering ──────────────────────────────────────

    #[test]
    fn usr_path_is_known_good() {
        let exe = "/usr/sbin/sshd";
        assert!(KNOWN_GOOD_PATHS.iter().any(|p| exe.starts_with(p)));
    }

    #[test]
    fn opt_path_is_suspicious() {
        let exe = "/opt/implant";
        assert!(!KNOWN_GOOD_PATHS.iter().any(|p| exe.starts_with(p)));
    }

    // ── fmt_cmdline ───────────────────────────────────────────────────────

    #[test]
    fn fmt_cmdline_empty_vec() {
        let result = fmt_cmdline(&[]);
        assert_eq!(result, "<empty>");
    }

    #[test]
    fn fmt_cmdline_single_arg() {
        let args = vec!["/usr/bin/python3".to_string()];
        assert_eq!(fmt_cmdline(&args), "/usr/bin/python3");
    }

    #[test]
    fn fmt_cmdline_multiple_args() {
        let args = vec![
            "python3".to_string(),
            "server.py".to_string(),
            "--port".to_string(),
            "4444".to_string(),
        ];
        assert_eq!(fmt_cmdline(&args), "python3 server.py --port 4444");
    }

    // ── contains_bytes ────────────────────────────────────────────────────

    #[test]
    fn contains_bytes_empty_needle_always_true() {
        assert!(contains_bytes(b"anything", b""));
        assert!(contains_bytes(b"", b""));
    }

    #[test]
    fn contains_bytes_not_found() {
        assert!(!contains_bytes(b"hello world", b"xyz"));
    }

    #[test]
    fn contains_bytes_found_at_start() {
        assert!(contains_bytes(b"Go build ID: abc", b"Go build ID:"));
    }

    #[test]
    fn contains_bytes_found_in_middle() {
        assert!(contains_bytes(
            b"ELF\x7fruntime.gopanicmore",
            b"runtime.gopanic"
        ));
    }

    // ── parse_hex_addr_v6 ─────────────────────────────────────────────────

    #[test]
    fn parse_hex_addr_v6_unspecified_on_short_input() {
        let (addr, _) = parse_hex_addr_v6("0000:1234");
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn parse_c2_connection_non_established_skipped() {
        // State 0A = LISTEN, not ESTABLISHED (01) — should not appear
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_c2_connections(sample, false);
        assert_eq!(conns.len(), 0);
    }

    #[test]
    fn parse_c2_connection_zero_inode_skipped() {
        // inode=0 should be skipped even if port matches
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0101A8C0:1234 0202A8C0:C382 01 00000000:00000000 00:00000000 00000000    33        0 0 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_c2_connections(sample, false);
        assert_eq!(conns.len(), 0, "zero inode must be skipped");
    }

    #[test]
    fn go_binary_strings_all_nonempty() {
        for s in GO_BINARY_STRINGS {
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn snap_path_is_known_good_for_go() {
        let exe = "/snap/go/current/bin/go";
        assert!(KNOWN_GOOD_GO_PATHS.iter().any(|p| exe.starts_with(p)));
    }
}
