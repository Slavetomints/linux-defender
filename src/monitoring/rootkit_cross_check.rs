//! Rootkit detection via independent source cross-check.
//!
//! Rootkits hide processes and ports by intercepting kernel interfaces such as
//! the getdents64 syscall or netlink sockets.  By comparing two independent
//! views of the same data — one from the kernel's `/proc` filesystem and one
//! from userspace tools (`ps`, `ss`/`netstat`) — we can surface discrepancies
//! that indicate tampering.
//!
//! ## Check 1 — Hidden processes
//! PIDs visible in `/proc` but absent from `ps` output, or vice versa, suggest
//! a rootkit is intercepting one of the two enumeration paths.
//!
//! ## Check 2 — Hidden listening ports
//! Ports listed in `/proc/net/tcp[6]` as LISTEN (state `0A`) but absent from
//! `ss -tlnp` / `netstat -tlnp`, or ports reported by those tools but absent
//! from `/proc/net/tcp`, indicate a rootkit hiding a backdoor listener.

use std::collections::HashSet;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

// ── Process helpers ──────────────────────────────────────────────────────────

/// Enumerate all numeric directories under `/proc` as PIDs.
fn pids_from_proc() -> HashSet<u32> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return HashSet::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect()
}

/// Run `ps -eo pid --no-headers` and parse the output into a PID set.
fn pids_from_ps() -> HashSet<u32> {
    let Ok(out) = std::process::Command::new("ps")
        .args(["--no-headers", "-eo", "pid"])
        .output()
    else {
        return HashSet::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect()
}

/// Read a single field from `/proc/<pid>/status`.
fn read_status_field(pid: u32, field: &str) -> String {
    let path = format!("/proc/{}/status", pid);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    let prefix = format!("{}:\t", field);
    contents
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Read `/proc/<pid>/cmdline`, replacing NUL bytes with spaces.
fn read_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .chars()
                .take(120)
                .collect()
        })
        .unwrap_or_default()
}

/// Read the exe symlink for a PID.
fn read_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// ── Port helpers ─────────────────────────────────────────────────────────────

/// Parse the local port (decimal) out of a `host:port` hex field from
/// `/proc/net/tcp[6]`.  The format is `XXXX…XXXX:PPPP` where the part after
/// the colon is the port in uppercase hexadecimal.
fn parse_hex_port(addr: &str) -> Option<u16> {
    u16::from_str_radix(addr.split(':').nth(1)?, 16).ok()
}

/// Collect all LISTEN (state `0A`) local ports from a `/proc/net/tcp[6]` file.
fn ports_from_proc_net(contents: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[3] != "0A" {
            continue; // only LISTEN
        }
        if let Some(port) = parse_hex_port(fields[1]) {
            ports.insert(port);
        }
    }
    ports
}

/// Run `ss -tlnp` (falling back to `netstat -tlnp`) and collect the set of
/// listening local ports from the output.
fn ports_from_ss() -> HashSet<u16> {
    // Try `ss` first; fall back to `netstat`.
    let output = std::process::Command::new("ss")
        .args(["-tlnp"])
        .output()
        .or_else(|_| {
            std::process::Command::new("netstat")
                .args(["-tlnp"])
                .output()
        });

    let Ok(out) = output else {
        return HashSet::new();
    };

    let text = String::from_utf8_lossy(&out.stdout);
    parse_ss_ports(&text)
}

/// Parse listening ports from the text output of `ss -tlnp` or `netstat -tlnp`.
///
/// `ss` format (after the header line):
/// ```text
/// LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  ...
/// ```
/// `netstat` format (after two header lines):
/// ```text
/// tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  ...
/// ```
fn parse_ss_ports(output: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // `ss` output: lines starting with "LISTEN"
        if trimmed.starts_with("LISTEN") {
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            // LISTEN  backlog  recv-q  local:port  peer:port  ...
            if let Some(local) = fields.get(3) {
                if let Some(port_str) = local.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        ports.insert(port);
                    }
                }
            }
            continue;
        }

        // `netstat` output: lines starting with "tcp" and containing "LISTEN"
        if (trimmed.starts_with("tcp") || trimmed.starts_with("tcp6")) && trimmed.contains("LISTEN")
        {
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            // tcp  recv-q  send-q  local:port  foreign:port  state  ...
            if let Some(local) = fields.get(3) {
                if let Some(port_str) = local.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        ports.insert(port);
                    }
                }
            }
        }
    }

    ports
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run rootkit cross-check: hidden processes and hidden listening ports.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Running rootkit cross-check (proc vs ps, proc/net vs ss)...");

    let mut findings = 0;

    // ── Check 1: Hidden processes ────────────────────────────────────────────
    let proc_pids = pids_from_proc();
    let ps_pids = pids_from_ps();

    // PIDs in /proc but hidden from ps
    for &pid in proc_pids.difference(&ps_pids) {
        // PID 1 and kernel threads frequently lack a clean ps entry; skip PID 1.
        if pid == 1 {
            continue;
        }

        let exe = read_exe(pid);
        let cmdline = read_cmdline(pid);
        let name = read_status_field(pid, "Name");
        let uid = read_status_field(pid, "Uid");

        findings += 1;
        ctx.emit(
            Finding::new(
                Severity::Critical,
                "rootkit_cross_check",
                format!("PID {} visible in /proc but hidden from ps", pid),
                format!(
                    "pid: {}\nname: {}\nexe: {}\ncmdline: {}\nuid: {}",
                    pid, name, exe, cmdline, uid
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("name", name.clone())
            .with_context("exe", exe.clone())
            .with_context("uid", uid.clone())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} is present in /proc (kernel view) but absent from ps \
                     (userspace view). A rootkit is likely intercepting the getdents64 \
                     syscall or hijacking /proc to hide this process. \
                     Investigate exe '{}' immediately — consider taking a memory image \
                     before killing the process.",
                    pid, exe
                ),
            ),
        );
    }

    // PIDs in ps but absent from /proc (less common, but possible with userspace hooks)
    for &pid in ps_pids.difference(&proc_pids) {
        if pid == 1 {
            continue;
        }
        findings += 1;
        ctx.emit(
            Finding::new(
                Severity::Critical,
                "rootkit_cross_check",
                format!("PID {} visible in ps but not in /proc", pid),
                format!("pid: {}", pid),
            )
            .with_context("pid", pid.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "PID {} appears in ps output but has no entry under /proc. \
                     This may indicate a rootkit manipulating the ps utility or its \
                     library calls while the kernel's /proc is unmodified. \
                     Investigate using independent forensic tools.",
                    pid
                ),
            ),
        );
    }

    ctx.log_msg(&format!(
        "[+] Process cross-check: {} in /proc, {} in ps, {} discrepanc{}",
        proc_pids.len(),
        ps_pids.len(),
        findings,
        if findings == 1 { "y" } else { "ies" },
    ));

    // ── Check 2: Hidden listening ports ──────────────────────────────────────
    let mut proc_ports = HashSet::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            proc_ports.extend(ports_from_proc_net(&contents));
        }
    }

    let ss_ports = ports_from_ss();

    let port_findings_start = findings;

    // Ports in /proc/net but hidden from ss/netstat
    for &port in proc_ports.difference(&ss_ports) {
        findings += 1;
        ctx.emit(
            Finding::new(
                Severity::Critical,
                "rootkit_cross_check",
                format!(
                    "Port {} in LISTEN state in /proc/net but hidden from ss/netstat",
                    port
                ),
                format!(
                    "port: {}\nvisible_in: /proc/net/tcp[6]\nhidden_from: ss/netstat",
                    port
                ),
            )
            .with_context("port", port.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "Port {} is listed as LISTEN in the kernel's /proc/net/tcp but does not \
                     appear in ss or netstat output. A rootkit is likely filtering the \
                     results of those tools. Block this port at the firewall immediately \
                     and investigate what is binding it.",
                    port
                ),
            ),
        );
    }

    // Ports reported by ss/netstat but absent from /proc/net (userspace injection)
    for &port in ss_ports.difference(&proc_ports) {
        findings += 1;
        ctx.emit(
            Finding::new(
                Severity::Critical,
                "rootkit_cross_check",
                format!(
                    "Port {} reported by ss/netstat but absent from /proc/net",
                    port
                ),
                format!(
                    "port: {}\nvisible_in: ss/netstat\nhidden_from: /proc/net/tcp[6]",
                    port
                ),
            )
            .with_context("port", port.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "Port {} appears in ss/netstat output but has no matching entry in \
                     /proc/net/tcp. This is unusual and may indicate tampering with ss \
                     or netstat. Verify with an independent tool.",
                    port
                ),
            ),
        );
    }

    let port_findings = findings - port_findings_start;
    ctx.log_msg(&format!(
        "[+] Port cross-check: {} in /proc/net, {} in ss/netstat, {} discrepanc{}",
        proc_ports.len(),
        ss_ports.len(),
        port_findings,
        if port_findings == 1 { "y" } else { "ies" },
    ));

    ctx.log_msg(&format!(
        "[✓] Rootkit cross-check complete — {} total discrepanc{}",
        findings,
        if findings == 1 { "y" } else { "ies" },
    ));

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PID set comparison ───────────────────────────────────────────────────

    #[test]
    fn pid_hidden_from_ps_is_detected() {
        let proc_set: HashSet<u32> = [1, 2, 100, 999].iter().copied().collect();
        let ps_set: HashSet<u32> = [1, 2, 100].iter().copied().collect();

        // 999 is in proc but not ps
        let hidden: Vec<u32> = proc_set.difference(&ps_set).copied().collect();
        assert_eq!(hidden, vec![999]);
    }

    #[test]
    fn pid_hidden_from_proc_is_detected() {
        let proc_set: HashSet<u32> = [1, 2, 100].iter().copied().collect();
        let ps_set: HashSet<u32> = [1, 2, 100, 555].iter().copied().collect();

        let ghost: Vec<u32> = ps_set.difference(&proc_set).copied().collect();
        assert_eq!(ghost, vec![555]);
    }

    #[test]
    fn matching_pid_sets_have_no_discrepancy() {
        let proc_set: HashSet<u32> = [1, 2, 100].iter().copied().collect();
        let ps_set: HashSet<u32> = [1, 2, 100].iter().copied().collect();

        assert!(proc_set.difference(&ps_set).next().is_none());
        assert!(ps_set.difference(&proc_set).next().is_none());
    }

    // ── Port hex parsing from /proc/net/tcp ──────────────────────────────────

    #[test]
    fn parse_hex_port_standard() {
        // Port 22 (SSH) = 0x0016
        assert_eq!(parse_hex_port("00000000:0016"), Some(22));
    }

    #[test]
    fn parse_hex_port_high() {
        // Port 31337 = 0x7A69
        assert_eq!(parse_hex_port("7F000001:7A69"), Some(31337));
    }

    #[test]
    fn parse_hex_port_missing_colon() {
        assert_eq!(parse_hex_port("00000000"), None);
    }

    #[test]
    fn parse_hex_port_invalid_hex() {
        assert_eq!(parse_hex_port("XXXXXXXX:ZZZZ"), None);
    }

    // ── /proc/net/tcp LISTEN parsing ─────────────────────────────────────────

    const SAMPLE_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0101A8C0:C3A0 0202A8C0:1194 01 00000000:00000000 00:00000000 00000000    33        0 33333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn proc_net_listen_parses_two_ports() {
        let ports = ports_from_proc_net(SAMPLE_TCP);
        assert_eq!(ports.len(), 2, "should find exactly two LISTEN entries");
        assert!(ports.contains(&22), "port 22 should be found (0x0016)");
        assert!(ports.contains(&443), "port 443 should be found (0x01BB)");
    }

    #[test]
    fn proc_net_skips_non_listen() {
        let ports = ports_from_proc_net(SAMPLE_TCP);
        // Entry 2 has state 01 (ESTABLISHED), not 0A — must be absent
        // Port 0xC3A0 = 50080
        assert!(!ports.contains(&50080), "ESTABLISHED entry must not appear");
    }

    #[test]
    fn proc_net_empty_file_returns_empty_set() {
        assert!(ports_from_proc_net("").is_empty());
    }

    #[test]
    fn proc_net_header_only_returns_empty_set() {
        let header = "  sl  local_address rem_address   st\n";
        assert!(ports_from_proc_net(header).is_empty());
    }

    // ── ss output parsing ────────────────────────────────────────────────────

    const SAMPLE_SS: &str = "\
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
LISTEN 0       128     0.0.0.0:22               0.0.0.0:*
LISTEN 0       5       127.0.0.1:53             0.0.0.0:*
";

    #[test]
    fn ss_output_parses_ports() {
        let ports = parse_ss_ports(SAMPLE_SS);
        assert!(ports.contains(&22), "port 22 must be present");
        assert!(ports.contains(&53), "port 53 must be present");
    }

    const SAMPLE_NETSTAT: &str = "\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address  Foreign Address  State
tcp        0      0 0.0.0.0:22     0.0.0.0:*        LISTEN
tcp6       0      0 :::80          :::*             LISTEN
";

    #[test]
    fn netstat_output_parses_ports() {
        let ports = parse_ss_ports(SAMPLE_NETSTAT);
        assert!(ports.contains(&22), "port 22 must be present");
        assert!(ports.contains(&80), "port 80 must be present");
    }

    // ── Port discrepancy detection ────────────────────────────────────────────

    #[test]
    fn hidden_port_detected() {
        let proc_ports: HashSet<u16> = [22, 80, 31337].iter().copied().collect();
        let ss_ports: HashSet<u16> = [22, 80].iter().copied().collect();

        let hidden: Vec<u16> = proc_ports.difference(&ss_ports).copied().collect();
        assert_eq!(hidden, vec![31337]);
    }

    #[test]
    fn no_hidden_ports_when_sets_match() {
        let a: HashSet<u16> = [22, 443].iter().copied().collect();
        let b: HashSet<u16> = [22, 443].iter().copied().collect();
        assert!(a.difference(&b).next().is_none());
        assert!(b.difference(&a).next().is_none());
    }

    #[test]
    fn ghost_port_in_ss_but_not_proc() {
        let proc_ports: HashSet<u16> = [22, 80].iter().copied().collect();
        let ss_ports: HashSet<u16> = [22, 80, 9999].iter().copied().collect();
        let ghost: HashSet<u16> = ss_ports.difference(&proc_ports).copied().collect();
        assert!(ghost.contains(&9999));
    }

    #[test]
    fn pid1_filtered_from_hidden_list() {
        let proc_set: HashSet<u32> = [1, 2, 999].iter().copied().collect();
        let ps_set: HashSet<u32> = [2].iter().copied().collect();
        // Filter out PID 1, same as the run() logic
        let hidden: Vec<u32> = proc_set
            .difference(&ps_set)
            .copied()
            .filter(|&p| p != 1)
            .collect();
        assert!(hidden.contains(&999));
        assert!(!hidden.contains(&1));
    }

    #[test]
    fn ss_output_with_ipv6_port() {
        let sample = "LISTEN 0 128 [::]:443 [::]:*\n";
        let ports = parse_ss_ports(sample);
        assert!(ports.contains(&443));
    }

    #[test]
    fn ss_output_non_listen_line_ignored() {
        let sample = "ESTAB  0  0  127.0.0.1:12345  127.0.0.1:54321\n";
        let ports = parse_ss_ports(sample);
        assert!(ports.is_empty());
    }

    #[test]
    fn parse_hex_port_zero() {
        assert_eq!(parse_hex_port("00000000:0000"), Some(0));
    }

    #[test]
    fn parse_hex_port_max() {
        // 0xFFFF = 65535
        assert_eq!(parse_hex_port("00000000:FFFF"), Some(65535));
    }
}
