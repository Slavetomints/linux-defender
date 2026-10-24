//! Anonymous executable memory detection via `/proc/*/maps`.
//!
//! Shellcode injection and JIT-compiled implants leave a characteristic
//! signature in a process's memory map: anonymous regions (no backing file,
//! inode == 0) that are simultaneously writable and executable (`rwxp`).
//! Legitimate binaries use `r-xp` (read+execute) for their code sections and
//! `rw-p` (read+write) for their data sections; a page that is both writable
//! and executable from an anonymous allocation is the hallmark of shellcode.
//!
//! ## False-positive mitigation
//! Several well-known runtimes (Java, Node.js, Python, Ruby, Firefox, etc.)
//! use JIT compilation and legitimately need `rwx` anonymous pages.  Findings
//! for these processes are downgraded to [`Severity::Info`] rather than
//! [`Severity::High`] so operators are not flooded with noise.
//!
//! ## What is checked
//! For each readable `/proc/<pid>/maps` file:
//! 1. Lines where the permissions field contains both `w` and `x` (writable +
//!    executable).
//! 2. The inode field is `0` — the region has no backing file (anonymous).
//! 3. The process binary does not live under `/usr/`, `/bin/`, `/sbin/`, or
//!    `/lib/` (system paths).
//!
//! One finding is emitted per process, summarising the count of such regions.

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

// ── Skip list ────────────────────────────────────────────────────────────────

/// Process names whose anonymous `rwx` pages are expected (JIT engines).
/// Matching is case-insensitive substring containment.
const JIT_PROCESS_NAMES: &[&str] = &[
    "java", "node", "python", "ruby", "perl", "php",
    "firefox", "chrome", "chromium", "electron",
];

fn is_jit_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    JIT_PROCESS_NAMES.iter().any(|jit| lower.contains(jit))
}

// ── System-path filter ───────────────────────────────────────────────────────

/// Return `true` if the executable lives under a standard system directory.
/// We avoid flagging kernel workers and well-known system daemons.
const SYSTEM_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/"];

fn is_system_exe(exe: &str) -> bool {
    if exe.is_empty() {
        return true; // kernel thread or unreadable — skip
    }
    SYSTEM_PREFIXES.iter().any(|p| exe.starts_with(p))
}

// ── Maps line parsing ────────────────────────────────────────────────────────

/// Parsed representation of a single `/proc/<pid>/maps` line.
#[derive(Debug, PartialEq)]
struct MapsEntry {
    /// Permissions string, e.g. `rwxp` or `r-xp`.
    perms: String,
    /// Backing-file inode.  `0` means anonymous (no file).
    inode: u64,
    /// Optional pathname (empty for anonymous regions like `[heap]`, `[stack]`,
    /// `[anon ...]`, or truly unnamed pages).
    pathname: String,
}

/// Parse a single `/proc/<pid>/maps` line into a [`MapsEntry`].
///
/// Format (space-separated):
/// ```text
/// address          perms  offset  dev    inode  [pathname]
/// 7f1234000-7f1235000  rwxp  00000000  00:00  0
/// ```
fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let mut fields = line.split_whitespace();
    let _address  = fields.next()?;  // "start-end"
    let perms     = fields.next()?.to_string();
    let _offset   = fields.next()?;
    let _dev      = fields.next()?;
    let inode_str = fields.next()?;
    let inode: u64 = inode_str.parse().ok()?;
    // Everything after the fifth field is the pathname (may be absent)
    let pathname = fields.next().unwrap_or("").to_string();

    Some(MapsEntry { perms, inode, pathname })
}

/// Return `true` if this maps entry represents an anonymous executable page.
///
/// Criteria:
/// - permissions contain both `w` (writable) and `x` (executable)
/// - inode is `0` (no backing file)
fn is_rwx_anonymous(entry: &MapsEntry) -> bool {
    entry.inode == 0
        && entry.perms.contains('w')
        && entry.perms.contains('x')
}

// ── Process metadata helpers ─────────────────────────────────────────────────

fn read_proc_status(pid: u32) -> (String, String) {
    let path = format!("/proc/{}/status", pid);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return (String::new(), String::new());
    };

    let mut name = String::new();
    let mut uid  = String::new();

    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("Name:\t") {
            name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Uid:\t") {
            uid = v.split_whitespace().next().unwrap_or("").to_string();
        }
        if !name.is_empty() && !uid.is_empty() {
            break;
        }
    }

    (name, uid)
}

fn read_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Scan all readable `/proc/*/maps` files for anonymous executable regions.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning /proc/*/maps for anonymous executable (rwx) regions...");

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        ctx.log_msg("[!] Cannot read /proc — skipping proc_maps check");
        return Ok(());
    };

    let mut findings = 0;

    for entry in proc_dir.flatten() {
        // Only numeric directories are process entries
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let maps_path = entry.path().join("maps");
        let Ok(maps_contents) = std::fs::read_to_string(&maps_path) else {
            continue; // process may have exited or we lack permission
        };

        // Count rwx anonymous regions in this process
        let rwx_count = maps_contents
            .lines()
            .filter_map(parse_maps_line)
            .filter(is_rwx_anonymous)
            .count();

        if rwx_count == 0 {
            continue;
        }

        // Collect process metadata
        let exe               = read_exe(pid);
        let (name, uid)       = read_proc_status(pid);
        let display_name      = if name.is_empty() { format!("pid:{}", pid) } else { name.clone() };

        // Skip processes we cannot meaningfully investigate (kernel threads etc.)
        // read_exe returns empty for kernel threads; is_system_exe returns true → skip
        if is_system_exe(&exe) {
            continue;
        }

        let severity = if is_jit_process(&name) {
            Severity::Info
        } else {
            Severity::High
        };

        let summary = format!(
            "{} (PID {}) has {} anonymous rwx memory region{}",
            display_name,
            pid,
            rwx_count,
            if rwx_count == 1 { "" } else { "s" },
        );

        let detail = format!(
            "pid: {}\nname: {}\nexe: {}\nuid: {}\nrwx_anon_regions: {}",
            pid, display_name, exe, uid, rwx_count
        );

        let recommendation = if severity == Severity::Info {
            format!(
                "'{}' is a known JIT runtime. Anonymous rwx pages are expected and \
                 do not indicate compromise by themselves. Verify the process is the \
                 legitimate binary at '{}' and that its parent lineage is normal.",
                display_name, exe
            )
        } else {
            format!(
                "'{}' (PID {}, exe '{}') has {} anonymous rwx page{} with no backing \
                 file. This is a strong indicator of shellcode injection or a \
                 memory-resident implant. Take a process memory dump with \
                 `gcore {}` before killing the process, then investigate the dump.",
                display_name, pid, exe,
                rwx_count,
                if rwx_count == 1 { "" } else { "s" },
                pid,
            )
        };

        findings += 1;
        ctx.emit(
            Finding::new(severity, "proc_maps", summary, detail)
                .with_context("pid", pid.to_string())
                .with_context("name", display_name)
                .with_context("exe", exe)
                .with_context("uid", uid)
                .with_context("rwx_anon_regions", rwx_count.to_string())
                .with_verdict(Verdict::Investigate, recommendation),
        );
    }

    ctx.log_msg(&format!(
        "[✓] proc_maps scan complete — {} process{} with anonymous rwx region{}",
        findings,
        if findings == 1 { "" } else { "es" },
        if findings == 1 { "" } else { "s" },
    ));

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_maps_line ───────────────────────────────────────────────────────

    #[test]
    fn parses_rwx_anonymous_line() {
        let line = "7f1234000000-7f1234001000 rwxp 00000000 00:00 0";
        let entry = parse_maps_line(line).expect("should parse");
        assert_eq!(entry.perms, "rwxp");
        assert_eq!(entry.inode, 0);
        assert!(entry.pathname.is_empty());
    }

    #[test]
    fn parses_rx_file_backed_line() {
        // A normal code section: r-xp, non-zero inode, and a pathname
        let line = "7f1234000000-7f1234100000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6";
        let entry = parse_maps_line(line).expect("should parse");
        assert_eq!(entry.perms, "r-xp");
        assert_eq!(entry.inode, 123456);
        assert!(entry.pathname.contains("libc"));
    }

    #[test]
    fn parses_rw_anonymous_line() {
        // rw-p anon — writable but not executable
        let line = "7ffff7ff0000-7ffff7ff1000 rw-p 00000000 00:00 0";
        let entry = parse_maps_line(line).expect("should parse");
        assert_eq!(entry.perms, "rw-p");
        assert_eq!(entry.inode, 0);
    }

    #[test]
    fn parse_maps_line_rejects_too_short() {
        assert!(parse_maps_line("").is_none());
        assert!(parse_maps_line("addr perms").is_none());
    }

    // ── is_rwx_anonymous ─────────────────────────────────────────────────────

    #[test]
    fn rwxp_anon_is_flagged() {
        let entry = MapsEntry {
            perms: "rwxp".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(is_rwx_anonymous(&entry));
    }

    #[test]
    fn rxp_file_backed_is_not_flagged() {
        let entry = MapsEntry {
            perms: "r-xp".into(),
            inode: 12345,
            pathname: "/bin/bash".into(),
        };
        assert!(!is_rwx_anonymous(&entry));
    }

    #[test]
    fn rwp_anon_is_not_flagged() {
        // writable but not executable
        let entry = MapsEntry {
            perms: "rw-p".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(!is_rwx_anonymous(&entry));
    }

    #[test]
    fn rxp_anon_is_not_flagged() {
        // executable but not writable — normal for anonymous trampolines on some systems
        let entry = MapsEntry {
            perms: "r-xp".into(),
            inode: 0,
            pathname: String::new(),
        };
        assert!(!is_rwx_anonymous(&entry));
    }

    #[test]
    fn rwxp_file_backed_is_not_flagged() {
        // rwx but has a backing file — unusual but not anonymous injection
        let entry = MapsEntry {
            perms: "rwxp".into(),
            inode: 99999,
            pathname: "/tmp/suspicious.so".into(),
        };
        assert!(!is_rwx_anonymous(&entry));
    }

    // ── is_jit_process ───────────────────────────────────────────────────────

    #[test]
    fn java_is_jit() {
        assert!(is_jit_process("java"));
        assert!(is_jit_process("java11"));
    }

    #[test]
    fn node_is_jit() {
        assert!(is_jit_process("node"));
        assert!(is_jit_process("nodejs"));
    }

    #[test]
    fn python_is_jit() {
        assert!(is_jit_process("python3"));
        assert!(is_jit_process("python2.7"));
    }

    #[test]
    fn chrome_is_jit() {
        assert!(is_jit_process("chrome"));
        assert!(is_jit_process("chromium"));
        assert!(is_jit_process("chromium-browser"));
    }

    #[test]
    fn nginx_is_not_jit() {
        assert!(!is_jit_process("nginx"));
    }

    #[test]
    fn bash_is_not_jit() {
        assert!(!is_jit_process("bash"));
    }

    // ── is_system_exe ─────────────────────────────────────────────────────────

    #[test]
    fn usr_bin_is_system() {
        assert!(is_system_exe("/usr/bin/python3"));
        assert!(is_system_exe("/usr/sbin/sshd"));
    }

    #[test]
    fn bin_is_system() {
        assert!(is_system_exe("/bin/bash"));
    }

    #[test]
    fn lib_is_system() {
        assert!(is_system_exe("/lib/systemd/systemd"));
    }

    #[test]
    fn tmp_is_not_system() {
        assert!(!is_system_exe("/tmp/evil"));
        assert!(!is_system_exe("/home/user/malware"));
    }

    #[test]
    fn empty_exe_is_system() {
        // kernel threads have no readable exe — treat as system to avoid noise
        assert!(is_system_exe(""));
    }
}
