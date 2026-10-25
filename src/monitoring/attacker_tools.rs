//! Attacker tool detection: known tool names, executables in hidden dirs,
//! double-extension files, and processes running from deleted/anonymous memory.

use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Filenames (or substrings) that indicate attacker tooling.
const KNOWN_TOOL_NAMES: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "socat",
    "chisel",
    "pspy",
    "pspy32",
    "pspy64",
    "ligolo",
    "ligolo-ng",
    "frp",
    "frps",
    "frpc",
    "fscan",
    "nmap",
    "masscan",
    "mimikatz",
    "meterpreter",
    "msf",
    "msfvenom",
    "cobalt",
    "sliver",
    "havoc",
    "mythic",
    "empire",
    "sqlmap",
    "hydra",
    "john",
    "hashcat",
    "proxychains",
    "revsocks",
    "stowaway",
    "goproxy",
    "ngrok",
    "bore",
    "rathole",
];

/// Directories scanned for known tool names.
const TOOL_SCAN_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/run/shm"];

/// Hidden subdirectories under a home dir that may hide executables.
const HIDDEN_HOME_DIRS: &[&str] = &[".local/bin", ".config", ".cache", ".local/lib"];

/// Double-extension combinations that are clearly attacker staging.
const DOUBLE_EXTENSIONS: &[&str] = &[
    ".sh.sh", ".py.py", ".pl.pl", ".rb.rb", ".php.php", ".sh.py", ".sh.pl", ".sh.rb", ".py.sh",
    ".tar.sh", ".gz.sh", ".zip.sh", ".jpg.sh", ".png.sh", ".pdf.sh",
];

/// Archive-like second-to-last extensions that become suspicious when paired
/// with an executable last extension.
const ARCHIVE_EXTS: &[&str] = &[".tar", ".gz", ".zip", ".bz2"];

/// Executable last-extensions that complete a suspicious double-extension.
const EXEC_EXTS: &[&str] = &[".sh", ".py", ".pl", ".rb", ".exe", ".elf"];

/// Directories scanned for double-extension files.
const DOUBLE_EXT_SCAN_DIRS: &[&str] = &[
    "/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/home", "/var/www", "/opt",
];

/// Scan for known attacker tools and suspicious executables on the host.
pub fn run(ctx: &DefenderContext) -> Result {
    scan_known_tools(ctx);
    scan_hidden_home_executables(ctx);
    scan_double_extensions(ctx);
    scan_deleted_proc_exe(ctx);
    Ok(())
}

// ─── Check 1: known tool names in temp dirs ───────────────────────────────────

/// Check temp directories for executables matching known attacker tool names.
fn scan_known_tools(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning temp dirs for known attacker tools...");
    let mut count = 0u32;

    // Also include per-user hidden dirs
    let mut dirs: Vec<String> = TOOL_SCAN_DIRS.iter().map(|s| s.to_string()).collect();
    if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let home = fields[5];
            dirs.push(format!("{}/.local/bin", home));
            dirs.push(format!("{}/.cache", home));
            dirs.push(format!("{}/.config", home));
        }
    }

    for dir in &dirs {
        for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let fname = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            let matched = KNOWN_TOOL_NAMES.iter().find(|&&t| fname.contains(t));
            if let Some(&tool) = matched {
                ctx.log_msg(&format!(
                    "[!] Known attacker tool found: {}",
                    path.display()
                ));
                ctx.log_evidence_file(path);
                count += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "attacker_tools",
                        format!("Known attacker tool '{}' found: {}", tool, path.display()),
                        format!(
                            "path: {}\nmatched tool: {}\nfilename: {}",
                            path.display(),
                            tool,
                            fname
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("matched tool", tool.to_string())
                    .with_context("filename", fname.to_string())
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "Known attacker tool '{}' found in staging directory. \
                             This is almost certainly red team tooling. Remove the file \
                             and investigate what process placed it here.",
                            tool
                        ),
                    ),
                );
            }
        }
    }

    ctx.log_msg(&format!("[✓] Known-tool scan: {} hit(s)", count));
}

// ─── Check 2: executables in hidden home directories ─────────────────────────

/// Check hidden directories under `/home` and `/root` for executable files.
fn scan_hidden_home_executables(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning hidden home directories for executables...");
    let mut count = 0u32;

    let home_dirs: Vec<String> = parse_home_dirs_from_passwd();

    for home in &home_dirs {
        for subdir in HIDDEN_HOME_DIRS {
            let target = std::path::PathBuf::from(home).join(subdir);
            if !target.exists() {
                continue;
            }

            for entry in WalkDir::new(&target)
                .follow_links(false)
                .into_iter()
                .flatten()
            {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Ok(meta) = path.metadata() else { continue };
                let mode = meta.permissions().mode();
                if mode & 0o111 == 0 {
                    continue;
                } // not executable

                count += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "attacker_tools",
                        format!("Executable in hidden home dir: {}", path.display()),
                        format!(
                            "path: {}\nmode: {:o}\nhome: {}\nsubdir: {}",
                            path.display(),
                            mode,
                            home,
                            subdir
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("mode", format!("{:o}", mode))
                    .with_context("home", home.clone())
                    .with_context("subdir", subdir.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "Executable found in hidden home directory {}. \
                             Legitimate tools installed by package managers use \
                             well-known names; novel binaries here are suspicious. \
                             Verify the binary's origin and remove if unrecognised.",
                            path.display()
                        ),
                    ),
                );
            }
        }
    }

    ctx.log_msg(&format!("[✓] Hidden home exec scan: {} hit(s)", count));
}

/// Read `/etc/passwd` and return the home directory path for every account.
fn parse_home_dirs_from_passwd() -> Vec<String> {
    let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
        return vec![];
    };
    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 6 {
                Some(fields[5].to_string())
            } else {
                None
            }
        })
        .filter(|h| !h.is_empty() && h != "/")
        .collect()
}

// ─── Check 3: double-extension files ─────────────────────────────────────────

/// Scan writable directories for files with misleading double extensions (e.g. `payload.sh.pdf`).
fn scan_double_extensions(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning for double-extension files...");
    let mut count = 0u32;

    for dir in DOUBLE_EXT_SCAN_DIRS {
        for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let fname = match path.file_name() {
                Some(n) => n.to_string_lossy().to_lowercase(),
                None => continue,
            };

            if !fname.contains('.') {
                continue;
            }

            let reason = classify_double_ext(&fname);
            if let Some(reason) = reason {
                count += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "attacker_tools",
                        format!("Double-extension file: {}", path.display()),
                        format!(
                            "path: {}\nfilename: {}\nreason: {}",
                            path.display(),
                            fname,
                            reason
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("filename", fname.to_string())
                    .with_context("reason", reason.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "File '{}' has a double extension that suggests disguised \
                             attacker staging. Archive+exec combos are a common way to \
                             trick users or bypass naive extension checks. Inspect the \
                             file contents and remove if malicious.",
                            path.display()
                        ),
                    ),
                );
            }
        }
    }

    ctx.log_msg(&format!("[✓] Double-extension scan: {} hit(s)", count));
}

/// Returns Some(reason) if the filename matches a suspicious double-extension pattern.
fn classify_double_ext(fname: &str) -> Option<&'static str> {
    // Explicit known-bad combos first
    for &combo in DOUBLE_EXTENSIONS {
        if fname.ends_with(combo) {
            return Some("known double-extension combo");
        }
    }

    // Archive + exec combo: find the last two dot-separated extensions
    let parts: Vec<&str> = fname.rsplitn(3, '.').collect();
    // rsplitn gives: [last_ext, second_to_last_ext, rest...]
    if parts.len() >= 2 {
        let last = format!(".{}", parts[0]);
        let second_last = format!(".{}", parts[1]);
        if ARCHIVE_EXTS.contains(&second_last.as_str()) && EXEC_EXTS.contains(&last.as_str()) {
            return Some("archive+exec extension combo");
        }
    }

    None
}

// ─── Check 4: processes running from deleted/anonymous exe ───────────────────

/// Check `/proc/*/exe` for processes running from deleted on-disk files or memfd.
fn scan_deleted_proc_exe(ctx: &DefenderContext) {
    ctx.log_msg("[+] Scanning /proc for deleted or memfd executables...");
    let mut count = 0u32;

    let Ok(procs) = std::fs::read_dir("/proc") else {
        return;
    };

    for entry in procs.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let exe_link = format!("/proc/{}/exe", pid);
        let Ok(target) = std::fs::read_link(&exe_link) else {
            continue;
        };
        let path_str = target.to_string_lossy();

        let is_deleted_temp = path_str.ends_with(" (deleted)")
            && (path_str.contains("/tmp/")
                || path_str.contains("/dev/shm/")
                || path_str.contains("/var/tmp/")
                || path_str.contains("/run/shm/"));

        let is_memfd = path_str.starts_with("/memfd:");

        if !is_deleted_temp && !is_memfd {
            continue;
        }

        let cmdline = read_proc_cmdline(pid);
        let (uid, proc_name) = read_proc_status(pid);

        count += 1;

        let (summary, reason) = if is_memfd {
            (
                format!(
                    "Process {} ({}) running from anonymous memory (memfd)",
                    proc_name, pid
                ),
                "memfd: executable never existed on disk — classic in-memory dropper technique",
            )
        } else {
            (
                format!(
                    "Process {} ({}) running from deleted temp executable: {}",
                    proc_name, pid, path_str
                ),
                "deleted temp exe: binary was removed after execution — staging cleanup technique",
            )
        };

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "attacker_tools",
                summary,
                format!(
                    "pid: {}\nprocess: {}\nuid: {}\nexe: {}\ncmdline: {}\nreason: {}",
                    pid, proc_name, uid, path_str, cmdline, reason
                ),
            )
            .with_context("pid", pid.to_string())
            .with_context("process", proc_name.clone())
            .with_context("uid", uid.to_string())
            .with_context("exe", path_str.to_string())
            .with_context("cmdline", cmdline.clone())
            .with_context("reason", reason.to_string())
            .with_verdict(
                Verdict::Remove,
                format!(
                    "Process {} (PID {}) is running from {}. \
                     This is a strong indicator of a fileless malware dropper or \
                     in-memory implant. Kill the process immediately: kill -9 {}",
                    proc_name,
                    pid,
                    if is_memfd {
                        "anonymous memory (memfd)"
                    } else {
                        "a deleted temp file"
                    },
                    pid,
                ),
            ),
        );
    }

    ctx.log_msg(&format!("[✓] Deleted/memfd exe scan: {} hit(s)", count));
}

/// Read the command line for `pid` from `/proc/<pid>/cmdline`, NUL-delimited.
fn read_proc_cmdline(pid: u32) -> String {
    let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else {
        return String::new();
    };
    // cmdline separates args with NUL bytes
    raw.split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read UID and process name for `pid` from `/proc/<pid>/status`.
fn read_proc_status(pid: u32) -> (u32, String) {
    let Ok(contents) = std::fs::read_to_string(format!("/proc/{}/status", pid)) else {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_exact_match() {
        let fname = "nmap";
        let matched = KNOWN_TOOL_NAMES.iter().find(|&&t| fname.contains(t));
        assert!(matched.is_some());
        assert_eq!(*matched.unwrap(), "nmap");
    }

    #[test]
    fn tool_name_case_insensitive_partial() {
        // e.g. "PSPY64-linux" should match "pspy64"
        let fname = "pspy64-linux".to_string();
        let lower = fname.to_lowercase();
        let matched = KNOWN_TOOL_NAMES.iter().find(|&&t| lower.contains(t));
        assert!(matched.is_some());
    }

    #[test]
    fn tool_name_no_false_positive() {
        // "script.sh" should not match any tool name
        let fname = "script.sh";
        let matched = KNOWN_TOOL_NAMES.iter().find(|&&t| fname.contains(t));
        assert!(matched.is_none());
    }

    #[test]
    fn double_ext_known_combos() {
        assert!(classify_double_ext("payload.sh.sh").is_some());
        assert!(classify_double_ext("exploit.tar.sh").is_some());
        assert!(classify_double_ext("image.png.sh").is_some());
        assert!(classify_double_ext("script.py.py").is_some());
    }

    #[test]
    fn double_ext_archive_exec_combo() {
        // .gz + .py = archive+exec
        assert!(classify_double_ext("data.gz.py").is_some());
        // .zip + .sh = archive+exec
        assert!(classify_double_ext("payload.zip.sh").is_some());
    }

    #[test]
    fn double_ext_no_false_positive() {
        assert!(classify_double_ext("backup.tar.gz").is_none());
        assert!(classify_double_ext("archive.tar.bz2").is_none());
        assert!(classify_double_ext("script.sh").is_none());
        assert!(classify_double_ext("file.txt").is_none());
    }

    #[test]
    fn memfd_path_detection() {
        let path = "/memfd:kworker (deleted)";
        let is_memfd = path.starts_with("/memfd:");
        assert!(is_memfd);
    }

    #[test]
    fn deleted_temp_path_detection() {
        let path = "/tmp/payload (deleted)";
        let is_deleted_temp = path.ends_with(" (deleted)")
            && (path.contains("/tmp/")
                || path.contains("/dev/shm/")
                || path.contains("/var/tmp/")
                || path.contains("/run/shm/"));
        assert!(is_deleted_temp);
    }

    #[test]
    fn non_temp_deleted_not_flagged() {
        let path = "/usr/bin/legit (deleted)";
        let is_deleted_temp = path.ends_with(" (deleted)")
            && (path.contains("/tmp/")
                || path.contains("/dev/shm/")
                || path.contains("/var/tmp/")
                || path.contains("/run/shm/"));
        assert!(!is_deleted_temp);
    }

    #[test]
    fn parse_home_dirs_extracts_field5() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      www-data:x:33:33::/var/www:/usr/sbin/nologin\n\
                      user1:x:1000:1000::/home/user1:/bin/bash\n";
        let homes: Vec<String> = passwd
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 6 {
                    Some(fields[5].to_string())
                } else {
                    None
                }
            })
            .filter(|h| !h.is_empty() && h != "/")
            .collect();
        assert!(homes.contains(&"/root".to_string()));
        assert!(homes.contains(&"/var/www".to_string()));
        assert!(homes.contains(&"/home/user1".to_string()));
    }

    #[test]
    fn parse_home_dirs_skips_short_lines() {
        let passwd = "bad_line_no_colons\n\
                      user:x:1000:1000::/home/user:/bin/bash\n";
        let homes: Vec<String> = passwd
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 6 {
                    Some(fields[5].to_string())
                } else {
                    None
                }
            })
            .filter(|h| !h.is_empty() && h != "/")
            .collect();
        assert_eq!(homes, vec!["/home/user"]);
    }

    #[test]
    fn classify_double_ext_empty_string() {
        assert!(classify_double_ext("").is_none());
    }

    #[test]
    fn classify_double_ext_single_ext() {
        assert!(classify_double_ext("file.txt").is_none());
        assert!(classify_double_ext("file.sh").is_none());
    }

    #[test]
    fn classify_double_ext_no_ext() {
        assert!(classify_double_ext("Makefile").is_none());
    }

    #[test]
    fn all_known_tool_names_nonempty() {
        for name in KNOWN_TOOL_NAMES {
            assert!(!name.is_empty(), "empty tool name in list");
        }
    }

    #[test]
    fn chisel_detected_as_tool() {
        let fname = "chisel_linux_amd64";
        assert!(KNOWN_TOOL_NAMES.iter().any(|&t| fname.contains(t)));
    }

    #[test]
    fn bash_not_detected_as_tool() {
        let fname = "bash";
        assert!(!KNOWN_TOOL_NAMES.iter().any(|&t| fname.contains(t)));
    }
}
