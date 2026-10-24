//! Parent→child process tree anomalies.
//!
//! Builds a snapshot of the process tree from `/proc` and flags relationships
//! that should never occur in normal operation: a web server spawning a shell,
//! a database spawning a compiler, a service-account process forking a network
//! tool, etc.  Catching these patterns means catching active webshell or
//! post-exploitation activity rather than just artifacts left on disk.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Process families whose children are suspicious when they spawn shells or
/// network tools.
const WEB_SERVER_NAMES: &[&str] = &[
    "apache2", "httpd", "nginx", "lighttpd",
    "php-fpm", "php", "php8.2", "php8.1", "php8.0", "php7.4",
    "uwsgi", "gunicorn", "unicorn",
    "tomcat", "catalina", "java",   // java covers Tomcat/Spring
];

const MAIL_SERVER_NAMES: &[&str] = &[
    "postfix", "master", "smtpd", "qmgr", "pickup", "smtp",
    "dovecot", "imap-login", "pop3-login", "lmtp",
    "exim4", "exim",
    "sendmail",
];

const DATABASE_NAMES: &[&str] = &[
    "mysqld", "mysqld_safe", "mariadbd",
    "postgres", "postgresql",
    "mongod", "redis-server",
];

const SHELL_NAMES: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "busybox",
];

const INTERPRETER_NAMES: &[&str] = &[
    "python", "python2", "python3",
    "perl", "ruby", "php", "node", "nodejs",
    "lua", "tclsh",
];

const NETWORK_TOOL_NAMES: &[&str] = &[
    "nc", "ncat", "netcat", "nmap",
    "curl", "wget",
    "socat", "stunnel",
    "ssh", "scp", "sftp",
];

const COMPILER_NAMES: &[&str] = &[
    "gcc", "cc", "g++", "clang", "clang++",
    "make", "cmake", "cargo", "go",
];

/// A snapshot of one process in /proc.
#[derive(Debug)]
struct ProcEntry {
    pid: u32,
    ppid: u32,
    name: String,
    exe: String,
    cmdline: String,
    uid: u32,
}

/// Read every readable /proc/<pid>/status file and build a process map.
fn snapshot_processes() -> HashMap<u32, ProcEntry> {
    let mut map = HashMap::new();

    let Ok(dir) = std::fs::read_dir("/proc") else {
        return map;
    };

    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let status_path = entry.path().join("status");
        let Ok(status) = std::fs::read_to_string(&status_path) else {
            continue;
        };

        let mut name = String::new();
        let mut ppid = 0u32;
        let mut uid = 0u32;

        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:\t") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("PPid:\t") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Uid:\t") {
                uid = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        if name.is_empty() {
            continue;
        }

        let exe = read_exe(pid);
        let cmdline = read_cmdline(pid);

        map.insert(pid, ProcEntry { pid, ppid, name, exe, cmdline, uid });
    }

    map
}

fn read_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().chars().take(120).collect())
        .unwrap_or_default()
}

fn base_name(exe_or_name: &str) -> &str {
    exe_or_name.split('/').last().unwrap_or(exe_or_name)
        .trim_end_matches(" (deleted)")
}

fn matches_any(name: &str, patterns: &[&str]) -> bool {
    let lower = name.to_lowercase();
    // Strip version suffixes: php8.2 → matches "php"
    patterns.iter().any(|p| lower == *p || lower.starts_with(&format!("{}-", p)) || lower.starts_with(p))
}

/// Classify what kind of process this is for anomaly detection.
#[derive(Debug, PartialEq)]
enum ProcKind {
    WebServer,
    MailServer,
    Database,
    Shell,
    Interpreter,
    NetworkTool,
    Compiler,
    Other,
}

fn classify(entry: &ProcEntry) -> ProcKind {
    let name = base_name(if entry.exe.is_empty() { &entry.name } else { &entry.exe });
    if matches_any(name, WEB_SERVER_NAMES)  { return ProcKind::WebServer; }
    if matches_any(name, MAIL_SERVER_NAMES) { return ProcKind::MailServer; }
    if matches_any(name, DATABASE_NAMES)    { return ProcKind::Database; }
    if matches_any(name, SHELL_NAMES)       { return ProcKind::Shell; }
    if matches_any(name, INTERPRETER_NAMES) { return ProcKind::Interpreter; }
    if matches_any(name, NETWORK_TOOL_NAMES){ return ProcKind::NetworkTool; }
    if matches_any(name, COMPILER_NAMES)    { return ProcKind::Compiler; }
    ProcKind::Other
}

/// Scan the process tree for suspicious parent→child relationships.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Building process tree snapshot...");
    let procs = snapshot_processes();
    ctx.log_msg(&format!("[+] {} processes visible in /proc", procs.len()));

    let mut findings = 0;

    for entry in procs.values() {
        let child_kind = classify(entry);

        // Only flag shells, interpreters, network tools, and compilers
        if !matches!(child_kind,
            ProcKind::Shell | ProcKind::Interpreter |
            ProcKind::NetworkTool | ProcKind::Compiler)
        {
            continue;
        }

        let Some(parent) = procs.get(&entry.ppid) else {
            continue;
        };

        let parent_kind = classify(parent);

        let (severity, parent_role, explanation) = match (&parent_kind, &child_kind) {
            (ProcKind::WebServer, ProcKind::Shell) => (
                Severity::Critical,
                "web server",
                "A web server spawning a shell is the classic webshell exploitation pattern. \
                 An attacker likely uploaded a PHP/CGI webshell and triggered it via HTTP.",
            ),
            (ProcKind::WebServer, ProcKind::Interpreter) => (
                Severity::Critical,
                "web server",
                "A web server spawning an interpreter is consistent with webshell exploitation. \
                 Inspect the HTTP access log around this process's start time.",
            ),
            (ProcKind::WebServer, ProcKind::NetworkTool) => (
                Severity::Critical,
                "web server",
                "A web server spawning a network tool (curl, wget, nc) suggests the attacker \
                 used a webshell to download a second-stage payload or establish a reverse shell.",
            ),
            (ProcKind::MailServer, ProcKind::Shell) => (
                Severity::Critical,
                "mail server",
                "A mail server spawning a shell suggests exploitation of a mail service \
                 vulnerability (e.g., Exim, Postfix pipe delivery, Dovecot plugin).",
            ),
            (ProcKind::Database, ProcKind::Shell) => (
                Severity::Critical,
                "database",
                "A database process spawning a shell suggests SQL injection leading to \
                 command execution (e.g., MySQL UDF exploitation or xp_cmdshell equivalent).",
            ),
            (ProcKind::WebServer, ProcKind::Compiler) |
            (ProcKind::MailServer, ProcKind::Compiler) |
            (ProcKind::Database, ProcKind::Compiler) => (
                Severity::High,
                "service",
                "A service process spawning a compiler is unusual and may indicate an attacker \
                 compiling a privilege-escalation exploit or rootkit on the box.",
            ),
            _ => continue,
        };

        findings += 1;
        let child_display = if entry.exe.is_empty() { &entry.name } else { &entry.exe };
        let parent_display = if parent.exe.is_empty() { &parent.name } else { &parent.exe };

        ctx.emit(
            Finding::new(
                severity,
                "process_tree",
                format!(
                    "{} spawned {} (PID {} → PID {})",
                    base_name(parent_display),
                    base_name(child_display),
                    parent.pid,
                    entry.pid,
                ),
                format!(
                    "parent_pid: {}\nparent_exe: {}\nparent_cmd: {}\nchild_pid:  {}\nchild_exe:  {}\nchild_cmd:  {}\nchild_uid:  {}",
                    parent.pid, parent_display, parent.cmdline,
                    entry.pid, child_display, entry.cmdline, entry.uid,
                ),
            )
            .with_context("parent_pid", parent.pid.to_string())
            .with_context("parent", parent_display.clone())
            .with_context("child_pid", entry.pid.to_string())
            .with_context("child", child_display.clone())
            .with_context("parent_role", parent_role)
            .with_verdict(
                Verdict::Investigate,
                format!("{} Kill PID {} and trace back to the entry point.", explanation, entry.pid),
            ),
        );
    }

    // Also flag any process running from a world-writable or suspicious directory
    for entry in procs.values() {
        if entry.exe.is_empty() { continue; }
        let suspicious_dir = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"]
            .iter()
            .any(|dir| entry.exe.starts_with(dir));

        if suspicious_dir {
            findings += 1;
            ctx.emit(
                Finding::new(
                    Severity::Critical,
                    "process_tree",
                    format!("Process running from world-writable dir: {} (PID {})", entry.exe, entry.pid),
                    format!("pid: {}\nexe: {}\ncmdline: {}\nuid: {}", entry.pid, entry.exe, entry.cmdline, entry.uid),
                )
                .with_context("pid", entry.pid.to_string())
                .with_context("exe", entry.exe.clone())
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "An executable in {} is never a legitimate system process. \
                         This is a strong indicator of a dropped payload. \
                         Kill PID {} and delete the file.",
                        Path::new(&entry.exe).parent().map(|p| p.display().to_string()).unwrap_or_default(),
                        entry.pid,
                    ),
                ),
            );
        }
    }

    ctx.log_msg(&format!("[✓] Process tree scan complete — {} anomal{}", findings,
        if findings == 1 { "y" } else { "ies" }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_server_names_match_versioned() {
        assert!(matches_any("php8.2", WEB_SERVER_NAMES));
        assert!(matches_any("apache2", WEB_SERVER_NAMES));
        assert!(matches_any("nginx", WEB_SERVER_NAMES));
    }

    #[test]
    fn shell_classification() {
        let e = ProcEntry { pid: 1, ppid: 0, name: "bash".into(), exe: "/bin/bash".into(), cmdline: "bash".into(), uid: 33 };
        assert_eq!(classify(&e), ProcKind::Shell);
    }

    #[test]
    fn web_server_classification() {
        let e = ProcEntry { pid: 1, ppid: 0, name: "apache2".into(), exe: "/usr/sbin/apache2".into(), cmdline: "".into(), uid: 33 };
        assert_eq!(classify(&e), ProcKind::WebServer);
    }

    #[test]
    fn snapshot_runs_without_panic() {
        let _ = snapshot_processes();
    }
}
