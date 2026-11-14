//! sudoers backdoor scanner.
//!
//! Parses `/etc/sudoers` and all files under `/etc/sudoers.d/`, following
//! `@include`, `#include`, and `#includedir` directives.  For each file it
//! looks for configurations that give an attacker a passwordless or
//! environment-injection escalation path and flags them at appropriate
//! severities.
//!
//! It also runs `visudo -c -f <file>` on each parsed file so a tampered or
//! syntactically broken file is surfaced as High — sshd/sudo can behave
//! unpredictably when the config is broken.
//!
//! Like the SSH config scanner, these checks are advisory only: auto-rewriting
//! sudoers is dangerous (a broken file can lock out all admin access).  Every
//! finding carries `Verdict::Investigate` with explicit remediation text.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Path to the main sudoers file.
const SUDOERS_FILE: &str = "/etc/sudoers";
/// Directory containing drop-in sudoers fragments.
const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// UID threshold for "service account" classification.
const SERVICE_UID_THRESHOLD: u32 = 1000;

// ── Entry point ───────────────────────────────────────────────────────────────

/// Scan sudoers files for dangerous configurations.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking sudoers for dangerous configurations...");

    // Load the known-good UIDs and names from /etc/passwd once.
    let known_uids = load_known_uids();
    let known_names: HashSet<String> = HashSet::new(); // is_known_user falls back to /etc/passwd when empty

    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();

    // Seed the queue with the main file and all drop-ins.
    queue.push(PathBuf::from(SUDOERS_FILE));
    let drop_in = Path::new(SUDOERS_DIR);
    if drop_in.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(drop_in)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.path())
            .collect();
        entries.sort();
        queue.extend(entries);
    }

    let mut total_findings = 0usize;

    while let Some(path) = queue.pop() {
        let canonical = match path.canonicalize() {
            Ok(c) => c,
            Err(_) => path.clone(),
        };
        if !visited.insert(canonical) {
            continue; // Already processed.
        }

        let Ok(contents) = std::fs::read_to_string(&path) else {
            ctx.log_msg(&format!("[!] Cannot read {} — skipping", path.display()));
            continue;
        };

        ctx.debug(&format!("Scanning {}", path.display()));

        // Follow include directives before inspecting — queue new files.
        for included in find_includes(&path, &contents) {
            queue.push(included);
        }

        // Run visudo syntax check.
        let visudo_findings = check_visudo(ctx, &path);
        total_findings += visudo_findings.len();
        for f in visudo_findings {
            ctx.emit(f);
        }

        // Inspect the file content.
        let findings = inspect(ctx, &path, &contents, &known_uids, &known_names);
        total_findings += findings.len();
        for f in findings {
            ctx.emit(f);
        }
    }

    if total_findings == 0 {
        ctx.log_msg("[✓] sudoers: no dangerous configurations found");
    } else {
        ctx.log_msg(&format!(
            "[!] sudoers: {} suspicious directive(s) — review with visudo before changing",
            total_findings
        ));
    }

    Ok(())
}

// ── Core inspection ───────────────────────────────────────────────────────────

/// Return all `Finding`s for a single sudoers file.
fn inspect(
    ctx: &DefenderContext,
    path: &Path,
    contents: &str,
    known_uids: &HashSet<u32>,
    known_names: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path_str = path.display().to_string();

    let lines = logical_lines(contents);

    let mut has_requiretty_disabled = false;

    for line in &lines {
        // ── Defaults directives ──────────────────────────────────────────────

        if let Some(defaults_body) = strip_prefix_ci(line, "Defaults") {
            let body_lc = defaults_body.to_lowercase();

            // env_keep += LD_PRELOAD / LD_LIBRARY_PATH
            if body_lc.contains("env_keep") {
                for var in &["ld_preload", "ld_library_path"] {
                    if body_lc.contains(var) {
                        ctx.log_evidence_line(&path_str, line);
                        findings.push(
                            Finding::new(
                                Severity::Critical,
                                "sudoers",
                                format!(
                                    "Defaults env_keep includes {} — dynamic linker injection via sudo",
                                    var.to_uppercase()
                                ),
                                format!(
                                    "File: {}\nLine: {}\n\n\
                                     sudo propagates the user's {} into the privileged environment. \
                                     An attacker can point it at a malicious shared library to gain \
                                     code execution as root.",
                                    path_str, line, var.to_uppercase()
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", line.clone())
                            .with_context("dangerous var", var.to_uppercase())
                            .with_verdict(
                                Verdict::Investigate,
                                "Remove the dangerous variable from env_keep. Run `visudo` to edit \
                                 safely. The env_reset default (keep it on) discards dangerous \
                                 variables unless explicitly listed.",
                            ),
                        );
                    }
                }
            }

            // !requiretty — note and combine later with NOPASSWD
            if body_lc.contains("!requiretty") {
                has_requiretty_disabled = true;
            }

            // !authenticate — equivalent to NOPASSWD for the whole scope
            if body_lc.contains("!authenticate") {
                ctx.log_evidence_line(&path_str, line);
                findings.push(
                    Finding::new(
                        Severity::High,
                        "sudoers",
                        "Defaults !authenticate — sudo never asks for a password",
                        format!(
                            "File: {}\nLine: {}\n\n\
                             The !authenticate default disables the password requirement for sudo \
                             globally (or for the matched scope). This means any user or command \
                             covered by this Defaults line can run as root without entering a \
                             password.",
                            path_str, line
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("directive", line.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        "Remove `!authenticate` from the Defaults line. Use per-rule NOPASSWD \
                         only where absolutely required, scoped to the minimum necessary command.",
                    ),
                );
            }

            continue; // Skip the user-rule checks for Defaults lines.
        }

        // ── User / group rule lines ───────────────────────────────────────────

        // Only check lines that look like rules (contain a `=`).
        if !line.contains('=') {
            continue;
        }

        let line_lc = line.to_lowercase();

        // NOPASSWD: ALL for any user — use extract_commands so we match the
        // command list "ALL" specifically, not "(ALL)" in the runas spec.
        if line_lc.contains("nopasswd")
            && extract_commands(line)
                .iter()
                .any(|c| c.eq_ignore_ascii_case("ALL"))
        {
            // Extract the subject (first token before any whitespace or `ALL`).
            let subject = subject_of_rule(line);
            let is_all_users = subject.eq_ignore_ascii_case("ALL");
            let is_service = is_service_account(&subject, known_uids);

            let severity = Severity::Critical; // NOPASSWD ALL is always Critical regardless of subject
            let _ = (is_all_users, is_service);

            ctx.log_evidence_line(&path_str, line);
            findings.push(
                Finding::new(
                    severity,
                    "sudoers",
                    format!("NOPASSWD: ALL for '{}' — passwordless full sudo", subject),
                    format!(
                        "File: {}\nLine: {}\n\n\
                         The subject '{}' can run ALL commands as root without a password. \
                         This is a complete privilege escalation path.",
                        path_str, line, subject
                    ),
                )
                .with_path(path.to_path_buf())
                .with_context("file", path_str.clone())
                .with_context("subject", subject.clone())
                .with_context("directive", line.clone())
                .with_verdict(
                    Verdict::Investigate,
                    "Remove the NOPASSWD tag, or restrict it to the minimum necessary commands. \
                     If this entry is not required at all, remove the entire line.",
                ),
            );

            // If !requiretty was seen, emit an additional Medium.
            if has_requiretty_disabled {
                findings.push(
                    Finding::new(
                        Severity::Medium,
                        "sudoers",
                        format!(
                            "Defaults !requiretty combined with NOPASSWD for '{}' — enables non-interactive sudo",
                            subject
                        ),
                        format!(
                            "File: {}\n\n\
                             With requiretty disabled and NOPASSWD set, sudo can be invoked from \
                             non-interactive contexts (cron jobs, web shells, reverse shells). \
                             This makes exploitation much easier.",
                            path_str
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        "Remove `!requiretty` from Defaults, or ensure NOPASSWD is not granted \
                         alongside it.",
                    ),
                );
            }

            continue; // Already flagged, don't double-report as wildcard.
        }

        // Wildcard command with NOPASSWD (GTFOBins escalation)
        if line_lc.contains("nopasswd") {
            let cmds = extract_commands(line);
            for cmd in &cmds {
                if cmd.contains(" *") || cmd.ends_with('*') {
                    ctx.log_evidence_line(&path_str, line);
                    findings.push(
                        Finding::new(
                            Severity::High,
                            "sudoers",
                            format!(
                                "NOPASSWD with wildcard command '{}' — GTFOBins escalation path",
                                cmd
                            ),
                            format!(
                                "File: {}\nLine: {}\nCommand: {}\n\n\
                                 The wildcard allows an attacker to pass arbitrary arguments. \
                                 Many common binaries (vim, bash, find, awk) can be used to \
                                 read files or spawn a root shell when called with specific \
                                 arguments (GTFOBins).",
                                path_str, line, cmd
                            ),
                        )
                        .with_path(path.to_path_buf())
                        .with_context("file", path_str.clone())
                        .with_context("command", cmd.clone())
                        .with_context("directive", line.clone())
                        .with_verdict(
                            Verdict::Investigate,
                            "Replace the wildcard with a fully-specified command and arguments, \
                             or remove the rule. Consult https://gtfobins.github.io/ to assess \
                             the risk for each binary.",
                        ),
                    );
                }
            }
        }

        // !authenticate inline in a rule
        if line_lc.contains("!authenticate") && line.contains('=') {
            ctx.log_evidence_line(&path_str, line);
            findings.push(
                Finding::new(
                    Severity::High,
                    "sudoers",
                    format!(
                        "!authenticate directive in rule — passwordless sudo without NOPASSWD tag: {}",
                        subject_of_rule(line)
                    ),
                    format!(
                        "File: {}\nLine: {}\n\n\
                         The !authenticate option in a user rule disables the password requirement \
                         for the matched commands.",
                        path_str, line
                    ),
                )
                .with_path(path.to_path_buf())
                .with_context("file", path_str.clone())
                .with_context("directive", line.clone())
                .with_verdict(
                    Verdict::Investigate,
                    "Remove !authenticate from the rule. Use NOPASSWD only where unavoidable and \
                     scoped to exact command paths.",
                ),
            );
        }

        // (ALL) ALL for a service account (UID < 1000, not root)
        if line_lc.contains("(all)") && line_lc.contains("all") {
            let subject = subject_of_rule(line);
            if is_service_account(&subject, known_uids) {
                ctx.log_evidence_line(&path_str, line);
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "sudoers",
                        format!(
                            "Service account '{}' (UID < 1000) has unrestricted sudo (ALL) ALL",
                            subject
                        ),
                        format!(
                            "File: {}\nLine: {}\n\n\
                             A service account with a low UID that can run ALL commands as any user \
                             is a major escalation risk. Service accounts should never have \
                             unrestricted sudo.",
                            path_str, line
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("account", subject)
                    .with_context("directive", line.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        "Remove the sudo rule for this service account, or restrict it to the \
                         minimum necessary command with full path and no wildcards.",
                    ),
                );
            }
        }

        // Ghost user: subject name maps to a username not in /etc/passwd
        let subject = subject_of_rule(line);
        if !subject.is_empty()
            && !subject.eq_ignore_ascii_case("ALL")
            && !subject.starts_with('%')    // group
            && !subject.starts_with('#')    // UID literal
            && !subject.starts_with('$')    // non-unix
            && !is_known_user(&subject, known_names)
        {
            ctx.log_evidence_line(&path_str, line);
            findings.push(
                Finding::new(
                    Severity::High,
                    "sudoers",
                    format!(
                        "sudoers entry for '{}' — username not found in /etc/passwd (ghost user)",
                        subject
                    ),
                    format!(
                        "File: {}\nLine: {}\n\n\
                         The user '{}' does not exist in /etc/passwd. An attacker may create \
                         this account later to claim the pre-placed sudo rule.",
                        path_str, line, subject
                    ),
                )
                .with_path(path.to_path_buf())
                .with_context("file", path_str.clone())
                .with_context("ghost user", subject)
                .with_context("directive", line.clone())
                .with_verdict(
                    Verdict::Investigate,
                    "Remove the sudoers entry for the non-existent user. If the account was \
                     intentionally removed, ensure its sudo rules were also cleaned up.",
                ),
            );
        }

        // sudoedit pointing to sensitive files
        if line_lc.contains("sudoedit") {
            for sensitive in &["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/"] {
                if line_lc.contains(sensitive) {
                    ctx.log_evidence_line(&path_str, line);
                    findings.push(
                        Finding::new(
                            Severity::High,
                            "sudoers",
                            format!(
                                "sudoedit grants edit access to sensitive path: {}",
                                sensitive
                            ),
                            format!(
                                "File: {}\nLine: {}\nSensitive path: {}\n\n\
                                 Allowing sudoedit on authentication or authorization files lets \
                                 a user plant backdoor accounts, change passwords, or inject \
                                 authorized keys.",
                                path_str, line, sensitive
                            ),
                        )
                        .with_path(path.to_path_buf())
                        .with_context("file", path_str.clone())
                        .with_context("sensitive path", (*sensitive).to_string())
                        .with_context("directive", line.clone())
                        .with_verdict(
                            Verdict::Investigate,
                            "Remove sudoedit access to authentication files. These files must be \
                             protected and managed only by the root account directly.",
                        ),
                    );
                }
            }
        }
    }

    findings
}

// ── visudo syntax check ───────────────────────────────────────────────────────

/// Run `visudo -c -f <path>` and return a `High` finding if it fails.
fn check_visudo(ctx: &DefenderContext, path: &Path) -> Vec<Finding> {
    let path_str = path.display().to_string();

    // If visudo is not available, skip gracefully.
    let output = match std::process::Command::new("visudo")
        .args(["-c", "-f", &path_str])
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            ctx.debug("visudo not available — skipping syntax check");
            return Vec::new();
        }
    };

    if output.status.success() {
        return Vec::new();
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    ctx.log_evidence_line(&path_str, &format!("visudo -c failed: {}", stderr.trim()));

    vec![
        Finding::new(
            Severity::High,
            "sudoers",
            format!(
                "sudoers file {} failed visudo syntax check — possible tampering",
                path_str
            ),
            format!(
                "File: {}\nvisudo stderr: {}\n\n\
                 A syntactically broken sudoers file can cause sudo to deny all access or \
                 fall back to a permissive state, depending on the sudo version and distribution. \
                 This may indicate a malformed backdoor or accidental corruption.",
                path_str,
                stderr.trim()
            ),
        )
        .with_path(path.to_path_buf())
        .with_context("file", path_str)
        .with_context("visudo output", stderr.trim().to_string())
        .with_verdict(
            Verdict::Investigate,
            "Run `visudo -c /etc/sudoers` to see the full error. Edit with `visudo` to fix. \
             Never edit sudoers with a plain text editor — a syntax error can lock out all \
             admin access.",
        ),
    ]
}

// ── Include-following ─────────────────────────────────────────────────────────

/// Find files referenced by `@include`, `#include`, and `#includedir` lines.
fn find_includes(base: &Path, contents: &str) -> Vec<PathBuf> {
    let mut result = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();

        // @include <file> or #include <file>
        if let Some(rest) =
            strip_prefix_ci(trimmed, "@include").or_else(|| strip_prefix_ci(trimmed, "#include"))
        {
            let p = rest.trim().trim_matches('"');
            if !p.is_empty() {
                result.push(PathBuf::from(p));
            }
            continue;
        }

        // @includedir <dir> or #includedir <dir>
        if let Some(rest) = strip_prefix_ci(trimmed, "@includedir")
            .or_else(|| strip_prefix_ci(trimmed, "#includedir"))
        {
            let dir_path = rest.trim().trim_matches('"');
            if dir_path.is_empty() {
                continue;
            }
            let dir = if Path::new(dir_path).is_absolute() {
                PathBuf::from(dir_path)
            } else {
                base.parent().unwrap_or(Path::new("/")).join(dir_path)
            };
            if dir.is_dir() {
                let mut entries: Vec<_> = std::fs::read_dir(&dir)
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .map(|e| e.path())
                    .collect();
                entries.sort();
                result.extend(entries);
            }
        }
    }

    result
}

// ── Line parsing helpers ──────────────────────────────────────────────────────

/// Expand continuation lines and strip comments, returning logical lines.
///
/// Sudoers comments start with `#` (unless it is `#include`/`#includedir`),
/// and lines ending with `\` are joined to the next line.
fn logical_lines(contents: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();

        // Skip blank lines.
        if trimmed.is_empty() {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
            continue;
        }

        // Comments — but keep #include/#includedir so find_includes sees them.
        if trimmed.starts_with('#') && !trimmed.to_lowercase().starts_with("#include") {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
            continue;
        }

        if let Some(cont) = trimmed.strip_suffix('\\') {
            current.push_str(cont);
            current.push(' ');
        } else {
            current.push_str(trimmed);
            result.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

/// Strip a case-insensitive prefix from a string, returning the rest.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    // `get` returns None instead of panicking when `prefix.len()` falls inside
    // a multi-byte character or past the end of `s`.
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// Return the subject (first token) of a sudoers user-spec rule.
///
/// For `alice ALL=(ALL) NOPASSWD: ALL` the subject is `alice`.
/// For `%wheel ALL=(ALL) ALL` the subject is `%wheel`.
fn subject_of_rule(line: &str) -> String {
    line.split_whitespace().next().unwrap_or("").to_string()
}

/// Extract the command portion(s) from a sudoers rule line.
///
/// After the `(run-as)` token, commands appear after the last `)`.
/// We do a best-effort extraction of everything after the last `)`.
fn extract_commands(line: &str) -> Vec<String> {
    // Find the run-as spec: `(ALL:ALL)` or `(root)` etc.
    if let Some(close) = line.rfind(')') {
        let after = line[close + 1..].trim();
        // Strip NOPASSWD: tag if present.
        let cmds_str = after
            .trim_start_matches("NOPASSWD:")
            .trim_start_matches("PASSWD:")
            .trim();
        return cmds_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    Vec::new()
}

// ── /etc/passwd helpers ───────────────────────────────────────────────────────

/// Parsed entry from /etc/passwd: name and UID.
struct PasswdEntry {
    /// Account name from the first field of `/etc/passwd`.
    name: String,
    /// Numeric user ID from the third field of `/etc/passwd`.
    uid: u32,
}

/// Parse /etc/passwd into a set of UIDs and a list of names for ghost-user detection.
fn load_known_uids() -> HashSet<u32> {
    let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
        return HashSet::new();
    };
    parse_passwd_uids(&contents)
        .into_iter()
        .map(|e| e.uid)
        .collect()
}

/// Parse /etc/passwd and return name+uid pairs.
fn parse_passwd_entries(contents: &str) -> Vec<PasswdEntry> {
    contents
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.splitn(7, ':').collect();
            if fields.len() < 3 {
                return None;
            }
            let uid: u32 = fields[2].parse().ok()?;
            Some(PasswdEntry {
                name: fields[0].to_string(),
                uid,
            })
        })
        .collect()
}

/// Alias for `parse_passwd_entries` — returns name+uid pairs from `/etc/passwd` text.
fn parse_passwd_uids(contents: &str) -> Vec<PasswdEntry> {
    parse_passwd_entries(contents)
}

/// True if `name` appears in the provided known-names set.
fn is_known_user(name: &str, known_names: &HashSet<String>) -> bool {
    if known_names.is_empty() {
        // Fallback for non-test paths where names weren't pre-loaded.
        let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
            return true;
        };
        return contents
            .lines()
            .any(|l| l.split(':').next().map(|n| n == name).unwrap_or(false));
    }
    known_names.contains(name)
}

/// True if the subject is a service account (UID < SERVICE_UID_THRESHOLD, not root).
fn is_service_account(name: &str, _known_uids: &HashSet<u32>) -> bool {
    if name.eq_ignore_ascii_case("root") {
        return false;
    }
    let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
        return false;
    };
    for entry in parse_passwd_entries(&contents) {
        if entry.name == name {
            return entry.uid > 0 && entry.uid < SERVICE_UID_THRESHOLD;
        }
    }
    // Name not found — ghost user, not a service account per se.
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_ctx() -> DefenderContext {
        DefenderContext::new(PathBuf::from("/dev/null"), false)
    }

    fn path() -> PathBuf {
        PathBuf::from("/etc/sudoers")
    }

    /// Run inspect with an empty passwd so ghost-user detection works on
    /// controlled input.  We use a wrapper that accepts a passwd string.
    fn inspect_with_passwd(contents: &str, passwd: &str) -> Vec<Finding> {
        let ctx = fake_ctx();
        let entries = parse_passwd_uids(passwd);
        let known_uids: HashSet<u32> = entries.iter().map(|e| e.uid).collect();
        let known_names: HashSet<String> = entries.into_iter().map(|e| e.name).collect();
        inspect(&ctx, &path(), contents, &known_uids, &known_names)
    }

    const MINIMAL_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                                   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                                   alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
                                   svcuser:x:500:500:service:/var/lib/svc:/usr/sbin/nologin\n";

    // ── logical_lines ─────────────────────────────────────────────────────────

    #[test]
    fn logical_lines_joins_continuation() {
        let src = "alice ALL=(ALL) \\\n    NOPASSWD: /bin/ls\n";
        let lines = logical_lines(src);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("NOPASSWD"));
        assert!(lines[0].contains("/bin/ls"));
    }

    #[test]
    fn logical_lines_strips_comments() {
        let src = "# This is a comment\nalice ALL=(ALL) ALL\n";
        let lines = logical_lines(src);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("alice"));
    }

    #[test]
    fn logical_lines_keeps_includedir() {
        let src = "#includedir /etc/sudoers.d\nalice ALL=(ALL) ALL\n";
        let lines = logical_lines(src);
        // Both the includedir and the rule should appear.
        assert!(lines.iter().any(|l| l.contains("includedir")));
        assert!(lines.iter().any(|l| l.contains("alice")));
    }

    // ── NOPASSWD ALL detection ────────────────────────────────────────────────

    #[test]
    fn flags_nopasswd_all_for_named_user() {
        let findings = inspect_with_passwd("alice ALL=(ALL) NOPASSWD: ALL\n", MINIMAL_PASSWD);
        assert!(
            findings.iter().any(|f| {
                f.severity == Severity::Critical && f.summary.contains("NOPASSWD: ALL")
            })
        );
    }

    #[test]
    fn flags_nopasswd_all_for_all_users() {
        let findings = inspect_with_passwd("ALL ALL=(ALL) NOPASSWD: ALL\n", MINIMAL_PASSWD);
        assert!(
            findings.iter().any(|f| {
                f.severity == Severity::Critical && f.summary.contains("NOPASSWD: ALL")
            })
        );
    }

    #[test]
    fn does_not_flag_normal_sudo_all() {
        let findings = inspect_with_passwd("alice ALL=(ALL) ALL\n", MINIMAL_PASSWD);
        // Should not have NOPASSWD finding.
        assert!(!findings.iter().any(|f| f.summary.contains("NOPASSWD: ALL")));
    }

    // ── env_keep LD_PRELOAD detection ─────────────────────────────────────────

    #[test]
    fn flags_env_keep_ld_preload_as_critical() {
        let findings = inspect_with_passwd("Defaults env_keep += LD_PRELOAD\n", MINIMAL_PASSWD);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::Critical && f.summary.contains("LD_PRELOAD") })
        );
    }

    #[test]
    fn flags_env_keep_ld_library_path_as_critical() {
        let findings =
            inspect_with_passwd("Defaults env_keep += LD_LIBRARY_PATH\n", MINIMAL_PASSWD);
        assert!(findings.iter().any(|f| {
            f.severity == Severity::Critical && f.summary.contains("LD_LIBRARY_PATH")
        }));
    }

    #[test]
    fn does_not_flag_env_keep_for_safe_vars() {
        let findings = inspect_with_passwd("Defaults env_keep += HOME MAIL\n", MINIMAL_PASSWD);
        assert!(!findings.iter().any(|f| f.summary.contains("LD_")));
    }

    // ── Ghost user detection ──────────────────────────────────────────────────

    #[test]
    fn flags_ghost_user_not_in_passwd() {
        // "ghost" does not appear in MINIMAL_PASSWD.
        let findings = inspect_with_passwd("ghost ALL=(ALL) ALL\n", MINIMAL_PASSWD);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::High && f.summary.contains("ghost user") })
        );
    }

    #[test]
    fn does_not_flag_known_user() {
        let findings = inspect_with_passwd("alice ALL=(ALL) ALL\n", MINIMAL_PASSWD);
        assert!(!findings.iter().any(|f| f.summary.contains("ghost user")));
    }

    #[test]
    fn does_not_flag_all_keyword_as_ghost_user() {
        let findings = inspect_with_passwd("ALL ALL=(ALL) ALL\n", MINIMAL_PASSWD);
        assert!(!findings.iter().any(|f| f.summary.contains("ghost user")));
    }

    // ── Wildcard command detection ────────────────────────────────────────────

    #[test]
    fn flags_nopasswd_wildcard_command_as_high() {
        let findings =
            inspect_with_passwd("alice ALL=(ALL) NOPASSWD: /usr/bin/vim *\n", MINIMAL_PASSWD);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::High && f.summary.contains("wildcard") })
        );
    }

    #[test]
    fn flags_nopasswd_bash_wildcard_as_high() {
        let findings =
            inspect_with_passwd("alice ALL=(ALL) NOPASSWD: /bin/bash *\n", MINIMAL_PASSWD);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::High && f.summary.contains("wildcard") })
        );
    }

    #[test]
    fn does_not_flag_nopasswd_exact_command_without_wildcard() {
        let findings = inspect_with_passwd(
            "alice ALL=(ALL) NOPASSWD: /usr/bin/apt update\n",
            MINIMAL_PASSWD,
        );
        assert!(!findings.iter().any(|f| f.summary.contains("wildcard")));
    }

    // ── subject_of_rule ───────────────────────────────────────────────────────

    #[test]
    fn subject_of_rule_returns_first_token() {
        assert_eq!(subject_of_rule("alice ALL=(ALL) NOPASSWD: ALL"), "alice");
        assert_eq!(subject_of_rule("%wheel ALL=(ALL) ALL"), "%wheel");
        assert_eq!(subject_of_rule("ALL ALL=(ALL) ALL"), "ALL");
    }

    // ── strip_prefix_ci ───────────────────────────────────────────────────────

    #[test]
    fn strip_prefix_ci_is_case_insensitive() {
        assert_eq!(
            strip_prefix_ci("Defaults env_reset", "defaults"),
            Some(" env_reset")
        );
        assert_eq!(
            strip_prefix_ci("DEFAULTS env_reset", "defaults"),
            Some(" env_reset")
        );
        assert_eq!(strip_prefix_ci("user ALL", "defaults"), None);
    }
}
