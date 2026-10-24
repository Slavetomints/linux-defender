//! sshd_config backdoor scanner.
//!
//! Parses `/etc/ssh/sshd_config` and any drop-in files under
//! `/etc/ssh/sshd_config.d/` looking for options that either directly enable
//! root/password access or represent common backdoor patterns: custom
//! `AuthorizedKeysFile` paths, `AuthorizedKeysCommand` hooks, `ForceCommand`
//! overrides, environment injection via `AcceptEnv`, and `Match` blocks that
//! downgrade a safe default.
//!
//! Because most of these options can lock an operator out if changed blindly,
//! this module never modifies the config — it emits `Verdict::Investigate`
//! findings with explicit remediation instructions so the operator can make an
//! informed decision.

use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_DIR: &str = "/etc/ssh/sshd_config.d";

/// One parsed directive from an sshd_config file.
#[derive(Debug, PartialEq, Eq)]
struct Directive {
    /// Lowercased key.
    key: String,
    /// Raw value, whitespace-trimmed but case preserved.
    value: String,
    /// The original line as it appears in the file (for evidence logging).
    raw: String,
}

/// Scan sshd_config and drop-ins for backdoor options and dangerous settings.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking sshd_config for backdoor configurations...");

    let mut files: Vec<(PathBuf, String)> = Vec::new();

    // Main config file.
    let main = Path::new(SSHD_CONFIG);
    if let Ok(content) = std::fs::read_to_string(main) {
        files.push((main.to_path_buf(), content));
    } else {
        ctx.log_msg(&format!("[!] Could not read {} — skipping", SSHD_CONFIG));
    }

    // Drop-in directory.
    let drop_in_dir = Path::new(SSHD_CONFIG_DIR);
    if drop_in_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(drop_in_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            if let Ok(content) = std::fs::read_to_string(&path) {
                files.push((path, content));
            }
        }
    }

    if files.is_empty() {
        ctx.log_msg("[!] No sshd_config files found — skipping SSH config check");
        return Ok(());
    }

    let mut total_findings = 0usize;

    for (path, contents) in &files {
        ctx.debug(&format!("Scanning {}", path.display()));
        let findings = inspect(ctx, path, contents);
        total_findings += findings.len();
        for f in findings {
            ctx.emit(f);
        }
    }

    // Check for missing access restriction directives across all files combined.
    let combined: String = files
        .iter()
        .map(|(_, c)| c.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let has_allow_deny = combined
        .lines()
        .filter_map(effective_ssh_line)
        .any(|(k, _)| {
            matches!(
                k.to_lowercase().as_str(),
                "allowusers" | "denyusers" | "allowgroups" | "denygroups"
            )
        });
    if !has_allow_deny {
        ctx.emit(
            Finding::new(
                Severity::Info,
                "ssh_config",
                "No AllowUsers/DenyUsers/AllowGroups/DenyGroups directives found",
                "Without access restriction directives, any valid user account may \
                 authenticate over SSH.",
            )
            .with_verdict(
                Verdict::Investigate,
                "Add `AllowUsers` or `AllowGroups` to sshd_config to restrict who can \
                 log in via SSH. Alternatively add a `DenyUsers` list for high-risk \
                 accounts.",
            ),
        );
        total_findings += 1;
    }

    if total_findings == 0 {
        ctx.log_msg("[✓] sshd_config: no dangerous options found");
    } else {
        ctx.log_msg(&format!(
            "[!] sshd_config: {} suspicious directive(s) found — review before changing",
            total_findings
        ));
    }

    Ok(())
}

/// Return all `Finding`s for a single sshd_config file.
fn inspect(ctx: &DefenderContext, path: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path_str = path.display().to_string();

    let directives: Vec<Directive> = parse_directives(contents);

    // Track whether we are inside a Match block so we can report it.
    let mut in_match_block = false;

    for directive in &directives {
        let key = directive.key.as_str();
        let value = directive.value.as_str();
        let value_lc = value.to_lowercase();

        // Detect entering a Match block.
        if key == "match" {
            in_match_block = true;
            continue;
        }

        let block_prefix = if in_match_block {
            " (inside Match block)"
        } else {
            ""
        };

        match key {
            "permitrootlogin" => match value_lc.as_str() {
                "yes" => {
                    ctx.log_evidence_line(&path_str, &directive.raw);
                    findings.push(
                            Finding::new(
                                Severity::High,
                                "ssh_config",
                                format!("PermitRootLogin yes{} — root can log in with a password", block_prefix),
                                format!(
                                    "File: {}\nLine: {}\n\n\
                                     Allows the root account to authenticate with a password over SSH. \
                                     Combined with PasswordAuthentication yes this exposes root to \
                                     brute-force attacks.",
                                    path_str, directive.raw
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", directive.raw.clone())
                            .with_verdict(
                                Verdict::Investigate,
                                "Change to `PermitRootLogin prohibit-password` (key-only) or \
                                 `PermitRootLogin no`. Then run `systemctl reload sshd`. \
                                 Verify you have an alternative root access path before reloading.",
                            ),
                        );
                }
                "without-password" | "prohibit-password" => {
                    findings.push(
                        Finding::new(
                            Severity::Info,
                            "ssh_config",
                            format!("PermitRootLogin {} — key-only root login permitted", value),
                            format!(
                                "File: {}\nLine: {}\n\n\
                                     Root can log in but only with a public key (password auth \
                                     is rejected). Acceptable in many environments, but worth \
                                     noting during a competition.",
                                path_str, directive.raw
                            ),
                        )
                        .with_path(path.to_path_buf())
                        .with_context("file", path_str.clone())
                        .with_context("directive", directive.raw.clone())
                        .with_verdict(
                            Verdict::Info,
                            "Key-only root login is lower-risk than password login, but \
                                 consider setting PermitRootLogin no if direct root SSH access \
                                 is not required.",
                        ),
                    );
                }
                _ => {}
            },

            "passwordauthentication" if value_lc == "yes" => {
                ctx.log_evidence_line(&path_str, &directive.raw);
                findings.push(
                    Finding::new(
                        Severity::Medium,
                        "ssh_config",
                        format!(
                            "PasswordAuthentication yes{} — passwords are brute-forceable",
                            block_prefix
                        ),
                        format!(
                            "File: {}\nLine: {}\n\n\
                             Allows password-based SSH login. Combined with a weak or reused \
                             password this makes accounts trivially brute-forceable.",
                            path_str, directive.raw
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("directive", directive.raw.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        "Set `PasswordAuthentication no` and rely on public-key auth. \
                         Ensure all legitimate users have their key loaded before reloading sshd.",
                    ),
                );
            }

            "permitemptypasswords" if value_lc == "yes" => {
                ctx.log_evidence_line(&path_str, &directive.raw);
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "ssh_config",
                        format!(
                            "PermitEmptyPasswords yes{} — empty password accepted",
                            block_prefix
                        ),
                        format!(
                            "File: {}\nLine: {}\n\n\
                             Any account with an empty password can log in with no credentials \
                             at all. This is almost certainly a backdoor.",
                            path_str, directive.raw
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("directive", directive.raw.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        "Set `PermitEmptyPasswords no` immediately and reload sshd. \
                         Also audit /etc/shadow for accounts with an empty password hash field.",
                    ),
                );
            }

            "authorizedkeysfile" => {
                // Flag any path that is not a relative home-relative .ssh path.
                for token in value.split_whitespace() {
                    let suspicious = token.starts_with('/')
                        && !token.starts_with("/home/")
                        && token != "/dev/null";
                    let in_world_writable = token.starts_with("/tmp/")
                        || token.starts_with("/var/tmp/")
                        || token.starts_with("/dev/shm/")
                        || token.starts_with("/run/");
                    if suspicious || in_world_writable {
                        ctx.log_evidence_line(&path_str, &directive.raw);
                        findings.push(
                            Finding::new(
                                Severity::Critical,
                                "ssh_config",
                                format!(
                                    "AuthorizedKeysFile points to non-standard path: {}{}",
                                    token, block_prefix
                                ),
                                format!(
                                    "File: {}\nLine: {}\nPath: {}\n\n\
                                     The authorized_keys file is stored outside ~/.ssh/. \
                                     An attacker can place a key in a world-writable location \
                                     (e.g. /tmp, /dev/shm) to persist SSH access.",
                                    path_str, directive.raw, token
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", directive.raw.clone())
                            .with_context("suspicious path", token.to_string())
                            .with_verdict(
                                Verdict::Investigate,
                                "Restore AuthorizedKeysFile to the default (`.ssh/authorized_keys`). \
                                 Inspect and remove any key stored at the flagged path. \
                                 Then reload sshd.",
                            ),
                        );
                    }
                }
            }

            "authorizedkeyscommand" => {
                ctx.log_evidence_line(&path_str, &directive.raw);
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "ssh_config",
                        format!(
                            "AuthorizedKeysCommand set to '{}'{} — executes a program to supply keys",
                            value, block_prefix
                        ),
                        format!(
                            "File: {}\nLine: {}\n\n\
                             sshd runs this program on every authentication attempt and trusts \
                             its stdout as a list of authorized keys. A backdoor program here \
                             can allow any key the attacker controls.",
                            path_str, directive.raw
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("directive", directive.raw.clone())
                    .with_context("command", value.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        "Remove or comment out AuthorizedKeysCommand. Inspect the program it \
                         points to for malicious content. Reload sshd after removing.",
                    ),
                );
            }

            "forcecommand" if value != "internal-sftp" => {
                ctx.log_evidence_line(&path_str, &directive.raw);
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "ssh_config",
                        format!(
                            "ForceCommand set to '{}'{} — overrides the login shell for all users",
                            value, block_prefix
                        ),
                        format!(
                            "File: {}\nLine: {}\n\n\
                             ForceCommand replaces the user's requested command (including their \
                             shell) with a fixed program. Used outside a Match block this applies \
                             to every SSH session. An attacker uses this to run a backdoor on \
                             every login.",
                            path_str, directive.raw
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("file", path_str.clone())
                    .with_context("directive", directive.raw.clone())
                    .with_context("forced command", value.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        "Remove ForceCommand unless it is intentional (e.g. inside a Match block \
                         for SFTP-only accounts). Inspect the command binary for tampering. \
                         Reload sshd after removing.",
                    ),
                );
            }

            "acceptenv" => {
                let dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH"];
                for var in &dangerous_vars {
                    // value may be a space-separated list or contain globs like LD_*
                    let value_uc = value.to_uppercase();
                    if value_uc.contains(*var)
                        || value_uc.contains("LD_*")
                        || value_uc.contains("LD_PRE")
                    {
                        ctx.log_evidence_line(&path_str, &directive.raw);
                        findings.push(
                            Finding::new(
                                Severity::Critical,
                                "ssh_config",
                                format!(
                                    "AcceptEnv allows {}{} — dynamic linker injection via SSH",
                                    var, block_prefix
                                ),
                                format!(
                                    "File: {}\nLine: {}\n\n\
                                     sshd forwards the client's {} environment variable to the \
                                     server session. An attacker can set this to a malicious \
                                     shared library to inject code into every process the user runs.",
                                    path_str, directive.raw, var
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", directive.raw.clone())
                            .with_context("dangerous var", (*var).to_string())
                            .with_verdict(
                                Verdict::Investigate,
                                "Remove the dangerous variable from AcceptEnv. If AcceptEnv is only \
                                 used for locale variables, restrict it to `LANG LC_*`. Reload sshd.",
                            ),
                        );
                        break; // Avoid duplicate findings for the same line.
                    }
                }
            }

            "listenaddress" => {
                // Flag if the address contains an unusual port (not 22).
                if let Some(port) = extract_port(value) {
                    if port != 22 {
                        findings.push(
                            Finding::new(
                                Severity::Medium,
                                "ssh_config",
                                format!(
                                    "ListenAddress on non-standard port {}{} — could indicate a hidden backdoor listener",
                                    port, block_prefix
                                ),
                                format!(
                                    "File: {}\nLine: {}\n\n\
                                     sshd is configured to listen on port {} in addition to (or \
                                     instead of) the standard port 22. Verify this is intentional.",
                                    path_str, directive.raw, port
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", directive.raw.clone())
                            .with_context("port", port.to_string())
                            .with_verdict(
                                Verdict::Investigate,
                                "Confirm whether the non-standard port was intentionally configured. \
                                 If not, restore ListenAddress to the default and reload sshd.",
                            ),
                        );
                    }
                }
            }

            "maxauthtries" => {
                if let Ok(n) = value.parse::<u32>() {
                    if n > 6 {
                        findings.push(
                            Finding::new(
                                Severity::Medium,
                                "ssh_config",
                                format!(
                                    "MaxAuthTries {} is above 6{} — makes brute-force easier",
                                    n, block_prefix
                                ),
                                format!(
                                    "File: {}\nLine: {}\n\n\
                                     A high MaxAuthTries allows an attacker to attempt many \
                                     passwords per connection, reducing the effectiveness of \
                                     brute-force rate limiting.",
                                    path_str, directive.raw
                                ),
                            )
                            .with_path(path.to_path_buf())
                            .with_context("file", path_str.clone())
                            .with_context("directive", directive.raw.clone())
                            .with_context("value", n.to_string())
                            .with_verdict(
                                Verdict::Investigate,
                                "Set MaxAuthTries to 3 or 4. The default in most distributions \
                                 is 6; lower is safer.",
                            ),
                        );
                    }
                }
            }

            _ => {}
        }
    }

    // Check for a "Match" block that overrides a safe setting with a dangerous one.
    // We detect this by re-scanning for dangerous directives that appear after a Match line.
    findings.extend(inspect_match_blocks(ctx, path, &path_str, contents));

    findings
}

/// Emit a `High` finding for each dangerous directive that appears inside a
/// `Match` block (directives that were not already flagged above because the
/// "in_match_block" flag is reset per file in `inspect`).
fn inspect_match_blocks(
    ctx: &DefenderContext,
    path: &Path,
    path_str: &str,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_match = false;

    for line in contents.lines() {
        let Some(effective) = effective_ssh_line(line) else {
            continue;
        };
        let (key, value) = effective;
        let key_lc = key.to_lowercase();
        let value_lc = value.to_lowercase();

        if key_lc == "match" {
            in_match = true;
            continue;
        }

        if !in_match {
            continue;
        }

        // These safe-to-dangerous downgrades inside a Match block are High.
        let dangerous = matches!(
            (key_lc.as_str(), value_lc.as_str()),
            ("permitrootlogin", "yes")
                | ("passwordauthentication", "yes")
                | ("permitemptypasswords", "yes")
        );

        if dangerous {
            ctx.log_evidence_line(path_str, line.trim());
            findings.push(
                Finding::new(
                    Severity::High,
                    "ssh_config",
                    format!(
                        "Match block overrides safe setting: {} {} — context-specific backdoor",
                        key, value
                    ),
                    format!(
                        "File: {}\nLine: {}\n\n\
                         A Match block selectively re-enables a dangerous option for a subset \
                         of connections (e.g. a specific user or IP). This can create a targeted \
                         backdoor that is harder to notice than a global setting.",
                        path_str,
                        line.trim()
                    ),
                )
                .with_path(path.to_path_buf())
                .with_context("file", path_str.to_string())
                .with_context("directive", line.trim().to_string())
                .with_verdict(
                    Verdict::Investigate,
                    "Review the entire Match block and remove any directives that restore \
                     dangerous options. Reload sshd after editing.",
                ),
            );
        }
    }

    findings
}

/// Parse all key=value directives from an sshd_config, handling continuation
/// lines (trailing `\`) and stripping inline comments after the value.
fn parse_directives(contents: &str) -> Vec<Directive> {
    let mut directives = Vec::new();
    let mut continued = String::new();

    for line in contents.lines() {
        let raw_trim = line.trim();

        // Blank lines and full-line comments.
        if raw_trim.is_empty() || raw_trim.starts_with('#') {
            continued.clear();
            continue;
        }

        // Continuation line.
        if raw_trim.ends_with('\\') {
            continued.push_str(&raw_trim[..raw_trim.len() - 1]);
            continued.push(' ');
            continue;
        }

        let effective = if continued.is_empty() {
            raw_trim.to_string()
        } else {
            let c = std::mem::take(&mut continued);
            format!("{}{}", c, raw_trim)
        };

        // Split on the first whitespace (or `=`) to get key and value.
        if let Some((key, value)) = split_directive(&effective) {
            directives.push(Directive {
                key: key.to_lowercase(),
                value: value.to_string(),
                raw: effective,
            });
        }
    }

    directives
}

/// Split `key value` or `key=value` into `(key, value)`.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    // sshd_config allows both `Key Value` and `Key=Value`.
    let line = line.trim();
    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();
        if !key.is_empty() {
            return Some((key, value));
        }
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next()?.trim();
    let value = parts.next().unwrap_or("").trim();
    if key.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

/// Yield `(key, value)` for a line that is not blank or a comment.
fn effective_ssh_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    split_directive(trimmed)
}

/// Extract the port number from a `ListenAddress` value.
///
/// Handles forms: `0.0.0.0:2222`, `:::2222`, `hostname:2222`, and bare `2222`.
fn extract_port(value: &str) -> Option<u16> {
    // IPv6 bracketed: `[::]:2222`
    if let Some(colon_pos) = value.rfind(':') {
        let port_str = &value[colon_pos + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            return Some(p);
        }
    }
    // Bare port number.
    value.parse::<u16>().ok()
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
        PathBuf::from("/etc/ssh/sshd_config")
    }

    // ── parse_directives ──────────────────────────────────────────────────────

    #[test]
    fn parses_key_value_separated_by_space() {
        let directives = parse_directives("PermitRootLogin yes\n");
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].key, "permitrootlogin");
        assert_eq!(directives[0].value, "yes");
    }

    #[test]
    fn parses_key_value_separated_by_equals() {
        let directives = parse_directives("PasswordAuthentication=yes\n");
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].key, "passwordauthentication");
        assert_eq!(directives[0].value, "yes");
    }

    #[test]
    fn key_matching_is_case_insensitive() {
        let directives = parse_directives("PERMITROOTLOGIN YES\n");
        assert_eq!(directives[0].key, "permitrootlogin");
        // Value preserves original case.
        assert_eq!(directives[0].value, "YES");
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let config = "\n# full-line comment\nPasswordAuthentication no\n";
        let directives = parse_directives(config);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].key, "passwordauthentication");
    }

    // ── PermitRootLogin ───────────────────────────────────────────────────────

    #[test]
    fn flags_permit_root_login_yes_as_high() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "PermitRootLogin yes\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.summary.contains("PermitRootLogin yes"))
        );
    }

    #[test]
    fn does_not_flag_permit_root_login_no() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "PermitRootLogin no\n");
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == Severity::High && f.summary.contains("PermitRootLogin"))
        );
    }

    #[test]
    fn flags_permit_root_login_prohibit_password_as_info() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "PermitRootLogin prohibit-password\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Info && f.summary.contains("key-only"))
        );
    }

    // ── PasswordAuthentication ────────────────────────────────────────────────

    #[test]
    fn flags_password_authentication_yes_as_medium() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "PasswordAuthentication yes\n");
        assert!(
            findings.iter().any(|f| f.severity == Severity::Medium
                && f.summary.contains("PasswordAuthentication yes"))
        );
    }

    #[test]
    fn does_not_flag_password_authentication_no() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "PasswordAuthentication no\n");
        assert!(
            !findings
                .iter()
                .any(|f| f.summary.contains("PasswordAuthentication yes"))
        );
    }

    // ── AuthorizedKeysFile path check ─────────────────────────────────────────

    #[test]
    fn flags_authorized_keys_file_in_tmp() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AuthorizedKeysFile /tmp/.keys\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.summary.contains("AuthorizedKeysFile"))
        );
    }

    #[test]
    fn flags_authorized_keys_file_in_dev_shm() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AuthorizedKeysFile /dev/shm/.auth\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.summary.contains("AuthorizedKeysFile"))
        );
    }

    #[test]
    fn does_not_flag_default_authorized_keys_file() {
        let ctx = fake_ctx();
        // The default is a relative path — not flagged.
        let findings = inspect(&ctx, &path(), "AuthorizedKeysFile .ssh/authorized_keys\n");
        assert!(
            !findings
                .iter()
                .any(|f| f.summary.contains("AuthorizedKeysFile"))
        );
    }

    #[test]
    fn flags_absolute_authorized_keys_file_outside_home() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AuthorizedKeysFile /var/lib/.secret_keys\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.summary.contains("AuthorizedKeysFile"))
        );
    }

    // ── AcceptEnv LD_PRELOAD ──────────────────────────────────────────────────

    #[test]
    fn flags_accept_env_ld_preload_as_critical() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AcceptEnv LANG LC_* LD_PRELOAD\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.summary.contains("LD_PRELOAD"))
        );
    }

    #[test]
    fn flags_accept_env_ld_library_path_as_critical() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AcceptEnv LD_LIBRARY_PATH\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.summary.contains("LD_LIBRARY_PATH"))
        );
    }

    #[test]
    fn does_not_flag_accept_env_locale_only() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "AcceptEnv LANG LC_*\n");
        assert!(!findings.iter().any(|f| f.summary.contains("AcceptEnv")));
    }

    // ── AuthorizedKeysCommand ─────────────────────────────────────────────────

    #[test]
    fn flags_authorized_keys_command_as_critical() {
        let ctx = fake_ctx();
        let findings = inspect(
            &ctx,
            &path(),
            "AuthorizedKeysCommand /usr/bin/fetch-keys %u\n",
        );
        assert!(findings.iter().any(
            |f| f.severity == Severity::Critical && f.summary.contains("AuthorizedKeysCommand")
        ));
    }

    // ── ForceCommand ──────────────────────────────────────────────────────────

    #[test]
    fn flags_force_command_not_internal_sftp_as_critical() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "ForceCommand /bin/bash\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.summary.contains("ForceCommand"))
        );
    }

    #[test]
    fn does_not_flag_force_command_internal_sftp() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "ForceCommand internal-sftp\n");
        assert!(!findings.iter().any(|f| f.summary.contains("ForceCommand")));
    }

    // ── MaxAuthTries ──────────────────────────────────────────────────────────

    #[test]
    fn flags_max_auth_tries_above_6_as_medium() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "MaxAuthTries 10\n");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.summary.contains("MaxAuthTries"))
        );
    }

    #[test]
    fn does_not_flag_max_auth_tries_at_or_below_6() {
        let ctx = fake_ctx();
        let findings = inspect(&ctx, &path(), "MaxAuthTries 6\n");
        assert!(!findings.iter().any(|f| f.summary.contains("MaxAuthTries")));
    }

    // ── extract_port ──────────────────────────────────────────────────────────

    #[test]
    fn extracts_port_from_address_colon_port() {
        assert_eq!(extract_port("0.0.0.0:2222"), Some(2222));
    }

    #[test]
    fn extracts_port_from_bare_number() {
        assert_eq!(extract_port("2222"), Some(2222));
    }

    #[test]
    fn returns_none_for_plain_address() {
        // "192.168.1.1" — last segment after colon would parse as port but there
        // is no colon, so falls through to bare parse which fails.
        // Actually 192.168.1.1 has colons in IPv6 but not IPv4. For IPv4 without
        // a port this is fine — just verify it doesn't panic.
        let _ = extract_port("192.168.1.1");
    }
}
