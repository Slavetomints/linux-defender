//! User account and file-permission hardening.
//!
//! Three categories of action, each prompted before execution:
//!
//! 1. **Lock unused accounts** — any UID ≥ 1000 account with a login shell that
//!    is not in the `ESSENTIAL_USERS` list is locked with `passwd -l`.
//! 2. **Fix sensitive file permissions** — `/etc/passwd` (644), `/etc/shadow`
//!    (640), and `/etc/sudoers` (440) are `chmod`-ed to their correct values if
//!    they are too permissive.
//! 3. **Restrictive umask** — deploys `/etc/profile.d/99-hardening.sh` with
//!    `umask 027` if not already present with that content.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::core::{
    Action, DefenderContext, DefenderError, Finding, Result, Severity, Verdict, require_root,
};

/// Accounts that must never be locked, regardless of their UID or shell.
const ESSENTIAL_USERS: &[&str] = &["root"];

/// Expected octal mode (lower 9 permission bits) for sensitive files.
struct FileSpec {
    /// Filesystem path to the file.
    path: &'static str,
    /// Required permission bits (e.g. `0o644`).
    expected_mode: u32,
}

/// Sensitive files with their required permission modes.
const SENSITIVE_FILES: &[FileSpec] = &[
    FileSpec {
        path: "/etc/passwd",
        expected_mode: 0o644,
    },
    FileSpec {
        path: "/etc/shadow",
        expected_mode: 0o640,
    },
    FileSpec {
        path: "/etc/sudoers",
        expected_mode: 0o440,
    },
];

/// Path of the umask profile drop-in deployed by this module.
const UMASK_PROFILE: &str = "/etc/profile.d/99-hardening.sh";
/// Content written to the umask profile drop-in.
const UMASK_CONTENT: &str = "umask 027\n";

/// Apply user-permission hardening: lock accounts, fix file modes, deploy umask.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if !ctx.in_tui() {
            eprintln!("[!] Not running as root — user-permissions hardening skipped");
        }
        ctx.emit(Finding::new(
            Severity::Medium,
            "user_perms",
            "Not running as root — user-permissions hardening skipped",
            "Run as root to lock accounts and fix file permissions.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Hardening user permissions...");

    lock_unused_accounts(ctx)?;
    fix_file_permissions(ctx)?;
    deploy_umask(ctx)?;

    ctx.log_msg("[✓] User-permission hardening complete");
    Ok(())
}

/// Lock every UID ≥ 1000 account that has a login shell and is not in
/// [`ESSENTIAL_USERS`].
fn lock_unused_accounts(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Locking unused login accounts...");

    let contents = fs::read_to_string("/etc/passwd")?;

    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let name = fields[0];
        let uid: u32 = match fields[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        let shell = fields[6];

        if uid < 1000 {
            continue;
        }
        if is_nologin_shell(shell) {
            ctx.emit(Finding::new(
                Severity::Info,
                "user_perms",
                format!(
                    "Account '{}' (uid={}) already has a no-login shell",
                    name, uid
                ),
                format!("shell: {}", shell),
            ));
            continue;
        }
        if ESSENTIAL_USERS.contains(&name) {
            ctx.debug(&format!("Skipping essential account: {}", name));
            continue;
        }

        // Log evidence before acting.
        ctx.log_evidence_line("/etc/passwd", line);

        let locked = ctx.run_remediation(&["passwd", "-l", name]);

        ctx.emit(
            Finding::new(
                Severity::High,
                "user_perms",
                format!("Account '{}' (uid={}) locked — had login shell", name, uid),
                format!("shell: {}\nlocked: {}", shell, locked),
            )
            .with_context("user", name)
            .with_context("uid", uid.to_string())
            .with_context("shell", shell)
            .with_context("locked", locked.to_string())
            .with_verdict(
                Verdict::Disable,
                format!(
                    "Account '{}' has UID ≥ 1000 with an interactive shell. \
                         It has been locked. Verify with `passwd -S {}`.",
                    name, name
                ),
            )
            .with_action(Action::Manual(format!("passwd -l {}", name))),
        );
    }

    Ok(())
}

/// Check each file in [`SENSITIVE_FILES`] and `chmod` it if the mode is wrong.
fn fix_file_permissions(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking sensitive file permissions...");

    for spec in SENSITIVE_FILES {
        let path = Path::new(spec.path);
        if !path.exists() {
            ctx.debug(&format!("{} does not exist — skipping", spec.path));
            continue;
        }

        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                ctx.log_msg(&format!("[!] Could not stat {}: {}", spec.path, e));
                continue;
            }
        };

        let actual = meta.permissions().mode() & 0o777;
        if actual == spec.expected_mode {
            ctx.emit(Finding::new(
                Severity::Info,
                "user_perms",
                format!("{} permissions are correct ({:04o})", spec.path, actual),
                format!("path: {}\nmode: {:04o}", spec.path, actual),
            ));
            continue;
        }

        // Log evidence (mode bits) before fixing.
        ctx.log_evidence_line(
            spec.path,
            &format!(
                "actual mode {:04o} expected {:04o}",
                actual, spec.expected_mode
            ),
        );

        let chmod_arg = format!("{:04o}", spec.expected_mode);
        let fixed = ctx.run_remediation(&["chmod", &chmod_arg, spec.path]);

        ctx.emit(
            Finding::new(
                Severity::High,
                "user_perms",
                format!(
                    "{} had incorrect permissions {:04o} (expected {:04o})",
                    spec.path, actual, spec.expected_mode
                ),
                format!(
                    "path: {}\nactual_mode: {:04o}\nexpected_mode: {:04o}\nfixed: {}",
                    spec.path, actual, spec.expected_mode, fixed
                ),
            )
            .with_context("path", spec.path)
            .with_context("actual_mode", format!("{:04o}", actual))
            .with_context("expected_mode", format!("{:04o}", spec.expected_mode))
            .with_context("fixed", fixed.to_string())
            .with_verdict(
                Verdict::Remove,
                format!(
                    "{} had overly permissive mode {:04o}. \
                     chmod {:04o} has been applied.",
                    spec.path, actual, spec.expected_mode
                ),
            )
            .with_action(Action::Manual(format!(
                "chmod {:04o} {}",
                spec.expected_mode, spec.path
            ))),
        );
    }

    Ok(())
}

/// Write `/etc/profile.d/99-hardening.sh` with `umask 027` if not present.
fn deploy_umask(ctx: &DefenderContext) -> Result {
    let path = Path::new(UMASK_PROFILE);

    if path.exists() {
        let current = fs::read_to_string(path).unwrap_or_default();
        if current.trim() == UMASK_CONTENT.trim() {
            ctx.emit(Finding::new(
                Severity::Info,
                "user_perms",
                format!("{} already contains umask 027", UMASK_PROFILE),
                format!("path: {}", UMASK_PROFILE),
            ));
            return Ok(());
        }
    }

    ctx.log_msg(&format!("[+] Writing umask 027 to {}", UMASK_PROFILE));

    match fs::write(path, UMASK_CONTENT) {
        Ok(()) => {
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "user_perms",
                    format!("Deployed umask 027 to {}", UMASK_PROFILE),
                    format!("path: {}\ncontent: umask 027", UMASK_PROFILE),
                )
                .with_context("path", UMASK_PROFILE)
                .with_context("deployed", "true")
                .with_verdict(
                    Verdict::Remove,
                    "umask 027 restricts new file permissions so group and world cannot \
                     write by default. This profile drop-in applies on all future logins.",
                ),
            );
        }
        Err(e) => {
            ctx.log_msg(&format!("[!] Failed to write {}: {}", UMASK_PROFILE, e));
        }
    }

    Ok(())
}

/// Return `true` when `shell` is a no-login shell path.
fn is_nologin_shell(shell: &str) -> bool {
    matches!(
        shell,
        "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | "/usr/bin/false" | "/dev/null"
    )
}

/// Return `true` when the lower 9 permission bits of `mode` match `expected`.
#[cfg(test)]
fn mode_matches(mode: u32, expected: u32) -> bool {
    (mode & 0o777) == (expected & 0o777)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nologin_shells_recognised() {
        assert!(is_nologin_shell("/usr/sbin/nologin"));
        assert!(is_nologin_shell("/sbin/nologin"));
        assert!(is_nologin_shell("/bin/false"));
        assert!(is_nologin_shell("/usr/bin/false"));
        assert!(is_nologin_shell("/dev/null"));
    }

    #[test]
    fn login_shells_not_nologin() {
        assert!(!is_nologin_shell("/bin/bash"));
        assert!(!is_nologin_shell("/bin/sh"));
        assert!(!is_nologin_shell("/usr/bin/zsh"));
        assert!(!is_nologin_shell(""));
    }

    #[test]
    fn mode_matches_exact() {
        assert!(mode_matches(0o100644, 0o644));
        assert!(mode_matches(0o100640, 0o640));
        assert!(mode_matches(0o100440, 0o440));
    }

    #[test]
    fn mode_mismatch_detected() {
        assert!(!mode_matches(0o100777, 0o644));
        assert!(!mode_matches(0o100666, 0o640));
        assert!(!mode_matches(0o100444, 0o440));
    }

    #[test]
    fn mode_masks_high_bits() {
        // The upper bits (file type etc.) must not affect the comparison.
        assert!(mode_matches(0o040644, 0o644));
        assert!(mode_matches(0o020640, 0o640));
    }

    #[test]
    fn essential_users_contains_root() {
        assert!(ESSENTIAL_USERS.contains(&"root"));
    }

    #[test]
    fn essential_users_does_not_skip_attacker() {
        assert!(!ESSENTIAL_USERS.contains(&"attacker"));
        assert!(!ESSENTIAL_USERS.contains(&"backdoor"));
    }

    #[test]
    fn sensitive_files_have_reasonable_modes() {
        for spec in SENSITIVE_FILES {
            let mode = spec.expected_mode;
            assert!(
                mode <= 0o777,
                "{} mode {:04o} is out of range",
                spec.path,
                mode
            );
            // World write should never be expected on these files.
            assert_eq!(
                mode & 0o002,
                0,
                "{} expected mode allows world-write",
                spec.path
            );
        }
    }

    #[test]
    fn umask_content_is_restrictive() {
        assert!(UMASK_CONTENT.contains("027"));
    }
}
