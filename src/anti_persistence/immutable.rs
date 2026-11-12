//! Immutable and append-only flags on sensitive system files.
//!
//! `chattr +i` makes a file immutable even to root — a red team trick to
//! prevent password changes and configuration repairs. `chattr +a` makes a
//! file append-only. Either flag on `/etc/passwd` or `/etc/shadow` is a
//! critical finding.

// ioctl_read! generates an undocumentable unsafe fn; suppress the lint for this file.
#![allow(missing_docs)]

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use nix::ioctl_read;

use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict};

// FS_IOC_GETFLAGS = _IOR('f', 1, long)
ioctl_read!(ext2_getflags, b'f', 1, libc::c_long);

/// ioctl flag bit for the immutable (i) attribute.
const FS_IMMUTABLE_FL: libc::c_long = 0x0010;
/// ioctl flag bit for the append-only (a) attribute.
const FS_APPEND_FL: libc::c_long = 0x0020;

/// Files checked for immutable/append-only flags.
const SENSITIVE_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/sysctl.conf",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth",
    // Attack artifact paths
    "/root/.ssh/authorized_keys",
    "/etc/pam.d/sshd",
    "/etc/bash.bashrc",
];

/// High-value files where immutable = Critical vs High for others.
const CRITICAL_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/bash.bashrc",
];

/// Check sensitive files for immutable/append-only flags.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking file immutability flags...");

    for path_str in SENSITIVE_FILES {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }

        match get_flags(path) {
            Ok(flags) => report_flags(ctx, path, flags),
            Err(e) => ctx.debug(&format!("ioctl on {}: {}", path_str, e)),
        }
    }

    // Sweep sudoers drop-ins — names are not predictable so we walk the dir.
    sweep_dir(ctx, "/etc/sudoers.d");

    // Sweep profile.d drop-ins — attacker may add hidden scripts.
    sweep_dir(ctx, "/etc/profile.d");

    // Sweep hidden files in directories where attackers drop persistent scripts.
    // Any dot-file or dot-dir in these locations with chattr +i is suspicious
    // regardless of its name -- we don't match on specific payload names.
    for dir in &[
        "/usr/local/lib", "/usr/lib", "/usr/lib/systemd", "/etc/cron.d",
        "/var/lib", "/opt",
    ] {
        sweep_hidden(ctx, dir);
    }

    // Sweep home directories for hidden immutable files (attacker-planted backdoors).
    if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let home = fields[5];
            if home.is_empty() || home == "/" {
                continue;
            }
            sweep_hidden(ctx, home);
        }
    }

    ctx.log_msg("[✓] Immutability check complete");
    Ok(())
}

/// Walk `dir` and check only hidden entries (names starting with `.`) for flags.
///
/// Regular files in these dirs may legitimately be immutable (distro-installed libs
/// with security hardening). We only care about dot-files -- those have no business
/// being there at all, let alone being locked down.
fn sweep_hidden(ctx: &DefenderContext, dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !name.starts_with('.') {
            continue;
        }
        match get_flags(&path) {
            Ok(flags) => report_flags(ctx, &path, flags),
            Err(e) => ctx.debug(&format!("ioctl on {}: {}", path.display(), e)),
        }
    }
}

/// Walk `dir` and check each file for immutable/append-only flags.
fn sweep_dir(ctx: &DefenderContext, dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match get_flags(&path) {
            Ok(flags) => report_flags(ctx, &path, flags),
            Err(e) => ctx.debug(&format!("ioctl on {}: {}", path.display(), e)),
        }
    }
}

/// Read the ext2 filesystem flags for `path` via ioctl.
fn get_flags(path: &Path) -> std::result::Result<libc::c_long, nix::Error> {
    let file = File::open(path).map_err(|_| nix::Error::EACCES)?;
    let mut flags: libc::c_long = 0;
    // Safety: fd is valid for the lifetime of `file`; ioctl writes one c_long.
    unsafe { ext2_getflags(file.as_raw_fd(), &mut flags) }?;
    Ok(flags)
}

/// Emit findings for immutable or append-only flags on `path`.
fn report_flags(ctx: &DefenderContext, path: &Path, flags: libc::c_long) {
    let immutable = (flags & FS_IMMUTABLE_FL) != 0;
    let append_only = (flags & FS_APPEND_FL) != 0;

    if !immutable && !append_only {
        return;
    }

    let flag_str: &'static str = match (immutable, append_only) {
        (true, true) => "immutable (+i) AND append-only (+a)",
        (true, false) => "immutable (+i)",
        (false, true) => "append-only (+a)",
        _ => unreachable!(),
    };

    let chattr_flag: &'static str = match (immutable, append_only) {
        (true, _) => "i",
        (false, true) => "a",
        _ => unreachable!(),
    };

    let is_critical = CRITICAL_FILES.contains(&path.to_str().unwrap_or(""));
    let severity = if is_critical {
        Severity::Critical
    } else {
        Severity::High
    };
    let verdict = if is_critical {
        Verdict::Remove
    } else {
        Verdict::Investigate
    };

    let note: &'static str = if immutable {
        "chattr +i prevents even root from modifying or deleting this file. \
         Red teams set this on /etc/passwd or /etc/shadow so you cannot change \
         passwords or disable accounts."
    } else {
        "chattr +a prevents the file from being overwritten or deleted, only \
         appended. This can prevent log truncation or lock a config in place."
    };

    let recommendation = format!(
        "Run `chattr -{} {}` to remove the flag, then inspect and repair the file \
         contents — the attacker may have modified it before setting the flag.",
        chattr_flag,
        path.display()
    );

    // Capture file content as evidence before attempting flag removal.
    ctx.log_evidence_file(path);

    // Remove the immutable/append-only flag.
    let path_str = path.to_str().unwrap_or("");
    let chattr_arg = format!("-{}", chattr_flag);
    let cmd_ok = ctx.run_remediation(&["chattr", &chattr_arg, path_str]);

    // Verify by re-reading the filesystem flags.
    let flag_cleared = if cmd_ok {
        get_flags(path)
            .map(|f| (f & FS_IMMUTABLE_FL) == 0 && (f & FS_APPEND_FL) == 0)
            .unwrap_or(false)
    } else {
        false
    };
    let proof = format!(
        "  chattr -{} verification: flag_cleared={}",
        chattr_flag, flag_cleared
    );
    ctx.log_msg(&proof);
    let _ = ctx.log(&proof);

    ctx.emit(
        Finding::new(
            severity,
            "immutable",
            format!(
                "{} has {} flag set — chattr needed to modify",
                path.display(),
                flag_str
            ),
            format!(
                "path: {}\nflags: {}\nto remove: chattr -{} {}",
                path.display(),
                flag_str,
                chattr_flag,
                path.display()
            ),
        )
        .with_path(path.to_path_buf())
        .with_context("path", path.display().to_string())
        .with_context("flags", flag_str)
        .with_context(
            "remove with",
            format!("chattr -{} {}", chattr_flag, path.display()),
        )
        .with_context("flag_cleared", flag_cleared.to_string())
        .with_context("note", note)
        .with_verdict(verdict, recommendation)
        .with_action(Action::RemoveImmutable(PathBuf::from(path))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_files_include_passwd_and_shadow() {
        assert!(CRITICAL_FILES.contains(&"/etc/passwd"));
        assert!(CRITICAL_FILES.contains(&"/etc/shadow"));
    }

    #[test]
    fn sensitive_files_is_superset_of_critical() {
        for cf in CRITICAL_FILES {
            assert!(
                SENSITIVE_FILES.contains(cf),
                "{} in CRITICAL_FILES but not in SENSITIVE_FILES",
                cf
            );
        }
    }
}
