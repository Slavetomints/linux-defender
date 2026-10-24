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

const FS_IMMUTABLE_FL: libc::c_long = 0x0010;
const FS_APPEND_FL: libc::c_long = 0x0020;

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
];

/// High-value files where immutable = Critical vs High for others.
const CRITICAL_FILES: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/sudoers"];

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

    ctx.log_msg("[✓] Immutability check complete");
    Ok(())
}

fn get_flags(path: &Path) -> std::result::Result<libc::c_long, nix::Error> {
    let file = File::open(path).map_err(|_| nix::Error::EACCES)?;
    let mut flags: libc::c_long = 0;
    // Safety: fd is valid for the lifetime of `file`; ioctl writes one c_long.
    unsafe { ext2_getflags(file.as_raw_fd(), &mut flags) }?;
    Ok(flags)
}

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
    let severity = if is_critical { Severity::Critical } else { Severity::High };
    let verdict = if is_critical { Verdict::Remove } else { Verdict::Investigate };

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
            format!("{} has {} flag set — chattr needed to modify", path.display(), flag_str),
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
        .with_context("remove with", format!("chattr -{} {}", chattr_flag, path.display()))
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
