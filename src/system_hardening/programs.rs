//! Restrict dangerous programs that should not be world-accessible.
//!
//! Sets permissions to 750 on compilers, network tools, and package managers.
//! This does not uninstall anything — it limits an unprivileged attacker's
//! ability to compile payloads, pivot laterally, or install new tools.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::{DefenderContext, Finding, Result, Severity};

/// Compilers that should not be world-executable on a competition box.
const COMPILERS: &[&str] = &["gcc", "g++", "clang", "cc", "make"];

/// Network reconnaissance and tunnelling tools.
const NETWORK_TOOLS: &[&str] = &["nmap", "nc", "netcat", "socat", "curl", "wget"];

/// Package managers at their canonical absolute paths.
const PACKAGE_MANAGERS: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dnf",
    "/usr/bin/yum",
    "/usr/bin/zypper",
];

/// Return the octal permission bits for a file, or `None` if it does not exist.
pub(crate) fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

/// True when the permission bits have world-execute set (the `---x` bit).
pub(crate) fn is_world_executable(mode: u32) -> bool {
    mode & 0o001 != 0
}

/// Restrict a binary at `path` to mode 750 if it is currently world-executable.
fn restrict_binary(ctx: &DefenderContext, path: &Path) {
    let Some(mode) = mode_of(path) else {
        return;
    };

    let path_str = path.to_string_lossy().into_owned();

    ctx.log_evidence_line(&path_str, &format!("mode {:04o} before restriction", mode));

    if !is_world_executable(mode) {
        ctx.emit(Finding::new(
            Severity::Info,
            "programs",
            format!("{} already restricted (mode {:04o})", path_str, mode),
            "No action needed.",
        ));
        return;
    }

    let changed = ctx.run_remediation(&["chmod", "750", &path_str]);

    let new_mode = mode_of(path).unwrap_or(0);
    ctx.log_evidence_line(
        &path_str,
        &format!("mode {:04o} after restriction", new_mode),
    );

    ctx.emit(
        Finding::new(
            Severity::High,
            "programs",
            format!("Restricted {} from mode {:04o} to 750", path_str, mode),
            format!(
                "Binary was world-executable (mode {:04o}). Changed to 750 so unprivileged \
                 users cannot run it. Attackers use these tools for lateral movement and \
                 payload compilation.",
                mode
            ),
        )
        .with_context("path", path_str)
        .with_context("old_mode", format!("{:04o}", mode))
        .with_context("restricted", if changed { "true" } else { "false" }),
    );
}

/// Locate a binary using `which` and return its path, or `None` if not found.
fn which(tool: &str) -> Option<PathBuf> {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        })
}

/// Check and restrict compiler binaries.
fn restrict_compilers(ctx: &DefenderContext) {
    ctx.log_msg("[+] Checking compiler permissions...");
    for &tool in COMPILERS {
        if let Some(path) = which(tool) {
            restrict_binary(ctx, &path);
        } else {
            ctx.debug(&format!("  {} not found — skipping", tool));
        }
    }
}

/// Check and restrict network tool binaries.
fn restrict_network_tools(ctx: &DefenderContext) {
    ctx.log_msg("[+] Checking network tool permissions...");
    for &tool in NETWORK_TOOLS {
        if let Some(path) = which(tool) {
            restrict_binary(ctx, &path);
        } else {
            ctx.debug(&format!("  {} not found — skipping", tool));
        }
    }
}

/// Check and restrict package manager binaries at their canonical paths.
fn restrict_package_managers(ctx: &DefenderContext) {
    ctx.log_msg("[+] Checking package manager permissions...");
    for &path_str in PACKAGE_MANAGERS {
        let path = Path::new(path_str);
        if path.exists() {
            restrict_binary(ctx, path);
        } else {
            ctx.debug(&format!("  {} not present — skipping", path_str));
        }
    }
}

/// Restrict compilers, network tools, and package managers to mode 750.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Hardening program permissions...");
    restrict_compilers(ctx);
    restrict_network_tools(ctx);
    restrict_package_managers(ctx);
    ctx.log_msg("[✓] Program permission hardening complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn world_exec_bit_detected_for_common_modes() {
        assert!(is_world_executable(0o755));
        assert!(is_world_executable(0o777));
        assert!(is_world_executable(0o711));
        assert!(is_world_executable(0o751));
        assert!(is_world_executable(0o001));
    }

    #[test]
    fn restricted_mode_not_world_executable() {
        assert!(!is_world_executable(0o750));
        assert!(!is_world_executable(0o700));
        assert!(!is_world_executable(0o640));
        assert!(!is_world_executable(0o600));
        assert!(!is_world_executable(0o000));
    }

    #[test]
    fn group_exec_not_confused_with_world_exec() {
        // Group-executable (bit 3) must not be treated as world-executable (bit 0).
        assert!(!is_world_executable(0o710));
        assert!(!is_world_executable(0o770));
        assert!(!is_world_executable(0o750));
    }

    #[test]
    fn setuid_world_exec_still_detected() {
        // SUID + world-exec should still be flagged.
        assert!(is_world_executable(0o4755));
        assert!(!is_world_executable(0o4750));
    }

    #[test]
    fn mode_zero_is_not_world_executable() {
        assert!(!is_world_executable(0));
    }

    #[test]
    fn setgid_world_exec_detected() {
        assert!(is_world_executable(0o2755));
        assert!(!is_world_executable(0o2750));
    }
}
