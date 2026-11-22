//! Back up VyOS router configuration and boot files.
//!
//! Captures `/config/config.boot`, boot and commit scripts under `/config/scripts/`,
//! authentication keys in `/config/auth/`, and core system credential databases.
//! Delegates to [`super::all::run_with_paths`] to share manifest hashing and copy logic.

use std::path::PathBuf;

use super::all;
use crate::core::{DefenderContext, Result};

/// Paths that hold VyOS router configuration, boot scripts, and admin credentials.
pub const ROUTER_PATHS: &[&str] = &[
    "/config/config.boot",
    "/config/scripts",
    "/config/auth",
    "/etc/ssh",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
];

/// Back up the VyOS router configuration to `save_location`.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    ctx.progress("[+] Backing up VyOS router configuration (/config/config.boot)...");
    all::run_with_paths(ctx, save_location, ROUTER_PATHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All paths must be non-empty and start with '/'.
    #[test]
    fn router_paths_are_absolute() {
        for p in ROUTER_PATHS {
            assert!(p.starts_with('/'), "{p} is not absolute");
            assert!(!p.is_empty());
        }
    }

    /// Router paths must include VyOS core config, boot scripts, and auth directories.
    #[test]
    fn router_paths_cover_config_boot_and_scripts() {
        assert!(ROUTER_PATHS.contains(&"/config/config.boot"));
        assert!(ROUTER_PATHS.contains(&"/config/scripts"));
        assert!(ROUTER_PATHS.contains(&"/config/auth"));
    }

    /// Router paths must include identity, SSH, and privilege escalation files.
    #[test]
    fn router_paths_cover_identity_files() {
        assert!(ROUTER_PATHS.contains(&"/etc/ssh"));
        assert!(ROUTER_PATHS.contains(&"/etc/passwd"));
        assert!(ROUTER_PATHS.contains(&"/etc/shadow"));
        assert!(ROUTER_PATHS.contains(&"/etc/group"));
        assert!(ROUTER_PATHS.contains(&"/etc/sudoers"));
        assert!(ROUTER_PATHS.contains(&"/etc/sudoers.d"));
    }

    /// No duplicate entries in ROUTER_PATHS.
    #[test]
    fn router_paths_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in ROUTER_PATHS {
            assert!(seen.insert(*p), "duplicate path: {p}");
        }
    }
}
