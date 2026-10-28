//! Backup of the user, group, and shadow databases.
//!
//! Captures `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
//! `/etc/sudoers`, and related files into the save directory alongside a
//! SHA-256 manifest. These files are the most likely target for attacker
//! persistence via added accounts or privilege escalation, so preserving a
//! clean copy at competition start is critical.

use std::path::PathBuf;

use crate::core::{DefenderContext, Result};

/// Paths that hold user, group, and privilege configuration.
pub const PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/security/limits.conf",
    "/etc/login.defs",
];

/// Back up the user and group databases.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    ctx.log_msg("[+] Backing up user/group databases...");
    super::all::run_with_paths(ctx, save_location, PATHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_is_non_empty() {
        assert!(!PATHS.is_empty());
    }

    #[test]
    fn all_paths_are_absolute() {
        for path in PATHS {
            assert!(path.starts_with('/'), "Expected absolute path, got: {path}");
        }
    }

    #[test]
    fn paths_includes_passwd_and_shadow() {
        assert!(PATHS.contains(&"/etc/passwd"));
        assert!(PATHS.contains(&"/etc/shadow"));
    }

    #[test]
    fn paths_includes_sudoers() {
        assert!(PATHS.contains(&"/etc/sudoers"));
    }
}
