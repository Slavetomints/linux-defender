//! Backup of the mail stack configuration.
//!
//! Captures Postfix, Dovecot, Roundcube, and related mail config into the save
//! directory with a SHA-256 manifest. Mail services are commonly targeted during
//! CCDC, and having a clean baseline makes it straightforward to detect and
//! revert attacker modifications to relay config or virtual domains.

use std::path::PathBuf;

use crate::core::{DefenderContext, Result};

/// Paths that hold mail service configuration.
pub const MAIL_PATHS: &[&str] = &[
    "/etc/postfix",
    "/etc/dovecot",
    "/etc/roundcubemail",
    "/var/www/roundcubemail",
    "/var/www/html/roundcubemail",
    "/var/lib/dovecot",
    "/etc/aliases",
    "/etc/mailname",
];

/// Back up the Postfix, Dovecot, and Roundcube configuration stack.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    ctx.log_msg("[+] Backing up mail service configuration...");
    super::all::run_with_paths(ctx, save_location, MAIL_PATHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_paths_is_non_empty() {
        assert!(!MAIL_PATHS.is_empty());
    }

    #[test]
    fn all_mail_paths_are_absolute() {
        for path in MAIL_PATHS {
            assert!(path.starts_with('/'), "Expected absolute path, got: {path}");
        }
    }

    #[test]
    fn mail_paths_includes_postfix_and_dovecot() {
        assert!(MAIL_PATHS.contains(&"/etc/postfix"));
        assert!(MAIL_PATHS.contains(&"/etc/dovecot"));
    }

    #[test]
    fn mail_paths_includes_aliases() {
        assert!(MAIL_PATHS.contains(&"/etc/aliases"));
    }
}
