//! Back up e-commerce stack configuration and files.
//!
//! Covers OpenCart and PrestaShop installations plus PHP configuration.
//! Delegates to [`super::all::run_with_paths`] so the same hash-manifest
//! and copy logic is shared across all backup types.

use std::path::PathBuf;

use super::all;
use crate::core::{DefenderContext, Result};

/// Paths that make up a typical e-commerce installation.
pub const ECOMM_PATHS: &[&str] = &[
    "/var/www/html/opencart",
    "/var/www/opencart",
    "/var/www/html/prestashop",
    "/var/www/prestashop",
    "/var/www/html/config.php",
    "/var/www/html/admin/config.php",
    "/etc/php",
    "/etc/php.ini",
    "/etc/php7",
    "/etc/php8",
];

/// Back up the e-commerce stack to `save_location`.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    ctx.log_msg("[+] Backing up e-commerce stack...");
    all::run_with_paths(ctx, save_location, ECOMM_PATHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every path in the constant is a non-empty, absolute path string.
    #[test]
    fn ecomm_paths_are_absolute() {
        for p in ECOMM_PATHS {
            assert!(p.starts_with('/'), "{p} is not absolute");
            assert!(!p.is_empty());
        }
    }

    /// The constant covers OpenCart, PrestaShop, and PHP.
    #[test]
    fn ecomm_paths_cover_expected_services() {
        let opencart = ECOMM_PATHS.iter().any(|p| p.contains("opencart"));
        let prestashop = ECOMM_PATHS.iter().any(|p| p.contains("prestashop"));
        let php = ECOMM_PATHS.iter().any(|p| p.contains("php"));
        assert!(opencart, "missing opencart path");
        assert!(prestashop, "missing prestashop path");
        assert!(php, "missing php path");
    }

    /// No duplicate entries.
    #[test]
    fn ecomm_paths_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in ECOMM_PATHS {
            assert!(seen.insert(*p), "duplicate path: {p}");
        }
    }
}
