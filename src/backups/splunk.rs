//! Back up Splunk configuration.
//!
//! Covers both the full Splunk Enterprise installation and the lightweight
//! Universal Forwarder. Delegates to [`super::all::run_with_paths`] so the
//! hash-manifest and copy logic is shared with all other backup types.

use std::path::PathBuf;

use super::all;
use crate::core::{DefenderContext, Result};

/// Paths that make up a typical Splunk or Splunk Forwarder installation.
pub const SPLUNK_PATHS: &[&str] = &[
    "/opt/splunk/etc/system/local",
    "/opt/splunk/etc/apps",
    "/opt/splunk/etc/users",
    "/opt/splunkforwarder/etc/system/local",
    "/opt/splunkforwarder/etc/apps",
];

/// Back up Splunk configuration to `save_location`.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    ctx.log_msg("[+] Backing up Splunk configuration...");
    all::run_with_paths(ctx, save_location, SPLUNK_PATHS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every path in the constant is a non-empty, absolute path string.
    #[test]
    fn splunk_paths_are_absolute() {
        for p in SPLUNK_PATHS {
            assert!(p.starts_with('/'), "{p} is not absolute");
            assert!(!p.is_empty());
        }
    }

    /// The constant covers both Enterprise and Forwarder installations.
    #[test]
    fn splunk_paths_cover_enterprise_and_forwarder() {
        let enterprise = SPLUNK_PATHS.iter().any(|p| p.starts_with("/opt/splunk/"));
        let forwarder = SPLUNK_PATHS
            .iter()
            .any(|p| p.starts_with("/opt/splunkforwarder/"));
        assert!(enterprise, "missing enterprise path");
        assert!(forwarder, "missing forwarder path");
    }

    /// No duplicate entries.
    #[test]
    fn splunk_paths_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in SPLUNK_PATHS {
            assert!(seen.insert(*p), "duplicate path: {p}");
        }
    }
}
