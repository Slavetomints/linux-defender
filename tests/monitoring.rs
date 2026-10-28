//! Integration tests for `src/monitoring.rs`.
//!
//! All formerly-stub monitoring flags are now implemented. Tests assert that
//! the CLI surface is accepted and each flag exits cleanly.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::run_cli;

/// All formerly-stub monitoring flags — now implemented.
const MONITORS: &[&str] = &[
    "--access-log",
    "--error-log",
    "--auth-log",
    "--pspy",
    "--network",
];

#[test]
fn every_monitor_flag_is_accepted_and_routed() {
    let dir = TempDir::new().unwrap();

    for flag in MONITORS {
        let out = run_cli(dir.path(), &["monitoring", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
    }
}

#[test]
fn monitors_can_be_combined() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["monitoring", "--auth-log", "--network"]);
    assert!(
        out.status.success(),
        "combined monitors should exit cleanly"
    );
}

#[test]
fn no_flags_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(!run_cli(dir.path(), &["monitoring"]).status.success());
}
