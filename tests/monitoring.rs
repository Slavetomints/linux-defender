//! Integration tests for `src/monitoring.rs`.
//!
//! Every monitor is still a stub, so these assert the CLI surface and routing
//! rather than any detection behaviour. They should be replaced with real
//! assertions as each monitor is implemented.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::{run_cli, stdout};

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
        assert!(
            stdout(&out).contains("Not implemented"),
            "{} is a stub and should say so",
            flag
        );
    }
}

#[test]
fn monitors_can_be_combined() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["monitoring", "--auth-log", "--network"]);

    assert!(out.status.success());
    assert_eq!(
        stdout(&out).matches("Not implemented").count(),
        2,
        "each requested monitor reports separately"
    );
}

#[test]
fn no_flags_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(!run_cli(dir.path(), &["monitoring"]).status.success());
}
