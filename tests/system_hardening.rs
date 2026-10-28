//! Integration tests for `src/system_hardening.rs`.
//!
//! `--install-tools` is deliberately not exercised: it downloads from GitHub,
//! so covering it here would make the suite depend on network access.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::run_cli;

/// Flags that run real work but do not require root to exit cleanly.
const NO_ROOT_STEPS: &[&str] = &["--programs", "--configs"];

/// Flags that require root; tested separately with `#[ignore]`.
const ROOT_STEPS: &[&str] = &["--user-permissions", "--services"];

#[test]
fn every_non_root_hardening_step_exits_cleanly() {
    let dir = TempDir::new().unwrap();

    for &flag in NO_ROOT_STEPS {
        let out = run_cli(dir.path(), &["system-hardening", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
    }
}

#[test]
#[ignore = "requires root"]
fn every_root_hardening_step_exits_cleanly() {
    let dir = TempDir::new().unwrap();

    for &flag in ROOT_STEPS {
        let out = run_cli(dir.path(), &["system-hardening", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
    }
}

#[test]
#[ignore = "requires root"]
fn hardening_steps_can_be_combined() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(
        dir.path(),
        &["system-hardening", "--user-permissions", "--services"],
    );
    assert!(out.status.success());
}

#[test]
fn no_flags_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(!run_cli(dir.path(), &["system-hardening"]).status.success());
}
