//! Integration tests for `src/system_hardening.rs`.
//!
//! `--install-tools` is deliberately not exercised: it downloads from GitHub,
//! so covering it here would make the suite depend on network access.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::{run_cli, stdout};

const HARDENING_STEPS: &[&str] = &[
    "--user-permissions",
    "--services",
    "--programs",
    "--configs",
];

#[test]
fn every_hardening_step_is_accepted_and_routed() {
    let dir = TempDir::new().unwrap();

    for flag in HARDENING_STEPS {
        let out = run_cli(dir.path(), &["system-hardening", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
        assert!(
            stdout(&out).contains("Not implemented"),
            "{} is a stub and should say so",
            flag
        );
    }
}

#[test]
fn hardening_steps_can_be_combined() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["system-hardening", "--services", "--configs"]);

    assert!(out.status.success());
    assert_eq!(stdout(&out).matches("Not implemented").count(), 2);
}

#[test]
fn no_flags_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(!run_cli(dir.path(), &["system-hardening"]).status.success());
}
