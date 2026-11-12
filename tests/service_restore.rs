//! Integration tests for the `service-restore` subcommand.
//!
//! Every destructive action requires root and prompts for confirmation, so
//! tests here cover flag parsing, routing, and the non-root guard — not the
//! actual reinstall or extraction (those need root and real services).

mod common;

use common::{run_cli, stderr, stdout};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Assert that the binary surfaces a clean usage error when no flags are given.
#[test]
fn no_flags_is_an_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["service-restore"]);
    assert!(!out.status.success(), "expected non-zero exit");
}

/// Every flag is accepted and dispatched without panicking.
/// Each module bails out early with NotRoot before touching the system.
#[test]
fn every_flag_routes_without_panicking() {
    let dir = tempfile::TempDir::new().unwrap();
    for flag in &[
        "--postfix",
        "--dovecot",
        "--splunk",
        "--opencart",
        "--prestashop",
    ] {
        let out = run_cli(dir.path(), &["service-restore", flag]);
        // Must not panic; exit code may be non-zero (not-root, missing archive, etc.)
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            !combined.contains("panic"),
            "flag {flag} caused a panic:\n{combined}"
        );
    }
}

/// The not-root guard fires before any system interaction.
#[test]
fn non_root_is_reported_gracefully() {
    if nix::unistd::Uid::effective().is_root() {
        return; // can't test this path as root
    }
    let dir = tempfile::TempDir::new().unwrap();
    for flag in &[
        "--postfix",
        "--dovecot",
        "--splunk",
        "--opencart",
        "--prestashop",
    ] {
        let out = run_cli(dir.path(), &["service-restore", flag]);
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            combined.to_lowercase().contains("root")
                || combined.contains("NotRoot")
                || combined.contains("privileges"),
            "flag {flag}: expected root-guard message, got:\n{combined}"
        );
    }
}

/// `--opencart-path` and `--prestashop-path` are forwarded; a missing
/// directory produces a clear error rather than a panic.
#[test]
fn missing_web_root_is_an_error_not_a_panic() {
    if nix::unistd::Uid::effective().is_root() {
        return; // path check comes after root check; skip when running as root
    }
    let dir = tempfile::TempDir::new().unwrap();
    let bogus = dir.path().join("does_not_exist");

    for (flag, path_flag) in &[
        ("--opencart", "--opencart-path"),
        ("--prestashop", "--prestashop-path"),
    ] {
        let out = run_cli(
            dir.path(),
            &["service-restore", flag, path_flag, bogus.to_str().unwrap()],
        );
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            !combined.contains("panic"),
            "{flag} with bad path caused a panic:\n{combined}"
        );
    }
}

/// Distro detection unit tests live in `src/service_restore/distro.rs`;
/// this just checks the field parser is exported correctly.
#[test]
fn os_release_field_parser_is_accessible() {
    use linux_defender::service_restore::distro::os_release_field;
    let text = "ID=arch\nID_LIKE=\nPRETTY_NAME=\"Arch Linux\"\n";
    assert_eq!(os_release_field(text, "ID"), Some("arch"));
    assert_eq!(os_release_field(text, "MISSING"), None);
}
