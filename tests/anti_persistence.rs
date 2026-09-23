//! Integration tests for `src/anti_persistence/`. One submodule per source
//! module; the tests in this file cover the dispatch table in
//! `src/anti_persistence.rs` itself.
//!
//! Submodules carry explicit `#[path]` attributes because a test crate root
//! resolves `mod` declarations against `tests/`, not `tests/anti_persistence/`.

#[path = "common.rs"]
mod common;

#[path = "anti_persistence/php_shells.rs"]
mod php_shells;

use tempfile::TempDir;

use common::{run_cli, running_as_root, stdout};

/// Read-only checks that finish quickly and never prompt without root, so they
/// are safe to drive from a test at any privilege level.
const FAST_CHECKS: &[&str] = &[
    "--grub",
    "--initramfs",
    "--kernel-modules",
    "--ld-preload",
    "--logrotate",
    "--pam",
    "--rc-local",
    "--startup-scripts",
    "--udev",
    "--xdg-autostart",
];

#[test]
fn every_fast_check_is_wired_to_its_module() {
    let dir = TempDir::new().unwrap();

    for flag in FAST_CHECKS {
        let out = run_cli(dir.path(), &["anti-persistence", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);

        // The dispatch table maps the flag to a module name; a misrouted entry
        // would report a different module than the flag requested.
        let expected = flag.trim_start_matches("--").replace('-', "_");
        let text = stdout(&out);
        assert!(
            text.contains(&format!("Running {} module", expected)),
            "{} should run the {} module, got: {}",
            flag,
            expected,
            text
        );
        assert!(text.contains(&format!("{} module complete", expected)));
    }
}

#[test]
fn several_checks_can_run_in_one_invocation() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(
        dir.path(),
        &["anti-persistence", "--pam", "--udev", "--grub"],
    );

    assert!(out.status.success());
    let text = stdout(&out);
    for module in ["pam", "udev", "grub"] {
        assert!(text.contains(&format!("{} module complete", module)));
    }
}

#[test]
fn each_module_result_is_recorded_in_the_report() {
    let dir = TempDir::new().unwrap();
    run_cli(dir.path(), &["anti-persistence", "--pam", "--udev"]);

    let report = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("defender-report-")
        })
        .expect("a report file should be written");

    let text = std::fs::read_to_string(report.path()).unwrap();
    assert!(text.contains("[ok] pam"));
    assert!(text.contains("[ok] udev"));
}

#[test]
fn root_gated_checks_fail_cleanly_without_privileges() {
    if running_as_root() {
        return; // these would prompt for input instead of refusing
    }

    let dir = TempDir::new().unwrap();

    for flag in ["--cron", "--users", "--ssh-keys", "--at-jobs"] {
        let out = run_cli(dir.path(), &["anti-persistence", flag]);

        // The module reports failure but the overall run still succeeds.
        assert!(
            out.status.success(),
            "{} should not abort the run, stderr: {}",
            flag,
            common::stderr(&out)
        );
        assert!(
            common::stderr(&out).contains("Not running as root"),
            "{} should explain the privilege requirement",
            flag
        );
    }
}

/// Sweeps the whole filesystem via `getcap -r /`, so it is as slow as the SUID
/// scan. Needs libcap installed; skipped rather than failed when it is not.
#[test]
#[ignore = "scans the entire filesystem; too slow for the default suite"]
fn the_capability_scan_completes() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["anti-persistence", "--capabilities"]);

    if common::stderr(&out).contains("install libcap") {
        return; // getcap is not present on this machine
    }

    assert!(out.status.success(), "stderr: {}", common::stderr(&out));
    assert!(stdout(&out).contains("capabilities module complete"));
}

/// Walks the whole root filesystem, so it takes minutes rather than seconds.
/// Run it deliberately with `cargo test -- --ignored`.
#[test]
#[ignore = "scans the entire filesystem; too slow for the default suite"]
fn the_suid_scan_completes() {
    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["anti-persistence", "--suid"]);

    assert!(out.status.success(), "stderr: {}", common::stderr(&out));
    assert!(stdout(&out).contains("SUID scan complete"));
}

#[test]
fn the_php_shell_scan_completes() {
    if running_as_root() {
        return; // would offer to delete, and prompt, if the web root exists
    }

    let dir = TempDir::new().unwrap();
    let out = run_cli(dir.path(), &["anti-persistence", "--php-shells"]);

    assert!(out.status.success());
    assert!(stdout(&out).contains("php_shells module complete"));
}
