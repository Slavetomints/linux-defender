//! Integration tests for `src/backups/`. One submodule per source module.
//!
//! Submodules carry explicit `#[path]` attributes because a test crate root
//! resolves `mod` declarations against `tests/`, not `tests/backups/`.

#[path = "common.rs"]
mod common;

#[path = "backups/all.rs"]
mod all;

#[path = "backups/compare_hashes.rs"]
mod compare_hashes;

#[path = "backups/hash.rs"]
mod hash;

use tempfile::TempDir;

use common::{run_cli, stdout};

/// Backup kinds that write into a provided `--save-location`.
/// Each entry is (flag, banner_fragment).
const SAVE_LOC_KINDS: &[(&str, &str)] = &[
    ("--ecomm", "ecomm service"),
    ("--mail", "mail service"),
    ("--splunk", "splunk service"),
    ("--users", "user databases"),
];

#[test]
fn every_backup_kind_is_wired_to_its_module() {
    let dir = TempDir::new().unwrap();
    let save = dir.path().join("backups");
    let save_str = save.to_str().unwrap();

    for (flag, banner) in SAVE_LOC_KINDS {
        let out = run_cli(dir.path(), &["backups", flag, "--save-location", save_str]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
        assert!(
            stdout(&out).contains(banner),
            "{} should announce {:?}, got: {}",
            flag,
            banner,
            stdout(&out)
        );
    }

    // --custom takes a path value; exercise it with a real directory.
    let custom_src = dir.path().join("custom_src");
    std::fs::create_dir_all(&custom_src).unwrap();
    let out = run_cli(
        dir.path(),
        &[
            "backups",
            "--custom",
            custom_src.to_str().unwrap(),
            "--save-location",
            save_str,
        ],
    );
    assert!(
        out.status.success(),
        "--custom should exit cleanly, got: {}",
        stdout(&out)
    );

    // --restore without --save-location should print a diagnostic and exit cleanly.
    let out = run_cli(dir.path(), &["backups", "--restore"]);
    assert!(
        out.status.success(),
        "--restore without --save-location should not error"
    );
}

#[test]
fn several_backup_kinds_can_run_in_one_invocation() {
    let dir = TempDir::new().unwrap();
    let save = dir.path().join("multi-backup");
    let save_str = save.to_str().unwrap();
    let out = run_cli(
        dir.path(),
        &["backups", "--mail", "--splunk", "--save-location", save_str],
    );

    assert!(out.status.success());
    assert!(stdout(&out).contains("mail service"));
    assert!(stdout(&out).contains("splunk service"));
}
