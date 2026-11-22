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
    ("--router", "router config"),
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

/// The `--router` flag backs up router configuration, creates manifest and roots files,
/// and allows subsequent hash comparison.
#[test]
fn router_backup_creates_manifest_and_allows_hash_comparison() {
    let dir = TempDir::new().unwrap();
    let save = dir.path().join("router-backup");
    let save_str = save.to_str().unwrap();

    // 1. Run router backup via CLI
    let out = run_cli(
        dir.path(),
        &["backups", "--router", "--save-location", save_str],
    );
    assert!(
        out.status.success(),
        "--router backup should exit cleanly, got: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("router config"),
        "stdout should announce router config backup, got: {}",
        stdout(&out)
    );

    // 2. Verify manifest, roots, and log files are generated
    let manifest_path = save.join("H@shes.txt");
    let roots_path = save.join("H@shes.roots");
    let log_path = save.join("backup.log");

    assert!(manifest_path.is_file(), "H@shes.txt manifest must exist");
    assert!(roots_path.is_file(), "H@shes.roots file must exist");
    assert!(log_path.is_file(), "backup.log must exist");

    // 3. Inspect H@shes.roots content to verify router target paths were registered
    let roots_content = std::fs::read_to_string(&roots_path).unwrap();
    assert!(
        roots_content.contains("/config/config.boot"),
        "roots must contain /config/config.boot"
    );
    assert!(
        roots_content.contains("/config/scripts"),
        "roots must contain /config/scripts"
    );
    assert!(
        roots_content.contains("/config/auth"),
        "roots must contain /config/auth"
    );

    // 4. Verify existing system identity files produce .bak copies
    if std::path::Path::new("/etc/passwd").exists() {
        assert!(
            save.join("_etc_passwd.bak").exists(),
            "_etc_passwd.bak should exist for /etc/passwd"
        );
    }

    // 5. Verify hash comparison against the newly created router backup
    let cmp_out = run_cli(
        dir.path(),
        &["backups", "--compare-hashes", "--save-location", save_str],
    );
    assert!(
        cmp_out.status.success(),
        "--compare-hashes should succeed against router backup, got: {}",
        stdout(&cmp_out)
    );
    let cmp_stdout = stdout(&cmp_out);
    assert!(
        cmp_stdout.contains("Comparison results against") || cmp_stdout.contains("Unchanged:"),
        "compare-hashes output should report comparison results, got: {}",
        cmp_stdout
    );
}

/// The `--router` flag combines cleanly with other backup flags (e.g. `--users`) in a single invocation.
#[test]
fn router_backup_combines_with_users_in_single_invocation() {
    let dir = TempDir::new().unwrap();
    let save = dir.path().join("multi-router");
    let save_str = save.to_str().unwrap();
    let out = run_cli(
        dir.path(),
        &[
            "backups",
            "--router",
            "--users",
            "--save-location",
            save_str,
        ],
    );

    assert!(out.status.success());
    assert!(stdout(&out).contains("router config"));
    assert!(stdout(&out).contains("user databases"));

    let manifest = save.join("H@shes.txt");
    assert!(
        manifest.is_file(),
        "manifest should exist after multi-flag backup"
    );

    let roots = std::fs::read_to_string(save.join("H@shes.roots")).unwrap();
    assert!(roots.contains("/config/config.boot"));
    assert!(roots.contains("/etc/passwd"));
}
