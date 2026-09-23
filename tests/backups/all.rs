//! Covers `src/backups/all.rs`.

use std::fs;

use defender_cli::backups::{all, hash};
use tempfile::TempDir;

use crate::common::{as_refs, config_tree, ctx};

#[test]
fn writes_manifest_log_and_copies() {
    let (_src, paths) = config_tree();
    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());

    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths)).unwrap();

    let manifest = dest.path().join(all::HASH_FILE);
    let log = dest.path().join(all::LOG_FILE);
    assert!(manifest.is_file(), "manifest should exist");
    assert!(log.is_file(), "log should exist");

    let manifest_text = fs::read_to_string(&manifest).unwrap();
    assert!(manifest_text.contains("sshd_config"));
    assert!(manifest_text.contains("site.conf"));
    assert!(
        manifest_text.contains("deep.conf"),
        "directories are walked recursively"
    );

    // Each line is "<token>  <path>", where the token is either a SHA-256
    // digest for a regular file or a marker for a non-file entry.
    let mut digests = 0;
    for line in manifest_text.lines() {
        let token = line.split_whitespace().next().unwrap();
        if token == hash::MARKER_DIR || token == hash::MARKER_OTHER {
            continue;
        }
        assert_eq!(token.len(), 64, "expected a SHA-256 digest, got {}", token);
        digests += 1;
    }
    assert_eq!(digests, 3, "three regular files in the fixture");

    let backups: Vec<_> = fs::read_dir(dest.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
        .collect();
    assert_eq!(backups.len(), 2, "one .bak per source path");
}

#[test]
fn skips_missing_paths_without_failing() {
    let (_src, mut paths) = config_tree();
    paths.push("/nonexistent/path/that/should/be/skipped".to_string());

    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());

    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths))
        .expect("a missing path must not abort the backup");

    let log = fs::read_to_string(dest.path().join(all::LOG_FILE)).unwrap();
    assert!(log.contains("does not exist, skipping"));
    assert!(log.contains("1 skipped"));
}

#[test]
fn creates_a_save_directory_that_does_not_exist_yet() {
    let (_src, paths) = config_tree();
    let parent = TempDir::new().unwrap();
    let dest = parent.path().join("new").join("nested");
    assert!(!dest.exists());

    all::run_with_paths(&ctx(parent.path()), &Some(dest.clone()), &as_refs(&paths)).unwrap();

    assert!(dest.join(all::HASH_FILE).is_file());
}

#[test]
fn logs_the_default_save_location_warning_only_when_unspecified() {
    let (_src, paths) = config_tree();
    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());

    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths)).unwrap();

    let log = fs::read_to_string(dest.path().join(all::LOG_FILE)).unwrap();
    assert!(
        !log.contains("No save_location provided"),
        "an explicit save location should not warn"
    );
}
