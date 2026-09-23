//! Covers `src/backups/compare_hashes.rs`, driven through a real backup so the
//! manifest under test is one the tool actually wrote.

use std::fs;

use defender_cli::backups::{all, compare_hashes, hash};
use tempfile::TempDir;

use crate::common::{as_refs, config_tree, ctx, write_file};

#[test]
fn detects_added_removed_and_modified_files() {
    let src = TempDir::new().unwrap();
    let stable = write_file(src.path(), "stable.conf", "unchanged\n");
    let modified = write_file(src.path(), "modified.conf", "original\n");
    let removed = write_file(src.path(), "removed.conf", "doomed\n");

    let paths = vec![
        stable.display().to_string(),
        modified.display().to_string(),
        removed.display().to_string(),
    ];

    // Take a baseline.
    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());
    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths)).unwrap();

    // Now mutate the system the way Red Team would.
    fs::write(&modified, "tampered\n").unwrap();
    fs::remove_file(&removed).unwrap();
    let added = write_file(src.path(), "added.conf", "new\n");

    let mut after_paths = paths.clone();
    after_paths.push(added.display().to_string());

    let previous = compare_hashes::parse_hashes_file(&dest.path().join(all::HASH_FILE)).unwrap();
    let current = hash::compute(&as_refs(&after_paths)).unwrap();
    let diff = compare_hashes::compare(&previous, &current);

    assert_eq!(diff.unchanged, 1, "stable.conf");
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].0.ends_with("modified.conf"));
    assert_eq!(diff.removed.len(), 1);
    assert!(diff.removed[0].ends_with("removed.conf"));
    assert_eq!(diff.added.len(), 1);
    assert!(diff.added[0].ends_with("added.conf"));
}

#[test]
fn an_untouched_system_reports_no_findings() {
    let (_src, paths) = config_tree();
    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());

    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths)).unwrap();

    let previous = compare_hashes::parse_hashes_file(&dest.path().join(all::HASH_FILE)).unwrap();
    let current = hash::compute(&as_refs(&paths)).unwrap();
    let diff = compare_hashes::compare(&previous, &current);

    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.unchanged, previous.len());
}

#[test]
fn a_written_manifest_round_trips_through_the_parser() {
    let (_src, paths) = config_tree();
    let dest = TempDir::new().unwrap();
    let save = Some(dest.path().to_path_buf());

    all::run_with_paths(&ctx(dest.path()), &save, &as_refs(&paths)).unwrap();

    let parsed = compare_hashes::parse_hashes_file(&dest.path().join(all::HASH_FILE)).unwrap();
    let computed = hash::compute(&as_refs(&paths)).unwrap();

    assert_eq!(
        parsed, computed,
        "parsing the manifest must reproduce what was hashed"
    );
}
