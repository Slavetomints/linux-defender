//! Covers `src/backups/hash.rs`.

use std::fs;

use defender_cli::backups::hash;
use tempfile::TempDir;

use crate::common::{as_refs, config_tree, write_file};

#[test]
fn covers_every_nested_file() {
    let (src, paths) = config_tree();
    let hashes = hash::compute(&as_refs(&paths)).unwrap();

    let deep = src
        .path()
        .join("conf.d/nested/deep.conf")
        .display()
        .to_string();
    assert!(hashes.contains_key(&deep), "nested file must be hashed");
}

#[test]
fn records_directories_with_a_marker_instead_of_a_digest() {
    let (src, paths) = config_tree();
    let hashes = hash::compute(&as_refs(&paths)).unwrap();

    let nested_dir = src.path().join("conf.d/nested").display().to_string();
    assert_eq!(
        hashes.get(&nested_dir).map(String::as_str),
        Some(hash::MARKER_DIR)
    );
}

#[test]
fn changes_when_contents_change() {
    let src = TempDir::new().unwrap();
    let file = write_file(src.path(), "f.conf", "before\n");
    let paths = vec![file.display().to_string()];

    let before = hash::compute(&as_refs(&paths)).unwrap();
    fs::write(&file, "after\n").unwrap();
    let after = hash::compute(&as_refs(&paths)).unwrap();

    let key = file.display().to_string();
    assert_ne!(before.get(&key), after.get(&key));
}

#[test]
fn is_stable_across_repeated_runs() {
    let (_src, paths) = config_tree();

    let first = hash::compute(&as_refs(&paths)).unwrap();
    let second = hash::compute(&as_refs(&paths)).unwrap();

    assert_eq!(first, second, "hashing must be deterministic");
}

#[test]
fn skips_paths_that_do_not_exist() {
    let hashes = hash::compute(&["/nonexistent/a", "/nonexistent/b"]).unwrap();
    assert!(hashes.is_empty());
}
