//! Covers `src/core/utils.rs`.

use defender_cli::core::{DefenderError, collect_users, require_root};

#[test]
fn collect_users_reads_every_account_from_passwd() {
    let users = collect_users().expect("/etc/passwd should be readable");

    assert!(users.contains(&"root".to_string()), "root must be present");
    assert!(
        users.iter().all(|u| !u.contains(':')),
        "a username must never contain the field separator"
    );
    assert!(
        users.iter().all(|u| !u.is_empty()),
        "blank usernames indicate a parsing bug"
    );
}

#[test]
fn require_root_agrees_with_the_effective_uid() {
    let is_root = nix::unistd::Uid::effective().is_root();

    match require_root() {
        Ok(()) => assert!(is_root, "returned Ok while not root"),
        Err(DefenderError::NotRoot) => assert!(!is_root, "returned NotRoot while root"),
        Err(other) => panic!("unexpected error variant: {}", other),
    }
}
