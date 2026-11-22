//! Integration tests for `src/system_hardening.rs`.
//!
//! `--install-tools` is deliberately not exercised: it downloads from GitHub,
//! so covering it here would make the suite depend on network access.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::run_cli;

/// Flags that run real work but do not require root to exit cleanly.
const NO_ROOT_STEPS: &[&str] = &["--programs", "--configs"];

/// Flags that require root; tested separately with `#[ignore]`.
const ROOT_STEPS: &[&str] = &["--user-permissions", "--services"];

#[test]
fn every_non_root_hardening_step_exits_cleanly() {
    let dir = TempDir::new().unwrap();

    for &flag in NO_ROOT_STEPS {
        let out = run_cli(dir.path(), &["system-hardening", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
    }
}

#[test]
#[ignore = "requires root"]
fn every_root_hardening_step_exits_cleanly() {
    if !common::running_as_root() {
        return; // these steps return NotRoot without privileges; only meaningful as root
    }
    let dir = TempDir::new().unwrap();

    for &flag in ROOT_STEPS {
        let out = run_cli(dir.path(), &["system-hardening", flag]);
        assert!(out.status.success(), "{} should exit cleanly", flag);
    }
}

#[test]
#[ignore = "requires root"]
fn hardening_steps_can_be_combined() {
    if !common::running_as_root() {
        return; // combined root steps return NotRoot without privileges
    }
    let dir = TempDir::new().unwrap();
    let out = run_cli(
        dir.path(),
        &["system-hardening", "--user-permissions", "--services"],
    );
    assert!(out.status.success());
}

#[test]
fn no_flags_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(!run_cli(dir.path(), &["system-hardening"]).status.success());
}

#[test]
fn router_allow_list_matches_router_allow_constant() {
    use linux_defender::core::BoxType;
    use linux_defender::system_hardening::services::{ROUTER_ALLOW, allow_list};

    assert_eq!(allow_list(BoxType::Router), ROUTER_ALLOW);
}

#[test]
fn router_allow_list_contains_vyos_and_frr() {
    use linux_defender::core::BoxType;
    use linux_defender::system_hardening::services::allow_list;

    let list = allow_list(BoxType::Router);
    assert!(list.contains(&"vyos-router"), "vyos-router must be in ROUTER_ALLOW");
    assert!(list.contains(&"frr"), "frr must be in ROUTER_ALLOW");
    assert!(list.contains(&"zebra"), "zebra must be in ROUTER_ALLOW");
    assert!(list.contains(&"staticd"), "staticd must be in ROUTER_ALLOW");
    assert!(list.contains(&"bgpd"), "bgpd must be in ROUTER_ALLOW");
    assert!(list.contains(&"ospfd"), "ospfd must be in ROUTER_ALLOW");
    assert!(list.contains(&"nftables"), "nftables must be in ROUTER_ALLOW");
    assert!(list.contains(&"snmpd"), "snmpd must be in ROUTER_ALLOW");
    assert!(list.contains(&"chrony"), "chrony must be in ROUTER_ALLOW");
}

#[test]
fn router_allow_list_excludes_databases() {
    use linux_defender::core::BoxType;
    use linux_defender::system_hardening::services::allow_list;

    let list = allow_list(BoxType::Router);
    assert!(!list.contains(&"mysql"), "mysql must NOT be in ROUTER_ALLOW");
    assert!(!list.contains(&"mariadb"), "mariadb must NOT be in ROUTER_ALLOW");
    assert!(!list.contains(&"postgresql"), "postgresql must NOT be in ROUTER_ALLOW");
    assert!(!list.contains(&"mongod"), "mongod must NOT be in ROUTER_ALLOW");
}

#[test]
fn essential_users_protects_vyos_user() {
    use linux_defender::system_hardening::user_perms::ESSENTIAL_USERS;

    assert!(
        ESSENTIAL_USERS.contains(&"vyos"),
        "vyos must be in ESSENTIAL_USERS to protect against lockout"
    );
    assert!(
        ESSENTIAL_USERS.contains(&"root"),
        "root must be in ESSENTIAL_USERS"
    );
    assert!(
        ESSENTIAL_USERS.contains(&"sysadmin"),
        "sysadmin must be in ESSENTIAL_USERS"
    );
}
