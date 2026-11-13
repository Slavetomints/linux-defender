//! Integration tests for `src/router.rs`.

use linux_defender::core::BoxType;
use linux_defender::router::{ROUTER_STEPS, VYOS_SCRIPT};

#[test]
fn embedded_script_is_valid() {
    assert!(!VYOS_SCRIPT.is_empty());
    assert!(VYOS_SCRIPT.starts_with("#!/usr/bin/env bash"));
    assert!(VYOS_SCRIPT.contains("VyOS_LockdownAndFirewall.sh"));
    assert!(VYOS_SCRIPT.contains("--harden"));
    assert!(VYOS_SCRIPT.contains("--console-lockdown"));
    assert!(VYOS_SCRIPT.contains("--audit"));
    assert!(VYOS_SCRIPT.contains("--diff"));
}

#[test]
fn router_steps_registry_is_valid() {
    assert_eq!(ROUTER_STEPS.len(), 4);
    let ids: Vec<&str> = ROUTER_STEPS.iter().map(|s| s.id).collect();
    assert!(ids.contains(&"audit"));
    assert!(ids.contains(&"diff"));
    assert!(ids.contains(&"harden"));
    assert!(ids.contains(&"console_lockdown"));
}

#[test]
fn router_box_type_definition() {
    assert_eq!(BoxType::Router.label(), "Router");
    assert!(BoxType::Router.description().contains("VyOS"));
    assert!(BoxType::ALL.contains(&BoxType::Router));
    assert_eq!(BoxType::Router.services().len(), 1);
    assert_eq!(BoxType::Router.services()[0].name, "SSH");
    assert_eq!(BoxType::Router.services()[0].port, 22);
}
