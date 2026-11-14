//! Integration tests for `src/router.rs`.

use std::time::{Duration, Instant};

use linux_defender::core::BoxType;
use linux_defender::router::{
    CliArgs, ROUTER_STEPS, VYOS_SCRIPT, build_script_args, format_countdown, is_pending_expired,
    remaining_time, should_enter_pending_state,
};

#[test]
fn embedded_script_is_valid() {
    assert!(!VYOS_SCRIPT.is_empty());
    assert!(VYOS_SCRIPT.starts_with("#!/usr/bin/env bash"));
    assert!(VYOS_SCRIPT.contains("VyOS_LockdownAndFirewall.sh"));
    assert!(VYOS_SCRIPT.contains("--harden"));
    assert!(VYOS_SCRIPT.contains("--console-lockdown"));
    assert!(VYOS_SCRIPT.contains("--confirm"));
    assert!(VYOS_SCRIPT.contains("--audit"));
    assert!(VYOS_SCRIPT.contains("--diff"));
}

#[test]
fn countdown_formatting_produces_mm_ss() {
    assert_eq!(format_countdown(299), "04:59");
    assert_eq!(format_countdown(300), "05:00");
    assert_eq!(format_countdown(0), "00:00");
    assert_eq!(format_countdown(59), "00:59");
    assert_eq!(format_countdown(60), "01:00");
    assert_eq!(format_countdown(65), "01:05");
}

#[test]
fn expiry_detection_handles_past_present_future() {
    let now = Instant::now();
    let future = now + Duration::from_secs(60);
    let past = now - Duration::from_secs(60);

    assert!(!is_pending_expired(now, future));
    assert!(is_pending_expired(now, past));
    assert!(is_pending_expired(now, now));

    assert_eq!(remaining_time(now, future), Duration::from_secs(60));
    assert_eq!(remaining_time(now, past), Duration::ZERO);
}

#[test]
fn failed_or_bypassed_harden_does_not_enter_pending_state() {
    // Only successful harden without no_confirm enters pending state
    assert!(should_enter_pending_state("harden", false, true));

    // Failed harden run must never enter pending state
    assert!(!should_enter_pending_state("harden", false, false));

    // Harden with --no-confirm bypassed must not enter pending state
    assert!(!should_enter_pending_state("harden", true, true));
    assert!(!should_enter_pending_state("harden", true, false));

    // Other operations never enter pending state
    assert!(!should_enter_pending_state("audit", false, true));
    assert!(!should_enter_pending_state("diff", false, true));
    assert!(!should_enter_pending_state("console_lockdown", false, true));
    assert!(!should_enter_pending_state("confirm", false, true));
}

#[test]
fn build_script_args_maps_confirm_flag() {
    let args = CliArgs {
        confirm: true,
        ..Default::default()
    };
    let script_args = build_script_args(&args);
    assert_eq!(script_args, vec!["--confirm"]);
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
