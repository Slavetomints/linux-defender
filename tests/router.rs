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
    assert_eq!(ROUTER_STEPS.len(), 9);
    let ids: Vec<&str> = ROUTER_STEPS.iter().map(|s| s.id).collect();
    assert!(ids.contains(&"audit"));
    assert!(ids.contains(&"diff"));
    assert!(ids.contains(&"harden"));
    assert!(ids.contains(&"router_nat"));
    assert!(ids.contains(&"rotate_passwords"));
    assert!(ids.contains(&"services"));
    assert!(ids.contains(&"user_permissions"));
    assert!(ids.contains(&"console_lockdown"));
    assert!(ids.contains(&"confirm"));
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

/// BoxType::Router must expose "router", "users", "all", and exclude server stacks ("mail", "splunk", "ecomm").
#[test]
fn router_box_type_backup_steps_contain_router_and_hide_server_stacks() {
    let steps = BoxType::Router.backup_steps();
    let step_ids: Vec<&str> = steps.iter().map(|(id, _)| *id).collect();

    // Must contain "router"
    assert!(
        step_ids.contains(&"router"),
        "BoxType::Router backup_steps must include 'router'"
    );

    // Must contain "users" and "all"
    assert!(
        step_ids.contains(&"users"),
        "BoxType::Router backup_steps must include 'users'"
    );
    assert!(
        step_ids.contains(&"all"),
        "BoxType::Router backup_steps must include 'all'"
    );

    // Must NOT contain server stacks
    assert!(
        !step_ids.contains(&"mail"),
        "BoxType::Router backup_steps must NOT contain 'mail'"
    );
    assert!(
        !step_ids.contains(&"splunk"),
        "BoxType::Router backup_steps must NOT contain 'splunk'"
    );
    assert!(
        !step_ids.contains(&"ecomm"),
        "BoxType::Router backup_steps must NOT contain 'ecomm'"
    );

    // Exactly 3 backup steps in defined order
    assert_eq!(
        steps.len(),
        3,
        "BoxType::Router must have exactly 3 backup steps"
    );
    assert_eq!(steps[0], ("router", "Router Config (/config/config.boot)"));
    assert_eq!(steps[1], ("users", "User/Group/Shadow DBs"));
    assert_eq!(steps[2], ("all", "Full Config Backup"));
}

/// Non-router box types must expose server stacks and strictly exclude "router".
#[test]
fn non_router_box_types_strictly_exclude_router_backup_step() {
    let non_router_types = [
        BoxType::Web,
        BoxType::Mail,
        BoxType::Splunk,
        BoxType::General,
    ];

    for bt in non_router_types {
        let steps = bt.backup_steps();
        let step_ids: Vec<&str> = steps.iter().map(|(id, _)| *id).collect();

        // Must NOT contain "router"
        assert!(
            !step_ids.contains(&"router"),
            "{:?} backup_steps must NOT contain 'router'",
            bt
        );

        // Must contain standard server stacks
        assert!(step_ids.contains(&"all"), "{:?} must contain 'all'", bt);
        assert!(step_ids.contains(&"mail"), "{:?} must contain 'mail'", bt);
        assert!(
            step_ids.contains(&"splunk"),
            "{:?} must contain 'splunk'",
            bt
        );
        assert!(step_ids.contains(&"users"), "{:?} must contain 'users'", bt);
        assert!(step_ids.contains(&"ecomm"), "{:?} must contain 'ecomm'", bt);

        assert_eq!(
            steps.len(),
            5,
            "{:?} backup_steps must have exactly 5 steps",
            bt
        );
    }
}

/// Router is the only box type with the router backup step, and no duplicate steps exist.
#[test]
fn all_box_types_partition_router_backup_step() {
    for &bt in BoxType::ALL {
        let steps = bt.backup_steps();
        let has_router = steps.iter().any(|(id, _)| *id == "router");

        if bt == BoxType::Router {
            assert!(
                has_router,
                "BoxType::Router must contain 'router' backup step"
            );
        } else {
            assert!(
                !has_router,
                "{:?} must NOT contain 'router' backup step",
                bt
            );
        }

        // Verify no duplicate IDs within any box type
        let mut seen = std::collections::HashSet::new();
        for (id, _) in steps {
            assert!(
                seen.insert(*id),
                "{:?} has duplicate backup step id: {}",
                bt,
                id
            );
        }
    }
}

#[test]
fn router_tabs_seven_and_digit_for_dynamic_scan() {
    use linux_defender::tui::Tab;

    let tabs = Tab::for_box_type(BoxType::Router);
    assert_eq!(tabs.len(), 7, "Router must have exactly 7 tabs");
    assert!(!tabs.contains(&Tab::Hardening));
    assert!(!tabs.contains(&Tab::ServiceRestore));
    assert_eq!(tabs[0], Tab::Dashboard);
    assert_eq!(tabs[1], Tab::Router);
    assert_eq!(tabs[2], Tab::Logs);
    assert_eq!(tabs[3], Tab::Scan);
    assert_eq!(tabs[4], Tab::Backups);
    assert_eq!(tabs[5], Tab::Monitor);
    assert_eq!(tabs[6], Tab::Tools);

    assert_eq!(Tab::digit_for(Tab::Scan, BoxType::Router), Some('4'));
    assert_eq!(Tab::digit_for(Tab::Scan, BoxType::Web), Some('3'));
}

#[test]
fn build_script_args_maps_restore_nat_and_pat() {
    let args = CliArgs {
        restore_nat: true,
        team: Some(3),
        dnat_target: Some("private".into()),
        enable_outbound_pat: true,
        ..Default::default()
    };
    let script_args = build_script_args(&args);
    assert!(script_args.contains(&"--restore-nat".to_string()));
    assert!(script_args.contains(&"--team".to_string()));
    assert!(script_args.contains(&"3".to_string()));
    assert!(script_args.contains(&"--dnat-target".to_string()));
    assert!(script_args.contains(&"private".to_string()));
    assert!(script_args.contains(&"--enable-outbound-pat".to_string()));
}

#[test]
fn build_script_args_maps_rotate_passwords_and_dual_credentials() {
    let args = CliArgs {
        rotate_passwords: true,
        vyos_pass: Some("SuperSecretVyOS123".into()),
        root_pass: Some("SuperSecretRoot456".into()),
        ..Default::default()
    };
    let script_args = build_script_args(&args);
    assert!(script_args.contains(&"--rotate-passwords".to_string()));
    assert!(script_args.contains(&"--vyos-pass".to_string()));
    assert!(script_args.contains(&"SuperSecretVyOS123".to_string()));
    assert!(script_args.contains(&"--root-pass".to_string()));
    assert!(script_args.contains(&"SuperSecretRoot456".to_string()));
}

#[test]
fn should_enter_pending_state_accepts_harden_and_restore_nat() {
    assert!(should_enter_pending_state("harden", false, true));
    assert!(should_enter_pending_state("router_nat", false, true));
    assert!(should_enter_pending_state("restore_nat", false, true));

    assert!(!should_enter_pending_state("harden", true, true));
    assert!(!should_enter_pending_state("router_nat", true, true));
    assert!(!should_enter_pending_state("rotate_passwords", false, true));
    assert!(!should_enter_pending_state("audit", false, true));
}
