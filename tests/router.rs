//! Integration tests for `src/router.rs`.

use std::time::{Duration, Instant};

use linux_defender::core::{BoxType, Finding, Severity};
use linux_defender::router::{
    CliArgs, ROUTER_STEPS, VYOS_SCRIPT, build_script_args, format_countdown, has_commit_failure,
    is_pending_expired, remaining_time, should_enter_pending_state,
    should_enter_pending_state_checked,
};
use linux_defender::tui::dashboard::{
    RouterSubsystemStatus, get_last_router_backup_timestamp, get_router_nat_status,
    get_router_routes_status,
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
fn build_script_args_maps_remediation_flags() {
    assert_eq!(
        build_script_args(&CliArgs { sanitize_hooks: true, ..Default::default() }),
        vec!["--sanitize-hooks"]
    );
    assert_eq!(
        build_script_args(&CliArgs { sanitize_cron: true, ..Default::default() }),
        vec!["--sanitize-cron"]
    );
    assert_eq!(
        build_script_args(&CliArgs { clean_rootkits: true, ..Default::default() }),
        vec!["--clean-rootkits"]
    );
    assert_eq!(
        build_script_args(&CliArgs { purge_containers: true, ..Default::default() }),
        vec!["--purge-containers"]
    );
}

#[test]
fn router_steps_registry_is_valid() {
    assert_eq!(ROUTER_STEPS.len(), 12);
    let ids: Vec<&str> = ROUTER_STEPS.iter().map(|s| s.id).collect();
    assert!(!ids.contains(&"audit"), "audit is superseded by Tab 3 modular scans");
    assert!(ids.contains(&"diff"));
    assert!(ids.contains(&"harden"));
    assert!(ids.contains(&"router_nat"));
    assert!(ids.contains(&"rotate_passwords"));
    assert!(ids.contains(&"sanitize_hooks"));
    assert!(ids.contains(&"sanitize_cron"));
    assert!(ids.contains(&"clean_rootkits"));
    assert!(ids.contains(&"purge_containers"));
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
    assert_eq!(tabs[1], Tab::Logs);
    assert_eq!(tabs[2], Tab::Scan);
    assert_eq!(tabs[3], Tab::Router);
    assert_eq!(tabs[4], Tab::Backups);
    assert_eq!(tabs[5], Tab::Monitor);
    assert_eq!(tabs[6], Tab::Tools);

    assert_eq!(Tab::digit_for(Tab::Scan, BoxType::Router), Some('3'));
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

#[test]
fn router_box_type_scan_modules_returns_fourteen_dedicated_modules() {
    let router_mods = BoxType::Router.scan_modules();
    assert_eq!(router_mods.len(), 14, "Router must have exactly 14 dedicated audit modules");

    let ids: Vec<&str> = router_mods.iter().map(|(id, _, _, _)| *id).collect();
    assert_eq!(
        ids,
        vec![
            "router_version",
            "router_boot_hooks",
            "router_commit_hooks",
            "router_task_scheduler",
            "router_users",
            "router_interfaces",
            "router_containers",
            "router_services_config",
            "router_listening_sockets",
            "router_dyn_linker",
            "router_suid_files",
            "router_commit_history",
            "router_nat",
            "router_services_whitelist",
        ]
    );

    // Non-router box types must return standard 49 Linux modules
    let web_mods = BoxType::Web.scan_modules();
    assert_eq!(web_mods.len(), 49);
    assert!(!web_mods.iter().any(|(id, _, _, _)| *id == "router_nat"));
}

#[test]
fn vyos_script_contains_clean_slate_deletion_and_commit_error_handling() {
    // R1: verify clean-slate deletions of destination NAT rules 10-14 and source rule 100
    assert!(
        VYOS_SCRIPT.contains("delete nat destination rule \"$r\""),
        "Script must perform clean-slate deletion of destination NAT rules 10-14"
    );
    assert!(
        VYOS_SCRIPT.contains("delete nat source rule 100"),
        "Script must perform clean-slate deletion of source NAT rule 100"
    );

    // R1: verify commit and commit-confirm failure detection with discard and exit 1
    assert!(
        VYOS_SCRIPT.contains("discard 2>/dev/null"),
        "Script must execute discard on commit failure"
    );
    assert!(
        VYOS_SCRIPT.contains("Commit failed"),
        "Script must check for 'Commit failed' marker"
    );
    assert!(
        VYOS_SCRIPT.contains("builtin exit 1"),
        "Script must exit with code 1 on commit failure"
    );

    // R2: verify routing baseline
    assert!(
        VYOS_SCRIPT.contains("apply_routing_baseline"),
        "Script must define apply_routing_baseline"
    );
    assert!(
        VYOS_SCRIPT.contains("172.20.240.0/24"),
        "Script must reference servers DMZ 172.20.240.0/24"
    );
}

#[test]
fn commit_failure_detection_and_checked_pending_state() {
    // Marker detection
    assert!(has_commit_failure("Commit failed"));
    assert!(has_commit_failure("[[nat destination rule 10]] failed"));
    assert!(has_commit_failure("commit-confirm failed! Rollback will not be initiated."));
    assert!(!has_commit_failure("Changes applied with commit-confirm 5!"));
    assert!(!has_commit_failure("Configuration committed and saved permanently."));

    // should_enter_pending_state_checked
    assert!(should_enter_pending_state_checked(
        "harden",
        false,
        0,
        "Changes applied with commit-confirm 5!"
    ));
    assert!(should_enter_pending_state_checked(
        "router_nat",
        false,
        0,
        "NAT rules applied with commit-confirm 5!"
    ));

    // Failed exit code must NOT enter pending state
    assert!(!should_enter_pending_state_checked(
        "harden",
        false,
        1,
        "Changes applied with commit-confirm 5!"
    ));

    // Commit failure output must NOT enter pending state even if exit code was 0
    assert!(!should_enter_pending_state_checked(
        "harden",
        false,
        0,
        "Commit failed\n[[nat destination rule 10]] failed"
    ));

    // --no-confirm must NOT enter pending state
    assert!(!should_enter_pending_state_checked(
        "harden",
        true,
        0,
        "Configuration committed and saved permanently."
    ));
}

#[test]
fn build_script_args_maps_restore_mode_and_config_source() {
    let args = CliArgs {
        restore_nat: true,
        team: Some(5),
        dnat_target: Some("private".into()),
        restore_mode: Some("baseline".into()),
        config_source: Some("/etc/linux-defender/vyos/detected_nat_routes.json".into()),
        ..Default::default()
    };
    let script_args = build_script_args(&args);
    assert!(script_args.contains(&"--restore-nat".to_string()));
    assert!(script_args.contains(&"--team".to_string()));
    assert!(script_args.contains(&"5".to_string()));
    assert!(script_args.contains(&"--dnat-target".to_string()));
    assert!(script_args.contains(&"private".to_string()));
    assert!(script_args.contains(&"--restore-mode".to_string()));
    assert!(script_args.contains(&"baseline".to_string()));
    assert!(script_args.contains(&"--config-source".to_string()));
    assert!(script_args.contains(&"/etc/linux-defender/vyos/detected_nat_routes.json".to_string()));
}

#[test]
fn dashboard_router_status_helpers() {
    // When clean config fixture is present on disk, live evaluation detects valid environment
    let (nat_st, desc_nat) = get_router_nat_status(&[]);
    assert_eq!(nat_st, RouterSubsystemStatus::Valid);
    assert!(desc_nat.contains("Configured & Valid"));

    let (rt_st, desc_rt) = get_router_routes_status(&[]);
    assert_eq!(rt_st, RouterSubsystemStatus::Valid);
    assert!(desc_rt.contains("Configured & Valid"));

    // Incomplete state: only 1 valid target finding present
    let mut valid_nat_finding = Finding::new(
        Severity::Info,
        "router_nat",
        "Scored DNAT Active: E-Commerce Web (Rule 10 -> 172.20.240.10)",
        "",
    );
    valid_nat_finding.resolved = true;
    let (nat_st_ok, desc_ok) = get_router_nat_status(&[valid_nat_finding]);
    assert_eq!(nat_st_ok, RouterSubsystemStatus::Invalid);
    assert!(desc_ok.contains("Incomplete: 1/5"));

    // Complete valid state: all 5 scored targets present as findings
    let all_5_findings = vec![
        Finding::new(Severity::Info, "router_nat", "Scored DNAT Active: E-Commerce Web (Rule 10 -> 172.20.240.10)", ""),
        Finding::new(Severity::Info, "router_nat", "Scored DNAT Active: Mail Server (Rule 11 -> 172.20.240.15)", ""),
        Finding::new(Severity::Info, "router_nat", "Scored DNAT Active: Splunk SIEM (Rule 12 -> 172.20.240.20)", ""),
        Finding::new(Severity::Info, "router_nat", "Scored DNAT Active: Active Directory (Rule 13 -> 172.20.240.100)", ""),
        Finding::new(Severity::Info, "router_nat", "Scored DNAT Active: MSSQL Database (Rule 14 -> 172.20.240.120)", ""),
    ];
    let (nat_st_5, desc_5) = get_router_nat_status(&all_5_findings);
    assert_eq!(nat_st_5, RouterSubsystemStatus::Valid);
    assert!(desc_5.contains("5/5 Scored Targets Active"));

    // Invalid state: High finding present
    let crit_nat_finding = Finding::new(
        Severity::High,
        "router_nat",
        "Missing Scored DNAT Rule 10: scoring traffic not forwarded",
        "Restore DNAT baseline",
    );
    let (nat_st_bad, desc_bad) = get_router_nat_status(&[crit_nat_finding]);
    assert_eq!(nat_st_bad, RouterSubsystemStatus::Invalid);
    assert!(desc_bad.contains("Rule 10"));

    // Backup timestamp formatting helper does not panic
    let _ = get_last_router_backup_timestamp();
}

#[test]
fn evaluate_config_routes_status_detects_clean_and_drifted() {
    use linux_defender::router::scan::evaluate_config_routes_status;

    let clean_routes = r#"
protocols {
    static {
        route 0.0.0.0/0 { next-hop 172.31.20.1 {} }
        route 172.20.240.0/24 { next-hop 172.16.0.254 {} }
    }
}
"#;
    let (st_ok, desc_ok) = evaluate_config_routes_status(clean_routes);
    assert_eq!(st_ok, RouterSubsystemStatus::Valid);
    assert!(desc_ok.contains("WAN Default & DMZ Transit Active"));

    let missing_def = r#"
protocols {
    static {
        route 172.20.240.0/24 { next-hop 172.16.0.254 {} }
    }
}
"#;
    let (st_no_def, desc_no_def) = evaluate_config_routes_status(missing_def);
    assert_eq!(st_no_def, RouterSubsystemStatus::Invalid);
    assert!(desc_no_def.contains("Missing Default Route"));

    let rogue_tunnel = r#"
interfaces {
    wireguard wg0 {
        address 10.99.0.1/24
    }
}
protocols {
    static {
        route 0.0.0.0/0 { next-hop 172.31.20.1 {} }
        route 172.20.240.0/24 { next-hop 172.16.0.254 {} }
    }
}
"#;
    let (st_tunnel, desc_tunnel) = evaluate_config_routes_status(rogue_tunnel);
    assert_eq!(st_tunnel, RouterSubsystemStatus::Invalid);
    assert!(desc_tunnel.contains("wireguard"));
}

#[test]
fn carriage_return_sanitization() {
    use linux_defender::core::utils::sanitize_cr;

    assert_eq!(sanitize_cr("plain line"), "plain line");
    assert_eq!(
        sanitize_cr("[INFO] Step 5: Disablin3 iRotating password for 'vyos'..."),
        "[INFO] Step 5: Disablin3 iRotating password for 'vyos'..."
    );
    assert_eq!(
        sanitize_cr("[INFO] Old text\r[INFO] New text"),
        "[INFO] New text"
    );
    assert_eq!(sanitize_cr("Progress 50%\rProgress 100%"), "Progress 100%");
}

#[test]
fn rule_100_cannot_masquerade_as_rule_10() {
    use linux_defender::router::scan::parse_nat_rules_from_content;

    // Adversarial scenario 1: Rule 100 configured in source NAT with translation address 172.20.240.10
    // and no destination NAT rules configured.
    let config_source_nat_only = r#"
nat {
    source {
        rule 100 {
            description "Workstation Outbound PAT"
            outbound-interface eth0
            source {
                address 172.16.0.0/12
            }
            translation {
                address 172.20.240.10
            }
        }
    }
}
"#;
    let (detected, missing, drifted) = parse_nat_rules_from_content(config_source_nat_only);
    assert!(
        missing.contains(&10),
        "Rule 10 must be reported missing when only source NAT rule 100 exists"
    );
    assert_eq!(
        missing.len(),
        5,
        "All rules 10-14 must be missing when destination NAT is absent"
    );
    assert!(
        detected.is_empty(),
        "No destination NAT rules should be detected"
    );
    assert!(drifted.is_empty());

    // Adversarial scenario 2: Rogue rule 100 inside destination NAT with target matching rule 10 target
    let config_rogue_dest_nat = r#"
nat {
    destination {
        rule 100 {
            description "Rogue Rule 100 Masquerading"
            destination {
                address 172.25.21.10
            }
            translation {
                address 172.20.240.10
            }
        }
        rule 11 {
            description "Email"
            destination {
                address 172.25.21.15
            }
            translation {
                address 172.20.240.15
            }
        }
    }
}
"#;
    let (detected2, missing2, _) = parse_nat_rules_from_content(config_rogue_dest_nat);
    assert!(
        missing2.contains(&10),
        "Rule 10 must be reported missing even if rule 100 exists in destination NAT"
    );
    let rule_10_detected = detected2.iter().any(|r| r.rule_num == 10);
    assert!(
        !rule_10_detected,
        "Rule 10 must NOT be satisfied by rule 100"
    );
    let rule_11_detected = detected2.iter().find(|r| r.rule_num == 11).unwrap();
    assert!(rule_11_detected.is_valid);
}

#[test]
fn save_detected_nat_routes_merges_state_without_wiping_nat_rules() {
    use linux_defender::router::scan::{
        DetectedNatRule, DetectedRoute, save_detected_nat_routes_to_path,
    };
    use std::fs;

    let test_dir = std::env::temp_dir().join(format!(
        "defender_test_merge_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state_file = test_dir.join("detected_nat_routes.json");

    let nat_rules = vec![
        DetectedNatRule {
            rule_num: 10,
            description: "Ecom".into(),
            translation: "172.20.240.10".into(),
            is_valid: true,
        },
        DetectedNatRule {
            rule_num: 11,
            description: "Email".into(),
            translation: "172.20.240.15".into(),
            is_valid: true,
        },
    ];

    // Step 1: scan_nat saves NAT rules with empty routes
    save_detected_nat_routes_to_path(&state_file, &nat_rules, &[], true);

    let content_step1 = fs::read_to_string(&state_file).expect("read step 1 state");
    assert!(content_step1.contains("\"rule\": 10"));
    assert!(content_step1.contains("\"rule\": 11"));
    assert!(content_step1.contains("\"outbound_pat\": true"));

    let routes = vec![
        DetectedRoute {
            prefix: "0.0.0.0/0".into(),
            next_hop: "172.31.21.1".into(),
            is_valid: true,
        },
        DetectedRoute {
            prefix: "172.20.240.0/24".into(),
            next_hop: "172.16.0.254".into(),
            is_valid: true,
        },
    ];

    // Step 2: scan_interfaces runs and passes empty nat_rules slice
    save_detected_nat_routes_to_path(&state_file, &[], &routes, false);

    let content_step2 = fs::read_to_string(&state_file).expect("read step 2 state");
    // NAT rules must NOT be wiped out
    assert!(
        content_step2.contains("\"rule\": 10"),
        "Rule 10 must persist after scan_interfaces runs"
    );
    assert!(
        content_step2.contains("\"rule\": 11"),
        "Rule 11 must persist after scan_interfaces runs"
    );
    assert!(
        content_step2.contains("\"prefix\": \"0.0.0.0/0\""),
        "Default route must be present"
    );
    assert!(
        content_step2.contains("\"prefix\": \"172.20.240.0/24\""),
        "Servers DMZ route must be present"
    );
    assert!(
        content_step2.contains("\"outbound_pat\": true"),
        "Outbound PAT setting must be preserved"
    );

    // Step 3: subsequent scan_nat runs with updated NAT rules, preserving existing routes
    let updated_nat = vec![DetectedNatRule {
        rule_num: 10,
        description: "Ecom".into(),
        translation: "172.20.240.10".into(),
        is_valid: true,
    }];
    save_detected_nat_routes_to_path(&state_file, &updated_nat, &[], false);

    let content_step3 = fs::read_to_string(&state_file).expect("read step 3 state");
    assert!(
        content_step3.contains("\"prefix\": \"0.0.0.0/0\""),
        "Routes must persist when scan_nat updates rules"
    );
    assert!(
        content_step3.contains("\"prefix\": \"172.20.240.0/24\""),
        "Routes must persist when scan_nat updates rules"
    );
    assert!(content_step3.contains("\"outbound_pat\": false"));

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn translation_ip_parses_translation_address_not_destination_address() {
    use linux_defender::router::scan::parse_nat_rules_from_content;

    // Case 1: Destination address is public 172.25.21.15, Translation address is internal 172.20.240.15
    let config_clean = r#"
nat {
    destination {
        rule 11 {
            description "Mail Server"
            destination {
                address 172.25.21.15
            }
            inbound-interface eth0
            protocol tcp
            translation {
                address 172.20.240.15
            }
        }
    }
}
"#;
    let (detected1, _, drifted1) = parse_nat_rules_from_content(config_clean);
    let rule_11 = detected1
        .iter()
        .find(|r| r.rule_num == 11)
        .expect("rule 11 detected");
    assert_eq!(
        rule_11.translation, "172.20.240.15",
        "Must extract translation address (172.20.240.15), NOT destination address (172.25.21.15)"
    );
    assert!(rule_11.is_valid);
    assert!(drifted1.is_empty());

    // Case 2: Adversary tampers translation address to rogue IP 10.0.0.99 while keeping destination address 172.25.21.15
    let config_tampered = r#"
nat {
    destination {
        rule 11 {
            description "Mail Server"
            destination {
                address 172.25.21.15
            }
            inbound-interface eth0
            protocol tcp
            translation {
                address 10.0.0.99
            }
        }
    }
}
"#;
    let (detected2, _, drifted2) = parse_nat_rules_from_content(config_tampered);
    let rule_11_tampered = detected2
        .iter()
        .find(|r| r.rule_num == 11)
        .expect("rule 11 detected");
    assert_eq!(
        rule_11_tampered.translation, "10.0.0.99",
        "Must extract hijacked translation address (10.0.0.99)"
    );
    assert!(
        !rule_11_tampered.is_valid,
        "Hijacked translation address must be marked invalid"
    );
    assert!(
        drifted2
            .iter()
            .any(|(r, ip)| *r == 11 && ip == "10.0.0.99"),
        "Drift must be reported with actual translation IP"
    );
}

#[test]
fn default_route_requires_actual_static_route_and_rejects_firewall_default_action() {
    use linux_defender::router::scan::detect_static_route;

    // Case 1: Config with firewall default-action drop and interface description containing 172.16.0.254,
    // but NO static routes configured.
    let config_firewall_only = r#"
firewall {
    ipv4 {
        forward {
            filter {
                default-action drop
                rule 10 {
                    action accept
                    state established
                }
            }
        }
    }
}
interfaces {
    ethernet eth0 {
        address 172.31.21.2/29
        description "WAN link"
    }
    ethernet eth1 {
        address 172.16.0.1/24
        description "Transit interface to 172.16.0.254"
    }
}
"#;
    assert_eq!(
        detect_static_route(config_firewall_only, "0.0.0.0/0"),
        None,
        "Firewall 'default-action drop' must NOT be detected as default route 0.0.0.0/0"
    );
    assert_eq!(
        detect_static_route(config_firewall_only, "172.20.240.0/24"),
        None,
        "Interface description mentioning 172.16.0.254 must NOT be detected as static transit route"
    );

    // Case 2: Config with valid hierarchical static routes
    let config_hierarchical_routes = r#"
protocols {
    static {
        route 0.0.0.0/0 {
            next-hop 172.31.21.1 {
            }
        }
        route 172.20.240.0/24 {
            next-hop 172.16.0.254 {
            }
        }
    }
}
"#;
    assert_eq!(
        detect_static_route(config_hierarchical_routes, "0.0.0.0/0"),
        Some("172.31.21.1".to_string())
    );
    assert_eq!(
        detect_static_route(config_hierarchical_routes, "172.20.240.0/24"),
        Some("172.16.0.254".to_string())
    );

    // Case 3: Flat set command syntax
    let config_set_routes = r#"
set protocols static route 0.0.0.0/0 next-hop 172.31.25.1
set protocols static route 172.20.240.0/24 next-hop 172.16.0.254
"#;
    assert_eq!(
        detect_static_route(config_set_routes, "0.0.0.0/0"),
        Some("172.31.25.1".to_string())
    );
    assert_eq!(
        detect_static_route(config_set_routes, "172.20.240.0/24"),
        Some("172.16.0.254".to_string())
    );
}

#[test]
fn vyos_script_contains_detected_restore_mode_engine() {
    // Verify script has detected state restoration engine and parsing logic
    assert!(
        VYOS_SCRIPT.contains("apply_detected_configuration"),
        "Script must define apply_detected_configuration"
    );
    assert!(
        VYOS_SCRIPT.contains("apply_detected_configuration \"$DETECTED_FILE\""),
        "Script must invoke apply_detected_configuration with DETECTED_FILE"
    );
    assert!(
        VYOS_SCRIPT.contains("nat_rules"),
        "Script must parse nat_rules from detected state"
    );
    assert!(
        VYOS_SCRIPT.contains("static_routes"),
        "Script must parse static_routes from detected state"
    );
}

#[test]
fn vyos_script_preserves_existing_dnat_and_disables_pat() {
    assert!(
        VYOS_SCRIPT.contains("EXISTING_DNAT_COUNT"),
        "Script must count existing destination NAT rules before modifying"
    );
    assert!(
        VYOS_SCRIPT.contains("Preserving existing destination NAT configuration"),
        "Script must log preservation of existing destination NAT rules"
    );
    assert!(
        VYOS_SCRIPT.contains("Outbound PAT is DISABLED by default"),
        "Script must disable Outbound PAT by default for anti-reverse-shell defense"
    );
}

#[test]
fn vyos_script_derives_team_0_practice_wan_ip_40() {
    assert!(
        VYOS_SCRIPT.contains("172.31.40.2/29"),
        "Script must use 172.31.40.2/29 as WAN Router IP for Team 0 practice environment"
    );
    assert!(
        VYOS_SCRIPT.contains("172.31.40.1"),
        "Script must use 172.31.40.1 as Core Gateway for Team 0 practice environment"
    );
    assert!(
        VYOS_SCRIPT.contains("172.25.40.0/24"),
        "Script must use 172.25.40.0/24 as Public Pool for Team 0 practice environment"
    );
}

#[test]
fn test_context_silent_progress_absorbs_messages() {
    let report = linux_defender::core::log_path("test_silent.log");
    let ctx = linux_defender::core::DefenderContext::new(report, false)
        .with_silent_progress();
    ctx.progress("This message should be silently absorbed into the progress sink channel");
    assert!(!ctx.interactive(), "Context with progress channel is not interactive");
}
