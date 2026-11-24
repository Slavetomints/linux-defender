//! VyOS 14 modular audit scan engine for Tab 3 (Scan) with IP-Centric NAT detection.
//!
//! Implements 14 dedicated router forensic audit and integrity checks grounded
//! in CCDC network topology:
//!   - WAN: 172.31.(20+Team).2/29 (Gateway .1)
//!   - Internal LAN: 172.16.0.254/24
//!   - Workstations: 172.17.0.1/24 (eth2)
//!   - Servers DMZ: 172.20.240.x (Ecom .10, Email .15, Splunk .20, AD .100, MSSQL .120)
//!
//! Each module runs independently, emits rich structured `Finding` objects with
//! command details, detection triggers, and remediation recommendations, and saves
//! state for Tab 4 (Router Operations) remediation actions.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::{DefenderContext, Finding, Severity};

/// Candidate locations to inspect for VyOS persistent configuration.
const CONFIG_BOOT_PATHS: &[&str] = &[
    "/config/config.boot",
    "/etc/linux-defender/vyos/config.boot",
    "/tmp/defender/vyos/config.boot",
    "tests/fixtures/router/config.boot.clean",
];

/// Path for recording detected NAT rules and routes for Tab 4 restore.
const DETECTED_STATE_PATH_PRIMARY: &str = "/etc/linux-defender/vyos/detected_nat_routes.json";
const DETECTED_STATE_PATH_FALLBACK: &str = "/tmp/defender/vyos/detected_nat_routes.json";

/// Scored CCDC server target definition for IP-centric NAT matching.
#[derive(Debug, Clone, Copy)]
pub struct ScoredServerTarget {
    /// Friendly service name (e.g. "E-Commerce Web").
    pub name: &'static str,
    /// Target IP suffix (e.g. ".10").
    pub ip_suffix: &'static str,
    /// Default internal target IP (e.g. "172.20.240.10").
    pub internal_ip: &'static str,
    /// List of expected scored inbound port numbers.
    pub expected_ports: &'static [&'static str],
    /// Transport layer protocol (e.g. "tcp" or "tcp_udp").
    pub protocol: &'static str,
}

/// Standard CCDC scored server definitions.
pub const SCORED_SERVERS: &[ScoredServerTarget] = &[
    ScoredServerTarget {
        name: "E-Commerce Web",
        ip_suffix: ".10",
        internal_ip: "172.20.240.10",
        expected_ports: &["80", "443"],
        protocol: "tcp",
    },
    ScoredServerTarget {
        name: "Mail Server",
        ip_suffix: ".15",
        internal_ip: "172.20.240.15",
        expected_ports: &["25", "143", "587", "993"],
        protocol: "tcp",
    },
    ScoredServerTarget {
        name: "Splunk SIEM",
        ip_suffix: ".20",
        internal_ip: "172.20.240.20",
        expected_ports: &["8000", "8089", "9997"],
        protocol: "tcp",
    },
    ScoredServerTarget {
        name: "Active Directory",
        ip_suffix: ".100",
        internal_ip: "172.20.240.100",
        expected_ports: &["53", "88", "389", "636", "5985"],
        protocol: "tcp",
    },
    ScoredServerTarget {
        name: "MSSQL Database",
        ip_suffix: ".120",
        internal_ip: "172.20.240.120",
        expected_ports: &["445", "1433", "3389"],
        protocol: "tcp",
    },
];

/// Load the active or fixture VyOS `config.boot` file content.
pub fn load_config_boot() -> Option<(PathBuf, String)> {
    for p in CONFIG_BOOT_PATHS {
        let path = PathBuf::from(p);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if !content.trim().is_empty() {
                    return Some((path, content));
                }
            }
        }
    }
    None
}

/// Helper to execute a command with args, returning stdout if successful.
fn run_cmd_output(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).to_string())
            } else {
                None
            }
        })
}

/// Helper to extract the contents of a braced block: `{ ... }` given the position of `{`.
pub fn extract_braced_block(s: &str, open_brace_pos: usize) -> Option<&str> {
    let mut depth = 0;
    for (i, c) in s[open_brace_pos..].char_indices() {
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(&s[open_brace_pos + 1..open_brace_pos + i]);
            }
        }
    }
    None
}

/// Helper to locate a named block body: `name { ... }` or `name \n { ... }`.
pub fn find_named_block<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    let mut search_idx = 0;
    while let Some(rel) = content[search_idx..].find(name) {
        let name_pos = search_idx + rel;
        search_idx = name_pos + name.len();

        // Ensure boundary before name: start of string or non-alphanumeric/underscore/hyphen
        if name_pos > 0 {
            let prev = content[..name_pos].chars().last().unwrap();
            if prev.is_alphanumeric() || prev == '-' || prev == '_' {
                continue;
            }
        }

        // Find the opening brace '{' after name, allowing only whitespace
        let after_name = &content[name_pos + name.len()..];
        let mut chars = after_name.char_indices();
        let mut brace_rel = None;
        for (idx, c) in chars.by_ref() {
            if c == '{' {
                brace_rel = Some(idx);
                break;
            } else if !c.is_whitespace() {
                break;
            }
        }

        if let Some(brace_offset) = brace_rel {
            let open_brace = name_pos + name.len() + brace_offset;
            if let Some(body) = extract_braced_block(content, open_brace) {
                return Some(body);
            }
        }
    }
    None
}

/// Helper to extract field value from a JSON string without external serde dependency.
fn extract_json_str(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":", key);
    let idx = line.find(&pattern)?;
    let rest = line[idx + pattern.len()..].trim();
    if rest.starts_with('"') {
        let content = &rest[1..];
        let end = content.find('"')?;
        Some(content[..end].to_string())
    } else {
        None
    }
}

fn extract_json_u32(line: &str, key: &str) -> Option<u32> {
    let pattern = format!("\"{}\":", key);
    let idx = line.find(&pattern)?;
    let rest = line[idx + pattern.len()..].trim();
    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse::<u32>().ok()
}

fn extract_json_bool(line: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", key);
    let idx = line.find(&pattern)?;
    let rest = line[idx + pattern.len()..].trim();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Save detected NAT rules and routes to a specific path, merging with existing state.
pub fn save_detected_nat_routes_to_path(
    target_path: &Path,
    detected_nat: &[DetectedNatRule],
    detected_routes: &[DetectedRoute],
    outbound_pat: bool,
) {
    if let Some(parent) = target_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut final_nat: Vec<DetectedNatRule> = detected_nat.to_vec();
    let mut final_routes: Vec<DetectedRoute> = detected_routes.to_vec();
    let mut final_outbound_pat = outbound_pat;

    if target_path.exists() {
        if let Ok(existing) = fs::read_to_string(target_path) {
            let mut existing_nat = Vec::new();
            let mut existing_routes = Vec::new();

            for line in existing.lines() {
                if line.contains("\"rule\":") {
                    if let (Some(rule_num), Some(description), Some(translation), Some(is_valid)) = (
                        extract_json_u32(line, "rule"),
                        extract_json_str(line, "description"),
                        extract_json_str(line, "translation"),
                        extract_json_bool(line, "valid"),
                    ) {
                        existing_nat.push(DetectedNatRule {
                            rule_num,
                            description,
                            translation,
                            is_valid,
                        });
                    }
                } else if line.contains("\"prefix\":") {
                    if let (Some(prefix), Some(next_hop), Some(is_valid)) = (
                        extract_json_str(line, "prefix"),
                        extract_json_str(line, "next_hop"),
                        extract_json_bool(line, "valid"),
                    ) {
                        existing_routes.push(DetectedRoute {
                            prefix,
                            next_hop,
                            is_valid,
                        });
                    }
                }
            }

            let existing_pat = extract_json_bool(&existing, "outbound_pat");

            if final_nat.is_empty() && !existing_nat.is_empty() {
                final_nat = existing_nat;
                if let Some(ep) = existing_pat {
                    final_outbound_pat = ep;
                }
            }

            if final_routes.is_empty() && !existing_routes.is_empty() {
                final_routes = existing_routes;
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"timestamp\": \"{}\",\n", now));
    json.push_str(&format!("  \"outbound_pat\": {},\n", final_outbound_pat));
    json.push_str("  \"nat_rules\": [\n");
    for (i, r) in final_nat.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"rule\": {}, \"description\": \"{}\", \"translation\": \"{}\", \"valid\": {}}}{}\n",
            r.rule_num,
            r.description,
            r.translation,
            r.is_valid,
            if i + 1 < final_nat.len() { "," } else { "" }
        ));
    }
    json.push_str("  ],\n");
    json.push_str("  \"static_routes\": [\n");
    for (i, rt) in final_routes.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"prefix\": \"{}\", \"next_hop\": \"{}\", \"valid\": {}}}{}\n",
            rt.prefix,
            rt.next_hop,
            rt.is_valid,
            if i + 1 < final_routes.len() { "," } else { "" }
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");

    let _ = fs::write(target_path, json);
}

/// Helper to ensure directory exists and record detected NAT rules and routes as JSON.
pub fn save_detected_nat_routes(
    detected_nat: &[DetectedNatRule],
    detected_routes: &[DetectedRoute],
    outbound_pat: bool,
) {
    let target_path = if nix::unistd::geteuid().is_root() {
        let dir = Path::new("/etc/linux-defender/vyos");
        if fs::create_dir_all(dir).is_ok() {
            PathBuf::from(DETECTED_STATE_PATH_PRIMARY)
        } else {
            PathBuf::from(DETECTED_STATE_PATH_FALLBACK)
        }
    } else {
        let dir = Path::new("/tmp/defender/vyos");
        let _ = fs::create_dir_all(dir);
        PathBuf::from(DETECTED_STATE_PATH_FALLBACK)
    };

    save_detected_nat_routes_to_path(&target_path, detected_nat, detected_routes, outbound_pat);
}

/// Detected NAT rule representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedNatRule {
    /// Rule number in VyOS configuration.
    pub rule_num: u32,
    /// Rule description or server label.
    pub description: String,
    /// Destination translation address.
    pub translation: String,
    /// Whether the rule is structurally valid and expected.
    pub is_valid: bool,
}

/// Raw parsed destination NAT rule extracted from configuration.
#[derive(Debug, Clone)]
pub struct ParsedDestNatRule {
    /// Discovered rule number.
    pub rule_num: u32,
    /// Rule description text.
    pub description: String,
    /// Target translation IP address.
    pub translation_address: String,
    /// Inbound destination port(s).
    pub destination_ports: String,
    /// Protocol (e.g. tcp, udp, tcp_udp).
    pub protocol: String,
    /// Inbound network interface (e.g. eth0).
    pub inbound_interface: String,
}

/// Detected static route representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedRoute {
    /// Destination CIDR prefix.
    pub prefix: String,
    /// Next-hop gateway IP address.
    pub next_hop: String,
    /// Whether this route matches competition topology.
    pub is_valid: bool,
}

/// Status of a router subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterSubsystemStatus {
    /// Subsystem is fully active and compliant with baseline.
    Valid,
    /// Subsystem has missing rules or drifted configuration.
    Invalid,
    /// Initial audit scan has not yet been executed or unconfigured.
    PendingScan,
}

/// Evaluates raw VyOS configuration text for destination NAT and outbound PAT status.
pub fn evaluate_config_nat_status(content: &str) -> (RouterSubsystemStatus, String) {
    let parsed_rules = parse_all_dest_nat_rules(content);
    if parsed_rules.is_empty() {
        return (
            RouterSubsystemStatus::PendingScan,
            "Pending scan — run [3]".into(),
        );
    }

    let outcome = audit_nat_rules_by_ip(&parsed_rules);

    if outcome.valid_targets.len() == 5
        && outcome.missing_targets.is_empty()
        && outcome.duplicate_conflicts.is_empty()
        && outcome.drifted_targets.is_empty()
        && outcome.rogue_rules.is_empty()
    {
        (
            RouterSubsystemStatus::Valid,
            "Configured & Valid (5/5 Scored Targets Active)".into(),
        )
    } else if !outcome.missing_targets.is_empty() {
        let missing_names: Vec<&str> = outcome.missing_targets.iter().map(|t| t.name).collect();
        (
            RouterSubsystemStatus::Invalid,
            format!("Missing {} scored target(s): {}", outcome.missing_targets.len(), missing_names.join(", ")),
        )
    } else if !outcome.drifted_targets.is_empty() {
        let (target, rule, reason) = &outcome.drifted_targets[0];
        (
            RouterSubsystemStatus::Invalid,
            format!("Port drift on {} (Rule {}): {}", target.name, rule.rule_num, reason),
        )
    } else if !outcome.duplicate_conflicts.is_empty() {
        let (target, rules) = &outcome.duplicate_conflicts[0];
        let nums: Vec<String> = rules.iter().map(|r| r.rule_num.to_string()).collect();
        (
            RouterSubsystemStatus::Invalid,
            format!("Conflicting rules for {} ({})", target.name, nums.join(", ")),
        )
    } else if !outcome.rogue_rules.is_empty() {
        (
            RouterSubsystemStatus::Invalid,
            format!("Rogue NAT Rule {} -> {}:{}", outcome.rogue_rules[0].rule_num, outcome.rogue_rules[0].translation_address, outcome.rogue_rules[0].destination_ports),
        )
    } else {
        (
            RouterSubsystemStatus::Invalid,
            format!("Incomplete: {}/5 Scored Targets Active", outcome.valid_targets.len()),
        )
    }
}

/// Evaluates raw VyOS configuration text for static routing and rogue tunnel status.
pub fn evaluate_config_routes_status(content: &str) -> (RouterSubsystemStatus, String) {
    if content.trim().is_empty() {
        return (
            RouterSubsystemStatus::PendingScan,
            "Pending scan — run [3]".into(),
        );
    }

    // Check rogue tunnels first
    for tunnel in &["wireguard", "openvpn", "vti", "tunnel", "pseudo-ethernet", "vxlan"] {
        if content.contains(&format!("interfaces {} ", tunnel)) {
            return (
                RouterSubsystemStatus::Invalid,
                format!("Rogue tunnel interface configured: '{}'", tunnel),
            );
        }
    }

    let has_default = detect_static_route(content, "0.0.0.0/0").is_some();
    let has_transit = detect_static_route(content, "172.20.240.0/24").is_some();

    if has_default && has_transit {
        (
            RouterSubsystemStatus::Valid,
            "Configured & Valid (WAN Default & DMZ Transit Active)".into(),
        )
    } else if !has_default && !has_transit {
        (
            RouterSubsystemStatus::Invalid,
            "Missing Default (0.0.0.0/0) & DMZ Transit (172.20.240.0/24) Routes".into(),
        )
    } else if !has_default {
        (
            RouterSubsystemStatus::Invalid,
            "Missing Default Route (0.0.0.0/0)".into(),
        )
    } else {
        (
            RouterSubsystemStatus::Invalid,
            "Missing DMZ Transit Route (172.20.240.0/24)".into(),
        )
    }
}

/// Evaluates live NAT status from persistent configuration or cached runtime state.
pub fn evaluate_live_nat_status() -> Option<(RouterSubsystemStatus, String)> {
    if let Some((_, content)) = load_config_boot() {
        Some(evaluate_config_nat_status(&content))
    } else {
        None
    }
}

/// Evaluates live routing status from persistent configuration or system routing table.
pub fn evaluate_live_routes_status() -> Option<(RouterSubsystemStatus, String)> {
    if let Some((_, content)) = load_config_boot() {
        let (st, desc) = evaluate_config_routes_status(&content);
        if st == RouterSubsystemStatus::Valid {
            return Some((st, desc));
        }
    }

    // Check kernel routing table fallback via `ip route show` or `/proc/net/route`
    if let Some(out) = run_cmd_output("ip", &["route", "show"]) {
        let has_default = out.contains("default via");
        let has_transit = out.contains("172.20.240.0/24 via");
        if has_default && has_transit {
            return Some((
                RouterSubsystemStatus::Valid,
                "Configured & Valid (WAN Default & DMZ Transit Active via kernel)".into(),
            ));
        }
    }

    if let Some((_, content)) = load_config_boot() {
        Some(evaluate_config_routes_status(&content))
    } else {
        None
    }
}

/// IP-Centric NAT audit outcome.
#[derive(Debug, Clone)]
pub struct NatIpAuditOutcome {
    /// All detected destination NAT rules formatted for display.
    pub detected_rules: Vec<DetectedNatRule>,
    /// Targets correctly mapped with valid ports and interface.
    pub valid_targets: Vec<(ScoredServerTarget, ParsedDestNatRule)>,
    /// Targets with port drift or misconfigured ports.
    pub drifted_targets: Vec<(ScoredServerTarget, ParsedDestNatRule, String)>,
    /// Targets with duplicate conflicting destination rules.
    pub duplicate_conflicts: Vec<(ScoredServerTarget, Vec<ParsedDestNatRule>)>,
    /// Scored targets lacking any inbound destination NAT rule.
    pub missing_targets: Vec<ScoredServerTarget>,
    /// Rules translating to unknown or untracked destination IPs.
    pub rogue_rules: Vec<ParsedDestNatRule>,
    /// Whether outbound masquerade/PAT is active.
    pub outbound_pat_active: bool,
}

/// Dispatch execution for any of the 14 router audit scan modules by ID.
pub fn run_module(id: &str, ctx: &DefenderContext) {
    match id {
        "router_version" => scan_version(ctx),
        "router_boot_hooks" => scan_boot_hooks(ctx),
        "router_commit_hooks" => scan_commit_hooks(ctx),
        "router_task_scheduler" => scan_task_scheduler(ctx),
        "router_users" => scan_users(ctx),
        "router_interfaces" => scan_interfaces(ctx),
        "router_containers" => scan_containers(ctx),
        "router_services_config" => scan_services_config(ctx),
        "router_listening_sockets" => scan_listening_sockets(ctx),
        "router_dyn_linker" => scan_dynamic_linker(ctx),
        "router_suid_files" => scan_suid_files(ctx),
        "router_commit_history" => scan_commit_history(ctx),
        "router_nat" => scan_nat(ctx),
        "router_services_whitelist" => scan_services_whitelist(ctx),
        _ => {
            ctx.progress(&format!("Unknown router scan module ID: {}", id));
        }
    }
}

// ==============================================================================
// 1. System Version & Identity
// ==============================================================================
/// Module 1: Probes system version, OS release, and system identity.
pub fn scan_version(ctx: &DefenderContext) {
    ctx.progress("[*] Module 1: Probing VyOS System Version & Identity...");

    let mut output = String::new();
    if let Some(ver_out) = run_cmd_output("show", &["version"]) {
        output = ver_out;
    } else if let Ok(os_rel) = fs::read_to_string("/etc/os-release") {
        output = os_rel;
    } else if let Ok(ver) = fs::read_to_string("/proc/version") {
        output = ver;
    }

    let release_line = output
        .lines()
        .find(|l| l.contains("Version:") || l.contains("PRETTY_NAME="))
        .unwrap_or("VyOS Sagitta 1.4.0")
        .trim();

    let mut finding = Finding::new(
        Severity::Info,
        "router_version",
        format!("System Identity: {}", release_line),
        output.clone(),
    );

    finding.context.push(("Command Executed", "show version || cat /etc/os-release".into()));
    finding.context.push(("System Release", release_line.to_string()));
    finding.recommendation = "Verify system release train, kernel version, and build UUID match official competition baseline.".into();

    ctx.emit(finding);
}

// ==============================================================================
// 2. /config/scripts/ Directory & Boot Hooks
// ==============================================================================
/// Module 2: Audits `/config/scripts/` bootup scripts, injected hooks, and active processes.
pub fn scan_boot_hooks(ctx: &DefenderContext) {
    ctx.progress("[*] Module 2: Auditing /config/scripts/ Directory & Boot Hooks...");

    // 1. Inspect live processes running from /config/scripts/
    if let Some(pgrep_out) = run_cmd_output("pgrep", &["-a", "-f", "/config/scripts/"]) {
        let mut procs = Vec::new();
        for line in pgrep_out.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.contains("pgrep")
                && !trimmed.contains("linux-defender")
                && !trimmed.contains("scan_boot_hooks")
            {
                procs.push(trimmed.to_string());
            }
        }
        if !procs.is_empty() {
            let mut finding = Finding::new(
                Severity::Critical,
                "router_boot_hooks",
                format!("Active rogue process executing from /config/scripts/ ({} detected)", procs.len()),
                procs.join("\n"),
            );
            finding.context.push(("Command Executed", "pgrep -a -f /config/scripts/".into()));
            finding.context.push(("Relevant Output", procs.join("\n")));
            finding.context.push(("Threat Vector", "Live C2 Callback / Persistence Process".into()));
            finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Boot & Commit Hooks'".into()));
            finding.context.push(("Manual CLI Command", "pkill -9 -f /config/scripts/".into()));
            finding.recommendation = "Active process running from /config/scripts/. Navigate to Tab [4] and run 'Sanitize Boot & Commit Hooks' to kill rogue processes and quarantine files.".into();
            ctx.emit(finding);
        }
    }

    let scripts_dir = Path::new("/config/scripts");
    if !scripts_dir.exists() {
        let mut finding = Finding::new(
            Severity::Info,
            "router_boot_hooks",
            "/config/scripts directory does not exist (Clean)",
            "No persistence scripts present.",
        );
        finding.context.push(("Directory", "/config/scripts/".into()));
        finding.context.push(("Status", "Clean - directory absent".into()));
        ctx.emit(finding);
        return;
    }

    let standard_boot_scripts = &[
        "vyos-preconfig-bootup.script",
        "vyos-postconfig-bootup.script",
        "post-upgrade",
    ];

    let suspicious_tokens = &[
        "/dev/tcp", "nc ", "bash -i", "sh -i", "curl ", "wget ", "python ",
        "perl ", "ruby ", "useradd", "usermod", "chpasswd", "rm -rf",
        ">>>RT_", "systemctl ", "/etc/cron", "chmod ", "nohup ", "disown",
        "cp /config/scripts", "cat > /etc/", "cat >> /etc/",
    ];

    let mut found_scripts = Vec::new();
    let mut rogue_files = Vec::new();
    let mut injected_standard_scripts = Vec::new();

    if let Ok(entries) = fs::read_dir(scripts_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let content = fs::read_to_string(&path).unwrap_or_default();
                found_scripts.push((name.clone(), path.clone(), content.clone()));

                let is_standard = standard_boot_scripts.contains(&name.as_str());
                if is_standard {
                    // Check for injected lines in standard boot scripts
                    let mut matched_lines = Vec::new();
                    for (idx, line) in content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.is_empty()
                            || trimmed == "#!/bin/bash"
                            || trimmed == "#!/bin/vbash"
                            || trimmed.starts_with("# Sanitized")
                            || trimmed == "exit 0"
                            || trimmed == "source /opt/vyatta/etc/functions/script-template"
                        {
                            continue;
                        }
                        for &tok in suspicious_tokens {
                            if line.contains(tok) {
                                matched_lines.push(format!("Line {}: {}", idx + 1, trimmed));
                                break;
                            }
                        }
                    }
                    if !matched_lines.is_empty() {
                        injected_standard_scripts.push((name, path, matched_lines, content));
                    }
                } else if !content.trim().is_empty() {
                    // Non-standard file in /config/scripts/
                    let mut matched_tokens = Vec::new();
                    for &token in suspicious_tokens {
                        if content.contains(token) {
                            matched_tokens.push(token);
                        }
                    }
                    rogue_files.push((name, path, matched_tokens, content));
                }
            }
        }
    }

    // Emit atomic findings for rogue files in /config/scripts/
    for (name, path, tokens, content) in rogue_files {
        let severity = if !tokens.is_empty() { Severity::Critical } else { Severity::High };
        let mut finding = Finding::new(
            severity,
            "router_boot_hooks",
            format!("Rogue script/template in /config/scripts/: {}", name),
            content.clone(),
        );
        finding.path = Some(path.clone());
        finding.context.push(("Command Executed", format!("cat /config/scripts/{}", name)));
        let preview = content.lines().take(12).collect::<Vec<_>>().join("\n");
        finding.context.push(("Relevant Output", preview));
        finding.context.push(("Threat Vector", "VyOS OverlayFS Persistent Script (survives reboot)".into()));
        if !tokens.is_empty() {
            finding.context.push(("Matched Indicators", tokens.join(", ")));
        }
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Boot & Commit Hooks'".into()));
        finding.context.push(("Manual CLI Command", format!("rm -f /config/scripts/{}", name)));
        finding.recommendation = format!(
            "Rogue file '{}' found in /config/scripts/. Navigate to Tab [4] Router Operations and run 'Sanitize Boot & Commit Hooks' to quarantine.",
            name
        );
        ctx.emit(finding);
    }

    // Emit atomic findings for injected code in standard boot scripts
    for (name, path, matched_lines, content) in injected_standard_scripts {
        let mut finding = Finding::new(
            Severity::Critical,
            "router_boot_hooks",
            format!("Injected boot hook code detected in /config/scripts/{}", name),
            content.clone(),
        );
        finding.path = Some(path.clone());
        finding.context.push((
            "Command Executed",
            format!("grep -n -E '(>>>RT_|systemctl|cron|/config/scripts|/dev/tcp)' /config/scripts/{}", name),
        ));
        finding.context.push(("Relevant Output", matched_lines.join("\n")));
        finding.context.push(("Threat Vector", "Reboot Re-infection Hook (OverlayFS Bypass)".into()));
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Boot & Commit Hooks'".into()));
        finding.context.push((
            "Manual CLI Command",
            format!("sed -i '/>>>RT_BEGIN<<</,/>>>RT_END<<</d' /config/scripts/{}", name),
        ));
        finding.recommendation = format!(
            "Injected persistence hook detected in standard boot script '{}'. Navigate to Tab [4] Router Operations and run 'Sanitize Boot & Commit Hooks' to sanitize.",
            name
        );
        ctx.emit(finding);
    }

    if found_scripts.is_empty() {
        let mut finding = Finding::new(
            Severity::Info,
            "router_boot_hooks",
            "Boot Hooks Clean: /config/scripts/ is empty",
            "No persistence scripts present.",
        );
        finding.context.push(("Command Executed", "ls -la /config/scripts/".into()));
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }
}

// ==============================================================================
// 3. Commit Hooks (High Risk)
// ==============================================================================
/// Module 3: Audits VyOS commit hooks in `pre-hooks.d` and `post-hooks.d`.
pub fn scan_commit_hooks(ctx: &DefenderContext) {
    ctx.progress("[*] Module 3: Inspecting VyOS Commit Hooks (pre/post-hooks.d)...");

    let hook_dirs = &[
        "/config/scripts/commit/pre-hooks.d",
        "/config/scripts/commit/post-hooks.d",
    ];

    let mut found_hooks = Vec::new();
    for &dir in hook_dirs {
        let p = Path::new(dir);
        if p.exists() {
            if let Ok(entries) = fs::read_dir(p) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        found_hooks.push((dir, path, content));
                    }
                }
            }
        }
    }

    if found_hooks.is_empty() {
        let mut finding = Finding::new(
            Severity::Info,
            "router_commit_hooks",
            "Commit Hooks Clean: No pre-hooks or post-hooks configured",
            "VyOS stock image has 0 commit hooks.",
        );
        finding.context.push(("Directories Checked", "/config/scripts/commit/(pre|post)-hooks.d/".into()));
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    } else {
        for (dir, path, content) in found_hooks {
            let mut finding = Finding::new(
                Severity::Critical,
                "router_commit_hooks",
                format!("High-Risk Commit Hook Detected: {}", path.display()),
                content.clone(),
            );
            finding.path = Some(path.clone());
            finding.context.push(("Command Executed", format!("ls -la {} && cat {}", dir, path.display())));
            finding.context.push(("Detection Trigger", "Commit hook scripts execute as root on every configuration commit!".into()));
            finding.recommendation = "Run 'Sanitize Boot & Commit Hooks' in Tab [4] Router Operations immediately to delete commit hooks.".into();
            ctx.emit(finding);
        }
    }
}

// ==============================================================================
// 4. Task Scheduler & Linux Cron
// ==============================================================================
/// Module 4: Audits VyOS task-scheduler configurations and Linux system crontabs.
pub fn scan_task_scheduler(ctx: &DefenderContext) {
    ctx.progress("[*] Module 4: Auditing VyOS Task Scheduler & Linux Crontabs...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    if let Some(task_body) = find_named_block(&content, "task-scheduler") {
        let mut finding = Finding::new(
            Severity::High,
            "router_task_scheduler",
            "VyOS system task-scheduler persistence found in configuration",
            task_body.to_string(),
        );
        finding.context.push(("Command Executed", "show configuration commands | grep task-scheduler".into()));
        finding.context.push(("Relevant Output", task_body.to_string()));
        finding.context.push(("Detection Trigger", "Active task-scheduler block in /config/config.boot".into()));
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Task Scheduler & Crons'".into()));
        finding.context.push(("Manual CLI Command", "delete system task-scheduler".into()));
        finding.recommendation = "Navigate to Tab [4] Router Operations and run 'Sanitize Task Scheduler & Crons'.".into();
        ctx.emit(finding);
    }

    let standard_cron_d = &["e2scrub_all", "otbr-firewall", ".placeholder"];
    let mut total_crons_checked = 0;
    let mut rogue_cron_d_files = Vec::new();
    let mut active_crons = Vec::new();

    // 1. Audit /etc/cron.d/ for dropped persistence files
    let cron_d = Path::new("/etc/cron.d");
    if cron_d.is_dir() {
        if let Ok(entries) = fs::read_dir(cron_d) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    total_crons_checked += 1;
                    let file_name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                    let is_standard = standard_cron_d.contains(&file_name.as_str());
                    let file_content = fs::read_to_string(&p).unwrap_or_default();
                    if !is_standard && !file_content.trim().is_empty() {
                        rogue_cron_d_files.push((file_name, p.clone(), file_content));
                    }
                }
            }
        }
    }

    // 2. Audit /etc/crontab and /var/spool/cron/crontabs/
    let other_paths = &["/etc/crontab", "/var/spool/cron/crontabs"];
    for &cp in other_paths {
        let p = Path::new(cp);
        if p.is_file() {
            total_crons_checked += 1;
            if let Ok(c) = fs::read_to_string(p) {
                for line in c.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        active_crons.push((cp.to_string(), trimmed.to_string()));
                    }
                }
            }
        } else if p.is_dir() {
            if let Ok(entries) = fs::read_dir(p) {
                for entry in entries.flatten() {
                    total_crons_checked += 1;
                    if let Ok(c) = fs::read_to_string(entry.path()) {
                        for line in c.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                active_crons.push((entry.path().display().to_string(), trimmed.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    // Emit atomic findings for rogue /etc/cron.d files
    for (name, path, file_content) in rogue_cron_d_files {
        let has_callback = file_content.contains("/config/scripts") || file_content.contains("/dev/tcp") || file_content.contains("net-diag");
        let severity = if has_callback { Severity::Critical } else { Severity::High };
        let mut finding = Finding::new(
            severity,
            "router_task_scheduler",
            format!("Rogue cron dropper detected: {}", path.display()),
            file_content.clone(),
        );
        finding.path = Some(path.clone());
        finding.context.push(("Command Executed", format!("cat {}", path.display())));
        let preview = file_content.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).collect::<Vec<_>>().join("\n");
        finding.context.push(("Relevant Output", preview));
        finding.context.push(("Threat Vector", "Periodic Scheduled Execution (Survives reboot via boot script drop)".into()));
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Task Scheduler & Crons'".into()));
        finding.context.push(("Manual CLI Command", format!("rm -f {}", path.display())));
        finding.recommendation = format!(
            "Rogue cron file '{}' detected in /etc/cron.d/. Run 'Sanitize Task Scheduler & Crons' in Tab [4] to quarantine and purge.",
            name
        );
        ctx.emit(finding);
    }

    // Emit findings for active entries in /etc/crontab or crontabs
    for (path, line) in active_crons {
        let mut finding = Finding::new(
            Severity::High,
            "router_task_scheduler",
            format!("Active Linux cron entry found in {}", path),
            line.clone(),
        );
        finding.context.push(("Command Executed", format!("cat {}", path)));
        finding.context.push(("Relevant Output", line.clone()));
        finding.context.push(("Threat Vector", "User or System Crontab Persistence".into()));
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Sanitize Task Scheduler & Crons'".into()));
        finding.context.push(("Manual CLI Command", format!("crontab -r || sed -i '/{}/d' {}", line.replace('/', "\\/"), path)));
        finding.recommendation = "Review scheduled task. Run 'Sanitize Task Scheduler & Crons' in Tab [4] to flush rogue crontabs.".into();
        ctx.emit(finding);
    }

    if total_crons_checked == 0 && !content.contains("task-scheduler") {
        let mut finding = Finding::new(
            Severity::Info,
            "router_task_scheduler",
            "Scheduled Tasks Clean: No active crontabs or task-scheduler jobs",
            "System crontabs and VyOS task scheduler verified clean.",
        );
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }
}

// ==============================================================================
// 5. Login Accounts, Sudoers & SSH Keys
// ==============================================================================
/// Module 5: Audits VyOS login users, `/etc/passwd`, sudoers, and authorized_keys.
pub fn scan_users(ctx: &DefenderContext) {
    ctx.progress("[*] Module 5: Auditing Login Accounts, Sudoers & SSH Keys...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    // 1. Check VyOS users in config.boot
    if let Some(login_body) = find_named_block(&content, "login") {
        for line in login_body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("user ") {
                let user = trimmed.strip_prefix("user ").unwrap_or("").trim_end_matches('{').trim();
                if user != "vyos" && !user.is_empty() {
                    let mut finding = Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Unauthorized VyOS operator account configured: '{}'", user),
                        format!("Config line: {}", trimmed),
                    );
                    finding.context.push(("Command Executed", "show configuration commands | grep 'system login'".into()));
                    finding.context.push(("Unauthorized User", user.to_string()));
                    finding.recommendation = "Delete unauthorized operator: delete system login user <name>.".into();
                    ctx.emit(finding);
                }
            }
            if trimmed.contains("plaintext-password") {
                let mut finding = Finding::new(
                    Severity::Critical,
                    "router_users",
                    "User configured with plaintext-password in /config/config.boot",
                    trimmed.to_string(),
                );
                finding.context.push(("Risk", "Cleartext password exposure in configuration file".into()));
                finding.recommendation = "Run 'Update VyOS & Linux Root Passwords' in Tab [4] to encrypt credentials.".into();
                ctx.emit(finding);
            }
        }
    }

    // 2. Check /etc/passwd for UID 0 backdoors
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let name = parts[0];
                let uid = parts[2].parse::<u32>().unwrap_or(999);
                if uid == 0 && name != "root" {
                    let mut finding = Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Rogue UID 0 superuser account found in /etc/passwd: '{}'", name),
                        line.to_string(),
                    );
                    finding.context.push(("Command Executed", "awk -F: '($3 == 0) {print $1}' /etc/passwd".into()));
                    finding.context.push(("Account", name.to_string()));
                    finding.recommendation = "Remove rogue superuser account immediately.".into();
                    ctx.emit(finding);
                }
                let shell = parts[6];
                if uid >= 1000 && name != "vyos" && !shell.contains("nologin") && !shell.contains("false") {
                    let mut finding = Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Unauthorized interactive Linux account: '{}' (UID {})", name, uid),
                        line.to_string(),
                    );
                    finding.context.push(("User", name.to_string()));
                    finding.context.push(("Shell", shell.to_string()));
                    finding.recommendation = "Lock account: passwd -l <user> and delete from /etc/passwd.".into();
                    ctx.emit(finding);
                }
            }
        }
    }

    // 3. Check VyOS configuration public-keys in config.boot
    // Matches both:
    // Hierarchical: user <name> { ... authentication { public-keys <id> { key ... type ... } } }
    // CLI commands: set system login user <name> authentication public-keys <id> [key|type] ...
    let mut configured_keys: Vec<(String, String, String, String)> = Vec::new();
    let mut current_user = "vyos".to_string();
    let mut current_key_id = String::new();
    let mut current_key_type = String::new();
    let mut current_key_body = String::new();
    let mut in_public_key = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("user ") {
            current_user = trimmed
                .strip_prefix("user ")
                .unwrap_or("")
                .trim_end_matches('{')
                .trim()
                .to_string();
        } else if trimmed.starts_with("public-keys ") {
            if in_public_key && !current_key_id.is_empty() {
                configured_keys.push((
                    current_user.clone(),
                    current_key_id.clone(),
                    current_key_type.clone(),
                    current_key_body.clone(),
                ));
                current_key_type.clear();
                current_key_body.clear();
            }
            current_key_id = trimmed
                .strip_prefix("public-keys ")
                .unwrap_or("")
                .trim_end_matches('{')
                .trim()
                .to_string();
            in_public_key = true;
        } else if in_public_key {
            if trimmed.starts_with("type ") {
                current_key_type = trimmed
                    .strip_prefix("type ")
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim()
                    .to_string();
            } else if trimmed.starts_with("key ") {
                current_key_body = trimmed
                    .strip_prefix("key ")
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim()
                    .to_string();
            } else if trimmed == "}" {
                if !current_key_id.is_empty() {
                    configured_keys.push((
                        current_user.clone(),
                        current_key_id.clone(),
                        current_key_type.clone(),
                        current_key_body.clone(),
                    ));
                    current_key_id.clear();
                    current_key_type.clear();
                    current_key_body.clear();
                }
                in_public_key = false;
            }
        } else if trimmed.contains("authentication public-keys ") {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|&t| t == "public-keys") {
                if pos + 1 < tokens.len() {
                    let k_id = tokens[pos + 1].trim_matches('"').trim();
                    let u_name = if let Some(u_pos) = tokens.iter().position(|&t| t == "user") {
                        tokens.get(u_pos + 1).copied().unwrap_or("vyos")
                    } else {
                        "vyos"
                    };
                    if !configured_keys.iter().any(|(_, id, _, _)| id == k_id) {
                        configured_keys.push((
                            u_name.to_string(),
                            k_id.to_string(),
                            String::new(),
                            String::new(),
                        ));
                    }
                }
            }
        }
    }
    if in_public_key && !current_key_id.is_empty() {
        configured_keys.push((
            current_user.clone(),
            current_key_id,
            current_key_type,
            current_key_body,
        ));
    }

    for (user, key_id, key_type, key_body) in configured_keys {
        let mut finding = Finding::new(
            Severity::Critical,
            "router_users",
            format!("Unauthorized VyOS configuration public key: '{}' (user: {})", key_id, user),
            format!(
                "Configured SSH Public Key in /config/config.boot:\nUser: {}\nKey ID: {}\nType: {}\nKey: {}",
                user, key_id, key_type, key_body
            ),
        );
        finding.context.push(("Command Executed", "show configuration commands | grep 'authentication public-keys'".into()));
        finding.context.push(("Relevant Output", format!(
            "set system login user {} authentication public-keys {} type {}\nset system login user {} authentication public-keys {} key {}",
            user, key_id, if key_type.is_empty() { "ssh-ed25519" } else { &key_type },
            user, key_id, if key_body.is_empty() { "<key_body>" } else { &key_body }
        )));
        finding.context.push(("Threat Vector", "Persistent VyOS Configuration SSH Backdoor (Committed to config.boot, populates authorized_keys on boot)".into()));
        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Update VyOS & Linux Root Passwords'".into()));
        finding.context.push(("Manual CLI Command", format!("delete system login user {} authentication public-keys {}", user, key_id)));
        finding.recommendation = format!(
            "Unauthorized SSH public key '{}' is committed to /config/config.boot. Run 'Update VyOS & Linux Root Passwords' in Tab [4] to purge.",
            key_id
        );
        ctx.emit(finding);
    }

    // 4. Check SSH authorized_keys
    for path in &["/home/vyos/.ssh/authorized_keys", "/root/.ssh/authorized_keys"] {
        if let Ok(keys) = fs::read_to_string(path) {
            for (line_no, line) in keys.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    let mut finding = Finding::new(
                        Severity::High,
                        "router_users",
                        format!("Authorized SSH Key found in {} (line {})", path, line_no + 1),
                        trimmed.to_string(),
                    );
                    finding.path = Some(PathBuf::from(path));
                    finding.context.push(("Command Executed", format!("cat {}", path)));
                    finding.context.push(("Relevant Output", trimmed.to_string()));
                    finding.context.push(("Threat Vector", "Host SSH Authorized Key Persistence".into()));
                    finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Update VyOS & Linux Root Passwords'".into()));
                    finding.context.push(("Manual CLI Command", format!("> {} && chmod 600 {}", path, path)));
                    finding.recommendation = "Sanitize authorized_keys in Tab [4] (Update VyOS & Linux Root Passwords).".into();
                    ctx.emit(finding);
                }
            }
        }
    }
}

// ==============================================================================
// 6. Network Interfaces, Tunnels & VPNs
// ==============================================================================
/// Module 6: Audits network interface addresses, rogue tunnels, and static routes.
pub fn scan_interfaces(ctx: &DefenderContext) {
    ctx.progress("[*] Module 6: Auditing Network Interfaces, Tunnels & Static Routes...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    let mut detected_routes: Vec<DetectedRoute> = Vec::new();

    // Default route check
    let (has_default_route, def_gateway) = match detect_static_route(&content, "0.0.0.0/0") {
        Some(nh) if !nh.is_empty() => (true, nh),
        _ => (false, String::new()),
    };

    if has_default_route {
        detected_routes.push(DetectedRoute {
            prefix: "0.0.0.0/0".into(),
            next_hop: def_gateway.clone(),
            is_valid: true,
        });
        let mut finding = Finding::new(
            Severity::Info,
            "router_interfaces",
            format!("Default Route Active: 0.0.0.0/0 via {}", def_gateway),
            format!("Upstream WAN gateway: {}", def_gateway),
        );
        finding.context.push(("Route", "0.0.0.0/0".into()));
        finding.context.push(("Next-Hop", def_gateway));
        ctx.emit(finding);
    } else {
        let mut finding = Finding::new(
            Severity::Critical,
            "router_interfaces",
            "Missing Default Route (0.0.0.0/0): WAN egress gateway unreachable",
            "Router cannot reach upstream competition network.",
        );
        finding.context.push(("Missing Route", "0.0.0.0/0".into()));
        finding.recommendation = "Deploy transit routes in Tab [4] Router Operations.".into();
        ctx.emit(finding);
    }

    // Transit route check
    let (has_servers_route, srv_gateway) = match detect_static_route(&content, "172.20.240.0/24") {
        Some(nh) if !nh.is_empty() => (true, nh),
        _ => (false, String::new()),
    };

    if has_servers_route {
        detected_routes.push(DetectedRoute {
            prefix: "172.20.240.0/24".into(),
            next_hop: srv_gateway.clone(),
            is_valid: true,
        });
        let mut finding = Finding::new(
            Severity::Info,
            "router_interfaces",
            format!("Servers DMZ Transit Route Active: 172.20.240.0/24 via {}", srv_gateway),
            format!("Firewall next-hop: {}", srv_gateway),
        );
        finding.context.push(("Route", "172.20.240.0/24".into()));
        finding.context.push(("Next-Hop", srv_gateway));
        ctx.emit(finding);
    } else {
        let mut finding = Finding::new(
            Severity::High,
            "router_interfaces",
            "Missing Static Transit Route to Servers DMZ (172.20.240.0/24)",
            "Traffic to internal servers cannot route across firewall interface.",
        );
        finding.context.push(("Missing Route", "172.20.240.0/24".into()));
        finding.recommendation = "Add static route 172.20.240.0/24 next-hop 172.16.0.254.".into();
        ctx.emit(finding);
    }

    save_detected_nat_routes(&[], &detected_routes, false);

    // Check rogue tunnels
    for tunnel in &["wireguard", "openvpn", "vti", "tunnel", "pseudo-ethernet", "vxlan"] {
        if content.contains(&format!("interfaces {} ", tunnel)) {
            let mut finding = Finding::new(
                Severity::Critical,
                "router_interfaces",
                format!("Unauthorized tunnel/VPN interface type configured: '{}'", tunnel),
                format!("Matched interfaces {} definition in VyOS config", tunnel),
            );
            finding.context.push(("Interface Type", tunnel.to_string()));
            finding.recommendation = "Remove rogue tunnel interface: delete interfaces <type>.".into();
            ctx.emit(finding);
        }
    }
}

/// Helper to detect static route and extract its next-hop gateway.
pub fn detect_static_route(content: &str, prefix: &str) -> Option<String> {
    let search_scope = if let Some(protocols_body) = find_named_block(content, "protocols") {
        if let Some(static_body) = find_named_block(protocols_body, "static") {
            static_body
        } else {
            protocols_body
        }
    } else {
        content
    };

    let route_marker = format!("route {}", prefix);
    let mut search_from = 0;
    while let Some(rel_pos) = search_scope[search_from..].find(&route_marker) {
        let pos = search_from + rel_pos;
        search_from = pos + route_marker.len();

        if pos > 0 {
            let prev = search_scope[..pos].chars().last().unwrap();
            if !prev.is_whitespace() && prev != '{' && prev != ';' {
                continue;
            }
        }

        if let Some(next_c) = search_scope[pos + route_marker.len()..].chars().next() {
            if !next_c.is_whitespace() && next_c != '{' {
                continue;
            }
        }

        let tail = &search_scope[pos..pos.saturating_add(300).min(search_scope.len())];
        if let Some(nh_idx) = tail.find("next-hop") {
            let after_nh = &tail[nh_idx + 8..];
            let ip_token: String = after_nh
                .trim_start()
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '{' && *c != ';' && *c != '\'' && *c != '"')
                .collect();
            if !ip_token.is_empty() {
                return Some(ip_token);
            }
        }
    }

    None
}

// ==============================================================================
// 7. Containers (Podman / VyOS 1.4+)
// ==============================================================================
/// Module 7: Inspects VyOS container configuration and active Podman daemons.
pub fn scan_containers(ctx: &DefenderContext) {
    ctx.progress("[*] Module 7: Inspecting VyOS Containers & Podman Daemons...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    let mut found_containers = false;
    if let Some(container_body) = find_named_block(&content, "container") {
        found_containers = true;
        let mut finding = Finding::new(
            Severity::High,
            "router_containers",
            "VyOS container configuration block found in /config/config.boot",
            container_body.to_string(),
        );
        finding.context.push(("Command Executed", "show configuration commands | grep container".into()));
        finding.context.push(("Risk", "Containers on routers frequently host C2 payloads or network proxies".into()));
        finding.recommendation = "Run 'Purge Rogue Containers' in Tab [4] Router Operations.".into();
        ctx.emit(finding);
    }

    if let Some(ps_out) = run_cmd_output("podman", &["ps", "-a", "--noheading"]) {
        if !ps_out.trim().is_empty() {
            found_containers = true;
            let mut finding = Finding::new(
                Severity::Critical,
                "router_containers",
                "Active Podman containers running on VyOS router",
                ps_out.clone(),
            );
            finding.context.push(("Command Executed", "podman ps -a".into()));
            finding.context.push(("Output", ps_out.lines().take(5).collect::<Vec<&str>>().join("\n")));
            finding.recommendation = "Stop and remove rogue containers: podman rm -f -a.".into();
            ctx.emit(finding);
        }
    }

    if !found_containers {
        let mut finding = Finding::new(
            Severity::Info,
            "router_containers",
            "Containers Clean: No Podman containers or container configurations active",
            "Verified no rogue containers on router.",
        );
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }
}

// ==============================================================================
// 8. Configured System Services
// ==============================================================================
/// Module 8: Audits configured VyOS services and flags insecure legacy protocols.
pub fn scan_services_config(ctx: &DefenderContext) {
    ctx.progress("[*] Module 8: Auditing Configured System Services...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    let insecure = &["telnet", "http", "tftp", "rsh"];
    for &svc in insecure {
        if content.contains(&format!("service {} ", svc)) || content.contains(&format!("{} {{", svc)) {
            let mut finding = Finding::new(
                Severity::Critical,
                "router_services_config",
                format!("Insecure service configured in VyOS: '{}'", svc),
                format!("Found active service definition for {} in config", svc),
            );
            finding.context.push(("Service", svc.to_string()));
            finding.recommendation = "Delete insecure service: delete service <name>.".into();
            ctx.emit(finding);
        }
    }

    if let Some(svc_body) = find_named_block(&content, "service") {
        let mut finding = Finding::new(
            Severity::Info,
            "router_services_config",
            "Configured Services Baseline: Inspected active VyOS service nodes",
            svc_body.to_string(),
        );
        finding.context.push(("Command Executed", "show configuration commands | grep '^set service'".into()));
        finding.recommendation = "Review configured service nodes against approved CCDC baseline.".into();
        ctx.emit(finding);
    }
}

// ==============================================================================
// 9. Listening Sockets & Active Connections
// ==============================================================================
/// Module 9: Audits listening sockets (`ss -tulpn`) and established network connections.
pub fn scan_listening_sockets(ctx: &DefenderContext) {
    ctx.progress("[*] Module 9: Auditing Listening Sockets & Active Connections...");

    let ss_out = run_cmd_output("ss", &["-tulpn"]).unwrap_or_default();
    let mut flagged_listeners = Vec::new();

    for line in ss_out.lines() {
        if line.contains("LISTEN") {
            if line.contains(":23 ") || line.contains(":8080 ") || line.contains(":4444 ") {
                flagged_listeners.push(line.to_string());
            }
        }
    }

    if !flagged_listeners.is_empty() {
        for l in flagged_listeners {
            let mut finding = Finding::new(
                Severity::High,
                "router_listening_sockets",
                "Suspicious listening socket detected on router",
                l.clone(),
            );
            finding.context.push(("Socket Entry", l));
            finding.recommendation = "Investigate listening PID and terminate unauthorized listener.".into();
            ctx.emit(finding);
        }
    }

    let mut finding = Finding::new(
        Severity::Info,
        "router_listening_sockets",
        "Listening Sockets Baseline captured",
        if ss_out.is_empty() { "No active socket output".into() } else { ss_out.clone() },
    );
    finding.context.push(("Command Executed", "ss -tulpn".into()));
    ctx.emit(finding);
}

// ==============================================================================
// 10. Dynamic Linker & Systemd Overrides
// ==============================================================================
/// Module 10: Checks `/etc/ld.so.preload` and systemd drop-in service overrides.
pub fn scan_dynamic_linker(ctx: &DefenderContext) {
    ctx.progress("[*] Module 10: Checking Dynamic Linker & Systemd Overrides...");

    let preload = Path::new("/etc/ld.so.preload");
    if preload.exists() {
        let content = fs::read_to_string(preload).unwrap_or_default();
        let mut finding = Finding::new(
            Severity::Critical,
            "router_dyn_linker",
            "CRITICAL: /etc/ld.so.preload exists! Potential userland rootkit active!",
            content.clone(),
        );
        finding.path = Some(preload.to_path_buf());
        finding.context.push(("Command Executed", "cat /etc/ld.so.preload".into()));
        finding.context.push(("Risk", "ld.so.preload hijacks libc function calls across all processes".into()));
        finding.recommendation = "Run 'Remove Linker Overrides' in Tab [4] to delete /etc/ld.so.preload.".into();
        ctx.emit(finding);
    } else {
        let mut finding = Finding::new(
            Severity::Info,
            "router_dyn_linker",
            "Dynamic Linker Clean: /etc/ld.so.preload does not exist",
            "Verified clean dynamic linker.",
        );
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }

    let systemd_dir = Path::new("/etc/systemd/system");
    if systemd_dir.exists() {
        if let Ok(entries) = fs::read_dir(systemd_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && p.extension().map_or(false, |ext| ext == "service") {
                    let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                    let content = fs::read_to_string(&p).unwrap_or_default();
                    let is_standard_unit = name.starts_with("vyos")
                        || name.starts_with("systemd")
                        || name.starts_with("dbus")
                        || name.starts_with("ssh")
                        || name.starts_with("frr");

                    let has_suspicious_payload = content.contains("/config/scripts")
                        || content.contains("/dev/tcp")
                        || content.contains("while true")
                        || content.contains("bash -i")
                        || content.contains("nc ")
                        || name.contains("backdoor")
                        || name.contains("tunnel")
                        || name.contains("c2");

                    if has_suspicious_payload || (!is_standard_unit && !content.trim().is_empty()) {
                        let severity = if has_suspicious_payload {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        let mut finding = Finding::new(
                            severity,
                            "router_dyn_linker",
                            format!("Rogue systemd service unit: {}", name),
                            content.clone(),
                        );
                        finding.path = Some(p.clone());
                        finding.context.push(("Command Executed", format!("cat /etc/systemd/system/{}", name)));
                        let preview = content.lines().take(12).collect::<Vec<_>>().join("\n");
                        finding.context.push(("Relevant Output", preview));
                        finding.context.push(("Threat Vector", "Systemd Service Persistence (Reinstalled on boot via postconfig hook)".into()));
                        finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Disable Unnecessary Services'".into()));
                        let svc_stem = name.strip_suffix(".service").unwrap_or(&name);
                        finding.context.push((
                            "Manual CLI Command",
                            format!("systemctl disable --now {} && rm -f /etc/systemd/system/{} && systemctl daemon-reload", svc_stem, name),
                        ));
                        finding.recommendation = format!(
                            "Rogue systemd unit '{}' detected. Run 'Disable Unnecessary Services' in Tab [4] to disable, quarantine, and remove.",
                            name
                        );
                        ctx.emit(finding);
                    }
                }
            }
        }
    }
}

// ==============================================================================
// 11. SUID Binaries & Modified System Files
// ==============================================================================
/// Module 11: Scans for unexpected SUID/SGID binaries on system paths.
pub fn scan_suid_files(ctx: &DefenderContext) {
    ctx.progress("[*] Module 11: Scanning SUID Binaries & Modified System Files...");

    let mut suspicious_suid = Vec::new();
    let common_suid = &[
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
        "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/bin/mount", "/bin/umount", "/bin/ping",
    ];

    if let Some(out) = run_cmd_output("find", &["/bin", "/sbin", "/usr/bin", "/usr/sbin", "-perm", "-4000", "-type", "f"]) {
        for line in out.lines() {
            let path = line.trim();
            if !path.is_empty() && !common_suid.contains(&path) {
                suspicious_suid.push(path.to_string());
            }
        }
    }

    if !suspicious_suid.is_empty() {
        for s in suspicious_suid {
            let mut finding = Finding::new(
                Severity::High,
                "router_suid_files",
                format!("Non-standard SUID binary detected: {}", s),
                format!("Path: {}", s),
            );
            finding.context.push(("Binary Path", s));
            finding.recommendation = "Remove SUID bit if not required: chmod u-s <binary>.".into();
            ctx.emit(finding);
        }
    } else {
        let mut finding = Finding::new(
            Severity::Info,
            "router_suid_files",
            "SUID Binaries Clean: Only standard system SUID binaries found",
            "Verified standard SUID set.",
        );
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }
}

// ==============================================================================
// 12. Commit History & Config Revisions
// ==============================================================================
/// Module 12: Reviews commit log history and configuration revisions.
pub fn scan_commit_history(ctx: &DefenderContext) {
    ctx.progress("[*] Module 12: Reviewing Commit History & Config Revisions...");

    let mut commit_log = String::new();
    if let Some(out) = run_cmd_output("show", &["system", "commit"]) {
        commit_log = out;
    }

    let mut finding = Finding::new(
        Severity::Info,
        "router_commit_history",
        "VyOS Commit History Log captured",
        if commit_log.is_empty() { "No commit history found in runtime.".into() } else { commit_log.clone() },
    );
    finding.context.push(("Command Executed", "show system commit".into()));
    finding.recommendation = "Verify authors of recent configuration commits. Use Tab [4] to rollback if unauthorized changes occurred.".into();
    ctx.emit(finding);
}

// ==============================================================================
// 13. NAT Configuration (IP-Centric Baseline)
// ==============================================================================
/// Parses all destination NAT rules from configuration text into structured records.
pub fn parse_all_dest_nat_rules(content: &str) -> Vec<ParsedDestNatRule> {
    let mut parsed: Vec<ParsedDestNatRule> = Vec::new();

    let dest_block = find_named_block(content, "nat")
        .and_then(|nb| find_named_block(nb, "destination"))
        .or_else(|| find_named_block(content, "destination"));

    if let Some(body) = dest_block {
        let mut search_idx = 0;
        while let Some(rel) = body[search_idx..].find("rule ") {
            let pos = search_idx + rel;
            search_idx = pos + 5;

            let after = &body[pos + 5..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(rule_num) = num_str.parse::<u32>() {
                if let Some(brace_rel) = after[num_str.len()..].find('{') {
                    let open_brace = pos + 5 + num_str.len() + brace_rel;
                    if let Some(rule_body) = extract_braced_block(body, open_brace) {
                        let mut desc = String::new();
                        let mut trans_addr = String::new();
                        let mut ports = String::new();
                        let mut proto = "tcp".to_string();
                        let mut iface = "eth0".to_string();

                        if let Some(p) = rule_body.find("description") {
                            let val: String = rule_body[p + 11..].trim_start().chars().take_while(|c| *c != ';' && *c != '\n' && *c != '}').collect();
                            desc = val.trim_matches(|c| c == '\'' || c == '"' || c == ' ').to_string();
                        }
                        if let Some(trans_body) = find_named_block(rule_body, "translation") {
                            if let Some(p) = trans_body.find("address") {
                                let val: String = trans_body[p + 7..].trim_start().chars().take_while(|c| !c.is_whitespace() && *c != ';' && *c != '}').collect();
                                trans_addr = val.trim_matches(|c| c == '\'' || c == '"').to_string();
                            }
                        }
                        if let Some(p) = rule_body.find("destination port") {
                            let val: String = rule_body[p + 16..].trim_start().chars().take_while(|c| *c != ';' && *c != '\n' && *c != '}').collect();
                            ports = val.trim_matches(|c| c == '\'' || c == '"' || c == ' ').to_string();
                        }
                        if let Some(p) = rule_body.find("protocol") {
                            let val: String = rule_body[p + 8..].trim_start().chars().take_while(|c| !c.is_whitespace() && *c != ';' && *c != '}').collect();
                            proto = val.trim_matches(|c| c == '\'' || c == '"').to_string();
                        }
                        if let Some(p) = rule_body.find("inbound-interface") {
                            let val: String = rule_body[p + 17..].trim_start().chars().take_while(|c| !c.is_whitespace() && *c != ';' && *c != '}').collect();
                            iface = val.trim_matches(|c| c == '\'' || c == '"').to_string();
                        }

                        parsed.push(ParsedDestNatRule {
                            rule_num,
                            description: desc,
                            translation_address: trans_addr,
                            destination_ports: ports,
                            protocol: proto,
                            inbound_interface: iface,
                        });
                    }
                }
            }
        }
    }

    // Also check flat commands: `set nat destination rule <num> translation address <ip>`
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("set nat destination rule ") && trimmed.contains(" translation address ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 8 {
                if let Ok(rule_num) = parts[4].parse::<u32>() {
                    let trans_addr = parts[7].trim_matches(|c| c == '\'' || c == '"').to_string();
                    if !parsed.iter().any(|r| r.rule_num == rule_num) {
                        parsed.push(ParsedDestNatRule {
                            rule_num,
                            description: String::new(),
                            translation_address: trans_addr,
                            destination_ports: String::new(),
                            protocol: "tcp".to_string(),
                            inbound_interface: "eth0".to_string(),
                        });
                    }
                }
            }
        }
    }

    parsed
}

/// Audit parsed destination NAT rules against scored server target IPs.
pub fn audit_nat_rules_by_ip(parsed_rules: &[ParsedDestNatRule]) -> NatIpAuditOutcome {
    let mut detected_rules: Vec<DetectedNatRule> = Vec::new();
    let mut valid_targets = Vec::new();
    let mut drifted_targets = Vec::new();
    let mut duplicate_conflicts = Vec::new();
    let mut missing_targets = Vec::new();

    for &target in SCORED_SERVERS {
        let matching: Vec<&ParsedDestNatRule> = parsed_rules
            .iter()
            .filter(|r| {
                r.translation_address == target.internal_ip
                    || (r.translation_address.starts_with("172.25.")
                        && r.translation_address.ends_with(target.ip_suffix))
            })
            .collect();

        if matching.is_empty() {
            missing_targets.push(target);
        } else if matching.len() == 1 {
            let rule = matching[0];
            let mut port_drift = false;
            let mut drift_detail = String::new();

            for &p in target.expected_ports {
                if !rule.destination_ports.is_empty() && !rule.destination_ports.contains(p) {
                    port_drift = true;
                    drift_detail = format!("missing port {}", p);
                    break;
                }
            }

            if port_drift {
                drifted_targets.push((target, rule.clone(), drift_detail));
                detected_rules.push(DetectedNatRule {
                    rule_num: rule.rule_num,
                    description: target.name.to_string(),
                    translation: rule.translation_address.clone(),
                    is_valid: false,
                });
            } else {
                valid_targets.push((target, rule.clone()));
                detected_rules.push(DetectedNatRule {
                    rule_num: rule.rule_num,
                    description: target.name.to_string(),
                    translation: rule.translation_address.clone(),
                    is_valid: true,
                });
            }
        } else {
            duplicate_conflicts.push((target, matching.into_iter().cloned().collect()));
            for r in parsed_rules.iter().filter(|r| r.translation_address.ends_with(target.ip_suffix)) {
                detected_rules.push(DetectedNatRule {
                    rule_num: r.rule_num,
                    description: target.name.to_string(),
                    translation: r.translation_address.clone(),
                    is_valid: false,
                });
            }
        }
    }

    let rogue_rules: Vec<ParsedDestNatRule> = parsed_rules
        .iter()
        .filter(|r| {
            !r.translation_address.is_empty()
                && !SCORED_SERVERS.iter().any(|s| {
                    r.translation_address == s.internal_ip
                        || (r.translation_address.starts_with("172.25.")
                            && r.translation_address.ends_with(s.ip_suffix))
                })
        })
        .cloned()
        .collect();

    NatIpAuditOutcome {
        detected_rules,
        valid_targets,
        drifted_targets,
        duplicate_conflicts,
        missing_targets,
        rogue_rules,
        outbound_pat_active: false,
    }
}

/// Module 13: Audits destination NAT rules and outbound PAT using IP-centric matching.
pub fn scan_nat(ctx: &DefenderContext) {
    ctx.progress("[*] Module 13: Executing IP-Centric NAT Configuration Audit...");

    let (path, content) = match load_config_boot() {
        Some(pair) => pair,
        None => {
            let mut finding = Finding::new(
                Severity::Critical,
                "router_nat",
                "VyOS configuration file (/config/config.boot) not found or unreadable",
                "Ensure /config/config.boot exists and is accessible.",
            );
            finding.recommendation = "Restore /config/config.boot from backup in Tab [5].".into();
            ctx.emit(finding);
            return;
        }
    };

    ctx.progress(&format!("→ Loaded VyOS config from: {}", path.display()));

    let parsed_rules = parse_all_dest_nat_rules(&content);
    let mut audit_outcome = audit_nat_rules_by_ip(&parsed_rules);

    let has_outbound_pat = (content.contains("source") && content.contains("masquerade"))
        || content.contains("translation address masquerade");
    audit_outcome.outbound_pat_active = has_outbound_pat;

    save_detected_nat_routes(&audit_outcome.detected_rules, &[], has_outbound_pat);

    // 1. Report Valid Scored Targets
    for (target, rule) in &audit_outcome.valid_targets {
        let mut finding = Finding::new(
            Severity::Info,
            "router_nat",
            format!("Scored DNAT Active: {} (Rule {} -> {})", target.name, rule.rule_num, rule.translation_address),
            format!("Discovered Rule {}: proto={}, ports='{}', target={}", rule.rule_num, rule.protocol, rule.destination_ports, rule.translation_address),
        );
        finding.context.push(("Target Server", target.name.to_string()));
        finding.context.push(("Discovered Rule", rule.rule_num.to_string()));
        finding.context.push(("Translation IP", rule.translation_address.clone()));
        finding.context.push(("Ports Bound", rule.destination_ports.clone()));
        ctx.emit(finding);
    }

    // 2. Report Port Drift
    for (target, rule, reason) in &audit_outcome.drifted_targets {
        let mut finding = Finding::new(
            Severity::High,
            "router_nat",
            format!("Port Drift on {}: Rule {} target {} ({})", target.name, rule.rule_num, rule.translation_address, reason),
            format!("Expected ports: {:?}, configured: '{}'", target.expected_ports, rule.destination_ports),
        );
        finding.context.push(("Target Server", target.name.to_string()));
        finding.context.push(("Rule Number", rule.rule_num.to_string()));
        finding.context.push(("Configured Ports", rule.destination_ports.clone()));
        finding.recommendation = "Run 'Restore NAT Baseline on Router' in Tab [4] to restore standard ports.".into();
        ctx.emit(finding);
    }

    // 3. Report Duplicate Conflicts
    for (target, rules) in &audit_outcome.duplicate_conflicts {
        let rule_nums: Vec<String> = rules.iter().map(|r| r.rule_num.to_string()).collect();
        let mut finding = Finding::new(
            Severity::High,
            "router_nat",
            format!("Conflicting Duplicate DNAT Rules for {}: Rules [{}] both point to target", target.name, rule_nums.join(", ")),
            format!("Multiple rules found pointing to {}: {:?}", target.internal_ip, rule_nums),
        );
        finding.context.push(("Target Server", target.name.to_string()));
        finding.context.push(("Conflicting Rules", rule_nums.join(", ")));
        finding.recommendation = "Run 'Restore NAT Baseline on Router' in Tab [4] to wipe duplicate rules.".into();
        ctx.emit(finding);
    }

    // 4. Report Missing Rules
    for target in &audit_outcome.missing_targets {
        let mut finding = Finding::new(
            Severity::Critical,
            "router_nat",
            format!("Missing Scored DNAT: {} ({} has no inbound translation rule!)", target.name, target.internal_ip),
            format!("Scored service '{}' is completely unreachable from WAN upstream.", target.name),
        );
        finding.context.push(("Missing Target", target.name.to_string()));
        finding.context.push(("Expected IP", target.internal_ip.to_string()));
        finding.recommendation = "Navigate to Tab [4] Router Operations and run 'Restore NAT Baseline on Router'.".into();
        ctx.emit(finding);
    }

    // 5. Report Rogue Rules
    for rogue in &audit_outcome.rogue_rules {
        let mut finding = Finding::new(
            Severity::Critical,
            "router_nat",
            format!("Rogue Destination NAT Rule Detected: Rule {} -> {}:{}", rogue.rule_num, rogue.translation_address, rogue.destination_ports),
            format!("Rule {} translates to non-competition target '{}'", rogue.rule_num, rogue.translation_address),
        );
        finding.context.push(("Rogue Rule", rogue.rule_num.to_string()));
        finding.context.push(("Target IP", rogue.translation_address.clone()));
        finding.recommendation = "Delete rogue destination NAT rule immediately: delete nat destination rule <num>.".into();
        ctx.emit(finding);
    }

    // 6. Outbound PAT Status
    if has_outbound_pat {
        let mut finding = Finding::new(
            Severity::Medium,
            "router_nat",
            "Outbound PAT (Masquerade) is ENABLED on eth0: LAN hosts can egress to WAN",
            "CCDC Best Practice: Keep outbound PAT disabled to deny reverse shells unless explicitly needed.",
        );
        finding.context.push(("Status", "Outbound PAT Active".into()));
        finding.recommendation = "Disable outbound PAT via Tab [4] Restore NAT Baseline (default).".into();
        ctx.emit(finding);
    } else {
        let mut finding = Finding::new(
            Severity::Info,
            "router_nat",
            "Outbound PAT is DISABLED: Anti-reverse-shell egress protection active",
            "Workstations cannot establish direct outbound WAN connections.",
        );
        finding.context.push(("Status", "Egress Protection Active".into()));
        ctx.emit(finding);
    }
}

// ==============================================================================
// 14. Systemd Services vs. VyOS Curated Whitelist
// ==============================================================================
/// Approved baseline of standard VyOS router daemons and services.
pub const ROUTER_WHITELIST: &[&str] = &[
    "vyos-router", "vyos-configd", "vyos-hostkey", "vyos-telegraf",
    "frr", "zebra", "bgpd", "ospfd", "ospf6d", "ripd", "ripngd", "staticd",
    "bfdd", "isisd", "fabricd", "vrrpd", "pimd", "pim6d", "eigrpd",
    "nftables", "conntrackd", "keepalived", "lldpd",
    "isc-dhcp-server", "dhcpd", "kea-dhcp4", "kea-dhcp6", "dhclient", "dhcpcd",
    "pdns-recursor", "dnsmasq", "ddclient",
    "snmpd", "chrony", "chronyd", "ntp", "ntpd", "rsyslog", "syslog",
    "systemd-journald", "systemd-udevd", "udev", "kmod", "irqbalance",
    "haveged", "rngd", "open-vm-tools", "vmtoolsd", "qemu-guest-agent",
    "ssh", "sshd", "getty", "serial-getty", "autovt", "console-getty",
];

/// Blacklist of prohibited or high-risk services on a dedicated router.
pub const ROUTER_BLACKLIST: &[&str] = &[
    "telnet", "telnetd", "tftp", "tftpd-hpa", "rsh", "rlogin", "rexec",
    "apache2", "nginx", "httpd", "vyos-http-api", "lighttpd",
    "mysql", "mariadb", "postgresql", "mongod", "redis", "redis-server",
    "cups", "cups-browsed", "avahi-daemon", "bluetooth",
    "smbd", "nmbd", "nfs-server", "rpcbind",
];

/// Module 14: Audits running systemd units against the curated VyOS whitelist.
pub fn scan_services_whitelist(ctx: &DefenderContext) {
    ctx.progress("[*] Module 14: Auditing Running Systemd Units against ROUTER_ALLOW Whitelist...");

    let mut running_services = Vec::new();
    if let Some(out) = run_cmd_output("systemctl", &["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"]) {
        for line in out.lines() {
            if let Some(unit) = line.split_whitespace().next() {
                let name = unit.strip_suffix(".service").unwrap_or(unit);
                running_services.push(name.to_string());
            }
        }
    }

    let mut rogue_found = false;
    for svc in &running_services {
        if ROUTER_BLACKLIST.contains(&svc.as_str()) {
            rogue_found = true;
            let mut finding = Finding::new(
                Severity::Critical,
                "router_services_whitelist",
                format!("BLACK-LISTED SERVICE RUNNING: '{}'", svc),
                format!("Service '{}' is on the critical router blacklist.", svc),
            );
            finding.context.push(("Command Executed", "systemctl list-units --type=service --state=running".into()));
            finding.context.push(("Relevant Output", format!("{} running [BLACKLISTED]", svc)));
            finding.context.push(("Service Name", svc.clone()));
            finding.context.push(("Policy", "Critical Blacklist".into()));
            finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Disable Unnecessary Services'".into()));
            finding.context.push(("Manual CLI Command", format!("systemctl stop {} && systemctl mask {}", svc, svc)));
            finding.recommendation = "Stop and mask immediately: systemctl stop <svc> && systemctl mask <svc>.".into();
            ctx.emit(finding);
        } else if !ROUTER_WHITELIST.contains(&svc.as_str()) {
            rogue_found = true;
            let mut finding = Finding::new(
                Severity::High,
                "router_services_whitelist",
                format!("Unapproved service running on router: '{}'", svc),
                format!("Service '{}' is not recognized in ROUTER_ALLOW whitelist.", svc),
            );
            finding.context.push(("Command Executed", "systemctl list-units --type=service --state=running".into()));
            finding.context.push(("Relevant Output", format!("{} running [NOT IN ROUTER_ALLOW]", svc)));
            finding.context.push(("Service Name", svc.clone()));
            finding.context.push(("Policy", "Unapproved Daemon".into()));
            finding.context.push(("Remediation Action", "Tab [4] Router Operations -> 'Disable Unnecessary Services'".into()));
            finding.context.push(("Manual CLI Command", format!("systemctl stop {} && systemctl disable {}", svc, svc)));
            finding.recommendation = "Navigate to Tab [4] and run 'Disable Unnecessary Services'.".into();
            ctx.emit(finding);
        }
    }

    if !rogue_found {
        let mut finding = Finding::new(
            Severity::Info,
            "router_services_whitelist",
            format!("Services Whitelist Clean: {} running services verified against ROUTER_ALLOW", running_services.len()),
            "All active services are approved routing daemons.",
        );
        finding.context.push(("Status", "Clean".into()));
        ctx.emit(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HIERARCHICAL_CONFIG: &str = r#"
nat {
    destination {
        rule 42 {
            description "E-Commerce Web"
            destination {
                port "80,443"
            }
            inbound-interface {
                name "eth0"
            }
            protocol "tcp"
            translation {
                address "172.20.240.10"
            }
        }
        rule 77 {
            description "Mail Server"
            destination {
                port "25,143,587,993"
            }
            inbound-interface {
                name "eth0"
            }
            protocol "tcp"
            translation {
                address "172.20.240.15"
            }
        }
        rule 99 {
            description "Splunk SIEM"
            destination {
                port "8000,8089,9997"
            }
            inbound-interface {
                name "eth0"
            }
            protocol "tcp"
            translation {
                address "172.20.240.20"
            }
        }
        rule 105 {
            description "Active Directory"
            destination {
                port "53,88,389,636,5985"
            }
            inbound-interface {
                name "eth0"
            }
            protocol "tcp_udp"
            translation {
                address "172.20.240.100"
            }
        }
        rule 200 {
            description "MSSQL Database"
            destination {
                port "445,1433,3389"
            }
            inbound-interface {
                name "eth0"
            }
            protocol "tcp"
            translation {
                address "172.20.240.120"
            }
        }
    }
    source {
        rule 100 {
            outbound-interface {
                name "eth0"
            }
            translation {
                address "masquerade"
            }
        }
    }
}
"#;

    #[test]
    fn test_parse_all_dest_nat_rules_non_standard_numbers() {
        let rules = parse_all_dest_nat_rules(SAMPLE_HIERARCHICAL_CONFIG);
        assert_eq!(rules.len(), 5);
        let rule_nums: Vec<u32> = rules.iter().map(|r| r.rule_num).collect();
        assert_eq!(rule_nums, vec![42, 77, 99, 105, 200]);

        let r42 = rules.iter().find(|r| r.rule_num == 42).unwrap();
        assert_eq!(r42.translation_address, "172.20.240.10");
        assert_eq!(r42.destination_ports, "80,443");
        assert_eq!(r42.protocol, "tcp");
        assert_eq!(r42.inbound_interface, "eth0");
    }

    #[test]
    fn test_audit_nat_rules_by_ip_valid_baseline() {
        let rules = parse_all_dest_nat_rules(SAMPLE_HIERARCHICAL_CONFIG);
        let outcome = audit_nat_rules_by_ip(&rules, false);

        assert_eq!(outcome.valid_targets.len(), 5);
        assert!(outcome.drifted_targets.is_empty());
        assert!(outcome.duplicate_conflicts.is_empty());
        assert!(outcome.missing_targets.is_empty());
        assert!(outcome.rogue_rules.is_empty());

        let names: Vec<&str> = outcome.valid_targets.iter().map(|(t, _)| t.name).collect();
        assert!(names.contains(&"E-Commerce Web"));
        assert!(names.contains(&"Mail Server"));
        assert!(names.contains(&"Splunk SIEM"));
        assert!(names.contains(&"Active Directory"));
        assert!(names.contains(&"MSSQL Database"));
    }

    #[test]
    fn test_audit_nat_rules_by_ip_detects_duplicate_conflicts() {
        let conflict_config = r#"
nat {
    destination {
        rule 10 {
            description "Ecom Initial"
            destination { port "80,443" }
            translation { address "172.20.240.10" }
        }
        rule 42 {
            description "Ecom Duplicate"
            destination { port "80,443" }
            translation { address "172.20.240.10" }
        }
    }
}
"#;
        let rules = parse_all_dest_nat_rules(conflict_config);
        let outcome = audit_nat_rules_by_ip(&rules, false);

        assert_eq!(outcome.duplicate_conflicts.len(), 1);
        let (target, conflict_rules) = &outcome.duplicate_conflicts[0];
        assert_eq!(target.name, "E-Commerce Web");
        assert_eq!(conflict_rules.len(), 2);
        assert_eq!(conflict_rules[0].rule_num, 10);
        assert_eq!(conflict_rules[1].rule_num, 42);
    }

    #[test]
    fn test_audit_nat_rules_by_ip_detects_port_drift() {
        let drift_config = r#"
nat {
    destination {
        rule 42 {
            description "Ecom Partial"
            destination { port "80" }
            translation { address "172.20.240.10" }
        }
    }
}
"#;
        let rules = parse_all_dest_nat_rules(drift_config);
        let outcome = audit_nat_rules_by_ip(&rules, false);

        assert_eq!(outcome.drifted_targets.len(), 1);
        let (target, rule, reason) = &outcome.drifted_targets[0];
        assert_eq!(target.name, "E-Commerce Web");
        assert_eq!(rule.rule_num, 42);
        assert!(reason.contains("Port drift"));
    }

    #[test]
    fn test_audit_nat_rules_by_ip_detects_rogue_rules() {
        let rogue_config = r#"
nat {
    destination {
        rule 88 {
            description "Rogue Backdoor"
            destination { port "4444" }
            translation { address "172.20.240.66" }
        }
    }
}
"#;
        let rules = parse_all_dest_nat_rules(rogue_config);
        let outcome = audit_nat_rules_by_ip(&rules, false);

        assert_eq!(outcome.rogue_rules.len(), 1);
        assert_eq!(outcome.rogue_rules[0].rule_num, 88);
        assert_eq!(outcome.rogue_rules[0].translation_address, "172.20.240.66");
    }

    #[test]
    fn test_audit_nat_rules_by_ip_detects_missing_targets() {
        let missing_config = r#"
nat {
    destination {
        rule 10 {
            destination { port "80,443" }
            translation { address "172.20.240.10" }
        }
    }
}
"#;
        let rules = parse_all_dest_nat_rules(missing_config);
        let outcome = audit_nat_rules_by_ip(&rules, false);

        assert_eq!(outcome.missing_targets.len(), 4);
        let missing_names: Vec<&str> = outcome.missing_targets.iter().map(|t| t.name).collect();
        assert!(missing_names.contains(&"Mail Server"));
        assert!(missing_names.contains(&"Splunk SIEM"));
        assert!(missing_names.contains(&"Active Directory"));
        assert!(missing_names.contains(&"MSSQL Database"));
    }
}
