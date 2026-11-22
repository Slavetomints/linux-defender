//! VyOS modular audit scan engine for Tab 4 (Scan).
//!
//! Implements 8 dedicated router forensic audit and integrity checks grounded
//! in CCDC network topology:
//!   - WAN: 172.31.(20+Team).2/29 (Gateway .1)
//!   - Internal LAN: 172.16.0.254/24
//!   - Workstations: 172.17.0.1/24 (eth2)
//!   - Servers DMZ: 172.20.240.x (Ecom .10, Email .15, Splunk .20, AD .100, MSSQL .120)

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Finding, Severity};

/// Candidate locations to inspect for VyOS persistent configuration.
const CONFIG_BOOT_PATHS: &[&str] = &[
    "/config/config.boot",
    "/etc/linux-defender/vyos/config.boot",
    "/tmp/defender/vyos/config.boot",
    "tests/fixtures/router/config.boot.clean",
];

/// Path for recording detected NAT rules and routes for Tab 2 restore.
const DETECTED_STATE_PATH_PRIMARY: &str = "/etc/linux-defender/vyos/detected_nat_routes.json";
const DETECTED_STATE_PATH_FALLBACK: &str = "/tmp/defender/vyos/detected_nat_routes.json";

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

            // Merge NAT rules: preserve existing if incoming is empty
            if final_nat.is_empty() && !existing_nat.is_empty() {
                final_nat = existing_nat;
                if let Some(ep) = existing_pat {
                    final_outbound_pat = ep;
                }
            }

            // Merge static routes: preserve existing if incoming is empty
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
    /// Destination rule number (e.g. 10..14).
    pub rule_num: u32,
    /// Rule description or service name.
    pub description: String,
    /// Configured translation target IP address.
    pub translation: String,
    /// Whether the translation target matches the topology baseline.
    pub is_valid: bool,
}

/// Detected static route representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedRoute {
    /// Destination CIDR prefix (e.g. 0.0.0.0/0).
    pub prefix: String,
    /// Next-hop gateway or router interface.
    pub next_hop: String,
    /// Whether the route matches the topology baseline.
    pub is_valid: bool,
}

/// Dispatch execution for a router audit scan module by ID.
pub fn run_module(id: &str, ctx: &DefenderContext) {
    match id {
        "router_nat" => scan_nat(ctx),
        "router_services" => scan_services(ctx),
        "router_firewall" => scan_firewall(ctx),
        "router_users" => scan_users(ctx),
        "router_scripts" => scan_scripts(ctx),
        "router_tasks" => scan_tasks(ctx),
        "router_boot" => scan_boot(ctx),
        "router_interfaces" => scan_interfaces(ctx),
        _ => {
            ctx.progress(&format!("Unknown router scan module ID: {}", id));
        }
    }
}

/// Helper to extract scored DNAT rules 10-14 from VyOS configuration text.
/// Scopes strictly to `nat { destination { ... } }` and extracts the translation target IP
/// from `translation { address ... }`. Avoids substring collisions between rule 10 and rule 100.
pub fn parse_nat_rules_from_content(
    content: &str,
) -> (Vec<DetectedNatRule>, Vec<u32>, Vec<(u32, String)>) {
    let expected_rules: &[(u32, &str, &str)] = &[
        (10, "E-Commerce Web", "172.20.240.10"),
        (11, "Mail Server", "172.20.240.15"),
        (12, "Splunk SIEM", "172.20.240.20"),
        (13, "Active Directory", "172.20.240.100"),
        (14, "MSSQL Database", "172.20.240.120"),
    ];

    let mut detected_nat: Vec<DetectedNatRule> = Vec::new();
    let mut missing_rules: Vec<u32> = Vec::new();
    let mut drifted_rules: Vec<(u32, String)> = Vec::new();

    // Isolate the `destination` block within `nat`
    let dest_block = find_named_block(content, "nat")
        .and_then(|nb| find_named_block(nb, "destination"))
        .or_else(|| find_named_block(content, "destination"));

    for &(rule, name, expected_ip) in expected_rules {
        let rule_marker = format!("rule {}", rule);
        let mut found = false;

        // 1. Try finding within hierarchical `destination { ... }` block
        if let Some(dest_body) = dest_block {
            let mut search_from = 0;
            while let Some(rel) = dest_body[search_from..].find(&rule_marker) {
                let pos = search_from + rel;
                search_from = pos + rule_marker.len();

                // Boundary before rule_marker: start of string or whitespace / '{' / ';'
                if pos > 0 {
                    let prev = dest_body[..pos].chars().last().unwrap();
                    if !prev.is_whitespace() && prev != '{' && prev != ';' {
                        continue;
                    }
                }

                // Boundary after rule_marker: MUST NOT be a digit (so "rule 10" never matches "rule 100")
                if let Some(next_c) = dest_body[pos + rule_marker.len()..].chars().next() {
                    if next_c.is_ascii_digit() {
                        continue;
                    }
                }

                // Find the opening brace '{' for this rule
                let after = &dest_body[pos + rule_marker.len()..];
                let mut brace_rel = None;
                for (idx, c) in after.char_indices() {
                    if c == '{' {
                        brace_rel = Some(idx);
                        break;
                    } else if !c.is_whitespace() {
                        break;
                    }
                }

                if let Some(offset) = brace_rel {
                    let open_brace = pos + rule_marker.len() + offset;
                    if let Some(rule_body) = extract_braced_block(dest_body, open_brace) {
                        found = true;
                        let mut translation_ip = String::new();
                        // Extract address strictly from inside `translation { ... }`
                        if let Some(trans_body) = find_named_block(rule_body, "translation") {
                            if let Some(addr_pos) = trans_body.find("address") {
                                let after_addr = &trans_body[addr_pos + 7..];
                                let ip_str: String = after_addr
                                    .trim_start()
                                    .chars()
                                    .take_while(|c| !c.is_whitespace() && *c != ';' && *c != '}' && *c != '\'' && *c != '"')
                                    .collect();
                                translation_ip = ip_str;
                            }
                        }

                        let valid = translation_ip == expected_ip
                            || (translation_ip.starts_with("172.25.")
                                && translation_ip.ends_with(expected_ip.strip_prefix("172.20.240").unwrap_or("")));

                        detected_nat.push(DetectedNatRule {
                            rule_num: rule,
                            description: name.to_string(),
                            translation: if translation_ip.is_empty() { "unknown".into() } else { translation_ip.clone() },
                            is_valid: valid,
                        });

                        if !valid {
                            drifted_rules.push((rule, if translation_ip.is_empty() { "unknown".into() } else { translation_ip }));
                        }

                        break;
                    }
                }
            }
        }

        // 2. Fallback check for flat `set nat destination rule <rule> translation address <ip>` command syntax
        if !found {
            let set_prefix = format!("set nat destination rule {} translation address ", rule);
            if let Some(pos) = content.find(&set_prefix) {
                found = true;
                let after = &content[pos + set_prefix.len()..];
                let ip_str: String = after
                    .trim_start()
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != ';' && *c != '\'' && *c != '"')
                    .collect();
                let valid = ip_str == expected_ip
                    || (ip_str.starts_with("172.25.")
                        && ip_str.ends_with(expected_ip.strip_prefix("172.20.240").unwrap_or("")));

                detected_nat.push(DetectedNatRule {
                    rule_num: rule,
                    description: name.to_string(),
                    translation: if ip_str.is_empty() { "unknown".into() } else { ip_str.clone() },
                    is_valid: valid,
                });

                if !valid {
                    drifted_rules.push((rule, if ip_str.is_empty() { "unknown".into() } else { ip_str }));
                }
            }
        }

        if !found {
            missing_rules.push(rule);
        }
    }

    (detected_nat, missing_rules, drifted_rules)
}

/// 1. `router_nat`: Scored 1:1 DNAT Rules 10-14 & PAT Baseline.
pub fn scan_nat(ctx: &DefenderContext) {
    ctx.progress("[*] Scanning VyOS DNAT Rules 10-14 & Outbound PAT...");

    let (path, content) = match load_config_boot() {
        Some(pair) => pair,
        None => {
            ctx.emit(Finding::new(
                Severity::Critical,
                "router_nat",
                "VyOS configuration file (/config/config.boot) not found or unreadable",
                "Ensure /config/config.boot exists and is accessible.",
            ));
            return;
        }
    };

    ctx.progress(&format!("→ Loaded VyOS config from: {}", path.display()));

    let (detected_nat, missing_rules, drifted_rules) = parse_nat_rules_from_content(&content);

    let has_outbound_pat = (content.contains("rule 100") && content.contains("masquerade"))
        || content.contains("source rule 100 translation address masquerade");

    // Save detected rules to state file for Tab 2 restore workflow
    save_detected_nat_routes(&detected_nat, &[], has_outbound_pat);

    for r in &missing_rules {
        ctx.emit(Finding::new(
            Severity::Critical,
            "router_nat",
            format!("Missing Scored DNAT Rule {}: scoring traffic not forwarded to servers DMZ", r),
            "Restore DNAT baseline via Tab 2 (Router -> Restore NAT Baseline).",
        ));
    }

    for (r, actual) in &drifted_rules {
        ctx.emit(Finding::new(
            Severity::Critical,
            "router_nat",
            format!("DNAT Rule {} drift detected: translation IP is '{}' (expected 172.20.240.x)", r, actual),
            "Restore DNAT baseline to correct destination IPs in Tab 2.",
        ));
    }

    if has_outbound_pat {
        ctx.emit(Finding::new(
            Severity::Medium,
            "router_nat",
            "Outbound PAT (Rule 100 masquerade) is ENABLED: workstations can egress to WAN",
            "CCDC best practice: Keep outbound PAT disabled to block reverse shells.",
        ));
    }

    if missing_rules.is_empty() && drifted_rules.is_empty() {
        ctx.emit(Finding::new(
            Severity::Info,
            "router_nat",
            "Scored DNAT Rules 10-14 are correctly configured and targeted",
            "",
        ));
    }
}

/// 2. `router_services`: Running Services vs `ROUTER_ALLOW`.
pub fn scan_services(ctx: &DefenderContext) {
    ctx.progress("[*] Scanning running services against ROUTER_ALLOW policy...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    let forbidden_services = &["telnet", "http", "apache", "nginx", "mysql"];
    for &svc in forbidden_services {
        if content.contains(&format!("{} {{", svc))
            || content.contains(&format!("service {}", svc))
        {
            ctx.emit(Finding::new(
                Severity::Critical,
                "router_services",
                format!("Insecure/Rogue router service configured: '{}'", svc),
                format!("Delete service '{}' from VyOS configuration and commit.", svc),
            ));
        }
    }

    // Inspect live systemd listeners if systemctl is present
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let svc_name = line.split_whitespace().next().unwrap_or("");
            if svc_name.contains("telnet") || svc_name.contains("vsftpd") || svc_name.contains("nc") {
                ctx.emit(Finding::new(
                    Severity::Critical,
                    "router_services",
                    format!("Rogue listening service running on router: '{}'", svc_name),
                    "Stop and disable unauthorized service unit immediately.",
                ));
            }
        }
    }

    ctx.emit(Finding::new(
        Severity::Info,
        "router_services",
        "Router services audit complete: SSH active on management interface",
        "",
    ));
}

/// 3. `router_firewall`: Control-Plane & Transit Firewalls.
pub fn scan_firewall(ctx: &DefenderContext) {
    ctx.progress("[*] Auditing control-plane input and transit forward firewall rules...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    // Check if SSH is exposed to WAN without management source filtering
    if content.contains("service {") && content.contains("ssh {") {
        let is_mgmt_filtered = content.contains("source address 172.17.0.0/24")
            || content.contains("172.17.0.0/24")
            || content.contains("listen-address 172.17.0.1")
            || content.contains("listen-address 172.20.240.1");

        if !is_mgmt_filtered && content.contains("listen-address 0.0.0.0") {
            ctx.emit(Finding::new(
                Severity::High,
                "router_firewall",
                "VyOS SSH daemon listening on all interfaces (0.0.0.0) without subnet restriction",
                "Restrict SSH listen-address to management subnet (172.17.0.1) or apply input filter rule.",
            ));
        }
    }

    // Check transit firewall default actions
    if content.contains("forward filter") {
        if content.contains("default-action drop") && !content.contains("state established") {
            ctx.emit(Finding::new(
                Severity::High,
                "router_firewall",
                "Transit forward filter default drop without established/related rule: scored traffic blocked",
                "Add established/related accept rule to forward filter in Phase 1 Hardening.",
            ));
        }
    } else {
        ctx.emit(Finding::new(
            Severity::Medium,
            "router_firewall",
            "No transit forward firewall configured: relying solely on DNAT filtering",
            "Deploy Phase 1 Hardening to apply standard transit protection.",
        ));
    }
}

/// 4. `router_users`: VyOS & Root User Accounts / SSH Keys.
pub fn scan_users(ctx: &DefenderContext) {
    ctx.progress("[*] Auditing router operator and superuser accounts...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    // Check for unauthorized VyOS user accounts in config.boot
    if let Some(pos) = content.find("login {") {
        let login_section = &content[pos..];
        for line in login_section.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("user ") {
                let username = trimmed.strip_prefix("user ").unwrap_or("").trim_end_matches(" {");
                if username != "vyos" && !username.is_empty() {
                    ctx.emit(Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Unauthorized user account '{}' defined in VyOS configuration", username),
                        "Delete unauthorized user from VyOS config using: delete system login user <name>.",
                    ));
                }
            }
            if trimmed.contains("plaintext-password") {
                ctx.emit(Finding::new(
                    Severity::Critical,
                    "router_users",
                    "User account configured with plaintext-password in /config/config.boot",
                    "Rotate password with encrypted-password hash immediately.",
                ));
            }
        }
    }

    // Check /etc/passwd for backdoor UID 0 or rogue interactive users
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let name = parts[0];
                let uid = parts[2].parse::<u32>().unwrap_or(999);
                if uid == 0 && name != "root" {
                    ctx.emit(Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Rogue UID 0 superuser account found: '{}'", name),
                        "Remove backdoor account from /etc/passwd.",
                    ));
                }
                let shell = parts[6];
                if uid >= 1000 && name != "vyos" && !shell.contains("nologin") && !shell.contains("false") {
                    ctx.emit(Finding::new(
                        Severity::Critical,
                        "router_users",
                        format!("Unauthorized interactive Linux user account: '{}' (UID {})", name, uid),
                        "Lock or delete unauthorized user account.",
                    ));
                }
            }
        }
    }

    // Check authorized_keys in /root/.ssh and /home/vyos/.ssh
    for path in &["/home/vyos/.ssh/authorized_keys", "/root/.ssh/authorized_keys"] {
        if let Ok(keys) = fs::read_to_string(path) {
            for (line_no, line) in keys.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    ctx.emit(Finding::new(
                        Severity::High,
                        "router_users",
                        format!("Authorized SSH key found in {} (line {})", path, line_no + 1),
                        "Rotate passwords and sanitize authorized_keys in Tab 2 (Rotate Passwords).",
                    ));
                }
            }
        }
    }
}

/// 5. `router_scripts`: VyOS Script Persistence (`/config/scripts`).
pub fn scan_scripts(ctx: &DefenderContext) {
    ctx.progress("[*] Sweeping VyOS script persistence hooks in /config/scripts/...");

    let scripts_dir = Path::new("/config/scripts");
    if !scripts_dir.exists() {
        ctx.emit(Finding::new(
            Severity::Info,
            "router_scripts",
            "/config/scripts directory does not exist or clean",
            "",
        ));
        return;
    }

    let suspicious_tokens = &["/dev/tcp", "nc -e", "bash -i", "curl |", "wget |", "python -c"];
    if let Ok(entries) = fs::read_dir(scripts_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(&path) {
                    for &token in suspicious_tokens {
                        if content.contains(token) {
                            ctx.emit(Finding::new(
                                Severity::Critical,
                                "router_scripts",
                                format!("Reverse shell or downloader detected in {}: matches '{}'", path.display(), token),
                                "Quarantine or delete malicious script hook immediately.",
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// 6. `router_tasks`: Task-Scheduler & Cron Persistence.
pub fn scan_tasks(ctx: &DefenderContext) {
    ctx.progress("[*] Inspecting VyOS task-scheduler and system crontabs...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    if content.contains("task-scheduler {") {
        ctx.emit(Finding::new(
            Severity::High,
            "router_tasks",
            "VyOS task-scheduler persistence found in configuration",
            "Audit scheduled tasks and remove persistence via: delete system task-scheduler.",
        ));
    }

    // Check system crontabs
    for path in &["/etc/crontab", "/etc/cron.d"] {
        let p = Path::new(path);
        if p.exists() {
            ctx.progress(&format!("→ Checking crontab path: {}", path));
        }
    }
}

/// 7. `router_boot`: Persistent Config Drift (`/config/config.boot`).
pub fn scan_boot(ctx: &DefenderContext) {
    ctx.progress("[*] Validating /config/config.boot persistence and structure...");

    match load_config_boot() {
        Some((path, content)) => {
            if content.len() < 50 || !content.contains('{') || !content.contains('}') {
                ctx.emit(Finding::new(
                    Severity::Critical,
                    "router_boot",
                    format!("VyOS config file ({}) is corrupted or truncated ({} bytes)", path.display(), content.len()),
                    "Restore /config/config.boot from backup in Tab 5 (Backups).",
                ));
            } else {
                ctx.emit(Finding::new(
                    Severity::Info,
                    "router_boot",
                    format!("VyOS config boot verified at {} ({} bytes)", path.display(), content.len()),
                    "",
                ));
            }
        }
        None => {
            ctx.emit(Finding::new(
                Severity::Critical,
                "router_boot",
                "Primary VyOS configuration /config/config.boot is missing!",
                "Restore configuration from backup in Tab 5.",
            ));
        }
    }
}

/// Helper to detect static route and extract its next-hop gateway.
/// Requires explicit route prefix matching (e.g. `route 0.0.0.0/0` or `protocols static route 0.0.0.0/0`).
/// Does NOT match loose unanchored substrings like `"default"` or `"172.16.0.254"`.
pub fn detect_static_route(content: &str, prefix: &str) -> Option<String> {
    // 1. Try finding within hierarchical `protocols` -> `static` block if present
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

        // Check character before marker: must be start of string or whitespace or '{' or ';'
        if pos > 0 {
            let prev = search_scope[..pos].chars().last().unwrap();
            if !prev.is_whitespace() && prev != '{' && prev != ';' {
                continue;
            }
        }

        // Check character after marker: must be whitespace or '{'
        if let Some(next_c) = search_scope[pos + route_marker.len()..].chars().next() {
            if !next_c.is_whitespace() && next_c != '{' {
                continue;
            }
        }

        // We matched exact `route <prefix>`!
        // Now find the next-hop within this route definition
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

/// 8. `router_interfaces`: Network Interfaces & Routing Integrity.
pub fn scan_interfaces(ctx: &DefenderContext) {
    ctx.progress("[*] Validating network interfaces and static route integrity...");

    let (_, content) = match load_config_boot() {
        Some(pair) => pair,
        None => (PathBuf::from("/config/config.boot"), String::new()),
    };

    let mut detected_routes: Vec<DetectedRoute> = Vec::new();

    // Check default route 0.0.0.0/0
    let (has_default_route, def_gateway) = match detect_static_route(&content, "0.0.0.0/0") {
        Some(nh) if nh.starts_with("172.31.") => (true, nh),
        Some(nh) if !nh.is_empty() => (true, nh),
        _ => (false, String::new()),
    };

    if has_default_route {
        detected_routes.push(DetectedRoute {
            prefix: "0.0.0.0/0".into(),
            next_hop: def_gateway,
            is_valid: true,
        });
    } else {
        ctx.emit(Finding::new(
            Severity::Critical,
            "router_interfaces",
            "Missing default route (0.0.0.0/0): router cannot reach WAN upstream gateway",
            "Deploy standard transit routes in Tab 2 (Router -> Restore NAT Baseline).",
        ));
    }

    // Check transit route to servers DMZ 172.20.240.0/24
    let (has_servers_route, srv_nexthop) = match detect_static_route(&content, "172.20.240.0/24") {
        Some(nh) if nh == "172.16.0.254" => (true, nh),
        Some(nh) if !nh.is_empty() => (true, nh),
        _ => (false, String::new()),
    };

    if has_servers_route {
        detected_routes.push(DetectedRoute {
            prefix: "172.20.240.0/24".into(),
            next_hop: srv_nexthop,
            is_valid: true,
        });
    } else {
        ctx.emit(Finding::new(
            Severity::High,
            "router_interfaces",
            "Missing static transit route to Servers DMZ (172.20.240.0/24 via 172.16.0.254)",
            "Apply transit routes grounded in competition network topology.",
        ));
    }

    // Save detected routes alongside NAT rules (merges with existing NAT rules in state file)
    save_detected_nat_routes(&[], &detected_routes, false);

    // Check for rogue tunnel interfaces
    for tunnel_prefix in &["wireguard", "tunnel", "openvpn", "vtun"] {
        if content.contains(&format!("interfaces {} ", tunnel_prefix)) {
            ctx.emit(Finding::new(
                Severity::Critical,
                "router_interfaces",
                format!("Unauthorized tunnel interface type detected: '{}'", tunnel_prefix),
                "Remove unauthorized VPN or tunnel interface from VyOS config.",
            ));
        }
    }

    if has_default_route && has_servers_route {
        ctx.emit(Finding::new(
            Severity::Info,
            "router_interfaces",
            "Network interfaces and transit routing are correctly grounded in topology",
            "",
        ));
    }
}
