//! Palo Alto PA-VM firewall XML config audit, API keygen, and drift remediation engine.
//!
//! Provides zero-dependency XML parsing of exported PAN-OS configuration files,
//! auditing against 22 scored CCDC services across 5 internal hosts, detection of
//! public destination mismatches, redundant static NAT rules, disabled scored rules,
//! rogue allow rules, and generation of executable PAN-OS CLI remediation scripts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;

use crate::core::finding::{Action, Finding, Severity, Verdict};
use crate::core::{DefenderContext, DefenderError, Result};

/// Scored host definitions mapping hostnames to private IPs, object names, and scored rules.
#[derive(Debug, Clone)]
pub struct ScoredHostDef {
    /// Host descriptive name.
    pub host_name: &'static str,
    /// Host private IP address.
    pub priv_ip: &'static str,
    /// Known private address object names.
    pub priv_objs: &'static [&'static str],
    /// Known public address object names.
    pub pub_objs: &'static [&'static str],
    /// Scored service identifiers.
    pub services: &'static [&'static str],
    /// Scored rule names in PAN-OS.
    pub rule_names: &'static [&'static str],
    /// Fallback rule names in PAN-OS.
    pub fallback_names: &'static [&'static str],
    /// Canonical private target address object.
    pub default_target: &'static str,
}

/// Curated mapping of the 22 scored services across 5 internal hosts in MWCCDC.
pub const SCORED_HOST_DEFS: &[ScoredHostDef] = &[
    ScoredHostDef {
        host_name: "Rocky Ecom",
        priv_ip: "172.20.240.10",
        priv_objs: &["EcommPrivate", "EcommPriv"],
        pub_objs: &["EcommPublic", "EcommPub"],
        services: &["ecomm-http", "ecomm-https", "ecomm-ping", "ecomm-ssh"],
        rule_names: &["AllowEcomm-AppID"],
        fallback_names: &["AllowEcomm-CustomFallback"],
        default_target: "EcommPrivate",
    },
    ScoredHostDef {
        host_name: "Ubuntu Email",
        priv_ip: "172.20.240.15",
        priv_objs: &["EmailPrivate", "EmailPriv"],
        pub_objs: &["EmailPublic", "EmailPub"],
        services: &[
            "webmail-smtp",
            "webmail-pop3",
            "webmail-imap",
            "webmail-roundcube",
            "webmail-ssh",
            "webmail-ping",
        ],
        rule_names: &["AllowEmail-AppID"],
        fallback_names: &["AllowEmail-CustomFallback"],
        default_target: "EmailPrivate",
    },
    ScoredHostDef {
        host_name: "Debian Splunk",
        priv_ip: "172.20.240.20",
        priv_objs: &["SplunkPrivate", "SplunkPriv"],
        pub_objs: &["SplunkPublic", "SplunkPub"],
        services: &[
            "splunk-ssh",
            "splunk-web",
            "splunk-mgmt",
            "splunk-query",
            "splunk-ping",
        ],
        rule_names: &["AllowSplunk-SSH-AppID", "AllowSplunk-WebMgmt-AppID"],
        fallback_names: &["AllowSplunk-CustomFallback"],
        default_target: "SplunkPrivate",
    },
    ScoredHostDef {
        host_name: "2022 AD",
        priv_ip: "172.20.240.100",
        priv_objs: &["ADPrivate", "ADPriv"],
        pub_objs: &["ADPublic", "ADPub"],
        services: &["ad-dns", "ad-ping", "ad-winrm"],
        rule_names: &["AllowAD-AppID"],
        fallback_names: &["AllowAD-CustomFallback"],
        default_target: "ADPrivate",
    },
    ScoredHostDef {
        host_name: "2019 MSSQL",
        priv_ip: "172.20.240.120",
        priv_objs: &["MSSQLPrivate", "MSSQLPriv"],
        pub_objs: &["MSSQLPublic", "MSSQLPub"],
        services: &["mssql-mssql", "mssql-ping", "mssql-rdp", "mssql-smb"],
        rule_names: &["AllowMSSQL-AppID"],
        fallback_names: &["AllowMSSQL-CustomFallback"],
        default_target: "MSSQLPrivate",
    },
];

/// Whitelist of approved baseline security rules in PAN-OS.
pub const BASELINE_APPROVED_RULES: &[&str] = &[
    "KillReverseShells",
    "AllowICMP",
    "AllowNTPOutbound",
    "AllowDNSOutbound-AppID",
    "AllowDNSOutbound-CustomFallback",
    "BlockUnauthorizedDNS",
    "AllowInternetOutbound-AppID",
    "AllowInternetOutbound-CustomFallback",
    "AllowEcomm-AppID",
    "AllowEmail-AppID",
    "AllowSplunk-SSH-AppID",
    "AllowSplunk-WebMgmt-AppID",
    "AllowAD-AppID",
    "AllowMSSQL-AppID",
    "AllowNTP-To-AD-AppID",
    "AllowEcomm-CustomFallback",
    "AllowEmail-CustomFallback",
    "AllowSplunk-CustomFallback",
    "AllowAD-CustomFallback",
    "AllowMSSQL-CustomFallback",
    "AllowNTP-To-AD-CustomFallback",
    "AllowIntrazoneLAN",
    "DENYINBOUND",
    "DENYOUTBOUND",
    "DENYANYANY",
];

/// Redundant NAT rule names that conflict with upstream VyOS DNAT.
pub const REDUNDANT_NAT_NAMES: &[&str] = &[
    "Ecomm-StaticNAT",
    "Email-StaticNAT",
    "Splunk-StaticNAT",
    "AD-StaticNAT",
    "MSSQL-StaticNAT",
    "LAN-OutboundPAT",
];

/// Required scored rules that must exist in the running configuration.
pub const REQUIRED_SCORED_RULES: &[&str] = &[
    "AllowICMP",
    "AllowEcomm-AppID",
    "AllowEmail-AppID",
    "AllowSplunk-SSH-AppID",
    "AllowSplunk-WebMgmt-AppID",
    "AllowAD-AppID",
    "AllowMSSQL-AppID",
];

/// Standard data-plane interfaces defined for MWCCDC topology.
pub const STANDARD_INTERFACES: &[&str] = &["ethernet1/2", "ethernet1/3"];

/// Standard security zones defined for MWCCDC topology.
pub const STANDARD_ZONES: &[&str] = &["External", "Internal"];

/// Command-line arguments for Palo Alto firewall mode.
#[derive(Args, Debug, Default, Clone)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Audit a local exported PAN-OS XML configuration file.
    #[arg(long, value_name = "FILE")]
    pub audit_xml: Option<PathBuf>,

    /// Perform a live XML API audit against the firewall over HTTPS.
    #[arg(long)]
    pub audit_api: bool,

    /// Generate a PAN-OS XML API key and test reachability.
    #[arg(long)]
    pub keygen: bool,

    /// Display setup instructions for API keygen and administrator configuration.
    #[arg(long)]
    pub instructions: bool,

    /// Palo Alto management IP or hostname (default: 172.20.240.200).
    #[arg(long, default_value = "172.20.240.200")]
    pub host: String,

    /// Palo Alto management port (default: 443).
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Management username for API keygen (default: api-admin).
    #[arg(long)]
    pub user: Option<String>,

    /// Management password for API keygen (prompted securely if omitted).
    #[arg(long)]
    pub pass: Option<String>,

    /// PAN-OS XML API key for authenticated API queries.
    #[arg(long)]
    pub api_key: Option<String>,

    /// Compare running configuration against a known-good baseline XML file.
    #[arg(long, value_name = "FILE")]
    pub diff_baseline: Option<PathBuf>,

    /// Output path for generated PAN-OS CLI remediation script.
    #[arg(long, value_name = "FILE")]
    pub out_remediation: Option<PathBuf>,

    /// Automatically apply remediations via live XML API (requires confirmation).
    #[arg(long)]
    pub auto_remediate: bool,

    /// CCDC Team number (1-20, or 0 for practice) to calculate public IP subnets.
    #[arg(long)]
    pub team: Option<u8>,
}

/// A node in the parsed XML tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlNode {
    /// Tag name of the element.
    pub tag: String,
    /// Attribute map.
    pub attributes: BTreeMap<String, String>,
    /// Inner text of the element trimmed of leading/trailing whitespace.
    pub text: String,
    /// Child elements.
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// Create a new empty XML element node.
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: BTreeMap::new(),
            text: String::new(),
            children: Vec::new(),
        }
    }

    /// Retrieve attribute value by key.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    /// Retrieve the `name` attribute value.
    pub fn name(&self) -> Option<&str> {
        self.attr("name")
    }

    /// Find first direct child element matching `tag`.
    pub fn child(&self, tag: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.tag == tag)
    }

    /// Find all direct children matching `tag`.
    pub fn children_named(&self, tag: &str) -> Vec<&XmlNode> {
        self.children.iter().filter(|c| c.tag == tag).collect()
    }

    /// Extract member values from `<member>...</member>` children or fallback to direct text.
    pub fn member_values(&self) -> Vec<String> {
        let members: Vec<String> = self
            .children
            .iter()
            .filter(|c| c.tag == "member")
            .map(|c| c.text.clone())
            .filter(|s| !s.is_empty())
            .collect();
        if !members.is_empty() {
            members
        } else if !self.text.is_empty() {
            vec![self.text.clone()]
        } else {
            Vec::new()
        }
    }

    /// Find all nodes recursively matching `tag`.
    pub fn find_all_deep<'a>(&'a self, tag: &str) -> Vec<&'a XmlNode> {
        let mut results = Vec::new();
        self.collect_deep(tag, &mut results);
        results
    }

    /// Internal recursive traversal helper.
    fn collect_deep<'a>(&'a self, tag: &str, results: &mut Vec<&'a XmlNode>) {
        if self.tag == tag {
            results.push(self);
        }
        for child in &self.children {
            child.collect_deep(tag, results);
        }
    }

    /// Parse raw XML string into an `XmlNode` root tree without external crates.
    pub fn parse(input: &str) -> std::result::Result<Self, String> {
        let mut chars = input.chars().peekable();
        let mut stack: Vec<XmlNode> = Vec::new();
        let mut root: Option<XmlNode> = None;

        while let Some(&ch) = chars.peek() {
            if ch == '<' {
                chars.next(); // consume '<'
                if let Some(&next) = chars.peek() {
                    if next == '?' {
                        // XML declaration <? ... ?>
                        chars.next();
                        while let Some(c) = chars.next() {
                            if c == '?' && chars.peek() == Some(&'>') {
                                chars.next();
                                break;
                            }
                        }
                    } else if next == '!' {
                        chars.next();
                        if chars.peek() == Some(&'-') {
                            chars.next();
                            if chars.peek() == Some(&'-') {
                                chars.next();
                                // Comment <!-- ... -->
                                while let Some(c) = chars.next() {
                                    if c == '-' && chars.peek() == Some(&'-') {
                                        chars.next();
                                        if chars.peek() == Some(&'>') {
                                            chars.next();
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            // CDATA or DOCTYPE <! ... >
                            let mut depth = 1;
                            while let Some(c) = chars.next() {
                                if c == '<' {
                                    depth += 1;
                                } else if c == '>' {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    } else if next == '/' {
                        // Closing tag </tag>
                        chars.next();
                        let mut close_tag = String::new();
                        while let Some(&c) = chars.peek() {
                            if c == '>' {
                                chars.next();
                                break;
                            }
                            if !c.is_whitespace() {
                                close_tag.push(c);
                            }
                            chars.next();
                        }
                        if stack.is_empty() {
                            return Err(format!(
                                "Unexpected closing tag </{}> with empty stack",
                                close_tag
                            ));
                        }
                        let completed_node = stack.pop().unwrap();
                        if completed_node.tag != close_tag {
                            return Err(format!(
                                "Mismatched closing tag: expected </{}>, found </{}>",
                                completed_node.tag, close_tag
                            ));
                        }
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(completed_node);
                        } else {
                            root = Some(completed_node);
                        }
                    } else {
                        // Open tag or self-closing tag
                        let (tag, attributes, self_closing) = parse_tag_details(&mut chars)?;
                        let new_node = XmlNode {
                            tag,
                            attributes,
                            text: String::new(),
                            children: Vec::new(),
                        };
                        if self_closing {
                            if let Some(parent) = stack.last_mut() {
                                parent.children.push(new_node);
                            } else {
                                root = Some(new_node);
                            }
                        } else {
                            stack.push(new_node);
                        }
                    }
                }
            } else {
                // Text content between tags
                let mut text = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '<' {
                        break;
                    }
                    text.push(c);
                    chars.next();
                }
                let decoded = decode_entities(text.trim());
                if !decoded.is_empty() {
                    if let Some(current) = stack.last_mut() {
                        if !current.text.is_empty() {
                            current.text.push(' ');
                        }
                        current.text.push_str(&decoded);
                    }
                }
            }
        }

        if !stack.is_empty() {
            return Err(format!(
                "Unclosed tags remaining on stack: {:?}",
                stack.iter().map(|n| &n.tag).collect::<Vec<_>>()
            ));
        }

        root.ok_or_else(|| "Empty XML document".to_string())
    }
}

/// Helper to decode standard XML entities.
fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '&' {
            let mut entity = String::new();
            while let Some(&next_ch) = chars.peek() {
                if next_ch == ';' {
                    chars.next();
                    break;
                }
                entity.push(chars.next().unwrap());
                if entity.len() > 10 {
                    break;
                }
            }
            match entity.as_str() {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ => {
                    out.push('&');
                    out.push_str(&entity);
                    out.push(';');
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Helper to parse tag name and attributes from `<...>` stream.
fn parse_tag_details<I>(
    chars: &mut std::iter::Peekable<I>,
) -> std::result::Result<(String, BTreeMap<String, String>, bool), String>
where
    I: Iterator<Item = char>,
{
    let mut tag = String::new();
    let mut attributes = BTreeMap::new();
    let mut self_closing = false;

    // Read tag name
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '/' || c == '>' {
            break;
        }
        tag.push(c);
        chars.next();
    }

    if tag.is_empty() {
        return Err("Encountered empty tag name".to_string());
    }

    // Read attributes
    loop {
        // Skip whitespace
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        match chars.peek() {
            Some(&'>') => {
                chars.next();
                break;
            }
            Some(&'/') => {
                chars.next();
                if chars.peek() == Some(&'>') {
                    chars.next();
                    self_closing = true;
                    break;
                }
            }
            Some(_) => {
                // Read attribute name
                let mut attr_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '=' || c.is_whitespace() || c == '/' || c == '>' {
                        break;
                    }
                    attr_name.push(c);
                    chars.next();
                }

                // Skip whitespace before '='
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }

                if chars.peek() == Some(&'=') {
                    chars.next(); // consume '='
                    // Skip whitespace after '='
                    while let Some(&c) = chars.peek() {
                        if c.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    let quote = chars.next();
                    if quote == Some('"') || quote == Some('\'') {
                        let quote_char = quote.unwrap();
                        let mut attr_val = String::new();
                        while let Some(c) = chars.next() {
                            if c == quote_char {
                                break;
                            }
                            attr_val.push(c);
                        }
                        attributes.insert(attr_name, decode_entities(&attr_val));
                    } else if let Some(first_char) = quote {
                        let mut attr_val = String::from(first_char);
                        while let Some(&c) = chars.peek() {
                            if c.is_whitespace() || c == '>' || c == '/' {
                                break;
                            }
                            attr_val.push(c);
                            chars.next();
                        }
                        attributes.insert(attr_name, decode_entities(&attr_val));
                    }
                } else if !attr_name.is_empty() {
                    attributes.insert(attr_name, String::new());
                }
            }
            None => {
                return Err("Unexpected EOF while parsing tag attributes".to_string());
            }
        }
    }

    Ok((tag, attributes, self_closing))
}

/// Parsed security rule from PAN-OS XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRule {
    /// Unique rule name (from `<entry name="...">`).
    pub name: String,
    /// Ingress zones.
    pub from: Vec<String>,
    /// Egress zones.
    pub to: Vec<String>,
    /// Source addresses or address groups.
    pub source: Vec<String>,
    /// Destination addresses or address groups.
    pub destination: Vec<String>,
    /// Service definitions.
    pub service: Vec<String>,
    /// Layer 7 App-ID applications.
    pub application: Vec<String>,
    /// Action ("allow", "deny", "drop").
    pub action: String,
    /// Disabled status (`<disabled>yes</disabled>`).
    pub disabled: bool,
}

impl SecurityRule {
    /// Parse a security rule from an XML `<entry>` node.
    pub fn from_xml(entry: &XmlNode) -> Self {
        let name = entry.name().unwrap_or("").to_string();
        let from = entry
            .child("from")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let to = entry
            .child("to")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let source = entry
            .child("source")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let destination = entry
            .child("destination")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let service = entry
            .child("service")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let application = entry
            .child("application")
            .map(|c| c.member_values())
            .unwrap_or_default();
        let action = entry
            .child("action")
            .map(|c| c.text.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "allow".to_string());
        let disabled = entry
            .child("disabled")
            .map(|c| c.text.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        Self {
            name,
            from,
            to,
            source,
            destination,
            service,
            application,
            action,
            disabled,
        }
    }
}

/// Parsed NAT rule from PAN-OS XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    /// Rule name.
    pub name: String,
    /// Disabled status.
    pub disabled: bool,
}

impl NatRule {
    /// Parse a NAT rule from an XML `<entry>` node.
    pub fn from_xml(entry: &XmlNode) -> Self {
        let name = entry.name().unwrap_or("").to_string();
        let disabled = entry
            .child("disabled")
            .map(|c| c.text.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);
        Self { name, disabled }
    }
}

/// Parsed security zone configuration from PAN-OS XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConfig {
    /// Zone name (e.g. "External", "Internal", "untrust").
    pub name: String,
    /// Interfaces assigned to this zone (e.g. ["ethernet1/2"]).
    pub interfaces: Vec<String>,
    /// Zone protection profile name (if configured).
    pub zone_protection_profile: Option<String>,
}

impl ZoneConfig {
    /// Parse a zone configuration from an XML `<entry>` node under `<zone>`.
    pub fn from_xml(entry: &XmlNode) -> Self {
        let name = entry.name().unwrap_or("").to_string();
        let mut interfaces = Vec::new();

        // 1. Check <network> child
        if let Some(net) = entry.child("network") {
            for mode in &["layer3", "layer2", "virtual-wire", "tap"] {
                if let Some(mode_node) = net.child(mode) {
                    for m in mode_node.member_values() {
                        if !interfaces.contains(&m) {
                            interfaces.push(m);
                        }
                    }
                }
            }
            for m in net.member_values() {
                if !interfaces.contains(&m) {
                    interfaces.push(m);
                }
            }
        }

        // 2. Direct <layer3>, <layer2>, etc. under <entry>
        for mode in &["layer3", "layer2", "virtual-wire", "tap"] {
            if let Some(mode_node) = entry.child(mode) {
                for m in mode_node.member_values() {
                    if !interfaces.contains(&m) {
                        interfaces.push(m);
                    }
                }
            }
        }

        // 3. Direct <member> under entry
        for m in entry.member_values() {
            if !interfaces.contains(&m) {
                interfaces.push(m);
            }
        }

        // 4. Zone protection profile
        let zone_protection_profile = entry
            .child("network")
            .and_then(|n| {
                n.child("zone-protection-profile")
                    .or_else(|| n.child("network-profile"))
            })
            .or_else(|| entry.child("zone-protection-profile"))
            .or_else(|| entry.child("network-profile"))
            .map(|n| n.text.trim().to_string())
            .filter(|s| !s.is_empty());

        Self {
            name,
            interfaces,
            zone_protection_profile,
        }
    }
}

/// Parsed physical, aggregate, or logical interface configuration from PAN-OS XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    /// Interface name (e.g. "ethernet1/1", "ethernet1/2", "tunnel.1").
    pub name: String,
    /// Interface type category (e.g. "ethernet", "loopback", "tunnel", "aggregate-ethernet", "vlan").
    pub if_type: String,
    /// Operating mode (e.g. "layer3", "layer2", "virtual-wire", "tap", "ha", "unknown").
    pub mode: String,
    /// Configured IP addresses/CIDRs.
    pub ip_addresses: Vec<String>,
    /// Assigned security zone (resolved from zone member definitions).
    pub zone: Option<String>,
    /// Attached interface management profile (e.g. "ping-only", None if none/detached).
    pub mgmt_profile: Option<String>,
    /// Administrative link-state override or status ("up", "down", "auto").
    pub link_state: Option<String>,
    /// Administrative disabled flag (`<disabled>yes</disabled>`).
    pub disabled: bool,
    /// User comment or description.
    pub comment: Option<String>,
}

impl InterfaceConfig {
    /// Parse an interface configuration from an XML `<entry>` node under `<interface>/<type>`.
    pub fn from_xml(if_type: &str, entry: &XmlNode, zones: &[ZoneConfig]) -> Self {
        let name = entry.name().unwrap_or("").to_string();
        let mut mode = "unknown".to_string();
        let mut ip_addresses = Vec::new();
        let mut mgmt_profile = None;

        if let Some(l3) = entry.child("layer3") {
            mode = "layer3".to_string();
            if let Some(ip_node) = l3.child("ip") {
                for ip_entry in ip_node.children_named("entry") {
                    if let Some(ip_name) = ip_entry.name() {
                        if !ip_addresses.contains(&ip_name.to_string()) {
                            ip_addresses.push(ip_name.to_string());
                        }
                    }
                }
                for m in ip_node.member_values() {
                    if !ip_addresses.contains(&m) {
                        ip_addresses.push(m);
                    }
                }
            }
            if let Some(mp) = l3.child("interface-management-profile") {
                let trimmed = mp.text.trim();
                if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("none") {
                    mgmt_profile = Some(trimmed.to_string());
                }
            }
        } else if entry.child("layer2").is_some() {
            mode = "layer2".to_string();
        } else if entry.child("virtual-wire").is_some() {
            mode = "virtual-wire".to_string();
        } else if entry.child("tap").is_some() {
            mode = "tap".to_string();
        } else if entry.child("ha").is_some() {
            mode = "ha".to_string();
        } else if if_type == "loopback" || if_type == "tunnel" || if_type == "vlan" {
            mode = "layer3".to_string();
            if let Some(ip_node) = entry.child("ip") {
                for ip_entry in ip_node.children_named("entry") {
                    if let Some(ip_name) = ip_entry.name() {
                        if !ip_addresses.contains(&ip_name.to_string()) {
                            ip_addresses.push(ip_name.to_string());
                        }
                    }
                }
                for m in ip_node.member_values() {
                    if !ip_addresses.contains(&m) {
                        ip_addresses.push(m);
                    }
                }
            }
            if let Some(mp) = entry.child("interface-management-profile") {
                let trimmed = mp.text.trim();
                if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("none") {
                    mgmt_profile = Some(trimmed.to_string());
                }
            }
        }

        let link_state = entry
            .child("link-state")
            .map(|l| l.text.trim().to_string())
            .filter(|s| !s.is_empty());

        let disabled = entry
            .child("disabled")
            .map(|c| c.text.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        let comment = entry
            .child("comment")
            .map(|c| c.text.trim().to_string())
            .filter(|s| !s.is_empty());

        let zone = zones
            .iter()
            .find(|z| z.interfaces.iter().any(|zi| zi == &name))
            .map(|z| z.name.clone());

        Self {
            name,
            if_type: if_type.to_string(),
            mode,
            ip_addresses,
            zone,
            mgmt_profile,
            link_state,
            disabled,
            comment,
        }
    }
}

/// Structured finding produced by the Palo Alto audit engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaloAltoFinding {
    /// Severity classification.
    pub severity: Severity,
    /// Audit check identifier (e.g. "AUD-DEST-PUB").
    pub check_id: &'static str,
    /// Target rule, object, or config setting.
    pub target: String,
    /// Detailed observation of the anomaly.
    pub message: String,
    /// Concrete PAN-OS CLI remediation command(s).
    pub remediation: Vec<String>,
}

impl PaloAltoFinding {
    /// Convert to core framework `Finding` for unified TUI/CLI reporting.
    pub fn to_core_finding(&self) -> Finding {
        let verdict = match self.severity {
            Severity::Critical => Verdict::Remove,
            Severity::High => Verdict::Disable,
            Severity::Medium => Verdict::Investigate,
            Severity::Info => Verdict::Info,
        };

        let mut finding = Finding::new(
            self.severity,
            "palo-alto",
            format!("{}: {}", self.check_id, self.target),
            &self.message,
        )
        .with_context("Check ID", self.check_id)
        .with_context("Target", &self.target)
        .with_verdict(verdict, "Apply recommended PAN-OS CLI remediation");

        if let Some(cmd) = self.remediation.first() {
            finding = finding.with_action(Action::Manual(cmd.clone()));
        }

        finding
    }
}

/// Accumulator for PAN-OS CLI configuration remediation commands.
#[derive(Debug, Clone, Default)]
pub struct RemediationScript {
    /// Ordered list of configuration commands.
    pub commands: Vec<String>,
}

impl RemediationScript {
    /// Create new empty remediation script.
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    /// Add a single command.
    pub fn add(&mut self, cmd: impl Into<String>) {
        self.commands.push(cmd.into());
    }

    /// Render executable PAN-OS CLI script suitable for SSH terminal paste.
    pub fn render(&self) -> String {
        let mut script = String::new();
        script
            .push_str("# =====================================================================\n");
        script.push_str("# PAN-OS Automated Remediation Script (CCDC 2026)\n");
        script.push_str(
            "# =====================================================================\n\n",
        );
        script.push_str("set cli scripting-mode on\n");
        script.push_str("configure\n\n");

        let mut nat_deletions = Vec::new();
        let mut rogue_deletions = Vec::new();
        let mut dest_corrections = Vec::new();
        let mut enable_cmds = Vec::new();
        let mut hardening_cmds = Vec::new();
        let mut other_cmds = Vec::new();

        for cmd in &self.commands {
            if cmd.contains("delete rulebase nat") {
                nat_deletions.push(cmd.clone());
            } else if cmd.contains("delete rulebase security rules") && cmd.contains("destination")
            {
                dest_corrections.push(cmd.clone());
            } else if cmd.contains("delete rulebase security rules") && cmd.contains("application")
            {
                hardening_cmds.push(cmd.clone());
            } else if cmd.contains("delete rulebase security rules") {
                rogue_deletions.push(cmd.clone());
            } else if cmd.contains("destination") {
                dest_corrections.push(cmd.clone());
            } else if cmd.contains("disabled no") {
                enable_cmds.push(cmd.clone());
            } else if cmd.contains("permitted-ip")
                || cmd.contains("AllowAD-AppID application")
                || cmd.contains("interface-management-profile")
            {
                hardening_cmds.push(cmd.clone());
            } else {
                other_cmds.push(cmd.clone());
            }
        }

        if !nat_deletions.is_empty() {
            script.push_str("# --- Phase 1: Purge Redundant NAT Rules ---\n");
            for c in &nat_deletions {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        if !rogue_deletions.is_empty() {
            script.push_str("# --- Phase 2: Purge Rogue / Backdoor Allow Rules ---\n");
            for c in &rogue_deletions {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        if !dest_corrections.is_empty() {
            script.push_str(
                "# --- Phase 3: Correct Inbound Scored Rule Destinations (*Private) ---\n",
            );
            for c in &dest_corrections {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        if !enable_cmds.is_empty() {
            script.push_str("# --- Phase 4: Enable Scored Service Rules ---\n");
            for c in &enable_cmds {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        if !hardening_cmds.is_empty() {
            script.push_str("# --- Phase 5: Hardening & Exposure Reduction ---\n");
            for c in &hardening_cmds {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        if !other_cmds.is_empty() {
            script.push_str("# --- Phase 6: Additional Corrections ---\n");
            for c in &other_cmds {
                script.push_str(c);
                script.push('\n');
            }
            script.push('\n');
        }

        script.push_str("# --- Phase 7: Commit Changes ---\n");
        script.push_str("commit\n\n");
        script.push_str("exit\n");
        script.push_str("set cli scripting-mode off\n");
        script
    }
}

/// Extract all security rules from XML configuration root.
pub fn extract_security_rules(root: &XmlNode) -> Vec<SecurityRule> {
    let mut rules = Vec::new();
    let security_nodes = root.find_all_deep("security");
    for sec in security_nodes {
        if let Some(rules_node) = sec.child("rules") {
            for entry in rules_node.children_named("entry") {
                rules.push(SecurityRule::from_xml(entry));
            }
        }
    }
    rules
}

/// Extract all NAT rules from XML configuration root.
pub fn extract_nat_rules(root: &XmlNode) -> Vec<NatRule> {
    let mut rules = Vec::new();
    let nat_nodes = root.find_all_deep("nat");
    for nat in nat_nodes {
        if let Some(rules_node) = nat.child("rules") {
            for entry in rules_node.children_named("entry") {
                rules.push(NatRule::from_xml(entry));
            }
        }
    }
    rules
}

/// Extract all management permitted-ip values from XML root.
pub fn extract_permitted_ips(root: &XmlNode) -> Vec<String> {
    let mut ips = Vec::new();
    let permitted_ip_nodes = root.find_all_deep("permitted-ip");
    for pip in permitted_ip_nodes {
        for entry in pip.children_named("entry") {
            if let Some(name) = entry.name() {
                ips.push(name.to_string());
            }
        }
    }
    ips
}

/// Extract all security zones from XML configuration root.
pub fn extract_zones(root: &XmlNode) -> Vec<ZoneConfig> {
    let mut zones = Vec::new();
    let zone_nodes = root.find_all_deep("zone");
    for z_node in zone_nodes {
        for entry in z_node.children_named("entry") {
            zones.push(ZoneConfig::from_xml(entry));
        }
    }
    // Deduplicate zones by name
    let mut seen = BTreeSet::new();
    zones.retain(|z| seen.insert(z.name.clone()));
    zones
}

/// Extract all configured interfaces from XML configuration root.
pub fn extract_interfaces(root: &XmlNode, zones: &[ZoneConfig]) -> Vec<InterfaceConfig> {
    let mut interfaces = Vec::new();
    let interface_parents = root.find_all_deep("interface");

    for if_parent in interface_parents {
        for if_type_node in &if_parent.children {
            let if_type = &if_type_node.tag;
            for entry in if_type_node.children_named("entry") {
                let iface = InterfaceConfig::from_xml(if_type, entry, zones);
                if !iface.name.is_empty() {
                    interfaces.push(iface);
                }
                // Also check for subinterfaces under <layer3><units>
                if let Some(l3) = entry.child("layer3") {
                    if let Some(units) = l3.child("units") {
                        for u_entry in units.children_named("entry") {
                            let u_iface = InterfaceConfig::from_xml(if_type, u_entry, zones);
                            if !u_iface.name.is_empty() {
                                interfaces.push(u_iface);
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate interfaces by name
    let mut seen = BTreeSet::new();
    interfaces.retain(|i| seen.insert(i.name.clone()));
    interfaces
}

/// Audit parsed PAN-OS XML tree against baseline rules, 22 scored services, and security posture.
pub fn audit_config(root: &XmlNode, _team: Option<u8>) -> Vec<PaloAltoFinding> {
    let mut findings = Vec::new();
    let sec_rules = extract_security_rules(root);
    let nat_rules = extract_nat_rules(root);
    let permitted_ips = extract_permitted_ips(root);

    let sec_rules_map: BTreeMap<String, &SecurityRule> =
        sec_rules.iter().map(|r| (r.name.clone(), r)).collect();

    // 1. AUD-DEST-PUB: Destination Address Object Mismatch (*Public vs *Private)
    for host in SCORED_HOST_DEFS {
        let mut target_rules = Vec::new();
        target_rules.extend_from_slice(host.rule_names);
        target_rules.extend_from_slice(host.fallback_names);

        for &r_name in &target_rules {
            if let Some(r) = sec_rules_map.get(r_name) {
                let has_pub = r.destination.iter().any(|d| {
                    d.ends_with("Pub")
                        || d.ends_with("Public")
                        || host.pub_objs.contains(&d.as_str())
                        || d.starts_with("172.25.")
                });
                if has_pub {
                    findings.push(PaloAltoFinding {
                        severity: Severity::Critical,
                        check_id: "AUD-DEST-PUB",
                        target: r_name.to_string(),
                        message: format!(
                            "Rule '{}' matches destination {:?}. Upstream VyOS 1:1 DNAT translates packets to {} ({}). Incoming packets will hit DENYINBOUND and fail scoring.",
                            r_name, r.destination, host.priv_ip, host.default_target
                        ),
                        remediation: vec![
                            format!("delete rulebase security rules \"{}\" destination", r_name),
                            format!("set rulebase security rules \"{}\" destination {}", r_name, host.default_target),
                        ],
                    });
                }
            }
        }
    }

    // 2. AUD-RED-NAT & AUD-EXTRA-NAT: NAT Rules Check
    for nr in &nat_rules {
        let is_redundant = REDUNDANT_NAT_NAMES.contains(&nr.name.as_str())
            || nr.name.ends_with("-StaticNAT")
            || nr.name == "LAN-OutboundPAT";
        if is_redundant {
            findings.push(PaloAltoFinding {
                severity: Severity::High,
                check_id: "AUD-RED-NAT",
                target: nr.name.clone(),
                message: format!(
                    "Redundant NAT rule '{}' duplicates upstream VyOS DNAT, causing asymmetric routing and App-ID state tracking failures.",
                    nr.name
                ),
                remediation: vec![format!("delete rulebase nat rules \"{}\"", nr.name)],
            });
        } else {
            // Any other NAT rule is in addition to the known baseline: flag for manual review, no auto-delete
            findings.push(PaloAltoFinding {
                severity: Severity::Medium,
                check_id: "AUD-EXTRA-NAT",
                target: nr.name.clone(),
                message: format!(
                    "Non-baseline NAT rule '{}' detected. Upstream VyOS handles scored NAT; verify this rule is authorized.",
                    nr.name
                ),
                remediation: Vec::new(),
            });
        }
    }

    // 3. AUD-DIS-RULE: Disabled Scored Security Rules
    for &req_rule in REQUIRED_SCORED_RULES {
        if let Some(r) = sec_rules_map.get(req_rule) {
            if r.disabled {
                findings.push(PaloAltoFinding {
                    severity: Severity::Critical,
                    check_id: "AUD-DIS-RULE",
                    target: req_rule.to_string(),
                    message: format!(
                        "Essential scored security rule '{}' is set to disabled ('disabled yes').",
                        req_rule
                    ),
                    remediation: vec![format!(
                        "set rulebase security rules \"{}\" disabled no",
                        req_rule
                    )],
                });
            }
        }
    }

    // 4. AUD-MISS-RULE: Required Scored Security Rule Missing
    for &req_rule in REQUIRED_SCORED_RULES {
        if !sec_rules_map.contains_key(req_rule) {
            findings.push(PaloAltoFinding {
                severity: Severity::Critical,
                check_id: "AUD-MISS-RULE",
                target: req_rule.to_string(),
                message: format!(
                    "Required scored rule '{}' is missing entirely from the security rulebase.",
                    req_rule
                ),
                remediation: Vec::new(),
            });
        }
    }

    // 5. AUD-ROG-ALLOW & AUD-EXTRA-RULE: Security Rules Baseline Verification
    for r in &sec_rules {
        if !BASELINE_APPROVED_RULES.contains(&r.name.as_str()) {
            if r.action == "allow" {
                // Rogue allow rules listed in script policy: auto-delete
                findings.push(PaloAltoFinding {
                    severity: Severity::Critical,
                    check_id: "AUD-ROG-ALLOW",
                    target: r.name.clone(),
                    message: format!(
                        "Unauthorized allow rule '{}' not in baseline whitelist. Source: {:?}, Destination: {:?}, App: {:?}.",
                        r.name, r.source, r.destination, r.application
                    ),
                    remediation: vec![format!("delete rulebase security rules \"{}\"", r.name)],
                });
            } else {
                // Any other rule configured in addition to the baseline: flag only, no automated fix
                findings.push(PaloAltoFinding {
                    severity: Severity::Medium,
                    check_id: "AUD-EXTRA-RULE",
                    target: r.name.clone(),
                    message: format!(
                        "Non-baseline security rule '{}' (action: '{}') detected. Verify this rule is authorized.",
                        r.name, r.action
                    ),
                    remediation: Vec::new(),
                });
            }
        }
    }

    // 6. AUD-MGMT-OPEN & AUD-MGMT-SUB: Management Permitted-IP Exposure
    if permitted_ips.is_empty() {
        findings.push(PaloAltoFinding {
            severity: Severity::High,
            check_id: "AUD-MGMT-OPEN",
            target: "permitted-ip".to_string(),
            message: "Permitted-IP list is empty; management interface is accessible from any IP without subnet restriction.".to_string(),
            remediation: vec![
                "set deviceconfig system permitted-ip 172.20.240.50/32".to_string(),
                "set deviceconfig system permitted-ip 172.20.240.60/32".to_string(),
            ],
        });
    } else {
        for pip in &permitted_ips {
            if pip == "0.0.0.0/0" || pip == "any" {
                findings.push(PaloAltoFinding {
                    severity: Severity::Critical,
                    check_id: "AUD-MGMT-OPEN",
                    target: pip.clone(),
                    message: format!(
                        "Permitted-IP contains wildcard '{}', exposing WebGUI and SSH to untrusted networks.",
                        pip
                    ),
                    remediation: vec![format!("delete deviceconfig system permitted-ip {}", pip)],
                });
            } else if pip == "172.20.240.0/24" {
                findings.push(PaloAltoFinding {
                    severity: Severity::Medium,
                    check_id: "AUD-MGMT-SUB",
                    target: pip.clone(),
                    message: "Permitted-IP contains entire internal subnet 172.20.240.0/24, allowing all internal LAN hosts to access management (Finding F5).".to_string(),
                    remediation: vec!["delete deviceconfig system permitted-ip 172.20.240.0/24".to_string()],
                });
            }
        }
    }

    // 7. AUD-AD-EXPOSE: Active Directory Overexposure (Finding F1)
    if let Some(ad_rule) = sec_rules_map.get("AllowAD-AppID") {
        let unneeded: BTreeSet<&str> = [
            "active-directory",
            "msrpc",
            "ms-ds-smb",
            "ldap",
            "kerberos",
            "ms-dc-replication",
        ]
        .iter()
        .copied()
        .collect();
        let present_apps: BTreeSet<&str> = ad_rule.application.iter().map(String::as_str).collect();
        let overlap: Vec<&str> = unneeded.intersection(&present_apps).copied().collect();
        if !overlap.is_empty() {
            findings.push(PaloAltoFinding {
                severity: Severity::High,
                check_id: "AUD-AD-EXPOSE",
                target: "AllowAD-AppID".to_string(),
                message: format!(
                    "AllowAD-AppID exposes non-scored AD internal services {:?} to External zone. Only DNS and WinRM are scored.",
                    overlap
                ),
                remediation: vec![
                    "delete rulebase security rules \"AllowAD-AppID\" application".to_string(),
                    "set rulebase security rules \"AllowAD-AppID\" application [ dns windows-remote-management ]".to_string(),
                ],
            });
        }
    }

    // Extract zones and interfaces
    let zones = extract_zones(root);
    let interfaces = extract_interfaces(root, &zones);

    // 8. AUD-IFACE-SETUP: Current Interface Inventory Notification
    for iface in &interfaces {
        findings.push(PaloAltoFinding {
            severity: Severity::Info,
            check_id: "AUD-IFACE-SETUP",
            target: iface.name.clone(),
            message: format!(
                "Interface '{}' ({}, mode: {}): zone={}, IPs={:?}, mgmt_profile={}, disabled={}, link_state={}.",
                iface.name,
                iface.if_type,
                iface.mode,
                iface.zone.as_deref().unwrap_or("none"),
                iface.ip_addresses,
                iface.mgmt_profile.as_deref().unwrap_or("none"),
                iface.disabled,
                iface.link_state.as_deref().unwrap_or("auto")
            ),
            remediation: Vec::new(),
        });
    }

    // 9. AUD-IFACE-MGMT: Data-Plane Management Profile Exposure
    for iface in &interfaces {
        if let Some(ref prof) = iface.mgmt_profile {
            findings.push(PaloAltoFinding {
                severity: Severity::High,
                check_id: "AUD-IFACE-MGMT",
                target: iface.name.clone(),
                message: format!(
                    "Data-plane interface '{}' has management profile '{}' attached, exposing management services on data network.",
                    iface.name, prof
                ),
                remediation: vec![format!(
                    "set network interface {} {} layer3 interface-management-profile none",
                    iface.if_type, iface.name
                )],
            });
        }
    }

    // 10. AUD-IFACE-NO-ZONE: Unzoned Layer 3 Interface
    for iface in &interfaces {
        if iface.mode == "layer3" && !iface.ip_addresses.is_empty() && iface.zone.is_none() {
            findings.push(PaloAltoFinding {
                severity: Severity::Medium,
                check_id: "AUD-IFACE-NO-ZONE",
                target: iface.name.clone(),
                message: format!(
                    "Layer 3 interface '{}' with IP(s) {:?} is not assigned to any security zone.",
                    iface.name, iface.ip_addresses
                ),
                remediation: Vec::new(),
            });
        }
    }

    // 11. AUD-IFACE-EXTRA: Non-Baseline Interfaces & Topology Variations
    for iface in &interfaces {
        if !STANDARD_INTERFACES.contains(&iface.name.as_str()) {
            findings.push(PaloAltoFinding {
                severity: Severity::Medium,
                check_id: "AUD-IFACE-EXTRA",
                target: iface.name.clone(),
                message: format!(
                    "Non-baseline interface '{}' detected (zone: {}, mode: {}, IPs: {:?}). Verify physical topology mapping (e.g. Netlab/Proxmox uplink on 1/1 vs 1/2).",
                    iface.name,
                    iface.zone.as_deref().unwrap_or("none"),
                    iface.mode,
                    iface.ip_addresses
                ),
                remediation: Vec::new(),
            });
        } else if iface.name == "ethernet1/2" {
            if iface.disabled {
                findings.push(PaloAltoFinding {
                    severity: Severity::Critical,
                    check_id: "AUD-IFACE-EXTRA",
                    target: iface.name.clone(),
                    message: "External uplink interface 'ethernet1/2' is administratively disabled ('disabled yes'). All traffic through this interface is blocked.".to_string(),
                    remediation: vec![format!("set network interface {} ethernet1/2 disabled no", iface.if_type)],
                });
            }
            if let Some(ref z) = iface.zone {
                if z != "External" {
                    findings.push(PaloAltoFinding {
                        severity: Severity::Medium,
                        check_id: "AUD-IFACE-EXTRA",
                        target: iface.name.clone(),
                        message: format!(
                            "External uplink interface 'ethernet1/2' is assigned to unexpected zone '{}' (expected 'External').",
                            z
                        ),
                        remediation: Vec::new(),
                    });
                }
            }
            if !iface.ip_addresses.is_empty() && !iface.ip_addresses.iter().any(|ip| ip.starts_with("172.16.0.")) {
                findings.push(PaloAltoFinding {
                    severity: Severity::Medium,
                    check_id: "AUD-IFACE-EXTRA",
                    target: iface.name.clone(),
                    message: format!(
                        "Interface 'ethernet1/2' configured with unexpected IP(s) {:?} (expected 172.16.0.0/24 subnet).",
                        iface.ip_addresses
                    ),
                    remediation: Vec::new(),
                });
            }
        } else if iface.name == "ethernet1/3" {
            if iface.disabled {
                findings.push(PaloAltoFinding {
                    severity: Severity::Critical,
                    check_id: "AUD-IFACE-EXTRA",
                    target: iface.name.clone(),
                    message: "Internal downlink interface 'ethernet1/3' is administratively disabled ('disabled yes'). All traffic through this interface is blocked.".to_string(),
                    remediation: vec![format!("set network interface {} ethernet1/3 disabled no", iface.if_type)],
                });
            }
            if let Some(ref z) = iface.zone {
                if z != "Internal" {
                    findings.push(PaloAltoFinding {
                        severity: Severity::Medium,
                        check_id: "AUD-IFACE-EXTRA",
                        target: iface.name.clone(),
                        message: format!(
                            "Internal downlink interface 'ethernet1/3' is assigned to unexpected zone '{}' (expected 'Internal').",
                            z
                        ),
                        remediation: Vec::new(),
                    });
                }
            }
            if !iface.ip_addresses.is_empty() && !iface.ip_addresses.iter().any(|ip| ip.starts_with("172.20.240.")) {
                findings.push(PaloAltoFinding {
                    severity: Severity::Medium,
                    check_id: "AUD-IFACE-EXTRA",
                    target: iface.name.clone(),
                    message: format!(
                        "Interface 'ethernet1/3' configured with unexpected IP(s) {:?} (expected 172.20.240.0/24 subnet).",
                        iface.ip_addresses
                    ),
                    remediation: Vec::new(),
                });
            }
        }
    }

    // 12. AUD-ZONE-MISMATCH: Security Rules Referencing Undefined Zones
    if !zones.is_empty() {
        let defined_zones: BTreeSet<&str> = zones.iter().map(|z| z.name.as_str()).collect();
        for rule in &sec_rules {
            for z in rule.from.iter().chain(rule.to.iter()) {
                if z != "any" && !defined_zones.contains(z.as_str()) {
                    findings.push(PaloAltoFinding {
                        severity: Severity::High,
                        check_id: "AUD-ZONE-MISMATCH",
                        target: format!("{}:{}", rule.name, z),
                        message: format!(
                            "Security rule '{}' references undefined zone '{}'. Traffic will not match as expected.",
                            rule.name, z
                        ),
                        remediation: Vec::new(),
                    });
                }
            }
        }
    }

    findings
}

/// Compare running configuration against known-good baseline configuration and produce drift findings.
pub fn diff_baseline(running: &XmlNode, baseline: &XmlNode) -> Vec<PaloAltoFinding> {
    let mut findings = Vec::new();
    let running_rules = extract_security_rules(running);
    let baseline_rules = extract_security_rules(baseline);

    let running_map: BTreeMap<String, &SecurityRule> =
        running_rules.iter().map(|r| (r.name.clone(), r)).collect();
    let baseline_map: BTreeMap<String, &SecurityRule> =
        baseline_rules.iter().map(|r| (r.name.clone(), r)).collect();

    // Check for rules present in baseline but missing from running
    for (name, _b_rule) in &baseline_map {
        if !running_map.contains_key(name) {
            findings.push(PaloAltoFinding {
                severity: Severity::High,
                check_id: "DIFF-MISSING-RULE",
                target: name.clone(),
                message: format!(
                    "Baseline rule '{}' is missing from running configuration. Manual configuration required.",
                    name
                ),
                remediation: Vec::new(),
            });
        }
    }

    // Check for rules present in running but not in baseline
    for (name, r_rule) in &running_map {
        if !baseline_map.contains_key(name) {
            let is_allow = r_rule.action == "allow";
            findings.push(PaloAltoFinding {
                severity: Severity::Critical,
                check_id: "DIFF-EXTRA-RULE",
                target: name.clone(),
                message: format!(
                    "Running configuration contains unexpected rule '{}' not present in baseline (action: '{}').",
                    name, r_rule.action
                ),
                remediation: if is_allow {
                    vec![format!("delete rulebase security rules \"{}\"", name)]
                } else {
                    Vec::new() // Flag only for non-allow extra rules
                },
            });
        } else {
            let b_rule = baseline_map.get(name).unwrap();
            if r_rule.disabled != b_rule.disabled {
                findings.push(PaloAltoFinding {
                    severity: Severity::High,
                    check_id: "DIFF-STATE-MISMATCH",
                    target: name.clone(),
                    message: format!(
                        "Rule '{}' disabled state differs: running={}, baseline={}",
                        name, r_rule.disabled, b_rule.disabled
                    ),
                    remediation: vec![format!(
                        "set rulebase security rules \"{}\" disabled {}",
                        name,
                        if b_rule.disabled { "yes" } else { "no" }
                    )],
                });
            }
            if r_rule.destination != b_rule.destination {
                findings.push(PaloAltoFinding {
                    severity: Severity::High,
                    check_id: "DIFF-DEST-MISMATCH",
                    target: name.clone(),
                    message: format!(
                        "Rule '{}' destination differs: running={:?}, baseline={:?}",
                        name, r_rule.destination, b_rule.destination
                    ),
                    remediation: vec![
                        format!("delete rulebase security rules \"{}\" destination", name),
                        format!(
                            "set rulebase security rules \"{}\" destination [ {} ]",
                            name,
                            b_rule.destination.join(" ")
                        ),
                    ],
                });
            }
        }
    }

    // Check NAT rules diff
    let running_nat = extract_nat_rules(running);
    let baseline_nat = extract_nat_rules(baseline);
    let running_nat_map: BTreeMap<String, &NatRule> =
        running_nat.iter().map(|r| (r.name.clone(), r)).collect();
    let baseline_nat_map: BTreeMap<String, &NatRule> =
        baseline_nat.iter().map(|r| (r.name.clone(), r)).collect();

    for (name, _) in &running_nat_map {
        if !baseline_nat_map.contains_key(name) {
            let is_redundant = REDUNDANT_NAT_NAMES.contains(&name.as_str())
                || name.ends_with("-StaticNAT")
                || name == "LAN-OutboundPAT";
            findings.push(PaloAltoFinding {
                severity: Severity::High,
                check_id: "DIFF-EXTRA-NAT",
                target: name.clone(),
                message: format!(
                    "Running configuration contains unexpected NAT rule '{}' not present in baseline.",
                    name
                ),
                remediation: if is_redundant {
                    vec![format!("delete rulebase nat rules \"{}\"", name)]
                } else {
                    Vec::new() // Flag only, no automated fix
                },
            });
        }
    }

    findings
}

/// Print formatted setup instructions for PAN-OS administration and API keygen.
pub fn print_instructions() {
    let instructions = r#"
================================================================================
   Palo Alto PAN-OS 11.0.2 - API Keygen & Administration Setup Guide
================================================================================

1. Dedicated API Administrator Creation
   ------------------------------------
   Best Practice: Create a dedicated administrator for API queries and auditing.

   Via Web GUI:
     1. Navigate to: Device > Administrators > Add
     2. Name: api-admin
     3. Authentication Profile: None (Local Database)
     4. Password: [Strong Unique Password]
     5. Administrator Type: Role Based
     6. Role Profile: Device Administrator (read-only) or Superuser
     7. Click OK and Commit.

   Via PAN-OS CLI:
     set cli scripting-mode on
     configure
     set mgt-config users api-admin password
     set mgt-config users api-admin permissions role-based superuser yes
     commit
     exit
     set cli scripting-mode off

2. API Key Generation via CLI / curl
   ----------------------------------
   Generate the API key using linux-defender:
     linux-defender palo-alto --keygen --host 172.20.240.200 --user api-admin

   Or manually using curl:
     curl -k -X POST "https://172.20.240.200/api/?type=keygen&user=api-admin&password=<PASSWORD>"

3. Verify API Key and Device Status
   ---------------------------------
   curl -k "https://172.20.240.200/api/?type=op&cmd=<show><system><info></info></system></show>&key=<API_KEY>"

4. Exporting running-config.xml for Auditing
   ------------------------------------------
   Via Web GUI:
     Device > Setup > Operations > Export > "Export named configuration snapshot" > running-config.xml

   Via curl:
     curl -k "https://172.20.240.200/api/?type=export&category=configuration&key=<API_KEY>" -o running-config.xml

5. Auditing and Remediation
   ------------------------
   linux-defender palo-alto --audit-xml running-config.xml --out-remediation pa_remedy.txt
================================================================================
"#;
    println!("{}", instructions.trim());
}

/// Execute authenticated curl against PAN-OS XML API over HTTPS.
fn call_pan_api(
    host: &str,
    port: u16,
    query_params: &[(&str, &str)],
    post_body: Option<&str>,
) -> Result<String> {
    let mut url = format!("https://{}:{}/api/?", host, port);
    for (i, (k, v)) in query_params.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&format!("{}={}", k, v));
    }

    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-ksSL", "--max-time", "30"]);
    if let Some(body) = post_body {
        cmd.args(["-X", "POST", "-d", body]);
    }
    cmd.arg(&url);

    let output = cmd.output().map_err(|e| {
        DefenderError::Command(format!("failed to execute curl for PAN-OS API: {e}"))
    })?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(DefenderError::Command(format!(
            "curl error ({}): {}",
            output.status, err
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Generate PAN-OS XML API key using curl over HTTPS.
pub fn generate_api_key(host: &str, port: u16, user: &str, pass: &str) -> Result<String> {
    let body = format!("user={}&password={}", user, pass);
    let resp = call_pan_api(host, port, &[("type", "keygen")], Some(&body))?;
    let node = XmlNode::parse(&resp)
        .map_err(|e| DefenderError::Command(format!("Failed to parse keygen XML response: {e}")))?;
    if node.attr("status") == Some("success") {
        if let Some(key_node) = node.find_all_deep("key").first() {
            if !key_node.text.is_empty() {
                return Ok(key_node.text.clone());
            }
        }
    }
    Err(DefenderError::Command(format!(
        "API keygen failed or key missing in response: {}",
        resp
    )))
}

/// Fetch complete running configuration XML from live firewall API.
pub fn fetch_running_config(host: &str, port: u16, api_key: &str) -> Result<String> {
    call_pan_api(
        host,
        port,
        &[
            ("type", "export"),
            ("category", "configuration"),
            ("key", api_key),
        ],
        None,
    )
}

/// Verify API connectivity and status via `show system info`.
pub fn verify_connectivity(host: &str, port: u16, api_key: &str) -> Result<()> {
    let resp = call_pan_api(
        host,
        port,
        &[
            ("type", "op"),
            ("cmd", "<show><system><info></info></system></show>"),
            ("key", api_key),
        ],
        None,
    )?;
    let node = XmlNode::parse(&resp).map_err(|e| {
        DefenderError::Command(format!("Failed to parse show system info response: {e}"))
    })?;
    if node.attr("status") == Some("success") {
        Ok(())
    } else {
        Err(DefenderError::Command(format!(
            "API verification returned non-success: {}",
            resp
        )))
    }
}

/// Main entrypoint for Palo Alto command execution.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result<()> {
    if args.instructions {
        print_instructions();
        ctx.log("Palo Alto setup instructions displayed.")?;
        return Ok(());
    }

    if args.keygen {
        let user = args.user.as_deref().unwrap_or("api-admin");
        let pass = match args.pass.as_deref() {
            Some(p) => p.to_string(),
            None => {
                println!(
                    "[*] Generating API key for user '{}' on {}:{}",
                    user, args.host, args.port
                );
                print!("Enter password for '{}': ", user);
                use std::io::{self, Write};
                io::stdout().flush().map_err(DefenderError::Io)?;
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(DefenderError::Io)?;
                input.trim().to_string()
            }
        };

        let key = generate_api_key(&args.host, args.port, user, &pass)?;
        println!("[+] API Key generated successfully!");
        println!(
            "    Key: {}...{}",
            &key[..12.min(key.len())],
            &key[key.len().saturating_sub(8)..]
        );
        let key_file = Path::new(".pa_api_key");
        fs::write(key_file, format!("{}\n", key)).map_err(DefenderError::Io)?;
        println!("[+] Saved API key to {}", key_file.display());
        ctx.log(&format!("Generated API key for {} on {}", user, args.host))?;
        return Ok(());
    }

    let mut xml_content: Option<String> = None;

    if let Some(ref path) = args.audit_xml {
        let content = fs::read_to_string(path).map_err(DefenderError::Io)?;
        xml_content = Some(content);
    } else if args.audit_api {
        let key = args.api_key.as_deref().ok_or_else(|| {
            DefenderError::Command("Missing --api-key for live audit-api mode".to_string())
        })?;
        verify_connectivity(&args.host, args.port, key)?;
        let content = fetch_running_config(&args.host, args.port, key)?;
        xml_content = Some(content);
    }

    if let Some(content) = xml_content {
        let root = XmlNode::parse(&content).map_err(|e| {
            DefenderError::Command(format!("Failed to parse PAN-OS configuration XML: {e}"))
        })?;

        let mut findings = audit_config(&root, args.team);

        if let Some(ref baseline_path) = args.diff_baseline {
            let base_content = fs::read_to_string(baseline_path).map_err(DefenderError::Io)?;
            let base_root = XmlNode::parse(&base_content).map_err(|e| {
                DefenderError::Command(format!("Failed to parse baseline XML: {e}"))
            })?;
            let diff_findings = diff_baseline(&root, &base_root);
            findings.extend(diff_findings);
        }

        let crit = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let med = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        println!(
            "\n=============================================================================="
        );
        println!("   PAN-OS CONFIGURATION AUDIT REPORT");
        println!("==============================================================================");
        println!(
            "Total Findings: {} (CRITICAL: {}, HIGH: {}, MEDIUM: {}, INFO: {})\n",
            findings.len(),
            crit,
            high,
            med,
            low
        );

        for (idx, f) in findings.iter().enumerate() {
            println!(
                "[{:02}] [{:?}] {}: {}",
                idx + 1,
                f.severity,
                f.check_id,
                f.target
            );
            println!("     {}", f.message);
            if !f.remediation.is_empty() {
                println!("     Remediation: {}", f.remediation.join("; "));
            }
            println!();

            ctx.emit(f.to_core_finding());
        }

        if let Some(ref out_path) = args.out_remediation {
            let mut script = RemediationScript::new();
            for f in &findings {
                for cmd in &f.remediation {
                    script.add(cmd.clone());
                }
            }
            let rendered = script.render();
            fs::write(out_path, rendered).map_err(DefenderError::Io)?;
            println!(
                "[+] PAN-OS remediation script written to: {}",
                out_path.display()
            );
            ctx.log(&format!(
                "Wrote remediation script to {}",
                out_path.display()
            ))?;
        }

        ctx.log(&format!(
            "Palo Alto audit completed with {} findings ({} critical, {} high)",
            findings.len(),
            crit,
            high
        ))?;
    }

    Ok(())
}
