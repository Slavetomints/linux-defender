/// Curated list of tools the operator can download from the Tools tab.
use super::downloader::{InstallMethod, ToolDef};

use crate::core::BoxType;

/// UW-Stout CCDC nftables ruleset builder.
pub const NFTBUILD: ToolDef = ToolDef {
    name: "nftbuild",
    description: "UW-Stout CCDC nftables ruleset generator (does not auto-apply rules)",
    url: "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/firewall/host_firewall/nftbuild",
    mirrors: &[],
    known_sha256: Some("8cb9971513af7346400fc53b9a386bd7469f66b79432f03a9b9421de540724a2"),
    install: InstallMethod::Binary,
};

/// DominicBreuker's process spy — watches /proc for short-lived processes without root.
pub const PSPY64: ToolDef = ToolDef {
    name: "pspy64",
    description: "Watch /proc for short-lived processes and cron activity without root",
    url: "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64",
    mirrors: &[],
    known_sha256: None,
    install: InstallMethod::Binary,
};

/// Every tool available for download in the Tools tab.
pub const ALL_TOOLS: &[&ToolDef] = &[&NFTBUILD, &PSPY64];

/// Metadata for a TUI-native wizard available in the Tools tab.
pub struct WizardDef {
    /// Short identifier, used to launch the wizard.
    pub name: &'static str,
    /// One-line description shown in the Tools tab.
    pub description: &'static str,
}

/// fail2ban deployment wizard.
pub const WIZARD_FAIL2BAN: WizardDef = WizardDef {
    name: "deploy_fail2ban",
    description: "Install and configure fail2ban with per-service jails",
};

/// Firewall assessment and hardening wizard.
pub const WIZARD_FIREWALL: WizardDef = WizardDef {
    name: "firewall_assessment",
    description: "Assess and harden IPv4 firewall (iptables/firewalld/nftables)",
};

/// IPv6 static address configuration wizard.
pub const WIZARD_IPV6: WizardDef = WizardDef {
    name: "deploy_ipv6",
    description: "Configure static IPv6 address (nmcli/netplan/interfaces/sysconfig)",
};

/// Splunk Universal Forwarder deployment wizard.
pub const WIZARD_SPLUNK: WizardDef = WizardDef {
    name: "splunk_forwarder",
    description: "Install and configure Splunk Universal Forwarder with per-box-type inputs",
};

/// Palo Alto PAN-OS XML configuration audit wizard.
pub const WIZARD_PALO_ALTO: WizardDef = WizardDef {
    name: "palo_alto_audit",
    description: "Audit PAN-OS XML config, detect drift, and generate CLI remediation script",
};

/// Every TUI wizard available in the Tools tab.
pub const ALL_WIZARDS: &[&WizardDef] = &[
    &WIZARD_FAIL2BAN,
    &WIZARD_FIREWALL,
    &WIZARD_IPV6,
    &WIZARD_SPLUNK,
    &WIZARD_PALO_ALTO,
];

/// Return the slice of wizards available for the given box type.
///
/// The Palo Alto audit wizard is only available on [`BoxType::General`]
/// (operator workstations with browser/SSH access to the PA management plane).
/// Router boxes never see it; server boxes (Web, Mail, Splunk) also exclude it
/// because the operator workstation is the correct place to review XML exports.
pub fn wizards_for_box_type(bt: BoxType) -> &'static [&'static WizardDef] {
    match bt {
        BoxType::General => ALL_WIZARDS,
        BoxType::Router => &ALL_WIZARDS[..4],
        _ => &ALL_WIZARDS[..4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_box_includes_palo_alto_wizard() {
        let wizards = wizards_for_box_type(BoxType::General);
        assert_eq!(wizards.len(), 5);
        assert!(wizards.iter().any(|w| w.name == "palo_alto_audit"));
    }

    #[test]
    fn non_general_boxes_exclude_palo_alto_wizard() {
        for bt in [
            BoxType::Router,
            BoxType::Web,
            BoxType::Mail,
            BoxType::Splunk,
        ] {
            let wizards = wizards_for_box_type(bt);
            assert_eq!(wizards.len(), 4, "{:?} should only have 4 wizards", bt);
            assert!(
                !wizards.iter().any(|w| w.name == "palo_alto_audit"),
                "{:?} must not include palo_alto_audit",
                bt
            );
        }
    }
}
