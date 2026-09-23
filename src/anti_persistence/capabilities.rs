//! File capabilities.
//!
//! Capabilities grant slices of root to an ordinary binary without setting the
//! setuid bit, so they are easy to miss in a `find -perm -4000` sweep. A
//! handful of them are directly equivalent to a root shell.

use std::path::PathBuf;
use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result};

/// Capabilities that hand an attacker root, or the means to get it, on any
/// binary that carries them.
const DANGEROUS: &[(&str, &str)] = &[
    ("cap_setuid", "can change UID directly to root"),
    ("cap_setgid", "can change GID, often enough to escalate"),
    (
        "cap_sys_admin",
        "near-root; mount, namespaces and much more",
    ),
    (
        "cap_sys_ptrace",
        "can attach to and inject into root processes",
    ),
    ("cap_sys_module", "can load kernel modules"),
    ("cap_dac_override", "bypasses all file permission checks"),
    ("cap_dac_read_search", "reads any file on the system"),
    ("cap_chown", "can reassign ownership of any file"),
    ("cap_fowner", "bypasses ownership checks"),
    ("cap_sys_rawio", "raw device access"),
];

/// A file carrying Linux capabilities.
pub struct CapabilityFile {
    /// The file the capabilities are set on.
    pub path: PathBuf,
    /// The capability set exactly as `getcap` printed it.
    pub capabilities: String,
    /// Why each capability here matters; empty if none are dangerous.
    pub reasons: Vec<&'static str>,
}

/// Sweep the filesystem for files carrying capabilities and flag the dangerous ones.
pub fn run(ctx: &DefenderContext) -> Result {
    println!("[+] Searching for files with capabilities. This may take a moment...");

    let output = Command::new("getcap")
        .args(["-r", "/"])
        .output()
        .map_err(|e| {
            DefenderError::Command(format!(
                "getcap: {} (install libcap2-bin / libcap to enable this check)",
                e
            ))
        })?;

    // getcap exits non-zero on unreadable directories; that is expected when
    // sweeping the whole filesystem, so only stdout matters.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let found = parse_getcap(&stdout);

    ctx.debug(&format!("getcap reported {} file(s)", found.len()));

    if found.is_empty() {
        println!("[✓] No files carry capabilities");
        return Ok(());
    }

    let flagged = found.iter().filter(|f| !f.reasons.is_empty()).count();
    println!(
        "[+] {} file(s) carry capabilities, {} flagged:",
        found.len(),
        flagged
    );

    for file in &found {
        println!("    {} — {}", file.path.display(), file.capabilities);
        if !file.reasons.is_empty() {
            println!("      [!] {}", file.reasons.join("; "));
        }
    }

    if flagged > 0 {
        println!("[!] Remove an unexpected capability with: setcap -r <file>");
        println!("[!] Not done automatically — some are legitimate (ping, dumpcap).");
    }

    Ok(())
}

/// Parse `getcap -r /` output. Lines look like:
///   `/usr/bin/ping cap_net_raw=ep`
/// Older releases use ` = ` as the separator instead.
fn parse_getcap(output: &str) -> Vec<CapabilityFile> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let (path, capabilities) = split_entry(line)?;
            let lowered = capabilities.to_lowercase();

            let reasons = DANGEROUS
                .iter()
                .filter(|(cap, _)| lowered.contains(cap))
                .map(|(_, why)| *why)
                .collect();

            Some(CapabilityFile {
                path: PathBuf::from(path),
                capabilities: capabilities.to_string(),
                reasons,
            })
        })
        .collect()
}

/// Split a getcap line into its path and capability set, tolerating both the
/// modern `path caps` form and the older `path = caps` form.
fn split_entry(line: &str) -> Option<(&str, &str)> {
    if let Some((path, caps)) = line.split_once(" = ") {
        return Some((path.trim(), caps.trim()));
    }

    let trimmed = line.trim();
    let split = trimmed.rfind(' ')?;
    Some((trimmed[..split].trim(), trimmed[split + 1..].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_modern_format() {
        let found = parse_getcap("/usr/bin/ping cap_net_raw=ep\n");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, PathBuf::from("/usr/bin/ping"));
        assert_eq!(found[0].capabilities, "cap_net_raw=ep");
    }

    #[test]
    fn parses_the_legacy_equals_format() {
        let found = parse_getcap("/usr/bin/ping = cap_net_raw+ep\n");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, PathBuf::from("/usr/bin/ping"));
        assert_eq!(found[0].capabilities, "cap_net_raw+ep");
    }

    #[test]
    fn ping_is_not_flagged_as_dangerous() {
        let found = parse_getcap("/usr/bin/ping cap_net_raw=ep\n");
        assert!(found[0].reasons.is_empty());
    }

    #[test]
    fn setuid_capability_is_flagged() {
        let found = parse_getcap("/tmp/rootme cap_setuid=ep\n");

        assert_eq!(found.len(), 1);
        assert!(
            found[0]
                .reasons
                .contains(&"can change UID directly to root")
        );
    }

    #[test]
    fn several_dangerous_capabilities_are_all_explained() {
        let found = parse_getcap("/usr/bin/evil cap_setuid,cap_sys_admin=eip\n");
        assert_eq!(found[0].reasons.len(), 2);
    }

    #[test]
    fn handles_paths_containing_spaces() {
        let found = parse_getcap("/opt/my tool/bin cap_setuid=ep\n");

        assert_eq!(found[0].path, PathBuf::from("/opt/my tool/bin"));
        assert_eq!(found[0].capabilities, "cap_setuid=ep");
    }

    #[test]
    fn empty_output_yields_nothing() {
        assert!(parse_getcap("").is_empty());
        assert!(parse_getcap("\n\n").is_empty());
    }
}
