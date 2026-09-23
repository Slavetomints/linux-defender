//! Bootloader configuration.
//!
//! Two things matter here. `/etc/default/grub` can hand the kernel a different
//! init process, which is game over before userspace starts. And every file in
//! `/etc/grub.d` is a shell script run as root at `update-grub` time.

use std::path::{Path, PathBuf};

use crate::core::scan::{effective_line, read_text_file, read_text_files, suspicious_matches};
use crate::core::{DefenderContext, Result};

/// Where the kernel command line is configured.
const DEFAULT_GRUB: &str = "/etc/default/grub";
/// Directory of shell scripts run as root at `update-grub` time.
const GRUB_D: &str = "/etc/grub.d";

/// Scripts shipped in `/etc/grub.d` by mainstream distributions.
///
/// This cannot be exhaustive — every distribution adds its own — so a name
/// missing from this list is reported as "verify this is yours", not as an
/// accusation. Content matching below is what actually flags a script.
const STOCK_SCRIPTS: &[&str] = &[
    "00_header",
    "01_users",
    "05_debian_theme",
    "08_fallback_counting",
    "10_linux",
    "10_linux_zfs",
    "10_reset_boot_success",
    "12_menu_auto_hide",
    "14_menu_show_once",
    "15_ostree",
    "20_linux_xen",
    "20_memtest86+",
    "20_ppc_terminfo",
    "25_bli",
    "30_os-prober",
    "30_uefi-firmware",
    "35_fwupd",
    "40_custom",
    "41_custom",
    "README",
];

/// Kernel parameters that change what runs as PID 1, or weaken the boot.
const DANGEROUS_PARAMS: &[(&str, &str)] = &[
    ("init=", "replaces PID 1 with another program"),
    ("rdinit=", "replaces the initramfs init"),
    ("single", "boots to single-user root shell"),
    ("selinux=0", "disables SELinux"),
    ("apparmor=0", "disables AppArmor"),
    ("enforcing=0", "puts SELinux in permissive mode"),
];

/// Check kernel parameters and `/etc/grub.d` scripts for boot-time tampering.
pub fn run(ctx: &DefenderContext) -> Result {
    check_kernel_params(ctx);
    check_grub_d(ctx);
    Ok(())
}

/// Report `GRUB_CMDLINE_*` entries that weaken or redirect the boot.
fn check_kernel_params(ctx: &DefenderContext) {
    let Some(contents) = read_text_file(Path::new(DEFAULT_GRUB)) else {
        println!(
            "[!] {} not found, skipping kernel parameter check",
            DEFAULT_GRUB
        );
        return;
    };

    let findings = inspect_cmdline(&contents);
    ctx.debug(&format!("{} parameter finding(s)", findings.len()));

    if findings.is_empty() {
        println!("[✓] No dangerous kernel parameters in {}", DEFAULT_GRUB);
        return;
    }

    println!("[!] Dangerous kernel parameters in {}:", DEFAULT_GRUB);
    for (line, reason) in findings {
        println!("    {}", line);
        println!("      [!] {}", reason);
    }
}

/// Report non-stock scripts and any script with dangerous content.
fn check_grub_d(ctx: &DefenderContext) {
    let dir = Path::new(GRUB_D);
    if !dir.is_dir() {
        println!("[!] {} not found, skipping boot script check", GRUB_D);
        return;
    }

    let files = read_text_files(dir);
    ctx.debug(&format!("Read {} file(s) from {}", files.len(), GRUB_D));

    let unexpected: Vec<&PathBuf> = files
        .iter()
        .map(|(path, _)| path)
        .filter(|path| !is_stock_script(path))
        .collect();

    if unexpected.is_empty() {
        println!("[✓] {} contains only recognised scripts", GRUB_D);
    } else {
        println!(
            "[+] {} script(s) in {} not on the known-stock list:",
            unexpected.len(),
            GRUB_D
        );
        for path in unexpected {
            println!("    - {}", path.display());
        }
        println!("[!] These run as root during update-grub. Distributions add their");
        println!("[!] own, so confirm each is expected rather than assuming the worst.");
    }

    for (path, contents) in &files {
        let reasons = suspicious_matches(contents);
        if !reasons.is_empty() {
            println!("[!] {} contains: {}", path.display(), reasons.join(", "));
        }
    }
}

/// Whether this filename is one a distribution is known to ship.
fn is_stock_script(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| STOCK_SCRIPTS.contains(&name))
}

/// Dangerous parameters on any `GRUB_CMDLINE_*` line.
fn inspect_cmdline(contents: &str) -> Vec<(String, &'static str)> {
    let mut findings = Vec::new();

    for line in contents.lines().filter_map(effective_line) {
        if !line.starts_with("GRUB_CMDLINE") {
            continue;
        }

        let value = line.split_once('=').map(|(_, v)| v).unwrap_or(line);

        for (param, reason) in DANGEROUS_PARAMS {
            if contains_param(value, param) {
                findings.push((line.to_string(), *reason));
            }
        }
    }

    findings
}

/// Whether the quoted parameter list contains `param` as its own token.
///
/// Matching on a bare substring would flag `init=` inside `rdinit=`, and
/// `single` inside `single-user-note`, so tokens are compared whole.
fn contains_param(value: &str, param: &str) -> bool {
    value
        .trim_matches(|c| c == '"' || c == '\'' || c == ' ')
        .split_whitespace()
        .any(|token| {
            if let Some(key) = param.strip_suffix('=') {
                token.split_once('=').is_some_and(|(k, _)| k == key)
            } else {
                token == param
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOCK: &str = r#"
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
"#;

    #[test]
    fn a_stock_config_is_clean() {
        assert!(inspect_cmdline(STOCK).is_empty());
    }

    #[test]
    fn flags_an_init_override() {
        let config = r#"GRUB_CMDLINE_LINUX="init=/tmp/evil""#;
        let findings = inspect_cmdline(config);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].1, "replaces PID 1 with another program");
    }

    #[test]
    fn flags_disabled_mandatory_access_control() {
        let config = r#"GRUB_CMDLINE_LINUX_DEFAULT="quiet selinux=0 apparmor=0""#;
        let findings = inspect_cmdline(config);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn rdinit_is_not_mistaken_for_init() {
        let config = r#"GRUB_CMDLINE_LINUX="rdinit=/bin/sh""#;
        let findings = inspect_cmdline(config);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].1, "replaces the initramfs init");
    }

    #[test]
    fn a_substring_does_not_trigger_a_bare_parameter() {
        assert!(!contains_param("\"quiet single-user-mode\"", "single"));
        assert!(contains_param("\"quiet single\"", "single"));
    }

    #[test]
    fn non_cmdline_lines_are_ignored() {
        assert!(inspect_cmdline("GRUB_TERMINAL=\"init=/x\"\n").is_empty());
    }

    #[test]
    fn stock_script_names_are_recognised() {
        assert!(is_stock_script(Path::new("/etc/grub.d/10_linux")));
        assert!(!is_stock_script(Path::new("/etc/grub.d/99_backdoor")));
    }
}
