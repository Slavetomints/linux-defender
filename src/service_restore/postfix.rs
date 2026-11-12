//! Reinstall Postfix (with LDAP and SASL support) and restart the service.
//!
//! A bare `postfix` reinstall leaves AD integration broken because the LDAP
//! lookup driver and SASL auth daemon live in separate packages. This module
//! installs the full set, then overlays the backed-up config so LDAP maps,
//! relay settings, and SASL bindings come back without manual re-integration.
//!
//! Package sets per distro family:
//!   - Debian/Ubuntu: `postfix postfix-ldap libsasl2-modules sasl2-bin`
//!   - RHEL/Fedora:   `postfix postfix-ldap cyrus-sasl-plain`
//!   - Arch:          `postfix cyrus-sasl`
//!   - openSUSE:      `postfix postfix-ldap`
//!   - Alpine:        `postfix postfix-ldap`

use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{
    Distro, enable_and_restart, restore_ad_integration, restore_config_from_backup,
};
use super::webserver::verify_tcp_service;

/// systemd service name for Postfix.
const SERVICE: &str = "postfix";

/// Full package set needed for an AD-integrated Postfix deployment.
fn packages(distro: Distro) -> &'static [&'static str] {
    match distro {
        Distro::Debian => &["postfix", "postfix-ldap", "libsasl2-modules", "sasl2-bin"],
        Distro::Rhel => &["postfix", "postfix-ldap", "cyrus-sasl-plain"],
        Distro::Arch => &["postfix", "cyrus-sasl"],
        Distro::Suse => &["postfix", "postfix-ldap"],
        Distro::Alpine => &["postfix", "postfix-ldap"],
    }
}

/// Remove any existing Postfix installation, install fresh, and bring it up.
pub fn run(ctx: &DefenderContext) -> Result {
    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    let pkgs = packages(distro);

    if ctx.interactive()
        && !prompt_yes(&format!(
            "[?] Reinstall Postfix (with LDAP/SASL support) from scratch via {} and restart? (y/N)",
            distro.name()
        ))?
    {
        ctx.progress("[-] Skipping Postfix restore");
        return Ok(());
    }

    // Purge the full package set so no stale configs or binaries remain.
    ctx.progress(&format!(
        "[+] Removing existing packages ({})...",
        distro.name()
    ));
    let _ = distro.remove_cmd(pkgs).output();
    ctx.progress("[✓] Removed (or were not present)");

    // Install the full set in one pass.
    ctx.progress(&format!(
        "[+] Installing {} ({})...",
        pkgs.join(" "),
        distro.name()
    ));
    let output = distro
        .install_cmd(pkgs)
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "install failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress(&format!("[✓] Installed {}", pkgs.join(", ")));

    // Restore AD/SASL/LDAP integration config from backup (covers main.cf, sasl/, etc.).
    restore_config_from_backup("/etc/postfix", ctx)?;
    restore_config_from_backup("/etc/aliases", ctx)?;
    // Re-apply AD/LDAP/Kerberos join state so AD auth survives a from-scratch reinstall.
    restore_ad_integration(ctx)?;

    // Rebuild the aliases binary database from the (possibly restored) text file.
    ctx.progress("[+] Rebuilding aliases database...");
    match Command::new("newaliases").output() {
        Ok(o) if o.status.success() => ctx.progress("[✓] Aliases database rebuilt"),
        Ok(o) => ctx.progress(&format!(
            "[!] newaliases failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => ctx.progress(&format!("[!] newaliases not found: {e}")),
    }

    enable_and_restart(SERVICE, ctx)?;

    // Verify SMTP port 25 is accepting connections and returns a 220 banner.
    if let Err(e) = verify_tcp_service(25, "220", ctx) {
        ctx.progress(&format!("[!] SMTP port 25 check failed: {e}"));
    }

    ctx.log("[ok] postfix installed from scratch and restarted")?;
    Ok(())
}
