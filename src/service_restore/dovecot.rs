//! Reinstall Dovecot (with LDAP support) and restart the service.
//!
//! A bare Dovecot reinstall breaks AD/LDAP authentication because the LDAP
//! driver lives in a separate package on most distros. This module installs
//! the full set needed for an AD-integrated mail stack, then overlays the
//! backed-up config so auth bindings and mailbox settings are restored without
//! manual re-integration.
//!
//! Package sets per distro family:
//!   - Debian/Ubuntu: `dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-ldap`
//!   - RHEL/Fedora:   `dovecot dovecot-ldap`
//!   - Arch:          `dovecot`            (LDAP built in)
//!   - openSUSE:      `dovecot dovecot-ldap`
//!   - Alpine:        `dovecot dovecot-ldap dovecot-lmtpd`

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{Distro, enable_and_restart, restore_config_from_backup};
use super::webserver::verify_tcp_service;

/// systemd service name for Dovecot.
const SERVICE: &str = "dovecot";

/// Full package set needed for an AD-integrated Dovecot deployment.
fn packages(distro: Distro) -> &'static [&'static str] {
    match distro {
        Distro::Debian => &[
            "dovecot-core",
            "dovecot-imapd",
            "dovecot-pop3d",
            "dovecot-lmtpd",
            "dovecot-ldap",
        ],
        Distro::Rhel => &["dovecot", "dovecot-ldap"],
        Distro::Arch => &["dovecot"],
        Distro::Suse => &["dovecot", "dovecot-ldap"],
        Distro::Alpine => &["dovecot", "dovecot-ldap", "dovecot-lmtpd"],
    }
}

/// Remove any existing Dovecot installation, install fresh, and bring it up.
pub fn run(ctx: &DefenderContext) -> Result {
    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    let pkgs = packages(distro);

    if ctx.interactive()
        && !prompt_yes(&format!(
            "[?] Reinstall Dovecot (with LDAP support) from scratch via {} and restart? (y/N)",
            distro.name()
        ))?
    {
        ctx.progress("[-] Skipping Dovecot restore");
        return Ok(());
    }

    // Purge the full package set so no stale configs or binaries remain.
    ctx.progress(&format!("[+] Removing existing packages ({})...", distro.name()));
    let _ = distro.remove_cmd(pkgs).output();
    ctx.progress("[✓] Removed (or were not present)");

    // Install the full set in one pass.
    ctx.progress(&format!("[+] Installing {} ({})...", pkgs.join(" "), distro.name()));
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

    // Restore AD/LDAP auth config from backup (covers conf.d/, dovecot.conf, etc.).
    restore_config_from_backup("/etc/dovecot", ctx)?;

    enable_and_restart(SERVICE, ctx)?;

    // Verify IMAP port 143 is up (Dovecot sends "* OK ... Dovecot ready." banner).
    if let Err(e) = verify_tcp_service(143, "* OK", ctx) {
        ctx.progress(&format!("[!] IMAP port 143 check failed: {e}"));
    }
    // Also check IMAPS (port 993) — it won't send a plaintext banner, so just
    // confirm the port is accepting connections.
    if let Err(e) = verify_tcp_service(993, "", ctx) {
        ctx.progress(&format!("[!] IMAPS port 993 check failed: {e}"));
    }

    ctx.log("[ok] dovecot installed from scratch and restarted")?;
    Ok(())
}
