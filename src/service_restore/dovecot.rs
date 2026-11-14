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

use crate::core::{DefenderContext, Result, prompt_yes};

use super::distro::{
    Distro, enable_and_restart, reinstall_from_scratch, restore_ad_integration, restore_config,
};
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

    // Prove the packages can be fetched and save the live config before the
    // purge, so a dead mirror or a missing baseline cannot cost us the service.
    let snapshot = reinstall_from_scratch(distro, pkgs, &["/etc/dovecot"], ctx)?;

    // Restore AD/LDAP auth config (covers conf.d/, dovecot.conf, etc.).
    restore_config("/etc/dovecot", snapshot.as_deref(), ctx)?;
    // Re-apply AD/LDAP/Kerberos join state so AD auth survives a from-scratch reinstall.
    restore_ad_integration(ctx)?;

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
