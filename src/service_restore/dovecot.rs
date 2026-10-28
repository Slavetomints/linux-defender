//! Reinstall Dovecot and restart the service.
//!
//! Debian-based distributions split Dovecot into separate packages for the
//! core daemon, IMAP, and POP3 (`dovecot-core`, `dovecot-imapd`,
//! `dovecot-pop3d`). Every other supported family ships a single `dovecot`
//! package that pulls in all protocols.

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::ensure_root_or_reexec;

use super::distro::{Distro, enable_and_restart};

/// systemd service name for Dovecot.
const SERVICE: &str = "dovecot";

/// Reinstall Dovecot via the host's package manager and bring it back up.
pub fn run(ctx: &DefenderContext) -> Result {
    ensure_root_or_reexec()?;

    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    // Debian splits Dovecot across three packages; everyone else ships one.
    let packages: &[&str] = match distro {
        Distro::Debian => &["dovecot-core", "dovecot-imapd", "dovecot-pop3d"],
        _ => &["dovecot"],
    };

    if ctx.interactive() && !prompt_yes(&format!(
        "[?] Reinstall {} via {} and restart the service? (y/N)",
        packages.join(" "),
        distro.name()
    ))? {
        ctx.progress("[-] Skipping Dovecot restore");
        return Ok(());
    }

    ctx.progress(&format!(
        "[+] Reinstalling {} ({})...",
        packages.join(" "),
        distro.name()
    ));
    let output = distro
        .reinstall_cmd(packages)
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "reinstall failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress(&format!("[✓] Reinstalled {}", packages.join(", ")));

    enable_and_restart(SERVICE, ctx)?;

    ctx.log("[ok] dovecot reinstalled and restarted")?;
    Ok(())
}
