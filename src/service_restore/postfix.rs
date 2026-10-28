//! Reinstall Postfix and restart the service.
//!
//! `postfix` is the package name on every supported distribution, so this
//! module just detects the distro, runs the reinstall, and brings the daemon
//! back up. The reinstall returns binaries and the stock `main.cf`.

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::ensure_root_or_reexec;

use super::distro::{Distro, enable_and_restart};

/// systemd service name for Postfix.
const SERVICE: &str = "postfix";

/// Reinstall Postfix via the host's package manager and bring it back up.
pub fn run(ctx: &DefenderContext) -> Result {
    ensure_root_or_reexec()?;

    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    if ctx.interactive() && !prompt_yes(&format!(
        "[?] Reinstall postfix via {} and restart the service? (y/N)",
        distro.name()
    ))? {
        ctx.progress("[-] Skipping Postfix restore");
        return Ok(());
    }

    ctx.progress(&format!("[+] Reinstalling postfix ({})...", distro.name()));
    let output = distro
        .reinstall_cmd(&["postfix"])
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "reinstall failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress("[✓] Reinstalled postfix");

    enable_and_restart(SERVICE, ctx)?;

    ctx.log("[ok] postfix reinstalled and restarted")?;
    Ok(())
}
