//! Reinstall OpenSSH server and restart the service.
//!
//! The package and service name vary by distribution:
//!   - Debian/Ubuntu  → `openssh-server`, service `ssh`
//!   - RHEL/Fedora    → `openssh-server`, service `sshd`
//!   - Arch/openSUSE/Alpine → `openssh`, service `sshd`
//!
//! `/etc/ssh/` is restored from backup so the scoring engine's known-hosts
//! fingerprint stays valid — regenerating host keys would break it.

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{Distro, enable_and_restart, restore_config_from_backup};

/// Remove any existing OpenSSH install, install fresh, and bring it up.
pub fn run(ctx: &DefenderContext) -> Result {
    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    let (package, service) = ssh_package_and_service(distro);

    if ctx.interactive()
        && !prompt_yes(&format!(
            "[?] Reinstall {package} from scratch via {} and restart {service}? (y/N)",
            distro.name()
        ))?
    {
        ctx.progress("[-] Skipping SSH restore");
        return Ok(());
    }

    ctx.progress(&format!("[+] Removing existing {package} ({})...", distro.name()));
    let _ = distro.remove_cmd(&[package]).output();
    ctx.progress("[✓] Removed (or was not present)");

    ctx.progress(&format!("[+] Installing {package} ({})...", distro.name()));
    let output = distro
        .install_cmd(&[package])
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "install failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress(&format!("[✓] Installed {package}"));

    // Restoring /etc/ssh preserves sshd_config AND the host keys — critical
    // so the scoring engine's cached fingerprint stays valid after reinstall.
    restore_config_from_backup("/etc/ssh", ctx)?;

    enable_and_restart(service, ctx)?;

    ctx.log("[ok] openssh-server installed from scratch and restarted")?;
    Ok(())
}

fn ssh_package_and_service(distro: Distro) -> (&'static str, &'static str) {
    match distro {
        Distro::Debian => ("openssh-server", "ssh"),
        Distro::Rhel => ("openssh-server", "sshd"),
        Distro::Arch => ("openssh", "sshd"),
        Distro::Suse => ("openssh", "sshd"),
        Distro::Alpine => ("openssh", "sshd"),
    }
}
