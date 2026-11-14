//! Reinstall OpenSSH server and restart the service.
//!
//! The package and service name vary by distribution:
//!   - Debian/Ubuntu  → `openssh-server`, service `ssh`
//!   - RHEL/Fedora    → `openssh-server`, service `sshd`
//!   - Arch/openSUSE/Alpine → `openssh`, service `sshd`
//!
//! `/etc/ssh/` is restored from backup so the scoring engine's known-hosts
//! fingerprint stays valid — regenerating host keys would break it.

use crate::core::{DefenderContext, Result, prompt_yes};

use super::distro::{Distro, enable_and_restart, reinstall_from_scratch, restore_config};

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

    // Prove the package can be fetched and save the live /etc/ssh (config and
    // host keys) before anything is removed.
    let snapshot = reinstall_from_scratch(distro, &[package], &["/etc/ssh"], ctx)?;

    // Restoring /etc/ssh preserves sshd_config AND the host keys — critical
    // so the scoring engine's cached fingerprint stays valid after reinstall.
    restore_config("/etc/ssh", snapshot.as_deref(), ctx)?;

    enable_and_restart(service, ctx)?;

    ctx.log("[ok] openssh-server installed from scratch and restarted")?;
    Ok(())
}

/// Return the SSH server package and service names for `distro`.
fn ssh_package_and_service(distro: Distro) -> (&'static str, &'static str) {
    match distro {
        Distro::Debian => ("openssh-server", "ssh"),
        Distro::Rhel => ("openssh-server", "sshd"),
        Distro::Arch => ("openssh", "sshd"),
        Distro::Suse => ("openssh", "sshd"),
        Distro::Alpine => ("openssh", "sshd"),
    }
}
