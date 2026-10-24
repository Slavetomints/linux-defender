//! Linux distribution detection for package-manager dispatch.
//!
//! Reads `/etc/os-release` and classifies the host into one of five
//! major package-manager families so each restore module can issue the
//! right install or reinstall command without duplicating detection logic.

use std::fs;
use std::path::Path;
use std::process::Command;

use nix::unistd::Uid;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

/// Package-manager family detected on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    /// Debian, Ubuntu, Mint, Pop!\_OS, Kali, Parrot — uses `apt-get`.
    Debian,
    /// RHEL, CentOS, Rocky, AlmaLinux, Fedora — uses `dnf`; falls back to `yum`.
    Rhel,
    /// Arch Linux, Manjaro, EndeavourOS, Garuda — uses `pacman`.
    Arch,
    /// openSUSE Leap / Tumbleweed, SLES — uses `zypper`.
    Suse,
    /// Alpine Linux — uses `apk`.
    Alpine,
}

impl Distro {
    /// Read `/etc/os-release` and return the best-fit family.
    pub fn detect() -> Result<Self> {
        let text = fs::read_to_string("/etc/os-release").map_err(|e| {
            DefenderError::Other(format!("cannot read /etc/os-release: {e}"))
        })?;

        let id = os_release_field(&text, "ID").unwrap_or_default().to_lowercase();
        let id_like = os_release_field(&text, "ID_LIKE")
            .unwrap_or_default()
            .to_lowercase();

        // Check ID_LIKE first — derivative distros inherit the family there.
        for src in [id_like.as_str(), id.as_str()] {
            if src.contains("debian") || src.contains("ubuntu") {
                return Ok(Distro::Debian);
            }
            if src.contains("rhel") || src.contains("centos") || src.contains("fedora") {
                return Ok(Distro::Rhel);
            }
            if src.contains("arch") || src.contains("manjaro") {
                return Ok(Distro::Arch);
            }
            if src.contains("suse") || src.contains("sles") {
                return Ok(Distro::Suse);
            }
            if src == "alpine" {
                return Ok(Distro::Alpine);
            }
        }

        Err(DefenderError::Other(format!(
            "unknown distribution (ID={id:?}, ID_LIKE={id_like:?}); \
             cannot select a package manager"
        )))
    }

    /// Build an install [`Command`] for packages that may not be present yet.
    pub fn install_cmd(&self, packages: &[&str]) -> Command {
        match self {
            Distro::Debian => {
                let mut cmd = Command::new("apt-get");
                cmd.args(["install", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Rhel => {
                let bin = rhel_bin();
                let mut cmd = Command::new(bin);
                cmd.args(["install", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Arch => {
                let mut cmd = Command::new("pacman");
                cmd.args(["-S", "--noconfirm"]);
                cmd.args(packages);
                cmd
            }
            Distro::Suse => {
                let mut cmd = Command::new("zypper");
                cmd.args(["install", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Alpine => {
                let mut cmd = Command::new("apk");
                cmd.args(["add", "--no-cache"]);
                cmd.args(packages);
                cmd
            }
        }
    }

    /// Build a reinstall [`Command`] for packages that are already installed.
    pub fn reinstall_cmd(&self, packages: &[&str]) -> Command {
        match self {
            Distro::Debian => {
                let mut cmd = Command::new("apt-get");
                cmd.args(["install", "--reinstall", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Rhel => {
                let mut cmd = Command::new(rhel_bin());
                cmd.args(["reinstall", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Arch => {
                let mut cmd = Command::new("pacman");
                cmd.args(["-S", "--noconfirm"]);
                cmd.args(packages);
                cmd
            }
            Distro::Suse => {
                let mut cmd = Command::new("zypper");
                cmd.args(["install", "--force", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Alpine => {
                let mut cmd = Command::new("apk");
                cmd.args(["add", "--no-cache"]);
                cmd.args(packages);
                cmd
            }
        }
    }

    /// The PHP CLI package name for this distribution.
    pub fn php_package(&self) -> &'static str {
        match self {
            Distro::Debian => "php-cli",
            Distro::Rhel => "php-cli",
            Distro::Arch => "php",
            Distro::Suse => "php8-cli",
            Distro::Alpine => "php-cli",
        }
    }

    /// Human-readable name for log messages.
    pub fn name(&self) -> &'static str {
        match self {
            Distro::Debian => "Debian/Ubuntu",
            Distro::Rhel => "RHEL/Fedora",
            Distro::Arch => "Arch",
            Distro::Suse => "openSUSE",
            Distro::Alpine => "Alpine",
        }
    }
}

// ── Root elevation ────────────────────────────────────────────────────────────

/// Ensure the process is running as root.
///
/// If not, the operator is offered a single prompt to re-run the full command
/// under `sudo`. On confirmation the current process re-execs itself under
/// sudo and exits with the same code — the elevated child does all the work.
/// On refusal (or if `sudo` is unavailable), an error is returned.
pub fn ensure_root_or_reexec() -> Result<()> {
    if Uid::effective().is_root() {
        return Ok(());
    }

    eprintln!("[!] This command requires root privileges.");
    if prompt_yes("[?] Re-run with sudo? (y/N)")? {
        let args: Vec<String> = std::env::args().collect();
        let status = Command::new("sudo")
            .args(&args)
            .status()
            .map_err(|e| DefenderError::Command(format!("sudo: {e}")))?;
        // Hand the exit code back to the shell and stop this non-root process.
        std::process::exit(status.code().unwrap_or(1));
    }

    Err(DefenderError::NotRoot)
}

// ── Service lifecycle ─────────────────────────────────────────────────────────

/// Enable and restart a systemd service, reporting success or failure.
pub fn enable_and_restart(service: &str, ctx: &DefenderContext) -> Result {
    ctx.debug(&format!("enabling and restarting {service}"));

    let status = Command::new("systemctl")
        .args(["enable", "--now", service])
        .status()
        .map_err(|e| DefenderError::Command(format!("systemctl enable {service}: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(format!(
            "systemctl enable {service} failed"
        )));
    }

    let status = Command::new("systemctl")
        .args(["restart", service])
        .status()
        .map_err(|e| DefenderError::Command(format!("systemctl restart {service}: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(format!(
            "systemctl restart {service} failed"
        )));
    }

    println!("[✓] {service} is running");
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Prefer `dnf` / `dnf5`; fall back to `yum` on older RHEL/CentOS 7.
fn rhel_bin() -> &'static str {
    if Path::new("/usr/bin/dnf5").exists() || Path::new("/usr/bin/dnf").exists() {
        "dnf"
    } else {
        "yum"
    }
}

/// Extract the unquoted value of `KEY=` or `KEY="…"` from `/etc/os-release` text.
pub fn os_release_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    text.lines()
        .find(|l| l.starts_with(&prefix))
        .map(|l| l[prefix.len()..].trim_matches('"'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unquoted_and_quoted_fields() {
        let text = "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n";
        assert_eq!(os_release_field(text, "ID"), Some("ubuntu"));
        assert_eq!(os_release_field(text, "ID_LIKE"), Some("debian"));
        assert_eq!(os_release_field(text, "VERSION_ID"), Some("22.04"));
        assert_eq!(os_release_field(text, "MISSING"), None);
    }

    #[test]
    fn detects_debian_from_id_like() {
        let text = "ID=ubuntu\nID_LIKE=debian\n";
        let id = os_release_field(text, "ID").unwrap_or_default().to_lowercase();
        let id_like = os_release_field(text, "ID_LIKE")
            .unwrap_or_default()
            .to_lowercase();
        let is_debian = [id_like.as_str(), id.as_str()]
            .iter()
            .any(|s| s.contains("debian") || s.contains("ubuntu"));
        assert!(is_debian);
    }

    #[test]
    fn detects_rhel_family_from_id_like() {
        let text = "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n";
        let id_like = os_release_field(text, "ID_LIKE")
            .unwrap_or_default()
            .to_lowercase();
        assert!(id_like.contains("rhel"));
    }
}
