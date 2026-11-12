//! Linux distribution detection for package-manager dispatch.
//!
//! Reads `/etc/os-release` and classifies the host into one of five
//! major package-manager families so each restore module can issue the
//! right install or reinstall command without duplicating detection logic.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::unistd::Uid;

use crate::core::{DefenderContext, DefenderError, Result};

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
        let text = fs::read_to_string("/etc/os-release")
            .map_err(|e| DefenderError::Other(format!("cannot read /etc/os-release: {e}")))?;

        let id = os_release_field(&text, "ID")
            .unwrap_or_default()
            .to_lowercase();
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
                // Suppress all interactive prompts (e.g. postfix mail-type dialog).
                cmd.env("DEBIAN_FRONTEND", "noninteractive");
                cmd.args(["install", "-y", "-q"]);
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
                cmd.env("DEBIAN_FRONTEND", "noninteractive");
                cmd.args(["install", "--reinstall", "-y", "-q"]);
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

    /// Build a remove/purge [`Command`] for packages that may be installed.
    ///
    /// On Debian `apt-get purge` is used so that config files are also removed,
    /// giving a truly clean slate before the follow-up `install`.  Errors from
    /// this command should be ignored by callers — it is fine if the package
    /// is not currently installed.
    pub fn remove_cmd(&self, packages: &[&str]) -> Command {
        match self {
            Distro::Debian => {
                let mut cmd = Command::new("apt-get");
                cmd.env("DEBIAN_FRONTEND", "noninteractive");
                cmd.args(["purge", "-y", "-q"]);
                cmd.args(packages);
                cmd
            }
            Distro::Rhel => {
                let mut cmd = Command::new(rhel_bin());
                cmd.args(["remove", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Arch => {
                let mut cmd = Command::new("pacman");
                cmd.args(["-Rns", "--noconfirm"]);
                cmd.args(packages);
                cmd
            }
            Distro::Suse => {
                let mut cmd = Command::new("zypper");
                cmd.args(["remove", "-y"]);
                cmd.args(packages);
                cmd
            }
            Distro::Alpine => {
                let mut cmd = Command::new("apk");
                cmd.args(["del"]);
                cmd.args(packages);
                cmd
            }
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

    eprintln!("[!] This command requires root privileges — re-running with sudo...");
    let args: Vec<String> = std::env::args().collect();
    let status = Command::new("sudo")
        .args(&args)
        .status()
        .map_err(|e| DefenderError::Command(format!("sudo: {e}")))?;
    std::process::exit(status.code().unwrap_or(1));
}

// ── Service lifecycle ─────────────────────────────────────────────────────────

/// Enable and restart a systemd service, reporting success or failure.
pub fn enable_and_restart(service: &str, ctx: &DefenderContext) -> Result {
    ctx.debug(&format!("enabling and restarting {service}"));

    // Clear a mask first: `systemctl enable --now` fails outright on a masked
    // unit ("Unit is masked"), which is exactly how an attacker takes a scored
    // service offline. Unmask is a no-op on a normal unit.
    let _ = Command::new("systemctl")
        .args(["unmask", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let status = Command::new("systemctl")
        .args(["enable", "--now", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| DefenderError::Command(format!("systemctl enable {service}: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(format!(
            "systemctl enable {service} failed"
        )));
    }

    let status = Command::new("systemctl")
        .args(["restart", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| DefenderError::Command(format!("systemctl restart {service}: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(format!(
            "systemctl restart {service} failed"
        )));
    }

    ctx.progress(&format!("[✓] {service} is running"));
    Ok(())
}

// ── Backup config restore ─────────────────────────────────────────────────────

/// Try to restore `config_path` (e.g. `/etc/postfix`) from the most recent
/// `/etc/ccdc-b@ckup-*` directory created by the backup module.
///
/// The backup stores `/etc/postfix` as `_etc_postfix.bak/` inside the backup
/// dir (see `backups/all.rs`).  This function finds the newest backup dir,
/// locates the `.bak` entry for `config_path`, and overlays it onto
/// `config_path` with `cp -rT` (copy source contents INTO dest, not nested).
///
/// Returns `Ok(true)` if a backup was found and applied, `Ok(false)` if no
/// backup exists (caller should warn the operator), or `Err` on a copy failure.
pub fn restore_config_from_backup(config_path: &str, ctx: &DefenderContext) -> Result<bool> {
    let backup_dir = match latest_backup_dir() {
        Some(d) => d,
        None => {
            ctx.progress(&format!(
                "[!] No backup found — {config_path} AD/integration config was NOT restored"
            ));
            return Ok(false);
        }
    };

    // The backup module replaces '/' with '_', e.g. /etc/postfix → _etc_postfix.bak
    let bak_name = format!("{}.bak", config_path.replace('/', "_"));
    let bak_path = backup_dir.join(&bak_name);

    if !bak_path.exists() {
        ctx.progress(&format!(
            "[!] Backup entry not found for {config_path} in {} — AD config NOT restored",
            backup_dir.display()
        ));
        return Ok(false);
    }

    ctx.progress(&format!(
        "[+] Restoring {config_path} from backup {}...",
        backup_dir.display()
    ));

    // cp -rT copies the SOURCE contents into DEST (not a nested copy).
    let out = Command::new("cp")
        .args(["-rT", "--", bak_path.to_str().unwrap_or(""), config_path])
        .output()
        .map_err(|e| DefenderError::Command(format!("cp config restore: {e}")))?;

    if !out.status.success() {
        return Err(DefenderError::Command(format!(
            "config restore failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    ctx.progress(&format!("[✓] {config_path} restored from backup"));
    Ok(true)
}

/// Shared AD / LDAP / Kerberos join state restored on either mail service.
///
/// This lives outside the postfix/dovecot trees; without it the box can lose
/// AD authentication even after a clean mail reinstall. Backed up by
/// `backups::mail`. Paths absent from the backup are silently skipped.
const AD_INTEGRATION_PATHS: &[&str] = &[
    "/etc/sssd",
    "/etc/krb5.conf",
    "/etc/krb5.keytab",
    "/etc/nsswitch.conf",
    "/etc/ldap",
    "/etc/openldap",
    "/etc/sasl2",
];

/// Restore the AD/LDAP/Kerberos join state from the latest backup.
///
/// Returns the number of paths actually restored. Safe to call from both the
/// Postfix and Dovecot restores: it is idempotent, and if no backup exists it
/// reports that once and restores nothing.
pub fn restore_ad_integration(ctx: &DefenderContext) -> Result<usize> {
    if latest_backup_dir().is_none() {
        ctx.progress(
            "[!] No backup found — AD/LDAP/Kerberos join state NOT restored (manual re-join may be needed)",
        );
        return Ok(0);
    }
    let mut restored = 0usize;
    for path in AD_INTEGRATION_PATHS {
        if restore_config_from_backup(path, ctx)? {
            restored += 1;
        }
    }
    if restored == 0 {
        ctx.progress("[!] No AD/LDAP join files were present in the backup — nothing to restore");
    } else {
        ctx.progress(&format!("[✓] Restored {restored} AD/LDAP/Kerberos join path(s)"));
    }
    Ok(restored)
}

/// Return the path of the most recently created `/etc/ccdc-b@ckup-*` directory.
fn latest_backup_dir() -> Option<PathBuf> {
    let base = Path::new("/etc");
    let mut dirs: Vec<PathBuf> = fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(OsStr::to_str)
                    .map(|n| n.starts_with("ccdc-b@ckup-"))
                    .unwrap_or(false)
        })
        .collect();

    // Sort lexicographically — the timestamp suffix (YYYYMMDDTHHMMSSz) sorts correctly.
    dirs.sort();
    dirs.into_iter().next_back()
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
        let id = os_release_field(text, "ID")
            .unwrap_or_default()
            .to_lowercase();
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
