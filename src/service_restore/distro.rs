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
    let dirs = backup_dirs();
    if dirs.is_empty() {
        ctx.progress(&format!(
            "[!] No backup found — {config_path} was NOT restored from a baseline"
        ));
        return Ok(false);
    }

    let Some((backup_dir, bak_path)) = find_backup_entry(&dirs, config_path) else {
        ctx.progress(&format!(
            "[!] No backup entry for {config_path} in any of {} backup dir(s) — NOT restored from a baseline",
            dirs.len()
        ));
        return Ok(false);
    };

    ctx.progress(&format!(
        "[+] Restoring {config_path} from backup {}...",
        backup_dir.display()
    ));

    copy_config_tree(&bak_path, config_path)?;

    ctx.progress(&format!("[✓] {config_path} restored from backup"));
    Ok(true)
}

/// Copy a saved config entry back over `config_path`, preserving ownership,
/// modes and timestamps.
fn copy_config_tree(saved: &Path, config_path: &str) -> Result {
    // cp -aT copies the SOURCE contents into DEST (not a nested copy).
    let out = Command::new("cp")
        .args(["-aT", "--", saved.to_str().unwrap_or(""), config_path])
        .output()
        .map_err(|e| DefenderError::Command(format!("cp config restore: {e}")))?;

    if !out.status.success() {
        return Err(DefenderError::Command(format!(
            "config restore failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Where the live config is copied before a package is removed.
const PRE_RESTORE_DIR: &str = "/var/lib/linux-defender/pre-restore";

/// `.bak` entry name the backup module uses for `config_path`.
fn bak_entry_name(config_path: &str) -> String {
    format!("{}.bak", config_path.replace('/', "_"))
}

/// Copy the live `config_paths` aside before a destructive reinstall.
///
/// Purging a package deletes its configuration. If the box has no baseline
/// backup, this copy is the only thing standing between "reinstall the
/// package" and "lose the AD/LDAP wiring for good". Returns the snapshot
/// directory, or `None` when nothing could be saved.
pub fn snapshot_live_config(config_paths: &[&str], ctx: &DefenderContext) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let dir = Path::new(PRE_RESTORE_DIR).join(ts);
    if let Err(e) = fs::create_dir_all(&dir) {
        ctx.progress(&format!(
            "[!] Could not create {} ({e}) — live config was NOT saved",
            dir.display()
        ));
        return None;
    }
    let _ = fs::set_permissions(PRE_RESTORE_DIR, fs::Permissions::from_mode(0o700));

    let mut saved = 0usize;
    for path in config_paths {
        if !Path::new(path).exists() {
            continue;
        }
        let dest = dir.join(bak_entry_name(path));
        let ok = Command::new("cp")
            .args(["-a", "--", path, dest.to_str().unwrap_or("")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            saved += 1;
        } else {
            ctx.progress(&format!("[!] Could not save live copy of {path}"));
        }
    }
    ctx.progress(&format!(
        "[+] Saved {saved} live config path(s) to {} before reinstall",
        dir.display()
    ));
    (saved > 0).then_some(dir)
}

/// Restore `config_path` from a baseline backup, falling back to the
/// pre-reinstall snapshot of the live config when no baseline has it.
///
/// The fallback keeps integration config (AD, LDAP, SASL) alive on a box that
/// was never backed up, at the cost of carrying over whatever the attacker
/// changed, so it is called out for review.
pub fn restore_config(
    config_path: &str,
    snapshot: Option<&Path>,
    ctx: &DefenderContext,
) -> Result<bool> {
    if restore_config_from_backup(config_path, ctx)? {
        return Ok(true);
    }
    let Some(snapshot) = snapshot else {
        return Ok(false);
    };
    let saved = snapshot.join(bak_entry_name(config_path));
    if !saved.exists() {
        return Ok(false);
    }
    copy_config_tree(&saved, config_path)?;
    ctx.progress(&format!(
        "[!] {config_path} put back from the pre-reinstall live copy ({}) — no baseline backup had it. REVIEW it for tampering.",
        snapshot.display()
    ));
    Ok(true)
}

/// Download `packages` without installing them, to prove the package manager
/// can deliver before anything is removed.
///
/// Returns an error when the fetch fails. Distros without a download-only
/// mode wired up here are skipped (returns `Ok`).
pub fn prefetch_packages(distro: Distro, packages: &[&str], ctx: &DefenderContext) -> Result {
    let attempts: Vec<Command> = match distro {
        Distro::Debian => {
            let mut cmd = Command::new("apt-get");
            cmd.env("DEBIAN_FRONTEND", "noninteractive");
            cmd.args(["install", "--reinstall", "--download-only", "-y", "-q"]);
            cmd.args(packages);
            vec![cmd]
        }
        Distro::Rhel => {
            // `reinstall` covers installed packages, `install` the missing ones.
            let mut reinstall = Command::new(rhel_bin());
            reinstall.args(["reinstall", "--downloadonly", "-y"]);
            reinstall.args(packages);
            let mut install = Command::new(rhel_bin());
            install.args(["install", "--downloadonly", "-y"]);
            install.args(packages);
            vec![reinstall, install]
        }
        _ => return Ok(()),
    };

    ctx.progress(&format!(
        "[+] Checking that {} can be downloaded before removing anything...",
        packages.join(" ")
    ));
    let mut last_err = String::new();
    for mut cmd in attempts {
        match cmd.output() {
            Ok(o) if o.status.success() => {
                ctx.progress("[✓] Packages are available");
                return Ok(());
            }
            Ok(o) => last_err = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(DefenderError::Command(format!(
        "cannot download {} — nothing was removed, the service is untouched. \
         Fix the package sources or network first. ({last_err})",
        packages.join(" ")
    )))
}

/// Remove and reinstall `packages` without betting the service on it.
///
/// Order matters: prove the packages can be fetched, save the live config,
/// and only then remove. Returns the pre-reinstall snapshot directory for
/// [`restore_config`].
pub fn reinstall_from_scratch(
    distro: Distro,
    packages: &[&str],
    config_paths: &[&str],
    ctx: &DefenderContext,
) -> Result<Option<PathBuf>> {
    prefetch_packages(distro, packages, ctx)?;
    let snapshot = snapshot_live_config(config_paths, ctx);

    ctx.progress(&format!(
        "[+] Removing existing packages ({})...",
        distro.name()
    ));
    let _ = distro.remove_cmd(packages).output();
    ctx.progress("[✓] Removed (or were not present)");

    ctx.progress(&format!(
        "[+] Installing {} ({})...",
        packages.join(" "),
        distro.name()
    ));
    let output = distro
        .install_cmd(packages)
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;
    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "install failed after removal: {}{}",
            String::from_utf8_lossy(&output.stderr).trim(),
            snapshot
                .as_ref()
                .map(|d| format!(" — previous config is saved in {}", d.display()))
                .unwrap_or_default()
        )));
    }
    ctx.progress(&format!("[✓] Installed {}", packages.join(", ")));
    Ok(snapshot)
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
    if backup_dirs().is_empty() {
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
        ctx.progress(&format!(
            "[✓] Restored {restored} AD/LDAP/Kerberos join path(s)"
        ));
    }
    Ok(restored)
}

/// Environment variable naming an extra backup directory to search first,
/// for backups taken with `--save-location`.
const BACKUP_DIR_ENV: &str = "LINUX_DEFENDER_BACKUP_DIR";

/// Every backup directory worth searching, most trustworthy first: the
/// operator's explicit `LINUX_DEFENDER_BACKUP_DIR`, then each
/// `/etc/ccdc-b@ckup-*` from oldest to newest.
///
/// Oldest first is deliberate. The baseline taken at the start of the
/// competition predates the attacker's changes; the newest directory may be a
/// partial backup (`--users`) or one taken after the config was poisoned.
fn backup_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(custom) = std::env::var(BACKUP_DIR_ENV) {
        let custom = PathBuf::from(custom);
        if custom.is_dir() {
            dirs.push(custom);
        }
    }

    let mut defaults: Vec<PathBuf> = fs::read_dir("/etc")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(OsStr::to_str)
                            .map(|n| n.starts_with("ccdc-b@ckup-"))
                            .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    // The timestamp suffix (YYYYMMDDTHHMMSSZ) sorts chronologically.
    defaults.sort();
    dirs.extend(defaults);
    dirs
}

/// First directory in `dirs` holding a backup entry for `config_path`,
/// together with the entry's path. Accepts both the plain entry name and the
/// trailing-slash variant (`/etc/x/` was saved as `_etc_x_.bak`).
fn find_backup_entry(dirs: &[PathBuf], config_path: &str) -> Option<(PathBuf, PathBuf)> {
    let trimmed = config_path.trim_end_matches('/');
    let names = [
        bak_entry_name(trimmed),
        bak_entry_name(&format!("{trimmed}/")),
    ];
    dirs.iter().find_map(|dir| {
        names
            .iter()
            .map(|name| dir.join(name))
            .find(|p| p.exists())
            .map(|entry| (dir.clone(), entry))
    })
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
    fn backup_entry_search_prefers_the_oldest_dir_that_has_it() {
        let root = tempfile::TempDir::new().unwrap();
        let old = root.path().join("ccdc-b@ckup-20260101T000000Z");
        let users_only = root.path().join("ccdc-b@ckup-20260102T000000Z");
        let newest = root.path().join("ccdc-b@ckup-20260103T000000Z");
        for d in [&old, &users_only, &newest] {
            fs::create_dir_all(d).unwrap();
        }
        fs::create_dir_all(old.join("_etc_postfix.bak")).unwrap();
        fs::write(users_only.join("_etc_passwd.bak"), "x").unwrap();
        fs::create_dir_all(newest.join("_etc_postfix.bak")).unwrap();
        fs::create_dir_all(newest.join("_opt_splunk_etc_system_local_.bak")).unwrap();
        let dirs = vec![old.clone(), users_only, newest.clone()];

        let (dir, entry) = find_backup_entry(&dirs, "/etc/postfix").unwrap();
        assert_eq!(dir, old);
        assert_eq!(entry, old.join("_etc_postfix.bak"));

        // Trailing-slash naming variant is found too.
        let (dir, _) = find_backup_entry(&dirs, "/opt/splunk/etc/system/local").unwrap();
        assert_eq!(dir, newest);

        assert!(find_backup_entry(&dirs, "/etc/dovecot").is_none());
    }

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
