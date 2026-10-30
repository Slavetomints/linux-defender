//! Reset Splunk to a clean running state — or install it from scratch.
//!
//! Two paths:
//!
//! **Already installed** (`/opt/splunk/bin/splunk` exists): stop the daemon,
//! wipe the local-override layer (`/opt/splunk/etc/system/local/`), and restart.
//! This removes any malicious inputs, outputs, or search commands planted by an
//! attacker while leaving the base install and accepted-license state intact.
//!
//! **Not installed**: download the Splunk Enterprise package (`.deb` or `.rpm`
//! depending on distro), install it, restore config from the most recent backup
//! if one exists, then start with `--accept-license --answer-yes --no-prompt`.
//!
//! The pinned default URL targets Splunk 10.0.2 (the competition VM version).
//! Pass `--splunk-url` to override for a different build.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{Distro, restore_config_from_backup};
use super::webserver::download_file;

const SPLUNK_BIN: &str = "/opt/splunk/bin/splunk";
const LOCAL_DIR: &str = "/opt/splunk/etc/system/local";

/// Pinned Splunk 10.0.2 .deb URL (Debian/Ubuntu).
const SPLUNK_DEB_URL: &str = "https://download.splunk.com/products/splunk/releases/10.0.2/linux/\
                               splunk-10.0.2-e2d18b4767e9-linux-amd64.deb";
/// Pinned Splunk 10.0.2 .rpm URL (RHEL/Fedora).
const SPLUNK_RPM_URL: &str = "https://download.splunk.com/products/splunk/releases/10.0.2/linux/\
                               splunk-10.0.2-e2d18b4767e9.x86_64.rpm";

/// Restore or install Splunk.
///
/// `url` overrides the pinned download URL for a fresh install; ignored if
/// Splunk is already installed.
pub fn run(ctx: &DefenderContext, url: Option<&str>) -> Result {
    if Path::new(SPLUNK_BIN).exists() {
        ctx.progress("[+] Splunk is installed — wiping local-override layer and restarting.");
        if ctx.interactive() && !prompt_yes("[?] Continue? (y/N)")? {
            ctx.progress("[-] Skipping Splunk restore");
            return Ok(());
        }
        splunk_stop(ctx)?;
        wipe_local(ctx)?;
        splunk_start(ctx)?;
    } else {
        ctx.progress("[!] Splunk binary not found — will download and install from scratch.");
        if ctx.interactive() && !prompt_yes("[?] Continue? (y/N)")? {
            ctx.progress("[-] Skipping Splunk restore");
            return Ok(());
        }
        fresh_install(ctx, url)?;
    }

    ctx.log("[ok] splunk restored")?;
    ctx.progress("[✓] Splunk restored");
    Ok(())
}

// ── Fresh install ─────────────────────────────────────────────────────────────

fn fresh_install(ctx: &DefenderContext, url: Option<&str>) -> Result {
    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    let (default_url, pkg_ext) = match distro {
        Distro::Debian => (SPLUNK_DEB_URL, "deb"),
        Distro::Rhel => (SPLUNK_RPM_URL, "rpm"),
        other => {
            return Err(DefenderError::Other(format!(
                "fresh Splunk install not supported on {} — \
                 install manually and re-run to get the wipe path",
                other.name()
            )))
        }
    };

    let download_url = url.unwrap_or(default_url);
    ctx.progress(&format!("[+] Downloading Splunk from {}...", download_url));

    let tmp_path = env::temp_dir().join(format!("splunk-installer.{pkg_ext}"));
    download_file(download_url, &tmp_path, &distro, ctx)?;

    ctx.progress("[+] Installing Splunk package...");
    let install_ok = match distro {
        Distro::Debian => Command::new("dpkg")
            .args(["-i", tmp_path.to_str().unwrap_or("")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        Distro::Rhel => {
            let bin = if Path::new("/usr/bin/dnf").exists() || Path::new("/usr/bin/dnf5").exists() {
                "dnf"
            } else {
                "rpm"
            };
            let args: &[&str] = if bin == "dnf" {
                &["install", "-y", tmp_path.to_str().unwrap_or("")]
            } else {
                &["-i", tmp_path.to_str().unwrap_or("")]
            };
            Command::new(bin)
                .args(args)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        _ => unreachable!(),
    };

    if !install_ok {
        return Err(DefenderError::Command(
            "Splunk package install failed — check dpkg/rpm output above".into(),
        ));
    }
    ctx.progress("[✓] Splunk package installed");

    // Clean up the installer; failure here is non-fatal.
    let _ = fs::remove_file(&tmp_path);

    // Restore config from backup if one exists.
    restore_config_from_backup(LOCAL_DIR, ctx)?;

    // First start — must accept the license explicitly.
    splunk_start(ctx)?;
    Ok(())
}

// ── Wipe ──────────────────────────────────────────────────────────────────────

fn wipe_local(ctx: &DefenderContext) -> Result {
    let local = Path::new(LOCAL_DIR);

    if !local.exists() {
        ctx.progress(&format!("[✓] {LOCAL_DIR} does not exist — nothing to wipe"));
        return Ok(());
    }

    ctx.debug(&format!("wiping {LOCAL_DIR}"));
    ctx.progress(&format!("[+] Clearing {LOCAL_DIR}..."));

    let mut wiped = 0usize;
    let mut failed = 0usize;
    for entry in fs::read_dir(local)? {
        let entry = entry?;
        let path = entry.path();

        let result = if path.is_dir() {
            fs::remove_dir_all(&path).map_err(|e| e.to_string())
        } else {
            fs::remove_file(&path).map_err(|e| e.to_string())
        };

        match result {
            Ok(()) => {
                ctx.debug(&format!("removed {}", path.display()));
                wiped += 1;
            }
            Err(e) => {
                ctx.progress(&format!(
                    "[!] could not remove {}: {e} (chattr +i?)",
                    path.display()
                ));
                failed += 1;
            }
        }
    }

    if failed > 0 {
        ctx.progress(&format!(
            "[!] Removed {wiped} entries from {LOCAL_DIR}; {failed} could not be removed"
        ));
    } else {
        ctx.progress(&format!("[✓] Removed {wiped} entries from {LOCAL_DIR}"));
    }
    Ok(())
}

// ── Daemon lifecycle ──────────────────────────────────────────────────────────

fn splunk_stop(ctx: &DefenderContext) -> Result {
    ctx.debug("stopping splunk");
    ctx.progress("[+] Stopping Splunk...");

    let output = Command::new(SPLUNK_BIN)
        .arg("stop")
        .output()
        .map_err(|e| DefenderError::Command(format!("splunk stop: {e}")))?;

    if !output.status.success() {
        ctx.progress(&format!(
            "[!] splunk stop returned non-zero: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    } else {
        ctx.progress("[✓] Splunk stopped");
    }
    Ok(())
}

/// Start Splunk, always passing `--accept-license --answer-yes --no-prompt`
/// so this works both on a fresh install and after a wipe.
fn splunk_start(ctx: &DefenderContext) -> Result {
    ctx.debug("starting splunk");
    ctx.progress("[+] Starting Splunk...");

    let output = Command::new(SPLUNK_BIN)
        .args(["start", "--accept-license", "--answer-yes", "--no-prompt"])
        .output()
        .map_err(|e| DefenderError::Command(format!("splunk start: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "splunk start failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    ctx.progress("[✓] Splunk started");
    Ok(())
}
