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

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::core::{
    DefenderContext, DefenderError, Result, prompt_string, prompt_string_default, prompt_yes,
};

use super::distro::{Distro, restore_config_from_backup};
use super::webserver::{DOWNLOAD_DIR, download_file, verify_site_insecure, verify_tcp_service};

/// Path to the Splunk CLI binary.
const SPLUNK_BIN: &str = "/opt/splunk/bin/splunk";
/// Splunk local-override config directory.
const LOCAL_DIR: &str = "/opt/splunk/etc/system/local";

/// Pinned Splunk 10.0.2 .deb URL (Debian/Ubuntu).
const SPLUNK_DEB_URL: &str = "https://download.splunk.com/products/splunk/releases/10.0.2/linux/\
                               splunk-10.0.2-e2d18b4767e9-linux-amd64.deb";
/// Pinned Splunk 10.0.2 .rpm URL (RHEL/Fedora).
const SPLUNK_RPM_URL: &str = "https://download.splunk.com/products/splunk/releases/10.0.2/linux/\
                               splunk-10.0.2-e2d18b4767e9.x86_64.rpm";

/// Credentials for Splunk admin user setup on a fresh install.
#[derive(Debug, Clone, Default)]
pub struct SplunkCredentials {
    /// Splunk admin username (defaults to "admin").
    pub admin_user: String,
    /// Splunk admin password.
    pub admin_pass: String,
}

/// Restore or install Splunk.
///
/// `url` overrides the pinned download URL for a fresh install; ignored if
/// Splunk is already installed. `creds` provides the admin user to seed on
/// a fresh install; if `None` the CLI will prompt interactively.
pub fn run(ctx: &DefenderContext, url: Option<&str>, creds: Option<&SplunkCredentials>) -> Result {
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
        fresh_install(ctx, url, creds)?;
    }

    ctx.log("[ok] splunk restored")?;
    ctx.progress("[✓] Splunk restored");

    // Verify Splunk web UI (port 8000) and management port (8089) are up.
    if let Err(e) = verify_site_insecure("http://localhost:8000", r"(?i)splunk", ctx) {
        ctx.progress(&format!("[!] Splunk web UI check failed: {e}"));
    }
    if let Err(e) = verify_tcp_service(8089, "", ctx) {
        ctx.progress(&format!(
            "[!] Splunk management port (8089) check failed: {e}"
        ));
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Check the Debian ar magic bytes (`!<arch>\n`) at the start of the file.
fn is_valid_deb(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut magic))
        .map(|n| n == 8 && &magic == b"!<arch>\n")
        .unwrap_or(false)
}

// ── Fresh install ─────────────────────────────────────────────────────────────

/// Install Splunk from scratch and bring it up.
fn fresh_install(
    ctx: &DefenderContext,
    url: Option<&str>,
    creds: Option<&SplunkCredentials>,
) -> Result {
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
            )));
        }
    };

    let download_url = url.unwrap_or(default_url);
    ctx.progress(&format!("[+] Downloading Splunk from {}...", download_url));

    let tmp_path = Path::new(DOWNLOAD_DIR).join(format!("splunk-installer.{pkg_ext}"));
    download_file(download_url, &tmp_path, &distro, ctx)?;

    // Validate the download before handing it to dpkg/rpm — Splunk's CDN can
    // return an HTML auth-redirect page with HTTP 200, which curl saves happily
    // but dpkg rejects. Fail early with an actionable message.
    if pkg_ext == "deb" && !is_valid_deb(&tmp_path) {
        let size = fs::metadata(&tmp_path).map(|m| m.len()).unwrap_or(0);
        let _ = fs::remove_file(&tmp_path);
        return Err(DefenderError::Other(format!(
            "downloaded file ({size} bytes) is not a valid .deb — Splunk CDN returned \
             an HTML page instead of the package (possible auth redirect).\n\
             Manual fix: wget -O /tmp/splunk.deb '{download_url}' && dpkg -i /tmp/splunk.deb\n\
             Or serve the .deb from your attacker box: wget http://<attacker-ip>/splunk.deb"
        )));
    }

    ctx.progress("[+] Installing Splunk package...");
    // setsid --wait detaches from the controlling terminal so dpkg/rpm
    // postinst scripts cannot open /dev/tty and corrupt the TUI.
    let install_ok = match distro {
        Distro::Debian => Command::new("setsid")
            .args(["--wait", "dpkg", "-i", tmp_path.to_str().unwrap_or("")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        Distro::Rhel => {
            let bin = if Path::new("/usr/bin/dnf").exists() || Path::new("/usr/bin/dnf5").exists() {
                "dnf"
            } else {
                "rpm"
            };
            let args: Vec<&str> = if bin == "dnf" {
                vec![
                    "--wait",
                    bin,
                    "install",
                    "-y",
                    tmp_path.to_str().unwrap_or(""),
                ]
            } else {
                vec!["--wait", bin, "-i", tmp_path.to_str().unwrap_or("")]
            };
            Command::new("setsid")
                .args(&args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        _ => unreachable!(),
    };

    if !install_ok {
        return Err(DefenderError::Command(
            "Splunk package install failed (dpkg/rpm exited non-zero)".into(),
        ));
    }
    ctx.progress("[✓] Splunk package installed");

    // Clean up the installer; failure here is non-fatal.
    let _ = fs::remove_file(&tmp_path);

    // Restore config from backup if one exists.
    restore_config_from_backup(LOCAL_DIR, ctx)?;

    // Write user-seed.conf before first start so Splunk creates the admin user.
    // Without this, Splunk boots into "no users exist" and requires manual setup.
    let seed_creds = match creds {
        Some(c) => c.clone(),
        None if ctx.interactive() => {
            let user = prompt_string_default("[?] Splunk admin username", "admin")?;
            let pass = prompt_string("[?] Splunk admin password")?;
            SplunkCredentials {
                admin_user: user,
                admin_pass: pass,
            }
        }
        None => {
            ctx.progress("[!] No Splunk credentials provided — admin user will NOT be created");
            ctx.progress("[!] After start, run: /opt/splunk/bin/splunk add user admin -role admin -password <pass>");
            splunk_start(ctx)?;
            return Ok(());
        }
    };

    let local_dir = Path::new(LOCAL_DIR);
    let _ = fs::create_dir_all(local_dir);
    let seed_path = local_dir.join("user-seed.conf");
    let seed_content = format!(
        "[user_info]\nUSERNAME = {}\nPASSWORD = {}\n",
        seed_creds.admin_user, seed_creds.admin_pass
    );
    if let Err(e) = fs::write(&seed_path, &seed_content) {
        ctx.progress(&format!(
            "[!] Failed to write user-seed.conf: {e} — admin user may not be created"
        ));
    } else {
        ctx.progress(&format!(
            "[✓] Admin user '{}' configured via user-seed.conf",
            seed_creds.admin_user
        ));
    }

    // First start — must accept the license explicitly.
    splunk_start(ctx)?;
    Ok(())
}

// ── Wipe ──────────────────────────────────────────────────────────────────────

/// Remove the Splunk local-override config layer.
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

/// Stop the Splunk service.
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
