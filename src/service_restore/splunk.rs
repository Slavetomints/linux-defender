//! Reset Splunk to a clean running state.
//!
//! Splunk is not distributed via any system package manager, so there is no
//! reinstall path. Instead, the restore wipes the local-override layer
//! (`/opt/splunk/etc/system/local/`), which is where attackers plant malicious
//! inputs, outputs, or search commands, then restarts the daemon.
//!
//! The base install under `/opt/splunk/bin/` and `/opt/splunk/etc/system/default/`
//! is left untouched; only the operator-editable override layer is cleared.

use std::fs;
use std::path::Path;
use std::process::Command;

use super::distro::ensure_root_or_reexec;
use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

/// Canonical Splunk installation directory.
const SPLUNK_HOME: &str = "/opt/splunk";
/// The override layer that can be safely wiped.
const LOCAL_DIR: &str = "/opt/splunk/etc/system/local";
/// Splunk CLI binary.
const SPLUNK_BIN: &str = "/opt/splunk/bin/splunk";

/// Stop Splunk, wipe the local-override layer, and start it again.
pub fn run(ctx: &DefenderContext) -> Result {
    ensure_root_or_reexec()?;

    if !Path::new(SPLUNK_BIN).exists() {
        return Err(DefenderError::Other(format!(
            "Splunk not found at {SPLUNK_HOME}; is it installed?"
        )));
    }

    println!("[!] This will wipe all files in {LOCAL_DIR} and restart Splunk.");
    if !prompt_yes("[?] Continue? (y/N)")? {
        println!("[-] Skipping Splunk restore");
        return Ok(());
    }

    splunk_stop(ctx)?;
    wipe_local(ctx)?;
    splunk_start(ctx)?;

    ctx.log("[ok] splunk local-override layer cleared and daemon restarted")?;
    println!("[✓] Splunk restored");
    Ok(())
}

/// Stop the Splunk daemon.
fn splunk_stop(ctx: &DefenderContext) -> Result {
    ctx.debug("stopping splunk");
    println!("[+] Stopping Splunk...");

    let output = Command::new(SPLUNK_BIN)
        .arg("stop")
        .output()
        .map_err(|e| DefenderError::Command(format!("splunk stop: {e}")))?;

    if !output.status.success() {
        // Splunk returns non-zero if it was already stopped; warn but continue.
        eprintln!(
            "[!] splunk stop returned non-zero: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    } else {
        println!("[✓] Splunk stopped");
    }
    Ok(())
}

/// Remove every file under the local-override directory.
fn wipe_local(ctx: &DefenderContext) -> Result {
    let local = Path::new(LOCAL_DIR);

    if !local.exists() {
        println!("[✓] {LOCAL_DIR} does not exist — nothing to wipe");
        return Ok(());
    }

    ctx.debug(&format!("wiping {LOCAL_DIR}"));
    println!("[+] Clearing {LOCAL_DIR}...");

    let mut wiped = 0usize;
    for entry in fs::read_dir(local)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }

        ctx.debug(&format!("removed {}", path.display()));
        wiped += 1;
    }

    println!("[✓] Removed {wiped} entries from {LOCAL_DIR}");
    Ok(())
}

/// Start the Splunk daemon.
fn splunk_start(ctx: &DefenderContext) -> Result {
    ctx.debug("starting splunk");
    println!("[+] Starting Splunk...");

    let output = Command::new(SPLUNK_BIN)
        .arg("start")
        .output()
        .map_err(|e| DefenderError::Command(format!("splunk start: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "splunk start failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    println!("[✓] Splunk started");
    Ok(())
}
