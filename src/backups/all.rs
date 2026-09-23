//! The full backup pass.
//!
//! Copies every path in [`super::paths::ALL_PATHS`] into a save directory and
//! writes a SHA-256 manifest beside it. That manifest is what
//! [`super::compare_hashes`] later diffs the live system against.
//!
//! A path that cannot be read is logged and skipped rather than aborting the
//! run: a partial backup is worth far more than none at all.

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;

use super::hash;
use super::paths::ALL_PATHS;
use crate::core::{DefenderContext, DefenderError, Result};

/// Manifest filename written into the backup directory.
pub const HASH_FILE: &str = "H@shes.txt";
/// Per-path log filename written into the backup directory.
pub const LOG_FILE: &str = "backup.log";

/// Back up every known config path in [`super::paths::ALL_PATHS`].
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    run_with_paths(ctx, save_location, ALL_PATHS)
}

/// Backup driver, parameterised over the source paths so it can be exercised
/// against a fixture tree instead of the real filesystem.
pub fn run_with_paths(
    ctx: &DefenderContext,
    save_location: &Option<PathBuf>,
    paths: &[&str],
) -> Result {
    let save_path = resolve_save_path(save_location);

    fs::create_dir_all(&save_path)?;

    let log_path = save_path.join(LOG_FILE);
    let hash_path = save_path.join(HASH_FILE);
    let mut log = BufWriter::new(fs::File::create(&log_path)?);

    if save_location.is_none() {
        writeln!(
            log,
            "[!] No save_location provided, defaulting to {}",
            save_path.display()
        )?;
    }

    println!("[!] Hash file -> {}", hash_path.display());
    println!("[!] Log file  -> {}", log_path.display());

    writeln!(
        log,
        "[+] Backing up service configs to {}",
        save_path.display()
    )?;

    // Hash everything first so the manifest reflects pre-copy state.
    let hashes = hash::compute(paths)?;
    let mut hashfile = fs::File::create(&hash_path)?;
    for (path, digest) in &hashes {
        writeln!(hashfile, "{}  {}", digest, path)?;
    }
    hashfile.flush()?;
    hashfile.sync_all()?;

    writeln!(log, "[+] Wrote {} hash entries", hashes.len())?;
    ctx.debug(&format!("Hashed {} entries", hashes.len()));

    let mut copied = 0usize;
    let mut skipped = 0usize;

    for path in paths {
        if !Path::new(path).exists() {
            writeln!(log, "[!] {} does not exist, skipping", path)?;
            skipped += 1;
            continue;
        }

        let dest = save_path.join(format!("{}.bak", path.replace('/', "_")));

        let output = Command::new("cp")
            .arg("-r")
            .arg(path)
            .arg(&dest)
            .output()
            .map_err(|e| DefenderError::Command(format!("cp -r {}: {}", path, e)))?;

        if output.status.success() {
            writeln!(log, "[+] Backed up {}", path)?;
            copied += 1;
        } else {
            // A single unreadable path should not abort the whole backup.
            writeln!(
                log,
                "[X] Failed to back up {}: {}",
                path,
                String::from_utf8_lossy(&output.stderr).trim()
            )?;
            eprintln!(
                "[!] Failed to back up {} (see {})",
                path,
                log_path.display()
            );
        }
    }

    writeln!(log, "[✓] Complete. {} copied, {} skipped", copied, skipped)?;
    log.flush()?;

    println!(
        "[✓] Backup complete: {} copied, {} skipped",
        copied, skipped
    );
    println!("[✓] Hashes written to {}", hash_path.display());
    println!("[✓] Logs written to {}", log_path.display());

    Ok(())
}

/// The operator's chosen directory, or a timestamped default.
fn resolve_save_path(save_location: &Option<PathBuf>) -> PathBuf {
    save_location.clone().unwrap_or_else(|| {
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
        PathBuf::from(format!("/etc/ccdc-b@ckup-{}", ts))
    })
}
