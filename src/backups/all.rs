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
use super::paths::{ALL_PATHS, without_nested};
use crate::core::{DefenderContext, DefenderError, Result};

/// Manifest filename written into the backup directory.
pub const HASH_FILE: &str = "H@shes.txt";
/// Per-path log filename written into the backup directory.
pub const LOG_FILE: &str = "backup.log";

/// The source paths every backup into this directory covered, one per line.
/// `compare_hashes` re-hashes exactly these instead of a fixed list.
pub const ROOTS_FILE: &str = "H@shes.roots";

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
    // Directories are handled recursively, so a path nested under another
    // listed path would be hashed and copied twice.
    // Trailing slashes are dropped so `/etc/nginx/conf.d/` and
    // `/etc/nginx/conf.d` name the same `.bak` entry.
    let normalized: Vec<&str> = paths.iter().map(|p| normalize_path(p)).collect();
    let paths = without_nested(&normalized);
    let paths = paths.as_slice();
    let save_path = resolve_save_path(save_location);

    fs::create_dir_all(&save_path)?;

    let log_path = save_path.join(LOG_FILE);
    let hash_path = save_path.join(HASH_FILE);
    // Append: several backup kinds may share one save directory.
    let mut log = BufWriter::new(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?,
    );

    if save_location.is_none() {
        writeln!(
            log,
            "[!] No save_location provided, defaulting to {}",
            save_path.display()
        )?;
    }

    ctx.progress(&format!("[!] Hash file -> {}", hash_path.display()));
    ctx.progress(&format!("[!] Log file  -> {}", log_path.display()));

    writeln!(
        log,
        "[+] Backing up service configs to {}",
        save_path.display()
    )?;

    // Hash everything first so the manifest reflects pre-copy state, merged
    // into any manifest an earlier backup left in this directory.
    let hashes = hash::compute(paths)?;
    let previous = if hash_path.exists() {
        super::compare_hashes::parse_hashes_file(&hash_path)?
    } else {
        Default::default()
    };
    let merged = merge_manifest(previous, paths, &hashes);
    let mut hashfile = fs::File::create(&hash_path)?;
    for (path, digest) in &merged {
        writeln!(hashfile, "{}  {}", digest, path)?;
    }
    hashfile.flush()?;
    hashfile.sync_all()?;

    let roots_path = save_path.join(ROOTS_FILE);
    let mut roots = read_roots(&roots_path);
    for p in paths {
        if !roots.iter().any(|r| r == p) {
            roots.push((*p).to_string());
        }
    }
    fs::write(&roots_path, roots.join("\n") + "\n")?;

    writeln!(
        log,
        "[+] Wrote {} hash entries ({} total in manifest)",
        hashes.len(),
        merged.len()
    )?;
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

        // -a keeps owner, group, mode, timestamps and symlinks, so a later
        // restore puts files back with the ownership the service expects.
        // -T: copy onto `dest` itself, so re-running into the same directory
        // refreshes the entry instead of nesting a second copy inside it.
        let output = Command::new("cp")
            .arg("-aT")
            .arg(path)
            .arg(&dest)
            .output()
            .map_err(|e| DefenderError::Command(format!("cp -a {}: {}", path, e)))?;

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
            ctx.progress(&format!(
                "[!] Failed to back up {} (see {})",
                path,
                log_path.display()
            ));
        }
    }

    writeln!(log, "[✓] Complete. {} copied, {} skipped", copied, skipped)?;
    log.flush()?;

    ctx.progress(&format!(
        "[✓] Backup complete: {} copied, {} skipped",
        copied, skipped
    ));
    ctx.progress(&format!("[✓] Hashes written to {}", hash_path.display()));
    ctx.progress(&format!("[✓] Logs written to {}", log_path.display()));

    Ok(())
}

/// `path` without trailing slashes (`/` itself is kept).
fn normalize_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

/// Combine an earlier manifest with fresh hashes for `roots`: entries at or
/// under a re-hashed root are replaced, everything else is kept.
fn merge_manifest(
    mut previous: std::collections::BTreeMap<String, String>,
    roots: &[&str],
    fresh: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    previous.retain(|path, _| {
        !roots
            .iter()
            .any(|r| path == r || path.starts_with(&format!("{r}/")))
    });
    previous.extend(fresh.iter().map(|(k, v)| (k.clone(), v.clone())));
    previous
}

/// Source paths recorded in a backup directory's [`ROOTS_FILE`].
pub fn read_roots(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The operator's chosen directory, or a timestamped default.
fn resolve_save_path(save_location: &Option<PathBuf>) -> PathBuf {
    save_location.clone().unwrap_or_else(|| {
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
        PathBuf::from(format!("/etc/ccdc-b@ckup-{}", ts))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_from_several_backups_merge() {
        let prev: std::collections::BTreeMap<String, String> = [
            ("/etc/passwd".to_string(), "a".to_string()),
            ("/etc/postfix/main.cf".to_string(), "old".to_string()),
            ("/etc/postfix/gone.cf".to_string(), "x".to_string()),
        ]
        .into();
        let fresh = [("/etc/postfix/main.cf".to_string(), "new".to_string())].into();
        let merged = merge_manifest(prev, &["/etc/postfix"], &fresh);
        assert_eq!(merged.get("/etc/passwd").map(String::as_str), Some("a"));
        assert_eq!(
            merged.get("/etc/postfix/main.cf").map(String::as_str),
            Some("new")
        );
        assert!(!merged.contains_key("/etc/postfix/gone.cf"));
    }

    #[test]
    fn two_backup_kinds_into_one_dir_keep_both_manifests() {
        let src = tempfile::TempDir::new().unwrap();
        let save = tempfile::TempDir::new().unwrap();
        let a = src.path().join("a.conf");
        let b = src.path().join("bdir");
        fs::write(&a, "a").unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(b.join("x"), "x").unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let ctx = DefenderContext::new(save.path().join("r.txt"), false).with_progress(tx);
        let loc = Some(save.path().to_path_buf());
        let a_s = a.to_string_lossy().to_string();
        let b_s = format!("{}/", b.display());
        run_with_paths(&ctx, &loc, &[a_s.as_str()]).unwrap();
        run_with_paths(&ctx, &loc, &[b_s.as_str()]).unwrap();
        run_with_paths(&ctx, &loc, &[b_s.as_str()]).unwrap();

        let manifest =
            super::super::compare_hashes::parse_hashes_file(&save.path().join(HASH_FILE)).unwrap();
        assert!(manifest.contains_key(&a_s));
        assert!(manifest.contains_key(&b.join("x").to_string_lossy().to_string()));
        assert_eq!(read_roots(&save.path().join(ROOTS_FILE)).len(), 2);
        // Re-running did not nest a second copy inside the .bak directory.
        let bak = save
            .path()
            .join(format!("{}.bak", b.display().to_string().replace('/', "_")));
        assert!(bak.join("x").is_file());
        assert!(!bak.join("bdir").exists());
        let log = fs::read_to_string(save.path().join(LOG_FILE)).unwrap();
        assert_eq!(log.matches("[+] Backing up service configs").count(), 3);
    }
}
