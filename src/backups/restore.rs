//! Restore files from a previous backup directory.
//!
//! Reads the `H@shes.txt` manifest that every backup pass writes, then
//! copies each backed-up file back to its original location on the live
//! system. When run from a terminal the operator confirms the restore once,
//! up front; every copy is then logged through
//! [`DefenderContext::run_remediation`]. A backup copy whose SHA-256 no longer
//! matches the manifest is skipped rather than restored.
//!
//! # Workflow
//!
//! ```text
//! linux-defender backups --restore --save-location /path/to/backup-dir
//! ```
//!
//! The backup directory must contain `H@shes.txt` and the `.bak` copies
//! written by the backup pass.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::all::HASH_FILE;
use super::hash::hash_file;
use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

/// Marker value recorded for directory entries in the manifest.
const MARKER_DIR: &str = "<dir>";
/// Marker value recorded for non-regular-file entries in the manifest.
const MARKER_OTHER: &str = "<other>";

/// Parse a manifest written by the backup pass into a path → digest map.
///
/// Lines are `"<digest>  <path>"` (two spaces). Lines that are empty or
/// contain only a marker digest are included; the caller filters them.
pub fn parse_manifest(contents: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // "<digest>  <path>" — split on the first run of whitespace.
        if let Some((digest, rest)) = trimmed.split_once(char::is_whitespace) {
            map.insert(rest.trim().to_string(), digest.to_string());
        }
    }
    map
}

/// Derive the `.bak` filename inside `backup_dir` for a given source `path`.
///
/// Mirrors the naming in [`super::all::run_with_paths`]:
/// `"<path>".replace('/', "_") + ".bak"`.
pub fn bak_name_for(path: &str) -> String {
    format!("{}.bak", path.replace('/', "_"))
}

/// Find the backup copy of `orig_path` inside `backup_dir`.
///
/// The backup pass stores each top-level path as one entry: a file becomes
/// `<name>.bak`, a directory becomes a `<name>.bak/` tree holding its contents.
/// The manifest, however, lists every file individually. So walk up from
/// `orig_path` to the nearest ancestor that has a `.bak` entry and resolve the
/// rest of the path inside it. Paths listed with a trailing slash produced a
/// `<name>_.bak` entry, which is tried as well.
pub fn locate_backup_copy(backup_dir: &Path, orig_path: &str) -> Option<PathBuf> {
    let orig = Path::new(orig_path);
    for ancestor in orig.ancestors() {
        let ancestor_str = ancestor.to_string_lossy();
        if ancestor_str.is_empty() || ancestor_str == "/" {
            break;
        }
        let rest = orig.strip_prefix(ancestor).ok()?;
        for name in [
            bak_name_for(&ancestor_str),
            bak_name_for(&format!("{ancestor_str}/")),
        ] {
            let bak = backup_dir.join(name);
            let candidate = if rest.as_os_str().is_empty() {
                bak
            } else {
                bak.join(rest)
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Restore files from `backup_dir` back to their original locations.
///
/// Requires `backup_dir` to contain a `H@shes.txt` manifest. Interactive runs
/// ask for one confirmation before anything is overwritten.
pub fn run(ctx: &DefenderContext, backup_dir: &Path) -> Result {
    if !backup_dir.exists() {
        return Err(DefenderError::Other(format!(
            "Backup directory not found: {}",
            backup_dir.display()
        )));
    }

    let manifest_path = backup_dir.join(HASH_FILE);
    if !manifest_path.exists() {
        return Err(DefenderError::Other(format!(
            "No manifest ({HASH_FILE}) found in {}; is this a defender backup directory?",
            backup_dir.display()
        )));
    }

    let contents = fs::read_to_string(&manifest_path)?;
    let entries = parse_manifest(&contents);

    ctx.log_msg(&format!(
        "[+] Restoring from {} ({} entries in manifest)",
        backup_dir.display(),
        entries.len()
    ));

    let file_count = entries
        .values()
        .filter(|d| *d != MARKER_DIR && *d != MARKER_OTHER)
        .count();
    if ctx.interactive()
        && !prompt_yes(&format!(
            "[?] Overwrite up to {file_count} live file(s) with the copies in {}? (y/N)",
            backup_dir.display()
        ))?
    {
        ctx.log_msg("[-] Restore cancelled");
        return Ok(());
    }

    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut missing = 0usize;
    let mut tampered = 0usize;

    for (orig_path, digest) in &entries {
        // Skip directory and non-file placeholders.
        if digest == MARKER_DIR || digest == MARKER_OTHER {
            continue;
        }

        let Some(src) = locate_backup_copy(backup_dir, orig_path) else {
            ctx.log_msg(&format!(
                "[!] Backup copy not found for {orig_path}, skipping"
            ));
            missing += 1;
            continue;
        };

        // The backup directory sits on the same box the attacker is on. Only
        // restore a copy that still matches what the manifest recorded.
        match hash_file(&src) {
            Ok(actual) if actual == *digest => {}
            Ok(_) => {
                ctx.log_msg(&format!(
                    "[!] Backup copy of {orig_path} does not match the manifest hash, skipping (possible tampering)"
                ));
                tampered += 1;
                continue;
            }
            Err(e) => {
                ctx.log_msg(&format!(
                    "[!] Could not read backup copy of {orig_path}: {e}, skipping"
                ));
                skipped += 1;
                continue;
            }
        }

        let dst = Path::new(orig_path);
        let src_str = src.to_string_lossy();
        let dst_str = dst.to_string_lossy();

        ctx.log_msg(&format!("  Restoring {orig_path}"));

        // Create parent directory if needed before asking to copy.
        if let Some(parent) = dst.parent()
            && !parent.exists()
            && let Err(e) = fs::create_dir_all(parent)
        {
            ctx.log_msg(&format!(
                "[!] Could not create parent dir {}: {e}",
                parent.display()
            ));
            skipped += 1;
            continue;
        }

        if ctx.run_remediation(&["cp", "-a", &src_str, &dst_str]) {
            restored += 1;
        } else {
            skipped += 1;
        }
    }

    ctx.log_msg(&format!(
        "[✓] Restore complete: {restored} restored, {skipped} skipped, {missing} backup copies missing, {tampered} failed hash check"
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty manifest parses to empty map.
    #[test]
    fn parse_manifest_empty() {
        assert!(parse_manifest("").is_empty());
    }

    /// Standard two-space-separated lines parse correctly.
    #[test]
    fn parse_manifest_standard_lines() {
        let input = "abc123  /etc/passwd\ndef456  /etc/shadow\n";
        let map = parse_manifest(input);
        assert_eq!(map.get("/etc/passwd").map(String::as_str), Some("abc123"));
        assert_eq!(map.get("/etc/shadow").map(String::as_str), Some("def456"));
    }

    /// Marker-valued lines are included (caller decides whether to skip them).
    #[test]
    fn parse_manifest_includes_markers() {
        let input = "<dir>  /etc/ssh\n<other>  /dev/null\n";
        let map = parse_manifest(input);
        assert_eq!(map.get("/etc/ssh").map(String::as_str), Some("<dir>"));
        assert_eq!(map.get("/dev/null").map(String::as_str), Some("<other>"));
    }

    /// Blank lines are ignored.
    #[test]
    fn parse_manifest_skips_blank_lines() {
        let input = "\n  \nabc123  /etc/hosts\n\n";
        let map = parse_manifest(input);
        assert_eq!(map.len(), 1);
    }

    /// `bak_name_for` mirrors the naming scheme used when writing a backup.
    #[test]
    fn bak_name_for_replaces_slashes() {
        assert_eq!(bak_name_for("/etc/passwd"), "_etc_passwd.bak");
        assert_eq!(
            bak_name_for("/var/www/html/index.php"),
            "_var_www_html_index.php.bak"
        );
    }

    /// Files inside a backed-up directory resolve inside that directory's
    /// `.bak` tree, including the trailing-slash naming variant.
    #[test]
    fn locates_files_inside_directory_backups() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = dir.path();
        fs::create_dir_all(b.join("_etc_pam.d.bak")).unwrap();
        fs::write(b.join("_etc_pam.d.bak/sshd"), "x").unwrap();
        fs::create_dir_all(b.join("_etc_nginx_conf.d_.bak/sub")).unwrap();
        fs::write(b.join("_etc_nginx_conf.d_.bak/sub/a.conf"), "x").unwrap();
        fs::write(b.join("_etc_hosts.bak"), "x").unwrap();

        assert_eq!(
            locate_backup_copy(b, "/etc/pam.d/sshd"),
            Some(b.join("_etc_pam.d.bak/sshd"))
        );
        assert_eq!(
            locate_backup_copy(b, "/etc/nginx/conf.d/sub/a.conf"),
            Some(b.join("_etc_nginx_conf.d_.bak/sub/a.conf"))
        );
        assert_eq!(
            locate_backup_copy(b, "/etc/hosts"),
            Some(b.join("_etc_hosts.bak"))
        );
        assert_eq!(locate_backup_copy(b, "/etc/missing/file"), None);
    }

    /// A full backup followed by a restore puts a deleted nested file back,
    /// and refuses a backup copy that was modified after the backup.
    #[test]
    fn round_trip_restores_nested_files_and_rejects_tampered_copies() {
        let src = tempfile::TempDir::new().unwrap();
        let save = tempfile::TempDir::new().unwrap();
        let tree = src.path().join("conf");
        fs::create_dir_all(tree.join("sub")).unwrap();
        let good = tree.join("sub/good.conf");
        let bad = tree.join("bad.conf");
        fs::write(&good, "good").unwrap();
        fs::write(&bad, "original").unwrap();

        // Report goes to a file, and a progress channel makes the context
        // non-interactive so the confirmation prompt is skipped.
        let (tx, _rx) = std::sync::mpsc::channel();
        let ctx = crate::core::DefenderContext::new(save.path().join("report.txt"), false)
            .with_progress(tx);
        let tree_str = tree.to_string_lossy().to_string();
        let save_loc = Some(save.path().to_path_buf());
        super::super::all::run_with_paths(&ctx, &save_loc, &[tree_str.as_str()]).unwrap();

        fs::remove_file(&good).unwrap();
        fs::write(&bad, "attacker edit").unwrap();
        let bak_bad = locate_backup_copy(save.path(), &bad.to_string_lossy()).unwrap();
        fs::write(&bak_bad, "poisoned backup").unwrap();

        run(&ctx, save.path()).unwrap();

        assert_eq!(fs::read_to_string(&good).unwrap(), "good");
        assert_eq!(fs::read_to_string(&bad).unwrap(), "attacker edit");
    }

    /// `run` returns an error when the backup directory does not exist.
    #[test]
    fn run_errors_on_missing_dir() {
        use std::path::PathBuf;
        let ctx = crate::core::DefenderContext::new(
            PathBuf::from("/tmp/defender-test-restore-nonexistent.txt"),
            false,
        );
        let result = run(&ctx, Path::new("/nonexistent/backup/dir/xyz123"));
        assert!(result.is_err());
    }

    /// `run` returns an error when the directory exists but has no manifest.
    #[test]
    fn run_errors_on_missing_manifest() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let ctx = crate::core::DefenderContext::new(dir.path().join("report.txt"), false);
        let result = run(&ctx, dir.path());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("H@shes.txt") || msg.contains("manifest"),
            "unexpected error: {msg}"
        );
    }
}
