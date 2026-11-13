//! Restore files from a previous backup directory.
//!
//! Reads the `H@shes.txt` manifest that every backup pass writes, then
//! copies each backed-up file back to its original location on the live
//! system. Every copy is gated on [`DefenderContext::run_remediation`] so
//! the operator approves (or skips) each overwrite.
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
use std::path::Path;

use super::all::HASH_FILE;
use crate::core::{DefenderContext, DefenderError, Result};

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

/// Restore files from `backup_dir` back to their original locations.
///
/// Requires `backup_dir` to contain a `H@shes.txt` manifest.  Each file
/// restore is individually prompted via [`DefenderContext::run_remediation`].
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

    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut missing = 0usize;

    for (orig_path, digest) in &entries {
        // Skip directory and non-file placeholders.
        if digest == MARKER_DIR || digest == MARKER_OTHER {
            continue;
        }

        let bak_file = backup_dir.join(bak_name_for(orig_path));

        // The backup may have stored the top-level path (a directory) as a
        // single `.bak` entry; if the bak is itself a directory, look for the
        // specific file inside it.
        let src = if bak_file.is_file() {
            bak_file
        } else {
            // Try stripping the leading '/' and looking relative to backup_dir.
            let rel = orig_path.trim_start_matches('/');
            let alt = backup_dir.join(rel);
            if alt.is_file() {
                alt
            } else {
                ctx.log_msg(&format!(
                    "[!] Backup copy not found for {orig_path}, skipping"
                ));
                missing += 1;
                continue;
            }
        };

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
        "[✓] Restore complete: {restored} restored, {skipped} skipped, {missing} backup copies missing"
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
