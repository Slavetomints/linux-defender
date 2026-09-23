//! Diffing the live system against a saved backup.
//!
//! Re-hashes the paths the backup covered and reports what has been added,
//! removed, or changed since. Given a baseline taken early, this is the
//! fastest way to see exactly what an attacker touched.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::all::HASH_FILE;
use super::hash;
use crate::core::{DefenderContext, DefenderError, Result};

/// What changed between a saved manifest and the live system.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Paths present now but absent from the manifest.
    pub added: Vec<String>,
    /// Paths in the manifest that are now gone.
    pub removed: Vec<String>,
    /// Paths whose digest moved, as (path, previous, current).
    pub changed: Vec<(String, String, String)>,
    /// How many paths still match the manifest.
    pub unchanged: usize,
}

/// Compare the live system against a manifest from a previous backup.
pub fn run(ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result {
    let Some(dir) = save_location.as_ref() else {
        return Err(DefenderError::Other(
            "Please provide the directory containing a previous H@shes.txt via --save-location"
                .into(),
        ));
    };

    let hash_file_path = dir.join(HASH_FILE);
    if !hash_file_path.exists() {
        return Err(DefenderError::Other(format!(
            "Hashes file not found: {}",
            hash_file_path.display()
        )));
    }

    let previous = parse_hashes_file(&hash_file_path)?;
    let current = hash::compute_all()?;

    ctx.debug(&format!(
        "{} previous entries, {} current entries",
        previous.len(),
        current.len()
    ));

    let diff = compare(&previous, &current);

    println!("Comparison results against {}:", hash_file_path.display());
    println!("  Added: {}", diff.added.len());
    for k in &diff.added {
        println!("    + {}", k);
    }
    println!("  Removed: {}", diff.removed.len());
    for k in &diff.removed {
        println!("    - {}", k);
    }
    println!("  Changed: {}", diff.changed.len());
    for (k, prev, curr) in &diff.changed {
        println!("    * {}\n      prev: {}\n      curr: {}", k, prev, curr);
    }
    println!("  Unchanged: {}", diff.unchanged);

    Ok(())
}

/// Read a manifest written by [`super::all`] back into a path -> digest map.
pub fn parse_hashes_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let reader = BufReader::new(fs::File::open(path)?);
    let mut map = BTreeMap::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format is "<digest>  <path>"; the path may itself contain spaces.
        if let Some((digest, rest)) = trimmed.split_once(char::is_whitespace) {
            map.insert(rest.trim().to_string(), digest.to_string());
        }
    }

    Ok(map)
}

/// Diff a saved manifest against freshly computed hashes.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use defender_cli::backups::compare_hashes::compare;
///
/// let previous: BTreeMap<String, String> = [
///     ("/etc/hosts".to_string(), "aaa".to_string()),
///     ("/etc/motd".to_string(), "bbb".to_string()),
/// ]
/// .into();
///
/// // /etc/hosts was edited, /etc/motd deleted, /etc/evil.conf appeared.
/// let current: BTreeMap<String, String> = [
///     ("/etc/hosts".to_string(), "TAMPERED".to_string()),
///     ("/etc/evil.conf".to_string(), "ccc".to_string()),
/// ]
/// .into();
///
/// let diff = compare(&previous, &current);
///
/// assert_eq!(diff.changed.len(), 1);
/// assert_eq!(diff.removed, vec!["/etc/motd".to_string()]);
/// assert_eq!(diff.added, vec!["/etc/evil.conf".to_string()]);
/// assert_eq!(diff.unchanged, 0);
/// ```
pub fn compare(previous: &BTreeMap<String, String>, current: &BTreeMap<String, String>) -> Diff {
    let mut diff = Diff::default();

    for (key, prev) in previous {
        match current.get(key) {
            Some(curr) if curr == prev => diff.unchanged += 1,
            Some(curr) => diff.changed.push((key.clone(), prev.clone(), curr.clone())),
            None => diff.removed.push(key.clone()),
        }
    }

    for key in current.keys() {
        if !previous.contains_key(key) {
            diff.added.push(key.clone());
        }
    }

    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn detects_every_category() {
        let previous = map(&[("/a", "h1"), ("/b", "h2"), ("/gone", "h3")]);
        let current = map(&[("/a", "h1"), ("/b", "CHANGED"), ("/new", "h4")]);

        let diff = compare(&previous, &current);

        assert_eq!(diff.unchanged, 1);
        assert_eq!(diff.removed, vec!["/gone".to_string()]);
        assert_eq!(diff.added, vec!["/new".to_string()]);
        assert_eq!(
            diff.changed,
            vec![("/b".to_string(), "h2".to_string(), "CHANGED".to_string())]
        );
    }

    #[test]
    fn identical_maps_produce_no_findings() {
        let m = map(&[("/a", "h1"), ("/b", "h2")]);
        let diff = compare(&m, &m);

        assert_eq!(diff.unchanged, 2);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn parses_paths_containing_spaces() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("H@shes.txt");
        fs::write(
            &f,
            "abc123  /etc/my config/file.conf\n\ndef456  /etc/hosts\n",
        )
        .unwrap();

        let parsed = parse_hashes_file(&f).unwrap();

        assert_eq!(
            parsed.get("/etc/my config/file.conf"),
            Some(&"abc123".to_string())
        );
        assert_eq!(parsed.get("/etc/hosts"), Some(&"def456".to_string()));
    }
}
