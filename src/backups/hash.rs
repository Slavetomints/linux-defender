//! SHA-256 hashing shared by the backup and comparison passes.
//!
//! Both passes need "walk these paths, hash every regular file", so it lives
//! here once and they cannot drift apart. Entries that are not regular files
//! are recorded with a marker instead of a digest, so both passes agree on
//! what a directory or socket looks like in a manifest.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::paths::ALL_PATHS;
use crate::core::Result;

/// Placeholder recorded for entries that are not regular files.
pub const MARKER_DIR: &str = "<dir>";
/// Recorded in place of a digest for sockets, devices and symlinks.
pub const MARKER_OTHER: &str = "<other>";

/// Map of path -> SHA-256 hex digest for every path in [`ALL_PATHS`].
pub fn compute_all() -> Result<BTreeMap<String, String>> {
    compute(ALL_PATHS)
}

/// Map of path -> SHA-256 hex digest for each of `paths`.
///
/// Missing paths are skipped. Directories are walked recursively and each
/// regular file inside is hashed individually.
pub fn compute(paths: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();

    for path in paths {
        let src = Path::new(path);
        if !src.exists() {
            continue;
        }

        if src.is_file() {
            hashes.insert((*path).to_string(), hash_file(src)?);
        } else if src.is_dir() {
            for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path == src {
                    continue;
                }

                let key = entry_path.to_string_lossy().to_string();
                let value = if entry_path.is_file() {
                    hash_file(entry_path)?
                } else if entry_path.is_dir() {
                    MARKER_DIR.to_string()
                } else {
                    MARKER_OTHER.to_string()
                };

                hashes.insert(key, value);
            }
        } else {
            hashes.insert((*path).to_string(), MARKER_OTHER.to_string());
        }
    }

    Ok(hashes)
}

/// SHA-256 digest of one file, as lowercase hex.
pub fn hash_file(path: &Path) -> Result<String> {
    let contents = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(&contents)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn hashes_a_known_value() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("abc.txt");
        fs::write(&file, "abc").unwrap();

        // Well-known SHA-256 of "abc".
        assert_eq!(
            hash_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn missing_paths_are_skipped() {
        let hashes = compute(&["/nonexistent/path"]).unwrap();
        assert!(hashes.is_empty());
    }
}
