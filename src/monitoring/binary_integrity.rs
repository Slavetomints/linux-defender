//! System binary integrity checking via SHA-256 baseline snapshots.
//!
//! Two modes:
//! - **Baseline mode**: hash all executables in canonical system paths and
//!   write `/etc/linux-defender/baseline.txt` (requires root).
//! - **Check mode**: re-hash the same paths and compare against the stored
//!   baseline, reporting deleted, modified, and new binaries.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

const BASELINE_PATH: &str = "/etc/linux-defender/baseline.txt";
const BASELINE_DIR: &str = "/etc/linux-defender";

/// Directories to scan for system executables.
const SCAN_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/local/bin",
    "/usr/local/sbin",
];

// ── SHA-256 helper ────────────────────────────────────────────────────────────

/// Compute a SHA-256 hex digest of a file using the system `sha256sum` binary.
/// Returns `None` on I/O error or if sha256sum is unavailable.
fn sha256_file(path: &Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // Output format: "<hash>  <path>\n"
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

/// Compute a SHA-256 hex digest of a byte slice via `sha256sum` on stdin.
/// Used in tests and baseline-write paths where data is already in memory.
fn sha256_hex(data: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sha256sum not found");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(data);
    }
    let out = child.wait_with_output().expect("sha256sum wait failed");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

// ── Baseline I/O ─────────────────────────────────────────────────────────────

/// Parse a baseline file into a `HashMap<path → sha256hex>`.
/// Each line is `<sha256hex>  <absolute_path>` (two spaces, sha256sum format).
pub fn parse_baseline(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Two spaces separate hash and path.
        if let Some((hash, path)) = line.split_once("  ") {
            map.insert(path.to_string(), hash.to_string());
        }
    }
    map
}

/// Walk `dir` recursively, returning the path of every regular executable.
fn collect_executables(dir: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            // Recurse one level (usr/lib has subdirs).
            out.extend(collect_executables(&path));
        } else if let Ok(meta) = path.metadata() {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                out.push(path);
            }
        }
    }
    out
}

/// Hash all executables across all SCAN_DIRS.
fn scan_all() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for dir in SCAN_DIRS {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        for path in collect_executables(dir_path) {
            if let Some(hash) = sha256_file(&path) {
                map.insert(path.to_string_lossy().into_owned(), hash);
            }
        }
    }
    map
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run binary integrity checks.  Creates a baseline on first run; compares
/// against the stored baseline on subsequent runs.
pub fn run(ctx: &DefenderContext) -> Result {
    let baseline_path = Path::new(BASELINE_PATH);

    if !baseline_path.exists() {
        // Baseline mode — requires root so we can write to /etc.
        if !nix::unistd::Uid::effective().is_root() {
            ctx.emit(
                Finding::new(
                    Severity::Info,
                    "binary_integrity",
                    "No baseline found and not running as root — skipping baseline creation",
                    "Run linux-defender as root to create the initial baseline.",
                )
                .with_verdict(Verdict::Info, "Rerun as root to create a baseline."),
            );
            return Ok(());
        }

        // Create the directory if needed.
        if let Err(e) = std::fs::create_dir_all(BASELINE_DIR) {
            ctx.log_msg(&format!(
                "[-] binary_integrity: could not create {}: {}",
                BASELINE_DIR, e
            ));
            return Ok(());
        }

        let hashes = scan_all();
        let n = hashes.len();

        let mut lines: Vec<String> = hashes
            .iter()
            .map(|(path, hash)| format!("{}  {}", hash, path))
            .collect();
        lines.sort();

        let content = lines.join("\n") + "\n";
        std::fs::write(baseline_path, content)?;

        let msg = format!("[+] binary_integrity: baseline created with {} entries", n);
        ctx.log_msg(&msg);

        ctx.emit(
            Finding::new(
                Severity::Info,
                "binary_integrity",
                format!("Binary baseline created — {} binaries hashed", n),
                format!(
                    "Baseline written to {}. Future runs will compare against this snapshot.",
                    BASELINE_PATH
                ),
            )
            .with_verdict(Verdict::Info, "Baseline created successfully."),
        );

        return Ok(());
    }

    // Check mode — baseline exists.
    let baseline_content = std::fs::read_to_string(baseline_path)?;
    let baseline = parse_baseline(&baseline_content);

    let current = scan_all();

    // Detect deleted and modified binaries (entries in baseline).
    for (path, baseline_hash) in &baseline {
        let p = Path::new(path);
        if !p.exists() {
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "binary_integrity",
                    format!("system binary deleted: {}", path),
                    format!("A system binary recorded in the baseline no longer exists: {}", path),
                )
                .with_path(PathBuf::from(path))
                .with_verdict(Verdict::Investigate, "Determine whether the binary was removed by a package manager update or deliberately deleted by an attacker."),
            );
        } else if let Some(current_hash) = current.get(path) {
            if current_hash != baseline_hash {
                ctx.log_evidence_file(p);
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "binary_integrity",
                        format!("system binary MODIFIED: {}", path),
                        format!(
                            "SHA-256 mismatch for {}.\n  baseline: {}\n  current:  {}",
                            path, baseline_hash, current_hash
                        ),
                    )
                    .with_path(PathBuf::from(path))
                    .with_context("baseline_hash", baseline_hash.clone())
                    .with_context("current_hash", current_hash.clone())
                    .with_verdict(Verdict::Investigate, "This binary has been replaced or patched since the baseline was taken. Treat it as compromised."),
                );
            }
        }
    }

    // Detect new executables not in the baseline.
    for (path, _hash) in &current {
        if !baseline.contains_key(path) {
            ctx.emit(
                Finding::new(
                    Severity::Medium,
                    "binary_integrity",
                    format!("new binary appeared: {}", path),
                    format!("Executable {} was not present when the baseline was taken.", path),
                )
                .with_path(PathBuf::from(path))
                .with_verdict(Verdict::Investigate, "Verify this binary was installed by a known package manager update and is not a backdoor left by an attacker."),
            );
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_baseline ────────────────────────────────────────────────────────

    #[test]
    fn parse_baseline_empty() {
        let map = parse_baseline("");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_baseline_single_entry() {
        let line =
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc1  /usr/bin/ls\n";
        let map = parse_baseline(line);
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get("/usr/bin/ls").map(|s| s.as_str()),
            Some("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
        );
    }

    #[test]
    fn parse_baseline_multiple_entries() {
        let content = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /bin/sh\n",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /usr/bin/sudo\n",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  /usr/bin/passwd\n",
        );
        let map = parse_baseline(content);
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("/bin/sh"));
        assert!(map.contains_key("/usr/bin/sudo"));
        assert!(map.contains_key("/usr/bin/passwd"));
    }

    #[test]
    fn parse_baseline_ignores_blank_lines() {
        let content =
            "\n\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /bin/ls\n\n";
        let map = parse_baseline(content);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn parse_baseline_ignores_malformed_lines() {
        // Single-space separator is not valid sha256sum format — should be ignored.
        let content = "badentry /usr/bin/bad\n";
        let map = parse_baseline(content);
        assert!(
            map.is_empty(),
            "malformed line (single space) should be ignored"
        );
    }

    // ── Change detection ──────────────────────────────────────────────────────

    #[test]
    fn detect_modified_binary() {
        let baseline_content =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/bin/sudo\n";
        let baseline = parse_baseline(baseline_content);
        let mut current: HashMap<String, String> = HashMap::new();
        current.insert(
            "/usr/bin/sudo".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );

        let mut modified = Vec::new();
        for (path, b_hash) in &baseline {
            if let Some(c_hash) = current.get(path) {
                if c_hash != b_hash {
                    modified.push(path.clone());
                }
            }
        }
        assert_eq!(modified, vec!["/usr/bin/sudo"]);
    }

    #[test]
    fn detect_deleted_binary() {
        let baseline_content =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/bin/ls\n";
        let baseline = parse_baseline(baseline_content);
        let current: HashMap<String, String> = HashMap::new(); // ls is gone

        let deleted: Vec<_> = baseline
            .keys()
            .filter(|path| !current.contains_key(*path))
            .collect();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0], "/usr/bin/ls");
    }

    #[test]
    fn detect_new_binary() {
        let baseline: HashMap<String, String> = HashMap::new(); // empty baseline
        let mut current: HashMap<String, String> = HashMap::new();
        current.insert(
            "/usr/bin/newcmd".to_string(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        );

        let new_binaries: Vec<_> = current
            .keys()
            .filter(|path| !baseline.contains_key(*path))
            .collect();
        assert_eq!(new_binaries.len(), 1);
        assert_eq!(new_binaries[0], "/usr/bin/newcmd");
    }

    #[test]
    fn no_change_when_hashes_match() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let baseline_content = format!("{}  /usr/bin/ls\n", hash);
        let baseline = parse_baseline(&baseline_content);
        let mut current: HashMap<String, String> = HashMap::new();
        current.insert("/usr/bin/ls".to_string(), hash.to_string());

        let modified: Vec<_> = baseline
            .iter()
            .filter(|(path, b_hash)| current.get(*path).map_or(false, |c| c != *b_hash))
            .collect();
        assert!(modified.is_empty());
    }

    // ── sha256_hex correctness ────────────────────────────────────────────────

    #[test]
    fn sha256_known_vector_empty() {
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_known_vector_abc() {
        let result = sha256_hex(b"abc");
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
