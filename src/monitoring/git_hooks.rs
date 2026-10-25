//! Detect malicious git hooks that execute code on common git operations.
//!
//! Git hooks are shell scripts (or binaries) that run automatically when the
//! developer executes common commands like `git commit`, `git push`, or
//! `git merge`.  Attackers plant hooks to establish persistence or exfiltrate
//! data every time any developer touches the repository.
//!
//! This module walks common repository root directories up to depth 4, locates
//! every hook file that is executable, and flags suspicious content or binary
//! hooks.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Well-known hook names defined by git.
const HOOK_NAMES: &[&str] = &[
    "pre-commit",
    "post-commit",
    "pre-push",
    "post-receive",
    "post-merge",
    "pre-rebase",
    "post-checkout",
    "update",
    "post-update",
    "pre-applypatch",
    "applypatch-msg",
];

/// Top-level directories to search for git repositories.
const SEARCH_ROOTS: &[&str] = &["/root", "/var/www", "/opt", "/srv"];

/// Substrings in hook content that are always suspicious.
const SUSPICIOUS_STRINGS: &[(&str, Severity)] = &[
    ("/dev/tcp/", Severity::Critical), // reverse shell
    ("mkfifo", Severity::Critical),    // named pipe — common in reverse shells
    ("bash -i", Severity::Critical),   // interactive bash (reverse shell)
    ("sh -c", Severity::High),         // arbitrary command execution
    ("exec", Severity::High),          // exec replaces the process
    ("eval", Severity::High),          // eval executes a string
    ("/tmp/", Severity::Critical),     // staging in /tmp
    ("/dev/shm/", Severity::Critical), // staging in shared memory
    ("curl", Severity::High),          // network download
    ("wget", Severity::High),          // network download
    ("nc ", Severity::High),           // netcat (note trailing space to avoid matching "include")
    ("ncat", Severity::High),          // ncat
    ("base64", Severity::High),        // encoded payload
    ("python -c", Severity::High),     // Python one-liner
    ("perl -e", Severity::High),       // Perl one-liner
];

// ── Repository discovery ──────────────────────────────────────────────────────

/// Whether `dir` is a git repository (has a `.git/` subdirectory).
fn is_git_repo(dir: &Path) -> bool {
    dir.join(".git").is_dir()
}

/// Whether `dir` looks like a bare git repository
/// (contains `hooks/` and `config` directly, but no working tree).
fn is_bare_repo(dir: &Path) -> bool {
    dir.join("hooks").is_dir() && dir.join("config").is_file()
}

/// Collect home directories from `/etc/passwd`.
fn home_dirs_from_passwd() -> Vec<PathBuf> {
    let Ok(content) = std::fs::read_to_string("/etc/passwd") else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(7, ':').collect();
            if parts.len() >= 6 {
                let home = PathBuf::from(parts[5]);
                if home.is_dir() { Some(home) } else { None }
            } else {
                None
            }
        })
        .collect()
}

/// Walk `root` up to `max_depth` looking for git repositories.
/// Returns pairs of (repo_root, hooks_directory).
fn find_repos(root: &Path, max_depth: u32) -> Vec<(PathBuf, PathBuf)> {
    let mut found = Vec::new();
    if max_depth == 0 {
        return found;
    }

    if is_git_repo(root) {
        found.push((root.to_path_buf(), root.join(".git").join("hooks")));
        return found; // don't descend into a repo's own subtree
    }
    if is_bare_repo(root) {
        found.push((root.to_path_buf(), root.join("hooks")));
        return found;
    }

    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && !path.is_symlink() {
            found.extend(find_repos(&path, max_depth - 1));
        }
    }
    found
}

// ── Hook analysis ─────────────────────────────────────────────────────────────

/// Classification of a hook file.
/// Result of inspecting a git hook file.
#[derive(Debug)]
enum HookVerdict {
    /// Hook looks benign.
    Clean,
    /// Hook matched a suspicious pattern.
    Suspicious {
        /// Severity of the most serious pattern matched.
        severity: Severity,
        /// Human-readable description of what was found.
        reason: String,
    },
}

/// Inspect the content of a hook file and return the worst issue found, if any.
fn analyse_hook(content: &[u8], path: &Path) -> HookVerdict {
    // A non-shell-script executable (no `#!` shebang) is highly suspicious —
    // ELF binaries in a hooks directory are almost never legitimate.
    let starts_with_shebang = content.starts_with(b"#!");
    if !starts_with_shebang {
        return HookVerdict::Suspicious {
            severity: Severity::Critical,
            reason: format!(
                "hook {} has no shebang — likely an ELF binary planted as a hook",
                path.display()
            ),
        };
    }

    // Scan text content for suspicious substrings.
    let text = String::from_utf8_lossy(content);
    let mut worst_severity: Option<Severity> = None;
    let mut worst_reason = String::new();

    for (pattern, sev) in SUSPICIOUS_STRINGS {
        if text.contains(pattern) {
            let is_worse = worst_severity.is_none_or(|prev: Severity| *sev < prev); // Critical < High < Medium < Info
            if is_worse {
                worst_severity = Some(*sev);
                worst_reason = format!(
                    "hook {} contains suspicious pattern {:?}",
                    path.display(),
                    pattern
                );
            }
        }
    }

    if let Some(severity) = worst_severity {
        HookVerdict::Suspicious {
            severity,
            reason: worst_reason,
        }
    } else {
        HookVerdict::Clean
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Scan all git repositories for malicious hooks.
pub fn run(ctx: &DefenderContext) -> Result {
    // Build the list of root directories to search.
    let mut search_roots: Vec<PathBuf> = home_dirs_from_passwd();
    for root in SEARCH_ROOTS {
        let p = PathBuf::from(root);
        if p.is_dir() {
            search_roots.push(p);
        }
    }

    // De-duplicate (e.g. /root might be in both passwd and SEARCH_ROOTS).
    search_roots.sort();
    search_roots.dedup();

    for root in &search_roots {
        for (_repo, hooks_dir) in find_repos(root, 4) {
            if !hooks_dir.is_dir() {
                continue;
            }

            for hook_name in HOOK_NAMES {
                let hook_path = hooks_dir.join(hook_name);
                if !hook_path.exists() {
                    continue;
                }

                // Only flag executable hooks (sample files shipped by git are
                // non-executable on purpose).
                let Ok(meta) = hook_path.metadata() else {
                    continue;
                };
                if meta.permissions().mode() & 0o111 == 0 {
                    continue;
                }

                let content = match std::fs::read(&hook_path) {
                    Ok(b) => b,
                    Err(e) => {
                        ctx.log_msg(&format!(
                            "[-] git_hooks: could not read {}: {}",
                            hook_path.display(),
                            e
                        ));
                        continue;
                    }
                };

                match analyse_hook(&content, &hook_path) {
                    HookVerdict::Clean => {}
                    HookVerdict::Suspicious { severity, reason } => {
                        ctx.log_evidence_file(&hook_path);

                        let should_remove = matches!(severity, Severity::Critical | Severity::High);
                        if should_remove {
                            ctx.remove_path_logged(&hook_path);
                        }

                        ctx.emit(
                            Finding::new(severity, "git_hooks", reason.clone(), reason)
                                .with_path(hook_path.clone())
                                .with_verdict(
                                    Verdict::Remove,
                                    "Malicious git hooks execute on every matching git operation. Remove the hook file to disable the trigger.",
                                ),
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
