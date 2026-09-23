//! Webshells under the web root.
//!
//! One PHP file that passes a request parameter to a shell gives an attacker
//! command execution as the web server user, reachable from anywhere the site
//! is. Files are scored by how many distinct command-execution primitives
//! they contain, so a dense shell sorts above an incidental `eval`.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::{DefenderContext, Result, prompt_yes, require_root};

/// Directory tree served by the web server.
const WEB_ROOT: &str = "/var/www/html";

/// PHP primitives a webshell needs to execute commands.
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "exec",
    "passthru",
    "shell_exec",
    "system",
    "proc_open",
    "popen",
    "pcntl_exec",
    "eval",
];

/// A web-root file containing webshell primitives.
pub struct SuspiciousFile {
    /// Path to the file.
    pub location: PathBuf,
    /// Number of distinct primitives matched.
    pub score: u16,
    /// Which primitives matched.
    pub keywords: Vec<String>,
}

/// Score files under the web root against known webshell primitives.
pub fn run(ctx: &DefenderContext) -> Result {
    let web_root = Path::new(WEB_ROOT);
    if !web_root.exists() {
        println!("[!] {} does not exist, skipping web shell check", WEB_ROOT);
        return Ok(());
    }

    let shells = find_shells(web_root);
    ctx.debug(&format!("Scanned {}, {} hit(s)", WEB_ROOT, shells.len()));

    let is_root = require_root().is_ok();

    for shell in shells {
        println!(
            "\n[!] Warning: Found suspicious file at {}, with a score of {}",
            shell.location.display(),
            shell.score
        );
        println!("[!] Keywords found were {}", shell.keywords.join(", "));

        if !is_root {
            println!("[!] Not running as root — skipping deletion option.");
            continue;
        }

        if prompt_yes("[?] Would you like to delete the file? (y/N)")? {
            match fs::remove_file(&shell.location) {
                Ok(()) => println!("[+] File removed successfully."),
                Err(e) => eprintln!("[X] Failed to remove file: {}", e),
            }
        }
    }

    Ok(())
}

/// Scan `root` recursively for files containing known webshell primitives.
pub fn find_shells(root: &Path) -> Vec<SuspiciousFile> {
    let mut shells = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Ok(content) = fs::read_to_string(path) else {
            continue; // unreadable or non-UTF-8
        };

        if let Some(hit) = score_content(path, &content) {
            shells.push(hit);
        }
    }

    shells
}

/// Score one file, or `None` when no primitive matched.
fn score_content(path: &Path, content: &str) -> Option<SuspiciousFile> {
    let lowered = content.to_lowercase();

    let keywords: Vec<String> = SUSPICIOUS_KEYWORDS
        .iter()
        .filter(|kw| lowered.contains(**kw))
        .map(|kw| (*kw).to_string())
        .collect();

    if keywords.is_empty() {
        return None;
    }

    Some(SuspiciousFile {
        location: path.to_path_buf(),
        score: keywords.len() as u16,
        keywords,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_file_scores_nothing() {
        assert!(score_content(Path::new("a.php"), "<?php echo 'hi'; ?>").is_none());
    }

    #[test]
    fn counts_each_distinct_keyword_once() {
        let content = "<?php system($_GET['c']); eval($x); system($y); ?>";
        let hit = score_content(Path::new("shell.php"), content).unwrap();
        assert_eq!(hit.score, 2);
        assert!(hit.keywords.contains(&"system".to_string()));
        assert!(hit.keywords.contains(&"eval".to_string()));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let hit = score_content(Path::new("s.php"), "SHELL_EXEC($cmd);").unwrap();
        assert!(hit.keywords.contains(&"shell_exec".to_string()));
    }
}
