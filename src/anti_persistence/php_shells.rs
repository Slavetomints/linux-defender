//! Webshells under the web root.
//!
//! Checks for known named shells first (p0wny, WSO, b374k, c99, weevely, etc.)
//! by matching all their distinguishing patterns. Unknown shells are scored by
//! how many distinct command-execution primitives they contain.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::{
    Action, DefenderContext, Finding, Result, Severity, Verdict, require_root,
};

const WEB_ROOT: &str = "/var/www/html";

/// A named shell family: every pattern must match (case-insensitive AND).
struct ShellSignature {
    name: &'static str,
    patterns: &'static [&'static str],
}

const KNOWN_SHELLS: &[ShellSignature] = &[
    ShellSignature {
        name: "p0wny-shell",
        patterns: &["p0wny@shell", "$_server['http_host']"],
    },
    ShellSignature {
        name: "b374k",
        patterns: &["b374k", "$auth_pass"],
    },
    ShellSignature {
        name: "c99shell",
        patterns: &["c99shell", "filesman"],
    },
    ShellSignature {
        name: "r57shell",
        patterns: &["r57shell"],
    },
    ShellSignature {
        name: "WSO",
        patterns: &["wso", "wso_ver"],
    },
    ShellSignature {
        name: "weevely",
        patterns: &["@eval(base64_decode", "$kh="],
    },
    ShellSignature {
        name: "alfa-shell",
        patterns: &["alfa shell", "a1fav4r"],
    },
];

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
    /// Path to the suspicious file.
    pub location: PathBuf,
    /// Number of distinct command-execution primitives matched.
    pub score: u16,
    /// Which primitives matched.
    pub keywords: Vec<String>,
    /// Named shell family if any signature matched; `None` for generic matches.
    pub matched_shell_name: Option<&'static str>,
}

/// Score files under the web root against known webshell primitives.
///
/// For each confirmed shell (named family OR score ≥ 3 when running as root):
///   1. Log file content as evidence
///   2. Delete the file
///   3. Verify deletion and log proof
///
/// Low-confidence hits (score < 3, no named match) are emitted as findings
/// for operator review without automatic deletion.
pub fn run(ctx: &DefenderContext) -> Result {
    let web_root = Path::new(WEB_ROOT);
    if !web_root.exists() {
        ctx.log_msg(&format!("[!] {} does not exist, skipping web shell check", WEB_ROOT));
        return Ok(());
    }

    let shells = find_shells(web_root);
    ctx.debug(&format!("Scanned {}, {} hit(s)", WEB_ROOT, shells.len()));

    let is_root = require_root().is_ok();

    for shell in shells {
        let name_tag = shell
            .matched_shell_name
            .map(|n| format!("{} — ", n))
            .unwrap_or_default();

        let severity = if shell.matched_shell_name.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };

        let mtime_label = shell
            .location
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| ctx.mtime_label(t))
            .unwrap_or_else(|| "unknown".into());

        // Determine whether to auto-remove: known shell OR score ≥ 3, with root.
        let auto_remove = is_root && (shell.matched_shell_name.is_some() || shell.score >= 3);

        if auto_remove {
            // Phase 1: log evidence
            ctx.log_msg(&format!(
                "[!] {}PHP webshell detected: {} (keywords: {})",
                name_tag,
                shell.location.display(),
                shell.keywords.join(", "),
            ));
            ctx.log_evidence_file(&shell.location);

            // Phase 2: remove
            let removed = ctx.remove_path_logged(&shell.location);

            let summary = format!(
                "{}PHP webshell REMOVED: {}",
                name_tag,
                shell.location.display(),
            );
            let detail = format!(
                "path: {}\nmatched keywords: {}\nremoved: {}",
                shell.location.display(),
                shell.keywords.join(", "),
                removed,
            );

            let mut finding = Finding::new(severity, "php_shells", summary, detail)
                .with_path(shell.location.clone())
                .with_context("path", shell.location.display().to_string())
                .with_context("score", shell.score.to_string())
                .with_context("keywords", shell.keywords.join(", "))
                .with_context("mtime", mtime_label)
                .with_context("removed", removed.to_string())
                .with_verdict(
                    Verdict::Remove,
                    if removed {
                        "File was automatically deleted. Evidence and proof logged above.".to_string()
                    } else {
                        "Deletion attempted but file may still exist — check the log.".to_string()
                    },
                );
            if let Some(name) = shell.matched_shell_name {
                finding = finding.with_context("shell name", name);
            }
            ctx.emit(finding);
        } else {
            // Low-confidence hit or non-root: report only.
            let summary = format!(
                "{}suspicious PHP (score:{}) at {}",
                name_tag,
                shell.score,
                shell.location.display()
            );
            let detail = format!(
                "path: {}\nmatched keywords: {}",
                shell.location.display(),
                shell.keywords.join(", ")
            );

            ctx.log_evidence_file(&shell.location);

            let verdict = if shell.matched_shell_name.is_some() || shell.score >= 3 {
                Verdict::Remove
            } else {
                Verdict::Investigate
            };
            let recommendation = if let Some(name) = shell.matched_shell_name {
                format!(
                    "{} is a well-known webshell that gives the attacker an interactive \
                     shell via HTTP — any visitor can run arbitrary commands as the web \
                     server user. Delete this file immediately.",
                    name
                )
            } else {
                format!(
                    "This PHP file contains {} command-execution primitive(s): {}. \
                     A score of 3 or more is a strong indicator of a webshell. \
                     Verify the file is expected before deleting.",
                    shell.score,
                    shell.keywords.join(", ")
                )
            };

            let mut finding = Finding::new(severity, "php_shells", summary, detail)
                .with_path(shell.location.clone())
                .with_context("path", shell.location.display().to_string())
                .with_context("score", shell.score.to_string())
                .with_context("keywords", shell.keywords.join(", "))
                .with_context("mtime", mtime_label)
                .with_verdict(verdict, recommendation);
            if let Some(name) = shell.matched_shell_name {
                finding = finding.with_context("shell name", name);
            }
            if is_root {
                finding = finding.with_action(Action::Delete(shell.location));
            }
            ctx.emit(finding);
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
            continue;
        };

        if let Some(hit) = score_content(path, &content) {
            shells.push(hit);
        }
    }

    shells
}

/// Score one file, or `None` when no primitive matched.
pub fn score_content(path: &Path, content: &str) -> Option<SuspiciousFile> {
    let lowered = content.to_lowercase();

    // Named signature check first.
    let matched_name = KNOWN_SHELLS
        .iter()
        .find(|sig| sig.patterns.iter().all(|p| lowered.contains(*p)))
        .map(|sig| sig.name);

    let keywords: Vec<String> = SUSPICIOUS_KEYWORDS
        .iter()
        .filter(|kw| lowered.contains(**kw))
        .map(|kw| (*kw).to_string())
        .collect();

    if keywords.is_empty() && matched_name.is_none() {
        return None;
    }

    Some(SuspiciousFile {
        location: path.to_path_buf(),
        score: keywords.len() as u16,
        keywords,
        matched_shell_name: matched_name,
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

    #[test]
    fn detects_p0wny_by_name() {
        let content = r#"<?php $p0wny@shell; $_SERVER['HTTP_HOST']; system($_GET['c']); ?>"#;
        let hit = score_content(Path::new("x.php"), content).unwrap();
        assert_eq!(hit.matched_shell_name, Some("p0wny-shell"));
    }

    #[test]
    fn detects_wso_by_name() {
        let content = "wso wso_ver eval($_POST['cmd']);";
        let hit = score_content(Path::new("x.php"), content).unwrap();
        assert_eq!(hit.matched_shell_name, Some("WSO"));
    }
}
