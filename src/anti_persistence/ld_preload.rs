//! `LD_PRELOAD` hijacking.
//!
//! A library listed in `/etc/ld.so.preload` is loaded into every dynamically
//! linked process on the system, which makes it one of the most powerful
//! rootkit footholds available. The file is absent on a stock install, so any
//! content at all is worth an operator's attention.

use std::env;
use std::fs;
use std::path::Path;

use crate::core::scan::{effective_line, read_text_file};
use crate::core::{DefenderContext, Finding, Result, Severity, prompt_yes, require_root};

/// Path to the system-wide loader preload configuration file.
const PRELOAD_FILE: &str = "/etc/ld.so.preload";

/// Check `/etc/ld.so.preload` and `$LD_PRELOAD` for loader hijacking.
pub fn run(ctx: &DefenderContext) -> Result {
    check_preload_file(ctx)?;
    check_environment(ctx);
    Ok(())
}

/// Inspect `/etc/ld.so.preload` for injected library paths and offer removal.
fn check_preload_file(ctx: &DefenderContext) -> Result {
    let path = Path::new(PRELOAD_FILE);

    let Some(contents) = read_text_file(path) else {
        ctx.log_msg(&format!("[✓] {} is absent", PRELOAD_FILE));
        return Ok(());
    };

    let entries = parse_preload(&contents);
    ctx.debug(&format!("{} has {} entry(s)", PRELOAD_FILE, entries.len()));

    if entries.is_empty() {
        ctx.log_msg(&format!("[✓] {} exists but is empty", PRELOAD_FILE));
        return Ok(());
    }

    let missing: Vec<&str> = entries
        .iter()
        .filter(|e| !Path::new(e.as_str()).exists())
        .map(|e| e.as_str())
        .collect();

    let detail = format!(
        "Libraries: {}\nMissing from disk: {}",
        entries.join(", "),
        if missing.is_empty() {
            "none".to_string()
        } else {
            missing.join(", ")
        }
    );

    if ctx.in_tui() {
        let is_root = require_root().is_ok();

        // Capture the preload file content as evidence before any changes.
        ctx.log_evidence_file(path);

        let mut removed = false;
        if is_root {
            let mut all_ok = true;
            for entry in &entries {
                let lib_path = Path::new(entry.as_str());
                if lib_path.exists() && !ctx.remove_path_logged(lib_path) {
                    all_ok = false;
                }
                if !ctx.remove_line_from_file_logged(path, entry) {
                    all_ok = false;
                }
            }
            removed = all_ok;
        }

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "ld_preload",
                format!(
                    "{} preloads {} library(s) into every process",
                    PRELOAD_FILE,
                    entries.len()
                ),
                detail,
            )
            .with_path(path.to_path_buf())
            .with_context("removed", removed.to_string()),
        );
    } else {
        println!(
            "[!] {} preloads {} library(s) into every process:",
            PRELOAD_FILE,
            entries.len()
        );
        for entry in &entries {
            let exists_tag = if Path::new(entry).exists() {
                ""
            } else {
                "  (missing from disk)"
            };
            println!("    - {}{}", entry, exists_tag);
        }
        println!("[!] This file is empty or absent on a stock system.");

        if require_root().is_err() {
            println!("[!] Not running as root — skipping removal option.");
            return Ok(());
        }

        if prompt_yes(&format!("[?] Remove {}? (y/N)", PRELOAD_FILE))? {
            fs::remove_file(path)?;
            println!("[+] Removed {}", PRELOAD_FILE);
        }
    }

    Ok(())
}

/// Check whether `$LD_PRELOAD` is set in the current process environment.
fn check_environment(ctx: &DefenderContext) {
    match env::var("LD_PRELOAD") {
        Ok(value) if !value.trim().is_empty() => {
            ctx.emit(Finding::new(
                Severity::High,
                "ld_preload",
                format!("$LD_PRELOAD is set in this shell: {}", value),
                "Run `unset LD_PRELOAD` and trace where it was exported from.",
            ));
        }
        _ => ctx.log_msg("[✓] $LD_PRELOAD is not set"),
    }
}

/// Parse non-comment lines from a preload file into a list of library paths.
fn parse_preload(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(effective_line)
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_has_no_entries() {
        assert!(parse_preload("").is_empty());
        assert!(parse_preload("\n\n   \n").is_empty());
    }

    #[test]
    fn reads_one_library_per_line() {
        let entries = parse_preload("/lib/evil.so\n/usr/lib/other.so\n");
        assert_eq!(entries, vec!["/lib/evil.so", "/usr/lib/other.so"]);
    }

    #[test]
    fn reads_space_separated_libraries() {
        let entries = parse_preload("/lib/a.so /lib/b.so\n");
        assert_eq!(entries, vec!["/lib/a.so", "/lib/b.so"]);
    }

    #[test]
    fn ignores_comments() {
        let entries = parse_preload("# installed by the admin\n/lib/real.so\n");
        assert_eq!(entries, vec!["/lib/real.so"]);
    }
}
