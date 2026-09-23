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
use crate::core::{DefenderContext, Result, prompt_yes, require_root};

/// Libraries here are loaded into every dynamically linked process.
const PRELOAD_FILE: &str = "/etc/ld.so.preload";

/// Check `/etc/ld.so.preload` and `$LD_PRELOAD` for loader hijacking.
pub fn run(ctx: &DefenderContext) -> Result {
    check_preload_file(ctx)?;
    check_environment();
    Ok(())
}

/// Report and optionally remove `/etc/ld.so.preload`.
fn check_preload_file(ctx: &DefenderContext) -> Result {
    let path = Path::new(PRELOAD_FILE);

    let Some(contents) = read_text_file(path) else {
        println!("[✓] {} is absent", PRELOAD_FILE);
        return Ok(());
    };

    let entries = parse_preload(&contents);
    ctx.debug(&format!("{} has {} entry(s)", PRELOAD_FILE, entries.len()));

    if entries.is_empty() {
        println!("[✓] {} exists but is empty", PRELOAD_FILE);
        return Ok(());
    }

    println!(
        "[!] {} preloads {} library(s) into every process:",
        PRELOAD_FILE,
        entries.len()
    );
    for entry in &entries {
        let exists = if Path::new(entry).exists() {
            ""
        } else {
            "  (missing from disk)"
        };
        println!("    - {}{}", entry, exists);
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

    Ok(())
}

/// Report `$LD_PRELOAD` set in the current environment.
fn check_environment() {
    match env::var("LD_PRELOAD") {
        Ok(value) if !value.trim().is_empty() => {
            println!("[!] $LD_PRELOAD is set in this shell: {}", value);
            println!("[!] Run `unset LD_PRELOAD` and check where it was exported from.");
        }
        _ => println!("[✓] $LD_PRELOAD is not set"),
    }
}

/// Library paths listed in `ld.so.preload`. Entries are whitespace or
/// newline separated; `#` comments are not honoured by the loader but are
/// commonly present, so they are ignored here too.
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
