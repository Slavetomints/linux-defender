//! Privilege checks, account lookup, and operator prompts.
//!
//! Account lookup reads the real home directory out of `/etc/passwd` rather
//! than assuming `/home/<user>`, which is wrong for service accounts.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use nix::unistd::Uid;

use super::{DefenderError, Result};

/// Error with [`DefenderError::NotRoot`] unless the process is root.
pub fn require_root() -> Result {
    if !Uid::effective().is_root() {
        return Err(DefenderError::NotRoot);
    }
    Ok(())
}

/// A local account as described by `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    /// Login name.
    pub name: String,
    /// Home directory as `/etc/passwd` records it.
    pub home: PathBuf,
    /// Login shell; service accounts use `nologin` or `false`.
    pub shell: String,
}

impl UserAccount {
    /// Whether this account can actually log in. Service accounts are pinned
    /// to `nologin` or `false`, and their dotfiles are not an attack surface
    /// worth prompting an operator about.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use defender_cli::core::UserAccount;
    ///
    /// let alice = UserAccount {
    ///     name: "alice".into(),
    ///     home: PathBuf::from("/home/alice"),
    ///     shell: "/bin/bash".into(),
    /// };
    /// let daemon = UserAccount {
    ///     name: "daemon".into(),
    ///     home: PathBuf::from("/usr/sbin"),
    ///     shell: "/usr/sbin/nologin".into(),
    /// };
    ///
    /// assert!(alice.can_log_in());
    /// assert!(!daemon.can_log_in());
    /// ```
    pub fn can_log_in(&self) -> bool {
        !self.shell.is_empty()
            && !self.shell.ends_with("/nologin")
            && !self.shell.ends_with("/false")
            && !self.shell.ends_with("/sync")
    }
}

/// Read every username from `/etc/passwd`.
pub fn collect_users() -> Result<Vec<String>> {
    Ok(collect_accounts()?.into_iter().map(|a| a.name).collect())
}

/// Read every account from `/etc/passwd`, including its real home directory.
///
/// Prefer this over assuming `/home/<user>`; accounts routinely live elsewhere.
pub fn collect_accounts() -> Result<Vec<UserAccount>> {
    Ok(parse_passwd(&fs::read_to_string("/etc/passwd")?))
}

/// Parse `/etc/passwd` content: `name:passwd:uid:gid:gecos:home:shell`.
fn parse_passwd(contents: &str) -> Vec<UserAccount> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 || fields[0].is_empty() {
                return None;
            }
            Some(UserAccount {
                name: fields[0].to_string(),
                home: PathBuf::from(fields[5]),
                shell: fields[6].to_string(),
            })
        })
        .collect()
}

/// Attempt to clear the immutable flag on `path` before a removal.
///
/// Runs `chattr -i <path>` and silently ignores all errors — the file may not
/// be on an ext4 filesystem, or the process may lack the privilege. Callers
/// should attempt this before any `rm` or file-write operation so that a
/// red-team `chattr +i` does not silently defeat remediation.
pub fn try_clear_immutable(path: &std::path::Path) {
    let _ = std::process::Command::new("chattr")
        .args(["-i", &path.to_string_lossy()])
        .output();
}

/// Ask the operator a yes/no question. Anything but `y` is treated as no.
pub fn prompt_yes(question: &str) -> Result<bool> {
    print!("{}\n> ", question);
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

/// Ask the operator for a free-form string value.
pub fn prompt_string(question: &str) -> Result<String> {
    print!("{}\n> ", question);
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    Ok(answer.trim().to_string())
}

/// Ask for a string value, using `default` if the operator presses Enter.
pub fn prompt_string_default(question: &str, default: &str) -> Result<String> {
    print!("{} [{}]\n> ", question, default);
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    let trimmed = answer.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
weird:x:1001:1001:Weird:/var/lib/weird:/bin/sh
";

    #[test]
    fn parses_name_home_and_shell() {
        let accounts = parse_passwd(SAMPLE);

        assert_eq!(accounts.len(), 4);
        assert_eq!(accounts[0].name, "root");
        assert_eq!(accounts[0].home, PathBuf::from("/root"));
        assert_eq!(accounts[2].home, PathBuf::from("/home/alice"));
    }

    #[test]
    fn honours_non_standard_home_directories() {
        let accounts = parse_passwd(SAMPLE);
        let weird = accounts.iter().find(|a| a.name == "weird").unwrap();

        assert_eq!(weird.home, PathBuf::from("/var/lib/weird"));
    }

    #[test]
    fn service_accounts_are_not_login_capable() {
        let accounts = parse_passwd(SAMPLE);

        assert!(
            accounts
                .iter()
                .find(|a| a.name == "root")
                .unwrap()
                .can_log_in()
        );
        assert!(
            accounts
                .iter()
                .find(|a| a.name == "alice")
                .unwrap()
                .can_log_in()
        );
        assert!(
            !accounts
                .iter()
                .find(|a| a.name == "daemon")
                .unwrap()
                .can_log_in()
        );
    }

    #[test]
    fn skips_blank_comment_and_malformed_lines() {
        let accounts = parse_passwd("\n# a comment\nbroken:x:1\n\nroot:x:0:0::/root:/bin/sh\n");

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "root");
    }
}

/// Strip ANSI/VT100 escape sequences so raw output renders cleanly in ratatui.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some(&'[') => {
                    chars.next();
                    for c2 in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c2) {
                            break;
                        }
                    }
                }
                Some(&']') => {
                    chars.next();
                    for c2 in chars.by_ref() {
                        if c2 == '\x07' || c2 == '\x1b' {
                            break;
                        }
                    }
                }
                _ => { chars.next(); }
            }
        } else {
            out.push(c);
        }
    }
    out
}
