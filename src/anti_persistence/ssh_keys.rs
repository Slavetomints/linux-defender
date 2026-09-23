//! Backdoor keys in `authorized_keys`.
//!
//! An added public key is persistent, survives password changes, and looks
//! entirely ordinary. Each account's file is summarised key by key — type and
//! comment, not the base64 body — so the operator can see what a key claims to
//! be before deciding.

use std::fs;
use std::path::PathBuf;

use crate::core::{
    DefenderContext, DefenderError, Result, UserAccount, collect_accounts, prompt_yes, require_root,
};

/// Review each account's `authorized_keys` and remove the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        eprintln!("[!] Not running as root - stopping ssh_keys check.");
        return Err(DefenderError::NotRoot);
    }

    println!("[+] Checking SSH authorized_keys...");

    for account in collect_accounts()? {
        let keyfile = authorized_keys_path(&account);
        ctx.debug(&format!("Checking {}", keyfile.display()));

        if !keyfile.exists() {
            continue;
        }

        let contents = fs::read_to_string(&keyfile).unwrap_or_default();
        let keys = parse_authorized_keys(&contents);

        println!(
            "[!] {} has {} authorized key(s) at {}",
            account.name,
            keys.len(),
            keyfile.display()
        );
        for key in &keys {
            println!("    - {}", key);
        }

        if prompt_yes("[?] Remove this authorized_keys file? (y/N)")? {
            fs::remove_file(&keyfile)?;
            println!("[+] Removed {}", keyfile.display());
        }
    }

    Ok(())
}

/// Where an account's `authorized_keys` lives, using the home directory
/// `/etc/passwd` actually assigns rather than assuming `/home/<user>`.
fn authorized_keys_path(account: &UserAccount) -> PathBuf {
    account.home.join(".ssh").join("authorized_keys")
}

/// Summarise each key as `<type> <comment>`, dropping the key body so the
/// operator sees who a key claims to belong to without a wall of base64.
fn parse_authorized_keys(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                [] => String::new(),
                [only] => (*only).to_string(),
                [kind, _body] => (*kind).to_string(),
                [kind, _body, comment @ ..] => format!("{} {}", kind, comment.join(" ")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn account(name: &str, home: &str) -> UserAccount {
        UserAccount {
            name: name.to_string(),
            home: PathBuf::from(home),
            shell: "/bin/bash".to_string(),
        }
    }

    #[test]
    fn uses_the_home_directory_from_passwd() {
        assert_eq!(
            authorized_keys_path(&account("root", "/root")),
            Path::new("/root/.ssh/authorized_keys")
        );
        assert_eq!(
            authorized_keys_path(&account("alice", "/home/alice")),
            Path::new("/home/alice/.ssh/authorized_keys")
        );
    }

    #[test]
    fn honours_a_non_standard_home() {
        assert_eq!(
            authorized_keys_path(&account("svc", "/var/lib/svc")),
            Path::new("/var/lib/svc/.ssh/authorized_keys")
        );
    }

    #[test]
    fn summarises_keys_without_the_body() {
        let keys = parse_authorized_keys(
            "ssh-rsa AAAAB3NzaC1yc2EAAAA alice@laptop\nssh-ed25519 AAAAC3NzaC1l attacker@evil\n",
        );

        assert_eq!(
            keys,
            vec!["ssh-rsa alice@laptop", "ssh-ed25519 attacker@evil"]
        );
    }

    #[test]
    fn handles_a_key_with_no_comment() {
        let keys = parse_authorized_keys("ssh-rsa AAAAB3NzaC1yc2EAAAA\n");
        assert_eq!(keys, vec!["ssh-rsa"]);
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let keys = parse_authorized_keys("\n# my key\nssh-rsa AAAA bob@host\n\n");
        assert_eq!(keys.len(), 1);
    }
}
