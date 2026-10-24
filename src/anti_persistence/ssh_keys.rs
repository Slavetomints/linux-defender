//! Backdoor keys in `authorized_keys`.
//!
//! An added public key is persistent, survives password changes, and looks
//! entirely ordinary. Each account's file is summarised key by key — type and
//! comment, not the base64 body — so the operator can see what a key claims to
//! be before deciding.

use std::fs;
use std::path::PathBuf;

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, UserAccount, Verdict,
    collect_accounts, require_root,
};

/// Review each account's `authorized_keys`, log all keys as evidence, then delete the file.
///
/// In CCDC every authorized_keys entry was planted by the red team or left over
/// from pre-competition setup. We log the key content (type + comment, not the
/// base64 body), delete the file, and verify it is gone — leaving a clean audit
/// trail in the run log.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if !ctx.in_tui() {
            eprintln!("[!] Not running as root — ssh_keys check skipped");
        }
        ctx.emit(Finding::new(
            Severity::Medium,
            "ssh_keys",
            "Not running as root — ssh_keys check skipped",
            "Run as root to review and remove authorized_keys.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking SSH authorized_keys...");

    for account in collect_accounts()? {
        let keyfile = authorized_keys_path(&account);
        ctx.debug(&format!("Checking {}", keyfile.display()));

        if !keyfile.exists() {
            continue;
        }

        let contents = fs::read_to_string(&keyfile).unwrap_or_default();
        let keys = parse_authorized_keys(&contents);
        if keys.is_empty() {
            continue;
        }

        let mtime_label = keyfile
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| ctx.mtime_label(t))
            .unwrap_or_else(|| "unknown".into());

        ctx.log_msg(&format!(
            "[!] {} authorized key(s) found in {} — auto-removing",
            keys.len(),
            keyfile.display(),
        ));

        // Phase 1: log evidence (key summaries + raw file)
        for key in &keys {
            ctx.log_evidence_line(&keyfile.display().to_string(), key);
        }
        ctx.log_evidence_file(&keyfile);

        // Phase 2: delete the entire file
        let removed = ctx.remove_path_logged(&keyfile);

        let mut finding = Finding::new(
            Severity::High,
            "ssh_keys",
            format!(
                "{} authorized_keys REMOVED: {} key(s) (removed: {})",
                account.name,
                keys.len(),
                removed,
            ),
            format!(
                "account: {}\npath: {}\nkeys: {}\nremoved: {}",
                account.name,
                keyfile.display(),
                keys.join(", "),
                removed,
            ),
        )
        .with_path(keyfile.clone())
        .with_context("account", account.name.clone())
        .with_context("path", keyfile.display().to_string())
        .with_context("key count", keys.len().to_string())
        .with_context("mtime", mtime_label)
        .with_context("removed", removed.to_string())
        .with_verdict(
            Verdict::Remove,
            if removed {
                "Authorized keys were deleted. Evidence and proof logged. \
                 In CCDC all authorized_keys are red team backdoors — they survive \
                 password changes and must be purged."
                .to_string()
            } else {
                "Authorized keys were found but deletion failed — check the log and \
                 remove manually."
                .to_string()
            },
        );

        for (i, key) in keys.iter().enumerate() {
            finding = finding.with_context(
                Box::leak(format!("key {}", i + 1).into_boxed_str()),
                key.clone(),
            );
        }
        ctx.emit(finding);
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
