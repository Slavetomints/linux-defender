//! Local account analysis.
//!
//! An added account — or an existing service account quietly given a login
//! shell or NOPASSWD sudo — is persistence that survives password changes.
//! The module flags three classes of risk:
//!
//! - **UID 0, not root** — a second root account is a classic red-team trick.
//! - **NOPASSWD sudo** — the account can escalate without a password.
//! - **Login shell on a service account** — e.g. `www-data` with `/bin/bash`.
//!
//! Legitimate-looking accounts (UID ≥ 1000, sensible shell, no NOPASSWD) are
//! emitted as Info so the operator has a full picture without noise.

use std::fs;
use std::path::PathBuf;

use crate::core::{
    Action, DefenderContext, DefenderError, Finding, Result, Severity, Verdict, require_root,
};

/// Parsed fields from one `/etc/passwd` line.
struct Account {
    name: String,
    uid: u32,
    home: PathBuf,
    shell: String,
}

/// Walk `/etc/passwd`, analyse each non-system account, and emit a verdict.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        if ctx.in_tui() {
            ctx.emit(Finding::new(
                Severity::Medium,
                "users",
                "Not running as root — users check skipped",
                "Run as root to inspect local accounts and sudoers.",
            ));
        } else {
            eprintln!("[!] Not running as root — users check skipped");
        }
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking local accounts...");

    let accounts = parse_passwd()?;

    for acct in &accounts {
        ctx.debug(&format!("Reviewing account {} (uid={})", acct.name, acct.uid));

        // Check for a second UID-0 account — always Critical.
        if acct.uid == 0 && acct.name != "root" {
            emit_uid0_finding(ctx, acct);
            continue;
        }

        // Skip pure system accounts (uid < 1000) that don't have login shells.
        if acct.uid < 1000 && is_nologin_shell(&acct.shell) {
            continue;
        }

        let nopasswd = has_nopasswd_sudo(&acct.name);
        let ssh_key_count = count_ssh_keys(&acct.home);
        let service_shell = acct.uid < 1000 && !is_nologin_shell(&acct.shell);

        if ctx.in_tui() {
            emit_account_finding(ctx, acct, nopasswd, ssh_key_count, service_shell);
        } else {
            print_account_legacy(ctx, acct, nopasswd, ssh_key_count, service_shell);
        }
    }

    ctx.log_msg("[✓] Account check complete");
    Ok(())
}

fn emit_uid0_finding(ctx: &DefenderContext, acct: &Account) {
    ctx.emit(
        Finding::new(
            Severity::Critical,
            "users",
            format!("UID-0 account '{}' is not root — backdoor account", acct.name),
            format!(
                "Account '{}' has UID 0, granting full root privileges without being the \
                 canonical root account. This is a textbook red-team persistence technique.",
                acct.name
            ),
        )
        .with_context("account", acct.name.clone())
        .with_context("uid", "0")
        .with_context("shell", acct.shell.clone())
        .with_context("home", acct.home.display().to_string())
        .with_verdict(
            Verdict::Remove,
            format!(
                "Any UID-0 account other than root is a backdoor. \
                 Delete it with `userdel {}` (add -r to remove home dir). \
                 Also check /etc/sudoers for NOPASSWD entries for this account.",
                acct.name
            ),
        )
        .with_action(Action::Manual(format!("userdel -r {}", acct.name))),
    );
}

fn emit_account_finding(
    ctx: &DefenderContext,
    acct: &Account,
    nopasswd: bool,
    ssh_key_count: usize,
    service_shell: bool,
) {
    let (severity, verdict, recommendation) = risk_verdict(&acct.name, nopasswd, service_shell);

    let summary = if nopasswd {
        format!("{} has NOPASSWD sudo (uid={})", acct.name, acct.uid)
    } else if service_shell {
        format!(
            "{} is a service account with a login shell (uid={})",
            acct.name, acct.uid
        )
    } else {
        format!("Local account {} (uid={})", acct.name, acct.uid)
    };

    let mut finding = Finding::new(
        severity,
        "users",
        summary,
        format!("account: {}\nuid: {}\nshell: {}", acct.name, acct.uid, acct.shell),
    )
    .with_context("account", acct.name.clone())
    .with_context("uid", acct.uid.to_string())
    .with_context("shell", acct.shell.clone())
    .with_context("home", acct.home.display().to_string())
    .with_context("NOPASSWD sudo", if nopasswd { "yes" } else { "no" })
    .with_context("SSH keys", ssh_key_count.to_string())
    .with_verdict(verdict, recommendation);

    if service_shell {
        finding = finding.with_context(
            "note",
            "Service account (uid < 1000) with a login shell — should be /usr/sbin/nologin",
        );
    }

    finding = finding.with_action(Action::Manual(format!("usermod -s /usr/sbin/nologin {}", acct.name)));

    ctx.emit(finding);
}

fn print_account_legacy(
    ctx: &DefenderContext,
    acct: &Account,
    nopasswd: bool,
    ssh_key_count: usize,
    service_shell: bool,
) {
    let flags: Vec<&str> = [
        nopasswd.then_some("NOPASSWD-sudo"),
        service_shell.then_some("service-with-login-shell"),
        (ssh_key_count > 0).then_some("has-ssh-keys"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if flags.is_empty() {
        ctx.debug(&format!("  {} uid={} — OK", acct.name, acct.uid));
    } else {
        println!(
            "[!] {} uid={} shell={} — {}",
            acct.name,
            acct.uid,
            acct.shell,
            flags.join(", ")
        );
    }
}

fn risk_verdict(name: &str, nopasswd: bool, service_shell: bool) -> (Severity, Verdict, String) {
    if nopasswd {
        (
            Severity::High,
            Verdict::Remove,
            format!(
                "Account '{}' can escalate to root without a password. In CCDC this is \
                 almost always a red-team implant. Remove the NOPASSWD entry from \
                 /etc/sudoers (or /etc/sudoers.d/) with `visudo`.",
                name
            ),
        )
    } else if service_shell {
        (
            Severity::Medium,
            Verdict::Disable,
            format!(
                "Service account '{}' has an interactive login shell. Service accounts \
                 should use /usr/sbin/nologin. Change it with \
                 `usermod -s /usr/sbin/nologin {}`.",
                name, name
            ),
        )
    } else {
        (
            Severity::Info,
            Verdict::Investigate,
            format!(
                "Verify that account '{}' is expected on this box. \
                 If it was added by the red team, delete it with `userdel -r {}`.",
                name, name
            ),
        )
    }
}

/// True when `shell` is a no-login shell (the account cannot open a TTY).
fn is_nologin_shell(shell: &str) -> bool {
    matches!(
        shell,
        "/usr/sbin/nologin"
            | "/sbin/nologin"
            | "/bin/false"
            | "/usr/bin/false"
            | "/dev/null"
    )
}

/// True when `name` appears in sudoers (including sudoers.d) with NOPASSWD.
fn has_nopasswd_sudo(name: &str) -> bool {
    check_sudoers_file("/etc/sudoers", name)
        || read_sudoers_d()
            .iter()
            .any(|path| check_sudoers_file(path, name))
}

fn check_sudoers_file(path: &str, name: &str) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    contents
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains(name) && l.contains("NOPASSWD"))
}

fn read_sudoers_d() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/etc/sudoers.d") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

/// Number of public keys in `home/.ssh/authorized_keys`.
fn count_ssh_keys(home: &PathBuf) -> usize {
    let path = home.join(".ssh").join("authorized_keys");
    let Ok(contents) = fs::read_to_string(path) else {
        return 0;
    };
    contents
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count()
}

/// Parse all accounts from `/etc/passwd`.
fn parse_passwd() -> Result<Vec<Account>> {
    let contents = fs::read_to_string("/etc/passwd")?;

    Ok(contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 {
                return None;
            }
            let uid: u32 = fields[2].parse().ok()?;
            Some(Account {
                name: fields[0].to_string(),
                uid,
                home: PathBuf::from(fields[5]),
                shell: fields[6].to_string(),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nologin_shells_are_recognised() {
        assert!(is_nologin_shell("/usr/sbin/nologin"));
        assert!(is_nologin_shell("/bin/false"));
        assert!(!is_nologin_shell("/bin/bash"));
        assert!(!is_nologin_shell("/usr/bin/zsh"));
    }

    #[test]
    fn passwd_parse_extracts_uid_and_shell() {
        let contents = "root:x:0:0:root:/root:/bin/bash\n\
                        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        let accounts: Vec<Account> = contents
            .lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() < 7 { return None; }
                let uid: u32 = f[2].parse().ok()?;
                Some(Account {
                    name: f[0].to_string(),
                    uid,
                    home: PathBuf::from(f[5]),
                    shell: f[6].to_string(),
                })
            })
            .collect();
        assert_eq!(accounts[0].uid, 0);
        assert_eq!(accounts[0].shell, "/bin/bash");
        assert_eq!(accounts[1].uid, 65534);
    }
}
