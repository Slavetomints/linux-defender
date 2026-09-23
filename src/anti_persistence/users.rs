//! Local accounts.
//!
//! An added account — or an existing service account quietly given a login
//! shell — is persistence that survives everything short of actually reading
//! `/etc/passwd`.

use std::process::Command;

use crate::core::{
    DefenderContext, DefenderError, Result, collect_users, prompt_yes, require_root,
};

/// Review every local account and delete the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        eprintln!("[!] Not running as root - stopping users check.");
        return Err(DefenderError::NotRoot);
    }

    println!("[+] Checking users...");

    for user in collect_users()? {
        ctx.debug(&format!("Considering user {}", user));

        if prompt_yes(&format!("[?] Is this user malicious? {}", user))? {
            delete_user(&user)?;
        }
    }

    Ok(())
}

/// Remove a local account, failing loudly if `userdel` refuses.
fn delete_user(user: &str) -> Result {
    let output = Command::new("userdel")
        .arg(user)
        .output()
        .map_err(|e| DefenderError::Command(format!("userdel {}: {}", user, e)))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "userdel {} failed: {}",
            user,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    println!("[+] Deleted user {}", user);
    Ok(())
}
