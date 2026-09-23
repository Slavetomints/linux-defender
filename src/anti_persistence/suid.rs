//! SUID binaries.
//!
//! A binary carrying the setuid bit runs as its owner no matter who starts it,
//! so one dropped into place is a permanent root shell. This only lists what
//! is present: stock systems ship a number of legitimate setuid binaries, and
//! removing the wrong one breaks `sudo` or `passwd`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use crate::core::{DefenderContext, DefenderError, Result};

/// List every SUID binary on the root filesystem.
pub fn run(ctx: &DefenderContext) -> Result {
    println!("[+] Checking for SUID binaries. This may take a while...");

    let mut child = Command::new("find")
        .args(["/", "-perm", "-4000", "-type", "f", "-xdev"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| DefenderError::Command(format!("spawn find: {}", e)))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| DefenderError::Command("failed to capture find stdout".into()))?;

    let mut count = 0usize;
    for line in BufReader::new(stdout).lines() {
        println!("{}", line?);
        count += 1;
    }

    let status = child.wait()?;

    // find exits 1 when it hit unreadable directories; that is expected here.
    if let Some(code) = status.code() {
        if code > 1 {
            return Err(DefenderError::Command(format!(
                "find failed with exit code {}",
                code
            )));
        }
        if code == 1 {
            eprintln!("[!] find completed with minor permission errors");
        }
    }

    ctx.debug(&format!("{} SUID binaries found", count));
    println!("[+] SUID scan complete");
    Ok(())
}
