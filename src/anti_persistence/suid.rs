//! SUID binaries.
//!
//! A binary carrying the setuid bit runs as its owner no matter who starts it,
//! so one dropped into place is a permanent root shell. This only lists what
//! is present: stock systems ship a number of legitimate setuid binaries, and
//! removing the wrong one breaks `sudo` or `passwd`.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::core::{DefenderContext, DefenderError, Finding, Result, Severity};

/// List every SUID binary on the root filesystem.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking for SUID binaries. This may take a while...");

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
        let path_str = line?;
        count += 1;
        ctx.emit(
            Finding::new(
                Severity::Info,
                "suid",
                format!("SUID binary: {}", path_str),
                "This binary runs as its owner regardless of who executes it.",
            )
            .with_path(PathBuf::from(&path_str)),
        );
    }

    let status = child.wait()?;

    if let Some(code) = status.code() {
        if code > 1 {
            return Err(DefenderError::Command(format!(
                "find failed with exit code {}",
                code
            )));
        }
        if code == 1 {
            ctx.emit(Finding::new(
                Severity::Info,
                "suid",
                "find completed with minor permission errors (some directories unreadable)",
                "",
            ));
        }
    }

    ctx.debug(&format!("{} SUID binaries found", count));
    ctx.log_msg(&format!(
        "[+] SUID scan complete — {} binaries found",
        count
    ));
    Ok(())
}
