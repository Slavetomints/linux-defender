//! Downloading the team's hardening toolchain.

use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result};

/// The team's host firewall script in the CCDC-scripts repository.
const NFTBUILD_URL: &str = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/firewall/host_firewall/nftbuild";

/// Download the nftbuild firewall script into the working directory.
pub fn run(ctx: &DefenderContext) -> Result {
    println!("[+] Downloading nftbuild");
    ctx.debug(NFTBUILD_URL);

    let output = Command::new("wget")
        .arg(NFTBUILD_URL)
        .output()
        .map_err(|e| DefenderError::Command(format!("wget: {}", e)))?;

    if output.status.success() {
        println!("[✓] Downloaded nftbuild to the current directory");
    } else {
        eprintln!(
            "[X] wget failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}
