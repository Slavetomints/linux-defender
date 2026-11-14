//! Downloading the team's hardening toolchain.

use crate::core::{DefenderContext, Result};
use crate::tools::catalog::NFTBUILD;
use crate::tools::downloader;

/// Download the nftbuild firewall script into `/usr/local/bin`.
///
/// Goes through [`downloader::download`], so the file is only installed when
/// its SHA-256 matches the pinned hash. A failed download or a hash mismatch
/// is returned as an error.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.progress("[+] Downloading nftbuild");
    ctx.debug(NFTBUILD.url);

    let result = downloader::download(&NFTBUILD)?;
    ctx.progress(&format!(
        "[✓] Installed nftbuild to {} (sha256 {})",
        result.path.display(),
        result.sha256
    ));
    Ok(())
}
