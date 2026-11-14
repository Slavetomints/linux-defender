/// Wrapper around the `nftbuild` binary.
///
/// **Warning**: nftbuild immediately writes AND applies a nftables ruleset —
/// it starts the `nftables` systemd service on exit. Never run it automatically;
/// always ask the operator for an explicit confirmation first.
use std::path::Path;
use std::process::Command;

use crate::core::{BoxType, DefenderError, Result};

/// Path where nftbuild writes (and immediately loads) its generated config.
pub const NFT_CONFIG_PATH: &str = "/etc/nftables.conf";

/// Maps our `BoxType` to the value nftbuild expects for `-sys`.
pub fn sys_arg(box_type: BoxType) -> &'static str {
    match box_type {
        BoxType::Web => "webserver",
        BoxType::Mail => "mail",
        BoxType::Splunk => "splunk",
        BoxType::General | BoxType::Router => "wrkstn",
    }
}

/// Options for running nftbuild.
#[derive(Default)]
pub struct RunOptions {
    /// Also allow outbound SSH. Inbound SSH is always enabled via `-ssh i`.
    /// Set this to true to pass `-ssh ie` instead (ingress + egress).
    pub allow_outbound_ssh: bool,
    /// Pass `-z` for Zero Trust mode (blocks outbound HTTP/HTTPS/DNS).
    pub zero_trust: bool,
    /// Pass `-ntp` to add NTP rules.
    pub ntp: bool,
}

/// Result of running nftbuild.
pub struct NftbuildResult {
    /// Contents of the generated (and applied) config file.
    pub config: String,
    /// Path the config was written to.
    pub config_path: &'static str,
}

/// Modification time of [`NFT_CONFIG_PATH`], if it exists.
fn config_mtime() -> Option<std::time::SystemTime> {
    std::fs::metadata(NFT_CONFIG_PATH)
        .and_then(|m| m.modified())
        .ok()
}

/// Whether the config was (re)written between two mtime samples.
fn config_was_written(
    before: Option<std::time::SystemTime>,
    after: Option<std::time::SystemTime>,
) -> bool {
    match (before, after) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(b), Some(a)) => a != b,
    }
}

/// Run nftbuild for `box_type`, applying the ruleset immediately.
///
/// **This modifies the active firewall.** Only call after explicit operator
/// confirmation. Requires root and nftbuild installed at `/usr/local/bin/nftbuild`.
pub fn run(box_type: BoxType, opts: &RunOptions) -> Result<NftbuildResult> {
    let binary = Path::new("/usr/local/bin/nftbuild");
    if !binary.exists() {
        return Err(DefenderError::Command(
            "nftbuild not installed — use [7] Tools to download it first".into(),
        ));
    }

    let mut cmd = Command::new(binary);
    cmd.arg("-sys").arg(sys_arg(box_type));

    // Always allow inbound SSH; optionally also allow outbound.
    cmd.arg("-ssh")
        .arg(if opts.allow_outbound_ssh { "ie" } else { "i" });
    if opts.zero_trust {
        cmd.arg("-z");
    }
    if opts.ntp {
        cmd.arg("-ntp");
    }

    let before = config_mtime();
    let output = cmd
        .output()
        .map_err(|e| DefenderError::Command(format!("nftbuild exec: {}", e)))?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "nftbuild exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    // An unchanged file is a config from an earlier run, not this one.
    if !config_was_written(before, config_mtime()) {
        return Err(DefenderError::Command(format!(
            "nftbuild exited 0 but did not write {}: {}",
            NFT_CONFIG_PATH,
            stderr.trim()
        )));
    }

    let config = std::fs::read_to_string(NFT_CONFIG_PATH).map_err(|e| {
        DefenderError::Command(format!(
            "nftbuild ran but config not found at {}: {}",
            NFT_CONFIG_PATH, e
        ))
    })?;

    Ok(NftbuildResult {
        config,
        config_path: NFT_CONFIG_PATH,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_or_missing_config_is_not_success() {
        use std::time::{Duration, UNIX_EPOCH};
        let t0 = UNIX_EPOCH + Duration::from_secs(100);
        let t1 = UNIX_EPOCH + Duration::from_secs(200);
        assert!(config_was_written(None, Some(t1)));
        assert!(config_was_written(Some(t0), Some(t1)));
        assert!(!config_was_written(Some(t0), Some(t0)));
        assert!(!config_was_written(Some(t0), None));
        assert!(!config_was_written(None, None));
    }
}
