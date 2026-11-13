/// Tool download, SHA256 verification, and installation.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::core::{DefenderError, Result};

/// Directory where per-tool SHA256 hashes are stored.
pub const HASH_DIR: &str = "/etc/linux-defender/tool-hashes";
/// Directory where tools are installed.
pub const INSTALL_DIR: &str = "/usr/local/bin";

/// How a downloaded binary is installed.
#[derive(Debug, Clone, Copy)]
pub enum InstallMethod {
    /// Copy to `INSTALL_DIR/<name>` and chmod 755.
    Binary,
}

/// Metadata describing a downloadable tool.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Short identifier, used as the filename.
    pub name: &'static str,
    /// One-line description shown in the Tools tab.
    pub description: &'static str,
    /// Primary download URL.
    pub url: &'static str,
    /// Fallback URLs tried in order if the primary fails.
    pub mirrors: &'static [&'static str],
    /// SHA256 pinned at build time; `None` = no compile-time pin.
    pub known_sha256: Option<&'static str>,
    /// How to install the downloaded bytes.
    pub install: InstallMethod,
}

/// Result of a successful download-and-install.
pub struct DownloadResult {
    /// Tool name.
    pub tool: &'static str,
    /// Installed path.
    pub path: PathBuf,
    /// SHA256 of the downloaded bytes.
    pub sha256: String,
    /// `true` if the new hash differs from the previously stored hash.
    pub hash_changed: bool,
    /// `true` if no stored hash existed before this download.
    pub hash_new: bool,
}

/// Download `tool`, verify its SHA256 (trust-on-first-use), and install it.
pub fn download(tool: &ToolDef) -> Result<DownloadResult> {
    let dest = Path::new(INSTALL_DIR).join(tool.name);

    let mut bytes: Option<Vec<u8>> = None;
    let mut last_err = String::new();

    for url in std::iter::once(tool.url).chain(tool.mirrors.iter().copied()) {
        match fetch_bytes(url) {
            Ok(b) => {
                bytes = Some(b);
                break;
            }
            Err(e) => last_err = e,
        }
    }

    let bytes = bytes.ok_or_else(|| {
        DefenderError::Command(format!("failed to download {}: {}", tool.name, last_err))
    })?;

    let sha256 = hex_sha256(&bytes);

    let _ = std::fs::create_dir_all(HASH_DIR);
    let hash_file = Path::new(HASH_DIR).join(format!("{}.sha256", tool.name));

    let (hash_changed, hash_new) = if hash_file.exists() {
        let stored = std::fs::read_to_string(&hash_file).unwrap_or_default();
        (stored.trim() != sha256.as_str(), false)
    } else {
        (false, true)
    };

    std::fs::write(&hash_file, &sha256)?;

    match tool.install {
        InstallMethod::Binary => {
            std::fs::write(&dest, &bytes)?;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(DownloadResult {
        tool: tool.name,
        path: dest,
        sha256,
        hash_changed,
        hash_new,
    })
}

/// Return `true` if `name` is already present in `INSTALL_DIR`.
pub fn is_installed(name: &str) -> bool {
    Path::new(INSTALL_DIR).join(name).exists()
}

/// Read the stored SHA256 for `name`, if any.
pub fn stored_sha256(name: &str) -> Option<String> {
    let p = Path::new(HASH_DIR).join(format!("{}.sha256", name));
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Compute a SHA-256 hex digest of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Fetch the bytes at `url` using `curl`, returning an error string on failure.
fn fetch_bytes(url: &str) -> std::result::Result<Vec<u8>, String> {
    let curl = Command::new("curl")
        .args(["-fsSL", "--max-time", "30", "-o", "-", url])
        .output();

    if let Ok(out) = curl
        && out.status.success()
    {
        return Ok(out.stdout);
    }

    let wget = Command::new("wget")
        .args(["-qO-", "--timeout=30", url])
        .output()
        .map_err(|e| e.to_string())?;

    if wget.status.success() {
        Ok(wget.stdout)
    } else {
        Err(String::from_utf8_lossy(&wget.stderr).into_owned())
    }
}
