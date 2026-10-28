//! Shared helpers for web-application restores.
//!
//! Both OpenCart and PrestaShop need the same three operations:
//! - download a release zip from the internet via `curl` or `wget`
//! - extract it onto the web root (stripping a leading prefix when present)
//! - fix ownership and permissions for the active web server

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use walkdir::WalkDir;
use zip::ZipArchive;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{Distro, enable_and_restart};

// ── Download ─────────────────────────────────────────────────────────────────

/// Download `url` to `dest` using `curl` (preferred) or `wget`.
///
/// In non-interactive mode (TUI), falls through to an error if neither tool
/// succeeds rather than prompting to install curl.
pub fn download_file(url: &str, dest: &Path, distro: &Distro, ctx: &DefenderContext) -> Result<()> {
    ctx.progress(&format!("[+] Downloading {}...", url));

    let dest_str = dest
        .to_str()
        .ok_or_else(|| DefenderError::Other("download path is not valid UTF-8".into()))?;

    if try_curl(url, dest_str) {
        ctx.progress("[✓] Download complete");
        return Ok(());
    }
    ctx.progress("[!] curl failed or not found, trying wget...");

    if try_wget(url, dest_str) {
        ctx.progress("[✓] Download complete");
        return Ok(());
    }

    ctx.progress("[!] Neither curl nor wget succeeded.");

    if ctx.interactive() && prompt_yes(&format!("[?] Install curl via {}? (y/N)", distro.name()))? {
        install_package(distro, &["curl"], ctx)?;
        if try_curl(url, dest_str) {
            ctx.progress("[✓] Download complete");
            return Ok(());
        }
    }

    Err(DefenderError::Other(
        "download failed: install curl or wget and ensure the host has internet access".into(),
    ))
}

/// Attempt a download with `curl`; returns `true` on success.
fn try_curl(url: &str, dest: &str) -> bool {
    Command::new("curl")
        .args(["-L", "--progress-bar", "-o", dest, url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Attempt a download with `wget`; returns `true` on success.
fn try_wget(url: &str, dest: &str) -> bool {
    Command::new("wget")
        .args(["--progress=bar:force", "-O", dest, url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Install packages via the host's package manager.
pub fn install_package(distro: &Distro, packages: &[&str], ctx: &DefenderContext) -> Result<()> {
    ctx.progress(&format!("[+] Installing {}...", packages.join(" ")));
    let output = distro
        .install_cmd(packages)
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "install failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress(&format!("[✓] Installed {}", packages.join(", ")));
    Ok(())
}

// ── Zip extraction ────────────────────────────────────────────────────────────

/// Extract a zip archive from disk onto `dest`, skipping `preserve` paths.
///
/// If the zip contains an `upload/` subdirectory (the OpenCart layout), only
/// that subtree is extracted and the `upload/` prefix is stripped.  Otherwise
/// every entry is extracted as-is (the PrestaShop flat layout).
pub fn extract_zip(
    zip_path: &Path,
    dest: &Path,
    preserve: &[&str],
    ctx: &DefenderContext,
) -> Result<()> {
    let prefix = detect_upload_prefix(zip_path)?;
    ctx.debug(&format!(
        "zip prefix: {}",
        prefix.as_deref().unwrap_or("(none — flat)")
    ));

    let file = fs::File::open(zip_path)?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| DefenderError::Other(format!("cannot open zip: {e}")))?;

    let total = archive.len();
    let mut extracted = 0usize;
    let mut preserved = 0usize;

    for i in 0..total {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| DefenderError::Other(format!("bad zip entry {i}: {e}")))?;

        let raw_name = entry.name().to_string();

        // Resolve relative path, stripping the upload prefix when present.
        let relative: &str = match prefix.as_deref() {
            Some(pfx) => {
                if !raw_name.starts_with(pfx) {
                    continue; // outside the subtree we want
                }
                &raw_name[pfx.len()..]
            }
            None => &raw_name,
        };

        if relative.is_empty() {
            continue; // the prefix directory entry itself
        }

        let relative_path = Path::new(relative);

        // Zip-slip guard: reject entries that would write outside dest.
        let out_path = dest.join(relative_path);
        if !out_path.starts_with(dest) {
            return Err(DefenderError::Other(format!(
                "zip-slip attempt: {raw_name} would escape {dest:?}"
            )));
        }

        // Preserve credential files.
        if preserve.iter().any(|p| relative_path == Path::new(p)) {
            ctx.debug(&format!("preserving {relative}"));
            preserved += 1;
            continue;
        }

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = fs::File::create(&out_path)?;
            io::copy(&mut entry, &mut out_file)?;
            extracted += 1;
        }
    }

    ctx.progress(&format!("[✓] Extracted {extracted} files, preserved {preserved}"));
    ctx.debug(&format!(
        "extraction complete: {extracted} extracted, {preserved} preserved, {total} total entries"
    ));
    Ok(())
}

/// Scan a zip for an `upload/` subtree and return the prefix to strip.
fn detect_upload_prefix(zip_path: &Path) -> Result<Option<String>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| DefenderError::Other(format!("cannot open zip for scan: {e}")))?;

    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| DefenderError::Other(format!("zip scan entry {i}: {e}")))?;
        let name = entry.name();

        if let Some(pos) = name.find("/upload/") {
            return Ok(Some(name[..pos + "/upload/".len()].to_string()));
        }
        if name.starts_with("upload/") {
            return Ok(Some("upload/".to_string()));
        }
    }

    Ok(None)
}

// ── Permissions ───────────────────────────────────────────────────────────────

/// Set ownership and permissions on a web root.
///
/// Directories get `755`, regular files get `644`.
pub fn fix_permissions(root: &Path, distro: &Distro, ctx: &DefenderContext) -> Result<()> {
    let candidates: &[&str] = match distro {
        Distro::Debian => &["www-data"],
        Distro::Rhel => &["apache", "www-data"],
        Distro::Arch => &["http", "www-data"],
        Distro::Suse => &["wwwrun", "www-data"],
        Distro::Alpine => &["www-data", "nginx"],
    };

    let web_user = candidates
        .iter()
        .find(|&&u| {
            Command::new("id")
                .arg(u)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .copied()
        .unwrap_or("www-data");

    let root_str = root
        .to_str()
        .ok_or_else(|| DefenderError::Other("web root path is not valid UTF-8".into()))?;

    let output = Command::new("chown")
        .args(["-R", &format!("{web_user}:{web_user}"), root_str])
        .output()
        .map_err(|e| DefenderError::Command(format!("chown: {e}")))?;

    if output.status.success() {
        ctx.progress(&format!("[✓] Ownership set to {web_user}:{web_user}"));
    } else {
        ctx.progress(&format!(
            "[!] chown failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let mode = if entry.file_type().is_dir() {
            0o755
        } else {
            0o644
        };
        let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode));
    }

    ctx.progress("[✓] Permissions set (dirs 755, files 644)");
    Ok(())
}

// ── Web-server detection and reload ──────────────────────────────────────────

/// Return the name of the first web server that is currently active.
pub fn active_webserver() -> Option<&'static str> {
    ["apache2", "httpd", "nginx"].into_iter().find(|&svc| {
        Command::new("systemctl")
            .args(["is-active", "--quiet", svc])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Reload the active web server; fall back to restart if reload isn't supported.
pub fn reload_webserver(ctx: &DefenderContext) -> Result<()> {
    match active_webserver() {
        None => {
            ctx.progress("[!] No active web server detected — restart it manually");
            Ok(())
        }
        Some(svc) => {
            ctx.debug(&format!("reloading {svc}"));
            let status = Command::new("systemctl")
                .args(["reload", svc])
                .status()
                .map_err(|e| DefenderError::Command(format!("systemctl reload {svc}: {e}")))?;

            if status.success() {
                ctx.progress(&format!("[✓] {svc} reloaded"));
                Ok(())
            } else {
                ctx.progress("[!] reload not supported, falling back to restart");
                enable_and_restart(svc, ctx)
            }
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Return `path` as a [`PathBuf`], creating it if the operator agrees.
///
/// In non-interactive mode (TUI), a missing path returns an error immediately
/// rather than prompting.
pub fn resolve_web_root(path: &Path, ctx: &DefenderContext) -> Result<PathBuf> {
    if !path.exists() {
        ctx.progress(&format!("[!] {} does not exist.", path.display()));
        if ctx.interactive() && prompt_yes(&format!("[?] Create {} now? (y/N)", path.display()))? {
            fs::create_dir_all(path)?;
            ctx.progress(&format!("[✓] Created {}", path.display()));
        } else {
            return Err(DefenderError::Other(format!(
                "web root {} does not exist",
                path.display()
            )));
        }
    }
    if !path.is_dir() {
        return Err(DefenderError::Other(format!(
            "{} exists but is not a directory",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

/// Locate an available PHP binary, preferring the newest version.
///
/// In non-interactive mode (TUI), errors immediately if PHP is not found rather
/// than prompting to install it.
pub fn find_php(distro: &Distro, ctx: &DefenderContext) -> Result<String> {
    if let Some(bin) = probe_php() {
        return Ok(bin);
    }

    ctx.progress("[!] PHP not found on this system.");

    if ctx.interactive() {
        let pkg = distro.php_package();
        if prompt_yes(&format!("[?] Install {pkg} via {}? (y/N)", distro.name()))? {
            install_package(distro, &[pkg], ctx)?;
            if let Some(bin) = probe_php() {
                ctx.progress(&format!("[✓] PHP is now available: {bin}"));
                return Ok(bin);
            }
            return Err(DefenderError::Other(
                "PHP was installed but no php binary found on $PATH; \
                 you may need to log out and back in, or run `hash -r`"
                    .into(),
            ));
        }
    }

    Err(DefenderError::Other(
        "PHP not found; install php-cli and retry".into(),
    ))
}

/// Try each php binary name; return the first one that responds.
fn probe_php() -> Option<String> {
    for candidate in ["php", "php8.3", "php8.2", "php8.1", "php8.0"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}
