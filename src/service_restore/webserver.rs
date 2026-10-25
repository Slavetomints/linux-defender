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
/// If neither tool is found, the operator is offered the chance to install
/// `curl` via the system package manager before retrying.
pub fn download_file(url: &str, dest: &Path, distro: &Distro) -> Result<()> {
    println!("[+] Downloading {}...", url);

    let dest_str = dest
        .to_str()
        .ok_or_else(|| DefenderError::Other("download path is not valid UTF-8".into()))?;

    if try_curl(url, dest_str) {
        println!("[✓] Download complete");
        return Ok(());
    }
    eprintln!("[!] curl failed or not found, trying wget...");

    if try_wget(url, dest_str) {
        println!("[✓] Download complete");
        return Ok(());
    }

    // Neither worked — offer to install curl.
    eprintln!("[!] Neither curl nor wget succeeded.");
    if prompt_yes(&format!("[?] Install curl via {}? (y/N)", distro.name()))? {
        install_package(distro, &["curl"])?;
        if try_curl(url, dest_str) {
            println!("[✓] Download complete");
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

/// Install packages via the host's package manager, prompting on failure.
pub fn install_package(distro: &Distro, packages: &[&str]) -> Result<()> {
    println!("[+] Installing {}...", packages.join(" "));
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
    println!("[✓] Installed {}", packages.join(", "));
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

    println!("[✓] Extracted {extracted} files, preserved {preserved}");
    ctx.debug(&format!(
        "extraction complete: {extracted} extracted, {preserved} preserved, {total} total entries"
    ));
    Ok(())
}

/// Scan a zip for an `upload/` subtree and return the prefix to strip.
///
/// OpenCart zips look like `opencart-4.x.x.x/upload/index.php`; the prefix
/// returned is `opencart-4.x.x.x/upload/`.  If the zip has a plain `upload/`
/// at the root, the prefix is `upload/`.  If there is no `upload/` directory
/// at all (PrestaShop flat layout), `None` is returned.
fn detect_upload_prefix(zip_path: &Path) -> Result<Option<String>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| DefenderError::Other(format!("cannot open zip for scan: {e}")))?;

    // Look for any entry whose name contains "/upload/" (e.g. "opencart-4.1.0.4/upload/")
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| DefenderError::Other(format!("zip scan entry {i}: {e}")))?;
        let name = entry.name();

        if let Some(pos) = name.find("/upload/") {
            return Ok(Some(name[..pos + "/upload/".len()].to_string()));
        }
        // Leading "upload/" with no version directory
        if name.starts_with("upload/") {
            return Ok(Some("upload/".to_string()));
        }
    }

    Ok(None)
}

// ── Permissions ───────────────────────────────────────────────────────────────

/// Set ownership and permissions on a web root.
///
/// Directories get `755`, regular files get `644`. Ownership is set to the
/// first web-server user that exists on this system.
pub fn fix_permissions(root: &Path, distro: &Distro) -> Result<()> {
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
        println!("[✓] Ownership set to {web_user}:{web_user}");
    } else {
        eprintln!(
            "[!] chown failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let mode = if entry.file_type().is_dir() {
            0o755
        } else {
            0o644
        };
        let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode));
    }

    println!("[✓] Permissions set (dirs 755, files 644)");
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

/// Reload the active web server (graceful reload); fall back to restart if
/// the unit does not support reload.
pub fn reload_webserver(ctx: &DefenderContext) -> Result<()> {
    match active_webserver() {
        None => {
            println!("[!] No active web server detected — restart it manually");
            Ok(())
        }
        Some(svc) => {
            ctx.debug(&format!("reloading {svc}"));
            let status = Command::new("systemctl")
                .args(["reload", svc])
                .status()
                .map_err(|e| DefenderError::Command(format!("systemctl reload {svc}: {e}")))?;

            if status.success() {
                println!("[✓] {svc} reloaded");
                Ok(())
            } else {
                eprintln!("[!] reload not supported, falling back to restart");
                enable_and_restart(svc, ctx)
            }
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Return `path` as a [`PathBuf`].
///
/// If the directory does not exist, the operator is offered the chance to
/// create it with `mkdir -p`. A path that exists but is not a directory is
/// always an error.
pub fn resolve_web_root(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        eprintln!("[!] {} does not exist.", path.display());
        if prompt_yes(&format!("[?] Create {} now? (y/N)", path.display()))? {
            fs::create_dir_all(path)?;
            println!("[✓] Created {}", path.display());
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
/// If no `php` executable is found, the operator is offered the chance to
/// install the distribution's PHP CLI package before retrying.
pub fn find_php(distro: &Distro) -> Result<String> {
    if let Some(bin) = probe_php() {
        return Ok(bin);
    }

    // PHP not found — offer to install it.
    let pkg = distro.php_package();
    eprintln!("[!] PHP not found on this system.");
    if prompt_yes(&format!("[?] Install {pkg} via {}? (y/N)", distro.name()))? {
        install_package(distro, &[pkg])?;
        if let Some(bin) = probe_php() {
            println!("[✓] PHP is now available: {bin}");
            return Ok(bin);
        }
        return Err(DefenderError::Other(
            "PHP was installed but no php binary found on $PATH; \
             you may need to log out and back in, or run `hash -r`"
                .into(),
        ));
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
