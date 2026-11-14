//! Shared helpers for web-application restores.
//!
//! Both OpenCart and PrestaShop need the same three operations:
//! - download a release zip from the internet via `curl` or `wget`
//! - extract it onto the web root (stripping a leading prefix when present)
//! - fix ownership and permissions for the active web server

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use regex::Regex;
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
    prepare_download_dest(dest)?;
    download_file_inner(url, dest, distro, ctx)?;
    match crate::backups::hash::hash_file(dest) {
        Ok(digest) => ctx.progress(&format!(
            "[+] SHA-256 of download: {digest} (compare with the vendor's published hash)"
        )),
        Err(e) => ctx.progress(&format!("[!] Could not hash download: {e}")),
    }
    Ok(())
}

/// Root-only directory for installers and archives fetched during a restore.
///
/// Downloads must not live in `/tmp`: a predictable name in a world-writable
/// directory lets any local user pre-create the file or a symlink there, and
/// what lands in it is installed or unpacked as root.
pub const DOWNLOAD_DIR: &str = "/var/lib/linux-defender/downloads";

/// Create the parent of `dest` as a 0700 directory and clear any stale file.
fn prepare_download_dest(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
        if parent.starts_with(DOWNLOAD_DIR) {
            fs::set_permissions(DOWNLOAD_DIR, fs::Permissions::from_mode(0o700))?;
        }
    }
    match fs::symlink_metadata(dest) {
        Ok(_) => fs::remove_file(dest)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Fetch `url` to `dest` with wget, then curl, installing wget if neither works.
fn download_file_inner(
    url: &str,
    dest: &Path,
    distro: &Distro,
    ctx: &DefenderContext,
) -> Result<()> {
    ctx.progress(&format!("[+] Downloading {}...", url));

    let dest_str = dest
        .to_str()
        .ok_or_else(|| DefenderError::Other("download path is not valid UTF-8".into()))?;

    // Suppress subprocess output whenever we have a progress channel (TUI restore thread)
    // or a findings channel (TUI mode). ctx.interactive() is only true when neither is set.
    let quiet = !ctx.interactive();
    if try_wget(url, dest_str, quiet) {
        ctx.progress("[✓] Download complete");
        return Ok(());
    }
    ctx.progress("[!] wget failed or not found, trying curl...");

    if try_curl(url, dest_str, quiet) {
        ctx.progress("[✓] Download complete");
        return Ok(());
    }

    ctx.progress("[!] Neither wget nor curl succeeded — installing wget automatically...");

    if !ctx.interactive() || prompt_yes(&format!("[?] Install wget via {}? (y/N)", distro.name()))?
    {
        install_package(distro, &["wget"], ctx)?;
        if try_wget(url, dest_str, quiet) {
            ctx.progress("[✓] Download complete (wget, fallback after install)");
            return Ok(());
        }
    }

    Err(DefenderError::Other(
        "download failed: install wget or curl and ensure the host has internet access".into(),
    ))
}

/// Attempt a download with `wget`; returns `true` on success.
///
/// wget is tried first because some CDNs (Splunk, in particular) serve the
/// actual binary to Wget's default User-Agent but return an HTML redirect
/// page to curl, causing a silent corrupt download.
fn try_wget(url: &str, dest: &str, quiet: bool) -> bool {
    let mut cmd = Command::new("wget");
    cmd.args(["--progress=bar:force", "-O", dest, url]);
    if quiet {
        // Redirect at the OS level — more reliable than -q, which some wget
        // versions ignore or which still writes headers before suppressing.
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Attempt a download with `curl`; returns `true` on success.
/// --fail causes curl to exit non-zero on HTTP 4xx/5xx instead of saving an error page.
fn try_curl(url: &str, dest: &str, quiet: bool) -> bool {
    let mut cmd = Command::new("curl");
    cmd.args(["-L", "--fail", "--progress-bar", "-o", dest, url]);
    if quiet {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Install packages via the host's package manager.
pub fn install_package(distro: &Distro, packages: &[&str], ctx: &DefenderContext) -> Result<()> {
    if matches!(distro, Distro::Debian) {
        fix_debian_apt_sources(ctx);
    }
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

/// Ensure `/etc/apt/sources.list` has at least one working network source.
///
/// VMs installed from DVD often ship with only a `deb cdrom:` line. With no
/// disc in the drive every `apt-get` call fails. This function:
/// 1. Comments out all `deb cdrom:` lines.
/// 2. If no non-cdrom `deb` lines remain, injects the standard Debian 12
///    (Bookworm) network mirrors so packages can actually be installed.
/// 3. Runs `apt-get update -q` to refresh the index.
fn fix_debian_apt_sources(ctx: &DefenderContext) {
    let sources = "/etc/apt/sources.list";
    let content = match std::fs::read_to_string(sources) {
        Ok(c) => c,
        Err(_) => return,
    };

    let has_cdrom = content
        .lines()
        .any(|l| l.trim_start().starts_with("deb cdrom:"));
    if !has_cdrom {
        return; // already fine
    }

    // Comment out cdrom lines.
    let mut fixed: Vec<String> = content
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("deb cdrom:") {
                format!("# {l}")
            } else {
                l.to_string()
            }
        })
        .collect();

    // Check whether any active (non-comment) network deb lines remain.
    let has_network = fixed.iter().any(|l| {
        let t = l.trim_start();
        t.starts_with("deb ") && !t.starts_with("deb cdrom:")
    });

    if !has_network {
        // No network sources — add standard Debian 12 Bookworm mirrors.
        fixed.push(String::new());
        fixed.push("# Added by linux-defender (cdrom source was the only source)".into());
        fixed.push(
            "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware"
                .into(),
        );
        fixed.push(
            "deb http://deb.debian.org/debian-security bookworm-security main contrib non-free"
                .into(),
        );
        fixed
            .push("deb http://deb.debian.org/debian bookworm-updates main contrib non-free".into());
        ctx.progress("[+] Added Debian 12 Bookworm network apt sources");
    }

    let _ = std::fs::write(sources, fixed.join("\n") + "\n");
    ctx.progress("[+] Disabled cdrom apt source; running apt-get update...");
    let _ = Command::new("apt-get")
        .args(["update", "-q"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdout(std::process::Stdio::null())
        .status();
}

// ── Web root purge ────────────────────────────────────────────────────────────

/// Empty `root` so the next extract starts from a clean slate.
///
/// The directory itself is kept (web server vhost still points at it). Its
/// contents are moved into the quarantine rather than deleted, so a failed
/// rebuild, or anything else that lived in the web root, can be put back.
/// An entry that cannot be moved is logged and skipped rather than aborting.
pub fn purge_web_root(root: &Path, ctx: &DefenderContext) -> Result<()> {
    if !root.exists() {
        fs::create_dir_all(root)?;
        ctx.progress(&format!("[✓] {} created (was absent)", root.display()));
        return Ok(());
    }

    ctx.progress(&format!(
        "[+] Moving the contents of {} to quarantine...",
        root.display()
    ));
    let (saved, failed) = crate::core::context::quarantine_dir_contents(root)?;
    for (path, e) in &failed {
        ctx.progress(&format!("[!] Could not move {}: {e}", path.display()));
    }
    ctx.progress(&format!(
        "[✓] Previous web root saved to {} ({} entr(ies) could not be moved). \
         Put it back with: cp -a '{}/.' '{}/'",
        saved.display(),
        failed.len(),
        saved.display(),
        root.display()
    ));
    Ok(())
}

/// Error unless the archive at `zip_path` opens and contains `relative`
/// (resolved under the archive's `upload/` prefix when it has one).
///
/// Run this before [`purge_web_root`]: a truncated download, an HTML error
/// page saved as a zip, or a release that nests the real archive inside
/// another one must fail while the old site is still in place.
pub fn require_archive_entry(zip_path: &Path, relative: &str) -> Result<()> {
    let prefix = detect_upload_prefix(zip_path)?.unwrap_or_default();
    let wanted = format!("{prefix}{relative}");
    let file = fs::File::open(zip_path)?;
    let mut archive = ZipArchive::new(file).map_err(|e| {
        DefenderError::Other(format!(
            "{} is not a usable zip ({e}); nothing was purged",
            zip_path.display()
        ))
    })?;

    let mut nested_zips = Vec::new();
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| DefenderError::Other(format!("bad zip entry {i}: {e}")))?;
        let Ok(name) = entry.name() else { continue };
        if name == wanted {
            return Ok(());
        }
        if name.ends_with(".zip") {
            nested_zips.push(name.to_string());
        }
    }

    let hint = if nested_zips.is_empty() {
        String::new()
    } else {
        format!(
            " The archive contains {}; the real release may be nested inside it — \
             extract that and pass it with the --*-url option.",
            nested_zips.join(", ")
        )
    };
    Err(DefenderError::Other(format!(
        "{} has no {wanted}; refusing to purge the web root.{hint}",
        zip_path.display()
    )))
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

        let raw_name = entry
            .name()
            .map_err(|e| DefenderError::Other(format!("bad zip entry name {i}: {e}")))?
            .to_string();

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

        // Zip-slip guard: reject entries that would write outside dest. Checking
        // `out_path.starts_with(dest)` is not enough, because it compares
        // components without resolving `..` (`dest/../x` still "starts with"
        // dest), so refuse any entry that is absolute or contains `..`.
        let out_path = dest.join(relative_path);
        if !is_contained_relative(relative_path) || !out_path.starts_with(dest) {
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

    ctx.progress(&format!(
        "[✓] Extracted {extracted} files, preserved {preserved}"
    ));
    ctx.debug(&format!(
        "extraction complete: {extracted} extracted, {preserved} preserved, {total} total entries"
    ));
    Ok(())
}

/// True when `path` stays inside whatever directory it is joined onto: it is
/// relative and has no `..`, root, or drive-prefix component.
fn is_contained_relative(path: &Path) -> bool {
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
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
        let name = entry
            .name()
            .map_err(|e| DefenderError::Other(format!("zip scan entry name {i}: {e}")))?;

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
/// The tree ends up `root:<web user>` with directories `755` and files `644`,
/// so the web server can read everything but a compromised PHP process cannot
/// rewrite the application. Only the `writable` subdirectories (relative to
/// `root`: caches, uploads) are handed to the web user.
///
/// Symlinks are never followed. Modes are set first, while the freshly
/// extracted tree is still root-owned, so the web user cannot swap a file for
/// a link to `/etc/shadow` between the walk and the chmod.
pub fn fix_permissions(
    root: &Path,
    distro: &Distro,
    writable: &[&str],
    ctx: &DefenderContext,
) -> Result<()> {
    let web_user = web_server_user(distro);
    let root_str = root
        .to_str()
        .ok_or_else(|| DefenderError::Other("web root path is not valid UTF-8".into()))?;

    // 1. Modes, skipping symlinks (set_permissions would follow them).
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let kind = entry.file_type();
        if kind.is_symlink() {
            continue;
        }
        let mode = if kind.is_dir() { 0o755 } else { 0o644 };
        let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode));
    }

    // 2. root:<web user> everywhere; -h acts on links themselves.
    report_chown(
        ctx,
        Command::new("chown")
            .args(["-R", "-h", &format!("root:{web_user}"), "--", root_str])
            .output(),
        &format!("root:{web_user}"),
    );

    // 3. The few directories the application must write to.
    let mut granted = 0usize;
    for rel in writable {
        let dir = root.join(rel);
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            continue;
        };
        if !meta.is_dir() || !dir.starts_with(root) {
            continue;
        }
        let ok = Command::new("chown")
            .args(["-R", "-h", &format!("{web_user}:{web_user}"), "--"])
            .arg(&dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o775));
        if ok {
            granted += 1;
        }
    }

    ctx.progress(&format!(
        "[✓] Permissions set (root:{web_user}, dirs 755, files 644; {granted} writable dir(s) owned by {web_user})"
    ));
    Ok(())
}

/// The account the web server runs as on `distro`.
fn web_server_user(distro: &Distro) -> &'static str {
    let candidates: &[&str] = match distro {
        Distro::Debian => &["www-data"],
        Distro::Rhel => &["apache", "www-data"],
        Distro::Arch => &["http", "www-data"],
        Distro::Suse => &["wwwrun", "www-data"],
        Distro::Alpine => &["www-data", "nginx"],
    };
    candidates
        .iter()
        .find(|&&u| {
            Command::new("id")
                .arg(u)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .copied()
        .unwrap_or("www-data")
}

/// Log the outcome of a chown run.
fn report_chown(ctx: &DefenderContext, out: io::Result<std::process::Output>, owner: &str) {
    match out {
        Ok(o) if o.status.success() => ctx.progress(&format!("[✓] Ownership set to {owner}")),
        Ok(o) => ctx.progress(&format!(
            "[!] chown failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => ctx.progress(&format!("[!] chown failed: {e}")),
    }
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
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
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
        if ctx.interactive() && !prompt_yes(&format!("[?] Create {} now? (y/N)", path.display()))? {
            return Err(DefenderError::Other(format!(
                "web root {} does not exist",
                path.display()
            )));
        }
        fs::create_dir_all(path)?;
        ctx.progress(&format!("[✓] Created {}", path.display()));
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

    ctx.progress("[!] PHP not found — installing automatically...");
    let pkg = distro.php_package();

    // In interactive mode, ask first; in TUI mode, just install.
    if ctx.interactive() && !prompt_yes(&format!("[?] Install {pkg} via {}? (y/N)", distro.name()))?
    {
        return Err(DefenderError::Other(
            "PHP not found; install php-cli and retry".into(),
        ));
    }

    install_package(distro, &[pkg], ctx)?;
    if let Some(bin) = probe_php() {
        ctx.progress(&format!("[✓] PHP is now available: {bin}"));
        return Ok(bin);
    }

    Err(DefenderError::Other(
        "PHP was installed but no php binary found on $PATH".into(),
    ))
}

// ── Web-server bootstrapping ──────────────────────────────────────────────────

/// Ensure a web server is installed and running.
///
/// If no web server is currently active, installs and starts Apache (or the
/// distro equivalent) automatically — no prompts.
pub fn ensure_webserver(distro: &Distro, ctx: &DefenderContext) -> Result<()> {
    if active_webserver().is_some() {
        return Ok(());
    }

    ctx.progress("[!] No active web server detected — installing Apache...");
    let pkg = match distro {
        Distro::Debian => "apache2",
        Distro::Rhel => "httpd",
        Distro::Arch => "apache",
        Distro::Suse => "apache2",
        Distro::Alpine => "apache2",
    };
    let svc = match distro {
        Distro::Rhel => "httpd",
        _ => "apache2",
    };

    install_package(distro, &[pkg], ctx)?;
    enable_and_restart(svc, ctx)?;
    open_http_firewall(ctx);
    ctx.progress(&format!("[✓] {svc} installed and running"));
    Ok(())
}

/// Ensure the Apache PHP module and MySQL/MariaDB driver are installed.
///
/// `php-cli` alone is enough to run the CLI installer, but Apache needs its
/// own PHP module to execute `.php` files over HTTP. This installs both the
/// web module and the MySQL driver, then restarts the web server so the new
/// module is active.
pub fn ensure_php_apache(distro: &Distro, ctx: &DefenderContext) -> Result<()> {
    // Apache PHP module + all extensions OpenCart requires.
    let pkgs: &[&str] = match distro {
        Distro::Debian => &[
            "libapache2-mod-php",
            "php-mysql",
            "php-gd",
            "php-curl",
            "php-zip",
            "php-xml",
            "php-intl",
            "php-mbstring",
        ],
        Distro::Rhel => &[
            "php",
            "php-mysqlnd",
            "php-gd",
            "php-curl",
            "php-zip",
            "php-xml",
            "php-intl",
            "php-mbstring",
        ],
        Distro::Arch => &["php-apache", "php-gd"],
        Distro::Suse => &[
            "apache2-mod_php8",
            "php8-mysql",
            "php8-gd",
            "php8-curl",
            "php8-zip",
            "php8-dom",
            "php8-intl",
            "php8-mbstring",
        ],
        Distro::Alpine => &[
            "php-apache2",
            "php-pdo_mysql",
            "php-gd",
            "php-curl",
            "php-zip",
            "php-xml",
            "php-intl",
            "php-mbstring",
        ],
    };

    // Rocky 9's default AppStream PHP stream is 8.0, which OpenCart 4.x rejects.
    // Enable php:8.2 before installing so every package lands on 8.2.
    if matches!(distro, Distro::Rhel) {
        let _ = Command::new("dnf")
            .args(["module", "enable", "-y", "php:8.2"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    ctx.progress("[+] Installing PHP Apache module and required extensions...");
    install_package(distro, pkgs, ctx)?;

    let svc = match distro {
        Distro::Rhel => "httpd",
        _ => "apache2",
    };
    enable_and_restart(svc, ctx)?;
    ctx.progress("[✓] PHP Apache module active");
    Ok(())
}

// ── Database bootstrapping ───────────────────────────────────────────────────

/// Ensure MariaDB is installed, running, has `db_name`, and that `db_user`
/// can log in with `db_pass` and use it.
///
/// The MariaDB root password is left untouched (it used to be overwritten with
/// the store's password, breaking anything else that used root).
pub fn ensure_mysql(
    distro: &Distro,
    db_name: &str,
    db_user: &str,
    db_pass: &str,
    ctx: &DefenderContext,
) -> Result<()> {
    let pkg = match distro {
        Distro::Debian => "mariadb-server",
        Distro::Rhel => "mariadb-server",
        Distro::Arch => "mariadb",
        Distro::Suse => "mariadb",
        Distro::Alpine => "mariadb",
    };

    let mysql_present = Command::new("mysql")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !mysql_present {
        ctx.progress(&format!("[+] Installing {pkg}..."));
        install_package(distro, &[pkg], ctx)?;

        // Rocky/RHEL needs the data directory initialised before first start.
        if matches!(distro, Distro::Rhel) {
            let _ = Command::new("mysql_install_db")
                .args(["--user=mysql", "--datadir=/var/lib/mysql"])
                .output();
        }
    }

    enable_and_restart("mariadb", ctx)?;

    validate_sql_identifier(db_name, "database name")?;
    validate_sql_identifier(db_user, "database user")?;

    // Connect as root over the unix socket (MariaDB's default root auth on
    // Debian/Ubuntu, and passwordless on a fresh RHEL install). The root
    // password is never changed: other services may depend on it.
    let sql = app_database_sql(db_name, db_user, db_pass);
    let output = run_mysql_root(&sql)?;
    if output.status.success() {
        ctx.progress(&format!(
            "[✓] Database '{db_name}' ready, '{db_user}'@'localhost' granted access"
        ));
        return Ok(());
    }

    Err(DefenderError::Command(format!(
        "could not set up database '{db_name}' as MariaDB root over the local socket: {}. \
         If root needs a password, put it in /root/.my.cnf ([client] password=...) and retry.",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Run `sql` as the MariaDB root user, passing the statements on stdin so
/// passwords never appear in the process list.
fn run_mysql_root(sql: &str) -> Result<std::process::Output> {
    use std::io::Write;
    let mut child = Command::new("mysql")
        .args(["-u", "root", "--batch"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| DefenderError::Command(format!("mysql: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(sql.as_bytes())?;
    }
    child
        .wait_with_output()
        .map_err(|e| DefenderError::Command(format!("mysql: {e}")))
}

/// Reject database and user names that are not plain identifiers. They are
/// interpolated into SQL, so anything beyond letters, digits, `_`, `-` and
/// `.` is refused rather than escaped.
fn validate_sql_identifier(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(DefenderError::Other(format!(
            "{what} {value:?} must be 1-64 characters of letters, digits, '_', '-' or '.'"
        )))
    }
}

/// Escape `value` for use inside a single-quoted MariaDB string literal.
fn sql_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\0' => out.push_str("\\0"),
            _ => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// SQL that creates `db_name` and gives `db_user` (identified by `db_pass`)
/// full rights on it. Identifiers must already be validated. A `root` user is
/// left alone: only the database is created.
fn app_database_sql(db_name: &str, db_user: &str, db_pass: &str) -> String {
    let mut sql = format!("CREATE DATABASE IF NOT EXISTS `{db_name}`;\n");
    if db_user != "root" {
        let user = format!("{}@'localhost'", sql_string_literal(db_user));
        let pass = sql_string_literal(db_pass);
        sql.push_str(&format!(
            "CREATE USER IF NOT EXISTS {user} IDENTIFIED BY {pass};\n\
             ALTER USER {user} IDENTIFIED BY {pass};\n\
             GRANT ALL PRIVILEGES ON `{db_name}`.* TO {user};\n"
        ));
    }
    sql.push_str("FLUSH PRIVILEGES;\n");
    sql
}

// ── Site verification ─────────────────────────────────────────────────────────

/// Curl `url` and confirm the response body matches `pattern`.
///
/// Uses a 15-second timeout. Returns `Ok(())` if the pattern matches,
/// `Err` if curl fails or the body does not match.
/// Connect to `localhost:port`, read the service banner, and check it contains
/// `banner_pattern`. Pass an empty pattern to just confirm the port is open.
pub fn verify_tcp_service(port: u16, banner_pattern: &str, ctx: &DefenderContext) -> Result<()> {
    use std::io::Read;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    ctx.progress(&format!("[+] Verifying service on port {port}..."));

    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| DefenderError::Other(format!("bad address: {e}")))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| DefenderError::Other(format!("port {port} not accepting connections: {e}")))?;

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);

    if banner_pattern.is_empty() || banner.contains(banner_pattern) {
        ctx.progress(&format!("[✓] Port {port} is up"));
        Ok(())
    } else {
        Err(DefenderError::Other(format!(
            "port {port} responded but banner did not match (got: {})",
            banner.trim()
        )))
    }
}

/// Fetch `url` and check that the response body contains `pattern`.
pub fn verify_site(url: &str, pattern: &str, ctx: &DefenderContext) -> Result<()> {
    verify_site_impl(url, pattern, false, ctx)
}

/// Like [`verify_site`] but passes `-k` to accept self-signed TLS certificates.
pub fn verify_site_insecure(url: &str, pattern: &str, ctx: &DefenderContext) -> Result<()> {
    verify_site_impl(url, pattern, true, ctx)
}

/// Fetch `url` and confirm the response body matches `pattern`.
fn verify_site_impl(url: &str, pattern: &str, insecure: bool, ctx: &DefenderContext) -> Result<()> {
    ctx.progress(&format!("[+] Verifying site at {url}..."));

    let mut args = vec!["-s", "-L", "--max-time", "15"];
    if insecure {
        args.push("-k");
    }
    args.push(url);

    let output = Command::new("curl")
        .args(&args)
        .output()
        .map_err(|e| DefenderError::Command(format!("curl verify: {e}")))?;

    if !output.status.success() {
        return Err(DefenderError::Other(format!(
            "curl returned non-zero checking {url}"
        )));
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(pattern)
        .map_err(|e| DefenderError::Other(format!("invalid verify regex: {e}")))?;

    if re.is_match(&body) {
        ctx.progress("[✓] Site verification passed");
        Ok(())
    } else {
        Err(DefenderError::Other(format!(
            "site at {url} did not match expected pattern — check server logs"
        )))
    }
}

/// Parse `php --version` output into a (major, minor) tuple.
fn php_semver(bin: &str) -> Option<(u8, u8)> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // "PHP 8.2.10 (cli) ..."
    let ver = text.split_whitespace().nth(1)?;
    let mut parts = ver.split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Try each php binary name; return the first one that is >= 8.1.
///
/// Versioned binaries are probed before the generic `php` so that a distro
/// default of PHP 8.0 is bypassed when a newer version is also installed.
fn probe_php() -> Option<String> {
    for candidate in ["php8.3", "php8.2", "php8.1"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    // Accept generic `php` only if it meets the minimum version requirement.
    if let Some((major, minor)) = php_semver("php")
        && (major > 8 || (major == 8 && minor >= 1))
    {
        return Some("php".to_string());
    }
    None
}

/// Open TCP ports 80 and 443 in the host firewall, silently ignoring errors.
///
/// Tries firewalld first (RHEL/Rocky default), then ufw (Debian/Ubuntu).
/// No-ops on systems without a managed firewall.
pub fn open_http_firewall(ctx: &DefenderContext) {
    let firewalld_80 = Command::new("firewall-cmd")
        .args(["--add-port=80/tcp", "--permanent"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if firewalld_80 {
        let _ = Command::new("firewall-cmd")
            .args(["--add-port=443/tcp", "--permanent"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = Command::new("firewall-cmd")
            .arg("--reload")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        ctx.progress("[✓] firewalld: ports 80 and 443 opened");
        return;
    }

    let ufw_80 = Command::new("ufw")
        .args(["allow", "80/tcp"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = Command::new("ufw")
        .args(["allow", "443/tcp"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if ufw_80 {
        ctx.progress("[✓] ufw: ports 80 and 443 opened");
    }
}

/// Install and enable the Apache SSL module with a self-signed certificate.
///
/// On RHEL/Rocky, `mod_ssl` ships its own default VirtualHost and generates
/// a self-signed cert automatically.  On Debian/Ubuntu the `ssl-cert` package
/// provides the snakeoil cert; `a2enmod ssl` and `a2ensite default-ssl` wire
/// it into Apache.
pub fn ensure_ssl(distro: &Distro, ctx: &DefenderContext) -> Result<()> {
    ctx.progress("[+] Configuring HTTPS/SSL...");

    let svc = match distro {
        Distro::Rhel => "httpd",
        _ => "apache2",
    };

    match distro {
        Distro::Rhel => {
            install_package(distro, &["mod_ssl"], ctx)?;
        }
        Distro::Debian => {
            install_package(distro, &["ssl-cert"], ctx)?;
            let _ = Command::new("a2enmod")
                .arg("ssl")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = Command::new("a2ensite")
                .arg("default-ssl")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        Distro::Arch => {
            // On Arch, mod_ssl is built in; just uncomment LoadModule ssl_module
            // in /etc/httpd/conf/httpd.conf — handled by a2enmod equivalent.
            let _ = Command::new("sed")
                .args([
                    "-i",
                    "s|#LoadModule ssl_module|LoadModule ssl_module|",
                    "/etc/httpd/conf/httpd.conf",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        Distro::Suse => {
            install_package(distro, &["apache2-mod_ssl"], ctx)?;
            let _ = Command::new("a2enmod")
                .arg("ssl")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        Distro::Alpine => {
            // Alpine apache2 has ssl built in; enable via conf.
        }
    }

    enable_and_restart(svc, ctx)?;
    ctx.progress("[✓] HTTPS/SSL enabled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::CompressionMethod;
    use zip::write::{SimpleFileOptions, ZipWriter};

    /// Write a zip at `path` holding `(name, contents)` entries.
    fn make_zip(path: &Path, entries: &[(&str, &str)]) {
        let mut zw = ZipWriter::new(fs::File::create(path).unwrap());
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, body) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(body.as_bytes()).unwrap();
        }
        zw.finish().unwrap();
    }

    #[test]
    fn archive_check_finds_installer_under_upload_prefix_or_flat() {
        let dir = TempDir::new().unwrap();
        let oc = dir.path().join("oc.zip");
        make_zip(
            &oc,
            &[("opencart-4/upload/install/cli_install.php", "<?php")],
        );
        assert!(require_archive_entry(&oc, "install/cli_install.php").is_ok());

        let ps = dir.path().join("ps.zip");
        make_zip(
            &ps,
            &[("install/index_cli.php", "<?php"), ("index.php", "")],
        );
        assert!(require_archive_entry(&ps, "install/index_cli.php").is_ok());
    }

    #[test]
    fn archive_check_rejects_nested_or_broken_archives_before_any_purge() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested.zip");
        make_zip(&nested, &[("prestashop.zip", "PK..."), ("index.php", "")]);
        let err = require_archive_entry(&nested, "install/index_cli.php")
            .unwrap_err()
            .to_string();
        assert!(err.contains("prestashop.zip"), "{err}");

        let html = dir.path().join("html.zip");
        fs::write(&html, "<html>login required</html>").unwrap();
        assert!(require_archive_entry(&html, "install/index_cli.php").is_err());
    }

    #[test]
    fn database_sql_escapes_passwords_and_never_touches_root() {
        let sql = app_database_sql("opencart", "oc_user", "p'w\\d");
        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `opencart`;"));
        assert!(sql.contains("IDENTIFIED BY 'p\\'w\\\\d'"));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `opencart`.* TO 'oc_user'@'localhost';"));
        assert!(!sql.contains("'root'"));

        let root_only = app_database_sql("shop", "root", "x");
        assert!(!root_only.contains("CREATE USER"));
        assert!(!root_only.contains("ALTER USER"));
    }

    #[test]
    fn sql_identifiers_are_validated() {
        assert!(validate_sql_identifier("opencart", "db").is_ok());
        assert!(validate_sql_identifier("oc_user-1.x", "db").is_ok());
        assert!(validate_sql_identifier("", "db").is_err());
        assert!(validate_sql_identifier("a`; DROP DATABASE x; --", "db").is_err());
        assert!(validate_sql_identifier("o'c", "db").is_err());
    }

    #[test]
    fn fix_permissions_never_follows_symlinks_out_of_the_web_root() {
        let dir = TempDir::new().unwrap();
        let outside = dir.path().join("shadow");
        fs::write(&outside, "secret").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let root = dir.path().join("html");
        fs::create_dir_all(root.join("image/cache")).unwrap();
        fs::write(root.join("index.php"), "<?php").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("evil")).unwrap();

        // chown fails without root; the mode pass is what matters here.
        fix_permissions(&root, &Distro::Debian, &["image/cache"], &ctx()).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&outside), 0o600, "symlink target was chmod-ed");
        assert_eq!(mode(&root.join("index.php")), 0o644);
        assert_eq!(mode(&root.join("image/cache")), 0o775);
    }

    fn ctx() -> DefenderContext {
        DefenderContext::new(PathBuf::from("/dev/null"), false)
    }

    #[test]
    fn contained_relative_rejects_escapes() {
        assert!(is_contained_relative(Path::new("index.php")));
        assert!(is_contained_relative(Path::new("admin/config.php")));
        assert!(is_contained_relative(Path::new("./a/b")));
        assert!(!is_contained_relative(Path::new("../x")));
        assert!(!is_contained_relative(Path::new("a/../../x")));
        assert!(!is_contained_relative(Path::new("/etc/passwd")));
    }

    #[test]
    fn extracts_flat_layout_and_preserves_listed_paths() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("flat.zip");
        make_zip(
            &zip_path,
            &[
                ("index.php", "<?php // new"),
                ("config/settings.php", "new"),
            ],
        );
        let dest = tmp.path().join("root");
        fs::create_dir_all(dest.join("config")).unwrap();
        fs::write(dest.join("config/settings.php"), "keep").unwrap();

        extract_zip(&zip_path, &dest, &["config/settings.php"], &ctx()).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("index.php")).unwrap(),
            "<?php // new"
        );
        assert_eq!(
            fs::read_to_string(dest.join("config/settings.php")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn strips_the_upload_prefix() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("oc.zip");
        make_zip(
            &zip_path,
            &[
                ("README.md", "skip me"),
                ("upload/index.php", "shop"),
                ("upload/admin/a.php", "a"),
            ],
        );
        let dest = tmp.path().join("root");
        fs::create_dir_all(&dest).unwrap();

        extract_zip(&zip_path, &dest, &[], &ctx()).unwrap();

        assert_eq!(fs::read_to_string(dest.join("index.php")).unwrap(), "shop");
        assert!(dest.join("admin/a.php").is_file());
        assert!(!dest.join("README.md").exists());
        assert!(!dest.join("upload").exists());
    }

    #[test]
    fn rejects_a_parent_dir_entry_without_writing_outside_dest() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        make_zip(&zip_path, &[("../escaped.txt", "pwned")]);
        let dest = tmp.path().join("root");
        fs::create_dir_all(&dest).unwrap();

        let err = extract_zip(&zip_path, &dest, &[], &ctx()).unwrap_err();

        assert!(err.to_string().contains("zip-slip"), "got: {err}");
        assert!(!tmp.path().join("escaped.txt").exists());
    }
}
