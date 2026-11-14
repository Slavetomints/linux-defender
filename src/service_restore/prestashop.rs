//! Reinstall PrestaShop from the official release zip.
//!
//! # What this does
//!
//! 1. Downloads the pinned release zip (or a URL the operator supplies).
//!    The release zip already contains the compiled vendor/ tree — no
//!    `composer install` step is needed.
//! 2. Extracts the zip directly onto the web root (PrestaShop release zips
//!    have a flat structure — files at the root, no leading version directory).
//! 3. Sets the writable-directory permissions that the installer requires.
//! 4. Prompts for database credentials, admin credentials, and the domain.
//! 5. Runs `php install/index_cli.php …` (PrestaShop's supported headless
//!    installer, available since 1.7).
//! 6. Deletes the `install/` directory (must be removed before the shop is
//!    accessible).
//! 7. Fixes ownership and permissions, then reloads the web server.
//!
//! # Preserved files
//!
//! `app/config/parameters.php` (PS 8/9) and `config/settings.inc.php` (PS 1.7)
//! are skipped during extraction so an existing database connection survives
//! if the files are still intact. If they are gone (full wipe), the installer
//! writes new ones from the credentials you provide.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::core::{
    DefenderContext, DefenderError, Result, prompt_string, prompt_string_default, prompt_yes,
};

use super::distro::Distro;
use super::webserver::{
    download_file, extract_zip, find_php, fix_permissions, purge_web_root, reload_webserver,
    require_archive_entry, resolve_web_root, verify_site, verify_site_insecure,
};

/// Credentials collected by the TUI dialog (or CLI prompts) before install.
#[derive(Debug, Clone)]
pub struct PrestaShopCredentials {
    /// Shop domain without scheme (e.g. `localhost` or `shop.example.com`).
    pub domain: String,
    /// Database server address (e.g. `localhost`).
    pub db_server: String,
    /// Database name (e.g. `prestashop`).
    pub db_name: String,
    /// Database username.
    pub db_user: String,
    /// Database password.
    pub db_pass: String,
    /// Admin account email address.
    pub admin_email: String,
    /// Admin account password.
    pub admin_pass: String,
}

impl Default for PrestaShopCredentials {
    fn default() -> Self {
        Self {
            domain: "localhost".into(),
            db_server: "localhost".into(),
            db_name: "prestashop".into(),
            db_user: String::new(),
            db_pass: String::new(),
            admin_email: String::new(),
            admin_pass: String::new(),
        }
    }
}

/// Pinned release version.
const PRESTASHOP_VERSION: &str = "9.0.0";

/// Default download URL.
const PRESTASHOP_DEFAULT_URL: &str =
    "https://github.com/PrestaShop/PrestaShop/releases/download/9.0.0/prestashop_9.0.0.zip";

/// Temporary zip path used during extraction.
const TMP_ZIP: &str = "/var/lib/linux-defender/downloads/prestashop.zip";

/// Directories that need to be writable during (and after) installation.
const WRITABLE_DIRS: &[&str] = &[
    "admin-dev/autoupgrade",
    "app/config",
    "app/logs",
    "cache",
    "config",
    "download",
    "img",
    "log",
    "mails",
    "modules",
    "override",
    "themes",
    "translations",
    "upload",
    "var",
];

/// Download, install, and configure PrestaShop on this host.
///
/// When `credentials` is `Some`, all interactive prompts are skipped — TUI path.
/// When `credentials` is `None`, the operator is prompted on the terminal.
pub fn run(
    ctx: &DefenderContext,
    web_root: &Path,
    download_url: Option<&str>,
    credentials: Option<&PrestaShopCredentials>,
) -> Result<()> {
    let root = resolve_web_root(web_root, ctx)?;
    let distro = Distro::detect()?;
    let php = find_php(&distro, ctx)?;
    let url = download_url.unwrap_or(PRESTASHOP_DEFAULT_URL);

    ctx.debug(&format!("prestashop url: {url}"));
    ctx.debug(&format!("web root: {}", root.display()));
    ctx.debug(&format!("php: {php}"));
    ctx.debug(&format!("distro: {}", distro.name()));

    ctx.progress(&format!(
        "[!] PrestaShop {PRESTASHOP_VERSION} will be installed to {}.",
        root.display()
    ));
    ctx.progress("[!] Web root will be PURGED then rebuilt from the official release zip.");

    if credentials.is_none() && !prompt_yes("[?] Continue? (y/N)")? {
        ctx.progress("[-] Skipping PrestaShop restore");
        return Ok(());
    }

    // ── 1. Download ───────────────────────────────────────────────────────────
    download_file(url, Path::new(TMP_ZIP), &distro, ctx)?;

    // Fail here, with the old site still in place, if the archive is not a
    // release we can install from.
    require_archive_entry(Path::new(TMP_ZIP), "install/index_cli.php")?;

    // ── 1b. Purge web root — previous contents go to quarantine ──────────────
    purge_web_root(&root, ctx)?;

    // ── 2. Extract flat zip to web root ───────────────────────────────────────
    ctx.progress(&format!("[+] Extracting to {}...", root.display()));
    extract_zip(
        Path::new(TMP_ZIP),
        &root,
        &[], // nothing to preserve — web root was just purged
        ctx,
    )?;

    // ── 3. Set writable directories ───────────────────────────────────────────
    set_writable_dirs(&root, ctx)?;

    // ── 4. Collect credentials ────────────────────────────────────────────────
    let owned;
    let creds = if let Some(c) = credentials {
        c
    } else {
        ctx.progress("[+] Database and admin credentials (press Enter to accept defaults):");
        let domain = prompt_string_default("  Shop domain (no http://)", "localhost")?;
        let db_server = prompt_string_default("  Database server", "localhost")?;
        let db_name = prompt_string_default("  Database name", "prestashop")?;
        let db_user = prompt_string("  Database username")?;
        let db_pass = prompt_string("  Database password")?;
        ctx.progress("[+] Admin account:");
        let admin_email = prompt_string("  Admin email")?;
        let admin_pass = prompt_string("  Admin password")?;
        owned = PrestaShopCredentials {
            domain,
            db_server,
            db_name,
            db_user,
            db_pass,
            admin_email,
            admin_pass,
        };
        &owned
    };
    let domain = &creds.domain;
    let db_server = &creds.db_server;
    let db_name = &creds.db_name;
    let db_user = &creds.db_user;
    let db_pass = &creds.db_pass;
    let admin_email = &creds.admin_email;
    let admin_pass = &creds.admin_pass;

    // ── 5. Run CLI installer ──────────────────────────────────────────────────
    ctx.progress("[+] Running PrestaShop CLI installer...");
    let cli_script = root.join("install/index_cli.php");
    if !cli_script.exists() {
        return Err(DefenderError::Other(format!(
            "CLI installer not found at {}; extraction may have failed",
            cli_script.display()
        )));
    }

    let out = Command::new(&php)
        .arg(cli_script.as_os_str())
        .arg(format!("--domain={domain}"))
        .arg(format!("--db_server={db_server}"))
        .arg(format!("--db_name={db_name}"))
        .arg(format!("--db_user={db_user}"))
        .arg(format!("--db_password={db_pass}"))
        .arg(format!("--email={admin_email}"))
        .arg(format!("--password={admin_pass}"))
        .arg("--db_create=1")
        .arg("--fixtures=0")
        .arg("--language=en")
        .output()
        .map_err(|e| DefenderError::Command(format!("prestashop installer: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(DefenderError::Command(format!(
            "PrestaShop CLI installer returned non-zero: {}",
            stderr.trim()
        )));
    }
    ctx.progress("[✓] PrestaShop installation complete");

    // ── 6. Delete web-accessible installer ───────────────────────────────────
    for dir in &["install", "install-dev"] {
        let p = root.join(dir);
        if p.exists() {
            fs::remove_dir_all(&p)?;
            ctx.progress(&format!("[✓] Deleted {dir}/ directory"));
        }
    }

    // ── 7. Permissions and web server ─────────────────────────────────────────
    ctx.progress("[+] Fixing ownership and permissions...");
    fix_permissions(&root, &distro, ctx)?;

    ctx.progress("[+] Reloading web server...");
    reload_webserver(ctx)?;

    let _ = fs::remove_file(TMP_ZIP);

    ctx.log(&format!("[ok] prestashop installed to {}", root.display()))?;
    ctx.progress(&format!("[✓] PrestaShop restored at http://{domain}/"));
    ctx.progress(&format!(
        "[!] Admin panel: http://{domain}/admin-dev/  (rename admin-dev/ when you have time)"
    ));

    // Verify both HTTP and HTTPS serve a PrestaShop page.
    if let Err(e) = verify_site(
        &format!("http://{domain}/"),
        r"(?i)prestashop|powered by prestashop",
        ctx,
    ) {
        ctx.progress(&format!("[!] HTTP site check failed: {e}"));
    }
    if let Err(e) = verify_site_insecure(
        &format!("https://{domain}/"),
        r"(?i)prestashop|powered by prestashop",
        ctx,
    ) {
        ctx.progress(&format!("[!] HTTPS site check failed: {e}"));
    }

    Ok(())
}

/// `chmod -R +w` on the directories PrestaShop's installer must write to.
fn set_writable_dirs(root: &Path, ctx: &DefenderContext) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut count = 0usize;
    for dir in WRITABLE_DIRS {
        let p = root.join(dir);
        if p.exists() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o775))?;
            count += 1;
        }
    }
    ctx.progress(&format!("[✓] Made {count} directories writable"));
    Ok(())
}
