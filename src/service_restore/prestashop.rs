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

use super::distro::{Distro, ensure_root_or_reexec};
use super::webserver::{
    download_file, extract_zip, find_php, fix_permissions, reload_webserver, resolve_web_root,
};

/// Pinned release version.
const PRESTASHOP_VERSION: &str = "9.0.0";

/// Default download URL.
const PRESTASHOP_DEFAULT_URL: &str =
    "https://github.com/PrestaShop/PrestaShop/releases/download/9.0.0/prestashop_9.0.0.zip";

/// Temporary zip path used during extraction.
const TMP_ZIP: &str = "/tmp/defender-prestashop.zip";

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

/// Files whose contents hold live database credentials; preserved on overlay.
const PRESERVE: &[&str] = &[
    "app/config/parameters.php",
    "config/settings.inc.php",
    ".env",
    ".env.local",
];

/// Download, install, and configure PrestaShop on this host.
pub fn run(ctx: &DefenderContext, web_root: &Path, download_url: Option<&str>) -> Result<()> {
    ensure_root_or_reexec()?;

    let root = resolve_web_root(web_root)?;
    let distro = Distro::detect()?;
    let php = find_php(&distro)?;
    let url = download_url.unwrap_or(PRESTASHOP_DEFAULT_URL);

    ctx.debug(&format!("prestashop url: {url}"));
    ctx.debug(&format!("web root: {}", root.display()));
    ctx.debug(&format!("php: {php}"));
    ctx.debug(&format!("distro: {}", distro.name()));

    println!(
        "[!] PrestaShop {PRESTASHOP_VERSION} will be installed to {}.",
        root.display()
    );
    println!("[!] Existing PHP files (except credential files) will be overwritten.");
    if !prompt_yes("[?] Continue? (y/N)")? {
        println!("[-] Skipping PrestaShop restore");
        return Ok(());
    }

    // ── 1. Download ───────────────────────────────────────────────────────────
    download_file(url, Path::new(TMP_ZIP), &distro)?;

    // ── 2. Extract flat zip to web root ───────────────────────────────────────
    println!("[+] Extracting to {}...", root.display());
    extract_zip(Path::new(TMP_ZIP), &root, PRESERVE, ctx)?;

    // ── 3. Set writable directories ───────────────────────────────────────────
    set_writable_dirs(&root)?;

    // ── 4. Collect credentials ────────────────────────────────────────────────
    println!("\n[+] Database and admin credentials (press Enter to accept defaults):");
    let domain = prompt_string_default("  Shop domain (no http://)", "localhost")?;
    let db_server = prompt_string_default("  Database server", "localhost")?;
    let db_name = prompt_string_default("  Database name", "prestashop")?;
    let db_user = prompt_string("  Database username")?;
    let db_pass = prompt_string("  Database password")?;
    println!();
    println!("[+] Admin account:");
    let admin_email = prompt_string("  Admin email")?;
    let admin_pass = prompt_string("  Admin password")?;

    // ── 5. Run CLI installer ──────────────────────────────────────────────────
    //
    // PrestaShop's CLI installer lives at install/index_cli.php.
    // --db_create=1 creates the database if it does not yet exist.
    // --fixtures=0 skips demo data (faster; irrelevant in CCDC).
    println!("\n[+] Running PrestaShop CLI installer...");
    let cli_script = root.join("install/index_cli.php");
    if !cli_script.exists() {
        return Err(DefenderError::Other(format!(
            "CLI installer not found at {}; extraction may have failed",
            cli_script.display()
        )));
    }

    let status = Command::new(&php)
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
        .status()
        .map_err(|e| DefenderError::Command(format!("prestashop installer: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(
            "PrestaShop CLI installer returned non-zero; check output above for details".into(),
        ));
    }
    println!("[✓] PrestaShop installation complete");

    // ── 6. Delete web-accessible installer ───────────────────────────────────
    for dir in &["install", "install-dev"] {
        let p = root.join(dir);
        if p.exists() {
            fs::remove_dir_all(&p)?;
            println!("[✓] Deleted {dir}/ directory");
        }
    }

    // ── 7. Permissions and web server ─────────────────────────────────────────
    println!("[+] Fixing ownership and permissions...");
    fix_permissions(&root, &distro)?;

    println!("[+] Reloading web server...");
    reload_webserver(ctx)?;

    // Cleanup temp zip
    let _ = fs::remove_file(TMP_ZIP);

    ctx.log(&format!("[ok] prestashop installed to {}", root.display()))?;
    println!("\n[✓] PrestaShop restored at http://{domain}/");
    println!("[!] Admin panel: http://{domain}/admin-dev/  (rename admin-dev/ when you have time)");
    Ok(())
}

/// `chmod -R +w` on the directories PrestaShop's installer must write to.
fn set_writable_dirs(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut count = 0usize;
    for dir in WRITABLE_DIRS {
        let p = root.join(dir);
        if p.exists() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o775))?;
            count += 1;
        }
    }
    println!("[✓] Made {count} directories writable");
    Ok(())
}
