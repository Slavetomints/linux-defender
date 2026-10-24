//! Reinstall OpenCart from the official release zip.
//!
//! # What this does
//!
//! 1. Downloads the pinned release zip (or a URL the operator supplies).
//! 2. Extracts the `upload/` subtree onto the web root, stripping the leading
//!    version directory (OpenCart zips look like `opencart-4.x.x.x/upload/`).
//! 3. Renames `config-dist.php` → `config.php` and
//!    `admin/config-dist.php` → `admin/config.php` so the CLI installer can
//!    write the database connection into them.
//! 4. Makes both config files world-writable (`0777`) as the installer requires.
//! 5. Prompts for database credentials, admin credentials, and the HTTP base URL.
//! 6. Runs `php install/cli_install.php install …` (the headless installer
//!    shipped with OpenCart 4.x; it lives in the `install/` subdirectory).
//! 7. Deletes the `install/` directory (web-accessible installer — must go).
//! 8. Moves `system/storage/` to `/var/opencart-storage/` (outside the web
//!    root) and patches the path in both config files.
//! 9. Fixes ownership and permissions, then reloads the web server.
//!
//! # Why `config-dist.php` must be renamed first
//!
//! `cli_install.php` opens `config.php` in write mode to record the
//! generated configuration. If the file does not exist yet the installer
//! aborts. The dist file is a valid empty template; renaming it fulfils that
//! requirement without pre-populating any credentials.

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

/// Pinned release version embedded in the default download URL.
const OPENCART_VERSION: &str = "4.1.0.4";

/// Default download URL — updated when a new release ships.
const OPENCART_DEFAULT_URL: &str =
    "https://github.com/opencart/opencart/releases/download/4.1.0.4/opencart-4.1.0.4.zip";

/// Temporary zip path used during extraction.
const TMP_ZIP: &str = "/tmp/defender-opencart.zip";

/// Where to move the storage directory (outside the web root).
const STORAGE_DEST: &str = "/var/opencart-storage";

/// Download, install, and configure OpenCart on this host.
pub fn run(ctx: &DefenderContext, web_root: &Path, download_url: Option<&str>) -> Result<()> {
    ensure_root_or_reexec()?;

    let root = resolve_web_root(web_root)?;
    let distro = Distro::detect()?;
    let php = find_php(&distro)?;
    let url = download_url.unwrap_or(OPENCART_DEFAULT_URL);

    ctx.debug(&format!("opencart url: {url}"));
    ctx.debug(&format!("web root: {}", root.display()));
    ctx.debug(&format!("php: {php}"));
    ctx.debug(&format!("distro: {}", distro.name()));

    println!(
        "[!] OpenCart {OPENCART_VERSION} will be installed to {}.",
        root.display()
    );
    println!("[!] Existing PHP files (except config.php / admin/config.php) will be overwritten.");
    if !prompt_yes("[?] Continue? (y/N)")? {
        println!("[-] Skipping OpenCart restore");
        return Ok(());
    }

    // ── 1. Download ───────────────────────────────────────────────────────────
    download_file(url, Path::new(TMP_ZIP), &distro)?;

    // ── 2. Extract upload/ subtree to web root ────────────────────────────────
    println!("[+] Extracting to {}...", root.display());
    extract_zip(
        Path::new(TMP_ZIP),
        &root,
        &["config.php", "admin/config.php"],
        ctx,
    )?;

    // ── 3. Rename config-dist.php → config.php (if not already there) ─────────
    rename_dist_config(&root)?;

    // ── 4. chmod 0777 on config files (installer writes into them) ────────────
    for cfg in &["config.php", "admin/config.php"] {
        let p = root.join(cfg);
        if p.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o777))?;
        }
    }
    println!("[✓] Config files made writable");

    // ── 5. Collect credentials ────────────────────────────────────────────────
    println!("\n[+] Database and admin credentials (press Enter to accept defaults):");
    let db_host = prompt_string_default("  Database hostname", "localhost")?;
    let db_user = prompt_string("  Database username")?;
    let db_pass = prompt_string("  Database password")?;
    let db_name = prompt_string_default("  Database name", "opencart")?;
    let db_port = prompt_string_default("  Database port", "3306")?;
    let http_server = prompt_string_default(
        "  HTTP base URL (include trailing slash)",
        "http://localhost/",
    )?;
    println!();
    println!("[+] Admin account:");
    let admin_user = prompt_string_default("  Admin username", "admin")?;
    let admin_pass = prompt_string("  Admin password")?;
    let admin_email = prompt_string("  Admin email")?;

    // ── 6. Run CLI installer ──────────────────────────────────────────────────
    println!("\n[+] Running OpenCart CLI installer...");
    let cli_script = root.join("install/cli_install.php");
    if !cli_script.exists() {
        return Err(DefenderError::Other(format!(
            "CLI installer not found at {}; extraction may have failed",
            cli_script.display()
        )));
    }
    let status = Command::new(&php)
        .arg(cli_script.as_os_str())
        .arg("install")
        .arg("--db_hostname")
        .arg(&db_host)
        .arg("--db_username")
        .arg(&db_user)
        .arg("--db_password")
        .arg(&db_pass)
        .arg("--db_database")
        .arg(&db_name)
        .arg("--db_port")
        .arg(&db_port)
        .arg("--db_driver")
        .arg("mysqli")
        .arg("--username")
        .arg(&admin_user)
        .arg("--password")
        .arg(&admin_pass)
        .arg("--email")
        .arg(&admin_email)
        .arg("--http_server")
        .arg(&http_server)
        .status()
        .map_err(|e| DefenderError::Command(format!("cli_install.php: {e}")))?;

    if !status.success() {
        return Err(DefenderError::Command(
            "OpenCart CLI installer returned non-zero; check output above for details".into(),
        ));
    }
    println!("[✓] OpenCart installation complete");

    // ── 7. Delete web-accessible installer ───────────────────────────────────
    let install_dir = root.join("install");
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir)?;
        println!("[✓] Deleted install/ directory");
    }

    // ── 8. Move storage/ outside the web root ─────────────────────────────────
    move_storage(&root)?;

    // ── 9. Permissions and web server ─────────────────────────────────────────
    println!("[+] Fixing ownership and permissions...");
    fix_permissions(&root, &distro)?;

    println!("[+] Reloading web server...");
    reload_webserver(ctx)?;

    // Cleanup temp zip
    let _ = fs::remove_file(TMP_ZIP);

    ctx.log(&format!("[ok] opencart installed to {}", root.display()))?;
    println!("\n[✓] OpenCart restored at {http_server}");
    println!(
        "[!] Admin panel: {http_server}admin/  (rename the admin/ directory when you have time)"
    );
    Ok(())
}

/// Rename `config-dist.php` → `config.php` and `admin/config-dist.php` →
/// `admin/config.php` if the target files don't already exist.
fn rename_dist_config(root: &Path) -> Result<()> {
    for (dist, target) in &[
        ("config-dist.php", "config.php"),
        ("admin/config-dist.php", "admin/config.php"),
    ] {
        let dist_path = root.join(dist);
        let target_path = root.join(target);

        if target_path.exists() {
            ctx_debug_noop(&format!("{} already exists, skipping rename", target));
            continue;
        }
        if dist_path.exists() {
            fs::rename(&dist_path, &target_path)?;
            println!("[✓] Renamed {} → {}", dist, target);
        } else {
            return Err(DefenderError::Other(format!(
                "{} not found in web root — is the archive correct?",
                dist
            )));
        }
    }
    Ok(())
}

/// Move `<root>/system/storage/` to [`STORAGE_DEST`] and update the path in
/// both config files.
fn move_storage(root: &Path) -> Result<()> {
    let src = root.join("system/storage");
    if !src.exists() {
        println!("[!] system/storage/ not found; skipping storage relocation");
        return Ok(());
    }

    let dest = Path::new(STORAGE_DEST);
    if dest.exists() {
        // Already relocated from a previous install — leave it.
        println!(
            "[✓] {} already exists; storage already relocated",
            STORAGE_DEST
        );
        patch_storage_path(root, STORAGE_DEST)?;
        return Ok(());
    }

    fs::create_dir_all(dest)?;
    // Use `cp -r` then `rm -rf` so we cross filesystem boundaries safely.
    let cp = Command::new("cp")
        .args(["-r", src.to_str().unwrap_or("."), STORAGE_DEST])
        .status()
        .map_err(|e| DefenderError::Command(format!("cp storage: {e}")))?;
    if !cp.success() {
        return Err(DefenderError::Command(
            "failed to copy storage directory".into(),
        ));
    }
    fs::remove_dir_all(&src)?;
    println!("[✓] Moved system/storage/ → {STORAGE_DEST}");

    patch_storage_path(root, STORAGE_DEST)?;
    Ok(())
}

/// Update `DIR_STORAGE` in both config files to point at `new_path`.
fn patch_storage_path(root: &Path, new_path: &str) -> Result<()> {
    for cfg in &["config.php", "admin/config.php"] {
        let p = root.join(cfg);
        if !p.exists() {
            continue;
        }
        let contents = fs::read_to_string(&p)?;
        // Replace the define line regardless of what path was there before.
        let patched = replace_define_line(
            &contents,
            "DIR_STORAGE",
            &format!("{}/", new_path.trim_end_matches('/')),
        );
        fs::write(&p, patched)?;
        println!("[✓] Patched DIR_STORAGE in {}", p.display());
    }
    Ok(())
}

/// Replace a `define('KEY', '...')` line in PHP source with a new value.
fn replace_define_line(src: &str, key: &str, value: &str) -> String {
    src.lines()
        .map(|line| {
            if line.contains(&format!("define('{key}'"))
                || line.contains(&format!("define(\"{key}\""))
            {
                format!("define('{key}', '{value}');")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Inline no-op for debug messages inside functions that don't take a `ctx`.
fn ctx_debug_noop(_msg: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_define_line_updates_storage_path() {
        let src = "<?php\ndefine('DIR_STORAGE', '/old/path/');\ndefine('VERSION', '4.0');\n";
        let patched = replace_define_line(src, "DIR_STORAGE", "/new/path/");
        assert!(patched.contains("define('DIR_STORAGE', '/new/path/');"));
        assert!(!patched.contains("/old/path/"));
        assert!(patched.contains("define('VERSION', '4.0');"));
    }

    #[test]
    fn replace_define_line_leaves_other_defines_untouched() {
        let src = "define('DB_HOST', 'localhost');\ndefine('DIR_STORAGE', '/old/');\n";
        let patched = replace_define_line(src, "DIR_STORAGE", "/new/");
        assert!(patched.contains("define('DB_HOST', 'localhost');"));
    }
}
