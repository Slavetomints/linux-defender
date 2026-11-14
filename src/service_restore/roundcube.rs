//! Reinstall Roundcube webmail and restart Apache.
//!
//! The mail box scores port 80.  A bare `apt install roundcube` puts the
//! application back; restoring the backed-up config brings the DB connection
//! and IMAP host settings back without manual re-integration.
//!
//! Package sets per distro family:
//!   - Debian/Ubuntu: `roundcube roundcube-core roundcube-mysql apache2`
//!   - RHEL/Fedora:   `roundcubemail httpd`
//!   - Arch:          `roundcubemail apache`
//!   - openSUSE:      `roundcubemail apache2`
//!   - Alpine:        `roundcubemail apache2`

use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

use super::distro::{Distro, enable_and_restart, restore_config_from_backup};
use super::webserver::{app_database_sql, run_mysql_root, validate_sql_identifier};

/// Return the Roundcube package set for `distro`.
fn roundcube_packages(distro: Distro) -> &'static [&'static str] {
    match distro {
        Distro::Debian => &[
            "roundcube",
            "roundcube-core",
            "roundcube-mysql",
            "mariadb-server",
            "apache2",
        ],
        Distro::Rhel => &["roundcubemail", "httpd"],
        Distro::Arch => &["roundcubemail", "apache"],
        Distro::Suse => &["roundcubemail", "apache2"],
        Distro::Alpine => &["roundcubemail", "apache2"],
    }
}

/// Return the Apache service unit name for `distro`.
fn apache_service(distro: Distro) -> &'static str {
    match distro {
        Distro::Rhel => "httpd",
        _ => "apache2",
    }
}

/// Reinstall Roundcube, wire up Apache, initialise the database, and start Apache.
pub fn run(ctx: &DefenderContext) -> Result {
    let distro = Distro::detect()?;
    ctx.debug(&format!("detected distro: {}", distro.name()));

    let pkgs = roundcube_packages(distro);

    if ctx.interactive()
        && !prompt_yes(&format!(
            "[?] Reinstall Roundcube + Apache via {} and restart? (y/N)",
            distro.name()
        ))?
    {
        ctx.progress("[-] Skipping Roundcube restore");
        return Ok(());
    }

    ctx.progress(&format!(
        "[+] Installing {} ({})...",
        pkgs.join(" "),
        distro.name()
    ));
    // Reinstall, not install: install is a no-op for packages that are
    // already present, which leaves tampered roundcube files in place.
    // `dnf reinstall` refuses packages that are missing, so fall back.
    let mut output = distro
        .reinstall_cmd(pkgs)
        .output()
        .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;
    if !output.status.success() {
        output = distro
            .install_cmd(pkgs)
            .output()
            .map_err(|e| DefenderError::Command(format!("package manager: {e}")))?;
    }

    if !output.status.success() {
        return Err(DefenderError::Command(format!(
            "install failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    ctx.progress(&format!("[✓] Installed {}", pkgs.join(", ")));

    // Restore config — try both Debian (/etc/roundcube) and RHEL (/etc/roundcubemail).
    let restored = restore_config_from_backup("/etc/roundcube", ctx)?
        || restore_config_from_backup("/etc/roundcubemail", ctx)?;
    if !restored {
        ctx.progress("[!] No roundcube config backup found — using fresh defaults");
    }

    if matches!(distro, Distro::Debian) {
        // Find where the roundcube web files actually landed — Ubuntu and Debian
        // differ between /usr/share/roundcube and /var/lib/roundcube/public_html.
        let webroot = if std::path::Path::new("/var/lib/roundcube/public_html").exists() {
            "/var/lib/roundcube/public_html"
        } else {
            "/usr/share/roundcube"
        };
        ctx.progress(&format!(
            "[+] Writing Apache alias for roundcube at {webroot}..."
        ));
        let conf = format!(
            "Alias /roundcube {webroot}\n\
             <Directory {webroot}>\n\
             Options +FollowSymLinks\n\
             AllowOverride All\n\
             Require all granted\n\
             </Directory>\n"
        );
        let conf_path = "/etc/apache2/conf-available/roundcube-alias.conf";
        if let Err(e) = std::fs::write(conf_path, &conf) {
            ctx.progress(&format!("[!] Could not write Apache conf: {e}"));
        } else {
            let _ = Command::new("a2enconf").arg("roundcube-alias").output();
            let _ = Command::new("a2enmod").arg("rewrite").output();
            ctx.progress("[✓] Apache roundcube alias enabled");
        }
    }

    // Ensure MariaDB is running and the roundcube database + schema exist.
    // dpkg-reconfigure roundcube-core sets up the DB automatically, but only
    // if it can reach the server.  We start the service first, then run the
    // roundcube SQL init script manually as a reliable fallback.
    if matches!(distro, Distro::Debian) {
        enable_and_restart("mariadb", ctx).unwrap_or(());
        // Read credentials from the package-managed include file.
        let db_conf = "/etc/roundcube/debian-db.php";
        if std::path::Path::new(db_conf).exists() {
            ctx.progress("[+] Initialising roundcube database...");
            // Parse user/pass/name from the PHP include (simple grep approach).
            let text = std::fs::read_to_string(db_conf).unwrap_or_default();
            let grab = |key: &str| -> String {
                text.lines()
                    .find(|l| l.contains(&format!("${key}=")))
                    .and_then(|l| {
                        let s = l.find('\'')?;
                        let e = l.rfind('\'')?;
                        if s < e {
                            Some(l[s + 1..e].to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default()
            };
            let dbuser = grab("dbuser");
            let dbpass = grab("dbpass");
            let dbname = grab("dbname");
            // These values come from a file on a possibly compromised box:
            // validate the identifiers, escape the password, and never hand
            // them to a shell.
            let ids_ok = validate_sql_identifier(&dbname, "roundcube database name").is_ok()
                && validate_sql_identifier(&dbuser, "roundcube database user").is_ok();
            if !ids_ok {
                ctx.progress(&format!(
                    "[!] {db_conf} has an unusable dbname/dbuser; database NOT initialised"
                ));
            } else {
                match run_mysql_root(&app_database_sql(&dbname, &dbuser, &dbpass)) {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => ctx.progress(&format!(
                        "[!] roundcube database setup failed: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    )),
                    Err(e) => ctx.progress(&format!("[!] roundcube database setup failed: {e}")),
                }
                // Initialize schema (errors if tables exist, which is fine).
                let schema = "/usr/share/roundcube/SQL/mysql.initial.sql";
                if let Ok(schema_file) = std::fs::File::open(schema) {
                    let _ = Command::new("mysql")
                        .args(["-u", "root", "--", &dbname])
                        .stdin(schema_file)
                        .output();
                }
                ctx.progress(&format!("[✓] Database '{dbname}' ready"));
            }
        }
        // Ensure IMAP host is set so the login form is usable.
        let cfg = "/etc/roundcube/config.inc.php";
        if std::path::Path::new(cfg).exists() {
            let _ = Command::new("sed")
                .args([
                    "-i",
                    r"s/\$config\['default_host'\] = '';/\$config['default_host'] = 'localhost';/",
                    cfg,
                ])
                .output();
        }
    }

    enable_and_restart(apache_service(distro), ctx)?;

    ctx.log("[ok] roundcube installed and apache restarted")?;
    Ok(())
}
