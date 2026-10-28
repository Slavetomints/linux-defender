//! PHP module and webshell detection.
//!
//! Three detection areas:
//!
//! 1. **PHP ini auditing** — scans all `php.ini` / `conf.d/*.ini` files for
//!    dangerous settings: remote includes, auto-prepend/append persistence,
//!    non-standard extension paths, and missing security constraints.
//! 2. **Extension binary auditing** — walks PHP extension directories for
//!    unknown `.so` files or recently modified ones.
//! 3. **Webshell pattern scan** — walks web roots for `.php` files containing
//!    known malicious patterns (eval+base64, `$_GET['cmd']`, etc.).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::core::{DefenderContext, Finding, Result, Severity};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Candidate PHP ini files / directories to scan, tried with glob-style
/// pattern expansion via manual directory listing.
const PHP_ETC_DIRS: &[&str] = &[
    "/etc/php",
    "/etc/php5",
    "/etc/php7",
    "/etc/php8",
    "/etc/php7.0",
    "/etc/php7.1",
    "/etc/php7.2",
    "/etc/php7.3",
    "/etc/php7.4",
    "/etc/php8.0",
    "/etc/php8.1",
    "/etc/php8.2",
    "/etc/php8.3",
];

/// Flat ini files to check directly.
const PHP_INI_DIRECT: &[&str] = &["/etc/php.ini", "/usr/local/etc/php.ini"];

/// Directories where PHP extension `.so` files are expected.
const PHP_EXT_DIRS: &[&str] = &["/usr/lib/php", "/usr/lib64/php", "/usr/local/lib/php"];

/// Web root directories to scan for webshells.
const WEB_ROOTS: &[&str] = &["/var/www", "/srv/www", "/usr/share/nginx/html"];

/// Maximum `.php` files to inspect in the webshell scan before bailing out.
const MAX_PHP_FILES: usize = 10_000;

/// Files larger than this are skipped in the webshell scan.
const MAX_WEBSHELL_FILE_BYTES: u64 = 500 * 1024;

/// Extensions considered to ship with standard PHP packages.
const KNOWN_SAFE_EXTENSIONS: &[&str] = &[
    "bcmath",
    "bz2",
    "calendar",
    "ctype",
    "curl",
    "dba",
    "dom",
    "enchant",
    "exif",
    "ffi",
    "fileinfo",
    "filter",
    "ftp",
    "gd",
    "gettext",
    "gmp",
    "hash",
    "iconv",
    "igbinary",
    "imagick",
    "imap",
    "intl",
    "json",
    "ldap",
    "mbstring",
    "memcache",
    "memcached",
    "msgpack",
    "mysqli",
    "mysqlnd",
    "opcache",
    "pcntl",
    "pdo",
    "pdo_mysql",
    "pdo_pgsql",
    "pdo_sqlite",
    "pgsql",
    "phar",
    "posix",
    "pspell",
    "readline",
    "redis",
    "shmop",
    "simplexml",
    "snmp",
    "soap",
    "sockets",
    "sodium",
    "sqlite3",
    "sysvmsg",
    "sysvsem",
    "sysvshm",
    "tidy",
    "tokenizer",
    "uuid",
    "xdebug",
    "xhprof",
    "xml",
    "xmlreader",
    "xmlrpc",
    "xmlwriter",
    "xsl",
    "yaml",
    "zip",
    "zlib",
];

/// Seconds in 30 days — extensions modified more recently are suspicious.
const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all three PHP detection passes and emit findings.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning PHP configuration and webshell indicators...");
    check_php_ini(ctx);
    check_extension_dirs(ctx);
    check_webroot_php(ctx);
    ctx.log_msg("[✓] PHP module scan complete");
    Ok(())
}

// ── 1. PHP ini auditing ───────────────────────────────────────────────────────

/// Collect all candidate PHP ini file paths from well-known directories.
fn collect_ini_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();

    // Direct flat files
    for p in PHP_INI_DIRECT {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            paths.push(pb);
        }
    }

    // Versioned /etc/phpX.Y directories
    for base in PHP_ETC_DIRS {
        let base_path = Path::new(base);
        if !base_path.is_dir() {
            continue;
        }
        // /etc/phpX.Y/php.ini
        let top_ini = base_path.join("php.ini");
        if top_ini.is_file() {
            paths.push(top_ini);
        }
        // /etc/phpX.Y/<sapi>/php.ini  (cli, apache2, fpm, …)
        if let Ok(entries) = std::fs::read_dir(base_path) {
            for entry in entries.flatten() {
                let ep = entry.path();
                if ep.is_dir() {
                    let sapi_ini = ep.join("php.ini");
                    if sapi_ini.is_file() {
                        paths.push(sapi_ini);
                    }
                    // /etc/phpX.Y/<sapi>/conf.d/*.ini
                    let conf_d = ep.join("conf.d");
                    if conf_d.is_dir() {
                        if let Ok(confs) = std::fs::read_dir(&conf_d) {
                            for cf in confs.flatten() {
                                let cp = cf.path();
                                if cp.extension().and_then(|e| e.to_str()) == Some("ini") {
                                    paths.push(cp);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    paths
}

/// Parse a single non-comment ini line into a `(key, value)` pair.
///
/// Returns `None` for blank lines, section headers (`[…]`), and comments.
pub fn parse_ini_setting(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
        return None;
    }
    if trimmed.starts_with('[') {
        return None;
    }
    let eq = trimmed.find('=')?;
    let key = trimmed[..eq].trim().to_ascii_lowercase();
    let val = trimmed[eq + 1..]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    Some((key, val))
}

/// Determine whether a PHP extension path is in an expected system directory.
fn is_standard_ext_path(path: &str) -> bool {
    path.starts_with("/usr/lib/php")
        || path.starts_with("/usr/lib64/php")
        || path.starts_with("/usr/local/lib/php")
        || path.starts_with("/usr/lib/x86_64-linux-gnu/php")
        || path.starts_with("/usr/lib/aarch64-linux-gnu/php")
}

/// Scan all discovered PHP ini files for dangerous settings.
fn check_php_ini(ctx: &DefenderContext) {
    let ini_paths = collect_ini_paths();
    if ini_paths.is_empty() {
        ctx.log_msg("  [~] No PHP ini files found");
        return;
    }

    for path in &ini_paths {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        let path_str = path.display().to_string();

        let mut saw_disable_functions = false;
        let mut saw_open_basedir = false;

        for line in contents.lines() {
            let Some((key, val)) = parse_ini_setting(line) else {
                continue;
            };

            match key.as_str() {
                "extension" | "zend_extension" => {
                    // Absolute paths outside standard dirs are suspicious
                    if val.starts_with('/') && !is_standard_ext_path(&val) {
                        ctx.emit(Finding::new(
                            Severity::High,
                            "php_modules",
                            format!("Non-standard PHP extension loaded from {val}"),
                            format!("file: {path_str}\nline: {line}"),
                        ));
                    }
                }
                "auto_prepend_file" | "auto_append_file" => {
                    if !val.is_empty() && val != "none" {
                        ctx.emit(Finding::new(
                            Severity::Critical,
                            "php_modules",
                            format!("PHP {key} set: {val}"),
                            format!("file: {path_str}\nline: {line}\nClassic persistence: code runs on every PHP request."),
                        ));
                    }
                }
                "disable_functions" => {
                    saw_disable_functions = true;
                    if val.is_empty() {
                        ctx.emit(Finding::new(
                            Severity::Medium,
                            "php_modules",
                            "PHP disable_functions is empty — dangerous built-ins callable",
                            format!("file: {path_str}"),
                        ));
                    }
                }
                "open_basedir" => {
                    saw_open_basedir = true;
                    if val.is_empty() {
                        ctx.emit(Finding::new(
                            Severity::Info,
                            "php_modules",
                            "PHP open_basedir not set — filesystem not restricted",
                            format!("file: {path_str}"),
                        ));
                    }
                }
                "allow_url_fopen" if val == "1" || val.eq_ignore_ascii_case("on") => {
                    ctx.emit(Finding::new(
                        Severity::Info,
                        "php_modules",
                        "PHP allow_url_fopen is enabled",
                        format!("file: {path_str}\nline: {line}"),
                    ));
                }
                "allow_url_include" if val == "1" || val.eq_ignore_ascii_case("on") => {
                    ctx.emit(Finding::new(
                        Severity::High,
                        "php_modules",
                        "PHP allow_url_include is enabled — remote code include possible",
                        format!("file: {path_str}\nline: {line}"),
                    ));
                }
                _ => {}
            }
        }

        if !saw_disable_functions {
            ctx.emit(Finding::new(
                Severity::Medium,
                "php_modules",
                "PHP disable_functions not set in this ini",
                format!("file: {path_str}"),
            ));
        }
        if !saw_open_basedir {
            ctx.emit(Finding::new(
                Severity::Info,
                "php_modules",
                "PHP open_basedir not configured in this ini",
                format!("file: {path_str}"),
            ));
        }
    }
}

// ── 2. Extension binary auditing ─────────────────────────────────────────────

/// Return the canonical base name of a PHP extension `.so` file.
///
/// Strips the `.so` suffix plus any version tags like `-20230831` or `.7.4`.
fn extension_base_name(filename: &str) -> String {
    let without_so = filename.strip_suffix(".so").unwrap_or(filename);
    // Strip trailing version suffix: -YYYYMMDD or .N.N
    let base = without_so
        .split('-')
        .next()
        .unwrap_or(without_so)
        .split('.')
        .next()
        .unwrap_or(without_so);
    base.to_ascii_lowercase()
}

/// Check whether a `.so` file name matches a known-safe PHP extension.
pub fn is_known_extension(filename: &str) -> bool {
    let base = extension_base_name(filename);
    KNOWN_SAFE_EXTENSIONS.contains(&base.as_str())
}

/// Recursively walk PHP extension directories and flag unknown or recently
/// modified `.so` files.
fn check_extension_dirs(ctx: &DefenderContext) {
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(THIRTY_DAYS_SECS))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    for dir in PHP_EXT_DIRS {
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            continue;
        }
        for entry in walkdir(dir_path) {
            let name = match entry.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(".so") => n.to_owned(),
                _ => continue,
            };
            let path_str = entry.display().to_string();

            if !is_known_extension(&name) {
                ctx.emit(Finding::new(
                    Severity::Medium,
                    "php_modules",
                    format!("Unknown PHP extension binary: {path_str}"),
                    format!("file: {path_str}\nNot in the known-safe extension list."),
                ));
            }

            if let Ok(meta) = std::fs::metadata(&entry) {
                if let Ok(mtime) = meta.modified() {
                    if mtime > cutoff {
                        let age = mtime
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        ctx.emit(Finding::new(
                            Severity::High,
                            "php_modules",
                            format!("Recently modified PHP extension: {name}"),
                            format!("file: {path_str}\nmtime epoch: {age}"),
                        ));
                    }
                }
            }
        }
    }
}

/// Walk a directory recursively, yielding all regular file paths.
fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_symlink() {
            continue;
        }
        if p.is_dir() {
            out.extend(walkdir(&p));
        } else if p.is_file() {
            out.push(p);
        }
    }
    out
}

// ── 3. Webshell pattern scan ──────────────────────────────────────────────────

/// A webshell pattern: a substring to search for (case-insensitive) and its
/// associated severity.
struct WebshellPattern {
    /// Needle to search for in PHP file contents (lowercased for comparison).
    needle: &'static str,
    /// Severity to emit when the pattern matches.
    severity: Severity,
    /// Human-readable label for the finding summary.
    label: &'static str,
}

/// Known malicious PHP patterns, ordered from most to least severe.
const WEBSHELL_PATTERNS: &[WebshellPattern] = &[
    WebshellPattern {
        needle: "eval(base64_decode",
        severity: Severity::Critical,
        label: "eval(base64_decode …) — obfuscated code execution",
    },
    WebshellPattern {
        needle: "eval(gzinflate",
        severity: Severity::Critical,
        label: "eval(gzinflate …) — compressed code execution",
    },
    WebshellPattern {
        needle: "eval(str_rot13",
        severity: Severity::Critical,
        label: "eval(str_rot13 …) — obfuscated code execution",
    },
    WebshellPattern {
        needle: "eval(gzuncompress",
        severity: Severity::Critical,
        label: "eval(gzuncompress …) — compressed code execution",
    },
    WebshellPattern {
        needle: "assert($_",
        severity: Severity::Critical,
        label: "assert($_…) — assert-based webshell",
    },
    WebshellPattern {
        needle: "system($_",
        severity: Severity::High,
        label: "system($_…) — command execution via superglobal",
    },
    WebshellPattern {
        needle: "passthru($_",
        severity: Severity::High,
        label: "passthru($_…) — command execution via superglobal",
    },
    WebshellPattern {
        needle: "shell_exec($_",
        severity: Severity::High,
        label: "shell_exec($_…) — command execution via superglobal",
    },
    WebshellPattern {
        needle: "exec($_",
        severity: Severity::High,
        label: "exec($_…) — command execution via superglobal",
    },
    WebshellPattern {
        needle: "$_get['cmd']",
        severity: Severity::High,
        label: "$_GET['cmd'] parameter — classic webshell trigger",
    },
    WebshellPattern {
        needle: "$_post['cmd']",
        severity: Severity::High,
        label: "$_POST['cmd'] parameter — classic webshell trigger",
    },
    WebshellPattern {
        needle: "$_request['cmd']",
        severity: Severity::High,
        label: "$_REQUEST['cmd'] parameter — classic webshell trigger",
    },
    WebshellPattern {
        needle: "base64_decode($_",
        severity: Severity::Medium,
        label: "base64_decode($_…) — possibly obfuscated input",
    },
];

/// Check a PHP file's contents against all known webshell patterns.
///
/// Returns the most severe match found, or `None` if no pattern matched.
pub fn contains_webshell_pattern(contents: &str) -> Option<(Severity, &'static str)> {
    let lower = contents.to_ascii_lowercase();
    // preg_replace /e is tricky — check separately
    let has_preg_e = lower.contains("preg_replace") && {
        // look for /e flag in the pattern argument: very rough heuristic
        lower.contains("/e\"") || lower.contains("/e'") || lower.contains("/e,")
    };
    if has_preg_e {
        return Some((
            Severity::Critical,
            "preg_replace with /e modifier — code execution",
        ));
    }
    for pat in WEBSHELL_PATTERNS {
        if lower.contains(pat.needle) {
            return Some((pat.severity, pat.label));
        }
    }
    None
}

/// Walk all web roots and emit a finding for each PHP file that matches a
/// known webshell pattern.
fn check_webroot_php(ctx: &DefenderContext) {
    let mut count = 0usize;
    let mut scanned = 0usize;

    for root in WEB_ROOTS {
        let root_path = Path::new(root);
        if !root_path.is_dir() {
            continue;
        }
        scan_php_dir(root_path, ctx, &mut count, &mut scanned);
        if count >= MAX_PHP_FILES {
            ctx.log_msg(&format!(
                "  [!] Webshell scan stopped at {MAX_PHP_FILES} PHP files limit"
            ));
            break;
        }
    }

    ctx.log_msg(&format!(
        "  [+] Webshell scan: {scanned} PHP files inspected"
    ));
}

/// Recursively scan a directory for PHP webshells, updating counters in place.
fn scan_php_dir(dir: &Path, ctx: &DefenderContext, count: &mut usize, scanned: &mut usize) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        if *count >= MAX_PHP_FILES {
            return;
        }
        let p = entry.path();
        if p.is_symlink() {
            continue;
        }
        if p.is_dir() {
            scan_php_dir(&p, ctx, count, scanned);
            continue;
        }
        if p.extension().and_then(|e| e.to_str()) != Some("php") {
            continue;
        }
        *count += 1;
        if *count % 1000 == 0 {
            ctx.log_msg(&format!(
                "  [+] Webshell scan: {count} PHP files checked..."
            ));
        }

        // Skip oversized files
        if let Ok(meta) = std::fs::metadata(&p) {
            if meta.len() > MAX_WEBSHELL_FILE_BYTES {
                continue;
            }
        }

        let Ok(contents) = std::fs::read_to_string(&p) else {
            continue;
        };
        *scanned += 1;

        if let Some((severity, label)) = contains_webshell_pattern(&contents) {
            ctx.emit(Finding::new(
                severity,
                "php_modules",
                format!("Possible webshell: {label}"),
                format!("file: {}", p.display()),
            ));
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ini_setting_basic() {
        assert_eq!(
            parse_ini_setting("allow_url_include = On"),
            Some(("allow_url_include".into(), "On".into()))
        );
    }

    #[test]
    fn parse_ini_setting_skips_comment() {
        assert_eq!(parse_ini_setting("; this is a comment"), None);
        assert_eq!(parse_ini_setting("# also a comment"), None);
    }

    #[test]
    fn parse_ini_setting_skips_blank() {
        assert_eq!(parse_ini_setting(""), None);
        assert_eq!(parse_ini_setting("   "), None);
    }

    #[test]
    fn parse_ini_setting_skips_section() {
        assert_eq!(parse_ini_setting("[PHP]"), None);
    }

    #[test]
    fn parse_ini_setting_strips_quotes() {
        let result = parse_ini_setting(r#"auto_prepend_file = "/tmp/evil.php""#);
        assert_eq!(
            result,
            Some(("auto_prepend_file".into(), "/tmp/evil.php".into()))
        );
    }

    #[test]
    fn parse_ini_setting_extension() {
        assert_eq!(
            parse_ini_setting("extension=/tmp/evil.so"),
            Some(("extension".into(), "/tmp/evil.so".into()))
        );
    }

    #[test]
    fn is_known_extension_safe_names() {
        assert!(is_known_extension("curl.so"));
        assert!(is_known_extension("mysqli.so"));
        assert!(is_known_extension("opcache.so"));
        assert!(is_known_extension("pdo_mysql.so"));
        assert!(is_known_extension("xdebug.so"));
    }

    #[test]
    fn is_known_extension_with_version_suffix() {
        assert!(is_known_extension("curl-20230831.so"));
        assert!(is_known_extension("mbstring-20210902.so"));
    }

    #[test]
    fn is_known_extension_unknown() {
        assert!(!is_known_extension("evilmod.so"));
        assert!(!is_known_extension("backdoor-20231001.so"));
        assert!(!is_known_extension("custom_logger.so"));
    }

    #[test]
    fn contains_webshell_eval_base64() {
        let code = r#"<?php eval(base64_decode($_POST['x'])); ?>"#;
        let result = contains_webshell_pattern(code);
        assert!(matches!(result, Some((Severity::Critical, _))));
    }

    #[test]
    fn contains_webshell_eval_gzinflate() {
        let code = "<?php eval(gzinflate(base64_decode($x))); ?>";
        let result = contains_webshell_pattern(code);
        assert!(matches!(result, Some((Severity::Critical, _))));
    }

    #[test]
    fn contains_webshell_assert() {
        let code = r#"<?php assert($_POST['cmd']); ?>"#;
        assert!(matches!(
            contains_webshell_pattern(code),
            Some((Severity::Critical, _))
        ));
    }

    #[test]
    fn contains_webshell_system() {
        let code = r#"<?php system($_GET['c']); ?>"#;
        assert!(matches!(
            contains_webshell_pattern(code),
            Some((Severity::High, _))
        ));
    }

    #[test]
    fn contains_webshell_cmd_param() {
        let code = r#"<?php system($_GET['cmd']); ?>"#;
        assert!(matches!(
            contains_webshell_pattern(code),
            Some((Severity::High, _))
        ));
    }

    #[test]
    fn contains_webshell_base64_decode_superglobal() {
        let code = r#"<?php echo base64_decode($_POST['x']); ?>"#;
        assert!(matches!(
            contains_webshell_pattern(code),
            Some((Severity::Medium, _))
        ));
    }

    #[test]
    fn contains_webshell_preg_replace_e() {
        let code = r#"<?php preg_replace("/.*/e", $_POST['cmd'], ""); ?>"#;
        assert!(matches!(
            contains_webshell_pattern(code),
            Some((Severity::Critical, _))
        ));
    }

    #[test]
    fn contains_webshell_clean_file() {
        let code = r#"<?php echo "Hello, world!"; ?>"#;
        assert!(contains_webshell_pattern(code).is_none());
    }

    #[test]
    fn contains_webshell_case_insensitive() {
        let code = r#"<?php EVAL(BASE64_DECODE($_POST['x'])); ?>"#;
        assert!(contains_webshell_pattern(code).is_some());
    }
}
