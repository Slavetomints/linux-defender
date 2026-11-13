//! Detect backdoors injected into web server and PHP configurations.
//!
//! Checks nginx, Apache, and PHP ini files for directives that enable code
//! execution, remote file inclusion, or proxying through attacker-controlled
//! hosts.
//!
//! Configuration changes are risky to auto-modify — a wrong edit can take a
//! scored service offline — so all findings use `Verdict::Investigate` with
//! specific remediation instructions.

use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Walk a directory tree and return paths of all files whose name ends with
/// `ext` (e.g. `.conf`).
fn walk_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            out.extend(walk_with_ext(&path, ext));
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext.trim_start_matches('.')) {
            out.push(path);
        }
    }
    out
}

/// Walk a directory tree and return all regular files (any extension).
fn walk_all_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            out.extend(walk_all_files(&path));
        } else if path.is_file() {
            out.push(path);
        }
    }
    out
}

/// Emit a finding for a suspicious configuration line.
#[allow(clippy::too_many_arguments)]
fn flag_line(
    ctx: &DefenderContext,
    file_path: &Path,
    line: &str,
    severity: Severity,
    module: &'static str,
    summary: impl Into<String>,
    detail: impl Into<String>,
    recommendation: impl Into<String>,
) {
    let file_str = file_path.to_string_lossy().into_owned();
    ctx.log_evidence_line(&file_str, line);
    ctx.emit(
        Finding::new(severity, module, summary, detail)
            .with_path(file_path.to_path_buf())
            .with_context("file", file_str)
            .with_context("line", line.trim().to_string())
            .with_verdict(Verdict::Investigate, recommendation),
    );
}

// ── nginx ─────────────────────────────────────────────────────────────────────

/// Return true if a `proxy_pass` target looks external (not localhost/loopback).
fn proxy_pass_is_external(target: &str) -> bool {
    let target = target.trim().trim_end_matches(';');
    // Legitimate internal proxies go to 127.x, ::1, localhost, or a unix socket.
    if target.starts_with("http://127.")
        || target.starts_with("https://127.")
        || target.starts_with("http://localhost")
        || target.starts_with("https://localhost")
        || target.starts_with("http://[::1]")
        || target.starts_with("https://[::1]")
        || target.starts_with("unix:")
        || target.starts_with("$")
    // nginx variable — ambiguous, skip
    {
        return false;
    }
    // If it starts with http(s):// and is not loopback, flag it.
    target.starts_with("http://") || target.starts_with("https://")
}

/// Check an nginx config file for suspicious directives.
fn check_nginx_file(ctx: &DefenderContext, path: &Path) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };

    for line in content.lines() {
        let trimmed = line.trim();

        // proxy_pass pointing to an external host.
        if let Some(rest) = trimmed.strip_prefix("proxy_pass ")
            && proxy_pass_is_external(rest)
        {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::High,
                "webserver_config",
                format!("nginx proxy_pass to external host in {}", path.display()),
                format!(
                    "nginx is forwarding requests to a potentially attacker-controlled host: {}",
                    rest.trim_end_matches(';')
                ),
                "Remove or correct the proxy_pass directive. Traffic should not be forwarded to external or untrusted hosts.",
            );
        }

        // alias/root pointing into volatile directories.
        if trimmed.starts_with("alias ") || trimmed.starts_with("root ") {
            for volatile in &["/tmp/", "/dev/shm/"] {
                if trimmed.contains(volatile) {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::Critical,
                        "webserver_config",
                        format!("nginx serves files from {} in {}", volatile, path.display()),
                        format!(
                            "nginx is configured to serve files from a world-writable path {}. An attacker can plant files there and serve them.",
                            volatile
                        ),
                        "Change the alias/root to a path owned by the web server user, not a world-writable directory.",
                    );
                }
            }
        }

        // Suspicious add_header with base64-looking value.
        if trimmed.starts_with("add_header X-") {
            // Base64 values contain only [A-Za-z0-9+/=] and are often padded.
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let value = parts[2].trim_matches(|c| c == '"' || c == '\'' || c == ';');
                let looks_b64 = value.len() > 20
                    && value
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
                if looks_b64 {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::Medium,
                        "webserver_config",
                        format!("nginx suspicious base64 add_header in {}", path.display()),
                        "A custom X- header contains a value that looks like base64-encoded data. Attackers sometimes use response headers to beacon data.",
                        "Remove the add_header directive unless it is known-good for your application.",
                    );
                }
            }
        }

        // lua_code_cache off combined with lua content.
        if trimmed.contains("lua_code_cache") && trimmed.contains("off") {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::Medium,
                "webserver_config",
                format!("nginx lua_code_cache off in {}", path.display()),
                "lua_code_cache off causes nginx to reload Lua code on every request, which makes it trivial for an attacker to hot-patch a backdoor without restarting the server.",
                "Set lua_code_cache on; in production. Confirm Lua content blocks are expected.",
            );
        }
        if trimmed.starts_with("content_by_lua")
            || trimmed.starts_with("access_by_lua")
            || trimmed.starts_with("rewrite_by_lua")
        {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::Medium,
                "webserver_config",
                format!("nginx inline Lua execution in {}", path.display()),
                "Inline Lua blocks execute arbitrary code inside nginx. Verify this code is expected and has not been modified.",
                "Audit all Lua blocks. Prefer lua_code_cache on and file-based modules over inline Lua.",
            );
        }
    }
}

// ── Apache ────────────────────────────────────────────────────────────────────

/// A list of extensions that PHP should legitimately process.
const NORMAL_PHP_EXTENSIONS: &[&str] = &["php", "php3", "php4", "php5", "php7", "php8", "phtml"];

/// Return true if `ext` is not in the normal PHP extension list.
fn is_unusual_php_extension(ext: &str) -> bool {
    let ext = ext.trim_matches(|c| c == '.' || c == '"' || c == '\'' || c == ';');
    !NORMAL_PHP_EXTENSIONS.contains(&ext)
}

/// Simple check: does a RewriteRule target look like an external IP/URL?
fn rewrite_proxies_external(rule: &str) -> bool {
    rule.contains("http://") || rule.contains("https://")
}

/// Check an Apache config file for suspicious directives.
fn check_apache_file(ctx: &DefenderContext, path: &Path) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };

    for line in content.lines() {
        let trimmed = line.trim();

        // AddHandler for unusual extensions.
        if let Some(rest) = trimmed.strip_prefix("AddHandler ")
            && (rest.contains("x-httpd-php") || rest.contains("application/x-httpd-php"))
        {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            // parts[0] = handler, parts[1..] = extensions
            for ext in parts.iter().skip(1) {
                if is_unusual_php_extension(ext) {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::High,
                        "webserver_config",
                        format!(
                            "Apache maps PHP handler to unusual extension {} in {}",
                            ext,
                            path.display()
                        ),
                        format!(
                            "AddHandler maps the PHP interpreter to extension {}. Attackers use this to execute PHP code from files with innocuous extensions (e.g. .jpg.php or .xyz).",
                            ext
                        ),
                        "Remove the AddHandler directive for non-standard extensions. PHP should only execute .php files.",
                    );
                }
            }
        }

        // Options +ExecCGI outside of a standard CGI directory.
        if trimmed.contains("Options") && trimmed.contains("+ExecCGI") {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::High,
                "webserver_config",
                format!("Apache +ExecCGI enabled in {}", path.display()),
                "+ExecCGI allows CGI scripts to execute inside this directory. Unless this is the designated cgi-bin, it should not be set.",
                "Remove +ExecCGI unless this directory is the authorised CGI directory.",
            );
        }

        // AddType PHP handler for non-PHP extensions.
        if let Some(rest) = trimmed.strip_prefix("AddType ")
            && rest.contains("x-httpd-php")
        {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            for ext in parts.iter().skip(1) {
                if is_unusual_php_extension(ext) {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::High,
                        "webserver_config",
                        format!(
                            "Apache AddType maps PHP to unusual extension {} in {}",
                            ext,
                            path.display()
                        ),
                        format!(
                            "AddType routes the PHP MIME type to extension {}. This allows PHP execution in files that look like static assets.",
                            ext
                        ),
                        "Remove the AddType directive for non-standard extensions.",
                    );
                }
            }
        }

        // RewriteRule that proxies to an external URL.
        if trimmed.starts_with("RewriteRule") && rewrite_proxies_external(trimmed) {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::Medium,
                "webserver_config",
                format!(
                    "Apache RewriteRule proxies to external URL in {}",
                    path.display()
                ),
                "A RewriteRule forwards requests to an external host. An attacker may use this to redirect traffic or proxy credentials.",
                "Audit the RewriteRule. If it proxies to an attacker-controlled host, remove it.",
            );
        }

        // PassEnv LD_PRELOAD — extremely dangerous.
        if trimmed.starts_with("PassEnv") && trimmed.contains("LD_PRELOAD") {
            flag_line(
                ctx,
                path,
                trimmed,
                Severity::Critical,
                "webserver_config",
                format!(
                    "Apache PassEnv LD_PRELOAD in {} — library injection",
                    path.display()
                ),
                "PassEnv LD_PRELOAD causes the web server to load an attacker-specified shared library into every PHP/CGI process. This achieves complete code execution.",
                "Remove the PassEnv LD_PRELOAD directive immediately. Verify the pointed-to library is not malicious.",
            );
        }
    }
}

// ── PHP ini ───────────────────────────────────────────────────────────────────

/// Check a PHP ini file for dangerous settings.
fn check_php_ini(ctx: &DefenderContext, path: &Path) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };

    let mut allow_url_fopen = false;
    let mut allow_url_include = false;

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments and section headers.
        if trimmed.starts_with(';') || trimmed.starts_with('[') || trimmed.is_empty() {
            continue;
        }

        // Normalise: key = value (strip inline comments).
        let without_comment = trimmed.split(';').next().unwrap_or(trimmed).trim();
        let Some((key, value)) = without_comment.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "disable_functions" => {
                if value.is_empty() {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::High,
                        "webserver_config",
                        format!("PHP disable_functions is empty in {}", path.display()),
                        "disable_functions = (empty) means ALL dangerous PHP functions are available, including exec(), system(), shell_exec(), passthru(), and others.",
                        "Add a restrictive disable_functions list: disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source",
                    );
                }
            }
            "allow_url_fopen" => {
                if value.eq_ignore_ascii_case("on") || value == "1" {
                    allow_url_fopen = true;
                }
            }
            "allow_url_include" => {
                if value.eq_ignore_ascii_case("on") || value == "1" {
                    allow_url_include = true;
                    // Flag immediately on its own line too.
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::High,
                        "webserver_config",
                        format!(
                            "PHP allow_url_include is On in {} — remote file inclusion enabled",
                            path.display()
                        ),
                        "allow_url_include = On allows PHP's include/require to load code from remote URLs — a classic remote file inclusion (RFI) vector.",
                        "Set allow_url_include = Off in php.ini.",
                    );
                }
            }
            "auto_prepend_file" | "auto_append_file" => {
                if !value.is_empty() && value != "none" {
                    flag_line(
                        ctx,
                        path,
                        trimmed,
                        Severity::Critical,
                        "webserver_config",
                        format!(
                            "PHP {} set to {:?} in {} — executes on every request",
                            key,
                            value,
                            path.display()
                        ),
                        format!(
                            "{} = {} causes PHP to execute this file before/after every script. An attacker can use this as a persistent backdoor that runs on every HTTP request.",
                            key, value
                        ),
                        format!(
                            "Remove the {} directive unless this file is a known-good application bootstrap.",
                            key
                        ),
                    );
                }
            }
            "open_basedir" if value.is_empty() => {
                flag_line(
                    ctx,
                    path,
                    trimmed,
                    Severity::Medium,
                    "webserver_config",
                    format!(
                        "PHP open_basedir is empty in {} — no filesystem restriction",
                        path.display()
                    ),
                    "open_basedir = (empty) means PHP scripts can read any file the web server user can access, including /etc/passwd and application secrets.",
                    "Set open_basedir to the web root, e.g. open_basedir = /var/www/html:/tmp",
                );
            }
            _ => {}
        }
    }

    // Combined allow_url_fopen + allow_url_include (extra finding for the pair).
    if allow_url_fopen && allow_url_include {
        flag_line(
            ctx,
            path,
            "allow_url_fopen = On  (combined with allow_url_include = On)",
            Severity::High,
            "webserver_config",
            format!(
                "PHP allow_url_fopen AND allow_url_include both On in {} — full RFI attack surface",
                path.display()
            ),
            "Both allow_url_fopen and allow_url_include are enabled. Together they allow PHP to fetch and execute arbitrary remote PHP code — a complete remote file inclusion (RFI) chain.",
            "Set both to Off in php.ini.",
        );
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run all web server configuration checks.
pub fn run(ctx: &DefenderContext) -> Result {
    // nginx
    let nginx_dir = Path::new("/etc/nginx");
    if nginx_dir.is_dir() {
        for conf in walk_with_ext(nginx_dir, "conf") {
            check_nginx_file(ctx, &conf);
        }
    }

    // Apache (Debian/Ubuntu path and RHEL/CentOS path).
    for apache_dir in &["/etc/apache2", "/etc/httpd"] {
        let dir = Path::new(apache_dir);
        if dir.is_dir() {
            for conf in walk_with_ext(dir, "conf") {
                check_apache_file(ctx, &conf);
            }
        }
    }

    // PHP ini files.
    let php_paths = [
        PathBuf::from("/etc/php.ini"),
        PathBuf::from("/etc/php"),
        PathBuf::from("/etc/php.d"),
    ];
    for php_path in &php_paths {
        if php_path.is_file() {
            check_php_ini(ctx, php_path);
        } else if php_path.is_dir() {
            for ini in walk_all_files(php_path) {
                if ini.extension().and_then(|e| e.to_str()) == Some("ini") {
                    check_php_ini(ctx, &ini);
                }
            }
        }
    }

    Ok(())
}
