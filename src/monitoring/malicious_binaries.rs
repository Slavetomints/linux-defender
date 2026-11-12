//! Malicious binary detection via package-manager integrity and PHP extension auditing.
//!
//! ## Check 1 — Package manager integrity
//! Runs `rpm -V` or `dpkg --verify` on critical service packages and flags any
//! file whose checksum no longer matches the package database. A modified
//! postfix or dovecot binary calling back to a red-team server is the classic
//! case this catches.
//!
//! ## Check 2 — PHP extension package ownership
//! Lists every `.so` file in the PHP extension directory and queries the
//! package manager to confirm it is package-owned. An unpackaged extension
//! is a strong indicator of a malicious PHP module injected by the red team.

use std::process::Command;

use crate::core::pkg::{PkgManager, detect_package_manager, is_package_owned};
use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict};

/// Critical packages to verify on RPM-based systems.
const RPM_PACKAGES: &[&str] = &[
    "openssh-server",
    "postfix",
    "dovecot",
    "httpd",
    "apache2",
    "php",
    "php-common",
    "php-cli",
    "php-fpm",
];

/// Critical packages to verify on Debian-based systems.
const DEB_PACKAGES: &[&str] = &[
    "openssh-server",
    "postfix",
    "dovecot-core",
    "apache2",
    "php-common",
    "php-cli",
    "php-fpm",
    "libapache2-mod-php",
];

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run malicious binary checks: package integrity and PHP extension ownership.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking for malicious/modified binaries...");

    let pkg_manager = detect_package_manager();
    check_package_integrity(ctx, pkg_manager);
    check_php_extensions(ctx, pkg_manager);

    ctx.log_msg("[✓] Malicious binary check complete");
    Ok(())
}

// ── Check 1: Package integrity ────────────────────────────────────────────────

/// Verify critical package file checksums via the package manager.
fn check_package_integrity(ctx: &DefenderContext, pm: PkgManager) {
    match pm {
        PkgManager::Rpm => check_rpm_integrity(ctx),
        PkgManager::Dpkg => check_dpkg_integrity(ctx),
        PkgManager::Unknown => {
            ctx.debug("No supported package manager found — skipping package integrity check");
        }
    }
}

/// Run `rpm -V <pkg>` for each critical package and emit findings for modified files.
fn check_rpm_integrity(ctx: &DefenderContext) {
    for &pkg in RPM_PACKAGES {
        // Check if the package is installed first; rpm -V on a missing package
        // prints an error and exits non-zero without useful output.
        let installed = Command::new("rpm")
            .args(["-q", "--quiet", pkg])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !installed {
            ctx.debug(&format!("rpm: package {} not installed — skipping", pkg));
            continue;
        }

        ctx.debug(&format!("rpm -V {}", pkg));
        let Ok(out) = Command::new("rpm").args(["-V", pkg]).output() else {
            continue;
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            parse_rpm_verify_line(ctx, pkg, line);
        }
    }
}

/// Parse one `rpm -V` output line and emit a finding if the checksum changed.
///
/// Format: `SM5DLUGT c /path/to/file`
/// Position 2 (0-indexed) = '5' means MD5/checksum mismatch.
/// Position 0 = 'S' means size changed.
fn parse_rpm_verify_line(ctx: &DefenderContext, pkg: &str, line: &str) {
    let flags = line.split_whitespace().next().unwrap_or("");
    let path = line.split_whitespace().last().unwrap_or(line);

    // Skip config-file markers — they legitimately diverge from package defaults.
    let is_config = line.split_whitespace().nth(1) == Some("c");
    if is_config {
        return;
    }

    let checksum_changed = flags.chars().nth(1) == Some('5');
    let size_changed = flags.starts_with('S');

    if checksum_changed {
        ctx.log_evidence_line(&format!("rpm -V {}", pkg), line);
        ctx.emit(
            Finding::new(
                Severity::Critical,
                "malicious_binaries",
                format!(
                    "Package file checksum mismatch: {} (package: {})",
                    path, pkg
                ),
                format!(
                    "package: {}\nfile: {}\nrpm -V output: {}\n\n\
                     The file's checksum no longer matches the package database. \
                     This may indicate a replaced or patched binary — a common red-team \
                     technique to install a backdoored version of a service.",
                    pkg, path, line
                ),
            )
            .with_context("package", pkg.to_string())
            .with_context("file", path.to_string())
            .with_context("rpm_flags", flags.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "Reinstall the package to restore the binary: `rpm -ivh --replacepkgs {}`\n\
                     Check {} for signs of compromise before replacing.",
                    pkg, path
                ),
            )
            .with_action(Action::Manual(format!("rpm -ivh --replacepkgs {}", pkg))),
        );
    } else if size_changed {
        ctx.log_evidence_line(&format!("rpm -V {}", pkg), line);
        ctx.emit(
            Finding::new(
                Severity::High,
                "malicious_binaries",
                format!("Package file size changed: {} (package: {})", path, pkg),
                format!("package: {}\nfile: {}\nrpm -V output: {}", pkg, path, line),
            )
            .with_context("package", pkg.to_string())
            .with_context("file", path.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "File size diverged from package database for {}. \
                     Investigate whether this is a legitimate config change or tampering.",
                    path
                ),
            ),
        );
    }
}

/// Run `dpkg --verify <pkg>` for each critical package.
fn check_dpkg_integrity(ctx: &DefenderContext) {
    for &pkg in DEB_PACKAGES {
        ctx.debug(&format!("dpkg --verify {}", pkg));
        let Ok(out) = Command::new("dpkg").args(["--verify", pkg]).output() else {
            continue;
        };

        // dpkg --verify exits 0 when clean; non-zero or output lines = problems.
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            parse_dpkg_verify_line(ctx, pkg, line);
        }
    }
}

/// Parse one `dpkg --verify` output line.
///
/// Format: `??5?????? /path/to/file`
/// Position 2 (0-indexed) = '5' means MD5 checksum failure.
fn parse_dpkg_verify_line(ctx: &DefenderContext, pkg: &str, line: &str) {
    let flags = line.split_whitespace().next().unwrap_or("");
    let path = line.split_whitespace().last().unwrap_or(line);

    let checksum_bad = flags.chars().nth(2) == Some('5');
    if !checksum_bad {
        return;
    }

    ctx.log_evidence_line(&format!("dpkg --verify {}", pkg), line);
    ctx.emit(
        Finding::new(
            Severity::Critical,
            "malicious_binaries",
            format!(
                "Package file checksum mismatch: {} (package: {})",
                path, pkg
            ),
            format!(
                "package: {}\nfile: {}\ndpkg --verify output: {}\n\n\
                 The file's MD5 no longer matches the package database. \
                 This may indicate a replaced or patched binary.",
                pkg, path, line
            ),
        )
        .with_context("package", pkg.to_string())
        .with_context("file", path.to_string())
        .with_context("dpkg_flags", flags.to_string())
        .with_verdict(
            Verdict::Investigate,
            format!(
                "Reinstall the package to restore the binary: \
                 `apt-get install --reinstall {}`",
                pkg
            ),
        )
        .with_action(Action::Manual(format!(
            "apt-get install --reinstall {}",
            pkg
        ))),
    );
}

// ── Check 2: PHP extension package ownership ──────────────────────────────────

/// Flag PHP extension .so files not owned by any package.
fn check_php_extensions(ctx: &DefenderContext, pm: PkgManager) {
    if pm == PkgManager::Unknown {
        ctx.debug("No package manager — skipping PHP extension ownership check");
        return;
    }

    // Get the runtime extension directory from PHP itself.
    let ext_dir = get_php_extension_dir();
    if ext_dir.is_empty() {
        ctx.debug("Could not determine PHP extension dir — php not installed or not in PATH");
        return;
    }

    ctx.log_msg(&format!("[+] Checking PHP extension dir: {}", ext_dir));

    let Ok(entries) = std::fs::read_dir(&ext_dir) else {
        ctx.debug(&format!("Could not read PHP extension dir: {}", ext_dir));
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(ext) = path.extension() else {
            continue;
        };
        if ext != "so" {
            continue;
        }

        let path_str = path.to_string_lossy().to_string();
        let owned = is_package_owned(&path_str, pm);

        if !owned {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            ctx.log_evidence_line("php_extension_unpackaged", &path_str);
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "malicious_binaries",
                    format!(
                        "PHP extension not owned by any package: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    format!(
                        "path: {}\nsize: {} bytes\n\n\
                         This PHP extension .so file is not registered with the package \
                         manager. A red team may have installed a malicious PHP module \
                         to intercept requests, exfiltrate data, or maintain persistence.",
                        path_str, size
                    ),
                )
                .with_context("path", path_str.clone())
                .with_context("size_bytes", size.to_string())
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "Inspect {} — if it is not a known legitimate extension, \
                         remove it and restart the web server / php-fpm.",
                        path_str
                    ),
                )
                .with_action(Action::Manual(format!("rm -f {}", path_str))),
            );
        }
    }
}

/// Ask PHP itself for its extension directory path.
fn get_php_extension_dir() -> String {
    Command::new("php")
        .args(["-r", "echo ini_get('extension_dir');"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}
