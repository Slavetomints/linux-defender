//! APT source integrity auditing.
//!
//! A rogue apt source is a supply-chain foothold: point the box at an attacker
//! mirror, or disable signature verification, and the next `apt-get install` or
//! unattended upgrade pulls attacker-controlled packages that run as root.
//!
//! Detection is behavioral, not name-based. We flag two things regardless of
//! what the file is called:
//!
//! 1. A source entry whose host is not a recognised Debian/Ubuntu mirror
//!    (points at attacker infrastructure).
//! 2. A source entry that disables package signature verification
//!    (`[trusted=yes]` / `allow-insecure=yes`, or deb822 `Trusted: yes`).
//!
//! This is read-only: apt sources are not auto-edited, since a wrong edit breaks
//! package installs mid-competition. Findings carry a manual remediation.

use std::path::{Path, PathBuf};

use crate::core::{Action, DefenderContext, Finding, Result, Severity, Verdict};

/// Files and directories that hold apt source definitions.
const SOURCES_FILE: &str = "/etc/apt/sources.list";
/// Directory holding drop-in apt source files.
const SOURCES_DIR: &str = "/etc/apt/sources.list.d";

/// Host suffixes that belong to the official Debian/Ubuntu archive network.
/// A source host that doesn't end in one of these is treated as untrusted.
const TRUSTED_HOST_SUFFIXES: &[&str] = &[
    ".debian.org",
    ".ubuntu.com",
    // local file:/cdrom sources are not remote supply-chain risks
];

/// Options that disable package signature verification.
const INSECURE_OPTIONS: &[&str] = &["trusted=yes", "allow-insecure=yes", "allow-weak=yes"];

/// Audit all apt source definitions for untrusted hosts and disabled verification.
pub fn run(ctx: &DefenderContext) -> Result {
    if !Path::new(SOURCES_FILE).exists() && !Path::new(SOURCES_DIR).exists() {
        ctx.log_msg("[+] No apt sources present — skipping apt source audit");
        return Ok(());
    }

    ctx.log_msg("[+] Auditing apt sources...");
    let mut files: Vec<PathBuf> = Vec::new();
    if Path::new(SOURCES_FILE).exists() {
        files.push(PathBuf::from(SOURCES_FILE));
    }
    if let Ok(entries) = std::fs::read_dir(SOURCES_DIR) {
        for e in entries.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if ext == "list" || ext == "sources" {
                files.push(p);
            }
        }
    }

    let mut flagged = 0u32;
    for file in &files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        if file.extension().and_then(|x| x.to_str()) == Some("sources") {
            flagged += audit_deb822(ctx, file, &content);
        } else {
            flagged += audit_one_line(ctx, file, &content);
        }
    }

    ctx.log_msg(&format!(
        "[✓] apt source audit: {} suspicious entr(ies)",
        flagged
    ));
    Ok(())
}

/// True when `host` is not part of the official Debian/Ubuntu mirror network.
fn is_untrusted_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    !TRUSTED_HOST_SUFFIXES.iter().any(|s| h.ends_with(s))
}

/// Extract the host portion of a URI like `http://deb.debian.org/debian`.
fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map(|(_, r)| r)?;
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// Scheme of a URI (`http`, `https`, `file`, `cdrom`, ...).
fn scheme_of(uri: &str) -> Option<String> {
    uri.split_once("://").map(|(s, _)| s.to_ascii_lowercase())
}

/// Audit a classic one-line-per-source file.
fn audit_one_line(ctx: &DefenderContext, file: &Path, content: &str) -> u32 {
    let mut flagged = 0;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !(line.starts_with("deb ") || line.starts_with("deb-src ") || line.starts_with("deb[")) {
            continue;
        }

        // Options live in a single [ ... ] group right after the type.
        let insecure: Vec<&str> = INSECURE_OPTIONS
            .iter()
            .copied()
            .filter(|opt| {
                line.split(['[', ']', ' '])
                    .any(|tok| tok.eq_ignore_ascii_case(opt))
            })
            .collect();

        // The URI is the first whitespace token starting with a scheme.
        let uri = line.split_whitespace().find(|t| t.contains("://"));
        let (scheme, host) = match uri {
            Some(u) => (scheme_of(u), host_of(u)),
            None => (None, None),
        };

        emit_if_suspicious(ctx, file, line, scheme, host, &insecure, &mut flagged);
    }
    flagged
}

/// Audit a deb822 `.sources` file (stanzas of `Key: value`).
fn audit_deb822(ctx: &DefenderContext, file: &Path, content: &str) -> u32 {
    let mut flagged = 0;
    for stanza in content.split("\n\n") {
        if stanza.trim().is_empty() {
            continue;
        }
        let mut uris: Vec<String> = Vec::new();
        let mut insecure: Vec<&str> = Vec::new();
        for line in stanza.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("uris:") {
                uris.extend(v.split_whitespace().map(|s| s.to_string()));
            } else if lower.starts_with("trusted:") && lower.contains("yes") {
                insecure.push("Trusted: yes");
            } else if lower.starts_with("allow-insecure:") && lower.contains("yes") {
                insecure.push("Allow-Insecure: yes");
            }
        }
        if uris.is_empty() {
            continue;
        }
        for uri in &uris {
            emit_if_suspicious(
                ctx,
                file,
                uri,
                scheme_of(uri),
                host_of(uri),
                &insecure,
                &mut flagged,
            );
        }
    }
    flagged
}

/// Emit a finding when an entry is on an untrusted host or disables verification.
fn emit_if_suspicious(
    ctx: &DefenderContext,
    file: &Path,
    entry: &str,
    scheme: Option<String>,
    host: Option<String>,
    insecure: &[&str],
    flagged: &mut u32,
) {
    // Local file:/cdrom sources carry no remote supply-chain risk.
    if matches!(scheme.as_deref(), Some("file") | Some("cdrom")) {
        return;
    }

    let untrusted_host = host.as_deref().map(is_untrusted_host).unwrap_or(false);
    let verification_off = !insecure.is_empty();
    if !untrusted_host && !verification_off {
        return;
    }

    *flagged += 1;
    let mut reasons = Vec::new();
    if untrusted_host {
        reasons.push(format!(
            "host '{}' is not an official Debian/Ubuntu mirror",
            host.as_deref().unwrap_or("?")
        ));
    }
    if verification_off {
        reasons.push(format!(
            "signature verification disabled ({})",
            insecure.join(", ")
        ));
    }

    // Disabled verification is unambiguous; an untrusted host alone warrants review.
    let severity = if verification_off {
        Severity::Critical
    } else {
        Severity::High
    };

    ctx.log_evidence_line(&file.display().to_string(), entry);
    ctx.emit(
        Finding::new(
            severity,
            "apt_sources",
            format!(
                "Suspicious apt source in {}: {}",
                file.display(),
                reasons.join("; ")
            ),
            format!(
                "file: {}\nentry: {}\nreasons: {}",
                file.display(),
                entry,
                reasons.join("; ")
            ),
        )
        .with_path(file.to_path_buf())
        .with_context("file", file.display().to_string())
        .with_context("entry", entry.to_string())
        .with_context("reasons", reasons.join("; "))
        .with_verdict(
            Verdict::Investigate,
            format!(
                "This apt source could pull attacker-controlled packages that run as root. \
                 {}. Remove the entry (or restore the clean sources.list) and run \
                 `apt-get update` before any install.",
                reasons.join("; ")
            ),
        )
        .with_action(Action::Manual(format!(
            "review and remove the offending line in {}",
            file.display()
        ))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_mirrors_pass() {
        assert!(!is_untrusted_host("deb.debian.org"));
        assert!(!is_untrusted_host("security.debian.org"));
        assert!(!is_untrusted_host("archive.ubuntu.com"));
        assert!(!is_untrusted_host("us.archive.ubuntu.com"));
    }

    #[test]
    fn rogue_hosts_flagged() {
        assert!(is_untrusted_host("evil.attacker.net"));
        assert!(is_untrusted_host("192.168.1.50"));
        assert!(is_untrusted_host("debian.org.evil.com"));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("http://deb.debian.org/debian").as_deref(),
            Some("deb.debian.org")
        );
        assert_eq!(
            host_of("https://evil.net:8080/x").as_deref(),
            Some("evil.net")
        );
        assert_eq!(scheme_of("http://x/y").as_deref(), Some("http"));
        assert_eq!(host_of("notauri"), None);
    }

    #[test]
    fn deb822_trusted_yes_is_detected() {
        let ctx = DefenderContext::new(std::path::PathBuf::from("/dev/null"), false);
        let stanza = "Types: deb\nURIs: http://evil.net/debian\nSuites: bookworm\nTrusted: yes\n";
        let n = audit_deb822(&ctx, Path::new("/etc/apt/sources.list.d/x.sources"), stanza);
        assert_eq!(n, 1);
    }

    #[test]
    fn one_line_legit_mirror_not_flagged() {
        let ctx = DefenderContext::new(std::path::PathBuf::from("/dev/null"), false);
        let content = "deb http://deb.debian.org/debian bookworm main\n# comment\n";
        let n = audit_one_line(&ctx, Path::new("/etc/apt/sources.list"), content);
        assert_eq!(n, 0);
    }

    #[test]
    fn one_line_trusted_option_flagged() {
        let ctx = DefenderContext::new(std::path::PathBuf::from("/dev/null"), false);
        let content = "deb [trusted=yes] http://deb.debian.org/debian bookworm main\n";
        let n = audit_one_line(&ctx, Path::new("/etc/apt/sources.list"), content);
        assert_eq!(n, 1);
    }

    #[test]
    fn one_line_rogue_host_flagged() {
        let ctx = DefenderContext::new(std::path::PathBuf::from("/dev/null"), false);
        let content = "deb http://apt.evil.net/debian bookworm main\n";
        let n = audit_one_line(&ctx, Path::new("/etc/apt/sources.list"), content);
        assert_eq!(n, 1);
    }

    #[test]
    fn cdrom_and_file_sources_ignored() {
        let ctx = DefenderContext::new(std::path::PathBuf::from("/dev/null"), false);
        let content = "deb cdrom:[Debian]/ bookworm main\ndeb file:/srv/mirror bookworm main\n";
        let n = audit_one_line(&ctx, Path::new("/etc/apt/sources.list"), content);
        assert_eq!(n, 0);
    }
}
