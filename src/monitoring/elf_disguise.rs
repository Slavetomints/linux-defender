//! ELF binaries and scripts masquerading as other file types.
//!
//! Five checks:
//!   1. ELF magic in temp/memory directories
//!   2. Hidden dotfiles containing ELF magic
//!   3. ELF magic in files with text-like extensions (.sh, .txt, .py, …)
//!   4. Shebang (`#!`) in files with binary/archive extensions (.png, .tar, …)
//!   5. ELF magic anywhere under web roots

use std::io::Read;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Magic bytes at the start of every ELF file.
const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
/// Magic bytes at the start of a POSIX shell script (`#!`).
const SHEBANG: [u8; 2] = [0x23, 0x21]; // #!

/// Directories where a staged ELF is almost always malicious.
const TEMP_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/run/shm"];

/// Roots walked for checks 2, 3, and 4.
const GENERAL_ROOTS: &[&str] = &[
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/shm",
    "/home",
    "/root",
    "/etc",
    "/opt",
    "/var/www",
    "/srv",
    "/usr/local",
];

/// Web roots — ELF here is unconditionally bad.
const WEB_ROOTS: &[&str] = &[
    "/var/www",
    "/srv",
    "/var/html",
    "/usr/share/nginx",
    "/usr/share/apache2",
];

/// Extensions that should never contain an ELF binary.
const TEXT_EXTENSIONS: &[&str] = &[
    "sh", "py", "pl", "rb", "txt", "log", "conf", "cfg", "ini", "md", "html", "php", "json",
    "yaml", "yml",
];

/// Extensions that should never contain a shell script.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "tar", "gz", "zip", "pdf", "mp3", "mp4", "avi",
];

/// Read the first `N` bytes of a file; returns `None` on any error or short read.
fn read_magic(path: &Path) -> Option<[u8; 4]> {
    let mut buf = [0u8; 4];
    let mut f = std::fs::File::open(path).ok()?;
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// Return true if `path` begins with the ELF magic bytes.
fn is_elf(path: &Path) -> bool {
    read_magic(path).map(|m| m == ELF_MAGIC).unwrap_or(false)
}

/// Return true if `path` begins with the `#!` shebang sequence.
fn is_shebang(path: &Path) -> bool {
    read_magic(path).map(|m| m[..2] == SHEBANG).unwrap_or(false)
}

/// Return the lowercased extension of `path`, or `None` if there is none.
fn ext(path: &Path) -> Option<String> {
    path.extension().map(|e| e.to_string_lossy().to_lowercase())
}

/// Scan for disguised ELF binaries and scripts with misleading extensions.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for disguised ELF binaries and scripts...");

    let mut findings = 0u32;

    // ── Check 1: ELF in temp/memory dirs ────────────────────────────────────
    for root in TEMP_DIRS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if is_elf(path) {
                findings += 1;
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "elf_disguise",
                        format!("ELF binary in temp dir: {}", path.display()),
                        format!(
                            "path: {}\nreason: ELF executable staged in volatile directory",
                            path.display()
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("check", "elf-in-temp")
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "{} is an ELF executable in {}. Legitimate processes do not store \
                             executables here. This is a staged payload, implant, or tool \
                             dropped by the red team. Delete it immediately.",
                            name, root
                        ),
                    ),
                );
            }
        }
    }

    // ── Check 2: Hidden ELF (dotfile) ────────────────────────────────────────
    for root in GENERAL_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let fname = path.file_name().unwrap_or_default().to_string_lossy();

            if fname.starts_with('.') && is_elf(path) {
                // Skip if already caught by check 1
                if TEMP_DIRS.iter().any(|t| path.starts_with(t)) {
                    continue;
                }
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "elf_disguise",
                        format!("Hidden ELF binary: {}", path.display()),
                        format!(
                            "path: {}\nreason: dotfile with ELF magic — hidden executable",
                            path.display()
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("check", "hidden-elf")
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "{} is a hidden file (starts with '.') containing ELF binary data. \
                             Legitimate dotfiles are text configs; a hidden ELF is a disguised \
                             implant or tool. Investigate and delete.",
                            path.display()
                        ),
                    ),
                );
            }
        }
    }

    // ── Check 3: ELF with text-like extension ────────────────────────────────
    for root in GENERAL_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let file_ext = match ext(path) {
                Some(e) => e,
                None => continue,
            };
            if TEXT_EXTENSIONS.iter().any(|&e| e == file_ext) && is_elf(path) {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "elf_disguise",
                        format!("ELF disguised as .{}: {}", file_ext, path.display()),
                        format!(
                            "path: {}\nextension: .{}\nreason: ELF magic in file with text extension",
                            path.display(), file_ext
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("extension", file_ext.clone())
                    .with_context("check", "elf-wrong-extension")
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "{} has a .{} extension but contains ELF binary data. The attacker \
                             renamed an executable to look like a text file/script. Delete it.",
                            path.display(), file_ext
                        ),
                    ),
                );
            }
        }
    }

    // ── Check 4: Script with binary/archive extension ─────────────────────────
    for root in GENERAL_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let file_ext = match ext(path) {
                Some(e) => e,
                None => continue,
            };
            if BINARY_EXTENSIONS.iter().any(|&e| e == file_ext) && is_shebang(path) {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "elf_disguise",
                        format!("Script disguised as .{}: {}", file_ext, path.display()),
                        format!(
                            "path: {}\nextension: .{}\nreason: shebang (#!) in file with binary/archive extension",
                            path.display(), file_ext
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("extension", file_ext.clone())
                    .with_context("check", "script-wrong-extension")
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "{} has a .{} extension but starts with a shell shebang (#!). \
                             A script disguised as an image or archive is a red team evasion \
                             technique. Inspect and delete if malicious.",
                            path.display(), file_ext
                        ),
                    ),
                );
            }
        }
    }

    // ── Check 5: ELF in web root ──────────────────────────────────────────────
    let already_seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for root in WEB_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if already_seen.contains(path) {
                continue;
            }
            if is_elf(path) {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "elf_disguise",
                        format!("ELF binary in web root: {}", path.display()),
                        format!(
                            "path: {}\nroot: {}\nreason: ELF executable in web-served directory",
                            path.display(),
                            root
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("web_root", root.to_string())
                    .with_context("check", "elf-in-webroot")
                    .with_verdict(
                        Verdict::Remove,
                        format!(
                            "{} is an ELF executable inside a web-served directory. Web roots \
                             should never contain executables — this is almost certainly a \
                             webshell payload, a compiled backdoor, or a staging artifact. \
                             Delete immediately.",
                            path.display()
                        ),
                    ),
                );
            }
        }
    }

    ctx.log_msg(&format!(
        "[✓] ELF disguise scan complete — {} suspicious file{}",
        findings,
        if findings == 1 { "" } else { "s" },
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_bytes(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    #[test]
    fn detects_elf_magic() {
        let f = write_bytes(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]);
        assert!(is_elf(f.path()));
    }

    #[test]
    fn rejects_non_elf() {
        let f = write_bytes(b"#!/bin/bash\necho hi\n");
        assert!(!is_elf(f.path()));
    }

    #[test]
    fn detects_shebang() {
        let f = write_bytes(b"#!/usr/bin/env python3\nprint('hi')\n");
        assert!(is_shebang(f.path()));
    }

    #[test]
    fn rejects_non_shebang() {
        let f = write_bytes(&[0x7F, 0x45, 0x4C, 0x46]);
        assert!(!is_shebang(f.path()));
    }

    #[test]
    fn read_magic_handles_short_file() {
        // A file with only 2 bytes — read_magic should return None (can't fill 4 bytes).
        let f = write_bytes(&[0x7F, 0x45]);
        assert!(read_magic(f.path()).is_none());
    }

    #[test]
    fn read_magic_handles_empty_file() {
        let f = write_bytes(&[]);
        assert!(read_magic(f.path()).is_none());
    }

    #[test]
    fn ext_lowercases_extension() {
        let p = Path::new("/tmp/test.SH");
        assert_eq!(ext(p), Some("sh".to_string()));
    }

    #[test]
    fn text_extensions_include_expected() {
        assert!(TEXT_EXTENSIONS.contains(&"sh"));
        assert!(TEXT_EXTENSIONS.contains(&"py"));
        assert!(TEXT_EXTENSIONS.contains(&"conf"));
    }

    #[test]
    fn binary_extensions_include_expected() {
        assert!(BINARY_EXTENSIONS.contains(&"png"));
        assert!(BINARY_EXTENSIONS.contains(&"tar"));
        assert!(BINARY_EXTENSIONS.contains(&"pdf"));
    }

    #[test]
    fn ext_returns_none_for_no_extension() {
        let p = Path::new("/tmp/Makefile");
        assert_eq!(ext(p), None);
    }

    #[test]
    fn ext_returns_last_component_only() {
        // For "payload.tar.sh" the extension is "sh"
        let p = Path::new("/tmp/payload.tar.sh");
        assert_eq!(ext(p), Some("sh".to_string()));
    }

    #[test]
    fn elf_in_text_extension_would_be_flagged() {
        let f = write_bytes(&[0x7F, 0x45, 0x4C, 0x46, 0, 0]);
        // Write to a path with .sh extension
        let sh_path = std::env::temp_dir().join("test_elf.sh");
        std::fs::copy(f.path(), &sh_path).unwrap();
        let file_ext = ext(&sh_path).unwrap_or_default();
        let is_text = TEXT_EXTENSIONS.iter().any(|&e| e == file_ext);
        let has_elf = is_elf(&sh_path);
        assert!(is_text && has_elf, "should be flagged as ELF in text ext");
        std::fs::remove_file(sh_path).unwrap();
    }

    #[test]
    fn shebang_in_png_would_be_flagged() {
        let f = write_bytes(b"#!/bin/sh\nmalicious\n");
        let png_path = std::env::temp_dir().join("test_script.png");
        std::fs::copy(f.path(), &png_path).unwrap();
        let file_ext = ext(&png_path).unwrap_or_default();
        let is_binary = BINARY_EXTENSIONS.iter().any(|&e| e == file_ext);
        let has_shebang = is_shebang(&png_path);
        assert!(is_binary && has_shebang, "should be flagged as shebang in binary ext");
        std::fs::remove_file(png_path).unwrap();
    }

    #[test]
    fn web_roots_include_var_www() {
        assert!(WEB_ROOTS.contains(&"/var/www"));
    }

    #[test]
    fn temp_dirs_include_dev_shm() {
        assert!(TEMP_DIRS.contains(&"/dev/shm"));
    }
}
