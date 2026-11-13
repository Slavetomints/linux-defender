//! Hidden ELF binaries in web roots and world-writable directories.
//!
//! An ELF magic header in a file with a dotfile name or a non-executable
//! extension (`.php`, `.jpg`, etc.) is a strong indicator of a hidden
//! backdoor or dropped payload.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::core::{Action, DefenderContext, Finding, Result, Severity};

/// Directories walked when looking for hidden ELF binaries.
const SCAN_DIRS: &[&str] = &["/var/www", "/tmp", "/dev/shm", "/var/tmp", "/home"];

/// Magic bytes that identify every ELF executable or shared object.
const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

/// Extensions that should never belong to an ELF binary.
const NON_EXEC_EXTENSIONS: &[&str] = &[
    "php", "jpg", "jpeg", "png", "gif", "txt", "conf", "log", "html", "htm", "css", "js", "json",
    "xml", "yaml", "yml", "md", "pdf", "zip", "tar",
];

/// A file whose name or extension should not be an ELF binary, but is.
pub struct HiddenElf {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Why the file is suspicious (dotfile, wrong extension, etc.).
    pub reason: &'static str,
}

/// Emit a finding for each hidden ELF binary found under the scan directories.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for hidden ELF binaries...");
    let mut count = 0usize;

    for dir in SCAN_DIRS {
        let base = Path::new(dir);
        if !base.exists() {
            continue;
        }

        for entry in WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let Some(reason) = suspicious_reason(path) else {
                continue;
            };

            if has_elf_magic(path) {
                count += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Critical,
                        "hidden_elf",
                        format!("Hidden ELF binary: {} ({})", path.display(), reason),
                        format!(
                            "path: {}\nreason: {}\nfirst 4 bytes match ELF magic \\x7fELF",
                            path.display(),
                            reason
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_action(Action::Delete(path.to_path_buf())),
                );
            }
        }
    }

    ctx.log_msg(&format!("[✓] Hidden ELF scan complete — {} found", count));
    Ok(())
}

/// Returns `Some(reason)` if the file is suspicious by name alone, else `None`.
fn suspicious_reason(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;

    if name.starts_with('.') {
        return Some("dotfile with ELF magic");
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && NON_EXEC_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    {
        return Some("ELF magic in non-executable extension");
    }

    None
}

/// Return true if the first four bytes of `path` match the ELF magic number.
fn has_elf_magic(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    matches!(file.read_exact(&mut buf), Ok(())) && buf == ELF_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotfiles_are_suspicious() {
        assert!(suspicious_reason(Path::new("/tmp/.backdoor")).is_some());
    }

    #[test]
    fn php_extension_is_suspicious() {
        assert!(suspicious_reason(Path::new("/var/www/shell.php")).is_some());
    }

    #[test]
    fn regular_binary_name_is_not_suspicious() {
        assert!(suspicious_reason(Path::new("/tmp/helper")).is_none());
    }
}
