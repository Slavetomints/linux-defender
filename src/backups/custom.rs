//! Backup of an operator-specified path.
//!
//! Used when a scored service lives outside the paths covered by the standard
//! backup modes. The operator supplies the path via `--custom <PATH>`; this
//! module hashes and copies it into the save directory the same way the full
//! backup does.

use std::path::{Path, PathBuf};

use crate::core::{DefenderContext, Result};

/// Back up an operator-specified path.
///
/// If `path` does not exist the function logs a warning and returns `Ok(())`
/// rather than failing — the caller should not abort the run for a missing
/// optional path.
pub fn run(ctx: &DefenderContext, path: &Path, save_location: &Option<PathBuf>) -> Result {
    if !path.exists() {
        ctx.log_msg(&format!(
            "[!] Custom backup path does not exist: {} — skipping",
            path.display()
        ));
        return Ok(());
    }

    ctx.log_msg(&format!("[+] Backing up custom path: {}", path.display()));

    let path_str = path.to_string_lossy();
    let paths: &[&str] = &[path_str.as_ref()];
    super::all::run_with_paths(ctx, save_location, paths)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::core::DefenderContext;
    use tempfile::TempDir;

    /// Build a minimal context that discards output.
    fn test_ctx() -> DefenderContext {
        DefenderContext::new(PathBuf::from("/dev/null"), false)
    }

    #[test]
    fn nonexistent_path_returns_ok() {
        let ctx = test_ctx();
        let missing = Path::new("/tmp/this_path_should_not_exist_ccdc_test_12345");
        let result = run(&ctx, missing, &None);
        assert!(result.is_ok());
    }

    #[test]
    fn existing_path_backs_up_successfully() {
        let ctx = test_ctx();

        let src_dir = TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("test.txt"), b"hello").unwrap();

        let save_dir = TempDir::new().unwrap();
        let save_location = Some(save_dir.path().to_path_buf());

        let result = run(&ctx, src_dir.path(), &save_location);
        assert!(result.is_ok());
    }
}
