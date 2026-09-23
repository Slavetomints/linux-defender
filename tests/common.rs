//! Fixture helpers shared by the integration test binaries.
//!
//! Each test binary pulls this in with `#[path = "common.rs"] mod common;`, so
//! every binary uses only part of it.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use defender_cli::core::DefenderContext;
use tempfile::TempDir;

/// The binary under test, built by Cargo for this integration test run.
pub const BIN: &str = env!("CARGO_BIN_EXE_defender-cli");

/// Run the CLI with `args`, using `dir` as the working directory so the report
/// file it writes lands somewhere disposable.
pub fn run_cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to execute defender-cli")
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// Several checks prompt on stdin when they have the privileges to act. Tests
/// that would trigger a prompt bail out instead of hanging.
pub fn running_as_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// A context whose report file lives inside `dir`, so tests never write to the
/// real working directory.
pub fn ctx(dir: &Path) -> DefenderContext {
    DefenderContext::new(dir.join("report.txt"), false)
}

/// Write `contents` to `dir/name`, creating parent directories as needed.
pub fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent dir");
    }
    fs::write(&path, contents).expect("write fixture file");
    path
}

/// A small config tree: one loose file plus a directory holding two more,
/// one of them nested. Returns the tempdir (keep it alive) and the two
/// top-level paths to feed to the backup routines.
pub fn config_tree() -> (TempDir, Vec<String>) {
    let src = TempDir::new().expect("create fixture tempdir");
    write_file(src.path(), "sshd_config", "PermitRootLogin no\n");
    write_file(src.path(), "conf.d/site.conf", "listen 80;\n");
    write_file(src.path(), "conf.d/nested/deep.conf", "deep = 1\n");

    let paths = vec![
        src.path().join("sshd_config").display().to_string(),
        src.path().join("conf.d").display().to_string(),
    ];

    (src, paths)
}

/// Borrow owned path strings as the `&[&str]` the backup routines take.
pub fn as_refs(paths: &[String]) -> Vec<&str> {
    paths.iter().map(String::as_str).collect()
}
