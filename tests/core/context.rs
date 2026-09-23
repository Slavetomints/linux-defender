//! Covers `src/core/context.rs`.

use std::fs;

use defender_cli::core::DefenderContext;
use tempfile::TempDir;

#[test]
fn log_creates_the_report_file_on_first_write() {
    let dir = TempDir::new().unwrap();
    let report = dir.path().join("report.txt");
    let ctx = DefenderContext::new(report.clone(), false);

    assert!(!report.exists());
    ctx.log("first line").unwrap();

    assert_eq!(fs::read_to_string(&report).unwrap(), "first line\n");
}

#[test]
fn log_appends_rather_than_truncating() {
    let dir = TempDir::new().unwrap();
    let report = dir.path().join("report.txt");
    let ctx = DefenderContext::new(report.clone(), false);

    ctx.log("one").unwrap();
    ctx.log("two").unwrap();
    ctx.log("three").unwrap();

    assert_eq!(fs::read_to_string(&report).unwrap(), "one\ntwo\nthree\n");
}

#[test]
fn log_fails_when_the_report_directory_does_not_exist() {
    let dir = TempDir::new().unwrap();
    let ctx = DefenderContext::new(dir.path().join("missing").join("report.txt"), false);

    assert!(ctx.log("nowhere to write").is_err());
}

#[test]
fn new_records_the_verbose_flag_and_path() {
    let dir = TempDir::new().unwrap();
    let report = dir.path().join("report.txt");

    let quiet = DefenderContext::new(report.clone(), false);
    let loud = DefenderContext::new(report.clone(), true);

    assert!(!quiet.verbose);
    assert!(loud.verbose);
    assert_eq!(quiet.report_file, report);
}

#[test]
fn elapsed_advances_and_starts_near_zero() {
    let dir = TempDir::new().unwrap();
    let ctx = DefenderContext::new(dir.path().join("report.txt"), false);

    let first = ctx.elapsed();
    assert!(first.as_secs() < 5, "a fresh context starts near zero");

    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(ctx.elapsed() >= first, "elapsed must be monotonic");
}
