//! End-to-end tests that drive the built binary; covers `src/main.rs`.

#[path = "common.rs"]
mod common;

use tempfile::TempDir;

use common::{run_cli as run_in, running_as_root, stderr, stdout};

#[test]
fn help_lists_every_subcommand() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["--help"]);

    assert!(out.status.success());
    let text = stdout(&out);
    for subcommand in [
        "anti-persistence",
        "backups",
        "monitoring",
        "system-hardening",
    ] {
        assert!(
            text.contains(subcommand),
            "--help should mention {}",
            subcommand
        );
    }
}

#[test]
fn version_flag_reports_a_version() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["--version"]);

    assert!(out.status.success());
    assert!(stdout(&out).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn an_unknown_subcommand_fails() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["definitely-not-a-mode"]);

    assert!(!out.status.success());
}

#[test]
fn a_subcommand_with_no_flags_shows_help_and_fails() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["anti-persistence"]);

    assert!(
        !out.status.success(),
        "arg_required_else_help should make a bare subcommand an error"
    );
}

#[test]
fn compare_hashes_without_a_save_location_explains_itself() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["backups", "--compare-hashes"]);

    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--save-location"),
        "the error should name the missing flag, got: {}",
        stderr(&out)
    );
}

#[test]
fn compare_hashes_against_a_missing_manifest_explains_itself() {
    let dir = TempDir::new().unwrap();
    let out = run_in(
        dir.path(),
        &[
            "backups",
            "--compare-hashes",
            "--save-location",
            dir.path().to_str().unwrap(),
        ],
    );

    assert!(!out.status.success());
    assert!(stderr(&out).contains("Hashes file not found"));
}

#[test]
fn a_successful_run_writes_a_report_file() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["anti-persistence", "--prompt-command"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let reports: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("defender-report-")
        })
        .collect();
    assert_eq!(reports.len(), 1, "exactly one report file per run");

    let report = std::fs::read_to_string(reports[0].path()).unwrap();
    assert!(report.contains("anti-persistence run started"));
    assert!(report.contains("[ok] prompt_command"));
    assert!(report.contains("finished in"));
}

#[test]
fn verbose_adds_debug_output() {
    let dir = TempDir::new().unwrap();

    let quiet = run_in(dir.path(), &["anti-persistence", "--prompt-command"]);
    let loud = run_in(
        dir.path(),
        &["--verbose", "anti-persistence", "--prompt-command"],
    );

    assert!(!stdout(&quiet).contains("[debug]"));
    assert!(stdout(&loud).contains("[debug]"));
}

#[test]
fn a_failing_module_does_not_abort_the_run() {
    let dir = TempDir::new().unwrap();
    // `--users` needs root; as an unprivileged user it fails, but the run as a
    // whole should still succeed and record the failure.
    let out = run_in(
        dir.path(),
        &["anti-persistence", "--users", "--prompt-command"],
    );

    if running_as_root() {
        return; // would prompt for input; not meaningful under root
    }

    assert!(out.status.success(), "run should survive a module failure");
    assert!(stdout(&out).contains("prompt_command module complete"));
}
