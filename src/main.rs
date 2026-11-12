//! Command-line entry point.
//!
//! With no arguments: launches the full TUI.
//! With arguments: runs the legacy CLI dispatch (used by integration tests
//! and for quick one-shot checks without a terminal).

use std::env;

use anyhow::Context;
use chrono::Local;
use clap::{Parser, Subcommand};
use nix::unistd::Uid;

use defender_cli::core::DefenderContext;
use defender_cli::{anti_persistence, backups, monitoring, service_restore, system_hardening};

/// CCDC Helper Program
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    verbose: bool,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Runs anti-persistence checks, attempts to clean system of persistence
    AntiPersistence(anti_persistence::CliArgs),

    /// Creates backups of system, service, and configuration files/directories
    Backups(backups::CliArgs),

    /// Monitors the system for any Red Team activity
    Monitoring(monitoring::CliArgs),

    /// Hardens the system from common attack vectors
    SystemHardening(system_hardening::CliArgs),

    /// Reinstalls or restores scored services from scratch
    ServiceRestore(service_restore::CliArgs),
}

impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::AntiPersistence(_) => "anti-persistence",
            Mode::Backups(_) => "backups",
            Mode::Monitoring(_) => "monitoring",
            Mode::SystemHardening(_) => "system-hardening",
            Mode::ServiceRestore(_) => "service-restore",
        }
    }
}

fn main() -> anyhow::Result<()> {
    // No arguments → launch the TUI, which requires root to do anything useful.
    if env::args().len() == 1 {
        if !Uid::effective().is_root() {
            eprintln!("[!] defender must be run as root (try: sudo defender-cli)");
            std::process::exit(1);
        }
        return defender_cli::tui::run();
    }

    // Parse first so clap handles --help/--version (and reports usage errors)
    // before any privilege logic.
    let cli = Cli::parse();

    // Subcommands self-gate per module (each privileged check calls require_root
    // and reports when it is skipped), so a non-root run still parses, runs, and
    // writes a report instead of aborting. Warn once up front.
    if !Uid::effective().is_root() {
        eprintln!("[!] Not running as root — privileged checks will be skipped or limited.");
    }

    let timestamp = Local::now().format("%d-%m-%y-%H-%M-%S").to_string();
    let report_file = env::current_dir()
        .context("Could not determine current directory")?
        .join(format!("defender-report-{}.txt", timestamp));

    let ctx = DefenderContext::new(report_file, cli.verbose);
    ctx.debug(&format!("Report file: {}", ctx.report_file.display()));
    ctx.log(&format!(
        "=== {} run started at {} ===",
        cli.mode.name(),
        timestamp
    ))?;

    match cli.mode {
        Mode::AntiPersistence(args) => {
            anti_persistence::run(&ctx, &args).context("Couldn't run Anti-Persistence mode")?
        }
        Mode::Backups(args) => backups::run(&ctx, &args).context("Couldn't run Backups mode")?,
        Mode::Monitoring(args) => {
            monitoring::run(&ctx, &args).context("Couldn't run Monitoring mode")?
        }
        Mode::SystemHardening(args) => {
            system_hardening::run(&ctx, &args).context("Couldn't run System Hardening mode")?
        }
        Mode::ServiceRestore(args) => {
            service_restore::run(&ctx, &args, None).context("Couldn't run Service Restore mode")?
        }
    }

    let elapsed = ctx.elapsed();
    ctx.log(&format!(
        "=== finished in {:.1}s ===",
        elapsed.as_secs_f64()
    ))?;
    println!("[✓] Done in {:.1}s", elapsed.as_secs_f64());
    println!("[✓] Report written to {}", ctx.report_file.display());

    Ok(())
}
