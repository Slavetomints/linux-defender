//! Command-line entry point.
//!
//! Parses arguments, builds the [`DefenderContext`] that every check shares,
//! and dispatches into exactly one subcommand. All real logic lives in the
//! library crate so that integration tests can reach it directly.

use std::env;

use anyhow::Context;
use chrono::Local;
use clap::{Parser, Subcommand};

use defender_cli::core::DefenderContext;
use defender_cli::{anti_persistence, backups, monitoring, system_hardening};

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
}

impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::AntiPersistence(_) => "anti-persistence",
            Mode::Backups(_) => "backups",
            Mode::Monitoring(_) => "monitoring",
            Mode::SystemHardening(_) => "system-hardening",
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
