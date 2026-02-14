use chrono::Local;
use clap::{Parser, Subcommand};
use std::{env, time::SystemTime};

use anti_persistence::CliArgs as AntiPersistenceArgs;
use backups::CliArgs as BackupArgs;
use monitoring::CliArgs as MonitoringArgs;
use system_hardening::CliArgs as SystemHardeningArgs;

use defender_core::DefenderContext;

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
    AntiPersistence(AntiPersistenceArgs),

    /// Creates backups of system, service, and configuration files/directories
    Backups(BackupArgs),

    /// Monitors the system for any Red Team activity
    Monitoring(MonitoringArgs),

    /// Hardens the system from common attack vectors  
    SystemHardening(SystemHardeningArgs),
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let now = Local::now();
    let timestamp = now.format("%d-%m-%y-%H-%M-%S").to_string();
    let filename = format!("defender-report-{}.txt", timestamp);
    let path = env::current_dir().expect("Could not determine current directory");

    let _ = path.join(filename);

    let ctx = DefenderContext {
        verbose: cli.verbose,
        start_time: SystemTime::now(),
        report_file: path,
    };

    match cli.mode {
        Mode::AntiPersistence(args) => {
            anti_persistence::run(&ctx, &args).expect("Couldn't run Anti-Persistence mode");
        },
        Mode::Backups(args) => {
            backups::run(&ctx, &args).expect("Couldn't run Backups mode");
        },
        Mode::Monitoring(args) => {
            monitoring::run(&ctx, &args).expect("Couldn't run Monitoring mode");
        },
        Mode::SystemHardening(args) => {
            system_hardening::run(&ctx, &args).expect("Couldn't run System Hardening mode")
        },
    }
    return Ok(());
}
