use std::path::PathBuf;

use clap::Args;
use defender_core::DefenderContext;

mod service_configs;

#[derive(Args, Debug)]
pub struct CliArgs {
    #[arg(long)]
    pub service_files: bool,

    #[arg(long)]
    pub service_configs: bool,

    #[arg(long)]
    pub custom_backup: bool,

    #[arg(long)]
    pub save_location: Option<PathBuf>,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    if args.service_files {
        println!("Backing up service files");
    }
    if args.service_configs {
        println!("Backing up service configs");
        service_configs::run(_ctx, &args.save_location).expect("[X] Failed to run service config backup");
    }
    if args.custom_backup {
        println!("Running Custom backup");
    }

    Ok(())
}
