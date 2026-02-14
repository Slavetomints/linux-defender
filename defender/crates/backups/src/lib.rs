use std::path::PathBuf;

use clap::Args;
use defender_core::DefenderContext;

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
    if let Some(path) = &args.save_location {
        println!("setting custom save location at {}", path.display());
    }
    if args.service_files {
        println!("Backing up service files");
    }
    if args.service_configs {
        println!("Backing up service configs");
    }
    if args.custom_backup {
        println!("Running Custom backup");
    }

    Ok(())
}
