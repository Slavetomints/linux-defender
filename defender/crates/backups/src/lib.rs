use std::path::PathBuf;

use clap::Args;
use defender_core::DefenderContext;

mod all;
mod compare_hashes;
mod custom;
mod ecomm;
mod mail;
mod restore;
mod splunk;
mod users;

#[derive(Args, Debug)]
pub struct CliArgs {
    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub compare_hashes: bool,

    #[arg(long)]
    pub custom: bool,

    #[arg(long)]
    pub ecomm: bool,

    #[arg(long)]
    pub mail: bool,

    #[arg(long)]
    pub restore: bool,

    #[arg(long)]
    pub splunk: bool,

    #[arg(long)]
    pub users: bool,

    #[arg(long)]
    pub save_location: Option<PathBuf>,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    if args.all {
        println!("Backing up service configs");
        all::run(_ctx, &args.save_location).expect("[X] Failed to run service config backup");
    }
    if args.compare_hashes {
        println!("Comparing hashes");
        compare_hashes::run(_ctx, &args.save_location).expect("[X] Failed to run hash comparison");
    }
    if args.custom {
        println!("Backing up custom service");
        custom::run(_ctx).expect("[X] Failed to run custom service backup");
    }
    if args.ecomm {
        println!("Backing up ecomm service");
        ecomm::run(_ctx).expect("[X] Failed to run ecomm service backup");
    }
    if args.mail {
        println!("Backing up mail service");
        mail::run(_ctx).expect("[X] Failed to run mail service backup");
    }
    if args.restore {
        println!("Restoring mail service");
        restore::run(_ctx).expect("[X] Failed to run restore");
    }
    if args.splunk {
        println!("Backing up splunk service");
        splunk::run(_ctx).expect("[X] Failed to run splunk service backup");
    }
    if args.users {
        println!("Backing up users service");
        users::run(_ctx).expect("[X] Failed to run users service backup");
    }

    Ok(())
}
