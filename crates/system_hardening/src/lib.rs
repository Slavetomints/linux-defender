use clap::Args;
use defender_core::DefenderContext;

#[derive(Args, Debug)]
pub struct CliArgs {
    #[arg(long)]
    pub user_permissions: bool,

    #[arg(long)]
    pub services: bool,

    #[arg(long)]
    pub programs: bool,

    #[arg(long)]
    pub configs: bool,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    if args.user_permissions {
        println!("Hardening User Permissions");
    }
    if args.services {
        println!("Removing unneeded services");
    }
    if args.programs {
        println!("Removing unneeded programs");
    }
    if args.configs {
      println!("Deploying hardened configs");
    }

    Ok(())
}
