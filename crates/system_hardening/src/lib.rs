use clap::Args;
use defender_core::DefenderContext;

mod install_tools;

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    #[arg(long)]
    pub user_permissions: bool,

    #[arg(long)]
    pub services: bool,

    #[arg(long)]
    pub programs: bool,

    #[arg(long)]
    pub configs: bool,

    #[arg(long)]
    pub install_tools: bool,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    if args.user_permissions {
        println!("[INFO]: NOT IMPLMENTED: Hardening User Permissions");
    }
    if args.services {
        println!("[INFO]: NOT IMPLMENTED: Hardening Services");
    }
    if args.programs {
        println!("[INFO]: NOT IMPLMENTED: Hardening Programs");
    }
    if args.configs {
      println!("[INFO]: NOT IMPLMENTED: Deploying hardened configs");
    }

    if args.install_tools {
        println!("[INFO]:Installing Hardening Tools");
        install_tools::run(_ctx). expect("[X] Failed to run install tools");

    }

    Ok(())
}
