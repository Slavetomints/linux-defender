use clap::Args;
use defender_core::DefenderContext;

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    #[arg(long)]
    pub access_log: bool,

    #[arg(long)]
    pub error_log: bool,

    #[arg(long)]
    pub auth_log: bool,

    #[arg(long)]
    pub pspy: bool,

    #[arg(long)]
    pub network: bool,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    if args.access_log {
        println!("Monitoring access log");
    }
    if args.error_log {
        println!("Monitoring error log");
    }
    if args.auth_log {
        println!("Monitoring auth log");
    }
    if args.pspy {
      println!("Starting pspy");
    }
    if args.network {
      println!("Monitoring Network connections")
    }

    Ok(())
}
