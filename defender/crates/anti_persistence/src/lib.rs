use clap::Args;
use defender_core::{DefenderContext};

mod cron;
mod systemd;

#[derive(Args, Debug)]
pub struct CliArgs {
    /// Checks cron jobs for currently logged in user
    #[arg(long)]
    pub cron: bool,

    /// Checks Systemd services
    #[arg(long)]
    pub systemd: bool,

    /// Checks for reverse shells in locations defined by the apache configurations
    #[arg(long)]
    pub php_shells: bool,

    /// Checks for a $PROMPT_COMMAND environment variable
    #[arg(long)]
    pub prompt_command: bool,

    /// Checks for everything
    #[arg(long)]
    pub all: bool,

    //#[arg(long)]
    //pub ask: bool,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String>  {
    if args.cron {
        cron::run(_ctx).expect("[X] Failed to run cron module");
    }
    if args.systemd {
        systemd::run(_ctx).expect("[X] Failed to run systemd module")
    }
    if args.php_shells {
        println!("Checking PHP Shells");
    }
    if args.prompt_command {
        println!("Checking $PROMPT_COMMAND");
    }

    Ok(())
}
