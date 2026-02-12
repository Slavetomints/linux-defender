use clap::Args;
use defender_core::{DefenderContext};

#[derive(Args, Debug)]
pub struct CliArgs {
    #[arg(long)]
    pub cron: bool,

    #[arg(long)]
    pub systemd: bool,

    #[arg(long)]
    pub php: bool,

    #[arg(long)]
    pub php_shells: bool,

    #[arg(long)]
    pub prompt_command: bool,
}

pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result<(), String>  {
    if args.cron {
        println!("Checking cron");
    }
    if args.systemd {
        println!("Checking systemd");
    }
    if args.php_shells {
        println!("Checking PHP Shells");
    }
    if args.prompt_command {
        println!("Checking $PROMPT_COMMAND");
    }

    Ok(())
}
