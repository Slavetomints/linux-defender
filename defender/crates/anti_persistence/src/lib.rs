use clap::Args;
use defender_core::{DefenderContext};

mod cron;
mod systemd;

#[derive(Args, Debug)]
pub struct CliArgs {
    // TODO: ADD CHECKS FOR EVERY USER AND SYSTEM-WIDE JOBS
    /// Checks cron jobs for the current user
    #[arg(long)]
    pub cron: bool,

    /// Checks systemd services for suspicious entries
    #[arg(long)]
    pub systemd: bool,

    /// Checks for PHP web shells in web server directories
    #[arg(long)]
    pub php_shells: bool,

    /// Checks for malicious $PROMPT_COMMAND environment variable
    #[arg(long)]
    pub prompt_command: bool,

    /// Checks for malicious or unexpected user accounts
    #[arg(long)]
    pub users: bool,

    /// Checks SSH authorized_keys for backdoors
    #[arg(long)]
    pub ssh_keys: bool,

    /// Checks shell startup scripts (.bashrc, .profile, etc.)
    #[arg(long)]
    pub startup_scripts: bool,

    /// Checks for LD_PRELOAD abuse
    #[arg(long)]
    pub ld_preload: bool,

    /// Checks for rc.local persistence
    #[arg(long)]
    pub rc_local: bool,

    /// Checks XDG autostart entries
    #[arg(long)]
    pub xdg_autostart: bool,

    /// Checks for SUID binaries
    #[arg(long)]
    pub suid: bool,

    /// Checks for Linux capabilities abuse
    #[arg(long)]
    pub capabilities: bool,

    /// Checks PAM configuration for tampering
    #[arg(long)]
    pub pam: bool,

    /// Checks for suspicious kernel modules
    #[arg(long)]
    pub kernel_modules: bool,

    /// Checks udev rules for persistence
    #[arg(long)]
    pub udev: bool,

    /// Checks logrotate configuration for abuse
    #[arg(long)]
    pub logrotate: bool,

    /// Checks GRUB configuration for tampering
    #[arg(long)]
    pub grub: bool,

    /// Checks initramfs for suspicious modifications
    #[arg(long)]
    pub initramfs: bool,

    /// Checks at jobs
    #[arg(long)]
    pub at_jobs: bool,

    

    /// Runs all persistence checks
    #[arg(long)]
    pub all: bool,
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
