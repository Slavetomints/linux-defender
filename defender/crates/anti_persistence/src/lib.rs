use clap::Args;
use defender_core::{DefenderContext};

mod at_jobs;
mod capabilities;
mod cron;
mod grub;
mod initramfs;
mod kernel_modules;
mod ld_preload;
mod logrotate;
mod pam;
mod php_shells;
mod prompt_command;
mod rc_local;
mod ssh_keys;
mod startup_scripts;
mod suid;
mod systemd;
mod udev;
mod users;
mod xdg_autostart;

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
    if args.at_jobs {
        at_jobs::run(_ctx).expect("[X] Failed to run at jobs module");
    }
    if args.capabilities {
        capabilities::run(_ctx).expect("[X] Failed to run capabilities module");
    }
    if args.cron {
        cron::run(_ctx).expect("[X] Failed to run cron module");
    }
    if args.grub {
        grub::run(_ctx).expect("[X] Failed to run grub module");
    }
    if args.initramfs {
        initramfs::run(_ctx).expect("[X] Failed to run initramfs module");
    }
    if args.kernel_modules {
        kernel_modules::run(_ctx).expect("[X] Failed to run kernel modules module");
    }
    if args.ld_preload {
        ld_preload::run(_ctx).expect("[X] Failed to run LD_PRELOAD module");
    }
    if args.logrotate {
        logrotate::run(_ctx).expect("[X] Failed to run logrotate module");
    }
    if args.pam {
        pam::run(_ctx).expect("[X] Failed to run PAM module");
    }
    if args.php_shells {
        php_shells::run(_ctx).expect("[X] Failed to run PHP Shells module");
    }
    if args.prompt_command {
        prompt_command::run(_ctx).expect("[X] Failed to run $PROMPT_COMMAND module");
    }
    if args.rc_local {
        rc_local::run(_ctx).expect("[X] Failed to run rc.local module");
    }
    if args.ssh_keys {
        ssh_keys::run(_ctx).expect("[X] Failed to run SSH keys module");
    }
    if args.startup_scripts {
        startup_scripts::run(_ctx).expect("[X] Failed to run startup scripts module");
    }
    if args.suid {
        suid::run(_ctx).expect("[X] Failed to run SUID module");
    }
    if args.systemd {
        systemd::run(_ctx).expect("[X] Failed to run systemd module")
    }
    if args.udev {
        udev::run(_ctx).expect("[X] Failed to run udev module");
    }
    if args.users {
        users::run(_ctx).expect("[X] Failed to run users module");
    }
    if args.xdg_autostart {
        xdg_autostart::run(_ctx).expect("[X] Failed to run XDG Autostart module");
    }
    Ok(())
}
