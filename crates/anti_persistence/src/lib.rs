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
#[command(arg_required_else_help = true)]
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

pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result<(), String> {
    struct Module<'a> {
        name: &'a str,
        enabled: bool,
        run: fn(&DefenderContext) -> Result<(), String>,
    }

    let modules = vec![
        Module { name: "at_jobs", enabled: args.at_jobs, run: at_jobs::run },
        Module { name: "capabilities", enabled: args.capabilities, run: capabilities::run },
        Module { name: "cron", enabled: args.cron, run: cron::run },
        Module { name: "grub", enabled: args.grub, run: grub::run },
        Module { name: "initramfs", enabled: args.initramfs, run: initramfs::run },
        Module { name: "kernel_modules", enabled: args.kernel_modules, run: kernel_modules::run },
        Module { name: "ld_preload", enabled: args.ld_preload, run: ld_preload::run },
        Module { name: "logrotate", enabled: args.logrotate, run: logrotate::run },
        Module { name: "pam", enabled: args.pam, run: pam::run },
        Module { name: "php_shells", enabled: args.php_shells, run: php_shells::run },
        Module { name: "prompt_command", enabled: args.prompt_command, run: prompt_command::run },
        Module { name: "rc_local", enabled: args.rc_local, run: rc_local::run },
        Module { name: "ssh_keys", enabled: args.ssh_keys, run: ssh_keys::run },
        Module { name: "startup_scripts", enabled: args.startup_scripts, run: startup_scripts::run },
        Module { name: "suid", enabled: args.suid, run: suid::run },
        Module { name: "systemd", enabled: args.systemd, run: systemd::run },
        Module { name: "udev", enabled: args.udev, run: udev::run },
        Module { name: "users", enabled: args.users, run: users::run },
        Module { name: "xdg_autostart", enabled: args.xdg_autostart, run: xdg_autostart::run },
    ];

    let run_all = args.all;

    for module in modules {
        if run_all || module.enabled {
            println!("[+] Running {} module", module.name);

            match (module.run)(ctx) {
                Ok(_) => println!("[+] {} module complete", module.name),
                Err(e) => eprintln!("[!] {} module failed: {}", module.name, e),
            }
        }
    }

    Ok(())
}
