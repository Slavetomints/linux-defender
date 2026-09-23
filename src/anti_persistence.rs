//! Finding and removing attacker persistence.
//!
//! Each submodule covers one persistence vector and exposes
//! `run(&DefenderContext) -> Result`. [`run`] maps CLI flags onto them through
//! a dispatch table, and a check that fails is reported without aborting the
//! rest of the run.
//!
//! Checks that can change the system always prompt first. Several are
//! deliberately read-only: a wrong automated edit to PAM, udev, or logrotate
//! locks the operator out or breaks hardware, so those only report.

use clap::Args;

use crate::core::{DefenderContext, Result};

pub mod at_jobs;
pub mod capabilities;
pub mod cron;
pub mod grub;
pub mod initramfs;
pub mod kernel_modules;
pub mod ld_preload;
pub mod logrotate;
pub mod pam;
pub mod php_shells;
pub mod prompt_command;
pub mod rc_local;
pub mod ssh_keys;
pub mod startup_scripts;
pub mod suid;
pub mod systemd;
pub mod udev;
pub mod users;
pub mod xdg_autostart;

/// Which persistence checks to run.
#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Checks cron jobs for every user
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

/// A persistence check: display name, whether it was requested, and its entry point.
type Module = (&'static str, bool, fn(&DefenderContext) -> Result);

/// Run each requested check, reporting failures without aborting the run.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    let modules: [Module; 19] = [
        ("at_jobs", args.at_jobs, at_jobs::run),
        ("capabilities", args.capabilities, capabilities::run),
        ("cron", args.cron, cron::run),
        ("grub", args.grub, grub::run),
        ("initramfs", args.initramfs, initramfs::run),
        ("kernel_modules", args.kernel_modules, kernel_modules::run),
        ("ld_preload", args.ld_preload, ld_preload::run),
        ("logrotate", args.logrotate, logrotate::run),
        ("pam", args.pam, pam::run),
        ("php_shells", args.php_shells, php_shells::run),
        ("prompt_command", args.prompt_command, prompt_command::run),
        ("rc_local", args.rc_local, rc_local::run),
        ("ssh_keys", args.ssh_keys, ssh_keys::run),
        (
            "startup_scripts",
            args.startup_scripts,
            startup_scripts::run,
        ),
        ("suid", args.suid, suid::run),
        ("systemd", args.systemd, systemd::run),
        ("udev", args.udev, udev::run),
        ("users", args.users, users::run),
        ("xdg_autostart", args.xdg_autostart, xdg_autostart::run),
    ];

    for (name, enabled, module_fn) in modules {
        if !args.all && !enabled {
            continue;
        }

        println!("[+] Running {} module", name);

        match module_fn(ctx) {
            Ok(()) => {
                println!("[+] {} module complete", name);
                ctx.log(&format!("[ok] {}", name))?;
            }
            Err(e) => {
                eprintln!("[!] {} module failed: {}", name, e);
                ctx.log(&format!("[fail] {}: {}", name, e))?;
            }
        }
    }

    Ok(())
}
