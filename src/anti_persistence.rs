//! Finding and removing attacker persistence.
//!
//! Each submodule covers one persistence vector and exposes
//! `run(&DefenderContext) -> Result`. [`run`] maps CLI flags onto them through
//! a dispatch table, and a check that fails is reported without aborting the
//! rest of the run.

use clap::Args;

use crate::core::{DefenderContext, DefenderError, Result};

pub mod at_jobs;
pub mod capabilities;
pub mod cron;
pub mod cron_system;
pub mod grub;
pub mod immutable;
pub mod initramfs;
pub mod kernel_modules;
pub mod ld_preload;
pub mod logrotate;
pub mod pam;
pub mod php_shells;
pub mod polkit;
pub mod prompt_command;
pub mod rc_local;
pub mod shell_aliases;
pub mod ssh_config;
pub mod ssh_keys;
pub mod startup_scripts;
pub mod sudoers;
pub mod suid;
pub mod systemd;
pub mod systemd_timers;
pub mod udev;
pub mod users;
pub mod xdg_autostart;

/// Which persistence checks to run.
#[derive(Args, Debug, Default)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Check user and system crontabs for malicious jobs
    #[arg(long)] pub cron: bool,
    /// Scan systemd unit files for backdoor services
    #[arg(long)] pub systemd: bool,
    /// Scan web root for PHP webshells
    #[arg(long)] pub php_shells: bool,
    /// Check PROMPT_COMMAND and shell hook variables
    #[arg(long)] pub prompt_command: bool,
    /// Review local accounts and offer to remove suspicious ones
    #[arg(long)] pub users: bool,
    /// Review SSH authorized_keys for all accounts
    #[arg(long)] pub ssh_keys: bool,
    /// Check SysV init scripts and /etc/rc.local equivalents
    #[arg(long)] pub startup_scripts: bool,
    /// Check LD_PRELOAD / ld.so.preload for injected libraries
    #[arg(long)] pub ld_preload: bool,
    /// Check /etc/rc.local for malicious commands
    #[arg(long)] pub rc_local: bool,
    /// Check XDG autostart entries
    #[arg(long)] pub xdg_autostart: bool,
    /// Find SUID/SGID binaries outside the distro baseline
    #[arg(long)] pub suid: bool,
    /// Check process capabilities for unexpected grants
    #[arg(long)] pub capabilities: bool,
    /// Review PAM configuration for backdoor modules
    #[arg(long)] pub pam: bool,
    /// List loaded kernel modules and boot-load config
    #[arg(long)] pub kernel_modules: bool,
    /// Check udev rules for malicious RUN+= hooks
    #[arg(long)] pub udev: bool,
    /// Check logrotate config for post-rotate persistence
    #[arg(long)] pub logrotate: bool,
    /// Check GRUB configuration for kernel parameter tampering
    #[arg(long)] pub grub: bool,
    /// Check initramfs for injected scripts
    #[arg(long)] pub initramfs: bool,
    /// Review pending at(1) jobs
    #[arg(long)] pub at_jobs: bool,
    /// Checks for immutable/append-only flags on sensitive files
    #[arg(long)] pub immutable: bool,
    /// Check sshd_config for dangerous directives (ForceCommand, AuthorizedKeysCommand, etc.)
    #[arg(long)] pub ssh_config: bool,
    /// Audit /etc/sudoers and sudoers.d for NOPASSWD, LD_PRELOAD, and wildcard rules
    #[arg(long)] pub sudoers: bool,
    /// Check system cron directories (/etc/cron.d, periodic scripts) for malicious jobs
    #[arg(long)] pub cron_system: bool,
    /// Scan systemd timer units for suspicious short-interval or malicious ExecStart
    #[arg(long)] pub systemd_timers: bool,
    /// Detect malicious shell aliases in global and per-user dotfiles
    #[arg(long)] pub shell_aliases: bool,
    /// Audit polkit rules and pkla files for unconditional privilege grants
    #[arg(long)] pub polkit: bool,
    /// Runs all persistence checks
    #[arg(long)] pub all: bool,
}

type Module = (&'static str, bool, fn(&DefenderContext) -> Result);

/// Run each requested check, reporting failures without aborting the run.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    let modules: [Module; 26] = [
        ("at_jobs",          args.at_jobs,          at_jobs::run),
        ("capabilities",     args.capabilities,     capabilities::run),
        ("cron",             args.cron,             cron::run),
        ("cron_system",      args.cron_system,      cron_system::run),
        ("grub",             args.grub,             grub::run),
        ("immutable",        args.immutable,        immutable::run),
        ("initramfs",        args.initramfs,        initramfs::run),
        ("kernel_modules",   args.kernel_modules,   kernel_modules::run),
        ("ld_preload",       args.ld_preload,       ld_preload::run),
        ("logrotate",        args.logrotate,        logrotate::run),
        ("pam",              args.pam,              pam::run),
        ("php_shells",       args.php_shells,       php_shells::run),
        ("polkit",           args.polkit,           polkit::run),
        ("prompt_command",   args.prompt_command,   prompt_command::run),
        ("rc_local",         args.rc_local,         rc_local::run),
        ("shell_aliases",    args.shell_aliases,    shell_aliases::run),
        ("ssh_config",       args.ssh_config,       ssh_config::run),
        ("ssh_keys",         args.ssh_keys,         ssh_keys::run),
        ("startup_scripts",  args.startup_scripts,  startup_scripts::run),
        ("sudoers",          args.sudoers,          sudoers::run),
        ("suid",             args.suid,             suid::run),
        ("systemd",          args.systemd,          systemd::run),
        ("systemd_timers",   args.systemd_timers,   systemd_timers::run),
        ("udev",             args.udev,             udev::run),
        ("users",            args.users,            users::run),
        ("xdg_autostart",    args.xdg_autostart,    xdg_autostart::run),
    ];

    for (name, enabled, module_fn) in modules {
        if !args.all && !enabled {
            continue;
        }

        ctx.log_msg(&format!("[+] Running {} module", name));

        match module_fn(ctx) {
            Ok(()) => {
                ctx.log_msg(&format!("[+] {} module complete", name));
                ctx.log(&format!("[ok] {}", name))?;
            }
            Err(e) => {
                ctx.emit(crate::core::Finding::new(
                    crate::core::Severity::Medium,
                    "anti_persistence",
                    format!("{} module failed: {}", name, e),
                    "",
                ));
                ctx.log(&format!("[fail] {}: {}", name, e))?;
            }
        }
    }

    Ok(())
}

/// Run a single named anti-persistence module by id. Used by the TUI scan tab.
pub fn run_module(name: &str, ctx: &DefenderContext) -> Result {
    match name {
        "at_jobs"          => at_jobs::run(ctx),
        "capabilities"     => capabilities::run(ctx),
        "cron"             => cron::run(ctx),
        "cron_system"      => cron_system::run(ctx),
        "grub"             => grub::run(ctx),
        "immutable"        => immutable::run(ctx),
        "initramfs"        => initramfs::run(ctx),
        "kernel_modules"   => kernel_modules::run(ctx),
        "ld_preload"       => ld_preload::run(ctx),
        "logrotate"        => logrotate::run(ctx),
        "pam"              => pam::run(ctx),
        "php_shells"       => php_shells::run(ctx),
        "polkit"           => polkit::run(ctx),
        "prompt_command"   => prompt_command::run(ctx),
        "rc_local"         => rc_local::run(ctx),
        "shell_aliases"    => shell_aliases::run(ctx),
        "ssh_config"       => ssh_config::run(ctx),
        "ssh_keys"         => ssh_keys::run(ctx),
        "startup_scripts"  => startup_scripts::run(ctx),
        "sudoers"          => sudoers::run(ctx),
        "suid"             => suid::run(ctx),
        "systemd"          => systemd::run(ctx),
        "systemd_timers"   => systemd_timers::run(ctx),
        "udev"             => udev::run(ctx),
        "users"            => users::run(ctx),
        "xdg_autostart"    => xdg_autostart::run(ctx),
        _ => Err(DefenderError::Command(format!(
            "unknown anti_persistence module: {}",
            name
        ))),
    }
}
