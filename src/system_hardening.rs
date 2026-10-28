//! Proactive hardening of the host.
//!
//! Each flag maps to one sub-module that performs the corresponding hardening
//! step. All destructive actions prompt before running.

use clap::Args;

use crate::core::{DefenderContext, Result};

pub mod configs;
pub mod install_tools;
pub mod programs;
pub mod services;
pub mod user_perms;

#[derive(Args, Debug)]
/// Which hardening steps to apply.
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Tighten user and file permissions
    #[arg(long)]
    pub user_permissions: bool,

    /// Disable unnecessary services
    #[arg(long)]
    pub services: bool,

    /// Remove dangerous programs
    #[arg(long)]
    pub programs: bool,

    /// Deploy hardened service configs
    #[arg(long)]
    pub configs: bool,

    /// Download the hardening toolchain used by the team
    #[arg(long)]
    pub install_tools: bool,
}

/// Apply each hardening step the operator asked for.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    if args.user_permissions {
        user_perms::run(ctx)?;
    }
    if args.services {
        services::run(ctx)?;
    }
    if args.programs {
        programs::run(ctx)?;
    }
    if args.configs {
        configs::run(ctx)?;
    }
    if args.install_tools {
        println!("[+] Installing hardening tools");
        install_tools::run(ctx)?;
    }

    Ok(())
}
