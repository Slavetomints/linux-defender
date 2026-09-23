//! Proactive hardening of the host.
//!
//! Largely not yet implemented: only `--install-tools` does real work today.
//! The remaining flags define the intended surface.

use clap::Args;

use crate::core::{DefenderContext, Result};

pub mod install_tools;

#[derive(Args, Debug)]
/// Which hardening steps to apply.
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Tighten user and file permissions (not yet implemented)
    #[arg(long)]
    pub user_permissions: bool,

    /// Disable unnecessary services (not yet implemented)
    #[arg(long)]
    pub services: bool,

    /// Remove dangerous programs (not yet implemented)
    #[arg(long)]
    pub programs: bool,

    /// Deploy hardened service configs (not yet implemented)
    #[arg(long)]
    pub configs: bool,

    /// Download the hardening toolchain used by the team
    #[arg(long)]
    pub install_tools: bool,
}

/// Apply each hardening step the operator asked for.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    if args.user_permissions {
        println!("[!] Not implemented: hardening user permissions");
    }
    if args.services {
        println!("[!] Not implemented: hardening services");
    }
    if args.programs {
        println!("[!] Not implemented: hardening programs");
    }
    if args.configs {
        println!("[!] Not implemented: deploying hardened configs");
    }
    if args.install_tools {
        println!("[+] Installing hardening tools");
        install_tools::run(ctx)?;
    }

    Ok(())
}
