//! Live monitoring of logs and network state.
//!
//! Not yet implemented. The CLI surface is defined so the flags are stable,
//! but every monitor currently reports that it is a stub.

use clap::Args;

use crate::core::{DefenderContext, Result};

#[derive(Args, Debug)]
/// Which monitors to start.
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Watch the web server access log (not yet implemented)
    #[arg(long)]
    pub access_log: bool,

    /// Watch the web server error log (not yet implemented)
    #[arg(long)]
    pub error_log: bool,

    /// Watch the authentication log (not yet implemented)
    #[arg(long)]
    pub auth_log: bool,

    /// Watch for short-lived processes (not yet implemented)
    #[arg(long)]
    pub pspy: bool,

    /// Watch listening ports and connections (not yet implemented)
    #[arg(long)]
    pub network: bool,
}

/// Start each monitor the operator asked for.
pub fn run(_ctx: &DefenderContext, args: &CliArgs) -> Result {
    if args.access_log {
        println!("[!] Not implemented: monitoring access log");
    }
    if args.error_log {
        println!("[!] Not implemented: monitoring error log");
    }
    if args.auth_log {
        println!("[!] Not implemented: monitoring auth log");
    }
    if args.pspy {
        println!("[!] Not implemented: pspy");
    }
    if args.network {
        println!("[!] Not implemented: monitoring network connections");
    }

    Ok(())
}
