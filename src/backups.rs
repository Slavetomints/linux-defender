//! Capturing a known-good copy of the system's service configuration.
//!
//! The intended workflow is to take a baseline at the start of a competition
//! with `--all`, then use `--compare-hashes` against that baseline to see what
//! has been altered since.
//!
//! Use `--restore --save-location <dir>` to copy files from a backup directory
//! back to their original locations, one prompt per file. Targeted backups (`--mail`, `--users`, `--custom`)
//! cover specific stacks and are useful for fast restore.

use std::path::PathBuf;

use clap::Args;

use crate::core::{DefenderContext, Result};

pub mod all;
pub mod compare_hashes;
pub mod custom;
pub mod ecomm;
pub mod hash;
pub mod mail;
pub mod paths;
pub mod restore;
pub mod splunk;
pub mod users;

/// Which backup or comparison to perform.
#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Back up every known service config path and write a hash manifest
    #[arg(long)]
    pub all: bool,

    /// Compare current file hashes against a previous backup's manifest
    #[arg(long)]
    pub compare_hashes: bool,

    /// Back up an arbitrary path (e.g. `--custom /srv/myapp`)
    #[arg(long)]
    pub custom: Option<PathBuf>,

    /// Back up the e-commerce stack (OpenCart, PrestaShop, PHP config)
    #[arg(long)]
    pub ecomm: bool,

    /// Back up the mail stack
    #[arg(long)]
    pub mail: bool,

    /// Restore from a previous backup (requires `--save-location`)
    #[arg(long)]
    pub restore: bool,

    /// Back up Splunk configuration
    #[arg(long)]
    pub splunk: bool,

    /// Back up the user and group databases
    #[arg(long)]
    pub users: bool,

    /// Directory to write the backup into, or read a previous one from
    #[arg(long)]
    pub save_location: Option<PathBuf>,
}

/// Run each backup the operator asked for, in a fixed order.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    if args.all {
        println!("[+] Backing up service configs");
        all::run(ctx, &args.save_location)?;
    }
    if args.compare_hashes {
        println!("[+] Comparing hashes");
        compare_hashes::run(ctx, &args.save_location)?;
    }
    if let Some(ref path) = args.custom {
        println!("[+] Backing up custom path: {}", path.display());
        custom::run(ctx, path, &args.save_location)?;
    }
    if args.ecomm {
        println!("[+] Backing up ecomm service");
        ecomm::run(ctx, &args.save_location)?;
    }
    if args.mail {
        println!("[+] Backing up mail service");
        mail::run(ctx, &args.save_location)?;
    }
    if args.restore {
        if let Some(ref dir) = args.save_location {
            println!("[+] Restoring from backup");
            restore::run(ctx, dir)?;
        } else {
            eprintln!("[!] --restore requires --save-location <backup-dir>");
        }
    }
    if args.splunk {
        println!("[+] Backing up splunk service");
        splunk::run(ctx, &args.save_location)?;
    }
    if args.users {
        println!("[+] Backing up user databases");
        users::run(ctx, &args.save_location)?;
    }

    Ok(())
}
