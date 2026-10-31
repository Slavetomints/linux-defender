//! Recreating scored services from scratch when no backup exists.
//!
//! Each submodule handles one service and exposes a `run` entry point that
//! downloads, installs, and configures the service in one pass.
//!
//! System services (Postfix, Dovecot) are reinstalled via the host's package
//! manager. Splunk is reset by wiping its local-override layer. Web
//! applications (OpenCart, PrestaShop) are downloaded from their GitHub
//! release pages, extracted onto the web root, and installed headlessly via
//! each project's CLI installer — the operator is prompted for database
//! credentials and admin account details.
//!
//! There is deliberately no `--all` flag: each service lives on a specific
//! machine in a CCDC topology, and a catch-all would waste time on services
//! that are not present.

use std::path::PathBuf;

use clap::Args;

use crate::core::{DefenderContext, Result};

pub mod distro;
pub mod dovecot;
pub mod opencart;
pub mod postfix;
pub mod prestashop;
pub mod roundcube;
pub mod splunk;
pub mod ssh;
pub mod webserver;

/// Pre-supplied credentials for web-app restores (avoids blocking stdin prompts).
///
/// The TUI collects these via a dialog before spawning the restore thread.
/// The CLI path leaves both fields as `None` and prompts interactively.
pub struct RestoreCredentials {
    /// Credentials for a Splunk admin user seed on fresh install.
    pub splunk: Option<splunk::SplunkCredentials>,
    /// Credentials for an OpenCart restore, or `None` to prompt interactively.
    pub opencart: Option<opencart::OpenCartCredentials>,
    /// Credentials for a PrestaShop restore, or `None` to prompt interactively.
    pub prestashop: Option<prestashop::PrestaShopCredentials>,
}

/// Which service to restore.
#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Reinstall OpenSSH server and restart the service
    #[arg(long)]
    pub ssh: bool,

    /// Reinstall Postfix and restart the service
    #[arg(long)]
    pub postfix: bool,

    /// Reinstall Dovecot and restart the service
    #[arg(long)]
    pub dovecot: bool,

    /// Wipe Splunk's local-override layer and restart the daemon (or install from scratch)
    #[arg(long)]
    pub splunk: bool,

    /// Override the Splunk installer URL (defaults to pinned 10.0.2 release)
    #[arg(long)]
    pub splunk_url: Option<String>,

    /// Download and reinstall OpenCart, preserving config.php if present
    #[arg(long)]
    pub opencart: bool,

    /// Web root for the OpenCart installation
    #[arg(long, default_value = "/var/www/html")]
    pub opencart_path: PathBuf,

    /// Override the OpenCart download URL (defaults to pinned release)
    #[arg(long)]
    pub opencart_url: Option<String>,

    /// Reinstall Roundcube webmail and restart Apache
    #[arg(long)]
    pub roundcube: bool,

    /// Download and reinstall PrestaShop, preserving parameters.php if present
    #[arg(long)]
    pub prestashop: bool,

    /// Web root for the PrestaShop installation
    #[arg(long, default_value = "/var/www/html")]
    pub prestashop_path: PathBuf,

    /// Override the PrestaShop download URL (defaults to pinned release)
    #[arg(long)]
    pub prestashop_url: Option<String>,
}

/// Run each requested service restore in flag order.
///
/// `creds` carries pre-supplied credentials for web-app restores (TUI path).
/// Pass `None` from the CLI to fall back to interactive prompts.
pub fn run(
    ctx: &DefenderContext,
    args: &CliArgs,
    creds: Option<&RestoreCredentials>,
) -> Result<()> {
    if args.ssh {
        ctx.progress("[+] Restoring SSH");
        ssh::run(ctx)?;
    }
    if args.postfix {
        ctx.progress("[+] Restoring Postfix");
        postfix::run(ctx)?;
    }
    if args.dovecot {
        ctx.progress("[+] Restoring Dovecot");
        dovecot::run(ctx)?;
    }
    if args.roundcube {
        ctx.progress("[+] Restoring Roundcube");
        roundcube::run(ctx)?;
    }
    if args.splunk {
        ctx.progress("[+] Restoring Splunk");
        let splunk_creds = creds.and_then(|c| c.splunk.as_ref());
        splunk::run(ctx, args.splunk_url.as_deref(), splunk_creds)?;
    }
    if args.opencart {
        ctx.progress(&format!("[+] Restoring OpenCart at {}", args.opencart_path.display()));
        let oc_creds = creds.and_then(|c| c.opencart.as_ref());
        opencart::run(
            ctx,
            &args.opencart_path,
            args.opencart_url.as_deref(),
            oc_creds,
        )?;
    }
    if args.prestashop {
        ctx.progress(&format!(
            "[+] Restoring PrestaShop at {}",
            args.prestashop_path.display()
        ));
        let ps_creds = creds.and_then(|c| c.prestashop.as_ref());
        prestashop::run(
            ctx,
            &args.prestashop_path,
            args.prestashop_url.as_deref(),
            ps_creds,
        )?;
    }
    Ok(())
}
