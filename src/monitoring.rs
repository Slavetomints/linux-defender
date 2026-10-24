//! Live monitoring: port mapping, hidden binaries, suspicious services.
//!
//! The CLI surface preserves the original stub flags for backwards
//! compatibility. The real detection modules are wired to the TUI scan tab
//! via `run_module`.

use clap::Args;

use crate::core::{DefenderContext, DefenderError, Result};

pub mod ai_artifacts;
pub mod attacker_tools;
pub mod auth_log;
pub mod binary_integrity;
pub mod bind_mounts;
pub mod c2_detection;
pub mod elf_disguise;
pub mod deleted_binaries;
pub mod fail2ban;
pub mod git_hooks;
pub mod perm_anomalies;
pub mod hidden_elf;
pub mod outbound_connections;
pub mod port_map;
pub mod proc_maps;
pub mod process_tree;
pub mod recently_modified;
pub mod rootkit_cross_check;
pub mod suspicious_services;
pub mod webserver_config;
pub mod world_writable;

/// Which monitoring checks to run.
#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    // ── Real detection modules ────────────────────────────────────────────

    /// Analyse auth.log / secure for brute-force and credential-stuffing
    #[arg(long)]
    pub auth_log_analysis: bool,

    /// Map listening TCP ports to their owning binaries
    #[arg(long)]
    pub port_map: bool,

    /// Scan for hidden ELF binaries in web roots and temp directories
    #[arg(long)]
    pub hidden_elf: bool,

    /// Find processes whose on-disk executable has been deleted
    #[arg(long)]
    pub deleted_binaries: bool,

    /// Detect parent→child process anomalies (web server spawning shell, etc.)
    #[arg(long)]
    pub process_tree: bool,

    /// Find system binaries modified after competition start (or last hour)
    #[arg(long)]
    pub recently_modified: bool,

    /// Scan systemd units for suspicious ExecStart paths
    #[arg(long)]
    pub suspicious_services: bool,

    /// Find world-writable directories and files outside expected locations
    #[arg(long)]
    pub world_writable: bool,

    /// Detect established TCP connections from service accounts to unexpected ports
    #[arg(long)]
    pub outbound_connections: bool,

    /// Check fail2ban daemon, active jails, and recent bans
    #[arg(long)]
    pub fail2ban_status: bool,

    /// Scan scripts and executables for AI-generation tells
    #[arg(long)]
    pub ai_artifacts: bool,

    /// Detect ELF binaries and scripts masquerading as other file types
    #[arg(long)]
    pub elf_disguise: bool,

    /// Detect permission/ownership anomalies: orphaned UIDs, SUID outside standard paths, etc.
    #[arg(long)]
    pub perm_anomalies: bool,

    /// Detect attacker tools in temp dirs, hidden executables, double-extension files
    #[arg(long)]
    pub attacker_tools: bool,

    /// Detect C2 implants and beacons (memfd execution, deleted-temp exe, C2 ports, Go implants)
    #[arg(long)]
    pub c2_detection: bool,

    /// Cross-check /proc PID list and listening ports against ps/ss for rootkit evidence
    #[arg(long)]
    pub rootkit_cross_check: bool,

    /// Scan /proc/*/maps for anonymous rwxp mappings (shellcode injection)
    #[arg(long)]
    pub proc_maps: bool,

    /// Verify SHA-256 hashes of system binaries against a stored baseline
    #[arg(long)]
    pub binary_integrity: bool,

    /// Scan git repos for malicious hook scripts
    #[arg(long)]
    pub git_hooks: bool,

    /// Audit nginx, Apache, and PHP config for webshell enablers
    #[arg(long)]
    pub webserver_config: bool,

    /// Detect bind mounts and overlay/tmpfs hiding system paths
    #[arg(long)]
    pub bind_mounts: bool,

    // ── Legacy stub flags (maintained for backwards compatibility) ────────

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

    /// Run all monitoring checks
    #[arg(long)]
    pub all: bool,
}

/// Run each requested monitoring check, reporting failures without aborting the run.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    if args.all || args.auth_log_analysis {
        run_module("auth_log", ctx)?;
    }
    if args.all || args.port_map {
        run_module("port_map", ctx)?;
    }
    if args.all || args.hidden_elf {
        run_module("hidden_elf", ctx)?;
    }
    if args.all || args.deleted_binaries {
        run_module("deleted_binaries", ctx)?;
    }
    if args.all || args.process_tree {
        run_module("process_tree", ctx)?;
    }
    if args.all || args.recently_modified {
        run_module("recently_modified", ctx)?;
    }
    if args.all || args.suspicious_services {
        run_module("suspicious_services", ctx)?;
    }
    if args.all || args.world_writable {
        run_module("world_writable", ctx)?;
    }
    if args.all || args.outbound_connections {
        run_module("outbound_connections", ctx)?;
    }
    if args.all || args.fail2ban_status {
        run_module("fail2ban", ctx)?;
    }
    if args.all || args.ai_artifacts {
        run_module("ai_artifacts", ctx)?;
    }
    if args.all || args.elf_disguise {
        run_module("elf_disguise", ctx)?;
    }
    if args.all || args.perm_anomalies {
        run_module("perm_anomalies", ctx)?;
    }
    if args.all || args.attacker_tools {
        run_module("attacker_tools", ctx)?;
    }
    if args.all || args.c2_detection {
        run_module("c2_detection", ctx)?;
    }
    if args.all || args.rootkit_cross_check {
        run_module("rootkit_cross_check", ctx)?;
    }
    if args.all || args.proc_maps {
        run_module("proc_maps", ctx)?;
    }
    if args.all || args.binary_integrity {
        run_module("binary_integrity", ctx)?;
    }
    if args.all || args.git_hooks {
        run_module("git_hooks", ctx)?;
    }
    if args.all || args.webserver_config {
        run_module("webserver_config", ctx)?;
    }
    if args.all || args.bind_mounts {
        run_module("bind_mounts", ctx)?;
    }

    // Legacy stubs — print a placeholder so existing integration tests pass.
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

/// Run a single named monitoring module by id. Used by the TUI scan tab.
pub fn run_module(name: &str, ctx: &DefenderContext) -> Result {
    match name {
        "auth_log"            => auth_log::run(ctx),
        "port_map"            => port_map::run(ctx),
        "hidden_elf"          => hidden_elf::run(ctx),
        "deleted_binaries"    => deleted_binaries::run(ctx),
        "process_tree"        => process_tree::run(ctx),
        "recently_modified"   => recently_modified::run(ctx),
        "suspicious_services"    => suspicious_services::run(ctx),
        "world_writable"         => world_writable::run(ctx),
        "outbound_connections"   => outbound_connections::run(ctx),
        "fail2ban"               => fail2ban::run(ctx),
        "ai_artifacts"           => ai_artifacts::run(ctx),
        "elf_disguise"           => elf_disguise::run(ctx),
        "perm_anomalies"         => perm_anomalies::run(ctx),
        "attacker_tools"         => attacker_tools::run(ctx),
        "c2_detection"           => c2_detection::run(ctx),
        "rootkit_cross_check"    => rootkit_cross_check::run(ctx),
        "proc_maps"              => proc_maps::run(ctx),
        "binary_integrity"       => binary_integrity::run(ctx),
        "git_hooks"              => git_hooks::run(ctx),
        "webserver_config"       => webserver_config::run(ctx),
        "bind_mounts"            => bind_mounts::run(ctx),
        _ => Err(DefenderError::Command(format!(
            "unknown monitoring module: {}",
            name
        ))),
    }
}
