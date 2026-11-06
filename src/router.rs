//! VyOS router hardening, firewalling, and forensic audit tooling.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::Args;

use crate::core::{DefenderContext, DefenderError, Result};

/// Embedded VyOS consolidated script.
pub const VYOS_SCRIPT: &str = include_str!("../scripts/VyOS_LockdownAndFirewall.sh");

/// Metadata for a router action available in the Router tab.
pub struct RouterStepDef {
    /// Short identifier passed to execution runner.
    pub id: &'static str,
    /// Display label shown in TUI.
    pub label: &'static str,
    /// One-line description of the step.
    pub description: &'static str,
}

/// All available router operations in display order.
pub const ROUTER_STEPS: &[RouterStepDef] = &[
    RouterStepDef {
        id: "audit",
        label: "Forensic Audit & Baseline",
        description: "12-section non-destructive persistence check & baseline capture",
    },
    RouterStepDef {
        id: "diff",
        label: "Diff Against Baseline",
        description: "Compare current router configuration/state against last baseline",
    },
    RouterStepDef {
        id: "harden",
        label: "Phase 1: Hardening & Password Rotation",
        description: "Rotate vyos password, lock SSH to Workstations (172.17.0.0/24), firewall",
    },
    RouterStepDef {
        id: "console_lockdown",
        label: "Phase 2: Console Lockdown (Nuke SSH)",
        description: "Pull SSH service from vyos, drop port 22, terminate running daemons",
    },
];

/// Command-line arguments for router mode.
#[derive(Args, Debug, Default)]
#[command(arg_required_else_help = true)]
pub struct CliArgs {
    /// Run non-destructive forensic audit and capture baseline
    #[arg(long)]
    pub audit: bool,

    /// Diff current state against previous baseline
    #[arg(long)]
    pub diff: Option<Option<String>>,

    /// Phase 1: Rotate vyos password, harden SSH, apply firewall
    #[arg(long)]
    pub harden: bool,

    /// Phase 2: Pull SSH from vyos (Console-Only Administration)
    #[arg(long)]
    pub console_lockdown: bool,

    /// Interactive configuration wizard
    #[arg(long)]
    pub interactive: bool,

    /// CCDC Team number (derives WAN subnet 172.31.{20+T}.2/29)
    #[arg(long)]
    pub team: Option<u8>,

    /// Trusted management subnet (default: 172.17.0.0/24)
    #[arg(long)]
    pub mgmt_subnet: Option<String>,

    /// Target admin username (default: vyos, per CCDC rules)
    #[arg(long)]
    pub user: Option<String>,

    /// New password for vyos (prompted securely if omitted)
    #[arg(long)]
    pub pass: Option<String>,

    /// SSH public key string (e.g. 'AAAAC3NzaC1...')
    #[arg(long)]
    pub ssh_key: Option<String>,

    /// Rollback timer for commit-confirm in minutes (default: 5)
    #[arg(long)]
    pub commit_timeout: Option<u32>,

    /// Bypass commit-confirm rollback (Instant commit; DANGEROUS)
    #[arg(long)]
    pub no_confirm: bool,

    /// Bypass safety checks (e.g. running --console-lockdown over SSH)
    #[arg(long)]
    pub force: bool,

    /// Display commands without applying changes
    #[arg(long)]
    pub dry_run: bool,
}

/// Execute the embedded VyOS script with the given command-line arguments.
pub fn run_script(ctx: &DefenderContext, script_args: &[&str]) -> Result {
    let tmp_dir = PathBuf::from("/tmp/defender/vyos");
    if let Err(e) = fs::create_dir_all(&tmp_dir) {
        return Err(DefenderError::Io(e));
    }

    let script_path = tmp_dir.join("VyOS_LockdownAndFirewall.sh");
    if let Err(e) = fs::write(&script_path, VYOS_SCRIPT) {
        return Err(DefenderError::Io(e));
    }

    let mut perms = match fs::metadata(&script_path) {
        Ok(m) => m.permissions(),
        Err(e) => return Err(DefenderError::Io(e)),
    };
    perms.set_mode(0o700);
    let _ = fs::set_permissions(&script_path, perms);

    ctx.progress(&format!("→ Executing VyOS script with args: {:?}", script_args));

    let mut cmd = Command::new("bash");
    cmd.arg(&script_path).args(script_args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_file(&script_path);
            return Err(DefenderError::Io(e));
        }
    };

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            ctx.progress(&line);
        }
    }

    if let Some(stderr) = child.stderr.take() {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            ctx.progress(&format!("[err] {}", line));
        }
    }

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(&script_path);
            return Err(DefenderError::Io(e));
        }
    };

    let _ = fs::remove_file(&script_path);

    if status.success() {
        ctx.progress("✓ Execution completed successfully.");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        ctx.progress(&format!("✗ Execution failed with exit code {}.", code));
        Err(DefenderError::Command(format!("Script failed with exit code {}", code)))
    }
}

/// Run router commands based on CLI flags.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    let mut script_args: Vec<String> = Vec::new();

    if args.audit {
        script_args.push("--audit".into());
    } else if let Some(ref diff_opt) = args.diff {
        script_args.push("--diff".into());
        if let Some(path) = diff_opt {
            script_args.push(path.clone());
        }
    } else if args.harden {
        script_args.push("--harden".into());
    } else if args.console_lockdown {
        script_args.push("--console-lockdown".into());
    } else if args.interactive {
        script_args.push("--interactive".into());
    }

    if let Some(t) = args.team {
        script_args.push("--team".into());
        script_args.push(t.to_string());
    }
    if let Some(ref m) = args.mgmt_subnet {
        script_args.push("--mgmt-subnet".into());
        script_args.push(m.clone());
    }
    if let Some(ref u) = args.user {
        script_args.push("--user".into());
        script_args.push(u.clone());
    }
    if let Some(ref p) = args.pass {
        script_args.push("--pass".into());
        script_args.push(p.clone());
    }
    if let Some(ref k) = args.ssh_key {
        script_args.push("--ssh-key".into());
        script_args.push(k.clone());
    }
    if let Some(timeout) = args.commit_timeout {
        script_args.push("--commit-timeout".into());
        script_args.push(timeout.to_string());
    }
    if args.no_confirm {
        script_args.push("--no-confirm".into());
    }
    if args.force {
        script_args.push("--force".into());
    }
    if args.dry_run {
        script_args.push("--dry-run".into());
    }

    let str_args: Vec<&str> = script_args.iter().map(|s| s.as_str()).collect();
    run_script(ctx, &str_args)
}
