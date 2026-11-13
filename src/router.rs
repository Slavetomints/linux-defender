//! VyOS router hardening, firewalling, and forensic audit tooling.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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

/// Execute the embedded VyOS script with the given command-line arguments and environment variables.
pub fn run_script(
    ctx: &DefenderContext,
    script_args: &[&str],
    env_vars: &[(&str, &str)],
) -> Result {
    let target_dir = if nix::unistd::geteuid().is_root() {
        let dir = PathBuf::from("/etc/linux-defender/vyos");
        if fs::create_dir_all(&dir).is_ok() {
            dir
        } else {
            PathBuf::from("/tmp/defender/vyos")
        }
    } else {
        PathBuf::from("/tmp/defender/vyos")
    };
    if let Err(e) = fs::create_dir_all(&target_dir) {
        return Err(DefenderError::Io(e));
    }

    let script_path = target_dir.join("VyOS_LockdownAndFirewall.sh");
    if let Err(e) = fs::write(&script_path, VYOS_SCRIPT) {
        return Err(DefenderError::Io(e));
    }

    let mut perms = match fs::metadata(&script_path) {
        Ok(m) => m.permissions(),
        Err(e) => return Err(DefenderError::Io(e)),
    };
    perms.set_mode(0o700);
    let _ = fs::set_permissions(&script_path, perms);

    let sanitized_args: Vec<String> = {
        let mut out = Vec::new();
        let mut skip_next = false;
        for arg in script_args {
            if skip_next {
                out.push("******".to_string());
                skip_next = false;
            } else if *arg == "--pass" {
                out.push(arg.to_string());
                skip_next = true;
            } else {
                out.push(arg.to_string());
            }
        }
        out
    };

    ctx.progress(&format!(
        "→ Executing VyOS script with args: {:?}",
        sanitized_args
    ));

    let shell = if std::path::Path::new("/bin/vbash").exists() {
        "/bin/vbash"
    } else {
        "bash"
    };

    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(target_dir.join("last_execution.log"))
        .ok()
        .map(|f| Arc::new(Mutex::new(f)));

    if let Some(ref f) = log_file
        && let Ok(mut file) = f.lock()
    {
        let _ = writeln!(
            file,
            "\n=== [{}] Shell: {} | Args: {:?} ===",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            shell,
            sanitized_args
        );
    }

    let mut cmd = Command::new(shell);
    cmd.arg(&script_path).args(script_args);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // On VyOS, ensure the process runs under group 'vyattacfg' so VyOS config APIs succeed
    if let Ok(Some(group)) = nix::unistd::Group::from_name("vyattacfg") {
        use std::os::unix::process::CommandExt;
        cmd.gid(group.gid.as_raw());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err(DefenderError::Io(e)),
    };

    let log_file_err = log_file.clone();
    let ctx_err = ctx.clone();
    let stderr_handle = child.stderr.take().map(|stderr| {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(std::result::Result::ok) {
                ctx_err.progress(&format!("[err] {}", line));
                if let Some(ref f) = log_file_err
                    && let Ok(mut file) = f.lock()
                {
                    let _ = writeln!(file, "[err] {}", line);
                }
            }
        })
    });

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(std::result::Result::ok) {
            ctx.progress(&line);
            if let Some(ref f) = log_file
                && let Ok(mut file) = f.lock()
            {
                let _ = writeln!(file, "{}", line);
            }
        }
    }

    if let Some(handle) = stderr_handle {
        let _ = handle.join();
    }

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => return Err(DefenderError::Io(e)),
    };

    if status.success() {
        ctx.progress("✓ Execution completed successfully.");
        if let Some(ref f) = log_file
            && let Ok(mut file) = f.lock()
        {
            let _ = writeln!(file, "=== Status: SUCCESS ===");
        }
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        ctx.progress(&format!("✗ Execution failed with exit code {}.", code));
        if let Some(ref f) = log_file
            && let Ok(mut file) = f.lock()
        {
            let _ = writeln!(file, "=== Status: FAILED (exit code: {}) ===", code);
        }
        Err(DefenderError::Command(format!(
            "Script failed with exit code {}",
            code
        )))
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
    let mut env_vars: Vec<(&str, &str)> = Vec::new();

    if let Some(ref p) = args.pass {
        env_vars.push(("DEFENDER_ADMIN_PASS", p.as_str()));
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
    run_script(ctx, &str_args, &env_vars)
}
