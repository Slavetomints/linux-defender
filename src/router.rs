//! VyOS router hardening, firewalling, and forensic audit tooling.

pub mod scan;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
        id: "diff",
        label: "Diff Against Baseline",
        description: "Compare live VyOS state against last captured baseline",
    },
    RouterStepDef {
        id: "harden",
        label: "Phase 1: Hardening & Init Config",
        description: "Deploy NAT rules 10-14, apply control-plane firewall, quarantine hooks",
    },
    RouterStepDef {
        id: "router_nat",
        label: "Restore NAT Baseline on Router",
        description: "Deploy scored 1:1 DNAT (Rules 10-14) and optional outbound PAT",
    },
    RouterStepDef {
        id: "rotate_passwords",
        label: "Update VyOS & Linux Root Passwords",
        description: "Separately update passwords; purge config.boot public-keys and sanitize keys",
    },
    RouterStepDef {
        id: "sanitize_hooks",
        label: "Sanitize Boot & Commit Hooks",
        description: "Quarantine /config/scripts/ hooks, reset bootup scripts, kill rogue processes",
    },
    RouterStepDef {
        id: "sanitize_cron",
        label: "Sanitize Task Scheduler & Crons",
        description: "Delete VyOS task-scheduler, flush crontabs, purge rogue /etc/cron.d/ drops",
    },
    RouterStepDef {
        id: "clean_rootkits",
        label: "Remove Dynamic Linker Overrides",
        description: "Remove /etc/ld.so.preload, drop-in overrides, and rogue systemd services",
    },
    RouterStepDef {
        id: "purge_containers",
        label: "Purge Rogue Containers",
        description: "Remove VyOS container config and stop all running podman containers",
    },
    RouterStepDef {
        id: "services",
        label: "Disable Unnecessary Services",
        description: "Apply VyOS 1.4.0 service whitelist; flag unknown daemons",
    },
    RouterStepDef {
        id: "user_permissions",
        label: "User & File Permissions",
        description: "Sanitize /config/scripts/, secure /etc/shadow, add vyos to essential users",
    },
    RouterStepDef {
        id: "console_lockdown",
        label: "Phase 2: Console Lockdown (Nuke SSH)",
        description: "Remove SSH service, drop port 22, terminate daemons (Console Only)",
    },
    RouterStepDef {
        id: "confirm",
        label: "Confirm Pending Commit",
        description: "Confirm and save pending commit-confirm changes permanently",
    },
    RouterStepDef {
        id: "rollback",
        label: "Rollback Pending Commit",
        description: "Cancel pending commit-confirm and revert router configuration immediately",
    },
];

/// Default commit-confirm rollback timeout in minutes when none is explicitly specified.
pub const DEFAULT_COMMIT_TIMEOUT_MINUTES: u32 = 5;

/// Progress channel sentinel indicating a router operation completed successfully.
pub const ROUTER_PROGRESS_DONE_OK: &str = "__ROUTER_DONE_OK__";

/// Progress channel sentinel indicating a router operation completed with an error.
pub const ROUTER_PROGRESS_DONE_ERROR: &str = "__ROUTER_DONE_ERROR__";

/// Format a remaining duration in seconds as an `mm:ss` countdown string.
///
/// # Examples
/// ```
/// use linux_defender::router::format_countdown;
/// assert_eq!(format_countdown(299), "04:59");
/// assert_eq!(format_countdown(0), "00:00");
/// ```
pub fn format_countdown(seconds: u64) -> String {
    let minutes = seconds / 60;
    let secs = seconds % 60;
    format!("{:02}:{:02}", minutes, secs)
}

/// Check whether a pending confirmation deadline has expired given the current instant.
pub fn is_pending_expired(now: std::time::Instant, deadline: std::time::Instant) -> bool {
    now >= deadline
}

/// Calculate remaining duration before a deadline, returning zero duration if already passed.
pub fn remaining_time(
    now: std::time::Instant,
    deadline: std::time::Instant,
) -> std::time::Duration {
    deadline.saturating_duration_since(now)
}

/// Check if text contains VyOS configuration commit failure markers.
pub fn has_commit_failure(output: &str) -> bool {
    output.contains("Commit failed")
        || output.contains("commit-confirm failed")
        || (output.contains("[[") && output.contains("]] failed"))
}

/// Determine whether a completed router operation should transition into pending-confirmation state.
///
/// Only a successful Phase 1 harden or NAT restore run without `--no-confirm` enters pending confirmation.
pub fn should_enter_pending_state(step_id: &str, no_confirm: bool, success: bool) -> bool {
    matches!(step_id, "harden" | "router_nat" | "restore_nat") && !no_confirm && success
}

/// Extended pending-state check verifying exit status and commit output logs.
pub fn should_enter_pending_state_checked(
    step_id: &str,
    no_confirm: bool,
    exit_code: i32,
    output: &str,
) -> bool {
    exit_code == 0
        && !has_commit_failure(output)
        && should_enter_pending_state(step_id, no_confirm, true)
}

/// Command-line arguments for router mode.
#[derive(Args, Debug, Default, Clone)]
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

    /// Restore CCDC DNAT Rules 10-14 & configure outbound PAT without full hardening
    #[arg(long)]
    pub restore_nat: bool,

    /// Separately rotate vyos and root passwords; sanitize authorized_keys
    #[arg(long)]
    pub rotate_passwords: bool,

    /// Quarantine persistence hooks from /config/scripts/ and reset templates
    #[arg(long)]
    pub sanitize_hooks: bool,

    /// Delete VyOS task-scheduler and flush /var/spool/cron/crontabs
    #[arg(long)]
    pub sanitize_cron: bool,

    /// Remove /etc/ld.so.preload and check systemd overrides
    #[arg(long)]
    pub clean_rootkits: bool,

    /// Delete VyOS container config and stop running podman containers
    #[arg(long)]
    pub purge_containers: bool,

    /// Phase 2: Pull SSH from vyos (Console-Only Administration)
    #[arg(long)]
    pub console_lockdown: bool,

    /// Confirm and save pending commit-confirm changes
    #[arg(long)]
    pub confirm: bool,

    /// Cancel and rollback pending commit-confirm changes immediately
    #[arg(long, visible_alias = "cancel-confirm")]
    pub rollback: bool,

    /// Interactive configuration wizard
    #[arg(long)]
    pub interactive: bool,

    /// CCDC Team number (derives WAN subnet 172.31.{20+T}.2/29)
    #[arg(long)]
    pub team: Option<u8>,

    /// DNAT destination target: 'private' (172.20.240.x) or 'public' (172.25.x.x)
    #[arg(long)]
    pub dnat_target: Option<String>,

    /// Enable Outbound PAT masquerade for workstations
    #[arg(long)]
    pub enable_outbound_pat: bool,

    /// Trusted management subnet (default: 172.17.0.0/24)
    #[arg(long)]
    pub mgmt_subnet: Option<String>,

    /// Target admin username (default: vyos, per CCDC rules)
    #[arg(long)]
    pub user: Option<String>,

    /// New password for vyos (prompted securely if omitted)
    #[arg(long)]
    pub pass: Option<String>,

    /// New password for Linux root superuser
    #[arg(long)]
    pub root_pass: Option<String>,

    /// New password for vyos (synonym for --pass)
    #[arg(long)]
    pub vyos_pass: Option<String>,

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

    /// Force overwriting existing destination NAT rules with baseline
    #[arg(long)]
    pub force_baseline: bool,

    /// Restore mode for --restore-nat: 'baseline', 'detected', or 'backup'
    #[arg(long)]
    pub restore_mode: Option<String>,

    /// Path to detected or backup config file for restore
    #[arg(long)]
    pub config_source: Option<String>,

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
            } else if *arg == "--pass" || *arg == "--vyos-pass" || *arg == "--root-pass" {
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

    let commit_failed = Arc::new(AtomicBool::new(false));
    let commit_failed_err = commit_failed.clone();

    let log_file_err = log_file.clone();
    let ctx_err = ctx.clone();
    let stderr_handle = child.stderr.take().map(|stderr| {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(std::result::Result::ok) {
                let clean = crate::core::utils::sanitize_cr(&line);
                if has_commit_failure(clean) {
                    commit_failed_err.store(true, Ordering::SeqCst);
                }
                if !clean.is_empty() {
                    ctx_err.progress(&format!("[err] {}", clean));
                }
                if let Some(ref f) = log_file_err
                    && let Ok(mut file) = f.lock()
                {
                    let _ = writeln!(file, "[err] {}", clean);
                }
            }
        })
    });

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(std::result::Result::ok) {
            let clean = crate::core::utils::sanitize_cr(&line);
            if has_commit_failure(clean) {
                commit_failed.store(true, Ordering::SeqCst);
            }
            if !clean.is_empty() {
                ctx.progress(clean);
            }
            if let Some(ref f) = log_file
                && let Ok(mut file) = f.lock()
            {
                let _ = writeln!(file, "{}", clean);
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

    let had_commit_failure = commit_failed.load(Ordering::SeqCst);

    if status.success() && !had_commit_failure {
        ctx.progress("✓ Execution completed successfully.");
        if let Some(ref f) = log_file
            && let Ok(mut file) = f.lock()
        {
            let _ = writeln!(file, "=== Status: SUCCESS ===");
        }
        Ok(())
    } else {
        let code = if had_commit_failure && status.success() {
            1
        } else {
            status.code().unwrap_or(-1)
        };
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

/// Build the list of command-line arguments to pass to the VyOS shell script.
pub fn build_script_args(args: &CliArgs) -> Vec<String> {
    let mut script_args: Vec<String> = Vec::new();

    if args.confirm {
        script_args.push("--confirm".into());
    } else if args.rollback {
        script_args.push("--rollback".into());
    } else if args.audit {
        script_args.push("--audit".into());
    } else if let Some(ref diff_opt) = args.diff {
        script_args.push("--diff".into());
        if let Some(path) = diff_opt {
            script_args.push(path.clone());
        }
    } else if args.harden {
        script_args.push("--harden".into());
    } else if args.restore_nat {
        script_args.push("--restore-nat".into());
    } else if args.rotate_passwords {
        script_args.push("--rotate-passwords".into());
    } else if args.sanitize_hooks {
        script_args.push("--sanitize-hooks".into());
    } else if args.sanitize_cron {
        script_args.push("--sanitize-cron".into());
    } else if args.clean_rootkits {
        script_args.push("--clean-rootkits".into());
    } else if args.purge_containers {
        script_args.push("--purge-containers".into());
    } else if args.console_lockdown {
        script_args.push("--console-lockdown".into());
    } else if args.interactive {
        script_args.push("--interactive".into());
    }

    if let Some(t) = args.team {
        script_args.push("--team".into());
        script_args.push(t.to_string());
    }
    if let Some(ref dnat) = args.dnat_target {
        script_args.push("--dnat-target".into());
        script_args.push(dnat.clone());
    }
    if args.enable_outbound_pat {
        script_args.push("--enable-outbound-pat".into());
    }
    if let Some(ref m) = args.mgmt_subnet {
        script_args.push("--mgmt-subnet".into());
        script_args.push(m.clone());
    }
    if let Some(ref u) = args.user {
        script_args.push("--user".into());
        script_args.push(u.clone());
    }
    let vyos_pw = args.vyos_pass.as_ref().or(args.pass.as_ref());
    if let Some(p) = vyos_pw {
        script_args.push("--vyos-pass".into());
        script_args.push(p.clone());
    }
    if let Some(ref rp) = args.root_pass {
        script_args.push("--root-pass".into());
        script_args.push(rp.clone());
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
    if args.force_baseline {
        script_args.push("--force-baseline".into());
    }
    if let Some(ref rm) = args.restore_mode {
        script_args.push("--restore-mode".into());
        script_args.push(rm.clone());
    }
    if let Some(ref cs) = args.config_source {
        script_args.push("--config-source".into());
        script_args.push(cs.clone());
    }
    if args.dry_run {
        script_args.push("--dry-run".into());
    }

    script_args
}

/// Run router commands based on CLI flags.
pub fn run(ctx: &DefenderContext, args: &CliArgs) -> Result {
    let script_args = build_script_args(args);
    let mut env_vars: Vec<(&str, &str)> = Vec::new();

    let vyos_pw = args.vyos_pass.as_ref().or(args.pass.as_ref());
    if let Some(p) = vyos_pw {
        env_vars.push(("DEFENDER_ADMIN_PASS", p.as_str()));
    }
    if let Some(ref rp) = args.root_pass {
        env_vars.push(("DEFENDER_ROOT_PASS", rp.as_str()));
    }

    let str_args: Vec<&str> = script_args.iter().map(|s| s.as_str()).collect();
    run_script(ctx, &str_args, &env_vars)
}
