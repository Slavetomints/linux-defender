//! Processes whose on-disk executable has been deleted.
//!
//! An attacker may drop a binary, execute it, and then delete the file to
//! reduce forensic evidence. Linux keeps the process running via an open fd
//! to the inode, and `/proc/<pid>/exe` appends ` (deleted)` to the path.

use crate::core::{DefenderContext, Finding, Result, Severity};

/// A running process whose on-disk executable has been deleted.
pub struct DeletedBinary {
    /// Process ID.
    pub pid: u32,
    /// Resolved exe path including the ` (deleted)` suffix.
    pub exe: String,
    /// First 80 chars of the process's command line.
    pub cmdline: String,
}

/// Emit a finding for each process running a deleted binary.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for processes with deleted executables...");
    let found = scan();
    let count = found.len();

    for d in found {
        ctx.emit(Finding::new(
            Severity::High,
            "deleted_binaries",
            format!("PID {} running deleted binary: {}", d.pid, d.exe),
            format!("pid: {}\nexe: {}\ncmdline: {}", d.pid, d.exe, d.cmdline),
        ));
    }

    ctx.log_msg(&format!("[✓] Deleted-binary scan complete — {} found", count));
    Ok(())
}

/// Walk `/proc/*/exe` and return every process whose binary has been deleted.
pub fn scan() -> Vec<DeletedBinary> {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut results = Vec::new();

    for entry in proc.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };

        let exe_link = entry.path().join("exe");
        let Ok(exe_path) = std::fs::read_link(&exe_link) else {
            continue;
        };

        let exe_str = exe_path.to_string_lossy().into_owned();
        if !exe_str.contains(" (deleted)") {
            continue;
        }

        results.push(DeletedBinary {
            pid,
            exe: exe_str,
            cmdline: read_cmdline(pid),
        });
    }

    results
}

fn read_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .replace('\0', " ")
                .trim()
                .chars()
                .take(80)
                .collect()
        })
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_runs_without_panic() {
        // Just ensures the code path doesn't crash; results vary by host.
        let _ = scan();
    }
}
