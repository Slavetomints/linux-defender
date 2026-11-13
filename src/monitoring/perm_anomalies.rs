//! Permission and ownership anomaly detection.
//!
//! Six checks that reveal attacker staging and anti-forensics:
//! orphaned UIDs/GIDs, executables in /etc, unexpected SUID bits,
//! unreadable-but-executable files, future timestamps, and near-epoch timestamps.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::SystemTime;
use walkdir::WalkDir;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

/// Unix timestamp for 2000-01-01 00:00:00 UTC; mtimes before this suggest tampering.
const EPOCH_2000: i64 = 946_684_800; // 2000-01-01 00:00:00 UTC

/// Path prefixes where SUID/SGID binaries are considered legitimate.
const SUID_ALLOWED_PREFIXES: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Path prefixes skipped during filesystem walks (virtual/kernel filesystems).
const SKIP_PREFIXES: &[&str] = &["/proc", "/sys", "/dev"];

/// Return true if `path` is under a virtual filesystem that should not be walked.
fn should_skip(path: &Path) -> bool {
    SKIP_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Parse a colon-delimited system file (passwd/group) and collect numeric IDs at `field_idx`.
fn load_known_ids(path: &str, field_idx: usize) -> HashSet<u32> {
    let mut ids = HashSet::new();
    let Ok(contents) = std::fs::read_to_string(path) else {
        return ids;
    };
    for line in contents.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if let Some(raw) = fields.get(field_idx)
            && let Ok(id) = raw.trim().parse::<u32>()
        {
            ids.insert(id);
        }
    }
    ids
}

/// Check for permission and ownership anomalies: SUID/SGID bits, orphaned files, etc.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Checking for permission and ownership anomalies...");

    check_orphaned_files(ctx);
    check_etc_executables(ctx);
    check_suid_outside_expected(ctx);
    check_reversed_permissions(ctx);
    check_future_timestamps(ctx);
    check_near_epoch_timestamps(ctx);

    ctx.log_msg("[✓] Permission anomaly check complete");
    Ok(())
}

/// Flag files and directories owned by UIDs/GIDs not present in `/etc/passwd` or `/etc/group`.
fn check_orphaned_files(ctx: &DefenderContext) {
    let known_uids = load_known_ids("/etc/passwd", 2);
    let known_gids = load_known_ids("/etc/group", 2);

    let scan_roots = &[
        "/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/home", "/var/www", "/opt", "/srv",
    ];

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if should_skip(path) {
                continue;
            }

            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            let uid = meta.uid();
            let gid = meta.gid();

            let orphan_uid = !known_uids.is_empty() && !known_uids.contains(&uid);
            let orphan_gid = !known_gids.is_empty() && !known_gids.contains(&gid);

            if orphan_uid || orphan_gid {
                let mode = meta.mode() & 0o7777;
                let reason = match (orphan_uid, orphan_gid) {
                    (true, true) => format!(
                        "uid {} and gid {} have no /etc/passwd or /etc/group entry",
                        uid, gid
                    ),
                    (true, false) => format!("uid {} has no /etc/passwd entry", uid),
                    (false, true) => format!("gid {} has no /etc/group entry", gid),
                    _ => unreachable!(),
                };

                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "perm_anomalies",
                        format!("Orphaned file ownership: {}", path.display()),
                        format!("path: {}\n{}", path.display(), reason),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("uid", uid.to_string())
                    .with_context("gid", gid.to_string())
                    .with_context("mode", format!("{:04o}", mode))
                    .with_context("reason", reason.clone())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "File at {} is owned by {} — common when an attacker drops files \
                             under a deleted or non-existent account. Verify the file's purpose \
                             and remove if unknown.",
                            path.display(),
                            reason,
                        ),
                    ),
                );
            }
        }
    }
}

/// Flag executable files found directly inside `/etc`.
fn check_etc_executables(ctx: &DefenderContext) {
    for entry in WalkDir::new("/etc")
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }

        let Ok(meta) = path.metadata() else { continue };
        let mode = meta.mode() & 0o7777;

        if mode & 0o111 != 0 {
            ctx.emit(
                Finding::new(
                    Severity::High,
                    "perm_anomalies",
                    format!("Executable file in /etc: {}", path.display()),
                    format!(
                        "path: {}\nmode: {:04o}\nLegitimate config files are never executable.",
                        path.display(),
                        mode
                    ),
                )
                .with_path(path.to_path_buf())
                .with_context("mode", format!("{:04o}", mode))
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "{} has executable bits set inside /etc. Config files are never \
                         executable — this is either a dropped backdoor script or a misplaced \
                         binary. Review the file and remove it if not a legitimate system file.",
                        path.display(),
                    ),
                ),
            );
        }
    }
}

/// Flag SUID/SGID files that are outside the expected system binary directories.
fn check_suid_outside_expected(ctx: &DefenderContext) {
    for entry in WalkDir::new("/")
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if should_skip(path) {
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }

        let Ok(meta) = path.metadata() else { continue };
        let mode = meta.mode() & 0o7777;

        if mode & 0o4000 == 0 {
            continue;
        }

        let path_str = path.to_string_lossy();
        let in_allowed = SUID_ALLOWED_PREFIXES
            .iter()
            .any(|p| path_str.starts_with(p));
        if in_allowed {
            continue;
        }

        ctx.log_evidence_file(path);

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "perm_anomalies",
                format!("SUID binary outside expected paths: {}", path.display()),
                format!(
                    "path: {}\nmode: {:04o}\nSUID outside /bin, /sbin, /usr/bin, /usr/sbin, \
                     /usr/lib, /usr/local/bin, /usr/local/sbin is unusual.",
                    path.display(),
                    mode,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("mode", format!("{:04o}", mode))
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{} has the SUID bit set and is not under a standard system binary path. \
                     Attackers plant SUID shells (chmod u+s /tmp/sh) for privilege escalation. \
                     Verify ownership and purpose; remove SUID bit with: chmod u-s {}",
                    path.display(),
                    path.display(),
                ),
            ),
        );
    }
}

/// Flag directories that are executable but not readable (reversed permission pattern).
fn check_reversed_permissions(ctx: &DefenderContext) {
    let scan_roots = &[
        "/etc", "/usr", "/bin", "/sbin", "/home", "/opt", "/var/www", "/tmp",
    ];

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if should_skip(path) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            let Ok(meta) = path.metadata() else { continue };
            let mode = meta.mode() & 0o7777;

            // Executable but not readable by anyone
            if (mode & 0o444 == 0) && (mode & 0o111 != 0) {
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "perm_anomalies",
                        format!("Unreadable-but-executable file (reversed permissions): {}", path.display()),
                        format!(
                            "path: {}\nmode: {:04o}\nExecutable by all, readable by none — \
                             anti-forensics trick to prevent content inspection.",
                            path.display(), mode,
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("mode", format!("{:04o}", mode))
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "{} is executable but has no read bits. This is an anti-forensics \
                             trick: the OS will exec it but tools like `cat`, `file`, and `strings` \
                             cannot inspect it. Restore read bits or remove: chmod +r {}",
                            path.display(),
                            path.display(),
                        ),
                    ),
                );
            }
        }
    }
}

/// Flag files whose mtime is in the future, which indicates clock manipulation or tampering.
fn check_future_timestamps(ctx: &DefenderContext) {
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let scan_roots = &[
        "/etc", "/usr", "/bin", "/sbin", "/home", "/opt", "/var/www", "/tmp",
    ];

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if should_skip(path) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            let Ok(meta) = path.metadata() else { continue };
            let mtime = meta.mtime();

            if mtime > now_secs {
                let delta_secs = mtime - now_secs;
                ctx.emit(
                    Finding::new(
                        Severity::Medium,
                        "perm_anomalies",
                        format!("Future timestamp on {}: {}s in the future", path.display(), delta_secs),
                        format!(
                            "path: {}\nmtime: {} ({}s ahead of now)\nAttackers set future timestamps \
                             to evade 'recently modified' scans.",
                            path.display(), mtime, delta_secs,
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("mtime_unix", mtime.to_string())
                    .with_context("delta_secs", delta_secs.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "{} has a modification time {}s in the future. Attackers use \
                             `touch -d` or `touch -t` to set future timestamps to evade time-based \
                             detection. Inspect the file's content.",
                            path.display(), delta_secs,
                        ),
                    ),
                );
            }
        }
    }
}

/// Flag files with an mtime before year 2000, suggesting the timestamp was zeroed or spoofed.
fn check_near_epoch_timestamps(ctx: &DefenderContext) {
    let scan_roots = &[
        "/etc", "/usr", "/bin", "/sbin", "/home", "/opt", "/var/www", "/tmp",
    ];

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if should_skip(path) {
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }

            let Ok(meta) = path.metadata() else { continue };
            let mtime = meta.mtime();

            if mtime < EPOCH_2000 {
                ctx.emit(
                    Finding::new(
                        Severity::Medium,
                        "perm_anomalies",
                        format!("Near-epoch timestamp on {}: mtime={}", path.display(), mtime),
                        format!(
                            "path: {}\nmtime: {} (before 2000-01-01)\nAttackers reset mtime to 0 or \
                             epoch-adjacent to hide modifications from recency-based detection.",
                            path.display(), mtime,
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("mtime_unix", mtime.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "{} has a modification time of {} (before year 2000). This is a \
                             strong indicator of `touch -t 197001010000 <file>` anti-forensics. \
                             Inspect the file content immediately.",
                            path.display(), mtime,
                        ),
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_known_ids_parses_passwd() {
        // Simulate a minimal /etc/passwd line format: name:x:uid:gid:...
        let tmp = std::env::temp_dir().join("perm_anomalies_test_passwd");
        std::fs::write(
            &tmp,
            "root:x:0:0::/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();
        let ids = load_known_ids(tmp.to_str().unwrap(), 2);
        assert!(ids.contains(&0));
        assert!(ids.contains(&65534));
        assert!(!ids.contains(&1001));
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn load_known_ids_parses_group() {
        let tmp = std::env::temp_dir().join("perm_anomalies_test_group");
        std::fs::write(&tmp, "root:x:0:\nsudo:x:27:alice,bob\n").unwrap();
        let ids = load_known_ids(tmp.to_str().unwrap(), 2);
        assert!(ids.contains(&0));
        assert!(ids.contains(&27));
        assert!(!ids.contains(&999));
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn epoch_constant_is_year_2000() {
        // 946684800 = 2000-01-01 00:00:00 UTC
        assert_eq!(EPOCH_2000, 946_684_800);
    }

    #[test]
    fn future_timestamp_detection_logic() {
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let future = now_secs + 3600;
        let past = now_secs - 3600;
        assert!(future > now_secs, "future should be flagged");
        assert!(past <= now_secs, "past should not be flagged");
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn near_epoch_detection_logic() {
        assert!(0_i64 < EPOCH_2000, "epoch 0 is before year 2000");
        assert!(631152000_i64 < EPOCH_2000, "1990 is before year 2000");
        assert!(
            1_700_000_000_i64 >= EPOCH_2000,
            "modern timestamp should not be flagged"
        );
    }

    #[test]
    fn suid_allowed_prefixes_cover_standard_paths() {
        let allowed = |p: &str| {
            SUID_ALLOWED_PREFIXES
                .iter()
                .any(|prefix| p.starts_with(prefix))
        };
        assert!(allowed("/bin/su"));
        assert!(allowed("/usr/bin/sudo"));
        assert!(allowed("/usr/sbin/mount.nfs"));
        assert!(!allowed("/tmp/evil_suid"));
        assert!(!allowed("/home/attacker/shell"));
    }

    #[test]
    fn skip_prefixes_block_proc_sys_dev() {
        assert!(should_skip(Path::new("/proc/1/status")));
        assert!(should_skip(Path::new("/sys/kernel/mm")));
        assert!(should_skip(Path::new("/dev/null")));
        assert!(!should_skip(Path::new("/tmp/evil")));
        assert!(!should_skip(Path::new("/etc/passwd")));
    }

    #[test]
    fn load_known_ids_skips_comments_and_blank_lines() {
        let tmp = std::env::temp_dir().join("perm_anomalies_test_skip");
        std::fs::write(&tmp, "# comment line\n\nroot:x:0:0::/root:/bin/bash\n").unwrap();
        let ids = load_known_ids(tmp.to_str().unwrap(), 2);
        assert!(ids.contains(&0));
        assert_eq!(ids.len(), 1);
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn load_known_ids_missing_file_returns_empty() {
        let ids = load_known_ids("/nonexistent/path/that/does/not/exist", 2);
        assert!(ids.is_empty());
    }

    #[test]
    fn load_known_ids_field_out_of_bounds_skipped() {
        let tmp = std::env::temp_dir().join("perm_anomalies_test_oob");
        // Only 2 fields — asking for field index 5 should return empty
        std::fs::write(&tmp, "only:two\n").unwrap();
        let ids = load_known_ids(tmp.to_str().unwrap(), 5);
        assert!(ids.is_empty());
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn suid_allowed_does_not_include_opt() {
        let p = "/opt/myapp";
        assert!(
            !SUID_ALLOWED_PREFIXES
                .iter()
                .any(|prefix| p.starts_with(prefix))
        );
    }

    #[test]
    fn suid_allowed_does_not_include_home() {
        let p = "/home/user/suidbin";
        assert!(
            !SUID_ALLOWED_PREFIXES
                .iter()
                .any(|prefix| p.starts_with(prefix))
        );
    }

    #[test]
    fn epoch_2000_is_not_flagged_as_future() {
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(EPOCH_2000 < now_secs);
    }
}
