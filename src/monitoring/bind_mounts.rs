//! Detect bind mounts and overlay mounts used to hide or shadow files.
//!
//! Attackers use bind mounts to shadow `/etc/passwd`, `/bin/ls`, or other
//! system files without modifying the underlying filesystem.  OverlayFS is
//! used by container runtimes and can be misused to hide modifications to the
//! lower layer.  tmpfs mounts over system paths wipe the real content from the
//! kernel's view while leaving the disk untouched.
//!
//! Parsing `/proc/mounts` requires no external commands and works even when
//! the `mount` binary is itself replaced.

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

// ── System path detection ─────────────────────────────────────────────────────

/// Prefixes that constitute "system paths" — a bind/tmpfs mount over these is
/// suspicious.
const SYSTEM_PREFIXES: &[&str] = &[
    "/etc/", "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/",
];

/// Return true if `path` is a sensitive system directory that should not be bind-mounted over.
fn is_system_path(path: &str) -> bool {
    // Exact matches for the directory itself (e.g. "/etc").
    let exact = ["/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot"];
    if exact.contains(&path) {
        return true;
    }
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Return true if the device string looks like a well-known legitimate device.
fn is_known_device(device: &str) -> bool {
    // Block devices
    if device.starts_with("/dev/sd")
        || device.starts_with("/dev/vd")
        || device.starts_with("/dev/hd")
        || device.starts_with("/dev/nvme")
        || device.starts_with("/dev/xvd")
        || device.starts_with("/dev/mapper/")
        || device.starts_with("/dev/loop")
        || device.starts_with("/dev/md")
    {
        return true;
    }
    // Pseudo-filesystems with well-known devices.
    let known_pseudo = [
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "pstore",
        "efivarfs",
        "securityfs",
        "configfs",
        "debugfs",
        "tracefs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "bpf",
        "overlay", // legitimate container use
        "none",    // some pseudo-fs use "none"
    ];
    if known_pseudo.contains(&device) {
        return true;
    }
    // Bind-mount source paths are paths, not devices — they are handled
    // separately by the bind-mount check.
    if device.starts_with('/') {
        return false;
    }
    // Anything else (NFS, CIFS, autofs, ...) is unknown.
    false
}

// ── Mount line parser ─────────────────────────────────────────────────────────

/// Fields extracted from one line of `/proc/mounts`.
#[derive(Debug, PartialEq)]
pub struct MountEntry {
    /// Source device or path (field 1).
    pub device: String,
    /// Mount point (field 2).
    pub mountpoint: String,
    /// Filesystem type (field 3).
    pub fstype: String,
    /// Mount options (field 4).
    pub options: String,
}

/// Parse a single `/proc/mounts` line into a `MountEntry`.
/// Returns `None` for blank lines or lines with fewer than 4 fields.
pub fn parse_mount_line(line: &str) -> Option<MountEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.splitn(6, ' ');
    let device = parts.next()?.to_string();
    let mountpoint = parts.next()?.to_string();
    let fstype = parts.next()?.to_string();
    let options = parts.next().unwrap_or("").to_string();
    Some(MountEntry {
        device,
        mountpoint,
        fstype,
        options,
    })
}

// ── Analysis ──────────────────────────────────────────────────────────────────

/// Classify a single mount entry and return a finding if it is suspicious.
pub fn classify_mount(entry: &MountEntry) -> Option<(Severity, String)> {
    // 1. bind mount: device is a path, options contain "bind", and source ≠ target
    //    where either touches a system path.
    let is_bind = entry.options.split(',').any(|o| o.trim() == "bind") || entry.fstype == "bind";

    if is_bind && entry.device != entry.mountpoint {
        let src_system = is_system_path(&entry.device);
        let dst_system = is_system_path(&entry.mountpoint);
        if src_system || dst_system {
            return Some((
                Severity::Critical,
                format!(
                    "bind mount shadowing system path: {} → {} (options: {})",
                    entry.device, entry.mountpoint, entry.options
                ),
            ));
        }
    }

    // 2. overlay filesystem — can hide lower-layer modifications.
    if entry.fstype == "overlay" || entry.fstype == "overlayfs" {
        return Some((
            Severity::High,
            format!(
                "OverlayFS mount at {} (device: {}, options: {})",
                entry.mountpoint, entry.device, entry.options
            ),
        ));
    }

    // 3. tmpfs over a system path.
    if entry.fstype == "tmpfs" && is_system_path(&entry.mountpoint) {
        return Some((
            Severity::Critical,
            format!(
                "tmpfs mounted over system path {} — real files are hidden",
                entry.mountpoint
            ),
        ));
    }

    // 4. Unusual device (not a known pseudo-fs or block device).
    if !is_known_device(&entry.device) && entry.device.starts_with('/') {
        // A path-based device that is NOT a bind mount is unusual (e.g. a
        // foreign image or loop-backed path the kernel didn't normalise).
        if !is_bind {
            return Some((
                Severity::Medium,
                format!(
                    "mount from unusual device {:?} at {} (type: {})",
                    entry.device, entry.mountpoint, entry.fstype
                ),
            ));
        }
    }

    None
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Scan `/proc/mounts` for suspicious bind mounts, overlay mounts, and
/// tmpfs mounts over system paths.
pub fn run(ctx: &DefenderContext) -> Result {
    let mounts_content = match std::fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(e) => {
            ctx.log_msg(&format!(
                "[-] bind_mounts: could not read /proc/mounts: {}",
                e
            ));
            return Ok(());
        }
    };

    // Also read /proc/self/mountinfo for extra context (peer groups, parent IDs).
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();

    for line in mounts_content.lines() {
        let Some(entry) = parse_mount_line(line) else {
            continue;
        };
        let Some((severity, description)) = classify_mount(&entry) else {
            continue;
        };

        // Find matching line in mountinfo for richer context.
        let extra_context: Option<String> = mountinfo
            .lines()
            .find(|l| l.contains(&entry.mountpoint))
            .map(|l| l.to_string());

        let mut finding = Finding::new(
            severity,
            "bind_mounts",
            description.clone(),
            format!(
                "Suspicious mount detected.\n  /proc/mounts line: {}\n  {}",
                line,
                extra_context
                    .as_deref()
                    .map(|s| format!("mountinfo: {}", s))
                    .unwrap_or_default()
            ),
        )
        .with_context("mounts_line", line.to_string())
        .with_verdict(
            Verdict::Investigate,
            format!(
                "Inspect this mount manually with `mount | grep '{}'` and `lsof +D {}`. \
                Do NOT unmount without confirming it will not break a running service.",
                entry.mountpoint, entry.mountpoint
            ),
        );

        if let Some(ctx_line) = &extra_context {
            finding = finding.with_context("mountinfo", ctx_line.clone());
        }

        ctx.emit(finding);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_mount_line ──────────────────────────────────────────────────────

    #[test]
    fn parse_valid_line() {
        let entry =
            parse_mount_line("sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0").unwrap();
        assert_eq!(entry.device, "sysfs");
        assert_eq!(entry.mountpoint, "/sys");
        assert_eq!(entry.fstype, "sysfs");
    }

    #[test]
    fn parse_blank_line_returns_none() {
        assert!(parse_mount_line("").is_none());
        assert!(parse_mount_line("   ").is_none());
    }

    #[test]
    fn parse_comment_line_returns_none() {
        assert!(parse_mount_line("# this is a comment").is_none());
    }

    #[test]
    fn parse_options_field() {
        let entry = parse_mount_line("/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 1").unwrap();
        assert_eq!(entry.options, "rw,relatime,errors=remount-ro");
    }

    // ── classify_mount: bind detection ───────────────────────────────────────

    #[test]
    fn bind_mount_over_etc_is_critical() {
        let entry = MountEntry {
            device: "/tmp/fake_etc".to_string(),
            mountpoint: "/etc".to_string(),
            fstype: "none".to_string(),
            options: "rw,bind".to_string(),
        };
        let result = classify_mount(&entry);
        assert!(result.is_some());
        let (sev, _) = result.unwrap();
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn bind_mount_over_etc_passwd_is_critical() {
        let entry = MountEntry {
            device: "/tmp/fake_passwd".to_string(),
            mountpoint: "/etc/passwd".to_string(),
            fstype: "none".to_string(),
            options: "bind".to_string(),
        };
        let (sev, msg) = classify_mount(&entry).unwrap();
        assert_eq!(sev, Severity::Critical);
        assert!(msg.contains("bind mount shadowing system path"));
    }

    #[test]
    fn bind_mount_non_system_is_clean() {
        let entry = MountEntry {
            device: "/data/backup".to_string(),
            mountpoint: "/mnt/backup".to_string(),
            fstype: "none".to_string(),
            options: "rw,bind".to_string(),
        };
        // Neither source nor target is a system path.
        assert!(classify_mount(&entry).is_none());
    }

    // ── classify_mount: overlay detection ────────────────────────────────────

    #[test]
    fn overlay_mount_is_high() {
        let entry = MountEntry {
            device:     "overlay".to_string(),
            mountpoint: "/var/lib/docker/overlay2/abc/merged".to_string(),
            fstype:     "overlay".to_string(),
            options:    "rw,lowerdir=/var/lib/docker/overlay2/abc/lower,upperdir=/var/lib/docker/overlay2/abc/upper".to_string(),
        };
        let (sev, _) = classify_mount(&entry).unwrap();
        assert_eq!(sev, Severity::High);
    }

    // ── classify_mount: tmpfs over system path ────────────────────────────────

    #[test]
    fn tmpfs_over_etc_is_critical() {
        let entry = MountEntry {
            device: "tmpfs".to_string(),
            mountpoint: "/etc".to_string(),
            fstype: "tmpfs".to_string(),
            options: "rw".to_string(),
        };
        let (sev, msg) = classify_mount(&entry).unwrap();
        assert_eq!(sev, Severity::Critical);
        assert!(msg.contains("tmpfs mounted over system path"));
    }

    #[test]
    fn tmpfs_over_usr_is_critical() {
        let entry = MountEntry {
            device: "tmpfs".to_string(),
            mountpoint: "/usr/bin".to_string(),
            fstype: "tmpfs".to_string(),
            options: "rw,noexec".to_string(),
        };
        let (sev, _) = classify_mount(&entry).unwrap();
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn tmpfs_over_tmp_is_clean() {
        // tmpfs on /tmp is completely normal.
        let entry = MountEntry {
            device: "tmpfs".to_string(),
            mountpoint: "/tmp".to_string(),
            fstype: "tmpfs".to_string(),
            options: "rw,nosuid,nodev".to_string(),
        };
        assert!(classify_mount(&entry).is_none());
    }

    // ── is_system_path ────────────────────────────────────────────────────────

    #[test]
    fn system_path_exact_matches() {
        assert!(is_system_path("/etc"));
        assert!(is_system_path("/bin"));
        assert!(is_system_path("/usr"));
    }

    #[test]
    fn system_path_prefix_matches() {
        assert!(is_system_path("/etc/passwd"));
        assert!(is_system_path("/usr/bin/ls"));
        assert!(is_system_path("/lib64/ld-linux.so.2"));
    }

    #[test]
    fn non_system_paths() {
        assert!(!is_system_path("/tmp"));
        assert!(!is_system_path("/home/user"));
        assert!(!is_system_path("/var/www"));
        assert!(!is_system_path("/mnt/data"));
    }
}
