//! Loaded kernel modules and module-load persistence.
//!
//! A malicious module runs in ring 0 and can hide itself from `lsmod`, so a
//! clean result here is not proof of safety. What this can do reliably is spot
//! a loaded module with no backing file in the kernel's module tree, and find
//! the config that would reload one at boot.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::scan::{effective_line, read_text_file, read_text_files};
use crate::core::{DefenderContext, DefenderError, Finding, Result, Severity};

/// Files that list modules to load at boot.
const LOAD_CONFIG_FILES: &[&str] = &["/etc/modules"];
/// Directories containing drop-in module-load configuration files.
const LOAD_CONFIG_DIRS: &[&str] = &["/etc/modules-load.d", "/usr/lib/modules-load.d"];

/// A module currently loaded into the kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    /// Module name as reported by the kernel.
    pub name: String,
    /// Memory footprint in bytes.
    pub size: u64,
    /// Other modules that depend on this one.
    pub used_by: Vec<String>,
}

/// Report loaded modules with no file on disk, and modules set to load at boot.
pub fn run(ctx: &DefenderContext) -> Result {
    let modules = loaded_modules()?;
    ctx.debug(&format!("{} module(s) loaded", modules.len()));
    ctx.log_msg(&format!("[+] {} kernel module(s) loaded", modules.len()));

    report_untracked(ctx, &modules)?;
    report_load_config(ctx);

    ctx.emit(Finding::new(
        Severity::Info,
        "kernel_modules",
        "A rootkit module can unlink itself from the module list — treat a clean result as weak evidence",
        "Use specialized rootkit detectors (rkhunter, chkrootkit) for stronger assurance.",
    ));

    Ok(())
}

/// Modules with no matching file under the running kernel's module tree.
fn report_untracked(ctx: &DefenderContext, modules: &[Module]) -> Result {
    let Some(release) = kernel_release() else {
        ctx.emit(Finding::new(
            Severity::Medium,
            "kernel_modules",
            "Could not determine kernel release — on-disk module check skipped",
            "",
        ));
        return Ok(());
    };

    let tree = PathBuf::from(format!("/lib/modules/{}", release));
    if !tree.is_dir() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "kernel_modules",
            format!(
                "{} does not exist — on-disk module check skipped",
                tree.display()
            ),
            "",
        ));
        return Ok(());
    }

    let available = available_modules(&tree);
    ctx.debug(&format!(
        "{} module file(s) under {}",
        available.len(),
        tree.display()
    ));

    let untracked: Vec<&Module> = modules
        .iter()
        .filter(|m| !available.contains(&normalise(&m.name)))
        .collect();

    if untracked.is_empty() {
        ctx.log_msg(&format!(
            "[✓] Every loaded module has a file in {}",
            tree.display()
        ));
        return Ok(());
    }

    for module in untracked {
        ctx.emit(Finding::new(
            Severity::High,
            "kernel_modules",
            format!("Module '{}' has no file under {}", module.name, tree.display()),
            format!(
                "name: {}\nused_by: {}\nnote: built-in and out-of-tree modules can explain this, but so can a rootkit.",
                module.name,
                if module.used_by.is_empty() { "-".to_string() } else { module.used_by.join(", ") }
            ),
        ));
    }

    Ok(())
}

/// Report modules configured to load at boot.
fn report_load_config(ctx: &DefenderContext) {
    let mut entries: Vec<(PathBuf, Vec<String>)> = Vec::new();

    for file in LOAD_CONFIG_FILES {
        let path = Path::new(file);
        if let Some(contents) = read_text_file(path) {
            let names = config_modules(&contents);
            if !names.is_empty() {
                entries.push((path.to_path_buf(), names));
            }
        }
    }

    for dir in LOAD_CONFIG_DIRS {
        for (path, contents) in read_text_files(Path::new(dir)) {
            let names = config_modules(&contents);
            if !names.is_empty() {
                entries.push((path, names));
            }
        }
    }

    if entries.is_empty() {
        ctx.log_msg("[✓] No modules are configured to load at boot");
        return;
    }

    for (path, names) in entries {
        ctx.emit(
            Finding::new(
                Severity::Medium,
                "kernel_modules",
                format!(
                    "Boot-load config {} enables: {}",
                    path.display(),
                    names.join(", ")
                ),
                format!("file: {}\nmodules: {}", path.display(), names.join(", ")),
            )
            .with_path(path),
        );
    }
}

/// Read and parse the currently loaded modules from `/proc/modules`.
fn loaded_modules() -> Result<Vec<Module>> {
    let contents = read_text_file(Path::new("/proc/modules"))
        .ok_or_else(|| DefenderError::Command("could not read /proc/modules".to_string()))?;
    Ok(parse_proc_modules(&contents))
}

/// Return the running kernel release string from `uname -r`.
fn kernel_release() -> Option<String> {
    let output = Command::new("uname").arg("-r").output().ok()?;
    let release = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!release.is_empty()).then_some(release)
}

/// Walk the kernel module tree and return all normalised module names present on disk.
fn available_modules(tree: &Path) -> HashSet<String> {
    walkdir::WalkDir::new(tree)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let name = entry.path().file_name()?.to_str()?;
            module_stem(name).map(normalise)
        })
        .collect()
}

/// Strip compression and `.ko` suffixes from a module filename, returning the bare stem.
fn module_stem(filename: &str) -> Option<&str> {
    let stem = filename
        .strip_suffix(".zst")
        .or_else(|| filename.strip_suffix(".xz"))
        .or_else(|| filename.strip_suffix(".gz"))
        .unwrap_or(filename);

    stem.strip_suffix(".ko")
}

/// Replace hyphens with underscores so module names compare consistently.
fn normalise(name: &str) -> String {
    name.replace('-', "_")
}

/// Parse `/proc/modules` text into a list of `Module` structs.
fn parse_proc_modules(contents: &str) -> Vec<Module> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }

            let used_by = match fields[3] {
                "-" => Vec::new(),
                list => list
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
            };

            Some(Module {
                name: fields[0].to_string(),
                size: fields[1].parse().unwrap_or(0),
                used_by,
            })
        })
        .collect()
}

/// Parse a module-load config file, returning the list of module names to load.
fn config_modules(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(effective_line)
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MODULES: &str = "\
nf_tables 274432 1 - Live 0x0000000000000000
overlay 155648 0 - Live 0x0000000000000000
snd_hda_intel 57344 3 snd_hda_codec,snd_hwdep Live 0x0000000000000000
";

    #[test]
    fn parses_name_and_size() {
        let modules = parse_proc_modules(PROC_MODULES);
        assert_eq!(modules.len(), 3);
        assert_eq!(modules[0].name, "nf_tables");
        assert_eq!(modules[0].size, 274432);
    }

    #[test]
    fn a_dash_means_nothing_depends_on_it() {
        let modules = parse_proc_modules(PROC_MODULES);
        assert!(modules[0].used_by.is_empty());
    }

    #[test]
    fn parses_the_dependant_list() {
        let modules = parse_proc_modules(PROC_MODULES);
        assert_eq!(modules[2].used_by, vec!["snd_hda_codec", "snd_hwdep"]);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        assert!(parse_proc_modules("garbage\n\nalso garbage\n").is_empty());
    }

    #[test]
    fn config_modules_ignores_comments_and_blanks() {
        let config = "# Load these at boot\n\nnf_tables\nbr_netfilter\n";
        assert_eq!(config_modules(config), vec!["nf_tables", "br_netfilter"]);
    }

    #[test]
    fn module_stem_strips_compression_suffixes() {
        assert_eq!(module_stem("nf_tables.ko"), Some("nf_tables"));
        assert_eq!(module_stem("nf_tables.ko.zst"), Some("nf_tables"));
        assert_eq!(module_stem("nf_tables.ko.xz"), Some("nf_tables"));
        assert_eq!(module_stem("nf_tables.ko.gz"), Some("nf_tables"));
    }

    #[test]
    fn module_stem_rejects_metadata_files() {
        assert_eq!(module_stem("modules.dep"), None);
        assert_eq!(module_stem("modules.alias.bin"), None);
    }

    #[test]
    fn hyphen_and_underscore_names_normalise_together() {
        assert_eq!(normalise("snd-hda-intel"), normalise("snd_hda_intel"));
    }
}
