//! Package-manager helpers: detection, file ownership, and checksum verification.
//!
//! Used to tell vendor files (installed and untouched by dpkg/rpm) apart from
//! files an attacker dropped or modified.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

/// Which package manager the box uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkgManager {
    /// RPM-based (RHEL, Fedora, Rocky).
    Rpm,
    /// dpkg-based (Debian, Ubuntu).
    Dpkg,
    /// Neither found; ownership checks cannot run.
    Unknown,
}

/// Detect the system package manager by probing for its binary.
pub fn detect_package_manager() -> PkgManager {
    if Path::new("/usr/bin/rpm").exists() || Path::new("/bin/rpm").exists() {
        PkgManager::Rpm
    } else if Path::new("/usr/bin/dpkg").exists() {
        PkgManager::Dpkg
    } else {
        PkgManager::Unknown
    }
}

/// Return true if the file at `path_str` is registered with the package manager.
///
/// `Unknown` returns true: when we cannot check, assume OK.
pub fn is_package_owned(path_str: &str, pm: PkgManager) -> bool {
    match pm {
        PkgManager::Unknown => true,
        _ => owning_package(path_str, pm).is_some(),
    }
}

/// Name of the package that owns `path_str`, or `None` if unowned or unknown.
pub fn owning_package(path_str: &str, pm: PkgManager) -> Option<String> {
    match pm {
        PkgManager::Rpm => {
            let out = Command::new("rpm")
                .args(["-qf", "--qf", "%{NAME}\n", path_str])
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let name = stdout.lines().next()?.trim();
            if name.is_empty() || name.contains("not owned") {
                None
            } else {
                Some(name.to_string())
            }
        }
        PkgManager::Dpkg => {
            let out = Command::new("dpkg")
                .args(["-S", path_str])
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            parse_dpkg_search(&String::from_utf8_lossy(&out.stdout))
        }
        PkgManager::Unknown => None,
    }
}

/// Parse `dpkg -S` output (`pkg[, pkg2]: /path`), skipping diversion lines.
fn parse_dpkg_search(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter(|l| !l.starts_with("diversion "))
        .find_map(|l| {
            let (pkgs, _) = l.split_once(": ")?;
            let first = pkgs.split(',').next()?.trim();
            // strip ":amd64"-style arch qualifiers
            let name = first.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
}

/// True if a verify output line (`rpm -V` / `dpkg --verify`) reports a
/// checksum mismatch for `path`.
fn verify_output_flags_path(output: &str, path: &str) -> bool {
    output.lines().any(|line| {
        let Some(flags) = line.split_whitespace().next() else {
            return false;
        };
        let Some(last) = line.split_whitespace().last() else {
            return false;
        };
        last == path && (flags.chars().nth(2) == Some('5') || flags.starts_with("missing"))
    })
}

/// Caches per-package verify output so scanning a big vendor tree only runs
/// `dpkg --verify` / `rpm -V` once per package.
pub struct PkgVerifier {
    /// Package manager this verifier targets.
    pm: PkgManager,
    /// Per-package verify output, cached to avoid repeat invocations.
    cache: RefCell<HashMap<String, String>>,
}

impl PkgVerifier {
    /// Build a verifier for the detected system package manager.
    pub fn new() -> Self {
        Self::with_manager(detect_package_manager())
    }

    /// Build a verifier for an explicit package manager.
    pub fn with_manager(pm: PkgManager) -> Self {
        Self {
            pm,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// True only when `path` is owned by a package AND its checksum still
    /// matches the package database. Unknown package manager, unowned files,
    /// and modified files all return false.
    pub fn is_pristine(&self, path: &Path) -> bool {
        if self.pm == PkgManager::Unknown {
            return false;
        }
        // Resolve symlinks (e.g. /var/lib/roundcube -> /usr/share/roundcube)
        // so the package database lookup sees the real path.
        let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let path_str = real.to_string_lossy().to_string();
        let Some(pkg) = owning_package(&path_str, self.pm) else {
            return false;
        };
        let mut cache = self.cache.borrow_mut();
        let output = cache
            .entry(pkg.clone())
            .or_insert_with(|| self.verify(&pkg));
        !verify_output_flags_path(output, &path_str)
    }

    /// Run the package manager's verify command for one package.
    fn verify(&self, pkg: &str) -> String {
        let (bin, args): (&str, Vec<&str>) = match self.pm {
            PkgManager::Rpm => ("rpm", vec!["-V", pkg]),
            PkgManager::Dpkg => ("dpkg", vec!["--verify", pkg]),
            PkgManager::Unknown => return String::new(),
        };
        Command::new(bin)
            .args(&args)
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }
}

impl Default for PkgVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dpkg_search_with_arch_and_multiple_pkgs() {
        assert_eq!(
            parse_dpkg_search("roundcube-core: /usr/share/roundcube/index.php\n"),
            Some("roundcube-core".into())
        );
        assert_eq!(
            parse_dpkg_search("libc6:amd64, libc6-dev:amd64: /usr/lib/x\n"),
            Some("libc6".into())
        );
        assert_eq!(
            parse_dpkg_search("diversion by foo from: /x\ndiversion by foo to: /y\nbar: /x\n"),
            Some("bar".into())
        );
    }

    #[test]
    fn verify_output_detects_checksum_mismatch_only_for_that_path() {
        let out = "??5?????? c /etc/roundcube/config.inc.php\n??5??????   /usr/share/roundcube/index.php\n";
        assert!(verify_output_flags_path(
            out,
            "/usr/share/roundcube/index.php"
        ));
        assert!(!verify_output_flags_path(
            out,
            "/usr/share/roundcube/program/x.php"
        ));
        let rpm = "S.5....T.    /usr/share/roundcubemail/index.php\n.M.......  c /etc/foo\n";
        assert!(verify_output_flags_path(
            rpm,
            "/usr/share/roundcubemail/index.php"
        ));
        assert!(!verify_output_flags_path(rpm, "/etc/foo"));
    }

    #[test]
    fn unknown_manager_is_never_pristine() {
        let v = PkgVerifier::with_manager(PkgManager::Unknown);
        assert!(!v.is_pristine(Path::new("/bin/sh")));
    }
}
