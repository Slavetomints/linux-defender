//! PAM stack tampering.
//!
//! PAM decides who gets to authenticate. A backdoored stack can accept any
//! password, or run an attacker's binary on every login. Rather than diffing
//! against a baseline the tool does not have, this looks for the specific
//! shapes a backdoor takes.

use std::path::{Path, PathBuf};

use crate::core::scan::{effective_line, read_text_files, references_untrusted_dir};
use crate::core::{DefenderContext, Result};

/// Directory holding one PAM stack per service.
const PAM_DIR: &str = "/etc/pam.d";

/// Directories a legitimate PAM module is installed into.
const TRUSTED_MODULE_DIRS: &[&str] = &["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"];

/// A PAM directive that matches a known backdoor shape.
#[derive(Debug, PartialEq, Eq)]
pub struct PamFinding {
    /// PAM config the directive appears in.
    pub file: PathBuf,
    /// The directive itself.
    pub line: String,
    /// Why it was flagged.
    pub reason: &'static str,
}

/// Scan the PAM stack for directives shaped like an authentication backdoor.
pub fn run(ctx: &DefenderContext) -> Result {
    let dir = Path::new(PAM_DIR);
    if !dir.is_dir() {
        println!("[!] {} does not exist, skipping PAM check", PAM_DIR);
        return Ok(());
    }

    let files = read_text_files(dir);
    ctx.debug(&format!("Read {} PAM config file(s)", files.len()));

    let findings = inspect_all(&files);

    if findings.is_empty() {
        println!("[✓] No PAM backdoor patterns found in {}", PAM_DIR);
        return Ok(());
    }

    println!("[!] {} suspicious PAM directive(s):", findings.len());
    for finding in &findings {
        println!("    {}", finding.file.display());
        println!("      {}", finding.line);
        println!("      [!] {}", finding.reason);
    }
    println!("[!] PAM edits are not auto-reverted — a wrong change locks you out.");
    println!("[!] Review each against a known-good config before editing by hand.");

    Ok(())
}

/// Findings across every PAM config, tagged with their file.
fn inspect_all(files: &[(PathBuf, String)]) -> Vec<PamFinding> {
    files
        .iter()
        .flat_map(|(path, contents)| {
            inspect(contents)
                .into_iter()
                .map(move |(line, reason)| PamFinding {
                    file: path.clone(),
                    line,
                    reason,
                })
        })
        .collect()
}

/// Directives in one PAM config that match a known backdoor shape.
fn inspect(contents: &str) -> Vec<(String, &'static str)> {
    let mut findings = Vec::new();

    for line in contents.lines().filter_map(effective_line) {
        let lowered = line.to_lowercase();

        // pam_permit.so always succeeds. That only bypasses authentication
        // when the control flag lets it short-circuit the stack: `sufficient`
        // ends the stack successfully, whereas `optional` has its result
        // discarded and `required` still runs everything after it. Stock
        // stacks on several distributions carry `optional pam_permit.so`, so
        // flagging on the module name alone is pure noise.
        if lowered.contains("pam_permit.so")
            && lowered.starts_with("auth")
            && control_flag(line).is_some_and(|c| c == "sufficient")
        {
            findings.push((
                line.to_string(),
                "sufficient pam_permit.so short-circuits auth, accepting any password",
            ));
        }

        // Runs an arbitrary program on authentication.
        if lowered.contains("pam_exec.so") {
            findings.push((
                line.to_string(),
                "pam_exec.so runs an external program during authentication",
            ));
        }

        // A module loaded from outside the system library directories.
        if let Some(module) = module_path(line)
            && !TRUSTED_MODULE_DIRS.iter().any(|d| module.starts_with(d))
        {
            findings.push((
                line.to_string(),
                "loads a module from outside the system library directories",
            ));
        }

        if references_untrusted_dir(line) {
            findings.push((line.to_string(), "references a world-writable directory"));
        }
    }

    findings
}

/// An absolute module path if the directive names one. Bare module names like
/// `pam_unix.so` resolve against the default directory and are not returned.
fn module_path(line: &str) -> Option<&str> {
    line.split_whitespace()
        .find(|token| token.starts_with('/') && token.contains(".so"))
}

/// The control flag of a PAM directive: the second field, lowercased.
///
/// Returns `None` for the bracketed form (`[success=1 default=ignore]`),
/// which encodes its own jump logic and cannot be judged this simply.
fn control_flag(line: &str) -> Option<String> {
    let second = line.split_whitespace().nth(1)?;
    (!second.starts_with('[')).then(|| second.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stock_debian_stack_is_clean() {
        let stock = "\
# /etc/pam.d/common-auth
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
";
        // `required pam_permit.so` is stock filler: it always succeeds but
        // does not short-circuit, so it grants nothing.
        assert!(inspect(stock).is_empty());
    }

    #[test]
    fn a_stock_arch_stack_is_clean() {
        let stock = "\
auth       required                    pam_faillock.so      preauth
auth       [success=2 default=ignore]  pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
";
        // `optional` has its result discarded; flagging it is noise.
        assert!(inspect(stock).is_empty());
    }

    #[test]
    fn flags_a_sufficient_permit_bypass() {
        let findings = inspect("auth sufficient pam_permit.so\n");

        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.contains("accepting any password"));
    }

    #[test]
    fn a_permit_outside_the_auth_stack_is_ignored() {
        assert!(inspect("session sufficient pam_permit.so\n").is_empty());
    }

    #[test]
    fn the_bracketed_control_form_has_no_simple_flag() {
        assert_eq!(
            control_flag("auth [success=1 default=ignore] pam_unix.so"),
            None
        );
        assert_eq!(
            control_flag("auth sufficient pam_permit.so"),
            Some("sufficient".to_string())
        );
    }

    #[test]
    fn flags_pam_exec() {
        let findings = inspect("auth optional pam_exec.so /usr/local/bin/notify\n");
        assert!(findings.iter().any(|(_, why)| why.contains("pam_exec.so")));
    }

    #[test]
    fn flags_a_module_loaded_from_tmp() {
        let findings = inspect("auth required /tmp/evil.so\n");

        assert!(
            findings
                .iter()
                .any(|(_, why)| why.contains("outside the system library directories"))
        );
        assert!(
            findings
                .iter()
                .any(|(_, why)| why.contains("world-writable"))
        );
    }

    #[test]
    fn an_absolute_path_under_usr_lib_is_fine() {
        let findings = inspect("auth required /usr/lib/security/pam_custom.so\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn bare_module_names_are_not_treated_as_paths() {
        assert_eq!(module_path("auth required pam_unix.so"), None);
        assert_eq!(
            module_path("auth required /tmp/x.so arg"),
            Some("/tmp/x.so")
        );
    }

    #[test]
    fn comments_are_ignored() {
        assert!(inspect("# auth required /tmp/evil.so\n").is_empty());
    }
}
