//! Polkit rules that grant unauthorised privilege escalation.
//!
//! Polkit (formerly PolicyKit) is the Linux authorisation framework that
//! mediates privileged operations between unprivileged processes and system
//! daemons. A crafted rule file can grant any user root-equivalent access
//! silently — and the rules directory is checked far less often than `sudoers`.
//!
//! Two rule formats are supported:
//!
//! - **JavaScript `.rules`** (modern format, `/etc/polkit-1/rules.d/` and
//!   `/usr/share/polkit-1/rules.d/`): look for `return polkit.Result.YES`
//!   without subject restriction, wildcard group matches, and modifications to
//!   the core `org.freedesktop.policykit` action namespace.
//! - **INI-style `.pkla`** (legacy format, `/etc/polkit-1/localauthority/`):
//!   look for `ResultAny=yes` / `ResultActive=yes` and `Identity=unix-user:*`
//!   (matches every user on the system).
//!
//! **Findings are emitted as `Verdict::Investigate` — no files are deleted.**
//! A polkit rule can be legitimately installed by a distribution package or an
//! administrator. Automatically removing it could break system services. The
//! operator must decide whether the rule is authorised.

use std::path::Path;

use crate::core::{
    DefenderContext, DefenderError, Finding, Result, Severity, Verdict, require_root,
};

/// Directories containing modern `.rules` (JavaScript) files.
const RULES_DIRS: &[&str] = &[
    "/etc/polkit-1/rules.d",
    "/usr/share/polkit-1/rules.d",
];

/// Root of the legacy `.pkla` directory tree.
const PKLA_ROOT: &str = "/etc/polkit-1/localauthority";

/// Scan all polkit rule and legacy authority files for dangerous grants.
pub fn run(ctx: &DefenderContext) -> Result {
    if require_root().is_err() {
        ctx.emit(Finding::new(
            Severity::Medium,
            "polkit",
            "Not running as root — polkit check skipped",
            "Run as root to review polkit rule files.",
        ));
        return Err(DefenderError::NotRoot);
    }

    ctx.log_msg("[+] Checking polkit rules...");

    // Modern JavaScript rules
    for dir in RULES_DIRS {
        let p = Path::new(dir);
        if p.is_dir() {
            scan_rules_directory(ctx, p);
        }
    }

    // Legacy .pkla files (may be nested in subdirectories)
    let pkla_root = Path::new(PKLA_ROOT);
    if pkla_root.is_dir() {
        scan_pkla_tree(ctx, pkla_root);
    }

    ctx.log_msg("[✓] Polkit check complete");
    Ok(())
}

// ── Modern .rules (JavaScript) ────────────────────────────────────────────────

fn scan_rules_directory(ctx: &DefenderContext, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().map(|e| e == "rules").unwrap_or(false) {
            scan_rules_file(ctx, &path);
        }
    }
}

/// Inspect one `.rules` JavaScript file for dangerous patterns.
fn scan_rules_file(ctx: &DefenderContext, path: &Path) {
    ctx.debug(&format!("Scanning polkit rules file: {}", path.display()));

    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };

    let issues = rules_file_issues(&content);
    if issues.is_empty() {
        return;
    }

    ctx.log_msg(&format!(
        "[!] Suspicious polkit rules file: {} [{} issue(s)]",
        path.display(),
        issues.len()
    ));
    ctx.log_evidence_file(path);

    for issue in &issues {
        ctx.emit(
            Finding::new(
                issue.severity,
                "polkit",
                format!("Polkit rules file — {}: {}", issue.label, path.display()),
                format!(
                    "file: {}\nissue: {}\ndetail: {}\n\n\
                     NOTE: polkit rules may be legitimately installed by packages or \
                     administrators. Review before removing.",
                    path.display(),
                    issue.label,
                    issue.detail,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("file", path.display().to_string())
            .with_context("issue", issue.label.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{}. Verify this file is legitimately installed. \
                     If unauthorised, remove it with: rm {}",
                    issue.recommendation,
                    path.display(),
                ),
            ),
        );
    }
}

// ── Legacy .pkla (INI format) ─────────────────────────────────────────────────

/// Recursively walk the legacy authority directory for `.pkla` files.
fn scan_pkla_tree(ctx: &DefenderContext, root: &Path) {
    use walkdir::WalkDir;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        let path = entry.path();
        if path.extension().map(|e| e == "pkla").unwrap_or(false) {
            scan_pkla_file(ctx, path);
        }
    }
}

/// Inspect one `.pkla` INI-format file for dangerous grants.
fn scan_pkla_file(ctx: &DefenderContext, path: &Path) {
    ctx.debug(&format!("Scanning polkit .pkla file: {}", path.display()));

    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };

    let issues = pkla_file_issues(&content);
    if issues.is_empty() {
        return;
    }

    ctx.log_msg(&format!(
        "[!] Suspicious polkit .pkla file: {} [{} issue(s)]",
        path.display(),
        issues.len()
    ));
    ctx.log_evidence_file(path);

    for issue in &issues {
        ctx.emit(
            Finding::new(
                issue.severity,
                "polkit",
                format!("Polkit .pkla file — {}: {}", issue.label, path.display()),
                format!(
                    "file: {}\nissue: {}\ndetail: {}\n\n\
                     NOTE: .pkla files may be legitimately installed by packages or \
                     administrators. Review before removing.",
                    path.display(),
                    issue.label,
                    issue.detail,
                ),
            )
            .with_path(path.to_path_buf())
            .with_context("file", path.display().to_string())
            .with_context("issue", issue.label.to_string())
            .with_verdict(
                Verdict::Investigate,
                format!(
                    "{}. Verify this file is legitimately installed. \
                     If unauthorised, remove it with: rm {}",
                    issue.recommendation,
                    path.display(),
                ),
            ),
        );
    }
}

// ── Detection helpers ─────────────────────────────────────────────────────────

/// A single suspicious finding inside a polkit file.
struct PolkitIssue {
    severity: Severity,
    /// Short label used in the finding summary and context.
    label: &'static str,
    /// Human-readable description of what was found.
    detail: String,
    /// One-sentence recommendation for the operator.
    recommendation: &'static str,
}

/// Analyse a `.rules` file's content and return all detected issues.
pub fn rules_file_issues(content: &str) -> Vec<PolkitIssue> {
    let mut issues = Vec::new();

    let has_return_yes = content.contains("return polkit.Result.YES");
    let has_wildcard_group = content.contains("subject.isInGroup(\"*\")");
    let has_policykit_action = content.contains("org.freedesktop.policykit");

    // Unconditional YES or wildcard group → Critical privilege escalation
    if has_return_yes || has_wildcard_group {
        let detail = match (has_return_yes, has_wildcard_group) {
            (true, true) => "contains both 'return polkit.Result.YES' and \
                             'subject.isInGroup(\"*\")' — unconditional escalation for all users"
                .to_string(),
            (true, false) => "contains 'return polkit.Result.YES' — may grant unconditional \
                              privilege escalation to any caller"
                .to_string(),
            (false, true) => "contains 'subject.isInGroup(\"*\")' — wildcard group match \
                              that may affect all users"
                .to_string(),
            _ => unreachable!(),
        };

        issues.push(PolkitIssue {
            severity: Severity::Critical,
            label: "unconditional polkit.Result.YES",
            detail,
            recommendation:
                "This rule may grant unconditional privilege escalation. \
                 Review the full file and check whether any subject/action guard is present",
        });
    }

    // Modification of core policykit action namespace → High
    if has_policykit_action {
        issues.push(PolkitIssue {
            severity: Severity::High,
            label: "modifies org.freedesktop.policykit actions",
            detail: "contains a rule matching 'org.freedesktop.policykit' actions, \
                     which control the policy engine itself"
                .to_string(),
            recommendation:
                "Rules matching org.freedesktop.policykit can alter authentication \
                 requirements for polkit itself — verify this is an authorised system file",
        });
    }

    issues
}

/// Analyse a `.pkla` file's content and return all detected issues.
pub fn pkla_file_issues(content: &str) -> Vec<PolkitIssue> {
    let mut issues = Vec::new();

    // Collect suspicious key=value lines
    let mut result_any_yes = false;
    let mut result_active_yes = false;
    let mut identity_wildcard = false;

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('[') || trimmed.starts_with('#') {
            continue;
        }

        let lower = trimmed.to_lowercase();

        if lower == "resultany=yes" {
            result_any_yes = true;
        } else if lower == "resultactive=yes" {
            result_active_yes = true;
        } else if lower.starts_with("identity=unix-user:*")
            || lower.starts_with("identity=unix-group:*")
            || trimmed.eq_ignore_ascii_case("Identity=unix-user:*")
        {
            identity_wildcard = true;
        }
    }

    if identity_wildcard {
        issues.push(PolkitIssue {
            severity: Severity::Critical,
            label: "Identity=unix-user:* (matches all users)",
            detail: "the Identity line uses a wildcard that matches every local user account, \
                     granting the rule's Result to anyone on the system"
                .to_string(),
            recommendation:
                "A wildcard identity in a polkit .pkla file grants the configured access to \
                 every user — this is almost never legitimate outside a development workstation",
        });
    }

    if result_any_yes || result_active_yes {
        let key = if result_any_yes { "ResultAny=yes" } else { "ResultActive=yes" };
        issues.push(PolkitIssue {
            severity: Severity::High,
            label: key,
            detail: format!(
                "{} grants the action to unauthenticated ({}) or active (ResultActive) sessions \
                 without prompting for a password",
                key,
                if result_any_yes { "ResultAny" } else { "ResultActive" },
            ),
            recommendation:
                "ResultAny=yes or ResultActive=yes bypasses password authentication. \
                 Verify the action and identity scope are intentional and minimal",
        });
    }

    issues
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // .rules file analysis

    #[test]
    fn clean_rules_file_has_no_issues() {
        let content = r#"
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.hostname1.set-hostname" &&
        subject.isInGroup("admins")) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
});
"#;
        assert!(rules_file_issues(content).is_empty());
    }

    #[test]
    fn return_yes_without_guard_is_critical() {
        let content = r#"
polkit.addRule(function(action, subject) {
    return polkit.Result.YES;
});
"#;
        let issues = rules_file_issues(content);
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.severity == Severity::Critical));
    }

    #[test]
    fn wildcard_group_is_critical() {
        let content = r#"
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("*")) {
        return polkit.Result.YES;
    }
});
"#;
        let issues = rules_file_issues(content);
        assert!(issues.iter().any(|i| i.severity == Severity::Critical));
    }

    #[test]
    fn policykit_action_modification_is_high() {
        let content = r#"
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.policykit") === 0) {
        return polkit.Result.YES;
    }
});
"#;
        let issues = rules_file_issues(content);
        // Has both Critical (return YES) and High (policykit action)
        assert!(issues.iter().any(|i| i.severity == Severity::High));
        assert!(issues.iter().any(|i| i.severity == Severity::Critical));
    }

    #[test]
    fn return_yes_with_legitimate_group_still_flagged() {
        // Even a guarded YES is surfaced for operator review.
        let content = r#"
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
});
"#;
        let issues = rules_file_issues(content);
        // return polkit.Result.YES present → still flagged
        assert!(issues.iter().any(|i| i.severity == Severity::Critical));
    }

    // .pkla file analysis

    #[test]
    fn clean_pkla_has_no_issues() {
        let content = "[Allow power management for admins]\n\
                       Identity=unix-group:power\n\
                       Action=org.freedesktop.upower.hibernate\n\
                       ResultAny=auth_admin\n\
                       ResultInactive=auth_admin\n\
                       ResultActive=auth_admin\n";
        assert!(pkla_file_issues(content).is_empty());
    }

    #[test]
    fn result_any_yes_is_high() {
        let content = "[Backdoor grant]\n\
                       Identity=unix-group:users\n\
                       Action=org.freedesktop.packagekit.package-install\n\
                       ResultAny=yes\n";
        let issues = pkla_file_issues(content);
        assert!(issues.iter().any(|i| i.severity == Severity::High));
    }

    #[test]
    fn result_active_yes_is_high() {
        let content = "[Suspicious grant]\n\
                       Identity=unix-group:users\n\
                       Action=org.freedesktop.systemd1.manage-units\n\
                       ResultActive=yes\n";
        let issues = pkla_file_issues(content);
        assert!(issues.iter().any(|i| i.severity == Severity::High));
    }

    #[test]
    fn identity_wildcard_user_is_critical() {
        let content = "[Grant everyone sudo-equivalent]\n\
                       Identity=unix-user:*\n\
                       Action=org.freedesktop.sudo\n\
                       ResultAny=yes\n";
        let issues = pkla_file_issues(content);
        // Two issues: wildcard identity (Critical) + ResultAny=yes (High)
        assert!(issues.iter().any(|i| i.severity == Severity::Critical));
        assert!(issues.iter().any(|i| i.severity == Severity::High));
    }

    #[test]
    fn pkla_issues_are_investigate_verdict() {
        // pkla_file_issues is a pure detection function; the Investigate verdict
        // is applied in scan_pkla_file. We just verify issues are returned.
        let content = "Identity=unix-user:*\nResultAny=yes\n";
        assert!(!pkla_file_issues(content).is_empty());
    }

    #[test]
    fn pkla_case_insensitive_key_match() {
        // Keys in .pkla files are documented as case-sensitive but some
        // implementations accept mixed case.
        let content = "resultany=yes\n";
        let issues = pkla_file_issues(content);
        assert!(issues.iter().any(|i| i.severity == Severity::High));
    }
}
