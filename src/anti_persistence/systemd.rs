//! systemd units.
//!
//! A unit buys an attacker restart-on-failure, start-at-boot, and a plausible
//! name in a list most operators skim. Every unit is presented for review, and
//! the ones flagged are stopped and then disabled so they do not return after
//! a reboot.

use std::path::Path;
use std::process::Command;

use crate::core::scan::suspicious_matches;
use crate::core::{
    Action, DefenderContext, DefenderError, Finding, Result, Severity, Verdict, is_scored_unit,
    prompt_yes,
};

/// One unit as `systemctl list-units` describes it.
struct Service {
    /// Unit name, e.g. `ssh.service`.
    name: String,
    /// Short description from the unit file.
    description: String,
    /// Active state reported by systemd (active, inactive, failed, etc.).
    status: String,
}

/// Review every systemd unit and stop plus disable the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Collecting systemd services...");
    let services = collect_services()?;
    ctx.log_msg(&format!(
        "[✓] {} systemd services collected",
        services.len()
    ));

    ctx.debug(&format!("Parsed {} services", services.len()));

    for service in &services {
        if ctx.in_tui() {
            ctx.emit(
                Finding::new(
                    Severity::Info,
                    "systemd",
                    format!(
                        "{} — {} ({})",
                        service.name, service.description, service.status
                    ),
                    format!(
                        "unit: {}\ndescription: {}\nstatus: {}",
                        service.name, service.description, service.status
                    ),
                )
                .with_action(Action::Manual(format!(
                    "systemctl stop {} && systemctl disable {}",
                    service.name, service.name
                ))),
            );
        } else {
            println!("[+] Name: {}", service.name);
            println!("[+] Description: {}", service.description);
            println!("[+] Status: {}", service.status);

            let scored = is_scored_unit(&service.name);
            if scored {
                println!(
                    "[!] {} backs a SCORED service -- disabling it costs uptime points",
                    service.name
                );
            }

            if prompt_yes("[?] Is this service malicious? (y/N)")?
                && (!scored || prompt_yes("[?] Really stop and disable a scored service? (y/N)")?)
            {
                stop_service(&service.name)?;
                disable_service(&service.name)?;
            }
        }
    }

    ctx.log_msg("[✓] All systemd services checked");
    check_suspicious_units(ctx, &services)?;
    check_unit_content_patterns(ctx, &services)?;
    Ok(())
}

/// Every unit known to systemd, loaded or not.
fn collect_services() -> Result<Vec<Service>> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .map_err(|e| DefenderError::Command(format!("systemctl list-units: {}", e)))?;

    if !output.status.success() {
        return Err(DefenderError::Command(
            "systemctl returned a non-zero exit code".into(),
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| DefenderError::Command(format!("systemctl produced invalid UTF-8: {}", e)))?;

    Ok(parse_services(&stdout))
}

/// Parse `systemctl list-units --no-legend` output.
fn parse_services(output: &str) -> Vec<Service> {
    let mut services = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().skip_while(|p| *p == "●").collect();

        if parts.len() < 4 {
            continue;
        }

        services.push(Service {
            name: parts[0].to_string(),
            status: parts[2].to_string(),
            description: parts[3..].join(" "),
        });
    }

    services
}

/// Stop a unit now.
fn stop_service(name: &str) -> Result {
    Command::new("systemctl")
        .args(["stop", name])
        .output()
        .map_err(|e| DefenderError::Command(format!("systemctl stop {}: {}", name, e)))?;

    println!("[+] Stopped {}", name);
    Ok(())
}

/// Prevent a unit from starting at boot.
fn disable_service(name: &str) -> Result {
    Command::new("systemctl")
        .args(["disable", name])
        .output()
        .map_err(|e| DefenderError::Command(format!("systemctl disable {}: {}", name, e)))?;

    println!("[+] Disabled {}", name);
    Ok(())
}

/// Exec paths that indicate a unit was planted by an attacker rather than
/// installed by a package manager. A hit here is auto-remediated, so the list
/// is limited to places no legitimate service runs from: world-writable
/// volatile directories and hidden directories under library paths.
const SUSPICIOUS_EXEC_PATHS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/shm/",
    "/usr/local/lib/.",
    "/usr/lib/.",
    "/var/lib/.",
];

/// Executable locations that are unusual for a packaged service but routinely
/// legitimate (Tomcat, guest additions, vendor agents and custom apps live in
/// `/opt`; developer services run from `/home`). A hit is reported for a human
/// to judge and is never stopped, disabled or deleted automatically.
const REVIEW_EXEC_PATHS: &[&str] = &["/home/", "/opt/"];

/// Ask systemd for the on-disk path of a unit file.
fn get_fragment_path(name: &str) -> Option<String> {
    let out = Command::new("systemctl")
        .args(["show", "--property=FragmentPath", "--value", name])
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() || s == "(null)" {
        None
    } else {
        Some(s)
    }
}

/// Return the first `ExecStart=` value found in a unit file's text.
fn extract_exec_start(unit_content: &str) -> Option<String> {
    unit_content
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart=").map(str::to_string))
}

/// True when the ExecStart path points into a temp/volatile directory.
fn is_suspicious_exec(exec_start: &str) -> bool {
    SUSPICIOUS_EXEC_PATHS.iter().any(|p| exec_start.contains(p))
}

/// The executable an `ExecStart=` value runs, without systemd's special
/// prefixes (`-`, `@`, `:`, `+`, `!`).
fn exec_binary(exec_start: &str) -> &str {
    exec_start
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches(['-', '@', ':', '+', '!'])
}

/// True when the executable itself (not its arguments) lives under a
/// [`REVIEW_EXEC_PATHS`] directory.
fn is_review_exec(exec_start: &str) -> bool {
    let binary = exec_binary(exec_start);
    REVIEW_EXEC_PATHS.iter().any(|p| binary.starts_with(p))
}

/// For every service whose unit file has a suspicious `ExecStart=` path:
/// capture the unit file as evidence, stop and disable the service, delete the
/// unit file, then emit a Critical finding with proof-of-removal context.
fn check_suspicious_units(ctx: &DefenderContext, services: &[Service]) -> Result {
    for service in services {
        let Some(unit_path_str) = get_fragment_path(&service.name) else {
            continue;
        };
        let unit_path = Path::new(&unit_path_str);
        let Ok(content) = std::fs::read_to_string(unit_path) else {
            continue;
        };
        let Some(exec_start) = extract_exec_start(&content) else {
            continue;
        };
        if !is_suspicious_exec(&exec_start) {
            if is_review_exec(&exec_start) {
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "systemd",
                        format!(
                            "Unit {} runs from {} (left running, review)",
                            service.name,
                            exec_binary(&exec_start)
                        ),
                        format!(
                            "unit: {}\nexec_start: {}\nunit_path: {}\nremoved: false",
                            service.name, exec_start, unit_path_str
                        ),
                    )
                    .with_path(unit_path.to_path_buf())
                    .with_context("unit_path", unit_path_str.clone())
                    .with_context("exec_start", exec_start.clone())
                    .with_context("removed", "false (review only)")
                    .with_verdict(
                        Verdict::Investigate,
                        format!(
                            "{} starts a binary under /opt or /home. That is normal for \
                             vendor and custom applications and also a common place for \
                             implants, so it was not touched. If it is not yours: \
                             `systemctl disable --now {}` and remove {}.",
                            service.name, service.name, unit_path_str
                        ),
                    )
                    .with_action(Action::Manual(format!(
                        "systemctl disable --now {} && rm {}",
                        service.name, unit_path_str
                    ))),
                );
            }
            continue;
        }

        // Log the full unit file as evidence for IR.
        ctx.log_evidence_file(unit_path);

        // Never auto-destroy a scored service's unit. A backdoored Splunkd or
        // sshd unit needs repairing, not deleting -- deleting it is a self-inflicted
        // outage. Flag it Critical for a human instead.
        if is_scored_unit(&service.name) {
            ctx.log_msg(&format!(
                "[!] {} is a scored service unit with suspicious ExecStart -- NOT removing, needs manual repair",
                service.name
            ));
            ctx.emit(
                Finding::new(
                    Severity::Critical,
                    "systemd",
                    format!(
                        "Scored service unit {} has suspicious ExecStart (left running)",
                        service.name
                    ),
                    format!(
                        "unit: {}\nexec_start: {}\nunit_path: {}\nremoved: false (scored service)",
                        service.name, exec_start, unit_path_str
                    ),
                )
                .with_path(unit_path.to_path_buf())
                .with_context("unit_path", unit_path_str.clone())
                .with_context("exec_start", exec_start.clone())
                .with_context("removed", "false (scored service)")
                .with_verdict(
                    Verdict::Investigate,
                    format!(
                        "{} backs a scored service, so it was not stopped or deleted. \
                         Check whether this ExecStart is legitimate for this box. If it was \
                         tampered with, fix the unit (or restore it from backup / reinstall \
                         the package), then `systemctl daemon-reload && systemctl restart {}`.",
                        service.name, service.name
                    ),
                ),
            );
            continue;
        }

        // Stop and disable before removing the file.
        ctx.run_remediation(&["systemctl", "stop", &service.name]);
        ctx.run_remediation(&["systemctl", "disable", &service.name]);
        let removed = ctx.remove_path_logged(unit_path);

        ctx.emit(
            Finding::new(
                Severity::Critical,
                "systemd",
                format!(
                    "Suspicious unit {} has ExecStart in a temp/volatile path",
                    service.name
                ),
                format!(
                    "unit: {}\nexec_start: {}\nunit_path: {}",
                    service.name, exec_start, unit_path_str
                ),
            )
            .with_context("removed", removed.to_string())
            .with_context("unit_path", unit_path_str)
            .with_context("exec_start", exec_start),
        );
    }
    Ok(())
}

/// Scan unit file content for behavioral patterns even when ExecStart looks clean.
///
/// A unit can have a normal-looking ExecStart path but still reference fetch-and-execute
/// patterns, reverse shells, or obfuscation in Environment= or ExecStartPre= directives.
/// We flag these High rather than Critical because a legitimate service might have
/// suspicious-looking content in its description or comments.
fn check_unit_content_patterns(ctx: &DefenderContext, services: &[Service]) -> Result {
    for service in services {
        let Some(unit_path_str) = get_fragment_path(&service.name) else {
            continue;
        };
        let unit_path = Path::new(&unit_path_str);
        let Ok(content) = std::fs::read_to_string(unit_path) else {
            continue;
        };

        let hits: Vec<&'static str> = content
            .lines()
            .flat_map(|line| suspicious_matches(line).into_iter())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        // Require at least 2 distinct pattern hits to avoid false positives from
        // legitimate units that use curl or wget for health checks.
        if hits.len() < 2 {
            continue;
        }

        // Skip units already handled by check_suspicious_units (ExecStart path check).
        if let Some(exec_start) = extract_exec_start(&content)
            && is_suspicious_exec(&exec_start)
        {
            continue;
        }

        ctx.log_evidence_file(unit_path);

        let action = if is_scored_unit(&service.name) {
            Action::Manual(format!(
                "SCORED SERVICE: repair {} in place, do not disable/delete it",
                unit_path_str
            ))
        } else {
            Action::Manual(format!(
                "systemctl stop {} && systemctl disable {} && rm {}",
                service.name, service.name, unit_path_str
            ))
        };

        ctx.emit(
            Finding::new(
                Severity::High,
                "systemd",
                format!(
                    "Unit {} contains suspicious behavioral patterns: [{}]",
                    service.name,
                    hits.join(", ")
                ),
                format!(
                    "unit: {}\nunit_path: {}\npatterns: {}",
                    service.name,
                    unit_path_str,
                    hits.join(", ")
                ),
            )
            .with_path(unit_path.to_path_buf())
            .with_action(action),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_unit_line() {
        let line = "sshd.service loaded active running OpenSSH server daemon";
        let services = parse_services(line);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "sshd.service");
        assert_eq!(services[0].status, "active");
        assert_eq!(services[0].description, "running OpenSSH server daemon");
    }

    #[test]
    fn strips_the_degraded_bullet_prefix() {
        let line = "● broken.service loaded failed failed Some broken unit";
        let services = parse_services(line);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "broken.service");
    }

    #[test]
    fn volatile_and_hidden_exec_paths_are_auto_remove_tier() {
        assert!(is_suspicious_exec("/tmp/.x/implant --daemon"));
        assert!(is_suspicious_exec("/bin/sh -c /dev/shm/run.sh"));
        assert!(is_suspicious_exec("/usr/lib/.cache/svc"));
    }

    #[test]
    fn opt_and_home_are_review_only_never_auto_removed() {
        for exec in [
            "/opt/tomcat/bin/startup.sh",
            "/opt/VBoxGuestAdditions-7.0.0/init/vboxadd-service start",
            "-/home/deploy/app/run",
        ] {
            assert!(!is_suspicious_exec(exec), "{exec} must not be auto-removed");
            assert!(is_review_exec(exec), "{exec} should be flagged for review");
        }
    }

    #[test]
    fn review_tier_looks_at_the_binary_not_its_arguments() {
        assert!(!is_review_exec("/usr/bin/java -jar /opt/app/app.jar"));
        assert!(!is_review_exec("/usr/sbin/nginx -c /home/web/nginx.conf"));
        assert_eq!(exec_binary("-@/opt/x/bin --flag"), "/opt/x/bin");
    }

    #[test]
    fn skips_blank_and_short_lines() {
        assert!(parse_services("\n  \nfoo bar\n").is_empty());
    }
}
