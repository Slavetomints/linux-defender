//! systemd units.
//!
//! A unit buys an attacker restart-on-failure, start-at-boot, and a plausible
//! name in a list most operators skim. Every unit is presented for review, and
//! the ones flagged are stopped and then disabled so they do not return after
//! a reboot.

use std::process::Command;

use crate::core::{DefenderContext, DefenderError, Result, prompt_yes};

/// One unit as `systemctl list-units` describes it.
struct Service {
    /// Unit name, for example `sshd.service`.
    name: String,
    /// Human-readable description.
    description: String,
    /// Active state, for example `active` or `failed`.
    status: String,
}

/// Review every systemd unit and stop plus disable the ones the operator flags.
pub fn run(ctx: &DefenderContext) -> Result {
    println!("[+] Collecting systemd services...");
    let services = collect_services()?;
    println!("[✓] {} systemd services collected", services.len());

    ctx.debug(&format!("Parsed {} services", services.len()));

    for service in &services {
        println!("[+] Name: {}", service.name);
        println!("[+] Description: {}", service.description);
        println!("[+] Status: {}", service.status);

        if prompt_yes("[?] Is this service malicious? (y/N)")? {
            stop_service(&service.name)?;
            disable_service(&service.name)?;
        }
    }

    println!("[✓] All systemd services checked");
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
        // systemctl marks degraded units with a leading bullet.
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
    fn skips_blank_and_short_lines() {
        assert!(parse_services("\n  \nfoo bar\n").is_empty());
    }
}
