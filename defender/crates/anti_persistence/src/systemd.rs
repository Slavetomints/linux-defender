use std::{io::{self, Write}, process::Command};

use defender_core::DefenderContext;

struct Service {
    name: String,
    description: String,
    status: String,
    //score: u8,
}

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    println!("[+] Checking systemd services...");
    println!("[+] Collecting systemd services...");
    let services: Vec<Service> =
        collect_services().expect("[X] Failed to collect systemd services");
    println!("[✓] systemd services collected");
    println!("[+] Filtering systemd services...");
    filter_services(services).expect("[X] Failed to filer systemd services");
    println!("[✓] Services filtered");
    println!("[✓] All systemd services checked");
    return Ok(());
}

fn collect_services() -> Result<Vec<Service>, String> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .map_err(|e| format!("[X] Failed to execute systemctl: {}", e))?;

    if !output.status.success() {
        return Err("[X] systemctl returned non-zero exit code".into());
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|e| format!("[X] Invalid UTF-8 output: {}", e))?;

    parse_services(&stdout)
}

fn parse_services(output: &str) -> Result<Vec<Service>, String> {
    let mut services = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            continue;
        }

        let mut name = parts[0].to_string();
        if name == "●" {
            name = parts[1].to_string();
        }
        let status = parts[3].to_string();

        let description = parts[4..].join(" ");

        services.push(Service {
            name,
            description,
            status,
            //score: 0,
        });
    }

    Ok(services)
}

fn filter_services(services: Vec<Service>) -> Result<(), String> {
    for service in &services {
        println!("[+] Name: {}", service.name);
        println!("[+] Description: {}", service.description);
        println!("[+] Status: {}", service.status);
        print!("[?] Is this service malicious? (y/N) \n> ");
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("[X] Failed to read the line");
        let answer = answer.trim();

        if answer.eq_ignore_ascii_case("y") {
            stop_service(service.name.clone()).expect("[X] Failed to run stop service function");
            disable_service(service.name.clone()).expect("[X] Failed to run disable service function");
        }
    }
    return Ok(());
}

fn stop_service(name: String) -> Result<(), String> {
    Command::new("systemctl")
        .arg("stop")
        .arg(&name)
        .output()
        .map_err(|e| format!("Failed to execute systemctl: {}", e))?;

    println!("[+] Stopped {}", name);
    return Ok(());
}

fn disable_service(name: String) -> Result<(), String> {
    Command::new("systemctl")
        .arg("disable")
        .arg(&name)
        .output()
        .map_err(|e| format!("Failed to execute systemctl: {}", e))?;

    println!("[+] Stopped {}", name);
    return Ok(());
}
