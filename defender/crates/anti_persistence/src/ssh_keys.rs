use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

use defender_core::{DefenderContext, require_root};

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    if require_root().is_err() {
        println!("[!] Not running as root - stopping crontab check.");
        return Err("[X] Must run as root to inspect user crontabs".into());
    }
    println!("[+] Checking users...");
    let users: Vec<String> = collect_users()?;
    for user in users {
        if user == "root" {
            if Path::new("/root/.ssh/authorized_keys").exists() {
                println!("[+] Removing SSH Authorized Keys for {}", user);
                fs::remove_file("/root/.ssh/authorized_keys")
                    .expect("[X] File does not exist or insufficient permissions");
                println!("[+] Removed SSH Authorized Keys file");
            }
        } else if Path::new("/home/{user}/.ssh/authorized_keys").exists() {
            println!("[+] Removing SSH Authorized Keys for {}", user);
            fs::remove_file("/home/{user}/.ssh/authorized_keys")
                .expect("[X] File does not exist or insufficient permissions");
            println!("[+] Removed SSH Authorized Keys file");
        }
    }
    return Ok(());
}

fn collect_users() -> Result<Vec<String>, String> {
    let file =
        File::open("/etc/passwd").map_err(|e| format!("Failed to open /etc/passwd: {}", e))?;

    let reader = BufReader::new(file);

    let mut users = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;

        if let Some(username) = line.split(':').next() {
            users.push(username.to_string());
        }
    }

    Ok(users)
}
