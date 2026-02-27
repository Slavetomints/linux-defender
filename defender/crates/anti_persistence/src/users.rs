use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    process::Command,
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
        print!("[?] Is this user malicious?: {} \n> ", user);
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("[X] Failed to read the line");
        let answer = answer.trim();

        if answer.eq_ignore_ascii_case("y") {
            Command::new("userdel")
                .arg(&user)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("[X] Failed to run the command");   
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
