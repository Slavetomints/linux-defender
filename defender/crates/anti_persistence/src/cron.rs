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

    println!("[+] Collecting users...");
    let users: Vec<String> = collect_users()?;
    println!("[✓] Users collected.");
    for user in users {
        println!("[+] {} - Checking cronjobs...", user);
        println!("[+] {} - Collecting cronjobs...", user);
        let cronjobs: Vec<String> = get_cronjobs(&user).expect("[X] Failed to get cronjobs");
        println!("[✓] {} - Cronjobs collected!", user);

        println!("[+] {} - Filtering cronjobs...", user);
        let good_jobs: Vec<String> = filter_jobs(cronjobs).expect("[X] Failed to filter cronjobs");
        println!("[✓] {} - Cronjobs filtered", user);

        println!("[+] {} - Writing good cronjobs to disk...", user);
        write_good_jobs(good_jobs, &user)
            .expect("[X] Failed to write good cron jobs to disk");
        println!("[✓] {} - Good cronjobs written to disk", user);
    }
    println!("[✓] All cronjobs checked!");
    Ok(())
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

fn get_cronjobs(user: &str) -> Result<Vec<String>, String> {
    let mut cronjobs: Vec<String> = Vec::new();

    let output = Command::new("crontab")
        .args(["-l", "-u", &user])
        .output()
        .map_err(|e| format!("Failed to execute crontab for {}: {}", user, e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);

        cronjobs.extend(stdout.lines().map(|line| format!("{}: {}", user, line)));
    }

    Ok(cronjobs)
}

fn filter_jobs(cronjobs: Vec<String>) -> Result<Vec<String>, String> {
    let mut good_jobs = Vec::<String>::new();
    let mut bad_jobs = Vec::<String>::new();

    for cronjob in &cronjobs {
        let trimmed = cronjob.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        println!("{}", cronjob.len());
        print!("[?] Is this malicious? (y/N) {} \n> ", cronjob);
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read the line");
        let answer = answer.trim();

        if answer.eq_ignore_ascii_case("y") {
            bad_jobs.push(cronjob.clone());
        } else {
            good_jobs.push(cronjob.clone());
        }
    }
    return Ok(good_jobs);
}

fn write_good_jobs(good_jobs: Vec<String>, user: &str) -> Result<(), String> {
    let new_cron: String = good_jobs.join("\n");

    let mut child = Command::new("crontab")
        .args(["-", "-u", &user])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("[X] Failed to spawn Crontab");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(new_cron.as_bytes())
        .unwrap();

    child.wait().unwrap();
    return Ok(());
}
