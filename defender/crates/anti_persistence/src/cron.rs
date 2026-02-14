use std::{io::{self, Write}, process::Command};

use defender_core::DefenderContext;

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    //println!("[+] Collecting all users...");
    //println!("[✓] Collected all users!");

    println!("[+] Checking cronjobs...");
    println!("[+] Collecting cronjobs...");
    let cronjobs: Vec<String> = get_cronjobs().expect("[X] Failed to get cronjobs");
    println!("[✓] Cronjobs collected!");

    println!("[+] Filtering cronjobs...");
    let good_jobs: Vec<String> = filter_jobs(cronjobs).expect("[X] Failed to filter cronjobs");
    println!("[✓] Cronjobs filtered");
     
    println!("[+] Writing good cronjobs to disk...");
    write_good_jobs(good_jobs).expect("[X] Failed to write good cron jobs to disk");
    println!("[✓] Good cronjobs written to disk");
    println!("[✓] All cronjobs checked!");
    Ok(())
}

fn get_cronjobs() -> Result<Vec<String>, String> {
    let output = Command::new("crontab")
        .arg("-l")
        .output()
        .expect("failed to execute 'crontab -l'");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let cronjobs: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
    return Ok(cronjobs);
}

fn filter_jobs(cronjobs: Vec<String>) -> Result<Vec<String>, String> {
    let mut good_jobs = Vec::<String>::new();
    let mut bad_jobs = Vec::<String>::new();

    for cronjob in &cronjobs {
        let trimmed = cronjob.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
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

fn write_good_jobs(good_jobs: Vec<String>) -> Result<(), String> {
    let mut new_cron: String = good_jobs.join("\n");
    new_cron.push('\n');
    
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn Crontab");

    child.stdin.as_mut().unwrap()
        .write_all(new_cron.as_bytes())
        .unwrap();

    child.wait().unwrap();
    return Ok(());
}