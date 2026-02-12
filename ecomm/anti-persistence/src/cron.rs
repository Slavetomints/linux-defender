use std::process::Command;
use std::io::{self, Write};


pub fn check_cron() {
    println!("[+] Checking cron jobs...");

    let output = Command::new("crontab")
        .arg("-l")
        .output()
        .expect("failed to execute 'crontab -l'");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let cronjobs: Vec<String> = stdout
        .lines()
        .map(|s| s.to_string())
        .collect();

    let mut good_jobs = Vec::<String>::new();
    let mut bad_jobs = Vec::<String>::new();
    
    for cronjob in &cronjobs {
        let trimmed = cronjob.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        print!("[?] Is this malicious? (y/N) {} \n>", cronjob);
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        io::stdin().read_line(&mut answer)
            .expect("Failed to read the line");
        let answer = answer.trim();

        if answer.eq_ignore_ascii_case("y") {
            bad_jobs.push(cronjob.clone());
        } else {
            good_jobs.push(cronjob.clone());
        }
    }

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


}