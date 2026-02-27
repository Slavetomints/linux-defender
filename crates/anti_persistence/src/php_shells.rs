use std::{
    fs::{self, exists},
    io::{self, Write},
    path::PathBuf,
};

use defender_core::DefenderContext;
use defender_core::require_root;
use walkdir::WalkDir;

struct SuspiciousFile {
    pub location: PathBuf,
    pub score: u16,
    pub keywords: Vec<String>,
}

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    if !exists("/var/www/html").expect("[X] Failed to check if /var/www/html exists") {
        return Err("[X] /var/www/html does not exist, skipping web shell check".to_string());
    }
    let suspicious_keywords: Vec<String> = suspicious_keywords();
    let shells: Vec<SuspiciousFile>;

    shells = find_shells(suspicious_keywords).expect("[X] Failed to find web shells");

    for shell in shells {
        println!(
            "\n[!] Warning: Found suspicious file at {}, with a score of {}",
            shell.location.display(),
            shell.score
        );

        println!("[!] Keywords found were {}", shell.keywords.join(", "));

        if require_root().is_err() {
            println!("[!] Not running as root — skipping deletion option.");
            continue;
        }

        print!("[?] Would you like to delete the file? (y/N)\n> ");
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("[X] Failed to read input");

        if answer.trim().eq_ignore_ascii_case("y") {
            match fs::remove_file(&shell.location) {
                Ok(_) => println!("[+] File removed successfully."),
                Err(e) => println!("[X] Failed to remove file: {}", e),
            }
        }
    }
    return Ok(());
}

fn find_shells(keywords: Vec<String>) -> Result<Vec<SuspiciousFile>, String> {
    let mut shells: Vec<SuspiciousFile> = Vec::new();

    for file in WalkDir::new("/var/www/html")
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = file.path();
        if !path.is_file() {
            continue;
        }
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue, // skip unreadable files
        };

        let mut matched: Vec<String> = Vec::new();
        let mut score: u16 = 0;

        for keyword in &keywords {
            let content = content.to_lowercase();
            if content.contains(keyword) {
                matched.push(keyword.clone());
                score += 1;
            }
        }

        if score > 0 {
            shells.push(SuspiciousFile {
                location: path.to_path_buf(),
                score,
                keywords: matched,
            });
        }
    }

    Ok(shells)
}

fn suspicious_keywords() -> Vec<String> {
    vec![
        "exec".into(),
        "passthru".into(),
        "shell_exec".into(),
        "system".into(),
        "proc_open".into(),
        "popen".into(),
        "pcntl_exec".into(),
        "eval".into(),
    ]
}
