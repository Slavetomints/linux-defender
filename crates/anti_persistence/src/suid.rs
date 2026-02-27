use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use defender_core::DefenderContext;

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    println!("[+] Checking for SUID binaries. This may take a while...");

    let mut child = Command::new("find")
        .args([
            "/",
            "-perm", "-4000",
            "-type", "f",
            "-xdev",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("[X] Failed to spawn find: {}", e))?;

    let stdout = child
        .stdout
        .take()
        .ok_or("[X] Failed to capture stdout")?;

    let reader = BufReader::new(stdout);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("[X] Read error: {}", e))?;
        println!("{}", line);
    }

    let status = child
        .wait()
        .map_err(|e| format!("[X] Failed waiting on find: {}", e))?;

    // Accept exit codes 0 and 1
    if let Some(code) = status.code() {
        if code > 1 {
            return Err(format!("[X] find failed with exit code {}", code));
        }
        if code == 1 {
            eprintln!("[!] find completed with minor permission errors");
        }
    }

    println!("[+] SUID scan complete");

    Ok(())
}