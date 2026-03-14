/*

Tools to install with the Install Tools Flag

Clam AV - Antivirus software

tShark - Wireshark CLI

iftop - Real-time network bandwidth monitoring

chkrootkit - Rootkit detection

fail2ban - Intrusion prevention software

AuditD - 

ntfBuild (Repo Script)

nettools - Networking utilities

PSPY - 

ADIE - 

Zeek - 

*/

// use clap::Args;
use defender_core::DefenderContext;
use std::process::Command;

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    // println!("[INFO]: Installing ClamAV");

    // println!("[INFO]: Installing tShark");
    // println!("[INFO]: Installing iftop");
    // println!("[INFO]: Installing chkrootkit");
    // println!("[INFO]: Installing fail2ban");
    // println!("[INFO]: Installing AuditD");
    println!("[INFO]: Installing ntfBuild");

    let output = Command::new("wget")
        .arg("https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/firewall/host_firewall/nftbuild")
        .output()
        .map_err(|e| format!("failed to start wget: {}", e))?;

    if !output.status.success() {
        eprintln!("wget failed: {}", String::from_utf8_lossy(&output.stderr));
    }else if output.status.success() {
        println!("[INFO]: Successfully downloaded ntfBuild to current Directory");
        
    }

    // println!("[INFO]: Installing nettools");
    // println!("[INFO]: Installing PSPY");
    // println!("[INFO]: Installing ADIE");
    // println!("[INFO]: Installing Zeek");

    Ok(())
}