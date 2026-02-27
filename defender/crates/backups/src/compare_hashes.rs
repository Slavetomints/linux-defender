//This would be to check previous hashes of files agaisnt other files currently in the system. 
// This compares previously-saved hashes against current system files.
use defender_core::DefenderContext;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use md5;

const ALL_PATHS: &[&str] = &[
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key.pub",
    "/etc/pam.conf",
    "/etc/pam.d",
    "/etc/apache2",
    "/etc/httpd",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/ports.conf",
    "/etc/apache2/sites-available",
    "/etc/apache2/sites-enabled",
    "/etc/apache2/mods-available",
    "/etc/apache2/mods-enabled",
    "/etc/apache2/conf-available/",
    "/etc/apache2/conf-enabled/",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-available/",
    "/etc/nginx/sites-enabled/",
    "/etc/nginx/conf.d/",
    "/var/www/html/opencart/config.php",
    "/var/www/html/opencart/admin/config.php",
    "/var/www/opencart/config.php",
    "/var/www/opencart/admin/config.php",
    "/var/www/html/config.php",
    "/var/www/html/admin/config.php",
    "/etc/postfix",
    "/etc/dovecot",
    "/etc/dovecot/conf.d",
    "/etc/aliases",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/var/spool/cron/crontabs/",
    "/opt/splunk/",
    "/opt/splunk/etc/",
    "/opt/splunk/etc/system/local/",
    "/opt/splunk/etc/system/default/",
    "/opt/splunk/etc/apps/",
    "/opt/splunk/etc/users/",
    "/opt/splunk/etc/deployment-apps/",
    "/opt/splunk/etc/master-apps/",
    "/opt/splunk/etc/shcluster/",
    "/etc/systemd/system/Splunkd.service",
    "/etc/init.d/splunk",
    "/etc/sysconfig/splunk",
    "/opt/splunk/etc/splunk-launch.conf",
];

pub fn run(_ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result<(), String> {
    // Determine previous hashes file location. Require `save_location` to point to the
    // directory that contains the previous `H@shes.txt` file.
    let hash_file_path = match save_location.as_ref() {
        Some(p) => p.join("H@shes.txt"),
        None => return Err("Please provide the directory containing a previous H@shes.txt via save_location".to_string()),
    };

    if !hash_file_path.exists() {
        return Err(format!("Hashes file not found: {}", hash_file_path.display()));
    }

    let previous = parse_hashes_file(&hash_file_path)?;
    let current = compute_current_hashes()?;

    // Compare
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    let mut all_keys: Vec<&String> = previous.keys().chain(current.keys()).collect();
    // dedupe
    all_keys.sort();
    all_keys.dedup();

    for key in all_keys {
        match (previous.get(key), current.get(key)) {
            (Some(prev), Some(curr)) => {
                if prev == curr {
                    unchanged.push(key.clone());
                } else {
                    changed.push((key.clone(), prev.clone(), curr.clone()));
                }
            }
            (Some(_), None) => removed.push(key.clone()),
            (None, Some(_)) => added.push(key.clone()),
            (None, None) => {}
        }
    }

    println!("Comparison results against {}:", hash_file_path.display());
    println!("  Added: {}", added.len());
    for k in &added { println!("    + {}", k); }
    println!("  Removed: {}", removed.len());
    for k in &removed { println!("    - {}", k); }
    println!("  Changed: {}", changed.len());
    for (k, p, c) in &changed { println!("    * {}\n      prev: {}\n      curr: {}", k, p, c); }
    println!("  Unchanged: {}", unchanged.len());

    Ok(())

}

fn parse_hashes_file(path: &Path) -> Result<HashMap<String,String>, String> {
    let f = fs::File::open(path).map_err(|e| format!("Failed to open hashes file {}: {}", path.display(), e))?;
    let reader = BufReader::new(f);
    let mut map = HashMap::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // split into two parts: token and path
        let mut parts = trimmed.split_whitespace();
        if let Some(token) = parts.next() {
            if let Some(rest) = parts.next() {
                let pathstr = rest.trim().to_string();
                map.insert(pathstr, token.to_string());
            }
        }
    }
    Ok(map)
}

fn compute_current_hashes() -> Result<HashMap<String,String>, String> {
    let mut map = HashMap::new();

    for path in ALL_PATHS {
        let src = Path::new(path);
        if !src.exists() {
            // skip missing
            continue;
        }

        if src.is_file() {
            let bytes = fs::read(src).map_err(|e| format!("Failed to read {}: {}", path, e))?;
            let digest = md5::compute(&bytes);
            map.insert(path.to_string(), format!("{:x}", digest));
        } else if src.is_dir() {
            for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path == src { continue; }
                let rel = entry_path.to_string_lossy().to_string();
                if entry_path.is_file() {
                    let bytes = fs::read(entry_path).map_err(|e| format!("Failed to read {}: {}", rel, e))?;
                    let digest = md5::compute(&bytes);
                    map.insert(rel, format!("{:x}", digest));
                } else if entry_path.is_dir() {
                    map.insert(rel, "<dir2>".to_string());
                } else {
                    map.insert(rel, "<other>".to_string());
                }
            }
        } else {
            // other types
            map.insert(path.to_string(), "<other>".to_string());
        }
    }

    Ok(map)
}