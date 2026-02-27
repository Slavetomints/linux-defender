use defender_core::DefenderContext;
use std::{process::Command, io::Write};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use md5;
use chrono::Utc;


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

//The service Files themselves should also be backed up like, should show Exec start or exec timeout or possibly also link to service config. 

pub fn run(_ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result<(), String> {
    // Determine save_path: use provided save_location or default to /etc/ccdc-b@ckup-{timestamp}
    let save_path: PathBuf = if let Some(p) = save_location.as_ref() {
        p.clone()
    } else {
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let default = PathBuf::from(format!("/etc/ccdc-b@ckup-{}", ts));
        println!("[!] WARN: No save_location provided, defaulting to {}", default.to_string_lossy());
        default
    };

    // Ensure the save directory exists and create the hashes file inside it so the caller
    // knows exactly where the hashes live.
    if !save_path.exists() {
        fs::create_dir_all(&save_path)
            .map_err(|e| format!("[X] ERROR : Failed to create save directory {}: {}", save_path.display(), e))?;
    }

    let hash_path = save_path.join("H@shes.txt");
    println!("[!] WARN:Writing hashes to {}", hash_path.to_string_lossy());

    let mut hashfile = fs::File::create(&hash_path)
        .map_err(|e| format!("Failed to create hash file {}: {}", hash_path.display(), e))?;

    println!("[+] Backing up service configs to {}", save_path.to_string_lossy());
    for path in ALL_PATHS {
        println!("[+] Backing up {}", path);
        let src = Path::new(path);

        // check if source exists before trying to copy
        if !src.exists() {
            println!("[!] Warning: {} does not exist, skipping backup", path);
            continue;
        }

        // If it's a file, read and hash it. If it's a directory, walk it recursively and hash each file.
        if src.is_file() {
            let file_contents = fs::read(src)
                .map_err(|e| format!("[X] ERROR : Failed to read file {}: {}", path, e))?;

            // compute md5 digest and write hex + path to the hashes file
            let digest = md5::compute(&file_contents);
            writeln!(hashfile, "{:x}  {}", digest, path)
                .map_err(|e| format!("[X] ERROR : Failed to write hash to file: {}", e))?;
        } else if src.is_dir() {
            // Walk the directory recursively and hash each regular file
            for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();

                // skip the root directory entry itself
                if entry_path == src {
                    continue;
                }

                let rel = entry_path.to_string_lossy();
                if entry_path.is_file() {
                    let file_contents = fs::read(entry_path)
                        .map_err(|e| format!("[X] ERROR : Failed to read file {}: {}", rel, e))?;
                    let digest = md5::compute(&file_contents);
                    writeln!(hashfile, "{:x}  {}", digest, rel)
                        .map_err(|e| format!("[X] ERROR : Failed to write hash to file: {}", e))?;
                } else if entry_path.is_dir() {
                    // Directory found inside a top-level directory: two levels deep. We don't hash
                    // directories two layers deep for now — just note and print.
                    println!("[!] WARN: Dir inside dir: {} - not hashed (2 levels deep)", rel);
                    writeln!(hashfile, "<dir2>  {}", rel)
                        .map_err(|e| format!("[X] ERROR : Failed to write hash file: {}", e))?;
                } else {
                    // Other types (symlink, device nodes, etc.) — note them.
                    writeln!(hashfile, "<other>  {}", rel)
                        .map_err(|e| format!("[X] ERROR : Failed to write hash file: {}", e))?;
                }
            }
        } else {
            // For other types (symlink, etc), just note the path
            writeln!(hashfile, "<other>  {}", path)
                .map_err(|e| format!("[X] ERROR : Failed to write hash file: {}", e))?;
        }

        let dest: PathBuf = save_path.join(format!("{}.bak", path.replace('/', "_")));

        let output = Command::new("cp")
            .arg("-r")
            .arg(path)
            .arg(dest)
            .output()
            .map_err(|e| format!("[X] ERROR : Failed to execute 'cp {}': {}", path, e))?;

        if !output.status.success() {
            return Err(format!(
                "[X] ERROR : Failed to back up {}: {}",
                path,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    // ensure all hashes are flushed to disk and report the final location
    hashfile.flush().map_err(|e| format!("[X] ERROR : Failed to flush hash file: {}", e))?;
    hashfile.sync_all().map_err(|e| format!("[X] ERROR : Failed to sync hash file to disk: {}", e))?;

    println!("[✓] Completed backups. Hashes written to {}", hash_path.to_string_lossy());

    Ok(())
}

