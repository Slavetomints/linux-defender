use defender_core::DefenderContext;
use std::{process::Command, path::PathBuf};

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
    "/etc/apache2/sites-available",
    "/etc/apache2/sites-enabled",
    "/etc/apache2/mods-available",
    "/etc/apache2/mods-enabled",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d",
    "/var/www/html/opencart/config.php",
    "/var/www/html/opencart/admin/config.php",
    "/var/www/opencart/config.php",
    "/var/www/opencart/admin/config.php",
    "/var/www/html/config.php",
    "/var/www/html/admin/config.php"
];

pub fn run(_ctx: &DefenderContext, save_location: &Option<PathBuf>) -> Result<(), String> {
    let save_path = save_location
        .as_ref()
        .ok_or_else(||"Save location is required for service config backup".to_string())?;


    println!("[+] Backing up service configs to {}", save_path.to_string_lossy());
    for path in ALL_PATHS {
        println!("[+] Backing up {}", path);
        let dest = save_path.join(format!("{}.bak", path.replace("/", "_")));

        //check if the file/directory exists before trying to copy
        if !dest.exists() {
            println!("[!] Warning: {} does not exist, skipping backup", path);
            continue;
        }


        let output = Command::new("cp")
            .arg("-r")
            .arg(path)
            .arg(dest)
            .output()
            .expect(&format!("failed to execute 'cp {}'", path));
        if !output.status.success() {
            return Err(format!("Failed to back up {}: {}", path, String::from_utf8_lossy(&output.stderr)));
        }
    }

    Ok(())

}

