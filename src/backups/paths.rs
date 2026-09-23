//! The configuration paths a full backup covers.

/// Config files and directories worth preserving at the start of a competition.
///
/// Not exhaustive, but covers the services that typically carry scored config.
pub const ALL_PATHS: &[&str] = &[
    // SSH
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key.pub",
    // PAM
    "/etc/pam.conf",
    "/etc/pam.d",
    // Apache / httpd
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
    // Nginx
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-available/",
    "/etc/nginx/sites-enabled/",
    "/etc/nginx/conf.d/",
    // OpenCart
    "/var/www/html/opencart/config.php",
    "/var/www/html/opencart/admin/config.php",
    "/var/www/opencart/config.php",
    "/var/www/opencart/admin/config.php",
    "/var/www/html/config.php",
    "/var/www/html/admin/config.php",
    // Mail
    "/etc/postfix",
    "/etc/dovecot",
    "/etc/dovecot/conf.d",
    "/etc/aliases",
    // DNS / host identity
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    // Cron
    "/etc/crontab",
    "/var/spool/cron/crontabs/",
    // Splunk
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
