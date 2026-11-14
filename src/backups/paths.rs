//! The configuration paths a full backup covers.

/// Config files and directories worth preserving at the start of a competition.
///
/// Not exhaustive, but covers the services that typically carry scored config.
pub const ALL_PATHS: &[&str] = &[
    // SSH: the whole directory, host keys included. Service restore puts
    // /etc/ssh back as a unit so the scoring engine sees the same fingerprint.
    "/etc/ssh",
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
    "/etc/mailname",
    // Webmail
    "/etc/roundcube",
    "/etc/roundcubemail",
    // AD / LDAP / Kerberos join state behind postfix and dovecot auth.
    // Service restore re-applies these; without them a reinstall loses AD auth.
    "/etc/sssd",
    "/etc/krb5.conf",
    "/etc/krb5.keytab",
    "/etc/nsswitch.conf",
    "/etc/ldap",
    "/etc/openldap",
    "/etc/sasl2",
    // DNS / host identity
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    // Cron
    "/etc/crontab",
    "/var/spool/cron/crontabs/",
    // Splunk: configuration layers only. Never list /opt/splunk or
    // /opt/splunk/etc themselves; that drags in var/lib/splunk (the indexes,
    // easily many GB) and the whole install tree.
    "/opt/splunk/etc/system/local/",
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

/// Drop every path that lives underneath another path in the same list.
///
/// A directory is copied and hashed recursively, so listing both `/etc/apache2`
/// and `/etc/apache2/sites-enabled` would do the same work twice. Order is
/// preserved; trailing slashes are ignored for the comparison.
///
/// # Examples
///
/// ```
/// use linux_defender::backups::paths::without_nested;
///
/// let kept = without_nested(&["/etc/apache2", "/etc/apache2/conf-enabled/", "/etc/hosts"]);
/// assert_eq!(kept, vec!["/etc/apache2", "/etc/hosts"]);
/// ```
pub fn without_nested<'a>(paths: &[&'a str]) -> Vec<&'a str> {
    let norm = |p: &str| p.trim_end_matches('/').to_string();
    let mut kept: Vec<&'a str> = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let this = norm(path);
        let covered = paths.iter().enumerate().any(|(j, other)| {
            let parent = norm(other);
            if parent == this {
                // Exact duplicates: keep only the first occurrence.
                j < i
            } else {
                this.starts_with(&format!("{parent}/"))
            }
        });
        if !covered {
            kept.push(path);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_and_duplicate_paths_are_dropped() {
        let kept = without_nested(&[
            "/etc/apache2",
            "/etc/apache2/sites-enabled",
            "/etc/dovecot/conf.d",
            "/etc/dovecot",
            "/etc/hosts",
            "/etc/hosts",
            "/etc/apache2-extra",
        ]);
        assert_eq!(
            kept,
            vec![
                "/etc/apache2",
                "/etc/dovecot",
                "/etc/hosts",
                "/etc/apache2-extra"
            ]
        );
    }

    #[test]
    fn all_paths_never_include_the_splunk_install_or_index_tree() {
        for path in ALL_PATHS {
            let p = path.trim_end_matches('/');
            assert!(
                p != "/opt/splunk" && p != "/opt/splunk/etc" && !p.starts_with("/opt/splunk/var"),
                "{path} would copy the whole Splunk tree"
            );
        }
    }
}
