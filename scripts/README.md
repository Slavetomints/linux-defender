# linux-defender standalone scripts

These scripts can be run directly from the shell as root, or launched from the linux-defender TUI (Tools tab → Interactive Wizards). They do not require the TUI to be running.

## deploy_fail2ban.sh

Installs and configures fail2ban on Debian/Ubuntu/RHEL-family systems. Interactively prompts for ban time, find time, max retries, and SSH jail settings. Enables the service at boot and shows active jails when complete.

## firewall_assessment.sh

Assesses the current firewall posture (iptables/nftables/ufw/firewalld). Reports active rules, open ports, and known risky exposures. Does not modify firewall state — audit only.

## deploy_ipv6.sh

Hardens IPv6 configuration. Optionally disables IPv6 entirely, or restricts it to link-local only. Applies sysctl settings persistently and updates GRUB if needed.

## splunk_forwarder.sh

Installs the Splunk Universal Forwarder and configures it to forward logs to a team indexer. Auto-detects box type (Web/Mail/Splunk/General) and writes a matching `inputs.conf`. Because Splunk does not allow unauthenticated downloads, place the `.deb` or `.rpm` package in `/tmp/` before running this script.
