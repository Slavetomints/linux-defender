# linux-defender standalone scripts

These scripts can be run directly from the shell as root, or launched from the linux-defender TUI (Tools tab → Interactive Wizards). They do not require the TUI to be running.

## deploy_fail2ban.sh

Installs and configures fail2ban on Debian/Ubuntu/RHEL-family systems. Interactively prompts for ban time, find time, max retries, and SSH jail settings. Enables the service at boot and shows active jails when complete.

## firewall_assessment.sh

Written for inject 35 (FW01). Option 1 assesses the current IPv4 firewall posture (iptables/nftables/ufw/firewalld) and option 3 prints verification evidence; both are read-only. **Option 2 changes live firewall rules**: it flushes the IPv4 INPUT chain (or updates the active firewalld zones), allows the ports for the profiles you pick, and sets default deny. Changes are runtime-only and are not persisted.

Inbound SSH (TCP 22) stays allowed by default. Option 2 asks whether to block it; answer `y` only if the inject requires it and you have VM console access, because it drops scored SSH checks and new remote sessions.

## deploy_ipv6.sh

Hardens IPv6 configuration. Optionally disables IPv6 entirely, or restricts it to link-local only. Applies sysctl settings persistently and updates GRUB if needed.

## splunk_forwarder.sh

Installs the Splunk Universal Forwarder and configures it to forward logs to a team indexer. Auto-detects box type (Web/Mail/Splunk/General) and writes a matching `inputs.conf`. Because Splunk does not allow unauthenticated downloads, place the `.deb` or `.rpm` package in `/tmp/` before running this script.
