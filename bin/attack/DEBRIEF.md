# Red Team Debrief — MWCCDC 2026

> What happened, how it was done, and what blue team could have done at each step.

---

## Initial Access

**What we did:** SSHed directly to each box with default or competition-provided credentials (`sysadmin` / default pass).

**How to stop it:**
- Change passwords immediately at game start — do not wait
- Disable root SSH login (`PermitRootLogin no` in sshd_config)
- Restrict SSH to known-good source IPs via firewall before the game starts
- Enable `AllowUsers` in sshd_config to whitelist only legitimate accounts

---

## Persistence — All Boxes

### Shadow UID-0 Account (`sys.sync`)

**What we did:** Created a duplicate root account with UID 0 using `useradd -u 0 -o`. Added two additional sudo accounts (`netadmin`, `svc.monitor`) with NOPASSWD sudoers entries.

**How to detect:**
```bash
awk -F: '$3 == 0' /etc/passwd          # more than one line = shadow root
grep NOPASSWD /etc/sudoers /etc/sudoers.d/*
ls -la /etc/sudoers.d/                 # look for hidden/unusual files
```

**How to stop it:** `chattr -i` on sudoers.d entries first, then delete them. Then `userdel sys.sync netadmin svc.monitor`. Check `/etc/passwd` for UID 0 duplicates after every incident.

---

### SSH Authorized Key Backdoor

**What we did:** Appended a controlled public key to `/root/.ssh/authorized_keys` under a `# svc-monitoring` comment. A restore timer re-plants it every 5 minutes if removed.

**How to detect:**
```bash
cat /root/.ssh/authorized_keys         # look for unknown keys
cat /home/*/.ssh/authorized_keys
systemctl list-timers                  # look for unusual timers
```

**How to stop it:** Kill the restore timer first (`systemctl disable --now systemd-network-helper.timer`), then remove the key. Removing the key without killing the timer just gets it re-planted.

---

### PAM Magic Password

**What we did:** Installed a PAM `exec` module that accepts a single hardcoded token as a valid password for **any** account on the box, regardless of real passwords.

**How to detect:**
```bash
grep -r "pam_exec" /etc/pam.d/
ls -la /usr/local/lib/.pam_auth        # hidden by LKM but detectable with chattr check
```

**How to stop it:** Remove the `auth sufficient pam_exec.so` line from `/etc/pam.d/sshd`, delete `/usr/local/lib/.pam_auth`, restart sshd. Changing passwords alone does nothing — the magic token bypasses all password checks.

---

### Cron Reverse Shell

**What we did:** Dropped `/etc/cron.d/sysaudit` (locked `chattr +i`) — fires a bash TCP reverse shell to our attacker box every 2 minutes.

**How to detect:**
```bash
ls -la /etc/cron.d/
cat /etc/cron.d/sysaudit
lsattr /etc/cron.d/sysaudit           # check for immutable flag
```

**How to stop it:**
```bash
chattr -i /etc/cron.d/sysaudit && rm /etc/cron.d/sysaudit
```
Also block outbound connections to unknown IPs with iptables/firewalld.

---

### Restore Service (Systemd Timer)

**What we did:** Planted a systemd service (`systemd-network-helper.timer`) that re-plants the SSH authorized key every 5 minutes even if defenders remove it.

**How to detect:**
```bash
systemctl list-timers --all
systemctl status systemd-network-helper.timer
ls -la /usr/local/lib/.net-helper      # the binary it runs (hidden by LKM)
```

**How to stop it:**
```bash
chattr -i /etc/systemd/system/systemd-network-helper.*
systemctl disable --now systemd-network-helper.timer
rm /etc/systemd/system/systemd-network-helper.*
chattr -i /usr/local/lib/.net-helper && rm /usr/local/lib/.net-helper
```

---

### Shell Poison (`/etc/bash.bashrc` + dotfiles)

**What we did:** Injected a block into `/etc/bash.bashrc` and every user's `.bashrc`/`.profile` that overrides key tools:
- `passwd` — captures new passwords and exfils to Discord before applying
- `chpasswd` — silently no-ops
- `apt/dnf/yum` — blocks installation of defensive tools (tcpdump, nmap, rkhunter, etc.)
- `systemctl stop/disable` — silently ignores commands targeting our services
- `chattr -i` — blocks unlocking our files
- `userdel/usermod -L` — silently ignores our accounts
- `rm` — silently skips our filenames
- `iptables/firewall-cmd` — drops rules targeting our ports

**How to detect:**
```bash
grep -r "SC_BEGIN" /etc/ ~root /home/* 2>/dev/null
cat /etc/bash.bashrc | tail -50
```

**How to stop it:** Find and remove the injected block between `>>>SC_BEGIN<<<` and `>>>SC_END<<<` markers in every affected file. **Start a fresh shell session after** — the overrides stay active in the current session even after the files are cleaned. Use `env -i bash --norc --noprofile` to get a clean shell first.

---

### LKM Rootkit (`nic_fw`)

**What we did:** Compiled and loaded a kernel module disguised as a NIC firmware driver. It hooks `getdents64` to hide planted files from `ls`, `find`, and any tool that lists directories.

**Hidden from view:** `.pam_auth`, `.net-helper`, `.sys_sync`, `.sys_cleanup`, `.user_registry`, `.locale_helper`, `.locale_cache`, `nic_fw*`, anything starting with `.def_`

**How to detect:**
```bash
# Can't use lsmod — module hides itself. Check for the .ko file directly:
find /lib/modules -name "*.ko" | xargs modinfo 2>/dev/null | grep -i "nic\|fw\|firmware"
cat /etc/modules-load.d/net-fw.conf    # auto-load config (not hidden by name)
# Use old getdents syscall (78) to see hidden files:
python3 -c "
import ctypes,os,struct
libc=ctypes.CDLL(None)
fd=os.open('/etc/cron.d',os.O_RDONLY|os.O_DIRECTORY)
buf=ctypes.create_string_buffer(65536)
n=libc.syscall(78,ctypes.c_int(fd),buf,ctypes.c_int(65536))
off=0
while off<n:
    _,_,reclen=struct.unpack_from('QQH',buf.raw,off)
    print(buf.raw[off+18:off+reclen-1].rstrip(b'\x00').decode())
    off+=reclen
"
```

**How to stop it:**
```bash
rmmod nic_fw    # may fail if it hid itself from lsmod — use:
chattr -i /etc/modules-load.d/net-fw.conf && rm /etc/modules-load.d/net-fw.conf
find /lib/modules -name "nic_fw.ko" -delete
depmod -a
# Then reboot — the module can't be cleanly unloaded while hiding itself
```

---

### Logic Bomb

**What we did:** Planted four `at` jobs (locked `chattr +i`) and a cron fallback that fire at 12:00 PM CDT. Payload creates 100 million fake users by writing directly to `/etc/passwd` and `/etc/shadow` at ~200k–500k entries/sec.

**Impact:** PAM, SSH, Dovecot, Roundcube all iterate `/etc/passwd` — they slow to a crawl or hang. Scoring checks that enumerate users will be overwhelmed.

**How to detect:**
```bash
atq                                    # check pending at jobs
lsattr /var/spool/at/jobs/*           # immutable = us
cat /etc/cron.d/pkg_audit             # cron fallback
ls -la /usr/local/lib/.sys_cleanup    # payload script (hidden by LKM)
```

**How to defuse:**
```bash
chattr -i /var/spool/at/jobs/* && atrm $(atq | awk '{print $1}')
chattr -i /etc/cron.d/pkg_audit && rm /etc/cron.d/pkg_audit
chattr -i /usr/local/lib/.sys_cleanup && rm /usr/local/lib/.sys_cleanup
```

**After it fires:** `/etc/passwd` has 100M extra lines. Use `12_logic_bomb.sh cleanup` to remove them from the registry, or manually trim `/etc/passwd` to remove lines with UID ≥ 100000.

---

## Rocky Ecom — Box-Specific

### Web App Disruption (httpd)

**What we did:**
- Ran `07_disrupt_web.sh` which masked httpd and corrupted config with a syntax error
- Manually deleted critical directives from the httpd config file directly
- Deleted `index.php` (the OpenCart/PrestaShop entrypoint)
- Deleted the admin directory entirely
- Planted a webshell at `/var/www/html/health.php`
- SELinux set to permissive (`setenforce 0`)

**How to detect:**
```bash
httpd -t                               # config syntax check
ls /var/www/html/health.php           # webshell
getenforce                            # should be Enforcing
systemctl status httpd                # masked = us
```

**How to stop it:**
- Restore httpd config from backup or reinstall
- Remove webshell
- `setenforce 1` + ensure `/etc/selinux/config` has `SELINUX=enforcing`
- `systemctl unmask httpd && systemctl start httpd`
- Restore deleted PHP files from backup

**What made it hard to recover:** Config file was directly corrupted (not just masked), and critical files were deleted — a service restart alone won't work. Needs full config restoration.

---

## Ubuntu Mail — Box-Specific

### Postfix Sabotage

**What we did:** Set `smtpd_recipient_restrictions = reject_all`, `relayhost = [mail.invalid]:25`, pointed TLS certs to nonexistent files, `smtpd_client_restrictions = reject`. Locked `main.cf` with `chattr +i`.

**How to detect:**
```bash
postconf smtpd_recipient_restrictions
postconf relayhost
lsattr /etc/postfix/main.cf           # immutable flag
```

**How to stop it:**
```bash
chattr -i /etc/postfix/main.cf
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
postconf -e "relayhost ="
# restore TLS cert paths, reload postfix
postfix reload
```

---

### Dovecot Broken

**What we did:** Appended bad config to `dovecot.conf` — empty `auth_mechanisms`, wrong `mail_location`, nonexistent SSL certs. Locked with `chattr +i`. Service is **down**.

**How to detect:**
```bash
systemctl status dovecot
lsattr /etc/dovecot/dovecot.conf
tail -20 /etc/dovecot/dovecot.conf    # look for our appended block
```

**How to stop it:**
```bash
chattr -i /etc/dovecot/dovecot.conf
# remove the appended block (last ~5 lines)
systemctl restart dovecot
```

---

### Roundcube JS Keylogger

**What we did:** Injected a JavaScript snippet into the Roundcube login template (`login.html`) that captures username and password on form submit and sends them to a Discord webhook before the form completes. Marked with `<!-- rc-kl -->`. A systemd timer (`apache2-cache.timer`) re-injects it every 5 minutes if defenders restore the file.

**How to detect:**
```bash
grep -r "rc-kl\|discord.com" /usr/share/roundcube/ /var/lib/roundcube/
systemctl status apache2-cache.timer
ls -la /usr/local/lib/.def_rc_inject  # hidden by LKM — use getdents78 trick
```

**How to stop it:**
```bash
chattr -i /etc/systemd/system/apache2-cache.*
systemctl disable --now apache2-cache.timer
rm /etc/systemd/system/apache2-cache.*
chattr -i /usr/local/lib/.def_rc_inject && rm /usr/local/lib/.def_rc_inject
# Then clean login.html — remove everything between <script> and <!-- rc-kl -->
```

**Credentials we captured:** Anything logged into Roundcube after injection lands in our Discord.

---

### Mail Intercept

**What we did:** Installed a Postfix `content_filter` that silently archives every email to `/usr/local/lib/.locale_cache/` before re-injecting it for normal delivery. Scoring stays up, content is captured.

**How to detect:**
```bash
postconf content_filter
lsattr /etc/postfix/main.cf /etc/postfix/master.cf
grep "svc-mailroute" /etc/postfix/master.cf
ls /usr/local/lib/.locale_cache/      # captured mail (hidden by LKM)
```

**How to stop it:** Four steps required — see `SCRIPTS.md` `11_mail_intercept.sh` defuse section.

---

### LDAP/Kerberos Removal

**What we did:** Purged `ldap-utils`, deleted `/etc/krb5.keytab`, `/etc/krb5.conf`, and `/var/lib/sss/`. Breaks AD-integrated authentication for domain accounts.

**How to stop it:** Reinstall packages and re-apply AD join config — the packages alone aren't enough, the join config must be restored from backup.

---

## Debian Splunk — Box-Specific

### Splunk Web Disabled

**What we did:** Added `server.socket_host = 127.0.0.1` to `web.conf` (locked `chattr +i`) — Splunk web UI on `:8000` no longer accepts external connections. Also set `allowRemoteLogin = never` in `server.conf`.

**How to detect:**
```bash
grep -r "socket_host\|allowRemoteLogin" /opt/splunk/etc/system/local/
lsattr /opt/splunk/etc/system/local/web.conf
```

**How to stop it:**
```bash
chattr -i /opt/splunk/etc/system/local/web.conf
# remove the [settings] block we added
chattr -i /opt/splunk/etc/system/local/server.conf
# remove the [general] allowRemoteLogin block
/opt/splunk/bin/splunk restart
```

---

## General Detection Checklist (Blue Team)

Run these immediately at game start on every box:

```bash
# UID-0 duplicates
awk -F: '$3==0' /etc/passwd

# Immutable files (we rely on this heavily)
find /etc /usr/local/lib /root -name "*" | xargs lsattr 2>/dev/null | grep "^....i"

# Unknown cron jobs
ls -la /etc/cron.d/ && cat /etc/cron.d/*

# Unknown systemd timers/services
systemctl list-timers --all
systemctl list-units --type=service --state=running

# Unknown authorized keys
find /root /home -name "authorized_keys" -exec cat {} \;

# PAM backdoor
grep -r "pam_exec" /etc/pam.d/

# Shell poison marker
grep -r "SC_BEGIN" /etc/ /root /home 2>/dev/null

# LKM rootkit
cat /etc/modules-load.d/*.conf
find /lib/modules -name "*.ko" -newer /boot/vmlinuz* 2>/dev/null

# Suspicious listening processes
ss -tlnp
netstat -tlnp

# Recent logins
last | head -20
lastb | head -20

# Pending at jobs
atq && ls -la /var/spool/at/jobs/
```

---

## What Would Have Stopped Us

1. **Changing passwords immediately** — we used default creds for initial access on all boxes
2. **Remote syslog** — we cleared local logs; remote syslog would have preserved everything
3. **File integrity monitoring (AIDE/tripwire)** — would have caught our planted files immediately
4. **`auditd` rules** — monitoring `/etc/passwd`, `/etc/sudoers`, PAM files, and `authorized_keys` would have alerted on every persistence mechanism
5. **Outbound firewall rules** — blocking unknown outbound connections would have killed our reverse shells and Discord exfil
6. **Starting a clean shell** (`env -i bash --norc --noprofile`) — would have bypassed our shell poison entirely
7. **Checking `lsattr`** — almost everything we planted was locked with `chattr +i`; this is a trivial check that would have revealed all of it
8. **Not trusting their own tools** — our shell poison made `systemctl`, `chattr`, `userdel`, `rm`, and package managers lie to them; running commands from a known-clean environment (like a live USB or a fresh SSH session with `--norc`) would have bypassed all of it
