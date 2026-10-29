# Persistence Test Scripts — Runbook

These scripts plant known persistence artifacts so the `linux-defender` detection
modules have something real to find. Each one has a paired `defender-cli` flag that
should catch it. Use them to verify your detection coverage before competition.

---

## Quick Usage

```bash
# Deploy one technique
sudo bash 01_cron.sh deploy

# Clean it up
sudo bash 01_cron.sh cleanup

# Deploy all at once
sudo bash ../deploy_persistence.sh deploy

# Clean up all at once
sudo bash ../deploy_persistence.sh cleanup
```

Most scripts respect these env vars (override per-run):

```bash
ATTACKER_IP=10.0.0.1   # default for fetch-and-exec payloads
ATTACKER_PORT=80
```

---

## Technique Reference

| # | Script | Technique | Detection flag | Notes |
|---|--------|-----------|---------------|-------|
| 01 | `01_cron.sh` | Root crontab fetch-and-exec | `--cron` | `*/5 * * * *` entry |
| 02 | `02_ssh_key.sh` | Authorized key in `/root/.ssh/authorized_keys` | `--ssh-keys` | Generates a fresh ed25519 key |
| 03 | `03_systemd_service.sh` | Masquerading service with `bash -c` ExecStart | `--systemd` | Triggers pattern matcher |
| 04 | `04_rc_local.sh` | Payload injected into `/etc/rc.local` | `--rc-local` | Creates file on Arch if absent |
| 05 | `05_ld_preload.sh` | Rogue library in `/etc/ld.so.preload` | `--ld-preload` | Compiles real .so if gcc present, placeholder otherwise |
| 06 | `06_at_job.sh` | Delayed `at` job scheduled far out | `--at-jobs` | Requires `at`/`atd` installed |
| 07 | `07_startup_script.sh` | Payload in `/etc/profile.d/` | `--startup-scripts` | Sourced on every interactive login |
| 08 | `08_xdg_autostart.sh` | `.desktop` file in XDG autostart | none listed | Fires on desktop session start |
| 09 | `09_php_shell.sh` | eval+base64 PHP webshell in web root | `--php-shells` | Drops to `/var/www/html/` |
| 10 | `10_suid_binary.sh` | SUID-root copy of `/usr/bin/id` | `--suid` | Find with `find -perm -4000` |
| 11 | `11_capabilities.sh` | `cap_net_raw` granted to binary | `--capabilities` | Requires `libcap` (usually installed) |
| 12 | `12_backdoor_user.sh` | Account `defender-test-backdoor` with `/bin/bash` | `--users` | `useradd --create-home` |
| 13 | `13_systemd_timer.sh` | Timer + service pair, fires every 5 min | `--systemd-timers` | Both units installed |
| 14 | `14_polkit_rule.sh` | JS polkit rule granting wheel passwordless root | `--polkit` | `/etc/polkit-1/rules.d/` |
| 15 | `15_git_hook.sh` | `post-commit` hook in `/root` that exfils | `--git-hooks` | Only triggers on git commits in /root |
| 16 | `16_cron_system.sh` | `/etc/cron.d/` drop-in (separate from user crontab) | `--cron-system` | Distinct from `--cron` |
| 17 | `17_prompt_command.sh` | Injected into `/etc/bash.bashrc` via `PROMPT_COMMAND` | `--prompt-command` | Fires on every interactive prompt |
| 18 | `18_shell_alias.sh` | Malicious `sudo` alias in `/etc/profile.d/` | `--shell-aliases` | Intercepts every `sudo` call |
| 19 | `19_sudoers_entry.sh` | Drop-in granting backdoor user NOPASSWD root | `--sudoers` | `/etc/sudoers.d/` |

---

## Detection Coverage Check

Run this after deploying all scripts to confirm your scanner catches each one:

```bash
defender-cli anti-persistence --cron
defender-cli anti-persistence --ssh-keys
defender-cli anti-persistence --systemd
defender-cli anti-persistence --rc-local
defender-cli anti-persistence --ld-preload
defender-cli anti-persistence --at-jobs
defender-cli anti-persistence --startup-scripts
defender-cli anti-persistence --php-shells
defender-cli anti-persistence --suid
defender-cli anti-persistence --capabilities
defender-cli anti-persistence --users
defender-cli anti-persistence --systemd-timers
defender-cli anti-persistence --polkit
defender-cli anti-persistence --git-hooks
defender-cli anti-persistence --cron-system
defender-cli anti-persistence --prompt-command
defender-cli anti-persistence --shell-aliases
defender-cli anti-persistence --sudoers
```

Or run everything at once:

```bash
defender-cli anti-persistence --all
```

---

## Cleanup Notes

- **05 ld_preload** — if you left a placeholder (no gcc), every new process will log
  a linker error until cleanup runs. Run it promptly.
- **06 at_job** — requires `atd` to be running: `systemctl start atd`
- **08 xdg_autostart** — only fires when a desktop session is active; harmless on
  headless servers.
- **11 capabilities** — requires `libcap` / `setcap` on the path.
- **15 git_hook** — the exfil curl will fail silently (attacker IP unreachable in test).

All scripts are idempotent on deploy and safe to re-run. Cleanup removes exactly
what deploy put down.
