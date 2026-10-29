# Attack Scripts Reference

Technical notes for each script — what it does, how it persists, how to defuse it, and known caveats.

---

## deploy_attack.sh

Master orchestrator. Generates a throwaway ed25519 key (`svc-monitoring`), SCPs all scripts to the target, and runs them in order. Modes: `persistence`, `disrupt`, `destroy`, `lkm`, or `all`.

- Key is written to `/tmp/.svc_key_<epoch>` and deleted after deploy.
- Each script self-deletes after `deploy` to reduce on-disk evidence.
- `cleanup` re-SCPs and runs each script's cleanup case.

---

## 01_shadow_root.sh

Plants a UID-0 duplicate account (`sys.sync` by default) plus two normal-looking sudo accounts (`netadmin`, `svc.monitor`).

- Primary account shares UID 0 with root — `su sys.sync` gives a root shell.
- Extra accounts get NOPASSWD sudoers entries in `/etc/sudoers.d/` (immutable).
- **Survives:** `passwd -l`, `userdel`, password changes on real root.
- **Defuse:** `chattr -i /etc/sudoers.d/.*`, then `userdel sys.sync netadmin svc.monitor`.
- **Caveat:** `useradd -u 0 -o` may be blocked by SELinux policy on hardened Rocky. Test with `setenforce 0` if needed.

---

## 02_ssh_backdoor.sh

Appends a controlled public key to `/root/.ssh/authorized_keys` under marker `# svc-monitoring`.

- Companion `.net-helper` binary (deployed by `04_restore_service.sh`) re-plants the key if removed.
- **Survives:** manual removal of the key line (restore timer re-plants it within minutes).
- **Defuse:** kill the restore timer service, then remove the `# svc-monitoring` block from `authorized_keys`.
- **Artifact:** `/tmp/.svc_key_*` — cleaned up by deploy script after use.

---

## 03_pam_backdoor.sh

Installs a PAM `exec` module that accepts a single magic password for **any** account on the box, regardless of the account's real password.

- Module is written to `/usr/local/lib/.pam_helper` (immutable).
- PAM config patched in `/etc/pam.d/sshd` (and `common-auth` on Debian).
- **Survives:** password changes, account lockout.
- **Defuse:** remove the `auth sufficient pam_exec.so` line from pam.d, delete the helper binary, restart sshd.
- **Note:** PAM module only intercepts sshd — local console login is unaffected.

---

## 04_restore_service.sh

Drops a systemd service + timer that re-plants the SSH authorized key every few minutes.

- Service binary: `/usr/local/lib/.net-helper` (immutable).
- Unit files written to `/etc/systemd/system/` (immutable).
- **Defuse:** `chattr -i` the unit files, `systemctl disable --now`, delete binary.

---

## 05_cron_shell.sh

Drops `/etc/cron.d/sysaudit` — a cron entry that fires a bash TCP reverse shell every 2 minutes.

- File is locked with `chattr +i` — `rm` fails without unlocking first.
- **Listener:** `nc -lvnp 4444` (or whatever `ATTACKER_PORT` is set to).
- **Shell stabilization:** `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `export TERM=xterm` → Ctrl+Z → `stty raw -echo; fg`.
- **Defuse:** `chattr -i /etc/cron.d/sysaudit && rm /etc/cron.d/sysaudit`.
- **Important:** filename must not start with `.` — crond silently ignores dotfiles in `/etc/cron.d/`.

---

## 06_immutable_sweep.sh

Applies `chattr +i` to all planted persistence files in a single pass. Run last in the deploy sequence to lock everything down.

- Cleanup case runs `chattr -i` on the same list — required first step before any manual removal.
- Files list covers: authorized_keys, PAM module, cron entry, sudoers entries, webshell, restore service units.

---

## 07_disrupt_web.sh

Corrupts httpd/nginx/apache2 configs with a syntax error at line 1, then stops and masks the service.

- Masking prevents `systemctl start` from reviving the service without `systemctl unmask` first.
- Original configs backed up as `${file}.orig` — cleanup restores from these.
- **Defuse:** `systemctl unmask httpd && systemctl start httpd` — but only after restoring configs.
- **Caveat:** if the backup fails (disk full, read-only mount), the corruption is permanent — the backup step intentionally aborts before corrupting to prevent data loss.

---

## 08_disrupt_mail.sh — Ubuntu Mail target

Binds postfix and dovecot to loopback only. Both daemons stay running and appear healthy — external SMTP/IMAP/POP3 connections are simply refused.

- Original `inet_interfaces` value saved to `/usr/local/lib/.postfix_ifaces_orig` and restored exactly on cleanup.
- Dovecot override written to `/etc/dovecot/conf.d/99-rt-override.conf` (immutable).
- **Visible to:** hash-compare on main.cf or dovecot conf.d.
- **Defuse:** `chattr -i` the dovecot conf, delete it, restore postfix `inet_interfaces`, restart both services.
- **Note:** dovecot requires a full `restart` (not `reload`) to pick up new conf.d files.

---

## 09_disrupt_splunk.sh — Debian Splunk target

Appends a `[settings]` stanza to `web.conf` forcing Splunk web to bind to `127.0.0.1` only. Splunk daemon stays running — `:8000` and `:8089` refuse external connections.

- Idempotent: skips if marker already present.
- **Defuse:** remove the 4-line stanza (blank + marker + `[settings]` + `server.socket_host`) and restart Splunk.
- **Visible to:** hash-compare on web.conf.

---

## 10_webshell_p0wny.sh

Drops p0wny-shell as `health.php` under the webroot.

- Requires `php-process` package on RHEL/Rocky (provides `posix_getpwuid()`).
- Requires `setenforce 0` — SELinux `httpd_t` context blocks `proc_open()`/`exec()` in PHP.
- `chcon` must run **before** `chattr +i` — immutable flag blocks context changes.
- **Access:** `curl -k https://<target>/health.php`
- **Defuse:** `chattr -i <webroot>/health.php && rm <webroot>/health.php`.

---

## 11_mail_intercept.sh — Ubuntu Mail target

Silent mail intercept via Postfix `content_filter`. Every message is archived to `/usr/local/lib/.locale_cache/` **and** re-injected for normal delivery — scoring stays up, content is captured.

- Filter script: `/usr/local/lib/.locale_helper` (immutable).
- Postfix `main.cf` and `master.cf` both locked with `chattr +i`.
- **Defuse (all four steps required):**
  1. `chattr -i /etc/postfix/main.cf` and remove `content_filter =` line.
  2. `chattr -i /etc/postfix/master.cf` and remove the `# svc-mailroute` block.
  3. `chattr -i /usr/local/lib/.locale_helper` and delete it.
  4. `postfix reload`
- Archived mail in `/usr/local/lib/.locale_cache/` — read with `dump` subcommand.

---

## 12_logic_bomb.sh

Two-layer bomb that creates 1000 fake users 2 hours after deploy.

- **Layer 1:** four staggered `at` jobs (T+2h, T+2h5m, T+2h10m, T+2h30m). Spool files locked with `chattr +i` to block `atrm`.
- **Layer 2:** `/etc/cron.d/pkg_audit` locked, fires at the exact trigger minute as fallback.
- Payload: `/usr/local/lib/.sys_cleanup` (immutable). Creates 1000 users with random 10-char names, password `password`.
- Impact: PAM, Dovecot, or Roundcube iterating `/etc/passwd` will be severely slowed.
- Installs `at` automatically if not present (not default on Rocky 9/10 or Ubuntu minimal).
- **Defuse:** `atq` → unlock spool files → `atrm` each job; `chattr -i /etc/cron.d/pkg_audit` and delete it; `chattr -i /usr/local/lib/.sys_cleanup` and delete it.
- **After bomb fires:** use `12_logic_bomb.sh cleanup` to bulk-remove created users from the registry.

---

## 13_destroy_web.sh

Wipes `/var/www` and uninstalls httpd/nginx/php packages with config purge. No automated recovery — web stack must be reinstalled from scratch.

- Strips `chattr +i` from `/var/www` before deletion (planted by `06_immutable_sweep.sh`).
- Removes packages and purges config dirs: `/etc/httpd`, `/etc/apache2`, `/etc/nginx`, `/etc/php*`, log dirs.
- **No cleanup case** — destruction is permanent by design.

---

## lkm/ — Kernel Module (nic_fw)

Loadable kernel module disguised as a NIC firmware cache driver.

- Hides files whose names start with `.def_` or contain any string in the hide list.
- **Hidden filenames:** `sysaudit`, `pkg_audit`, `.pam_auth`, `.net-helper`, `systemd-network-helper`, `.sys_sync`, `.netadmin`, `.svc_monitor`, `.sys_cleanup`, `.user_registry`, `.locale_helper`, `.locale_cache`, `net-fw.conf`, `nic_fw`; also any name starting with `.def_`.
- Auto-loads on reboot via `/etc/modules-load.d/net-fw.conf`.
- Source and Makefile are wiped after build — only the `.ko` binary remains.
- Auto-installs kernel headers on first run: tries exact `kernel-devel-<kver>` first, falls back to latest `kernel-devel`. Also installs `elfutils-libelf-devel` (required for Rocky 9+ module builds).
- **Rocky 9 target:** kernel 5.14.x (el9). **Rocky 10:** kernel 6.12.x (el10). Both supported via `kallsyms_lookup_name` kprobe approach.
- **Hook mechanism:** `kretprobe` on `__x64_sys_getdents64` — no `sys_call_table` patching, no `set_memory_rw`, no CR0 tricks. The kretprobe fires on every getdents64 return, reads the user buffer via `copy_from_user`, filters hidden names, writes back via `copy_to_user`, and updates `rax`. Zero kernel memory writes outside the standard kprobe API — safe on all kernels including Rocky 9/10 with `__ro_after_init` and RHEL lockdown.
- **If headers version mismatch:** `dnf install -y kernel-devel && reboot`, then re-run.
- **Defuse:** `rmmod nic_fw` (may fail if module hid itself — requires manual intervention); delete `/lib/modules/<kver>/extra/nic_fw.ko` and `/etc/modules-load.d/net-fw.conf`; `depmod -a`.

---

## Network Reference

| Target | IP | Services |
|--------|-----|---------|
| Rocky Ecom | 172.20.240.10 | httpd, opencart |
| Ubuntu Mail | 172.20.240.15 | postfix, dovecot, roundcube |
| Debian Splunk | 172.20.240.20 | splunk |
| Attacker range | 172.31.40.1–6 | nc listeners, SSH |

Default reverse shell listener: `nc -lvnp 4444` on `172.31.40.1`.
