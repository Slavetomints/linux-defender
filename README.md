# linux-defender

[![CI](https://github.com/UWStout-CCDC/linux-defender/actions/workflows/ci.yml/badge.svg)](https://github.com/UWStout-CCDC/linux-defender/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-75%25-brightgreen)](https://github.com/UWStout-CCDC/linux-defender/actions)
[![MSRV](https://img.shields.io/badge/rustc-1.86%2B-blue)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Full-screen TUI + traditional CLI for hardening Linux boxes in CCDC competition environments.
> Covers anti-persistence hunting, real-time monitoring, config hardening, targeted backups,
> and service restoration — all runnable with a single binary dropped onto an unknown host.

---

## Quick start

```sh
# build a static binary (no shared libs — drop it anywhere)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# binary at target/x86_64-unknown-linux-musl/release/linux-defender

# or a normal build
cargo build --release
```

```sh
# interactive TUI (auto-detects box type, runs all scan modules in background)
sudo ./linux-defender

# one-shot CLI
sudo ./linux-defender anti-persistence --all
sudo ./linux-defender monitoring --all
sudo ./linux-defender system-hardening --user-permissions --services --programs --configs
sudo ./linux-defender backups --all --save-location /root/baseline
```

Tagged pushes (`v*`) build and attach both gnu and static musl binaries to a GitHub Release.

---

## Interactive TUI

Launch with no subcommand. The tab bar adapts dynamically based on detected box type.

### Standard Box Types (Web, Mail, Splunk, General)
Eight tabs, `1`–`8` to switch:

```
┌─[1] Dashboard──[2] Logs──[3] Scan──[4] Hardening──[5] Backups──[6] Monitor──[7] Tools──[8] Svc Restore─┐
│                                                                                                           │
│  ...                                                                                                      │
│                                                                                                           │
├───────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Web  │  5 findings  │  WATCHDOG     [q] quit  [1-8] tabs  [↑↓] select  [Enter] run module               │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Tab | Key | What it does |
|---|---|---|
| **Dashboard** | `1` | Live service status for all scored ports, sessions, auth events |
| **Logs** | `2` | Tail live log streams across multiple panes |
| **Scan** | `3` | Run any combination of the 47 scan modules; browse findings with detail view |
| **Hardening** | `4` | Apply hardening steps (user perms, disable services, restrict programs, deploy configs) |
| **Backups** | `5` | Run targeted backups; live output log |
| **Monitor** | `6` | Run any of 26 monitoring modules on demand |
| **Tools** | `7` | Download and run companion tools and interactive wizards |
| **Svc Restore** | `8` | Reinstall scored services from scratch (Postfix, Dovecot, Splunk, OpenCart, PrestaShop) |

### VyOS Router (`BoxType::Router`)
On VyOS routers, generic Linux services and package reinstalls are omitted. The tab bar dynamically presents 7 streamlined tabs with **Tab 3 (Scan)** dedicated to non-destructive VyOS audit checks and **Tab 4 (Router)** dedicated to active operational remediations:

```
┌─[1] Dashboard──[2] Logs──[3] Scan──[4] Router──[5] Backups──[6] Monitor──[7] Tools──────────────────────┐
│                                                                                                           │
│  ...                                                                                                      │
│                                                                                                           │
├───────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Router │  0 findings  │  WATCHDOG   [q] quit  [1-7] tabs  [↑↓] select  [Enter] run operation            │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Tab | Key | What it does |
|---|---|---|
| **Dashboard** | `1` | Scored SSH status, NAT Rules status, Transit Routing status, last backup timestamp |
| **Logs** | `2` | Full-width stacked syslog and auth streams |
| **Scan** | `3` | 14 dedicated VyOS modular scans emitting structured `Finding` alerts to Dashboard and Findings view |
| **Router** | `4` | VyOS operations: Phase 1 Hardening, Restore NAT Baseline, Dual Password Rotation, Sanitize Hooks/Crons, Linker Cleanup, Purge Containers, Console Lockdown |
| **Backups** | `5` | Targeted router configuration backups (`/config/config.boot`, scripts, credentials) |
| **Monitor** | `6` | Forensic inspection tools (process spy, network watch, binary integrity) |
| **Tools** | `7` | Interactive wizards with stateful list navigation and scrollable active firewall ruleset |

#### Dedicated VyOS Audit Modules (Tab 3)
When running on `Router`, Tab 3 executes 14 non-destructive, modular audit scanners tailored to VyOS 1.4+ configuration and CCDC topology:
1. **`router_version`** (*1. System Version & Identity*): Captures `show version`, release train, kernel version, architecture, uptime, and build UUID.
2. **`router_boot_hooks`** (*2. /config/scripts/ Boot Hooks*): Scans `/config/scripts/` (`vyos-preconfig-bootup.script`, `vyos-postconfig-bootup.script`, `post-upgrade`) for backdoor persistence tokens.
3. **`router_commit_hooks`** (*3. Commit Hooks (High Risk)*): Audits `/config/scripts/commit/pre-hooks.d/` and `post-hooks.d/`. Stock VyOS has 0 commit hooks; flags any root hooks.
4. **`router_task_scheduler`** (*4. Task Scheduler & Linux Cron*): Audits VyOS `system task-scheduler` and system crontabs (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/`).
5. **`router_users`** (*5. Login Accounts & SSH Keys*): Audits VyOS operator accounts, `/etc/passwd` UID 0 backdoors, plaintext passwords, and all `authorized_keys`.
6. **`router_interfaces`** (*6. Interfaces, Tunnels & VPNs*): Scans interfaces, detects rogue tunnel/VPN adapters (wireguard, openvpn, vxlan), and verifies static routes.
7. **`router_containers`** (*7. Containers (Podman)*): Audits VyOS container configurations and queries running Podman/Docker containers.
8. **`router_services_config`** (*8. Configured System Services*): Audits configured services; flags cleartext legacy protocols (Telnet, HTTP API, TFTP).
9. **`router_listening_sockets`** (*9. Listening Sockets & Conns*): Audits active listening sockets (`ss -tulpn`) and established outbound reverse shells.
10. **`router_dyn_linker`** (*10. Linker & Systemd Overrides*): Inspects `/etc/ld.so.preload` for userland rootkits and detects rogue systemd drop-in overrides.
11. **`router_suid_files`** (*11. SUID & Modified Files*): Scans system paths for non-standard SUID/SGID binaries.
12. **`router_commit_history`** (*12. Commit History & Revisions*): Parses commit log history (`show system commit`) for audit trails.
13. **`router_nat`** (*13. NAT Configuration (IP Baseline)*): **IP-Centric NAT Engine**: Matches rules by target server IP (`.10`, `.15`, `.20`, `.100`, `.120`) and ports under ANY rule number. Flags port drift, duplicate/conflicting rules, rogue translations, missing scored targets, and outbound PAT masquerade status.
14. **`router_services_whitelist`** (*14. Services vs ROUTER_ALLOW*): Compares running systemd services against the curated VyOS whitelist (`ROUTER_WHITELIST`) and blacklist (`ROUTER_BLACKLIST`).

#### Dedicated Router Remediations (Tab 4)
Tab 4 provides single-key failsafe remediations with rollback protection:
- **Phase 1: Hardening & Init Config** (`--harden`): Deploys 1:1 NAT, control-plane firewall, cleans persistence hooks, rotates credentials with 5-minute failsafe rollback.
- **Restore NAT Baseline on Router** (`--restore-nat`): IP-centric cleanup that dynamically deletes any conflicting rule numbers pointing to scored server IPs before deploying standard rules 10–14.
- **Update VyOS & Linux Root Passwords** (`--rotate-passwords`): Separately updates `vyos` and Linux superuser `root` passwords and sanitizes `authorized_keys`.
- **Sanitize Boot & Commit Hooks** (`--sanitize-hooks`): Quarantines commit hooks from `(pre|post)-hooks.d/` and resets bootup scripts to clean stock templates.
- **Sanitize Task Scheduler & Crons** (`--sanitize-cron`): Deletes VyOS `system task-scheduler` and clears `/var/spool/cron/crontabs/*`.
- **Remove Dynamic Linker Overrides** (`--clean-rootkits`): Deletes `/etc/ld.so.preload` and removes rogue systemd service drop-ins.
- **Purge Rogue Containers** (`--purge-containers`): Deletes VyOS container config and forcefully removes all Podman containers (`podman rm -f -a`).
- **Phase 2: Console Lockdown** (`--console-lockdown`): Completely tears down SSH service and drops port 22 (Console-Only Administration).
- **Confirm Pending Commit** (`--confirm`): Confirms and saves pending `commit-confirm` changes permanently.
---

## CLI reference

Every run appends to `defender-report-<timestamp>.txt` in the working directory.

### `anti-persistence`

Hunts for Red Team persistence mechanisms. Every destructive action prompts `y/N` first.

| Flag | Mode | What it does |
|---|---|---|
| `--cron` | prompts | Reviews each user's crontab entry by entry, rewrites keeping only approved lines |
| `--cron-system` | prompts | Checks `/etc/cron.d` and periodic script directories for malicious jobs |
| `--systemd` | prompts | Walks all systemd units, stops + disables ones you flag |
| `--systemd-timers` | prompts | Scans systemd timer units for suspicious intervals or malicious `ExecStart` |
| `--users` | prompts | Reviews every account in `/etc/passwd`, `userdel`s ones you flag |
| `--ssh-keys` | prompts | Finds `authorized_keys` per account, removes on confirmation |
| `--at-jobs` | prompts | Reviews `atq` jobs, `atrm`s flagged ones |
| `--webshells` | prompts | Scores files under `/var/www/html` against webshell primitives |
| `--ld-preload` | prompts | Checks `/etc/ld.so.preload` and `$LD_PRELOAD` for loader hijacking |
| `--rc-local` | prompts | Reports boot commands in `rc.local`, offers to blank them |
| `--xdg-autostart` | prompts | Lists autostart `.desktop` entries, offers to remove flagged ones |
| `--immutable` | prompts | Detects immutable/append-only flags on sensitive files |
| `--ssh-config` | read-only | Audits `sshd_config` for dangerous directives (`ForceCommand`, `AuthorizedKeysCommand`, etc.) |
| `--sudoers` | read-only | Audits `/etc/sudoers` and `sudoers.d` for `NOPASSWD`, `LD_PRELOAD`, and wildcard rules |
| `--shell-aliases` | read-only | Detects malicious shell aliases in global and per-user dotfiles |
| `--polkit` | read-only | Audits polkit rules and pkla files for unconditional privilege grants |
| `--pam` | read-only | Finds PAM directives shaped like an auth backdoor |
| `--startup-scripts` | read-only | Scans system and per-user shell dotfiles for dangerous lines |
| `--udev` | read-only | Finds admin-managed udev rules that execute a program |
| `--logrotate` | read-only | Finds logrotate script blocks (run as root on a timer) |
| `--grub` | read-only | Checks kernel parameters and `/etc/grub.d` scripts |
| `--kernel-modules` | read-only | Loaded modules with no file on disk, plus boot-load config |
| `--initramfs` | read-only | Custom initramfs hooks, and images newer than their kernel |
| `--capabilities` | read-only | Files carrying dangerous Linux capabilities (slow: sweeps `/`) |
| `--suid` | read-only | Lists SUID binaries (slow: sweeps `/`) |
| `--prompt-command` | read-only | Reports a hijacked `$PROMPT_COMMAND` |
| `--git-hooks` | read-only | Scans git repositories for malicious hook scripts |
| `--all` | — | Runs every check |

**prompts** = can modify the system, always asks `y/N` first. **read-only** = never modifies. PAM, udev, and logrotate are intentionally read-only — an automated edit there can lock you out or break devices.

### `monitoring`

Scans the live system for attacker activity and anomalies. All checks are read-only.

| Flag | What it detects |
|---|---|
| `--auth-log-analysis` | Brute-force and credential-stuffing patterns in `auth.log` / `secure` |
| `--access-log` | Web request anomalies: traversal, webshell params, scanner UAs, 404 storms |
| `--error-log` | Nginx/Apache error log: CGI errors, sensitive-path denials, WAF triggers |
| `--auth-log-watch` | 1-hour sliding window: account creation/deletion, password changes, SSH logins |
| `--pspy` | New short-lived processes, deleted binaries still running under `/proc` |
| `--network-watch` | Active connections to public IPs, suspicious listeners |
| `--php-modules` | Malicious PHP ini settings, unknown extension `.so` files, webshell patterns in PHP files |
| `--port-map` | Maps listening TCP ports to their owning binaries |
| `--hidden-elf` | Hidden ELF binaries in web roots and temp directories |
| `--deleted-binaries` | Processes whose on-disk executable has been deleted |
| `--process-tree` | Parent→child anomalies (web server spawning a shell, etc.) |
| `--recently-modified` | System binaries modified after competition start |
| `--suspicious-services` | Systemd units with suspicious `ExecStart` paths |
| `--world-writable` | World-writable directories and files outside expected locations |
| `--outbound-connections` | Established TCP connections from service accounts to unexpected ports |
| `--fail2ban` | fail2ban daemon status, active jails, and recent bans |
| `--elf-disguise` | ELF binaries and scripts masquerading as other file types |
| `--perm-anomalies` | Orphaned UIDs, SUID outside standard paths, permission anomalies |
| `--attacker-tools` | Attacker tools in temp dirs, hidden executables, double-extension files |
| `--c2-detection` | C2 implants and beacons: memfd execution, deleted-temp exe, C2 ports, Go implants |
| `--rootkit-cross-check` | Cross-checks `/proc` PID list and listening ports against `ps`/`ss` |
| `--proc-maps` | Anonymous `rwxp` mappings in `/proc/*/maps` (shellcode injection) |
| `--binary-integrity` | SHA-256 hashes of system binaries against a stored baseline |
| `--webserver-config` | nginx, Apache, and PHP config for webshell enablers |
| `--bind-mounts` | Bind mounts and overlay/tmpfs hiding system paths |
| `--ai-artifacts` | Scripts and executables for AI-generation tells |
| `--all` | Runs all checks |

### `system-hardening`

Applies hardening in one shot. Steps that require root say so and exit cleanly if unprivileged.

| Flag | Requires root | What it does |
|---|---|---|
| `--user-permissions` | yes | Locks unused accounts, fixes `/etc/passwd` / `/etc/shadow` / `/etc/sudoers` permissions, deploys `umask 027` |
| `--services` | yes | Enumerates enabled systemd units, disables anything not on the box-type allow-list |
| `--programs` | no | `chmod 750` on compilers (`gcc`, `g++`, `clang`), network tools (`nmap`, `nc`, `curl`, `wget`), package managers |
| `--configs` | no | Hardens `sshd_config`, writes `/etc/sysctl.d/99-defender-hardening.conf`, locks cron to root only |
| `--install-tools` | — | Downloads the team's `nftbuild` firewall script |

### `backups`

| Flag | What it does |
|---|---|
| `--all` | Copies every known config path and writes a SHA-256 manifest |
| `--compare-hashes` | Re-hashes the system and diffs against a previous manifest |
| `--web` | Backs up nginx / Apache / PHP config |
| `--mail` | Backs up Postfix + Dovecot + Roundcube config |
| `--splunk` | Backs up Splunk local config and apps |
| `--users` | Backs up `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, and related files |
| `--ecomm` | Backs up OpenCart + PrestaShop config |
| `--router` | Backs up VyOS router configuration (`/config/config.boot`, scripts, credentials, hash manifest) |
| `--custom <PATH>` | Backs up an arbitrary path with a hash manifest |
| `--restore` | Restores files from a backup directory using its `H@shes.txt` manifest |
| `--save-location <DIR>` | Where to write (or read) the backup. Defaults to `/etc/ccdc-b@ckup-<timestamp>` |

```sh
# At competition start — snapshot the whole system
sudo linux-defender backups --all --save-location /root/baseline

# On VyOS router — snapshot configuration and scripts
sudo linux-defender backups --router --save-location /etc/ccdc-b@ckup-router

# Later — see what Red Team touched
sudo linux-defender backups --compare-hashes --save-location /root/baseline

# Restore from snapshot
sudo linux-defender backups --restore --save-location /root/baseline
```

### `router`

VyOS router hardening, forensic audit, firewall deployment, and NAT restoration grounded in CCDC topology

| Flag | Mode | What it does |
|---|---|---|
| `--audit` | read-only | 14-section forensic audit of VyOS configuration, services, NAT, firewall, and tasks |
| `--diff [BASE]` | read-only | Compares live VyOS state against last captured baseline |
| `--harden` | prompts / commit-confirm | Phase 1: Cleans and deploys DNAT rules 10-14, transit routing, control-plane firewall, quenches hooks |
| `--restore-nat` | prompts / commit-confirm | Restores scored DNAT rules 10-14 and static routes using selected restore strategy |
| `--restore-mode <MODE>` | option | Restore strategy: `baseline` (clean-slate wipe & topology baseline), `detected` (re-apply from Tab 3 scan), or `backup` |
| `--config-source <PATH>` | option | File path to detected JSON (`/etc/linux-defender/vyos/detected_nat_routes.json`) or backup for restore |
| `--rotate-passwords` | prompts | Separately updates `vyos` and Linux `root` passwords; sanitizes `authorized_keys` |
| `--console-lockdown` | prompts | Phase 2: Removes SSH service and drops port 22 (Console-Only Administration) |
| `--confirm` | commit | Persists pending `commit-confirm` configuration permanently |
| `--interactive` | wizard | Interactive configuration wizard |
| `--team <NUM>` | option | CCDC team number (1–20) used to derive WAN subnet `172.31.(20+T).2/29` |
| `--dnat-target <IP>` | option | Target internal host for port forwarding / DNAT (e.g. `172.20.240.10`) |
| `--enable-outbound-pat` | option | Deploys source NAT (rule 100) masquerading internal traffic out WAN interface |
| `--mgmt-subnet <CIDR>` | option | Trusted management subnet (default: `172.17.0.0/24`) |
| `--commit-timeout <MIN>` | option | Rollback timer for `commit-confirm` in minutes (default: 5) |
| `--no-confirm` | dangerous | Commits immediately without `commit-confirm` rollback safety |
| `--force` | dangerous | Bypasses safety checks (e.g. executing console lockdown over SSH) |

```sh
# Run VyOS forensic audit
sudo linux-defender router --audit

# Deploy Phase 1 baseline hardening with 10-minute commit-confirm rollback safety
sudo linux-defender router --harden --team 1 --commit-timeout 10

# Confirm pending configuration after verifying connectivity
sudo linux-defender router --confirm

# Restore NAT and routes from clean-slate baseline grounded in topology
sudo linux-defender router --restore-nat --team 1 --restore-mode baseline

# Restore NAT and routes from detected JSON recorded by Tab 3 scan
sudo linux-defender router --restore-nat --restore-mode detected --config-source /etc/linux-defender/vyos/detected_nat_routes.json
```

### `service-restore`

Reinstalls scored services from scratch when no backup is enough. Uses the host's package manager
for system services; downloads fresh releases from GitHub for web apps.

| Flag | What it does |
|---|---|
| `--postfix` | Reinstalls Postfix via package manager, restarts the service |
| `--dovecot` | Reinstalls Dovecot (splits packages on Debian), restarts the service |
| `--splunk` | Wipes Splunk's local-override layer, restarts the daemon |
| `--opencart` | Downloads a fresh OpenCart release, installs to web root, preserves `config.php` if present |
| `--prestashop` | Downloads a fresh PrestaShop release, installs to web root, preserves `parameters.php` if present |

### `score-check`

Polls all scored ports for the detected box type and displays uptime % and average latency.
Protocol-level checks (SMTP banner, IMAP `* OK`, POP3 `+OK`) go beyond a bare TCP connect.

```sh
linux-defender score-check
```

---

## Persistence test fixtures

`bin/persist/` contains 19 scripts that deploy and clean up real persistence techniques — used to
verify that `anti-persistence` detects each one. `bin/deploy_persistence.sh` is a master script
that prompts for attacker IP/port and deploys any or all of them.

```sh
export ATTACKER_IP=10.0.0.1 ATTACKER_PORT=4444
sudo bin/deploy_persistence.sh         # interactive menu
sudo bin/persist/01_cron.sh deploy     # one at a time
sudo bin/persist/01_cron.sh cleanup
```

Techniques covered: cron user, cron.d, rc.local, at job, SSH key, startup script, XDG autostart,
systemd service, systemd timer, polkit rule, git hook, PROMPT\_COMMAND, shell alias, sudoers drop-in.

---

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features                            # unit + integration (no root needed)
cargo test --all-features -- --ignored               # root-gated tests (filesystem mutation)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Or with `just`:

```sh
just ci          # fmt + clippy + build + test + docs (what CI runs)
just test        # cargo test only
just test-root   # --ignored tests (requires root)
```

### CI workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push / PR | fmt, clippy, build, test, coverage, docs |
| `msrv.yml` | push / PR (code changes) | Builds and tests on MSRV (currently 1.86) |
| `audit.yml` | weekly + dep changes | `cargo audit` against RUSTSEC advisory DB |
| `cargo-deny.yml` | dep changes | License, advisory, source and duplicate policy |
| `codeql.yml` | push / PR / weekly | CodeQL static analysis |
| `typos.yml` | push / PR | Spell check |
| `actionlint.yml` | workflow changes | Lints workflow files (shellcheck included) |
| `commitlint.yml` | push / PR | Conventional Commit message enforcement |
| `docs.yml` | push to `main` | Publishes rustdoc to GitHub Pages |
| `release.yml` | `v*` tag | Builds gnu + musl binaries, attaches to GitHub Release |

Coverage is gated at 60% (currently ~75% lines / ~87% functions). It will never reach 100% —
interactive prompts and root-gated system mutation cannot run in CI.

Enable GitHub Pages (Settings → Pages → source "GitHub Actions") before `docs.yml`'s deploy step.

### Layout

Single crate, library + thin binary. Modules use the sibling-file convention (`backups.rs` +
`backups/`), never `mod.rs`. `tests/` mirrors `src/`.

```
src/                                tests/
├── main.rs                         ├── cli.rs
├── lib.rs                          ├── core.rs
├── core.rs                         ├── anti_persistence.rs
│   └── core/                       ├── backups.rs
│       ├── box_type.rs             ├── monitoring.rs
│       ├── context.rs              ├── router.rs
│       ├── error.rs                ├── system_hardening.rs
│       ├── scan.rs                 └── service_restore.rs
│       └── utils.rs
├── anti_persistence.rs             (one file per technique)
│   └── anti_persistence/
├── backups.rs
│   └── backups/
│       ├── all.rs, compare_hashes.rs, custom.rs
│       ├── ecomm.rs, hash.rs, mail.rs
│       ├── paths.rs, restore.rs, router.rs
│       └── splunk.rs, users.rs
├── monitoring.rs
│   └── monitoring/
│       ├── access_log.rs, auth_log_watch.rs, error_log.rs
│       ├── network_watch.rs, php_modules.rs, pspy.rs
│       └── (20+ other modules)
├── router.rs
│   └── router/
│       └── scan.rs
├── system_hardening.rs
│   └── system_hardening/
│       ├── configs.rs, programs.rs, services.rs, user_perms.rs
├── service_restore.rs
│   └── service_restore/
│       ├── distro.rs, dovecot.rs, opencart.rs
│       ├── postfix.rs, prestashop.rs, splunk.rs, webserver.rs
├── score_check.rs
└── tui/
    ├── app.rs          (main TUI loop, all tab rendering)
    ├── dashboard.rs
    ├── tools_view.rs
    ├── wizards.rs
    └── logs/
```

Every module exposes `run(&DefenderContext, ...) -> core::Result`. Detection logic is a pure
function over `&str` / `&Path`, unit-tested against fixtures; `run()` handles the system
interaction around it — that split keeps coverage high without root.

### Documentation

Every module has a `//!` header explaining the technique or detection method.
`missing_docs` is enabled crate-wide; CI fails on a gap.

```sh
cargo doc --no-deps --open
```

Rustdoc is published automatically to GitHub Pages on push to `main`.
