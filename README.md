# linux-defender

System hardening tool for CCDC environments. Focuses on anti-persistence, monitoring, system
hardening, and effective backups. Ships as a full-screen TUI and a traditional CLI.

## Requirements

- Linux
- Rust (stable — see `rust-toolchain.toml`)
- Checks that modify the system require **root**; modules that need root say so and exit rather
  than half-run.

## Build

```sh
cargo build --release
# binary at target/release/defender-cli
```

For a static binary with no shared library dependencies — useful when dropping the tool onto an
unknown competition host:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Tagged pushes (`v*`) build both targets and attach them to a GitHub Release automatically.

## Usage

```
defender-cli [--verbose] <COMMAND> [FLAGS]
```

Every run appends to `defender-report-<timestamp>.txt` in the working directory.

Running without a subcommand launches the **interactive TUI**, which runs all 47 scan modules in
the background and displays findings in real time.

### `anti-persistence`

Hunts for Red Team persistence. Every destructive action prompts for `y/N` first.

| Flag | Acts? | What it does |
|---|---|---|
| `--cron` | prompts | Reviews each user's crontab entry by entry, rewrites with only the kept lines |
| `--cron-system` | prompts | Checks `/etc/cron.d` and periodic script directories for malicious jobs |
| `--systemd` | prompts | Walks all systemd units, stops + disables ones you flag |
| `--systemd-timers` | prompts | Scans systemd timer units for suspicious short-interval or malicious ExecStart |
| `--users` | prompts | Reviews every account in `/etc/passwd`, `userdel`s ones you flag |
| `--ssh-keys` | prompts | Finds `authorized_keys` per account, removes on confirmation |
| `--at-jobs` | prompts | Reviews `atq` jobs, `atrm`s ones you flag |
| `--php-shells` | prompts | Scores files under `/var/www/html` against webshell primitives |
| `--ld-preload` | prompts | Checks `/etc/ld.so.preload` and `$LD_PRELOAD` for loader hijacking |
| `--rc-local` | prompts | Reports boot commands in `rc.local`, offers to blank them |
| `--xdg-autostart` | prompts | Lists autostart `.desktop` entries, offers to remove flagged ones |
| `--immutable` | prompts | Detects immutable/append-only flags on sensitive files |
| `--ssh-config` | reports | Audits `sshd_config` for dangerous directives (ForceCommand, AuthorizedKeysCommand, etc.) |
| `--sudoers` | reports | Audits `/etc/sudoers` and `sudoers.d` for NOPASSWD, LD_PRELOAD, and wildcard rules |
| `--shell-aliases` | reports | Detects malicious shell aliases in global and per-user dotfiles |
| `--polkit` | reports | Audits polkit rules and pkla files for unconditional privilege grants |
| `--pam` | reports | Finds PAM directives shaped like an auth backdoor |
| `--startup-scripts` | reports | Scans system and per-user shell dotfiles for dangerous lines |
| `--udev` | reports | Finds admin-managed udev rules that execute a program |
| `--logrotate` | reports | Finds logrotate script blocks, which run as root on a timer |
| `--grub` | reports | Checks kernel parameters and `/etc/grub.d` scripts |
| `--kernel-modules` | reports | Loaded modules with no file on disk, plus boot-load config |
| `--initramfs` | reports | Custom initramfs hooks, and images newer than their kernel |
| `--capabilities` | reports | Files carrying dangerous Linux capabilities (slow: sweeps `/`) |
| `--suid` | reports | Lists SUID binaries (slow: sweeps `/`) |
| `--prompt-command` | reports | Reports a hijacked `$PROMPT_COMMAND` |
| `--all` | — | Runs every check |

"prompts" means the check can change the system, and always asks `y/N` first. "reports" means
it is strictly read-only — for PAM, udev and logrotate that is deliberate, since a wrong
automated edit there locks you out or breaks devices.

Checks that modify the system need root. Read-only reporting works unprivileged, and a check
that needs root without having it says so and is skipped rather than half-run. A module that
fails is reported and the run continues to the next one.

Detection is tuned to be specific rather than exhaustive: flagging every `curl` in every dotfile
would bury a real finding. For example `--pam` flags `sufficient pam_permit.so` (an actual
bypass) but not the `optional pam_permit.so` that ships in stock Arch and Debian stacks.

### `monitoring`

Scans the live system for attacker activity and anomalies.

| Flag | What it does |
|---|---|
| `--auth-log-analysis` | Parses `auth.log` / `secure` for brute-force and credential-stuffing |
| `--port-map` | Maps listening TCP ports to their owning binaries |
| `--hidden-elf` | Finds hidden ELF binaries in web roots and temp directories |
| `--deleted-binaries` | Finds processes whose on-disk executable has been deleted |
| `--process-tree` | Detects parent→child anomalies (web server spawning a shell, etc.) |
| `--recently-modified` | Finds system binaries modified after competition start (or last hour) |
| `--suspicious-services` | Detects systemd units with suspicious ExecStart paths |
| `--world-writable` | Finds world-writable directories and files outside expected locations |
| `--outbound-connections` | Detects established TCP connections from service accounts to unexpected ports |
| `--fail2ban` | Checks fail2ban daemon, active jails, and recent bans |
| `--ai-artifacts` | Scans scripts and executables for AI-generation tells |
| `--elf-disguise` | Detects ELF binaries and scripts masquerading as other file types |
| `--perm-anomalies` | Detects permission/ownership anomalies: orphaned UIDs, SUID outside standard paths, etc. |
| `--attacker-tools` | Detects attacker tools in temp dirs, hidden executables, double-extension files |
| `--c2-detection` | Detects C2 implants and beacons (memfd execution, deleted-temp exe, C2 ports, Go implants) |
| `--rootkit-cross-check` | Cross-checks `/proc` PID list and listening ports against `ps`/`ss` for rootkit evidence |
| `--proc-maps` | Scans `/proc/*/maps` for anonymous `rwxp` mappings (shellcode injection) |
| `--binary-integrity` | Verifies SHA-256 hashes of system binaries against a stored baseline |
| `--git-hooks` | Scans git repositories for malicious hook scripts |
| `--webserver-config` | Audits nginx, Apache, and PHP config for webshell enablers |
| `--bind-mounts` | Detects bind mounts and overlay/tmpfs hiding system paths |
| `--all` | Runs all checks |

### `backups`

| Flag | Status | What it does |
|---|---|---|
| `--all` | working | Copies every known config path and writes a SHA-256 manifest |
| `--compare-hashes` | working | Re-hashes the system and diffs against a previous manifest |
| `--save-location <DIR>` | — | Where to write (or read) the backup. Defaults to `/etc/ccdc-b@ckup-<timestamp>` |
| `--custom` `--ecomm` `--mail` `--restore` `--splunk` `--users` | stub | Not yet implemented |

A backup directory contains `H@shes.txt` (the manifest), `backup.log` (per-path detail), and one
`.bak` copy per source path.

```sh
# At competition start
defender-cli backups --all --save-location /root/baseline

# Later, to see what Red Team touched
defender-cli backups --compare-hashes --save-location /root/baseline
```

An unreadable path is logged and skipped — one bad file does not abort the run.

### `system-hardening`

`--install-tools` downloads the team's `nftbuild` firewall script. The remaining flags
(`--user-permissions`, `--services`, `--programs`, `--configs`) are stubs.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --all-features -- --ignored   # the SUID scan; walks the whole filesystem
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) and are
linted in CI — see `commitlint.config.mjs` for the accepted scopes.

### What runs in CI

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push / PR | fmt, clippy, build, test, coverage, docs — as parallel jobs |
| `msrv.yml` | push / PR touching code | Builds and tests on the MSRV in `Cargo.toml` (currently 1.86) |
| `audit.yml` | weekly + dependency changes | `cargo audit` against the RUSTSEC advisory database |
| `cargo-deny.yml` | dependency changes | License, advisory, source and duplicate policy (`deny.toml`) |
| `codeql.yml` | push / PR / weekly | CodeQL static analysis |
| `typos.yml` | push / PR | Spell check |
| `actionlint.yml` | workflow changes | Lints these workflow files, shellcheck included |
| `commitlint.yml` | push / PR | Conventional Commit messages |
| `docs.yml` | push to `main` | Publishes rustdoc to GitHub Pages |
| `release.yml` | `v*` tag | Builds gnu + static musl binaries, attaches to a Release |

Coverage is gated at 60% lines and functions; it currently sits at roughly 75% / 87%, so there is
headroom to raise the floor in `ci.yml`. It will never reach 100%: interactive prompts and
root-gated system mutation cannot run in CI.

`docs.yml` needs GitHub Pages enabled on the repository (Settings → Pages → source "GitHub
Actions") before its deploy step will succeed.

### Layout

Single crate, built as a library plus a thin binary so the logic is reachable from integration
tests. Modules use the sibling-file convention (`backups.rs` + `backups/`), not `mod.rs`.

`tests/` mirrors `src/`, so it is always clear which source module a test covers.

```
src/                                tests/
├── main.rs                         ├── cli.rs          drives the built binary
├── lib.rs                          │
├── core.rs                         ├── core.rs
│   └── core/                       │   └── core/
│       ├── context.rs              │       ├── context.rs
│       ├── error.rs                │       ├── scan.rs
│       ├── scan.rs                 │       └── utils.rs
│       └── utils.rs                │
├── anti_persistence.rs             ├── anti_persistence.rs
│   └── anti_persistence/           │   └── anti_persistence/
│       ├── cron.rs                 │       └── php_shells.rs
│       ├── cron_system.rs          │
│       ├── php_shells.rs           │
│       ├── polkit.rs               │
│       ├── shell_aliases.rs        │
│       ├── ssh_config.rs           │
│       ├── sudoers.rs              │
│       ├── systemd_timers.rs       │
│       └── ... one per check       │
├── backups.rs                      ├── backups.rs
│   └── backups/                    │   └── backups/
│       ├── all.rs                  │       ├── all.rs
│       ├── compare_hashes.rs       │       ├── compare_hashes.rs
│       ├── hash.rs                 │       ├── hash.rs
│       └── paths.rs                │
├── monitoring.rs                   └── common.rs       shared fixture helpers
│   └── monitoring/
│       ├── binary_integrity.rs
│       ├── bind_mounts.rs
│       ├── c2_detection.rs
│       ├── git_hooks.rs
│       ├── proc_maps.rs
│       ├── rootkit_cross_check.rs
│       ├── webserver_config.rs
│       └── ... one per check
└── system_hardening.rs
    └── system_hardening/
```

Each top-level file under `tests/` is one test binary, declared explicitly in `Cargo.toml`
(`autotests = false`) so `common.rs` stays a shared helper instead of becoming an empty target.
Submodules use `#[path]` attributes because a test crate root resolves `mod` against `tests/`
rather than its own subdirectory.

Every module exposes `run(&DefenderContext, ...) -> core::Result`. Errors use `DefenderError`
(`src/core/error.rs`); `main` surfaces them through `anyhow`.

Each check separates detection from action: the logic deciding whether something is suspicious is
a pure function over `&str` or `&Path`, unit tested against fixtures, while `run` handles the
system interaction around it. That split is why the suite covers detection without root.

### Documentation

Every public module carries a `//!` header explaining the persistence vector or detection
technique it covers and why it matters — start there rather than with the code.
`missing_docs` is enabled crate-wide, so every public item is documented and CI fails on a gap.

```sh
cargo doc --no-deps --open
```

Published automatically to GitHub Pages on push to `main`.

Code that walks the filesystem takes its paths as a parameter (`backups::all::run_with_paths`,
`backups::hash::compute`, `php_shells::find_shells`) so tests can point it at a fixture tree
instead of the real system.
