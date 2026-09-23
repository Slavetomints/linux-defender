//! CCDC system hardening, anti-persistence, and backup tooling.
//!
//! Built for the Collegiate Cyber Defense Competition, where a small team has
//! to find and evict an attacker from a handful of Linux hosts while keeping
//! scored services running. That shapes every design decision here: findings
//! must be specific enough to act on under time pressure, and nothing
//! destructive happens without the operator saying so.
//!
//! # Layout
//!
//! Four top-level modules, one per subcommand. Each exposes a `CliArgs` struct
//! and a `run(&DefenderContext, &CliArgs) -> core::Result` entry point, so
//! adding a subcommand means adding a module and one match arm in `main`.
//!
//! - [`anti_persistence`] — find and remove attacker footholds
//! - [`backups`] — capture a baseline, then diff against it later
//! - [`monitoring`] — watch logs and network state (not yet implemented)
//! - [`system_hardening`] — proactive hardening (largely not yet implemented)
//!
//! [`core`] holds what they share: the [`DefenderContext`](core::DefenderContext)
//! threaded through every check, the [`DefenderError`](core::DefenderError) they
//! all return, and the detection helpers in [`core::scan`].
//!
//! # Conventions
//!
//! Every check follows the same shape, which is worth knowing before reading
//! any single one:
//!
//! - **Detection is separated from action.** The logic that decides whether
//!   something is suspicious is a pure function over `&str` or `&Path`, unit
//!   tested against fixtures. The `run` function handles the system
//!   interaction around it. This is why the test suite can cover detection
//!   without root and without touching the host.
//! - **Destructive actions prompt.** Anything that deletes, disables, or
//!   rewrites asks `y/N` first, via [`core::prompt_yes`].
//! - **Some checks never act.** PAM, udev, and logrotate are report-only on
//!   purpose: a wrong automated edit there locks the operator out of the box
//!   or breaks hardware, which is worse than the persistence.
//! - **A failing check does not abort the run.** It is reported and the next
//!   one starts, so one unreadable path cannot cost you the whole sweep.
//! - **Specificity over recall.** A check that flags every `curl` in every
//!   dotfile trains an operator to ignore it. Detection aims at the shapes
//!   that are actually hostile — see [`core::scan::SUSPICIOUS_PATTERNS`].
//!
//! # Privileges
//!
//! Checks that modify the system need root and say so rather than half-running.
//! Read-only reporting works unprivileged, which is what makes most of the
//! suite testable in CI.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod anti_persistence;
pub mod backups;
pub mod core;
pub mod monitoring;
pub mod system_hardening;
