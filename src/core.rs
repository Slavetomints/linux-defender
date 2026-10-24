//! Plumbing shared by every check: per-run state, the error type, and the
//! handful of helpers that would otherwise be copied into each module.

/// Remediation action executor.
pub mod actions;
/// Box-type detection and per-box scored service configuration.
pub mod box_type;
pub mod context;
pub mod error;
/// Structured finding emitted by every check module.
pub mod finding;
pub mod scan;
pub mod utils;

pub use actions::execute as execute_action;
pub use box_type::{BoxType, ServiceConfig, detect_box_type};
pub use context::DefenderContext;
pub use error::{DefenderError, Result};
pub use finding::{Action, Finding, Severity, Verdict};
pub use utils::{
    UserAccount, collect_accounts, collect_users, prompt_string, prompt_string_default,
    prompt_yes, require_root,
};
