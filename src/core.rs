//! Plumbing shared by every check: per-run state, the error type, and the
//! handful of helpers that would otherwise be copied into each module.

pub mod context;
pub mod error;
pub mod scan;
pub mod utils;

pub use context::DefenderContext;
pub use error::{DefenderError, Result};
pub use utils::{UserAccount, collect_accounts, collect_users, prompt_yes, require_root};
