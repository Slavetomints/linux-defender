//! Backup of the Splunk forwarder and indexer configuration.
//!
//! Not yet implemented. The paths this would cover are currently swept up by
//! [`super::all`], which backs up every known config path in one pass.

use crate::core::{DefenderContext, Result};

/// Placeholder until this backup is implemented.
pub fn run(_ctx: &DefenderContext) -> Result {
    println!("[!] Not implemented");
    Ok(())
}
