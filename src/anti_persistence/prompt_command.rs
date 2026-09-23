//! A hijacked `$PROMPT_COMMAND`.
//!
//! Bash evaluates `$PROMPT_COMMAND` before drawing each prompt, so an exported
//! value runs again on every command the operator types.

use std::env;

use crate::core::{DefenderContext, Result};

/// Report a hijacked `$PROMPT_COMMAND`.
pub fn run(_ctx: &DefenderContext) -> Result {
    match env::var("PROMPT_COMMAND") {
        Ok(value) if !value.trim().is_empty() => {
            println!("[!] Prompt command is defined as the following:");
            println!("{}", value);
            println!("[!] Please run `unset PROMPT_COMMAND` to fix");
        }
        _ => println!("[✓] No Prompt Command on this system"),
    }

    Ok(())
}
