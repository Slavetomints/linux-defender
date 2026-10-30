//! A hijacked `$PROMPT_COMMAND`.
//!
//! Bash evaluates `$PROMPT_COMMAND` before drawing each prompt, so an exported
//! value runs again on every command the operator types.

use std::env;

use crate::core::{Action, DefenderContext, Finding, Result, Severity};

/// Report a hijacked `$PROMPT_COMMAND`.
pub fn run(ctx: &DefenderContext) -> Result {
    match env::var("PROMPT_COMMAND") {
        Ok(value) if !value.trim().is_empty() => {
            if ctx.in_tui() {
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "prompt_command",
                        "PROMPT_COMMAND is set — runs on every shell prompt",
                        format!("Value: {}", value),
                    )
                    .with_action(Action::Manual("unset PROMPT_COMMAND".into())),
                );
            } else {
                println!("[!] Prompt command is defined as the following:");
                println!("{}", value);
                println!("[!] Please run `unset PROMPT_COMMAND` to fix");
            }
        }
        _ => {
            if !ctx.in_tui() {
                println!("[✓] No Prompt Command on this system");
            }
        }
    }

    Ok(())
}
