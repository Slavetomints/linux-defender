//! A hijacked `$PROMPT_COMMAND`.
//!
//! Bash evaluates `$PROMPT_COMMAND` before drawing each prompt, so an exported
//! value runs again on every command the operator types.

use crate::core::scan::report_variable;
use crate::core::{DefenderContext, Result};

/// Report a hijacked `$PROMPT_COMMAND`.
///
/// The defender's own environment is no evidence either way: sudo scrubs it.
/// So this looks where the value would come from (shell startup files) and
/// where it is live (the environment of running processes).
pub fn run(ctx: &DefenderContext) -> Result {
    let found = report_variable(
        ctx,
        "prompt_command",
        "PROMPT_COMMAND",
        "Bash runs PROMPT_COMMAND before every prompt, so a hijacked value \
         re-executes on every command typed.",
    );
    if found == 0 {
        ctx.log_msg("[✓] PROMPT_COMMAND is not set in startup files or running processes");
    }
    Ok(())
}
