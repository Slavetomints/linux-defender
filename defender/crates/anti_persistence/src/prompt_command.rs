use std::env;
use defender_core::DefenderContext;

pub fn run(_ctx: &DefenderContext) -> Result<(), String> {
    if let Ok(prompt_command) = env::var("PROMPT_COMMAND") {
        if !prompt_command.trim().is_empty() {
            println!("[!] Prompt command is defined as the following:");
            println!("{}", prompt_command);
            println!("[!] Please run `unset PROMPT_COMMAND` to fix");
        }
    } else {
        println!("[✓] No Prompt Command on this system");
    }

    Ok(())
}
