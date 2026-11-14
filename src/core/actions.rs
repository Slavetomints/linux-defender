//! Execute the remediation actions attached to a [`Finding`].
//!
//! Each [`Action`] variant maps to a concrete system operation. The caller is
//! responsible for confirming with the operator before invoking this.

use std::process::Stdio;

use super::finding::Action;
use super::{DefenderError, Result};

/// Execute `action` and return a short description of what happened.
pub fn execute(action: &Action) -> Result<String> {
    match action {
        Action::Delete(path) => {
            // Same policy as the scan modules: move to quarantine, so a
            // mistaken keypress is one `mv` away from undone.
            super::utils::try_clear_immutable(path);
            let dest = super::context::quarantine(path)?;
            Ok(format!(
                "Moved {} to quarantine ({})",
                path.display(),
                dest.display()
            ))
        }
        Action::RemoveImmutable(path) => {
            let status = std::process::Command::new("chattr")
                .args(["-i", &path.to_string_lossy()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.success() {
                Ok(format!("Removed immutable flag from {}", path.display()))
            } else {
                Err(DefenderError::Command(format!(
                    "chattr -i failed on {}",
                    path.display()
                )))
            }
        }
        Action::RestartService(name) => {
            let status = std::process::Command::new("systemctl")
                .args(["restart", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.success() {
                Ok(format!("Restarted {}", name))
            } else {
                Err(DefenderError::Command(format!(
                    "systemctl restart {} failed",
                    name
                )))
            }
        }
        Action::Manual(desc) => Ok(format!("Manual action required: {}", desc)),
    }
}
