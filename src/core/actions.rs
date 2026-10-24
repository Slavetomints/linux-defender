//! Execute the remediation actions attached to a [`Finding`].
//!
//! Each [`Action`] variant maps to a concrete system operation. The caller is
//! responsible for confirming with the operator before invoking this.

use super::finding::Action;
use super::{DefenderError, Result};

/// Execute `action` and return a short description of what happened.
pub fn execute(action: &Action) -> Result<String> {
    match action {
        Action::Delete(path) => {
            std::fs::remove_file(path)?;
            Ok(format!("Deleted {}", path.display()))
        }
        Action::RemoveImmutable(path) => {
            let status = std::process::Command::new("chattr")
                .args(["-i", &path.to_string_lossy()])
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
