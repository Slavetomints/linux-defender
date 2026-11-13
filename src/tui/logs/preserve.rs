use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Local;

/// Root directory under which snapshots and live log copies are stored.
const BASE: &str = "/etc/linux-defender/logs";

pub struct PreserveConfig {
    pub snapshot_dir: PathBuf,
    pub live_dir: PathBuf,
}

impl PreserveConfig {
    pub fn live_path_for(&self, source_path: &str) -> PathBuf {
        let name = Path::new(source_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "log".to_string());
        self.live_dir.join(name)
    }
}

/// Create the preservation directory, snapshot existing logs, and lock the
/// live directory append-only so an attacker cannot truncate our copies.
///
/// Silently skips operations that fail (e.g. insufficient permissions) — the
/// tool is still usable without root, it just cannot protect the log copies.
pub fn setup(sources: &[&str]) -> PreserveConfig {
    let ts = Local::now().format("%Y-%m-%dT%H-%M-%S").to_string();
    let snapshot_dir = PathBuf::from(BASE).join("snapshots").join(&ts);
    let live_dir = PathBuf::from(BASE).join("live");

    let _ = fs::create_dir_all(&snapshot_dir);
    let _ = fs::create_dir_all(&live_dir);

    for src in sources {
        let p = Path::new(src);
        if p.exists()
            && let Some(name) = p.file_name()
        {
            let _ = fs::copy(p, snapshot_dir.join(name));
        }
    }

    for src in sources {
        if let Some(name) = Path::new(src).file_name() {
            let live = live_dir.join(name);
            let _ = fs::OpenOptions::new().create(true).append(true).open(&live);
            // chattr +a — append-only; even root cannot truncate
            let _ = Command::new("chattr")
                .args(["+a", &live.to_string_lossy()])
                .status();
        }
    }
    let _ = Command::new("chattr")
        .args(["+a", &live_dir.to_string_lossy()])
        .status();

    PreserveConfig {
        snapshot_dir,
        live_dir,
    }
}
