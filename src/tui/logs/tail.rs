use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::core::strip_ansi;

/// Spawn a background thread that tails `path` and sends each new line to `tx`.
/// If `preserve_path` is Some, each line is also appended there.
pub fn spawn_tail(path: impl Into<PathBuf>, tx: Sender<String>, preserve_path: Option<PathBuf>) {
    let path = path.into();
    std::thread::Builder::new()
        .name(format!("tail:{}", path.display()))
        .spawn(move || tail_loop(&path, tx, preserve_path))
        .ok();
}

/// Background loop that reads new lines from `path` and sends them over `tx`.
fn tail_loop(path: &Path, tx: Sender<String>, preserve_path: Option<PathBuf>) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    if file.seek(SeekFrom::End(0)).is_err() {
        return;
    }
    let mut reader = BufReader::new(file);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(200));
                // detect log rotation: if our position is beyond current file size, reopen
                if let Ok(pos) = reader.stream_position()
                    && let Ok(meta) = std::fs::metadata(path)
                    && pos > meta.len()
                    && let Ok(f) = File::open(path)
                {
                    reader = BufReader::new(f);
                }
            }
            Ok(_) => {
                let trimmed = strip_ansi(line.trim_end());
                if let Some(pp) = &preserve_path
                    && let Ok(mut pf) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(pp)
                {
                    let _ = writeln!(pf, "{}", trimmed);
                }
                if tx.send(trimmed).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
