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

/// Whether the tailed file was rotated: truncated in place (copytruncate),
/// or renamed away with a new file created at `path` (logrotate's default),
/// which leaves our descriptor on the old inode forever.
fn needs_reopen(reader: &mut BufReader<File>, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(on_disk) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(open) = reader.get_ref().metadata() else {
        return true;
    };
    if open.ino() != on_disk.ino() || open.dev() != on_disk.dev() {
        return true;
    }
    reader
        .stream_position()
        .is_ok_and(|pos| pos > on_disk.len())
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
        // Bytes, not read_line: one invalid UTF-8 byte (binary junk, a
        // Latin-1 username) made read_line fail and ended the tail for good.
        let mut raw = Vec::new();
        match reader.read_until(b'\n', &mut raw) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(200));
                if needs_reopen(&mut reader, path)
                    && let Ok(f) = File::open(path)
                {
                    reader = BufReader::new(f);
                }
            }
            Ok(_) => {
                let line = String::from_utf8_lossy(&raw);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    fn recv_until(rx: &mpsc::Receiver<String>, want: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(line) = rx.recv_timeout(Duration::from_millis(100))
                && line.contains(want)
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn survives_invalid_utf8_and_rename_rotation() {
        let dir = tempfile::TempDir::new().unwrap();
        let log = dir.path().join("auth.log");
        std::fs::write(&log, "old\n").unwrap();
        let (tx, rx) = mpsc::channel();
        spawn_tail(&log, tx, None);
        std::thread::sleep(Duration::from_millis(300));

        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(b"bad \xff byte\nafter bad\n").unwrap();
        assert!(recv_until(&rx, "after bad"), "tail died on invalid UTF-8");

        // logrotate default: rename away, create a fresh file.
        std::fs::rename(&log, dir.path().join("auth.log.1")).unwrap();
        std::fs::write(&log, "after rotation\n").unwrap();
        assert!(
            recv_until(&rx, "after rotation"),
            "tail missed the rotated file"
        );
    }
}
