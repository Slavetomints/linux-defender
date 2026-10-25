//! Per-run state.
//!
//! One [`DefenderContext`] is built in `main` and handed to every check. It
//! carries the report file each check appends to, when the run began, and
//! whether the operator asked for verbose output.
//!
//! When `finding_tx` is set the context is running inside the TUI: calls to
//! [`emit`](DefenderContext::emit) send structured [`Finding`]s to the UI
//! thread rather than printing to stdout.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

use super::Result;
use super::finding::{Finding, Severity};

/// State shared by every check in a single run.
#[derive(Clone)]
pub struct DefenderContext {
    /// File each check appends its result to.
    pub report_file: PathBuf,
    /// When the run began, used for the elapsed-time summary.
    pub start_time: SystemTime,
    /// Whether `--verbose` was passed.
    pub verbose: bool,
    /// When set, emit() sends findings here instead of printing.
    pub finding_tx: Option<Sender<Finding>>,
    /// When the competition started — artifacts created after this time are
    /// flagged as more suspicious.
    pub competition_start: Option<SystemTime>,
}

impl std::fmt::Debug for DefenderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefenderContext")
            .field("report_file", &self.report_file)
            .field("verbose", &self.verbose)
            .field("in_tui", &self.finding_tx.is_some())
            .finish()
    }
}

impl DefenderContext {
    /// Build a context, stamping the start time as now.
    pub fn new(report_file: PathBuf, verbose: bool) -> Self {
        Self {
            report_file,
            start_time: SystemTime::now(),
            verbose,
            finding_tx: None,
            competition_start: None,
        }
    }

    /// Send a structured finding to the TUI, or print it in legacy mode.
    pub fn emit(&self, finding: Finding) {
        if let Some(tx) = &self.finding_tx {
            let _ = tx.send(finding);
        } else {
            println!("[{}] {}", finding.severity.label(), finding.summary);
        }
    }

    /// True when the context is wired to a TUI findings channel.
    pub fn in_tui(&self) -> bool {
        self.finding_tx.is_some()
    }

    /// Emit a plain informational message. In TUI mode this becomes an Info
    /// finding; in legacy mode it prints.
    pub fn log_msg(&self, msg: &str) {
        if self.in_tui() {
            self.emit(Finding::new(Severity::Info, "log", msg, ""));
        } else {
            println!("{}", msg);
        }
    }

    /// Append a line to the run's report file.
    pub fn log(&self, message: &str) -> Result {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.report_file)?;
        writeln!(file, "{}", message)?;
        Ok(())
    }

    /// Print only when running with `--verbose`.
    pub fn debug(&self, message: &str) {
        if self.verbose {
            println!("[debug] {}", message);
        }
    }

    // ── Remediation helpers ───────────────────────────────────────────────────

    /// Read a file and emit its content as an evidence record.
    ///
    /// Text files up to `MAX_EVIDENCE_BYTES` are logged verbatim.  Larger or
    /// binary files get a hex dump of the first 512 bytes plus a SHA-256 hash.
    /// The output goes to both the TUI log pane and the on-disk report file.
    pub fn log_evidence_file(&self, path: &Path) {
        const MAX_EVIDENCE_BYTES: usize = 4096;
        const HEX_DUMP_BYTES: usize = 512;

        let banner = format!("══ EVIDENCE: {} ══", path.display());
        self.log_msg(&banner);
        let _ = self.log(&banner);

        match std::fs::read(path) {
            Err(e) => {
                let msg = format!("  (could not read: {})", e);
                self.log_msg(&msg);
                let _ = self.log(&msg);
            }
            Ok(bytes) => {
                let size_line = format!("  size: {} bytes", bytes.len());
                self.log_msg(&size_line);
                let _ = self.log(&size_line);

                let is_text = bytes
                    .iter()
                    .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (32..=126).contains(&b));

                if is_text {
                    let content =
                        String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_EVIDENCE_BYTES)]);
                    let truncated = bytes.len() > MAX_EVIDENCE_BYTES;
                    if truncated {
                        self.log_msg(&format!("  (truncated at {} bytes)", MAX_EVIDENCE_BYTES));
                    }
                    for line in content.lines() {
                        let l = format!("  | {}", line);
                        self.log_msg(&l);
                        let _ = self.log(&l);
                    }
                } else {
                    let hash = Self::sha256_hex(&bytes);
                    let hash_line = format!("  sha256: {}", hash);
                    self.log_msg(&hash_line);
                    let _ = self.log(&hash_line);

                    let hex_slice = &bytes[..bytes.len().min(HEX_DUMP_BYTES)];
                    let hex: String = hex_slice
                        .iter()
                        .enumerate()
                        .map(|(i, b)| {
                            if i > 0 && i % 16 == 0 {
                                format!("\n  {:04x}  {:02x}", i, b)
                            } else if i == 0 {
                                format!("  {:04x}  {:02x}", i, b)
                            } else {
                                format!(" {:02x}", b)
                            }
                        })
                        .collect();
                    for line in hex.lines() {
                        let _ = self.log(line);
                    }
                    self.log_msg("  (binary: hex dump written to report file)");
                }
            }
        }

        let end = "══ END EVIDENCE ══";
        self.log_msg(end);
        let _ = self.log(end);
    }

    /// Remove a file or directory, verify it is gone, and log both operations.
    ///
    /// Returns `true` when the path is confirmed absent after removal.
    /// Failure messages are logged but do not panic — the module can decide how
    /// to handle a failed removal.
    pub fn remove_path_logged(&self, path: &Path) -> bool {
        let action_banner = format!("══ ACTION: rm {} ══", path.display());
        self.log_msg(&action_banner);
        let _ = self.log(&action_banner);

        let result = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };

        match result {
            Ok(()) => {
                let msg = "  rm: OK";
                self.log_msg(msg);
                let _ = self.log(msg);
            }
            Err(e) => {
                let msg = format!("  rm: FAILED — {}", e);
                self.log_msg(&msg);
                let _ = self.log(&msg);
                // Still check proof below — file might have been gone already.
            }
        }

        // Proof: stat the path to confirm absence.
        let gone = !path.exists();
        let proof_banner = "══ PROOF ══";
        self.log_msg(proof_banner);
        let _ = self.log(proof_banner);

        if gone {
            let msg = format!("  CONFIRMED GONE: {} no longer exists", path.display());
            self.log_msg(&msg);
            let _ = self.log(&msg);
        } else {
            let msg = format!(
                "  WARNING: {} still exists after removal attempt",
                path.display()
            );
            self.log_msg(&msg);
            let _ = self.log(&msg);
        }

        let end = "══ END ACTION ══";
        self.log_msg(end);
        let _ = self.log(end);

        gone
    }

    /// Log a single line as evidence (for inline entries like cron jobs or SSH keys).
    pub fn log_evidence_line(&self, source: &str, line: &str) {
        let msg = format!("  EVIDENCE in {}: {}", source, line);
        self.log_msg(&msg);
        let _ = self.log(&msg);
    }

    /// Remove a specific line from a text file, logging before and after.
    ///
    /// Matches lines that contain `line_content` (substring match, trimmed).
    /// Returns `true` if the line was found and the file was rewritten cleanly.
    pub fn remove_line_from_file_logged(&self, path: &Path, line_content: &str) -> bool {
        let action_msg = format!("══ ACTION: remove line from {} ══", path.display());
        self.log_msg(&action_msg);
        let _ = self.log(&action_msg);
        self.log_msg(&format!("  removing: {}", line_content));
        let _ = self.log(&format!("  removing: {}", line_content));

        let Ok(original) = std::fs::read_to_string(path) else {
            let msg = format!("  FAILED to read {} for line removal", path.display());
            self.log_msg(&msg);
            let _ = self.log(&msg);
            return false;
        };

        let line_count_before = original.lines().count();
        let filtered: Vec<&str> = original
            .lines()
            .filter(|l| !l.trim().contains(line_content.trim()))
            .collect();
        let line_count_after = filtered.len();

        if line_count_before == line_count_after {
            let msg = "  line not found — no change made";
            self.log_msg(msg);
            let _ = self.log(msg);
            return false;
        }

        let new_content = filtered.join("\n") + "\n";
        match std::fs::write(path, new_content) {
            Ok(()) => {
                let msg = format!("  removed {} line(s)", line_count_before - line_count_after);
                self.log_msg(&msg);
                let _ = self.log(&msg);

                // Proof: verify line is absent
                let proof = std::fs::read_to_string(path)
                    .map(|s| !s.contains(line_content.trim()))
                    .unwrap_or(false);
                let proof_msg = format!("══ PROOF: line absent={} in {} ══", proof, path.display());
                self.log_msg(&proof_msg);
                let _ = self.log(&proof_msg);
                proof
            }
            Err(e) => {
                let msg = format!("  FAILED to write {} — {}", path.display(), e);
                self.log_msg(&msg);
                let _ = self.log(&msg);
                false
            }
        }
    }

    /// Run a command for remediation and log its output.
    /// Returns true if the command exited 0.
    pub fn run_remediation(&self, args: &[&str]) -> bool {
        if args.is_empty() {
            return false;
        }

        let action_msg = format!("══ ACTION: {} ══", args.join(" "));
        self.log_msg(&action_msg);
        let _ = self.log(&action_msg);

        match std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
        {
            Err(e) => {
                let msg = format!("  FAILED to run: {}", e);
                self.log_msg(&msg);
                let _ = self.log(&msg);
                false
            }
            Ok(out) => {
                let success = out.status.success();
                let code = out.status.code().unwrap_or(-1);
                let status_msg = format!(
                    "  exit: {} ({})",
                    code,
                    if success { "OK" } else { "FAILED" }
                );
                self.log_msg(&status_msg);
                let _ = self.log(&status_msg);

                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if !line.trim().is_empty() {
                        let l = format!("  stdout: {}", line);
                        self.log_msg(&l);
                        let _ = self.log(&l);
                    }
                }
                for line in String::from_utf8_lossy(&out.stderr).lines() {
                    if !line.trim().is_empty() {
                        let l = format!("  stderr: {}", line);
                        self.log_msg(&l);
                        let _ = self.log(&l);
                    }
                }

                let end = "══ END ACTION ══";
                self.log_msg(end);
                let _ = self.log(end);
                success
            }
        }
    }

    /// Compute a SHA-256 hex string for the given bytes.
    fn sha256_hex(data: &[u8]) -> String {
        // Simple iterative SHA-256 without an external crate.
        // Constants and algorithm from FIPS 180-4.
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Pad message
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
                [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        h.iter().map(|v| format!("{:08x}", v)).collect()
    }

    /// Wall-clock time since the run began.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed().unwrap_or(Duration::ZERO)
    }

    /// Human-readable label for a file's mtime, noting if it falls after the
    /// competition start time (which makes it more suspicious).
    pub fn mtime_label(&self, mtime: SystemTime) -> String {
        let age = mtime.elapsed().unwrap_or_default();
        let mins = age.as_secs() / 60;
        let base = if mins < 60 {
            format!("{}m ago", mins)
        } else {
            format!("{}h {}m ago", mins / 60, mins % 60)
        };
        if let Some(start) = self.competition_start {
            if mtime > start {
                return format!("{} (after competition start — suspicious)", base);
            }
        }
        base
    }
}
