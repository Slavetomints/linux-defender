//! AI-generated script detection.
//!
//! Red teams use LLMs to write malware, persistence scripts, and C2 implants.
//! AI assistants leave consistent typographic and stylistic tells that human
//! shell authors never produce.  Five checks:
//!
//! 1. Em/en dash (`—` U+2014, `–` U+2013) — appears in AI comments/strings,
//!    never in hand-typed shell scripts.
//! 2. Curly/smart quotes (`'` `'` `"` `"`) — copy-pasted from AI output.
//! 3. AI comment patterns (`# Note:`, `# This script`, etc.) — ≥2 matches.
//! 4. Over-long comment lines — ≥3 comment lines longer than 120 chars.
//! 5. Base64-blob files — >85 % of non-whitespace bytes are base64 alphabet.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use walkdir::WalkDir;

use crate::core::{DefenderContext, Finding, Result, Severity, Verdict};

const MAX_FILE_BYTES: u64 = 512 * 1024; // 512 KB

const SCAN_ROOTS: &[&str] = &[
    "/etc",
    "/opt",
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/shm",
    "/var/www",
    "/home",
    "/root",
    "/usr/local/bin",
    "/usr/local/sbin",
];

// UTF-8 byte sequences for typographic characters AI tools emit.
const EM_DASH: &[u8]      = &[0xE2, 0x80, 0x94]; // — U+2014
const EN_DASH: &[u8]      = &[0xE2, 0x80, 0x93]; // – U+2013
const LSQUO:   &[u8]      = &[0xE2, 0x80, 0x98]; // ' U+2018
const RSQUO:   &[u8]      = &[0xE2, 0x80, 0x99]; // ' U+2019
const LDQUO:   &[u8]      = &[0xE2, 0x80, 0x9C]; // " U+201C
const RDQUO:   &[u8]      = &[0xE2, 0x80, 0x9D]; // " U+201D

const AI_COMMENT_PATTERNS: &[&str] = &[
    "# Note:",
    "# Note that",
    "# This script",
    "# This function",
    "# Make sure",
    "# Please note",
    "# Remember to",
    "# Don't forget",
    "# don't forget",
];

const LONG_COMMENT_THRESHOLD: usize = 120;
const LONG_COMMENT_MIN_COUNT: usize = 3;
const AI_PATTERN_MIN_MATCHES: usize = 2;
const BASE64_RATIO_THRESHOLD: f64 = 0.85;

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run(ctx: &DefenderContext) -> Result {
    ctx.log_msg("[+] Scanning for AI-generated scripts and artifacts...");

    let mut findings = 0usize;

    for root in SCAN_ROOTS {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }

        for entry in WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            let path = entry.path();

            // Skip files over the size limit.
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }

            let mode = meta.permissions().mode();
            let is_executable = mode & 0o111 != 0;

            // Decide whether this file is worth scanning.
            let is_script_ext = has_script_extension(path);
            let Ok(bytes) = std::fs::read(path) else { continue };
            let has_shebang = bytes.starts_with(b"#!");
            let text_like = is_text_like(&bytes);

            // Check 5 (base64 blob): scan any file regardless of type.
            if is_base64_blob(&bytes) {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "ai_artifacts",
                        format!("Base64-blob file: {}", path.display()),
                        format!(
                            "path: {}\nsize: {} bytes\n>85% of content is base64 alphabet — \
                             likely a staged payload or obfuscated script.",
                            path.display(), bytes.len()
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("size", bytes.len().to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        "This file is almost entirely base64 alphabet. It is likely a \
                         staged payload awaiting decode-and-execute, or an obfuscated \
                         script. Decode it (base64 -d) and inspect the result.",
                    ),
                );
            }

            // Checks 1 & 2 apply to executables and text files.
            if !text_like && !is_executable {
                continue;
            }
            if !is_script_ext && !has_shebang && !is_executable {
                continue;
            }

            // Check 1: em/en dash.
            if contains_sequence(&bytes, EM_DASH) || contains_sequence(&bytes, EN_DASH) {
                let which = if contains_sequence(&bytes, EM_DASH) { "em dash (—)" } else { "en dash (–)" };
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "ai_artifacts",
                        format!("AI typographic tell ({}) in {}", which, path.display()),
                        format!(
                            "path: {}\ntell: {}\nEm/en dashes never appear in hand-typed \
                             shell scripts — strong indicator of AI-generated content.",
                            path.display(), which
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("tell", which)
                    .with_verdict(
                        Verdict::Investigate,
                        "Em and en dashes in shell scripts are a reliable AI authorship \
                         signal — no human types these at a terminal. Inspect this file \
                         for malicious content and compare against expected files.",
                    ),
                );
            }

            // Check 2: curly/smart quotes.
            let has_curly = contains_sequence(&bytes, LSQUO)
                || contains_sequence(&bytes, RSQUO)
                || contains_sequence(&bytes, LDQUO)
                || contains_sequence(&bytes, RDQUO);
            if has_curly {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::High,
                        "ai_artifacts",
                        format!("Smart/curly quotes in {}", path.display()),
                        format!(
                            "path: {}\nSmart quotes (\u{2018}\u{2019}\u{201C}\u{201D}) in a \
                             script strongly indicate AI-generated content copy-pasted \
                             from a chat interface.",
                            path.display()
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("tell", "curly/smart quotes")
                    .with_verdict(
                        Verdict::Investigate,
                        "Curly quotes break shell syntax — this file likely fails to \
                         execute as-is, but the intent is malicious. Inspect it for \
                         persistence or C2 logic.",
                    ),
                );
            }

            // Checks 3 & 4 require the file to be valid text.
            if !text_like {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&bytes) else { continue };

            // Check 3: AI comment patterns.
            let matched_ai_patterns = count_ai_patterns(text);
            if matched_ai_patterns >= AI_PATTERN_MIN_MATCHES {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Medium,
                        "ai_artifacts",
                        format!(
                            "AI comment style ({} patterns) in {}",
                            matched_ai_patterns,
                            path.display()
                        ),
                        format!(
                            "path: {}\nmatched AI comment patterns: {}\nPatterns like \
                             '# Note:', '# This script', '# Make sure' are characteristic \
                             of LLM-generated code.",
                            path.display(), matched_ai_patterns
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("ai pattern count", matched_ai_patterns.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        "Multiple AI-characteristic comment phrases found. \
                         While not conclusive alone, combined with other signals this \
                         suggests the script was AI-generated. Review for malicious logic.",
                    ),
                );
            }

            // Check 4: over-long comment lines.
            let long_comment_count = count_long_comments(text);
            if long_comment_count >= LONG_COMMENT_MIN_COUNT {
                findings += 1;
                ctx.emit(
                    Finding::new(
                        Severity::Medium,
                        "ai_artifacts",
                        format!(
                            "AI verbose comments ({} long lines) in {}",
                            long_comment_count,
                            path.display()
                        ),
                        format!(
                            "path: {}\ncomment lines >120 chars: {}\nAI models write \
                             long explanatory comments; human shell authors write terse ones.",
                            path.display(), long_comment_count
                        ),
                    )
                    .with_path(path.to_path_buf())
                    .with_context("path", path.display().to_string())
                    .with_context("long comment lines", long_comment_count.to_string())
                    .with_verdict(
                        Verdict::Investigate,
                        "Unusually long comment lines are a secondary AI authorship signal. \
                         Review the script for malicious logic hidden in otherwise \
                         plausible-looking code.",
                    ),
                );
            }
        }
    }

    ctx.log_msg(&format!(
        "[✓] AI artifact scan complete — {} suspicious file{}",
        findings,
        if findings == 1 { "" } else { "s" },
    ));
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn has_script_extension(path: &Path) -> bool {
    path.extension()
        .map(|e| matches!(
            e.to_string_lossy().to_lowercase().as_str(),
            "sh" | "bash" | "py" | "pl" | "rb" | "zsh" | "fish"
        ))
        .unwrap_or(false)
}

/// Returns true if the byte slice looks like text.
///
/// A file is "text-like" when fewer than 5% of its first 512 bytes are
/// control/binary bytes.  Any byte ≥ 0x80 is a valid UTF-8 leading or
/// continuation byte and is *not* counted as binary — this lets files
/// containing em dashes, smart quotes, and other multi-byte sequences pass.
fn is_text_like(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(512)];
    let non_text = sample.iter().filter(|&&b| {
        b < 0x80 && b != b'\t' && b != b'\n' && b != b'\r' && !(0x20..=0x7E).contains(&b)
    }).count();
    non_text * 20 <= sample.len()
}

/// True if the byte slice contains `needle` as a contiguous subsequence.
fn contains_sequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Count distinct AI comment pattern strings matched (each counted once).
fn count_ai_patterns(text: &str) -> usize {
    AI_COMMENT_PATTERNS
        .iter()
        .filter(|&&pat| text.contains(pat))
        .count()
}

/// Count comment lines (trimmed, starts with `#`) longer than the threshold.
fn count_long_comments(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            t.starts_with('#') && t.len() > LONG_COMMENT_THRESHOLD
        })
        .count()
}

/// True if >85% of non-whitespace bytes are in the base64 alphabet.
fn is_base64_blob(bytes: &[u8]) -> bool {
    let non_ws: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|&b| b != b' ' && b != b'\n' && b != b'\r' && b != b'\t')
        .collect();

    if non_ws.len() < 64 {
        // Too short to be meaningful.
        return false;
    }

    let b64_count = non_ws
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .count();

    b64_count as f64 / non_ws.len() as f64 > BASE64_RATIO_THRESHOLD
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_em_dash() {
        // "# This is a test — value" contains an em dash.
        let bytes: Vec<u8> = b"#!/bin/bash\n# This is a test ".iter()
            .chain(EM_DASH)
            .chain(b" value\necho hi\n")
            .copied()
            .collect();
        assert!(contains_sequence(&bytes, EM_DASH));
        assert!(!contains_sequence(&bytes, EN_DASH));
    }

    #[test]
    fn detects_en_dash() {
        let bytes: Vec<u8> = b"#!/bin/sh\n# range 1 ".iter()
            .chain(EN_DASH)
            .chain(b" 10\n")
            .copied()
            .collect();
        assert!(contains_sequence(&bytes, EN_DASH));
    }

    #[test]
    fn detects_smart_quotes() {
        // Right single quotation mark (U+2019)
        let bytes: Vec<u8> = b"#!/bin/bash\n# don".iter()
            .chain(RSQUO)
            .chain(b"t forget\n")
            .copied()
            .collect();
        assert!(contains_sequence(&bytes, RSQUO));

        // Left double quotation mark (U+201C)
        let bytes2: Vec<u8> = b"echo ".iter()
            .chain(LDQUO)
            .chain(b"hello")
            .chain(RDQUO)
            .chain(b"\n")
            .copied()
            .collect();
        assert!(contains_sequence(&bytes2, LDQUO));
        assert!(contains_sequence(&bytes2, RDQUO));
    }

    #[test]
    fn base64_blob_detected_above_threshold() {
        // Pure base64 string.
        let b64 = b"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA==\n".repeat(4);
        assert!(is_base64_blob(&b64));
    }

    #[test]
    fn base64_blob_not_triggered_below_threshold() {
        // Normal shell script — nowhere near 85% base64.
        let script = b"#!/bin/bash\nset -euo pipefail\necho \"Starting backup...\"\n\
                       for f in /etc/*.conf; do\n  cp \"$f\" /backup/\ndone\n";
        assert!(!is_base64_blob(script));
    }

    #[test]
    fn base64_blob_too_short_not_flagged() {
        // Under 64 non-ws bytes.
        let short = b"YWJj";
        assert!(!is_base64_blob(short));
    }

    #[test]
    fn clean_script_scores_nothing() {
        let script = "#!/bin/bash\n# backup configs\nset -e\ncp /etc/nginx/nginx.conf /backup/\n";
        assert_eq!(count_ai_patterns(script), 0);
        assert_eq!(count_long_comments(script), 0);
        assert!(!contains_sequence(script.as_bytes(), EM_DASH));
        assert!(!contains_sequence(script.as_bytes(), EN_DASH));
        assert!(!contains_sequence(script.as_bytes(), RSQUO));
        assert!(!is_base64_blob(script.as_bytes()));
    }

    #[test]
    fn ai_comment_patterns_counted_correctly() {
        let script = "#!/bin/bash\n# Note: this sets up the env\n# Make sure you run as root\n\
                      # This script configures nginx\necho done\n";
        assert_eq!(count_ai_patterns(script), 3);
    }

    #[test]
    fn long_comment_threshold() {
        let long_line = format!("# {}\n", "x".repeat(130));
        let script = long_line.repeat(4);
        assert!(count_long_comments(&script) >= LONG_COMMENT_MIN_COUNT);
    }

    #[test]
    fn short_comment_not_flagged() {
        let script = "# short\n# also short\n# brief\n";
        assert_eq!(count_long_comments(script), 0);
    }

    #[test]
    fn text_like_accepts_utf8_em_dash() {
        // A script containing an em dash should still be treated as text-like.
        let bytes: Vec<u8> = b"#!/bin/bash\n# test ".iter()
            .chain(EM_DASH)
            .chain(b" end\n")
            .copied()
            .collect();
        assert!(is_text_like(&bytes));
    }

    #[test]
    fn elf_magic_is_not_text_like() {
        let elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(!is_text_like(elf));
    }
}
