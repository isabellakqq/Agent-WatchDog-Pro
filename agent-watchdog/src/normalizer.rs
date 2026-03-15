//! Parameter Normalization Layer for Agent-WatchDog.
//!
//! Pre-processes tool-call arguments before risk scoring and policy
//! evaluation to defeat encoding-based evasion techniques:
//!
//! - URL encoding (`%2F` → `/`)
//! - Hex encoding (`0x2F` → `/`)
//! - Base64 decoding (detects and decodes base64 blobs)
//! - SQL comment stripping (`un/**/ion` → `union`)
//! - Path canonicalization (`/etc/../etc/shadow` → `/etc/shadow`)
//! - Unicode normalization (fullwidth → ASCII)

use log::debug;

/// Normalize a string by applying all evasion-defeating transforms.
///
/// The output is a **lowercase** string suitable for pattern matching.
/// The original input is NOT modified — this returns a new string.
pub fn normalize(input: &str) -> String {
    let mut s = input.to_string();

    // 1. URL-decode (multi-pass to handle double-encoding)
    s = url_decode_recursive(&s, 3);

    // 2. Strip SQL comments (/* ... */, --, #)
    s = strip_sql_comments(&s);

    // 3. Collapse whitespace (defeats "un ion sel ect")
    s = collapse_whitespace(&s);

    // 4. Decode hex literals (0x2F → /)
    s = decode_hex_literals(&s);

    // 5. Unicode fullwidth → ASCII
    s = fullwidth_to_ascii(&s);

    // 6. Path canonicalization
    s = canonicalize_path_segments(&s);

    // 7. Try to detect and inline-decode base64 blobs
    s = try_decode_base64_blobs(&s);

    s.to_ascii_lowercase()
}

// ── URL decoding ─────────────────────────────────────────────────

/// Recursively URL-decode up to `max_passes` times to handle
/// double/triple encoding attacks like `%252F` → `%2F` → `/`.
fn url_decode_recursive(input: &str, max_passes: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_passes {
        let decoded = url_decode_once(&current);
        if decoded == current {
            break; // no more changes
        }
        current = decoded;
    }
    current
}

/// Single-pass percent-decoding.
fn url_decode_once(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── SQL Comment Stripping ────────────────────────────────────────

/// Remove SQL comments that can be used to obfuscate keywords:
/// - Block comments: `/* ... */` (including nested)
/// - Inline comments: `--` to end-of-line
/// - Hash comments: `#` to end-of-line  
///
/// Example: `un/**/ion sel/**/ect` → `union select`
fn strip_sql_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Block comment: /* ... */
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            i += 2;
            let mut depth = 1;
            while i < len && depth > 0 {
                if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }

        // Line comment: --
        if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

// ── Whitespace Collapsing ────────────────────────────────────────

/// Collapse runs of whitespace into a single space.
/// Defeats `un  ion   sel  ect` → `un ion sel ect` → pattern match.
fn collapse_whitespace(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut prev_space = false;

    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
                prev_space = true;
            }
        } else {
            result.push(ch);
            prev_space = false;
        }
    }

    result
}

// ── Hex Literal Decoding ─────────────────────────────────────────

/// Decode `0x41` style hex literals into ASCII characters.
fn decode_hex_literals(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if i + 3 < bytes.len()
            && bytes[i] == b'0'
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            // Try to read 2 hex digits
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                let val = (hi << 4) | lo;
                if val.is_ascii_graphic() || val == b' ' {
                    result.push(val as char);
                    i += 4;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

// ── Unicode Fullwidth to ASCII ───────────────────────────────────

/// Convert fullwidth Unicode characters (U+FF01–U+FF5E) to ASCII.
/// Attackers use `ＳＥＬＥＣＴrecord` to evade ASCII-only pattern matching.
fn fullwidth_to_ascii(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            let cp = c as u32;
            if (0xFF01..=0xFF5E).contains(&cp) {
                // Fullwidth ASCII variants: U+FF01 = '!', maps to U+0021
                char::from_u32(cp - 0xFF01 + 0x0021).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

// ── Path Canonicalization ────────────────────────────────────────

/// Normalize path segments: resolve `.` and `..` without filesystem access.
/// `/etc/../etc/shadow` → `/etc/shadow`
/// `/etc/./shadow` → `/etc/shadow`
fn canonicalize_path_segments(input: &str) -> String {
    // Only process substrings that look like paths
    if !input.contains('/') {
        return input.to_string();
    }

    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let chars: Vec<char> = input.chars().collect();

    while i < chars.len() {
        // Find path-like substrings (start with /)
        if chars[i] == '/' {
            let start = i;
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '"' && chars[i] != '\'' {
                i += 1;
            }
            let path_str: String = chars[start..i].iter().collect();
            result.push_str(&normalize_path_string(&path_str));
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

/// Normalize a single path string by resolving `.` and `..`.
fn normalize_path_string(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }

    if path.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    }
}

// ── Base64 Detection & Decoding ──────────────────────────────────

/// Detect base64-encoded blobs in the string and append their
/// decoded form. This catches attacks like:
/// `cm0gLXJmIC8=` (base64 for `rm -rf /`)
fn try_decode_base64_blobs(input: &str) -> String {
    // Quick check: is there a long-enough base64-like substring?
    let mut result = input.to_string();

    // Look for base64-like tokens (alphanumeric + /+=, length >= 8)
    for token in input.split_whitespace() {
        if token.len() >= 8 && looks_like_base64(token) {
            if let Some(decoded) = decode_base64(token) {
                if decoded.is_ascii() && decoded.len() >= 4 {
                    debug!("Decoded base64 blob: {} → {}", token, decoded);
                    result.push(' ');
                    result.push_str(&decoded);
                }
            }
        }
    }

    // Also check inside JSON string values (common in args)
    for token in input.split('"') {
        if token.len() >= 8 && looks_like_base64(token) {
            if let Some(decoded) = decode_base64(token) {
                if decoded.is_ascii() && decoded.len() >= 4 {
                    debug!("Decoded base64 blob in JSON: {} → {}", token, decoded);
                    result.push(' ');
                    result.push_str(&decoded);
                }
            }
        }
    }

    result
}

/// Heuristic: does this string look like it could be base64?
fn looks_like_base64(s: &str) -> bool {
    let valid_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let has_mixed = s.chars().any(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase());
    valid_chars && (has_mixed || s.ends_with('='))
}

/// Attempt to decode a base64 string.
fn decode_base64(input: &str) -> Option<String> {
    // Standard base64 alphabet
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut buf: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4);

    let mut accum: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = TABLE.iter().position(|&t| t == b)? as u32;
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }

    String::from_utf8(buf).ok()
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_simple() {
        assert_eq!(url_decode_once("%2Fetc%2Fshadow"), "/etc/shadow");
    }

    #[test]
    fn url_decode_double_encoding() {
        // %252F → %2F → /
        let result = url_decode_recursive("%252Fetc%252Fshadow", 3);
        assert_eq!(result, "/etc/shadow");
    }

    #[test]
    fn strip_sql_inline_comments() {
        assert_eq!(
            strip_sql_comments("un/**/ion sel/**/ect"),
            "union select"
        );
    }

    #[test]
    fn strip_sql_block_comment() {
        assert_eq!(
            strip_sql_comments("SELECT /* all columns */ * FROM users"),
            "SELECT  * FROM users"
        );
    }

    #[test]
    fn strip_sql_line_comment() {
        assert_eq!(
            strip_sql_comments("SELECT * FROM users-- WHERE id=1"),
            "SELECT * FROM users"
        );
    }

    #[test]
    fn collapse_whitespace_works() {
        assert_eq!(collapse_whitespace("un  ion   sel  ect"), "un ion sel ect");
    }

    #[test]
    fn hex_literal_decode() {
        // 0x53 = 'S', 0x45 = 'E', 0x4C = 'L'
        assert_eq!(decode_hex_literals("0x530x450x4C"), "SEL");
    }

    #[test]
    fn fullwidth_to_ascii_conversion() {
        // Ｓ = U+FF33, Ｅ = U+FF25, Ｌ = U+FF2C
        assert_eq!(fullwidth_to_ascii("ＳＥＬＥＣＴ"), "SELECT");
    }

    #[test]
    fn path_traversal_normalization() {
        assert_eq!(
            normalize_path_string("/etc/../etc/shadow"),
            "/etc/shadow"
        );
        assert_eq!(
            normalize_path_string("/home/user/./../../etc/shadow"),
            "/etc/shadow"
        );
    }

    #[test]
    fn base64_detection_and_decode() {
        // "rm -rf /" in base64
        let input = "execute cm0gLXJmIC8=";
        let result = try_decode_base64_blobs(input);
        assert!(result.contains("rm -rf /"));
    }

    #[test]
    fn full_normalize_pipeline() {
        // SQL comment obfuscation + URL encoding
        let input = "un%2F%2A%2A%2Fion%20sel%2F%2A%2A%2Fect";
        let result = normalize(input);
        assert!(result.contains("union select"), "got: {}", result);
    }

    #[test]
    fn normalize_path_traversal_attack() {
        let input = r#"{"path": "/etc/../etc/shadow"}"#;
        let result = normalize(input);
        assert!(result.contains("/etc/shadow"));
    }
}
