//! Parse a password "pattern" (mask) into a per-position alphabet list.
//!
//! Each output `Vec<u8>` is the alphabet for one password position; a literal
//! character is just a size-1 alphabet. The keyspace of a pattern is the product
//! of the per-position sizes, decoded by the same mixed-radix scheme the
//! charset+length mode uses (see `Mask` in `main.rs`).
//!
//! Notation:
//! - literal bytes: a size-1 alphabet at that position.
//! - `[abc]` / `[a-z0-9]`: a character class — inclusive `a-z` ranges and
//!   individual chars, order-preserving and deduped.
//! - `X{n}`: repeat the preceding position `n` times (n >= 1).
//! - `\d \l \u \s`: digit / lower / upper / symbol preset classes (usable bare
//!   or inside `[...]`).
//! - `\X`: a literal `X` (escape `[ ] { } \` or a preset letter).
//!
//! Example: `9409[0-9][5-9][x-z];\d{3}` matches e.g. `940995y;117`.

/// Same punctuation set as the `--symbols` preset in `main.rs`.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>/?";

/// Parse `pat` into one alphabet per password position.
pub fn parse(pat: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = pat.as_bytes();
    let mut positions: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let (alpha, next) = parse_escape(bytes, i + 1)?;
                positions.push(alpha);
                i = next;
            }
            b'[' => {
                let (alpha, next) = parse_class(bytes, i + 1)?;
                positions.push(alpha);
                i = next;
            }
            b'{' => {
                let (count, next) = parse_quantifier(bytes, i + 1)?;
                let last = positions
                    .last()
                    .ok_or_else(|| "quantifier {N} has no preceding element".to_string())?
                    .clone();
                // The quantified element already contributed one position; add
                // `count - 1` more copies of it.
                for _ in 1..count {
                    positions.push(last.clone());
                }
                i = next;
            }
            b']' => return Err("unmatched ']' in pattern (escape it as \\])".to_string()),
            b'}' => return Err("unmatched '}' in pattern (escape it as \\})".to_string()),
            c => {
                positions.push(vec![c]);
                i += 1;
            }
        }
    }
    if positions.is_empty() {
        return Err("pattern is empty".to_string());
    }
    Ok(positions)
}

/// Resolve a backslash escape at `i` (the byte after `\`). Returns the alphabet
/// it expands to and the index just past it.
fn parse_escape(bytes: &[u8], i: usize) -> Result<(Vec<u8>, usize), String> {
    let c = *bytes
        .get(i)
        .ok_or_else(|| "trailing '\\' in pattern".to_string())?;
    let alpha = match c {
        b'd' => (b'0'..=b'9').collect(),
        b'l' => (b'a'..=b'z').collect(),
        b'u' => (b'A'..=b'Z').collect(),
        b's' => SYMBOLS.to_vec(),
        other => vec![other],
    };
    Ok((alpha, i + 1))
}

/// Parse a `[...]` class. `start` is the byte after `[`. Returns the (deduped,
/// order-preserving) alphabet and the index just past the closing `]`.
fn parse_class(bytes: &[u8], start: usize) -> Result<(Vec<u8>, usize), String> {
    let mut seen = [false; 256];
    let mut out: Vec<u8> = Vec::new();
    let push = |b: u8, out: &mut Vec<u8>, seen: &mut [bool; 256]| {
        if !seen[b as usize] {
            seen[b as usize] = true;
            out.push(b);
        }
    };

    let mut i = start;
    let mut closed = false;
    while i < bytes.len() {
        match bytes[i] {
            b']' => {
                closed = true;
                i += 1;
                break;
            }
            b'\\' => {
                let (alpha, next) = parse_escape(bytes, i + 1)?;
                for b in alpha {
                    push(b, &mut out, &mut seen);
                }
                i = next;
            }
            c => {
                // A range `c-e` only when a `-` and a non-`]` endpoint follow.
                if i + 2 < bytes.len() && bytes[i + 1] == b'-' && bytes[i + 2] != b']' {
                    let end = bytes[i + 2];
                    if c > end {
                        return Err(format!(
                            "invalid range '{}-{}' in class",
                            c as char, end as char
                        ));
                    }
                    for b in c..=end {
                        push(b, &mut out, &mut seen);
                    }
                    i += 3;
                } else {
                    push(c, &mut out, &mut seen);
                    i += 1;
                }
            }
        }
    }
    if !closed {
        return Err("unterminated '[' in pattern".to_string());
    }
    if out.is_empty() {
        return Err("empty character class '[]' in pattern".to_string());
    }
    Ok((out, i))
}

/// Parse a `{N}` quantifier. `start` is the byte after `{`. Returns the count
/// (>= 1) and the index just past the closing `}`.
fn parse_quantifier(bytes: &[u8], start: usize) -> Result<(usize, usize), String> {
    let mut i = start;
    let mut n: usize = 0;
    let mut any = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        any = true;
        n = n
            .checked_mul(10)
            .and_then(|x| x.checked_add((bytes[i] - b'0') as usize))
            .ok_or_else(|| "quantifier count too large".to_string())?;
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'}' {
        return Err("malformed quantifier (expected {N})".to_string());
    }
    if !any {
        return Err("empty quantifier '{}'".to_string());
    }
    if n == 0 {
        return Err("quantifier {0} is not allowed".to_string());
    }
    Ok((n, i + 1))
}
