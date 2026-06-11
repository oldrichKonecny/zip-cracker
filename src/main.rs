mod verify;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use verify::{ScanInfo, Target};

// Batch size between atomic-counter flushes / found-flag polls. Smaller is more
// responsive (early exit on find, fresher progress) but adds more atomic
// traffic. Sized so each batch takes a few ms at the relevant cipher's speed.
// Must be a power of two — the worker uses `local & (flush - 1)` as fast modulo.
const FLUSH_ZIPCRYPTO: u64 = 1 << 16; // ~7 ms at ~10M pw/s
const FLUSH_AES: u64 = 1 << 4; //       ~6 ms at ~2.5k pw/s/core
// PDF R2-R4 (RC4/MD5) is fast; R5/R6 (AES-256 + hardened SHA-2 hash) is slow
// like ZIP AES, so it reuses FLUSH_AES.
const FLUSH_PDF_FAST: u64 = 1 << 12;
const _: () = assert!(FLUSH_ZIPCRYPTO.is_power_of_two());
const _: () = assert!(FLUSH_AES.is_power_of_two());
const _: () = assert!(FLUSH_PDF_FAST.is_power_of_two());

#[derive(Parser)]
#[command(
    name = "zip_pass_cracker",
    about = "Brute-force a ZIP or PDF password over a configurable alphabet and length range"
)]
struct Args {
    /// Path to the encrypted ZIP or PDF file (auto-detected by content).
    zip_path: PathBuf,

    #[arg(short, long)]
    threads: Option<usize>,

    /// Literal characters to use as the password alphabet. Combined (deduped)
    /// with any of the preset flags below. Defaults to digits if nothing given.
    #[arg(short, long)]
    charset: Option<String>,

    /// Add 0-9 to the alphabet.
    #[arg(long)]
    digits: bool,

    /// Add a-z to the alphabet.
    #[arg(long)]
    lower: bool,

    /// Add A-Z to the alphabet.
    #[arg(long)]
    upper: bool,

    /// Add a common set of punctuation symbols to the alphabet.
    #[arg(long)]
    symbols: bool,

    /// Minimum password length to try (inclusive).
    #[arg(long, default_value_t = 1)]
    min_len: usize,

    /// Maximum password length to try (inclusive).
    #[arg(long, default_value_t = 8)]
    max_len: usize,

    /// Exact password length — shorthand that sets both --min-len and --max-len.
    #[arg(short = 'L', long)]
    length: Option<usize>,

    /// Resume: global candidate index to start from (across the whole
    /// length-ordered keyspace).
    #[arg(long, default_value_t = 0)]
    start: u64,

    /// Global candidate index to stop at, exclusive. 0 means "to the end".
    #[arg(long, default_value_t = 0)]
    end: u64,
}

/// One password length to search and where it sits in the global keyspace.
struct LenSpan {
    len: usize,
    /// Global index of this length's first candidate.
    offset: u64,
    /// Number of candidates of this length (alphabet_len^len).
    space: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let charset = build_charset(&args);
    let base = charset.len() as u64;

    let (min_len, max_len) = match args.length {
        Some(l) => (l, l),
        None => (args.min_len, args.max_len),
    };
    if min_len == 0 {
        return Err("minimum length must be at least 1".into());
    }
    if max_len < min_len {
        return Err(format!("max-len ({}) must be >= min-len ({})", max_len, min_len).into());
    }

    // Build the per-length spans and the total keyspace. Everything is u64; a
    // keyspace that overflows u64 (~1.8e19) is infeasible to brute-force anyway.
    let mut spans = Vec::new();
    let mut total: u64 = 0;
    for len in min_len..=max_len {
        let space = base
            .checked_pow(len as u32)
            .and_then(|s| if s == 0 { None } else { Some(s) })
            .ok_or_else(|| {
                format!(
                    "keyspace for length {} exceeds 2^64 (alphabet size {}) — reduce --max-len or the alphabet",
                    len, base
                )
            })?;
        total = total
            .checked_add(space)
            .ok_or("total keyspace exceeds 2^64 — reduce --max-len or the alphabet")?;
        spans.push(LenSpan {
            len,
            offset: total - space,
            space,
        });
    }

    let start = args.start;
    let end = if args.end == 0 || args.end > total {
        total
    } else {
        args.end
    };
    if start >= end {
        return Err(format!(
            "invalid keyspace: start={} end={} (must satisfy start < end <= {})",
            start, end, total
        )
        .into());
    }

    let threads = args
        .threads
        .or_else(|| thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(4)
        .max(1);

    let info = verify::scan(&args.zip_path)?;
    let kind: String = match &info.target {
        Target::ZipCrypto { .. } => "ZipCrypto".to_string(),
        Target::Aes { key_len, .. } => match key_len {
            16 => "AES-128",
            24 => "AES-192",
            32 => "AES-256",
            _ => "AES-?",
        }
        .to_string(),
        Target::Pdf(t) => verify::pdf_kind(t.revision, (t.key_bytes as i64) * 8),
    };
    let space = end - start;
    eprintln!(
        "Target entry: [{}] {}\nEncryption: {}\nThreads: {}\nAlphabet: {} chars [{}]\nLengths: {}..={}\nKeyspace: {}..{} ({} candidates)",
        info.entry_idx,
        info.entry_name,
        kind,
        threads,
        base,
        String::from_utf8_lossy(&charset),
        min_len,
        max_len,
        start,
        end,
        space,
    );

    let found = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let result: OnceLock<String> = OnceLock::new();
    let ctx = WorkerCtx {
        info: &info,
        found: &found,
        attempts: &attempts,
        result: &result,
        charset: &charset,
    };
    let start_t = Instant::now();

    // Two nested scopes: the inner scope joins all workers before we flip
    // `done` to signal the outer progress thread to exit.
    thread::scope(|outer| {
        outer.spawn(|| progress_loop(&found, &done, &attempts, space));

        for span in &spans {
            if found.load(Ordering::Relaxed) {
                break;
            }
            // Intersect this length's global range [offset, offset+space) with
            // the requested [start, end) window, then map back to local indices.
            let lo = start.max(span.offset);
            let hi = end.min(span.offset + span.space);
            if lo >= hi {
                continue;
            }
            let local_start = lo - span.offset;
            let local_space = hi - lo;

            thread::scope(|s| {
                for t in 0..threads as u64 {
                    let ctx = &ctx;
                    let n = threads as u64;
                    let chunk_start = local_start + t * local_space / n;
                    let chunk_end = local_start + (t + 1) * local_space / n;
                    let len = span.len;
                    s.spawn(move || worker(ctx, len, chunk_start, chunk_end));
                }
            });
        }

        done.store(true, Ordering::Relaxed);
    });

    let elapsed = start_t.elapsed();
    match result.get() {
        Some(pw) => {
            eprintln!("Found in {:.1}s", elapsed.as_secs_f64());
            println!("{}", pw);
            Ok(())
        }
        None => {
            eprintln!(
                "Password not found in {:.1}s (searched {} attempts)",
                elapsed.as_secs_f64(),
                attempts.load(Ordering::Relaxed),
            );
            std::process::exit(2);
        }
    }
}

/// Build the password alphabet from the literal --charset plus any preset flags,
/// deduplicating bytes while preserving first-seen order. Defaults to digits.
fn build_charset(args: &Args) -> Vec<u8> {
    let mut chars: Vec<u8> = Vec::new();
    if let Some(c) = &args.charset {
        chars.extend_from_slice(c.as_bytes());
    }
    if args.digits {
        chars.extend(b'0'..=b'9');
    }
    if args.lower {
        chars.extend(b'a'..=b'z');
    }
    if args.upper {
        chars.extend(b'A'..=b'Z');
    }
    if args.symbols {
        chars.extend_from_slice(b"!@#$%^&*()-_=+[]{};:,.<>/?");
    }
    if chars.is_empty() {
        chars.extend(b'0'..=b'9');
    }

    let mut seen = [false; 256];
    let mut out = Vec::with_capacity(chars.len());
    for b in chars {
        if !seen[b as usize] {
            seen[b as usize] = true;
            out.push(b);
        }
    }
    out
}

/// Shared state every worker needs. Bundling these into one ref keeps the
/// hot-loop signature short and makes the worker/main wiring less noisy.
struct WorkerCtx<'a> {
    info: &'a ScanInfo,
    found: &'a AtomicBool,
    attempts: &'a AtomicU64,
    result: &'a OnceLock<String>,
    charset: &'a [u8],
}

fn worker(ctx: &WorkerCtx, len: usize, chunk_start: u64, chunk_end: u64) {
    // `confirm` runs only on candidates that pass the cheap check, to filter
    // false positives. ZIP needs a real decrypt (ZipCrypto's check is 1 byte);
    // PDF's check compares 16-32 crypto bytes, so a pass is conclusive.
    match &ctx.info.target {
        Target::ZipCrypto { header, check_byte } => run_loop(
            ctx,
            len,
            chunk_start,
            chunk_end,
            FLUSH_ZIPCRYPTO,
            |pw| verify::zipcrypto_check(header, pw, *check_byte),
            |pw| verify::full_verify(&ctx.info.zip_bytes, ctx.info.entry_idx, pw),
        ),
        Target::Aes { salt, pv, key_len } => run_loop(
            ctx,
            len,
            chunk_start,
            chunk_end,
            FLUSH_AES,
            |pw| verify::aes_check(salt, pv, pw, *key_len),
            |pw| verify::full_verify(&ctx.info.zip_bytes, ctx.info.entry_idx, pw),
        ),
        Target::Pdf(t) => {
            let flush = if t.revision <= 4 { FLUSH_PDF_FAST } else { FLUSH_AES };
            run_loop(
                ctx,
                len,
                chunk_start,
                chunk_end,
                flush,
                |pw| verify::pdf_check(t, pw),
                |_| true,
            )
        }
    }
}

#[inline]
fn run_loop<F: Fn(&[u8]) -> bool, G: Fn(&[u8]) -> bool>(
    ctx: &WorkerCtx,
    len: usize,
    chunk_start: u64,
    chunk_end: u64,
    flush: u64,
    check: F,
    confirm: G,
) {
    let mut pw = vec![0u8; len];
    let mut local: u64 = 0;

    for n in chunk_start..chunk_end {
        write_candidate(&mut pw, n, ctx.charset);
        if check(&pw) && confirm(&pw) {
            let pw_str = String::from_utf8_lossy(&pw).into_owned();
            let _ = ctx.result.set(pw_str);
            ctx.found.store(true, Ordering::Relaxed);
            return;
        }
        local += 1;
        if local & (flush - 1) == 0 {
            ctx.attempts.fetch_add(flush, Ordering::Relaxed);
            if ctx.found.load(Ordering::Relaxed) {
                return;
            }
        }
    }

    let tail = local & (flush - 1);
    if tail > 0 {
        ctx.attempts.fetch_add(tail, Ordering::Relaxed);
    }
}

fn progress_loop(found: &AtomicBool, done: &AtomicBool, attempts: &AtomicU64, space: u64) {
    let mut last_attempts = 0u64;
    let mut last_print = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(100));
        if found.load(Ordering::Relaxed) || done.load(Ordering::Relaxed) {
            break;
        }
        if last_print.elapsed() < Duration::from_secs(2) {
            continue;
        }
        let now = attempts.load(Ordering::Relaxed);
        let elapsed = last_print.elapsed().as_secs_f64().max(0.001);
        let rate = (now.saturating_sub(last_attempts)) as f64 / elapsed;
        let remaining = if rate > 0.0 {
            (space.saturating_sub(now) as f64) / rate
        } else {
            f64::INFINITY
        };
        let pct = (now as f64 / space as f64) * 100.0;
        eprintln!(
            "  {:>10}/{} ({:5.2}%)  {:>11.0} pw/s  ETA {}",
            now,
            space,
            pct,
            rate,
            fmt_eta(remaining),
        );
        last_attempts = now;
        last_print = Instant::now();
    }
}

/// Map a numeric index to a password by treating it as a mixed-radix number in
/// the alphabet's base, most-significant digit first. Index 0 -> all charset[0].
#[inline(always)]
fn write_candidate(buf: &mut [u8], mut n: u64, charset: &[u8]) {
    let base = charset.len() as u64;
    for i in (0..buf.len()).rev() {
        buf[i] = charset[(n % base) as usize];
        n /= base;
    }
}

fn fmt_eta(secs: f64) -> String {
    if !secs.is_finite() {
        return "unknown".to_string();
    }
    let s = secs as u64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{}h{:02}m{:02}s", h, m, sec)
    } else if m > 0 {
        format!("{}m{:02}s", m, sec)
    } else {
        format!("{}s", sec)
    }
}
