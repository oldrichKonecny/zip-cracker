# CLAUDE.md

Guidance for working in this repository.

## What this is

`zip_pass_cracker` is a multi-threaded brute-force **ZIP and PDF** password
recovery tool written in Rust. Given an encrypted file, it enumerates candidate
passwords over a configurable alphabet and length range and tests each against
the file's encryption. The input format is auto-detected from the file's magic
bytes (`%PDF-` → PDF, otherwise ZIP).

- **ZIP**: tests against the archive's first encrypted entry. Supports both
  ZipCrypto (legacy) and WinZip AES (AE-1/AE-2, 128/192/256-bit), auto-detected.
- **PDF**: tests against the Standard Security Handler **user** password.
  Supports revisions 2-6 — R2-R4 (RC4/AES-128 with an MD5-derived key) and
  R5/R6 (AES-256 with the SHA-2 hardened "Algorithm 2.B" hash), auto-detected
  from the `/Encrypt` dictionary. Owner-password cracking is not implemented.

This is a security/recovery tool intended for files you are authorized to
access (e.g. your own forgotten passwords, authorized pentesting, CTFs).

## Build & run

```bash
cargo build --release          # always use --release; the debug build is ~50x slower
./target/release/zip_pass_cracker <ZIP> [options]
```

On success the recovered password is printed to **stdout** (everything else —
progress, target info — goes to **stderr**), and the process exits 0. If the
keyspace is exhausted without a match it exits 2.

### Key options

- `-c, --charset <CHARS>` — literal characters in the alphabet.
- `--digits` / `--lower` / `--upper` / `--symbols` — preset character classes,
  combined (and deduplicated) with `--charset`. Defaults to digits if none given.
- `--min-len <N>` / `--max-len <N>` — length range to search (inclusive).
  Lengths are tried shortest-first. Defaults: 1..=8.
- `-L, --length <N>` — shorthand setting both min and max to an exact length.
- `-p, --pattern <P>` — **pattern (mask) mode**: a per-position template that
  fixes some characters and brute-forces the rest. Conflicts with `--charset`,
  the preset flags, and the length flags (the pattern determines the length).
  Notation: literal bytes match themselves; `[a-z0-9]` is a character class
  (inclusive ranges + individual chars); `X{n}` repeats the previous position
  `n` times; `\d \l \u \s` are the digit/lower/upper/symbol presets (usable bare
  or inside `[...]`); `\` escapes a special char (`[ ] { } \` or a preset
  letter). Variable `{m,n}` quantifiers and negated `[^...]` classes are not
  supported.
- `-t, --threads <N>` — worker count (defaults to available parallelism).
- `--start <I>` / `--end <I>` — resume window as global candidate indices across
  the whole length-ordered keyspace (`--end 0` means "to the end").

Examples:

```bash
# 10 numeric digits (the tool's original fixed behavior)
zip_pass_cracker secret.zip --digits -L 10
# 1-6 chars of lowercase + digits
zip_pass_cracker secret.zip --lower --digits --max-len 6
# custom alphabet
zip_pass_cracker secret.zip -c 'abcABC!?' --min-len 4 --max-len 8
# pattern: fixed prefix/suffix, brute-force the middle -> e.g. 940995y;117
zip_pass_cracker secret.zip -p '9409[0-9][5-9][x-z];\d{3}'
```

## Architecture

Three source files:

- **`src/main.rs`** — CLI (clap), alphabet/keyspace construction, thread
  orchestration, and progress reporting.
- **`src/pattern.rs`** — parses a `--pattern` string into a per-position alphabet
  list (the `Mask` positions). No crypto or I/O.
- **`src/verify.rs`** — ZIP/PDF parsing and the cryptographic password checks.

### Keyspace model

The unit of the search space is a `Mask`: a fixed number of positions, each with
its own alphabet (`Vec<Vec<u8>>`). A `Mask`'s candidate count is the **product**
of its per-position alphabet sizes, and `Mask::write` maps an index to a password
by mixed-radix decoding with a per-position base, most-significant position first
(index 0 → first char of every position).

The two input modes both reduce to a list of masks:

- **charset + length**: for each length `L`, a uniform mask of `L` positions all
  sharing the alphabet (so its count is `base^L`).
- **pattern**: a single mask whose positions come from `pattern::parse`. A literal
  pattern char is just a size-1 alphabet; a `[...]` class or `\d`-style preset is
  a larger one.

Masks are laid out consecutively into one global keyspace: each mask's span
starts at the cumulative offset of all earlier masks. `--start`/`--end` operate
on these global indices, and each mask's local sub-range is the intersection of
its span with the requested window. **All indices are `u64`** — a keyspace that
overflows `u64` (~1.8e19) is rejected at startup, since it is infeasible to
brute-force anyway.

Each mask is searched in turn; its sub-range is split evenly across worker
threads via `thread::scope`.

### Two-phase verification

`verify::scan` reads the whole file into memory once, sniffs the format, and
dispatches to `scan_zip` or `scan_pdf`. Each extracts the cheap material needed
for a fast per-candidate check (`Target` enum):

- **ZipCrypto**: decrypt the 12-byte encryption header and compare the final
  check byte (high byte of CRC32, or of mod-time when the streaming GPBF bit 3 is
  set). ~1-in-256 false-positive rate.
- **AES** (ZIP): PBKDF2-HMAC-SHA1 (1000 iterations) to derive the 2-byte password
  verification value and compare it. ~1-in-65536 false-positive rate.
- **PDF**: `pdf_check` recomputes the encryption dictionary's `/U` value from the
  candidate and compares it. R2-R4 derive an MD5 file key then RC4 (Algorithm
  4/5); R5/R6 run the SHA-2 Algorithm 2.B hardened hash against the 8-byte
  validation salt. The comparison is 16-32 cryptographic bytes, so there is **no
  meaningful false-positive rate** — a passing candidate is the password.

Any ZIP candidate passing the fast check is confirmed with `full_verify`, which
actually decrypts and reads the entry through the `zip` crate to eliminate false
positives. The PDF path passes a no-op confirm (`|_| true`) since its check is
already conclusive. Because false positives are rare, the slow ZIP confirm path
runs seldom.

ZIP structure (local file header, AES extra field `0x9901`, salt/pv layout) is
parsed by hand from the cached bytes rather than via the `zip` crate, so the hot
loop touches no I/O. PDF structure is parsed once at scan time via the `lopdf`
crate (which handles compressed xref/object streams) to reach the `/Encrypt`
dictionary and trailer `/ID`; the per-candidate crypto is then hand-rolled
(`md-5`/`sha2`/`aes`+`cbc`, RC4 inline) so the hot loop touches no `lopdf` types.
Candidate bytes are used as the password verbatim — correct for ASCII passwords
(the character presets); non-ASCII `--charset` bytes are not spec-normalized.

### Performance notes

- Worker hot loop flushes its attempt counter and polls the shared `found` flag
  in power-of-two batches (`FLUSH_ZIPCRYPTO`, `FLUSH_AES`, `FLUSH_PDF_FAST`) to
  limit atomic traffic. The `local & (flush - 1)` trick requires these stay
  powers of two (enforced by `const` asserts). PDF R2-R4 use `FLUSH_PDF_FAST`;
  PDF R5/R6 reuse `FLUSH_AES`.
- ZipCrypto runs ~10M pw/s; ZIP-AES and PDF R5/R6 are far slower (~thousands
  pw/s/core) because of PBKDF2 / the Algorithm 2.B hash — prefer narrow alphabets
  / short lengths for those. PDF R2-R4 (RC4/MD5) are fast.
- `[profile.release]` uses thin LTO and a single codegen unit.

## Testing

There is no test suite. To verify changes manually, create a ZIP with a known
password and confirm recovery:

```bash
echo secret > /tmp/s.txt
zip -P a7k /tmp/crackme.zip /tmp/s.txt        # ZipCrypto
# zip -e ... for the platform's default encryption
./target/release/zip_pass_cracker /tmp/crackme.zip --lower --digits -L 3
```

For PDF, create known-password files at each revision with `qpdf` (RC4 revisions
need `--allow-weak-crypto`) and confirm recovery:

```bash
qpdf --allow-weak-crypto --empty --encrypt --user-password=ab1 --owner-password=o --bits=40  -- /tmp/r2.pdf   # R2 RC4-40
qpdf --allow-weak-crypto --empty --encrypt --user-password=ab1 --owner-password=o --bits=128 --use-aes=n -- /tmp/r3.pdf  # R3 RC4-128
qpdf --empty --encrypt --user-password=ab1 --owner-password=o --bits=128 --use-aes=y -- /tmp/r4.pdf   # R4 AES-128
qpdf --empty --encrypt --user-password=ab1 --owner-password=o --bits=256 -- /tmp/r6.pdf               # R6 AES-256
./target/release/zip_pass_cracker /tmp/r6.pdf --lower --digits -L 3   # expect: ab1
```

`test_input/` (gitignored) holds local sample archives and PDFs.

## Conventions

- Keep the candidate-testing hot loop allocation- and I/O-free.
- Preserve the stdout (password only) / stderr (diagnostics) split — callers may
  capture the password by piping stdout.
- When touching flush constants, keep them powers of two.
