# CLAUDE.md

Guidance for working in this repository.

## What this is

`zip_pass_cracker` is a multi-threaded brute-force ZIP password recovery tool
written in Rust. Given an encrypted ZIP, it enumerates candidate passwords over a
configurable alphabet and length range, testing each against the archive's first
encrypted entry. It supports both ZipCrypto (legacy) and WinZip AES (AE-1/AE-2,
128/192/256-bit) encryption, auto-detecting which is in use.

This is a security/recovery tool intended for archives you are authorized to
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
```

## Architecture

Two source files:

- **`src/main.rs`** — CLI (clap), alphabet/keyspace construction, thread
  orchestration, and progress reporting.
- **`src/verify.rs`** — ZIP parsing and the cryptographic password checks.

### Keyspace model

The search space is enumerated by integer index. For each length `L`, there are
`base^L` candidates (where `base` = alphabet size). `write_candidate` maps an
index to a password by interpreting it as a mixed-radix number in the alphabet's
base, most-significant digit first (index 0 → all `charset[0]`).

Lengths are laid out consecutively into one global keyspace: length `L`'s span
starts at the cumulative offset of all shorter lengths. `--start`/`--end` operate
on these global indices, and each length's local sub-range is the intersection of
its span with the requested window. **All indices are `u64`** — a keyspace that
overflows `u64` (~1.8e19) is rejected at startup, since it is infeasible to
brute-force anyway.

Each length is searched in turn; its sub-range is split evenly across worker
threads via `thread::scope`.

### Two-phase verification

`verify::scan` reads the whole archive into memory once and extracts the cheap
material needed for a fast per-candidate check:

- **ZipCrypto**: decrypt the 12-byte encryption header and compare the final
  check byte (high byte of CRC32, or of mod-time when the streaming GPBF bit 3 is
  set). ~1-in-256 false-positive rate.
- **AES**: PBKDF2-HMAC-SHA1 (1000 iterations) to derive the 2-byte password
  verification value and compare it. ~1-in-65536 false-positive rate.

Any candidate passing the fast check is confirmed with `full_verify`, which
actually decrypts and reads the entry through the `zip` crate to eliminate false
positives. Because false positives are rare, this slow path runs seldom.

ZIP structure (local file header, AES extra field `0x9901`, salt/pv layout) is
parsed by hand from the cached bytes rather than via the `zip` crate, so the hot
loop touches no I/O.

### Performance notes

- Worker hot loop flushes its attempt counter and polls the shared `found` flag
  in power-of-two batches (`FLUSH_ZIPCRYPTO`, `FLUSH_AES`) to limit atomic
  traffic. The `local & (flush - 1)` trick requires these stay powers of two
  (enforced by `const` asserts).
- ZipCrypto runs ~10M pw/s; AES is far slower (~thousands pw/s/core) because of
  PBKDF2 — prefer narrow alphabets / short lengths for AES archives.
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

`test_input/` (gitignored) holds local sample archives.

## Conventions

- Keep the candidate-testing hot loop allocation- and I/O-free.
- Preserve the stdout (password only) / stderr (diagnostics) split — callers may
  capture the password by piping stdout.
- When touching flush constants, keep them powers of two.
