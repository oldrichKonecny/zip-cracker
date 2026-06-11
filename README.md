## Zip & PDF Cracker 🥨

Multi-threaded brute-force **ZIP and PDF** password recovery tool written in Rust.
Point it at an encrypted file and it enumerates candidate passwords over a
configurable alphabet and length range. The format is auto-detected from the
file's content:

- **ZIP** — both **ZipCrypto** (legacy) and **WinZip AES** (AE-1/AE-2,
  128/192/256-bit).
- **PDF** — the Standard Security Handler **user** password, revisions 2-6:
  R2-R4 (RC4 / AES-128 with an MD5-derived key) and R5/R6 (AES-256 with the
  SHA-2 "Algorithm 2.B" hardened hash). Owner-password recovery is not supported.

> ⚠️ Use this only on files you are authorized to access — e.g. recovering
> your own forgotten passwords, authorized penetration testing, or CTFs.

## 🚧 Work in progress

This project is a **work in progress** and is **not** production-ready. It is
experimental, has had limited testing, and may contain bugs or change without
notice. Do not rely on it for anything important. Use at your own risk.

## Build

Requires a [Rust toolchain](https://rustup.rs/).

```bash
cargo build --release
```

The binary is produced at `target/release/zip_pass_cracker`.

> Always use the `--release` build. The debug build is dramatically slower.

The repo ships a `.cargo/config.toml` that builds for the host CPU and enables
the hardware AES/SHA backends of the `aes`/`sha2` crates (the `aes_armv8` cfg on
ARM, runtime-detected AES-NI/SHA-NI on x86). This makes the AES-256 paths
(ZIP-AES, PDF R5/R6) roughly **15× faster** on Apple Silicon — without it those
crates fall back to software implementations. A normal `cargo build --release`
picks this up automatically.

## Usage

```bash
./target/release/zip_pass_cracker <ZIP_OR_PDF_FILE> [OPTIONS]
```

The recovered password is printed to **stdout**; all progress and diagnostics go
to **stderr**. On success the process exits `0`; if the whole keyspace is
searched with no match it exits `2`.

### Options

| Option | Description |
| --- | --- |
| `-c, --charset <CHARS>` | Literal characters to use as the alphabet. Combined (and deduplicated) with any preset flags below. |
| `--digits` | Add `0-9` to the alphabet. |
| `--lower` | Add `a-z` to the alphabet. |
| `--upper` | Add `A-Z` to the alphabet. |
| `--symbols` | Add a common set of punctuation symbols to the alphabet. |
| `--min-len <N>` | Minimum password length to try, inclusive (default: `1`). |
| `--max-len <N>` | Maximum password length to try, inclusive (default: `8`). |
| `-L, --length <N>` | Exact length — shorthand that sets both `--min-len` and `--max-len`. |
| `-t, --threads <N>` | Number of worker threads (default: detected CPU parallelism). |
| `--start <I>` | Resume from this global candidate index (see [Resuming](#resuming-a-long-run)). |
| `--end <I>` | Stop at this global candidate index, exclusive. `0` means "to the end". |

If you specify neither `--charset` nor any preset flag, the alphabet defaults to
digits (`0-9`). Lengths are tried shortest-first.

### Examples

```bash
# 10 numeric digits
./target/release/zip_pass_cracker secret.zip --digits -L 10

# 1 to 6 characters of lowercase letters and digits
./target/release/zip_pass_cracker secret.zip --lower --digits --max-len 6

# A custom alphabet, 4 to 8 characters
./target/release/zip_pass_cracker secret.zip -c 'abcABC!?' --min-len 4 --max-len 8

# An encrypted PDF (format auto-detected), lowercase + digits up to 5 chars
./target/release/zip_pass_cracker secret.pdf --lower --digits --max-len 5

# Digits, 8 to 11 characters, capturing the password to a file
./target/release/zip_pass_cracker secret.zip --digits --min-len 8 --max-len 11 | tee found.txt
```

## How it works & performance

The tool reads the file once and runs a cheap per-candidate check across all
threads (a one-byte ZipCrypto check, the ZIP-AES password-verification value, or
the PDF `/U` recomputation). For ZIP, any candidate that passes is confirmed by a
full decrypt to rule out false positives; the PDF check compares 16-32
cryptographic bytes so it is already conclusive.

- **ZipCrypto** and **PDF R2-R4** (RC4/MD5) run very fast — on the order of
  millions to tens of millions of passwords per second across modern multi-core
  machines.
- **ZIP-AES** and **PDF R5/R6** (AES-256) are *much* slower because each guess
  requires 1000 rounds of PBKDF2 (ZIP) or the iterated SHA-2 Algorithm 2.B hash
  (PDF) — both deliberately expensive by design. With the hardware crypto
  backends enabled (see [Build](#build)) PDF R6 runs on the order of tens of
  thousands of passwords/sec on a modern multi-core machine (~80k pw/s on an
  Apple M5 Pro); without them it is ~15× slower. Keep the alphabet and length
  range as small as possible for these.

Keep in mind the keyspace grows exponentially with length. For an alphabet of
size `B` and length `L` there are `Bᴸ` candidates, so widening the alphabet or
adding length quickly makes a search infeasible. The startup banner prints the
total candidate count and a live ETA — check it before committing to a long run.
Keyspaces larger than `2^64` are rejected at startup.

### Resuming a long run

All lengths share one continuous, length-ordered index space. If you stop a run
(`Ctrl-C`), note the last progress index printed and pass it to `--start` to pick
up roughly where you left off:

```bash
./target/release/zip_pass_cracker secret.zip --digits --min-len 8 --max-len 11 --start 5000000000
```

You can also split a search across machines by giving each a disjoint
`--start`/`--end` window.
