use std::io::{Cursor, Read, Seek};
use std::path::Path;

use zip::ZipArchive;

pub enum Target {
    ZipCrypto {
        header: [u8; 12],
        check_byte: u8,
    },
    Aes {
        salt: Vec<u8>,
        pv: [u8; 2],
        key_len: usize,
    },
    Pdf(PdfTarget),
}

/// Cheap material for a PDF Standard Security Handler user-password check,
/// extracted once at scan time. Covers revisions 2-6 (RC4/AES-128 with an
/// MD5-derived key for R2-R4, AES-256 with a SHA-2 hardened hash for R5/R6).
pub struct PdfTarget {
    pub revision: u8,
    /// File-encryption-key length in bytes (R2-R4 key derivation only).
    pub key_bytes: usize,
    pub encrypt_metadata: bool,
    /// `/O` owner value (32 bytes for R<=4, 48 for R>=5).
    pub o: Vec<u8>,
    /// `/U` user value (32 bytes for R<=4, 48 for R>=5).
    pub u: Vec<u8>,
    /// `/P` permissions, as the raw 32-bit value used in key derivation.
    pub p: u32,
    /// First element of the trailer `/ID` array (R2-R4 key derivation).
    pub id0: Vec<u8>,
}

pub struct ScanInfo {
    pub target: Target,
    pub entry_idx: usize,
    pub entry_name: String,
    /// Whole archive cached in memory so false-positive verification doesn't
    /// pay open/seek cost per check.
    pub zip_bytes: Vec<u8>,
}

struct LfhFields {
    gp_flag: u16,
    compression: u16,
    mod_time: u16,
    name_len: usize,
    extra_len: usize,
}

pub fn scan(path: &Path) -> Result<ScanInfo, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    // Sniff the magic: PDFs start with "%PDF-" (possibly after a few junk bytes),
    // everything else is treated as a ZIP.
    let head = &bytes[..bytes.len().min(1024)];
    if head.windows(5).any(|w| w == b"%PDF-") {
        return scan_pdf(bytes);
    }
    scan_zip(bytes)
}

fn scan_zip(zip_bytes: Vec<u8>) -> Result<ScanInfo, Box<dyn std::error::Error>> {
    let mut cursor = Cursor::new(&zip_bytes[..]);
    let mut archive = ZipArchive::new(&mut cursor)?;

    let target_idx = find_first_encrypted_entry(&mut archive)?;

    let entry = archive.by_index_raw(target_idx)?;
    let data_start = entry
        .data_start()
        .ok_or("zip crate did not expose data_start for the target entry")?;
    let header_start = entry.header_start() as usize;
    let crc32 = entry.crc32();
    let entry_name = entry.name().to_string();
    drop(entry);
    drop(archive);

    let lfh = parse_local_file_header(&zip_bytes, header_start)?;
    let ds = data_start as usize;

    let target = if lfh.compression == 99 {
        let extra_start = header_start + 30 + lfh.name_len;
        let extra = zip_bytes
            .get(extra_start..extra_start + lfh.extra_len)
            .ok_or("local extra field out of range")?;
        let strength = parse_aes_strength(extra)?;
        let (salt_len, key_len) = match strength {
            1 => (8usize, 16usize),
            2 => (12, 24),
            3 => (16, 32),
            n => return Err(format!("unknown AES strength: {}", n).into()),
        };

        let salt = zip_bytes
            .get(ds..ds + salt_len)
            .ok_or("salt out of range")?
            .to_vec();
        let pv_slice = zip_bytes
            .get(ds + salt_len..ds + salt_len + 2)
            .ok_or("password verification value out of range")?;
        let pv = [pv_slice[0], pv_slice[1]];

        Target::Aes { salt, pv, key_len }
    } else {
        let header: [u8; 12] = zip_bytes
            .get(ds..ds + 12)
            .ok_or("encryption header out of range")?
            .try_into()
            .unwrap();
        // Spec: if GPBF bit 3 is set (streaming), check byte = high byte of
        // mod-time. Otherwise check byte = high byte of CRC32.
        let check_byte = if lfh.gp_flag & 0x0008 != 0 {
            (lfh.mod_time >> 8) as u8
        } else {
            (crc32 >> 24) as u8
        };
        Target::ZipCrypto { header, check_byte }
    };

    Ok(ScanInfo {
        target,
        entry_idx: target_idx,
        entry_name,
        zip_bytes,
    })
}

/// Parse a PDF's encryption dictionary and trailer `/ID` into a `PdfTarget`.
///
/// lopdf parses the (compressed) cross-reference and object streams and exposes
/// the trailer and encryption dictionary without needing the password — it only
/// auto-decrypts when the *empty* password works, which is exactly the case we
/// are not interested in. All the per-candidate crypto is hand-rolled below so
/// the hot loop touches no lopdf types.
fn scan_pdf(pdf_bytes: Vec<u8>) -> Result<ScanInfo, Box<dyn std::error::Error>> {
    use lopdf::Document;

    let doc = Document::load_mem(&pdf_bytes)?;
    let enc = doc
        .get_encrypted()
        .map_err(|_| "PDF is not encrypted (no /Encrypt dictionary)")?;

    let get_i64 = |key: &[u8]| enc.get(key).ok().and_then(|o| o.as_i64().ok());
    let revision = get_i64(b"R").ok_or("encryption dict missing /R")? as u8;
    if !(2..=6).contains(&revision) {
        return Err(format!("unsupported PDF security handler revision: {}", revision).into());
    }
    let length_bits = get_i64(b"Length").unwrap_or(40);
    let key_bytes = if revision >= 3 {
        (length_bits / 8) as usize
    } else {
        5
    };
    let encrypt_metadata = enc
        .get(b"EncryptMetadata")
        .ok()
        .and_then(|o| o.as_bool().ok())
        .unwrap_or(true);

    let o = enc.get(b"O").and_then(|o| o.as_str())?.to_vec();
    let u = enc.get(b"U").and_then(|o| o.as_str())?.to_vec();
    // /P is a signed 32-bit flag word; key derivation uses its raw 32-bit value.
    let p = get_i64(b"P").ok_or("encryption dict missing /P")? as i32 as u32;

    let id0 = doc
        .trailer
        .get(b"ID")
        .ok()
        .and_then(|o| o.as_array().ok())
        .and_then(|a| a.first())
        .and_then(|o| o.as_str().ok())
        .map(|s| s.to_vec())
        .unwrap_or_default();

    if revision <= 4 {
        if o.len() < 32 || u.len() < 32 {
            return Err("PDF /O or /U too short for revision <= 4".into());
        }
        if key_bytes > 16 {
            return Err("PDF key length exceeds 16 bytes (MD5 limit)".into());
        }
    } else if o.len() < 48 || u.len() < 48 {
        return Err("PDF /O or /U too short for revision >= 5".into());
    }

    let kind = pdf_kind(revision, length_bits);
    Ok(ScanInfo {
        target: Target::Pdf(PdfTarget {
            revision,
            key_bytes,
            encrypt_metadata,
            o,
            u,
            p,
            id0,
        }),
        entry_idx: 0,
        entry_name: format!("<PDF document, {}>", kind),
        zip_bytes: pdf_bytes,
    })
}

/// Human-readable cipher label for the encryption banner.
pub fn pdf_kind(revision: u8, length_bits: i64) -> String {
    match revision {
        2 => "PDF R2 RC4-40".to_string(),
        3 => format!("PDF R3 RC4-{}", length_bits),
        4 => format!("PDF R4 RC4/AES-{}", length_bits),
        5 => "PDF R5 AES-256".to_string(),
        6 => "PDF R6 AES-256".to_string(),
        _ => format!("PDF R{}", revision),
    }
}

fn find_first_encrypted_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<usize, Box<dyn std::error::Error>> {
    for i in 0..archive.len() {
        if archive.by_index_raw(i)?.encrypted() {
            return Ok(i);
        }
    }
    Err("no encrypted entries in archive".into())
}

fn parse_local_file_header(
    zip_bytes: &[u8],
    header_start: usize,
) -> Result<LfhFields, Box<dyn std::error::Error>> {
    let lfh: &[u8; 30] = zip_bytes
        .get(header_start..header_start + 30)
        .ok_or("local file header out of range")?
        .try_into()
        .unwrap();
    if &lfh[0..4] != b"PK\x03\x04" {
        return Err("bad local file header signature".into());
    }
    Ok(LfhFields {
        gp_flag: u16::from_le_bytes([lfh[6], lfh[7]]),
        compression: u16::from_le_bytes([lfh[8], lfh[9]]),
        mod_time: u16::from_le_bytes([lfh[10], lfh[11]]),
        name_len: u16::from_le_bytes([lfh[26], lfh[27]]) as usize,
        extra_len: u16::from_le_bytes([lfh[28], lfh[29]]) as usize,
    })
}

fn parse_aes_strength(extra: &[u8]) -> Result<u8, Box<dyn std::error::Error>> {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[i], extra[i + 1]]);
        let size = u16::from_le_bytes([extra[i + 2], extra[i + 3]]) as usize;
        if id == 0x9901 && size >= 7 && i + 4 + size <= extra.len() {
            // layout: version(2) vendor(2) strength(1) actual_method(2)
            return Ok(extra[i + 4 + 4]);
        }
        i += 4 + size;
    }
    Err("AES extra field (0x9901) not found".into())
}

// ===== ZipCrypto =====

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

#[inline(always)]
fn crc32_byte(crc: u32, b: u8) -> u32 {
    (crc >> 8) ^ CRC_TABLE[((crc ^ b as u32) & 0xff) as usize]
}

#[inline(always)]
fn update_keys(keys: &mut [u32; 3], b: u8) {
    keys[0] = crc32_byte(keys[0], b);
    keys[1] = keys[1].wrapping_add(keys[0] & 0xff);
    // 0x08088405: Borland C rand() LCG multiplier (APPNOTE.TXT 6.1.5).
    keys[1] = keys[1].wrapping_mul(0x08088405).wrapping_add(1);
    keys[2] = crc32_byte(keys[2], (keys[1] >> 24) as u8);
}

#[inline(always)]
fn stream_byte(keys: &[u32; 3]) -> u8 {
    // Keystream PRNG formula from APPNOTE.TXT 6.1.6.
    let temp = (keys[2] | 2) as u16;
    (temp.wrapping_mul(temp ^ 1) >> 8) as u8
}

#[inline]
pub fn zipcrypto_check(header: &[u8; 12], password: &[u8], check_byte: u8) -> bool {
    let mut keys = [0x12345678u32, 0x23456789, 0x34567890];
    for &b in password {
        update_keys(&mut keys, b);
    }
    for i in 0..11 {
        let s = stream_byte(&keys);
        let pt = header[i] ^ s;
        update_keys(&mut keys, pt);
    }
    let s = stream_byte(&keys);
    (header[11] ^ s) == check_byte
}

// ===== AES (WinZip AE-2 / AE-1) =====

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

#[inline]
pub fn aes_check(salt: &[u8], pv: &[u8; 2], password: &[u8], key_len: usize) -> bool {
    // PBKDF2-HMAC-SHA1, 1000 iterations.
    // Output layout: enc_key (key_len) | mac_key (key_len) | pv (2)
    let mut out = [0u8; 66];
    let total = 2 * key_len + 2;
    pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut out[..total]);
    out[total - 2] == pv[0] && out[total - 1] == pv[1]
}

// ===== PDF Standard Security Handler (revisions 2-6) =====

use md5::Md5;
use sha2::{Digest, Sha256, Sha384, Sha512};

use aes::Aes128;
use cipher::{BlockModeEncrypt, KeyIvInit};
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

// Password padding string from Algorithm 2 (ISO 32000), used for R2-R4.
const PAD_BYTES: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Verify a candidate against a PDF's user password. The comparison is against
/// a 16-byte (R3/R4) or 32-byte (R2/R6) cryptographic value, so unlike
/// ZipCrypto's 1-byte check there is no meaningful false-positive rate — a
/// passing candidate is the password and needs no `full_verify`.
///
/// Candidate bytes are used as the password verbatim. Spec sanitization is the
/// identity for ASCII passwords (PDFDocEncoding for R2-R4, SASLprep/UTF-8 for
/// R5/R6), which covers the tool's character presets; non-ASCII `--charset`
/// bytes are not normalized.
#[inline]
pub fn pdf_check(t: &PdfTarget, pw: &[u8]) -> bool {
    if t.revision <= 4 {
        pdf_check_r2_r4(t, pw)
    } else {
        pdf_check_r5_r6(t, pw)
    }
}

/// Hand-rolled RC4 keystream XOR (KSA + PRGA). `out` must be at least
/// `data.len()`; only `data.len()` bytes are written.
#[inline]
fn rc4(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for (k, &b) in data.iter().enumerate() {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let ks = s[(s[i] as usize + s[j] as usize) & 0xff];
        out[k] = b ^ ks;
    }
}

/// R2-R4: derive the file encryption key (Algorithm 2) from the password, then
/// recompute `/U` (Algorithm 4 for R2, Algorithm 5 for R3/R4) and compare.
fn pdf_check_r2_r4(t: &PdfTarget, pw: &[u8]) -> bool {
    let n = t.key_bytes;
    let plen = pw.len().min(32);

    let mut md = Md5::new();
    md.update(&pw[..plen]);
    md.update(&PAD_BYTES[..32 - plen]);
    md.update(&t.o);
    md.update(t.p.to_le_bytes());
    md.update(&t.id0);
    if t.revision >= 4 && !t.encrypt_metadata {
        md.update([0xff, 0xff, 0xff, 0xff]);
    }
    let mut hash = md.finalize();
    if t.revision >= 3 {
        for _ in 0..50 {
            hash = Md5::digest(&hash[..n]);
        }
    }
    let key = &hash[..n];

    if t.revision == 2 {
        // Algorithm 4: U = RC4(key, PAD); full 32-byte comparison.
        let mut out = [0u8; 32];
        rc4(key, &PAD_BYTES, &mut out);
        out[..] == t.u[..32]
    } else {
        // Algorithm 5: x = RC4(key, MD5(PAD || ID0)), then 19 XOR-keyed rounds;
        // compare the first 16 bytes against /U.
        let mut h = Md5::new();
        h.update(PAD_BYTES);
        h.update(&t.id0);
        let seed = h.finalize();

        let mut x = [0u8; 16];
        rc4(key, &seed, &mut x);
        let mut keyi = [0u8; 16];
        for i in 1u8..=19 {
            for b in 0..n {
                keyi[b] = key[b] ^ i;
            }
            let mut tmp = [0u8; 16];
            rc4(&keyi[..n], &x, &mut tmp);
            x = tmp;
        }
        x[..] == t.u[..16]
    }
}

/// R5/R6: hash the password with the 8-byte validation salt (Algorithm 2.B for
/// R6, plain SHA-256 for R5) and compare against the first 32 bytes of `/U`.
fn pdf_check_r5_r6(t: &PdfTarget, pw: &[u8]) -> bool {
    let pw = if pw.len() > 127 { &pw[..127] } else { pw };
    let salt = &t.u[32..40];
    let expected = &t.u[0..32];
    pdf_hash_2b(t.revision, pw, salt).as_slice() == expected
}

/// Algorithm 2.B hardened hash (ISO 32000-2). R5 short-circuits to a single
/// SHA-256. Mirrors the reference loop: 64+ rounds of (AES-128-CBC over 64×(pw||K),
/// then SHA-256/384/512 selected by the first 16 bytes of E mod 3), terminating
/// when the last byte of E is <= round-32.
fn pdf_hash_2b(revision: u8, pw: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut k = {
        let mut h = Sha256::new();
        h.update(pw);
        h.update(salt);
        h.finalize().to_vec()
    };
    if revision == 5 {
        return k;
    }

    let mut k1 = Vec::with_capacity(64 * (pw.len() + 64));
    for round in 1u32.. {
        k1.clear();
        for _ in 0..64 {
            k1.extend_from_slice(pw);
            k1.extend_from_slice(&k);
        }
        let mut enc = Aes128CbcEnc::new_from_slices(&k[0..16], &k[16..32]).unwrap();
        for block in k1.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = block.try_into().unwrap();
            enc.encrypt_block(block.into());
        }
        let e = k1;
        k = match e[..16].iter().map(|v| *v as u32).sum::<u32>() % 3 {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            2 => Sha512::digest(&e).to_vec(),
            _ => unreachable!(),
        };
        if round >= 64 && e.last().copied().unwrap_or(0) as u32 <= round - 32 {
            break;
        }
        k1 = e;
    }
    k.truncate(32);
    k
}

// ===== Full verification (filter false positives) =====

/// Returns false on any decode error — used to filter ZipCrypto check-byte
/// false positives (candidates that survive the 1-byte filter but don't
/// actually decrypt cleanly).
pub fn full_verify(zip_bytes: &[u8], entry_idx: usize, password: &[u8]) -> bool {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(zip_bytes)) else {
        return false;
    };
    let Ok(mut entry) = archive.by_index_decrypt(entry_idx, password) else {
        return false;
    };
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).is_ok()
}
