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
    let zip_bytes = std::fs::read(path)?;
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
