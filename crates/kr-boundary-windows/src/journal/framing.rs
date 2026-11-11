//! The framing of the invocation journal's records.
//!
//! A record is a four-byte little-endian length, that many bytes, and a four-byte little-endian
//! CRC-32C of the length and the bytes together. Covering the length means a damaged length cannot
//! pass for a short record, and a region the file system zero-filled never reads as a valid one.
//!
//! The writer makes each record in one buffer so that it reaches the file in one write. A crash
//! can leave the last record cut short, so the reader treats a record that does not complete, a
//! last record whose checksum is wrong and a tail of zero bytes as a torn tail: it returns the
//! complete records before it and says how many bytes it dropped. A record that is not the last
//! and whose checksum is wrong cannot come from a cut write; the reader refuses the whole journal
//! and names the record. A length over [`MAX_RECORD`] is damage in the same way, since no writer
//! makes one. A length damaged to a smaller value that still ends before the journal's end fails
//! its checksum, but one damaged to point past the end reads as a cut record, because a cut record
//! is exactly a length whose bytes did not all arrive: the damage model is a torn write, not a
//! flipped bit in the middle of the file.
//!
//! This module knows nothing of what a record means, where the bytes live or when they are
//! durable.

/// The most bytes one record may carry.
pub const MAX_RECORD: usize = 1024 * 1024;

const LENGTH_BYTES: usize = 4;
const CHECKSUM_BYTES: usize = 4;

/// What the framing refuses.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    /// A record to write is longer than [`MAX_RECORD`].
    #[error("a record of {0} bytes is longer than the limit")]
    TooLong(usize),
    /// A record that is not the last is damaged.
    #[error("record {index} of the journal, at byte {offset}, is damaged")]
    Damaged {
        /// The record's position among the journal's records, counted from zero.
        index: usize,
        /// Where the record begins in the journal's bytes.
        offset: usize,
    },
}

/// The records a journal's bytes hold.
#[derive(Debug, PartialEq, Eq)]
pub struct Reading<'a> {
    /// The bytes of each complete record, in order.
    pub records: Vec<&'a [u8]>,
    /// How many bytes the complete records take. A writer that goes on appending first cuts the
    /// journal to this length.
    pub valid_len: usize,
}

impl Reading<'_> {
    /// How many bytes at the end were not a complete record.
    #[must_use]
    pub fn torn_len(&self, total: usize) -> usize {
        total - self.valid_len
    }
}

/// The CRC-32C (Castagnoli) of some bytes.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut state = !0_u32;
    for byte in bytes {
        state = TABLE[usize::from((state as u8) ^ byte)] ^ (state >> 8);
    }
    !state
}

/// The table of the reflected polynomial 0x1EDC6F41, made when the crate is compiled.
static TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0x82F6_3B78
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

/// Frames one record.
///
/// # Errors
///
/// Returns [`FramingError::TooLong`] for a record over [`MAX_RECORD`].
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if payload.len() > MAX_RECORD {
        return Err(FramingError::TooLong(payload.len()));
    }
    // MAX_RECORD fits a u32, so the conversion cannot fail once the check above has passed.
    let length = u32::try_from(payload.len()).map_err(|_| FramingError::TooLong(payload.len()))?;
    let mut record = Vec::with_capacity(LENGTH_BYTES + payload.len() + CHECKSUM_BYTES);
    record.extend_from_slice(&length.to_le_bytes());
    record.extend_from_slice(payload);
    let checksum = crc32c(&record);
    record.extend_from_slice(&checksum.to_le_bytes());
    Ok(record)
}

/// Reads every complete record in a journal's bytes.
///
/// # Errors
///
/// Returns [`FramingError::Damaged`] for a record before the tail whose checksum is wrong, or whose
/// length is over [`MAX_RECORD`].
pub fn read_all(bytes: &[u8]) -> Result<Reading<'_>, FramingError> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let damaged = FramingError::Damaged {
            index: records.len(),
            offset,
        };
        // Zero bytes are what the file system leaves where a write never landed.
        if rest.iter().all(|byte| *byte == 0) {
            break;
        }
        let Some(length) = rest.first_chunk::<LENGTH_BYTES>() else {
            break;
        };
        let length = u32::from_le_bytes(*length) as usize;
        if length > MAX_RECORD {
            return Err(damaged);
        }
        let total = LENGTH_BYTES + length + CHECKSUM_BYTES;
        if rest.len() < total {
            break;
        }
        let covered = &rest[..LENGTH_BYTES + length];
        let stored = u32::from_le_bytes([
            rest[total - 4],
            rest[total - 3],
            rest[total - 2],
            rest[total - 1],
        ]);
        if crc32c(covered) != stored {
            if rest.len() == total {
                break;
            }
            return Err(damaged);
        }
        records.push(&covered[LENGTH_BYTES..]);
        offset += total;
    }
    Ok(Reading {
        records,
        valid_len: offset,
    })
}
