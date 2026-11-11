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
//! and whose checksum is wrong cannot come from a cut write, and neither can a length over
//! [`MAX_RECORD`] or a length that runs past the end of the journal while a valid record follows
//! it: the reader returns the records before the damage and the damage, so that the invocation's
//! first rows are still known. A cut record is the last thing in the file, so a valid record found
//! after a record that does not complete shows the length is damaged and nothing was cut.
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
    /// A record that is not a torn tail is damaged.
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
    /// The bytes of each complete record before any damage, in order.
    pub records: Vec<&'a [u8]>,
    /// How many bytes the complete records take. A writer that goes on appending first cuts the
    /// journal to this length.
    pub valid_len: usize,
    /// The damage that ended the reading, when the bytes after the records are not a torn tail.
    pub damage: Option<FramingError>,
}

impl Reading<'_> {
    /// How many bytes at the end were a torn record: none when the journal is damaged.
    #[must_use]
    pub fn torn_len(&self, total: usize) -> usize {
        if self.damage.is_some() {
            0
        } else {
            total - self.valid_len
        }
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

/// Whether a valid record begins after the first record's own length and checksum within `rest`.
///
/// It is asked only of bytes that end before the length at their start says they should, so `rest`
/// is shorter than one record can be and the search is bounded by that: it tries each starting
/// point whose length is plausible and checks one record's checksum there.
fn a_valid_record_follows(rest: &[u8]) -> bool {
    for start in LENGTH_BYTES + CHECKSUM_BYTES..rest.len() {
        let Some(length) = rest[start..].first_chunk::<LENGTH_BYTES>() else {
            break;
        };
        let length = u32::from_le_bytes(*length) as usize;
        if length == 0 || length > MAX_RECORD {
            continue;
        }
        let total = LENGTH_BYTES + length + CHECKSUM_BYTES;
        let Some(record) = rest[start..].get(..total) else {
            continue;
        };
        let stored = u32::from_le_bytes([
            record[total - 4],
            record[total - 3],
            record[total - 2],
            record[total - 1],
        ]);
        if crc32c(&record[..total - CHECKSUM_BYTES]) == stored {
            return true;
        }
    }
    false
}

/// Reads every complete record in a journal's bytes, and says how the reading ended.
///
/// A torn tail ends the reading with no damage. A record before the tail whose checksum is wrong,
/// a length over [`MAX_RECORD`] and a length that runs past the end while a valid record follows
/// it end it with [`FramingError::Damaged`], and the records before that point are returned.
#[must_use]
pub fn read_all(bytes: &[u8]) -> Reading<'_> {
    let mut records = Vec::new();
    let mut offset = 0;
    let mut damage = None;
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
            damage = Some(damaged);
            break;
        }
        let total = LENGTH_BYTES + length + CHECKSUM_BYTES;
        if rest.len() < total {
            if a_valid_record_follows(rest) {
                damage = Some(damaged);
            }
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
            if rest.len() != total {
                damage = Some(damaged);
            }
            break;
        }
        records.push(&covered[LENGTH_BYTES..]);
        offset += total;
    }
    Reading {
        records,
        valid_len: offset,
        damage,
    }
}
