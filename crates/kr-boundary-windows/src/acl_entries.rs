//! The entries of a permission list, read from the bytes the platform returned for an object.
//!
//! Any account that may change an object's list chooses the bytes of its entries, and the list
//! may hold entries that no tool of this crate wrote, so nothing is read before the size that
//! says it is there: the list's own size and revision first, then each entry's size, then the
//! fields of the entry's type, then each identifier's revision and length. An entry of a type that
//! is not read keeps its type and its flags and nothing else, and says so; the Git folder refuses
//! an object with such an entry that could allow.

/// The revision of a list of the system's own kind and of one with entries for directory objects.
const REVISIONS: [u8; 2] = [2, 4];
/// The bytes of a list's header: the revision, a spare byte, the size, the count and a spare field.
const LIST_HEADER_BYTES: usize = 8;
/// The bytes of an entry's header: the type, the flags and the entry's size.
const ENTRY_HEADER_BYTES: usize = 4;
/// The most subordinate authorities an identifier has.
const MAX_SUBAUTHORITIES: usize = 15;
/// The bytes of an identifier before its subordinate authorities.
const SID_HEADER_BYTES: usize = 8;
/// The bytes of one globally unique identifier in an object entry.
const GUID_BYTES: usize = 16;

/// One entry of a permission list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The entry's type: 0 allows, 1 denies, 5 and 6 are their object forms, 9 and 10 their
    /// forms with a condition, 11 and 12 the two together.
    pub kind: u8,
    /// The entry's inheritance flags.
    pub flags: u8,
    /// The rights it names; none for an entry that is not read.
    pub mask: u32,
    /// Who it names, as text; empty for an entry that is not read.
    pub sid: String,
    /// Whether the type of the entry is one this module reads. An entry that is not read has no
    /// rights and no identifier here.
    pub understood: bool,
}

impl Entry {
    /// Whether the entry is of a type that is not read and could allow: the compound form that no
    /// tool of this crate writes, and any type that no version of the platform has defined. The
    /// types of the system access list (audit, alarm, label and the rest) allow nothing.
    #[must_use]
    pub fn unread_allow(&self) -> bool {
        !self.understood && (self.kind == 4 || self.kind > 0x15)
    }
}

/// The bytes of a list that does not fit its own sizes, or whose entry or identifier does not fit
/// its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

fn u16_at(bytes: &[u8], at: usize) -> Option<usize> {
    let field = bytes.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_le_bytes([field[0], field[1]])))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// The entries of a list, in order. `list` is the whole list: as many bytes as its own size field
/// says, and no more.
///
/// # Errors
///
/// Returns [`Malformed`] when the revision is not a known one, when the size field is not the
/// length of `list`, when an entry is smaller than its header, not a whole number of 32-bit
/// words or longer than the bytes left, when an entry's fields or its identifier do not fit the
/// entry, and when an identifier has another revision than 1 or more than 15 subordinate
/// authorities.
pub fn entries(list: &[u8]) -> Result<Vec<Entry>, Malformed> {
    let revision = *list.first().ok_or(Malformed)?;
    let size = u16_at(list, 2).ok_or(Malformed)?;
    if !REVISIONS.contains(&revision) || size < LIST_HEADER_BYTES || size != list.len() {
        return Err(Malformed);
    }
    let count = u16_at(list, 4).ok_or(Malformed)?;
    let mut offset = LIST_HEADER_BYTES;
    let mut found = Vec::new();
    for _ in 0..count {
        let entry_size = u16_at(list, offset.checked_add(2).ok_or(Malformed)?).ok_or(Malformed)?;
        if entry_size < ENTRY_HEADER_BYTES || entry_size % 4 != 0 {
            return Err(Malformed);
        }
        let end = offset.checked_add(entry_size).ok_or(Malformed)?;
        found.push(entry(list.get(offset..end).ok_or(Malformed)?)?);
        offset = end;
    }
    Ok(found)
}

/// One entry, whole: its header says its type and flags, and its size is the length of `bytes`.
fn entry(bytes: &[u8]) -> Result<Entry, Malformed> {
    let (kind, flags) = (bytes[0], bytes[1]);
    // The plain forms (allow, deny, audit and alarm, and the same with a condition) put the
    // identifier right after the mask; the object forms put two optional identifiers of object
    // types between a flags word and it.
    let object = match kind {
        0..=3 | 9 | 0xA | 0xD | 0xE => false,
        5..=8 | 0xB | 0xC | 0xF | 0x10 => true,
        _ => {
            return Ok(Entry {
                kind,
                flags,
                mask: 0,
                sid: String::new(),
                understood: false,
            });
        }
    };
    let mask = u32_at(bytes, 4).ok_or(Malformed)?;
    let mut at = 8;
    if object {
        let present = u32_at(bytes, 8).ok_or(Malformed)?;
        if present & !3 != 0 {
            return Err(Malformed);
        }
        at = 12;
        if present & 1 != 0 {
            at += GUID_BYTES;
        }
        if present & 2 != 0 {
            at += GUID_BYTES;
        }
    }
    Ok(Entry {
        kind,
        flags,
        mask,
        sid: sid_text(bytes.get(at..).ok_or(Malformed)?)?,
        understood: true,
    })
}

/// An identifier at the start of `bytes`, as text, in the platform's own form: `S-1-`, the
/// authority (a number, or twelve hexadecimal digits after `0x` when it has more than 32 bits),
/// and each subordinate authority.
fn sid_text(bytes: &[u8]) -> Result<String, Malformed> {
    if bytes.len() < SID_HEADER_BYTES || bytes[0] != 1 {
        return Err(Malformed);
    }
    let count = usize::from(bytes[1]);
    if count > MAX_SUBAUTHORITIES || bytes.len() < SID_HEADER_BYTES + 4 * count {
        return Err(Malformed);
    }
    let authority = &bytes[2..8];
    let mut text = String::from("S-1-");
    if authority[0] == 0 && authority[1] == 0 {
        let low = u32::from_be_bytes([authority[2], authority[3], authority[4], authority[5]]);
        text.push_str(&low.to_string());
    } else {
        text.push_str("0x");
        for byte in authority {
            text.push_str(&format!("{byte:02x}"));
        }
    }
    for index in 0..count {
        let sub = u32_at(bytes, SID_HEADER_BYTES + 4 * index).ok_or(Malformed)?;
        text.push('-');
        text.push_str(&sub.to_string());
    }
    Ok(text)
}
