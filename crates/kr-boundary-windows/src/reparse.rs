//! What a folder's reparse data says about where a link leads, read from the bytes a platform call
//! returned. The bytes come from a folder that any account may have written, so every field is
//! checked against the length of the data before it is read.

/// The tag of a directory junction and of a volume mounted in a folder.
pub const MOUNT_POINT_TAG: u32 = 0xA000_0003;

/// How the target of a volume mounted in a folder starts, as the platform spells it.
const VOLUME_TARGET: &str = r"\??\Volume{";

/// The bytes before the mount point's own fields: the tag, the data's length and a reserved field.
const HEADER_BYTES: usize = 8;
/// The bytes of the four fields of a mount point's data that come before its path buffer.
const FIELD_BYTES: usize = 8;

fn u16_at(data: &[u8], at: usize) -> Option<usize> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

fn volume_mount(data: &[u8]) -> Option<bool> {
    let tag = data.get(..4)?;
    if u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]) != MOUNT_POINT_TAG {
        return Some(false);
    }
    let length = u16_at(data, 4)?;
    let body = data.get(HEADER_BYTES..HEADER_BYTES.checked_add(length)?)?;
    let offset = u16_at(body, 0)?;
    let size = u16_at(body, 2)?;
    let start = FIELD_BYTES.checked_add(offset)?;
    let name = body.get(start..start.checked_add(size)?)?;
    if name.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = name
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let wanted: Vec<u16> = VOLUME_TARGET.encode_utf16().collect();
    let head = units.get(..wanted.len())?;
    Some(
        head.iter()
            .zip(&wanted)
            .all(|(unit, expected)| lower(*unit) == lower(*expected)),
    )
}

fn lower(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

/// Whether reparse data is a mount point that leads to a volume (a volume mounted in a folder), and
/// not a junction to a folder. Data that is cut short, whose fields lie about their length, or
/// that is of another kind is not.
#[must_use]
pub fn is_volume_mount(data: &[u8]) -> bool {
    volume_mount(data).unwrap_or(false)
}
