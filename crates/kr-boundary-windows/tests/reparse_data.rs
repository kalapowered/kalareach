//! `reparse`: a mount point that leads to a volume is told from a junction by its reparse data, and
//! data that is cut short or lies about its own lengths is never read past its end.

use kr_boundary_windows::reparse::{MOUNT_POINT_TAG, is_volume_mount};

/// The reparse data of a mount point with this target and print name, as the platform lays it out.
fn mount_point(target: &str, print: &str) -> Vec<u8> {
    let target: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let print: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut body = Vec::new();
    body.extend(0_u16.to_le_bytes());
    body.extend(u16::try_from(target.len()).unwrap().to_le_bytes());
    body.extend(u16::try_from(target.len() + 2).unwrap().to_le_bytes());
    body.extend(u16::try_from(print.len()).unwrap().to_le_bytes());
    body.extend(&target);
    body.extend([0, 0]);
    body.extend(&print);
    body.extend([0, 0]);
    let mut data = Vec::new();
    data.extend(MOUNT_POINT_TAG.to_le_bytes());
    data.extend(u16::try_from(body.len()).unwrap().to_le_bytes());
    data.extend([0, 0]);
    data.extend(body);
    data
}

const VOLUME: &str = r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\";

#[test]
fn a_mount_point_to_a_volume_is_told_from_a_junction_to_a_folder() {
    assert!(is_volume_mount(&mount_point(VOLUME, VOLUME)));
    assert!(is_volume_mount(&mount_point(
        r"\??\volume{01234567-89ab-cdef-0123-456789abcdef}\",
        ""
    )));
    assert!(!is_volume_mount(&mount_point(r"\??\C:\real", r"C:\real")));
    assert!(!is_volume_mount(&mount_point(r"\??\Volume", "")));
    assert!(!is_volume_mount(&mount_point(r"\??\UNC\host\share", "")));
}

#[test]
fn data_of_another_kind_is_not_a_mount_point() {
    let mut symlink = mount_point(VOLUME, VOLUME);
    symlink[..4].copy_from_slice(&0xA000_000C_u32.to_le_bytes());
    assert!(!is_volume_mount(&symlink));
}

#[test]
fn data_that_is_cut_short_or_lies_about_its_lengths_is_not_read_past_its_end() {
    let whole = mount_point(VOLUME, VOLUME);
    for cut in 0..whole.len() {
        // The data's own length field says more than a cut copy holds.
        assert!(!is_volume_mount(&whole[..cut]), "a cut at {cut} bytes");
    }
    // The data's length field is larger than the bytes there are.
    let mut longer = whole.clone();
    longer[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(!is_volume_mount(&longer));
    // The target's offset and its length run past the data.
    let mut far = whole.clone();
    far[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(!is_volume_mount(&far));
    let mut wide = whole.clone();
    wide[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(!is_volume_mount(&wide));
    // An odd length cannot be a whole number of UTF-16 units.
    let mut odd = whole.clone();
    let length = u16::from_le_bytes([odd[10], odd[11]]) - 1;
    odd[10..12].copy_from_slice(&length.to_le_bytes());
    assert!(!is_volume_mount(&odd));
    assert!(!is_volume_mount(&[]));
}
