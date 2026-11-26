//! `acl_entries`: the entries of a permission list are read by their type, and nothing is read
//! before the size that says it is there.

use kr_boundary_windows::acl_entries::{Entry, Malformed, entries};

/// An identifier's bytes: revision 1, the authority and the subordinate authorities.
fn sid(authority: u64, subs: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, u8::try_from(subs.len()).unwrap()];
    bytes.extend(&authority.to_be_bytes()[2..]);
    for sub in subs {
        bytes.extend(sub.to_le_bytes());
    }
    bytes
}

/// One entry: its type, its flags and its body, with the size that holds them whole.
fn ace(kind: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let size = (4 + body.len()).div_ceil(4) * 4;
    let mut bytes = vec![kind, flags];
    bytes.extend(u16::try_from(size).unwrap().to_le_bytes());
    bytes.extend(body);
    bytes.resize(size, 0);
    bytes
}

fn plain(kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut body = mask.to_le_bytes().to_vec();
    body.extend(sid);
    ace(kind, flags, &body)
}

/// An object entry: the mask, the flags word that says which object types follow, those types
/// (sixteen bytes each, with a value that no identifier shares) and the identifier.
fn object(kind: u8, mask: u32, present: u32, sid: &[u8]) -> Vec<u8> {
    let mut body = mask.to_le_bytes().to_vec();
    body.extend(present.to_le_bytes());
    for _ in 0..(present & 1) + ((present >> 1) & 1) {
        body.extend([0xA5; 16]);
    }
    body.extend(sid);
    ace(kind, 0, &body)
}

fn list(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![revision, 0];
    bytes.extend(u16::try_from(size).unwrap().to_le_bytes());
    bytes.extend(u16::try_from(aces.len()).unwrap().to_le_bytes());
    bytes.extend([0, 0]);
    for entry in aces {
        bytes.extend(entry);
    }
    bytes
}

const SYSTEM: u64 = 5;
const OTHER: &[u32] = &[21, 1, 2, 3, 1001];

#[test]
fn a_plain_entry_has_its_mask_and_identifier_right_after_its_header() {
    let read = entries(&list(
        2,
        &[
            plain(0, 0, 0x1f01ff, &sid(SYSTEM, &[18])),
            plain(1, 0x08, 0x2, &sid(SYSTEM, &[32, 544])),
        ],
    ))
    .unwrap();
    assert_eq!(
        read,
        [
            Entry {
                kind: 0,
                flags: 0,
                mask: 0x1f01ff,
                sid: "S-1-5-18".to_owned(),
                understood: true
            },
            Entry {
                kind: 1,
                flags: 0x08,
                mask: 0x2,
                sid: "S-1-5-32-544".to_owned(),
                understood: true
            },
        ]
    );
    // An entry with a condition has the identifier at the same place, and the condition's bytes
    // after it are not read as part of it.
    let mut condition = plain(9, 0, 0x2, &sid(SYSTEM, OTHER));
    condition.extend([0xFF; 8]);
    let size = u16::try_from(condition.len()).unwrap();
    condition[2..4].copy_from_slice(&size.to_le_bytes());
    let read = entries(&list(4, &[condition])).unwrap();
    assert_eq!(read[0].sid, "S-1-5-21-1-2-3-1001");
    assert!(read[0].understood);
}

#[test]
fn an_object_entry_has_its_identifier_after_the_object_types_it_names() {
    for kind in [5, 6, 7, 8, 0xB, 0xC, 0xF, 0x10] {
        for present in 0..=3 {
            let read = entries(&list(4, &[object(kind, 0x2, present, &sid(SYSTEM, OTHER))]))
                .unwrap_or_else(|_| panic!("type {kind:#x} with {present} is read"));
            assert_eq!(read.len(), 1);
            assert_eq!(
                read[0].sid, "S-1-5-21-1-2-3-1001",
                "type {kind:#x}, object types {present}"
            );
            assert_eq!(read[0].mask, 0x2);
            assert!(read[0].understood, "type {kind:#x}");
        }
    }
}

#[test]
fn an_entry_of_a_type_that_is_not_read_says_so_and_only_one_that_could_allow_is_unread_allow() {
    for kind in [4_u8, 0x16, 0x40, 0xFF] {
        let read = entries(&list(2, &[ace(kind, 3, &[1, 2, 3, 4, 5, 6, 7, 8])])).unwrap();
        assert!(!read[0].understood, "type {kind:#x}");
        assert_eq!((read[0].mask, read[0].sid.as_str()), (0, ""));
        assert_eq!((read[0].kind, read[0].flags), (kind, 3));
        assert!(read[0].unread_allow(), "type {kind:#x} could allow");
    }
    // The types of the system access list are not read and allow nothing.
    for kind in 0x11_u8..=0x15 {
        let read = entries(&list(2, &[ace(kind, 0, &[0; 8])])).unwrap();
        assert!(!read[0].understood, "type {kind:#x}");
        assert!(!read[0].unread_allow(), "type {kind:#x} allows nothing");
    }
    // A type that is read is never unread.
    let read = entries(&list(2, &[plain(0, 0, 1, &sid(SYSTEM, &[18]))])).unwrap();
    assert!(!read[0].unread_allow());
}

#[test]
fn an_identifier_is_written_as_the_platform_writes_it() {
    let text = |authority: u64, subs: &[u32]| {
        entries(&list(2, &[plain(0, 0, 1, &sid(authority, subs))])).unwrap()[0]
            .sid
            .clone()
    };
    assert_eq!(text(1, &[0]), "S-1-1-0");
    assert_eq!(text(3, &[1]), "S-1-3-1");
    assert_eq!(text(9, &[0x4B52_4247, 1, 2, 3]), "S-1-9-1263682119-1-2-3");
    assert_eq!(text(0x0001_0000_0000, &[7]), "S-1-0x000100000000-7");
    assert_eq!(text(5, &[]), "S-1-5");
}

#[test]
fn a_list_cut_short_is_refused_at_every_length() {
    let whole = list(
        2,
        &[
            plain(0, 0, 1, &sid(SYSTEM, &[18])),
            object(5, 2, 3, &sid(SYSTEM, OTHER)),
            plain(1, 0, 4, &sid(1, &[0])),
        ],
    );
    assert!(entries(&whole).is_ok());
    for cut in 0..whole.len() {
        let mut part = whole[..cut].to_vec();
        // The list that says it is cut where it is cut: its size field fits, its entries do not.
        if part.len() >= 4 {
            part[2..4].copy_from_slice(&u16::try_from(cut).unwrap().to_le_bytes());
        }
        assert_eq!(entries(&part), Err(Malformed), "a list of {cut} bytes");
        // And the whole size field with fewer bytes than it says.
        assert_eq!(
            entries(&whole[..cut]),
            Err(Malformed),
            "{cut} bytes of a list that says {}",
            whole.len()
        );
    }
}

#[test]
fn a_size_that_lies_is_refused() {
    let one = plain(0, 0, 1, &sid(SYSTEM, &[18]));
    let good = list(2, std::slice::from_ref(&one));
    assert!(entries(&good).is_ok());
    let with = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = good.clone();
        edit(&mut bytes);
        entries(&bytes)
    };
    // The list's own revision and size.
    assert_eq!(with(&|b| b[0] = 3), Err(Malformed));
    assert_eq!(with(&|b| b[0] = 0), Err(Malformed));
    assert_eq!(
        with(&|b| b[2..4].copy_from_slice(&7_u16.to_le_bytes())),
        Err(Malformed)
    );
    assert_eq!(
        with(&|b| b[2..4].copy_from_slice(&u16::MAX.to_le_bytes())),
        Err(Malformed)
    );
    assert_eq!(
        with(&|b| {
            let size = u16::try_from(b.len() + 4).unwrap();
            b[2..4].copy_from_slice(&size.to_le_bytes());
        }),
        Err(Malformed),
        "a size that is longer than the bytes"
    );
    // More entries than the list holds.
    assert_eq!(
        with(&|b| b[4..6].copy_from_slice(&2_u16.to_le_bytes())),
        Err(Malformed)
    );
    assert_eq!(
        with(&|b| b[4..6].copy_from_slice(&u16::MAX.to_le_bytes())),
        Err(Malformed)
    );
    // The entry's own size: under its header, not a whole number of words, past the list, and
    // past the largest an entry can have.
    for size in [0_u16, 1, 3, 4, 5, 6, 7, 8, 12, 24, 4096, u16::MAX] {
        assert_eq!(
            with(&|b| b[10..12].copy_from_slice(&size.to_le_bytes())),
            Err(Malformed),
            "an entry that says {size} bytes in a list of {}",
            good.len()
        );
    }
    // A size under the entry's own fields: the identifier no longer fits it.
    let small = plain(0, 0, 1, &sid(SYSTEM, &[18, 19, 20]));
    let mut bytes = list(2, &[small]);
    assert!(entries(&bytes).is_ok());
    bytes[10..12].copy_from_slice(&12_u16.to_le_bytes());
    assert_eq!(entries(&bytes), Err(Malformed));
}

#[test]
fn an_identifier_that_does_not_fit_is_refused() {
    let bad = |bytes: Vec<u8>| entries(&list(2, &[plain(0, 0, 1, &bytes)]));
    assert!(bad(sid(SYSTEM, &[18])).is_ok());
    // Revision 2, and 16 subordinate authorities (the most is 15).
    let mut other = sid(SYSTEM, &[18]);
    other[0] = 2;
    assert_eq!(bad(other), Err(Malformed));
    assert_eq!(bad(sid(SYSTEM, &[1; 16])), Err(Malformed));
    assert!(bad(sid(SYSTEM, &[1; 15])).is_ok());
    // More subordinate authorities than the entry has bytes for: the count says 15 and holds 1.
    let mut lying = sid(SYSTEM, &[18]);
    lying[1] = 15;
    assert_eq!(bad(lying), Err(Malformed));
    // No identifier at all.
    assert_eq!(bad(Vec::new()), Err(Malformed));
    assert_eq!(bad(vec![1, 0, 0, 0]), Err(Malformed));
}

#[test]
fn an_object_entry_whose_fields_do_not_fit_or_name_an_unknown_part_is_refused() {
    let good = object(5, 2, 3, &sid(SYSTEM, &[18]));
    assert!(entries(&list(4, std::slice::from_ref(&good))).is_ok());
    // A flags word with a bit that no object type goes with.
    let mut unknown = good.clone();
    unknown[8] = 4;
    assert_eq!(entries(&list(4, &[unknown])), Err(Malformed));
    // Object types that the entry has no room for: the flags say two, and the entry holds none.
    let mut room = object(5, 2, 0, &sid(SYSTEM, &[18]));
    room[8] = 3;
    assert_eq!(entries(&list(4, &[room])), Err(Malformed));
    // An entry that ends inside its mask or its flags word.
    for body in [
        &[][..],
        &[1, 2][..],
        &[1, 2, 3, 4][..],
        &[1, 2, 3, 4, 0, 0][..],
    ] {
        for kind in [0_u8, 1, 5, 9, 0xB] {
            assert_eq!(
                entries(&list(4, &[ace(kind, 0, body)])),
                Err(Malformed),
                "type {kind:#x}, body {body:?}"
            );
        }
    }
}
