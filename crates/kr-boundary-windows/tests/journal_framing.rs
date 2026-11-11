//! The journal's record framing against real bytes: the checksum's published vectors, the exact
//! bytes of a record, a record cut at every offset, and each kind of damage.

use kr_boundary_windows::journal::framing::{FramingError, MAX_RECORD, crc32c, encode, read_all};

fn journal(payloads: &[&[u8]]) -> Vec<u8> {
    payloads
        .iter()
        .flat_map(|payload| encode(payload).unwrap())
        .collect()
}

#[test]
fn the_checksum_is_crc_32c() {
    // The Castagnoli check value and the vectors of RFC 3720, appendix B.4.
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c(&[0_u8; 32]), 0x8A91_36AA);
    assert_eq!(crc32c(&[0xFF_u8; 32]), 0x62A8_AB43);
    let ascending: Vec<u8> = (0..32).collect();
    assert_eq!(crc32c(&ascending), 0x46DD_794E);
    assert_eq!(crc32c(b""), 0);
}

#[test]
fn a_record_is_its_length_its_bytes_and_a_checksum_of_both() {
    // The length is little-endian, and the checksum covers the length, so these eight bytes are
    // what any writer must produce for the two bytes "ok".
    let record = encode(b"ok").unwrap();
    assert_eq!(&record[..6], [2, 0, 0, 0, b'o', b'k']);
    let expected = crc32c(&[2, 0, 0, 0, b'o', b'k']);
    assert_eq!(&record[6..], expected.to_le_bytes());
    assert_eq!(record.len(), 10);
}

#[test]
fn records_come_back_in_order_with_nothing_dropped() {
    let bytes = journal(&[b"begin", b"", b"a longer row with \0 and \n inside", b"end"]);
    let reading = read_all(&bytes).unwrap();
    assert_eq!(
        reading.records,
        [
            b"begin".as_slice(),
            b"".as_slice(),
            b"a longer row with \0 and \n inside".as_slice(),
            b"end".as_slice()
        ]
    );
    assert_eq!(reading.valid_len, bytes.len());
    assert_eq!(reading.torn_len(bytes.len()), 0);
    assert!(read_all(b"").unwrap().records.is_empty());
}

#[test]
fn a_last_record_cut_at_any_offset_is_dropped_and_the_earlier_ones_stay() {
    let first = journal(&[b"begin", b"middle"]);
    let last = encode(b"the row a crash cut").unwrap();
    for cut in 0..last.len() {
        let mut bytes = first.clone();
        bytes.extend_from_slice(&last[..cut]);
        let reading = read_all(&bytes).unwrap_or_else(|error| panic!("cut {cut}: {error}"));
        assert_eq!(reading.records, [b"begin".as_slice(), b"middle".as_slice()]);
        assert_eq!(reading.valid_len, first.len(), "cut {cut}");
        assert_eq!(reading.torn_len(bytes.len()), cut);
    }
    let mut whole = first.clone();
    whole.extend_from_slice(&last);
    assert_eq!(read_all(&whole).unwrap().records.len(), 3);
}

#[test]
fn a_last_record_with_a_wrong_checksum_is_a_torn_tail() {
    let first = journal(&[b"begin"]);
    let mut last = encode(b"half written").unwrap();
    let end = last.len();
    last[end - 1] ^= 0x01;
    let mut bytes = first.clone();
    bytes.extend_from_slice(&last);
    let reading = read_all(&bytes).unwrap();
    assert_eq!(reading.records, [b"begin".as_slice()]);
    assert_eq!(reading.valid_len, first.len());
}

#[test]
fn a_tail_of_zero_bytes_is_a_torn_tail() {
    let first = journal(&[b"begin", b"middle"]);
    for zeros in [1_usize, 3, 4, 7, 8, 9, 64, 4096] {
        let mut bytes = first.clone();
        bytes.extend(std::iter::repeat_n(0_u8, zeros));
        let reading = read_all(&bytes).unwrap_or_else(|error| panic!("{zeros} zeros: {error}"));
        assert_eq!(reading.records.len(), 2, "{zeros} zeros");
        assert_eq!(reading.valid_len, first.len(), "{zeros} zeros");
    }
}

#[test]
fn a_damaged_record_before_the_tail_names_its_index() {
    let payloads: [&[u8]; 4] = [b"zero", b"one", b"two", b"three"];
    let whole = journal(&payloads);
    let mut offsets = Vec::new();
    let mut at = 0;
    for payload in payloads {
        offsets.push(at);
        at += payload.len() + 8;
    }
    // One flipped bit in the length's low byte, the bytes or the checksum of any record but the
    // last. (A length flipped to point past the journal's end reads as a cut record: the module's
    // documentation names that limit.)
    for index in 0..payloads.len() - 1 {
        let record_len = payloads[index].len() + 8;
        for byte in (0..record_len).filter(|byte| !(1..4).contains(byte)) {
            let mut bytes = whole.clone();
            bytes[offsets[index] + byte] ^= 0x01;
            assert_eq!(
                read_all(&bytes),
                Err(FramingError::Damaged {
                    index,
                    offset: offsets[index]
                }),
                "record {index}, byte {byte}"
            );
        }
    }
}

#[test]
fn a_length_over_the_limit_is_damage_not_a_tail() {
    let mut bytes = journal(&[b"begin"]);
    let length = u32::try_from(MAX_RECORD + 1).unwrap();
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(b"only a few bytes follow");
    assert_eq!(
        read_all(&bytes),
        Err(FramingError::Damaged {
            index: 1,
            offset: 13
        })
    );
}

#[test]
fn a_record_may_be_as_long_as_the_limit_and_no_longer() {
    let payload = vec![0xA5_u8; MAX_RECORD];
    let framed = encode(&payload).unwrap();
    let reading = read_all(&framed).unwrap();
    assert_eq!(reading.records.len(), 1);
    assert_eq!(reading.records[0], payload.as_slice());
    assert_eq!(
        encode(&vec![0_u8; MAX_RECORD + 1]),
        Err(FramingError::TooLong(MAX_RECORD + 1))
    );
}
