//! The frames of a terminal-input stream: what a client writes and what the host answers.
//!
//! The wire values are written here by hand, member by member, and are not read off the types, so
//! a change to a name, a tag or a number's form fails against what a peer sends. Each message is
//! read from its KR-CBOR-1 wire value and written back as the same bytes, the JSON the schema
//! names is read, and what a message has no place for is refused: a member it does not have, a
//! member it lacks, a null where the count is a plain number.

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{InputLeaseEpoch, InputSequence};
use kr_protocol::input::{
    INPUT_FRAME_OVERHEAD, InputAck, InputClaim, InputFrame, InputWindow, PASTE_END_LEN,
    input_claim, max_input_bytes,
};
use kr_protocol::scalars::{Bytes, Nullable, U64};
use kr_protocol::wire::WireMessage;
use serde_json::json;

fn map(members: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    let mut map = CanonicalMap::new();
    for (name, value) in members {
        map.insert(name.to_owned(), value).expect("a new member");
    }
    CanonicalValue::Map(map)
}

fn number(value: u64) -> CanonicalValue {
    CanonicalValue::integer(value.into()).expect("a number")
}

fn text(value: &str) -> CanonicalValue {
    CanonicalValue::Text(value.to_owned())
}

/// Reads a message from the wire value, and writes the value back as the same bytes.
fn reads_and_writes_back<T: WireMessage + PartialEq + std::fmt::Debug>(
    wire: &CanonicalValue,
    expected: &T,
) {
    let sent = ParamsValue::new(wire.clone());
    let read: T = sent.to_typed().expect("the wire value reads");
    assert_eq!(&read, expected);
    let written = ParamsValue::from_typed(&read).expect("it writes");
    assert_eq!(
        kr_cbor::encode(written.as_value()),
        kr_cbor::encode(wire),
        "the value is written back as the bytes it was read from"
    );
}

fn is_refused<T: WireMessage>(wire: CanonicalValue) -> bool {
    ParamsValue::new(wire).to_typed::<T>().is_err()
}

fn frame_wire(epoch: u64, sequence: u64, bytes: &[u8]) -> CanonicalValue {
    map(vec![
        ("epoch", number(epoch)),
        ("sequence", number(sequence)),
        ("bytes", CanonicalValue::Bytes(bytes.to_vec())),
    ])
}

fn window_wire(frames: u64, bytes: u64) -> CanonicalValue {
    map(vec![("frames", number(frames)), ("bytes", number(bytes))])
}

/// A frame carries the lease epoch, the position and the bytes, and nothing else.
#[test]
fn a_frame_reads_from_the_wire_and_writes_back_unchanged() {
    reads_and_writes_back(
        &frame_wire(3, 7, b"\x1b[A\xffq"),
        &InputFrame {
            epoch: InputLeaseEpoch::new(3),
            sequence: InputSequence::new(7),
            bytes: Bytes::new(b"\x1b[A\xffq".to_vec()),
        },
    );
    let from_json: InputFrame = serde_json::from_value(json!({
        "epoch": "3",
        "sequence": "7",
        "bytes": kr_protocol::scalars::to_base64url(b"q"),
    }))
    .expect("the JSON the schema names reads");
    assert_eq!(from_json.bytes, Bytes::new(b"q".to_vec()));
    assert_eq!(from_json.epoch, InputLeaseEpoch::new(3));
}

#[test]
fn a_frame_refuses_what_it_has_no_place_for() {
    // A member it does not have, one of its three missing, and the bytes written as text.
    assert!(is_refused::<InputFrame>(map(vec![
        ("epoch", number(3)),
        ("sequence", number(7)),
        ("bytes", CanonicalValue::Bytes(vec![1])),
        ("input", text("bytes")),
    ])));
    for missing in ["epoch", "sequence", "bytes"] {
        let CanonicalValue::Map(whole) = frame_wire(3, 7, b"q") else {
            unreachable!("a map");
        };
        let kept: Vec<(String, CanonicalValue)> = whole
            .into_entries()
            .into_iter()
            .filter(|(name, _)| name != missing)
            .collect();
        let mut rebuilt = CanonicalMap::new();
        for (name, value) in kept {
            rebuilt.insert(name, value).expect("a new member");
        }
        assert!(
            is_refused::<InputFrame>(CanonicalValue::Map(rebuilt)),
            "a frame without {missing} is refused"
        );
    }
    assert!(is_refused::<InputFrame>(map(vec![
        ("epoch", number(3)),
        ("sequence", number(7)),
        ("bytes", text("q")),
    ])));
}

/// The key bytes of one frame never make the frame's encoding longer than the stream's limit, and
/// one byte more does. The overhead is what the one shape costs at its widest: the largest epoch
/// and sequence, and a byte string long enough for a three-byte head.
#[test]
fn the_most_a_frame_holds_is_exact_at_the_floor_and_at_the_ceiling() {
    let encoded_len = |keys: usize| {
        let frame = InputFrame {
            epoch: InputLeaseEpoch::new(u64::MAX),
            sequence: InputSequence::new(u64::MAX),
            bytes: Bytes::new(vec![0x61; keys]),
        };
        kr_cbor::encode(
            ParamsValue::from_typed(&frame)
                .expect("it writes")
                .as_value(),
        )
        .len()
    };
    assert_eq!(
        encoded_len(1000) - 1000,
        INPUT_FRAME_OVERHEAD,
        "the overhead is what the widest frame adds to its bytes"
    );
    for limit in [1024, 4096, 64 * 1024] {
        let most = max_input_bytes(limit);
        assert_eq!(
            encoded_len(most) + 4,
            limit,
            "the most fits the limit with its four-byte prefix, to the byte"
        );
        assert_eq!(
            encoded_len(most + 1) + 4,
            limit + 1,
            "one more byte does not fit"
        );
    }
}

/// What the worker holds for one accepted frame: two entries, since the recogniser can add one of
/// its own, and the bytes with the longest delimiter the worker may add.
#[test]
fn a_frames_claim_is_two_entries_and_its_bytes_with_the_delimiter() {
    assert_eq!(PASTE_END_LEN, 6);
    assert_eq!(
        input_claim(0),
        InputClaim {
            frames: 2,
            bytes: 6
        }
    );
    assert_eq!(
        input_claim(1000),
        InputClaim {
            frames: 2,
            bytes: 1006
        }
    );
    assert_eq!(input_claim(usize::MAX).bytes, usize::MAX, "it saturates");
}

fn error() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::LeaseLost,
        "This view no longer controls the program.",
    )
}

/// Each form of an answer reads from its wire value and writes back unchanged.
#[test]
fn every_answer_reads_from_the_wire_and_writes_back_unchanged() {
    reads_and_writes_back(
        &map(vec![
            ("kind", text("ready")),
            ("window", window_wire(32, 524_288)),
        ]),
        &InputAck::Ready {
            window: InputWindow {
                frames: 32,
                bytes: U64::new(524_288),
            },
        },
    );
    reads_and_writes_back(
        &map(vec![
            ("kind", text("accepted")),
            ("epoch", number(3)),
            ("through", number(41)),
        ]),
        &InputAck::Accepted {
            epoch: InputLeaseEpoch::new(3),
            through: InputSequence::new(41),
        },
    );
    reads_and_writes_back(
        &map(vec![
            ("kind", text("launch_reserved")),
            ("launch", number(9)),
        ]),
        &InputAck::LaunchReserved { launch: 9 },
    );
    reads_and_writes_back(
        &map(vec![
            ("kind", text("epoch_ended")),
            ("epoch", number(3)),
            ("fenced_bytes", number(512)),
        ]),
        &InputAck::EpochEnded {
            epoch: InputLeaseEpoch::new(3),
            fenced_bytes: U64::new(512),
        },
    );
}

/// A refusal names the first refused frame and the prefix that was accepted before it, which is
/// null when nothing of the epoch was accepted.
#[test]
fn a_refusal_carries_the_accepted_prefix_or_null() {
    for (accepted_through, wire) in [
        (Nullable::some(InputSequence::new(4)), number(4)),
        (Nullable::null(), CanonicalValue::Null),
    ] {
        let refused = InputAck::Refused {
            epoch: InputLeaseEpoch::new(3),
            sequence: InputSequence::new(5),
            accepted_through,
            error: error(),
        };
        let value = ParamsValue::from_typed(&refused).expect("it writes");
        let CanonicalValue::Map(members) = value.as_value() else {
            panic!("a map");
        };
        assert_eq!(members.get("kind"), Some(&text("refused")));
        assert_eq!(members.get("epoch"), Some(&number(3)));
        assert_eq!(members.get("sequence"), Some(&number(5)));
        assert_eq!(members.get("accepted_through"), Some(&wire));
        let read: InputAck = value.to_typed().expect("it reads back");
        assert_eq!(read, refused);
    }
}

/// An answer is closed: a member it has no place for, a tag it does not know, and a null where the
/// count of bytes a lease's end discarded is a plain number are all refused.
#[test]
fn an_answer_refuses_what_it_has_no_place_for() {
    let forms: Vec<(&str, Vec<(&str, CanonicalValue)>)> = vec![
        ("ready", vec![("window", window_wire(32, 524_288))]),
        (
            "accepted",
            vec![("epoch", number(3)), ("through", number(4))],
        ),
        ("launch_reserved", vec![("launch", number(9))]),
        (
            "epoch_ended",
            vec![("epoch", number(3)), ("fenced_bytes", number(0))],
        ),
    ];
    for (kind, members) in forms {
        let mut with_extra = vec![("kind", text(kind))];
        with_extra.extend(members.iter().map(|(name, value)| (*name, value.clone())));
        assert!(
            !is_refused::<InputAck>(map(with_extra.clone())),
            "{kind} reads as it is"
        );
        with_extra.push(("reason", text("takeover")));
        assert!(
            is_refused::<InputAck>(map(with_extra)),
            "{kind} has no place for another member"
        );
    }
    assert!(is_refused::<InputAck>(map(vec![("kind", text("ended"))])));
    assert!(is_refused::<InputAck>(map(vec![
        ("kind", text("epoch_ended")),
        ("epoch", number(3)),
        ("fenced_bytes", CanonicalValue::Null),
    ])));
    assert!(is_refused::<InputAck>(map(vec![
        ("kind", text("epoch_ended")),
        ("epoch", number(3)),
    ])));
}

#[test]
fn an_answer_reads_from_the_json_the_schema_names() {
    let read: InputAck = serde_json::from_value(json!({
        "kind": "epoch_ended",
        "epoch": "3",
        "fenced_bytes": "512",
    }))
    .expect("the JSON the schema names reads");
    assert_eq!(
        read,
        InputAck::EpochEnded {
            epoch: InputLeaseEpoch::new(3),
            fenced_bytes: U64::new(512),
        }
    );
    let ready = serde_json::to_value(InputAck::Ready {
        window: InputWindow {
            frames: 32,
            bytes: U64::new(524_288),
        },
    })
    .expect("it writes");
    assert_eq!(
        ready,
        json!({ "kind": "ready", "window": { "frames": 32, "bytes": "524288" } })
    );
}

/// The window is the client's own: the most it may have written to the stream and not had accepted.
#[test]
fn the_window_reads_from_the_wire_and_refuses_a_third_member() {
    reads_and_writes_back(
        &window_wire(32, 524_288),
        &InputWindow {
            frames: 32,
            bytes: U64::new(524_288),
        },
    );
    assert!(is_refused::<InputWindow>(map(vec![
        ("frames", number(32)),
        ("bytes", number(1)),
        ("epoch", number(1)),
    ])));
    assert!(is_refused::<InputWindow>(map(vec![
        ("frames", number(u64::from(u32::MAX) + 1)),
        ("bytes", number(1)),
    ])));
}

/// A frame's debug form says how much it holds and never what: it carries what a person typed.
#[test]
fn a_frame_never_shows_its_bytes() {
    let frame = InputFrame {
        epoch: InputLeaseEpoch::new(1),
        sequence: InputSequence::new(0),
        bytes: Bytes::new(b"hunter2".to_vec()),
    };
    let shown = format!("{frame:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(!shown.contains("104"), "{shown}");
    assert!(shown.contains('7'), "{shown}");
}
