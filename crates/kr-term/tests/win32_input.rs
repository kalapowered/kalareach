//! The ConPTY win32 input mode: where its requests stop, and what a record is encoded as.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-08.51 | The byte-preservation promise starts at ConPTY's output pipe |
//! | KR-REQ-08.52 | The encoding, the final underscore, the six fields and their defaults |
//! | KR-REQ-08.53 | The worker records its owned backend's input encoding from what that backend asked for |
//! | KR-REQ-08.54 | Legacy VT input is accepted without claiming scan-code fidelity |
//! | KR-REQ-08.55 | Every mode request and reset stops at this boundary and is never broadcast |
//! | KR-REQ-08.56 | The record path's own qualification: composition, dead keys, AltGr, paste, mouse, ordering |
//!
//! None of this needs Windows. The encoding is a rule about bytes, the boundary is a rule about a
//! stream, and a record is six numbers; writing them out by hand is what lets the same rule be
//! checked on every machine the workspace builds on. What *does* need Windows is reading a record
//! from a console in the first place, and that is `crates/kr-cli/src/windows/`.

use kr_term::engine::{Engine, EngineConfig};
use kr_term::modes::ModeKind;
use kr_term::policy::{Backend, Policy};
use kr_term::win32::{Fidelity, KeyRecord, MODE_RESET, MODE_SET, control_keys, decode, encode_all};

/// An engine whose backend is the pseudo-console this worker owns.
fn owned_conpty() -> Engine {
    Engine::new(EngineConfig {
        policy: Policy {
            backend: Backend::ConPty,
            ..Policy::DEFAULT
        },
        ..EngineConfig::DEFAULT
    })
    .expect("an engine")
}

/// A record for one key going down, with nothing held.
fn pressed(virtual_key: u16, scan_code: u16, unicode: u16) -> KeyRecord {
    KeyRecord {
        virtual_key,
        scan_code,
        unicode,
        key_down: true,
        control_keys: 0,
        repeat: 1,
    }
}

#[test]
fn the_worker_records_what_its_own_backend_asked_for(/* KR-REQ-08.53 */) {
    let mut engine = owned_conpty();

    // Before anything asks, the session carries legacy VT input and says so.
    assert!(!engine.modes().win32_input());
    assert_eq!(engine.modes().backend_input_fidelity(), Fidelity::LegacyVt);

    let outcome = engine.feed(MODE_SET, 0);
    assert!(
        outcome.forward.is_empty(),
        "the request is never broadcast to a client"
    );
    assert!(
        engine.modes().win32_input(),
        "the worker recorded its own backend's input encoding"
    );
    assert_eq!(engine.modes().backend_input_fidelity(), Fidelity::Records);

    // And it answers honestly when the backend asks what it is in.
    engine.feed(b"\x1b[?9001$p", 0);
    let replies = engine
        .lane_mut()
        .drain(kr_term::lane::LaneGate::default(), 4096, 0);
    assert_eq!(replies[0].bytes(), b"\x1b[?9001;1$y");

    let outcome = engine.feed(MODE_RESET, 0);
    assert!(outcome.forward.is_empty());
    assert!(!engine.modes().win32_input());
    assert_eq!(engine.modes().backend_input_fidelity(), Fidelity::LegacyVt);
}

#[test]
fn a_nested_transition_never_forwards_a_mode_change_across_this_boundary(/* KR-REQ-08.55 */) {
    // A session runs `wsl.exe`, an `ssh` client, or another ConPTY, and each asks for win32 input
    // and disables it when it ends. Whatever of that reaches this host is what the console it owns
    // chose to send; keeping an inner console's disable from reaching the outer one happens on the
    // boundary between those two consoles, below this. What this host owes, and what this checks,
    // is that neither a request nor a reset is ever broadcast onwards, however many of them arrive
    // and in whatever order.
    let mut engine = owned_conpty();
    for sequence in [
        MODE_SET, MODE_SET, MODE_RESET, MODE_RESET, MODE_SET, MODE_RESET,
    ] {
        let outcome = engine.feed(sequence, 0);
        assert!(
            outcome.forward.is_empty(),
            "{sequence:?} is never broadcast to a client"
        );
    }
    // And what this host records afterwards is what the backend last said, rather than a count it
    // kept of its own.
    assert!(!engine.modes().win32_input());
    engine.feed(MODE_SET, 0);
    assert!(engine.modes().win32_input());
    assert_eq!(engine.modes().backend_input_fidelity(), Fidelity::Records);
}

#[test]
fn a_request_that_names_other_modes_keeps_them_and_still_stops_here(/* KR-REQ-08.55 */) {
    let mut engine = owned_conpty();
    let outcome = engine.feed(b"\x1b[?9001;1049h", 0);
    assert!(
        outcome.forward.is_empty(),
        "the request never travels onwards, because it names mode 9001"
    );
    assert!(engine.modes().win32_input());
    assert!(
        engine.modes().is_set(ModeKind::Dec, 1049),
        "the alternate buffer still changed"
    );
}

#[test]
fn a_unix_backend_never_enters_the_mode_however_often_it_is_asked(/* KR-REQ-08.55 */) {
    let mut engine = Engine::new(EngineConfig::default()).expect("an engine");
    for _ in 0..3 {
        let outcome = engine.feed(MODE_SET, 0);
        assert!(outcome.forward.is_empty(), "never broadcast");
    }
    assert!(!engine.modes().win32_input());
    assert_eq!(engine.modes().backend_input_fidelity(), Fidelity::LegacyVt);
}

#[test]
fn a_composed_character_arrives_as_the_records_the_console_produced(/* KR-REQ-08.56 */) {
    // Windows IME composition ends in one `WM_CHAR` per UTF-16 code unit, which the console
    // reports as a key record with no virtual key and no scan code: the character was composed,
    // not typed. Encoding it means carrying exactly that, rather than inventing the key somebody
    // would have pressed to produce it on a keyboard that has one.
    let composed = KeyRecord {
        virtual_key: 0,
        scan_code: 0,
        unicode: 0x3042, // HIRAGANA LETTER A
        key_down: true,
        control_keys: 0,
        repeat: 1,
    };
    assert_eq!(encode_all(&[composed]), b"\x1b[0;0;12354;1;0;1_");
    assert_eq!(
        decode(b"\x1b[0;0;12354;1;0;1_").expect("a record"),
        composed
    );

    // A character outside the basic plane is two records, and both halves travel.
    let high = KeyRecord {
        unicode: 0xD867,
        ..composed
    };
    let low = KeyRecord {
        unicode: 0xDE3D,
        ..composed
    };
    let bytes = encode_all(&[high, low]);
    assert_eq!(bytes, b"\x1b[0;0;55399;1;0;1_\x1b[0;0;56893;1;0;1_");
    assert_eq!(
        String::from_utf16(&[0xD867, 0xDE3D]).expect("a character"),
        "\u{29E3D}"
    );
}

#[test]
fn a_dead_key_is_its_own_record_and_so_is_what_it_composes(/* KR-REQ-08.56 */) {
    // A dead key produces a record with a virtual key and a scan code and no code unit at all;
    // the key after it produces the composed character. Both are carried, in that order, because
    // an application that tracks the keyboard itself needs to see the dead key happen.
    let dead_circumflex = KeyRecord {
        virtual_key: 0xDD,
        scan_code: 0x1A,
        unicode: 0,
        key_down: true,
        control_keys: 0,
        repeat: 1,
    };
    let composed_e = pressed(0x45, 0x12, 0x00EA); // LATIN SMALL LETTER E WITH CIRCUMFLEX
    let bytes = encode_all(&[dead_circumflex, composed_e]);
    let sequences: Vec<&[u8]> = bytes
        .split_inclusive(|byte| *byte == b'_')
        .filter(|part| !part.is_empty())
        .collect();
    assert_eq!(sequences.len(), 2, "one record each, in order");
    assert_eq!(decode(sequences[0]).expect("the dead key"), dead_circumflex);
    assert_eq!(decode(sequences[1]).expect("the character"), composed_e);
    assert_eq!(
        decode(sequences[0]).expect("the dead key").unicode,
        0,
        "a dead key carries no character, and none is invented for it"
    );
}

#[test]
fn alt_graph_travels_as_the_state_the_console_reported(/* KR-REQ-08.56 */) {
    // On a keyboard with an AltGr key the console reports right Alt and left Ctrl together. An
    // encoder that decided this was "Ctrl and Alt" and re-encoded it as a control character would
    // turn a perfectly ordinary character into an interrupt.
    let at_sign = KeyRecord {
        virtual_key: 0x32,
        scan_code: 0x03,
        unicode: u16::from(b'@'),
        key_down: true,
        control_keys: control_keys::RIGHT_ALT_PRESSED | control_keys::LEFT_CTRL_PRESSED,
        repeat: 1,
    };
    assert!(at_sign.is_alt_graph());
    let encoded = encode_all(&[at_sign]);
    assert_eq!(encoded, b"\x1b[50;3;64;1;9;1_");
    let read_back = decode(&encoded).expect("a record");
    assert_eq!(read_back.control_keys, at_sign.control_keys);
    assert!(read_back.is_alt_graph());
}

#[test]
fn a_repeat_and_a_key_up_keep_their_own_order_and_their_own_counts(/* KR-REQ-08.56 */) {
    // A held key is one record with a count. A key coming up is a record of its own, and it comes
    // after the one that put it down. Legacy VT input can express neither.
    let down = KeyRecord {
        repeat: 4,
        ..pressed(0x41, 0x1E, u16::from(b'a'))
    };
    let up = KeyRecord {
        key_down: false,
        repeat: 1,
        ..down
    };
    let bytes = encode_all(&[down, up]);
    assert_eq!(bytes, b"\x1b[65;30;97;1;0;4_\x1b[65;30;97;0;0;1_");
    let sequences: Vec<&[u8]> = bytes
        .split_inclusive(|byte| *byte == b'_')
        .filter(|part| !part.is_empty())
        .collect();
    assert!(decode(sequences[0]).expect("down").key_down);
    assert!(!decode(sequences[1]).expect("up").key_down);
    assert_eq!(decode(sequences[0]).expect("down").repeat, 4);
}

#[test]
fn paste_and_mouse_stay_the_separate_operations_they_are(/* KR-REQ-08.56 */) {
    // Section 8 keeps paste and mouse as their own VT operations whatever the keyboard encoding
    // is. The engine's own state is what proves it: the backend can be in win32 input mode and
    // bracketed paste at the same time, and neither request answers for the other.
    let mut engine = owned_conpty();
    engine.feed(MODE_SET, 0);
    engine.feed(b"\x1b[?2004h", 0);
    engine.feed(b"\x1b[?1006h", 0);
    engine.feed(b"\x1b[?1000h", 0);
    assert!(engine.modes().win32_input());
    assert!(
        engine.modes().is_set(ModeKind::Dec, 2004),
        "bracketed paste is on"
    );
    assert!(
        engine.modes().is_set(ModeKind::Dec, 1006) && engine.modes().is_set(ModeKind::Dec, 1000),
        "mouse reporting is on"
    );

    // Turning the keyboard encoding off leaves both exactly where they were.
    engine.feed(MODE_RESET, 0);
    assert!(!engine.modes().win32_input());
    assert!(engine.modes().is_set(ModeKind::Dec, 2004));
    assert!(engine.modes().is_set(ModeKind::Dec, 1006));
}

#[test]
fn legacy_input_is_accepted_without_claiming_a_fidelity_it_has_not_got(/* KR-REQ-08.54 */) {
    // Microsoft's contract lets a terminal ignore mode 9001, so a client that sends no records is
    // behaving correctly. What must never happen is this host describing that input as carrying
    // Windows scan codes.
    assert!(!Fidelity::LegacyVt.carries_console_scan_codes());
    assert!(
        Fidelity::LegacyVt
            .describe()
            .contains("no Windows scan-code fidelity")
    );
    // And what records do carry is the console's own scan codes rather than a keyboard's, which
    // is what the description says rather than "recovered hardware scan codes".
    assert!(Fidelity::Records.carries_console_scan_codes());
    let described = Fidelity::Records.describe();
    assert!(described.contains("as the console reported them"));
    assert!(
        !described.contains("hardware"),
        "nothing claims a hardware scan code: {described:?}"
    );
}

#[test]
fn the_byte_preservation_promise_starts_at_the_consoles_output_pipe(/* KR-REQ-08.51 */) {
    // What the engine sees on this backend is already what ConPTY rendered. An application that
    // wrote through the console API produced no bytes at all, and the ones that arrive are the
    // console's rendering of what it did. So the promise this session makes is about the bytes it
    // was handed, and the conformance record says which backend produced them.
    let mut engine = owned_conpty();
    let rendered = b"\x1b[1;31mred\x1b[0m";
    let outcome = engine.feed(rendered, 0);
    let forwarded: Vec<u8> = outcome
        .forward
        .iter()
        .flat_map(|span| {
            let start = usize::try_from(span.start()).expect("a byte offset");
            let end = usize::try_from(span.end()).expect("a byte offset");
            rendered[start..end].to_vec()
        })
        .collect();
    assert_eq!(
        forwarded, rendered,
        "every byte the console's output pipe produced is carried through unchanged"
    );
}
