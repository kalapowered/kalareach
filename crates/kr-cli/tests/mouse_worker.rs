//! The client's reader of the mouse modes, held against the worker's own record of them.
//!
//! A worker's engine cuts the session's output into sequences, decides which of them a terminal is
//! handed, and keeps the mouse modes the application set. A client that is handed what the worker
//! forwards has to end in the state the worker holds, so these cases feed the same bytes to a real
//! engine and to the reader, and compare. KR-REQ-01.11.

use kr_cli::mouse::{MouseReporting, Reading, Tracking};
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::modes::ModeKind;

/// What the worker did with some output.
struct Worker {
    /// The bytes it hands a direct attachment, in order.
    forwarded: Vec<u8>,
    /// The tracking it holds.
    tracking: Tracking,
    /// The encoding it holds: 1005, 1006 or the default.
    encoding: Option<u32>,
    /// Where the attachment has to move to projected mode, when it has to.
    projected_at: Option<u64>,
}

/// Runs a fresh worker engine over `input`.
fn worker(input: &[u8]) -> Worker {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(8, 3),
        ..EngineConfig::DEFAULT
    })
    .expect("an engine");
    let mut outcome = engine.feed(input, 0);
    let settled = engine.quiesce(0);
    outcome.forward.extend(settled.forward);
    let mut forwarded = Vec::new();
    for span in &outcome.forward {
        let start = usize::try_from(span.start()).expect("an offset");
        let end = usize::try_from(span.end()).expect("an offset");
        forwarded.extend_from_slice(&input[start..end]);
    }
    let modes = engine.modes();
    let tracking = if modes.is_set(ModeKind::Dec, 1003) {
        Tracking::Motion
    } else if modes.is_set(ModeKind::Dec, 1002) {
        Tracking::Drag
    } else if modes.is_set(ModeKind::Dec, 1000) {
        Tracking::Clicks
    } else {
        Tracking::Off
    };
    let encoding = [1005_u16, 1006]
        .into_iter()
        .find(|mode| modes.is_set(ModeKind::Dec, *mode))
        .map(u32::from);
    Worker {
        forwarded,
        tracking,
        encoding,
        projected_at: outcome.projection_required_at,
    }
}

/// What the worker holds at the place where a direct attachment is handed over to the projected
/// one: what it held of the output before that place. The screen the attachment is drawn from
/// there on says the rest.
fn worker_up_to_its_hand_over(input: &[u8]) -> Worker {
    let whole = worker(input);
    match whole.projected_at {
        Some(at) => {
            let before = worker(&input[..usize::try_from(at).expect("an offset")]);
            assert_eq!(
                before.projected_at,
                None,
                "the output before the place of the hand-over needs no hand-over: {}",
                input.escape_ascii()
            );
            before
        }
        None => whole,
    }
}

/// What a reader that is shown the forwarded bytes ends in, read as one write and then cut in two
/// at every place.
fn client_after(forwarded: &[u8]) -> (Tracking, Option<u32>) {
    let mut whole = MouseReporting::default();
    let _ = whole.read(forwarded, Reading::Live);
    let state = (whole.tracking(), whole.encoding_in_force());
    for cut in 0..=forwarded.len() {
        let mut parts = MouseReporting::default();
        let _ = parts.read(&forwarded[..cut], Reading::Live);
        let _ = parts.read(&forwarded[cut..], Reading::Live);
        assert_eq!(
            (parts.tracking(), parts.encoding_in_force()),
            state,
            "a stream cut at {cut} is read as one write: {}",
            forwarded.escape_ascii()
        );
    }
    state
}

/// Says what the first difference between the client and the worker is, for the strings it found.
fn differences(strings: impl IntoIterator<Item = Vec<u8>>) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut found = Vec::new();
    for input in strings {
        let worker = worker_up_to_its_hand_over(&input);
        let client = client_after(&worker.forwarded);
        count += 1;
        if client != (worker.tracking, worker.encoding) {
            found.push(format!(
                "{}: the client holds {client:?} and the worker {:?}",
                input.escape_ascii(),
                (worker.tracking, worker.encoding)
            ));
        }
    }
    (count, found)
}

/// Every byte string of up to `length` bytes over `alphabet`.
fn strings_over(alphabet: &[u8], length: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut level = vec![Vec::new()];
    for _ in 0..length {
        let mut next = Vec::new();
        for head in &level {
            for &byte in alphabet {
                let mut string = head.clone();
                string.push(byte);
                next.push(string);
            }
        }
        all.extend(next.iter().cloned());
        level = next;
    }
    all
}

/// KR-REQ-01.11: the client reads from what the worker forwards the mouse modes the worker holds,
/// whatever the bytes between and inside the sequences are.
///
/// Two sets. Every string of up to three bytes over the bytes that make and break a sequence:
/// escape, the opening of a control sequence, its private marker, its separator, the digits of the
/// mouse modes, `h`, `l`, `c`, padding, cancel, substitute, the bell, one other control and the raw
/// 8-bit introducer. And the sequences that set and reset the mouse modes, alone, in two lists and
/// as a full reset, each with one or two of those bytes put in at every place, in the middle of what
/// an application wrote before and after. The worker's record is taken where it hands a direct
/// attachment over to the projected one, which it does for the sequences a terminal would frame
/// differently, because a client that is handed the projected screen is then written the state in
/// it.
#[test]
fn what_the_client_reads_of_the_mouse_is_what_the_worker_holds() {
    let alphabet = [
        0x1b, b'[', b'?', b';', b'0', b'1', b'2', b'3', b'5', b'6', b'h', b'l', b'c', 0x00, 0x7f,
        0x18, 0x1a, 0x07, 0x01, 0x9b,
    ];
    let mut strings = strings_over(&alphabet, 3);

    let bases: [&[u8]; 10] = [
        b"\x1b[?1006l",
        b"\x1b[?1005h",
        b"\x1b[?1000;1006h",
        b"\x1b[?1006;1005l",
        b"\x1b[?1002l",
        b"\x1b[?1003h",
        b"\x1b[?1005;1000l",
        b"\x1b[?;1006l",
        b"\x1b[?1006;l",
        b"\x1bc",
    ];
    let contexts: [(&[u8], &[u8]); 4] = [
        (b"", b""),
        (b"\x1b[?1000;1006h", b"\x1b[?1005l"),
        (b"\x1b[?1005h", b"\x1b[?1006l"),
        (b"\x1b[?1003h\x1b[?1006h", b"\x1b[?1002l\x1b[?1006l"),
    ];
    let inserted = [
        0x00, 0x7f, 0x18, 0x1a, 0x07, 0x01, 0x9b, 0x1b, b'[', b'?', b';', b'c', b'l', b'1',
    ];
    for base in bases {
        for (index, (before, after)) in contexts.into_iter().enumerate() {
            for at in 0..=base.len() {
                for &byte in &inserted {
                    let mut once = base.to_vec();
                    once.insert(at, byte);
                    strings.push([before, &once, after].concat());
                    // Two of the bytes in one sequence, in the context that has the most at stake.
                    if index != 1 || !inserted[..7].contains(&byte) {
                        continue;
                    }
                    for second in at..=once.len() {
                        for &other in &inserted[..7] {
                            let mut twice = once.clone();
                            twice.insert(second, other);
                            strings.push([before, &twice, after].concat());
                        }
                    }
                }
            }
        }
    }

    let (count, found) = differences(strings);
    assert!(
        count > 40_000,
        "the set is the size it was made to be: {count}"
    );
    assert!(
        found.is_empty(),
        "{} of {count} strings differ, the first of them:\n{}",
        found.len(),
        found
            .iter()
            .take(10)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// KR-REQ-01.11: what the worker does not hand a terminal is not read by the client, and the client
/// holds what the worker held where it handed the attachment over to the projected one.
///
/// Three kinds of bytes look like a mode setting to a scanner of the bytes alone, and the worker
/// never forwards them: a mode setting inside a tmux passthrough, one with a control inside the
/// sequence, and one opened by the raw 8-bit introducer. The worker holds the mode, because its
/// screen is the one the application drew, and moves the attachment to the projected screen from
/// before the sequence, which is drawn with that mode in it. Until then the client holds what it
/// was handed.
#[test]
fn a_mode_setting_the_worker_does_not_forward_is_not_read_by_the_client() {
    for (name, written) in [
        (
            "inside a tmux passthrough",
            &b"\x1bPtmux;\x1b\x1b[?1006h\x1b\\"[..],
        ),
        ("with a control inside it", b"\x1b[?10\x0706h"),
        ("opened by the raw 8-bit introducer", b"\x9b?1006h"),
    ] {
        let input = [&b"\x1b[?1000h"[..], written].concat();
        let whole = worker(&input);
        assert_eq!(
            (whole.tracking, whole.encoding),
            (Tracking::Clicks, Some(1006)),
            "the worker holds the mode that was set {name}"
        );
        assert_eq!(
            whole.projected_at,
            Some(b"\x1b[?1000h".len() as u64),
            "and moves the attachment to the projected screen before it, {name}"
        );
        assert_eq!(
            whole.forwarded, b"\x1b[?1000h",
            "and forwards none of it, {name}"
        );
        let held = worker_up_to_its_hand_over(&input);
        assert_eq!(
            client_after(&whole.forwarded),
            (held.tracking, held.encoding),
            "the client holds what the worker held where it handed the attachment over, {name}"
        );
        let mut reader = MouseReporting::default();
        let _ = reader.read(written, Reading::Live);
        assert_eq!(
            reader.encoding_in_force(),
            None,
            "a reader shown it directly does not read it, {name}"
        );
    }
}
