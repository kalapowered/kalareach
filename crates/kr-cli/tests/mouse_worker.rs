//! The client's reader of the mouse modes, held against the worker's own record of them.
//!
//! A worker's engine cuts the session's output into sequences, decides which of them a terminal is
//! handed, and keeps the mouse modes the application set. A client that is handed what the worker
//! forwards has to end in the state the worker holds, so these cases feed the same bytes to a real
//! engine and to the reader, and compare. KR-REQ-01.11.

use kr_cli::mouse::{MouseReporting, Reading, Tracking};
use kr_term::budget::GridSize;
use kr_term::classify::CsiView;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::event::{DirectDisposition, EventKind};
use kr_term::lexer::{LexLimits, Lexer};
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

/// What the rules give for a reader that is shown `forwarded` under `reading`: the tracking and the
/// encoding it ends in, and the follow-ups it is to return, each as the place it goes at and the
/// encoding it puts a terminal in.
///
/// The rules, written out once more here and not read from the reader: the tracking is one state, a
/// set replaces it and a reset of any of the three turns it off (a screen drawn by a worker of an
/// earlier build is the exception, where a reset of one that is not on changes nothing); the
/// encoding is one state by xterm's rule (a set replaces it, and a reset returns the default only
/// when it names the one in force); a terminal that returns the default at a reset of either mode
/// holds the last set only, and after live output that leaves it elsewhere than xterm is, it is
/// written the resets of both and the set of the one in force. Which sequences are acted on is the
/// lexer's: that is what the worker forwards.
struct Rules {
    tracking: Tracking,
    encoding: Option<u32>,
    follows: Vec<(usize, u32)>,
    /// Whether a mouse mode was ever on.
    changed_a_mode: bool,
}

fn rules(forwarded: &[u8], reading: Reading) -> Rules {
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    lexer.feed(forwarded, &mut events);
    let mut tracking: Option<u16> = None;
    let mut xterm: Option<u16> = None;
    let mut terminal: Option<u16> = None;
    let mut follows = Vec::new();
    let mut changed_a_mode = false;
    for event in &events {
        if event.disposition != DirectDisposition::Forward || event.passthrough_depth != 0 {
            continue;
        }
        match &event.kind {
            EventKind::Esc {
                intermediate: None,
                extra_intermediates: false,
                final_byte: b'c',
            } => {
                tracking = None;
                xterm = None;
                terminal = None;
            }
            EventKind::Csi {
                params,
                truncated,
                final_byte: final_byte @ (b'h' | b'l'),
            } => {
                let csi = CsiView::with_truncation(params, *final_byte, *truncated);
                if csi.private != Some(b'?') || !csi.intermediates.is_empty() {
                    continue;
                }
                let set = *final_byte == b'h';
                let mut encoding_named = false;
                for slot in &csi.numbers {
                    let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) else {
                        continue;
                    };
                    match mode {
                        1000 | 1002 | 1003 => {
                            if set {
                                tracking = Some(mode);
                            } else if reading != Reading::Restoration || tracking == Some(mode) {
                                tracking = None;
                            }
                        }
                        1005 | 1006 => {
                            encoding_named = true;
                            if set {
                                xterm = Some(mode);
                                terminal = Some(mode);
                            } else {
                                if xterm == Some(mode) {
                                    xterm = None;
                                }
                                terminal = None;
                            }
                        }
                        _ => {}
                    }
                }
                if encoding_named && reading == Reading::Live && xterm != terminal {
                    if let Some(encoding) = xterm {
                        let end = usize::try_from(event.span.end()).expect("an offset");
                        follows.push((end, u32::from(encoding)));
                    }
                    terminal = xterm;
                }
            }
            _ => {}
        }
        changed_a_mode |= tracking.is_some() || xterm.is_some();
    }
    Rules {
        tracking: match tracking {
            Some(1003) => Tracking::Motion,
            Some(1002) => Tracking::Drag,
            Some(1000) => Tracking::Clicks,
            _ => Tracking::Off,
        },
        encoding: xterm.map(u32::from),
        follows,
        changed_a_mode,
    }
}

/// What a reader that is shown the forwarded bytes under `reading` ends in and returns, read as one
/// write and then cut in two at every place, which must give the same state and the same follow-ups
/// at the same places. The follow-ups' bytes are checked against what is written after a sequence.
fn client_reads(forwarded: &[u8], reading: Reading) -> (Tracking, Option<u32>, Vec<(usize, u32)>) {
    let mut whole = MouseReporting::default();
    let follows = whole.read(forwarded, reading);
    for follow in &follows {
        assert_eq!(
            follow.bytes(),
            format!("\x1b[?1005;1006l\x1b[?{}h", follow.encoding).into_bytes()
        );
    }
    let follows: Vec<(usize, u32)> = follows
        .iter()
        .map(|follow| (follow.at, follow.encoding))
        .collect();
    let state = (whole.tracking(), whole.encoding_in_force(), follows);
    for cut in 0..=forwarded.len() {
        let mut parts = MouseReporting::default();
        let mut cut_follows: Vec<(usize, u32)> = parts
            .read(&forwarded[..cut], reading)
            .iter()
            .map(|follow| (follow.at, follow.encoding))
            .collect();
        cut_follows.extend(
            parts
                .read(&forwarded[cut..], reading)
                .iter()
                .map(|follow| (cut + follow.at, follow.encoding)),
        );
        assert_eq!(
            (parts.tracking(), parts.encoding_in_force(), cut_follows),
            state,
            "a stream cut at {cut} is read as one write: {}",
            forwarded.escape_ascii()
        );
    }
    state
}

/// What a comparison of a set of strings found.
struct Tally {
    /// How many strings were compared.
    count: usize,
    /// How many of them turned a mouse mode on at some point, which no string that is too short to
    /// hold a mode setting can.
    changing: usize,
    /// The strings where the client and the worker, or the client and the rules, differ.
    found: Vec<String>,
}

/// Compares, for each string, the client under each of the three readings with the rules, and under
/// the reading of live output and of a drawn screen with the worker's own record too.
fn differences(strings: impl IntoIterator<Item = Vec<u8>>) -> Tally {
    let mut tally = Tally {
        count: 0,
        changing: 0,
        found: Vec::new(),
    };
    for input in strings {
        let worker = worker_up_to_its_hand_over(&input);
        tally.count += 1;
        for reading in [Reading::Live, Reading::Restoration, Reading::Painted] {
            let (tracking, encoding, follows) = client_reads(&worker.forwarded, reading);
            let expected = rules(&worker.forwarded, reading);
            if reading == Reading::Live && expected.changed_a_mode {
                tally.changing += 1;
            }
            let held_by_worker = match reading {
                // A screen drawn by a worker of an earlier build is read by a rule of its own for
                // the tracking, so only the encoding is the worker's.
                Reading::Restoration => (expected.tracking, worker.encoding),
                _ => (worker.tracking, worker.encoding),
            };
            if (tracking, encoding) != held_by_worker
                || (tracking, encoding) != (expected.tracking, expected.encoding)
                || follows != expected.follows
            {
                tally.found.push(format!(
                    "{} read as {reading:?}: the client holds {:?} and returns {follows:?}; the \
                     worker holds {:?}; the rules give {:?} and {:?}",
                    input.escape_ascii(),
                    (tracking, encoding),
                    (worker.tracking, worker.encoding),
                    (expected.tracking, expected.encoding),
                    expected.follows
                ));
            }
        }
    }
    tally
}

/// The longest list of resets of 1006 the worker's lexer keeps as one sequence, as bytes: every slot
/// names a mode that is tracked, because an empty one makes the sequence an extension, so the filler
/// is the modes 1 and 12, which are not the mouse's.
fn reset_of_1006_in(bytes: usize) -> Vec<u8> {
    let mut list = b"\x1b[?".to_vec();
    let mut room = bytes - list.len() - b"1006l".len();
    if room % 2 == 1 {
        list.extend_from_slice(b"12;");
        room -= 3;
    }
    list.extend(b"1;".repeat(room / 2));
    list.extend_from_slice(b"1006l");
    list
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
/// whatever the bytes between and inside the sequences are, and is written what the rules say after
/// a sequence that leaves a terminal elsewhere than the session.
///
/// Every string is lexed by a real worker engine, and what the engine forwards is read by the client
/// under each of the three readings, as one write and cut in two at every place. The client's
/// tracking and encoding must be the worker's (for a screen drawn by a worker of an earlier build,
/// the encoding only), and equal what the rules give; the follow-ups it returns must be the ones the
/// rules give, at the same places however the write is cut, and in the bytes that are written.
///
/// Two sets. The first is every string of up to three bytes over the bytes that make and break a
/// sequence: escape, the opening of a control sequence, its private marker and the other markers, an
/// intermediate, a colon, its separator, the digits of the mouse modes, `h`, `l`, `c`, padding,
/// cancel, substitute, the bell, one other control and the raw 8-bit introducer: 12,720 strings,
/// **none of which can change a mode**, because the shortest mode setting is eight bytes and a full
/// reset of a terminal in its default state changes nothing; they test the lexer's framing only. The second is the
/// sequences that set and reset the mouse modes, alone, in two lists and as a full reset, each with
/// one or two of those bytes put in at every place, in the middle of what an application wrote
/// before and after, and the resets of 1006 in a list of the longest length the worker's lexer keeps
/// and in one byte more, which the worker withholds; a bound that is not the same in the engine and
/// in the client's lexer fails there: about 41,800 strings, of which about 40,200 turn a mouse mode
/// on at some point, so the comparison's weight is in this set. The worker's record is taken where it hands a direct
/// attachment over to the projected one, which it does for the sequences a terminal would frame
/// differently, because a client that is handed the projected screen is then written the state in
/// it.
#[test]
fn what_the_client_reads_of_the_mouse_is_what_the_worker_holds() {
    let alphabet = [
        0x1b, b'[', b'?', b'$', b'>', b':', b';', b'0', b'1', b'2', b'3', b'5', b'6', b'h', b'l',
        b'c', 0x00, 0x7f, 0x18, 0x1a, 0x07, 0x01, 0x9b,
    ];
    let exhaustive = strings_over(&alphabet, 3);

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
        0x00, 0x7f, 0x18, 0x1a, 0x07, 0x01, 0x9b, 0x1b, b'[', b'?', b';', b'c', b'l', b'1', b'$',
        b'>', b':',
    ];
    let mut constructed = Vec::new();
    for base in bases {
        for (index, (before, after)) in contexts.into_iter().enumerate() {
            for at in 0..=base.len() {
                for &byte in &inserted {
                    let mut once = base.to_vec();
                    once.insert(at, byte);
                    constructed.push([before, &once, after].concat());
                    // Two of the bytes in one sequence, in the context that has the most at stake.
                    if index != 1 || !inserted[..7].contains(&byte) {
                        continue;
                    }
                    for second in at..=once.len() {
                        for &other in &inserted[..7] {
                            let mut twice = once.clone();
                            twice.insert(second, other);
                            constructed.push([before, &twice, after].concat());
                        }
                    }
                }
            }
        }
    }
    let longest = LexLimits::DEFAULT.max_sequence_bytes;
    for bytes in [longest, longest + 1] {
        for (before, after) in contexts {
            constructed.push([before, &reset_of_1006_in(bytes), after].concat());
        }
    }

    let exhaustive = differences(exhaustive);
    let constructed = differences(constructed);
    let found: Vec<&String> = exhaustive.found.iter().chain(&constructed.found).collect();
    assert!(
        found.is_empty(),
        "{} strings differ, the first of them:\n{}",
        found.len(),
        found
            .iter()
            .take(10)
            .map(|string| string.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        exhaustive.changing, 0,
        "a string of up to three bytes holds no mode setting"
    );
    assert!(
        exhaustive.count == 12_720 && constructed.count > 40_000 && constructed.changing > 35_000,
        "the sets are the size they were made to be: {} and {} strings, of which {} turn a mode on",
        exhaustive.count,
        constructed.count,
        constructed.changing
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
            {
                let (tracking, encoding, _) = client_reads(&whole.forwarded, Reading::Live);
                (tracking, encoding)
            },
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
