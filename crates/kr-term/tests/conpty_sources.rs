//! What the sources of ConPTY's win32 input mode really send, replayed through the engine.
//!
//! `win32_input.rs` feeds the engine sequences written by hand. A nested pseudo-console, a session
//! of the Windows Subsystem for Linux and an `ssh` client each send whatever the system they run
//! on makes them send, so those are recorded: `crates/kr-cli/tests/conpty_sources_windows.rs` runs
//! each in a pseudo-console on a Windows machine and writes every read of the pseudo-console's
//! output pipe into `tests/conpty_sources/<source>.capture`, with the build of Windows it was
//! made on. This file feeds each recording, read by read as it came, to the engine of the owned
//! ConPTY backend, which is what the worker holds for a session whose program is that source.
//!
//! Nothing here needs Windows: the recording is bytes, and the rule is about a stream of them.

use kr_term::engine::{Engine, EngineConfig};
use kr_term::policy::{Backend, Policy};
use kr_term::snapshot::Viewport;
use kr_term::win32::Fidelity;

/// The sources there are recordings of, in the order the recorder runs them: a program that has
/// nothing to do with the mode, then a pseudo-console inside the pseudo-console, `wsl.exe` and
/// `ssh.exe`.
const SOURCES: [&str; 4] = [
    "plain-program",
    "nested-pseudo-console",
    "wsl-exe",
    "ssh-exe",
];

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

/// A recording of one source.
struct Capture {
    name: &'static str,
    /// The text the source's command printed, which says its output came through.
    marker: String,
    /// The build of Windows the recording was made on.
    windows: String,
    /// Each read of the pseudo-console's output pipe, in order.
    chunks: Vec<Vec<u8>>,
}

/// The bytes a `chunk` line spells: printable ASCII as itself, `\\` for a backslash, `\xNN` for any
/// other byte.
fn unspelled(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' {
            out.push(bytes[at]);
            at += 1;
        } else if bytes.get(at + 1) == Some(&b'\\') {
            out.push(b'\\');
            at += 2;
        } else {
            assert_eq!(bytes.get(at + 1), Some(&b'x'), "an escape in {text:?}");
            let digits = std::str::from_utf8(&bytes[at + 2..at + 4]).expect("two hex digits");
            out.push(u8::from_str_radix(digits, 16).expect("two hex digits"));
            at += 4;
        }
    }
    out
}

/// Reads the recording of `name`.
fn capture(name: &'static str) -> Capture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("conpty_sources")
        .join(format!("{name}.capture"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut marker = None;
    let mut windows = None;
    let mut chunks = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# marker: ") {
            marker = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("# windows: ") {
            windows = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("chunk ") {
            chunks.push(unspelled(rest));
        }
    }
    Capture {
        name,
        marker: marker.expect("the recording says what its command printed"),
        windows: windows.expect("the recording says what it was made on"),
        chunks,
    }
}

/// One `CSI ? ... h` or `CSI ? ... l` that names mode 9001, found in a recording by its own
/// scanner, apart from the engine's.
struct Word {
    start: usize,
    end: usize,
    /// `h` (a request) or `l` (a reset).
    enabled: bool,
}

/// Finds every sequence in `stream` that sets or resets a private mode list holding 9001.
fn words(stream: &[u8]) -> Vec<Word> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 3 <= stream.len() {
        if stream[at..].starts_with(b"\x1b[?") {
            let mut end = at + 3;
            while end < stream.len() && (stream[end].is_ascii_digit() || stream[end] == b';') {
                end += 1;
            }
            if end < stream.len() && matches!(stream[end], b'h' | b'l') {
                if stream[at + 3..end]
                    .split(|byte| *byte == b';')
                    .any(|part| part == b"9001")
                {
                    found.push(Word {
                        start: at,
                        end: end + 1,
                        enabled: stream[end] == b'h',
                    });
                }
                at = end + 1;
                continue;
            }
        }
        at += 1;
    }
    found
}

/// What the engine did with a stream fed to it in reads.
struct Replay {
    /// For each byte of the stream, whether the engine let a direct attachment forward it.
    forwarded: Vec<bool>,
    /// After each read: how far into the stream it reached, and whether the worker had recorded the
    /// backend's input encoding as records.
    recorded: Vec<(usize, bool)>,
    /// Whether the engine's last snapshot names mode 9001 among its modes.
    snapshot_names_the_mode: bool,
    /// The input fidelity the engine reports at the end.
    fidelity: Fidelity,
}

/// Feeds `reads` to a new engine, one after the other.
fn replay(reads: &[&[u8]]) -> Replay {
    let mut engine = owned_conpty();
    let total: usize = reads.iter().map(|read| read.len()).sum();
    let mut forwarded = vec![false; total];
    let mut recorded = Vec::new();
    let mut reached = 0;
    for read in reads {
        let outcome = engine.feed(read, 0);
        for span in &outcome.forward {
            let start = usize::try_from(span.start()).expect("a stream offset");
            let end = usize::try_from(span.end()).expect("a stream offset");
            for flag in &mut forwarded[start..end] {
                *flag = true;
            }
        }
        reached += read.len();
        recorded.push((reached, engine.modes().win32_input()));
    }
    let viewport = Viewport {
        top_row: 0,
        rows: 24,
        left_col: 0,
        cols: 100,
    };
    let (snapshot, _) = engine.snapshot(viewport, 0);
    Replay {
        forwarded,
        recorded,
        snapshot_names_the_mode: snapshot.modes.iter().any(|entry| entry.mode == 9001),
        fidelity: engine.modes().backend_input_fidelity(),
    }
}

/// The state the last word in `stream[..reached]` leaves the mode in, which is off before any word.
fn state_after(words: &[Word], reached: usize) -> bool {
    words
        .iter()
        .rev()
        .find(|word| word.end <= reached)
        .is_some_and(|word| word.enabled)
}

/// Replays `capture` as recorded and with every byte its own read, and checks what each replay did
/// against what the recording itself says.
fn assert_the_boundary_holds(capture: &Capture) {
    let stream: Vec<u8> = capture.chunks.concat();
    let words = words(&stream);
    assert!(
        words.iter().any(|word| word.enabled),
        "the recording of {} ({}) holds no request for mode 9001: {} bytes",
        capture.name,
        capture.windows,
        stream.len()
    );

    eprintln!(
        "{} ({}): {} bytes in {} reads, {} requests and {} resets for mode 9001",
        capture.name,
        capture.windows,
        stream.len(),
        capture.chunks.len(),
        words.iter().filter(|word| word.enabled).count(),
        words.iter().filter(|word| !word.enabled).count()
    );

    let as_read: Vec<&[u8]> = capture.chunks.iter().map(Vec::as_slice).collect();
    let by_byte: Vec<&[u8]> = stream.chunks(1).collect();
    let mut flags_of_each = Vec::new();
    for (how, reads) in [("as it was read", &as_read), ("a byte at a time", &by_byte)] {
        let replayed = replay(reads);
        for word in &words {
            assert!(
                replayed.forwarded[word.start..word.end]
                    .iter()
                    .all(|forwarded| !forwarded),
                "{} replayed {how}: a sequence for mode 9001 at {}..{} was forwarded",
                capture.name,
                word.start,
                word.end
            );
        }
        // Where the worker's record of the backend's input encoding stands after each read is what
        // the last word it has read says, however the reads fall.
        for (reached, recorded) in &replayed.recorded {
            assert_eq!(
                *recorded,
                state_after(&words, *reached),
                "{} replayed {how}: after {reached} bytes the recorded encoding is not what the \
                 last sequence for mode 9001 said",
                capture.name
            );
        }
        assert!(
            !replayed.snapshot_names_the_mode,
            "{} replayed {how}: a snapshot names mode 9001",
            capture.name
        );
        let last = state_after(&words, stream.len());
        assert_eq!(
            replayed.fidelity,
            if last {
                Fidelity::Records
            } else {
                Fidelity::LegacyVt
            },
            "{} replayed {how}: the fidelity the engine reports",
            capture.name
        );
        // What the source printed came through, so the stream was not stopped as a whole.
        let carried: Vec<u8> = stream
            .iter()
            .zip(&replayed.forwarded)
            .filter_map(|(byte, forwarded)| forwarded.then_some(*byte))
            .collect();
        assert!(
            String::from_utf8_lossy(&carried).contains(&capture.marker),
            "{} replayed {how}: what the source printed ({:?}) was not forwarded",
            capture.name,
            capture.marker
        );
        flags_of_each.push(replayed.forwarded);
    }
    assert_eq!(
        flags_of_each[0], flags_of_each[1],
        "{}: which bytes are forwarded does not depend on where the reads fall",
        capture.name
    );
}

/// KR-REQ-08.55: the requests and resets for mode 9001 that a program, a nested pseudo-console,
/// `wsl.exe` and `ssh.exe` really send into the pseudo-console they run in do not cross the
/// boundary: none is forwarded to a client, none is listed in a snapshot, and the worker's record
/// of the backend's input encoding is what the last of them said, replayed as the reads came and a
/// byte at a time.
///
/// The recordings were made on the build of Windows each names, one run of each source. Not shown
/// here: what the outer console does to its own mode when an attachment ends, and a person's
/// terminal reading the stream.
#[test]
fn what_each_source_sends_into_its_pseudo_console_stops_at_the_boundary() {
    for name in SOURCES {
        let capture = capture(name);
        assert_the_boundary_holds(&capture);
    }
}
