//! KR-REQ-18.11 and KR-REQ-25.25: a closed session's retained output is exported to a file the
//! person names, without the side effects it carries, with what it does not hold declared, and
//! never from an environment whose privacy mode is on.
//!
//! The daemon is a script: each case says which answers it gives, in the order the export asks for
//! them, so a case also says what the export asked and what it did not.

use std::collections::VecDeque;

use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, ActionWindowId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalBuild;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyReport, PrivacySession, PrivacySessionStanding,
};
use kr_protocol::recovery::{HistoryGapCause, HistoryPageParams};
use kr_protocol::scalars::{Bytes, TimestampMs, Uuid};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, DisplayNumber, Durability, OwnershipCoverage,
    ShellMode,
};

use serde_json::Value;

use super::*;
use crate::bridge::link::Answer;

/// An answer the scripted daemon gives to one method.
enum Step {
    Ok(Method, ParamsValue),
    Refuses(Method, ProtocolError),
}

/// A daemon that answers the questions an export asks, in order, and records each one.
struct Scripted {
    steps: VecDeque<Step>,
    asked: Vec<(Method, ParamsValue)>,
}

impl Scripted {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            asked: Vec::new(),
        }
    }

    /// The methods the export asked, in order.
    fn methods(&self) -> Vec<Method> {
        self.asked.iter().map(|(method, _)| *method).collect()
    }

    /// The cursors the export asked history pages from, in order.
    fn page_cursors(&self) -> Vec<u64> {
        self.asked
            .iter()
            .filter(|(method, _)| *method == Method::HistoryPage)
            .map(|(_, params)| {
                params
                    .to_typed::<HistoryPageParams>()
                    .expect("page parameters")
                    .from_cursor
                    .get()
            })
            .collect()
    }
}

impl Link for Scripted {
    fn build(&self) -> Option<&LocalBuild> {
        None
    }

    fn action_window_id(&self) -> ActionWindowId {
        ActionWindowId::new("scripted").expect("a window")
    }

    async fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<Answer> {
        self.asked.push((
            method,
            ParamsValue::from_typed(params).expect("parameters encode"),
        ));
        match self.steps.pop_front() {
            Some(Step::Ok(expected, answer)) => {
                assert_eq!(method, expected, "the export asked for something else");
                Ok(Ok(answer))
            }
            Some(Step::Refuses(expected, refusal)) => {
                assert_eq!(method, expected, "the export asked for something else");
                Ok(Err(refusal))
            }
            None => panic!("the export asked {method:?}, which nothing was scripted for"),
        }
    }

    async fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        _method: Method,
        _action_id: ActionId,
        _target: ActionTarget,
        _params: &T,
    ) -> Result<Answer> {
        panic!("an export changes nothing");
    }

    async fn recv(&mut self) -> Result<kr_protocol::envelope::ControlFrame> {
        panic!("an export is not pushed anything");
    }

    async fn send(&mut self, _frame: kr_protocol::envelope::ControlFrame) -> Result<()> {
        panic!("an export sends no frame without waiting for its answer");
    }

    async fn finish(self) {}
}

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([5; 16]))
}

fn other_session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([6; 16]))
}

fn closure(session_id: SessionId) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::RootExit,
        root_exit_code: Nullable::some(U64::new(0)),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Complete,
        durability: Durability::Durable,
        closed_at_ms: TimestampMs::new(9_000),
    }
}

/// A closed session the daemon still holds the record of.
fn closed(display: u64) -> SessionSummary {
    SessionSummary {
        session_id: session_id(),
        session_epoch: SessionEpoch::V1,
        environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
        display_number: DisplayNumber::new(display),
        state: SessionState::Closed,
        shell_mode: ShellMode::NativeCompat,
        shell_path: "/bin/sh".to_owned(),
        cwd: "/home/kala".to_owned(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: TimestampMs::new(1_000),
        dimensions: Dimensions::new(100, 30),
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::some(closure(session_id())),
        // An export does not read where the environment came from.
        environment_sources: None,
    }
}

fn listing(sessions: Vec<SessionSummary>) -> Step {
    Step::Ok(
        Method::SessionList,
        ParamsValue::from_typed(&SessionListResult { sessions }).expect("a listing"),
    )
}

fn privacy(enabled: bool, generation: u64, owing: &[SessionId]) -> Step {
    Step::Ok(
        Method::PrivacyStatus,
        ParamsValue::from_typed(&PrivacyReport {
            generation: U64::new(generation),
            enabled,
            changed_at_ms: TimestampMs::new(1),
            completion: PrivacyCompletion::Complete,
            sessions: owing
                .iter()
                .map(|session_id| PrivacySession {
                    session_id: *session_id,
                    generation: U64::new(generation),
                    standing: PrivacySessionStanding::WorkerEnded,
                })
                .collect(),
            disabled: Vec::new(),
            kept: Vec::new(),
            exported: Vec::new(),
            unlisted: Vec::new(),
        })
        .expect("a report"),
    )
}

/// A page of retained output from `from` to `from + bytes.len()`.
fn page(from: u64, bytes: &[u8]) -> Step {
    page_with(from, bytes, None)
}

/// A page that starts at `from`, after a gap that began at `gap_from` where one is given.
fn page_with(from: u64, bytes: &[u8], gap_from: Option<u64>) -> Step {
    page_after(from, bytes, gap_from, 0)
}

/// The same, for an archive whose oldest retained cursor is `oldest`.
fn page_after(from: u64, bytes: &[u8], gap_from: Option<u64>, oldest: u64) -> Step {
    Step::Ok(
        Method::HistoryPage,
        ParamsValue::from_typed(&HistoryPageResult {
            from_cursor: U64::new(from),
            next_cursor: U64::new(from + bytes.len() as u64),
            bytes: Bytes::new(bytes.to_vec()),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap_from.map(|gap_from| HistoryGap {
                from_cursor: U64::new(gap_from),
                to_cursor: U64::new(from),
                cause: Some(HistoryGapCause::SessionCapacity),
            })),
        })
        .expect("a page"),
    )
}

/// The page that says nothing is left after `end`.
fn end(end: u64) -> Step {
    page(end, b"")
}

/// What a file holds, read back as a person's own tool would read it.
struct Read(Value);

impl Read {
    fn of(exported: &Exported) -> Self {
        Self(serde_json::from_slice(&exported.document).expect("the file is JSON"))
    }

    /// The output the file carries, chunk by chunk, with the cursor each starts at.
    fn chunks(&self) -> Vec<(u64, Vec<u8>)> {
        self.0["output"]["chunks"]
            .as_array()
            .expect("chunks")
            .iter()
            .map(|chunk| {
                (
                    chunk["cursor"]
                        .as_str()
                        .expect("a cursor")
                        .parse()
                        .expect("digits"),
                    kr_protocol::scalars::from_base64url(
                        chunk["base64url"].as_str().expect("base64url"),
                    )
                    .expect("decodes"),
                )
            })
            .collect()
    }

    /// Everything the file carries as output, joined.
    fn output(&self) -> Vec<u8> {
        self.chunks()
            .into_iter()
            .flat_map(|(_, bytes)| bytes)
            .collect()
    }

    fn omission(&self, kind: &str) -> Option<&Value> {
        self.0["omissions"]
            .as_array()
            .expect("omissions")
            .iter()
            .find(|omission| omission["kind"] == kind)
    }

    fn count(&self, kind: &str) -> Option<u64> {
        self.omission(kind)
            .and_then(|omission| omission["count"].as_str())
            .map(|count| count.parse().expect("digits"))
    }
}

async fn export(link: &mut Scripted, max_bytes: u64) -> Result<Exported> {
    read(link, &SessionSelector::Display(1), max_bytes, 42).await
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// What a program does to a terminal besides drawing on it: write the clipboard, ask what it is, ring
/// it. Each is between lines of ordinary output.
const WITH_SIDE_EFFECTS: &[u8] = b"first line\r\n\
    \x1b]52;c;c2VjcmV0LXRva2Vu\x07\
    \x1b[c\
    \x07\
    \x1b[31mred\x1b[0m second line\r\n";

/// An export of a session whose output asks the terminal to do things carries the output and none of
/// the things: a clipboard write, a question to the terminal and a bell appear nowhere in the file,
/// and the file counts each. The control: output that asks for nothing is carried byte for byte
/// with no such omission.
#[tokio::test]
async fn an_exports_output_has_no_side_effect_and_says_what_was_dropped() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, WITH_SIDE_EFFECTS),
        end(WITH_SIDE_EFFECTS.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    let output = file.output();
    for kept in ["first line", "second line", "red"] {
        assert!(contains(&output, kept.as_bytes()), "{kept} is carried");
    }
    assert!(
        contains(&output, b"\x1b[31m"),
        "drawing is carried as drawn"
    );
    for gone in [&b"\x1b]52"[..], b"c2VjcmV0LXRva2Vu", b"\x1b[c", b"\x07"] {
        assert!(
            !contains(&output, gone),
            "{} is not carried",
            String::from_utf8_lossy(gone).escape_debug()
        );
    }
    // The file as a whole, base64 and all, never holds the secret the clipboard write carried.
    let whole = String::from_utf8_lossy(&exported.document);
    assert!(!whole.contains("c2VjcmV0LXRva2Vu"), "{whole}");
    assert!(
        !whole.contains(&kr_protocol::scalars::to_base64url(b"secret-token")),
        "{whole}"
    );
    assert_eq!(file.count("clipboard_write"), Some(1), "{}", file.0);
    assert_eq!(file.count("terminal_query"), Some(1), "{}", file.0);
    assert_eq!(file.count("bell"), Some(1), "{}", file.0);
    assert!(
        file.count("bytes_not_carried")
            .is_some_and(|dropped| dropped > 0),
        "{}",
        file.0
    );

    // The control.
    let plain = b"just text\r\n\x1b[1mbold\x1b[0m\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, plain),
        end(plain.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(
        file.output(),
        plain,
        "nothing asked of a terminal is dropped"
    );
    for kind in [
        "clipboard_write",
        "terminal_query",
        "bell",
        "bytes_not_carried",
    ] {
        assert!(file.omission(kind).is_none(), "{kind}: {}", file.0);
    }
}

/// A soft reset is rendering, so a recording keeps it as the program wrote it: section 8 forwards
/// it as it came, so a file that left it out would replay a screen the program never had. The file
/// carries one written inside the alternate buffer byte for byte, and declares nothing dropped.
#[tokio::test]
async fn an_exports_output_carries_a_soft_reset_from_the_alternate_buffer() {
    let written = b"shell\r\n\x1b[?1049halt\x1b[!pafter\r\n\x1b[?1049lprompt\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, written),
        end(written.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(
        file.output(),
        written,
        "the reset is carried where it was written"
    );
    assert!(
        file.omission("bytes_not_carried").is_none(),
        "nothing is declared dropped: {}",
        file.0
    );
}

/// The file says what it is, whose it is and how the session ended; what the archive does not keep
/// is declared; and the chunks start at the cursor the output was retained at.
#[tokio::test]
async fn the_file_names_the_session_its_closure_and_what_the_archive_does_not_keep() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.0["format"], FORMAT);
    assert_eq!(file.0["exported_at_ms"], "42");
    assert_eq!(file.0["session"]["session_id"], session_id().to_string());
    assert_eq!(file.0["session"]["display_number"], "1");
    assert_eq!(file.0["session"]["shell"], "/bin/sh");
    assert_eq!(file.0["session"]["created_at_ms"], "1000");
    assert_eq!(file.0["closure"]["reason"], "root_exit", "{}", file.0);
    assert_eq!(file.0["closure"]["closed_at_ms"], "9000", "{}", file.0);
    assert_eq!(file.0["dimensions"]["columns"], "100");
    assert_eq!(file.0["dimensions"]["rows"], "30");
    assert_eq!(file.chunks(), vec![(0, b"abc".to_vec())]);
    assert_eq!(file.0["output"]["next_cursor"], "3");
    assert_eq!(file.0["output"]["truncated"], false);
    for kind in [
        "output_timestamps",
        "earlier_dimensions",
        "archive_completeness",
    ] {
        assert!(
            file.omission(kind).is_some(),
            "{kind} is declared: {}",
            file.0
        );
    }
    // What a person would ask of an export that holds a closed session whole.
    for kind in [
        "history_gap",
        "output_truncated",
        "session_record_unavailable",
    ] {
        assert!(file.omission(kind).is_none(), "{kind}: {}", file.0);
    }
    assert_eq!(exported.summary.bytes_read, 3);
    assert_eq!(exported.summary.bytes_carried, 3);
    assert_eq!(
        daemon.methods(),
        vec![
            Method::SessionList,
            Method::PrivacyStatus,
            Method::HistoryPage,
            Method::HistoryPage,
            Method::PrivacyStatus,
        ]
    );
    assert_eq!(daemon.page_cursors(), vec![0, 3]);
}

/// A range the archive no longer holds is carried with its cause, the output on either side of it
/// keeps its own cursors, and a control string cut by the gap does not swallow what comes after it.
#[tokio::test]
async fn a_gap_is_carried_and_what_follows_it_is_not_read_as_a_continuation() {
    // The first stretch ends inside an operating-system command that was never ended; after the gap
    // the output is text, which a reader that carried the command over would have swallowed up to
    // the next terminator. The first byte after the gap is a cancel, which ends whatever string the
    // gap cut, so reading begins after it.
    let before = b"before\r\n\x1b]0;a title that is cut";
    let after = b"\x18\x1b[32mafter the gap\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, before),
        page_with(1_000, after, Some(before.len() as u64)),
        end(1_000 + after.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(exported.summary.gaps, 1);
    assert_eq!(
        file.0["output"]["gaps"][0]["from_cursor"],
        before.len().to_string()
    );
    assert_eq!(file.0["output"]["gaps"][0]["to_cursor"], "1000");
    assert_eq!(file.0["output"]["gaps"][0]["cause"], "session_capacity");
    assert_eq!(file.count("history_gap"), Some(1), "{}", file.0);
    let chunks = file.chunks();
    assert_eq!(
        chunks.first().map(|(cursor, _)| *cursor),
        Some(0),
        "{chunks:?}"
    );
    let (cursor, bytes) = chunks.last().expect("a chunk after the gap");
    assert_eq!(*cursor, 1_001, "{chunks:?}");
    assert_eq!(bytes, &after[1..], "{chunks:?}");
    assert!(
        contains(&file.output(), b"before"),
        "what came before the gap is carried"
    );
}

/// What one export carries of the output that follows a gap, given as the tail and what is left of
/// the file once the gap has been crossed: the bytes after the first point the output can be taken
/// to begin again at, and how many bytes came before it.
async fn after_a_gap(tails: &[&[u8]]) -> (Vec<u8>, Option<u64>) {
    let mut steps = vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"before\r\n"),
    ];
    let mut at = 1_000_u64;
    for (index, tail) in tails.iter().enumerate() {
        steps.push(if index == 0 {
            page_with(at, tail, Some(8))
        } else {
            page(at, tail)
        });
        at += tail.len() as u64;
    }
    steps.push(end(at));
    steps.push(privacy(false, 4, &[]));
    let mut daemon = Scripted::new(steps);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    let after: Vec<u8> = file
        .chunks()
        .into_iter()
        .filter(|(cursor, _)| *cursor >= 1_000)
        .flat_map(|(_, bytes)| bytes)
        .collect();
    (after, file.count("output_resumed_mid_stream"))
}

/// Output that begins after a range the archive no longer holds can begin inside a control string
/// whose start is gone, in any state the lexer keeps one in. It is not read until a point that ends
/// every one of them: a string terminator that follows a byte of its own, or a cancel or a
/// substitute. What came before is not carried, whatever it looks like, and is counted.
#[tokio::test]
async fn output_after_a_gap_is_read_only_from_a_point_every_state_ends_at() {
    let secret = b"c2VjcmV0LXRva2Vu";

    // A string terminator ends a clipboard write the gap cut.
    let (after, skipped) = after_a_gap(&[b"c2VjcmV0LXRva2Vu\x1b\\visible after\r\n"]).await;
    assert_eq!(after, b"visible after\r\n");
    assert_eq!(skipped, Some(secret.len() as u64 + 2));

    // A cancel and a substitute end any string and any sequence.
    for end in [0x18_u8, 0x1a] {
        let tail = [secret.as_slice(), &[end], b"visible after\r\n"].concat();
        let (after, skipped) = after_a_gap(&[&tail]).await;
        assert_eq!(after, b"visible after\r\n", "{end:#x}");
        assert_eq!(skipped, Some(secret.len() as u64 + 1));
    }

    // A bell ends an operating-system command and nothing else: in a device control string, an
    // application program command, a privacy message or a start-of-string it is payload, and what
    // follows it is payload too.
    let (after, skipped) = after_a_gap(&[b"tail\x07secret\x1b\\visible\r\n"]).await;
    assert_eq!(after, b"visible\r\n", "a bell is not where reading begins");
    assert_eq!(skipped, Some(b"tail\x07secret\x1b\\".len() as u64));

    // An escape is not where reading begins either: inside a string that was being thrown away for
    // its size an escape and the bytes after it stay in the string.
    let (after, skipped) = after_a_gap(&[b"secret\x1b[31mmore secret\x07\x18visible\r\n"]).await;
    assert_eq!(after, b"visible\r\n");
    assert_eq!(
        skipped,
        Some(b"secret\x1b[31mmore secret\x07\x18".len() as u64)
    );

    // A line ending is payload to a string, as a clipboard write wrapped at a fixed width is.
    let (after, _) = after_a_gap(&[b"c2VjcmV0\r\ncmV0LXRva2Vu\nZW5k\x1b\\visible after\r\n"]).await;
    assert_eq!(after, b"visible after\r\n");

    // Inside a multiplexer's pass-through string an escape is doubled, so a terminator is an escape
    // that follows something else: the second of two is not one, and neither is the first byte of
    // the output, which may follow an escape the gap took.
    let (after, _) = after_a_gap(&[b"x\x1b\x1b\\secret\x07\x1b\\after\r\n"]).await;
    assert_eq!(
        after, b"after\r\n",
        "an escape that follows an escape is not a terminator"
    );
    let (after, _) = after_a_gap(&[b"\x1b\\secret\x07\x1b\\after\r\n"]).await;
    assert_eq!(after, b"after\r\n", "nor is one the output begins with");

    // Output with no such point is not read at all, and every byte of it is counted.
    let tail = b"plain text\x1b[1mbold\x1b[0m\x07\r\nmore\r\n";
    let (after, skipped) = after_a_gap(&[tail]).await;
    assert!(after.is_empty(), "{after:?}");
    assert_eq!(skipped, Some(tail.len() as u64));
}

/// The point reading begins at can come where a page ends, or be spread over two pages: the
/// terminator is an escape and a backslash, one on each, or the last bytes of a page.
#[tokio::test]
async fn the_point_reading_begins_at_can_end_a_page_or_be_split_over_two() {
    // The terminator is the last of the page; the next page is read from its first byte.
    let (after, skipped) = after_a_gap(&[b"c2VjcmV0\x1b\\", b"visible after\r\n"]).await;
    assert_eq!(after, b"visible after\r\n");
    assert_eq!(skipped, Some(b"c2VjcmV0\x1b\\".len() as u64));

    // The escape ends one page and the backslash begins the next.
    let (after, skipped) = after_a_gap(&[b"c2VjcmV0\x1b", b"\\visible after\r\n"]).await;
    assert_eq!(after, b"visible after\r\n");
    assert_eq!(skipped, Some(b"c2VjcmV0\x1b\\".len() as u64));

    // The same split where the escape follows an escape: not a terminator.
    let (after, _) = after_a_gap(&[b"c2Vj\x1b\x1b", b"\\secret\x07\x1b\\after\r\n"]).await;
    assert_eq!(after, b"after\r\n");

    // A page with no point in it is skipped, and the next is asked the same.
    let (after, skipped) = after_a_gap(&[b"c2VjcmV0", b"cmV0LXRva2Vu\x18", b"visible\r\n"]).await;
    assert_eq!(after, b"visible\r\n");
    assert_eq!(skipped, Some(b"c2VjcmV0cmV0LXRva2Vu\x18".len() as u64));
}

/// The head of the archive was evicted: what is retained begins inside the stream, and is read from
/// a point that ends every state. The control: output that begins at the start of the stream is read
/// from its first byte.
#[tokio::test]
async fn an_evicted_head_is_read_from_a_point_that_ends_every_state_and_a_whole_stream_from_its_start()
 {
    let retained = b"cmV0LXRva2Vu\x07\x1b\\\x1b[1mbold\x1b[0m\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page_after(500, retained, Some(0), 500),
        end(500 + retained.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert!(!contains(&file.output(), b"cmV0"), "{}", file.0);
    assert!(contains(&file.output(), b"bold"), "{}", file.0);
    assert_eq!(file.0["output"]["from_cursor"], "500");

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"first line\r\n"),
        end(12),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.output(), b"first line\r\n");
    assert!(file.omission("output_resumed_mid_stream").is_none());
}

/// An archive that cannot say where its output got to reports the same gap on every page, though no
/// page skipped anything. It is listed once, and the pages are one stretch of output: a control
/// string that runs across two of them stays one string, and is not cut where a page ends.
#[tokio::test]
async fn a_gap_every_page_repeats_is_listed_once_and_does_not_cut_a_sequence() {
    let same = |from: u64, bytes: &[u8]| {
        Step::Ok(
            Method::HistoryPage,
            ParamsValue::from_typed(&HistoryPageResult {
                from_cursor: U64::new(from),
                next_cursor: U64::new(from + bytes.len() as u64),
                bytes: Bytes::new(bytes.to_vec()),
                oldest_retained_cursor: U64::new(0),
                gap: Nullable::some(HistoryGap {
                    from_cursor: U64::new(0),
                    to_cursor: U64::new(0),
                    cause: Some(HistoryGapCause::SpoolUnavailable),
                }),
            })
            .expect("a page"),
        )
    };
    let first = b"a\x1b]0;a title that";
    let second = b" runs on\x07b\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        same(0, first),
        same(first.len() as u64, second),
        end(first.len() as u64 + second.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(exported.summary.gaps, 1, "{}", file.0);
    assert_eq!(file.0["output"]["gaps"].as_array().map(Vec::len), Some(1));
    // The title is a window title, rendering data, and it comes through whole: one string that ran
    // across two pages, and not text and a stray bell.
    assert!(
        contains(&file.output(), b"\x1b]0;a title that runs on\x07"),
        "{}",
        file.0
    );
    assert!(contains(&file.output(), b"b\r\n"), "{}", file.0);
}

/// Every question a program asked is counted, however many there were: the engine that reads the
/// output for the export answers each as a terminal would, and a bound on how fast a live terminal
/// is answered is not a reason for the file to stop counting.
#[tokio::test]
async fn every_question_the_program_asked_is_counted_however_many() {
    let questions = 1_000_u64;
    let output: Vec<u8> = b"x\x1b[c".repeat(usize::try_from(questions).expect("a small count"));
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, &output),
        end(output.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.count("terminal_query"), Some(questions), "{}", file.0);
    assert!(!contains(&file.output(), b"\x1b[c"), "{}", file.0);
}

/// A page that holds more questions than the engine's queue has room for the replies to is counted
/// in full: the count is of what the program asked, not of the answers that were kept.
#[tokio::test]
async fn questions_past_the_size_of_the_reply_queue_in_one_page_are_counted() {
    // Each cursor report is six bytes, and the queue holds 128 KiB, so 21,845 fit and these do not.
    let questions = 30_000_u64;
    let output: Vec<u8> = b"\x1b[6n".repeat(usize::try_from(questions).expect("a small count"));
    assert!(output.len() < 1 << 20, "the page is within the page bound");
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, &output),
        end(output.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.count("terminal_query"), Some(questions), "{}", file.0);
}

/// A program that asks the terminal to read the clipboard is answered by the terminal engine itself,
/// with no side effect to count. The request is not in the file, and the file counts it as one of the
/// questions the program asked the terminal.
#[tokio::test]
async fn a_clipboard_read_is_not_carried_and_is_counted_as_a_question() {
    let output = b"x\x1b]52;c;?\x07y\x1b[c\r\n";
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, output),
        end(output.len() as u64),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    assert!(!contains(&file.output(), b"\x1b]52"), "{}", file.0);
    assert!(!contains(&file.output(), b"\x1b[c"), "{}", file.0);
    assert_eq!(file.count("terminal_query"), Some(2), "{}", file.0);
    assert!(file.omission("clipboard_read").is_none(), "{}", file.0);
}

/// Every 64-bit value in the file is a decimal string, as the protocol writes one, so a value past
/// what a floating-point number holds is not rounded by the reader: the display number here is one
/// past 2^53.
#[tokio::test]
async fn a_value_past_what_a_float_holds_is_written_whole() {
    let mut summary = closed(1);
    summary.display_number = DisplayNumber::new(9_007_199_254_740_993);
    let mut daemon = Scripted::new(vec![
        listing(vec![summary]),
        privacy(false, 4, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 4, &[]),
    ]);
    let exported = read(
        &mut daemon,
        &SessionSelector::Display(9_007_199_254_740_993),
        DEFAULT_MAX_BYTES,
        42,
    )
    .await
    .expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.0["session"]["display_number"], "9007199254740993");
}

/// A bound of no bytes is refused before the daemon is asked anything; the least there is, one byte,
/// is read.
#[tokio::test]
async fn a_bound_of_no_bytes_is_refused_before_anything_is_asked() {
    let mut daemon = Scripted::new(Vec::new());
    let refused = export(&mut daemon, 0).await.expect_err("is refused");
    assert!(matches!(refused, CliError::Usage(_)), "{refused}");
    assert!(daemon.methods().is_empty());

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"a"),
        page(1, b"b"),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, 1).await.expect("one byte is read");
    assert_eq!(Read::of(&exported).output(), b"a");
}

/// The read stops at the byte bound and says so, and it keeps the start of what is retained. The
/// control: a bound that is exactly the retained output is not a truncation.
#[tokio::test]
async fn the_byte_bound_keeps_the_start_and_says_what_it_left() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"12345"),
        // One byte past the bound is asked for, and it is there.
        page(5, b"6"),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, 5).await.expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.output(), b"12345");
    assert_eq!(file.0["output"]["truncated"], true);
    assert!(file.omission("output_truncated").is_some(), "{}", file.0);
    assert!(exported.summary.truncated);

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 4, &[]),
        page(0, b"12345"),
        end(5),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, 5).await.expect("exports");
    let file = Read::of(&exported);
    assert_eq!(file.output(), b"12345");
    assert_eq!(file.0["output"]["truncated"], false);
    assert!(file.omission("output_truncated").is_none(), "{}", file.0);
}

/// A session whose own record is gone comes back from the daemon with an empty shell and a default
/// size. The file does not state those as the session's own: it says they are not known.
#[tokio::test]
async fn a_session_whose_record_is_gone_is_not_given_a_shell_or_a_size_it_never_had() {
    let mut summary = closed(1);
    summary.shell_path = String::new();
    summary.cwd = String::new();
    let mut daemon = Scripted::new(vec![
        listing(vec![summary]),
        privacy(false, 4, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 4, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let file = Read::of(&exported);
    for member in [
        "shell",
        "cwd",
        "created_at_ms",
        "shell_mode",
        "worker_profile",
    ] {
        assert_eq!(file.0["session"][member], Value::Null, "{member}");
    }
    assert_eq!(file.0["dimensions"], Value::Null);
    assert!(
        file.omission("session_record_unavailable").is_some(),
        "{}",
        file.0
    );
    assert_eq!(file.output(), b"abc", "the output is carried all the same");
}

/// While privacy mode is on nothing is exported, closed sessions included: the privacy state is
/// read before any output, no page is asked for, and the refusal names privacy mode. The control: the
/// same session with the mode off is exported.
#[tokio::test]
async fn nothing_is_exported_while_privacy_mode_is_on() {
    let mut daemon = Scripted::new(vec![listing(vec![closed(1)]), privacy(true, 7, &[])]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(
        refused.to_string().contains("privacy mode is on"),
        "{refused}"
    );
    assert_eq!(refused.exit_code(), 8, "{refused}");
    assert_eq!(
        refused.code(),
        ErrorCode::PermissionDenied,
        "a refusal names its code"
    );
    assert!(
        !daemon.methods().contains(&Method::HistoryPage),
        "no output was asked for: {:?}",
        daemon.methods()
    );
}

/// A session that still owes the cleanup privacy mode asked for is not exported, whatever the switch
/// says now, because what its worker retained is not known to be gone. Another session's debt is not
/// this one's.
#[tokio::test]
async fn a_session_that_owes_privacy_cleanup_is_not_exported() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[session_id()]),
    ]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(
        refused.to_string().contains("owes the cleanup"),
        "{refused}"
    );
    assert!(!daemon.methods().contains(&Method::HistoryPage));

    // The control: a debt of another session is not this one's.
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[other_session_id()]),
        page(0, b"abc"),
        end(3),
        privacy(false, 7, &[other_session_id()]),
    ]);
    export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
}

/// Privacy mode turned on while the output was read leaves nothing written, and so does a change of
/// its generation with the mode off at both ends: a reading that straddled a change is no reading.
/// The control: the same generation at both ends exports.
#[tokio::test]
async fn a_change_of_privacy_mode_during_the_read_exports_nothing() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(true, 8, &[]),
    ]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(
        refused.to_string().contains("privacy mode is on"),
        "{refused}"
    );

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 9, &[]),
    ]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(
        refused.to_string().contains("privacy mode changed"),
        "{refused}"
    );

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 7, &[]),
    ]);
    export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
}

/// A session that has not closed is refused before any privacy state or output is read, and a
/// session the daemon does not hold is unknown. The control: the closed one is exported.
#[tokio::test]
async fn a_live_session_is_refused_and_an_unknown_one_is_unknown() {
    let mut live = closed(1);
    live.state = SessionState::Live;
    live.closure = Nullable::null();
    let mut daemon = Scripted::new(vec![listing(vec![live])]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(refused.to_string().contains("has not closed"), "{refused}");
    assert_eq!(daemon.methods(), vec![Method::SessionList]);

    let mut daemon = Scripted::new(vec![listing(vec![closed(2)])]);
    let unknown = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is unknown");
    assert!(matches!(unknown, CliError::UnknownSession(_)), "{unknown}");
    assert_eq!(daemon.methods(), vec![Method::SessionList]);
}

/// The daemon's own refusal to serve the archive, for a worker it has not seen end, is the answer:
/// nothing is composed.
#[tokio::test]
async fn the_daemons_refusal_of_the_archive_is_the_answer() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        Step::Refuses(
            Method::HistoryPage,
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the session has a worker this daemon has not confirmed ended",
            ),
        ),
    ]);
    let refused = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect_err("is refused");
    assert!(
        matches!(&refused, CliError::Refused(error) if error.code == ErrorCode::InvalidArgument),
        "{refused}"
    );
}

/// The file is made new and readable by its owner alone, holds what was composed whole, and leaves
/// no other file beside it.
#[cfg(unix)]
#[tokio::test]
async fn the_file_is_new_owner_only_and_whole() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 7, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("session.json");
    write(&path, &exported).expect("writes");
    assert_eq!(
        std::fs::read(&path).expect("reads"),
        exported.document,
        "the file holds exactly what was composed"
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let names: Vec<_> = std::fs::read_dir(directory.path())
        .expect("lists")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("session.json")]);
}

/// An export never replaces a file and never writes through a link: a name that is taken, whether
/// by a file or by a link to one, is refused before the output is read and again where the file is
/// made, and what was there is untouched.
#[cfg(unix)]
#[tokio::test]
async fn an_existing_file_or_a_link_is_refused_and_left_as_it_was() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 7, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let directory = tempfile::tempdir().expect("a directory");

    let taken_by_a_file = directory.path().join("taken.json");
    std::fs::write(&taken_by_a_file, "mine").expect("a file");
    assert!(matches!(
        refuse_existing(&taken_by_a_file),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        write(&taken_by_a_file, &exported),
        Err(CliError::Usage(_))
    ));
    assert_eq!(std::fs::read(&taken_by_a_file).expect("reads"), b"mine");

    let target = directory.path().join("somewhere-else.json");
    let link = directory.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).expect("a link to nothing yet");
    assert!(matches!(refuse_existing(&link), Err(CliError::Usage(_))));
    assert!(matches!(write(&link, &exported), Err(CliError::Usage(_))));
    assert!(
        !target.exists(),
        "nothing was written through the link to the name it leads to"
    );

    // The control: a name nothing holds is free.
    refuse_existing(&directory.path().join("free.json")).expect("a free name");
}

/// A write that cannot be made leaves nothing behind: not the file, and not the file it was being
/// made as.
#[cfg(unix)]
#[tokio::test]
async fn a_write_that_fails_leaves_nothing_behind() {
    let mut daemon = Scripted::new(vec![
        listing(vec![closed(1)]),
        privacy(false, 7, &[]),
        page(0, b"abc"),
        end(3),
        privacy(false, 7, &[]),
    ]);
    let exported = export(&mut daemon, DEFAULT_MAX_BYTES)
        .await
        .expect("exports");
    let directory = tempfile::tempdir().expect("a directory");
    let missing = directory.path().join("no-such-directory").join("out.json");
    assert!(matches!(write(&missing, &exported), Err(CliError::Ipc(_))));
    assert_eq!(
        std::fs::read_dir(directory.path()).expect("lists").count(),
        0,
        "nothing was made"
    );
}
