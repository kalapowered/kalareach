//! KR-REQ-18.11: the document a closed session's retained output is exported as holds its size
//! limits while the output is read, not after: a session whose output makes a piece for every other
//! byte cannot use more than the limits allow, and the document stays within its size.
//!
//! The pages come from a buffer in memory, served the way the daemon serves a history: from a
//! cursor, at most as many bytes as were asked, and an empty page that moves the cursor on where a
//! range was lost.

#![cfg(feature = "terminal")]

use kr_client::session_export::{Bounds, Composed, MAX_CHUNKS, PageSource, Stop, compose};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::recovery::{HistoryGap, HistoryPageResult};
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, DisplayNumber, Durability, OwnershipCoverage,
    SessionState, SessionSummary, ShellMode,
};
use serde_json::Value;

/// A history served from memory.
struct Memory {
    output: Vec<u8>,
    /// A source that ignores the size answers with everything left, as a daemon that did not keep
    /// to the size it was asked for would.
    ignores_the_size: bool,
    /// The most a page holds, where the source answers with less than it is asked for.
    page_limit: usize,
    /// A range the archive lost: a page asked from inside it holds nothing and begins after it.
    lost: Option<(u64, u64)>,
    /// The size of each page asked for.
    asked: Vec<u64>,
}

impl Memory {
    fn of(output: Vec<u8>) -> Self {
        Self {
            output,
            ignores_the_size: false,
            page_limit: usize::MAX,
            lost: None,
            asked: Vec::new(),
        }
    }
}

impl PageSource for Memory {
    type Error = std::convert::Infallible;

    async fn page(
        &mut self,
        from_cursor: u64,
        max_bytes: u64,
    ) -> Result<HistoryPageResult, Self::Error> {
        self.asked.push(max_bytes);
        if let Some((lost_from, lost_to)) = self.lost
            && (lost_from..lost_to).contains(&from_cursor)
        {
            return Ok(HistoryPageResult {
                from_cursor: U64::new(lost_to),
                next_cursor: U64::new(lost_to),
                bytes: Bytes::new(Vec::new()),
                oldest_retained_cursor: U64::new(0),
                gap: Nullable::some(HistoryGap {
                    from_cursor: U64::new(from_cursor),
                    to_cursor: U64::new(lost_to),
                    cause: None,
                }),
            });
        }
        let start = usize::try_from(from_cursor)
            .unwrap_or(usize::MAX)
            .min(self.output.len());
        let end = if self.ignores_the_size {
            self.output.len()
        } else {
            start
                .saturating_add(usize::try_from(max_bytes).unwrap_or(usize::MAX))
                .min(start.saturating_add(self.page_limit))
                .min(self.output.len())
        };
        Ok(HistoryPageResult {
            from_cursor: U64::new(start as u64),
            next_cursor: U64::new(end as u64),
            bytes: Bytes::new(self.output[start..end].to_vec()),
            oldest_retained_cursor: U64::new(0),
            gap: Nullable::null(),
        })
    }
}

fn session() -> SessionSummary {
    let session_id = SessionId::new(Uuid::from_bytes([5; 16]));
    SessionSummary {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
        display_number: DisplayNumber::new(1),
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
        closure: Nullable::some(ClosureRecord {
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
        }),
        environment_sources: None,
    }
}

/// Ordinary output: lines of text, every byte drawn.
fn lines(total: usize) -> Vec<u8> {
    let line = b"0123456789abcdefghijklmnopqrstuvwxyz\r\n";
    line.iter().copied().cycle().take(total).collect()
}

/// Output of a byte that is drawn and a bell, which the engine drops, so every other byte starts a
/// piece of output of its own.
fn alternating(pairs: usize) -> Vec<u8> {
    b"a\x07".iter().copied().cycle().take(pairs * 2).collect()
}

async fn composed(output: Vec<u8>, bounds: Bounds) -> Composed {
    run(&mut Memory::of(output), bounds).await
}

async fn run(source: &mut Memory, bounds: Bounds) -> Composed {
    match compose(source, &session(), bounds, 0, 42).await {
        Ok(composed) => composed,
        Err(Stop::Source(never)) => match never {},
        Err(stop) => panic!("the composition stopped: {stop:?}"),
    }
}

fn bounds(max_read_bytes: u64, max_document_bytes: u64) -> Bounds {
    Bounds {
        max_read_bytes,
        max_document_bytes,
        max_chunks: MAX_CHUNKS,
    }
}

/// The pieces of output the document carries, joined, and how many pieces there are.
fn carried(document: &[u8]) -> (Vec<u8>, usize) {
    let file: Value = serde_json::from_slice(document).expect("the document is JSON");
    let chunks = file["output"]["chunks"].as_array().expect("chunks");
    let joined = chunks
        .iter()
        .flat_map(|chunk| {
            kr_protocol::scalars::from_base64url(chunk["base64url"].as_str().expect("text"))
                .expect("decodes")
        })
        .collect();
    (joined, chunks.len())
}

fn next_cursor(document: &[u8]) -> u64 {
    let file: Value = serde_json::from_slice(document).expect("the document is JSON");
    file["output"]["next_cursor"]
        .as_str()
        .expect("a cursor")
        .parse()
        .expect("digits")
}

const MIB: u64 = 1024 * 1024;

/// A document that would pass its size stops the read at a page and declares it: the start of the
/// output is kept, the cursor the document ends at is where the kept output ends, and the file is
/// within its size. The control: the same output under a size it fits, at the proportion of a
/// session at the host's per-session cap to the file's size, is read whole.
#[tokio::test]
async fn a_document_that_would_pass_its_size_stops_the_read_and_says_so() {
    let output = lines(4 * MIB as usize);

    let cut = composed(output.clone(), bounds(16 * MIB, MIB)).await;
    assert!(
        cut.document.len() as u64 <= MIB,
        "the document is {} bytes",
        cut.document.len()
    );
    assert!(cut.truncated);
    assert!(cut.omissions.contains(&"output_truncated"));
    assert!(cut.bytes_read < output.len() as u64, "{}", cut.bytes_read);
    let (kept, _) = carried(&cut.document);
    assert!(
        !kept.is_empty() && output.starts_with(&kept),
        "the start is kept"
    );
    assert_eq!(
        next_cursor(&cut.document),
        kept.len() as u64,
        "the cursor names where the kept output ends"
    );

    let whole = composed(output.clone(), bounds(16 * MIB, 6 * MIB)).await;
    assert!(!whole.truncated);
    assert!(!whole.omissions.contains(&"output_truncated"));
    let (everything, _) = carried(&whole.document);
    assert_eq!(everything, output);
    assert!(whole.document.len() as u64 <= 6 * MIB);
}

/// Output that makes a piece for every other byte is held to the limit on pieces and to the size of
/// the document as it is read, and the page asked for is never a byte or two: the read stops where
/// a page worth asking for no longer fits. The control: the same output under limits it fits is
/// carried whole, piece for piece.
#[tokio::test]
async fn output_that_makes_a_piece_for_every_other_byte_is_held_to_the_limits() {
    let pairs = 100_000;
    let output = alternating(pairs);

    let free = composed(output.clone(), bounds(16 * MIB, 192 * MIB)).await;
    let (_, pieces) = carried(&free.document);
    assert_eq!(pieces, pairs, "each drawn byte is a piece of its own");
    assert!(!free.truncated);

    let few = composed(
        output.clone(),
        Bounds {
            max_chunks: 20_000,
            ..bounds(16 * MIB, 192 * MIB)
        },
    )
    .await;
    let (kept, pieces) = carried(&few.document);
    assert!(pieces <= 20_000, "{pieces} pieces");
    assert!(pieces > 10_000, "the read goes on to the limit: {pieces}");
    assert!(few.truncated);
    assert!(few.omissions.contains(&"output_truncated"));
    assert!(kept.iter().all(|&byte| byte == b'a'));
    assert_eq!(
        next_cursor(&few.document),
        2 * pieces as u64,
        "the cursor is where the next piece would begin"
    );

    let mut source = Memory::of(output);
    let small = run(&mut source, bounds(16 * MIB, 2 * MIB)).await;
    let (_, pieces) = carried(&small.document);
    assert!(
        small.document.len() as u64 <= 2 * MIB,
        "the document is {} bytes",
        small.document.len()
    );
    assert!(small.truncated);
    assert!(pieces > 10_000, "the read goes on to the size: {pieces}");
    assert!(
        source
            .asked
            .iter()
            .all(|&asked| asked == 1 || asked >= 8 * 1024),
        "a page was asked for that is not worth asking for: {:?}",
        source.asked
    );
}

/// A source that answers with more than it was asked for does not take the document past its
/// limits: the pieces that would pass them are cut off the end, and the cursor names where the
/// first of them began. Pieces and size are cut apart.
#[tokio::test]
async fn a_source_that_ignores_the_size_asked_for_does_not_pass_the_limits() {
    let greedy = || Memory {
        ignores_the_size: true,
        ..Memory::of(alternating(100_000))
    };

    let by_pieces = run(
        &mut greedy(),
        Bounds {
            max_chunks: 5_000,
            ..bounds(16 * MIB, 192 * MIB)
        },
    )
    .await;
    let (_, pieces) = carried(&by_pieces.document);
    assert_eq!(pieces, 5_000);
    assert!(by_pieces.truncated);
    assert_eq!(
        next_cursor(&by_pieces.document),
        10_000,
        "the cursor is where the first dropped piece began"
    );

    let by_size = run(&mut greedy(), bounds(16 * MIB, MIB)).await;
    let (_, pieces) = carried(&by_size.document);
    assert!(
        by_size.document.len() as u64 <= MIB,
        "{} bytes",
        by_size.document.len()
    );
    assert!(by_size.truncated);
    assert_eq!(next_cursor(&by_size.document), 2 * pieces as u64);
}

/// The engine holds a control string back until it ends, so a page of a byte can let go of all of
/// it at once. Whatever the size the document is allowed, no piece that was read is cut off to keep
/// it: the cursor the document ends at is where the read stopped.
#[tokio::test]
async fn a_string_the_engine_lets_go_of_late_does_not_cost_the_document_its_end() {
    let mut output = alternating(10_000);
    output.extend_from_slice(b"\x1b]2;");
    output.extend(std::iter::repeat_n(b'x', 60_000));
    output.push(0x07);
    output.extend_from_slice(&alternating(10_000));
    for allowed in (500_000..=1_300_000).step_by(50_000) {
        let mut source = Memory {
            page_limit: 1_024,
            ..Memory::of(output.clone())
        };
        let composed = run(&mut source, bounds(16 * MIB, allowed)).await;
        assert!(
            composed.document.len() as u64 <= allowed,
            "{} bytes under {allowed}",
            composed.document.len()
        );
        assert_eq!(
            next_cursor(&composed.document),
            composed.bytes_read,
            "a piece was cut off after it was read, under {allowed}"
        );
    }
}

/// A page can hold nothing and still move the cursor on, across a range the archive lost. Output
/// that lies past it is output left behind.
#[tokio::test]
async fn output_past_a_lost_range_is_output_left_behind() {
    let mut source = Memory {
        lost: Some((10, 20)),
        ..Memory::of(lines(30))
    };
    let cut = run(&mut source, bounds(10, 192 * MIB)).await;
    assert!(cut.truncated);
    assert!(cut.omissions.contains(&"output_truncated"));

    let mut source = Memory {
        lost: Some((10, 20)),
        ..Memory::of(lines(20))
    };
    let whole = run(&mut source, bounds(10, 192 * MIB)).await;
    assert!(!whole.truncated, "nothing lies past the lost range");
}
