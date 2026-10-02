//! `kr export`: one closed session's retained output, written to a file the person names.
//!
//! What a host keeps of a session is the raw terminal output its program wrote, before anything
//! decided what the bytes meant. They carry whatever the program asked a terminal to do: write the
//! clipboard, raise a notification, ask what the terminal is. An export that wrote them as they were
//! kept would hand every reader of the file a stream that does those things again to whoever
//! replays it. So the output is read through the terminal engine that read it the first time, and
//! the file carries only the spans of it the engine clears for a terminal to draw. What the engine
//! dropped is counted by what it was, and the count is in the file.
//!
//! The same code serves a session on this host and one in an enrolled environment, because both are
//! reached through a [`Link`]: the daemon that holds the archive is asked the same questions either
//! way.
//!
//! Three rules decide what is read and what is written.
//!
//! * **Privacy mode fences the read.** No session of an environment whose privacy mode is on is
//!   exported, and neither is one that still owes the cleanup privacy mode asked for. The mode is
//!   read before the first page of output and after the last, and an export during which it changed
//!   writes nothing.
//! * **Nothing is written until the whole read has passed.** The file is made new, beside its final
//!   name, and given its name without replacing anything: an existing file, or a link to one, is
//!   refused, and a failure leaves no partial file. Its mode is 0600 on Unix. On Windows it takes
//!   the access list of the folder the person named, which is theirs to choose.
//! * **The file says what it does not hold.** The archive keeps no time for any piece of output and
//!   no size but the session's last, and it can have lost a range; each is declared.
//!
//! The file is one JSON document. A position in the output and a time are written as decimal
//! strings, as the protocol writes every 64-bit value, so a reader that holds numbers as floating
//! point does not lose their last digits; output bytes are base64url text, unpadded.

use std::path::Path;

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::recovery::{HistoryGap, HistoryPageParams, HistoryPageResult};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{
    ClosureRecord, Dimensions, SessionListParams, SessionListResult, SessionState, SessionSummary,
};
use kr_term::budget::GridSize;
use kr_term::diag::DiagnosticKind;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::lane::{LaneGate, LaneLimits};
use kr_term::sideeffect::SideEffectKind;
use kr_term::span::ByteSpan;
use serde::Serialize;

use crate::bridge::link::Link;
use crate::error::{CliError, Result};
use crate::resolve::SessionSelector;

/// The format the file declares, so a reader knows what it has.
pub const FORMAT: &str = "kalareach-session-export/1";

/// How much retained output an export reads unless the person says otherwise.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// What a read of one session produced, before any file exists.
pub struct Exported {
    document: Vec<u8>,
    /// What the file holds, for the command to say.
    pub summary: Summary,
}

kr_client::debug_as_name!(Exported);

/// What an export holds, in numbers a person can read at a glance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The session.
    pub session_id: SessionId,
    /// The number it is listed under in its environment.
    pub display_number: u64,
    /// How many bytes of retained output were read.
    pub bytes_read: u64,
    /// How many of those bytes the file carries.
    pub bytes_carried: u64,
    /// How many ranges of output the archive no longer holds.
    pub gaps: usize,
    /// Whether the read stopped at the byte bound with output left.
    pub truncated: bool,
    /// What the file declares it does not hold, by kind.
    pub omissions: Vec<&'static str>,
}

/// Refuses a bound of no bytes, which names nothing to read.
///
/// The command asks this before it reaches an environment, so a mistake in the arguments starts and
/// asks nothing.
///
/// # Errors
///
/// Returns a usage failure when `max_bytes` is zero.
pub fn check_bound(max_bytes: u64) -> Result<()> {
    if max_bytes == 0 {
        return Err(CliError::Usage(Shown::said(
            "--max-bytes names how much retained output to read, and an export reads at least one \
             byte",
        )));
    }
    Ok(())
}

/// Reads one closed session's retained output and composes the export of it.
///
/// Nothing is written: the file is made by [`write`] once this has passed.
///
/// # Errors
///
/// Returns `UNKNOWN_SESSION` for a session the daemon does not hold, a refusal for one that has not
/// closed or whose worker the daemon has not seen end, and a refusal naming privacy mode when it is
/// on, when the session still owes its cleanup, or when it changed during the read. Returns the
/// daemon's refusal or a transport failure otherwise.
pub async fn read<L: Link>(
    link: &mut L,
    selector: &SessionSelector,
    max_bytes: u64,
    exported_at_ms: u64,
) -> Result<Exported> {
    check_bound(max_bytes)?;
    let listed: SessionListResult = ask(
        link,
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::null(),
            include_closed: true,
        },
    )
    .await?;
    let found = listed.sessions.into_iter().find(|summary| match selector {
        SessionSelector::Display(number) => summary.display_number.get() == *number,
        SessionSelector::Identifier(session_id) => summary.session_id == *session_id,
    });
    let Some(session) = found else {
        return Err(CliError::UnknownSession(selector.said()));
    };
    if session.state != SessionState::Closed {
        return Err(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "session {} has not closed, and a session is exported after it closes: its \
                 output is read from the archive of a session that has ended",
                session.display_number.get()
            ),
        });
    }

    let before: PrivacyReport = ask(link, Method::PrivacyStatus, &PrivacyStatusParams {}).await?;
    fence(&before, &session)?;

    let read = pages(link, &session, max_bytes).await?;

    let after: PrivacyReport = ask(link, Method::PrivacyStatus, &PrivacyStatusParams {}).await?;
    fence(&after, &session)?;
    if after.generation != before.generation {
        return Err(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: Shown::said(
                "privacy mode changed while the output was being read, so nothing was written; \
                 export again",
            ),
        });
    }

    compose(&session, read, exported_at_ms)
}

/// Refuses a session privacy mode keeps from an export.
///
/// Privacy mode is one switch for the whole environment, so while it is on every session is private,
/// closed ones included. A session that still owes cleanup is private whatever the switch says now:
/// what its worker retained is not known to be gone.
fn fence(report: &PrivacyReport, session: &SessionSummary) -> Result<()> {
    if report.enabled {
        return Err(refused(shown!(
            "privacy mode is on in this environment, so session {} is not exported; nothing is \
             exported while it is on",
            session.display_number.get()
        )));
    }
    if report
        .sessions
        .iter()
        .any(|owing| owing.session_id == session.session_id)
    {
        return Err(refused(shown!(
            "session {} still owes the cleanup privacy mode asked for, so what it retained is not \
             exported; `kr privacy status` says where the cleanup stands",
            session.display_number.get()
        )));
    }
    Ok(())
}

fn refused(message: Shown) -> CliError {
    CliError::refused_in_its_own_words(ErrorCode::PermissionDenied, message)
}

/// What reading a session's pages found.
struct Read {
    chunks: Vec<Chunk>,
    gaps: Vec<HistoryGap>,
    /// Where the first page began, after any gap before it.
    from_cursor: u64,
    oldest_retained: u64,
    next_cursor: u64,
    bytes_read: u64,
    truncated: bool,
    tally: Tally,
}

/// One piece of output the engine cleared, and the cursor it starts at.
struct Chunk {
    cursor: u64,
    bytes: Vec<u8>,
}

/// Reads every page of the session's retained output from its start, through the engine.
async fn pages<L: Link>(link: &mut L, session: &SessionSummary, max_bytes: u64) -> Result<Read> {
    let session_id = session.session_id;
    let size = grid_size(session);
    let mut read = Read {
        chunks: Vec::new(),
        gaps: Vec::new(),
        from_cursor: 0,
        oldest_retained: 0,
        next_cursor: 0,
        bytes_read: 0,
        truncated: false,
        tally: Tally::default(),
    };
    let mut run: Option<Run> = None;
    let mut cursor = 0_u64;
    let mut first = true;
    loop {
        let remaining = max_bytes.saturating_sub(read.bytes_read);
        if remaining == 0 {
            // The bound is met. One more byte says whether anything was left behind.
            let more = page(link, session_id, cursor, 1).await?;
            read.truncated = !more.bytes.is_empty();
            break;
        }
        let page = page(
            link,
            session_id,
            cursor,
            remaining.min(kr_protocol::recovery::MAX_HISTORY_PAGE_BYTES),
        )
        .await?;
        if first {
            read.from_cursor = page.from_cursor.get();
            read.oldest_retained = page.oldest_retained_cursor.get();
            first = false;
        }
        if let Some(gap) = page.gap.0
            && !read.gaps.contains(&gap)
        {
            read.gaps.push(gap);
        }
        let from = page.from_cursor.get();
        let next = page.next_cursor.get();
        // Output that does not continue from where the last page ended: a range the archive no
        // longer holds came between. What follows it is not a continuation of what came before, so a
        // control string cut by the gap does not swallow the output after it, and what follows
        // begins somewhere in the stream that is not known, which is the start of the first
        // sequence the output is read from. A page that reports a gap it did not skip, because the
        // archive cannot say where its output got to, is a continuation.
        if from != cursor
            && let Some(ended) = run.take()
        {
            ended.finish(&mut read);
        }
        let bytes = page.bytes.into_vec();
        read.bytes_read += bytes.len() as u64;
        if !bytes.is_empty() {
            let current = match run.as_mut() {
                Some(current) => current,
                None => run.insert(Run::start(from, size, from != 0)?),
            };
            current.feed(from, &bytes, &mut read.tally);
        }
        read.next_cursor = read.next_cursor.max(next);
        if next <= cursor && bytes.is_empty() {
            break;
        }
        cursor = next;
    }
    if let Some(ended) = run.take() {
        ended.finish(&mut read);
    }
    Ok(read)
}

/// The size the session's output is read at: its last one, or the engine's default where that is
/// not a size a screen can have, as it is for a session whose own record is gone.
fn grid_size(session: &SessionSummary) -> GridSize {
    let size = GridSize::new(
        u32::try_from(session.dimensions.columns()).unwrap_or(0),
        u32::try_from(session.dimensions.rows()).unwrap_or(0),
    );
    size.validate().unwrap_or(kr_term::budget::DEFAULT_SIZE)
}

/// Asks for one page of retained output.
async fn page<L: Link>(
    link: &mut L,
    session_id: SessionId,
    from_cursor: u64,
    max_bytes: u64,
) -> Result<HistoryPageResult> {
    ask(
        link,
        Method::HistoryPage,
        &HistoryPageParams {
            session_id,
            from_cursor: U64::new(from_cursor),
            max_bytes: U64::new(max_bytes),
        },
    )
    .await
}

/// Calls a read and decodes the answer as the type it should be.
async fn ask<L: Link, T: kr_protocol::wire::WireMessage>(
    link: &mut L,
    method: Method,
    params: &(impl serde::Serialize + ?Sized),
) -> Result<T> {
    let answer = link.request(method, params).await?;
    decode(answer)
}

fn decode<T: kr_protocol::wire::WireMessage>(answer: crate::bridge::link::Answer) -> Result<T> {
    let value: ParamsValue = answer.map_err(CliError::Refused)?;
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the daemon's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}

/// One unbroken stretch of retained output, read by an engine of its own.
struct Run {
    /// Where the bytes the engine was fed begin in the session's output.
    start: u64,
    /// Set where the stretch begins somewhere in the stream that is not known, so that its first
    /// bytes may be the end of a sequence the output before it began: nothing is read until the
    /// point [`Skipping`] finds, and then this is clear.
    skipping: Option<Skipping>,
    /// Every byte fed to the engine, so the spans it clears can be cut out.
    fed: Vec<u8>,
    engine: Engine,
    /// What the engine cleared, merged where one span ends where the next begins.
    spans: Vec<ByteSpan>,
}

impl Run {
    /// Starts a stretch at `start`, read by an engine whose screen is the session's last size.
    ///
    /// The clock does not change which bytes are cleared for a terminal, so it never moves.
    fn start(start: u64, size: GridSize, resuming: bool) -> Result<Self> {
        let engine = Engine::new(EngineConfig {
            size,
            // The replies are written to nobody, so a bound on how fast a terminal is answered
            // would only stop the count of the questions asked.
            lane: LaneLimits {
                responses_per_second: u32::MAX,
                ..LaneLimits::DEFAULT
            },
            ..EngineConfig::DEFAULT
        })
        .map_err(|_| {
            CliError::Other(Shown::said(
                "the terminal engine could not be made for the session's size",
            ))
        })?;
        Ok(Self {
            start,
            skipping: resuming.then(Skipping::default),
            fed: Vec::new(),
            engine,
            spans: Vec::new(),
        })
    }

    /// Feeds the bytes of one page, which begin at `from` in the session's output.
    fn feed(&mut self, from: u64, bytes: &[u8], tally: &mut Tally) {
        let mut bytes = bytes;
        let mut from = from;
        if let Some(skipping) = &mut self.skipping {
            let Some(skipped) = skipping.point(bytes) else {
                // Nothing in this page is somewhere reading can begin, so the next page is asked
                // the same.
                tally.bytes_resumed += bytes.len() as u64;
                self.start = from + bytes.len() as u64;
                return;
            };
            tally.bytes_resumed += skipped as u64;
            bytes = &bytes[skipped..];
            from += skipped as u64;
            self.start = from;
            // Reading has begun, even where the point was the last byte of the page.
            self.skipping = None;
            if bytes.is_empty() {
                return;
            }
        }
        self.fed.extend_from_slice(bytes);
        let outcome = self.engine.feed(bytes, 0);
        self.take(&outcome, tally);
        self.discard_replies();
    }

    /// Throws away the replies the engine queued, which nothing is waiting for.
    fn discard_replies(&mut self) {
        let _ = self
            .engine
            .lane_mut()
            .drain(LaneGate::default(), usize::MAX, 0);
    }

    fn take(&mut self, outcome: &FeedOutcome, tally: &mut Tally) {
        for span in &outcome.forward {
            match self.spans.last_mut() {
                Some(last) if last.adjoins(*span) => *last = last.join(*span),
                _ => self.spans.push(*span),
            }
        }
        tally.absorb(outcome);
        // A reply the lane refused for want of room is a question all the same, and the record of
        // those refusals is read once and cleared, so the next outcome has its own.
        let refused = self.engine.lane().degradation();
        tally.replies += refused.dropped + refused.over_budget + refused.oversized;
        self.engine.lane_mut().clear_degradation();
    }

    /// Ends the stretch: what the engine held back is released, and what it cleared is cut out.
    fn finish(mut self, read: &mut Read) {
        let tail = self.engine.quiesce(0);
        self.take(&tail, &mut read.tally);
        self.discard_replies();
        let closing = self.engine.close(0);
        self.take(&closing, &mut read.tally);
        for (kind, count) in self.engine.diagnostic_totals() {
            *read.tally.diagnostics.entry(kind).or_insert(0) += count;
        }
        read.tally.bytes_fed += self.fed.len() as u64;
        for span in &self.spans {
            let (Ok(from), Ok(to)) = (usize::try_from(span.start()), usize::try_from(span.end()))
            else {
                continue;
            };
            let Some(bytes) = self.fed.get(from..to) else {
                continue;
            };
            read.tally.bytes_carried += bytes.len() as u64;
            read.chunks.push(Chunk {
                cursor: self.start + span.start(),
                bytes: bytes.to_vec(),
            });
        }
    }
}

/// Finds where output that begins somewhere in the stream can first be read, a page at a time.
///
/// Output that begins after a range the archive no longer holds can begin inside any state the
/// terminal's lexer keeps a sequence in: the rest of a clipboard write, a title or a notification
/// looks like text, and what ends it can look like a bell. A point where reading can begin has to
/// end every one of those states, so it is one of two things:
///
/// * a cancel or a substitute, which end every string and every sequence;
/// * a string terminator, an escape and a backslash, that follows a byte of the output's own and
///   that byte is not an escape. A multiplexer's pass-through string doubles the escapes inside it,
///   so an escape that follows another is not the one that ends it, and the first byte of the output
///   may follow the escape the gap took.
///
/// A bell is not such a point, because it ends an operating-system command and is payload in the
/// other strings. An escape alone is not, because a string thrown away for its size keeps an escape
/// and what follows it. A line ending is not, because a string carries carriage returns and line
/// feeds, as a clipboard write wrapped at a fixed width does. Everything before the point is counted
/// as not carried, and output with no such point is not read at all.
#[derive(Default)]
struct Skipping {
    /// The last two bytes skipped, the earlier first.
    last: [Option<u8>; 2],
}

impl Skipping {
    /// How many of `bytes`, which follow what was skipped before, are not read: those up to and
    /// including the point reading begins after. None when there is no such point in them.
    fn point(&mut self, bytes: &[u8]) -> Option<usize> {
        for (at, &byte) in bytes.iter().enumerate() {
            let [before, previous] = self.last;
            let ends = match byte {
                0x18 | 0x1a => true,
                b'\\' => previous == Some(0x1b) && before.is_some_and(|before| before != 0x1b),
                _ => false,
            };
            if ends {
                return Some(at + 1);
            }
            self.last = [previous, Some(byte)];
        }
        None
    }
}

/// What the engines found in the output that the file does not carry.
#[derive(Default)]
struct Tally {
    bytes_fed: u64,
    bytes_carried: u64,
    /// Bytes at the start of output that began after a gap, which were not read.
    bytes_resumed: u64,
    clipboard_writes: u64,
    notifications: u64,
    progress_reports: u64,
    bells: u64,
    refused_effects: u64,
    /// What the engine answered itself where the program asked the terminal something, among them
    /// reads of the clipboard.
    replies: u64,
    diagnostics: std::collections::BTreeMap<DiagnosticKind, u64>,
}

impl Tally {
    fn absorb(&mut self, outcome: &FeedOutcome) {
        for effect in &outcome.side_effects {
            match effect.kind {
                SideEffectKind::Bell => self.bells += 1,
                SideEffectKind::Notification { .. } => self.notifications += 1,
                SideEffectKind::Progress { .. } => self.progress_reports += 1,
                SideEffectKind::ClipboardWrite { .. } => self.clipboard_writes += 1,
                // The engine's own policy answers a read itself, so it routes none.
                SideEffectKind::ClipboardRead { .. } => self.replies += 1,
            }
        }
        self.refused_effects += outcome.refusals.len() as u64;
        self.replies += outcome.responses as u64;
    }

    fn diagnosed(&self, kind: DiagnosticKind) -> u64 {
        self.diagnostics.get(&kind).copied().unwrap_or(0)
    }
}

/// One thing the file does not carry.
struct Omission {
    kind: &'static str,
    detail: String,
    count: Option<u64>,
}

impl Omission {
    fn said(kind: &'static str, detail: &str) -> Self {
        Self {
            kind,
            detail: detail.to_owned(),
            count: None,
        }
    }

    fn counted(kind: &'static str, detail: &str, count: u64) -> Option<Self> {
        (count > 0).then(|| Self {
            kind,
            detail: detail.to_owned(),
            count: Some(count),
        })
    }
}

/// The omissions of one read, in the order they are declared.
fn omissions(session: &SessionSummary, read: &Read) -> Vec<Omission> {
    let tally = &read.tally;
    let mut declared = vec![
        Omission::said(
            "output_timestamps",
            "the archive keeps no time for any piece of output, so the file carries none, and no \
             asciicast recording can be made from it",
        ),
        Omission::said(
            "earlier_dimensions",
            "the archive keeps the session's last size and not the sizes it had before, so the \
             file names that one",
        ),
        Omission::said(
            "archive_completeness",
            "whether the archive lost output beyond the ranges listed under gaps is not reported \
             by the host, so the file does not say",
        ),
    ];
    if session_record_unavailable(session) {
        declared.push(Omission::said(
            "session_record_unavailable",
            "the session's own record is gone, so its shell, directory, size, mode and creation \
             time are not known",
        ));
    }
    if !read.gaps.is_empty() {
        declared.push(Omission {
            kind: "history_gap",
            detail: "ranges of output the archive no longer holds, each listed under gaps with \
                     its cause"
                .to_owned(),
            count: Some(read.gaps.len() as u64),
        });
    }
    if read.truncated {
        declared.push(Omission::said(
            "output_truncated",
            "the read stopped at the byte bound with output left; the start of what the archive \
             retains is kept and the rest is not",
        ));
    }
    let diagnosed = |kind| tally.diagnosed(kind);
    declared.extend(
        [
            Omission::counted(
                "output_resumed_mid_stream",
                "bytes at the start of output that began after a range the archive no longer \
                 holds, which are not read: they may be the end of a control string, such as a \
                 clipboard write, whose start is gone",
                tally.bytes_resumed,
            ),
            Omission::counted(
                "clipboard_write",
                "requests to write the clipboard, which a replay would perform",
                tally.clipboard_writes,
            ),
            Omission::counted(
                "notification",
                "requests to raise a notification",
                tally.notifications,
            ),
            Omission::counted(
                "progress_report",
                "progress reports for a window's title bar or taskbar",
                tally.progress_reports,
            ),
            Omission::counted("bell", "bells", tally.bells),
            Omission::counted(
                "side_effect_refused",
                "requests of a terminal that the terminal engine refused whole, such as a clipboard \
                 write past its bound or one that was not well formed",
                tally.refused_effects,
            ),
            Omission::counted(
                "terminal_query",
                "questions the program asked the terminal, among them reads of the clipboard, \
                 which the terminal engine answers itself and a replay would be asked again",
                tally.replies,
            ),
            Omission::counted(
                "image_sequence",
                "image and raster-graphics sequences",
                diagnosed(DiagnosticKind::ImageSequenceDisabled),
            ),
            Omission::counted(
                "window_request",
                "requests to change the physical window",
                diagnosed(DiagnosticKind::PhysicalWindowRequest),
            ),
            Omission::counted(
                "unclassified_sequence",
                "sequences the terminal engine has no class for",
                diagnosed(DiagnosticKind::UnclassifiedSequence),
            ),
            Omission::counted(
                "control_string_dropped",
                "control strings that passed their bound or were never ended",
                diagnosed(DiagnosticKind::OversizedControlString)
                    + diagnosed(DiagnosticKind::AbandonedControlString),
            ),
            Omission::counted(
                "malformed_utf8",
                "malformed text, which is not carried",
                diagnosed(DiagnosticKind::MalformedUtf8),
            ),
            Omission::counted(
                "bytes_not_carried",
                "bytes of the retained output that are not carried. The kinds above are the ones \
                 that are counted; the rest, such as raw eight-bit controls, hyperlinks and titles \
                 the terminal engine refused, and the controls inside a sequence, are counted only \
                 here, with those that need the screen drawn again",
                tally.bytes_fed.saturating_sub(tally.bytes_carried),
            ),
        ]
        .into_iter()
        .flatten(),
    );
    declared
}

/// Whether the daemon built this summary from the closure alone, because the session's own record
/// was gone. A session that ran always had a shell, so an empty one is not a real value.
fn session_record_unavailable(session: &SessionSummary) -> bool {
    session.shell_path.is_empty()
}

/// The file, as it is written. Every 64-bit value is a [`U64`], which the protocol writes as a
/// decimal string.
#[derive(Serialize)]
struct File<'a> {
    format: &'static str,
    exported_at_ms: U64,
    environment_id: kr_protocol::ids::EnvironmentId,
    session: SessionPart<'a>,
    closure: Option<&'a ClosureRecord>,
    dimensions: Option<DimensionsPart>,
    output: OutputPart<'a>,
    omissions: Vec<OmissionPart<'a>>,
}

/// What the file says of the session, each member null where the session's own record is gone.
#[derive(Serialize)]
struct SessionPart<'a> {
    session_id: SessionId,
    display_number: U64,
    created_at_ms: Option<U64>,
    shell_mode: Option<&'static str>,
    shell: Option<&'a str>,
    cwd: Option<&'a str>,
    worker_profile: Option<&'static str>,
}

/// The session's last size.
#[derive(Serialize)]
struct DimensionsPart {
    #[serde(flatten)]
    size: Dimensions,
    as_of: &'static str,
}

/// The retained output the file carries.
#[derive(Serialize)]
struct OutputPart<'a> {
    from_cursor: U64,
    next_cursor: U64,
    oldest_retained_cursor: U64,
    chunks: Vec<ChunkPart>,
    gaps: &'a [HistoryGap],
    truncated: bool,
}

/// One piece of output, and where in the session's output it begins.
#[derive(Serialize)]
struct ChunkPart {
    cursor: U64,
    base64url: String,
}

/// One thing the file does not hold.
#[derive(Serialize)]
struct OmissionPart<'a> {
    kind: &'static str,
    detail: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<U64>,
}

/// Composes the file from what was read.
fn compose(session: &SessionSummary, read: Read, exported_at_ms: u64) -> Result<Exported> {
    let unknown = session_record_unavailable(session);
    let declared = omissions(session, &read);
    let file = File {
        format: FORMAT,
        exported_at_ms: U64::new(exported_at_ms),
        environment_id: session.environment_id,
        session: SessionPart {
            session_id: session.session_id,
            display_number: U64::new(session.display_number.get()),
            created_at_ms: (!unknown).then(|| U64::new(session.created_at_ms.get())),
            shell_mode: (!unknown).then(|| session.shell_mode.as_str()),
            shell: (!unknown).then_some(session.shell_path.as_str()),
            cwd: (!unknown).then_some(session.cwd.as_str()),
            worker_profile: (!unknown).then(|| session.worker_profile.as_str()),
        },
        closure: session.closure.as_ref(),
        dimensions: (!unknown).then_some(DimensionsPart {
            size: session.dimensions,
            as_of: "the session's last size",
        }),
        output: OutputPart {
            from_cursor: U64::new(read.from_cursor),
            next_cursor: U64::new(read.next_cursor),
            oldest_retained_cursor: U64::new(read.oldest_retained),
            chunks: read
                .chunks
                .iter()
                .map(|chunk| ChunkPart {
                    cursor: U64::new(chunk.cursor),
                    base64url: kr_protocol::scalars::to_base64url(&chunk.bytes),
                })
                .collect(),
            gaps: &read.gaps,
            truncated: read.truncated,
        },
        omissions: declared
            .iter()
            .map(|omission| OmissionPart {
                kind: omission.kind,
                detail: &omission.detail,
                count: omission.count.map(U64::new),
            })
            .collect(),
    };
    let mut bytes = serde_json::to_vec(&file).map_err(|_| {
        CliError::Other(Shown::said(
            "the export could not be written out as a document",
        ))
    })?;
    bytes.push(b'\n');
    Ok(Exported {
        document: bytes,
        summary: Summary {
            session_id: session.session_id,
            display_number: session.display_number.get(),
            bytes_read: read.bytes_read,
            bytes_carried: read.tally.bytes_carried,
            gaps: read.gaps.len(),
            truncated: read.truncated,
            omissions: declared.iter().map(|omission| omission.kind).collect(),
        },
    })
}

/// Refuses an output name that is already taken, before anything is read.
///
/// [`write`] refuses it again where the file is made, which is the check that holds: a name taken
/// between the two is still refused there.
///
/// # Errors
///
/// Returns a usage failure when something, a link included, is already at `path`.
pub fn refuse_existing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(taken(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::Ipc(kr_ipc::IpcError::io("check", path, error))),
    }
}

fn taken(path: &Path) -> CliError {
    CliError::Usage(shown!(
        "{} already exists; an export never replaces a file or writes through a link, so name one \
         that is not there",
        crate::shown::named(path)
    ))
}

/// Writes the export to `path`: new, and complete or not there.
///
/// The bytes are written to a file beside it and given the name without replacing anything, so a
/// reader never finds a partial file and a name taken in the meantime is refused. The file's mode is
/// 0600 on Unix; on Windows it takes the access list of the folder it is in.
///
/// # Errors
///
/// Returns a usage failure when something is at `path`, and the failure to write otherwise. A
/// failure leaves nothing at `path`.
pub fn write(path: &Path, exported: &Exported) -> Result<()> {
    // A bare file name has no directory to flush once the file is in place, so the name is made
    // whole first: where the file goes is where the command was run.
    let whole = std::path::absolute(path)
        .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("resolve", path, error)))?;
    kr_ipc::paths::create_new_owner_only_file(&whole, &exported.document).map_err(|error| {
        match &error {
            kr_ipc::IpcError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                taken(path)
            }
            _ => CliError::Ipc(error),
        }
    })
}

#[cfg(test)]
mod tests;
