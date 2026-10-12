//! The document a closed session's retained output is exported as.
//!
//! What a host keeps of a session is the raw terminal output its program wrote, before anything
//! decided what the bytes meant. They carry whatever the program asked a terminal to do: write the
//! clipboard, raise a notification, ask what the terminal is. A document that held them as they were
//! kept would hand every reader a stream that does those things again to whoever replays it. So the
//! output is read through the terminal engine that read it the first time, and the document carries
//! only the spans of it the engine clears for a terminal to draw. What the engine dropped is counted
//! by what it was, and the count is in the document.
//!
//! The same composer serves `kr export`, which reads the pages from a daemon over a link, and the
//! host's backup, which reads them from the archive it holds. Both give it a [`PageSource`].
//!
//! # What the document says it does not hold
//!
//! The archive keeps no time for any piece of output and no size but the session's last, and it can
//! have lost a range. Each is declared under `omissions`, with the kinds of side effect the engine
//! dropped and the bytes it did not carry.
//!
//! # How it is bounded
//!
//! A hostile session can alternate one byte of text with one byte the engine drops, so that every
//! other byte starts a piece of output of its own. The composer therefore keeps a piece as a cursor
//! and a range into the bytes it was fed (16 bytes), never as a copy, and holds three limits as the
//! pieces arrive and not after:
//!
//! * the bytes read, [`Bounds::max_read_bytes`];
//! * the pieces, [`Bounds::max_chunks`], so the list that holds them never grows past it;
//! * the size of the finished document, [`Bounds::max_document_bytes`]. Every piece is charged its
//!   framing and its base64 text, the document buffer is reserved at the charge and written from
//!   the ranges, and a page is asked for only when the most it can add still fits, counting what
//!   the engine can hold back and let go in it.
//!
//! When a limit would be passed the read stops at a page boundary, keeps the start of the output
//! and drops the rest, and the document says `output_truncated`. The cursor the document ends at
//! is where the read stopped, or where the first piece that was cut off begins, so a reader that
//! continues from it misses none of the output the document leaves out.

use std::future::Future;

use base64::display::Base64Display;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::recovery::{HistoryGap, HistoryPageResult, MAX_HISTORY_PAGE_BYTES};
use kr_protocol::scalars::U64;
use kr_protocol::session::{ClosureRecord, Dimensions, SessionSummary};
use kr_term::budget::GridSize;
use kr_term::diag::DiagnosticKind;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::lane::{LaneGate, LaneLimits};
use kr_term::lexer::LexLimits;
use kr_term::sideeffect::SideEffectKind;
use kr_term::span::ByteSpan;
use serde::{Serialize, Serializer};

/// The format the document declares, so a reader knows what it has.
pub const FORMAT: &str = "kalareach-session-export/1";

/// The most pieces of output a document holds: 64 MiB of ranges.
pub const MAX_CHUNKS: usize = 4_000_000;

/// What the framing of one piece of output is charged at in the document's projected size.
///
/// The smallest piece the format writes is 32 bytes, a one-byte cursor and one byte of output. The
/// framing of a piece is 29 bytes and its cursor's digits, at most 20, and its text is rounded up to
/// whole base64 symbols, under one more symbol: 50 is over all three.
const CHUNK_FRAMING: u64 = 50;

/// The most a byte read can add to the document's projected size: a piece of one byte for every
/// other byte read comes to under 27, and 40 leaves room.
const MOST_A_BYTE_ADDS: u64 = 40;

/// What the engine can hold back between pages and let go in a later one: a control string, a text
/// run and a sequence, each at its bound. A page of one byte can release all of it.
const HELD_BACK: u64 = (LexLimits::DEFAULT.max_control_string
    + LexLimits::DEFAULT.max_text_run
    + LexLimits::DEFAULT.max_sequence_bytes) as u64;

/// The least a page asks for while the read has more to ask for. A read that cannot afford a page
/// this size stops, so a document nearing its limit is not read a byte at a time.
const LEAST_PAGE: u64 = 8 * 1024;

/// The most bytes read: a piece's offset among the bytes fed is 32 bits.
const MOST_READ: u64 = u32::MAX as u64;

/// How many pieces the list is first made room for.
const FIRST_CHUNKS: usize = 1024;

/// Where the pages of a session's retained output come from.
pub trait PageSource {
    /// Why a page could not be had.
    type Error;

    /// Reads at most `max_bytes` of the retained output from `from_cursor`.
    ///
    /// # Errors
    ///
    /// Returns what stopped the read. The composition stops with it and writes nothing.
    fn page(
        &mut self,
        from_cursor: u64,
        max_bytes: u64,
    ) -> impl Future<Output = Result<HistoryPageResult, Self::Error>>;
}

/// The limits a composition holds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// The most retained output to read, in bytes. The start of what is retained is kept. A read
    /// is held to one byte under 4 GiB whatever is given, because a piece's offset among the bytes
    /// fed is 32 bits.
    pub max_read_bytes: u64,
    /// The most the finished document may hold, in bytes.
    pub max_document_bytes: u64,
    /// The most pieces of output the document may hold. [`MAX_CHUNKS`] unless a case needs less.
    pub max_chunks: usize,
}

/// What a composition produced.
pub struct Composed {
    /// The document, ending in a line feed.
    pub document: Vec<u8>,
    /// How many bytes of retained output were read.
    pub bytes_read: u64,
    /// How many of those bytes the document carries.
    pub bytes_carried: u64,
    /// How many ranges of output the archive no longer holds.
    pub gaps: usize,
    /// Whether the read stopped at a bound with output left.
    pub truncated: bool,
    /// What the document declares it does not hold, by kind.
    pub omissions: Vec<&'static str>,
}

crate::debug_as_name!(Composed);

/// Why a composition stopped.
pub enum Stop<E> {
    /// The source could not give a page.
    Source(E),
    /// The terminal engine could not be made for the session's size.
    Engine,
    /// The document could not be written out within its limit.
    Document,
}

impl<E> core::fmt::Debug for Stop<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Stop").finish_non_exhaustive()
    }
}

/// Reads one closed session's retained output from `source` and composes its document.
///
/// `expected_bytes` is how much retained output the caller expects, so the bytes fed to the engine
/// are reserved once; a caller that does not know passes zero. `exported_at_ms` is written into the
/// document.
///
/// # Errors
///
/// Returns the source's failure, or a failure to make the engine or to write the document.
pub async fn compose<S: PageSource>(
    source: &mut S,
    session: &SessionSummary,
    bounds: Bounds,
    expected_bytes: u64,
    exported_at_ms: u64,
) -> Result<Composed, Stop<S::Error>> {
    let mut collector = Collector::new(session, bounds, expected_bytes, exported_at_ms)?;
    collector.read(source).await?;
    collector.finish()
}

/// One piece of output the engine cleared: where it starts in the session's output, and where its
/// bytes are among those fed.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    cursor: u64,
    offset: u32,
    len: u32,
}

impl Chunk {
    fn end(self) -> u32 {
        self.offset.saturating_add(self.len)
    }

    fn bytes(self, fed: &[u8]) -> &[u8] {
        let start = self.offset as usize;
        fed.get(start..start + self.len as usize)
            .unwrap_or_default()
    }
}

/// Where the engines' output goes as it is produced: the bytes fed, the pieces cut out of them and
/// the counts.
struct Sink {
    fed: Vec<u8>,
    chunks: Vec<Chunk>,
    /// The bytes the pieces hold.
    carried: u64,
    max_chunks: usize,
    /// Where the first piece dropped for want of room begins, which a source that kept to the page
    /// size it was asked for never causes.
    dropped_from: Option<u64>,
    tally: Tally,
}

impl Sink {
    /// Takes the spans an engine cleared as pieces of the run `run`, joining a span to the piece
    /// before it where the two touch.
    fn take(&mut self, run: &Run, outcome: &FeedOutcome) {
        for span in &outcome.forward {
            self.push(run, *span);
        }
        self.tally.absorb(outcome);
    }

    fn push(&mut self, run: &Run, span: ByteSpan) {
        let cursor = run.start.saturating_add(span.start());
        let placed = usize::try_from(span.start())
            .ok()
            .and_then(|start| run.base.checked_add(start))
            .and_then(|offset| u32::try_from(offset).ok())
            .zip(u32::try_from(span.len()).ok());
        let Some((offset, len)) = placed else {
            self.dropped_from.get_or_insert(cursor);
            return;
        };
        if len == 0 {
            return;
        }
        if let Some(last) = self
            .chunks
            .get_mut(run.first_chunk..)
            .and_then(<[Chunk]>::last_mut)
            && last.end() == offset
            && let Some(joined) = last.len.checked_add(len)
        {
            last.len = joined;
            self.carried += u64::from(len);
            return;
        }
        if self.chunks.len() >= self.max_chunks {
            self.dropped_from.get_or_insert(cursor);
            return;
        }
        if self.chunks.len() == self.chunks.capacity() {
            // Doubled, and never past the limit, which a list that doubled on its own could be.
            let room = self.chunks.len().max(FIRST_CHUNKS);
            self.chunks
                .reserve_exact(room.min(self.max_chunks - self.chunks.len()));
        }
        self.chunks.push(Chunk {
            cursor,
            offset,
            len,
        });
        self.carried += u64::from(len);
    }
}

/// What a read of one session found, and the limits it is held to.
struct Collector<'a> {
    session: &'a SessionSummary,
    size: GridSize,
    bounds: Bounds,
    exported_at_ms: u64,
    sink: Sink,
    gaps: Vec<HistoryGap>,
    /// Where the first page began, after any gap before it.
    from_cursor: u64,
    oldest_retained: u64,
    next_cursor: u64,
    bytes_read: u64,
    truncated: bool,
    /// The size of the document without its pieces of output and its gaps, at the most it can be.
    overhead: u64,
    /// What a gap is charged in the document's projected size.
    gap_charge: u64,
    /// What a page can add that its own bytes do not account for: the two pieces it can begin, a
    /// gap with its listing, and everything the engine can let go that an earlier page left with
    /// it.
    page_fixed: u64,
}

impl<'a> Collector<'a> {
    fn new<E>(
        session: &'a SessionSummary,
        bounds: Bounds,
        expected_bytes: u64,
        exported_at_ms: u64,
    ) -> Result<Self, Stop<E>> {
        let reserve = expected_bytes.min(bounds.max_read_bytes).min(MOST_READ);
        let overhead = skeleton(session, exported_at_ms).ok_or(Stop::Document)?;
        if overhead > bounds.max_document_bytes {
            return Err(Stop::Document);
        }
        let gap_charge = gap_charge();
        Ok(Self {
            session,
            size: grid_size(session),
            bounds,
            exported_at_ms,
            sink: Sink {
                fed: Vec::with_capacity(usize::try_from(reserve).unwrap_or(0)),
                chunks: Vec::new(),
                carried: 0,
                max_chunks: bounds.max_chunks,
                dropped_from: None,
                tally: Tally::default(),
            },
            gaps: Vec::new(),
            from_cursor: 0,
            oldest_retained: 0,
            next_cursor: 0,
            bytes_read: 0,
            truncated: false,
            overhead,
            gap_charge,
            page_fixed: CHUNK_FRAMING
                .saturating_mul(2)
                .saturating_add(gap_charge)
                .saturating_add(HELD_BACK.div_ceil(3).saturating_mul(4))
                .saturating_add(1),
        })
    }

    /// What the document comes to if it were written now, at the most: its framing, the text of its
    /// pieces rounded up, and its gaps.
    fn projected(&self) -> u64 {
        let chunks = self.sink.chunks.len() as u64;
        self.overhead
            .saturating_add(CHUNK_FRAMING.saturating_mul(chunks))
            .saturating_add(self.sink.carried.saturating_mul(4).div_ceil(3))
            .saturating_add(self.gap_charge.saturating_mul(self.gaps.len() as u64))
    }

    /// How much the next page may ask for, so that the most it can add still fits every limit, or
    /// nothing when a limit leaves no room for a page worth asking for.
    fn next_page(&self) -> u64 {
        let by_read = self
            .bounds
            .max_read_bytes
            .min(MOST_READ)
            .saturating_sub(self.bytes_read)
            .min(MAX_HISTORY_PAGE_BYTES);
        let by_document = self
            .bounds
            .max_document_bytes
            .saturating_sub(self.projected())
            .saturating_sub(self.page_fixed)
            / MOST_A_BYTE_ADDS;
        // A page of `n` bytes adds at most `n / 2 + 2` pieces: two pieces are parted by at least
        // one byte the engine did not clear, and the engine can release one it held back from the
        // page before and one it begins at the page's end.
        let by_chunks = (self
            .bounds
            .max_chunks
            .saturating_sub(self.sink.chunks.len())
            .saturating_sub(2) as u64)
            .saturating_mul(2);
        let room = by_document.min(by_chunks);
        if room < by_read.min(LEAST_PAGE) {
            return 0;
        }
        by_read.min(room)
    }

    /// Reads every page of the session's retained output from its start, through the engine.
    async fn read<S: PageSource>(&mut self, source: &mut S) -> Result<(), Stop<S::Error>> {
        let mut run: Option<Run> = None;
        let mut cursor = 0_u64;
        let mut first = true;
        loop {
            let want = self.next_page();
            if want == 0 {
                // A limit is met. One more byte says whether anything was left behind.
                self.truncated = left_behind(source, cursor).await.map_err(Stop::Source)?;
                break;
            }
            let page = source.page(cursor, want).await.map_err(Stop::Source)?;
            if first {
                self.from_cursor = page.from_cursor.get();
                self.oldest_retained = page.oldest_retained_cursor.get();
                first = false;
            }
            if let Some(gap) = page.gap.0
                && !self.gaps.contains(&gap)
            {
                self.gaps.push(gap);
            }
            let from = page.from_cursor.get();
            let next = page.next_cursor.get();
            // Output that does not continue from where the last page ended: a range the archive no
            // longer holds came between. What follows it is not a continuation of what came before,
            // so a control string cut by the gap does not swallow the output after it, and what
            // follows begins somewhere in the stream that is not known, which is the start of the
            // first sequence the output is read from. A page that reports a gap it did not skip,
            // because the archive cannot say where its output got to, is a continuation.
            if from != cursor
                && let Some(ended) = run.take()
            {
                ended.finish(&mut self.sink);
            }
            let bytes = page.bytes.into_vec();
            self.bytes_read = self.bytes_read.saturating_add(bytes.len() as u64);
            if !bytes.is_empty() {
                let current = match run.as_mut() {
                    Some(current) => current,
                    None => run.insert(Run::start(
                        from,
                        self.size,
                        from != 0,
                        self.sink.fed.len(),
                        self.sink.chunks.len(),
                    )?),
                };
                current.feed(from, &bytes, &mut self.sink);
            }
            self.next_cursor = self.next_cursor.max(next);
            if next <= cursor && bytes.is_empty() {
                break;
            }
            cursor = next;
        }
        if let Some(ended) = run.take() {
            ended.finish(&mut self.sink);
        }
        Ok(())
    }

    /// Cuts the end off a read that passed a limit all the same, and writes the document.
    fn finish<E>(mut self) -> Result<Composed, Stop<E>> {
        let mut trimmed = false;
        if let Some(dropped) = self.sink.dropped_from {
            self.next_cursor = self.next_cursor.min(dropped);
            trimmed = true;
        }
        while (self.projected() > self.bounds.max_document_bytes
            || self.sink.chunks.len() > self.bounds.max_chunks)
            && let Some(dropped) = self.sink.chunks.pop()
        {
            self.sink.carried -= u64::from(dropped.len);
            self.next_cursor = self.next_cursor.min(dropped.cursor);
            trimmed = true;
        }
        self.truncated |= trimmed;
        self.sink.tally.bytes_carried = self.sink.carried;

        let declared = omissions(
            session_record_unavailable(self.session),
            self.gaps.len(),
            self.truncated,
            &self.sink.tally,
        );
        let output = OutputPart {
            from_cursor: U64::new(self.from_cursor),
            next_cursor: U64::new(self.next_cursor),
            oldest_retained_cursor: U64::new(self.oldest_retained),
            chunks: ChunksPart {
                chunks: &self.sink.chunks,
                fed: &self.sink.fed,
            },
            gaps: &self.gaps,
            truncated: self.truncated,
        };
        let capacity = usize::try_from(self.projected()).unwrap_or(0);
        let document = write_document(
            self.session,
            self.exported_at_ms,
            output,
            &declared,
            capacity,
        )
        .ok_or(Stop::Document)?;
        Ok(Composed {
            document,
            bytes_read: self.bytes_read,
            bytes_carried: self.sink.tally.bytes_carried,
            gaps: self.gaps.len(),
            truncated: self.truncated,
            omissions: declared.iter().map(|omission| omission.kind).collect(),
        })
    }
}

/// Whether the source holds output past `cursor`.
///
/// A page can hold no bytes and still move the cursor on, across a range the archive lost, so an
/// empty page is followed to the page after it and not taken for the end.
async fn left_behind<S: PageSource>(source: &mut S, mut cursor: u64) -> Result<bool, S::Error> {
    loop {
        let more = source.page(cursor, 1).await?;
        if !more.bytes.is_empty() {
            return Ok(true);
        }
        let next = more.next_cursor.get();
        if next <= cursor {
            return Ok(false);
        }
        cursor = next;
    }
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

/// One unbroken stretch of retained output, read by an engine of its own.
struct Run {
    /// Where the bytes the engine was fed begin in the session's output.
    start: u64,
    /// Where the first byte this run feeds goes among the bytes fed to all runs.
    base: usize,
    /// The first of the pieces this run makes, so a piece is never joined to another run's.
    first_chunk: usize,
    /// How many bytes the engine was fed.
    fed: u64,
    /// Set where the stretch begins somewhere in the stream that is not known, so that its first
    /// bytes may be the end of a sequence the output before it began: nothing is read until the
    /// point [`Skipping`] finds, and then this is clear.
    skipping: Option<Skipping>,
    engine: Engine,
}

impl Run {
    /// Starts a stretch at `start`, read by an engine whose screen is the session's last size.
    ///
    /// The clock does not change which bytes are cleared for a terminal, so it never moves.
    fn start<E>(
        start: u64,
        size: GridSize,
        resuming: bool,
        base: usize,
        first_chunk: usize,
    ) -> Result<Self, Stop<E>> {
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
        .map_err(|_| Stop::Engine)?;
        Ok(Self {
            start,
            base,
            first_chunk,
            fed: 0,
            skipping: resuming.then(Skipping::default),
            engine,
        })
    }

    /// Feeds the bytes of one page, which begin at `from` in the session's output.
    fn feed(&mut self, from: u64, bytes: &[u8], sink: &mut Sink) {
        let mut bytes = bytes;
        let mut from = from;
        if let Some(skipping) = &mut self.skipping {
            let Some(skipped) = skipping.point(bytes) else {
                // Nothing in this page is somewhere reading can begin, so the next page is asked
                // the same.
                sink.tally.bytes_resumed += bytes.len() as u64;
                self.start = from.saturating_add(bytes.len() as u64);
                return;
            };
            sink.tally.bytes_resumed += skipped as u64;
            bytes = &bytes[skipped..];
            from = from.saturating_add(skipped as u64);
            self.start = from;
            // Reading has begun, even where the point was the last byte of the page.
            self.skipping = None;
            if bytes.is_empty() {
                return;
            }
        }
        sink.fed.extend_from_slice(bytes);
        self.fed += bytes.len() as u64;
        let outcome = self.engine.feed(bytes, 0);
        self.take(&outcome, sink);
        self.discard_replies();
    }

    /// Throws away the replies the engine queued, which nothing is waiting for.
    fn discard_replies(&mut self) {
        let _ = self
            .engine
            .lane_mut()
            .drain(LaneGate::default(), usize::MAX, 0);
    }

    fn take(&mut self, outcome: &FeedOutcome, sink: &mut Sink) {
        sink.take(self, outcome);
        // A reply the lane refused for want of room is a question all the same, and the record of
        // those refusals is read once and cleared, so the next outcome has its own.
        let refused = self.engine.lane().degradation();
        sink.tally.replies += refused.dropped + refused.over_budget + refused.oversized;
        self.engine.lane_mut().clear_degradation();
    }

    /// Ends the stretch: what the engine held back is released, and what it cleared is cut out.
    fn finish(mut self, sink: &mut Sink) {
        let tail = self.engine.quiesce(0);
        self.take(&tail, sink);
        self.discard_replies();
        let closing = self.engine.close(0);
        self.take(&closing, sink);
        for (kind, count) in self.engine.diagnostic_totals() {
            *sink.tally.diagnostics.entry(kind).or_insert(0) += count;
        }
        sink.tally.bytes_fed += self.fed;
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

/// What the engines found in the output that the document does not carry.
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

    /// A tally in which every count is as long as a count can be, for the size the declarations of
    /// a document can come to at the most.
    fn greatest() -> Self {
        Self {
            bytes_fed: u64::MAX,
            bytes_carried: 0,
            bytes_resumed: u64::MAX,
            clipboard_writes: u64::MAX,
            notifications: u64::MAX,
            progress_reports: u64::MAX,
            bells: u64::MAX,
            refused_effects: u64::MAX,
            replies: u64::MAX,
            diagnostics: [
                DiagnosticKind::ImageSequenceDisabled,
                DiagnosticKind::PhysicalWindowRequest,
                DiagnosticKind::UnclassifiedSequence,
                DiagnosticKind::OversizedControlString,
                DiagnosticKind::AbandonedControlString,
                DiagnosticKind::MalformedUtf8,
            ]
            .into_iter()
            .map(|kind| (kind, u64::MAX / 2))
            .collect(),
        }
    }
}

/// One thing the document does not carry.
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
fn omissions(
    record_unavailable: bool,
    gaps: usize,
    truncated: bool,
    tally: &Tally,
) -> Vec<Omission> {
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
    if record_unavailable {
        declared.push(Omission::said(
            "session_record_unavailable",
            "the session's own record is gone, so its shell, directory, size, mode and creation \
             time are not known",
        ));
    }
    if gaps > 0 {
        declared.push(Omission {
            kind: "history_gap",
            detail: "ranges of output the archive no longer holds, each listed under gaps with \
                     its cause"
                .to_owned(),
            count: Some(gaps as u64),
        });
    }
    if truncated {
        declared.push(Omission::said(
            "output_truncated",
            "the read stopped at a bound, the bytes read or the size of the file, with output \
             left; the start of what the archive retains is kept and the rest is not",
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
                    .saturating_add(diagnosed(DiagnosticKind::AbandonedControlString)),
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

/// The document, as it is written. Every 64-bit value is a [`U64`], which the protocol writes as a
/// decimal string.
#[derive(Serialize)]
struct File<'a> {
    format: &'static str,
    exported_at_ms: U64,
    environment_id: EnvironmentId,
    session: SessionPart<'a>,
    closure: Option<&'a ClosureRecord>,
    dimensions: Option<DimensionsPart>,
    output: OutputPart<'a>,
    omissions: Vec<OmissionPart<'a>>,
}

/// What the document says of the session, each member null where the session's own record is gone.
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

/// The retained output the document carries.
#[derive(Serialize)]
struct OutputPart<'a> {
    from_cursor: U64,
    next_cursor: U64,
    oldest_retained_cursor: U64,
    #[serde(serialize_with = "write_chunks")]
    chunks: ChunksPart<'a>,
    gaps: &'a [HistoryGap],
    truncated: bool,
}

/// The pieces of output, written from the bytes fed without a copy of any of them.
struct ChunksPart<'a> {
    chunks: &'a [Chunk],
    fed: &'a [u8],
}

fn write_chunks<S: Serializer>(part: &ChunksPart<'_>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(part.chunks.iter().map(|chunk| ChunkPart {
        cursor: U64::new(chunk.cursor),
        base64url: chunk.bytes(part.fed),
    }))
}

/// One piece of output, and where in the session's output it begins.
#[derive(Serialize)]
struct ChunkPart<'a> {
    cursor: U64,
    #[serde(serialize_with = "write_base64url")]
    base64url: &'a [u8],
}

/// Writes bytes as unpadded base64url text as they are encoded, and not made into a string first.
fn write_base64url<S: Serializer>(bytes: &&[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&Base64Display::new(bytes, &URL_SAFE_NO_PAD))
}

/// One thing the document does not hold.
#[derive(Serialize)]
struct OmissionPart<'a> {
    kind: &'static str,
    detail: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<U64>,
}

/// Writes the document into a buffer made room for `capacity` bytes.
fn write_document(
    session: &SessionSummary,
    exported_at_ms: u64,
    output: OutputPart<'_>,
    declared: &[Omission],
    capacity: usize,
) -> Option<Vec<u8>> {
    let unknown = session_record_unavailable(session);
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
        output,
        omissions: declared
            .iter()
            .map(|omission| OmissionPart {
                kind: omission.kind,
                detail: &omission.detail,
                count: omission.count.map(U64::new),
            })
            .collect(),
    };
    let mut document = Vec::with_capacity(capacity);
    serde_json::to_writer(&mut document, &file).ok()?;
    document.push(b'\n');
    Some(document)
}

/// The size of the document with no piece of output and no gap, at the most: every cursor as long
/// as one can be and every count the longest, with every declaration a read can make.
fn skeleton(session: &SessionSummary, exported_at_ms: u64) -> Option<u64> {
    let declared = omissions(
        session_record_unavailable(session),
        1,
        true,
        &Tally::greatest(),
    );
    let output = OutputPart {
        from_cursor: U64::new(u64::MAX),
        next_cursor: U64::new(u64::MAX),
        oldest_retained_cursor: U64::new(u64::MAX),
        chunks: ChunksPart {
            chunks: &[],
            fed: &[],
        },
        gaps: &[],
        truncated: true,
    };
    write_document(session, exported_at_ms, output, &declared, 0)
        .map(|document| document.len() as u64)
}

/// What one gap is charged at: its listing at the most it can come to, and the comma after it.
///
/// A cause is named by at most 32 symbols; the longest today is 18.
fn gap_charge() -> u64 {
    let gap = HistoryGap {
        from_cursor: U64::new(u64::MAX),
        to_cursor: U64::new(u64::MAX),
        cause: None,
    };
    let cause = br#","cause":"""#.len() + 32;
    serde_json::to_vec(&gap).map_or(256, |listing| (listing.len() + cause + 1) as u64)
}
