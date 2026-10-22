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
//! # Two documents
//!
//! The semantic JSON document ([`Form::Json`]) carries each piece of output with its cursor and the
//! wall-clock reading of when its first byte was written. The asciicast recording
//! ([`Form::Asciicast`]) carries the same pieces as the events of an asciicast v2 file, each at the
//! time it was written, relative to the first piece that has one. Both come from one read through
//! the terminal engine, so both hold the same spans and neither can replay a side effect.
//!
//! # What the document says it does not hold
//!
//! The archive keeps the session's last size and not the sizes before it, and it can have lost a
//! range. A piece the host has no recorded time for carries none, and the document counts those
//! bytes. Each is declared under `omissions`, with the kinds of side effect the engine dropped and
//! the bytes it did not carry.
//!
//! # How it is bounded
//!
//! A hostile session can alternate one byte of text with one byte the engine drops, and a session
//! can write one byte at a time, so that every byte starts a piece of output of its own. The
//! composer therefore keeps a piece as a cursor and a range into the bytes it was fed (16 bytes),
//! never as a copy, keeps the times in a list beside them with one entry for each stretch of pieces
//! that share a time, and holds three limits as the pieces arrive and not after:
//!
//! * the bytes read, [`Bounds::max_read_bytes`];
//! * the pieces, [`Bounds::max_chunks`], so the list that holds them never grows past it;
//! * the size of the finished document, [`Bounds::max_document_bytes`]. Every piece is charged its
//!   framing and its text (its base64 text in the JSON form, and the length it comes to once it is
//!   escaped as a JSON string in the recording), the document buffer is reserved at the charge and
//!   written from the ranges, and a page is asked for only when the most it can add still fits,
//!   counting what the engine can hold back and let go in it.
//!
//! When a limit would be passed the read stops at a page boundary, keeps the start of the output
//! and drops the rest, and the document says `output_truncated`. The cursor the document ends at
//! is where the read stopped, or where the first piece that was cut off begins, so a reader that
//! continues from it misses none of the output the document leaves out.

use std::future::Future;

use base64::display::Base64Display;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::recovery::{
    HistoryGap, HistoryPageResult, HistoryTimesResult, MAX_HISTORY_PAGE_BYTES,
};
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

/// The format the semantic JSON document declares, so a reader knows what it has.
pub const FORMAT: &str = "kalareach-session-export/2";

/// The most pieces of output a document holds: 32 MiB of ranges, and as much again for the times
/// that go with them.
pub const MAX_CHUNKS: usize = 2_000_000;

/// What the framing of one piece of output is charged at in the semantic JSON document's projected
/// size.
///
/// The piece is `{"cursor":"…","at_ms":"…","base64url":"…"},`: 59 bytes of framing and the digits
/// of its cursor and its time, at most 20 each, and its text is rounded up to whole base64 symbols,
/// under one more symbol: 81 is over all of them.
const CHUNK_FRAMING: u64 = 81;

/// What the framing of one event is charged at in the recording's projected size.
///
/// The event is `[seconds,"o","…"]` and a line feed: 11 bytes of framing and the seconds, at most
/// 23 digits with the point, so 34, and 40 leaves room.
const EVENT_FRAMING: u64 = 40;

/// The most a byte read can add to the semantic JSON document's projected size: the output may be
/// timed one byte at a time, so that every byte is a piece of its own, and that comes to 83.
pub const MOST_A_BYTE_ADDS: u64 = 90;

/// The most a byte read can add to the recording's projected size: an event of one byte whose text
/// is escaped to six, and 60 leaves room.
const MOST_A_BYTE_ADDS_CAST: u64 = 60;

/// The most the reason a host gives for having no times is kept to, in characters.
const MOST_REASON: usize = 256;

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

    /// Reads when the output between two cursors was written.
    ///
    /// A source that has no record says so in the answer, with the reason, and the output it
    /// covers carries no time. A source that cannot answer at all fails, and the composition stops
    /// with it.
    ///
    /// # Errors
    ///
    /// Returns what stopped the read.
    fn times(
        &mut self,
        from_cursor: u64,
        to_cursor: u64,
    ) -> impl Future<Output = Result<HistoryTimesResult, Self::Error>>;
}

/// Which document a composition writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The semantic JSON document: [`FORMAT`].
    Json,
    /// An asciicast v2 recording.
    Asciicast,
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
    /// Which document to write.
    pub form: Form,
}

/// What a composition produced.
pub struct Composed {
    /// The document, ending in a line feed.
    pub document: Vec<u8>,
    /// How many bytes of retained output were read.
    pub bytes_read: u64,
    /// How many of those bytes the document carries.
    pub bytes_carried: u64,
    /// How many of the bytes carried have no recorded time.
    pub bytes_untimed: u64,
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
    /// A recording was asked for and none of the output carries a time, so there is nothing to
    /// play. The reason is the host's, when it gave one.
    Untimed(Option<String>),
}

impl<E> core::fmt::Debug for Stop<E> {
    /// Names what stopped it and nothing the source said, which may be a path or a person's text.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let why = match self {
            Self::Source(_) => "Source",
            Self::Engine => "Engine",
            Self::Document => "Document",
            Self::Untimed(_) => "Untimed",
        };
        formatter
            .debug_struct("Stop")
            .field("why", &why)
            .finish_non_exhaustive()
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

/// An interval of the session's output and the wall-clock reading of when its first byte was
/// written, as the host reported it.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    from: u64,
    to: u64,
    at_ms: u64,
    proven: bool,
}

/// The time a run of pieces shares: which interval they were written in, or none.
#[derive(Clone, Copy, Debug)]
struct ChunkTime {
    /// The first piece of the run.
    first_chunk: usize,
    /// The interval, as its place in the list of stamps.
    stamp: Option<usize>,
    at_ms: u64,
    proven: bool,
}

/// Where the engines' output goes as it is produced: the bytes fed, the pieces cut out of them and
/// the counts.
struct Sink {
    fed: Vec<u8>,
    chunks: Vec<Chunk>,
    /// The time of each run of pieces that share one, in order, so a piece's time is the entry
    /// whose first piece is the last one at or before it.
    times: Vec<ChunkTime>,
    /// The intervals the host reported times for, ascending and apart.
    stamps: Vec<Stamp>,
    /// The bytes the pieces hold.
    carried: u64,
    /// The bytes the pieces hold that have no recorded time.
    untimed: u64,
    /// What the pieces come to once their text is escaped as a JSON string, which is what the
    /// recording charges for their text.
    escaped: u64,
    max_chunks: usize,
    /// Where the first piece dropped for want of room begins, which a source that kept to the page
    /// size it was asked for never causes.
    dropped_from: Option<u64>,
    tally: Tally,
}

impl Sink {
    /// Takes the spans an engine cleared as pieces of the run `run`, joining a span to the piece
    /// before it where the two touch and share a time.
    fn take(&mut self, run: &Run, outcome: &FeedOutcome) {
        for span in &outcome.forward {
            self.push(run, *span);
        }
        self.tally.absorb(outcome);
    }

    /// Adds an interval the host reported, when it follows the ones held. The host's answer is
    /// ascending and apart; an interval that is not is left out, and its bytes carry no time.
    fn stamp(&mut self, stamp: Stamp) {
        let follows = self.stamps.last().is_none_or(|last| last.to <= stamp.from);
        if stamp.from < stamp.to && follows && self.stamps.len() < self.max_chunks {
            self.stamps.push(stamp);
        }
    }

    /// Returns how much of `len` bytes from `cursor` share a time, and the interval it is from.
    fn timed_part(&self, cursor: u64, len: u32) -> (u32, Option<usize>) {
        let at = self.stamps.partition_point(|stamp| stamp.to <= cursor);
        let (part, stamp) = match self.stamps.get(at) {
            Some(stamp) if stamp.from <= cursor => (stamp.to - cursor, Some(at)),
            Some(stamp) => (stamp.from - cursor, None),
            None => (u64::from(len), None),
        };
        (
            u32::try_from(part.min(u64::from(len))).unwrap_or(len),
            stamp,
        )
    }

    fn push(&mut self, run: &Run, span: ByteSpan) {
        let cursor = run.start.saturating_add(span.start());
        let placed = usize::try_from(span.start())
            .ok()
            .and_then(|start| run.base.checked_add(start))
            .and_then(|offset| u32::try_from(offset).ok())
            .zip(u32::try_from(span.len()).ok());
        let Some((mut offset, mut len)) = placed else {
            self.dropped_from.get_or_insert(cursor);
            return;
        };
        let mut cursor = cursor;
        while len > 0 {
            let (part, stamp) = self.timed_part(cursor, len);
            self.push_part(run, cursor, offset, part.max(1), stamp);
            cursor = cursor.saturating_add(u64::from(part.max(1)));
            offset = offset.saturating_add(part.max(1));
            len = len.saturating_sub(part.max(1));
        }
    }

    /// Adds one piece that shares one time.
    fn push_part(&mut self, run: &Run, cursor: u64, offset: u32, len: u32, stamp: Option<usize>) {
        let escaped = escaped_len(
            self.fed
                .get(offset as usize..offset as usize + len as usize)
                .unwrap_or_default(),
        );
        let same_time = self.times.last().is_some_and(|last| last.stamp == stamp);
        if same_time
            && let Some(last) = self
                .chunks
                .get_mut(run.first_chunk..)
                .and_then(<[Chunk]>::last_mut)
            && last.end() == offset
            && let Some(joined) = last.len.checked_add(len)
        {
            last.len = joined;
            self.carried += u64::from(len);
            self.escaped += escaped;
            if stamp.is_none() {
                self.untimed += u64::from(len);
            }
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
        if !same_time {
            let (at_ms, proven) = stamp.map_or((0, false), |at| {
                (self.stamps[at].at_ms, self.stamps[at].proven)
            });
            self.times.push(ChunkTime {
                first_chunk: self.chunks.len(),
                stamp,
                at_ms,
                proven,
            });
        }
        self.chunks.push(Chunk {
            cursor,
            offset,
            len,
        });
        self.carried += u64::from(len);
        self.escaped += escaped;
        if stamp.is_none() {
            self.untimed += u64::from(len);
        }
    }

    /// Takes the last piece away, with its time and its share of every count, and returns it.
    fn pop(&mut self) -> Option<Chunk> {
        let dropped = self.chunks.pop()?;
        self.carried -= u64::from(dropped.len);
        self.escaped -= escaped_len(dropped.bytes(&self.fed));
        if self
            .times
            .last()
            .is_some_and(|last| last.first_chunk >= self.chunks.len())
        {
            let last = self.times.pop();
            if last.is_some_and(|last| last.stamp.is_none()) {
                self.untimed -= u64::from(dropped.len);
            }
        } else if self.times.last().is_some_and(|last| last.stamp.is_none()) {
            self.untimed -= u64::from(dropped.len);
        }
        Some(dropped)
    }

    /// Returns how many of the bytes the pieces hold were timed on a clock the host could not prove.
    fn unproven(&self) -> u64 {
        let mut unproven = 0;
        for (at, time) in self.times.iter().enumerate() {
            if time.stamp.is_none() || time.proven {
                continue;
            }
            let end = self
                .times
                .get(at + 1)
                .map_or(self.chunks.len(), |next| next.first_chunk);
            unproven += self.chunks[time.first_chunk..end]
                .iter()
                .map(|chunk| u64::from(chunk.len))
                .sum::<u64>();
        }
        unproven
    }
}

/// Returns the time of the piece at `index`, or none for a piece with no recorded time.
fn time_of(times: &[ChunkTime], index: usize) -> Option<(u64, bool)> {
    let at = times.partition_point(|time| time.first_chunk <= index);
    times
        .get(at.checked_sub(1)?)
        .filter(|time| time.stamp.is_some())
        .map(|time| (time.at_ms, time.proven))
}

/// How long `bytes` come to once they are written as the text of a JSON string, at the most.
///
/// A control character is six bytes as `\u00XX`, a quote and a backslash two, and anything else is
/// itself. Bytes that are not text are written by the recording as nothing, which is less.
fn escaped_len(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .map(|&byte| match byte {
            b'"' | b'\\' | 0x08 | 0x09 | 0x0a | 0x0c | 0x0d => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
        .sum()
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
    /// Why the host has no times for the output, when it said so.
    no_times: Option<String>,
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
        let overhead = skeleton(session, exported_at_ms, bounds.form).ok_or(Stop::Document)?;
        if overhead > bounds.max_document_bytes {
            return Err(Stop::Document);
        }
        let gap_charge = gap_charge();
        let (framing, held_back) = match bounds.form {
            Form::Json => (CHUNK_FRAMING, HELD_BACK.div_ceil(3).saturating_mul(4)),
            Form::Asciicast => (EVENT_FRAMING, HELD_BACK.saturating_mul(6)),
        };
        Ok(Self {
            session,
            size: grid_size(session),
            bounds,
            exported_at_ms,
            sink: Sink {
                fed: Vec::with_capacity(usize::try_from(reserve).unwrap_or(0)),
                chunks: Vec::new(),
                times: Vec::new(),
                stamps: Vec::new(),
                carried: 0,
                untimed: 0,
                escaped: 0,
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
            no_times: None,
            overhead,
            gap_charge,
            page_fixed: framing
                .saturating_mul(2)
                .saturating_add(gap_charge)
                .saturating_add(held_back)
                .saturating_add(1),
        })
    }

    /// What the document comes to if it were written now, at the most: its framing, the text of its
    /// pieces (rounded up as base64, or as escaped), and its gaps.
    fn projected(&self) -> u64 {
        let chunks = self.sink.chunks.len() as u64;
        let pieces = match self.bounds.form {
            Form::Json => CHUNK_FRAMING
                .saturating_mul(chunks)
                .saturating_add(self.sink.carried.saturating_mul(4).div_ceil(3)),
            Form::Asciicast => EVENT_FRAMING
                .saturating_mul(chunks)
                .saturating_add(self.sink.escaped),
        };
        self.overhead
            .saturating_add(pieces)
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
        let most_a_byte_adds = match self.bounds.form {
            Form::Json => MOST_A_BYTE_ADDS,
            Form::Asciicast => MOST_A_BYTE_ADDS_CAST,
        };
        let by_document = self
            .bounds
            .max_document_bytes
            .saturating_sub(self.projected())
            .saturating_sub(self.page_fixed)
            / most_a_byte_adds;
        // A page of `n` bytes adds at most `n + 2` pieces: a host that wrote it one byte at a time
        // timed every byte apart, and the engine can release one piece it held back from the page
        // before and one it begins at the page's end.
        let by_chunks = self
            .bounds
            .max_chunks
            .saturating_sub(self.sink.chunks.len())
            .saturating_sub(2) as u64;
        let room = by_document.min(by_chunks);
        if room < by_read.min(LEAST_PAGE) {
            return 0;
        }
        by_read.min(room)
    }

    /// Asks the source when the output of a page was written, before the page is fed to the engine.
    ///
    /// A source with no record says why, once, and the output of every page after it carries no
    /// time.
    async fn timed<S: PageSource>(
        &mut self,
        source: &mut S,
        from: u64,
        to: u64,
    ) -> Result<(), Stop<S::Error>> {
        let mut at = from;
        while self.no_times.is_none() && at < to {
            let answer = source.times(at, to).await.map_err(Stop::Source)?;
            if let Some(why) = answer.unavailable.0 {
                self.no_times = Some(why.chars().take(MOST_REASON).collect());
                return Ok(());
            }
            for interval in answer.intervals {
                self.sink.stamp(Stamp {
                    from: interval.from_cursor.get(),
                    to: interval.to_cursor.get(),
                    at_ms: interval.at_ms.get(),
                    proven: interval.proven,
                });
            }
            let next = answer.next_cursor.get();
            if answer.complete || next <= at {
                break;
            }
            at = next;
        }
        Ok(())
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
                // Before the engine reads the page, so every piece it clears is cut at the end of
                // the interval it was written in.
                self.timed(source, from, next).await?;
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
            && let Some(dropped) = self.sink.pop()
        {
            self.next_cursor = self.next_cursor.min(dropped.cursor);
            trimmed = true;
        }
        self.truncated |= trimmed;
        self.sink.tally.bytes_carried = self.sink.carried;
        let declared_untimed = self.sink.untimed;
        match self.bounds.form {
            Form::Json => self.write_json(declared_untimed),
            Form::Asciicast => self.write_cast(declared_untimed),
        }
    }

    /// The omissions to declare, once the bytes that carry no time are known.
    fn declared(&self, untimed: u64) -> Vec<Omission> {
        omissions(
            session_record_unavailable(self.session),
            self.gaps.len(),
            self.truncated,
            &self.sink.tally,
            Times {
                untimed,
                unproven: self.sink.unproven(),
                reason: self.no_times.as_deref(),
            },
        )
    }

    fn write_json<E>(self, untimed: u64) -> Result<Composed, Stop<E>> {
        let declared = self.declared(untimed);
        let output = OutputPart {
            from_cursor: U64::new(self.from_cursor),
            next_cursor: U64::new(self.next_cursor),
            oldest_retained_cursor: U64::new(self.oldest_retained),
            chunks: ChunksPart {
                chunks: &self.sink.chunks,
                fed: &self.sink.fed,
                times: &self.sink.times,
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
            bytes_untimed: untimed,
            gaps: self.gaps.len(),
            truncated: self.truncated,
            omissions: declared.iter().map(|omission| omission.kind).collect(),
        })
    }

    fn write_cast<E>(mut self, untimed: u64) -> Result<Composed, Stop<E>> {
        if untimed >= self.sink.carried {
            return Err(Stop::Untimed(self.no_times.take()));
        }
        // What the recording writes as text is text: a piece cut in the middle of a character
        // carries its start into the piece that follows it, and bytes that are not text are not
        // written. They are counted with the bytes not carried.
        let mut dropped = 0;
        cast_events(&self.sink, |_, _| {}, &mut dropped);
        self.sink.tally.bytes_carried = self.sink.carried.saturating_sub(dropped);
        let declared = self.declared(untimed);
        let capacity = usize::try_from(self.projected()).unwrap_or(0);
        let document = write_cast(
            self.session,
            self.exported_at_ms,
            &self.sink,
            &declared,
            capacity,
        )
        .ok_or(Stop::Document)?;
        Ok(Composed {
            document,
            bytes_read: self.bytes_read,
            bytes_carried: self.sink.tally.bytes_carried,
            bytes_untimed: untimed,
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
    times: Times<'_>,
) -> Vec<Omission> {
    let mut declared = Vec::new();
    if times.untimed > 0 {
        declared.push(Omission {
            kind: "output_timestamps",
            detail: match times.reason {
                Some(reason) => format!(
                    "bytes of output that carry no time, because the host has no record of when \
                     they were written: {reason}"
                ),
                None => "bytes of output that carry no time, because the host recorded none for \
                         the stretch they were written in"
                    .to_owned(),
            },
            count: Some(times.untimed),
        });
    }
    if times.unproven > 0 {
        declared.push(Omission {
            kind: "output_clock_unproven",
            detail: "bytes of output whose time was read from a wall clock the host could not \
                     prove when they were written, so their times may be wrong"
                .to_owned(),
            count: Some(times.unproven),
        });
    }
    declared.extend([
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
    ]);
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
    times: &'a [ChunkTime],
}

fn write_chunks<S: Serializer>(part: &ChunksPart<'_>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(
        part.chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| ChunkPart {
                cursor: U64::new(chunk.cursor),
                at_ms: time_of(part.times, index).map(|(at_ms, _)| U64::new(at_ms)),
                base64url: chunk.bytes(part.fed),
            }),
    )
}

/// One piece of output, where in the session's output it begins, and when its first byte was
/// written, or null where the host recorded no time for it.
#[derive(Serialize)]
struct ChunkPart<'a> {
    cursor: U64,
    at_ms: Option<U64>,
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
fn skeleton(session: &SessionSummary, exported_at_ms: u64, form: Form) -> Option<u64> {
    let reason = "x".repeat(MOST_REASON);
    let declared = omissions(
        session_record_unavailable(session),
        1,
        true,
        &Tally::greatest(),
        Times {
            untimed: u64::MAX,
            unproven: u64::MAX,
            reason: Some(&reason),
        },
    );
    match form {
        Form::Json => {
            let output = OutputPart {
                from_cursor: U64::new(u64::MAX),
                next_cursor: U64::new(u64::MAX),
                oldest_retained_cursor: U64::new(u64::MAX),
                chunks: ChunksPart {
                    chunks: &[],
                    fed: &[],
                    times: &[],
                },
                gaps: &[],
                truncated: true,
            };
            write_document(session, exported_at_ms, output, &declared, 0)
                .map(|document| document.len() as u64)
        }
        Form::Asciicast => {
            let empty = Sink {
                fed: Vec::new(),
                chunks: Vec::new(),
                times: Vec::new(),
                stamps: Vec::new(),
                carried: 0,
                untimed: 0,
                escaped: 0,
                max_chunks: 0,
                dropped_from: None,
                tally: Tally::default(),
            };
            write_cast(session, exported_at_ms, &empty, &declared, 0)
                .map(|document| document.len() as u64)
        }
    }
}

/// What the document says of when its output was written.
#[derive(Clone, Copy)]
struct Times<'a> {
    /// The bytes with no recorded time.
    untimed: u64,
    /// The bytes timed on a clock the host could not prove.
    unproven: u64,
    /// Why the host has none, when it said so.
    reason: Option<&'a str>,
}

/// The recording's format, named in its header beside the version asciicast gives.
pub const RECORDING_FORMAT: &str = "kalareach-session-recording/1";

/// Walks the pieces as the text of the events of a recording, and calls `event` with each text and
/// the time of the piece it came from.
///
/// A recording's events are text. A piece cut in the middle of a character carries its start into
/// the piece that follows it when the two are adjacent in the session's output, and bytes that are
/// not text are not written; `dropped` counts them.
fn cast_events(sink: &Sink, mut event: impl FnMut(Option<u64>, &str), dropped: &mut u64) {
    let mut carry: Vec<u8> = Vec::new();
    let mut carry_ends = 0_u64;
    for (index, chunk) in sink.chunks.iter().enumerate() {
        let time = time_of(&sink.times, index).map(|(at_ms, _)| at_ms);
        let mut bytes = std::mem::take(&mut carry);
        if !bytes.is_empty() && chunk.cursor != carry_ends {
            *dropped += bytes.len() as u64;
            bytes.clear();
        }
        bytes.extend_from_slice(chunk.bytes(&sink.fed));
        let ends = chunk.cursor.saturating_add(u64::from(chunk.len));
        let mut from = 0;
        loop {
            match core::str::from_utf8(&bytes[from..]) {
                Ok(text) => {
                    if !text.is_empty() {
                        event(time, text);
                    }
                    break;
                }
                Err(error) => {
                    let valid = from + error.valid_up_to();
                    if valid > from
                        && let Ok(text) = core::str::from_utf8(&bytes[from..valid])
                    {
                        event(time, text);
                    }
                    match error.error_len() {
                        Some(bad) => {
                            *dropped += bad as u64;
                            from = valid + bad;
                        }
                        None => {
                            carry = bytes[valid..].to_vec();
                            carry_ends = ends;
                            break;
                        }
                    }
                }
            }
        }
    }
    *dropped += carry.len() as u64;
}

/// Writes the recording into a buffer made room for `capacity` bytes: the header line, then one
/// event for each piece of text.
///
/// The header is asciicast v2's, with the session's last size, the time the first timed piece was
/// written as whole seconds, and what the recording does not hold under `kalareach`. An event's
/// time is the number of seconds since that piece, and never earlier than the event before it: a
/// wall clock that stepped back is not played backwards, and a piece with no recorded time plays
/// with the one before it.
fn write_cast(
    session: &SessionSummary,
    exported_at_ms: u64,
    sink: &Sink,
    declared: &[Omission],
    capacity: usize,
) -> Option<Vec<u8>> {
    use std::io::Write as _;

    let size = grid_size(session);
    let base = sink
        .times
        .iter()
        .find_map(|time| time.stamp.map(|_| time.at_ms))
        .unwrap_or(0);
    let unknown = session_record_unavailable(session);
    let header = serde_json::json!({
        "version": 2,
        "width": size.cols,
        "height": size.rows,
        "timestamp": base / 1000,
        "title": if unknown {
            format!("kalareach session {}", session.display_number.get())
        } else {
            format!("kalareach session {}: {}", session.display_number.get(), session.shell_path)
        },
        "env": { "TERM": "xterm-256color" },
        "kalareach": {
            "format": RECORDING_FORMAT,
            "session_id": session.session_id,
            "exported_at_ms": U64::new(exported_at_ms),
            "closure": session.closure.as_ref(),
            "omissions": declared
                .iter()
                .map(|omission| serde_json::json!({
                    "kind": omission.kind,
                    "detail": omission.detail,
                    "count": omission.count,
                }))
                .collect::<Vec<_>>(),
        },
    });
    let mut document = Vec::with_capacity(capacity);
    serde_json::to_writer(&mut document, &header).ok()?;
    document.push(b'\n');
    let mut played = 0_u64;
    let mut ignored = 0;
    let mut failed = false;
    cast_events(
        sink,
        |time, text| {
            let at = time
                .map_or(played, |at_ms| at_ms.saturating_sub(base))
                .max(played);
            played = at;
            failed |= write!(document, "[{}.{:06},\"o\",", at / 1000, (at % 1000) * 1000).is_err()
                || serde_json::to_writer(&mut document, text).is_err()
                || document.write_all(b"]\n").is_err();
        },
        &mut ignored,
    );
    (!failed).then_some(document)
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
