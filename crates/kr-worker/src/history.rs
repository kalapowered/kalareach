//! Retained terminal output: a resident window and an indexed spool behind it.
//!
//! Output is a byte stream with one monotonically increasing cursor. A client subscribes from a
//! cursor and the worker serves everything after it, so a reconnecting attachment can ask for
//! exactly what it missed.
//!
//! What the worker cannot do is keep everything. Section 8 puts a resident cache of 8 MiB per
//! session on the in-memory side, and section 24 makes the rest a bounded indexed spool. So there
//! are two layers: a ring in memory, and fixed-size segment files on disk named by the cursor they
//! start at. When the spool passes its own bound the oldest segments are deleted, and the range
//! they held becomes a **gap**.
//!
//! A gap is reported, never smoothed over. A page that cannot start where the caller asked says
//! so and names the range it lost; a client that receives one discards its partial state and
//! installs a fresh snapshot. Returning a shorter page as though it were complete would leave the
//! client's screen silently wrong.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use kr_protocol::recovery::{
    HistoryGap, HistoryGapCause, HistoryPageResult, MAX_HISTORY_PAGE_BYTES,
};
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64};

use crate::persistence::retention::{Eviction, OutputRetention, Pressure, RetentionLimit};

use crate::error::{Result, WorkerError};

/// The resident history cache of one session, in bytes.
pub const DEFAULT_RESIDENT_BYTES: usize = 8 * 1024 * 1024;

/// One interval of the resident window, and when its output arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResidentMark {
    /// The cursor this interval starts at.
    cursor: u64,
    /// When the interval began, which is what bounds how long it may go on for.
    started_at_ms: u64,
    /// When the newest byte in it arrived, which is what expiry reads.
    last_at_ms: u64,
}

/// What discarding a session's retained output took, and what it could not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Discarded {
    /// Bytes of retained output that went.
    pub bytes: u64,
    /// Spool segments that went.
    pub segments: u64,
    /// Why some of it is still there, when some of it is.
    pub left_behind: Option<String>,
}

/// How coarse the resident window's own record of when its output arrived is.
///
/// One mark per minute bounds the record at a few entries for a window of any size, and bounds
/// how much output past the retention period the window can still be serving to one minute of it.
pub const RESIDENT_MARK_MS: u64 = 60 * 1000;

/// How long one spool segment accepts output before the next one starts.
///
/// It bounds how far a segment's oldest byte can be behind its newest, which is what stops a
/// session that produces a line an hour from holding a week of output in a segment retention
/// would never collect.
pub const SEGMENT_ROTATION_MS: u64 = 60 * 60 * 1000;

/// How many evictions a session remembers the reason for.
///
/// A reader is told which bound took the range it asked for, and the answer is only useful while
/// anything before it is still retained. A small number is enough, and it keeps the record from
/// growing on a host that evicts often.
pub const MAX_RECORDED_EVICTIONS: usize = 32;

/// How a session's spool is laid out on disk.
///
/// Eviction works in whole segments, so the segment size decides how coarse the retained boundary
/// is: a smaller segment loses less history when the bound is reached, and a larger one keeps the
/// directory small. How many segments a session has is bounded by the capacity for a session
/// producing output steadily, and by [`SEGMENT_ROTATION_MS`] and the retention period for one
/// producing a little at a time: an hour's rotation over seven days is at most 168 mostly empty
/// segments before age collection takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolLayout {
    /// Bytes one segment holds before the next one starts.
    pub segment_bytes: u64,
    /// The bound on the whole spool.
    pub capacity_bytes: u64,
}

impl SpoolLayout {
    /// The layout a session uses unless it is configured otherwise.
    ///
    /// The capacity is section 20's per-session cap, so the bound holds between maintenance
    /// passes as well as at them: a session that produced a gigabyte in a minute would otherwise
    /// keep every byte of it until the next tick. The host-wide bound cannot be kept this way,
    /// because one worker cannot see another's spool; it is applied on the maintenance tick and
    /// what that leaves is recorded in this task's handoff.
    pub const DEFAULT: Self = Self {
        segment_bytes: 8 * 1024 * 1024,
        capacity_bytes: crate::persistence::retention::SESSION_CAP_BYTES,
    };

    /// Builds a layout, keeping the segment size within the capacity.
    #[must_use]
    pub const fn new(segment_bytes: u64, capacity_bytes: u64) -> Self {
        Self {
            segment_bytes: if segment_bytes == 0 { 1 } else { segment_bytes },
            capacity_bytes,
        }
    }
}

/// Retained output for one session.
#[derive(Debug)]
pub struct OutputHistory {
    resident: VecDeque<u8>,
    resident_capacity: usize,
    resident_start: u64,
    next_cursor: u64,
    spool: Option<Spool>,
    /// The resident window's own record of when its output arrived, oldest first.
    ///
    /// The window is what a session serves when its spool has nothing left, so section 20's seven
    /// days has to reach it as well, and bytes carry no timestamps. Each entry is one interval:
    /// the cursor it starts at, the instant it started and the instant of its *newest* byte. Every
    /// byte in it was written at or before that newest instant, and reading the newest rather
    /// than the oldest is what makes the answer safe: a range is removed only when this host can
    /// say every byte in it had expired.
    ///
    /// A new interval starts once [`RESIDENT_MARK_MS`] has passed *since the interval began*,
    /// not since its last byte. Measuring from the last byte would let one byte a minute extend
    /// one interval for a week, and the whole of it would then be held by the newest byte in it.
    resident_marks: VecDeque<ResidentMark>,
    /// Whether output is being retained at all.
    ///
    /// Privacy mode disables content-history retention prospectively, which is this: what arrives
    /// while it is false reaches the live parser and the attachments and is not kept.
    retaining: bool,
    /// Whether this session was given a spool and then lost it.
    ///
    /// A write failure narrows the retained range to the resident window, and that is a different
    /// answer from a bound being reached: it is reported as one rather than as retention.
    spool_lost: bool,
    /// Where a spool this session lost kept what it had already written.
    ///
    /// The spool is dropped on a write failure so nothing more is appended to a store that is
    /// failing. What it wrote before that is still on the disk, and is still content this session
    /// can be asked to remove: a privacy purge that answered "nothing to remove" because the
    /// handle had gone would be reporting a removal it never made. Keeping the directory is what
    /// lets the purge reach those files.
    lost_spool_directory: Option<PathBuf>,
    /// What retention took, newest last.
    ///
    /// A gap is reported by the cursors a page carries, and those say what is gone. This says
    /// which bound took it, which is what section 20 asks eviction to leave explicit: a person
    /// looking at a gap can tell their own session's size from a busy host.
    evictions: VecDeque<Eviction>,
}

impl OutputHistory {
    /// Builds a history with a resident window and no spool.
    ///
    /// Without a spool the retained range is the resident window, and anything older is a gap.
    #[must_use]
    pub fn in_memory(resident_capacity: usize) -> Self {
        Self {
            resident: VecDeque::new(),
            resident_capacity,
            resident_start: 0,
            next_cursor: 0,
            spool: None,
            retaining: true,
            spool_lost: false,
            lost_spool_directory: None,
            resident_marks: VecDeque::new(),
            evictions: VecDeque::new(),
        }
    }

    /// Opens an existing spool for reading, without creating or repairing anything.
    ///
    /// The archive reads a session's retained output after the session is gone, and a read is a
    /// read: it does not create the directory it was asked about, and it does not narrow the
    /// permissions of one that is already there. Repair belongs to the host that owns the
    /// session, under recovery ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read.
    pub fn read_spool(directory: impl Into<PathBuf>, layout: SpoolLayout) -> Result<Self> {
        let mut history = Self::in_memory(0);
        let spool = Spool::read_existing(directory.into(), layout)?;
        history.next_cursor = spool.next_cursor();
        history.resident_start = history.next_cursor;
        history.spool = Some(spool);
        Ok(history)
    }

    /// Builds a history backed by a spool directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool directory cannot be created.
    pub fn with_spool(
        resident_capacity: usize,
        directory: impl Into<PathBuf>,
        layout: SpoolLayout,
    ) -> Result<Self> {
        let mut history = Self::in_memory(resident_capacity);
        let spool = Spool::open(directory.into(), layout)?;
        // The cursor continues from what is already retained; it does not restart at zero and
        // rewrite history a client may already have read.
        history.next_cursor = spool.next_cursor();
        history.resident_start = history.next_cursor;
        history.spool = Some(spool);
        Ok(history)
    }

    /// Returns the cursor after the last byte written.
    #[must_use]
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    /// Returns the oldest cursor that can still be served.
    ///
    /// The two layers are both readable, so it is the older of them: a spool whose every segment
    /// has been evicted still leaves the resident window, and a restarted session whose resident
    /// window is empty still leaves whatever the spool holds. A session that has just restarted
    /// over a spool with nothing left starts its cursor at the boundary the spool wrote down
    /// rather than at nought, so the range that went is a gap rather than output that never
    /// existed.
    #[must_use]
    pub fn oldest_retained_cursor(&self) -> u64 {
        match &self.spool {
            Some(spool) => spool.oldest_cursor().map_or(self.resident_start, |oldest| {
                oldest.min(self.resident_start)
            }),
            None => self.resident_start,
        }
    }

    /// Appends output and returns the cursor those bytes start at.
    ///
    /// Appending never fails on a full spool: a write failure disables the spool and narrows the
    /// retained range to the resident window, which is reported as a gap rather than as success.
    pub fn append(&mut self, bytes: &[u8]) -> u64 {
        let start = self.next_cursor;
        if bytes.is_empty() {
            return start;
        }
        if !self.retaining {
            // Privacy mode has disabled retention. The cursor still advances, because it is the
            // session's own position and a client that asked for what it missed is told the range
            // is gone rather than served later output under an earlier cursor.
            self.next_cursor += bytes.len() as u64;
            self.resident_start = self.next_cursor;
            return start;
        }
        if let Some(spool) = self.spool.as_mut()
            && spool.append(start, bytes).is_err()
        {
            // Losing the spool costs history, not correctness: the resident window still serves
            // recent output and everything older reads as an explicit gap. Where it wrote is kept,
            // because those files are still there and are still this session's to remove.
            self.lost_spool_directory = self.spool.as_ref().map(|spool| spool.directory.clone());
            self.spool = None;
            self.spool_lost = true;
        }
        self.resident.extend(bytes.iter().copied());
        self.next_cursor += bytes.len() as u64;
        let now_ms = kr_ipc::now_ms().get();
        match self.resident_marks.back_mut() {
            // Still inside the current interval, measured from when the interval began.
            Some(mark) if now_ms.saturating_sub(mark.started_at_ms) < RESIDENT_MARK_MS => {
                mark.last_at_ms = now_ms;
            }
            _ => self.resident_marks.push_back(ResidentMark {
                cursor: start,
                started_at_ms: now_ms,
                last_at_ms: now_ms,
            }),
        }
        while self.resident.len() > self.resident_capacity {
            let excess = self.resident.len() - self.resident_capacity;
            self.resident.drain(..excess);
            self.resident_start += excess as u64;
        }
        self.trim_marks();
        start
    }

    /// Drops the marks for output the resident window no longer holds.
    ///
    /// An interval the window has moved into keeps its instant and starts where the window now
    /// starts, because what it says about the bytes still in it has not changed.
    fn trim_marks(&mut self) {
        while self
            .resident_marks
            .get(1)
            .is_some_and(|mark| mark.cursor <= self.resident_start)
        {
            self.resident_marks.pop_front();
        }
        if let Some(mark) = self.resident_marks.front_mut()
            && mark.cursor < self.resident_start
        {
            mark.cursor = self.resident_start;
        }
    }

    /// Returns how many bytes of output this session retains.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.next_cursor
            .saturating_sub(self.oldest_retained_cursor())
    }

    /// Returns when the oldest retained output was last written.
    ///
    /// The spool's oldest segment when it has one, and otherwise the resident window's own
    /// oldest mark: a session serving from memory alone still has an age.
    #[must_use]
    pub fn oldest_written_at_ms(&self) -> Option<TimestampMs> {
        self.spool
            .as_ref()
            .and_then(Spool::oldest_written_at_ms)
            .or_else(|| self.resident_marks.front().map(|mark| mark.last_at_ms))
            .map(TimestampMs::new)
    }

    /// Stops retaining output.
    ///
    /// What is already held stays until [`Self::discard_retained`] takes it; what arrives after
    /// this is not retained at all. Privacy mode fences before it removes, so the two are
    /// separate: a capture still running while the removal walked the spool would write behind
    /// the cleanup.
    pub fn stop_retaining(&mut self) {
        self.retaining = false;
    }

    /// Starts retaining output again, from this moment.
    ///
    /// Nothing before it is reconstructed.
    pub fn resume_retaining(&mut self) {
        self.retaining = true;
    }

    /// Returns whether output is being retained.
    #[must_use]
    pub const fn is_retaining(&self) -> bool {
        self.retaining
    }

    /// Removes every byte of retained output, and returns what went.
    ///
    /// The bytes are the resident window and the spool together; the records are the spool
    /// segments that were deleted. The boundary is published first, as every other eviction
    /// publishes it, so a session reopened over the emptied directory still says where its output
    /// had reached rather than starting again at nought.
    ///
    /// This is logical cleanup. The files are unlinked and the window is dropped; nothing here
    /// claims the bytes are unrecoverable from the device they were on.
    pub fn discard_retained(&mut self) -> Discarded {
        let resident = self.resident.len() as u64;
        self.resident.clear();
        self.resident_marks.clear();
        self.resident_start = self.next_cursor;
        let mut discarded = Discarded {
            bytes: resident,
            segments: 0,
            left_behind: None,
        };
        let Some(spool) = self.spool.as_mut() else {
            // A spool this session lost still has files where it left them, and they are what a
            // purge is owed. Answering "nothing to remove" over them would call the removal
            // complete over output the archive can still be served.
            if let Some(directory) = self.lost_spool_directory.clone() {
                let (bytes, segments, left_behind) =
                    remove_spool_files(&directory, self.next_cursor);
                discarded.bytes += bytes;
                discarded.segments += segments;
                discarded.left_behind = left_behind;
                if discarded.left_behind.is_none() {
                    self.lost_spool_directory = None;
                }
            }
            return discarded;
        };
        if !spool.record_boundary() {
            discarded.left_behind = Some(
                "this session's spool boundary could not be written, so its retained output \
                      was left where it was"
                    .to_owned(),
            );
            return discarded;
        }
        while !spool.segments.is_empty() {
            let went = spool.drop_oldest();
            if went == 0 {
                // A segment this host could not unlink is content it was asked to remove and has
                // not. It stays in the accounting and the failure is reported rather than the
                // removal being called complete over a file a reader can still be served.
                discarded.left_behind = Some(format!(
                    "{} of this session's spool segments could not be removed",
                    spool.segments.len()
                ));
                break;
            }
            discarded.bytes += went;
            discarded.segments += 1;
        }
        discarded
    }

    /// Returns whether this session recorded where its output got to and cannot read it back.
    ///
    /// A host in that condition does not know what it is missing, which is a different answer
    /// from knowing that it is missing nothing.
    #[must_use]
    pub fn boundary_unreadable(&self) -> bool {
        self.spool
            .as_ref()
            .is_some_and(|spool| spool.unreadable_boundary)
    }

    /// Returns what retention has taken from this session, oldest first.
    #[must_use]
    pub fn evictions(&self) -> Vec<Eviction> {
        self.evictions.iter().copied().collect()
    }

    /// Applies section 20's retention, and returns what it took.
    ///
    /// `host_bytes` is what every session on this host retains, including this one. The host cap
    /// is not divided between sessions, so a session well inside its own 128 MiB is still evicted
    /// when the host is over 1 GiB: the caps are simultaneous upper bounds, not reserved
    /// capacity. Each pass records the bound that forced it, and a reader asking for a cursor
    /// inside the range is told which one.
    ///
    /// `age_permitted` is the host time contract's answer. Removing output because it is old is
    /// expiry-based collection, and section 9 stops that while the wall clock cannot be proved:
    /// collecting against an unproved clock is how a rollback deletes something that had not
    /// expired. The caps do not depend on a clock and are applied either way.
    pub fn apply_retention(
        &mut self,
        retention: OutputRetention,
        host_bytes: u64,
        now_ms: TimestampMs,
        age_permitted: bool,
    ) -> Vec<Eviction> {
        let mut taken = Vec::new();
        let expires_before = retention.expires_before(now_ms).get();
        let mut files_removed = 0;

        // The age bound first, which is the order section 20 states the three in.
        if age_permitted {
            let (eviction, file_bytes) = self.evict_expired(expires_before, now_ms);
            files_removed += file_bytes;
            if let Some(eviction) = eviction {
                taken.push(eviction);
            }
        }

        // Then the two caps, which hold at once. Whichever asks for more bytes decides how many
        // go; which one applies decides what the reader is told. The host figure is what the age
        // pass left of it, and only the bytes that left the filesystem count against a figure
        // measured from files.
        let session_bytes = self.retained_bytes();
        let pressure = Pressure {
            session_bytes,
            host_bytes: host_bytes.saturating_sub(files_removed).max(session_bytes),
            oldest_at_ms: self.oldest_written_at_ms(),
        };
        let over = retention.bytes_over_cap(&pressure);
        if over > 0
            && let Some(spool) = self.spool.as_mut()
        {
            // The cause is chosen from the caps alone. The age bound is not what is running here,
            // and a host whose clock cannot be proved would otherwise report a range as expired
            // when what took it was a byte cap.
            let limit = if retention.applies(RetentionLimit::HostCap, &pressure, now_ms) {
                RetentionLimit::HostCap
            } else {
                RetentionLimit::SessionCap
            };
            let start = spool.oldest_cursor().unwrap_or(self.resident_start);
            let dropped = spool.drop_at_least(over);
            if dropped > 0 {
                let after = spool.oldest_cursor().unwrap_or(self.resident_start);
                taken.push(Eviction {
                    limit,
                    from_cursor: start,
                    to_cursor: after,
                    bytes: dropped,
                    at_ms: now_ms,
                });
            }
        }

        for eviction in &taken {
            self.evictions.push_back(*eviction);
            while self.evictions.len() > MAX_RECORDED_EVICTIONS {
                self.evictions.pop_front();
            }
        }
        taken
    }

    /// Removes every byte this host can prove was produced before `expires_before`.
    ///
    /// Both layers, because the resident window is what a session serves when its spool has
    /// nothing left, and output past the retention period is not something a host may keep
    /// serving because it happens to be the newest it has.
    ///
    /// It is conservative in both. A spool segment goes only when its *newest* byte is past the
    /// deadline, and the window advances only to a mark whose own instant is past it, so every
    /// byte removed is one this host can say was expired. What that leaves is output that is
    /// expired and still retained, bounded by [`SEGMENT_ROTATION_MS`] for the spool and
    /// [`RESIDENT_MARK_MS`] for the window; the bound is an approximation of section 20's seven
    /// days from the safe side rather than an exact line.
    ///
    /// Returns the eviction and, separately, how many bytes left the filesystem. The two differ:
    /// output evicted from both layers is one range and two counts, and only the spool's bytes
    /// were ever part of a host-wide measurement taken from files.
    fn evict_expired(
        &mut self,
        expires_before: u64,
        now_ms: TimestampMs,
    ) -> (Option<Eviction>, u64) {
        let before = self.oldest_retained_cursor();
        let mut file_bytes = 0;
        if let Some(spool) = self.spool.as_mut() {
            file_bytes += spool.drop_older_than(expires_before);
        }
        // The window's own marks say how far this host can prove the expired output reaches.
        // Every byte before the first interval whose newest byte is *not* expired is one this
        // host can say had expired; a window with no such interval has expired entirely.
        let expired_to = self
            .resident_marks
            .iter()
            .find(|mark| mark.last_at_ms >= expires_before)
            .map_or(self.next_cursor, |mark| mark.cursor);
        {
            let to = expired_to;
            let excess =
                usize::try_from(to.saturating_sub(self.resident_start)).unwrap_or(usize::MAX);
            let take = excess.min(self.resident.len());
            if take > 0 {
                self.resident.drain(..take);
                self.resident_start += take as u64;
                self.trim_marks();
            }
        }
        let after = self.oldest_retained_cursor();
        if after <= before {
            return (None, file_bytes);
        }
        (
            Some(Eviction {
                limit: RetentionLimit::Age,
                from_cursor: before,
                to_cursor: after,
                bytes: after - before,
                at_ms: now_ms,
            }),
            file_bytes,
        )
    }

    /// Returns why a cursor is no longer retained, when this host recorded a reason.
    fn cause_of(&self, cursor: u64) -> Option<HistoryGapCause> {
        if self.spool_lost
            || self
                .spool
                .as_ref()
                .is_some_and(|spool| spool.unreadable_boundary)
        {
            // Either the spool could not be written, or it recorded where its output got to and
            // this host cannot read it back. Both leave a range this host cannot account for, and
            // both are a different answer from a bound being reached.
            return Some(HistoryGapCause::SpoolUnavailable);
        }
        self.evictions
            .iter()
            .rev()
            .find(|eviction| cursor >= eviction.from_cursor && cursor < eviction.to_cursor)
            .map(|eviction| match eviction.limit {
                RetentionLimit::Age => HistoryGapCause::Retention,
                RetentionLimit::HostCap => HistoryGapCause::HostCapacity,
                RetentionLimit::SessionCap => HistoryGapCause::SessionCapacity,
            })
    }

    /// Reads one page of retained output.
    ///
    /// # Errors
    ///
    /// Returns an error when a spool segment cannot be read.
    pub fn page(&self, from_cursor: u64, max_bytes: u64) -> Result<HistoryPageResult> {
        let oldest = self.oldest_retained_cursor();
        let limit = max_bytes.clamp(1, MAX_HISTORY_PAGE_BYTES);
        if self.boundary_unreadable() {
            // This host recorded where its output got to and cannot read it back, so it does not
            // know what it is missing. A page that reported no gap would be saying there is
            // nothing before this, which is the one thing it cannot say.
            let bytes = self.read_range(oldest.max(from_cursor), limit)?;
            let start = oldest.max(from_cursor);
            return Ok(HistoryPageResult {
                from_cursor: U64::new(start),
                next_cursor: U64::new(start + bytes.len() as u64),
                bytes: Bytes::new(bytes),
                oldest_retained_cursor: U64::new(oldest),
                gap: Nullable::some(HistoryGap {
                    from_cursor: U64::new(0),
                    to_cursor: U64::new(oldest),
                    cause: Some(HistoryGapCause::SpoolUnavailable),
                }),
            });
        }
        let (start, gap) = if from_cursor < oldest {
            (
                oldest,
                Some(HistoryGap {
                    from_cursor: U64::new(from_cursor),
                    to_cursor: U64::new(oldest),
                    cause: self.cause_of(from_cursor),
                }),
            )
        } else {
            (from_cursor.min(self.next_cursor), None)
        };
        let bytes = self.read_range(start, limit)?;
        Ok(HistoryPageResult {
            from_cursor: U64::new(start),
            next_cursor: U64::new(start + bytes.len() as u64),
            bytes: Bytes::new(bytes),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap),
        })
    }

    fn read_range(&self, start: u64, limit: u64) -> Result<Vec<u8>> {
        if start >= self.next_cursor {
            return Ok(Vec::new());
        }
        let available = self.next_cursor - start;
        let wanted = usize::try_from(available.min(limit)).unwrap_or(usize::MAX);
        if start >= self.resident_start {
            let offset = usize::try_from(start - self.resident_start).unwrap_or(usize::MAX);
            let take = wanted.min(self.resident.len().saturating_sub(offset));
            return Ok(self
                .resident
                .iter()
                .skip(offset)
                .take(take)
                .copied()
                .collect());
        }
        let Some(spool) = self.spool.as_ref() else {
            return Ok(Vec::new());
        };
        // Stop at the resident boundary: the caller pages forward and the next request is served
        // from memory.
        let take = wanted.min(usize::try_from(self.resident_start - start).unwrap_or(usize::MAX));
        spool.read(start, take)
    }
}

/// The file a spool records its boundary in, beside its segments.
///
/// A spool whose every segment has been evicted still has to say where its output got to.
/// Without this, reopening an empty directory would start the cursor again at nought, a client
/// asking for what it missed would be served the new output as though it were the old, and the
/// archive would have nothing to report a gap from.
const BOUNDARY_FILE: &str = "boundary";

/// Fixed-size segment files holding output older than the resident window.
#[derive(Debug)]
struct Spool {
    directory: PathBuf,
    layout: SpoolLayout,
    segments: VecDeque<Segment>,
    total_bytes: u64,
    /// The cursor after the last byte this spool has ever been given.
    ///
    /// It is written down before eviction deletes anything, and read back when the spool opens,
    /// so an empty directory is a spool that has lost its history rather than one that has none.
    boundary: u64,
    /// Whether a boundary was recorded and could not be read back.
    unreadable_boundary: bool,
    /// The segment being written, held open.
    ///
    /// Terminal output arrives in small batches — often one line at a time — and opening and
    /// closing a file for each of them makes the session's own output path the slowest thing in
    /// the host. The handle is kept for as long as the segment is the one being appended to.
    open_segment: Option<(PathBuf, std::fs::File)>,
}

#[derive(Clone, Debug)]
struct Segment {
    start: u64,
    len: u64,
    path: PathBuf,
    /// When this segment was first written.
    ///
    /// It bounds how much older than its newest byte a segment's oldest byte can be, because a
    /// segment is rotated once it reaches [`SEGMENT_ROTATION_MS`] whether or not it is full.
    /// Without that, one slow session could hold a month of output in a segment whose newest byte
    /// was written this minute and never be collected.
    started_at_ms: u64,
    /// When this segment was last written, as the host reads it back after a restart.
    ///
    /// Section 20's seven-day bound is about when output was produced, and a spool that survives
    /// a restart has to answer that without a record of its own. The file's own modification time
    /// is what the filesystem already keeps, so it is what this reads. Eviction reads the newest
    /// byte rather than the oldest, which is the direction that cannot delete output too early.
    written_at_ms: u64,
}

impl Spool {
    fn open(directory: PathBuf, layout: SpoolLayout) -> Result<Self> {
        create_owner_only(&directory)
            .map_err(|error| WorkerError::storage("create the output spool", error))?;
        Self::read_existing(directory, layout)
    }

    /// Opens a spool that is already there, creating and repairing nothing.
    fn read_existing(directory: PathBuf, layout: SpoolLayout) -> Result<Self> {
        // A spool that already has segments is this session's own history from before a restart.
        // Starting with an empty index would report it as a gap while the bytes sat on disk.
        let mut segments: Vec<Segment> = Vec::new();
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| WorkerError::storage("read the output spool", error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| WorkerError::storage("read the output spool", error))?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            if path.extension().is_none_or(|extension| extension != "out") {
                continue;
            }
            let Ok(start) = stem.parse::<u64>() else {
                continue;
            };
            let metadata = entry
                .metadata()
                .map_err(|error| WorkerError::storage("read the output spool", error))?;
            let len = metadata.len();
            let written_at_ms = metadata
                .modified()
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |since| {
                    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
                });
            segments.push(Segment {
                start,
                len,
                path,
                // A restart cannot tell when a segment was started, and the modification time is
                // the later of the two, so both read it: the segment is treated as if every byte
                // in it were as new as its newest, which keeps rather than deletes.
                started_at_ms: written_at_ms,
                written_at_ms,
            });
        }
        segments.sort_by_key(|segment| segment.start);
        let total_bytes = segments.iter().map(|segment| segment.len).sum();
        let recorded = read_boundary(&directory);
        let from_segments = segments
            .last()
            .map_or(0, |segment| segment.start + segment.len);
        let boundary = match recorded {
            RecordedBoundary::At(at) => at.max(from_segments),
            RecordedBoundary::None | RecordedBoundary::Unreadable => from_segments,
        };
        Ok(Self {
            directory,
            layout,
            segments: segments.into(),
            total_bytes,
            boundary,
            unreadable_boundary: recorded == RecordedBoundary::Unreadable,
            open_segment: None,
        })
    }

    fn next_cursor(&self) -> u64 {
        self.segments.back().map_or(self.boundary, |segment| {
            (segment.start + segment.len).max(self.boundary)
        })
    }

    fn oldest_cursor(&self) -> Option<u64> {
        self.segments.front().map(|segment| segment.start)
    }

    fn append(&mut self, start: u64, bytes: &[u8]) -> Result<()> {
        let mut written = 0_usize;
        while written < bytes.len() {
            let now_ms = kr_ipc::now_ms().get();
            let needs_new_segment = self.segments.back().is_none_or(|segment| {
                segment.len >= self.layout.segment_bytes
                    || now_ms.saturating_sub(segment.started_at_ms) >= SEGMENT_ROTATION_MS
            });
            if needs_new_segment {
                let segment_start = start + written as u64;
                self.segments.push_back(Segment {
                    start: segment_start,
                    len: 0,
                    path: self.directory.join(format!("{segment_start:020}.out")),
                    started_at_ms: now_ms,
                    written_at_ms: now_ms,
                });
            }
            let segment_bytes = self.layout.segment_bytes;
            let segment = self.segments.back_mut().expect("a segment exists");
            let room = usize::try_from(segment_bytes - segment.len).unwrap_or(usize::MAX);
            let take = room.min(bytes.len() - written);
            let path = segment.path.clone();
            let segment_len = take;
            // Borrowed separately from the segment, because the handle lives beside the index
            // rather than inside it: a segment that is evicted takes its entry, not this handle.
            let handle = match self.open_segment.as_mut() {
                Some((open, file)) if *open == path => file,
                _ => {
                    let file = open_segment(&path)?;
                    self.open_segment = Some((path.clone(), file));
                    &mut self
                        .open_segment
                        .as_mut()
                        .expect("the handle was just installed")
                        .1
                }
            };
            append_open(handle, &bytes[written..written + segment_len])?;
            let segment = self.segments.back_mut().expect("a segment exists");
            segment.len += take as u64;
            self.boundary = self.boundary.max(segment.start + segment.len);
            // The newest byte's time, not the oldest: a segment is past its retention only when
            // everything in it is, which is the direction that cannot delete output too early.
            segment.written_at_ms = kr_ipc::now_ms().get();
            self.total_bytes += take as u64;
            written += take;
        }
        let _ = self.evict();
        Ok(())
    }

    fn evict(&mut self) -> u64 {
        if self.total_bytes <= self.layout.capacity_bytes || self.segments.len() < 2 {
            return 0;
        }
        if !self.record_boundary() {
            // The boundary could not be published, so nothing that supports it is deleted.
            return 0;
        }
        let mut dropped = 0;
        while self.total_bytes > self.layout.capacity_bytes && self.segments.len() > 1 {
            let went = self.drop_oldest();
            if went == 0 {
                break;
            }
            dropped += went;
        }
        dropped
    }

    /// Removes the oldest segment and returns how many bytes went.
    ///
    /// The boundary is on disk before this is called, because the segment being deleted is part
    /// of what says where the output got to: a crash between the delete and the write would put
    /// the spool back in the condition the boundary exists to prevent.
    ///
    /// A file this host could not remove stays in the accounting. Dropping the entry while the
    /// bytes were still on disk would make the spool report less than it holds, and the next
    /// capacity pass would then delete something it did not need to.
    fn drop_oldest(&mut self) -> u64 {
        let Some(segment) = self.segments.front().cloned() else {
            return 0;
        };
        // The newest segment can also be the oldest, and retention may take it: the handle it is
        // being written through is dropped with it, so the next append opens a new one.
        if self
            .open_segment
            .as_ref()
            .is_some_and(|(path, _)| *path == segment.path)
        {
            self.open_segment = None;
        }
        match std::fs::remove_file(&segment.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return 0,
        }
        self.segments.pop_front();
        self.total_bytes -= segment.len;
        segment.len
    }

    /// Publishes the boundary before anything that supports it is deleted.
    ///
    /// Returns false when it could not be written, and then nothing is deleted: the retained
    /// output stays and the bound is breached until the next pass, which is the lesser of the two
    /// failures. Losing the record of where the output reached is the greater one.
    fn record_boundary(&mut self) -> bool {
        let boundary = self.boundary.max(self.next_cursor());
        if !write_boundary(&self.directory, boundary) {
            return false;
        }
        self.boundary = boundary;
        true
    }

    /// Removes the segments that are entirely past the retention period.
    ///
    /// Retention runs between appends rather than inside one, so it may take every segment: the
    /// next append starts a new one, and what stays readable meanwhile is the resident window.
    /// The eviction the capacity bound does inside an append keeps its own guard, because there
    /// the newest segment is the one being written to.
    fn drop_older_than(&mut self, expires_before: u64) -> u64 {
        if self
            .segments
            .front()
            .is_none_or(|segment| segment.written_at_ms >= expires_before)
        {
            return 0;
        }
        if !self.record_boundary() {
            // The boundary could not be published, so nothing that supports it is deleted.
            return 0;
        }
        let mut dropped = 0;
        while self
            .segments
            .front()
            .is_some_and(|segment| segment.written_at_ms < expires_before)
        {
            let went = self.drop_oldest();
            if went == 0 {
                break;
            }
            dropped += went;
        }
        dropped
    }

    /// Removes the oldest segments until at least `bytes` have gone.
    fn drop_at_least(&mut self, bytes: u64) -> u64 {
        if bytes == 0 || self.segments.is_empty() {
            return 0;
        }
        if !self.record_boundary() {
            // The boundary could not be published, so nothing that supports it is deleted.
            return 0;
        }
        let mut dropped = 0;
        while dropped < bytes && !self.segments.is_empty() {
            let went = self.drop_oldest();
            if went == 0 {
                break;
            }
            dropped += went;
        }
        dropped
    }

    /// Returns when the oldest retained segment was last written.
    fn oldest_written_at_ms(&self) -> Option<u64> {
        self.segments.front().map(|segment| segment.written_at_ms)
    }

    fn read(&self, start: u64, wanted: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(wanted);
        let mut cursor = start;
        while out.len() < wanted {
            let Some(segment) = self
                .segments
                .iter()
                .find(|segment| cursor >= segment.start && cursor < segment.start + segment.len)
            else {
                break;
            };
            let offset = cursor - segment.start;
            let take = (segment.len - offset).min((wanted - out.len()) as u64);
            let chunk = read_file_range(&segment.path, offset, take)?;
            if chunk.is_empty() {
                break;
            }
            cursor += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// What a spool's recorded boundary says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordedBoundary {
    /// No boundary has been written, which is a spool that has never evicted.
    None,
    /// The cursor after the last byte this spool was given.
    At(u64),
    /// A boundary was written and cannot be read back.
    ///
    /// What this host then cannot say is where its output got to, so it says that rather than
    /// guessing: the range reads as lost for a reason of its own.
    Unreadable,
}

/// Reads the boundary a spool recorded.
fn read_boundary(directory: &Path) -> RecordedBoundary {
    match std::fs::read_to_string(directory.join(BOUNDARY_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RecordedBoundary::None,
        Err(_) => RecordedBoundary::Unreadable,
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_or(RecordedBoundary::Unreadable, RecordedBoundary::At),
    }
}

/// Removes what a lost spool left on the disk, and says what is still there.
///
/// This is the purge path for a spool whose handle has gone: the segment files are ordinary files
/// in a directory this session owns, and removing them is what makes a privacy cleanup true
/// rather than merely reported. A file this host cannot unlink, and a directory it cannot read,
/// are named rather than counted as removed.
///
/// The boundary is written first and kept. It says where this session's output got to, which is
/// what makes the range that went read as a gap rather than as a session that started at nought,
/// and it is a number rather than content, so privacy mode has no reason to take it.
fn remove_spool_files(directory: &Path, boundary: u64) -> (u64, u64, Option<String>) {
    if !write_boundary(directory, boundary) {
        return (
            0,
            0,
            Some(
                "this session's spool boundary could not be written, so what its lost spool left \
                 was kept rather than deleted behind a range nothing could account for"
                    .to_owned(),
            ),
        );
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return (
            0,
            0,
            Some(format!(
                "this session's spool directory at {} could not be read, so what it holds was \
                 left where it was",
                directory.display()
            )),
        );
    };
    let mut bytes = 0;
    let mut removed = 0;
    let mut left = 0;
    for entry in entries {
        // An entry this host could not even read is an entry it cannot say it removed.
        let Ok(entry) = entry else {
            left += 1;
            continue;
        };
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == BOUNDARY_FILE) {
            continue;
        }
        let size = entry.metadata().map(|data| data.len()).unwrap_or_default();
        if std::fs::remove_file(&path).is_ok() {
            bytes += size;
            removed += 1;
        } else {
            left += 1;
        }
    }
    let left_behind =
        (left > 0).then(|| format!("{left} of this session's spool files could not be removed"));
    (bytes, removed, left_behind)
}

/// Writes the boundary down, replacing it in one step, and says whether it is published.
///
/// The temporary file and the rename are what make it one step: a crash during the write leaves
/// either the previous boundary or the new one, never half of either.
///
/// The answer matters. A full disk can refuse this write and still allow the deletions that
/// follow it, and a spool that deleted its segments over an unpublished boundary would come back
/// from a restart with no record of where its output had reached. So the answer is returned, and
/// the caller does not delete what the boundary describes until it is true.
fn write_boundary(directory: &Path, boundary: u64) -> bool {
    let staging = directory.join("boundary.writing");
    if std::fs::write(&staging, boundary.to_string()).is_err() {
        let _ = std::fs::remove_file(&staging);
        return false;
    }
    if std::fs::rename(&staging, directory.join(BOUNDARY_FILE)).is_err() {
        let _ = std::fs::remove_file(&staging);
        return false;
    }
    true
}

/// Creates the spool directory so that only this account can read it.
///
/// Section 24 makes local state directories owner-only. `create_dir_all` alone leaves the mode to
/// the process umask, which is not a decision this host may delegate: the spool holds the
/// terminal's own output.
#[cfg(unix)]
fn create_owner_only(directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    if let Some(parent) = directory.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A directory an earlier build created may be wider than this one accepts, so it is
            // narrowed rather than trusted.
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        }
        Err(error) => Err(error),
    }
}

/// Creates the spool directory.
///
/// Windows inherits the owner-only access list of the environment's state directory, which the
/// host creates before any session exists.
#[cfg(not(unix))]
fn create_owner_only(directory: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)
}

fn open_segment(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| WorkerError::storage("open an output spool segment", error))
}

fn append_open(file: &mut std::fs::File, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    file.write_all(bytes)
        .map_err(|error| WorkerError::storage("write an output spool segment", error))
}

fn read_file_range(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = std::fs::File::open(path)
        .map_err(|error| WorkerError::storage("open an output spool segment", error))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| WorkerError::storage("seek an output spool segment", error))?;
    let mut buffer = vec![0_u8; usize::try_from(len).unwrap_or(usize::MAX)];
    let read = file
        .read(&mut buffer)
        .map_err(|error| WorkerError::storage("read an output spool segment", error))?;
    buffer.truncate(read);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_increase_by_the_bytes_written() {
        let mut history = OutputHistory::in_memory(1024);
        assert_eq!(history.append(b"hello"), 0);
        assert_eq!(history.append(b" world"), 5);
        assert_eq!(history.next_cursor(), 11);
    }

    #[test]
    fn a_page_returns_what_was_written_from_the_requested_cursor() {
        let mut history = OutputHistory::in_memory(1024);
        history.append(b"hello world");
        let page = history.page(6, 64).expect("pages");
        assert_eq!(page.bytes.as_slice(), b"world");
        assert_eq!(page.from_cursor.get(), 6);
        assert_eq!(page.next_cursor.get(), 11);
        assert!(!page.gap.is_present());
    }

    /// A spool directory on the internal disk, named so two tests never share one.
    fn spool_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("kr-spool-{name}-{}", kr_ipc::new_uuid()))
    }

    #[test]
    fn output_older_than_the_resident_window_is_an_explicit_gap() {
        let mut history = OutputHistory::in_memory(8);
        history.append(b"0123456789abcdef");
        assert_eq!(history.oldest_retained_cursor(), 8);
        let page = history.page(0, 64).expect("pages");
        let gap = page.gap.as_ref().expect("a gap is reported");
        assert_eq!(gap.from_cursor.get(), 0);
        assert_eq!(gap.to_cursor.get(), 8);
        assert_eq!(page.from_cursor.get(), 8);
        assert_eq!(page.bytes.as_slice(), b"89abcdef");
    }

    #[test]
    fn a_page_is_bounded_even_when_more_is_asked_for() {
        let mut history = OutputHistory::in_memory(4 * 1024 * 1024);
        history.append(&vec![b'x'; 2 * 1024 * 1024]);
        let page = history.page(0, u64::MAX).expect("pages");
        assert_eq!(page.bytes.len() as u64, MAX_HISTORY_PAGE_BYTES);
        assert_eq!(page.next_cursor.get(), MAX_HISTORY_PAGE_BYTES);
    }

    #[test]
    fn a_page_at_the_end_is_empty_rather_than_an_error() {
        let mut history = OutputHistory::in_memory(64);
        history.append(b"abc");
        let page = history.page(3, 64).expect("pages");
        assert!(page.bytes.is_empty());
        assert_eq!(page.next_cursor.get(), 3);
    }

    #[test]
    fn the_spool_serves_output_that_has_left_the_resident_window() {
        let directory = std::env::temp_dir().join(format!("kr-spool-{}", kr_ipc::new_uuid()));
        let mut history =
            OutputHistory::with_spool(8, &directory, SpoolLayout::DEFAULT).expect("opens a spool");
        history.append(b"0123456789abcdef");
        assert_eq!(history.oldest_retained_cursor(), 0);
        let page = history.page(0, 64).expect("pages");
        assert!(!page.gap.is_present());
        assert_eq!(page.bytes.as_slice(), b"01234567");
        let next = history.page(page.next_cursor.get(), 64).expect("pages");
        assert_eq!(next.bytes.as_slice(), b"89abcdef");
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn the_spool_drops_its_oldest_segments_and_reports_the_gap() {
        let directory = std::env::temp_dir().join(format!("kr-spool-{}", kr_ipc::new_uuid()));
        // Segments and a bound small enough that the eviction rule runs within one test.
        let mut history = OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 16))
            .expect("opens a spool");
        for _ in 0..8 {
            history.append(&[b'z'; 8]);
        }
        let oldest = history.oldest_retained_cursor();
        assert!(oldest > 0, "the oldest segments were dropped");
        let page = history.page(0, 64).expect("pages");
        assert!(page.gap.is_present());
        assert_eq!(page.from_cursor.get(), oldest);
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn output_past_the_retention_period_goes_and_the_gap_says_it_was_its_age() {
        let directory = spool_directory("retention-age");
        let mut history =
            OutputHistory::with_spool(4, directory.clone(), SpoolLayout::new(8, 1024 * 1024))
                .expect("a spool");
        history.append(&[b'a'; 8]);
        history.append(&[b'b'; 8]);
        history.append(&[b'c'; 8]);
        // Everything written so far is older than the retention period.
        let now = TimestampMs::new(kr_ipc::now_ms().get() + 8 * 24 * 60 * 60 * 1000);
        let taken = history.apply_retention(OutputRetention::DEFAULT, 0, now, true);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].limit, RetentionLimit::Age);
        assert_eq!(taken[0].from_cursor, 0);
        let page = history.page(0, 64).expect("a page");
        let gap = page.gap.0.expect("the evicted range is reported");
        assert_eq!(gap.from_cursor.get(), 0);
        assert_eq!(gap.cause, Some(HistoryGapCause::Retention));
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_session_inside_its_own_cap_still_gives_bytes_up_when_the_host_is_over_its() {
        let directory = spool_directory("retention-host-cap");
        let mut history =
            OutputHistory::with_spool(4, directory.clone(), SpoolLayout::new(8, 1024 * 1024))
                .expect("a spool");
        for _ in 0..4 {
            history.append(&[b'x'; 8]);
        }
        let retention =
            OutputRetention::new(std::time::Duration::from_secs(7 * 24 * 60 * 60), 40, 1024);
        let now = kr_ipc::now_ms();
        // This session holds 32 bytes, well inside its own 1,024-byte cap, and the host holds 64.
        let taken = history.apply_retention(retention, 64, now, true);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].limit, RetentionLimit::HostCap);
        assert_eq!(taken[0].bytes, 24);
        let page = history.page(0, 64).expect("a page");
        let gap = page.gap.0.expect("the evicted range is reported");
        assert_eq!(gap.cause, Some(HistoryGapCause::HostCapacity));
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_session_over_its_own_cap_is_told_which_cap_it_was() {
        let directory = spool_directory("retention-session-cap");
        let mut history =
            OutputHistory::with_spool(4, directory.clone(), SpoolLayout::new(8, 1024 * 1024))
                .expect("a spool");
        for _ in 0..4 {
            history.append(&[b'x'; 8]);
        }
        let retention =
            OutputRetention::new(std::time::Duration::from_secs(7 * 24 * 60 * 60), 1024, 16);
        let taken = history.apply_retention(retention, 32, kr_ipc::now_ms(), true);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].limit, RetentionLimit::SessionCap);
        let page = history.page(0, 64).expect("a page");
        assert_eq!(
            page.gap.0.expect("a gap").cause,
            Some(HistoryGapCause::SessionCapacity)
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn retention_that_nothing_breaches_takes_nothing_and_leaves_no_gap() {
        let directory = spool_directory("retention-quiet");
        let mut history =
            OutputHistory::with_spool(4, directory.clone(), SpoolLayout::new(8, 1024 * 1024))
                .expect("a spool");
        history.append(&[b'x'; 8]);
        let taken = history.apply_retention(OutputRetention::DEFAULT, 8, kr_ipc::now_ms(), true);
        assert!(taken.is_empty());
        assert!(history.evictions().is_empty());
        assert!(!history.page(0, 64).expect("a page").gap.is_present());
        std::fs::remove_dir_all(&directory).ok();
    }
}
