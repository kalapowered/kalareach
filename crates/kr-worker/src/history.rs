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
    /// keep every byte of it until the next tick. The host-wide bound cannot be kept by a layout
    /// constant at all, because nothing accounts for a write against what the other sessions have
    /// already spent; it is applied by the maintenance tick reading the whole spool directory, so
    /// the host-wide total can stand over that bound between two ticks.
    pub const DEFAULT: Self = Self {
        segment_bytes: 8 * 1024 * 1024,
        capacity_bytes: crate::persistence::retention::SESSION_CAP_BYTES,
    };

    /// Builds a layout, keeping the segment size within the capacity.
    ///
    /// A segment larger than the capacity could not be written without standing over it, so the
    /// segment is cut to the capacity; and a spool holds at least one byte, because one that could
    /// hold nothing would be a spool that makes room it can never use.
    #[must_use]
    pub const fn new(segment_bytes: u64, capacity_bytes: u64) -> Self {
        let capacity_bytes = if capacity_bytes == 0 {
            1
        } else {
            capacity_bytes
        };
        let segment_bytes = if segment_bytes == 0 {
            1
        } else if segment_bytes > capacity_bytes {
            capacity_bytes
        } else {
            segment_bytes
        };
        Self {
            segment_bytes,
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
    /// The ranges the spool could not take while it was stopped, newest last.
    ///
    /// A stopped spool keeps what it holds and takes nothing more, so the output that arrives
    /// meanwhile is retained only as far as the resident window can keep it within the cap. A
    /// range that ended up held by neither is a range this host lost to its storage rather than to
    /// a bound, and a reader asking for it is told that, even after the spool takes output again.
    unretained: VecDeque<(u64, u64)>,
    /// Why the last retention pass left output it was asked to remove, when it did.
    left_behind: Option<String>,
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
            unretained: VecDeque::new(),
            left_behind: None,
            resident_marks: VecDeque::new(),
            evictions: VecDeque::new(),
        }
    }

    /// Opens an existing spool, without creating or repairing anything.
    ///
    /// The archive reads a session's retained output after the session is gone, and a read is a
    /// read: it does not create the directory it was asked about, and it does not narrow the
    /// permissions of one that is already there. The archive also collects a closed session's
    /// output through it, under recovery ownership: collection removes what is past its bounds,
    /// and a directory that is not there is not one it makes.
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
    /// The session cap holds before the write, not after it: the spool gives up its oldest
    /// segments to make room for each piece of an append before that piece is written, so one
    /// large append never stands over the bound, and the range it gave up reads as a gap that
    /// names the session cap.
    ///
    /// Appending never fails. A spool that cannot make room, write a segment or publish its
    /// boundary stops taking output at that cursor and keeps everything it holds: indexed, served,
    /// counted against the cap and tried again by every retention pass. A boundary that could not
    /// be written is tried again by the next append as well, which does not wait for it: another
    /// program can hold it for a moment. What arrives while the spool is stopped is retained in the
    /// resident window only as far as the spool's remaining room allows, so the two layers
    /// together stay within the cap, and the range neither holds reads as a gap whose cause is the
    /// spool rather than a bound.
    pub fn append(&mut self, bytes: &[u8]) -> u64 {
        let start = self.next_cursor;
        if bytes.is_empty() {
            return start;
        }
        if !self.retaining {
            // Privacy mode has disabled retention. The cursor still advances, because it is the
            // session's own position and a client that asked for what it missed is told the range
            // is gone rather than served later output under an earlier cursor.
            // The window ends where the output does, so the output it does not keep empties it:
            // left in place, its bytes would be read at cursors they were never written at.
            self.next_cursor += bytes.len() as u64;
            self.resident.clear();
            self.resident_marks.clear();
            self.resident_start = self.next_cursor;
            if let Some(spool) = self.spool.as_mut() {
                spool.note_position(self.next_cursor);
            }
            return start;
        }
        // A spool stopped for want of its boundary is tried again before this append takes its
        // bytes: one write that is never waited for, so a boundary that is still held costs the
        // output path a refused write and no wait, and one that has been let go is written and the
        // eviction made.
        if self.spool.as_ref().is_some_and(Spool::awaits_boundary) {
            self.try_resume();
        }
        let now = kr_ipc::now_ms();
        if let Some(spool) = self.spool.as_mut()
            && let Some((from_cursor, to_cursor, gone)) = spool.append(start, bytes)
        {
            self.record_eviction(Eviction {
                limit: RetentionLimit::SessionCap,
                from_cursor,
                to_cursor,
                bytes: gone,
                at_ms: now,
            });
        }
        self.resident.extend(bytes.iter().copied());
        self.next_cursor += bytes.len() as u64;
        if let Some(spool) = self.spool.as_mut() {
            spool.note_position(self.next_cursor);
        }
        let now_ms = now.get();
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
        self.bound_past_suspension();
        self.trim_marks();
        start
    }

    /// Keeps the output a stopped spool could not take within the room the spool has left.
    ///
    /// The session cap is on what the session retains, which is the spool and the resident window
    /// together. While the spool takes everything, the window is the newest part of it and adds
    /// nothing; once the spool has stopped, the window holds output the spool does not, and that
    /// output fits only in the room the spool has left. What does not fit is not retained: the
    /// terminal still shows it and every attachment still receives it.
    fn bound_past_suspension(&mut self) {
        let Some(spool) = self.spool.as_ref() else {
            return;
        };
        let Some(stopped) = spool.suspended_at() else {
            return;
        };
        let room = spool
            .layout
            .capacity_bytes
            .saturating_sub(spool.total_bytes);
        let past = self.resident_start.max(stopped);
        if self.next_cursor.saturating_sub(past) <= room {
            return;
        }
        let keep_from = self.next_cursor - room;
        let excess = usize::try_from(keep_from.saturating_sub(self.resident_start))
            .unwrap_or(usize::MAX)
            .min(self.resident.len());
        self.resident.drain(..excess);
        self.resident_start += excess as u64;
    }

    /// Records one eviction, keeping the newest [`MAX_RECORDED_EVICTIONS`].
    fn record_eviction(&mut self, eviction: Eviction) {
        self.evictions.push_back(eviction);
        while self.evictions.len() > MAX_RECORDED_EVICTIONS {
            self.evictions.pop_front();
        }
    }

    /// Returns where the spool stopped taking output, and why, while it has.
    #[must_use]
    pub fn suspended(&self) -> Option<(u64, &str)> {
        self.spool.as_ref().and_then(Spool::suspension)
    }

    /// Returns why the last retention pass left output it was asked to remove, when it did.
    ///
    /// A pass that could not remove a segment says so here rather than reporting what it managed
    /// as though it were everything: the segment is still on the disk, still counted and still
    /// served, and the next pass tries it again.
    #[must_use]
    pub fn left_behind(&self) -> Option<&str> {
        self.left_behind.as_deref()
    }

    /// Lets a stopped spool take output again, once it can.
    ///
    /// Each retention pass asks. The spool makes room for what the resident window holds past the
    /// point it stopped and writes that; only when both succeed does it take output again, from
    /// where the window's copy begins. The range before that is output neither layer kept, and it
    /// is recorded as that. A spool that still cannot make room or write stays stopped where it
    /// first stopped.
    fn try_resume(&mut self) {
        let Some(spool) = self.spool.as_mut() else {
            return;
        };
        let Some(stopped) = spool.suspended_at() else {
            return;
        };
        let from = self.resident_start.max(stopped);
        let offset = usize::try_from(from.saturating_sub(self.resident_start)).unwrap_or(0);
        let pending: Vec<u8> = self.resident.iter().skip(offset).copied().collect();
        let (resumption, evicted) = spool.resume(from, &pending);
        if let Some((from_cursor, to_cursor, gone)) = evicted {
            self.record_eviction(Eviction {
                limit: RetentionLimit::SessionCap,
                from_cursor,
                to_cursor,
                bytes: gone,
                at_ms: kr_ipc::now_ms(),
            });
        }
        // Once the spool has written from `from`, whether it then kept going or stopped again
        // further on, the range before `from` is output neither layer kept.
        if resumption != Resumption::Stopped && from > stopped {
            self.unretained.push_back((stopped, from));
            while self.unretained.len() > MAX_RECORDED_EVICTIONS {
                self.unretained.pop_front();
            }
        }
    }

    /// Returns the most bytes this session's spool has held at once since it was opened.
    ///
    /// Room is made before each write, so it never passes the spool's capacity, which is the
    /// session cap. It is what lets a caller confirm that rather than take it on trust.
    #[must_use]
    pub fn spool_peak_bytes(&self) -> u64 {
        self.spool.as_ref().map_or(0, |spool| spool.peak_bytes)
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

    /// Returns the ranges inside the retained range that nothing retained holds.
    ///
    /// Retained output is one run of cursors, and the spool is meant to hold every byte of it that
    /// the resident window does not. A segment that has gone - deleted from under the session, or
    /// lost with its disk - leaves a range between its neighbours that nothing holds, and so does a
    /// newest segment that went after the spool recorded a boundary past it. Each is output this
    /// host cannot account for, and each is reported rather than read as a quiet stretch: a page
    /// that reaches one says so, and the archive's own account names it.
    ///
    /// It reads the spool's index. A file that goes while the index still names it is found when
    /// a page reaches it, and is forgotten by the next retention pass.
    #[must_use]
    pub fn holes(&self) -> Vec<(u64, u64)> {
        self.spool
            .as_ref()
            .map_or_else(Vec::new, |spool| spool.uncovered(self.resident_start))
    }

    /// Returns how many bytes of output this session retains.
    ///
    /// It is what the two layers hold together, counted once. The resident window is normally the
    /// newest part of what the spool holds, so adding the two would read a session as larger than
    /// it is; and a range the spool no longer holds is not retained, whatever the distance from
    /// the oldest cursor to the newest says.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        let resident = self.resident.len() as u64;
        let Some(spool) = self.spool.as_ref() else {
            return resident;
        };
        spool.total_bytes
            + resident.saturating_sub(spool.covered(self.resident_start, self.next_cursor))
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
        // A spool that stopped taking output still indexes every segment it wrote, so the purge
        // reaches all of them through the index: nothing it wrote is out of its account.
        let Some(spool) = self.spool.as_mut() else {
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
            match spool.drop_oldest() {
                Ok(went) => {
                    discarded.bytes += went;
                    discarded.segments += 1;
                }
                Err(reason) => {
                    // A segment this host could not unlink is content it was asked to remove and
                    // has not. It stays in the accounting and the failure is reported rather than
                    // the removal being called complete over a file a reader can still be served.
                    discarded.left_behind = Some(format!(
                        "{} of this session's spool segments could not be removed: {reason}",
                        spool.segments.len()
                    ));
                    break;
                }
            }
        }
        if discarded.left_behind.is_none() {
            // An empty spool is owed nothing, so one that had stopped takes output again once
            // retention does.
            spool.clear_suspension();
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
        self.left_behind = None;
        // A segment whose file has gone is not retained, and a pass that counted it would evict
        // output this session did not need to give up.
        if let Some(spool) = self.spool.as_mut() {
            spool.forget_vanished();
        }

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
            let (dropped, left_behind) = spool.drop_at_least(over);
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
            if left_behind.is_some() {
                self.left_behind = left_behind;
            }
        }

        for eviction in &taken {
            self.record_eviction(*eviction);
        }
        if let Some(spool) = self.spool.as_mut() {
            // The directory says where the session's output reached, even where the spool did not
            // take it - privacy mode's output, or a stopped spool's - so a spool reopened over it,
            // and the archive reading it after the session has gone, continue from there rather
            // than from where the spool stopped. Best effort: a directory that cannot be written
            // is one the next pass tries again.
            let _ = spool.publish_position();
        }
        // A spool that stopped taking output is asked each pass whether it can take it again.
        self.try_resume();
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
        let held_before = self.retained_bytes();
        let mut file_bytes = 0;
        if let Some(spool) = self.spool.as_mut() {
            let (dropped, left_behind) = spool.drop_older_than(expires_before);
            file_bytes += dropped;
            if left_behind.is_some() {
                self.left_behind = left_behind;
            }
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
                bytes: held_before.saturating_sub(self.retained_bytes()),
                at_ms: now_ms,
            }),
            file_bytes,
        )
    }

    /// Returns why a cursor is no longer retained, when this host recorded a reason.
    fn cause_of(&self, cursor: u64) -> Option<HistoryGapCause> {
        let spool_stopped_before = self
            .spool
            .as_ref()
            .and_then(Spool::suspended_at)
            .is_some_and(|stopped| cursor >= stopped);
        if spool_stopped_before
            || self
                .unretained
                .iter()
                .any(|&(from, to)| cursor >= from && cursor < to)
            || self
                .spool
                .as_ref()
                .is_some_and(|spool| spool.unreadable_boundary)
        {
            // The spool stopped taking output before this cursor, or it recorded where its output
            // got to and this host cannot read it back. Both leave a range this host cannot
            // account for, and both are a different answer from a bound being reached.
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
        let unaccounted = self.boundary_unreadable();
        let (mut start, mut gap) = if unaccounted {
            // This host recorded where its output got to and cannot read it back, so it does not
            // know what it is missing. A page that reported no gap would be saying there is
            // nothing before this, which is the one thing it cannot say.
            (
                oldest.max(from_cursor),
                Some(HistoryGap {
                    from_cursor: U64::new(0),
                    to_cursor: U64::new(oldest),
                    cause: Some(HistoryGapCause::SpoolUnavailable),
                }),
            )
        } else if from_cursor < oldest {
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
        let bytes = match self.read_held(start, limit)? {
            Held::Bytes(bytes) => bytes,
            Held::Missing { to } => match gap.as_mut() {
                // A host that cannot say where its output got to cannot account for this range
                // either. The gap it already reports reaches over it, which is what moves the
                // reader past it rather than asking the same cursor again.
                Some(reported) if unaccounted => {
                    reported.to_cursor = U64::new(to);
                    start = to;
                    self.read_held(start, limit)?.into_bytes()
                }
                // One page carries one gap, and this one already reports the range before the
                // oldest cursor. The reader asks again from here and is told about this one.
                Some(_) => Vec::new(),
                // A range inside the retained range that nothing holds. It is reported with the
                // cause this host recorded for it, or as a range it cannot account for, and the
                // page goes on to what comes after it.
                None => {
                    gap = Some(HistoryGap {
                        from_cursor: U64::new(start),
                        to_cursor: U64::new(to),
                        cause: Some(
                            self.cause_of(start)
                                .unwrap_or(HistoryGapCause::ArchiveIncomplete),
                        ),
                    });
                    start = to;
                    self.read_held(start, limit)?.into_bytes()
                }
            },
        };
        Ok(HistoryPageResult {
            from_cursor: U64::new(start),
            next_cursor: U64::new(start + bytes.len() as u64),
            bytes: Bytes::new(bytes),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap),
        })
    }

    /// Reads what this history holds from `start`, up to `limit` bytes.
    fn read_held(&self, start: u64, limit: u64) -> Result<Held> {
        if start >= self.next_cursor {
            return Ok(Held::Bytes(Vec::new()));
        }
        let available = self.next_cursor - start;
        let wanted = usize::try_from(available.min(limit)).unwrap_or(usize::MAX);
        if start >= self.resident_start {
            let offset = usize::try_from(start - self.resident_start).unwrap_or(usize::MAX);
            let take = wanted.min(self.resident.len().saturating_sub(offset));
            return Ok(Held::Bytes(
                self.resident
                    .iter()
                    .skip(offset)
                    .take(take)
                    .copied()
                    .collect(),
            ));
        }
        let Some(spool) = self.spool.as_ref() else {
            // A cursor before the resident window with no spool behind it is before the oldest
            // retained cursor, which a page reports before it reads anything.
            return Ok(Held::Missing {
                to: self.resident_start,
            });
        };
        // Stop at the resident boundary: the caller pages forward and the next request is served
        // from memory.
        let take = wanted.min(usize::try_from(self.resident_start - start).unwrap_or(usize::MAX));
        spool.read_at(start, take, self.resident_start)
    }
}

/// What a history holds at one cursor.
#[derive(Debug)]
enum Held {
    /// Bytes from the cursor, up to the first range nothing holds.
    Bytes(Vec<u8>),
    /// Nothing is held from the cursor up to `to`.
    Missing {
        /// The first cursor after the one asked for that something holds, or the end of the range
        /// that was asked about.
        to: u64,
    },
}

impl Held {
    /// The bytes, or none for a range nothing holds.
    fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Missing { .. } => Vec::new(),
        }
    }
}

/// The file a spool records its boundary in, beside its segments.
///
/// A spool whose every segment has been evicted still has to say where its output got to.
/// Without this, reopening an empty directory would start the cursor again at nought, a client
/// asking for what it missed would be served the new output as though it were the old, and the
/// archive would have nothing to report a gap from.
const BOUNDARY_FILE: &str = "boundary";

/// What a retention pass says when it could not publish the boundary, and so removed nothing.
const BOUNDARY_UNWRITTEN: &str =
    "this session's spool boundary could not be written, so nothing it supports was removed";

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
    /// The most bytes this spool has held at once since it was opened.
    ///
    /// Room is made before each write, so it never passes the capacity; it is what lets a caller
    /// see that rather than take it on trust.
    peak_bytes: u64,
    /// The boundary this spool last wrote down, or read back when it opened.
    ///
    /// A position ahead of both this and the newest segment is one only memory holds, and each
    /// retention pass writes it down, so a spool reopened after output it did not take - privacy
    /// mode's, or a stopped spool's - continues the session's cursor rather than reusing it.
    published: u64,
    /// The segment being written, held open.
    ///
    /// Terminal output arrives in small batches — often one line at a time — and opening and
    /// closing a file for each of them makes the session's own output path the slowest thing in
    /// the host. The handle is kept for as long as the segment is the one being appended to.
    open_segment: Option<(PathBuf, std::fs::File)>,
    /// Where this spool stopped taking output, and why, when it has.
    ///
    /// A spool that could not make room, open or write a segment, or publish its boundary takes
    /// nothing more until a retention pass finds that it can, or, for a boundary that could not be
    /// written, until an append does, and keeps everything it already holds: dropping it would
    /// take its files out of the account while they were still on the disk, and out of reach of
    /// the passes that collect them.
    suspended: Option<Suspension>,
    /// A write that stops part way, which a test arranges: the next write lays down this many
    /// bytes and then fails.
    #[cfg(test)]
    short_write: Option<usize>,
    /// Whether a test has arranged that a file cannot be cut back after a failed write.
    #[cfg(test)]
    refuse_cut: bool,
}

/// Where a spool stopped taking output, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Suspension {
    /// The first cursor the spool did not take.
    at: u64,
    /// What stops it now, in words a person can act on: the obstacle the last attempt to take
    /// output again found, which is the one `boundary` says whether it is.
    reason: String,
    /// Whether a later pass may let it take output again.
    ///
    /// False when a write failed and this host could neither cut the file back to what it counted
    /// nor read how much the file holds: past that, where the next byte would land in the file is
    /// not something this host knows, so nothing more is written to this spool.
    resumable: bool,
    /// Whether what stops it now is a boundary that could not be written.
    ///
    /// Another program can hold the boundary for a moment, and the output path does not wait for
    /// it, so the next append tries it again, as a retention pass does. The other stops - a
    /// segment that could not be removed, opened or written - wait for a retention pass.
    boundary: bool,
}

/// Why a spool could not make room for a write.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NoRoom {
    /// What went wrong, in words a person can act on.
    reason: String,
    /// Whether the boundary that has to be written before anything goes could not be written.
    boundary: bool,
}

/// Why a write into the newest segment failed, and how much of it the segment now holds.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WriteFailure {
    /// How many of the bytes the segment is counted as holding.
    kept: u64,
    /// What went wrong, in words a person can act on.
    reason: String,
    /// Whether a later pass may let the spool take output again.
    resumable: bool,
}

/// Where an attempt to let a stopped spool take output again left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resumption {
    /// Still stopped where it first stopped: nothing was written.
    Stopped,
    /// Taking output again.
    Taking,
    /// It wrote from where it was asked to and stopped again, at the first cursor it did not take.
    StoppedLater,
}

/// Joins the ranges two steps of one append gave up, the earlier first.
fn joined(
    earlier: Option<(u64, u64, u64)>,
    later: Option<(u64, u64, u64)>,
) -> Option<(u64, u64, u64)> {
    match (earlier, later) {
        (Some((from, _, before)), Some((_, to, gone))) => Some((from, to, before + gone)),
        (earlier, later) => earlier.or(later),
    }
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
    /// Whether this segment takes no more bytes.
    ///
    /// A segment a write failed on is closed to further writes, whatever the failure left in it:
    /// the next byte starts a new segment, so no write lands after bytes this host did not count.
    sealed: bool,
    /// Bytes a failed write may have left in the file beyond what it counted.
    ///
    /// Nought unless a write failed and neither cutting the file back nor reading its length
    /// answered. They are counted against the cap until the segment goes, because a byte that may
    /// be on the disk is not one to count as free.
    uncertain: u64,
}

impl Segment {
    /// The cursor after this segment's last byte.
    const fn end(&self) -> u64 {
        self.start + self.len
    }
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
            // The size and the time come from the file itself, not from `DirEntry::metadata`: on
            // Windows that reads what NTFS keeps in the directory entry, which it does not bring
            // up to date while a handle to the file is open, so a segment still being written
            // would read shorter than it is. A segment that went between the listing and this
            // read is a range the spool no longer holds.
            let metadata = match std::fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(WorkerError::storage("read the output spool", error)),
            };
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
                // The index is the file's own length, so a write may continue it.
                sealed: false,
                uncertain: 0,
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
            peak_bytes: total_bytes,
            published: match recorded {
                RecordedBoundary::At(at) => at,
                RecordedBoundary::None | RecordedBoundary::Unreadable => 0,
            },
            open_segment: None,
            suspended: None,
            #[cfg(test)]
            short_write: None,
            #[cfg(test)]
            refuse_cut: false,
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

    /// Remembers where the session's output has reached, whether this spool took it or not.
    ///
    /// It is what the boundary publishes. A spool that stopped, or that retention was turned off
    /// for, did not take everything; its boundary still says where the output got to, so a spool
    /// reopened over this directory continues the session's cursor rather than reusing cursors
    /// already given out, and a reader is told the range it does not hold.
    fn note_position(&mut self, cursor: u64) {
        self.boundary = self.boundary.max(cursor);
    }

    /// Writes one append, making room for each piece before it is written, and returns the range
    /// the append gave up to make that room: its first cursor, the first cursor still held, and
    /// how many bytes went.
    ///
    /// A piece never needs more than one segment of room, and the layout keeps a segment within
    /// the capacity, so once the older segments have gone the room is there; the segment a piece
    /// is written into is never the one given up for it. A cursor that does not continue the
    /// newest segment starts a new one, because a segment's bytes are the cursors from its start
    /// in order, and so does a segment a write failed on.
    ///
    /// Nothing here stands over the capacity. When the room cannot be made, or a segment cannot be
    /// opened or written, the spool stops at the first cursor it did not take, keeps everything it
    /// holds, and takes nothing more until a retention pass finds that it can, or, when the
    /// boundary could not be written, until the next append does.
    fn append(&mut self, start: u64, bytes: &[u8]) -> Option<(u64, u64, u64)> {
        if self.suspended.is_some() {
            return None;
        }
        let mut evicted: Option<(u64, u64, u64)> = None;
        let mut written = 0_usize;
        while written < bytes.len() {
            let cursor = start + written as u64;
            let now_ms = kr_ipc::now_ms().get();
            let rotate = self.segments.back().is_none_or(|segment| {
                segment.sealed
                    || segment.len >= self.layout.segment_bytes
                    || now_ms.saturating_sub(segment.started_at_ms) >= SEGMENT_ROTATION_MS
                    || segment.end() != cursor
            });
            let room = if rotate {
                self.layout.segment_bytes
            } else {
                self.segments
                    .back()
                    .map_or(self.layout.segment_bytes, |segment| {
                        self.layout.segment_bytes.saturating_sub(segment.len)
                    })
            };
            let take = usize::try_from(room)
                .unwrap_or(usize::MAX)
                .min(bytes.len() - written);
            let (made, failure) = self.make_room(take as u64, !rotate, cursor);
            evicted = joined(evicted, made);
            if let Some(no_room) = failure {
                self.suspend(cursor, no_room.reason, true, no_room.boundary);
                break;
            }
            if rotate {
                let path = self.directory.join(format!("{cursor:020}.out"));
                match open_segment(&path, true) {
                    Ok(file) => {
                        self.open_segment = Some((path.clone(), file));
                        self.segments.push_back(Segment {
                            start: cursor,
                            len: 0,
                            path,
                            started_at_ms: now_ms,
                            written_at_ms: now_ms,
                            sealed: false,
                            uncertain: 0,
                        });
                    }
                    Err(error) => {
                        self.suspend(
                            cursor,
                            format!(
                                "segment {} could not be opened: {error}",
                                segment_name(&path)
                            ),
                            true,
                            false,
                        );
                        break;
                    }
                }
            }
            if let Err(failed) = self.write_newest(&bytes[written..written + take]) {
                self.suspend(cursor + failed.kept, failed.reason, failed.resumable, false);
                break;
            }
            written += take;
        }
        evicted
    }

    /// Writes bytes at the end of the newest segment, and counts them once they are there.
    fn write_newest(&mut self, bytes: &[u8]) -> std::result::Result<(), WriteFailure> {
        let Some(segment) = self.segments.back() else {
            return Err(WriteFailure {
                kept: 0,
                reason: "no segment was open to write into".to_owned(),
                resumable: true,
            });
        };
        let path = segment.path.clone();
        let counted = segment.len;
        // A segment that holds bytes is opened again only where it still is. Creating it again
        // would put the next bytes at the start of an empty file, where a reader of the cursors
        // the index gives the segment would find them in place of what was there.
        let holds_bytes = counted > 0 || segment.uncertain > 0;
        // Borrowed separately from the segment, because the handle lives beside the index rather
        // than inside it: a segment that is evicted takes its entry, not this handle.
        let handle = match self.open_segment.as_mut() {
            Some((open, file)) if *open == path => file,
            _ => match open_segment(&path, !holds_bytes) {
                Ok(file) => {
                    self.open_segment = Some((path.clone(), file));
                    &mut self
                        .open_segment
                        .as_mut()
                        .expect("the handle was just installed")
                        .1
                }
                Err(error) => {
                    return Err(WriteFailure {
                        kept: 0,
                        reason: format!(
                            "segment {} could not be opened: {error}",
                            segment_name(&path)
                        ),
                        resumable: true,
                    });
                }
            },
        };
        #[cfg(test)]
        let written = match self.short_write.take() {
            Some(keep) => append_open(handle, &bytes[..keep.min(bytes.len())])
                .and_then(|()| Err(std::io::Error::other("the write stopped part way"))),
            None => append_open(handle, bytes),
        };
        #[cfg(not(test))]
        let written = append_open(handle, bytes);
        if let Err(error) = written {
            let reason = format!(
                "segment {} could not be written: {error}",
                segment_name(&path)
            );
            return Err(self.settle_failed_write(counted, bytes.len() as u64, reason));
        }
        let segment = self.segments.back_mut().expect("a segment exists");
        segment.len += bytes.len() as u64;
        self.boundary = self.boundary.max(segment.end());
        // The newest byte's time, not the oldest: a segment is past its retention only when
        // everything in it is, which is the direction that cannot delete output too early.
        segment.written_at_ms = kr_ipc::now_ms().get();
        self.total_bytes += bytes.len() as u64;
        self.peak_bytes = self.peak_bytes.max(self.total_bytes);
        Ok(())
    }

    /// Settles a write that failed part way, so that the index and the file agree again.
    ///
    /// The file is cut back to what the index counts, and the cut is checked. Where it cannot be
    /// made, the file's own length says how many of the bytes it holds, and those are counted: a
    /// write lays its bytes down in order, so what reached the file is the start of them, at the
    /// cursors the index expects. Where neither answers, the whole piece is counted as possibly
    /// there and the spool writes nothing more. Either way the segment takes no further bytes, and
    /// one that holds none leaves the index.
    fn settle_failed_write(
        &mut self,
        counted: u64,
        attempted: u64,
        reason: String,
    ) -> WriteFailure {
        #[cfg(test)]
        let may_cut = !self.refuse_cut;
        #[cfg(not(test))]
        let may_cut = true;
        let (kept, uncertain) = match self.open_segment.as_ref() {
            Some((path, _)) if may_cut && cut_back(path, counted) => (0, 0),
            Some((_, file)) => match file.metadata() {
                Ok(metadata) => (metadata.len().saturating_sub(counted).min(attempted), 0),
                Err(_) => (0, attempted),
            },
            None => (0, attempted),
        };
        self.open_segment = None;
        let segment = self.segments.back_mut().expect("the segment being written");
        segment.sealed = true;
        segment.len += kept;
        segment.uncertain += uncertain;
        let end = segment.end();
        let empty = segment.len == 0 && segment.uncertain == 0;
        self.total_bytes += kept + uncertain;
        self.peak_bytes = self.peak_bytes.max(self.total_bytes);
        self.boundary = self.boundary.max(end);
        if empty {
            // Nothing of it is on the disk, so the next segment to start at this cursor is the only
            // entry that names its file.
            if let Some(gone) = self.segments.pop_back() {
                let _ = std::fs::remove_file(&gone.path);
            }
        }
        let resumable = uncertain == 0;
        WriteFailure {
            kept,
            reason: if resumable {
                reason
            } else {
                format!("{reason}, and how much of it reached the file could not be read back")
            },
            resumable,
        }
    }

    /// Gives up the oldest segments until `needed` more bytes fit within the capacity.
    ///
    /// The boundary is published before the first segment goes, as every eviction publishes it.
    /// `keep_newest` keeps the segment the bytes are about to be written into. Returns the range
    /// that went, and why the room could not be made when it could not: a boundary that could not
    /// be written, or a segment that could not be removed and is still counted. What went before a
    /// failure is still returned, so a reader is told which bound took it.
    fn make_room(
        &mut self,
        needed: u64,
        keep_newest: bool,
        cursor: u64,
    ) -> (Option<(u64, u64, u64)>, Option<NoRoom>) {
        if self.total_bytes.saturating_add(needed) <= self.layout.capacity_bytes {
            return (None, None);
        }
        if !self.record_boundary() {
            return (
                None,
                Some(NoRoom {
                    reason: "this session's spool boundary could not be written, so nothing was \
                             removed to make room"
                        .to_owned(),
                    boundary: true,
                }),
            );
        }
        let from = self.oldest_cursor().unwrap_or(cursor);
        let mut gone = 0;
        let mut failure = None;
        while self.total_bytes.saturating_add(needed) > self.layout.capacity_bytes {
            if self.segments.is_empty() || (keep_newest && self.segments.len() == 1) {
                failure = Some(NoRoom {
                    reason: format!(
                        "{needed} bytes do not fit within this session's spool capacity of {} \
                         bytes",
                        self.layout.capacity_bytes
                    ),
                    boundary: false,
                });
                break;
            }
            match self.drop_oldest() {
                Ok(went) => gone += went,
                Err(reason) => {
                    failure = Some(NoRoom {
                        reason,
                        boundary: false,
                    });
                    break;
                }
            }
        }
        let made = (gone > 0).then(|| (from, self.oldest_cursor().unwrap_or(cursor), gone));
        (made, failure)
    }

    /// Stops taking output at `at`, for `reason`, unless it has already stopped.
    ///
    /// The first stop is the one kept, because it is where the output this spool did not take
    /// begins.
    fn suspend(&mut self, at: u64, reason: String, resumable: bool, boundary: bool) {
        if self.suspended.is_none() {
            self.suspended = Some(Suspension {
                at,
                reason,
                resumable,
                boundary,
            });
        }
    }

    /// Whether what stops the spool now is a boundary that could not be written.
    fn awaits_boundary(&self) -> bool {
        self.suspended
            .as_ref()
            .is_some_and(|suspension| suspension.boundary)
    }

    /// Returns the first cursor this spool did not take, while it has stopped.
    fn suspended_at(&self) -> Option<u64> {
        self.suspended.as_ref().map(|suspension| suspension.at)
    }

    /// Returns where this spool stopped taking output, and why.
    fn suspension(&self) -> Option<(u64, &str)> {
        self.suspended
            .as_ref()
            .map(|suspension| (suspension.at, suspension.reason.as_str()))
    }

    /// Takes output again, because nothing it held is left to be owed anything.
    fn clear_suspension(&mut self) {
        self.suspended = None;
    }

    /// Takes output again from `from`, writing `pending` there first, when it can.
    ///
    /// Room is made for what is pending, and for at least one byte, before anything is written,
    /// so a spool whose oldest segment still cannot be removed stays stopped where it first
    /// stopped rather than stopping again at the next append. A write that stops part way keeps
    /// what it wrote: the spool stops again at the first cursor it did not take, and the next
    /// attempt starts there, never before it, so no byte is written twice. Returns where that left
    /// the spool, and the range it gave up to make room, whatever it came to.
    fn resume(&mut self, from: u64, pending: &[u8]) -> (Resumption, Option<(u64, u64, u64)>) {
        let Some(held) = self.suspended.take() else {
            return (Resumption::Taking, None);
        };
        if !held.resumable {
            self.suspended = Some(held);
            return (Resumption::Stopped, None);
        }
        let (made, failure) = self.make_room((pending.len() as u64).max(1), false, from);
        if let Some(no_room) = failure {
            // Still stopped where it first stopped, and for what it has found this time: an append
            // tries the boundary again, and only a retention pass tries anything else.
            self.suspended = Some(Suspension {
                reason: no_room.reason,
                boundary: no_room.boundary,
                ..held
            });
            return (Resumption::Stopped, made);
        }
        let written = self.append(from, pending);
        let evicted = joined(made, written);
        if self.suspended.is_some() {
            return (Resumption::StoppedLater, evicted);
        }
        (Resumption::Taking, evicted)
    }

    /// Removes the oldest segment and returns how many bytes went.
    ///
    /// The boundary is on disk before this is called, because the segment being deleted is part
    /// of what says where the output got to: a crash between the delete and the write would put
    /// the spool back in the condition the boundary exists to prevent.
    ///
    /// A file this host could not remove stays in the accounting, and the refusal names it.
    /// Dropping the entry while the bytes were still on disk would make the spool report less than
    /// it holds, and the next capacity pass would then delete something it did not need to.
    fn drop_oldest(&mut self) -> std::result::Result<u64, String> {
        let Some(segment) = self.segments.front().cloned() else {
            return Ok(0);
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
            Err(error) => {
                return Err(format!(
                    "segment {} could not be removed: {error}",
                    segment_name(&segment.path)
                ));
            }
        }
        self.segments.pop_front();
        let went = segment.len + segment.uncertain;
        self.total_bytes -= went;
        Ok(went)
    }

    /// Writes the position down when only memory holds it, and says whether the record is current.
    ///
    /// While the spool takes everything its newest segment says where the output reached, so
    /// nothing is written then. Output the spool did not take - privacy mode's, or a stopped
    /// spool's - moves the position past it, and the record written here is what lets a spool
    /// reopened over this directory continue from there.
    fn publish_position(&mut self) -> bool {
        let shown = self
            .published
            .max(self.segments.back().map_or(0, Segment::end));
        if self.boundary <= shown {
            return true;
        }
        self.record_boundary()
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
        self.published = boundary;
        true
    }

    /// Removes the segments that are entirely past the retention period, and says what it could
    /// not remove.
    ///
    /// Retention runs between appends rather than inside one, so it may take every segment: the
    /// next append starts a new one, and what stays readable meanwhile is the resident window.
    /// The room an append makes keeps its own guard, because there the newest segment is the one
    /// being written to.
    fn drop_older_than(&mut self, expires_before: u64) -> (u64, Option<String>) {
        if self
            .segments
            .front()
            .is_none_or(|segment| segment.written_at_ms >= expires_before)
        {
            return (0, None);
        }
        if !self.record_boundary() {
            // The boundary could not be published, so nothing that supports it is deleted.
            return (0, Some(BOUNDARY_UNWRITTEN.to_owned()));
        }
        let mut dropped = 0;
        while self
            .segments
            .front()
            .is_some_and(|segment| segment.written_at_ms < expires_before)
        {
            match self.drop_oldest() {
                Ok(went) => dropped += went,
                Err(reason) => return (dropped, Some(reason)),
            }
        }
        (dropped, None)
    }

    /// Removes the oldest segments until at least `bytes` have gone, and says what it could not
    /// remove.
    fn drop_at_least(&mut self, bytes: u64) -> (u64, Option<String>) {
        if bytes == 0 || self.segments.is_empty() {
            return (0, None);
        }
        if !self.record_boundary() {
            // The boundary could not be published, so nothing that supports it is deleted.
            return (0, Some(BOUNDARY_UNWRITTEN.to_owned()));
        }
        let mut dropped = 0;
        while dropped < bytes && !self.segments.is_empty() {
            match self.drop_oldest() {
                Ok(went) => dropped += went,
                Err(reason) => return (dropped, Some(reason)),
            }
        }
        (dropped, None)
    }

    /// Returns when the oldest retained segment was last written.
    fn oldest_written_at_ms(&self) -> Option<u64> {
        self.segments.front().map(|segment| segment.written_at_ms)
    }

    /// Reads what the spool holds from `start`, up to `wanted` bytes and never past `end`.
    ///
    /// It stops at the first range it does not hold, so one page never carries bytes from both
    /// sides of a hole as though they were one run. A cursor inside such a range is answered with
    /// where the range ends: the next segment the index has, or `end`. A segment whose file has
    /// gone from under the index, or holds less than the index says, is a range it does not hold.
    fn read_at(&self, start: u64, wanted: usize, end: u64) -> Result<Held> {
        let Some(first) = self
            .segments
            .iter()
            .position(|segment| start >= segment.start && start < segment.end())
        else {
            let to = self
                .segments
                .iter()
                .map(|segment| segment.start)
                .find(|&next| next > start)
                .map_or(end, |next| next.min(end));
            return Ok(Held::Missing { to });
        };
        let mut out = Vec::with_capacity(wanted);
        let mut cursor = start;
        let mut at = first;
        while out.len() < wanted && cursor < end {
            // The next segment continues this run only when it starts where the last one ended.
            let Some(segment) = self
                .segments
                .get(at)
                .filter(|segment| cursor >= segment.start && cursor < segment.end())
            else {
                break;
            };
            let offset = cursor - segment.start;
            let take = (segment.len - offset)
                .min((wanted - out.len()) as u64)
                .min(end - cursor);
            let chunk = match read_file_range(&segment.path, offset, take) {
                Ok(chunk) => chunk,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(WorkerError::storage("read an output spool segment", error));
                }
            };
            cursor += chunk.len() as u64;
            out.extend_from_slice(&chunk);
            if (chunk.len() as u64) < take {
                break;
            }
            at += 1;
        }
        if out.is_empty() {
            let segment = &self.segments[first];
            return Ok(Held::Missing {
                to: segment.end().min(end),
            });
        }
        Ok(Held::Bytes(out))
    }

    /// Returns the ranges from the oldest segment up to `until` that no segment covers.
    ///
    /// The end is the boundary this spool reached, which is what makes a newest segment that has
    /// gone a range rather than a spool that simply ended earlier.
    fn uncovered(&self, until: u64) -> Vec<(u64, u64)> {
        let mut holes = Vec::new();
        let Some(first) = self.segments.front() else {
            return holes;
        };
        let mut reached = first.start;
        for segment in &self.segments {
            if segment.start >= until {
                break;
            }
            if segment.start > reached {
                holes.push((reached, segment.start));
            }
            reached = reached.max(segment.end());
        }
        let end = self.next_cursor().min(until);
        if reached < end {
            holes.push((reached, end));
        }
        holes
    }

    /// Returns how many bytes of the cursors from `from` to `to` the segments hold.
    fn covered(&self, from: u64, to: u64) -> u64 {
        self.segments
            .iter()
            .map(|segment| {
                segment
                    .end()
                    .min(to)
                    .saturating_sub(segment.start.max(from))
            })
            .sum()
    }

    /// Forgets the segments whose files have gone.
    ///
    /// A file that went from under the index is a range this host no longer holds, and counting it
    /// would make the session look larger than it is: the next capacity pass would evict output it
    /// did not need to. The range reads as a hole afterwards, as it did to any reader that reached
    /// it before. The newest segment is no exception, and the handle it is written through goes
    /// first: where the platform keeps a removed file until its last handle closes, as Windows
    /// does, the file is still there while this spool holds it open, and would be counted as held.
    /// The next write opens the newest segment again, and only where it still is; one that has gone
    /// is forgotten here, and the next byte starts a new segment.
    fn forget_vanished(&mut self) {
        self.open_segment = None;
        let mut kept = 0;
        self.segments.retain(|segment| {
            let gone = matches!(
                std::fs::symlink_metadata(&segment.path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            );
            if !gone {
                kept += segment.len + segment.uncertain;
            }
            !gone
        });
        self.total_bytes = kept;
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

/// Writes the boundary down, replacing it in one step, and says whether it is published.
///
/// The temporary file and the rename are what make it one step: a crash during the write leaves
/// either the previous boundary or the new one, never half of either.
///
/// The answer matters. A full disk can refuse this write and still allow the deletions that
/// follow it, and a spool that deleted its segments over an unpublished boundary would come back
/// from a restart with no record of where its output had reached. So the answer is returned, and
/// the caller does not delete what the boundary describes until it is true.
///
/// The rename is made once and never waited for, although on Windows another program can hold the
/// boundary for a moment and refuse it: this runs on the session's output path, under the
/// session's lock, which must not pause. A refusal keeps every segment, and the next pass writes
/// the boundary again.
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

/// Opens a segment to append to it, creating it only when `create` says so.
fn open_segment(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(create)
        .append(true)
        .open(path)
}

/// Cuts a segment back to `len` bytes, and says whether its file now holds exactly that many.
///
/// It opens a handle of its own to do it: the one the spool appends through may add to a file
/// and not shorten it, which is what a Windows handle opened to append is.
fn cut_back(path: &Path, len: u64) -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| {
            file.set_len(len)?;
            file.metadata()
        })
        .is_ok_and(|metadata| metadata.len() == len)
}

fn append_open(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    file.write_all(bytes)
}

/// Names a segment by its file, which is what a person looking at the spool directory sees.
fn segment_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Reads up to `len` bytes of a segment from `offset`, fewer only where the file ends.
fn read_file_range(path: &Path, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(len).read_to_end(&mut buffer)?;
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

    /// On Windows a boundary file that another program holds without sharing its deletion, as a
    /// scanner holds a file it has just seen written, is not waited for on the output path. The
    /// append that needs an eviction returns at once and keeps every segment, since nothing may go
    /// before the boundary that accounts for it is written, and the first append after that
    /// program lets go writes the boundary and evicts.
    #[cfg(windows)]
    #[test]
    fn a_held_boundary_leaves_the_eviction_to_a_later_append_without_waiting() {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// Reading and writing are shared; deleting is not.
        const FILE_SHARE_READ_WRITE: u32 = 0x0001 | 0x0002;

        let directory = spool_directory("held-boundary");
        let mut history = OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 16))
            .expect("opens a spool");
        for _ in 0..4 {
            history.append(&[b'z'; 8]);
        }
        let boundary = directory.join(BOUNDARY_FILE);
        assert!(boundary.is_file(), "an eviction wrote the boundary");
        let oldest = history.oldest_retained_cursor();
        let holding = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(&boundary)
            .expect("the boundary is held");
        let started = std::time::Instant::now();
        history.append(&[b'z'; 8]);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(1),
            "the output path does not wait for the boundary: {took:?}"
        );
        assert_eq!(
            history.oldest_retained_cursor(),
            oldest,
            "nothing goes while its boundary cannot be written"
        );
        drop(holding);
        history.append(&[b'z'; 8]);
        assert!(
            history.oldest_retained_cursor() > oldest,
            "the next append writes the boundary and evicts"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    /// A spool's boundary file held out of its reach, as another program holds it: on Windows by an
    /// open handle that shares reading and writing but not deletion, as a scanner holds a file it
    /// has just seen written, and elsewhere by a directory in its place, which no file can be
    /// renamed over. Letting go gives the name back.
    struct HeldBoundary {
        #[cfg(windows)]
        handle: std::fs::File,
        #[cfg(not(windows))]
        path: std::path::PathBuf,
    }

    impl HeldBoundary {
        #[cfg(windows)]
        fn take(path: &std::path::Path) -> Self {
            use std::os::windows::fs::OpenOptionsExt as _;

            /// Reading and writing are shared; deleting is not.
            const FILE_SHARE_READ_WRITE: u32 = 0x0001 | 0x0002;

            let handle = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ_WRITE)
                .open(path)
                .expect("the boundary is held");
            Self { handle }
        }

        #[cfg(not(windows))]
        fn take(path: &std::path::Path) -> Self {
            std::fs::remove_file(path).expect("takes the boundary's file away");
            std::fs::create_dir(path).expect("puts a directory in its place");
            Self {
                path: path.to_owned(),
            }
        }

        #[cfg(windows)]
        fn let_go(self) {
            drop(self.handle);
        }

        #[cfg(not(windows))]
        fn let_go(self) {
            std::fs::remove_dir(&self.path).expect("gives the name back");
        }
    }

    /// A boundary that stays held across several appends stops nothing on the output path and
    /// leaves the cap where it is, and the first append after it is let go writes it and gives up
    /// what the cap needs. Where the test above lets go after one append, this holds it across two,
    /// which is what a stopped spool has to survive without taking the next append's bytes for its
    /// own or waiting for the file.
    #[test]
    fn a_boundary_held_across_appends_is_written_by_the_first_append_after_it_is_let_go() {
        let directory = spool_directory("held-boundary-across");
        let mut history = OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 16))
            .expect("opens a spool");
        // Each append has bytes of its own, so what is read back says which append it came from.
        for byte in *b"abcd" {
            history.append(&[byte; 8]);
        }
        let boundary = directory.join(BOUNDARY_FILE);
        assert!(boundary.is_file(), "an eviction wrote the boundary");
        let oldest = history.oldest_retained_cursor();
        assert_eq!(history.retained_bytes(), 16);
        let held = HeldBoundary::take(&boundary);
        for byte in *b"ef" {
            let started = std::time::Instant::now();
            history.append(&[byte; 8]);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(1),
                "the output path does not wait for the boundary: {took:?}"
            );
            assert_eq!(
                history.oldest_retained_cursor(),
                oldest,
                "nothing goes while its boundary cannot be written"
            );
            assert_eq!(history.retained_bytes(), 16, "and the cap holds meanwhile");
            assert_eq!(
                history.suspended().map(|(at, _)| at),
                Some(32),
                "the spool stopped at the first cursor it did not take, and stays there"
            );
        }
        held.let_go();
        history.append(&[b'g'; 8]);
        assert!(
            history.oldest_retained_cursor() > oldest,
            "the first append after the boundary is let go writes it and evicts"
        );
        assert!(
            history.suspended().is_none(),
            "and the spool takes output again"
        );
        assert!(history.retained_bytes() <= 16, "the cap holds");
        assert_eq!(
            read_boundary(&directory),
            RecordedBoundary::At(48),
            "the boundary says where the output had reached when it was written"
        );
        // What the spool could not take while the boundary was held is a gap that says why and
        // ends where the spool took output again, and what follows it is the append that did.
        let (gap, bytes) = read_to_end(&history, 32);
        let gap = gap.expect("the range the stopped spool did not take is a gap");
        assert_eq!(
            (gap.from_cursor.get(), gap.to_cursor.get()),
            (32, 48),
            "the two appends made while the boundary was held"
        );
        assert_eq!(gap.cause, Some(HistoryGapCause::SpoolUnavailable));
        assert_eq!(bytes, [b'g'; 8]);
        // What it gave up when it could is one range that names the cap, and what is left is the
        // newest segment it held and the one it wrote.
        let taken = history.evictions();
        let last = taken.last().expect("the eviction was recorded");
        assert_eq!(
            (last.limit, last.from_cursor, last.bytes),
            (RetentionLimit::SessionCap, oldest, 8)
        );
        let (given_up, kept) = read_to_end(&history, oldest);
        assert_eq!(
            given_up.map(|gap| (gap.from_cursor.get(), gap.to_cursor.get())),
            Some((oldest, oldest + 8)),
            "the segment given up is a gap"
        );
        assert_eq!(
            kept,
            [[b'd'; 8], [b'g'; 8]].concat(),
            "and what is served is the newest segment it held and the one it wrote"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    /// A spool stopped for want of its boundary is tried again by the next append only while it is
    /// the boundary that stops it. When the boundary is written and the oldest segment then cannot
    /// be removed, the stop is a segment's, which waits for a retention pass: the appends that
    /// follow neither try it again nor let the spool take output before the pass does.
    #[test]
    fn a_stop_that_moves_from_the_boundary_to_a_segment_waits_for_a_retention_pass() {
        let directory = spool_directory("held-boundary-then-segment");
        let mut history = OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 16))
            .expect("opens a spool");
        for byte in *b"abcd" {
            history.append(&[byte; 8]);
        }
        let boundary = directory.join(BOUNDARY_FILE);
        let oldest = history.oldest_retained_cursor();
        let held = HeldBoundary::take(&boundary);
        history.append(&[b'e'; 8]);
        assert_eq!(history.suspended().map(|(at, _)| at), Some(32));
        held.let_go();
        // The boundary can be written now, but the oldest segment cannot be removed: a directory
        // with something in it stands where its file was, so no platform removes it as a file.
        let segment = directory.join(format!("{oldest:020}.out"));
        std::fs::remove_file(&segment).expect("takes the oldest segment's file away");
        std::fs::create_dir(&segment).expect("puts a directory in its place");
        std::fs::write(segment.join("in-the-way"), b"x").expect("and something in it");
        history.append(&[b'f'; 8]);
        assert_eq!(
            read_boundary(&directory),
            RecordedBoundary::At(40),
            "the append wrote the boundary that was let go"
        );
        assert_eq!(
            history.suspended().map(|(at, _)| at),
            Some(32),
            "and the spool is still stopped where it stopped, for the segment now"
        );
        assert!(
            history
                .suspended()
                .is_some_and(|(_, reason)| reason.contains("could not be removed")),
            "and says so: {:?}",
            history.suspended()
        );
        assert_eq!(history.oldest_retained_cursor(), oldest);
        // The way is clear, and the next append does not take it: only a retention pass does.
        std::fs::remove_dir_all(&segment).expect("clears the way");
        history.append(&[b'g'; 8]);
        assert_eq!(
            history.suspended().map(|(at, _)| at),
            Some(32),
            "a stop that is not the boundary's is left to a retention pass"
        );
        history.apply_retention(
            OutputRetention::DEFAULT,
            history.retained_bytes(),
            kr_ipc::now_ms(),
            true,
        );
        assert!(
            history.suspended().is_none(),
            "the pass lets the spool take output again"
        );
        assert!(history.retained_bytes() <= 16, "the cap holds");
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

    /// Reads everything a spool directory holds from `from`, as a reader opening it would.
    fn read_back(directory: &std::path::Path, from: u64) -> (Option<HistoryGap>, Vec<u8>) {
        let reopened =
            OutputHistory::read_spool(directory, SpoolLayout::DEFAULT).expect("reads the spool");
        read_to_end(&reopened, from)
    }

    /// Reads a history from `from` to its end, page by page: the first gap it reports and the
    /// bytes it serves.
    fn read_to_end(history: &OutputHistory, from: u64) -> (Option<HistoryGap>, Vec<u8>) {
        let mut cursor = from;
        let mut gap = None;
        let mut bytes = Vec::new();
        while cursor < history.next_cursor() {
            let page = history.page(cursor, 64).expect("a page");
            gap = gap.or(page.gap.0);
            bytes.extend_from_slice(page.bytes.as_slice());
            assert!(
                page.next_cursor.get() > cursor,
                "every page moves the reader on"
            );
            cursor = page.next_cursor.get();
        }
        (gap, bytes)
    }

    #[test]
    fn a_write_that_stops_part_way_is_cut_back_and_the_spool_goes_on_from_there() {
        // The file is cut back to what the index counts, so the index and the file agree, and
        // the next pass writes the rest from the resident window into a new segment.
        let directory = spool_directory("short-write-cut");
        let mut history =
            OutputHistory::with_spool(64, directory.clone(), SpoolLayout::new(8, 1 << 20))
                .expect("a spool");
        history.append(b"abcd");
        history.spool.as_mut().expect("a spool").short_write = Some(2);
        history.append(b"efgh");
        assert_eq!(history.suspended().map(|(at, _)| at), Some(4));
        assert_eq!(history.spool.as_ref().expect("a spool").total_bytes, 4);
        history.apply_retention(OutputRetention::DEFAULT, 8, kr_ipc::now_ms(), true);
        assert!(
            history.suspended().is_none(),
            "the next pass lets it take output again"
        );
        history.append(b"ij");
        let (gap, bytes) = read_back(&directory, 0);
        assert!(gap.is_none(), "{gap:?}");
        assert_eq!(bytes, b"abcdefghij", "every byte once, and in its place");
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_write_that_stops_part_way_and_cannot_be_cut_back_counts_what_the_file_holds() {
        // Where the file cannot be cut back, its own length says how much of the write reached
        // it: those bytes are the start of the write, at the cursors the index expects, so they
        // are counted, and the spool goes on after them rather than writing them again.
        let directory = spool_directory("short-write-kept");
        let mut history =
            OutputHistory::with_spool(64, directory.clone(), SpoolLayout::new(8, 1 << 20))
                .expect("a spool");
        history.append(b"abcd");
        {
            let spool = history.spool.as_mut().expect("a spool");
            spool.short_write = Some(2);
            spool.refuse_cut = true;
        }
        history.append(b"efgh");
        assert_eq!(
            history.suspended().map(|(at, _)| at),
            Some(6),
            "it stopped after the bytes the file holds"
        );
        assert_eq!(history.spool.as_ref().expect("a spool").total_bytes, 6);
        history.apply_retention(OutputRetention::DEFAULT, 8, kr_ipc::now_ms(), true);
        assert!(history.suspended().is_none());
        history.append(b"ij");
        let (gap, bytes) = read_back(&directory, 0);
        assert!(gap.is_none(), "{gap:?}");
        assert_eq!(bytes, b"abcdefghij", "every byte once, and in its place");
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn output_that_is_not_kept_leaves_no_bytes_at_the_wrong_cursors() {
        // The resident window ends where the output does. Output privacy mode does not keep moves
        // that end on, so the window is emptied rather than left holding bytes that would then be
        // read as the output at cursors they were never written at.
        let mut history = OutputHistory::in_memory(64);
        history.append(b"kept");
        history.stop_retaining();
        history.append(b"private");
        history.resume_retaining();
        history.append(b"after");
        assert_eq!(history.next_cursor(), 16);
        let page = history.page(0, 64).expect("a page");
        assert_eq!(page.from_cursor.get(), 11);
        assert_eq!(page.bytes.as_slice(), b"after");
        let gap = page.gap.0.expect("what was not kept is a gap");
        assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (0, 11));
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
