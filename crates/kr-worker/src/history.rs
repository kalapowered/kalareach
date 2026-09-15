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

use kr_protocol::recovery::{HistoryGap, HistoryPageResult, MAX_HISTORY_PAGE_BYTES};
use kr_protocol::scalars::{Bytes, Nullable, U64};

use crate::error::{Result, WorkerError};

/// The resident history cache of one session, in bytes.
pub const DEFAULT_RESIDENT_BYTES: usize = 8 * 1024 * 1024;

/// How a session's spool is laid out on disk.
///
/// Eviction works in whole segments, so the segment size decides how coarse the retained boundary
/// is: a smaller segment loses less history when the bound is reached, and a larger one keeps the
/// directory small. The default keeps at most 32 segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolLayout {
    /// Bytes one segment holds before the next one starts.
    pub segment_bytes: u64,
    /// The bound on the whole spool.
    pub capacity_bytes: u64,
}

impl SpoolLayout {
    /// The layout a session uses unless it is configured otherwise.
    pub const DEFAULT: Self = Self {
        segment_bytes: 8 * 1024 * 1024,
        capacity_bytes: 256 * 1024 * 1024,
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
        }
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
    #[must_use]
    pub fn oldest_retained_cursor(&self) -> u64 {
        match &self.spool {
            Some(spool) => spool.oldest_cursor().unwrap_or(self.resident_start),
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
        if let Some(spool) = self.spool.as_mut()
            && spool.append(start, bytes).is_err()
        {
            // Losing the spool costs history, not correctness: the resident window still serves
            // recent output and everything older reads as an explicit gap.
            self.spool = None;
        }
        self.resident.extend(bytes.iter().copied());
        self.next_cursor += bytes.len() as u64;
        while self.resident.len() > self.resident_capacity {
            let excess = self.resident.len() - self.resident_capacity;
            self.resident.drain(..excess);
            self.resident_start += excess as u64;
        }
        start
    }

    /// Reads one page of retained output.
    ///
    /// # Errors
    ///
    /// Returns an error when a spool segment cannot be read.
    pub fn page(&self, from_cursor: u64, max_bytes: u64) -> Result<HistoryPageResult> {
        let oldest = self.oldest_retained_cursor();
        let limit = max_bytes.clamp(1, MAX_HISTORY_PAGE_BYTES);
        let (start, gap) = if from_cursor < oldest {
            (
                oldest,
                Some(HistoryGap {
                    from_cursor: U64::new(from_cursor),
                    to_cursor: U64::new(oldest),
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

/// Fixed-size segment files holding output older than the resident window.
#[derive(Debug)]
struct Spool {
    directory: PathBuf,
    layout: SpoolLayout,
    segments: VecDeque<Segment>,
    total_bytes: u64,
}

#[derive(Clone, Debug)]
struct Segment {
    start: u64,
    len: u64,
    path: PathBuf,
}

impl Spool {
    fn open(directory: PathBuf, layout: SpoolLayout) -> Result<Self> {
        std::fs::create_dir_all(&directory)
            .map_err(|error| WorkerError::storage("create the output spool", error))?;
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
            let len = entry
                .metadata()
                .map_err(|error| WorkerError::storage("read the output spool", error))?
                .len();
            segments.push(Segment { start, len, path });
        }
        segments.sort_by_key(|segment| segment.start);
        let total_bytes = segments.iter().map(|segment| segment.len).sum();
        Ok(Self {
            directory,
            layout,
            segments: segments.into(),
            total_bytes,
        })
    }

    fn next_cursor(&self) -> u64 {
        self.segments
            .back()
            .map_or(0, |segment| segment.start + segment.len)
    }

    fn oldest_cursor(&self) -> Option<u64> {
        self.segments.front().map(|segment| segment.start)
    }

    fn append(&mut self, start: u64, bytes: &[u8]) -> Result<()> {
        let mut written = 0_usize;
        while written < bytes.len() {
            let needs_new_segment = self
                .segments
                .back()
                .is_none_or(|segment| segment.len >= self.layout.segment_bytes);
            if needs_new_segment {
                let segment_start = start + written as u64;
                self.segments.push_back(Segment {
                    start: segment_start,
                    len: 0,
                    path: self.directory.join(format!("{segment_start:020}.out")),
                });
            }
            let segment_bytes = self.layout.segment_bytes;
            let segment = self.segments.back_mut().expect("a segment exists");
            let room = usize::try_from(segment_bytes - segment.len).unwrap_or(usize::MAX);
            let take = room.min(bytes.len() - written);
            append_file(&segment.path, &bytes[written..written + take])?;
            segment.len += take as u64;
            self.total_bytes += take as u64;
            written += take;
        }
        self.evict();
        Ok(())
    }

    fn evict(&mut self) {
        while self.total_bytes > self.layout.capacity_bytes && self.segments.len() > 1 {
            let Some(segment) = self.segments.pop_front() else {
                break;
            };
            self.total_bytes -= segment.len;
            let _ = std::fs::remove_file(&segment.path);
        }
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

fn append_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| WorkerError::storage("open an output spool segment", error))?;
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
}
