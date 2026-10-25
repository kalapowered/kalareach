//! Reading a release archive that is a `.zip`, which is how a release comes to a Windows host.
//!
//! The archive is parsed before any signature is checked: the manifest that is signed is inside it.
//! So what it can make this host do is bounded first, and nothing is written until every entry has
//! been looked at. An entry count and a size beyond what a release is are refused; so is every entry
//! that is not a file or a directory, that is encrypted or compressed in a way a release is not, that
//! is named twice, or whose name Windows would read as another ([`kr_ipc::install::names`]): an
//! absolute or drive path, a parent, a device, a stream, a name that ends in a dot, two names that
//! differ only in case. Then each file is read from the entry for no more than the entry says it
//! holds, so an entry that lies about its size writes no more than it declared.
//!
//! What the archive holds is then held to the manifest by [`super::release::check_files`], as the
//! files of a `.tar.gz` are.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_ipc::install::names::{NameFault, PathFault, PathRules};
use zip::{CompressionMethod, ZipArchive};

use super::release::{
    Written, create_directories, ensure_space, refused_archive, write_failure, write_new,
};
use crate::error::Result;

/// What an archive may hold: more than a release is made of, and not so much that reading it
/// exhausts the host.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The most entries, directories among them.
    pub entries: usize,
    /// The most bytes all the files hold together, as the entries say.
    pub total_bytes: u64,
    /// The most bytes one file holds, as its entry says.
    pub entry_bytes: u64,
    /// The most bytes the archive's directory of entries takes, which is read whole before any
    /// entry is looked at.
    pub directory_bytes: u64,
    /// The longest an entry's name may be, in bytes.
    pub name_bytes: usize,
    /// The most parts an entry's name may have.
    pub depth: usize,
}

impl Limits {
    /// A release holds a few hundred files and a few hundred megabytes: these are several times
    /// that.
    pub const DEFAULT: Self = Self {
        entries: 50_000,
        total_bytes: 8 * 1024 * 1024 * 1024,
        entry_bytes: 2 * 1024 * 1024 * 1024,
        directory_bytes: 64 * 1024 * 1024,
        name_bytes: 1024,
        depth: 32,
    };
}

/// One entry to be written, as the first look found it.
struct Planned {
    index: usize,
    relative: Vec<String>,
    directory: bool,
    size: u64,
}

/// Why a name breaks a rule, said without repeating the name, which came from the archive.
pub(super) const fn reason_of(fault: &PathFault) -> &'static str {
    match fault {
        PathFault::Component { fault, .. } => match fault {
            NameFault::Empty => "has an entry that is an absolute path or has an empty part",
            NameFault::DotName => {
                "has an entry that climbs out of the release or names a part Windows reads as another"
            }
            NameFault::ForbiddenCharacter => {
                "has an entry whose name Windows reads as a drive, a data stream or a separator, or holds a character no name holds"
            }
            NameFault::TrailingDotOrSpace => {
                "has an entry whose name ends in a dot or a space, which Windows removes"
            }
            NameFault::DeviceName => "has an entry named for a device",
            NameFault::TooLong => "has an entry whose name is longer than Windows keeps",
        },
        PathFault::Collides { .. } => "has two entries that Windows reads as one name",
        PathFault::FileAndDirectory { .. } => "has an entry that is both a file and a directory",
    }
}

/// Unpacks the `.zip` `file`, which was opened from `archive`, into `staging`, an owner-only
/// directory, and returns the release's directory in it and what was written.
///
/// Every entry is under one top directory, which is the release's directory; an entry is a file or a
/// directory and nothing else.
///
/// # Errors
///
/// Returns a refusal naming what is wrong with the archive, or the failure to read or write it.
pub fn unpack(
    file: std::fs::File,
    archive: &Path,
    staging: &Path,
    limits: &Limits,
) -> Result<(PathBuf, Written)> {
    let unreadable = |reason: &'static str| refused_archive(archive, reason);
    if !file.metadata().is_ok_and(|about| about.is_file()) {
        return Err(unreadable("is not a regular file"));
    }
    // The archive's end and its directory are read and judged here, before the parser is given
    // anything: the parser keeps every entry of the directory in memory and follows whatever end
    // record it finds, and the record is the last 22 bytes of the file or the archive is refused.
    let mut file = file;
    let tail = match read_tail(&mut file, limits).map_err(|_| unreadable(NOT_A_ZIP))? {
        Ok(tail) => tail,
        Err(reason) => return Err(unreadable(reason)),
    };
    // The parser sees the directory and the end record as they were judged and zeros everywhere
    // else, so that no other record can be found for it to follow; once it has its list of entries
    // it reads the file itself.
    let building = Arc::new(AtomicBool::new(true));
    let entries = tail.entries;
    let mut zipped = ZipArchive::new(Shown::new(file, tail, Arc::clone(&building)))
        .map_err(|_| unreadable(NOT_A_ZIP))?;
    building.store(false, Ordering::Release);
    // The reader keeps one entry for each name, the last of two that share one, so an archive that
    // names a file twice shows fewer entries than its directory declares.
    if zipped.len() as u64 != entries {
        return Err(unreadable("has the same name twice"));
    }

    // The first look: every entry is judged before anything is written.
    let mut rules = PathRules::new();
    let mut names = HashSet::new();
    let mut top: Option<String> = None;
    let mut planned = Vec::with_capacity(zipped.len());
    let mut total = 0_u64;
    for index in 0..zipped.len() {
        let member = zipped
            .by_index_raw(index)
            .map_err(|_| unreadable("has an entry this host cannot read"))?;
        if member.encrypted() {
            return Err(unreadable("has an encrypted entry"));
        }
        if member.is_symlink() {
            return Err(unreadable(
                "has an entry that is a link, which a release does not hold",
            ));
        }
        if let Some(mode) = member.unix_mode()
            && !matches!(mode & 0o170_000, 0 | 0o100_000 | 0o040_000)
        {
            return Err(unreadable(
                "has an entry that is neither a file nor a directory",
            ));
        }
        if !matches!(
            member.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(unreadable(
                "has an entry compressed in a way a release is not",
            ));
        }
        let name = member.name();
        let directory = name.ends_with('/');
        let name = name.strip_suffix('/').unwrap_or(name);
        // Before the rules, which keep every prefix of the name.
        if name.len() > limits.name_bytes {
            return Err(unreadable(
                "has an entry name longer than any a release has",
            ));
        }
        if name.split('/').count() > limits.depth {
            return Err(unreadable(
                "has an entry nested deeper than any a release is",
            ));
        }
        rules
            .admit(name, directory)
            .map_err(|fault| unreadable(reason_of(&fault)))?;
        if !names.insert(name.to_owned()) {
            return Err(unreadable("has the same name twice"));
        }
        let mut parts = name.split('/').map(str::to_owned);
        let entry_top = parts.next().unwrap_or_default();
        match &top {
            Some(top) if *top != entry_top => {
                return Err(unreadable("has entries under more than one top directory"));
            }
            Some(_) => {}
            None => top = Some(entry_top),
        }
        let relative: Vec<String> = parts.collect();
        if relative.is_empty() && !directory {
            return Err(unreadable("has a file where its top directory goes"));
        }
        let size = if directory { 0 } else { member.size() };
        if size > limits.entry_bytes {
            return Err(unreadable("has a file larger than any a release holds"));
        }
        total = total.saturating_add(size);
        if total > limits.total_bytes {
            return Err(unreadable("holds more bytes than a release does"));
        }
        planned.push(Planned {
            index,
            relative,
            directory,
            size,
        });
    }
    let top = top.ok_or_else(|| unreadable("is empty"))?;

    // Then each file is written, read for no more than its entry says it holds.
    let directory = staging.join(&top);
    let mut written = Written::new();
    for entry in &planned {
        let destination = entry
            .relative
            .iter()
            .fold(directory.clone(), |path, part| path.join(part));
        if entry.directory {
            create_directories(staging, &destination)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            create_directories(staging, parent)?;
        }
        ensure_space(staging, entry.size)?;
        let mut member = zipped
            .by_index(entry.index)
            .map_err(|_| unreadable("has an entry this host cannot read"))?;
        // No more than the entry says is written. A byte read past it, which writes nothing, shows
        // that the entry holds more than it says.
        let summary = write_new(&destination, &mut (&mut member).take(entry.size))
            .map_err(|error| write_failure(&destination, &error))?;
        let mut past = [0_u8; 1];
        let more = member
            .read(&mut past)
            .map_err(|_| unreadable("has an entry this host cannot read"))?;
        if summary.0 != entry.size || more != 0 {
            return Err(unreadable(
                "has an entry that does not hold the bytes it says",
            ));
        }
        written.insert(entry.relative.join("/"), summary);
    }
    Ok((directory, written))
}

/// What a release archive's end looks like, which the parser is shown and nothing else of the file
/// until it has its list of entries.
struct Tail {
    /// How long the file is.
    length: u64,
    /// Where the directory of entries starts.
    start: u64,
    /// The directory of entries and then the end record, which reach the end of the file.
    bytes: Vec<u8>,
    /// How many entries the directory holds.
    entries: u64,
}

/// What a refusal of the archive's shape says.
const NOT_A_ZIP: &str = "is not a zip archive this host reads";

/// The signatures of the end record, of its 64-bit form and of that form's locator.
const END_RECORDS: [[u8; 4]; 3] = [*b"PK\x05\x06", *b"PK\x06\x06", *b"PK\x06\x07"];

/// The most extra data an entry of the directory may carry. The packer writes none.
const EXTRA_BYTES: usize = 1024;

/// Reads the directory of entries and the end record from the tail of the file, and judges them
/// whole: the end record is the last 22 bytes of the file with no comment, names one disk and
/// counts and sizes that fit it (so no 64-bit record), and the directory is exactly the bytes
/// before it, which hold that many entries one after another, with a name and extra data within
/// bounds, no comment, and no end record or locator among them. The archive a release is packed
/// into has this shape; any other is refused, so the parser has one end record to follow and the
/// bytes it will read are the bytes judged here.
///
/// Returns the refusal where the archive is not of this shape, or beyond the limits.
fn read_tail(
    file: &mut std::fs::File,
    limits: &Limits,
) -> std::io::Result<std::result::Result<Tail, &'static str>> {
    let length = file.seek(SeekFrom::End(0))?;
    if length < 22 {
        return Ok(Err(NOT_A_ZIP));
    }
    let mut end = [0_u8; 22];
    file.seek(SeekFrom::Start(length - 22))?;
    file.read_exact(&mut end)?;
    let sixteen = |at: usize| u16::from_le_bytes([end[at], end[at + 1]]);
    let thirty_two =
        |at: usize| u32::from_le_bytes([end[at], end[at + 1], end[at + 2], end[at + 3]]);
    let (entries, size, start) = (sixteen(10), thirty_two(12), thirty_two(16));
    if end[..4] != END_RECORDS[0]
        || sixteen(4) != 0
        || sixteen(6) != 0
        || sixteen(8) != entries
        || sixteen(20) != 0
        || entries == u16::MAX
        || size == u32::MAX
        || start == u32::MAX
        || u64::from(start) + u64::from(size) != length - 22
    {
        return Ok(Err(NOT_A_ZIP));
    }
    if entries == 0 {
        return Ok(Err("is empty"));
    }
    if usize::from(entries) > limits.entries {
        return Ok(Err("holds more entries than a release does"));
    }
    if u64::from(size) > limits.directory_bytes {
        return Ok(Err("has a directory larger than any a release has"));
    }
    let mut bytes = vec![0_u8; usize::try_from(size).unwrap_or(0) + 22];
    file.seek(SeekFrom::Start(u64::from(start)))?;
    file.read_exact(&mut bytes[..usize::try_from(size).unwrap_or(0)])?;
    let directory = bytes.len() - 22;
    bytes[directory..].copy_from_slice(&end);
    let judged = &bytes[..directory];
    let mut at = 0_usize;
    for _ in 0..entries {
        let Some(header) = judged.get(at..at + 46) else {
            return Ok(Err(NOT_A_ZIP));
        };
        let field = |from: usize| usize::from(u16::from_le_bytes([header[from], header[from + 1]]));
        let (name, extra, comment, disk) = (field(28), field(30), field(32), field(34));
        if header[..4] != *b"PK\x01\x02" || comment != 0 || disk != 0 || extra > EXTRA_BYTES {
            return Ok(Err(NOT_A_ZIP));
        }
        if name > limits.name_bytes {
            return Ok(Err("has an entry name longer than any a release has"));
        }
        at += 46 + name + extra;
    }
    // The entries tile the directory, and nothing in it or at its edge is an end record.
    let edge: Vec<u8> = judged[directory.saturating_sub(3)..]
        .iter()
        .chain(&end[..3])
        .copied()
        .collect();
    let named = |window: &[u8]| END_RECORDS.iter().any(|record| record == window);
    if at != directory
        || judged.windows(4).any(named)
        || edge.windows(4).take(directory.min(3)).any(named)
    {
        return Ok(Err(NOT_A_ZIP));
    }
    Ok(Ok(Tail {
        length,
        start: u64::from(start),
        bytes,
        entries: u64::from(entries),
    }))
}

/// The archive as the parser is shown it while it builds its list of entries: the directory and the
/// end record where they are, zeros before them, and the end of the file where it is. When the
/// list is built the file itself is read.
struct Shown {
    file: std::io::BufReader<std::fs::File>,
    tail: Tail,
    /// Whether the list of entries is still being built.
    building: Arc<AtomicBool>,
    /// Where a read is, in the archive as it is shown.
    at: u64,
    /// Whether the file has been moved to `at` since the list was built.
    synced: bool,
}

impl Shown {
    fn new(file: std::fs::File, tail: Tail, building: Arc<AtomicBool>) -> Self {
        Self {
            file: std::io::BufReader::new(file),
            tail,
            building,
            at: 0,
            synced: false,
        }
    }
}

impl Read for Shown {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.building.load(Ordering::Acquire) {
            if !self.synced {
                self.file.seek(SeekFrom::Start(self.at))?;
                self.synced = true;
            }
            let read = self.file.read(buffer)?;
            self.at += read as u64;
            return Ok(read);
        }
        let left = self.tail.length.saturating_sub(self.at);
        let wanted = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        if self.at < self.tail.start {
            let zeros =
                wanted.min(usize::try_from(self.tail.start - self.at).unwrap_or(usize::MAX));
            buffer[..zeros].fill(0);
            self.at += zeros as u64;
            return Ok(zeros);
        }
        let from = usize::try_from(self.at - self.tail.start).unwrap_or(usize::MAX);
        let shown = self.tail.bytes.get(from..).unwrap_or_default();
        let copied = wanted.min(shown.len());
        buffer[..copied].copy_from_slice(&shown[..copied]);
        self.at += copied as u64;
        Ok(copied)
    }
}

impl Seek for Shown {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        if !self.building.load(Ordering::Acquire) {
            let at = self.file.seek(position)?;
            self.at = at;
            self.synced = true;
            return Ok(at);
        }
        let target = match position {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.tail.length.checked_add_signed(by),
            SeekFrom::Current(by) => self.at.checked_add_signed(by),
        };
        let Some(target) = target else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a seek before the start of the archive",
            ));
        };
        self.at = target;
        Ok(target)
    }
}
