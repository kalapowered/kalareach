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
use std::io::Read as _;
use std::path::{Path, PathBuf};

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
}

impl Limits {
    /// A release holds a few hundred files and a few hundred megabytes: these are several times
    /// that.
    pub const DEFAULT: Self = Self {
        entries: 50_000,
        total_bytes: 8 * 1024 * 1024 * 1024,
        entry_bytes: 2 * 1024 * 1024 * 1024,
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
const fn reason_of(fault: &PathFault) -> &'static str {
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
    let declared = file
        .try_clone()
        .and_then(|mut copy| declared_entries(&mut copy))
        .map_err(|_| unreadable("is not a zip archive this host reads"))?;
    let mut zipped = ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|_| unreadable("is not a zip archive this host reads"))?;
    if zipped.is_empty() {
        return Err(unreadable("is empty"));
    }
    // The reader keeps one entry for each name, the last of two that share one, so an archive that
    // names a file twice shows fewer entries than its directory declares.
    if declared != Some(zipped.len() as u64) {
        return Err(unreadable(
            "has the same name twice, or a directory that does not say how many entries it has",
        ));
    }
    if zipped.len() > limits.entries {
        return Err(unreadable("holds more entries than a release does"));
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

/// The number of entries an archive's end-of-central-directory record declares, read from the tail
/// of the file: the last record whose comment ends the file, with the 64-bit record that follows its
/// locator where the count does not fit in 16 bits. `None` where there is no such record.
fn declared_entries(file: &mut std::fs::File) -> std::io::Result<Option<u64>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    const END: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const END64: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    let length = file.seek(SeekFrom::End(0))?;
    // The record is 22 bytes and a comment of at most 65,535 bytes, with the locator before it.
    let window = length.min(22 + 65_535 + 20);
    file.seek(SeekFrom::Start(length - window))?;
    let mut tail = vec![0_u8; usize::try_from(window).unwrap_or(0)];
    file.read_exact(&mut tail)?;
    let Some(at) = (0..tail.len().saturating_sub(21)).rev().find(|&at| {
        tail[at..at + 4] == END
            && usize::from(u16::from_le_bytes([tail[at + 20], tail[at + 21]]))
                == tail.len() - (at + 22)
    }) else {
        return Ok(None);
    };
    let entries = u16::from_le_bytes([tail[at + 10], tail[at + 11]]);
    if entries != u16::MAX {
        return Ok(Some(u64::from(entries)));
    }
    let Some(locator) = at
        .checked_sub(20)
        .filter(|&locator| tail[locator..locator + 4] == LOCATOR)
    else {
        return Ok(Some(u64::from(entries)));
    };
    let mut offset = [0_u8; 8];
    offset.copy_from_slice(&tail[locator + 8..locator + 16]);
    file.seek(SeekFrom::Start(u64::from_le_bytes(offset)))?;
    let mut record = [0_u8; 56];
    file.read_exact(&mut record)?;
    if record[..4] != END64 {
        return Ok(None);
    }
    let mut total = [0_u8; 8];
    total.copy_from_slice(&record[32..40]);
    Ok(Some(u64::from_le_bytes(total)))
}
