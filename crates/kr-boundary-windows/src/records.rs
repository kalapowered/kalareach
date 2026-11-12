//! The installation's own records in the data directory, and the order the removal deletes them in.
//!
//! The records are the manifest, the earlier-state record, any replacement of the manifest that a
//! crash or a failed write left, and the `staging` directory. A removal that fails at one of them
//! is run again whole, and the second run reads the manifest to know what is installed. So the
//! manifest goes last: only once every other record is gone, and so a record that stays always has
//! the manifest beside it.

use std::fs;
use std::io;
use std::path::Path;

/// Whether a text is 32 lowercase hexadecimal digits, the form of an identifier in a file's name.
#[must_use]
pub fn is_hex32(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether a name in the data directory is that of a replacement of the manifest, which a crash or
/// a failed write left: `manifest-` and 32 hexadecimal digits and `.new`.
#[must_use]
pub fn is_manifest_replacement(name: &str) -> bool {
    name.strip_prefix("manifest-")
        .and_then(|rest| rest.strip_suffix(".new"))
        .is_some_and(is_hex32)
}

/// Where the records are.
#[derive(Clone, Copy, Debug)]
pub struct Records<'a> {
    /// The data directory.
    pub data: &'a Path,
    /// The manifest.
    pub manifest: &'a Path,
    /// The earlier-state record.
    pub prior: &'a Path,
    /// The directory a run stages in.
    pub staging: &'a Path,
}

/// Deletes the records, last of all in a removal, and then the data directory.
///
/// The earlier-state record and every replacement of the manifest go first. `staging` goes next,
/// only when each of those is gone, and the manifest goes last, only when `staging` is gone too. A
/// removal run again reads the manifest and the earlier-state record, and reads the policy through
/// the channel, which makes its temporary directory in `staging`: so a record that stayed finds the
/// manifest beside it, and a manifest that stayed is found by the removal that runs again.
///
/// The data directory is tried last in any case, so that what keeps it is named. Returns each thing
/// that could not be removed, with the reason; nothing is returned when everything is gone.
pub fn remove(records: &Records<'_>) -> Vec<String> {
    let mut stayed = Vec::new();
    // Whether the thing is gone: it stayed when the call failed for any reason but its absence.
    let mut leave = |path: &Path, result: io::Result<()>| -> bool {
        if let Err(error) = result
            && error.kind() != io::ErrorKind::NotFound
        {
            stayed.push(format!("{} ({error})", path.display()));
            return false;
        }
        true
    };
    let mut gone = leave(records.prior, fs::remove_file(records.prior));
    if let Ok(entries) = fs::read_dir(records.data) {
        for entry in entries.flatten() {
            if is_manifest_replacement(&entry.file_name().to_string_lossy()) {
                gone &= leave(&entry.path(), fs::remove_file(entry.path()));
            }
        }
    }
    if gone {
        gone = leave(records.staging, fs::remove_dir_all(records.staging));
    }
    if gone {
        leave(records.manifest, fs::remove_file(records.manifest));
    }
    leave(records.data, fs::remove_dir(records.data));
    stayed
}
