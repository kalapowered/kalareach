//! The installation's own records in the data directory, and the order the removal deletes them in.
//!
//! The records are the manifest, the earlier-state record, any replacement of the manifest that a
//! crash or a failed write left, and the `staging` directory. A removal that fails at one of them
//! is run again whole, and the second run reads the manifest to know what is installed. So the
//! manifest goes last: only once every other record is gone, and so a record that stays always has
//! the manifest beside it.

use std::ffi::OsString;
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
    remove_with(records, &list_names)
}

/// The names in a directory, each with the error that listing it gave.
fn list_names(dir: &Path) -> io::Result<Vec<io::Result<OsString>>> {
    Ok(fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect())
}

/// [`remove`] with the way the data directory is listed given, so that a listing that fails can be
/// shown. An error of the listing, and an error of one entry of it, both mean that a replacement of
/// the manifest may be there and is not gone: neither `staging` nor the manifest is then deleted,
/// and the removal says so.
pub fn remove_with(
    records: &Records<'_>,
    names: &dyn Fn(&Path) -> io::Result<Vec<io::Result<OsString>>>,
) -> Vec<String> {
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
    match names(records.data) {
        Ok(listed) => {
            for name in listed {
                match name {
                    Ok(name) if is_manifest_replacement(&name.to_string_lossy()) => {
                        let path = records.data.join(&name);
                        gone &= leave(&path, fs::remove_file(&path));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        gone &= leave(records.data, Err(unlisted(&error)));
                    }
                }
            }
        }
        // A data directory that is not there has no replacement in it.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => gone &= leave(records.data, Err(unlisted(&error))),
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

/// A listing's error as the failure to say that no replacement can be ruled out.
fn unlisted(error: &io::Error) -> io::Error {
    io::Error::other(format!(
        "its listing failed, so a replacement of the manifest cannot be ruled out: {error}"
    ))
}

/// What the person does about a data directory that stayed after the records went: while the
/// manifest stays, the removal is run again and reads it; an empty directory with no manifest is a
/// state that a new installation accepts and the next removal finishes; anything else in it is for
/// the person to remove, and a new installation refuses until it is gone.
#[must_use]
pub fn next_step(manifest_stays: bool, data_is_empty: bool) -> &'static str {
    if manifest_stays {
        "The manifest stays with them: close what holds them, then run the removal again, which reads the manifest and finishes"
    } else if data_is_empty {
        "The directory is empty, and a new installation accepts an empty data directory: close what holds it (a console that has it as its current directory, for one), then run the removal again, which removes it"
    } else {
        "A new installation refuses until they are gone: remove them, then run the setup program again"
    }
}
