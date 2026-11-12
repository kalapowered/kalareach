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
    /// What the removal's inspection opened and approved: nothing else is deleted.
    pub approved: &'a Approved,
}

/// Which records the removal's own inspection opened and approved. A record that is there now and
/// that it did not see appeared after the inspection: nothing opened it, so it is left and named,
/// and the removal that is run again reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Approved {
    /// The earlier-state record.
    pub prior: bool,
    /// The directory a run stages in: opened by the inspection, or made by the removal itself with
    /// an exclusive creation.
    pub staging: bool,
    /// The names of the manifest's replacements that the inspection opened.
    pub replacements: Vec<OsString>,
}

impl Approved {
    /// The earlier-state record, loaded only where the inspection approved it: a record that appeared
    /// after the inspection decides nothing (not the Application Identity service's start value, not
    /// whether that service is stopped, not the baseline of the residue check), and the removal acts
    /// as with no record. It is left and named when the records are deleted.
    pub fn prior_record<T>(&self, load: impl FnOnce() -> Option<T>) -> Option<T> {
        if self.prior { load() } else { None }
    }

    /// Approves every record that is in the data directory now, for a case that inspected nothing:
    /// the earlier-state record, `staging` and each replacement of the manifest. It exists for the
    /// tests alone; the removal approves only what its own inspection opened.
    #[must_use]
    pub fn all_that_are_there(data: &Path) -> Approved {
        let replacements = fs::read_dir(data)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| is_manifest_replacement(&name.to_string_lossy()))
            .collect();
        Approved {
            prior: true,
            staging: true,
            replacements,
        }
    }
}

/// What a removal says of something that is there now and that its inspection did not see.
#[must_use]
pub fn not_there_at_the_inspection(path: &Path) -> String {
    format!(
        "{} was not there when the removal looked for it, and something is there now, so it was not removed",
        path.display()
    )
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

/// Whether the thing is gone: it stayed when the call failed for any reason but its absence, and
/// the reason is added to what stayed.
fn leave(stayed: &mut Vec<String>, path: &Path, result: io::Result<()>) -> bool {
    if let Err(error) = result
        && error.kind() != io::ErrorKind::NotFound
    {
        stayed.push(format!("{} ({error})", path.display()));
        return false;
    }
    true
}

/// Whether nothing is at the path of a record that the inspection did not see; something that is
/// there is left where it is, and named.
fn unseen(stayed: &mut Vec<String>, path: &Path) -> bool {
    if entry_exists(path) {
        stayed.push(not_there_at_the_inspection(path));
        return false;
    }
    true
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
    let mut gone = if records.approved.prior {
        leave(&mut stayed, records.prior, fs::remove_file(records.prior))
    } else {
        unseen(&mut stayed, records.prior)
    };
    match names(records.data) {
        Ok(listed) => {
            for name in listed {
                match name {
                    Ok(name) if is_manifest_replacement(&name.to_string_lossy()) => {
                        let path = records.data.join(&name);
                        gone &= if records.approved.replacements.contains(&name) {
                            leave(&mut stayed, &path, fs::remove_file(&path))
                        } else {
                            unseen(&mut stayed, &path)
                        };
                    }
                    Ok(_) => {}
                    Err(error) => {
                        gone &= leave(&mut stayed, records.data, Err(unlisted(&error)));
                    }
                }
            }
        }
        // A data directory that is not there has no replacement in it.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => gone &= leave(&mut stayed, records.data, Err(unlisted(&error))),
    }
    if gone {
        gone = if records.approved.staging {
            leave(
                &mut stayed,
                records.staging,
                fs::remove_dir_all(records.staging),
            )
        } else {
            unseen(&mut stayed, records.staging)
        };
    }
    if gone {
        leave(
            &mut stayed,
            records.manifest,
            fs::remove_file(records.manifest),
        );
    }
    leave(&mut stayed, records.data, fs::remove_dir(records.data));
    stayed
}

/// What a removal's own inspection of the data directory found, in this run: the directory was
/// opened by handle and checked as the installation's own, or it was not there to be opened. The
/// removal acts on the directory, and on nothing in it, only through this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspection<M> {
    /// The folder above the directory, or the directory itself, was not there.
    Absent,
    /// The directory was opened, checked and found empty.
    Empty,
    /// The directory was opened and checked, and its manifest was read.
    Recorded(M),
}

/// What a removal does first, decided by what its inspection found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Begin<M> {
    /// There is nothing to remove, and the removal ends without a word.
    Nothing,
    /// The removal ends with this refusal, and nothing was deleted.
    Refuse(String),
    /// The empty directory that the inspection approved is removed, and nothing in it is read.
    FinishEmpty,
    /// What the manifest records is removed.
    Remove(M),
}

/// Decides how a removal begins. Only a directory that the inspection opened and approved is acted
/// on: when it found none, the path is looked at once more, only to refuse with the reason if
/// something is there now (the folder above it is one that an ordinary account may write in until
/// the installation has made it), and no deletion follows that look.
///
/// `something_there_now` says whether anything is at the directory's name now; it is asked only
/// when the inspection found none.
pub fn begin<M>(
    found: Inspection<M>,
    something_there_now: &dyn Fn() -> bool,
    quiet_when_empty: bool,
    data: &Path,
) -> Begin<M> {
    match found {
        Inspection::Recorded(manifest) => Begin::Remove(manifest),
        Inspection::Empty => Begin::FinishEmpty,
        Inspection::Absent if something_there_now() => Begin::Refuse(format!(
            "{} was not there when the removal looked for it, and something is there now, so nothing was removed. Run the removal again: it checks the directory first, and says what to do about it if it is not the installation's own.",
            data.display()
        )),
        Inspection::Absent if quiet_when_empty => Begin::Nothing,
        Inspection::Absent => Begin::Refuse("nothing is installed".to_owned()),
    }
}

/// Removes the data directory that the inspection found empty, and nothing else: no record is
/// deleted by name and no directory is emptied. A directory that holds anything by now stays, and
/// is named. Returns what could not be removed, with the reason; nothing when it is gone.
pub fn remove_empty(data: &Path) -> Vec<String> {
    match fs::remove_dir(data) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            vec![format!("{} ({error})", data.display())]
        }
        _ => Vec::new(),
    }
}

/// Whether anything is at the path: a link that points nowhere and an entry that cannot be read
/// count, because the look follows no link and only an answer of not found says that nothing is
/// there. It is a look for a refusal's reason or for a decision to leave something alone, and no
/// deletion follows it.
#[must_use]
pub fn entry_exists(path: &Path) -> bool {
    !matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

/// Which of the data directory's `journal` and `run` directories the removal's inspection opened
/// and approved. A directory that is not marked was not there when it looked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// The journal's directory.
    pub journal: bool,
    /// The directory of the invocations' private roots.
    pub run: bool,
}

/// Deletes the journal's files and the empty `run` and `journal` directories, in the directories
/// that the inspection approved and in no other. A directory that it did not see and that is there
/// now is left whole and named in the result: nothing opened it, so nothing in it was read.
/// Returns each thing that stayed, with the reason; nothing when all is done.
pub fn finish_journal_and_run(journal: &Path, run: &Path, seen: Seen) -> Vec<String> {
    let mut stayed = Vec::new();
    if seen.journal
        && let Ok(entries) = fs::read_dir(journal)
    {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|text| text.to_str()) == Some("journal") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    for (directory, approved) in [(run, seen.run), (journal, seen.journal)] {
        if !approved {
            if entry_exists(directory) {
                stayed.push(not_there_at_the_inspection(directory));
            }
            continue;
        }
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => stayed.push(format!(
                "removing {} failed ({error}): the call fails for an entry that is still in the directory and for a program that holds it open, and the removal run again reads it",
                directory.display()
            )),
        }
    }
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
/// state that a new installation accepts and the next removal finishes; anything else in it was
/// checked by no handle in this run, and a new installation refuses until it is gone: the removal
/// is run again, reads the first entry that it finds on its own handle and says what to do about it.
#[must_use]
pub fn next_step(manifest_stays: bool, data_is_empty: bool) -> &'static str {
    if manifest_stays {
        "The manifest stays with them: close what holds them, then run the removal again, which reads the manifest and finishes"
    } else if data_is_empty {
        "The directory is empty, and a new installation accepts an empty data directory: close what holds it (a console that has it as its current directory, for one), then run the removal again, which removes it"
    } else {
        "A new installation refuses until they are gone, and nothing has checked them: run the removal again, which reads the first entry that it finds on its own handle and says what to do about it, then run the setup program again"
    }
}
