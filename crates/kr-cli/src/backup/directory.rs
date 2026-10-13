//! The folder a restore fills.
//!
//! The person makes the folder; the command fills it and never makes, removes or replaces it. That
//! leaves no name in a parent for another program to race, and no access list of the command's own
//! to get wrong. The folder is checked once at the start, so a bad one fails before a kit is
//! typed, and opened for the run only after the person has confirmed the plan. From then on the
//! command holds an open handle on the directory and reaches every name through it: a rename or a
//! symbolic link put at the folder's path afterwards reaches no write and no removal.
//!
//! The trust boundary is the one a change set's removal keeps. On Unix the folder has to be owned
//! by this user and not writable by every account; a writer the person admitted by group or by an
//! access list is theirs to choose, because a private-group scheme makes every folder a person
//! creates group-writable. So a writer the person admitted can replace a name between this
//! command's creating a file and removing it, and the cleanup guarantee is only that it removes by
//! name, through the handle, the files this run made. On Windows a folder takes the access list of
//! its parent.
//!
//! Files are named from a member's role and a number and never from the archive. Each is made new
//! (nothing is replaced), mode 0600 on Unix, and synchronised. `restore.json` is written last and
//! given its name whole, without replacing anything: a directory that holds it is a restore that
//! finished, and one that does not is incomplete.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use cap_fs_ext::DirExt as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use kr_client::shown;
use kr_client::shown::Shown;

use crate::error::{CliError, Result};

/// The name the record is given once everything is written.
pub const RECORD_NAME: &str = "restore.json";

/// The name the record is written under until it is whole.
const RECORD_TEMPORARY: &str = ".restore.json.tmp";

/// The names a probe of the folder uses.
const PROBE: &str = ".restore-probe";
const PROBE_LINK: &str = ".restore-probe-link";

/// Names a file manager adds to a folder, which the refusal can name because they are well known.
const WELL_KNOWN: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini"];

/// A folder that passed the check, named by an absolute path.
#[derive(Clone, PartialEq, Eq)]
pub struct Destination {
    path: PathBuf,
}

kr_client::debug_as_name!(Destination);

impl Destination {
    /// Checks the folder `argument` names: it exists, is a directory (not a link to one), is empty,
    /// and on Unix is owned by this user and not writable by every account.
    ///
    /// A relative path is resolved in the command's own directory.
    ///
    /// # Errors
    ///
    /// Returns a usage failure saying which of those does not hold.
    pub fn check(argument: &Path) -> Result<Self> {
        let path = if argument.is_absolute() {
            argument.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    CliError::Usage(shown!(
                        "the folder cannot be found from this directory: {}",
                        Shown::io(&error)
                    ))
                })?
                .join(argument)
        };
        open_checked(&path)?;
        Ok(Self { path })
    }

    /// The absolute path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path as the plan's digest holds it.
    #[must_use]
    pub fn spelled(&self) -> String {
        kr_client::shown::spelled(&self.path)
    }

    /// Opens the folder for the run, checking it again.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when the folder is no longer one that passes the check.
    pub fn open(&self) -> Result<Held> {
        Ok(Held {
            dir: open_checked(&self.path)?,
            path: self.path.clone(),
            made: Vec::new(),
        })
    }
}

fn unusable(path: &Path, reason: &'static str) -> CliError {
    CliError::Usage(shown!(
        "{} {}",
        crate::shown::named(path),
        reason
    ))
}

/// Opens the directory at `path` without following a link at its end, and checks it through the
/// handle.
fn open_checked(path: &Path) -> Result<Dir> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(unusable(
            path,
            "has no parent folder, so it cannot be the folder a restore fills; make a folder in it",
        ));
    };
    let parent = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|error| {
        CliError::Usage(shown!(
            "the folder {} cannot be reached: {}",
            crate::shown::named(path),
            Shown::io(&error)
        ))
    })?;
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.is_symlink() => {
            return Err(unusable(
                path,
                "is a symbolic link; name the folder itself, which a restore does not reach through a link",
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(unusable(path, "is not a folder"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(unusable(
                path,
                "does not exist; make the folder first, and the restore fills it",
            ));
        }
        Err(error) => {
            return Err(CliError::Usage(shown!(
                "the folder {} cannot be inspected: {}",
                crate::shown::named(path),
                Shown::io(&error)
            )));
        }
    }
    let dir = parent.open_dir_nofollow(name).map_err(|error| {
        CliError::Usage(shown!(
            "the folder {} cannot be opened: {}",
            crate::shown::named(path),
            Shown::io(&error)
        ))
    })?;
    check_owner(&dir, path)?;
    check_empty(&dir, path)?;
    Ok(dir)
}

#[cfg(unix)]
fn check_owner(dir: &Dir, path: &Path) -> Result<()> {
    use cap_std::fs::MetadataExt as _;

    let metadata = dir.dir_metadata().map_err(|error| {
        CliError::Usage(shown!(
            "the folder {} cannot be inspected: {}",
            crate::shown::named(path),
            Shown::io(&error)
        ))
    })?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(unusable(path, "is not owned by you, so a restore does not fill it"));
    }
    if metadata.mode() & 0o002 != 0 {
        return Err(unusable(
            path,
            "can be written in by every account on this machine, so a restore does not fill it; \
             make a folder only you and the people you choose can write in",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn check_owner(_dir: &Dir, _path: &Path) -> Result<()> {
    Ok(())
}

fn check_empty(dir: &Dir, path: &Path) -> Result<()> {
    let entries = dir.entries().map_err(|error| {
        CliError::Usage(shown!(
            "the folder {} cannot be listed: {}",
            crate::shown::named(path),
            Shown::io(&error)
        ))
    })?;
    let mut count = 0_u64;
    let mut known = None;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::Usage(shown!(
                "the folder {} cannot be listed: {}",
                crate::shown::named(path),
                Shown::io(&error)
            ))
        })?;
        count += 1;
        let name = entry.file_name();
        if let Some(well_known) = WELL_KNOWN
            .iter()
            .find(|candidate| name.to_str() == Some(**candidate))
        {
            known.get_or_insert(*well_known);
        }
    }
    match (count, known) {
        (0, _) => Ok(()),
        (_, Some(name)) => Err(CliError::Usage(shown!(
            "the folder {} is not empty: it holds {} entries, among them {}, which a file manager \
             adds; a restore fills an empty folder",
            crate::shown::named(path),
            count,
            name
        ))),
        (_, None) => Err(CliError::Usage(shown!(
            "the folder {} is not empty: it holds {} entries; a restore fills an empty folder",
            crate::shown::named(path),
            count
        ))),
    }
}

/// The folder, held open for the run, and the names this run made in it.
pub struct Held {
    dir: Dir,
    /// The path the person named, for the lines that say where a name is.
    path: PathBuf,
    /// The names this run made and has not given up, in the order it made them.
    made: Vec<String>,
}

kr_client::debug_as_name!(Held);

fn fault(what: &'static str, error: &std::io::Error) -> CliError {
    CliError::Other(shown!("{}: {}", what, Shown::io(error)))
}

impl Held {
    /// Whether this folder can give a name to a file that is whole, without replacing one, which is
    /// how the record is published.
    ///
    /// It is tried before the first member is read, so a folder that cannot (a file system with no
    /// hard links, such as exFAT) fails before the download and not after it.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when it cannot.
    pub fn probe_publication(&self) -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let made = self.dir.open_with(PROBE, &options).map(drop);
        if let Err(error) = made {
            return Err(CliError::Usage(shown!(
                "the folder {} cannot be written in: {}",
                crate::shown::named(&self.path),
                Shown::io(&error)
            )));
        }
        let published = self.publish_probe();
        let _ = self.dir.remove_file(PROBE);
        let _ = self.dir.remove_file(PROBE_LINK);
        published.map_err(|error| {
            CliError::Usage(shown!(
                "the folder {} is on a file system that cannot give a finished file its name \
                 without replacing one ({}), which a restore needs; make the folder somewhere \
                 else",
                crate::shown::named(&self.path),
                Shown::io(&error)
            ))
        })
    }

    #[cfg(unix)]
    fn publish_probe(&self) -> std::io::Result<()> {
        self.dir.hard_link(PROBE, &self.dir, PROBE_LINK)
    }

    #[cfg(windows)]
    fn publish_probe(&self) -> std::io::Result<()> {
        let (from, to) = self.publication_names(PROBE, PROBE_LINK)?;
        kr_flush::retry_while_held(|| kr_flush::publish_without_replacing(&from, &to))
    }

    /// Both names, built from the held handle's own path and not from the text the person typed:
    /// the typed path can differ from what the handle holds by a junction earlier in it.
    #[cfg(windows)]
    fn publication_names(&self, from: &str, to: &str) -> std::io::Result<(PathBuf, PathBuf)> {
        let held = winx::file::get_file_path(&self.dir.try_clone()?.into_std_file())?;
        Ok((held.join(from), held.join(to)))
    }

    /// Writes one member's plaintext as a new file, mode 0600 on Unix, and synchronises it.
    ///
    /// # Errors
    ///
    /// Returns a failure when the file cannot be made or written. A file made and not finished is
    /// among [`Self::clean`]'s names.
    pub fn write_member(&mut self, name: &str, plaintext: &[u8]) -> Result<()> {
        let mut file = self.create(name)?;
        file.write_all(plaintext)
            .and_then(|()| file.sync_all())
            .map_err(|error| fault("a restored file could not be written", &error))
    }

    fn create(&mut self, name: &str) -> Result<cap_std::fs::File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = self
            .dir
            .open_with(name, &options)
            .map_err(|error| fault("a restored file could not be made", &error))?;
        self.made.push(name.to_owned());
        Ok(file)
    }

    /// Flushes the folder, so every name this run made survives a crash.
    ///
    /// # Errors
    ///
    /// Returns a failure when the flush fails.
    pub fn flush(&self) -> Result<()> {
        kr_flush::flush_held_directory(&self.dir, kr_flush::NameKind::File)
            .map_err(|error| fault("the folder could not be flushed", &error))
    }

    /// Publishes the record whole, without replacing a name, and returns what could not be tidied
    /// after it.
    ///
    /// The record is written under a temporary name and synchronised, then given its name. Once it
    /// has its name nothing is cleaned up: the members and the record were synchronised before it,
    /// so a crash leaves one of two consistent states, and a temporary left behind or a failed
    /// flush after that is a warning with its path and not a failed run.
    ///
    /// # Errors
    ///
    /// Returns a failure when the record cannot be written or given its name; the run then cleans
    /// up.
    pub fn publish_record(&mut self, record: &[u8]) -> Result<Vec<Shown>> {
        self.flush()?;
        let mut file = self.create(RECORD_TEMPORARY)?;
        file.write_all(record)
            .and_then(|()| file.sync_all())
            .map_err(|error| fault("the record could not be written", &error))?;
        drop(file);
        self.give_record_its_name()
            .map_err(|error| fault("the record could not be given its name", &error))?;
        // The record has its name: this run has finished and nothing it made is taken back.
        self.made.clear();
        let mut left = Vec::new();
        if self.dir.remove_file(RECORD_TEMPORARY).is_err() {
            left.push(shown!(
                "a temporary file was left at {}",
                crate::shown::named(&self.path.join(RECORD_TEMPORARY))
            ));
        }
        if kr_flush::flush_held_directory(&self.dir, kr_flush::NameKind::File).is_err() {
            left.push(shown!(
                "the folder {} could not be flushed after the record was written",
                crate::shown::named(&self.path)
            ));
        }
        Ok(left)
    }

    #[cfg(unix)]
    fn give_record_its_name(&self) -> std::io::Result<()> {
        self.dir.hard_link(RECORD_TEMPORARY, &self.dir, RECORD_NAME)
    }

    #[cfg(windows)]
    fn give_record_its_name(&self) -> std::io::Result<()> {
        let (from, to) = self.publication_names(RECORD_TEMPORARY, RECORD_NAME)?;
        kr_flush::retry_while_held(|| kr_flush::publish_without_replacing(&from, &to))
    }

    /// Removes, by name through the held handle, the files this run made, and returns a line for
    /// each it could not remove, with the path left behind.
    ///
    /// The folder itself is never removed, and nothing is removed recursively.
    pub fn clean(&mut self) -> Vec<Shown> {
        let mut left = Vec::new();
        for name in std::mem::take(&mut self.made).into_iter().rev() {
            match self.dir.remove_file(&name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => left.push(shown!(
                    "a file this restore made could not be removed: {}",
                    crate::shown::named(&self.path.join(&name))
                )),
            }
        }
        left
    }
}
