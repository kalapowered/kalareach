//! The record of a run's tree that a case which restarts the control daemon makes when its agent
//! starts, and the changes between two records.
//!
//! The agent runs in the run's own account, so once it has started it may have written any file
//! the restarted daemon reads. The record holds every entry below the two roots the daemon is
//! given (the runtime and the state directory): a regular file by its digest and size, every
//! entry by its kind, its object identity (device and inode), its owner and its permission bits,
//! and a link by its target. The walk goes through handles opened relative to the run's pinned
//! directory and follows no link, so a link, a replaced directory or an entry on another file
//! system is never read through. Access lists and file flags are not recorded.
//!
//! A record opens no store and reads no row: a store is recorded by the digests of its files,
//! because a first open could itself rewrite a sidecar.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, RawMode};
use rustix::io::Errno;

use crate::run::RootPin;

/// The directory of the run that holds the host's runtime directory (`--runtime-dir`).
pub const RUNTIME_ROOT: &str = "r";

/// The directory of the run that holds the host's state directory (`--state-dir`).
pub const STATE_ROOT: &str = "s";

/// The directory that holds the programs the run placed.
pub const PROGRAMS_ROOT: &str = "b";

/// The application directory of the run's home, where the agent's own files live.
pub const APPLICATION_ROOT: &str = "h/.claude";

/// The roots every record holds.
pub const REQUIRED_ROOTS: [&str; 3] = [RUNTIME_ROOT, STATE_ROOT, PROGRAMS_ROOT];

/// The roots a record holds where they are there.
pub const OPTIONAL_ROOTS: [&str; 1] = [APPLICATION_ROOT];

/// The kind of an entry, as the walk tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A socket.
    Socket,
    /// A symbolic link.
    Link,
    /// A pipe or a device.
    Other,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::File => "a file",
            Self::Directory => "a directory",
            Self::Socket => "a socket",
            Self::Link => "a link",
            Self::Other => "a pipe or a device",
        })
    }
}

/// What the record holds of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The kind.
    pub kind: Kind,
    /// The bytes read, for a file, and 0 for every other kind.
    pub size: u64,
    /// The SHA-256 of the bytes read, for a file.
    pub digest: Option<[u8; 32]>,
    /// The device the entry lies on.
    pub device: i128,
    /// The inode.
    pub inode: i128,
    /// The owner.
    pub owner: u32,
    /// The permission bits, the setuid, setgid and sticky bits included.
    pub mode: RawMode,
    /// Where a link points.
    pub target: Option<PathBuf>,
}

impl Entry {
    /// The entry in words, for a line that says what was found.
    #[must_use]
    pub fn facts(&self) -> String {
        let mut said = format!(
            "{}, owner {}, mode {:04o}",
            self.kind, self.owner, self.mode
        );
        if let Some(digest) = &self.digest {
            let _ = write!(said, ", {} bytes, digest {}", self.size, hex(&digest[..4]));
        }
        if let Some(target) = &self.target {
            let _ = write!(said, ", pointing at {}", target.display());
        }
        let _ = write!(said, ", device {} inode {}", self.device, self.inode);
        said
    }

    /// What differs between this entry and `now`, which is the entry at `path` later.
    fn changes_to(&self, now: &Self, path: &Path, changes: &mut Vec<Change>) {
        if self.kind != now.kind {
            changes.push(Change::Retyped {
                path: path.to_path_buf(),
                was: self.kind,
                now: now.kind,
            });
            return;
        }
        if (self.device, self.inode) != (now.device, now.inode) {
            changes.push(Change::Replaced {
                path: path.to_path_buf(),
                was: self.clone(),
                now: now.clone(),
            });
        }
        if (self.size, self.digest) != (now.size, now.digest) {
            changes.push(Change::Bytes {
                path: path.to_path_buf(),
                was: self.clone(),
                now: now.clone(),
            });
        }
        if self.target != now.target {
            changes.push(Change::Target {
                path: path.to_path_buf(),
                was: self.target.clone(),
                now: now.target.clone(),
            });
        }
        if self.owner != now.owner {
            changes.push(Change::Owner {
                path: path.to_path_buf(),
                was: self.owner,
                now: now.owner,
            });
        }
        if self.mode != now.mode {
            changes.push(Change::Mode {
                path: path.to_path_buf(),
                was: self.mode,
                now: now.mode,
            });
        }
    }
}

/// One difference between an earlier record and a later one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// An entry the earlier record does not hold.
    Added {
        /// Where, relative to the run's directory.
        path: PathBuf,
        /// What it is now.
        now: Entry,
    },
    /// An entry the later record does not hold.
    Gone {
        /// Where.
        path: PathBuf,
        /// What it was.
        was: Entry,
    },
    /// The entry has another kind.
    Retyped {
        /// Where.
        path: PathBuf,
        /// The kind it had.
        was: Kind,
        /// The kind it has.
        now: Kind,
    },
    /// The entry is another object of the same kind: another device or another inode.
    Replaced {
        /// Where.
        path: PathBuf,
        /// What it was.
        was: Entry,
        /// What it is.
        now: Entry,
    },
    /// A file's size or digest differs.
    Bytes {
        /// Where.
        path: PathBuf,
        /// What it was.
        was: Entry,
        /// What it is.
        now: Entry,
    },
    /// A link points elsewhere.
    Target {
        /// Where.
        path: PathBuf,
        /// Where it pointed.
        was: Option<PathBuf>,
        /// Where it points.
        now: Option<PathBuf>,
    },
    /// The owner differs.
    Owner {
        /// Where.
        path: PathBuf,
        /// The owner it had.
        was: u32,
        /// The owner it has.
        now: u32,
    },
    /// The permission bits differ.
    Mode {
        /// Where.
        path: PathBuf,
        /// The bits it had.
        was: RawMode,
        /// The bits it has.
        now: RawMode,
    },
}

impl Change {
    /// Where the change is, relative to the run's directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Added { path, .. }
            | Self::Gone { path, .. }
            | Self::Retyped { path, .. }
            | Self::Replaced { path, .. }
            | Self::Bytes { path, .. }
            | Self::Target { path, .. }
            | Self::Owner { path, .. }
            | Self::Mode { path, .. } => path,
        }
    }
}

impl std::fmt::Display for Change {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path().display();
        match self {
            Self::Added { now, .. } => write!(formatter, "{path}: added, {}", now.facts()),
            Self::Gone { was, .. } => write!(formatter, "{path}: gone, it was {}", was.facts()),
            Self::Retyped { was, now, .. } => {
                write!(formatter, "{path}: it was {was} and is now {now}")
            }
            Self::Replaced { was, now, .. } => write!(
                formatter,
                "{path}: another object of the same kind, device {} inode {} before and device {} \
                 inode {} now",
                was.device, was.inode, now.device, now.inode
            ),
            Self::Bytes { was, now, .. } => write!(
                formatter,
                "{path}: the bytes changed, {} bytes with digest {} before and {} bytes with \
                 digest {} now",
                was.size,
                was.digest
                    .map_or_else(String::new, |digest| hex(&digest[..4])),
                now.size,
                now.digest
                    .map_or_else(String::new, |digest| hex(&digest[..4])),
            ),
            Self::Target { was, now, .. } => {
                let said = |target: &Option<PathBuf>| {
                    target
                        .as_ref()
                        .map_or_else(String::new, |target| target.display().to_string())
                };
                write!(
                    formatter,
                    "{path}: the link pointed at {} and points at {}",
                    said(was),
                    said(now)
                )
            }
            Self::Owner { was, now, .. } => {
                write!(formatter, "{path}: the owner was {was} and is now {now}")
            }
            Self::Mode { was, now, .. } => write!(
                formatter,
                "{path}: the permission bits were {was:04o} and are now {now:04o}"
            ),
        }
    }
}

/// The first bytes of a digest, in hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut said, byte| {
        let _ = write!(said, "{byte:02x}");
        said
    })
}

/// Every entry below some roots of a run's directory, at one time.
#[derive(Clone, Debug, Default)]
pub struct Record {
    entries: BTreeMap<PathBuf, Entry>,
}

impl Record {
    /// Records the roots of the run's directory `root`: each root and everything below it. The
    /// `required` roots must be there; an `optional` root is recorded where it is, and is no entry
    /// where it is not.
    ///
    /// `root` must be the directory `pin` names. A root name may have several components
    /// (`h/.claude`): each is looked at with no link followed, opened through the handle of the one
    /// before, checked to lie beneath the pinned place, and recorded as an entry of its own. An
    /// entry that is removed between the listing of its directory and the look at it is not
    /// recorded, since the live daemon removes its staging files as the walk goes.
    ///
    /// # Errors
    ///
    /// Returns why the tree cannot be recorded: the run's directory is not the one that was
    /// pinned, a required root is absent, a root or a component of one is not a directory, an
    /// entry lies on another file system, an entry cannot be listed, opened or read, or an entry
    /// was another one when it was opened than when it was looked at.
    pub fn of(
        root: &Path,
        pin: &RootPin,
        required: &[&str],
        optional: &[&str],
    ) -> Result<Self, String> {
        let handle = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("the run's directory cannot be opened: {error}"))?;
        if !pin.holds(&handle) {
            return Err("the run's directory is not the directory the run made".to_owned());
        }
        let device = rustix::fs::fstat(&handle)
            .map_err(|error| format!("the run's directory cannot be looked at: {error}"))?
            .st_dev;
        let mut entries = BTreeMap::new();
        let names = required
            .iter()
            .map(|name| (*name, false))
            .chain(optional.iter().map(|name| (*name, true)));
        for (name, optional) in names {
            record_root(&handle, device, pin, name, optional, &mut entries)?;
        }
        Ok(Self { entries })
    }

    /// The entry at `path`, relative to the run's directory.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&Entry> {
        self.entries.get(path)
    }

    /// Every entry, by its path relative to the run's directory.
    pub fn entries(&self) -> impl Iterator<Item = (&Path, &Entry)> {
        self.entries
            .iter()
            .map(|(path, entry)| (path.as_path(), entry))
    }

    /// What differs between this record and `later`: the entries added and gone, and for an entry
    /// in both its kind, object, bytes, link target, owner and permission bits.
    #[must_use]
    pub fn changes_to(&self, later: &Self) -> Vec<Change> {
        let mut changes = Vec::new();
        for (path, was) in &self.entries {
            match later.entries.get(path) {
                None => changes.push(Change::Gone {
                    path: path.clone(),
                    was: was.clone(),
                }),
                Some(now) => was.changes_to(now, path, &mut changes),
            }
        }
        for (path, now) in &later.entries {
            if !self.entries.contains_key(path) {
                changes.push(Change::Added {
                    path: path.clone(),
                    now: now.clone(),
                });
            }
        }
        changes
    }
}

/// The entry of a stat result and what was read of it.
fn entry_of(
    looked: &rustix::fs::Stat,
    kind: Kind,
    size: u64,
    digest: Option<[u8; 32]>,
    target: Option<PathBuf>,
) -> Entry {
    Entry {
        kind,
        size,
        digest,
        device: i128::from(looked.st_dev),
        inode: i128::from(looked.st_ino),
        owner: looked.st_uid,
        mode: looked.st_mode & 0o7777,
        target,
    }
}

/// Records the root `name` of the run's directory `handle` and everything below it: each
/// component of the name is an entry of its own, and the last is walked. An `optional` root that is
/// not there is no entry.
fn record_root(
    handle: &OwnedFd,
    device: rustix::fs::Dev,
    pin: &RootPin,
    name: &str,
    optional: bool,
    entries: &mut BTreeMap<PathBuf, Entry>,
) -> Result<(), String> {
    let mut current: Option<OwnedFd> = None;
    let mut relative = PathBuf::new();
    for component in name.split('/') {
        relative.push(component);
        let directory = current.as_ref().unwrap_or(handle);
        let looked = match rustix::fs::statat(directory, component, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(looked) => looked,
            Err(Errno::NOENT) if optional => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "{} cannot be looked at: {error}",
                    relative.display()
                ));
            }
        };
        if FileType::from_raw_mode(looked.st_mode) != FileType::Directory {
            return Err(format!(
                "{} is not a directory of the run",
                relative.display()
            ));
        }
        if looked.st_dev != device {
            return Err(format!(
                "{} is on another file system than the run's",
                relative.display()
            ));
        }
        let child = match open_directory_at(directory, component, &looked) {
            Ok(Some(child)) => child,
            Ok(None) if optional => return Ok(()),
            Ok(None) => return Err(format!("{} is gone", relative.display())),
            Err(why) => return Err(format!("{} {why}", relative.display())),
        };
        if !pin.contains(&child) {
            return Err(format!(
                "{} is not beneath the run's directory",
                relative.display()
            ));
        }
        entries.insert(
            relative.clone(),
            entry_of(&looked, Kind::Directory, 0, None, None),
        );
        current = Some(child);
    }
    let last = current.ok_or_else(|| "a root has no name".to_owned())?;
    walk(&last, &relative, device, entries)
}

/// Opens the directory `name` in `directory` with no link followed, and checks it to be the
/// directory `looked` described; `None` where it is removed before it is opened.
fn open_directory_at(
    directory: &OwnedFd,
    name: impl rustix::path::Arg + Copy,
    looked: &rustix::fs::Stat,
) -> Result<Option<OwnedFd>, String> {
    let opened = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(opened) => opened,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("cannot be opened: {error}")),
    };
    let stat =
        rustix::fs::fstat(&opened).map_err(|error| format!("cannot be looked at: {error}"))?;
    if (stat.st_dev, stat.st_ino) != (looked.st_dev, looked.st_ino) {
        return Err(
            "was another directory when it was opened than when it was looked at".to_owned(),
        );
    }
    Ok(Some(opened))
}

/// Records what is in `directory`, which is `relative`, and below it.
fn walk(
    directory: &OwnedFd,
    relative: &Path,
    device: rustix::fs::Dev,
    entries: &mut BTreeMap<PathBuf, Entry>,
) -> Result<(), String> {
    let listing = Dir::read_from(directory)
        .map_err(|error| format!("{} cannot be listed: {error}", relative.display()))?;
    for item in listing {
        let item =
            item.map_err(|error| format!("{} cannot be listed: {error}", relative.display()))?;
        let name = item.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let path = relative.join(OsStr::from_bytes(name.to_bytes()));
        let looked = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(looked) => looked,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(format!("{} cannot be looked at: {error}", path.display())),
        };
        if looked.st_dev != device {
            return Err(format!(
                "{} is on another file system than the run's",
                path.display()
            ));
        }
        let entry = match FileType::from_raw_mode(looked.st_mode) {
            FileType::Directory => {
                let child = match open_directory_at(directory, name, &looked) {
                    Ok(Some(child)) => child,
                    Ok(None) => continue,
                    Err(why) => return Err(format!("{} {why}", path.display())),
                };
                walk(&child, &path, device, entries)?;
                entry_of(&looked, Kind::Directory, 0, None, None)
            }
            FileType::RegularFile => {
                let Some((size, digest)) = read_file(directory, name, &looked, &path)? else {
                    continue;
                };
                entry_of(&looked, Kind::File, size, Some(digest), None)
            }
            FileType::Symlink => {
                let target = match rustix::fs::readlinkat(directory, name, Vec::new()) {
                    Ok(target) => PathBuf::from(OsStr::from_bytes(target.to_bytes())),
                    Err(Errno::NOENT) => continue,
                    Err(error) => {
                        return Err(format!("{} cannot be read: {error}", path.display()));
                    }
                };
                entry_of(&looked, Kind::Link, 0, None, Some(target))
            }
            FileType::Socket => entry_of(&looked, Kind::Socket, 0, None, None),
            _ => entry_of(&looked, Kind::Other, 0, None, None),
        };
        entries.insert(path, entry);
    }
    Ok(())
}

/// The size and the digest of the regular file `name` in `directory`, opened with no link followed
/// and no wait for a writer, and checked to be the file `looked` described; `None` where it is
/// removed before it is opened.
fn read_file(
    directory: &OwnedFd,
    name: &std::ffi::CStr,
    looked: &rustix::fs::Stat,
    path: &Path,
) -> Result<Option<(u64, [u8; 32])>, String> {
    let file = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    let opened = rustix::fs::fstat(&file)
        .map_err(|error| format!("{} cannot be looked at: {error}", path.display()))?;
    if (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino)
        || FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
    {
        return Err(format!(
            "{} was another entry when it was opened than when it was looked at",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(file)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
    Ok(Some((
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        kr_cbor::sha256(&bytes),
    )))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A run directory of this test's own, short enough for a socket below it, and its pin.
    fn run_directory(name: &str) -> (PathBuf, RootPin) {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        };
        let root = base.join(format!(
            "kt-{name}-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(root.join("s")).expect("a state root");
        std::fs::create_dir_all(root.join("r")).expect("a runtime root");
        let pin = RootPin::of(&root).expect("a pin");
        (root, pin)
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, bytes).expect("a file");
    }

    fn record(root: &Path, pin: &RootPin) -> Record {
        Record::of(root, pin, &["r", "s"], &[]).expect("a record")
    }

    /// Each change is said in one line that names the entry and what is found of it.
    #[test]
    fn each_change_is_said_in_one_line() {
        let file = Entry {
            kind: Kind::File,
            size: 5,
            digest: Some([0xab; 32]),
            device: 7,
            inode: 9,
            owner: 501,
            mode: 0o600,
            target: None,
        };
        let link = Entry {
            kind: Kind::Link,
            size: 0,
            digest: None,
            device: 7,
            inode: 11,
            owner: 501,
            mode: 0o777,
            target: Some(PathBuf::from("/etc")),
        };
        let path = || PathBuf::from("s/x");
        let said = |change: Change| change.to_string();
        assert_eq!(
            said(Change::Added {
                path: path(),
                now: file.clone()
            }),
            "s/x: added, a file, owner 501, mode 0600, 5 bytes, digest abababab, device 7 inode 9"
        );
        assert_eq!(
            said(Change::Gone {
                path: path(),
                was: link.clone()
            }),
            "s/x: gone, it was a link, owner 501, mode 0777, pointing at /etc, device 7 inode 11"
        );
        assert_eq!(
            said(Change::Retyped {
                path: path(),
                was: Kind::File,
                now: Kind::Directory
            }),
            "s/x: it was a file and is now a directory"
        );
        let moved = Entry {
            inode: 10,
            ..file.clone()
        };
        assert_eq!(
            said(Change::Replaced {
                path: path(),
                was: file.clone(),
                now: moved
            }),
            "s/x: another object of the same kind, device 7 inode 9 before and device 7 inode 10 \
             now"
        );
        let longer = Entry {
            size: 6,
            digest: Some([0xcd; 32]),
            ..file.clone()
        };
        assert_eq!(
            said(Change::Bytes {
                path: path(),
                was: file,
                now: longer
            }),
            "s/x: the bytes changed, 5 bytes with digest abababab before and 6 bytes with digest \
             cdcdcdcd now"
        );
        assert_eq!(
            said(Change::Target {
                path: path(),
                was: Some(PathBuf::from("/etc")),
                now: Some(PathBuf::from("/usr"))
            }),
            "s/x: the link pointed at /etc and points at /usr"
        );
        assert_eq!(
            said(Change::Owner {
                path: path(),
                was: 501,
                now: 0
            }),
            "s/x: the owner was 501 and is now 0"
        );
        assert_eq!(
            said(Change::Mode {
                path: path(),
                was: 0o600,
                now: 0o644
            }),
            "s/x: the permission bits were 0600 and are now 0644"
        );
    }

    /// Cleans up a test's run directory by its literal path.
    fn clean(root: &Path) {
        std::fs::remove_dir_all(root).expect("clean up");
    }

    /// The record holds each kind by its kind, with the object, the owner and the bits, a file by
    /// its digest and a link by its target, and follows no link.
    #[test]
    fn the_record_holds_each_kind_and_follows_no_link() {
        use std::os::unix::net::UnixListener;
        let (root, pin) = run_directory("kinds");
        write(&root.join("s/a/file"), b"bytes");
        std::os::unix::fs::symlink("/etc", root.join("s/a/link")).expect("a link");
        let _socket = UnixListener::bind(root.join("r/w1.sock")).expect("a socket");
        let held = record(&root, &pin);
        let kind = |path: &str| held.get(Path::new(path)).map(|entry| entry.kind);
        assert_eq!(kind("s"), Some(Kind::Directory));
        assert_eq!(kind("s/a"), Some(Kind::Directory));
        assert_eq!(kind("s/a/file"), Some(Kind::File));
        assert_eq!(kind("s/a/link"), Some(Kind::Link));
        assert_eq!(kind("r/w1.sock"), Some(Kind::Socket));
        let file = held.get(Path::new("s/a/file")).expect("the file");
        assert_eq!(file.size, 5);
        assert_eq!(file.digest, Some(kr_cbor::sha256(b"bytes")));
        assert_eq!(file.owner, rustix::process::getuid().as_raw());
        let link = held.get(Path::new("s/a/link")).expect("the link");
        assert_eq!(link.target.as_deref(), Some(Path::new("/etc")));
        assert!(
            held.entries()
                .all(|(path, _)| path == Path::new("s/a/link") || !path.starts_with("s/a/link")),
            "nothing below a link is recorded"
        );
        assert_eq!(held.changes_to(&record(&root, &pin)), []);
        clean(&root);
    }

    /// An entry the earlier record does not hold is a change, with what it is.
    #[test]
    fn an_entry_that_is_added_is_a_change() {
        let (root, pin) = run_directory("added");
        write(&root.join("s/a/file"), b"bytes");
        let before = record(&root, &pin);
        write(&root.join("s/a/new"), b"new");
        let changes = before.changes_to(&record(&root, &pin));
        assert!(
            matches!(changes.as_slice(), [Change::Added { path, now }] if path == Path::new("s/a/new") && now.kind == Kind::File && now.size == 3),
            "{changes:?}"
        );
        clean(&root);
    }

    /// A link replaced by a link that points elsewhere is a change of object and of target.
    #[test]
    fn a_link_that_points_elsewhere_is_a_change_of_target() {
        let (root, pin) = run_directory("target");
        std::os::unix::fs::symlink("/etc", root.join("s/link")).expect("a link");
        let before = record(&root, &pin);
        std::fs::remove_file(root.join("s/link")).expect("removed");
        std::os::unix::fs::symlink("/usr", root.join("s/link")).expect("a link elsewhere");
        let changes = before.changes_to(&record(&root, &pin));
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::Target { path, was, now }
                if path == Path::new("s/link")
                    && was.as_deref() == Some(Path::new("/etc"))
                    && now.as_deref() == Some(Path::new("/usr")))),
            "{changes:?}"
        );
        clean(&root);
    }

    /// A recorded entry that is gone is a change.
    #[test]
    fn an_entry_that_is_gone_is_a_change() {
        let (root, pin) = run_directory("gone");
        write(&root.join("s/a/file"), b"bytes");
        let before = record(&root, &pin);
        std::fs::remove_file(root.join("s/a/file")).expect("removed");
        let changes = before.changes_to(&record(&root, &pin));
        assert!(
            matches!(changes.as_slice(), [Change::Gone { path, .. }] if path == Path::new("s/a/file")),
            "{changes:?}"
        );
        clean(&root);
    }

    /// A file replaced by a directory or a link, and a directory replaced by a link or a file, is
    /// a change of kind, and so is a link in place of a socket.
    #[test]
    fn an_entry_of_another_kind_is_a_change() {
        let (root, pin) = run_directory("retyped");
        write(&root.join("s/file"), b"bytes");
        write(&root.join("s/directory/inside"), b"inside");
        let before = record(&root, &pin);
        std::fs::remove_file(root.join("s/file")).expect("removed");
        std::fs::create_dir(root.join("s/file")).expect("a directory in its place");
        std::fs::remove_dir_all(root.join("s/directory")).expect("removed");
        std::os::unix::fs::symlink(root.join("s/file"), root.join("s/directory"))
            .expect("a link in its place");
        let changes = before.changes_to(&record(&root, &pin));
        let retyped = |path: &str, was: Kind, now: Kind| {
            changes.iter().any(|change| {
                matches!(change, Change::Retyped { path: at, was: from, now: to }
                    if at == Path::new(path) && *from == was && *to == now)
            })
        };
        assert!(
            retyped("s/file", Kind::File, Kind::Directory),
            "{changes:?}"
        );
        assert!(
            retyped("s/directory", Kind::Directory, Kind::Link),
            "{changes:?}"
        );
        clean(&root);
    }

    /// A directory replaced by a file is a change of kind, with what was inside it gone.
    #[test]
    fn a_directory_replaced_by_a_file_is_a_change_and_what_it_held_is_gone() {
        let (root, pin) = run_directory("directory-file");
        write(&root.join("s/directory/inside"), b"inside");
        let before = record(&root, &pin);
        std::fs::remove_dir_all(root.join("s/directory")).expect("removed");
        write(&root.join("s/directory"), b"a file now");
        let changes = before.changes_to(&record(&root, &pin));
        assert!(
            changes.iter().any(|change| matches!(change, Change::Retyped { path, was: Kind::Directory, now: Kind::File } if path == Path::new("s/directory"))),
            "{changes:?}"
        );
        assert!(
            changes.iter().any(|change| matches!(change, Change::Gone { path, .. } if path == Path::new("s/directory/inside"))),
            "{changes:?}"
        );
        clean(&root);
    }

    /// Changed contents inside an unchanged directory are a change of bytes, and a copy with the
    /// same bytes on a new inode is a replacement.
    #[test]
    fn changed_contents_and_a_copy_on_a_new_inode_are_changes() {
        let (root, pin) = run_directory("bytes");
        write(&root.join("s/directory/changed"), b"before");
        write(&root.join("s/directory/copied"), b"same");
        let before = record(&root, &pin);
        std::fs::write(root.join("s/directory/changed"), b"after!").expect("rewritten in place");
        let copy = root.join("s/directory/copied.new");
        std::fs::write(&copy, b"same").expect("a copy");
        std::fs::rename(&copy, root.join("s/directory/copied")).expect("renamed over");
        let changes = before.changes_to(&record(&root, &pin));
        assert!(
            changes.iter().any(|change| matches!(change, Change::Bytes { path, .. } if path == Path::new("s/directory/changed"))),
            "{changes:?}"
        );
        assert!(
            changes.iter().any(|change| matches!(change, Change::Replaced { path, .. } if path == Path::new("s/directory/copied"))),
            "{changes:?}"
        );
        assert!(
            !changes.iter().any(|change| matches!(change, Change::Bytes { path, .. } if path == Path::new("s/directory/copied"))),
            "the copy has the same bytes: {changes:?}"
        );
        assert!(
            changes
                .iter()
                .all(|change| change.path() != Path::new("s/directory")),
            "the directory is unchanged: {changes:?}"
        );
        clean(&root);
    }

    /// A `chmod` is a change of the permission bits, and an entry of another owner is a change of
    /// the owner (the owner cannot be changed here without privilege, so the entries are compared
    /// as the walk would record them).
    #[test]
    fn a_chmod_and_another_owner_are_changes() {
        let (root, pin) = run_directory("mode");
        write(&root.join("s/file"), b"bytes");
        std::fs::set_permissions(root.join("s/file"), std::fs::Permissions::from_mode(0o600))
            .expect("owner only");
        let before = record(&root, &pin);
        std::fs::set_permissions(root.join("s/file"), std::fs::Permissions::from_mode(0o640))
            .expect("group may read");
        let after = record(&root, &pin);
        let changes = before.changes_to(&after);
        assert!(
            matches!(changes.as_slice(), [Change::Mode { path, was: 0o600, now: 0o640 }] if path == Path::new("s/file")),
            "{changes:?}"
        );
        let entry = after.get(Path::new("s/file")).expect("the file").clone();
        let other = Entry {
            owner: entry.owner.wrapping_add(1),
            ..entry.clone()
        };
        let mut owner_changes = Vec::new();
        entry.changes_to(&other, Path::new("s/file"), &mut owner_changes);
        assert!(
            matches!(owner_changes.as_slice(), [Change::Owner { was, now, .. }] if *was == entry.owner && *now == other.owner),
            "{owner_changes:?}"
        );
        clean(&root);
    }

    /// A root that is a link, a root that is a file, a root that is absent and a run directory that
    /// is not the pinned one are no record.
    #[test]
    fn a_root_that_is_not_the_directory_the_run_made_is_no_record() {
        let (root, pin) = run_directory("roots");
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).expect("a directory outside the roots");
        std::fs::remove_dir_all(root.join("s")).expect("removed");
        std::os::unix::fs::symlink(&outside, root.join("s")).expect("a link at the root");
        let why = Record::of(&root, &pin, &["r", "s"], &[]).expect_err("a link is no root");
        assert!(why.contains("s is not a directory of the run"), "{why}");
        std::fs::remove_file(root.join("s")).expect("removed");
        write(&root.join("s"), b"a file");
        let why = Record::of(&root, &pin, &["r", "s"], &[]).expect_err("a file is no root");
        assert!(why.contains("s is not a directory of the run"), "{why}");
        std::fs::remove_file(root.join("s")).expect("removed");
        let why = Record::of(&root, &pin, &["r", "s"], &[]).expect_err("an absent root");
        assert!(why.starts_with("s cannot be looked at"), "{why}");
        std::fs::create_dir(root.join("s")).expect("a root again");
        let moved = root.with_file_name(format!(
            "{}-moved",
            root.file_name().and_then(OsStr::to_str).expect("a name")
        ));
        std::fs::rename(&root, &moved).expect("the run's directory moved");
        std::fs::create_dir_all(root.join("s")).expect("a directory in its place");
        std::fs::create_dir_all(root.join("r")).expect("a directory in its place");
        let why = Record::of(&root, &pin, &["r", "s"], &[]).expect_err("another directory");
        assert!(why.contains("is not the directory the run made"), "{why}");
        clean(&root);
        clean(&moved);
    }

    /// A root with several components records each component and walks the last; an optional root
    /// that is not there is no entry, and one that is there is recorded whole.
    #[test]
    fn a_nested_root_is_recorded_component_by_component_and_an_optional_root_may_be_absent() {
        let (root, pin) = run_directory("nested");
        let both = |root: &Path, pin: &RootPin| {
            Record::of(root, pin, &["r", "s"], &["h/.app"]).expect("a record")
        };
        let absent = both(&root, &pin);
        assert!(
            absent.get(Path::new("h")).is_none(),
            "{:?}",
            absent.entries().count()
        );
        write(&root.join("h/.app/recipe"), b"recipe");
        write(&root.join("h/other/file"), b"not under the root");
        let held = both(&root, &pin);
        assert_eq!(
            held.get(Path::new("h")).map(|entry| entry.kind),
            Some(Kind::Directory)
        );
        assert_eq!(
            held.get(Path::new("h/.app")).map(|entry| entry.kind),
            Some(Kind::Directory)
        );
        assert_eq!(
            held.get(Path::new("h/.app/recipe")).map(|entry| entry.size),
            Some(6)
        );
        assert!(
            held.get(Path::new("h/other")).is_none(),
            "only the root's own components and what is below it"
        );
        // A required root with several components is an error where it is not there, and a
        // component of a root that is a link is no directory of the run.
        let why = Record::of(&root, &pin, &["r", "s", "h/.missing"], &[])
            .expect_err("a required root that is absent");
        assert!(why.starts_with("h/.missing cannot be looked at"), "{why}");
        std::fs::remove_dir_all(root.join("h")).expect("removed");
        std::os::unix::fs::symlink(root.join("s"), root.join("h")).expect("a link at a component");
        let why = Record::of(&root, &pin, &["r", "s"], &["h/.app"]).expect_err("a link");
        assert!(why.contains("h is not a directory of the run"), "{why}");
        clean(&root);
    }

    /// A file the walk cannot read and an entry on no file system of the run fail the record: the
    /// refusal is the record's, not a gap in it.
    #[test]
    fn an_entry_that_cannot_be_read_fails_the_record() {
        if rustix::process::getuid().is_root() {
            eprintln!("skipping: a privileged process reads every file");
            return;
        }
        let (root, pin) = run_directory("unreadable");
        write(&root.join("s/secret"), b"bytes");
        std::fs::set_permissions(
            root.join("s/secret"),
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("no access");
        let why = Record::of(&root, &pin, &["r", "s"], &[]).expect_err("an unreadable file");
        assert!(why.starts_with("s/secret cannot be read"), "{why}");
        std::fs::set_permissions(
            root.join("s/secret"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("access");
        clean(&root);
    }
}
