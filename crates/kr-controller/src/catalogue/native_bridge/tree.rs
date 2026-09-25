//! The application's directory, walked from one handle on it without following a link.
//!
//! Every name a recipe writes, reads or removes is reached from the handle this host opened on the
//! application's directory, one component at a time, each opened without following a link. A
//! directory on the way that somebody replaced with a link, or with anything that is not a
//! directory, stops the walk instead of leading it somewhere else, so a removal can never be sent
//! into another directory to delete a file that happens to hold the same bytes. The directory
//! itself is opened by its name once: it is the one the host selected, and a link there is the
//! person's own layout.
//!
//! A file is published by writing it under a temporary name beside its destination, flushing it,
//! and renaming it into place; a new file is renamed only where nothing is, and the directory is
//! flushed after. The staged file's identity is what the journal records, because a rename keeps
//! it: the destination holding that identity afterwards is the file this host published.

use std::path::Path;

/// The identity the kernel reports for one file object, which a rename keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Identity {
    /// The device it is on.
    pub(super) device: u64,
    /// Its inode.
    pub(super) inode: u64,
    /// Its length in bytes.
    pub(super) size: u64,
    /// Its last modification, in whole seconds.
    pub(super) modified_seconds: i64,
    /// The nanoseconds past those seconds.
    pub(super) modified_nanoseconds: i64,
}

impl Identity {
    /// True when both name the same file object. A directory's size and modification time move
    /// as its entries change, so it is known by its device and inode alone.
    pub(super) const fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// What is at one name in a directory.
// Where this host does not walk an application's directory, nothing reads one, so nothing makes
// one either.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Entry {
    /// Nothing.
    Absent,
    /// A regular file, with its identity.
    File(Identity),
    /// A directory.
    Directory,
    /// Something else: a link, a pipe, a device.
    Other,
}

/// One component of a walk.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) enum Child {
    /// A directory, opened.
    Directory(Dir),
    /// Nothing is there.
    Absent,
    /// Something that is not a directory is there, or a link.
    NotADirectory,
}

/// What reading one name found.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) enum Fetched {
    /// Nothing is there.
    Absent,
    /// A regular file, read whole.
    File(Read),
    /// Something that is not a regular file is there, or a link.
    NotRegular,
    /// A regular file larger than the reader takes.
    TooLarge,
}

/// A staged write that did not finish: why, and the identity of the file it had made by then, so
/// the caller can take back that file and nothing else.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) struct Unstaged {
    /// Why it did not finish.
    pub(super) error: std::io::Error,
    /// The file it made, as it was when the write stopped; `None` when it made none, or its
    /// identity could not be read.
    pub(super) made: Option<Identity>,
}

/// A file read through the directory's handle.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) struct Read {
    /// Its bytes.
    pub(super) bytes: Vec<u8>,
    /// Its identity when it was read.
    pub(super) identity: Identity,
    /// Its permission bits.
    pub(super) mode: u32,
    /// The user and the group that own it.
    pub(super) owners: Owners,
}

/// The user and the group that own a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Owners {
    /// The owning user.
    pub(super) user: u32,
    /// The owning group.
    pub(super) group: u32,
}

pub(super) use platform::{Dir, acting_user};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
    use rustix::io::Errno;

    use super::{Child, Entry, Fetched, Identity, Owners, Read, Unstaged};

    /// An open directory, its identity, and the path it was reached by, for messages and for the
    /// checks that only take a path.
    #[derive(Debug)]
    pub(in crate::catalogue::native_bridge) struct Dir {
        handle: OwnedFd,
        identity: Identity,
        path: PathBuf,
    }

    impl Dir {
        /// Opens the application's directory.
        pub(in crate::catalogue::native_bridge) fn open(path: &Path) -> std::io::Result<Self> {
            let handle = rustix::fs::openat(
                rustix::fs::CWD,
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Self::held(handle, path.to_path_buf())
        }

        fn held(handle: OwnedFd, path: PathBuf) -> std::io::Result<Self> {
            let identity = identity(&std::fs::File::from(handle.try_clone()?).metadata()?);
            Ok(Self {
                handle,
                identity,
                path,
            })
        }

        /// Returns the path this directory was reached by.
        pub(in crate::catalogue::native_bridge) fn path(&self) -> &Path {
            &self.path
        }

        /// Returns the path of one name in this directory.
        pub(in crate::catalogue::native_bridge) fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        /// Returns this directory's own identity, as it was opened. A directory's device and inode
        /// do not change while it is held.
        pub(in crate::catalogue::native_bridge) const fn identity(&self) -> Identity {
            self.identity
        }

        /// True when this directory's path, followed as any program would follow it, still leads
        /// to this directory.
        pub(in crate::catalogue::native_bridge) fn path_leads_here(&self) -> bool {
            leads_to(&self.path, &self.identity)
        }

        /// True when the path of `name` in this directory, followed as any program would follow
        /// it, leads to the file object `identity` names.
        pub(in crate::catalogue::native_bridge) fn path_leads_to(
            &self,
            name: &str,
            identity: &Identity,
        ) -> bool {
            leads_to(&self.join(name), identity)
        }

        /// Opens a directory in this one, without following a link.
        pub(in crate::catalogue::native_bridge) fn child(
            &self,
            name: &str,
        ) -> std::io::Result<Child> {
            match rustix::fs::openat(
                self.handle.as_fd(),
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(handle) => Ok(Child::Directory(Self::held(handle, self.join(name))?)),
                Err(Errno::NOENT) => Ok(Child::Absent),
                Err(Errno::LOOP | Errno::NOTDIR) => Ok(Child::NotADirectory),
                Err(error) => Err(error.into()),
            }
        }

        /// Returns who owns what is at `name`, without following a link; `None` when nothing is.
        pub(in crate::catalogue::native_bridge) fn owners(
            &self,
            name: &str,
        ) -> std::io::Result<Option<Owners>> {
            match rustix::fs::statat(self.handle.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(Owners {
                    user: stat.st_uid,
                    group: stat.st_gid,
                })),
                Err(Errno::NOENT) => Ok(None),
                Err(error) => Err(error.into()),
            }
        }

        /// Makes a directory in this one; false when something was already there.
        pub(in crate::catalogue::native_bridge) fn make_child(
            &self,
            name: &str,
        ) -> std::io::Result<bool> {
            match rustix::fs::mkdirat(self.handle.as_fd(), name, Mode::from_raw_mode(0o755)) {
                Ok(()) => Ok(true),
                Err(Errno::EXIST) => Ok(false),
                Err(error) => Err(error.into()),
            }
        }

        /// Says what is at one name, without following a link.
        pub(in crate::catalogue::native_bridge) fn entry(
            &self,
            name: &str,
        ) -> std::io::Result<Entry> {
            let stat =
                match rustix::fs::statat(self.handle.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => stat,
                    Err(Errno::NOENT) => return Ok(Entry::Absent),
                    Err(error) => return Err(error.into()),
                };
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => Ok(Entry::Directory),
                FileType::RegularFile => match self.open_regular(name)? {
                    Some(file) => Ok(Entry::File(identity(&file.metadata()?))),
                    None => Ok(Entry::Other),
                },
                _ => Ok(Entry::Other),
            }
        }

        /// Reads a regular file of at most `limit` bytes, without following a link.
        pub(in crate::catalogue::native_bridge) fn fetch(
            &self,
            name: &str,
            limit: u64,
        ) -> std::io::Result<Fetched> {
            let file = match self.open_regular(name) {
                Ok(Some(file)) => file,
                Ok(None) => return Ok(Fetched::NotRegular),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Fetched::Absent);
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            if metadata.len() > limit {
                return Ok(Fetched::TooLarge);
            }
            let mut bytes = Vec::new();
            (&file).take(limit + 1).read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
                return Ok(Fetched::TooLarge);
            }
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            Ok(Fetched::File(Read {
                bytes,
                identity: identity(&metadata),
                mode: metadata.permissions().mode() & 0o777,
                owners: Owners {
                    user: metadata.uid(),
                    group: metadata.gid(),
                },
            }))
        }

        /// Writes `bytes` to a new file at `name` with exactly the permission bits of `mode`,
        /// flushes it, and returns its identity. A write that does not finish leaves the file it
        /// made where it is and says which file that is: its name is already recorded, so taking
        /// it back is the caller's, by the same identity check as any other cleanup.
        pub(in crate::catalogue::native_bridge) fn stage(
            &self,
            name: &str,
            bytes: &[u8],
            mode: u32,
        ) -> Result<Identity, Unstaged> {
            let handle = rustix::fs::openat(
                self.handle.as_fd(),
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                permissions(mode),
            )
            .map_err(|error| Unstaged {
                error: error.into(),
                made: None,
            })?;
            // The creation mask narrows what the file is created with. The bits are set again,
            // before anything is written, so a replacement has the protection of the file it
            // replaces, no more and no less.
            let exact = rustix::fs::fchmod(&handle, permissions(mode)).map_err(Into::into);
            let mut file = std::fs::File::from(handle);
            let staged = exact
                .and_then(|()| file.write_all(bytes))
                .and_then(|()| file.sync_all())
                .and_then(|()| file.metadata());
            staged
                .map(|metadata| identity(&metadata))
                .map_err(|error| Unstaged {
                    error,
                    made: file.metadata().ok().map(|metadata| identity(&metadata)),
                })
        }

        /// Renames `from` to `to` only where nothing is at `to`.
        pub(in crate::catalogue::native_bridge) fn rename_new(
            &self,
            from: &str,
            to: &str,
        ) -> std::io::Result<()> {
            rustix::fs::renameat_with(
                self.handle.as_fd(),
                from,
                self.handle.as_fd(),
                to,
                RenameFlags::NOREPLACE,
            )
            .map_err(Into::into)
        }

        /// Renames `from` over whatever is at `to`.
        pub(in crate::catalogue::native_bridge) fn rename_over(
            &self,
            from: &str,
            to: &str,
        ) -> std::io::Result<()> {
            rustix::fs::renameat(self.handle.as_fd(), from, self.handle.as_fd(), to)
                .map_err(Into::into)
        }

        /// Removes a file.
        pub(in crate::catalogue::native_bridge) fn remove_file(
            &self,
            name: &str,
        ) -> std::io::Result<()> {
            rustix::fs::unlinkat(self.handle.as_fd(), name, AtFlags::empty()).map_err(Into::into)
        }

        /// Removes an empty directory.
        pub(in crate::catalogue::native_bridge) fn remove_directory(
            &self,
            name: &str,
        ) -> std::io::Result<()> {
            rustix::fs::unlinkat(self.handle.as_fd(), name, AtFlags::REMOVEDIR).map_err(Into::into)
        }

        /// Makes this directory's own entries durable.
        pub(in crate::catalogue::native_bridge) fn flush(&self) -> std::io::Result<()> {
            rustix::fs::fsync(self.handle.as_fd()).map_err(Into::into)
        }

        /// Makes the bytes of the regular file at `name` durable, where there is one.
        pub(in crate::catalogue::native_bridge) fn sync_file(
            &self,
            name: &str,
        ) -> std::io::Result<()> {
            match self.open_regular(name) {
                Ok(Some(file)) => file.sync_all(),
                Ok(None) => Err(std::io::Error::other(format!(
                    "{} is not a regular file",
                    self.join(name).display()
                ))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }

        /// Opens a regular file to read, without following a link and without waiting; `None` when
        /// what is there is not a regular file.
        fn open_regular(&self, name: &str) -> std::io::Result<Option<std::fs::File>> {
            let handle = match rustix::fs::openat(
                self.handle.as_fd(),
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(handle) => handle,
                Err(Errno::LOOP) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let file = std::fs::File::from(handle);
            Ok(file.metadata()?.is_file().then_some(file))
        }
    }

    /// The user this process acts as.
    pub(in crate::catalogue::native_bridge) fn acting_user() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// True when `path`, followed as any program would follow it, leads to the file object
    /// `identity` names.
    fn leads_to(path: &Path, identity: &Identity) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).is_ok_and(|metadata| {
            metadata.dev() == identity.device && metadata.ino() == identity.inode
        })
    }

    /// The permission bits of `mode`, whatever width this platform's mode has.
    fn permissions(mode: u32) -> Mode {
        [
            (0o400, Mode::RUSR),
            (0o200, Mode::WUSR),
            (0o100, Mode::XUSR),
            (0o040, Mode::RGRP),
            (0o020, Mode::WGRP),
            (0o010, Mode::XGRP),
            (0o004, Mode::ROTH),
            (0o002, Mode::WOTH),
            (0o001, Mode::XOTH),
        ]
        .into_iter()
        .filter(|(bit, _)| mode & bit != 0)
        .fold(Mode::empty(), |permissions, (_, flag)| permissions | flag)
    }

    fn identity(metadata: &std::fs::Metadata) -> Identity {
        use std::os::unix::fs::MetadataExt as _;
        Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

/// Where this host does not walk an application's directory, every step refuses: the executor has
/// refused the recipe before it reaches one.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use std::path::{Path, PathBuf};

    use super::{Child, Entry, Fetched, Identity, Owners, Unstaged};

    fn unsupported() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this host does not change an application's directory on this platform",
        )
    }

    /// No user is named here: nothing is ever replaced on this platform.
    pub(in crate::catalogue::native_bridge) fn acting_user() -> u32 {
        u32::MAX
    }

    /// An open directory. None is ever opened on this platform.
    #[derive(Debug)]
    pub(in crate::catalogue::native_bridge) struct Dir {
        identity: Identity,
        path: PathBuf,
    }

    impl Dir {
        pub(in crate::catalogue::native_bridge) fn open(_path: &Path) -> std::io::Result<Self> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn path(&self) -> &Path {
            &self.path
        }

        pub(in crate::catalogue::native_bridge) fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        pub(in crate::catalogue::native_bridge) const fn identity(&self) -> Identity {
            self.identity
        }

        pub(in crate::catalogue::native_bridge) fn path_leads_here(&self) -> bool {
            false
        }

        pub(in crate::catalogue::native_bridge) fn path_leads_to(
            &self,
            _name: &str,
            _identity: &Identity,
        ) -> bool {
            false
        }

        pub(in crate::catalogue::native_bridge) fn child(
            &self,
            _name: &str,
        ) -> std::io::Result<Child> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn make_child(
            &self,
            _name: &str,
        ) -> std::io::Result<bool> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn owners(
            &self,
            _name: &str,
        ) -> std::io::Result<Option<Owners>> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn entry(
            &self,
            _name: &str,
        ) -> std::io::Result<Entry> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn fetch(
            &self,
            _name: &str,
            _limit: u64,
        ) -> std::io::Result<Fetched> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn stage(
            &self,
            _name: &str,
            _bytes: &[u8],
            _mode: u32,
        ) -> Result<Identity, Unstaged> {
            Err(Unstaged {
                error: unsupported(),
                made: None,
            })
        }

        pub(in crate::catalogue::native_bridge) fn rename_new(
            &self,
            _from: &str,
            _to: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn rename_over(
            &self,
            _from: &str,
            _to: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn remove_file(
            &self,
            _name: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn remove_directory(
            &self,
            _name: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn flush(&self) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn sync_file(
            &self,
            _name: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }
    }
}

/// Splits a relative path into its components.
pub(super) fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

/// Returns the directory that holds `path`, walked from `root`, with `path`'s last component.
///
/// # Errors
///
/// Returns an error when a directory on the way cannot be opened. A directory that is not there is
/// [`Walk::Missing`], and one that is a link or not a directory is [`Walk::Substituted`].
pub(super) fn parent_of<'p>(root: &Dir, path: &'p str) -> std::io::Result<Walk<'p>> {
    let parts = components(path);
    let Some((name, directories)) = parts.split_last() else {
        return Ok(Walk::Substituted(path.to_owned()));
    };
    let mut current: Option<Dir> = None;
    let mut walked = String::new();
    for part in directories {
        if !walked.is_empty() {
            walked.push('/');
        }
        walked.push_str(part);
        let next = match current.as_ref().unwrap_or(root).child(part)? {
            Child::Directory(directory) => directory,
            Child::Absent => return Ok(Walk::Missing { reached: current }),
            Child::NotADirectory => return Ok(Walk::Substituted(walked)),
        };
        current = Some(next);
    }
    Ok(Walk::Found {
        parent: current,
        name,
    })
}

/// Where a walk to a path's directory ended.
pub(super) enum Walk<'p> {
    /// The directory, `None` for the application's directory itself, and the last component.
    Found {
        /// The directory holding the name, `None` when it is the application's directory.
        parent: Option<Dir>,
        /// The last component.
        name: &'p str,
    },
    /// A directory on the way is not there. `reached` is the deepest one that is, `None` when that
    /// is the application's directory.
    Missing {
        /// The deepest directory on the way that is there.
        reached: Option<Dir>,
    },
    /// A directory on the way is a link, or not a directory.
    Substituted(String),
}

/// Returns the path a relative path names under `root`, for messages.
pub(super) fn display(root: &Path, path: &str) -> String {
    root.join(path).display().to_string()
}

/// Returns a temporary name beside `name` that nothing else uses.
pub(super) fn temporary_name(name: &str) -> String {
    format!(
        ".{name}.{}.kalareach",
        crate::catalogue::files::hex(&kr_cbor::sha256(kr_ipc::new_uuid().as_bytes())[..6])
    )
}
