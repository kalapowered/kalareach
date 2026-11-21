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

/// Who can change a folder or a file, as the handle that holds it reports.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Control {
    /// Nobody but the acting user can change it.
    Own,
    /// Another user can change it, and why.
    Shared(Cause),
    /// Its access list could not be read, so nothing can be said about it.
    Unreadable(String),
}

/// Why another user can change a folder or a file.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    /// Another user owns it.
    AnotherOwner,
    /// Its mode gives every user, or its group, the right to write, and its group is not the acting
    /// user's own private group.
    WriteBit,
    /// Its access list can let an account change it.
    ListEntry,
}

/// What the system says about the access list of a file or a folder.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Listing {
    /// The list as the system writes it, nothing where there is none, and whether it can let an
    /// account change what it describes.
    Read {
        /// The entries.
        entries: Vec<String>,
        /// True when an entry can let an account change what the list describes.
        allows: bool,
    },
    /// The list could not be read, and why.
    Unreadable(String),
}

/// The owner, the group, the mode and the access list of one file or folder, read through one
/// descriptor on it.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Protection {
    /// The object the descriptor holds.
    pub(super) identity: Identity,
    /// Who owns it.
    pub(super) owners: Owners,
    /// Its permission bits.
    pub(super) mode: u32,
    /// Its access list.
    pub(super) listing: Listing,
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
impl Protection {
    /// True when `other` has this one's owner, group, mode and access list: a copy that does gives
    /// no account anything the original did not.
    pub(super) fn matches(&self, other: &Self) -> bool {
        self.owners == other.owners && self.mode == other.mode && self.listing == other.listing
    }

    /// Says who can change what this describes.
    pub(super) fn control(&self) -> Control {
        decide(
            self.owners.user,
            acting_user(),
            self.mode,
            || private_group(self.owners.group),
            &self.listing,
        )
    }
}

/// Decides, from the facts a descriptor gave, whether another user can change what they describe.
///
/// Another owner decides first. Then a write bit: every user's always, and the group's unless
/// `private_group` says the group is the acting user's own and holds nobody else. Then the access
/// list, which where it could not be read leaves the question open.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) fn decide(
    owner: u32,
    acting: u32,
    mode: u32,
    private_group: impl FnOnce() -> bool,
    listing: &Listing,
) -> Control {
    if owner != acting {
        return Control::Shared(Cause::AnotherOwner);
    }
    if mode & 0o002 != 0 || (mode & 0o020 != 0 && !private_group()) {
        return Control::Shared(Cause::WriteBit);
    }
    match listing {
        Listing::Unreadable(why) => Control::Unreadable(why.clone()),
        Listing::Read { allows: true, .. } => Control::Shared(Cause::ListEntry),
        Listing::Read { .. } => Control::Own,
    }
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

pub(super) use platform::{Dir, acting_user, private_group};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
    use rustix::io::Errno;

    use super::{
        Child, Control, Entry, Fetched, Identity, Listing, Owners, Protection, Read, Unstaged,
    };

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

        /// Returns a second handle on this open directory. It is the same directory whatever has
        /// happened to the name this one was reached by since.
        pub(in crate::catalogue::native_bridge) fn duplicate(&self) -> std::io::Result<Self> {
            Ok(Self {
                handle: self.handle.try_clone()?,
                identity: self.identity,
                path: self.path.clone(),
            })
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

        /// Opens a directory in this one, following a link at its name: for the one place a person's
        /// own link is kept, an application's directory a package declares no placement for.
        pub(in crate::catalogue::native_bridge) fn child_following(
            &self,
            name: &str,
        ) -> std::io::Result<Child> {
            match rustix::fs::openat(
                self.handle.as_fd(),
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(handle) => Ok(Child::Directory(Self::held(handle, self.join(name))?)),
                Err(Errno::NOENT) => Ok(Child::Absent),
                Err(Errno::NOTDIR) => Ok(Child::NotADirectory),
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

        /// Says who can change this directory, read through the handle that holds it.
        pub(in crate::catalogue::native_bridge) fn control(&self) -> std::io::Result<Control> {
            let folder = std::fs::File::from(self.handle.try_clone()?);
            Ok(protection_of(&folder)?.control())
        }

        /// Reads the protection of the regular file at `name` through a descriptor opened on it
        /// without following a link; `None` where nothing regular is there.
        pub(in crate::catalogue::native_bridge) fn protection(
            &self,
            name: &str,
        ) -> std::io::Result<Option<Protection>> {
            match self.open_regular(name) {
                Ok(Some(file)) => protection_of(&file).map(Some),
                Ok(None) => Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }

        /// Says what is at one name from the status of the name alone, without opening it, so a
        /// file that denies reading is told as well as any. A regular file comes with its identity.
        pub(in crate::catalogue::native_bridge) fn look(
            &self,
            name: &str,
        ) -> std::io::Result<Entry> {
            let stat =
                match rustix::fs::statat(self.handle.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => stat,
                    Err(Errno::NOENT) => return Ok(Entry::Absent),
                    Err(error) => return Err(error.into()),
                };
            Ok(match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => Entry::Directory,
                FileType::RegularFile => Entry::File(identity_of_stat(&stat)),
                _ => Entry::Other,
            })
        }

        /// The identity of whatever is at one name, without following a link, or none where
        /// nothing is there.
        pub(in crate::catalogue::native_bridge) fn object_at(
            &self,
            name: &str,
        ) -> std::io::Result<Option<Identity>> {
            match rustix::fs::statat(self.handle.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(identity_of_stat(&stat))),
                Err(Errno::NOENT) => Ok(None),
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
            self.begin_stage(name, mode)?.finish(bytes)
        }

        /// Makes a new file at `name` with exactly the permission bits of `mode`, and writes
        /// nothing to it. The file is made only where nothing is, without following a link, and the
        /// protection it was given is read through its descriptor, so the caller sees what the
        /// folder gave it before any byte goes in.
        pub(in crate::catalogue::native_bridge) fn begin_stage(
            &self,
            name: &str,
            mode: u32,
        ) -> Result<Staging, Unstaged> {
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
            let file = std::fs::File::from(handle);
            let made =
                |file: &std::fs::File| file.metadata().ok().map(|metadata| identity(&metadata));
            // The creation mask narrows what the file is created with. The bits are set again,
            // before anything is written, so a replacement has the protection of the file it
            // replaces, no more and no less.
            if let Err(error) = rustix::fs::fchmod(&file, permissions(mode)) {
                return Err(Unstaged {
                    error: error.into(),
                    made: made(&file),
                });
            }
            match protection_of(&file) {
                Ok(protection) => Ok(Staging {
                    file,
                    identity: protection.identity,
                    protection,
                }),
                Err(error) => Err(Unstaged {
                    error,
                    made: made(&file),
                }),
            }
        }

        /// Renames `from` in this directory to `to` in `into`, only where nothing is at `to`. A
        /// file system that cannot refuse a name that is taken says `Unsupported`.
        pub(in crate::catalogue::native_bridge) fn rename_new(
            &self,
            from: &str,
            into: &Self,
            to: &str,
        ) -> std::io::Result<()> {
            rustix::fs::renameat_with(
                self.handle.as_fd(),
                from,
                into.handle.as_fd(),
                to,
                RenameFlags::NOREPLACE,
            )
            .map_err(rename_failure)
        }

        /// Makes `from` in this directory and `to` in `with` trade places in one step: both names
        /// stay in use, and no instant has either of them absent. It fails where `to` is not
        /// there, and with `Unsupported` where the file system has no such exchange.
        pub(in crate::catalogue::native_bridge) fn exchange(
            &self,
            from: &str,
            with: &Self,
            to: &str,
        ) -> std::io::Result<()> {
            rustix::fs::renameat_with(
                self.handle.as_fd(),
                from,
                with.handle.as_fd(),
                to,
                RenameFlags::EXCHANGE,
            )
            .map_err(rename_failure)
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

        /// Lists the names in this directory, through the handle it was opened by.
        pub(in crate::catalogue::native_bridge) fn names(&self) -> std::io::Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in rustix::fs::Dir::read_from(&self.handle)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if name != "." && name != ".." {
                    names.push(name);
                }
            }
            Ok(names)
        }

        /// Makes this directory's own entries durable.
        pub(in crate::catalogue::native_bridge) fn flush(&self) -> std::io::Result<()> {
            #[cfg(test)]
            if super::flush_failure::take(self.path()) {
                return Err(std::io::Error::other(
                    "the folder could not be made durable",
                ));
            }
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

    /// A file made in a directory and not yet written: its descriptor, and what it was given.
    pub(in crate::catalogue::native_bridge) struct Staging {
        file: std::fs::File,
        identity: Identity,
        protection: Protection,
    }

    impl Staging {
        /// Returns the identity of the file, as it was made.
        pub(in crate::catalogue::native_bridge) const fn identity(&self) -> Identity {
            self.identity
        }

        /// Returns the owner, group, mode and access list the file was given.
        pub(in crate::catalogue::native_bridge) const fn protection(&self) -> &Protection {
            &self.protection
        }

        /// Writes `bytes` to the file, flushes it, and returns its identity. A write that does not
        /// finish leaves the file where it is and says which file it is.
        pub(in crate::catalogue::native_bridge) fn finish(
            mut self,
            bytes: &[u8],
        ) -> Result<Identity, Unstaged> {
            let written = self
                .file
                .write_all(bytes)
                .and_then(|()| self.file.sync_all())
                .and_then(|()| self.file.metadata());
            written
                .map(|metadata| identity(&metadata))
                .map_err(|error| Unstaged {
                    error,
                    made: Some(self.identity),
                })
        }
    }

    /// The user this process acts as.
    pub(in crate::catalogue::native_bridge) fn acting_user() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// True when `group` is the acting user's own private group, so that a write bit it holds gives
    /// no other user anything. That is the group the user's account names as its primary, which
    /// `/etc/group` calls by the user's name and lists no other member of, and which no other
    /// account of `/etc/passwd` has as its primary group. A group that only another name service
    /// knows is not one.
    #[cfg(target_os = "linux")]
    pub(in crate::catalogue::native_bridge) fn private_group(group: u32) -> bool {
        let read = |path| std::fs::read_to_string(path).ok();
        match (read("/etc/passwd"), read("/etc/group")) {
            (Some(passwd), Some(groups)) => {
                is_private_group(&passwd, &groups, acting_user(), group)
            }
            _ => false,
        }
    }

    /// No group is the acting user's own on this platform: a group that can write is shared.
    #[cfg(target_os = "macos")]
    pub(in crate::catalogue::native_bridge) const fn private_group(_group: u32) -> bool {
        false
    }

    /// True when the account of `user` in `passwd` has `group` as its primary group, `groups` names
    /// that group once, by the account's name and with no other member, and no other account has it
    /// as its primary group.
    #[cfg(any(target_os = "linux", test))]
    fn is_private_group(passwd: &str, groups: &str, user: u32, group: u32) -> bool {
        let accounts: Vec<(&str, u32, u32)> = passwd
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                let id = fields.nth(1)?.parse().ok()?;
                let primary = fields.next()?.parse().ok()?;
                Some((name, id, primary))
            })
            .collect();
        let Some(&(name, _, primary)) = accounts.iter().find(|(_, id, _)| *id == user) else {
            return false;
        };
        if primary != group
            || accounts
                .iter()
                .any(|(_, id, theirs)| *theirs == group && *id != user)
        {
            return false;
        }
        let mut holders = groups
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let named = fields.next()?;
                let id: u32 = fields.nth(1)?.parse().ok()?;
                Some((named, id, fields.next().unwrap_or("")))
            })
            .filter(|(_, id, _)| *id == group);
        match (holders.next(), holders.next()) {
            (Some((named, _, members)), None) => {
                named == name
                    && members
                        .split(',')
                        .filter(|member| !member.is_empty())
                        .all(|member| member == name)
            }
            _ => false,
        }
    }

    /// Reads the protection of an open file or folder through its descriptor.
    fn protection_of(file: &std::fs::File) -> std::io::Result<Protection> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata()?;
        let mode = metadata.mode() & 0o777;
        Ok(Protection {
            identity: identity(&metadata),
            owners: Owners {
                user: metadata.uid(),
                group: metadata.gid(),
            },
            mode,
            listing: listing_of(file, mode),
        })
    }

    /// Reads the access list of an open file or folder through its descriptor. A list that cannot be
    /// read is said so, and not taken for an empty one.
    #[cfg(target_os = "macos")]
    fn listing_of(file: &std::fs::File, _mode: u32) -> Listing {
        match kr_ipc::access_list::read(file.as_fd()) {
            Ok(list) => Listing::Read {
                allows: list.allows(),
                entries: list.entries.into_iter().map(|entry| entry.text).collect(),
            },
            Err(error) => Listing::Unreadable(error.to_string()),
        }
    }

    /// Reads the access list of an open file or folder through its descriptor. A list that cannot be
    /// read is said so, and not taken for an empty one.
    #[cfg(target_os = "linux")]
    fn listing_of(file: &std::fs::File, mode: u32) -> Listing {
        match posix_list(file) {
            Ok(None) => Listing::Read {
                entries: Vec::new(),
                allows: false,
            },
            Ok(Some(list)) => Listing::Read {
                allows: posix_list_lets_the_group_write(mode),
                entries: vec![crate::catalogue::files::hex(&list)],
            },
            Err(error) => Listing::Unreadable(error.to_string()),
        }
    }

    /// True when a POSIX access list on an object of `mode` can let an account write. Where a list is
    /// kept, the group bits of the mode are its mask, so a named entry writes only where they do.
    #[cfg(any(target_os = "linux", test))]
    const fn posix_list_lets_the_group_write(mode: u32) -> bool {
        mode & 0o020 != 0
    }

    /// Reads the POSIX access list of an open file or folder: nothing where it has none, which a file
    /// system with no lists has none of.
    #[cfg(target_os = "linux")]
    fn posix_list(file: &std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
        const NAME: &str = "system.posix_acl_access";
        let size = match rustix::fs::fgetxattr_query(file, NAME) {
            Ok(size) => size,
            Err(Errno::NODATA | Errno::NOTSUP) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut list = vec![0_u8; size];
        match rustix::fs::fgetxattr(file, NAME, &mut list) {
            Ok(read) => {
                list.truncate(read);
                Ok(Some(list))
            }
            Err(Errno::NODATA) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// The identity a `stat` reports. The widths of its fields differ by platform, and a negative
    /// device number is widened as the standard library widens it.
    #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
    fn identity_of_stat(stat: &rustix::fs::Stat) -> Identity {
        Identity {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            size: stat.st_size as u64,
            modified_seconds: stat.st_mtime as i64,
            modified_nanoseconds: stat.st_mtime_nsec as i64,
        }
    }

    /// The error of a rename that takes a flag. A file system that does not take the flag says so
    /// with a different number on each system (`ENOTSUP` on macOS, `EINVAL` on Linux, `ENOSYS`
    /// where the flags do not exist); each is `Unsupported`, and any other failure keeps its kind.
    fn rename_failure(errno: Errno) -> std::io::Error {
        if [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS, Errno::INVAL].contains(&errno) {
            std::io::Error::new(std::io::ErrorKind::Unsupported, std::io::Error::from(errno))
        } else {
            errno.into()
        }
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

    #[cfg(test)]
    mod tests {
        use std::io::ErrorKind;

        use rustix::io::Errno;

        use super::{is_private_group, posix_list_lets_the_group_write, rename_failure};

        /// A file system that does not take a rename flag is `Unsupported`, whichever number the
        /// system answers with; every other failure keeps its kind.
        #[test]
        fn a_file_system_that_does_not_take_a_rename_flag_is_unsupported_by_every_number() {
            for errno in [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::NOSYS, Errno::INVAL] {
                assert_eq!(
                    rename_failure(errno).kind(),
                    ErrorKind::Unsupported,
                    "{errno}"
                );
            }
            assert_eq!(
                rename_failure(Errno::EXIST).kind(),
                ErrorKind::AlreadyExists
            );
            assert_eq!(rename_failure(Errno::NOENT).kind(), ErrorKind::NotFound);
        }

        const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
            ana:x:1000:1000:Ana:/home/ana:/bin/bash\n\
            ben:x:1001:100:Ben:/home/ben:/bin/bash\n\
            cy:x:1002:1000:Cy:/home/cy:/bin/bash\n";

        /// A group is the acting user's own private group only where the account files give it
        /// that name, say nobody else is in it and give it to nobody else as a primary group.
        #[test]
        fn a_group_is_the_acting_users_private_group_by_the_account_files() {
            let groups = "root:x:0:\nana:x:1000:\nusers:x:100:ben\n";
            // Ana's primary group is 1000, which is named ana, holds nobody, and is Ana's alone:
            // but Cy has it as a primary group too, so it is shared.
            assert!(
                !is_private_group(PASSWD, groups, 1000, 1000),
                "another account has it"
            );
            let alone =
                "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000:Ana:/home/ana:/bin/bash\n";
            assert!(
                is_private_group(alone, groups, 1000, 1000),
                "the user's own group"
            );
            assert!(
                is_private_group(alone, "ana:x:1000:ana\n", 1000, 1000),
                "the user as its only member"
            );
            assert!(
                !is_private_group(alone, "ana:x:1000:ana,ben\n", 1000, 1000),
                "another member"
            );
            assert!(
                !is_private_group(alone, "staff:x:1000:\n", 1000, 1000),
                "named otherwise than the user"
            );
            assert!(
                !is_private_group(alone, "ana:x:1000:\nteam:x:1000:\n", 1000, 1000),
                "two groups hold the number"
            );
            assert!(
                !is_private_group(alone, "root:x:0:\n", 1000, 1000),
                "a group only another name service knows"
            );
            assert!(
                !is_private_group(alone, groups, 1000, 100),
                "a group that is not the user's primary"
            );
            assert!(
                !is_private_group(alone, "ana:x:100:\n", 1000, 100),
                "a group named after the user, with no other member, that is not the user's primary"
            );
            assert!(
                !is_private_group(alone, groups, 4242, 4242),
                "a user the file does not know"
            );
            let namesake = "root:x:0:0:root:/root:/bin/bash\n\
                ana:x:1000:1000:Ana:/home/ana:/bin/bash\n\
                ana:x:2000:1000:Ana again:/home/ana-again:/bin/bash\n";
            assert!(
                !is_private_group(namesake, "ana:x:1000:\n", 1000, 1000),
                "an account of the same name and another number has it as its primary group"
            );
        }

        /// A POSIX list lets an account write only where the group bits, which are its mask, do.
        #[test]
        fn a_posix_list_lets_an_account_write_only_where_the_group_bits_do() {
            assert!(posix_list_lets_the_group_write(0o775));
            assert!(posix_list_lets_the_group_write(0o620));
            assert!(!posix_list_lets_the_group_write(0o755));
            assert!(!posix_list_lets_the_group_write(0o604));
        }
    }
}

/// Where this host does not walk an application's directory, every step refuses: the executor has
/// refused the recipe before it reaches one.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use std::path::{Path, PathBuf};

    use super::{Child, Control, Entry, Fetched, Identity, Owners, Protection, Unstaged};

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

    /// A file made in a directory. None is ever made on this platform.
    pub(in crate::catalogue::native_bridge) struct Staging {
        identity: Identity,
        protection: Protection,
    }

    impl Staging {
        pub(in crate::catalogue::native_bridge) const fn identity(&self) -> Identity {
            self.identity
        }

        pub(in crate::catalogue::native_bridge) const fn protection(&self) -> &Protection {
            &self.protection
        }

        pub(in crate::catalogue::native_bridge) fn finish(
            self,
            _bytes: &[u8],
        ) -> Result<Identity, Unstaged> {
            Err(Unstaged {
                error: unsupported(),
                made: None,
            })
        }
    }

    /// No group is the acting user's own: nothing is ever written on this platform.
    pub(in crate::catalogue::native_bridge) const fn private_group(_group: u32) -> bool {
        false
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

        pub(in crate::catalogue::native_bridge) fn duplicate(&self) -> std::io::Result<Self> {
            Err(unsupported())
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

        pub(in crate::catalogue::native_bridge) fn child_following(
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

        pub(in crate::catalogue::native_bridge) fn control(&self) -> std::io::Result<Control> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn protection(
            &self,
            _name: &str,
        ) -> std::io::Result<Option<Protection>> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn look(
            &self,
            _name: &str,
        ) -> std::io::Result<Entry> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn owners(
            &self,
            _name: &str,
        ) -> std::io::Result<Option<Owners>> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn object_at(
            &self,
            _name: &str,
        ) -> std::io::Result<Option<Identity>> {
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

        pub(in crate::catalogue::native_bridge) fn begin_stage(
            &self,
            _name: &str,
            _mode: u32,
        ) -> Result<Staging, Unstaged> {
            Err(Unstaged {
                error: unsupported(),
                made: None,
            })
        }

        pub(in crate::catalogue::native_bridge) fn rename_new(
            &self,
            _from: &str,
            _into: &Self,
            _to: &str,
        ) -> std::io::Result<()> {
            Err(unsupported())
        }

        pub(in crate::catalogue::native_bridge) fn exchange(
            &self,
            _from: &str,
            _with: &Self,
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

        pub(in crate::catalogue::native_bridge) fn names(&self) -> std::io::Result<Vec<String>> {
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

/// Lets a test make the next flush of one folder on its thread fail.
#[cfg(all(test, unix))]
pub(crate) mod flush_failure {
    use std::cell::Cell;
    use std::path::Path;

    thread_local! {
        static NEXT: Cell<Option<&'static str>> = const { Cell::new(None) };
    }

    /// The next flush on this thread of a folder whose path ends with `folder` fails.
    pub(crate) fn once_at(folder: &'static str) {
        NEXT.with(|next| next.set(Some(folder)));
    }

    /// True once after `once_at`, for the folder it named.
    pub(super) fn take(path: &Path) -> bool {
        NEXT.with(|next| match next.get() {
            Some(folder) if path.ends_with(folder) => {
                next.set(None);
                true
            }
            _ => false,
        })
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

#[cfg(test)]
mod tests {
    use super::{Cause, Control, Listing, decide};

    fn listed(allows: bool) -> Listing {
        Listing::Read {
            entries: Vec::new(),
            allows,
        }
    }

    /// A folder or a file of another user is shared whatever its mode and list say: the owner
    /// decides before any other cause.
    #[test]
    fn another_owner_decides_before_every_other_cause() {
        for mode in [0o700, 0o755, 0o775, 0o777] {
            assert_eq!(
                decide(0, 501, mode, || true, &listed(false)),
                Control::Shared(Cause::AnotherOwner),
                "{mode:o}"
            );
        }
        assert_eq!(
            decide(
                0,
                501,
                0o700,
                || true,
                &Listing::Unreadable("no".to_owned())
            ),
            Control::Shared(Cause::AnotherOwner),
            "an unreadable list does not hide another owner"
        );
        assert_eq!(
            decide(501, 501, 0o700, || false, &listed(false)),
            Control::Own
        );
    }

    /// A write bit makes a folder or a file shared: every user's always, and the group's unless the
    /// group is the acting user's own private group.
    #[test]
    fn a_write_bit_decides_by_the_group_the_object_has() {
        for mode in [0o757, 0o777, 0o602, 0o662] {
            assert_eq!(
                decide(501, 501, mode, || true, &listed(false)),
                Control::Shared(Cause::WriteBit),
                "every user can write at {mode:o}, whatever the group"
            );
        }
        for mode in [0o775, 0o770, 0o620] {
            assert_eq!(
                decide(501, 501, mode, || false, &listed(false)),
                Control::Shared(Cause::WriteBit),
                "a shared group can write at {mode:o}"
            );
            assert_eq!(
                decide(501, 501, mode, || true, &listed(false)),
                Control::Own,
                "the user's own private group can write at {mode:o}"
            );
        }
        for mode in [0o755, 0o750, 0o644, 0o600, 0o500] {
            assert_eq!(
                decide(
                    501,
                    501,
                    mode,
                    || panic!("no group bit asks"),
                    &listed(false)
                ),
                Control::Own,
                "{mode:o}"
            );
        }
    }

    /// An access list that can let an account change what it describes makes it shared; one that
    /// cannot be read leaves the question open; neither is asked before the owner and the mode.
    #[test]
    fn an_access_list_decides_after_the_owner_and_the_mode() {
        assert_eq!(
            decide(501, 501, 0o700, || false, &listed(true)),
            Control::Shared(Cause::ListEntry)
        );
        assert_eq!(
            decide(
                501,
                501,
                0o700,
                || false,
                &Listing::Unreadable("no".to_owned())
            ),
            Control::Unreadable("no".to_owned())
        );
        assert_eq!(
            decide(501, 501, 0o757, || false, &listed(true)),
            Control::Shared(Cause::WriteBit),
            "the mode decides before the list"
        );
    }
}
