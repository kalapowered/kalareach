//! Handle-based filesystem authority.
//!
//! Section 14 paragraph 5 says filesystem authority resolves to environment-local **opened**
//! directory and object handles, not to validated path strings. That is what this module is: an
//! [`AuthorisedDirectory`] owns an open directory descriptor, and every descendant is opened
//! relative to it, one component at a time, with symbolic links and reparse points refused rather
//! than followed. The final object's identity and its permitted use are revalidated through the
//! handle before anything reads or writes it.
//!
//! ## The no-escape policy, qualified
//!
//! * A name is relative, in this crate's own accepted form: no root, no drive prefix, no `..`, no
//!   `.`, no empty component, no NUL, no separator other than `/`, no trailing dot or space on a
//!   component, no alternate-data-stream colon, and no Windows reserved device name with or
//!   without an extension. The same rules apply on every platform, so a name that one host accepts
//!   is a name every host accepts.
//! * Resolution opens each intermediate component with the no-follow open, so a component that is
//!   a symbolic link or a reparse point fails the lookup instead of redirecting it. Replacing a
//!   component with a link *during* the walk fails the same way: the open that would have crossed
//!   it is the one that refuses.
//! * On Linux the underlying open uses `openat2` with `RESOLVE_BENEATH`; on other Unix systems it
//!   is a component-wise `openat` with `O_NOFOLLOW`; on Windows it is a relative `NtCreateFile`
//!   that rejects reparse points. [`cap_std`] owns those three implementations, which is why this
//!   module is the policy and not the syscalls.
//! * After the open, the object's stable filesystem identity (device and inode, or volume serial
//!   and file index) is read back **through the handle** and checked against the policy the caller
//!   asked for. A directory handle's own identity is recorded when it is opened, so a scope
//!   reopened after a restart is refused unless it finds the same object.
//! * An environment identity travels with every handle. A handle from one environment is never
//!   accepted by another, which is how a Windows path and a WSL path stay separate rather than
//!   aliasing.
//!
//! ## What this does not do
//!
//! It removes path-resolution races. It does not make an authorised file private: another process
//! running as the same operating-system user can open and write a file this host has authorised,
//! and nothing here prevents that. Where immutability matters, as it does for a download, the host
//! stages its own copy instead of trusting an open handle.

use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, File, OpenOptions};
use kr_protocol::ids::EnvironmentId;

/// Longest accepted relative name, in bytes.
pub const MAX_RELATIVE_NAME_LEN: usize = 4096;

/// Longest accepted component of a relative name, in bytes.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Windows device names, which name a device rather than a file whatever directory they appear in.
const RESERVED_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Why a name or an object was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Escape {
    /// The name is empty.
    #[error("a relative name cannot be empty")]
    Empty,
    /// The name is absolute, or names a root or a drive.
    #[error("{name} is not relative to the authorised directory")]
    NotRelative {
        /// The name that was given.
        name: String,
    },
    /// The name contains a traversal segment.
    #[error("a relative name cannot contain a parent segment")]
    ParentSegment,
    /// The name contains a current-directory segment.
    #[error("a relative name cannot contain a current-directory segment")]
    CurrentSegment,
    /// The name contains an empty component.
    #[error("a relative name cannot contain an empty component")]
    EmptyComponent,
    /// The name contains a byte that cannot appear in a filename.
    #[error("{detail}")]
    ForbiddenByte {
        /// Which byte, and where.
        detail: String,
    },
    /// A component names a device rather than a file.
    #[error("{component} names a device rather than a file")]
    ReservedName {
        /// The component.
        component: String,
    },
    /// The name or one of its components is too long.
    #[error("{detail}")]
    TooLong {
        /// Which bound was exceeded.
        detail: String,
    },
    /// A component is a symbolic link or a reparse point, and this policy follows neither.
    #[error("{component} is a link, and resolution beneath an authorised directory follows none")]
    Link {
        /// The component that is a link.
        component: String,
    },
    /// The object could not be opened relative to the authorised directory.
    #[error("{component} could not be opened beneath the authorised directory: {detail}")]
    Unopenable {
        /// The component that failed.
        component: String,
        /// What the platform reported.
        detail: String,
    },
    /// The opened object is not the kind the policy permits.
    #[error("{detail}")]
    WrongKind {
        /// What was opened and what was required.
        detail: String,
    },
    /// The opened object's stable identity is not the one that was recorded.
    #[error("{detail}")]
    IdentityChanged {
        /// What was recorded and what was found.
        detail: String,
    },
    /// The handle belongs to another environment.
    #[error("this handle belongs to environment {holder}, not {named}")]
    WrongEnvironment {
        /// The environment the handle belongs to.
        holder: String,
        /// The environment that tried to use it.
        named: String,
    },
}

/// A relative name validated for use beneath an authorised directory.
///
/// The only accepted separator is `/`. A backslash is a legal filename byte on Unix and a
/// separator on Windows, so accepting it would mean one name resolving two ways; it is refused
/// instead.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeName {
    text: String,
}

impl RelativeName {
    /// Validates a name for use beneath an authorised directory.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks.
    pub fn parse(name: &str) -> Result<Self, Escape> {
        if name.is_empty() {
            return Err(Escape::Empty);
        }
        if name.len() > MAX_RELATIVE_NAME_LEN {
            return Err(Escape::TooLong {
                detail: format!(
                    "a relative name is at most {MAX_RELATIVE_NAME_LEN} bytes, not {}",
                    name.len()
                ),
            });
        }
        if name.starts_with('/') || name.starts_with('\\') {
            return Err(Escape::NotRelative {
                name: name.to_owned(),
            });
        }
        // `C:` and `C:name` are both drive-relative on Windows, and a colon anywhere opens an
        // alternate data stream. Neither is a name beneath a directory.
        if name.contains(':') {
            return Err(Escape::NotRelative {
                name: name.to_owned(),
            });
        }
        if name.contains('\\') {
            return Err(Escape::ForbiddenByte {
                detail: "a backslash resolves two ways across platforms, so it is not a separator \
                         or a filename byte here"
                    .to_owned(),
            });
        }
        for component in name.split('/') {
            check_component(component)?;
        }
        Ok(Self {
            text: name.to_owned(),
        })
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the components, in order.
    #[must_use]
    pub fn components(&self) -> Vec<&str> {
        self.text.split('/').collect()
    }
}

impl std::fmt::Display for RelativeName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text)
    }
}

fn check_component(component: &str) -> Result<(), Escape> {
    if component.is_empty() {
        return Err(Escape::EmptyComponent);
    }
    if component == ".." {
        return Err(Escape::ParentSegment);
    }
    if component == "." {
        return Err(Escape::CurrentSegment);
    }
    if component.len() > MAX_COMPONENT_LEN {
        return Err(Escape::TooLong {
            detail: format!(
                "a component is at most {MAX_COMPONENT_LEN} bytes, not {}",
                component.len()
            ),
        });
    }
    if component.contains('\0') {
        return Err(Escape::ForbiddenByte {
            detail: "a component cannot contain a null byte".to_owned(),
        });
    }
    if let Some(character) = component.chars().find(|character| character.is_control()) {
        return Err(Escape::ForbiddenByte {
            detail: format!(
                "a component cannot contain the control character U+{:04X}",
                character as u32
            ),
        });
    }
    // Windows strips a trailing dot or space, so `report.` and `report` would name one file while
    // reading as two names. Refusing both keeps one name meaning one file everywhere.
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(Escape::ForbiddenByte {
            detail: format!("{component} ends in a dot or a space, which Windows would strip"),
        });
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_lowercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        return Err(Escape::ReservedName {
            component: component.to_owned(),
        });
    }
    Ok(())
}

/// The stable filesystem identity of one object.
///
/// On Unix this is the device number and the inode. On Windows it is the volume serial number and
/// the file index, both read from an open handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIdentity {
    /// The device or volume the object lives on.
    pub device: u64,
    /// The object's number within that device or volume.
    pub file_id: u64,
}

impl std::fmt::Display for ObjectIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.device, self.file_id)
    }
}

/// What an opened object may be used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectPolicy {
    /// A regular file this host created and is the only namer of.
    ///
    /// A second hard link means something else under this account has taken a name for the host's
    /// own payload file, which is refused rather than written to.
    HostOwnedFile,
    /// A regular file the host reads but did not create.
    ///
    /// Multiple links are accepted: a hard link is a name inside the directory rather than a path
    /// that leaves it, and content reachable under another name is not something path authority
    /// can decide.
    ReadableFile,
}

impl ObjectPolicy {
    fn check(self, metadata: &cap_std::fs::Metadata, what: &str) -> Result<(), Escape> {
        if !metadata.is_file() {
            return Err(Escape::WrongKind {
                detail: format!("{what} is not a regular file"),
            });
        }
        if matches!(self, Self::HostOwnedFile) && metadata.nlink() != 1 {
            return Err(Escape::WrongKind {
                detail: format!(
                    "{what} has {} names; a payload file this host created has one",
                    metadata.nlink()
                ),
            });
        }
        Ok(())
    }
}

/// An opened directory that authorises what lies beneath it.
#[derive(Debug)]
pub struct AuthorisedDirectory {
    environment_id: EnvironmentId,
    directory: Dir,
    identity: ObjectIdentity,
    /// The path the directory was opened from. Diagnostics only: the handle is the authority, and
    /// re-resolving this path would let a rename hand the grant to an unrelated tree.
    display: PathBuf,
}

impl AuthorisedDirectory {
    /// Opens a directory as an authority for one environment.
    ///
    /// The path is resolved once, here, with the process's ambient authority. Everything after
    /// this point is relative to the handle.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::Unopenable`] when the directory cannot be opened, or [`Escape::Link`]
    /// when the path names a link.
    pub fn open_root(environment_id: EnvironmentId, path: &Path) -> Result<Self, Escape> {
        let ambient = cap_std::ambient_authority();
        let directory = Dir::open_ambient_dir(path, ambient).map_err(|error| {
            if is_link_errno(&error) {
                Escape::Link {
                    component: path.display().to_string(),
                }
            } else {
                Escape::Unopenable {
                    component: path.display().to_string(),
                    detail: error.to_string(),
                }
            }
        })?;
        let identity = directory_identity(&directory, path)?;
        Ok(Self {
            environment_id,
            directory,
            identity,
            display: path.to_path_buf(),
        })
    }

    /// Wraps a directory handle a caller already holds.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::Unopenable`] when the handle's identity cannot be read.
    pub fn from_handle(
        environment_id: EnvironmentId,
        directory: Dir,
        display: PathBuf,
    ) -> Result<Self, Escape> {
        let identity = directory_identity(&directory, &display)?;
        Ok(Self {
            environment_id,
            directory,
            identity,
            display,
        })
    }

    /// Returns the environment this authority belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the identity recorded when the directory was opened.
    #[must_use]
    pub const fn identity(&self) -> ObjectIdentity {
        self.identity
    }

    /// Returns the path the directory was opened from, for diagnostics.
    #[must_use]
    pub fn display_path(&self) -> &Path {
        &self.display
    }

    /// Returns the underlying handle.
    #[must_use]
    pub const fn handle(&self) -> &Dir {
        &self.directory
    }

    /// Refuses a caller from another environment.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::WrongEnvironment`] when the identities differ.
    pub fn check_environment(&self, environment_id: EnvironmentId) -> Result<(), Escape> {
        if environment_id == self.environment_id {
            Ok(())
        } else {
            Err(Escape::WrongEnvironment {
                holder: self.environment_id.to_string(),
                named: environment_id.to_string(),
            })
        }
    }

    /// Checks that this handle still names the object whose identity was recorded.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::IdentityChanged`] when it does not.
    pub fn revalidate(&self) -> Result<(), Escape> {
        let found = directory_identity(&self.directory, &self.display)?;
        if found == self.identity {
            Ok(())
        } else {
            Err(Escape::IdentityChanged {
                detail: format!(
                    "the authorised directory was {}, and this handle now names {found}",
                    self.identity
                ),
            })
        }
    }

    /// Checks that this handle names the object whose identity a store recorded earlier.
    ///
    /// This is what a scope reopened after a restart is checked against: a rename, a case alias or
    /// a replacement directory at the same path finds a different object and is refused.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::IdentityChanged`] when the identities differ.
    pub fn check_identity(&self, expected: ObjectIdentity) -> Result<(), Escape> {
        if expected == self.identity {
            Ok(())
        } else {
            Err(Escape::IdentityChanged {
                detail: format!(
                    "this authority was recorded for {expected} and now names {}",
                    self.identity
                ),
            })
        }
    }

    /// Opens a subdirectory as an authority of its own, following no link.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the open failure.
    pub fn subdirectory(&self, name: &RelativeName) -> Result<Self, Escape> {
        let mut directory = self.clone_handle()?;
        let mut display = self.display.clone();
        for component in name.components() {
            directory = open_child_directory(&directory, component)?;
            display.push(component);
        }
        Self::from_handle(self.environment_id, directory, display)
    }

    /// Creates a subdirectory, owner-only, and opens it as an authority of its own.
    ///
    /// An existing directory is opened rather than replaced; an existing non-directory is refused.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the create or open failure.
    pub fn create_subdirectory(&self, name: &RelativeName) -> Result<Self, Escape> {
        let mut directory = self.clone_handle()?;
        let mut display = self.display.clone();
        for component in name.components() {
            let child = RelativeName::parse(component)?;
            match create_owner_only_directory(&directory, &child) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(Escape::Unopenable {
                        component: component.to_owned(),
                        detail: error.to_string(),
                    });
                }
            }
            directory = open_child_directory(&directory, component)?;
            display.push(component);
        }
        Self::from_handle(self.environment_id, directory, display)
    }

    /// Opens a descendant for reading, refusing every link on the way.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name or the object breaks.
    pub fn open_read(
        &self,
        name: &RelativeName,
        policy: ObjectPolicy,
    ) -> Result<AuthorisedFile, Escape> {
        let (parent, leaf) = self.walk(name)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        no_wait(&mut options);
        let file = open_leaf(&parent, leaf, &options)?;
        AuthorisedFile::adopt(self.environment_id, file, leaf, policy)
    }

    /// Creates a descendant exclusively, refusing every link on the way.
    ///
    /// The file is created with owner-only permissions where the platform has them, and never with
    /// an executable bit. An existing name is refused rather than truncated.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the create failure.
    pub fn create_new(&self, name: &RelativeName) -> Result<AuthorisedFile, Escape> {
        let (parent, leaf) = self.walk(name)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        no_wait(&mut options);
        owner_only_file(&mut options);
        let file = open_leaf(&parent, leaf, &options)?;
        AuthorisedFile::adopt(self.environment_id, file, leaf, ObjectPolicy::HostOwnedFile)
    }

    /// Opens a descendant this host created, for reading and writing.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name or the object breaks.
    pub fn open_write(&self, name: &RelativeName) -> Result<AuthorisedFile, Escape> {
        let (parent, leaf) = self.walk(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        no_wait(&mut options);
        let file = open_leaf(&parent, leaf, &options)?;
        AuthorisedFile::adopt(self.environment_id, file, leaf, ObjectPolicy::HostOwnedFile)
    }

    /// Returns true when a descendant exists, whatever kind of object it is.
    #[must_use]
    pub fn exists(&self, name: &RelativeName) -> bool {
        match self.walk(name) {
            Ok((parent, leaf)) => parent.symlink_metadata(leaf).is_ok(),
            Err(_) => false,
        }
    }

    /// Renames a descendant of this directory into a descendant of `destination`.
    ///
    /// Both names are resolved component by component first, so neither side can be redirected by
    /// a link. The rename itself is one operation relative to the two opened parents.
    ///
    /// # Errors
    ///
    /// Returns the first rule either name breaks, or the rename failure.
    pub fn rename_into(
        &self,
        name: &RelativeName,
        destination: &Self,
        destination_name: &RelativeName,
    ) -> Result<(), Escape> {
        let (from_parent, from_leaf) = self.walk(name)?;
        let (to_parent, to_leaf) = destination.walk(destination_name)?;
        from_parent
            .rename(from_leaf, &to_parent, to_leaf)
            .map_err(|error| Escape::Unopenable {
                component: destination_name.as_str().to_owned(),
                detail: error.to_string(),
            })
    }

    /// Removes a descendant, whether it is a file or a link.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the removal failure. A name that is already
    /// absent succeeds.
    pub fn remove(&self, name: &RelativeName) -> Result<(), Escape> {
        let (parent, leaf) = self.walk(name)?;
        match parent.remove_file_or_symlink(leaf) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Escape::Unopenable {
                component: leaf.to_owned(),
                detail: error.to_string(),
            }),
        }
    }

    /// Returns the host path of a descendant, for a grant that has to name one.
    ///
    /// This is the one place a path leaves the authority, and it is never how the host itself
    /// reaches a file: it is what a narrow read grant hands to an agent that must open the file
    /// with its own tools.
    #[must_use]
    pub fn host_path(&self, name: &RelativeName) -> PathBuf {
        let mut path = self.display.clone();
        for component in name.components() {
            path.push(component);
        }
        path
    }

    fn clone_handle(&self) -> Result<Dir, Escape> {
        self.directory
            .try_clone()
            .map_err(|error| Escape::Unopenable {
                component: self.display.display().to_string(),
                detail: error.to_string(),
            })
    }

    /// Opens every component but the last, returning that parent and the leaf name.
    fn walk<'a>(&self, name: &'a RelativeName) -> Result<(Dir, &'a str), Escape> {
        let mut components = name.components();
        let leaf = components.pop().ok_or(Escape::Empty)?;
        let mut directory = self.clone_handle()?;
        for component in components {
            directory = open_child_directory(&directory, component)?;
        }
        Ok((directory, leaf))
    }
}

/// An opened object beneath an authorised directory.
#[derive(Debug)]
pub struct AuthorisedFile {
    environment_id: EnvironmentId,
    file: File,
    identity: ObjectIdentity,
    byte_len: u64,
    policy: ObjectPolicy,
}

impl AuthorisedFile {
    fn adopt(
        environment_id: EnvironmentId,
        file: File,
        what: &str,
        policy: ObjectPolicy,
    ) -> Result<Self, Escape> {
        // The metadata comes from the open handle, not from the name: what was opened is what is
        // checked, so a name replaced between the open and the check decides nothing.
        let metadata = file.metadata().map_err(|error| Escape::Unopenable {
            component: what.to_owned(),
            detail: error.to_string(),
        })?;
        policy.check(&metadata, what)?;
        Ok(Self {
            environment_id,
            identity: ObjectIdentity {
                device: metadata.dev(),
                file_id: metadata.ino(),
            },
            byte_len: metadata.len(),
            file,
            policy,
        })
    }

    /// Returns the environment this handle belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the identity read through the handle when it was opened.
    #[must_use]
    pub const fn identity(&self) -> ObjectIdentity {
        self.identity
    }

    /// Returns the length read through the handle when it was opened.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Returns the underlying handle.
    #[must_use]
    pub const fn handle(&self) -> &File {
        &self.file
    }

    /// Returns the underlying handle for writing.
    pub const fn handle_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Consumes the wrapper and returns the handle.
    #[must_use]
    pub fn into_handle(self) -> File {
        self.file
    }

    /// Rereads the object's identity, length and kind through the handle.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::IdentityChanged`] when the identity has changed, or the policy failure
    /// when the object is no longer the kind it must be.
    pub fn revalidate(&mut self) -> Result<u64, Escape> {
        let metadata = self.file.metadata().map_err(|error| Escape::Unopenable {
            component: self.identity.to_string(),
            detail: error.to_string(),
        })?;
        self.policy.check(&metadata, "the authorised file")?;
        let found = ObjectIdentity {
            device: metadata.dev(),
            file_id: metadata.ino(),
        };
        if found != self.identity {
            return Err(Escape::IdentityChanged {
                detail: format!(
                    "the authorised file was {} and this handle now names {found}",
                    self.identity
                ),
            });
        }
        self.byte_len = metadata.len();
        Ok(self.byte_len)
    }

    /// Checks that this handle names the object whose identity was recorded earlier.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::IdentityChanged`] when the identities differ.
    pub fn check_identity(&self, expected: ObjectIdentity) -> Result<(), Escape> {
        if expected == self.identity {
            Ok(())
        } else {
            Err(Escape::IdentityChanged {
                detail: format!(
                    "this file was recorded as {expected} and now names {}",
                    self.identity
                ),
            })
        }
    }

    /// Refuses a caller from another environment.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::WrongEnvironment`] when the identities differ.
    pub fn check_environment(&self, environment_id: EnvironmentId) -> Result<(), Escape> {
        if environment_id == self.environment_id {
            Ok(())
        } else {
            Err(Escape::WrongEnvironment {
                holder: self.environment_id.to_string(),
                named: environment_id.to_string(),
            })
        }
    }
}

fn directory_identity(directory: &Dir, what: &Path) -> Result<ObjectIdentity, Escape> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| Escape::Unopenable {
            component: what.display().to_string(),
            detail: error.to_string(),
        })?;
    if !metadata.is_dir() {
        return Err(Escape::WrongKind {
            detail: format!("{} is not a directory", what.display()),
        });
    }
    Ok(ObjectIdentity {
        device: metadata.dev(),
        file_id: metadata.ino(),
    })
}

fn open_child_directory(directory: &Dir, component: &str) -> Result<Dir, Escape> {
    check_component(component)?;
    directory
        .open_dir_nofollow(component)
        .map_err(|error| classify(directory, component, &error))
}

fn open_leaf(directory: &Dir, leaf: &str, options: &OpenOptions) -> Result<File, Escape> {
    check_component(leaf)?;
    directory
        .open_with(leaf, options)
        .map_err(|error| classify(directory, leaf, &error))
}

/// Reads an open failure as a link refusal where it was one, and as an open failure otherwise.
///
/// Each platform says it differently. A no-follow open returns `ELOOP` on Linux and on Apple and
/// `EMLINK` on some BSDs; Windows has no `O_NOFOLLOW`, so `cap_std` checks the opened object and
/// returns `ERROR_STOPPED_ON_SYMLINK`, `ERROR_TOO_MANY_LINKS` or `ERROR_CANT_ACCESS_FILE` for a
/// reparse point. Because the list is platform-specific and none of it is guaranteed, the name is
/// also examined without following it: a component that is a link is reported as one whatever the
/// open said, which is the answer a caller has to be able to act on.
fn classify(directory: &Dir, component: &str, error: &std::io::Error) -> Escape {
    let owned = component.to_owned();
    if is_link_errno(error) {
        return Escape::Link { component: owned };
    }
    if directory
        .symlink_metadata(component)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Escape::Link { component: owned };
    }
    Escape::Unopenable {
        component: owned,
        detail: error.to_string(),
    }
}

#[cfg(unix)]
fn is_link_errno(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::EMLINK)
}

#[cfg(windows)]
fn is_link_errno(error: &std::io::Error) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_CANT_ACCESS_FILE, ERROR_STOPPED_ON_SYMLINK, ERROR_TOO_MANY_LINKS,
    };

    matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_STOPPED_ON_SYMLINK as i32
                || code == ERROR_TOO_MANY_LINKS as i32
                || code == ERROR_CANT_ACCESS_FILE as i32
    )
}

#[cfg(not(any(unix, windows)))]
fn is_link_errno(_error: &std::io::Error) -> bool {
    false
}

/// Refuses to wait on a name replaced with something that has an open-time handshake.
///
/// A named pipe with no writer blocks an ordinary open until one arrives. A service that opened
/// one would stop serving, so the open is non-blocking and the handle's own metadata then decides
/// whether it is a regular file at all.
#[cfg(unix)]
fn no_wait(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    options.custom_flags(libc::O_NONBLOCK);
}

#[cfg(not(unix))]
fn no_wait(_options: &mut OpenOptions) {}

/// Creates a payload file owner-only and never executable.
#[cfg(unix)]
fn owner_only_file(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    options.mode(0o600);
}

/// Windows has no mode bits and no executable bit on a file; a directory's access-control list is
/// what restricts the file, and the staging area carries an owner-only one.
#[cfg(not(unix))]
fn owner_only_file(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn create_owner_only_directory(directory: &Dir, name: &RelativeName) -> std::io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    directory.create_dir_with(name.as_str(), &builder)
}

#[cfg(not(unix))]
fn create_owner_only_directory(directory: &Dir, name: &RelativeName) -> std::io::Result<()> {
    // The staging root carries the owner-only access-control list and blocks inheritance from
    // above it; a directory created beneath it inherits that list.
    directory.create_dir(name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([5; 16]))
    }

    fn other_environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([6; 16]))
    }

    fn name(text: &str) -> RelativeName {
        RelativeName::parse(text).expect("a valid relative name")
    }

    #[test]
    fn an_absolute_name_is_not_relative() {
        assert!(matches!(
            RelativeName::parse("/etc/passwd"),
            Err(Escape::NotRelative { .. })
        ));
        assert!(matches!(
            RelativeName::parse("\\\\server\\share"),
            Err(Escape::NotRelative { .. })
        ));
        assert!(matches!(
            RelativeName::parse("C:/Windows/System32"),
            Err(Escape::NotRelative { .. })
        ));
        assert!(matches!(
            RelativeName::parse("C:notes.txt"),
            Err(Escape::NotRelative { .. })
        ));
    }

    #[test]
    fn a_traversal_segment_is_refused_wherever_it_appears() {
        assert_eq!(RelativeName::parse(".."), Err(Escape::ParentSegment));
        assert_eq!(RelativeName::parse("a/../b"), Err(Escape::ParentSegment));
        assert_eq!(RelativeName::parse("a/b/.."), Err(Escape::ParentSegment));
        assert_eq!(RelativeName::parse("./a"), Err(Escape::CurrentSegment));
        assert_eq!(RelativeName::parse("a//b"), Err(Escape::EmptyComponent));
        assert_eq!(RelativeName::parse(""), Err(Escape::Empty));
    }

    #[test]
    fn a_device_name_never_becomes_a_storage_path() {
        for text in [
            "NUL", "nul", "con", "CON.txt", "aux.png", "com1", "LPT9.dat", "prn",
        ] {
            assert!(
                matches!(RelativeName::parse(text), Err(Escape::ReservedName { .. })),
                "{text} should be refused"
            );
        }
        // A name that merely starts with those letters is an ordinary file.
        assert!(RelativeName::parse("console.log").is_ok());
        assert!(RelativeName::parse("nullable.json").is_ok());
    }

    #[test]
    fn a_name_windows_would_rewrite_is_refused() {
        for text in ["report.", "report ", "a/b./c"] {
            assert!(
                matches!(RelativeName::parse(text), Err(Escape::ForbiddenByte { .. })),
                "{text} should be refused"
            );
        }
    }

    #[test]
    fn a_control_byte_or_a_stream_name_is_refused() {
        assert!(matches!(
            RelativeName::parse("a\0b"),
            Err(Escape::ForbiddenByte { .. })
        ));
        assert!(matches!(
            RelativeName::parse("a\nb"),
            Err(Escape::ForbiddenByte { .. })
        ));
        assert!(matches!(
            RelativeName::parse("notes.txt:hidden"),
            Err(Escape::NotRelative { .. })
        ));
    }

    #[test]
    fn a_name_longer_than_the_bound_is_refused() {
        let component = "x".repeat(MAX_COMPONENT_LEN + 1);
        assert!(matches!(
            RelativeName::parse(&component),
            Err(Escape::TooLong { .. })
        ));
        let long = std::iter::repeat_n("y".repeat(MAX_COMPONENT_LEN), 20)
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            RelativeName::parse(&long),
            Err(Escape::TooLong { .. })
        ));
    }

    #[test]
    fn a_descendant_opens_and_revalidates_through_its_handle() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("payload.bin"), b"hello").expect("writes");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        let mut file = authority
            .open_read(&name("payload.bin"), ObjectPolicy::ReadableFile)
            .expect("opens the descendant");
        assert_eq!(file.byte_len(), 5);
        assert_eq!(file.revalidate().expect("revalidates"), 5);
        file.check_identity(file.identity()).expect("same object");
        assert!(matches!(
            file.check_identity(ObjectIdentity {
                device: 0,
                file_id: 0
            }),
            Err(Escape::IdentityChanged { .. })
        ));
    }

    #[test]
    fn a_handle_refuses_another_environment() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        authority
            .check_environment(environment())
            .expect("its own environment");
        assert!(matches!(
            authority.check_environment(other_environment()),
            Err(Escape::WrongEnvironment { .. })
        ));
        let file = authority.create_new(&name("payload.bin")).expect("creates");
        assert!(matches!(
            file.check_environment(other_environment()),
            Err(Escape::WrongEnvironment { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_that_leaves_the_directory_is_refused() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let outside = tempfile::tempdir().expect("a second temporary directory");
        std::fs::write(outside.path().join("secret"), b"not yours").expect("writes");
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("link"))
            .expect("links");
        std::os::unix::fs::symlink(outside.path(), root.path().join("elsewhere")).expect("links");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(matches!(
            authority.open_read(&name("link"), ObjectPolicy::ReadableFile),
            Err(Escape::Link { .. })
        ));
        assert!(matches!(
            authority.open_read(&name("elsewhere/secret"), ObjectPolicy::ReadableFile),
            Err(Escape::Link { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_that_stays_inside_the_directory_is_refused_too() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("payload.bin"), b"hello").expect("writes");
        std::os::unix::fs::symlink("payload.bin", root.path().join("alias")).expect("links");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(
            matches!(
                authority.open_read(&name("alias"), ObjectPolicy::ReadableFile),
                Err(Escape::Link { .. })
            ),
            "the policy follows no link, inside or out"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_created_payload_file_is_owner_only_and_not_executable() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        authority.create_new(&name("payload.bin")).expect("creates");
        let mode = std::fs::metadata(root.path().join("payload.bin"))
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
        assert_eq!(mode & 0o111, 0, "no executable bit");
    }

    #[test]
    fn an_exclusive_create_refuses_an_existing_name() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("payload.bin"), b"already here").expect("writes");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(authority.create_new(&name("payload.bin")).is_err());
        assert_eq!(
            std::fs::read(root.path().join("payload.bin")).expect("still there"),
            b"already here"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_exclusive_create_never_follows_a_link_to_a_file_outside() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let outside = tempfile::tempdir().expect("a second temporary directory");
        let target = outside.path().join("victim");
        std::fs::write(&target, b"untouched").expect("writes");
        std::os::unix::fs::symlink(&target, root.path().join("payload.bin")).expect("links");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(authority.create_new(&name("payload.bin")).is_err());
        assert_eq!(std::fs::read(&target).expect("still there"), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn a_payload_file_with_a_second_name_is_refused() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(root.path().join("payload.bin"), b"hello").expect("writes");
        std::fs::hard_link(
            root.path().join("payload.bin"),
            root.path().join("second-name"),
        )
        .expect("links");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(matches!(
            authority.open_write(&name("payload.bin")),
            Err(Escape::WrongKind { .. })
        ));
        // A file the host only reads may carry more than one name.
        authority
            .open_read(&name("payload.bin"), ObjectPolicy::ReadableFile)
            .expect("a readable file is not refused for its links");
    }

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_is_not_a_regular_file_and_does_not_hold_the_open() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let path = root.path().join("payload.bin");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo runs");
        assert!(status.success(), "mkfifo failed");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(matches!(
            authority.open_read(&name("payload.bin"), ObjectPolicy::ReadableFile),
            Err(Escape::WrongKind { .. })
        ));
    }

    #[test]
    fn a_directory_is_not_a_file() {
        let root = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir(root.path().join("inner")).expect("creates");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        assert!(matches!(
            authority.open_read(&name("inner"), ObjectPolicy::ReadableFile),
            Err(Escape::WrongKind { .. })
        ));
    }

    #[test]
    fn a_reopened_scope_at_a_replaced_path_is_refused() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        let original = parent.path().join("scope");
        std::fs::create_dir(&original).expect("creates");
        let first =
            AuthorisedDirectory::open_root(environment(), &original).expect("opens the root");
        let recorded = first.identity();
        drop(first);
        // The recorded tree is renamed away and an unrelated one takes its name.
        std::fs::rename(&original, parent.path().join("moved")).expect("renames");
        std::fs::create_dir(&original).expect("creates a different directory");
        let second =
            AuthorisedDirectory::open_root(environment(), &original).expect("opens the root");
        assert!(matches!(
            second.check_identity(recorded),
            Err(Escape::IdentityChanged { .. })
        ));
        // The same tree under its new name is the one the grant was recorded for.
        let moved = AuthorisedDirectory::open_root(environment(), &parent.path().join("moved"))
            .expect("opens the root");
        moved.check_identity(recorded).expect("the same object");
    }

    #[test]
    fn a_subdirectory_is_created_once_and_opened_thereafter() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        let first = authority
            .create_subdirectory(&name("a/b"))
            .expect("creates a tree");
        let second = authority
            .create_subdirectory(&name("a/b"))
            .expect("opens the same tree");
        assert_eq!(first.identity(), second.identity());
        let opened = authority.subdirectory(&name("a/b")).expect("opens it");
        assert_eq!(opened.identity(), first.identity());
    }

    #[cfg(unix)]
    #[test]
    fn a_created_subdirectory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        authority
            .create_subdirectory(&name("staged"))
            .expect("creates");
        let mode = std::fs::metadata(root.path().join("staged"))
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "mode was {mode:o}");
    }

    #[test]
    fn a_rename_between_authorities_moves_the_object_it_opened() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        let incomplete = authority
            .create_subdirectory(&name("incomplete"))
            .expect("creates");
        let complete = authority
            .create_subdirectory(&name("complete"))
            .expect("creates");
        {
            use std::io::Write as _;
            let mut file = incomplete
                .create_new(&name("staged.part"))
                .expect("creates")
                .into_handle();
            file.write_all(b"verified").expect("writes");
        }
        incomplete
            .rename_into(&name("staged.part"), &complete, &name("published.bin"))
            .expect("renames");
        assert!(!incomplete.exists(&name("staged.part")));
        assert!(complete.exists(&name("published.bin")));
        assert_eq!(
            std::fs::read(root.path().join("complete").join("published.bin")).expect("reads"),
            b"verified"
        );
    }

    #[test]
    fn removing_an_absent_name_succeeds() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        authority.remove(&name("never-there")).expect("succeeds");
    }

    #[test]
    fn a_grant_path_is_built_from_the_authority_not_from_the_caller() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");
        let path = authority.host_path(&name("complete/payload.bin"));
        assert!(path.starts_with(root.path()));
        assert!(path.ends_with("complete/payload.bin"));
    }
}
