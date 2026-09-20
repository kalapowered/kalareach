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
//!   `.`, no empty component, no NUL or other control byte, no separator other than `/`, none of
//!   the characters Windows refuses in a filename, no trailing dot or space on a component, no
//!   alternate-data-stream colon, and no Windows reserved device name with or without an
//!   extension. The same rules apply on every platform, so a name that one host accepts is a name
//!   every host accepts.
//! * A name is resolved **one component at a time, and the descent produces the object**. Each
//!   component is opened with the no-follow open against the handle above it, checked as it is
//!   opened, and then *kept open* as the directory the next component is opened in. The last
//!   component is opened in the last directory the descent checked. Nothing resolves the whole
//!   name again afterwards, because a second resolution is a second chance to land somewhere
//!   else: what a check said about a directory is true of the directory the open then happened
//!   in, which is the same object the handle holds.
//! * A component that is a symbolic link or a reparse point at the moment it is resolved fails the
//!   lookup instead of redirecting it, and so does the object itself. What a held handle costs is
//!   stated below with the other residuals.
//! * An authority can be **confined to one mount**, and one that is refuses every name that
//!   resolves through, or ends on, a directory or file somewhere else. A link is not the only way
//!   a path reaches content the path does not name: a directory mounted over a name inside the
//!   tree reaches another tree entirely, and the path that gets there crosses nothing. A bind
//!   mount shares its device with what it came from, so the device number alone does not see one,
//!   and the mount the **handle** was resolved through is what is compared: the prefix opens, the
//!   subdirectory that comes back, and the file a read returns, which is the handle the bytes come
//!   from. A caller asks for that rule when what it reads has to be the tree it named and nothing
//!   grafted into it; an authority that has not asked for it resolves as it always did.
//! * Each step is one directory-relative open: `openat2` with `RESOLVE_BENEATH` on Linux,
//!   `openat` with `O_NOFOLLOW` on the other Unix systems, a relative `NtCreateFile` on Windows.
//!   [`cap_std`] owns those three implementations, which is why this module is the policy and not
//!   the syscalls. Every platform takes the same descent. On Windows this crate adds its own check
//!   for
//!   `FILE_ATTRIBUTE_REPARSE_POINT`, because `cap_std`'s no-follow test recognises name-surrogate
//!   reparse tags (junctions and symbolic links) and not every reparse point.
//! * After the open, the object's stable filesystem identity (device and inode, or volume serial
//!   and file index) is read back **through the handle** and checked against the policy the caller
//!   asked for. A directory handle's own identity is recorded when it is opened, so a scope
//!   reopened after a restart is refused unless it finds the same object.
//! * An environment identity travels with every handle. A handle from one environment is never
//!   accepted by another, which is how a Windows path and a WSL path stay separate rather than
//!   aliasing. An operation across two handles, such as a rename, refuses two different
//!   environments before it resolves either name.
//!
//! ## What this does not do
//!
//! Three residuals, stated rather than implied.
//!
//! * It removes path-resolution races. It does not make an authorised file private: another
//!   process running as the same operating-system user can open and write a file this host has
//!   authorised, and nothing here prevents that. Where immutability matters, as it does for a
//!   download, the host stages its own copy instead of trusting an open handle.
//! * A directory moved out of the authorised tree *while* a name is being resolved through it is
//!   still descended into, and so is everything under it: the handle is what the descent holds,
//!   and a handle keeps its object wherever the name goes. Nothing re-establishes that such a
//!   directory is still beneath the root. That is the same rule the rest of this module is built
//!   on — the grant follows the object, not the name — and it is the price of the leaf being the
//!   thing the descent checked rather than whatever the name reaches next.
//! * A regular file with a **second hard link** is an alias this module does not decide. A
//!   confined authority compares the mount of every directory it descends through and of the file
//!   a read returns, so a directory or a file mounted into the tree is refused; a second name in
//!   another directory of the same filesystem is a name, not a mount, and nothing about the path
//!   says it is there.

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

/// Characters Windows refuses in a filename.
///
/// A name this crate accepts has to be a name every platform accepts, so these are refused
/// everywhere even though Unix would take them. The colon is refused earlier, for the whole name,
/// because it also introduces a drive and an alternate data stream.
const FORBIDDEN_CHARACTERS: &[char] = &['<', '>', '"', '|', '?', '*'];

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
    /// A component is a directory on another mount, and resolution beneath an authority crosses
    /// none.
    #[error(
        "{component} is on a different mount from the authorised directory, and resolution \
         beneath one crosses no mount"
    )]
    CrossedMount {
        /// The component that is somewhere else.
        component: String,
    },
    /// The operation accepts only a name with nothing to resolve above it.
    #[error("{name} is not a single component, and this operation resolves nothing above one")]
    NotSingleComponent {
        /// The name that was given.
        name: String,
    },
    /// The name does not exist beneath the authorised directory.
    ///
    /// Reported the same way an unauthorised name is, so a caller cannot learn from the refusal
    /// whether something with that name exists.
    #[error("{component} is not beneath the authorised directory")]
    NotFound {
        /// The component that was not there.
        component: String,
    },
    /// The object could not be opened for a reason the storage decided.
    ///
    /// A full disk, a read failure, a permission the operating system refused. This is a storage
    /// failure rather than an authority refusal, and it is reported as one.
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

    /// Returns true when the name is one component, with nothing to resolve above it.
    ///
    /// A one-component name is the strongest form this module offers: the open is a single
    /// directory-relative operation that nothing above it can redirect, and there is no
    /// intermediate resolution for a concurrent rename to interfere with. Every name this host
    /// gives its own payloads is one.
    #[must_use]
    pub fn is_single_component(&self) -> bool {
        !self.text.contains('/')
    }
}

impl std::fmt::Display for RelativeName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Refuses a name with anything to resolve above it.
fn single_component(name: &RelativeName) -> Result<(), Escape> {
    if name.is_single_component() {
        Ok(())
    } else {
        Err(Escape::NotSingleComponent {
            name: name.as_str().to_owned(),
        })
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
    if let Some(character) = component
        .chars()
        .find(|character| FORBIDDEN_CHARACTERS.contains(character))
    {
        return Err(Escape::ForbiddenByte {
            detail: format!("Windows refuses {character} in a filename"),
        });
    }
    // Windows strips a trailing dot or space, so `report.` and `report` would name one file while
    // reading as two names. Refusing both keeps one name meaning one file everywhere.
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(Escape::ForbiddenByte {
            detail: format!("{component} ends in a dot or a space, which Windows would strip"),
        });
    }
    if RESERVED_STEMS.contains(&device_stem(component).as_str()) {
        return Err(Escape::ReservedName {
            component: component.to_owned(),
        });
    }
    Ok(())
}

/// Returns the stem Windows would compare against its device names.
///
/// Everything from the first dot is dropped, surrounding space is dropped, and the superscript
/// digits Windows folds onto `1`, `2` and `3` are folded the same way. `NUL .txt` and `COM¹` name
/// devices; a comparison against the raw text would not say so.
fn device_stem(component: &str) -> String {
    component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim()
        .chars()
        .map(|character| match character {
            '¹' => '1',
            '²' => '2',
            '³' => '3',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// What kind of object a name is taken by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link or a reparse point, examined without following it.
    Link,
    /// Something else: a device, a socket, a named pipe.
    Other,
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

/// Which mount an opened directory was resolved through.
///
/// Two parts, because one platform answers more than another. Linux names the mount itself, which
/// is what sees a bind mount: a second mount of one filesystem shares its device with the first,
/// so a device number alone would call the two the same place. Everywhere else the device is the
/// whole of what a host can say, and it still sees a mount of another filesystem. Both are
/// compared, so neither answer is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MountId {
    mount: u64,
    device: u64,
}

impl std::fmt::Display for MountId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.mount, self.device)
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
    /// The mount this authority is confined to, when a caller asked for that rule. Absent means
    /// no name resolved beneath this directory is compared with a mount at all.
    mount: Option<MountId>,
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
        Self::from_handle(environment_id, directory, path.to_path_buf())
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
            mount: None,
            display,
        })
    }

    /// Returns this authority with the one-mount rule on it, and every authority it hands out.
    ///
    /// What the rule is for: a mount is the other way a path reaches content the path does not
    /// name, and unlike a link nothing in the path itself says so. A caller that has to read the
    /// tree it named, rather than whatever has since been grafted into it, asks for this and gets
    /// a refusal instead of the other tree's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::Unopenable`] when this host will not say which mount the directory was
    /// resolved through. The rule is refused rather than approximated: a comparison that cannot
    /// tell two mounts apart would answer every question with yes.
    pub fn confined_to_one_mount(mut self) -> Result<Self, Escape> {
        self.mount = Some(mount_of(
            &self.directory,
            &self.display.display().to_string(),
        )?);
        Ok(self)
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

    /// Returns a second authority over the same open directory, with the same rule on it.
    ///
    /// The handle is duplicated, not reopened: two authorities over one object, which is what a
    /// caller needs when one of them is going to be consumed and the object must stay reachable.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::Unopenable`] when the handle cannot be duplicated.
    pub fn try_clone(&self) -> Result<Self, Escape> {
        let handle = self
            .directory
            .try_clone()
            .map_err(|error| Escape::Unopenable {
                component: self.display.display().to_string(),
                detail: error.to_string(),
            })?;
        let held = Self::from_handle(self.environment_id, handle, self.display.clone())?;
        if self.mount.is_some() {
            return held.confined_to_one_mount();
        }
        Ok(held)
    }

    /// Returns the mount this authority is confined to, when it is confined to one.
    #[must_use]
    pub const fn mount(&self) -> Option<MountId> {
        self.mount
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

    /// Checks that this directory's access rules still meet the policy.
    ///
    /// The rules are read from the opened handle rather than from the path, so what is checked is
    /// the directory this authority holds and not whatever the name resolves to now.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::WrongKind`] when the rules do not meet the policy, and
    /// [`Escape::Unopenable`] when they cannot be read.
    pub fn check_privacy(&self, privacy: Privacy) -> Result<(), Escape> {
        owner_only(
            &self.directory,
            &self.display.display().to_string(),
            privacy,
        )
    }

    /// Opens a subdirectory as an authority of its own, following no link.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the open failure.
    pub fn subdirectory(&self, name: &RelativeName) -> Result<Self, Escape> {
        let (above, leaf) = self.descend(name)?;
        let directory = open_step(&above, &leaf, name.as_str())?;
        let mut display = self.display.clone();
        for component in name.components() {
            display.push(component);
        }
        let child = Self::from_handle(self.environment_id, directory, display)?;
        // The mount of what was opened, rather than of the prefix that was checked and let go: a
        // name mounted over between the two resolutions is refused here. The rule travels with the
        // authority, so everything the caller reaches through this one carries it too.
        self.confine_like_me(child, name.as_str())
    }

    /// Creates a subdirectory, owner-only, and opens it as an authority of its own.
    ///
    /// An existing directory is opened rather than replaced; an existing non-directory is refused.
    /// Every component is created and opened against this directory's own handle with the
    /// accumulated path, so the boundary is this directory at every step.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name breaks, or the create or open failure.
    pub fn create_subdirectory(&self, name: &RelativeName) -> Result<Self, Escape> {
        // One component, so this directory's own handle is the whole resolution. A creation is the
        // operation a later refusal cannot undo, so a caller that wants a tree creates each level
        // against the authority the level above it returned rather than naming a path.
        single_component(name)?;
        let component = name.as_str();
        check_component(component)?;
        match create_owner_only_directory(&self.directory, component) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Escape::Unopenable {
                    component: component.to_owned(),
                    detail: error.to_string(),
                });
            }
        }
        let child = open_directory(&self.directory, component)?;
        // A directory beneath a boundary inherits the boundary's owner entry on Windows by design,
        // so what is checked here is the accounts its list names.
        owner_only(&child, component, Privacy::OwnerOnly)?;
        // The entry that names the new directory is durable before anything inside it is created,
        // so a power loss cannot leave a payload in a directory the parent forgot.
        self.sync()?;
        let mut display = self.display.clone();
        display.push(component);
        let child = Self::from_handle(self.environment_id, child, display)?;
        self.confine_like_me(child, component)
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
        let (above, leaf) = self.descend(name)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        no_wait(&mut options);
        let file = open_object_as(&above, &leaf, name.as_str(), &options)?;
        let opened = AuthorisedFile::adopt(self.environment_id, file, name.as_str(), policy)?;
        // The handle the bytes will come from, on the mount this authority is confined to. A
        // directory checked and then mounted over is not reachable from here, because the open
        // above happened in the directory the descent is holding; what this catches is the last
        // component itself being somewhere else.
        if let Some(mount) = self.mount
            && mount_of_file(opened.handle(), name.as_str())? != mount
        {
            return Err(Escape::CrossedMount {
                component: name.as_str().to_owned(),
            });
        }
        Ok(opened)
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
        // One component, so this directory's own handle is the whole resolution. A creation is the
        // one operation a later refusal cannot undo, so it never depends on a prefix that could
        // have been replaced between being checked and being resolved.
        single_component(name)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        no_wait(&mut options);
        owner_only_file(&mut options);
        let file = open_object(&self.directory, name.as_str(), &options)?;
        let opened = AuthorisedFile::adopt(
            self.environment_id,
            file,
            name.as_str(),
            ObjectPolicy::HostOwnedFile,
        )?;
        Ok(opened)
    }

    /// Opens a descendant this host created, for reading and writing.
    ///
    /// # Errors
    ///
    /// Returns the first rule the name or the object breaks.
    pub fn open_write(&self, name: &RelativeName) -> Result<AuthorisedFile, Escape> {
        // One component, for the same reason a creation is: what is written cannot be unwritten.
        single_component(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        no_wait(&mut options);
        let file = open_object(&self.directory, name.as_str(), &options)?;
        let opened = AuthorisedFile::adopt(
            self.environment_id,
            file,
            name.as_str(),
            ObjectPolicy::HostOwnedFile,
        )?;
        if let Some(mount) = self.mount
            && mount_of_file(opened.handle(), name.as_str())? != mount
        {
            return Err(Escape::CrossedMount {
                component: name.as_str().to_owned(),
            });
        }
        Ok(opened)
    }

    /// Reports what kind of object a descendant is, without following a link to find out.
    ///
    /// A caller that has to distinguish "it is not there" from "the storage would not say" needs
    /// both answers, which is why this reports the refusal rather than a boolean.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::NotFound`] when the name is absent, or the storage failure when the
    /// platform would not answer.
    pub fn probe(&self, name: &RelativeName) -> Result<ObjectKind, Escape> {
        let (above, leaf) = self.descend(name)?;
        match above.symlink_metadata(&leaf) {
            Ok(metadata) => {
                let kind = metadata.file_type();
                Ok(if kind.is_symlink() {
                    ObjectKind::Link
                } else if kind.is_dir() {
                    ObjectKind::Directory
                } else if kind.is_file() {
                    ObjectKind::File
                } else {
                    ObjectKind::Other
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(Escape::NotFound {
                component: name.as_str().to_owned(),
            }),
            Err(error) => Err(named(classify(&above, &leaf, &error), name.as_str())),
        }
    }

    /// Returns whether a descendant's name is taken by anything at all.
    ///
    /// A directory, a link and a device all count as taken. A storage failure is reported rather
    /// than read as an absence, because a caller that treated it as one would overwrite something
    /// it could not see.
    ///
    /// # Errors
    ///
    /// Returns the storage failure when the platform would not answer.
    pub fn occupied(&self, name: &RelativeName) -> Result<bool, Escape> {
        match self.probe(name) {
            Ok(_) => Ok(true),
            Err(Escape::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Renames a descendant of this directory into a descendant of `destination`.
    ///
    /// Both names have every prefix resolved against their own authorised directory first, so
    /// neither side can be redirected by a link, and the rename itself is one operation relative
    /// to the two authorised handles.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::WrongEnvironment`] when the two handles belong to different environments,
    /// the first rule either name breaks, or the rename failure.
    pub fn rename_into(
        &self,
        name: &RelativeName,
        destination: &Self,
        destination_name: &RelativeName,
    ) -> Result<(), Escape> {
        // Two environments are never one filesystem authority, even when they share a disk.
        destination.check_environment(self.environment_id)?;
        // Both names are one component, so the rename is a single operation relative to the two
        // authorised handles with nothing resolved above either. A multi-component name would put
        // two resolutions before the rename and a window between them, which is the one thing a
        // mutation across two directories must not have.
        single_component(name)?;
        single_component(destination_name)?;
        check_component(name.as_str())?;
        check_component(destination_name.as_str())?;
        self.directory
            .rename(
                name.as_str(),
                &destination.directory,
                destination_name.as_str(),
            )
            .map_err(|error| Escape::Unopenable {
                component: destination_name.as_str().to_owned(),
                detail: error.to_string(),
            })
    }

    /// Links a descendant of this directory to a name in `destination` that must not exist.
    ///
    /// The one portable atomic no-replace publish. A link fails when the destination name is
    /// taken, on every platform, so a file that appeared between a check and a publish is never
    /// overwritten. Both names are one component for the same reason a rename's are.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::WrongEnvironment`] for two environments, the first rule either name
    /// breaks, or the link failure, which includes the destination already existing.
    pub fn link_into(
        &self,
        name: &RelativeName,
        destination: &Self,
        destination_name: &RelativeName,
    ) -> Result<(), Escape> {
        destination.check_environment(self.environment_id)?;
        single_component(name)?;
        single_component(destination_name)?;
        check_component(name.as_str())?;
        check_component(destination_name.as_str())?;
        self.directory
            .hard_link(
                name.as_str(),
                &destination.directory,
                destination_name.as_str(),
            )
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
        // One component, as for every other operation that changes what a directory holds.
        single_component(name)?;
        match self.directory.remove_file_or_symlink(name.as_str()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Escape::Unopenable {
                component: name.as_str().to_owned(),
                detail: error.to_string(),
            }),
        }
    }

    /// Flushes this directory's own entries to storage.
    ///
    /// A payload file that is created, or renamed into the completed area, is not durable until
    /// the directory that names it is. The journal commits after this, so a record that says a
    /// file exists is never more durable than the name.
    ///
    /// # Errors
    ///
    /// Returns [`Escape::Unopenable`] when the flush fails.
    pub fn sync(&self) -> Result<(), Escape> {
        sync_directory(&self.directory).map_err(|error| Escape::Unopenable {
            component: self.display.display().to_string(),
            detail: error.to_string(),
        })
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

    /// Opens every component above the last one, keeping each handle as the next one's parent.
    ///
    /// This is the whole of how a name is resolved here. Each step is opened with the no-follow
    /// open against the handle above it, checked where the authority has something to check, and
    /// then held: the directory that comes back is the directory the next component is opened in,
    /// and for the last component it is the directory the caller's object is opened in. Nothing
    /// resolves the name again afterwards, so nothing that was checked can be replaced by
    /// something that was not between the check and the open.
    ///
    /// What comes back is that last directory and the final component, unopened.
    fn descend(&self, name: &RelativeName) -> Result<(Dir, String), Escape> {
        let components = name.components();
        let Some((leaf, above)) = components.split_last() else {
            return Err(Escape::Empty);
        };
        check_component(leaf)?;
        let mut here = self
            .directory
            .try_clone()
            .map_err(|error| Escape::Unopenable {
                component: self.display.display().to_string(),
                detail: error.to_string(),
            })?;
        let mut walked = String::new();
        for component in above {
            check_component(component)?;
            if !walked.is_empty() {
                walked.push('/');
            }
            walked.push_str(component);
            let step = open_step(&here, component, &walked)?;
            // And, where the caller asked for it, on the mount this authority is confined to. A
            // directory mounted over a name inside the tree holds content the name never named,
            // reached by a path that crosses no link, so a name that descends through one does
            // not resolve at all.
            if let Some(mount) = self.mount
                && mount_of(&step, &walked)? != mount
            {
                return Err(Escape::CrossedMount { component: walked });
            }
            here = step;
        }
        Ok((here, (*leaf).to_owned()))
    }

    /// Gives an authority this one hands out the same mount rule, and refuses one somewhere else.
    fn confine_like_me(&self, child: Self, what: &str) -> Result<Self, Escape> {
        let Some(mount) = self.mount else {
            return Ok(child);
        };
        let child = child.confined_to_one_mount()?;
        if child.mount == Some(mount) {
            Ok(child)
        } else {
            Err(Escape::CrossedMount {
                component: what.to_owned(),
            })
        }
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

    /// Returns true when this file carries protection beyond its mode bits.
    ///
    /// Asked of **this handle**, never of a name: a name asked twice can be two different files,
    /// and what a caller decides from this is whether replacing the file would take protection
    /// away from it or give protection to it.
    ///
    /// Each platform keeps its list somewhere else and this asks each in its own way. A POSIX list
    /// includes the mode bits themselves, and the kernel writes its extended attribute only when
    /// there is something a mode cannot say; an Apple list lives beside the mode bits, reachable
    /// only through the platform's own interface. A platform this host does not know how to ask
    /// answers false, which is the answer that leaves a caller carrying the mode bits alone.
    #[must_use]
    pub fn carries_access_control(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd as _;

            crate::apple::carries_access_control(self.file.as_fd())
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd as _;

            match rustix::fs::fgetxattr(
                self.file.as_fd(),
                "system.posix_acl_access",
                &mut [0_u8; 0][..],
            ) {
                // There is one, and this asked for its length rather than reading it.
                Ok(_) | Err(rustix::io::Errno::RANGE) => true,
                // No such attribute, or a filesystem that keeps none.
                Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => false,
                // A file this host could not ask about is one whose protection it cannot say it
                // can carry across.
                Err(_) => true,
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            // A platform this host does not know how to ask. It answers false, which leaves a
            // caller carrying the mode bits alone, and that is what the callers state as a limit
            // rather than something this establishes.
            false
        }
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

/// How strictly a directory's access rules are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privacy {
    /// Only this user may reach the directory.
    OwnerOnly,
    /// Only this user may reach it, and nothing above it can widen it later.
    ///
    /// This is the check for the directory that is the boundary of the service's own storage. On
    /// Unix it is the same check: a directory's mode is its own, and the directory above it cannot
    /// change it. On Windows a list can be inherited, so a boundary is additionally required to
    /// hold a protected list, which is what stops the user profile above from propagating an entry
    /// into it.
    Boundary,
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

/// Returns the mount an open directory was resolved through.
///
/// The kernel's own answer: `statx` carries the mount a handle was resolved through, which is what
/// tells a bind mount from the tree it was made from. A kernel too old to carry it reports so in
/// the mask, and then this refuses rather than comparing device numbers a bind mount would
/// satisfy.
#[cfg(target_os = "linux")]
fn mount_of_handle(handle: impl std::os::fd::AsFd, what: &str) -> Result<MountId, Escape> {
    let stat = rustix::fs::statx(
        handle,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::MNT_ID,
    )
    .map_err(|error| Escape::Unopenable {
        component: what.to_owned(),
        detail: error.to_string(),
    })?;
    mount_reported(
        stat.stx_mask,
        stat.stx_mnt_id,
        rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor),
        what,
    )
}

/// Turns what the kernel said it filled in into a mount, or into a refusal.
///
/// The kernel reports which fields it answered. One too old to carry the mount leaves this one
/// out, and then every object answers the same and the comparison says yes to everything. A caller
/// that asked to stay on one mount is told this host cannot tell, rather than being given a
/// comparison that cannot fail.
#[cfg(target_os = "linux")]
fn mount_reported(mask: u32, mount: u64, device: u64, what: &str) -> Result<MountId, Escape> {
    if mask & rustix::fs::StatxFlags::MNT_ID.bits() == 0 {
        return Err(Escape::Unopenable {
            component: what.to_owned(),
            detail: "this host does not report which mount an object was resolved through, and \
                     an authority confined to one mount cannot be established without it"
                .to_owned(),
        });
    }
    Ok(MountId { mount, device })
}

/// Returns the mount an open directory was resolved through.
#[cfg(target_os = "linux")]
fn mount_of(directory: &Dir, what: &str) -> Result<MountId, Escape> {
    mount_of_handle(directory, what)
}

/// Returns the mount an open file was resolved through.
#[cfg(target_os = "linux")]
fn mount_of_file(file: &File, what: &str) -> Result<MountId, Escape> {
    mount_of_handle(file, what)
}

/// Returns the device an open directory is on, which is what this platform says about mounts.
#[cfg(not(target_os = "linux"))]
fn mount_of(directory: &Dir, what: &str) -> Result<MountId, Escape> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| Escape::Unopenable {
            component: what.to_owned(),
            detail: error.to_string(),
        })?;
    Ok(MountId {
        mount: 0,
        device: metadata.dev(),
    })
}

/// Returns the device an open file is on, which is what this platform says about mounts.
#[cfg(not(target_os = "linux"))]
fn mount_of_file(file: &File, what: &str) -> Result<MountId, Escape> {
    let metadata = file.metadata().map_err(|error| Escape::Unopenable {
        component: what.to_owned(),
        detail: error.to_string(),
    })?;
    Ok(MountId {
        mount: 0,
        device: metadata.dev(),
    })
}

/// Opens one component of a descent, reporting it by the path walked so far.
fn open_step(parent: &Dir, component: &str, walked: &str) -> Result<Dir, Escape> {
    let opened = parent
        .open_dir_nofollow(component)
        .map_err(|error| named(classify(parent, component, &error), walked))?;
    refuse_reparse_point(&opened, walked)?;
    Ok(opened)
}

/// Opens one object in the directory a descent reached, reported by the name the caller gave.
fn open_object_as(
    parent: &Dir,
    component: &str,
    reported: &str,
    options: &OpenOptions,
) -> Result<File, Escape> {
    let opened = parent
        .open_with(component, options)
        .map_err(|error| named(classify(parent, component, &error), reported))?;
    refuse_reparse_file(&opened, reported)?;
    Ok(opened)
}

/// Reports a refusal by the whole name the caller gave rather than by the component it reached.
fn named(escape: Escape, reported: &str) -> Escape {
    match escape {
        Escape::Link { .. } => Escape::Link {
            component: reported.to_owned(),
        },
        Escape::NotFound { .. } => Escape::NotFound {
            component: reported.to_owned(),
        },
        Escape::Unopenable { detail, .. } => Escape::Unopenable {
            component: reported.to_owned(),
            detail,
        },
        other => other,
    }
}

/// Opens one path beneath `directory`, refusing a link at its final component.
fn open_directory(directory: &Dir, path: &str) -> Result<Dir, Escape> {
    let opened = directory
        .open_dir_nofollow(path)
        .map_err(|error| classify(directory, path, &error))?;
    refuse_reparse_point(&opened, path)?;
    Ok(opened)
}

/// Opens one object beneath `directory` with the caller's options.
fn open_object(directory: &Dir, path: &str, options: &OpenOptions) -> Result<File, Escape> {
    let opened = directory
        .open_with(path, options)
        .map_err(|error| classify(directory, path, &error))?;
    refuse_reparse_file(&opened, path)?;
    Ok(opened)
}

/// Refuses an opened directory that is a reparse point of any tag.
///
/// `cap_std`'s no-follow test on Windows recognises the name-surrogate tags, which covers
/// junctions and symbolic links and not every reparse point. This check is the attribute itself,
/// read from the handle that was opened.
#[cfg(windows)]
fn refuse_reparse_point(directory: &Dir, path: &str) -> Result<(), Escape> {
    use cap_primitives::fs::_WindowsByHandle as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = directory
        .dir_metadata()
        .map_err(|error| classify(directory, path, &error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Escape::Link {
            component: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn refuse_reparse_point(_directory: &Dir, _path: &str) -> Result<(), Escape> {
    Ok(())
}

/// Refuses an opened file that is a reparse point of any tag.
#[cfg(windows)]
fn refuse_reparse_file(file: &File, path: &str) -> Result<(), Escape> {
    use cap_primitives::fs::_WindowsByHandle as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file.metadata().map_err(|error| Escape::Unopenable {
        component: path.to_owned(),
        detail: error.to_string(),
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Escape::Link {
            component: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn refuse_reparse_file(_file: &File, _path: &str) -> Result<(), Escape> {
    Ok(())
}

/// Checks that a directory belongs to this user and is owner-only.
///
/// The policy is the same for both strictnesses here: a Unix directory's mode belongs to the
/// directory, and the one above it cannot widen it.
#[cfg(unix)]
fn owner_only(directory: &Dir, path: &str, _privacy: Privacy) -> Result<(), Escape> {
    use cap_std::fs::MetadataExt as _;

    let metadata = directory
        .dir_metadata()
        .map_err(|error| classify(directory, path, &error))?;
    let expected = rustix_uid();
    if metadata.uid() != expected {
        return Err(Escape::WrongKind {
            detail: format!(
                "{path} belongs to user {} and this host runs as {expected}",
                metadata.uid()
            ),
        });
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(Escape::WrongKind {
            detail: format!(
                "{path} is mode {:o} and a KalaReach directory is owner-only",
                metadata.mode() & 0o777
            ),
        });
    }
    Ok(())
}

/// Checks the access-control list of a directory on Windows, which is where its access rules live.
///
/// The list is read from the handle that was opened, so an existing directory is checked rather
/// than adopted. A list that names any account except the directory's owner, the local system and
/// the administrators group is refused; so is one whose entries this host cannot evaluate. A
/// boundary additionally has to hold a protected list.
#[cfg(not(unix))]
fn owner_only(directory: &Dir, path: &str, privacy: Privacy) -> Result<(), Escape> {
    use std::os::windows::io::AsHandle as _;

    let outcome = crate::windows::check_access_list(
        directory.as_handle(),
        path,
        matches!(privacy, Privacy::Boundary),
    );
    match outcome {
        Ok(()) => Ok(()),
        Err(crate::windows::Refusal::Policy(detail)) => Err(Escape::WrongKind { detail }),
        Err(crate::windows::Refusal::Unreadable(detail)) => Err(Escape::Unopenable {
            component: path.to_owned(),
            detail,
        }),
    }
}

#[cfg(unix)]
fn rustix_uid() -> u32 {
    kr_ipc::paths::current_uid()
}

/// Flushes a directory's entries to storage.
#[cfg(unix)]
fn sync_directory(directory: &Dir) -> std::io::Result<()> {
    use std::os::fd::AsFd as _;

    // A duplicate of this handle is not enough. `cap-std` opens a directory with `O_PATH` where
    // the platform has it, which is a reference to the directory rather than a file description,
    // and Linux refuses to flush one. So the flush opens a descriptor of its own for the same
    // directory, relative to the handle and never by path, and flushes that.
    let flushable = rustix::fs::openat(
        directory.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    rustix::fs::fsync(&flushable).map_err(std::io::Error::from)
}

/// Windows refuses a flush on a directory handle, and a rename inside one volume is the platform's
/// own ordered metadata operation. The Windows qualification pass records what that leaves open.
#[cfg(not(unix))]
fn sync_directory(_directory: &Dir) -> std::io::Result<()> {
    Ok(())
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
    // Examined without following it. A name replaced between the failed open and this look is
    // reported as whichever it is now, which changes the diagnosis and never the refusal: the open
    // failed either way.
    if directory
        .symlink_metadata(component)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Escape::Link { component: owned };
    }
    if error.kind() == std::io::ErrorKind::NotFound {
        return Escape::NotFound { component: owned };
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
fn create_owner_only_directory(directory: &Dir, path: &str) -> std::io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    directory.create_dir_with(path, &builder)
}

#[cfg(not(unix))]
fn create_owner_only_directory(directory: &Dir, path: &str) -> std::io::Result<()> {
    // The staging root carries the owner-only access-control list and blocks inheritance from
    // above it; a directory created beneath it inherits that list.
    directory.create_dir(path)
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
        // A tree is created one level at a time, each against the authority the level above
        // returned: a creation names one entry in the directory whose handle is held.
        let outer = authority
            .create_subdirectory(&name("a"))
            .expect("creates the first level");
        let first = outer
            .create_subdirectory(&name("b"))
            .expect("creates the second");
        let second = outer
            .create_subdirectory(&name("b"))
            .expect("opens the same directory");
        assert_eq!(first.identity(), second.identity());
        // A read may still name a path, and it finds the same object.
        let opened = authority.subdirectory(&name("a/b")).expect("opens it");
        assert_eq!(opened.identity(), first.identity());
    }

    #[test]
    fn a_created_directory_names_one_entry() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority =
            AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the root");

        assert!(matches!(
            authority.create_subdirectory(&name("a/b")),
            Err(Escape::NotSingleComponent { .. })
        ));
        assert!(!root.path().join("a").exists(), "and created nothing");
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
        assert!(
            !incomplete
                .occupied(&name("staged.part"))
                .expect("the storage answers")
        );
        assert!(
            complete
                .occupied(&name("published.bin"))
                .expect("the storage answers")
        );
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

    /// A host that will not say which mount an object was resolved through cannot be confined to
    /// one, and says so instead of comparing something that cannot differ.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mount_the_kernel_did_not_report_is_a_refusal_rather_than_a_comparison() {
        let reported = rustix::fs::StatxFlags::MNT_ID.bits();
        let mount = mount_reported(reported, 42, 7, "a directory").expect("a reported mount");
        assert_eq!(
            mount,
            mount_reported(reported, 42, 7, "the same directory").expect("the same answer"),
            "one reported mount answers the same twice"
        );
        assert_ne!(
            mount,
            mount_reported(reported, 43, 7, "another directory").expect("another mount"),
            "two mounts of one device are two mounts, which is what a bind mount is"
        );
        let refusal = mount_reported(0, 0, 7, "a directory")
            .expect_err("a kernel that reported no mount is not a mount of its own");
        assert!(
            matches!(refusal, Escape::Unopenable { ref detail, .. } if detail.contains("does not report which mount")),
            "the refusal says the host cannot tell: {refusal}"
        );
    }
}
