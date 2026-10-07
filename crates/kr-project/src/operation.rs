//! Destinations, staged publication and the reconciliation of an interrupted one.
//!
//! Section 14 paragraph 2 gives the shape of `project.init`, `project.clone` and `project.adopt` in
//! four clauses, and this module is each of them:
//!
//! * **Authorised destination handles.** A destination is a parent directory resolved once into an
//!   open directory descriptor and one single-component name inside it. Every check and every
//!   mutation is relative to that handle, so a rename above it cannot redirect the operation.
//! * **Reject a nonempty or existing destination.** [`Destination::probe`] says what is there, and
//!   anything at all is refused unless the caller explicitly chose the one supported adoption flow.
//!   Nothing is ever merged into an existing directory.
//! * **Stage new content in a private sibling and publish without replacing an unexpected entry.**
//!   The sibling is `.kr-project-<32 hexadecimal characters>` in the same parent, so the
//!   publication is a rename inside one directory. The rename refuses to replace anything at all,
//!   through `renameat2(RENAME_NOREPLACE)` on Linux and `renameatx_np(RENAME_EXCL)` on Apple.
//! * **Reconcile a crash or an ambiguous publish against the create token.** The operation row's
//!   key is the caller's action identifier, and the staged repository's filesystem identity is
//!   recorded before the rename. So the question after a crash is never "does the name exist" but
//!   "which name holds *that object*", which has one answer.
//!
//! Cancellation is the fifth clause. A cancellation sets the operation's flag; the Git invocation
//! that holds the child process sees it, ends the child it started, and the result names every
//! staging path that was removed and every one that was kept.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::ids::EnvironmentId;
use kr_protocol::project::{
    DestinationParent, DestinationRequest, DestinationState, LocationPurpose, MAX_NAME_LEN,
    OPERATION_DEADLINE, RemoteTransport,
};
use kr_transfer::authority::ObjectKind;
use kr_transfer::{
    AuthorisedDirectory, ObjectIdentity, Privacy, RecordedIdentity, RelativeName, Settled,
};

use crate::credential::ValidatedRemote;
use crate::error::{ProjectError, Result};
use crate::git::{Cancellation, GitRequest, ReadAdmission, RestrictedProfile};
use crate::policy::{Admitting, HeldLocation, LocationPolicy, LocationUse};

/// The prefix of the private sibling a repository operation stages its content in.
///
/// It starts with a dot so it is hidden on Unix, and it names this host so a person who finds one
/// knows what left it. A cancellation and the recovery both report it by name.
pub const STAGING_PREFIX: &str = ".kr-project-";

/// The name the staged repository is created under inside the staging directory.
pub const STAGED_TREE: &str = "tree";

/// One authorised destination: the parent's handle, and one name inside it.
///
/// The handle is not handed out. Every method that resolves, reads, creates, renames or removes
/// anything beneath it asks the location's admission first, once, for the one read or effect it
/// performs, and so does every [`StagingSibling`] made beneath it: no read through a location can
/// start after a withdrawal commits, because nothing can reach the handle without asking.
#[derive(Debug)]
pub struct Destination {
    parent: AuthorisedDirectory,
    parent_path: PathBuf,
    name: RelativeName,
    /// The location the parent is, when the request named one: the policy's own reference, kept
    /// for as long as the destination is used.
    location: Option<Arc<HeldLocation>>,
    /// What every read and every effect beneath the parent asks immediately before it starts, when
    /// the parent is a location. None for a parent the owner named by path.
    admission: Option<ReadAdmission>,
}

impl Destination {
    /// Resolves a caller's destination request into a handle and a name.
    ///
    /// A host path is resolved once, here, with this host's own authority, and only a caller who
    /// holds no grant may name one. A location is not resolved at all: its parent is the handle the
    /// policy holds for it, admitted for this caller as a destination in this environment, and the
    /// policy's own reference to it is kept so the transaction that begins the effect, and every
    /// read after it, can prove it is still the one admitted. The name is one component with no
    /// separator, no traversal segment and no reserved device name, because the creation that
    /// follows is the operation a later refusal cannot undo.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the parent cannot be opened or the name is not
    /// one component, [`ProjectError::WrongEnvironment`] when the request names another
    /// environment, or [`ProjectError::PermissionDenied`] when the caller may not name that
    /// parent.
    pub fn resolve(
        request: &DestinationRequest,
        environment_id: EnvironmentId,
        policy: &LocationPolicy,
        admitting: Admitting,
    ) -> Result<Self> {
        if request.environment_id != environment_id {
            return Err(ProjectError::WrongEnvironment {
                named: request.environment_id.to_string().into(),
                owned: environment_id.to_string().into(),
            });
        }
        if request.name.len() > MAX_NAME_LEN {
            return Err(ProjectError::Destination {
                detail: format!(
                    "a destination name is at most {MAX_NAME_LEN} bytes and this one is {}",
                    request.name.len()
                )
                .into(),
            });
        }
        let name = RelativeName::parse(&request.name)?;
        if !name.is_single_component() {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} is more than one name; a repository is created as one entry in the \
                     directory whose handle this host holds",
                    crate::git::redact(&request.name)
                )
                .into(),
            });
        }
        match &request.parent {
            DestinationParent::Host { path } => {
                if let Admitting::Caller(Some(grant)) = admitting {
                    return Err(ProjectError::PermissionDenied {
                        detail: format!(
                            "a caller bounded by grant {grant} names a location for a destination, \
                             never a path on this host"
                        )
                        .into(),
                    });
                }
                let parent_path = PathBuf::from(path);
                if !parent_path.is_absolute() {
                    return Err(ProjectError::Destination {
                        detail: format!(
                            "{} is not an absolute path; a destination's parent is named \
                             absolutely and resolved once",
                            crate::git::redact(&parent_path.display().to_string())
                        )
                        .into(),
                    });
                }
                let parent = AuthorisedDirectory::open_root(environment_id, &parent_path)?;
                Ok(Self {
                    parent,
                    parent_path,
                    name,
                    location: None,
                    admission: None,
                })
            }
            DestinationParent::Location { location_id } => {
                let wanted = LocationUse {
                    purpose: LocationPurpose::Destination,
                    environment_id,
                    admitting,
                };
                let held = policy.admit(*location_id, &wanted)?;
                let admission =
                    crate::service::admission_for(policy, vec![(Arc::clone(&held), wanted)]);
                let parent = held.handle().try_clone()?;
                let parent_path = parent.display_path().to_path_buf();
                Ok(Self {
                    parent,
                    parent_path,
                    name,
                    location: Some(held),
                    admission,
                })
            }
        }
    }

    /// Asks the destination's location, when it has one, whether this operation may still reach
    /// beneath it. A destination the owner named by path has nothing to ask.
    ///
    /// # Errors
    ///
    /// Returns the policy's refusal once the location no longer admits this operation.
    pub fn admit(&self) -> Result<()> {
        self.admission.as_ref().map_or(Ok(()), ReadAdmission::admit)
    }

    /// Returns what every read and effect beneath this destination asks first, when its parent
    /// is a location.
    #[must_use]
    pub const fn admission(&self) -> Option<&ReadAdmission> {
        self.admission.as_ref()
    }

    /// Returns the parent's handle for one read or one effect, once the location has admitted it.
    fn reach(&self) -> Result<&AuthorisedDirectory> {
        self.admit()?;
        Ok(&self.parent)
    }

    /// Returns the location this destination's parent is, when the request named one.
    #[must_use]
    pub const fn location(&self) -> Option<&Arc<HeldLocation>> {
        self.location.as_ref()
    }

    /// Returns the parent's path, for a diagnostic.
    #[must_use]
    pub fn parent_path(&self) -> &Path {
        &self.parent_path
    }

    /// Returns the single name inside it.
    #[must_use]
    pub const fn name(&self) -> &RelativeName {
        &self.name
    }

    /// Returns the destination's full path, for a diagnostic and for `-C`.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.parent.host_path(&self.name)
    }

    /// Creates the destination directory, exclusively, and returns it as an authority.
    ///
    /// Creating a directory fails when the name is taken, on every platform, so this is the
    /// atomic no-replace step for an operation that fills the destination in place rather than
    /// renaming one into it. A linked worktree is such an operation: Git records the path inside
    /// the repository's administrative state, so the tree cannot be staged elsewhere and moved,
    /// and `git worktree add` accepts an existing empty directory.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the name is taken or the directory cannot be
    /// created.
    pub fn reserve(&self) -> Result<AuthorisedDirectory> {
        let parent = self.reach()?;
        parent
            .handle()
            .create_dir(self.name.as_str())
            .map_err(|error| ProjectError::Destination {
                detail: if error.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "{} is taken, and an isolated workspace is created rather than merged into \
                         something",
                        crate::git::redact(&self.path().display().to_string())
                    )
                    .into()
                } else {
                    format!(
                        "{} could not be created: {error}",
                        crate::git::redact(&self.path().display().to_string())
                    )
                    .into()
                },
            })?;
        parent.sync(kr_flush::NameKind::Directory)?;
        Ok(parent.subdirectory(&self.name)?)
    }

    /// Reports what is at the destination now.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the platform will not say, or the location's
    /// refusal.
    pub fn probe(&self) -> Result<DestinationState> {
        let parent = self.reach()?;
        match parent.probe(&self.name) {
            Ok(ObjectKind::Directory) => {
                let subdirectory = parent.subdirectory(&self.name)?;
                let mut entries =
                    subdirectory
                        .handle()
                        .entries()
                        .map_err(|error| ProjectError::Destination {
                            detail: format!("{} could not be listed: {error}", self.name).into(),
                        })?;
                Ok(if entries.next().is_some() {
                    DestinationState::NonEmptyDirectory
                } else {
                    DestinationState::EmptyDirectory
                })
            }
            Ok(_) => Ok(DestinationState::Occupied),
            Err(kr_transfer::Escape::NotFound { .. }) => Ok(DestinationState::Absent),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns whether nothing at all is at one name beside the destination.
    ///
    /// Only a plain absence is absence. A question the platform would not answer says nothing
    /// about what is at the name, and a caller that read it as "gone" would forget a directory
    /// that is still there. Nor does a question the location no longer admits: it is not asked.
    #[must_use]
    pub fn absent(&self, name: &RelativeName) -> bool {
        self.reach().is_ok_and(|parent| {
            matches!(
                parent.handle().symlink_metadata(name.as_str()),
                Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
            )
        })
    }

    /// Returns whether anything is at one name beside the destination.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the platform will not say, or the location's
    /// refusal.
    pub fn occupied(&self, name: &RelativeName) -> Result<bool> {
        Ok(self.reach()?.occupied(name)?)
    }

    /// Opens the directory at the destination's name and requires it to be `made`, the directory
    /// this operation made there and still holds open.
    ///
    /// Both handles were opened in this run, so a directory that is not the one `made` names is
    /// another object, and nothing is written into it. The object `made` is on cannot give its
    /// number to another while that handle is open.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when no directory is there, [`ProjectError::IdentityChanged`]
    /// when the directory at the name is not the one that was made, or the location's refusal.
    pub fn opened_as(&self, made: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
        let found = self.reach()?.subdirectory(&self.name)?;
        if found.identity() != made.identity() {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this operation made the directory {} and {} now holds {}; nothing is written \
                     into it",
                    made.identity(),
                    crate::git::redact(&self.path().display().to_string()),
                    found.identity()
                )
                .into(),
            });
        }
        Ok(found)
    }
}

/// The private sibling one operation stages its content in.
///
/// It is beneath its destination's parent, so it is beneath that destination's location when
/// there is one, and every descent into it or removal of it asks what every read through that
/// location asks. Its handle is not handed out either.
#[derive(Debug)]
pub struct StagingSibling {
    directory: AuthorisedDirectory,
    name: RelativeName,
    path: PathBuf,
    /// The destination's admission, asked immediately before each read of what is in the sibling.
    admission: Option<ReadAdmission>,
}

impl StagingSibling {
    /// Creates a private sibling of the destination, with a random name.
    ///
    /// It is a sibling rather than a child, so the publication is a rename inside one directory
    /// and cannot cross a filesystem. It is made where nothing was, owner-only, so nothing under
    /// another account reads a repository this host has not finished building, and a directory
    /// that was waiting at the name is never staged in.
    ///
    /// It is also asked, before anything is staged in it, the question its removal will ask:
    /// whether it is a directory only this account can change. One that is not, such as one that
    /// inherited an access-control list from the directory it was made in, is one this host could
    /// never show still holds only what it staged, so nothing is staged in it. It is taken away
    /// again only while it is empty, so anything somebody else put inside it stays.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be made, or when it is not
    /// one only this account can change, or the location's refusal.
    pub fn create(destination: &Destination, name: &str) -> Result<Self> {
        let name = RelativeName::parse(name)?;
        let parent = destination.reach()?;
        let path = parent.host_path(&name);
        let directory = parent
            .create_new_subdirectory(&name, Privacy::Exclusive)
            .map_err(|refusal| ProjectError::Destination {
                detail: format!(
                    "the staging directory {} could not be made as a directory only this account \
                     can change, so nothing is staged: {}",
                    crate::git::redact(&path.display().to_string()),
                    crate::git::redact(&refusal.to_string())
                )
                .into(),
            })?;
        Ok(Self {
            directory,
            name,
            path,
            admission: destination.admission.clone(),
        })
    }

    /// Returns a name for a sibling that does not exist yet.
    ///
    /// The caller records it before creating the directory, so every sibling this host makes is
    /// one a journal row accounts for. Nothing is ever removed because its name looks like one of
    /// these: a repository a user happened to call `.kr-project-something` is not this host's.
    #[must_use]
    pub fn propose() -> String {
        format!("{STAGING_PREFIX}{}", random_suffix())
    }

    /// Opens a sibling an earlier daemon created, for recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the name is not one this host would have used,
    /// or the directory cannot be opened, or the location's refusal.
    pub fn open(destination: &Destination, name: &str) -> Result<Self> {
        if !name.starts_with(STAGING_PREFIX) {
            return Err(ProjectError::Destination {
                detail: format!("{name} is not a staging directory this host created").into(),
            });
        }
        let name = RelativeName::parse(name)?;
        let parent = destination.reach()?;
        let directory = parent.subdirectory(&name)?;
        let path = parent.host_path(&name);
        Ok(Self {
            directory,
            name,
            path,
            admission: destination.admission.clone(),
        })
    }

    /// Returns the sibling's handle for one read, once the destination's location has admitted it.
    fn reach(&self) -> Result<&AuthorisedDirectory> {
        if let Some(admission) = &self.admission {
            admission.admit()?;
        }
        Ok(&self.directory)
    }

    /// Returns the sibling's name inside the parent.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the sibling's path, which a cancellation reports.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the staged repository's path.
    #[must_use]
    pub fn tree_path(&self) -> PathBuf {
        self.path.join(STAGED_TREE)
    }

    /// Returns the staged repository's filesystem identity.
    ///
    /// Recorded before the publication, so an interrupted one is resolved by asking which name
    /// holds this object rather than whether a name exists. Read by a descent from the sibling's
    /// handle, which is a read through the destination's location, so the location is asked first.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the staged repository is not there, or the
    /// location's refusal.
    pub fn staged_identity(&self) -> Result<ObjectIdentity> {
        let name = RelativeName::parse(STAGED_TREE)?;
        Ok(self.reach()?.subdirectory(&name)?.identity())
    }

    /// Returns the staged repository's identity and the instant the filesystem says it was made.
    ///
    /// A filesystem reuses a device and inode pair after the object that held it is gone, so an
    /// identity alone cannot tell this host's own staged repository from an unrelated one that
    /// inherited its numbers. The creation instant is a second witness: reuse with the same
    /// creation instant is not something a filesystem produces. Where the platform reports no
    /// creation instant the witness is the identity alone, and [`StagedWitness`] says so.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the staged repository is not there, or the
    /// location's refusal.
    pub fn staged_witness(&self) -> Result<StagedWitness> {
        staged_in(self.reach()?)
    }

    /// Returns the filesystem identity of the staged repository's own Git directory, the `.git`
    /// inside the staged tree, as the journal records it.
    ///
    /// Read before the publication with the staged tree's own identity: the rename that publishes
    /// the tree keeps the directory inside it, so what a later open finds at the tree's `.git` is
    /// this object or something that took its place. Read by a descent from the sibling's handle,
    /// which is a read through the destination's location, so the location is asked first.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the staged repository holds no `.git` directory,
    /// or the location's refusal.
    pub fn staged_git_dir(&self) -> Result<RecordedIdentity> {
        let tree = staged_tree_in(self.reach()?)?;
        Ok(tree
            .subdirectory(&RelativeName::parse(".git")?)?
            .recorded()?)
    }

    /// Returns the sibling's own object, read through its handle, for the invocations that have to
    /// run in this directory and no other.
    #[must_use]
    pub fn identity(&self) -> ObjectIdentity {
        self.directory.identity()
    }

    /// Returns the sibling's own filesystem identity as the journal records it, read through its
    /// handle.
    ///
    /// The cleanup removes a name this host recorded *and* checks that the object at that name is
    /// still this one, on the filesystem it was recorded on, so a replacement at an old name is
    /// never removed as though it were the staging directory.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be asked which filesystem it
    /// is on.
    pub fn recorded(&self) -> Result<RecordedIdentity> {
        Ok(self.directory.recorded()?)
    }

    /// Removes the sibling and everything in it, when it is still the directory this host
    /// recorded and still one only this account can change.
    ///
    /// A recorded name is not authority to remove whatever holds it now, so the handle this
    /// sibling holds has to be the object whose identity was recorded. The rest is asked of that
    /// same handle: this account owns the directory, its mode admits nobody else, and on Apple
    /// platforms it carries no access-control list. No other account can put anything at a name
    /// inside such a directory, so what the removal takes away beneath it is what this host staged
    /// or what a process of this same account put there, which already holds every authority this
    /// host has over the tree. The contents go through handles the removal holds rather than a
    /// path, and the sibling's own name goes last, only while it still holds this directory and
    /// only once it is empty.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the sibling is not the recorded object, or
    /// [`ProjectError::Destination`] when it is not a directory only this account can change or
    /// the removal stopped, or the location's refusal. A removal that stopped names where, and
    /// what it removed before then stays removed.
    pub fn remove(
        self,
        destination: &Destination,
        expected: RecordedIdentity,
        settle: Settle<'_>,
    ) -> Result<()> {
        // A removal beneath a location is an effect through it, asked for once, before anything.
        let parent = destination.reach()?;
        remove_staging_directory(
            parent,
            &self.name,
            self.directory,
            expected,
            &self.path,
            settle,
        )
    }

    /// Removes the sibling as [`Self::remove`] does, and says what that left.
    ///
    /// What a cleanup records is whether the directory is gone, and "gone" is a fact about the
    /// filesystem rather than about whether this call did the removing: a name nothing holds is
    /// free whoever freed it, and a name this host could not look at is not one it found free.
    /// A directory that is still there comes back with the refusal, which names where a removal
    /// stopped and what it removed first, so the record can say why.
    #[must_use]
    pub fn clean_up(
        self,
        destination: &Destination,
        expected: RecordedIdentity,
        settle: Settle<'_>,
    ) -> Cleanup {
        let name = self.name.clone();
        match self.remove(destination, expected, settle) {
            Ok(()) => Cleanup::Removed,
            Err(_) if destination.absent(&name) => Cleanup::Absent,
            Err(refusal) => Cleanup::Kept(refusal.to_string()),
        }
    }
}

/// What the holder of a record does with what the record is to become when a directory it names is
/// found to be the recorded one: the record is written before the removal starts, so a removal
/// that stops part way leaves a record that names the filesystem the directory was found on and a
/// retry cannot take another filesystem's directory for it.
pub(crate) type Settle<'a> = &'a dyn Fn(&Settled) -> Result<()>;

/// Removes one staging directory and everything in it through its parent's handle, when it is the
/// directory this host recorded and still one only this account can change.
///
/// `directory` is the handle opened at `name` beneath `parent`, and the caller has been admitted to
/// `parent` for this one removal. A recorded name is not authority to remove whatever holds it
/// now, so the handle has to be the object whose identity was recorded; the rest is asked of that
/// same handle: this account owns the directory, its mode admits nobody else, and on Apple
/// platforms it carries no access-control list. The contents go through handles the removal holds
/// rather than a path, and the directory's own name goes last, only while it still holds this
/// directory and only once it is empty.
///
/// # Errors
///
/// Returns [`ProjectError::IdentityChanged`] when the directory is not the recorded object, or
/// [`ProjectError::Destination`] when it is not a directory only this account can change or the
/// removal stopped. A removal that stopped names where, and what it removed before then stays
/// removed.
pub(crate) fn remove_staging_directory(
    parent: &AuthorisedDirectory,
    name: &RelativeName,
    directory: AuthorisedDirectory,
    expected: RecordedIdentity,
    shown: &Path,
    settle: Settle<'_>,
) -> Result<()> {
    let path = crate::git::redact(&shown.display().to_string());
    // The recorded directory on the filesystem it was recorded on is the recorded one, under
    // whatever device number the filesystem has now, and its record takes what it is now before
    // the removal starts.
    let Ok(settled) = directory.check_recorded(expected) else {
        return Err(ProjectError::IdentityChanged {
            detail: format!(
                "this operation staged its content in {expected} and {path} now holds {}; nothing \
                 is removed",
                directory.identity()
            )
            .into(),
        });
    };
    settle(&settled)?;
    directory
        .check_privacy(Privacy::Exclusive)
        .map_err(|refusal| ProjectError::Destination {
            detail: format!(
                "{path} is not a directory only this account can change, so this host cannot show \
                 that what is in it is only what it staged; nothing is removed: {}",
                crate::git::redact(&refusal.to_string())
            )
            .into(),
        })?;
    parent
        .remove_tree(name, directory)
        .map_err(|refusal| ProjectError::Destination {
            detail: format!(
                "{path} was not removed: {}",
                crate::git::redact(&refusal.to_string())
            )
            .into(),
        })?;
    parent.sync(kr_flush::NameKind::Directory)?;
    Ok(())
}

/// What the cleanup of one staging directory left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cleanup {
    /// This cleanup removed it.
    Removed,
    /// Nothing is at its name, though this cleanup did not remove it.
    Absent,
    /// It is still there, and why: the refusal, which names where a removal stopped, how many
    /// entries went before it did, and why it stopped.
    Kept(String),
}

impl Cleanup {
    /// Returns whether nothing is at the directory's name any more.
    #[must_use]
    pub const fn gone(&self) -> bool {
        matches!(self, Self::Removed | Self::Absent)
    }

    /// Returns why the directory is still there, when it is.
    #[must_use]
    pub fn why(&self) -> Option<&str> {
        match self {
            Self::Kept(why) => Some(why),
            Self::Removed | Self::Absent => None,
        }
    }
}

/// What this host recorded about the object it staged.
///
/// The identity is the answer to "which name holds that object". The creation instant is what
/// keeps that answer from being satisfied by an unrelated object whose numbers were reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedWitness {
    /// The staged repository's filesystem identity.
    pub identity: RecordedIdentity,
    /// When the filesystem says it was created, where the platform reports it.
    pub created_at_ms: Option<u64>,
}

impl StagedWitness {
    /// Returns whether `directory`, read now, is the object this witness recorded.
    ///
    /// The identity must be the recorded one ([`AuthorisedDirectory::check_recorded`]). The
    /// creation instants must match too where both readings have one; where either does not, the
    /// identity is the whole of the witness and this host says so rather than pretending to more.
    #[must_use]
    pub fn is_the_object_in(&self, directory: &AuthorisedDirectory) -> bool {
        if directory.check_recorded(self.identity).is_err() {
            return false;
        }
        match (self.created_at_ms, creation_instant(directory)) {
            (Some(first), Some(second)) => first == second,
            _ => true,
        }
    }
}

/// Returns when the filesystem says a directory was created, where the platform reports it.
fn creation_instant(directory: &AuthorisedDirectory) -> Option<u64> {
    directory
        .handle()
        .dir_metadata()
        .ok()
        .and_then(|metadata| metadata.created().ok().or_else(|| metadata.modified().ok()))
        .and_then(|instant| {
            instant
                .into_std()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
        })
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// Opens the repository staged in a sibling's directory, which the caller has been admitted to
/// for this read.
fn staged_tree_in(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let name = RelativeName::parse(STAGED_TREE)?;
    Ok(directory.subdirectory(&name)?)
}

/// Reads the witness of the repository staged in a sibling's directory, which the caller has been
/// admitted to for this read.
fn staged_in(directory: &AuthorisedDirectory) -> Result<StagedWitness> {
    let staged = staged_tree_in(directory)?;
    Ok(StagedWitness {
        identity: staged.recorded()?,
        created_at_ms: creation_instant(&staged),
    })
}

/// Publishes the staged repository into the destination, replacing nothing, and returns the
/// published directory as the handle that was checked to be the staged object.
///
/// The object published is required to be the one the caller recorded, so a replacement between
/// the recording and the publication is refused rather than published under the same action. The
/// publication is one effect through the destination's location, asked for once, immediately
/// before it starts: the witness, the rename and the check of what the name then holds.
///
/// A caller that goes on to write into the published tree writes through the returned handle, or
/// opens the destination again with [`Destination::opened_as`], and so never into whatever has
/// since taken the name.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the destination name is taken or the rename fails,
/// [`ProjectError::IdentityChanged`] when the staged object is not the recorded one, or the
/// location's refusal.
pub fn publish(
    staging: &StagingSibling,
    destination: &Destination,
    expected: StagedWitness,
) -> Result<AuthorisedDirectory> {
    let parent = destination.reach()?;
    // The staged object is the recorded one, looked at before the rename, and on Windows before
    // every attempt at it: there the rename waits while another program holds a file inside the
    // tree, and something else can take the staging name meanwhile.
    let still_staged = || -> Result<()> {
        let found = staged_tree_in(&staging.directory)?;
        if expected.is_the_object_in(&found) {
            return Ok(());
        }
        Err(ProjectError::IdentityChanged {
            detail: format!(
                "this operation staged the repository {} and {} now holds {}; nothing is published",
                expected.identity,
                crate::git::redact(&staging.tree_path().display().to_string()),
                found.identity()
            )
            .into(),
        })
    };
    let tree = RelativeName::parse(STAGED_TREE)?;
    rename_no_replace(
        &staging.directory,
        &tree,
        parent,
        destination.name(),
        &still_staged,
    )?;
    parent.sync(kr_flush::NameKind::Directory)?;
    // The object at the destination has to be the object that was staged. A rename preserves the
    // identity, so a mismatch here is something else having taken the name.
    let published = parent.subdirectory(destination.name())?;
    if published.check_recorded(expected.identity).is_err() {
        return Err(ProjectError::OutcomeUnknown {
            detail: format!(
                "the staged repository was {} and {} now holds {}; this host cannot say which \
                 publication landed",
                expected.identity,
                crate::git::redact(&destination.path().display().to_string()),
                published.identity()
            )
            .into(),
        });
    }
    Ok(published)
}

/// Renames one directory into another's single name, refusing to replace anything, once
/// `unchanged`, the caller's check of what the rename stands on, has passed.
///
/// On Linux and Apple platforms this is one system call that fails when the destination name is
/// taken: `renameat2` with `RENAME_NOREPLACE` and `renameatx_np` with `RENAME_EXCL`. Nothing
/// unexpected can be replaced however close the race is.
///
/// On Windows it is a rename that does not replace, `MoveFileEx` without the flag that lets it
/// replace, which fails when the destination name is taken, a file's as well as a directory's: a
/// rename that may replace does replace a file there with the staged tree. The rename is tried
/// again while another program holds a file inside the tree, and the occupancy check before every
/// attempt is the courtesy that gives a better diagnostic; [`publish`]'s identity comparison
/// afterwards is the second check rather than the guarantee.
#[cfg(unix)]
fn rename_no_replace(
    from: &AuthorisedDirectory,
    from_name: &RelativeName,
    to: &AuthorisedDirectory,
    to_name: &RelativeName,
    unchanged: &dyn Fn() -> Result<()>,
) -> Result<()> {
    use std::os::fd::AsFd as _;

    unchanged()?;
    rustix::fs::renameat_with(
        from.handle().as_fd(),
        from_name.as_str(),
        to.handle().as_fd(),
        to_name.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY => ProjectError::Destination {
            detail: format!(
                "{} was taken between this operation's check and its publication, so nothing was \
                 replaced",
                crate::git::redact(to_name.as_str())
            )
            .into(),
        },
        other => ProjectError::Destination {
            detail: format!(
                "{} could not be published: {other}",
                crate::git::redact(to_name.as_str())
            )
            .into(),
        },
    })
}

/// Renames one directory into another's single name, refusing to replace anything.
#[cfg(not(unix))]
fn rename_no_replace(
    from: &AuthorisedDirectory,
    from_name: &RelativeName,
    to: &AuthorisedDirectory,
    to_name: &RelativeName,
    unchanged: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let taken = || ProjectError::Destination {
        detail: format!(
            "{} is taken, so nothing was replaced",
            crate::git::redact(to_name.as_str())
        )
        .into(),
    };
    let checked = || {
        if let Err(changed) = unchanged() {
            return std::ops::ControlFlow::Break(changed);
        }
        match to.occupied(to_name) {
            Ok(false) => {
                #[cfg(test)]
                tests::between_check_and_attempt();
                std::ops::ControlFlow::Continue(())
            }
            Ok(true) => std::ops::ControlFlow::Break(taken()),
            Err(error) => std::ops::ControlFlow::Break(ProjectError::from(error)),
        }
    };
    match from.publish_into(from_name, to, to_name, checked) {
        Ok(std::ops::ControlFlow::Continue(())) => Ok(()),
        Ok(std::ops::ControlFlow::Break(refused)) => Err(refused),
        // Taken in the instant between the last check and the rename, which refused it.
        Err(_) if matches!(to.occupied(to_name), Ok(true)) => Err(taken()),
        Err(error) => Err(ProjectError::from(error)),
    }
}

/// What an interrupted publication turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// The rename landed: the destination holds the object that was staged.
    Published,
    /// The rename did not land: the staging directory still holds it.
    Staged,
    /// Neither name holds it, so this host cannot say what happened.
    Unknown,
}

/// Resolves an interrupted publication against the identity recorded before it.
///
/// This is the whole of "a crash or ambiguous publish is reconciled against the original create
/// token, not retried as another clone": the create token is the operation row, the row carries
/// the staged object's identity, and the answer is which name holds that object. The two names
/// are looked at in one read through the destination's location, asked for once before it.
///
/// # Errors
///
/// Returns the location's refusal: this host did not look, so it has no answer to give.
pub fn reconcile(
    destination: &Destination,
    staging: Option<&StagingSibling>,
    staged: StagedWitness,
) -> Result<Reconciliation> {
    let parent = destination.reach()?;
    if let Ok(published) = parent.subdirectory(destination.name())
        && staged.is_the_object_in(&published)
    {
        return Ok(Reconciliation::Published);
    }
    if let Some(staging) = staging
        && let Ok(found) = staged_tree_in(&staging.directory)
        && staged.is_the_object_in(&found)
    {
        return Ok(Reconciliation::Staged);
    }
    Ok(Reconciliation::Unknown)
}

/// Runs `git init` in the staging directory.
///
/// # Errors
///
/// Returns whatever the invocation failed with.
pub fn stage_init(
    profile: &RestrictedProfile,
    staging: &StagingSibling,
    initial_branch: Option<&str>,
    cancel: &Arc<Cancellation>,
    admission: Option<&ReadAdmission>,
) -> Result<()> {
    let branch = initial_branch.map(|branch| format!("--initial-branch={branch}"));
    let mut arguments: Vec<&OsStr> = vec![OsStr::new("init")];
    if let Some(branch) = branch.as_deref() {
        arguments.push(OsStr::new(branch));
    }
    arguments.push(OsStr::new(STAGED_TREE));
    // The directory is named by path for Git, and it has to be the object this host created.
    let request = GitRequest::write(staging.path(), &arguments)
        .expecting(staging.identity())
        .with_ceiling(staging.path())
        .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
        .with_cancellation(Arc::clone(cancel))
        .admitted(admission.cloned());
    profile.run_checked(&request)?;
    Ok(())
}

/// Runs `git clone` into the staging directory.
///
/// # Errors
///
/// Returns whatever the invocation failed with, with any credential removed from its output.
pub fn stage_clone(
    profile: &RestrictedProfile,
    staging: &StagingSibling,
    remote: &ValidatedRemote,
    cancel: &Arc<Cancellation>,
    admission: Option<&ReadAdmission>,
) -> Result<()> {
    let origin = format!("--origin={}", remote.specification.remote_name);
    let mut arguments: Vec<&OsStr> = vec![
        OsStr::new("clone"),
        // A template directory's hooks are copied into the new repository, so no template is used
        // beyond the empty one the profile already names.
        OsStr::new("--template="),
        // Nothing is checked out here. A checkout consults the repository's attributes and is the
        // one thing that makes Git look for a driver, and a clone is the one invocation whose
        // boundary holds the shell Git starts its connection through. Keeping them apart means no
        // invocation ever has both: `check_out` below runs with no shell in its list at all.
        OsStr::new("--no-checkout"),
        OsStr::new(&origin),
    ];
    if matches!(remote.specification.transport, RemoteTransport::LocalPath) {
        // A local clone hardlinks the source's objects by default, which would leave the new
        // repository sharing them. An independent object store is what a separate repository is.
        arguments.push(OsStr::new("--no-hardlinks"));
    }
    arguments.push(OsStr::new("--"));
    arguments.push(OsStr::new(&remote.specification.url));
    arguments.push(OsStr::new(STAGED_TREE));
    // A clone from a path on this machine reads the repository it copies, which is not one of the
    // directories this operation owns. It matters where a platform's mechanism confines reading.
    let source = PathBuf::from(&remote.specification.url);
    // The directory is named by path for Git, and it has to be the object this host created.
    let mut request = GitRequest::write(staging.path(), &arguments)
        .expecting(staging.identity())
        .with_ceiling(staging.path())
        .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
        .with_transport(remote.access())
        .with_cancellation(Arc::clone(cancel))
        .admitted(admission.cloned());
    if matches!(remote.specification.transport, RemoteTransport::LocalPath) {
        request = request.reading(&[source.as_path()]);
    }
    profile.run_checked(&request)?;
    // The URL the repository stored has to be the one this host passed. A rewrite, a helper or a
    // version of Git that stored something else is a credential in remote state waiting to happen.
    let key = format!("remote.{}.url", remote.specification.remote_name);
    let arguments: [&OsStr; 4] = [
        OsStr::new("config"),
        OsStr::new("--get"),
        OsStr::new("--"),
        OsStr::new(&key),
    ];
    // From here on every invocation runs in the tree the clone made, which has to be that object:
    // its identity is read through the staging directory's handle, never through the path, and
    // that read asks the destination's location first, as the invocation then asks the request's.
    let tree = staging.tree_path();
    let stored = profile
        .run_checked(
            &GitRequest::read(&tree, &arguments)
                .expecting(staging.staged_identity()?)
                .with_ceiling(staging.path())
                .admitted(admission.cloned()),
        )?
        .trim()
        .to_owned();
    crate::credential::require_no_credential(&remote.specification.remote_name, &stored)?;
    if stored != remote.specification.url {
        return Err(ProjectError::RemoteRejected {
            detail: format!(
                "the remote {} was stored as a different URL from the one this host passed, so \
                 the clone is not published",
                remote.specification.remote_name
            )
            .into(),
        });
    }
    check_out(profile, staging, cancel, admission)
}

/// Populates the working tree of a repository that was cloned without one.
///
/// A separate invocation, and the reason is the boundary: a clone starts Git's own connection
/// through the system shell, and a checkout is what makes Git consult a repository's attributes and
/// look for a driver. This one's execution list holds Git and the helpers under Git's own directory
/// and nothing else, so a driver planted in the clone's own configuration while it ran has nothing
/// to run through.
///
/// A remote with no commit in it has nothing to check out, which is what a newly created repository
/// on the other end looks like, and that is not a failure.
///
/// # Errors
///
/// Returns whatever the invocation failed with.
fn check_out(
    profile: &RestrictedProfile,
    staging: &StagingSibling,
    cancel: &Arc<Cancellation>,
    admission: Option<&ReadAdmission>,
) -> Result<()> {
    let tree = staging.tree_path();
    // The staged tree as the object this host found through the staging directory's handle, once
    // the destination's location admitted that read. Each invocation below requires its directory
    // to be that object, so a tree swapped for a link or another directory between two of them
    // sends the next one nowhere.
    let staged = staging.staged_identity()?;
    let arguments: [&OsStr; 3] = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new("HEAD"),
    ];
    let head = profile.run(
        &GitRequest::read(&tree, &arguments)
            .expecting(staged)
            .with_ceiling(staging.path())
            .admitted(admission.cloned()),
    )?;
    head.require_complete()?;
    if !head.success {
        return Ok(());
    }
    let revision = head.text().trim().to_owned();
    let arguments: [&OsStr; 4] = [
        OsStr::new("symbolic-ref"),
        OsStr::new("--quiet"),
        OsStr::new("--short"),
        OsStr::new("HEAD"),
    ];
    let named = profile.run(
        &GitRequest::read(&tree, &arguments)
            .expecting(staged)
            .with_ceiling(staging.path())
            .admitted(admission.cloned()),
    )?;
    named.require_complete()?;
    let branch = named.text().trim().to_owned();
    // A remote whose own HEAD is detached gives no branch name, and the revision is then what the
    // working tree is put at. Either argument goes through the same argument check as every other.
    let mut arguments: Vec<&OsStr> = vec![OsStr::new("checkout")];
    if named.success && !branch.is_empty() {
        arguments.push(OsStr::new(&branch));
    } else {
        arguments.push(OsStr::new("--detach"));
        arguments.push(OsStr::new(&revision));
    }
    let request = GitRequest::write(&tree, &arguments)
        .expecting(staged)
        .with_ceiling(staging.path())
        .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
        .with_cancellation(Arc::clone(cancel))
        .admitted(admission.cloned());
    profile.run_checked(&request)?;
    Ok(())
}

/// Returns thirty-two random hexadecimal characters for a staging directory's name.
///
/// The name is not a secret and nothing depends on it staying unknown. It is there so two
/// operations in one parent never collide, and so a path guessed from an action identifier alone
/// names nothing.
fn random_suffix() -> String {
    let bytes = uuid::Uuid::new_v4().as_bytes().to_owned();
    let mut text = String::with_capacity(32);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test does between the check before an attempt at a publication's rename and the
    /// attempt.
    #[cfg(not(unix))]
    type AttemptHook = Box<dyn FnMut()>;

    #[cfg(not(unix))]
    std::thread_local! {
        /// The hook the test running on this thread set, if any.
        static BEFORE_ATTEMPT: std::cell::RefCell<Option<AttemptHook>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Runs what the test on this thread does between the check before an attempt at a
    /// publication's rename and the attempt.
    #[cfg(not(unix))]
    pub(super) fn between_check_and_attempt() {
        BEFORE_ATTEMPT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    /// Opens `file` with a handle that shares reading and writing but not its deletion, as a
    /// program that reads each file as it is written holds it.
    #[cfg(windows)]
    fn hold(file: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// Reading and writing are shared; deleting is not.
        const FILE_SHARE_READ_WRITE: u32 = 0x0001 | 0x0002;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(file)
            .expect("the file is held")
    }

    /// Counts the renames refused as held on this thread while the guard stands. At the first of
    /// them, `meanwhile` is given the hold, and lets go of it when it drops it.
    #[cfg(windows)]
    fn at_the_first_refusal(
        holding: std::fs::File,
        meanwhile: impl FnOnce(std::fs::File) + 'static,
    ) -> (
        std::rc::Rc<std::cell::Cell<u32>>,
        kr_flush::testing::AfterHeldRefusal,
    ) {
        let refusals = std::rc::Rc::new(std::cell::Cell::new(0));
        let counted = std::rc::Rc::clone(&refusals);
        let mut first = Some((holding, meanwhile));
        let hook = kr_flush::testing::after_held_refusal(move || {
            counted.set(counted.get() + 1);
            if let Some((holding, meanwhile)) = first.take() {
                meanwhile(holding);
            }
        });
        (refusals, hook)
    }

    /// A staged tree with a file in it, the directory it is staged in and the one it is published
    /// into, both authorised for one environment, and the file.
    #[cfg(windows)]
    fn a_tree_to_publish() -> (
        tempfile::TempDir,
        AuthorisedDirectory,
        AuthorisedDirectory,
        PathBuf,
    ) {
        let root = tempfile::tempdir().expect("a directory");
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        let file = root.path().join("staging/tree/objects/pack");
        std::fs::create_dir_all(root.path().join("staging/tree/objects")).expect("a staged tree");
        std::fs::write(&file, b"staged\n").expect("a file in it");
        std::fs::create_dir(root.path().join("parent")).expect("a parent");
        let staging = AuthorisedDirectory::open_root(environment_id, &root.path().join("staging"))
            .expect("the staging directory opens");
        let parent = AuthorisedDirectory::open_root(environment_id, &root.path().join("parent"))
            .expect("the parent opens");
        (root, staging, parent, file)
    }

    #[cfg(windows)]
    fn name(text: &str) -> RelativeName {
        RelativeName::parse(text).expect("a valid relative name")
    }

    /// On Windows a staged tree that holds a file another program holds without sharing its
    /// deletion, as a scanner holds a file it reads, is published once that program lets go.
    #[cfg(windows)]
    #[test]
    fn a_tree_holding_a_held_file_is_published_once_it_is_let_go() {
        let (root, staging, parent, file) = a_tree_to_publish();
        let (refusals, guard) = at_the_first_refusal(hold(&file), drop);
        let published = rename_no_replace(
            &staging,
            &name("tree"),
            &parent,
            &name("published"),
            &|| Ok(()),
        );
        drop(guard);
        published.expect("published once it is let go");
        assert_eq!(
            refusals.get(),
            1,
            "refused once while a file inside was held"
        );
        assert!(root.path().join("parent/published/objects/pack").is_file());
        assert!(!root.path().join("staging/tree").exists());
    }

    /// On Windows the check a publication stands on, that the destination's name is free, is made
    /// again before every attempt: a file put there while the held publication waits is never
    /// replaced, the publication says the name is taken, and the staged tree stays where it was.
    #[cfg(windows)]
    #[test]
    fn a_name_taken_while_the_publication_waits_is_not_replaced() {
        let (root, staging, parent, file) = a_tree_to_publish();
        let taken = root.path().join("parent/published");
        let (refusals, guard) = at_the_first_refusal(hold(&file), move |holding| {
            std::fs::write(&taken, b"somebody's file").expect("somebody takes the name meanwhile");
            drop(holding);
        });
        let published = rename_no_replace(
            &staging,
            &name("tree"),
            &parent,
            &name("published"),
            &|| Ok(()),
        );
        drop(guard);
        assert_eq!(refusals.get(), 1);
        let refused = published.expect_err("the name was taken meanwhile");
        assert!(
            refused
                .to_string()
                .contains("is taken, so nothing was replaced"),
            "{refused}"
        );
        assert_eq!(
            std::fs::read(root.path().join("parent/published")).expect("somebody's file"),
            b"somebody's file"
        );
        assert!(root.path().join("staging/tree/objects/pack").is_file());
    }

    /// On Windows a file that takes the destination's name after the last check, in the instant
    /// before the rename, is kept: the rename never replaces, and the publication says the name is
    /// taken and leaves the staged tree where it was.
    #[cfg(windows)]
    #[test]
    fn a_file_that_takes_the_name_after_the_last_check_is_kept() {
        let (root, staging, parent, _file) = a_tree_to_publish();
        let taken = root.path().join("parent/published");
        let mut attempts = 0;
        BEFORE_ATTEMPT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                attempts += 1;
                if attempts == 1 {
                    std::fs::write(&taken, b"somebody's file")
                        .expect("somebody takes the name after the check");
                }
            }));
        });
        let published = rename_no_replace(
            &staging,
            &name("tree"),
            &parent,
            &name("published"),
            &|| Ok(()),
        );
        BEFORE_ATTEMPT.with(|hook| *hook.borrow_mut() = None);
        let refused = published.expect_err("the name was taken after the check");
        assert!(
            refused
                .to_string()
                .contains("is taken, so nothing was replaced"),
            "{refused}"
        );
        assert_eq!(
            std::fs::read(root.path().join("parent/published")).expect("somebody's file"),
            b"somebody's file"
        );
        assert!(root.path().join("staging/tree/objects/pack").is_file());
    }

    /// On Windows a published tree is the object that was recorded when it was staged: the
    /// identity a staged repository is recorded with, the volume's serial number with the
    /// directory's own 128-bit id, holds across the rename into another directory, so the
    /// publication finds the staged object at its new name.
    #[cfg(windows)]
    #[test]
    fn a_published_tree_is_the_object_that_was_recorded_when_it_was_staged() {
        let (_parent, destination, sibling) = staged_by_plain_means();
        let witness = sibling
            .staged_witness()
            .expect("the staged repository is read");

        let published = publish(&sibling, &destination, witness).expect("the tree is published");
        assert_eq!(published.identity(), witness.identity.object);
        assert_eq!(
            std::fs::read(destination.path().join("objects/pack")).expect("the published file"),
            b"staged\n"
        );
    }

    /// On Windows the staged repository is compared with the one recorded before every attempt
    /// at its publication: a tree put in its place while the held publication waits is never
    /// published, the publication says the staged object changed, and the destination stays
    /// absent.
    #[cfg(windows)]
    #[test]
    fn a_staged_tree_replaced_while_its_publication_waits_is_not_published() {
        let (_parent, destination, sibling) = staged();
        let witness = staged_in(&sibling.directory).expect("the staged tree's witness");
        let tree = sibling.tree_path();
        let (refusals, guard) = at_the_first_refusal(hold(&tree.join("objects/pack")), {
            let tree = tree.clone();
            move |holding| {
                drop(holding);
                std::fs::rename(&tree, tree.with_extension("recorded"))
                    .expect("the recorded tree goes");
                std::fs::create_dir_all(tree.join("objects")).expect("another tree takes its name");
                std::fs::write(tree.join("objects/pack"), b"another\n").expect("a file in it");
            }
        });
        let published = publish(&sibling, &destination, witness);
        drop(guard);
        let refused = published.expect_err("another tree is not published");
        assert_eq!(refusals.get(), 1);
        assert!(
            matches!(refused, ProjectError::IdentityChanged { .. }),
            "{refused:?}"
        );
        assert!(!destination.path().exists(), "the destination stays absent");
    }

    #[test]
    fn a_staging_name_is_thirty_two_hexadecimal_characters_and_never_repeats() {
        let first = random_suffix();
        let second = random_suffix();
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn a_staging_directory_is_recognised_by_its_prefix() {
        assert!(format!("{STAGING_PREFIX}{}", random_suffix()).starts_with(STAGING_PREFIX));
        // A directory somebody else left in the parent is not one this host will adopt.
        assert!(!"build".starts_with(STAGING_PREFIX));
    }

    #[test]
    fn a_cancellation_counts_what_it_stopped() {
        let cancel = Cancellation::default();
        assert!(!cancel.requested());
        assert_eq!(cancel.stopped(), 0);
        cancel.request();
        assert!(cancel.requested());
        cancel.record_stop();
        cancel.record_stop();
        assert_eq!(cancel.stopped(), 2);
    }

    /// A destination in a directory of its own, and a sibling of it made by plain means, which is
    /// opened and not created: a test of what is recorded about a staged tree and of its rename
    /// is not a test of who may change the sibling, which only a sibling that `create` makes is
    /// asked.
    fn staged_by_plain_means() -> (tempfile::TempDir, Destination, StagingSibling) {
        let (parent, destination) = a_destination();
        let name = StagingSibling::propose();
        std::fs::create_dir(parent.path().join(&name)).expect("the staging directory");
        let sibling = StagingSibling::open(&destination, &name).expect("the sibling opens");
        std::fs::create_dir_all(sibling.tree_path().join("objects")).expect("staged content");
        std::fs::write(sibling.tree_path().join("objects/pack"), b"staged\n").expect("a file");
        (parent, destination, sibling)
    }

    /// A destination named `published`, in a directory of its own.
    fn a_destination() -> (tempfile::TempDir, Destination) {
        let parent = tempfile::tempdir().expect("a directory to stage beside");
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        let destination = Destination::resolve(
            &DestinationRequest {
                environment_id,
                parent: kr_protocol::project::DestinationParent::Host {
                    path: parent.path().display().to_string(),
                },
                name: "published".to_owned(),
            },
            environment_id,
            &crate::policy::LocationPolicy::default(),
            crate::policy::Admitting::Caller(None),
        )
        .expect("the destination resolves");
        (parent, destination)
    }

    /// A staging directory with something staged in it, beside a destination in a directory of
    /// its own.
    fn staged() -> (tempfile::TempDir, Destination, StagingSibling) {
        let (parent, destination) = a_destination();
        let sibling = StagingSibling::create(&destination, &StagingSibling::propose())
            .expect("the staging directory is made");
        std::fs::create_dir_all(sibling.tree_path().join("objects")).expect("staged content");
        std::fs::write(sibling.tree_path().join("objects/pack"), b"staged\n").expect("a file");
        (parent, destination, sibling)
    }

    /// A staged repository is the object a witness recorded only on the filesystem it was
    /// recorded on, and a witness made before filesystems were recorded is decided by the numbers.
    #[test]
    fn a_witness_names_the_staged_object_on_the_filesystem_it_was_recorded_on() {
        let (_parent, _destination, sibling) = staged_by_plain_means();
        let witness = sibling
            .staged_witness()
            .expect("the staged repository is read");
        let staged = staged_tree_in(&sibling.directory).expect("the staged repository opens");
        assert!(witness.is_the_object_in(&staged));

        // The same numbers on another filesystem are not the object that was staged.
        let elsewhere = StagedWitness {
            identity: kr_transfer::RecordedIdentity {
                filesystem: Some(kr_transfer::FilesystemId::from_bytes(
                    [0xee; kr_transfer::FilesystemId::LEN],
                )),
                ..witness.identity
            },
            ..witness
        };
        assert!(!elsewhere.is_the_object_in(&staged));

        // A witness recorded without a filesystem is decided as it was, by the numbers.
        let before = StagedWitness {
            identity: kr_transfer::RecordedIdentity::without_filesystem(witness.identity.object),
            ..witness
        };
        assert!(before.is_the_object_in(&staged));

        // And another object is never the one that was staged.
        let other = StagedWitness {
            identity: kr_transfer::RecordedIdentity::from_parts(
                witness.identity.object.device,
                witness.identity.object.file_id.wrapping_add(1),
                witness.identity.filesystem,
            ),
            ..witness
        };
        assert!(!other.is_the_object_in(&staged));
    }

    /// A cleanup that stops part way keeps the directory and says where it stopped and why.
    #[cfg(unix)]
    #[test]
    fn a_cleanup_that_stops_part_way_keeps_the_directory_and_says_where() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let (_parent, destination, sibling) = staged();
        let path = sibling.path().to_path_buf();
        let locked = sibling.tree_path().join("locked");
        std::fs::create_dir(&locked).expect("a directory");
        std::fs::write(locked.join("stuck"), b"stuck\n").expect("its file");
        if std::fs::metadata(&path).is_ok_and(|metadata| metadata.uid() == 0) {
            println!(
                "not exercised: this process removes entries whatever a directory's mode says"
            );
            return;
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
            .expect("its entries cannot be removed");
        let recorded = sibling.recorded().expect("reads its identity");
        let cleanup = sibling.clean_up(&destination, recorded, &|_| Ok(()));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is writable again");
        let Cleanup::Kept(why) = cleanup else {
            panic!("a cleanup that stopped keeps the directory: {cleanup:?}");
        };
        assert!(
            why.contains("stopped at") && why.contains("locked/stuck"),
            "and says where: {why}"
        );
        assert!(
            locked.join("stuck").is_file(),
            "the entry it stopped at is still there"
        );
        assert!(path.is_dir(), "and so is the staging directory");
    }

    /// The three refusals of a staging directory's removal, and the removal they leave.
    ///
    /// A staging directory goes only while it is the object this host recorded, and only while
    /// it is one no account but this one can change, because only then can nothing but a process
    /// of this same account have put something else at a name inside it. Another account as its
    /// owner is the third refusal, and it is proved on the judgement itself in the transfer
    /// crate: putting another account's name on a directory is a privileged act no test here can
    /// perform.
    #[cfg(unix)]
    #[test]
    fn a_staging_directory_goes_only_as_the_recorded_directory_only_this_account_can_change() {
        use std::os::unix::fs::PermissionsExt as _;

        // A mode that admits another account.
        let (_parent, destination, sibling) = staged();
        let path = sibling.path().to_path_buf();
        let recorded = sibling.recorded().expect("reads its identity");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750))
            .expect("the group is let in");
        let refusal = sibling
            .remove(&destination, recorded, &|_| Ok(()))
            .expect_err("a directory another account may enter is not removed");
        assert!(
            refusal.to_string().contains("only this account can change"),
            "{refusal}"
        );
        assert!(
            path.join("tree/objects/pack").is_file(),
            "nothing in it was removed"
        );

        // A directory that moved: another one holds the name now.
        let (parent, destination, sibling) = staged();
        let name = sibling.name().to_owned();
        let recorded = sibling.recorded().expect("reads its identity");
        drop(sibling);
        std::fs::rename(parent.path().join(&name), parent.path().join("moved"))
            .expect("the staging directory moves");
        std::fs::create_dir(parent.path().join(&name)).expect("another directory at its name");
        std::fs::set_permissions(
            parent.path().join(&name),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("as private as the one it replaced");
        std::fs::write(parent.path().join(&name).join("theirs"), b"theirs\n").expect("its file");
        let reopened = StagingSibling::open(&destination, &name).expect("the name opens");
        let refusal = reopened
            .remove(&destination, recorded, &|_| Ok(()))
            .expect_err("a directory that is not the recorded one is not removed");
        assert!(
            matches!(refusal, ProjectError::IdentityChanged { .. }),
            "{refusal}"
        );
        assert!(
            parent.path().join(&name).join("theirs").is_file(),
            "the replacement stays"
        );
        assert!(
            parent.path().join("moved/tree/objects/pack").is_file(),
            "and so does the directory that moved"
        );

        // The recorded directory, only this account's: it goes, whole.
        let (_parent, destination, sibling) = staged();
        let path = sibling.path().to_path_buf();
        let recorded = sibling.recorded().expect("reads its identity");
        sibling
            .remove(&destination, recorded, &|_| Ok(()))
            .expect("the recorded directory goes");
        assert!(
            std::fs::symlink_metadata(&path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "nothing is left at its name"
        );
    }
}
