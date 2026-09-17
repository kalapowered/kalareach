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
    DestinationRequest, DestinationState, MAX_NAME_LEN, OPERATION_DEADLINE, RemoteTransport,
};
use kr_transfer::authority::ObjectKind;
use kr_transfer::{AuthorisedDirectory, ObjectIdentity, RelativeName};

use crate::credential::ValidatedRemote;
use crate::error::{ProjectError, Result};
use crate::git::{Cancellation, GitRequest, RestrictedProfile};

/// The prefix of the private sibling a repository operation stages its content in.
///
/// It starts with a dot so it is hidden on Unix, and it names this host so a person who finds one
/// knows what left it. A cancellation and the recovery both report it by name.
pub const STAGING_PREFIX: &str = ".kr-project-";

/// The name the staged repository is created under inside the staging directory.
pub const STAGED_TREE: &str = "tree";

/// One authorised destination: the parent's handle, and one name inside it.
#[derive(Debug)]
pub struct Destination {
    parent: AuthorisedDirectory,
    parent_path: PathBuf,
    name: RelativeName,
}

impl Destination {
    /// Resolves a caller's destination request into a handle and a name.
    ///
    /// The parent path is resolved once, here, with the process's own authority. The name is one
    /// component with no separator, no traversal segment and no reserved device name, because the
    /// creation that follows is the operation a later refusal cannot undo.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the parent cannot be opened or the name is not
    /// one component, or [`ProjectError::WrongEnvironment`] when the request names another
    /// environment.
    pub fn resolve(request: &DestinationRequest, environment_id: EnvironmentId) -> Result<Self> {
        if request.environment_id != environment_id {
            return Err(ProjectError::WrongEnvironment {
                named: request.environment_id.to_string(),
                owned: environment_id.to_string(),
            });
        }
        if request.name.len() > MAX_NAME_LEN {
            return Err(ProjectError::Destination {
                detail: format!(
                    "a destination name is at most {MAX_NAME_LEN} bytes and this one is {}",
                    request.name.len()
                ),
            });
        }
        let parent_path = PathBuf::from(&request.parent_path);
        if !parent_path.is_absolute() {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} is not an absolute path; a destination's parent is named absolutely and \
                     resolved once",
                    parent_path.display()
                ),
            });
        }
        let name = RelativeName::parse(&request.name)?;
        if !name.is_single_component() {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} is more than one name; a repository is created as one entry in the \
                     directory whose handle this host holds",
                    request.name
                ),
            });
        }
        let parent = AuthorisedDirectory::open_root(environment_id, &parent_path)?;
        Ok(Self {
            parent,
            parent_path,
            name,
        })
    }

    /// Returns the parent's authorised handle.
    #[must_use]
    pub const fn parent(&self) -> &AuthorisedDirectory {
        &self.parent
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

    /// Reports what is at the destination now.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the platform will not say.
    pub fn probe(&self) -> Result<DestinationState> {
        match self.parent.probe(&self.name) {
            Ok(ObjectKind::Directory) => {
                let subdirectory = self.parent.subdirectory(&self.name)?;
                let mut entries =
                    subdirectory
                        .handle()
                        .entries()
                        .map_err(|error| ProjectError::Destination {
                            detail: format!("{} could not be listed: {error}", self.name),
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
}

/// The private sibling one operation stages its content in.
#[derive(Debug)]
pub struct StagingSibling {
    directory: AuthorisedDirectory,
    name: RelativeName,
    path: PathBuf,
}

impl StagingSibling {
    /// Creates a private sibling of the destination, with a random name.
    ///
    /// It is a sibling rather than a child, so the publication is a rename inside one directory
    /// and cannot cross a filesystem. It is created owner-only, so nothing under another account
    /// reads a repository this host has not finished building.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be created.
    pub fn create(destination: &Destination) -> Result<Self> {
        let name = RelativeName::parse(&format!("{STAGING_PREFIX}{}", random_suffix()))?;
        let directory = destination.parent.create_subdirectory(&name)?;
        let path = destination.parent.host_path(&name);
        Ok(Self {
            directory,
            name,
            path,
        })
    }

    /// Opens a sibling an earlier daemon created, for recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the name is not one this host would have used,
    /// or the directory cannot be opened.
    pub fn open(destination: &Destination, name: &str) -> Result<Self> {
        if !name.starts_with(STAGING_PREFIX) {
            return Err(ProjectError::Destination {
                detail: format!("{name} is not a staging directory this host created"),
            });
        }
        let name = RelativeName::parse(name)?;
        let directory = destination.parent.subdirectory(&name)?;
        let path = destination.parent.host_path(&name);
        Ok(Self {
            directory,
            name,
            path,
        })
    }

    /// Returns the sibling's authorised handle.
    #[must_use]
    pub const fn directory(&self) -> &AuthorisedDirectory {
        &self.directory
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
    /// holds this object rather than whether a name exists.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the staged repository is not there.
    pub fn staged_identity(&self) -> Result<ObjectIdentity> {
        let name = RelativeName::parse(STAGED_TREE)?;
        Ok(self.directory.subdirectory(&name)?.identity())
    }

    /// Removes the sibling and everything inside it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the removal fails for a reason other than the
    /// directory already being gone.
    pub fn remove(self, destination: &Destination) -> Result<()> {
        match destination
            .parent
            .handle()
            .remove_dir_all(self.name.as_str())
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ProjectError::Destination {
                    detail: format!("{} could not be removed: {error}", self.path.display()),
                });
            }
        }
        destination.parent.sync()?;
        Ok(())
    }
}

/// Publishes the staged repository into the destination, replacing nothing.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when the destination name is taken or the rename fails.
pub fn publish(staging: &StagingSibling, destination: &Destination) -> Result<ObjectIdentity> {
    let staged = staging.staged_identity()?;
    let tree = RelativeName::parse(STAGED_TREE)?;
    rename_no_replace(
        staging.directory(),
        &tree,
        destination.parent(),
        destination.name(),
    )?;
    destination.parent().sync()?;
    // The object at the destination has to be the object that was staged. A rename preserves the
    // identity, so a mismatch here is something else having taken the name.
    let published = destination.parent().subdirectory(destination.name())?;
    if published.identity() != staged {
        return Err(ProjectError::OutcomeUnknown {
            detail: format!(
                "the staged repository was {staged} and {} now holds {}; this host cannot say \
                 which publication landed",
                destination.path().display(),
                published.identity()
            ),
        });
    }
    Ok(staged)
}

/// Renames one directory into another's single name, refusing to replace anything.
///
/// On Linux and Apple platforms this is one system call that fails when the destination name is
/// taken, so nothing unexpected can be replaced however close the race is. Elsewhere the name is
/// checked first and the identity of the published object is compared afterwards, which detects a
/// replacement rather than preventing it; [`publish`] does the comparison for both paths.
#[cfg(unix)]
fn rename_no_replace(
    from: &AuthorisedDirectory,
    from_name: &RelativeName,
    to: &AuthorisedDirectory,
    to_name: &RelativeName,
) -> Result<()> {
    use std::os::fd::AsFd as _;

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
                "{to_name} was taken between this operation's check and its publication, so \
                 nothing was replaced"
            ),
        },
        other => ProjectError::Destination {
            detail: format!("{to_name} could not be published: {other}"),
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
) -> Result<()> {
    if to.occupied(to_name)? {
        return Err(ProjectError::Destination {
            detail: format!("{to_name} is taken, so nothing was replaced"),
        });
    }
    from.rename_into(from_name, to, to_name)?;
    Ok(())
}

/// What an interrupted publication turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// The rename landed: the destination holds the object that was staged.
    Published(ObjectIdentity),
    /// The rename did not land: the staging directory still holds it.
    Staged(ObjectIdentity),
    /// Neither name holds it, so this host cannot say what happened.
    Unknown,
}

/// Resolves an interrupted publication against the identity recorded before it.
///
/// This is the whole of "a crash or ambiguous publish is reconciled against the original create
/// token, not retried as another clone": the create token is the operation row, the row carries
/// the staged object's identity, and the answer is which name holds that object.
///
/// # Errors
///
/// Returns [`ProjectError::Destination`] when neither name can be examined.
pub fn reconcile(
    destination: &Destination,
    staging: Option<&StagingSibling>,
    staged: ObjectIdentity,
) -> Result<Reconciliation> {
    if let Ok(published) = destination.parent().subdirectory(destination.name())
        && published.identity() == staged
    {
        return Ok(Reconciliation::Published(staged));
    }
    if let Some(staging) = staging
        && let Ok(identity) = staging.staged_identity()
        && identity == staged
    {
        return Ok(Reconciliation::Staged(staged));
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
) -> Result<()> {
    let branch = initial_branch.map(|branch| format!("--initial-branch={branch}"));
    let mut arguments: Vec<&OsStr> = vec![OsStr::new("init")];
    if let Some(branch) = branch.as_deref() {
        arguments.push(OsStr::new(branch));
    }
    arguments.push(OsStr::new(STAGED_TREE));
    let request = GitRequest::write(staging.path(), &arguments)
        .with_ceiling(staging.path())
        .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
        .with_cancellation(Arc::clone(cancel));
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
) -> Result<()> {
    let origin = format!("--origin={}", remote.specification.remote_name);
    let mut arguments: Vec<&OsStr> = vec![
        OsStr::new("clone"),
        // A template directory's hooks are copied into the new repository, so no template is used
        // beyond the empty one the profile already names.
        OsStr::new("--template="),
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
    let request = GitRequest::write(staging.path(), &arguments)
        .with_ceiling(staging.path())
        .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
        .with_transport(
            remote.specification.transport,
            remote.credential_helper(),
            remote.ssh_command(),
        )
        .with_cancellation(Arc::clone(cancel));
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
    let tree = staging.tree_path();
    let stored = profile
        .run_checked(&GitRequest::read(&tree, &arguments).with_ceiling(staging.path()))?
        .trim()
        .to_owned();
    crate::credential::require_no_credential(&remote.specification.remote_name, &stored)?;
    if stored != remote.specification.url {
        return Err(ProjectError::RemoteRejected {
            detail: format!(
                "the remote {} was stored as a different URL from the one this host passed, so \
                 the clone is not published",
                remote.specification.remote_name
            ),
        });
    }
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
}
