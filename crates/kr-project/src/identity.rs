//! Repository identity, and the handles every operation works through.
//!
//! Section 14 paragraph 5 makes a repository's identity its **stable filesystem identity** rather
//! than its path, so that a rename or an added worktree never extends a grant. This module is
//! where that is decided, and it decides it twice, because a repository and a working copy are two
//! objects:
//!
//! * A **repository** is identified by its Git common directory: the device and inode on Unix, the
//!   volume serial and file index on Windows. That object survives renaming the checkout, so a
//!   grant recorded against it still names the same repository afterwards. A different repository
//!   moved to the old path has a different identity and is refused.
//! * A **workspace** is identified by its own working tree's directory. A linked worktree is a new
//!   object with a new identity, so adding one creates a record rather than widening the grant
//!   that covers an existing one.
//!
//! Every operation afterwards goes through an [`kr_transfer::AuthorisedDirectory`], which is an
//! open directory descriptor rather than a path: the same authority model the transfer service
//! uses, so a repository, a staging area and a client destination are all authorised the same way.
//! The recorded identity is compared on every open, and a mismatch is
//! [`ProjectError::IdentityChanged`] rather than a silent redirection.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kr_protocol::ids::EnvironmentId;
use kr_protocol::project::FilesystemIdentity;
use kr_protocol::scalars::U64;
use kr_transfer::{AuthorisedDirectory, ObjectIdentity};

use crate::error::{ProjectError, Result};
use crate::git::{ConfigurationAudit, GitRequest, ObjectFormat, RestrictedProfile};

/// Returns the wire form of one filesystem identity.
#[must_use]
pub const fn wire_identity(identity: ObjectIdentity) -> FilesystemIdentity {
    FilesystemIdentity {
        device: U64::new(identity.device),
        file_id: U64::new(identity.file_id),
    }
}

/// Returns the internal form of one filesystem identity.
#[must_use]
pub const fn object_identity(identity: FilesystemIdentity) -> ObjectIdentity {
    ObjectIdentity {
        device: identity.device.get(),
        file_id: identity.file_id.get(),
    }
}

/// What one repository's two identities are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryIdentity {
    /// The Git common directory: the repository itself, stable across a rename of the checkout.
    pub git_dir: ObjectIdentity,
    /// The working tree this open used. One of possibly several.
    pub work_tree: ObjectIdentity,
}

/// An opened repository: the handle, the identities and what its configuration named.
#[derive(Debug)]
pub struct OpenedRepository {
    work_tree: AuthorisedDirectory,
    /// The administrative directory every worktree of this repository shares, held open from the
    /// moment its identity was read. A caller that has to account for this repository's own data
    /// works from this handle rather than resolving the path again: a path resolved a second time
    /// can reach a different object, and what was checked is then not what was read.
    git_dir: AuthorisedDirectory,
    /// This working tree's own administrative directory, held open for the same reason. The same
    /// object as [`Self::git_dir`] in an ordinary repository.
    own_dir: AuthorisedDirectory,
    identity: RepositoryIdentity,
    git_dir_path: PathBuf,
    own_dir_path: PathBuf,
    top_level: PathBuf,
    audit: ConfigurationAudit,
}

impl OpenedRepository {
    /// Opens a working tree, reads the repository's identity and audits its configuration.
    ///
    /// The path is resolved once, here, with the process's own authority; everything afterwards is
    /// relative to the handle. The audit runs before any other invocation, because its result is
    /// what the later invocations' driver overrides are built from.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when the directory cannot be opened,
    /// [`ProjectError::GitFailed`] when the repository cannot be read, or
    /// [`ProjectError::ConfigurationRejected`] when its configuration names something no override
    /// removes.
    pub fn open(
        profile: &RestrictedProfile,
        environment_id: EnvironmentId,
        path: &Path,
    ) -> Result<Self> {
        let work_tree = AuthorisedDirectory::open_root(environment_id, path)?;
        // `--git-common-dir` rather than `--git-dir`: a linked worktree's own Git directory lives
        // inside the main one, and what identifies the repository is the object every worktree of
        // it shares.
        // This worktree's own directory as well: a repository can keep that in one place and
        // everything its worktrees share in another, and both are its administrative data, so a
        // caller that has to exclude that data has to know both. `--absolute-git-dir` asks for it;
        // the profile passes no argument that could redirect an invocation, and this is the query
        // rather than the redirect.
        let arguments: [&OsStr; 6] = [
            OsStr::new("rev-parse"),
            OsStr::new("--path-format=absolute"),
            OsStr::new("--git-common-dir"),
            OsStr::new("--absolute-git-dir"),
            OsStr::new("--show-toplevel"),
            OsStr::new("--is-inside-work-tree"),
        ];
        let reported = profile.run_checked(&GitRequest::read(path, &arguments))?;
        let mut lines = reported.lines();
        let git_dir_path = PathBuf::from(lines.next().unwrap_or_default());
        let own_dir_path = PathBuf::from(lines.next().unwrap_or_default());
        let top_level = PathBuf::from(lines.next().unwrap_or_default());
        let inside = lines.next().unwrap_or_default().trim();
        if inside != "true" {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} is not inside a Git working tree, so it is not a project repository",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        }
        if git_dir_path.as_os_str().is_empty() || top_level.as_os_str().is_empty() {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} did not report its own repository and working tree",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        }
        // The Git directory is opened as an object of its own, because for a linked worktree it
        // lies outside the working tree this call named. Both directories are opened here, where
        // Git has just said where they are, and kept: every later question about this
        // repository's own data is asked of these handles, so nothing has to resolve those paths
        // again and find whatever has since taken the name.
        let git_dir = AuthorisedDirectory::open_root(environment_id, &git_dir_path)?;
        let own_dir = if own_dir_path == git_dir_path {
            git_dir.try_clone()?
        } else {
            AuthorisedDirectory::open_root(environment_id, &own_dir_path)?
        };
        let tree = AuthorisedDirectory::open_root(environment_id, &top_level)?;
        let identity = RepositoryIdentity {
            git_dir: git_dir.identity(),
            work_tree: tree.identity(),
        };
        let audit = ConfigurationAudit::take(profile, &top_level, Some(identity.work_tree))?;
        // A driver whose name this host cannot express as an override is one whose override would
        // be for a different key. Reading the repository beside it could be reading it *through*
        // it, so nothing is read at all: this is the bar for every operation rather than only for
        // taking the repository into the registry.
        audit.require_expressible()?;
        Ok(Self {
            work_tree,
            git_dir,
            own_dir,
            identity,
            git_dir_path,
            own_dir_path,
            top_level,
            audit,
        })
    }

    /// Opens a working tree and requires it to be the object a record named.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when either identity differs from the record's,
    /// or whatever [`Self::open`] returns.
    pub fn open_recorded(
        profile: &RestrictedProfile,
        environment_id: EnvironmentId,
        path: &Path,
        expected: RepositoryIdentity,
    ) -> Result<Self> {
        let opened = Self::open(profile, environment_id, path)?;
        opened.require_identity(expected)?;
        Ok(opened)
    }

    /// Refuses when this repository is not the object a record named.
    ///
    /// A rename of the checkout keeps both identities, so the grant still names the same objects.
    /// A different repository at the recorded path, or a linked worktree standing in for the tree
    /// the record was made against, has a different identity and is refused rather than served.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] naming what was recorded and what is there.
    pub fn require_identity(&self, expected: RepositoryIdentity) -> Result<()> {
        if self.identity.git_dir != expected.git_dir {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this record names the repository {}, and {} holds the repository {}; a \
                     recorded identity is the object rather than the path, so nothing is served \
                     from it",
                    expected.git_dir,
                    crate::git::redact(&self.top_level.display().to_string()),
                    self.identity.git_dir
                )
                .into(),
            });
        }
        if self.identity.work_tree != expected.work_tree {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this record names the working tree {}, and {} is the working tree {}; a \
                     linked worktree is its own object and a record of one never covers another",
                    expected.work_tree,
                    crate::git::redact(&self.top_level.display().to_string()),
                    self.identity.work_tree
                )
                .into(),
            });
        }
        Ok(())
    }

    /// Returns the working tree's authorised handle.
    #[must_use]
    pub const fn work_tree(&self) -> &AuthorisedDirectory {
        &self.work_tree
    }

    /// Returns both identities.
    #[must_use]
    pub const fn identity(&self) -> RepositoryIdentity {
        self.identity
    }

    /// Returns the working tree's top level, for a diagnostic and for `-C`.
    #[must_use]
    pub fn top_level(&self) -> &Path {
        &self.top_level
    }

    /// Returns the Git common directory's path, for a diagnostic.
    #[must_use]
    pub fn git_dir_path(&self) -> &Path {
        &self.git_dir_path
    }

    /// Returns the handle on the administrative directory every worktree of this repository
    /// shares, opened when its identity was read.
    #[must_use]
    pub const fn git_dir(&self) -> &AuthorisedDirectory {
        &self.git_dir
    }

    /// Returns the handle on **this working tree's own** administrative directory.
    #[must_use]
    pub const fn own_dir(&self) -> &AuthorisedDirectory {
        &self.own_dir
    }

    /// Returns **this working tree's own** Git directory, which a split repository keeps apart
    /// from the one every worktree of it shares.
    ///
    /// The same path as [`Self::git_dir_path`] in an ordinary repository, and a different one in a
    /// linked worktree or a repository that was made with the two apart. A caller excluding a
    /// repository's administrative data has to know both, because both hold it.
    #[must_use]
    pub fn own_dir_path(&self) -> &Path {
        &self.own_dir_path
    }

    /// Returns what this repository's configuration named.
    #[must_use]
    pub const fn audit(&self) -> &ConfigurationAudit {
        &self.audit
    }

    /// Confirms that the objects and the configuration an invocation ran against are still these.
    ///
    /// Two things a Git invocation does are outside this crate's handles. It resolves the path
    /// `-C` names for itself, and it reads the configuration for itself. So a writer under the
    /// same operating-system account could put a different tree at that path, or add a driver the
    /// audit did not blank, between the check and the invocation.
    ///
    /// Neither is preventable through Git's own interface, so what this host does is notice:
    /// re-open the path, compare both filesystem identities, re-read the configuration and compare
    /// its digest. A result produced against something else is refused rather than returned. What
    /// remains is a change made and undone inside one invocation, which two readings cannot
    /// distinguish from no change at all.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when either identity or the configuration differs.
    pub fn confirm(&self, profile: &RestrictedProfile) -> Result<()> {
        // The repository is asked where its common directory and its top level are, rather than
        // reopened at the paths recorded earlier. A `.git` file rewritten to point elsewhere would
        // otherwise pass a check made against the old path's object.
        let arguments: [&OsStr; 4] = [
            OsStr::new("rev-parse"),
            OsStr::new("--path-format=absolute"),
            OsStr::new("--git-common-dir"),
            OsStr::new("--show-toplevel"),
        ];
        let reported = profile.run_checked(
            &GitRequest::read(&self.top_level, &arguments).expecting(self.identity.work_tree),
        )?;
        let mut lines = reported.lines();
        let git_dir_path = PathBuf::from(lines.next().unwrap_or_default());
        let top_level = PathBuf::from(lines.next().unwrap_or_default());
        if git_dir_path != self.git_dir_path || top_level != self.top_level {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this repository reported {} and {} and now reports {} and {}; what the host \
                     read was read somewhere else",
                    // All four came out of Git: two when the repository was opened and two now.
                    // A path is repeated as it is unless it holds something a URL is made of,
                    // which is what the rule decides.
                    crate::git::redact(&self.git_dir_path.display().to_string()),
                    crate::git::redact(&self.top_level.display().to_string()),
                    crate::git::redact(&git_dir_path.display().to_string()),
                    crate::git::redact(&top_level.display().to_string())
                )
                .into(),
            });
        }
        let tree = AuthorisedDirectory::open_root(self.work_tree.environment_id(), &top_level)?;
        let git_dir =
            AuthorisedDirectory::open_root(self.work_tree.environment_id(), &git_dir_path)?;
        self.require_identity(RepositoryIdentity {
            git_dir: git_dir.identity(),
            work_tree: tree.identity(),
        })?;
        let later = ConfigurationAudit::take(profile, &top_level, Some(self.identity.work_tree))?;
        self.audit.unchanged(&later)
    }

    /// Re-reads this repository's configuration and refuses when it changed.
    ///
    /// The overrides an invocation runs with are built from the audit taken when the repository
    /// was opened, and a writer under the same operating-system account can add a driver after
    /// that. This is what a caller runs immediately before writing: it does not close the window
    /// between the reading and the process starting — nothing Git offers does — but it does mean
    /// the configuration a write runs under was read a moment earlier rather than whenever the
    /// repository was opened.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the configuration changed, or
    /// [`ProjectError::ConfigurationRejected`] when what it now holds cannot be neutralised.
    pub fn recheck(&self, profile: &RestrictedProfile) -> Result<()> {
        let later =
            ConfigurationAudit::take(profile, &self.top_level, Some(self.identity.work_tree))?;
        later.require_expressible()?;
        self.audit.unchanged(&later)
    }

    /// Builds a read that runs under this repository's own driver overrides.
    ///
    /// The invocation is started in the working tree this record names, as the object rather than
    /// as the path, and its boundary lets it write in that tree and in the repository's own Git
    /// directory and nowhere else.
    #[must_use]
    pub fn read<'a>(&'a self, arguments: &'a [&'a OsStr]) -> GitRequest<'a> {
        GitRequest::read(&self.top_level, arguments)
            .with_drivers(self.audit.drivers.clone())
            .writing(&[(self.git_dir_path.as_path(), self.identity.git_dir)])
            .expecting(self.identity.work_tree)
    }

    /// Builds a write that runs under this repository's own driver overrides.
    #[must_use]
    pub fn write<'a>(&'a self, arguments: &'a [&'a OsStr]) -> GitRequest<'a> {
        GitRequest::write(&self.top_level, arguments)
            .with_drivers(self.audit.drivers.clone())
            .writing(&[(self.git_dir_path.as_path(), self.identity.git_dir)])
            .expecting(self.identity.work_tree)
    }

    /// Returns the revision `HEAD` names, and the reference it was named by.
    ///
    /// A repository with no commit yet has neither, which is what `project.init` leaves behind.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the repository cannot be read.
    pub fn head(&self, profile: &RestrictedProfile) -> Result<(Option<String>, Option<String>)> {
        let arguments: [&OsStr; 3] = [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("HEAD"),
        ];
        let output = profile.run(&self.read(&arguments))?;
        // A non-zero exit is the answer for a repository with no commit yet, so the exit code is
        // not what is checked here. A short read is still refused: an output this host holds only
        // part of would look exactly like that answer.
        output.require_complete()?;
        let revision = if output.success {
            let text = output.text().trim().to_owned();
            (!text.is_empty()).then_some(text)
        } else {
            None
        };
        let arguments: [&OsStr; 3] = [
            OsStr::new("symbolic-ref"),
            OsStr::new("--quiet"),
            OsStr::new("HEAD"),
        ];
        let output = profile.run(&self.read(&arguments))?;
        output.require_complete()?;
        let reference = if output.success {
            let text = output.text().trim().to_owned();
            (!text.is_empty()).then_some(text)
        } else {
            None
        };
        Ok((revision, reference))
    }

    /// Returns the object format this repository names its objects in.
    ///
    /// Asked of the **Git common directory**, under the identity this record holds for it, rather
    /// than of the working tree. A working tree names its repository through an indirection it
    /// holds itself — a linked worktree's `.git` is a file saying where the repository is — and
    /// that indirection can be rewritten to name another repository without the working tree or
    /// the Git directory this record opened becoming a different object. A reference update
    /// writes in the Git directory, so the format that decides how long a full object name is has
    /// to be read from the same place.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the repository will not say, and
    /// [`ProjectError::InvalidArgument`] for a format this service does not know.
    pub fn object_format(&self, profile: &RestrictedProfile) -> Result<ObjectFormat> {
        let arguments: [&OsStr; 2] = [OsStr::new("rev-parse"), OsStr::new("--show-object-format")];
        let request = GitRequest::read(&self.git_dir_path, &arguments)
            .with_drivers(self.audit.drivers.clone())
            .expecting(self.identity.git_dir);
        let output = profile.run(&request)?;
        output.require_success()?;
        ObjectFormat::parse(output.text().trim())
    }

    /// Performs a reference update via `update-ref` with expected old value.
    ///
    /// The write is bounded by a write grant for the repository's Git common directory
    /// (`git_dir_path`) and nothing wider: the working tree is not writable.
    ///
    /// Both object names are checked against **this repository's own format** before the
    /// invocation is built. A full name of the other format's length is a revision here rather
    /// than an object, and Git would resolve it: a reference or a tag whose own name is that many
    /// hexadecimal characters would then decide what the update moves or what it was compared
    /// against, which is not the compare-and-swap this method offers.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::InvalidArgument`] when either name is not full in this
    /// repository's format, and [`ProjectError::GitFailed`] when the reference cannot be updated
    /// or the old value does not match.
    pub fn update_ref(
        &self,
        profile: &RestrictedProfile,
        reference: &str,
        new_oid: &str,
        old_oid: &str,
        no_deref: bool,
    ) -> Result<()> {
        let format = self.object_format(profile)?;
        crate::git::check_object_name_width(new_oid, format, "the new value")?;
        crate::git::check_object_name_width(old_oid, format, "the expected old value")?;
        let mut arguments: Vec<&OsStr> = vec![OsStr::new("update-ref")];
        if no_deref {
            arguments.push(OsStr::new("--no-deref"));
        }
        arguments.push(OsStr::new(reference));
        arguments.push(OsStr::new(new_oid));
        arguments.push(OsStr::new(old_oid));
        let request = GitRequest::write(&self.git_dir_path, &arguments)
            .with_drivers(self.audit.drivers.clone())
            .expecting(self.identity.git_dir);
        let output = profile.run(&request)?;
        output.require_success()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-14.05: the administrative handles name the objects whose identities were read, and
    /// go on naming them when the paths they were read from name something else.
    ///
    /// This is what a caller accounting for a repository's own data stands on. Resolving those
    /// paths again would let whatever has since taken the name be the thing that was accounted
    /// for, while the data it covered went unexamined.
    #[cfg(unix)]
    #[test]
    fn the_administrative_handles_keep_their_objects_when_the_paths_name_something_else() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
        let checkout = root.path().join("project");
        std::fs::create_dir_all(&checkout).expect("a directory for the checkout");
        let profile_root = root.path().join("profile");
        let profile = match RestrictedProfile::prepare(&profile_root, environment_id) {
            Ok(profile) => profile,
            Err(error) => {
                println!("not exercised: this host has no Git to prepare a profile with: {error}");
                return;
            }
        };
        let made = std::process::Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(["init", "--initial-branch=main"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", root.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git runs");
        assert!(made.status.success(), "the repository is made");
        std::fs::write(
            checkout.join(".git/kr-witness"),
            b"the object that was opened\n",
        )
        .expect("a file only the real directory holds");
        let opened = OpenedRepository::open(&profile, environment_id, &checkout)
            .expect("the repository opens");
        let recorded = opened.identity().git_dir;
        assert_eq!(
            opened.git_dir().identity(),
            recorded,
            "the handle is on the object the identity was read from"
        );

        // The name now belongs to something else entirely.
        std::fs::rename(checkout.join(".git"), root.path().join("moved"))
            .expect("the administrative directory is moved away");
        std::fs::create_dir(checkout.join(".git")).expect("something else takes the name");

        // Asked of the handle rather than of anything it remembered: what it reads is what the
        // object it opened holds, and the name reaches none of it.
        let witness = kr_transfer::RelativeName::parse("kr-witness").expect("a name");
        let mut held = opened
            .git_dir()
            .open_read(&witness, kr_transfer::ObjectPolicy::ReadableFile)
            .expect("the handle still reaches what it opened");
        let mut said = String::new();
        std::io::Read::read_to_string(held.handle_mut(), &mut said).expect("it reads");
        assert_eq!(said, "the object that was opened\n");
        assert_eq!(
            opened.own_dir().identity(),
            recorded,
            "an ordinary repository keeps its own data in the one place, and that is this object"
        );
        let taken = AuthorisedDirectory::open_root(environment_id, &checkout.join(".git"))
            .expect("the name opens");
        assert_ne!(
            opened.git_dir().identity(),
            taken.identity(),
            "which is a different object from the one the path reaches now"
        );
        assert!(
            taken
                .open_read(&witness, kr_transfer::ObjectPolicy::ReadableFile)
                .is_err(),
            "and what took the name holds none of it"
        );
    }

    #[test]
    fn the_wire_form_of_an_identity_carries_both_numbers_unchanged() {
        let identity = ObjectIdentity {
            device: 16_777_234,
            file_id: 92_143_887,
        };
        let wire = wire_identity(identity);
        assert_eq!(wire.device.get(), 16_777_234);
        assert_eq!(wire.file_id.get(), 92_143_887);
        assert_eq!(object_identity(wire), identity);
    }
}
