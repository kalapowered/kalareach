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
use kr_transfer::{AuthorisedDirectory, ObjectIdentity, RecordedIdentity, RelativeName, Settled};

use crate::discovery::Discovered;
use crate::error::{ProjectError, Result};
use crate::git::{ConfigurationAudit, GitRequest, ObjectFormat, ReadAdmission, RestrictedProfile};

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

/// What one repository's two identities are as the journal records them: each with the filesystem
/// it was on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedRepository {
    /// The Git common directory.
    pub git_dir: RecordedIdentity,
    /// The working tree.
    pub work_tree: RecordedIdentity,
}

/// A repository whose record is to be replaced by what the repository is now.
///
/// A device number names one mounting of a filesystem and not the filesystem: a container's root
/// filesystem comes back under another number when the container starts again after another has
/// started. A record written before filesystems were recorded holds none. Either way the
/// repository is the recorded one, and whoever holds the record replaces `was` by `now`, so that
/// the numbers it carries are not taken for another filesystem's later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revised {
    /// The identities as the record carries them.
    pub was: RecordedRepository,
    /// The identities as the repository has them now.
    pub now: RecordedRepository,
}

/// What a record names of the repository a working tree belongs to, which an open decides before
/// Git is asked anything in the tree and before the repository's configuration is audited.
#[derive(Clone, Copy, Debug)]
pub struct RecordedTree {
    /// The working tree's top level.
    pub tree: RecordedIdentity,
    /// How the repository's Git directory is decided.
    pub git_dir: GitDirectory,
}

/// How the Git directory of the repository a recorded working tree belongs to is decided.
#[derive(Clone, Copy, Debug)]
pub enum GitDirectory {
    /// A record names it, and the repository keeps it wherever its configuration puts it: a
    /// checkout whose configuration sets `core.worktree` keeps it above its tree, so Git's search
    /// for the repository is not stopped above the tree. A repository the owner registered may
    /// have been registered through a directory below its top level; the record says whether its
    /// path is the top level, and where it is not, the directory at the recorded path is the tree
    /// or lies inside it.
    Named {
        /// The record of the repository's Git directory.
        recorded: RecordedIdentity,
        /// Whether the record's path is the working tree's top level, which the registration
        /// established when the repository was taken in: the directory at the path is then the
        /// tree itself, never a directory inside it.
        path_is_top_level: bool,
    },
    /// A record names it, and this host made the tree at the record's path: a linked worktree, or
    /// a repository it published. The tree's own `.git`, a directory or a file that names the
    /// repository's Git directory, is how Git finds the repository, so the directory at the path
    /// is the tree itself, never a directory inside it, and Git's search for the repository is
    /// stopped above the tree. Unlike [`Self::InsideTree`] it asks nothing of what the `.git` is.
    AtTree(RecordedIdentity),
    /// The repository was made inside its tree, an independent clone or a repository this host
    /// staged: its Git directory is the tree's own `.git`, a directory and never a file or a link
    /// to another repository, and no other repository is its repository, so Git's search for one
    /// is stopped above the tree. The directory at its path is the tree itself, never a directory
    /// inside it.
    ///
    /// `recorded` is the record of that directory. A clone an earlier build recorded, and a
    /// repository that has only just been published, have none yet: the directory found is the
    /// tree's own `.git`, and what it is is what the open reports for its holder to record.
    InsideTree {
        /// The record of the tree's own `.git`, when one was made.
        recorded: Option<RecordedIdentity>,
    },
}

/// What the records of an opened repository are to become once its directories were decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decided {
    /// What the record of the working tree is to become.
    pub tree: Settled,
    /// What the record of the Git directory is to become.
    pub git_dir: GitDirOutcome,
}

/// What the record of a repository's Git directory is to become.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitDirOutcome {
    /// No record named the directory and none was asked to: the open decided nothing about it.
    Undecided,
    /// A record named it, and the directory is that one: the record is as it is or is revised, as
    /// every recorded directory's is.
    Settled(Settled),
    /// No record named it, and it is the tree's own `.git`: this is the record it is to have.
    Found(RecordedIdentity),
}

impl Decided {
    /// Returns what the record of a repository is to become, or `None` when it is as the
    /// repository is. A Git directory that no record decided leaves its record as it is.
    #[must_use]
    pub fn revision(&self, expected: RecordedRepository) -> Option<Revised> {
        let git_dir = match self.git_dir {
            GitDirOutcome::Settled(settled) => settled,
            GitDirOutcome::Undecided | GitDirOutcome::Found(_) => Settled::AsRecorded,
        };
        (git_dir != Settled::AsRecorded || self.tree != Settled::AsRecorded).then_some(Revised {
            was: expected,
            now: RecordedRepository {
                git_dir: git_dir.current(expected.git_dir),
                work_tree: self.tree.current(expected.work_tree),
            },
        })
    }
}

impl GitDirectory {
    /// Returns whether the directory at the record's path is the working tree itself, and never a
    /// directory inside it.
    const fn path_is_tree(self) -> bool {
        matches!(
            self,
            Self::AtTree(_)
                | Self::InsideTree { .. }
                | Self::Named {
                    path_is_top_level: true,
                    ..
                }
        )
    }

    /// Returns whether Git's search for the repository stops above the tree: the repository is
    /// found from the tree's own `.git` and nowhere else.
    const fn stops_above_tree(self) -> bool {
        matches!(self, Self::AtTree(_) | Self::InsideTree { .. })
    }

    /// Refuses, before Git is asked anything, a tree whose own `.git` is not a directory, and one
    /// that is not the directory recorded for it where a record names one. Git then never follows
    /// a `.git` file or a link in the tree to another repository.
    fn decide_before_git(self, tree: &AuthorisedDirectory) -> Result<()> {
        let Self::InsideTree { recorded } = self else {
            return Ok(());
        };
        let own = own_git_dir(tree)?;
        match recorded {
            Some(recorded) => own.check_recorded(recorded).map(|_| ()).map_err(|refusal| {
                not_the_recorded_git_dir(recorded, tree.display_path(), own.identity(), &refusal)
            }),
            None => Ok(()),
        }
    }

    /// Decides the Git directory Git reported, before the repository's configuration is audited.
    ///
    /// `tree` is the working tree the repository belongs to, and `shown` names it in a refusal.
    fn decide(
        self,
        tree: &AuthorisedDirectory,
        git_dir: &AuthorisedDirectory,
        shown: &Path,
    ) -> Result<GitDirOutcome> {
        match self {
            Self::Named { recorded, .. }
            | Self::AtTree(recorded)
            | Self::InsideTree {
                recorded: Some(recorded),
            } => git_dir
                .check_recorded(recorded)
                .map(GitDirOutcome::Settled)
                .map_err(|refusal| {
                    not_the_recorded_git_dir(recorded, shown, git_dir.identity(), &refusal)
                }),
            Self::InsideTree { recorded: None } => {
                // Nothing is recorded to decide against, so the repository has to be the tree's
                // own: the directory Git reported is the `.git` inside the tree.
                let own = own_git_dir(tree)?;
                if own.identity() != git_dir.identity() {
                    return Err(ProjectError::IdentityChanged {
                        detail: format!(
                            "{} is a repository made inside its tree, and the repository Git \
                             found for it is not the tree's own .git",
                            crate::git::redact(&shown.display().to_string())
                        )
                        .into(),
                    });
                }
                Ok(GitDirOutcome::Found(own.recorded()?))
            }
        }
    }
}

/// An opened repository: the handle, the identities and what its configuration named.
#[derive(Debug)]
pub struct OpenedRepository {
    work_tree: AuthorisedDirectory,
    /// The working tree's top level, held open from the moment its identity was read: the object
    /// [`RepositoryIdentity::work_tree`] names. [`Self::work_tree`] is the directory the repository
    /// was opened through, which is a directory below the top when the caller named one.
    top: AuthorisedDirectory,
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
    /// Where Git's search for this repository stops, given to every invocation against it: the
    /// directory above the working tree of a repository that lies inside its tree. A tree that
    /// loses its own repository then finds none, whichever request is the first to look, instead
    /// of finding the repository around it. None where the repository may keep its Git directory
    /// anywhere, and where the platform cannot say where the tree is.
    ceiling: Option<PathBuf>,
    /// What every invocation against this repository asks before it starts, when the repository
    /// was reached through an authorised location.
    admission: Option<ReadAdmission>,
    /// The location the repository was reached through and its working tree's name beneath it,
    /// so a confirmation finds it again the same way rather than by a path.
    through: Option<(AuthorisedDirectory, RelativeName)>,
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
        Self::open_deciding(profile, environment_id, path, None).map(|(opened, _)| opened)
    }

    /// Opens a working tree that a record names, and decides that the directory at its path is
    /// that tree, and that the repository Git finds is the recorded one, before anything else is
    /// done.
    ///
    /// The directory is opened and decided first, and Git starts in that object: a directory that
    /// took the place of the recorded tree, or a filesystem mounted over it, is refused before Git
    /// is asked anything. For a repository the owner registered through a directory below its top
    /// level the directory at the path may lie inside the recorded tree
    /// ([`GitDirectory::Named`], `require_within`); for a tree this host made
    /// ([`GitDirectory::AtTree`], [`GitDirectory::InsideTree`]) and for one the owner registered
    /// at its top level it is the tree itself, and for a
    /// repository made inside its tree the tree's own `.git` must also be a directory, and the
    /// recorded one where a record names it, before Git starts. Git then
    /// reports the top level of the repository it finds, and that top level is decided before its
    /// configuration is audited: a repository whose top level is not the recorded tree, found
    /// inside or around it, is refused unaudited. Its Git directory is decided the same way
    /// ([`GitDirectory`]), so a repository around the tree whose configuration names the tree as
    /// its working tree, and so reports the recorded tree as its top level, is refused before its
    /// configuration is read.
    ///
    /// For a tree this host made Git's search is stopped at the directory above the tree, and that
    /// ceiling stays on the opened repository for every request made against it, so a tree that
    /// lost its own `.git` finds no repository rather than the one around it. A repository the
    /// owner registered can keep its Git directory anywhere (a checkout whose configuration sets
    /// `core.worktree` keeps it above the tree), so the search is not stopped. It is not stopped
    /// either where the platform cannot say where the tree is, or where the path of the directory
    /// above it holds the character Git separates its ceilings by; the Git directory decision
    /// then refuses another repository, after Git has said where it is.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the directory is not the recorded tree (nor
    /// inside it, for a repository the owner registered), when the top level Git
    /// reports is not the recorded tree, when the Git directory is not the recorded one, or what
    /// [`Self::open`] returns.
    pub fn open_recorded_tree(
        profile: &RestrictedProfile,
        environment_id: EnvironmentId,
        path: &Path,
        recorded: RecordedTree,
    ) -> Result<(Self, Decided)> {
        Self::open_deciding(profile, environment_id, path, Some(recorded))
    }

    /// Opens a working tree like [`Self::open`], deciding it against `recorded` when a record
    /// names it: the directory at the path before Git is asked anything, which is where Git
    /// starts, the top level Git reports, and the Git directory it reports, each before the
    /// configuration is audited.
    fn open_deciding(
        profile: &RestrictedProfile,
        environment_id: EnvironmentId,
        path: &Path,
        recorded: Option<RecordedTree>,
    ) -> Result<(Self, Decided)> {
        let work_tree = AuthorisedDirectory::open_root(environment_id, path)?;
        let ceiling = match recorded {
            Some(recorded) => {
                // A tree this host made is at its own place and nowhere below it, and so is a
                // repository the owner registered at its top level, so the directory at the path
                // is the tree itself. A directory inside the tree is what Git would start in when
                // a link at the path names one, and a repository found there is not the one the
                // record is for. A repository the owner registered through a directory below its
                // top level keeps that directory's path.
                let within = if recorded.git_dir.path_is_tree() {
                    decide_tree_before_git(&work_tree, recorded.tree)?;
                    work_tree.try_clone()?
                } else {
                    require_within(&work_tree, recorded.tree)?
                };
                recorded.git_dir.decide_before_git(&within)?;
                recorded
                    .git_dir
                    .stops_above_tree()
                    .then(|| ceiling_above(&within))
                    .flatten()
            }
            None => None,
        };
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
        let mut request = GitRequest::read(path, &arguments).expecting(work_tree.identity());
        if let Some(ceiling) = ceiling.as_deref() {
            request = request.with_ceiling(ceiling);
        }
        let reported = profile.run_checked(&request)?;
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
        // The top level is opened and decided before its configuration is audited, and before
        // anything else is run in the repository Git found.
        let tree = AuthorisedDirectory::open_root(environment_id, &top_level)?;
        let settled_tree = match recorded {
            Some(recorded) => tree.check_recorded(recorded.tree).map_err(|refusal| {
                not_the_recorded_tree(recorded.tree, tree.display_path(), &refusal)
            })?,
            None => Settled::AsRecorded,
        };
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
        // And the Git directory is decided before the configuration is audited too: a repository
        // that is not the recorded one is not read, whatever top level it reports.
        let settled_git_dir = match recorded {
            Some(recorded) => recorded.git_dir.decide(&tree, &git_dir, &top_level)?,
            None => GitDirOutcome::Undecided,
        };
        let identity = RepositoryIdentity {
            git_dir: git_dir.identity(),
            work_tree: tree.identity(),
        };
        let audit = ConfigurationAudit::take(
            profile,
            &top_level,
            Some(identity.work_tree),
            None,
            ceiling.as_deref(),
        )?;
        // A driver whose name this host cannot express as an override is one whose override would
        // be for a different key. Reading the repository beside it could be reading it *through*
        // it, so nothing is read at all: this is the bar for every operation rather than only for
        // taking the repository into the registry.
        audit.require_expressible()?;
        Ok((
            Self {
                work_tree,
                top: tree,
                git_dir,
                own_dir,
                identity,
                git_dir_path,
                own_dir_path,
                top_level,
                audit,
                ceiling,
                admission: None,
                through: None,
            },
            Decided {
                tree: settled_tree,
                git_dir: settled_git_dir,
            },
        ))
    }

    /// Takes a repository this host found through a location, and audits its configuration.
    ///
    /// Nothing is discovered here: the directories are the handles [`crate::discovery`] found,
    /// each by a descent from the location, before Git was asked anything. When a record names
    /// the repository's Git directory, `git_dir` decides it before the configuration is audited;
    /// what is left is the configuration, read through the profile with every invocation asking
    /// `admission` first, and one more refusal: a repository that sets `core.worktree` is not
    /// reached through a location, because overriding it would change where Git looks without
    /// proving where it looked.
    ///
    /// Every directory of a repository found this way lies beneath its working tree, which is what
    /// the descent accepts, so Git's search for it never has to leave the tree: it is stopped at
    /// the directory above, for every invocation against the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] for a Git directory that is not the recorded one,
    /// [`ProjectError::PermissionDenied`] for a repository that sets `core.worktree`,
    /// [`ProjectError::ConfigurationRejected`] for one whose drivers cannot be overridden, or the
    /// refusal the admission gives.
    pub fn discovered(
        profile: &RestrictedProfile,
        found: Discovered,
        through: (AuthorisedDirectory, RelativeName),
        admission: Option<ReadAdmission>,
        git_dir: Option<GitDirectory>,
    ) -> Result<(Self, GitDirOutcome)> {
        let top_level = found.work_tree.display_path().to_path_buf();
        let git_dir_path = found.common_dir.display_path().to_path_buf();
        let own_dir_path = found.git_dir.display_path().to_path_buf();
        let settled_git_dir = match git_dir {
            Some(rule) => rule.decide(&found.work_tree, &found.common_dir, &top_level)?,
            None => GitDirOutcome::Undecided,
        };
        let identity = RepositoryIdentity {
            git_dir: found.common_dir.identity(),
            work_tree: found.work_tree.identity(),
        };
        let ceiling = ceiling_above(&found.work_tree);
        let audit = ConfigurationAudit::take(
            profile,
            &top_level,
            Some(identity.work_tree),
            admission.as_ref(),
            ceiling.as_deref(),
        )?;
        audit.require_expressible()?;
        if audit.sets_worktree {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "the repository at {} is not reached through a location: its configuration \
                     sets core.worktree, and overriding that would change where Git looks \
                     without proving where it looked",
                    crate::git::redact(&top_level.display().to_string())
                )
                .into(),
            });
        }
        Ok((
            Self {
                top: found.work_tree.try_clone()?,
                work_tree: found.work_tree,
                git_dir: found.common_dir,
                own_dir: found.git_dir,
                identity,
                git_dir_path,
                own_dir_path,
                top_level,
                audit,
                ceiling,
                admission,
                through: Some(through),
            },
            settled_git_dir,
        ))
    }

    /// Returns what every invocation against this repository asks before it starts, when it was
    /// reached through a location.
    #[must_use]
    pub const fn admission(&self) -> Option<&ReadAdmission> {
        self.admission.as_ref()
    }

    /// Returns whether the directory this repository was opened through is its working tree's top
    /// level, as opposed to a directory below it.
    #[must_use]
    pub fn path_is_top_level(&self) -> bool {
        self.work_tree.identity() == self.top.identity()
    }

    /// Returns both identities as the journal records them.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when a directory cannot be asked which filesystem it
    /// is on.
    pub fn recorded(&self) -> Result<RecordedRepository> {
        Ok(RecordedRepository {
            git_dir: self.git_dir.recorded()?,
            work_tree: self.top.recorded()?,
        })
    }

    /// Refuses when this repository is not the object a record named.
    ///
    /// A rename of the checkout keeps both identities, so the grant still names the same objects.
    /// A different repository at the recorded path, or a linked worktree standing in for the tree
    /// the record was made against, has a different identity and is refused rather than served.
    ///
    /// Each directory is decided by [`AuthorisedDirectory::check_recorded`]: it is the recorded
    /// one by its inode on the filesystem it was recorded on, under whatever device number that
    /// filesystem has now, and what comes back says what the record is to become ([`Revised`]);
    /// `None` says the record is as the repository is.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] naming what was recorded and what is there.
    pub fn require_identity(&self, expected: RecordedRepository) -> Result<Option<Revised>> {
        let git_dir = self.require_git_dir(expected.git_dir)?;
        let work_tree = self.require_tree(expected.work_tree)?;
        Ok(Decided {
            tree: work_tree,
            git_dir: GitDirOutcome::Settled(git_dir),
        }
        .revision(expected))
    }

    /// Refuses when this repository's Git common directory is not the directory a record named,
    /// by the rule [`Self::require_identity`] applies.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] naming what was recorded and what is there.
    pub fn require_git_dir(&self, expected: RecordedIdentity) -> Result<Settled> {
        self.git_dir
            .check_recorded(expected)
            .map_err(|refusal| self.git_dir_changed(expected, refusal))
    }

    /// Refuses when this repository's working tree is not the directory a record named, by the
    /// rule [`Self::require_identity`] applies. The tree is the top level, which is the object a
    /// record names, and not the directory the repository was opened through.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] naming what was recorded and what is there.
    pub fn require_tree(&self, expected: RecordedIdentity) -> Result<Settled> {
        self.top
            .check_recorded(expected)
            .map_err(|refusal| self.work_tree_changed(expected, refusal))
    }

    /// Refuses when what this repository is now is not what it was when it was opened.
    ///
    /// Both identities were read in this run, so they are compared as numbers: a device number
    /// that differs within one run is another filesystem and never a renumbered one.
    fn require_same(&self, now: RepositoryIdentity) -> Result<()> {
        let changed = |what: &str, was: ObjectIdentity, found: ObjectIdentity| {
            ProjectError::IdentityChanged {
                detail: format!(
                    "this repository was opened as the {what} {was}, and {} now holds the {what} \
                     {found}; what the host read was read somewhere else",
                    crate::git::redact(&self.top_level.display().to_string())
                )
                .into(),
            }
        };
        if self.identity.git_dir != now.git_dir {
            return Err(changed("repository", self.identity.git_dir, now.git_dir));
        }
        if self.identity.work_tree != now.work_tree {
            return Err(changed(
                "working tree",
                self.identity.work_tree,
                now.work_tree,
            ));
        }
        Ok(())
    }

    fn git_dir_changed(
        &self,
        expected: RecordedIdentity,
        refusal: kr_transfer::Escape,
    ) -> ProjectError {
        not_the_recorded_git_dir(expected, &self.top_level, self.identity.git_dir, &refusal)
    }

    fn work_tree_changed(
        &self,
        expected: RecordedIdentity,
        refusal: kr_transfer::Escape,
    ) -> ProjectError {
        ProjectError::IdentityChanged {
            detail: format!(
                "this record names the working tree {}, and {} is the working tree {}; a \
                 linked worktree is its own object and a record of one never covers another: {}",
                expected,
                crate::git::redact(&self.top_level.display().to_string()),
                self.identity.work_tree,
                crate::git::redact(&refusal.to_string())
            )
            .into(),
        }
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
            &self.bounded(
                GitRequest::read(&self.top_level, &arguments)
                    .expecting(self.identity.work_tree)
                    .admitted(self.admission.clone()),
            ),
        )?;
        let mut lines = reported.lines();
        let git_dir_path = PathBuf::from(lines.next().unwrap_or_default());
        let top_level = PathBuf::from(lines.next().unwrap_or_default());
        let moved = match &self.through {
            // A repository found through a location is named to Git by a path whose spelling
            // need not be Git's own, which resolves every link. What Git reports is compared with
            // the path the operating system gives for the handles this host holds, so nothing is
            // opened by the path Git reported.
            Some(_) => {
                path_of(&self.work_tree)? != top_level || path_of(&self.git_dir)? != git_dir_path
            }
            None => git_dir_path != self.git_dir_path || top_level != self.top_level,
        };
        if moved {
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
        let now = match &self.through {
            // Found again the way it was found the first time: through the location, by the
            // same descent, rather than by the paths Git reported.
            Some((location, relative)) => {
                let again = crate::discovery::discover_through(
                    location,
                    relative,
                    &self.top_level.display().to_string(),
                    self.admission.as_ref(),
                )?;
                RepositoryIdentity {
                    git_dir: again.common_dir.identity(),
                    work_tree: again.work_tree.identity(),
                }
            }
            None => {
                let tree =
                    AuthorisedDirectory::open_root(self.work_tree.environment_id(), &top_level)?;
                let git_dir =
                    AuthorisedDirectory::open_root(self.work_tree.environment_id(), &git_dir_path)?;
                RepositoryIdentity {
                    git_dir: git_dir.identity(),
                    work_tree: tree.identity(),
                }
            }
        };
        self.require_same(now)?;
        let later = ConfigurationAudit::take(
            profile,
            &top_level,
            Some(self.identity.work_tree),
            self.admission.as_ref(),
            self.ceiling.as_deref(),
        )?;
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
        let later = ConfigurationAudit::take(
            profile,
            &self.top_level,
            Some(self.identity.work_tree),
            self.admission.as_ref(),
            self.ceiling.as_deref(),
        )?;
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
        self.bounded(
            GitRequest::read(&self.top_level, arguments)
                .with_drivers(self.audit.drivers.clone())
                .writing(&[(self.git_dir_path.as_path(), self.identity.git_dir)])
                .expecting(self.identity.work_tree)
                .admitted(self.admission.clone()),
        )
    }

    /// Builds a write that runs under this repository's own driver overrides.
    #[must_use]
    pub fn write<'a>(&'a self, arguments: &'a [&'a OsStr]) -> GitRequest<'a> {
        self.bounded(
            GitRequest::write(&self.top_level, arguments)
                .with_drivers(self.audit.drivers.clone())
                .writing(&[(self.git_dir_path.as_path(), self.identity.git_dir)])
                .expecting(self.identity.work_tree)
                .admitted(self.admission.clone()),
        )
    }

    /// Gives a request the ceiling this repository was opened with, so that no request made
    /// against it searches for a repository above its tree when the repository lies inside it.
    ///
    /// Every request this repository builds goes through here, those that name its Git directory
    /// as the repository included: Git discovers nothing for those, and the ceiling is inert.
    fn bounded<'a>(&'a self, request: GitRequest<'a>) -> GitRequest<'a> {
        match self.ceiling.as_deref() {
            Some(ceiling) => request.with_ceiling(ceiling),
            None => request,
        }
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
    /// to be read from the same place. Git is told that the directory is the repository's Git
    /// directory rather than left to find one there, which is also what lets every Git this host
    /// accepts answer: Git 2.38 to 2.43 refuse a Git directory found by discovery as a bare
    /// repository under the profile's `safe.bareRepository=explicit`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the repository will not say, and
    /// [`ProjectError::InvalidArgument`] for a format this service does not know.
    pub fn object_format(&self, profile: &RestrictedProfile) -> Result<ObjectFormat> {
        let arguments: [&OsStr; 2] = [OsStr::new("rev-parse"), OsStr::new("--show-object-format")];
        let request = self.bounded(
            GitRequest::read(&self.git_dir_path, &arguments)
                .in_git_directory()
                .with_drivers(self.audit.drivers.clone())
                .expecting(self.identity.git_dir)
                .admitted(self.admission.clone()),
        );
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
        let request = self.bounded(
            GitRequest::write(&self.git_dir_path, &arguments)
                .in_git_directory()
                .with_drivers(self.audit.drivers.clone())
                .expecting(self.identity.git_dir)
                .admitted(self.admission.clone()),
        );
        let output = profile.run(&request)?;
        output.require_success()?;
        Ok(())
    }
}

/// Refuses, before Git is asked anything, when the directory found at a recorded path is neither
/// the working tree a record names nor a directory inside it, and returns the recorded tree.
///
/// A record names the top level of a working tree, and a repository that was registered through a
/// directory below its top level keeps that directory's path, so the directory at a recorded path
/// is the recorded tree itself or lies beneath it. A directory that is not the recorded tree is
/// followed upward by its own handle for as long as it stays on one mount; finding the recorded
/// tree on the way says the path is inside it. The mount is what the platform names it by (on
/// Linux its own identifier, which tells a bind mount from the tree it was made from, and
/// elsewhere the device). Another filesystem mounted over the path ends the climb at its own
/// root, and so does the root of the filesystem, and either refuses. Where a platform does not
/// open a directory's parent from its handle, only the recorded tree itself is accepted.
fn require_within(
    named: &AuthorisedDirectory,
    tree: RecordedIdentity,
) -> Result<AuthorisedDirectory> {
    let refusal = match named.check_recorded(tree) {
        Ok(_) => return Ok(named.try_clone()?),
        Err(refusal) => refusal,
    };
    let mount_of = |directory: &AuthorisedDirectory| {
        directory
            .try_clone()
            .and_then(AuthorisedDirectory::confined_to_one_mount)
            .ok()
            .and_then(|held| held.mount())
    };
    if let Some(mount) = mount_of(named) {
        let mut here = named.try_clone()?;
        while let Ok(above) = here.parent() {
            if above.identity() == here.identity() || mount_of(&above) != Some(mount) {
                break;
            }
            if above.check_recorded(tree).is_ok() {
                return Ok(above);
            }
            here = above;
        }
    }
    Err(not_the_recorded_tree(tree, named.display_path(), &refusal))
}

/// Returns where Git's search for a repository stops for a tree: the directory above it, which Git
/// does not look in. None where the platform does not say where the tree is, and where that
/// directory's path holds the character Git separates its ceilings by, which would split it.
fn ceiling_above(tree: &AuthorisedDirectory) -> Option<PathBuf> {
    let above = path_of(tree).ok()?.parent()?.to_path_buf();
    (!above.to_string_lossy().contains(crate::git::PATH_SEPARATOR)).then_some(above)
}

/// Returns the refusal for a directory that is not the working tree a record names.
pub(crate) fn not_the_recorded_tree(
    tree: RecordedIdentity,
    shown: &Path,
    refusal: &kr_transfer::Escape,
) -> ProjectError {
    ProjectError::IdentityChanged {
        detail: format!(
            "this record names the working tree {tree}, and {} is not that tree: a recorded \
             identity is the object rather than the path, so a record of one never covers another \
             object ({})",
            crate::git::redact(&shown.display().to_string()),
            crate::git::redact(&refusal.to_string())
        )
        .into(),
    }
}

/// Decides that the directory found at a working tree's place is exactly the recorded tree, and
/// returns what the tree's record is to become. It runs before anything of the repository is read
/// and before Git is asked anything: for a repository reached through a location, and for one made
/// inside its tree and opened by path. The repository's Git directory is decided once the descent
/// or Git has found it, before its configuration is audited ([`OpenedRepository::discovered`]).
///
/// # Errors
///
/// Returns [`ProjectError::IdentityChanged`] when the directory is not the recorded tree.
pub(crate) fn decide_tree_before_git(
    work_tree: &AuthorisedDirectory,
    tree: RecordedIdentity,
) -> Result<Settled> {
    work_tree
        .check_recorded(tree)
        .map_err(|refusal| not_the_recorded_tree(tree, work_tree.display_path(), &refusal))
}

/// Returns the refusal for a Git directory that is not the one a record names.
fn not_the_recorded_git_dir(
    expected: RecordedIdentity,
    shown: &Path,
    found: ObjectIdentity,
    refusal: &kr_transfer::Escape,
) -> ProjectError {
    ProjectError::IdentityChanged {
        detail: format!(
            "this record names the repository {expected}, and {} holds the repository {found}; a \
             recorded identity is the object rather than the path, so nothing is served from it: \
             {}",
            crate::git::redact(&shown.display().to_string()),
            crate::git::redact(&refusal.to_string())
        )
        .into(),
    }
}

/// Opens the `.git` directory a working tree holds, from the tree's own handle and following no
/// link, which is the Git directory of a repository made inside its tree.
fn own_git_dir(tree: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let name = RelativeName::parse(".git")?;
    tree.subdirectory(&name)
        .map_err(|refusal| ProjectError::IdentityChanged {
            detail: format!(
                "{} is a repository made inside its tree, and the tree holds no .git directory of \
             its own: {}",
                crate::git::redact(&tree.display_path().display().to_string()),
                crate::git::redact(&refusal.to_string())
            )
            .into(),
        })
}

/// Returns the path the operating system gives for an open directory now, taken from its handle.
///
/// It is the directory's path as the kernel knows it, with every link above it resolved, which is
/// how Git spells the paths it reports.
#[cfg(target_vendor = "apple")]
fn path_of(directory: &AuthorisedDirectory) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    let path = rustix::fs::getpath(directory.handle()).map_err(|error| unlocated(&error.into()))?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(
        path.into_bytes(),
    )))
}

/// Returns the path the operating system gives for an open directory now, taken from its handle.
///
/// It is the directory's path as the kernel knows it, with every link above it resolved, which is
/// how Git spells the paths it reports.
#[cfg(target_os = "linux")]
fn path_of(directory: &AuthorisedDirectory) -> Result<PathBuf> {
    use std::os::fd::{AsFd as _, AsRawFd as _};
    let descriptor = directory.handle().as_fd().as_raw_fd();
    std::fs::read_link(format!("/proc/self/fd/{descriptor}")).map_err(|error| unlocated(&error))
}

/// No platform this crate runs Git on is without one of the two above; elsewhere a repository
/// reached through a location is not confirmed at all.
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn path_of(_directory: &AuthorisedDirectory) -> Result<PathBuf> {
    Err(ProjectError::IdentityChanged {
        detail: "this platform does not say where an open directory is, so a repository reached \
                 through a location is not confirmed here"
            .to_owned()
            .into(),
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn unlocated(error: &std::io::Error) -> ProjectError {
    ProjectError::IdentityChanged {
        detail: format!(
            "this host could not ask where a repository's directory is now ({error}), so what Git \
             reported is not taken as that directory"
        )
        .into(),
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

    /// A record of a repository on a filesystem numbered differently since is still the record of
    /// it, and two readings taken in one run are not: within a run a device number that differs is
    /// another filesystem, and never a renumbered one.
    #[cfg(unix)]
    #[test]
    fn a_record_under_another_device_number_is_the_repository_and_a_live_reading_is_not() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([10; 16]));
        let checkout = root.path().join("project");
        std::fs::create_dir_all(&checkout).expect("a directory for the checkout");
        let profile = match RestrictedProfile::prepare(&root.path().join("profile"), environment_id)
        {
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
        let opened = OpenedRepository::open(&profile, environment_id, &checkout)
            .expect("the repository opens");
        let found = opened.identity();
        let recorded_now = opened.recorded().expect("reads its identities");
        let renumbered = |identity: RecordedIdentity| {
            RecordedIdentity::from_parts(
                identity.object.device.wrapping_add(1),
                identity.object.file_id,
                identity.filesystem,
            )
        };
        let recorded = RecordedRepository {
            git_dir: renumbered(recorded_now.git_dir),
            work_tree: renumbered(recorded_now.work_tree),
        };

        // The record carries numbers the repository no longer has: it is still the repository.
        assert_eq!(
            opened.require_identity(recorded_now).expect("as recorded"),
            None
        );
        assert_eq!(
            opened.require_identity(recorded).expect("renumbered"),
            Some(Revised {
                was: recorded,
                now: recorded_now
            })
        );
        // A record made before filesystems were recorded is decided by its numbers, and takes the
        // filesystem the repository is found on.
        let before = RecordedRepository {
            git_dir: RecordedIdentity::without_filesystem(recorded_now.git_dir.object),
            work_tree: RecordedIdentity::without_filesystem(recorded_now.work_tree.object),
        };
        assert_eq!(
            opened.require_identity(before).expect("made before"),
            Some(Revised {
                was: before,
                now: recorded_now
            })
        );
        // Another object is refused under either number, and so is another filesystem.
        let other = RecordedRepository {
            git_dir: RecordedIdentity {
                object: ObjectIdentity {
                    file_id: found.git_dir.file_id.wrapping_add(1),
                    ..recorded.git_dir.object
                },
                ..recorded.git_dir
            },
            ..recorded
        };
        assert!(opened.require_identity(other).is_err());
        let elsewhere = RecordedRepository {
            work_tree: RecordedIdentity {
                filesystem: Some(kr_transfer::FilesystemId::from_bytes(
                    [0xee; kr_transfer::FilesystemId::LEN],
                )),
                ..recorded_now.work_tree
            },
            ..recorded_now
        };
        assert!(opened.require_identity(elsewhere).is_err());

        // Two readings of one run are compared as numbers, each directory by itself.
        opened.require_same(found).expect("the same reading");
        let moved = RepositoryIdentity {
            git_dir: recorded.git_dir.object,
            work_tree: recorded.work_tree.object,
        };
        assert!(opened.require_same(moved).is_err());
        assert!(
            opened
                .require_same(RepositoryIdentity {
                    work_tree: moved.work_tree,
                    ..found
                })
                .is_err()
        );
        assert!(
            opened
                .require_same(RepositoryIdentity {
                    git_dir: moved.git_dir,
                    ..found
                })
                .is_err()
        );

        // A repository opened through a directory below its top is the object its record names,
        // whose identity is the top's, and not the directory it was opened through.
        std::fs::create_dir(checkout.join("below")).expect("a directory in the working tree");
        let below = OpenedRepository::open(&profile, environment_id, &checkout.join("below"))
            .expect("the repository opens below its top");
        assert_eq!(below.identity(), found);
        assert_eq!(
            below.require_identity(recorded_now).expect("as recorded"),
            None
        );
        assert_eq!(
            below.require_identity(recorded).expect("renumbered"),
            Some(Revised {
                was: recorded,
                now: recorded_now
            })
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
