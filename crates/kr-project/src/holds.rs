//! Who may write a repository while a capture reads it, and who is told to wait.
//!
//! A capture of a working tree can be recorded as a quiesced capture only if nothing this host
//! coordinates wrote the tree, its index or its repository's references for as long as the read
//! took. This module is that coordination, and nothing else: every writer the host makes asks it
//! before it writes, every session it starts says where it started, and a capture asks it for a
//! hold. A hold and a writer never overlap, and neither waits for the other: the one that comes
//! second is refused at once and asks again later. Holds do not exclude one another: each only
//! keeps writers off, so two captures of one repository can both be held.
//!
//! # Everything is a set of filesystem identities
//!
//! * A **writer** names what it writes inside or administers (`touch`) and the directories it may
//!   remove with everything beneath them (`deletes`).
//! * A **session** names the identities of the directory it started in and of every parent above
//!   it, or says it does not know where it started.
//! * A **hold** names the working tree held, its repository's Git directory and every tree this
//!   host records for that repository (`covers`), and the parents of the held tree (`ancestors`).
//!
//! A writer conflicts with a hold when its `touch` meets `covers`, or when its `deletes` meets
//! `covers` or `ancestors` (removing a tree removes the registered trees inside it). A session
//! conflicts when its chain meets `covers`, or when it is unknown. Sessions are matched to trees
//! when a hold is asked for, against what the host records then, so a tree adopted or published
//! after a session began still counts.
//!
//! The registry lives in memory behind one mutex that is a leaf: nothing is acquired while it is
//! held, and every read of the store and every directory open happens before it is taken. A hold
//! ends at its bound whatever its holder does, and a hold that ended never holds again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kr_protocol::ids::{SessionId, WorkspaceId};
use kr_protocol::project::{IsolationMechanism, WorkspaceKind, WorkspaceState};
use kr_transfer::{AuthorisedDirectory, ObjectIdentity};

use crate::error::{ProjectError, Result};
use crate::identity::OpenedRepository;
use crate::service::ProjectService;

/// How long a hold lasts at most, by the monotonic clock, whatever its holder does.
pub const HOLD_BOUND: Duration = Duration::from_secs(300);

/// How many parents a chain of identities climbs at most.
const MAX_CLIMB: usize = 256;

/// A set of filesystem identities.
pub type Identities = BTreeSet<ObjectIdentity>;

/// Where a registry reads the monotonic clock.
type Moment = Arc<dyn Fn() -> Instant + Send + Sync>;

/// What a writer writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Footprint {
    /// What it writes inside or administers.
    pub touch: Identities,
    /// The directories it may remove with everything beneath them.
    pub deletes: Identities,
    /// Whether nobody can say where it writes: it is in the way of every hold.
    pub anywhere: bool,
}

impl Footprint {
    /// A writer of the working tree and the Git directory of a repository it has open.
    #[must_use]
    pub fn of_repository(repository: &OpenedRepository) -> Self {
        let identity = repository.identity();
        Self {
            touch: Identities::from([identity.work_tree, identity.git_dir]),
            ..Self::default()
        }
    }

    /// A writer of a repository's Git directory alone.
    #[must_use]
    pub fn of_git_directory(git_dir: ObjectIdentity) -> Self {
        Self {
            touch: Identities::from([git_dir]),
            ..Self::default()
        }
    }

    /// A writer inside a directory, or beneath one of its parents.
    #[must_use]
    pub fn inside(chain: &[ObjectIdentity]) -> Self {
        Self {
            touch: chain.iter().copied().collect(),
            ..Self::default()
        }
    }

    /// A writer whose place nobody can say, which every hold turns away and which keeps every hold
    /// from being granted while it is at work.
    #[must_use]
    pub fn everywhere() -> Self {
        Self {
            anywhere: true,
            ..Self::default()
        }
    }

    /// Adds what `other` writes.
    #[must_use]
    pub fn and(mut self, other: Self) -> Self {
        self.touch.extend(other.touch);
        self.deletes.extend(other.deletes);
        self.anywhere |= other.anywhere;
        self
    }

    /// Adds a directory this writer may remove with everything beneath it.
    #[must_use]
    pub fn removing(mut self, directory: ObjectIdentity) -> Self {
        self.touch.insert(directory);
        self.deletes.insert(directory);
        self
    }
}

/// Where a session started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionPlace {
    /// The identities of the directory it started in and of every parent above it.
    Chain(Identities),
    /// Nobody can say where it started, so every hold waits for it to end.
    Unknown,
}

/// What a hold keeps other writers off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reach {
    /// The working tree, its repository's Git directory and every tree recorded for that
    /// repository.
    pub covers: Identities,
    /// The parents of the held working tree, which a writer that removes a tree meets.
    pub ancestors: Identities,
}

/// Why a hold was not granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The workspace is the user's own checkout, which the user's own tools write.
    SharedCheckout,
    /// The workspace is not ready, or is going.
    NotReady,
    /// What is at the workspace's place is not what the host recorded and the capture opened.
    TreeMoved,
    /// A writer of this host is at work in the repository.
    WriterAtWork(&'static str),
    /// This many live sessions started in a tree of the repository.
    SessionsBound(usize),
    /// The hold ran out before every tree of the repository was covered.
    Lapsed,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedCheckout => formatter.write_str(
                "it is a shared existing checkout, which the user's own tools write and nothing \
                 on this host can hold off",
            ),
            Self::NotReady => formatter.write_str("it is not a ready workspace"),
            Self::TreeMoved => formatter.write_str(
                "what is at its place is not the working tree this host recorded for it",
            ),
            Self::WriterAtWork(what) => write!(
                formatter,
                "{what} is at work in its repository, and a hold never waits for a writer"
            ),
            Self::SessionsBound(1) => formatter.write_str(
                "a live session started in a tree of its repository, and a session's shell \
                 writes where it runs",
            ),
            Self::Lapsed => formatter
                .write_str("the hold ran out before every tree of its repository was covered"),
            Self::SessionsBound(count) => write!(
                formatter,
                "{count} live sessions started in trees of its repository, and a session's \
                 shell writes where it runs"
            ),
        }
    }
}

struct Granted {
    reach: Reach,
    bound: Instant,
}

#[derive(Default)]
struct State {
    next: u64,
    writers: BTreeMap<u64, (&'static str, Footprint)>,
    sessions: BTreeMap<SessionId, SessionPlace>,
    holds: BTreeMap<u64, Granted>,
}

impl State {
    fn take_id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Forgets the holds whose bound has passed, and says what now is.
    fn expire(&mut self, now: Instant) {
        self.holds.retain(|_, granted| now < granted.bound);
    }

    /// Why a hold over `reach` cannot stand now: a writer at work, or a session alive, where it
    /// would reach.
    fn in_the_way_of(&self, reach: &Reach) -> Option<Refusal> {
        if let Some(what) = self
            .writers
            .values()
            .find(|(_, footprint)| writer_meets(footprint, reach))
            .map(|(what, _)| *what)
        {
            return Some(Refusal::WriterAtWork(what));
        }
        let sessions = self
            .sessions
            .values()
            .filter(|place| session_meets(place, reach))
            .count();
        (sessions > 0).then_some(Refusal::SessionsBound(sessions))
    }
}

/// Whether a writer's footprint meets a hold's reach.
fn writer_meets(footprint: &Footprint, reach: &Reach) -> bool {
    footprint.anywhere
        || !footprint.touch.is_disjoint(&reach.covers)
        || !footprint.deletes.is_disjoint(&reach.covers)
        || !footprint.deletes.is_disjoint(&reach.ancestors)
}

/// Whether a session started where a hold reaches.
fn session_meets(place: &SessionPlace, reach: &Reach) -> bool {
    match place {
        SessionPlace::Unknown => true,
        SessionPlace::Chain(chain) => !chain.is_disjoint(&reach.covers),
    }
}

/// The writers, the sessions and the holds of one environment.
pub struct WorkspaceHolds {
    state: Mutex<State>,
    moment: Moment,
}

impl std::fmt::Debug for WorkspaceHolds {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkspaceHolds")
    }
}

impl Default for WorkspaceHolds {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceHolds {
    /// An empty registry on the monotonic clock.
    #[must_use]
    pub fn new() -> Self {
        Self::on(Arc::new(Instant::now))
    }

    /// An empty registry that reads the monotonic clock from `moment`, so a case can move it.
    #[must_use]
    pub fn on(moment: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            moment,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A panic inside a critical section here leaves plain maps, never a half-made change.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a writer for as long as the returned guard lives.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Held`] when a hold stands where the writer would write. Nothing is
    /// registered then, and the writer has done nothing yet.
    pub fn begin_write(
        self: &Arc<Self>,
        what: &'static str,
        footprint: Footprint,
    ) -> Result<Writer> {
        let now = (self.moment)();
        let mut state = self.state();
        state.expire(now);
        if state
            .holds
            .values()
            .any(|granted| writer_meets(&footprint, &granted.reach))
        {
            return Err(ProjectError::Held {
                detail: format!(
                    "{what} was refused because a capture is holding the repository still; ask \
                     again when the capture has finished"
                )
                .into(),
            });
        }
        let id = state.take_id();
        state.writers.insert(id, (what, footprint));
        Ok(Writer {
            holds: Arc::clone(self),
            id,
        })
    }

    /// Registers a session as alive, where it started, for as long as the returned guard lives
    /// unless it is kept.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Held`] when a hold stands where the session started. Nothing is
    /// registered then.
    pub fn begin_session(
        self: &Arc<Self>,
        session: SessionId,
        place: SessionPlace,
    ) -> Result<SessionRegistration> {
        let now = (self.moment)();
        let mut state = self.state();
        state.expire(now);
        if state
            .holds
            .values()
            .any(|granted| session_meets(&place, &granted.reach))
        {
            return Err(ProjectError::Held {
                detail: "a session was refused because a capture is holding the repository it \
                         would start in still; ask again when the capture has finished"
                    .to_owned()
                    .into(),
            });
        }
        state.sessions.insert(session, place);
        Ok(SessionRegistration {
            holds: Arc::clone(self),
            session,
            armed: true,
        })
    }

    /// Registers a session that is known to be alive without asking: the daemon found it running
    /// at start, before anything can hold a repository.
    pub fn adopt_session(&self, session: SessionId, place: SessionPlace) {
        self.state().sessions.insert(session, place);
    }

    /// Records that a session has ended and can no longer write.
    pub fn end_session(&self, session: SessionId) {
        self.state().sessions.remove(&session);
    }

    /// Whether a session is registered as alive.
    #[must_use]
    pub fn has_session(&self, session: SessionId) -> bool {
        self.state().sessions.contains_key(&session)
    }

    /// Holds a repository still now, or says why not. It never waits.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] when a writer is at work or a session is alive where the hold would
    /// reach.
    pub fn try_hold(self: &Arc<Self>, reach: Reach) -> std::result::Result<Hold, Refusal> {
        let now = (self.moment)();
        let mut state = self.state();
        state.expire(now);
        if let Some(refusal) = state.in_the_way_of(&reach) {
            return Err(refusal);
        }
        let id = state.take_id();
        let bound = now + HOLD_BOUND;
        state.holds.insert(id, Granted { reach, bound });
        Ok(Hold {
            holds: Arc::clone(self),
            id,
            bound,
        })
    }
}

/// A writer that is at work, until it is dropped.
#[derive(Debug)]
pub struct Writer {
    holds: Arc<WorkspaceHolds>,
    id: u64,
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.holds.state().writers.remove(&self.id);
    }
}

/// A session's registration, which ends with the guard unless it is kept.
#[derive(Debug)]
pub struct SessionRegistration {
    holds: Arc<WorkspaceHolds>,
    session: SessionId,
    armed: bool,
}

impl SessionRegistration {
    /// Keeps the registration after the guard is gone: a process may be running, and the session
    /// ends it when it closes.
    pub fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        if self.armed {
            self.holds.end_session(self.session);
        }
    }
}

/// A repository held still, until it is released or its bound passes.
#[derive(Debug)]
pub struct Hold {
    holds: Arc<WorkspaceHolds>,
    id: u64,
    bound: Instant,
}

impl Hold {
    /// This hold's own identity, distinct from every other hold of this registry.
    #[must_use]
    pub fn grant_id(&self) -> u128 {
        u128::from(self.id)
    }

    /// The instant this hold ends whatever its holder does.
    #[must_use]
    pub const fn bound(&self) -> Instant {
        self.bound
    }

    /// Whether this hold has kept every writer off without interruption since it was granted.
    #[must_use]
    pub fn holding(&self) -> bool {
        let now = (self.holds.moment)();
        let mut state = self.holds.state();
        state.expire(now);
        state.holds.contains_key(&self.id)
    }

    /// Extends what this hold covers by `more`, and the directories whose removal it turns away by
    /// `more_ancestors`, if no writer is at work and no session is alive where the whole of it now
    /// reaches. A hold is granted over what its holder knows first, and
    /// the rest of what it must cover is read from the host's records while the hold already keeps
    /// the writers that make those records off; this is where the two meet.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] when something is in the way of the larger reach, and
    /// [`Refusal::Lapsed`] when the hold has ended. The hold stays as it was, and its holder drops
    /// it.
    pub fn widen(
        &self,
        more: Identities,
        more_ancestors: Identities,
    ) -> std::result::Result<(), Refusal> {
        let now = (self.holds.moment)();
        let mut state = self.holds.state();
        state.expire(now);
        let Some(granted) = state.holds.get(&self.id) else {
            return Err(Refusal::Lapsed);
        };
        let mut reach = granted.reach.clone();
        reach.covers.extend(more);
        reach.ancestors.extend(more_ancestors);
        if let Some(refusal) = state.in_the_way_of(&reach) {
            return Err(refusal);
        }
        if let Some(granted) = state.holds.get_mut(&self.id) {
            granted.reach = reach;
        }
        Ok(())
    }

    /// Gives the repository back. Releasing a hold that ended does nothing, and never touches a
    /// later hold.
    pub fn release(&self) {
        self.holds.state().holds.remove(&self.id);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

/// The identities of a directory and of every parent above it, nearest first.
///
/// The nearest existing directory at or above `path` after links are resolved: a name that does
/// not exist yet, or a file, stands for the directory it would be in. `None` when nothing of it
/// can be opened.
fn identity_chain(
    environment_id: kr_protocol::ids::EnvironmentId,
    path: &Path,
) -> Option<Vec<ObjectIdentity>> {
    let mut candidate: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let real = loop {
        match std::fs::canonicalize(&candidate) {
            Ok(real) => break real,
            Err(_) => {
                if !candidate.pop() {
                    return None;
                }
            }
        }
    };
    let real = if real.is_dir() {
        real
    } else {
        real.parent()?.to_path_buf()
    };
    let mut here = AuthorisedDirectory::open_root(environment_id, &real).ok()?;
    let mut chain = vec![here.identity()];
    for _ in 0..MAX_CLIMB {
        // A directory is opened from its own handle where the platform can do that, so a rename
        // above it while this climbs changes nothing; where it cannot, each parent is opened by the
        // name the canonical path gives it.
        let above = match here.parent() {
            Ok(above) => above,
            Err(_) => {
                let Some(parent) = real.ancestors().nth(chain.len()) else {
                    break;
                };
                let Ok(above) = AuthorisedDirectory::open_root(environment_id, parent) else {
                    break;
                };
                above
            }
        };
        if above.identity() == here.identity() {
            break;
        }
        chain.push(above.identity());
        here = above;
    }
    Some(chain)
}

/// What a writer of a directory writes, given the chain of identities the directory opened to: the
/// directory and everything above it, or anywhere when it could not be opened.
fn footprint_of_chain(chain: Option<Vec<ObjectIdentity>>) -> Footprint {
    chain.map_or_else(Footprint::everywhere, |chain| Footprint::inside(&chain))
}

/// One tree this host records, and the repository it belongs to when that is known.
struct KnownTree {
    tree: Option<ObjectIdentity>,
    repository: Option<ObjectIdentity>,
    /// The directories above the tree, which removing one of them removes the tree with.
    parents: Vec<ObjectIdentity>,
}

/// The identities of the directories above the working tree a record names at `path`, nearest
/// first, or none when it cannot be opened.
fn parents_of(environment_id: kr_protocol::ids::EnvironmentId, path: &str) -> Vec<ObjectIdentity> {
    identity_chain(environment_id, Path::new(path))
        .map_or_else(Vec::new, |chain| chain.into_iter().skip(1).collect())
}

impl ProjectService {
    /// The registry of the writers, sessions and holds of this service.
    #[must_use]
    pub const fn holds(&self) -> &Arc<WorkspaceHolds> {
        &self.holds
    }

    /// The identities of a directory and of every parent above it, nearest first, or nothing when
    /// the directory cannot be opened.
    #[must_use]
    pub fn directory_chain(&self, path: &Path) -> Option<Vec<ObjectIdentity>> {
        identity_chain(self.environment_id, path)
    }

    /// Where a session that is asked to start in `directory` starts. No directory is the
    /// worker's own default, the root; one that is not absolute, or cannot be opened, is unknown.
    #[must_use]
    pub fn session_place(&self, directory: Option<&str>) -> SessionPlace {
        let path = match directory {
            None => Path::new("/"),
            Some(named) if Path::new(named).is_absolute() => Path::new(named),
            Some(_) => return SessionPlace::Unknown,
        };
        identity_chain(self.environment_id, path).map_or(SessionPlace::Unknown, |chain| {
            SessionPlace::Chain(chain.into_iter().collect())
        })
    }

    /// Registers a writer of the directory a path names, or of the one it would be in.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Held`] when a capture is holding the repository the directory is
    /// in.
    pub fn writer_in_directory(&self, what: &'static str, path: &Path) -> Result<Writer> {
        self.holds.begin_write(what, self.footprint_inside(path))
    }

    /// What a writer of the directory a path names, or of the one it would be in, writes: the
    /// directory and every parent above it. A directory that cannot be opened is a place nobody
    /// can name, and what is written there may be anywhere.
    #[must_use]
    pub fn footprint_inside(&self, path: &Path) -> Footprint {
        footprint_of_chain(self.directory_chain(path))
    }

    /// Registers a writer of the repository `repository` is open on, and of the directory a path
    /// names when there is one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Held`] when a capture is holding the repository.
    pub fn writer_of_repository(
        &self,
        what: &'static str,
        repository: &OpenedRepository,
        also_in: Option<&Path>,
    ) -> Result<Writer> {
        let mut footprint = Footprint::of_repository(repository);
        if let Some(path) = also_in {
            footprint = footprint.and(self.footprint_inside(path));
        }
        self.holds.begin_write(what, footprint)
    }

    /// Registers a writer of the Git directory of a repository it does not have open, and of the
    /// directory a path names.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Held`] when a capture is holding the repository.
    pub fn writer_of_git_directory(
        &self,
        what: &'static str,
        git_dir: ObjectIdentity,
        also_in: Option<&Path>,
    ) -> Result<Writer> {
        let mut footprint = Footprint::of_git_directory(git_dir);
        if let Some(path) = also_in {
            footprint = footprint.and(self.footprint_inside(path));
        }
        self.holds.begin_write(what, footprint)
    }

    /// Every tree this host records, with the repository each belongs to.
    fn known_trees(&self) -> Result<Vec<KnownTree>> {
        let store = self.locked()?;
        let projects = store.projects(self.environment_id)?;
        let workspaces = store.workspaces(self.environment_id, None)?;
        drop(store);
        let project_git_dir = |id| {
            projects
                .iter()
                .find(|project| project.project_repository_id == id)
                .map(|project| project.identity.git_dir.object)
        };
        let mut known: Vec<KnownTree> = projects
            .iter()
            .map(|project| KnownTree {
                tree: Some(project.identity.work_tree.object),
                repository: Some(project.identity.git_dir.object),
                parents: parents_of(self.environment_id, &project.display_path),
            })
            .collect();
        for row in workspaces
            .iter()
            .filter(|row| row.state != WorkspaceState::Removed)
        {
            known.push(KnownTree {
                tree: row.identity.map(|identity| identity.object),
                repository: match row.isolation {
                    Some(IsolationMechanism::IndependentClone) => {
                        row.git_dir.map(|identity| identity.object)
                    }
                    _ => project_git_dir(row.project_repository_id),
                },
                parents: parents_of(self.environment_id, &row.display_path),
            });
        }
        Ok(known)
    }

    /// The identities of a workspace's tree and repository as the host records them: what a
    /// removal asks for when it cannot open the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownWorkspace`] for a workspace this environment does not have.
    pub fn recorded_footprint(&self, workspace_id: WorkspaceId) -> Result<Footprint> {
        let store = self.locked()?;
        let row = store
            .workspace(workspace_id)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string().into(),
            })?;
        let project = store.project(row.project_repository_id)?;
        drop(store);
        let mut footprint = Footprint::default();
        if let Some(tree) = row.identity {
            footprint = if row.kind == WorkspaceKind::Isolated {
                footprint.removing(tree.object)
            } else {
                footprint.and(Footprint::inside(&[tree.object]))
            };
        }
        let git_dir = match row.isolation {
            Some(IsolationMechanism::IndependentClone) => row.git_dir.map(|id| id.object),
            _ => project.map(|project| project.identity.git_dir.object),
        };
        if let Some(git_dir) = git_dir {
            footprint.touch.insert(git_dir);
        }
        Ok(footprint)
    }

    /// Holds the repository of a host-made workspace still for a capture that reads it through
    /// `work_tree` and `git_dir`, or says why it cannot.
    ///
    /// Granted only for an isolated, ready workspace whose recorded tree and Git directory are the
    /// ones the capture opened, at the place the host recorded, and only when no writer of this
    /// host is at work and no live session started in a tree this host records for the
    /// repository.
    ///
    /// The hold is granted over the tree and the Git directory first, and the other trees this host
    /// records for the repository are read afterwards and added to it. The writers that publish a
    /// tree of the repository write its Git directory, so from the first grant none of them can
    /// finish unseen between the reading of the records and the end of this call; what the
    /// records say once the hold stands is what it covers. A tree adopted afterwards is not
    /// covered.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownWorkspace`] for a workspace this environment does not have,
    /// and [`ProjectError::StoreUnavailable`] when the records cannot be read. A hold that is
    /// refused is not an error: it is the inner [`Refusal`].
    pub fn hold_workspace(
        &self,
        workspace_id: WorkspaceId,
        work_tree: ObjectIdentity,
        git_dir: ObjectIdentity,
    ) -> Result<std::result::Result<Hold, Refusal>> {
        let chain = match self.workspace_is_holdable(workspace_id, work_tree, git_dir)? {
            Ok(chain) => chain,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let first = Reach {
            covers: Identities::from([work_tree, git_dir]),
            ancestors: chain.into_iter().skip(1).collect(),
        };
        let hold = match self.holds.try_hold(first) {
            Ok(hold) => hold,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // The records are read again now that the hold stands: a removal that finished since the
        // first reading is seen here, and one that has not finished is a writer at work and was
        // refused above.
        if let Err(refusal) = self.workspace_is_holdable(workspace_id, work_tree, git_dir)? {
            return Ok(Err(refusal));
        }
        // The directories above every tree of the repository are protected from removal too, so a
        // cleanup that removes a directory holding the project's checkout, and with it the Git
        // directory the held worktree depends on, is turned away.
        let mut more = Identities::new();
        let mut more_ancestors = Identities::new();
        for known in self.known_trees()? {
            if known.repository == Some(git_dir) {
                more.extend(known.tree);
                more_ancestors.extend(known.parents);
            }
        }
        Ok(hold.widen(more, more_ancestors).map(|()| hold))
    }

    /// Whether the records and the disk agree that `workspace_id` is a ready, host-made workspace
    /// at `work_tree` in the repository `git_dir`, and the chain of identities of its tree and of
    /// every parent above it when they do.
    fn workspace_is_holdable(
        &self,
        workspace_id: WorkspaceId,
        work_tree: ObjectIdentity,
        git_dir: ObjectIdentity,
    ) -> Result<std::result::Result<Vec<ObjectIdentity>, Refusal>> {
        let (row, project) = {
            let store = self.locked()?;
            let row =
                store
                    .workspace(workspace_id)?
                    .ok_or_else(|| ProjectError::UnknownWorkspace {
                        workspace: workspace_id.to_string().into(),
                    })?;
            let project = store.project(row.project_repository_id)?;
            (row, project)
        };
        if row.kind == WorkspaceKind::SharedExisting {
            return Ok(Err(Refusal::SharedCheckout));
        }
        if row.state != WorkspaceState::Ready {
            return Ok(Err(Refusal::NotReady));
        }
        let recorded_git_dir = match row.isolation {
            Some(IsolationMechanism::IndependentClone) => row.git_dir.map(|id| id.object),
            _ => project.map(|project| project.identity.git_dir.object),
        };
        if row.identity.map(|id| id.object) != Some(work_tree) || recorded_git_dir != Some(git_dir)
        {
            return Ok(Err(Refusal::TreeMoved));
        }
        let Some(chain) = identity_chain(self.environment_id, Path::new(&row.display_path)) else {
            return Ok(Err(Refusal::TreeMoved));
        };
        if chain.first() != Some(&work_tree) {
            return Ok(Err(Refusal::TreeMoved));
        }
        Ok(Ok(chain))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use kr_protocol::scalars::Uuid;

    use super::*;

    fn identity(number: u64) -> ObjectIdentity {
        ObjectIdentity {
            device: 1,
            file_id: number,
        }
    }

    fn identities(numbers: &[u64]) -> Identities {
        numbers.iter().copied().map(identity).collect()
    }

    fn session(number: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([number; 16]))
    }

    /// A hold over the tree `1`, its repository `2` and a second tree `3` of the same repository
    /// that is recorded for it, whose parents are `10` and `11`.
    fn reach() -> Reach {
        Reach {
            covers: identities(&[1, 2, 3]),
            ancestors: identities(&[10, 11]),
        }
    }

    fn registry() -> Arc<WorkspaceHolds> {
        Arc::new(WorkspaceHolds::new())
    }

    /// KR-REQ-14.32: a writer of what a hold reaches is refused while the hold stands, whichever
    /// of the held tree, the repository's Git directory and another tree of the repository it
    /// writes, and proceeds when the hold is released; a writer elsewhere is never refused.
    #[test]
    fn a_writer_is_refused_where_a_hold_reaches_and_proceeds_when_it_is_released() {
        let holds = registry();
        let hold = holds.try_hold(reach()).expect("nothing is at work");
        for touched in [1, 2, 3] {
            let refused = holds
                .begin_write("a test writer", Footprint::inside(&[identity(touched)]))
                .expect_err("a hold stands where this writer would write");
            assert_eq!(
                refused.code(),
                kr_protocol::error::ErrorCode::ResourceUnavailable
            );
        }
        assert!(
            holds
                .begin_write(
                    "a test writer",
                    Footprint::inside(&[identity(4), identity(5)])
                )
                .is_ok(),
            "a writer that reaches none of it is not in the way"
        );
        hold.release();
        assert!(
            holds
                .begin_write("a test writer", Footprint::inside(&[identity(1)]))
                .is_ok(),
            "and the released hold refuses nothing"
        );
    }

    /// KR-REQ-14.32: a writer that removes a tree takes the trees recorded inside it away, so a
    /// hold on one of them refuses it, while a writer that merely writes the outer tree does not
    /// reach the inner one.
    #[test]
    fn a_removal_meets_a_hold_on_a_tree_inside_the_tree_it_removes() {
        let holds = registry();
        let _hold = holds.try_hold(reach()).expect("nothing is at work");
        assert!(
            holds
                .begin_write("a removal", Footprint::default().removing(identity(10)))
                .is_err(),
            "the tree a removal takes away holds the held one"
        );
        assert!(
            holds
                .begin_write("a write", Footprint::inside(&[identity(10)]))
                .is_ok(),
            "writing in the outer tree is not writing in the held one"
        );
    }

    /// KR-REQ-14.32: a hold is refused by a writer at work and by a live session that started
    /// where it reaches, and by a session nobody can place; a session elsewhere does not refuse
    /// it. Holds do not exclude one another.
    #[test]
    fn a_hold_is_refused_by_a_writer_or_a_session_where_it_reaches() {
        let holds = registry();
        let writer = holds
            .begin_write("a test writer", Footprint::of_git_directory(identity(2)))
            .expect("no hold stands");
        assert_eq!(
            holds.try_hold(reach()).expect_err("a writer is at work"),
            Refusal::WriterAtWork("a test writer")
        );
        drop(writer);

        let inside = holds
            .begin_session(session(1), SessionPlace::Chain(identities(&[3, 20])))
            .expect("no hold stands");
        let unknown = holds
            .begin_session(session(2), SessionPlace::Unknown)
            .expect("no hold stands");
        let elsewhere = holds
            .begin_session(session(3), SessionPlace::Chain(identities(&[30, 31])))
            .expect("no hold stands");
        assert_eq!(
            holds.try_hold(reach()).expect_err("two sessions"),
            Refusal::SessionsBound(2)
        );
        drop(inside);
        holds.end_session(session(2));
        let first = holds
            .try_hold(reach())
            .expect("only a session elsewhere is alive");
        let second = holds
            .try_hold(reach())
            .expect("a hold keeps writers off and excludes no other hold");
        drop((first, second, elsewhere, unknown));
    }

    /// KR-REQ-14.32: a session is refused where a hold stands, and registers nowhere; one that
    /// is registered ends with its guard unless it is kept, so an exit before a process can run
    /// leaves no session behind.
    #[test]
    fn a_session_registration_ends_with_its_guard_unless_it_is_kept() {
        let holds = registry();
        let hold = holds.try_hold(reach()).expect("nothing is at work");
        assert!(
            holds
                .begin_session(session(1), SessionPlace::Chain(identities(&[1])))
                .is_err()
        );
        assert!(
            !holds.has_session(session(1)),
            "a refused session registers nothing"
        );
        drop(hold);

        let dropped = holds
            .begin_session(session(1), SessionPlace::Chain(identities(&[1])))
            .expect("no hold stands");
        assert!(holds.has_session(session(1)));
        drop(dropped);
        assert!(
            !holds.has_session(session(1)),
            "an exit before a process runs leaves nothing registered"
        );

        let kept = holds
            .begin_session(session(1), SessionPlace::Chain(identities(&[1])))
            .expect("no hold stands");
        kept.keep();
        assert!(holds.has_session(session(1)), "a kept registration stays");
        holds.end_session(session(1));
        assert!(!holds.has_session(session(1)));
    }

    /// KR-REQ-14.32: a hold ends at its bound whatever its holder does, the end is permanent, and
    /// releasing a hold that ended never releases a later one.
    #[test]
    fn a_hold_ends_at_its_bound_and_never_holds_again() {
        let base = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let moved = Arc::clone(&offset);
        let holds = Arc::new(WorkspaceHolds::on(Arc::new(move || {
            base + Duration::from_secs(moved.load(Ordering::SeqCst))
        })));
        let first = holds.try_hold(reach()).expect("nothing is at work");
        assert!(first.holding());
        offset.store(HOLD_BOUND.as_secs() - 1, Ordering::SeqCst);
        assert!(first.holding(), "it holds until its bound");
        assert!(
            holds
                .begin_write("a test writer", Footprint::inside(&[identity(1)]))
                .is_err()
        );

        offset.store(HOLD_BOUND.as_secs(), Ordering::SeqCst);
        assert!(!first.holding(), "and not at it");
        let writer = holds
            .begin_write("a test writer", Footprint::inside(&[identity(1)]))
            .expect("a writer is no longer turned away");
        assert_eq!(
            holds
                .try_hold(reach())
                .expect_err("the writer that went ahead is at work"),
            Refusal::WriterAtWork("a test writer")
        );
        drop(writer);

        let later = holds.try_hold(reach()).expect("nothing is at work now");
        assert_ne!(first.grant_id(), later.grant_id());
        first.release();
        assert!(
            later.holding(),
            "releasing a hold that ended releases nothing of a later one"
        );
        assert!(!first.holding(), "and the one that ended holds no more");
    }

    /// KR-REQ-14.32: a hold is widened over the other trees of its repository only when nothing
    /// writes them and no session is alive in them, and a widening that is turned away leaves the
    /// hold as it was; a hold that ended cannot be widened.
    #[test]
    fn a_hold_is_widened_only_over_trees_nothing_writes() {
        let holds = registry();
        let first = Reach {
            covers: identities(&[1, 2]),
            ancestors: identities(&[10]),
        };

        let hold = holds.try_hold(first.clone()).expect("nothing is at work");
        assert!(
            holds
                .begin_write("a test writer", Footprint::inside(&[identity(3)]))
                .is_ok(),
            "the tree about to be added is not held yet"
        );
        hold.widen(identities(&[4]), identities(&[30]))
            .expect("nothing is in the added tree");
        assert!(
            holds
                .begin_write("a test writer", Footprint::inside(&[identity(4)]))
                .is_err(),
            "and the added tree is held"
        );
        assert!(
            holds
                .begin_write("a removal", Footprint::default().removing(identity(30)))
                .is_err(),
            "and a removal of a directory above the added tree is turned away"
        );
        drop(hold);

        let hold = holds.try_hold(first.clone()).expect("nothing is at work");
        let writer = holds
            .begin_write("a test writer", Footprint::inside(&[identity(3)]))
            .expect("the tree is not held yet");
        assert_eq!(
            hold.widen(identities(&[3]), Identities::new()),
            Err(Refusal::WriterAtWork("a test writer")),
            "a writer came to the tree between the grant and the widening"
        );
        assert!(
            holds
                .begin_write("a test writer", Footprint::inside(&[identity(1)]))
                .is_err(),
            "the hold stands as it was"
        );
        drop(writer);
        let session_there = holds
            .begin_session(session(1), SessionPlace::Chain(identities(&[3, 20])))
            .expect("the tree is not held yet");
        assert_eq!(
            hold.widen(identities(&[3]), Identities::new()),
            Err(Refusal::SessionsBound(1)),
            "a session began in the tree between the grant and the widening"
        );
        drop(session_there);
        hold.widen(identities(&[3]), Identities::new())
            .expect("nothing is there any more");
        drop(hold);

        let base = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let moved = Arc::clone(&offset);
        let holds = Arc::new(WorkspaceHolds::on(Arc::new(move || {
            base + Duration::from_secs(moved.load(Ordering::SeqCst))
        })));
        let hold = holds.try_hold(first).expect("nothing is at work");
        offset.store(HOLD_BOUND.as_secs(), Ordering::SeqCst);
        assert_eq!(
            hold.widen(identities(&[3]), Identities::new()),
            Err(Refusal::Lapsed)
        );
    }

    /// KR-REQ-14.32: a writer whose place nobody can say is in the way of every hold, and every
    /// hold is in the way of it.
    #[test]
    fn a_writer_nobody_can_place_is_in_the_way_of_every_hold() {
        let holds = registry();
        let writer = holds
            .begin_write("a test writer", Footprint::everywhere())
            .expect("no hold stands");
        assert_eq!(
            holds
                .try_hold(reach())
                .expect_err("it may be writing there"),
            Refusal::WriterAtWork("a test writer")
        );
        drop(writer);
        let _hold = holds.try_hold(reach()).expect("nothing is at work");
        assert!(
            holds
                .begin_write("a test writer", Footprint::everywhere())
                .is_err()
        );
    }

    /// KR-REQ-14.32: the chain of a directory holds its own identity and that of every directory
    /// above it, on every platform, and a name that does not exist yet stands for the directory it
    /// would be in.
    #[test]
    fn a_directorys_chain_holds_its_own_identity_and_every_parent_above_it() {
        let temp = tempfile::TempDir::new().expect("a directory");
        let real = std::fs::canonicalize(temp.path()).expect("it resolves");
        let inner = real.join("a").join("b");
        std::fs::create_dir_all(&inner).expect("two directories");
        let environment = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16]));
        let identity_of = |path: &Path| {
            AuthorisedDirectory::open_root(environment, path)
                .expect("it opens")
                .identity()
        };

        let chain = identity_chain(environment, &inner).expect("the directory opens");
        assert_eq!(chain[0], identity_of(&inner));
        assert!(chain.contains(&identity_of(&real.join("a"))));
        assert!(chain.contains(&identity_of(&real)), "the directory above");
        assert_eq!(
            identity_chain(environment, &inner.join("missing")).expect("its parent opens")[0],
            chain[0],
            "a name that is not there yet stands for the directory it would be in"
        );
    }

    /// KR-REQ-14.32: a writer of a directory that could not be opened writes anywhere, and one of a
    /// directory that opened writes it and the directories above it.
    #[test]
    fn a_directory_that_could_not_be_opened_is_written_anywhere() {
        assert!(footprint_of_chain(None).anywhere);
        let placed = footprint_of_chain(Some(vec![identity(1), identity(2)]));
        assert!(!placed.anywhere);
        assert_eq!(placed.touch, identities(&[1, 2]));
    }
}
