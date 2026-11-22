//! The life of one invocation, from the client's request to the reply that says it ended.
//!
//! The phases follow one order, and each names what it cleans up. A failure before a child may
//! exist takes the first cleanup that is listed for its phase; **a failure after the journal's
//! first row takes the one ending function** (`ending`), the only place that ends an invocation.
//!
//! 1. The client is identified from the pipe and the account is enrolled.
//! 2. Cheap admission: maintenance, the proof, the limits.
//! 3. The tree is resolved and its slot is taken (`Trees`, the interface of the tree's hold, its
//!    slot, its grant and its release; the guest cases run on a fixture of it, the tree's own
//!    modules replace the fixture).
//! 4. The group and the token are made, the token is read back, the logon session is read, and
//!    the journal's first row is durable.
//! 5. The job and the private root are made.
//! 6. The tree's reader child, when the tree has one, runs in the private root as a child of the
//!    job: it is made suspended, the journal makes its permit without a row, and it has ended before
//!    the grant. Its end is proved with every other child's, by the session.
//! 7. The tree is granted.
//! 8. The data pipes are made, the reply `accepted` is sent, and the client connects both.
//! 9. The primary child is made suspended inside the job; the checks before its resume run; its
//!    row is durable; only the permit that row returns lets it run.
//! 10. The wait: the child, the client's process, the control pipe, a cancel, the deadline and the
//!     service's stop.
//! 11. The ending function.
//!
//! The operate path serves nothing in production: no request of the broker's pipes reaches
//! [`run_invocation`], and the tree interface has no implementation outside the guest cases.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::channel::CONNECT_BOUND;
use crate::env::EnvBlock;
use crate::filekey::FileKey;
use crate::frame::invocation::{self, EndedBy, InvocationReply, InvocationRequest, OperateRequest};
use crate::journal::replay::Invocation;
use crate::journal::rows::Row;
use crate::lifecycle::{self as facts, Left};
use crate::limits::{INVOCATION_DEADLINE, InvocationCounts};
use crate::manifest::Manifest;
use crate::messages::STILL_STARTING;
use crate::refusal::Refusal;

use super::boot;
use super::channel::{DataPipes, Outcome, make_data_pipes};
use super::client::{ClientIdentity, client_from_pipe};
use super::ffi::{self, Handle, Sid};
use super::install::Paths;
use super::job::{Job, Limits};
use super::journal::{Journal, JournalError};
use super::launch::{
    Child, ChildSpec, InvocationId, Std, SuspendedChild, TokenSpec, VerifiedPath, launch,
};
use super::pipe::{Connection, Stop};
use super::proof::account_of;
use super::root::{self, PrivateRoot, RootError, RootRows};
use super::sd::{Principals, SdKind, descriptor};
use super::token;
use super::walk::DirHandle;

mod ending;
#[cfg(feature = "testing")]
pub mod fixture;
mod recovery;

pub use recovery::{Recovered, Recovery, recover};

/// How long the wait for the end of the job and of its processes may take.
pub const END_BOUND: Duration = Duration::from_secs(30);

/// How long a reader child has to end.
pub const READER_BOUND: Duration = Duration::from_secs(30);

/// How long the wait for the logon session to leave the system's list may take.
pub const SESSION_BOUND: Duration = Duration::from_secs(30);

/// How long the job's count of live processes is given to fall to nothing after a reader ended.
const DESCENDANTS_BOUND: Duration = Duration::from_secs(2);

/// How often the wait of step 10 looks at the control pipe, which has no handle to wait on.
const CONTROL_SLICE: Duration = Duration::from_millis(50);

/// The name of the local account an operation of a class runs as.
pub type Accounts = Box<dyn Fn(crate::frame::Class) -> Result<String, String> + Send + Sync>;

/// The accounts the installation recorded in its manifest.
#[must_use]
pub fn recorded_accounts(manifest: Manifest) -> Accounts {
    Box::new(move |class| account_of(&manifest, class).map(|(name, _)| name))
}

/// The bounds of an invocation's waits: the values of the product, which a case may shorten.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// The deadline of the whole invocation.
    pub deadline: Duration,
    /// How long the client has to connect both data pipes.
    pub connect: Duration,
    /// How long a reader child has to end.
    pub reader: Duration,
    /// How long the job and its processes have to end.
    pub end: Duration,
    /// How long the logon session has to leave the system's list.
    pub session: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            deadline: INVOCATION_DEADLINE,
            connect: CONNECT_BOUND,
            reader: READER_BOUND,
            end: END_BOUND,
            session: SESSION_BOUND,
        }
    }
}

/// What every invocation of the broker shares.
pub struct Environment {
    /// The account of each class.
    pub accounts: Accounts,
    /// The data directory's places: the journal's folder and the private roots' folder.
    pub paths: Paths,
    /// The service's stop.
    pub stop: Arc<Stop>,
    /// The limits' counts.
    pub counts: Arc<InvocationCounts>,
    /// The projects.
    pub trees: Arc<dyn Trees>,
    /// The people the broker serves.
    pub persons: Vec<Sid>,
    /// The identifier of this start of Windows, which every `Begin` row records.
    pub boot: String,
    /// Whether the broker is in maintenance.
    pub maintenance: AtomicBool,
    /// Whether the proof of the boundary has passed and is current.
    pub proof_current: AtomicBool,
    /// The waits.
    pub bounds: Bounds,
}

impl Environment {
    /// The environment of a broker whose proof has passed.
    #[must_use]
    pub fn new(
        accounts: Accounts,
        paths: Paths,
        stop: Arc<Stop>,
        trees: Arc<dyn Trees>,
        persons: Vec<Sid>,
        boot: &boot::BootMarker,
    ) -> Environment {
        Environment {
            accounts,
            paths,
            stop,
            counts: InvocationCounts::new(),
            trees,
            persons,
            boot: boot.id.clone(),
            maintenance: AtomicBool::new(false),
            proof_current: AtomicBool::new(true),
            bounds: Bounds::default(),
        }
    }
}

/// Why a project is blocked after an invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// An object of the tree, the repository or the journal is left unfinished.
    Leftover(String),
    /// The end of an invocation is not proved.
    Uncertain,
}

/// A project's slot, taken when its tree is resolved and given back last. A slot that is dropped
/// stays blocked: only [`Slot::free`] opens it.
pub trait Slot: Send {
    /// Opens the slot: the invocation ended with nothing left, or never began.
    fn free(self: Box<Self>);
    /// Keeps the slot closed, with the reason that the next request is refused with, and the tree's
    /// hold when the end is not proved: its handles stay held while the slot is blocked.
    fn keep(self: Box<Self>, blocked: Blocked, hold: Option<Box<dyn TreeHold>>);
}

/// What an end check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndCheck {
    /// The repository's own files are as the hold recorded them.
    Same,
    /// They are not: the snapshot row (a `RepositorySnapshot` of kind `Changed`), the object and why.
    Changed(Box<Row>, Left),
}

/// What the release did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Release {
    /// The objects the release covered.
    pub objects: u64,
    /// The objects of the person's files that it could not finish.
    pub left: Vec<Left>,
}

/// A program to start as a child of the invocation.
#[derive(Debug)]
pub struct ChildPlan {
    /// The program.
    pub program: VerifiedPath,
    /// Its command line.
    pub command_line: String,
    /// Where it runs.
    pub cwd: PathBuf,
    /// Its environment.
    pub env: EnvBlock,
}

/// The tree of one invocation: its hold, its grant, its release and its checks. The interface is
/// the tree's; each method is a step of the phases.
pub trait TreeHold: Send {
    /// The path the journal records for the tree.
    fn tree_path(&self) -> String;
    /// The identities from the volume's root to the tree, which the slot and the journal record.
    fn chain(&self) -> Vec<FileKey>;
    /// The snapshot of the repository's own files, taken at the hold, if the tree makes one.
    fn initial_snapshot(&self) -> Option<Row>;
    /// Phase 7: grants the group, writing each object's `Grant` row before its change and ending
    /// with `GrantComplete`.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the tree cannot be granted.
    fn grant(
        &mut self,
        group: &Sid,
        rows: &mut dyn FnMut(Row) -> Result<(), String>,
    ) -> Result<(), Refusal>;
    /// Phase 6: the program of the tree's reader child, when the tree has one. It runs in the
    /// private root before the grant and ends with the code 0 when the tree is accepted.
    ///
    /// # Errors
    ///
    /// Returns why the child cannot be planned.
    fn reader(&self, root: &PrivateRoot) -> Result<Option<ChildPlan>, String>;
    /// The program of the primary child.
    ///
    /// # Errors
    ///
    /// Returns why the child cannot be planned.
    fn child(&self, root: &PrivateRoot) -> Result<ChildPlan, String>;
    /// The checks before the primary child is resumed: the chain's identities, the names that must
    /// be absent.
    ///
    /// # Errors
    ///
    /// Returns the name that changed.
    fn pre_resume_check(&self) -> Result<(), String>;
    /// The end check: the repository's own files against the hold, writing no row of its own.
    ///
    /// # Errors
    ///
    /// Returns why the check could not be made.
    fn end_check(&mut self) -> Result<EndCheck, String>;
    /// The release: rules O and G over the grant's rows, each intent journalled before its write.
    fn release(&mut self, rows: &mut dyn FnMut(Row) -> Result<(), String>) -> Release;
    /// Lets go of the tree's handles: the invocation ended and nothing is left.
    fn close(self: Box<Self>);
}

/// What resolving a tree gives: the hold and the slot that was taken.
pub type Resolved = (Box<dyn TreeHold>, Box<dyn Slot>);

/// The projects: resolves a request's directory to a tree and a slot, and reopens a recorded one.
pub trait Trees: Send + Sync {
    /// Resolves the directory the request names and takes its slot.
    ///
    /// # Errors
    ///
    /// Returns the refusal: busy, a leftover, an uncertain end, or a directory the broker does not
    /// run in.
    fn resolve(
        &self,
        request: &OperateRequest,
        client: &ClientIdentity,
    ) -> Result<Resolved, Refusal>;

    /// Recovery: reserves the slot of an invocation that did not end, by its recorded chain, so
    /// that requests that overlap it are refused from the first moment.
    fn reserve(&self, chain: &[FileKey], blocked: Blocked) -> Box<dyn Slot>;

    /// Recovery: reopens the tree of an invocation that did not end, by the chain and the path its
    /// journal records; the rows say what was granted and what is pending.
    ///
    /// # Errors
    ///
    /// Returns why the tree cannot be reopened; the invocation then stays unfinished.
    fn reopen(&self, recorded: &Invocation) -> Result<Box<dyn TreeHold>, String>;
}

/// Hooks of the guest cases: a name for each point of the lifecycle, so that a case can stop the
/// broker, hold a handle or look at the machine there. A build that ships has none.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A hook: called with the name of the point.
    pub type Hook = Arc<dyn Fn(&str) + Send + Sync>;

    static HOOK: Mutex<Option<Hook>> = Mutex::new(None);
    static TOKEN: AtomicUsize = AtomicUsize::new(0);
    static SESSION: AtomicU64 = AtomicU64::new(0);

    /// Sets, or clears, the hook that every point calls.
    pub fn set_hook(hook: Option<Hook>) {
        *crate::win::ffi::locked(&HOOK) = hook;
    }

    /// The handle value of the token of the invocation that is in progress: a case duplicates it to
    /// keep a reference to the session past the invocation's end. Zero when there is none.
    #[must_use]
    pub fn token_handle() -> usize {
        TOKEN.load(Ordering::SeqCst)
    }

    /// The logon session of the invocation that is in progress.
    #[must_use]
    pub fn session() -> u64 {
        SESSION.load(Ordering::SeqCst)
    }

    pub(super) fn note(token: usize, session: u64) {
        TOKEN.store(token, Ordering::SeqCst);
        SESSION.store(session, Ordering::SeqCst);
    }

    pub(super) fn at(name: &str) {
        let hook = crate::win::ffi::locked(&HOOK).clone();
        if let Some(hook) = hook {
            hook(name);
        }
    }
}

/// A point of the lifecycle, for the guest cases.
#[cfg(feature = "testing")]
pub(super) fn at(name: &str) {
    testing::at(name);
}

/// A point of the lifecycle: nothing in a build that ships.
#[cfg(not(feature = "testing"))]
pub(super) fn at(_name: &str) {}

/// A row, written through with a point before it and one after it.
pub(super) fn append(journal: &mut Journal, row: &Row) -> Result<(), JournalError> {
    let kind = format!("{:?}", row.kind());
    at(&format!("before {kind}"));
    journal.append(row)?;
    at(&format!("after {kind}"));
    Ok(())
}

/// The journal as the private root's rows, so that the root's rows go through the same points.
pub(super) struct JournalRows<'a>(pub(super) &'a mut Journal);

impl RootRows for JournalRows<'_> {
    fn intent(&mut self, name: &crate::journal::rows::RootName) -> Result<(), RootError> {
        append(self.0, &Row::RootIntent { name: name.clone() })
            .map_err(|failure| RootError::Journal(failure.to_string()))
    }

    fn made(
        &mut self,
        name: &crate::journal::rows::RootName,
        key: &FileKey,
    ) -> Result<(), RootError> {
        append(
            self.0,
            &Row::RootMade {
                name: name.clone(),
                key: *key,
            },
        )
        .map_err(|failure| RootError::Journal(failure.to_string()))
    }

    fn removed(&mut self) -> Result<(), RootError> {
        append(self.0, &Row::RootRemoved).map_err(|failure| RootError::Journal(failure.to_string()))
    }
}

/// The platform's time as a 64-bit count of 100-nanosecond steps since 1601, which is how the
/// system counts a process's creation.
pub(super) fn filetime_now() -> u64 {
    super::session::now()
}

/// The final reply of an invocation, which the ending function makes.
pub(super) enum Final {
    /// The reply `finished`.
    Finished(InvocationReply),
    /// A refusal that follows the reply `accepted`: the client did not connect.
    Refused(Refusal),
}

/// One invocation's resources, in the order they are made.
pub(super) struct Run<'a> {
    pub(super) env: &'a Environment,
    pub(super) client: &'a ClientIdentity,
    pub(super) id: InvocationId,
    pub(super) _permit: crate::limits::Permit,
    pub(super) tree: Option<Box<dyn TreeHold>>,
    pub(super) slot: Option<Box<dyn Slot>>,
    pub(super) group: Sid,
    pub(super) token: Option<Handle>,
    pub(super) session: u64,
    pub(super) since: u64,
    pub(super) journal: Option<Journal>,
    pub(super) job: Option<Job>,
    pub(super) root: Option<PrivateRoot>,
    pub(super) primary: Option<Child>,
    pub(super) readers: Vec<Child>,
    pub(super) pipes: Option<DataPipes>,
    pub(super) started: bool,
    pub(super) began: bool,
    pub(super) accepted: bool,
    pub(super) deadline: Instant,
}

/// What a phase gives back when it fails: the refusal, and whether the journal's first row was
/// written, which decides between the first cleanup and the ending function.
pub(super) struct Failure {
    pub(super) refusal: Refusal,
    /// Whether the service's stop is what ended the phase: the ending then keeps it as its reason.
    pub(super) stopped: bool,
}

impl From<Refusal> for Failure {
    fn from(refusal: Refusal) -> Self {
        Failure {
            refusal,
            stopped: false,
        }
    }
}

fn not_started(failure: impl std::fmt::Display) -> Failure {
    Failure::from(facts::not_started(&failure.to_string()))
}

/// A phase that the service's stop ended.
fn stopping() -> Failure {
    Failure {
        stopped: true,
        ..not_started("the broker is stopping")
    }
}

impl Run<'_> {
    /// Writes a row; the failure is a refusal that says the operation could not be started.
    pub(super) fn row(&mut self, row: &Row) -> Result<(), Failure> {
        let Some(journal) = self.journal.as_mut() else {
            return Err(not_started("the journal is not open"));
        };
        append(journal, row).map_err(not_started)
    }

    fn account(&self, class: crate::frame::Class) -> Result<String, Failure> {
        (self.env.accounts)(class).map_err(not_started)
    }

    /// Phase 4: the group, the token, the session, the journal's first row.
    fn begin(&mut self, request: &OperateRequest) -> Result<(), Failure> {
        let account = self.account(request.class)?;
        self.group = token::new_invocation_group();
        self.since = filetime_now();
        let made = token::boundary_token(&account, &self.group).map_err(not_started)?;
        token::read_back(&made, &self.group).map_err(not_started)?;
        self.session = super::session::session_of(&made).map_err(not_started)?;
        #[cfg(feature = "testing")]
        testing::note(made.raw() as usize, self.session);
        self.token = Some(made);
        at("token made");
        let journal = Journal::create(&self.env.paths.journal, self.id).map_err(not_started)?;
        self.journal = Some(journal);
        let tree = self.tree.as_ref().ok_or_else(|| not_started("no tree"))?;
        let begin = Row::Begin {
            invocation: hex::encode(self.id.0),
            boot_marker: self.env.boot.clone(),
            session_luid: self.session,
            group_sid: self.group.to_text().map_err(not_started)?,
            client_sid: self.client.user_sid.to_text().map_err(not_started)?,
            client_pid: self.client.pid,
            client_creation_time: self.client.creation_time,
            chain: tree.chain(),
            tree_path: tree.tree_path(),
        };
        let snapshot = tree.initial_snapshot();
        self.row(&begin)?;
        self.began = true;
        if let Some(snapshot) = snapshot {
            self.row(&snapshot)?;
        }
        Ok(())
    }

    /// Phase 5: the job and the private root.
    fn make_root(&mut self) -> Result<(), Failure> {
        self.job = Some(Job::new(Limits::INVOCATION).map_err(not_started)?);
        at("job made");
        let run = DirHandle::open_anchor(&self.env.paths.run)
            .map_err(not_started)?
            .map_err(not_started)?;
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| not_started("the journal is not open"))?;
        let made = root::create_root(
            &run,
            &self.env.paths.run,
            &self.group,
            &mut JournalRows(journal),
        )
        .map_err(not_started)?;
        self.root = Some(made);
        Ok(())
    }

    fn process_descriptor(&self) -> Result<super::sd::OwnedSd, Failure> {
        descriptor(
            SdKind::ProcessThread,
            &Principals {
                group: Some(self.group.clone()),
                ..Principals::default()
            },
        )
        .map_err(not_started)
    }

    /// Phase 6: the tree's reader child. A reader that ends with another code than 0, that does not
    /// end within its bound or that cannot be started refuses the operation, and the ending
    /// function ends what ran.
    fn classify(&mut self) -> Result<(), Failure> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| not_started("no private root"))?;
        let Some(plan) = self
            .tree
            .as_ref()
            .ok_or_else(|| not_started("no tree"))?
            .reader(root)
            .map_err(not_started)?
        else {
            return Ok(());
        };
        let descriptor = self.process_descriptor()?;
        let token = self.token.as_ref().ok_or_else(|| not_started("no token"))?;
        let job = self.job.as_ref().ok_or_else(|| not_started("no job"))?;
        let suspended = launch(ChildSpec {
            invocation: Some(self.id),
            token: TokenSpec::Boundary(token),
            job,
            program: plan.program,
            command_line: plan.command_line,
            cwd: &plan.cwd,
            env: &plan.env,
            stdin: Std::Nul,
            stdout: Std::Nul,
            stderr: Std::Nul,
            process_descriptor: &descriptor,
            thread_descriptor: &descriptor,
            deadline: Some(self.deadline),
        })
        .map_err(not_started)?;
        self.started = true;
        at("reader suspended");
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| not_started("the journal is not open"))?;
        let permit = journal.permit_for_reader(&suspended).map_err(not_started)?;
        let child = suspended.resume(permit).map_err(not_started)?;
        at("reader resumed");
        // The end of the invocation waits for this child with the others, whatever came of it.
        self.readers.push(child);
        let reader = self
            .readers
            .last()
            .ok_or_else(|| not_started("no reader"))?;
        match reader.wait_or_stop(self.env.bounds.reader, &self.env.stop) {
            Ok(Some(0)) => {
                at("reader ended");
                self.no_process_is_left()
            }
            Ok(Some(code)) => Err(not_started(format!(
                "the reader of the project ended with the code {code}"
            ))),
            Ok(None) if self.env.stop.is_set() => Err(stopping()),
            Ok(None) => Err(not_started("the reader of the project did not end in time")),
            Err(unread) => Err(not_started(unread)),
        }
    }

    /// Every process of the reader has ended, not only the reader: the job counts none alive. A
    /// process that a reader left would hold the group's token through the grant.
    fn no_process_is_left(&self) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or_else(|| not_started("no job"))?;
        let until = Instant::now() + DESCENDANTS_BOUND;
        loop {
            let live = job.active_processes().map_err(not_started)?;
            if live == 0 {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(not_started(format!(
                    "the reader of the project ended and left {live} live processes"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Phase 7: the grant.
    fn grant(&mut self) -> Result<(), Failure> {
        let Some(journal) = self.journal.as_mut() else {
            return Err(not_started("the journal is not open"));
        };
        let tree = self.tree.as_mut().ok_or_else(|| not_started("no tree"))?;
        let mut write = |row: Row| append(journal, &row).map_err(|failure| failure.to_string());
        tree.grant(&self.group, &mut write)?;
        at("granted");
        Ok(())
    }

    /// Phase 8: the data pipes, the reply `accepted` and the client's two connections.
    fn open_channel(&mut self, connection: &mut Connection) -> Result<(), Failure> {
        let pipes = make_data_pipes(self.client).map_err(not_started)?;
        let reply = InvocationReply::Accepted {
            invocation: invocation::InvocationId::from_bytes(self.id.0),
            stdout_pipe: pipes.names.stdout.clone(),
            stderr_pipe: pipes.names.stderr.clone(),
        };
        send(connection, &reply)?;
        self.accepted = true;
        at("accepted");
        let outcome = pipes
            .wait_connected(self.env.bounds.connect, &self.env.stop)
            .map_err(not_started)?;
        match outcome {
            Outcome::Connected => {
                self.pipes = Some(pipes);
                at("connected");
                Ok(())
            }
            Outcome::TimedOut => Err(Failure::from(facts::not_connected())),
            Outcome::Stopped => Err(stopping()),
        }
    }

    /// Phase 9: the primary child, suspended inside the job; the checks; its row; the resume.
    fn start_primary(&mut self) -> Result<(), Failure> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| not_started("no private root"))?;
        let plan = self
            .tree
            .as_ref()
            .ok_or_else(|| not_started("no tree"))?
            .child(root)
            .map_err(not_started)?;
        let pipes = self
            .pipes
            .take()
            .ok_or_else(|| not_started("no data pipes"))?;
        let (stdout, stderr) = pipes.into_child_ends().map_err(not_started)?;
        let descriptor = self.process_descriptor()?;
        let token = self.token.as_ref().ok_or_else(|| not_started("no token"))?;
        let job = self.job.as_ref().ok_or_else(|| not_started("no job"))?;
        let suspended = launch(ChildSpec {
            invocation: Some(self.id),
            token: TokenSpec::Boundary(token),
            job,
            program: plan.program,
            command_line: plan.command_line,
            cwd: &plan.cwd,
            env: &plan.env,
            stdin: Std::Nul,
            stdout: Std::Pipe(stdout),
            stderr: Std::Pipe(stderr),
            process_descriptor: &descriptor,
            thread_descriptor: &descriptor,
            deadline: Some(self.deadline),
        })
        .map_err(not_started)?;
        self.started = true;
        self.check_before_resume(&suspended)?;
        at("suspended");
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| not_started("the journal is not open"))?;
        at("before ProcessStarted");
        let permit = journal
            .append_process_started(&suspended)
            .map_err(not_started)?;
        at("after ProcessStarted");
        let child = suspended.resume(permit).map_err(not_started)?;
        self.primary = Some(child);
        at("resumed");
        Ok(())
    }

    /// The checks of step 9 before the resume: the child is in the job and is the job's only live
    /// process; its table holds exactly the inherited handles; the tree is as it was held.
    fn check_before_resume(&self, suspended: &SuspendedChild) -> Result<(), Failure> {
        if !suspended.in_job_checked {
            return Err(not_started("the child is not in the job"));
        }
        let job = self.job.as_ref().ok_or_else(|| not_started("no job"))?;
        let live = job.active_processes().map_err(not_started)?;
        if live != 1 {
            return Err(not_started(format!(
                "the job holds {live} live processes before the child is resumed, not one"
            )));
        }
        let mut held = suspended.handle_values().map_err(not_started)?;
        held.sort_unstable();
        let mut listed = suspended.inherited.to_vec();
        listed.sort_unstable();
        listed.dedup();
        if held != listed {
            return Err(not_started(format!(
                "the child's handles before its resume are {held:?}, not the three that were listed, {listed:?}"
            )));
        }
        self.tree
            .as_ref()
            .ok_or_else(|| not_started("no tree"))?
            .pre_resume_check()
            .map_err(not_started)
    }

    /// Step 10: waits for the primary child, the client's process, the control pipe, a cancel, the
    /// deadline and the service's stop, and says which came first.
    fn wait(&mut self, connection: &mut Connection) -> EndedBy {
        at("waiting");
        let Some(primary) = self.primary.as_ref() else {
            return EndedBy::Stop;
        };
        let handles = [primary.process.raw(), self.client.process.raw()];
        loop {
            if Instant::now() >= self.deadline {
                return EndedBy::Deadline;
            }
            match self.env.stop.wait_for(
                &handles,
                ffi::milliseconds(CONTROL_SLICE, u32::MAX - 1),
                "waiting for the operation to end",
            ) {
                Ok(ffi::Waited::Signalled(0)) => return EndedBy::Stop,
                // A wait that failed is kept by the stop, which is set: the service is ending.
                Err(unwaited) => {
                    drop(unwaited);
                    return EndedBy::Stop;
                }
                Ok(ffi::Waited::Signalled(1)) => return EndedBy::Exit,
                Ok(ffi::Waited::Signalled(_)) => return EndedBy::ClientExit,
                Ok(ffi::Waited::TimedOut) => {}
            }
            match control(connection, self.id) {
                Control::Quiet => {}
                Control::Cancel => return EndedBy::Cancel,
                Control::Gone => return EndedBy::Disconnect,
            }
        }
    }
}

impl Run<'_> {
    /// Phases 4 to 10. A failure is the refusal that says why; whether the journal's first row was
    /// written decides how it is cleaned up.
    fn phases(
        &mut self,
        connection: &mut Connection,
        request: &OperateRequest,
    ) -> Result<EndedBy, Failure> {
        self.begin(request)?;
        self.make_root()?;
        self.classify()?;
        self.grant()?;
        self.open_channel(connection)?;
        self.start_primary()?;
        Ok(self.wait(connection))
    }

    /// A failure before the journal's first row: nothing durable was made and no child ran, so
    /// the first cleanup is all there is: the handles close and the slot opens.
    fn first_cleanup(&mut self, failure: Failure) -> Final {
        self.token = None;
        if let Some(slot) = self.slot.take() {
            slot.free();
        }
        if let Some(tree) = self.tree.take() {
            tree.close();
        }
        Final::Refused(failure.refusal)
    }
}

/// What the control pipe said.
enum Control {
    Quiet,
    Cancel,
    Gone,
}

fn control(connection: &mut Connection, id: InvocationId) -> Control {
    match connection.available() {
        Ok(0) => Control::Quiet,
        Ok(_) => {
            connection.set_deadline(Some(Instant::now() + Duration::from_secs(1)));
            match invocation::read_request(connection) {
                Ok(InvocationRequest::Cancel { invocation })
                    if invocation == invocation::InvocationId::from_bytes(id.0) =>
                {
                    Control::Cancel
                }
                Ok(_) => Control::Quiet,
                Err(unread) => {
                    drop(unread);
                    Control::Gone
                }
            }
        }
        Err(closed) => {
            drop(closed);
            Control::Gone
        }
    }
}

fn send(connection: &mut Connection, reply: &InvocationReply) -> Result<(), Failure> {
    connection.set_deadline(Some(Instant::now() + Duration::from_secs(10)));
    invocation::write_reply(connection, reply).map_err(not_started)
}

/// Sends a refusal and lets the client read it before the connection closes.
fn refuse(connection: &mut Connection, refusal: Refusal) {
    send_and_let_read(connection, &refusal.into_reply());
}

/// Sends the reply that ends a connection and lets the client read it before the connection closes.
fn send_and_let_read(connection: &mut Connection, reply: &InvocationReply) {
    match send(connection, reply) {
        // Whether the client read it in time changes nothing that is left to do: the connection
        // closes next either way.
        Ok(()) => {
            connection.let_the_client_read(Duration::from_secs(5));
        }
        // A reply that could not be sent leaves nothing for the client to read.
        Err(unsent) => drop(unsent),
    }
}

/// Phase 1 and then the rest: identifies the client from the pipe, requires its account to be
/// enrolled, and runs the invocation. The reply is written to the connection.
pub fn serve_operate(connection: &mut Connection, request: &OperateRequest, env: &Environment) {
    let client = match client_from_pipe(connection) {
        Ok(client) => client,
        Err(refusal) => return refuse(connection, refusal),
    };
    if let Err(refusal) = client.require_enrolled(&env.persons) {
        return refuse(connection, refusal);
    }
    run_invocation(connection, client, request, env);
}

/// Phases 2 to 11 for an identified client.
pub fn run_invocation(
    connection: &mut Connection,
    client: ClientIdentity,
    request: &OperateRequest,
    env: &Environment,
) {
    // Phase 2: cheap admission.
    if env.maintenance.load(Ordering::SeqCst) {
        return refuse(connection, facts::maintenance());
    }
    if !env.proof_current.load(Ordering::SeqCst) {
        return refuse(
            connection,
            Refusal::new(
                invocation::RefusedKind::Maintenance,
                facts::RULE_MAINTENANCE,
                STILL_STARTING,
            ),
        );
    }
    let account = match client.user_sid.to_text() {
        Ok(text) => text,
        Err(unread) => return refuse(connection, facts::not_started(&unread.to_string())),
    };
    let permit = match env.counts.admit(&account) {
        Ok(permit) => permit,
        Err(refusal) => return refuse(connection, refusal),
    };
    at("admitted");
    // Phase 3: the tree and its slot.
    let (tree, slot) = match env.trees.resolve(request, &client) {
        Ok(resolved) => resolved,
        Err(refusal) => return refuse(connection, refusal),
    };
    at("tree resolved");
    let mut run = Run {
        env,
        client: &client,
        id: InvocationId(*uuid::Uuid::new_v4().as_bytes()),
        _permit: permit,
        tree: Some(tree),
        slot: Some(slot),
        group: token::new_invocation_group(),
        token: None,
        session: 0,
        since: 0,
        journal: None,
        job: None,
        root: None,
        primary: None,
        readers: Vec::new(),
        pipes: None,
        started: false,
        began: false,
        accepted: false,
        deadline: Instant::now() + env.bounds.deadline,
    };
    let finished = match run.phases(connection, request) {
        Ok(ended_by) => run.end(ended_by, None),
        Err(failure) if run.began => {
            let ended_by = if failure.stopped {
                EndedBy::Stop
            } else {
                EndedBy::NotStarted
            };
            run.end(ended_by, Some(failure))
        }
        Err(failure) => run.first_cleanup(failure),
    };
    match finished {
        Final::Finished(reply) => send_and_let_read(connection, &reply),
        Final::Refused(refusal) => refuse(connection, refusal),
    }
}
