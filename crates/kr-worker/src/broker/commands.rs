//! The command backends: the worker-owned endpoint an integrated invocation is given before it runs.
//!
//! Section 12 has an opt-in command integration establish the worker-owned backend before the native
//! program starts, preserve the command name and argument vector, and never create a gateway for a
//! program after it started. A native-bridge application such as Claude Code has no protocol for a
//! gateway to stand in front of: what its hooks and its channel need is a registration, published
//! before the application exists, that names the process they must descend from. The shell cannot
//! name that process before it forks, so the invocation's own process names itself.
//!
//! # The order
//!
//! 1. **Establish**, when the root shell asks to resolve an integrated invocation: an endpoint in a
//!    fresh owner-only directory, a credential, and a launch record that says where to connect and
//!    which variables the connector's verified manifest declares. Nothing is reserved and no
//!    registration exists yet. The answer names the registration's path, whose file name says which
//!    flags the integration added, and the installation's launcher. The shell exports the
//!    registration's path alone.
//! 2. **Present**: the shell runs the launcher in the child it forked for the invocation, and the
//!    launcher presents itself, with the credential, the executable and the argument vector.
//! 3. **Admit**: the process the kernel names is the root shell's own child, started after the
//!    establish, with the credential, running the file this backend hashed with the vector it
//!    answered. The launch profile is recorded, the instance registered by its reservation, and the
//!    registration published whole, naming that process. The launcher is told it is admitted.
//! 4. **Commit**, when the launcher says it is going: the backend is committed and says so, and only
//!    then does the launcher set the declared variables and exec the program in place, keeping its
//!    process identity, so the registration names the program before the program runs.
//!
//! A launcher that is refused, runs out of time or cannot reach the endpoint runs the invocation as
//! typed, without the flags and without the registration's variable. The declared variables were
//! never exported, so the program runs in the person's own environment exactly, their own value of
//! a declared variable included. The registration's file name says where the added flags stand in
//! the vector, so what was typed is known from the variable alone, whatever has become of the
//! backend.
//!
//! # What is served
//!
//! One accept loop per backend, one task per accepted connection, at most
//! [`MAX_CONCURRENT_ADMISSIONS`] at once, each ended when the backend is retired. A bridge that
//! connects while a launch is being committed waits for the commit; one that connects to a backend no
//! launch holds is refused. A bridge is authenticated before it can ask whether the process executes
//! what was hashed, so only the program's own bridges decide that.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, EnvironmentId, LaunchProfileId, SessionId};
use kr_protocol::root::{CommandBackend, CwdRevision, PromptGeneration};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::{CommandIntegration, EnvironmentVariable};

use crate::broker::Broker;
use crate::broker::attach::{NativeGateway, NativeLaunch, Opening, PresentedLaunch};
use crate::broker::bridge::{BridgeStream, BridgeSurface};
use crate::broker::connectors::{ConnectorSources, InstalledConnector};
use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::image::{ExecutableIdentity, FileIdentity, HashedFiles};
use crate::broker::listener::Registration;
use crate::broker::process::{Credential, ManagedProcess};
use crate::broker::profiles::ForegroundMark;

/// The most admissions one backend runs at once.
///
/// A connection beyond them is closed unread: its hook answers `{}` and its report is lost, or its
/// channel fails its handshake, which is what a worker that does not answer already means.
pub const MAX_CONCURRENT_ADMISSIONS: usize = 16;

/// The prefix of a backend's registration file name, which goes on `.<at>.<count>`: where in the
/// answered vector the integration's flags start, and how many there are.
pub const REGISTRATION_PREFIX: &str = "registration";

/// How long a launch the backend admitted has to say it is going.
///
/// The launcher says so as soon as it reads its admission, so anything slower is a launcher that
/// is not going to run the program with the integration.
///
/// On Windows the launcher creates the program before it says so, and the first start of a program
/// the system has not run costs it up to three and a half seconds, because the system scans the
/// file again as its image is first mapped, so it has four seconds.
pub const GOING_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(if cfg!(windows) { 4 } else { 2 });

/// How long an admission waits for the executable's identity to be read.
///
/// The launcher gives the whole exchange two seconds on Unix and six on Windows; this leaves it
/// room to hear the answer.
///
/// Reading an agent's executable takes up to about four and a half seconds on Windows for a file of
/// 300 MB that the system has not seen: the system scans a fresh executable as it is first opened,
/// at up to ten milliseconds for each megabyte, and the hash follows. The wait there is five, which
/// still leaves the launcher room to hear the answer inside its six.
pub const IDENTITY_WAIT: std::time::Duration =
    std::time::Duration::from_millis(if cfg!(windows) { 5000 } else { 1500 });

/// How long a launcher that was told its launch is committed has to say it has resumed the
/// program, on a platform where it creates the program suspended and starts it only then.
#[cfg(windows)]
pub const RESUME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(4);

/// The file a backend's launch record is published as.
pub const LAUNCH_RECORD_FILE: &str = "launch";

/// How often the committed program is looked at while it runs.
const SUPERVISION_POLL: std::time::Duration = crate::broker::attach::TERMINAL_POLL;

/// Where one backend is.
#[derive(Clone, Debug)]
pub enum BackendState {
    /// Established, and no launch holds it.
    Unbound,
    /// A launch was admitted and has not said it is going.
    Launching,
    /// A launch is running under it; bridges are admitted against its registration.
    Committed(Arc<Registration>),
    /// It has ended.
    Retired,
}

/// A backend's state and the lock that orders its commit, its confirmation and its retirement.
///
/// The commit (the state, the guard, the supervision) and the confirmation (still committed, then
/// the one line the launcher execs on) each run under the lock, and so does retirement. So a
/// retirement is either before the commit, which then fails; between the two, which withholds the
/// confirmation; or after the confirmation. The successful write of the confirmation is the
/// launch's commitment point: a launcher may still be between reading it and its exec when a later
/// retirement lands, and it then runs the program with the flags and without a backend, as a session
/// that closes a moment after its program started leaves it.
struct Lifecycle {
    state: tokio::sync::watch::Sender<BackendState>,
    lock: Mutex<()>,
}

impl Lifecycle {
    fn new(state: BackendState) -> Self {
        Self {
            state: tokio::sync::watch::channel(state).0,
            lock: Mutex::new(()),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Moves a launch in progress to committed and runs `then` under the lock; a backend retired
    /// meanwhile stays retired, and `then` is not run.
    fn commit(&self, registration: Arc<Registration>, then: impl FnOnce()) -> bool {
        let _held = self.held();
        let moved = self.state.send_if_modified(|state| {
            if matches!(state, BackendState::Launching) {
                *state = BackendState::Committed(registration);
                true
            } else {
                false
            }
        });
        if moved {
            then();
        }
        moved
    }

    /// Runs `confirm` under the lock while the backend is still committed, and nothing otherwise.
    fn confirm<T>(&self, confirm: impl FnOnce() -> T) -> Option<T> {
        let _held = self.held();
        // The state is read and let go before `confirm` runs: what keeps retirement out while it
        // does is the lifecycle lock, and nothing else.
        let committed = matches!(*self.state.borrow(), BackendState::Committed(_));
        committed.then(confirm)
    }

    /// Marks the backend retired, under the lock.
    fn retire(&self) {
        let _held = self.held();
        self.state.send_replace(BackendState::Retired);
    }
}

/// The invocation one backend was established for, exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Invocation {
    typed: Vec<String>,
    arguments: Vec<String>,
    added: Vec<String>,
    executable: String,
    cwd: String,
    cwd_revision: CwdRevision,
}

/// One established backend.
struct Backend {
    application_instance_id: ApplicationInstanceId,
    prompt_generation: PromptGeneration,
    invocation: Invocation,
    directory: PathBuf,
    registration: PathBuf,
    /// Set when the backend's line is over while a launch holds it, so a rollback retires it.
    line_over: AtomicBool,
    profile_id: LaunchProfileId,
    gateway: Arc<NativeGateway>,
    credential: Credential,
    root_shell: ProcessStartIdentity,
    established_at: Option<u64>,
    connector: Arc<InstalledConnector>,
    /// The frame of the admissions snapshot the connector came from, which the launch's binding
    /// is decided at.
    frame: Option<kr_protocol::admission::FrameId>,
    lifecycle: Lifecycle,
    identity: tokio::sync::watch::Receiver<Option<std::result::Result<ExecutableIdentity, String>>>,
    /// Why a bridge of this instance was refused for the image its process runs, once one was:
    /// every later bridge is refused too.
    image_refused: Mutex<Option<String>>,
    /// The executables already shown to hold the digest that was hashed, or, on Windows, the one
    /// process shown to have been created from it.
    image_verified: crate::broker::image::VerifiedFiles,
    /// The file the program was read through, opened for readers only and kept until the process
    /// made from it has been shown to be created from it.
    ///
    /// While it is held nothing can rename, delete, write or copy over the file, so the path the
    /// launcher runs is the file that was hashed. It is given up when the verdict is taken.
    #[cfg(windows)]
    held_image: Arc<Mutex<Option<std::fs::File>>>,
    /// The path the invocation was resolved in, held from the drive's root to the directory, which
    /// is what keeps the directory the grant was opened on the directory the program works in.
    ///
    /// It is taken where the directory is opened, and let go of when the backend is retired.
    #[cfg(windows)]
    pinned: Arc<Mutex<Option<crate::windows::pin::Pin>>>,
    /// Why the last launch this backend took did not go, where one did not.
    ///
    /// It belongs to the backend and not to an instance: a launch that failed before its program
    /// was shown has no instance, and what a launcher declined survives the launch's rollback.
    #[cfg(windows)]
    launch_failure: Mutex<Option<String>>,
    /// Set when the backend is retired, so a reading of the executable in progress stops.
    stopped: Arc<AtomicBool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// The operating-system user the session runs as.
    os_user: String,
    /// The directory the shell reported for this invocation, for a connector whose installation
    /// may read files.
    ///
    /// The reading that reads the executable opens it first, off the session's lock, and publishes
    /// the executable's identity only afterwards: an admission waits for that identity, so one that
    /// has it finds the directory opened, or never to be.
    host_directory: Arc<std::sync::OnceLock<kr_transfer::authority::AuthorisedDirectory>>,
    /// The session whose attached views a channel's transitions are delivered to, where one is.
    views: Option<(SessionId, Weak<crate::runtime::SessionRuntime>)>,
    /// What the session's views were last told this backend's instance is.
    ///
    /// Every announcement about the instance is decided while this is held, and made while it is
    /// still held, so the views hear its start, a refusal of its bridges and its end in the order
    /// they were decided, whichever task found each. The session's lock is taken first.
    announced: Mutex<Announced>,
    #[cfg(feature = "testing")]
    confirm_pause: Arc<Mutex<Option<ConfirmPause>>>,
    #[cfg(feature = "testing")]
    commit_pause: Arc<Mutex<Option<ConfirmPause>>>,
}

/// What a backend's instance was last announced as, and what may still be announced about it.
#[derive(Debug, Default)]
struct Announced {
    /// The instance as the views were told, once its program was announced as started.
    summary: Option<kr_protocol::projection::AgentInstanceSummary>,
    /// Why the instance's bridges are refused, where one was, whether or not it was announced yet.
    refusal: Option<String>,
    /// Set once the instance's end is decided, by its program's exit or by its session closing.
    /// Nothing about it is announced afterwards.
    ended: bool,
}

impl Announced {
    /// The program's start, unless its start was announced already or its end came first. A
    /// refusal found before the start goes out with it.
    fn start(
        &mut self,
        mut summary: kr_protocol::projection::AgentInstanceSummary,
    ) -> Option<kr_protocol::projection::AgentInstanceSummary> {
        if self.ended || self.summary.is_some() {
            return None;
        }
        summary.refusal = kr_protocol::scalars::Nullable(self.refusal.clone());
        self.summary = Some(summary.clone());
        Some(summary)
    }

    /// A refusal of the instance's bridges: kept for the start where the start is still to come,
    /// announced once for each new reason where it went, and never after the end.
    fn refuse(&mut self, why: &str) -> Option<kr_protocol::projection::AgentInstanceSummary> {
        let why = bounded_refusal(why);
        if self.ended || self.refusal.as_deref() == Some(why) {
            return None;
        }
        self.refusal = Some(why.to_owned());
        let summary = self.summary.as_mut()?;
        summary.refusal = kr_protocol::scalars::Nullable::some(why.to_owned());
        Some(summary.clone())
    }

    /// The instance's end, once, with the refusal that stood: announced where the start was.
    fn end(
        &mut self,
        at: kr_protocol::scalars::TimestampMs,
    ) -> Option<kr_protocol::projection::AgentInstanceSummary> {
        if self.ended {
            return None;
        }
        self.ended = true;
        let summary = self.summary.as_mut()?;
        summary.ended_at = kr_protocol::scalars::Nullable::some(at);
        summary.refusal = kr_protocol::scalars::Nullable(self.refusal.clone());
        Some(summary.clone())
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Backend")
            .field("application_instance_id", &self.application_instance_id)
            .field("prompt_generation", &self.prompt_generation)
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

/// What the session asks for when an integrated invocation is resolved.
#[derive(Clone, Debug)]
pub struct EstablishRequest<'a> {
    /// The prompt generation the invocation's line was accepted at.
    pub prompt_generation: PromptGeneration,
    /// The vector the shell resolved, command name first.
    pub typed: &'a [String],
    /// The vector the answer gives the launcher to run: the typed one with the flags added.
    pub arguments: &'a [String],
    /// The flags the integration added: all of the connector's, in order, or none where the
    /// person typed them.
    pub added: &'a [String],
    /// The session's integration entry the resolution came from.
    pub integration: &'a CommandIntegration,
    /// The executable the shell resolved the command name to.
    pub executable: &'a str,
    /// The working directory the invocation runs in.
    pub cwd: &'a str,
    /// The working-directory revision the shell reported.
    pub cwd_revision: CwdRevision,
    /// The session's root shell, whose own child the launcher must be.
    pub root_shell: ProcessStartIdentity,
}

/// The session's command backends.
pub struct CommandBackends {
    broker: Arc<Broker>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    os_user: String,
    runtime_dir: PathBuf,
    /// The session's own root, made fresh at the first establish and removed at close.
    root: Mutex<Option<PathBuf>>,
    sources: Arc<ConnectorSources>,
    launcher: Option<PathBuf>,
    handle: tokio::runtime::Handle,
    publishes_credential_file: bool,
    backends: Mutex<Vec<Arc<Backend>>>,
    hashed: Arc<HashedFiles>,
    /// The session whose attached views a channel's transitions are delivered to, where one is.
    ///
    /// Held weakly: the session holds these backends, so a strong hold would keep both alive.
    views: Option<Weak<crate::runtime::SessionRuntime>>,
    /// The session's adoptions, which end with its backends when the session closes.
    #[cfg(unix)]
    adoptions: Option<Arc<crate::broker::adoption::Adoptions>>,
    /// Where the next committed launch stops before the launcher is told, for this host's own tests.
    #[cfg(feature = "testing")]
    confirm_pause: Arc<Mutex<Option<ConfirmPause>>>,
    /// Where the next launch that says it is going stops before it is committed, for this host's
    /// own tests.
    #[cfg(feature = "testing")]
    commit_pause: Arc<Mutex<Option<ConfirmPause>>>,
    /// Where the next backend's reading stops before it opens the directory it grants, for this
    /// host's own tests.
    #[cfg(feature = "testing")]
    directory_pause: Mutex<Option<DirectoryPause>>,
    /// Where the next close stops before it retires a backend, for this host's own tests.
    #[cfg(feature = "testing")]
    retire_pause: Mutex<Option<DirectoryPause>>,
}

/// The two ends of one armed pause: what says the launch arrived there, and what lets it go on.
#[cfg(feature = "testing")]
type ConfirmPause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

/// The two ends of one armed pause before a directory is opened, taken on a blocking thread.
#[cfg(feature = "testing")]
type DirectoryPause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

/// How long a paused directory open waits to be let go before it goes on by itself.
///
/// A pause no test releases, as when the open is somewhere it holds the test up, ends on its own,
/// so the test fails rather than waits for ever.
#[cfg(feature = "testing")]
const DIRECTORY_PAUSE_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

impl std::fmt::Debug for CommandBackends {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandBackends")
            .field("runtime_dir", &self.runtime_dir)
            .field("launcher", &self.launcher)
            .finish_non_exhaustive()
    }
}

/// Where one session's command backends live and what they launch through.
#[derive(Clone, Debug)]
pub struct CommandBackendsConfig {
    /// The session.
    pub session_id: SessionId,
    /// The environment the session runs in.
    pub environment_id: EnvironmentId,
    /// The operating-system user the session runs as.
    pub os_user: String,
    /// The directory the session's own root is made in, fresh, at the first establish.
    pub runtime_dir: PathBuf,
    /// The connectors the installation handed over.
    pub sources: Arc<ConnectorSources>,
    /// The installation's `kr-hook`, which the shell runs an integrated invocation through.
    pub launcher: Option<PathBuf>,
}

impl CommandBackends {
    /// Builds the session's command backends.
    #[must_use]
    pub fn new(
        broker: Arc<Broker>,
        config: CommandBackendsConfig,
        handle: tokio::runtime::Handle,
    ) -> Self {
        // The kernel's record of a start is checked the first time it is used, and the check
        // creates a process. Making it here keeps that off the session's lock at the first
        // establish; a failed check is read again there and refuses the route by name.
        #[cfg(windows)]
        let _ = crate::windows::lineage::start_clock();
        Self {
            broker,
            session_id: config.session_id,
            environment_id: config.environment_id,
            os_user: config.os_user,
            runtime_dir: config.runtime_dir,
            root: Mutex::new(None),
            sources: config.sources,
            launcher: config.launcher,
            handle,
            publishes_credential_file: ManagedProcess::publishes_credential_file(),
            backends: Mutex::new(Vec::new()),
            hashed: Arc::new(HashedFiles::default()),
            views: None,
            #[cfg(unix)]
            adoptions: None,
            #[cfg(feature = "testing")]
            confirm_pause: Arc::new(Mutex::new(None)),
            #[cfg(feature = "testing")]
            commit_pause: Arc::new(Mutex::new(None)),
            #[cfg(feature = "testing")]
            directory_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            retire_pause: Mutex::new(None),
        }
    }

    /// Delivers the transitions of every channel these backends serve to the session's attached
    /// views.
    #[must_use]
    pub fn with_views(mut self, runtime: Weak<crate::runtime::SessionRuntime>) -> Self {
        self.views = Some(runtime);
        self
    }

    /// Ends the session's adoptions with its backends when the session closes.
    #[cfg(unix)]
    #[must_use]
    pub fn with_adoptions(mut self, adoptions: Arc<crate::broker::adoption::Adoptions>) -> Self {
        self.adoptions = Some(adoptions);
        self
    }

    /// Stops the next launch that says it is going after it is committed and before the launcher is
    /// told, for this host's own tests: the backend is committed while its process still runs the
    /// launcher.
    ///
    /// Returns the end that says the launch has arrived there and the end that lets it go on. It is
    /// compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_confirming(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived, watch) = tokio::sync::oneshot::channel();
        let (release, go) = tokio::sync::oneshot::channel();
        *self
            .confirm_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Stops the next backend's reading before it opens the directory its launch is granted, for
    /// this host's own tests: an open that takes its time.
    ///
    /// Returns the end that says the reading has arrived there and the end that lets it go on;
    /// unreleased, it goes on by itself after [`DIRECTORY_PAUSE_LIMIT`]. It is compiled away in
    /// every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_opening_the_directory(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (arrived, watch) = std::sync::mpsc::channel();
        let (release, go) = std::sync::mpsc::channel();
        *self
            .directory_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Stops the next launch that says it is going before it is committed, for this host's own
    /// tests: the backend is still being launched while it waits.
    ///
    /// Returns the end that says the launch has arrived there and the end that lets it go on. It
    /// is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_committing(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived, watch) = tokio::sync::oneshot::channel();
        let (release, go) = tokio::sync::oneshot::channel();
        *self
            .commit_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Stops the next close before it retires its first backend, for this host's own tests: a
    /// launch can then commit between the close starting and the retirement.
    ///
    /// Returns the end that says the close has arrived there and the end that lets it go on, which
    /// it also does once the test drops that end. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_retiring(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (arrived, watch) = std::sync::mpsc::channel();
        let (release, go) = std::sync::mpsc::channel();
        *self
            .retire_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Answers establish as a platform that cannot publish a credential file would, for this host's
    /// own tests of that gate on a platform that can. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn as_if_without_credential_files(mut self) -> Self {
        self.publishes_credential_file = false;
        self
    }

    /// Returns the connectors this session's backends are established from.
    #[must_use]
    pub const fn sources(&self) -> &Arc<ConnectorSources> {
        &self.sources
    }

    /// Establishes the backend one integrated invocation runs behind, or says why none can be.
    ///
    /// # Errors
    ///
    /// Returns the reason no backend is established; the invocation then runs as typed.
    pub fn establish(
        &self,
        request: &EstablishRequest<'_>,
    ) -> std::result::Result<CommandBackend, String> {
        // Everything that can refuse without creating anything is asked first.
        if !self.publishes_credential_file {
            return Err(
                "this platform cannot prove a file is closed to other accounts, so no backend's \
                 credential can be published"
                    .to_owned(),
            );
        }
        let command = request
            .typed
            .first()
            .ok_or_else(|| "the invocation names no command".to_owned())?;
        let (connector, frame) = self
            .sources
            .for_command_at(command)
            .ok_or_else(|| format!("no installed connector integrates {command:?}"))?;
        let declared = connector
            .integration()
            .ok_or_else(|| format!("no installed connector integrates {command:?}"))?;
        // The session was created with one package's integration, and only that package's may
        // launch under it: another that came to integrate the command since, whatever it declares,
        // is one whose integration the configuration never turned on for this session.
        if connector.plugin_id() != request.integration.plugin_id {
            return Err(format!(
                "{command:?} is integrated here by {}, and this session was created with the \
                 integration of {}",
                connector.plugin_id(),
                request.integration.plugin_id
            ));
        }
        if declared.flags != request.integration.flags {
            return Err(format!(
                "the flags this session integrates {command:?} with are not the ones its installed \
                 connector declares"
            ));
        }
        // The flags are whole argument elements in a fixed order, so they are added as one run or,
        // where the person typed them, not at all: a value is never added without its flag.
        if !request.added.is_empty() && request.added != declared.flags.as_slice() {
            return Err(format!(
                "the answer adds only some of the flags {command:?} is integrated with, and they are \
                 added whole or not at all"
            ));
        }
        let launcher = self.launcher()?;
        check_executable(request.executable)?;
        // The command name matched the package; where the shell found it has to as well, so a
        // match rule that names its application's directory is held to it.
        if !connector.recognises(command, request.executable) {
            return Err(format!(
                "none of {}'s match rules recognises {command:?} where the shell found it, {}",
                connector.plugin_id(),
                request.executable
            ));
        }
        let added_at =
            added_run(request.typed, request.arguments, request.added).ok_or_else(|| {
                "the answered vector is not the typed one with the added flags as one run"
                    .to_owned()
            })?;

        let invocation = Invocation {
            typed: request.typed.to_vec(),
            arguments: request.arguments.to_vec(),
            added: request.added.to_vec(),
            executable: request.executable.to_owned(),
            cwd: request.cwd.to_owned(),
            cwd_revision: request.cwd_revision,
        };
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A resolve for a later line says every earlier line is over.
        end_lines(&mut backends, |generation| {
            generation < request.prompt_generation
        });
        // One backend per line. A retry of the same invocation is answered with the backend it was
        // given; anything else in the line runs as typed.
        if let Some(existing) = backends
            .iter()
            .find(|backend| backend.prompt_generation == request.prompt_generation)
        {
            if existing.is_unbound() && existing.invocation == invocation {
                return Ok(self.answer(existing, request.prompt_generation, &launcher));
            }
            return Err(
                "this line already has a backend, and one line runs one integrated invocation"
                    .to_owned(),
            );
        }
        let backend = self
            .create(request, invocation, added_at, connector, frame, &launcher)
            .map_err(|error| error.to_string())?;
        let answer = self.answer(&backend, request.prompt_generation, &launcher);
        backends.push(backend);
        Ok(answer)
    }

    /// Retires the backends of lines that are over.
    ///
    /// A finished command block says its line is over; a backend no launch took for it, or for an
    /// earlier line, is retired. A backend a launch is running under ends with its program.
    pub fn line_ended(&self, prompt_generation: PromptGeneration) {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        end_lines(&mut backends, |generation| generation <= prompt_generation);
    }

    /// Retires every backend, because the session is closing, removes the session's root, and
    /// returns the ends the session is to announce.
    ///
    /// No program is stopped here: the session's own closure owns the programs. What ends here is
    /// each committed launch's instance, with its grant, since the session is ending its program,
    /// and every instance the session adopted. It is called with the session's lock held, so
    /// nothing here takes it: the session announces what this returns. A launcher that looks now
    /// finds nothing to present to, and runs what was typed.
    #[must_use]
    pub fn close(&self) -> Vec<kr_protocol::projection::AgentInstanceSummary> {
        let backends = std::mem::take(
            &mut *self
                .backends
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut ended = Vec::new();
        for backend in backends {
            #[cfg(feature = "testing")]
            {
                let armed = self
                    .retire_pause
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some((arrived, go)) = armed {
                    let _ = arrived.send(());
                    let _ = go.recv();
                }
            }
            // Retired first, under its lifecycle lock, so no launch commits under it afterwards;
            // then whatever instance it registered is ended, whichever state the launch had
            // reached: a committed one is the session's to end, and one a launch still holds is
            // given back by that launch's guard, for which an ended instance is nothing to undo.
            backend.retire();
            ended.extend(backend.end_at_close(&self.broker));
        }
        #[cfg(unix)]
        if let Some(adoptions) = self.adoptions.as_ref() {
            ended.extend(adoptions.close());
        }
        let root = self
            .root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(root) = root {
            let _ = std::fs::remove_dir_all(root);
        }
        ended
    }

    /// Returns the session's root, once the first establish has made it.
    #[must_use]
    pub fn root(&self) -> Option<PathBuf> {
        self.root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns the session's root, making it fresh the first time: a new name in the runtime
    /// directory, so no two sessions share one whatever their identifiers.
    fn session_root(&self) -> Result<PathBuf> {
        let mut root = self
            .root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(root) = root.as_ref() {
            return Ok(root.clone());
        }
        let made = new_private_directory(&self.runtime_dir, "c")?;
        *root = Some(made.clone());
        Ok(made)
    }

    /// Returns the state of the backend established for one instance, where one is.
    #[must_use]
    pub fn state_of(&self, application_instance_id: ApplicationInstanceId) -> Option<BackendState> {
        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|backend| backend.application_instance_id == application_instance_id)
            .map(|backend| backend.lifecycle.state.borrow().clone())
    }

    /// Returns why the last launch the backend of one line took did not go, where one did not.
    ///
    /// It belongs to the backend and not to an instance: a launch that failed before its program was
    /// shown has no instance, and what a launcher declined or what the worker refused is kept here
    /// after the launch is given back.
    #[cfg(windows)]
    #[must_use]
    pub fn launch_failure_of(&self, prompt_generation: PromptGeneration) -> Option<String> {
        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|backend| backend.prompt_generation == prompt_generation)
            .and_then(|backend| {
                backend
                    .launch_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
    }

    fn launcher(&self) -> std::result::Result<PathBuf, String> {
        let launcher = self
            .launcher
            .clone()
            .ok_or_else(|| "this installation has no launcher".to_owned())?;
        if !launcher.is_absolute() {
            return Err(format!(
                "the launcher {} is not an absolute path",
                launcher.display()
            ));
        }
        if !runnable(&launcher) {
            return Err(format!(
                "the launcher {} is not a file this account may execute",
                launcher.display()
            ));
        }
        Ok(launcher)
    }

    /// The answer the shell runs an established invocation from: the registration's path, which is
    /// the one variable the shell exports.
    ///
    /// The variables the connector's verified manifest declares are in the launch record, and the
    /// launcher sets them once the launch is committed. A shell that exported them would replace the
    /// person's own value of the same name before the launcher knew whether the launch would run,
    /// and an invocation that then runs as typed could not have it back.
    fn answer(
        &self,
        backend: &Backend,
        prompt_generation: PromptGeneration,
        launcher: &Path,
    ) -> CommandBackend {
        CommandBackend {
            session_id: self.session_id,
            prompt_generation,
            environment: vec![EnvironmentVariable {
                name: "KR_REGISTRATION".to_owned(),
                value: backend.registration.display().to_string(),
            }],
            launcher: launcher.display().to_string(),
        }
    }

    /// Makes one backend: its directory, endpoint, credential, launch record and tasks.
    fn create(
        &self,
        request: &EstablishRequest<'_>,
        invocation: Invocation,
        added_at: usize,
        connector: Arc<InstalledConnector>,
        frame: Option<kr_protocol::admission::FrameId>,
        launcher: &Path,
    ) -> Result<Arc<Backend>> {
        let _entered = self.handle.enter();
        // Asked before anything is made: a platform that cannot place a start on a clock that only
        // moves forward has no launch it could tell from one that began earlier, and says why.
        let established_at =
            forward_now().map_err(|detail| BrokerError::UnsupportedCapability {
                detail: format!(
                    "the kernel's record of when a process started cannot be used: {detail}"
                ),
            })?;
        let application_instance_id =
            ApplicationInstanceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()));
        // A socket path has a small fixed bound, so the backend's directory has a short name of its
        // own rather than the instance's identifier; it is fresh, and taken new.
        let directory = new_private_directory(&self.session_root()?, "")?;
        let registration = directory.join(registration_name(added_at, invocation.added.len()));
        let profile_id = crate::broker::profiles::new_profile_id(kr_ipc::now_ms())?;
        let launch = NativeLaunch {
            profile_id: profile_id.clone(),
            expected_process: None,
            native_terminal: None,
            application_instance_id,
            plugin_id: connector.plugin_id(),
            installed_protocol_version: String::new(),
            framing: Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            site: self.environment_id,
            os_user: self.os_user.clone(),
            // The directory the invocation runs in, which is what its program works in.
            working_directory: PathBuf::from(request.cwd),
        };
        let mut gateway = NativeGateway::bind(Arc::clone(&self.broker), &directory, launch)?;
        if let Some(installed) = connector.launch_bridge(launcher) {
            gateway = gateway.with_bridge(installed)?;
        }
        let gateway = Arc::new(gateway);
        let credential = Credential::generate()?;
        let credential_path = directory.join(crate::broker::attach::CREDENTIAL_FILE);
        credential.write_file(&credential_path)?;
        // The variables the connector's verified manifest declares, in its order, which the
        // launcher sets only once the launch is committed.
        let variables: &[EnvironmentVariable] = connector
            .integration()
            .map_or(&[], |integration| integration.variables.as_slice());
        let record = serde_json::json!({
            "endpoint": gateway.address().for_diagnostics(),
            "credential": credential_path.display().to_string(),
            "variables": variables,
        });
        kr_ipc::paths::write_owner_only_file(
            &directory.join(LAUNCH_RECORD_FILE),
            record.to_string().as_bytes(),
        )
        .map_err(|error| {
            BrokerError::ledger(format!("could not write the launch record: {error}"))
        })?;
        let (identity_sender, identity) = tokio::sync::watch::channel(None);
        // A connector whose installation may read files is granted the directory the shell
        // reported for this invocation.
        let reads_files =
            connector.granted(kr_plugin_sdk::capability::PluginCapability::FilesystemRead);
        let backend = Arc::new(Backend {
            application_instance_id,
            prompt_generation: request.prompt_generation,
            invocation,
            directory,
            registration,
            line_over: AtomicBool::new(false),
            profile_id,
            gateway,
            credential,
            root_shell: request.root_shell.clone(),
            established_at,
            connector,
            frame,
            lifecycle: Lifecycle::new(BackendState::Unbound),
            identity,
            image_refused: Mutex::new(None),
            announced: Mutex::new(Announced::default()),
            image_verified: crate::broker::image::VerifiedFiles::default(),
            #[cfg(windows)]
            held_image: Arc::new(Mutex::new(None)),
            #[cfg(windows)]
            pinned: Arc::new(Mutex::new(None)),
            #[cfg(windows)]
            launch_failure: Mutex::new(None),
            stopped: Arc::new(AtomicBool::new(false)),
            tasks: Mutex::new(Vec::new()),
            os_user: self.os_user.clone(),
            host_directory: Arc::new(std::sync::OnceLock::new()),
            views: self
                .views
                .as_ref()
                .map(|runtime| (self.session_id, Weak::clone(runtime))),
            #[cfg(feature = "testing")]
            confirm_pause: Arc::clone(&self.confirm_pause),
            #[cfg(feature = "testing")]
            commit_pause: Arc::clone(&self.commit_pause),
        });
        let reading = {
            let path = PathBuf::from(&backend.invocation.executable);
            let hashed = Arc::clone(&self.hashed);
            let connector = Arc::clone(&backend.connector);
            let stopped = Arc::clone(&backend.stopped);
            #[cfg(windows)]
            let holding = Arc::clone(&backend.held_image);
            #[cfg(windows)]
            let pinning = Arc::clone(&backend.pinned);
            let granted = Arc::clone(&backend.host_directory);
            let cwd = reads_files.then(|| PathBuf::from(request.cwd));
            let environment_id = self.environment_id;
            #[cfg(feature = "testing")]
            let pause = self
                .directory_pause
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            self.handle.spawn_blocking(move || {
                // The directory first, here rather than under the session's lock, because a path
                // on a filesystem that has stopped answering can hold its open for as long as it
                // likes. Opened now, what the launch is granted is the directory at the reported
                // revision, whatever the path names later; one that cannot be opened leaves the
                // launch with no directory, and every reverse file request refused. An open that
                // outlasts the admission's wait for the identity below refuses the launch, which
                // then runs as typed.
                if let Some(cwd) = cwd {
                    #[cfg(feature = "testing")]
                    if let Some((arrived, go)) = pause {
                        let _ = arrived.send(());
                        let _ = go.recv_timeout(DIRECTORY_PAUSE_LIMIT);
                    }
                    // Windows holds the path first, from the drive's root to the directory, and
                    // opens the directory after: what is opened is then the object the path named
                    // while it was held, and a directory that is not the pinned one is granted
                    // nothing.
                    #[cfg(windows)]
                    {
                        if let Some(pin) = cwd
                            .to_str()
                            .and_then(|text| crate::windows::pin::pin(text).ok())
                            && let Ok(opened) =
                                kr_transfer::authority::AuthorisedDirectory::open_root(
                                    environment_id,
                                    &cwd,
                                )
                            && opened.identity() == pin.identity()
                        {
                            let _ = granted.set(opened);
                            *pinning
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pin);
                        }
                    }
                    #[cfg(not(windows))]
                    if let Ok(opened) =
                        kr_transfer::authority::AuthorisedDirectory::open_root(environment_id, &cwd)
                    {
                        let _ = granted.set(opened);
                    }
                }
                let read = crate::broker::image::read_holding(&path, &hashed, &stopped).map(
                    |(hashed, held)| {
                        // Kept where the launch can be held to it; elsewhere the file is let go
                        // as soon as it has been read.
                        #[cfg(windows)]
                        {
                            *holding
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(held);
                        }
                        #[cfg(not(windows))]
                        drop(held);
                        let version = connector
                            .qualified_version(&hashed.digest)
                            .map(str::to_owned);
                        ExecutableIdentity { hashed, version }
                    },
                );
                let _ = identity_sender.send(Some(read));
            })
        };
        drop(reading);
        let serving = self.handle.spawn(serve(
            Arc::clone(&backend),
            Arc::clone(&self.broker),
            self.environment_id,
        ));
        backend
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(serving);
        Ok(backend)
    }
}

impl Backend {
    /// Announces the committed program to the session's views: launched through the integration,
    /// with the refusal of its bridges where one came first.
    fn announce_started(&self) {
        let summary = kr_protocol::projection::AgentInstanceSummary {
            application_instance_id: self.application_instance_id,
            plugin_id: kr_protocol::scalars::Nullable::some(self.connector.plugin_id()),
            profile_id: kr_protocol::scalars::Nullable::some(self.profile_id.clone()),
            mode: IntegrationMode::NativeBridge,
            bypass: kr_protocol::scalars::Nullable::null(),
            started_at: kr_ipc::now_ms(),
            ended_at: kr_protocol::scalars::Nullable::null(),
            refusal: kr_protocol::scalars::Nullable::null(),
        };
        self.announce(|announced| announced.start(summary));
    }

    /// Records why the instance's bridges are refused, and announces it once the program has been.
    ///
    /// A refusal stands for every later bridge and is found again by each, so only a new reason is
    /// announced, and none after the end.
    fn announce_refusal(&self, why: &str) {
        self.announce(|announced| announced.refuse(why));
    }

    /// Announces the end of the program that was announced as started, unless its session's
    /// closing announced it first.
    fn announce_ended(&self) {
        self.announce(|announced| announced.end(kr_ipc::now_ms()));
    }

    /// Decides one announcement and makes it to the session's views, where this backend was given
    /// them.
    ///
    /// The session's lock is taken first and the announced state second, here and when the
    /// session's closing ends the instance, so the views hear each instance's announcements in the
    /// order they were decided and no two locks are ever taken the other way round.
    fn announce(
        &self,
        decide: impl FnOnce(&mut Announced) -> Option<kr_protocol::projection::AgentInstanceSummary>,
    ) {
        let runtime = self
            .views
            .as_ref()
            .and_then(|(_, runtime)| runtime.upgrade());
        let Some(runtime) = runtime else {
            let _ = decide(
                &mut self
                    .announced
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            return;
        };
        let mut session = runtime.session();
        let decided = decide(
            &mut self
                .announced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if let Some(summary) = decided {
            session.announce_instance(summary);
        }
    }

    /// Ends this retired backend's instance, because its session is closing, and returns what the
    /// session is to announce.
    ///
    /// Called with the session's lock held, after the retirement. Nothing here stops the program,
    /// which the session's own closure ends; what ends here is the instance, its grant and what the
    /// views were told, so no list the session keeps names a program it is ending.
    fn end_at_close(
        &self,
        broker: &Broker,
    ) -> Option<kr_protocol::projection::AgentInstanceSummary> {
        let _ = broker.end(
            self.application_instance_id,
            crate::broker::InstanceEnding::NativeExit,
        );
        self.announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .end(kr_ipc::now_ms())
    }

    fn is_unbound(&self) -> bool {
        matches!(*self.lifecycle.state.borrow(), BackendState::Unbound)
    }

    fn is_retired(&self) -> bool {
        matches!(*self.lifecycle.state.borrow(), BackendState::Retired)
    }

    /// Ends this backend: no more connections, no running admission, no endpoint, no credential, no
    /// registration and no launch record.
    ///
    /// Each admission task ends when it sees the state become retired, dropping its connection and
    /// any guard it holds. A launcher that looks later finds nothing and runs what was typed, which
    /// its variable's file name tells it.
    fn retire(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.lifecycle.retire();
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
        // The path held for the grant is let go of with the backend: the directory can be renamed
        // again once nothing is using it for a launch.
        #[cfg(windows)]
        self.pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let _ = std::fs::remove_file(self.directory.join(crate::broker::attach::CREDENTIAL_FILE));
        let _ = std::fs::remove_file(&self.registration);
        let _ = std::fs::remove_file(self.directory.join(LAUNCH_RECORD_FILE));
        if let crate::broker::listener::ListenerAddress::PrivateSocket(socket) =
            self.gateway.address()
        {
            let _ = std::fs::remove_file(socket);
        }
    }

    /// Marks this backend's line as over: unbound, it is retired now; being launched, its rollback
    /// will retire it. Returns true when it is done with and can be forgotten.
    fn end_line(&self) -> bool {
        self.line_over.store(true, Ordering::SeqCst);
        if self.is_unbound() || self.is_retired() {
            self.retire();
            true
        } else {
            false
        }
    }

    /// Takes back a launch that did not go: the backend is unbound again for a retry of the same
    /// invocation, or retired when its line ended meanwhile.
    fn roll_back(&self) {
        let _ = std::fs::remove_file(&self.registration);
        let mut retired = false;
        self.lifecycle.state.send_if_modified(|state| {
            if matches!(state, BackendState::Launching) {
                if self.line_over.load(Ordering::SeqCst) {
                    *state = BackendState::Retired;
                    retired = true;
                } else {
                    *state = BackendState::Unbound;
                }
                true
            } else {
                false
            }
        });
        if retired {
            self.retire();
        }
    }

    /// Waits for the executable's identity, within `wait`.
    async fn identity(
        &self,
        wait: std::time::Duration,
    ) -> std::result::Result<ExecutableIdentity, String> {
        let mut identity = self.identity.clone();
        let read = tokio::time::timeout(wait, identity.wait_for(Option::is_some))
            .await
            .map_err(|_| "the executable's identity was not read in time".to_owned())?
            .map_err(|_| "the executable's identity was never read".to_owned())?
            .clone();
        read.unwrap_or_else(|| Err("the executable's identity was never read".to_owned()))
    }
}

/// Serves one backend's endpoint until the backend is retired.
async fn serve(backend: Arc<Backend>, broker: Arc<Broker>, environment_id: EnvironmentId) {
    let admissions = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ADMISSIONS));
    loop {
        let accepted = match backend.gateway.accept_next().await {
            Ok(accepted) => accepted,
            Err(_) => {
                if matches!(*backend.lifecycle.state.borrow(), BackendState::Retired) {
                    return;
                }
                // An accept the kernel refused, for a descriptor limit or a connection reset
                // before it was taken, is not the endpoint ending.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
        };
        // Beyond the bound a connection is closed unread.
        let Ok(permit) = Arc::clone(&admissions).try_acquire_owned() else {
            drop(accepted);
            continue;
        };
        let backend = Arc::clone(&backend);
        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            let _permit = permit;
            // Retiring the backend ends the admission wherever it is: its connection closes, and a
            // guard it holds gives back.
            let mut state = backend.lifecycle.state.subscribe();
            tokio::select! {
                biased;
                _ = state.wait_for(|state| matches!(state, BackendState::Retired)) => {}
                () = admit(Arc::clone(&backend), broker, environment_id, accepted) => {}
            }
        });
    }
}

/// Reads one connection's first frame and hands it to what it opened as.
async fn admit(
    backend: Arc<Backend>,
    broker: Arc<Broker>,
    environment_id: EnvironmentId,
    accepted: crate::broker::endpoint::Accepted,
) {
    let opened = match backend.gateway.open(accepted).await {
        Ok(opened) => opened,
        Err(_) => return,
    };
    match opened {
        Opening::Launch(presented) => {
            let _ = admit_launch(&backend, &broker, environment_id, presented).await;
        }
        Opening::Bridge(pending) => {
            let Some(registration) = committed(
                &backend.lifecycle.state,
                crate::broker::attach::HELLO_DEADLINE,
            )
            .await
            else {
                return;
            };
            // Only the program's own bridges may ask whether it executes what was hashed.
            let Ok(authenticated) = backend.gateway.authenticate_bridge(pending, &registration)
            else {
                return;
            };
            // Off the runtime's threads: an executable whose metadata changed is hashed again.
            let verdict = {
                let backend = Arc::clone(&backend);
                let registration = Arc::clone(&registration);
                tokio::task::spawn_blocking(move || verify(&backend, &registration)).await
            };
            match verdict {
                Ok(Ok(())) => {}
                Ok(Err(why)) => {
                    backend.announce_refusal(&why);
                    return;
                }
                Err(_) => return,
            }
            let Ok(admitted) = authenticated.admit().await else {
                return;
            };
            match admitted.surface {
                BridgeSurface::Hook => {
                    let _ = backend.gateway.observe_hook(admitted).await;
                }
                BridgeSurface::Channel => {
                    // Served in a task of its own, outside the admission bound, for as long as it
                    // is open. It is not one of the backend's tasks, which retirement aborts: the
                    // retirement is what ends it, and it ends through its own close, which settles
                    // what it relayed.
                    let version = backend
                        .identity
                        .borrow()
                        .as_ref()
                        .and_then(|read| read.as_ref().ok())
                        .and_then(|identity| identity.version.clone());
                    let launch = crate::broker::channels::ChannelLaunch {
                        broker,
                        application_instance_id: backend.application_instance_id,
                        connector: Arc::clone(&backend.connector),
                        version,
                        site: environment_id,
                        os_user: backend.os_user.clone(),
                        views: backend.views.clone(),
                    };
                    let mut state = backend.lifecycle.state.subscribe();
                    let retired = async move {
                        let _ = state
                            .wait_for(|state| matches!(state, BackendState::Retired))
                            .await;
                    };
                    tokio::spawn(crate::broker::channels::serve(launch, admitted, retired));
                }
            }
        }
    }
}

/// Waits, within `within`, for a launch being committed to be committed, and returns the
/// registration bridges are admitted against.
///
/// A bridge that connects while the launch it belongs to is still being committed is the program's
/// first hook or its channel, started the moment the launcher execs: it waits for the commit rather
/// than being refused for arriving first. A backend no launch holds admits no bridge.
async fn committed(
    state: &tokio::sync::watch::Sender<BackendState>,
    within: std::time::Duration,
) -> Option<Arc<Registration>> {
    let mut state = state.subscribe();
    let settled = tokio::time::timeout(
        within,
        state.wait_for(|state| !matches!(state, BackendState::Launching)),
    )
    .await
    .ok()?
    .ok()?
    .clone();
    match settled {
        BackendState::Committed(registration) => Some(registration),
        BackendState::Unbound | BackendState::Launching | BackendState::Retired => None,
    }
}

/// Checks, for each bridge, that the committed process executes what this backend hashed.
///
/// Only an authenticated bridge asks: it descends from the registered process, which starts no child
/// before its exec, so the check is never taken before the exec. It is taken again for every bridge,
/// because the program can exec another in its place; one refusal refuses every later bridge.
fn verify(backend: &Backend, registration: &Registration) -> std::result::Result<(), String> {
    let mut refused = backend
        .image_refused
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(why) = refused.as_ref() {
        return Err(why.clone());
    }
    let identity = backend
        .identity
        .borrow()
        .clone()
        .unwrap_or_else(|| Err("the executable's identity was never read".to_owned()));
    let verified = identity.and_then(|identity| {
        crate::broker::image::verify_image(
            &registration.expected_process,
            &identity,
            &backend.image_verified,
            &backend.stopped,
        )
    });
    if let Err(why) = &verified {
        *refused = Some(why.clone());
    }
    verified
}

/// Reads the identity of the file a launch presented as its executable.
///
/// A path is read where a path is all there is. Windows holds the file this backend hashed, and the
/// file the path names cannot have moved while it is held, so the identity is the held file's own.
#[cfg(not(windows))]
fn presented_identity(_backend: &Backend, executable: &str) -> std::io::Result<FileIdentity> {
    std::fs::metadata(executable).map(|metadata| FileIdentity::of(&metadata))
}

/// Reads the identity of the file a launch presented as its executable, through the file this
/// backend holds, which cannot have been renamed, replaced or written since it was hashed.
#[cfg(windows)]
fn presented_identity(backend: &Backend, _executable: &str) -> std::io::Result<FileIdentity> {
    let held = backend
        .held_image
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.as_ref()
        .ok_or_else(|| {
            std::io::Error::other("the file this backend was established for is not held")
        })
        .and_then(FileIdentity::of_file)
}

/// Answers one launch that presented itself: admitted, or closed without a word.
async fn admit_launch(
    backend: &Arc<Backend>,
    broker: &Arc<Broker>,
    environment_id: EnvironmentId,
    presented: PresentedLaunch,
) -> Result<()> {
    let PresentedLaunch {
        peer,
        credential,
        launch,
        stream,
    } = presented;
    // The kernel's account of the peer, first: the owner, and the process it names, which is the one
    // the launcher says it is.
    if !peer.is_owner() {
        return Err(BrokerError::denied(
            "this connection is not the operating-system user who owns the session",
        ));
    }
    let process = peer.process().clone();
    if process.pid.get() != launch.pid || process.start_value.get() != launch.start {
        return Err(BrokerError::denied(
            "this connection says it is another process than the one the kernel named",
        ));
    }
    // The root shell's own child: the invocation's fork, and nothing further down. Where a parent
    // that has ended is still named, the shell must also have been running when this process
    // started.
    #[cfg(windows)]
    crate::windows::lineage::started_by(&process, &backend.root_shell).map_err(|why| {
        BrokerError::denied(format!(
            "this process was not started by the session's root shell: {why}"
        ))
    })?;
    #[cfg(not(windows))]
    {
        let parent = crate::questions::binding::parent_of(&process);
        if !parent.is_some_and(|parent| parent.matches(&backend.root_shell)) {
            return Err(BrokerError::denied(
                "this process was not started by the session's root shell",
            ));
        }
    }
    // Started after this backend was established, on the clock the kernel records starts on.
    started_after(&process, backend.established_at)?;
    if !backend.credential.authenticates(&credential) {
        return Err(BrokerError::denied(
            "this connection did not present this backend's credential",
        ));
    }
    let identity = backend
        .identity(IDENTITY_WAIT)
        .await
        .map_err(BrokerError::denied)?;
    let presented_file = presented_identity(backend, &launch.executable).map_err(|error| {
        BrokerError::denied(format!("the executable presented cannot be read: {error}"))
    })?;
    if launch.executable != backend.invocation.executable || presented_file != identity.hashed.file
    {
        return Err(BrokerError::denied(
            "the executable presented is not the file this backend was established for",
        ));
    }
    if launch.arguments != backend.invocation.arguments {
        return Err(BrokerError::denied(
            "the argument vector presented is not the one this backend answered",
        ));
    }
    // Unbound to launching, or refused: one launch per backend.
    let claimed = backend.lifecycle.state.send_if_modified(|state| {
        if matches!(state, BackendState::Unbound) {
            *state = BackendState::Launching;
            true
        } else {
            false
        }
    });
    if !claimed {
        return Err(BrokerError::denied(
            "this backend is not waiting for a launch",
        ));
    }
    continue_launch(backend, broker, environment_id, &process, &identity, stream).await
}

/// Takes a launch this admission claimed from its admission to its commitment, for a program that
/// replaces the launcher in place.
///
/// The launcher says it is going as soon as it reads its admission, and then execs: the process
/// that presented itself is the program, so the instance and the registration name it from the
/// admission on.
#[cfg(not(windows))]
async fn continue_launch(
    backend: &Arc<Backend>,
    broker: &Arc<Broker>,
    environment_id: EnvironmentId,
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    mut stream: BridgeStream,
) -> Result<()> {
    let admitted = admit_claimed(
        backend,
        broker,
        environment_id,
        process,
        identity,
        &mut stream,
    )
    .await;
    let registered = match admitted {
        Ok(registered) => registered,
        Err(error) => {
            backend.roll_back();
            return Err(error);
        }
    };
    let (guard, registration) = registered;
    // The launcher says it is going as soon as it reads its admission, and then execs.
    let going = tokio::time::timeout(GOING_DEADLINE, stream.read_frame()).await;
    let said_going = matches!(
        going,
        Ok(Ok(Some(ref frame))) if is_going(frame)
    );
    if !said_going {
        drop(guard);
        backend.roll_back();
        return Err(BrokerError::denied(
            "the admitted launch did not say it is going",
        ));
    }
    #[cfg(feature = "testing")]
    {
        let armed = backend
            .commit_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
    // The commit, under the lifecycle lock: the state, the guard and the supervision together, or,
    // for a backend retired meanwhile, none of them, and the guard gives back.
    let mut guard = Some(guard);
    let committed = backend.lifecycle.commit(Arc::new(registration), || {
        if let Some(guard) = guard.take() {
            guard.commit();
        }
        let supervising = tokio::spawn(supervise(
            Arc::clone(backend),
            Arc::clone(broker),
            process.clone(),
        ));
        backend
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(supervising);
    });
    if !committed {
        drop(guard);
        return Err(BrokerError::denied("this backend was retired"));
    }
    #[cfg(feature = "testing")]
    {
        let armed = backend
            .confirm_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
    // The launcher execs with the integration's flags only on this, written under the lifecycle
    // lock while the backend is still committed, and without waiting: the connection's buffer is
    // empty, and a write that would wait is a confirmation withheld. Should it not arrive, the
    // launcher runs what was typed without the variable, and the instance, which names that
    // process, has no bridge and ends with it.
    match backend
        .lifecycle
        .confirm(|| stream.try_write_frame(&confirmation()))
    {
        Some(Ok(true)) => Ok(()),
        Some(Ok(false)) => Err(BrokerError::UpstreamUnavailable {
            detail: "the launch's confirmation could not be written without waiting".to_owned(),
        }),
        Some(Err(error)) => Err(error),
        None => Err(BrokerError::denied(
            "this backend was retired before its launch was confirmed",
        )),
    }
}

/// What a launcher says when it says it is going, on a platform where it has created the program
/// suspended and names it.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Going {
    /// The program the launcher created, and the directory string it was given, which the program
    /// inherits.
    Program {
        /// The program's process identifier.
        pid: u32,
        /// The launcher's own current directory, where it could be read.
        directory: Option<String>,
    },
    /// The launcher could not create the program, and says why.
    Declined(String),
}

/// Reads the frame a launcher says it is going in.
#[cfg(any(windows, test))]
fn going_of(frame: &[u8]) -> std::result::Result<Going, String> {
    let value: serde_json::Value = serde_json::from_slice(frame)
        .map_err(|_| "the launcher's frame is not a frame it speaks".to_owned())?;
    let launch = value
        .get("kr_launch")
        .ok_or_else(|| "the launcher's frame is not a launch frame".to_owned())?;
    match launch.get("going").and_then(serde_json::Value::as_bool) {
        Some(true) => {
            let pid = launch
                .get("program")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or_else(|| "the launcher says it is going and names no program".to_owned())?;
            let directory = launch
                .get("directory")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            Ok(Going::Program { pid, directory })
        }
        Some(false) => Ok(Going::Declined(
            bounded_refusal(
                launch
                    .get("declined")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("the launcher declined to go and gave no reason"),
            )
            .to_owned(),
        )),
        None => Err("the launcher's frame does not say whether it is going".to_owned()),
    }
}

/// Returns true for the frame a launcher writes once it has started the program it created.
#[cfg(any(windows, test))]
fn is_resumed(frame: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(frame).is_ok_and(|value| {
        value
            .get("kr_launch")
            .and_then(|launch| launch.get("resumed"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    })
}

/// Records why a launch did not go, on the backend that took it.
#[cfg(windows)]
fn failed(backend: &Backend, why: String) -> BrokerError {
    *backend
        .launch_failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(why.clone());
    BrokerError::denied(why)
}

/// The profile one launch of this backend is recorded under.
fn launch_profile(
    backend: &Backend,
    environment_id: EnvironmentId,
    identity: &ExecutableIdentity,
) -> LaunchProfile {
    LaunchProfile {
        profile_id: backend.profile_id.clone(),
        environment_id,
        binary: BinaryIdentity {
            resolved_path: backend.invocation.executable.clone(),
            digest: identity.hashed.digest,
            version: identity
                .version
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            distribution: "command".to_owned(),
        },
        arguments: backend.invocation.arguments.clone(),
        authentication: AuthenticationState::Unknown,
        mode: IntegrationMode::NativeBridge,
        resolved_at: kr_ipc::now_ms(),
    }
}

/// The job of a program that was created suspended and has not yet been started, which ends the
/// program with everything in the job when the launch that holds it ends for any reason before the
/// launcher says it started it: a refusal, a failed write, a launcher that has gone, a launch
/// dropped meanwhile.
///
/// Nothing the program could have started exists until it has run, so ending it costs nothing, and
/// the launcher that created it is the one place a program left suspended would otherwise wait for
/// the session's end.
#[cfg(windows)]
struct Unstarted(Option<Arc<crate::windows::job::AgentJob>>);

#[cfg(windows)]
impl Unstarted {
    /// The launcher has started the program: it is the person's now, and this ends nothing.
    fn started(&mut self) {
        self.0 = None;
    }
}

#[cfg(windows)]
impl Drop for Unstarted {
    fn drop(&mut self) {
        if let Some(job) = self.0.take() {
            // Best effort: a program that cannot be ended is still in the session's job.
            let _ = job.terminate(1);
        }
    }
}

/// The program a launcher created, as the worker shows it: its identity, and the job it was put in.
#[cfg(windows)]
struct ShownProgram {
    process: ProcessStartIdentity,
    job: crate::windows::job::AgentJob,
}

/// Shows that the process a launcher named is the program this backend was established for.
///
/// Each of these is read from the kernel, and each refuses the launch on its own: the process is
/// the launcher's own child and was running when the launcher was; it started after this backend was
/// established; it was created from the file this backend hashed and holds; and it is put in a job of
/// its own, before it has run, so that what it starts is the program's.
#[cfg(windows)]
fn show_program(
    backend: &Backend,
    launcher: &ProcessStartIdentity,
    program: u32,
) -> std::result::Result<ShownProgram, String> {
    let process = kr_ipc::identity::started_process_identity(program)
        .map_err(|error| format!("the program cannot be identified: {error}"))?;
    if process.start_value.get() == kr_ipc::identity::START_VALUE_UNREAD {
        return Err("the program ended before it could be identified".to_owned());
    }
    crate::windows::lineage::started_by(&process, launcher)
        .map_err(|why| format!("the program was not started by the launcher: {why}"))?;
    let started = crate::windows::lineage::monotonic_start(&process)
        .map_err(|why| format!("when the program started cannot be read: {why}"))?;
    match backend.established_at {
        Some(established) if started >= established => {}
        Some(_) => {
            return Err("the program started before this backend was established".to_owned());
        }
        None => return Err("this platform keeps no record of when a program started".to_owned()),
    }
    {
        let held = backend
            .held_image
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = held
            .as_ref()
            .ok_or_else(|| "the file this backend was established for is not held".to_owned())?;
        crate::broker::image::show_image(&process, held)?;
    }
    let job = crate::windows::job::AgentJob::create()
        .map_err(|error| format!("the program's job cannot be made: {error}"))?;
    job.assign(program)
        .map_err(|error| format!("the program cannot be put in its job: {error}"))?;
    Ok(ShownProgram { process, job })
}

/// Makes the grant of the directory the program works in, where it can be made.
///
/// The directory the shell reported was held and opened when the backend was established. The
/// launcher says what directory the program inherits; that string is held the same way, and only
/// where it reaches the object the shell's did is anything granted: a launcher started in another
/// directory grants nothing. The commit reads the held directory's attributes again, and withdraws
/// the grant from one that has become a link. Nothing here fails a launch.
#[cfg(windows)]
async fn directory_grant(
    backend: &Backend,
    inherited: Option<String>,
) -> Option<crate::broker::host::HostFiles> {
    let granted = backend.host_directory.get()?;
    let reported = inherited?;
    let walked = tokio::task::spawn_blocking(move || crate::windows::pin::pin(&reported))
        .await
        .ok()?
        .ok()?;
    {
        let pinned = backend
            .pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pinned = pinned.as_ref()?;
        if walked.identity() != pinned.identity() {
            return None;
        }
    }
    drop(walked);
    granted.try_clone().ok().and_then(|root| {
        crate::broker::host::HostFiles::new(root, crate::broker::host::FileAccess::Read).ok()
    })
}

/// Takes a launch this admission claimed from its admission to its commitment, for a program the
/// launcher has created beside itself.
///
/// Windows has no `exec`: the launcher creates the program suspended, says it is going and names it,
/// and starts it only once the commitment arrives. So the instance, the registration and the job of
/// the program all name the program and not the launcher, and nothing is registered or published
/// until the program has been shown. A launch that fails before the commitment leaves the program
/// suspended and unrun, and the launcher ends it and runs what was typed.
#[cfg(windows)]
async fn continue_launch(
    backend: &Arc<Backend>,
    broker: &Arc<Broker>,
    environment_id: EnvironmentId,
    launcher: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    mut stream: BridgeStream,
) -> Result<()> {
    let idle = ForegroundMark::idle(backend.prompt_generation.get());
    let reserved = broker
        .prepare_launch(
            launch_profile(backend, environment_id, identity),
            idle.clone(),
            None,
        )
        .and_then(|intent| broker.execute_launch(&intent, &idle, backend.application_instance_id));
    let reservation = match reserved {
        Ok(reservation) => reservation,
        Err(error) => {
            backend.roll_back();
            return Err(error);
        }
    };
    if let Err(error) = stream.write_frame(&admission()).await {
        drop(reservation);
        backend.roll_back();
        return Err(error);
    }
    // The launcher creates the program and says so as soon as it reads its admission.
    let going = match tokio::time::timeout(GOING_DEADLINE, stream.read_frame()).await {
        Ok(Ok(Some(frame))) => going_of(&frame),
        Ok(_) => Err("the admitted launch closed without saying it is going".to_owned()),
        Err(_) => Err("the admitted launch did not say it is going in time".to_owned()),
    };
    let (program, directory) = match going {
        Ok(Going::Program { pid, directory }) => (pid, directory),
        Ok(Going::Declined(why)) => {
            drop(reservation);
            let error = failed(
                backend,
                format!("the launcher could not start the program: {why}"),
            );
            backend.roll_back();
            return Err(error);
        }
        Err(why) => {
            drop(reservation);
            let error = failed(backend, why);
            backend.roll_back();
            return Err(error);
        }
    };
    let shown = {
        let (backend, launcher) = (Arc::clone(backend), launcher.clone());
        tokio::task::spawn_blocking(move || show_program(&backend, &launcher, program))
            .await
            .unwrap_or_else(|_| Err("showing the program did not finish".to_owned()))
    };
    let ShownProgram { process, job } = match shown {
        Ok(shown) => shown,
        Err(why) => {
            drop(reservation);
            let error = failed(backend, why);
            backend.roll_back();
            return Err(error);
        }
    };
    // From here the program exists, shown to be the launcher's own child made from the held file,
    // and is ended unless the launcher says it started it.
    let job = Arc::new(job);
    let mut unstarted = Unstarted(Some(Arc::clone(&job)));
    // Registered by the reservation, with the program and not the launcher.
    let managed = ManagedProcess::new(
        backend.application_instance_id,
        process.clone(),
        crate::broker::process::TransportHandle {
            transport: crate::broker::process::BrokerTransport::PrivateSocket,
            application_instance_id: backend.application_instance_id,
            executable_digest: identity.hashed.digest,
            process: process.clone(),
        },
        backend.credential.duplicate(),
        // The program is the person's own terminal application, not a backend this host started
        // for it: nothing here stops it when it ends, because its ending is the end.
        false,
        kr_ipc::now_ms(),
    );
    let registered = match reservation.register(IntegrationMode::NativeBridge, Some(managed)) {
        Ok(registered) => registered,
        Err(refused) => {
            let error = failed(backend, refused.error.to_string());
            backend.roll_back();
            return Err(error);
        }
    };
    // Kept for the broker, which places what the program starts by what its job holds. The
    // registered launch lets it go again if the launch is given back.
    crate::windows::job::keep_agent(process.clone(), Arc::clone(&job), None);
    let finished = finish_binding(backend, broker, identity, &process, directory).await;
    let (registered, registration) = match finished {
        Ok(finished) => (registered, finished),
        Err(error) => {
            drop(registered);
            let error = failed(backend, error.to_string());
            backend.roll_back();
            return Err(error);
        }
    };
    #[cfg(feature = "testing")]
    {
        let armed = backend
            .commit_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
    // The directory the grant was made on is read again at the commit: a principal that may write
    // to an empty directory can convert it to a link in place whatever is held, and the grant is
    // then withdrawn. It never moves: it keeps naming the directory that was held, and a read through
    // it after the conversion is refused.
    let still_a_directory = backend
        .pinned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_none_or(|pin| pin.recheck().is_ok());
    if !still_a_directory {
        broker.withdraw_host_files(backend.application_instance_id);
    }
    // The commit, under the lifecycle lock: the state, the guard and the supervision together, or,
    // for a backend retired meanwhile, none of them, and the guard gives back. The verdict on the
    // program's image is recorded in the same step: it is final for the process.
    let mut guard = Some(registered);
    let shown_image =
        crate::broker::image::record_verdict(&process, identity, &backend.image_verified);
    let committed = shown_image.is_ok()
        && backend.lifecycle.commit(Arc::new(registration), || {
            if let Some(guard) = guard.take() {
                guard.commit();
            }
            let supervising = tokio::spawn(supervise(
                Arc::clone(backend),
                Arc::clone(broker),
                process.clone(),
            ));
            backend
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(supervising);
        });
    if !committed {
        drop(guard);
        return Err(match shown_image {
            Err(why) => failed(backend, why),
            Ok(()) => BrokerError::denied("this backend was retired"),
        });
    }
    // The hold on the file ends with the commit. It kept the file from being renamed, deleted or
    // written between the hash and the program's creation; the program's image is the verdict from
    // here, which never reads a path, and a program that updates itself in place while it runs
    // must be able to.
    drop(
        backend
            .held_image
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(),
    );
    #[cfg(feature = "testing")]
    {
        let armed = backend
            .confirm_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }
    // The launcher starts the program only on this, written under the lifecycle lock while the
    // backend is still committed, and without waiting. Should it not arrive, the launcher ends the
    // program it created and runs what was typed.
    match backend
        .lifecycle
        .confirm(|| stream.try_write_frame(&confirmation()))
    {
        Some(Ok(true)) => {}
        Some(Ok(false)) => {
            return Err(BrokerError::UpstreamUnavailable {
                detail: "the launch's confirmation could not be written without waiting".to_owned(),
            });
        }
        Some(Err(error)) => return Err(error),
        None => {
            return Err(BrokerError::denied(
                "this backend was retired before its launch was confirmed",
            ));
        }
    }
    // The program is committed and not yet running. The launcher starts it and says so; one that
    // does not within its deadline, or that closes the connection, leaves a program that was
    // committed and never started, which is ended with everything in its job.
    let resumed = match tokio::time::timeout(RESUME_DEADLINE, stream.read_frame()).await {
        Ok(Ok(Some(frame))) => is_resumed(&frame),
        _ => false,
    };
    if resumed {
        unstarted.started();
        Ok(())
    } else {
        // `unstarted` ends the program and everything in its job as this returns.
        Err(BrokerError::denied(
            "the launcher did not say it started the program it was committed to",
        ))
    }
}

/// Binds the registered launch to its package, makes the directory's grant where one can be made,
/// and publishes the registration, which names the program.
#[cfg(windows)]
async fn finish_binding(
    backend: &Backend,
    broker: &Broker,
    identity: &ExecutableIdentity,
    process: &ProcessStartIdentity,
    inherited: Option<String>,
) -> Result<Registration> {
    let frame = backend
        .frame
        .ok_or_else(|| BrokerError::PreconditionFailed {
            detail: "this backend's connector came from no admissions this worker holds".to_owned(),
        })?;
    broker.bind(
        kr_protocol::ids::BrokerBindingId::new(kr_ipc::new_uuid()),
        backend.application_instance_id,
        backend.connector.package_digest(),
        frame,
        crate::broker::binder::MatchedExecutable {
            path: backend.invocation.executable.clone(),
            digest: identity.hashed.digest,
        },
        kr_ipc::now_ms(),
    )?;
    if let Some(files) = directory_grant(backend, inherited).await {
        broker.grant_host_files(backend.application_instance_id, files)?;
    }
    let registration = Registration::new(
        backend.gateway.address().clone(),
        backend.profile_id.clone(),
        backend.application_instance_id,
        process.clone(),
        backend
            .directory
            .join(crate::broker::attach::CREDENTIAL_FILE),
    );
    let published = format!("{}framing=json_lines\n", registration.to_file());
    kr_ipc::paths::write_owner_only_file(&backend.registration, published.as_bytes()).map_err(
        |error| BrokerError::ledger(format!("could not write the registration: {error}")),
    )?;
    Ok(registration)
}

/// Records the launch, registers its instance by its reservation, publishes the registration and
/// answers `admitted`, all for a backend this admission claimed.
#[cfg(not(windows))]
async fn admit_claimed<'a>(
    backend: &Backend,
    broker: &'a Broker,
    environment_id: EnvironmentId,
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    stream: &mut BridgeStream,
) -> Result<(crate::broker::RegisteredLaunch<'a>, Registration)> {
    let generation = backend.prompt_generation.get();
    let profile = launch_profile(backend, environment_id, identity);
    let idle = ForegroundMark::idle(generation);
    let intent = broker.prepare_launch(profile, idle.clone(), None)?;
    let reservation = broker.execute_launch(&intent, &idle, backend.application_instance_id)?;
    let managed = ManagedProcess::new(
        backend.application_instance_id,
        process.clone(),
        crate::broker::process::TransportHandle {
            transport: crate::broker::process::BrokerTransport::PrivateSocket,
            application_instance_id: backend.application_instance_id,
            executable_digest: identity.hashed.digest,
            process: process.clone(),
        },
        backend.credential.duplicate(),
        // The program is the person's own terminal application, not a backend this host started
        // for it: nothing here stops it when it ends, because its ending is the end.
        false,
        kr_ipc::now_ms(),
    );
    let registered = reservation
        .register(IntegrationMode::NativeBridge, Some(managed))
        .map_err(|refused| refused.error)?;
    // The instance is bound to the package this backend was established from, at the frame it was
    // decided at, from the admissions this worker holds. A package that left them since is refused
    // here, and the launch fails as any failure here does: what it registered is given back, its
    // binding with it, and the launcher runs what was typed.
    let frame = backend
        .frame
        .ok_or_else(|| BrokerError::PreconditionFailed {
            detail: "this backend's connector came from no admissions this worker holds".to_owned(),
        })?;
    broker.bind(
        kr_protocol::ids::BrokerBindingId::new(kr_ipc::new_uuid()),
        backend.application_instance_id,
        backend.connector.package_digest(),
        frame,
        crate::broker::binder::MatchedExecutable {
            path: backend.invocation.executable.clone(),
            digest: identity.hashed.digest,
        },
        kr_ipc::now_ms(),
    )?;
    // The directory the invocation was resolved in, for reading only and confined to its own
    // mount. The grant is the instance's, so it goes with the instance: a launch given back takes
    // it along, and so does the program's end. It is granted only when it is the directory the
    // launched process works in, as the kernel keeps it: the path was opened after the shell
    // reported it, and a directory moved away and replaced at that path meanwhile is another
    // directory. A directory no grant can be made from (its handle cannot be taken again, or its
    // mount cannot be told) is granted nothing, like one that could not be opened.
    let working = working_directory_of(process.pid.get());
    if let Some(files) = backend
        .host_directory
        .get()
        .filter(|directory| {
            working.is_some_and(|working| directory.check_identity(working).is_ok())
        })
        .and_then(|directory| directory.try_clone().ok())
        .and_then(|root| {
            crate::broker::host::HostFiles::new(root, crate::broker::host::FileAccess::Read).ok()
        })
    {
        broker.grant_host_files(backend.application_instance_id, files)?;
    }
    let registration = Registration::new(
        backend.gateway.address().clone(),
        backend.profile_id.clone(),
        backend.application_instance_id,
        process.clone(),
        backend
            .directory
            .join(crate::broker::attach::CREDENTIAL_FILE),
    );
    let published = format!("{}framing=json_lines\n", registration.to_file());
    let registration_path = &backend.registration;
    kr_ipc::paths::write_owner_only_file(registration_path, published.as_bytes()).map_err(
        |error| BrokerError::ledger(format!("could not write the registration: {error}")),
    )?;
    if let Err(error) = stream.write_frame(&admission()).await {
        let _ = std::fs::remove_file(registration_path);
        return Err(error);
    }
    Ok((registered, registration))
}

/// The frame a launch that was admitted is answered with.
fn admission() -> Vec<u8> {
    serde_json::json!({ "kr_launch": { "admitted": true } })
        .to_string()
        .into_bytes()
}

/// The frame a launch that was committed is answered with; the launcher execs on it.
fn confirmation() -> Vec<u8> {
    serde_json::json!({ "kr_launch": { "committed": true } })
        .to_string()
        .into_bytes()
}

/// Returns the identity of the directory a process works in, as the kernel keeps it: the directory
/// object itself, whatever path names it now.
#[cfg(target_os = "linux")]
fn working_directory_of(pid: u64) -> Option<kr_transfer::authority::ObjectIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(format!("/proc/{pid}/cwd")).ok()?;
    Some(kr_transfer::authority::ObjectIdentity {
        device: metadata.dev(),
        file_id: metadata.ino(),
    })
}

/// Returns the identity of the directory a process works in, as the kernel keeps it: the directory
/// object itself, whatever path names it now.
#[cfg(target_os = "macos")]
fn working_directory_of(pid: u64) -> Option<kr_transfer::authority::ObjectIdentity> {
    let pid = i32::try_from(pid).ok()?;
    let info: WorkingDirectories = libproc::proc_pid::pidinfo(pid, 0).ok()?;
    let stat = &info.current.vnode.stat;
    Some(kr_transfer::authority::ObjectIdentity {
        device: u64::from(stat.vst_dev),
        file_id: stat.vst_ino,
    })
}

/// Returns the path of the directory a process works in, as the kernel names it now.
#[cfg(target_os = "macos")]
pub(crate) fn working_directory_path_of(pid: u64) -> Option<std::path::PathBuf> {
    let pid = i32::try_from(pid).ok()?;
    let info: WorkingDirectories = libproc::proc_pid::pidinfo(pid, 0).ok()?;
    let path = &info.current.path;
    let end = path.iter().position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(&path[..end]).ok()?;
    (!text.is_empty()).then(|| std::path::PathBuf::from(text))
}

/// No platform record of a process's working directory is read here, so none is granted.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const fn working_directory_of(_pid: u64) -> Option<kr_transfer::authority::ObjectIdentity> {
    None
}

/// The kernel's `struct proc_vnodepathinfo`: the current and the root directory of a process.
#[cfg(target_os = "macos")]
#[repr(C)]
struct WorkingDirectories {
    current: VnodeWithPath,
    root: VnodeWithPath,
}

/// The kernel's `struct vnode_info_path`.
#[cfg(target_os = "macos")]
#[repr(C)]
struct VnodeWithPath {
    vnode: Vnode,
    path: [u8; 1024],
}

/// The kernel's `struct vnode_info`.
#[cfg(target_os = "macos")]
#[repr(C)]
struct Vnode {
    stat: libproc::net_info::VInfoStat,
    kind: i32,
    pad: i32,
    fsid: [i32; 2],
}

#[cfg(target_os = "macos")]
impl libproc::proc_pid::PIDInfo for WorkingDirectories {
    fn flavor() -> libproc::proc_pid::PidInfoFlavor {
        libproc::proc_pid::PidInfoFlavor::VNodePathInfo
    }
}

/// The most bytes of a refusal's reason an announcement carries.
///
/// A reason names paths the platform reported, and an announcement is carried whole in every
/// subscription's answer, so it is bounded where it is made.
pub const MAX_REFUSAL_BYTES: usize = 512;

/// Returns a refusal's reason cut to [`MAX_REFUSAL_BYTES`], at a character boundary.
fn bounded_refusal(why: &str) -> &str {
    if why.len() <= MAX_REFUSAL_BYTES {
        return why;
    }
    let mut end = MAX_REFUSAL_BYTES;
    while !why.is_char_boundary(end) {
        end -= 1;
    }
    &why[..end]
}

/// Returns true for the frame a launcher writes when it is about to exec the program.
#[cfg(not(windows))]
fn is_going(frame: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(frame).is_ok_and(|value| {
        value
            .get("kr_launch")
            .and_then(|launch| launch.get("going"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    })
}

/// Announces the committed program, watches it for as long as it runs, and ends the instance and
/// announces its end when it exits.
///
/// The start is announced here rather than where the launch is committed, so the one task that
/// announces the end has announced the start before it.
async fn supervise(backend: Arc<Backend>, broker: Arc<Broker>, process: ProcessStartIdentity) {
    backend.announce_started();
    loop {
        if matches!(
            kr_ipc::identity::process_state(&process),
            kr_ipc::identity::ProcessState::Ended
        ) {
            let _ = broker.end(
                backend.application_instance_id,
                crate::broker::InstanceEnding::NativeExit,
            );
            backend.retire();
            backend.announce_ended();
            return;
        }
        tokio::time::sleep(SUPERVISION_POLL).await;
    }
}

/// Ends the lines `ended` says are over: their unbound backends are retired and forgotten, and a
/// backend being launched is marked so that its rollback retires it.
fn end_lines(backends: &mut Vec<Arc<Backend>>, ended: impl Fn(PromptGeneration) -> bool) {
    backends.retain(|backend| !(ended(backend.prompt_generation) && backend.end_line()));
}

/// Returns where the added flags stand in the answered vector: the index of the one run whose
/// removal gives the typed vector.
fn added_run(typed: &[String], answered: &[String], added: &[String]) -> Option<usize> {
    if answered.len() != typed.len().checked_add(added.len())? {
        return None;
    }
    if added.is_empty() {
        return (answered == typed).then_some(0);
    }
    (0..=typed.len()).find(|&at| {
        answered.get(at..at + added.len()) == Some(added)
            && answered.get(..at) == typed.get(..at)
            && answered.get(at + added.len()..) == typed.get(at..)
    })
}

/// The file name a backend's registration is published under, which tells the launcher where the
/// added flags stand: `registration.<at>.<count>`.
fn registration_name(at: usize, count: usize) -> String {
    format!("{REGISTRATION_PREFIX}.{at}.{count}")
}

/// Refuses an executable that is not an absolute path to a regular file.
fn check_executable(executable: &str) -> std::result::Result<(), String> {
    let path = Path::new(executable);
    if !path.is_absolute() {
        return Err(format!(
            "the executable {executable:?} is not an absolute path"
        ));
    }
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("the executable {executable:?} cannot be read: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("the executable {executable:?} is not a file"));
    }
    Ok(())
}

/// Whether `path` is a regular file this account may execute: what a launcher, and an executable a
/// command resolves to, are held to wherever this host needs to know that one would run.
///
/// The kernel is asked, for this account, rather than the mode read: an execute bit for another
/// account, or one an access list withdraws, runs nothing here.
#[must_use]
pub fn runnable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) && executable_here(path)
}

#[cfg(unix)]
fn executable_here(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

#[cfg(not(unix))]
const fn executable_here(_path: &Path) -> bool {
    true
}

/// Makes one new owner-only directory at `directory`: `Ok(false)` when the name is already taken,
/// and a directory the host cannot show is private is an error, not a success.
///
/// On Unix the directory is made and then given its mode. On Windows it is made with its own
/// protected list in the one call, so there is no moment at which it carries the list of the
/// directory above it; the name is looked for first, and a name another launch took in the instant
/// between is read back by its list like any other directory this host publishes into.
fn create_new_private_directory(directory: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        match std::fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => {
                return Err(BrokerError::ledger(format!(
                    "could not make {}: {error}",
                    directory.display()
                )));
            }
        }
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                BrokerError::ledger(format!(
                    "could not make {} owner-only: {error}",
                    directory.display()
                ))
            },
        )?;
    }
    #[cfg(windows)]
    {
        if directory.exists() {
            return Ok(false);
        }
        kr_ipc::paths::create_private_directory(directory).map_err(|error| {
            BrokerError::ledger(format!(
                "could not make {} owner-only: {error}",
                directory.display()
            ))
        })?;
    }
    crate::broker::process::check_private_directory(directory)?;
    Ok(true)
}

/// Makes a new owner-only directory with a short fresh name, `prefix` then eight hexadecimal
/// digits, inside `root`; a name already there is drawn again.
fn new_private_directory(root: &Path, prefix: &str) -> Result<PathBuf> {
    for _ in 0..8 {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let directory = root.join(format!("{prefix}{name}"));
        if create_new_private_directory(&directory)? {
            return Ok(directory);
        }
    }
    Err(BrokerError::ledger(format!(
        "no fresh backend directory could be made in {}",
        root.display()
    )))
}

/// Refuses a process that started before `established_at`, on the clock the kernel records starts
/// on, where the platform keeps such a record.
fn started_after(process: &ProcessStartIdentity, established_at: Option<u64>) -> Result<()> {
    #[cfg(windows)]
    let started = crate::windows::lineage::monotonic_start(process).map(Some);
    #[cfg(not(windows))]
    let started = crate::questions::binding::monotonic_start(process);
    let started = started.map_err(|why| {
        BrokerError::denied(format!(
            "the kernel's record of when this process started cannot be read: {why}"
        ))
    })?;
    match (started, established_at) {
        (Some(started), Some(established)) if started >= established => Ok(()),
        (Some(_), Some(_)) => Err(BrokerError::denied(
            "this process started before this backend was established",
        )),
        _ => Err(BrokerError::denied(
            "this platform keeps no forward-only record of when a process started",
        )),
    }
}

/// Reads the clock the kernel records a process's start on, now.
///
/// Linux records a start in clock ticks since the boot, on the clock that counts a suspend.
#[cfg(target_os = "linux")]
fn forward_now() -> std::result::Result<Option<u64>, String> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let ticks = rustix::param::clock_ticks_per_second();
    let seconds = u64::try_from(now.tv_sec).ok();
    let nanoseconds = u64::try_from(now.tv_nsec).ok();
    Ok(seconds.zip(nanoseconds).map(|(seconds, nanoseconds)| {
        seconds
            .saturating_mul(ticks)
            .saturating_add(nanoseconds.saturating_mul(ticks) / 1_000_000_000)
    }))
}

/// Reads the clock the kernel records a process's start on, now.
///
/// macOS records a start as the host's absolute time at the fork, in the units
/// `mach_absolute_time` reads.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "mach_absolute_time takes nothing, touches no memory and cannot fail; it is the \
              clock the kernel's record of a process's start is on, and nothing safe reads it"
)]
#[expect(
    deprecated,
    reason = "libc points at a separate crate for the Mach calls, and this one call is all the \
              worker makes"
)]
fn forward_now() -> std::result::Result<Option<u64>, String> {
    // SAFETY: the function takes no argument and reads a counter; it has no precondition.
    Ok(Some(unsafe { libc::mach_absolute_time() }))
}

/// Reads the clock the kernel records a process's start on, now.
///
/// Windows records a start as the kernel's interrupt time, which counts sleep and never goes back
/// within a boot: the start of a process is the interrupt time when it was created.
#[cfg(windows)]
fn forward_now() -> std::result::Result<Option<u64>, String> {
    crate::windows::lineage::interrupt_now().map(Some)
}

/// This platform records no start on a clock that only moves forward.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const fn forward_now() -> std::result::Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file is runnable only where this account may execute it: a mode that lets only another
    /// account execute it, or nobody, is not, and neither is a directory.
    #[cfg(unix)]
    #[test]
    fn a_file_is_runnable_only_where_this_account_may_execute_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = std::env::temp_dir().join(format!("kr-runnable-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let program = directory.join("program");
        std::fs::write(&program, [0x7f, b'E', b'L', b'F']).expect("a program");
        let mut modes = vec![(0o700, true), (0o755, true), (0o600, false)];
        // The superuser may execute a file any execute bit allows, so only an ordinary account
        // has a mode that lets another account execute a file and not itself.
        if !rustix::process::geteuid().is_root() {
            modes.extend([(0o601, false), (0o610, false)]);
        }
        for (mode, expected) in modes {
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(mode))
                .expect("its mode");
            assert_eq!(runnable(&program), expected, "mode {mode:o}");
        }
        assert!(!runnable(&directory), "a directory is not runnable");
        assert!(!runnable(&directory.join("absent")), "nor is nothing");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A backend's directory is made owner-only and is read back as such, and a name that is taken
    /// is drawn again rather than shared: the directories two backends get are two.
    #[test]
    fn a_backend_directory_is_made_owner_only_and_is_not_shared() {
        let root = std::env::temp_dir().join(format!("kr-backend-{}", kr_ipc::new_uuid()));
        kr_ipc::paths::create_private_directory(&root).expect("a private root");
        let first = new_private_directory(&root, "c").expect("a backend directory");
        let second = new_private_directory(&root, "c").expect("another backend directory");
        assert_ne!(first, second);
        for directory in [&first, &second] {
            assert!(directory.starts_with(&root));
            crate::broker::process::check_private_directory(directory)
                .expect("a directory this host made is owner-only");
        }
        assert!(
            !create_new_private_directory(&first).expect("a taken name is not an error"),
            "a name that is taken is not made again"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn summary() -> kr_protocol::projection::AgentInstanceSummary {
        kr_protocol::projection::AgentInstanceSummary {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            plugin_id: kr_protocol::scalars::Nullable::null(),
            profile_id: kr_protocol::scalars::Nullable::null(),
            mode: IntegrationMode::NativeBridge,
            bypass: kr_protocol::scalars::Nullable::null(),
            started_at: kr_protocol::scalars::TimestampMs::new(1),
            ended_at: kr_protocol::scalars::Nullable::null(),
            refusal: kr_protocol::scalars::Nullable::null(),
        }
    }

    /// KR-REQ-12.07: an instance's end is final and carries the refusal that stood; a refusal found
    /// before the start goes out with the start, a reason goes out once, and nothing goes out after
    /// the end, whichever task finds it.
    #[test]
    fn kr_req_12_07_an_instance_s_end_is_final_and_carries_the_refusal_that_stood() {
        let mut announced = Announced::default();
        assert!(
            announced.refuse("first").is_none(),
            "nothing is announced before the start"
        );
        let started = announced.start(summary()).expect("the start");
        assert_eq!(started.refusal.as_ref().map(String::as_str), Some("first"));
        assert!(
            announced.start(summary()).is_none(),
            "the start goes out once"
        );
        let refused = announced.refuse("second").expect("a new reason");
        assert_eq!(refused.refusal.as_ref().map(String::as_str), Some("second"));
        assert!(
            announced.refuse("second").is_none(),
            "a reason goes out once"
        );
        let ended = announced
            .end(kr_protocol::scalars::TimestampMs::new(9))
            .expect("the end");
        assert!(ended.ended_at.is_present());
        assert_eq!(ended.refusal.as_ref().map(String::as_str), Some("second"));
        assert!(
            announced.refuse("third").is_none(),
            "a refusal found after the end is not announced"
        );
        assert!(
            announced
                .end(kr_protocol::scalars::TimestampMs::new(10))
                .is_none(),
            "the end goes out once"
        );
    }

    /// KR-REQ-12.07: an instance whose end was decided before its start was announced, as a session
    /// that closes before the supervision first runs decides it, is never announced as started.
    #[test]
    fn kr_req_12_07_an_end_before_the_start_announces_nothing() {
        let mut announced = Announced::default();
        assert!(
            announced
                .end(kr_protocol::scalars::TimestampMs::new(9))
                .is_none()
        );
        assert!(
            announced.start(summary()).is_none(),
            "a start after the end is not announced"
        );
    }

    /// A refusal's reason is cut at a character boundary within its bound.
    #[test]
    fn a_long_refusal_is_cut_at_a_character_boundary() {
        let long = "é".repeat(MAX_REFUSAL_BYTES);
        let cut = bounded_refusal(&long);
        assert!(cut.len() <= MAX_REFUSAL_BYTES);
        assert!(cut.len() >= MAX_REFUSAL_BYTES - 1);
        assert_eq!(bounded_refusal("short"), "short");
    }

    fn registration() -> Arc<Registration> {
        Arc::new(Registration::new(
            crate::broker::listener::ListenerAddress::PrivateSocket(PathBuf::from(
                "/run/kr/c/a/a-1.sock",
            )),
            LaunchProfileId::new("lp-1").expect("valid"),
            ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            ProcessStartIdentity::new(
                41,
                kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo,
                900,
            ),
            PathBuf::from("/run/kr/c/a/credential"),
        ))
    }

    /// A bridge that arrives while its launch is being committed waits for the commit and is then
    /// admitted against the registration; one that arrives while a launch is rolled back, or to a
    /// backend no launch holds, is not.
    #[tokio::test]
    async fn a_bridge_waits_for_the_launch_being_committed() {
        let (state, _) = tokio::sync::watch::channel(BackendState::Launching);
        let waiting = {
            let state = state.clone();
            tokio::spawn(async move { committed(&state, std::time::Duration::from_secs(5)).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !waiting.is_finished(),
            "it waits while the launch is being committed"
        );
        state.send_replace(BackendState::Committed(registration()));
        assert!(
            waiting.await.expect("joins").is_some(),
            "and is admitted against the committed launch"
        );

        let (state, _) = tokio::sync::watch::channel(BackendState::Launching);
        let waiting = {
            let state = state.clone();
            tokio::spawn(async move { committed(&state, std::time::Duration::from_secs(5)).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.send_replace(BackendState::Unbound);
        assert!(
            waiting.await.expect("joins").is_none(),
            "a launch rolled back admits no bridge"
        );

        let (state, _) = tokio::sync::watch::channel(BackendState::Unbound);
        assert!(
            committed(&state, std::time::Duration::from_secs(5))
                .await
                .is_none(),
            "a backend no launch holds admits no bridge"
        );
    }

    fn words(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn the_added_flags_are_found_where_they_stand() {
        let added = words(&["--flag", "value"]);
        assert_eq!(
            added_run(
                &words(&["claude", "--", "prompt"]),
                &words(&["claude", "--flag", "value", "--", "prompt"]),
                &added
            ),
            Some(1)
        );
        assert_eq!(
            added_run(
                &words(&["claude", "-p"]),
                &words(&["claude", "-p", "--flag", "value"]),
                &added
            ),
            Some(2)
        );
        assert_eq!(
            added_run(&words(&["claude"]), &words(&["claude"]), &[]),
            Some(0),
            "nothing added"
        );
        assert_eq!(
            added_run(
                &words(&["claude", "-p"]),
                &words(&["claude", "--flag", "-p", "value"]),
                &added
            ),
            None,
            "not one run"
        );
        assert_eq!(
            added_run(
                &words(&["claude", "-p"]),
                &words(&["claude", "-q", "--flag", "value"]),
                &added
            ),
            None,
            "not the typed vector around it"
        );
        assert_eq!(registration_name(3, 2), "registration.3.2");
    }

    /// A retirement waits for a confirmation being written, and withholds one not yet begun; a
    /// retired backend is not committed.
    #[test]
    fn retirement_and_the_confirmation_exclude_each_other() {
        let lifecycle = Arc::new(Lifecycle::new(BackendState::Launching));
        assert!(lifecycle.commit(registration(), || {}));
        let (writing, written) = std::sync::mpsc::channel();
        let (finish, finished) = std::sync::mpsc::channel::<()>();
        let confirming = {
            let lifecycle = Arc::clone(&lifecycle);
            std::thread::spawn(move || {
                lifecycle.confirm(|| {
                    let _ = writing.send(());
                    let _ = finished.recv();
                    "written"
                })
            })
        };
        written.recv().expect("the confirmation is being written");
        let retiring = {
            let lifecycle = Arc::clone(&lifecycle);
            std::thread::spawn(move || lifecycle.retire())
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !retiring.is_finished(),
            "the retirement waits for the confirmation being written"
        );
        let _ = finish.send(());
        assert_eq!(confirming.join().expect("joins"), Some("written"));
        retiring.join().expect("joins");
        assert_eq!(
            lifecycle.confirm(|| "written"),
            None,
            "a retired backend confirms nothing"
        );
        assert!(
            !lifecycle.commit(registration(), || panic!(
                "nothing is run for a retired backend"
            )),
            "and commits nothing"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_launcher_says_it_is_going_in_one_frame() {
        assert!(is_going(br#"{"kr_launch":{"going":true}}"#));
        assert!(!is_going(br#"{"kr_launch":{"going":false}}"#));
        assert!(!is_going(br#"{"kr_launch":{}}"#));
        assert!(!is_going(b"going"));
    }

    #[test]
    fn a_launcher_names_the_program_it_created_and_the_directory_it_works_in() {
        assert_eq!(
            going_of(br#"{"kr_launch":{"going":true,"program":4242,"directory":"C:\\work"}}"#),
            Ok(Going::Program {
                pid: 4242,
                directory: Some("C:\\work".to_owned())
            })
        );
        assert_eq!(
            going_of(br#"{"kr_launch":{"going":true,"program":7}}"#),
            Ok(Going::Program {
                pid: 7,
                directory: None
            }),
            "a directory the launcher could not read is not a refusal to go"
        );
        for refused in [
            &br#"{"kr_launch":{"going":true}}"#[..],
            br#"{"kr_launch":{"going":true,"program":"4"}}"#,
            br#"{"kr_launch":{"going":true,"program":99999999999}}"#,
            br#"{"kr_launch":{}}"#,
            br#"{"other":{"going":true}}"#,
            b"going",
        ] {
            assert!(going_of(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_launcher_that_declines_says_why_and_a_long_reason_is_cut() {
        assert_eq!(
            going_of(br#"{"kr_launch":{"going":false,"declined":"the job limits the desktop"}}"#),
            Ok(Going::Declined("the job limits the desktop".to_owned()))
        );
        let long = "x".repeat(2_000);
        let frame = format!(r#"{{"kr_launch":{{"going":false,"declined":"{long}"}}}}"#);
        let Ok(Going::Declined(why)) = going_of(frame.as_bytes()) else {
            panic!("a decline");
        };
        assert!(why.len() <= MAX_REFUSAL_BYTES, "{}", why.len());
        assert!(matches!(
            going_of(br#"{"kr_launch":{"going":false}}"#),
            Ok(Going::Declined(_))
        ));
    }

    #[test]
    fn a_launcher_says_it_resumed_the_program_in_one_frame() {
        assert!(is_resumed(br#"{"kr_launch":{"resumed":true}}"#));
        assert!(!is_resumed(br#"{"kr_launch":{"resumed":false}}"#));
        assert!(!is_resumed(br#"{"kr_launch":{"going":true}}"#));
        assert!(!is_resumed(b"resumed"));
    }
}
