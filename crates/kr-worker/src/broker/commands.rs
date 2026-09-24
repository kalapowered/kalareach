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
//!    which flags the integration added. Nothing is reserved and no registration exists yet. The
//!    answer names the registration's path and the installation's launcher.
//! 2. **Present**: the shell runs the launcher in the child it forked for the invocation, and the
//!    launcher presents itself, with the credential, the executable and the argument vector.
//! 3. **Admit**: the process the kernel names is the root shell's own child, started after the
//!    establish, with the credential, running the file this backend hashed with the vector it
//!    answered. The launch profile is recorded, the instance registered by its reservation, and the
//!    registration published whole, naming that process. The launcher is told it is admitted.
//! 4. **Commit**, when the launcher says it is going: it execs the program in place, keeping its
//!    process identity, so the registration names the program before the program runs.
//!
//! A launcher that is refused, runs out of time or cannot reach the endpoint runs the invocation as
//! typed, without the flags and without the variable: the launch record tells it which flags were
//! added, and the record outlives the backend for that reason.
//!
//! # What is served
//!
//! One accept loop per backend, one task per accepted connection, at most
//! [`MAX_CONCURRENT_ADMISSIONS`] at once. A bridge that connects while a launch is being committed
//! waits for the commit; one that connects to a backend no launch holds is refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, EnvironmentId, LaunchProfileId, SessionId};
use kr_protocol::root::{CommandBackend, CwdRevision, PromptGeneration};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_protocol::session::{CommandIntegration, EnvironmentVariable};

use crate::broker::Broker;
use crate::broker::attach::{NativeGateway, NativeLaunch, Opening, PresentedLaunch};
use crate::broker::bridge::{BridgeStream, BridgeSurface};
use crate::broker::connectors::{ConnectorSources, InstalledConnector};
use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::listener::Registration;
use crate::broker::process::{Credential, ManagedProcess};
use crate::broker::profiles::ForegroundMark;

/// The most admissions one backend runs at once.
///
/// A connection beyond them is closed unread: its hook answers `{}` and its report is lost, or its
/// channel fails its handshake, which is what a worker that does not answer already means.
pub const MAX_CONCURRENT_ADMISSIONS: usize = 16;

/// How long a launch the backend admitted has to say it is going.
///
/// The launcher says so as soon as it reads its admission, so anything slower is a launcher that
/// is not going to run the program with the integration.
pub const GOING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long an admission waits for the executable's identity to be read.
///
/// The launcher gives the whole exchange two seconds; this leaves it room to hear the answer.
pub const IDENTITY_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// The file a backend's launch record is published as.
pub const LAUNCH_RECORD_FILE: &str = "launch";

/// How many times the identity of a file that changed while it was read is read again.
const IDENTITY_ATTEMPTS: usize = 3;

/// How often the committed program is looked at while it runs.
const SUPERVISION_POLL: std::time::Duration = crate::broker::attach::TERMINAL_POLL;

/// A file's identity, as the kernel reports it for one opened file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileIdentity {
    /// The device it is on.
    pub device: u64,
    /// Its inode.
    pub inode: u64,
    /// Its length in bytes.
    pub size: u64,
    /// Its last modification, in nanoseconds.
    pub modified_ns: i128,
    /// Its last status change, in nanoseconds.
    pub changed_ns: i128,
}

impl FileIdentity {
    /// Reads the identity of one opened file.
    #[cfg(unix)]
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }

    /// A platform without inodes names no identity this backend could hold a file to.
    #[cfg(not(unix))]
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: 0,
            inode: 0,
            size: metadata.len(),
            modified_ns: 0,
            changed_ns: 0,
        }
    }

    /// Returns true when a file the kernel reports is this one: the same device, inode, length and
    /// modification. The change time is left out, because the kernel's record of a mapped file does
    /// not carry it.
    #[must_use]
    pub fn is_mapped_as(&self, device: u64, inode: u64, size: u64, modified_s: i64) -> bool {
        self.device == device
            && self.inode == inode
            && self.size == size
            && self.modified_ns.div_euclid(1_000_000_000) == i128::from(modified_s)
    }
}

/// What the backend read about the executable an invocation runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    /// The file object that was hashed.
    pub file: FileIdentity,
    /// The SHA-256 digest of its bytes.
    pub digest: Digest256,
    /// The version a signed qualification record names for that digest, where one does.
    pub version: Option<String>,
}

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
    profile_id: LaunchProfileId,
    gateway: Arc<NativeGateway>,
    credential: Credential,
    root_shell: ProcessStartIdentity,
    established_at: Option<u64>,
    connector: Arc<InstalledConnector>,
    state: tokio::sync::watch::Sender<BackendState>,
    identity: tokio::sync::watch::Receiver<Option<std::result::Result<ExecutableIdentity, String>>>,
    image: Mutex<Option<std::result::Result<(), String>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "testing")]
    commit_pause: Arc<Mutex<Option<CommitPause>>>,
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
    /// The flags the integration added.
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
    root: PathBuf,
    sources: Arc<ConnectorSources>,
    launcher: Option<PathBuf>,
    handle: tokio::runtime::Handle,
    publishes_credential_file: bool,
    backends: Mutex<Vec<Arc<Backend>>>,
    digests: Arc<Mutex<BTreeMap<FileIdentity, Digest256>>>,
    /// Where the next admitted launch stops before it commits, for this host's own tests.
    #[cfg(feature = "testing")]
    commit_pause: Arc<Mutex<Option<CommitPause>>>,
}

/// The two ends of one armed commit pause: what says the launch arrived, and what lets it go on.
#[cfg(feature = "testing")]
type CommitPause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

impl std::fmt::Debug for CommandBackends {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandBackends")
            .field("root", &self.root)
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
    /// The owner-only directory each backend's own directory is made in.
    pub root: PathBuf,
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
        Self {
            broker,
            session_id: config.session_id,
            environment_id: config.environment_id,
            os_user: config.os_user,
            root: config.root,
            sources: config.sources,
            launcher: config.launcher,
            handle,
            publishes_credential_file: ManagedProcess::publishes_credential_file(),
            backends: Mutex::new(Vec::new()),
            digests: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(feature = "testing")]
            commit_pause: Arc::new(Mutex::new(None)),
        }
    }

    /// Stops the next launch that says it is going before it is committed, for this host's own
    /// tests: a bridge that connects then meets a launch still being committed.
    ///
    /// Returns the end that says the launch has arrived there and the end that lets it go on. It is
    /// compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_commit(
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
        let connector = self
            .sources
            .for_command(command)
            .ok_or_else(|| format!("no installed connector integrates {command:?}"))?;
        if connector.integration().flags != request.integration.flags {
            return Err(format!(
                "the flags this session integrates {command:?} with are not the ones its installed \
                 connector declares"
            ));
        }
        let launcher = self.launcher()?;
        check_executable(request.executable)?;

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
        // A resolve for a later line says every earlier line is over, so an earlier backend no
        // launch took is retired.
        let (earlier, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut *backends)
            .into_iter()
            .partition(|backend| {
                backend.prompt_generation < request.prompt_generation
                    && (backend.is_unbound() || backend.is_retired())
            });
        *backends = kept;
        for backend in earlier {
            backend.retire();
        }
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
            .create(request, invocation, connector)
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
        let (ended, kept): (Vec<_>, Vec<_>) =
            std::mem::take(&mut *backends)
                .into_iter()
                .partition(|backend| {
                    backend.prompt_generation <= prompt_generation
                        && (backend.is_unbound() || backend.is_retired())
                });
        *backends = kept;
        for backend in ended {
            backend.retire();
        }
    }

    /// Retires every backend, because the session is closing, and removes their directory.
    ///
    /// Nothing a launch is running is ended here: the session's own closure owns the program. The
    /// launch records go with the directory: a launcher that looks now finds none and runs its
    /// program without the integration's variable, in a session that is going away.
    pub fn close(&self) {
        let backends = std::mem::take(
            &mut *self
                .backends
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for backend in backends {
            backend.retire();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }

    /// Returns the state of the backend established for one instance, where one is.
    #[must_use]
    pub fn state_of(&self, application_instance_id: ApplicationInstanceId) -> Option<BackendState> {
        self.backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|backend| backend.application_instance_id == application_instance_id)
            .map(|backend| backend.state.borrow().clone())
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
        let metadata = std::fs::metadata(&launcher).map_err(|error| {
            format!(
                "the launcher {} cannot be read: {error}",
                launcher.display()
            )
        })?;
        if !metadata.is_file() || !is_executable(&metadata) {
            return Err(format!(
                "the launcher {} is not an executable file",
                launcher.display()
            ));
        }
        Ok(launcher)
    }

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
                value: backend
                    .directory
                    .join(crate::broker::attach::REGISTRATION_FILE)
                    .display()
                    .to_string(),
            }],
            launcher: launcher.display().to_string(),
        }
    }

    /// Makes one backend: its directory, endpoint, credential, launch record and tasks.
    fn create(
        &self,
        request: &EstablishRequest<'_>,
        invocation: Invocation,
        connector: Arc<InstalledConnector>,
    ) -> Result<Arc<Backend>> {
        let _entered = self.handle.enter();
        let application_instance_id =
            ApplicationInstanceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()));
        make_private_directory(&self.root)?;
        // A socket path has a small fixed bound, so the backend's directory has a short name of its
        // own rather than the instance's identifier; it is fresh, and taken new.
        let directory = new_private_directory(&self.root)?;
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
        };
        let mut gateway = NativeGateway::bind(Arc::clone(&self.broker), &directory, launch)?;
        if let Some(installed) = connector.installed_bridge() {
            gateway = gateway.with_bridge(installed)?;
        }
        let gateway = Arc::new(gateway);
        let established_at = forward_now();
        let credential = Credential::generate()?;
        let credential_path = directory.join(crate::broker::attach::CREDENTIAL_FILE);
        credential.write_file(&credential_path)?;
        let record = serde_json::json!({
            "endpoint": gateway.address().for_diagnostics(),
            "credential": credential_path.display().to_string(),
            "added": invocation.added,
        });
        kr_ipc::paths::write_owner_only_file(
            &directory.join(LAUNCH_RECORD_FILE),
            record.to_string().as_bytes(),
        )
        .map_err(|error| {
            BrokerError::ledger(format!("could not write the launch record: {error}"))
        })?;
        let (identity_sender, identity) = tokio::sync::watch::channel(None);
        let (state, _) = tokio::sync::watch::channel(BackendState::Unbound);
        let backend = Arc::new(Backend {
            application_instance_id,
            prompt_generation: request.prompt_generation,
            invocation,
            directory,
            profile_id,
            gateway,
            credential,
            root_shell: request.root_shell.clone(),
            established_at,
            connector,
            state,
            identity,
            image: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            #[cfg(feature = "testing")]
            commit_pause: Arc::clone(&self.commit_pause),
        });
        let reading = {
            let path = PathBuf::from(&backend.invocation.executable);
            let digests = Arc::clone(&self.digests);
            let connector = Arc::clone(&backend.connector);
            self.handle.spawn_blocking(move || {
                let read = read_identity(&path, &digests).map(|(file, digest)| {
                    let version = connector.qualified_version(&digest).map(str::to_owned);
                    ExecutableIdentity {
                        file,
                        digest,
                        version,
                    }
                });
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
    fn is_unbound(&self) -> bool {
        matches!(*self.state.borrow(), BackendState::Unbound)
    }

    fn is_retired(&self) -> bool {
        matches!(*self.state.borrow(), BackendState::Retired)
    }

    /// Ends this backend: no more connections, no endpoint, no credential and no registration.
    ///
    /// The launch record stays until the session's directory goes, so a launcher that looks later
    /// still finds the flags it has to leave out.
    fn retire(&self) {
        self.state.send_replace(BackendState::Retired);
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
        let _ = std::fs::remove_file(self.directory.join(crate::broker::attach::CREDENTIAL_FILE));
        let _ = std::fs::remove_file(
            self.directory
                .join(crate::broker::attach::REGISTRATION_FILE),
        );
        if let crate::broker::listener::ListenerAddress::PrivateSocket(socket) =
            self.gateway.address()
        {
            let _ = std::fs::remove_file(socket);
        }
    }

    /// Moves this backend out of a launch in progress, and nowhere else: a backend retired while
    /// a launch was being admitted stays retired.
    fn settle_launch(&self, next: BackendState) -> bool {
        self.state.send_if_modified(|state| {
            if matches!(state, BackendState::Launching) {
                *state = next;
                true
            } else {
                false
            }
        })
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
                if matches!(*backend.state.borrow(), BackendState::Retired) {
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
            admit(backend, broker, environment_id, accepted).await;
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
            let Some(registration) =
                committed(&backend.state, crate::broker::attach::HELLO_DEADLINE).await
            else {
                return;
            };
            if let Err(_refused) = verify_once(&backend, &registration) {
                return;
            }
            let Ok(admitted) = backend.gateway.admit_bridge(pending, &registration).await else {
                return;
            };
            match admitted.surface {
                BridgeSurface::Hook => {
                    let _ = backend.gateway.observe_hook(admitted).await;
                }
                BridgeSurface::Channel => {
                    // The Channels consumer serves an admitted channel; until it is given one, the
                    // channel is closed and Claude Code shows the server as failed.
                    let mut stream = admitted.stream;
                    stream.close().await;
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

/// Checks, once for the instance, that the committed process runs the file this backend hashed.
fn verify_once(backend: &Backend, registration: &Registration) -> std::result::Result<(), String> {
    let mut image = backend
        .image
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(verified) = image.as_ref() {
        return verified.clone();
    }
    let identity = backend
        .identity
        .borrow()
        .clone()
        .unwrap_or_else(|| Err("the executable's identity was never read".to_owned()));
    let verified =
        identity.and_then(|identity| verify_image(&registration.expected_process, &identity.file));
    *image = Some(verified.clone());
    verified
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
        mut stream,
    } = presented;
    // The kernel's account of the peer, first: the owner, and the process it names, which is the one
    // the launcher says it is.
    if !peer.is_owner() {
        return Err(BrokerError::denied(
            "this connection is not the operating-system user who owns the session",
        ));
    }
    let Some(process) = peer
        .process()
        .filter(|_| peer.from_operating_system())
        .cloned()
    else {
        return Err(BrokerError::denied(
            "the kernel named no process for this connection, and a launch is admitted only by \
             the process the kernel names",
        ));
    };
    if process.pid.get() != launch.pid || process.start_value.get() != launch.start {
        return Err(BrokerError::denied(
            "this connection says it is another process than the one the kernel named",
        ));
    }
    // The root shell's own child: the invocation's fork, and nothing further down.
    let parent = crate::questions::binding::parent_of(&process);
    if !parent.is_some_and(|parent| parent.matches(&backend.root_shell)) {
        return Err(BrokerError::denied(
            "this process was not started by the session's root shell",
        ));
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
    let presented_file = std::fs::metadata(&launch.executable)
        .map(|metadata| FileIdentity::of(&metadata))
        .map_err(|error| {
            BrokerError::denied(format!("the executable presented cannot be read: {error}"))
        })?;
    if launch.executable != backend.invocation.executable || presented_file != identity.file {
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
    let claimed = backend.state.send_if_modified(|state| {
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
    let admitted = admit_claimed(
        backend,
        broker,
        environment_id,
        &process,
        &identity,
        &mut stream,
    )
    .await;
    let registered = match admitted {
        Ok(registered) => registered,
        Err(error) => {
            backend.settle_launch(BackendState::Unbound);
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
        let _ = std::fs::remove_file(
            backend
                .directory
                .join(crate::broker::attach::REGISTRATION_FILE),
        );
        drop(guard);
        backend.settle_launch(BackendState::Unbound);
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
    if !backend.settle_launch(BackendState::Committed(Arc::new(registration))) {
        // Retired while the launch was admitted: the session is closing, and nothing is kept.
        drop(guard);
        return Err(BrokerError::denied("this backend was retired"));
    }
    guard.commit();
    let supervising = tokio::spawn(supervise(Arc::clone(backend), Arc::clone(broker), process));
    backend
        .tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(supervising);
    Ok(())
}

/// Records the launch, registers its instance by its reservation, publishes the registration and
/// answers `admitted`, all for a backend this admission claimed.
async fn admit_claimed<'a>(
    backend: &Backend,
    broker: &'a Broker,
    environment_id: EnvironmentId,
    process: &ProcessStartIdentity,
    identity: &ExecutableIdentity,
    stream: &mut BridgeStream,
) -> Result<(crate::broker::RegisteredLaunch<'a>, Registration)> {
    let generation = backend.prompt_generation.get();
    let profile = LaunchProfile {
        profile_id: backend.profile_id.clone(),
        environment_id,
        binary: BinaryIdentity {
            resolved_path: backend.invocation.executable.clone(),
            digest: identity.digest,
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
    };
    let idle = ForegroundMark::idle(generation);
    let intent = broker.prepare_launch(profile, idle.clone(), None)?;
    let reservation = broker.execute_launch(&intent, &idle, backend.application_instance_id)?;
    let managed = ManagedProcess::new(
        backend.application_instance_id,
        process.clone(),
        crate::broker::process::TransportHandle {
            transport: crate::broker::process::BrokerTransport::PrivateSocket,
            application_instance_id: backend.application_instance_id,
            executable_digest: identity.digest,
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
    let registration_path = backend
        .directory
        .join(crate::broker::attach::REGISTRATION_FILE);
    kr_ipc::paths::write_owner_only_file(&registration_path, published.as_bytes()).map_err(
        |error| BrokerError::ledger(format!("could not write the registration: {error}")),
    )?;
    if let Err(error) = stream.write_frame(&admission()).await {
        let _ = std::fs::remove_file(&registration_path);
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

/// Returns true for the frame a launcher writes when it is about to exec the program.
fn is_going(frame: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(frame).is_ok_and(|value| {
        value
            .get("kr_launch")
            .and_then(|launch| launch.get("going"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    })
}

/// Watches the committed program for as long as it runs, and ends the instance when it exits.
async fn supervise(backend: Arc<Backend>, broker: Arc<Broker>, process: ProcessStartIdentity) {
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
            return;
        }
        tokio::time::sleep(SUPERVISION_POLL).await;
    }
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

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    true
}

/// Makes a directory owner-only, creating it where it is not there.
fn make_private_directory(directory: &Path) -> Result<()> {
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(BrokerError::ledger(format!(
                "could not make {}: {error}",
                directory.display()
            )));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                BrokerError::ledger(format!(
                    "could not make {} owner-only: {error}",
                    directory.display()
                ))
            },
        )?;
    }
    crate::broker::process::check_private_directory(directory)
}

/// Makes a new owner-only directory with a short fresh name inside `root`.
fn new_private_directory(root: &Path) -> Result<PathBuf> {
    for _ in 0..8 {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let directory = root.join(name);
        match std::fs::create_dir(&directory) {
            Ok(()) => {
                make_private_directory(&directory)?;
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(BrokerError::ledger(format!(
                    "could not make a backend directory in {}: {error}",
                    root.display()
                )));
            }
        }
    }
    Err(BrokerError::ledger(format!(
        "no fresh backend directory could be made in {}",
        root.display()
    )))
}

/// Reads one executable's identity and digest through one opened file.
///
/// The identity is read before and after the bytes are hashed through the same descriptor, so the
/// digest belongs to the file object the identity names; a file that changed meanwhile is read
/// again, and one that keeps changing is not read at all. A script is refused: the image its process
/// runs is its interpreter, which nothing here could tie to it.
fn read_identity(
    path: &Path,
    digests: &Mutex<BTreeMap<FileIdentity, Digest256>>,
) -> std::result::Result<(FileIdentity, Digest256), String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    for _ in 0..IDENTITY_ATTEMPTS {
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let before = file
            .metadata()
            .map(|metadata| FileIdentity::of(&metadata))
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let cached = digests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&before)
            .copied();
        if let Some(digest) = cached {
            return Ok((before, digest));
        }
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0_u8; 1 << 20];
        let mut first = true;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
            if read == 0 {
                break;
            }
            let chunk = buffer.get(..read).unwrap_or_default();
            if first && chunk.starts_with(b"#!") {
                return Err(format!(
                    "{} is a script, and the program it runs is its interpreter",
                    path.display()
                ));
            }
            first = false;
            hasher.update(chunk);
        }
        let after = file
            .metadata()
            .map(|metadata| FileIdentity::of(&metadata))
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        if before != after {
            continue;
        }
        let digest = Digest256::from_bytes(hasher.finalize().into());
        digests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(before, digest);
        return Ok((before, digest));
    }
    Err(format!(
        "{} kept changing while it was read",
        path.display()
    ))
}

/// Refuses a process that started before `established_at`, on the clock the kernel records starts
/// on, where the platform keeps such a record.
fn started_after(process: &ProcessStartIdentity, established_at: Option<u64>) -> Result<()> {
    let started = crate::questions::binding::monotonic_start(process).map_err(|why| {
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
fn forward_now() -> Option<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let ticks = rustix::param::clock_ticks_per_second();
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanoseconds = u64::try_from(now.tv_nsec).ok()?;
    Some(
        seconds
            .saturating_mul(ticks)
            .saturating_add(nanoseconds.saturating_mul(ticks) / 1_000_000_000),
    )
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
fn forward_now() -> Option<u64> {
    // SAFETY: the function takes no argument and reads a counter; it has no precondition.
    Some(unsafe { libc::mach_absolute_time() })
}

/// This platform records no start on a clock that only moves forward.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn forward_now() -> Option<u64> {
    None
}

/// Checks, from the kernel's own record, that a process runs the file object this backend hashed.
#[cfg(target_os = "linux")]
fn verify_image(
    process: &ProcessStartIdentity,
    file: &FileIdentity,
) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let link = format!("/proc/{}/exe", process.pid.get());
    let executed = std::fs::metadata(&link).map_err(|error| {
        format!(
            "the image of process {} cannot be read: {error}",
            process.pid
        )
    })?;
    if !matches!(
        kr_ipc::identity::process_state(process),
        kr_ipc::identity::ProcessState::Running
    ) {
        return Err(format!("process {} is not the one registered", process.pid));
    }
    if file.is_mapped_as(
        executed.dev(),
        executed.ino(),
        executed.size(),
        executed.mtime(),
    ) {
        Ok(())
    } else {
        Err(format!(
            "process {} runs another file than the one its launch presented",
            process.pid
        ))
    }
}

/// Checks, from the kernel's own record, that a process runs the file object this backend hashed.
///
/// The kernel's record of the process's mapped regions names each region's file by its vnode. The
/// executed image is always mapped, and nothing of the launcher survives its exec, so the check
/// holds when a mapped region's file is the one that was hashed.
#[cfg(target_os = "macos")]
fn verify_image(
    process: &ProcessStartIdentity,
    file: &FileIdentity,
) -> std::result::Result<(), String> {
    let pid = i32::try_from(process.pid.get())
        .map_err(|_| format!("{} is not a process identifier", process.pid))?;
    let mut address = 0_u64;
    for _ in 0..MAX_REGIONS {
        let Ok(region) =
            libproc::libproc::proc_pid::pidinfo::<regions::RegionWithPathInfo>(pid, address)
        else {
            break;
        };
        let stat = &region.prp_vip.vip_vi.vi_stat;
        if stat.vst_ino != 0
            && file.is_mapped_as(
                u64::from(stat.vst_dev),
                stat.vst_ino,
                u64::try_from(stat.vst_size).unwrap_or(u64::MAX),
                stat.vst_mtime,
            )
        {
            return if matches!(
                kr_ipc::identity::process_state(process),
                kr_ipc::identity::ProcessState::Running
            ) {
                Ok(())
            } else {
                Err(format!("process {} is not the one registered", process.pid))
            };
        }
        let next = region
            .prp_prinfo
            .pri_address
            .saturating_add(region.prp_prinfo.pri_size);
        if next <= address {
            break;
        }
        address = next;
    }
    Err(format!(
        "process {} maps no file that is the one its launch presented",
        process.pid
    ))
}

/// The most regions one image check reads.
#[cfg(target_os = "macos")]
const MAX_REGIONS: usize = 1 << 16;

/// No record of a process's image is read on this platform, so nothing here is verified.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn verify_image(
    process: &ProcessStartIdentity,
    _file: &FileIdentity,
) -> std::result::Result<(), String> {
    Err(format!(
        "this platform keeps no record of the image process {} runs",
        process.pid
    ))
}

/// The kernel's record of one mapped region, as `proc_pidinfo` answers `PROC_PIDREGIONPATHINFO`.
#[cfg(target_os = "macos")]
mod regions {
    use libproc::libproc::net_info::VInfoStat;
    use libproc::libproc::proc_pid::{PIDInfo, PidInfoFlavor};

    /// `struct proc_regioninfo`.
    #[repr(C)]
    pub struct RegionInfo {
        pub pri_protection: u32,
        pub pri_max_protection: u32,
        pub pri_inheritance: u32,
        pub pri_flags: u32,
        pub pri_offset: u64,
        pub pri_behavior: u32,
        pub pri_user_wired_count: u32,
        pub pri_user_tag: u32,
        pub pri_pages_resident: u32,
        pub pri_pages_shared_now_private: u32,
        pub pri_pages_swapped_out: u32,
        pub pri_pages_dirtied: u32,
        pub pri_ref_count: u32,
        pub pri_shadow_depth: u32,
        pub pri_share_mode: u32,
        pub pri_private_pages_resident: u32,
        pub pri_shared_pages_resident: u32,
        pub pri_obj_id: u32,
        pub pri_depth: u32,
        pub pri_address: u64,
        pub pri_size: u64,
    }

    /// `struct vnode_info`.
    #[repr(C)]
    pub struct VnodeInfo {
        pub vi_stat: VInfoStat,
        pub vi_type: i32,
        pub vi_pad: i32,
        pub vi_fsid: [i32; 2],
    }

    /// `struct vnode_info_path`.
    #[repr(C)]
    pub struct VnodeInfoPath {
        pub vip_vi: VnodeInfo,
        pub vip_path: [u8; 1024],
    }

    /// `struct proc_regionwithpathinfo`.
    #[repr(C)]
    pub struct RegionWithPathInfo {
        pub prp_prinfo: RegionInfo,
        pub prp_vip: VnodeInfoPath,
    }

    impl PIDInfo for RegionWithPathInfo {
        fn flavor() -> PidInfoFlavor {
            PidInfoFlavor::RegionPathInfo
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's record of this test's own regions names this test's own executable, which is
    /// what pins the record's layout on the platform that has it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_process_s_own_image_is_the_file_it_was_started_from() {
        let exe = std::env::current_exe().expect("this test's executable");
        let digests = Mutex::new(BTreeMap::new());
        let (file, _digest) = read_identity(&exe, &digests).expect("its identity is read");
        let me = kr_ipc::identity::current_process_start_identity().expect("this process");
        verify_image(&me, &file).expect("this process runs its own executable");
        let other = FileIdentity {
            inode: file.inode.wrapping_add(1),
            ..file
        };
        assert!(
            verify_image(&me, &other).is_err(),
            "and not a file it was not started from"
        );
    }

    #[test]
    fn a_script_is_not_an_executable_this_backend_holds() {
        let directory = std::env::temp_dir().join(format!("kr-script-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let script = directory.join("claude");
        std::fs::write(&script, b"#!/bin/sh\nexec true\n").expect("a script");
        let digests = Mutex::new(BTreeMap::new());
        let refused = read_identity(&script, &digests).expect_err("a script is refused");
        assert!(refused.contains("script"), "{refused}");
        let _ = std::fs::remove_dir_all(&directory);
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

    #[test]
    fn a_launcher_says_it_is_going_in_one_frame() {
        assert!(is_going(br#"{"kr_launch":{"going":true}}"#));
        assert!(!is_going(br#"{"kr_launch":{"going":false}}"#));
        assert!(!is_going(br#"{"kr_launch":{}}"#));
        assert!(!is_going(b"going"));
    }
}
