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
//! 4. **Commit**, when the launcher says it is going: the backend is committed and says so, and only
//!    then does the launcher exec the program in place, keeping its process identity, so the
//!    registration names the program before the program runs.
//!
//! A launcher that is refused, runs out of time or cannot reach the endpoint runs the invocation as
//! typed, without the flags and without the variable. The registration's file name says where the
//! added flags stand in the vector, so what was typed is known from the variable alone, whatever has
//! become of the backend.
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
use std::sync::{Arc, Mutex};

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
pub const GOING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long an admission waits for the executable's identity to be read.
///
/// The launcher gives the whole exchange two seconds; this leaves it room to hear the answer.
pub const IDENTITY_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

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
/// confirmation; or after the confirmation, when the program has been told and started, like a
/// session that closes while its program runs.
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
        matches!(*self.state.borrow(), BackendState::Committed(_)).then(confirm)
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
    lifecycle: Lifecycle,
    identity: tokio::sync::watch::Receiver<Option<std::result::Result<ExecutableIdentity, String>>>,
    /// Why a bridge of this instance was refused for the image its process runs, once one was:
    /// every later bridge is refused too.
    image_refused: Mutex<Option<String>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "testing")]
    confirm_pause: Arc<Mutex<Option<ConfirmPause>>>,
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
    runtime_dir: PathBuf,
    /// The session's own root, made fresh at the first establish and removed at close.
    root: Mutex<Option<PathBuf>>,
    sources: Arc<ConnectorSources>,
    launcher: Option<PathBuf>,
    handle: tokio::runtime::Handle,
    publishes_credential_file: bool,
    backends: Mutex<Vec<Arc<Backend>>>,
    hashed: Arc<HashedFiles>,
    /// Where the next committed launch stops before the launcher is told, for this host's own tests.
    #[cfg(feature = "testing")]
    confirm_pause: Arc<Mutex<Option<ConfirmPause>>>,
}

/// The two ends of one armed pause: what says the launch arrived there, and what lets it go on.
#[cfg(feature = "testing")]
type ConfirmPause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

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
            #[cfg(feature = "testing")]
            confirm_pause: Arc::new(Mutex::new(None)),
        }
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
            .create(request, invocation, added_at, connector)
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

    /// Retires every backend, because the session is closing, and removes the session's root.
    ///
    /// Nothing a launch is running is ended here: the session's own closure owns the program. A
    /// launcher that looks now finds nothing to present to, and runs what was typed.
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
        let root = self
            .root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(root) = root {
            let _ = std::fs::remove_dir_all(root);
        }
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
    ) -> Result<Arc<Backend>> {
        let _entered = self.handle.enter();
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
        });
        kr_ipc::paths::write_owner_only_file(
            &directory.join(LAUNCH_RECORD_FILE),
            record.to_string().as_bytes(),
        )
        .map_err(|error| {
            BrokerError::ledger(format!("could not write the launch record: {error}"))
        })?;
        let (identity_sender, identity) = tokio::sync::watch::channel(None);
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
            lifecycle: Lifecycle::new(BackendState::Unbound),
            identity,
            image_refused: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            #[cfg(feature = "testing")]
            confirm_pause: Arc::clone(&self.confirm_pause),
        });
        let reading = {
            let path = PathBuf::from(&backend.invocation.executable);
            let hashed = Arc::clone(&self.hashed);
            let connector = Arc::clone(&backend.connector);
            self.handle.spawn_blocking(move || {
                let read = crate::broker::image::read_identity(&path, &hashed).map(|hashed| {
                    let version = connector
                        .qualified_version(&hashed.digest)
                        .map(str::to_owned);
                    ExecutableIdentity { hashed, version }
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
        self.lifecycle.retire();
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
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
            if let Err(_refused) = verify(&backend, &registration) {
                return;
            }
            let Ok(admitted) = authenticated.admit().await else {
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
        crate::broker::image::verify_image(&registration.expected_process, &identity)
    });
    if let Err(why) = &verified {
        *refused = Some(why.clone());
    }
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
    // The commit, under the lifecycle lock: the state, the guard and the supervision together, or,
    // for a backend retired meanwhile, none of them, and the guard gives back.
    let mut guard = Some(guard);
    let committed = backend.lifecycle.commit(Arc::new(registration), || {
        if let Some(guard) = guard.take() {
            guard.commit();
        }
        let supervising = tokio::spawn(supervise(Arc::clone(backend), Arc::clone(broker), process));
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_launcher_says_it_is_going_in_one_frame() {
        assert!(is_going(br#"{"kr_launch":{"going":true}}"#));
        assert!(!is_going(br#"{"kr_launch":{"going":false}}"#));
        assert!(!is_going(br#"{"kr_launch":{}}"#));
        assert!(!is_going(b"going"));
    }
}
