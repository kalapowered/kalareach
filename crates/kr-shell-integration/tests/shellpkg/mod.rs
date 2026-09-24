//! Drives a built managed shell package through the contract, in a real pseudo-terminal.
//!
//! Each test here is the worker's side of one session: it creates the owner-only endpoint, starts
//! the packaged shell under a pseudo-terminal with the two bootstrap variables, answers the
//! handshake with `decide_handshake`, and then asks the reader the three questions the contract
//! puts to it. The expectations come from the committed scenarios under `fixtures/shell-bridge/`,
//! so a package and the worker are checked against one corpus rather than against each other.
//!
//! Nothing a launched process touches is inside the workspace: the shell's executable is the
//! installed package, and its home directory, its runtime directory and its endpoint are all on
//! the internal disk.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch, RequestId, SessionId};
use kr_protocol::root::{
    DETACH_HINT, EditorBufferRevision, EditorFence, FenceId, FencePublication, FenceState,
    PromptGeneration, ReaderRevision, RootCommandAcceptedResult, RootEditorEnterParams,
    RootEditorEnterResult, RootEditorLeaveResult, RootEofDetachResult, WithheldReason,
};
use kr_protocol::scalars::{Bytes, DurationMs, Nullable, U64, Uuid};
use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::fixtures::{Scenario, replay, scenarios};
use kr_shell_integration::contract::qualification::{BridgeAbi, ShellKind};
use kr_shell_integration::contract::requests::{BridgeAnswer, WorkerRequest};
use kr_shell_integration::contract::transport::{
    BOOTSTRAP_SECRET_LEN, BRIDGE_PROTOCOL, BridgeAccepted, BridgeEndpoint, BridgeFrame,
    BridgeHello, EventOutcome, HandshakeOutcome, ObservedPeer, ProofVerdict, WorkerExpectation,
    bootstrap_transcript, decide_handshake, frame_codec,
};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

/// How long a reader is given to answer before a test calls it a failure.
///
/// Generous: these tests share a machine with compilation, and a reader that answers late is a
/// different failure from one that does not answer.
pub const REPLY: Duration = Duration::from_secs(20);

/// How long the step given to an editor that only reaches its queue when the reader steps lasts.
pub const STEP: Duration = Duration::from_millis(60);

/// The environment variable that turns a missing package into a failure rather than a skip.
pub const REQUIRE: &str = "KR_REQUIRE_SHELL_PACKAGES";

/// Which side of the endpoint has gone, or `None` where it is whole.
///
/// A write that found the peer gone and a read that reached the end of the stream are separate
/// answers about separate directions, and either one on its own is the endpoint no longer being
/// whole. Neither stands in for the other: a check that asked only whether the stream had ended
/// would carry on writing into an endpoint the bridge had already left, and read the silence that
/// followed as the shell having answered nothing.
#[must_use]
pub fn endpoint_break(shut: bool, write_gone: bool, read_gone: bool) -> Option<&'static str> {
    match (shut, write_gone, read_gone) {
        (true, _, _) => Some("this side shut it"),
        (_, true, true) => Some("a write found the bridge gone and the stream has ended"),
        (_, true, false) => Some("a write found the bridge gone"),
        (_, false, true) => Some("the stream has ended"),
        (false, false, false) => None,
    }
}

/// The moment a wait ends at, carried into every wait that runs inside it.
///
/// A wait nested inside a longer one answers to that one. A constant of its own would either end
/// the outer budget early or run past it, and both are a caller having asked for one thing and
/// waited for another. So a step that owns a budget makes one of these and hands it down, and
/// every wait below it reads the clock against that one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(Instant);

impl Deadline {
    /// The moment `budget` from now.
    #[must_use]
    pub fn after(budget: Duration) -> Self {
        Self(Instant::now() + budget)
    }

    /// Whether that moment has arrived.
    #[must_use]
    pub fn passed(self) -> bool {
        Instant::now() >= self.0
    }

    /// How much of the budget is left, which is nothing once it has passed.
    #[must_use]
    pub fn left(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// The earlier of two moments, which is the one a nested wait answers to.
    #[must_use]
    pub fn earlier(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    /// `within`, or the rest of this budget where that ends sooner.
    #[must_use]
    pub fn at_most(self, within: Duration) -> Duration {
        within.min(self.left())
    }
}

/// What became of a write to the endpoint.
///
/// A write that finds the bridge gone is not the same event as a read that reaches the end of the
/// stream, and it says nothing about the frames the bridge sent before it went. The two are kept
/// apart so that neither can stand in for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Every byte reached the bridge.
    Delivered,
    /// The bridge's side of the endpoint has gone, so this write delivered nothing.
    PeerGone,
}

/// How long a torn-down session waits for the thread reading its terminal to stop.
const READER_STOP: Duration = Duration::from_secs(5);

/// One built package, as `scripts/build-shells.sh` installed it.
pub struct Package {
    pub kind: ShellKind,
    pub identity: String,
    pub executable: PathBuf,
    pub startup_entry: PathBuf,
    /// Where a package that loads modules by name keeps them.
    pub module_directory: PathBuf,
    pub record: serde_json::Value,
}

fn cache_root() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KR_SHELL_PREFIX") {
        return PathBuf::from(explicit);
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach/shells")
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("kalareach/shells")
    } else {
        home.join(".cache/kalareach/shells")
    }
}

impl Package {
    /// Finds the built package, or says why it is not there.
    ///
    /// # Errors
    ///
    /// Returns the reason a test should skip: the package has not been built here.
    pub fn find(kind: ShellKind) -> Result<Self, String> {
        let name = kind.as_str();
        let root = cache_root().join(name);
        let pointer = root.join("current");
        let how = match kind {
            // This package builds no shell: it is qualified against the editor the person already
            // has, and the module publishes what it found.
            ShellKind::PowerShell => {
                "import shells/psreadline/module and run Publish-KalaReachQualification".to_owned()
            }
            other => format!("run scripts/build-shells.sh --{}", other.as_str()),
        };
        let identity = std::fs::read_to_string(&pointer)
            .map_err(|error| {
                format!(
                    "{} is not built here ({}: {error}); {how}",
                    name,
                    pointer.display()
                )
            })?
            .trim()
            .to_owned();
        let directory = root.join(&identity);
        let record_path = directory.join("kr-shell-identity.json");
        let record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&record_path).map_err(|error| {
                format!("{} has no identity record ({error})", record_path.display())
            })?)
            .map_err(|error| format!("{} does not decode ({error})", record_path.display()))?;
        let executable = PathBuf::from(
            record["shell"]["executable"]
                .as_str()
                .ok_or_else(|| format!("{} names no executable", record_path.display()))?,
        );
        if !executable.exists() {
            return Err(format!("{} is not installed", executable.display()));
        }
        let module_directory = directory.join("modules");
        let startup_entry = directory.join("startup").join(match kind {
            ShellKind::Zsh => "kr-zshrc.zsh",
            ShellKind::Bash => "kr-bashrc.bash",
            ShellKind::Fish => "kr-fish.fish",
            ShellKind::PowerShell => "kr-profile.ps1",
        });
        Ok(Self {
            kind,
            identity,
            executable,
            startup_entry,
            module_directory,
            record,
        })
    }

    /// Returns the package, or prints the reason and returns `None` so the test can stop.
    ///
    /// # Panics
    ///
    /// Panics when [`REQUIRE`] is set, which is what continuous integration does: there the build
    /// is a step of the same job, so an absent package is a failure rather than a skip.
    #[must_use]
    pub fn found(kind: ShellKind) -> Option<Self> {
        match Self::find(kind) {
            Ok(package) => Some(package),
            Err(reason) => {
                assert!(
                    std::env::var_os(REQUIRE).is_none(),
                    "{REQUIRE} is set and the package is missing: {reason}"
                );
                println!("skipped: {reason}");
                None
            }
        }
    }

    /// The patches the identity record names, as the handshake must declare them.
    #[must_use]
    pub fn patch_names(&self) -> Vec<String> {
        self.record["shell"]["patches"]
            .as_array()
            .map(|patches| {
                patches
                    .iter()
                    .filter_map(|patch| patch["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The marked block the package publishes, exactly as it publishes it.
fn startup_entry(package: &Package) -> String {
    std::fs::read_to_string(&package.startup_entry)
        .unwrap_or_else(|error| panic!("{}: {error}", package.startup_entry.display()))
}

/// The person's own configuration, which the integration never replaces.
fn user_configuration(kind: ShellKind, prompt: &str) -> String {
    match kind {
        ShellKind::Zsh => format!(
            "# the person's own configuration, which the integration never replaces\n\
             PROMPT='{prompt}'\n\
             setopt no_beep\n\
             unsetopt zle_rprompt_indent 2>/dev/null\n\
             HISTFILE=\n\
             typeset -g KR_TEST_USER_CONFIGURATION=1\n\n"
        ),
        ShellKind::Bash => format!(
            "# the person's own configuration, which the integration never replaces\n\
             PS1='{prompt}'\n\
             HISTFILE=\n\
             KR_TEST_USER_CONFIGURATION=1\n\n"
        ),
        ShellKind::Fish => format!(
            "# the person's own configuration, which the integration never replaces\n\
             function fish_prompt; printf '%s' '{prompt}'; end\n\
             set -g fish_greeting\n\
             set -g KR_TEST_USER_CONFIGURATION 1\n\n"
        ),
        ShellKind::PowerShell => format!(
            "# the person's own configuration, which the integration never replaces\n\
             function global:prompt {{ '{prompt}' }}\n\
             $global:KR_TEST_USER_CONFIGURATION = 1\n\
             Set-PSReadLineOption -HistorySaveStyle SaveNothing\n\
             Set-PSReadLineOption -PredictionSource None\n\
             # A line typed before this editor takes the terminal arrives through the terminal's\n\
             # own line discipline, which sends a line feed where the return was. This person has\n\
             # bound that to the same acceptance, so a line they type a moment early is still\n\
             # theirs. The integration goes on top of this binding rather than in place of it.\n\
             Set-PSReadLineKeyHandler -Chord Ctrl+j -Function AcceptLine\n\n"
        ),
    }
}

/// Writes the person's configuration and the package's own marked entry where the shell reads
/// them, in the layout the package's manifest names.
fn install_startup(package: &Package, home: &Path, prompt: &str) {
    let user = user_configuration(package.kind, prompt);
    let entry = startup_entry(package);
    match package.kind {
        ShellKind::Zsh => {
            std::fs::write(home.join(".zshrc"), format!("{user}{entry}"))
                .expect("the startup file");
        }
        ShellKind::Bash => {
            std::fs::write(home.join(".bashrc"), format!("{user}{entry}"))
                .expect("the startup file");
        }
        ShellKind::Fish => {
            // Files under conf.d run before the person's own config.fish, which is why the entry
            // waits for the first prompt before it activates anything.
            let config = home.join(".config").join("fish");
            std::fs::create_dir_all(config.join("conf.d")).expect("a configuration directory");
            std::fs::write(config.join("config.fish"), user).expect("the startup file");
            std::fs::write(config.join("conf.d").join("kr-kalareach.fish"), entry)
                .expect("the startup entry");
        }
        ShellKind::PowerShell => {
            let config = home.join(".config").join("powershell");
            std::fs::create_dir_all(&config).expect("a configuration directory");
            std::fs::write(
                config.join("Microsoft.PowerShell_profile.ps1"),
                format!("{user}{entry}"),
            )
            .expect("the startup file");
        }
    }
}

/// One event as it came off the endpoint, with what this session knew about the reader then.
///
/// The stamp is taken when the frame is read rather than when the event is looked at, because the
/// order on the endpoint is the order things happened in: a report that arrived before a reader
/// left is about the reader that left, whenever a check gets round to reading it.
pub struct Received {
    pub id: RequestId,
    pub event: BridgeEvent,
    /// How many readers of this session had entered or left when this frame was read.
    pub reader_lifetime: u64,
}

/// How the worker side of a session answers a `command_resolve`.
#[derive(Clone, Debug)]
pub enum ResolvePolicy {
    /// The worker's own decision for the integrations the session was created with. An integrated
    /// name is answered `backend_unavailable`, because nothing here establishes a backend, which
    /// is what the worker answers when it cannot.
    Decide(Vec<kr_protocol::session::CommandIntegration>),
    /// No answer to a resolve, while every other event is still answered.
    Silent,
    /// A backend the worker established: the answer names `launcher`, adds `environment` for the
    /// one invocation and appends `added` to the vector.
    Backend {
        launcher: String,
        environment: Vec<kr_protocol::session::EnvironmentVariable>,
        added: Vec<String>,
    },
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self::Decide(Vec::new())
    }
}

/// What a session's worker side answers for the commands a line runs, and everything the bridge
/// reported about them, in the order it arrived.
///
/// These are kept apart from the event queue, which waits drop from: a check that counts the
/// resolves one command asked needs every one of them, whatever a wait took off the queue.
#[derive(Default)]
pub struct Commands {
    /// How a resolve is answered.
    pub policy: ResolvePolicy,
    /// Whether an acceptance is answered with no capability, as for a line nothing can be
    /// attributed to.
    pub withhold_tokens: bool,
    /// Whether the worker side has stopped answering anything at all.
    pub stuck: bool,
    /// Every resolve the bridge asked.
    pub resolves: Vec<kr_protocol::root::RootCommandResolveParams>,
    /// Every command block the bridge reported.
    pub blocks: Vec<kr_protocol::root::RootCommandBlockParams>,
    /// The capability each acceptance was answered with.
    pub tokens: Vec<Option<String>>,
    /// Every acceptance the bridge reported.
    pub accepted: Vec<kr_protocol::root::RootCommandAcceptedParams>,
    /// Every reader entry the bridge reported.
    pub entries: Vec<RootEditorEnterParams>,
}

impl Commands {
    /// The primary reader that accepted the line reported last, as it reported itself on entry.
    ///
    /// # Panics
    ///
    /// Panics when no line has been accepted, or no primary reader entered at its prompt.
    #[must_use]
    pub fn last_line_reader(&self) -> &RootEditorEnterParams {
        let line = self.accepted.last().expect("a line was accepted");
        self.entries
            .iter()
            .rev()
            .find(|entry| {
                entry.prompt_generation == line.prompt_generation
                    && entry.reader_context == kr_protocol::root::ReaderContext::Primary
            })
            .expect("a primary reader entered at the prompt the line was accepted at")
    }
}

/// What the worker decides for one invocation, for the integrations a session was created with.
///
/// The decision is the one the worker makes, from the same function. A worker that can establish
/// no backend answers an integrated name as a bypass, and so does this one.
#[must_use]
pub fn worker_decision(
    integrations: &[kr_protocol::session::CommandIntegration],
    params: &kr_protocol::root::RootCommandResolveParams,
) -> kr_protocol::root::RootCommandResolveResult {
    use kr_shell_integration::host::command::{InvocationContext, Resolution, resolve};

    let resolution = resolve(
        integrations,
        InvocationContext {
            managed_root_shell: true,
            interactive: params.interactive,
        },
        &params.argv,
    );
    if resolution.establishes_backend() {
        return Resolution::Bypassed {
            command: params.argv.first().cloned().unwrap_or_default(),
            arguments: params.argv.clone(),
            reason: kr_protocol::root::CommandBypassReason::BackendUnavailable,
        }
        .to_answer(None);
    }
    resolution.to_answer(None)
}

/// One live session: the worker's endpoint, the shell under a pseudo-terminal, and the frames
/// between them.
pub struct Session {
    pub package_kind: ShellKind,
    pub session_id: SessionId,
    pub hello: BridgeHello,
    pub accepted: BridgeAccepted,
    pub prompt: String,
    /// The primary reader an entry last named, for a fence asked while it is mid-operation.
    pub last_entry: Option<RootEditorEnterParams>,
    /// How far into the terminal's output a drawn prompt has already been typed at.
    mark: usize,
    /// True once the shell has a reader of its own, which is what a step can be given to.
    pub reading: bool,
    /// False while what is being written is not something the reader is waiting for.
    stepping: bool,
    stream: UnixStream,
    /// True once this side shut the endpoint, after which nothing is written or read.
    shut: bool,
    /// True once a write found the bridge's side of the endpoint gone.
    ///
    /// This is not an end of file on the read side. Frames the bridge sent before it went are
    /// still here to be decoded, and a check that read one flag for both would lose them: a
    /// forbidden event already in hand would go unread and the drive waiting for it would report
    /// that nothing forbidden happened.
    peer_write_gone: bool,
    /// True once a read reached the end of the stream.
    peer_read_gone: bool,
    /// True while the caller expects the bridge to go, so a closure is a result rather than a
    /// fault. A drive that expects one says so for the part of its work where it does.
    closure_expected: bool,
    /// The moment every wait inside this session answers to, while a caller owns a budget.
    budget: Option<Deadline>,
    /// How many times a reader of this session has entered or left, counted as the frames
    /// arrived.
    ///
    /// No reader reports this of itself, and it is what tells a reader that was replaced from one
    /// that redrew: an observation made before a lifecycle event is about a reader that is no
    /// longer the one a later key would reach.
    reader_lifetime: u64,
    /// The reader the last successful probe found inside its read.
    reading_reader: Option<stacks::ReaderMark>,
    pending: Vec<u8>,
    /// What the bridge has sent and no check has taken, with the managed decisions among it
    /// counted as they arrived.
    events: Inbox,
    /// Each answer the reader sent, with the instant it was taken off the endpoint: a wait under a
    /// deadline accepts an answer that arrived inside its window, however late it notices it.
    answers: HashMap<RequestId, (Instant, BridgeAnswer)>,
    next_request: u64,
    /// What this session answers for the commands a line runs, and what the bridge reported.
    pub commands: Commands,
    output: Arc<Mutex<Vec<u8>>>,
    stopped: Arc<AtomicBool>,
    /// The reader thread's report that it has stopped, so a session that is torn down does not
    /// leave a thread still writing into what the next case reads.
    stopped_reading: std::sync::mpsc::Receiver<()>,
    terminal: Arc<TerminalInput>,
    child: Box<dyn Child + Send + Sync>,
    _master: Box<dyn MasterPty + Send>,
    _directory: tempfile::TempDir,
}

impl Session {
    /// Starts the packaged shell and completes the handshake.
    ///
    /// # Panics
    ///
    /// Panics when the endpoint cannot be created, the shell does not connect, or the worker's own
    /// decision refuses the handshake: each is a failure of the package under test.
    #[must_use]
    pub fn start(package: &Package) -> Self {
        Self::start_with(package, &[])
    }

    /// Starts the packaged shell with `environment` added to what it inherits, and completes the
    /// handshake.
    ///
    /// # Panics
    ///
    /// Panics as [`Session::start`] does.
    #[must_use]
    pub fn start_with(package: &Package, environment: &[(String, String)]) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("kr-shell-")
            .tempdir()
            .expect("a session directory on the internal disk");
        let home = directory.path().join("home");
        let runtime = directory.path().join("rt");
        std::fs::create_dir(&home).expect("a home directory");
        std::fs::create_dir(&runtime).expect("a runtime directory");
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("an owner-only runtime directory");

        let endpoint_path = runtime.join("shell-bridge");
        let endpoint = BridgeEndpoint::unix(endpoint_path.to_string_lossy().into_owned());
        endpoint
            .validate()
            .expect("the endpoint path fits a socket address");
        let listener = UnixListener::bind(&endpoint_path).expect("the endpoint binds");
        std::fs::set_permissions(&endpoint_path, std::fs::Permissions::from_mode(0o600))
            .expect("an owner-only endpoint");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");

        let prompt = "KR> ".to_owned();
        let session_id = SessionId::new(Uuid::from_bytes([0x5e; 16]));
        let secret: Vec<u8> = (0..BOOTSTRAP_SECRET_LEN)
            .map(|i| (i as u8).wrapping_mul(7))
            .collect();

        install_startup(package, &home, &prompt);

        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");

        let mut command = CommandBuilder::new(package.executable.to_string_lossy().into_owned());
        match package.kind {
            ShellKind::PowerShell => {
                // The host reads its profile and drops into its own read loop; nothing else about
                // the launch is this package's.
                command.arg("-NoLogo");
                // The qualified editor and this module are selected before the profile runs, which
                // is what the marked block then imports by name.
                let mut module_path = package.module_directory.to_string_lossy().into_owned();
                if let Some(existing) = std::env::var_os("PSModulePath") {
                    module_path.push(':');
                    module_path.push_str(&existing.to_string_lossy());
                }
                command.env("PSModulePath", module_path);
                // The host's own image needs its runtime's location, which the qualification
                // recorded from the launcher that started the host it qualified.
                if let Some(environment) = package.record["launch"]["environment"].as_object() {
                    for (name, value) in environment {
                        if let Some(value) = value.as_str() {
                            command.env(name, value);
                        }
                    }
                }
            }
            _ => {
                command.arg("-i");
            }
        }
        command.cwd(&home);
        command.env("HOME", &home);
        command.env("ZDOTDIR", &home);
        command.env("XDG_CONFIG_HOME", home.join(".config"));
        command.env("XDG_DATA_HOME", home.join(".local").join("share"));
        command.env("TERM", "xterm-256color");
        command.env("LANG", "C");
        for (name, value) in environment {
            command.env(name, value);
        }
        command.env("KR_SESSION", session_id.to_string());
        command.env("KR_SHELL_BRIDGE", &endpoint.path);
        command.env(
            "KR_SHELL_BRIDGE_SECRET",
            kr_protocol::scalars::to_base64url(&secret),
        );
        // A run that asked a package for diagnostics passes that through to the shell it starts.
        if let Some(trace) = std::env::var_os("KR_SHELL_BRIDGE_TRACE") {
            command.env("KR_SHELL_BRIDGE_TRACE", trace);
        }

        let child = pty
            .slave
            .spawn_command(command)
            .expect("the packaged shell starts");
        drop(pty.slave);

        let output = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let mut reader = pty.master.try_clone_reader().expect("a terminal reader");
        let collected = Arc::clone(&output);
        let finished = Arc::clone(&stopped);
        let terminal = Arc::new(TerminalInput::of(
            pty.master.take_writer().expect("a terminal writer"),
        ));
        let answering = Arc::clone(&terminal);
        let (finished_reading, stopped_reading) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !finished.load(Ordering::Relaxed) {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(taken) => {
                        // A terminal that never answers a query is a terminal the editor waits
                        // for, so this one answers the three an editor asks at every prompt.
                        answer_terminal_queries(&buffer[..taken], &answering);
                        collected
                            .lock()
                            .expect("the output lock")
                            .extend_from_slice(&buffer[..taken]);
                    }
                }
            }
            drop(finished_reading);
        });

        let stream = accept_within(&listener, REPLY)
            .expect("the shell connects to the endpoint it was given");
        stream
            .set_nonblocking(true)
            .expect("a non-blocking connection");

        let mut session = Self {
            package_kind: package.kind,
            session_id,
            hello: placeholder_hello(session_id),
            accepted: placeholder_accept(session_id),
            prompt,
            mark: 0,
            reading: false,
            stepping: true,
            last_entry: None,
            stream,
            shut: false,
            peer_write_gone: false,
            peer_read_gone: false,
            closure_expected: false,
            budget: None,
            reader_lifetime: 0,
            reading_reader: None,
            pending: Vec::new(),
            events: Inbox::default(),
            answers: HashMap::new(),
            next_request: 1,
            commands: Commands::default(),
            output,
            stopped,
            stopped_reading,
            terminal,
            child,
            _master: pty.master,
            _directory: directory,
        };

        let hello = match session.read_frame(REPLY).expect("the opening frame") {
            BridgeFrame::Hello(hello) => hello,
            other => panic!("the bridge opened with {other:?}"),
        };

        // The proof is checked here, against the transcript this contract defines, rather than
        // taken on trust: it is what binds this shell's own process and this endpoint.
        let transcript = bootstrap_transcript(
            session.session_id,
            &endpoint,
            &hello.shell_process,
            &hello.shell.integration_version,
        )
        .expect("the transcript encodes");
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret).expect("any key length");
        mac.update(&transcript);
        let verdict = if mac.verify_slice(hello.proof.as_slice()).is_ok() {
            ProofVerdict::Verified
        } else {
            ProofVerdict::Failed
        };

        let expectation = WorkerExpectation {
            session_id: session.session_id,
            root_process: hello.shell_process.clone(),
            supported_editor_abis: vec![hello.shell.editor_abi.clone()],
            supported_integration_versions: vec![hello.shell.integration_version.clone()],
            launched_package: None,
            already_registered: false,
            gesture: kr_shell_integration::contract::events::EofGesture::default(),
        };
        let peer = ObservedPeer {
            uid: endpoint_owner(&endpoint_path),
            process: Some(hello.shell_process.clone()),
        };
        let outcome = decide_handshake(&expectation, &peer, &hello, verdict);
        let accepted = match outcome {
            HandshakeOutcome::Accepted(accepted) => accepted,
            HandshakeOutcome::Refused(refused) => {
                panic!("the package was refused: {:?}", refused.reason)
            }
        };
        session.write_frame(&BridgeFrame::Handshake(HandshakeOutcome::Accepted(
            accepted.clone(),
        )));
        session.hello = hello;
        session.accepted = accepted;
        session
    }

    /// The directory the shell started in, as the kernel names it.
    ///
    /// A shell reports the physical path of its working directory, and the platform's temporary
    /// directory can be reached through a link, so this is the path with every link resolved.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        let home = self._directory.path().join("home");
        std::fs::canonicalize(&home).unwrap_or(home)
    }

    /// The process the shell says it is.
    #[must_use]
    pub fn shell_process(&self) -> ProcessStartIdentity {
        self.hello.shell_process.clone()
    }

    /// The child's operating-system process identifier.
    #[must_use]
    pub fn child_pid(&self) -> Option<u32> {
        self.child.process_id()
    }

    /// Sends one frame, which has to reach the bridge.
    ///
    /// A write that finds the bridge gone is a fault unless the caller said it expected one, so an
    /// ordinary write cannot lose a frame quietly. A drive that is waiting for the shell to end
    /// says so with [`Session::expecting_the_bridge_to_go`], and reads the delivery itself.
    ///
    /// # Panics
    ///
    /// Panics when the bridge has gone and no caller expected it to.
    pub fn write_frame(&mut self, frame: &BridgeFrame) {
        let delivery = self.write_frames(std::slice::from_ref(frame));
        assert!(
            delivery == Delivery::Delivered || self.closure_expected,
            "the bridge's side of the endpoint has gone and this write did not expect it; the \
             terminal showed:\n{}",
            self.terminal_output()
        );
    }

    /// Runs `work` with a closure of the bridge's counting as a result rather than a fault.
    ///
    /// The one thing this permits is a write that finds the peer gone. Everything else a check
    /// asserts is asserted as it was.
    pub fn expecting_the_bridge_to_go<T>(&mut self, work: impl FnOnce(&mut Self) -> T) -> T {
        let previous = std::mem::replace(&mut self.closure_expected, true);
        let outcome = work(self);
        self.closure_expected = previous;
        outcome
    }

    /// Runs `work` with every wait inside it answering to `deadline`.
    ///
    /// This is how one budget reaches the waits below a caller. A wait that owned a limit of its
    /// own would either end the caller's budget early or run past it, and both are the caller
    /// having asked for one thing and waited for another. A budget already in force is kept where
    /// it ends sooner, because a nested wait answers to the outer one.
    pub fn within_budget<T>(&mut self, deadline: Deadline, work: impl FnOnce(&mut Self) -> T) -> T {
        let effective = match self.budget {
            Some(outer) => outer.earlier(deadline),
            None => deadline,
        };
        let previous = self.budget.replace(effective);
        let outcome = work(self);
        self.budget = previous;
        outcome
    }

    /// The moment a wait inside this session ends at, given what its caller asked for.
    fn deadline_for(&self, default: Duration) -> Deadline {
        match self.budget {
            Some(deadline) => deadline,
            None => Deadline::after(default),
        }
    }

    /// `within`, cut to what is left of the budget in force.
    fn bounded(&self, within: Duration) -> Duration {
        match self.budget {
            Some(deadline) => deadline.at_most(within),
            None => within,
        }
    }

    /// Sends one frame the endpoint has until `deadline` to take, which has to reach the bridge
    /// as [`Session::write_frame`]'s does.
    ///
    /// # Panics
    ///
    /// Panics when the bridge has gone and no caller expected it to.
    pub fn write_frame_before(&mut self, frame: &BridgeFrame, deadline: Instant) {
        let delivery = self.write_frames_before(std::slice::from_ref(frame), deadline);
        assert!(
            delivery == Delivery::Delivered || self.closure_expected,
            "the bridge's side of the endpoint has gone and this write did not expect it; the \
             terminal showed:\n{}",
            self.terminal_output()
        );
    }

    /// Sends several frames in one write, so the reader takes them off the endpoint together.
    ///
    /// A shell that has ended has taken its side of the endpoint with it. That is a real answer
    /// here — a gesture the editor answers with the shell's own end of file is one of the results
    /// these drives look for — so the delivery is returned rather than swallowed, and the caller
    /// says whether it expected one.
    #[must_use]
    pub fn write_frames(&mut self, frames: &[BridgeFrame]) -> Delivery {
        let deadline = self.deadline_for(REPLY);
        self.write_frames_before(frames, deadline.0)
    }

    /// Sends several frames in one write the endpoint has until `deadline` to take.
    ///
    /// A caller waiting for one condition under a deadline of its own passes it here, so neither
    /// the endpoint's backpressure nor the step the editor is given afterwards outlasts it.
    #[must_use]
    pub fn write_frames_before(&mut self, frames: &[BridgeFrame], deadline: Instant) -> Delivery {
        if self.shut || self.peer_write_gone {
            return Delivery::PeerGone;
        }
        let mut bytes = Vec::new();
        for frame in frames {
            let body = kr_cbor::to_canonical_vec(frame).expect("a frame encodes");
            assert!(
                body.len() <= frame_codec().max_payload_len(),
                "a frame of {} bytes is outside the stream's bound",
                body.len()
            );
            bytes.extend_from_slice(
                &u32::try_from(body.len())
                    .expect("a bounded frame")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&body);
        }
        let mut written = 0;
        while written < bytes.len() {
            match self.stream.write(&bytes[written..]) {
                Ok(0) => {
                    self.peer_write_gone = true;
                    return Delivery::PeerGone;
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    assert!(!left.is_zero(), "the bridge stopped reading");
                    std::thread::sleep(left.min(Duration::from_millis(2)));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                    ) =>
                {
                    self.peer_write_gone = true;
                    return Delivery::PeerGone;
                }
                Err(error) => panic!("writing to the bridge: {error}"),
            }
        }
        // An editor that reaches its own queue only when the reader steps is given that step here,
        // which is the one a person at the keyboard gives it by typing at all.
        self.nudge_before(deadline);
        Delivery::Delivered
    }

    /// The length of the whole frame at the front of what has been received, where one is there.
    fn whole_frame_len(&self) -> Option<usize> {
        let header: [u8; 4] = self.pending.get(..4)?.try_into().ok()?;
        let length = u32::from_be_bytes(header) as usize;
        (self.pending.len() >= 4 + length).then_some(length)
    }

    /// Decodes one whole frame out of what has already been received, where there is one.
    fn decode_pending(&mut self) -> Option<BridgeFrame> {
        let length = self.whole_frame_len()?;
        let body: Vec<u8> = self.pending[4..4 + length].to_vec();
        self.pending.drain(..4 + length);
        // Strict decoding, and the typed value has to re-encode to the same bytes: this is where a
        // package that wrote its own encoding of the contract's types is caught, byte for byte.
        let frame: BridgeFrame = kr_cbor::from_canonical_slice(&body, &kr_cbor::Limits::DEFAULT)
            .unwrap_or_else(|error| panic!("a frame is not canonical KR-CBOR-1: {error}"));
        Some(frame)
    }

    /// Reads the next frame, taking what has already arrived before anything else.
    ///
    /// The end of the stream is the end of what the bridge will send, not the end of what it has
    /// sent: frames it wrote before it went are in hand here, and they are decoded and returned
    /// first. A write that found the peer gone does not stop this side reading at all — the two
    /// directions are separate, and evidence this session already holds is evidence whatever
    /// happened to the write.
    fn read_frame(&mut self, within: Duration) -> Option<BridgeFrame> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(frame) = self.decode_pending() {
                return Some(frame);
            }
            if self.shut || self.peer_read_gone {
                return None;
            }
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => self.peer_read_gone = true,
                Ok(taken) => self.pending.extend_from_slice(&buffer[..taken]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                    ) =>
                {
                    self.peer_read_gone = true;
                }
                Err(error) => panic!("reading from the bridge: {error}"),
            }
        }
    }

    /// Reads whatever has arrived, sorting events from answers and acknowledging what the contract
    /// says needs no decision.
    fn pump(&mut self, within: Duration) {
        let deadline = self.deadline_for(REPLY);
        self.pump_before(self.bounded(within), deadline.0);
    }

    /// Reads for `within`, acknowledging what the contract says needs no decision, with every
    /// write it makes on the way bounded by `deadline`.
    ///
    /// The reading itself ends at `deadline` too: a thread that was descheduled between being told
    /// how long to read for and starting to read would otherwise begin an interval its caller has
    /// already spent.
    fn pump_before(&mut self, within: Duration, deadline: Instant) {
        let end = (Instant::now() + within).min(deadline);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let Some(frame) = self.read_frame(left.min(Duration::from_millis(20))) else {
                if self.peer_read_gone && self.pending.len() < 4 {
                    // Nothing more is coming and nothing whole is left to decode, so waiting out
                    // the rest of this call would be waiting for a stream that has ended.
                    return;
                }
                continue;
            };
            match frame {
                BridgeFrame::Event { id, event } => {
                    // A reader entering or leaving is what invalidates an observation of the
                    // reader before it, so it is counted here, where the order is the endpoint's
                    // own. The event itself carries the new count: a report from the reader that
                    // has just entered belongs with it, and everything before a leave is stamped
                    // lower than the leave and so is plainly about a reader that has gone.
                    if matches!(
                        event,
                        BridgeEvent::EditorEnter(_) | BridgeEvent::EditorLeave(_)
                    ) {
                        self.reader_lifetime += 1;
                    }
                    let outcome = self.routine_answer(&event);
                    if let Some(result) = outcome {
                        // A routine acknowledgement is not a check's own write, so a bridge that
                        // has gone is recorded here rather than asserted: the check that needs a
                        // working endpoint asks for one and says so itself.
                        let _ = self.write_frames_before(
                            &[BridgeFrame::EventResult { id, result }],
                            deadline,
                        );
                    }
                    // The one way an event reaches the queue, and the inbox counts a managed
                    // decision as it takes it in: a wait that later drops it from the queue
                    // cannot drop it from the count.
                    self.events.arrive(Received {
                        id,
                        event,
                        reader_lifetime: self.reader_lifetime,
                    });
                }
                BridgeFrame::Answer { id, answer } => {
                    self.answers.insert(id, (Instant::now(), answer));
                }
                other => panic!("a bridge sent {other:?}"),
            }
        }
    }

    /// What the worker answers an event that needs no decision of its own.
    fn routine_answer(&mut self, event: &BridgeEvent) -> Option<EventOutcome> {
        if self.commands.stuck {
            // A worker that has stopped answering still received what the bridge sent.
            match event {
                BridgeEvent::EditorEnter(params) => self.commands.entries.push(params.clone()),
                BridgeEvent::CommandAccepted(params) => {
                    self.commands.accepted.push(params.clone());
                }
                BridgeEvent::CommandResolve(params) => {
                    self.commands.resolves.push(params.clone());
                }
                BridgeEvent::CommandBlock(params) => self.commands.blocks.push((**params).clone()),
                _ => {}
            }
            return None;
        }
        match event {
            BridgeEvent::EditorEnter(params) => {
                self.commands.entries.push(params.clone());
                Some(EventOutcome::EditorEntered(RootEditorEnterResult {
                    state: FenceState::Unfenced,
                    fence_exchange: Nullable::null(),
                }))
            }
            BridgeEvent::EditorLeave(_) => Some(EventOutcome::EditorLeft(RootEditorLeaveResult {
                state: FenceState::Outside,
            })),
            BridgeEvent::CommandAccepted(params) => {
                self.commands.accepted.push(params.clone());
                // The capability a real worker mints for the line it has just recorded. This
                // harness stands in for the worker, so it mints one the same way.
                let token =
                    (!self.commands.withhold_tokens).then(|| kr_ipc::new_uuid().to_string());
                self.commands.tokens.push(token.clone());
                Some(EventOutcome::CommandRecorded(RootCommandAcceptedResult {
                    origin: params.origin.clone(),
                    detach_token: Nullable(token),
                    state: FenceState::Fenced,
                }))
            }
            BridgeEvent::CommandResolve(params) => {
                self.commands.resolves.push(params.clone());
                let answer = match &self.commands.policy {
                    ResolvePolicy::Decide(integrations) => worker_decision(integrations, params),
                    ResolvePolicy::Silent => return None,
                    ResolvePolicy::Backend {
                        launcher,
                        environment,
                        added,
                    } => {
                        let mut arguments = params.argv.clone();
                        arguments.extend(added.iter().cloned());
                        kr_protocol::root::RootCommandResolveResult {
                            arguments,
                            added: added.clone(),
                            bypass: Nullable::null(),
                            backend: Nullable::some(kr_protocol::root::CommandBackend {
                                session_id: params.session_id,
                                prompt_generation: params.prompt_generation,
                                environment: environment.clone(),
                                launcher: launcher.clone(),
                            }),
                        }
                    }
                };
                Some(EventOutcome::CommandResolved(Box::new(answer)))
            }
            BridgeEvent::CommandBlock(params) => {
                self.commands.blocks.push((**params).clone());
                Some(EventOutcome::CommandBlockRecorded(
                    kr_protocol::root::RootCommandBlockResult {
                        prompt_generation: params.prompt_generation,
                        retained: kr_protocol::scalars::U64::new(1),
                    },
                ))
            }
            BridgeEvent::ReaderIdle(_)
            | BridgeEvent::GestureChanged(_)
            | BridgeEvent::PreEofConsumed(_)
            | BridgeEvent::HooksActivated(_)
            | BridgeEvent::IntegrationLost(_) => Some(EventOutcome::Received),
            // A detach is the worker's decision, so the test answers it.
            BridgeEvent::EofDetach(_) => None,
        }
    }

    /// Waits for the next event the predicate accepts, dropping the ones that came before it.
    ///
    /// Dropping is what makes a sequence of these read as a sequence: each call asks for the next
    /// thing the reader does, and what it did before that has already been asserted or does not
    /// matter to this test.
    ///
    /// # Panics
    ///
    /// Panics when no such event arrives inside [`REPLY`].
    pub fn expect_event<F>(&mut self, what: &str, accept: F) -> (RequestId, BridgeEvent)
    where
        F: Fn(&BridgeEvent) -> bool,
    {
        let deadline = self.deadline_for(REPLY);
        loop {
            if let Some(received) = self.events.take_first(|received| accept(&received.event)) {
                return (received.id, received.event);
            }
            assert!(
                !deadline.passed(),
                "no {what} arrived; the events were {:?}\nterminal output:\n{}",
                self.events.waiting(),
                self.terminal_output()
            );
            self.pump(Duration::from_millis(50));
        }
    }

    /// Returns true when an event the predicate accepts arrived inside `within`.
    pub fn saw_event<F>(&mut self, within: Duration, accept: F) -> bool
    where
        F: Fn(&BridgeEvent) -> bool,
    {
        let deadline = Instant::now() + self.bounded(within);
        loop {
            if self
                .events
                .take_first(|received| accept(&received.event))
                .is_some()
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump(Duration::from_millis(50));
        }
    }

    /// Drops every event received so far, and the count of managed decisions with them.
    ///
    /// The pump before it is what makes this a boundary rather than a guess: anything the reader
    /// had already sent is taken off the endpoint and dropped with the rest. It answers to the
    /// budget in force, so a caller that has little left drops what is here and goes on. This is
    /// the only boundary a check draws, and a drive that rejects the managed decision draws it
    /// before its first key and nowhere after.
    pub fn forget_events(&mut self) {
        self.pump(Duration::from_millis(200));
        self.events.boundary();
    }

    /// Answers one event.
    ///
    /// The reader asked for this and is not waiting on it, so it is not given a step of its own:
    /// a session that stepped the reader for every acknowledgement would never let it be idle.
    pub fn answer_event(&mut self, id: RequestId, result: EventOutcome) {
        self.stepping = false;
        self.write_frame(&BridgeFrame::EventResult { id, result });
        self.stepping = true;
    }

    /// Sends one request to the reader thread and returns its identifier.
    pub fn ask(&mut self, request: WorkerRequest) -> RequestId {
        let deadline = self.deadline_for(REPLY);
        self.ask_before(request, deadline.0)
    }

    /// Sends one request the endpoint has until `deadline` to take, and returns its identifier.
    pub fn ask_before(&mut self, request: WorkerRequest, deadline: Instant) -> RequestId {
        let id = RequestId::new(self.next_request);
        self.next_request += 1;
        self.write_frame_before(&BridgeFrame::Request { id, request }, deadline);
        id
    }

    /// Gives a reader that reaches its own queue only when it steps one step to take.
    ///
    /// The key is one the editor has a binding for, because that is where this package's own
    /// wrapper sits, and one whose binding moves the cursor and touches nothing else. A person at
    /// the keyboard gives the reader the same step by typing at all.
    ///
    /// [`STEP`] is how long the step lasts, not how long the key has to reach the terminal: the
    /// key is typed inside the same window as anything else this session types, because a terminal
    /// that is slow to take a keystroke is a different failure from a reader that will not step.
    pub fn nudge(&mut self) {
        let deadline = self.deadline_for(REPLY);
        self.nudge_before(deadline.0);
    }

    /// Gives the reader that step, and is over by `deadline` whatever happens.
    fn nudge_before(&mut self, deadline: Instant) {
        // A key typed before the shell has a reader is not a step for it: it goes through the
        // terminal's own line discipline and waits there for the line it is part of.
        if !self.reading || !self.stepping || !dialect(self.package_kind).answers_at_the_next_step {
            return;
        }
        // A caller whose own wait is spent has nothing to give the reader a step for: the condition
        // it was waiting for did not hold, which is what it says next, and a key typed here would
        // reach a prompt the test has already left.
        if Instant::now() >= deadline {
            return;
        }
        self.type_bytes_before(&[0x06], deadline);
        // The step is over before anything is asked of the reader: a key it has not taken yet is
        // input of the person's, and the contract puts that ahead of anything the worker asks for.
        // A caller waiting under a deadline of its own never waits past it for the step, and a
        // budget in force bounds it as well.
        std::thread::sleep(
            self.bounded(deadline.saturating_duration_since(Instant::now()).min(STEP)),
        );
    }

    /// Waits for the reader's answer to one request.
    ///
    /// # Panics
    ///
    /// Panics when the reader does not answer inside [`REPLY`].
    pub fn answer(&mut self, id: RequestId) -> BridgeAnswer {
        let deadline = self.deadline_for(REPLY);
        self.answer_before(id, deadline.0)
    }

    /// Waits for the reader's answer to one request, no later than `deadline`.
    ///
    /// A caller that asks the reader the same thing more than once for one condition gives every
    /// one of those waits the same instant, so the condition is bounded by that instant rather
    /// than by a fresh reply window per request. An answer counts by the instant it came off the
    /// endpoint, so a slow notice does not fail a reader that answered in time, and an answer that
    /// arrived after the deadline is a failure rather than a pass.
    ///
    /// # Panics
    ///
    /// Panics when the reader has not answered by `deadline`, and when what it sent arrived after
    /// it.
    pub fn answer_before(&mut self, id: RequestId, deadline: Instant) -> BridgeAnswer {
        loop {
            if let Some((arrived, answer)) = self.answers.remove(&id) {
                assert!(
                    arrived <= deadline,
                    "the reader answered request {id:?} {:?} after the deadline of this wait\nterminal output:\n{}",
                    arrived.saturating_duration_since(deadline),
                    self.terminal_output()
                );
                return answer;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "the reader did not answer request {id:?} before the deadline of this wait\nterminal output:\n{}",
                self.terminal_output()
            );
            self.pump_before(left.min(Duration::from_millis(50)), deadline);
        }
    }

    /// Waits for one answer until `deadline`, for a caller that owns a budget of its own.
    ///
    /// A wait inside a longer wait answers to that one: a deadline of its own would either end the
    /// caller's budget early or run past it, and both are the caller having asked for one thing and
    /// waited for another. An answer counts by the instant it came off the endpoint, as it does for
    /// [`Session::answer_before`]: one that arrived after the deadline is no answer inside it.
    pub fn answer_by(&mut self, id: RequestId, deadline: Deadline) -> Option<BridgeAnswer> {
        loop {
            if let Some((arrived, answer)) = self.answers.remove(&id) {
                return (arrived <= deadline.0).then_some(answer);
            }
            // A bridge that has closed its side sends nothing more, so once every whole frame it
            // did send has been read, no answer is coming, and waiting out the deadline would be
            // waiting for a stream that has ended.
            if deadline.passed() || self.read_to_the_end() {
                return None;
            }
            self.pump_before(deadline.left().min(Duration::from_millis(50)), deadline.0);
        }
    }

    /// Whether the bridge's side of the endpoint has gone and nothing whole it sent is left unread.
    fn read_to_the_end(&self) -> bool {
        (self.shut || self.peer_read_gone) && self.whole_frame_len().is_none()
    }

    /// Publishes a fence the bridge will hold until it is invalidated.
    pub fn publish(&mut self, fence: &EditorFence) {
        self.write_frame(&BridgeFrame::FencePublished(FencePublication::Published(
            fence.clone(),
        )));
    }

    /// Tells the bridge the fence it held has gone.
    pub fn invalidate(&mut self, fence_id: FenceId, reason: WithheldReason) {
        self.write_frame(&BridgeFrame::FencePublished(
            FencePublication::Invalidated {
                fence_id,
                reason,
                state: FenceState::Unfenced,
            },
        ));
    }

    /// Types bytes into the terminal, as a person at the keyboard would.
    ///
    /// # Panics
    ///
    /// Panics when the terminal has not taken them inside [`REPLY`].
    pub fn type_bytes(&mut self, bytes: &[u8]) {
        self.type_bytes_before(bytes, Instant::now() + REPLY);
    }

    /// Types bytes into the terminal, no later than `deadline`.
    ///
    /// # Panics
    ///
    /// Panics when the terminal has not taken them by then. A shell that has stopped reading its
    /// terminal fills the queue behind it, and what that does to a caller waiting for a condition
    /// is what this bound is for: the wait fails at the instant it was given rather than lasting
    /// as long as the shell stays wedged.
    fn type_bytes_before(&mut self, bytes: &[u8], deadline: Instant) {
        if let Err(reason) = self.terminal.write_before(bytes, deadline) {
            panic!("{reason}\nterminal output:\n{}", self.terminal_output());
        }
    }

    /// Types a line and its return, at a prompt where this editor needs one.
    pub fn type_line(&mut self, line: &str) {
        if dialect(self.package_kind).types_at_the_prompt && !line.is_empty() {
            assert!(
                self.wait_for_prompt(),
                "the shell drew no prompt to type {line:?} at:\n{}",
                self.terminal_output()
            );
            // The return goes in once the editor has drawn what was typed, which is where it is
            // reading the terminal itself. Before that the terminal's own line discipline holds
            // the line, and it sends a line feed where the return was.
            let start = self.output.lock().expect("the output lock").len();
            self.type_bytes(line.as_bytes());
            assert!(
                self.wait_for_editor(start),
                "the editor drew nothing for {line:?}:\n{}",
                self.terminal_output()
            );
            self.type_bytes(b"\r");
        } else {
            let mut bytes = line.as_bytes().to_vec();
            bytes.push(b'\r');
            self.type_bytes(&bytes);
        }
        self.mark = self.output.lock().expect("the output lock").len();
    }

    /// Waits for the editor's own drawing to reach the terminal after `start`.
    ///
    /// The sequence is the one this editor puts around every line it draws, and nothing the
    /// terminal echoes by itself contains it.
    fn wait_for_editor(&mut self, start: usize) -> bool {
        const DRAWING: &[u8] = b"\x1b[?25l";
        let deadline = self.deadline_for(REPLY);
        loop {
            {
                let output = self.output.lock().expect("the output lock");
                if find(&output[start.min(output.len())..], DRAWING) {
                    return true;
                }
            }
            if deadline.passed() {
                return false;
            }
            self.pump(Duration::from_millis(10));
        }
    }

    /// Waits until the shell has drawn a prompt that nothing has been typed at yet.
    ///
    /// This is where a person types: a line given to a shell that is still running the last one
    /// reaches the reader through the terminal's own line discipline rather than as the keys it
    /// was typed as. A prompt that never comes is left to the assertion that follows.
    fn wait_for_prompt(&mut self) -> bool {
        let deadline = self.deadline_for(REPLY);
        self.wait_for_prompt_by(deadline)
    }

    /// Waits for that prompt until `deadline`, for a caller that owns a budget of its own.
    fn wait_for_prompt_by(&mut self, deadline: Deadline) -> bool {
        loop {
            {
                let output = self.output.lock().expect("the output lock");
                let mark = self.mark.min(output.len());
                if find(&output[mark..], self.prompt.as_bytes()) {
                    return true;
                }
            }
            if deadline.passed() {
                return false;
            }
            self.pump(Duration::from_millis(25));
        }
    }

    /// Everything the terminal has shown so far.
    #[must_use]
    pub fn terminal_output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().expect("the output lock")).into_owned()
    }

    /// Runs one command through the terminal and waits for what it prints when it has run.
    ///
    /// This is the one way a check here learns that a command finished. Two things make that so.
    /// The marker has to be one the submitted text cannot put on the screen by being echoed, which
    /// [`Session::refuse_an_echoable_marker`] decides; and only what the terminal shows from the
    /// moment the line is submitted counts, so a marker an earlier command printed is not this
    /// one's either.
    ///
    /// # Panics
    ///
    /// Panics when the submitted text could produce the marker by itself.
    pub fn run(&mut self, command: &str, marker: &str) -> bool {
        let deadline = self.deadline_for(REPLY);
        self.run_by(command, marker, deadline)
    }

    /// Runs a command of this session's own that prints `marker`, and waits for it.
    ///
    /// This is how a check says "the shell is back at a prompt and answering" without believing
    /// the terminal's echo: [`print_assembled`] builds the word out of pieces, so it appears only
    /// because the command ran.
    pub fn answered(&mut self, marker: &str) -> bool {
        let command = print_assembled(self.package_kind, marker);
        self.run(&command, marker)
    }

    /// Runs one command for a caller that owns a budget of its own.
    ///
    /// # Panics
    ///
    /// Panics when the submitted text could produce the marker by itself.
    pub fn run_by(&mut self, command: &str, marker: &str, deadline: Deadline) -> bool {
        Self::refuse_an_echoable_marker(command, marker);
        let start = self.written();
        self.type_line(command);
        self.wait_for_output_after_by(start, marker, deadline)
    }

    /// Submits a command whose completion is read later, for a check that watches what happens in
    /// between.
    ///
    /// The marker is refused here, on the way in, and the boundary is taken here too, so a check
    /// that reads the events of a running command gets the same guarantee as one that waits for it
    /// straight away.
    ///
    /// # Panics
    ///
    /// Panics when the submitted text could produce the marker by itself.
    pub fn submit(&mut self, command: &str, marker: &str) -> PendingCommand {
        Self::refuse_an_echoable_marker(command, marker);
        let start = self.written();
        self.type_line(command);
        PendingCommand {
            start,
            marker: marker.to_owned(),
        }
    }

    /// Waits for the command [`Session::submit`] left running to print what it prints when it has
    /// run.
    pub fn finished(&mut self, pending: &PendingCommand) -> bool {
        let deadline = self.deadline_for(REPLY);
        self.wait_for_output_after_by(pending.start, &pending.marker, deadline)
    }

    /// Submits the rest of a line that is already part typed and waits for what the whole prints.
    ///
    /// A line submitted in pieces is still one line to the terminal that echoes it, so the marker
    /// is checked against everything that has been submitted rather than against this call's own
    /// piece: `already` is what was typed before and `rest` is what completes it.
    ///
    /// # Panics
    ///
    /// Panics when the submitted text could produce the marker by itself.
    pub fn finish_line(&mut self, already: &str, rest: &str, marker: &str) -> bool {
        Self::refuse_an_echoable_marker(&format!("{already}{rest}"), marker);
        let deadline = self.deadline_for(REPLY);
        let start = self.written();
        self.type_line(rest);
        self.wait_for_output_after_by(start, marker, deadline)
    }

    /// Refuses a marker the submitted text alone could put on the screen.
    ///
    /// The terminal echoes what is typed at it and the editor redraws the line as it is edited, so
    /// any run of characters in the submitted text can reach the screen, and a redraw can put the
    /// end of one copy of the line next to the start of the next. A marker that survives this is
    /// one the screen can show only because something ran.
    ///
    /// # Panics
    ///
    /// Panics on such a marker, which is a check that would pass against a shell that ran nothing.
    fn refuse_an_echoable_marker(submitted: &str, marker: &str) {
        assert!(
            !the_echo_could_draw(submitted, marker),
            "{submitted:?} can put {marker:?} on the screen by being echoed or redrawn, so \
             waiting for it would say the command ran whether it ran or not; print the marker \
             from pieces the command puts together instead"
        );
    }

    /// Watches the terminal for something drawn after `start`, as a display observation.
    ///
    /// Two checks here are about what the screen shows rather than about a command having
    /// finished: the hint the bridge prints, and the text a customisation's own binding writes
    /// into the line. They read the screen through this, which carries no completion meaning and
    /// cannot be made to carry one — there is no method on [`DisplayObservation`] that says a
    /// command ran.
    pub fn drew_after(&mut self, start: usize, text: &str, within: Duration) -> DisplayObservation {
        let deadline = Deadline::after(self.bounded(within));
        DisplayObservation {
            drawn: self.wait_for_output_after_by(start, text, deadline),
        }
    }

    /// True while the shell is still running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// The status the shell exited with, where it has exited.
    pub fn exit_status(&mut self) -> Option<portable_pty::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Whether the bridge's side of the endpoint is still there, both ways.
    ///
    /// A write that found the peer gone and a read that reached the end of the stream are separate
    /// answers, and either one is the endpoint no longer being whole.
    #[must_use]
    pub fn endpoint_open(&self) -> bool {
        endpoint_break(self.shut, self.peer_write_gone, self.peer_read_gone).is_none()
    }

    /// Which side of the endpoint has gone, for a failure that says so.
    #[must_use]
    pub fn endpoint_state(&self) -> &'static str {
        endpoint_break(self.shut, self.peer_write_gone, self.peer_read_gone).unwrap_or("whole")
    }

    /// Ends the endpoint the way a worker that has gone would.
    ///
    /// Nothing is written or read afterwards: the worker is gone, and what the shell does from
    /// here is what it does on its own.
    pub fn close_endpoint(&mut self) {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .expect("the endpoint closes");
        self.shut = true;
    }
}

/// Whether the screen could show `marker` from `submitted` alone, with nothing having run.
///
/// The terminal echoes what is typed at it and the editor redraws the line as it is edited, so any
/// run of characters in the submitted text can reach the screen, and a redraw can put the end of
/// one copy of the line against the start of the next. An empty marker is refused outright: it
/// matches everything, so a check waiting for one waits for nothing.
///
/// A line submitted in pieces is one line to the terminal, so `submitted` is everything that was
/// typed rather than the last piece of it.
#[must_use]
pub fn the_echo_could_draw(submitted: &str, marker: &str) -> bool {
    marker.is_empty() || format!("{submitted}{submitted}").contains(marker)
}

/// A command that was submitted and whose completion has not been read yet.
///
/// It carries the boundary the answer is looked for after, so what an earlier command printed is
/// never mistaken for this one's.
pub struct PendingCommand {
    start: usize,
    marker: String,
}

/// Something the terminal drew, which is not evidence that any command finished.
///
/// A check that watches the screen gets one of these. It answers the one question it is for and
/// nothing else, so a completion check cannot be built out of it by accident: what says a command
/// ran is [`Session::run`], which submits the line itself and refuses a marker the echo could
/// produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct DisplayObservation {
    drawn: bool,
}

impl DisplayObservation {
    /// Whether the terminal drew it, which says nothing about any command having finished.
    #[must_use]
    pub fn was_drawn(self) -> bool {
        self.drawn
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // The terminal keeps being read while the shell goes away: a process whose last bytes have
        // nowhere to go cannot finish leaving, and a session that cannot be torn down would hold
        // up every test after it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        self.stopped.store(true, Ordering::Relaxed);
        // The thread's read ends when the last handle on the other side of the terminal is closed,
        // which is the shell going away above. The wait is bounded: a shell whose own children
        // still hold that terminal would otherwise hold up every case after this one, and a thread
        // that outlives its session is a smaller problem than a suite that cannot be torn down.
        let _ = self.stopped_reading.recv_timeout(READER_STOP);
    }
}

/// What one event is called, for a record that says what was seen.
#[must_use]
pub fn name_of_event(event: &BridgeEvent) -> &'static str {
    name_of(event)
}

fn name_of(event: &BridgeEvent) -> &'static str {
    match event {
        BridgeEvent::EditorEnter(_) => "editor_enter",
        BridgeEvent::EditorLeave(_) => "editor_leave",
        BridgeEvent::ReaderIdle(_) => "reader_idle",
        BridgeEvent::EofDetach(_) => "eof_detach",
        BridgeEvent::CommandAccepted(_) => "command_accepted",
        BridgeEvent::CommandResolve(_) => "command_resolve",
        BridgeEvent::CommandBlock(_) => "command_block",
        BridgeEvent::GestureChanged(_) => "gesture_changed",
        BridgeEvent::PreEofConsumed(_) => "pre_eof_consumed",
        BridgeEvent::HooksActivated(_) => "hooks_activated",
        BridgeEvent::IntegrationLost(_) => "integration_lost",
    }
}

/// The terminal's input side: one writer, and a thread that types on it.
///
/// A pseudo-terminal's input queue is the shell's to drain, so a shell that has stopped reading
/// fills it, and a write into a full queue waits inside a system call, where no clock of the
/// caller's can reach it. What a session types therefore goes to a thread of its own, in the order
/// it was asked for, and the caller waits for the answer that its bytes went in rather than for the
/// write: that wait ends at the caller's deadline whatever the terminal is doing. Bytes a caller
/// stopped waiting for may still reach the shell afterwards, by which time that caller has already
/// failed its test.
///
/// What the terminal answers the editor with does not go through that thread: [`answer_now`] takes
/// the writer directly, because an editor that asked where the cursor is waits only briefly for the
/// answer and reads a late one as keys a person typed.
///
/// [`answer_now`]: TerminalInput::answer_now
struct TerminalInput {
    typing: mpsc::Sender<Typing>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
}

/// Bytes to type, and where to say that they went in.
struct Typing {
    bytes: Vec<u8>,
    typed: mpsc::Sender<Result<(), String>>,
}

impl TerminalInput {
    /// Takes the terminal's input side and starts the thread that types on it.
    fn of(writer: Box<dyn Write + Send>) -> Self {
        let writer = Arc::new(Mutex::new(writer));
        let typing_on = Arc::clone(&writer);
        let (typing, asked) = mpsc::channel::<Typing>();
        std::thread::spawn(move || {
            while let Ok(next) = asked.recv() {
                let outcome = match typing_on.lock() {
                    Ok(mut writer) => writer
                        .write_all(&next.bytes)
                        .and_then(|()| writer.flush())
                        .map_err(|error| format!("the terminal refused input: {error}")),
                    Err(_) => Err("the terminal's writer was left broken".to_owned()),
                };
                let _ = next.typed.send(outcome);
            }
        });
        Self { typing, writer }
    }

    /// Types `bytes`, and says by `deadline` whether they went in.
    fn write_before(&self, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        let (typed, done) = mpsc::channel();
        self.typing
            .send(Typing {
                bytes: bytes.to_vec(),
                typed,
            })
            .map_err(|_| "the terminal's writer has gone".to_owned())?;
        match done.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "the terminal did not take {} bytes of input before the deadline of this wait",
                bytes.len()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("the terminal's writer has gone".to_owned())
            }
        }
    }

    /// Answers a query the editor is waiting on, from the thread that read it.
    fn answer_now(&self, bytes: &[u8]) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_all(bytes);
            let _ = writer.flush();
        }
    }
}

/// Answers the queries a terminal is expected to answer while an editor draws a prompt.
///
/// An editor that asks where the cursor is and waits for the reply cannot start its read loop
/// until something answers, so this terminal answers rather than leaving it waiting. It answers on
/// this thread, the one that read the query: an answer that arrives after the editor has stopped
/// waiting for it is read as keys a person typed, and the prompt the test then types at is not the
/// one it thinks.
fn answer_terminal_queries(bytes: &[u8], terminal: &TerminalInput) {
    let mut reply: Vec<u8> = Vec::new();
    if find(bytes, b"\x1b[6n") {
        reply.extend_from_slice(b"\x1b[1;1R");
    }
    if find(bytes, b"\x1b[c") || find(bytes, b"\x1b[0c") {
        reply.extend_from_slice(b"\x1b[?6c");
    }
    if find(bytes, b"\x1b]11;?") {
        reply.extend_from_slice(b"\x1b]11;rgb:0000/0000/0000\x1b\\");
    }
    if reply.is_empty() {
        return;
    }
    terminal.answer_now(&reply);
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn accept_within(listener: &UnixListener, within: Duration) -> Option<UnixStream> {
    let deadline = Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accepting the bridge: {error}"),
        }
    }
}

/// The user the endpoint belongs to, which is the only one it serves.
fn endpoint_owner(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path).map(|data| data.uid()).unwrap_or(0)
}

fn placeholder_hello(session_id: SessionId) -> BridgeHello {
    BridgeHello {
        protocol: BRIDGE_PROTOCOL.to_owned(),
        session_id,
        shell_process: ProcessStartIdentity::new(
            0,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            0,
        ),
        shell: kr_shell_integration::contract::transport::ShellIdentity {
            kind: ShellKind::Zsh,
            executable: String::new(),
            upstream_version: String::new(),
            editor_abi: String::new(),
            integration_version: String::new(),
            patches: Vec::new(),
            modules: Vec::new(),
        },
        abi: BridgeAbi::qualified(ShellKind::Zsh),
        proof: Bytes::new(Vec::new()),
    }
}

fn placeholder_accept(session_id: SessionId) -> BridgeAccepted {
    BridgeAccepted {
        protocol: BRIDGE_PROTOCOL.to_owned(),
        session_id,
        editor_abi: String::new(),
        hold_ms: DurationMs::new(0),
        gesture: kr_shell_integration::contract::events::EofGesture::default(),
        hint: DETACH_HINT.to_owned(),
        secret_location:
            kr_shell_integration::contract::transport::SecretLocation::PrivateIntegrationState,
        unexport: Vec::new(),
    }
}

/// Every committed scenario that names this shell.
#[must_use]
pub fn scenarios_for(kind: ShellKind) -> Vec<Scenario> {
    scenarios()
        .into_iter()
        .filter(|scenario| scenario.shells.contains(&kind))
        .collect()
}

/// Replays one scenario against the contract and returns what did not hold.
#[must_use]
pub fn contract_failures(scenario: &Scenario) -> Vec<String> {
    replay(scenario).failures
}

/// Builds a fence for the reader an `editor_enter` describes.
#[must_use]
pub fn fence_for(
    enter: &RootEditorEnterParams,
    fence_id: FenceId,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
) -> EditorFence {
    EditorFence {
        fence_id,
        root_process: enter.root_process.clone(),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
        input_epoch: epoch,
        originating_attachment: attachment,
    }
}

/// The identifiers the tests use, so a failure names something recognisable.
#[must_use]
pub fn fence_id(index: u8) -> FenceId {
    FenceId::new(Uuid::from_bytes([0xF0u8.wrapping_add(index); 16]))
}

#[must_use]
pub fn attachment_id(index: u8) -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([0xA0u8.wrapping_add(index); 16]))
}

#[must_use]
pub fn epoch(value: u64) -> InputLeaseEpoch {
    InputLeaseEpoch::new(value)
}

/// The refusal a worker sends when it will not act on a detach.
#[must_use]
pub fn detach_refusal() -> EventOutcome {
    EventOutcome::Refused(ProtocolError::new(
        ErrorCode::EditorBusy,
        "the fence this detach names is not the one the worker holds",
    ))
}

/// What a worker answers an accepted detach with.
#[must_use]
pub fn detached(attachment: AttachmentId) -> EventOutcome {
    EventOutcome::Detached(RootEofDetachResult {
        detached_attachment: attachment,
        state: FenceState::Unfenced,
        discarded_input_bytes: U64::new(0),
    })
}

/// Reads the `editor_enter` out of an event.
///
/// # Panics
///
/// Panics when the event is something else.
#[must_use]
pub fn as_enter(event: &BridgeEvent) -> &RootEditorEnterParams {
    match event {
        BridgeEvent::EditorEnter(params) => params,
        other => panic!("expected an editor entry, got {}", name_of(other)),
    }
}

/// The prompt generation and reader revision of an entry.
#[must_use]
pub fn reader_of(enter: &RootEditorEnterParams) -> (PromptGeneration, ReaderRevision) {
    (enter.prompt_generation, enter.reader_revision)
}

/// A buffer revision one step on from the one an entry reported.
#[must_use]
pub fn next_revision(revision: EditorBufferRevision) -> EditorBufferRevision {
    EditorBufferRevision::new(revision.get() + 1)
}

/// Where a test writes evidence a reader can be checked against later.
///
/// Every run has one, because evidence is part of what a run concludes: a case whose record went
/// nowhere would still say what it proved while nothing kept what it narrowed. A run that names
/// none writes to a directory of its own in the system's temporary directory, which is where
/// section 27 puts a test run's artefacts when nothing names a place for them.
///
/// That directory is made once, under a name nothing else has, and kept. A name taken from
/// something the system hands out again, such as a process identifier, would let this run write
/// into an earlier run's evidence and leave that run's records beside its own.
///
/// # Panics
///
/// Panics when no directory of this run's own can be made.
#[must_use]
pub fn artifact_directory() -> PathBuf {
    if let Some(named) = std::env::var_os("KR_TEST_ARTIFACTS_DIR") {
        return PathBuf::from(named);
    }
    static OWN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    OWN.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("kr-test-artifacts-")
            .tempdir()
            .expect("a directory of this run's own in the system's temporary directory")
            .keep()
    })
    .clone()
}

/// Writes one record of evidence.
///
/// # Panics
///
/// Panics when the record cannot be written: a run whose evidence was lost has not shown what it
/// says it has.
pub fn record(name: &str, body: &str) {
    let directory = artifact_directory();
    std::fs::create_dir_all(&directory).unwrap_or_else(|error| {
        panic!(
            "the evidence directory {} could not be made: {error}",
            directory.display()
        )
    });
    let path = directory.join(name);
    std::fs::write(&path, body)
        .unwrap_or_else(|error| panic!("{} could not be written: {error}", path.display()));
}

/// True when `path` is on the internal disk rather than the workspace volume.
#[must_use]
pub fn outside_workspace(path: &Path) -> bool {
    !path.starts_with("/Volumes/")
}

/// A terminal that is not taking input: a write into it waits, as one into the full input queue of
/// a shell that has stopped reading does.
struct Wedged {
    /// The write waits on this rather than for a length of time, so it is the test that decides
    /// when the terminal starts taking input again.
    until: mpsc::Receiver<()>,
}

impl Write for Wedged {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let _ = self.until.recv();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A shell that has stopped reading its terminal does not hold a wait past the instant it was
/// given, and does not hold the wait behind it either.
///
/// This is the harness's own guarantee rather than a package's, and it is what lets a case bound a
/// whole settlement by one deadline: the typing on the way to the reader is inside that bound. A
/// write into a terminal whose queue is full is a wait inside a system call, so the proof is that
/// the caller comes back from a write that has not returned.
#[test]
fn a_terminal_that_stopped_reading_ends_a_write_at_its_deadline() {
    let (taking, until) = mpsc::channel();
    let terminal = TerminalInput::of(Box::new(Wedged { until }));

    let asked = Instant::now();
    let outcome = terminal.write_before(b"echo kr\r", asked + Duration::from_millis(250));
    let spent = asked.elapsed();
    assert!(
        outcome.is_err(),
        "a terminal that took nothing reported the input as typed"
    );
    assert!(
        spent >= Duration::from_millis(200),
        "the write gave up after {spent:?}, before the deadline it was given, so what ended it was \
         not the deadline"
    );
    assert!(
        spent < Duration::from_secs(5),
        "the write ran for {spent:?}, past the deadline it was given"
    );

    // The step a settlement types next waits for its own answer, not for the write in front of it.
    let stepped = Instant::now();
    let outcome = terminal.write_before(&[0x06], stepped + Duration::from_millis(250));
    let spent = stepped.elapsed();
    assert!(
        outcome.is_err(),
        "a terminal that took nothing reported the step as typed"
    );
    assert!(
        spent < Duration::from_secs(5),
        "the step behind a waiting write ran for {spent:?}, past the deadline it was given"
    );

    // The terminal takes input again, and the writer's thread ends with the session that started
    // it rather than outliving this test.
    drop(taking);
}

mod cases;
mod commands;
mod dialect;
mod inbox;
mod stacks;

// Each test binary that includes this module uses one part of it: the four package suites use the
// cases and the dialects, and the qualification uses the corpus. What the other one does not name
// is still part of the module it shares.
#[allow(unused_imports)]
pub use cases::*;
#[allow(unused_imports)]
pub use commands::*;
pub use dialect::*;
#[allow(unused_imports)]
pub use inbox::*;
#[allow(unused_imports)]
pub use stacks::*;
