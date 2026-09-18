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

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

/// The environment variable that turns a missing package into a failure rather than a skip.
pub const REQUIRE: &str = "KR_REQUIRE_SHELL_PACKAGES";

/// One built package, as `scripts/build-shells.sh` installed it.
pub struct Package {
    pub kind: ShellKind,
    pub identity: String,
    pub executable: PathBuf,
    pub startup_entry: PathBuf,
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
        let identity = std::fs::read_to_string(&pointer)
            .map_err(|error| {
                format!(
                    "{} is not built here ({}: {error}); run scripts/build-shells.sh --{name}",
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
        let startup_entry = directory.join("startup").join(match kind {
            ShellKind::Zsh => "kr-zshrc.zsh",
            ShellKind::Bash => "kr-bashrc.bash",
            ShellKind::Fish | ShellKind::PowerShell => {
                return Err(format!("{name} is not one of this task's packages"));
            }
        });
        Ok(Self {
            kind,
            identity,
            executable,
            startup_entry,
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

/// What the shell's startup file holds: the user's own configuration and the marked block.
fn startup_file(package: &Package, prompt: &str) -> String {
    let entry = std::fs::read_to_string(&package.startup_entry)
        .unwrap_or_else(|error| panic!("{}: {error}", package.startup_entry.display()));
    let user = match package.kind {
        ShellKind::Zsh => format!(
            "# the person's own configuration, which the integration never replaces\n\
             PROMPT='{prompt}'\n\
             setopt no_beep\n\
             unsetopt zle_rprompt_indent 2>/dev/null\n\
             HISTFILE=\n\
             typeset -g KR_TEST_USER_CONFIGURATION=1\n\n"
        ),
        _ => format!(
            "# the person's own configuration, which the integration never replaces\n\
             PS1='{prompt}'\n\
             HISTFILE=\n\
             KR_TEST_USER_CONFIGURATION=1\n\n"
        ),
    };
    format!("{user}{entry}")
}

/// One live session: the worker's endpoint, the shell under a pseudo-terminal, and the frames
/// between them.
pub struct Session {
    pub package_kind: ShellKind,
    pub session_id: SessionId,
    pub hello: BridgeHello,
    pub accepted: BridgeAccepted,
    pub prompt: String,
    stream: UnixStream,
    pending: Vec<u8>,
    events: VecDeque<(RequestId, BridgeEvent)>,
    answers: HashMap<RequestId, BridgeAnswer>,
    next_request: u64,
    output: Arc<Mutex<Vec<u8>>>,
    stopped: Arc<AtomicBool>,
    writer: Box<dyn Write + Send>,
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

        match package.kind {
            ShellKind::Zsh => {
                std::fs::write(home.join(".zshrc"), startup_file(package, &prompt))
                    .expect("the startup file");
            }
            _ => {
                std::fs::write(home.join(".bashrc"), startup_file(package, &prompt))
                    .expect("the startup file");
            }
        }

        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");

        let mut command = CommandBuilder::new(package.executable.to_string_lossy().into_owned());
        command.arg("-i");
        command.cwd(&home);
        command.env("HOME", &home);
        command.env("ZDOTDIR", &home);
        command.env("TERM", "xterm-256color");
        command.env("LANG", "C");
        command.env("KR_SESSION", session_id.to_string());
        command.env("KR_SHELL_BRIDGE", &endpoint.path);
        command.env(
            "KR_SHELL_BRIDGE_SECRET",
            kr_protocol::scalars::to_base64url(&secret),
        );

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
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !finished.load(Ordering::Relaxed) {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(taken) => collected
                        .lock()
                        .expect("the output lock")
                        .extend_from_slice(&buffer[..taken]),
                }
            }
        });
        let writer = pty.master.take_writer().expect("a terminal writer");

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
            stream,
            pending: Vec::new(),
            events: VecDeque::new(),
            answers: HashMap::new(),
            next_request: 1,
            output,
            stopped,
            writer,
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

    /// Sends one frame.
    pub fn write_frame(&mut self, frame: &BridgeFrame) {
        let body = kr_cbor::to_canonical_vec(frame).expect("a frame encodes");
        assert!(
            body.len() <= frame_codec().max_payload_len(),
            "a frame of {} bytes is outside the stream's bound",
            body.len()
        );
        let mut bytes = Vec::with_capacity(4 + body.len());
        bytes.extend_from_slice(
            &u32::try_from(body.len())
                .expect("a bounded frame")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&body);
        let deadline = Instant::now() + REPLY;
        let mut written = 0;
        while written < bytes.len() {
            match self.stream.write(&bytes[written..]) {
                Ok(0) => panic!("the bridge closed the endpoint"),
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "the bridge stopped reading");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("writing to the bridge: {error}"),
            }
        }
    }

    fn read_frame(&mut self, within: Duration) -> Option<BridgeFrame> {
        let deadline = Instant::now() + within;
        loop {
            if self.pending.len() >= 4 {
                let length = u32::from_be_bytes([
                    self.pending[0],
                    self.pending[1],
                    self.pending[2],
                    self.pending[3],
                ]) as usize;
                if self.pending.len() >= 4 + length {
                    let body: Vec<u8> = self.pending[4..4 + length].to_vec();
                    self.pending.drain(..4 + length);
                    // Strict decoding, and the typed value has to re-encode to the same bytes:
                    // this is where a package that wrote its own encoding of the contract's types
                    // is caught, byte for byte.
                    let frame: BridgeFrame =
                        kr_cbor::from_canonical_slice(&body, &kr_cbor::Limits::DEFAULT)
                            .unwrap_or_else(|error| {
                                panic!("a frame is not canonical KR-CBOR-1: {error}")
                            });
                    return Some(frame);
                }
            }
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => return None,
                Ok(taken) => self.pending.extend_from_slice(&buffer[..taken]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("reading from the bridge: {error}"),
            }
        }
    }

    /// Reads whatever has arrived, sorting events from answers and acknowledging what the contract
    /// says needs no decision.
    fn pump(&mut self, within: Duration) {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            let Some(frame) = self.read_frame(Duration::from_millis(20)) else {
                continue;
            };
            match frame {
                BridgeFrame::Event { id, event } => {
                    let outcome = self.routine_answer(&event);
                    if let Some(result) = outcome {
                        self.write_frame(&BridgeFrame::EventResult { id, result });
                    }
                    self.events.push_back((id, event));
                }
                BridgeFrame::Answer { id, answer } => {
                    self.answers.insert(id, answer);
                }
                other => panic!("a bridge sent {other:?}"),
            }
        }
    }

    /// What the worker answers an event that needs no decision of its own.
    fn routine_answer(&self, event: &BridgeEvent) -> Option<EventOutcome> {
        match event {
            BridgeEvent::EditorEnter(_) => {
                Some(EventOutcome::EditorEntered(RootEditorEnterResult {
                    state: FenceState::Unfenced,
                    fence_exchange: Nullable::null(),
                }))
            }
            BridgeEvent::EditorLeave(_) => Some(EventOutcome::EditorLeft(RootEditorLeaveResult {
                state: FenceState::Outside,
            })),
            BridgeEvent::CommandAccepted(params) => {
                Some(EventOutcome::CommandRecorded(RootCommandAcceptedResult {
                    origin: params.origin.clone(),
                    state: FenceState::Fenced,
                }))
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
        let deadline = Instant::now() + REPLY;
        loop {
            if let Some(position) = self.events.iter().position(|(_, event)| accept(event)) {
                self.events.drain(..position);
                return self.events.pop_front().expect("the event is there");
            }
            assert!(
                Instant::now() < deadline,
                "no {what} arrived; the events were {:?}\nterminal output:\n{}",
                self.events
                    .iter()
                    .map(|(_, event)| name_of(event))
                    .collect::<Vec<_>>(),
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
        let deadline = Instant::now() + within;
        loop {
            if let Some(position) = self.events.iter().position(|(_, event)| accept(event)) {
                self.events.drain(..=position);
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump(Duration::from_millis(50));
        }
    }

    /// Drops every event received so far.
    pub fn forget_events(&mut self) {
        self.pump(Duration::from_millis(200));
        self.events.clear();
    }

    /// Answers one event.
    pub fn answer_event(&mut self, id: RequestId, result: EventOutcome) {
        self.write_frame(&BridgeFrame::EventResult { id, result });
    }

    /// Sends one request to the reader thread and returns its identifier.
    pub fn ask(&mut self, request: WorkerRequest) -> RequestId {
        let id = RequestId::new(self.next_request);
        self.next_request += 1;
        self.write_frame(&BridgeFrame::Request { id, request });
        id
    }

    /// Waits for the reader's answer to one request.
    ///
    /// # Panics
    ///
    /// Panics when the reader does not answer inside [`REPLY`].
    pub fn answer(&mut self, id: RequestId) -> BridgeAnswer {
        let deadline = Instant::now() + REPLY;
        loop {
            if let Some(answer) = self.answers.remove(&id) {
                return answer;
            }
            assert!(
                Instant::now() < deadline,
                "the reader did not answer request {id:?}\nterminal output:\n{}",
                self.terminal_output()
            );
            self.pump(Duration::from_millis(50));
        }
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
    pub fn type_bytes(&mut self, bytes: &[u8]) {
        self.writer
            .write_all(bytes)
            .expect("the terminal accepts input");
        self.writer.flush().expect("the terminal flushes");
    }

    /// Types a line and its return.
    pub fn type_line(&mut self, line: &str) {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\r');
        self.type_bytes(&bytes);
    }

    /// Everything the terminal has shown so far.
    #[must_use]
    pub fn terminal_output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().expect("the output lock")).into_owned()
    }

    /// Waits for `needle` to appear in the terminal.
    pub fn wait_for_output(&mut self, needle: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            if self.terminal_output().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump(Duration::from_millis(25));
        }
    }

    /// Runs one command through the terminal and waits for a marker it prints.
    pub fn run(&mut self, command: &str, marker: &str) -> bool {
        self.type_line(command);
        self.wait_for_output(marker, REPLY)
    }

    /// True while the shell is still running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
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
    }
}

fn name_of(event: &BridgeEvent) -> &'static str {
    match event {
        BridgeEvent::EditorEnter(_) => "editor_enter",
        BridgeEvent::EditorLeave(_) => "editor_leave",
        BridgeEvent::ReaderIdle(_) => "reader_idle",
        BridgeEvent::EofDetach(_) => "eof_detach",
        BridgeEvent::CommandAccepted(_) => "command_accepted",
        BridgeEvent::GestureChanged(_) => "gesture_changed",
        BridgeEvent::PreEofConsumed(_) => "pre_eof_consumed",
        BridgeEvent::HooksActivated(_) => "hooks_activated",
        BridgeEvent::IntegrationLost(_) => "integration_lost",
    }
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
    FenceId::new(Uuid::from_bytes([0xF0 + index; 16]))
}

#[must_use]
pub fn attachment_id(index: u8) -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([0xA0 + index; 16]))
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
#[must_use]
pub fn artifact_directory() -> Option<PathBuf> {
    std::env::var_os("KR_TEST_ARTIFACTS_DIR").map(PathBuf::from)
}

/// Writes one line of evidence, when the run asked for it.
pub fn record(name: &str, body: &str) {
    if let Some(directory) = artifact_directory() {
        let _ = std::fs::create_dir_all(&directory);
        let _ = std::fs::write(directory.join(name), body);
    }
}

/// True when `path` is on the internal disk rather than the workspace volume.
#[must_use]
pub fn outside_workspace(path: &Path) -> bool {
    !path.starts_with("/Volumes/")
}

mod cases;

pub use cases::*;
