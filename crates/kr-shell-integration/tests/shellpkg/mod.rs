//! Drives a built managed shell package through the contract, in a real pseudo-terminal.
//!
//! Each test here is the worker's side of one session: it creates the owner-only endpoint, starts
//! the packaged shell under a pseudo-terminal with the two bootstrap variables, answers the
//! handshake with `handshake::admit_observed`, and then asks the reader the three questions the
//! contract puts to it. The expectations come from the committed scenarios under
//! `fixtures/shell-bridge/`, so a package and the worker are checked against one corpus rather than
//! against each other.
//!
//! Nothing a launched process touches is inside the workspace: the shell's executable is the
//! installed package, and its home directory, its runtime directory and its endpoint are all on
//! the internal disk.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use kr_crypto::secret::SymmetricKey;
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
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason, LaunchTransactionId,
    WorkerRequest,
};
use kr_shell_integration::contract::transport::{
    BOOTSTRAP_SECRET_LEN, BRIDGE_PROTOCOL, BridgeAccepted, BridgeEndpoint, BridgeFrame,
    BridgeHello, EventOutcome, HandshakeOutcome, ObservedPeer, WorkerExpectation, frame_codec,
};
use kr_shell_integration::host::{handshake, startup};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// How long a wait for the shell, or for a reader's answer, goes on before a test gives up on it.
///
/// The waits it bounds end when the thing they wait for happens, or sooner when it cannot: a shell
/// that has ended without connecting is found within half a second, and the waits for an event
/// or an answer end at once when the endpoint's stream has ended with nothing whole left in it.
/// So the bound is reached only by a shell that is running and says nothing, and a runner that is
/// slow to start a shell only makes the wait longer. It is far beyond what a loaded machine has
/// taken: a shell started at background priority on a machine with its processors busy took more
/// than twenty seconds to connect, where an idle machine takes a second or two, and the longest
/// whole case of a loaded run took 83 seconds.
pub const REPLY: Duration = Duration::from_secs(240);

/// What a wait goes on for once an earlier wait in this run has given up on a shell that was
/// running and said nothing.
///
/// A package that fails in the same way for every case would otherwise cost [`REPLY`] in each of
/// them, which is longer than the job that runs them, and the failure text libtest prints at the
/// end of a run would be lost with the job. The run is already a failure when this applies, so the
/// cap cannot turn a passing run into a failing one; it can fail a later case that a loaded runner
/// would have let through. A failure of [`Session::expect_event`] after the cap says so.
const REPLY_AFTER_A_GIVE_UP: Duration = Duration::from_secs(20);

/// Whether a wait has given up on a silent shell in this run.
static A_WAIT_GAVE_UP: AtomicBool = AtomicBool::new(false);

/// Notes that a wait gave up on a silent shell, for the waits after it.
///
/// A wait whose running out fails the case notes it itself when its [`REPLY`] window runs out (see
/// [`Deadline::passed`]), whoever asked. A wait whose running out is an answer, not a failure, is
/// made with [`Session::probe_window`] and does not. A wait that reports its own end some other way
/// notes it where it does.
fn note_that_a_wait_gave_up() {
    A_WAIT_GAVE_UP.store(true, Ordering::Relaxed);
}

/// `within`, or [`REPLY_AFTER_A_GIVE_UP`] where that is shorter and a wait has given up already.
fn after_any_give_up(within: Duration) -> Duration {
    if A_WAIT_GAVE_UP.load(Ordering::Relaxed) {
        within.min(REPLY_AFTER_A_GIVE_UP)
    } else {
        within
    }
}

/// Waits until the system says `stream` can be read or written, as `flags` ask, or until `within`
/// has passed, whichever is first.
///
/// This is the wait for a reply, and it is not a sleep that asks again. The system holds a
/// process that runs at background priority to a coarse timer, so that a sleep of two milliseconds
/// takes a hundred, and a loop that sleeps between reads answers a reader that waits a second for
/// its answer late by a measure that says nothing about the code under test. A wait on the
/// stream's readiness returns when the data arrives. A wait that a signal cut short is asked again
/// by the loop around it; any other error is a fault of the harness and is not waited out.
///
/// # Panics
///
/// Panics when the system refuses the wait for a reason other than a signal.
fn wait_until_ready(stream: &impl AsFd, flags: PollFlags, within: Duration) {
    let timeout = Timespec {
        tv_sec: i64::try_from(within.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: within.subsec_nanos().into(),
    };
    let mut watched = [PollFd::new(stream, flags)];
    match poll(&mut watched, Some(&timeout)) {
        Ok(_) | Err(rustix::io::Errno::INTR) => {}
        Err(error) => panic!("waiting for the endpoint to be ready: {error}"),
    }
}

/// Whether `error` is what an operation on the endpoint answers once the shell has gone.
///
/// A shell that ends takes its side of the endpoint with it, and the system says so in more than
/// one form. A write to the closed stream is refused as a broken pipe; a reset is the same state
/// reported as one the shell ended with data of ours unread. macOS can also answer "not
/// connected": a write that meets the close while it is being made gets it, and so does every
/// shutdown of a stream whose peer has closed. This is the one place that lists the forms, for
/// every read, write and shutdown on the endpoint, so that none of them takes a form the others
/// know as a fault of the harness.
fn peer_has_gone(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::NotConnected
    )
}

/// Writes all of `bytes` to the endpoint, waiting for room in it until `deadline`.
///
/// Says [`Delivery::PeerGone`] when the shell's side has gone, in whatever form the system reports
/// it ([`peer_has_gone`]), and [`Stalled`] when the endpoint took nothing more by `deadline`.
///
/// # Panics
///
/// Panics on an error that is not the peer's going: that is a fault of the harness or the system.
fn send_to_bridge<S: Write + AsFd>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
) -> Result<Delivery, Stalled> {
    let mut written = 0;
    while written < bytes.len() {
        match stream.write(&bytes[written..]) {
            Ok(0) => return Ok(Delivery::PeerGone),
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(Stalled);
                }
                wait_until_ready(&*stream, PollFlags::OUT, left);
            }
            Err(error) if peer_has_gone(&error) => return Ok(Delivery::PeerGone),
            Err(error) => panic!("writing to the bridge: {error}"),
        }
    }
    Ok(Delivery::Delivered)
}

/// Ends both directions of the endpoint, as a worker that has gone does. An endpoint whose shell
/// has already gone is ended already.
///
/// # Panics
///
/// Panics on an error that is not the peer's going.
fn shut_the_endpoint(stream: &UnixStream) {
    match stream.shutdown(std::net::Shutdown::Both) {
        Err(error) if !peer_has_gone(&error) => panic!("the endpoint closes: {error}"),
        Ok(()) | Err(_) => {}
    }
}

/// How long the step given to an editor that only reaches its queue when the reader steps lasts.
pub const STEP: Duration = Duration::from_millis(60);

/// How long the PowerShell package's bridge waits for the worker's answer to a question about a
/// command, or to the acceptance of a line, while a case waits for that answer in turn.
///
/// The bridge ships with a second, which is long beside a worker that answers in under a
/// millisecond and the right thing to give up at when a worker has stopped answering. In a case
/// the worker is this harness, and a runner that does not run the shell or the harness for a
/// second leaves an answer unread by a measure that says nothing about the package: the command
/// runs as it was typed and the case fails. So a case lets the bridge wait for the answer as long
/// as a case waits for anything, set in the bridge's own variable from the person's profile, and a
/// case in which the worker is silent by design gives a shorter wait back with
/// [`Session::lets_the_bridge_give_up_on_a_question`].
const PATIENT_ANSWER_WAIT_MS: u32 = 120_000;

/// How long the bridge waits for an answer in a case that holds one back until the harness has done
/// something that no pace of the harness's can delay past the wait.
///
/// The harness gives up on any of its own waits at [`REPLY`] and fails its case, so a bridge that
/// waits for longer than that is still waiting at every moment at which the harness is still going.
const WAIT_BEYOND_ANY_REPLY_MS: u32 = 600_000;

/// How long the PowerShell package's module waits for the worker's answer to its hello.
///
/// The module ships with five seconds, which is long beside a worker that answers in under a
/// millisecond. In a case the worker is this harness, and a runner that does not run the harness
/// or the shell for five seconds between the hello and the answer fails every case on a handshake
/// that says nothing about the package. The module takes a longer wait from the environment, before
/// it has run a line of the profile, so a case gives it the wait that a case gives any answer.
const PATIENT_HANDSHAKE_WAIT_MS: u32 = 120_000;

/// How long the bridge waits in a case in which the worker never answers something. What the case
/// observes is the wait running out, which a stalled runner only lengthens; but the worker still
/// answers every other line in that window, and those answers have to be read inside it. Ten
/// seconds is ten times the second that failed when the harness polled on a timer a runner at
/// background priority stretched to a hundred milliseconds, and the harness now reads on the
/// endpoint's readiness, in well under a millisecond.
const SILENT_WORKER_ANSWER_WAIT_MS: u32 = 10_000;

/// PowerShell that sets the bridge's wait for an answer, where the bridge is loaded and nowhere
/// else, and leaves nothing behind in the session's scope.
fn set_answer_wait(milliseconds: u32) -> String {
    format!(
        "& {{ $kr_bridge = Get-Module KalaReach.ShellBridge; if ($kr_bridge) {{ & $kr_bridge {{ \
         $script:KR_ANSWER_WAIT_MS = {milliseconds} }} }} }}"
    )
}

/// PowerShell that sets the bridge's wait for an answer and prints what the bridge holds after it,
/// as `kr-answer-wait-` and the number of milliseconds, nothing at all of it where the bridge is
/// not loaded. The marker is put together by the line, so the echo of the line cannot print it.
fn set_answer_wait_and_say(milliseconds: u32) -> String {
    format!(
        "& {{ $kr_bridge = Get-Module KalaReach.ShellBridge; $kr_wait = if ($kr_bridge) {{ \
         & $kr_bridge {{ $script:KR_ANSWER_WAIT_MS = {milliseconds}; $script:KR_ANSWER_WAIT_MS }} \
         }} else {{ 'unloaded' }}; Write-Output ('kr-answer-wait-' + $kr_wait) }}"
    )
}

/// PowerShell that has the next command lookup of `command`, typed at the prompt, set the
/// bridge's wait for an answer to `milliseconds`, and prints `kr-lookup-armed` once it is in place.
///
/// The line the lookup belongs to has by then been accepted: the bridge asked for its acceptance
/// answer, and waited for it, under the wait the session had. The question the lookup leads to is
/// asked under the wait this sets. So a case in which the worker leaves a question unanswered gives
/// the acceptance of that line the long wait, which the harness answers inside, and the short one
/// only to the question it leaves. The handler goes at its first use, and the marker is put
/// together by the line, so the echo of the line cannot print it.
fn set_answer_wait_at_the_lookup_of(command: &str, milliseconds: u32) -> String {
    format!(
        "& {{ $kr_bridge = Get-Module KalaReach.ShellBridge; if ($kr_bridge) {{ \
         $global:KR_LOOKUP_BRIDGE = $kr_bridge; \
         $ExecutionContext.InvokeCommand.PreCommandLookupAction = {{ param($name, $lookup) \
         if ($name -ceq '{command}' -and \"$($lookup.CommandOrigin)\" -ceq 'Runspace') {{ \
         $ExecutionContext.InvokeCommand.PreCommandLookupAction = $null; \
         & $global:KR_LOOKUP_BRIDGE {{ $script:KR_ANSWER_WAIT_MS = {milliseconds} }} }} }}; \
         Write-Output ('kr-look' + 'up-armed') }} }}"
    )
}

/// PowerShell that prints what the bridge's wait for an answer holds, as
/// [`set_answer_wait_and_say`] does after it sets it.
fn read_answer_wait_and_say() -> String {
    "& { $kr_bridge = Get-Module KalaReach.ShellBridge; $kr_wait = if ($kr_bridge) { \
     & $kr_bridge { $script:KR_ANSWER_WAIT_MS } } else { 'unloaded' }; \
     Write-Output ('kr-answer-wait-' + $kr_wait) }"
        .to_owned()
}

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
///
/// The second member says whether the moment ends a whole [`REPLY`] window whose running out fails
/// the case, the wait for a shell that is expected to answer. Such a deadline notes it when it
/// passes, so the waits after it are held to [`REPLY_AFTER_A_GIVE_UP`] however the caller reports
/// the failure. The deadline of a probe for something that must not happen, which is a few hundred
/// milliseconds, does not, and neither does a [`Session::probe_window`], whose length is a whole
/// [`REPLY`] but whose running out is an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(Instant, bool);

impl Deadline {
    /// The moment `budget` from now.
    #[must_use]
    pub fn after(budget: Duration) -> Self {
        Self(Instant::now() + budget, false)
    }

    /// The moment a caller fixed itself.
    #[must_use]
    pub fn at(moment: Instant) -> Self {
        Self(moment, false)
    }

    /// Whether that moment has arrived.
    ///
    /// A [`REPLY`] window that has run out is noted here.
    #[must_use]
    pub fn passed(self) -> bool {
        let over = Instant::now() >= self.0;
        if over && self.1 {
            note_that_a_wait_gave_up();
        }
        over
    }

    /// How much of the budget is left, which is nothing once it has passed.
    #[must_use]
    pub fn left(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// The earlier of two moments, which is the one a nested wait answers to.
    #[must_use]
    pub fn earlier(self, other: Self) -> Self {
        if other.0 < self.0 { other } else { self }
    }

    /// The end of a wait of `within` for a shell that is expected to answer.
    ///
    /// It is a [`REPLY`] window when `within` is that long, and one that ran out is a shell that
    /// said nothing for that long. A shorter wait is a probe, which a deliberate silence ends.
    fn reply_window(within: Duration) -> Self {
        Self(Instant::now() + after_any_give_up(within), within >= REPLY)
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

/// The bridge took nothing more of a write before the deadline the write was given: the shell is
/// not reading its end of the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stalled;

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
    /// The package's own directory: its record, its module tree and its startup entry.
    ///
    /// # Panics
    ///
    /// Panics when the module tree is not inside a directory, which no package's is.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.module_directory
            .parent()
            .expect("a package's module tree is inside the package")
    }

    /// What starting this package's shell sets over this process's own environment: the runtime
    /// location the record holds and the package's module directory first on the list of module
    /// directories. The package's own reader of its record decides it, as a session's worker does.
    ///
    /// # Panics
    ///
    /// Panics when the host cannot read the package it was just handed.
    #[must_use]
    pub fn launch(&self) -> Vec<(String, String)> {
        let package = kr_shell_integration::host::package::ShellPackage::read(self.directory())
            .unwrap_or_else(|fault| {
                panic!(
                    "the host cannot read {}: {fault}",
                    self.directory().display()
                )
            });
        let base: Vec<(String, String)> = std::env::vars().collect();
        package.launch_environment(&base, cfg!(windows))
    }

    /// The package's host as the PowerShell this host asks about profiles, started the way a session
    /// starts it.
    #[must_use]
    pub fn powershell(&self) -> startup::PowerShell {
        startup::PowerShell {
            executable: self.executable.clone(),
            environment: self.launch(),
        }
    }

    /// The package's shell as a command to run, started the way a session starts it.
    #[must_use]
    pub fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.executable);
        command.envs(self.launch());
        command
    }

    /// Runs `script` in the package's host with no profile and no terminal, started the way a
    /// session starts it, and returns what the host did.
    ///
    /// No bridge is in the host's environment, so a module imported by the script finds none to
    /// open. This is the one way a case asks the package's host something outside a session: a host
    /// started by its path alone loses the runtime location the record holds, and a framework-dependent
    /// one then does not start.
    ///
    /// # Panics
    ///
    /// Panics when the host cannot be started.
    #[must_use]
    pub fn ask(&self, script: &str) -> std::process::Output {
        self.command()
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env_remove("KR_SHELL_BRIDGE")
            .env_remove("KR_SHELL_BRIDGE_SECRET")
            .env_remove("KR_SESSION")
            .output()
            .expect("the package's host runs")
    }

    /// Runs the script `script_for` writes in the package's host on a terminal of its own, and
    /// once the script has printed `marker`, types `typed` at that terminal. Returns what the
    /// terminal showed once the host had ended.
    ///
    /// What is typed stays in the terminal's queue until the script reads it, and a script that
    /// reads nothing leaves all of it there for as long as it runs. A terminal is read in lines
    /// until a program says otherwise, so `typed` is a line.
    ///
    /// `script_for` is given the path of a file that this makes once `typed` is in the terminal's
    /// queue, so that a script which counts the queue can wait for the file rather than for a
    /// length of time the harness would have to beat. The script is the one that bounds the wait,
    /// and it is bounded by [`REPLY`], as the harness's own are.
    ///
    /// # Panics
    ///
    /// Panics when the host cannot be started, or has not printed `marker` or ended in time.
    #[cfg(unix)]
    #[must_use]
    pub fn ask_with_input_typed_after(
        &self,
        script_for: impl FnOnce(&Path) -> String,
        marker: &str,
        typed: &[u8],
    ) -> String {
        let directory = tempfile::Builder::new()
            .prefix("kr-shell-typed-")
            .tempdir()
            .expect("a directory for the file that says the input is typed");
        let typed_flag = directory.path().join("typed");
        let script = script_for(&typed_flag);
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");
        let mut command = CommandBuilder::new(&self.executable);
        command.args(["-NoLogo", "-NoProfile", "-Command", &script]);
        for (name, value) in self.launch() {
            command.env(name, value);
        }
        for name in ["KR_SHELL_BRIDGE", "KR_SHELL_BRIDGE_SECRET", "KR_SESSION"] {
            command.env_remove(name);
        }
        command.env("TERM", "xterm-256color");
        let mut child = pty
            .slave
            .spawn_command(command)
            .expect("the package's host starts");
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader().expect("a terminal reader");
        let mut writer = pty.master.take_writer().expect("a terminal writer");
        let shown = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&shown);
        let thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(taken) = reader.read(&mut buffer) {
                if taken == 0 {
                    break;
                }
                collected
                    .lock()
                    .expect("the output lock")
                    .extend_from_slice(&buffer[..taken]);
            }
        });
        let text = || String::from_utf8_lossy(&shown.lock().expect("the output lock")).into_owned();
        let window = after_any_give_up(REPLY);
        let deadline = Instant::now() + window;
        while !text().contains(marker) {
            if Instant::now() >= deadline {
                note_that_a_wait_gave_up();
                let _ = child.kill();
                panic!("the host did not print {marker:?}:\n{}", text());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        writer.write_all(typed).expect("types at the terminal");
        writer.flush().expect("flushes the terminal");
        // The input is in the terminal's queue: a script that waits for this file counts it.
        std::fs::write(&typed_flag, b"").expect("the file that says the input is typed");
        while child.try_wait().expect("the host's state").is_none() {
            if Instant::now() >= deadline + window {
                note_that_a_wait_gave_up();
                let _ = child.kill();
                panic!("the host did not end:\n{}", text());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(writer);
        drop(pty.master);
        let _ = thread.join();
        text()
    }

    /// Finds this tree's own built package, or says why it is not there.
    ///
    /// The installation's `current` names a build, and a build is named by a digest of what it was
    /// built from, so the build it names is this tree's only when this tree's inputs are the ones it
    /// was built from. A build of other inputs, left by a build of another tree, is not this tree's
    /// package, and a suite that drove it would be testing somebody else's patches.
    ///
    /// # Errors
    ///
    /// Returns why this tree's package is not here.
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
        identity::this_trees(kind, &identity, &record).map_err(|reason| {
            format!(
                "{} names {name} {identity}, which is not this tree's package: {reason}; {how}",
                pointer.display()
            )
        })?;
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

    /// Returns this tree's built package, for a check that drives it.
    ///
    /// Every check that drives a package is left out of an ordinary run, which has no packages, and
    /// runs with `--include-ignored` where the packages have been built: continuous integration's
    /// shell-packages job, `scripts/e2e-fence.sh` and the build box's verification. A run that
    /// includes it has said the packages are there, so one that is not fails and says why.
    ///
    /// # Panics
    ///
    /// Panics when this tree's package is not here.
    #[must_use]
    pub fn built(kind: ShellKind) -> Self {
        Self::find(kind).unwrap_or_else(|reason| {
            panic!(
                "this check drives this tree's built {} package, which is not here: {reason}",
                kind.as_str()
            )
        })
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

/// What a case adds to the person's own startup, beside the configuration every case has.
#[derive(Clone, Copy)]
pub struct Profile<'a> {
    /// Text that runs after the person's own configuration and before the package's entry, in
    /// the file that configuration is in.
    pub after_configuration: &'a str,
    /// Whether the package's own marked entry is installed at all.
    pub entry: bool,
    /// Text that runs once the package's entry has been installed: after it in the file, or, for
    /// PowerShell, in the profile its own host reads, which runs after the first profile's entry
    /// that loads the bridge and before the last profile's entry that checks the reader.
    pub after_entry: &'a str,
    /// What the person keeps in the PowerShell profile that every host reads, which runs before the
    /// profile its own host reads. Nothing for the other shells.
    pub all_hosts: &'a str,
    /// The end-of-file character the person's terminal has when the shell starts, as `stty` spells
    /// it. A terminal setting the person changes from inside the shell does not outlast the
    /// command that changed it in every editor, so this is set before the shell is started.
    pub terminal_eof: Option<&'a str>,
}

impl Profile<'_> {
    /// The startup every case without a profile of its own has: the configuration and the entry.
    pub const ORDINARY: Profile<'static> = Profile {
        after_configuration: "",
        entry: true,
        after_entry: "",
        all_hosts: "",
        terminal_eof: None,
    };
}

/// Writes the person's configuration and the package's own marked entry where the shell reads
/// them, in the layout the package's manifest names.
fn install_startup(package: &Package, home: &Path, prompt: &str, profile: Profile<'_>) {
    let user = format!(
        "{}{}",
        user_configuration(package.kind, prompt),
        profile.after_configuration
    );
    let entry = if package.kind == ShellKind::PowerShell {
        // Written below through the installer, which is how this shell's entry gets in.
        String::new()
    } else if profile.entry {
        format!("{}{}", startup_entry(package), profile.after_entry)
    } else {
        profile.after_entry.to_owned()
    };
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
            if profile.entry {
                std::fs::write(config.join("conf.d").join("kr-kalareach.fish"), entry)
                    .expect("the startup entry");
            }
        }
        ShellKind::PowerShell => {
            let config = home.join(".config").join("powershell");
            std::fs::create_dir_all(&config).expect("a configuration directory");
            let all_hosts = config.join("profile.ps1");
            let current_host = config.join("Microsoft.PowerShell_profile.ps1");
            // What the person wrote, in both profiles, before the installer has added to either.
            std::fs::write(&all_hosts, profile.all_hosts).expect("the startup file");
            std::fs::write(&current_host, format!("{user}{}", profile.after_entry))
                .expect("the startup file");
            if profile.entry {
                // The entries go in as `kr shell install` puts them: the one that opens the bridge
                // is the first thing in the first profile and the one that checks the reader is the
                // last thing in the last.
                // The installation's own record keeps its locks, beside the home and not in it.
                let state = home.with_file_name(format!(
                    "{}-install-state",
                    home.file_name().map_or_else(
                        || "home".to_owned(),
                        |name| name.to_string_lossy().into_owned()
                    )
                ));
                let record = startup::EntryRecord::in_state_directory(&state);
                for target in
                    startup::powershell_targets(&package.powershell(), all_hosts, current_host)
                {
                    let body = startup::entry(&target, &package.startup_entry, false)
                        .expect("the package's entry is text");
                    startup::install(&target.path, &body, &target.placement, &record)
                        .expect("the entry goes into the profile");
                }
            }
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
    /// A refusal, which is no detach's and must not be taken for one.
    Refuse,
    /// No answer, and the endpoint closed, as by a worker that went while the shell asked.
    CloseEndpoint,
    /// The worker's own decision for a session with integrations, with a backend it can
    /// establish: an integrated invocation is answered with `launcher`, `environment` and the flags
    /// its integration adds, and every other invocation as the decision says, which is as typed.
    Establishing {
        integrations: Vec<kr_protocol::session::CommandIntegration>,
        launcher: String,
        environment: Vec<kr_protocol::session::EnvironmentVariable>,
    },
    /// A backend whose answer renames the command: the vector it names does not begin with the
    /// name the person typed, which no worker's answer does.
    Renaming { launcher: String },
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
    /// Whether an acceptance goes unanswered while every other event is still answered.
    pub silent_acceptance: bool,
    /// Whether the entry of a reader goes unanswered until a case answers it, while every other
    /// event is still answered.
    pub hold_entries: bool,
    /// The entries held, by the identifier the bridge gave each.
    pub held_entries: Vec<RequestId>,
    /// Frames written ahead of the next answer to a resolve, as a worker's other traffic can be.
    pub before_resolve_answer: Vec<BridgeFrame>,
    /// Frames written ahead of the next answer to an acceptance.
    pub before_acceptance_answer: Vec<BridgeFrame>,
    /// Whether the worker side stops answering anything once it has answered the next resolve.
    pub silent_after_resolve: bool,
    /// The answers and events the bridge sent, together in the order they arrived.
    pub arrivals: Vec<Arrival>,
    /// Set when this side is to close the endpoint once the event in hand has been read.
    close_requested: bool,
    /// Every resolve the bridge asked.
    pub resolves: Vec<kr_protocol::root::RootCommandResolveParams>,
    /// The resolves this side left unanswered, by the identifier the bridge gave each.
    pub unanswered: Vec<RequestId>,
    /// Every command block the bridge reported.
    pub blocks: Vec<kr_protocol::root::RootCommandBlockParams>,
    /// The capability each acceptance was answered with.
    pub tokens: Vec<Option<String>>,
    /// Every acceptance the bridge reported.
    pub accepted: Vec<kr_protocol::root::RootCommandAcceptedParams>,
    /// Every reader entry the bridge reported.
    pub entries: Vec<RootEditorEnterParams>,
}

/// One frame the bridge sent, as the order of arrival needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// The reader's answer to a request.
    Answer(RequestId),
    /// An event, by its name on the wire.
    Event(&'static str),
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

/// The text a shell is told for `path`, such as the endpoint it connects to.
///
/// The endpoint travels as text, in the shell's environment and in the contract, so a path that
/// is not text cannot be told to a shell: a lossy copy names another path, and the shell would
/// connect to one nothing is bound at. Such a path is refused with the reason instead.
///
/// # Panics
///
/// Panics when `path` is not UTF-8.
#[must_use]
pub fn told(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| {
            panic!(
                "{} is not UTF-8, so no shell can be told it",
                path.display()
            )
        })
        .to_owned()
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
    /// The other end of the stream of a session that is not managed, held so it stays open.
    _bridge_peer: Option<UnixStream>,
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
    /// How many idle reports the reader has sent, and whether the last one said its buffer was
    /// empty. A report is the reader saying what it holds between two keys, so one that arrives
    /// after a key was typed is about a reader that has dealt with that key.
    idle_reports: u64,
    last_idle_empty: bool,
    /// The reader the last successful probe found inside its read.
    reading_reader: Option<stacks::ReaderMark>,
    pending: Vec<u8>,
    /// What the bridge has sent and no check has taken, with the managed decisions among it
    /// counted as they arrived.
    events: Inbox,
    /// Each answer the reader sent, with the instant it was taken off the endpoint: a wait under a
    /// deadline accepts an answer that arrived inside its window, however late it notices it. The
    /// number is how many readers of this session had entered or left when it arrived.
    answers: HashMap<RequestId, (Instant, BridgeAnswer, u64)>,
    next_request: u64,
    /// What this session answers for the commands a line runs, and what the bridge reported.
    pub commands: Commands,
    output: Arc<Mutex<Vec<u8>>>,
    /// Where in `output` the last cursor query the terminal answered ends.
    cursor_answered: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    /// The reader thread's report that it has stopped, so a session that is torn down does not
    /// leave a thread still writing into what the next case reads.
    stopped_reading: std::sync::mpsc::Receiver<()>,
    terminal: Arc<TerminalInput>,
    child: Box<dyn Child + Send + Sync>,
    _master: Box<dyn MasterPty + Send>,
    _directory: tempfile::TempDir,
}

/// What the worker answers the bridge's opening frame with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeAnswer {
    /// The worker's own decision, which accepts the package under test.
    Accept,
    /// A frame whose body is not a value of the contract at all, which the bridge cannot decode.
    NotDecodable,
    /// The worker's own refusal of a shell whose start time it reads one unit away from the one
    /// the shell named, followed at once by the end of the connection, as the worker ends it.
    Refuse,
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
        Self::start_configured(
            package,
            environment,
            kr_shell_integration::contract::events::EofGesture::default(),
            Profile::ORDINARY,
        )
    }

    /// Starts the packaged shell with `environment` added to what it inherits and `profile` in
    /// the person's startup, and completes the handshake.
    ///
    /// # Panics
    ///
    /// Panics as [`Session::start_with_profile`] does.
    #[must_use]
    pub fn start_with_environment_and_profile(
        package: &Package,
        environment: &[(String, String)],
        profile: Profile<'_>,
    ) -> Self {
        Self::start_configured(
            package,
            environment,
            kr_shell_integration::contract::events::EofGesture::default(),
            profile,
        )
    }

    /// Starts the packaged shell with `profile` in the person's startup, and completes the
    /// handshake.
    ///
    /// # Panics
    ///
    /// Panics as [`Session::start`] does, and so does a shell whose startup asks for input before
    /// its bridge has connected: nothing here types until the handshake is done.
    #[must_use]
    pub fn start_with_profile(package: &Package, profile: Profile<'_>) -> Self {
        Self::start_configured(
            package,
            &[],
            kr_shell_integration::contract::events::EofGesture::default(),
            profile,
        )
    }

    /// Starts the packaged shell, answering its handshake with `gesture` as the key that ends
    /// input.
    ///
    /// # Panics
    ///
    /// Panics as [`Session::start`] does.
    #[must_use]
    pub fn start_with_gesture(
        package: &Package,
        gesture: kr_shell_integration::contract::events::EofGesture,
    ) -> Self {
        Self::start_configured(package, &[], gesture, Profile::ORDINARY)
    }

    fn start_configured(
        package: &Package,
        environment: &[(String, String)],
        gesture: kr_shell_integration::contract::events::EofGesture,
        profile: Profile<'_>,
    ) -> Self {
        Self::start_as(
            package,
            environment,
            gesture,
            profile,
            true,
            HandshakeAnswer::Accept,
        )
    }

    /// Starts the packaged shell and answers its opening frame with one the bridge cannot decode.
    ///
    /// The shell is the person's own shell afterwards, with no worker behind it: what a case
    /// reads from this session is what the bridge made of the answer.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not connect or opens with anything but a hello.
    #[must_use]
    pub fn start_answered_with_a_frame_that_does_not_decode(package: &Package) -> Self {
        Self::start_as(
            package,
            &[],
            kr_shell_integration::contract::events::EofGesture::default(),
            Profile::ORDINARY,
            true,
            HandshakeAnswer::NotDecodable,
        )
    }

    /// Starts the packaged shell and refuses its opening frame the way the worker refuses a shell
    /// whose process it cannot match: with the refusal, and then the end of the connection.
    ///
    /// The shell is the person's own shell afterwards, with no worker behind it: what a case reads
    /// from this session is what the bridge made of the refusal.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not connect, opens with anything but a hello, or the worker's
    /// own decision does not refuse it.
    #[must_use]
    pub fn start_refused(package: &Package) -> Self {
        Self::start_as(
            package,
            &[],
            kr_shell_integration::contract::events::EofGesture::default(),
            Profile::ORDINARY,
            true,
            HandshakeAnswer::Refuse,
        )
    }

    /// Starts the packaged shell as an ordinary shell of a person's: the same binary, the same
    /// startup, and nothing exported that tells it to connect to a bridge.
    ///
    /// It is the baseline a managed session's behaviour is compared with. Nothing here reads or
    /// writes a bridge, so the events, the fences and the frames of a managed session are not
    /// available on it; what it offers is a terminal to type at and read.
    ///
    /// # Panics
    ///
    /// Panics when the shell cannot be started.
    #[must_use]
    pub fn start_unmanaged(
        package: &Package,
        environment: &[(String, String)],
        profile: Profile<'_>,
    ) -> Self {
        Self::start_as(
            package,
            environment,
            kr_shell_integration::contract::events::EofGesture::default(),
            profile,
            false,
            HandshakeAnswer::Accept,
        )
    }

    fn start_as(
        package: &Package,
        environment: &[(String, String)],
        gesture: kr_shell_integration::contract::events::EofGesture,
        profile: Profile<'_>,
        managed: bool,
        answer: HandshakeAnswer,
    ) -> Self {
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
        let endpoint = BridgeEndpoint::unix(told(&endpoint_path));
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
        let secret = bootstrap_secret();

        let patient = format!(
            "{}\n{}",
            set_answer_wait(PATIENT_ANSWER_WAIT_MS),
            profile.after_entry
        );
        let profile = if package.kind == ShellKind::PowerShell && profile.entry {
            Profile {
                after_entry: &patient,
                ..profile
            }
        } else {
            profile
        };
        install_startup(package, &home, &prompt, profile);

        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");

        let mut command = if let Some(eof) = profile.terminal_eof {
            // The terminal is set up first, by the program that sets terminals up, and the shell
            // takes over its place: what it finds is the person's terminal as it was.
            let mut command = CommandBuilder::new("/bin/sh");
            command.args(["-c", "stty eof \"$1\" && shift && exec \"$@\"", "sh", eof]);
            command.arg(&package.executable);
            command
        } else {
            CommandBuilder::new(&package.executable)
        };
        match package.kind {
            ShellKind::PowerShell => {
                // The host reads its profile and drops into its own read loop; nothing else about
                // the launch is this package's.
                command.arg("-NoLogo");
                // The qualified editor and this module are selected before the profile runs, which
                // is what the marked block then imports by name. The package's launch puts its
                // module directory first on the module path and gives the host the runtime
                // location the qualification recorded, as a session's worker does.
                for (name, value) in package.launch() {
                    command.env(name, value);
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
        // `LC_ALL` is set with `LANG`: a run that inherits `LC_ALL` or `LC_CTYPE` would otherwise
        // run the shell in that locale, whatever `LANG` says. The locale is the byte locale
        // unless the case runs inside `in_each_locale`, which names the locale of each run.
        let locale = locale_in_force();
        command.env("LANG", &locale);
        command.env("LC_ALL", &locale);
        if managed {
            command.env("KR_SESSION", session_id.to_string());
            command.env("KR_SHELL_BRIDGE", &endpoint.path);
            command.env(
                "KR_SHELL_BRIDGE_SECRET",
                kr_protocol::scalars::to_base64url(&secret),
            );
            if package.kind == ShellKind::PowerShell {
                command.env(
                    "KR_SHELL_BRIDGE_HANDSHAKE_WAIT_MS",
                    PATIENT_HANDSHAKE_WAIT_MS.to_string(),
                );
            }
            // A run that asked a package for diagnostics passes that through to the shell it starts.
            if let Some(trace) = std::env::var_os("KR_SHELL_BRIDGE_TRACE") {
                command.env("KR_SHELL_BRIDGE_TRACE", trace);
            }
        }
        // What the case itself names goes last, so a variable a case sets replaces the one set
        // above. The locale is the one variable it may not name: the log names the locale of each
        // run, and a case that set its own would run under another, so a case that needs a locale
        // goes through `in_each_locale`.
        for (name, value) in environment {
            assert!(
                name != "LANG" && !name.starts_with("LC_"),
                "a case that sets {name}={value} would run in a locale its log does not name; \
                 run it through `in_each_locale` instead"
            );
            command.env(name, value);
        }

        // The terminal is read, and its queries answered, before the shell starts: the shell asks
        // its first question as it draws its first prompt.
        let TerminalReading {
            output,
            terminal,
            cursor_answered,
            stopped,
            stopped_reading,
        } = read_terminal(pty.master.as_ref());
        let mut child = pty
            .slave
            .spawn_command(command)
            .expect("the packaged shell starts");
        drop(pty.slave);

        // A shell that is not managed connects to nothing. The stream a session reads is then one
        // whose other end this session holds and never writes to, so a read finds nothing.
        let (stream, bridge_peer) = if managed {
            let connect_window = after_any_give_up(REPLY);
            let connected = accept_unless(&listener, connect_window, || {
                matches!(child.try_wait(), Ok(Some(_)))
            });
            let Some(stream) = connected else {
                let state = match child.try_wait() {
                    Ok(Some(status)) => format!("it ended with {status:?}"),
                    _ => {
                        note_that_a_wait_gave_up();
                        format!("it was still running after {connect_window:?}")
                    }
                };
                panic!(
                    "the shell did not connect to the endpoint it was given: {state}; the terminal \
                     showed:\n{}",
                    String::from_utf8_lossy(&output.lock().expect("the output lock"))
                );
            };
            (stream, None)
        } else {
            let (ours, theirs) = UnixStream::pair().expect("a stream that connects to nothing");
            (ours, Some(theirs))
        };
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
            _bridge_peer: bridge_peer,
            shut: false,
            peer_write_gone: false,
            peer_read_gone: false,
            closure_expected: false,
            budget: None,
            reader_lifetime: 0,
            idle_reports: 0,
            last_idle_empty: false,
            reading_reader: None,
            pending: Vec::new(),
            events: Inbox::default(),
            answers: HashMap::new(),
            next_request: 1,
            commands: Commands::default(),
            output,
            cursor_answered,
            stopped,
            stopped_reading,
            terminal,
            child,
            _master: pty.master,
            _directory: directory,
        };

        if !managed {
            return session;
        }
        let Some(opening) = session.read_frame(after_any_give_up(REPLY)) else {
            note_that_a_wait_gave_up();
            panic!(
                "the bridge sent no opening frame; the terminal showed:\n{}",
                session.terminal_output()
            );
        };
        let hello = match opening {
            BridgeFrame::Hello(hello) => hello,
            other => panic!("the bridge opened with {other:?}"),
        };

        // The proof is the worker's own: the bridge's SHA-256 and HMAC-SHA-256 are written in C
        // and the worker's are RustCrypto's, so the two tags are compared here, over the
        // transcript this contract defines, before the handshake is decided. A package whose hash
        // or MAC is wrong fails on this line, and not as a refusal further on.
        let secret_key = SymmetricKey::from_bytes(
            <[u8; BOOTSTRAP_SECRET_LEN]>::try_from(secret.as_slice())
                .expect("the bootstrap secret has its fixed length"),
        );
        let workers_proof = handshake::proof_bytes(
            &secret_key,
            session.session_id,
            &endpoint,
            &hello.shell_process,
            &hello.shell.integration_version,
        )
        .expect("the transcript encodes");
        assert_eq!(
            hello.proof, workers_proof,
            "the proof this package's bridge computed is not the worker's HMAC-SHA-256 of the same \
             transcript"
        );

        if answer == HandshakeAnswer::NotDecodable {
            // A length that a frame may have and a body that is no value of the contract.
            let body = [0xff_u8; 3];
            let mut bytes = u32::try_from(body.len())
                .expect("a short body")
                .to_be_bytes()
                .to_vec();
            bytes.extend_from_slice(&body);
            session
                .stream
                .write_all(&bytes)
                .expect("the bridge takes the frame");
            session.hello = hello;
            return session;
        }

        let expectation = WorkerExpectation {
            session_id: session.session_id,
            root_process: hello.shell_process.clone(),
            supported_editor_abis: vec![hello.shell.editor_abi.clone()],
            supported_integration_versions: vec![hello.shell.integration_version.clone()],
            launched_package: None,
            already_registered: false,
            gesture,
        };
        let observed = if answer == HandshakeAnswer::Refuse {
            // The kernel's start value is a unit away from the one the shell named: the least a
            // start time can differ by, and the worker refuses the shell as another process.
            let mut seen = hello.shell_process.clone();
            seen.start_value = U64::new(seen.start_value.get() + 1);
            seen
        } else {
            hello.shell_process.clone()
        };
        let peer = ObservedPeer {
            uid: endpoint_owner(&endpoint_path),
            process: Some(observed),
        };
        let outcome =
            handshake::admit_observed(&secret_key, &expectation, &endpoint, &peer, &hello)
                .expect("the transcript encodes");
        if answer == HandshakeAnswer::Refuse {
            assert!(
                matches!(
                    &outcome,
                    HandshakeOutcome::Refused(refused)
                        if refused.reason
                            == kr_shell_integration::contract::qualification::QualificationReason::ProcessMismatch
                ),
                "the worker's decision did not refuse the shell as another process: {outcome:?}"
            );
            // The refusal and the end of the connection go out together, as the worker's do: it
            // writes the answer and drops the connection.
            session.write_frame(&BridgeFrame::Handshake(outcome));
            session.close_endpoint();
            session.hello = hello;
            return session;
        }
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

    /// The moment a wait inside this session ends at, given what its caller asked for: the budget
    /// in force, or a window of `default`. A window of a whole [`REPLY`] notes that the wait gave up
    /// when it passes, so use it for a wait whose running out fails the case.
    fn deadline_for(&self, default: Duration) -> Deadline {
        match self.budget {
            Some(deadline) => deadline,
            None => Deadline::reply_window(default),
        }
    }

    /// The moment a wait for `within` ends at, cut to what is left of the budget in force.
    ///
    /// This is [`Session::bounded`] as a deadline. Where no budget is in force and `within` is a
    /// whole [`REPLY`], the deadline notes that the wait gave up when it passes. Use it for a wait
    /// whose running out is a failure of the case. [`Session::probe_window`] is for one whose
    /// running out is an answer.
    fn window(&self, within: Duration) -> Deadline {
        match self.budget {
            Some(deadline) => Deadline::after(deadline.at_most(within)),
            None => Deadline::reply_window(within),
        }
    }

    /// The moment a wait for `within` ends at, for a wait whose running out is an answer and not
    /// a failure: a reader that says nothing is a reader the caller did not see do something, and
    /// the caller records a smaller claim. It never notes a give-up.
    fn probe_window(&self, within: Duration) -> Deadline {
        Deadline::after(self.bounded(within))
    }

    /// `within`, cut to what is left of the budget in force.
    fn bounded(&self, within: Duration) -> Duration {
        match self.budget {
            Some(deadline) => deadline.at_most(within),
            None => after_any_give_up(within),
        }
    }

    /// Sends one frame the endpoint has until `deadline` to take, which has to reach the bridge
    /// as [`Session::write_frame`]'s does.
    ///
    /// # Panics
    ///
    /// Panics when the bridge has gone and no caller expected it to.
    pub fn write_frame_before(&mut self, frame: &BridgeFrame, deadline: Instant) {
        self.try_write_frame_before(frame, deadline)
            .unwrap_or_else(|Stalled| panic!("the bridge stopped reading"));
    }

    /// As [`Session::write_frame_before`], and says that the endpoint took nothing more before
    /// `deadline` instead of panicking.
    fn try_write_frame_before(
        &mut self,
        frame: &BridgeFrame,
        deadline: Instant,
    ) -> Result<(), Stalled> {
        let delivery = self.try_write_frames_before(std::slice::from_ref(frame), deadline)?;
        assert!(
            delivery == Delivery::Delivered || self.closure_expected,
            "the bridge's side of the endpoint has gone and this write did not expect it; the \
             terminal showed:\n{}",
            self.terminal_output()
        );
        Ok(())
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
    ///
    /// # Panics
    ///
    /// Panics when the endpoint takes none of the rest by `deadline`.
    #[must_use]
    pub fn write_frames_before(&mut self, frames: &[BridgeFrame], deadline: Instant) -> Delivery {
        self.try_write_frames_before(frames, deadline)
            .unwrap_or_else(|Stalled| panic!("the bridge stopped reading"))
    }

    /// As [`Session::write_frames_before`], and says that the endpoint took nothing more before
    /// `deadline` instead of panicking, for a caller that has something to report with it. Part of
    /// a frame may have been written, so a caller writes no more frames after a stall: it reports
    /// it and ends the case.
    fn try_write_frames_before(
        &mut self,
        frames: &[BridgeFrame],
        deadline: Instant,
    ) -> Result<Delivery, Stalled> {
        if self.shut || self.peer_write_gone {
            return Ok(Delivery::PeerGone);
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
        if send_to_bridge(&mut self.stream, &bytes, deadline)? == Delivery::PeerGone {
            self.peer_write_gone = true;
            return Ok(Delivery::PeerGone);
        }
        // An editor that reaches its own queue only when the reader steps is given that step here,
        // which is the one a person at the keyboard gives it by typing at all.
        self.nudge_before(deadline);
        Ok(Delivery::Delivered)
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
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    wait_until_ready(&self.stream, PollFlags::IN, left);
                }
                Err(error) if peer_has_gone(&error) => self.peer_read_gone = true,
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
        self.take_in(within, deadline, true);
    }

    /// Takes in what the bridge has already sent, acknowledging it as [`Session::pump`] does, and
    /// waits for nothing more.
    ///
    /// A frame the bridge wrote before something the harness saw on the terminal is in the
    /// endpoint already, and a check that has seen the terminal and not yet read the endpoint
    /// reads it here. A short wait for it would not: its time can be spent before the frame is
    /// reached.
    pub fn take_in_what_has_arrived(&mut self) {
        let deadline = self.deadline_for(REPLY).0;
        self.take_in(REPLY, deadline, false);
    }

    /// [`Session::pump_before`], or with `waiting` false the reading of what is there and no more.
    fn take_in(&mut self, within: Duration, deadline: Instant, waiting: bool) {
        let end = (Instant::now() + within).min(deadline);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let window = if waiting {
                left.min(Duration::from_millis(20))
            } else {
                Duration::ZERO
            };
            let Some(frame) = self.read_frame(window) else {
                if !waiting {
                    return;
                }
                if self.peer_read_gone && self.pending.len() < 4 {
                    // Nothing more is coming and nothing whole is left to decode, so waiting out
                    // the rest of this call would be waiting for a stream that has ended. A caller
                    // that goes on waiting for the terminal does not spin while it does.
                    std::thread::sleep(left.min(Duration::from_millis(20)));
                    return;
                }
                if self.shut {
                    // This side closed the endpoint, so the read above returned at once: the
                    // interval is only time passing, and passes without taking a processor.
                    std::thread::sleep(left.min(Duration::from_millis(20)));
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
                    self.commands.arrivals.push(Arrival::Event(name_of(&event)));
                    if let BridgeEvent::ReaderIdle(idle) = &event {
                        self.idle_reports += 1;
                        self.last_idle_empty = idle.editor.buffer_empty;
                    }
                    let outcome = self.routine_answer(&event);
                    if outcome.is_none() && matches!(event, BridgeEvent::CommandResolve(_)) {
                        self.commands.unanswered.push(id);
                    }
                    if outcome.is_none() && matches!(event, BridgeEvent::EditorEnter(_)) {
                        self.commands.held_entries.push(id);
                    }
                    if let Some(result) = outcome {
                        // What a case put ahead of this answer goes first, in the same write, so
                        // the shell reads it while it waits.
                        let mut frames = match &event {
                            BridgeEvent::CommandResolve(_) => {
                                std::mem::take(&mut self.commands.before_resolve_answer)
                            }
                            BridgeEvent::CommandAccepted(_) => {
                                std::mem::take(&mut self.commands.before_acceptance_answer)
                            }
                            _ => Vec::new(),
                        };
                        frames.push(BridgeFrame::EventResult { id, result });
                        // A routine acknowledgement is not a check's own write, so a bridge that
                        // has gone is recorded here rather than asserted: the check that needs a
                        // working endpoint asks for one and says so itself.
                        // An idle report asks for nothing, so its acknowledgement gives the reader
                        // no step: a step makes the reader report idle again, and an
                        // acknowledgement of that report would then step it for good, with a key
                        // always on its way to the terminal.
                        let steps = self.stepping;
                        if matches!(event, BridgeEvent::ReaderIdle(_)) {
                            self.stepping = false;
                        }
                        let _ = self.write_frames_before(&frames, deadline);
                        self.stepping = steps;
                        if matches!(event, BridgeEvent::CommandResolve(_))
                            && std::mem::take(&mut self.commands.silent_after_resolve)
                        {
                            self.commands.stuck = true;
                        }
                    }
                    // The one way an event reaches the queue, and the inbox counts a managed
                    // decision as it takes it in: a wait that later drops it from the queue
                    // cannot drop it from the count.
                    self.events.arrive(Received {
                        id,
                        event,
                        reader_lifetime: self.reader_lifetime,
                    });
                    if std::mem::take(&mut self.commands.close_requested) {
                        self.close_endpoint();
                        return;
                    }
                }
                BridgeFrame::Answer { id, answer } => {
                    self.commands.arrivals.push(Arrival::Answer(id));
                    self.answers
                        .insert(id, (Instant::now(), answer, self.reader_lifetime));
                }
                other => panic!("a bridge sent {other:?}"),
            }
        }
    }

    /// The worker's answer to the acceptance of a line: the capability a real worker mints for the
    /// line it has just recorded. This harness stands in for the worker, so it mints one the same
    /// way.
    ///
    /// A case that held an acceptance unanswered answers it with this when it is ready for the
    /// answer to come.
    pub fn acceptance_answer(
        &mut self,
        params: &kr_protocol::root::RootCommandAcceptedParams,
    ) -> EventOutcome {
        let token = (!self.commands.withhold_tokens).then(|| kr_ipc::new_uuid().to_string());
        self.commands.tokens.push(token.clone());
        EventOutcome::CommandRecorded(RootCommandAcceptedResult {
            origin: params.origin.clone(),
            detach_token: Nullable(token),
            state: FenceState::Fenced,
        })
    }

    /// The worker's answer to the entry of a reader.
    fn entry_answer() -> EventOutcome {
        EventOutcome::EditorEntered(RootEditorEnterResult {
            state: FenceState::Unfenced,
            fence_exchange: Nullable::null(),
        })
    }

    /// Answers the entries a case held, in the order they came, and stops holding the ones that
    /// come after.
    pub fn answer_held_entries(&mut self) {
        self.commands.hold_entries = false;
        let held = std::mem::take(&mut self.commands.held_entries);
        let frames: Vec<BridgeFrame> = held
            .into_iter()
            .map(|id| BridgeFrame::EventResult {
                id,
                result: Self::entry_answer(),
            })
            .collect();
        if !frames.is_empty() {
            // The answer is no reason to type a key at the reader: it is not reading yet.
            let steps = std::mem::replace(&mut self.stepping, false);
            let _ = self.write_frames(&frames);
            self.stepping = steps;
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
                if self.commands.hold_entries {
                    return None;
                }
                Some(Self::entry_answer())
            }
            BridgeEvent::EditorLeave(_) => Some(EventOutcome::EditorLeft(RootEditorLeaveResult {
                state: FenceState::Outside,
            })),
            BridgeEvent::CommandAccepted(params) => {
                self.commands.accepted.push(params.clone());
                if self.commands.silent_acceptance {
                    return None;
                }
                Some(self.acceptance_answer(params))
            }
            BridgeEvent::CommandResolve(params) => {
                self.commands.resolves.push(params.clone());
                let answer = match &self.commands.policy {
                    ResolvePolicy::Decide(integrations) => worker_decision(integrations, params),
                    ResolvePolicy::Establishing {
                        integrations,
                        launcher,
                        environment,
                    } => {
                        use kr_shell_integration::host::command::{InvocationContext, resolve};

                        let resolution = resolve(
                            integrations,
                            InvocationContext {
                                managed_root_shell: true,
                                interactive: params.interactive,
                            },
                            &params.argv,
                        );
                        let backend = resolution.establishes_backend().then(|| {
                            kr_protocol::root::CommandBackend {
                                session_id: params.session_id,
                                prompt_generation: params.prompt_generation,
                                environment: environment.clone(),
                                launcher: launcher.clone(),
                            }
                        });
                        resolution.to_answer(backend)
                    }
                    ResolvePolicy::Silent => return None,
                    ResolvePolicy::CloseEndpoint => {
                        self.commands.close_requested = true;
                        return None;
                    }
                    ResolvePolicy::Refuse => {
                        return Some(EventOutcome::Refused(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this invocation is not resolved",
                        )));
                    }
                    ResolvePolicy::Renaming { launcher } => {
                        let mut arguments = params.argv.clone();
                        arguments[0] = "renamed".to_owned();
                        kr_protocol::root::RootCommandResolveResult {
                            arguments,
                            added: Vec::new(),
                            bypass: Nullable::null(),
                            backend: Nullable::some(kr_protocol::root::CommandBackend {
                                session_id: params.session_id,
                                prompt_generation: params.prompt_generation,
                                environment: Vec::new(),
                                launcher: launcher.clone(),
                            }),
                        }
                    }
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
    /// Panics when no such event arrives inside [`REPLY`], or sooner when the stream it would come
    /// on has ended and what it held has been taken.
    pub fn expect_event<F>(&mut self, what: &str, accept: F) -> (RequestId, BridgeEvent)
    where
        F: Fn(&BridgeEvent) -> bool,
    {
        // Read before the deadline is made, which is where the cap is applied: a wait that runs out
        // the whole window has not been cut short, whatever it notes when it does.
        let cut_short = A_WAIT_GAVE_UP.load(Ordering::Relaxed);
        let deadline = self.deadline_for(REPLY);
        loop {
            if let Some(received) = self.events.take_first(|received| accept(&received.event)) {
                return (received.id, received.event);
            }
            let gave_up = deadline.passed();
            if gave_up {
                note_that_a_wait_gave_up();
            }
            assert!(
                !gave_up && !self.read_to_the_end(),
                "no {what} arrived{}; the events were {:?}\nterminal output:\n{}",
                if !gave_up {
                    " and the stream has ended"
                } else if cut_short {
                    " (cut short, because an earlier wait in this run gave up)"
                } else {
                    ""
                },
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
        let deadline = self.window(within);
        loop {
            if self
                .events
                .take_first(|received| accept(&received.event))
                .is_some()
            {
                return true;
            }
            if deadline.passed() {
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
    /// A reader that answers only when it steps is waiting for this and takes it at the step it
    /// is given here. Its idle reports are acknowledged without one, so that the step is the last.
    pub fn answer_event(&mut self, id: RequestId, result: EventOutcome) {
        self.write_frame(&BridgeFrame::EventResult { id, result });
    }

    /// Sends one request to the reader thread and returns its identifier.
    pub fn ask(&mut self, request: WorkerRequest) -> RequestId {
        let deadline = self.deadline_for(REPLY);
        self.ask_before(request, deadline.0)
    }

    /// Whether a fence's answer reports the terminal's or the macro queue as holding input the
    /// reader has not taken yet: such a fence is asked again about the same prompt, since keys
    /// typed first go first and the reader may judge the fence before it has taken them. A reader
    /// that reports a partial key sequence is not asked again, since no key typed here leaves one:
    /// that report is the one that counts.
    fn input_not_yet_taken(queues: kr_protocol::root::QueueDrainReport) -> bool {
        queues.partial_key_drained && !(queues.tty_typeahead_drained && queues.macro_input_drained)
    }

    /// Asks the reader for the launch `request` and returns what it decided.
    ///
    /// A reader judges a launch on its own thread, when it takes the request off its mailbox. One
    /// that is slower to take a key than the harness is to type the next judges the launch with a
    /// key still unread in the terminal's queue, and refuses it as queued prior input: keys typed
    /// first go first, as the contract says. Every reader can meet that, whether the key is the
    /// step the harness gives a reader that answers at its next step behind every frame, or the
    /// text a case typed before it asked. A case that is about that refusal asks for it with
    /// [`Session::ask`] and says what the keys were. A case that can meet it without being about
    /// it asks here, and a launch so refused is asked again, as a new transaction, until the
    /// reader judges it with its keys taken, the window of one reply ends, or 256 launches have
    /// been asked (the transactions differ only in their first byte); a reader that never takes its
    /// keys is refused until then, and its last decision is returned. Any other decision is
    /// returned as it comes. An accepted launch is checked to be the transaction that was asked.
    ///
    /// # Panics
    ///
    /// Panics when the reader answers a launch with something other than a decision, answers
    /// after the window, or accepts a transaction other than the one it was asked.
    pub fn launched(&mut self, request: LaunchMailboxRequest) -> LaunchDecision {
        let until = self.deadline_for(REPLY);
        let mut asked = 0_u8;
        loop {
            let mut again = request.clone();
            let mut identifier = *request.transaction.get().as_bytes();
            identifier[0] = identifier[0].wrapping_add(asked);
            again.transaction = LaunchTransactionId::new(Uuid::from_bytes(identifier));
            let transaction = again.transaction;
            let id = self.ask_before(WorkerRequest::Launch(again), until.0);
            let BridgeAnswer::Launch(decision) = self.answer_before(id, until.0) else {
                panic!("the reader answered a launch with something else")
            };
            if let LaunchDecision::Accepted(accepted) = &decision {
                assert_eq!(
                    accepted.transaction, transaction,
                    "the reader accepted another launch than the one it was asked"
                );
            }
            if decision.rejection() != Some(LaunchRejectionReason::QueuedPriorInput)
                || until.passed()
                || asked == u8::MAX
            {
                return decision;
            }
            asked += 1;
            eprintln!(
                "a launch was refused for input the reader had not taken; asking again ({asked})"
            );
            self.pump_before(self.bounded(Duration::from_millis(50)), until.0);
            if until.passed() {
                return decision;
            }
        }
    }

    /// Sends one request the endpoint has until `deadline` to take, and returns its identifier.
    ///
    /// # Panics
    ///
    /// Panics when the endpoint takes none of the rest by `deadline`.
    pub fn ask_before(&mut self, request: WorkerRequest, deadline: Instant) -> RequestId {
        self.try_ask_before(request, deadline)
            .unwrap_or_else(|Stalled| panic!("the bridge stopped reading"))
    }

    /// As [`Session::ask_before`], and says that the endpoint took nothing more before `deadline`
    /// instead of panicking, for a caller that has the reader's last report to give with it. A
    /// caller writes no more frames after a stall: part of the request may have been written.
    pub fn try_ask_before(
        &mut self,
        request: WorkerRequest,
        deadline: Instant,
    ) -> Result<RequestId, Stalled> {
        let id = RequestId::new(self.next_request);
        self.next_request += 1;
        self.try_write_frame_before(&BridgeFrame::Request { id, request }, deadline)?;
        Ok(id)
    }

    /// Sends one request to a reader that has been given its step already, without giving it
    /// another: a case that has put bytes into the terminal behind that step wants nothing typed
    /// after them.
    pub fn ask_after_the_step(&mut self, request: WorkerRequest) -> RequestId {
        self.stepping = false;
        let id = self.ask(request);
        self.stepping = true;
        id
    }

    /// Waits for the answer to a request asked after the reader's step, without giving the reader
    /// another step while it waits.
    ///
    /// Every acknowledgement this session writes gives the reader a step, and a step is a key in
    /// the terminal's queue. A case that is counting what the terminal holds unread would count
    /// those keys, so it waits for the answer here and not in [`Session::answer`].
    ///
    /// # Panics
    ///
    /// Panics when the reader does not answer inside [`REPLY`].
    pub fn answer_after_the_step(&mut self, id: RequestId) -> BridgeAnswer {
        self.stepping = false;
        let answer = self.answer(id);
        self.stepping = true;
        answer
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

    /// Types `bytes` into the terminal, behind the step a reader that answers only when it steps
    /// will take, in one write, without waiting for the step.
    ///
    /// A shell that is stopped takes the step in its terminal's queue ahead of what follows it, and
    /// steps when it is let go. One write puts both in the terminal together, so a runtime that
    /// reads in chunks takes them in one read, which is how input comes to be behind the step in
    /// the runtime's buffer and not in the terminal's queue.
    pub fn type_behind_the_step(&mut self, bytes: &[u8]) {
        let mut typed = Vec::with_capacity(bytes.len() + 1);
        if self.reading && self.stepping && dialect(self.package_kind).answers_at_the_next_step {
            typed.push(0x06);
        }
        typed.extend_from_slice(bytes);
        let deadline = self.deadline_for(REPLY);
        self.type_bytes_before(&typed, deadline.0);
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
        // The step is given time to be taken before anything is asked of the reader: a key it has
        // not taken yet is input of the person's, and the contract puts that ahead of anything the
        // worker asks for. A reader slower than the step refuses what it is asked for the key it
        // has not taken, which [`Session::launched`] answers for a launch.
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
            if let Some((arrived, answer, _)) = self.answers.remove(&id) {
                assert!(
                    arrived <= deadline,
                    "the reader answered request {id:?} {:?} after the deadline of this wait\nterminal output:\n{}",
                    arrived.saturating_duration_since(deadline),
                    self.terminal_output()
                );
                return answer;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                note_that_a_wait_gave_up();
            }
            assert!(
                !left.is_zero() && !self.read_to_the_end(),
                "the reader did not answer request {id:?} {}\nterminal output:\n{}",
                if left.is_zero() {
                    "before the deadline of this wait"
                } else {
                    "and the stream has ended"
                },
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
        self.stamped_answer_by(id, deadline)
            .map(|(answer, _)| answer)
    }

    /// Waits as [`Session::answer_by`] does, and returns with the answer how many readers of this
    /// session had entered or left when it arrived: an answer is about the reader that was running
    /// then, whatever entered or left while this was still reading what came behind it.
    pub fn stamped_answer_by(
        &mut self,
        id: RequestId,
        deadline: Deadline,
    ) -> Option<(BridgeAnswer, u64)> {
        loop {
            if let Some((arrived, answer, lifetime)) = self.answers.remove(&id) {
                return (arrived <= deadline.0).then_some((answer, lifetime));
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

    /// Tells the bridge the exchange it answered ended with no fence.
    pub fn withhold(&mut self, reason: WithheldReason) {
        self.write_frame(&BridgeFrame::FencePublished(FencePublication::Withheld {
            reason,
            state: FenceState::Unfenced,
        }));
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
        let deadline = self.deadline_for(REPLY);
        self.type_bytes_before(bytes, deadline.0);
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
            if Instant::now() >= deadline {
                note_that_a_wait_gave_up();
            }
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
            // The line goes in once the editor reads the terminal itself.
            assert!(
                self.wait_for_editor_reading(),
                "the editor never asked where the cursor was after the prompt, to type {line:?} at:\n{}",
                self.terminal_output()
            );
            // The return goes in once the editor has drawn what was typed, which is where it is
            // reading the terminal itself. Before that the terminal's own line discipline holds
            // the line, and it sends a line feed where the return was.
            let start = self.output.lock().expect("the output lock").len();
            self.type_bytes(line.as_bytes());
            let drawn = self.wait_for_editor(start);
            if !drawn {
                note_that_a_wait_gave_up();
            }
            assert!(
                drawn,
                "the editor drew nothing for {line:?}:\n{}",
                self.terminal_output()
            );
            self.type_bytes(b"\r");
        } else {
            let mut bytes = line.as_bytes().to_vec();
            bytes.push(b'\r');
            let before = self.output.lock().expect("the output lock").len();
            self.type_bytes(&bytes);
            if line.is_empty() {
                // An empty line draws the next prompt at once, so the prompt a later wait looks for
                // is the first thing after what was on the screen before the return.
                self.mark = before;
                return;
            }
        }
        self.mark = self.output.lock().expect("the output lock").len();
    }

    /// Waits until the editor has asked where the cursor is after the prompt `mark` points at and
    /// been answered, which is where it stops starting to read and reads keys.
    ///
    /// The prompt is on the screen before the editor reads: it goes on to set the terminal up for
    /// reading and to ask where the cursor is, and what a person types in that time goes to a
    /// terminal that is not yet the editor's. A line typed then is sometimes never read, and the
    /// editor shows nothing for it.
    fn wait_for_editor_reading(&mut self) -> bool {
        let deadline = self.deadline_for(REPLY);
        loop {
            if self.editor_has_asked_where_the_cursor_is() {
                return true;
            }
            if deadline.passed() {
                return false;
            }
            self.pump(Duration::from_millis(10));
        }
    }

    /// Says whether the editor has asked where the cursor is after the prompt `mark` points at, and
    /// been answered or told to wait for its answer, without waiting for it to.
    fn editor_has_asked_where_the_cursor_is(&self) -> bool {
        let prompt_ended = {
            let output = self.output.lock().expect("the output lock");
            let mark = self.mark.min(output.len());
            output[mark..]
                .windows(self.prompt.len())
                .position(|window| window == self.prompt.as_bytes())
                .map(|at| mark + at + self.prompt.len())
        };
        prompt_ended.is_some_and(|ended| self.cursor_answered.load(Ordering::Acquire) > ended)
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

    /// Gives the bridge a short wait for the worker's answer, for a case in which the worker never
    /// answers something and what the case looks at is the wait running out. Every other case lets
    /// the bridge wait far longer; see [`PATIENT_ANSWER_WAIT_MS`] and
    /// [`SILENT_WORKER_ANSWER_WAIT_MS`]. The wait applies to every question and every acceptance
    /// the bridge sends until [`Session::lets_the_bridge_wait_for_answers`] is called. Nothing is
    /// done for a shell whose bridge has no such wait.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not take the line or the bridge does not hold the wait after it.
    pub fn lets_the_bridge_give_up_on_a_question(&mut self) {
        self.sets_the_bridge_answer_wait(SILENT_WORKER_ANSWER_WAIT_MS);
    }

    /// Gives the bridge a short wait for the worker's answer to the question the next line leads to
    /// when it looks `command` up, and keeps the wait it has for everything before that, the
    /// acceptance of the line included.
    ///
    /// This is [`Session::lets_the_bridge_give_up_on_a_question`] for a case in which the worker
    /// answers the acceptance and leaves the question unanswered, and what the case looks at is the
    /// question's wait running out: a runner that is slow to run the harness between the two only
    /// lengthens it, and cannot leave the acceptance owed. The wait stays short until
    /// [`Session::lets_the_bridge_wait_for_answers`] is called. Nothing is done for a shell whose
    /// bridge has no such wait.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not take the line.
    pub fn lets_the_bridge_give_up_on_the_question_the_lookup_of(&mut self, command: &str) {
        if self.package_kind != ShellKind::PowerShell {
            return;
        }
        let line = set_answer_wait_at_the_lookup_of(command, SILENT_WORKER_ANSWER_WAIT_MS);
        assert!(
            self.run(&line, "kr-lookup-armed"),
            "the shell does not take the line that sets the wait for the next question:\n{}",
            self.terminal_output()
        );
    }

    /// Makes the bridge wait for the worker's answers longer than the harness waits for anything,
    /// for a case that holds an answer back until it has typed a key.
    ///
    /// Nothing the harness does at any pace puts the key after the wait: the harness has failed its
    /// own case by [`REPLY`], which is less. Nothing is done for a shell whose bridge has no such
    /// wait.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not take the line or the bridge does not hold the wait after it.
    pub fn lets_the_bridge_wait_beyond_any_reply(&mut self) {
        // The harness can spend two windows before the key: one for the acceptance, one to type.
        const _: () = assert!(WAIT_BEYOND_ANY_REPLY_MS as u128 > 2 * REPLY.as_millis());
        self.sets_the_bridge_answer_wait(WAIT_BEYOND_ANY_REPLY_MS);
    }

    /// Whether the bridge holds the short wait for answers that the lookup it was armed for set.
    pub fn bridge_gives_up_on_questions(&mut self) -> bool {
        self.package_kind != ShellKind::PowerShell
            || self.run(
                &read_answer_wait_and_say(),
                &format!("kr-answer-wait-{SILENT_WORKER_ANSWER_WAIT_MS}"),
            )
    }

    /// Makes the bridge wait for the worker's answers as long as a case waits for anything, as it
    /// does when the case starts.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not take the line or the bridge does not hold the wait after it.
    pub fn lets_the_bridge_wait_for_answers(&mut self) {
        self.sets_the_bridge_answer_wait(PATIENT_ANSWER_WAIT_MS);
    }

    /// Whether the bridge holds the long wait for answers that a case starts with.
    pub fn bridge_waits_for_answers(&mut self) -> bool {
        self.package_kind != ShellKind::PowerShell || self.says_the_bridge_answer_wait(None)
    }

    fn sets_the_bridge_answer_wait(&mut self, milliseconds: u32) {
        if self.package_kind != ShellKind::PowerShell {
            return;
        }
        assert!(
            self.says_the_bridge_answer_wait(Some(milliseconds)),
            "the bridge does not hold a wait of {milliseconds} ms for answers:\n{}",
            self.terminal_output()
        );
    }

    /// Sets the bridge's wait to `set` where that is given, or reads it where it is not, and says
    /// whether the bridge then holds the value the case expects: `set`, or the long wait a case
    /// starts with.
    fn says_the_bridge_answer_wait(&mut self, set: Option<u32>) -> bool {
        let expected = set.unwrap_or(PATIENT_ANSWER_WAIT_MS);
        let line = match set {
            Some(milliseconds) => set_answer_wait_and_say(milliseconds),
            None => read_answer_wait_and_say(),
        };
        self.run(&line, &format!("kr-answer-wait-{expected}"))
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
        let deadline = self.window(within);
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

    /// Has the terminal say nothing to the editor's questions from here on, as a terminal that is
    /// slow to answer does.
    pub fn hold_terminal_answers(&self) {
        self.terminal.hold_answers();
    }

    /// Has the terminal say nothing to the editor's questions from the second one about the cursor
    /// on, as a terminal that is slow to answer does. The first is the shell's own, asked before
    /// it draws a prompt, and a shell that waits for it never gets as far as a prompt.
    pub fn hold_terminal_answers_after_the_shells_own_cursor_question(&self) {
        self.terminal.hold_answers_after_cursor_questions(1);
    }

    /// Gives the editor the answers the terminal kept, and has it answer at once again.
    pub fn release_terminal_answers(&self) {
        self.terminal.release_answers();
    }

    /// Ends the endpoint the way a worker that has gone would.
    ///
    /// Nothing is written or read afterwards: the worker is gone, and what the shell does from
    /// here is what it does on its own.
    pub fn close_endpoint(&mut self) {
        shut_the_endpoint(&self.stream);
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
    /// Where the terminal's answers wait while it is told to say nothing: `None` answers at once.
    held: Mutex<Option<Vec<u8>>>,
    /// How many questions about the cursor the shell has asked.
    cursor_questions: AtomicUsize,
    /// After how many of them the terminal keeps its answers, or `usize::MAX` for never.
    hold_after_cursor_questions: AtomicUsize,
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
        Self {
            typing,
            writer,
            held: Mutex::new(None),
            cursor_questions: AtomicUsize::new(0),
            hold_after_cursor_questions: AtomicUsize::new(usize::MAX),
        }
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

    /// Answers a query the editor is waiting on, from the thread that read it, or keeps the answer
    /// for [`TerminalInput::release_answers`] while the terminal is told to say nothing.
    fn answer_now(&self, bytes: &[u8]) {
        if let Ok(mut held) = self.held.lock()
            && let Some(kept) = held.as_mut()
        {
            kept.extend_from_slice(bytes);
            return;
        }
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_all(bytes);
            let _ = writer.flush();
        }
    }
}

impl TerminalInput {
    /// Keeps every answer the terminal gives from now on, until [`TerminalInput::release_answers`].
    fn hold_answers(&self) {
        if let Ok(mut held) = self.held.lock() {
            held.get_or_insert_with(Vec::new);
        }
    }

    /// Keeps every answer from the one to the cursor question after the first `asked` of them
    /// onward, until [`TerminalInput::release_answers`]. The shell asks one of its own before it
    /// draws a prompt, and the editor asks the next after it.
    fn hold_answers_after_cursor_questions(&self, asked: usize) {
        self.hold_after_cursor_questions
            .store(asked, Ordering::Release);
    }

    /// Takes note of `count` more questions about the cursor, and keeps the answers from the one
    /// that passes the number the terminal was told to hold after.
    fn note_cursor_questions(&self, count: usize) {
        let total = self.cursor_questions.fetch_add(count, Ordering::AcqRel) + count;
        if total > self.hold_after_cursor_questions.load(Ordering::Acquire) {
            self.hold_answers();
        }
    }

    /// Gives the editor the answers kept since [`TerminalInput::hold_answers`], and answers at
    /// once from here on.
    fn release_answers(&self) {
        self.hold_after_cursor_questions
            .store(usize::MAX, Ordering::Release);
        let kept = self.held.lock().ok().and_then(|mut held| held.take());
        if let Some(kept) = kept.filter(|kept| !kept.is_empty())
            && let Ok(mut writer) = self.writer.lock()
        {
            let _ = writer.write_all(&kept);
            let _ = writer.flush();
        }
    }
}

/// What reads one session's terminal: the transcript it fills, the side that types on it, where in
/// the transcript the last cursor query it answered ends, the flag that ends the reading and the
/// report that the reading has ended.
struct TerminalReading {
    output: Arc<Mutex<Vec<u8>>>,
    terminal: Arc<TerminalInput>,
    cursor_answered: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    stopped_reading: mpsc::Receiver<()>,
}

/// Reads `master` on a thread of its own, answering the queries an editor asks at every prompt, and
/// returns once that thread is running.
///
/// A shell is started after the call, so its first question goes to a terminal whose reader has
/// been started: the thread's start does not come after the shell has asked. The thread can still
/// be descheduled before its first read, and the terminal holds the question until it reads. A
/// shell started first asks into a terminal no thread has been started for, and an editor gives up
/// on an answer that is late: what arrives after is read as keys a person typed, at a prompt the
/// case does not think it is at.
fn read_terminal(master: &dyn MasterPty) -> TerminalReading {
    let output = Arc::new(Mutex::new(Vec::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let mut reader = master.try_clone_reader().expect("a terminal reader");
    let collected = Arc::clone(&output);
    let finished = Arc::clone(&stopped);
    let terminal = Arc::new(TerminalInput::of(
        master.take_writer().expect("a terminal writer"),
    ));
    let answering = Arc::clone(&terminal);
    let cursor_answered = Arc::new(AtomicUsize::new(0));
    let answered_to = Arc::clone(&cursor_answered);
    let (finished_reading, stopped_reading) = mpsc::channel();
    let (running, started) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        // Said before the first read, and the call that started this thread does not return until
        // it is heard.
        let _ = running.send(());
        let mut buffer = [0u8; 4096];
        // A terminal read ends wherever the kernel had bytes, which can be in the middle of a
        // query an editor is waiting for an answer to, so the queries are read from the stream and
        // not from one read of it.
        let mut queries = TerminalQueries::new(Arc::clone(&answered_to));
        while !finished.load(Ordering::Relaxed) {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(taken) => {
                    // A terminal that never answers a query is a terminal the editor waits for,
                    // so this one answers the ones an editor asks at every prompt.
                    queries.answer(&buffer[..taken], &answering);
                    collected
                        .lock()
                        .expect("the output lock")
                        .extend_from_slice(&buffer[..taken]);
                }
            }
        }
        drop(finished_reading);
    });
    started
        .recv()
        .expect("the thread that reads the terminal started");
    TerminalReading {
        output,
        terminal,
        cursor_answered,
        stopped,
        stopped_reading,
    }
}

/// The queries an editor asks the terminal at every prompt, each with the reply a terminal gives.
const TERMINAL_QUERIES: &[(&[u8], &[u8])] = &[
    (b"\x1b[6n", b"\x1b[1;1R"),
    (b"\x1b[c", b"\x1b[?6c"),
    (b"\x1b[0c", b"\x1b[?6c"),
    (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
];

/// Answers the queries a terminal is expected to answer while an editor draws a prompt.
///
/// An editor that asks where the cursor is and waits for the reply cannot start its read loop
/// until something answers, so this terminal answers rather than leaving it waiting. It answers on
/// this thread, the one that read the query: an answer that arrives after the editor has stopped
/// waiting for it is read as keys a person typed, and the prompt the test then types at is not the
/// one it thinks.
///
/// A query is a sequence in the stream the terminal shows, not in one read of it: a pseudo-terminal
/// hands over what has arrived, and on a loaded machine that can be the first bytes of a query and
/// then the rest. So what could be the start of one is kept from each read, a query cut between two
/// reads is found once it is whole, and a query that ended in an earlier read is not answered
/// again.
struct TerminalQueries {
    /// The last bytes read, which could be the start of a query the next read finishes.
    carry: Vec<u8>,
    /// How many bytes of the terminal's output have been read.
    read: usize,
    /// Where, in the terminal's output, the last cursor query this has answered ends. The editor
    /// reads the keys typed at it once it has the answer, so a line typed before that is typed
    /// while the editor is still starting to read.
    cursor_answered_to: Arc<AtomicUsize>,
}

impl TerminalQueries {
    fn new(cursor_answered_to: Arc<AtomicUsize>) -> Self {
        Self {
            carry: Vec::new(),
            read: 0,
            cursor_answered_to,
        }
    }

    /// Takes the next bytes the terminal showed and answers each query that ended in them.
    fn answer(&mut self, bytes: &[u8], terminal: &TerminalInput) {
        let kept = self.carry.len();
        let stream = [self.carry.as_slice(), bytes].concat();
        // Where the first byte of `stream` is in the terminal's output as a whole.
        let origin = self.read - kept;
        self.read += bytes.len();
        let mut reply: Vec<u8> = Vec::new();
        let mut cursor_answered_to = None;
        let mut cursor_questions = 0;
        let mut at = 0;
        while at < stream.len() {
            let matched = TERMINAL_QUERIES
                .iter()
                .find(|(query, _)| stream[at..].starts_with(query));
            let Some((query, answer)) = matched else {
                at += 1;
                continue;
            };
            at += query.len();
            // A query that ended in an earlier read was answered then.
            if at <= kept {
                continue;
            }
            reply.extend_from_slice(answer);
            if *query == b"\x1b[6n" {
                cursor_answered_to = Some(origin + at);
                cursor_questions += 1;
            }
        }
        let longest = TERMINAL_QUERIES
            .iter()
            .map(|(query, _)| query.len())
            .max()
            .unwrap_or(1);
        self.carry = stream[stream.len().saturating_sub(longest - 1)..].to_vec();
        if reply.is_empty() {
            return;
        }
        terminal.note_cursor_questions(cursor_questions);
        terminal.answer_now(&reply);
        if let Some(ended) = cursor_answered_to {
            self.cursor_answered_to.store(ended, Ordering::Release);
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn accept_within(listener: &UnixListener, within: Duration) -> Option<UnixStream> {
    accept_unless(listener, within, || false)
}

/// Accepts the connection the shell makes to `listener`, waiting for it until `within` has passed
/// or `gone` says that no connection is coming.
///
/// The wait is for the listener to become readable, which it does when the shell connects. A shell
/// that has ended without connecting is not coming, and a connection it made just before it ended
/// is still in the listener's queue, so the queue is asked once more before the wait is given up.
fn accept_unless(
    listener: &UnixListener,
    within: Duration,
    mut gone: impl FnMut() -> bool,
) -> Option<UnixStream> {
    let deadline = Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                if gone() {
                    return listener.accept().ok().map(|(stream, _)| stream);
                }
                wait_until_ready(
                    listener,
                    PollFlags::IN,
                    left.min(Duration::from_millis(500)),
                );
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

/// A stream whose every write fails with one error, for the forms of a gone peer that a real
/// socket gives only while the peer is closing, or only on some platforms.
struct FailsWith {
    error: rustix::io::Errno,
    /// What the harness waits on for room; a failing write is never waited on.
    endpoint: UnixStream,
}

impl Write for FailsWith {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(self.error.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsFd for FailsWith {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.endpoint.as_fd()
    }
}

/// A write to an endpoint whose shell has gone says so, whatever form the platform gives it.
///
/// A shell ends when a case sends it its own end of file, and the harness's next write to the
/// endpoint then meets the close. Linux answers a broken pipe, or a reset when data of ours was
/// unread. macOS answers a broken pipe too, and "not connected" in the instant the close is being
/// made, which is the form a hosted macOS runner showed. Each is the shell's going, which the case
/// that expected it takes as its result, and none is a fault of the harness.
#[test]
fn a_write_to_an_endpoint_whose_shell_has_gone_says_so_in_every_form_of_it() {
    use rustix::io::Errno;

    let (endpoint, _shell) = UnixStream::pair().expect("a pair of connected streams");
    for error in [Errno::PIPE, Errno::CONNRESET, Errno::NOTCONN] {
        let mut stream = FailsWith {
            error,
            endpoint: endpoint
                .try_clone()
                .expect("a second handle to the endpoint"),
        };
        let delivery = send_to_bridge(&mut stream, b"kr", Instant::now() + REPLY);
        assert_eq!(
            delivery,
            Ok(Delivery::PeerGone),
            "a write answered {error} was not taken as the shell having gone"
        );
    }
}

/// A write to a stream whose peer has really closed says so on the platform the case runs on, and
/// so does ending the endpoint, which macOS refuses as "not connected" every time.
#[test]
fn an_endpoint_whose_peer_has_closed_takes_a_write_and_its_own_end_as_the_peers_going() {
    let (mut endpoint, shell) = UnixStream::pair().expect("a pair of connected streams");
    endpoint
        .set_nonblocking(true)
        .expect("a non-blocking endpoint");
    drop(shell);
    assert_eq!(
        send_to_bridge(&mut endpoint, b"kr", Instant::now() + REPLY),
        Ok(Delivery::PeerGone)
    );
    shut_the_endpoint(&endpoint);
}

/// An error that is not the peer's going stays a fault of the harness, whatever else is taken.
#[test]
#[should_panic(expected = "writing to the bridge")]
fn a_write_that_fails_for_another_reason_is_not_taken_as_the_shell_having_gone() {
    let (endpoint, _shell) = UnixStream::pair().expect("a pair of connected streams");
    let mut stream = FailsWith {
        error: rustix::io::Errno::INVAL,
        endpoint,
    };
    let _ = send_to_bridge(&mut stream, b"kr", Instant::now() + REPLY);
}

/// An endpoint whose path is not text is refused by name, rather than told to the shell as a
/// lossy copy that names another path.
#[test]
#[should_panic(expected = "is not UTF-8, so no shell can be told it")]
fn a_path_that_is_not_text_is_refused_rather_than_told_as_another() {
    use std::os::unix::ffi::OsStringExt as _;

    let path = PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/kr-shell-\xff/rt/shell-bridge".to_vec(),
    ));
    let _ = told(&path);
}

/// The bootstrap secret every session of this harness is started with.
#[must_use]
pub fn bootstrap_secret() -> Vec<u8> {
    (0..BOOTSTRAP_SECRET_LEN)
        .map(|i| (i as u8).wrapping_mul(7))
        .collect()
}

mod cases;
mod commands;
mod confinement;
mod dialect;
mod identity;
mod inbox;
mod launch;
mod lines;
mod locale;
mod stacks;

// Each test binary that includes this module uses one part of it: the four package suites use the
// cases and the dialects, and the qualification uses the corpus. What the other one does not name
// is still part of the module it shares.
#[allow(unused_imports)]
pub use cases::*;
#[allow(unused_imports)]
pub use commands::*;
#[allow(unused_imports)]
pub use confinement::*;
pub use dialect::*;
#[allow(unused_imports)]
pub use inbox::*;
#[allow(unused_imports)]
pub use launch::*;
#[allow(unused_imports)]
pub use lines::*;
#[allow(unused_imports)]
pub use locale::*;
#[allow(unused_imports)]
pub use stacks::*;
