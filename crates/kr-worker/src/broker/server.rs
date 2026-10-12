//! The application server a session starts for a native terminal, and how it is ended.
//!
//! A terminal that points itself at the worker's gateway speaks to one application server for the
//! session, a child of the worker on pipes. This is the starting of it and the ending of it, and
//! nothing between: what the server and the terminal say to each other is the gateway's.
//!
//! **Starting.** The executable is hashed and must be the one a signed record names, it runs in a
//! process group of its own (a signal sent to the worker's group is not one the server must
//! answer), with the environment the launcher presented less the two variables that name the
//! launch, and the process the kernel started is read at once and shown to run the code that was
//! hashed. From the moment it exists it is held by a guard: if nothing retires it, dropping it ends
//! the process by its identity.
//!
//! **Ending.** One operation, whatever the reason, with one window of five seconds from the moment
//! it begins, and nothing in it is forced before the window is over. The server's input is closed
//! and it is given a moment to finish what it does when its input ends, which for the
//! application's own server is to end the commands it started. If it is still there it is asked to
//! terminate (never to hang up: a hang-up kills it at once and leaves its commands behind), and so
//! is every process the session recorded below it, which is ended by its identity because a
//! command of the server's leaves its process group and its session and outlives a server that
//! dies; a recorded process is asked as soon as the server is gone when that is sooner. What is
//! still running when the window is over is ended by force, and a process that was forced has two
//! more seconds to be gone, after which the survivors are recorded. What the session recorded is
//! read before the server is asked anything, again and again while the processes below it are
//! ending, and before it is ended, since a command whose parent has gone can no longer be found by
//! its parentage; a process first shown while the others are ending is asked, with the rest of the
//! window, and every force waits for the window to be over. A process the ending forces is noted
//! as forced.
//!
//! **A limit.** On Linux the worker is the child subreaper, so a command the server leaves behind
//! and the ladder then ends is a child of the worker's that nothing collects: it stays in the
//! process table, ended, until the worker exits. The record reads it as ended.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Waker;
use std::time::Duration;

use kr_ipc::identity::{
    ProcessState, Stop, Stopped, process_state, started_process_identity, stop_process,
};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use tokio::io::{AsyncReadExt as _, AsyncWrite};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::broker::image::{ExecutableIdentity, HashedFiles, VerifiedFiles};

/// How long the server has to end after its input has closed, before it is asked to terminate.
pub const INPUT_GRACE: Duration = Duration::from_millis(1500);

/// How long an ending lasts before anything in it is forced, counted from its beginning: the
/// grace a session gives the processes it owns.
pub const GRACE_WINDOW: Duration = crate::session::GRACE_PERIOD;

/// How long a process that was ended by force has to be gone: the drain a session gives after it
/// forces what it owns.
pub const FORCE_WAIT: Duration = crate::session::DRAIN_PERIOD;

/// How much of what the server writes to its error stream is kept: the last of it.
pub const MAX_ERROR_BYTES: usize = 64 * 1024;

/// The variables of the launch that are not given to the server: the launcher's registration and
/// its credential name the launch, and the server is not the launched program.
pub const WITHHELD_VARIABLES: [&str; 2] = kr_protocol::root::LAUNCH_VARIABLES;

/// What a session recorded of the processes below its servers, as the ending reads and changes it.
///
/// The session implements it over its record of the processes it owns.
///
/// The ending reads the record when it begins, again and again while the processes below the server
/// end, before each round of force, and once more at its end. The last reading only reports: a
/// process that it shows for the first time is returned as one that is still running, with no
/// request to terminate and no force. What the session records cannot show one then, because it
/// records a process only while its parent runs and is recorded, and the ending reaches its end
/// after a reading that found nothing running; an implementation that can must expect that.
pub trait Owned: Send + Sync {
    /// Reads what runs below `server` now, and returns the processes recorded below it, the ones
    /// read earlier included, that have not been read as ended.
    fn below(&self, server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity>;

    /// Notes that `process` was ended by force.
    fn forced(&self, process: &ProcessStartIdentity);

    /// Notes that `process` could not be signalled, and why: the system refused, or could not tell
    /// the process from a stranger that holds its number.
    fn unsignalled(&self, process: &ProcessStartIdentity, why: &str);
}

/// What the server is started from.
pub struct ServerSpec<'a> {
    /// The executable, as the launch presented it.
    pub executable: &'a Path,
    /// The digest a signed qualification record names for it.
    pub digest: &'a Digest256,
    /// The arguments the integration's backend declares.
    pub arguments: &'a [String],
    /// The directory the invocation works in.
    pub directory: &'a Path,
    /// The environment the launcher presented.
    pub presented: &'a [(OsString, OsString)],
}

impl std::fmt::Debug for ServerSpec<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The environment is the person's, and is never shown: only how many variables it holds.
        formatter
            .debug_struct("ServerSpec")
            .field("executable", &self.executable)
            .field("digest", &self.digest)
            .field("arguments", &self.arguments)
            .field("directory", &self.directory)
            .field(
                "presented",
                &format_args!("{} variables", self.presented.len()),
            )
            .finish()
    }
}

/// How the server came to an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It was gone before the ending began.
    Already,
    /// It ended when its input closed.
    Input,
    /// It ended when it was asked to terminate, within the window.
    Terminate,
    /// It was still running when the window was over, and was ended by force, or ended of itself
    /// as that was done.
    Force,
    /// It was still running when the ending was over: a signal was refused, or it did not end in
    /// the time a forced end is given. It is among the survivors.
    Alive,
}

/// What ending a server came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    /// How the server itself ended.
    pub ended: Ended,
    /// The processes that were ended by force, the server among them when it was.
    pub forced: Vec<ProcessStartIdentity>,
    /// The processes still running when the ending was over: the ones recorded below the server,
    /// and the server itself when it is [`Ended::Alive`].
    pub survivors: Vec<ProcessStartIdentity>,
}

/// The server's input, which the connection writes to and the ending closes.
///
/// The connection owns what it writes through; the ending has to close the pipe whoever holds it,
/// so the pipe is shared, and closing it makes every later write fail and wakes a write that was
/// waiting. A shutdown of a holder's end closes it for every holder, which is the end of the
/// server's input.
#[derive(Clone, Debug)]
pub struct Input(Arc<Mutex<InputState>>);

#[derive(Debug)]
struct InputState {
    pipe: Option<ChildStdin>,
    /// The task whose write or flush is waiting, woken when the pipe is closed.
    waiting: Option<Waker>,
}

impl Input {
    fn new(pipe: Option<ChildStdin>) -> Self {
        Self(Arc::new(Mutex::new(InputState {
            pipe,
            waiting: None,
        })))
    }

    /// Closes the pipe, for every holder.
    fn close(&self) {
        let (pipe, waiting) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            (state.pipe.take(), state.waiting.take())
        };
        drop(pipe);
        if let Some(waker) = waiting {
            waker.wake();
        }
    }

    fn with<T>(
        &self,
        cx: &mut std::task::Context<'_>,
        use_pipe: impl FnOnce(
            std::pin::Pin<&mut ChildStdin>,
            &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pipe) = state.pipe.as_mut() else {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        };
        let polled = use_pipe(std::pin::Pin::new(pipe), cx);
        if polled.is_pending() {
            state.waiting = Some(cx.waker().clone());
        }
        polled
    }
}

impl AsyncWrite for Input {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.with(cx, |pipe, cx| pipe.poll_write(cx, buffer))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.with(cx, |pipe, cx| pipe.poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.close();
        std::task::Poll::Ready(Ok(()))
    }
}

/// The last bytes of what a process wrote.
#[derive(Debug, Default)]
struct Tail(Mutex<VecDeque<u8>>);

impl Tail {
    fn push(&self, bytes: &[u8]) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.extend(bytes);
        let over = held.len().saturating_sub(MAX_ERROR_BYTES);
        held.drain(..over);
    }

    fn text(&self) -> String {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes: Vec<u8> = held.iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// What a started server is shown against: the executable that was hashed.
#[derive(Debug)]
pub(crate) struct Unshown {
    hashed: crate::broker::image::HashedFile,
    stop: Arc<AtomicBool>,
}

/// An application server a session started.
#[derive(Debug)]
pub struct Server {
    identity: ProcessStartIdentity,
    child: tokio::sync::Mutex<Option<Child>>,
    input: Input,
    output: Mutex<Option<ChildStdout>>,
    errors: Arc<Tail>,
    retired: AtomicBool,
}

impl Server {
    /// Starts the server `spec` names.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started, or why what started was ended again: the executable could
    /// not be read or is not the one the record names, the process could not be started, could not
    /// be read once started, or does not run the code that was hashed.
    pub async fn start(spec: &ServerSpec<'_>) -> Result<Self, String> {
        let (server, unshown) = Self::spawn(spec, Arc::new(HashedFiles::default())).await?;
        server.show(unshown).await?;
        Ok(server)
    }

    /// Starts the server `spec` names, reading the executable through `cache`, which holds what
    /// was read of it already while it is unchanged, and returns it before it is shown to run the
    /// executable that was hashed.
    ///
    /// The process exists when this returns, and nothing that can be cancelled is awaited after it
    /// is started, so a caller that puts the server where its ending finds it, and has it recorded,
    /// before it awaits [`Server::show`] leaves no moment in which the server runs and nothing
    /// would end it and what it starts.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started: the executable could not be read or is not the one the
    /// record names, or the process could not be started or read once started.
    pub(crate) async fn spawn(
        spec: &ServerSpec<'_>,
        cache: Arc<HashedFiles>,
    ) -> Result<(Self, Unshown), String> {
        if !spec.executable.is_absolute() {
            return Err(format!(
                "{} is not an absolute path, so no server was started",
                spec.executable.display()
            ));
        }
        if let Some((name, _)) = spec
            .presented
            .iter()
            .find(|(name, _)| !is_variable_name(name.as_bytes()))
        {
            return Err(format!(
                "the environment presented holds the name {name:?}, which no variable has, so no \
                 server was started"
            ));
        }
        let path = spec.executable.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let hashed = {
            let stop = Arc::clone(&stop);
            tokio::task::spawn_blocking(move || {
                crate::broker::image::read_identity(&path, &cache, &stop)
            })
            .await
            .map_err(|error| format!("the executable could not be read: {error}"))??
        };
        if &hashed.digest != spec.digest {
            return Err(format!(
                "{} is not the executable the signed record names, so no server was started",
                spec.executable.display()
            ));
        }
        let mut command = Command::new(spec.executable);
        command
            .args(spec.arguments)
            .current_dir(spec.directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        for (name, value) in spec.presented {
            if !WITHHELD_VARIABLES.iter().any(|withheld| name == *withheld) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().map_err(|error| {
            format!(
                "{} could not be started: {error}",
                spec.executable.display()
            )
        })?;
        let identity = match child.id().map(started_process_identity) {
            Some(Ok(identity)) => identity,
            Some(Err(error)) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(format!(
                    "the server started cannot be read, so it was ended: {error}"
                ));
            }
            None => return Err("the server ended as it started".to_owned()),
        };
        let errors = Arc::new(Tail::default());
        let output = child.stdout.take();
        let input = child.stdin.take();
        if let Some(mut stream) = child.stderr.take() {
            let errors = Arc::clone(&errors);
            tokio::spawn(async move {
                let mut chunk = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    errors.push(&chunk[..read]);
                }
            });
        }
        // From here the guard holds it: whatever returns or is dropped below ends the process.
        let server = Self {
            identity: identity.clone(),
            child: tokio::sync::Mutex::new(Some(child)),
            input: Input::new(input),
            output: Mutex::new(output),
            errors,
            retired: AtomicBool::new(false),
        };
        Ok((server, Unshown { hashed, stop }))
    }

    /// Shows that the server runs the executable that was hashed.
    ///
    /// # Errors
    ///
    /// Returns why it was not shown to: the image could not be read, or is not the one that was
    /// hashed. The server is still running, and is the caller's to end.
    pub(crate) async fn show(&self, unshown: Unshown) -> Result<(), String> {
        let identity = self.identity.clone();
        // Off the runtime's threads: where the image is hashed again, it is the whole file.
        let shown = tokio::task::spawn_blocking(move || {
            crate::broker::image::verify_image(
                &identity,
                &ExecutableIdentity {
                    hashed: unshown.hashed,
                    version: None,
                },
                &VerifiedFiles::default(),
                &unshown.stop,
            )
        })
        .await
        .map_err(|error| format!("the server's image could not be read: {error}"))?;
        shown.map_err(|why| {
            format!("the server started does not run the code that was hashed: {why}")
        })
    }

    /// The process the kernel started, by its identifier and start.
    #[must_use]
    pub const fn identity(&self) -> &ProcessStartIdentity {
        &self.identity
    }

    /// Hands over the server's output and input, once.
    #[must_use]
    pub fn take_pipes(&self) -> Option<(ChildStdout, Input)> {
        let output = self
            .output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        Some((output, self.input.clone()))
    }

    /// The last of what the server wrote to its error stream.
    #[must_use]
    pub fn error_tail(&self) -> String {
        self.errors.text()
    }

    /// Waits until `deadline` for the server to end, and reaps it when it has.
    async fn ended_by(&self, deadline: tokio::time::Instant) -> bool {
        let mut held = self.child.lock().await;
        let Some(child) = held.as_mut() else {
            return true;
        };
        match tokio::time::timeout_at(deadline, child.wait()).await {
            Ok(Ok(_)) => {
                *held = None;
                true
            }
            // The system will not say how it ended, so the kernel is asked whether it did.
            Ok(Err(_)) => {
                let mut remaining = vec![self.identity.clone()];
                wait_until_ended(&mut remaining, deadline).await;
                remaining.is_empty()
            }
            Err(_) => false,
        }
    }

    /// Asks the server to end with `stop`, by its identity; where the system will not signal by
    /// identity, through the child this holds, which has not been collected and so still names
    /// the server. Returns whether a signal was delivered: not when the server was already gone,
    /// which delivers nothing and so forces nothing.
    async fn ask(&self, stop: Stop, owned: &dyn Owned) -> bool {
        match stop_process(&self.identity, stop) {
            Stopped::Signalled => true,
            Stopped::Gone | Stopped::Unsupported => false,
            Stopped::Refused(why) | Stopped::Unsafe(why) => {
                let mut held = self.child.lock().await;
                let signalled = held.as_mut().is_some_and(|child| match stop {
                    Stop::Kill => child.start_kill().is_ok(),
                    _ => child
                        .id()
                        .and_then(|pid| i32::try_from(pid).ok())
                        .and_then(rustix::process::Pid::from_raw)
                        .is_some_and(|pid| {
                            rustix::process::kill_process(pid, rustix::process::Signal::TERM)
                                .is_ok()
                        }),
                });
                if !signalled {
                    owned.unsignalled(&self.identity, &why);
                }
                signalled
            }
        }
    }

    /// Ends the server, and everything the session recorded below it.
    ///
    /// `begun` is when the graceful stop of the server began: nothing is forced before
    /// [`GRACE_WINDOW`] after it. A session that is closing passes the moment its own stop began,
    /// so that its forcing of the processes it owns and this ending keep one clock.
    ///
    /// What comes back says how the server ended, which processes were ended by force, and which
    /// are still running: the server too, when it would not end.
    pub async fn retire(&self, owned: &dyn Owned, begun: tokio::time::Instant) -> Retirement {
        let window_over = begun + GRACE_WINDOW;
        let mut known: BTreeSet<ProcessStartIdentity> =
            owned.below(&self.identity).into_iter().collect();
        let mut asked = BTreeSet::new();
        let mut forced = Vec::new();
        let ended = if self.ended_by(begun).await {
            Ended::Already
        } else {
            // Its input closes, and with it the application's own end of the session.
            self.input.close();
            if self.ended_by(begun + INPUT_GRACE).await {
                Ended::Input
            } else {
                known.extend(owned.below(&self.identity));
                self.ask(Stop::Term, owned).await;
                ask_below(&known, &mut asked, owned);
                if self.ended_by(window_over).await {
                    Ended::Terminate
                } else {
                    // The last reading before the process that holds the trees is gone.
                    known.extend(owned.below(&self.identity));
                    if self.ask(Stop::Kill, owned).await {
                        owned.forced(&self.identity);
                        forced.push(self.identity.clone());
                    }
                    if self
                        .ended_by(tokio::time::Instant::now() + FORCE_WAIT)
                        .await
                    {
                        Ended::Force
                    } else {
                        Ended::Alive
                    }
                }
            }
        };
        let mut survivors = end_below(
            &self.identity,
            known,
            asked,
            window_over,
            owned,
            &mut forced,
        )
        .await;
        if ended == Ended::Alive {
            // The guard has one more try when this is dropped.
            survivors.push(self.identity.clone());
        } else {
            self.retired.store(true, Ordering::Release);
        }
        Retirement {
            ended,
            forced,
            survivors,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.retired.load(Ordering::Acquire) {
            // Closed for every holder of the pipe, so a server that ends with its input does.
            self.input.close();
            let _ = stop_process(&self.identity, Stop::Kill);
            // The child is held and not collected, so it names the server even where the system
            // would not signal by identity.
            if let Ok(mut held) = self.child.try_lock()
                && let Some(child) = held.as_mut()
            {
                let _ = child.start_kill();
            }
        }
    }
}

/// Whether `name` can be the name of a variable the server is given: not empty, and holding no
/// `=` (which would end the name where the system writes `NAME=value`) and no NUL.
fn is_variable_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&b'=') && !name.contains(&0)
}

/// Asks each of `known` that is running and has not been asked to terminate, by its identity.
fn ask_below(
    known: &BTreeSet<ProcessStartIdentity>,
    asked: &mut BTreeSet<ProcessStartIdentity>,
    owned: &dyn Owned,
) {
    for process in known {
        if process_state(process) != ProcessState::Ended && asked.insert(process.clone()) {
            signal(process, Stop::Term, owned);
        }
    }
}

/// How often the record is read again while the processes below the server are ending.
const RECORD_REREAD: Duration = Duration::from_millis(200);

/// Ends each process recorded below `server` that is running, by its identity.
///
/// Until `window_over` the record is read again and again, and every process it shows is asked to
/// terminate once, so that one that a command started while the others were ending has its grace
/// too; the window ends early only when a reading finds nothing running. Then what is still running
/// is ended by force, a few rounds, each reading the record for what the last one left.
///
/// **Nothing is forced before `window_over`, by construction:** every round of force first asks
/// what it has not asked and waits for it until `window_over`, so a process that a reading before
/// force shows for the first time, at any moment, has the rest of the window and is forced only if
/// it is still there when the window is over. The reading at the very end only reports (see
/// [`Owned`]). Returns the processes still running at the end.
async fn end_below(
    server: &ProcessStartIdentity,
    mut known: BTreeSet<ProcessStartIdentity>,
    mut asked: BTreeSet<ProcessStartIdentity>,
    window_over: tokio::time::Instant,
    owned: &dyn Owned,
    forced: &mut Vec<ProcessStartIdentity>,
) -> Vec<ProcessStartIdentity> {
    let running = |set: &BTreeSet<ProcessStartIdentity>| -> Vec<ProcessStartIdentity> {
        set.iter()
            .filter(|process| process_state(process) != ProcessState::Ended)
            .cloned()
            .collect()
    };
    let mut remaining;
    loop {
        known.extend(owned.below(server));
        ask_below(&known, &mut asked, owned);
        remaining = running(&known);
        let now = tokio::time::Instant::now();
        if remaining.is_empty() || now >= window_over {
            break;
        }
        wait_until_ended(&mut remaining, (now + RECORD_REREAD).min(window_over)).await;
    }
    for _ in 0..KILL_ROUNDS {
        known.extend(owned.below(server));
        ask_below(&known, &mut asked, owned);
        remaining = running(&known);
        if remaining.is_empty() {
            break;
        }
        // The one place a process is forced: not before the window is over, whatever the readings
        // showed and whenever they showed it.
        wait_until_ended(&mut remaining, window_over).await;
        for process in &remaining {
            if signal(process, Stop::Kill, owned) {
                owned.forced(process);
                forced.push(process.clone());
            }
        }
        wait_until_ended(&mut remaining, tokio::time::Instant::now() + FORCE_WAIT).await;
    }
    known.extend(owned.below(server));
    running(&known)
}

/// How many times the ending reads the record again and ends what it finds there.
const KILL_ROUNDS: usize = 3;

/// Signals one process by its identity, and says whether it was signalled; a refusal goes to
/// `owned`.
fn signal(process: &ProcessStartIdentity, stop: Stop, owned: &dyn Owned) -> bool {
    match stop_process(process, stop) {
        Stopped::Signalled => true,
        Stopped::Gone | Stopped::Unsupported => false,
        Stopped::Refused(why) | Stopped::Unsafe(why) => {
            owned.unsignalled(process, &why);
            false
        }
    }
}

/// Waits until `deadline` for every process in `remaining` to be gone, and leaves the ones that
/// are not.
async fn wait_until_ended(
    remaining: &mut Vec<ProcessStartIdentity>,
    deadline: tokio::time::Instant,
) {
    loop {
        remaining.retain(|process| process_state(process) != ProcessState::Ended);
        if remaining.is_empty() || tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
