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
//! **Ending.** One operation, whatever the reason: the server's input is closed and it is given a
//! moment to finish what it does when its input ends, which for the application's own server is to
//! end the commands it started; if it is still there it is asked to terminate (never to hang up: a
//! hang-up kills it at once and leaves its commands behind) and given a moment more; if it is
//! still there it is ended. Then every process the session recorded below it is ended by its
//! identity, because a command of the server's leaves its process group and its session and
//! outlives a server that dies. What the session recorded is read before the server is asked
//! anything and again before it is ended, since a command whose parent has gone can no longer be
//! found by its parentage. A process the ladder ends by force is noted as forced.
//!
//! **A limit.** On Linux the worker is the child subreaper, so a command the server leaves behind
//! and the ladder then ends is a child of the worker's that nothing collects: it stays in the
//! process table, ended, until the worker exits. The record reads it as ended.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_ipc::identity::{ProcessState, Stop, process_state, started_process_identity, stop_process};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use tokio::io::{AsyncReadExt as _, AsyncWrite};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::broker::image::{ExecutableIdentity, HashedFiles, VerifiedFiles};

/// How long the server has to end after its input has closed.
pub const INPUT_GRACE: Duration = Duration::from_millis(1500);

/// How long it has to end after it was asked to terminate.
pub const TERMINATE_GRACE: Duration = Duration::from_millis(1500);

/// How long a process that was ended by force has to be gone.
pub const FORCE_WAIT: Duration = Duration::from_secs(5);

/// How much of what the server writes to its error stream is kept: the last of it.
pub const MAX_ERROR_BYTES: usize = 64 * 1024;

/// The variables of the launch that are not given to the server: the launcher's registration and
/// its credential name the launch, and the server is not the launched program.
pub const WITHHELD_VARIABLES: [&str; 2] = ["KR_REGISTRATION", "KR_CREDENTIAL"];

/// What a session recorded of the processes below its servers, as the ending reads and changes it.
///
/// The session implements it over its record of the processes it owns.
pub trait Owned: Send + Sync {
    /// Reads what runs below `server` now, and returns the processes recorded below it, the ones
    /// read earlier included, that have not been read as ended.
    fn below(&self, server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity>;

    /// Notes that `process` was ended by force.
    fn forced(&self, process: &ProcessStartIdentity);
}

/// What the server is started from.
#[derive(Debug)]
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

/// How the server came to an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It was gone before the ending began.
    Already,
    /// It ended when its input closed.
    Input,
    /// It ended when it was asked to terminate.
    Terminate,
    /// It was ended by force.
    Force,
}

/// What ending a server came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    /// How the server itself ended.
    pub ended: Ended,
    /// The processes that were ended by force, the server among them when it was.
    pub forced: Vec<ProcessStartIdentity>,
    /// The processes recorded below the server that are still running.
    pub survivors: Vec<ProcessStartIdentity>,
}

/// The server's input, which the connection writes to and the ending closes.
///
/// The connection owns what it writes through; the ending has to close the pipe whoever holds it,
/// so the pipe is shared, and closing it makes every later write fail.
#[derive(Clone, Debug)]
pub struct Input(Arc<Mutex<Option<ChildStdin>>>);

impl Input {
    /// Closes the pipe, for every holder.
    fn close(&self) {
        drop(self.0.lock().unwrap_or_else(PoisonError::into_inner).take());
    }

    fn with<T>(
        &self,
        use_pipe: impl FnOnce(std::pin::Pin<&mut ChildStdin>) -> std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>> {
        match self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            Some(pipe) => use_pipe(std::pin::Pin::new(pipe)),
            None => std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
        }
    }
}

impl AsyncWrite for Input {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.with(|pipe| pipe.poll_write(cx, buffer))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.with(|pipe| pipe.poll_flush(cx))
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
        let path = spec.executable.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let hashed = {
            let stop = Arc::clone(&stop);
            tokio::task::spawn_blocking(move || {
                crate::broker::image::read_identity(&path, &HashedFiles::default(), &stop)
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
        let shown = crate::broker::image::verify_image(
            &identity,
            &ExecutableIdentity {
                hashed,
                version: None,
            },
            &VerifiedFiles::default(),
            &stop,
        );
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
        let server = Self {
            identity,
            child: tokio::sync::Mutex::new(Some(child)),
            input: Input(Arc::new(Mutex::new(input))),
            output: Mutex::new(output),
            errors,
            retired: AtomicBool::new(false),
        };
        match shown {
            Ok(()) => Ok(server),
            Err(why) => {
                // The guard ends it.
                Err(format!(
                    "the server started does not run the code that was hashed, so it was ended: \
                     {why}"
                ))
            }
        }
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

    /// Waits up to `grace` for the server to end, and reaps it when it has.
    async fn ended_within(&self, grace: Duration) -> bool {
        let mut held = self.child.lock().await;
        let Some(child) = held.as_mut() else {
            return true;
        };
        if tokio::time::timeout(grace, child.wait()).await.is_ok() {
            *held = None;
            return true;
        }
        false
    }

    /// Ends the server, and everything the session recorded below it.
    pub async fn retire(&self, owned: &dyn Owned) -> Retirement {
        let mut known: BTreeSet<ProcessStartIdentity> =
            owned.below(&self.identity).into_iter().collect();
        let mut forced = Vec::new();
        let ended = if self.ended_within(Duration::ZERO).await {
            Ended::Already
        } else {
            // Its input closes, and with it the application's own end of the session.
            self.input.close();
            if self.ended_within(INPUT_GRACE).await {
                Ended::Input
            } else {
                known.extend(owned.below(&self.identity));
                let _ = stop_process(&self.identity, Stop::Term);
                if self.ended_within(TERMINATE_GRACE).await {
                    Ended::Terminate
                } else {
                    // The last reading before the process that holds the trees is gone.
                    known.extend(owned.below(&self.identity));
                    let _ = stop_process(&self.identity, Stop::Kill);
                    owned.forced(&self.identity);
                    forced.push(self.identity.clone());
                    self.ended_within(FORCE_WAIT).await;
                    Ended::Force
                }
            }
        };
        self.retired.store(true, Ordering::Release);
        known.extend(owned.below(&self.identity));
        let survivors = end_by_identity(known, owned, &mut forced).await;
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
            let _ = stop_process(&self.identity, Stop::Kill);
        }
    }
}

/// Ends each of `processes` that is running, by its identity: asked to terminate first and given
/// a moment, then ended. Returns the ones still running at the end.
async fn end_by_identity(
    processes: BTreeSet<ProcessStartIdentity>,
    owned: &dyn Owned,
    forced: &mut Vec<ProcessStartIdentity>,
) -> Vec<ProcessStartIdentity> {
    let running = |set: &BTreeSet<ProcessStartIdentity>| -> Vec<ProcessStartIdentity> {
        set.iter()
            .filter(|process| process_state(process) != ProcessState::Ended)
            .cloned()
            .collect()
    };
    let mut remaining = running(&processes);
    for process in &remaining {
        let _ = stop_process(process, Stop::Term);
    }
    wait_until_ended(&mut remaining, TERMINATE_GRACE).await;
    for process in &remaining {
        let _ = stop_process(process, Stop::Kill);
        owned.forced(process);
        forced.push(process.clone());
    }
    wait_until_ended(&mut remaining, FORCE_WAIT).await;
    remaining
}

/// Waits up to `grace` for every process in `remaining` to be gone, and leaves the ones that are
/// not.
async fn wait_until_ended(remaining: &mut Vec<ProcessStartIdentity>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        remaining.retain(|process| process_state(process) != ProcessState::Ended);
        if remaining.is_empty() || tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
