//! The application server on Windows: a process in a job of its own, started inside the session's
//! job, on pipes the runtime reads and writes.
//!
//! **Starting.** The executable is read through one held file, which nothing can rename, write or
//! delete while it is held, hashed once, and must be the one a signed record names. The server
//! runs in the environment the launcher presented less the two variables that name the launch, in
//! a job of its own that ends what it holds when its last handle closes, and in the session's job:
//! a session whose job has gone starts no server. Its three standard streams are private overlapped
//! pipes. The process the kernel started is read at once and shown to have been created from the
//! held file, and its job is kept (see [`crate::windows::job::keep_agent`]). From the moment it
//! exists it is held by a guard: if nothing retires it, dropping it ends its job, and a start that
//! is given up while the process is being created ends what that creates itself.
//!
//! **Ending.** The server's job holds the server and every process a descendant of it created as
//! its own child, so the ending is of the job: the input is closed, the job is waited for until the
//! window is over to be empty (not only for the server to be gone: a command that is ending after
//! the input closed is not forced early), and then terminated, and the job is read until it is
//! empty or the time a forced process has to be gone is over. The steps and their order are
//! [`super::end_tree`]'s, which a case runs over a tree that is a script; here the tree is the job.
//! There is no request to terminate on Windows, so a server that ignores the end of its input is
//! ended by force when the window is over, and the ending never ends a process the server's job
//! does not hold.
//!
//! **A limit.** The job holds no process that a service creates on a descendant's behalf, and none
//! that a descendant creates under a parent outside the job.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_ipc::identity::{START_VALUE_UNREAD, started_process_identity};
use kr_protocol::identity::ProcessStartIdentity;
use tokio::io::AsyncReadExt as _;
use tokio::net::windows::named_pipe::NamedPipeServer;

use super::{
    Emptiness, Ended, Input, Member, Owned, Retirement, ServerSpec, Tail, Tree, WITHHELD_VARIABLES,
    end_tree,
};
use crate::broker::image::{HashedFiles, read_holding, show_image};
use crate::windows::job::{AgentJob, MemberReading, holding, keep_agent, release_agent};
use crate::windows::launch::{Child, Environment, Spec, Stdio, start};

/// What the server's input is made of: this worker's end of a private pipe.
pub type InputPipe = NamedPipeServer;

/// What the server's output is made of: this worker's end of a private pipe.
pub type Output = NamedPipeServer;

/// What a started server is shown against: the file that was hashed, held open.
#[derive(Debug)]
pub(crate) struct Unshown {
    held: std::fs::File,
}

/// Gives up a start when the future that awaits it is dropped: the blocking call that creates the
/// process cannot be cancelled, so it is told, and ends what it made.
struct GivenUp(Arc<AtomicBool>);

impl Drop for GivenUp {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// An application server a session started.
#[derive(Debug)]
pub struct Server {
    identity: ProcessStartIdentity,
    job: Arc<AgentJob>,
    process: Mutex<Child>,
    input: Input,
    output: Mutex<Option<Output>>,
    errors: Arc<Tail>,
    retired: AtomicBool,
}

impl Server {
    /// Starts the server `spec` names, inside the job of the session whose root shell is
    /// `session_root`.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started, or why what started was ended again: the session's job has
    /// gone, the executable could not be read or is not the one the record names, the process could
    /// not be started or read once started, or it was not created from the file that was hashed.
    pub async fn start(spec: &ServerSpec<'_>, session_root: u32) -> Result<Self, String> {
        let (server, unshown) =
            Self::spawn(spec, Arc::new(HashedFiles::default()), session_root).await?;
        server.show(unshown).await?;
        Ok(server)
    }

    /// Starts the server `spec` names, reading the executable through `cache`, which holds what
    /// was read of it already while it is unchanged, and returns it before it is shown to have
    /// been created from the file that was hashed.
    ///
    /// The process exists when this returns, and its job is kept, so a caller that puts the server
    /// where its ending finds it, and has it recorded, before it awaits [`Server::show`] leaves no
    /// moment in which the server runs and nothing would end it and what it starts.
    ///
    /// # Errors
    ///
    /// Returns why nothing was started: the session's job has gone, the executable could not be
    /// read or is not the one the record names, or the process could not be started or read once
    /// started.
    pub(crate) async fn spawn(
        spec: &ServerSpec<'_>,
        cache: Arc<HashedFiles>,
        session_root: u32,
    ) -> Result<(Self, Unshown), String> {
        if !spec.executable.is_absolute() {
            return Err(format!(
                "{} is not an absolute path, so no server was started",
                spec.executable.display()
            ));
        }
        let environment = Environment::from_pairs(spec.presented)
            .map_err(|why| format!("the environment presented cannot be given to a server: {why}"))?
            .without(&WITHHELD_VARIABLES);
        let session = holding(session_root).ok_or_else(|| {
            "the session's job has gone, so the server a session holds was not started".to_owned()
        })?;
        let path = spec.executable.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let (hashed, held) = {
            let (path, stop) = (path.clone(), Arc::clone(&stop));
            tokio::task::spawn_blocking(move || read_holding(&path, &cache, &stop))
                .await
                .map_err(|error| format!("the executable could not be read: {error}"))??
        };
        if &hashed.digest != spec.digest {
            return Err(format!(
                "{} is not the executable the signed record names, so no server was started",
                spec.executable.display()
            ));
        }
        let job = Arc::new(
            AgentJob::create_owning()
                .map_err(|error| format!("the server's job could not be made: {error}"))?,
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let _given_up = GivenUp(Arc::clone(&cancelled));
        let mut child = {
            let arguments = spec.arguments.to_vec();
            let directory = spec.directory.to_path_buf();
            let job = Arc::clone(&job);
            let cancelled = Arc::clone(&cancelled);
            tokio::task::spawn_blocking(move || {
                #[cfg(feature = "testing")]
                kr_ipc::testing::created::note_words_here(
                    "backend",
                    &path.to_string_lossy(),
                    &arguments,
                );
                let child = start(&Spec {
                    program: &path,
                    arguments: &arguments,
                    directory: &directory,
                    environment: &environment,
                    session: Some(&session),
                    agent: &job,
                    stdin: Stdio::Overlapped,
                    stdout: Stdio::Overlapped,
                    stderr: Stdio::Overlapped,
                })?;
                // The caller stopped waiting while the process was being created: what was made
                // is ended here, since nothing else holds it.
                if cancelled.load(Ordering::Acquire) {
                    let _ = job.terminate(1);
                    return Err(std::io::Error::other("the start was given up"));
                }
                Ok(child)
            })
            .await
            .map_err(|error| format!("the server could not be started: {error}"))?
            .map_err(|error| {
                format!(
                    "{} could not be started: {error}",
                    spec.executable.display()
                )
            })?
        };
        let identity = match started_process_identity(child.id()) {
            Ok(identity) if identity.start_value.get() != START_VALUE_UNREAD => identity,
            Ok(_) => {
                let _ = job.terminate(1);
                return Err("the server ended as it started".to_owned());
            }
            Err(error) => {
                let _ = job.terminate(1);
                return Err(format!(
                    "the server started cannot be read, so it was ended: {error}"
                ));
            }
        };
        let errors = Arc::new(Tail::default());
        let output = child.overlapped_stdout.take();
        let input = child.overlapped_stdin.take();
        if let Some(mut stream) = child.overlapped_stderr.take() {
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
        // The job is kept for whoever records the server, and is ended with it below.
        keep_agent(identity.clone(), Arc::clone(&job));
        // From here the guard holds it: whatever returns or is dropped below ends the job.
        let server = Self {
            identity,
            job,
            process: Mutex::new(child),
            input: Input::new(input),
            output: Mutex::new(output),
            errors,
            retired: AtomicBool::new(false),
        };
        Ok((server, Unshown { held }))
    }

    /// Shows that the server was created from the file that was hashed.
    ///
    /// # Errors
    ///
    /// Returns why it was not shown to: the image could not be read, or is not the held file. The
    /// server is still running, and is the caller's to end.
    pub(crate) async fn show(&self, unshown: Unshown) -> Result<(), String> {
        let identity = self.identity.clone();
        // Off the runtime's threads: the process's image is opened and read by the system.
        tokio::task::spawn_blocking(move || show_image(&identity, &unshown.held))
            .await
            .map_err(|error| format!("the server's image could not be read: {error}"))?
            .map_err(|why| {
                format!("the server started does not run the code that was hashed: {why}")
            })
    }

    /// The process the kernel started, by its identifier and start.
    #[must_use]
    pub const fn identity(&self) -> &ProcessStartIdentity {
        &self.identity
    }

    /// The server's own job: the server and what its descendants created as their own children.
    #[must_use]
    pub fn job(&self) -> &Arc<AgentJob> {
        &self.job
    }

    /// Hands over the server's output and input, once.
    #[must_use]
    pub fn take_pipes(&self) -> Option<(Output, Input)> {
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

    /// Ends the server, and everything its job holds.
    ///
    /// `begun` is when the graceful stop of the server began: nothing is forced before
    /// [`super::GRACE_WINDOW`] after it. A session that is closing passes the moment its own stop
    /// began, so that its forcing of the processes it owns and this ending keep one clock.
    ///
    /// What comes back says how the server ended, which processes were ended by force, which are
    /// still running (the server too, when it would not end), and whether the job is empty.
    pub async fn retire(&self, owned: &dyn Owned, begun: tokio::time::Instant) -> Retirement {
        let mut retirement = end_tree(self, owned, begun).await;
        if retirement.ended == Ended::Alive && !retirement.survivors.contains(&self.identity) {
            retirement.survivors.push(self.identity.clone());
        }
        if retirement.emptiness == Emptiness::Empty {
            self.retired.store(true, Ordering::Release);
        }
        retirement
    }
}

impl Tree for Server {
    async fn root_running(&self) -> bool {
        // A process that cannot be asked about is taken to run: its input is closed, and its job
        // is read and ended all the same.
        !matches!(
            self.process
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .try_wait(),
            Ok(Some(_))
        )
    }

    fn close_input(&self) {
        self.input.close();
    }

    async fn members(&self) -> Result<Vec<Member>, String> {
        let job = Arc::clone(&self.job);
        tokio::task::spawn_blocking(move || {
            let mut members = Vec::new();
            for pid in job.process_ids().map_err(|error| error.to_string())? {
                match job.member(pid) {
                    MemberReading::Held(identity) => members.push(Member::Held(identity)),
                    // Listed, and not in the job when it was asked: it ended, or a stranger holds
                    // the number.
                    MemberReading::NotHeld => {}
                    MemberReading::Unreadable(why) => members.push(Member::Unreadable(why)),
                }
            }
            Ok(members)
        })
        .await
        .map_err(|error| format!("the job could not be read: {error}"))?
    }

    async fn terminate(&self) -> Result<(), String> {
        let job = Arc::clone(&self.job);
        tokio::task::spawn_blocking(move || job.terminate(1))
            .await
            .map_err(|error| format!("the job could not be ended: {error}"))?
            .map_err(|error| error.to_string())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.retired.load(Ordering::Acquire) {
            // Closed for every holder of the pipe, so a server that ends with its input does.
            self.input.close();
            // The job holds the server and what it started, so nothing is left to find by hand.
            let _ = self.job.terminate(1);
            release_agent(&self.identity);
        }
    }
}
