//! Running a package's launch probe.
//!
//! A package can declare how to read the mode its application will run in: the application's own
//! diagnostic, the options of the launch that decide which configuration it reads, and where in
//! what it prints the mode is (see [`kr_plugin_sdk::launch_probe`]). This runs that declaration for
//! one launch, with what it can cost bounded: the probe is a program the package chose, run on this
//! host before a launch, so it gets no input, no shell, an environment its caller names, a short
//! deadline, a cap on what it may print, and a job of its own (a process group on Unix) that ends
//! with it, so nothing it started outlives the answer.
//!
//! One absolute deadline covers the whole operation, from the caller's first instant: creating the
//! process, reading its output, ending it and collecting it. The operation runs on one thread of its
//! own, which owns the process until it has ended it, so a process created after the deadline has
//! passed is ended at once by the thread that created it, and a caller that gave up at the deadline
//! has left nothing running that the thread does not end. The call returns by the deadline plus
//! [`CLEANUP_BOUND`] at the latest.
//!
//! The answer is a word or no word. A probe that cannot be started, does not finish, prints too
//! much or prints something the declaration cannot read records no mode and says why, and does not
//! stop a launch by itself: what the host could not read it does not guess at. One that did not
//! finish is marked late, so that a launch that must not run in a mode it could not read can tell
//! an application that did not finish from one whose answer holds no mode. A nonzero exit status
//! is not a failure: an application's diagnostic exits nonzero for a problem it reports in the
//! output the host reads, and the output is the answer.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};

use kr_plugin_sdk::launch_probe::LaunchProbe;

/// How long a probe is given to print its answer and end, in all.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// How long the thread that ran a probe is given, after the answer is known or the deadline has
/// passed, to end the probe's process and everything it started and to collect it. A placeholder
/// that the figures `Probed` reports will set.
pub const CLEANUP_BOUND: Duration = Duration::from_secs(1);

/// The most a probe may print, in bytes.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// How long the thread waits for output before it looks at the clock and at the cancel flag again.
const SLICE: Duration = Duration::from_millis(20);

/// The one clock a probe runs under, made by the caller before the call and before any queueing, so
/// that a call that waited for a thread has less time and not all of it.
#[derive(Clone, Debug)]
pub struct ProbeRun {
    /// The caller's first instant: what the call's whole time is measured from.
    pub begin: Instant,
    /// The deadline: the call gives its answer, or says it is late, no later than this.
    pub by: Instant,
    /// Set by the caller that gives up before the probe has ended. The thread sees it when it
    /// creates, reads and ends, and ends what it owns.
    pub cancel: Arc<AtomicBool>,
}

impl ProbeRun {
    /// A run that begins now and has `deadline` to finish in.
    #[must_use]
    pub fn within(deadline: Duration) -> Self {
        let begin = Instant::now();
        Self {
            begin,
            by: begin + deadline,
            cancel: Arc::default(),
        }
    }

    fn expired(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || Instant::now() >= self.by
    }
}

/// What running a probe produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probed {
    /// The mode the application reported, exactly as it printed it, where the probe read one.
    pub mode: Option<String>,
    /// Why no mode was read, where none was.
    pub unread: Option<String>,
    /// Whether the probe's output had not ended when its deadline passed: the application did not
    /// finish, as against one that finished with something no mode can be read from. It holds
    /// also for an application that printed a mode and then went on running, whose output the host
    /// does not use.
    pub late: bool,
    /// From the run's first instant to the return of the call, a wait for a thread included.
    pub took: Duration,
    /// From the run's first instant to the end of the probe's own thread, its cleanup included. It
    /// is set when that thread ends, which for a late probe is after the call has returned.
    pub thread_took: Arc<OnceLock<Duration>>,
}

impl Probed {
    fn read(mode: String) -> Self {
        Self {
            mode: Some(mode),
            unread: None,
            late: false,
            took: Duration::ZERO,
            thread_took: Arc::default(),
        }
    }

    fn unread(why: impl Into<String>) -> Self {
        Self {
            mode: None,
            unread: Some(why.into()),
            late: false,
            took: Duration::ZERO,
            thread_took: Arc::default(),
        }
    }

    fn late(why: impl Into<String>) -> Self {
        Self {
            late: true,
            ..Self::unread(why)
        }
    }
}

/// What the probe's thread knew when it stopped reading.
enum Answer {
    Printed(Vec<u8>),
    TooMuch,
    Unread(String),
    Late,
}

/// What the probe's thread tells the call, in this order.
enum Message {
    /// The answer is known. The thread now ends the process.
    Answered(Answer),
    /// The process is ended and collected, or the bound for that has passed.
    Cleaned,
}

/// What the probe's thread is given.
struct Work {
    executable: PathBuf,
    arguments: Vec<String>,
    directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
    run: ProbeRun,
    cap: usize,
    total: Arc<OnceLock<Duration>>,
}

/// Runs `probe` against `executable` for a launch whose own arguments are `launch`, in
/// `directory`, and reads the mode from what it prints, within the deadline `run` holds and with
/// `cap` bytes of output. A launch and the doctor give a run of [`DEADLINE`] and
/// [`MAX_OUTPUT_BYTES`]; this host's own tests give a longer deadline, so that they decide by what
/// a program prints and not by how soon a machine starts it, or a smaller cap.
///
/// The probe runs in `environment` and in no other: the whole set of variables, which the caller
/// gives and nothing of this process's own is added to. A caller that probes for a launch gives the
/// environment that launch runs in, and the doctor gives its own process's variables. It runs in the
/// launch's own directory, and belongs on a thread that may block.
///
/// The call returns by `run.by` plus [`CLEANUP_BOUND`] at the latest. Where the probe is not done
/// at `run.by` the call returns it as late and the probe's thread, which owns the process, goes on
/// to end it.
#[must_use]
pub fn run_within(
    executable: &Path,
    probe: &LaunchProbe,
    launch: &[String],
    directory: &Path,
    environment: &[(OsString, OsString)],
    run: &ProbeRun,
    cap: usize,
) -> Probed {
    let thread_took: Arc<OnceLock<Duration>> = Arc::default();
    let finish = |probed: Probed| Probed {
        took: run.begin.elapsed(),
        thread_took: Arc::clone(&thread_took),
        ..probed
    };
    let shown = executable.display();
    let late = || {
        Probed::late(format!(
            "{shown} did not finish within {} ms",
            run.by.saturating_duration_since(run.begin).as_millis()
        ))
    };
    let arguments = match probe.invocation(launch) {
        Ok(arguments) => arguments,
        Err(why) => return finish(Probed::unread(why)),
    };
    // A call that waited for a thread until its deadline has passed starts nothing.
    if run.expired() {
        return finish(late());
    }
    let (sender, receiver) = mpsc::channel();
    let work = Work {
        executable: executable.to_path_buf(),
        arguments,
        directory: directory.to_path_buf(),
        environment: environment.to_vec(),
        run: run.clone(),
        cap,
        total: Arc::clone(&thread_took),
    };
    let _ = std::thread::spawn(move || operate(&work, &sender));
    let waited = run.by.saturating_duration_since(Instant::now());
    let answer = match receiver.recv_timeout(waited) {
        Ok(Message::Answered(answer)) => answer,
        Ok(Message::Cleaned) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            return finish(Probed::unread(format!(
                "what {shown} printed was lost when its reader ended"
            )));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The thread owns the process, and ends it when it sees this or when its create returns.
            run.cancel.store(true, Ordering::SeqCst);
            return finish(late());
        }
    };
    // The process is ended before the call returns, for as long as the bound allows.
    let ended_by = run.by + CLEANUP_BOUND;
    let _ = receiver.recv_timeout(ended_by.saturating_duration_since(Instant::now()));
    finish(match answer {
        Answer::Printed(printed) => probe.read_mode(&printed).map_or_else(
            || {
                Probed::unread(format!(
                    "what {shown} printed holds no mode at {}",
                    probe.mode
                ))
            },
            Probed::read,
        ),
        Answer::TooMuch => Probed::unread(format!("{shown} printed more than {cap} bytes")),
        Answer::Unread(why) => Probed::unread(why),
        Answer::Late => late(),
    })
}

/// The probe's own thread: creates the process, reads what it prints until the deadline, tells the
/// call, ends the process and collects it.
fn operate(work: &Work, answers: &mpsc::Sender<Message>) {
    #[cfg(feature = "testing")]
    seams::before_create(&work.directory);
    let (answer, mut process) = match Process::start(
        &work.executable,
        &work.arguments,
        &work.directory,
        &work.environment,
    ) {
        Err(error) => (
            Answer::Unread(format!(
                "{} could not be started to read its mode: {error}",
                work.executable.display()
            )),
            None,
        ),
        Ok(mut process) => {
            // Created after the deadline, or after the caller gave up: nothing is read, and this
            // thread, which made it, ends it below.
            let answer = if work.run.expired() {
                Answer::Late
            } else {
                read_output(&mut process, work)
            };
            (answer, Some(process))
        }
    };
    let _ = answers.send(Message::Answered(answer));
    if let Some(process) = process.as_mut() {
        process.end(Instant::now() + CLEANUP_BOUND);
    }
    drop(process);
    let _ = answers.send(Message::Cleaned);
    let _ = work.total.set(work.run.begin.elapsed());
}

/// What the output of a process offers at a moment.
enum Readable {
    /// Data to read, or the end of the file, which a read says.
    Ready,
    /// Neither yet.
    NotYet,
}

/// Reads what the process prints, until its end of the file, the cap, a failure or the deadline.
fn read_output(process: &mut Process, work: &Work) -> Answer {
    let shown = work.executable.display();
    let mut printed = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        if work.run.expired() {
            return Answer::Late;
        }
        let wait = work
            .run
            .by
            .saturating_duration_since(Instant::now())
            .min(SLICE);
        match process.readable(wait) {
            Ok(Readable::NotYet) => continue,
            Ok(Readable::Ready) => {}
            Err(error) => {
                return Answer::Unread(format!("what {shown} printed could not be read: {error}"));
            }
        }
        // One byte past the cap is read, and says that the cap was passed.
        let room = (work.cap + 1 - printed.len()).min(chunk.len());
        match process.read(&mut chunk[..room]) {
            Ok(0) => return Answer::Printed(printed),
            Ok(read) => {
                printed.extend_from_slice(&chunk[..read]);
                if printed.len() > work.cap {
                    return Answer::TooMuch;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Answer::Unread(format!("what {shown} printed could not be read: {error}"));
            }
        }
    }
}

/// The seam the cases of the probe's deadline stand in; it does not exist in a shipped build.
#[cfg(feature = "testing")]
pub mod seams {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    static CREATE_DELAY: Mutex<Option<(PathBuf, Duration)>> = Mutex::new(None);

    /// Makes the probe's thread wait this long before it creates a process that is to run in
    /// `directory`, or stops doing so.
    pub fn delay_create(directory: &Path, delay: Option<Duration>) {
        *CREATE_DELAY.lock().unwrap_or_else(PoisonError::into_inner) =
            delay.map(|delay| (directory.to_path_buf(), delay));
    }

    pub(super) fn before_create(directory: &Path) {
        let delay = CREATE_DELAY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some((held, delay)) = delay
            && held == directory
        {
            std::thread::sleep(delay);
        }
    }
}

/// The process a probe is, and what ends it and everything it started.
#[cfg(unix)]
struct Process {
    child: std::process::Child,
    output: std::process::ChildStdout,
}

#[cfg(unix)]
impl Process {
    fn start(
        executable: &Path,
        arguments: &[String],
        directory: &Path,
        environment: &[(OsString, OsString)],
    ) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt as _;

        let mut command = std::process::Command::new(executable);
        command
            .args(arguments)
            .current_dir(directory)
            .env_clear()
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            // A group of its own, so ending the probe ends what it started.
            .process_group(0);
        #[cfg(feature = "testing")]
        kr_ipc::testing::created::note_here("backend-probe", &command);
        let mut child = command.spawn()?;
        let output = child.stdout.take().expect("the output is piped");
        Ok(Self { child, output })
    }

    /// Waits up to `wait` for the output to have data or to end.
    fn readable(&self, wait: Duration) -> std::io::Result<Readable> {
        use std::os::fd::AsFd as _;

        let output = self.output.as_fd();
        let mut fds = [rustix::event::PollFd::new(
            &output,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(wait.subsec_nanos()),
        };
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => Ok(Readable::NotYet),
            // Data, or the end of the file or a hang-up: a read says which.
            Ok(_) => Ok(Readable::Ready),
            Err(errno) => Err(errno.into()),
        }
    }

    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.output.read(buffer)
    }

    /// Ends the probe's group and waits for the probe until `until`.
    fn end(&mut self, until: Instant) {
        if let Some(group) = i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            // Best effort: a group that has ended already cannot be signalled, which is the
            // outcome wanted.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The process a probe is, and what ends it and everything it started.
#[cfg(windows)]
struct Process {
    child: crate::windows::launch::Child,
    output: std::fs::File,
    /// The job the probe runs in: kill-on-close, so nothing it started outlives it.
    job: crate::windows::job::AgentJob,
}

#[cfg(windows)]
impl Process {
    fn start(
        executable: &Path,
        arguments: &[String],
        directory: &Path,
        environment: &[(OsString, OsString)],
    ) -> std::io::Result<Self> {
        let environment = crate::windows::launch::Environment::from_pairs(environment)
            .map_err(std::io::Error::other)?;
        let job = crate::windows::job::AgentJob::create_owning()?;
        #[cfg(feature = "testing")]
        kr_ipc::testing::created::note_words_here(
            "backend-probe",
            &executable.to_string_lossy(),
            arguments,
        );
        let mut child = crate::windows::launch::start(&crate::windows::launch::Spec {
            program: executable,
            arguments,
            directory,
            environment: &environment,
            session: None,
            agent: &job,
            stdin: crate::windows::launch::Stdio::Null,
            stdout: crate::windows::launch::Stdio::Blocking,
            stderr: crate::windows::launch::Stdio::Null,
        })?;
        let output = child.stdout.take().expect("the output is piped");
        Ok(Self { child, output, job })
    }

    /// Waits up to `wait` for the output to have data or to end.
    fn readable(&self, wait: Duration) -> std::io::Result<Readable> {
        match crate::windows::launch::available(&self.output)? {
            // Broken: the end of the file, which a read says.
            None => Ok(Readable::Ready),
            Some(0) => {
                std::thread::sleep(wait.min(Duration::from_millis(5)));
                Ok(Readable::NotYet)
            }
            Some(_) => Ok(Readable::Ready),
        }
    }

    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.output.read(buffer)
    }

    /// Ends the probe's job and waits for the probe until `until`.
    fn end(&mut self, until: Instant) {
        let _ = self.job.terminate(1);
        let _ = self
            .child
            .wait_for(until.saturating_duration_since(Instant::now()));
    }
}
