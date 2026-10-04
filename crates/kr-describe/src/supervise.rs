//! The daemon's side of the description process: starting it, speaking the wire, holding it to its
//! deadlines, and ending it.
//!
//! [`Driver`] owns the [`DescriptionService`] and the one process it drives, and it runs on one
//! thread of the host's. Each [`Driver::turn`] takes the answers that have arrived, enforces the
//! timers, and then does what the service says until it says to wait. Around it, two threads per
//! process do the blocking: a reader posts each answer, whole, to the driver's channel, and a
//! writer holds at most [`REQUESTS_HELD`] frames for the process's input. The host blocks in
//! [`Driver::wait`], which returns when something arrives or its time is up; a [`Waker`] lets
//! anything else wake it.
//!
//! The timers are the host's side of every bound, and each ends a process that breaks it with
//! `Child::kill` and collects it:
//!
//! | Timer | Bound |
//! | --- | --- |
//! | The handshake | [`HANDSHAKE_MS`] for `ready` |
//! | A load | its own deadline, plus [`ANSWER_GRACE_MS`] |
//! | A job | its execution deadline, plus [`ANSWER_GRACE_MS`] |
//! | A cancellation | [`CANCEL_MS`] for the process to say it has read it; a load's or a check's own answer is then held to the same bound |
//! | A check of a file | its deadline, plus [`ANSWER_GRACE_MS`] |
//! | The ceiling | the process's resident set, read every [`SAMPLE_MS`] while it loads or runs a job |
//!
//! Nothing here reads a clock for a decision: every turn takes the host's reading, as the service
//! does, so a timer is tested by the reading a test passes rather than by waiting for it.
//!
//! A process started to check a file holds no model: when the check is done, and it has been given
//! no load and no job, the driver ends it ([`UnloadReason::CheckDone`]), so nothing is left running
//! for a file that has been checked. A load or a job asked for while a check is in the process is
//! the host's to avoid, as a host that holds nothing without its files does.
//!
//! The process is started with no environment but what the launch names, in the working directory
//! the launch names, and it is the daemon's own child. Nothing in it outlives the daemon: its input
//! ends when the daemon does, and its watchdog looks for the daemon by the start identity it is
//! given, which covers a control thread that never sees that end.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::U64;

use crate::error::Result;
use crate::resource::HostConditions;
use crate::serve::DAEMON_IDENTITY_ARGUMENT;
use crate::service::{
    Answered, DescriptionService, Instruction, Outcome, ProcessEnd, UnloadReason, Work,
};
use crate::time::Reading;
use crate::wire::{
    Answer, AssetFile, Background, JobLimits, Request, VerifyResult, WIRE_VERSION, WireError,
    frame_of, read_message, same_release,
};

/// How long a process has to answer `hello`.
pub const HANDSHAKE_MS: u64 = 10_000;

/// How far past its own deadline a load or a job may go before the process is ended.
pub const ANSWER_GRACE_MS: u64 = 2_000;

/// How long a process has to say it has read a cancellation, and how long a load or a check of a
/// file has to answer one.
///
/// A job's cancellation is held to the first alone: the control thread says at once that it has
/// read it, and the job's own answer is then bounded by the job's deadline and the process's own
/// watchdog, so a busy host that takes a moment to stop a job is not mistaken for a process that is
/// not listening. A load and a check of a file lose nothing when the process is ended, so each is
/// held to this bound for its own answer too. A process that said it had read the cancellation and
/// then did not stop the load or the check is ended without a failure of inference
/// ([`ProcessEnd::StopOverdue`]); one that did not say so is not listening, which is one
/// ([`ProcessEnd::CancelUnanswered`]).
pub const CANCEL_MS: u64 = 2_000;

/// How often the process's resident set is read while it loads or runs a job.
pub const SAMPLE_MS: u64 = 1_000;

/// How many frames wait for the process's input at most. A process that has not read them is not
/// reading, and is ended.
pub const REQUESTS_HELD: usize = 4;

/// How long an unload waits for the process to leave on its own once its input is closed.
const LEAVE_WAIT: Duration = Duration::from_secs(2);

/// The name of the thread that writes a process's requests to its input.
pub const WRITER_THREAD: &str = "describe-writer";

/// The name of the thread that reads a process's answers from its output.
pub const READER_THREAD: &str = "describe-reader";

/// How the daemon starts the description process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// The executable.
    pub program: PathBuf,
    /// Its arguments.
    pub arguments: Vec<OsString>,
    /// Where it runs: the daemon's state directory.
    pub working_directory: PathBuf,
    /// The whole of its environment.
    pub environment: Vec<(OsString, OsString)>,
    /// Where the model files are: `<models>/<profile>/<revision>/<file>`.
    pub models: PathBuf,
}

/// Something the driver's channel carries.
#[derive(Debug)]
pub enum Event {
    /// An answer, whole, from the process started as `tag`.
    Answer {
        /// Which process.
        tag: u64,
        /// What it said.
        answer: Answer,
    },
    /// The process started as `tag` stopped speaking the wire.
    Closed {
        /// Which process.
        tag: u64,
        /// How.
        why: ProcessEnd,
    },
    /// Something the host holds changed, and the driver should look again.
    Wake,
}

/// Wakes a driver waiting in [`Driver::wait`].
#[derive(Clone, Debug)]
pub struct Waker(Sender<Event>);

impl Waker {
    /// Wakes the driver.
    pub fn wake(&self) {
        let _ = self.0.send(Event::Wake);
    }
}

/// What a turn did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    /// A process was started.
    Started {
        /// Its identifier.
        pid: u32,
    },
    /// What the service made of an answer, or of the process ending.
    Outcome(Outcome),
    /// The process was ended on the service's word.
    Unloaded {
        /// Why.
        why: UnloadReason,
    },
    /// A check of a file came to an end.
    Checked {
        /// The check's identifier.
        id: u64,
        /// How it came out.
        checked: Checked,
    },
}

/// How a check of a file came out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checked {
    /// The process answered.
    Answered {
        /// What it found.
        result: VerifyResult,
        /// What it said besides, when it said anything.
        detail: Option<String>,
    },
    /// The process ended before it answered.
    ProcessEnded {
        /// How.
        why: ProcessEnd,
    },
    /// The check was not sent: the process holds work or another check, and a check holds the
    /// process's model thread, so one sent behind either would wait while its own deadline ran.
    Refused,
    /// The service had the process ended while the check was in it.
    Unloaded,
}

/// A file to check, and what it is to be checked against: a file of one of the profiles the
/// process's own catalogue holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// The check's identifier, which the host chooses and the driver reports back.
    pub id: u64,
    /// The profile.
    pub profile_id: String,
    /// The profile's revision.
    pub revision: u64,
    /// The file's name, as the profile records it.
    pub file_name: String,
    /// Where the file is.
    pub path: PathBuf,
    /// How long it may take, in milliseconds.
    pub deadline_ms: u64,
}

/// A timer on one piece of work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Due {
    id: u64,
    at_ms: u64,
}

/// The process the driver has.
#[derive(Debug)]
struct Running {
    tag: u64,
    child: Child,
    requests: Option<SyncSender<Vec<u8>>>,
    ready: bool,
    hello_at_ms: u64,
    identity: Option<ProcessStartIdentity>,
    work: Option<Due>,
    cancel: Option<Cancel>,
    /// The check of a file in the process, when one is.
    check: Option<Due>,
    /// Whether the process has been given a load or a job. One that has only ever checked a file
    /// holds no model, and goes when the check is done.
    worked: bool,
    next_sample_ms: u64,
}

/// What kind of work a cancellation is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Job,
    Load,
    Check,
}

/// A cancellation sent, and whether the control thread has said it has read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cancel {
    id: u64,
    at_ms: u64,
    kind: Kind,
    acknowledged: bool,
}

impl Cancel {
    /// Whether this cancellation is still held to its timer: always before it is acknowledged, and
    /// after it for a load or a check, whose own answer is bounded the same way.
    const fn timed(self) -> bool {
        !self.acknowledged || !matches!(self.kind, Kind::Job)
    }
}

/// The daemon's driver of the description service and its process.
#[derive(Debug)]
pub struct Driver {
    service: DescriptionService,
    launch: Launch,
    build: String,
    tell: Sender<Event>,
    heard: Receiver<Event>,
    held: VecDeque<Event>,
    process: Option<Running>,
    tag: u64,
    started: u64,
    background: Option<Background>,
    ceiling: Option<String>,
    until_ms: Option<u64>,
}

impl Driver {
    /// Builds a driver of a service, which starts its process the first time the service asks for
    /// a load. `build` is the daemon's own build identifier, which the process is told.
    #[must_use]
    pub fn new(service: DescriptionService, launch: Launch, build: String) -> Self {
        let (tell, heard) = std::sync::mpsc::channel();
        Self {
            service,
            launch,
            build,
            tell,
            heard,
            held: VecDeque::new(),
            process: None,
            tag: 0,
            started: 0,
            background: None,
            ceiling: None,
            until_ms: None,
        }
    }

    /// Returns the service.
    #[must_use]
    pub const fn service(&self) -> &DescriptionService {
        &self.service
    }

    /// Returns the service, to apply what the host holds: sessions, contexts, pins, privacy.
    pub const fn service_mut(&mut self) -> &mut DescriptionService {
        &mut self.service
    }

    /// Returns a handle that wakes this driver.
    #[must_use]
    pub fn waker(&self) -> Waker {
        Waker(self.tell.clone())
    }

    /// Returns the running process's identifier, when there is one.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|running| running.child.id())
    }

    /// Returns the running process's start identity, as it gave it when it said it was ready.
    #[must_use]
    pub fn identity(&self) -> Option<&ProcessStartIdentity> {
        self.process
            .as_ref()
            .and_then(|running| running.identity.as_ref())
    }

    /// Returns the background class the last process to say it was ready runs its model under.
    #[must_use]
    pub const fn background(&self) -> Option<&Background> {
        self.background.as_ref()
    }

    /// Returns how the last process to say it was ready has its memory ceiling enforced.
    #[must_use]
    pub fn ceiling(&self) -> Option<&str> {
        self.ceiling.as_deref()
    }

    /// Returns whether a check of a file is in the process, by its identifier.
    #[must_use]
    pub fn checking(&self) -> Option<u64> {
        self.process
            .as_ref()
            .and_then(|running| running.check)
            .map(|due| due.id)
    }

    /// Returns the work a cancellation has been sent for and not yet seen answered, and whether
    /// the control thread has said it has read it.
    #[must_use]
    pub fn cancelling(&self) -> Option<(u64, bool)> {
        self.process
            .as_ref()
            .and_then(|running| running.cancel)
            .map(|cancel| (cancel.id, cancel.acknowledged))
    }

    /// Returns how many processes this driver has started.
    #[must_use]
    pub const fn started(&self) -> u64 {
        self.started
    }

    /// Returns when the driver next has something to do on its own, on the continuous clock: a
    /// timer, or the time the service said to look again.
    #[must_use]
    pub fn due_ms(&self) -> Option<u64> {
        let timers = self.process.as_ref().map(|running| {
            let mut soonest = u64::MAX;
            if !running.ready {
                soonest = soonest.min(running.hello_at_ms.saturating_add(HANDSHAKE_MS));
            }
            if let Some(due) = running.work {
                soonest = soonest.min(due.at_ms).min(running.next_sample_ms);
            }
            if let Some(cancel) = running.cancel.filter(|cancel| cancel.timed()) {
                soonest = soonest.min(cancel.at_ms);
            }
            if let Some(due) = running.check {
                soonest = soonest.min(due.at_ms);
            }
            soonest
        });
        match (timers.filter(|at| *at != u64::MAX), self.until_ms) {
            (Some(timer), Some(until)) => Some(timer.min(until)),
            (timer, until) => timer.or(until),
        }
    }

    /// Waits until something arrives or `timeout` passes, and says whether something arrived.
    ///
    /// What arrived is handled by the next [`Self::turn`].
    pub fn wait(&mut self, timeout: Duration) -> bool {
        if !self.held.is_empty() {
            return true;
        }
        match self.heard.recv_timeout(timeout) {
            Ok(event) => {
                self.held.push_back(event);
                true
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => false,
        }
    }

    /// Sends a check of a file to the process, starting the process when there is none.
    ///
    /// A check holds the process's model thread, so one sent behind a load, a job or another check
    /// would wait while its own deadline ran: it is not sent, and is reported as
    /// [`Checked::Refused`]. A job or a load asked for while a check is in the process is the
    /// host's to avoid, as a host that holds nothing without its files does. The result comes back
    /// as [`Report::Checked`] on a later turn. A check the process cannot be started for counts as
    /// a failure of inference, as any start that fails does, since the same executable runs the
    /// model; one the process ends before answering is reported as ended with the process.
    ///
    /// # Errors
    ///
    /// Returns the store failures the service returns when the process's end is told to it.
    pub fn verify(&mut self, check: &Check, now: Reading) -> Result<Vec<Report>> {
        let mut reports = Vec::new();
        if self
            .process
            .as_ref()
            .is_some_and(|running| running.check.is_some() || running.work.is_some())
        {
            reports.push(Report::Checked {
                id: check.id,
                checked: Checked::Refused,
            });
            return Ok(reports);
        }
        if let Err(why) = self.start(now, &mut reports) {
            reports.extend(
                self.service
                    .process_ended(why, now)?
                    .into_iter()
                    .map(Report::Outcome),
            );
            reports.push(Report::Checked {
                id: check.id,
                checked: Checked::ProcessEnded { why },
            });
            return Ok(reports);
        }
        // Recorded before it is sent, so a process that cannot take the request ends with the
        // check reported as ended with it.
        if let Some(running) = self.process.as_mut() {
            running.check = Some(Due {
                id: check.id,
                at_ms: now
                    .monotonic_ms()
                    .saturating_add(check.deadline_ms)
                    .saturating_add(ANSWER_GRACE_MS),
            });
        }
        let request = Request::Verify {
            id: U64::new(check.id),
            profile_id: check.profile_id.clone(),
            revision: U64::new(check.revision),
            file_name: check.file_name.clone(),
            path: check.path.to_string_lossy().into_owned(),
            deadline_ms: U64::new(check.deadline_ms),
        };
        self.send(&request, now, &mut reports)?;
        Ok(reports)
    }

    /// Tells the process to stop the check it is making, if it is making one. The process is
    /// ended when it has not said it has read the cancellation within [`CANCEL_MS`], and when the
    /// check has not stopped within [`CANCEL_MS`] of that.
    ///
    /// Asking again for a check already being stopped changes nothing: the bound runs from the
    /// first ask.
    ///
    /// # Errors
    ///
    /// Returns the store failures the service returns when the process's end is told to it.
    pub fn cancel_check(&mut self, now: Reading) -> Result<Vec<Report>> {
        let mut reports = Vec::new();
        let Some(id) = self.checking() else {
            return Ok(reports);
        };
        if self
            .process
            .as_ref()
            .and_then(|running| running.cancel)
            .is_some_and(|cancel| cancel.id == id)
        {
            return Ok(reports);
        }
        if self.send(&Request::Cancel { id: U64::new(id) }, now, &mut reports)?
            && let Some(running) = self.process.as_mut()
        {
            running.cancel = Some(Cancel {
                id,
                at_ms: now.monotonic_ms().saturating_add(CANCEL_MS),
                kind: Kind::Check,
                acknowledged: false,
            });
        }
        Ok(reports)
    }

    /// Lets go of the process without ending it or closing its input, as a daemon that hangs
    /// does: what a test uses to have a process outlive the driver that started it.
    ///
    /// Nothing reads the process's answers any more, so it goes at its next write, which says the
    /// daemon is gone; a daemon that was killed closes its end of the pipes, which ends the
    /// process at once.
    #[cfg(feature = "testing")]
    pub fn abandon(mut self) {
        if let Some(running) = self.process.take() {
            std::mem::forget(running);
        }
    }

    /// Takes what has arrived, enforces the timers at `now`, and does what the service says until
    /// it says to wait.
    ///
    /// # Errors
    ///
    /// Returns the store failures the service returns.
    pub fn turn(&mut self, conditions: &HostConditions, now: Reading) -> Result<Vec<Report>> {
        let mut reports = Vec::new();
        while let Some(event) = self.held.pop_front().or_else(|| self.heard.try_recv().ok()) {
            self.on_event(event, now, &mut reports)?;
        }
        self.on_timers(now, &mut reports)?;
        loop {
            match self.service.next(conditions, now)? {
                Instruction::Wait { until_ms } => {
                    self.until_ms = until_ms;
                    break;
                }
                Instruction::Load {
                    id,
                    profile,
                    deadline_ms,
                } => {
                    if let Err(why) = self.start(now, &mut reports) {
                        reports.extend(
                            self.service
                                .process_ended(why, now)?
                                .into_iter()
                                .map(Report::Outcome),
                        );
                        continue;
                    }
                    let directory = self
                        .launch
                        .models
                        .join(profile.profile_id())
                        .join(profile.revision().get().to_string());
                    let assets = profile
                        .assets()
                        .iter()
                        .map(|asset| AssetFile {
                            file_name: asset.file_name.clone(),
                            path: directory
                                .join(&asset.file_name)
                                .to_string_lossy()
                                .into_owned(),
                        })
                        .collect();
                    let request = Request::Load {
                        id: U64::new(id),
                        profile_id: profile.profile_id().to_owned(),
                        revision: U64::new(profile.revision().get()),
                        assets,
                        deadline_ms: U64::new(deadline_ms),
                    };
                    if self.send(&request, now, &mut reports)? {
                        self.start_work(id, now, deadline_ms);
                    }
                }
                Instruction::Generate { id, request, .. } => {
                    let deadline_ms = request.deadline_ms;
                    let request = Request::Generate {
                        id: U64::new(id),
                        prompt: request.prompt,
                        grammar: request.grammar.to_owned(),
                        limits: JobLimits {
                            context_tokens: U64::new(u64::from(request.context_tokens)),
                            max_output_tokens: U64::new(u64::from(request.max_output_tokens)),
                            prompt_tokens: U64::new(u64::from(request.prompt_tokens)),
                            cpu_threads: U64::new(u64::from(request.cpu_threads)),
                        },
                        deadline_ms: U64::new(deadline_ms),
                        ceiling_bytes: U64::new(request.ceiling_bytes),
                    };
                    if self.send(&request, now, &mut reports)? {
                        self.start_work(id, now, deadline_ms);
                    }
                }
                Instruction::Cancel { id, work } => {
                    if self.send(&Request::Cancel { id: U64::new(id) }, now, &mut reports)?
                        && let Some(running) = self.process.as_mut()
                    {
                        running.cancel = Some(Cancel {
                            id,
                            at_ms: now.monotonic_ms().saturating_add(CANCEL_MS),
                            kind: match work {
                                Work::Load => Kind::Load,
                                Work::Job => Kind::Job,
                            },
                            acknowledged: false,
                        });
                    }
                }
                Instruction::Unload { why } => {
                    self.leave(&mut reports);
                    reports.push(Report::Unloaded { why });
                }
            }
        }
        // A process that was started only to check a file holds no model, and has nothing to do
        // once the check is done: it goes, and a load that follows starts another.
        if self.process.as_ref().is_some_and(|running| {
            !running.worked
                && running.work.is_none()
                && running.check.is_none()
                && running.cancel.is_none()
        }) {
            self.leave(&mut reports);
            reports.push(Report::Unloaded {
                why: UnloadReason::CheckDone,
            });
        }
        Ok(reports)
    }

    /// Starts the process when there is none, and says hello.
    ///
    /// The process is given this daemon's start identity, read afresh for each start, and none is
    /// started without it: its watchdog is what ends it when the daemon goes and its input does
    /// not tell it. The two threads that carry its frames start next, each waiting to be handed its
    /// end of the pipes, so a thread that cannot start leaves no process behind. From the spawn
    /// on, nothing fails without the process being killed and collected.
    fn start(
        &mut self,
        now: Reading,
        reports: &mut Vec<Report>,
    ) -> std::result::Result<(), ProcessEnd> {
        if self.process.is_some() {
            return Ok(());
        }
        let identity = daemon_identity().map_err(|detail| {
            eprintln!(
                "kr-describe: this daemon's start identity could not be read, so no description \
                 process is started: {detail}"
            );
            ProcessEnd::CouldNotStart
        })?;
        let tag = self.tag.wrapping_add(1);
        let (requests, pending) = std::sync::mpsc::sync_channel::<Vec<u8>>(REQUESTS_HELD);
        let (give_input, take_input) = std::sync::mpsc::sync_channel::<ChildStdin>(1);
        start_thread(WRITER_THREAD, move || {
            let Ok(mut input) = take_input.recv() else {
                return;
            };
            // The input is dropped when the frames stop, which is the end of the process's input
            // and the end of the process.
            for frame in pending {
                if input
                    .write_all(&frame)
                    .and_then(|()| input.flush())
                    .is_err()
                {
                    return;
                }
            }
        })?;
        let (give_output, take_output) = std::sync::mpsc::sync_channel::<ChildStdout>(1);
        let tell = self.tell.clone();
        start_thread(READER_THREAD, move || {
            let Ok(mut output) = take_output.recv() else {
                return;
            };
            loop {
                let event = match read_message::<Answer>(&mut output) {
                    Ok(Some(answer)) => Event::Answer { tag, answer },
                    Ok(None) | Err(WireError::Io(_)) => Event::Closed {
                        tag,
                        why: ProcessEnd::Exited,
                    },
                    Err(WireError::Truncated { .. } | WireError::Frame(_)) => Event::Closed {
                        tag,
                        why: ProcessEnd::BrokenWire,
                    },
                };
                let closed = matches!(event, Event::Closed { .. });
                if tell.send(event).is_err() || closed {
                    return;
                }
            }
        })?;
        let mut child = Command::new(&self.launch.program)
            .args(&self.launch.arguments)
            .arg(DAEMON_IDENTITY_ARGUMENT)
            .arg(&identity)
            .current_dir(&self.launch.working_directory)
            .env_clear()
            .envs(
                self.launch
                    .environment
                    .iter()
                    .map(|(name, value)| (name, value)),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| {
                eprintln!(
                    "kr-describe: {} could not be started: {error}",
                    self.launch.program.display()
                );
                ProcessEnd::CouldNotStart
            })?;
        // The threads end on their own when what they wait for is dropped, which is what happens
        // to both on every return below.
        let handed = match (child.stdin.take(), child.stdout.take()) {
            (Some(input), Some(output)) => {
                give_input.send(input).is_ok() && give_output.send(output).is_ok()
            }
            _ => false,
        };
        if !handed {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessEnd::CouldNotStart);
        }
        self.tag = tag;
        self.started = self.started.saturating_add(1);
        reports.push(Report::Started { pid: child.id() });
        self.process = Some(Running {
            tag,
            child,
            requests: Some(requests),
            ready: false,
            hello_at_ms: now.monotonic_ms(),
            identity: None,
            work: None,
            cancel: None,
            check: None,
            worked: false,
            next_sample_ms: u64::MAX,
        });
        let hello = Request::Hello {
            build: self.build.clone(),
            wire: U64::new(WIRE_VERSION),
        };
        let handed = frame_of(&hello)
            .map_err(|_| ProcessEnd::BrokenWire)
            .and_then(|frame| self.hand_over(frame));
        if let Err(why) = handed {
            self.kill_only();
            return Err(why);
        }
        Ok(())
    }

    /// Hands one frame to the writer, or says why the process is not taking it.
    fn hand_over(&mut self, frame: Vec<u8>) -> std::result::Result<(), ProcessEnd> {
        let Some(requests) = self
            .process
            .as_ref()
            .and_then(|running| running.requests.as_ref())
        else {
            return Err(ProcessEnd::Exited);
        };
        match requests.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ProcessEnd::NotReading),
            Err(TrySendError::Disconnected(_)) => Err(ProcessEnd::Exited),
        }
    }

    /// Sends a request, ending the process when it will not take it. Says whether it was sent.
    fn send(&mut self, request: &Request, now: Reading, reports: &mut Vec<Report>) -> Result<bool> {
        let sent = match frame_of(request) {
            Ok(frame) => self.hand_over(frame),
            Err(_) => Err(ProcessEnd::BrokenWire),
        };
        match sent {
            Ok(()) => Ok(true),
            Err(why) => {
                self.kill(why, now, reports)?;
                Ok(false)
            }
        }
    }

    /// Starts the timers on a load or a job that was just sent.
    fn start_work(&mut self, id: u64, now: Reading, deadline_ms: u64) {
        if let Some(running) = self.process.as_mut() {
            running.work = Some(Due {
                id,
                at_ms: now
                    .monotonic_ms()
                    .saturating_add(deadline_ms)
                    .saturating_add(ANSWER_GRACE_MS),
            });
            running.next_sample_ms = now.monotonic_ms().saturating_add(SAMPLE_MS);
            running.worked = true;
        }
    }

    /// Takes one event from the channel.
    fn on_event(&mut self, event: Event, now: Reading, reports: &mut Vec<Report>) -> Result<()> {
        let current = self.process.as_ref().map(|running| running.tag);
        match event {
            Event::Wake => {}
            Event::Closed { tag, why } => {
                if Some(tag) == current {
                    self.kill(why, now, reports)?;
                }
            }
            Event::Answer {
                tag,
                answer:
                    Answer::Ready {
                        build,
                        wire,
                        identity,
                        background,
                        ceiling,
                        ..
                    },
            } => {
                if Some(tag) != current {
                    return Ok(());
                }
                if wire.get() != WIRE_VERSION || !same_release(&build) {
                    eprintln!(
                        "kr-describe: the description process is {build}, wire {}, and this \
                         daemon speaks only to its own release and wire {WIRE_VERSION}",
                        wire.get()
                    );
                    return self.kill(ProcessEnd::WrongBuild, now, reports);
                }
                if let Some(running) = self.process.as_mut() {
                    running.ready = true;
                    running.identity = identity.0;
                }
                self.background = Some(background);
                self.ceiling = Some(ceiling);
            }
            Event::Answer {
                tag,
                answer: Answer::Cancelling { id },
            } => {
                // The control thread says it has read the cancellation. It is not an answer to the
                // work: the work's timer, the sampler and the service's records are left as they
                // are, and one that names nothing outstanding is not a dropped answer.
                if Some(tag) == current
                    && let Some(running) = self.process.as_mut()
                    && running.ready
                    && let Some(cancel) = running.cancel.as_mut()
                    && cancel.id == id.get()
                {
                    cancel.acknowledged = true;
                }
            }
            Event::Answer {
                tag,
                answer: Answer::Verified { id, result, detail },
            } => {
                if Some(tag) != current {
                    return Ok(());
                }
                let Some(running) = self.process.as_mut() else {
                    return Ok(());
                };
                if !running.ready {
                    return self.kill(ProcessEnd::BrokenWire, now, reports);
                }
                if running.check.is_some_and(|due| due.id == id.get()) {
                    running.check = None;
                    if running.cancel.is_some_and(|cancel| cancel.id == id.get()) {
                        running.cancel = None;
                    }
                    reports.push(Report::Checked {
                        id: id.get(),
                        checked: Checked::Answered {
                            result,
                            detail: detail.0,
                        },
                    });
                }
            }
            Event::Answer { tag, answer } => {
                let Some(id) = answer.id() else {
                    return Ok(());
                };
                if Some(tag) == current {
                    let Some(running) = self.process.as_mut() else {
                        return Ok(());
                    };
                    if !running.ready {
                        // Work answered before the process said what it is: it is not speaking
                        // this wire.
                        return self.kill(ProcessEnd::BrokenWire, now, reports);
                    }
                    if running.work.is_some_and(|due| due.id == id) {
                        running.work = None;
                        running.next_sample_ms = u64::MAX;
                    }
                    if running.cancel.is_some_and(|cancel| cancel.id == id) {
                        running.cancel = None;
                    }
                }
                // An answer from a process that has been ended is still given to the service,
                // which drops it: its work ended with the process.
                let outcome = self.service.finished(id, answered(answer), now)?;
                reports.push(Report::Outcome(outcome));
            }
        }
        Ok(())
    }

    /// Ends a process that broke a bound.
    fn on_timers(&mut self, now: Reading, reports: &mut Vec<Report>) -> Result<()> {
        let Some(running) = self.process.as_mut() else {
            return Ok(());
        };
        let at = now.monotonic_ms();
        let why = if !running.ready && at >= running.hello_at_ms.saturating_add(HANDSHAKE_MS) {
            Some(ProcessEnd::SilentAtStart)
        } else if let Some(cancel) = running
            .cancel
            .filter(|cancel| cancel.timed() && at >= cancel.at_ms)
        {
            Some(if cancel.acknowledged {
                ProcessEnd::StopOverdue
            } else {
                ProcessEnd::CancelUnanswered
            })
        } else if running.work.is_some_and(|due| at >= due.at_ms) {
            Some(ProcessEnd::PastDeadline)
        } else if running.check.is_some_and(|due| at >= due.at_ms) {
            Some(ProcessEnd::CheckOverdue)
        } else if running.work.is_some() && at >= running.next_sample_ms {
            running.next_sample_ms = at.saturating_add(SAMPLE_MS);
            let pid = running.child.id();
            let ceiling = self.service.ceiling_bytes();
            resident_bytes(pid)
                .is_some_and(|rss| rss > ceiling)
                .then_some(ProcessEnd::MemoryCeiling)
        } else {
            None
        };
        match why {
            Some(why) => self.kill(why, now, reports),
            None => Ok(()),
        }
    }

    /// Ends the process at once, collects it, and tells the service how it ended.
    fn kill(&mut self, why: ProcessEnd, now: Reading, reports: &mut Vec<Report>) -> Result<()> {
        let Some(running) = self.process.as_ref() else {
            return Ok(());
        };
        let checking = running.check.map(|due| due.id);
        self.kill_only();
        if let Some(id) = checking {
            reports.push(Report::Checked {
                id,
                checked: Checked::ProcessEnded { why },
            });
        }
        reports.extend(
            self.service
                .process_ended(why, now)?
                .into_iter()
                .map(Report::Outcome),
        );
        Ok(())
    }

    /// Ends the process at once and collects it.
    fn kill_only(&mut self) {
        if let Some(mut running) = self.process.take() {
            running.requests = None;
            let _ = running.child.kill();
            let _ = running.child.wait();
        }
    }

    /// Ends the process on the service's word: closes its input, which it leaves on, and ends it
    /// outright when it has not left in time.
    fn leave(&mut self, reports: &mut Vec<Report>) {
        let Some(mut running) = self.process.take() else {
            return;
        };
        if let Some(due) = running.check {
            reports.push(Report::Checked {
                id: due.id,
                checked: Checked::Unloaded,
            });
        }
        running.requests = None;
        let until = Instant::now() + LEAVE_WAIT;
        loop {
            match running.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = running.child.kill();
        let _ = running.child.wait();
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.kill_only();
    }
}

/// Turns a process's terminal answer into what the service takes.
fn answered(answer: Answer) -> Answered {
    match answer {
        Answer::Loaded {
            load_ms, rss_bytes, ..
        } => Answered::Loaded {
            load_ms: load_ms.get(),
            rss_bytes: rss_bytes.get(),
        },
        Answer::LoadEnded { why, detail, .. } => Answered::LoadEnded {
            why,
            detail: detail.0,
        },
        Answer::Produced {
            bytes,
            phases,
            peak_rss_bytes,
            ..
        } => Answered::Produced {
            bytes: bytes.into_vec(),
            phases,
            peak_rss_bytes: peak_rss_bytes.get(),
        },
        Answer::Ended { why, detail, .. } => Answered::Ended {
            why,
            detail: detail.0,
        },
        // `ready`, a check's result and a cancellation's acknowledgement carry no job or load and
        // are handled before this is reached.
        Answer::Ready { .. } | Answer::Verified { .. } | Answer::Cancelling { .. } => {
            Answered::Ended {
                why: crate::wire::JobEnd::Failed,
                detail: Some("this is not an answer to a job or a load".to_owned()),
            }
        }
    }
}

/// Returns a process's resident set, when the platform will say.
fn resident_bytes(pid: u32) -> Option<u64> {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(sysinfo::Process::memory)
}

/// Starts one of the two threads that carry a process's frames.
fn start_thread(
    name: &'static str,
    work: impl FnOnce() + Send + 'static,
) -> std::result::Result<(), ProcessEnd> {
    #[cfg(feature = "testing")]
    if crate::testing::thread_start_refused(name) {
        eprintln!("kr-describe: the {name} thread was not started, as a test asked");
        return Err(ProcessEnd::CouldNotStart);
    }
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(work)
        .map(drop)
        .map_err(|error| {
            eprintln!("kr-describe: the {name} thread could not be started: {error}");
            ProcessEnd::CouldNotStart
        })
}

/// Returns this daemon's start identity as JSON, for the description process it starts.
fn daemon_identity() -> std::result::Result<String, String> {
    #[cfg(feature = "testing")]
    if crate::testing::identity_lookup_refused() {
        return Err("the query was refused, as a test asked".to_owned());
    }
    let identity =
        kr_ipc::identity::current_process_start_identity().map_err(|error| error.to_string())?;
    serde_json::to_string(&identity).map_err(|error| error.to_string())
}
