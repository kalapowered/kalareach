//! `kr host stop`: asks this installation's control daemon to stop, waits for it to end, and says
//! what that left.
//!
//! The model is the specification's: local peer credentials prove an OS identity, and code that
//! runs as this account can end the daemon with the platform's own tools. The request is served on
//! the account's own local socket and asks for the right to manage the host; this command is the
//! way a person asks, and a guard against an accident, not a boundary: it refuses where the
//! session variables are set or a session's worker places the process inside its session.
//!
//! What the command knows is kept apart in its result, because a request that left may have been
//! taken and a command that was killed may have stopped the daemon: `ended` (the daemon was seen
//! to end), `told` (the daemon took the stop and was not seen to end), `maybe_asked` (the request
//! may have left, and neither its answer nor the daemon's end was seen), `refused` (the request left and the
//! daemon refused it) and `not_asked` (no request left). An answer that is
//! missing or cut is an unknown outcome and never "not stopped": the command looks at the lock and
//! the process.
//!
//! Before it asks, the command writes a record of its attempt ([`kr_controller::attempt`]), and
//! every message that no control daemon runs reads the records.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::attempt::{self, Marker, Standing};
use kr_controller::singleton::SingletonLock;
use kr_ipc::client::{Listed, LocalClient};
use kr_ipc::error::ErrorSource;
use kr_ipc::identity::{self, ProcessReading, ProcessState};
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::backup_setup::BackupStatusParams;
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome};
use kr_protocol::error::{ErrorCode, ProtocolError, RetryCategory};
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ActionId, ControllerGeneration, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::update::{HostStopParams, HostStopResult, STOP_SETTLE_MS};

use crate::error::{CliError, Result};
use crate::output::{self, Document};
use crate::report::{self, Completion};
use crate::resolve::KnownEnvironment;
use crate::startup::{self, Reached};
use crate::update::handover;

/// How long the answer to the request is waited for: the daemon settles the creates under way for
/// [`STOP_SETTLE_MS`] before it answers, and its answer is written within a few seconds.
pub(crate) const ANSWER_BOUND: Duration = Duration::from_millis(STOP_SETTLE_MS + 5_000);

/// How long the end of the daemon is waited for once it was told to stop.
pub(crate) const END_BOUND: Duration = handover::DAEMON_STOP;

/// How often the end of the daemon is looked for.
pub(crate) const LOOK_EVERY: Duration = Duration::from_millis(50);

/// What a refusal says of the sessions meanwhile, for a command that stops the daemon.
const SESSIONS_GO_ON: &str = "Sessions and local attachments go on while no daemon runs.";

/// What a refusal says of the sessions meanwhile, for a command that stops the daemon and starts
/// one.
const SESSIONS_GO_ON_THROUGH: &str = "Sessions and local attachments go on through a restart.";

/// The command that runs: what a text says of it, of what it did not request and of the sessions
/// meanwhile, and the command that an attempt's record names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Which {
    /// `kr host stop`.
    Stop,
    /// `kr host restart`.
    Restart,
}

impl Which {
    /// The command as a person types it.
    pub(crate) const fn command(self) -> &'static str {
        match self {
            Self::Stop => "kr host stop",
            Self::Restart => "kr host restart",
        }
    }

    /// The command as the record of an attempt names it.
    pub(crate) const fn attempt(self) -> attempt::Command {
        match self {
            Self::Stop => attempt::Command::Stop,
            Self::Restart => attempt::Command::Restart,
        }
    }

    /// What a refusal of the guard says of the sessions meanwhile.
    const fn sessions(self) -> &'static str {
        match self {
            Self::Stop => SESSIONS_GO_ON,
            Self::Restart => SESSIONS_GO_ON_THROUGH,
        }
    }

    /// What a text says where the command ended before it asked the daemon for anything.
    pub(crate) const fn nothing_asked(self) -> &'static str {
        match self {
            Self::Stop => "No stop was requested.",
            Self::Restart => "No stop was requested and no start was made.",
        }
    }

    /// What a text that ends a restart without a start says last.
    const fn no_start(self) -> &'static str {
        match self {
            Self::Stop => "",
            Self::Restart => " This command requested no start.",
        }
    }
}

/// What this command knows of whether the daemon was asked, for `--json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Knows {
    /// The daemon was seen to end.
    Ended,
    /// The daemon took the stop, and was not seen to end.
    Told,
    /// The request may have left (its write failed where a part of it may have gone, or no answer
    /// came), and neither its answer nor the daemon's end was seen.
    MaybeAsked,
    /// The request left and the daemon refused it: nothing was stopped.
    Refused,
    /// Nothing was asked: no request left.
    NotAsked,
}

impl Knows {
    const fn word(self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::Told => "told",
            Self::MaybeAsked => "maybe_asked",
            Self::Refused => "refused",
            Self::NotAsked => "not_asked",
        }
    }
}

/// Where the command has come to, which says what an interrupt may say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// The request has not been written.
    BeforeAsking = 0,
    /// The request has been written or is being written; the answer or the end is not seen.
    Asked = 1,
    /// The daemon took the stop; its end is not yet seen.
    Told = 2,
    /// The daemon refused the request, and nothing was stopped.
    Refused = 3,
}

/// What the command's interrupt handling and its work share.
pub(crate) struct Progress {
    stage: AtomicU8,
    /// The command's own record, from the moment it is written.
    pub(crate) marker: Mutex<Option<Marker>>,
    pub(crate) environment_id: EnvironmentId,
    /// What the command said at its start of the attempts earlier commands recorded.
    earlier: Mutex<Vec<Shown>>,
}

impl Progress {
    /// The progress of a command at its first stage, with nothing recorded.
    pub(crate) fn new(environment_id: EnvironmentId) -> Self {
        Self {
            stage: AtomicU8::new(Stage::BeforeAsking as u8),
            marker: Mutex::new(None),
            environment_id,
            earlier: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn enter(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::SeqCst);
    }

    pub(crate) fn stage(&self) -> Stage {
        match self.stage.load(Ordering::SeqCst) {
            0 => Stage::BeforeAsking,
            1 => Stage::Asked,
            2 => Stage::Told,
            _ => Stage::Refused,
        }
    }

    pub(crate) fn with_marker<T>(&self, then: impl FnOnce(&mut Marker) -> T) -> Option<T> {
        let mut held = self
            .marker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.as_mut().map(then)
    }

    pub(crate) fn said_earlier(&self) -> Vec<Shown> {
        self.earlier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn remove_marker(&self) {
        let taken = self
            .marker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(marker) = taken {
            marker.remove();
        }
    }
}

/// An interrupt of the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interrupt {
    /// The terminal went away.
    Hangup,
    /// Interrupt, terminate or quit.
    Other,
}

/// The signals that interrupt the command, caught from the command's first line.
struct Interrupts {
    #[cfg(unix)]
    hangup: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    quit: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
    #[cfg(windows)]
    ctrl_break: Option<tokio::signal::windows::CtrlBreak>,
}

impl Interrupts {
    /// Starts catching them. One that cannot be caught keeps its default action.
    fn catch() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            Self {
                hangup: signal(SignalKind::hangup()).ok(),
                interrupt: signal(SignalKind::interrupt()).ok(),
                terminate: signal(SignalKind::terminate()).ok(),
                quit: signal(SignalKind::quit()).ok(),
            }
        }
        #[cfg(windows)]
        {
            Self {
                ctrl_c: tokio::signal::windows::ctrl_c().ok(),
                ctrl_break: tokio::signal::windows::ctrl_break().ok(),
            }
        }
    }

    /// Waits for the next interrupt.
    async fn next(&mut self) -> Interrupt {
        #[cfg(unix)]
        {
            async fn one(signal: &mut Option<tokio::signal::unix::Signal>) {
                match signal {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                () = one(&mut self.hangup) => Interrupt::Hangup,
                () = one(&mut self.interrupt) => Interrupt::Other,
                () = one(&mut self.terminate) => Interrupt::Other,
                () = one(&mut self.quit) => Interrupt::Other,
            }
        }
        #[cfg(windows)]
        {
            async fn c(signal: &mut Option<tokio::signal::windows::CtrlC>) {
                match signal {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            async fn b(signal: &mut Option<tokio::signal::windows::CtrlBreak>) {
                match signal {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                () = c(&mut self.ctrl_c) => Interrupt::Other,
                () = b(&mut self.ctrl_break) => Interrupt::Other,
            }
        }
    }
}

/// Runs `kr host stop`.
///
/// The handlers stand from the first line: an interrupt before the request is written ends the
/// command with nothing asked and its record removed; after it, a hangup is ignored, and any other
/// interrupt says what may be so and exits, and never cancels a stop that was asked.
///
/// # Errors
///
/// Returns the failures that are not the command's own result: this installation's environment
/// cannot be found.
pub async fn run(paths: &HostPaths, json: bool) -> Result<Completion> {
    run_with(
        paths,
        json,
        async |environment, progress| stop(Which::Stop, paths, environment, json, progress).await,
        interrupted,
        hangup_ignored_by_a_stop,
    )
    .await
}

/// Whether a stop ignores a hangup at `stage`: once the request has left, the report may print into
/// a closed terminal, which the record covers.
const fn hangup_ignored_by_a_stop(stage: Stage) -> bool {
    !matches!(stage, Stage::BeforeAsking)
}

/// Runs a command with the handlers from its first line. `interrupted` says what an interrupt at a
/// stage came to, and `hangup_ignored` says at which stages a hangup is ignored: the report may
/// print into a closed terminal, which the record covers.
///
/// # Errors
///
/// Returns the failures that are not the command's own result: this installation's environment
/// cannot be found.
pub(crate) async fn run_with(
    paths: &HostPaths,
    json: bool,
    work: impl AsyncFnOnce(&KnownEnvironment, &Progress) -> Result<Completion>,
    interrupted: impl FnOnce(&Progress, Stage, bool) -> Completion,
    hangup_ignored: impl Fn(Stage) -> bool,
) -> Result<Completion> {
    let mut interrupts = Interrupts::catch();
    let environment = installation(paths)?;
    let progress = Progress::new(environment.environment_id);
    let work = work(&environment, &progress);
    tokio::pin!(work);
    loop {
        tokio::select! {
            done = &mut work => return done,
            interrupt = interrupts.next() => {
                let stage = progress.stage();
                if interrupt == Interrupt::Hangup && hangup_ignored(stage) {
                    continue;
                }
                return Ok(interrupted(&progress, stage, json));
            }
        }
    }
}

/// This installation's own environment, whether or not a daemon has ever run there.
fn installation(paths: &HostPaths) -> Result<KnownEnvironment> {
    let environment_id = paths.open_environment_id()?;
    Ok(KnownEnvironment {
        environment_id,
        paths: paths.environment(environment_id),
    })
}

/// What an interrupt says in each stage.
fn interrupted(progress: &Progress, stage: Stage, json: bool) -> Completion {
    let id = progress.environment_id;
    let (knows, said) = match stage {
        Stage::BeforeAsking => {
            progress.remove_marker();
            (
                Knows::NotAsked,
                shown!(
                    "kr host stop was interrupted before it asked the control daemon for \
                     environment {} to stop. Nothing was stopped.",
                    id
                ),
            )
        }
        Stage::Asked => (
            Knows::MaybeAsked,
            shown!(
                "kr host stop was interrupted while it asked the control daemon for environment {} \
                 to stop. The daemon may have taken the request and may still stop; an interrupt \
                 does not cancel a stop. No session stops. Run kr host stop to see.",
                id
            ),
        ),
        Stage::Refused => {
            progress.remove_marker();
            (
                Knows::Refused,
                shown!(
                    "kr host stop was interrupted after the control daemon for environment {} \
                     refused the request. Nothing was stopped.",
                    id
                ),
            )
        }
        Stage::Told => (
            Knows::Told,
            shown!(
                "The control daemon for environment {} was told to stop and may still be ending. \
                 kr host stop was interrupted before it saw the end. No session stops. Run kr host \
                 stop again to see.",
                id
            ),
        ),
    };
    failed(
        CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: said,
        },
        &Facts {
            knows,
            ..Facts::none(progress.said_earlier())
        },
        json,
    )
}

/// The daemon a restart started, for `--json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StartedFact {
    /// The start: `standalone`, `launchd`, `systemd` or `task`.
    pub(crate) start: &'static str,
    /// Its process, where the start knows it.
    pub(crate) pid: Option<u32>,
}

/// What a restart's result says in `--json` of the daemon that answers and of what this command
/// launched: absent for a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The process the daemon that answers states, where it states one.
    pub(crate) serving: Option<u64>,
    /// What this command launched, where it launched something, whether or not the daemon that
    /// answers is the one it made.
    pub(crate) launched: Option<StartedFact>,
}

/// The facts a result carries in `--json`.
#[derive(Clone)]
pub(crate) struct Facts {
    pub(crate) knows: Knows,
    pub(crate) pid: Option<u64>,
    pub(crate) unsettled: Option<u64>,
    /// What earlier attempts recorded, which this command said at its start.
    pub(crate) records: Vec<Shown>,
    /// The daemon that answers a restart and what the restart launched: absent for a stop.
    pub(crate) answer: Option<Answer>,
}

impl Facts {
    /// Nothing asked, and nothing known of a process.
    pub(crate) fn none(records: Vec<Shown>) -> Self {
        Self {
            knows: Knows::NotAsked,
            pid: None,
            unsettled: None,
            records,
            answer: None,
        }
    }

    fn document(&self) -> Document {
        let mut document = Document::new()
            .with("stop", self.knows.word())
            .with("pid", self.pid)
            .with("unsettled", self.unsettled);
        if let Some(answer) = self.answer {
            document.set("serving", answer.serving);
            document.set(
                "launched",
                answer.launched.map(|launched| {
                    Document::new()
                        .with("start", launched.start)
                        .with("pid", launched.pid)
                }),
            );
        }
        if self.records.is_empty() {
            document
        } else {
            document.with("records", self.records.clone())
        }
    }
}

/// Reports a result that is a failure, in the form the caller asked for, and ends the command.
pub(crate) fn failed(error: CliError, result: &Facts, json: bool) -> Completion {
    if json {
        output::document(&report::with_failure(result.document(), &error));
    } else {
        report::failed(&error);
    }
    Completion::Reported(error)
}

/// Reports a result that is a success, and then removes the records of earlier attempts that the
/// report has put out. This is the one place that removes them: a result that is not this command's
/// own, seen and written, removes nothing.
pub(crate) fn done(said: &Shown, result: &Facts, json: bool, earlier: &Earlier) -> Completion {
    if json {
        output::document(&result.document().with("ok", true));
    } else {
        output::say(said);
    }
    earlier.remove_those_put_out(json);
    Completion::Done
}

/// What a stop's request came to, where it was written.
#[derive(Clone, Debug)]
pub(crate) enum Request {
    /// The daemon took the stop and answered.
    Told,
    /// The outcome is not known; the failure says why (its words).
    MaybeAsked(Shown),
}

impl Request {
    /// What the command knows of the request, for `--json`.
    const fn knows(&self) -> Knows {
        match self {
            Self::Told => Knows::Told,
            Self::MaybeAsked(_) => Knows::MaybeAsked,
        }
    }

    /// What the request's failure said where whether the daemon took the stop is not known.
    pub(crate) const fn not_known(&self) -> Option<&Shown> {
        match self {
            Self::Told => None,
            Self::MaybeAsked(failure) => Some(failure),
        }
    }
}

/// How a result ends the command: its exit code, and so the failure that reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    /// Exit 0: the result is a success.
    Done,
    /// Exit 1: the command could not show that the environment is as it should be, and says what it
    /// knows (the host is unavailable for now; a person runs the command again).
    Unfinished,
    /// Exit 1: a failure of the command's own, said in its words.
    Failed,
    /// Exit 3: the request could not be made, and the failure keeps its own words.
    Unavailable,
}

impl Exit {
    /// The failure that ends the command with this exit, with `message` as its words; none for a
    /// success.
    fn failure(self, message: Shown) -> Option<CliError> {
        match self {
            Self::Done => None,
            Self::Unfinished => Some(CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message,
            }),
            Self::Failed => Some(CliError::Other(message)),
            Self::Unavailable => Some(CliError::HostUnavailable(message)),
        }
    }
}

/// What the command ends with in one place: the kind of sentence, the exit, and the `stop` member
/// that `--json` carries. Each place has its own kinds, decided by one pure function of the
/// readings that reach it.
#[derive(Clone, Debug)]
pub(crate) struct Said<Sentence> {
    pub(crate) sentence: Sentence,
    pub(crate) exit: Exit,
    pub(crate) stop: Knows,
}

impl<Sentence> Said<Sentence> {
    const fn new(sentence: Sentence, exit: Exit, stop: Knows) -> Self {
        Self {
            sentence,
            exit,
            stop,
        }
    }
}

/// Reports `message` with `exit`: a success where the exit is 0, and otherwise the failure that has
/// that exit.
pub(crate) fn conclude(
    exit: Exit,
    message: Shown,
    result: &Facts,
    json: bool,
    earlier: &Earlier,
) -> Completion {
    match exit.failure(message.clone()) {
        None => done(&message, result, json, earlier),
        Some(error) => failed(error, result, json),
    }
}

/// The kinds of sentence after a request that was written. A told stop and one whose outcome was
/// not shown differ in the words ([`Request`]), not in the kind.
#[derive(Clone, Debug)]
enum AfterRequest {
    /// The daemon ended and the environment is free: "Stopped ..." for a told stop, and what the
    /// command knows for the other.
    Stopped,
    /// The daemon ended and another holds the environment (the process the lock file names, where
    /// it names one).
    Successor(Option<u64>),
    /// The daemon has not ended: its process runs, or the daemon of the generation asked answers.
    NotEnded,
    /// The lock was free and the last look showed neither that the daemon runs nor that it had gone.
    NotShown,
    /// The process has gone and something that is not shown to be a daemon holds the environment.
    StillHeld,
    /// The environment is held, and nothing shows whether the daemon that was told or another holds it.
    HeldNotShown,
    /// The lock could not be read: why.
    Unlooked(Shown),
}

/// What the command ends with where the end is decided after a request that was written: `end` is
/// what the last round showed. The exit is 0 only where the end is shown, and the `stop` member
/// says `ended` only there.
fn said_after_the_request(end: End, request: &Request) -> Said<AfterRequest> {
    let asked = request.knows();
    match end {
        End::Gone => Said::new(AfterRequest::Stopped, Exit::Done, Knows::Ended),
        End::Successor(successor) => {
            Said::new(AfterRequest::Successor(successor), Exit::Done, Knows::Ended)
        }
        End::NotEnded(why, _answered) => match why {
            Why::Running | Why::Answers => {
                Said::new(AfterRequest::NotEnded, Exit::Unfinished, asked)
            }
            Why::NotShown => Said::new(AfterRequest::NotShown, Exit::Unfinished, asked),
            Why::Held => Said::new(AfterRequest::StillHeld, Exit::Unfinished, asked),
            Why::HeldNotShown => Said::new(AfterRequest::HeldNotShown, Exit::Unfinished, asked),
            Why::Unlooked(why) => Said::new(AfterRequest::Unlooked(why), Exit::Unfinished, asked),
        },
    }
}

/// The kinds of sentence where the request could not be made.
#[derive(Clone, Debug)]
enum BeforeRequest {
    /// The daemon had ended (or another holds the environment now): the words are made already.
    Ended { words: Shown, pid: Option<u64> },
    /// A daemon holds the environment and does not answer.
    HoldsAndSilent,
    /// A connection was accepted and nothing answered within the bound.
    Silent,
    /// The failure keeps its own words: what makes that true.
    Unmade(Unmade),
}

/// What the command ends with where the request could not be made: `lock_again` is the lock read
/// once more, which only a failure with no end shown within the bound asks for.
fn said_before_the_request(
    before: Before,
    lock_again: impl FnOnce() -> Lock,
) -> Said<BeforeRequest> {
    match before {
        Before::Ended { said, pid, .. } => Said::new(
            BeforeRequest::Ended { words: said, pid },
            Exit::Done,
            Knows::Ended,
        ),
        Before::Silent { accepted } => match lock_again() {
            Lock::Held => Said::new(
                BeforeRequest::HoldsAndSilent,
                Exit::Unfinished,
                Knows::NotAsked,
            ),
            Lock::Free | Lock::Unreadable(_) => {
                if accepted {
                    Said::new(BeforeRequest::Silent, Exit::Unfinished, Knows::NotAsked)
                } else {
                    Said::new(
                        BeforeRequest::Unmade(Unmade::NothingListening),
                        Exit::Unavailable,
                        Knows::NotAsked,
                    )
                }
            }
        },
        Before::Answers(answered) => Said::new(
            BeforeRequest::Unmade(Unmade::Answered(answered)),
            Exit::Unavailable,
            Knows::NotAsked,
        ),
        Before::OwnFault => Said::new(
            BeforeRequest::Unmade(Unmade::OwnFault),
            Exit::Unavailable,
            Knows::NotAsked,
        ),
    }
}

/// What the first reach of the endpoint showed, where it ends the command with no wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Start {
    /// A daemon answers and states another public major than this command.
    OtherMajor,
    /// Something accepted the connection and did not answer.
    Silent,
    /// Nothing listens at the endpoint.
    NothingListening,
}

/// The kinds of sentence at the start.
#[derive(Clone, Debug)]
pub(crate) enum AtStart {
    OtherMajor,
    /// Nothing listens and the lock is free: no daemon runs.
    NoDaemon,
    /// A daemon holds the environment and does not answer.
    HoldsAndSilent,
    Silent,
    /// The lock could not be read: why.
    LockUnreadable(Shown),
}

/// What the command ends with at its start: `lock` is the environment's lock, read only where the
/// decision needs it.
fn said_at_the_start(start: &Start, lock: impl FnOnce() -> Lock) -> Said<AtStart> {
    match start {
        Start::OtherMajor => Said::new(AtStart::OtherMajor, Exit::Failed, Knows::NotAsked),
        Start::Silent => match lock() {
            Lock::Held => Said::new(AtStart::HoldsAndSilent, Exit::Unfinished, Knows::NotAsked),
            Lock::Free | Lock::Unreadable(_) => {
                Said::new(AtStart::Silent, Exit::Unfinished, Knows::NotAsked)
            }
        },
        Start::NothingListening => match lock() {
            Lock::Free => Said::new(AtStart::NoDaemon, Exit::Done, Knows::NotAsked),
            Lock::Held => Said::new(AtStart::HoldsAndSilent, Exit::Unfinished, Knows::NotAsked),
            Lock::Unreadable(why) => {
                Said::new(AtStart::LockUnreadable(why), Exit::Failed, Knows::NotAsked)
            }
        },
    }
}

/// What the command has read before it reaches the daemon: the result so far, and the records of
/// earlier attempts.
pub(crate) struct Begun {
    pub(crate) none: Facts,
    pub(crate) earlier: Earlier,
}

/// The command's start, up to the first reach of the endpoint: the guard, and what earlier attempts
/// recorded and whose process has gone, said at the start (in the document under `--json`) and
/// removed only by `done`, after the result that put it out has been written. A refused guard is
/// the completion that the command ends with.
pub(crate) async fn begin(
    which: Which,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> std::result::Result<Begun, Completion> {
    let id = environment.environment_id;
    let none = Facts::none(Vec::new());
    if let Err(error) = crate::bind::require_outside_to_end_a_daemon(
        &crate::build_id(),
        which.command(),
        which.sessions(),
    )
    .await
    {
        return Err(failed(error, &none, json));
    }
    let mut earlier = Earlier::read(&environment.paths);
    let none = Facts::none(earlier.said(id));
    *progress
        .earlier
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = none.records.clone();
    if !json {
        earlier.say(id);
    }
    Ok(Begun { none, earlier })
}

/// What the first reach of the endpoint found.
pub(crate) enum Looked {
    /// A daemon of this build's public major answered the hello. `holder` is the process that
    /// held the environment before the reach, read once there.
    Daemon {
        client: Box<LocalClient>,
        holder: Option<ProcessStartIdentity>,
    },
    /// The reach ends the command with no wait.
    Said(Start),
    /// The greeting failed for a reason other than nothing listening: what that failure came to.
    Refused {
        before: Before,
        error: kr_ipc::IpcError,
    },
}

/// The first reach of the daemon's endpoint. A failure to find the endpoint is the command's own
/// error.
pub(crate) async fn look(host: &HostPaths, environment: &KnownEnvironment) -> Result<Looked> {
    let id = environment.environment_id;
    let endpoint = environment.paths.controller_endpoint()?;
    // The process that holds the environment before the reach, which is the one that the reach is
    // made to: read after a failed greeting, the lock file may already name a successor, which is
    // not the daemon that was asked.
    let holder = lock_holder(&environment.paths);
    Ok(
        match startup::reach(&endpoint, startup::ANSWER_BOUND, &[]).await {
            Reached::Answered(listed) => match *listed {
                Listed::Ours(client) => Looked::Daemon { client, holder },
                _ => Looked::Said(Start::OtherMajor),
            },
            Reached::Silent => Looked::Said(Start::Silent),
            Reached::Refused(error) if startup::nothing_listening(&error) => {
                Looked::Said(Start::NothingListening)
            }
            Reached::Refused(error) => {
                let operations = Real::of(host, &environment.paths, None);
                let before = greeting_failed(
                    &operations,
                    &error,
                    holder.as_ref(),
                    id,
                    tokio::time::Instant::now() + END_BOUND,
                )
                .await;
                Looked::Refused { before, error }
            }
        },
    )
}

/// The command, from the guard to the daemon's end.
async fn stop(
    which: Which,
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> Result<Completion> {
    let id = environment.environment_id;
    let Begun { none, earlier } = match begin(which, environment, json, progress).await {
        Ok(begun) => begun,
        Err(completion) => return Ok(completion),
    };
    Ok(match look(host, environment).await? {
        Looked::Daemon { client, holder } => {
            stop_the_daemon(
                which,
                host,
                environment,
                *client,
                holder,
                json,
                progress,
                &earlier,
            )
            .await
        }
        Looked::Said(start) => at_the_start(
            which,
            &start,
            environment,
            &none,
            json,
            &earlier,
            startup::ANSWER_BOUND,
        ),
        Looked::Refused { before, error } => {
            match ended_by(which, before, environment, &none, json, &earlier) {
                Ok(completion) => completion,
                Err(cause) => failed(unreached(which, id, &error, cause), &none, json),
            }
        }
    })
}

/// What earlier attempts recorded whose process is no longer the one that recorded it.
pub(crate) struct Earlier {
    records: Vec<attempt::Recorded>,
    /// Whether the lines that say them were written on standard error at the start, which is where
    /// they go without `--json`.
    written: bool,
}

impl Earlier {
    fn read(environment: &EnvironmentPaths) -> Self {
        Self {
            records: attempt::recorded(environment)
                .into_iter()
                .filter(|recorded| recorded.standing() != Standing::UnderWay)
                .collect(),
            written: false,
        }
    }

    /// Says each record on standard error, and keeps whether every line was written. A line that
    /// standard error refused ends the saying: it refuses every later line too.
    fn say(&mut self, id: EnvironmentId) {
        self.written = self
            .records
            .iter()
            .all(|recorded| report::shown_before_going_on(&record_said(recorded, id)));
    }

    fn said(&self, id: EnvironmentId) -> Vec<Shown> {
        self.records
            .iter()
            .map(|recorded| record_said(recorded, id))
            .collect()
    }

    /// Removes what was put out, now that this command's own result has been written. Under
    /// `--json` the records are in that document; otherwise they were said at the start. A record
    /// that was not put out stays for the next command to say.
    fn remove_those_put_out(&self, json: bool) {
        // The result is the document or the result line on standard output, and under text the
        // lines at the start went to standard error as well: none of them may have been refused.
        let put_out = output::unwritten_output().is_none() && (json || self.written);
        if !put_out {
            return;
        }
        for recorded in &self.records {
            if recorded.standing() == Standing::Gone {
                recorded.remove();
            }
        }
    }
}

/// What a recorded attempt says, where no control daemon runs: that it is under way while its
/// process lives, and otherwise the last phase it recorded and when, as a record and not as a
/// claim of what happened after it.
fn record_said(recorded: &attempt::Recorded, id: EnvironmentId) -> Shown {
    let at = crate::shown::utc_moment(recorded.attempt.at_ms);
    let process = recorded.attempt.process.pid.get();
    let command = match recorded.attempt.command {
        attempt::Command::Stop => "kr host stop",
        attempt::Command::Restart => "kr host restart",
    };
    if recorded.standing() == Standing::UnderWay {
        return shown!(
            "A {} is under way for environment {} (process {}, last recorded at {}); wait for it.",
            command,
            id,
            process,
            at
        );
    }
    match recorded.attempt.phase {
        attempt::Phase::Asking => shown!(
            "The last record of a {} (process {}) is at {}: it was asking the control daemon for \
             environment {} to stop. What happened after that is not recorded.",
            command,
            process,
            at,
            id
        ),
        attempt::Phase::Told => shown!(
            "The last record of a {} (process {}) is at {}: the control daemon for environment {} \
             had been told to stop. What happened after that is not recorded.",
            command,
            process,
            at,
            id
        ),
        attempt::Phase::Starting => shown!(
            "The last record of a {} (process {}) is at {}: it was asking for a new control daemon \
             for environment {}. What happened after that is not recorded.",
            command,
            process,
            at,
            id
        ),
        attempt::Phase::StartFailed => shown!(
            "The last record of a {} (process {}) is at {}: its start of a control daemon for \
             environment {} had failed. Run kr host restart to try again.",
            command,
            process,
            at,
            id
        ),
    }
}

/// What every message that no control daemon runs says of the attempts recorded for an
/// environment: nothing where there is none, and otherwise a space and each record's words. A
/// command's record is its own whatever phase it last wrote, and the failure of its start does not
/// say it: a record is its own where the process that wrote it is this process. It removes nothing.
#[must_use]
pub fn records_said(environment: &EnvironmentPaths) -> Shown {
    let id = environment.environment_id();
    let own = identity::current_process_start_identity();
    let said: Vec<Shown> = attempt::recorded(environment)
        .iter()
        .filter(|recorded| {
            !own.as_ref()
                .is_ok_and(|own| *own == recorded.attempt.process)
        })
        .map(|recorded| record_said(recorded, id))
        .collect();
    if said.is_empty() {
        Shown::said("")
    } else {
        shown!(" {}", Shown::joined(said, " "))
    }
}

/// The words where nothing listens at the endpoint and the lock is free: no daemon runs. The
/// records of earlier attempts that are still under way follow.
fn no_daemon_said(environment: &KnownEnvironment) -> Shown {
    shown!(
        "No control daemon runs for environment {}. Nothing was stopped.{}",
        environment.environment_id,
        under_way_said(environment)
    )
}

/// What a message that no daemon runs adds where an attempt is under way: a space and each such
/// record's words, and nothing where there is none.
pub(crate) fn under_way_said(environment: &KnownEnvironment) -> Shown {
    let id = environment.environment_id;
    let under_way: Vec<Shown> = attempt::recorded(&environment.paths)
        .iter()
        .filter(|recorded| recorded.standing() == Standing::UnderWay)
        .map(|recorded| record_said(recorded, id))
        .collect();
    if under_way.is_empty() {
        Shown::said("")
    } else {
        shown!(" {}", Shown::joined(under_way, " "))
    }
}

/// The words where something accepted the connection and did not answer within `bound`.
fn silent_said(which: Which, id: EnvironmentId, bound: Duration) -> Shown {
    shown!(
        "the control daemon listening for environment {} accepted the connection and did not answer \
         within {} seconds. {} Run {} again in a moment.",
        id,
        bound.as_secs(),
        which.nothing_asked(),
        which.command()
    )
}

/// The words where a daemon holds the environment and does not answer, so it may be starting or
/// stopping.
fn holds_and_is_silent_said(which: Which, environment: &KnownEnvironment) -> Shown {
    shown!(
        "A control daemon holds environment {} and does not answer, so it may be starting or \
         stopping. {} Run {} again in a moment. {}",
        environment.environment_id,
        which.nothing_asked(),
        which.command(),
        how_to_end_the_holder(&environment.paths)
    )
}

/// The words where the environment's lock could not be read at the start.
fn lock_unreadable_said(which: Which, id: EnvironmentId, why: &Shown) -> Shown {
    shown!(
        "whether a control daemon holds environment {} could not be read: {}. {}",
        id,
        *why,
        which.nothing_asked()
    )
}

/// The words where the daemon at the endpoint states another public major than this command.
fn other_major_said(which: Which, id: EnvironmentId) -> Shown {
    shown!(
        "the control daemon for environment {} states another public major than this command does. {}",
        id,
        which.nothing_asked()
    )
}

/// Ends the command at its start, where the first reach of the endpoint shows what it does, by
/// the decision of [`said_at_the_start`]. The lock is read only where the decision needs it.
pub(crate) fn at_the_start(
    which: Which,
    start: &Start,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
    bound: Duration,
) -> Completion {
    let said = decided_at_the_start(start, environment);
    say_at_the_start(which, said, environment, none, json, earlier, bound)
}

/// What [`said_at_the_start`] decides for the environment, reading its lock only where the decision
/// needs it.
pub(crate) fn decided_at_the_start(start: &Start, environment: &KnownEnvironment) -> Said<AtStart> {
    said_at_the_start(start, || Lock::of(lock_held(&environment.paths)))
}

/// Ends the command with what [`said_at_the_start`] decided.
pub(crate) fn say_at_the_start(
    which: Which,
    said: Said<AtStart>,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
    bound: Duration,
) -> Completion {
    let id = environment.environment_id;
    let message = match said.sentence {
        AtStart::OtherMajor => other_major_said(which, id),
        AtStart::NoDaemon => no_daemon_said(environment),
        AtStart::HoldsAndSilent => holds_and_is_silent_said(which, environment),
        AtStart::Silent => silent_said(which, id, bound),
        AtStart::LockUnreadable(why) => lock_unreadable_said(which, id, &why),
    };
    conclude(said.exit, message, none, json, earlier)
}

/// What a person does if the process that holds the environment stays: the process the lock file
/// names where it is a process named kr-controller, and otherwise the way to find it.
pub(crate) fn how_to_end_the_holder(environment: &EnvironmentPaths) -> Shown {
    how_to_end_the_process(named_daemon(environment))
}

/// What a person does if the process that holds the environment stays, where the process that the
/// lock file names is `named`.
pub(crate) fn how_to_end_the_process(named: Option<u64>) -> Shown {
    match named {
        Some(pid) => shown!(
            "If it stays like this, process {} is the daemon and {} {} ends it.",
            pid,
            handover::STOP_COMMAND,
            pid
        ),
        None if cfg!(windows) => Shown::said(
            "If it stays like this, end the kr-controller.exe process of this installation in \
             Task Manager.",
        ),
        None => Shown::said("If it stays like this, end the process that holds the lock file."),
    }
}

/// The process the lock file names, with its start identity, read now: the holder of the
/// environment's lock, which a daemon writes when it takes it. A lock file that cannot be read, a
/// process that has gone and one whose identity cannot be read name none.
pub(crate) fn lock_holder(environment: &EnvironmentPaths) -> Option<ProcessStartIdentity> {
    let pid = SingletonLock::holder(&environment.singleton_lock())
        .ok()
        .flatten()?;
    identity::process_start_identity(pid).ok()
}

/// Whether `holder` is a process that runs this installation's daemon, by the name of its program.
fn runs_the_daemon(holder: &ProcessStartIdentity) -> bool {
    match identity::read_process(holder) {
        ProcessReading::Running(facts) => {
            facts.name.as_deref() == Some(kr_ipc::install::Program::Controller.file_name().as_str())
        }
        _ => false,
    }
}

/// The process a message may name as the daemon: the lock file's holder, where it runs this
/// installation's daemon. Anything else is not named.
pub(crate) fn named_daemon(environment: &EnvironmentPaths) -> Option<u64> {
    lock_holder(environment)
        .filter(runs_the_daemon)
        .map(|holder| holder.pid.get())
}

/// Whether a daemon holds the environment's lock, which the kernel gives up when its process has
/// gone and the daemon when it lets the environment go first. The look takes the lock for a moment, so a daemon that starts during it can find the
/// lock taken and exit; only [`Installation::held`] in a store keeps a start out of that moment,
/// by the install lock that a daemon's start holds.
fn lock_held(environment: &EnvironmentPaths) -> std::result::Result<bool, Shown> {
    let lock = environment.singleton_lock();
    // An environment whose state directory is not there has never had a daemon.
    if !lock.parent().is_some_and(std::path::Path::is_dir) {
        return Ok(false);
    }
    match SingletonLock::hold(&lock, environment.environment_id()) {
        Ok(_) => Ok(false),
        Err(kr_controller::ControllerError::AlreadyRunning { .. }) => Ok(true),
        Err(error) => Err(Shown::protocol(&error.to_protocol_error())),
    }
}

/// What the request came to.
pub(crate) enum Asked {
    /// The daemon took the stop and answered.
    Taken(HostStopResult),
    /// The outcome is not known: the write of the request failed where a part of it may have gone,
    /// or no answer came, or it was cut, or the daemon's word does not say whether it took the
    /// stop. The request may or may not have left. The daemon is waited for as one that took it.
    Unknown(Shown),
    /// The daemon refused, and its word is that nothing was done.
    Refused(ProtocolError),
    /// The request could not be made: nothing was sent. `error` is the failure of composing it, or
    /// the level's refusal at the write, which comes before any byte is written.
    NotComposed { error: kr_ipc::IpcError },
}

/// Whether a failure of the connection is the daemon's close of it, which a daemon does when it
/// goes: the end of the stream at a frame boundary, and inside a frame too (a reset reads as an end
/// of the stream, so a frame that the close cut is a truncated one).
fn closed_by_the_daemon(error: &kr_ipc::IpcError) -> bool {
    matches!(
        error,
        kr_ipc::IpcError::PeerClosed | kr_ipc::IpcError::TruncatedFrame { .. }
    )
}

/// What the request came to where its write failed with `error`. The level's check refuses a frame
/// that the daemon's level cannot read ([`kr_ipc::IpcError::NotInLevel`]) before any byte is
/// written, so nothing left and the request is as one that could not be made. Every other failure
/// of the write may come after a part of the frame went, and its outcome is unknown. A frame that
/// cannot be encoded ([`kr_ipc::IpcError::Frame`]) is also raised before any byte, and stays
/// unknown here: the source function answers it as a closure, the roster's `Frame` row that
/// differs.
fn after_the_write_failed(error: kr_ipc::IpcError) -> Asked {
    if matches!(error, kr_ipc::IpcError::NotInLevel(_)) {
        Asked::NotComposed { error }
    } else {
        Asked::Unknown(Shown::ipc(&error))
    }
}

/// Sends the request, says that it left, and waits for its answer.
///
/// A write that the level's check refuses left nothing ([`after_the_write_failed`]). Any other
/// write that fails, and anything but a whole answer to this request, is an unknown outcome: a
/// daemon that ends for another cause gets no answer, and the daemon stops when its write of the
/// answer has completed, failed or reached its bound, so an answer can be cut.
pub(crate) async fn ask(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    json: bool,
    progress: &Progress,
    launch_only: bool,
) -> Asked {
    let composed = client
        .compose(
            Method::HostStop,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &HostStopParams { launch_only },
        )
        .await;
    let mutation = match composed {
        Ok(mutation) => mutation,
        Err(error) => {
            return Asked::NotComposed { error };
        }
    };
    // Set before the request is written: an interrupt from here on may find it taken.
    if !launch_only {
        progress.enter(Stage::Asked);
    }
    let request_id = mutation.request_id;
    if let Err(error) = client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
    {
        let failed = after_the_write_failed(error);
        if matches!(failed, Asked::NotComposed { .. }) && !launch_only {
            // Nothing left, so an interrupt from here on has no request to speak of.
            progress.enter(Stage::BeforeAsking);
        }
        return failed;
    }
    if !json && !launch_only {
        report::say(&shown!(
            "Asked the control daemon for environment {} to stop. It waits up to {} seconds for \
             session creates under way, and an interrupt does not cancel the stop.",
            environment_id,
            STOP_SETTLE_MS / 1000
        ));
    }
    let answered = tokio::time::timeout(ANSWER_BOUND, async {
        loop {
            match client.recv().await {
                Ok(ControlFrame::Response(response)) if response.request_id == request_id => {
                    return Ok(response.outcome);
                }
                // What the host pushes meanwhile is not the answer.
                Ok(ControlFrame::Notification(_)) => {}
                Ok(_) => {
                    return Err(Shown::said("the daemon answered something else"));
                }
                Err(error) => return Err(Shown::ipc(&error)),
            }
        }
    })
    .await;
    match answered {
        Ok(Ok(Outcome::Ok(value))) => match value.to_typed::<HostStopResult>() {
            Ok(result) => Asked::Taken(result),
            Err(error) => Asked::Unknown(shown!(
                "its answer is not a stop's: {}",
                Shown::cbor(&error)
            )),
        },
        // A refusal says nothing was done only where it is definite; a withheld or transient one
        // does not, and the daemon is waited for as one that took the stop.
        Ok(Ok(Outcome::Error(error))) => match split_of(error.code.retry_category()) {
            Split::MaybeAsked => Asked::Unknown(Shown::protocol(&error)),
            Split::Refused => Asked::Refused(error),
        },
        Ok(Err(said)) => Asked::Unknown(said),
        Err(_) => Asked::Unknown(shown!(
            "it did not answer within {} seconds",
            ANSWER_BOUND.as_secs()
        )),
    }
}

/// What the daemon's refusal of the stop says of the request, by the retry category of its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Split {
    /// The daemon refused the stop, and nothing was taken: no wait.
    Refused,
    /// The refusal does not say that nothing was done (its category is transient or its outcome is
    /// unknown): the daemon is waited for as one that took the stop.
    MaybeAsked,
}

/// Where a refusal of the stop goes, by the retry category of its code. Every category is an
/// arm, with no catch-all, so that a new category is a compile error here until it is decided.
fn split_of(category: RetryCategory) -> Split {
    match category {
        RetryCategory::Transient | RetryCategory::OutcomeUnknown => Split::MaybeAsked,
        RetryCategory::NoRetry | RetryCategory::Resync | RetryCategory::ConfigurationChange => {
            Split::Refused
        }
    }
}

/// Whether the record of the attempt is told that the daemon took the stop: for a request that the
/// daemon took and answered, and for no request whose outcome is not known.
fn marker_told(request: &Request) -> bool {
    match request {
        Request::Told => true,
        Request::MaybeAsked(_) => false,
    }
}

/// The process that the end of a stop is waited for by, and the one that `--json` shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waited<'a> {
    /// The process that the wait is for by its start identity: the one that the lock file named
    /// before the request, where a reply on the connection that carried the request named the
    /// same process.
    old: Option<&'a ProcessStartIdentity>,
    /// The process that `--json` shows: the one that the answer named, and otherwise the one that
    /// the lock file named.
    pid: Option<u64>,
}

/// Which process a stop is waited for by, from the one that the lock file named before the request
/// (`holder`), the one that an earlier reply on the connection that carries the request named
/// (`stated`: the restart's request for the launch alone) and the one that the answer to the
/// request named (`answered`). The lock file was read before the connection was made, so it may
/// name a daemon that another has replaced since: the wait is for that process by its identity only
/// where a reply on the carrying connection named it. A reply that names none (an unknown outcome)
/// gives no identity, and the wait then ends as it does where no process is known.
fn process_waited_for(
    holder: Option<&ProcessStartIdentity>,
    stated: Option<u64>,
    answered: Option<u64>,
) -> Waited<'_> {
    let named = answered.or(stated);
    Waited {
        old: holder.filter(|holder| named == Some(holder.pid.get())),
        pid: answered.or_else(|| holder.map(|holder| holder.pid.get())),
    }
}

/// What ended the command before the daemon's end was waited for.
pub(crate) enum Cut {
    /// The command's own words, said: a read of the daemon that was refused, the record that could
    /// not be made, or the daemon's refusal of the request.
    Said(Completion),
    /// A daemon that accepted the connection did not answer `host.info` within the bound: a holder
    /// that is silent. The caller says what that comes to, at once.
    Silent,
    /// The connection failed before the request was made, in the read of `host.info` or in making
    /// the request: how that came out, decided on its own deadline.
    Unmade {
        before: Before,
        error: kr_ipc::IpcError,
    },
}

/// What a request that was made and the wait for the daemon's end came to.
pub(crate) struct Settled {
    /// What the request came to.
    pub(crate) request: Request,
    /// How the wait for the daemon's end came out.
    pub(crate) ended: End,
    /// The process that `--json` shows: the one that the answer named, and otherwise the one that
    /// the lock file named.
    pub(crate) pid: Option<u64>,
    /// The sessions' creates that the daemon said were still under way when it went on with its
    /// stop, where it answered.
    pub(crate) unsettled: Option<u64>,
    /// The process that the wait was for by its start identity, owned: the one that the lock file
    /// named before the request, where a reply on the connection that carried the request named the
    /// same process.
    pub(crate) old: Option<ProcessStartIdentity>,
}

/// A daemon answered the hello: reads what it says of itself, asks it to stop, waits for it to end
/// and says what that came to. `holder` is the process that held the environment before the
/// reach.
// One argument for each fact its steps read: the command, the paths, the environment, the
// connection, the holder before the reach, the output form, the progress and what was said before.
#[allow(clippy::too_many_arguments)]
async fn stop_the_daemon(
    which: Which,
    host: &HostPaths,
    environment: &KnownEnvironment,
    client: LocalClient,
    holder: Option<ProcessStartIdentity>,
    json: bool,
    progress: &Progress,
    earlier: &Earlier,
) -> Completion {
    let id = environment.environment_id;
    let none = Facts::none(earlier.said(id));
    let settled = async {
        let (client, info) =
            read_the_daemon(host, environment, client, holder.as_ref(), json, &none).await?;
        ask_and_wait(
            which,
            host,
            environment,
            client,
            &info,
            holder,
            None,
            json,
            progress,
            &none,
        )
        .await
    }
    .await;
    match settled {
        Ok(settled) => say_the_stop(which, settled, environment, &none, json, progress, earlier),
        Err(Cut::Said(completion)) => completion,
        Err(Cut::Silent) => at_the_start(
            which,
            &Start::Silent,
            environment,
            &none,
            json,
            earlier,
            startup::ANSWER_BOUND,
        ),
        Err(Cut::Unmade { before, error }) => {
            unmade_ended(which, before, &error, id, environment, &none, json, earlier)
        }
    }
}

/// Reads what a daemon that answered the hello says of itself. A daemon that answered the hello and
/// does not answer this is a holder that is silent. `holder` is the process that held the
/// environment before the reach.
pub(crate) async fn read_the_daemon(
    host: &HostPaths,
    environment: &KnownEnvironment,
    mut client: LocalClient,
    holder: Option<&ProcessStartIdentity>,
    json: bool,
    none: &Facts,
) -> std::result::Result<(LocalClient, HostInfoResult), Cut> {
    let id = environment.environment_id;
    match tokio::time::timeout(
        startup::ANSWER_BOUND,
        host_info(&mut client, &environment.paths),
    )
    .await
    {
        Ok(Ok(info)) => Ok((client, info)),
        Ok(Err(CliError::Ipc(error))) => {
            let operations = Real::of(host, &environment.paths, None);
            let before = host_info_failed(
                &operations,
                client,
                &error,
                holder,
                id,
                tokio::time::Instant::now() + END_BOUND,
            )
            .await;
            Err(Cut::Unmade { before, error })
        }
        Ok(Err(error)) => Err(Cut::Said(failed(error, none, json))),
        Err(_) => Err(Cut::Silent),
    }
}

/// Records the attempt, asks the daemon to stop and waits for it to end. What ends the command
/// before the wait is a [`Cut`]. `stated` is the process that a reply on this connection named
/// before the request, where the command asked for one (the restart's request for the launch
/// alone).
// The command, the paths, the environment, the connection, what the daemon said of itself, the
// holder, the process a reply stated, the output form, the progress and the result so far.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ask_and_wait(
    which: Which,
    host: &HostPaths,
    environment: &KnownEnvironment,
    mut client: LocalClient,
    info: &HostInfoResult,
    holder: Option<ProcessStartIdentity>,
    stated: Option<u64>,
    json: bool,
    progress: &Progress,
    none: &Facts,
) -> std::result::Result<Settled, Cut> {
    let id = environment.environment_id;
    // `holder` is who held the environment, and which process that is, before anything was asked,
    // read once before the first reach: a process that has ended and not been collected is read as
    // gone, and its number may be reused.
    let marker = match Marker::begin(&environment.paths, which.attempt(), holder.clone()) {
        Ok(marker) => marker,
        Err(error) => {
            return Err(Cut::Said(failed(
                CliError::Other(shown!(
                    "{} could not record its attempt: {}. {}",
                    which.command(),
                    Shown::ipc(&error),
                    which.nothing_asked()
                )),
                none,
                json,
            )));
        }
    };
    *progress
        .marker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);

    let (request, pid, unsettled) = match ask(&mut client, id, json, progress, false).await {
        Asked::Taken(result) => {
            progress.enter(Stage::Told);
            (
                Request::Told,
                Some(result.pid.get()),
                Some(result.unsettled.get()),
            )
        }
        Asked::Unknown(said) => {
            // The request may have left; the daemon is waited for as one that took it.
            progress.enter(Stage::Asked);
            (Request::MaybeAsked(said), None, None)
        }
        Asked::NotComposed { error } => {
            // The request was never made (it could not be composed, or the level's check refused
            // the frame at the write), so nothing left and there is no stop to wait for. The
            // daemon may have gone meanwhile, as it does when another command's stop has taken
            // effect: its end is decided as for any failure before the request, within the one
            // deadline, which counts from the failure. A daemon that answered a look is the unmade
            // request's failure; where none answered, the end is proved or it is not shown.
            let deadline = tokio::time::Instant::now() + END_BOUND;
            progress.remove_marker();
            let operations = Real::of(host, &environment.paths, Some(info.generation));
            let before = failed_before_the_request(
                &operations,
                client,
                holder.as_ref(),
                &error,
                id,
                deadline,
            )
            .await;
            return Err(Cut::Unmade { before, error });
        }
        Asked::Refused(error) => {
            // Nothing was taken, so an interrupt from here on has nothing to say but that.
            progress.enter(Stage::Refused);
            progress.remove_marker();
            let refusal = Facts {
                knows: Knows::Refused,
                ..none.clone()
            };
            return Err(Cut::Said(
                refused(&mut client, which, id, info, error, &refusal, json).await,
            ));
        }
    };
    if marker_told(&request) {
        let _ = progress.with_marker(|marker| marker.told());
    }
    drop(client);

    // The process that is waited for by its start identity is the one that a reply on this
    // connection named: a lock file that names another, or that no reply confirms, says nothing
    // about this daemon, which may have replaced the one that it names. Where there is none, the
    // wait is for the lock and the endpoint, and no text names the asked process by its identity; a
    // text names only a process that the lock file names, where that is a live process named
    // kr-controller.
    let Waited { old, pid } = process_waited_for(holder.as_ref(), stated, pid);
    let operations = Real::of(host, &environment.paths, Some(info.generation));
    let ended = wait_for_the_end(&operations, old, END_BOUND).await;
    Ok(Settled {
        request,
        ended,
        pid,
        unsettled,
        old: old.cloned(),
    })
}

/// What the command says of a stop that was made and waited for, and the record of the attempt
/// removed where the end is shown.
pub(crate) fn say_the_stop(
    which: Which,
    settled: Settled,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    progress: &Progress,
    earlier: &Earlier,
) -> Completion {
    let Settled {
        request,
        ended,
        pid,
        unsettled,
        old,
    } = settled;
    let said = said_after_the_request(ended, &request);
    let message = words_after_the_request(
        which,
        &said.sentence,
        &request,
        &environment.paths,
        environment.environment_id,
        old.as_ref(),
        unsettled,
    );
    // The record of the attempt is removed where the end is shown.
    if said.exit == Exit::Done {
        progress.remove_marker();
    }
    let facts = Facts {
        knows: said.stop,
        pid,
        unsettled,
        records: none.records.clone(),
        answer: none.answer,
    };
    conclude(said.exit, message, &facts, json, earlier)
}

/// What the command says where it saw the daemon end after the request was written and no other
/// daemon holds the environment. Where the daemon took the stop and answered, it says that it
/// stopped the daemon. Where the outcome is not known (`not_known` is the request's failure), it
/// says only what it knows: that the daemon did not show whether it took the stop, and that it has
/// ended. What follows the first sentence is the same for both.
fn gone_said(
    id: EnvironmentId,
    named: Option<u64>,
    not_known: Option<&Shown>,
    unsettled: Option<u64>,
) -> Shown {
    let process = named.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
    let first = match not_known {
        None => shown!(
            "Stopped the control daemon for environment {}{}.",
            id,
            process
        ),
        Some(failure) => shown!(
            "The control daemon for environment {}{} did not show whether it took the stop ({}), \
             and it has ended.",
            id,
            process,
            *failure
        ),
    };
    shown!(
        "{} No session was stopped: its workers keep running, a local attach keeps working, and \
         the next daemon finds the sessions again. Paired devices' connections close until a \
         daemon runs.{}",
        first,
        creates_under_way(unsettled)
    )
}

/// What the command says after a request that was written, by the kind of sentence that
/// [`said_after_the_request`] decided. The process of the daemon that was asked is named where it
/// is known (`old`).
fn words_after_the_request(
    which: Which,
    sentence: &AfterRequest,
    request: &Request,
    environment: &EnvironmentPaths,
    id: EnvironmentId,
    old: Option<&ProcessStartIdentity>,
    unsettled: Option<u64>,
) -> Shown {
    let not_known = request.not_known();
    let named = old.map(|old| old.pid.get());
    match sentence {
        AfterRequest::Stopped => gone_said(id, named, not_known, unsettled),
        AfterRequest::Successor(successor) => successor_said(id, named, *successor, unsettled),
        AfterRequest::NotEnded => {
            let what = match not_known {
                Some(failure) => shown!(
                    "did not show whether it took the stop ({}), and it has not ended",
                    *failure
                ),
                None => Shown::said("was told to stop and has not ended"),
            };
            not_ended(which, environment, id, &what, old)
        }
        AfterRequest::NotShown => not_shown(which, id, not_known),
        AfterRequest::StillHeld => still_held(which, environment, id),
        AfterRequest::HeldNotShown => held_not_shown(which, id, not_known),
        AfterRequest::Unlooked(why) => unlooked(which, id, not_known, why),
    }
}

/// The words where the lock was free and the last look showed neither that the daemon runs nor
/// that it had gone.
fn not_shown(which: Which, id: EnvironmentId, not_known: Option<&Shown>) -> Shown {
    match not_known {
        None => shown!(
            "The control daemon for environment {} was told to stop. After {} seconds the lock was \
             free, and the last look at the endpoint showed neither that the daemon still runs nor \
             that it had gone, so the command could not confirm the end. Run {} again in \
             a moment; it looks again.{}",
            id,
            END_BOUND.as_secs(),
            which.command(),
            which.no_start()
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}). \
             After {} seconds the lock was free, and the last look at the endpoint showed neither \
             that the daemon still runs nor that it had gone, so the command could not confirm the \
             end. Run {} again in a moment; it looks again.{}",
            id,
            *failure,
            END_BOUND.as_secs(),
            which.command(),
            which.no_start()
        ),
    }
}

/// Ends the command where its request could not be made, by what the failure came to: with the
/// daemon's end, with silence (exit 1) where the end is not shown in the bound after a connection
/// was accepted, and with the unmade request's failure (exit 3) where a daemon answered, where the
/// failure is this side's own, and where the connect found nothing listening and no lock is held.
/// The read of `host.info` and the compose of the stop request end here.
// One argument for each fact its arms read: the command, the decision, the failure, the environment,
// the result so far, the output form and the records.
#[allow(clippy::too_many_arguments)]
pub(crate) fn unmade_ended(
    which: Which,
    before: Before,
    error: &kr_ipc::IpcError,
    id: EnvironmentId,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> Completion {
    match ended_by(which, before, environment, none, json, earlier) {
        Ok(completion) => completion,
        Err(cause) => failed(
            unmade_request(which, id, &Shown::ipc(error), cause),
            none,
            json,
        ),
    }
}

/// The failure of a greeting that could not be completed: that the daemon could not be reached
/// and that no stop was requested. A daemon's reply or this side's own fault makes it, and the
/// words are the failure's own.
pub(crate) fn unreached(
    which: Which,
    id: EnvironmentId,
    error: &kr_ipc::IpcError,
    _cause: Unmade,
) -> CliError {
    CliError::HostUnavailable(shown!(
        "the control daemon for environment {} could not be reached: {}. {}",
        id,
        Shown::ipc(error),
        which.nothing_asked()
    ))
}

/// The failure of a request that could not be made: what was not made and that the stop was not
/// asked. A daemon's answer, this side's own fault or a connect that found nothing listening makes
/// it, and the words are the failure's own; `Unmade` says which.
fn unmade_request(which: Which, id: EnvironmentId, why: &Shown, _cause: Unmade) -> CliError {
    CliError::HostUnavailable(shown!(
        "{} could not make its request for the control daemon of environment {}: {}. \
         Nothing was sent, and nothing was stopped.",
        which.command(),
        id,
        *why
    ))
}

/// What the end's decision came to where a request could not be made.
enum Decided {
    /// The daemon had ended: its process has gone and the environment's lock is free or another
    /// control daemon holds it.
    Ended(End),
    /// The end is not shown within the bound, and no daemon answered.
    NotShown,
    /// A daemon answered a look, with a proved generation or without one: the first, or the last of
    /// the wait at its bound. It holds the answer.
    Answers(Answered),
}

/// Decides, where the request could not be made, whether the daemon had ended when it could not be.
/// A daemon that closed the connection is going and is waited for to its end within the one
/// deadline, once. A daemon that did not close it is looked at once first, for as long as the
/// deadline leaves, and one that answers stays: nothing is waited for. A daemon that answers the
/// last look of the wait, at its bound, stays as well. Where no daemon answered, the end is proved
/// or it is not shown in the bound; there is no other result. The deadline is the caller's, set
/// before the look, so that the look and the wait together stay inside it.
///
/// `connection` is the command's connection to the daemon, which is let go before anything is
/// looked at, as before the wait of a request that was asked.
async fn ended_before_the_request(
    operations: &impl Operations,
    connection: impl Sized,
    old: Option<&ProcessStartIdentity>,
    closed: bool,
    deadline: tokio::time::Instant,
) -> Decided {
    // Where the platform keeps a pipe instance for as long as a handle to it is open, a daemon
    // that has gone stays at its endpoint for a command that holds its end: every new connection
    // finds the pipe busy, so no look sees the end, and a new daemon cannot create the pipe's
    // first instance.
    drop(connection);
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let first = match first_look(closed) {
        FirstLook::NotMade => Endpoint::Unclear,
        FirstLook::Made => {
            operations
                .look(startup::ANSWER_BOUND.min(left()), &mut |_| {})
                .await
        }
    };
    match first_look_answers(first) {
        Some(answered) => Decided::Answers(answered),
        None => decided_by_the_wait(wait_for_the_end(operations, old, left()).await),
    }
}

/// Whether a request that could not be made is looked at first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstLook {
    /// A daemon that closed the connection is going: no look is made, and the wait decides.
    NotMade,
    /// The connection was not closed by the daemon: the endpoint is looked at once first.
    Made,
}

/// Whether the first look is made, by whether the daemon closed the connection.
fn first_look(closed: bool) -> FirstLook {
    if closed {
        FirstLook::NotMade
    } else {
        FirstLook::Made
    }
}

/// What the first look makes of a request that could not be made: any answer at the endpoint is an
/// answer, whether or not it proves the generation of the daemon that was asked, and nothing else
/// is.
fn first_look_answers(look: Endpoint) -> Option<Answered> {
    match look {
        Endpoint::Same(answered) | Endpoint::Unproved(answered) => Some(answered),
        Endpoint::Nobody | Endpoint::Another | Endpoint::Unclear => None,
    }
}

/// What the end of the wait makes of a request that could not be made: a daemon that answered the
/// last look of the wait is an answer, as at the first look; the daemon's end is its end; and
/// anything else is an end that is not shown.
fn decided_by_the_wait(end: End) -> Decided {
    match end {
        End::NotEnded(_, answer) => answer.map_or(Decided::NotShown, Decided::Answers),
        End::Gone | End::Successor(_) => Decided::Ended(end),
    }
}

/// How the failure of the command's connection to the daemon came out, where it failed before the
/// command could make its request.
pub(crate) enum Before {
    /// The daemon had ended, or another holds the environment now: what the command says, and the
    /// process that it names.
    Ended {
        said: Shown,
        pid: Option<u64>,
        /// What the end was: a free environment, or another daemon that holds it.
        end: End,
    },
    /// A daemon's end can have caused the failure, and no end was shown within the bound, with no
    /// daemon answering the last look. `accepted` is whether a connection was accepted before the
    /// failure: a connect that found nothing listening accepted none.
    Silent { accepted: bool },
    /// A daemon answered, by a look or by a reply of its own: the failure keeps its own words,
    /// with exit 3. It holds the answer.
    Answers(Answered),
    /// The failure is this side's own: no daemon wrote it and no daemon's end causes it. It says
    /// its own words, with exit 3, and nothing is looked at.
    OwnFault,
}

/// What makes a failure that ends with exit 3 true: a daemon's answer, this side's own fault, or a
/// connect that found nothing listening where the end was not shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unmade {
    /// A daemon answered.
    Answered(Answered),
    /// This side's own fault.
    OwnFault,
    /// The connect found nothing listening, and no end was shown within the bound.
    NothingListening,
}

/// Decides what a failure of the connection before the command's request was made came to, as the
/// arm for a request that could not be made decides it: by the daemon's end, looked for within
/// `deadline`. A daemon's own reply is an answer, and this side's own fault is said as it is. A
/// closure is decided by the daemon's end: a closed connection, or a frame that the close cut, is
/// waited for; any other closure is looked at once first. A daemon that answers a look leaves the
/// failure its own words; where none answered, the end is proved or it is not shown in the bound.
async fn failed_before_the_request(
    operations: &impl Operations,
    connection: impl Sized,
    holder: Option<&ProcessStartIdentity>,
    error: &kr_ipc::IpcError,
    id: EnvironmentId,
    deadline: tokio::time::Instant,
) -> Before {
    // The source is read through the one function that names every variant, and [`route_of`]
    // says where each goes.
    match route_of(error.comes_from()) {
        Route::Reply => {
            drop(connection);
            return Answered::of_reply(error).map_or(Before::OwnFault, Before::Answers);
        }
        Route::OwnFault => {
            drop(connection);
            return Before::OwnFault;
        }
        Route::TheEnd => {}
    }
    let closed = closed_by_the_daemon(error);
    let decided = ended_before_the_request(operations, connection, holder, closed, deadline).await;
    before_by_the_wait(
        decided,
        !startup::nothing_listening(error),
        id,
        holder.map(|holder| holder.pid.get()),
        &Shown::ipc(error),
    )
}

/// Where a failure of the connection before the request goes, by where it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// A daemon wrote it: it is an answer, and nothing is looked at.
    Reply,
    /// This side's own fault: no daemon's end causes it, so nothing is looked at.
    OwnFault,
    /// A daemon's end can cause it: the end is looked for within the deadline.
    TheEnd,
}

/// Where a failure goes, by its source. Every source is an arm, with no catch-all, so that a new
/// source is a compile error here until it is decided.
fn route_of(source: ErrorSource) -> Route {
    match source {
        ErrorSource::Reply => Route::Reply,
        ErrorSource::OwnFault => Route::OwnFault,
        ErrorSource::Closure => Route::TheEnd,
    }
}

/// What a failure that a daemon's end can cause came to, by what the wait decided: the daemon had
/// ended (`pid` is the process that the lock file named before the request, and `why` the
/// failure's words), no end was shown and no daemon answered (`accepted` is whether a connection
/// was accepted before the failure), or a daemon answered. Every decision is an arm, with no
/// catch-all, so that a new decision is a compile error here until it is decided.
fn before_by_the_wait(
    decided: Decided,
    accepted: bool,
    id: EnvironmentId,
    pid: Option<u64>,
    why: &Shown,
) -> Before {
    match decided {
        Decided::Ended(ended) => Before::Ended {
            said: ended_before_the_request_said(id, pid, &ended, why),
            pid,
            end: ended,
        },
        Decided::NotShown => Before::Silent { accepted },
        Decided::Answers(answered) => Before::Answers(answered),
    }
}

/// The command's greeting of the daemon failed with `error`: what the failure came to.
async fn greeting_failed(
    operations: &impl Operations,
    error: &kr_ipc::IpcError,
    holder: Option<&ProcessStartIdentity>,
    id: EnvironmentId,
    deadline: tokio::time::Instant,
) -> Before {
    failed_before_the_request(operations, (), holder, error, id, deadline).await
}

/// The command's read of `host.info` failed with `error`: what the failure came to. The stop was
/// not asked yet, so the failure is judged as an unmade request is, whatever its kind. The
/// command owns `connection` and lets it go before anything is looked at.
async fn host_info_failed(
    operations: &impl Operations,
    connection: impl Sized,
    error: &kr_ipc::IpcError,
    holder: Option<&ProcessStartIdentity>,
    id: EnvironmentId,
    deadline: tokio::time::Instant,
) -> Before {
    failed_before_the_request(operations, connection, holder, error, id, deadline).await
}

/// Ends the command by what a failed connection came to, by the decision of
/// [`said_before_the_request`]: with the daemon's end where it had ended, and as for a daemon that
/// does not answer where no end was shown within the bound and no daemon answered the last look.
/// It gives the cause where the failure keeps its own words (exit 3): a daemon answered, the
/// failure is this side's own, or the connect found nothing listening and no lock is held.
pub(crate) fn ended_by(
    which: Which,
    before: Before,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> std::result::Result<Completion, Unmade> {
    let id = environment.environment_id;
    let said = said_before_the_request(before, || Lock::of(lock_held(&environment.paths)));
    match said.sentence {
        BeforeRequest::Ended { words, pid } => {
            let facts = Facts {
                knows: said.stop,
                pid,
                unsettled: None,
                records: none.records.clone(),
                answer: none.answer,
            };
            Ok(conclude(said.exit, words, &facts, json, earlier))
        }
        BeforeRequest::HoldsAndSilent => Ok(conclude(
            said.exit,
            holds_and_is_silent_said(which, environment),
            none,
            json,
            earlier,
        )),
        BeforeRequest::Silent => Ok(conclude(
            said.exit,
            silent_said(which, id, END_BOUND),
            none,
            json,
            earlier,
        )),
        BeforeRequest::Unmade(cause) => Err(cause),
    }
}

/// What the command says where the daemon had ended when its request could not be made: that it
/// ended, why the request could not be made and that this command sent nothing. It says nothing of
/// which came first, which the command did not see. Where something holds the environment now, the
/// words are those of any end that finds a successor.
pub(crate) fn ended_before_the_request_said(
    id: EnvironmentId,
    old: Option<u64>,
    ended: &End,
    why: &Shown,
) -> Shown {
    match ended {
        End::Successor(successor) => successor_said(id, old, *successor, None),
        End::Gone | End::NotEnded(..) => {
            let process = old.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
            shown!(
                "The control daemon for environment {}{} ended, and this command could not make \
                 its request for it: {}. This command sent nothing.",
                id,
                process,
                *why
            )
        }
    }
}

/// What the creates that the daemon's stop went on without add to a result that saw it end: a
/// space and the sentence where the answer gave a count above zero, and nothing otherwise.
pub(crate) fn creates_under_way(unsettled: Option<u64>) -> Shown {
    match unsettled {
        Some(count) if count > 0 => shown!(
            " {} session creates were still under way after {} seconds, when the daemon went on \
             with its stop. Each of them finished or ended with the daemon.",
            count,
            STOP_SETTLE_MS / 1000
        ),
        _ => Shown::said(""),
    }
}

/// What the command says where the daemon ended and another holds the environment: the old process
/// and the new one where the command read them, and the creates that the stop went on without.
pub(crate) fn successor_said(
    id: EnvironmentId,
    old: Option<u64>,
    successor: Option<u64>,
    unsettled: Option<u64>,
) -> Shown {
    let old = old.map_or_else(
        || Shown::said("The control daemon"),
        |pid| shown!("The control daemon (process {})", pid),
    );
    let now = successor.map_or_else(
        || Shown::said("another control daemon"),
        |pid| shown!("process {}", pid),
    );
    shown!(
        "{} ended; {} now holds environment {}, so something started it again.{}",
        old,
        now,
        id,
        creates_under_way(unsettled)
    )
}

/// Whether a refusal of the stop is the daemon's own, with nothing more to ask: any refusal but
/// `PERMISSION_DENIED`, and that one where this program is a release of a store and the daemon
/// reports the controller build of that same release, which lists the request. Outside a store
/// every build of one version carries the same name, and the probe decides.
fn is_the_daemons_own_refusal(
    own_build: Option<&str>,
    daemon_build: &str,
    code: ErrorCode,
) -> bool {
    code != ErrorCode::PermissionDenied || own_build == Some(daemon_build)
}

/// The daemon refused the request, and said so definitely: nothing was stopped.
///
/// `PERMISSION_DENIED` is what a daemon of the same level answers a method it does not list, and
/// what it answers a request it will not take. Where this program is a release of a store and the
/// daemon reports that release's own build, the daemon lists `host.stop` and the refusal is its
/// own. Otherwise the two are told apart as the level documents: a read that every build lists,
/// under the same right, is asked. Where it is answered, the daemon is of a build that does not
/// know the request, and nothing is done to it; where it is refused too, the refusal is the
/// daemon's own and is shown as it is, the lapse of a lease included.
pub(crate) async fn refused(
    client: &mut LocalClient,
    which: Which,
    id: EnvironmentId,
    info: &HostInfoResult,
    error: ProtocolError,
    none: &Facts,
    json: bool,
) -> Completion {
    if is_the_daemons_own_refusal(
        crate::controller_build_of_this_release().as_deref(),
        info.build_id.as_str(),
        error.code,
    ) {
        return failed(refusal_said(which, error), none, json);
    }
    let probe = tokio::time::timeout(
        startup::ANSWER_BOUND,
        client.request(Method::BackupStatus, &BackupStatusParams {}),
    )
    .await
    .ok()
    .map(|read| read.map(|answer| answer.map(|_| ())));
    failed(after_the_probe(which, id, error, probe), none, json)
}

/// The daemon's own refusal as the command says it: the stop gives the daemon's words as they
/// are, and the restart adds that nothing was stopped, since a refusal that is definite means that
/// the daemon did not take the request.
fn refusal_said(which: Which, refusal: ProtocolError) -> CliError {
    match which {
        Which::Stop => CliError::Refused(refusal),
        Which::Restart => CliError::refused_in_its_own_words(
            refusal.code,
            shown!("{}. Nothing was stopped.", Shown::protocol(&refusal)),
        ),
    }
}

/// What the probe's answer makes of a refusal that may be the daemon's own. `None` is a probe
/// that was not answered in its bound.
fn after_the_probe(
    which: Which,
    id: EnvironmentId,
    refusal: ProtocolError,
    probe: Option<std::result::Result<std::result::Result<(), ProtocolError>, kr_ipc::IpcError>>,
) -> CliError {
    match probe {
        Some(Ok(Ok(()))) => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "The control daemon of environment {} is of another build and takes no stop \
                 request. Nothing was stopped. kr host update or kr host rollback switches this \
                 host to another release and replaces this daemon. Each checks the stores for \
                 that release before it switches, and starts this daemon again if it cannot \
                 switch.",
                id
            ),
        },
        Some(Ok(Err(probe))) if probe.code == ErrorCode::PermissionDenied => {
            CliError::refused_in_its_own_words(
                ErrorCode::PermissionDenied,
                shown!(
                    "The control daemon of environment {} takes no stop request or refuses it, \
                     and the check that tells which was refused too: {}. Nothing was stopped.",
                    id,
                    Shown::protocol(&probe)
                ),
            )
        }
        Some(Ok(Err(other))) => refusal_said(which, other),
        Some(Err(_)) | None => refusal_said(which, refusal),
    }
}

/// M4: the daemon was asked and has not ended after the wait. A process is named only while it is
/// a process named kr-controller: `old`, the process that held the environment before the request
/// where the daemon's answer, if it came, named it too, or the one the lock file names now.
fn not_ended(
    which: Which,
    environment: &EnvironmentPaths,
    id: EnvironmentId,
    what: &Shown,
    old: Option<&ProcessStartIdentity>,
) -> Shown {
    let ends_with = match old
        .filter(|holder| runs_the_daemon(holder))
        .map(|holder| holder.pid.get())
        .or_else(|| named_daemon(environment))
    {
        Some(pid) => shown!(
            "If it stays, {} {} ends it, and the next daemon recovers as it does after a crash.",
            handover::STOP_COMMAND,
            pid
        ),
        None if cfg!(windows) => Shown::said(
            "If it stays, end the kr-controller.exe process of this installation in Task Manager; \
             the next daemon recovers as it does after a crash.",
        ),
        None => Shown::said(
            "If it stays, end the process that holds the lock file; the next daemon recovers as it \
             does after a crash.",
        ),
    };
    let then = match which {
        Which::Stop => "",
        Which::Restart => " Run kr host restart again once the old one has ended.",
    };
    shown!(
        "The control daemon for environment {} {} after {} seconds. It may be finishing a write. \
         {}{}{}",
        id,
        *what,
        END_BOUND.as_secs(),
        ends_with,
        then,
        which.no_start()
    )
}

/// The words where the environment's own lock was still held at the bound and nothing showed what
/// holds it: the process of the daemon asked could not be read, and no look showed that daemon
/// answering. The holder can be the daemon that was told, a daemon that is starting, or another
/// command's brief look, so the words say only that the end is not confirmed.
fn held_not_shown(which: Which, id: EnvironmentId, not_known: Option<&Shown>) -> Shown {
    match not_known {
        None => shown!(
            "The control daemon for environment {} was told to stop. After {} seconds the \
             environment was still held, and the command could not show what holds it, so it \
             could not confirm the end. Run {} again in a moment; it looks again.{}",
            id,
            END_BOUND.as_secs(),
            which.command(),
            which.no_start()
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}). \
             After {} seconds the environment was still held, and the command could not show \
             what holds it, so it could not confirm the end. Run {} again in a \
             moment; it looks again.{}",
            id,
            *failure,
            END_BOUND.as_secs(),
            which.command(),
            which.no_start()
        ),
    }
}

/// The environment after the daemon's process was seen to have gone, and still held when the wait
/// ended: what is said is that the process has gone and that something holds the environment which
/// is not shown to be a control daemon. It does not say that the daemon ended: the daemon ended only
/// where the lock is free or another control daemon holds it.
fn still_held(which: Which, environment: &EnvironmentPaths, id: EnvironmentId) -> Shown {
    shown!(
        "The process of the control daemon for environment {} has gone, and something that is not \
         shown to be a control daemon still holds the environment after {} seconds. Run {} \
         again in a moment. {}{}",
        id,
        END_BOUND.as_secs(),
        which.command(),
        how_to_end_the_holder(environment),
        which.no_start()
    )
}

/// The environment's lock could not be looked at, so that nothing is known of whether the daemon
/// has ended. `not_known` is what the request's failure said where whether the daemon took the
/// stop is not known; where it took it, the text says that it was told.
fn unlooked(which: Which, id: EnvironmentId, not_known: Option<&Shown>, why: &Shown) -> Shown {
    match not_known {
        None => shown!(
            "The control daemon for environment {} was told to stop, and whether it has ended could \
             not be read after {} seconds: {}. Run {} again in a moment.{}",
            id,
            END_BOUND.as_secs(),
            *why,
            which.command(),
            which.no_start()
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}), and \
             whether it has ended could not be read after {} seconds: {}. Run {} again in \
             a moment.{}",
            id,
            *failure,
            END_BOUND.as_secs(),
            *why,
            which.command(),
            which.no_start()
        ),
    }
}

/// Why the daemon had not ended when the wait did.
#[derive(Clone, Debug)]
pub(crate) enum Why {
    /// Its process runs: the daemon is told to stop and goes on.
    Running,
    /// The last look of the last round showed a daemon of the generation asked answering, whatever
    /// else the round read: a daemon answers, so it has not ended.
    Answers,
    /// No sign of life in the last round and no sign of an end: with no usable reading of the
    /// process (none was possible, or the system did not say) the lock was free and the last look
    /// showed neither the daemon nor its end. The command cannot say that the daemon has not ended.
    NotShown,
    /// Its process has gone and something holds the environment that nothing shows to be a daemon.
    Held,
    /// The lock is held, and there is no usable reading of the process (none was possible, or the
    /// system did not say) and no proved answer of the daemon asked: the environment is held, and
    /// nothing shows by whom. The daemon that was told may still be stopping, and another may be
    /// starting.
    HeldNotShown,
    /// The lock could not be looked at.
    Unlooked(Shown),
}

/// How the wait for the daemon's end came out.
#[derive(Clone, Debug)]
pub(crate) enum End {
    /// The daemon has ended and the environment is free: its process has gone where its identity
    /// was known, and otherwise the lock is free and nothing answers at its endpoint.
    Gone,
    /// The daemon has ended and another daemon holds the environment or answers at its endpoint:
    /// the number of the process the lock file names as a control daemon, where it names one.
    Successor(Option<u64>),
    /// The daemon had not ended when the wait did, or it could not be seen whether it had: why,
    /// and the answer of the last look where something answered it (a proved generation or not).
    NotEnded(Why, Option<Answered>),
}

/// Reads `host.info`, on a new connection once where the authority behind this one was withdrawn,
/// which a read of the host's configuration can do to every connection.
pub(crate) async fn host_info(
    client: &mut LocalClient,
    environment: &EnvironmentPaths,
) -> Result<HostInfoResult> {
    let typed =
        |outcome: std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError>| {
            outcome.map_err(CliError::Refused).and_then(|value| {
                value.to_typed().map_err(|error| {
                    CliError::Other(shown!(
                        "the host's answer could not be read: {}",
                        Shown::cbor(&error)
                    ))
                })
            })
        };
    match client.request(Method::HostInfo, &()).await? {
        Err(refused) if refused.code == ErrorCode::PermissionDenied => {
            // The new connection keeps its transport error: the opener that commands use turns it
            // into "no KalaReach host is running", which a daemon that is ending would make false.
            let endpoint = environment.controller_endpoint()?;
            *client = LocalClient::connect(
                &endpoint,
                kr_protocol::local::LocalClientKind::Cli,
                crate::build_id(),
            )
            .await?;
            typed(client.request(Method::HostInfo, &()).await?)
        }
        other => typed(other),
    }
}

/// What the environment's lock showed in a round.
#[derive(Clone, Debug)]
enum Lock {
    /// No process holds the environment's lock.
    Free,
    /// A process holds the environment's lock. The reading does not say which, and not whether it
    /// is a control daemon.
    Held,
    /// The lock could not be read: why, in this command's words.
    Unreadable(Shown),
}

impl Lock {
    fn of(read: std::result::Result<bool, Shown>) -> Self {
        match read {
            Ok(false) => Self::Free,
            Ok(true) => Self::Held,
            Err(why) => Self::Unreadable(why),
        }
    }
}

/// What the system said in a round of the process of the daemon that was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Process {
    /// The command has no identity of the process (always so on Windows), so none was read.
    NoIdentity,
    /// The process runs and its start identity matches.
    Running,
    /// The process has gone, or its number belongs to another process now.
    Ended,
    /// The system did not say whether the process runs: neither answer is established.
    Unreadable,
}

impl Process {
    fn of(state: Option<ProcessState>) -> Self {
        match state {
            None => Self::NoIdentity,
            Some(ProcessState::Running) => Self::Running,
            Some(ProcessState::Ended) => Self::Ended,
            Some(ProcessState::Unknown { .. }) => Self::Unreadable,
        }
    }
}

/// The process that the lock file names as a control daemon, in a round that read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holder {
    /// The round did not read it.
    NotRead,
    /// It names none, or the process that it names is no process named kr-controller.
    Nobody,
    /// It names the process that was asked itself.
    Asked,
    /// It names another process (its number), named kr-controller.
    Other(u64),
}

impl Holder {
    fn of(named: Option<u64>, old: Option<&ProcessStartIdentity>) -> Self {
        match named {
            None => Self::Nobody,
            Some(pid) if old.is_some_and(|old| old.pid.get() == pid) => Self::Asked,
            Some(pid) => Self::Other(pid),
        }
    }
}

/// What one round of the wait read. The decision of what the round shows is one function of this
/// value ([`what_the_round_shows`]), and which rounds make a look is another ([`look_wanted`]).
#[derive(Clone, Debug)]
struct Round {
    lock: Lock,
    process: Process,
    holder: Holder,
    /// What the look showed; none where the round made none.
    look: Option<Endpoint>,
    /// The process that the lock file named after a look that showed a daemon of another
    /// generation, where it named one.
    successor: Option<u64>,
}

/// Whether a round reads the process that the lock file names: where the lock is held and the
/// process is gone or was not read. Where the process is gone, a named process other than the
/// asked one is a successor. With no identity the named process is read too, but
/// [`what_the_round_shows`] never takes it for a successor, because the command cannot tell it
/// from the daemon that was asked: there the read only fills the table's column.
fn holder_wanted(lock: &Lock, process: Process) -> bool {
    match lock {
        Lock::Held => match process {
            Process::Ended | Process::NoIdentity => true,
            Process::Running | Process::Unreadable => false,
        },
        Lock::Free | Lock::Unreadable(_) => false,
    }
}

/// Whether a round makes a look at the endpoint. A look is made where the lock and the process
/// leave the end undecided and a look can decide it: with the lock free and no usable reading of
/// the process, and with the lock held and the process gone or not read, unless the lock file
/// names another process that is a daemon (which is evidence of a successor with no look).
fn look_wanted(lock: &Lock, process: Process, holder: Holder) -> bool {
    match lock {
        Lock::Free => match process {
            Process::Ended | Process::Running => false,
            Process::NoIdentity | Process::Unreadable => true,
        },
        Lock::Held => match process {
            Process::Ended => match holder {
                Holder::Other(_) => false,
                Holder::NotRead | Holder::Nobody | Holder::Asked => true,
            },
            Process::NoIdentity => true,
            Process::Running | Process::Unreadable => false,
        },
        Lock::Unreadable(_) => false,
    }
}

/// Whether a round reads the number of the process that the lock file names after its look: where
/// the look showed a daemon of another generation, that process is the successor, and no other
/// look makes the round read it.
fn successor_wanted(look: Option<Endpoint>) -> bool {
    match look {
        Some(Endpoint::Another) => true,
        Some(Endpoint::Nobody | Endpoint::Same(_) | Endpoint::Unproved(_) | Endpoint::Unclear)
        | None => false,
    }
}

/// What a round shows: the end (`End::Gone`, or `End::Successor`), nothing yet (none: the wait
/// goes on) or, where the bound is reached, why the end is not shown. Every combination of what a
/// round reads is an arm, with no catch-all arm over any of the readings, so that a new value of
/// one is a compile error here until it is decided.
///
/// The principle is that the command says only what the round's own readings show:
///
/// - The end is shown by the process gone with the lock free; by the lock free and nobody
///   listening where no usable reading of the process exists; and by a successor: another process
///   that the lock file names as a daemon, or a daemon of another generation at the endpoint.
/// - At the bound, a daemon of the generation asked answering the look is a sign that it has not
///   ended and wins over every other reading. An answer with no proved generation is no such
///   sign: it is kept as an answer at the endpoint (the second member of `End::NotEnded`) and the
///   other readings decide why.
fn what_the_round_shows(round: &Round, at_bound: bool) -> Option<End> {
    match &round.lock {
        Lock::Free => match round.process {
            Process::Ended => Some(End::Gone),
            Process::Running => bound_shows(round, at_bound, Why::Running),
            Process::NoIdentity | Process::Unreadable => the_endpoint_decides(round, at_bound),
        },
        Lock::Held => match round.process {
            Process::Ended => match round.holder {
                Holder::Other(pid) => Some(End::Successor(Some(pid))),
                Holder::NotRead | Holder::Nobody | Holder::Asked => {
                    a_successor_by_the_endpoint(round, at_bound, Why::Held)
                }
            },
            Process::Running => bound_shows(round, at_bound, Why::Running),
            Process::Unreadable => bound_shows(round, at_bound, Why::HeldNotShown),
            Process::NoIdentity => a_successor_by_the_endpoint(round, at_bound, Why::HeldNotShown),
        },
        Lock::Unreadable(why) => match round.process {
            Process::NoIdentity | Process::Unreadable | Process::Ended => {
                bound_shows(round, at_bound, Why::Unlooked(why.clone()))
            }
            Process::Running => bound_shows(round, at_bound, Why::Running),
        },
    }
}

/// With the lock free and no usable reading of the process, the look decides: nobody listening is
/// the end, another generation is a successor, and anything else shows no end.
fn the_endpoint_decides(round: &Round, at_bound: bool) -> Option<End> {
    match round.look {
        Some(Endpoint::Nobody) => Some(End::Gone),
        Some(Endpoint::Another) => Some(End::Successor(round.successor)),
        Some(Endpoint::Same(_) | Endpoint::Unproved(_) | Endpoint::Unclear) | None => {
            bound_shows(round, at_bound, Why::NotShown)
        }
    }
}

/// With the lock held, a daemon of another generation at the endpoint is a successor, and
/// anything else shows no end.
fn a_successor_by_the_endpoint(round: &Round, at_bound: bool, why: Why) -> Option<End> {
    match round.look {
        Some(Endpoint::Another) => Some(End::Successor(round.successor)),
        Some(Endpoint::Nobody | Endpoint::Same(_) | Endpoint::Unproved(_) | Endpoint::Unclear)
        | None => bound_shows(round, at_bound, why),
    }
}

/// What a round that shows no end shows at the bound, and nothing before it: `why` from the lock
/// and the process, except where the look showed the daemon of the generation asked answering.
fn bound_shows(round: &Round, at_bound: bool, why: Why) -> Option<End> {
    if !at_bound {
        return None;
    }
    Some(match round.look {
        Some(Endpoint::Same(answered)) => End::NotEnded(Why::Answers, Some(answered)),
        Some(Endpoint::Unproved(answered)) => End::NotEnded(why, Some(answered)),
        Some(Endpoint::Nobody | Endpoint::Another | Endpoint::Unclear) | None => {
            End::NotEnded(why, None)
        }
    })
}

/// Waits up to `bound` for the daemon that was asked to stop to end.
///
/// Where the daemon's process identity is known (`old`) it has ended only when that process has
/// gone and the environment's lock is free; a lock that is held then is a successor only where the
/// lock file names a live process named kr-controller that is not the old one, or a daemon of
/// another generation answers. Anything else that holds the lock for a moment, another command's
/// look among it, is waited through. Where no identity is known (always on Windows; where the
/// lock file cannot be read or names no process whose start can be read; or where no reply on the
/// connection that carried the request named the process that the lock file named: the answer was
/// an unknown outcome, or named another process), the daemon has ended when the lock is free and nothing
/// answers at its endpoint, or when a daemon of another generation answers, which is a successor
/// (the process that the lock file names, where it names one, is that successor's, and with the
/// lock held it is never taken for one on its own); the command cannot wait for the asked process
/// by its start identity. Where the system does not say whether the process runs, the wait is the
/// same with the lock free; with the lock held no look is made and no successor is shown, and at
/// the bound the lock is said to be still held.
///
/// Each wait is bounded by what is left of the one deadline when it starts, counted after the wait
/// before it: the install lock's wait, a look at the endpoint and the pause between two rounds. A
/// look that cannot be made leaves the daemon as not ended.
///
/// Each round reads the lock, the process, where it matters the process that the lock file names,
/// and, where [`look_wanted`] says so, the endpoint, and, where [`successor_wanted`] says so, the
/// process that the lock file names after it; [`what_the_round_shows`] says what that is.
pub(crate) async fn wait_for_the_end(
    operations: &impl Operations,
    old: Option<&ProcessStartIdentity>,
    bound: Duration,
) -> End {
    let deadline = tokio::time::Instant::now() + bound;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    loop {
        let lock = Lock::of(operations.held(left()).await);
        let process = Process::of(old.map(|old| operations.process_state(old)));
        let holder = if holder_wanted(&lock, process) {
            Holder::of(operations.named_daemon(), old)
        } else {
            Holder::NotRead
        };
        let look = if look_wanted(&lock, process, holder) {
            Some(operations.look(left(), &mut |_| {}).await)
        } else {
            None
        };
        let successor = if successor_wanted(look) {
            operations.named_daemon()
        } else {
            None
        };
        let round = Round {
            lock,
            process,
            holder,
            look,
            successor,
        };
        let at_bound = tokio::time::Instant::now() >= deadline;
        match what_the_round_shows(&round, at_bound) {
            Some(end) => return end,
            None => operations.pause(LOOK_EVERY.min(left())).await,
        }
    }
}

/// The evidence that a daemon answered.
mod answered {
    use kr_ipc::IpcError;
    use kr_ipc::error::ErrorSource;
    use kr_protocol::error::ProtocolError;
    use kr_protocol::ids::ControllerGeneration;

    /// What shows that a daemon answered: its answer to a look (the generation that it reported),
    /// or a reply of its own that cannot be used. The product builds one only from an answer's
    /// content, a `host.info` result or a reply error, which no code of this command makes up; the
    /// field is private to this module. The type does not hold that rule: `reporting`,
    /// `of_refusal` and `of_undecodable` take a generation, a refusal and a decode error, and
    /// product code can make each of these itself. The call sites, which pass only what a daemon
    /// sent, and their cases hold the rule; `for_a_case`, in test builds, is how a case makes one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Answered {
        /// The generation that the answering daemon reported; none for an unusable reply.
        generation: Option<ControllerGeneration>,
    }

    impl Answered {
        /// The answer of a look: the generation that the daemon's `host.info` reported.
        pub(super) const fn reporting(generation: ControllerGeneration) -> Self {
            Self {
                generation: Some(generation),
            }
        }

        /// An answer for a case, of a daemon that reported `generation`.
        #[cfg(test)]
        pub(crate) const fn for_a_case(generation: ControllerGeneration) -> Self {
            Self {
                generation: Some(generation),
            }
        }

        /// The daemon's own reply, where `error` is one (a refusal of the hello, a version that
        /// does not fit, a message of another kind). A closure, a frame that cannot be read and
        /// this side's own fault (the check of the peer's credentials among them) are no reply.
        /// Every source is an arm, so that a new source is a compile error here until it is decided.
        pub(super) fn of_reply(error: &IpcError) -> Option<Self> {
            match error.comes_from() {
                ErrorSource::Reply => Some(Self { generation: None }),
                ErrorSource::Closure | ErrorSource::OwnFault => None,
            }
        }

        /// The daemon's own refusal of a request, as the protocol carries it. The argument is
        /// that refusal, which is what makes the reply the daemon's.
        pub(super) const fn of_refusal(_refusal: &ProtocolError) -> Self {
            Self { generation: None }
        }

        /// The daemon's own result that does not decode. The argument is that decode error,
        /// which is what makes the reply the daemon's.
        pub(super) const fn of_undecodable(_error: &kr_cbor::CborError) -> Self {
            Self { generation: None }
        }
    }
}

pub(crate) use answered::Answered;

/// What answers at the environment's endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Endpoint {
    /// Nothing listens there.
    Nobody,
    /// A daemon answers and reports the generation that was asked: the same daemon, proved.
    Same(Answered),
    /// Something answers and no generation is proved: a reply of the daemon's own that cannot be
    /// used (a refusal of the greeting or of the read, a version that does not fit, a message of
    /// another kind, a result that does not decode), or an answer where the generation that was
    /// asked is not known. It shows that something answers at the endpoint, and neither that the
    /// daemon that was asked runs nor that it has ended.
    Unproved(Answered),
    /// A daemon of another generation answers.
    Another,
    /// Nothing came within the bound, or the look itself failed (its address could not be made, or
    /// the link failed): it shows neither that something answers nor that nothing does.
    Unclear,
}

/// What an answer at the endpoint is, by the generation that it reports and the one that was
/// asked, where the command knows it.
fn by_generation(asked: Option<ControllerGeneration>, reported: ControllerGeneration) -> Endpoint {
    match asked {
        Some(asked) if asked == reported => Endpoint::Same(Answered::reporting(reported)),
        Some(_) => Endpoint::Another,
        None => Endpoint::Unproved(Answered::reporting(reported)),
    }
}

/// What the exchange of a look gave: one value for each way it can end, from the address of the
/// endpoint to the answer of `host.info`. [`label_of`] takes each to what answers at the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gave {
    /// The address of the endpoint could not be made, so nothing was tried.
    NoAddress,
    /// Nothing came within the bound: the connection and the greeting did not finish, or `host.info`
    /// was not answered.
    NothingInTime,
    /// The connection found nothing listening.
    NothingListens,
    /// The link failed and no reply of the daemon's came with it: a peer that closed, a stream cut
    /// short, a frame that cannot be read, or this side's own fault (a check of the peer's
    /// credentials, a fault of this side's socket, a request that this side cannot encode).
    LinkFailed,
    /// The greeting was acknowledged, and then the link failed in the read of `host.info`: a peer
    /// that closed, a stream cut short, a frame that cannot be read, or this side's own fault. A
    /// usable greeting was given, and no reply of the daemon's came with the failure.
    GreetingThenLinkFailed,
    /// The daemon replied to the greeting with something that cannot be used: a refusal of the hello,
    /// a version that does not fit, or a message that is not the acknowledgement.
    GreetingReplied(Answered),
    /// A daemon that states another major than this command's answered the greeting.
    GreetingOfAnotherMajor,
    /// The daemon answered `host.info` and reported this generation.
    Reported(ControllerGeneration),
    /// The daemon refused the read of `host.info`.
    ReadRefused(Answered),
    /// The result of `host.info` does not decode.
    ReadUndecodable(Answered),
    /// The daemon replied to the read with something that is not its answer: a message of another
    /// kind, or a refusal of the link.
    ReadReplied(Answered),
}

/// What an exchange that gave `gave` shows at the endpoint, where the generation of the daemon
/// that was asked is `asked`, if the command knows it. Every way that an exchange ends is an arm,
/// with no catch-all, so that a new way is a compile error here until it is labelled. An answer
/// that came within the bound and proves no generation is unproved, whatever its kind; nothing
/// is unclear but an exchange where nothing came within the bound or the look itself failed.
fn label_of(asked: Option<ControllerGeneration>, gave: Gave) -> Endpoint {
    match gave {
        Gave::NothingListens => Endpoint::Nobody,
        Gave::Reported(reported) => by_generation(asked, reported),
        Gave::GreetingReplied(answered) => Endpoint::Unproved(answered),
        Gave::ReadRefused(answered) => Endpoint::Unproved(answered),
        Gave::ReadUndecodable(answered) => Endpoint::Unproved(answered),
        Gave::ReadReplied(answered) => Endpoint::Unproved(answered),
        Gave::GreetingOfAnotherMajor => Endpoint::Another,
        Gave::NoAddress => Endpoint::Unclear,
        Gave::NothingInTime => Endpoint::Unclear,
        Gave::LinkFailed => Endpoint::Unclear,
        Gave::GreetingThenLinkFailed => Endpoint::Unclear,
    }
}

/// What a look at the endpoint saw as it went, told to whoever asked for the look, so that a
/// time-out or a failure that comes later cannot discard what was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sight {
    /// The look began: until it shows more, nothing came.
    Began,
    /// The greeting was acknowledged: a usable greeting.
    Greeted,
    /// The exchange ended and gave this.
    Gave(Gave),
}

/// What the failure of the connection or of the greeting gave.
pub(crate) fn gave_by_the_greeting(error: &kr_ipc::IpcError) -> Gave {
    if startup::nothing_listening(error) {
        return Gave::NothingListens;
    }
    match Answered::of_reply(error) {
        Some(answered) => Gave::GreetingReplied(answered),
        None => Gave::LinkFailed,
    }
}

/// What the read of `host.info` gave.
pub(crate) fn gave_by_the_read(
    read: kr_ipc::Result<std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError>>,
) -> Gave {
    match read {
        Ok(Ok(value)) => match value.to_typed::<HostInfoResult>() {
            Ok(info) => Gave::Reported(info.generation),
            Err(error) => Gave::ReadUndecodable(Answered::of_undecodable(&error)),
        },
        Ok(Err(refusal)) => Gave::ReadRefused(Answered::of_refusal(&refusal)),
        Err(error) => match Answered::of_reply(&error) {
            Some(answered) => Gave::ReadReplied(answered),
            None => Gave::GreetingThenLinkFailed,
        },
    }
}

/// What a daemon that answered the greeting gives: a daemon that states another major is another
/// daemon, whatever it would say to a read, and one that states this command's major is asked
/// `host.info`. A look offers no other major, so the first never answers a look over a real link.
async fn gave_after_the_greeting(listed: Listed, seen: &mut dyn FnMut(Sight)) -> Gave {
    match listed {
        Listed::Other(_) => Gave::GreetingOfAnotherMajor,
        Listed::Ours(mut client) => {
            seen(Sight::Greeted);
            gave_by_the_read(client.request(Method::HostInfo, &()).await)
        }
    }
}

/// The connection, the greeting and the read of `host.info`, as the exchange of a look.
async fn the_exchange(
    endpoint: &kr_ipc::paths::Endpoint,
    within: Duration,
    seen: &mut dyn FnMut(Sight),
) -> Gave {
    match startup::reach(endpoint, within, &[]).await {
        Reached::Silent => Gave::NothingInTime,
        Reached::Refused(error) => gave_by_the_greeting(&error),
        Reached::Answered(listed) => gave_after_the_greeting(*listed, seen).await,
    }
}

/// What the exchange of a look at the environment's endpoint gave, bounded as a whole by `within`
/// and by one second: the address, then the connection, the hello and `host.info` together. What
/// it saw is told to `seen` as it goes, the greeting before the read that follows it.
async fn the_look_gave(
    environment: &EnvironmentPaths,
    within: Duration,
    seen: &mut dyn FnMut(Sight),
) -> Gave {
    seen(Sight::Began);
    let gave = match environment.controller_endpoint().ok() {
        Some(endpoint) => {
            let within = within.min(LOOK_EVERY * 20);
            tokio::time::timeout(within, the_exchange(&endpoint, within, &mut *seen))
                .await
                .unwrap_or(Gave::NothingInTime)
        }
        None => Gave::NoAddress,
    };
    seen(Sight::Gave(gave));
    gave
}

/// Looks at the environment's endpoint and says what answers there: what the exchange gave,
/// labelled by [`label_of`].
async fn endpoint_look(
    environment: &EnvironmentPaths,
    generation: Option<ControllerGeneration>,
    within: Duration,
    seen: &mut dyn FnMut(Sight),
) -> Endpoint {
    label_of(generation, the_look_gave(environment, within, seen).await)
}

/// What a failed look at the lock says, in this command's words. The store's start lock, which
/// stayed held to the look's bound, is said as that: the update commands' sentence for it names a
/// daemon that is starting, another command to run and a count of seconds, none of which this
/// command knows. Every other failure of the look keeps its own words: the install lock could not
/// be tried, the environment's lock could not be taken (outside a store, the same failure of the
/// lock).
fn look_failed(store: &std::path::Path, error: &CliError) -> Shown {
    match error {
        CliError::UpdateDeferred(_) => shown!(
            "the start lock of the store at {} was held when the command looked",
            Shown::root(store)
        ),
        other => kr_client::shown::Said::said(other),
    }
}

/// How the environment's lock is looked at: under the store's install lock for a release of a
/// store, whose daemons hold it, shared, while they start, and by the lock itself elsewhere.
struct Installation {
    environment: crate::update::inventory::Environment,
    store: Option<kr_ipc::install::Store>,
}

impl Installation {
    fn of(host: &HostPaths, environment: &EnvironmentPaths) -> Self {
        let store = kr_ipc::install::this_process()
            .ok()
            .and_then(|running| running.store().cloned());
        Self {
            environment: crate::update::inventory::Environment {
                environment_id: environment.environment_id(),
                paths: environment.clone(),
                host: host.clone(),
            },
            store,
        }
    }

    /// Whether a daemon holds the environment, waiting up to `within` for one that is starting.
    async fn held(&self, within: Duration) -> std::result::Result<bool, Shown> {
        match &self.store {
            Some(store) => handover::held(store, &self.environment, within)
                .await
                .map_err(|error| look_failed(store.root(), &error)),
            None => lock_held(&self.environment.paths),
        }
    }
}

/// What the wait for a daemon's end and the look before it read of the machine and wait on, given
/// to them so that a case can supply each answer and the pause, with the runtime's clock in its
/// own hands. [`Real`] is the command's own.
pub(crate) trait Operations {
    /// Whether a daemon holds the environment, waiting up to `within` for one that is starting.
    async fn held(&self, within: Duration) -> std::result::Result<bool, Shown>;
    /// What the system says of the process of the daemon that was asked.
    fn process_state(&self, old: &ProcessStartIdentity) -> ProcessState;
    /// What answers at the environment's endpoint, bounded by `within`; what the look saw is told to
    /// `seen` as it goes.
    async fn look(&self, within: Duration, seen: &mut dyn FnMut(Sight)) -> Endpoint;
    /// The process the lock file names as a control daemon, where it names one.
    fn named_daemon(&self) -> Option<u64>;
    /// Waits `time` between two rounds of looks.
    async fn pause(&self, time: Duration);
}

/// The operations on this machine: its locks, its processes, its endpoint and its timer.
pub(crate) struct Real<'a> {
    installation: Installation,
    environment: &'a EnvironmentPaths,
    /// The generation of the daemon that was asked, where the command has read it: a command
    /// whose connection failed before `host.info` was read does not know it, and a daemon that
    /// answers then cannot be told from a successor by its generation.
    generation: Option<ControllerGeneration>,
}

impl<'a> Real<'a> {
    pub(crate) fn of(
        host: &HostPaths,
        environment: &'a EnvironmentPaths,
        generation: Option<ControllerGeneration>,
    ) -> Self {
        Self {
            installation: Installation::of(host, environment),
            environment,
            generation,
        }
    }
}

impl Operations for Real<'_> {
    async fn held(&self, within: Duration) -> std::result::Result<bool, Shown> {
        self.installation.held(within).await
    }

    fn process_state(&self, old: &ProcessStartIdentity) -> ProcessState {
        identity::process_state(old)
    }

    async fn look(&self, within: Duration, seen: &mut dyn FnMut(Sight)) -> Endpoint {
        endpoint_look(self.environment, self.generation, within, seen).await
    }

    fn named_daemon(&self) -> Option<u64> {
        named_daemon(self.environment)
    }

    async fn pause(&self, time: Duration) {
        tokio::time::sleep(time).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal that is `PERMISSION_DENIED` is told from a request the daemon does not list by the
    /// probe, except where this program is a release of a store and the daemon is of that very
    /// release, which lists it; any other refusal is the daemon's own.
    #[test]
    fn a_refusal_is_the_daemons_own_only_where_the_probe_has_nothing_to_tell() {
        let own = Some("kr-controller/0.78.0+aaaaaaaaaaaa");
        let same = "kr-controller/0.78.0+aaaaaaaaaaaa";
        let earlier = "kr-controller/0.77.0+bbbbbbbbbbbb";
        assert!(is_the_daemons_own_refusal(
            own,
            same,
            ErrorCode::PermissionDenied
        ));
        assert!(!is_the_daemons_own_refusal(
            own,
            earlier,
            ErrorCode::PermissionDenied
        ));
        // Outside a store the build name tells nothing, so the probe decides.
        assert!(!is_the_daemons_own_refusal(
            None,
            same,
            ErrorCode::PermissionDenied
        ));
        assert!(is_the_daemons_own_refusal(
            None,
            same,
            ErrorCode::InvalidArgument
        ));
    }

    /// The wait for the daemon's end gives up at its bound with the daemon not ended where a
    /// process the lock names runs and holds it, and sees the end where neither does. The bound is
    /// passed in, so no case waits for the real thirty seconds.
    #[tokio::test]
    async fn the_wait_for_the_end_gives_up_at_its_bound_and_sees_the_end() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let host = HostPaths::new(environment.runtime_root(), environment.state_root())
            .expect("the roots of the environment");
        let own = identity::current_process_start_identity().expect("an identity");
        let held = SingletonLock::hold(&environment.singleton_lock(), environment.environment_id())
            .expect("takes the lock");
        let generation = ControllerGeneration::new(1);
        let waited = tokio::time::timeout(
            Duration::from_secs(60),
            wait_for_the_end(
                &Real::of(&host, &environment, Some(generation)),
                Some(&own),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("the wait ends at its bound");
        assert!(
            matches!(waited, End::NotEnded(Why::Running, _)),
            "a live holder is not an end"
        );
        drop(held);
        let ended = identity::ended_process_identity(std::process::id());
        let waited = wait_for_the_end(
            &Real::of(&host, &environment, Some(generation)),
            Some(&ended),
            Duration::from_secs(60),
        )
        .await;
        assert!(
            matches!(waited, End::Gone),
            "no holder and a process that has gone is the end"
        );
    }
    /// The paths of a temporary host's environment, with the host's own.
    fn paths_of(temp: &kr_ipc::testing::TempHost) -> (HostPaths, EnvironmentPaths) {
        let environment = temp.environment();
        let host = HostPaths::new(environment.runtime_root(), environment.state_root())
            .expect("the roots of the environment");
        (host, environment)
    }

    /// A lock that another command's look holds for a moment, with the old process gone, is waited
    /// through to the end and is no successor; where nothing proves one, a lock that stays held
    /// leaves the environment held, and says so, not that the daemon has not ended.
    #[tokio::test]
    async fn a_lock_that_another_look_holds_for_a_moment_is_waited_through() {
        let temp = kr_ipc::testing::TempHost::create();
        let (host, environment) = paths_of(&temp);
        let generation = ControllerGeneration::new(1);
        let ended = identity::ended_process_identity(std::process::id());
        let held = SingletonLock::hold(&environment.singleton_lock(), environment.environment_id())
            .expect("takes the lock");
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        let waited = tokio::time::timeout(
            Duration::from_secs(60),
            wait_for_the_end(
                &Real::of(&host, &environment, Some(generation)),
                Some(&ended),
                Duration::from_secs(30),
            ),
        )
        .await
        .expect("the wait ends");
        release.join().expect("the look's hold ends");
        assert!(
            matches!(waited, End::Gone),
            "a moment's hold is no successor"
        );

        let held = SingletonLock::hold(&environment.singleton_lock(), environment.environment_id())
            .expect("takes the lock again");
        let waited = wait_for_the_end(
            &Real::of(&host, &environment, Some(generation)),
            Some(&ended),
            Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(waited, End::NotEnded(Why::Held, _)),
            "a lock that stays held with nothing to show for it is not a successor"
        );
        drop(held);
    }

    /// With no process identity known, the daemon has ended when the lock is free and nothing
    /// answers at its endpoint, and not before: a free lock and a listener, or a held lock and no
    /// proof of a successor, are not an end.
    #[tokio::test]
    async fn with_no_process_identity_the_end_is_a_free_lock_and_an_endpoint_nobody_answers() {
        let temp = kr_ipc::testing::TempHost::create();
        let (host, environment) = paths_of(&temp);
        let generation = ControllerGeneration::new(1);
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let waited = wait_for_the_end(
            &Real::of(&host, &environment, Some(generation)),
            None,
            Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(waited, End::NotEnded(Why::NotShown, _)),
            "a free lock and a listener that does not answer is not an end, and no sign of life"
        );
        drop(listener);

        let held = SingletonLock::hold(&environment.singleton_lock(), environment.environment_id())
            .expect("takes the lock");
        let waited = wait_for_the_end(
            &Real::of(&host, &environment, Some(generation)),
            None,
            Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(waited, End::NotEnded(Why::HeldNotShown, _)),
            "a held lock with nothing to show for a successor is not an end, and shows no daemon"
        );
        drop(held);

        let waited = wait_for_the_end(
            &Real::of(&host, &environment, Some(generation)),
            None,
            Duration::from_secs(30),
        )
        .await;
        assert!(
            matches!(waited, End::Gone),
            "a free lock and nobody at the endpoint is the end"
        );
    }

    /// The words of a daemon that has not ended where the answer to the stop named none name a
    /// process only as the lock file names it when the words are made, after the last look at the
    /// endpoint, and only where that process runs the daemon: the read starts nothing and stops
    /// nothing. A lock file that names a process that has gone gives the form with no number.
    #[cfg(unix)]
    #[test]
    fn the_words_of_a_daemon_that_has_not_ended_name_no_number_for_a_lock_file_that_names_a_dead_process()
     {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let lock = environment.singleton_lock();
        std::fs::create_dir_all(lock.parent().expect("a state directory")).expect("a directory");
        let mut ended = std::process::Command::new("true")
            .spawn()
            .expect("starts a process");
        ended.wait().expect("collects it");
        std::fs::write(&lock, format!("{}\n", ended.id())).expect("names a process that has gone");
        let what = Shown::said("did not show whether it took the stop (x), and it has not ended");
        let said = not_ended(Which::Stop, &environment, id, &what, None).to_string();
        assert!(
            said.contains(
                "If it stays, end the process that holds the lock file; the next daemon recovers as it does after a crash."
            ),
            "{said}"
        );
        assert!(!said.contains(&ended.id().to_string()), "{said}");
    }

    /// The same for a lock file that names a live process that is no control daemon: it is not
    /// named, however it came to be in the lock file.
    #[cfg(unix)]
    #[test]
    fn the_words_of_a_daemon_that_has_not_ended_name_no_number_for_a_lock_file_that_names_no_control_daemon()
     {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let lock = environment.singleton_lock();
        std::fs::create_dir_all(lock.parent().expect("a state directory")).expect("a directory");
        // This test program is a live process, and its program is not a control daemon's.
        let own = std::process::id();
        std::fs::write(&lock, format!("{own}\n")).expect("names a live process");
        let what = Shown::said("did not show whether it took the stop (x), and it has not ended");
        let said = not_ended(Which::Stop, &environment, id, &what, None).to_string();
        assert!(
            said.contains(
                "If it stays, end the process that holds the lock file; the next daemon recovers as it does after a crash."
            ),
            "{said}"
        );
        assert!(!said.contains(&own.to_string()), "{said}");
    }

    /// The words of a daemon that was told and has not ended, and of an environment that is held after
    /// the daemon's process has gone, name no process they cannot show and promise no wait.
    #[test]
    fn the_words_of_a_daemon_that_has_not_ended_name_no_process_and_promise_no_wait() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let what = Shown::said("was told to stop and has not ended");
        let said = not_ended(Which::Stop, &environment, id, &what, None).to_string();
        assert!(
            said.contains(
                "was told to stop and has not ended after 30 seconds. It may be finishing a write."
            ),
            "{said}"
        );
        assert!(
            said.contains("the next daemon recovers as it does after a crash."),
            "{said}"
        );
        assert!(
            !said.contains("kill -KILL") && !said.contains("taskkill"),
            "{said}"
        );
        assert!(!said.contains("wait again"), "{said}");
        let held = still_held(Which::Stop, &environment, id).to_string();
        assert!(
            held.contains(
                "has gone, and something that is not shown to be a control daemon still holds the environment after 30 seconds"
            ),
            "{held}"
        );
        assert!(!held.contains("ended"), "{held}");
        assert!(
            held.contains("Run kr host stop again in a moment."),
            "{held}"
        );
    }

    /// The records of earlier attempts are removed only where they were put out: a record that was
    /// not said stands.
    #[test]
    fn earlier_records_are_removed_only_where_they_were_put_out() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let directory = environment.state_dir().join(attempt::DIRECTORY);
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        let record = attempt::Attempt {
            command: attempt::Command::Stop,
            phase: attempt::Phase::Told,
            process: identity::ended_process_identity(std::process::id()),
            at_ms: 1,
            daemon: None,
        };
        kr_ipc::paths::write_owner_only_file(
            &directory.join("an-earlier-attempt"),
            &serde_json::to_vec(&record).expect("encodes"),
        )
        .expect("writes the record");
        let mut earlier = Earlier::read(&environment);
        assert_eq!(earlier.records.len(), 1);
        earlier.remove_those_put_out(false);
        assert_eq!(
            attempt::recorded(&environment).len(),
            1,
            "not said, so it stands"
        );
        earlier.written = true;
        earlier.remove_those_put_out(false);
        assert!(
            attempt::recorded(&environment).is_empty(),
            "said, so it goes"
        );
    }
    /// A stop ignores a hangup at every stage after the request was written, and not before it.
    #[test]
    fn a_stop_ignores_a_hangup_only_once_its_request_was_written() {
        for (stage, ignored) in [
            (Stage::BeforeAsking, false),
            (Stage::Asked, true),
            (Stage::Told, true),
            (Stage::Refused, true),
        ] {
            assert_eq!(hangup_ignored_by_a_stop(stage), ignored, "{stage:?}");
        }
    }

    /// The command's start reads the records of earlier attempts into the result and into the
    /// progress that an interrupt reads, and says them at once only where the output is text: under
    /// `--json` they go in the document.
    #[tokio::test]
    async fn the_start_reads_the_earlier_records_and_says_them_only_in_text() {
        for json in [false, true] {
            let temp = kr_ipc::testing::TempHost::create();
            let paths = temp.environment();
            let id = paths.environment_id();
            let directory = paths.state_dir().join(attempt::DIRECTORY);
            kr_ipc::paths::create_private_directory(&directory).expect("the directory");
            let record = attempt::Attempt {
                command: attempt::Command::Stop,
                phase: attempt::Phase::Told,
                process: identity::ended_process_identity(std::process::id()),
                at_ms: 1,
                daemon: None,
            };
            kr_ipc::paths::write_owner_only_file(
                &directory.join("an-earlier-attempt"),
                &serde_json::to_vec(&record).expect("encodes"),
            )
            .expect("writes the record");
            let environment = KnownEnvironment {
                environment_id: id,
                paths,
            };
            let progress = Progress {
                stage: AtomicU8::new(Stage::BeforeAsking as u8),
                marker: Mutex::new(None),
                environment_id: id,
                earlier: Mutex::new(Vec::new()),
            };
            let Ok(begun) = begin(Which::Stop, &environment, json, &progress).await else {
                panic!("outside a session the guard lets the command begin");
            };
            assert_eq!(begun.none.records.len(), 1);
            assert_eq!(progress.said_earlier().len(), 1);
            assert_eq!(begun.earlier.written, !json, "json {json}");
        }
    }

    /// What a stand-in daemon does with the connection that `ask_and_wait` is given.
    #[derive(Clone, Copy)]
    enum StandIn {
        /// It takes the stop and answers, and ends once the command has let go of the connection.
        TakesTheStop,
        /// It refuses the request, and the check that follows it, and ends with the connection.
        RefusesTheStop,
        /// It closes the connection after its hello, so that no request can be composed, and ends.
        ClosesAndEnds,
    }

    /// The attempts that the records of an environment hold.
    fn attempts_of(environment: &EnvironmentPaths) -> Vec<attempt::Attempt> {
        attempt::recorded(environment)
            .into_iter()
            .map(|recorded| recorded.attempt)
            .collect()
    }

    /// What `ask_and_wait` gave on a real connection, and the attempts that the stand-in daemon
    /// found where the request reached it, where the next request that the command made on the
    /// connection reached it (`None` where there was none), and where the command let go of the
    /// connection.
    struct Observed {
        environment: KnownEnvironment,
        progress: Progress,
        result: std::result::Result<Settled, Cut>,
        at_the_request: Vec<attempt::Attempt>,
        at_the_next_request: Option<Vec<attempt::Attempt>>,
        at_the_close: Vec<attempt::Attempt>,
        _temp: kr_ipc::testing::TempHost,
    }

    /// A progress for a case, at the first stage with nothing recorded.
    fn progress_of(id: EnvironmentId) -> Progress {
        Progress {
            stage: AtomicU8::new(Stage::BeforeAsking as u8),
            marker: Mutex::new(None),
            environment_id: id,
            earlier: Mutex::new(Vec::new()),
        }
    }

    /// Runs `ask_and_wait` against a stand-in daemon that does `standing`, from the real client on a
    /// real link.
    async fn ask_and_wait_against(standing: StandIn) -> Observed {
        use kr_ipc::client::LocalClient;
        use kr_protocol::local::LocalClientKind;
        use kr_protocol::scalars::{Nullable, U64};

        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let host = HostPaths::new(paths.runtime_root(), paths.state_root())
            .expect("the roots of the environment");
        let endpoint = paths.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let seen = temp.environment();
        let daemon = tokio::spawn(async move {
            let (mut reader, mut writer) = greet(&listener, id).await;
            if matches!(standing, StandIn::ClosesAndEnds) {
                return (Vec::new(), None, Vec::new());
            }
            let ControlFrame::Mutation(request) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("the read request")
            else {
                panic!("the command writes a mutation");
            };
            let at_the_request = attempts_of(&seen);
            let outcome = if matches!(standing, StandIn::TakesTheStop) {
                Outcome::Ok(
                    kr_protocol::envelope::ParamsValue::from_typed(&HostStopResult {
                        pid: U64::new(4242),
                        unsettled: U64::new(2),
                        launch: Nullable::null(),
                    })
                    .expect("a stop result"),
                )
            } else {
                refused(false)
            };
            write_outcome(&mut writer, request.request_id, outcome).await;
            // Whatever else the command writes here is refused too, and the first of it finds the
            // records as the command left them before it wrote it. The loop ends where the
            // command lets go of the connection, and the daemon ends with the listener after it.
            let mut at_the_next_request = None;
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                let next = match frame {
                    ControlFrame::Mutation(next) => next.request_id,
                    ControlFrame::Request(next) => next.request_id,
                    _ => continue,
                };
                at_the_next_request.get_or_insert_with(|| attempts_of(&seen));
                write_outcome(&mut writer, next, refused(false)).await;
            }
            let at_the_close = attempts_of(&seen);
            drop(listener);
            (at_the_request, at_the_next_request, at_the_close)
        });
        let client = LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id())
            .await
            .expect("connects");
        let mut daemon = Some(daemon);
        if matches!(standing, StandIn::ClosesAndEnds) {
            // The connection and the listener are closed before the command writes anything.
            daemon
                .take()
                .expect("spawned")
                .await
                .expect("the daemon has closed the connection");
        }
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let progress = progress_of(id);
        let info = host_info_of(ControllerGeneration::new(1));
        let none = Facts::none(Vec::new());
        let result = ask_and_wait(
            Which::Stop,
            &host,
            &environment,
            client,
            &info,
            lock_holder(&environment.paths),
            None,
            true,
            &progress,
            &none,
        )
        .await;
        let (at_the_request, at_the_next_request, at_the_close) = match daemon {
            Some(daemon) => daemon.await.expect("the daemon saw the command's request"),
            None => (Vec::new(), None, Vec::new()),
        };
        Observed {
            environment,
            progress,
            result,
            at_the_request,
            at_the_next_request,
            at_the_close,
            _temp: temp,
        }
    }

    /// A stop that the daemon takes is recorded as asking where the request reaches the daemon and
    /// as told before the command lets go of the connection, and the command lets go of it before
    /// the wait for the daemon's end can end: the daemon ends only when it sees that. What the
    /// command settled is what the daemon answered, and the record stays until the stop is said.
    #[tokio::test]
    async fn a_stop_the_daemon_takes_is_recorded_asking_then_told_and_the_connection_goes_before_the_end()
     {
        let observed = ask_and_wait_against(StandIn::TakesTheStop).await;
        let Ok(settled) = observed.result else {
            panic!("a daemon that takes the stop and ends settles it");
        };
        assert!(matches!(settled.request, Request::Told));
        assert_eq!(settled.pid, Some(4242));
        assert_eq!(settled.unsettled, Some(2));
        assert!(
            matches!(settled.ended, End::Gone),
            "the daemon ended once the connection was let go: {:?}",
            settled.ended
        );
        assert!(settled.old.is_none());
        for (when, attempts, phase) in [
            (
                "where the request arrived",
                &observed.at_the_request,
                attempt::Phase::Asking,
            ),
            (
                "where the connection was let go",
                &observed.at_the_close,
                attempt::Phase::Told,
            ),
            (
                "where the wait ended",
                &attempts_of(&observed.environment.paths),
                attempt::Phase::Told,
            ),
        ] {
            assert_eq!(attempts.len(), 1, "one record {when}");
            assert_eq!(attempts[0].command, attempt::Command::Stop, "{when}");
            assert_eq!(attempts[0].phase, phase, "{when}");
        }
        assert_eq!(observed.progress.stage(), Stage::Told);
    }

    /// A stop that the daemon refuses is recorded as asking where the request arrives, and the
    /// record is removed before anything more is asked of the daemon, where the check of the
    /// refusal reaches it: the command is at the stage that says it was refused, and nothing was
    /// told.
    #[tokio::test]
    async fn a_refused_stop_removes_its_record_before_the_check_and_stays_at_the_refused_stage() {
        let observed = ask_and_wait_against(StandIn::RefusesTheStop).await;
        assert!(matches!(observed.result, Err(Cut::Said(_))));
        assert_eq!(observed.at_the_request.len(), 1);
        assert_eq!(observed.at_the_request[0].phase, attempt::Phase::Asking);
        let Some(at_the_check) = &observed.at_the_next_request else {
            panic!("the command made the check of the refusal on the connection");
        };
        assert!(
            at_the_check.is_empty(),
            "the record was removed before the check reached the daemon: {at_the_check:?}"
        );
        assert!(
            observed.at_the_close.is_empty(),
            "the record was removed before the check on the connection: {:?}",
            observed.at_the_close
        );
        assert!(attempts_of(&observed.environment.paths).is_empty());
        assert_eq!(observed.progress.stage(), Stage::Refused);
    }

    /// A request that cannot be composed leaves no record, and the command is back at the first
    /// stage: nothing was asked, and its end is decided as for any failure before the request.
    #[tokio::test]
    async fn a_request_that_cannot_be_composed_leaves_no_record_and_the_first_stage() {
        let observed = ask_and_wait_against(StandIn::ClosesAndEnds).await;
        let Err(Cut::Unmade { before, error }) = observed.result else {
            panic!("a request on a closed connection is not made");
        };
        assert!(closed_by_the_daemon(&error), "{error}");
        assert!(
            matches!(before, Before::Ended { .. }),
            "the daemon ended with its connection"
        );
        assert!(attempts_of(&observed.environment.paths).is_empty());
        assert_eq!(observed.progress.stage(), Stage::BeforeAsking);
    }

    /// The stop is said with the record of the attempt removed where the end is shown, and kept
    /// where it is not: a daemon that has not ended may still be stopping.
    #[test]
    fn a_settled_stop_is_said_with_its_record_removed_only_where_the_end_is_shown() {
        for (ended, shown) in [
            (End::Gone, true),
            (End::Successor(Some(4343)), true),
            (End::NotEnded(Why::Running, None), false),
        ] {
            let temp = kr_ipc::testing::TempHost::create();
            let paths = temp.environment();
            let environment = KnownEnvironment {
                environment_id: paths.environment_id(),
                paths,
            };
            let progress = progress_of(environment.environment_id);
            let marker = Marker::begin(&environment.paths, attempt::Command::Stop, None)
                .expect("the record");
            *progress
                .marker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);
            let _ = progress.with_marker(|marker| marker.told());
            let settled = Settled {
                request: Request::Told,
                ended: ended.clone(),
                pid: Some(4242),
                unsettled: Some(0),
                old: None,
            };
            let completion = say_the_stop(
                Which::Stop,
                settled,
                &environment,
                &Facts::none(Vec::new()),
                true,
                &progress,
                &Earlier::read(&environment.paths),
            );
            assert_eq!(
                matches!(completion, Completion::Done),
                shown,
                "{ended:?} ends the command as a success only where the daemon ended"
            );
            assert_eq!(
                attempts_of(&environment.paths).len(),
                usize::from(!shown),
                "{ended:?}"
            );
        }
    }

    /// What a record of an earlier attempt says, for each command and phase that a record can hold,
    /// and for one whose process is still running: the stop's words stay as they are, and a
    /// restart's say its own command and its two phases.
    #[test]
    fn a_record_of_an_earlier_attempt_says_its_command_and_phase_in_whole() {
        let at = crate::shown::utc_moment(1);
        let pid = std::process::id();
        for (command, phase, name, tail) in [
            (
                attempt::Command::Stop,
                attempt::Phase::Asking,
                "kr host stop",
                "it was asking the control daemon for environment {id} to stop. What happened after that is not recorded.",
            ),
            (
                attempt::Command::Stop,
                attempt::Phase::Told,
                "kr host stop",
                "the control daemon for environment {id} had been told to stop. What happened after that is not recorded.",
            ),
            (
                attempt::Command::Restart,
                attempt::Phase::Asking,
                "kr host restart",
                "it was asking the control daemon for environment {id} to stop. What happened after that is not recorded.",
            ),
            (
                attempt::Command::Restart,
                attempt::Phase::Told,
                "kr host restart",
                "the control daemon for environment {id} had been told to stop. What happened after that is not recorded.",
            ),
            (
                attempt::Command::Restart,
                attempt::Phase::Starting,
                "kr host restart",
                "it was asking for a new control daemon for environment {id}. What happened after that is not recorded.",
            ),
            (
                attempt::Command::Restart,
                attempt::Phase::StartFailed,
                "kr host restart",
                "its start of a control daemon for environment {id} had failed. Run kr host restart to try again.",
            ),
        ] {
            let temp = kr_ipc::testing::TempHost::create();
            let environment = temp.environment();
            let id = environment.environment_id();
            let directory = environment.state_dir().join(attempt::DIRECTORY);
            kr_ipc::paths::create_private_directory(&directory).expect("the directory");
            let record = attempt::Attempt {
                command,
                phase,
                process: identity::ended_process_identity(pid),
                at_ms: 1,
                daemon: None,
            };
            kr_ipc::paths::write_owner_only_file(
                &directory.join("an-earlier-attempt"),
                &serde_json::to_vec(&record).expect("encodes"),
            )
            .expect("writes the record");
            let tail = tail.replace("{id}", &id.to_string());
            assert_eq!(
                records_said(&environment).to_string(),
                format!(" The last record of a {name} (process {pid}) is at {at}: {tail}"),
            );
        }
        // The process that wrote the record lives, and is not this one.
        #[cfg(unix)]
        let mut other = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("a live process");
        #[cfg(unix)]
        let (pid, other_identity) = (
            other.id(),
            identity::process_start_identity(other.id()).expect("an identity"),
        );
        #[cfg(unix)]
        for (command, name) in [
            (attempt::Command::Stop, "kr host stop"),
            (attempt::Command::Restart, "kr host restart"),
        ] {
            let temp = kr_ipc::testing::TempHost::create();
            let environment = temp.environment();
            let id = environment.environment_id();
            let directory = environment.state_dir().join(attempt::DIRECTORY);
            kr_ipc::paths::create_private_directory(&directory).expect("the directory");
            let record = attempt::Attempt {
                command,
                phase: attempt::Phase::Told,
                process: other_identity.clone(),
                at_ms: 1,
                daemon: None,
            };
            kr_ipc::paths::write_owner_only_file(
                &directory.join("an-attempt-under-way"),
                &serde_json::to_vec(&record).expect("encodes"),
            )
            .expect("writes the record");
            assert_eq!(
                records_said(&environment).to_string(),
                format!(
                    " A {name} is under way for environment {id} (process {pid}, last recorded at {at}); wait for it."
                ),
            );
        }
        #[cfg(unix)]
        {
            let _ = other.kill();
            let _ = other.wait();
        }
    }

    /// What the restart reports and exits with, in whole, for a result that is a failure.
    fn reported_in_whole(completion: Completion) -> (u8, String) {
        use kr_client::shown::Said as _;

        match completion {
            Completion::Reported(error) => (error.exit_code(), error.said().to_string()),
            _ => panic!("a failure that the restart has reported"),
        }
    }

    /// An environment for a case that reads no daemon.
    fn an_environment_for_the_whole_texts() -> (kr_ipc::testing::TempHost, KnownEnvironment) {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let environment = KnownEnvironment {
            environment_id: paths.environment_id(),
            paths,
        };
        (temp, environment)
    }

    /// What the restart says and exits with where its first reach of the endpoint shows `start`
    /// and the lock reads as `lock`.
    fn the_restart_at_the_start(start: &Start, lock: Lock) -> (KnownEnvironment, u8, String) {
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let (code, said) = reported_in_whole(say_at_the_start(
            Which::Restart,
            said_at_the_start(start, || lock),
            &environment,
            &Facts::none(Vec::new()),
            true,
            &Earlier::read(&environment.paths),
            startup::ANSWER_BOUND,
        ));
        (environment, code, said)
    }

    /// The restart's sentence for a daemon that states another public major.
    #[test]
    fn the_restart_says_in_whole_that_the_daemon_states_another_major() {
        let (environment, code, said) = the_restart_at_the_start(&Start::OtherMajor, Lock::Free);
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "the control daemon for environment {} states another public major than this command does. No stop was requested and no start was made.",
                environment.environment_id
            )
        );
    }

    /// The restart's sentence for a lock that could not be read where nothing listens.
    #[test]
    fn the_restart_says_in_whole_that_the_lock_could_not_be_read() {
        let (environment, code, said) = the_restart_at_the_start(
            &Start::NothingListening,
            Lock::Unreadable(Shown::said("the lock file could not be opened")),
        );
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "whether a control daemon holds environment {} could not be read: the lock file could not be opened. No stop was requested and no start was made.",
                environment.environment_id
            )
        );
    }

    /// The restart's sentence for a daemon that accepts the connection and does not answer.
    #[test]
    fn the_restart_says_in_whole_that_the_daemon_accepted_the_connection_and_did_not_answer() {
        let (environment, code, said) = the_restart_at_the_start(&Start::Silent, Lock::Free);
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "the control daemon listening for environment {} accepted the connection and did not answer within 10 seconds. No stop was requested and no start was made. Run kr host restart again in a moment.",
                environment.environment_id
            )
        );
    }

    /// The restart's sentence for a daemon that cannot be reached for a reason other than nothing
    /// listening.
    #[test]
    fn the_restart_says_in_whole_that_the_daemon_could_not_be_reached() {
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let id = environment.environment_id;
        let error = kr_ipc::IpcError::socket(
            "connect",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        let (code, said) = {
            use kr_client::shown::Said as _;
            let failure = unreached(Which::Restart, id, &error, Unmade::OwnFault);
            (failure.exit_code(), failure.said().to_string())
        };
        assert_eq!(code, 3);
        assert_eq!(
            said,
            format!(
                "the control daemon for environment {id} could not be reached: {}. No stop was requested and no start was made.",
                Shown::ipc(&error)
            )
        );
    }

    /// The restart's sentence for a request that could not be composed.
    #[test]
    fn the_restart_says_in_whole_that_its_request_could_not_be_made() {
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let id = environment.environment_id;
        let failure = unmade_request(
            Which::Restart,
            id,
            &Shown::said("the request could not be composed"),
            Unmade::OwnFault,
        );
        use kr_client::shown::Said as _;
        assert_eq!(failure.exit_code(), 3);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "kr host restart could not make its request for the control daemon of environment {id}: the request could not be composed. Nothing was sent, and nothing was stopped."
            )
        );
    }

    /// The restart's sentence for a daemon of another build that takes no stop request.
    #[test]
    fn the_restart_says_in_whole_that_the_daemon_is_of_another_build_and_takes_no_stop() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let id = environment.environment_id;
        let refusal = ProtocolError::new(ErrorCode::PermissionDenied, "refused for the case");
        let failure = after_the_probe(Which::Restart, id, refusal, Some(Ok(Ok(()))));
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "The control daemon of environment {id} is of another build and takes no stop request. Nothing was stopped. kr host update or kr host rollback switches this host to another release and replaces this daemon. Each checks the stores for that release before it switches, and starts this daemon again if it cannot switch."
            )
        );
    }

    /// The restart's sentence for a stop request that is refused with a check that is refused too.
    #[test]
    fn the_restart_says_in_whole_that_the_stop_and_the_check_were_refused() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let id = environment.environment_id;
        let refusal = ProtocolError::new(ErrorCode::PermissionDenied, "refused for the case");
        let probe = ProtocolError::new(ErrorCode::PermissionDenied, "the check was refused");
        let failure = after_the_probe(Which::Restart, id, refusal, Some(Ok(Err(probe.clone()))));
        assert_eq!(failure.exit_code(), 8);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "The control daemon of environment {id} takes no stop request or refuses it, and the check that tells which was refused too: {}. Nothing was stopped.",
                Shown::protocol(&probe)
            )
        );
    }

    /// The restart's sentence for a stop request that is refused in the daemon's own words, and
    /// for one whose check cannot be read or is refused in other words: the refusal as the daemon
    /// gave it, and that nothing was stopped, with the refusal's code and exit 8; the stop's
    /// own sentence for the same refusal is the daemon's words alone.
    #[test]
    fn the_restart_says_in_its_own_words_what_the_daemon_refused_and_that_nothing_was_stopped() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let id = environment.environment_id;
        let refusal = ProtocolError::new(ErrorCode::PermissionDenied, "refused for the case");
        for probe in [
            None,
            Some(Err(kr_ipc::IpcError::socket(
                "read",
                std::io::Error::from(std::io::ErrorKind::BrokenPipe),
            ))),
        ] {
            let failure = after_the_probe(Which::Restart, id, refusal.clone(), probe);
            assert_eq!(failure.exit_code(), 8);
            assert_eq!(
                failure.said().to_string(),
                format!("{}. Nothing was stopped.", Shown::protocol(&refusal))
            );
            assert_eq!(
                failure.machine_message().to_string(),
                format!(
                    "PERMISSION_DENIED: {}. Nothing was stopped.",
                    Shown::protocol(&refusal)
                )
            );
        }
        let other = ProtocolError::new(ErrorCode::EnvironmentUnavailable, "the check says why");
        let failure = after_the_probe(
            Which::Restart,
            id,
            refusal.clone(),
            Some(Ok(Err(other.clone()))),
        );
        assert_eq!(failure.exit_code(), 8);
        assert_eq!(
            failure.said().to_string(),
            format!("{}. Nothing was stopped.", Shown::protocol(&other))
        );
        let stop = after_the_probe(Which::Stop, id, refusal.clone(), None);
        assert_eq!(
            stop.said().to_string(),
            CliError::Refused(refusal).said().to_string(),
            "the stop says the daemon's words alone"
        );
    }

    /// What the restart says and exits with after a stop request that was written and a wait that
    /// ended as `end`.
    fn the_restart_after_the_request(
        end: End,
        request: &Request,
    ) -> (KnownEnvironment, u8, String) {
        let (_temp, environment) = an_environment_for_the_whole_texts();
        let said = said_after_the_request(end, request);
        let message = words_after_the_request(
            Which::Restart,
            &said.sentence,
            request,
            &environment.paths,
            environment.environment_id,
            None,
            None,
        );
        let code = said
            .exit
            .failure(message.clone())
            .map_or(0, |error| error.exit_code());
        (environment, code, message.to_string())
    }

    /// The restart's sentence for a daemon that was told to stop and has not ended.
    #[test]
    fn the_restart_says_in_whole_that_the_daemon_has_not_ended() {
        let (environment, code, said) =
            the_restart_after_the_request(End::NotEnded(Why::Running, None), &Request::Told);
        let id = environment.environment_id;
        let ends_with = if cfg!(windows) {
            "If it stays, end the kr-controller.exe process of this installation in Task Manager; the next daemon recovers as it does after a crash."
        } else {
            "If it stays, end the process that holds the lock file; the next daemon recovers as it does after a crash."
        };
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "The control daemon for environment {id} was told to stop and has not ended after 30 seconds. It may be finishing a write. {ends_with} Run kr host restart again once the old one has ended. This command requested no start."
            )
        );
    }

    /// The restart's sentence for a process that has gone while something else holds the
    /// environment.
    #[test]
    fn the_restart_says_in_whole_that_something_else_still_holds_the_environment() {
        let (environment, code, said) =
            the_restart_after_the_request(End::NotEnded(Why::Held, None), &Request::Told);
        let id = environment.environment_id;
        let how = if cfg!(windows) {
            "If it stays like this, end the kr-controller.exe process of this installation in Task Manager."
        } else {
            "If it stays like this, end the process that holds the lock file."
        };
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "The process of the control daemon for environment {id} has gone, and something that is not shown to be a control daemon still holds the environment after 30 seconds. Run kr host restart again in a moment. {how} This command requested no start."
            )
        );
    }

    /// The restart's sentence for a lock that could not be looked at after the request.
    #[test]
    fn the_restart_says_in_whole_that_the_lock_could_not_be_looked_at_after_the_request() {
        let (environment, code, said) = the_restart_after_the_request(
            End::NotEnded(
                Why::Unlooked(Shown::said("the lock file could not be opened")),
                None,
            ),
            &Request::Told,
        );
        let id = environment.environment_id;
        assert_eq!(code, 1);
        assert_eq!(
            said,
            format!(
                "The control daemon for environment {id} was told to stop, and whether it has ended could not be read after 30 seconds: the lock file could not be opened. Run kr host restart again in a moment. This command requested no start."
            )
        );
    }

    /// What a message that no control daemon runs says of the records names no record that is the
    /// command's own, whatever phase it last wrote (the write of the phase that follows can fail
    /// and leave an earlier one): a record of this process is not said by the message of the
    /// failure of its own start, and a record of another process is, in every phase.
    #[test]
    fn a_command_does_not_say_its_own_record_in_any_phase() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let directory = environment.state_dir().join(attempt::DIRECTORY);
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        let write = |file: &str, phase: attempt::Phase, process| {
            let record = attempt::Attempt {
                command: attempt::Command::Restart,
                phase,
                process,
                at_ms: 1,
                daemon: None,
            };
            kr_ipc::paths::write_owner_only_file(
                &directory.join(file),
                &serde_json::to_vec(&record).expect("encodes"),
            )
            .expect("writes the record");
        };
        let own = || identity::current_process_start_identity().expect("an identity");
        for (file, phase) in [
            ("its-own-asking", attempt::Phase::Asking),
            ("its-own-told", attempt::Phase::Told),
            ("its-own-starting", attempt::Phase::Starting),
            ("its-own-failed-start", attempt::Phase::StartFailed),
        ] {
            write(file, phase, own());
            assert_eq!(
                records_said(&environment).to_string(),
                "",
                "this process's record in the phase {phase:?} is its own"
            );
        }
        let pid = std::process::id();
        let at = crate::shown::utc_moment(1);
        write(
            "another-start",
            attempt::Phase::Starting,
            identity::ended_process_identity(pid),
        );
        let said = records_said(&environment).to_string();
        assert!(
            said.contains(&format!(
                "The last record of a kr host restart (process {pid}) is at {at}: it was asking for a new control daemon for environment {id}."
            )),
            "another process's record of a start is said: {said}"
        );
    }

    /// The text for a lock that could not be looked at takes what the request came to: after a stop
    /// that was taken it says that the daemon was told, and after a request whose taking is not
    /// known it says that, with the request's failure, and never that the daemon was told.
    #[test]
    fn the_text_for_a_lock_that_could_not_be_looked_at_takes_the_requests_known_state() {
        let temp = kr_ipc::testing::TempHost::create();
        let id = temp.environment().environment_id();
        let why = Shown::said("the lock file could not be opened");
        let told = unlooked(Which::Stop, id, None, &why).to_string();
        assert!(
            told.contains("was told to stop, and whether it has ended could not be read after 30 seconds: the lock file could not be opened. Run kr host stop again in a moment."),
            "{told}"
        );
        let failure = Shown::said("the connection was cut");
        let unknown = unlooked(Which::Stop, id, Some(&failure), &why).to_string();
        assert!(
            unknown.contains("did not show whether it took the stop (the connection was cut), and whether it has ended could not be read after 30 seconds: the lock file could not be opened. Run kr host stop again in a moment."),
            "{unknown}"
        );
        assert!(!unknown.contains("was told to stop"), "{unknown}");
    }
    /// A failed look at the lock is said in this command's words: the start lock that stayed held
    /// is said as that, with no daemon that is starting, no other command and no count; any other
    /// failure keeps its own words.
    #[test]
    fn a_failed_look_at_the_lock_is_said_in_this_commands_words() {
        let store = std::path::Path::new("/store");
        let held = look_failed(
            store,
            &CliError::UpdateDeferred(Shown::said(
                "a control daemon of the store at /store is starting and has held its start lock \
                 for more than 0 seconds; run kr host update or kr host rollback again once it \
                 has started or stopped",
            )),
        )
        .to_string();
        assert!(
            held.starts_with("the start lock of the store at "),
            "{held}"
        );
        assert!(
            held.ends_with(" was held when the command looked"),
            "{held}"
        );
        for other_words in [
            "is starting",
            "kr host update",
            "kr host rollback",
            "seconds",
        ] {
            assert!(!held.contains(other_words), "{held}");
        }
        let other = look_failed(
            store,
            &CliError::Other(Shown::said("the install lock could not be tried")),
        )
        .to_string();
        assert_eq!(other, "the install lock could not be tried");
    }
    /// A result that saw the daemon end gives the count of creates that the stop went on without,
    /// by one sentence, where the answer gave a count above zero: the successor's text too.
    #[test]
    fn a_successors_text_gives_the_count_of_creates_by_the_sentence_of_the_stop() {
        let temp = kr_ipc::testing::TempHost::create();
        let id = temp.environment().environment_id();
        let sentence = " 3 session creates were still under way after 10 seconds, when the daemon went on with its stop. Each of them finished or ended with the daemon.";
        assert_eq!(creates_under_way(Some(3)).to_string(), sentence);
        assert_eq!(creates_under_way(Some(0)).to_string(), "");
        assert_eq!(creates_under_way(None).to_string(), "");
        let with = successor_said(id, Some(7), Some(9), Some(3)).to_string();
        assert!(
            with.starts_with(
                "The control daemon (process 7) ended; process 9 now holds environment "
            ),
            "{with}"
        );
        assert!(
            with.ends_with(&format!("so something started it again.{sentence}")),
            "{with}"
        );
        let without = successor_said(id, None, None, Some(0)).to_string();
        assert!(
            without.ends_with("so something started it again."),
            "{without}"
        );
    }

    // The cases below run the decision of the command, the look for a daemon's end after a request
    // that could not be made and the wait for the end, on operations that each case supplies, with
    // the runtime's clock paused: an operation spends the time the case says by advancing it, so a
    // case counts the time of every call, and none waits for real time or meets a socket.

    /// A call that the decision made on its operations.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        ConnectionLetGo,
        Held(Duration),
        ProcessState,
        Look(Duration),
        NamedDaemon,
        Pause(Duration),
    }

    /// What one call gives, and the time it takes on the paused clock: the whole of the bound it
    /// was given where `takes` is none.
    #[derive(Clone)]
    struct Step<T> {
        takes: Option<Duration>,
        gives: T,
    }

    fn at_once<T>(gives: T) -> Step<T> {
        Step {
            takes: Some(Duration::ZERO),
            gives,
        }
    }

    fn after<T>(takes: Duration, gives: T) -> Step<T> {
        Step {
            takes: Some(takes),
            gives,
        }
    }

    fn whole<T>(gives: T) -> Step<T> {
        Step { takes: None, gives }
    }

    fn seconds(count: u64) -> Duration {
        Duration::from_secs(count)
    }

    fn millis(count: u64) -> Duration {
        Duration::from_millis(count)
    }

    /// The steps of one operation: its n-th call takes the n-th step, and the last step repeats.
    struct Script<T>(Mutex<(usize, Vec<Step<T>>)>);

    impl<T: Clone> Script<T> {
        fn of(steps: Vec<Step<T>>) -> Self {
            assert!(!steps.is_empty(), "a script has a step");
            Self(Mutex::new((0, steps)))
        }

        fn next(&self) -> Step<T> {
            let mut script = self.0.lock().expect("the script");
            let step = script.1[script.0.min(script.1.len() - 1)].clone();
            script.0 += 1;
            step
        }
    }

    type Calls = std::sync::Arc<Mutex<Vec<(Duration, Call)>>>;

    /// The connection of the command to the daemon, as the arm is given it: letting it go is a call
    /// like the others, so the case sees whether it comes before the first look or the wait.
    struct Connection {
        start: tokio::time::Instant,
        calls: Calls,
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            self.calls
                .lock()
                .expect("the calls")
                .push((self.start.elapsed(), Call::ConnectionLetGo));
        }
    }

    /// Operations that a case supplies. Each call is recorded with the time at which it began,
    /// counted from the start of the case on the paused clock, and spends the time of its step.
    struct Supplied {
        start: tokio::time::Instant,
        calls: Calls,
        held: Script<std::result::Result<bool, Shown>>,
        process: Script<ProcessState>,
        look: Script<Endpoint>,
        named: Script<Option<u64>>,
    }

    impl Supplied {
        /// A lock that is free, a process that runs, a listener that does not answer and a lock
        /// file that names nobody, each at once.
        fn new() -> Self {
            Self {
                start: tokio::time::Instant::now(),
                calls: Calls::default(),
                held: Script::of(vec![at_once(Ok(false))]),
                process: Script::of(vec![at_once(ProcessState::Running)]),
                look: Script::of(vec![at_once(Endpoint::Unclear)]),
                named: Script::of(vec![at_once(None)]),
            }
        }

        fn held(mut self, steps: Vec<Step<std::result::Result<bool, Shown>>>) -> Self {
            self.held = Script::of(steps);
            self
        }

        fn process(mut self, steps: Vec<Step<ProcessState>>) -> Self {
            self.process = Script::of(steps);
            self
        }

        fn look(mut self, steps: Vec<Step<Endpoint>>) -> Self {
            self.look = Script::of(steps);
            self
        }

        fn named(mut self, steps: Vec<Step<Option<u64>>>) -> Self {
            self.named = Script::of(steps);
            self
        }

        fn record(&self, call: Call) {
            self.calls
                .lock()
                .expect("the calls")
                .push((self.start.elapsed(), call));
        }

        fn connection(&self) -> Connection {
            Connection {
                start: self.start,
                calls: self.calls.clone(),
            }
        }

        fn calls(&self) -> Vec<(Duration, Call)> {
            self.calls.lock().expect("the calls").clone()
        }

        /// How many looks were made.
        fn looks(&self) -> usize {
            self.calls()
                .iter()
                .filter(|(_, call)| matches!(call, Call::Look(_)))
                .count()
        }
    }

    impl Operations for Supplied {
        async fn held(&self, within: Duration) -> std::result::Result<bool, Shown> {
            self.record(Call::Held(within));
            let step = self.held.next();
            tokio::time::advance(step.takes.unwrap_or(within)).await;
            step.gives
        }

        fn process_state(&self, _old: &ProcessStartIdentity) -> ProcessState {
            self.record(Call::ProcessState);
            self.process.next().gives
        }

        async fn look(&self, within: Duration, _seen: &mut dyn FnMut(Sight)) -> Endpoint {
            self.record(Call::Look(within));
            let step = self.look.next();
            tokio::time::advance(step.takes.unwrap_or(within)).await;
            step.gives
        }

        fn named_daemon(&self) -> Option<u64> {
            self.record(Call::NamedDaemon);
            self.named.next().gives
        }

        async fn pause(&self, time: Duration) {
            self.record(Call::Pause(time));
            tokio::time::advance(time).await;
        }
    }

    /// The process of the daemon that was asked, as the cases name it.
    fn asked_process() -> ProcessStartIdentity {
        identity::ended_process_identity(4000)
    }

    /// What the command says where the wait ended at its bound as `why`, after a request that was
    /// told (`not_known` is none) or whose outcome was not shown (`not_known` is its failure).
    fn not_ended_said(
        why: Why,
        not_known: Option<&Shown>,
        environment: &EnvironmentPaths,
        id: EnvironmentId,
        old: Option<&ProcessStartIdentity>,
    ) -> Shown {
        let request = not_known.map_or(Request::Told, |failure| {
            Request::MaybeAsked(failure.clone())
        });
        let said = said_after_the_request(End::NotEnded(why, None), &request);
        words_after_the_request(
            Which::Stop,
            &said.sentence,
            &request,
            environment,
            id,
            old,
            None,
        )
    }

    /// How a wait came out, in words a failed assertion shows.
    fn said(end: &End) -> String {
        match end {
            End::Gone => "gone".to_owned(),
            End::Successor(named) => format!("successor {named:?}"),
            End::NotEnded(Why::Running, _) => "not ended, running".to_owned(),
            End::NotEnded(Why::Answers, _) => "not ended, answers".to_owned(),
            End::NotEnded(Why::NotShown, _) => "not ended, not shown".to_owned(),
            End::NotEnded(Why::Held, _) => "not ended, held".to_owned(),
            End::NotEnded(Why::HeldNotShown, _) => "not ended, held, not shown".to_owned(),
            End::NotEnded(Why::Unlooked(_), _) => "not ended, not looked at".to_owned(),
        }
    }

    /// How the arm for a request that could not be made came out.
    fn arm_said(ended: Option<&End>) -> String {
        ended.map_or_else(|| "the request's failure".to_owned(), said)
    }

    /// Runs the arm on `supplied` with its deadline counted from now, as the command counts it.
    async fn arm(
        supplied: &Supplied,
        old: Option<&ProcessStartIdentity>,
        closed: bool,
    ) -> Option<End> {
        let deadline = tokio::time::Instant::now() + END_BOUND;
        match ended_before_the_request(supplied, supplied.connection(), old, closed, deadline).await
        {
            Decided::Ended(end) => Some(end),
            Decided::NotShown | Decided::Answers(_) => None,
        }
    }

    /// Where the connection was not closed and a daemon of the same start answers at the first
    /// look, the request's failure is the result at once: one look, no wait.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_of_the_same_start_at_the_first_look_gives_the_failure_at_once() {
        let process = asked_process();
        for old in [None, Some(&process)] {
            let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
            let ended = arm(&supplied, old, false).await;
            assert_eq!(arm_said(ended.as_ref()), "the request's failure", "{old:?}");
            assert_eq!(
                supplied.calls(),
                vec![
                    (Duration::ZERO, Call::ConnectionLetGo),
                    (Duration::ZERO, Call::Look(startup::ANSWER_BOUND)),
                ],
                "one look and nothing else, {old:?}"
            );
        }
    }

    /// Where the daemon closed the connection no first look is made, and the daemon is waited for
    /// to the end of the one deadline where it still answers, and found ended where it has gone.
    #[tokio::test(start_paused = true)]
    async fn a_closed_connection_is_waited_for_with_no_look_before_the_wait() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let ended = arm(&supplied, None, true).await;
        assert_eq!(arm_said(ended.as_ref()), "the request's failure");
        let calls = supplied.calls();
        assert_eq!(
            calls[..3],
            [
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Held(END_BOUND)),
                (Duration::ZERO, Call::Look(END_BOUND)),
            ],
            "the wait follows the let-go connection, with no look between"
        );
        assert!(supplied.looks() > 1, "the wait looks again and again");
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "it waits to the deadline"
        );

        let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
        let ended = arm(&supplied, None, true).await;
        assert_eq!(arm_said(ended.as_ref()), "gone");
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Held(END_BOUND)),
                (Duration::ZERO, Call::Look(END_BOUND)),
            ]
        );
    }

    /// The command's connection is let go before the first look where it makes one, and before the
    /// wait where it does not.
    #[tokio::test(start_paused = true)]
    async fn the_connection_is_let_go_before_the_first_look_and_before_the_wait() {
        for (closed, next) in [
            (false, Call::Look(startup::ANSWER_BOUND)),
            (true, Call::Held(END_BOUND)),
        ] {
            let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
            let _ = arm(&supplied, None, closed).await;
            let calls = supplied.calls();
            assert_eq!(
                calls[0].1,
                Call::ConnectionLetGo,
                "the first call, closed {closed}"
            );
            assert_eq!(
                calls[1].1, next,
                "then the look or the wait, closed {closed}"
            );
        }
    }

    /// A daemon that has ended where no daemon answered the one look is the end: with no identity
    /// where nobody answers at the endpoint and the lock is free, and with one where the process
    /// has gone and the lock is free; and a successor where the lock is held by another daemon.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_ended_is_found_to_have_ended_after_the_one_look() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
        let ended = arm(&supplied, None, false).await;
        assert_eq!(arm_said(ended.as_ref()), "gone");
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Look(startup::ANSWER_BOUND)),
                (Duration::ZERO, Call::Held(END_BOUND)),
                (Duration::ZERO, Call::Look(END_BOUND)),
            ],
            "the first look finds nobody, and the wait looks again"
        );

        let process = asked_process();
        let supplied = Supplied::new()
            .look(vec![at_once(Endpoint::Unclear)])
            .process(vec![at_once(ProcessState::Ended)]);
        let ended = arm(&supplied, Some(&process), false).await;
        assert_eq!(
            arm_said(ended.as_ref()),
            "gone",
            "a process that has gone, a free lock"
        );

        let supplied = Supplied::new()
            .held(vec![at_once(Ok(true))])
            .process(vec![at_once(ProcessState::Ended)])
            .named(vec![at_once(Some(5000))]);
        let ended = arm(&supplied, Some(&process), true).await;
        assert_eq!(arm_said(ended.as_ref()), "successor Some(5000)");
    }

    /// One deadline counts from the failure: the look for the end takes its time from it, the wait
    /// has what is left, and each wait after another, the lock's, the look and the pause between
    /// rounds, is given what is left of the deadline when it starts.
    #[tokio::test(start_paused = true)]
    async fn one_deadline_counts_from_the_failure_and_each_wait_has_what_is_left() {
        let supplied = Supplied::new()
            .held(vec![
                after(seconds(4), Ok(false)),
                after(seconds(2), Ok(false)),
            ])
            .look(vec![
                after(seconds(1), Endpoint::Unclear),
                after(seconds(3), Endpoint::Unclear),
                after(seconds(1), Endpoint::Nobody),
            ]);
        let ended = arm(&supplied, None, false).await;
        assert_eq!(arm_said(ended.as_ref()), "gone");
        assert_eq!(
            supplied.calls(),
            vec![
                (seconds(0), Call::ConnectionLetGo),
                (seconds(0), Call::Look(startup::ANSWER_BOUND)),
                // The wait has what the one look left of the 30 seconds.
                (seconds(1), Call::Held(seconds(29))),
                (seconds(5), Call::Look(seconds(25))),
                (seconds(8), Call::Pause(millis(50))),
                (millis(8050), Call::Held(millis(21950))),
                (millis(10050), Call::Look(millis(19950))),
            ]
        );
    }

    /// A pause is never longer than what is left of the deadline, and the wait ends at the
    /// deadline with the daemon not ended: no wait runs past it.
    #[tokio::test(start_paused = true)]
    async fn the_pause_does_not_run_past_the_deadline() {
        let supplied =
            Supplied::new().held(vec![after(millis(29_990), Ok(false)), at_once(Ok(false))]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, not shown");
        let calls = supplied.calls();
        assert_eq!(
            calls,
            vec![
                (seconds(0), Call::Held(END_BOUND)),
                (millis(29_990), Call::Look(millis(10))),
                (millis(29_990), Call::Pause(millis(10))),
                (seconds(30), Call::Held(Duration::ZERO)),
                (seconds(30), Call::Look(Duration::ZERO)),
            ]
        );
        assert_eq!(supplied.start.elapsed(), END_BOUND);
    }

    /// Operations that use their whole bound end the wait at its deadline: each is given what is
    /// left when it starts, so a wait after one that used its whole bound has none.
    #[tokio::test(start_paused = true)]
    async fn operations_that_use_their_whole_bound_end_the_wait_at_its_deadline() {
        let supplied = Supplied::new()
            .held(vec![whole(Ok(false))])
            .look(vec![whole(Endpoint::Unclear)]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, not shown");
        assert_eq!(
            supplied.calls(),
            vec![
                (seconds(0), Call::Held(END_BOUND)),
                (seconds(30), Call::Look(Duration::ZERO)),
            ],
            "a look after a wait that used the whole bound has none left"
        );
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "and the wait ends at its deadline"
        );
    }

    /// The real wait loop, against a daemon that still answers every time: a daemon of the same
    /// start is not an end, with or without an identity for its process, and the wait gives up at
    /// its deadline as not ended: answering where the last look showed it, and running where its
    /// process was read as running. A supplied end could not show this.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_still_answers_in_every_round_is_not_ended_at_the_deadline() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, answers");
        assert!(supplied.looks() > 100, "the wait looked round after round");
        assert_eq!(supplied.start.elapsed(), END_BOUND);

        // With an identity the process is read in every round, and a process that runs is the
        // daemon that has not ended, whatever answers at the endpoint.
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(said(&ended), "not ended, running");
        assert_eq!(supplied.looks(), 0, "a process that runs needs no look");
        assert_eq!(supplied.start.elapsed(), END_BOUND);
    }

    /// With the process's identity known, the daemon has ended only where its process has: running
    /// or unknown is not an end whatever the lock says; ended with a free lock is the end; ended
    /// with a held lock is a successor only on evidence, which is a live kr-controller that is not
    /// the old one, or a daemon of another generation that answers.
    #[tokio::test(start_paused = true)]
    async fn with_an_identity_the_end_is_the_process_gone_and_the_lock_free_or_a_successor() {
        let process = asked_process();
        for (state, held, expected) in [
            (ProcessState::Running, Ok(false), "not ended, running"),
            (
                ProcessState::Unknown {
                    detail: "denied".to_owned(),
                },
                Ok(false),
                "not ended, answers",
            ),
            (ProcessState::Running, Ok(true), "not ended, running"),
            (ProcessState::Ended, Ok(false), "gone"),
            // The look that decides a held lock shows the daemon answering, and the last look
            // decides: it is not a held lock that nothing shows to be a daemon.
            (ProcessState::Ended, Ok(true), "not ended, answers"),
            (
                ProcessState::Ended,
                Err(Shown::said("the lock could not be taken")),
                "not ended, not looked at",
            ),
            (
                ProcessState::Running,
                Err(Shown::said("the lock could not be taken")),
                "not ended, running",
            ),
            // Nothing shows a process that runs, and the lock cannot be read: nothing is known.
            (
                ProcessState::Unknown {
                    detail: "denied".to_owned(),
                },
                Err(Shown::said("the lock could not be taken")),
                "not ended, not looked at",
            ),
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(held)])
                .process(vec![at_once(state.clone())])
                .look(vec![at_once(Endpoint::Same(an_answer()))]);
            let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
            assert_eq!(said(&ended), expected, "{state:?}");
        }

        // A process whose state the system did not say is no sign of life and no sign of an end:
        // with the lock free the endpoint decides, as where there is no identity.
        for (look, expected) in [
            (Endpoint::Unclear, "not ended, not shown"),
            (Endpoint::Nobody, "gone"),
            (Endpoint::Same(an_answer()), "not ended, answers"),
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(Ok(false))])
                .process(vec![at_once(ProcessState::Unknown {
                    detail: "denied".to_owned(),
                })])
                .look(vec![at_once(look)]);
            let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
            assert_eq!(said(&ended), expected, "{look:?}");
        }

        // A successor: another process that the lock file names, with no look made for it; and
        // where it names none or the old one, a daemon of another generation at the endpoint.
        let held_ended = || {
            Supplied::new()
                .held(vec![at_once(Ok(true))])
                .process(vec![at_once(ProcessState::Ended)])
        };
        let supplied = held_ended().named(vec![at_once(Some(5000))]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(said(&ended), "successor Some(5000)");
        assert_eq!(supplied.looks(), 0, "the lock file's word is evidence");
        let supplied = held_ended()
            .named(vec![at_once(Some(4000))])
            .look(vec![at_once(Endpoint::Another)]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(said(&ended), "successor Some(4000)", "the endpoint's word");
        let supplied = held_ended()
            .named(vec![at_once(None)])
            .look(vec![at_once(Endpoint::Another)]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(said(&ended), "successor None");
        let supplied = held_ended().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(
            said(&ended),
            "not ended, answers",
            "a daemon of the same start is no successor, and the last look shows that it answers"
        );
        let supplied = held_ended();
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(
            said(&ended),
            "not ended, held",
            "a lock that stays held, and a look that shows nothing, is not a successor"
        );
    }

    /// With no process identity, which is what Windows always has, the daemon has ended where the
    /// lock is free and nobody answers at its endpoint, is replaced where a daemon of another
    /// generation answers, and is not ended where it answers or cannot be seen; no process is
    /// read, and the lock that cannot be looked at is said as that.
    #[tokio::test(start_paused = true)]
    async fn with_no_identity_the_end_is_a_free_lock_and_an_endpoint_nobody_answers() {
        for (held, look, expected) in [
            (Ok(false), Endpoint::Nobody, "gone"),
            (Ok(false), Endpoint::Another, "successor None"),
            (Ok(false), Endpoint::Same(an_answer()), "not ended, answers"),
            (Ok(false), Endpoint::Unclear, "not ended, not shown"),
            (Ok(true), Endpoint::Another, "successor None"),
            (Ok(true), Endpoint::Nobody, "not ended, held, not shown"),
            (Ok(true), Endpoint::Same(an_answer()), "not ended, answers"),
            (
                Err(Shown::said("the lock could not be taken")),
                Endpoint::Nobody,
                "not ended, not looked at",
            ),
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(held.clone())])
                .look(vec![at_once(look)]);
            let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
            assert_eq!(said(&ended), expected, "{held:?} {look:?}");
            assert!(
                !supplied
                    .calls()
                    .iter()
                    .any(|(_, call)| *call == Call::ProcessState),
                "with no identity no process is read"
            );
        }
    }

    // The failures of the command's connection before it made its request: the greeting, and the
    // read of `host.info`. Each is decided on supplied operations with the paused clock.

    /// What a case shows of a decision about a failed connection.
    fn before_said(before: &Before) -> String {
        match before {
            Before::Ended { said, pid, .. } => format!("ended ({pid:?}): {said}"),
            Before::Silent { accepted: true } => "silent".to_owned(),
            Before::Silent { accepted: false } => "silent, nothing accepted".to_owned(),
            Before::Answers(_) => "answers".to_owned(),
            Before::OwnFault => "own fault".to_owned(),
        }
    }

    /// The words of a daemon that ended and whose closed connection stopped this command's request.
    fn the_end_said(id: EnvironmentId, pid: Option<u64>) -> String {
        the_end_said_for(id, pid, &kr_ipc::IpcError::PeerClosed)
    }

    /// The same words for the failure `error`.
    fn the_end_said_for(id: EnvironmentId, pid: Option<u64>, error: &kr_ipc::IpcError) -> String {
        let process = pid.map_or_else(String::new, |pid| format!(" (process {pid})"));
        format!(
            "ended ({pid:?}): The control daemon for environment {id}{process} ended, and this \
             command could not make its request for it: {}. This command sent nothing.",
            Shown::ipc(error)
        )
    }

    /// Where the daemon that the request could not be made to has ended and another holds the
    /// environment, the words are those of any end that finds a successor: the old process and the
    /// new one where the command read them, and nothing of the request that could not be made.
    /// Where the daemon is gone, the words say why the request could not be made.
    #[test]
    fn a_request_that_could_not_be_made_says_a_successor_by_the_words_of_any_end_that_finds_one() {
        let id = an_environment();
        let why = Shown::ipc(&kr_ipc::IpcError::PeerClosed);
        let said =
            |old, ended: &End| ended_before_the_request_said(id, old, ended, &why).to_string();
        assert_eq!(
            said(Some(4000), &End::Successor(Some(5000))),
            format!(
                "The control daemon (process 4000) ended; process 5000 now holds environment {id}, \
                 so something started it again."
            )
        );
        assert_eq!(
            said(None, &End::Successor(None)),
            format!(
                "The control daemon ended; another control daemon now holds environment {id}, so \
                 something started it again."
            )
        );
        assert_eq!(
            said(Some(4000), &End::Gone),
            the_end_said_for(id, Some(4000), &kr_ipc::IpcError::PeerClosed)
                .strip_prefix("ended (Some(4000)): ")
                .expect("the words")
        );
    }

    /// The answer of a daemon of the first generation to a look.
    fn an_answer() -> Answered {
        Answered::for_a_case(ControllerGeneration::new(1))
    }

    /// A frame that the daemon's end cut: the end of the stream, or a reset, inside a frame.
    fn a_frame_cut_by_the_end() -> kr_ipc::IpcError {
        kr_ipc::IpcError::TruncatedFrame {
            received: 3,
            expected: 16,
        }
    }

    /// A frame that cannot be read: a closure that is not a closed peer, so that it is looked at
    /// once first.
    fn a_spoiled_frame() -> kr_ipc::IpcError {
        kr_ipc::IpcError::Frame(kr_protocol::frame::FrameError::EmptyPayload)
    }

    /// The reset that a connect gets when the daemon's end closes its listener with the connection
    /// still in the queue.
    fn a_connect_reset() -> kr_ipc::IpcError {
        kr_ipc::IpcError::socket(
            "connect",
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        )
    }

    /// A fault of this side's own socket.
    fn a_fault_of_the_socket() -> kr_ipc::IpcError {
        kr_ipc::IpcError::socket("read the control frame", std::io::Error::other("a fault"))
    }

    fn the_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + END_BOUND
    }

    fn an_environment() -> EnvironmentId {
        kr_ipc::testing::TempHost::create()
            .environment()
            .environment_id()
    }

    /// A daemon that closes the greeting as it ends is the daemon's end, with the process named
    /// where it is known, and not a stop that this command made: it sent nothing.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_closed_by_a_daemon_that_ends_is_the_daemons_end() {
        let id = an_environment();
        let process = asked_process();
        for (old, named) in [(Some(&process), Some(4000)), (None, None)] {
            let supplied = Supplied::new()
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![at_once(Endpoint::Nobody)]);
            let before = greeting_failed(
                &supplied,
                &kr_ipc::IpcError::PeerClosed,
                old,
                id,
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), the_end_said(id, named), "{old:?}");
            assert_eq!(supplied.start.elapsed(), Duration::ZERO, "{old:?}");
        }
    }

    /// A connect that the daemon's end resets, because the listener closed with the connection in
    /// its queue, is the daemon's end as a closed greeting is: no fault of this side's own, and the
    /// command sent nothing. It is looked at once, and an old process that has gone with a free lock
    /// is the end.
    #[tokio::test(start_paused = true)]
    async fn a_connect_reset_before_the_greeting_is_the_daemons_end() {
        let id = an_environment();
        let process = asked_process();
        let reset = a_connect_reset();
        let supplied = Supplied::new()
            .process(vec![at_once(ProcessState::Ended)])
            .look(vec![at_once(Endpoint::Nobody)]);
        let before = greeting_failed(&supplied, &reset, Some(&process), id, the_deadline()).await;
        let said = before_said(&before);
        assert_eq!(said, the_end_said_for(id, Some(4000), &reset));
        assert_eq!(supplied.looks(), 1, "{said}");
        assert_eq!(supplied.start.elapsed(), Duration::ZERO, "{said}");
    }

    /// The kernel's own order on Linux: a connection that waits in the queue of a listener that
    /// closes without accepting it fails at the connect with a reset, and that failure is the
    /// daemon's end, with the words of an end that this command's request did not cause.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_connect_reset_by_a_listener_that_closes_with_it_queued_is_the_daemons_end() {
        use std::future::Future as _;

        let directory = kr_ipc::testing::PrivateTempDir::create();
        let path = directory.path().join("stand-in.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&path).expect("the stand-in listener binds");
        let endpoint = kr_ipc::paths::Endpoint::from_path(path).expect("the endpoint");
        let reach = startup::reach(&endpoint, startup::ANSWER_BOUND, &[]);
        let mut reach = std::pin::pin!(reach);
        // One poll makes the connect, which the kernel queues at the listener that never accepts;
        // the greeting cannot be answered, so the reach is pending.
        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(reach.as_mut().poll(cx))).await;
        assert!(
            first.is_pending(),
            "the connection waits in the listener's queue"
        );
        drop(listener);
        let startup::Reached::Refused(error) = reach.await else {
            panic!("the reach of a listener that closed with the connection queued is refused");
        };
        assert!(
            matches!(
                &error,
                kr_ipc::IpcError::Socket { operation: "connect", source }
                    if source.kind() == std::io::ErrorKind::ConnectionReset
            ),
            "{error:?}"
        );

        let id = an_environment();
        let process = asked_process();
        let supplied = Supplied::new()
            .process(vec![at_once(ProcessState::Ended)])
            .look(vec![at_once(Endpoint::Nobody)]);
        let before = greeting_failed(&supplied, &error, Some(&process), id, the_deadline()).await;
        assert_eq!(
            before_said(&before),
            the_end_said_for(id, Some(4000), &error)
        );
    }

    /// A greeting that fails on the socket and is no closure is judged as any failure before the
    /// request is: by one look first. A daemon that answers it stays the answer of the failure, and a
    /// daemon that has gone is the end.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_that_fails_on_the_socket_is_judged_by_one_look() {
        let id = an_environment();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = greeting_failed(&supplied, &a_spoiled_frame(), None, id, the_deadline()).await;
        assert_eq!(before_said(&before), "answers");
        assert_eq!(
            supplied.calls(),
            vec![(Duration::ZERO, Call::Look(startup::ANSWER_BOUND))]
        );

        let process = asked_process();
        let fault = a_spoiled_frame();
        let supplied = Supplied::new()
            .process(vec![at_once(ProcessState::Ended)])
            .look(vec![at_once(Endpoint::Nobody)]);
        let before = greeting_failed(&supplied, &fault, Some(&process), id, the_deadline()).await;
        assert_eq!(
            before_said(&before),
            the_end_said_for(id, Some(4000), &fault)
        );
    }

    /// A greeting that a daemon answers with something that cannot be used (a frame that cannot be
    /// read, a message of another kind, a rejection) is a daemon's answer: nothing is looked at, and
    /// the failure keeps its words.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_that_a_daemon_answers_with_something_unusable_is_an_answer() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
        let before = greeting_failed(
            &supplied,
            &kr_ipc::IpcError::UnexpectedMessage("a frame of another kind"),
            None,
            an_environment(),
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "answers");
        assert!(supplied.calls().is_empty(), "{:?}", supplied.calls());
    }

    /// A daemon that closed the greeting and is not shown to have ended at the deadline is the
    /// command's silence, as for a daemon that does not answer.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_closed_by_a_daemon_that_does_not_end_is_silence_at_the_deadline() {
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = greeting_failed(
            &supplied,
            &kr_ipc::IpcError::PeerClosed,
            Some(&process),
            an_environment(),
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "it waits to the deadline"
        );
    }

    /// A read of `host.info` that the daemon closes as it ends is the daemon's end, and the
    /// command's connection is let go before anything is looked at.
    #[tokio::test(start_paused = true)]
    async fn a_host_info_closed_by_a_daemon_that_ends_is_the_daemons_end() {
        let id = an_environment();
        let process = asked_process();
        for (old, named) in [(Some(&process), Some(4000)), (None, None)] {
            let supplied = Supplied::new()
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![at_once(Endpoint::Nobody)]);
            let before = host_info_failed(
                &supplied,
                supplied.connection(),
                &kr_ipc::IpcError::PeerClosed,
                old,
                id,
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), the_end_said(id, named), "{old:?}");
            assert_eq!(
                supplied.calls()[0].1,
                Call::ConnectionLetGo,
                "the connection is let go first, {old:?}"
            );
            assert_eq!(supplied.start.elapsed(), Duration::ZERO, "{old:?}");
        }
    }

    /// A fault of the read that is not a closed peer is judged as the unmade request is: one look,
    /// and the failure keeps its words where a daemon of the same start still answers, and a daemon
    /// that has gone is the end.
    #[tokio::test(start_paused = true)]
    async fn a_host_info_that_fails_on_the_socket_is_judged_by_one_look() {
        let id = an_environment();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_spoiled_frame(),
            None,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "answers");
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Look(startup::ANSWER_BOUND)),
            ]
        );

        let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_spoiled_frame(),
            None,
            id,
            the_deadline(),
        )
        .await;
        assert!(
            before_said(&before).starts_with("ended (None): The control daemon for environment"),
            "{}",
            before_said(&before)
        );
    }

    /// A daemon that closed the read of `host.info` and is not shown to have ended at the deadline
    /// is the command's silence.
    #[tokio::test(start_paused = true)]
    async fn a_host_info_closed_by_a_daemon_that_does_not_end_is_silence_at_the_deadline() {
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &kr_ipc::IpcError::PeerClosed,
            Some(&process),
            an_environment(),
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "it waits to the deadline"
        );
    }

    /// A greeting cut inside a frame by a daemon that ends is the daemon's end, as a closed peer is:
    /// the end of the stream inside a frame is the daemon going.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_cut_inside_a_frame_by_a_daemon_that_ends_is_the_daemons_end() {
        let id = an_environment();
        let process = asked_process();
        let cut = a_frame_cut_by_the_end();
        for (old, named) in [(Some(&process), Some(4000)), (None, None)] {
            let supplied = Supplied::new()
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![at_once(Endpoint::Nobody)]);
            let before = greeting_failed(&supplied, &cut, old, id, the_deadline()).await;
            assert_eq!(
                before_said(&before),
                the_end_said_for(id, named, &cut),
                "{old:?}"
            );
            assert_eq!(supplied.start.elapsed(), Duration::ZERO, "{old:?}");
        }
    }

    /// A greeting cut inside a frame by a daemon that is not shown to have ended at the deadline is
    /// the command's silence, as for a closed peer.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_cut_inside_a_frame_by_a_daemon_that_does_not_end_is_silence() {
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = greeting_failed(
            &supplied,
            &a_frame_cut_by_the_end(),
            Some(&process),
            an_environment(),
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "it waits to the deadline"
        );
    }

    /// A read of `host.info` cut inside a frame is waited for as a closed peer is: no look comes
    /// before the wait, and a daemon that is not shown to have ended is the command's silence.
    #[tokio::test(start_paused = true)]
    async fn a_host_info_cut_inside_a_frame_is_waited_for_as_a_closed_peer_is() {
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_frame_cut_by_the_end(),
            Some(&process),
            an_environment(),
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        let calls = supplied.calls();
        assert_eq!(
            calls[..2],
            [
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Held(END_BOUND)),
            ],
            "the wait follows the let-go connection, with no look between"
        );
        assert_eq!(
            supplied.start.elapsed(),
            END_BOUND,
            "it waits to the deadline"
        );

        let id = an_environment();
        let cut = a_frame_cut_by_the_end();
        let supplied = Supplied::new()
            .process(vec![at_once(ProcessState::Ended)])
            .look(vec![at_once(Endpoint::Nobody)]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &cut,
            Some(&process),
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), the_end_said_for(id, Some(4000), &cut));
    }

    /// Where the retry's connection finds nothing listening and the end is not shown past the bound,
    /// no daemon has answered anything: the decision is silence, with no connection accepted, after
    /// the whole bound, and never the failure of an answered request. What the command says of it
    /// then depends on the lock: exit 1 where it is held, exit 3 where it is not (the case below
    /// and `a_connect_that_found_nothing_listening_is_no_connection_that_did_not_answer`).
    #[tokio::test(start_paused = true)]
    async fn nothing_listening_with_the_lock_held_past_the_bound_is_silence() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let process = asked_process();
        let held =
            SingletonLock::hold(&environment.paths.singleton_lock(), id).expect("takes the lock");
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let supplied = Supplied::new().look(vec![at_once(Endpoint::Nobody)]);
            let gone = kr_ipc::IpcError::socket("connect", std::io::Error::from(kind));
            let before = host_info_failed(
                &supplied,
                supplied.connection(),
                &gone,
                Some(&process),
                id,
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), "silent, nothing accepted", "{kind:?}");
            assert_eq!(supplied.start.elapsed(), END_BOUND, "{kind:?}");
            // The lock is held at the end: a daemon holds the environment and does not answer.
            match unmade_ended(
                Which::Stop,
                before,
                &gone,
                id,
                &environment,
                &none,
                true,
                &earlier,
            ) {
                Completion::Reported(error) => {
                    assert_eq!(error.exit_code(), 1, "{kind:?}");
                    assert_eq!(
                        error.to_string(),
                        format!(
                            "A control daemon holds environment {id} and does not answer, so it \
                             may be starting or stopping. No stop was requested. Run kr host stop \
                             again in a moment. {}",
                            how_to_end_the_holder(&environment.paths)
                        ),
                        "{kind:?}"
                    );
                }
                _ => panic!("a silent end is a failure that the command has reported"),
            }
        }
        drop(held);
    }

    /// A silent end is exit 1 with the silence sentence for a lock that is held, and no word that
    /// no host runs.
    #[test]
    fn a_silent_end_is_exit_1_with_the_silence_sentence_and_no_word_that_no_host_runs() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let _held = SingletonLock::hold(&paths.singleton_lock(), id).expect("takes the lock");
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        match ended_by(
            Which::Stop,
            Before::Silent { accepted: true },
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Ok(Completion::Reported(error)) => {
                assert_eq!(error.exit_code(), 1);
                let said = error.to_string();
                assert!(
                    said.contains("does not answer, so it may be starting or stopping")
                        && said.contains("No stop was requested"),
                    "{said}"
                );
                assert!(!said.contains("no KalaReach host"), "{said}");
            }
            _ => panic!("a silent end is a failure that the command has reported"),
        }
    }

    /// The first look takes what is left of the deadline where that is less than its own bound.
    #[tokio::test(start_paused = true)]
    async fn the_first_look_takes_what_is_left_of_the_deadline() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_spoiled_frame(),
            None,
            an_environment(),
            tokio::time::Instant::now() + seconds(3),
        )
        .await;
        assert_eq!(before_said(&before), "answers");
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::ConnectionLetGo),
                (Duration::ZERO, Call::Look(seconds(3))),
            ]
        );
    }

    /// Where a daemon answers a look after a fault that is no closure, exit 3 stays, with the words
    /// of an unmade request.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_answers_a_look_keeps_exit_3_and_the_unmade_requests_words() {
        let id = an_environment();
        let fault = a_spoiled_frame();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &fault,
            None,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "answers");
        let error = unmade_request(
            Which::Stop,
            id,
            &Shown::ipc(&fault),
            Unmade::Answered(an_answer()),
        );
        assert_eq!(error.exit_code(), 3);
        assert!(
            error
                .to_string()
                .contains("could not make its request for the control daemon"),
            "{error}"
        );
    }

    /// A frame that cannot be read (cut or spoiled) is no answer of a daemon: a daemon that goes
    /// can leave one. It is looked at once, as a fault is, and the daemon's end decides: the end
    /// where the daemon has gone, and an answer only from the look that a daemon answered.
    #[tokio::test(start_paused = true)]
    async fn a_frame_that_cannot_be_read_is_no_answer_of_a_daemon() {
        let id = an_environment();
        let process = asked_process();
        let spoiled = kr_ipc::IpcError::Frame(kr_protocol::frame::FrameError::EmptyPayload);
        for at_the_read in [false, true] {
            let supplied = Supplied::new()
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![at_once(Endpoint::Nobody)]);
            let before = if at_the_read {
                host_info_failed(
                    &supplied,
                    supplied.connection(),
                    &spoiled,
                    Some(&process),
                    id,
                    the_deadline(),
                )
                .await
            } else {
                greeting_failed(&supplied, &spoiled, Some(&process), id, the_deadline()).await
            };
            assert_eq!(
                before_said(&before),
                the_end_said_for(id, Some(4000), &spoiled),
                "a daemon that has gone is the end, at the read {at_the_read}"
            );
            assert_eq!(supplied.looks(), 1, "one look, at the read {at_the_read}");

            let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
            let before = if at_the_read {
                host_info_failed(
                    &supplied,
                    supplied.connection(),
                    &spoiled,
                    None,
                    id,
                    the_deadline(),
                )
                .await
            } else {
                greeting_failed(&supplied, &spoiled, None, id, the_deadline()).await
            };
            assert_eq!(before_said(&before), "answers", "at the read {at_the_read}");
            assert_eq!(
                supplied.looks(),
                1,
                "the answer comes from a look, at the read {at_the_read}"
            );
        }
    }

    /// The compose arm ends through the one decision: a request that could not be made on a
    /// connection that the daemon closed, with the daemon not shown to have ended in the bound, is
    /// exit 1 with the silence sentence and not the unmade request's words; and a fault with a
    /// daemon that answers a look is still exit 3 with those words.
    #[tokio::test(start_paused = true)]
    async fn an_unmade_request_on_a_closed_connection_not_shown_ended_is_exit_1_with_silence() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let _held = SingletonLock::hold(&paths.singleton_lock(), id).expect("takes the lock");
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let process = asked_process();

        let closed = kr_ipc::IpcError::PeerClosed;
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = failed_before_the_request(
            &supplied,
            supplied.connection(),
            Some(&process),
            &closed,
            id,
            the_deadline(),
        )
        .await;
        match unmade_ended(
            Which::Stop,
            before,
            &closed,
            id,
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Completion::Reported(error) => {
                assert_eq!(error.exit_code(), 1);
                let said = error.to_string();
                assert!(
                    said.contains("does not answer, so it may be starting or stopping")
                        && said.contains("No stop was requested"),
                    "{said}"
                );
                assert!(!said.contains("could not make its request"), "{said}");
            }
            _ => panic!("a silent end is a failure that the command has reported"),
        }

        let fault = a_spoiled_frame();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same(an_answer()))]);
        let before = failed_before_the_request(
            &supplied,
            supplied.connection(),
            None,
            &fault,
            id,
            the_deadline(),
        )
        .await;
        match unmade_ended(
            Which::Stop,
            before,
            &fault,
            id,
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Completion::Reported(error) => {
                assert_eq!(error.exit_code(), 3);
                assert!(
                    error
                        .to_string()
                        .contains("could not make its request for the control daemon"),
                    "{error}"
                );
            }
            _ => panic!("an answered request's failure is a failure that the command has reported"),
        }
    }

    /// The failures of this side's own checks, which no daemon wrote and no daemon's end causes,
    /// among them the checks of the peer's credentials that are made before any hello and the
    /// failure to read this side's own clock-floor identity.
    fn own_faults() -> Vec<kr_ipc::IpcError> {
        vec![
            kr_ipc::IpcError::PeerRejected {
                peer_uid: 501,
                owner_uid: 502,
            },
            kr_ipc::IpcError::PeerUnknown {
                source: std::io::Error::other("no credentials"),
            },
            kr_ipc::IpcError::PeerAccountRejected {
                detail: "the access list".to_owned(),
            },
            a_fault_of_the_socket(),
            kr_ipc::IpcError::NotInLevel("a field".to_owned()),
            kr_ipc::IpcError::IdentityUnavailable {
                what: "a clock floor identity",
                detail: "no identity".to_owned(),
            },
        ]
    }

    /// The daemon's own refusal of the hello: a complete error response that the host wrote.
    fn the_hellos_refusal() -> kr_ipc::IpcError {
        kr_ipc::IpcError::HostRefused {
            detail: "PERMISSION_DENIED: no".to_owned(),
        }
    }

    /// At the greeting and at the read of `host.info`, each source does what it is: a reply is the
    /// answer of a daemon with no look; this side's own fault says its own words with no look and
    /// is never an answer; a closure is the daemon's end (its cases are above).
    #[tokio::test(start_paused = true)]
    async fn each_source_is_read_for_what_it_is_at_the_greeting_and_at_the_read() {
        let id = an_environment();
        let process = asked_process();
        let mut replies = vec![
            the_hellos_refusal(),
            kr_ipc::IpcError::LinkFenced {
                detail: "the worker refused the link".to_owned(),
            },
        ];
        replies.push(kr_ipc::IpcError::UnexpectedMessage(
            "a frame of another kind",
        ));
        for (errors, said) in [(replies, "answers"), (own_faults(), "own fault")] {
            for error in &errors {
                let supplied = Supplied::new()
                    .process(vec![at_once(ProcessState::Ended)])
                    .look(vec![at_once(Endpoint::Nobody)]);
                let before =
                    greeting_failed(&supplied, error, Some(&process), id, the_deadline()).await;
                assert_eq!(before_said(&before), said, "the greeting, {error}");
                assert!(
                    supplied.calls().is_empty(),
                    "no look at the greeting, {error}"
                );

                let supplied = Supplied::new()
                    .process(vec![at_once(ProcessState::Ended)])
                    .look(vec![at_once(Endpoint::Nobody)]);
                let before = host_info_failed(
                    &supplied,
                    supplied.connection(),
                    error,
                    Some(&process),
                    id,
                    the_deadline(),
                )
                .await;
                assert_eq!(before_said(&before), said, "the read, {error}");
                assert_eq!(
                    supplied.calls(),
                    vec![(Duration::ZERO, Call::ConnectionLetGo)],
                    "only the connection is let go at the read, {error}"
                );
            }
        }
    }

    /// At a look, a reply of the daemon's own (the refusal of the hello) shows that a daemon answers,
    /// and nothing else of a failed connection does.
    #[test]
    fn a_look_reads_a_refusal_of_the_hello_as_an_answer() {
        assert!(Answered::of_reply(&the_hellos_refusal()).is_some());
        for error in own_faults() {
            assert!(Answered::of_reply(&error).is_none(), "{error}");
        }
        for error in [
            kr_ipc::IpcError::PeerClosed,
            a_frame_cut_by_the_end(),
            a_spoiled_frame(),
        ] {
            assert!(Answered::of_reply(&error).is_none(), "{error}");
        }
    }

    /// This side's own fault ends with exit 3 and its own words, and never with the silence
    /// sentence ("does not answer") or a word that a host still answers.
    #[test]
    fn this_sides_own_fault_says_its_own_words_with_exit_3() {
        let id = an_environment();
        for fault in own_faults() {
            let why = Shown::ipc(&fault);
            for error in [
                unmade_request(Which::Stop, id, &why, Unmade::OwnFault),
                unreached(Which::Stop, id, &fault, Unmade::OwnFault),
            ] {
                assert_eq!(error.exit_code(), 3, "{fault}");
                let said = error.to_string();
                assert!(said.contains(&why.to_string()), "{said}");
                assert!(!said.contains("does not answer"), "{said}");
            }
        }
    }

    /// Where the command ends a request that could not be made by what the failure came to, this
    /// side's own fault ends with exit 3 and its own words, whole. It never ends with the silence
    /// sentence, which is for a daemon that closed the connection and was not shown to have ended,
    /// and it says no word that a host still answers.
    #[tokio::test(start_paused = true)]
    async fn an_own_fault_at_an_unmade_request_ends_with_exit_3_and_its_own_words() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let process = asked_process();
        for fault in own_faults() {
            let supplied = Supplied::new()
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![at_once(Endpoint::Nobody)]);
            let before = failed_before_the_request(
                &supplied,
                supplied.connection(),
                Some(&process),
                &fault,
                id,
                the_deadline(),
            )
            .await;
            match unmade_ended(
                Which::Stop,
                before,
                &fault,
                id,
                &environment,
                &none,
                true,
                &earlier,
            ) {
                Completion::Reported(error) => {
                    assert_eq!(error.exit_code(), 3, "{fault}");
                    let said = error.to_string();
                    assert_eq!(
                        said,
                        format!(
                            "kr host stop could not make its request for the control daemon of \
                             environment {id}: {}. Nothing was sent, and nothing was stopped.",
                            Shown::ipc(&fault)
                        ),
                        "{fault}"
                    );
                    assert!(!said.contains("does not answer"), "{said}");
                    assert!(!said.contains("still answers"), "{said}");
                }
                _ => panic!("this side's own fault is a failure that the command has reported"),
            }
        }
    }

    /// At the wait's bound with the request written, the command says that the daemon has not ended
    /// only with a sign of life in the last round. With the lock free, no process identity and the
    /// last look unclear (an earlier look that showed the same daemon is no sign at the bound), it
    /// says what it knows and not that the daemon runs: exit 1, the whole text, for a daemon that was
    /// told and for one whose answer was not shown.
    #[tokio::test(start_paused = true)]
    async fn a_free_lock_and_an_unclear_last_look_do_not_say_that_the_daemon_has_not_ended() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let failure = Shown::said("the connection was lost");
        for (early_same, not_known, expected) in [
            (
                false,
                None,
                format!(
                    "The control daemon for environment {id} was told to stop. After 30 seconds \
                     the lock was free, and the last look at the endpoint showed neither that the \
                     daemon still runs nor that it had gone, so the command could not confirm the \
                     end. Run kr host stop again in a moment; it looks again."
                ),
            ),
            (
                true,
                Some(&failure),
                format!(
                    "The control daemon for environment {id} did not show whether it took the stop \
                     (the connection was lost). After 30 seconds the lock was free, and the last \
                     look at the endpoint showed neither that the daemon still runs nor that it \
                     had gone, so the command could not confirm the end. Run kr host stop again in \
                     a moment; it looks again."
                ),
            ),
        ] {
            let looks = if early_same {
                vec![
                    at_once(Endpoint::Same(an_answer())),
                    at_once(Endpoint::Unclear),
                ]
            } else {
                vec![at_once(Endpoint::Unclear)]
            };
            let supplied = Supplied::new().held(vec![at_once(Ok(false))]).look(looks);
            let End::NotEnded(why, _) = wait_for_the_end(&supplied, None, END_BOUND).await else {
                panic!("the daemon is not shown to have ended");
            };
            assert!(
                matches!(why, Why::NotShown),
                "early look of the daemon {early_same}"
            );
            let error = CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: not_ended_said(why, not_known, &paths, id, None),
            };
            assert_eq!(error.exit_code(), 1);
            assert_eq!(error.to_string(), expected);
        }
    }

    /// With the environment's lock read as held and no usable reading of the process, and no proved
    /// answer of the daemon asked, the command says that the environment was still held and that
    /// it could not show what holds it: exit 1, the whole text, and the `stop` member of a told
    /// request or of one whose outcome was not shown.
    #[tokio::test(start_paused = true)]
    async fn a_held_lock_with_no_usable_reading_of_the_process_says_what_the_lock_shows() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let failure = Shown::said("the connection was lost");
        for (request, expected, stop) in [
            (
                Request::Told,
                format!(
                    "The control daemon for environment {id} was told to stop. After 30 seconds \
                     the environment was still held, and the command could not show what holds \
                     it, so it could not confirm the end. Run kr host stop again in a moment; it \
                     looks again."
                ),
                "told",
            ),
            (
                Request::MaybeAsked(failure),
                format!(
                    "The control daemon for environment {id} did not show whether it took the \
                     stop (the connection was lost). After 30 seconds the environment was still \
                     held, and the command could not show what holds it, so it could not confirm \
                     the end. Run kr host stop again in a moment; it looks again."
                ),
                "maybe_asked",
            ),
        ] {
            for look in [
                Endpoint::Nobody,
                Endpoint::Unproved(an_answer()),
                Endpoint::Unclear,
            ] {
                let supplied = Supplied::new()
                    .held(vec![at_once(Ok(true))])
                    .look(vec![at_once(look)]);
                let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
                assert_eq!(said(&ended), "not ended, held, not shown", "{look:?}");
                let said = said_after_the_request(ended, &request);
                assert_eq!((said.exit, said.stop.word()), (Exit::Unfinished, stop));
                let words = words_after_the_request(
                    Which::Stop,
                    &said.sentence,
                    &request,
                    &paths,
                    id,
                    None,
                    None,
                );
                let error = Exit::Unfinished
                    .failure(words)
                    .expect("a failure that the command reports");
                assert_eq!(error.exit_code(), 1);
                assert_eq!(error.to_string(), expected, "{look:?}");
            }
        }
    }

    /// The last look that shows the same daemon, with the lock free, is a sign of life and an
    /// answer: the daemon has not ended, and the words say so.
    #[tokio::test(start_paused = true)]
    async fn a_last_look_of_the_same_daemon_with_a_free_lock_says_that_it_has_not_ended() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let supplied = Supplied::new().held(vec![at_once(Ok(false))]).look(vec![
            at_once(Endpoint::Unclear),
            at_once(Endpoint::Same(an_answer())),
        ]);
        let End::NotEnded(why, _) = wait_for_the_end(&supplied, None, END_BOUND).await else {
            panic!("the daemon still answers");
        };
        assert!(matches!(why, Why::Answers));
        let said = not_ended_said(why, None, &paths, id, None).to_string();
        assert!(
            said.starts_with(&format!(
                "The control daemon for environment {id} was told to stop and has not ended after 30 seconds."
            )),
            "{said}"
        );
    }

    /// An answer proves the daemon that was asked only by the generation that it reports. Where the
    /// generation asked is not known, or the answer names none, the answer proves nothing of which
    /// daemon it is.
    #[test]
    fn an_answer_proves_the_daemon_only_by_the_generation_that_was_asked() {
        let one = ControllerGeneration::new(1);
        let two = ControllerGeneration::new(2);
        assert!(matches!(by_generation(Some(one), one), Endpoint::Same(_)));
        assert!(matches!(by_generation(Some(one), two), Endpoint::Another));
        assert!(matches!(by_generation(None, one), Endpoint::Unproved(_)));
        assert!(matches!(by_generation(None, two), Endpoint::Unproved(_)));
    }

    /// An answer with no proved generation shows that something answers at the endpoint, and
    /// neither that the daemon that was asked runs nor that it has ended. After a request that
    /// was written, with the process read as ended and the lock held by a holder that is not named,
    /// the command says what the lock shows ("has gone, and something ... still holds"), for a
    /// told stop and for one whose outcome was not shown: it does not say that the daemon has not
    /// ended. With no usable reading of the process and the lock free, it says that the end was not
    /// confirmed. Where the request could not be made, any answer is an answer.
    #[tokio::test(start_paused = true)]
    async fn an_answer_with_no_proved_generation_is_no_sign_of_life_and_no_sign_of_an_end() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let process = asked_process();
        let failure = Shown::said("the connection was lost");
        let unproved = || at_once(Endpoint::Unproved(an_answer()));
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(true))])
            .process(vec![at_once(ProcessState::Ended)])
            .look(vec![unproved()]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(said(&ended), "not ended, held");
        let End::NotEnded(why, answered) = ended else {
            panic!("the daemon is not shown to have ended");
        };
        assert!(answered.is_some(), "something answered the last look");
        assert!(matches!(why, Why::Held));
        for not_known in [None, Some(&failure)] {
            let said = not_ended_said(Why::Held, not_known, &paths, id, Some(&process)).to_string();
            assert!(
                said.starts_with(&format!(
                    "The process of the control daemon for environment {id} has gone, and something \
                     that is not shown to be a control daemon still holds the environment"
                )),
                "{said}"
            );
            assert!(!said.contains("has not ended"), "{said}");
        }
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(false))])
            .look(vec![unproved()]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, not shown");
        for old in [None, Some(&process)] {
            let supplied = Supplied::new().look(vec![unproved()]);
            let ended = arm(&supplied, old, false).await;
            assert_eq!(arm_said(ended.as_ref()), "the request's failure", "{old:?}");
            let supplied = Supplied::new()
                .held(vec![at_once(Ok(true))])
                .process(vec![at_once(ProcessState::Ended)])
                .look(vec![unproved()]);
            let ended = arm(&supplied, old, true).await;
            assert_eq!(arm_said(ended.as_ref()), "the request's failure", "{old:?}");
        }
    }

    /// A lock that is held and a process that cannot be read (no identity, as on Windows) is a
    /// daemon that is not shown to have ended: the silence sentence, exit 1, after the whole bound.
    #[tokio::test(start_paused = true)]
    async fn a_held_lock_with_no_process_identity_is_silence_after_the_bound() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let _held = SingletonLock::hold(&paths.singleton_lock(), id).expect("takes the lock");
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(true))])
            .look(vec![at_once(Endpoint::Nobody)])
            .named(vec![at_once(None)]);
        let closed = kr_ipc::IpcError::PeerClosed;
        let before = failed_before_the_request(
            &supplied,
            supplied.connection(),
            None,
            &closed,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        assert_eq!(supplied.start.elapsed(), END_BOUND);
        match unmade_ended(
            Which::Stop,
            before,
            &closed,
            id,
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Completion::Reported(error) => {
                assert_eq!(error.exit_code(), 1);
                assert!(
                    error
                        .to_string()
                        .contains("does not answer, so it may be starting or stopping"),
                    "{error}"
                );
            }
            _ => panic!("a silent end is a failure that the command has reported"),
        }
    }

    fn a_refusal() -> ProtocolError {
        ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the daemon will not take a stop",
        )
    }

    /// A probe whose connection fails is no answer to the probe, as one that is not answered in its
    /// bound is none: the daemon's refusal is the result, and nothing was stopped.
    #[test]
    fn a_probe_that_fails_on_its_connection_leaves_the_daemons_refusal() {
        let id = an_environment();
        for probe in [
            None,
            Some(Err(kr_ipc::IpcError::PeerClosed)),
            Some(Err(a_frame_cut_by_the_end())),
            Some(Err(a_spoiled_frame())),
            Some(Err(kr_ipc::IpcError::UnexpectedMessage(
                "a frame of another kind",
            ))),
            Some(Err(a_fault_of_the_socket())),
        ] {
            match after_the_probe(Which::Stop, id, a_refusal(), probe) {
                CliError::Refused(refusal) => {
                    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
                }
                other => panic!("the refusal is the result, not {other}"),
            }
        }
        let withheld = ProtocolError::new(ErrorCode::PermissionDenied, "the check is refused too");
        let said =
            after_the_probe(Which::Stop, id, a_refusal(), Some(Ok(Err(withheld)))).to_string();
        assert!(
            said.contains("takes no stop request or refuses it")
                && said.contains("Nothing was stopped"),
            "the check's own refusal is shown in this command's words: {said}"
        );
        let another = ProtocolError::new(ErrorCode::ResourceUnavailable, "the daemon is busy");
        match after_the_probe(Which::Stop, id, a_refusal(), Some(Ok(Err(another)))) {
            CliError::Refused(refusal) => assert_eq!(refusal.code, ErrorCode::ResourceUnavailable),
            other => panic!("another refusal of the probe is shown as it is, not {other}"),
        }
        match after_the_probe(Which::Stop, id, a_refusal(), Some(Ok(Ok(())))) {
            CliError::Unfinished { message, .. } => {
                assert!(message.to_string().contains("takes no stop request"));
            }
            other => panic!("a daemon that answers the probe is of another build, not {other}"),
        }
    }

    /// The daemon's side of a greeting: accepts the next connection, reads its hello and answers it.
    async fn greet(
        listener: &kr_ipc::endpoint::Listener,
        id: EnvironmentId,
    ) -> (kr_ipc::framed::FrameReader, kr_ipc::framed::FrameWriter) {
        greet_selecting(listener, id, kr_protocol::hello::PROTOCOL_VERSION).await
    }

    /// The daemon's side of a greeting that answers the hello with `selected_version`.
    async fn greet_selecting(
        listener: &kr_ipc::endpoint::Listener,
        id: EnvironmentId,
        selected_version: kr_protocol::hello::ProtocolVersion,
    ) -> (kr_ipc::framed::FrameReader, kr_ipc::framed::FrameWriter) {
        use kr_protocol::scalars::CanonicalSet;

        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let boot_epoch = kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch");
        let (connection, peer) = listener.accept().await.expect("a connection");
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
        let hello = reader
            .read_message::<ControlFrame>()
            .await
            .expect("a hello");
        assert!(
            matches!(hello, ControlFrame::Hello(_)),
            "the client says hello"
        );
        let ack = kr_protocol::local::LocalHelloAck {
            selected_version,
            role: kr_protocol::local::LocalRole::Controller,
            connection_id,
            environment_id: id,
            boot_identity: boot,
            peer: peer.to_wire(),
            action_window: kr_protocol::hello::ActionWindow {
                action_window_id: kr_protocol::ids::ActionWindowId::new("test-daemon")
                    .expect("a window identifier"),
                connection_id,
                boot_epoch,
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                valid_for_ms: kr_protocol::scalars::DurationMs::new(600_000),
            },
            capabilities: CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
            build: Some(kr_protocol::local::LocalBuild {
                build_id: crate::build_id(),
                protocol_version: kr_protocol::hello::PACKAGE_VERSION,
            }),
        };
        writer
            .write_message(&ControlFrame::HelloAck(Box::new(ack)))
            .await
            .expect("the ack");
        (reader, writer)
    }

    /// How a daemon closes the connection after its hello.
    #[derive(Clone, Copy, Debug)]
    enum Closure {
        /// With nothing more to say: the end of the stream at a frame boundary.
        Clean,
        /// After a frame that cannot be read.
        BadFrame,
        /// After a frame of which the last bytes are missing: the end of the stream inside a frame.
        HalfFrame,
    }

    /// What a daemon writes before it closes the connection after its hello, as `closure` says.
    async fn close_after_the_hello(writer: &mut kr_ipc::framed::FrameWriter, closure: Closure) {
        let codec = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control);
        match closure {
            Closure::Clean => {}
            Closure::BadFrame => {
                let bytes = codec.encode(&[0xff, 0xff]).expect("frames");
                writer.write_frame(&bytes).await.expect("the bad frame");
            }
            Closure::HalfFrame => {
                let bytes = codec.encode(&[0_u8; 16]).expect("frames");
                writer
                    .write_frame(&bytes[..bytes.len() - 3])
                    .await
                    .expect("half a frame");
            }
        }
    }

    /// What `ask` makes of a request it cannot compose on a connection whose daemon says its hello
    /// and then closes the connection as `closure` says: the `closed` that it gives, from the real
    /// failure of the real client.
    async fn closed_after_the_hello(closure: Closure) -> bool {
        use kr_ipc::client::LocalClient;
        use kr_protocol::local::LocalClientKind;

        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(async move {
            let (_reader, mut writer) = greet(&listener, id).await;
            close_after_the_hello(&mut writer, closure).await;
            // The connection closes here, with the answer and the frame already written.
        });
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id())
            .await
            .expect("connects");
        daemon.await.expect("the daemon has closed the connection");
        let progress = Progress {
            stage: AtomicU8::new(Stage::BeforeAsking as u8),
            marker: Mutex::new(None),
            environment_id: id,
            earlier: Mutex::new(Vec::new()),
        };
        match ask(&mut client, id, true, &progress, false).await {
            Asked::NotComposed { error } => closed_by_the_daemon(&error),
            _ => panic!("the request could be composed"),
        }
    }

    /// What `ask` writes on a real connection for `launch_only`, with the same request composed by
    /// hand on the same connection for `launch_only` and for its opposite, and the stage that the
    /// command is at afterwards.
    async fn request_written_for(
        launch_only: bool,
    ) -> (
        kr_protocol::envelope::MutationRequest,
        kr_protocol::envelope::MutationRequest,
        kr_protocol::envelope::MutationRequest,
        Stage,
    ) {
        use kr_ipc::client::LocalClient;
        use kr_protocol::local::LocalClientKind;

        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(async move {
            let (mut reader, mut writer) = greet(&listener, id).await;
            let ControlFrame::Mutation(request) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("the read request")
            else {
                panic!("the command writes a mutation");
            };
            writer
                .write_message(&ControlFrame::Response(kr_protocol::envelope::Response {
                    request_id: request.request_id,
                    outcome: Outcome::Error(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "refused for the case",
                    )),
                }))
                .await
                .expect("the refusal");
            *request
        });
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id())
            .await
            .expect("connects");
        let progress = Progress {
            stage: AtomicU8::new(Stage::BeforeAsking as u8),
            marker: Mutex::new(None),
            environment_id: id,
            earlier: Mutex::new(Vec::new()),
        };
        let mut same = client
            .compose(
                Method::HostStop,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(id),
                &HostStopParams { launch_only },
            )
            .await
            .expect("composes");
        let mut other = client
            .compose(
                Method::HostStop,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(id),
                &HostStopParams {
                    launch_only: !launch_only,
                },
            )
            .await
            .expect("composes");
        let _ = ask(&mut client, id, true, &progress, launch_only).await;
        let written = daemon.await.expect("the daemon read the request");
        for composed in [&mut same, &mut other] {
            composed.action_id = written.action_id;
            composed.request_id = written.request_id;
        }
        (written, same, other, progress.stage())
    }

    /// The request that `ask` writes for a stop is the one composed by hand with `launch_only`
    /// false, whatever its identifiers: the same method, version, target, preconditions, window,
    /// lifetime and parameters, and not the request for the launch alone. The command is at the
    /// stage that says it asked.
    #[tokio::test]
    async fn the_request_a_stop_writes_is_the_one_composed_with_launch_only_false() {
        let (written, same, other, stage) = request_written_for(false).await;
        assert_eq!(written, same);
        assert_ne!(written, other, "the control: the other request differs");
        assert_eq!(stage, Stage::Asked);
    }

    /// The request that `ask` writes for the launch alone is the one composed by hand with
    /// `launch_only` true, and it enters no stage: nothing is asked to stop, so an interrupt has no
    /// request to speak of.
    #[tokio::test]
    async fn the_request_for_the_launch_alone_is_composed_with_launch_only_true_and_enters_no_stage()
     {
        let (written, same, other, stage) = request_written_for(true).await;
        assert_eq!(written, same);
        assert_ne!(written, other, "the control: the other request differs");
        assert_eq!(stage, Stage::BeforeAsking);
    }

    /// A connection that the daemon closed is a closed connection, as the command reads the failure
    /// of the real client's compose.
    #[tokio::test]
    async fn the_failure_of_a_closed_peer_is_a_closed_connection() {
        assert!(closed_after_the_hello(Closure::Clean).await);
        assert!(closed_by_the_daemon(&kr_ipc::IpcError::PeerClosed));
    }

    /// A frame that the daemon's end cut is a closed connection too: the end of the stream inside
    /// a frame is the daemon going, from the real failure of the real client.
    #[tokio::test]
    async fn the_failure_of_a_frame_cut_by_the_close_is_a_closed_connection() {
        assert!(closed_after_the_hello(Closure::HalfFrame).await);
        assert!(closed_by_the_daemon(&a_frame_cut_by_the_end()));
    }

    /// A frame that cannot be read is not a close: the command takes the daemon for one that
    /// stays and looks at its endpoint.
    #[tokio::test]
    async fn the_failure_of_a_bad_frame_is_not_a_closed_connection() {
        assert!(!closed_after_the_hello(Closure::BadFrame).await);
        assert!(!closed_by_the_daemon(&kr_ipc::IpcError::UnexpectedMessage(
            "a frame of another kind"
        )));
    }

    /// What the daemon does to the connection that `host_info` opens again after the first was
    /// refused for a withdrawn authority.
    #[derive(Clone, Copy)]
    enum Retry {
        /// The daemon has ended: nothing listens when the command connects again.
        Gone,
        /// The daemon accepts the new connection and closes it before it answers the hello.
        Closes,
    }

    /// What `host_info` gives where a daemon refuses its first request for a withdrawn authority
    /// and then ends or closes the connection that the retry opens: the real failure of the real
    /// client.
    async fn host_info_whose_retry_meets(retry: Retry) -> Result<HostInfoResult> {
        use kr_ipc::client::LocalClient;
        use kr_protocol::local::LocalClientKind;

        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(async move {
            let (mut reader, mut writer) = greet(&listener, id).await;
            let ControlFrame::Request(request) = reader
                .read_message::<ControlFrame>()
                .await
                .expect("the read request")
            else {
                panic!("the command asks for host.info");
            };
            // A daemon that has ended is not listening when the answer reaches the command.
            let listener = match retry {
                Retry::Gone => {
                    drop(listener);
                    None
                }
                Retry::Closes => Some(listener),
            };
            writer
                .write_message(&ControlFrame::Response(kr_protocol::envelope::Response {
                    request_id: request.request_id,
                    outcome: Outcome::Error(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the authority behind this connection was withdrawn",
                    )),
                }))
                .await
                .expect("the refusal");
            if let Some(listener) = listener {
                let (connection, _peer) = listener.accept().await.expect("the new connection");
                drop(connection);
            }
        });
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id())
            .await
            .expect("connects");
        let read = host_info(&mut client, &environment).await;
        daemon.await.expect("the daemon has done its part");
        read
    }

    /// The connection that `host_info` opens again keeps its transport error where the daemon has
    /// ended or closes it, so that the command judges it by the daemon's end before anything says
    /// that no host runs.
    #[tokio::test]
    async fn the_retry_of_the_host_info_read_keeps_its_transport_error() {
        match host_info_whose_retry_meets(Retry::Gone).await {
            Err(CliError::Ipc(_)) => {}
            Err(other) => panic!("a daemon that has gone leaves the transport error, not {other}"),
            Ok(_) => panic!("the read was refused"),
        }
        match host_info_whose_retry_meets(Retry::Closes).await {
            Err(CliError::Ipc(error)) => assert!(closed_by_the_daemon(&error), "{error}"),
            Err(other) => panic!("a closed connection leaves the transport error, not {other}"),
            Ok(_) => panic!("the read was refused"),
        }
    }

    // The look's exchange at its producers: a stand-in daemon on a real link does each thing that
    // the exchange can meet, and the look's value and label are read from the real client.

    /// A `host.info` result as a daemon of `generation` answers it.
    fn host_info_of(generation: ControllerGeneration) -> HostInfoResult {
        use kr_protocol::scalars::{Nullable, TimestampMs, U64};

        HostInfoResult {
            build_id: kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier"),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16])),
            generation,
            boot_identity: kr_protocol::identity::BootIdentity {
                source: kr_protocol::identity::BootIdentitySource::BootTime,
                value: kr_protocol::scalars::Bytes::new(Vec::new()),
            },
            started_at_ms: TimestampMs::new(1_700_000_000_000),
            live_sessions: U64::new(0),
            session_limit: U64::new(8),
            default_worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            power: kr_protocol::desktop::SleepInhibitionState {
                holder: Nullable::null(),
                withheld_reason: Nullable::null(),
                ..kr_protocol::desktop::SleepInhibitionState::off(
                    kr_protocol::desktop::InhibitionMechanism::None,
                    kr_protocol::desktop::PowerSource::Unknown,
                )
            },
            machine: None,
            privacy: None,
            default_shell_mode: None,
        }
    }

    /// What a stand-in daemon does with the exchange of a look.
    #[derive(Clone, Copy, Debug)]
    enum Peer {
        /// Nothing listens at the endpoint.
        NobodyListens,
        /// It accepts the connection, reads the hello and says nothing.
        SaysNothingToTheHello,
        /// It reads the hello and closes the connection before it answers.
        ClosesBeforeTheHello,
        /// It answers the hello with a refusal.
        RefusesTheHello,
        /// It answers the hello with a version that does not fit.
        AnswersAnotherVersion,
        /// It answers the hello with a frame that is not an acknowledgement.
        AnswersTheHelloWithAnotherKind,
        /// It acknowledges the hello and closes the connection as the closure says.
        ClosesAfterTheHello(Closure),
        /// It acknowledges the hello and says nothing to the read.
        SaysNothingToTheRead,
        /// It acknowledges the hello and answers the read with the generation that it reports.
        Reports(ControllerGeneration),
        /// It acknowledges the hello and refuses the read.
        RefusesTheRead,
        /// It acknowledges the hello and answers the read with a result that does not decode.
        AnswersWhatDoesNotDecode,
        /// It acknowledges the hello and answers the read with a frame for another request.
        AnswersAnotherKind,
        /// It acknowledges the hello and answers the read with a refusal of the link.
        FencesTheLink,
        /// It acknowledges the hello and answers the read after the look's bound.
        AnswersAfterTheBound,
    }

    /// The bound of a look at a peer that answers, and of one that does not: the look is made with
    /// the shorter one where the peer's answer does not come within it, so that the case waits for
    /// the bound and no longer.
    const LOOK_BOUND_FOR_AN_ANSWER: Duration = Duration::from_secs(1);
    const LOOK_BOUND_FOR_SILENCE: Duration = Duration::from_millis(300);

    /// A frame that a daemon writes as an outcome.
    async fn write_outcome(
        writer: &mut kr_ipc::framed::FrameWriter,
        request_id: kr_protocol::ids::RequestId,
        outcome: Outcome,
    ) {
        // The look may have ended and let go of its end of the connection.
        let _ = writer
            .write_message(&ControlFrame::Response(kr_protocol::envelope::Response {
                request_id,
                outcome,
            }))
            .await;
    }

    /// The daemon's refusal, as a protocol error that may fence the link.
    fn refused(link_fenced: bool) -> Outcome {
        Outcome::Error(ProtocolError {
            link_fenced,
            ..ProtocolError::new(ErrorCode::PermissionDenied, "the daemon will not say")
        })
    }

    /// The stand-in daemon's side of the exchange: the connection, then what `peer` does.
    async fn stand_in(listener: kr_ipc::endpoint::Listener, id: EnvironmentId, peer: Peer) {
        use kr_protocol::ids::RequestId;

        match peer {
            Peer::NobodyListens => {}
            Peer::SaysNothingToTheHello => {
                let (connection, _peer) = listener.accept().await.expect("a connection");
                let (mut reader, _writer) =
                    kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                reader
                    .read_message::<ControlFrame>()
                    .await
                    .expect("a hello");
                std::future::pending::<()>().await;
            }
            Peer::ClosesBeforeTheHello => {
                let (connection, _peer) = listener.accept().await.expect("a connection");
                let (mut reader, writer) =
                    kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                reader
                    .read_message::<ControlFrame>()
                    .await
                    .expect("a hello");
                drop(writer);
            }
            Peer::RefusesTheHello | Peer::AnswersTheHelloWithAnotherKind => {
                let (connection, _peer) = listener.accept().await.expect("a connection");
                let (mut reader, mut writer) =
                    kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                reader
                    .read_message::<ControlFrame>()
                    .await
                    .expect("a hello");
                let outcome = if matches!(peer, Peer::RefusesTheHello) {
                    refused(false)
                } else {
                    Outcome::Ok(kr_protocol::envelope::ParamsValue::empty())
                };
                write_outcome(&mut writer, RequestId::new(0), outcome).await;
            }
            Peer::AnswersAnotherVersion => {
                let version = kr_protocol::hello::ProtocolVersion::new(
                    kr_protocol::hello::PROTOCOL_VERSION.major + 1,
                    0,
                );
                let _ = greet_selecting(&listener, id, version).await;
            }
            Peer::ClosesAfterTheHello(closure) => {
                let (_reader, mut writer) = greet(&listener, id).await;
                close_after_the_hello(&mut writer, closure).await;
            }
            read_peer => {
                let (mut reader, mut writer) = greet(&listener, id).await;
                let ControlFrame::Request(request) = reader
                    .read_message::<ControlFrame>()
                    .await
                    .expect("the read request")
                else {
                    panic!("the look asks for host.info");
                };
                answer_the_read(read_peer, request.request_id, &mut writer).await;
            }
        }
    }

    /// What a daemon that acknowledged the hello does with the read of `host.info`.
    async fn answer_the_read(
        peer: Peer,
        asked: kr_protocol::ids::RequestId,
        writer: &mut kr_ipc::framed::FrameWriter,
    ) {
        let empty = || Outcome::Ok(kr_protocol::envelope::ParamsValue::empty());
        let info = |generation| {
            Outcome::Ok(
                kr_protocol::envelope::ParamsValue::from_typed(&host_info_of(generation))
                    .expect("a host.info result"),
            )
        };
        match peer {
            Peer::Reports(generation) => write_outcome(writer, asked, info(generation)).await,
            Peer::RefusesTheRead => write_outcome(writer, asked, refused(false)).await,
            Peer::FencesTheLink => write_outcome(writer, asked, refused(true)).await,
            Peer::AnswersWhatDoesNotDecode => write_outcome(writer, asked, empty()).await,
            Peer::AnswersAnotherKind => {
                write_outcome(writer, kr_protocol::ids::RequestId::new(u64::MAX), empty()).await;
            }
            Peer::AnswersAfterTheBound => {
                tokio::time::sleep(LOOK_BOUND_FOR_SILENCE * 4).await;
                write_outcome(writer, asked, info(ControllerGeneration::new(1))).await;
            }
            other => {
                assert!(
                    matches!(other, Peer::SaysNothingToTheRead),
                    "{other:?} answers before the read"
                );
                std::future::pending::<()>().await;
            }
        }
    }

    /// The environment that a stand-in daemon listens for, the bound of a look at it, and the
    /// stand-in's task, where one listens.
    fn a_stand_in_for(
        peer: Peer,
    ) -> (
        kr_ipc::testing::TempHost,
        EnvironmentPaths,
        Duration,
        Option<tokio::task::JoinHandle<()>>,
    ) {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let within = if matches!(
            peer,
            Peer::SaysNothingToTheHello | Peer::SaysNothingToTheRead | Peer::AnswersAfterTheBound
        ) {
            LOOK_BOUND_FOR_SILENCE
        } else {
            LOOK_BOUND_FOR_AN_ANSWER
        };
        let daemon = if matches!(peer, Peer::NobodyListens) {
            None
        } else {
            let endpoint = environment.controller_endpoint().expect("an endpoint");
            let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
            Some(tokio::spawn(stand_in(listener, id, peer)))
        };
        (temp, environment, within, daemon)
    }

    /// What the exchange of a look at `peer` gave, from the real client on a real link.
    async fn the_exchange_with(peer: Peer) -> Gave {
        let (_temp, environment, within, daemon) = a_stand_in_for(peer);
        let gave = the_look_gave(&environment, within, &mut |_| {}).await;
        if let Some(daemon) = daemon {
            daemon.abort();
        }
        gave
    }

    /// A look takes no longer than one second, however much of the deadline is left: a daemon
    /// that says nothing to the hello is waited for until that second has gone, not until the
    /// deadline, and the look then shows nothing in time.
    #[tokio::test(start_paused = true)]
    async fn a_look_takes_no_longer_than_one_second_however_much_of_the_deadline_is_left() {
        let (_temp, environment, _within, daemon) = a_stand_in_for(Peer::SaysNothingToTheHello);
        let started = tokio::time::Instant::now();
        let gave = the_look_gave(&environment, seconds(30), &mut |_| {}).await;
        let taken = tokio::time::Instant::now() - started;
        if let Some(daemon) = daemon {
            daemon.abort();
        }
        assert!(matches!(gave, Gave::NothingInTime), "{gave:?}");
        assert_eq!(taken, seconds(1));
    }

    /// What a look at `peer` says answers at the endpoint, where the generation asked is `asked`.
    async fn look_at(peer: Peer, asked: Option<ControllerGeneration>) -> Endpoint {
        let (_temp, environment, within, daemon) = a_stand_in_for(peer);
        let look = endpoint_look(&environment, asked, within, &mut |_| {}).await;
        if let Some(daemon) = daemon {
            daemon.abort();
        }
        look
    }

    /// Every way that the exchange of a look can end that a stand-in daemon makes, the value that
    /// the exchange gives and the label that the look says, for the generation asked. The address
    /// that cannot be made has its own case; a daemon of another major cannot answer a look, which
    /// offers no other major.
    fn the_ways_the_exchange_ends() -> Vec<(Peer, Option<u64>, &'static str, &'static str)> {
        vec![
            (Peer::NobodyListens, Some(1), "nothing_listens", "nobody"),
            (
                Peer::ClosesBeforeTheHello,
                Some(1),
                "link_failed",
                "unclear",
            ),
            (
                Peer::SaysNothingToTheHello,
                Some(1),
                "nothing_in_time",
                "unclear",
            ),
            (
                Peer::RefusesTheHello,
                Some(1),
                "greeting_replied",
                "unproved",
            ),
            (
                Peer::AnswersAnotherVersion,
                Some(1),
                "greeting_replied",
                "unproved",
            ),
            (
                Peer::AnswersTheHelloWithAnotherKind,
                Some(1),
                "greeting_replied",
                "unproved",
            ),
            (
                Peer::ClosesAfterTheHello(Closure::Clean),
                Some(1),
                "greeting_then_link_failed",
                "unclear",
            ),
            (
                Peer::ClosesAfterTheHello(Closure::BadFrame),
                Some(1),
                "greeting_then_link_failed",
                "unclear",
            ),
            (
                Peer::ClosesAfterTheHello(Closure::HalfFrame),
                Some(1),
                "greeting_then_link_failed",
                "unclear",
            ),
            (
                Peer::SaysNothingToTheRead,
                Some(1),
                "nothing_in_time",
                "unclear",
            ),
            (
                Peer::AnswersAfterTheBound,
                Some(1),
                "nothing_in_time",
                "unclear",
            ),
            (
                Peer::Reports(ControllerGeneration::new(1)),
                Some(1),
                "reported",
                "same",
            ),
            (
                Peer::Reports(ControllerGeneration::new(2)),
                Some(1),
                "reported",
                "another",
            ),
            (
                Peer::Reports(ControllerGeneration::new(1)),
                None,
                "reported",
                "unproved",
            ),
            (Peer::RefusesTheRead, Some(1), "read_refused", "unproved"),
            (
                Peer::AnswersWhatDoesNotDecode,
                Some(1),
                "read_undecodable",
                "unproved",
            ),
            (
                Peer::AnswersAnotherKind,
                Some(1),
                "read_replied",
                "unproved",
            ),
            (Peer::FencesTheLink, Some(1), "read_replied", "unproved"),
        ]
    }

    /// Each way that the exchange ends gives its own value, and the look says what that value is
    /// labelled: the producers of the look's value, on a real link with a stand-in daemon.
    #[tokio::test]
    async fn the_exchange_of_a_look_gives_a_value_for_each_way_it_ends() {
        for (peer, asked, gave, label) in the_ways_the_exchange_ends() {
            assert_eq!(
                the_exchange_with(peer).await.label(),
                gave,
                "the value of the exchange with {peer:?}"
            );
            let asked = asked.map(ControllerGeneration::new);
            assert_eq!(
                Some(look_at(peer, asked).await).label(),
                label,
                "the label of the look at {peer:?}, asked {asked:?}"
            );
        }
    }

    /// A refusal of the hello is an answer of the daemon's own: a look that reads it as the same
    /// daemon, or as no answer, is wrong. It shows that something answers, and no generation.
    #[tokio::test]
    async fn a_refused_greeting_is_an_answer_that_proves_no_generation() {
        for asked in [None, Some(ControllerGeneration::new(1))] {
            assert!(
                matches!(
                    look_at(Peer::RefusesTheHello, asked).await,
                    Endpoint::Unproved(_)
                ),
                "asked {asked:?}"
            );
        }
    }

    /// The producers give a value by the source of a failure and by what an answer is, whatever
    /// made the failure: a connection that found nothing listening, a reply of the daemon's, a
    /// closure and this side's own fault, at the greeting and at the read.
    #[test]
    fn the_producers_give_a_value_by_the_source_of_a_failure() {
        use kr_ipc::IpcError;

        for kind in [
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NotFound,
        ] {
            let nothing = IpcError::socket("connect", std::io::Error::from(kind));
            assert_eq!(gave_by_the_greeting(&nothing).label(), "nothing_listens");
        }
        let replies = [
            the_hellos_refusal(),
            IpcError::LinkFenced {
                detail: "the worker refused the link".to_owned(),
            },
            IpcError::UnexpectedMessage("a frame of another kind"),
            IpcError::VersionMismatch {
                host: "1.0".to_owned(),
                offered: "2.0".to_owned(),
            },
        ];
        let failures = [
            IpcError::PeerClosed,
            a_frame_cut_by_the_end(),
            a_spoiled_frame(),
        ];
        for reply in &replies {
            assert_eq!(
                gave_by_the_greeting(reply).label(),
                "greeting_replied",
                "{reply}"
            );
            assert_eq!(
                gave_by_the_read(Err(IpcError::UnexpectedMessage("x"))).label(),
                "read_replied"
            );
        }
        for failure in failures.iter().chain(own_faults().iter()) {
            assert_eq!(
                gave_by_the_greeting(failure).label(),
                "link_failed",
                "{failure}"
            );
        }
        for failure in failures {
            assert_eq!(
                gave_by_the_read(Err(failure)).label(),
                "greeting_then_link_failed"
            );
        }
        for fault in own_faults() {
            assert_eq!(
                gave_by_the_read(Err(fault)).label(),
                "greeting_then_link_failed"
            );
        }
        for reply in replies {
            assert_eq!(gave_by_the_read(Err(reply)).label(), "read_replied");
        }
        assert_eq!(
            gave_by_the_read(Ok(Err(a_refusal()))).label(),
            "read_refused"
        );
        let empty = kr_protocol::envelope::ParamsValue::empty();
        assert_eq!(gave_by_the_read(Ok(Ok(empty))).label(), "read_undecodable");
        let info = kr_protocol::envelope::ParamsValue::from_typed(&host_info_of(
            ControllerGeneration::new(7),
        ))
        .expect("a host.info result");
        match gave_by_the_read(Ok(Ok(info))) {
            Gave::Reported(generation) => assert_eq!(generation, ControllerGeneration::new(7)),
            other => panic!("the generation that the daemon reports is the value, not {other:?}"),
        }
    }

    /// A daemon that states another major answers the greeting of a look that offered that major:
    /// the look gives another daemon, as the label says. The look itself offers no major, so this
    /// answer is read from the real client here and no look over a real link meets it.
    #[tokio::test]
    async fn a_daemon_of_another_major_that_answers_the_greeting_is_another_daemon() {
        let other = kr_protocol::hello::PROTOCOL_VERSION.major + 1;
        let (_temp, environment, within, daemon) = a_stand_in_for(Peer::AnswersAnotherVersion);
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let Reached::Answered(listed) = startup::reach(&endpoint, within, &[other]).await else {
            panic!("the daemon answers the greeting and the look offers its major");
        };
        let gave = gave_after_the_greeting(*listed, &mut |_| {}).await;
        assert_eq!(gave.label(), "greeting_of_another_major");
        assert!(matches!(label_of(None, gave), Endpoint::Another));
        if let Some(daemon) = daemon {
            daemon.abort();
        }
    }

    /// An address that cannot be made is a look that did not happen, whatever the generation asked:
    /// nothing was tried.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_address_that_cannot_be_made_gives_no_answer() {
        let parent = tempfile::tempdir().expect("a folder");
        let long = parent.path().join("a".repeat(150));
        std::fs::create_dir_all(&long).expect("a long folder");
        let temp = kr_ipc::testing::TempHost::create_in(&long);
        let environment = temp.environment();
        assert!(
            environment.controller_endpoint().is_err(),
            "the address is too long for a socket"
        );
        let gave = the_look_gave(&environment, LOOK_BOUND_FOR_AN_ANSWER, &mut |_| {}).await;
        assert_eq!(gave.label(), "no_address");
        assert!(matches!(
            endpoint_look(&environment, None, LOOK_BOUND_FOR_AN_ANSWER, &mut |_| {}).await,
            Endpoint::Unclear
        ));
    }

    /// With an identity whose process state the system did not say, and a lock that cannot be read
    /// in the last round, nothing shows that the daemon runs and nothing that it has gone: the
    /// wait ends as not looked at, and the words say that the end could not be read, with exit 1,
    /// whether the daemon was told or its outcome is not known.
    #[tokio::test(start_paused = true)]
    async fn an_unreadable_process_and_an_unreadable_lock_say_that_the_end_could_not_be_read() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let process = asked_process();
        let failure = Shown::said("the connection was lost");
        for (not_known, expected) in [
            (
                None,
                format!(
                    "The control daemon for environment {id} was told to stop, and whether it has \
                     ended could not be read after 30 seconds: the lock could not be taken. Run \
                     kr host stop again in a moment."
                ),
            ),
            (
                Some(&failure),
                format!(
                    "The control daemon for environment {id} did not show whether it took the \
                     stop (the connection was lost), and whether it has ended could not be read \
                     after 30 seconds: the lock could not be taken. Run kr host stop again in a \
                     moment."
                ),
            ),
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(Err(Shown::said(
                    "the lock could not be taken",
                )))])
                .process(vec![at_once(ProcessState::Unknown {
                    detail: "denied".to_owned(),
                })]);
            let End::NotEnded(why, _) =
                wait_for_the_end(&supplied, Some(&process), END_BOUND).await
            else {
                panic!("nothing shows that the daemon has ended");
            };
            assert!(matches!(why, Why::Unlooked(_)), "{not_known:?}");
            let error = CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: not_ended_said(why, not_known, &paths, id, Some(&process)),
            };
            assert_eq!(error.exit_code(), 1);
            assert_eq!(error.to_string(), expected);
        }
    }

    /// A write that fails at the level's check left nothing, and is a request that could not be
    /// made. Every other failure of the write may come after a part of the frame went: its outcome
    /// is unknown, whatever the source function says of it (a fault of the socket of another kind
    /// than nothing listening is this side's own, and part of the frame may have gone before it).
    /// A frame that cannot be encoded stays unknown: the roster's `Frame` row that differs.
    #[test]
    fn a_write_that_the_level_refused_left_nothing_and_any_other_failure_is_unknown() {
        let refused = kr_ipc::IpcError::NotInLevel("a field".to_owned());
        let said = refused.to_string();
        match after_the_write_failed(refused) {
            Asked::NotComposed { error } => assert_eq!(error.to_string(), said),
            _ => panic!("the level refused before any byte was written: {said}"),
        }
        for error in [
            kr_ipc::IpcError::PeerClosed,
            a_frame_cut_by_the_end(),
            a_spoiled_frame(),
            a_fault_of_the_socket(),
            kr_ipc::IpcError::socket(
                "write the control frame",
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ),
        ] {
            let said = Shown::ipc(&error).to_string();
            match after_the_write_failed(error) {
                Asked::Unknown(unknown) => assert_eq!(unknown.to_string(), said),
                _ => panic!("a failed write may have sent a part of the frame: {said}"),
            }
        }
    }

    /// A daemon that answers the last look of the wait is an answer, as one that answers the first
    /// look is. Where the request could not be made and the connection was closed, the wait reads
    /// its last look at the bound: the daemon that answers it stays, with exit 3 and the unmade
    /// request's words, and the command does not say that it does not answer. A look that showed
    /// nothing, and an answer of an earlier round only, leave the end not shown.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_answers_the_last_look_of_the_wait_is_an_answer() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let closed = kr_ipc::IpcError::PeerClosed;
        let same = || at_once(Endpoint::Same(an_answer()));
        for (held, looks, expected) in [
            (Ok(false), vec![same()], "answers"),
            (Ok(true), vec![same()], "answers"),
            (
                Ok(false),
                vec![same(), at_once(Endpoint::Unclear)],
                "silent",
            ),
            (Ok(true), vec![same(), at_once(Endpoint::Unclear)], "silent"),
            (Ok(false), vec![at_once(Endpoint::Unclear)], "silent"),
            (Ok(true), vec![at_once(Endpoint::Nobody)], "silent"),
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(held.clone())])
                .look(looks);
            let before = failed_before_the_request(
                &supplied,
                supplied.connection(),
                None,
                &closed,
                id,
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), expected, "{held:?}");
        }
        let supplied = Supplied::new().look(vec![same()]);
        let before = failed_before_the_request(
            &supplied,
            supplied.connection(),
            None,
            &closed,
            id,
            the_deadline(),
        )
        .await;
        match unmade_ended(
            Which::Stop,
            before,
            &closed,
            id,
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Completion::Reported(error) => {
                assert_eq!(error.exit_code(), 3);
                assert_eq!(
                    error.to_string(),
                    format!(
                        "kr host stop could not make its request for the control daemon of \
                         environment {id}: {}. Nothing was sent, and nothing was stopped.",
                        Shown::ipc(&closed)
                    )
                );
            }
            _ => panic!("a daemon that answers is a failure that the command has reported"),
        }
    }

    /// Where the daemon was seen to end after the request was written, the first sentence says
    /// that the command stopped it only where the daemon took the stop and answered, and otherwise
    /// says what the command knows: that the daemon did not show whether it took the stop, and
    /// that it has ended. The sentences after the first are the same, and the command ends with
    /// exit 0 either way.
    #[test]
    fn an_end_after_a_stop_that_was_told_says_stopped_and_one_not_known_says_what_is_known() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let failure = Shown::said("the connection was lost");
        let after = "No session was stopped: its workers keep running, a local attach keeps \
                     working, and the next daemon finds the sessions again. Paired devices' \
                     connections close until a daemon runs.";
        let creates = " 2 session creates were still under way after 10 seconds, when the daemon \
                       went on with its stop. Each of them finished or ended with the daemon.";
        for (said, expected) in [
            (
                gone_said(id, Some(4000), None, Some(0)),
                format!("Stopped the control daemon for environment {id} (process 4000). {after}"),
            ),
            (
                gone_said(id, None, None, Some(2)),
                format!("Stopped the control daemon for environment {id}. {after}{creates}"),
            ),
            (
                gone_said(id, Some(4000), Some(&failure), None),
                format!(
                    "The control daemon for environment {id} (process 4000) did not show whether \
                     it took the stop (the connection was lost), and it has ended. {after}"
                ),
            ),
            (
                gone_said(id, None, Some(&failure), None),
                format!(
                    "The control daemon for environment {id} did not show whether it took the \
                     stop (the connection was lost), and it has ended. {after}"
                ),
            ),
        ] {
            assert_eq!(said.to_string(), expected);
            let earlier = Earlier::read(&paths);
            let facts = Facts {
                knows: Knows::Ended,
                pid: Some(4000),
                unsettled: None,
                records: Vec::new(),
                answer: None,
            };
            assert!(
                matches!(done(&said, &facts, true, &earlier), Completion::Done),
                "an end that was seen is a result, with exit 0"
            );
        }
    }

    /// A lock that was free in an earlier round is no sign of life at a bound where the last
    /// round read it as held, and the other way round: the marks are the last round's. With no
    /// identity, a lock that is free in the first round and held in every later one is a held lock
    /// to the bound, which shows that the environment is held and not by whom, and not a free lock
    /// with a look that showed nothing.
    #[tokio::test(start_paused = true)]
    async fn a_lock_that_was_free_in_an_earlier_round_is_read_as_the_last_round_reads_it() {
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(false)), at_once(Ok(true))])
            .look(vec![at_once(Endpoint::Unclear)]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, held, not shown");
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(true)), at_once(Ok(false))])
            .look(vec![at_once(Endpoint::Unclear)]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, not shown");
    }

    /// The words of a daemon that has not ended, for the request that was told and the one whose
    /// outcome is not known, with exit 1. What follows (the process to end) depends on the platform.
    #[test]
    fn a_daemon_that_has_not_ended_says_so_for_a_stop_that_was_told_and_one_not_known() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let failure = Shown::said("the connection was lost");
        for (not_known, expected) in [
            (
                None,
                format!(
                    "The control daemon for environment {id} was told to stop and has not ended \
                     after 30 seconds. It may be finishing a write."
                ),
            ),
            (
                Some(&failure),
                format!(
                    "The control daemon for environment {id} did not show whether it took the \
                     stop (the connection was lost), and it has not ended after 30 seconds. It \
                     may be finishing a write."
                ),
            ),
        ] {
            for why in [Why::Running, Why::Answers] {
                let error = CliError::Unfinished {
                    code: ErrorCode::EnvironmentUnavailable,
                    message: not_ended_said(why, not_known, &paths, id, None),
                };
                assert_eq!(error.exit_code(), 1);
                assert!(error.to_string().starts_with(&expected), "{error}");
            }
        }
    }

    /// A connect that found nothing listening accepted no connection: where the end is not shown
    /// in the bound, the silence sentence ("accepted the connection and did not answer") is not
    /// said. A held lock keeps the sentence that a daemon holds the environment and does not
    /// answer; otherwise the request could not be made, with exit 3 and the connect's failure.
    /// A connection that was accepted and then closed keeps the silence sentence.
    #[tokio::test(start_paused = true)]
    async fn a_connect_that_found_nothing_listening_is_no_connection_that_did_not_answer() {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let id = paths.environment_id();
        let environment = KnownEnvironment {
            environment_id: id,
            paths,
        };
        let earlier = Earlier::read(&environment.paths);
        let none = Facts::none(Vec::new());
        let reported = |before: Before, error: &kr_ipc::IpcError| match unmade_ended(
            Which::Stop,
            before,
            error,
            id,
            &environment,
            &none,
            true,
            &earlier,
        ) {
            Completion::Reported(error) => error,
            _ => panic!("a failure that the command has reported"),
        };
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let nothing = kr_ipc::IpcError::socket("connect", std::io::Error::from(kind));
            let supplied = Supplied::new();
            let before = host_info_failed(
                &supplied,
                supplied.connection(),
                &nothing,
                None,
                id,
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), "silent, nothing accepted", "{kind:?}");
            let error = reported(before, &nothing);
            assert_eq!(error.exit_code(), 3);
            assert_eq!(
                error.to_string(),
                format!(
                    "kr host stop could not make its request for the control daemon of \
                     environment {id}: {}. Nothing was sent, and nothing was stopped.",
                    Shown::ipc(&nothing)
                )
            );
        }
        // A connection that was accepted and then closed: the silence sentence.
        let closed = kr_ipc::IpcError::PeerClosed;
        let supplied = Supplied::new();
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &closed,
            None,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent");
        let error = reported(before, &closed);
        assert_eq!(error.exit_code(), 1);
        assert_eq!(
            error.to_string(),
            format!(
                "the control daemon listening for environment {id} accepted the connection and \
                 did not answer within 30 seconds. No stop was requested. Run kr host stop again \
                 in a moment."
            )
        );
        // A held lock: a daemon holds the environment and does not answer, whatever failed.
        let held =
            SingletonLock::hold(&environment.paths.singleton_lock(), id).expect("takes the lock");
        let nothing = kr_ipc::IpcError::socket(
            "connect",
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        );
        let supplied = Supplied::new().held(vec![at_once(Ok(true))]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &nothing,
            None,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "silent, nothing accepted");
        let error = reported(before, &nothing);
        assert_eq!(error.exit_code(), 1);
        assert!(
            error
                .to_string()
                .contains("does not answer, so it may be starting or stopping"),
            "{error}"
        );
        drop(held);
    }

    // The table of the end's decision: every combination of what a round reads and of what a
    // request came to, walked, written into one file that the repository holds, and read by the
    // properties of the cases after it.

    /// A set whose every value is listed by a chain: `after` has an arm for each value in turn.
    /// For the eight sets of the product that the tables walk (`Lock`, `Process`, `Holder`,
    /// `Endpoint`, `Request`, `Start`, `Before` and `Gave`), the case
    /// `each_walk_sees_every_variant_of_its_set` compares the variants that a chain gives with a
    /// list of the set's variants that the compiler holds to the set, so that a variant added to
    /// one of them fails the test build until the list names it, and that case until the walk
    /// takes it.
    trait Every: Sized {
        fn first() -> Self;
        fn after(&self) -> Option<Self>;
    }

    /// Every value of `T`, from the chain.
    fn every<T: Every>() -> Vec<T> {
        let mut all = vec![T::first()];
        while let Some(next) = all.last().and_then(T::after) {
            all.push(next);
        }
        all
    }

    /// What a value is called in the table.
    trait Label {
        fn label(&self) -> String;
    }

    /// What a round's look showed: none where the round made none.
    type Look = Option<Endpoint>;

    impl Every for Lock {
        fn first() -> Self {
            Self::Free
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Free => Some(Self::Held),
                Self::Held => Some(Self::Unreadable(Shown::said("the lock could not be taken"))),
                Self::Unreadable(_) => None,
            }
        }
    }

    impl Label for Lock {
        fn label(&self) -> String {
            match self {
                Self::Free => "free",
                Self::Held => "held",
                Self::Unreadable(_) => "unreadable",
            }
            .to_owned()
        }
    }

    impl Every for Process {
        fn first() -> Self {
            Self::NoIdentity
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::NoIdentity => Some(Self::Running),
                Self::Running => Some(Self::Ended),
                Self::Ended => Some(Self::Unreadable),
                Self::Unreadable => None,
            }
        }
    }

    impl Label for Process {
        fn label(&self) -> String {
            match self {
                Self::NoIdentity => "no_identity",
                Self::Running => "running",
                Self::Ended => "ended",
                Self::Unreadable => "unreadable",
            }
            .to_owned()
        }
    }

    impl Every for Holder {
        fn first() -> Self {
            Self::NotRead
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::NotRead => Some(Self::Nobody),
                Self::Nobody => Some(Self::Asked),
                Self::Asked => Some(Self::Other(4001)),
                Self::Other(_) => None,
            }
        }
    }

    impl Label for Holder {
        fn label(&self) -> String {
            match self {
                Self::NotRead => "not_read",
                Self::Nobody => "nobody",
                Self::Asked => "asked",
                Self::Other(_) => "other",
            }
            .to_owned()
        }
    }

    impl Every for Look {
        fn first() -> Self {
            None
        }

        fn after(&self) -> Option<Self> {
            match self {
                None => Some(Some(Endpoint::Nobody)),
                Some(Endpoint::Nobody) => Some(Some(Endpoint::Same(an_answer()))),
                Some(Endpoint::Same(_)) => Some(Some(Endpoint::Unproved(an_answer()))),
                Some(Endpoint::Unproved(_)) => Some(Some(Endpoint::Another)),
                Some(Endpoint::Another) => Some(Some(Endpoint::Unclear)),
                Some(Endpoint::Unclear) => None,
            }
        }
    }

    impl Label for Look {
        fn label(&self) -> String {
            match self {
                None => "not_made",
                Some(Endpoint::Nobody) => "nobody",
                Some(Endpoint::Same(_)) => "same",
                Some(Endpoint::Unproved(_)) => "unproved",
                Some(Endpoint::Another) => "another",
                Some(Endpoint::Unclear) => "unclear",
            }
            .to_owned()
        }
    }

    impl Every for Request {
        fn first() -> Self {
            Self::Told
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Told => Some(Self::MaybeAsked(Shown::said("the connection was lost"))),
                Self::MaybeAsked(_) => None,
            }
        }
    }

    impl Label for Request {
        fn label(&self) -> String {
            match self {
                Self::Told => "told",
                Self::MaybeAsked(_) => "maybe_asked",
            }
            .to_owned()
        }
    }

    impl Every for Start {
        fn first() -> Self {
            Self::OtherMajor
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::OtherMajor => Some(Self::Silent),
                Self::Silent => Some(Self::NothingListening),
                Self::NothingListening => None,
            }
        }
    }

    impl Label for Start {
        fn label(&self) -> String {
            match self {
                Self::OtherMajor => "other_major",
                Self::Silent => "silent",
                Self::NothingListening => "nothing_listening",
            }
            .to_owned()
        }
    }

    impl Every for Before {
        fn first() -> Self {
            Self::Ended {
                said: Shown::said("the daemon ended"),
                pid: Some(4000),
                end: End::Gone,
            }
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Ended { .. } => Some(Self::Silent { accepted: true }),
                Self::Silent { accepted: true } => Some(Self::Silent { accepted: false }),
                Self::Silent { accepted: false } => Some(Self::Answers(an_answer())),
                Self::Answers(_) => Some(Self::OwnFault),
                Self::OwnFault => None,
            }
        }
    }

    impl Label for Before {
        fn label(&self) -> String {
            match self {
                Self::Ended { .. } => "ended",
                Self::Silent { accepted: true } => "silent_accepted",
                Self::Silent { accepted: false } => "silent_nothing_accepted",
                Self::Answers(_) => "answers",
                Self::OwnFault => "own_fault",
            }
            .to_owned()
        }
    }

    impl Label for Why {
        fn label(&self) -> String {
            match self {
                Self::Running => "running",
                Self::Answers => "answers",
                Self::NotShown => "not_shown",
                Self::Held => "held",
                Self::HeldNotShown => "held_not_shown",
                Self::Unlooked(_) => "unlooked",
            }
            .to_owned()
        }
    }

    impl Label for Option<End> {
        fn label(&self) -> String {
            match self {
                None => "go_on".to_owned(),
                Some(End::Gone) => "gone".to_owned(),
                Some(End::Successor(pid)) => format!(
                    "successor({})",
                    pid.map_or_else(|| "-".to_owned(), |pid| pid.to_string())
                ),
                Some(End::NotEnded(why, answered)) => format!(
                    "not_ended:{} answered={}",
                    why.label(),
                    if answered.is_some() { "yes" } else { "no" }
                ),
            }
        }
    }

    impl Label for AfterRequest {
        fn label(&self) -> String {
            match self {
                Self::Stopped => "stopped",
                Self::Successor(_) => "successor",
                Self::NotEnded => "not_ended",
                Self::NotShown => "not_shown",
                Self::StillHeld => "still_held",
                Self::HeldNotShown => "held_not_shown",
                Self::Unlooked(_) => "unlooked",
            }
            .to_owned()
        }
    }

    impl Label for BeforeRequest {
        fn label(&self) -> String {
            match self {
                Self::Ended { .. } => "ended",
                Self::HoldsAndSilent => "holds_and_is_silent",
                Self::Silent => "silent",
                Self::Unmade(Unmade::Answered(_)) => "unmade:answered",
                Self::Unmade(Unmade::OwnFault) => "unmade:own_fault",
                Self::Unmade(Unmade::NothingListening) => "unmade:nothing_listening",
            }
            .to_owned()
        }
    }

    impl Label for AtStart {
        fn label(&self) -> String {
            match self {
                Self::OtherMajor => "other_major",
                Self::NoDaemon => "no_daemon",
                Self::HoldsAndSilent => "holds_and_is_silent",
                Self::Silent => "silent",
                Self::LockUnreadable(_) => "lock_unreadable",
            }
            .to_owned()
        }
    }

    impl Label for Decided {
        fn label(&self) -> String {
            match self {
                Self::Ended(End::Gone) => "ended",
                Self::Ended(End::Successor(_)) => "ended_by_a_successor",
                Self::Ended(End::NotEnded(..)) => "ended?",
                Self::NotShown => "not_shown",
                Self::Answers(_) => "answers",
            }
            .to_owned()
        }
    }

    /// A reply of the daemon's own that cannot be used, for the walk.
    fn a_reply() -> Answered {
        Answered::of_refusal(&a_refusal())
    }

    impl Every for Gave {
        fn first() -> Self {
            Self::NoAddress
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::NoAddress => Some(Self::NothingInTime),
                Self::NothingInTime => Some(Self::NothingListens),
                Self::NothingListens => Some(Self::LinkFailed),
                Self::LinkFailed => Some(Self::GreetingThenLinkFailed),
                Self::GreetingThenLinkFailed => Some(Self::GreetingReplied(a_reply())),
                Self::GreetingReplied(_) => Some(Self::GreetingOfAnotherMajor),
                Self::GreetingOfAnotherMajor => Some(Self::Reported(ControllerGeneration::new(1))),
                Self::Reported(_) => Some(Self::ReadRefused(a_reply())),
                Self::ReadRefused(_) => Some(Self::ReadUndecodable(a_reply())),
                Self::ReadUndecodable(_) => Some(Self::ReadReplied(a_reply())),
                Self::ReadReplied(_) => None,
            }
        }
    }

    impl Label for Gave {
        fn label(&self) -> String {
            match self {
                Self::NoAddress => "no_address",
                Self::NothingInTime => "nothing_in_time",
                Self::NothingListens => "nothing_listens",
                Self::LinkFailed => "link_failed",
                Self::GreetingThenLinkFailed => "greeting_then_link_failed",
                Self::GreetingReplied(_) => "greeting_replied",
                Self::GreetingOfAnotherMajor => "greeting_of_another_major",
                Self::Reported(_) => "reported",
                Self::ReadRefused(_) => "read_refused",
                Self::ReadUndecodable(_) => "read_undecodable",
                Self::ReadReplied(_) => "read_replied",
            }
            .to_owned()
        }
    }

    /// The generation that the command asked, as the label table has it: not known, the one that
    /// the daemon reports, or another.
    #[derive(Clone, Copy)]
    enum AskedGeneration {
        Unknown,
        Reported,
        Another,
    }

    impl Every for AskedGeneration {
        fn first() -> Self {
            Self::Unknown
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Unknown => Some(Self::Reported),
                Self::Reported => Some(Self::Another),
                Self::Another => None,
            }
        }
    }

    impl Label for AskedGeneration {
        fn label(&self) -> String {
            match self {
                Self::Unknown => "none",
                Self::Reported => "same",
                Self::Another => "another",
            }
            .to_owned()
        }
    }

    impl AskedGeneration {
        /// The generation that the walk's `Gave::Reported` reports is the first.
        fn generation(self) -> Option<ControllerGeneration> {
            match self {
                Self::Unknown => None,
                Self::Reported => Some(ControllerGeneration::new(1)),
                Self::Another => Some(ControllerGeneration::new(2)),
            }
        }
    }

    /// One row of the look's label table: what the exchange gave, the generation asked, and the
    /// label that `label` gives.
    struct LookRow {
        gave: Gave,
        asked: AskedGeneration,
        look: Endpoint,
    }

    /// Every row of the look's label, made by `label`.
    fn look_rows(label: impl Fn(Option<ControllerGeneration>, Gave) -> Endpoint) -> Vec<LookRow> {
        let mut rows = Vec::new();
        for gave in every::<Gave>() {
            for asked in every::<AskedGeneration>() {
                rows.push(LookRow {
                    gave,
                    asked,
                    look: label(asked.generation(), gave),
                });
            }
        }
        rows
    }

    const LOOK_TABLE_HEADER: &str = "\
# Generated by the lib case host_stop::tests::the_table_of_the_look_is_the_file of kr-cli. Make it again: KR_WRITE_LOOK_TABLE=1 cargo test -p kr-cli --lib host_stop::tests::the_table_of_the_look_is_the_file (the case fails once after it writes; run it again without the variable).
# One line for each way that the exchange of a look at the endpoint can end (`gave`) and each generation asked (`asked`: none where the command does not know it, same where it is the one that the daemon reports, another), and what answers at the endpoint.
# The label is unclear only where nothing came within the bound or the look itself failed (no address, no answer in time, a link that failed). An answer that came within the bound and proves no generation is unproved, whatever its kind.
";

    /// The look's label table, as the file holds it.
    fn the_look_table() -> String {
        let mut out = String::from(LOOK_TABLE_HEADER);
        out.push_str("\n## what the exchange gave, the generation asked, and what answers\n");
        for row in look_rows(label_of) {
            out.push_str(&format!(
                "gave={} asked={} -> {}\n",
                row.gave.label(),
                row.asked.label(),
                Some(row.look).label()
            ));
        }
        out
    }

    /// Fails with the first lines where `made` and the file `held` differ; writes the file where
    /// `variable` is set.
    fn is_the_file(made: &str, held: &str, file: &str, variable: &str) {
        let path = format!("{}/tests/{file}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os(variable).is_some() {
            std::fs::write(&path, made).expect("the table is written");
            panic!(
                "the table was written to {path}; build and run the case again without {variable}"
            );
        }
        if made != held {
            let (made_lines, held_lines): (Vec<_>, Vec<_>) =
                (made.lines().collect(), held.lines().collect());
            let first = (0..made_lines.len().max(held_lines.len()))
                .find(|index| made_lines.get(*index) != held_lines.get(*index))
                .unwrap_or(0);
            let said: Vec<String> = (first..first + 6)
                .filter(|index| *index < made_lines.len().max(held_lines.len()))
                .map(|index| {
                    format!(
                        "line {}:\n  file: {}\n  made: {}",
                        index + 1,
                        held_lines.get(index).unwrap_or(&"(none)"),
                        made_lines.get(index).unwrap_or(&"(none)")
                    )
                })
                .collect();
            panic!(
                "the table that the code makes differs from crates/kr-cli/tests/{file} from line {}:\n{}",
                first + 1,
                said.join("\n")
            );
        }
    }

    /// The look's label table that the code makes is the table that the repository holds.
    #[test]
    fn the_table_of_the_look_is_the_file() {
        is_the_file(
            &the_look_table(),
            include_str!("../tests/host_stop_look_table.txt"),
            "host_stop_look_table.txt",
            "KR_WRITE_LOOK_TABLE",
        );
    }

    /// What the rows of the look's label break of the principle that an answer that came within the
    /// bound and proves no generation is unproved, and that nothing is unclear but a look where
    /// nothing came within the bound or the look itself failed.
    fn look_violations(rows: &[LookRow]) -> Vec<String> {
        let mut found = Vec::new();
        for row in rows {
            let said = format!("gave={} asked={}", row.gave.label(), row.asked.label());
            let nothing_came = matches!(
                row.gave,
                Gave::NoAddress
                    | Gave::NothingInTime
                    | Gave::LinkFailed
                    | Gave::GreetingThenLinkFailed
            );
            let replied = matches!(
                row.gave,
                Gave::GreetingReplied(_)
                    | Gave::ReadRefused(_)
                    | Gave::ReadUndecodable(_)
                    | Gave::ReadReplied(_)
            );
            let unproved = replied
                || matches!(
                    (row.gave, row.asked),
                    (Gave::Reported(_), AskedGeneration::Unknown)
                );
            if matches!(row.look, Endpoint::Unclear) != nothing_came {
                found.push(format!(
                    "{said}: unclear is for a look where nothing came or it failed, and only there"
                ));
            }
            if matches!(row.look, Endpoint::Unproved(_)) != unproved {
                found.push(format!(
                    "{said}: an answer that proves no generation is unproved, and only that"
                ));
            }
            if matches!(row.look, Endpoint::Nobody) != matches!(row.gave, Gave::NothingListens) {
                found.push(format!(
                    "{said}: nobody is for a connection that found nothing listening, and only that"
                ));
            }
            if matches!(row.look, Endpoint::Same(_))
                != matches!(
                    (row.gave, row.asked),
                    (Gave::Reported(_), AskedGeneration::Reported)
                )
            {
                found.push(format!(
                    "{said}: the same daemon is proved only by the generation that was asked"
                ));
            }
            if matches!(row.look, Endpoint::Another)
                != (matches!(row.gave, Gave::GreetingOfAnotherMajor)
                    || matches!(
                        (row.gave, row.asked),
                        (Gave::Reported(_), AskedGeneration::Another)
                    ))
            {
                found.push(format!(
                    "{said}: another daemon is a daemon of another major or of another generation"
                ));
            }
        }
        found
    }

    /// The label of the look holds its principle in every row.
    #[test]
    fn the_look_label_holds_its_principle_in_every_row() {
        assert_eq!(look_violations(&look_rows(label_of)), Vec::<String>::new());
    }

    /// The property has teeth: a label that reads a refused greeting as the same daemon, one that
    /// reads a reply that cannot be used as no answer, and one that reads a silent peer as an
    /// answer each break exactly the rows that they change.
    #[test]
    fn the_look_label_property_fails_for_a_label_that_reads_an_answer_wrongly() {
        let as_the_same = |asked: Option<ControllerGeneration>, gave: Gave| match gave {
            Gave::GreetingReplied(answered) => Endpoint::Same(answered),
            other => label_of(asked, other),
        };
        let broken = look_violations(&look_rows(as_the_same));
        assert_eq!(broken.len(), 6, "{broken:?}");
        assert!(
            broken
                .iter()
                .all(|line| line.starts_with("gave=greeting_replied"))
        );
        let as_unclear = |asked: Option<ControllerGeneration>, gave: Gave| match gave {
            Gave::ReadRefused(_) => Endpoint::Unclear,
            other => label_of(asked, other),
        };
        let broken = look_violations(&look_rows(as_unclear));
        assert_eq!(broken.len(), 6, "{broken:?}");
        assert!(
            broken
                .iter()
                .all(|line| line.starts_with("gave=read_refused"))
        );
        let as_an_answer = |asked: Option<ControllerGeneration>, gave: Gave| match gave {
            Gave::NothingInTime => Endpoint::Unproved(a_reply()),
            other => label_of(asked, other),
        };
        let broken = look_violations(&look_rows(as_an_answer));
        assert_eq!(broken.len(), 6, "{broken:?}");
        assert!(
            broken
                .iter()
                .all(|line| line.starts_with("gave=nothing_in_time"))
        );
    }

    /// The exit code of a result.
    fn code_of(exit: Exit) -> u8 {
        exit.failure(Shown::said("a failure"))
            .map_or(0, |error| error.exit_code())
    }

    /// What a result says in the table: the kind of sentence, the exit code, the code of the `--json`
    /// failure beside it and the `stop` member.
    fn said_line<S: Label>(said: &Said<S>) -> String {
        format!(
            "{} exit={} code={} stop={}",
            said.sentence.label(),
            code_of(said.exit),
            failure_code_of(said.exit),
            said.stop.word()
        )
    }

    /// The code that the `--json` failure of a result carries, as `--json` spells it; `-` for a
    /// success, which carries none.
    fn failure_code_of(exit: Exit) -> String {
        exit.failure(Shown::said("a failure"))
            .map_or_else(|| "-".to_owned(), |error| error.code().to_string())
    }

    /// What a round reads, in the table.
    fn readings(round: &Round) -> String {
        let look = match (round.look, round.successor) {
            (Some(Endpoint::Another), Some(pid)) => format!("another({pid})"),
            (Some(Endpoint::Another), None) => "another(-)".to_owned(),
            (look, _) => look.label(),
        };
        format!(
            "lock={} process={} holder={} look={look}",
            round.lock.label(),
            round.process.label(),
            round.holder.label(),
        )
    }

    /// The successors that the lock file can name after a look: where [`successor_wanted`] says
    /// that the round reads it, its process (5000) and none (where the lock file cannot be read,
    /// as on Windows), and none after any other look.
    fn successors_after(look: Look) -> Vec<Option<u64>> {
        if successor_wanted(look) {
            vec![Some(5000), None]
        } else {
            vec![None]
        }
    }

    /// Every combination of what a round reads, with each successor that the lock file can name
    /// after a look of another generation.
    fn every_round() -> Vec<Round> {
        let mut all = Vec::new();
        for lock in every::<Lock>() {
            for process in every::<Process>() {
                for holder in every::<Holder>() {
                    for look in every::<Look>() {
                        for successor in successors_after(look) {
                            all.push(Round {
                                lock: lock.clone(),
                                process,
                                holder,
                                look,
                                successor,
                            });
                        }
                    }
                }
            }
        }
        all
    }

    /// The process that the lock file names, as the walk of the holder has it: none, the asked
    /// process and another.
    #[derive(Clone, Copy)]
    enum Named {
        Nobody,
        TheAsked,
        Another,
    }

    impl Every for Named {
        fn first() -> Self {
            Self::Nobody
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Nobody => Some(Self::TheAsked),
                Self::TheAsked => Some(Self::Another),
                Self::Another => None,
            }
        }
    }

    impl Label for Named {
        fn label(&self) -> String {
            match self {
                Self::Nobody => "none",
                Self::TheAsked => "asked",
                Self::Another => "other",
            }
            .to_owned()
        }
    }

    impl Named {
        /// The number that the lock file names: the asked process is 4000.
        const fn pid(self) -> Option<u64> {
            match self {
                Self::Nobody => None,
                Self::TheAsked => Some(4000),
                Self::Another => Some(4001),
            }
        }
    }

    /// The identity of the asked process that a round has, as the walk of the holder has it: none
    /// where the command has no identity of the process, and the asked process's.
    #[derive(Clone, Copy)]
    enum Identity {
        None,
        TheAsked,
    }

    impl Every for Identity {
        fn first() -> Self {
            Self::None
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::None => Some(Self::TheAsked),
                Self::TheAsked => None,
            }
        }
    }

    impl Label for Identity {
        fn label(&self) -> String {
            match self {
                Self::None => "none",
                Self::TheAsked => "asked",
            }
            .to_owned()
        }
    }

    impl Identity {
        fn of(self) -> Option<ProcessStartIdentity> {
            match self {
                Self::None => None,
                Self::TheAsked => Some(asked_process()),
            }
        }
    }

    /// The identity that a round has of the asked process: none where the command has no identity
    /// of it, and its identity otherwise.
    const fn identity_of(process: Process) -> Identity {
        match process {
            Process::NoIdentity => Identity::None,
            Process::Running | Process::Ended | Process::Unreadable => Identity::TheAsked,
        }
    }

    /// The values of `Holder` that a round reads where the lock file is read: what [`Holder::of`]
    /// gives for each process that the lock file can name, with the identity that the round has,
    /// each value once, in the order of the walk of the named process.
    fn holders_read(process: Process) -> Vec<Holder> {
        let identity = identity_of(process).of();
        let mut all: Vec<Holder> = Vec::new();
        for named in every::<Named>() {
            let holder = Holder::of(named.pid(), identity.as_ref());
            if !all
                .iter()
                .any(|seen| std::mem::discriminant(seen) == std::mem::discriminant(&holder))
            {
                all.push(holder);
            }
        }
        all
    }

    /// Whether a round can happen: the holder is read where [`holder_wanted`] says so (to a value
    /// that [`Holder::of`] gives), and the look is made where [`look_wanted`] says so. These are
    /// the rounds that the wait makes.
    fn reachable(round: &Round) -> bool {
        let holder_read = if holder_wanted(&round.lock, round.process) {
            holders_read(round.process)
                .iter()
                .any(|read| std::mem::discriminant(read) == std::mem::discriminant(&round.holder))
        } else {
            round.holder == Holder::NotRead
        };
        holder_read && round.look.is_some() == look_wanted(&round.lock, round.process, round.holder)
    }

    /// The rounds that can happen, made by asking [`holder_wanted`] and [`look_wanted`] and not by a
    /// list: one round where no look is made, and one for each value of the look where one is.
    fn the_rounds_that_happen() -> Vec<Round> {
        let mut all = Vec::new();
        for lock in every::<Lock>() {
            for process in every::<Process>() {
                let holders: Vec<Holder> = if holder_wanted(&lock, process) {
                    holders_read(process)
                } else {
                    vec![Holder::NotRead]
                };
                for holder in holders {
                    let looks: Vec<Look> = if look_wanted(&lock, process, holder) {
                        every::<Look>().into_iter().flatten().map(Some).collect()
                    } else {
                        vec![None]
                    };
                    for look in looks {
                        for successor in successors_after(look) {
                            all.push(Round {
                                lock: lock.clone(),
                                process,
                                holder,
                                look,
                                successor,
                            });
                        }
                    }
                }
            }
        }
        all
    }

    const TABLE_HEADER: &str = "\
# Generated by the lib case host_stop::tests::the_table_of_the_end_is_the_file of kr-cli. Make it again: KR_WRITE_END_TABLE=1 cargo test -p kr-cli --lib host_stop::tests::the_table_of_the_end_is_the_file (the case fails once after it writes; run it again without the variable).
# One line per combination. The file holds each result's kind of sentence, its exit, the code of its `--json` failure and its `stop` member, and each walked decision, all printed by the product's own functions. It does not hold the sentences' words, and a decision that no walk here prints is held by a named case.
# rounds: every combination of what a round of the wait reads (lock, process, holder named, look), with whether the bound is reached,
#   whether the wait can make that round (`reachable`), and what the round shows: gone, successor(pid), go_on, or not_ended:<why> with
#   whether something answered the last look (a proved generation or not).
# after a request: the rounds that can happen, at the bound, for a told request and one whose outcome was not shown: the kind of
#   sentence, the exit code, the code of the `--json` failure beside it (`-` for a success) and the `stop` member of `--json`.
# a look of another generation is walked twice: with the process that the lock file names (`another(5000)`) and with none
#   (`another(-)`, which is what Windows gives, where the lock file cannot be read).
# before a request: the decision of the wait for a request that could not be made, what is said for each way the failure came out
#   (with the lock read again where the decision asks for it), the first look, and the start of the command.
# the walks that follow: the lock's and the process's readings, the process that the lock file names, where a failure goes by its
#   source, what a failure that the daemon's end can cause came to by what the wait decided, the process that a stop is waited for by
#   with the `--json` `pid` beside it, and where a refusal of the stop goes by the retry category of its code.
";

    /// The whole table, as the file holds it.
    fn the_table() -> String {
        let mut out = String::from(TABLE_HEADER);
        out.push_str("\n## rounds\n");
        for round in every_round() {
            for at_bound in [false, true] {
                out.push_str(&format!(
                    "{} bound={} reachable={} -> {}\n",
                    readings(&round),
                    if at_bound { "yes" } else { "no" },
                    if reachable(&round) { "yes" } else { "no" },
                    what_the_round_shows(&round, at_bound).label()
                ));
            }
        }
        out.push_str("\n## after a request that was written, at the bound\n");
        for round in the_rounds_that_happen() {
            let end =
                what_the_round_shows(&round, true).expect("a round at the bound shows an end");
            for request in every::<Request>() {
                let said = said_after_the_request(end.clone(), &request);
                out.push_str(&format!(
                    "{} request={} -> {}\n",
                    readings(&round),
                    request.label(),
                    said_line(&said)
                ));
            }
        }
        out.push_str(
            "\n## a request that could not be made: what the wait decides, at the bound\n",
        );
        for round in the_rounds_that_happen() {
            let end =
                what_the_round_shows(&round, true).expect("a round at the bound shows an end");
            out.push_str(&format!(
                "{} -> {}\n",
                readings(&round),
                decided_by_the_wait(end).label()
            ));
        }
        out.push_str("\n## a request that could not be made: what is said, with the lock read again where asked\n");
        for lock in every::<Lock>() {
            for before in every::<Before>() {
                let label = before.label();
                let asked = std::cell::Cell::new(false);
                let said = said_before_the_request(before, || {
                    asked.set(true);
                    lock.clone()
                });
                if asked.get() {
                    out.push_str(&format!(
                        "before={} lock_again={} -> {}\n",
                        label,
                        lock.label(),
                        said_line(&said)
                    ));
                } else if matches!(lock, Lock::Free) {
                    out.push_str(&format!(
                        "before={} lock_again=- -> {}\n",
                        label,
                        said_line(&said)
                    ));
                }
            }
        }
        out.push_str("\n## a request that could not be made: the first look, made where the connection was not closed\n");
        out.push_str(&format!(
            "closed=yes: {}\n",
            match first_look(true) {
                FirstLook::NotMade => "no look is made, and the wait decides",
                FirstLook::Made => "the endpoint is looked at once first",
            }
        ));
        for look in every::<Look>().into_iter().flatten() {
            out.push_str(&format!(
                "closed=no look={} -> {}\n",
                Some(look).label(),
                match (first_look(false), first_look_answers(look).is_some()) {
                    (FirstLook::Made, true) => "answers",
                    (FirstLook::Made, false) => "the wait decides",
                    (FirstLook::NotMade, _) => "no look is made, and the wait decides",
                }
            ));
        }
        out.push_str("\n## the start of the command\n");
        for start in every::<Start>() {
            for lock in every::<Lock>() {
                let said = said_at_the_start(&start, || lock.clone());
                out.push_str(&format!(
                    "start={} lock={} -> {}\n",
                    start.label(),
                    lock.label(),
                    said_line(&said)
                ));
            }
        }
        walks_of_the_functions(&mut out);
        out
    }

    /// What a raw reading of the lock was, for the walk of [`Lock::of`].
    #[derive(Clone, Copy)]
    enum LockReading {
        NotHeld,
        Held,
        Failed,
    }

    impl Every for LockReading {
        fn first() -> Self {
            Self::NotHeld
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::NotHeld => Some(Self::Held),
                Self::Held => Some(Self::Failed),
                Self::Failed => None,
            }
        }
    }

    impl Label for LockReading {
        fn label(&self) -> String {
            match self {
                Self::NotHeld => "not_held",
                Self::Held => "held",
                Self::Failed => "failed",
            }
            .to_owned()
        }
    }

    impl LockReading {
        fn raw(self) -> std::result::Result<bool, Shown> {
            match self {
                Self::NotHeld => Ok(false),
                Self::Held => Ok(true),
                Self::Failed => Err(Shown::said("the lock could not be taken")),
            }
        }
    }

    /// What the system said of the process, raw, for the walk of [`Process::of`]: none where the
    /// command has no identity.
    #[derive(Clone, Copy)]
    enum ProcessReading {
        NoIdentity,
        Running,
        Ended,
        Unknown,
    }

    impl Every for ProcessReading {
        fn first() -> Self {
            Self::NoIdentity
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::NoIdentity => Some(Self::Running),
                Self::Running => Some(Self::Ended),
                Self::Ended => Some(Self::Unknown),
                Self::Unknown => None,
            }
        }
    }

    impl Label for ProcessReading {
        fn label(&self) -> String {
            match self {
                Self::NoIdentity => "no_identity",
                Self::Running => "running",
                Self::Ended => "ended",
                Self::Unknown => "unknown",
            }
            .to_owned()
        }
    }

    impl ProcessReading {
        fn raw(self) -> Option<ProcessState> {
            match self {
                Self::NoIdentity => None,
                Self::Running => Some(ProcessState::Running),
                Self::Ended => Some(ProcessState::Ended),
                Self::Unknown => Some(ProcessState::Unknown {
                    detail: "the system did not say".to_owned(),
                }),
            }
        }
    }

    impl Every for ErrorSource {
        fn first() -> Self {
            Self::Reply
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Reply => Some(Self::Closure),
                Self::Closure => Some(Self::OwnFault),
                Self::OwnFault => None,
            }
        }
    }

    impl Label for ErrorSource {
        fn label(&self) -> String {
            match self {
                Self::Reply => "reply",
                Self::Closure => "closure",
                Self::OwnFault => "own_fault",
            }
            .to_owned()
        }
    }

    impl Label for Route {
        fn label(&self) -> String {
            match self {
                Self::Reply => "reply: an answer, nothing is looked at",
                Self::OwnFault => "own_fault: nothing is looked at",
                Self::TheEnd => "the_end: the daemon's end is looked for",
            }
            .to_owned()
        }
    }

    impl Every for Decided {
        fn first() -> Self {
            Self::Ended(End::Gone)
        }

        fn after(&self) -> Option<Self> {
            match self {
                Self::Ended(End::Gone) => Some(Self::Ended(End::Successor(Some(5000)))),
                Self::Ended(End::Successor(Some(_))) => Some(Self::Ended(End::Successor(None))),
                Self::Ended(End::Successor(None)) => Some(Self::NotShown),
                Self::NotShown => Some(Self::Answers(an_answer())),
                Self::Answers(_) => None,
                // A decision of the wait never holds an end that is not shown.
                Self::Ended(End::NotEnded(..)) => None,
            }
        }
    }

    impl Label for Waited<'_> {
        fn label(&self) -> String {
            format!(
                "waits_for={} json_pid={}",
                self.old
                    .map_or_else(|| "-".to_owned(), |old| old.pid.get().to_string()),
                self.pid
                    .map_or_else(|| "-".to_owned(), |pid| pid.to_string())
            )
        }
    }

    /// What a retry category is called in the table: its wire spelling.
    fn category_label(category: RetryCategory) -> &'static str {
        match category {
            RetryCategory::NoRetry => "no_retry",
            RetryCategory::Transient => "transient",
            RetryCategory::Resync => "resync",
            RetryCategory::ConfigurationChange => "configuration_change",
            RetryCategory::OutcomeUnknown => "outcome_unknown",
        }
    }

    impl Label for Split {
        fn label(&self) -> String {
            match self {
                Self::Refused => "refused: nothing was taken, no wait",
                Self::MaybeAsked => {
                    "maybe_asked: the daemon is waited for as one that took the stop"
                }
            }
            .to_owned()
        }
    }

    /// The categories of every error code, each once, in the order of their names.
    fn categories_of_every_code() -> Vec<RetryCategory> {
        let mut all: Vec<RetryCategory> = Vec::new();
        for code in ErrorCode::ALL {
            let category = code.retry_category();
            if !all.contains(&category) {
                all.push(category);
            }
        }
        all.sort_by_key(|category| category_label(*category));
        all
    }

    /// The walks of the functions that decide a result which is the input of a section above:
    /// each is printed by calling the product's own function over every value of what it takes.
    fn walks_of_the_functions(out: &mut String) {
        out.push_str("\n## the lock's reading, as the wait reads it\n");
        for reading in every::<LockReading>() {
            out.push_str(&format!(
                "reading={} -> lock={}\n",
                reading.label(),
                Lock::of(reading.raw()).label()
            ));
        }
        out.push_str("\n## the process's reading, as the wait reads it\n");
        for reading in every::<ProcessReading>() {
            out.push_str(&format!(
                "reading={} -> process={}\n",
                reading.label(),
                Process::of(reading.raw()).label()
            ));
        }
        out.push_str(
            "\n## the process that the lock file names: the process it names, the identity of the asked process\n",
        );
        for named in every::<Named>() {
            for identity in every::<Identity>() {
                out.push_str(&format!(
                    "named={} identity={} -> holder={}\n",
                    named.label(),
                    identity.label(),
                    Holder::of(named.pid(), identity.of().as_ref()).label()
                ));
            }
        }
        out.push_str(
            "\n## a request that could not be made: where a failure goes, by its source\n",
        );
        for source in every::<ErrorSource>() {
            out.push_str(&format!(
                "source={} -> {}\n",
                source.label(),
                route_of(source).label()
            ));
        }
        out.push_str("\n## a request that could not be made: what a failure that the daemon's end can cause came to, by what the wait decided\n");
        for accepted in [true, false] {
            for decided in every::<Decided>() {
                let label = match &decided {
                    Decided::Ended(End::Successor(successor)) => format!(
                        "ended_by_a_successor({})",
                        successor.map_or_else(|| "-".to_owned(), |pid| pid.to_string())
                    ),
                    Decided::Ended(End::Gone | End::NotEnded(..))
                    | Decided::NotShown
                    | Decided::Answers(_) => decided.label(),
                };
                let before = before_by_the_wait(
                    decided,
                    accepted,
                    an_environment(),
                    Some(4000),
                    &Shown::said("the connection was closed"),
                );
                let pid = match &before {
                    Before::Ended { pid, .. } => {
                        format!(
                            " pid={}",
                            pid.map_or_else(|| "-".to_owned(), |pid| pid.to_string())
                        )
                    }
                    Before::Silent { .. } | Before::Answers(_) | Before::OwnFault => String::new(),
                };
                out.push_str(&format!(
                    "accepted={} decided={} -> before={}{}\n",
                    if accepted { "yes" } else { "no" },
                    label,
                    before.label(),
                    pid
                ));
            }
        }
        out.push_str("\n## the process that the end of a stop is waited for by: the process that the lock file named, the process that the answer named\n");
        for named in [None, Some(4000_u64)] {
            for answered in [None, Some(4000_u64), Some(4001)] {
                let holder = named.map(|_| asked_process());
                let waited = process_waited_for(holder.as_ref(), None, answered);
                out.push_str(&format!(
                    "named={} answer={} -> {}\n",
                    named.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
                    answered.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
                    waited.label()
                ));
            }
        }
        out.push_str("\n## the same where the answer named none and an earlier reply on the connection that carries the request (the restart's request for the launch alone) named a process\n");
        for named in [None, Some(4000_u64)] {
            for stated in [4000_u64, 4001] {
                let holder = named.map(|_| asked_process());
                let waited = process_waited_for(holder.as_ref(), Some(stated), None);
                out.push_str(&format!(
                    "named={} stated={} -> {}\n",
                    named.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
                    stated,
                    waited.label()
                ));
            }
        }
        out.push_str(
            "\n## the stop: where a refusal goes, by the retry category of its code (every code's category)\n",
        );
        for category in categories_of_every_code() {
            out.push_str(&format!(
                "category={} -> {}\n",
                category_label(category),
                split_of(category).label()
            ));
        }
    }

    /// The table that the code makes is the table that the repository holds: a change of a walked
    /// decision, of a sentence's kind, of an exit or of a `stop` member shows as a change of the
    /// file. The sentences' words are not in it, and a decision that no walk prints is held by a
    /// named case.
    #[test]
    fn the_table_of_the_end_is_the_file() {
        is_the_file(
            &the_table(),
            include_str!("../tests/host_stop_end_table.txt"),
            "host_stop_end_table.txt",
            "KR_WRITE_END_TABLE",
        );
    }

    /// The rounds that the wait can make, asked of the two small functions, are the combinations
    /// that [`reachable`] keeps of the whole product.
    #[test]
    fn the_rounds_that_happen_are_those_of_the_whole_product_that_the_wait_can_make() {
        let all = every_round();
        let made = the_rounds_that_happen();
        let kept: Vec<String> = all
            .iter()
            .filter(|round| reachable(round))
            .map(readings)
            .collect();
        assert_eq!(made.iter().map(readings).collect::<Vec<_>>(), kept);
        assert!(made.len() < all.len());
    }

    /// The number of distinct variants that a walk gives.
    fn variants_walked<T>(walk: &[T]) -> usize {
        walk.iter()
            .map(std::mem::discriminant)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    /// The name of the set that a walk gives values of.
    fn set_of<T>(_: &[T]) -> &'static str {
        std::any::type_name::<T>()
    }

    /// Holds the walk of a set to the set. The one list of the set's variants, each as a path, is
    /// the count and also the arms of a `match` with no wildcard arm: the macro writes each
    /// pattern itself, so an entry that would match more than one variant (a wildcard or a
    /// binding) is no path and does not build, and a variant added to the set is an error in the
    /// test build until the list names it. A walk that gives fewer distinct variants than the list
    /// names fails the assertion, which names the set. A variant named twice makes the count
    /// larger than any walk can give, so that the assertion fails for it too.
    macro_rules! the_walk_gives_every_variant {
        ($walk:expr; $($variant:path),+ $(,)?) => {{
            let walk = $walk;
            for value in &walk {
                match value {
                    $($variant { .. } => {})+
                }
            }
            assert_eq!(
                variants_walked(&walk),
                [$(stringify!($variant)),+].len(),
                "the walk of {} gives a different number of distinct variants than its list names",
                set_of(&walk)
            );
        }};
    }

    /// Each walk of a set of the product sees every variant of it: the number of distinct variants
    /// that its chain gives is the number of variants that the list of the set names, and the
    /// compiler holds that list to the set. The look is none or an endpoint.
    #[test]
    fn each_walk_sees_every_variant_of_its_set() {
        the_walk_gives_every_variant!(
            every::<Lock>();
            Lock::Free, Lock::Held, Lock::Unreadable
        );
        the_walk_gives_every_variant!(
            every::<Process>();
            Process::NoIdentity, Process::Running, Process::Ended, Process::Unreadable
        );
        the_walk_gives_every_variant!(
            every::<Holder>();
            Holder::NotRead, Holder::Nobody, Holder::Asked, Holder::Other
        );
        the_walk_gives_every_variant!(
            every::<Request>();
            Request::Told, Request::MaybeAsked
        );
        the_walk_gives_every_variant!(
            every::<Start>();
            Start::OtherMajor, Start::Silent, Start::NothingListening
        );
        the_walk_gives_every_variant!(
            every::<Before>();
            Before::Ended, Before::Silent, Before::Answers, Before::OwnFault
        );
        the_walk_gives_every_variant!(
            every::<Gave>();
            Gave::NoAddress,
            Gave::NothingInTime,
            Gave::NothingListens,
            Gave::LinkFailed,
            Gave::GreetingThenLinkFailed,
            Gave::GreetingReplied,
            Gave::GreetingOfAnotherMajor,
            Gave::Reported,
            Gave::ReadRefused,
            Gave::ReadUndecodable,
            Gave::ReadReplied
        );
        assert!(every::<Look>().iter().any(Option::is_none));
        the_walk_gives_every_variant!(
            every::<Look>().into_iter().flatten().collect::<Vec<_>>();
            Endpoint::Nobody,
            Endpoint::Same,
            Endpoint::Unproved,
            Endpoint::Another,
            Endpoint::Unclear
        );
    }

    // The properties of the end's decision, asserted over every row of the table. They are written
    // from the principle that the command at its end says only what its own readings showed, and
    // its last readings decide (not from the table): each reads the words that a row says, and
    // the readings of the round, and judges one against the other.

    /// A row of the whole product: a round at the bound, the request that came before it, what is
    /// said and the words.
    struct Composed {
        round: Round,
        request: Request,
        /// Whether the marker is told that the daemon took the stop, as [`marker_told`] says.
        marked_told: bool,
        said: Said<AfterRequest>,
        text: String,
    }

    /// The rows for `rounds` and both requests, with the words that the command prints. Where
    /// `unproved_is_proved` the round is decided as if an answer with no proved generation were a
    /// proved one (the base of this change): the readings of the row stay as they were.
    fn composed_rows(rounds: &[Round], unproved_is_proved: bool) -> Vec<Composed> {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let mut rows = Vec::new();
        for round in rounds {
            let mut read = round.clone();
            if let (true, Some(Endpoint::Unproved(answered))) = (unproved_is_proved, read.look) {
                read.look = Some(Endpoint::Same(answered));
            }
            for request in every::<Request>() {
                let end =
                    what_the_round_shows(&read, true).expect("a round at the bound shows an end");
                let said = said_after_the_request(end, &request);
                let old = (round.process != Process::NoIdentity).then(asked_process);
                let text = words_after_the_request(
                    Which::Stop,
                    &said.sentence,
                    &request,
                    &environment,
                    id,
                    old.as_ref(),
                    None,
                )
                .to_string();
                rows.push(Composed {
                    round: round.clone(),
                    marked_told: marker_told(&request),
                    request,
                    said,
                    text,
                });
            }
        }
        rows
    }

    fn lock_free(round: &Round) -> bool {
        matches!(round.lock, Lock::Free)
    }

    fn lock_held(round: &Round) -> bool {
        matches!(round.lock, Lock::Held)
    }

    fn lock_unreadable(round: &Round) -> bool {
        matches!(round.lock, Lock::Unreadable(_))
    }

    /// The last look proved that the daemon asked answers, by the generation that it reports.
    fn proved_same(round: &Round) -> bool {
        matches!(round.look, Some(Endpoint::Same(_)))
    }

    /// There is no usable reading of the process: none was possible, or the system did not say.
    fn no_usable_process(round: &Round) -> bool {
        matches!(round.process, Process::NoIdentity | Process::Unreadable)
    }

    /// Another daemon holds the environment, shown by the lock file naming another process that is a
    /// daemon, or by a daemon of another generation answering where the lock and the process leave
    /// room for one.
    fn successor_shown(round: &Round) -> bool {
        let named = lock_held(round)
            && round.process == Process::Ended
            && matches!(round.holder, Holder::Other(_));
        let another_generation = matches!(round.look, Some(Endpoint::Another))
            && ((lock_free(round) && no_usable_process(round))
                || (lock_held(round)
                    && matches!(round.process, Process::Ended | Process::NoIdentity)));
        named || another_generation
    }

    /// The end is shown: the process has gone and the lock is free; nobody listens, the lock is free
    /// and no process can be read; or a successor is shown.
    fn end_shown(round: &Round) -> bool {
        let gone = lock_free(round) && round.process == Process::Ended;
        let nobody_listens = lock_free(round)
            && no_usable_process(round)
            && matches!(round.look, Some(Endpoint::Nobody));
        gone || nobody_listens || successor_shown(round)
    }

    /// The rows that break a property, each as a line that names the property, the readings, the
    /// request and the words.
    fn violations(rows: &[Composed]) -> Vec<String> {
        let mut broken = Vec::new();
        for row in rows {
            let (round, text) = (&row.round, &row.text);
            let code = code_of(row.said.exit);
            let mut broke = |property: &str| {
                broken.push(format!(
                    "{property}: {} request={} says: {text}",
                    readings(round),
                    row.request.label()
                ));
            };
            // P1: "has not ended" only where the last round proved that the same daemon answers by
            // its generation, or that its process runs.
            if text.contains("has not ended")
                && !(proved_same(round) || round.process == Process::Running)
            {
                broke("P1 has not ended");
            }
            // P2: "has ended" and "Stopped" only where the end is shown by the process gone with
            // the lock free, or by nobody listening with the lock free and no process to read.
            if (text.contains("and it has ended") || text.contains("Stopped the control daemon"))
                && !(lock_free(round)
                    && (round.process == Process::Ended
                        || (no_usable_process(round)
                            && matches!(round.look, Some(Endpoint::Nobody)))))
            {
                broke("P2 has ended");
            }
            // P3: the words of a told stop only where the request was told, and the words of one
            // not shown only where it was not.
            if (text.contains("was told to stop") || text.contains("Stopped the control daemon"))
                && !matches!(row.request, Request::Told)
            {
                broke("P3 told words");
            }
            if text.contains("did not show whether it took the stop")
                && !matches!(row.request, Request::MaybeAsked(_))
            {
                broke("P3 not-shown words");
            }
            // P4: a process number only where a process is named: the asked process (4000) where an
            // identity exists, the process that the lock file names (4001) where it names one, and
            // the process of a look that showed another generation (5000).
            if text.contains("process 4000") && round.process == Process::NoIdentity {
                broke("P4 the asked process");
            }
            if text.contains("process 4001") && !matches!(round.holder, Holder::Other(_)) {
                broke("P4 the holder");
            }
            if text.contains("process 5000") && round.successor != Some(5000) {
                broke("P4 the successor of a look");
            }
            // A successor that only a look showed, where the lock file named none, has no number: the
            // words say another control daemon.
            let named = lock_held(round)
                && round.process == Process::Ended
                && matches!(round.holder, Holder::Other(_));
            if successor_shown(round)
                && !named
                && matches!(round.look, Some(Endpoint::Another))
                && round.successor.is_none()
                && !text.contains("another control daemon")
            {
                broke("P4 the successor without a number");
            }
            // P5: exit 0 only where the end is shown, and where it is shown, exit 0.
            if code == 0 && !end_shown(round) {
                broke("P5 exit 0");
            }
            if end_shown(round) && code != 0 {
                broke("P5 the end is shown and the exit is not 0");
            }
            // P6: exit 3 only where nothing was sent: a request that was written never ends with 3.
            if code == 3 {
                broke("P6 exit 3");
            }
            // P7: a held lock's words only where the lock was read as held.
            if (text.contains("still holds") || text.contains("still held")) && !lock_held(round) {
                broke("P7 held lock");
            }
            // P8: "could not be read" only where a reading failed.
            if text.contains("could not be read") && !lock_unreadable(round) {
                broke("P8 could not be read");
            }
            // P9: "showed neither that the daemon still runs nor that it had gone" only with the lock
            // free and no usable reading of the process.
            if text.contains("showed neither") && !(lock_free(round) && no_usable_process(round)) {
                broke("P9 showed neither");
            }
            // P10: "has gone, and something" only where the process was read as ended.
            if text.contains("has gone, and something") && round.process != Process::Ended {
                broke("P10 the process has gone");
            }
            // P11: a successor's words only where a successor is shown.
            if text.contains("now holds") && !successor_shown(round) {
                broke("P11 successor");
            }
            // P12: the stop member says `ended` where the exit is 0, and only there.
            if (row.said.stop == Knows::Ended) != (code == 0) {
                broke("P12 the stop member");
            }
            // P15: where the end is not shown, the stop member is the request's own: `told` only for
            // a request that was told, and `maybe_asked` only for one whose outcome was not shown.
            let own = match row.request {
                Request::Told => Knows::Told,
                Request::MaybeAsked(_) => Knows::MaybeAsked,
            };
            if row.said.stop != Knows::Ended && row.said.stop != own {
                broke("P15 the stop member of an unfinished request");
            }
            // P16: the marker is told that the daemon took the stop for a request that was told, and
            // for no other: where the request's own stop member is `told`, and only there.
            if row.marked_told != (row.request.knows() == Knows::Told) {
                broke("P16 the told write");
            }
            // P13: "could not show what holds it" only where the lock was read as held (the
            // environment's own lock) and neither the same daemon was proved nor its process read as
            // running or as ended; and in every such round that shows no successor, those words.
            let holds_unshown = lock_held(round) && no_usable_process(round) && !proved_same(round);
            if text.contains("could not show what holds it") && !holds_unshown {
                broke("P13 held and not shown");
            }
            if holds_unshown
                && !successor_shown(round)
                && !text.contains("could not show what holds it")
            {
                broke("P13 the held lock is not said");
            }
            // P14: a process that runs is a daemon that has not ended, whatever the lock says: the
            // words say so, and say nothing else of the end.
            if round.process == Process::Running && !text.contains("has not ended") {
                broke("P14 a running process");
            }
        }
        broken
    }

    /// The properties hold over every combination of the readings: the whole product of the sets,
    /// the combinations that the wait can make among them, and a request that was told and one
    /// whose outcome was not shown.
    #[test]
    fn the_properties_hold_over_every_row() {
        let all = every_round();
        let happen = the_rounds_that_happen();
        assert_eq!((all.len(), happen.len()), (336, 45));
        let rows = composed_rows(&all, false);
        assert_eq!(rows.len(), 336 * 2);
        assert_eq!(violations(&rows), Vec::<String>::new());
        let rows = composed_rows(&happen, false);
        assert_eq!(rows.len(), 45 * 2);
        assert_eq!(violations(&rows), Vec::<String>::new());
    }

    /// The properties have teeth. Read as the base of this change read it, with an answer of no
    /// proved generation taken for the same daemon, the cell that the twelfth read found (an ended
    /// process, a held lock, a holder that is not named, such an answer, a told stop) says "has
    /// not ended" and breaks the first property; so does the same cell for a request whose outcome
    /// was not shown.
    #[test]
    fn the_properties_fail_where_an_answer_with_no_proved_generation_is_read_as_the_same_daemon() {
        let broken = violations(&composed_rows(&the_rounds_that_happen(), true));
        for request in ["told", "maybe_asked"] {
            let cell = format!(
                "P1 has not ended: lock=held process=ended holder=nobody look=unproved request={request} says: "
            );
            assert!(
                broken.iter().any(|line| line.starts_with(&cell)),
                "{request}: {broken:#?}"
            );
        }
    }

    /// The row of the table with these readings and this request, as the code makes it.
    fn the_row(readings_line: &str, request: &str) -> Composed {
        composed_rows(&the_rounds_that_happen(), false)
            .into_iter()
            .find(|row| readings(&row.round) == readings_line && row.request.label() == request)
            .unwrap_or_else(|| panic!("no row {readings_line} {request}"))
    }

    /// One case of the teeth: the property that it breaks, the readings and the request of the row
    /// that it starts from, and how the row is changed.
    type Tooth = (
        &'static str,
        &'static str,
        &'static str,
        Box<dyn Fn(&mut Composed)>,
    );

    /// Each property has teeth: a row that is made to break exactly that property, and no other,
    /// fails exactly that property. The rows are those of the code, with the words or the result
    /// changed in one place; the row as the code makes it breaks none.
    #[test]
    fn each_property_fails_for_a_row_that_breaks_exactly_that_property() {
        let held_ended = "lock=held process=ended holder=nobody look=unclear";
        let free_gone = "lock=free process=ended holder=not_read look=not_made";
        let held_unreadable = "lock=held process=unreadable holder=not_read look=not_made";
        let free_no_identity = "lock=free process=no_identity holder=not_read look=nobody";
        let free_another_none = "lock=free process=no_identity holder=not_read look=another(-)";
        let free_running = "lock=free process=running holder=not_read look=not_made";
        let unreadable_running = "lock=unreadable process=running holder=not_read look=not_made";
        let says = |text: &str| -> Box<dyn Fn(&mut Composed)> {
            let text = text.to_owned();
            Box::new(move |row| row.text.clone_from(&text))
        };
        let cases: Vec<Tooth> = vec![
            ("P1 ", held_ended, "told", says("the daemon has not ended")),
            ("P2 ", held_ended, "told", says("and it has ended")),
            (
                "P3 told words",
                held_ended,
                "maybe_asked",
                says("was told to stop"),
            ),
            (
                "P3 not-shown words",
                held_ended,
                "told",
                says("did not show whether it took the stop"),
            ),
            (
                "P4 the asked process",
                free_no_identity,
                "told",
                says("process 4000"),
            ),
            ("P4 the holder", held_ended, "told", says("process 4001")),
            (
                "P4 the successor of a look",
                held_ended,
                "told",
                says("process 5000"),
            ),
            (
                "P4 the successor without a number",
                free_another_none,
                "told",
                says("something"),
            ),
            (
                "P5 exit 0",
                held_ended,
                "told",
                Box::new(|row| {
                    row.said.exit = Exit::Done;
                    row.said.stop = Knows::Ended;
                }),
            ),
            (
                "P5 the end is shown",
                free_gone,
                "told",
                Box::new(|row| {
                    row.said.exit = Exit::Unfinished;
                    row.said.stop = Knows::Told;
                }),
            ),
            (
                "P6 ",
                held_ended,
                "told",
                Box::new(|row| row.said.exit = Exit::Unavailable),
            ),
            ("P7 ", free_gone, "told", says("still held")),
            ("P8 ", held_ended, "told", says("could not be read")),
            ("P9 ", held_ended, "told", says("showed neither")),
            (
                "P10 ",
                free_no_identity,
                "told",
                says("has gone, and something"),
            ),
            ("P11 ", held_ended, "told", says("now holds")),
            (
                "P12 the stop member",
                held_ended,
                "told",
                Box::new(|row| row.said.stop = Knows::Ended),
            ),
            (
                "P13 held and not shown",
                free_gone,
                "told",
                says("could not show what holds it"),
            ),
            (
                "P13 the held lock is not said",
                held_unreadable,
                "told",
                says("something"),
            ),
            ("P14 ", free_running, "told", says("something")),
            (
                "P14 ",
                unreadable_running,
                "told",
                says("the lock could not be read"),
            ),
            (
                "P15 ",
                held_ended,
                "told",
                Box::new(|row| row.said.stop = Knows::MaybeAsked),
            ),
            (
                "P15 ",
                held_ended,
                "maybe_asked",
                Box::new(|row| row.said.stop = Knows::Told),
            ),
            (
                "P16 ",
                held_ended,
                "maybe_asked",
                Box::new(|row| row.marked_told = true),
            ),
            (
                "P16 ",
                held_ended,
                "told",
                Box::new(|row| row.marked_told = false),
            ),
        ];
        for (property, readings_line, request, doctor) in cases {
            let clean = the_row(readings_line, request);
            assert_eq!(
                violations(std::slice::from_ref(&clean)),
                Vec::<String>::new()
            );
            let mut row = the_row(readings_line, request);
            doctor(&mut row);
            let broken = violations(std::slice::from_ref(&row));
            assert_eq!(broken.len(), 1, "{property}: {broken:?}");
            assert!(broken[0].starts_with(property), "{property}: {broken:?}");
        }
    }

    /// The properties hold for what is said where a request could not be made and at the start.
    #[test]
    fn the_properties_hold_for_a_request_that_could_not_be_made_and_for_the_start() {
        // What the wait decides: an answer at the last look is an answer, and only that.
        for round in every_round() {
            let end = what_the_round_shows(&round, true).expect("an end at the bound");
            let shown = end_shown(&round);
            let answered = matches!(round.look, Some(Endpoint::Same(_) | Endpoint::Unproved(_)));
            match decided_by_the_wait(end) {
                Decided::Answers(_) => assert!(answered && !shown, "{}", readings(&round)),
                Decided::Ended(_) => assert!(shown, "{}", readings(&round)),
                Decided::NotShown => assert!(!shown && !answered, "{}", readings(&round)),
            }
        }
        // What is said: exit 3 only where nothing was sent, a held lock's words only where the
        // lock read again was held, and an end only where the daemon ended.
        for lock in every::<Lock>() {
            for before in every::<Before>() {
                let label = before.label();
                let accepted = matches!(before, Before::Silent { accepted: true });
                let said = said_before_the_request(before, || lock.clone());
                let code = code_of(said.exit);
                let held = matches!(lock, Lock::Held);
                match said.sentence {
                    BeforeRequest::Ended { .. } => assert_eq!((code, said.stop), (0, Knows::Ended)),
                    BeforeRequest::HoldsAndSilent => {
                        assert_eq!(
                            (held, code, said.stop),
                            (true, 1, Knows::NotAsked),
                            "{label}"
                        );
                    }
                    BeforeRequest::Silent => {
                        assert_eq!(
                            (!held && accepted, code, said.stop),
                            (true, 1, Knows::NotAsked),
                            "{label}"
                        );
                    }
                    BeforeRequest::Unmade(_) => {
                        assert_eq!((code, said.stop), (3, Knows::NotAsked), "{label}");
                    }
                }
                assert!(code != 3 || said.stop == Knows::NotAsked, "{label}");
            }
        }
        // The start: "No control daemon runs" (exit 0) only where nothing listens and the lock is
        // free; a held lock's words only where the lock was held; an unreadable lock only where it
        // was unreadable.
        for start in every::<Start>() {
            for lock in every::<Lock>() {
                let said = said_at_the_start(&start, || lock.clone());
                let code = code_of(said.exit);
                let free = matches!(lock, Lock::Free);
                let held = matches!(lock, Lock::Held);
                // Nothing was asked at the start: every result carries `not_asked`, whatever its exit.
                assert_eq!(
                    said.stop,
                    Knows::NotAsked,
                    "{} {}",
                    start.label(),
                    lock.label()
                );
                match said.sentence {
                    AtStart::NoDaemon => {
                        assert!(
                            matches!(start, Start::NothingListening) && free && code == 0,
                            "{}",
                            start.label()
                        );
                    }
                    AtStart::HoldsAndSilent => assert!(held && code == 1, "{}", start.label()),
                    AtStart::LockUnreadable(_) => {
                        assert!(matches!(lock, Lock::Unreadable(_)) && code == 1);
                    }
                    AtStart::Silent => assert!(!held && code == 1, "{}", start.label()),
                    AtStart::OtherMajor => assert_eq!(code, 1),
                }
                assert!(code != 3 && (code != 0 || free));
            }
        }
    }

    /// Each kind of failure ends with the exit that the table says.
    #[test]
    fn each_exit_is_the_exit_of_its_failure() {
        for (exit, code) in [
            (Exit::Done, 0),
            (Exit::Unfinished, 1),
            (Exit::Failed, 1),
            (Exit::Unavailable, 3),
        ] {
            assert_eq!(code_of(exit), code);
        }
        let id = an_environment();
        let error = unmade_request(Which::Stop, id, &Shown::said("a failure"), Unmade::OwnFault);
        assert_eq!(error.exit_code(), code_of(Exit::Unavailable));
    }

    mod guide;
}
