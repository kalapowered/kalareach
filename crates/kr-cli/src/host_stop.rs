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
const ANSWER_BOUND: Duration = Duration::from_millis(STOP_SETTLE_MS + 5_000);

/// How long the end of the daemon is waited for once it was told to stop.
const END_BOUND: Duration = handover::DAEMON_STOP;

/// How often the end of the daemon is looked for.
const LOOK_EVERY: Duration = Duration::from_millis(50);

/// What a refusal says of the sessions meanwhile, for a command that stops the daemon.
const SESSIONS_GO_ON: &str = "Sessions and local attachments go on while no daemon runs.";

/// What this command knows of whether the daemon was asked, for `--json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Knows {
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
enum Stage {
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
struct Progress {
    stage: AtomicU8,
    /// The command's own record, from the moment it is written.
    marker: Mutex<Option<Marker>>,
    environment_id: EnvironmentId,
    /// What the command said at its start of the attempts earlier commands recorded.
    earlier: Mutex<Vec<Shown>>,
}

impl Progress {
    fn enter(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::SeqCst);
    }

    fn stage(&self) -> Stage {
        match self.stage.load(Ordering::SeqCst) {
            0 => Stage::BeforeAsking,
            1 => Stage::Asked,
            2 => Stage::Told,
            _ => Stage::Refused,
        }
    }

    fn with_marker<T>(&self, then: impl FnOnce(&mut Marker) -> T) -> Option<T> {
        let mut held = self
            .marker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.as_mut().map(then)
    }

    fn said_earlier(&self) -> Vec<Shown> {
        self.earlier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn remove_marker(&self) {
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
    let mut interrupts = Interrupts::catch();
    let environment = installation(paths)?;
    let progress = Progress {
        stage: AtomicU8::new(Stage::BeforeAsking as u8),
        marker: Mutex::new(None),
        environment_id: environment.environment_id,
        earlier: Mutex::new(Vec::new()),
    };
    let work = stop(paths, &environment, json, &progress);
    tokio::pin!(work);
    loop {
        tokio::select! {
            done = &mut work => return done,
            interrupt = interrupts.next() => {
                let stage = progress.stage();
                // A hangup after the request left is ignored: the report may print into a closed
                // terminal, which the record covers.
                if interrupt == Interrupt::Hangup && stage != Stage::BeforeAsking {
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

/// The facts a result carries in `--json`.
#[derive(Clone)]
struct Facts {
    knows: Knows,
    pid: Option<u64>,
    unsettled: Option<u64>,
    /// What earlier attempts recorded, which this command said at its start.
    records: Vec<Shown>,
}

impl Facts {
    /// Nothing asked, and nothing known of a process.
    fn none(records: Vec<Shown>) -> Self {
        Self {
            knows: Knows::NotAsked,
            pid: None,
            unsettled: None,
            records,
        }
    }

    fn document(&self) -> Document {
        let document = Document::new()
            .with("stop", self.knows.word())
            .with("pid", self.pid)
            .with("unsettled", self.unsettled);
        if self.records.is_empty() {
            document
        } else {
            document.with("records", self.records.clone())
        }
    }
}

/// Reports a result that is a failure, in the form the caller asked for, and ends the command.
fn failed(error: CliError, result: &Facts, json: bool) -> Completion {
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
fn done(said: &Shown, result: &Facts, json: bool, earlier: &Earlier) -> Completion {
    if json {
        output::document(&result.document().with("ok", true));
    } else {
        output::say(said);
    }
    earlier.remove_those_put_out(json);
    Completion::Done
}

/// The command, from the guard to the daemon's end.
async fn stop(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> Result<Completion> {
    let id = environment.environment_id;
    let none = Facts::none(Vec::new());
    if let Err(error) = crate::bind::require_outside_to_end_a_daemon(
        &crate::build_id(),
        "kr host stop",
        SESSIONS_GO_ON,
    )
    .await
    {
        return Ok(failed(error, &none, json));
    }
    // What earlier attempts recorded and whose process has gone is said at the start (in the
    // document under `--json`), and removed only by `done`, after the result that put it out has
    // been written.
    let mut earlier = Earlier::read(&environment.paths);
    let none = Facts::none(earlier.said(id));
    *progress
        .earlier
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = none.records.clone();
    if !json {
        earlier.say(id);
    }
    let endpoint = environment.paths.controller_endpoint()?;
    match startup::reach(&endpoint, startup::ANSWER_BOUND, &[]).await {
        Reached::Answered(listed) => {
            let Listed::Ours(client) = *listed else {
                return Ok(failed(
                    CliError::Other(shown!(
                        "the control daemon for environment {} states another public major than \
                         this command does. No stop was requested.",
                        id
                    )),
                    &none,
                    json,
                ));
            };
            Ok(stop_the_daemon(host, environment, *client, json, progress, &earlier).await)
        }
        Reached::Silent => Ok(silent(environment, &none, json, startup::ANSWER_BOUND)),
        Reached::Refused(error) if startup::nothing_listening(&error) => {
            Ok(vacant(environment, &none, json, &earlier))
        }
        Reached::Refused(error) => {
            let operations = Real::of(host, &environment.paths, None);
            let before = greeting_failed(
                &operations,
                &error,
                lock_holder(&environment.paths).as_ref(),
                id,
                tokio::time::Instant::now() + END_BOUND,
            )
            .await;
            Ok(match ended_by(before, environment, &none, json, &earlier) {
                Ok(completion) => completion,
                Err(cause) => failed(unreached(id, &error, cause), &none, json),
            })
        }
    }
}

/// What earlier attempts recorded whose process is no longer the one that recorded it.
struct Earlier {
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
    }
}

/// What every message that no control daemon runs says of the attempts recorded for an
/// environment: nothing where there is none, and otherwise a space and each record's words. It
/// removes nothing.
#[must_use]
pub fn records_said(environment: &EnvironmentPaths) -> Shown {
    let id = environment.environment_id();
    let said: Vec<Shown> = attempt::recorded(environment)
        .iter()
        .map(|recorded| record_said(recorded, id))
        .collect();
    if said.is_empty() {
        Shown::said("")
    } else {
        shown!(" {}", Shown::joined(said, " "))
    }
}

/// Nothing listens at the endpoint: no daemon runs, or one holds the environment and has not begun
/// to listen or has stopped listening.
fn vacant(
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> Completion {
    let id = environment.environment_id;
    match lock_held(&environment.paths) {
        Ok(false) => {
            let under_way: Vec<Shown> = attempt::recorded(&environment.paths)
                .iter()
                .filter(|recorded| recorded.standing() == Standing::UnderWay)
                .map(|recorded| record_said(recorded, id))
                .collect();
            let tail = if under_way.is_empty() {
                Shown::said("")
            } else {
                shown!(" {}", Shown::joined(under_way, " "))
            };
            done(
                &shown!(
                    "No control daemon runs for environment {}. Nothing was stopped.{}",
                    id,
                    tail
                ),
                none,
                json,
                earlier,
            )
        }
        Ok(true) => holds_and_is_silent(environment, none, json),
        Err(error) => failed(
            CliError::Other(shown!(
                "whether a control daemon holds environment {} could not be read: {}. No stop \
                 was requested.",
                id,
                error
            )),
            none,
            json,
        ),
    }
}

/// Something accepted the connection and did not answer within `bound`.
fn silent(environment: &KnownEnvironment, none: &Facts, json: bool, bound: Duration) -> Completion {
    match lock_held(&environment.paths) {
        Ok(true) => holds_and_is_silent(environment, none, json),
        _ => failed(
            CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: shown!(
                    "the control daemon listening for environment {} accepted the connection and \
                     did not answer within {} seconds. No stop was requested. Run kr host stop \
                     again in a moment.",
                    environment.environment_id,
                    bound.as_secs()
                ),
            },
            none,
            json,
        ),
    }
}

/// The connect found nothing listening and the end was not shown in the bound: no connection was
/// accepted, so the silence sentence ("accepted the connection and did not answer") is not said.
/// Where the lock is held, a daemon holds the environment and does not answer, which is true; where
/// it is not, the request could not be made.
fn unaccepted(
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
) -> std::result::Result<Completion, Unmade> {
    match lock_held(&environment.paths) {
        Ok(true) => Ok(holds_and_is_silent(environment, none, json)),
        _ => Err(Unmade::NothingListening),
    }
}

/// A daemon holds the environment and does not answer, so it may be starting or stopping.
fn holds_and_is_silent(environment: &KnownEnvironment, none: &Facts, json: bool) -> Completion {
    let id = environment.environment_id;
    let ending = how_to_end_the_holder(&environment.paths);
    failed(
        CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "A control daemon holds environment {} and does not answer, so it may be starting \
                 or stopping. No stop was requested. Run kr host stop again in a moment. {}",
                id,
                ending
            ),
        },
        none,
        json,
    )
}

/// What a person does if the process that holds the environment stays: the process the lock file
/// names where it is a process named kr-controller, and otherwise the way to find it.
fn how_to_end_the_holder(environment: &EnvironmentPaths) -> Shown {
    match named_daemon(environment) {
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
fn lock_holder(environment: &EnvironmentPaths) -> Option<ProcessStartIdentity> {
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
fn named_daemon(environment: &EnvironmentPaths) -> Option<u64> {
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
enum Asked {
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
async fn ask(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    json: bool,
    progress: &Progress,
) -> Asked {
    let composed = client
        .compose(
            Method::HostStop,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &HostStopParams { launch_only: false },
        )
        .await;
    let mutation = match composed {
        Ok(mutation) => mutation,
        Err(error) => {
            return Asked::NotComposed { error };
        }
    };
    // Set before the request is written: an interrupt from here on may find it taken.
    progress.enter(Stage::Asked);
    let request_id = mutation.request_id;
    if let Err(error) = client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
    {
        let failed = after_the_write_failed(error);
        if matches!(failed, Asked::NotComposed { .. }) {
            // Nothing left, so an interrupt from here on has no request to speak of.
            progress.enter(Stage::BeforeAsking);
        }
        return failed;
    }
    if !json {
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
        Ok(Ok(Outcome::Error(error))) => match error.code.retry_category() {
            RetryCategory::Transient | RetryCategory::OutcomeUnknown => {
                Asked::Unknown(Shown::protocol(&error))
            }
            _ => Asked::Refused(error),
        },
        Ok(Err(said)) => Asked::Unknown(said),
        Err(_) => Asked::Unknown(shown!(
            "it did not answer within {} seconds",
            ANSWER_BOUND.as_secs()
        )),
    }
}

/// A daemon answered the hello: asks it to stop, and waits for it to end.
async fn stop_the_daemon(
    host: &HostPaths,
    environment: &KnownEnvironment,
    mut client: LocalClient,
    json: bool,
    progress: &Progress,
    earlier: &Earlier,
) -> Completion {
    let id = environment.environment_id;
    let none = Facts::none(earlier.said(id));
    // A daemon that answered the hello and does not answer this is a holder that is silent.
    let info = match tokio::time::timeout(
        startup::ANSWER_BOUND,
        host_info(&mut client, &environment.paths),
    )
    .await
    {
        Ok(Ok(info)) => info,
        Ok(Err(CliError::Ipc(error))) => {
            let operations = Real::of(host, &environment.paths, None);
            let before = host_info_failed(
                &operations,
                client,
                &error,
                lock_holder(&environment.paths).as_ref(),
                id,
                tokio::time::Instant::now() + END_BOUND,
            )
            .await;
            return unmade_ended(before, &error, id, environment, &none, json, earlier);
        }
        Ok(Err(error)) => return failed(error, &none, json),
        Err(_) => return silent(environment, &none, json, startup::ANSWER_BOUND),
    };
    // Who holds the environment, and which process that is, before anything is asked: a process
    // that has ended and not been collected is read as gone, and its number may be reused.
    let holder = lock_holder(&environment.paths);
    let marker = match Marker::begin(&environment.paths, attempt::Command::Stop, holder.clone()) {
        Ok(marker) => marker,
        Err(error) => {
            return failed(
                CliError::Other(shown!(
                    "kr host stop could not record its attempt: {}. No stop was requested.",
                    Shown::ipc(&error)
                )),
                &none,
                json,
            );
        }
    };
    *progress
        .marker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);

    let (knows, pid, unsettled, unknown) = match ask(&mut client, id, json, progress).await {
        Asked::Taken(result) => {
            progress.enter(Stage::Told);
            (
                Knows::Told,
                Some(result.pid.get()),
                Some(result.unsettled.get()),
                None,
            )
        }
        Asked::Unknown(said) => {
            // The request may have left; the daemon is waited for as one that took it.
            progress.enter(Stage::Asked);
            (Knows::MaybeAsked, None, None, Some(said))
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
            return unmade_ended(before, &error, id, environment, &none, json, earlier);
        }
        Asked::Refused(error) => {
            // Nothing was taken, so an interrupt from here on has nothing to say but that.
            progress.enter(Stage::Refused);
            progress.remove_marker();
            let refusal = Facts {
                knows: Knows::Refused,
                ..none
            };
            return refused(&mut client, id, &info, error, &refusal, json).await;
        }
    };
    if knows == Knows::Told {
        let _ = progress.with_marker(|marker| marker.told());
    }
    drop(client);

    // The process that is waited for by its start identity is the one that answered: a lock file
    // that names another says nothing about this daemon. Where there is none, the wait is for the
    // lock and the endpoint, and no text names a process.
    let old = holder
        .as_ref()
        .filter(|holder| pid.is_none_or(|answered| answered == holder.pid.get()));
    let named = old.map(|old| old.pid.get());
    // For `--json`: the process the answer gave, and otherwise the one the lock file named.
    let pid = pid.or_else(|| holder.as_ref().map(|holder| holder.pid.get()));
    let operations = Real::of(host, &environment.paths, Some(info.generation));
    let ended = wait_for_the_end(&operations, old, END_BOUND).await;
    let result = |knows| Facts {
        knows,
        pid,
        unsettled,
        records: none.records.clone(),
    };
    // What the request came to: its failure where whether the daemon took it is not known.
    let not_known = match (knows, unknown.as_ref()) {
        (Knows::MaybeAsked, Some(failure)) => Some(failure),
        _ => None,
    };
    match ended {
        End::Gone => {
            progress.remove_marker();
            done(
                &gone_said(id, named, not_known, unsettled),
                &result(Knows::Ended),
                json,
                earlier,
            )
        }
        End::Successor(successor) => {
            progress.remove_marker();
            done(
                &successor_said(id, named, successor, unsettled),
                &result(Knows::Ended),
                json,
                earlier,
            )
        }
        End::NotEnded(why, _) => {
            let message = not_ended_said(why, not_known, &environment.paths, id, old);
            failed(
                CliError::Unfinished {
                    code: ErrorCode::EnvironmentUnavailable,
                    message,
                },
                &result(knows),
                json,
            )
        }
    }
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

/// What the command says where the wait for the end gave up at its bound with the request written:
/// that the daemon has not ended only where the last round shows a sign of life, and otherwise what
/// it knows.
fn not_ended_said(
    why: Why,
    not_known: Option<&Shown>,
    environment: &EnvironmentPaths,
    id: EnvironmentId,
    old: Option<&ProcessStartIdentity>,
) -> Shown {
    match why {
        Why::Held => still_held(environment, id),
        Why::Unlooked(why) => unlooked(id, not_known, &why),
        Why::NotShown => not_shown(id, not_known),
        Why::Running | Why::Answers => {
            let what = match not_known {
                Some(failure) => shown!(
                    "did not show whether it took the stop ({}), and it has not ended",
                    *failure
                ),
                None => Shown::said("was told to stop and has not ended"),
            };
            not_ended(environment, id, &what, old)
        }
    }
}

/// The words where the lock was free and the last look showed neither that the daemon runs nor
/// that it had gone.
fn not_shown(id: EnvironmentId, not_known: Option<&Shown>) -> Shown {
    match not_known {
        None => shown!(
            "The control daemon for environment {} was told to stop. After {} seconds the lock was \
             free, and the last look at the endpoint showed neither that the daemon still runs nor \
             that it had gone, so the command could not confirm the end. Run kr host stop again in \
             a moment; it looks again.",
            id,
            END_BOUND.as_secs()
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}). \
             After {} seconds the lock was free, and the last look at the endpoint showed neither \
             that the daemon still runs nor that it had gone, so the command could not confirm the \
             end. Run kr host stop again in a moment; it looks again.",
            id,
            *failure,
            END_BOUND.as_secs()
        ),
    }
}

/// Ends the command where its request could not be made, by what the failure came to: with the
/// daemon's end, with silence (exit 1) where the end is not shown in the bound after a connection
/// was accepted, and with the unmade request's failure (exit 3) where a daemon answered, where the
/// failure is this side's own, and where the connect found nothing listening and no lock is held.
/// The read of `host.info` and the compose of the stop request end here.
fn unmade_ended(
    before: Before,
    error: &kr_ipc::IpcError,
    id: EnvironmentId,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> Completion {
    match ended_by(before, environment, none, json, earlier) {
        Ok(completion) => completion,
        Err(cause) => failed(unmade_request(id, &Shown::ipc(error), cause), none, json),
    }
}

/// The failure of a greeting that could not be completed: that the daemon could not be reached
/// and that no stop was requested. A daemon's reply or this side's own fault makes it, and the
/// words are the failure's own.
fn unreached(id: EnvironmentId, error: &kr_ipc::IpcError, _cause: Unmade) -> CliError {
    CliError::HostUnavailable(shown!(
        "the control daemon for environment {} could not be reached: {}. No stop was requested.",
        id,
        Shown::ipc(error)
    ))
}

/// The failure of a request that could not be made: what was not made and that the stop was not
/// asked. A daemon's answer, this side's own fault or a connect that found nothing listening makes
/// it, and the words are the failure's own; `Unmade` says which.
fn unmade_request(id: EnvironmentId, why: &Shown, _cause: Unmade) -> CliError {
    CliError::HostUnavailable(shown!(
        "kr host stop could not make its request for the control daemon of environment {}: {}. \
         Nothing was sent, and nothing was stopped.",
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
    /// A daemon answered a look: the first, or the last of the wait at its bound. This is the only
    /// result that leads to exit 3, and it holds the answer.
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
    let first = if closed {
        Endpoint::Unclear
    } else {
        operations.look(startup::ANSWER_BOUND.min(left())).await
    };
    // Where the request was not made, any answer at the endpoint is an answer, whether or not it
    // proves the generation of the daemon that was asked.
    if let Endpoint::Same(answered) | Endpoint::Unproved(answered) = first {
        return Decided::Answers(answered);
    }
    match wait_for_the_end(operations, old, left()).await {
        // A daemon that answers the last look of the wait is an answer, as at the first look.
        End::NotEnded(_, Some(answered)) => Decided::Answers(answered),
        End::NotEnded(_, None) => Decided::NotShown,
        ended @ (End::Gone | End::Successor(_)) => Decided::Ended(ended),
    }
}

/// How the failure of the command's connection to the daemon came out, where it failed before the
/// command could make its request.
enum Before {
    /// The daemon had ended: what the command says, and the process that it names.
    Ended { said: Shown, pid: Option<u64> },
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
enum Unmade {
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
    // The source is read through the one function that names every variant. A reply shows that a
    // daemon answers; this side's own fault is no daemon's and no end causes it, so it is not
    // looked at; a closure is decided by the daemon's end.
    match error.comes_from() {
        ErrorSource::Reply => {
            drop(connection);
            return Answered::of_reply(error).map_or(Before::OwnFault, Before::Answers);
        }
        ErrorSource::OwnFault => {
            drop(connection);
            return Before::OwnFault;
        }
        ErrorSource::Closure => {}
    }
    let closed = closed_by_the_daemon(error);
    match ended_before_the_request(operations, connection, holder, closed, deadline).await {
        Decided::Ended(ended) => {
            let pid = holder.map(|holder| holder.pid.get());
            Before::Ended {
                said: ended_before_the_request_said(id, pid, ended, &Shown::ipc(error)),
                pid,
            }
        }
        Decided::NotShown => Before::Silent {
            accepted: !startup::nothing_listening(error),
        },
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

/// Ends the command by what a failed connection came to: with the daemon's end where it had
/// ended, and as for a daemon that does not answer where no end was shown within the bound and no
/// daemon answered the last look. It gives the answer where a daemon answered: the failure keeps its own
/// words, and only an answer in hand builds those.
fn ended_by(
    before: Before,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> std::result::Result<Completion, Unmade> {
    match before {
        Before::Ended { said, pid } => {
            let facts = Facts {
                knows: Knows::Ended,
                pid,
                unsettled: None,
                records: none.records.clone(),
            };
            Ok(done(&said, &facts, json, earlier))
        }
        Before::Silent { accepted: true } => Ok(silent(environment, none, json, END_BOUND)),
        Before::Silent { accepted: false } => unaccepted(environment, none, json),
        Before::Answers(answered) => Err(Unmade::Answered(answered)),
        Before::OwnFault => Err(Unmade::OwnFault),
    }
}

/// What the command says where the daemon had ended when its request could not be made: that it
/// ended, why the request could not be made and that this command sent nothing. It says nothing of
/// which came first, which the command did not see. Where something holds the environment now, the
/// words are those of any end that finds a successor.
fn ended_before_the_request_said(
    id: EnvironmentId,
    old: Option<u64>,
    ended: End,
    why: &Shown,
) -> Shown {
    match ended {
        End::Successor(successor) => successor_said(id, old, successor, None),
        _ => {
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
fn creates_under_way(unsettled: Option<u64>) -> Shown {
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
fn successor_said(
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
async fn refused(
    client: &mut LocalClient,
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
        return failed(CliError::Refused(error), none, json);
    }
    let probe = tokio::time::timeout(
        startup::ANSWER_BOUND,
        client.request(Method::BackupStatus, &BackupStatusParams {}),
    )
    .await
    .ok()
    .map(|read| read.map(|answer| answer.map(|_| ())));
    failed(after_the_probe(id, error, probe), none, json)
}

/// What the probe's answer makes of a refusal that may be the daemon's own. `None` is a probe
/// that was not answered in its bound.
fn after_the_probe(
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
        Some(Ok(Err(other))) => CliError::Refused(other),
        Some(Err(_)) | None => CliError::Refused(refusal),
    }
}

/// M4: the daemon was asked and has not ended after the wait. A process is named only while it is
/// a process named kr-controller: `old`, the process that held the environment before the request
/// where the daemon's answer, if it came, named it too, or the one the lock file names now.
fn not_ended(
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
    shown!(
        "The control daemon for environment {} {} after {} seconds. It may be finishing a write. {}",
        id,
        *what,
        END_BOUND.as_secs(),
        ends_with
    )
}

/// The environment after the daemon's process was seen to have gone, and still held when the wait
/// ended: what is said is that the process has gone and that something holds the environment which
/// is not shown to be a control daemon. It does not say that the daemon ended: the daemon ended only
/// where the lock is free or another control daemon holds it.
fn still_held(environment: &EnvironmentPaths, id: EnvironmentId) -> Shown {
    shown!(
        "The process of the control daemon for environment {} has gone, and something that is not \
         shown to be a control daemon still holds the environment after {} seconds. Run kr host \
         stop again in a moment. {}",
        id,
        END_BOUND.as_secs(),
        how_to_end_the_holder(environment)
    )
}

/// The environment's lock could not be looked at, so that nothing is known of whether the daemon
/// has ended. `not_known` is what the request's failure said where whether the daemon took the
/// stop is not known; where it took it, the text says that it was told.
fn unlooked(id: EnvironmentId, not_known: Option<&Shown>, why: &Shown) -> Shown {
    match not_known {
        None => shown!(
            "The control daemon for environment {} was told to stop, and whether it has ended could \
             not be read after {} seconds: {}. Run kr host stop again in a moment.",
            id,
            END_BOUND.as_secs(),
            *why
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}), and \
             whether it has ended could not be read after {} seconds: {}. Run kr host stop again in \
             a moment.",
            id,
            *failure,
            END_BOUND.as_secs(),
            *why
        ),
    }
}

/// Why the daemon had not ended when the wait did.
enum Why {
    /// Its process runs, or the lock is held: the daemon is told to stop and goes on.
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
    /// The lock could not be looked at.
    Unlooked(Shown),
}

/// How the wait for the daemon's end came out.
enum End {
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
async fn host_info(
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

/// Waits up to `bound` for the daemon that was asked to stop to end.
///
/// Where the daemon's process identity is known (`old`) it has ended only when that process has
/// gone and the environment's lock is free; a lock that is held then is a successor only where the
/// lock file names a live process named kr-controller that is not the old one, or a daemon of
/// another generation answers. Anything else that holds the lock for a moment, another command's
/// look among it, is waited through. Where no identity is known (always on Windows, where the
/// holder cannot be read), or the system does not say whether the process runs, the daemon has
/// ended when the lock is free and nothing answers at its endpoint, and the command cannot name or
/// wait for the process itself.
///
/// Each wait is bounded by what is left of the one deadline when it starts, counted after the wait
/// before it: the install lock's wait, a look at the endpoint and the pause between two rounds. A
/// look that cannot be made leaves the daemon as not ended.
///
/// At the bound the command says what its LAST round read: the daemon of the generation asked
/// answering the round's look is [`Why::Answers`], whatever else the round read (an answer with no
/// proved generation is no such sign, and is kept as the answer of the last look); otherwise a held lock or a running process is
/// [`Why::Running`]; and with no usable reading of the process a free lock and a last look that
/// showed nothing is [`Why::NotShown`], and an unreadable lock is [`Why::Unlooked`].
async fn wait_for_the_end(
    operations: &impl Operations,
    old: Option<&ProcessStartIdentity>,
    bound: Duration,
) -> End {
    let deadline = tokio::time::Instant::now() + bound;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    loop {
        let held = operations.held(left()).await;
        let unlooked = held.as_ref().err().cloned();
        let process = old.map(|old| operations.process_state(old));
        let old_gone = matches!(process, Some(ProcessState::Ended));
        // No usable reading of the process: none was possible, or the system did not say.
        let no_reading = old.is_none() || matches!(process, Some(ProcessState::Unknown { .. }));
        // What this round shows of the daemon: the lock's reading and the look are this round's.
        let lock_free = matches!(held, Ok(false));
        let mut last_look = None;
        let seen = match (held, process) {
            (Ok(false), Some(ProcessState::Ended)) => Some(End::Gone),
            (Ok(true), Some(ProcessState::Ended)) => {
                let (successor, look) = successor_of(operations, old, left()).await;
                last_look = look;
                successor.map(End::Successor)
            }
            // The process runs, or the system did not say and the lock is held or unreadable: the
            // daemon has not ended.
            (_, Some(ProcessState::Running))
            | (Ok(true) | Err(_), Some(ProcessState::Unknown { .. })) => None,
            // No usable reading of the process, and the lock is free: the endpoint decides.
            (Ok(false), None | Some(ProcessState::Unknown { .. })) => {
                let look = operations.look(left()).await;
                last_look = Some(look);
                match look {
                    Endpoint::Nobody => Some(End::Gone),
                    Endpoint::Another => Some(End::Successor(operations.named_daemon())),
                    Endpoint::Same(_) | Endpoint::Unproved(_) | Endpoint::Unclear => None,
                }
            }
            (Ok(true), None) => {
                let (successor, look) = successor_of(operations, None, left()).await;
                last_look = look;
                successor.map(End::Successor)
            }
            (Err(_), _) => None,
        };
        if let Some(seen) = seen {
            return seen;
        }
        if tokio::time::Instant::now() >= deadline {
            // Something answered the last look, with a proved generation or without one.
            let answered = match last_look {
                Some(Endpoint::Same(answered) | Endpoint::Unproved(answered)) => Some(answered),
                Some(Endpoint::Nobody | Endpoint::Another | Endpoint::Unclear) | None => None,
            };
            let why = match (unlooked, old_gone, last_look) {
                // The last look showed a daemon of the generation asked answering.
                (_, _, Some(Endpoint::Same(_))) => Why::Answers,
                // The lock could not be read, and no process is shown to run: there is no usable
                // reading of the process, or it has gone.
                (Some(why), _, _) if no_reading || old_gone => Why::Unlooked(why),
                (None, true, _) => Why::Held,
                // The lock is free and the last look did not show the daemon: no sign of life.
                _ if no_reading && lock_free => Why::NotShown,
                _ => Why::Running,
            };
            return End::NotEnded(why, answered);
        }
        operations.pause(LOOK_EVERY.min(left())).await;
    }
}

/// Whether the environment is held by a daemon that is not the one that was asked, and the number
/// of the process the lock file names as that daemon where it names one: a live process named
/// kr-controller other than `old`, or a daemon of another generation that answers. Nothing else
/// proves a successor. With it, the look that it made, where it made one: the round keeps it.
async fn successor_of(
    operations: &impl Operations,
    old: Option<&ProcessStartIdentity>,
    within: Duration,
) -> (Option<Option<u64>>, Option<Endpoint>) {
    let named = operations
        .named_daemon()
        .filter(|named| old.is_none_or(|old| *named != old.pid.get()));
    if named.is_some() && old.is_some() {
        return (Some(named), None);
    }
    let look = operations.look(within).await;
    (
        (look == Endpoint::Another).then(|| operations.named_daemon()),
        Some(look),
    )
}

/// The evidence that a daemon answered.
mod answered {
    use kr_ipc::IpcError;
    use kr_ipc::error::ErrorSource;
    use kr_protocol::ids::ControllerGeneration;

    /// What shows that a daemon answered: its answer to a look (the generation that it reported),
    /// or a reply of its own that cannot be used. The product builds one only from an answer's
    /// content, a `host.info` result or a reply error, which no code of this command makes up; the
    /// field is private to this module. Only a case can build one from nothing (`for_a_case`, in
    /// test builds), so there the cases and not the type hold the rule.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Answered {
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
        pub(super) const fn for_a_case(generation: ControllerGeneration) -> Self {
            Self {
                generation: Some(generation),
            }
        }

        /// The daemon's own reply, where `error` is one (a refusal of the hello, a version that
        /// does not fit, a message of another kind). A closure, a frame that cannot be read and
        /// this side's own fault (the check of the peer's credentials among them) are no reply.
        pub(super) fn of_reply(error: &IpcError) -> Option<Self> {
            (error.comes_from() == ErrorSource::Reply).then_some(Self { generation: None })
        }
    }
}

use answered::Answered;

/// What answers at the environment's endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    /// Nothing listens there.
    Nobody,
    /// A daemon answers and reports the generation that was asked: the same daemon, proved.
    Same(Answered),
    /// Something answers and no generation is proved: a refusal of the greeting (the daemon's own
    /// reply, which names no generation), or an answer where the generation that was asked is not
    /// known. It shows that something answers at the endpoint, and neither that the daemon that
    /// was asked runs nor that it has ended.
    Unproved(Answered),
    /// A daemon of another generation answers.
    Another,
    /// Something listens and does not answer, or the look could not be made.
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

/// Looks at the environment's endpoint, the connection, the hello and `host.info` together bounded
/// by `within` and by one second, and treats a daemon that does not answer as unclear.
async fn endpoint_look(
    environment: &EnvironmentPaths,
    generation: Option<ControllerGeneration>,
    within: Duration,
) -> Endpoint {
    let Ok(endpoint) = environment.controller_endpoint() else {
        return Endpoint::Unclear;
    };
    let within = within.min(LOOK_EVERY * 20);
    tokio::time::timeout(within, async {
        match startup::reach(&endpoint, within, &[]).await {
            Reached::Refused(error) if startup::nothing_listening(&error) => Endpoint::Nobody,
            // A reply of the daemon's own (a refusal of the hello) shows that a daemon answers, and
            // names no generation.
            Reached::Refused(error) => {
                Answered::of_reply(&error).map_or(Endpoint::Unclear, Endpoint::Unproved)
            }
            Reached::Silent => Endpoint::Unclear,
            Reached::Answered(listed) => match *listed {
                Listed::Other(_) => Endpoint::Another,
                Listed::Ours(mut client) => match client.request(Method::HostInfo, &()).await {
                    Ok(Ok(value)) => match value.to_typed::<HostInfoResult>() {
                        Ok(now) => by_generation(generation, now.generation),
                        Err(_) => Endpoint::Unclear,
                    },
                    _ => Endpoint::Unclear,
                },
            },
        }
    })
    .await
    .unwrap_or(Endpoint::Unclear)
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
trait Operations {
    /// Whether a daemon holds the environment, waiting up to `within` for one that is starting.
    async fn held(&self, within: Duration) -> std::result::Result<bool, Shown>;
    /// What the system says of the process of the daemon that was asked.
    fn process_state(&self, old: &ProcessStartIdentity) -> ProcessState;
    /// What answers at the environment's endpoint, bounded by `within`.
    async fn look(&self, within: Duration) -> Endpoint;
    /// The process the lock file names as a control daemon, where it names one.
    fn named_daemon(&self) -> Option<u64>;
    /// Waits `time` between two rounds of looks.
    async fn pause(&self, time: Duration);
}

/// The operations on this machine: its locks, its processes, its endpoint and its timer.
struct Real<'a> {
    installation: Installation,
    environment: &'a EnvironmentPaths,
    /// The generation of the daemon that was asked, where the command has read it: a command
    /// whose connection failed before `host.info` was read does not know it, and a daemon that
    /// answers then cannot be told from a successor by its generation.
    generation: Option<ControllerGeneration>,
}

impl<'a> Real<'a> {
    fn of(
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

    async fn look(&self, within: Duration) -> Endpoint {
        endpoint_look(self.environment, self.generation, within).await
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
            matches!(waited, End::NotEnded(Why::Running, _)),
            "a held lock with nothing to show for a successor is not an end"
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

    /// The words of a daemon that was told and has not ended, and of an environment that is held after
    /// the daemon's process has gone, name no process they cannot show and promise no wait.
    #[test]
    fn the_words_of_a_daemon_that_has_not_ended_name_no_process_and_promise_no_wait() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let id = environment.environment_id();
        let what = Shown::said("was told to stop and has not ended");
        let said = not_ended(&environment, id, &what, None).to_string();
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
        let held = still_held(&environment, id).to_string();
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
    /// The text for a lock that could not be looked at takes what the request came to: after a stop
    /// that was taken it says that the daemon was told, and after a request whose taking is not
    /// known it says that, with the request's failure, and never that the daemon was told.
    #[test]
    fn the_text_for_a_lock_that_could_not_be_looked_at_takes_the_requests_known_state() {
        let temp = kr_ipc::testing::TempHost::create();
        let id = temp.environment().environment_id();
        let why = Shown::said("the lock file could not be opened");
        let told = unlooked(id, None, &why).to_string();
        assert!(
            told.contains("was told to stop, and whether it has ended could not be read after 30 seconds: the lock file could not be opened. Run kr host stop again in a moment."),
            "{told}"
        );
        let failure = Shown::said("the connection was cut");
        let unknown = unlooked(id, Some(&failure), &why).to_string();
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

        async fn look(&self, within: Duration) -> Endpoint {
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

    /// How a wait came out, in words a failed assertion shows.
    fn said(end: &End) -> String {
        match end {
            End::Gone => "gone".to_owned(),
            End::Successor(named) => format!("successor {named:?}"),
            End::NotEnded(Why::Running, _) => "not ended, running".to_owned(),
            End::NotEnded(Why::Answers, _) => "not ended, answers".to_owned(),
            End::NotEnded(Why::NotShown, _) => "not ended, not shown".to_owned(),
            End::NotEnded(Why::Held, _) => "not ended, held".to_owned(),
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
            (Ok(true), Endpoint::Nobody, "not ended, running"),
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
            Before::Ended { said, pid } => format!("ended ({pid:?}): {said}"),
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
            match unmade_ended(before, &gone, id, &environment, &none, true, &earlier) {
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
        let error = unmade_request(id, &Shown::ipc(&fault), Unmade::Answered(an_answer()));
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
        match unmade_ended(before, &closed, id, &environment, &none, true, &earlier) {
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
        match unmade_ended(before, &fault, id, &environment, &none, true, &earlier) {
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
                unmade_request(id, &why, Unmade::OwnFault),
                unreached(id, &fault, Unmade::OwnFault),
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
            match unmade_ended(before, &fault, id, &environment, &none, true, &earlier) {
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
        match unmade_ended(before, &closed, id, &environment, &none, true, &earlier) {
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
            match after_the_probe(id, a_refusal(), probe) {
                CliError::Refused(refusal) => {
                    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
                }
                other => panic!("the refusal is the result, not {other}"),
            }
        }
        let withheld = ProtocolError::new(ErrorCode::PermissionDenied, "the check is refused too");
        let said = after_the_probe(id, a_refusal(), Some(Ok(Err(withheld)))).to_string();
        assert!(
            said.contains("takes no stop request or refuses it")
                && said.contains("Nothing was stopped"),
            "the check's own refusal is shown in this command's words: {said}"
        );
        let another = ProtocolError::new(ErrorCode::ResourceUnavailable, "the daemon is busy");
        match after_the_probe(id, a_refusal(), Some(Ok(Err(another)))) {
            CliError::Refused(refusal) => assert_eq!(refusal.code, ErrorCode::ResourceUnavailable),
            other => panic!("another refusal of the probe is shown as it is, not {other}"),
        }
        match after_the_probe(id, a_refusal(), Some(Ok(Ok(())))) {
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
            selected_version: kr_protocol::hello::PROTOCOL_VERSION,
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
    #[derive(Clone, Copy)]
    enum Closure {
        /// With nothing more to say: the end of the stream at a frame boundary.
        Clean,
        /// After a frame that cannot be read.
        BadFrame,
        /// After a frame of which the last bytes are missing: the end of the stream inside a frame.
        HalfFrame,
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
            let codec =
                kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control);
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
        match ask(&mut client, id, true, &progress).await {
            Asked::NotComposed { error } => closed_by_the_daemon(&error),
            _ => panic!("the request could be composed"),
        }
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
        match unmade_ended(before, &closed, id, &environment, &none, true, &earlier) {
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
    /// to the bound, which is running, and not a free lock with a look that showed nothing.
    #[tokio::test(start_paused = true)]
    async fn a_lock_that_was_free_in_an_earlier_round_is_read_as_the_last_round_reads_it() {
        let supplied = Supplied::new()
            .held(vec![at_once(Ok(false)), at_once(Ok(true))])
            .look(vec![at_once(Endpoint::Unclear)]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, running");
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
}
