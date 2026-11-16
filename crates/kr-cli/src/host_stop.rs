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
//! left, and neither its answer nor the daemon's end was seen), `refused` (the request left and the
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
    /// The request left, and neither its answer nor the daemon's end was seen.
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
            let ended = ended_by(before, environment, &none, json, &earlier);
            Ok(ended.unwrap_or_else(|| {
                failed(
                    CliError::HostUnavailable(shown!(
                        "the control daemon for environment {} could not be reached: {}. No stop \
                         was requested.",
                        id,
                        Shown::ipc(&error)
                    )),
                    &none,
                    json,
                )
            }))
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

/// Whether a daemon holds the environment's lock, which the kernel gives up only when its process
/// has gone. The look takes the lock for a moment, so a daemon that starts during it can find the
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
    /// The outcome is not known: no answer came, it was cut, or the daemon's word does not say
    /// whether it took the stop. The daemon is waited for as one that took it.
    Unknown(Shown),
    /// The daemon refused, and its word is that nothing was done.
    Refused(ProtocolError),
    /// The request could not be made: nothing was sent. `closed` is whether the daemon closed the
    /// connection, which a daemon does when it goes.
    NotComposed { why: Shown, closed: bool },
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

/// Sends the request, says that it left, and waits for its answer.
///
/// The answer is read from the connection, and anything but a whole answer to this request is an
/// unknown outcome: a daemon that ends for another cause gets no answer, and the daemon stops when
/// its write of the answer has completed, failed or reached its bound, so an answer can be cut.
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
            return Asked::NotComposed {
                closed: closed_by_the_daemon(&error),
                why: Shown::ipc(&error),
            };
        }
    };
    // Set before the request is written: an interrupt from here on may find it taken.
    progress.enter(Stage::Asked);
    let request_id = mutation.request_id;
    if let Err(error) = client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
    {
        return Asked::Unknown(Shown::ipc(&error));
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
            let ended = ended_by(before, environment, &none, json, earlier);
            return ended
                .unwrap_or_else(|| failed(unmade_request(id, &Shown::ipc(&error)), &none, json));
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
        Asked::NotComposed { why, closed } => {
            // The request was never made, so nothing left and there is no stop to wait for. The
            // daemon may have gone meanwhile, as it does when another command's stop has taken
            // effect: its end is looked for once, within the one deadline. A daemon that stays is
            // the unmade request's failure. The deadline counts from the failure.
            let deadline = tokio::time::Instant::now() + END_BOUND;
            progress.remove_marker();
            let named = holder.as_ref().map(|holder| holder.pid.get());
            let operations = Real::of(host, &environment.paths, Some(info.generation));
            if let Some(ended) =
                ended_before_the_request(&operations, client, holder.as_ref(), closed, deadline)
                    .await
            {
                let facts = Facts {
                    knows: Knows::Ended,
                    pid: named,
                    unsettled: None,
                    records: none.records.clone(),
                };
                return done(
                    &ended_before_the_request_said(id, named, ended, &why),
                    &facts,
                    json,
                    earlier,
                );
            }
            return failed(unmade_request(id, &why), &none, json);
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
    match ended {
        End::Gone => {
            progress.remove_marker();
            let cut = creates_under_way(unsettled);
            let process = named.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
            done(
                &shown!(
                    "Stopped the control daemon for environment {}{}. No session was stopped: its \
                     workers keep running, a local attach keeps working, and the next daemon finds \
                     the sessions again. Paired devices' connections close until a daemon runs.{}",
                    id,
                    process,
                    cut
                ),
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
        End::NotEnded(why) => {
            // What the request came to: its failure where whether the daemon took it is not known.
            let not_known = match (knows, unknown.as_ref()) {
                (Knows::MaybeAsked, Some(failure)) => Some(failure),
                _ => None,
            };
            let message = match why {
                Why::Held => still_held(&environment.paths, id),
                Why::Unlooked(why) => unlooked(id, not_known, &why),
                Why::Running => {
                    let what = match not_known {
                        Some(failure) => shown!(
                            "did not show whether it took the stop ({}), and it has not ended",
                            *failure
                        ),
                        None => Shown::said("was told to stop and has not ended"),
                    };
                    not_ended(&environment.paths, id, &what, old)
                }
            };
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

/// The failure of a request that could not be made while the daemon stays: what was not made and
/// that the stop was not asked.
fn unmade_request(id: EnvironmentId, why: &Shown) -> CliError {
    CliError::HostUnavailable(shown!(
        "kr host stop could not make its request for the control daemon of environment {}: {}. \
         Nothing was sent, and nothing was stopped.",
        id,
        *why
    ))
}

/// Where the request could not be made, whether the daemon had ended when it could not be: the end,
/// where the daemon's process has gone and the environment's lock is free or another control
/// daemon holds it. A daemon that closed the connection is going, and a listener that is gone is
/// waited for to its end within the one deadline, once. A daemon that did not close it and still
/// answers at its endpoint stays, and nothing is waited for. A daemon that has not ended by the
/// deadline is the failure's, and so is one whose end cannot be looked at. The deadline is the
/// caller's, set before the look, so that the look and the wait together stay inside it.
///
/// `connection` is the command's connection to the daemon, which is let go before anything is
/// looked at, as before the wait of a request that was asked.
async fn ended_before_the_request(
    operations: &impl Operations,
    connection: impl Sized,
    old: Option<&ProcessStartIdentity>,
    closed: bool,
    deadline: tokio::time::Instant,
) -> Option<End> {
    // Where the platform keeps a pipe instance for as long as a handle to it is open, a daemon
    // that has gone stays at its endpoint for a command that holds its end: every new connection
    // finds the pipe busy, so no look sees the end, and a new daemon cannot create the pipe's
    // first instance.
    drop(connection);
    if !closed && operations.look(startup::ANSWER_BOUND).await == Endpoint::Same {
        return None;
    }
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    match wait_for_the_end(operations, old, left).await {
        End::NotEnded(_) => None,
        ended => Some(ended),
    }
}

/// How the failure of the command's connection to the daemon came out, where it failed before the
/// command could make its request.
enum Before {
    /// The daemon had ended: what the command says, and the process that it names.
    Ended { said: Shown, pid: Option<u64> },
    /// The daemon closed the connection and was not shown to have ended within the bound.
    Silent,
    /// The connection failed some other way, or the daemon still answers: the failure keeps its
    /// own words.
    Stays,
}

/// Decides what a failure of the connection before the command's request was made came to, as the
/// arm for a request that could not be made decides it: by the daemon's end, looked for within
/// `deadline`. A daemon that closed the connection is going and is waited for; any other failure
/// is looked at once, and the daemon that still answers leaves the failure its own words.
async fn failed_before_the_request(
    operations: &impl Operations,
    connection: impl Sized,
    holder: Option<&ProcessStartIdentity>,
    error: &kr_ipc::IpcError,
    id: EnvironmentId,
    deadline: tokio::time::Instant,
) -> Before {
    let closed = closed_by_the_daemon(error);
    match ended_before_the_request(operations, connection, holder, closed, deadline).await {
        Some(ended) => {
            let pid = holder.map(|holder| holder.pid.get());
            Before::Ended {
                said: ended_before_the_request_said(id, pid, ended, &Shown::ipc(error)),
                pid,
            }
        }
        None if closed => Before::Silent,
        None => Before::Stays,
    }
}

/// The command's greeting of the daemon failed with `error`: what the failure came to. Only a
/// closed peer, or a frame that the close cut, says that a daemon is ending; a rejection, a
/// mismatch or a fault of another kind keeps its words and nothing is looked at.
async fn greeting_failed(
    operations: &impl Operations,
    error: &kr_ipc::IpcError,
    holder: Option<&ProcessStartIdentity>,
    id: EnvironmentId,
    deadline: tokio::time::Instant,
) -> Before {
    if !closed_by_the_daemon(error) {
        return Before::Stays;
    }
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
/// ended, and as for a daemon that does not answer where it closed the connection and was not
/// shown to have ended. It gives none where the failure keeps its own words.
fn ended_by(
    before: Before,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    earlier: &Earlier,
) -> Option<Completion> {
    match before {
        Before::Ended { said, pid } => {
            let facts = Facts {
                knows: Knows::Ended,
                pid,
                unsettled: None,
                records: none.records.clone(),
            };
            Some(done(&said, &facts, json, earlier))
        }
        Before::Silent => Some(silent(environment, none, json, END_BOUND)),
        Before::Stays => None,
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
    /// Its process runs, or nothing shows that it has gone: the daemon is told to stop and goes on.
    Running,
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
    /// The daemon had not ended when the wait did, or it could not be seen whether it had.
    NotEnded(Why),
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
/// holder cannot be read), the daemon has ended when the lock is free and nothing answers at its
/// endpoint, and the command cannot name or wait for the process itself.
///
/// Each wait is bounded by what is left of the one deadline when it starts, counted after the wait
/// before it: the install lock's wait, a look at the endpoint and the pause between two rounds. A
/// look that cannot be made leaves the daemon as not ended.
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
        let seen = match (held, process) {
            (Ok(false), Some(ProcessState::Ended)) => Some(End::Gone),
            (Ok(true), Some(ProcessState::Ended)) => successor_of(operations, old, left())
                .await
                .map(End::Successor),
            // The process runs, or the system did not say: the daemon has not ended.
            (_, Some(ProcessState::Running | ProcessState::Unknown { .. })) => None,
            (Ok(false), None) => match operations.look(left()).await {
                Endpoint::Nobody => Some(End::Gone),
                Endpoint::Another => Some(End::Successor(operations.named_daemon())),
                Endpoint::Same | Endpoint::Unclear => None,
            },
            (Ok(true), None) => successor_of(operations, None, left())
                .await
                .map(End::Successor),
            (Err(_), _) => None,
        };
        if let Some(seen) = seen {
            return seen;
        }
        if tokio::time::Instant::now() >= deadline {
            return End::NotEnded(match (unlooked, old_gone) {
                (Some(why), _) if old.is_none() || old_gone => Why::Unlooked(why),
                (None, true) => Why::Held,
                _ => Why::Running,
            });
        }
        operations.pause(LOOK_EVERY.min(left())).await;
    }
}

/// Whether the environment is held by a daemon that is not the one that was asked, and the number
/// of the process the lock file names as that daemon where it names one: a live process named
/// kr-controller other than `old`, or a daemon of another generation that answers. Nothing else
/// proves a successor.
async fn successor_of(
    operations: &impl Operations,
    old: Option<&ProcessStartIdentity>,
    within: Duration,
) -> Option<Option<u64>> {
    let named = operations
        .named_daemon()
        .filter(|named| old.is_none_or(|old| *named != old.pid.get()));
    if named.is_some() && old.is_some() {
        return Some(named);
    }
    (operations.look(within).await == Endpoint::Another).then(|| operations.named_daemon())
}

/// What answers at the environment's endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    /// Nothing listens there.
    Nobody,
    /// A daemon of the generation that was asked answers.
    Same,
    /// A daemon of another generation answers.
    Another,
    /// Something listens and does not answer, or the look could not be made.
    Unclear,
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
            Reached::Refused(_) | Reached::Silent => Endpoint::Unclear,
            Reached::Answered(listed) => match *listed {
                Listed::Other(_) => Endpoint::Another,
                Listed::Ours(mut client) => match client.request(Method::HostInfo, &()).await {
                    Ok(Ok(value)) => match value.to_typed::<HostInfoResult>() {
                        Ok(now) if generation.is_some_and(|asked| now.generation != asked) => {
                            Endpoint::Another
                        }
                        Ok(_) => Endpoint::Same,
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
            matches!(waited, End::NotEnded(Why::Running)),
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
            matches!(waited, End::NotEnded(Why::Held)),
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
            matches!(waited, End::NotEnded(Why::Running)),
            "a free lock and a listener that does not answer is not an end"
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
            matches!(waited, End::NotEnded(Why::Running)),
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
            End::NotEnded(Why::Running) => "not ended, running".to_owned(),
            End::NotEnded(Why::Held) => "not ended, held".to_owned(),
            End::NotEnded(Why::Unlooked(_)) => "not ended, not looked at".to_owned(),
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
        ended_before_the_request(supplied, supplied.connection(), old, closed, deadline).await
    }

    /// Where the connection was not closed and a daemon of the same start answers at the first
    /// look, the request's failure is the result at once: one look, no wait.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_of_the_same_start_at_the_first_look_gives_the_failure_at_once() {
        let process = asked_process();
        for old in [None, Some(&process)] {
            let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        assert_eq!(said(&ended), "not ended, running");
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
        assert_eq!(said(&ended), "not ended, running");
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
    /// its deadline as not ended and running. A supplied end could not show this.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_still_answers_in_every_round_is_not_ended_at_the_deadline() {
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
        let ended = wait_for_the_end(&supplied, None, END_BOUND).await;
        assert_eq!(said(&ended), "not ended, running");
        assert!(supplied.looks() > 100, "the wait looked round after round");
        assert_eq!(supplied.start.elapsed(), END_BOUND);

        // With an identity the process is read in every round, and a process that runs is the
        // daemon that has not ended, whatever answers at the endpoint.
        let process = asked_process();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
                "not ended, running",
            ),
            (ProcessState::Running, Ok(true), "not ended, running"),
            (ProcessState::Ended, Ok(false), "gone"),
            (ProcessState::Ended, Ok(true), "not ended, held"),
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
        ] {
            let supplied = Supplied::new()
                .held(vec![at_once(held)])
                .process(vec![at_once(state.clone())])
                .look(vec![at_once(Endpoint::Same)]);
            let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
            assert_eq!(said(&ended), expected, "{state:?}");
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
        let supplied = held_ended().look(vec![at_once(Endpoint::Same)]);
        let ended = wait_for_the_end(&supplied, Some(&process), END_BOUND).await;
        assert_eq!(
            said(&ended),
            "not ended, held",
            "a daemon of the same start is no successor"
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
            (Ok(false), Endpoint::Same, "not ended, running"),
            (Ok(false), Endpoint::Unclear, "not ended, running"),
            (Ok(true), Endpoint::Another, "successor None"),
            (Ok(true), Endpoint::Nobody, "not ended, running"),
            (Ok(true), Endpoint::Same, "not ended, running"),
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
            Before::Silent => "silent".to_owned(),
            Before::Stays => "answers".to_owned(),
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

    /// A frame that the daemon's end cut: the end of the stream, or a reset, inside a frame.
    fn a_frame_cut_by_the_end() -> kr_ipc::IpcError {
        kr_ipc::IpcError::TruncatedFrame {
            received: 3,
            expected: 16,
        }
    }

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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
        let before = greeting_failed(
            &supplied,
            &a_fault_of_the_socket(),
            None,
            id,
            the_deadline(),
        )
        .await;
        assert_eq!(before_said(&before), "answers");
        assert_eq!(
            supplied.calls(),
            vec![(Duration::ZERO, Call::Look(startup::ANSWER_BOUND))]
        );

        let process = asked_process();
        let fault = a_fault_of_the_socket();
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_fault_of_the_socket(),
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
            &a_fault_of_the_socket(),
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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

    /// Where the retry's connection finds nothing listening and the lock is held past the bound, no
    /// daemon has answered anything: the command's result is its silence (exit 1), after the whole
    /// bound, and never the failure of an answered request.
    #[tokio::test(start_paused = true)]
    async fn nothing_listening_with_the_lock_held_past_the_bound_is_silence() {
        let process = asked_process();
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
                an_environment(),
                the_deadline(),
            )
            .await;
            assert_eq!(before_said(&before), "silent", "{kind:?}");
            assert_eq!(supplied.start.elapsed(), END_BOUND, "{kind:?}");
        }
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
        match ended_by(Before::Silent, &environment, &none, true, &earlier) {
            Some(Completion::Reported(error)) => {
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
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
        let before = host_info_failed(
            &supplied,
            supplied.connection(),
            &a_fault_of_the_socket(),
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
        let fault = a_fault_of_the_socket();
        let supplied = Supplied::new().look(vec![at_once(Endpoint::Same)]);
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
        let error = unmade_request(id, &Shown::ipc(&fault));
        assert_eq!(error.exit_code(), 3);
        assert!(
            error
                .to_string()
                .contains("could not make its request for the control daemon"),
            "{error}"
        );
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
            Some(Err(a_fault_of_the_socket())),
            Some(Err(kr_ipc::IpcError::UnexpectedMessage(
                "a frame of another kind",
            ))),
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
            Asked::NotComposed { closed, .. } => closed,
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
}
