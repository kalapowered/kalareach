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
//! left, and neither its answer nor the daemon's end was seen) and `not_asked`. An answer that is
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
    /// Nothing was asked.
    NotAsked,
}

impl Knows {
    const fn word(self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::Told => "told",
            Self::MaybeAsked => "maybe_asked",
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
                Knows::NotAsked,
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
                 stop to wait for it.",
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

/// Reports a result that is a success.
fn done(said: &Shown, result: &Facts, json: bool) -> Completion {
    if json {
        output::document(&result.document().with("ok", true));
    } else {
        output::say(said);
    }
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
    // What earlier attempts recorded and whose process has gone is said at the start, and removed
    // once this command has seen its own result.
    let earlier = Earlier::read(&environment.paths);
    let none = Facts::none(earlier.said(id));
    *progress
        .earlier
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = none.records.clone();
    if !json {
        for said in &none.records {
            report::say(said);
        }
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
        Reached::Refused(error) => Ok(failed(
            CliError::HostUnavailable(shown!(
                "the control daemon for environment {} could not be reached: {}. No stop was \
                 requested.",
                id,
                Shown::ipc(&error)
            )),
            &none,
            json,
        )),
    }
}

/// What earlier attempts recorded whose process is no longer the one that recorded it.
struct Earlier {
    records: Vec<attempt::Recorded>,
}

impl Earlier {
    fn read(environment: &EnvironmentPaths) -> Self {
        Self {
            records: attempt::recorded(environment)
                .into_iter()
                .filter(|recorded| recorded.standing() != Standing::UnderWay)
                .collect(),
        }
    }

    fn said(&self, id: EnvironmentId) -> Vec<Shown> {
        self.records
            .iter()
            .map(|recorded| record_said(recorded, id))
            .collect()
    }

    /// Removes what was said, now that this command has ended with its own result seen.
    fn remove(&self) {
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
            "A {} is under way for environment {} (process {}, since {}); wait for it.",
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
            earlier.remove();
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
    let ending = match named_daemon(&environment.paths) {
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
    };
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
/// has gone. A daemon that is starting holds the install lock, shared, and is waited for there.
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
}

/// Sends the request, says that it left, and waits for its answer.
///
/// The answer is read from the connection, and anything but a whole answer to this request is an
/// unknown outcome: a daemon that ends for another cause gets no answer, and on Windows an answer
/// of more than about 4.5 KiB can be cut at the exit.
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
        Err(error) => return Asked::Unknown(Shown::ipc(&error)),
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
    let info = match host_info(&mut client, &environment.paths).await {
        Ok(info) => info,
        Err(error) => return failed(error, &none, json),
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
        Asked::Refused(error) => {
            // Nothing was taken, so an interrupt from here on has nothing to say but that.
            progress.enter(Stage::Refused);
            progress.remove_marker();
            return refused(&mut client, id, &info, error, &none, json).await;
        }
    };
    if knows == Knows::Told {
        let _ = progress.with_marker(|marker| marker.told());
    }
    drop(client);

    let answered = pid;
    // The process that is waited for by its start identity is the one that answered: a lock file
    // that names another says nothing about this daemon.
    let old = holder
        .as_ref()
        .filter(|holder| answered.is_none_or(|answered| answered == holder.pid.get()));
    let pid = pid.or_else(|| holder.as_ref().map(|holder| holder.pid.get()));
    let ended = wait_for_the_end(host, &environment.paths, info.generation, old, END_BOUND).await;
    let result = |knows| Facts {
        knows,
        pid,
        unsettled,
        records: none.records.clone(),
    };
    match ended {
        End::Gone => {
            progress.remove_marker();
            earlier.remove();
            let cut = match unsettled {
                Some(count) if count > 0 => shown!(
                    " {} session creates were still under way after {} seconds and were cut; the \
                     next daemon resolves them as it does after a crash.",
                    count,
                    STOP_SETTLE_MS / 1000
                ),
                _ => Shown::said(""),
            };
            let process = pid.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
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
            )
        }
        End::Successor(successor) => {
            progress.remove_marker();
            earlier.remove();
            let old = pid.map_or_else(
                || Shown::said("the control daemon"),
                |pid| shown!("process {}", pid),
            );
            let now = successor.map_or_else(
                || Shown::said("a control daemon"),
                |pid| shown!("process {}", pid),
            );
            done(
                &shown!(
                    "The control daemon of {} ended; {} now holds environment {}, so something \
                     started it again.",
                    old,
                    now,
                    id
                ),
                &result(Knows::Ended),
                json,
            )
        }
        End::NotEnded => {
            let what = match (knows, unknown) {
                (Knows::MaybeAsked, Some(why)) => shown!(
                    "did not show whether it took the stop ({}), and it has not ended",
                    why
                ),
                _ => Shown::said("was told to stop and has not ended"),
            };
            failed(
                CliError::Unfinished {
                    code: ErrorCode::EnvironmentUnavailable,
                    message: not_ended(&environment.paths, id, &what, (answered, holder.as_ref())),
                },
                &result(knows),
                json,
            )
        }
    }
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
    .await;
    match probe {
        Ok(Ok(Ok(_))) => failed(
            CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: shown!(
                    "The control daemon of environment {} is of another build and takes no stop \
                     request. Nothing was stopped. kr host update or kr host rollback switches \
                     this host to another release and replaces this daemon. Each checks the \
                     stores for that release before it switches, and starts this daemon again if \
                     it cannot switch.",
                    id
                ),
            },
            none,
            json,
        ),
        Ok(Ok(Err(probe))) if probe.code == ErrorCode::PermissionDenied => failed(
            CliError::refused_in_its_own_words(
                ErrorCode::PermissionDenied,
                shown!(
                    "The control daemon of environment {} takes no stop request or refuses it, \
                     and the check that tells which was refused too: {}. Nothing was stopped.",
                    id,
                    Shown::protocol(&probe)
                ),
            ),
            none,
            json,
        ),
        Ok(Ok(Err(other))) => failed(CliError::Refused(other), none, json),
        Ok(Err(error)) => failed(CliError::Ipc(error), none, json),
        Err(_) => failed(CliError::Refused(error), none, json),
    }
}

/// M4: the daemon was asked and has not ended after the wait.
fn not_ended(
    environment: &EnvironmentPaths,
    id: EnvironmentId,
    what: &Shown,
    (answered, holder): (Option<u64>, Option<&ProcessStartIdentity>),
) -> Shown {
    let ends_with = match answered
        .or_else(|| {
            holder
                .filter(|holder| runs_the_daemon(holder))
                .map(|holder| holder.pid.get())
        })
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

/// How the wait for the daemon's end came out.
enum End {
    /// The daemon's process has gone and the environment is free.
    Gone,
    /// The daemon has gone and another process holds the environment now; its number where the lock
    /// file names it.
    Successor(Option<u64>),
    /// The daemon had not ended when the wait did.
    NotEnded,
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
            *client = crate::resolve::open_controller(environment, crate::build_id()).await?;
            typed(client.request(Method::HostInfo, &()).await?)
        }
        other => typed(other),
    }
}

/// Waits up to `bound` for the daemon that was asked to stop to end: its process gone by its start
/// identity where it was read, and the environment's lock free or held by another process.
///
/// Each look is bounded by what is left of the one deadline, and a look that cannot be made
/// leaves the daemon as not ended.
async fn wait_for_the_end(
    host: &HostPaths,
    environment: &EnvironmentPaths,
    generation: ControllerGeneration,
    old: Option<&ProcessStartIdentity>,
    bound: Duration,
) -> End {
    let deadline = tokio::time::Instant::now() + bound;
    let installation = Installation::of(host, environment);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let held = installation.held(left).await;
        let process_gone = old.and_then(|old| match identity::process_state(old) {
            ProcessState::Ended => Some(true),
            ProcessState::Running => Some(false),
            ProcessState::Unknown { .. } => None,
        });
        match (held, process_gone) {
            (Ok(false), Some(true) | None) => return End::Gone,
            // The old process has gone and another holds the environment.
            (Ok(true), Some(true)) => {
                return End::Successor(
                    SingletonLock::holder(&environment.singleton_lock())
                        .ok()
                        .flatten()
                        .map(u64::from),
                );
            }
            // Where the old process is not known (no start identity could be read), a daemon of
            // another generation that answers is the successor.
            (Ok(true), None) if another_generation_answers(environment, generation).await => {
                return End::Successor(
                    SingletonLock::holder(&environment.singleton_lock())
                        .ok()
                        .flatten()
                        .map(u64::from),
                );
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return End::NotEnded;
        }
        tokio::time::sleep(LOOK_EVERY.min(left)).await;
    }
}

/// Whether a daemon that is not the one that was asked answers at the environment's endpoint.
async fn another_generation_answers(
    environment: &EnvironmentPaths,
    generation: ControllerGeneration,
) -> bool {
    let Ok(endpoint) = environment.controller_endpoint() else {
        return false;
    };
    let Reached::Answered(listed) = startup::reach(&endpoint, LOOK_EVERY * 20, &[]).await else {
        return false;
    };
    let Listed::Ours(mut client) = *listed else {
        return true;
    };
    match client.request(Method::HostInfo, &()).await {
        Ok(Ok(value)) => value
            .to_typed::<HostInfoResult>()
            .is_ok_and(|now| now.generation != generation),
        _ => false,
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
                .map_err(|error| kr_client::shown::Said::said(&error)),
            None => lock_held(&self.environment.paths),
        }
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
                &host,
                &environment,
                generation,
                Some(&own),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("the wait ends at its bound");
        assert!(
            matches!(waited, End::NotEnded),
            "a live holder is not an end"
        );
        drop(held);
        let ended = identity::ended_process_identity(std::process::id());
        let waited = wait_for_the_end(
            &host,
            &environment,
            generation,
            Some(&ended),
            Duration::from_secs(60),
        )
        .await;
        assert!(
            matches!(waited, End::Gone),
            "no holder and a process that has gone is the end"
        );
    }
}
