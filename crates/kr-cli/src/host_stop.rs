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
pub(crate) const ANSWER_BOUND: Duration = Duration::from_millis(STOP_SETTLE_MS + 5_000);

/// How long the end of the daemon is waited for once it was told to stop.
pub(crate) const END_BOUND: Duration = handover::DAEMON_STOP;

/// How often the end of the daemon is looked for.
const LOOK_EVERY: Duration = Duration::from_millis(50);

/// What a refusal says of the sessions meanwhile, for a command that stops the daemon.
const SESSIONS_GO_ON: &str = "Sessions and local attachments go on while no daemon runs.";

/// What a refusal says of the sessions meanwhile, for a command that stops the daemon and starts one.
const SESSIONS_GO_ON_THROUGH: &str = "Sessions and local attachments go on through a restart.";

/// What this command knows of whether the daemon was asked, for `--json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Knows {
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
    pub(crate) const fn word(self) -> &'static str {
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
    /// The daemon's end was seen and no start has been asked for: only a restart enters it.
    Ended = 4,
    /// A start has been asked for: only a restart enters it.
    Starting = 5,
}

/// What the command's interrupt handling and its work share.
pub(crate) struct Progress {
    pub(crate) stage: AtomicU8,
    /// The command's own record, from the moment it is written.
    pub(crate) marker: Mutex<Option<Marker>>,
    pub(crate) environment_id: EnvironmentId,
    /// What the command said at its start of the attempts earlier commands recorded.
    pub(crate) earlier: Mutex<Vec<Shown>>,
}

impl Progress {
    pub(crate) fn enter(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::SeqCst);
    }

    pub(crate) fn stage(&self) -> Stage {
        match self.stage.load(Ordering::SeqCst) {
            0 => Stage::BeforeAsking,
            1 => Stage::Asked,
            2 => Stage::Told,
            3 => Stage::Refused,
            4 => Stage::Ended,
            _ => Stage::Starting,
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

/// Which of the two commands that end the control daemon is running.
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

    /// What a refusal of the guard says of the sessions meanwhile.
    const fn sessions(self) -> &'static str {
        match self {
            Self::Stop => SESSIONS_GO_ON,
            Self::Restart => SESSIONS_GO_ON_THROUGH,
        }
    }

    /// What a text says where the command ended before it asked the daemon for anything.
    const fn nothing_asked(self) -> &'static str {
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

/// Runs one of the two commands.
///
/// The handlers stand from the first line: an interrupt before the request is written ends the
/// command with nothing asked and its record removed; after it, a hangup is ignored, and any other
/// interrupt says what may be so and exits, and never cancels a stop that was asked.
///
/// # Errors
///
/// Returns the failures that are not the command's own result: this installation's environment
/// cannot be found.
pub(crate) async fn run_command(which: Which, paths: &HostPaths, json: bool) -> Result<Completion> {
    let mut interrupts = Interrupts::catch();
    let environment = installation(paths)?;
    let progress = Progress {
        stage: AtomicU8::new(Stage::BeforeAsking as u8),
        marker: Mutex::new(None),
        environment_id: environment.environment_id,
        earlier: Mutex::new(Vec::new()),
    };
    let work = async {
        match which {
            Which::Stop => stop(paths, &environment, json, &progress).await,
            Which::Restart => {
                crate::host_restart::restart(paths, &environment, json, &progress).await
            }
        }
    };
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
                return Ok(match which {
                    Which::Stop => interrupted(&progress, stage, json),
                    Which::Restart => crate::host_restart::interrupted(&progress, stage, json),
                });
            }
        }
    }
}

/// Runs `kr host stop`.
///
/// # Errors
///
/// Returns the failures that are not the command's own result: this installation's environment
/// cannot be found.
pub async fn run(paths: &HostPaths, json: bool) -> Result<Completion> {
    run_command(Which::Stop, paths, json).await
}

/// This installation's own environment, whether or not a daemon has ever run there.
pub(crate) fn installation(paths: &HostPaths) -> Result<KnownEnvironment> {
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
        // Only a restart is ever past the end of the daemon it stopped.
        Stage::Told | Stage::Ended | Stage::Starting => (
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

/// The facts a result carries in `--json`.
#[derive(Clone)]
pub(crate) struct Facts {
    pub(crate) knows: Knows,
    pub(crate) pid: Option<u64>,
    pub(crate) unsettled: Option<u64>,
    /// What earlier attempts recorded, which this command said at its start.
    pub(crate) records: Vec<Shown>,
    /// What a restart started: absent for a stop, and null where the restart started no daemon.
    pub(crate) started: Option<Option<StartedFact>>,
}

impl Facts {
    /// Nothing asked, and nothing known of a process.
    pub(crate) fn none(records: Vec<Shown>) -> Self {
        Self {
            knows: Knows::NotAsked,
            pid: None,
            unsettled: None,
            records,
            started: None,
        }
    }

    /// These facts for a restart, which started no daemon so far.
    pub(crate) fn of_a_restart(self) -> Self {
        Self {
            started: Some(None),
            ..self
        }
    }

    pub(crate) fn document(&self) -> Document {
        let mut document = Document::new()
            .with("stop", self.knows.word())
            .with("pid", self.pid)
            .with("unsettled", self.unsettled);
        if let Some(started) = self.started {
            document.set(
                "started",
                started.map(|started| {
                    Document::new()
                        .with("start", started.start)
                        .with("pid", started.pid)
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

/// What both commands have done once they begin: the guard has passed, and what earlier attempts
/// recorded has been said. A record is removed only by [`done`], once the result that put it out
/// has been written.
pub(crate) struct Begun {
    pub(crate) earlier: Earlier,
    /// The facts of a result that asked nothing: the earlier records, said in `--json`.
    pub(crate) none: Facts,
}

/// The guard, then the records of earlier attempts, which are said at the start (in the document
/// under `--json`).
pub(crate) async fn begin(
    which: Which,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> std::result::Result<Begun, Completion> {
    let id = environment.environment_id;
    if let Err(error) = crate::bind::require_outside_to_end_a_daemon(
        &crate::build_id(),
        which.command(),
        which.sessions(),
    )
    .await
    {
        return Err(failed(error, &Facts::none(Vec::new()), json));
    }
    let mut earlier = Earlier::read(&environment.paths);
    let none = match which {
        Which::Stop => Facts::none(earlier.said(id)),
        Which::Restart => Facts::none(earlier.said(id)).of_a_restart(),
    };
    *progress
        .earlier
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = none.records.clone();
    if !json {
        earlier.say(id);
    }
    Ok(Begun { earlier, none })
}

/// A control daemon that answered the look, with what was read before anything was asked of it.
pub(crate) struct Daemon {
    pub(crate) client: LocalClient,
    /// What it said of itself.
    pub(crate) info: HostInfoResult,
    /// The process that held the environment, with its start identity, read before anything is
    /// asked: a process that has ended and not been collected is read as gone, and its number may
    /// be reused.
    pub(crate) holder: Option<ProcessStartIdentity>,
}

/// What the look at the environment found.
pub(crate) enum Looked {
    /// A control daemon of this command's public major answers.
    Daemon(Box<Daemon>),
    /// Nothing listens, and no daemon holds the environment.
    NoDaemon,
    /// The look ended the command with this result.
    Ended(Completion),
}

/// The look both commands make before they ask for anything: whether a daemon answers, what it says
/// of itself, and who holds the environment. A daemon that holds the environment and does not answer,
/// one of another public major and a look that cannot be made end the command here.
pub(crate) async fn look(
    which: Which,
    environment: &KnownEnvironment,
    json: bool,
    begun: &Begun,
) -> Looked {
    let id = environment.environment_id;
    let none = &begun.none;
    let endpoint = match environment.paths.controller_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => return Looked::Ended(failed(error.into(), none, json)),
    };
    match startup::reach(&endpoint, startup::ANSWER_BOUND, &[]).await {
        Reached::Answered(listed) => {
            let Listed::Ours(client) = *listed else {
                return Looked::Ended(failed(
                    CliError::Other(shown!(
                        "the control daemon for environment {} states another public major than \
                         this command does. {}",
                        id,
                        which.nothing_asked()
                    )),
                    none,
                    json,
                ));
            };
            let mut client = *client;
            // A daemon that answered the hello and does not answer this is a holder that is silent.
            let info = match tokio::time::timeout(
                startup::ANSWER_BOUND,
                host_info(&mut client, &environment.paths),
            )
            .await
            {
                Ok(Ok(info)) => info,
                Ok(Err(error)) => return Looked::Ended(failed(error, none, json)),
                Err(_) => {
                    return Looked::Ended(silent(
                        which,
                        environment,
                        none,
                        json,
                        startup::ANSWER_BOUND,
                    ));
                }
            };
            let holder = lock_holder(&environment.paths);
            Looked::Daemon(Box::new(Daemon {
                client,
                info,
                holder,
            }))
        }
        Reached::Silent => Looked::Ended(silent(
            which,
            environment,
            none,
            json,
            startup::ANSWER_BOUND,
        )),
        Reached::Refused(error) if startup::nothing_listening(&error) => {
            match lock_held(&environment.paths) {
                Ok(false) => Looked::NoDaemon,
                Ok(true) => Looked::Ended(holds_and_is_silent(which, environment, none, json)),
                Err(error) => Looked::Ended(failed(
                    CliError::Other(shown!(
                        "whether a control daemon holds environment {} could not be read: {}. {}",
                        id,
                        error,
                        which.nothing_asked()
                    )),
                    none,
                    json,
                )),
            }
        }
        Reached::Refused(error) => Looked::Ended(failed(
            CliError::HostUnavailable(shown!(
                "the control daemon for environment {} could not be reached: {}. {}",
                id,
                Shown::ipc(&error),
                which.nothing_asked()
            )),
            none,
            json,
        )),
    }
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

/// The command, from the guard to the daemon's end.
async fn stop(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> Result<Completion> {
    let begun = match begin(Which::Stop, environment, json, progress).await {
        Ok(begun) => begun,
        Err(ended) => return Ok(ended),
    };
    Ok(match look(Which::Stop, environment, json, &begun).await {
        Looked::Daemon(daemon) => {
            stop_the_daemon(host, environment, *daemon, json, progress, &begun).await
        }
        Looked::NoDaemon => done(
            &shown!(
                "No control daemon runs for environment {}. Nothing was stopped.{}",
                environment.environment_id,
                under_way_said(environment)
            ),
            &begun.none,
            json,
            &begun.earlier,
        ),
        Looked::Ended(ended) => ended,
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
    pub(crate) fn read(environment: &EnvironmentPaths) -> Self {
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
    pub(crate) fn say(&mut self, id: EnvironmentId) {
        self.written = self
            .records
            .iter()
            .all(|recorded| report::shown_before_going_on(&record_said(recorded, id)));
    }

    pub(crate) fn said(&self, id: EnvironmentId) -> Vec<Shown> {
        self.records
            .iter()
            .map(|recorded| record_said(recorded, id))
            .collect()
    }

    /// Removes what was put out, now that this command's own result has been written. Under
    /// `--json` the records are in that document; otherwise they were said at the start. A record
    /// that was not put out stays for the next command to say.
    pub(crate) fn remove_those_put_out(&self, json: bool) {
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
            "The last record of a {} (process {}) is at {}: it had asked for a new control daemon \
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

/// Something accepted the connection and did not answer within `bound`.
fn silent(
    which: Which,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
    bound: Duration,
) -> Completion {
    match lock_held(&environment.paths) {
        Ok(true) => holds_and_is_silent(which, environment, none, json),
        _ => failed(
            CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: shown!(
                    "the control daemon listening for environment {} accepted the connection and \
                     did not answer within {} seconds. {} Run {} again in a moment.",
                    environment.environment_id,
                    bound.as_secs(),
                    which.nothing_asked(),
                    which.command()
                ),
            },
            none,
            json,
        ),
    }
}

/// A daemon holds the environment and does not answer, so it may be starting or stopping.
fn holds_and_is_silent(
    which: Which,
    environment: &KnownEnvironment,
    none: &Facts,
    json: bool,
) -> Completion {
    let id = environment.environment_id;
    let ending = how_to_end_the_holder(&environment.paths);
    failed(
        CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "A control daemon holds environment {} and does not answer, so it may be starting \
                 or stopping. No stop was requested. Run {} again in a moment. {}{}",
                id,
                which.command(),
                ending,
                match which {
                    Which::Stop => "",
                    Which::Restart => " This command requested no stop and no start.",
                }
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
pub(crate) enum Asked {
    /// The daemon took the stop and answered.
    Taken(HostStopResult),
    /// The outcome is not known: no answer came, it was cut, or the daemon's word does not say
    /// whether it took the stop. The daemon is waited for as one that took it.
    Unknown(Shown),
    /// The daemon refused, and its word is that nothing was done.
    Refused(ProtocolError),
    /// The request could not be made: nothing was sent.
    /// The request could not be made: nothing was sent. `closed` is whether the daemon closed the
    /// connection, which a daemon does when it goes.
    NotComposed { why: Shown, closed: bool },
}

/// Sends the request, says that it left, and waits for its answer.
///
/// The answer is read from the connection, and anything but a whole answer to this request is an
/// unknown outcome: a daemon that ends for another cause gets no answer, and the daemon stops when
/// its write of the answer has completed, failed or reached its bound, so an answer can be cut.
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
            return Asked::NotComposed {
                closed: matches!(error, kr_ipc::IpcError::PeerClosed),
                why: Shown::ipc(&error),
            };
        }
    };
    // Set before the request is written: an interrupt from here on may find it taken. A request for
    // the launch alone stops nothing and enters no stage.
    if !launch_only {
        progress.enter(Stage::Asked);
    }
    let request_id = mutation.request_id;
    if let Err(error) = client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
    {
        return Asked::Unknown(Shown::ipc(&error));
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
    daemon: Daemon,
    json: bool,
    progress: &Progress,
    begun: &Begun,
) -> Completion {
    let which = Which::Stop;
    let id = environment.environment_id;
    let none = begun.none.clone();
    let earlier = &begun.earlier;
    let Daemon {
        mut client,
        info,
        holder,
    } = daemon;
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

    let (knows, pid, unsettled, unknown) = match ask(&mut client, id, json, progress, false).await {
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
            // the unmade request's failure.
            progress.remove_marker();
            let named = holder.as_ref().map(|holder| holder.pid.get());
            if let Some(ended) = ended_before_the_request(
                host,
                &environment.paths,
                info.generation,
                holder.as_ref(),
                closed,
            )
            .await
            {
                let facts = Facts {
                    knows: Knows::Ended,
                    pid: named,
                    unsettled: None,
                    records: none.records.clone(),
                    started: None,
                };
                return done(
                    &ended_before_the_request_said(id, named, ended, &why),
                    &facts,
                    json,
                    earlier,
                );
            }
            return failed(
                CliError::HostUnavailable(shown!(
                    "kr host stop could not make its request for the control daemon of \
                     environment {}: {}. Nothing was sent, and nothing was stopped.",
                    id,
                    why
                )),
                &none,
                json,
            );
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
    let ended = wait_for_the_end(host, &environment.paths, info.generation, old, END_BOUND).await;
    let result = |knows| Facts {
        knows,
        pid,
        unsettled,
        records: none.records.clone(),
        started: None,
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
                     the sessions again. Paired devices' connections close until a daemon runs.{} Run \
                     kr host restart to start one where a start is chosen.",
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
                Why::Held => still_held(which, &environment.paths, id),
                Why::Unlooked(why) => unlooked(which, id, not_known, &why),
                Why::Running => {
                    let what = match not_known {
                        Some(failure) => shown!(
                            "did not show whether it took the stop ({}), and it has not ended",
                            *failure
                        ),
                        None => Shown::said("was told to stop and has not ended"),
                    };
                    not_ended(which, &environment.paths, id, &what, old)
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

/// Where the request could not be made, whether the daemon had ended when it could not be: the end,
/// where the daemon's process has gone and the environment's lock is free or another control
/// daemon holds it. A daemon that closed the connection is going, and a listener that is gone is
/// waited for to its end within the one deadline, once. A daemon that did not close it and still
/// answers at its endpoint stays, and nothing is waited for. A daemon that has not ended by the
/// deadline is the failure's, and so is one whose end cannot be looked at.
async fn ended_before_the_request(
    host: &HostPaths,
    environment: &EnvironmentPaths,
    generation: ControllerGeneration,
    old: Option<&ProcessStartIdentity>,
    closed: bool,
) -> Option<End> {
    if !closed
        && endpoint_look(environment, generation, startup::ANSWER_BOUND).await == Endpoint::Same
    {
        return None;
    }
    match wait_for_the_end(host, environment, generation, old, END_BOUND).await {
        End::NotEnded(_) => None,
        ended => Some(ended),
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
pub(crate) async fn refused(
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

/// M4: the daemon was asked and has not ended after the wait. A process is named only while it is
/// a process named kr-controller: `old`, the process that held the environment before the request
/// where the daemon's answer, if it came, named it too, or the one the lock file names now.
pub(crate) fn not_ended(
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

/// The environment after the daemon's process was seen to have gone, and still held when the wait
/// ended: what is said is that the process has gone and that something holds the environment which
/// is not shown to be a control daemon. It does not say that the daemon ended: the daemon ended only
/// where the lock is free or another control daemon holds it.
pub(crate) fn still_held(which: Which, environment: &EnvironmentPaths, id: EnvironmentId) -> Shown {
    shown!(
        "The process of the control daemon for environment {} has gone, and something that is not \
         shown to be a control daemon still holds the environment after {} seconds. Run {} again \
         in a moment. {}{}",
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
pub(crate) fn unlooked(
    which: Which,
    id: EnvironmentId,
    not_known: Option<&Shown>,
    why: &Shown,
) -> Shown {
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
             whether it has ended could not be read after {} seconds: {}. Run {} again in a \
             moment.{}",
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
pub(crate) enum Why {
    /// Its process runs, or nothing shows that it has gone: the daemon is told to stop and goes on.
    Running,
    /// Its process has gone and something holds the environment that nothing shows to be a daemon.
    Held,
    /// The lock could not be looked at.
    Unlooked(Shown),
}

/// How the wait for the daemon's end came out.
pub(crate) enum End {
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
            *client = crate::resolve::open_controller(environment, crate::build_id()).await?;
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
/// Each look is bounded by what is left of the one deadline, and a look that cannot be made
/// leaves the daemon as not ended.
pub(crate) async fn wait_for_the_end(
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
        let unlooked = held.as_ref().err().cloned();
        let process = old.map(identity::process_state);
        let old_gone = matches!(process, Some(ProcessState::Ended));
        let seen = match (held, process) {
            (Ok(false), Some(ProcessState::Ended)) => Some(End::Gone),
            (Ok(true), Some(ProcessState::Ended)) => {
                successor_of(environment, generation, old, left)
                    .await
                    .map(End::Successor)
            }
            // The process runs, or the system did not say: the daemon has not ended.
            (_, Some(ProcessState::Running | ProcessState::Unknown { .. })) => None,
            (Ok(false), None) => match endpoint_look(environment, generation, left).await {
                Endpoint::Nobody => Some(End::Gone),
                Endpoint::Another => Some(End::Successor(named_daemon(environment))),
                Endpoint::Same | Endpoint::Unclear => None,
            },
            (Ok(true), None) => successor_of(environment, generation, None, left)
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
        tokio::time::sleep(LOOK_EVERY.min(left)).await;
    }
}

/// Whether the environment is held by a daemon that is not the one that was asked, and the number
/// of the process the lock file names as that daemon where it names one: a live process named
/// kr-controller other than `old`, or a daemon of another generation that answers. Nothing else
/// proves a successor.
async fn successor_of(
    environment: &EnvironmentPaths,
    generation: ControllerGeneration,
    old: Option<&ProcessStartIdentity>,
    within: Duration,
) -> Option<Option<u64>> {
    let named =
        named_daemon(environment).filter(|named| old.is_none_or(|old| *named != old.pid.get()));
    if named.is_some() && old.is_some() {
        return Some(named);
    }
    (endpoint_look(environment, generation, within).await == Endpoint::Another)
        .then(|| named_daemon(environment))
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
    generation: ControllerGeneration,
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
                        Ok(now) if now.generation != generation => Endpoint::Another,
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
            matches!(waited, End::NotEnded(Why::Running)),
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
                &host,
                &environment,
                generation,
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
            &host,
            &environment,
            generation,
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
            &host,
            &environment,
            generation,
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
            &host,
            &environment,
            generation,
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
            &host,
            &environment,
            generation,
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
}
