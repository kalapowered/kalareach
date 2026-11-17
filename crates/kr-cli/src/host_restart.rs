//! `kr host restart`: stops this installation's control daemon as `kr host stop` does, and starts one
//! the way `kr new` starts one.
//!
//! The model is the one `kr host stop` keeps: the request is served on the account's own local
//! socket, and this command is the way a person asks, with a guard against an accident and no
//! boundary. It stops no session: workers belong to the service manager or to the account and a
//! daemon that starts later finds them again.
//!
//! A restart is not done when the old daemon has ended. It says it restarted the daemon only once
//! a daemon that it started, or that the service manager started on its ask, answers; a daemon that
//! something else started after the old one ended is named for what it is.
//!
//! Before it stops anything the command looks at what the start it would make needs (`preflight`)
//! and at how the daemon was started (the launch comparison): a restart that would stop a daemon
//! and then find no equivalent start refuses first, and says that nothing was stopped.

mod holder;
mod proof;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_controller::attempt::{self, Marker};
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::configuration::ControllerStartup;
use kr_protocol::ids::{ControllerGeneration, EnvironmentId};

use crate::error::{CliError, Result};
use crate::host_stop::{
    self, Asked, AtStart, Before, Begun, Cut, End, Facts, Knows, Looked, Operations, Progress,
    Real, Settled, Stage, Start, StartedFact, Which,
};
use crate::report::Completion;
use crate::resolve::KnownEnvironment;
use crate::restart_launch;
use crate::startup::{self, Started, Unstartable};

/// Where a restart is past its stop. The stop's own stages stand in the [`Progress`] that the work
/// and the interrupt share; these are the two that only a restart enters, and whether the daemon
/// that was stopped was seen to end: what this command did, and not what its record names, which a
/// host that cannot read the lock's holder leaves out.
struct Past {
    beyond: AtomicU8,
    daemon_ended: AtomicBool,
}

/// How far past its stop a restart is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Beyond {
    /// Not past it: the stop's stage says where the command is.
    Stop = 0,
    /// The daemon's end was seen and no start has been asked for.
    Ended = 1,
    /// A start has been asked for.
    Starting = 2,
}

impl Past {
    const fn new() -> Self {
        Self {
            beyond: AtomicU8::new(Beyond::Stop as u8),
            daemon_ended: AtomicBool::new(false),
        }
    }

    fn enter(&self, beyond: Beyond) {
        self.beyond.store(beyond as u8, Ordering::SeqCst);
    }

    fn beyond(&self) -> Beyond {
        match self.beyond.load(Ordering::SeqCst) {
            0 => Beyond::Stop,
            1 => Beyond::Ended,
            _ => Beyond::Starting,
        }
    }

    /// The stop returned and the daemon was seen to end.
    fn end_seen(&self) {
        self.daemon_ended.store(true, Ordering::SeqCst);
        self.enter(Beyond::Ended);
    }
}

/// Runs `kr host restart`.
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
    let past = Past::new();
    host_stop::run_with(
        paths,
        json,
        async |environment, progress| restart(paths, environment, json, progress, &past).await,
        |progress, stage, json| interrupted(progress, stage, &past, json),
        |stage| stage != Stage::BeforeAsking || past.beyond() != Beyond::Stop,
    )
    .await
}

/// The command, from the guard to the proof of the daemon it started.
async fn restart(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
) -> Result<Completion> {
    let id = environment.environment_id;
    let begun = match host_stop::begin(Which::Restart, environment, json, progress).await {
        Ok(begun) => begun,
        Err(ended) => return Ok(ended),
    };
    let begun = Begun {
        none: begun.none.of_a_restart(),
        ..begun
    };
    // Before anything is asked of a daemon: what the start needs is there, or nothing is stopped.
    let start = match startup::preflight(environment).await {
        Ok(start) => start,
        Err(unstartable) => {
            return Ok(host_stop::failed(
                not_startable(id, unstartable),
                &begun.none,
                json,
            ));
        }
    };
    Ok(match host_stop::look(host, environment).await? {
        Looked::Daemon(client) => {
            restart_the_daemon(
                host,
                environment,
                start,
                *client,
                json,
                progress,
                past,
                &begun,
            )
            .await
        }
        Looked::Said(seen) => {
            at_the_start(host, environment, &seen, json, progress, past, &begun).await
        }
        Looked::Refused { before, error } => {
            match host_stop::ended_by(
                Which::Restart,
                before,
                environment,
                &begun.none,
                json,
                &begun.earlier,
            ) {
                Ok(completion) => completion,
                Err(cause) => host_stop::failed(
                    host_stop::unreached(Which::Restart, id, &error, cause),
                    &begun.none,
                    json,
                ),
            }
        }
    })
}

/// What the first reach of the endpoint, or the read of the daemon, showed where it ends the
/// command with no stop: no daemon runs, and the restart starts one; a holder does not answer, and
/// the restart waits for it; the other results end the command as the stop's do, with no start.
async fn at_the_start(
    host: &HostPaths,
    environment: &KnownEnvironment,
    seen: &Start,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let said = host_stop::decided_at_the_start(seen, environment);
    match said.sentence {
        AtStart::NoDaemon => {
            start_where_none_ran(host, environment, json, progress, past, begun).await
        }
        AtStart::HoldsAndSilent => {
            wait_for_the_holder(host, environment, json, progress, past, begun).await
        }
        _ => host_stop::say_at_the_start(
            Which::Restart,
            said,
            environment,
            &begun.none,
            json,
            &begun.earlier,
            startup::ANSWER_BOUND,
        ),
    }
}

/// A process holds the environment and does not answer, so it may be a daemon that is starting, as
/// another restart's start makes one, or one that is stopping. This command stops nothing and starts
/// nothing beside it: it waits, within the start's bound, for the holder to answer or to let go. A
/// daemon that answers is the end of this command, which stopped none and started none; a
/// holder that lets go leaves no daemon, and the restart starts one; one that does neither is said
/// as the stop says it.
async fn wait_for_the_holder(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    // No daemon was asked here, so no generation is the one that answers: any answer counts.
    let operations = Real::of(host, &environment.paths, Some(ControllerGeneration::new(0)));
    match holder::wait(&operations, startup::START_BOUND).await {
        holder::Holder::Answers => {
            let named = operations.named_daemon();
            host_stop::done(
                &holder_answers_said(id, named),
                &Facts {
                    pid: named,
                    ..begun.none.clone()
                },
                json,
                &begun.earlier,
            )
        }
        holder::Holder::Gone => {
            start_where_none_ran(host, environment, json, progress, past, begun).await
        }
        holder::Holder::Silent => host_stop::failed(
            CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message: holder_silent_said(environment),
            },
            &begun.none,
            json,
        ),
    }
}

/// What the restart says where a process held the environment and did not answer, and a daemon
/// answers now: that this command stopped none and started none.
fn holder_answers_said(id: EnvironmentId, named: Option<u64>) -> Shown {
    shown!(
        "A control daemon held environment {} and did not answer, and a control daemon{} answers \
         now. This command stopped none and started none.",
        id,
        process_said(named)
    )
}

/// What the restart says where a process holds the environment and neither answers nor lets go
/// within the start's bound.
fn holder_silent_said(environment: &KnownEnvironment) -> Shown {
    shown!(
        "A control daemon holds environment {} and does not answer, so it may be starting or \
         stopping. No stop was requested. Run kr host restart again in a moment. {} This command \
         requested no stop and no start.",
        environment.environment_id,
        host_stop::how_to_end_the_holder(&environment.paths)
    )
}

/// ` (process N)` where the process is known, and nothing otherwise.
fn process_said(pid: Option<u64>) -> Shown {
    pid.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid))
}

/// What a restart that finds the start unmakeable says: the start's own refusal, and that nothing
/// was stopped. A refusal of the setup is `HOST_NOT_CONFIGURED`; a manager or a lock that could not
/// be asked is an unfinished command.
fn not_startable(id: EnvironmentId, unstartable: Unstartable) -> CliError {
    let remedy = unstartable
        .remedy
        .map_or_else(|| Shown::said(""), |remedy| shown!(" {}", remedy));
    let message = shown!(
        "kr host restart can make no start for environment {}: {}. Nothing was stopped.{}",
        id,
        unstartable.why,
        remedy
    );
    if unstartable.not_set_up {
        CliError::HostUnavailable(message)
    } else {
        CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message,
        }
    }
}

/// What the restart's stop came to where the daemon was seen to end.
struct Stopped {
    /// The process that held the environment before, where the command read it.
    named: Option<u64>,
    /// The process that `--json` shows for the daemon that was stopped.
    pid: Option<u64>,
    /// The creates that were still under way when the daemon went on with its stop.
    unsettled: Option<u64>,
    /// Another daemon that holds the environment since the end, and the process the lock names.
    successor: Option<Option<u64>>,
    /// The generation of the daemon that was stopped, where the command read it.
    generation: Option<ControllerGeneration>,
    /// The stop's own words, where its request could not be made and the daemon was seen to end:
    /// the restart did not stop it, and says so before it says what its start did.
    first: Option<Shown>,
}

/// A control daemon answers: asks how it was started, refuses before it stops anything where the
/// start would not give what it has, stops the daemon, and then starts one and proves it.
// One argument for each fact its steps read: the paths, the environment, the start, the connection, the output form, the progress, where the restart is past its stop and what it read before the daemon.
#[allow(clippy::too_many_arguments)]
async fn restart_the_daemon(
    host: &HostPaths,
    environment: &KnownEnvironment,
    start: ControllerStartup,
    client: LocalClient,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    let (mut client, info) =
        match host_stop::read_the_daemon(host, environment, client, json, &begun.none).await {
            Ok(read) => read,
            Err(cut) => {
                return cut_said(host, environment, cut, None, json, progress, past, begun).await;
            }
        };
    // How it was started, before anything is stopped. The request for it stops nothing. A daemon of
    // another build that lists no such request refuses it, and says so as `kr host stop` does.
    let launch = match host_stop::ask(&mut client, id, json, progress, true).await {
        Asked::Taken(result) => result.launch.0,
        Asked::Refused(error) => {
            let refusal = Facts {
                knows: Knows::Refused,
                ..begun.none.clone()
            };
            return host_stop::refused(&mut client, id, &info, error, &refusal, json).await;
        }
        // A daemon that cannot say how it was started, or whose answer was cut or withheld, gives
        // no launch to compare: the restart goes on, since a start that fails after the stop says
        // so and the keys stay on disk.
        Asked::Unknown(_) | Asked::NotComposed { .. } => None,
    };
    if let Some(launch) = &launch {
        let differences = restart_launch::compare_here(launch, start, &environment.paths);
        if !differences.is_none() {
            return host_stop::failed(
                CliError::HostUnavailable(differences.said(id)),
                &begun.none,
                json,
            );
        }
    }
    let old = host_stop::lock_holder(&environment.paths);
    let settled = match host_stop::ask_and_wait(
        Which::Restart,
        host,
        environment,
        client,
        &info,
        json,
        progress,
        &begun.none,
    )
    .await
    {
        Ok(settled) => settled,
        Err(cut) => {
            return cut_said(
                host,
                environment,
                cut,
                Some((info.generation, old)),
                json,
                progress,
                past,
                begun,
            )
            .await;
        }
    };
    let (successor, named) = match &settled.ended {
        End::Gone => (None, settled.old.as_ref().map(|old| old.pid.get())),
        End::Successor(successor) => (
            Some(*successor),
            settled.old.as_ref().map(|old| old.pid.get()),
        ),
        // The daemon was not seen to end: the stop's own words, with nothing started.
        End::NotEnded(..) => {
            return host_stop::say_the_stop(
                Which::Restart,
                settled,
                environment,
                &begun.none,
                json,
                progress,
                &begun.earlier,
            );
        }
    };
    let Settled {
        pid,
        unsettled,
        old,
        ..
    } = settled;
    let stopped = Stopped {
        named,
        pid,
        unsettled,
        successor,
        generation: Some(info.generation),
        first: None,
    };
    after_the_end(host, environment, json, progress, past, begun, stopped, old).await
}

/// What ended the command before the daemon's end was waited for. A daemon that was seen to end
/// where the request could not be made is the end of the stop as another command's stop has
/// brought it, and the restart goes on to start; the other ends are the stop's own.
// One argument for each fact its steps read: the paths, the environment, what ended the command, what the read gave, the output form, the progress, where the restart is past its stop and what it read before the daemon.
#[allow(clippy::too_many_arguments)]
async fn cut_said(
    host: &HostPaths,
    environment: &KnownEnvironment,
    cut: Cut,
    read: Option<(
        ControllerGeneration,
        Option<kr_protocol::identity::ProcessStartIdentity>,
    )>,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    match cut {
        Cut::Said(completion) => completion,
        Cut::Silent => {
            at_the_start(
                host,
                environment,
                &Start::Silent,
                json,
                progress,
                past,
                begun,
            )
            .await
        }
        Cut::Unmade { before, error } => match ended_without_a_request(before) {
            Ok((first, pid, end)) => {
                let (generation, old) = match read {
                    Some((generation, old)) => (Some(generation), old),
                    None => (None, None),
                };
                let stopped = Stopped {
                    named: pid,
                    pid,
                    unsettled: None,
                    successor: match end {
                        End::Successor(successor) => Some(successor),
                        End::Gone | End::NotEnded(..) => None,
                    },
                    generation,
                    first: Some(first),
                };
                after_the_end(host, environment, json, progress, past, begun, stopped, old).await
            }
            Err(before) => host_stop::unmade_ended(
                Which::Restart,
                *before,
                &error,
                id,
                environment,
                &begun.none,
                json,
                &begun.earlier,
            ),
        },
    }
}

/// What a restart does with a request that could not be made: where the daemon was seen to end, or
/// another daemon holds the environment now, it goes on to its start, with the stop's own words
/// for that state as the first of its result (it did not stop the daemon); any other end is the
/// stop's, which the caller says.
fn ended_without_a_request(
    before: Before,
) -> std::result::Result<(Shown, Option<u64>, End), Box<Before>> {
    match before {
        Before::Ended { said, pid, end } => Ok((said, pid, end)),
        other => Err(Box::new(other)),
    }
}

/// The daemon that was stopped has ended: the start is made, and the daemon that answers is proved
/// to be the one this command started, where no other daemon holds the environment.
// One argument for each fact its steps read: the paths, the environment, the output form, the progress, where the restart is past its stop, what it read before the daemon, what the stop came to and the daemon it stopped.
#[allow(clippy::too_many_arguments)]
async fn after_the_end(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
    stopped: Stopped,
    old: Option<kr_protocol::identity::ProcessStartIdentity>,
) -> Completion {
    let id = environment.environment_id;
    past.end_seen();
    // The record is the command's own until a daemon that it started answers. A request that could
    // not be made let it go, and the start needs it again.
    if progress.with_marker(|_| ()).is_none() {
        let _ = begin_the_record(environment, old, progress);
    }
    let facts = Facts {
        knows: Knows::Ended,
        pid: stopped.pid,
        unsettled: stopped.unsettled,
        ..begun.none.clone()
    };
    let proved = match stopped.successor {
        // Another daemon holds the environment: nothing is started beside it.
        Some(successor) => match wait_for_the_successor(environment, successor).await {
            Ok(proved) => Ok(proved),
            Err(error) => return host_stop::failed(error, &facts, json),
        },
        None => start_and_prove(host, environment, stopped.generation, progress, past).await,
    };
    let creates = host_stop::creates_under_way(stopped.unsettled);
    match proved {
        Ok(Proved::Ours(started)) => {
            progress.remove_marker();
            let said = match &stopped.first {
                None => restarted_said(id, stopped.named, &started, creates),
                Some(first) => unmade_then_started_said(first, &started),
            };
            host_stop::done(
                &said,
                &Facts {
                    started: Some(Some(started_fact(&started))),
                    ..facts
                },
                json,
                &begun.earlier,
            )
        }
        Ok(Proved::Another {
            serving,
            launched,
            cut,
        }) => {
            progress.remove_marker();
            let said = match (&stopped.first, launched) {
                (Some(first), launched) => unmade_and_another_serves_said(
                    first,
                    stopped.successor.is_some(),
                    serving,
                    launched,
                    cut,
                ),
                (None, Some(started)) if cut => stopped_and_another_serves_after_a_cut(
                    id,
                    stopped.named,
                    serving,
                    &started,
                    creates,
                ),
                (None, launched) => stopped_and_another_already_serves_said(
                    id,
                    stopped.named,
                    serving,
                    launched,
                    creates,
                ),
            };
            host_stop::done(&said, &facts, json, &begun.earlier)
        }
        Err(failed) => {
            failed
                .reported(
                    environment,
                    Had::Daemon(stopped.named),
                    stopped.first.as_ref(),
                    json,
                    progress,
                    &facts,
                )
                .await
        }
    }
}

/// Another daemon holds the environment after the one that was stopped ended: waits for it to
/// answer, and starts nothing beside it.
async fn wait_for_the_successor(
    environment: &KnownEnvironment,
    successor: Option<u64>,
) -> std::result::Result<Proved, CliError> {
    let id = environment.environment_id;
    let endpoint = environment.paths.controller_endpoint()?;
    let deadline = tokio::time::Instant::now() + startup::START_BOUND;
    match startup::answered_by(&endpoint, deadline, &[], || {}).await {
        Ok(_) => Ok(Proved::Another {
            serving: successor,
            launched: None,
            cut: false,
        }),
        Err(last) => Err(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "A control daemon{} holds environment {} since the daemon that was stopped ended, \
                 and it did not answer within {} seconds: {}. No new daemon was started. Run kr \
                 host restart again once it answers.",
                process_said(successor),
                id,
                startup::START_BOUND.as_secs(),
                last
            ),
        }),
    }
}

/// No control daemon runs: the start is made, and the daemon that answers is proved to be the one
/// this command started.
async fn start_where_none_ran(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    let none = begun.none.clone();
    if let Err(error) = begin_the_record(environment, None, progress) {
        return host_stop::failed(
            CliError::Other(shown!(
                "kr host restart could not record its attempt: {}. No start was made.",
                Shown::ipc(&error)
            )),
            &none,
            json,
        );
    }
    let result = start_and_prove(host, environment, None, progress, past).await;
    match result {
        Ok(Proved::Ours(started)) => {
            progress.remove_marker();
            host_stop::done(
                &none_ran_started_said(id, &started, host_stop::under_way_said(environment)),
                &Facts {
                    started: Some(Some(started_fact(&started))),
                    ..none
                },
                json,
                &begun.earlier,
            )
        }
        Ok(Proved::Another {
            serving,
            launched,
            cut,
        }) => {
            progress.remove_marker();
            let said = match launched {
                Some(started) if cut => none_ran_and_another_serves_after_a_cut(
                    id,
                    serving,
                    &started,
                    host_stop::under_way_said(environment),
                ),
                launched => none_ran_and_another_already_serves_said(
                    id,
                    serving,
                    launched,
                    host_stop::under_way_said(environment),
                ),
            };
            host_stop::done(&said, &none, json, &begun.earlier)
        }
        Err(failed) => {
            failed
                .reported(environment, Had::NoDaemon, None, json, progress, &none)
                .await
        }
    }
}

/// What a restart's start came to once a daemon answered.
pub(crate) enum Proved {
    /// The daemon this command started, or had the manager start, answers and holds the
    /// environment.
    Ours(Started),
    /// A control daemon answers that this command did not start: another start won the
    /// environment, or something else started one.
    Another {
        /// The process that the answering daemon states, where it states one.
        serving: Option<u64>,
        /// What this command launched, where it launched something, and none where its look
        /// found the daemon already there. The process that answers is not the one launched.
        launched: Option<Started>,
        /// Whether the exchange that proves which daemon answers was cut on the connection that
        /// the start gave, so that the daemon that is named here was read on a later one. The
        /// command then does not know what became of the daemon on the first connection, or
        /// whether it was the one this command launched.
        cut: bool,
    },
}

impl Proved {
    /// This outcome for a proof whose exchange was cut on the connection that the start gave and
    /// was then read whole on another: where this command launched something and another process
    /// answers, the outcome says that the exchange was cut.
    fn after_a_cut(self) -> Self {
        match self {
            Self::Another {
                serving,
                launched: Some(started),
                ..
            } => Self::Another {
                serving,
                launched: Some(started),
                cut: true,
            },
            other => other,
        }
    }

    /// What a result says where another daemon serves: that this command's own start, where it
    /// made one, did not take the environment.
    fn own_start_said(launched: Option<Started>) -> Shown {
        match launched {
            None => Shown::said(""),
            Some(started) => shown!(
                " This command's own start{} did not take the environment.",
                process_said(started.pid.map(u64::from))
            ),
        }
    }
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and the
/// daemon that this command started answers: the stop's own words for that state, then the start.
fn unmade_then_started_said(first: &Shown, started: &Started) -> Shown {
    shown!(
        "{} This command then started a control daemon{} under the {} start. No session was stopped.",
        *first,
        process_said(started.pid.map(u64::from)),
        start_said(started)
    )
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and
/// another daemon serves the environment: after a daemon that holds it since the end, nothing was
/// started; otherwise what this command's own start came to, where it made one.
fn unmade_and_another_serves_said(
    first: &Shown,
    successor: bool,
    serving: Option<u64>,
    launched: Option<Started>,
    cut: bool,
) -> Shown {
    if successor {
        return shown!(
            "{} This command sent nothing and started none. No session was stopped.",
            *first
        );
    }
    match launched {
        None => shown!(
            "{} A control daemon already serves the environment{}. This command started none. No \
             session was stopped.",
            *first,
            process_said(serving)
        ),
        Some(started) if cut => shown!(
            "{} A control daemon now serves the environment{}. This command's own start{} does not \
             serve it. No session was stopped.",
            *first,
            process_said(serving),
            process_said(started.pid.map(u64::from))
        ),
        Some(started) => shown!(
            "{} A control daemon already serves the environment{}. This command's own start{} did \
             not take the environment. No session was stopped.",
            *first,
            process_said(serving),
            process_said(started.pid.map(u64::from))
        ),
    }
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and
/// the start failed: the stop's own words, the start's, and what to do.
fn unmade_and_start_failed_said(first: &Shown, own: Shown, launched: bool) -> Shown {
    let still = if launched {
        Shown::said(" The requested daemon may still start.")
    } else {
        Shown::said("")
    };
    shown!(
        "{} This command's start failed: {}.{} No session was stopped: its workers keep running and \
         a local attach still works. Fix the cause and run kr host restart again.",
        *first,
        own,
        still
    )
}

/// What a restart says where the daemon that it started answers: the process that ended and the one
/// that started, where it read them, and the start.
fn restarted_said(id: EnvironmentId, old: Option<u64>, started: &Started, creates: Shown) -> Shown {
    let processes = match (old, started.pid) {
        (Some(old), Some(new)) => shown!(" (process {} ended, process {} started)", old, new),
        (Some(old), None) => shown!(" (process {} ended)", old),
        (None, Some(new)) => shown!(" (process {} started)", new),
        (None, None) => Shown::said(""),
    };
    shown!(
        "Restarted the control daemon for environment {}{} under the {} start. No session was \
         stopped.{}",
        id,
        processes,
        start_said(started),
        creates
    )
}

/// What a restart says where it stopped a daemon and another daemon already serves the
/// environment: the process that answers, and where this command launched a start, that it did not
/// take the environment.
fn stopped_and_another_already_serves_said(
    id: EnvironmentId,
    stopped: Option<u64>,
    serving: Option<u64>,
    launched: Option<Started>,
    creates: Shown,
) -> Shown {
    shown!(
        "Stopped the control daemon for environment {}{}; a control daemon already serves it{}.{} \
         No session was stopped.{}",
        id,
        process_said(stopped),
        process_said(serving),
        Proved::own_start_said(launched),
        creates
    )
}

/// What a restart says where no daemon ran and the one that it started answers.
fn none_ran_started_said(id: EnvironmentId, started: &Started, under_way: Shown) -> Shown {
    shown!(
        "No control daemon was running for environment {}. Started one{} under the {} start.{}",
        id,
        process_said(started.pid.map(u64::from)),
        start_said(started),
        under_way
    )
}

/// What a restart says where no daemon ran and another daemon serves the environment now. Where
/// this command launched nothing it started none; where it launched a process that did not take the
/// environment, it says that instead.
fn none_ran_and_another_already_serves_said(
    id: EnvironmentId,
    serving: Option<u64>,
    launched: Option<Started>,
    under_way: Shown,
) -> Shown {
    let own = match launched {
        None => Shown::said(" This command started none."),
        Some(_) => Proved::own_start_said(launched),
    };
    shown!(
        "No control daemon was running for environment {}, and one serves it now{}.{}{}",
        id,
        process_said(serving),
        own,
        under_way
    )
}

/// What a restart says where it stopped a daemon, launched a start whose exchange was cut, and a
/// daemon of another process then gave a whole exchange. It says what it read and nothing of what
/// became of the daemon on the cut connection: the control daemon that serves the environment now
/// (process Q), and that its own start (process P) does not serve it.
fn stopped_and_another_serves_after_a_cut(
    id: EnvironmentId,
    stopped: Option<u64>,
    serving: Option<u64>,
    started: &Started,
    creates: Shown,
) -> Shown {
    shown!(
        "Stopped the control daemon for environment {}{}; a control daemon now serves it{}. This \
         command's own start{} does not serve it. No session was stopped.{}",
        id,
        process_said(stopped),
        process_said(serving),
        process_said(started.pid.map(u64::from)),
        creates
    )
}

/// What a restart says where no daemon ran, it launched a start whose exchange was cut, and a
/// daemon of another process then gave a whole exchange: as the sentence above, without a stop.
fn none_ran_and_another_serves_after_a_cut(
    id: EnvironmentId,
    serving: Option<u64>,
    started: &Started,
    under_way: Shown,
) -> Shown {
    shown!(
        "No control daemon was running for environment {}; a control daemon now serves it{}. \
         This command's own start{} does not serve it.{}",
        id,
        process_said(serving),
        process_said(started.pid.map(u64::from)),
        under_way
    )
}

/// What a restart says where its start failed: what it had stopped, the start's own words, that the
/// requested daemon may still start where a daemon was launched and not seen to end, that no
/// session was stopped, and what to do.
fn start_failed_said(id: EnvironmentId, had: Had, own: Shown, launched: bool) -> Shown {
    let stop = match had {
        Had::NoDaemon => shown!(
            "No control daemon was running for environment {} and the start failed",
            id
        ),
        Had::Daemon(pid) => shown!(
            "The control daemon for environment {}{} was stopped and the start failed",
            id,
            process_said(pid)
        ),
    };
    let still = if launched {
        Shown::said(" The requested daemon may still start.")
    } else {
        Shown::said("")
    };
    let sessions = match had {
        Had::NoDaemon => Shown::said("Nothing was stopped."),
        Had::Daemon(_) => Shown::said(
            "No session was stopped: its workers keep running and a local attach still works.",
        ),
    };
    shown!(
        "{}: {}.{} {} Fix the cause and run kr host restart again.",
        stop,
        own,
        still,
        sessions
    )
}

/// What the restart had stopped when its start failed.
#[derive(Clone, Copy)]
pub(crate) enum Had {
    /// No daemon ran, and nothing was stopped.
    NoDaemon,
    /// The daemon ended, and the process that it was, where the command read it.
    Daemon(Option<u64>),
}

/// A start that did not give a daemon that answers.
pub(crate) struct StartFailed {
    /// What the start said, in its own words.
    pub(crate) error: CliError,
    /// Whether a daemon was started, or the service manager or the task was asked to start one: the
    /// requested daemon may still come up.
    pub(crate) launched: bool,
}

impl StartFailed {
    /// Reports the failure: the start's own words, that nothing of the sessions was stopped, and
    /// the record as a failed start. A daemon that answers once the record is written makes the
    /// failure moot, and the record goes.
    async fn reported(
        self,
        environment: &KnownEnvironment,
        had: Had,
        first: Option<&Shown>,
        json: bool,
        progress: &Progress,
        facts: &Facts,
    ) -> Completion {
        let id = environment.environment_id;
        let _ = progress.with_marker(|marker| marker.start_failed());
        // A daemon that answers now, started by something else meanwhile, leaves the record
        // nothing to say: it is removed, and the failure is still said as it was.
        if let Ok(endpoint) = environment.paths.controller_endpoint()
            && matches!(
                startup::reach(&endpoint, startup::ANSWER_BOUND, &[]).await,
                startup::Reached::Answered(_)
            )
        {
            progress.remove_marker();
        }
        let message = match first {
            None => start_failed_said(id, had, self.error.said(), self.launched),
            Some(first) => unmade_and_start_failed_said(first, self.error.said(), self.launched),
        };
        let error = match self.error {
            CliError::HostUnavailable(_) => CliError::HostUnavailable(message),
            CliError::Unfinished { code, .. } => CliError::Unfinished { code, message },
            _ => CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message,
            },
        };
        host_stop::failed(error, facts, json)
    }
}

/// Writes the command's record before it asks for anything, and keeps it where an interrupt finds
/// it. `daemon` is the daemon the attempt stops, where there is one.
fn begin_the_record(
    environment: &KnownEnvironment,
    daemon: Option<kr_protocol::identity::ProcessStartIdentity>,
    progress: &Progress,
) -> std::result::Result<(), kr_ipc::IpcError> {
    let marker = Marker::begin(&environment.paths, attempt::Command::Restart, daemon)?;
    *progress
        .marker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);
    Ok(())
}

/// What one connection to a daemon says of the daemon behind it. Both are read on the connection
/// that answered, so they are of one process: a daemon that ends and another that takes its place
/// cannot be told apart by two reads that are not made on the same connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Answering {
    /// Its generation.
    generation: ControllerGeneration,
    /// Its process, as the daemon states it; none where it did not.
    pid: Option<u64>,
}

/// Whether the daemon that answered is the one that was started, from what one connection said of
/// it. `started` is what the start made, and none where its look found a daemon already there.
///
/// The daemon is the one that was started where it is of a newer generation than the one that was
/// stopped and its process is the started one. Where the start has no process to name (the
/// scheduled task, a manager that does not say), a newer generation alone is the proof, and that is
/// a named limit.
fn judge(
    started: Option<Started>,
    stopped: Option<ControllerGeneration>,
    answering: &Answering,
) -> std::result::Result<Proved, &'static str> {
    // The look found a daemon: another restart's, or a manager's.
    let Some(started) = started else {
        return Ok(Proved::Another {
            serving: answering.pid,
            launched: None,
            cut: false,
        });
    };
    if !stopped.is_none_or(|old| answering.generation > old) {
        return Err("the control daemon that answers is of the generation that was told to stop");
    }
    match (started.pid, answering.pid) {
        (None, _) => Ok(Proved::Ours(started)),
        (Some(process), Some(answered)) if answered == u64::from(process) => {
            Ok(Proved::Ours(started))
        }
        // The child that was started lost the environment to another daemon, which answers.
        (Some(_), Some(answered)) => Ok(Proved::Another {
            serving: Some(answered),
            launched: Some(started),
            cut: false,
        }),
        (Some(_), None) => Err(
            "the control daemon that answers did not state its process, so it \
             cannot be told from the one that was started",
        ),
    }
}

/// Starts a daemon as `kr new` does, and proves that the daemon that answers is the one this
/// command started: the connection that answered gives a generation newer than the one that was
/// stopped and, where the start knows its process, that process. Where the start has no process to
/// name (the scheduled task, a manager that does not say), a newer generation is the proof, and
/// that is a named limit. A proof whose exchange is cut after a daemon answered starts nothing
/// more, and waits within the start's bound for a daemon to answer (`proof::prove`).
async fn start_and_prove(
    host: &HostPaths,
    environment: &KnownEnvironment,
    stopped: Option<ControllerGeneration>,
    progress: &Progress,
    past: &Past,
) -> std::result::Result<Proved, StartFailed> {
    // Written before the start is asked for: a command that is killed from here on leaves the word
    // that it had asked.
    let _ = progress.with_marker(|marker| marker.starting());
    past.enter(Beyond::Starting);
    proof::prove(
        &proof::Real {
            host,
            environment,
            progress,
        },
        stopped,
        startup::START_BOUND,
    )
    .await
}

/// The start as a person names it.
fn start_said(started: &Started) -> &'static str {
    match started.manager {
        Some(manager) => manager.as_str(),
        None if cfg!(windows) => "scheduled task",
        None => "standalone",
    }
}

/// The start as `--json` names it.
fn started_fact(started: &Started) -> StartedFact {
    StartedFact {
        start: match started.manager {
            Some(manager) => manager.as_str(),
            None if cfg!(windows) => "task",
            None => "standalone",
        },
        pid: started.pid,
    }
}

/// What an interrupt says in each stage of a restart.
fn interrupted(progress: &Progress, stage: Stage, past: &Past, json: bool) -> Completion {
    let (knows, said) = interrupt_says(progress, stage, past);
    host_stop::failed(
        CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: said,
        },
        &Facts {
            knows,
            ..Facts::none(progress.said_earlier()).of_a_restart()
        },
        json,
    )
}

/// What an interrupt at `stage` knows of the stop, and says.
fn interrupt_says(progress: &Progress, stage: Stage, past: &Past) -> (Knows, Shown) {
    let id = progress.environment_id;
    // Whether the daemon that was stopped was seen to end: what this command did, and not what
    // its record names, which a host that cannot read the lock's holder leaves out.
    let stopped = past.daemon_ended.load(Ordering::SeqCst);
    let (knows, said) = match (past.beyond(), stage) {
        (Beyond::Stop, Stage::BeforeAsking) => {
            progress.remove_marker();
            (
                Knows::NotAsked,
                shown!(
                    "kr host restart was interrupted before it asked the control daemon for \
                     environment {} to stop. Nothing was stopped.",
                    id
                ),
            )
        }
        (Beyond::Stop, Stage::Asked) => (
            Knows::MaybeAsked,
            shown!(
                "kr host restart was interrupted while it asked the control daemon for environment \
                 {} to stop. The daemon may have taken the request and may still stop, and no new \
                 daemon was started; an interrupt does not cancel a stop. No session stops. Run kr \
                 host restart to be sure of the result.",
                id
            ),
        ),
        (Beyond::Stop, Stage::Refused) => {
            progress.remove_marker();
            (
                Knows::Refused,
                shown!(
                    "kr host restart was interrupted after the control daemon for environment {} \
                     refused the request. Nothing was stopped.",
                    id
                ),
            )
        }
        (Beyond::Stop, Stage::Told) => (
            Knows::Told,
            shown!(
                "The control daemon for environment {} was told to stop. kr host restart was \
                 interrupted before it asked for a new daemon, so none was started, and the old \
                 one may still be ending, after which no control daemon runs. No session stops. \
                 Run kr host restart to start one.",
                id
            ),
        ),
        (Beyond::Ended, _) => (
            Knows::Ended,
            shown!(
                "The control daemon for environment {} ended. kr host restart was interrupted \
                 before it asked for a new daemon, so it started none, and none may be running. \
                 No session stops. Run kr host restart to start one.",
                id
            ),
        ),
        (Beyond::Starting, _) => (
            if stopped {
                Knows::Ended
            } else {
                Knows::NotAsked
            },
            shown!(
                "kr host restart was interrupted while it asked for a new control daemon for \
                 environment {}, so one may be starting. No session stops. Run kr host restart to \
                 be sure.",
                id
            ),
        ),
    };
    (knows, said)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(pid: Option<u32>) -> Started {
        Started {
            pid,
            start: ControllerStartup::Standalone,
            manager: None,
        }
    }

    fn answering(generation: u64, pid: Option<u64>) -> Answering {
        Answering {
            generation: ControllerGeneration::new(generation),
            pid,
        }
    }

    fn proof(
        started: Option<Started>,
        stopped: Option<u64>,
        answering: &Answering,
    ) -> std::result::Result<Proved, &'static str> {
        judge(started, stopped.map(ControllerGeneration::new), answering)
    }

    /// The daemon that answers is the started one only where the connection that answered says the
    /// started process, with a newer generation.
    #[test]
    fn the_answering_connection_names_the_started_process_with_a_newer_generation() {
        let proved = proof(Some(started(Some(40))), Some(3), &answering(4, Some(40)));
        assert!(matches!(proved, Ok(Proved::Ours(ours)) if ours.pid == Some(40)));
    }

    /// A daemon of another process that answers is another's, whatever process the start made.
    #[test]
    fn a_newer_daemon_of_another_process_is_another() {
        let proved = proof(Some(started(Some(40))), Some(3), &answering(4, Some(41)));
        assert!(matches!(
            proved,
            Ok(Proved::Another {
                serving: Some(41),
                launched: Some(launched),
                cut: false
            }) if launched.pid == Some(40)
        ));
    }

    /// The generation that was told to stop proves nothing, with the started process or without.
    #[test]
    fn the_generation_that_was_told_to_stop_is_no_proof() {
        for pid in [Some(40), Some(41), None] {
            let proved = proof(Some(started(Some(40))), Some(3), &answering(3, pid));
            assert!(proved.is_err(), "{pid:?}");
        }
        assert!(proof(Some(started(None)), Some(3), &answering(3, None)).is_err());
    }

    /// A daemon that does not state its process cannot be told from the started one, so it is no
    /// proof; and with no process to name, a newer generation alone is the named limit.
    #[test]
    fn a_process_that_is_not_stated_proves_only_where_the_start_names_none() {
        assert!(proof(Some(started(Some(40))), Some(3), &answering(4, None)).is_err());
        assert!(matches!(
            proof(Some(started(None)), Some(3), &answering(4, None)),
            Ok(Proved::Ours(_))
        ));
        assert!(matches!(
            proof(Some(started(None)), Some(3), &answering(4, Some(9))),
            Ok(Proved::Ours(_))
        ));
    }

    /// A daemon that the start's look found is another's, named by the process it states, and the
    /// process the start would have made is none.
    #[test]
    fn a_daemon_that_the_look_found_is_another_and_is_named_by_what_it_states() {
        assert!(matches!(
            proof(None, Some(3), &answering(4, Some(9))),
            Ok(Proved::Another {
                serving: Some(9),
                launched: None,
                cut: false
            })
        ));
        assert!(matches!(
            proof(None, None, &answering(1, None)),
            Ok(Proved::Another {
                serving: None,
                launched: None,
                cut: false
            })
        ));
    }

    /// With no daemon stopped (a start where none ran), any generation is new.
    #[test]
    fn where_none_was_stopped_any_generation_is_new() {
        let proved = proof(Some(started(Some(40))), None, &answering(1, Some(40)));
        assert!(matches!(proved, Ok(Proved::Ours(_))));
    }

    /// A restart that stopped a daemon and then read another process after a cut exchange says what
    /// it read: the daemon that serves the environment now, and that its own start does not serve
    /// it; it says nothing of what became of the daemon on the cut connection. The creates that the
    /// stop went on without come after it.
    #[test]
    fn a_restart_that_read_another_daemon_after_a_cut_says_only_what_it_read() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let said = stopped_and_another_serves_after_a_cut(
            id,
            Some(30),
            Some(41),
            &started(Some(40)),
            Shown::said(""),
        );
        assert_eq!(
            said.to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 now serves it (process 41). This command's own start (process 40) does not \
                 serve it. No session was stopped."
            )
        );
        let creates = host_stop::creates_under_way(Some(2));
        let said =
            stopped_and_another_serves_after_a_cut(id, None, Some(41), &started(Some(40)), creates);
        assert!(
            said.to_string().starts_with(&format!(
                "Stopped the control daemon for environment {id}; a control daemon now serves it \
                 (process 41). This command's own start (process 40) does not serve it. No \
                 session was stopped. 2 session creates were still under way"
            )),
            "{said}"
        );
    }

    /// The same where no daemon ran: no stop is said, and the attempts under way come after it.
    #[test]
    fn a_start_where_none_ran_that_read_another_daemon_after_a_cut_says_only_what_it_read() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let said = none_ran_and_another_serves_after_a_cut(
            id,
            Some(41),
            &started(Some(40)),
            Shown::said(""),
        );
        assert_eq!(
            said.to_string(),
            format!(
                "No control daemon was running for environment {id}; a control daemon now \
                 serves it (process 41). This command's own start (process 40) does not serve it."
            )
        );
    }

    /// The outcome of a proof whose exchange was cut carries `cut` only where this command
    /// launched a process and another one answers; a daemon that the start's look found, or the
    /// started process that answers, is the outcome it was without the cut.
    #[test]
    fn only_a_launch_that_another_process_answers_after_a_cut_is_marked_cut() {
        let another = |launched| Proved::Another {
            serving: Some(41),
            launched,
            cut: false,
        };
        assert!(matches!(
            another(Some(started(Some(40)))).after_a_cut(),
            Proved::Another { cut: true, .. }
        ));
        assert!(matches!(
            another(None).after_a_cut(),
            Proved::Another { cut: false, .. }
        ));
        assert!(matches!(
            Proved::Ours(started(Some(40))).after_a_cut(),
            Proved::Ours(_)
        ));
    }

    /// The daemon that the restart started answers: the processes that ended and started where the
    /// command read them, and the start; where it read none, the sentence names none.
    #[test]
    fn a_restart_whose_started_daemon_answers_says_what_ended_and_what_started() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let start = start_said(&started(None));
        assert_eq!(
            restarted_said(id, Some(30), &started(Some(40)), Shown::said("")).to_string(),
            format!(
                "Restarted the control daemon for environment {id} (process 30 ended, process 40 \
                 started) under the {start} start. No session was stopped."
            )
        );
        assert_eq!(
            restarted_said(id, None, &started(None), Shown::said("")).to_string(),
            format!(
                "Restarted the control daemon for environment {id} under the {start} start. \
                 No session was stopped."
            )
        );
        assert_eq!(
            none_ran_started_said(id, &started(Some(40)), Shown::said("")).to_string(),
            format!(
                "No control daemon was running for environment {id}. Started one (process 40) \
                 under the {start} start."
            )
        );
    }

    /// Another daemon serves the environment and the exchange was not cut: where this command
    /// launched a start, it says the start did not take the environment; where it launched none,
    /// the restart after a stop says nothing of a start and the start where none ran says it
    /// started none.
    #[test]
    fn another_daemon_that_serves_the_environment_is_said_with_this_commands_own_start() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        assert_eq!(
            stopped_and_another_already_serves_said(
                id,
                Some(30),
                Some(41),
                Some(started(Some(40))),
                Shown::said("")
            )
            .to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 already serves it (process 41). This command's own start (process 40) did not \
                 take the environment. No session was stopped."
            )
        );
        assert_eq!(
            stopped_and_another_already_serves_said(id, Some(30), None, None, Shown::said(""))
                .to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 already serves it. No session was stopped."
            )
        );
        assert_eq!(
            none_ran_and_another_already_serves_said(
                id,
                Some(41),
                Some(started(Some(40))),
                Shown::said("")
            )
            .to_string(),
            format!(
                "No control daemon was running for environment {id}, and one serves it now \
                 (process 41). This command's own start (process 40) did not take the \
                 environment."
            )
        );
        assert_eq!(
            none_ran_and_another_already_serves_said(id, None, None, Shown::said("")).to_string(),
            format!(
                "No control daemon was running for environment {id}, and one serves it now. This \
                 command started none."
            )
        );
    }

    /// A holder that did not answer and a daemon that answers now: the restart stopped none and
    /// started none, and names the process that answers where it reads one.
    #[test]
    fn a_holder_that_gives_way_to_a_daemon_says_that_nothing_was_stopped_or_started() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        assert_eq!(
            holder_answers_said(id, Some(41)).to_string(),
            format!(
                "A control daemon held environment {id} and did not answer, and a control daemon \
                 (process 41) answers now. This command stopped none and started none."
            )
        );
        assert_eq!(
            holder_answers_said(id, None).to_string(),
            format!(
                "A control daemon held environment {id} and did not answer, and a control daemon \
                 answers now. This command stopped none and started none."
            )
        );
    }

    /// A start that fails says what had been stopped, the start's own words, and what to do; it
    /// adds that the requested daemon may still start only where one was launched and not seen to
    /// end.
    #[test]
    fn a_start_that_fails_says_what_was_stopped_and_what_to_do() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let own = Shown::said("the daemon did not answer");
        assert_eq!(
            start_failed_said(id, Had::Daemon(Some(30)), own.clone(), true).to_string(),
            format!(
                "The control daemon for environment {id} (process 30) was stopped and the start \
                 failed: the daemon did not answer. The requested daemon may still start. No \
                 session was stopped: its workers keep running and a local attach still works. \
                 Fix the cause and run kr host restart again."
            )
        );
        assert_eq!(
            start_failed_said(id, Had::NoDaemon, own, false).to_string(),
            format!(
                "No control daemon was running for environment {id} and the start failed: the \
                 daemon did not answer. Nothing was stopped. Fix the cause and run kr host \
                 restart again."
            )
        );
    }

    /// A start that cannot be made is refused before the stop with the start's own words, that
    /// nothing was stopped, and the remedy where there is one; a setup that is wrong is
    /// `HOST_NOT_CONFIGURED` (exit 3), and a manager or a lock that could not be asked is not (exit 1).
    #[test]
    fn a_start_that_cannot_be_made_says_that_nothing_was_stopped() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let unstartable = |not_set_up| Unstartable {
            why: Shown::said("no start is chosen"),
            remedy: Some(Shown::said("Run kr host startup.")),
            not_set_up,
        };
        let expected = format!(
            "kr host restart can make no start for environment {id}: no start is chosen. Nothing \
             was stopped. Run kr host startup."
        );
        match not_startable(id, unstartable(true)) {
            CliError::HostUnavailable(message) => assert_eq!(message.to_string(), expected),
            other => panic!("a setup that is wrong is HOST_NOT_CONFIGURED: {other:?}"),
        }
        match not_startable(id, unstartable(false)) {
            CliError::Unfinished { message, .. } => assert_eq!(message.to_string(), expected),
            other => panic!("a manager that could not be asked is unfinished: {other:?}"),
        }
    }

    /// What a proof says where the process that answers is not the one that was started, or is not
    /// stated, or is of the generation that was told to stop, and what a result says of its own
    /// start where another daemon serves.
    #[test]
    fn what_the_proof_and_the_result_say_of_the_start_that_did_not_take_the_environment() {
        assert!(
            judge(
                Some(started(Some(40))),
                Some(ControllerGeneration::new(3)),
                &answering(3, Some(40))
            )
            .is_err_and(|said| said
                == "the control daemon that answers is of the generation that was told to stop")
        );
        assert!(
            judge(
                Some(started(Some(40))),
                Some(ControllerGeneration::new(3)),
                &answering(4, None)
            )
            .is_err_and(|said| said
                == "the control daemon that answers did not state its process, so it cannot be \
                    told from the one that was started")
        );
        assert_eq!(
            Proved::own_start_said(Some(started(Some(40)))).to_string(),
            " This command's own start (process 40) did not take the environment."
        );
        assert_eq!(Proved::own_start_said(None).to_string(), "");
    }

    /// What an interrupt says in each stage: the words of each, which name what was asked, what
    /// was seen and what to run. None of them says that a daemon ended where the command did not
    /// see an end.
    #[test]
    fn an_interrupt_says_in_each_stage_what_was_asked_and_what_was_seen() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let said = |stage, beyond, ended| says(&host, stage, beyond, ended).1.to_string();
        assert_eq!(
            said(Stage::BeforeAsking, Beyond::Stop, false),
            format!(
                "kr host restart was interrupted before it asked the control daemon for \
                 environment {id} to stop. Nothing was stopped."
            )
        );
        assert_eq!(
            said(Stage::Asked, Beyond::Stop, false),
            format!(
                "kr host restart was interrupted while it asked the control daemon for \
                 environment {id} to stop. The daemon may have taken the request and may still \
                 stop, and no new daemon was started; an interrupt does not cancel a stop. No \
                 session stops. Run kr host restart to be sure of the result."
            )
        );
        assert_eq!(
            said(Stage::Refused, Beyond::Stop, false),
            format!(
                "kr host restart was interrupted after the control daemon for environment {id} \
                 refused the request. Nothing was stopped."
            )
        );
        assert_eq!(
            said(Stage::Told, Beyond::Stop, false),
            format!(
                "The control daemon for environment {id} was told to stop. kr host restart was \
                 interrupted before it asked for a new daemon, so none was started, and the old \
                 one may still be ending, after which no control daemon runs. No session stops. \
                 Run kr host restart to start one."
            )
        );
        assert_eq!(
            said(Stage::Told, Beyond::Ended, true),
            format!(
                "The control daemon for environment {id} ended. kr host restart was interrupted \
                 before it asked for a new daemon, so it started none, and none may be running. \
                 No session stops. Run kr host restart to start one."
            )
        );
        assert_eq!(
            said(Stage::Told, Beyond::Starting, true),
            format!(
                "kr host restart was interrupted while it asked for a new control daemon for \
                 environment {id}, so one may be starting. No session stops. Run kr host restart \
                 to be sure."
            )
        );
    }

    /// A progress with no record of the command's own, as an interrupt finds it where the record
    /// could not be read: only the flag says whether the stop's request returned.
    fn says(
        host: &kr_ipc::testing::TempHost,
        stage: Stage,
        beyond: Beyond,
        daemon_ended: bool,
    ) -> (Knows, Shown) {
        let past = Past::new();
        past.enter(beyond);
        past.daemon_ended.store(daemon_ended, Ordering::SeqCst);
        interrupt_says(&Progress::new(host.environment_id()), stage, &past)
    }

    /// An interrupt after the stop's request returned and before the start's own exchange says that
    /// the daemon was stopped, from the flag that the stop set and not from a record, which a host
    /// that cannot read the lock's holder leaves out; with the flag unset it says nothing was asked.
    #[test]
    fn an_interrupt_after_the_stop_and_before_the_start_says_the_daemon_was_stopped_from_the_flag()
    {
        let host = kr_ipc::testing::TempHost::create();
        let (knows, said) = says(&host, Stage::Told, Beyond::Starting, true);
        assert_eq!(knows, Knows::Ended, "{said}");
        let (knows, said) = says(&host, Stage::Told, Beyond::Starting, false);
        assert_eq!(knows, Knows::NotAsked, "{said}");
        let (knows, said) = says(&host, Stage::Told, Beyond::Ended, true);
        assert_eq!(knows, Knows::Ended, "{said}");
        assert!(
            said.to_string()
                .contains("interrupted before it asked for a new daemon"),
            "{said}"
        );
    }

    /// An interrupt in each stage before the stop returned knows what the request came to, and the
    /// flag, which is set only where the stop returned, changes none of them.
    #[test]
    fn an_interrupt_before_the_stop_returned_knows_what_the_request_came_to() {
        let host = kr_ipc::testing::TempHost::create();
        for (stage, expected) in [
            (Stage::BeforeAsking, Knows::NotAsked),
            (Stage::Asked, Knows::MaybeAsked),
            (Stage::Refused, Knows::Refused),
            (Stage::Told, Knows::Told),
        ] {
            let (knows, said) = says(&host, stage, Beyond::Stop, false);
            assert_eq!(knows, expected, "{stage:?}: {said}");
        }
    }

    /// The stop's own words for a request that could not be made where the daemon ended, as the
    /// restart takes them, and the environment they name.
    fn the_stops_words_for_an_end_without_a_request() -> (EnvironmentId, Shown) {
        let id = kr_ipc::testing::TempHost::create().environment_id();
        let first = host_stop::ended_before_the_request_said(
            id,
            Some(4000),
            &End::Gone,
            &Shown::said("the connection closed"),
        );
        assert_eq!(
            first.to_string(),
            format!(
                "The control daemon for environment {id} (process 4000) ended, and this command \
                 could not make its request for it: the connection closed. This command sent \
                 nothing."
            )
        );
        (id, first)
    }

    /// Where the stop's request could not be made and the daemon was seen to end, the restart says
    /// the stop's own words first, that it did not stop the daemon, and then what its start did:
    /// the start took the environment, another daemon serves it (with this command's own start
    /// or with none, and after a cut exchange), another daemon holds it since the end, or the
    /// start failed.
    #[test]
    fn a_request_that_could_not_be_made_where_the_daemon_ended_says_so_and_then_what_the_start_did()
    {
        let (_, first) = the_stops_words_for_an_end_without_a_request();
        let x = first.to_string();
        let start = start_said(&started(Some(40)));
        assert_eq!(
            unmade_then_started_said(&first, &started(Some(40))).to_string(),
            format!(
                "{x} This command then started a control daemon (process 40) under the {start} \
                 start. No session was stopped."
            )
        );
        assert_eq!(
            unmade_and_another_serves_said(&first, false, Some(50), Some(started(Some(40))), false)
                .to_string(),
            format!(
                "{x} A control daemon already serves the environment (process 50). This command's \
                 own start (process 40) did not take the environment. No session was stopped."
            )
        );
        assert_eq!(
            unmade_and_another_serves_said(&first, false, Some(50), None, false).to_string(),
            format!(
                "{x} A control daemon already serves the environment (process 50). This command \
                 started none. No session was stopped."
            )
        );
        assert_eq!(
            unmade_and_another_serves_said(&first, false, Some(50), Some(started(Some(40))), true)
                .to_string(),
            format!(
                "{x} A control daemon now serves the environment (process 50). This command's own \
                 start (process 40) does not serve it. No session was stopped."
            )
        );
        assert_eq!(
            unmade_and_another_serves_said(&first, true, Some(50), None, false).to_string(),
            format!("{x} This command sent nothing and started none. No session was stopped.")
        );
        for (launched, still) in [
            (false, ""),
            (true, " The requested daemon may still start."),
        ] {
            assert_eq!(
                unmade_and_start_failed_said(
                    &first,
                    Shown::said("the log could not be used"),
                    launched
                )
                .to_string(),
                format!(
                    "{x} This command's start failed: the log could not be used.{still} No session \
                     was stopped: its workers keep running and a local attach still works. Fix the \
                     cause and run kr host restart again."
                )
            );
        }
    }

    /// A request that could not be made where the daemon was seen to end, or another holds the
    /// environment now, goes on to the start with the stop's own words and what the end was; any
    /// other end of a request that could not be made is the stop's.
    #[test]
    fn only_an_end_that_was_seen_goes_on_to_the_start_and_any_other_is_the_stops() {
        let said = Shown::said("the daemon ended");
        for end in [End::Gone, End::Successor(Some(77))] {
            let before = Before::Ended {
                said: said.clone(),
                pid: Some(4000),
                end,
            };
            match ended_without_a_request(before) {
                Ok((first, pid, _)) => {
                    assert_eq!(first.to_string(), "the daemon ended");
                    assert_eq!(pid, Some(4000));
                }
                Err(_) => panic!("an end that was seen goes on"),
            }
        }
        for before in [Before::Silent { accepted: true }, Before::OwnFault] {
            assert!(ended_without_a_request(before).is_err());
        }
    }
}
