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
use kr_controller::attempt::Marker;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::configuration::ControllerStartup;
use kr_protocol::ids::{ControllerGeneration, EnvironmentId};

use crate::error::{CliError, Result};
use crate::host_stop::{
    self, Answer, Asked, AtStart, Before, Begun, Cut, End, Facts, Knows, Looked, Progress, Real,
    Settled, Stage, Start, StartedFact, Which,
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
        Looked::Daemon { client, holder } => {
            restart_the_daemon(
                host,
                environment,
                start,
                *client,
                holder,
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
        Looked::Refused { before, error } => match ended_without_a_request(before) {
            // The greeting failed because the daemon was ending, and the wait saw its end: the
            // restart goes on to its start as it does for a request that could not be made.
            Ok((_, pid, end)) => {
                let first = ended_unmade_said(id, pid, &error);
                ended_before_the_request(
                    host,
                    environment,
                    json,
                    progress,
                    past,
                    &begun,
                    None,
                    (first, pid, end),
                )
                .await
            }
            Err(before) => {
                match host_stop::ended_by(
                    Which::Restart,
                    *before,
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
        },
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
    let deadline = tokio::time::Instant::now() + startup::START_BOUND;
    // What the read of who serves gave after the wait saw a daemon answer, where it was no daemon:
    // the command goes on waiting within its bound and says it if the bound ends so.
    let mut since: Option<Shown> = None;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match holder::wait(&operations, left).await {
            holder::Holder::Answers => {
                match who_serves(environment, startup::ANSWER_BOUND, progress).await {
                    Serves::Daemon(serving) => {
                        return host_stop::done(
                            &holder_answers_said(id, serving),
                            &Facts {
                                pid: serving,
                                answer: Some(Answer {
                                    serving,
                                    launched: None,
                                }),
                                ..begun.none.clone()
                            },
                            json,
                            &begun.earlier,
                        );
                    }
                    Serves::Replied(why) | Serves::NoReply(why) => since = Some(why),
                }
            }
            holder::Holder::Gone => {
                return start_where_none_ran(host, environment, json, progress, past, begun).await;
            }
            holder::Holder::Silent { replied } => {
                return host_stop::failed(
                    holder_silent(environment, replied, since.as_ref()),
                    &begun.none,
                    json,
                );
            }
        }
        if deadline <= tokio::time::Instant::now() {
            return host_stop::failed(
                holder_silent(environment, false, since.as_ref()),
                &begun.none,
                json,
            );
        }
        tokio::time::sleep(host_stop::LOOK_EVERY).await;
    }
}

/// What one read of who serves the environment gave, in the three outcomes that a result keeps
/// apart.
enum Serves {
    /// A daemon gave a usable greeting, and this is the process that it states on that connection:
    /// none where it states none.
    Daemon(Option<u64>),
    /// A daemon replied, and this command cannot use the reply.
    Replied(Shown),
    /// No daemon replied, or the exchange that reads its process was cut after its greeting.
    NoReply(Shown),
}

/// Reads who serves at the environment's endpoint: the greeting, and then the process that the
/// daemon states, on the connection that answered. It is never read from the lock file, which may
/// name an earlier daemon.
async fn who_serves(
    environment: &KnownEnvironment,
    bound: std::time::Duration,
    progress: &Progress,
) -> Serves {
    let Ok(endpoint) = environment.paths.controller_endpoint() else {
        return Serves::NoReply(Shown::said("the endpoint's address could not be made"));
    };
    match startup::read(&endpoint, bound, &[]).await {
        startup::Read::Greeting(listed) => {
            let mut client = match startup::ours(*listed) {
                Ok(client) => client,
                Err(error) => return Serves::Replied(error.said()),
            };
            let stated = tokio::time::timeout(
                bound,
                proof::process_stated(&mut client, environment.environment_id, progress),
            )
            .await;
            match stated {
                Ok(Ok(process)) => Serves::Daemon(process),
                Ok(Err(why)) => Serves::NoReply(why),
                Err(_) => Serves::NoReply(Shown::said(
                    "a control daemon answered and did not state its process in time",
                )),
            }
        }
        startup::Read::Reply(why) => Serves::Replied(why),
        startup::Read::NoReply(why) => Serves::NoReply(why),
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

/// The restart's failure where its record could not be written where no daemon ran: nothing was
/// started.
fn not_recorded_before_the_start(error: &kr_ipc::IpcError) -> CliError {
    CliError::Other(shown!(
        "kr host restart could not record its attempt: {}. No start was made.",
        Shown::ipc(error)
    ))
}

/// The restart's failure where a process holds the environment and neither answers nor lets go
/// within the start's bound.
fn holder_silent(environment: &KnownEnvironment, replied: bool, since: Option<&Shown>) -> CliError {
    CliError::Unfinished {
        code: ErrorCode::EnvironmentUnavailable,
        message: holder_silent_said(environment, replied, since),
    }
}

/// What the restart says where a process holds the environment and neither answers nor lets go
/// within the start's bound. `replied` is whether a look of the wait found a reply that this
/// command cannot use, and `since` what the read of who serves gave after a look saw a daemon
/// answer: either keeps the sentence from saying that no daemon answered.
fn holder_silent_said(
    environment: &KnownEnvironment,
    replied: bool,
    since: Option<&Shown>,
) -> Shown {
    let answers = if replied || since.is_some() {
        "gave no usable greeting"
    } else {
        "does not answer"
    };
    // Where a daemon answered or replied, the closing sentence says that no stop was requested.
    let (earlier, requested) = match (since, replied) {
        (Some(why), _) => (
            shown!(
                " A control daemon answered during the wait, and none gave a usable greeting after that: {}.",
                *why
            ),
            "",
        ),
        (None, true) => (Shown::said(""), ""),
        (None, false) => (Shown::said(""), " No stop was requested."),
    };
    shown!(
        "A control daemon holds environment {} and {}, so it may be starting or stopping.{}{} Run \
         kr host restart again in a moment. {} This command requested no stop and no start.",
        environment.environment_id,
        answers,
        earlier,
        requested,
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
    /// What the command read of the generation of the daemon that was stopped.
    generation: Old,
    /// The stop's own words, where its request could not be made and the daemon was seen to end:
    /// the restart did not stop it, and says so before it says what its start did.
    first: Option<Shown>,
    /// What the request's failure said, where the request was written and whether the daemon took
    /// it is not known: the restart did not see it take the stop, and says so before it says what
    /// its start did.
    unknown: Option<Shown>,
}

impl Stopped {
    /// The stop's words as the first sentence of a result: where the request could not be made,
    /// the words for that; where its outcome is not known, the stop's words for that, closed by a
    /// full stop; and none where the daemon took the stop.
    fn opening(&self, id: EnvironmentId) -> Option<Shown> {
        match (&self.first, &self.unknown) {
            (Some(first), _) => Some(first.clone()),
            (None, Some(_)) => Some(shown!("{}.", self.clause(id))),
            (None, None) => None,
        }
    }

    /// What the stop came to, as the first sentence of a result that has no other opening: the
    /// stop's words where the request could not be made or its outcome is not known, and that the
    /// daemon was stopped where it took the stop.
    fn sentence(&self, id: EnvironmentId) -> Shown {
        self.opening(id)
            .unwrap_or_else(|| shown!("{}.", self.clause(id)))
    }

    /// The stop's words that open a sentence of the result: that the daemon was stopped where it
    /// took the stop, and that it ended where the request's outcome is not known.
    fn clause(&self, id: EnvironmentId) -> Shown {
        stop_clause(id, self.named, self.unknown.as_ref())
    }
}

/// What the restart says of the daemon's end: that it stopped the daemon where the daemon took the
/// stop, and, where the request's outcome is not known (`unknown` is its failure), the stop's own
/// words that the daemon did not show whether it took the stop and that it has ended.
fn stop_clause(id: EnvironmentId, named: Option<u64>, unknown: Option<&Shown>) -> Shown {
    match unknown {
        None => shown!(
            "Stopped the control daemon for environment {}{}",
            id,
            process_said(named)
        ),
        Some(failure) => shown!(
            "The control daemon for environment {}{} did not show whether it took the stop ({}), \
             and it has ended",
            id,
            process_said(named),
            *failure
        ),
    }
}

/// A control daemon answers: asks how it was started, refuses before it stops anything where the
/// start would not give what it has, stops the daemon, and then starts one and proves it.
/// `holder` is the process that held the environment before the reach.
// One argument for each fact its steps read: the paths, the environment, the start, the connection, the output form, the progress, where the restart is past its stop and what it read before the daemon.
#[allow(clippy::too_many_arguments)]
async fn restart_the_daemon(
    host: &HostPaths,
    environment: &KnownEnvironment,
    start: ControllerStartup,
    client: LocalClient,
    holder: Option<kr_protocol::identity::ProcessStartIdentity>,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    let (mut client, info) = match host_stop::read_the_daemon(
        host,
        environment,
        client,
        holder.as_ref(),
        json,
        &begun.none,
    )
    .await
    {
        Ok(read) => read,
        Err(cut) => {
            return cut_said(host, environment, cut, None, json, progress, past, begun).await;
        }
    };
    // How it was started, before anything is stopped. The request for it stops nothing. A daemon of
    // another build that lists no such request refuses it, and says so as `kr host stop` does. Its
    // answer states the process of the daemon that is on this connection, which the stop then waits
    // for by its identity where the lock file named the same process.
    let (launch, stated) = match host_stop::ask(&mut client, id, json, progress, true).await {
        Asked::Taken(result) => (result.launch.0, Some(result.pid.get())),
        Asked::Refused(error) => {
            let refusal = Facts {
                knows: Knows::Refused,
                ..begun.none.clone()
            };
            return host_stop::refused(
                &mut client,
                Which::Restart,
                id,
                &info,
                error,
                &refusal,
                json,
            )
            .await;
        }
        // A daemon that cannot say how it was started, or whose answer was cut or withheld, gives
        // no launch to compare and states no process: the restart goes on, since a start that
        // fails after the stop says so and the keys stay on disk.
        Asked::Unknown(_) | Asked::NotComposed { .. } => (None, None),
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
    let old = holder.clone();
    let settled = match host_stop::ask_and_wait(
        Which::Restart,
        host,
        environment,
        client,
        &info,
        holder,
        stated,
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
    match stopped_by_the_request(settled, info.generation) {
        Ok((stopped, old)) => {
            after_the_end(host, environment, json, progress, past, begun, stopped, old).await
        }
        // The daemon was not seen to end: the stop's own words, with nothing started.
        Err(settled) => host_stop::say_the_stop(
            Which::Restart,
            *settled,
            environment,
            &begun.none,
            json,
            progress,
            &begun.earlier,
        ),
    }
}

/// What the restart's stop came to where its request was written and the daemon was seen to end,
/// and the daemon's identity where the stop read it; the stop as it came out where the daemon was
/// not seen to end, which the stop says in its own words.
fn stopped_by_the_request(
    settled: Settled,
    generation: ControllerGeneration,
) -> std::result::Result<(Stopped, Option<kr_protocol::identity::ProcessStartIdentity>), Box<Settled>>
{
    let (successor, named) = match &settled.ended {
        End::Gone => (None, settled.old.as_ref().map(|old| old.pid.get())),
        End::Successor(successor) => (
            Some(*successor),
            settled.old.as_ref().map(|old| old.pid.get()),
        ),
        End::NotEnded(..) => return Err(Box::new(settled)),
    };
    let unknown = settled.request.not_known().cloned();
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
        generation: Old::Generation(generation),
        first: None,
        unknown,
    };
    Ok((stopped, old))
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
            Ok((_, pid, end)) => {
                let ended = (ended_unmade_said(id, pid, &error), pid, end);
                ended_before_the_request(
                    host,
                    environment,
                    json,
                    progress,
                    past,
                    begun,
                    read,
                    ended,
                )
                .await
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

/// The daemon was seen to end where the restart's request could not be made: the stop's own words for
/// that state come first, and the restart goes on to its start. `read` is what the command read of
/// the daemon before, where it read the daemon at all, and `ended` is the stop's words, the process
/// they name and what the end was.
// One argument for each fact its steps read: the paths, the environment, the output form, the progress, where the restart is past its stop, what it read before the daemon, and what the end was.
#[allow(clippy::too_many_arguments)]
async fn ended_before_the_request(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
    read: Option<(
        ControllerGeneration,
        Option<kr_protocol::identity::ProcessStartIdentity>,
    )>,
    ended: (Shown, Option<u64>, End),
) -> Completion {
    let (stopped, old) = stopped_unmade(read, ended);
    after_the_end(host, environment, json, progress, past, begun, stopped, old).await
}

/// The stop's words for a daemon that ended where this command's request could not be made, said
/// as for an end with no successor: a process that took the environment after the end is named
/// apart, in the past tense, as an earlier reading.
fn ended_unmade_said(id: EnvironmentId, pid: Option<u64>, error: &kr_ipc::IpcError) -> Shown {
    host_stop::ended_before_the_request_said(id, pid, &End::Gone, &Shown::ipc(error))
}

/// What the restart's stop came to where its request could not be made and the daemon was seen to
/// end, and the daemon's identity where it was read: the stop's words are the first of the result.
fn stopped_unmade(
    read: Option<(
        ControllerGeneration,
        Option<kr_protocol::identity::ProcessStartIdentity>,
    )>,
    (first, pid, end): (Shown, Option<u64>, End),
) -> (Stopped, Option<kr_protocol::identity::ProcessStartIdentity>) {
    let (generation, old) = match read {
        Some((generation, old)) => (Old::Generation(generation), old),
        None => (Old::Unread, None),
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
        unknown: None,
    };
    (stopped, old)
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
    let facts = Facts {
        knows: Knows::Ended,
        pid: stopped.pid,
        unsettled: stopped.unsettled,
        ..begun.none.clone()
    };
    let proved = match stopped.successor {
        // Another daemon holds the environment: nothing is started beside it.
        Some(successor) => {
            match wait_for_the_successor(environment, &stopped.sentence(id), successor, progress)
                .await
            {
                Ok(proved) => Ok(proved),
                Err(error) => return host_stop::failed(error, &facts, json),
            }
        }
        None => {
            // The start's side. The record is the command's own until a daemon that it started
            // answers. A request that could not be made let it go, and the start needs it again;
            // where another daemon holds the environment nothing is asked or started, and no
            // record is written.
            if progress.with_marker(|_| ()).is_none() {
                let _ = begin_the_record(environment, old, progress);
            }
            start_and_prove(host, environment, stopped.generation, progress, past).await
        }
    };
    let creates = host_stop::creates_under_way(stopped.unsettled);
    let opening = stopped.opening(id);
    match proved {
        Ok(proved) => {
            progress.remove_marker();
            let said = said_after_the_proof(id, &stopped, &proved, creates);
            host_stop::done(&said, &answered_facts(&proved, facts), json, &begun.earlier)
        }
        Err(failed) => {
            failed
                .reported(
                    environment,
                    Had::Daemon(stopped.named),
                    opening.as_ref(),
                    json,
                    progress,
                    &facts,
                )
                .await
        }
    }
}

/// The facts of a result in which a daemon answers after the restart's look or start: `started` is
/// set only where the proof holds, and `serving` and `launched` say what answers and what this
/// command launched, so that none launched and a launch that was not proved differ.
fn answered_facts(proved: &Proved, facts: Facts) -> Facts {
    match proved {
        Proved::Ours(started) => Facts {
            started: Some(Some(started_fact(started))),
            answer: Some(Answer {
                serving: started.pid.map(u64::from),
                launched: Some(started_fact(started)),
            }),
            ..facts
        },
        Proved::Unproven {
            serving, started, ..
        } => Facts {
            answer: Some(Answer {
                serving: *serving,
                launched: Some(started_fact(started)),
            }),
            ..facts
        },
        Proved::Another {
            serving, launched, ..
        } => Facts {
            answer: Some(Answer {
                serving: *serving,
                launched: launched.as_ref().map(started_fact),
            }),
            ..facts
        },
    }
}

/// What the restart says where its start came to `proved` after a stop that came to `stopped`: the
/// stop's words come first (that the daemon was stopped, or what the stop's own words say where its
/// request could not be made or its outcome is not known), then what the start did.
fn said_after_the_proof(
    id: EnvironmentId,
    stopped: &Stopped,
    proved: &Proved,
    creates: Shown,
) -> Shown {
    match proved {
        Proved::Ours(started) => match stopped.opening(id) {
            None => restarted_said(id, stopped.named, started, creates),
            Some(first) => unmade_then_started_said(&first, started),
        },
        Proved::Unproven {
            serving,
            started,
            newer,
        } => match &stopped.first {
            Some(first) => unmade_and_unproven_said(first, *serving, started, *newer),
            None => {
                stopped_and_unproven_said(&stopped.clause(id), *serving, started, *newer, creates)
            }
        },
        Proved::Another {
            serving,
            launched,
            cut,
        } => match (&stopped.first, launched) {
            (Some(first), launched) => unmade_and_another_serves_said(
                id,
                first,
                stopped.successor,
                *serving,
                *launched,
                *cut,
            ),
            (None, Some(started)) if *cut => stopped_and_another_serves_after_a_cut(
                &stopped.clause(id),
                *serving,
                started,
                creates,
            ),
            (None, launched) => stopped_and_another_already_serves_said(
                &stopped.clause(id),
                *serving,
                *launched,
                stopped.unknown.is_some(),
                creates,
            ),
        },
    }
}

/// Another daemon holds the environment after the one that was stopped ended: waits for it to
/// answer, and starts nothing beside it. The process of the daemon that answers is read on the
/// connection that answered; `successor`, the process the lock file named when the end was seen,
/// is said only as that earlier reading, after the stop's own words (`opening`).
async fn wait_for_the_successor(
    environment: &KnownEnvironment,
    opening: &Shown,
    successor: Option<u64>,
    progress: &Progress,
) -> std::result::Result<Proved, CliError> {
    let id = environment.environment_id;
    let deadline = tokio::time::Instant::now() + startup::START_BOUND;
    // Whether any read of the wait was a reply that this command cannot use.
    let mut replied = false;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let last = match who_serves(environment, left, progress).await {
            Serves::Daemon(serving) => {
                return Ok(Proved::Another {
                    serving,
                    launched: None,
                    cut: false,
                });
            }
            Serves::Replied(why) => {
                replied = true;
                why
            }
            Serves::NoReply(why) => why,
        };
        if deadline <= tokio::time::Instant::now() {
            return Err(successor_silent(id, opening, successor, replied, &last));
        }
        tokio::time::sleep(host_stop::LOOK_EVERY.min(left)).await;
    }
}

/// The restart's failure where another daemon held the environment after the daemon that was
/// stopped ended and no daemon answers within the start's bound: the stop's own words (`opening`),
/// what the command read of the successor when the end was seen, and what the last read said. No
/// daemon "answered" only where no read of the wait was a reply; where one was, none gave a usable
/// greeting.
fn successor_silent(
    id: EnvironmentId,
    opening: &Shown,
    successor: Option<u64>,
    replied: bool,
    last: &Shown,
) -> CliError {
    let did = if replied {
        "gave a usable greeting"
    } else {
        "answered"
    };
    CliError::Unfinished {
        code: ErrorCode::EnvironmentUnavailable,
        message: shown!(
            "{} After it ended, a control daemon{} held environment {}, and no control daemon {} \
             within {} seconds: {}. This command started none. Run kr host restart again.",
            *opening,
            process_said(successor),
            id,
            did,
            startup::START_BOUND.as_secs(),
            *last
        ),
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
        return host_stop::failed(not_recorded_before_the_start(&error), &none, json);
    }
    let result = start_and_prove(host, environment, Old::None, progress, past).await;
    match result {
        Ok(proved) => {
            progress.remove_marker();
            let under_way = host_stop::under_way_said(environment);
            let said = match &proved {
                Proved::Ours(started) => none_ran_started_said(id, started, under_way),
                Proved::Unproven {
                    serving, started, ..
                } => none_ran_and_unproven_said(id, *serving, started, under_way),
                Proved::Another {
                    serving,
                    launched: Some(started),
                    cut: true,
                } => none_ran_and_another_serves_after_a_cut(id, *serving, started, under_way),
                Proved::Another {
                    serving, launched, ..
                } => none_ran_and_another_already_serves_said(id, *serving, *launched, under_way),
            };
            host_stop::done(&said, &answered_facts(&proved, none), json, &begun.earlier)
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
    /// A control daemon answers, and what it states does not show whether it is the one this
    /// command started: the start names no process. The command says what it read and what it
    /// asked.
    Unproven {
        /// The process that the answering daemon states, where it states one.
        serving: Option<u64>,
        /// What this command launched.
        started: Started,
        /// Whether a stopped generation was read and the daemon that answers is of a newer one.
        newer: bool,
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
    /// made one, is not the daemon that answers.
    fn own_start_said(launched: Option<Started>) -> Shown {
        match launched {
            None => Shown::said(""),
            Some(started) => shown!(
                " The control daemon that answers is not this command's own start{}.",
                process_said(started.pid.map(u64::from))
            ),
        }
    }
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and the
/// daemon that this command started answers: the stop's own words for that state, then the start.
fn unmade_then_started_said(first: &Shown, started: &Started) -> Shown {
    if let (Some(manager), Some(pid)) = (started.manager, started.pid) {
        return shown!(
            "{} This command then asked the {} start for a daemon, which named process {}, and process {} answers. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
            *first,
            manager.as_str(),
            pid,
            pid
        );
    }
    shown!(
        "{} This command then started a control daemon{} under the {} start. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
        *first,
        process_said(started.pid.map(u64::from)),
        start_said(started)
    )
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and
/// another daemon serves the environment: after a daemon that holds it since the end, nothing was
/// started; otherwise what this command's own start came to, where it made one.
fn unmade_and_another_serves_said(
    id: EnvironmentId,
    first: &Shown,
    successor: Option<Option<u64>>,
    serving: Option<u64>,
    launched: Option<Started>,
    cut: bool,
) -> Shown {
    if let Some(successor) = successor {
        return shown!(
            "{} After it ended, a control daemon{} held environment {}, and a control daemon{} answers now. This command started none. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
            *first,
            process_said(successor),
            id,
            process_said(serving)
        );
    }
    match launched {
        None => shown!(
            "{} A control daemon already serves the environment{}. This command started none. No \
             session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
            *first,
            process_said(serving)
        ),
        Some(started) if cut => shown!(
            "{} A control daemon now serves the environment{}. This command's own start{} does not \
             serve it. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
            *first,
            process_said(serving),
            process_said(started.pid.map(u64::from))
        ),
        Some(started) => shown!(
            "{} A control daemon already serves the environment{}. The control daemon that answers \
             is not this command's own start{}. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
            *first,
            process_said(serving),
            process_said(started.pid.map(u64::from))
        ),
    }
}

/// What a restart says where the stop's request could not be made, the daemon was seen to end and
/// the start failed: the stop's own words, the start's, and what to do.
fn unmade_and_start_failed_said(first: &Shown, own: Shown, launched: bool, reach: Reach) -> Shown {
    shown!(
        "{} This command's start failed: {}.{}",
        *first,
        own,
        failure_tail(true, launched, reach)
    )
}

/// What a restart says where the daemon that it started answers: the process that ended and the one
/// that started, where it read them, and the start.
fn restarted_said(id: EnvironmentId, old: Option<u64>, started: &Started, creates: Shown) -> Shown {
    // A service manager's start names the process, and this command read its identity twice: the
    // words say who named it, and that it answers, and not that this command started it.
    let named = started.manager.zip(started.pid);
    let processes = match (old, started.pid) {
        (Some(old), _) if named.is_some() => shown!(" (process {} ended)", old),
        (_, _) if named.is_some() => Shown::said(""),
        (Some(old), Some(new)) => shown!(" (process {} ended, process {} started)", old, new),
        (Some(old), None) => shown!(" (process {} ended)", old),
        (None, Some(new)) => shown!(" (process {} started)", new),
        (None, None) => Shown::said(""),
    };
    let under = match named {
        Some((manager, pid)) => shown!(
            "{} start, which named process {}, and process {} answers",
            manager.as_str(),
            pid,
            pid
        ),
        None => shown!("{} start", start_said(started)),
    };
    shown!(
        "Restarted the control daemon for environment {}{} under the {}. No session was \
         stopped. Paired devices' connections to the old daemon closed; their pairings stand.{}",
        id,
        processes,
        under,
        creates
    )
}

/// What a result says of a daemon that answers where nothing shows whether it is the one this
/// command's start made: that a control daemon (of a newer generation where a stopped generation
/// was read) now answers, with its process where read.
fn answers_now(serving: Option<u64>, newer: bool) -> Shown {
    let generation = if newer { " of a newer generation" } else { "" };
    shown!(
        "control daemon{} now answers{}",
        generation,
        process_said(serving)
    )
}

/// What a result says this command did where nothing shows whether the daemon that answers is the
/// one its start made: it asked the start for a daemon, and cannot tell.
fn asked_and_cannot_tell(started: &Started) -> Shown {
    shown!(
        " This command asked the {} start for a daemon{} and cannot tell whether the daemon that \
         answers is that one.",
        start_said(started),
        process_said(started.pid.map(u64::from))
    )
}

/// What a restart says where the daemon ended and a control daemon answers that nothing shows to
/// be the one its start made: the stop's words (`clause`), what answers, and what it asked.
fn stopped_and_unproven_said(
    clause: &Shown,
    serving: Option<u64>,
    started: &Started,
    newer: bool,
    creates: Shown,
) -> Shown {
    shown!(
        "{}; a {}.{} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.{}",
        *clause,
        answers_now(serving, newer),
        asked_and_cannot_tell(started),
        creates
    )
}

/// The same after a request that could not be made, with the stop's words first.
fn unmade_and_unproven_said(
    first: &Shown,
    serving: Option<u64>,
    started: &Started,
    newer: bool,
) -> Shown {
    shown!(
        "{} A {}.{} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.",
        *first,
        answers_now(serving, newer),
        asked_and_cannot_tell(started)
    )
}

/// What a restart says where no daemon ran and a control daemon answers that nothing shows to be
/// the one its start made.
fn none_ran_and_unproven_said(
    id: EnvironmentId,
    serving: Option<u64>,
    started: &Started,
    under_way: Shown,
) -> Shown {
    shown!(
        "No control daemon was running for environment {}; a {}.{}{}",
        id,
        answers_now(serving, false),
        asked_and_cannot_tell(started),
        under_way
    )
}

/// What a restart says where the daemon ended and another daemon already serves the environment:
/// the stop's words (`clause`), the process that answers, and where this command launched a start,
/// that it did not take the environment. Where the request's outcome is not known and this command
/// launched nothing, it says that it started none.
fn stopped_and_another_already_serves_said(
    clause: &Shown,
    serving: Option<u64>,
    launched: Option<Started>,
    say_none_started: bool,
    creates: Shown,
) -> Shown {
    let own = match launched {
        None if say_none_started => Shown::said(" This command started none."),
        launched => Proved::own_start_said(launched),
    };
    shown!(
        "{}; a control daemon already serves it{}.{} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.{}",
        *clause,
        process_said(serving),
        own,
        creates
    )
}

/// What a restart says where no daemon ran and the one that it started answers.
fn none_ran_started_said(id: EnvironmentId, started: &Started, under_way: Shown) -> Shown {
    if let (Some(manager), Some(pid)) = (started.manager, started.pid) {
        return shown!(
            "No control daemon was running for environment {}. This command asked the {} start for a daemon, which named process {}, and process {} answers.{}",
            id,
            manager.as_str(),
            pid,
            pid,
            under_way
        );
    }
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

/// What a restart says where the daemon ended, it launched a start whose exchange was cut, and a
/// daemon of another process then gave a whole exchange. It says what it read and nothing of what
/// became of the daemon on the cut connection: the control daemon that serves the environment now
/// (process Q), and that its own start (process P) does not serve it.
fn stopped_and_another_serves_after_a_cut(
    clause: &Shown,
    serving: Option<u64>,
    started: &Started,
    creates: Shown,
) -> Shown {
    shown!(
        "{}; a control daemon now serves it{}. This command's own start{} does not serve it. No \
         session was stopped. Paired devices' connections to the old daemon closed; their pairings stand.{}",
        *clause,
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

/// What a restart says where its start failed after a stop whose words come first (`first`), or
/// after what it had stopped where the stop's words are not the first.
fn failure_said(
    id: EnvironmentId,
    had: Had,
    first: Option<&Shown>,
    own: Shown,
    launched: bool,
    reach: Reach,
) -> Shown {
    match first {
        None => start_failed_said(id, had, own, launched, reach),
        Some(first) => unmade_and_start_failed_said(first, own, launched, reach),
    }
}

/// What a failed start knows of a control daemon besides its own words, by the last read of the
/// endpoint.
#[derive(Clone, Debug)]
pub(crate) enum Reach {
    /// No control daemon answered during the start, and the last read gave no reply.
    Nobody,
    /// The last read gave a usable greeting, whether or not one answered during the start.
    Answers,
    /// A control daemon answered during the start, and the last read gave no reply.
    Answered,
    /// The last read gave a reply that this command cannot use: the words say what it was.
    Replied(Shown),
}

/// What a failure says after the start's own words: that a requested daemon may still start where
/// none answered or answers; what became of the sessions (`stopped`: the old daemon was stopped);
/// what is known of a control daemon; and what to do. Paired devices are said to be unable to
/// connect only where the old daemon was stopped and no daemon answers now, and a requested daemon
/// is said to be able to start only where no daemon answered at all, since a daemon that holds the
/// environment lets no second one start.
fn failure_tail(stopped: bool, launched: bool, reach: Reach) -> Shown {
    let sessions = if stopped {
        Shown::said(
            "No session was stopped: its workers keep running and a local attach still works.",
        )
    } else {
        Shown::said("Nothing was stopped.")
    };
    let paired = if stopped {
        Shown::said(" Paired devices cannot connect until a control daemon runs.")
    } else {
        Shown::said("")
    };
    match reach {
        Reach::Nobody => {
            let still = if launched {
                Shown::said(" The requested daemon may still start.")
            } else {
                Shown::said("")
            };
            shown!(
                "{} {}{} Fix the cause and run kr host restart again.",
                still,
                sessions,
                paired
            )
        }
        Reach::Answers => shown!(
            " A control daemon answers now. {} Run kr host restart again if that daemon must be \
             replaced.",
            sessions
        ),
        Reach::Answered => shown!(
            " A control daemon answered during the start, and none answers now. {}{} Run kr host \
             restart again.",
            sessions,
            paired
        ),
        Reach::Replied(why) => {
            // Where the old daemon was seen to end, its connections to the paired devices closed.
            let paired = if stopped {
                Shown::said(
                    " Paired devices' connections to the old daemon closed; their pairings stand.",
                )
            } else {
                Shown::said("")
            };
            shown!(
                " A control daemon replies, and this command cannot use its reply: {}. {}{}",
                why,
                sessions,
                paired
            )
        }
    }
}

/// What a restart says where its start failed: what it had stopped, the start's own words, that the
/// requested daemon may still start where a daemon was launched and not seen to end, that no
/// session was stopped, and what to do.
fn start_failed_said(
    id: EnvironmentId,
    had: Had,
    own: Shown,
    launched: bool,
    reach: Reach,
) -> Shown {
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
    shown!(
        "{}: {}.{}",
        stop,
        own,
        failure_tail(matches!(had, Had::Daemon(_)), launched, reach)
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
    /// Whether a control daemon answered during the start: the proof's failures come after an
    /// answer, and a start's own failure comes before one.
    pub(crate) answered: bool,
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
        // A daemon that answers now leaves the record nothing to say: it is removed, and the
        // failure says that a daemon answers.
        let no_reply = if self.answered {
            Reach::Answered
        } else {
            Reach::Nobody
        };
        let reach = match environment.paths.controller_endpoint() {
            Ok(endpoint) => match startup::read(&endpoint, startup::ANSWER_BOUND, &[]).await {
                startup::Read::Greeting(_) => {
                    progress.remove_marker();
                    Reach::Answers
                }
                startup::Read::Reply(why) => Reach::Replied(why),
                startup::Read::NoReply(_) => no_reply,
            },
            Err(_) => no_reply,
        };
        let message = failure_said(id, had, first, self.error.said(), self.launched, reach);
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

/// Writes the record of a start that asks for no stop, as `starting` from its first write, and
/// keeps it where an interrupt finds it. `daemon` is the daemon that ended before the start, where
/// the command read it.
fn begin_the_record(
    environment: &KnownEnvironment,
    daemon: Option<kr_protocol::identity::ProcessStartIdentity>,
    progress: &Progress,
) -> std::result::Result<(), kr_ipc::IpcError> {
    let marker = Marker::begin_start(&environment.paths, daemon)?;
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

/// What the proof knows of the daemon that was stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Old {
    /// No daemon ran, so none is older than the one that answers.
    None,
    /// A daemon was stopped, and this was its generation.
    Generation(ControllerGeneration),
    /// A daemon was stopped, and its generation was not read.
    Unread,
}

/// Whether the daemon that answered is the one that was started, from what one connection said of
/// it. `started` is what the start made, and none where its look found a daemon already there.
///
/// Three strengths of evidence. The daemon is the one that was started where the start knows its
/// process and the daemon states that process, and, where the generation of the daemon that was
/// stopped was read, the daemon is of a newer generation than it. A live process number names one
/// process, and this command saw the daemon that it stopped, or none, end before it launched: a
/// daemon that states the process the command launched is that process's own, whatever was read of
/// the old daemon. Where the start has no process to name (the scheduled task, a manager that does
/// not say), a daemon answers and nothing shows whether it is the one that was started: that is
/// [`Proved::Unproven`], and it says only what was read. A daemon of another process than the one
/// the start made is another daemon whatever else is known.
fn judge(
    started: Option<Started>,
    old: Old,
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
    if let Old::Generation(stopped) = old
        && answering.generation <= stopped
    {
        return Err("the control daemon that answers is of the generation that was told to stop");
    }
    let unproven = |newer| Proved::Unproven {
        serving: answering.pid,
        started,
        newer,
    };
    match (started.pid, answering.pid) {
        (None, _) => Ok(unproven(matches!(old, Old::Generation(_)))),
        // The child that was started lost the environment to another daemon, which answers.
        (Some(process), Some(answered)) if u64::from(process) != answered => Ok(Proved::Another {
            serving: Some(answered),
            launched: Some(started),
            cut: false,
        }),
        // The answer states the launched process's number, and this command holds that process
        // (or read its start identity twice) only where `held` says so: a number alone can be
        // used again.
        (Some(_), Some(_)) if started.held => Ok(Proved::Ours(started)),
        (Some(_), Some(_)) => Ok(unproven(matches!(old, Old::Generation(_)))),
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
    stopped: Old,
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
pub(crate) mod tests {
    use super::*;
    use crate::host_stop::Request;
    use kr_controller::attempt;

    fn started(pid: Option<u32>) -> Started {
        Started {
            pid,
            start: ControllerStartup::Standalone,
            manager: None,
            held: pid.is_some(),
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
        judge(
            started,
            stopped.map_or(Old::None, |generation| {
                Old::Generation(ControllerGeneration::new(generation))
            }),
            answering,
        )
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
            Ok(Proved::Unproven {
                serving: None,
                newer: true,
                ..
            })
        ));
        assert!(matches!(
            proof(Some(started(None)), Some(3), &answering(4, Some(9))),
            Ok(Proved::Unproven {
                serving: Some(9),
                newer: true,
                ..
            })
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

    /// Where a daemon was stopped and its generation was not read, an answer that states the process
    /// this command launched is its own start (a live process number names one process, and the
    /// command saw the old daemon end before it launched), and another process is another's
    /// whatever else is known. Where the start has no process to name, nothing shows either.
    #[test]
    fn where_the_stopped_generation_was_not_read_the_launched_process_is_still_the_proof() {
        let unread = |started, answering: &Answering| judge(started, Old::Unread, answering);
        assert!(matches!(
            unread(Some(started(Some(40))), &answering(1, Some(40))),
            Ok(Proved::Ours(_))
        ));
        assert!(matches!(
            unread(Some(started(Some(40))), &answering(1, Some(41))),
            Ok(Proved::Another {
                serving: Some(41),
                cut: false,
                ..
            })
        ));
        assert!(unread(Some(started(Some(40))), &answering(1, None)).is_err());
        assert!(matches!(
            proof(Some(started(None)), None, &answering(1, Some(9))),
            Ok(Proved::Unproven {
                serving: Some(9),
                newer: false,
                ..
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
            &stop_clause(id, Some(30), None),
            Some(41),
            &started(Some(40)),
            Shown::said(""),
        );
        assert_eq!(
            said.to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 now serves it (process 41). This command's own start (process 40) does not \
                 serve it. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        let creates = host_stop::creates_under_way(Some(2));
        let said = stopped_and_another_serves_after_a_cut(
            &stop_clause(id, None, None),
            Some(41),
            &started(Some(40)),
            creates,
        );
        assert!(
            said.to_string().starts_with(&format!(
                "Stopped the control daemon for environment {id}; a control daemon now serves it \
                 (process 41). This command's own start (process 40) does not serve it. No \
                 session was stopped. Paired devices' connections to the old daemon closed; their pairings stand. 2 session creates were still under way"
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
                 started) under the {start} start. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            restarted_said(id, None, &started(None), Shown::said("")).to_string(),
            format!(
                "Restarted the control daemon for environment {id} under the {start} start. \
                 No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
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
                &stop_clause(id, Some(30), None),
                Some(41),
                Some(started(Some(40))),
                false,
                Shown::said("")
            )
            .to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 already serves it (process 41). The control daemon that answers is not this \
                 command's own start (process 40). No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            stopped_and_another_already_serves_said(
                &stop_clause(id, Some(30), None),
                None,
                None,
                false,
                Shown::said("")
            )
            .to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 already serves it. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
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
                 (process 41). The control daemon that answers is not this command's own \
                 start (process 40)."
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
            start_failed_said(id, Had::Daemon(Some(30)), own.clone(), true, Reach::Nobody)
                .to_string(),
            format!(
                "The control daemon for environment {id} (process 30) was stopped and the start \
                 failed: the daemon did not answer. The requested daemon may still start. No \
                 session was stopped: its workers keep running and a local attach still works. Paired devices cannot connect until a control daemon runs. \
                 Fix the cause and run kr host restart again."
            )
        );
        assert_eq!(
            start_failed_said(id, Had::NoDaemon, own, false, Reach::Nobody).to_string(),
            format!(
                "No control daemon was running for environment {id} and the start failed: the \
                 daemon did not answer. Nothing was stopped. Fix the cause and run kr host \
                 restart again."
            )
        );
    }

    /// A start that fails after a control daemon answered, with a proof's own words, says what is
    /// known of a daemon and not that none runs: where a daemon answers now it says only that, and
    /// does not say that a requested daemon may still start or that paired devices cannot connect;
    /// where one answered during the start and none answers now it says that, and the sentence on
    /// paired devices stands. The frame is the same where the old daemon's stop opens it.
    #[test]
    fn a_start_that_fails_after_a_daemon_answered_says_what_is_known_of_a_daemon() {
        let host = kr_ipc::testing::TempHost::create();
        let id = host.environment_id();
        let own = || {
            Shown::said(
                "this command started a control daemon (process 31) but could not read which \
                 control daemon serves the environment, and no control daemon gave a whole answer \
                 within 30 seconds",
            )
        };
        let first = Shown::said("The control daemon for environment E ended.");
        let stopped = format!(
            "The control daemon for environment {id} (process 30) was stopped and the start failed: "
        );
        let sessions =
            "No session was stopped: its workers keep running and a local attach still works.";
        assert_eq!(
            start_failed_said(id, Had::Daemon(Some(30)), own(), false, Reach::Answers).to_string(),
            format!(
                "{stopped}{}. A control daemon answers now. {sessions} Run kr host restart again if that daemon must be replaced.",
                own()
            )
        );
        assert_eq!(
            start_failed_said(id, Had::Daemon(Some(30)), own(), false, Reach::Answered).to_string(),
            format!(
                "{stopped}{}. A control daemon answered during the start, and none answers now. {sessions} Paired devices cannot connect until a control daemon runs. Run kr host restart again.",
                own()
            )
        );
        assert_eq!(
            start_failed_said(id, Had::NoDaemon, own(), false, Reach::Answers).to_string(),
            format!(
                "No control daemon was running for environment {id} and the start failed: {}. A control daemon answers now. Nothing was stopped. Run kr host restart again if that daemon must be replaced.",
                own()
            )
        );
        assert_eq!(
            start_failed_said(id, Had::NoDaemon, own(), false, Reach::Answered).to_string(),
            format!(
                "No control daemon was running for environment {id} and the start failed: {}. A control daemon answered during the start, and none answers now. Nothing was stopped. Run kr host restart again.",
                own()
            )
        );
        for launched in [false, true] {
            assert_eq!(
                failure_said(
                    id,
                    Had::Daemon(Some(30)),
                    Some(&first),
                    own(),
                    launched,
                    Reach::Answers
                )
                .to_string(),
                format!(
                    "The control daemon for environment E ended. This command's start failed: {}. A control daemon answers now. {sessions} Run kr host restart again if that daemon must be replaced.",
                    own()
                ),
                "no requested daemon may still start where one answers"
            );
            assert_eq!(
                failure_said(
                    id,
                    Had::Daemon(Some(30)),
                    Some(&first),
                    own(),
                    launched,
                    Reach::Answered
                )
                .to_string(),
                format!(
                    "The control daemon for environment E ended. This command's start failed: {}. A control daemon answered during the start, and none answers now. {sessions} Paired devices cannot connect until a control daemon runs. Run kr host restart again.",
                    own()
                )
            );
        }
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
                Old::Generation(ControllerGeneration::new(3)),
                &answering(3, Some(40))
            )
            .is_err_and(|said| said
                == "the control daemon that answers is of the generation that was told to stop")
        );
        assert!(
            judge(
                Some(started(Some(40))),
                Old::Generation(ControllerGeneration::new(3)),
                &answering(4, None)
            )
            .is_err_and(|said| said
                == "the control daemon that answers did not state its process, so it cannot be \
                    told from the one that was started")
        );
        assert_eq!(
            Proved::own_start_said(Some(started(Some(40)))).to_string(),
            " The control daemon that answers is not this command's own start (process 40)."
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

    /// The restart's stop where its request could not be made and the daemon was seen to end: the
    /// stop's own words for that state, the environment they name, and what the restart makes of
    /// them with what it read of the daemon before.
    fn a_stop_whose_request_could_not_be_made(end: End) -> (EnvironmentId, Shown, Stopped) {
        let id = kr_ipc::testing::TempHost::create().environment_id();
        let first = host_stop::ended_before_the_request_said(
            id,
            Some(4000),
            &end,
            &Shown::said("the connection closed"),
        );
        let before = Before::Ended {
            said: first.clone(),
            pid: Some(4000),
            end,
        };
        let Ok(ended) = ended_without_a_request(before) else {
            panic!("an end that was seen goes on");
        };
        let (stopped, _) = stopped_unmade(Some((ControllerGeneration::new(3), None)), ended);
        (id, first, stopped)
    }

    fn another(serving: Option<u64>, launched: Option<Started>, cut: bool) -> Proved {
        Proved::Another {
            serving,
            launched,
            cut,
        }
    }

    /// Where the stop's request could not be made and the daemon was seen to end, the restart says
    /// the stop's own words first, that it did not stop the daemon, and then what its start did:
    /// the start took the environment, another daemon serves it (with this command's own start
    /// or with none, and after a cut exchange), another daemon holds it since the end, or the
    /// start failed. The words are those of the result that the decision makes, from the stop's
    /// words as it gives them.
    #[test]
    fn a_request_that_could_not_be_made_where_the_daemon_ended_says_so_and_then_what_the_start_did()
    {
        let (id, first, stopped) = a_stop_whose_request_could_not_be_made(End::Gone);
        let x = first.to_string();
        let said = |proved: &Proved| {
            said_after_the_proof(id, &stopped, proved, Shown::said("")).to_string()
        };
        let start = start_said(&started(Some(40)));
        assert_eq!(
            said(&Proved::Ours(started(Some(40)))),
            format!(
                "{x} This command then started a control daemon (process 40) under the {start} \
                 start. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&another(Some(50), Some(started(Some(40))), false)),
            format!(
                "{x} A control daemon already serves the environment (process 50). The control \
                 daemon that answers is not this command's own start (process 40). No session was \
                 stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&another(Some(50), None, false)),
            format!(
                "{x} A control daemon already serves the environment (process 50). This command \
                 started none. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&another(Some(50), Some(started(Some(40))), true)),
            format!(
                "{x} A control daemon now serves the environment (process 50). This command's own \
                 start (process 40) does not serve it. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        let (id, first, successor) =
            a_stop_whose_request_could_not_be_made(End::Successor(Some(77)));
        assert_eq!(
            said_after_the_proof(
                id,
                &successor,
                &another(Some(77), None, false),
                Shown::said("")
            )
            .to_string(),
            format!(
                "{first} After it ended, a control daemon (process 77) held environment {id}, and a control daemon (process 77) answers now. This command started none. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        for (launched, still) in [
            (false, ""),
            (true, " The requested daemon may still start."),
        ] {
            assert_eq!(
                failure_said(
                    id,
                    Had::Daemon(stopped.named),
                    stopped.opening(id).as_ref(),
                    Shown::said("the log could not be used"),
                    launched,
                    Reach::Nobody
                )
                .to_string(),
                format!(
                    "{x} This command's start failed: the log could not be used.{still} No session \
                     was stopped: its workers keep running and a local attach still works. Paired devices cannot connect until a control daemon runs. Fix the \
                     cause and run kr host restart again."
                )
            );
        }
    }

    /// A request that could not be made where the daemon was seen to end, or another holds the
    /// environment now, goes on to the start with the stop's own words and what the end was, which
    /// the result reads: a daemon that holds the environment since the end is not started beside;
    /// any other end of a request that could not be made is the stop's.
    #[test]
    fn only_an_end_that_was_seen_goes_on_to_the_start_and_any_other_is_the_stops() {
        for (end, successor) in [
            (End::Gone, None),
            (End::Successor(Some(77)), Some(Some(77))),
            (End::Successor(None), Some(None)),
        ] {
            let (_, first, stopped) = a_stop_whose_request_could_not_be_made(end);
            assert_eq!(stopped.successor, successor);
            assert_eq!(stopped.named, Some(4000));
            assert_eq!(stopped.first.as_ref(), Some(&first));
        }
        for before in [Before::Silent { accepted: true }, Before::OwnFault] {
            assert!(ended_without_a_request(before).is_err());
        }
    }

    /// The stop's request as the stop settled it where the daemon was seen to end: the process it
    /// named, and what the request came to.
    fn settled(request: Request, ended: End) -> Settled {
        Settled {
            request,
            ended,
            pid: Some(4000),
            unsettled: None,
            old: Some(kr_protocol::identity::ProcessStartIdentity::new(
                4000,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                1,
            )),
        }
    }

    /// Where the daemon took the stop the restart says that it stopped the daemon; where the request
    /// was written and the daemon did not show whether it took it, the restart says the stop's own
    /// words for that, and never "Stopped", before what its start did; where the daemon was not seen
    /// to end the stop says it.
    #[test]
    fn a_stop_whose_outcome_is_not_known_is_said_so_before_what_the_start_did() {
        let id = kr_ipc::testing::TempHost::create().environment_id();
        let failure = Shown::said("the connection closed");
        let generation = ControllerGeneration::new(3);
        let Ok((taken, _)) = stopped_by_the_request(settled(Request::Told, End::Gone), generation)
        else {
            panic!("an end that was seen goes on");
        };
        let Ok((unknown, _)) = stopped_by_the_request(
            settled(Request::MaybeAsked(failure.clone()), End::Gone),
            generation,
        ) else {
            panic!("an end that was seen goes on");
        };
        let said = |stopped: &Stopped, proved: &Proved| {
            said_after_the_proof(id, stopped, proved, Shown::said("")).to_string()
        };
        let s = format!(
            "The control daemon for environment {id} (process 4000) did not show whether it \
             took the stop (the connection closed), and it has ended"
        );
        let start = start_said(&started(Some(40)));
        assert_eq!(
            said(&taken, &Proved::Ours(started(Some(40)))),
            format!(
                "Restarted the control daemon for environment {id} (process 4000 ended, process \
                 40 started) under the {start} start. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&unknown, &Proved::Ours(started(Some(40)))),
            format!(
                "{s}. This command then started a control daemon (process 40) under the {start} \
                 start. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&unknown, &another(Some(50), Some(started(Some(40))), false)),
            format!(
                "{s}; a control daemon already serves it (process 50). The control daemon that \
                 answers is not this command's own start (process 40). No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&unknown, &another(Some(50), Some(started(Some(40))), true)),
            format!(
                "{s}; a control daemon now serves it (process 50). This command's own start \
                 (process 40) does not serve it. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&unknown, &another(Some(50), None, false)),
            format!(
                "{s}; a control daemon already serves it (process 50). This command started \
                 none. No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said(&taken, &another(Some(50), None, false)),
            format!(
                "Stopped the control daemon for environment {id} (process 4000); a control daemon \
                 already serves it (process 50). No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            failure_said(
                id,
                Had::Daemon(unknown.named),
                unknown.opening(id).as_ref(),
                Shown::said("the log could not be used"),
                true,
                Reach::Nobody
            )
            .to_string(),
            format!(
                "{s}. This command's start failed: the log could not be used. The requested \
                 daemon may still start. No session was stopped: its workers keep running and a \
                 local attach still works. Paired devices cannot connect until a control daemon runs. Fix the cause and run kr host restart again."
            )
        );
        let Err(not_ended) = stopped_by_the_request(
            settled(
                Request::Told,
                End::NotEnded(crate::host_stop::Why::Running, None),
            ),
            generation,
        ) else {
            panic!("a daemon that was not seen to end is the stop's");
        };
        assert!(matches!(not_ended.ended, End::NotEnded(..)));
    }

    /// Where a control daemon answers and nothing shows whether it is the one the start made, the
    /// restart says what it read (that a control daemon answers, of a newer generation only where
    /// the stopped generation was read, with its process where read) and what it asked (the start),
    /// and never that the daemon is its own start's or another's.
    #[test]
    fn a_daemon_that_nothing_shows_to_be_the_started_one_is_said_with_what_was_read_and_asked() {
        let (id, first, unmade) = a_stop_whose_request_could_not_be_made(End::Gone);
        let taken = Stopped {
            named: Some(30),
            pid: Some(30),
            unsettled: None,
            successor: None,
            generation: Old::Generation(ControllerGeneration::new(3)),
            first: None,
            unknown: None,
        };
        let unproven = |serving, newer| Proved::Unproven {
            serving,
            started: started(None),
            newer,
        };
        let start = start_said(&started(None));
        let asked = format!(
            "This command asked the {start} start for a daemon and cannot tell whether the daemon \
             that answers is that one."
        );
        assert_eq!(
            said_after_the_proof(id, &taken, &unproven(Some(41), true), Shown::said(""))
                .to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 of a newer generation now answers (process 41). {asked} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said_after_the_proof(id, &taken, &unproven(None, false), Shown::said("")).to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 30); a control daemon \
                 now answers. {asked} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            said_after_the_proof(id, &unmade, &unproven(Some(41), false), Shown::said(""))
                .to_string(),
            format!(
                "{first} A control daemon now answers (process 41). {asked} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            none_ran_and_unproven_said(id, Some(41), &started(None), Shown::said("")).to_string(),
            format!(
                "No control daemon was running for environment {id}; a control daemon now \
                 answers (process 41). {asked}"
            )
        );
    }

    /// An environment for a case that reads no daemon.
    fn an_environment() -> (kr_ipc::testing::TempHost, KnownEnvironment) {
        let temp = kr_ipc::testing::TempHost::create();
        let paths = temp.environment();
        let environment = KnownEnvironment {
            environment_id: paths.environment_id(),
            paths,
        };
        (temp, environment)
    }

    /// The restart's sentence for a holder that neither answers nor lets go within the bound, with
    /// its exit.
    #[test]
    fn the_restart_says_in_whole_that_a_holder_neither_answers_nor_lets_go() {
        use kr_client::shown::Said as _;

        let (_temp, environment) = an_environment();
        let failure = holder_silent(&environment, false, None);
        let how = if cfg!(windows) {
            "If it stays like this, end the kr-controller.exe process of this installation in Task Manager."
        } else {
            "If it stays like this, end the process that holds the lock file."
        };
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "A control daemon holds environment {} and does not answer, so it may be starting or stopping. No stop was requested. Run kr host restart again in a moment. {how} This command requested no stop and no start.",
                environment.environment_id
            )
        );
    }

    /// The restart's sentence for a record that could not be written where no daemon ran, with
    /// its exit.
    #[test]
    fn the_restart_says_in_whole_that_its_record_could_not_be_written_where_none_ran() {
        use kr_client::shown::Said as _;

        let error = kr_ipc::IpcError::socket(
            "create",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        let failure = not_recorded_before_the_start(&error);
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "kr host restart could not record its attempt: {}. No start was made.",
                Shown::ipc(&error)
            )
        );
    }

    /// What `reported` reads picks what a failed start says of a control daemon: a failure that came
    /// after an answer says so where none answers now, and a failure of a start that no daemon
    /// answered keeps the sentence that tells what to fix. (A daemon that answers now is read at
    /// the endpoint, and a start-up case covers it.)
    #[tokio::test]
    async fn a_failed_start_says_by_what_answered_it_what_is_known_of_a_daemon() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let sessions = " No session was stopped: its workers keep running and a local attach still works. Paired devices cannot connect until a control daemon runs.";
        for (answered, tail) in [
            (
                false,
                format!("{sessions} Fix the cause and run kr host restart again."),
            ),
            (
                true,
                format!(
                    " A control daemon answered during the start, and none answers now.{sessions} Run kr host restart again."
                ),
            ),
        ] {
            let progress = Progress::new(id);
            let failed = StartFailed {
                error: CliError::Other(Shown::said("the daemon did not answer")),
                launched: false,
                answered,
            };
            let reported = failed
                .reported(
                    &environment,
                    Had::Daemon(Some(30)),
                    None,
                    true,
                    &progress,
                    &Facts::none(Vec::new()),
                )
                .await;
            let Completion::Reported(error) = reported else {
                panic!("a failure is reported");
            };
            assert_eq!(
                error.said().to_string(),
                format!(
                    "The control daemon for environment {id} (process 30) was stopped and the start failed: the daemon did not answer.{tail}"
                ),
                "answered {answered}"
            );
        }
    }

    /// The daemon's side of one greeting at the environment's endpoint: accepts the next
    /// connection, reads its hello and answers it, and keeps the connection open.
    pub(crate) async fn answer_one_hello(
        listener: &kr_ipc::endpoint::Listener,
        id: EnvironmentId,
        another_major: bool,
    ) -> (kr_ipc::framed::FrameReader, kr_ipc::framed::FrameWriter) {
        use kr_protocol::envelope::ControlFrame;
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
        assert!(matches!(hello, ControlFrame::Hello(_)), "a hello");
        let selected_version = if another_major {
            kr_protocol::hello::ProtocolVersion::new(
                kr_protocol::hello::PROTOCOL_VERSION.major + 1,
                0,
            )
        } else {
            kr_protocol::hello::PROTOCOL_VERSION
        };
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

    /// A failed start where a control daemon answers at the endpoint when the failure is reported
    /// says so, whether or not one answered during the start and whether or not the start's
    /// process was seen to end: it does not say that a requested daemon may still start or that
    /// paired devices cannot connect.
    #[tokio::test]
    async fn a_failed_start_says_that_a_daemon_answers_where_one_answers_now() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let endpoint = environment
            .paths
            .controller_endpoint()
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(async move { answer_one_hello(&listener, id, false).await });
        let progress = Progress::new(id);
        let failed = StartFailed {
            error: CliError::Other(Shown::said("the daemon did not answer")),
            launched: true,
            answered: false,
        };
        let reported = failed
            .reported(
                &environment,
                Had::Daemon(Some(30)),
                None,
                true,
                &progress,
                &Facts::none(Vec::new()),
            )
            .await;
        let Completion::Reported(error) = reported else {
            panic!("a failure is reported");
        };
        assert_eq!(
            error.said().to_string(),
            format!(
                "The control daemon for environment {id} (process 30) was stopped and the start failed: the daemon did not answer. A control daemon answers now. No session was stopped: its workers keep running and a local attach still works. Run kr host restart again if that daemon must be replaced."
            )
        );
        let _connection = daemon.await.expect("the daemon answered once");
    }

    /// A start that asked for no stop writes its record as `starting` from the first write, so
    /// that a command killed between that write and the next leaves no record that says it was
    /// asking a daemon to stop.
    #[test]
    fn the_record_of_a_start_that_asked_for_no_stop_begins_as_starting() {
        let (_temp, environment) = an_environment();
        let progress = Progress::new(environment.environment_id);
        begin_the_record(&environment, None, &progress).expect("writes the record");
        let found = attempt::recorded(&environment.paths);
        assert_eq!(found.len(), 1, "one record stands");
        assert_eq!(found[0].attempt.command, attempt::Command::Restart);
        assert_eq!(found[0].attempt.phase, attempt::Phase::Starting);
        progress.remove_marker();
        assert!(attempt::recorded(&environment.paths).is_empty());
    }

    /// What a failed start says where the last read of the endpoint gave a reply that this command
    /// cannot use: the reply is said as what it is, the sessions' words follow, and the sentence that
    /// paired devices cannot connect is never said, since a daemon replies. Where the old daemon was
    /// seen to end, its connections to the paired devices closed, and that is said.
    #[test]
    fn a_failed_start_says_what_a_reply_that_cannot_be_used_is() {
        let id = EnvironmentId::new(kr_ipc::new_uuid());
        let own = || Shown::said("the daemon did not answer");
        let reply = || Reach::Replied(Shown::said("it states another public major"));
        assert_eq!(
            start_failed_said(id, Had::Daemon(Some(30)), own(), false, reply()).to_string(),
            format!(
                "The control daemon for environment {id} (process 30) was stopped and the start failed: the daemon did not answer. A control daemon replies, and this command cannot use its reply: it states another public major. No session was stopped: its workers keep running and a local attach still works. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        assert_eq!(
            start_failed_said(id, Had::NoDaemon, own(), false, reply()).to_string(),
            format!(
                "No control daemon was running for environment {id} and the start failed: the daemon did not answer. A control daemon replies, and this command cannot use its reply: it states another public major. Nothing was stopped."
            )
        );
    }

    /// A failed start where a daemon of another major answers the last read at the endpoint says
    /// that a daemon replies and that this command cannot use the reply: never that none answers
    /// now, and never that paired devices cannot connect.
    #[tokio::test]
    async fn a_failed_start_where_another_major_replies_never_says_that_none_answers() {
        use kr_client::shown::Said as _;
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let endpoint = environment
            .paths
            .controller_endpoint()
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(async move { answer_one_hello(&listener, id, true).await });
        let progress = Progress::new(id);
        let failed = StartFailed {
            error: CliError::Other(Shown::said("the daemon did not answer")),
            launched: false,
            answered: true,
        };
        let reported = failed
            .reported(
                &environment,
                Had::Daemon(Some(30)),
                None,
                true,
                &progress,
                &Facts::none(Vec::new()),
            )
            .await;
        let Completion::Reported(error) = reported else {
            panic!("a failure is reported");
        };
        let said = error.said().to_string();
        assert!(
            said.contains(" A control daemon replies, and this command cannot use its reply: "),
            "{said}"
        );
        assert!(!said.contains("none answers now"), "{said}");
        assert!(!said.contains("cannot connect"), "{said}");
        let _connection = daemon.await.expect("the daemon replied once");
    }

    /// The launched process is "ours" only where this command holds it (or read its start identity
    /// twice): an answer that states the launched number is otherwise unproven, in every state of
    /// what was read of the stopped daemon.
    #[test]
    fn an_answer_that_states_the_launched_number_is_ours_only_where_the_process_is_held() {
        let held = started(Some(7));
        let unheld = Started {
            held: false,
            ..held
        };
        for old in [
            Old::None,
            Old::Unread,
            Old::Generation(ControllerGeneration::new(1)),
        ] {
            assert!(matches!(
                judge(Some(held), old, &answering(2, Some(7))),
                Ok(Proved::Ours(_))
            ));
            assert!(matches!(
                judge(Some(unheld), old, &answering(2, Some(7))),
                Ok(Proved::Unproven {
                    serving: Some(7),
                    ..
                })
            ));
        }
    }

    /// A wait for a successor in which a read gave a reply that this command cannot use says that
    /// no control daemon gave a usable greeting, and not that none answered.
    #[test]
    fn a_successor_wait_that_met_a_reply_says_that_none_gave_a_usable_greeting() {
        use kr_client::shown::Said as _;

        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let opening = Shown::said("The daemon ended.");
        let last = Shown::said("it states another public major");
        let failure = successor_silent(id, &opening, Some(77), true, &last);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "The daemon ended. After it ended, a control daemon (process 77) held environment {id}, and no control daemon gave a usable greeting within 30 seconds: it states another public major. This command started none. Run kr host restart again."
            )
        );
    }

    /// The restart's sentence for another daemon that held the environment after the stopped
    /// daemon ended and no daemon answers, with its exit, for a successor whose process is known
    /// and for one whose process is not, after each of the stop's three openings: the daemon took
    /// the stop, the request could not be made, and its outcome is not known.
    #[test]
    fn the_restart_says_in_whole_that_a_successor_does_not_answer() {
        use kr_client::shown::Said as _;

        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let last = Shown::said("the endpoint accepted the connection and did not answer");
        let stopped = |first: Option<&'static str>, unknown: Option<&'static str>| Stopped {
            named: Some(4000),
            pid: Some(4000),
            unsettled: None,
            successor: Some(None),
            generation: Old::Unread,
            first: first.map(Shown::said),
            unknown: unknown.map(Shown::said),
        };
        for (stopped, opening) in [
            (
                stopped(None, None),
                format!("Stopped the control daemon for environment {id} (process 4000)."),
            ),
            (
                stopped(
                    Some("the stop's words for a request that was not made."),
                    None,
                ),
                "the stop's words for a request that was not made.".to_owned(),
            ),
            (
                stopped(None, Some("the connection was cut")),
                format!(
                    "The control daemon for environment {id} (process 4000) did not show whether it took the stop (the connection was cut), and it has ended."
                ),
            ),
        ] {
            for (successor, named) in [(Some(77), " (process 77)"), (None, "")] {
                let failure = successor_silent(id, &stopped.sentence(id), successor, false, &last);
                assert_eq!(failure.exit_code(), 1);
                assert_eq!(
                    failure.said().to_string(),
                    format!(
                        "{opening} After it ended, a control daemon{named} held environment {id}, and no control daemon answered within 30 seconds: the endpoint accepted the connection and did not answer. This command started none. Run kr host restart again."
                    )
                );
            }
        }
    }
}
