//! `kr host restart`: stops this installation's control daemon as `kr host stop` does, and starts one
//! the way `kr new` starts one.
//!
//! The model is the one `kr host stop` keeps: the request is served on the account's own local
//! socket, and this command is the way a person asks, with a guard against an accident and no
//! boundary. It stops no session: workers belong to the service manager or to the account and a
//! daemon that starts later finds them again.
//!
//! A restart is not done when the old daemon has ended. It reads what answers, and says what it
//! read and what it did: that a control daemon of another generation answers, and what this
//! command started or asked for, or that it started none. It gives no verdict of whose start the
//! daemon that answers is.
//!
//! Before it stops anything the command looks at what the start it would make needs (`preflight`)
//! and at how the daemon was started (the launch comparison): a restart that would stop a daemon
//! and then find no equivalent start refuses first, and says that nothing was stopped.

mod holder;
mod proof;
mod record;

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
    self, Answer, Asked, AtStart, Before, Begun, Cut, End, Facts, Knows, Launched, Looked,
    Progress, Real, Settled, Stage, Start, StartedFact, Which,
};
use crate::report::Completion;
use crate::resolve::KnownEnvironment;
use crate::restart_launch;
use crate::startup::{self, Launching, Started, Unstartable};
use record::{Last, Lock, Record};

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

/// The command, from the guard to the last read of the daemon that answers.
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
            start_where_none_ran(
                host,
                environment,
                json,
                progress,
                past,
                begun,
                Came::NoneRan,
            )
            .await
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
/// as the record of the wait shows it.
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
    // What every read of this wait gave, written as each is seen.
    let record = record::Shared::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match holder::wait(&operations, left, &record).await {
            holder::Holder::Answers => {
                proof::read(environment, progress, &record, proof::within(deadline)).await;
                let _ = holder::read_the_lock(&operations, proof::within(deadline), &record).await;
                let read = record.read();
                if let (Some(Last::Whole(_)), Some(whole)) = (read.last, read.whole) {
                    return host_stop::done(
                        &holder_answers_said(id, whole.process),
                        &Facts {
                            pid: whole.process,
                            answer: Some(Answer {
                                serving: whole.process,
                            }),
                            ..begun.none.clone()
                        },
                        json,
                        &begun.earlier,
                    );
                }
            }
            holder::Holder::Gone => {
                let read = record.read();
                let came = Came::HolderLetGo {
                    read: read.greeted || read.replied,
                };
                return start_where_none_ran(host, environment, json, progress, past, begun, came)
                    .await;
            }
            holder::Holder::Silent => break,
        }
        if deadline <= tokio::time::Instant::now() {
            break;
        }
        tokio::time::sleep(host_stop::LOOK_EVERY).await;
    }
    host_stop::failed(holder_silent(id, &record.read()), &begun.none, json)
}

/// What the restart says where a process held the environment and did not answer, and a daemon
/// answers now: that this command stopped none and started none.
fn holder_answers_said(id: EnvironmentId, serving: Option<u64>) -> Shown {
    shown!(
        "Environment {} was held, no control daemon answered, and a control daemon{} answers now. \
         This command stopped none and started none.",
        id,
        process_said(serving)
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
fn holder_silent(id: EnvironmentId, record: &Record) -> CliError {
    CliError::Unfinished {
        code: ErrorCode::EnvironmentUnavailable,
        message: failed_said(id, None, record, false, None),
    }
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
#[derive(Clone)]
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
    /// the words for that; where its outcome is not known, the stop's words for that; and that the
    /// daemon was stopped where it took the stop.
    fn sentence(&self, id: EnvironmentId) -> Shown {
        match (&self.first, &self.unknown) {
            (Some(first), _) => first.clone(),
            (None, unknown) => shown!("{}.", stop_clause(id, self.named, unknown.as_ref())),
        }
    }
}

/// What the restart says of the daemon's end: that it stopped the daemon where the daemon took the
/// stop, and, where the request's outcome is not known (`unknown` is its failure), the stop's own
/// words that the daemon did not show whether it took the stop and that it has ended: no process is
/// named there, for nothing shows which process took the request.
fn stop_clause(id: EnvironmentId, named: Option<u64>, unknown: Option<&Shown>) -> Shown {
    match unknown {
        None => shown!(
            "Stopped the control daemon for environment {}{}",
            id,
            process_said(named)
        ),
        Some(failure) => shown!(
            "The control daemon for environment {} did not show whether it took the stop ({}), and \
             it has ended",
            id,
            *failure
        ),
    }
}

/// A control daemon answers: asks how it was started, refuses before it stops anything where the
/// start would not give what it has, stops the daemon, and then starts one and reads what
/// answers.
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

/// The daemon that was stopped has ended: the wait for the daemon that holds the environment since,
/// or the start, and what the command says of what it read.
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
    past.end_seen();
    let facts = Facts {
        knows: Knows::Ended,
        pid: stopped.pid,
        unsettled: stopped.unsettled,
        ..begun.none.clone()
    };
    let came = Came::Stopped(stopped);
    let record = record::Shared::new();
    let waited = if came.successor().is_some() {
        // Another daemon holds the environment: nothing is started beside it.
        wait_for_the_successor(host, environment, came.old(), progress, &record).await
    } else {
        // The start's side. The record is the command's own until a daemon answers. A request that
        // could not be made let it go, and the start needs it again; where another daemon holds
        // the environment nothing is asked or started, and no record is written.
        if progress.with_marker(|_| ()).is_none() {
            let _ = begin_the_record(environment, old, progress);
        }
        start_and_prove(host, environment, came.old(), progress, past, &record).await
    };
    said_after(
        host,
        environment,
        json,
        progress,
        begun,
        &came,
        &record,
        waited,
        facts,
    )
    .await
}

/// Says what the wait or the start came to: where a daemon of another generation than the stopped
/// one gave a whole answer, what the record holds of it and what this command launched; where none
/// did, what the record of the reads shows.
// One argument for each fact its steps read: the paths, the environment, the output form, the progress, what began the command, what the restart did before, the record, what the wait came to and the facts.
#[allow(clippy::too_many_arguments)]
async fn said_after(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    begun: &Begun,
    came: &Came,
    record: &record::Shared,
    waited: std::result::Result<Option<Started>, StartFailed>,
    facts: Facts,
) -> Completion {
    let id = environment.environment_id;
    match waited {
        Ok(started) => {
            progress.remove_marker();
            let read = record.read();
            let said = succeeded_said(id, came, &read, started.as_ref(), came.creates(environment));
            host_stop::done(
                &said,
                &Facts {
                    answer: Some(answer_of(&read)),
                    launched: Some(launched_of(started.as_ref())),
                    ..facts
                },
                json,
                &begun.earlier,
            )
        }
        Err(failed) => {
            failed
                .reported(host, environment, came, record, json, progress, &facts)
                .await
        }
    }
}

/// Another daemon holds the environment after the one that was stopped ended: reads, within the
/// start's bound, until a daemon gives a whole answer, and starts nothing beside it.
async fn wait_for_the_successor(
    host: &HostPaths,
    environment: &KnownEnvironment,
    stopped: Old,
    progress: &Progress,
    record: &record::Shared,
) -> std::result::Result<Option<Started>, StartFailed> {
    let deadline = tokio::time::Instant::now() + startup::START_BOUND;
    let operations = proof::Real {
        host,
        environment,
        progress,
    };
    let whole = proof::until_whole(&operations, record, deadline).await;
    if whole && proof::answers_as_another_daemon(&record.read(), stopped) {
        return Ok(None);
    }
    Err(StartFailed {
        error: None,
        made: None,
        may_still_start: false,
    })
}

/// No control daemon runs, or the holder of the environment let go: the start is made, and what
/// answers is read.
async fn start_where_none_ran(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
    past: &Past,
    begun: &Begun,
    came: Came,
) -> Completion {
    let none = begun.none.clone();
    if let Err(error) = begin_the_record(environment, None, progress) {
        return host_stop::failed(not_recorded_before_the_start(&error), &none, json);
    }
    let record = record::Shared::new();
    let waited = start_and_prove(host, environment, Old::None, progress, past, &record).await;
    said_after(
        host,
        environment,
        json,
        progress,
        begun,
        &came,
        &record,
        waited,
        none,
    )
    .await
}

/// What the restart did before its wait or its start, which the record of reads does not hold: it
/// opens a result, and says what became of the old daemon.
#[derive(Clone)]
enum Came {
    /// No control daemon ran: nothing held the environment and nothing listened.
    NoneRan,
    /// A process held the environment and let go. `read` is whether a read of that wait gave a
    /// usable greeting or a reply.
    HolderLetGo { read: bool },
    /// The daemon was stopped, or was seen to end where the request could not be made.
    Stopped(Stopped),
}

impl Came {
    /// What the restart read of the daemon that was stopped.
    fn old(&self) -> Old {
        match self {
            Self::Stopped(stopped) => stopped.generation,
            Self::NoneRan | Self::HolderLetGo { .. } => Old::None,
        }
    }

    /// Whether the old daemon was seen to end.
    const fn ended(&self) -> bool {
        matches!(self, Self::Stopped(_))
    }

    /// The process that the lock named when the end was seen, where another daemon held the
    /// environment since the end.
    const fn successor(&self) -> Option<Option<u64>> {
        match self {
            Self::Stopped(stopped) => stopped.successor,
            Self::NoneRan | Self::HolderLetGo { .. } => None,
        }
    }

    /// The first sentence of a result.
    fn opening(&self, id: EnvironmentId) -> Shown {
        match self {
            Self::NoneRan => shown!("No control daemon was running for environment {}.", id),
            Self::HolderLetGo { read: false } => shown!(
                "Environment {} was held, no control daemon answered, and the hold ended.",
                id
            ),
            Self::HolderLetGo { read: true } => shown!(
                "Environment {} was held, a control daemon gave no whole answer, and the hold \
                 ended.",
                id
            ),
            Self::Stopped(stopped) => stopped.sentence(id),
        }
    }

    /// What a result says of the creates that were still under way.
    fn creates(&self, environment: &KnownEnvironment) -> Shown {
        match self {
            Self::Stopped(stopped) => host_stop::creates_under_way(stopped.unsettled),
            Self::NoneRan | Self::HolderLetGo { .. } => host_stop::under_way_said(environment),
        }
    }
}

/// What a restart says where a daemon gave a whole answer: the stop's words, that another daemon
/// answers (of another generation where the stopped generation was read, and its process where the
/// launch-only answer stated it), and what this command started or asked for.
fn succeeded_said(
    id: EnvironmentId,
    came: &Came,
    record: &Record,
    started: Option<&Started>,
    creates: Shown,
) -> Shown {
    let after = if came.ended() {
        Shown::said(
            "No session was stopped. Paired devices' connections to the old daemon closed; \
             their pairings stand.",
        )
    } else {
        Shown::said("")
    };
    let said = sentences([
        came.opening(id),
        successor_said(id, came),
        another_answers_said(came.old(), record),
        launched_said(started),
        after,
    ]);
    // The creates clause begins with its own space where there is one.
    shown!("{}{}", said, creates)
}

/// The sentences that are not empty, one space apart.
fn sentences(parts: impl IntoIterator<Item = Shown>) -> Shown {
    Shown::joined(
        parts
            .into_iter()
            .filter(|part| !part.as_str().is_empty())
            .collect::<Vec<_>>(),
        " ",
    )
}

/// That another daemon held the environment after the old one ended, where it did.
fn successor_said(id: EnvironmentId, came: &Came) -> Shown {
    match came.successor() {
        Some(process) => shown!(
            "After it ended, a control daemon{} held environment {}.",
            process_said(process),
            id
        ),
        None => Shown::said(""),
    }
}

/// What this command started or asked for: the standalone child with its process, the service
/// manager or the scheduled task that it asked, or that it started none.
fn launched_said(started: Option<&Started>) -> Shown {
    match started {
        None => Shown::said("This command started none."),
        Some(started) => match started.manager {
            Some(manager) => shown!(
                "This command asked {} to start a control daemon.",
                manager.as_str()
            ),
            None if cfg!(windows) => Shown::said(
                "This command asked this user's scheduled task to start a control daemon.",
            ),
            None => shown!(
                "This command started a control daemon{} under the standalone start.",
                process_said(started.pid.map(u64::from))
            ),
        },
    }
}

/// What a restart says where no daemon gave a whole answer of another generation than the stopped
/// one: each present-tense phrase is from the last read, each phrase about the whole wait from
/// the reads of any kind, and the lock is said only as it was read after the last read.
/// `came` is none where this command stopped and started nothing, and `own` is the start's own
/// words where the start failed.
fn failed_said(
    id: EnvironmentId,
    came: Option<&Came>,
    record: &Record,
    launched: bool,
    own: Option<&Shown>,
) -> Shown {
    let seen = record.greeted || record.replied;
    let mut parts = Vec::new();
    if let Some(came) = came {
        parts.push(came.opening(id));
        parts.push(successor_said(id, came));
    }
    if let Some(own) = own {
        parts.push(shown!("This command's start failed: {}.", *own));
    }
    parts.push(present_said(record, came.map_or(Old::None, Came::old)));
    parts.push(earlier_said(record));
    parts.push(wait_said(record, own.is_none()));
    parts.push(lock_said(id, record));
    if launched && !seen {
        parts.push(Shown::said("The requested daemon may still start."));
    }
    parts.push(match came {
        Some(came) => stopped_tail(came, record, own.is_some()),
        None => holder_tail(record),
    });
    sentences(parts)
}

/// That a daemon of another generation than the stopped one answers (of another generation where
/// the stopped generation was read), and its process where the launch-only answer stated it.
fn another_answers_said(old: Old, record: &Record) -> Shown {
    let generation = match old {
        Old::Generation(_) => " of another generation",
        Old::None | Old::Unread => "",
    };
    let serving = record.whole.and_then(|whole| whole.process);
    shown!(
        "A control daemon{}{} answers now.",
        generation,
        process_said(serving)
    )
}

/// What the last read of the endpoint gave. A whole answer is said as a success says it where the
/// generation test says that it is another daemon's, and as the stopped generation's where it is not.
fn present_said(record: &Record, old: Old) -> Shown {
    if matches!(record.last, Some(Last::Whole(_))) && proof::answers_as_another_daemon(record, old)
    {
        return another_answers_said(old, record);
    }
    Shown::said(match record.last {
        None => "",
        Some(Last::Whole(_)) => {
            "A control daemon of the generation that was asked to stop answers now."
        }
        Some(Last::Greeting(_)) => "A control daemon gave a usable greeting and no whole answer.",
        Some(Last::Reply) => "A control daemon replied, and this command cannot use its reply.",
        Some(Last::NothingListens) => "No control daemon answers now: nothing listens.",
        Some(Last::NothingInTime) => {
            "This command's last try to reach a control daemon got no answer in time."
        }
        Some(Last::CheckFailed) => "This command could not check whether a control daemon answers.",
    })
}

/// What an earlier read gave, where the last read does not say it.
fn earlier_said(record: &Record) -> Shown {
    let greeting = record.greeted
        && !matches!(
            record.last,
            Some(Last::Greeting(_) | Last::Whole(_) | Last::Reply)
        );
    let reply = record.replied && !matches!(record.last, Some(Last::Reply));
    Shown::said(match (greeting, reply) {
        (false, false) => "",
        (true, false) => "A control daemon gave a usable greeting during the wait.",
        (false, true) => {
            "A control daemon replied during the wait, and this command cannot use its reply."
        }
        (true, true) => {
            "A control daemon gave a usable greeting and a reply that this command cannot use \
             during the wait."
        }
    })
}

/// What the whole wait gave: no control daemon answered only where no read gave a usable greeting
/// or a reply, and where one did and no whole answer followed, none gave a whole answer. The
/// start's own words say it where the start failed.
fn wait_said(record: &Record, own_is_silent: bool) -> Shown {
    let seconds = startup::START_BOUND.as_secs();
    if !own_is_silent || record.whole.is_some() {
        Shown::said("")
    } else if record.greeted || record.replied {
        shown!(
            "No control daemon gave a whole answer within {} seconds.",
            seconds
        )
    } else {
        shown!("No control daemon answered within {} seconds.", seconds)
    }
}

/// What the lock read after the last read of the endpoint says: a control daemon holds the
/// environment only where the last read greeted or replied and the lock was then held; a held lock
/// alone is a held environment.
fn lock_said(id: EnvironmentId, record: &Record) -> Shown {
    match record.lock.map(|read| read.lock) {
        Some(Lock::Held)
            if matches!(
                record.last,
                Some(Last::Whole(_) | Last::Greeting(_) | Last::Reply)
            ) =>
        {
            shown!("A control daemon holds environment {}.", id)
        }
        Some(Lock::Held) => shown!("The lock of environment {} is held.", id),
        Some(Lock::NotReadable) => {
            Shown::said("This command could not check whether the environment is held.")
        }
        Some(Lock::Free) | None => Shown::said(""),
    }
}

/// How a restart that stopped or started something ends where no daemon gave a whole answer: what
/// became of the sessions and of the paired devices, and what to do. Paired devices are said to be
/// unable to connect only where the old daemon was seen to end and the last read found nothing
/// listening; their connections to the old daemon are said to have closed wherever it was seen
/// to end.
fn stopped_tail(came: &Came, record: &Record, own: bool) -> Shown {
    let sessions = if came.ended() {
        "No session was stopped: its workers keep running, and a local attach keeps working."
    } else {
        "Nothing was stopped."
    };
    let paired = match (came.ended(), record.last) {
        (true, Some(Last::NothingListens)) => {
            "Paired devices cannot connect until a control daemon runs. Paired devices' \
             connections to the old daemon closed; their pairings stand."
        }
        (true, _) => "Paired devices' connections to the old daemon closed; their pairings stand.",
        (false, _) => "",
    };
    let started_none = if came.successor().is_some() {
        "This command started none."
    } else {
        ""
    };
    let advice = if own {
        "Fix the cause and run kr host restart again."
    } else {
        "Run kr host restart again."
    };
    sentences([
        Shown::said(started_none),
        Shown::said(sessions),
        Shown::said(paired),
        Shown::said(advice),
    ])
}

/// How a wait for a holder ends where no daemon gave a whole answer and the holder did not let go:
/// that it may be starting or stopping where the lock is held, what to do about it with the process
/// that the lock file named at the read of the lock, and that this command asked for nothing.
fn holder_tail(record: &Record) -> Shown {
    let held = record.lock.filter(|read| read.lock == Lock::Held);
    let may = if held.is_some() {
        Shown::said("It may be starting or stopping.")
    } else {
        Shown::said("")
    };
    let how = match held {
        Some(read) => shown!("{}", host_stop::how_to_end_the_process(read.named)),
        None => Shown::said(""),
    };
    sentences([
        may,
        Shown::said("Run kr host restart again in a moment."),
        how,
        Shown::said("This command requested no stop and no start."),
    ])
}

/// A start that did not give a whole answer of another generation than the stopped one.
pub(crate) struct StartFailed {
    /// What the start said in its own words, where the start itself failed: none where the daemon
    /// that answered is what the record shows.
    pub(crate) error: Option<CliError>,
    /// The start that was made, as the start or its request gave it: the daemon this command
    /// started, or the service manager or the task that it asked to start one, whether or not that
    /// daemon may still come up; none where no start was made.
    pub(crate) made: Option<Started>,
    /// Whether the daemon that the start asked for may still come up.
    pub(crate) may_still_start: bool,
}

impl StartFailed {
    /// The failure of a start that made what `launched` says it made, with the start's own words
    /// where the start itself failed.
    pub(super) fn after(launched: &Launching, error: Option<CliError>) -> Self {
        Self {
            error,
            made: launched.made(),
            may_still_start: launched.may_still_start(),
        }
    }

    /// Reports the failure: what the record shows after one more read of the endpoint and of the
    /// lock, and the record of the attempt as a failed start. A daemon that gives a usable greeting
    /// once the record is written makes the failure moot, and the record goes.
    // One argument for each fact its steps read: the paths, the environment, what the restart did before, the record, the output form, the progress and the facts.
    #[allow(clippy::too_many_arguments)]
    async fn reported(
        self,
        host: &HostPaths,
        environment: &KnownEnvironment,
        came: &Came,
        record: &record::Shared,
        json: bool,
        progress: &Progress,
        facts: &Facts,
    ) -> Completion {
        let id = environment.environment_id;
        // A command that waited for a successor started nothing: its record keeps the stop's phase.
        if came.successor().is_none() {
            let _ = progress.with_marker(|marker| marker.start_failed());
        }
        proof::read(environment, progress, record, startup::ANSWER_BOUND).await;
        let locks = Real::of(host, &environment.paths, None);
        let _ = holder::read_the_lock(&locks, startup::ANSWER_BOUND, record).await;
        let read = record.read();
        // A daemon that answers now leaves the record nothing to say.
        if matches!(read.last, Some(Last::Whole(_) | Last::Greeting(_))) {
            progress.remove_marker();
        }
        let own = self.error.as_ref().map(Said::said);
        let message = failed_said(id, Some(came), &read, self.may_still_start, own.as_ref());
        let facts = self.facts(facts);
        let error = match self.error {
            Some(CliError::HostUnavailable(_)) => CliError::HostUnavailable(message),
            Some(CliError::Unfinished { code, .. }) => CliError::Unfinished { code, message },
            _ => CliError::Unfinished {
                code: ErrorCode::EnvironmentUnavailable,
                message,
            },
        };
        host_stop::failed(error, &facts, json)
    }

    /// The facts of the failure's result: what this command asked for. A start that was made says
    /// which start it made, as the start or its request gave it and not as the environment
    /// chooses by now, without a process, since none was read; one that made none says so.
    fn facts(&self, facts: &Facts) -> Facts {
        Facts {
            launched: Some(self.made.as_ref().map_or(Launched::Nothing, |started| {
                Launched::Start(StartedFact {
                    pid: None,
                    ..started_fact(started)
                })
            })),
            ..facts.clone()
        }
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

/// What the restart read of the daemon that was stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Old {
    /// No daemon ran, so none is older than the one that answers.
    None,
    /// A daemon was stopped, and this was its generation.
    Generation(ControllerGeneration),
    /// A daemon was stopped, and its generation was not read.
    Unread,
}

/// Starts a daemon as `kr new` does and reads what answers (`proof::prove`): a whole answer of a
/// generation other than the one that was stopped, or a start that failed. What the daemon states
/// is in `record`.
async fn start_and_prove(
    host: &HostPaths,
    environment: &KnownEnvironment,
    stopped: Old,
    progress: &Progress,
    past: &Past,
    record: &record::Shared,
) -> std::result::Result<Option<Started>, StartFailed> {
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
        record,
    )
    .await
}

/// What `--json` says of the daemon that answered, as the record shows it, and of what this command
/// launched.
fn answer_of(record: &Record) -> Answer {
    Answer {
        serving: record.whole.and_then(|whole| whole.process),
    }
}

/// What `--json` says of the start where the restart ended with a daemon that answers: what this
/// command started or asked for, or that it started nothing.
fn launched_of(started: Option<&Started>) -> Launched {
    started.map_or(Launched::Nothing, |started| {
        Launched::Start(started_fact(started))
    })
}

/// The start as `--json` names it: the standalone child with its process, and the service manager
/// or the scheduled task that this command asked, with none.
fn started_fact(started: &Started) -> StartedFact {
    StartedFact {
        start: match started.manager {
            Some(manager) => manager.as_str(),
            None if cfg!(windows) => "task",
            None => "standalone",
        },
        pid: if started.manager.is_none() {
            started.pid
        } else {
            None
        },
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
        &interrupted_facts(knows, past, progress),
        json,
    )
}

/// The facts of an interrupt's result: what it knows of the stop, and, where the start was begun,
/// that it cannot tell whether its request left.
fn interrupted_facts(knows: Knows, past: &Past, progress: &Progress) -> Facts {
    Facts {
        knows,
        launched: Some(match past.beyond() {
            Beyond::Starting => Launched::Unknown,
            Beyond::Stop | Beyond::Ended => Launched::Nothing,
        }),
        ..Facts::none(progress.said_earlier())
    }
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
    use super::record::{LockRead, Whole};
    use super::*;
    use kr_controller::attempt;

    fn generation(number: u64) -> ControllerGeneration {
        ControllerGeneration::new(number)
    }

    /// The stop's outcome where the daemon took the request and was seen to end.
    fn taken(old: Old) -> Came {
        Came::Stopped(Stopped {
            named: Some(90),
            pid: Some(90),
            unsettled: None,
            successor: None,
            generation: old,
            first: None,
            unknown: None,
        })
    }

    fn standalone(pid: u32) -> Started {
        Started {
            pid: Some(pid),
            start: ControllerStartup::Standalone,
            manager: None,
        }
    }

    fn whole(number: u64, process: Option<u64>) -> Record {
        Record {
            greeted: true,
            replied: false,
            last: Some(Last::Whole(generation(number))),
            whole: Some(Whole {
                generation: generation(number),
                process,
            }),
            lock: None,
        }
    }

    /// A whole answer is said with the stop's words, that a daemon of another generation answers
    /// with the process that its launch-only answer stated, and what this command started: and
    /// nothing about whose start the daemon that answers is.
    #[test]
    fn a_whole_answer_is_said_with_what_ended_and_what_was_started_and_no_verdict() {
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let said = succeeded_said(
            id,
            &taken(Old::Generation(generation(1))),
            &whole(2, Some(91)),
            Some(&standalone(77)),
            Shown::said(""),
        );
        // The start's words are the platform's own.
        let started = launched_said(Some(&standalone(77)));
        if cfg!(windows) {
            assert_eq!(
                started.to_string(),
                "This command asked this user's scheduled task to start a control daemon."
            );
        }
        assert_eq!(
            said.to_string(),
            format!(
                "Stopped the control daemon for environment {id} (process 90). A control daemon of another generation (process 91) answers now. {started} No session was stopped. Paired devices' connections to the old daemon closed; their pairings stand."
            )
        );
        // Where the stopped generation was never read no comparison is made, and a daemon that
        // states no process says none.
        let said = succeeded_said(id, &Came::NoneRan, &whole(2, None), None, Shown::said(""));
        assert_eq!(
            said.to_string(),
            format!(
                "No control daemon was running for environment {id}. A control daemon answers now. This command started none."
            )
        );
    }

    /// Every result of a restart carries `launched`: null where nothing was started or asked, the
    /// start's kind where a failed start made one (no process was read), `unknown` for an
    /// interrupt while the start runs, and the success's own form; a stop's result carries none.
    /// The kind of a failed start is the kind of the start that was made, as the start or its
    /// request gave it: the environment's choice, changed between the request and the report,
    /// does not change it.
    #[test]
    fn every_result_of_a_restart_says_what_it_started_or_asked_for() {
        let (_temp, environment) = an_environment();
        let facts = Facts {
            launched: Some(Launched::Nothing),
            ..Facts::none(Vec::new())
        };
        assert!(
            Facts::none(Vec::new()).launched.is_none(),
            "a stop has no member"
        );
        let nothing = StartFailed {
            error: None,
            made: None,
            may_still_start: false,
        };
        assert_eq!(
            nothing.facts(&facts).launched.map(Launched::parts),
            Some(None),
            "a failed start that asked for nothing"
        );
        let standalone_word = if cfg!(windows) { "task" } else { "standalone" };
        let service = Started {
            pid: None,
            start: ControllerStartup::Service,
            manager: Some(crate::service_manager::Manager::Systemd),
        };
        let document = crate::doctor::configuration::document_path(&environment.paths);
        let choose = |chosen: &str| {
            let text = format!(
                r#"{{"version": 1, "revision": 1, "startup": {{"controller": "{chosen}"}}}}"#
            );
            kr_ipc::paths::write_owner_only_file(&document, text.as_bytes())
                .expect("the choice is written");
        };
        // The environment chooses one start when the request is made and the other by the time the
        // failure is reported: the start that was made is the one that the request gave.
        for (started, expected, at_the_request, by_the_report) in [
            (standalone(77), standalone_word, "standalone", "service"),
            (service, "systemd", "service", "standalone"),
        ] {
            choose(at_the_request);
            let launching = Launching::default();
            launching.start_made(started);
            choose(by_the_report);
            // The start's kind does not depend on whether its daemon may still come up: a child
            // that started and ended made a start as well.
            for may_still_start in [true, false] {
                let failed = StartFailed {
                    error: None,
                    made: launching.made(),
                    may_still_start,
                };
                let said = failed.facts(&facts).launched.map(Launched::parts);
                assert_eq!(
                    said,
                    Some(Some((expected, None))),
                    "a failed start that made {started:?} (its daemon may still come up: \
                     {may_still_start}), the environment choosing {at_the_request} at the request \
                     and {by_the_report} at the report"
                );
            }
        }
        let progress = Progress::new(environment.environment_id);
        for (beyond, expected) in [
            (Beyond::Stop, None),
            (Beyond::Ended, None),
            (Beyond::Starting, Some(("unknown", None))),
        ] {
            let past = Past::new();
            past.enter(beyond);
            let said = interrupted_facts(Knows::NotAsked, &past, &progress)
                .launched
                .map(Launched::parts);
            assert_eq!(said, Some(expected), "an interrupt at {beyond:?}");
        }
        assert_eq!(
            launched_of(Some(&standalone(77))).parts(),
            Some((standalone_word, Some(77)))
        );
        assert_eq!(launched_of(None).parts(), None);
    }

    /// The `--json` start names the standalone child with its process, and the service manager or
    /// the task that was asked with none.
    #[test]
    fn the_json_start_names_a_process_only_for_the_standalone_child() {
        let child = started_fact(&standalone(77));
        assert_eq!(child.pid, Some(77));
        let managed = started_fact(&Started {
            pid: Some(88),
            start: ControllerStartup::Service,
            manager: Some(crate::service_manager::Manager::Systemd),
        });
        assert_eq!((managed.start, managed.pid), ("systemd", None));
    }

    /// What a failed start says where a stand-in daemon of `generation` gives the final read of the
    /// reporting a whole exchange with the process 7, through the real reporting of the command.
    async fn said_by_a_failed_start_that_a_daemon_answers_late(
        came: Came,
        generation: u64,
    ) -> String {
        use kr_client::shown::Said as _;

        let (temp, environment) = an_environment();
        let id = environment.environment_id;
        let endpoint = environment
            .paths
            .controller_endpoint()
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(host_stop::tests::answer_a_whole_exchange(
            listener,
            id,
            generation_of(generation),
            7,
        ));
        let completion = StartFailed {
            error: Some(CliError::HostUnavailable(Shown::said(
                "the start's own words",
            ))),
            made: Some(standalone(77)),
            may_still_start: true,
        }
        .reported(
            temp.paths(),
            &environment,
            &came,
            &record::Shared::new(),
            false,
            &Progress::new(id),
            &Facts::none(Vec::new()),
        )
        .await;
        let Completion::Reported(error) = completion else {
            panic!("a failed start is reported");
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), daemon)
            .await
            .expect("the stand-in daemon ends where the command lets go of its connection")
            .expect("the stand-in daemon ran");
        error.said().to_string()
    }

    fn generation_of(number: u64) -> ControllerGeneration {
        ControllerGeneration::new(number)
    }

    /// A failed start whose final read finds a daemon of a newer generation than the stopped one
    /// says what a success says of it, and never that it is the generation that was asked to stop.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_start_that_a_new_generation_answers_late_does_not_call_it_the_stopped_one() {
        let said = said_by_a_failed_start_that_a_daemon_answers_late(
            taken(Old::Generation(generation(1))),
            2,
        )
        .await;
        assert!(
            said.contains(
                "This command's start failed: the start's own words. A control daemon of another generation (process 7) answers now."
            ),
            "{said}"
        );
        assert!(!said.contains("asked to stop"), "{said}");
    }

    /// A failed start where no daemon ran, whose final read finds a daemon, says what a success
    /// says of it, and never that it is the generation that was asked to stop: none was.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_start_where_none_ran_does_not_call_a_late_answer_the_stopped_one() {
        let said = said_by_a_failed_start_that_a_daemon_answers_late(Came::NoneRan, 2).await;
        assert!(
            said.contains(
                "This command's start failed: the start's own words. A control daemon (process 7) answers now."
            ),
            "{said}"
        );
        assert!(!said.contains("asked to stop"), "{said}");
        assert!(!said.contains("another generation"), "{said}");
    }

    /// A failed start whose final read finds the stopped generation says so.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_start_whose_final_read_finds_the_stopped_generation_says_so() {
        let said = said_by_a_failed_start_that_a_daemon_answers_late(
            taken(Old::Generation(generation(1))),
            1,
        )
        .await;
        assert!(
            said.contains(
                "This command's start failed: the start's own words. A control daemon of the generation that was asked to stop answers now."
            ),
            "{said}"
        );
    }

    /// A read of a daemon that answers on a real link is in the record as it goes: the greeting
    /// where the connection is made, before any read follows it, and then the whole exchange with
    /// the generation that `host.info` gave and the process that the launch-only answer stated.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_read_of_a_daemon_that_answers_is_in_the_record_by_its_greeting_and_its_exchange() {
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let endpoint = environment
            .paths
            .controller_endpoint()
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let daemon = tokio::spawn(host_stop::tests::answer_a_whole_exchange(
            listener,
            id,
            generation_of(2),
            7,
        ));
        let record = record::Shared::new();
        let connection = proof::connect(&environment.paths, startup::ANSWER_BOUND, &record).await;
        let greeted = record.read();
        // The stand-in greets at once: a connection that was not made in time is none, and the
        // record is judged only where the connection was made.
        let Some(mut connection) = connection else {
            panic!(
                "the stand-in's greeting is usable and comes within the bound: {:?}",
                greeted.last
            );
        };
        assert!(
            greeted.greeted,
            "the greeting is in the record where the connection was made"
        );
        assert_eq!(greeted.last, Some(Last::Greeting(None)));
        let (gave, asked) = proof::exchange(&mut connection, id, &Progress::new(id), &record).await;
        drop(connection);
        // The exchange ended as the daemon made it end, before the record is read: the read gave
        // the generation and the request for the launch alone was taken. What the record lacks
        // after this is a write that was not made, and no exchange that ran out of time.
        assert_eq!(
            gave,
            host_stop::Gave::Reported(generation_of(2)),
            "the read of `host.info` gave the generation"
        );
        let Some(host_stop::Asked::Taken(taken)) = asked else {
            panic!("the request for the launch alone was taken: it was made after the read");
        };
        assert_eq!(taken.pid.get(), 7, "the answer states the daemon's process");
        let answered = tokio::time::timeout(std::time::Duration::from_secs(10), daemon)
            .await
            .expect("the stand-in daemon ends where the command lets go of its connection")
            .expect("the stand-in daemon ran");
        // Both requests were answered: what the record lacks now is a write that was not made.
        assert_eq!(
            answered, 2,
            "the stand-in answered `host.info` and the request for the launch alone"
        );
        let read = record.read();
        assert_eq!(read.last, Some(Last::Whole(generation_of(2))));
        assert_eq!(read.whole.and_then(|whole| whole.process), Some(7));
    }

    /// The record of an attempt says that this command's start failed only where this command
    /// entered its start path: a wait for a successor leaves the stop's phase, and a start that
    /// fails writes `start_failed`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_wait_for_a_successor_keeps_the_stops_phase_in_the_record() {
        use kr_controller::attempt::{self, Phase};

        let old = Old::Generation(generation(1));
        let successor = Came::Stopped(Stopped {
            successor: Some(Some(3)),
            ..match taken(old) {
                Came::Stopped(stopped) => stopped,
                Came::NoneRan | Came::HolderLetGo { .. } => unreachable!("a stop"),
            }
        });
        for (came, expected) in [(successor, Phase::Told), (taken(old), Phase::StartFailed)] {
            let (temp, environment) = an_environment();
            let progress = Progress::new(environment.environment_id);
            begin_the_record(&environment, None, &progress).expect("writes the record");
            let _ = progress.with_marker(|marker| marker.told());
            let _ = StartFailed {
                error: None,
                made: None,
                may_still_start: false,
            }
            .reported(
                temp.paths(),
                &environment,
                &came,
                &record::Shared::new(),
                false,
                &progress,
                &Facts::none(Vec::new()),
            )
            .await;
            let found = attempt::recorded(&environment.paths);
            assert_eq!(found.len(), 1, "one record stands");
            assert_eq!(found[0].attempt.phase, expected);
        }
    }

    /// KR-REQ-07.12: a failed start says the lock that it read after its last read of the
    /// endpoint: where nothing listens and the lock is held, the text says so in that order, and
    /// where the lock is free it says nothing of a hold.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_start_reports_the_lock_it_read_after_its_last_read_of_the_endpoint() {
        use kr_client::shown::Said as _;

        async fn said_by_a_failed_start(
            temp: &kr_ipc::testing::TempHost,
            environment: &KnownEnvironment,
        ) -> String {
            let completion = StartFailed {
                error: None,
                made: None,
                may_still_start: false,
            }
            .reported(
                temp.paths(),
                environment,
                &taken(Old::Generation(generation(1))),
                &record::Shared::new(),
                false,
                &Progress::new(environment.environment_id),
                &Facts::none(Vec::new()),
            )
            .await;
            let Completion::Reported(error) = completion else {
                panic!("a failed start is reported");
            };
            error.said().to_string()
        }

        let (temp, environment) = an_environment();
        let id = environment.environment_id;
        let lock = environment.paths.singleton_lock();
        let held = kr_controller::singleton::SingletonLock::hold(&lock, id).expect("holds");
        let said = said_by_a_failed_start(&temp, &environment).await;
        let nothing = said.find("No control daemon answers now: nothing listens.");
        let hold = said.find(&format!("The lock of environment {id} is held."));
        assert!(
            matches!((nothing, hold), (Some(nothing), Some(hold)) if nothing < hold),
            "the last read of the endpoint, then the lock that was read after it: {said}"
        );
        drop(held);
        let said = said_by_a_failed_start(&temp, &environment).await;
        assert!(
            said.contains("No control daemon answers now: nothing listens."),
            "{said}"
        );
        assert!(!said.contains("is held."), "{said}");
    }

    /// A holder that neither answers nor lets go says only what the reads showed: a held lock
    /// alone is a held environment, and the process in the advice is the one that the lock file
    /// named at the read of the lock.
    #[test]
    fn a_holder_that_neither_answers_nor_lets_go_says_only_what_the_record_shows() {
        use kr_client::shown::Said as _;

        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let mut record = Record {
            greeted: false,
            replied: false,
            last: Some(Last::NothingInTime),
            whole: None,
            lock: Some(LockRead {
                lock: Lock::Held,
                named: Some(5),
            }),
        };
        let failure = holder_silent(id, &record);
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(
            failure.said().to_string(),
            format!(
                "This command's last try to reach a control daemon got no answer in time. No control daemon answered within 30 seconds. The lock of environment {id} is held. It may be starting or stopping. Run kr host restart again in a moment. {} This command requested no stop and no start.",
                host_stop::how_to_end_the_process(Some(5))
            )
        );
        // A read that greeted and a held lock after it say that a control daemon holds it.
        record.greeted = true;
        record.last = Some(Last::Greeting(None));
        let said = holder_silent(id, &record).said().to_string();
        assert!(
            said.contains(&format!(
                "A control daemon gave a usable greeting and no whole answer. No control daemon gave a whole answer within 30 seconds. A control daemon holds environment {id}."
            )),
            "{said}"
        );
    }

    /// A failed start after the old daemon ended says what the last read gave, says that paired
    /// devices cannot connect only where nothing listens, and says that their connections to the
    /// old daemon closed wherever the old daemon was seen to end.
    #[test]
    fn a_failed_start_says_by_the_last_read_whether_paired_devices_can_connect() {
        let (_temp, environment) = an_environment();
        let id = environment.environment_id;
        let came = taken(Old::Generation(generation(1)));
        let mut record = Record {
            greeted: false,
            replied: false,
            last: Some(Last::NothingListens),
            whole: None,
            lock: Some(LockRead {
                lock: Lock::Free,
                named: None,
            }),
        };
        let nothing = failed_said(id, Some(&came), &record, true, None).to_string();
        assert!(
            nothing.contains("Paired devices cannot connect until a control daemon runs.")
                && nothing.contains("The requested daemon may still start."),
            "{nothing}"
        );
        record.last = Some(Last::NothingInTime);
        let silent = failed_said(id, Some(&came), &record, true, None).to_string();
        assert!(
            !silent.contains("cannot connect") && !silent.contains("answers now"),
            "{silent}"
        );
        assert!(
            silent.contains("Paired devices' connections to the old daemon closed"),
            "{silent}"
        );
        record.greeted = true;
        record.last = Some(Last::Greeting(None));
        let greeted = failed_said(id, Some(&came), &record, true, None).to_string();
        assert!(
            greeted.contains("No control daemon gave a whole answer within 30 seconds.")
                && !greeted.contains("may still start")
                && !greeted.contains("No control daemon answered"),
            "{greeted}"
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

    /// The daemon's side of one greeting at the environment's endpoint: accepts the next
    /// connection, reads its hello and answers it, and keeps the connection open.
    #[cfg(windows)]
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

    /// What the restart did before the reads, the start's own words and what it launched, under a
    /// name.
    type Shape = (
        &'static str,
        Option<Came>,
        Option<&'static str>,
        Option<Started>,
    );

    /// The shapes of a result that the table of the words covers: what the restart did before, the
    /// start's own words where the start failed, and what this command launched.
    fn shapes() -> Vec<Shape> {
        let old = Old::Generation(generation(1));
        let successor = Came::Stopped(Stopped {
            successor: Some(Some(3)),
            ..match taken(old) {
                Came::Stopped(stopped) => stopped,
                Came::NoneRan | Came::HolderLetGo { .. } => unreachable!("a stop"),
            }
        });
        let words = Some("the start's own words");
        let managed = Started {
            pid: Some(88),
            start: ControllerStartup::Service,
            manager: Some(crate::service_manager::Manager::Systemd),
        };
        vec![
            ("holder wait", None, None, None),
            (
                "stopped, no start words",
                Some(taken(old)),
                None,
                Some(standalone(77)),
            ),
            (
                "stopped, start words",
                Some(taken(old)),
                words,
                Some(standalone(77)),
            ),
            ("stopped, nothing started", Some(taken(old)), None, None),
            (
                "stopped, manager asked",
                Some(taken(old)),
                None,
                Some(managed),
            ),
            (
                "stopped, generation unread",
                Some(taken(Old::Unread)),
                None,
                Some(standalone(77)),
            ),
            ("stopped, successor", Some(successor), None, None),
            ("none ran", Some(Came::NoneRan), words, Some(standalone(77))),
            (
                "none ran, no start words",
                Some(Came::NoneRan),
                None,
                Some(standalone(77)),
            ),
            (
                "holder let go, a read gave",
                Some(Came::HolderLetGo { read: true }),
                None,
                Some(standalone(77)),
            ),
            (
                "holder let go, no read gave",
                Some(Came::HolderLetGo { read: false }),
                None,
                Some(standalone(77)),
            ),
        ]
    }

    /// The whole text and the `--json` members that the product's makers write for a record, in a
    /// shape. The environment is written as `E`.
    ///
    /// The failure's maker writes a row for every record of every shape, and the success's maker
    /// one only where the shape has no start words of its own and the generation test holds: the
    /// two decisions that the command's reporting makes. A failure whose final read finds a daemon
    /// of another generation is a row of its own, labelled with that.
    fn words_of(
        shape: &Shape,
        record: &Record,
        id: EnvironmentId,
    ) -> Vec<(String, String, String)> {
        use crate::host_stop::StartedFact;

        let (label, came, own, started) = shape;
        let own = own.map(Shown::said);
        let none = Answer { serving: None };
        let mut made = Vec::new();
        match came {
            None => {
                if let (Some(Last::Whole(_)), Some(whole)) = (record.last, record.whole) {
                    made.push((
                        (*label).to_owned(),
                        holder_answers_said(id, whole.process),
                        Answer {
                            serving: whole.process,
                        },
                        Launched::Nothing,
                    ));
                } else {
                    made.push((
                        (*label).to_owned(),
                        failed_said(id, None, record, false, None),
                        none,
                        Launched::Nothing,
                    ));
                }
            }
            Some(came) => {
                let succeeds =
                    own.is_none() && proof::answers_as_another_daemon(record, came.old());
                if succeeds {
                    made.push((
                        (*label).to_owned(),
                        succeeded_said(id, came, record, started.as_ref(), Shown::said("")),
                        answer_of(record),
                        launched_of(started.as_ref()),
                    ));
                }
                let late = if succeeds {
                    format!("{label}, late answer after a failed start")
                } else {
                    (*label).to_owned()
                };
                // A failed start that made a start says its kind and no process. The kind here is
                // this table's own rule for the shape, not the product's own carrying of it
                // (`StartFailed::facts`): the member case of
                // `every_result_of_a_restart_says_what_it_started_or_asked_for` holds that
                // function, and the start-up target's two Linux cases hold it end to end.
                let asked = started.as_ref().map_or(Launched::Nothing, |started| {
                    Launched::Start(StartedFact {
                        pid: None,
                        ..started_fact(started)
                    })
                });
                made.push((
                    late,
                    failed_said(id, Some(came), record, started.is_some(), own.as_ref()),
                    none,
                    asked,
                ));
            }
        }
        made.into_iter()
            .map(|(label, text, answer, launched)| {
                // The frozen file holds the Unix word of a start with no manager: the task's word
                // for it is put back to it.
                let launched = launched.parts().map(|(start, pid)| {
                    let start = if cfg!(windows) && start == "task" {
                        "standalone"
                    } else {
                        start
                    };
                    serde_json::json!({"start": start, "pid": pid})
                });
                let json = serde_json::json!({"serving": answer.serving, "launched": launched});
                // The frozen file holds the Unix words: the platform's own words for the standalone
                // start, for the command that ends a process and for the advice where no process is
                // named are put back to them where they differ.
                let text = text
                    .to_string()
                    .replace(
                        &launched_said(Some(&standalone(77))).to_string(),
                        "This command started a control daemon (process 77) under the standalone start.",
                    )
                    .replace(crate::update::handover::STOP_COMMAND, "kill -KILL")
                    .replace(
                        &host_stop::how_to_end_the_process(None).to_string(),
                        "If it stays like this, end the process that holds the lock file.",
                    );
                (
                    label,
                    text.replace(&id.to_string(), "E"),
                    json.to_string(),
                )
            })
            .collect()
    }

    /// Phrases that claim whose start the daemon that answers is, or that its identity is proved: no
    /// text of the table holds one, since the command gives no verdict of ownership.
    const CLAIMS_OF_OWNERSHIP: &[&str] = &[
        "own start",
        "proved",
        "already serves",
        "is the one",
        "the daemon that this command started",
        "the daemon this command started",
        "started the daemon that answers",
        "this command's own",
    ];

    /// The second check of the table, beside the frozen file: no text holds a claim of ownership,
    /// and each present-tense phrase of a text is one that the record's last read allows, each
    /// phrase about the whole wait one that the reads of any kind allow, and each phrase about the
    /// lock one that the lock read after the last read allows.
    fn the_phrases_of_a_text_match_its_record(text: &str, came: Option<&Came>, record: &Record) {
        for claim in CLAIMS_OF_OWNERSHIP {
            assert!(!text.contains(claim), "{claim:?} is in a text: {text}");
        }
        let last = record.last;
        let held = matches!(record.lock.map(|read| read.lock), Some(Lock::Held));
        let greeted_or_replied = record.greeted || record.replied;
        let reads = matches!(last, Some(Last::Whole(_) | Last::Greeting(_) | Last::Reply));
        // The stopped generation's phrase is for a whole answer of that generation or an older one.
        let stopped = matches!(
            (last, came.map(Came::old)),
            (Some(Last::Whole(whole)), Some(Old::Generation(old))) if whole <= old
        );
        let phrases: [(&str, bool); 13] = [
            (
                " answers now.",
                matches!(last, Some(Last::Whole(_))) && record.whole.is_some(),
            ),
            (
                "of the generation that was asked to stop answers now.",
                stopped,
            ),
            (
                "No control daemon answers now: nothing listens.",
                matches!(last, Some(Last::NothingListens)),
            ),
            (
                "A control daemon gave a usable greeting and no whole answer.",
                matches!(last, Some(Last::Greeting(_))),
            ),
            (
                "A control daemon replied, and this command cannot use its reply.",
                matches!(last, Some(Last::Reply)),
            ),
            (
                "got no answer in time.",
                matches!(last, Some(Last::NothingInTime)),
            ),
            (
                "could not check whether a control daemon answers.",
                matches!(last, Some(Last::CheckFailed)),
            ),
            ("No control daemon answered within", !greeted_or_replied),
            (
                "No control daemon gave a whole answer within",
                greeted_or_replied && record.whole.is_none(),
            ),
            ("A control daemon holds environment", reads && held),
            ("The lock of environment E is held.", held),
            (
                "Paired devices cannot connect",
                came.is_some_and(Came::ended) && matches!(last, Some(Last::NothingListens)),
            ),
            (
                "Paired devices' connections to the old daemon closed",
                came.is_some_and(Came::ended),
            ),
        ];
        for (phrase, allowed) in phrases {
            assert!(
                !text.contains(phrase) || allowed,
                "{phrase:?} is said for a record that does not show it ({record:?}): {text}"
            );
        }
    }

    /// The table of the words: for each shape of a result and each record that up to three reads of
    /// the endpoint reach, the whole text and the `--json` members that the makers write, one row for
    /// each distinct pair with the number of records that give it. A new or changed word is a change
    /// of the frozen file, which a person accepts; `KR_WRITE_WORDS_TABLE=1` writes it (the case then
    /// fails once).
    #[test]
    fn the_table_of_the_words_is_the_file() {
        use std::collections::BTreeMap;
        use std::fmt::Write as _;

        let id = EnvironmentId::new(kr_ipc::new_uuid());
        let records = super::record::tests::every_record_that_up_to_three_reads_reach();
        let mut rows: BTreeMap<(String, String, String), usize> = BTreeMap::new();
        let mut texts = Vec::new();
        for shape in &shapes() {
            for record in &records {
                for (label, text, json) in words_of(shape, record, id) {
                    texts.push((shape.1.clone(), *record, text.clone()));
                    *rows.entry((label, text, json)).or_default() += 1;
                }
            }
        }
        let mut table = String::new();
        for ((shape, text, json), states) in &rows {
            let _ = write!(
                table,
                "shape: {shape}\nstates: {states}\ntext: {text}\njson: {json}\n\n"
            );
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/host_restart_words.txt");
        if std::env::var_os("KR_WRITE_WORDS_TABLE").is_some() {
            std::fs::write(path, &table).expect("writes the table of the words");
            panic!("wrote the table of the words to {path}");
        }
        assert!(
            table == include_str!("../tests/host_restart_words.txt"),
            "the words changed: rerun with KR_WRITE_WORDS_TABLE=1 and read the file's diff"
        );
        // The second check follows the frozen file's, so that a changed word fails on the file.
        for (came, record, text) in &texts {
            the_phrases_of_a_text_match_its_record(text, came.as_ref(), record);
        }
    }
}
