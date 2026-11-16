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

use std::sync::atomic::{AtomicBool, Ordering};

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
    self, Asked, Begun, Daemon, Facts, Knows, Looked, Progress, Stage, StartedFact, Which,
};
use crate::report::Completion;
use crate::resolve::KnownEnvironment;
use crate::restart_launch;
use crate::startup::{self, Started, Unstartable};

/// Runs `kr host restart`.
///
/// # Errors
///
/// Returns the failures that are not the command's own result: this installation's environment
/// cannot be found.
pub async fn run(paths: &HostPaths, json: bool) -> Result<Completion> {
    host_stop::run_command(Which::Restart, paths, json).await
}

/// The command, from the guard to the proof of the daemon it started.
pub(crate) async fn restart(
    host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> Result<Completion> {
    let begun = match host_stop::begin(Which::Restart, environment, json, progress).await {
        Ok(begun) => begun,
        Err(ended) => return Ok(ended),
    };
    // Before anything is asked of a daemon: what the start needs is there, or nothing is stopped.
    let start = match startup::preflight(environment).await {
        Ok(start) => start,
        Err(unstartable) => {
            return Ok(host_stop::failed(
                not_startable(environment.environment_id, unstartable),
                &begun.none,
                json,
            ));
        }
    };
    Ok(
        match host_stop::look(Which::Restart, environment, json, &begun).await {
            Looked::Ended(ended) => ended,
            Looked::NoDaemon => {
                start_where_none_ran(host, environment, json, progress, &begun).await
            }
            Looked::Daemon(daemon) => {
                restart_the_daemon(host, environment, start, *daemon, json, progress, &begun).await
            }
        },
    )
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

/// A control daemon answers: asks how it was started, refuses before it stops anything where the
/// start would not give what it has, stops the daemon, and then starts one and proves it.
async fn restart_the_daemon(
    host: &HostPaths,
    environment: &KnownEnvironment,
    start: ControllerStartup,
    daemon: Daemon,
    json: bool,
    progress: &Progress,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    let Daemon {
        mut client,
        info,
        holder,
    } = daemon;
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
    let old = holder.clone();
    let daemon = Daemon {
        client,
        info,
        holder,
    };
    let stopped = match host_stop::ask_to_stop(
        Which::Restart,
        host,
        environment,
        daemon,
        json,
        progress,
        begun,
    )
    .await
    {
        Ok(stopped) => stopped,
        Err(reported) => return reported,
    };
    progress.enter(Stage::Ended);
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
        None => start_and_prove(host, environment, Some(stopped.generation), progress).await,
    };
    let creates = host_stop::creates_under_way(stopped.unsettled);
    match proved {
        Ok(Proved::Ours(started)) => {
            progress.remove_marker();
            let processes = match (stopped.named, started.pid) {
                (Some(old), Some(new)) => {
                    shown!(" (process {} ended, process {} started)", old, new)
                }
                (Some(old), None) => shown!(" (process {} ended)", old),
                (None, Some(new)) => shown!(" (process {} started)", new),
                (None, None) => Shown::said(""),
            };
            host_stop::done(
                &shown!(
                    "Restarted the control daemon for environment {}{} under the {} start. No \
                     session was stopped.{}",
                    id,
                    processes,
                    start_said(&started),
                    creates
                ),
                &Facts {
                    started: Some(Some(started_fact(&started))),
                    ..facts
                },
                json,
                &begun.earlier,
            )
        }
        Ok(Proved::Another(serving)) => {
            progress.remove_marker();
            host_stop::done(
                &shown!(
                    "Stopped the control daemon for environment {}{}; a control daemon already \
                     serves it{}. No session was stopped.{}",
                    id,
                    host_stop::process_said(stopped.named),
                    host_stop::process_said(serving),
                    creates
                ),
                &facts,
                json,
                &begun.earlier,
            )
        }
        Err(failed) => {
            failed
                .reported(
                    environment,
                    Had::Daemon(stopped.named),
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
        Ok(_) => Ok(Proved::Another(successor)),
        Err(last) => Err(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "A control daemon{} holds environment {} since the daemon that was stopped ended, \
                 and it did not answer within {} seconds: {}. No new daemon was started. Run kr \
                 host restart again once it answers.",
                host_stop::process_said(successor),
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
    let result = start_and_prove(host, environment, None, progress).await;
    match result {
        Ok(Proved::Ours(started)) => {
            progress.remove_marker();
            let process = host_stop::process_said(started.pid.map(u64::from));
            let under_way = host_stop::under_way_said(environment);
            host_stop::done(
                &shown!(
                    "No control daemon was running for environment {}. Started one{} under the {} \
                     start.{}",
                    id,
                    process,
                    start_said(&started),
                    under_way
                ),
                &Facts {
                    started: Some(Some(started_fact(&started))),
                    ..none
                },
                json,
                &begun.earlier,
            )
        }
        Ok(Proved::Another(serving)) => {
            progress.remove_marker();
            host_stop::done(
                &shown!(
                    "No control daemon was running for environment {}, and one serves it now{}. \
                     This command started none.{}",
                    id,
                    host_stop::process_said(serving),
                    host_stop::under_way_said(environment)
                ),
                &none,
                json,
                &begun.earlier,
            )
        }
        Err(failed) => {
            failed
                .reported(environment, Had::NoDaemon, json, progress, &none)
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
    /// environment, or something else started one. The process the lock file names, where it
    /// names one.
    Another(Option<u64>),
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
        let own = self.error.said();
        let stop = match had {
            Had::NoDaemon => shown!(
                "No control daemon was running for environment {} and the start failed",
                id
            ),
            Had::Daemon(pid) => shown!(
                "The control daemon for environment {}{} was stopped and the start failed",
                id,
                host_stop::process_said(pid)
            ),
        };
        let still = if self.launched {
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
        let message = shown!(
            "{}: {}.{} {} Fix the cause and run kr host restart again.",
            stop,
            own,
            still,
            sessions
        );
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

/// Reads, on the connection that answered, the daemon's generation and then its process. The
/// process comes from a request for the launch alone, which answers the daemon's process and stops
/// nothing.
async fn answering(
    client: &mut LocalClient,
    environment: &KnownEnvironment,
    progress: &Progress,
) -> std::result::Result<Answering, Shown> {
    let info = match tokio::time::timeout(
        startup::ANSWER_BOUND,
        host_stop::host_info(client, &environment.paths),
    )
    .await
    {
        Ok(Ok(info)) => info,
        Ok(Err(error)) => {
            return Err(shown!(
                "a control daemon answered and its generation could not be read: {}",
                error.said()
            ));
        }
        Err(_) => {
            return Err(Shown::said(
                "a control daemon answered and did not state its generation in time",
            ));
        }
    };
    let pid = match host_stop::ask(client, environment.environment_id, false, progress, true).await
    {
        Asked::Taken(result) => Some(result.pid.get()),
        Asked::Unknown(_) | Asked::Refused(_) | Asked::NotComposed { .. } => None,
    };
    Ok(Answering {
        generation: info.generation,
        pid,
    })
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
        return Ok(Proved::Another(answering.pid));
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
        (Some(_), Some(answered)) => Ok(Proved::Another(Some(answered))),
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
/// that is a named limit.
pub(crate) async fn start_and_prove(
    host: &HostPaths,
    environment: &KnownEnvironment,
    stopped: Option<ControllerGeneration>,
    progress: &Progress,
) -> std::result::Result<Proved, StartFailed> {
    let launched = AtomicBool::new(false);
    // Written before the start is asked for: a command that is killed from here on leaves the word
    // that it had asked.
    let _ = progress.with_marker(|marker| marker.starting());
    progress.enter(Stage::Starting);
    let (mut client, started) =
        match startup::open_or_start_telling(host, environment, &launched).await {
            Ok(found) => found,
            Err(error) => {
                return Err(StartFailed {
                    error,
                    launched: launched.load(Ordering::SeqCst),
                });
            }
        };
    let unproved = |message: Shown, launched: bool| StartFailed {
        error: CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message,
        },
        launched,
    };
    // A daemon answered, so there is no requested daemon that may still start.
    let answering = answering(&mut client, environment, progress)
        .await
        .map_err(|message| unproved(message, false))?;
    judge(started, stopped, &answering)
        .map_err(|message| unproved(Shown::said(message), started.is_some()))
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
pub(crate) fn interrupted(progress: &Progress, stage: Stage, json: bool) -> Completion {
    let id = progress.environment_id;
    // Whether a daemon was stopped before the start: the record names the one it stops.
    let stopped = progress
        .with_marker(|marker| marker.attempt().daemon.is_some())
        .unwrap_or(false);
    let (knows, said) = match stage {
        Stage::BeforeAsking => {
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
        Stage::Asked => (
            Knows::MaybeAsked,
            shown!(
                "kr host restart was interrupted while it asked the control daemon for environment \
                 {} to stop. The daemon may have taken the request and may still stop, and no new \
                 daemon was started; an interrupt does not cancel a stop. No session stops. Run kr \
                 host restart to be sure of the result.",
                id
            ),
        ),
        Stage::Refused => {
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
        Stage::Told => (
            Knows::Told,
            shown!(
                "The control daemon for environment {} was told to stop. kr host restart was \
                 interrupted before it asked for a new daemon, so none was started, and the old \
                 one may still be ending, after which no control daemon runs. No session stops. \
                 Run kr host restart to start one.",
                id
            ),
        ),
        Stage::Ended => (
            Knows::Ended,
            shown!(
                "The control daemon for environment {} ended. kr host restart was interrupted \
                 before it asked for a new daemon, so it started none, and none may be running. \
                 No session stops. Run kr host restart to start one.",
                id
            ),
        ),
        Stage::Starting => (
            if stopped {
                Knows::Ended
            } else {
                Knows::NotAsked
            },
            shown!(
                "kr host restart was interrupted after it asked for a new control daemon for \
                 environment {}, so one may be starting. No session stops. Run kr host restart to \
                 be sure.",
                id
            ),
        ),
    };
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
        assert!(matches!(proved, Ok(Proved::Another(Some(41)))));
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
            Ok(Proved::Another(Some(9)))
        ));
        assert!(matches!(
            proof(None, None, &answering(1, None)),
            Ok(Proved::Another(None))
        ));
    }

    /// With no daemon stopped (a start where none ran), any generation is new.
    #[test]
    fn where_none_was_stopped_any_generation_is_new() {
        let proved = proof(Some(started(Some(40))), None, &answering(1, Some(40)));
        assert!(matches!(proved, Ok(Proved::Ours(_))));
    }
}
