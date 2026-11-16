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

/// A control daemon answers: asks how it was started, and refuses before it stops anything where
/// the start would not give what it has.
async fn restart_the_daemon(
    _host: &HostPaths,
    environment: &KnownEnvironment,
    start: ControllerStartup,
    daemon: Daemon,
    json: bool,
    progress: &Progress,
    begun: &Begun,
) -> Completion {
    let id = environment.environment_id;
    let Daemon {
        mut client, info, ..
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
    host_stop::failed(
        CliError::Other(Shown::said("kr host restart has no stop to make yet")),
        &begun.none,
        json,
    )
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
            let process = process_of(started.pid.map(u64::from));
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
                    process_of(serving),
                    host_stop::under_way_said(environment)
                ),
                &none,
                json,
                &begun.earlier,
            )
        }
        Err(failed) => failed.reported(environment, Stopped::Nothing, json, progress, &none),
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
pub(crate) enum Stopped {
    /// No daemon ran, and nothing was stopped.
    Nothing,
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
    fn reported(
        self,
        environment: &KnownEnvironment,
        stopped: Stopped,
        json: bool,
        progress: &Progress,
        facts: &Facts,
    ) -> Completion {
        let id = environment.environment_id;
        let _ = progress.with_marker(|marker| marker.start_failed());
        let own = self.error.said();
        let stop = match stopped {
            Stopped::Nothing => shown!(
                "No control daemon was running for environment {} and the start failed",
                id
            ),
        };
        let still = if self.launched {
            Shown::said(" The requested daemon may still start.")
        } else {
            Shown::said("")
        };
        let sessions = match stopped {
            Stopped::Nothing => Shown::said("Nothing was stopped."),
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

/// Starts a daemon as `kr new` does, and proves that the daemon that answers is the one this
/// command started: it is of a newer generation than the one that was stopped, and where the start
/// knows its process, that process holds the environment's lock. Where the start has no process to
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
    let unproved = |message: Shown| StartFailed {
        error: CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message,
        },
        launched: true,
    };
    let info = match tokio::time::timeout(
        startup::ANSWER_BOUND,
        host_stop::host_info(&mut client, &environment.paths),
    )
    .await
    {
        Ok(Ok(info)) => info,
        Ok(Err(error)) => {
            return Err(unproved(shown!(
                "a control daemon answered and its generation could not be read: {}",
                error.said()
            )));
        }
        Err(_) => {
            return Err(unproved(Shown::said(
                "a control daemon answered and did not state its generation in time",
            )));
        }
    };
    let holding = host_stop::lock_holder(&environment.paths);
    let holder = holding.as_ref().map(|holder| holder.pid.get());
    let Some(started) = started else {
        // The look found a daemon: another restart's, or a manager's.
        return Ok(Proved::Another(holder));
    };
    let newer = stopped.is_none_or(|old| info.generation > old);
    match (started.pid, holder) {
        (Some(pid), Some(_)) if newer && holds_the_environment(holding.as_ref(), pid) => {
            Ok(Proved::Ours(started))
        }
        // The child that was started lost the environment to another daemon, which answers.
        (Some(_), _) if newer => Ok(Proved::Another(holder)),
        (None, _) if newer => Ok(Proved::Ours(started)),
        _ => Err(unproved(Shown::said(
            "the control daemon that answers is of the generation that was told to stop",
        ))),
    }
}

/// Whether the process that holds the environment is the one that was started, or a child of it:
/// the daemon is the started process itself, except where the program that was started runs the
/// daemon as its own child.
fn holds_the_environment(
    holder: Option<&kr_protocol::identity::ProcessStartIdentity>,
    started: u32,
) -> bool {
    let Some(holder) = holder else {
        return false;
    };
    holder.pid.get() == u64::from(started)
        || matches!(
            kr_ipc::identity::read_process(holder),
            kr_ipc::identity::ProcessReading::Running(facts)
                if facts.parent.as_ref().is_some_and(|parent| parent.pid.get() == u64::from(started))
        )
}

/// ` (process N)` where the process is known, and nothing otherwise.
fn process_of(pid: Option<u64>) -> Shown {
    pid.map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid))
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
