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

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;

use crate::error::{CliError, Result};
use crate::host_stop::{self, Facts, Knows, Progress, Stage, Which};
use crate::report::Completion;
use crate::resolve::KnownEnvironment;

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
    _host: &HostPaths,
    environment: &KnownEnvironment,
    json: bool,
    progress: &Progress,
) -> Result<Completion> {
    let begun = match host_stop::begin(Which::Restart, environment, json, progress).await {
        Ok(begun) => begun,
        Err(ended) => return Ok(ended),
    };
    Ok(
        match host_stop::look(Which::Restart, environment, json, &begun).await {
            host_stop::Looked::Ended(ended) => ended,
            host_stop::Looked::Daemon(_) | host_stop::Looked::NoDaemon => host_stop::failed(
                CliError::Other(Shown::said("kr host restart has no start to make yet")),
                &begun.none,
                json,
            ),
        },
    )
}

/// What an interrupt says in each stage of a restart.
pub(crate) fn interrupted(progress: &Progress, stage: Stage, json: bool) -> Completion {
    let id = progress.environment_id;
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
            Knows::Ended,
            shown!(
                "The control daemon for environment {} ended. kr host restart was interrupted \
                 after it asked for a new daemon, so one may be starting. No session stops. Run \
                 kr host restart to be sure.",
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
            ..Facts::none(progress.said_earlier())
        },
        json,
    )
}
