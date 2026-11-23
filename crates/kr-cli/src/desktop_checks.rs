//! `kr host desktop-checks`: running the disclosed desktop checks and showing what each found.
//!
//! The checks take a screen image and start an application, so the host never performs them on a
//! read: a person asks, here, and the control daemon has the worker of one of the host's sessions
//! perform them, because a platform files what they need under the program that asks and the
//! worker is the context an agent runs in. This command asks, waits for the run to end for a
//! bounded time, and prints the records the way `kr doctor` does, so one renderer says what each
//! check found wherever a person reads it.
//!
//! `--file` names the file the read check reads. A path relative to the directory the command runs
//! in is made absolute here, because the host reads it from a worker that runs elsewhere. Without
//! the option the read check reads nothing and says so.

use std::path::Path;
use std::time::{Duration, Instant};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::desktop::{
    CapabilityChecks, CapabilityChecksFailure, CapabilityChecksState,
    EnvironmentCapabilitiesCheckParams, EnvironmentCapabilitiesParams,
    EnvironmentCapabilitiesResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::DesktopChecksArguments;
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Document, closed};
use crate::report::{self, Completion};
use crate::stdout_line;

/// How long the command waits for a run to end. The setup page says a run takes about two
/// minutes, most of it a person answering a platform's question.
const WAIT: Duration = Duration::from_secs(300);

/// How often the daemon is asked where the run stands.
const POLL: Duration = Duration::from_millis(500);

/// Runs `kr host desktop-checks` and prints what the checks found.
///
/// # Errors
///
/// Returns a usage error for a path that is not text, the daemon's refusal of the request, or a
/// transport failure. A run that ends without findings is reported as a failure that has already
/// been written.
pub async fn run(
    paths: &HostPaths,
    arguments: &DesktopChecksArguments,
    json: bool,
) -> Result<Completion> {
    let authorised_file = arguments.file.as_deref().map(named).transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let environment_id = daemon.environment_id();
    let begun: CapabilityChecks = daemon
        .mutate(
            Method::EnvironmentCapabilitiesCheck,
            &EnvironmentCapabilitiesCheckParams {
                environment_id,
                authorised_file: Nullable(authorised_file),
            },
        )
        .await?;
    if begun.state == CapabilityChecksState::Running && !json {
        // Only macOS asks the person at the machine for permission while the checks run.
        report::say(&if cfg!(target_os = "macos") {
            shown!(
                "The checks are running in a session's worker. macOS may ask you to allow \
                 something while they do, and they can take about two minutes."
            )
        } else {
            shown!(
                "The checks are running in a session's worker, and they can take about two minutes."
            )
        });
    }
    let started = Instant::now();
    let result = loop {
        let result: EnvironmentCapabilitiesResult = daemon
            .read(
                Method::EnvironmentCapabilities,
                &EnvironmentCapabilitiesParams { environment_id },
            )
            .await?;
        if result.checks.state != CapabilityChecksState::Running || started.elapsed() >= WAIT {
            break result;
        }
        tokio::time::sleep(POLL).await;
    };
    let unfinished = unfinished(&result.checks).map(|message| CliError::Unfinished {
        code: ErrorCode::ResourceUnavailable,
        message,
    });
    match (&unfinished, json) {
        (None, true) => output::document(&document(&result)),
        (Some(error), true) => output::document(&report::with_failure(document(&result), error)),
        (None, false) => {
            output::line(&stdout_line!("Disclosed desktop checks"));
            output::lines(&report::capability_lines(&result.desktop));
        }
        (Some(error), false) => report::failed(error),
    }
    Ok(unfinished.map_or(Completion::Done, Completion::Reported))
}

/// The path the host is asked to read: absolute, and text, which the request carries it as.
fn named(file: &Path) -> Result<String> {
    let absolute = std::path::absolute(file).map_err(|error| {
        CliError::Usage(shown!(
            "the directory this command runs in cannot be read, so a relative path cannot be \
             made absolute: {}",
            Shown::io(&error)
        ))
    })?;
    absolute.to_str().map(str::to_owned).ok_or_else(|| {
        CliError::Usage(shown!(
            "that path is not text, so the host cannot be asked to read it"
        ))
    })
}

/// What the command prints with `--json`: where the run stands, and the records the host holds.
fn document(result: &EnvironmentCapabilitiesResult) -> Document {
    let checks = &result.checks;
    Document::new()
        .with(
            "checks",
            Document::new()
                .with("state", closed(&checks.state))
                .with("failure", closed(&checks.failure))
                .with("started_at_ms", closed(&checks.started_at_ms))
                .with("finished_at_ms", closed(&checks.finished_at_ms))
                .with("session_id", closed(&checks.session_id)),
        )
        .with("desktop", report::desktop_capabilities(&result.desktop))
}

/// What a run that has not given findings says, or nothing where it has.
///
/// The words of a run that failed are the setup page's, with this program in place of the
/// application: a person reads one account of a failure wherever the checks are run.
fn unfinished(checks: &CapabilityChecks) -> Option<Shown> {
    match checks.state {
        CapabilityChecksState::Current => None,
        CapabilityChecksState::Running => Some(shown!(
            "The checks are still running after five minutes. They go on in the session's \
             worker, and kr doctor shows what they found once they end."
        )),
        CapabilityChecksState::NotRun => Some(shown!(
            "The host holds no run of the checks, so nothing was checked. Run the command again."
        )),
        CapabilityChecksState::Stale => Some(shown!(
            "The checks were run before something changed. Run them again."
        )),
        CapabilityChecksState::Failed => Some(match checks.failure.as_ref() {
            Some(CapabilityChecksFailure::NoSession) => shown!(
                "No session of the kind this host creates is running. The checks run inside a \
                 session's own worker, which is the place an agent runs, so start a session and \
                 run them again."
            ),
            Some(CapabilityChecksFailure::WorkerRefused) => shown!(
                "The session's worker answered with an error: it was already performing a run, \
                 could not start one, or its run did not finish. Run the checks again."
            ),
            Some(CapabilityChecksFailure::WorkerUnreachable) => shown!(
                "The session's worker did not answer in time, or could not be reached. Run the \
                 checks again."
            ),
            Some(CapabilityChecksFailure::WorkerFailed) => shown!(
                "The session's worker answered with something this program cannot use. Run the \
                 checks again."
            ),
            None => shown!(
                "The latest run ended without a result, and the host gave no reason. Run the \
                 checks again."
            ),
        }),
    }
}
