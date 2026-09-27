//! `kr privacy`: turning this environment's privacy mode on and off, and reading where it stands.
//!
//! All three go through the control daemon under this user's own authority on this host. Turning
//! privacy mode on records a new privacy generation before anything else happens, and the answer
//! says whether the cleanup it asks for has finished: until it has, the command prints what is
//! still owed and fails, as a revocation still pending does, and `kr privacy status` reports how
//! far it has got. Turning it off is refused while cleanup is owed. `status` changes nothing.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyDisabled, PrivacyOutstanding, PrivacyReport, PrivacySession,
    PrivacySessionStanding, PrivacySetParams, PrivacyStatusParams, PrivacyUnavailable,
};

use crate::cli::{EnvironmentSelector, PrivacyCommand};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::report::{self, Completion};
use crate::stdout_line;

/// Runs one `kr privacy` command and prints its result.
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: PrivacyCommand, json: bool) -> Result<Completion> {
    match command {
        PrivacyCommand::On(arguments) => set(paths, &arguments.selector, true, json).await,
        PrivacyCommand::Off(arguments) => set(paths, &arguments.selector, false, json).await,
        PrivacyCommand::Status(arguments) => status(paths, &arguments.selector, json)
            .await
            .map(|()| Completion::Done),
    }
}

/// `kr privacy on` and `kr privacy off`.
async fn set(
    paths: &HostPaths,
    selector: &EnvironmentSelector,
    enabled: bool,
    json: bool,
) -> Result<Completion> {
    let mut daemon = Daemon::open(paths, selector).await?;
    let report: PrivacyReport = daemon
        .mutate(Method::PrivacySet, &PrivacySetParams { enabled })
        .await?;
    let unfinished = unfinished(&report);
    match (&unfinished, json) {
        (None, true) => output::document(&document(&report)),
        (Some(error), true) => {
            output::document(&report::with_failure(document(&report), error));
        }
        (None, false) => output::lines(&lines(&report)),
        (Some(error), false) => {
            output::lines(&lines(&report));
            report::failed(error);
        }
    }
    Ok(unfinished.map_or(Completion::Done, Completion::Reported))
}

/// `kr privacy status`.
async fn status(paths: &HostPaths, selector: &EnvironmentSelector, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, selector).await?;
    let report: PrivacyReport = daemon
        .read(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await?;
    if json {
        output::document(&document(&report));
    } else {
        output::lines(&lines(&report));
    }
    Ok(())
}

/// The failure a change that has not finished taking effect is reported as, or none once it has.
fn unfinished(report: &PrivacyReport) -> Option<CliError> {
    let state = if report.enabled { "on" } else { "off" };
    match &report.completion {
        PrivacyCompletion::Complete => None,
        PrivacyCompletion::Reconciling { .. } => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "privacy mode is {} at generation {} and the change is still taking effect; kr \
                 privacy status reports how far it has got",
                state,
                report.generation
            ),
        }),
        PrivacyCompletion::Unavailable { .. } => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "privacy mode is {} at generation {}, and something is in the way of the change \
                 taking effect; kr privacy status says what",
                state,
                report.generation
            ),
        }),
    }
}

/// Where privacy mode stands, as lines for a person.
fn lines(report: &PrivacyReport) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "Privacy mode is {}, at generation {}, since {} ms.",
        if report.enabled { "on" } else { "off" },
        report.generation.get(),
        report.changed_at_ms.get()
    )];
    match &report.completion {
        PrivacyCompletion::Complete => {
            lines.push(stdout_line!("The change has taken effect."));
        }
        PrivacyCompletion::Reconciling { outstanding } => {
            lines.push(stdout_line!("The change is still taking effect:"));
            lines.extend(outstanding.iter().map(outstanding_line));
        }
        PrivacyCompletion::Unavailable {
            unavailable,
            outstanding,
        } => {
            lines.push(stdout_line!(
                "Something is in the way of the change taking effect:"
            ));
            lines.extend(unavailable.iter().map(unavailable_line));
            lines.extend(outstanding.iter().map(outstanding_line));
        }
    }
    if !report.disabled.is_empty() {
        lines.push(stdout_line!("Stopped while it is on:"));
        lines.extend(
            report
                .disabled
                .iter()
                .map(|disabled| stdout_line!("  {}", disabled_text(*disabled))),
        );
    }
    lines.extend(report.sessions.iter().map(session_line));
    if !report.kept.is_empty() {
        lines.push(stdout_line!("Kept:"));
        lines.extend(report.kept.iter().map(|kept| {
            stdout_line!(
                "  {}: {}",
                Asked::text(Request::Privacy, &kept.what),
                Asked::text(Request::Privacy, &kept.why)
            )
        }));
    }
    if !report.exported.is_empty() {
        lines.push(stdout_line!("Already left this host:"));
        lines.extend(report.exported.iter().map(|exported| {
            stdout_line!(
                "  {} {}, left at {} ms, {}",
                Asked::text(Request::Privacy, &exported.kind),
                Asked::text(Request::Privacy, &exported.reference),
                exported.left_at_ms.get(),
                if exported.deletable {
                    "this host can ask for its removal"
                } else {
                    "this host has no way to ask for its removal"
                }
            )
        }));
    }
    if !report.unlisted.is_empty() {
        lines.push(stdout_line!("What left this host could not all be listed:"));
        lines.extend(report.unlisted.iter().map(unavailable_line));
    }
    lines
}

/// One subsystem's outstanding work, as a line.
fn outstanding_line(outstanding: &PrivacyOutstanding) -> Line {
    stdout_line!(
        "  {}: {} outstanding",
        Asked::text(Request::Privacy, &outstanding.subsystem),
        outstanding.count.get()
    )
}

/// One subsystem that could not answer, as a line.
fn unavailable_line(unavailable: &PrivacyUnavailable) -> Line {
    stdout_line!(
        "  {}: {}",
        Asked::text(Request::Privacy, &unavailable.subsystem),
        Asked::text(Request::Privacy, &unavailable.reason)
    )
}

/// One session's own cleanup, as a line.
fn session_line(session: &PrivacySession) -> Line {
    match &session.standing {
        PrivacySessionStanding::AwaitingWorker => stdout_line!(
            "Session {} owes its cleanup for generation {}: its worker has not answered yet.",
            session.session_id,
            session.generation.get()
        ),
        PrivacySessionStanding::Reconciling { outstanding } => stdout_line!(
            "Session {} owes its cleanup for generation {}: {} outstanding.",
            session.session_id,
            session.generation.get(),
            outstanding.get()
        ),
        PrivacySessionStanding::Unavailable { reason } => stdout_line!(
            "Session {} owes its cleanup for generation {}: {}",
            session.session_id,
            session.generation.get(),
            Asked::text(Request::Privacy, reason)
        ),
        PrivacySessionStanding::WorkerEnded => stdout_line!(
            "Session {} owes its cleanup for generation {}: its worker ended first, and the \
             archive holds what it kept.",
            session.session_id,
            session.generation.get()
        ),
    }
}

/// What privacy mode stops, in words.
const fn disabled_text(disabled: PrivacyDisabled) -> &'static str {
    match disabled {
        PrivacyDisabled::ContentHistoryRetention => "keeping the content of session history",
        PrivacyDisabled::DescriptionInference => "generated session descriptions",
        PrivacyDisabled::Sync => "sync",
        PrivacyDisabled::Backup => "backup",
    }
}

/// Where privacy mode stands, for a script, in the shape the protocol answers it. Each subsystem's
/// name and each reason arrived from the host and is shown as what was asked for.
fn document(report: &PrivacyReport) -> Document {
    Document::new()
        .with("generation", closed(&report.generation))
        .with("enabled", report.enabled)
        .with("changed_at_ms", closed(&report.changed_at_ms))
        .with("completion", completion_document(&report.completion))
        .with(
            "sessions",
            report
                .sessions
                .iter()
                .map(session_document)
                .collect::<Vec<_>>(),
        )
        .with("disabled", closed(&report.disabled))
        .with(
            "kept",
            report
                .kept
                .iter()
                .map(|kept| {
                    Document::new()
                        .with("what", Asked::text(Request::Privacy, &kept.what))
                        .with("why", Asked::text(Request::Privacy, &kept.why))
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "exported",
            report
                .exported
                .iter()
                .map(|exported| {
                    Document::new()
                        .with("kind", Asked::text(Request::Privacy, &exported.kind))
                        .with(
                            "reference",
                            Asked::text(Request::Privacy, &exported.reference),
                        )
                        .with("left_at_ms", closed(&exported.left_at_ms))
                        .with("deletable", exported.deletable)
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "unlisted",
            report
                .unlisted
                .iter()
                .map(unavailable_document)
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// A completion, for a script.
fn completion_document(completion: &PrivacyCompletion) -> Document {
    match completion {
        PrivacyCompletion::Complete => Document::new().with("state", Shown::said("complete")),
        PrivacyCompletion::Reconciling { outstanding } => Document::new()
            .with("state", Shown::said("reconciling"))
            .with(
                "outstanding",
                outstanding
                    .iter()
                    .map(outstanding_document)
                    .collect::<Vec<_>>(),
            ),
        PrivacyCompletion::Unavailable {
            unavailable,
            outstanding,
        } => Document::new()
            .with("state", Shown::said("unavailable"))
            .with(
                "unavailable",
                unavailable
                    .iter()
                    .map(unavailable_document)
                    .collect::<Vec<_>>(),
            )
            .with(
                "outstanding",
                outstanding
                    .iter()
                    .map(outstanding_document)
                    .collect::<Vec<_>>(),
            ),
    }
}

/// One subsystem's outstanding work, for a script.
fn outstanding_document(outstanding: &PrivacyOutstanding) -> Document {
    Document::new()
        .with(
            "subsystem",
            Asked::text(Request::Privacy, &outstanding.subsystem),
        )
        .with("count", closed(&outstanding.count))
}

/// One subsystem that could not answer, for a script.
fn unavailable_document(unavailable: &PrivacyUnavailable) -> Document {
    Document::new()
        .with(
            "subsystem",
            Asked::text(Request::Privacy, &unavailable.subsystem),
        )
        .with("reason", Asked::text(Request::Privacy, &unavailable.reason))
}

/// One session's own cleanup, for a script.
fn session_document(session: &PrivacySession) -> Document {
    let standing = match &session.standing {
        PrivacySessionStanding::AwaitingWorker => {
            Document::new().with("state", Shown::said("awaiting_worker"))
        }
        PrivacySessionStanding::Reconciling { outstanding } => Document::new()
            .with("state", Shown::said("reconciling"))
            .with("outstanding", closed(outstanding)),
        PrivacySessionStanding::Unavailable { reason } => Document::new()
            .with("state", Shown::said("unavailable"))
            .with("reason", Asked::text(Request::Privacy, reason)),
        PrivacySessionStanding::WorkerEnded => {
            Document::new().with("state", Shown::said("worker_ended"))
        }
    };
    Document::new()
        .with("session_id", closed(&session.session_id))
        .with("generation", closed(&session.generation))
        .with("standing", standing)
}
