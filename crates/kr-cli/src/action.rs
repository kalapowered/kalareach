//! `kr action`: what the host recorded of one action.
//!
//! `kr action read` shows the receipt a host retains for an action: the method, the state it
//! stands in and the revision of that state. An action whose outcome the host could not establish
//! is shown as exactly that, with the failure the host recorded for it, because the earlier result
//! of an uncertain action is what a later request for the same thing has to be made in sight of.
//!
//! Where the receipt is kept decides how it is read:
//!
//! * An action a live session performed is kept by that session's worker, which this command asks
//!   directly, as `kr` asks a worker for everything a session owns.
//! * An action a closed session performed is kept in the environment's archive, which the control
//!   daemon serves.
//! * An action the host performed itself, such as a catalogue or plugin change, names no session
//!   and is kept by the control daemon. Other actions the daemon performs are not served by this
//!   read yet.
//!
//! The command changes no receipt. A worker does note, for the caller, the revision it answered
//! with, because that is how it knows what the caller has seen when a later request names the
//! action; the daemon and the archive note nothing.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, Receipt, ReceiptState};

use crate::cli::{ActionCommand, ActionReadArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::report::Completion;
use crate::resolve::{Registered, SessionSelector};
use crate::stdout_line;

/// Runs one `kr action` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the host's or the worker's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: ActionCommand, json: bool) -> Result<Completion> {
    match command {
        ActionCommand::Read(arguments) => read(paths, &arguments, json)
            .await
            .map(|()| Completion::Done),
    }
}

/// Who keeps the receipt that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kept {
    /// A live session's worker.
    Worker,
    /// The environment's archive of a closed session.
    Archive,
    /// The control daemon, for an action it performed itself.
    Daemon,
}

/// `kr action read`.
async fn read(paths: &HostPaths, arguments: &ActionReadArguments, json: bool) -> Result<()> {
    let action_id: ActionId = identifier(&arguments.action, "an action")?;
    let (read, kept) = match &arguments.session {
        None => (
            host_receipt(paths, arguments, action_id).await?,
            Kept::Daemon,
        ),
        Some(session) => session_receipt(paths, arguments, session, action_id).await?,
    };
    if json {
        output::document(&receipt_document(&read));
    } else {
        output::lines(&receipt_lines(&read, kept));
    }
    Ok(())
}

/// The receipt of an action the control daemon itself performed.
async fn host_receipt(
    paths: &HostPaths,
    arguments: &ActionReadArguments,
    action_id: ActionId,
) -> Result<ActionReadResult> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    daemon
        .read(
            Method::ActionRead,
            &ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await
}

/// The receipt of an action a session performed: from its worker while the session is live, from
/// the environment's archive once it has closed.
///
/// A session is looked for in every environment of this host unless `--environment` names one, as
/// `kr close` looks, so a display number two environments use is ambiguous rather than answered
/// from the first.
async fn session_receipt(
    paths: &HostPaths,
    arguments: &ActionReadArguments,
    session: &str,
    action_id: ActionId,
) -> Result<(ActionReadResult, Kept)> {
    let selector = SessionSelector::parse(session)?;
    let wanted = arguments
        .selector
        .environment
        .as_deref()
        .map(|text| {
            text.parse::<EnvironmentId>().map_err(|_| {
                CliError::Usage(Shown::said(
                    "the text given is not an environment identifier",
                ))
            })
        })
        .transpose()?;
    match crate::resolve::find(paths, &selector, wanted) {
        Ok((_, descriptor)) => {
            let mut worker = crate::resolve::open_worker(&descriptor, crate::build_id()).await?;
            let outcome = worker
                .request(
                    Method::ActionRead,
                    &ActionReadParams {
                        action_id,
                        session_id: None,
                    },
                )
                .await?;
            Ok((answered(outcome)?, Kept::Worker))
        }
        Err(CliError::UnknownSession(_)) => Ok((
            archived_receipt(paths, arguments, &selector, action_id).await?,
            Kept::Archive,
        )),
        Err(error) => Err(error),
    }
}

/// The receipt a closed session's archive keeps.
async fn archived_receipt(
    paths: &HostPaths,
    arguments: &ActionReadArguments,
    selector: &SessionSelector,
    action_id: ActionId,
) -> Result<ActionReadResult> {
    // The daemon that keeps a closed session is its environment's: the one `--environment` names,
    // or this installation's own, as `kr close` and `kr status` ask.
    let session_id: SessionId = match crate::resolve::registered(
        paths,
        selector,
        arguments.selector.environment.as_deref(),
    )
    .await?
    {
        Registered::Closed { session_id, .. } => session_id,
        Registered::Unpublished { session_id, state } => {
            return Err(CliError::refused_in_its_own_words(
                ErrorCode::ResourceUnavailable,
                shown!(
                    "session {} is {} and has no worker to ask yet, so its receipts cannot be \
                     read",
                    session_id,
                    state
                ),
            ));
        }
    };
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    daemon
        .read(
            Method::ActionRead,
            &ActionReadParams {
                action_id,
                session_id: Some(session_id),
            },
        )
        .await
}

/// A worker's answer to the read, as the receipt it holds or the refusal it gave.
fn answered(
    outcome: std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError>,
) -> Result<ActionReadResult> {
    match outcome {
        Ok(value) => value.to_typed().map_err(|error| {
            CliError::Other(shown!(
                "the worker's answer could not be read: {}",
                Shown::cbor(&error)
            ))
        }),
        Err(refusal) => Err(CliError::Refused(refusal)),
    }
}

/// Whether the host could not establish what became of the action.
///
/// The receipt is in the state the contract keeps for dispatch that may have happened, or it ended
/// in a failure recorded as an unknown outcome.
fn outcome_unknown(receipt: &Receipt) -> bool {
    receipt.state == ReceiptState::Unknown
        || receipt
            .error
            .as_ref()
            .is_some_and(|error| error.code == ErrorCode::OutcomeUnknown)
}

/// A receipt, as lines for a person.
///
/// Only a live session's worker holds a later request to the rule that it names the uncertain
/// outcome it replaces, and it applies the rule to the newest uncertain outcome of a subject, so
/// only a receipt read from a worker is told what a later request has to name.
fn receipt_lines(read: &ActionReadResult, kept: Kept) -> Vec<Line> {
    let receipt = &read.receipt;
    let mut lines = vec![stdout_line!(
        "Action {}: {} is {}, at revision {}.",
        receipt.action_id,
        Asked::text(Request::Actions, receipt.method.as_str()),
        crate::output::closed_word(&receipt.state),
        receipt.revision
    )];
    if outcome_unknown(receipt) {
        lines.push(stdout_line!(
            "The host could not establish whether it was performed, and it never sends it again \
             under this identifier."
        ));
        if kept == Kept::Worker {
            lines.push(stdout_line!(
                "If this is the latest uncertain outcome of its subject, a later request for the \
                 same thing is a new action that has to name this one at revision {}.",
                receipt.revision
            ));
        }
    }
    if let Some(error) = receipt.error.as_ref() {
        lines.push(stdout_line!(
            "It failed with {}: {}",
            error.code,
            Asked::text(Request::Actions, &crate::share::visibly(&error.message))
        ));
    }
    lines.push(if read.result.as_ref().is_some() {
        stdout_line!("The result it produced is retained.")
    } else {
        stdout_line!("No result is retained for it.")
    });
    lines
}

/// A receipt, for a script, in the shape the protocol answers it: the method and the failure's
/// message are what the host recorded, and the rest is words of the protocol's closed sets.
fn receipt_document(read: &ActionReadResult) -> Document {
    let receipt = &read.receipt;
    Document::new()
        .with("action_id", closed(&receipt.action_id))
        .with(
            "method",
            Asked::text(Request::Actions, receipt.method.as_str()),
        )
        .with("revision", closed(&receipt.revision))
        .with("state", closed(&receipt.state))
        .with("outcome_unknown", outcome_unknown(receipt))
        .with(
            "error_code",
            receipt
                .error
                .as_ref()
                .map(|error| output::said(&error.code)),
        )
        .with(
            "error_message",
            receipt
                .error
                .as_ref()
                .map(|error| Asked::text(Request::Actions, &error.message)),
        )
        .with("result_retained", read.result.as_ref().is_some())
        .with("ok", true)
}
