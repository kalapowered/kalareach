//! A mutation whose outcome the host did not establish, as the command that sent it says so.
//!
//! A command sends each mutation once, under an identifier it makes for that intent. When the
//! connection ends after the request may have been written, the host's answer cannot be read, or the
//! host answers that it cannot say what became of the action, the command does not know whether the
//! action was performed and does
//! not send it again, under that identifier or a new one: a later request is the person's, and has
//! to be made in sight of the earlier result. So the command ends with `OUTCOME_UNKNOWN`, names the
//! action and says where the person reads what the host holds of it. [`earlier`] is the person's
//! later request: it reads the earlier action's receipt from the worker that keeps it, shows it, and
//! returns what the new request names. A plain run again is refused by the worker while the earlier
//! outcome stands, and [`Unknown::refused`] adds to that refusal the command that makes the later
//! request.

use kr_client::answers::{self, Quote};
use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_ipc::client::LocalClient;
use kr_ipc::error::IpcError;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::ActionId;
use kr_protocol::method::{Method, MethodName};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptState};

use crate::error::{CliError, Result};

/// How a worker's refusal of a request that names no earlier action words itself when an earlier
/// action of the same subject has an uncertain outcome: that action's identifier stands just before.
const STANDS: &str = " for this subject has an uncertain outcome";

/// What a command says when one of its mutations ended with an outcome nobody established.
pub struct Unknown {
    /// What the mutation was, as a phrase that follows "performed": "the close".
    pub what: &'static str,
    /// Where the person reads what the host holds of the action.
    pub read_back: ReadBack,
    /// The later request for the same thing, where the command has one.
    pub later: Option<Later>,
}

/// A command's later request, in the words a person is told it in.
pub struct Later {
    /// The command line that makes it, without its `--after-unknown` flag.
    pub command: Shown,
    /// What the command does where the host holds no receipt for the earlier action, which is to
    /// ask again, and what that costs. It is the command's own sentence, without its full stop.
    pub asks_again: Shown,
}

/// Where a person reads back what became of an action: the session whose worker keeps its receipt,
/// and the environment when it is not this installation's own.
pub struct ReadBack {
    session: Shown,
    environment: Option<Shown>,
}

impl ReadBack {
    /// The session `session` names, in the environment the command was given with `environment`.
    #[must_use]
    pub const fn of(session: Shown, environment: Option<Shown>) -> Self {
        Self {
            session,
            environment,
        }
    }

    /// The command that shows what the host holds of `action`.
    #[must_use]
    pub fn command(&self, action: ActionId) -> Shown {
        match &self.environment {
            Some(environment) => shown!(
                "kr action read {} --session {} --environment {}",
                action,
                self.session.clone(),
                environment.clone()
            ),
            None => shown!(
                "kr action read {} --session {}",
                action,
                self.session.clone()
            ),
        }
    }
}

/// Why the command does not know what became of its request.
pub enum Cause<'a> {
    /// The exchange with the host failed after the request was composed, and the request may have
    /// been written before it did.
    Connection,
    /// The host answered, and the answer could not be read.
    Unreadable,
    /// The host said that it cannot establish what became of the action.
    Host(&'a ProtocolError),
}

impl Unknown {
    /// What the command ends as: `OUTCOME_UNKNOWN`, naming the action, the command that reads it
    /// back and what a later request is.
    #[must_use]
    pub fn ended(&self, action: ActionId, cause: Cause<'_>) -> CliError {
        let cause = match cause {
            Cause::Connection => shown!(
                "the exchange with the host failed after the request for {} was composed, and the \
                 request may have reached the host, so whether it performed it is not known",
                self.what
            ),
            Cause::Unreadable => shown!(
                "the host answered the request for {} and its answer could not be read, so whether \
                 it performed it is not known",
                self.what
            ),
            Cause::Host(refusal) => shown!(
                "the host could not say whether it performed {} ({})",
                self.what,
                Shown::protocol(refusal)
            ),
        };
        let message = match &self.later {
            Some(later) => shown!(
                "{}. The request was made as action {} and is not sent again; `{}` shows what the \
                 host holds of it. If the host holds it with an unknown outcome, `{} \
                 --after-unknown {}` makes the later request that names it. If the host holds no \
                 receipt for it, {}.",
                cause,
                action,
                self.read_back.command(action),
                later.command.clone(),
                action,
                later.asks_again.clone()
            ),
            None => shown!(
                "{}. The request was made as action {} and is not sent again; `{}` shows what the \
                 host holds of it, and this command makes no later request",
                cause,
                action,
                self.read_back.command(action)
            ),
        };
        CliError::Unfinished {
            code: ErrorCode::OutcomeUnknown,
            message,
        }
    }

    /// What the command ends as when the host refused its request.
    ///
    /// A worker holds an uncertain outcome against every later request that does not name it, and
    /// its refusal names the action that stands. Where the command has a later request, the person
    /// is also told the command that makes it: the refusal alone does not say there is one.
    #[must_use]
    pub fn refused(&self, refusal: ProtocolError) -> CliError {
        let (Some(Later { command, .. }), Some(action)) = (&self.later, standing(&refusal)) else {
            return CliError::Refused(refusal);
        };
        CliError::refused_in_its_own_words(
            refusal.code,
            shown!(
                "{}\n`{}` shows what the host holds of it, and `{} --after-unknown {}` makes the \
                 later request that names it",
                Shown::protocol(&refusal),
                self.read_back.command(action),
                command.clone(),
                action
            ),
        )
    }
}

/// The action a worker's refusal says stands in the way of a request that names none.
fn standing(refusal: &ProtocolError) -> Option<ActionId> {
    let (before, _) = refusal.message.split_once(STANDS)?;
    before.rsplit(' ').next()?.parse().ok()
}

/// Calls a mutation on a worker or a daemon that a person's command made, once.
///
/// The request is composed first, which writes nothing, so a failure there is the connection's and
/// sent nothing. Once it is written, a connection that ends, an answer this command cannot read and
/// the host's own `OUTCOME_UNKNOWN` each mean the outcome is not known, and end the command as
/// [`Unknown::ended`] says, naming the action. A request the connection's level cannot carry is not
/// written, and is not an unknown outcome. `quote` is the earlier uncertain action a later request
/// names, when the person asked for one.
///
/// # Errors
///
/// Returns the host's refusal ([`Unknown::refused`]), a failure before anything was written, or the
/// unknown outcome.
pub async fn mutate_naming<P, T>(
    client: &mut LocalClient,
    method: Method,
    target: ActionTarget,
    params: &P,
    quote: Option<Quote>,
    unknown: &Unknown,
) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let mut mutation = client.compose(method, action_id, target, params).await?;
    mutation.expected = answers::supersession(quote).map_err(|error| {
        CliError::Other(shown!(
            "the earlier action could not be named in the request: {}",
            error
        ))
    })?;
    match client.repeat(&mutation).await {
        // A reply that cannot be read came after the request went out, so the action may have been
        // performed.
        Ok(Ok(value)) => value
            .to_typed()
            .map_err(|_| unknown.ended(action_id, Cause::Unreadable)),
        Ok(Err(refusal)) if refusal.code == ErrorCode::OutcomeUnknown => {
            Err(unknown.ended(action_id, Cause::Host(&refusal)))
        }
        Ok(Err(refusal)) => Err(unknown.refused(refusal)),
        Err(error @ IpcError::NotInLevel(_)) => Err(CliError::Ipc(error)),
        Err(_) => Err(unknown.ended(action_id, Cause::Connection)),
    }
}

/// What the command ends as when the worker refuses to show the receipt of the earlier action.
///
/// The refusal is shown as it always was. One that the worker gives to an argument it cannot use is
/// followed, where the command has a later request, by what the person does if the host holds no
/// receipt for the action. Only the refusal's code decides that: the worker words that refusal for
/// an action it has no receipt for, and also for other arguments it cannot use, and the sentence
/// says what holds if it is the first.
pub(crate) fn read_refused(
    refusal: ProtocolError,
    action: ActionId,
    what: &'static str,
    unknown: &Unknown,
) -> CliError {
    let Some(later) = &unknown.later else {
        return CliError::Refused(refusal);
    };
    if refusal.code != ErrorCode::InvalidArgument {
        return CliError::Refused(refusal);
    }
    let code = refusal.code;
    CliError::refused_in_its_own_words(
        code,
        shown!(
            "{}\nIf the host holds no receipt for action {}, there is nothing for a later {} to \
             name: {}.",
            CliError::Refused(refusal).said(),
            action,
            what,
            later.asks_again.clone()
        ),
    )
}

/// Reads the receipt of the earlier action a person names and shows it, which is also how the worker
/// comes to hold that this caller was shown it at that revision, and returns what a later request
/// for the same thing names.
///
/// `client` is a connection to the worker that keeps the receipt, `method` the method the earlier
/// action was made with, and `what` that mutation as a noun ("close").
///
/// # Errors
///
/// Returns a usage failure when the action is not a request for `method` whose outcome the worker
/// could not establish, when its receipt could not be shown on standard error (nothing is sent: a
/// later request names a result the person was shown), and the worker's refusal when it holds no
/// such action. A refusal that says an argument cannot be used is shown with one sentence more,
/// where the command has a later request: if the host holds no receipt for the action there is
/// nothing to name, and the plain command asks again. The sentence is chosen by the refusal's code
/// and by nothing it says.
pub async fn earlier(
    client: &mut LocalClient,
    action: ActionId,
    method: Method,
    what: &'static str,
    unknown: &Unknown,
) -> Result<Quote> {
    let outcome = client
        .request(
            Method::ActionRead,
            &ActionReadParams {
                action_id: action,
                session_id: None,
            },
        )
        .await?;
    let value = outcome.map_err(|refusal| read_refused(refusal, action, what, unknown))?;
    let read: ActionReadResult = value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the worker's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })?;
    let receipt = read.receipt;
    if receipt.method != MethodName::from(method) {
        return Err(CliError::Usage(shown!(
            "action {} is not a {}, so a later {} cannot name it",
            action,
            what,
            what
        )));
    }
    if receipt.state != ReceiptState::Unknown {
        return Err(CliError::Usage(shown!(
            "action {} is {}, and not an outcome the worker could not establish, so nothing is \
             sent: a {} is not made again for it",
            action,
            crate::output::closed_word(&receipt.state),
            what
        )));
    }
    if !crate::report::shown_before_going_on(&shown!(
        "The earlier {}, action {}, stands at revision {} with an outcome the worker could not \
         establish. This sends a new action that names it.",
        what,
        action,
        receipt.revision
    )) {
        return Err(CliError::Other(shown!(
            "the earlier {}, action {}, could not be shown on standard error, so nothing is sent: \
             a later {} names a result the person was shown",
            what,
            action,
            what
        )));
    }
    Ok(Quote {
        action_id: action,
        revision: receipt.revision.get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn action() -> ActionId {
        ActionId::new(Uuid::from_bytes([7; 16]))
    }

    fn cancelling() -> Unknown {
        let command = shown!("kr question cancel 11");
        Unknown {
            what: "the cancellation",
            read_back: ReadBack::of(shown!("5"), None),
            later: Some(Later {
                asks_again: shown!("`{}` asks again", command),
                command,
            }),
        }
    }

    fn refusal(code: ErrorCode, message: Shown) -> ProtocolError {
        kr_client::error::refusal(code, message)
    }

    /// A command with a later request tells the person what the host holds, what each state calls
    /// for, and what the command does where the host holds nothing.
    #[test]
    fn an_unknown_outcome_tells_what_the_host_holds_and_what_each_state_calls_for() {
        let CliError::Unfinished { message, .. } = cancelling().ended(action(), Cause::Connection)
        else {
            panic!("an unknown outcome ends as unfinished");
        };
        assert_eq!(
            message.as_str(),
            format!(
                "the exchange with the host failed after the request for the cancellation was \
                 composed, and the request may have reached the host, so whether it performed it \
                 is not known. The request was made as action {a} and is not sent again; \
                 `kr action read {a} --session 5` shows what the host holds of it. If the host \
                 holds it with an unknown outcome, `kr question cancel 11 --after-unknown {a}` \
                 makes the later request that names it. If the host holds no receipt for it, \
                 `kr question cancel 11` asks again.",
                a = action()
            )
        );
    }

    /// A command with no later request keeps the words it had.
    #[test]
    fn a_command_with_no_later_request_keeps_its_words() {
        let mut unknown = cancelling();
        unknown.later = None;
        let CliError::Unfinished { message, .. } = unknown.ended(action(), Cause::Unreadable)
        else {
            panic!("an unknown outcome ends as unfinished");
        };
        assert_eq!(
            message.as_str(),
            format!(
                "the host answered the request for the cancellation and its answer could not be \
                 read, so whether it performed it is not known. The request was made as action \
                 {a} and is not sent again; `kr action read {a} --session 5` shows what the host \
                 holds of it, and this command makes no later request",
                a = action()
            )
        );
    }

    /// The refusal of an argument the worker cannot use is shown as it was, and one sentence says
    /// what holds if the host has no receipt for the action.
    #[test]
    fn a_refusal_of_an_argument_adds_what_holds_where_the_host_has_no_receipt() {
        let worker = refusal(
            ErrorCode::InvalidArgument,
            shown!("no receipt for action {}", action()),
        );
        let today = CliError::Refused(worker.clone()).said();
        let said = read_refused(worker, action(), "cancellation", &cancelling()).said();
        assert_eq!(
            said.as_str(),
            format!(
                "{today}\nIf the host holds no receipt for action {a}, there is nothing for a \
                 later cancellation to name: `kr question cancel 11` asks again.",
                a = action()
            )
        );
    }

    /// A refusal with any other code is shown as it was, and so is any refusal where the command has
    /// no later request.
    #[test]
    fn a_refusal_with_another_code_is_shown_as_it_was() {
        for code in [
            ErrorCode::PermissionDenied,
            ErrorCode::UnknownSession,
            ErrorCode::OutcomeUnknown,
        ] {
            let worker = refusal(code, Shown::said("the worker would not say"));
            let said = read_refused(worker.clone(), action(), "cancellation", &cancelling()).said();
            assert_eq!(said.as_str(), CliError::Refused(worker).said().as_str());
        }
        let worker = refusal(
            ErrorCode::InvalidArgument,
            Shown::said("no receipt for action"),
        );
        let mut unknown = cancelling();
        unknown.later = None;
        let said = read_refused(worker.clone(), action(), "cancellation", &unknown).said();
        assert_eq!(said.as_str(), CliError::Refused(worker).said().as_str());
    }
}
