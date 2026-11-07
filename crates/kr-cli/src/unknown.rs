//! A mutation whose outcome the host did not establish, as the command that sent it says so.
//!
//! A command sends each mutation once, under an identifier it makes for that intent. When the
//! connection ends after the request may have been written, or the host answers that it cannot say
//! what became of the action, the command does not know whether the action was performed and does
//! not send it again, under that identifier or a new one: a later request is the person's, and has
//! to be made in sight of the earlier result. So the command ends with `OUTCOME_UNKNOWN`, names the
//! action and says where the person reads what the host holds of it.

use kr_client::answers::{self, Quote};
use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_ipc::error::IpcError;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;

use crate::error::{CliError, Result};

/// What a command says when one of its mutations ended with an outcome nobody established.
pub struct Unknown {
    /// What the mutation was, as a phrase that follows "performed": "the close".
    pub what: &'static str,
    /// Where the person reads what the host holds of the action.
    pub read_back: ReadBack,
    /// The command line that makes a later request for the same thing, without its
    /// `--after-unknown` flag, where the command has one.
    pub later: Option<Shown>,
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

impl Unknown {
    /// What the command ends as: `OUTCOME_UNKNOWN`, naming the action, the command that reads it
    /// back and what a later request is. `host_said` is the host's own refusal when it gave one;
    /// without it the connection ended.
    #[must_use]
    pub fn ended(&self, action: ActionId, host_said: Option<&ProtocolError>) -> CliError {
        let cause = match host_said {
            Some(refusal) => shown!(
                "the host could not say whether it performed {} ({})",
                self.what,
                Shown::protocol(refusal)
            ),
            None => shown!(
                "the connection ended after the request for {} was sent, so whether the host \
                 performed it is not known",
                self.what
            ),
        };
        let next = match &self.later {
            Some(command) => shown!(
                "`{} --after-unknown {}` makes the later request that names it",
                command.clone(),
                action
            ),
            None => Shown::said("a later request has to be made in sight of that result"),
        };
        CliError::Unfinished {
            code: ErrorCode::OutcomeUnknown,
            message: shown!(
                "{}. It was sent as action {} and is not sent again; `{}` shows what the host holds \
                 of it, and {}",
                cause,
                action,
                self.read_back.command(action),
                next
            ),
        }
    }
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
/// Returns the host's refusal, a failure before anything was written, or the unknown outcome.
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
        Ok(Ok(value)) => value.to_typed().map_err(|_| unknown.ended(action_id, None)),
        Ok(Err(refusal)) if refusal.code == ErrorCode::OutcomeUnknown => {
            Err(unknown.ended(action_id, Some(&refusal)))
        }
        Ok(Err(refusal)) => Err(CliError::Refused(refusal)),
        Err(error @ IpcError::NotInLevel(_)) => Err(CliError::Ipc(error)),
        Err(_) => Err(unknown.ended(action_id, None)),
    }
}
