//! The subject a mutation names.
//!
//! Section 23 makes every mutation state the exact thing it applies to: the environment, and where
//! the effect has them, the session and its epoch, the foreground application instance and its
//! agent binding revision. A host refuses a mutation whose target does not name what the request
//! is about, so this is not bookkeeping: it is the difference between an action that applies and
//! one the controller rejects.
//!
//! The interface supplies the subject because the interface is what read it. It saw the session in
//! a list the host sent, with the epoch on it; the environment is not the page's to choose and
//! comes from the connection's own handshake.

use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::scalars::Nullable;
use serde::Deserialize;

use crate::error::{CommandError, Result};

/// What the interface says a mutation is about.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Subject {
    /// The session, as the host reported it.
    pub session_id: Option<String>,
    /// That session's epoch, as the host reported it beside the identifier.
    pub session_epoch: Option<String>,
    /// The foreground application instance, when the effect has one.
    pub application_instance_id: Option<String>,
    /// That instance's binding revision.
    pub agent_binding_revision: Option<String>,
}

impl Subject {
    /// Builds the action target for a connection's environment.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` when an identifier is not one, and when the named fields do not
    /// agree with each other: a session without its epoch, an application without a session, or a
    /// binding revision without the instance it belongs to.
    pub fn target(&self, environment_id: EnvironmentId) -> Result<ActionTarget> {
        let session_id = parse::<SessionId>(self.session_id.as_deref(), "session_id")?;
        let session_epoch = match self.session_epoch.as_deref() {
            None => Nullable::null(),
            Some(value) => Nullable::some(SessionEpoch::new(
                value
                    .parse::<u64>()
                    .map_err(|_| CommandError::invalid("session_epoch is a counter"))?,
            )),
        };
        let application_instance_id = parse::<ApplicationInstanceId>(
            self.application_instance_id.as_deref(),
            "application_instance_id",
        )?;
        let agent_binding_revision = match self.agent_binding_revision.as_deref() {
            None => Nullable::null(),
            Some(value) => {
                Nullable::some(AgentBindingRevision::new(value.parse::<u64>().map_err(
                    |_| CommandError::invalid("agent_binding_revision is a counter"),
                )?))
            }
        };

        let target = ActionTarget {
            environment_id,
            session_id,
            session_epoch,
            application_instance_id,
            agent_binding_revision,
        };
        target
            .validate()
            .map_err(|error| CommandError::invalid(error.to_string()))?;
        Ok(target)
    }
}

fn parse<T>(value: Option<&str>, field: &str) -> Result<Nullable<T>>
where
    T: std::str::FromStr,
{
    match value {
        None => Ok(Nullable::null()),
        Some(text) => text
            .parse::<T>()
            .map(Nullable::some)
            .map_err(|_| CommandError::invalid(format!("{field} is not an identifier"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> EnvironmentId {
        "33333333-3333-4333-8333-333333333333"
            .parse()
            .expect("a valid environment")
    }

    fn session() -> String {
        "44444444-4444-4444-8444-444444444444".to_owned()
    }

    #[test]
    fn a_host_wide_effect_names_only_the_environment() {
        let target = Subject::default()
            .target(environment())
            .expect("a valid target");
        assert_eq!(target.environment_id, environment());
        assert!(!target.session_id.is_present());
    }

    #[test]
    fn a_session_effect_carries_the_session_and_its_epoch() {
        let subject = Subject {
            session_id: Some(session()),
            session_epoch: Some("1".to_owned()),
            ..Subject::default()
        };
        let target = subject.target(environment()).expect("a valid target");
        assert!(target.session_id.is_present());
        assert!(target.session_epoch.is_present());
    }

    #[test]
    fn a_session_without_its_epoch_is_refused() {
        let subject = Subject {
            session_id: Some(session()),
            ..Subject::default()
        };
        let error = subject
            .target(environment())
            .expect_err("a session names its epoch");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_application_instance_without_a_session_is_refused() {
        let subject = Subject {
            application_instance_id: Some("55555555-5555-4555-8555-555555555555".to_owned()),
            agent_binding_revision: Some("2".to_owned()),
            ..Subject::default()
        };
        let error = subject
            .target(environment())
            .expect_err("an application belongs to a session");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_identifier_that_is_not_one_is_refused_rather_than_sent() {
        let subject = Subject {
            session_id: Some("the session I was looking at".to_owned()),
            session_epoch: Some("1".to_owned()),
            ..Subject::default()
        };
        let error = subject
            .target(environment())
            .expect_err("not an identifier");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }
}
