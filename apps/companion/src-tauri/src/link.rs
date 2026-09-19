//! The one way this backend reaches a host.
//!
//! A command names a [`Method`] and hands this trait the parameters. The link decides nothing: the
//! method registry says whether the call is a read or a mutation, and [`kr_client::Session`]
//! refuses a call that does not match its entry. That is why a command can be three lines and
//! still cannot reach an effect the registry does not list.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use kr_protocol::authority::EffectClass;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::method::Method;
use kr_protocol::scalars::DurationMs;
use serde_json::Value;

use crate::error::{CommandError, Result};

/// How long a mutation this application submits may stay acceptable.
///
/// Long enough that a person who presses a button and watches the receipt settle sees the outcome,
/// short enough that an application closed mid-action does not leave one acceptable for an hour.
pub const MUTATION_TTL: DurationMs = DurationMs::new(60_000);

/// The answer of one call, still in the protocol's own JSON shape.
pub type Answer = Pin<Box<dyn Future<Output = Result<Value>> + Send>>;

/// A host this backend can call.
pub trait HostLink: Send + Sync + std::fmt::Debug {
    /// Performs one registry-listed method.
    ///
    /// `target` is the action target a mutation needs and a read ignores.
    fn call(&self, method: Method, target: ActionTarget, params: Value) -> Answer;

    /// Whether a host connection is live.
    fn connected(&self) -> bool;
}

/// A link over a real session.
#[derive(Debug)]
pub struct SessionLink {
    session: Arc<kr_client::Session>,
}

impl SessionLink {
    /// Wraps a live session.
    #[must_use]
    pub const fn new(session: Arc<kr_client::Session>) -> Self {
        Self { session }
    }
}

impl HostLink for SessionLink {
    fn call(&self, method: Method, target: ActionTarget, params: Value) -> Answer {
        let session = Arc::clone(&self.session);
        Box::pin(async move {
            match method.entry().effect {
                EffectClass::Read => {
                    let value: Value = session.read(method, &params).await?;
                    Ok(value)
                }
                EffectClass::Write => {
                    let settled = session
                        .mutate(method, target, None, &Value::Null, &params, MUTATION_TTL)
                        .await?;
                    settled_to_json(&settled)
                }
            }
        })
    }

    fn connected(&self) -> bool {
        true
    }
}

/// Turns a settled mutation into what the interface shows: the receipt, and the value when the
/// host returned one.
///
/// Section 9 makes the receipt the outcome, so it travels beside the value rather than being
/// replaced by it: an interface that shows "applied" shows it because a receipt said so.
fn settled_to_json(settled: &kr_client::Settled) -> Result<Value> {
    let receipt = settled.receipt().map(|receipt| serde_json::to_value(receipt));
    let receipt = match receipt {
        Some(Ok(value)) => value,
        Some(Err(error)) => {
            return Err(CommandError::local_failure(format!(
                "the receipt could not be represented: {error}"
            )));
        }
        None => Value::Null,
    };
    let value = match settled.result() {
        Some(result) => serde_json::to_value(result).map_err(|error| {
            CommandError::local_failure(format!("the result could not be represented: {error}"))
        })?,
        None => Value::Null,
    };
    Ok(serde_json::json!({ "receipt": receipt, "value": value }))
}

/// The link of an application that has no host yet.
///
/// Every call refuses with `UNAVAILABLE`, which is the same answer a reachable host that went away
/// produces. The interface has one disconnected state rather than two.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unconnected;

impl HostLink for Unconnected {
    fn call(&self, _method: Method, _target: ActionTarget, _params: Value) -> Answer {
        Box::pin(async { Err(CommandError::not_connected()) })
    }

    fn connected(&self) -> bool {
        false
    }
}

/// Builds the narrowest target a mutation can name: one environment and nothing else.
///
/// A mutation that applies to a session names it instead; this is what a host-wide effect carries.
///
/// # Errors
///
/// Returns the failure when the identifier is not a valid environment name.
pub fn environment_target(environment_id: &str) -> Result<ActionTarget> {
    let environment_id: kr_protocol::ids::EnvironmentId = environment_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not an environment identifier"))?;
    Ok(ActionTarget::environment(environment_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_application_without_a_host_refuses_every_call_as_unavailable() {
        let link = Unconnected;
        let error = link
            .call(
                Method::SessionList,
                environment_target("11111111-1111-4111-8111-111111111111")
                    .expect("a valid environment"),
                Value::Null,
            )
            .await
            .expect_err("no host is connected");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::HostNotConfigured);
        assert!(!link.connected());
    }
}
