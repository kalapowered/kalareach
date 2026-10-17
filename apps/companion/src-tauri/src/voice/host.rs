//! The host a call belongs to, and the ways to reach it.
//!
//! A call is bound to the host that created it. Choosing another host to browse, a connection that
//! is replaced and a host that is forgotten all happen while a call runs, and the revocation of its
//! grant has to go to the host that issued it and to no other: another host would answer that it
//! knows no such call, and that is not the same as the grant being revoked.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kr_client::Session;
use kr_client::pairing::paired::PairedHost;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{EnvironmentId, VoiceSessionId};
use kr_protocol::method::Method;
use tauri::{AppHandle, Manager as _, Runtime};

use super::view::HostEnd;
use crate::commands::{MUTATION_TTL, NoPreconditions, fence_of};
use crate::connection::{Connection, Standing};
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// The host a call belongs to.
#[derive(Clone)]
pub struct CallHost {
    /// This device's record of the pairing.
    pub paired: PairedHost,
    /// The environment the host stamped on its handshake.
    pub environment_id: EnvironmentId,
    /// The connection the call was started on.
    pub session: Arc<Session>,
}

/// What reaching the host takes.
pub type Reaching<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// How a call reaches its host.
pub trait HostReach: Send + Sync + 'static {
    /// The host this application's commands go to now, with the connection they use.
    ///
    /// # Errors
    ///
    /// Returns why there is none: no connection, or a host on this machine, which a call is not
    /// started against.
    fn in_use(&self) -> Result<CallHost>;

    /// A connection to `host` that is open now: the one in use when it is that host's, and
    /// another connection otherwise. A connection that is `avoiding` is not returned.
    fn session_to<'a>(
        &'a self,
        host: &'a PairedHost,
        avoiding: Option<&'a Arc<Session>>,
    ) -> Reaching<'a, Arc<Session>>;

    /// Whether this device still holds its pairing with `host`. A record that cannot be read is
    /// not a pairing that is gone.
    fn pairing(&self, host: &PairedHost) -> Pairing;

    /// Whether the commands of this application now go to a host other than `host`: another
    /// paired host, or this computer's own.
    fn another_host_in_use(&self, host: &PairedHost) -> bool;
}

/// What this device's records say of a pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pairing {
    /// The pairing is held.
    Held,
    /// The pairing is not in the records.
    Gone,
    /// The records could not be read.
    Unreadable,
}

/// How an application reaches the host its commands go to.
pub struct AppReach<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> AppReach<R> {
    /// The reach of the application `app` runs.
    #[must_use]
    pub const fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

/// Whether a connection has ended.
pub(super) async fn has_ended(session: &Session) -> bool {
    tokio::time::timeout(Duration::ZERO, session.closed())
        .await
        .is_ok()
}

impl<R: Runtime> HostReach for AppReach<R> {
    fn in_use(&self) -> Result<CallHost> {
        let connection = self.app.state::<AppState>().connection()?;
        match connection.standing() {
            Standing::Paired { host, .. } => Ok(CallHost {
                paired: (**host).clone(),
                environment_id: connection.environment_id(),
                session: connection.session(),
            }),
            Standing::Owner => Err(CommandError::refused(
                "this application is the owner of the host it is connected to, not a paired device",
            )),
        }
    }

    fn session_to<'a>(
        &'a self,
        host: &'a PairedHost,
        avoiding: Option<&'a Arc<Session>>,
    ) -> Reaching<'a, Arc<Session>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            if let Ok(connection) = state.connection()
                && let Standing::Paired { host: current, .. } = connection.standing()
                && current.host_device_id == host.host_device_id
            {
                let session = connection.session();
                let other = avoiding.is_none_or(|avoided| !Arc::ptr_eq(avoided, &session));
                if other && !has_ended(&session).await {
                    return Ok(session);
                }
            }
            let device = state.device()?;
            let connection = Connection::paired(&device, host).await?;
            Ok(connection.session())
        })
    }

    fn pairing(&self, host: &PairedHost) -> Pairing {
        match self
            .app
            .state::<AppState>()
            .device()
            .and_then(|device| device.is_paired_with(host.host_device_id))
        {
            Ok(true) => Pairing::Held,
            Ok(false) => Pairing::Gone,
            Err(_) => Pairing::Unreadable,
        }
    }

    fn another_host_in_use(&self, host: &PairedHost) -> bool {
        let state = self.app.state::<AppState>();
        if let Some(chosen) = state.device().ok().and_then(|device| device.host_in_use()) {
            return chosen.host_device_id != host.host_device_id;
        }
        // None is chosen: only this computer's own host is another one.
        state
            .connection()
            .is_ok_and(|connection| matches!(connection.standing(), Standing::Owner))
    }
}

/// Asks `host` to revoke the grant of the voice session `voice_session_id`, and says what came
/// of it.
///
/// What is kept apart is what the host answered: the stop revoked the grant, the host refused the
/// stop (it no longer knows the call, so the grant it may hold ends when the call was to close),
/// or the host was not told or did not answer in time (the revocation is owed).
pub async fn revoke(
    session: &Arc<Session>,
    environment_id: EnvironmentId,
    voice_session_id: VoiceSessionId,
    within: Duration,
) -> HostEnd {
    let params = kr_protocol::voice::VoiceStopParams { voice_session_id };
    let asking = session.mutate(
        Method::VoiceStop,
        ActionTarget::environment(environment_id),
        None,
        &NoPreconditions {},
        &params,
        MUTATION_TTL,
    );
    match tokio::time::timeout(within, asking).await {
        Err(_) => HostEnd::NotTold {
            words: format!(
                "The host was asked to revoke the call's grant and has not answered in {} \
                 seconds.",
                within.as_secs()
            ),
        },
        Ok(Ok(answer)) => match fence_of(&answer) {
            Ok(fence) => HostEnd::Revoked {
                fence,
                broker_notified: told_the_service(&answer),
            },
            Err(error) => HostEnd::NotTold {
                words: error.message,
            },
        },
        Ok(Err(kr_client::ClientError::Host(error))) => end_of_refusal(&error),
        Ok(Err(error)) => HostEnd::NotTold {
            words: error.to_string(),
        },
    }
}

/// Whether the host's answer to a stop says it told the voice service the call ended.
fn told_the_service(answer: &kr_client::Settled) -> bool {
    let kr_client::Settled::Result(value) = answer else {
        return false;
    };
    matches!(
        value.as_value(),
        kr_cbor::CanonicalValue::Map(result)
            if matches!(result.get("broker_notified"), Some(kr_cbor::CanonicalValue::Bool(true)))
    )
}

/// What a host's refusal of a stop came to.
///
/// A refusal that says the host holds no such voice session, or does not let this device stop it
/// (`PermissionDenied`), is the host's last word: the grant it holds ends when the call was to
/// close. Any other refusal is a host that could not do it now, such as a store that would not
/// write the revocation, and the host then keeps the session and its live grant for a stop asked
/// again: nothing was revoked, and the revocation is still owed.
pub(super) fn end_of_refusal(error: &kr_protocol::error::ProtocolError) -> HostEnd {
    if error.code == kr_protocol::error::ErrorCode::PermissionDenied {
        HostEnd::Refused {
            words: error.message.clone(),
        }
    } else {
        HostEnd::NotTold {
            words: format!("The host could not revoke the grant now: {}", error.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(code: kr_protocol::error::ErrorCode) -> kr_protocol::error::ProtocolError {
        kr_protocol::error::ProtocolError::new(code, "the host's words".to_owned())
    }

    /// Only a host that holds no such voice session is done with a revocation. A host whose store
    /// refused to write it holds the grant live, and a revocation owed to it stays owed.
    #[test]
    fn only_a_refusal_that_says_no_such_voice_session_is_final() {
        assert!(matches!(
            end_of_refusal(&refusal(kr_protocol::error::ErrorCode::PermissionDenied)),
            HostEnd::Refused { .. }
        ));
        assert!(matches!(
            end_of_refusal(&refusal(kr_protocol::error::ErrorCode::StorageUnavailable)),
            HostEnd::NotTold { .. }
        ));
    }
}
