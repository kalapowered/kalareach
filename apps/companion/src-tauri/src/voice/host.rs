//! The host a call belongs to, and the ways to reach it.
//!
//! A call is bound to the host that created it. Choosing another host to browse, a connection that
//! is replaced and a host that is forgotten all happen while a call runs, and the revocation of its
//! grant has to go to the host that issued it and to no other: another host would answer that it
//! knows no such call, and that is not the same as the grant being revoked.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use companion_platform::call::{CallId, CallPlatform};
use kr_client::pairing::paired::PairedHost;
use kr_client::session::ComposedMutation;
use kr_client::{ClientError, Session, Settled};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, EnvironmentId, VoiceSessionId};
use kr_protocol::method::Method;
use kr_protocol::voice::{VoiceDelegateParams, VoiceDelegateResult};
use tauri::{AppHandle, Manager as _, Runtime};
use tokio::time::Instant;

use super::delegation::{Cause, usable};
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

    /// The key this device signs a voice confirmation with: its own identity key for the host it
    /// is paired with, the one that signs its authority-bearing requests.
    ///
    /// # Errors
    ///
    /// Returns why there is none: this application holds no device identity.
    fn authorisation_key(&self) -> Result<AuthorisationKeyPair>;
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

    fn authorisation_key(&self) -> Result<AuthorisationKeyPair> {
        Ok(self
            .app
            .state::<AppState>()
            .device()?
            .identity()
            .keys
            .authorisation
            .clone())
    }
}

/// Asks `host` to revoke the grant of the voice session `voice_session_id`, and says what came
/// of it.
///
/// What is kept apart is what the host answered: the stop revoked the grant, the host holds no
/// call of this device by that name, the host refused the stop for another reason, or the host was
/// not told or did not answer in time. The first two settle a revocation owed to the host: after
/// the first the grant is gone, and after the second this device can end nothing more there. The
/// host answers the unknown session with its own code. Any other refusal is not a revocation done:
/// the host answers `PermissionDenied` before it looks at the call at all, when the device's right
/// to stop is not admitted, when its window has expired or when its grants cannot be read, and the
/// grant is then still live. So such a refusal leaves the revocation owed, until the moment the
/// grant ends by itself.
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
        Ok(Err(kr_client::ClientError::Host(error))) => {
            if error.code == kr_protocol::error::ErrorCode::UnknownSession {
                HostEnd::NotHeld {
                    words: error.message,
                }
            } else {
                HostEnd::Refused {
                    words: error.message,
                }
            }
        }
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

/// What came of handing one delegation to the host.
pub(super) enum Delivered {
    /// The host answered with a result.
    Result(Box<VoiceDelegateResult>),
    /// The host refused the request itself, and said so with an error.
    Refused,
    /// The host answered with a receipt, which is not a decision: it says the host holds the
    /// action, never what became of it.
    Receipt,
    /// Nothing was written, for this cause. The same delegation can be said again.
    Withheld(Cause),
    /// The proof taken before the send showed what taints the call. Nothing was written.
    Tainted(Cause),
    /// The request was written, or may have been, and no answer came: what became of it is not
    /// known, and only the host's record can say.
    Unknown,
}

/// A delegation handed to the host, with what the owner needs to ask about it again.
pub(super) struct Exchange {
    /// The connection the request was composed on, and sent on when it was sent.
    pub session: Arc<Session>,
    /// The whole request as composed, window included, which is what is asked again with. None
    /// when it was never composed.
    pub composed: Option<ComposedMutation>,
    /// What came of it.
    pub delivered: Delivered,
}

/// What a delegation is handed over with.
pub(super) struct Handover {
    pub host: CallHost,
    pub platform: Arc<dyn CallPlatform>,
    pub call: CallId,
    /// The action the request goes out under: none for a first request, which takes a new one, and
    /// the same action again for the request that carries a confirmation of the first.
    pub action_id: Option<ActionId>,
    pub params: VoiceDelegateParams,
    /// How old a capture proof may be at the moment the request is written.
    pub age_bound: Duration,
    /// How long the host is given to answer.
    pub within: Duration,
    /// Set by the owner when the path to the host is lost: nothing is written after it.
    pub lost: Arc<AtomicBool>,
}

/// Hands one delegation to the host, once: the request is composed once and kept whole, a capture
/// proof is taken as late as it can be, and the request is written only while that proof is
/// young, where the writing happens and not where it is asked for.
///
/// The send is made on the connection that composed the request, which is the one whose window
/// admits it. It is settled when the host answered, as the host's word, whatever the word was; an
/// answer that did not come leaves it unsettled, and unknown.
pub(super) async fn hand_over(handover: Handover) -> Exchange {
    let Handover {
        host,
        platform,
        call,
        action_id,
        params,
        age_bound,
        within,
        lost,
    } = handover;
    let action_id = action_id.unwrap_or_else(|| ActionId::new(kr_ipc::new_uuid()));
    let session = Arc::clone(&host.session);
    let nothing = |cause: Cause, composed: Option<ComposedMutation>| Exchange {
        session: Arc::clone(&session),
        composed,
        delivered: Delivered::Withheld(cause),
    };
    let composed = match host
        .session
        .compose(
            Method::VoiceDelegate,
            action_id,
            ActionTarget::environment(host.environment_id),
            None,
            &NoPreconditions {},
            &params,
            MUTATION_TTL,
        )
        .await
    {
        Ok(composed) => composed,
        Err(_) => return nothing(Cause::NotComposed, None),
    };
    // The proof is asked for as late as it can be, and its age is counted from the moment it is
    // asked: what native code answers is how old the freshest sign was then, and the time the
    // answer and the write take is added to it.
    let asked = Instant::now();
    let proof = platform.capture_proof(&call, false).await;
    let age = match proof {
        Ok(proof) => match usable(&proof, &call) {
            Ok(age) => age,
            Err(cause) if cause.taints() => {
                // A request waiting for the connection's turn is stopped here, by the task that
                // read the proof, and not when the owner next handles a message: no other write
                // leaves in between.
                lost.store(true, Ordering::SeqCst);
                return Exchange {
                    session,
                    composed: Some(composed),
                    delivered: Delivered::Tainted(cause),
                };
            }
            Err(cause) => return nothing(cause, Some(composed)),
        },
        Err(_) => return nothing(Cause::NoProof, Some(composed)),
    };
    // A proof as old as the bound is not young: nothing is asked of the writer for it.
    let age = Duration::from_millis(age);
    if age >= age_bound {
        return nothing(Cause::StaleProof, Some(composed));
    }
    let not_after = asked + (age_bound - age);
    if lost.load(Ordering::SeqCst) {
        return nothing(Cause::HostLost, Some(composed));
    }
    // Written only while the call can still hand a request over, and while the proof is young:
    // both are looked at once the connection holds the right to write.
    let wanted = || !lost.load(Ordering::SeqCst);
    let sent = tokio::time::timeout(
        within,
        host.session.send_before(&composed, not_after, &wanted),
    )
    .await;
    let delivered = match sent {
        Ok(Ok(Settled::Result(value))) => {
            host.session.settle(action_id).await;
            match value.to_typed::<VoiceDelegateResult>() {
                Ok(result) => Delivered::Result(Box::new(result)),
                // An answer that is not a result of the method is not the host's word.
                Err(_) => Delivered::Unknown,
            }
        }
        Ok(Ok(Settled::Receipt(_))) => Delivered::Receipt,
        Ok(Err(ClientError::Withheld)) => Delivered::Withheld(if lost.load(Ordering::SeqCst) {
            Cause::HostLost
        } else {
            Cause::StaleProof
        }),
        Ok(Err(ClientError::Host(_))) => {
            host.session.settle(action_id).await;
            Delivered::Refused
        }
        // Nothing of these left, or nothing was recorded: the request was not sent.
        Ok(Err(
            ClientError::Cbor(_)
            | ClientError::NoActionWindow
            | ClientError::Misdirected { .. }
            | ClientError::StillAccounting
            | ClientError::TooManyOutstandingMutations { .. }
            | ClientError::TooManyUnresolvedActions { .. },
        )) => Delivered::Withheld(Cause::NotComposed),
        Ok(Err(_)) | Err(_) => Delivered::Unknown,
    };
    Exchange {
        session,
        composed: Some(composed),
        delivered,
    }
}

/// Asks the host what became of a delegation whose answer was lost, with the request as it was
/// composed, on a connection other than the one that sent it. A repeat is a question: the host
/// answers it from the record it kept of the action, or does not answer. Only a result settles it.
///
/// Asks after each of `delays`, and returns the result when one came.
pub(super) async fn ask_again(
    reach: Arc<dyn HostReach>,
    host: CallHost,
    composed: ComposedMutation,
    delays: [Duration; 3],
    within: Duration,
) -> Option<VoiceDelegateResult> {
    let action_id = composed.action_id();
    let mut found = None;
    for delay in delays {
        tokio::time::sleep(delay).await;
        let Ok(session) = reach.session_to(&host.paired, Some(&host.session)).await else {
            continue;
        };
        let asked = tokio::time::timeout(within, session.repeat(&composed)).await;
        if let Ok(Ok(Settled::Result(value))) = asked
            && let Ok(result) = value.to_typed::<VoiceDelegateResult>()
        {
            found = Some(result);
        }
        session.settle(action_id).await;
        if found.is_some() {
            break;
        }
    }
    host.session.settle(action_id).await;
    found
}
