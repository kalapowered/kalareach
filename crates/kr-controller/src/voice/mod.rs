//! The host's voice service: the coordinator, its seams and the five methods.
//!
//! `kr-voice` holds the rules and this module holds the host. The division is deliberate and is
//! decision D-089's: the coordinator depends on the protocol, the client and the cryptography and
//! never on this daemon, so what reaches it is what this module passes in. That is what makes the
//! data boundary in `docs/voice/README.md` something a reader can check by reading three
//! implementations rather than the whole daemon.
//!
//! | Seam | What this module gives it |
//! | --- | --- |
//! | `ContextSource` | Session facts, every item filtered at `Surface::VoiceContext` under a viewer scope built from the requesting device's grant |
//! | `VoiceAuthority` | The grant store this host already keeps, and the device record that holds the identity key a confirmation is checked against |
//! | `ActionSubmitter` | The host's own dispatch, which validates a spoken proposal exactly as a typed one |
//!
//! Nothing here reaches the managed broker with content. The broker client is used to create and
//! to end a call; selected context and host results go back to the paired client, which is what
//! sends them.

mod authority;
mod context;
mod host;
mod submit;

use std::sync::Arc;

use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, AuthorityRevision, DeviceId, EnvironmentId};
use kr_protocol::method::Method;
use kr_voice::Coordinator;
use kr_voice::broker::{ManagedVoiceBroker, ManagedVoiceService, ServiceHttp};

pub use authority::GrantAuthority;
pub use context::{FilteredContext, SessionFacts, SessionSnapshot, snapshot_of};
pub use host::{ControllerDispatch, ControllerFacts};
pub use submit::{HostDispatch, ProposalSubmitter};

use crate::error::{ControllerError, Result};

/// The environment variable that names the managed voice broker's origin.
///
/// Absent means this host brokers no managed call. It is a complete host: a person's own provider
/// credential and the agent already running in the session both still work, and `voice.start`
/// says so rather than failing obscurely.
pub const VOICE_BROKER_ORIGIN_VARIABLE: &str = "KR_VOICE_BROKER_ORIGIN";

/// Who is asking, as this host resolved the actor.
///
/// Section 23 gives four of the five voice methods `PairedDevice` ingress and gives `voice.grant`
/// both: a device changes its own voice grant, and the person at this machine changes a device's.
/// The distinction is here rather than inside the coordinator, because it is a fact about the
/// connection the request arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceActor {
    /// A paired device, acting as itself over its own authenticated connection.
    Device(DeviceId),
    /// The person at this machine, on the host's own socket.
    Owner,
}

impl VoiceActor {
    /// The device this actor acts as, when it is one.
    #[must_use]
    pub const fn device(self) -> Option<DeviceId> {
        match self {
            Self::Device(device_id) => Some(device_id),
            Self::Owner => None,
        }
    }
}

/// The environment's voice service.
#[derive(Debug)]
pub struct VoiceModule {
    coordinator: Coordinator,
}

impl VoiceModule {
    /// Builds the service over this host's own stores and connections.
    #[must_use]
    pub fn new(
        facts: Arc<dyn SessionFacts>,
        authority: Arc<GrantAuthority>,
        dispatch: Arc<dyn HostDispatch>,
        provider: Option<Arc<dyn ManagedVoiceService>>,
        host_device_id: DeviceId,
        environment_id: EnvironmentId,
        broker_origin: String,
    ) -> Self {
        Self {
            coordinator: Coordinator::new(
                Arc::new(FilteredContext::new(facts)),
                authority,
                Arc::new(ProposalSubmitter::new(dispatch)),
                provider,
                host_device_id,
                environment_id,
                broker_origin,
            ),
        }
    }

    /// Builds the managed broker client for a host that has one configured.
    ///
    /// `None` when no origin is configured, which is a complete host: a person's own provider
    /// credential and the agent already running in the session both still work.
    #[must_use]
    pub fn managed_provider(
        origin: Option<String>,
        http: Arc<dyn ServiceHttp>,
        runtime_root: &std::path::Path,
    ) -> Option<Arc<dyn ManagedVoiceService>> {
        let origin = origin?;
        // Bound to the origin this host is configured to reach, so a token issued for another
        // service is refused before a request carries it.
        let tokens = Arc::new(
            kr_voice::broker::AccountTokenFile::under(runtime_root).for_origin(origin.clone()),
        );
        ManagedVoiceBroker::new(origin, http, tokens)
            .ok()
            .map(|broker| Arc::new(broker) as Arc<dyn ManagedVoiceService>)
    }

    /// Replaces the provider this service brokers through.
    ///
    /// An embedder with an HTTP exchange of its own attaches the managed broker here, or attaches
    /// a backend of the person's own. Nothing above the seam knows which one answered.
    #[must_use]
    pub fn with_provider(mut self, provider: Option<Arc<dyn ManagedVoiceService>>) -> Self {
        self.coordinator = self.coordinator.with_provider(provider);
        self
    }

    /// Attaches a provider to the service this host has already registered.
    ///
    /// The daemon registers its voice service while it starts, and nothing inside it reaches a
    /// network: an embedder brings the HTTP exchange and attaches the managed broker afterwards,
    /// or attaches a backend of the person's own. Until one is attached this host brokers no
    /// managed call, which is a complete host and says so.
    pub fn attach_provider(&self, provider: Option<Arc<dyn ManagedVoiceService>>) {
        self.coordinator.attach_provider(provider);
    }

    /// The coordinator, for a caller that needs it directly.
    #[must_use]
    pub const fn coordinator(&self) -> &Coordinator {
        &self.coordinator
    }

    /// Returns true when this service serves `method`.
    #[must_use]
    pub const fn serves(method: Method) -> bool {
        matches!(
            method,
            Method::VoiceStart
                | Method::VoiceStop
                | Method::VoiceGrant
                | Method::VoiceDelegate
                | Method::VoiceContext
        )
    }

    /// Checks that a voice mutation's envelope and its parameters name the same subject.
    ///
    /// A voice session belongs to this host rather than to one terminal session, so a voice
    /// mutation names the environment. The session a delegation acts on is inside the parameters,
    /// where the coordinator checks it against what the voice session may reach.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope names a session, or the parameters are not the shape the
    /// method declares.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.session_id.as_ref().is_some() {
            return Err(ControllerError::InvalidArgument(
                "a voice session belongs to this host, not to one terminal session".to_owned(),
            ));
        }
        match method {
            Method::VoiceStart => {
                let _: kr_protocol::voice::VoiceStartParams = parse(&mutation.params)?;
            }
            Method::VoiceStop => {
                let _: kr_protocol::voice::VoiceStopParams = parse(&mutation.params)?;
            }
            Method::VoiceGrant => {
                let _: kr_protocol::voice::VoiceGrantParams = parse(&mutation.params)?;
            }
            Method::VoiceDelegate => {
                let _: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a voice mutation",
                    method.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Answers `voice.context`.
    pub async fn read_frame(
        &self,
        device_id: DeviceId,
        request: &Request,
        now_ms: u64,
    ) -> ControlFrame {
        let outcome = async {
            let params: kr_protocol::voice::VoiceContextParams = parse(&request.params)?;
            let result = self
                .coordinator
                .context(device_id, &params, now_ms)
                .await
                .map_err(voice_error)?;
            value(&result)
        }
        .await;
        frame(request.request_id, outcome)
    }

    /// Answers one of the four voice mutations.
    pub async fn write_frame(
        &self,
        actor: VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
    ) -> ControlFrame {
        let outcome = self
            .dispatch(actor, mutation, method, authority_revision, now_ms)
            .await;
        frame(mutation.request_id, outcome)
    }

    async fn dispatch(
        &self,
        actor: VoiceActor,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
    ) -> Result<ParamsValue> {
        let action_id: ActionId = mutation.action_id;
        let device_of = |actor: VoiceActor| {
            actor
                .device()
                .ok_or_else(|| ControllerError::PermissionDenied {
                    detail: "this voice method is reachable from a paired device".to_owned(),
                })
        };
        match method {
            Method::VoiceGrant => {
                let params: kr_protocol::voice::VoiceGrantParams = parse(&mutation.params)?;
                // Three cases, which are the registry's own two conditions. A device changes its
                // own voice grant, which is the resource owner acting on its own subject. The
                // person at this machine changes any device's, which is what the host's own socket
                // is. A device changing another device's needs host management, and this host does
                // not yet resolve that right for a device, so it is refused rather than guessed
                // at.
                if let Some(device_id) = actor.device()
                    && params.device_id != device_id
                {
                    return Err(ControllerError::PermissionDenied {
                        detail: "a device changes its own voice grant; changing another device's \
                                 needs host-management authority"
                            .to_owned(),
                    });
                }
                value(
                    &self
                        .coordinator
                        .grant(&params, authority_revision, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceStart => {
                let params: kr_protocol::voice::VoiceStartParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .start(device_of(actor)?, &params, authority_revision, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceStop => {
                let params: kr_protocol::voice::VoiceStopParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .stop(device_of(actor)?, &params, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceDelegate => {
                let params: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .delegate(device_of(actor)?, action_id, &params, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a voice mutation",
                method.as_str()
            ))),
        }
    }
}

/// Reads one request's parameters.
fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Writes one result.
fn value<T: serde::Serialize>(result: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(result)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// The daemon error one coordinator refusal becomes.
fn voice_error(error: kr_voice::VoiceError) -> ControllerError {
    let protocol = error.to_protocol_error();
    match protocol.code {
        ErrorCode::PermissionDenied => ControllerError::PermissionDenied {
            detail: protocol.message,
        },
        ErrorCode::InvalidArgument => ControllerError::InvalidArgument(protocol.message),
        ErrorCode::HostNotConfigured => ControllerError::NotConfigured(protocol.message),
        _ => ControllerError::Refused {
            code: protocol.code,
            detail: protocol.message,
        },
    }
}

/// The frame one answer becomes.
fn frame(request_id: kr_protocol::ids::RequestId, outcome: Result<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(ProtocolError::new(error.code(), error.to_string())),
        },
    })
}
