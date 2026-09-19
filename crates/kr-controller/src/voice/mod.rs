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
pub use context::{FilteredContext, SessionFacts, SessionSnapshot};
pub use host::{ControllerDispatch, ControllerFacts};
pub use submit::{HostDispatch, ProposalSubmitter};

use crate::error::{ControllerError, Result};

/// The environment variable that names the managed voice broker's origin.
///
/// Absent means this host brokers no managed call. It is a complete host: a person's own provider
/// credential and the agent already running in the session both still work, and `voice.start`
/// says so rather than failing obscurely.
pub const VOICE_BROKER_ORIGIN_VARIABLE: &str = "KR_VOICE_BROKER_ORIGIN";

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
        let tokens = Arc::new(kr_voice::broker::AccountTokenFile::under(runtime_root));
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
        device_id: DeviceId,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
    ) -> ControlFrame {
        let outcome = self
            .dispatch(device_id, mutation, method, authority_revision, now_ms)
            .await;
        frame(mutation.request_id, outcome)
    }

    async fn dispatch(
        &self,
        device_id: DeviceId,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        now_ms: u64,
    ) -> Result<ParamsValue> {
        let action_id: ActionId = mutation.action_id;
        match method {
            Method::VoiceGrant => {
                let params: kr_protocol::voice::VoiceGrantParams = parse(&mutation.params)?;
                // A device may broaden its own voice grant; changing another device's is a
                // host-management change, which the registry's own entry already demands.
                if params.device_id != device_id {
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
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceStart => {
                let params: kr_protocol::voice::VoiceStartParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .start(device_id, &params, authority_revision, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceStop => {
                let params: kr_protocol::voice::VoiceStopParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .stop(device_id, &params, now_ms)
                        .await
                        .map_err(voice_error)?,
                )
            }
            Method::VoiceDelegate => {
                let params: kr_protocol::voice::VoiceDelegateParams = parse(&mutation.params)?;
                value(
                    &self
                        .coordinator
                        .delegate(device_id, action_id, &params, now_ms)
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
