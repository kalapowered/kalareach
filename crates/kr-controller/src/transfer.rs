//! The environment's transfer service, hosted by the control daemon.
//!
//! The daemon owns the service's lifetime and its two endpoints; `kr-transfer` owns the store, the
//! staging area and the filesystem authority. What this module adds is the part that has to be the
//! daemon's: admission.
//!
//! * Every transfer method arrives through the daemon's ordinary path. A read is checked against
//!   current authority before and after it runs; a mutation carries an action window, is checked
//!   against the method registry, and runs on a task that a dropped connection cannot cancel part
//!   way. Nothing here has a second admission path of its own.
//! * A 1 MiB chunk does not fit a control frame, so chunks arrive on the environment's
//!   attachment-chunk endpoint: the same handshake, the same peer-credential authentication and the
//!   same action windows, framed at the attachment bound instead of the control bound. That is the
//!   local form of section 23's attachment-chunk stream; the network form is a data stream of the
//!   same kind, carrying the same frames.
//! * The service's calls are synchronous: they talk to SQLite and to files. They run on blocking
//!   tasks rather than on the daemon's reactor.
//!
//! A transfer refusal reaches the caller under the code the service decided, not a code this
//! module chose for it: `ATTACHMENT_INTEGRITY` for a chunk that does not verify, `QUOTA_EXCEEDED`
//! for a budget, `SOURCE_CHANGED` for a snapshot that cannot continue, and so on. That is why the
//! replies here are built from the protocol error rather than mapped through the daemon's own
//! failure set.
//!
//! The daemon also gives the service the two things it cannot know for itself: which sessions its
//! retention still covers, and when to sweep.

use std::sync::{Arc, Weak};

use kr_ipc::endpoint::Listener;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActorId, RequestId, SessionId};
use kr_protocol::method::{Method, MethodGroup};
use kr_transfer::service::{RetainedOutcome, SessionRetention};
use kr_transfer::{Sweep, TransferService};

use crate::error::{ControllerError, Result};
use crate::registry::LaunchPhase;
use crate::service::Controller;

/// How often the daemon sweeps expired transfers.
///
/// Every window the sweep enforces is measured in hours or days, so an hour is frequent enough to
/// keep the staging area honest and rare enough that it costs nothing.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Every launch phase a session's reservation can be in.
///
/// A session with a reservation in any of them is one the registry still knows about, which is
/// what retention is measured against here.
const EVERY_PHASE: &[LaunchPhase] = &[
    LaunchPhase::Reserved,
    LaunchPhase::Spawned,
    LaunchPhase::Claimed,
    LaunchPhase::Live,
    LaunchPhase::Fenced,
    LaunchPhase::Failed,
    LaunchPhase::Closed,
];

/// What a transfer call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The transfer service, as the daemon holds it.
///
/// The module owns the tasks that serve the attachment-chunk endpoint and run the expiry sweep, and
/// ends them when it is dropped. The daemon owns the module, so its endpoint is released at the
/// same moment its singleton lock is: a listener that outlived the daemon would keep an address
/// bound that nothing is serving, and the next daemon would find it occupied.
#[derive(Debug)]
pub struct TransferModule {
    service: Arc<TransferService>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for TransferModule {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

impl TransferModule {
    /// Opens the environment's transfer service and resolves whatever an earlier daemon left
    /// unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store or the staging area cannot
    /// be prepared.
    pub fn open(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Self> {
        let service =
            TransferService::open(paths).map_err(|error| ControllerError::RegistryUnavailable {
                detail: error.to_string(),
            })?;
        // A publication interrupted between its two commits is resolved before anything is served,
        // so a handle never names a file this daemon has not found.
        service
            .recover()
            .map_err(|error| ControllerError::RegistryUnavailable {
                detail: error.to_string(),
            })?;
        Ok(Self {
            service: Arc::new(service),
            tasks: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Returns the service itself.
    #[must_use]
    pub fn service(&self) -> &Arc<TransferService> {
        &self.service
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        matches!(method.group(), MethodGroup::DraftsAndMedia)
    }

    /// Checks that a transfer mutation's envelope and its parameters name the same subject.
    ///
    /// A transfer names its subject in its parameters, because an action target has no transfer
    /// field: what the envelope has to agree about is the session an upload or a draft is bound to,
    /// and that a transfer is never addressed to an application instance.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.application_instance_id.is_present()
            && !matches!(method, Method::AgentDraftAddAttachment)
        {
            return Err(ControllerError::InvalidArgument(format!(
                "{} does not act on an application instance",
                method.as_str()
            )));
        }
        let (environment_id, session_id) = match method {
            Method::UploadBegin => {
                let params: kr_protocol::transfer::UploadBeginParams = parse(&mutation.params)?;
                (Some(params.environment_id), params.session_id.0)
            }
            Method::DraftCreate => {
                let params: kr_protocol::transfer::DraftCreateParams = parse(&mutation.params)?;
                (Some(params.environment_id), params.session_id.0)
            }
            // The remaining mutations name a transfer or a draft, neither of which the envelope's
            // target can carry. The environment is checked for every mutation before this point,
            // and the service checks the named subject against its own record.
            Method::UploadChunk
            | Method::UploadFinish
            | Method::UploadCancel
            | Method::DraftUpdate
            | Method::AgentDraftAddAttachment => (None, None),
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a transfer mutation this daemon serves",
                    method.as_str()
                )));
            }
        };
        if let Some(environment_id) = environment_id {
            if environment_id != mutation.target.environment_id {
                return Err(ControllerError::InvalidArgument(
                    "the request's target and its parameters name different environments"
                        .to_owned(),
                ));
            }
            if session_id != mutation.target.session_id.0 {
                return Err(ControllerError::InvalidArgument(
                    "the request's target and its parameters name different sessions".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Answers an action this service has already performed for this caller, if it has.
    ///
    /// This runs **before** the freshness window is considered, because a retry after a lost reply
    /// carries the window the action was first admitted under and this connection holds a newer
    /// one. Refusing it for that would deny a caller its own completed result, which is the one
    /// thing an action identifier exists to prevent.
    #[must_use]
    pub async fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<ControlFrame> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        let outcome = blocking(move || {
            Ok(service
                .retained_action(&actor, action_id, name, digest)
                .map_err(ProtocolError::from))
        })
        .await;
        match outcome {
            // The blocking task itself failed, which says nothing about the action.
            Err(error) => Some(frame(mutation.request_id, Err(error))),
            Ok(Err(error)) => Some(frame(mutation.request_id, Err(error))),
            Ok(Ok(None)) => None,
            Ok(Ok(Some(RetainedOutcome::Ok(result)))) => Some(frame(
                mutation.request_id,
                kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                    .map(ParamsValue::new)
                    .map_err(|error| {
                        ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                    }),
            )),
            Ok(Ok(Some(RetainedOutcome::Error { code, detail }))) => Some(frame(
                mutation.request_id,
                Err(ProtocolError::new(code, detail)),
            )),
        }
    }

    /// Serves one transfer read and returns the frame it answers with.
    #[must_use]
    pub async fn read_frame(&self, actor_id: &ActorId, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(actor_id, request).await)
    }

    /// Serves one transfer mutation and returns the frame it answers with.
    #[must_use]
    pub async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> ControlFrame {
        frame(
            mutation.request_id,
            self.write(actor_id, mutation, method).await,
        )
    }

    /// Serves one transfer read.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn read(&self, actor_id: &ActorId, request: &Request) -> Answer<ParamsValue> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = request.params.clone();
        blocking(move || match method {
            Method::UploadStatus => encode(&service.upload_status(&actor, &typed(&params)?)?),
            Method::DownloadBegin => encode(&service.download_begin(&actor, &typed(&params)?)?),
            Method::DownloadChunk => encode(&service.download_chunk(&actor, &typed(&params)?)?),
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} is not a transfer read this daemon serves",
                    method.as_str()
                ),
            )),
        })
        .await
    }

    /// Serves one transfer mutation, answering an exact repeat from its retained record.
    ///
    /// The de-duplication key is the actor and the action together, and the payload digest decides
    /// whether a repeat is the same action or a reused identifier. That is what makes a lost reply
    /// to `upload.finish` resolvable without publishing a second file, and what makes a repeated
    /// chunk or cancellation cost nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Answer<ParamsValue> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = mutation.params.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        blocking(move || {
            if let Some(retained) = service.retained_action(&actor, action_id, name, digest)? {
                return match retained {
                    RetainedOutcome::Ok(result) => {
                        kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                            .map(ParamsValue::new)
                            .map_err(|error| {
                                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                            })
                    }
                    RetainedOutcome::Error { code, detail } => {
                        Err(ProtocolError::new(code, detail))
                    }
                };
            }
            let outcome = match method {
                Method::UploadBegin => encode(&service.upload_begin(&actor, &typed(&params)?)?),
                Method::UploadChunk => encode(&service.upload_chunk(&actor, &typed(&params)?)?),
                Method::UploadFinish => encode(&service.upload_finish(&actor, &typed(&params)?)?),
                Method::UploadCancel => encode(&service.upload_cancel(&actor, &typed(&params)?)?),
                Method::DraftCreate => encode(&service.draft_create(&actor, &typed(&params)?)?),
                Method::DraftUpdate => encode(&service.draft_update(&actor, &typed(&params)?)?),
                Method::AgentDraftAddAttachment => {
                    encode(&service.draft_add_attachment(&actor, &typed(&params)?)?)
                }
                _ => Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{} is not a transfer mutation this daemon serves",
                        method.as_str()
                    ),
                )),
            };
            // The outcome is retained before it is returned, so the reply and the record cannot
            // disagree about what happened.
            let record = match &outcome {
                Ok(value) => {
                    RetainedOutcome::Ok(kr_cbor::to_canonical_vec(value).map_err(|error| {
                        ProtocolError::new(ErrorCode::InvalidArgument, error.to_string())
                    })?)
                }
                Err(error) => RetainedOutcome::Error {
                    code: error.code,
                    detail: error.message.clone(),
                },
            };
            service.record_action(&actor, action_id, name, digest, &record)?;
            outcome
        })
        .await
    }

    /// Expires everything whose retention has run out, under the registry's own view of its
    /// sessions.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided.
    pub async fn sweep(&self, controller: &Controller) -> Answer<Sweep> {
        let retention = controller
            .session_retention()
            .await
            .map_err(|error| error.to_protocol_error())?;
        let service = Arc::clone(&self.service);
        blocking(move || service.sweep(&retention).map_err(Into::into)).await
    }
}

/// The sessions the registry still knows about.
///
/// Retention is the archive service's policy to decide; what this settles is the part the transfer
/// service cannot see for itself. A session the registry has a record of keeps what was submitted
/// to it, and one it has no record of keeps nothing. Declining to delete is the answer that cannot
/// lose a file.
#[derive(Clone, Debug, Default)]
pub struct RegistryRetention {
    sessions: std::collections::BTreeSet<SessionId>,
}

impl RegistryRetention {
    /// Records one session as retained.
    pub fn insert(&mut self, session_id: SessionId) {
        self.sessions.insert(session_id);
    }

    /// Returns how many sessions are retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns true when no session is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl SessionRetention for RegistryRetention {
    fn retains(&self, session_id: SessionId) -> bool {
        self.sessions.contains(&session_id)
    }
}

impl Controller {
    /// Returns the sessions this environment's registry still knows about.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the registry cannot be read.
    pub async fn session_retention(&self) -> Result<RegistryRetention> {
        let registry = self.registry_handle().lock().await;
        let mut retention = RegistryRetention::default();
        for phase in EVERY_PHASE {
            for reservation in registry.reservations_in(*phase)? {
                retention.insert(reservation.session_id);
            }
        }
        Ok(retention)
    }
}

/// Starts the environment's attachment-chunk endpoint and its expiry sweep.
///
/// Both tasks hold a weak reference to the daemon, so neither keeps it alive and both stop when it
/// goes. The endpoint sits beside the control endpoint in the same owner-only runtime directory.
///
/// # Errors
///
/// Returns [`ControllerError::Ipc`] when the endpoint cannot be bound.
pub fn serve(controller: &Arc<Controller>) -> Result<()> {
    let endpoint = kr_transfer::chunks::chunk_endpoint(controller.paths()).map_err(|error| {
        ControllerError::NotConfigured(format!(
            "the attachment-chunk endpoint cannot be addressed: {error}"
        ))
    })?;
    let listener = Listener::bind(&endpoint)?;
    let chunks = Arc::downgrade(controller);
    let sweeps = Arc::downgrade(controller);
    let started = vec![
        tokio::spawn(async move {
            serve_chunks(chunks, listener).await;
        }),
        tokio::spawn(async move {
            sweep_forever(sweeps).await;
        }),
    ];
    let mut tasks = controller.transfer().tasks.lock().map_err(|_| {
        ControllerError::NotConfigured(
            "the transfer service's task list was left poisoned by an earlier failure".to_owned(),
        )
    })?;
    for task in started {
        tasks.push(task);
    }
    Ok(())
}

/// Accepts attachment-chunk connections until the daemon goes.
///
/// An accept that fails ends the loop, as it does on the control endpoint: a listener that cannot
/// accept has nothing left to serve, and spinning on it would hide that.
async fn serve_chunks(controller: Weak<Controller>, listener: Listener) {
    loop {
        let Ok((connection, peer)) = listener.accept().await else {
            return;
        };
        let Some(controller) = controller.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            // The frame bound is the only difference from a control connection. Everything else —
            // the hello, the peer check, the authority registration, the action window and its
            // renewals — is the same code, which is what keeps the two from drifting.
            let _ = controller
                .client(connection, peer, StreamKind::AttachmentChunks)
                .await;
        });
    }
}

/// Sweeps expired transfers until the daemon goes.
async fn sweep_forever(controller: Weak<Controller>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let Some(controller) = controller.upgrade() else {
            return;
        };
        let _ = controller.transfer().sweep(&controller).await;
    }
}

/// Runs one synchronous service call on a blocking task.
///
/// A dropped connection cannot cancel it: the task owns the work, and only the reply is lost.
async fn blocking<T, F>(work: F) -> Answer<T>
where
    T: Send + 'static,
    F: FnOnce() -> Answer<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| {
        Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "the transfer service could not report what happened to this action",
        ))
    })
}

fn frame(request_id: RequestId, outcome: Answer<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Answer<T> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Answer<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_serves_the_draft_and_media_group() {
        for method in [
            Method::UploadBegin,
            Method::UploadStatus,
            Method::UploadChunk,
            Method::UploadFinish,
            Method::UploadCancel,
            Method::DownloadBegin,
            Method::DownloadChunk,
            Method::DraftCreate,
            Method::DraftUpdate,
            Method::AgentDraftAddAttachment,
        ] {
            assert!(
                TransferModule::serves(method),
                "{} belongs to this service",
                method.as_str()
            );
        }
        // Submission is an agent mutation performed by the worker that owns the session. It is not
        // in this group and this service never performs it.
        assert!(!TransferModule::serves(Method::AgentPromptSubmit));
        assert!(!TransferModule::serves(Method::SessionCreate));
        assert!(!TransferModule::serves(Method::DiffApply));
    }

    #[test]
    fn every_transfer_method_the_daemon_serves_is_reachable_from_a_local_caller() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;

        for method in [
            Method::UploadBegin,
            Method::UploadStatus,
            Method::UploadChunk,
            Method::UploadFinish,
            Method::UploadCancel,
            Method::DownloadBegin,
            Method::DownloadChunk,
            Method::DraftCreate,
            Method::DraftUpdate,
            Method::AgentDraftAddAttachment,
        ] {
            let decision = kr_protocol::method::decide(
                method.as_str(),
                method.entry().version,
                ActorIngress::LocalIpc,
            );
            assert!(
                matches!(decision, AuthorityDecision::Listed(_)),
                "{} is not reachable from a local caller",
                method.as_str()
            );
        }
    }

    #[test]
    fn a_retention_answers_only_for_the_sessions_it_holds() {
        use kr_protocol::scalars::Uuid;

        let held = SessionId::new(Uuid::from_bytes([1; 16]));
        let other = SessionId::new(Uuid::from_bytes([2; 16]));
        let mut retention = RegistryRetention::default();
        assert!(retention.is_empty());
        retention.insert(held);
        assert_eq!(retention.len(), 1);
        assert!(retention.retains(held));
        assert!(!retention.retains(other));
    }
}
