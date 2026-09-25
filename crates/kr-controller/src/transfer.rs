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
//!
//! The attachment-chunk endpoint is bound and served by whoever runs the daemon, the same way the
//! control endpoint is. That is deliberate: a listener has to be released before the next daemon
//! binds the same address, and only the owner of the task that holds it can release it at a known
//! moment. A task this module spawned and abandoned could not be.

use std::sync::{Arc, Weak};

use kr_ipc::endpoint::Listener;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActorId, RequestId, SessionId};
use kr_protocol::method::{Method, MethodGroup};
use kr_transfer::service::{Action, RetainedOutcome, SessionRetention, Subject};
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

/// What a caller is told when it used the wrong endpoint for a method.
pub const WRONG_ENDPOINT: &str = "this endpoint does not carry that method: attachment chunks travel on the attachment-chunk \
     endpoint and everything else on the control endpoint";

/// Returns whether one kind of stream carries a method.
///
/// The frame bound is what makes the attachment endpoint exist, and it is the only thing that
/// differs about it. Without a policy the larger bound would also admit an oversized ordinary
/// request, which the control endpoint would have refused: two endpoints with two different
/// admissions rather than one admission at two frame sizes. So each endpoint carries exactly the
/// methods its bound is for.
#[must_use]
pub fn carries(kind: StreamKind, method: Option<Method>) -> bool {
    let chunks = matches!(
        method,
        Some(Method::UploadChunk) | Some(Method::DownloadChunk)
    );
    match kind {
        StreamKind::AttachmentChunks => chunks,
        _ => !chunks,
    }
}

/// The transfer service, as the daemon holds it.
///
/// The module owns the expiry sweep and ends it when it is dropped. It does not own the
/// attachment-chunk endpoint: that listener belongs to the caller that bound it, because releasing
/// an address is something the holder of the task has to do and a dropped module cannot.
#[derive(Debug)]
pub struct TransferModule {
    service: Arc<TransferService>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Where a test stops a sweep: see [`StorePause`].
    #[cfg(test)]
    before_the_store_sweep: Arc<StorePause>,
}

/// A place a test stops a sweep: where its store work begins, once the daemon has answered it.
///
/// Unarmed, it lets every sweep through. It exists only in test builds.
#[cfg(test)]
#[derive(Debug, Default)]
struct StorePause {
    armed: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

#[cfg(test)]
impl StorePause {
    /// Stops the next sweep that gets here: the receiver hears that it has arrived, and the
    /// sender lets it go on.
    fn arm(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = std::sync::mpsc::channel();
        *self
            .armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, going));
        (arrival, go)
    }

    /// Stops here, on the sweep's own blocking thread, when a test has armed the pause.
    fn wait(&self) {
        let armed = self
            .armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, going)) = armed {
            let _ = arrived.send(());
            let _ = going.recv();
        }
    }
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
    pub async fn open(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Self> {
        // Opening the store migrates it, and recovery reads whole payloads back. Both are storage
        // work, so they run on a blocking task rather than on the daemon's reactor.
        let paths = paths.clone();
        let service = tokio::task::spawn_blocking(move || {
            let service = TransferService::open(&paths)?;
            // A publication interrupted between its two commits is resolved before anything is
            // served, so a handle never names a file this daemon has not found.
            service.recover()?;
            Ok::<_, kr_transfer::TransferError>(service)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the transfer service could not be opened".to_owned(),
        })?
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: error.to_string(),
        })?;
        Ok(Self {
            service: Arc::new(service),
            tasks: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            before_the_store_sweep: Arc::default(),
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
    ///
    /// `admission` is as [`Self::write`].
    #[must_use]
    pub async fn write_frame<A>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: A,
    ) -> ControlFrame
    where
        A: Fn() -> std::result::Result<(), ProtocolError> + Send + 'static,
    {
        frame(
            mutation.request_id,
            self.write(actor_id, mutation, method, admission).await,
        )
    }

    /// Checks that a mutation's envelope names the subject its stored object belongs to.
    ///
    /// An action target cannot carry a transfer, so the parameters name the transfer or the draft
    /// and the envelope names the session. Neither proves the other, which leaves a request able to
    /// address session A while acting on an object that belongs to session B: the receipt would
    /// name a session the effect never touched. Ownership does not catch it, because both are the
    /// same principal's. The stored subject is the authority, and this is where the two are
    /// compared.
    /// This is a read, and it waits: for a blocking thread and for the journal's lock. So the
    /// caller runs it *before* the admission check, and the admission check is the last thing
    /// between a mutation and its effect.
    pub async fn check_subject_of_record(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Answer<()> {
        let Some(subject) = subject_of(&mutation.params, method)? else {
            // `upload.begin` and `draft.create` allocate their subject, so there is nothing stored
            // to compare with; `check_subject` compares their parameters instead.
            return Ok(());
        };
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let stored = blocking(move || Ok(service.stored_subject(&actor, subject)?)).await?;
        if stored.environment_id != mutation.target.environment_id {
            return Err(ProtocolError::new(
                ErrorCode::EnvironmentUnavailable,
                "this object belongs to another environment",
            ));
        }
        // An object bound to a session is acted on by a request that names that session. A
        // target that names none would otherwise produce a receipt against the environment for an
        // effect on a session, and one that names another session would name the wrong one.
        if stored.session_id.is_some() && mutation.target.session_id.0 != stored.session_id {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "this object belongs to a session, and the request's target does not name it",
            ));
        }
        if mutation.target.session_id.0.is_some()
            && mutation.target.session_id.0 != stored.session_id
        {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the request's target and the object it acts on name different sessions",
            ));
        }
        if stored.application_instance_id.is_some()
            && mutation.target.application_instance_id.0 != stored.application_instance_id
        {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "this object belongs to an application, and the request's target does not name it",
            ));
        }
        if mutation.target.application_instance_id.0.is_some()
            && mutation.target.application_instance_id.0 != stored.application_instance_id
        {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the request's target and the object it acts on name different applications",
            ));
        }
        Ok(())
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
    /// `admission` is the daemon's answer to whether the admission the mutation was accepted under
    /// still stands. It is asked inside the blocking work, once no retained record has answered
    /// and immediately before the action, the way the project service asks it.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code, or the admission's
    /// refusal.
    pub async fn write<A>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: A,
    ) -> Answer<ParamsValue>
    where
        A: Fn() -> std::result::Result<(), ProtocolError> + Send + 'static,
    {
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
            // Nothing retained, so this is a first admission and it is about to act. The admission
            // is asked here rather than before the blocking task started: the task had to be
            // scheduled and the journal read, both of which wait, and a first admission may not
            // begin while this host owes a fence it could not raise, under a registration it has
            // withdrawn or replaced, or after its deadline. The refusal is not retained, so the
            // same action submitted again under a window that still stands is decided again. A
            // retry of a completed action never reaches this, because the record above answered
            // it. What this does not cover is the service's own lock and transaction, which each
            // action takes inside the call below.
            admission()?;
            // The action this mutation is performed under. The three methods whose idempotency is
            // their own identifier commit it beside the state they change, which is what makes a
            // crash between the mutation and its record impossible.
            let performed = Action {
                actor_id: actor.clone(),
                action_id,
                method: name.to_owned(),
                payload_digest: digest,
            };
            // Every arm runs inside a closure, so a refusal the service decided reaches the
            // retention below instead of returning from the task. An action whose failure was not
            // retained could be performed again under the same identifier and succeed.
            let outcome = (|| -> Answer<ParamsValue> {
                match method {
                    Method::UploadBegin => {
                        encode(&service.upload_begin(&actor, &typed(&params)?, Some(&performed))?)
                    }
                    Method::UploadChunk => {
                        encode(&service.upload_chunk(&actor, &typed(&params)?, Some(&performed))?)
                    }
                    Method::UploadFinish => encode(&service.upload_finish(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    Method::UploadCancel => encode(&service.upload_cancel(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    Method::DraftCreate => {
                        encode(&service.draft_create(&actor, &typed(&params)?, Some(&performed))?)
                    }
                    Method::DraftUpdate => {
                        encode(&service.draft_update(&actor, &typed(&params)?, Some(&performed))?)
                    }
                    Method::AgentDraftAddAttachment => encode(&service.draft_add_attachment(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    _ => Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "{} is not a transfer mutation this daemon serves",
                            method.as_str()
                        ),
                    )),
                }
            })();
            // The outcome is retained before it is returned, so the reply and the record cannot
            // disagree about what happened. The three methods above recorded their own inside
            // their transaction; this insert leaves an existing row alone and covers the rest.
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
            // Recorded before it is returned, so the reply and the record cannot disagree about
            // what happened. When another copy of this action recorded first, that record is the
            // answer both callers get: one action, one receipt.
            match service.record_action(&actor, action_id, name, digest, &record)? {
                None => outcome,
                Some(RetainedOutcome::Ok(result)) => {
                    kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                        .map(ParamsValue::new)
                        .map_err(|error| {
                            ProtocolError::new(ErrorCode::OutcomeUnknown, error.to_string())
                        })
                }
                Some(RetainedOutcome::Error { code, detail }) => {
                    Err(ProtocolError::new(code, detail))
                }
            }
        })
        .await
    }

    /// Expires everything whose retention has run out, under the archive's view of its sessions.
    ///
    /// The daemon is asked one question, which sessions its registry still knows about, and is
    /// held for that and for nothing else: not while the sweep waits for a blocking thread, and not
    /// while the store sweeps. The sweep is the daemon's own background work, and it must never be
    /// what keeps a daemon, and its environment's lock, alive once the daemon's owner has let it go.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, and [`ErrorCode::ResourceUnavailable`] when the
    /// daemon has gone before the sweep could ask it.
    pub async fn sweep(&self, daemon: &Weak<Controller>) -> Answer<Sweep> {
        // The registry scan and the sweep are both storage work, so both run on the same blocking
        // task. Reading the registry means holding its lock, and that lock is a task-aware one, so
        // it is taken in its blocking form *inside* the blocking task rather than awaited on the
        // reactor and handed over.
        let daemon = Weak::clone(daemon);
        let service = Arc::clone(&self.service);
        #[cfg(test)]
        let pause = Arc::clone(&self.before_the_store_sweep);
        blocking(move || {
            // The archive is the authority on what a session keeps. The sweep still asks one
            // question through one interface; what changed is which store answers it.
            let retention = {
                let owner = daemon.upgrade().ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::ResourceUnavailable,
                        "the daemon this sweep was for has stopped",
                    )
                })?;
                owner
                    .archive_retention()
                    .map_err(|error| error.to_protocol_error())?
            };
            #[cfg(test)]
            pause.wait();
            service.sweep(&retention).map_err(Into::into)
        })
        .await
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
    /// This is a synchronous read of the registry's own store, so it is called from a blocking
    /// task: the lock is taken in its blocking form, which is only correct off the reactor.
    pub fn session_retention(&self) -> Result<RegistryRetention> {
        let registry = self.registry_handle().blocking_lock();
        let mut retention = RegistryRetention::default();
        for phase in EVERY_PHASE {
            for reservation in registry.reservations_in(*phase)? {
                retention.insert(reservation.session_id);
            }
        }
        Ok(retention)
    }
}

/// Starts the environment's expiry sweep.
///
/// The sweep holds the daemon weakly and asks it only the one question it needs answered
/// ([`TransferModule::sweep`]), so it never keeps the daemon alive, and it stops when the daemon
/// goes. The attachment-chunk endpoint is served by whoever runs the daemon ([`serve_chunks`]).
///
/// # Errors
///
/// Returns [`ControllerError::Ipc`] when the endpoint cannot be bound.
pub fn serve(controller: &Arc<Controller>) -> Result<()> {
    let sweeps = Arc::downgrade(controller);
    let started = tokio::spawn(async move {
        sweep_forever(sweeps).await;
    });
    let mut tasks = controller.transfer().tasks.lock().map_err(|_| {
        ControllerError::NotConfigured(
            "the transfer service's task list was left poisoned by an earlier failure".to_owned(),
        )
    })?;
    tasks.push(started);
    Ok(())
}

/// Binds the environment's attachment-chunk endpoint.
///
/// The caller owns the listener and the task that serves it, so it can release the address at a
/// moment it decides: an in-process restart binds the same endpoint again, and a bind that finds a
/// live listener there is refused rather than silently sharing it.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the endpoint cannot be addressed, or the bind
/// failure when the address is taken.
pub fn bind_chunk_endpoint(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Listener> {
    let endpoint = kr_transfer::chunks::chunk_endpoint(paths).map_err(|error| {
        ControllerError::NotConfigured(format!(
            "the attachment-chunk endpoint cannot be addressed: {error}"
        ))
    })?;
    Ok(Listener::bind(&endpoint)?)
}

/// Accepts attachment-chunk connections until the daemon goes.
///
/// An accept that fails ends the loop, as it does on the control endpoint: a listener that cannot
/// accept has nothing left to serve, and spinning on it would hide that.
/// Serves the attachment-chunk endpoint until the listener fails or this task is stopped.
///
/// The reference to the daemon is weak so that serving an endpoint does not keep a daemon alive.
/// The listener belongs to this task, which means the address is released when whoever spawned it
/// stops it and not before.
pub async fn serve_chunks(controller: Weak<Controller>, listener: Listener) {
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
///
/// What it holds through a sweep is the transfer module, never the daemon: a daemon let go while a
/// sweep waits or runs is gone at once, and the sweep finds it gone when it asks.
async fn sweep_forever(daemon: Weak<Controller>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let Some(transfer) = daemon
            .upgrade()
            .map(|controller| Arc::clone(controller.transfer()))
        else {
            return;
        };
        let _ = transfer.sweep(&daemon).await;
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

fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

/// Returns the stored object a transfer mutation acts on, where it names one.
fn subject_of(params: &ParamsValue, method: Method) -> Answer<Option<Subject>> {
    Ok(match method {
        Method::UploadChunk => {
            let params: kr_protocol::transfer::UploadChunkParams = typed(params)?;
            Some(Subject::Transfer(params.transfer_id))
        }
        Method::UploadFinish => {
            let params: kr_protocol::transfer::UploadFinishParams = typed(params)?;
            Some(Subject::Transfer(params.transfer_id))
        }
        Method::UploadCancel => {
            let params: kr_protocol::transfer::UploadCancelParams = typed(params)?;
            Some(Subject::Transfer(params.transfer_id))
        }
        Method::DraftUpdate => {
            let params: kr_protocol::transfer::DraftUpdateParams = typed(params)?;
            Some(Subject::Draft(params.draft_id))
        }
        Method::AgentDraftAddAttachment => {
            let params: kr_protocol::transfer::AgentDraftAddAttachmentParams = typed(params)?;
            Some(Subject::Draft(params.draft_id))
        }
        _ => None,
    })
}

fn typed<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Answer<T> {
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

    /// A sweep that has begun holds its daemon until its store work ends. The daemon's hold on its
    /// environment is what keeps a daemon started after it from opening the transfer store while
    /// this sweep still works on it, so for as long as the sweep works, every daemon started on the
    /// environment is refused; once it ends, one is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sweep_that_has_begun_keeps_its_daemon_until_its_store_work_ends() {
        use crate::service::net::tests::{daemon, setup, started};

        let temp = kr_ipc::testing::TempHost::create();
        let boot_identity = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller = daemon(&temp).await;
        let held = Arc::downgrade(&controller);

        // The next sweep to begin stops where its store work starts, and says so.
        let (arrived, go) = controller.transfer().before_the_store_sweep.arm();
        let swept = {
            let transfer = Arc::clone(controller.transfer());
            let daemon = Weak::clone(&held);
            tokio::spawn(async move { transfer.sweep(&daemon).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
            .await
            .expect("a sweep reaches its store work in time")
            .expect("the sweep says it has arrived");

        // The daemon is let go while that sweep works on the store.
        drop(controller);
        for _ in 0..25 {
            match Controller::start(setup(&temp, boot_identity.clone())).await {
                Err(ControllerError::AlreadyRunning { .. }) => {}
                Ok(_) => panic!(
                    "a daemon took the environment while an earlier daemon's sweep worked on its store"
                ),
                Err(error) => panic!("a daemon was refused for another reason: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(held.strong_count() > 0, "the sweep still holds its daemon");

        // Once the sweep ends, its daemon goes, and another daemon takes the environment.
        let _ = go.send(());
        swept
            .await
            .expect("the sweep's task ends")
            .expect("the sweep runs");
        drop(started(|| Controller::start(setup(&temp, boot_identity.clone()))).await);
    }

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
