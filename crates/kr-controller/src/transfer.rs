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
//! retention still covers, which the archive answers ([`Controller::archive_retention`]), and when
//! to sweep.
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
use kr_protocol::scalars::TimestampMs;
use kr_transfer::service::{Action, RetainedOutcome, Subject};
use kr_transfer::{Sweep, TransferService};

use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// How often the daemon sweeps expired transfers.
///
/// Every window the sweep enforces is measured in hours or days, so an hour is frequent enough to
/// keep the staging area honest and rare enough that it costs nothing.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

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

/// What an exact repeat that arrived with no usable window is owed ([`TransferModule::settles`]).
#[derive(Debug)]
pub enum Settling {
    /// Its action claimed an effect that is not finished: the service finishes it.
    Open,
    /// Its action's claim was settled, and this is the answer it was settled with.
    Answered(ControlFrame),
    /// Its action claimed nothing here, so the repeat is a first admission and has no window.
    No,
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
    /// Where this host's own tests stop a mutation that has passed the daemon's own check and not
    /// yet entered the service, so that its admission can lapse there and the service's own question
    /// is what refuses it. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    after_the_outer_check: Arc<crate::attention::Pause>,
}

/// The admission one transfer mutation arrived under, as the transfer service asks about it.
///
/// Every answer is the check each service asks from inside the work a mutation has begun,
/// [`Controller::check_registration`]: a fence this host owes and could not raise, then the
/// connection's registration under the revision the mutation was admitted at, then the accepted
/// deadline. The service asks it where the mutation begins an effect, with its own lock held, and
/// runs each commit through [`Controller::under_registration`], so the connection table, which a
/// withdrawal takes, is held from the check to the end of the commit. The refusal the check gave is
/// kept, so that [`TransferModule::write`] can answer with it and not retain it.
pub struct TransferAdmission {
    controller: Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
    /// True for an exact repeat that carries no freshness: it may finish what its action already
    /// claimed and may begin nothing.
    settling: bool,
    refusal: std::sync::Mutex<Option<ProtocolError>>,
}

impl TransferAdmission {
    pub(crate) fn new(
        controller: Arc<Controller>,
        carried: crate::authority::AdmittedMutation,
    ) -> Arc<Self> {
        Arc::new(Self {
            controller,
            carried,
            settling: false,
            refusal: std::sync::Mutex::new(None),
        })
    }

    /// The admission of an exact repeat that carries no freshness.
    ///
    /// The connection's registration and the fence this host owes are asked as for any mutation. A
    /// deadline is not, because the repeat began nothing: its action claimed its effect under an
    /// admission that stood then, and what is left is to finish it. Every question the service asks
    /// where an effect begins is refused, so a repeat that turned out to need a new effect writes
    /// nothing.
    pub(crate) fn settling(
        controller: Arc<Controller>,
        carried: crate::authority::AdmittedMutation,
    ) -> Arc<Self> {
        Arc::new(Self {
            controller,
            carried: crate::authority::AdmittedMutation {
                deadline: None,
                ..carried
            },
            settling: true,
            refusal: std::sync::Mutex::new(None),
        })
    }

    /// The refusal of a first admission that carries no freshness.
    fn without_freshness() -> ControllerError {
        ControllerError::WindowExpired {
            detail: "this action carries no freshness, so it may finish what it has already begun \
                     and may not begin anything"
                .to_owned(),
        }
    }

    /// Asks the check, and keeps its refusal.
    fn check(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .check_registration(&self.carried)
            .map_err(|error| self.refused(&error))
    }

    /// Asks the check a retained answer is owed before it goes back: a fence this host owes, and the
    /// registration under the revision the mutation was admitted at, without the deadline a receipt
    /// outlives. The refusal is not kept: a retained answer is not retained again.
    fn check_retained(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .check_registration(&crate::authority::AdmittedMutation {
                deadline: None,
                ..self.carried
            })
            .map_err(|error| error.to_protocol_error())
    }

    fn refused(&self, error: &ControllerError) -> ProtocolError {
        let refusal = error.to_protocol_error();
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| refusal.clone());
        refusal
    }

    /// The first refusal the check gave, when it gave one.
    fn refusal(&self) -> Option<ProtocolError> {
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl kr_transfer::service::AdmissionHook for TransferAdmission {
    fn ask(&self) -> std::result::Result<(), ProtocolError> {
        if self.settling {
            return Err(self.refused(&Self::without_freshness()));
        }
        self.check()
    }

    fn run(&self, commit: &mut dyn FnMut()) -> std::result::Result<(), ProtocolError> {
        if self.settling {
            return Err(self.refused(&Self::without_freshness()));
        }
        self.controller
            .under_registration(&self.carried, commit)
            .map_err(|error| self.refused(&error))
    }
}

/// Where a test stops one sweep or one closure's write. A sweep stops once the archive has
/// answered which sessions retain, and before the sweep is given the answer. A closure's write
/// stops once its store call has returned, and before it lets the daemon go.
///
/// Either carries one only when a test asked for it ([`TransferModule::sweep_paused`],
/// [`TransferModule::session_ended_paused`]), so the daemon's own never stop. It exists only for
/// this crate's unit tests.
#[cfg(test)]
#[derive(Debug)]
struct StorePause {
    arrived: tokio::sync::oneshot::Sender<()>,
    go: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl StorePause {
    /// Says the stopped work has arrived, and waits on its blocking thread until the test lets it go.
    fn wait(self) {
        let _ = self.arrived.send(());
        let _ = self.go.recv();
    }
}

/// What the archive answers when the sweep asks which sessions still retain what was submitted to
/// them.
///
/// The archive is read when it is asked, which is after the sweep has read the attachments, so a
/// session an attachment names was already known to this host when the archive is read.
struct ArchiveAnswers<'a> {
    owner: &'a Arc<Controller>,
    /// The stop a test asked this sweep for, taken once the archive has answered.
    #[cfg(test)]
    pause: std::sync::Mutex<Option<StorePause>>,
    /// The stop a test asked this sweep for at the clock question, taken once the sweep has read
    /// the time and before the host answers whether it can prove it.
    #[cfg(test)]
    at_the_clock: std::sync::Mutex<Option<StorePause>>,
}

impl kr_transfer::SessionRetention for ArchiveAnswers<'_> {
    fn retained(
        &self,
        sessions: &std::collections::BTreeSet<SessionId>,
    ) -> kr_transfer::Result<std::collections::BTreeSet<SessionId>> {
        let view = self.owner.archive_retention().map_err(|error| {
            kr_transfer::TransferError::RetentionUnavailable {
                detail: error.to_string(),
            }
        })?;
        #[cfg(test)]
        if let Some(pause) = self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            pause.wait();
        }
        Ok(sessions
            .iter()
            .copied()
            .filter(|session_id| view.retains(*session_id))
            .collect())
    }

    fn clock_is_proven(&self, reading: TimestampMs) -> bool {
        #[cfg(test)]
        if let Some(pause) = self
            .at_the_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            pause.wait();
        }
        // The host's own reading is settled first: the floor is raised to it and written down, so
        // the check covers the reading the sweep counts its retentions from.
        self.owner.settled_now_ms();
        self.owner.lifetimes().may_forget_at(reading.get())
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

/// The daemon's own wall clock, as the transfer service reads the time.
///
/// The service stamps its records and the deadlines of what it holds from this, so they are on the
/// clock the host's time contract decides about and not on one of the service's own.
#[derive(Debug)]
struct DaemonWall(crate::service::WallClock);

impl kr_transfer::Clock for DaemonWall {
    fn now_ms(&self) -> TimestampMs {
        TimestampMs::new(self.0.now_ms())
    }
}

impl TransferModule {
    /// Opens the environment's transfer service on the daemon's wall clock, and resolves whatever
    /// an earlier daemon left unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store or the staging area cannot
    /// be prepared.
    pub async fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        wall: crate::service::WallClock,
    ) -> Result<Self> {
        // Opening the store migrates it, and recovery reads whole payloads back. Both are storage
        // work, so they run on a blocking task rather than on the daemon's reactor.
        let paths = paths.clone();
        let service = tokio::task::spawn_blocking(move || {
            let service = TransferService::with_clock(&paths, Arc::new(DaemonWall(wall)))?;
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
            #[cfg(feature = "testing")]
            after_the_outer_check: Arc::new(crate::attention::Pause::default()),
        })
    }

    /// Arms the pause a mutation, or the record of the draft a prompt names, stops at once it has
    /// passed the daemon's own check, before it enters the transfer service. Returns the end that
    /// says it has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_the_outer_check(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_the_outer_check.arm()
    }

    /// Returns the service itself.
    #[must_use]
    pub fn service(&self) -> &Arc<TransferService> {
        &self.service
    }

    /// Queues the end of the insertions the agent of `session_id` never confirmed, because the
    /// session's worker has ended ([`TransferService::end_session_insertions`]).
    ///
    /// The write is queued on a blocking thread as it is asked for, and the answer returned here
    /// holds nothing of the daemon. While the write waits for its thread it holds the daemon
    /// weakly, so a daemon let go meanwhile goes at once, and the write, when its turn comes, does
    /// nothing: the next start ends the insertions of every closure the registry holds. Once the
    /// write runs, it holds the daemon until it is done, because the daemon's hold on its
    /// environment is what keeps a daemon started after it from opening the journal while this
    /// write still works on it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the journal cannot be written. The
    /// sweep records every closure as ended again, so a session whose end was recorded before the
    /// write failed does not keep its insertions for good.
    pub fn session_ended(
        &self,
        daemon: &Weak<Controller>,
        session_id: SessionId,
    ) -> impl Future<Output = Result<()>> + Send + use<> {
        self.queue_session_ended(
            daemon,
            session_id,
            #[cfg(test)]
            None,
        )
    }

    /// Queues the end of a closed session's insertions as an ordinary one is, and stops it once
    /// its store work is done and before it lets the daemon go, until the test lets it go: the
    /// receiver hears it arrive there, and the sender lets it go on.
    #[cfg(test)]
    pub(crate) fn session_ended_paused(
        &self,
        daemon: &Weak<Controller>,
        session_id: SessionId,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        impl Future<Output = Result<()>> + Send + use<>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = std::sync::mpsc::channel();
        let pause = StorePause { arrived, go: going };
        (
            arrival,
            go,
            self.queue_session_ended(daemon, session_id, Some(pause)),
        )
    }

    /// Queues the end [`TransferModule::session_ended`] describes. In this crate's unit tests it
    /// carries the pause a test asked for, if any, and stops there.
    fn queue_session_ended(
        &self,
        daemon: &Weak<Controller>,
        session_id: SessionId,
        #[cfg(test)] pause: Option<StorePause>,
    ) -> impl Future<Output = Result<()>> + Send + use<> {
        let daemon = Weak::clone(daemon);
        let service = Arc::clone(&self.service);
        let ended = tokio::task::spawn_blocking(move || {
            let Some(owner) = daemon.upgrade() else {
                return Ok(0);
            };
            let ended =
                service.end_session_insertions(&std::collections::BTreeSet::from([session_id]));
            #[cfg(test)]
            if let Some(pause) = pause {
                pause.wait();
            }
            drop(owner);
            ended
        });
        async move {
            ended
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the transfer service could not end a closed session's insertions"
                        .to_owned(),
                })?
                .map(|_| ())
                .map_err(|error| ControllerError::RegistryUnavailable {
                    detail: error.to_string(),
                })
        }
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

    /// Says what an exact repeat of a transfer action that arrived with no usable window is owed.
    ///
    /// A publication and a cancellation are two commits with a claim recorded by the first. A
    /// repeat of such an action finishes what the claim began, which is no first admission and
    /// needs no deadline of its own: a repeat is the original request, window included, and on a
    /// replacement connection that window is one this connection never issued. What the caller is
    /// owed is the effect, not a refusal about a window the action was admitted under.
    ///
    /// A claim moves from open to settled and never back, so a claim that is no longer open is read
    /// once more for the answer it was settled with.
    pub async fn settles(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Settling {
        let Ok(digest) = kr_protocol::digest::mutation_digest(mutation, actor_id) else {
            return Settling::No;
        };
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        let open =
            blocking(move || Ok(service.claim_is_open(&actor, action_id, name, digest)?)).await;
        if open == Ok(true) {
            return Settling::Open;
        }
        match self.retained(actor_id, mutation, method).await {
            Some(answer) => Settling::Answered(answer),
            None => Settling::No,
        }
    }

    /// Records that a prompt sends a draft to a session, which moves the draft's attachments, and
    /// any it gets later, from the seven-day window of an unused attachment onto that session's
    /// retention.
    ///
    /// It runs before the prompt is forwarded to the session's worker, so that nothing the worker
    /// does or fails to do afterwards decides whether a file this host was asked to hand to a
    /// session is kept. A draft is sent to one session, so a repeat of the prompt has nothing left
    /// to record. A draft this actor does not hold has no attachments for this host to retain, so
    /// naming one is not a failure.
    ///
    /// The record is a write, so it is made under the admission the prompt arrived under, asked
    /// where the service takes its own lock and again around the commit: a prompt whose deadline
    /// passed or whose registration was withdrawn while it waited records nothing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, other than for a draft it does not hold: among
    /// them a draft that is for another session, or holds an attachment that belongs to one, a
    /// session that has ended (`SESSION_CLOSED`), and an admission that no longer stands.
    pub(crate) async fn record_submission(
        &self,
        actor_id: &ActorId,
        draft_id: kr_protocol::ids::DraftId,
        session_id: SessionId,
        admission: Arc<TransferAdmission>,
    ) -> Answer<usize> {
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let admission = kr_transfer::service::Admission::new(admission);
        #[cfg(feature = "testing")]
        let after_the_outer_check = Arc::clone(&self.after_the_outer_check);
        blocking(move || {
            #[cfg(feature = "testing")]
            after_the_outer_check.wait();
            match service.record_prompt(&actor, draft_id, session_id, &admission) {
                Err(kr_transfer::TransferError::UnknownDraft { .. }) => Ok(0),
                other => Ok(other?),
            }
        })
        .await
    }

    /// Answers one question a session's worker asks about a draft, on a blocking task that a dropped
    /// connection cannot cancel part way: what it holds, a claim of one binding for an offer to the
    /// agent, or the report of the offer.
    ///
    /// A refusal is the answer the service decided, under its code, and its retry category tells
    /// the worker whether asking again can help.
    pub(crate) async fn draft_step(
        &self,
        session_id: SessionId,
        actor_id: ActorId,
        step: kr_protocol::insertion::DraftStep,
    ) -> kr_protocol::insertion::DraftAnswer {
        use kr_protocol::insertion::{DraftAnswer, DraftStep};
        let service = Arc::clone(&self.service);
        blocking(move || {
            Ok(match step {
                DraftStep::Facts { draft_id } => {
                    DraftAnswer::Facts(service.insertion_facts(&actor_id, session_id, draft_id)?)
                }
                DraftStep::Begin(begin) => DraftAnswer::Claim(Box::new(service.insertion_begin(
                    &actor_id,
                    session_id,
                    &begin,
                    &kr_ipc::clock::boot_elapsed_ms,
                )?)),
                DraftStep::Report(report) => DraftAnswer::Reported(
                    service.record_insertion_outcome(&actor_id, session_id, &report)?,
                ),
            })
        })
        .await
        .unwrap_or_else(DraftAnswer::Refused)
    }

    /// Notes every session this host knows as one whose agent may be sent a prompt that names a
    /// draft without this host being told, the first time a daemon of this build starts over a
    /// transfer journal an earlier build wrote, and notes nothing at any start after.
    ///
    /// A worker that outlived the daemon before this one is of an earlier build, and one of a build
    /// before the control daemon recorded the draft a prompt names takes such a prompt on its own
    /// socket, where this host is not told ([`kr_transfer::TransferService::note_unseen_prompt_sessions`]).
    /// At the first start of this build over such a journal every session this host knows was started
    /// by a daemon of an earlier build, and a session started by this build's daemon afterwards has a
    /// worker that refuses a draft prompt that does not come from the daemon, so noting is done once.
    /// A journal this build makes has no earlier session to note.
    ///
    /// The sessions are the registry's, in every launch phase, and the archive's: a worker that has
    /// not yet reported, one that has stopped answering and one that has ended are among them. A
    /// start that cannot note them does not go on, because no sweep may run before the host has.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the registry, the archive or the
    /// journal cannot be read or written.
    pub(crate) async fn note_sessions_of_earlier_builds(
        &self,
        owner: &Arc<Controller>,
    ) -> Result<()> {
        let service = Arc::clone(&self.service);
        let owner = Arc::clone(owner);
        let unavailable = |detail: String| ControllerError::RegistryUnavailable { detail };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let storage = |error: kr_transfer::TransferError| unavailable(error.to_string());
            if service.noting().map_err(storage)? != kr_transfer::Noting::Owed {
                return Ok(());
            }
            let known = owner.archive_retention()?.sessions();
            service.note_unseen_prompt_sessions(&known).map_err(storage)
        })
        .await
        .map_err(|_| unavailable("the sessions of earlier builds could not be noted".to_owned()))?
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
    pub(crate) async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: Arc<TransferAdmission>,
    ) -> ControlFrame {
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
    /// and immediately before the action, the way the project service asks it; and the service asks
    /// it again, inside its own lock, at each place the mutation begins an effect and around each
    /// commit that makes one durable ([`TransferAdmission`]).
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code, or the admission's
    /// refusal.
    pub(crate) async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: Arc<TransferAdmission>,
    ) -> Answer<ParamsValue> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = mutation.params.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        #[cfg(feature = "testing")]
        let after_the_outer_check = Arc::clone(&self.after_the_outer_check);
        blocking(move || {
            if let Some(retained) = service.retained_action(&actor, action_id, name, digest)? {
                // Found here, after the lookup the local door made before it considered a first
                // admission: another attempt may have recorded it since. It goes back under the
                // same check, asked once the answer is in hand.
                admission.check_retained()?;
                return answer_of(retained);
            }
            // Nothing retained, so this is a first admission and it is about to act. The admission
            // is asked here rather than before the blocking task started: the task had to be
            // scheduled and the journal read, both of which wait, and a first admission may not
            // begin while this host owes a fence it could not raise, under a registration it has
            // withdrawn or replaced, or after its deadline. The refusal is not retained, so the
            // same action submitted again under a window that still stands is decided again. A
            // retry of a completed action never reaches this, because the record above answered
            // it. The service asks again inside its own lock and around each commit, because
            // taking the lock and opening the transaction wait as well.
            // An exact repeat that carries no freshness is only ever allowed to finish an effect
            // its action already claimed, which is the one thing a lapsed window does not take
            // from it. Anything else it asks for is a first admission, and has none.
            if admission.settling && !service.claim_is_open(&actor, action_id, name, digest)? {
                // A claim moves from open to settled and never back, so one that is not open
                // now and was when the lookup above found it open has been settled since, and
                // what it was settled with is the answer.
                if let Some(retained) = service.retained_action(&actor, action_id, name, digest)? {
                    admission.check_retained()?;
                    return answer_of(retained);
                }
                return Err(admission.refused(&TransferAdmission::without_freshness()));
            }
            admission.check()?;
            #[cfg(feature = "testing")]
            after_the_outer_check.wait();
            // The action this mutation is performed under. The three methods whose idempotency is
            // their own identifier commit it beside the state they change, which is what makes a
            // crash between the mutation and its record impossible.
            let performed = Action {
                actor_id: actor.clone(),
                action_id,
                method: name.to_owned(),
                payload_digest: digest,
                admission: kr_transfer::service::Admission::new(admission.clone()),
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
            // An admission that no longer stood where the service asked it wrote nothing, and what
            // it says is about this attempt: it is the answer to this call and is not retained, so
            // the same action under an admission that stands is decided as a first admission.
            if let Some(refusal) = admission.refusal() {
                debug_assert!(outcome.is_err(), "a refused admission performed the action");
                return Err(refusal);
            }
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
    /// The sweep is queued on a blocking thread as it is asked for, and the answer returned here
    /// holds nothing of the daemon or of this module. While the sweep waits for its thread it holds
    /// the daemon weakly, so a daemon let go meanwhile goes at once, and the sweep, when its turn
    /// comes, does nothing. Once the sweep runs, it holds the daemon until its store work ends: the
    /// daemon's hold on its environment is what keeps a daemon started after it from opening the
    /// store while this sweep still works on it, and two services working on one store at once
    /// would each act on rows the other is changing.
    ///
    /// # Errors
    ///
    /// The answer is the refusal the service decided, [`ErrorCode::ResourceUnavailable`] when the
    /// daemon had gone before the sweep's turn came, or [`ErrorCode::OutcomeUnknown`] when the
    /// blocking task could not report.
    pub fn sweep(
        &self,
        daemon: &Weak<Controller>,
    ) -> impl Future<Output = Answer<Sweep>> + Send + use<> {
        self.queue_sweep(
            daemon,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
    }

    /// Queues a sweep as [`TransferModule::sweep`] does, one that stops once the archive has said
    /// which sessions retain, until the test lets it go: the receiver hears it arrive there, and
    /// the sender lets it go on.
    #[cfg(test)]
    pub(crate) fn sweep_paused(
        &self,
        daemon: &Weak<Controller>,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        impl Future<Output = Answer<Sweep>> + Send + use<>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = std::sync::mpsc::channel();
        let pause = StorePause { arrived, go: going };
        (arrival, go, self.queue_sweep(daemon, Some(pause), None))
    }

    /// Queues a sweep as [`TransferModule::sweep`] does, one that stops at its first clock
    /// question, after it has read the time and before the host answers, until the test lets it
    /// go: the receiver hears it arrive there, and the sender lets it go on.
    #[cfg(test)]
    pub(crate) fn sweep_paused_at_the_clock(
        &self,
        daemon: &Weak<Controller>,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        impl Future<Output = Answer<Sweep>> + Send + use<>,
    ) {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (go, going) = std::sync::mpsc::channel();
        let pause = StorePause { arrived, go: going };
        (arrival, go, self.queue_sweep(daemon, None, Some(pause)))
    }

    /// Queues the sweep [`TransferModule::sweep`] describes. In this crate's unit tests it carries
    /// the pause a test asked for, if any, and stops there.
    fn queue_sweep(
        &self,
        daemon: &Weak<Controller>,
        #[cfg(test)] pause: Option<StorePause>,
        #[cfg(test)] at_the_clock: Option<StorePause>,
    ) -> impl Future<Output = Answer<Sweep>> + Send + use<> {
        // The registry scan and the sweep are both storage work, so both run on the same blocking
        // task. Reading the registry means holding its lock, and that lock is a task-aware one, so
        // it is taken in its blocking form *inside* the blocking task rather than awaited on the
        // reactor and handed over.
        let daemon = Weak::clone(daemon);
        let service = Arc::clone(&self.service);
        answer(tokio::task::spawn_blocking(move || {
            let owner = daemon.upgrade().ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    "the daemon this sweep was for has stopped",
                )
            })?;
            // The sessions of earlier builds that nothing can still send a prompt are settled
            // first, so the sweep that follows reads none of them. A settling that cannot be made
            // is tried again at the next sweep, and this sweep reads the noted sessions as they
            // stand, so it never stops an expiry.
            let _ = settle_the_sessions_of_earlier_builds(&service, &owner);
            // The archive is the authority on what a session keeps. The sweep asks it once, after
            // it has read the attachments, so the answer is a view taken after them.
            let answers = ArchiveAnswers {
                owner: &owner,
                #[cfg(test)]
                pause: std::sync::Mutex::new(pause),
                #[cfg(test)]
                at_the_clock: std::sync::Mutex::new(at_the_clock),
            };
            let swept = service.sweep(&answers).map_err(Into::into);
            // A closure whose insertions were not ended, because its write failed, has them ended
            // here, and the session is refused from here on. A failure is left for the next sweep.
            let _ = end_insertions_of_every_closure(&owner, &service);
            // Only now may the daemon go, and its environment with it.
            drop(owner);
            swept
        }))
    }
}

/// Ends the noting of the sessions of earlier builds once none of them can run a worker
/// ([`TransferService::note_unseen_prompt_sessions`]), which puts what each names under its
/// retention and forgets the sessions ([`TransferService::settle_unseen_prompt_sessions`]).
///
/// The noting was made because a worker of an earlier build may take a draft prompt this host is not
/// told of. A session that cannot run a worker cannot be sent one, so what it names is all it will
/// name. The registry is asked only while sessions are noted, and a registry that cannot be read
/// leaves them noted. Settling removes the noting from the journal, so a journal that holds none
/// costs a sweep one read.
fn settle_the_sessions_of_earlier_builds(
    service: &TransferService,
    owner: &Controller,
) -> kr_transfer::Result<()> {
    if service.noting()? != kr_transfer::Noting::Held {
        return Ok(());
    }
    let noted = service.unseen_prompt_sessions()?;
    if !noted.is_empty() {
        let running = sessions_that_may_run_a_worker(owner, &noted).map_err(|error| {
            kr_transfer::TransferError::RetentionUnavailable {
                detail: error.to_string(),
            }
        })?;
        if !running.is_empty() {
            return Ok(());
        }
    }
    service.settle_unseen_prompt_sessions()?;
    Ok(())
}

/// Returns those of `sessions` whose worker may still be running.
///
/// A session whose closure is recorded has none, and neither has one whose launch failed or one the
/// registry has no record of, which only the archive remembers. Any other session has a worker until
/// the kernel says the process the registry recorded for it has ended: the worker's own record where
/// there is one, otherwise the launcher's. That covers a launch that was fenced, which never reaches
/// a closure record because its worker is never admitted. A process the kernel cannot be asked
/// about, and one the registry records no process for, may be running.
fn sessions_that_may_run_a_worker(
    owner: &Controller,
    sessions: &std::collections::BTreeSet<SessionId>,
) -> Result<std::collections::BTreeSet<SessionId>> {
    use crate::registry::LaunchPhase;

    let mut candidates = Vec::new();
    {
        let registry = owner.registry_handle().blocking_lock();
        let workers = registry.workers()?;
        for session_id in sessions {
            if registry.closure(*session_id)?.is_some() {
                continue;
            }
            let reservation = registry.reservation_for_session(*session_id)?;
            let worker = workers.iter().find(|row| row.session_id == *session_id);
            let launch_over = reservation
                .as_ref()
                .is_some_and(|row| matches!(row.phase, LaunchPhase::Failed | LaunchPhase::Closed));
            if worker.is_none() && (reservation.is_none() || launch_over) {
                continue;
            }
            let process = worker
                .map(|row| row.process_identity.clone())
                .or_else(|| reservation.and_then(|row| row.launcher_identity));
            candidates.push((*session_id, process));
        }
    }
    Ok(candidates
        .into_iter()
        .filter(|(_, process)| {
            process.as_ref().is_none_or(|identity| {
                kr_ipc::identity::process_state(identity) != kr_ipc::identity::ProcessState::Ended
            })
        })
        .map(|(session_id, _)| session_id)
        .collect())
}

/// Records every session the registry holds a closure for as ended, and fails the insertions the
/// agents of those sessions never confirmed ([`TransferService::end_session_insertions`]).
///
/// This is how a closure is acted on whatever happened to the write that followed it: the daemon
/// stopped between the two, or the write failed. The registry's closures are the record, and what
/// the transfer journal holds is made to agree with them.
///
/// # Errors
///
/// Returns [`ControllerError::RegistryUnavailable`] when the registry cannot be read or the
/// journal cannot be written.
fn end_insertions_of_every_closure(owner: &Controller, service: &TransferService) -> Result<()> {
    let closed = owner
        .registry_handle()
        .blocking_lock()
        .closed_sessions()?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    service
        .end_session_insertions(&closed)
        .map(|_| ())
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: error.to_string(),
        })
}

/// Ends the insertions of every closure the registry holds before the daemon serves a transfer,
/// so a closure recorded by a daemon that stopped before it acted on it refuses a binding for
/// that session from the first request.
///
/// # Errors
///
/// Returns [`ControllerError::RegistryUnavailable`] when the registry or the transfer journal
/// cannot be read or written; the start does not go on then, as it does not for the sessions of
/// earlier builds.
pub async fn end_the_insertions_of_closed_sessions(controller: &Arc<Controller>) -> Result<()> {
    let owner = Arc::clone(controller);
    let service = Arc::clone(controller.transfer().service());
    tokio::task::spawn_blocking(move || end_insertions_of_every_closure(&owner, &service))
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the transfer service could not end a closed session's insertions".to_owned(),
        })?
}

/// Starts the environment's expiry sweep.
///
/// The sweep holds the daemon weakly between sweeps and while a sweep waits for its thread, and
/// strongly only while a sweep runs ([`TransferModule::sweep`]). A daemon whose owner lets it go
/// therefore lives on for one running sweep at most, and the sweep stops once the daemon has gone.
/// The attachment-chunk endpoint is served by whoever runs the daemon ([`serve_chunks`]).
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the transfer service's task list was left
/// poisoned by an earlier failure.
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
/// It holds nothing of the daemon across an await: the upgrade only asks the module for a sweep,
/// and the answer it then waits for holds neither the daemon nor the module.
async fn sweep_forever(daemon: Weak<Controller>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let Some(swept) = daemon
            .upgrade()
            .map(|controller| controller.transfer().sweep(&daemon))
        else {
            return;
        };
        let _ = swept.await;
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
    answer(tokio::task::spawn_blocking(work)).await
}

/// What work queued on a blocking task answered, or that it could not say.
async fn answer<T>(queued: tokio::task::JoinHandle<Answer<T>>) -> Answer<T> {
    queued.await.unwrap_or_else(|_| {
        Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "the transfer service could not report what happened to this action",
        ))
    })
}

/// What a retained outcome answers with.
fn answer_of(retained: RetainedOutcome) -> Answer<ParamsValue> {
    match retained {
        RetainedOutcome::Ok(result) => kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
            .map(ParamsValue::new)
            .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())),
        RetainedOutcome::Error { code, detail } => Err(ProtocolError::new(code, detail)),
    }
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

/// The draft a prompt names, when the mutation is a prompt that names a draft.
///
/// A queued prompt counts with a submitted one: the session's agent holds it from the moment the
/// worker takes it and may run it long after, and this host is not told when it does.
pub(crate) fn prompted_draft(mutation: &MutationRequest) -> Option<kr_protocol::ids::DraftId> {
    if !matches!(
        mutation.method.method(),
        Some(Method::AgentPromptSubmit | Method::AgentPromptQueue)
    ) {
        return None;
    }
    mutation
        .params
        .to_typed::<kr_protocol::agent::AgentPromptParams>()
        .ok()
        .and_then(|params| params.draft_id.0)
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

        // A sweep that stops where its store work starts, and says so. The daemon's own sweeps
        // never stop there, so the sweep that arrives is this one.
        let (arrived, go, swept) = controller.transfer().sweep_paused(&held);
        tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
            .await
            .expect("the sweep reaches its store work in time")
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
        swept.await.expect("the sweep runs");
        drop(started(|| Controller::start(setup(&temp, boot_identity.clone()))).await);
    }

    /// A closure's write holds its daemon until its store call has returned, as a sweep does,
    /// though the task that waits on the write is dropped meanwhile, as a runtime that shuts down
    /// drops it. The write here stops after its store call and before it lets the daemon go: for
    /// as long as it stands there, every daemon started on the environment is refused; once it
    /// goes on, one is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closures_write_that_has_begun_keeps_its_daemon_until_its_store_work_ends() {
        use crate::service::net::tests::{daemon, setup, started};

        let temp = kr_ipc::testing::TempHost::create();
        let boot_identity = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller = daemon(&temp).await;
        let held = Arc::downgrade(&controller);

        // A write that stops once its store call has returned, and says so.
        let (arrived, go, ending) = controller
            .transfer()
            .session_ended_paused(&held, SessionId::new(kr_ipc::new_uuid()));
        tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
            .await
            .expect("the write reaches the end of its store work in time")
            .expect("the write says it has arrived");

        // The task that waits on the write is dropped and the daemon is let go while the write
        // stands after its store call, before it lets the daemon go.
        drop(ending);
        drop(controller);
        for _ in 0..25 {
            match Controller::start(setup(&temp, boot_identity.clone())).await {
                Err(ControllerError::AlreadyRunning { .. }) => {}
                Ok(_) => panic!(
                    "a daemon took the environment while an earlier daemon's write still held its daemon"
                ),
                Err(error) => panic!("a daemon was refused for another reason: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(held.strong_count() > 0, "the write still holds its daemon");

        // Once the write ends, its daemon goes, and another daemon takes the environment.
        let _ = go.send(());
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
}
