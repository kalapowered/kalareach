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

use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::given::Given;
use crate::service::Controller;

/// How often the daemon sweeps expired transfers.
///
/// Every window the sweep enforces is measured in hours or days, so an hour is frequent enough to
/// keep the staging area honest and rare enough that it costs nothing.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// How many open drafts one paired device may hold.
///
/// A draft is open until a prompt sends it to a session or its target session ends, and the
/// service counts it against the device's own principal. The page makes one draft for each session
/// it attaches files in, and another for each eight files, so the bound is several times what a
/// person works in at once; a device holds at most this many open drafts, each of up to
/// [`kr_protocol::transfer::MAX_TRANSFER_RESULT_BYTES`] of text. The person at this machine has
/// no bound, and nothing a device sends changes it: the limit is a constant of this host, which an
/// owner cannot change.
pub const DEVICE_OPEN_DRAFTS: u64 = 64;

/// How many uploads one paired device may keep staged.
///
/// An upload is staged from `upload.begin` until it ends: while it receives chunks, while it is
/// published, and until the attachment it made expires. An attachment that a prompt has sent to a
/// session follows that session's retention instead and stops counting, as a draft a prompt has
/// sent does. A device frees a place by cancelling an upload that is still receiving, or by sending
/// a file or letting it expire, which an unused file does after seven days; a published file cannot
/// be cancelled. The bytes of every upload are bounded by the environment's own limit, so this
/// bounds what bytes do not: the rows and the files of no bytes a device leaves. The page makes a
/// draft of up to eight files and a device holds at most [`DEVICE_OPEN_DRAFTS`] drafts open, which
/// is about 512 files, so the bound leaves that much again for what is waiting to be sent. The
/// person at this machine has no bound; the limit is a constant of this host, which an owner cannot
/// change.
pub const DEVICE_STAGED_UPLOADS: u64 = 1_024;

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
    /// Its action claimed nothing here, so the repeat is a first admission and has no window,
    /// unless another arrival holds the action and has not reached its claim, which the door
    /// knows and this service does not.
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
    /// Where this host's own tests stop a device's create between its first try, which the bound
    /// refused, and its second, and how many second tries have been made. Compiled only with the
    /// `testing` feature.
    #[cfg(feature = "testing")]
    between_the_tries: Arc<crate::attention::Pause>,
    #[cfg(feature = "testing")]
    second_tries: Arc<std::sync::atomic::AtomicU64>,
    /// Where this host's own tests hold the lookup that admits a data stream, on its blocking
    /// thread. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    inside_the_stream_lookup: Arc<LookupHold>,
    /// The point a repeat that arrived with no usable window stops at once the claim of its action
    /// has been asked about, before it looks for the record. Compiled only with the `testing`
    /// feature.
    #[cfg(feature = "testing")]
    after_the_claim_is_asked_about: Arc<crate::attention::Pause>,
    /// The point a worker's read of a draft stops at once the transfer service has answered it,
    /// before the answer is written. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    after_a_read: Arc<crate::attention::Pause>,
    /// The point a worker's claim of an attachment stops at, before it enters the transfer service.
    /// Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    before_a_claim: Arc<crate::attention::Pause>,
    /// The point a worker's claim stops at once the transfer service has decided it, before the
    /// answer is written. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    after_a_claim: Arc<crate::attention::Pause>,
    /// How many sweeps the daemon's own sweep loop has ended, for this crate's tests to wait for
    /// the one it makes as it starts. Compiled only into this crate's tests.
    #[cfg(test)]
    sweeps_ended: tokio::sync::watch::Sender<u64>,
}

/// The admission one transfer mutation arrived under, as the transfer service asks about it.
///
/// Every answer is the check each service asks from inside the work a mutation has begun,
/// `Controller::check_registration`: a fence this host owes and could not raise, then the
/// connection's registration under the revision the mutation was admitted at, then the accepted
/// deadline. The service asks it where the mutation begins an effect, with its own lock held, and
/// runs each commit through `Controller::under_registration`, so a withdrawal, which waits for it,
/// is ordered wholly before the check or wholly after the commit. The refusal the check gave is
/// kept, so that `TransferModule::write` can answer with it and not retain it.
pub struct TransferAdmission {
    controller: Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
    /// True for an exact repeat that carries no freshness: it may finish what its action already
    /// claimed and may begin nothing.
    settling: bool,
    refusal: std::sync::Mutex<Option<ProtocolError>>,
    /// Whether the service asked this admission where it begins an effect. A draft write does so
    /// only once it has found no record of the action, as a draft whose revision an earlier attempt
    /// moved on is refused, or answered from its record, before it asks. Each upload write looks
    /// for its record under the store's lock before it first asks; `upload.finish` and
    /// `upload.cancel` let go of the lock after that look (`upload.finish` to verify the file) and
    /// ask without looking again. A create's second try clears the mark before its call.
    reached: AtomicBool,
    /// The attachment-chunk stream the mutation arrived on, when it arrived on one. The stream's
    /// revoked state is part of what the service asks where an effect begins: the loss of the
    /// control stream, once declared, ends every chunk that has not begun its effect.
    stream: Option<Arc<crate::service::net::chunks::ChunkAdmission>>,
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
            reached: AtomicBool::new(false),
            stream: None,
        })
    }

    /// The admission of a chunk that arrived on `stream`.
    ///
    /// The service asks it where the chunk begins an effect, and it refuses first when the stream
    /// has been taken away: lost with its connection, or replaced by a newer stream of the same
    /// transfer. The refusal is the admission's own and is not retained, so the same chunk sent on
    /// the replacement stream is a first admission.
    pub(crate) fn on_a_stream(
        controller: Arc<Controller>,
        carried: crate::authority::AdmittedMutation,
        stream: Arc<crate::service::net::chunks::ChunkAdmission>,
    ) -> Arc<Self> {
        Arc::new(Self {
            controller,
            carried,
            settling: false,
            refusal: std::sync::Mutex::new(None),
            reached: AtomicBool::new(false),
            stream: Some(stream),
        })
    }

    /// The gate of the chunk's transfer, for the blocking call that takes the chunk into the
    /// service to hold until it ends.
    fn take_gate(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.stream.as_ref().and_then(|stream| stream.take_gate())
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
            reached: AtomicBool::new(false),
            stream: None,
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
        if self.stream.as_ref().is_some_and(|stream| !stream.stands()) {
            return Err(self.refused(&ControllerError::PermissionDenied {
                detail: "the stream this chunk arrived on has been taken away".to_owned(),
            }));
        }
        self.controller
            .check_registration(&self.carried)
            .map_err(|error| self.refused(&error))
    }

    /// Asks the check a retained answer is owed before it goes back: a fence this host owes, and the
    /// registration under the revision the mutation was admitted at, without the deadline a receipt
    /// outlives. The refusal is not kept: a retained answer is not retained again.
    fn check_retained(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .check_retained_under(&self.carried)
            .map_err(|error| error.to_protocol_error())
    }

    fn refused(&self, error: &ControllerError) -> ProtocolError {
        if let Some(stream) = &self.stream {
            stream.note_refusal();
        }
        let refusal = error.to_protocol_error();
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| refusal.clone());
        refusal
    }

    /// Whether the service reached the place it begins an effect, which a service that answers an
    /// action from its own record does not.
    fn reached(&self) -> bool {
        self.reached.load(Ordering::Acquire)
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
        self.reached.store(true, Ordering::Release);
        if self.settling {
            return Err(self.refused(&Self::without_freshness()));
        }
        self.check()
    }

    fn run(&self, commit: &mut dyn FnMut()) -> std::result::Result<(), ProtocolError> {
        self.reached.store(true, Ordering::Release);
        if self.settling {
            return Err(self.refused(&Self::without_freshness()));
        }
        self.controller
            .under_registration(&self.carried, commit)
            .map_err(|error| self.refused(&error))
    }
}

/// Holds the lookups that admit data streams, on their blocking threads, while a suite looks at what
/// the host does meanwhile.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
struct LookupHold {
    state: std::sync::Mutex<Option<Arc<LookupHeld>>>,
}

#[cfg(feature = "testing")]
#[derive(Debug)]
struct LookupHeld {
    arrived: std::sync::mpsc::Sender<()>,
    released: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

#[cfg(feature = "testing")]
impl LookupHold {
    fn arm(&self) -> (std::sync::mpsc::Receiver<()>, LookupRelease) {
        let (arrived, arrival) = std::sync::mpsc::channel();
        let held = Arc::new(LookupHeld {
            arrived,
            released: std::sync::Mutex::new(false),
            changed: std::sync::Condvar::new(),
        });
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&held));
        (arrival, LookupRelease(held))
    }

    /// Says a lookup has arrived and waits here until the hold is released.
    fn wait(&self) {
        let held = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(held) = held else { return };
        let _ = held.arrived.send(());
        let mut released = held
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = held
                .changed
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// The end of [`TransferModule::hold_the_stream_lookups`] that lets the held lookups go, and every
/// lookup after them. Dropping it lets them go too: a holder that fails or ends while lookups are
/// held would otherwise leave their blocking threads waiting for good, and a runtime does not shut
/// down until its blocking threads have returned.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct LookupRelease(Arc<LookupHeld>);

#[cfg(feature = "testing")]
impl LookupRelease {
    /// Lets the lookups go.
    pub fn release(self) {
        drop(self);
    }
}

#[cfg(feature = "testing")]
impl Drop for LookupRelease {
    fn drop(&mut self) {
        *self
            .0
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.0.changed.notify_all();
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
        let retained = self.owner.retained_among(sessions).map_err(|error| {
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
        Ok(retained)
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
            #[cfg(feature = "testing")]
            between_the_tries: Arc::new(crate::attention::Pause::default()),
            #[cfg(feature = "testing")]
            second_tries: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(feature = "testing")]
            inside_the_stream_lookup: Arc::new(LookupHold::default()),
            #[cfg(feature = "testing")]
            after_the_claim_is_asked_about: Arc::new(crate::attention::Pause::default()),
            #[cfg(feature = "testing")]
            after_a_read: Arc::new(crate::attention::Pause::default()),
            #[cfg(feature = "testing")]
            before_a_claim: Arc::new(crate::attention::Pause::default()),
            #[cfg(feature = "testing")]
            after_a_claim: Arc::new(crate::attention::Pause::default()),
            #[cfg(test)]
            sweeps_ended: tokio::sync::watch::channel(0).0,
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

    /// Arms the pause a device's create stops at between its first try, which the bound refused,
    /// and its second. It fires once; the ends are as for [`Self::pause_after_the_outer_check`].
    #[cfg(feature = "testing")]
    pub fn pause_between_the_tries(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.between_the_tries.arm()
    }

    /// How many times a device's create has been tried a second time, after a refusal at the bound.
    #[cfg(feature = "testing")]
    pub fn second_tries(&self) -> u64 {
        self.second_tries.load(Ordering::Acquire)
    }

    /// Holds every lookup that admits a data stream, on its blocking thread, until the returned end
    /// releases them. Returns the end that hears each lookup arrive, one message for each, and the
    /// release. Compiled only with the `testing` feature.
    #[cfg(feature = "testing")]
    pub fn hold_the_stream_lookups(&self) -> (std::sync::mpsc::Receiver<()>, LookupRelease) {
        self.inside_the_stream_lookup.arm()
    }

    /// Looks up `actor`'s upload for a data stream's header: where it belongs, when it is receiving
    /// and has not expired.
    ///
    /// The lookup waits for the store, which a deadline cannot cancel, so it runs on a blocking task
    /// that owns `place`, the lookup place of the device's principal: the place is given back when
    /// the lookup ends, however long ago the stream that asked was given up.
    ///
    /// # Errors
    ///
    /// Returns the refusal every unknown identifier is given.
    pub(crate) async fn receiving_upload(
        &self,
        actor: ActorId,
        transfer_id: kr_protocol::ids::TransferId,
        place: tokio::sync::OwnedSemaphorePermit,
    ) -> Answer<kr_transfer::service::StoredSubject> {
        let service = Arc::clone(&self.service);
        #[cfg(feature = "testing")]
        let hold = Arc::clone(&self.inside_the_stream_lookup);
        blocking(move || {
            let _place = place;
            #[cfg(feature = "testing")]
            hold.wait();
            Ok(service.receiving_upload(&actor, transfer_id)?)
        })
        .await
    }

    /// Arms the pause a repeat that arrived with no usable window stops at once the claim of its
    /// action has been asked about, before it looks for the record. Returns the end that says it
    /// has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_the_claim_is_asked_about(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_the_claim_is_asked_about.arm()
    }

    /// Arms the pause a worker's read of a draft stops at once the transfer service has answered
    /// it, before the answer is written. Returns the end that says it has arrived, and the end that
    /// lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_a_read(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_a_read.arm()
    }

    /// Arms the pause a worker's claim of an attachment stops at once it has been asked of this
    /// daemon, before it enters the transfer service. Returns the end that says it has arrived, and
    /// the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_a_claim(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.before_a_claim.arm()
    }

    /// Arms the pause a worker's claim of an attachment stops at once the transfer service has
    /// decided it, whether it committed or was refused, before the answer is written. Returns the
    /// end that says it has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_a_claim(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_a_claim.arm()
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
        let outcome = blocking(move || kept(&service, &actor, action_id, name, digest)).await;
        match outcome {
            // The blocking task itself failed, which says nothing about the action.
            Err(error) => Some(frame(mutation.request_id, Err(error))),
            Ok(None) => None,
            Ok(Some(retained)) => Some(frame(mutation.request_id, answer_of(retained))),
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
        #[cfg(feature = "testing")]
        let after_the_claim_is_asked_about = Arc::clone(&self.after_the_claim_is_asked_about);
        let open = blocking(move || {
            let open = service.claim_is_open(&actor, action_id, name, digest);
            #[cfg(feature = "testing")]
            after_the_claim_is_asked_about.wait();
            open.map_err(|error| {
                ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS)
            })
        })
        .await;
        match open {
            Ok(true) => return Settling::Open,
            Ok(false) => {}
            // A claim that cannot be read is not one that is not open: the second look for the
            // record gives nothing for an open claim, and the repeat would be refused for its
            // window, which says nothing was done.
            Err(error) => return Settling::Answered(frame(mutation.request_id, Err(error))),
        }
        match self.retained(actor_id, mutation, method).await {
            Some(answer) => Settling::Answered(answer),
            None => Settling::No,
        }
    }

    /// Writes the end of each session the registry holds as closed among the sessions the drafts
    /// `actor_id` holds open target and `target`, the one the create names, before the create is
    /// counted against those drafts.
    ///
    /// A session's closure queues the write that ends its drafts on a task of its own, so a create
    /// that follows closely, or a write that failed and waits for the next sweep or start, would
    /// count drafts of a session that has ended, or add one for it. Each create settles, before its
    /// count, the closed sessions its principal's open drafts target and the one it names, whatever
    /// the count is: a draft of a session recorded closed before then stops counting without a
    /// second try, and a create that names one is refused as the service refuses any draft for an
    /// ended session, unless the bound speaks first. A refusal at the bound is kept only after a
    /// second settle and a second count ([`Self::write`]). What remains possible is a refusal for a
    /// draft whose session another create's own registry read missed and then closed, at the first
    /// settle and again at the second, or one after a settle that failed in both passes. The
    /// registry is read once for each of those sessions in a pass, at most 65 key reads under its
    /// lock (the principal's open drafts at the bound, and the create's own session); a create at
    /// the bound makes two passes, so up to 130 key reads and two scans of the drafts, besides the
    /// store's other reads and writes, which are as they are for any such write. A pass that
    /// cannot be made leaves a line in the log and does not stop the create: the service counts
    /// what it holds.
    pub(crate) async fn settle_closures_of_open_drafts(
        &self,
        owner: &Arc<Controller>,
        actor_id: &ActorId,
        target: Option<SessionId>,
    ) {
        let service = Arc::clone(&self.service);
        let owner = Arc::clone(owner);
        let actor = actor_id.clone();
        let settled = tokio::task::spawn_blocking(move || {
            settle_closures(&owner, &service, &actor, target);
        })
        .await;
        if settled.is_err() {
            say_closures_unsettled();
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
    /// draft written for another application than the prompt's (`DRAFT_CONFLICT`), a session that
    /// has ended (`SESSION_CLOSED`), and an admission that no longer stands.
    pub(crate) async fn record_submission(
        &self,
        actor_id: &ActorId,
        prompted: PromptedDraft,
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
            match service.record_prompt(
                &actor,
                prompted.draft_id,
                session_id,
                prompted.application_instance_id,
                &admission,
            ) {
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
        #[cfg(feature = "testing")]
        let after_a_read = Arc::clone(&self.after_a_read);
        #[cfg(feature = "testing")]
        let before_a_claim = Arc::clone(&self.before_a_claim);
        #[cfg(feature = "testing")]
        let after_a_claim = Arc::clone(&self.after_a_claim);
        blocking(move || {
            Ok(match step {
                DraftStep::Facts { draft_id } => {
                    let read = service.insertion_facts(&actor_id, session_id, draft_id);
                    #[cfg(feature = "testing")]
                    after_a_read.wait();
                    DraftAnswer::Facts(read?)
                }
                DraftStep::Begin(begin) => {
                    #[cfg(feature = "testing")]
                    before_a_claim.wait();
                    let decided = service.insertion_begin(
                        &actor_id,
                        session_id,
                        &begin,
                        &kr_ipc::clock::SystemSharedClock,
                    );
                    #[cfg(feature = "testing")]
                    after_a_claim.wait();
                    DraftAnswer::Claim(Box::new(decided?))
                }
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

    /// Serves one transfer mutation and returns the frame it answers with, and whether the service
    /// read it from the record of an earlier submission of the action.
    ///
    /// `admission` and `draft_limit` are as [`Self::write`].
    pub(crate) async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: Arc<TransferAdmission>,
        draft_limit: Option<u64>,
    ) -> Given<ControlFrame> {
        self.write(actor_id, mutation, method, admission, draft_limit)
            .await
            .map(|answer| frame(mutation.request_id, answer))
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
    /// `draft_limit` is how many open drafts the caller may hold, which only a paired device is
    /// held to: `None` is the person at this machine, whose drafts have no bound.
    ///
    /// The answer says whether the service read it from the record of an earlier submission of the
    /// action. A copy goes back only under the authority this attempt arrived under, asked once the
    /// copy is in hand ([`Given::checked`]): the check's refusal replaces the copy, and is given as
    /// a copy that was withheld. The conflict of a reused identifier is no copy and is held to the
    /// same check.
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
        draft_limit: Option<u64>,
    ) -> Given<Answer<ParamsValue>> {
        let digest = match kr_protocol::digest::mutation_digest(mutation, actor_id) {
            Ok(digest) => digest,
            Err(error) => {
                return Given::Fresh(Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                )));
            }
        };
        let copied = Arc::new(AtomicBool::new(false));
        let found = Arc::clone(&copied);
        let standing = Arc::clone(&admission);
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = mutation.params.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        #[cfg(feature = "testing")]
        let after_the_outer_check = Arc::clone(&self.after_the_outer_check);
        #[cfg(feature = "testing")]
        let between_the_tries = Arc::clone(&self.between_the_tries);
        #[cfg(feature = "testing")]
        let second_tries = Arc::clone(&self.second_tries);
        let answer = blocking(move || {
            // The transfer's gate is held by this call until it ends, and not by the stream's task,
            // which is aborted when its connection ends while this call goes on.
            let _gate = admission.take_gate();
            // A look at the record that cannot read it says a record exists, so what it answers is
            // a copy whichever way it is told. The other places this work cannot read or write a
            // record answer the word that the outcome is unknown, which carries no record, except
            // a refusal the request alone decided, which is told as itself, the conflict of a
            // reused identifier, and a store the service itself could not read, which is told as
            // the service refused it. None of them carries another attempt's record.
            let looked_at = || {
                let looked = kept(&service, &actor, action_id, name, digest);
                if looked
                    .as_ref()
                    .is_err_and(|error| error.code == ErrorCode::OutcomeUnknown)
                {
                    found.store(true, Ordering::Release);
                }
                looked
            };
            if let Some(retained) = looked_at()? {
                // Found here, after the lookup the door made before it considered a first
                // admission: another attempt may have recorded it since.
                found.store(true, Ordering::Release);
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
            if admission.settling
                && !service
                    .claim_is_open(&actor, action_id, name, digest)
                    .map_err(|error| {
                        ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS)
                    })?
            {
                // A claim moves from open to settled and never back, so one that is not open
                // now and was when the lookup above found it open has been settled since, and
                // what it was settled with is the answer.
                if let Some(retained) = looked_at()? {
                    found.store(true, Ordering::Release);
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
            // Whether the service's refusal was decided by the request alone, which no copy of the
            // request can have changed ([`kr_transfer::TransferError::is_decided_by_the_request`]).
            let by_the_request = std::cell::Cell::new(false);
            let told = |error: kr_transfer::TransferError| {
                by_the_request.set(error.is_decided_by_the_request());
                ProtocolError::from(error)
            };
            // Every arm runs inside a closure, so a refusal the service decided reaches the
            // retention below instead of returning from the task. An action whose failure was not
            // retained could be performed again under the same identifier and succeed.
            let outcome = (|| -> Answer<ParamsValue> {
                match method {
                    Method::UploadBegin => encode(
                        &service
                            .upload_begin(&actor, &typed(&params)?, Some(&performed))
                            .map_err(&told)?,
                    ),
                    Method::UploadChunk => encode(
                        &service
                            .upload_chunk(&actor, &typed(&params)?, Some(&performed))
                            .map_err(&told)?,
                    ),
                    Method::UploadFinish => encode(
                        &service
                            .upload_finish(&actor, &typed(&params)?, Some(&performed))
                            .map_err(&told)?,
                    ),
                    Method::UploadCancel => encode(
                        &service
                            .upload_cancel(&actor, &typed(&params)?, Some(&performed))
                            .map_err(&told)?,
                    ),
                    Method::DraftCreate => {
                        let params: kr_protocol::transfer::DraftCreateParams = typed(&params)?;
                        let mut made =
                            service.draft_create(&actor, &params, Some(&performed), draft_limit);
                        // The refusal at a device's bound is kept as the action's outcome, so it
                        // is not given on a count that a draft inserted for a closed session since
                        // the door settled could have filled: the closed sessions are settled once
                        // more, outside the count and its holds, and the create is tried once more.
                        if draft_limit.is_some()
                            && matches!(made, Err(kr_transfer::TransferError::QuotaExceeded { .. }))
                        {
                            settle_closures(
                                &admission.controller,
                                &service,
                                &actor,
                                params.session_id.0,
                            );
                            // The second call can be answered from a record another copy of this
                            // action wrote since the first, without asking the admission: what it
                            // finds is then a copy's, so the first try's mark is cleared.
                            admission.reached.store(false, Ordering::Release);
                            #[cfg(feature = "testing")]
                            {
                                second_tries.fetch_add(1, Ordering::AcqRel);
                                between_the_tries.wait();
                            }
                            made = service.draft_create(
                                &actor,
                                &params,
                                Some(&performed),
                                draft_limit,
                            );
                        }
                        encode(&made.map_err(&told)?)
                    }
                    Method::DraftUpdate => encode(
                        &service
                            .draft_update(&actor, &typed(&params)?, Some(&performed))
                            .map_err(&told)?,
                    ),
                    Method::AgentDraftAddAttachment => {
                        let params: kr_protocol::transfer::AgentDraftAddAttachmentParams =
                            typed(&params)?;
                        require_declared_path(params.contribution.insertion_method)?;
                        encode(
                            &service
                                .draft_add_attachment(&actor, &params, Some(&performed))
                                .map_err(&told)?,
                        )
                    }
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
            let recorded = match service.record_action(&actor, action_id, name, digest, &record) {
                Ok(recorded) => recorded,
                // An action that was carried out is not one that was not: a record that cannot be
                // written or read back now is told as a record that cannot be read, and a
                // transient word would have it sent again as though nothing had been done.
                Err(error) if outcome.is_ok() => {
                    return Err(ControllerError::found_unreadable_on_the_wire(
                        error.into(),
                        RECORDS,
                    ));
                }
                // A refusal that a check of the request alone decided, before anything was done,
                // is the same for every exact copy of the request whatever another copy did: the
                // host knows nothing ran, and says what it said.
                Err(_) if by_the_request.get() => return outcome,
                // Any other refusal that cannot be written down is not told as a definite one, nor
                // as the store's transient word: it can be a word about what another copy of the
                // action did. The record is read instead. It is the answer where the action has
                // one, under the check any retained answer is owed, and where there is none to be
                // read the outcome is not known.
                Err(_) => {
                    return match service.retained_action(&actor, action_id, name, digest) {
                        Ok(Some(retained)) => {
                            found.store(true, Ordering::Release);
                            answer_of(retained)
                        }
                        Ok(None) => Err(ControllerError::refusal_not_recorded()),
                        Err(error @ kr_transfer::TransferError::IdConflict { .. }) => {
                            Err(error.into())
                        }
                        Err(_) => Err(ControllerError::refusal_not_recorded()),
                    };
                }
            };
            match recorded {
                None => outcome,
                // The record is the answer both callers get. The three draft writes record their
                // own action in the transaction that performs it, and hold the journal's lock from
                // the look that decides whether they begin (the record for a create, the draft's
                // revision for the other two, which an earlier attempt's success has moved on) to
                // that commit, so once that call has reached the place it begins an effect, a record
                // that it finds after its own success is its own. A create's second try is a call of
                // its own, and the mark is cleared before it. The upload writes let go of the lock
                // after their look at the record, so another copy can record in between: any record
                // read for them, and for every other method, is a copy.
                Some(retained) => {
                    let performed_here = outcome.is_ok()
                        && admission.reached()
                        && matches!(
                            method,
                            Method::DraftCreate
                                | Method::DraftUpdate
                                | Method::AgentDraftAddAttachment
                        );
                    if !performed_here {
                        found.store(true, Ordering::Release);
                    }
                    answer_of(retained)
                }
            }
        })
        .await;
        let copied = copied.load(Ordering::Acquire);
        // The answer first, then the authority it is owed: a refusal replaces what the record
        // held, and is given as a copy that was withheld.
        let reused = answer
            .as_ref()
            .is_err_and(|refusal| refusal.code == ErrorCode::IdConflict);
        Given::checked(answer, copied, reused, || standing.check_retained())
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

    /// Waits until the daemon's own sweep loop has ended a sweep, which is the one it makes as it
    /// starts. That sweep asks the host whether its clock may be trusted to let a record go, and a
    /// test that moves the host's clocks by hand has to move them after that question and not
    /// while it is still to come: the answer is read from the clocks as they stand.
    #[cfg(test)]
    pub(crate) async fn until_a_sweep_has_ended(&self) {
        let mut ended = self.sweeps_ended.subscribe();
        let _ = ended.wait_for(|ended| *ended > 0).await;
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

/// The line left when the closed sessions of a device's open drafts could not all be settled before
/// its create was counted.
fn say_closures_unsettled() {
    eprintln!(
        "kr-controller: the closed sessions of a device's open drafts could not all be settled \
         before its create was counted; the next sweep or start settles them"
    );
}

/// Records as ended each session among those `actor`'s open drafts target, and `target`, that the
/// registry holds a closure for ([`TransferModule::settle_closures_of_open_drafts`]).
///
/// It asks the registry only whether a closure exists, goes on past a session whose record cannot
/// be read, and never holds the registry and the journal together. Whatever fails is left for the
/// sweep and the next start, which write every closure the registry holds.
fn settle_closures(
    owner: &Controller,
    service: &TransferService,
    actor: &ActorId,
    target: Option<SessionId>,
) {
    let mut failed = false;
    let mut asked = service.open_draft_sessions(actor).unwrap_or_else(|_| {
        failed = true;
        std::collections::BTreeSet::new()
    });
    asked.extend(target);
    let mut closed = std::collections::BTreeSet::new();
    if !asked.is_empty() {
        let registry = owner.registry_handle().blocking_lock();
        for session_id in asked {
            match registry.has_closure(session_id) {
                Ok(true) => {
                    closed.insert(session_id);
                }
                Ok(false) => {}
                Err(_) => failed = true,
            }
        }
    }
    if !closed.is_empty() && service.end_session_insertions(&closed).is_err() {
        failed = true;
    }
    if failed {
        say_closures_unsettled();
    }
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
    // The connections belong to this loop: ending it ends the ones being served.
    let _ = crate::service::serve_each(&listener, |connection, peer| {
        let controller = controller.upgrade()?;
        Some(async move {
            // The frame bound is the only difference from a control connection. Everything else —
            // the hello, the peer check, the authority registration, the action window and its
            // renewals — is the same code, which is what keeps the two from drifting.
            let _ = controller
                .client(connection, peer, StreamKind::AttachmentChunks)
                .await;
        })
    })
    .await;
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
        #[cfg(test)]
        if let Some(controller) = daemon.upgrade() {
            controller
                .transfer()
                .sweeps_ended
                .send_modify(|ended| *ended += 1);
        }
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
            .map_err(|_| ControllerError::record_unreadable(RECORDS).to_protocol_error()),
        RetainedOutcome::Error { code, detail } => Err(ProtocolError::new(code, detail)),
    }
}

/// The records this module's store keeps, as a repeat is told of them when they cannot be read.
const RECORDS: &str = "transfer actions";

/// The record an action left, read for a repeat of it.
///
/// A store that cannot be read is not one that holds no record: the action may have been carried
/// out, so the repeat is told that what became of it is not known. A reused identifier keeps its
/// code. The lookup cannot tell a first action from a repeat, so a first action on a store that
/// cannot be read is told the same.
fn kept(
    service: &TransferService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
) -> Answer<Option<RetainedOutcome>> {
    service
        .retained_action(actor, action_id, name, digest)
        .map_err(|error| ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS))
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

/// A draft a prompt names, and the application the prompt is for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PromptedDraft {
    /// The draft.
    pub(crate) draft_id: kr_protocol::ids::DraftId,
    /// The application instance the prompt is for, which the draft must not be written against
    /// another of.
    pub(crate) application_instance_id: kr_protocol::ids::ApplicationInstanceId,
}

/// The draft a prompt names, when the mutation is a prompt that names a draft.
///
/// A queued prompt counts with a submitted one: the session's agent holds it from the moment the
/// worker takes it and may run it long after, and this host is not told when it does.
pub(crate) fn prompted_draft(mutation: &MutationRequest) -> Option<PromptedDraft> {
    if !matches!(
        mutation.method.method(),
        Some(Method::AgentPromptSubmit | Method::AgentPromptQueue)
    ) {
        return None;
    }
    let params = mutation
        .params
        .to_typed::<kr_protocol::agent::AgentPromptParams>()
        .ok()?;
    Some(PromptedDraft {
        draft_id: params.draft_id.0?,
        application_instance_id: params.target.subject.application_instance_id,
    })
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

/// Refuses an insertion path that no integration declared for the session.
///
/// A manual terminal workflow puts nothing in front of the agent: the host binds the completed
/// transfer, and the person performs the native operation with the file's path, so it needs no
/// declaration. A typed submission and a verified composer insertion both reach the agent through
/// its integration, so they are admitted only for a path the session's integration declared for
/// the operation. The daemon holds no such declaration, so both are refused.
fn require_declared_path(method: kr_protocol::transfer::InsertionMethod) -> Answer<()> {
    use kr_protocol::transfer::InsertionMethod;

    match method {
        InsertionMethod::ManualTerminalWorkflow => Ok(()),
        InsertionMethod::TypedSubmission | InsertionMethod::VerifiedComposerInsertion => {
            Err(ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                format!(
                    "no integration declared {} for this operation; only a manual_terminal_workflow \
                     can be bound",
                    method.as_str()
                ),
            ))
        }
    }
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
