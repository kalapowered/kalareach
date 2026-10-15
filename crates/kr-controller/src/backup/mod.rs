//! The environment's backup service: what this host has produced, staged and accounted for.
//!
//! The producer itself is `kr_crypto::backup`: it encrypts the objects, wraps the keys, signs the
//! manifest and builds the descriptor. Object storage is the storage service's. What this module
//! owns is the part in between, which is the part a crash can lose:
//!
//! * **`backup.sqlite`.** Generation records, object rows, upload state and an outbox, each write
//!   committed in the same transaction as the state transition it belongs to. See
//!   [`store::BackupStore`].
//! * **Reconciliation at startup.** What is still authorised resumes; what is not is cancelled;
//!   and a publication that was dispatched and never answered is recorded as *unknown*, because
//!   that is what this host knows about it.
//! * **The privacy hook.** [`BackupService::privacy`] is the service's
//!   `kr_worker::privacy::PrivacySubsystem`: it fences the outbox at the generation, takes back
//!   what has not been dispatched, removes the staged ciphertext it holds, reports what is still in
//!   flight, names what it keeps, and shows already-uploaded archives as retained artifacts. Each
//!   step answers with the reason the store gave when it could not be taken. It marks the archives
//!   **not** deletable, because this host holds no route through which it could ask a service to
//!   remove one; the separately authorised deletion action section 24 asks for is not built here.
//!
//! # What this host never writes down
//!
//! An object key, a plaintext or a filename. The keys stay in the producer's hands until the
//! generation is sealed; the filenames are inside the encrypted manifest. `backup.sqlite` holds
//! identities, hashes, sizes, states and the paths of ciphertext.

pub mod binding;
mod lease;
pub mod relay;
pub mod runtime;
pub mod setup;
mod statements;
pub mod store;
pub mod uploader;

pub use lease::{ProductionLease, StagedFile, Staging};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use kr_client::services::AccountMark;
use kr_crypto::backup::{SealedArchive, StagedObject};
use kr_flush::{NameKind, flush_directory};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{KeyId, TimestampMs};
use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
    Unavailable,
};

use crate::backup::store::{
    Attempt, AttemptStatus, BackupStore, FenceRelease, GenerationRecord, MadeFrom, NewGeneration,
    NewObject, ObjectRecord, Obligation, ObligationKind, PrivacyRequest, PrivacyStatus,
    Publication, Remote, Setup, SetupCommit, SetupRecord, Step,
};
use crate::error::{ControllerError, Result};

/// How many days after a deletion the storage service removes an object's ciphertext, and goes on
/// charging for it until then. The service publishes its figure; a status read that says another
/// is reported by `kr doctor`.
pub const TOMBSTONE_DAYS: u64 = 7;

/// The stable name this subsystem is reported under, which is section 24's.
pub const SUBSYSTEM_NAME: &str = "backup";

/// One privacy step this host can be asked to take.
///
/// It names a step, never a piece of cleanup. What is owed lives in the store; these say only that
/// this process tried a step for one privacy generation and the store would not take it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PrivacyStep {
    Fence,
    Cancel,
    Remove,
}

impl PrivacyStep {
    const fn describe(self) -> &'static str {
        match self {
            Self::Fence => "raise the backup privacy fence",
            Self::Cancel => "cancel undispatched backup work",
            Self::Remove => "remove staged backup ciphertext",
        }
    }
}

/// One step this process tried, for one privacy generation, and could not carry out.
///
/// The generation is part of the identity. Without it, a step that succeeded for some *other*
/// request would clear a failure that belongs to this one, and the host would be ready again on
/// the strength of a success that established nothing about what it had failed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FailedStep {
    step: PrivacyStep,
    privacy_generation: u64,
}

impl FailedStep {
    fn describe(self) -> String {
        format!(
            "{} for privacy generation {}",
            self.step.describe(),
            self.privacy_generation
        )
    }
}

/// Whether this process will let backup production go on, and why not when it will not.
///
/// It can only ever *withhold* production. Nothing in it discharges a durable obligation, and
/// nothing in it reports work done. Two things make a host unready: a store that has not been
/// reconciled since it was opened, and a privacy step this process was asked to take and could
/// not.
/// Its default is unready on every open. What an earlier process left unfinished is not known
/// until reconciliation has read it back, and admitting work before then would add to a store
/// whose state nothing had established.
#[derive(Debug, Default)]
struct Readiness {
    reconciled: bool,
    /// Each step that failed, with the reason the store gave, until that step succeeds.
    failed: BTreeMap<FailedStep, String>,
}

impl Readiness {
    /// Returns the privacy step this process was asked to take and could not, if there is one.
    ///
    /// This is the half of the condition that reconciliation cannot clear. Reading back what an
    /// earlier process left is what makes a host reconciled, so a host in the middle of doing that
    /// is not yet ready and is not withholding anything either; a step it was asked to take and
    /// could not is withheld throughout.
    fn withheld(&self) -> Option<String> {
        self.failed.iter().next().map(|(failed, cause)| {
            format!(
                "this host could not {} ({cause}), so backup production stays stopped until it \
                 can",
                failed.describe()
            )
        })
    }

    /// Returns why backup production is refused, if it is.
    fn refusal(&self) -> Option<String> {
        if let Some(withheld) = self.withheld() {
            return Some(withheld);
        }
        if !self.reconciled {
            return Some(
                "this host has not reconciled its backup store since it opened, so what an \
                 earlier process left unfinished is not established yet"
                    .to_owned(),
            );
        }
        None
    }
}

/// One generation this host has admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The upload attempt that will carry it.
    pub sequence: u64,
    /// The privacy generation the store admitted it under, from its own durable state.
    pub privacy_generation: u64,
    /// How many objects were staged, the encrypted manifest included.
    pub staged_objects: usize,
    /// How many bytes of ciphertext are on this host for it.
    pub staged_bytes: u64,
}

/// Everything that keeps backup cleanup from being complete, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutstandingWork {
    /// Where this host stands with privacy mode.
    pub status: PrivacyStatus,
    /// Each piece of cleanup a fence wrote down and this host has not finished.
    pub obligations: Vec<Obligation>,
    /// How many attempts had left this host and have not been answered.
    pub dispatched_attempts: u64,
    /// Privacy steps this process tried and the store would not take, each with its request.
    ///
    /// They last as long as this process. A step that later works clears its own entry, for its
    /// own request or a newer one, and no other; nothing here ever discharges a durable
    /// obligation.
    pub failed_steps: Vec<String>,
}

impl OutstandingWork {
    /// Returns true when nothing is left: no fence, no obligation, no unanswered attempt.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.obligations.is_empty()
            && self.failed_steps.is_empty()
            // Before a fence exists, an attempt that has left this host is the outstanding work.
            // Once one does, that attempt has an obligation of its own and is counted there.
            && (self.status.inhibited_at().is_some() || self.dispatched_attempts == 0)
    }

    /// Returns a line per outstanding thing, for a report a person reads.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.obligations.iter().map(Obligation::describe).collect();
        if self.dispatched_attempts > 0 {
            lines.push(format!(
                "{} backup attempts have left this host and have not been answered",
                self.dispatched_attempts
            ));
        }
        for step in &self.failed_steps {
            lines.push(format!("this host could not {step}"));
        }
        lines
    }
}

/// What startup reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Generations whose work this host may still do, and has put back in hand.
    pub resumed: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations this host may no longer publish, which are cancelled.
    pub no_longer_authorised: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations whose publication left this host and was never answered.
    pub outcome_unknown: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations a service had accepted the publication of, whose production this finished.
    ///
    /// An answer is delivered once. A host that was told to stop and could not records the
    /// artifact and withholds completion, so the production it belongs to is finished here rather
    /// than left with nothing to carry it.
    pub completed: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations with an attempt that left this host and has not been answered.
    ///
    /// A restart does not end that wait. Only evidence about the attempt itself does: the service
    /// answering, or the caller establishing that the transfer stopped. Until then the attempt and
    /// whatever cleanup names it are both still there, which is what keeps this host from
    /// reporting a reconciliation it has not made.
    pub unanswered: Vec<(ArchiveId, BackupGeneration)>,
    /// Generations left where they are because privacy mode fenced this host.
    ///
    /// A restart does not un-fence work a fence stopped. They are neither resumed nor settled:
    /// turning privacy mode off is what decides what becomes of them.
    pub fenced: Vec<(ArchiveId, BackupGeneration)>,
}

impl Reconciliation {
    /// Returns true when there was nothing to reconcile.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resumed.is_empty()
            && self.no_longer_authorised.is_empty()
            && self.outcome_unknown.is_empty()
            && self.completed.is_empty()
            && self.unanswered.is_empty()
            && self.fenced.is_empty()
    }
}

/// The environment's backup service.
///
/// It owns `backup.sqlite` and the staging directory beside it. Its calls talk to SQLite and to
/// files, so a caller on an asynchronous runtime runs them on a blocking task.
#[derive(Debug)]
pub struct BackupService {
    store: Mutex<BackupStore>,
    readiness: Mutex<Readiness>,
    signals: Arc<BackupSignals>,
    /// The account the backups belong to, as a request's token is held to it.
    binding: Arc<binding::Binding>,
    /// The fingerprint of the kit the recorded setup was made with, kept beside the binding so that
    /// `kr doctor` can say it without a read of the store.
    kit: Mutex<Option<String>>,
    /// The production passes that hold the staging directory. Always taken after the store, and
    /// never while waiting for it.
    leases: Arc<Mutex<lease::Leases>>,
    /// Where a test stops the thread that commits a setup, before it commits.
    #[cfg(feature = "testing")]
    commit_pause: Mutex<Option<CommitPause>>,
}

/// The two ends of a pause in a setup's commit: the thread says it has arrived, and waits there
/// until the test lets it go.
#[cfg(feature = "testing")]
type CommitPause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

/// What releasing the ciphertext of finished generations did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Released {
    /// How many objects' ciphertext was removed from the disk.
    pub objects: u64,
    /// How many bytes that was.
    pub bytes: u64,
    /// How many objects are still to release, because their removal or its flush failed.
    pub pending: u64,
    /// Why the first of them failed.
    pub failure: Option<String>,
}

/// What tells whatever carries the outbox to the service that there is something to do.
///
/// Each is a standing permit rather than a message: a change made while the carrier is busy is
/// still there to be seen when it looks again, and several changes are one look.
#[derive(Debug, Default)]
pub struct BackupSignals {
    /// Work arrived or became possible: a generation was admitted, a writer was enrolled or a
    /// fence was released.
    pub work: Notify,
    /// A privacy fence was raised, which the carrier answers whatever else it is waiting for,
    /// because the cleanup a fence owes waits for work in flight to end.
    pub fence: Notify,
    /// A production pass ended, so the cleanup a fence owes, which waits for it, can be tried
    /// again at once.
    pub lease_ended: Notify,
    /// Something that can change what the producer does happened: a setup was committed, a fence
    /// was released, a generation finished or ciphertext left the disk.
    pub produce: Notify,
}

impl BackupService {
    /// Opens the service beside `state_dir`.
    ///
    /// It opens **unready**: nothing is admitted and nothing is dispatched until
    /// [`Self::reconcile`] has read back what an earlier process left unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be opened.
    pub fn open(state_dir: &Path) -> Result<Self> {
        let store = BackupStore::open(state_dir)?;
        let binding = binding_of(&store)?;
        let kit = Mutex::new(store.setup()?.map(|setup| setup.record.kit_fingerprint));
        Ok(Self {
            store: Mutex::new(store),
            readiness: Mutex::new(Readiness::default()),
            signals: Arc::default(),
            binding,
            kit,
            leases: Arc::default(),
            #[cfg(feature = "testing")]
            commit_pause: Mutex::new(None),
        })
    }

    /// Opens a service whose store exists only for the life of this process.
    ///
    /// It opens unready, on the same terms as [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be created.
    pub fn in_memory(staging_root: &Path) -> Result<Self> {
        let store = BackupStore::in_memory(staging_root)?;
        let binding = binding_of(&store)?;
        let kit = Mutex::new(store.setup()?.map(|setup| setup.record.kit_fingerprint));
        Ok(Self {
            store: Mutex::new(store),
            readiness: Mutex::new(Readiness::default()),
            signals: Arc::default(),
            binding,
            kit,
            leases: Arc::default(),
            #[cfg(feature = "testing")]
            commit_pause: Mutex::new(None),
        })
    }

    /// What tells the carrier of the outbox that there is something to do.
    #[must_use]
    pub fn signals(&self) -> Arc<BackupSignals> {
        Arc::clone(&self.signals)
    }

    /// The account the backups belong to, which the token source of every request of the backup
    /// clients is held to.
    #[must_use]
    pub fn binding(&self) -> Arc<binding::Binding> {
        Arc::clone(&self.binding)
    }

    /// The fingerprint of the kit the recorded setup was made with, when a setup is recorded.
    #[must_use]
    pub fn recorded_kit(&self) -> Option<String> {
        self.kit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn store(&self) -> std::sync::MutexGuard<'_, BackupStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn leases(&self) -> std::sync::MutexGuard<'_, lease::Leases> {
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn readiness(&self) -> std::sync::MutexGuard<'_, Readiness> {
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records that one privacy step could not be carried out in this process, for its request.
    ///
    /// This is a guard, not an account. It can only make this subsystem report *more* work than
    /// the store does, never less, and nothing it holds discharges a durable obligation. Its whole
    /// job is the window the store owns nothing in: a request this host could not even accept
    /// leaves no row behind, so without the guard a failed enabling would look like a host with
    /// nothing to do and would go on producing.
    ///
    /// The store's reason is kept with it, so every later account of the step says why, whichever
    /// caller asks.
    fn note_step_failed(
        &self,
        step: PrivacyStep,
        privacy_generation: u64,
        cause: &ControllerError,
    ) {
        self.readiness().failed.insert(
            FailedStep {
                step,
                privacy_generation,
            },
            cause.to_string(),
        );
        // A host that could not take a privacy step is unready, and a pass that is running is
        // cancelled with it.
        self.leases().cancel_all();
    }

    /// Records that one privacy step did, in the end, do what it was asked.
    ///
    /// Only that step, and only for its own request or an older one. A step that succeeds for
    /// generation `g` says nothing about the same step for a *newer* request, so a repeat of an
    /// older request cannot make this host ready again after a newer one failed. A different step
    /// succeeding says nothing about this one at all, and a read that works says nothing about a
    /// write that did not.
    fn note_step_succeeded(&self, step: PrivacyStep, privacy_generation: u64) {
        self.readiness().failed.retain(|failed, _| {
            failed.step != step || failed.privacy_generation > privacy_generation
        });
    }

    fn failed_steps(&self) -> Vec<String> {
        self.readiness()
            .failed
            .iter()
            .map(|(failed, cause)| format!("{} ({cause})", failed.describe()))
            .collect()
    }

    /// Returns why backup production is refused in this process, if it is.
    ///
    /// The defined readiness condition the production gates enforce: this host has reconciled its
    /// store since it opened, and no privacy step it was asked to take is outstanding.
    #[must_use]
    pub fn unready(&self) -> Option<String> {
        self.readiness().refusal()
    }

    /// Returns the privacy step this process could not take, if there is one.
    ///
    /// What a process that was told to stop and could not withholds, whether or not it has
    /// reconciled. Reconciliation itself runs on a host that is not yet ready, and it may finish
    /// nothing this guard is withholding.
    fn withheld(&self) -> Option<String> {
        self.readiness().withheld()
    }

    fn require_ready(&self) -> Result<()> {
        match self.unready() {
            None => Ok(()),
            Some(detail) => Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail,
            }),
        }
    }

    /// Returns every piece of cleanup privacy mode is owed that this host has not done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read. The error
    /// is the answer: a host that cannot read what it owes does not owe nothing.
    pub fn obligations(&self) -> Result<Vec<Obligation>> {
        self.store().obligations()
    }

    /// Returns where this host stands with privacy mode.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_status(&self) -> Result<PrivacyStatus> {
        self.store().privacy_status()
    }

    /// Returns one privacy request, if this host accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_request(&self, privacy_generation: u64) -> Result<Option<PrivacyRequest>> {
        self.store().privacy_request(privacy_generation)
    }

    /// Returns the directory this service's staged ciphertext lives in, and owns exclusively.
    #[must_use]
    pub fn staging_root(&self) -> PathBuf {
        self.store().staging_root().to_path_buf()
    }

    /// Accepts privacy mode's request to stop backup production, before the fence is attempted.
    ///
    /// The caller takes this step first and keeps the request until it succeeds: a store that
    /// cannot commit it cannot hold it at all, so the request stays the caller's to replay. Once
    /// it is accepted, this host is inhibited whatever happens next.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the generation is older than the one in
    /// force, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn accept_privacy_request(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<PrivacyRequest> {
        // The store lock is held across the guard update, and every production gate reads the
        // guard while holding it. Without that, a gate could pass its readiness check and then
        // wait for the store while this failure was being recorded, and produce afterwards.
        let mut store = self.store();
        self.leases().cancel_all();
        match store.accept_privacy_request(generation.get(), now_ms) {
            Ok(request) => Ok(request),
            Err(error) => {
                // A request this host could not accept leaves no row behind. Nothing but this
                // guard stops it producing as though it had never been asked to stop.
                self.note_step_failed(PrivacyStep::Fence, generation.get(), &error);
                Err(error)
            }
        }
    }

    /// Accepts privacy mode's request and raises the fence it asks for.
    ///
    /// This is the step behind the privacy hook's fence ([`BackupPrivacy`]), which answers with
    /// this error's reason. A failure also sets the readiness guard, on the service rather than on
    /// the hook, so production stays withheld however many hooks are built until the step
    /// succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store will not accept the request
    /// or raise the fence. A request that could not be accepted is the caller's to keep and
    /// replay: no design can persist it in the same database that would not take it.
    pub fn raise_fence(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Fenced> {
        let mut store = self.store();
        self.leases().cancel_all();
        match Self::fence_within_store(&mut store, generation, now_ms) {
            Ok(fenced) => {
                self.note_step_succeeded(PrivacyStep::Fence, generation.get());
                self.signals.fence.notify_one();
                Ok(fenced)
            }
            Err(error) => {
                // Whichever half failed, this host was asked to stop and did not. That is true of
                // this call whether the trait made it or a caller did, so the guard is set here
                // rather than in one wrapper.
                self.note_step_failed(PrivacyStep::Fence, generation.get(), &error);
                Err(error)
            }
        }
    }

    /// Runs `record`, the caller's own record of the privacy boundary, and then raises this
    /// service's fence for `generation`, both inside one hold of the store.
    ///
    /// Every production decision this service makes takes the same hold, so none can fall between
    /// the caller's record and the fence: work is decided either before the boundary was recorded
    /// or after this service was stopped at it. When `record` fails nothing here has changed, and
    /// its error is returned as it was; when the fence then fails, the readiness guard withholds
    /// production exactly as [`Self::raise_fence`] does.
    ///
    /// # Errors
    ///
    /// Returns `record`'s own error, untouched, when it fails. Otherwise returns the fence's
    /// outcome inside `Ok`: [`ControllerError::RegistryUnavailable`] when the store will not accept
    /// the request or raise the fence.
    pub fn raise_fence_recorded<E>(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
        record: impl FnOnce() -> std::result::Result<(), E>,
    ) -> std::result::Result<Result<Fenced>, E> {
        let mut store = self.store();
        self.leases().cancel_all();
        record()?;
        Ok(
            match Self::fence_within_store(&mut store, generation, now_ms) {
                Ok(fenced) => {
                    self.note_step_succeeded(PrivacyStep::Fence, generation.get());
                    self.signals.fence.notify_one();
                    Ok(fenced)
                }
                Err(error) => {
                    self.note_step_failed(PrivacyStep::Fence, generation.get(), &error);
                    Err(error)
                }
            },
        )
    }

    fn fence_within_store(
        store: &mut BackupStore,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Fenced> {
        let items = store
            .outbox()?
            .iter()
            .filter(|attempt| attempt.status == AttemptStatus::Queued)
            .count() as u64;
        store.accept_privacy_request(generation.get(), now_ms)?;
        store.activate_fence(generation.get(), now_ms)?;
        Ok(Fenced { queues: 1, items })
    }

    /// Takes back every admitted, undispatched piece of backup work, with its error kept.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_undispatched_work(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Cancelled> {
        let mut store = self.store();
        match store.cancel_undispatched(now_ms) {
            Ok((undispatched, in_flight)) => {
                self.note_step_succeeded(PrivacyStep::Cancel, generation.get());
                Ok(Cancelled {
                    undispatched,
                    in_flight,
                })
            }
            Err(error) => {
                self.note_step_failed(PrivacyStep::Cancel, generation.get(), &error);
                Err(error)
            }
        }
    }

    /// Carries out the cleanup a fence wrote down, and reports what it actually removed.
    ///
    /// Three passes, in this order, because each one can create work for the next. The staging
    /// walk first, since it turns ciphertext no row names into removals of its own; then the
    /// removals; then whatever bookkeeping is now ready. The obligations are re-read between
    /// passes rather than carried over, so every step acts on the durable list as it stands.
    ///
    /// Each removal follows one order: read the obligation, unlink the file, flush its directory
    /// where the platform allows it, and commit the absence together with the discharge. A stop
    /// between the unlink and the commit leaves the obligation, and the retry accepts a file that
    /// is already gone and finishes the store's half.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    /// A target this host could not remove is not an error: its obligation stays, with the reason
    /// recorded beside it, and cleanup is simply not complete.
    pub fn run_cleanup(
        &self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Removed> {
        let mut store = self.store();
        // A pass that holds the staging directory may be between two writes, so the scan that
        // would call its files unclaimed waits for it. The lease is read in this hold of the
        // store, before the walk: a pass cannot write and end between the walk and the discharge.
        let writing = self.leases().any();
        match Self::cleanup_within_store(&mut store, writing, now_ms) {
            Ok(removed) => {
                self.note_step_succeeded(PrivacyStep::Remove, generation.get());
                Ok(removed)
            }
            Err(error) => {
                self.note_step_failed(PrivacyStep::Remove, generation.get(), &error);
                Err(error)
            }
        }
    }

    fn cleanup_within_store(
        store: &mut BackupStore,
        writing: bool,
        now_ms: TimestampMs,
    ) -> Result<Removed> {
        let mut removed = Removed::default();
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::ScanStaging)
        {
            if writing {
                // Not discharged, and the report says why.
                store.note_obligation_failed(
                    obligation.id,
                    "a backup pass is still writing to the staging directory",
                    now_ms,
                )?;
                continue;
            }
            // What a pass took away is made durable before the walk is called done: names a power
            // loss could bring back are names this cleanup would have reported gone.
            let walked = flush_staging_tree(store.staging_root())
                .and_then(|()| unregistered_staged_files(store));
            match walked {
                Ok(found) => {
                    let records = store.record_staging_scan(&obligation, &found, now_ms)?;
                    removed.records = removed.records.saturating_add(records);
                }
                Err(error) => {
                    // A directory this host cannot read is a directory it cannot say is empty.
                    store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                }
            }
        }
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::UnlinkObject)
        {
            // The staging root is absolute, and a registered path is absolute with it, so an
            // already-rooted path is never rooted a second time. Only the walk's own findings are
            // relative, and they are relative to this root.
            let Some(path) = obligation.staged_path.as_ref().map(|path| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    store.staging_root().join(path)
                }
            }) else {
                continue;
            };
            let bytes = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            };
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                // The file is already gone. The obligation is still this host's to end, because
                // the row that says the ciphertext is here has not been written over yet.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                    continue;
                }
            }
            // The directory of a generation goes with its last file; one that still holds another
            // object stays.
            if let Some(directory) = path.parent()
                && directory != store.staging_root()
            {
                let _ = std::fs::remove_dir(directory);
            }
            // The name is gone from the directory, and the directory entry is flushed so losing
            // power cannot bring it back. A flush this host could not make is not a removal it may
            // report: losing power could return the name, and the obligation that would find it
            // again would be gone. The directory the name was in may be gone too, with its last
            // object, and then it is the nearest one that is still there that is flushed.
            if let Err(error) = sync_removal(&path) {
                store.note_obligation_failed(obligation.id, &error.to_string(), now_ms)?;
                continue;
            }
            let records = store.note_object_unlinked(&obligation)?;
            removed.bytes = removed.bytes.saturating_add(bytes);
            removed.records = removed.records.saturating_add(records);
        }
        for obligation in store
            .obligations()?
            .into_iter()
            .filter(|obligation| obligation.kind == ObligationKind::FinishGeneration)
        {
            removed.records = removed
                .records
                .saturating_add(store.finish_generation(&obligation)?);
        }
        Ok(removed)
    }

    /// Returns everything that keeps this subsystem from reporting its cleanup complete.
    ///
    /// The whole answer, with its error kept, rather than the single count the privacy contract
    /// takes. A caller that has to explain *why* backup cleanup is not finished reads this.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outstanding_work(&self) -> Result<OutstandingWork> {
        let store = self.store();
        let status = store.privacy_status()?;
        let obligations = store.obligations()?;
        let dispatched = store
            .outbox()?
            .iter()
            .filter(|attempt| attempt.status == AttemptStatus::Dispatched)
            .count() as u64;
        Ok(OutstandingWork {
            status,
            obligations,
            dispatched_attempts: dispatched,
            failed_steps: self.failed_steps().into_iter().collect(),
        })
    }

    #[doc(hidden)]
    pub fn set_query_only(&self, query_only: bool) -> Result<()> {
        self.store().set_query_only(query_only)
    }

    /// Enrols a backup writer for one archive.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn enrol_writer(
        &self,
        writer_key_id: KeyId,
        archive_id: ArchiveId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store()
            .enrol_writer(writer_key_id, archive_id, now_ms)?;
        self.signals.work.notify_one();
        Ok(())
    }

    /// Returns the setup the owner made, if there is one, with the count of the generations made
    /// under it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn setup(&self) -> Result<Option<Setup>> {
        self.store().setup()
    }

    /// Returns every writer this host may still publish under, with the archive it may publish.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn authorised_writers(&self) -> Result<Vec<(ArchiveId, KeyId)>> {
        self.store().authorised_writers()
    }

    /// Raises the number of the last generation made for the setup's archive to `generation`, and
    /// never lowers it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn raise_generation_counter(
        &self,
        archive_id: ArchiveId,
        generation: BackupGeneration,
    ) -> Result<()> {
        self.store()
            .raise_generation_counter(archive_id, generation)
    }

    /// Writes the setup the owner made and enrols its writer, in one transaction, and wakes
    /// whatever produces and carries.
    ///
    /// With `replace` over a setup of another archive, the earlier archive's writer is retired and
    /// what it had not finished is cancelled in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when a setup of another archive is there and
    /// `replace` was not asked for, or one of this archive is there with something else recorded,
    /// and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn commit_setup(
        &self,
        record: &SetupRecord,
        replace: bool,
        now_ms: TimestampMs,
    ) -> Result<SetupCommit> {
        #[cfg(feature = "testing")]
        if let Some((arrived, go)) = self
            .commit_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = arrived.send(());
            let _ = go.recv();
        }
        let mut store = self.store();
        let commit = store.commit_setup(record, replace, now_ms)?;
        // Inside the hold in which the setup committed, and nowhere else: from here a request the
        // backup clients make is held to this account.
        if commit != SetupCommit::Unchanged {
            self.binding
                .switch(AccountMark::from_bytes(record.account_mark));
            *self
                .kit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(record.kit_fingerprint.clone());
        }
        if matches!(commit, SetupCommit::Replaced { .. }) {
            // What the earlier archive had running is told to stop with the commit.
            self.leases().cancel_all();
        }
        self.signals.work.notify_one();
        self.signals.produce.notify_one();
        Ok(commit)
    }

    /// Stops the next commit of a setup on its thread, before it commits. Returns the end that
    /// says the thread has arrived and the end that lets it go.
    #[cfg(feature = "testing")]
    pub fn pause_the_next_setup_commit(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (arrived, arrival) = std::sync::mpsc::channel();
        let (go, going) = std::sync::mpsc::channel();
        *self
            .commit_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, going));
        (arrival, go)
    }

    /// Retires a backup writer for one archive, so its unfinished generations there stop being
    /// authorised. Its enrolments for other collections are untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn retire_writer(
        &self,
        archive_id: ArchiveId,
        writer_key_id: KeyId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store()
            .retire_writer(archive_id, writer_key_id, now_ms)
    }

    /// Releases one privacy fence, so backup production is admitted again under a new generation.
    ///
    /// It names both generations, and it refuses while that fence still has cleanup outstanding:
    /// backup production does not resume into a scope this host has not finished clearing, because
    /// new content admitted there would join work that is still being removed. A caller takes this
    /// step after `PrivacyMode::disable`, and takes it again once the cleanup finishes.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the resumed generation is not newer than
    /// the fence, and [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn release_fence(
        &self,
        fence_generation: PrivacyGeneration,
        resumed_generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<FenceRelease> {
        let released =
            self.store()
                .release_fence(fence_generation.get(), resumed_generation.get(), now_ms)?;
        self.signals.work.notify_one();
        self.signals.produce.notify_one();
        Ok(released)
    }

    /// Takes the lease a production pass holds while it writes to the staging directory.
    ///
    /// It is granted under the store's lock, to a service that is ready, with no privacy fence up
    /// and no privacy request accepted whose fence is not up yet. The content the pass reads is
    /// read under the privacy generation the lease names.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the service is not ready or privacy mode stops
    /// production, and [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn begin_production(&self) -> Result<ProductionLease> {
        let store = self.store();
        self.require_ready()?;
        let status = store.privacy_status()?;
        if let Some(fenced_at) = status.inhibited_at() {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!("backup production is fenced at privacy generation {fenced_at}"),
            });
        }
        let (id, flag) = self.leases().grant();
        Ok(ProductionLease::new(
            id,
            flag,
            Arc::clone(&self.leases),
            Arc::clone(&self.signals),
            store.staging_root().to_path_buf(),
            status.current_generation,
        ))
    }

    /// Returns what one generation was made from, if it was made from the host's state.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn made_from(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<MadeFrom>> {
        self.store().made_from(archive_id, backup_generation)
    }

    /// Whether the disk still holds ciphertext that no generation needs any more.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn has_finished_ciphertext(&self) -> Result<bool> {
        let store = self.store();
        // Under a fence the cleanup the fence owes removes what is left, and a removal of the same
        // files and their directory from here would leave that cleanup nothing to flush.
        if store.privacy_status()?.inhibited_at().is_some() {
            return Ok(false);
        }
        Ok(!store.releasable_ciphertext()?.is_empty())
    }

    /// Whether the disk holds ciphertext of a generation whose production is over, in any archive,
    /// whether or not it can be given back yet: an attempt or an upload of it may still be open.
    ///
    /// The producer stages nothing while this is so, so the ciphertext on the disk is at most one
    /// generation's, across a replacement of the setup too.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn holds_finished_ciphertext(&self) -> Result<bool> {
        self.store().holds_finished_ciphertext()
    }

    /// Removes the staged ciphertext of every generation whose production is over and which no
    /// attempt or upload holds open, one object at a time.
    ///
    /// The order is the privacy cleanup's: the file is unlinked, its directory is flushed, and only
    /// then is the row written that says it is absent, so a row never runs ahead of the removal.
    /// A flush that fails leaves the object to release again. The file is found by the staging
    /// root and the object's name, not by the path its row was written with. A generation's
    /// directory goes with its last object.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    /// A file that cannot be removed is not an error: it is counted as pending, with the reason.
    pub fn release_finished_ciphertext(&self) -> Result<Released> {
        let (todo, root) = {
            let store = self.store();
            // Nothing is given back under a fence: the cleanup it owes names the same files and
            // flushes the directories they are in, and it is the cleanup that completes it.
            if store.privacy_status()?.inhibited_at().is_some() {
                return Ok(Released::default());
            }
            (
                store.releasable_ciphertext()?,
                store.staging_root().to_path_buf(),
            )
        };
        let mut released = Released::default();
        for item in todo {
            let path = lease::staged_path_under(
                &root,
                item.archive_id,
                item.backup_generation,
                item.object_id,
            );
            let bytes = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                // Already gone: the row that says the ciphertext is here is what is left to write.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    released.pending += 1;
                    released.failure.get_or_insert_with(|| error.to_string());
                    continue;
                }
            }
            if let Err(error) = sync_removal(&path) {
                released.pending += 1;
                released.failure.get_or_insert_with(|| error.to_string());
                continue;
            }
            let changed = self.store().note_ciphertext_released(
                item.archive_id,
                item.backup_generation,
                item.object_id,
            )?;
            if changed {
                released.objects += 1;
                released.bytes = released.bytes.saturating_add(bytes);
            }
            if let Some(directory) = path.parent() {
                // The last object's removal leaves the generation's directory empty. One that
                // still holds a file is not empty and stays.
                let _ = std::fs::remove_dir(directory);
            }
        }
        if released.objects > 0 {
            // The producer waits for this before it stages another generation.
            self.signals.produce.notify_one();
        }
        Ok(released)
    }

    /// Tells every production pass to stop where it is, and any that begins afterwards. Nothing
    /// waits for any of them.
    pub fn stop_production_passes(&self) {
        self.leases().stop();
    }

    /// Removes the files in the staging directory that no object row names, and the directories
    /// they leave empty.
    ///
    /// A kill between a file's write and the row that names it leaves a file nothing accounts for.
    /// The files are found by their names under the staging root, so a state directory reached by
    /// another spelling than the one a row was written under does not make a claimed file look
    /// unclaimed. A pass that holds the staging directory is not interrupted: nothing is removed
    /// while one runs, and a sweep that finds one claims nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store or the directory cannot be
    /// read, a file cannot be removed, or the staging directory cannot be flushed.
    pub fn remove_unclaimed_staging(&self) -> Result<u64> {
        let store = self.store();
        if self.leases().any() {
            return Ok(0);
        }
        let found = unregistered_staged_files(&store)?;
        let mut removed = 0u64;
        for path in &found {
            match std::fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(ControllerError::registry(error)),
            }
            if let Some(directory) = path.parent()
                && directory != store.staging_root()
            {
                let _ = std::fs::remove_dir(directory);
            }
        }
        // The whole staging directory is flushed on every sweep that runs, the one that found
        // nothing included: a removal whose flush failed last time is not a removal that is made.
        flush_staging_tree(store.staging_root())?;
        Ok(removed)
    }

    /// Prohibits further production of one generation and takes back what it never sent, and
    /// wakes whatever releases the ciphertext of a generation whose production is over.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn cancel_production(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        detail: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.store()
            .cancel_production(archive_id, backup_generation, detail, now_ms)?;
        self.signals.produce.notify_one();
        self.signals.work.notify_one();
        Ok(())
    }

    /// Whether a production pass holds the staging directory now.
    #[must_use]
    pub fn production_running(&self) -> bool {
        self.leases().any()
    }

    /// Records one sealed generation whose ciphertext the pass has already staged under `lease`.
    ///
    /// The ciphertext is written before the rows, so a crash between them leaves files nothing
    /// claims rather than rows naming files that are not there: the next start removes the first,
    /// and nothing can recover from the second. Nothing is written here: each file is found where
    /// the lease put it, at the length its object says, and the rows are one transaction.
    ///
    /// The object keys are never written. They are in the [`StagedObject`]s the caller holds, and
    /// they stop mattering the moment the generation is sealed. `made_from` is the digest of what
    /// the generation was made from, kept with it so that unchanged content makes no second one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the pass was cancelled, the service is not ready
    /// or privacy mode stopped production, or the content was read under a privacy generation
    /// that is no longer in force; [`ControllerError::PermissionDenied`] when the writer is not
    /// enrolled for the archive or did not sign the manifest; [`ControllerError::InvalidArgument`]
    /// when the generation is already admitted, the objects are not the manifest's members, or a
    /// staged file is not the length its object says; and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the transaction.
    pub fn admit_produced(
        &self,
        lease: &ProductionLease,
        sealed: &SealedArchive,
        objects: &[StagedObject],
        writer_key_id: KeyId,
        made_from: MadeFrom,
        now_ms: TimestampMs,
    ) -> Result<Admitted> {
        let archive_id = sealed.descriptor.archive_id;
        let backup_generation = sealed.descriptor.backup_generation;
        // The store lock first, then the guard. A step this process was asked to take and could
        // not, or a store nothing has reconciled since it opened, stops production here; both are
        // cases the store owns no row for. Reading the guard while holding the store lock is what
        // stops this gate passing and then waiting for the store while a failure is recorded.
        let mut store = self.store();
        self.require_ready()?;
        if lease.is_cancelled() {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: "this backup pass was cancelled, by privacy mode or by a replacement of the setup".to_owned(),
            });
        }

        // Privacy mode stopped content-bearing backup production at a generation, and it stays
        // stopped. A host that recorded a fence and then admitted more work would have fenced
        // nothing.
        if let Some(fenced_at) = store.fenced_at()? {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: format!("backup production is fenced at privacy generation {fenced_at}"),
            });
        }
        // Authority is the pair: this writer, this archive.
        if !store.authorises(archive_id, writer_key_id)? {
            return Err(ControllerError::PermissionDenied {
                detail: "this host holds no enrolment of that writer for that archive".to_owned(),
            });
        }
        // A generation already admitted is not admitted again.
        if store.generation(archive_id, backup_generation)?.is_some() {
            return Err(ControllerError::InvalidArgument(
                "that backup generation is already admitted on this host".to_owned(),
            ));
        }
        // The encrypted manifest is staged under its own object identifier, so a member that
        // claimed it would have them write over each other.
        let manifest_object_id = sealed.descriptor.encrypted_manifest.object_id;
        if objects
            .iter()
            .any(|staged| staged.object_id() == manifest_object_id)
        {
            return Err(ControllerError::InvalidArgument(
                "a member object under the encrypted manifest's own identifier".to_owned(),
            ));
        }
        // The writer is the one that signed the manifest, not a label the caller chose. Admitting
        // work under a writer that did not sign it would account for it under an authority it does
        // not have.
        if sealed.signed_manifest.writer_key_id != writer_key_id {
            return Err(ControllerError::PermissionDenied {
                detail: "that generation's manifest is signed by another writer".to_owned(),
            });
        }
        // And the objects are the manifest's members, exactly. A caller that admitted fewer than
        // the manifest names would stage an archive this host could complete and publish while
        // some of its members had never been uploaded at all.
        let members = &sealed.signed_manifest.manifest.objects;
        if members.len() != objects.len()
            || !members.iter().all(|entry| {
                objects
                    .iter()
                    .any(|staged| staged.reference() == &entry.object)
            })
        {
            return Err(ControllerError::InvalidArgument(
                "the objects offered are not the members the signed manifest names".to_owned(),
            ));
        }

        let mut rows: Vec<NewObject> = Vec::with_capacity(objects.len() + 1);
        let mut staged_bytes = 0u64;
        let mut claimed = Vec::with_capacity(objects.len() + 1);
        let manifest = &sealed.descriptor.encrypted_manifest;
        let references = objects
            .iter()
            .map(StagedObject::reference)
            .chain(std::iter::once(manifest));
        for reference in references {
            let path = lease.staged_path(archive_id, backup_generation, reference.object_id);
            let staged_len = std::fs::metadata(&path)
                .map_err(|_| {
                    ControllerError::InvalidArgument(format!(
                        "the ciphertext of object {} is not staged on this host",
                        reference.object_id
                    ))
                })?
                .len();
            if staged_len != reference.encrypted_len.get() {
                return Err(ControllerError::InvalidArgument(format!(
                    "the ciphertext staged for object {} is {staged_len} bytes, and its \
                     reference says {}",
                    reference.object_id,
                    reference.encrypted_len.get()
                )));
            }
            staged_bytes = staged_bytes.saturating_add(staged_len);
            claimed.push(path.clone());
            rows.push(NewObject {
                object_id: reference.object_id,
                encrypted_object_hash: reference.encrypted_object_hash,
                encrypted_len: reference.encrypted_len.get(),
                staged_path: path,
            });
        }

        let offered = NewGeneration {
            archive_id,
            backup_generation,
            writer_key_id,
            descriptor: sealed.descriptor_bytes.clone(),
            created_at_ms: now_ms,
            content_read_under: lease.read_under(),
            made_from: Some(made_from),
        };
        // The privacy generation the row is stamped with is the store's, read inside the
        // transaction that writes it, and the generation the content was read under must be that
        // one. There is no way for this host, or the caller behind it, to admit work read before
        // a fence went up and came down again.
        let admission = store.admit(&offered, &rows, now_ms)?;
        lease.claim(&claimed);
        self.signals.work.notify_one();
        Ok(Admitted {
            archive_id,
            backup_generation,
            sequence: admission.sequence,
            privacy_generation: admission.privacy_generation,
            staged_objects: rows.len(),
            staged_bytes,
        })
    }

    /// Stages one sealed generation's ciphertext and records it, for a test that fabricates a
    /// generation without a production pass.
    ///
    /// It takes a lease of its own, writes each object's ciphertext and the encrypted manifest
    /// under it, and admits through the same call a pass does.
    ///
    /// # Errors
    ///
    /// As [`Self::admit_produced`], and [`ControllerError::RegistryUnavailable`] when the
    /// ciphertext cannot be written.
    #[cfg(any(test, feature = "testing"))]
    pub fn admit(
        &self,
        sealed: &SealedArchive,
        objects: &[StagedObject],
        writer_key_id: KeyId,
        now_ms: TimestampMs,
    ) -> Result<Admitted> {
        let lease = self.begin_production()?;
        let archive_id = sealed.descriptor.archive_id;
        let backup_generation = sealed.descriptor.backup_generation;
        let manifest_object_id = sealed.descriptor.encrypted_manifest.object_id;
        let staging = |object_id, bytes: &[u8]| {
            lease
                .stage(archive_id, backup_generation, object_id, bytes)
                .map(|_| ())
                .map_err(|staging| match staging {
                    Staging::Cancelled => ControllerError::Refused {
                        code: kr_protocol::error::ErrorCode::PermissionDenied,
                        detail: "this backup pass was cancelled, by privacy mode or by a replacement of the setup".to_owned(),
                    },
                    Staging::Failed(error) => error,
                })
        };
        for staged in objects {
            if staged.object_id() == manifest_object_id {
                return Err(ControllerError::InvalidArgument(
                    "a member object under the encrypted manifest's own identifier".to_owned(),
                ));
            }
            staging(staged.object_id(), staged.bytes())?;
        }
        staging(manifest_object_id, &sealed.encrypted_manifest)?;
        let made_from = MadeFrom {
            fingerprint: kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(
                &sealed.descriptor_bytes,
            )),
            unreadable: Vec::new(),
        };
        self.admit_produced(&lease, sealed, objects, writer_key_id, made_from, now_ms)
    }

    /// Hands one queued attempt to `executor`, and records that it has gone.
    ///
    /// The store decides, in the transaction that lets the work go: the attempt is still queued,
    /// nothing inhibits production, and this host has not moved past the privacy generation the
    /// work was admitted under. A caller supplies none of that.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when production is inhibited or the work belongs to a
    /// privacy generation this host has moved past, [`ControllerError::InvalidArgument`] when the
    /// attempt is not queued, and [`ControllerError::RegistryUnavailable`] when the store refuses
    /// the write.
    pub fn note_dispatched(
        &self,
        sequence: u64,
        executor: &str,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let mut store = self.store();
        self.require_ready()?;
        store.note_dispatched(sequence, executor, now_ms)
    }

    /// Records that one object's bytes reached a service, as the attempt that carried them.
    ///
    /// `attempt` is the upload attempt the executor was running, and the acknowledgement is
    /// checked against the work that attempt was enqueued for. **It ends no attempt.** One object
    /// arriving is not the end of a transfer, and a generation with nothing left outstanding is a
    /// fact about its objects: the executor holding the attempt says when it finished, through
    /// [`Self::note_attempt_accepted`].
    ///
    /// Returns true when the generation has no object left to arrive. That is a fact about the
    /// objects, not about the call: an acknowledgement repeated after the upload had finished
    /// returns true again and changes nothing.
    ///
    /// A finished upload ordinarily enqueues the publish attempt in the same transaction. A
    /// generation privacy mode cancelled, or one finishing while production is fenced, gets no
    /// publication at all, so a true here is not a promise that anything is waiting to be
    /// published.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the attempt is not an upload attempt of
    /// that generation that left this host, and [`ControllerError::RegistryUnavailable`] when the
    /// store refuses the write.
    pub fn note_object_uploaded(
        &self,
        attempt: u64,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        now_ms: TimestampMs,
    ) -> Result<bool> {
        self.store()
            .note_object_uploaded(attempt, archive_id, backup_generation, object_id, now_ms)
    }

    /// Records that one upload attempt finished and a service took what it carried.
    ///
    /// The executor that held the attempt is the only thing that can say this, and it says it
    /// about that attempt alone. Another attempt at the same upload keeps its place, whatever the
    /// generation's objects say.
    ///
    /// A publication is answered through [`Self::note_published`] instead, because accepting one
    /// is also the statement that a service holds the archive.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when that attempt is not an upload attempt
    /// that left this host and is either unanswered or already accepted, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_attempt_accepted(&self, attempt: u64, now_ms: TimestampMs) -> Result<()> {
        self.store().note_attempt_accepted(attempt, now_ms)
    }

    /// Records that a service accepted the publication one attempt carried.
    ///
    /// `attempt` is the publication attempt the answer is about; the archive and generation come
    /// from its row. An answer is evidence about one transfer, so a replacement enqueued while
    /// this host could not account for an earlier attempt keeps its place until it is answered in
    /// its own right.
    ///
    /// `produced_under` is the privacy generation the work that produced this result was admitted
    /// under, as the caller reports it, and it is checked against the one this host actually
    /// admitted the work under. Everything else is the store's, read inside the transaction that
    /// records the result.
    ///
    /// An answer that arrives after privacy mode drew its line is recorded as
    /// [`Publication::RetainedArtifact`]: the service holds it, that attempt is over, and nothing
    /// of this host's becomes current. That is what a person is shown, rather than an attempt left
    /// waiting for an answer it had already been given. A process that was told to stop and could
    /// not is in the same position, and its readiness guard withholds completion here too.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the attempt is not a publication attempt
    /// that left this host, [`ControllerError::Refused`] when the result claims a privacy
    /// generation other than the one this host admitted the work under, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_published(
        &self,
        attempt: u64,
        produced_under: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<Publication> {
        let mut store = self.store();
        // Read under the store lock, like every other production decision, so a failure recorded
        // by another thread cannot land between the read and the transaction.
        let withheld = self.unready();
        let publication =
            store.note_published(attempt, produced_under.get(), withheld.as_deref(), now_ms)?;
        // A generation finished: the producer looks again. The carrier releases its ciphertext at
        // the end of the pass it is in.
        self.signals.produce.notify_one();
        Ok(publication)
    }

    /// Records that one attempt stopped and this host cannot establish what became of it.
    ///
    /// It is a statement about two things, and a caller makes it only when both hold: that
    /// transfer has ended, and no answer arrived. From then on the attempt is not in flight - so it
    /// does not hold privacy mode's reconciliation open for ever - and what it carried *is* a copy
    /// that may be at a service, so [`PrivacySubsystem::exported`] shows it as one.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when that attempt is not one that left this
    /// host and is still unanswered, and [`ControllerError::RegistryUnavailable`] when the store
    /// refuses the write.
    pub fn note_attempt_stopped(&self, attempt: u64, now_ms: TimestampMs) -> Result<()> {
        // Both halves of the caller's statement are recorded: that attempt has ended, so it and
        // the obligation naming it end together, and what a service may hold is written down.
        self.store().note_attempt_stopped(attempt, now_ms)?;
        self.signals.produce.notify_one();
        Ok(())
    }

    /// Resolves whatever an earlier daemon left unfinished.
    ///
    /// A generation whose production is over is left exactly as it is. An attempt of it that had
    /// left this host and was never answered is **not** ended here and is listed instead: a
    /// restart is not evidence about what a service did, and a wait ended on the strength of one
    /// would be a cleanup reported over work still out there. Only an answer, or a caller
    /// establishing that the transfer stopped, ends such an attempt.
    ///
    /// For everything still producing there are five answers, in this order:
    ///
    /// * A generation a service **accepted** the descriptor of is produced, and its production is
    ///   finished here. The answer arrived once, and a host that was told to stop and could not
    ///   had to withhold completion when it did; nothing will deliver it again, so leaving the
    ///   generation producing would leave work with nothing to carry it. A process that is *still*
    ///   withholding finishes nothing: the generation stays a retained artifact until the privacy
    ///   step it could not take succeeds and a later reconciliation finishes it.
    /// * A generation whose *publication* was dispatched and never answered has that written down:
    ///   production of it is over, and what a service holds of it is **unknown**. A service may
    ///   hold it and may not, and a host that wrote either answer would be writing something it
    ///   does not know; section 23 never retries that automatically, and retiring the writer
    ///   afterwards must not rewrite an outcome this host never learned.
    /// * A generation whose writer this host no longer holds an enrolment for, **for that
    ///   archive**, is **cancelled**. It is work this host may not do, whatever state it was left
    ///   in.
    /// * A generation privacy mode fenced stays **fenced**. A restart does not un-fence work a
    ///   fence stopped.
    /// * Everything else **resumes**, as a *new* attempt beside the old one. The attempt that left
    ///   this host keeps its identity and stays unanswered, because nothing here has established
    ///   how it ended; sending the same object under the same identity and hash again is not a
    ///   second publication.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub fn reconcile(&self, now_ms: TimestampMs) -> Result<Reconciliation> {
        let mut store = self.store();
        let authorised = store.authorised_writers()?;
        let fenced = store.fenced_at()?;
        let generations = store.generations()?;
        let open = store.outbox()?;
        let mut outcome = Reconciliation::default();
        for record in generations {
            let attempts: Vec<&Attempt> = open
                .iter()
                .filter(|attempt| {
                    attempt.archive_id == record.archive_id
                        && attempt.backup_generation == record.backup_generation
                })
                .collect();
            let unanswered = attempts
                .iter()
                .any(|attempt| attempt.status == AttemptStatus::Dispatched);
            if record.production.is_over() {
                // Nothing is reconstructed here and nothing is ended here. What privacy mode is
                // owed was written down when its fence went up, one row per target, and those
                // rows are what a restart reads back. An attempt that had already left this host
                // is still unanswered: reopening a store is not evidence that it stopped, and a
                // restart that cleared it would report a cleanup nobody had followed.
                if unanswered {
                    outcome
                        .unanswered
                        .push((record.archive_id, record.backup_generation));
                }
                continue;
            }
            // A generation a service accepted the descriptor of is produced. The answer arrived
            // once and is not delivered again, so a host that had to withhold completion at the
            // time finishes it here rather than leaving it producing with nothing to carry it.
            //
            // Unless it is *still* withholding it. A process that was asked to take a privacy step
            // and could not refuses completion everywhere it is decided, and reconciliation is no
            // exception: the generation stays as it is, a retained artifact, until that step
            // succeeds and a later reconciliation finishes it. The guard is read here, while the
            // store lock is held, in the same order as every other production decision.
            if record.remote == Remote::Published
                && self.withheld().is_none()
                && store.finish_accepted_production(
                    record.archive_id,
                    record.backup_generation,
                    now_ms,
                )?
            {
                outcome
                    .completed
                    .push((record.archive_id, record.backup_generation));
                if unanswered {
                    outcome
                        .unanswered
                        .push((record.archive_id, record.backup_generation));
                }
                continue;
            }
            // An uncertain outcome is written down as uncertain even when the writer has since
            // been retired: retiring a writer stops future work and does not rewrite what this
            // host already dispatched and never heard back about.
            if attempts.iter().any(|attempt| {
                attempt.status == AttemptStatus::Dispatched && attempt.step == Step::Publish
            }) {
                store.note_dispatch_unanswered(
                    record.archive_id,
                    record.backup_generation,
                    "its publication left this host and was never answered, so whether a service \
                     holds it is not something this host can say",
                    now_ms,
                )?;
                outcome
                    .outcome_unknown
                    .push((record.archive_id, record.backup_generation));
                outcome
                    .unanswered
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            // Authority is the pair. A writer enrolled for one archive does not authorise
            // unfinished work for another.
            if !authorised.iter().any(|(archive, writer)| {
                *archive == record.archive_id && *writer == record.writer_key_id
            }) {
                store.cancel_production(
                    record.archive_id,
                    record.backup_generation,
                    "this host no longer holds an enrolment of that writer for that archive",
                    now_ms,
                )?;
                outcome
                    .no_longer_authorised
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            // A fence stops what it stopped. A restart does not un-fence undispatched work.
            if fenced.is_some() {
                outcome
                    .fenced
                    .push((record.archive_id, record.backup_generation));
                continue;
            }
            // A fresh attempt at whatever it needs next, beside any attempt that left. The old one
            // is not relabelled as queued: a fence arriving afterwards would then write a
            // cancellation for it, the cancellation would end it, and cleanup could finish with
            // nothing left saying that anything had ever gone to a service.
            //
            // It runs whether or not something is still unanswered, because a generation whose
            // last attempt stopped has nothing carrying it: leaving it there would be work this
            // host had taken on and would never do until a privacy fence cleaned it up.
            store.ensure_open_attempt(record.archive_id, record.backup_generation, now_ms)?;
            if unanswered {
                outcome
                    .unanswered
                    .push((record.archive_id, record.backup_generation));
            }
            outcome
                .resumed
                .push((record.archive_id, record.backup_generation));
        }
        // What an earlier process left unfinished has now been read back, which is the condition
        // this process opens without. A reconciliation that failed returns above and leaves the
        // service unready, so nothing is admitted or dispatched on a store nothing has read. The
        // store lock is still held, so no gate can read a half-updated guard.
        self.readiness().reconciled = true;
        drop(store);
        Ok(outcome)
    }

    /// Returns every generation this host has a record of, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generations(&self) -> Result<Vec<GenerationRecord>> {
        self.store().generations()
    }

    /// Returns one generation's record.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn generation(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<GenerationRecord>> {
        self.store().generation(archive_id, backup_generation)
    }

    /// Returns one generation's objects.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn objects(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Vec<ObjectRecord>> {
        self.store().objects(archive_id, backup_generation)
    }

    /// Returns every attempt this host is still owed an answer about, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn outbox(&self) -> Result<Vec<Attempt>> {
        self.store().outbox()
    }

    /// Returns every attempt this host has made or is making, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn attempts(&self) -> Result<Vec<Attempt>> {
        self.store().attempts()
    }

    /// Returns the privacy generation this host recorded a fence at, if it has.
    ///
    /// It is read back from the store rather than held in memory, so a restart comes back fenced
    /// rather than dispatching the entries the fence had just stopped.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn fenced_at(&self) -> Result<Option<u64>> {
        self.store().fenced_at()
    }
}

/// The binding of the setup the store holds, or none when it holds none.
fn binding_of(store: &BackupStore) -> Result<Arc<binding::Binding>> {
    Ok(match store.setup()? {
        Some(setup) => binding::Binding::of(AccountMark::from_bytes(setup.record.account_mark)),
        None => binding::Binding::unbound(),
    })
}

/// Returns every file under this store's staging directory that no object row names.
///
/// Ciphertext is written before the row that names it, so a stop in between leaves a file nothing
/// accounts for. Only the directory this store owns is walked, and a directory it cannot read is
/// an error rather than an empty answer: "there is nothing there" and "this host cannot look" are
/// not the same finding.
fn unregistered_staged_files(store: &BackupStore) -> Result<Vec<PathBuf>> {
    let registered: std::collections::BTreeSet<PathBuf> =
        store.registered_staged_paths()?.into_iter().collect();
    let mut found = Vec::new();
    let mut directories = vec![store.staging_root().to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ControllerError::registry(error)),
        };
        for entry in entries {
            let entry = entry.map_err(ControllerError::registry)?;
            let path = entry.path();
            let kind = entry.file_type().map_err(ControllerError::registry)?;
            if kind.is_dir() {
                directories.push(path);
            } else if !registered.contains(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Writes one staged object's ciphertext, durably, before any row names it.
///
/// Created exclusively, flushed, and its directory entry flushed, so a row committed afterwards
/// never names a file that losing power would take away. Exclusive creation is also what stops a
/// second admission writing over ciphertext an earlier one is still accounting for.
fn write_staged(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let Some(parent) = path.parent() else {
        return Err(ControllerError::registry(
            "a staged object has no directory",
        ));
    };
    std::fs::create_dir_all(parent).map_err(ControllerError::registry)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(ControllerError::registry)?;
    file.write_all(bytes).map_err(ControllerError::registry)?;
    file.flush().map_err(ControllerError::registry)?;
    file.sync_all().map_err(ControllerError::registry)?;
    drop(file);
    // The bytes are on the disk; the name that reaches them may not be until the directory that
    // holds it is flushed, nor the directory itself until *its* parent is.
    sync_directory(path)
}

/// Flushes the directory entry of `path` and of every directory made for it under the staging root.
///
/// A file flushed into a directory that was itself created and never flushed is a file whose name
/// losing power can take away, so the walk goes up to the staging root rather than stopping at the
/// immediate parent. The directory holding the file is flushed for a file's name and each one above
/// it for a directory's, which is the right the flush's handle asks for on Windows.
fn sync_directory(path: &Path) -> Result<()> {
    flush_up_from(path.parent(), NameKind::File)
}

/// Flushes the directory entries a removal changed: the nearest directory of `path` that is still
/// there, and every one above it up to the staging root. A removal that took an empty directory
/// with it changed the entry in its parent.
fn sync_removal(path: &Path) -> Result<()> {
    let mut directory = path.parent();
    let mut kind = NameKind::File;
    while let Some(current) = directory {
        if current.exists() {
            // A staging root that is gone changed the entry in the nearest directory that is
            // there, and nothing above it: the walk up to the root has no root to stop at.
            let root_gone = path.ancestors().any(|above| {
                above.file_name().is_some_and(|name| name == "backup") && !above.exists()
            });
            if root_gone {
                return flush_directory(current, NameKind::Directory)
                    .map_err(ControllerError::registry);
            }
            return flush_up_from(Some(current), kind);
        }
        kind = NameKind::Directory;
        directory = current.parent();
    }
    Ok(())
}

/// Makes every removal under the staging root durable: the directory of each generation, then the
/// root.
pub(super) fn flush_staging_tree(root: &Path) -> Result<()> {
    // A root that is gone has nothing in it to flush: the removal changed the entry in the nearest
    // directory that is there, which is the only one to flush (none above it is changed), and the
    // next write of a file makes the root again.
    if !root.exists() {
        return sync_removal(root);
    }
    for entry in std::fs::read_dir(root).map_err(ControllerError::registry)? {
        let path = entry.map_err(ControllerError::registry)?.path();
        // A directory that is gone since the listing was taken has nothing left to flush; the
        // flush of the root below makes its removal durable.
        if path.is_dir() {
            match flush_directory(&path, NameKind::File) {
                Ok(()) => {}
                Err(_) if !path.exists() => {}
                Err(error) => return Err(ControllerError::registry(error)),
            }
        }
    }
    flush_directory(root, NameKind::Directory).map_err(ControllerError::registry)
}

fn flush_up_from(start: Option<&Path>, first: NameKind) -> Result<()> {
    let mut directory = start;
    let mut kind = first;
    while let Some(current) = directory {
        flush_directory(current, kind).map_err(ControllerError::registry)?;
        if current.file_name().is_some_and(|name| name == "backup") {
            break;
        }
        kind = NameKind::Directory;
        directory = current.parent();
    }
    Ok(())
}

/// The backup service as privacy mode sees it, for one pass.
///
/// It borrows the service, which a daemon holds shared, and carries the time the pass reads, so
/// every obligation a step writes down is stamped with the same instant. Each step is one of the
/// service's own error-carrying calls, and the reason its store gave is the step's answer. The
/// readiness guard a refused step sets lives on the service, so it withholds production however
/// many hooks are built, and only that step's own success clears it.
#[derive(Debug)]
pub struct BackupPrivacy<'a> {
    service: &'a BackupService,
    now_ms: TimestampMs,
}

impl BackupService {
    /// Returns privacy mode's hook over this service, for one pass at `now_ms`.
    #[must_use]
    pub const fn privacy(&self, now_ms: TimestampMs) -> BackupPrivacy<'_> {
        BackupPrivacy {
            service: self,
            now_ms,
        }
    }
}

/// Says what a step could not do, with the store's own reason.
fn unavailable(what: &str, error: &ControllerError) -> Unavailable {
    Unavailable::new(format!("{what}: {error}"))
}

impl PrivacySubsystem for BackupPrivacy<'_> {
    fn name(&self) -> &'static str {
        SUBSYSTEM_NAME
    }

    /// Stops the outbox at this generation, durably, before anything else is touched.
    ///
    /// Two transactions, in this order, and the order is the point. The first accepts the request
    /// and records the obligation to raise the fence; the second raises it. An activation that
    /// fails therefore leaves an accepted request and an outstanding obligation behind, so this
    /// host is inhibited, counts the work, and cannot report a fence it did not raise. A request
    /// this host could not even accept leaves the caller holding it, with the store's reason.
    fn fence(&mut self, generation: PrivacyGeneration) -> std::result::Result<Fenced, Unavailable> {
        self.service
            .raise_fence(generation, self.now_ms)
            .map_err(|error| unavailable("the backup privacy fence could not be raised", &error))
    }

    /// Takes back every admitted, undispatched piece of backup work.
    ///
    /// What has been dispatched is counted rather than claimed: it has left this host and can only
    /// be followed, which is what reconciliation is for.
    fn cancel_undispatched(
        &mut self,
        generation: PrivacyGeneration,
    ) -> std::result::Result<Cancelled, Unavailable> {
        self.service
            .cancel_undispatched_work(generation, self.now_ms)
            .map_err(|error| {
                unavailable("undispatched backup work could not be taken back", &error)
            })
    }

    /// Carries out the cleanup the fence wrote down, one obligation at a time.
    ///
    /// It reports only what it actually removed, and it ends only what it has evidence for. A file
    /// this host could not unlink keeps its obligation, with the reason written beside it, so the
    /// next pass finds the same target rather than a fresh guess at what is left. That is work
    /// outstanding rather than a refused step; a store that refused the pass itself is the latter.
    fn remove_retained(
        &mut self,
        generation: PrivacyGeneration,
    ) -> std::result::Result<Removed, Unavailable> {
        self.service
            .run_cleanup(generation, self.now_ms)
            .map_err(|error| unavailable("staged backup ciphertext could not be removed", &error))
    }

    /// Returns how much backup work is still being cleaned up.
    ///
    /// One query over the durable rows. While a fence stands, what is outstanding is the cleanup
    /// that fence wrote down and this host has not finished; before there is a fence, it is the
    /// work that has left this host and not been answered. Nothing is counted twice: an attempt
    /// that an obligation already names is that obligation.
    ///
    /// A privacy step this process could not take, and a store that cannot be read, are both
    /// answered as unavailable with the reason, never as a count: "this host cannot say what it
    /// owes" is not "this host owes nothing", and a refused step is in the way rather than
    /// settling.
    fn outstanding(&self) -> std::result::Result<u64, Unavailable> {
        let store = self.service.store();
        // A step this process could not carry out is in the way whatever the store says. It is the
        // one case the store owns nothing for: a request it would not accept left no row behind.
        if let Some(withheld) = self.service.withheld() {
            return Err(Unavailable::new(withheld));
        }
        let status = store.privacy_status().map_err(|error| {
            unavailable(
                "the backup store cannot say what privacy mode is owed",
                &error,
            )
        })?;
        if status.inhibited_at().is_some() {
            // Under a fence the obligations are the account, and nothing else is. A pending
            // activation has an obligation of its own, so a request whose fence never went up is
            // counted here; an attempt that has left this host is counted by the obligation that
            // names it, never a second time. A fence that is still up over finished cleanup is
            // not outstanding work: what is outstanding is what has not been done.
            return Ok(status.obligations);
        }
        // A generation whose outcome is *unknown* is not counted here, and that is deliberate.
        // `note_outcome_unknown` is the caller saying the transfer stopped and the answer never
        // came; the work is not still in flight, and counting it would leave privacy mode
        // reconciling for ever over something that will never become known. It is a copy that may
        // have left, which section 24 answers by showing it: the exported list shows it as a
        // retained artifact whose outcome this host cannot establish.
        let dispatched = store
            .outbox()
            .map_err(|error| {
                unavailable(
                    "the backup store cannot say what has left this host",
                    &error,
                )
            })?
            .iter()
            .filter(|attempt| attempt.status == AttemptStatus::Dispatched)
            .count() as u64;
        Ok(dispatched.saturating_add(status.obligations))
    }

    /// Names what this host keeps whatever privacy mode is doing.
    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![
            KeptExplicitly {
                what: "the record of each backup generation this host produced, and what became \
                       of it",
                why: "a host that forgot which generations it had published could not tell a \
                      replayed older archive from a current one",
            },
            KeptExplicitly {
                what: "the enrolment of each backup writer this host holds",
                why: "a host that forgot its writers could not say whether unfinished work is \
                      still authorised after a restart",
            },
        ]
    }

    /// Names the archives that had already left this host.
    ///
    /// Privacy mode does not erase them and does not claim it could. What it offers is this list:
    /// the reference is the archive and generation, never a path. `deletable` is false, because
    /// this host holds no route through which it could ask a service to remove one; the separately
    /// authorised deletion action section 24 asks for needs that route, and building it belongs
    /// with the component that carries an object to a service.
    ///
    /// What a service holds is read from the generation's own record of it, which production being
    /// cancelled never changes. An archive whose ciphertext was acknowledged and whose production
    /// privacy mode then stopped is listed here, because the bytes are still there.
    fn exported(&self) -> std::result::Result<Vec<Exported>, Unavailable> {
        let store = self.service.store();
        let generations = store
            .generations()
            .map_err(|error| unavailable("the backup store cannot list its generations", &error))?;
        // An attempt that left this host and has not been answered is a copy that may be at a
        // service. It is shown on the same terms as one this host knows left: the alternative is
        // to say nothing about bytes that may well be there.
        let unanswered: Vec<(ArchiveId, BackupGeneration)> = store
            .outbox()
            .map_err(|error| {
                unavailable(
                    "the backup store cannot say what has left this host",
                    &error,
                )
            })?
            .into_iter()
            .filter(|attempt| attempt.status == AttemptStatus::Dispatched)
            .map(|attempt| (attempt.archive_id, attempt.backup_generation))
            .collect();
        let listed = generations
            .into_iter()
            .map(
                |record| -> std::result::Result<Option<Exported>, Unavailable> {
                    let left = record.remote.is_artifact();
                    let in_doubt = unanswered.iter().any(|(archive, generation)| {
                        *archive == record.archive_id && *generation == record.backup_generation
                    });
                    if !left && !in_doubt {
                        return Ok(None);
                    }
                    // What this host has deleted at the service. A generation all of whose objects it
                    // deleted is shown until the service removes them, which is the tombstone window
                    // after the last deletion, and not after; one it deleted some of is shown as that.
                    let objects = store
                        .objects(record.archive_id, record.backup_generation)
                        .map_err(|error| {
                            unavailable(
                                "the backup store cannot list a generation's objects",
                                &error,
                            )
                        })?;
                    let deleted: Vec<u64> = objects
                        .iter()
                        .filter_map(|object| object.released_at_ms.map(TimestampMs::get))
                        .collect();
                    let wholly_deleted = !objects.is_empty() && deleted.len() == objects.len();
                    if wholly_deleted
                        && deleted.iter().max().is_some_and(|last| {
                            self.now_ms.get() >= last.saturating_add(TOMBSTONE_DAYS * 86_400_000)
                        })
                    {
                        return Ok(None);
                    }
                    Ok(Some(Exported {
                        kind: if wholly_deleted {
                            "backup archive, deleted and awaiting removal at the service".to_owned()
                        } else if !deleted.is_empty() {
                            "backup archive, partly deleted".to_owned()
                        } else if record.remote == Remote::Published {
                            "backup archive".to_owned()
                        } else if in_doubt || record.remote == Remote::Unknown {
                            // Something of it left this host and nothing here knows whether a service
                            // kept it. A person is told that rather than told nothing.
                            "backup archive, outcome unknown".to_owned()
                        } else {
                            // A service acknowledged its ciphertext and no descriptor of it was
                            // published. The bytes are there; the archive is not complete.
                            "backup object ciphertext".to_owned()
                        },
                        reference: format!(
                            "{} generation {}",
                            record.archive_id,
                            record.backup_generation.get()
                        ),
                        left_at_ms: record.settled_at_ms.unwrap_or(record.created_at_ms),
                        // False, and it stays false until this host holds a route to ask for the
                        // removal. `deletable` says this host has a way to ask; it does not say a
                        // person cannot ask the service themselves. Claiming otherwise would offer an
                        // action nothing here can perform, which is the false promise section 24
                        // forbids.
                        deletable: false,
                    }))
                },
            )
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(listed.into_iter().flatten().collect())
    }
}
