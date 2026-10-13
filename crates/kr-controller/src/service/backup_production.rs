//! The host's backup producer: what the daemon packs into an archive, and when.
//!
//! Once the owner has set backups up, a task on the daemon's reactor makes one full generation a
//! day when what would be packed has changed. Nothing here holds a seed: the recovery recipient's
//! public key is all the setup keeps of it.
//!
//! # What is packed
//!
//! * `sessions/<session uuid>.json`, one document for each closed session, the document `kr export`
//!   writes, newest closure first. A session still open is not in a backup until it closes.
//! * `host/configuration.json`, the configuration document as the daemon reads it, when it
//!   accepts it.
//!
//! The members, their bounds and their names are the convention's, held in
//! `kr_crypto::backup` for the producer and the restore alike. Over the total, the sessions after
//! the one that would pass it are left out of this generation and `kr doctor` says how many.
//!
//! # When a pass makes a generation
//!
//! Only if every check holds: there is a setup; privacy mode is off; the account and the origin are
//! the setup's; the writer and the producer are the keys it names; the writer is enrolled for the
//! archive; no generation of it is still being made; no finished ciphertext is still on the disk;
//! it has been a day since the newest counted generation; and what would be packed differs from
//! what that generation was made from. The pass holds a lease on the staging directory, which keeps
//! the cleanup privacy mode owes open until it has stopped.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::session_export::{self, Bounds, PageSource, Stop};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, MAX_CONFIGURATION_MEMBER_BYTES,
    MAX_RESTORED_BYTES, MAX_SESSION_MEMBER_BYTES, ObjectSource, StagedObject, seal_archive,
    stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::ids::{BackupGeneration, BackupObjectId, DeviceId, SessionId};
use kr_protocol::recovery::HistoryPageResult;
use kr_protocol::scalars::{Digest256, TimestampMs};
use kr_protocol::session::SessionSummary;
use kr_transport::reconnect::Backoff;

use crate::archive::ArchiveService;
use crate::backup::store::{Production as ProductionState, Setup};
use crate::backup::{ProductionLease, Staging};
use crate::error::{ControllerError, Result};
use crate::quiet::Timer;

use super::Controller;

/// How long after the newest counted generation the next one is made: one snapshot a day.
pub const INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;

/// The most output a host retains of one session: 128 MiB, the cap a producer reads at most.
const RETAINED_PER_SESSION_BYTES: u64 = 128 << 20;

/// The longest a pass waits before it looks at its checks again.
const RECHECK: Duration = Duration::from_secs(60 * 60);

/// How long a pass waits for ciphertext still to be released from the disk.
const RELEASE_WAIT: Duration = Duration::from_secs(60);

/// The sizes a generation is held to: the convention's, which a restore accepts.
///
/// There is one value, `PRODUCTION`, and a daemon takes it; a test lowers it through the same
/// path, so the selection has no branch of its own for a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerBounds {
    /// The most plaintext a session member may hold.
    pub session_member_bytes: u64,
    /// The most plaintext the configuration member may hold.
    pub configuration_member_bytes: u64,
    /// The most plaintext the members hold together.
    pub total_bytes: u64,
    /// The most members one generation holds.
    pub members: usize,
}

impl ProducerBounds {
    /// What a restore accepts: the convention's figures, from the one place they are written.
    pub const PRODUCTION: Self = Self {
        session_member_bytes: MAX_SESSION_MEMBER_BYTES,
        configuration_member_bytes: MAX_CONFIGURATION_MEMBER_BYTES,
        total_bytes: MAX_RESTORED_BYTES,
        members: kr_protocol::archive::MAX_MANIFEST_OBJECTS,
    };
}

/// Why a pass made nothing, as `kr doctor` says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Held {
    /// The owner has not set backups up.
    NoSetup,
    /// Privacy mode is on, or a request for it is accepted.
    Privacy,
    /// The account signed in, or the service origin, is not the setup's.
    Account,
    /// A key the host holds is not the one the setup names.
    Keys,
    /// The writer is not enrolled for the archive any more, as when its collection was deleted at
    /// the account console.
    WriterRetired,
    /// A generation is still being made, uploaded or published.
    InProgress,
    /// The ciphertext of a finished generation is still on the disk, and nothing new is staged
    /// before it is released.
    Releasing,
    /// It has not been a day yet.
    NotDue,
    /// What would be packed is what the newest generation was made from.
    NothingChanged,
    /// There is nothing to pack: no closed session with output and no configuration document.
    NothingToPack,
    /// A pass failed, and the host tries again after a wait.
    Failed(String),
}

/// What the producer last found, for `kr doctor`.
#[derive(Debug, Default)]
pub(crate) struct Observed {
    held: Option<Held>,
    /// How many closed sessions the last pass left out, and whether the configuration was.
    left_out_sessions: u64,
    left_out_configuration: bool,
    /// How many sessions had not closed at the last pass, and so are in no backup yet.
    open_sessions: u64,
    /// The generation the last pass made, and when it is next due.
    next_due_ms: Option<u64>,
}

/// What the daemon needs to produce, when its configuration selects a storage service.
pub(crate) struct Production {
    pub(crate) origin: String,
    pub(crate) writer: AuthorisationKeyPair,
    pub(crate) sender: StoredEnvelopeKeyPair,
    pub(crate) timer: Arc<dyn Timer>,
    bounds: Mutex<ProducerBounds>,
    observed: Mutex<Observed>,
}

impl Production {
    pub(crate) fn new(
        origin: String,
        writer: AuthorisationKeyPair,
        sender: StoredEnvelopeKeyPair,
        timer: Arc<dyn Timer>,
    ) -> Self {
        Self {
            origin,
            writer,
            sender,
            timer,
            bounds: Mutex::new(ProducerBounds::PRODUCTION),
            observed: Mutex::default(),
        }
    }

    fn bounds(&self) -> ProducerBounds {
        *self.bounds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn hold(&self, held: Held) {
        self.observed().held = Some(held);
    }
}

impl std::fmt::Debug for Production {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Production")
            .field("writer_key_id", &self.writer.key_id())
            .finish_non_exhaustive()
    }
}

/// One closed session that may be packed.
struct Candidate {
    summary: SessionSummary,
    closed_at_ms: u64,
    retained_bytes: u64,
}

impl Controller {
    /// Lowers the sizes a generation is held to, for a test of the bounds through the daemon.
    #[cfg(feature = "testing")]
    pub fn lower_producer_bounds(&self, bounds: ProducerBounds) {
        if let Some(production) = &self.backup_production {
            *production
                .bounds
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = bounds;
        }
    }

    /// Starts the producer's task, which runs until the daemon goes. It holds the daemon weakly.
    pub(super) fn start_backup_production(self: &Arc<Self>) {
        let Some(production) = self.backup_production.clone() else {
            return;
        };
        let weak = Arc::downgrade(self);
        let signals = self.backup.signals();
        tokio::spawn(async move {
            let mut backoff = Backoff::new(Duration::from_secs(60), RECHECK);
            loop {
                let Some(controller) = weak.upgrade() else {
                    return;
                };
                let wait = controller.production_pass(&production, &mut backoff).await;
                drop(controller);
                match wait {
                    Some(wait) => {
                        tokio::select! {
                            () = production.timer.sleep(wait) => {}
                            () = signals.produce.notified() => {}
                        }
                    }
                    // What holds the pass back changes only with a signal: a setup committed, a
                    // fence released. Waiting by the clock would only look again at the same thing.
                    None => signals.produce.notified().await,
                }
            }
        });
    }

    /// One look at the checks, and a generation if they all hold. Returns how long to wait, or none
    /// when only a signal can change what held the pass back.
    async fn production_pass(
        self: &Arc<Self>,
        production: &Arc<Production>,
        backoff: &mut Backoff,
    ) -> Option<Duration> {
        let backup = Arc::clone(&self.backup);
        let facts = {
            let backup = Arc::clone(&backup);
            tokio::task::spawn_blocking(move || {
                Ok::<_, ControllerError>((
                    backup.setup()?,
                    backup.generations()?,
                    backup.authorised_writers()?,
                    backup.has_finished_ciphertext()?,
                    backup.privacy_status()?,
                ))
            })
            .await
        };
        let Ok(Ok((setup, generations, writers, finished, privacy))) = facts else {
            production.hold(Held::Failed(
                "the backup store could not be read".to_owned(),
            ));
            return Some(backoff.next_delay());
        };
        let Some(Setup {
            record,
            generation_counter,
        }) = setup
        else {
            production.hold(Held::NoSetup);
            return None;
        };
        if self.privacy.state().now().private || privacy.inhibited_at().is_some() {
            production.hold(Held::Privacy);
            return None;
        }
        let account = self.host_account().mark_at(&production.origin);
        if production.origin != record.origin
            || account.map(|mark| mark.to_bytes()) != Some(record.account_mark)
        {
            production.hold(Held::Account);
            return Some(RECHECK);
        }
        if production.writer.key_id() != record.writer_key_id
            || production.sender.key_id() != record.producer_key_id
        {
            production.hold(Held::Keys);
            return Some(RECHECK);
        }
        if !writers.contains(&(record.archive_id, record.writer_key_id)) {
            production.hold(Held::WriterRetired);
            return Some(RECHECK);
        }
        let mine: Vec<_> = generations
            .iter()
            .filter(|generation| generation.archive_id == record.archive_id)
            .collect();
        if mine
            .iter()
            .any(|generation| generation.production == ProductionState::Producing)
        {
            production.hold(Held::InProgress);
            return Some(RECHECK);
        }
        if finished {
            production.hold(Held::Releasing);
            // The carrier releases it; it is asked to look now.
            backup.signals().work.notify_one();
            return Some(RELEASE_WAIT);
        }
        let now = production.timer.unix_ms();
        // The newest time not in the future among the generations that count. A stored time ahead
        // of the clock is ignored, not clamped, so a clock that was wrong never postpones a pass
        // again and again. A generation privacy cancelled, or whose outcome is unknown, does not
        // suppress the next: the next one carries the backup.
        let newest = mine
            .iter()
            .filter(|generation| {
                matches!(
                    generation.production,
                    ProductionState::Producing | ProductionState::Complete
                ) && generation.created_at_ms.get() <= now
            })
            .max_by_key(|generation| generation.created_at_ms);
        if let Some(newest) = newest {
            let due = newest.created_at_ms.get().saturating_add(INTERVAL_MS);
            production.observed().next_due_ms = Some(due);
            if now < due {
                production.hold(Held::NotDue);
                return Some(Duration::from_millis(due - now).min(RECHECK));
            }
        }

        let bounds = production.bounds();
        let (candidates, open) = match self.closed_candidates().await {
            Ok(found) => found,
            Err(error) => {
                production.hold(Held::Failed(error.to_string()));
                return Some(backoff.next_delay());
            }
        };
        production.observed().open_sessions = open;
        let configuration = self.configuration_member(bounds);
        let selected = bounds
            .members
            .saturating_sub(usize::from(configuration.is_some()));
        let left_out = candidates.len().saturating_sub(selected);
        let mut candidates = candidates;
        candidates.truncate(selected);
        let fingerprint = fingerprint_of(&candidates, configuration.as_deref());
        {
            let mut observed = production.observed();
            observed.left_out_sessions = left_out as u64;
            observed.left_out_configuration = configuration.is_none();
        }
        if candidates.is_empty() && configuration.is_none() {
            production.hold(Held::NothingToPack);
            return Some(RECHECK);
        }
        let unchanged = newest
            .and_then(|generation| {
                backup
                    .made_from(generation.archive_id, generation.backup_generation)
                    .ok()
                    .flatten()
            })
            .is_some_and(|made| made == fingerprint);
        if unchanged {
            production.hold(Held::NothingChanged);
            return Some(RECHECK);
        }

        let lease = match backup.begin_production() {
            Ok(lease) => lease,
            // Refused: privacy mode stopped production between the check and the lease, or the
            // store is not ready. The first is signalled when it is over; the second is looked at
            // again soon.
            Err(_) => {
                production.hold(Held::Privacy);
                return Some(RELEASE_WAIT);
            }
        };
        let archive = self.archive().clone();
        let pass = Pass {
            lease,
            archive,
            setup: record,
            generation: generation_counter.saturating_add(1),
            candidates,
            configuration,
            fingerprint,
            bounds,
            now_ms: now,
            environment: self.paths().environment_id().get(),
            writer: production.writer.clone(),
            sender: production.sender.clone(),
            backup: Arc::clone(&backup),
        };
        let handle = tokio::runtime::Handle::current();
        let made = tokio::task::spawn_blocking(move || handle.block_on(pass.make())).await;
        match made {
            Ok(Ok(Made::Admitted { left_out })) => {
                production.observed().left_out_sessions += left_out;
                production.hold(Held::InProgress);
                backoff.reset();
                Some(RECHECK)
            }
            Ok(Ok(Made::Cancelled)) => {
                production.hold(Held::Privacy);
                None
            }
            Ok(Ok(Made::Nothing)) => {
                production.hold(Held::NothingToPack);
                Some(RECHECK)
            }
            Ok(Err(error)) => {
                production.hold(Held::Failed(error.to_string()));
                Some(backoff.next_delay())
            }
            Err(_) => {
                production.hold(Held::Failed("the pass stopped".to_owned()));
                Some(backoff.next_delay())
            }
        }
    }

    /// The closed sessions that can be packed, newest closure first, and how many sessions have
    /// not closed.
    ///
    /// A session is packed when its closure is recorded, its worker is confirmed ended (the same
    /// check every read of a closed session asks), it owes privacy mode no cleanup, and the
    /// archive holds output for it.
    async fn closed_candidates(self: &Arc<Self>) -> Result<(Vec<Candidate>, u64)> {
        let closed = {
            let registry = self.registry.lock().await;
            let mut closed = Vec::new();
            for reservation in registry.closed_reservations()? {
                if let Some(closure) = registry.closure(reservation.session_id)? {
                    closed.push((closure, reservation.display_number));
                }
            }
            closed
        };
        let privacy = Arc::clone(&self.privacy);
        let now_ms = kr_ipc::now_ms();
        let owing: Vec<SessionId> = tokio::task::spawn_blocking(move || {
            privacy
                .status(now_ms)
                .sessions
                .iter()
                .map(|owing| owing.session_id)
                .collect()
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "privacy mode's report could not be made".to_owned(),
        })?;
        let mut candidates = Vec::new();
        for (closure, display_number) in closed {
            let session_id = closure.session_id;
            if owing.contains(&session_id) || self.refuse_if_live(session_id).await.is_err() {
                continue;
            }
            let spool = self.paths().session_spool(session_id);
            let retained = spool_bytes(&spool);
            if retained == 0 {
                continue;
            }
            let closed_at_ms = closure.closed_at_ms.get();
            candidates.push(Candidate {
                summary: self.closed_session(&closure, display_number).await,
                closed_at_ms,
                retained_bytes: retained,
            });
        }
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.closed_at_ms));
        let registry = self.registry.lock().await;
        let mut open = 0u64;
        for phase in [
            crate::registry::LaunchPhase::Claimed,
            crate::registry::LaunchPhase::Live,
        ] {
            open += registry.reservations_in(phase)?.len() as u64;
        }
        drop(registry);
        Ok((candidates, open))
    }

    /// The configuration document as the daemon accepts it, as the canonical text it is kept as,
    /// or none when it is not there, cannot be used or passes its bound.
    fn configuration_member(&self, bounds: ProducerBounds) -> Option<Vec<u8>> {
        let path = kr_worker::config::document_path(self.paths());
        let bytes = std::fs::read(path).ok()?;
        let loaded = kr_protocol::hostinfo::configuration::load(Some(&bytes));
        if loaded.fails_closed() {
            return None;
        }
        let document = kr_protocol::hostinfo::configuration::contents(&loaded.document?);
        let document = document.into_bytes();
        (document.len() as u64 <= bounds.configuration_member_bytes).then_some(document)
    }

    /// What `kr doctor` says of the producer.
    pub(super) fn production_check(&self) -> kr_protocol::hostinfo::DoctorCheck {
        use kr_protocol::hostinfo::export::Sentence;
        use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};

        let Some(production) = &self.backup_production else {
            return DoctorCheck::new(
                "backup-production",
                "This host makes its backups",
                DoctorStatus::NotApplicable,
                Sentence::new()
                    .stated("no managed storage service is selected, so this host makes none"),
                None,
            );
        };
        let observed = production.observed();
        let (status, mut detail, remedy) = match &observed.held {
            None => (
                DoctorStatus::Ok,
                Sentence::new().stated("no pass has looked yet"),
                None,
            ),
            Some(Held::NoSetup) => (
                DoctorStatus::Warning,
                Sentence::new().stated("backups are not set up on this host"),
                Some("Run `kr backup setup` at a terminal."),
            ),
            Some(Held::Privacy) => (
                DoctorStatus::Ok,
                Sentence::new().stated("privacy mode is on, so nothing is read or backed up"),
                None,
            ),
            Some(Held::Account) => (
                DoctorStatus::Warning,
                Sentence::new().stated(
                    "the account signed in, or the service selected, is not the one the backups \
                     were set up for",
                ),
                Some(
                    "Sign in as that account with `kr account sign-in`, or run `kr backup setup \
                     --replace`.",
                ),
            ),
            Some(Held::Keys) => (
                DoctorStatus::Warning,
                Sentence::new()
                    .stated("a key this host holds is not the one its backups were set up with"),
                Some("Run `kr backup setup --replace`."),
            ),
            Some(Held::WriterRetired) => (
                DoctorStatus::Warning,
                Sentence::new().stated(
                    "this host's backup writer is not enrolled for its archive any more, as when \
                     the collection was deleted at the account console",
                ),
                Some("Run `kr backup setup --replace`."),
            ),
            Some(Held::InProgress) => (
                DoctorStatus::Ok,
                Sentence::new().stated("a backup is being made or sent"),
                None,
            ),
            Some(Held::Releasing) => (
                DoctorStatus::Warning,
                Sentence::new().stated(
                    "the ciphertext of a finished backup is still on this host's disk, so no new \
                     backup is made until it is removed",
                ),
                None,
            ),
            Some(Held::NotDue) => (
                DoctorStatus::Ok,
                Sentence::new().stated("the newest backup is less than a day old"),
                None,
            ),
            Some(Held::NothingChanged) => (
                DoctorStatus::Ok,
                Sentence::new().stated("nothing has changed since the newest backup"),
                None,
            ),
            Some(Held::NothingToPack) => (
                DoctorStatus::Ok,
                Sentence::new().stated("there is no closed session with output to back up"),
                None,
            ),
            Some(Held::Failed(_)) => (
                DoctorStatus::Warning,
                Sentence::new().stated("the last pass failed and will be tried again"),
                None,
            ),
        };
        if observed.open_sessions > 0 {
            detail = detail
                .stated("; ")
                .number(observed.open_sessions)
                .stated(" sessions have not closed and are in no backup until they do");
        }
        if observed.left_out_sessions > 0 {
            detail = detail
                .stated("; ")
                .number(observed.left_out_sessions)
                .stated(" closed sessions were left out of the last backup because of its size");
        }
        if observed.left_out_configuration {
            detail = detail.stated("; the configuration document was not packed");
        }
        DoctorCheck::new(
            "backup-production",
            "This host makes its backups",
            status,
            detail,
            remedy,
        )
    }
}

/// How the pass ended.
enum Made {
    /// A generation was admitted, with this many sessions left out for size.
    Admitted { left_out: u64 },
    /// Every member was left out, so there was nothing to make a generation of.
    Nothing,
    /// Privacy mode cancelled the pass; whatever it wrote is gone.
    Cancelled,
}

/// One pass: everything it needs, moved to the blocking worker that holds the lease.
struct Pass {
    lease: ProductionLease,
    archive: ArchiveService,
    setup: crate::backup::store::SetupRecord,
    generation: u64,
    candidates: Vec<Candidate>,
    configuration: Option<Vec<u8>>,
    fingerprint: Digest256,
    bounds: ProducerBounds,
    now_ms: u64,
    environment: kr_protocol::scalars::Uuid,
    writer: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    backup: Arc<crate::backup::BackupService>,
}

/// The pages of a closed session's retained output, read from the archive under the lease.
struct SpoolPages<'a> {
    archive: &'a ArchiveService,
    session_id: SessionId,
    lease: &'a ProductionLease,
}

impl PageSource for SpoolPages<'_> {
    type Error = Staging;

    async fn page(
        &mut self,
        from_cursor: u64,
        max_bytes: u64,
    ) -> std::result::Result<HistoryPageResult, Staging> {
        if self.lease.is_cancelled() {
            return Err(Staging::Cancelled);
        }
        self.archive
            .history_page(self.session_id, from_cursor, max_bytes)
            .map_err(Staging::Failed)
    }
}

impl Pass {
    async fn make(self) -> Result<Made> {
        let mut objects: Vec<StagedObject> = Vec::new();
        let mut total = 0u64;
        let mut left_out = 0u64;
        let generation = BackupGeneration::new(self.generation);
        let archive_id = self.setup.archive_id;
        let stage = |staged: &mut StagedObject| -> Result<Option<()>> {
            match self
                .lease
                .stage(archive_id, generation, staged.object_id(), staged.bytes())
            {
                Ok(_) => {
                    staged.release_ciphertext();
                    Ok(Some(()))
                }
                Err(Staging::Cancelled) => Ok(None),
                Err(Staging::Failed(error)) => Err(error),
            }
        };
        for candidate in &self.candidates {
            let mut source = SpoolPages {
                archive: &self.archive,
                session_id: candidate.summary.session_id,
                lease: &self.lease,
            };
            let composed = session_export::compose(
                &mut source,
                &candidate.summary,
                Bounds {
                    max_read_bytes: RETAINED_PER_SESSION_BYTES,
                    max_document_bytes: self.bounds.session_member_bytes,
                    max_chunks: session_export::MAX_CHUNKS,
                },
                candidate.retained_bytes,
                self.now_ms,
            )
            .await;
            let composed = match composed {
                Ok(composed) => composed,
                Err(Stop::Source(Staging::Cancelled)) => return Ok(Made::Cancelled),
                // A session whose output cannot be read is left out, and the rest go on.
                Err(_) => {
                    left_out += 1;
                    continue;
                }
            };
            let size = composed.document.len() as u64;
            if total.saturating_add(size) > self.bounds.total_bytes {
                left_out += 1;
                continue;
            }
            total += size;
            let name = format!("sessions/{}.json", candidate.summary.session_id);
            let mut staged = stage_object(
                &ObjectSource {
                    object_id: BackupObjectId::new(kr_ipc::new_uuid()),
                    filename: &name,
                    plaintext: &composed.document,
                },
                KeyRotation::INITIAL,
            )
            .map_err(ControllerError::registry)?;
            drop(composed);
            if stage(&mut staged)?.is_none() {
                return Ok(Made::Cancelled);
            }
            objects.push(staged);
        }
        if let Some(document) = &self.configuration {
            let mut staged = stage_object(
                &ObjectSource {
                    object_id: BackupObjectId::new(kr_ipc::new_uuid()),
                    filename: kr_crypto::backup::CONFIGURATION_MEMBER,
                    plaintext: document,
                },
                KeyRotation::INITIAL,
            )
            .map_err(ControllerError::registry)?;
            if stage(&mut staged)?.is_none() {
                return Ok(Made::Cancelled);
            }
            objects.push(staged);
        }
        if objects.is_empty() {
            return Ok(Made::Nothing);
        }
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        recipients.add(self.setup.recovery_public_key);
        let manifest_object_id = BackupObjectId::new(kr_ipc::new_uuid());
        let sealed = seal_archive(
            &self.writer,
            &self.sender,
            &recipients,
            &ArchivePlan {
                archive_id,
                backup_generation: generation,
                owner_device_id: DeviceId::new(self.environment),
                manifest_object_id,
                created_at_ms: TimestampMs::new(self.now_ms),
            },
            &objects,
        )
        .map_err(ControllerError::registry)?;
        match self.lease.stage(
            archive_id,
            generation,
            manifest_object_id,
            &sealed.encrypted_manifest,
        ) {
            Ok(_) => {}
            Err(Staging::Cancelled) => return Ok(Made::Cancelled),
            Err(Staging::Failed(error)) => return Err(error),
        }
        match self.backup.admit_produced(
            &self.lease,
            &sealed,
            &objects,
            self.writer.key_id(),
            self.fingerprint,
            TimestampMs::new(self.now_ms),
        ) {
            Ok(_) => Ok(Made::Admitted { left_out }),
            // Privacy mode cancelled the pass between its last write and its admission.
            Err(ControllerError::Refused { .. }) if self.lease.is_cancelled() => {
                Ok(Made::Cancelled)
            }
            Err(error) => Err(error),
        }
    }
}

/// The bytes the spool of one session holds, which is how much retained output there is.
fn spool_bytes(directory: &std::path::Path) -> u64 {
    std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .sum()
}

/// A digest of what would be packed: each session's identifier, when it closed and how much output
/// it retains, and the configuration's own digest. The identifiers go into the digest and nowhere
/// else; a member's name is inside the encrypted manifest and the store never writes it down.
fn fingerprint_of(candidates: &[Candidate], configuration: Option<&[u8]>) -> Digest256 {
    let mut hashed = Vec::new();
    hashed.extend_from_slice(b"kalareach-backup-source/1");
    for candidate in candidates {
        hashed.extend_from_slice(candidate.summary.session_id.get().as_bytes());
        hashed.extend_from_slice(&candidate.closed_at_ms.to_be_bytes());
        hashed.extend_from_slice(&candidate.retained_bytes.to_be_bytes());
    }
    match configuration {
        Some(document) => {
            hashed.push(1);
            hashed.extend_from_slice(&kr_cbor::sha256(document));
        }
        None => hashed.push(0),
    }
    Digest256::from_bytes(kr_cbor::sha256(&hashed))
}
