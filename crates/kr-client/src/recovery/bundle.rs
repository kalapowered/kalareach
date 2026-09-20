//! The recovery bundle at its stable locator: reading it, committing it, and moving it.
//!
//! The bundle is the only thing a restore trusts a writer key from. Everything about how it is
//! written follows from that:
//!
//! * **Committed before the writer is declared.** [`BundleStore::enable_writer`] writes the bundle
//!   and only then returns [`WriterEnabled`], which is what a caller needs to declare a writer
//!   recovery-enabled. There is no other way to build one.
//! * **Compare-and-swap at the locator.** Two devices that both enrol a writer do not lose one
//!   another's enrolment silently: the loser is told its generation moved on and reads again.
//! * **Bound to where it is stored.** The encryption key mixes the seed with the origin and the
//!   locator, so a bundle copied to another location does not authenticate there. A migration is
//!   therefore a deliberate act with its own record, not a copy.

use std::sync::Arc;

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{
    ArchiveCheckpoint, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle, RecoveryContext,
    RecoveryKit, TrustedProducer, TrustedWriter,
};
use kr_protocol::scalars::{Bytes, KeyId, StoredEnvelopeKey, TimestampMs, U64};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::recovery::{RecoveryError, Result};
use crate::services::SyncBackupService;

/// Returns the collection name one bundle is stored under.
///
/// It is the locator itself. The locator is opaque and stable, which is the whole point of it:
/// bundle updates go to the same name for the life of the kit, so enabling a new writer never
/// means reprinting the seed.
#[must_use]
pub fn bundle_collection(context: &RecoveryContext) -> &str {
    &context.bundle_locator
}

/// The owner's bundle at one service, and the generation this device last saw.
#[derive(Clone)]
pub struct BundleStore {
    service: Arc<dyn SyncBackupService>,
    context: RecoveryContext,
    generation: Option<u64>,
    /// The bundle this store last authenticated at that generation.
    ///
    /// A caller holding a bundle it read earlier holds a snapshot, and writing that snapshot back
    /// against this store's newer compare-and-swap token would write over whatever landed in
    /// between. The store keeps what it read, so a commit of a bundle that is not what this store
    /// last saw is refused rather than accepted with the token it happens to hold.
    held: Option<RecoveryBundle>,
}

impl std::fmt::Debug for BundleStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleStore")
            .field("service_origin", &self.context.service_origin)
            .field("bundle_locator", &self.context.bundle_locator)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl BundleStore {
    /// Opens the bundle at one retrieval context.
    #[must_use]
    pub fn new(service: Arc<dyn SyncBackupService>, context: RecoveryContext) -> Self {
        Self {
            service,
            context,
            generation: None,
            held: None,
        }
    }

    /// Returns where this bundle is stored.
    #[must_use]
    pub const fn context(&self) -> &RecoveryContext {
        &self.context
    }

    /// Returns the generation this device last read or wrote, when it has one.
    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// Builds the first bundle for a collection that has none.
    #[must_use]
    pub fn empty(now_ms: TimestampMs) -> RecoveryBundle {
        RecoveryBundle {
            schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
            collections: Vec::new(),
            trusted_writers: [].into_iter().collect(),
            trusted_producers: [].into_iter().collect(),
            checkpoints: [].into_iter().collect(),
            revision: U64::new(0),
            written_at_ms: now_ms,
        }
    }

    /// Fetches the bundle and authenticates it under the key this seed and context derive.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleNotAuthentic`] when the bytes do not open here, which is
    /// what a substituted origin or locator looks like, and a service error when the fetch fails.
    pub async fn fetch(&mut self, seed: &RecoverySeed) -> Result<RecoveryBundle> {
        let (generation, bundle) = self.read(seed).await?;
        self.generation = Some(generation);
        self.held = Some(bundle.clone());
        Ok(bundle)
    }

    /// Reads and authenticates the bundle without making it this store's.
    ///
    /// [`Self::fetch`] is this and the remembering. A caller that has still to decide whether what
    /// came back is acceptable wants this one: a bundle adopted before it was judged would leave
    /// this store holding the very thing it went on to refuse, and the refusal would then pass on
    /// the next attempt.
    async fn read(&self, seed: &RecoverySeed) -> Result<(u64, RecoveryBundle)> {
        let (generation, ciphertext) = self
            .service
            .fetch(bundle_collection(&self.context))
            .await
            .map_err(RecoveryError::Service)?;
        let key = seed.bundle_key_for(&self.context)?;
        let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &ciphertext)
            .map_err(|_| RecoveryError::BundleNotAuthentic)?;
        Ok((generation, bundle))
    }

    /// Commits a bundle at the generation this device last saw.
    ///
    /// The revision advances with the write, so a reader can tell which of two bundles it is
    /// holding without asking the service.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleConflict`] when another device wrote first, and a service
    /// error when the write fails.
    pub async fn commit(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let expected = self.generation.unwrap_or(0);
        // The bundle being written has to be the one this store last authenticated, changed. A
        // snapshot from before somebody else's write would otherwise be committed against this
        // store's newer token and take their change with it.
        if self
            .held
            .as_ref()
            .is_some_and(|held| held.revision.get() != bundle.revision.get())
        {
            return Err(RecoveryError::BundleConflict { expected });
        }
        // The candidate is prepared beside the caller's bundle, so a failure anywhere below leaves
        // the caller's revision where it was: a rollback after the fact would not cover a failure
        // that happened before it, and the caller would then be holding a revision it could never
        // commit.
        let mut candidate = bundle.clone();
        candidate.revision = U64::new(candidate.revision.get().saturating_add(1));
        candidate.written_at_ms = now_ms;
        let key = seed.bundle_key_for(&self.context)?;
        let ciphertext = kr_crypto::archive::encrypt_recovery_bundle(&key, &candidate)?;
        match self
            .service
            .compare_exchange(bundle_collection(&self.context), expected, &ciphertext)
            .await
        {
            Ok(generation) => {
                self.generation = Some(generation);
                self.held = Some(candidate.clone());
                *bundle = candidate;
                Ok(generation)
            }
            Err(error) => Err(conflict_or_service(error, expected)),
        }
    }

    /// Enables a backup writer, committing the updated bundle *before* declaring it.
    ///
    /// Section 20: *enabling a new backup writer or rotating its signing key commits an updated
    /// bundle before declaring that writer recovery-enabled.* The declaration is
    /// [`WriterEnabled`], and it is returned by this call and constructed nowhere else, so a
    /// caller cannot declare a writer whose bundle has not landed.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns. The writer is not declared when the commit
    /// fails.
    pub async fn enable_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        writer: TrustedWriter,
        now_ms: TimestampMs,
    ) -> Result<WriterEnabled> {
        let writer_key_id = writer.writer_key_id;
        let mut writers: Vec<TrustedWriter> = bundle.trusted_writers.iter().cloned().collect();
        writers.retain(|held| held.writer_key_id != writer_key_id);
        writers.push(writer);
        bundle.trusted_writers = writers.into_iter().collect();
        let generation = self.commit(seed, bundle, now_ms).await?;
        Ok(WriterEnabled {
            writer_key_id,
            context: self.context.clone(),
            bundle_revision: bundle.revision.get(),
            bundle_generation: generation,
        })
    }

    /// Enrols the producer whose key wraps a restore will have to open.
    ///
    /// A restore that has only the kit needs the producer's *public* stored-envelope key: a wrap
    /// is a `crypto_box` between two keys and the descriptor carries only an identifier, which is
    /// a hash. Taking it from the archive instead would be taking key material from something
    /// untrusted, which is the one thing section 20 ¶10 forbids.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn enable_producer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        sender_key_id: KeyId,
        stored_envelope_key: StoredEnvelopeKey,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let mut producers: Vec<TrustedProducer> =
            bundle.trusted_producers.iter().cloned().collect();
        producers.retain(|held| held.sender_key_id != sender_key_id);
        producers.push(TrustedProducer {
            sender_key_id,
            stored_envelope_key,
            enrolled_at_ms: now_ms,
        });
        bundle.trusted_producers = producers.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Rotates a writer's signing key: the replacement enters the bundle and the retired key
    /// stays, in one commit.
    ///
    /// **The retired key stays.** The bundle is the only place a restore takes a writer key from,
    /// so removing the old one would leave every archive it had already signed unverifiable: a
    /// rotation would silently destroy the backups it was meant to protect. What rotation changes
    /// is which writer may *publish*, and that is the collection's enrolment record rather than
    /// this set. [`Self::retire_writer`] is the separate, deliberate step that drops a key once no
    /// retained archive needs it.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn rotate_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        replacement: TrustedWriter,
        now_ms: TimestampMs,
    ) -> Result<WriterEnabled> {
        self.enable_writer(seed, bundle, replacement, now_ms).await
    }

    /// Drops a writer key from the bundle, which no restore will verify against afterwards.
    ///
    /// It is separate from a rotation because it is a different decision: rotating a key is about
    /// what may be published next, and dropping one is about what may still be read. A caller
    /// takes this step when no retained archive is signed by that key any more.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::commit`] returns.
    pub async fn retire_writer(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        retiring: &KeyId,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let mut writers: Vec<TrustedWriter> = bundle.trusted_writers.iter().cloned().collect();
        writers.retain(|held| &held.writer_key_id != retiring);
        bundle.trusted_writers = writers.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Records the latest generation the owner has verified for one archive.
    ///
    /// A checkpoint only ever moves forward. A verification of generation four arriving after one
    /// of generation nine is a late answer, not a newer fact, and writing it would give a service
    /// five generations of archives it could replay unnoticed. The compare-and-swap protects the
    /// bundle's revision; this protects what the bundle says.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::CheckpointWentBackwards`] when the recorded generation is newer
    /// than this one, and whatever [`Self::commit`] returns.
    pub async fn record_checkpoint(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        checkpoint: ArchiveCheckpoint,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let mut checkpoints: Vec<ArchiveCheckpoint> = bundle.checkpoints.iter().cloned().collect();
        if let Some(held) = checkpoints
            .iter()
            .find(|held| held.archive_id == checkpoint.archive_id)
        {
            if held.backup_generation.get() > checkpoint.backup_generation.get() {
                return Err(RecoveryError::CheckpointWentBackwards {
                    recorded: held.backup_generation.get(),
                    offered: checkpoint.backup_generation.get(),
                });
            }
            if held.backup_generation == checkpoint.backup_generation
                && held.encrypted_manifest_hash != checkpoint.encrypted_manifest_hash
            {
                return Err(RecoveryError::CheckpointWentBackwards {
                    recorded: held.backup_generation.get(),
                    offered: checkpoint.backup_generation.get(),
                });
            }
        }
        checkpoints.retain(|held| held.archive_id != checkpoint.archive_id);
        checkpoints.push(checkpoint);
        bundle.checkpoints = checkpoints.into_iter().collect();
        self.commit(seed, bundle, now_ms).await
    }

    /// Moves the bundle to another service origin or another locator.
    ///
    /// The key is bound to where the bundle lives, so a migration re-encrypts rather than copies.
    /// It is verified before it is reported: the bundle is written at the new location, read back
    /// from it and authenticated there, and only then is the updated kit produced. A migration
    /// that could not be read back is not a migration.
    ///
    /// **The copy at the old location stays there.** This seam publishes and fetches; it does not
    /// delete, and removing the old object is the service's own operation. That is also the safer
    /// order: a bundle removed before its owner has the new kit in hand would be a migration that
    /// lost the archive it was moving. [`MigrationRecord::describe`] says so, because an owner who
    /// keeps the old kit keeps a kit that still opens a superseded bundle.
    ///
    /// **Everything that can be checked is checked before anything is written.** The kit is the
    /// one this store's bundle belongs to and carries the seed being migrated; the bundle at the
    /// old location is read again and has to be the one the caller is holding, so a write another
    /// device made in between is a conflict rather than a migration that quietly moves an older
    /// writer set. What cannot be checked first is the write itself: a destination that takes the
    /// bundle and then fails to serve it back leaves the new location populated and this store
    /// where it was. The caller's bundle is untouched in that case, so reading the old location
    /// again is a valid retry, and the destination object has to be cleared before one can
    /// succeed.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::UnknownServiceOrigin`] when the kit does not name this store's
    /// origin, [`RecoveryError::KitLocatorMismatch`] when it names another bundle,
    /// [`RecoveryError::MigrationWouldLoseAnOrigin`] for a kit that names several origins,
    /// [`RecoveryError::KitIsForAnotherSeed`] when the kit and the seed disagree,
    /// [`RecoveryError::BundleConflict`] when the old location has moved on,
    /// [`RecoveryError::BundleNotAuthentic`] when the bundle does not read back at the new
    /// location, and whatever [`Self::commit`] returns for the write itself.
    pub async fn migrate(
        &mut self,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        kit: &RecoveryKit,
        destination_service: Arc<dyn SyncBackupService>,
        destination: RecoveryContext,
        now_ms: TimestampMs,
    ) -> Result<Migrated> {
        // A kit's origins share one locator, so the updated kit can name only the destination: an
        // origin left in it would point at a bundle this migration did not move. That makes a kit
        // naming several origins impossible to migrate one service at a time without losing the
        // others, so it is refused rather than silently reduced. Per-origin locators are what a
        // multiple-service migration needs, and this build does not have them.
        if kit.service_origins.len() > 1 {
            return Err(RecoveryError::MigrationWouldLoseAnOrigin {
                origins: kit.service_origins.len(),
            });
        }
        if !kit
            .service_origins
            .iter()
            .any(|origin| origin == &self.context.service_origin)
        {
            return Err(RecoveryError::UnknownServiceOrigin);
        }
        if kit.bundle_locator != self.context.bundle_locator {
            return Err(RecoveryError::KitLocatorMismatch);
        }
        // The kit has to be this seed's. `from_kit` reads it under its declared profile and checks
        // its own checksum, which is what a mistyped or foreign-profile kit fails; the checksums
        // then have to agree, because the updated kit this call returns is built from the *seed*,
        // and a caller that handed in a kit for another seed would be handed back a kit that opens
        // nothing it owns while its existing archives still wrap their keys for the old recovery
        // recipient.
        let kit_seed = RecoverySeed::from_kit(kit)?;
        if !kit_seed
            .bundle_key_for(&self.context)?
            .constant_time_eq(&seed.bundle_key_for(&self.context)?)
        {
            return Err(RecoveryError::KitIsForAnotherSeed);
        }

        // The kit the migration will hand back has to be one its owner can actually keep. A
        // destination whose locator cannot be printed, or whose kit is larger than a scannable
        // code, would otherwise be found out after the bundle had been written there, which is
        // the one failure this call cannot undo.
        let origins = vec![destination.service_origin.clone()];
        let updated_kit =
            kr_crypto::kdf::RecoverySeed::to_kit(seed, origins, destination.bundle_locator.clone());
        drop(crate::recovery::kit::render(&updated_kit)?);

        // The bundle being moved has to be the one at the old location *now*, not the one this
        // device read at some point. Migrating a snapshot from before somebody else's write would
        // move an older writer set and older checkpoints to the new location and point the updated
        // kit at them. Reading it again is also what proves this seed opens it: a seed that does
        // not is an authentication failure here rather than a bundle re-encrypted under the wrong
        // authority at the destination.
        //
        // Authentication says who could have written the ciphertext, never how long ago. A service
        // that serves a bundle this device has already seen superseded is serving a replay, so the
        // revision this store knew is held against what comes back: a source that has gone
        // backwards is a conflict, not a migration that quietly drops the writers in between. The
        // read does not make what it returns this store's, so a refused replay does not become the
        // baseline that would let the next attempt through.
        let known = self.held.as_ref().map(|held| held.revision.get());
        let (_, current) = self.read(seed).await?;
        if &current != bundle || known.is_some_and(|known| known > current.revision.get()) {
            return Err(RecoveryError::BundleConflict {
                expected: self.generation.unwrap_or(0),
            });
        }
        let origin = self.context.clone();
        // The candidate is prepared beside the caller's bundle. A destination that takes the write
        // and then fails to serve it back must not leave the caller holding a revision it has
        // nowhere to commit: what it holds is still the bundle at the old location.
        let mut candidate = bundle.clone();
        let mut moved = Self::new(destination_service, destination.clone());
        let generation = moved.commit(seed, &mut candidate, now_ms).await?;
        // Read back and authenticate at the new location. The key there is a different key, so a
        // service that stored the old ciphertext under the new name fails here.
        let verified = moved.fetch(seed).await?;
        if verified != candidate {
            // The revision alone would not do: a service that served a different bundle at the
            // same revision would pass. What was written is what has to come back.
            return Err(RecoveryError::BundleNotAuthentic);
        }

        *bundle = candidate;
        *self = moved;
        Ok(Migrated {
            record: MigrationRecord {
                from: origin,
                to: destination,
                bundle_revision: bundle.revision.get(),
                bundle_generation: generation,
                verified_at_ms: now_ms,
            },
            updated_kit,
        })
    }
}

/// The evidence that a writer's bundle landed before the writer was declared.
///
/// It is returned by [`BundleStore::enable_writer`] and built nowhere else, so holding one is
/// holding the ordering section 20 requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterEnabled {
    writer_key_id: KeyId,
    context: RecoveryContext,
    bundle_revision: u64,
    bundle_generation: u64,
}

impl WriterEnabled {
    /// Returns the writer this evidence is for.
    #[must_use]
    pub const fn writer_key_id(&self) -> KeyId {
        self.writer_key_id
    }

    /// Returns where the bundle that carries it is stored.
    ///
    /// The evidence is about one bundle at one location. A writer enabled in the bundle at one
    /// origin is not enabled in the bundle at another, and carrying the context is what stops that
    /// being assumed.
    #[must_use]
    pub const fn context(&self) -> &RecoveryContext {
        &self.context
    }

    /// Returns the bundle revision that carries the writer.
    #[must_use]
    pub const fn bundle_revision(&self) -> u64 {
        self.bundle_revision
    }

    /// Returns the service generation the bundle was committed at.
    #[must_use]
    pub const fn bundle_generation(&self) -> u64 {
        self.bundle_generation
    }
}

/// A verified move of the bundle to another origin or locator.
///
/// It names both locations, because after a migration both hold bytes: the new one holds the
/// bundle and the old one holds the copy it superseded, until the service removes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRecord {
    /// Where the bundle was.
    pub from: RecoveryContext,
    /// Where it is now.
    pub to: RecoveryContext,
    /// The revision that was moved.
    pub bundle_revision: u64,
    /// The service generation it landed at.
    pub bundle_generation: u64,
    /// When it was read back and authenticated at the new location.
    pub verified_at_ms: TimestampMs,
}

impl MigrationRecord {
    /// The sentence an owner is shown, which says what to do with the kit they were holding.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "Your recovery bundle is now at {} under a new locator, and it was read back and \
             authenticated there. Keep the updated kit and destroy the old one: the old kit still \
             opens the copy left at {}, which is the bundle as it was before this move.",
            self.to.service_origin, self.from.service_origin
        )
    }
}

/// A migration and the kit it obsoletes the old one with.
#[derive(Debug)]
pub struct Migrated {
    /// The verified record of the move.
    pub record: MigrationRecord,
    /// The kit a person keeps from now on. The old one points at a location the bundle has left.
    pub updated_kit: RecoveryKit,
}

/// One offline export: the encrypted bundle and the selected archives' own ciphertext.
///
/// Everything in it is already encrypted, so the export adds no protection of its own and claims
/// none. It exists so an owner can keep a copy somewhere the service is not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineExport {
    /// The encrypted recovery bundle, as the service holds it.
    pub encrypted_bundle: Bytes,
    /// The archive's public descriptor bytes.
    pub descriptor: Bytes,
    /// The encrypted archive manifest object.
    pub encrypted_manifest: Bytes,
    /// The selected member objects' encrypted bytes.
    pub objects: Vec<Bytes>,
}

impl OfflineExport {
    /// Constructs one offline export.
    #[must_use]
    pub fn new(
        encrypted_bundle: Vec<u8>,
        descriptor: Vec<u8>,
        encrypted_manifest: Vec<u8>,
        objects: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            encrypted_bundle: Bytes::new(encrypted_bundle),
            descriptor: Bytes::new(descriptor),
            encrypted_manifest: Bytes::new(encrypted_manifest),
            objects: objects.into_iter().map(Bytes::new).collect(),
        }
    }

    /// Encodes this offline export into its canonical KR-CBOR-1 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the export cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(kr_cbor::to_canonical_vec(self)?)
    }

    /// Decodes an offline export from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the bytes cannot be decoded.
    pub fn from_canonical_slice(bytes: &[u8]) -> Result<Self> {
        let limits = kr_cbor::Limits {
            max_message_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_message_len),
            max_bytes_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_bytes_len),
            max_collection_len: 65_536,
            max_items: 1_000_000,
            ..kr_cbor::Limits::DEFAULT
        };
        Ok(kr_cbor::from_canonical_slice(bytes, &limits)?)
    }
}

/// Turns a compare-and-exchange refusal into a conflict where that is what it was.
///
/// `DRAFT_CONFLICT` is the code section 23 gives a compare-and-exchange whose subject changed
/// under the request, and the sync and backup service answers every one of its collections with
/// it. A bundle write that lost the comparison is that, not a failure of the service.
fn conflict_or_service(error: ClientError, expected: u64) -> RecoveryError {
    if error.code() == kr_protocol::error::ErrorCode::DraftConflict {
        RecoveryError::BundleConflict { expected }
    } else {
        RecoveryError::Service(error)
    }
}
