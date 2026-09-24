//! Recovery: the owner's seed, the kit that carries it, the bundle it authenticates, and what a
//! fresh restore may and may not put back.
//!
//! Section 20 ¶9 to ¶13. The cryptography is `kr-crypto`'s: the seed's two `KRRECOV1` subkeys, the
//! recovery recipient, and the bundle's context-bound encryption. What this module adds is the
//! order those pieces go in, which is where the guarantees actually live:
//!
//! * **The bundle is committed before a writer is declared recovery-enabled.** A writer enabled
//!   first and written down second is a writer whose archives a restore cannot verify.
//!   [`BundleStore::enable_writer`] returns the evidence, and the evidence cannot be built without
//!   the commit having landed.
//! * **Service access is not decryption.** A fresh restore obtains access through the configured
//!   retrieval policy and then authenticates the bundle with the kit. Signing in gets a restore to
//!   the ciphertext and no further: [`FreshRestore`] will not open a bundle it has only access to.
//! * **Substituting the origin or the locator fails authentication.** The bundle's key is derived
//!   from the seed *and* its retrieval context, so a bundle served from somewhere else does not
//!   open. It does not fall back to a writer key the archive supplied, because nothing here reads
//!   a writer key out of an archive at all.
//! * **A restore puts back data and device configuration, and nothing that would recreate
//!   authority.** [`may_back_up`] and [`may_restore`] are that rule, each case with the reason it
//!   is refused.
//! * **Settings come back as the device's own, and nothing comes back with them.**
//!   [`export_settings`] and [`import_settings`] are the paths this device's settings object takes
//!   into a recovery-enabled archive and out of one, and each asks the table for what it carries.
//!   Neither carries a settings collection's key, its key records, this device's membership or
//!   where the object stood on the sync service, so a restored device joins a collection only once
//!   the owner has paired it again and a member has authorised it.
//!
//! # What the seed is, and is not
//!
//! It is the whole of the owner's recovery authority, and the service never holds it. An account
//! password reset therefore returns an account and nothing else: [`SeedSource`] is the complete
//! list of places a seed comes from, and a service is not one of them.

mod bundle;
mod kit;
mod record;
mod restore;
mod settings;

use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::Digest256;

use crate::services::SyncPosition;

pub use crate::recovery::bundle::{
    BundleStore, LostWrite, Migrated, MigrationRecord, OfflineExport, WriterEnabled,
    bundle_collection,
};
pub use crate::recovery::kit::{
    MAX_RECOVERY_KIT_BYTES, RECOVERY_KIT_FORMAT, parse as parse_kit, qr_payload,
    render as render_kit,
};
pub use crate::recovery::restore::{FreshRestore, RetrievalPolicy, ServiceAccess, TrustedMaterial};
pub use crate::recovery::settings::{
    ExportedSettings, ImportedSettings, SETTINGS_FILENAME, export_settings, import_settings,
};
// One definition of what a backup carries, in the crate that owns the backup layer. A device and a
// host that answered this question separately could answer it differently; they ask the same table.
pub use kr_crypto::backup::{
    Admission, Material, RestoreAdmissions, RestoreLimits, may_back_up, may_restore,
};

/// What can go wrong on the recovery path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The kit declares a cryptographic profile this build does not read.
    #[error("the recovery kit declares profile {version}; this build reads profile 1")]
    UnsupportedProfile {
        /// The profile the kit declared.
        version: u64,
    },
    /// The document is not a recovery kit in this format.
    #[error("that is not a recovery kit: {what}")]
    MalformedKit {
        /// What was wrong with it.
        what: &'static str,
    },
    /// The seed and its checksum disagree, which is what a mistyped kit looks like.
    #[error("the recovery kit's checksum does not match its seed, so it was copied wrongly")]
    MistypedKit,
    /// A kit member cannot be written into a line-oriented document.
    #[error("that kit cannot be printed: {what}")]
    UnprintableKit {
        /// Which member.
        what: &'static str,
    },
    /// The rendered kit is larger than a scannable QR code holds.
    #[error("the recovery kit renders to {len} bytes, over the {limit}-byte limit")]
    KitTooLarge {
        /// The rendered size.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// A restore tried to open the bundle before it had service access.
    #[error("service access has not been obtained through the configured retrieval policy")]
    NoServiceAccess,
    /// The kit does not name the origin a restore is trying.
    #[error("the recovery kit does not name that service origin")]
    UnknownServiceOrigin,
    /// The bundle did not authenticate under the key the kit and this retrieval context derive.
    ///
    /// Substituting the origin or the locator arrives here. It is an authentication failure and
    /// nothing else: no writer key is taken from the archive to make up for it.
    #[error("the recovery bundle did not authenticate at that origin and locator")]
    BundleNotAuthentic,
    /// A checkpoint would have moved backwards, which is a late answer rather than a newer fact.
    #[error(
        "this archive's verified generation is {recorded}; recording {offered} would move it \
         backwards"
    )]
    CheckpointWentBackwards {
        /// The generation the bundle already records.
        recorded: u64,
        /// The generation that was offered.
        offered: u64,
    },
    /// The kit names another bundle than the one this store holds.
    ///
    /// It is the caller's kit that is wrong, not the bytes a service served, which is why it is
    /// not [`Self::BundleNotAuthentic`]: nothing has been fetched and nothing has failed to
    /// authenticate.
    #[error("that recovery kit names another bundle than the one this store holds")]
    KitLocatorMismatch,
    /// The kit and the seed offered with it are not the same recovery authority.
    #[error("that recovery kit belongs to another recovery seed")]
    KitIsForAnotherSeed,
    /// Migrating this kit would drop a service origin it names.
    ///
    /// A kit's origins share one bundle locator, so a kit that names several cannot be migrated one
    /// service at a time: the updated kit would point every origin at the one bundle that moved.
    /// Per-origin locators are what this needs, and this build does not have them.
    #[error(
        "this kit names {origins} service origins and they share one locator, so migrating it \
         would lose all but one"
    )]
    MigrationWouldLoseAnOrigin {
        /// How many origins the kit names.
        origins: usize,
    },
    /// The store a migration was given for the destination already holds a bundle.
    ///
    /// A migration writes where there is none. Comparing against a bundle already there would put
    /// the moved one over the top of it, and a bundle is the only thing a restore takes a writer
    /// key from, so the one replaced would take its archives with it.
    ///
    /// Completing a migration meets the same refusal when the bundle at the destination is not
    /// the one that migration's write left there, whatever place in the order it holds.
    #[error(
        "that destination already holds a recovery bundle, and a migration does not write over one"
    )]
    DestinationHoldsABundle,
    /// The migration being completed left nothing at the destination.
    ///
    /// The destination store sent no write for it, or the service refused that write or
    /// establishes that it never ran, and nothing could be read there. Nothing will land under
    /// that write's identity later, because the service has fenced it, so there is no move to
    /// complete and making it again is safe.
    #[error(
        "that migration's write never landed at the destination, so there is nothing to complete"
    )]
    MigrationDidNotLand,
    /// The bundle at the locator was written by somebody else since this device last read it.
    #[error("the recovery bundle has moved on since this device last read it; read it again")]
    BundleConflict {
        /// Where this device was writing against, or nothing where it believed the locator held
        /// no bundle at all.
        expected: Option<SyncPosition>,
        /// The copy the service kept of the refused write, when it kept one.
        ///
        /// A refusal says the comparison did not hold. It does not say the service kept nothing:
        /// what it keeps is ciphertext this device sent, and naming it is the difference between
        /// showing a retained artefact and pretending it away.
        retained: Option<SyncConflictId>,
    },
    /// A bundle write was sent and no answer came back, so whether it applied is not established.
    ///
    /// Nothing is resent on its own: an exchange that was not answered may still have been
    /// executed, and a second write made in the dark would compare against a place the first one
    /// may have left. Read the bundle instead, which establishes what is at the locator and
    /// whether it is what this device sent.
    #[error("the recovery bundle write was not answered, so read the bundle again: {source}")]
    BundleOutcomeUnknown {
        /// The digest of the encrypted bundle this device sent.
        sent: Digest256,
        /// Why no answer came back.
        #[source]
        source: Box<crate::error::ClientError>,
    },
    /// A write whose answer never came back is still outstanding.
    ///
    /// It has to be over before another goes out: a request still on its way can land after a read
    /// that did not see it, and the write made on the strength of that read would then be refused
    /// by this device's own earlier write.
    #[error("a recovery bundle write is unsettled; end it before writing the bundle again")]
    BundleWriteUnsettled {
        /// The digest of the encrypted bundle this device sent.
        sent: Digest256,
    },
    /// The service answered an applied write with the place the bundle was already at.
    ///
    /// Every applied write takes the next place in its collection's order, so a position that
    /// stands still is a service saying it wrote and did not write.
    #[error("the recovery bundle was answered with {found} for a write that had to move it on")]
    BundleDidNotMoveOn {
        /// The position the service answered with.
        found: SyncPosition,
    },
    /// The service answered with a position no write of the bundle could be at.
    ///
    /// A place in the order counts from one, and a write that produced content is named by a
    /// revision; a position with neither is a removal, which no write of the bundle produced.
    /// Nothing here invents the missing part.
    #[error(
        "the recovery bundle was answered with {found}, which is not where a write of it can be"
    )]
    BundleNotAWrite {
        /// The position the service answered with.
        found: SyncPosition,
    },
    /// The service answered behind where this device had already seen the bundle.
    #[error(
        "the recovery bundle reached write {expected} at that locator, which now answers \
         {found}: the service has gone back"
    )]
    BundleWentBack {
        /// The write sequence this device had already seen.
        expected: u64,
        /// The write sequence the service answered with.
        found: u64,
    },
    /// The service holds a different write of the bundle under the same place in its order.
    ///
    /// One write sequence names one write for the life of a collection, so two answers under one
    /// place come from two histories, and the locator is not the collection this store has been
    /// reading. That holds for another name under the place and for other content under the same
    /// name: a place in the order names one content, and a second reading of it that differs is
    /// this refusal rather than a newer copy.
    #[error(
        "the recovery bundle reached {expected} at that locator, which now holds another write \
         under that same place ({found})"
    )]
    BundleHistoryForked {
        /// The position this device last saw.
        expected: SyncPosition,
        /// The position the service answered with, under the same write sequence.
        found: SyncPosition,
    },
    /// The service answered from another history of the bundle's collection than the one this
    /// store read the bundle in: the collection was put back from an archive.
    ///
    /// Places compare only within one history, and a bundle put back can lack a writer this device
    /// trusted or a generation it verified since, whatever place in the order it answers at. So
    /// nothing is compared or adopted across the two, ahead, behind or at the same place, and the
    /// owner's recovery is the explicit one: read the bundle from a store that knows nothing, and
    /// judge what comes back.
    #[error(
        "the recovery bundle was read at {expected}, and that locator now answers {found} from a collection put back from an archive"
    )]
    BundlePutBack {
        /// The position this device last saw.
        expected: SyncPosition,
        /// The position the service answered with, in another history.
        found: SyncPosition,
    },
    /// This device's record of a bundle write could not be read or written.
    #[error("the recovery bundle's write record at {path} could not be used: {source}")]
    Storage {
        /// What was being read or written.
        path: std::path::PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// This device's record of a bundle write is not one this build can read back.
    ///
    /// It may be the only account of a write that can still land, so no store is opened over it:
    /// a store that set it aside would write again while that write was still on its way. A record
    /// that would be too large to read back is refused before its write is sent, for the same
    /// reason.
    #[error("the recovery bundle's write record at {path} cannot be read back by this build")]
    UnreadableWriteRecord {
        /// Which record.
        path: std::path::PathBuf,
    },
    /// Another bundle store on this device holds that bundle's write record.
    ///
    /// One store writes one bundle from a device at a time. A second one would keep a record of
    /// its own writes over the first one's, and the first one's lost write would then have no
    /// account left.
    #[error("another recovery bundle store on this device holds the write record at {path}")]
    BundleStoreInUse {
        /// The lock the other store holds.
        path: std::path::PathBuf,
    },
    /// The table refuses this material, for the reason it gives.
    ///
    /// Asked before a byte of the material is read, so what is refused is named rather than
    /// silently left out.
    #[error("{} is never carried here: {because}", .material.as_str())]
    Refused {
        /// What was offered.
        material: Material,
        /// The table's reason.
        because: &'static str,
    },
    /// What was offered as this device's settings is not its settings object.
    #[error("that is not this device's settings: {what}")]
    NotSettings {
        /// What it is instead.
        what: &'static str,
    },
    /// This device's sync store refused.
    #[error("{0}")]
    Sync(#[from] crate::sync::SyncError),
    /// The service failed.
    #[error("{0}")]
    Service(#[from] crate::error::ClientError),
    /// A cryptographic operation failed.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("{0}")]
    Cbor(#[from] kr_cbor::CborError),
}

/// The result of a recovery operation.
pub type Result<T> = core::result::Result<T, RecoveryError>;

/// Where a recovery seed can come from.
///
/// The complete list. The service never held the seed, so no account operation is on it: an
/// account password reset gives back an account, and a restore still needs the kit or a device
/// that still has its secure store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeedSource {
    /// The printed or scanned recovery kit.
    Kit,
    /// The owner's secure store, on a device that still has it.
    SecureStore,
}

impl SeedSource {
    /// Every way a seed is obtained.
    pub const ALL: [Self; 2] = [Self::Kit, Self::SecureStore];

    /// Returns the stable name a report uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kit => "the recovery kit",
            Self::SecureStore => "this device's secure store",
        }
    }
}
