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
//!
//! # What the seed is, and is not
//!
//! It is the whole of the owner's recovery authority, and the service never holds it. An account
//! password reset therefore returns an account and nothing else: [`SeedSource`] is the complete
//! list of places a seed comes from, and a service is not one of them.

mod bundle;
mod kit;
mod restore;

pub use crate::recovery::bundle::{
    BundleStore, Migrated, MigrationRecord, OfflineExport, WriterEnabled, bundle_collection,
};
pub use crate::recovery::kit::{
    MAX_RECOVERY_KIT_BYTES, RECOVERY_KIT_FORMAT, parse as parse_kit, qr_payload,
    render as render_kit,
};
pub use crate::recovery::restore::{FreshRestore, RetrievalPolicy, ServiceAccess, TrustedMaterial};
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
    /// The bundle at the locator was written by somebody else since this device last read it.
    #[error("the recovery bundle at generation {expected} has moved on; read it again")]
    BundleConflict {
        /// The generation this device was writing against.
        expected: u64,
    },
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
