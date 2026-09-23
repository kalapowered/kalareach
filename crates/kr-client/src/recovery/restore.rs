//! A fresh restore: getting to the service, authenticating the bundle, and what comes back.
//!
//! The order is the guarantee. A restore reaches the ciphertext through the retrieval policy the
//! owner configured, and it opens that ciphertext with the kit. Those are two different things, and
//! a restore that had done only the first has nothing: the service never held the seed.

use std::sync::Arc;

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{
    ArchiveCheckpoint, CollectionLocator, RecoveryContext, RecoveryKit, TrustedProducer,
    TrustedWriter,
};

use crate::recovery::bundle::read_bundle;
use crate::recovery::{RecoveryError, Result};
use crate::services::SyncBackupService;

/// How a fresh restore is meant to reach the service that holds the ciphertext.
///
/// It is the owner's configuration rather than the restore's choice, which is why it is carried
/// rather than inferred: a self-hosted deployment has no account to sign in to, and a managed one
/// has no way in without one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetrievalPolicy {
    /// A managed account. The restore signs in, and signing in gets it the ciphertext.
    Account,
    /// A service the owner runs. The restore is given its access directly.
    SelfHosted,
}

impl RetrievalPolicy {
    /// Returns the stable name a report uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "the configured account",
            Self::SelfHosted => "the self-hosted service",
        }
    }
}

/// The caller's own statement that it reached the service through the configured retrieval policy.
///
/// It is an assertion rather than a proof: nothing here authenticates anybody to a service, and a
/// caller that constructed one without signing in would be lying to itself. What it does is order
/// the two steps, so a restore cannot skip the policy its owner configured.
///
/// It carries no key, and that half *is* structural. Holding one means a restore can *fetch*
/// ciphertext; opening that ciphertext needs the seed the kit carries, and section 20 says so in
/// as many words: service login alone does not decrypt the bundle.
#[derive(Clone, Debug)]
pub struct ServiceAccess {
    /// Which policy granted it.
    pub policy: RetrievalPolicy,
    /// The origin it is access to.
    pub service_origin: String,
}

/// What the authenticated bundle gives a restore.
///
/// Every writer key a restore will ever trust is in here, and it came out of a bundle that
/// authenticated under a key only the seed derives. Nothing in a restore reads a writer key from
/// an archive descriptor, so there is no path by which one could be added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedMaterial {
    /// Where the bundle was read from.
    pub context: RecoveryContext,
    /// The writers whose manifests this restore may verify.
    pub trusted_writers: Vec<TrustedWriter>,
    /// The producers whose key wraps this restore may open.
    ///
    /// A restore needs the producer's public stored-envelope key to open a wrap, and this is where
    /// it comes from. Taking it from the archive would be taking key material from something
    /// untrusted.
    pub trusted_producers: Vec<TrustedProducer>,
    /// Where the owner's collections live.
    pub collections: Vec<CollectionLocator>,
    /// The latest generation the owner verified for each archive.
    pub checkpoints: Vec<ArchiveCheckpoint>,
    /// The bundle revision this came from.
    pub bundle_revision: u64,
}

impl TrustedMaterial {
    /// Returns the producer key one wrap's sender identifier names, when the bundle carries it.
    #[must_use]
    pub fn producer(&self, sender_key_id: kr_protocol::scalars::KeyId) -> Option<&TrustedProducer> {
        self.trusted_producers
            .iter()
            .find(|producer| producer.sender_key_id == sender_key_id)
    }

    /// Returns the checkpoint for one archive, when the bundle carries one.
    #[must_use]
    pub fn checkpoint(
        &self,
        archive_id: kr_protocol::ids::ArchiveId,
    ) -> Option<&ArchiveCheckpoint> {
        self.checkpoints
            .iter()
            .find(|checkpoint| checkpoint.archive_id == archive_id)
    }
}

/// A restore on a device that holds nothing but the kit.
#[derive(Debug)]
pub struct FreshRestore {
    kit: RecoveryKit,
    policy: RetrievalPolicy,
    access: Option<ServiceAccess>,
}

impl FreshRestore {
    /// Starts a restore from a kit and the retrieval policy the owner configured.
    #[must_use]
    pub const fn new(kit: RecoveryKit, policy: RetrievalPolicy) -> Self {
        Self {
            kit,
            policy,
            access: None,
        }
    }

    /// Returns the kit this restore is working from.
    #[must_use]
    pub const fn kit(&self) -> &RecoveryKit {
        &self.kit
    }

    /// Returns the retrieval policy.
    #[must_use]
    pub const fn policy(&self) -> RetrievalPolicy {
        self.policy
    }

    /// Records that the configured retrieval policy granted access to one origin.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::UnknownServiceOrigin`] when the kit does not name that origin, and
    /// [`RecoveryError::NoServiceAccess`] when the access was granted under another policy than
    /// the one configured.
    pub fn obtained_access(&mut self, access: ServiceAccess) -> Result<()> {
        if access.policy != self.policy {
            return Err(RecoveryError::NoServiceAccess);
        }
        self.kit
            .context(&access.service_origin)
            .map_err(|_| RecoveryError::UnknownServiceOrigin)?;
        self.access = Some(access);
        Ok(())
    }

    /// Authenticates and decrypts the bundle with the kit.
    ///
    /// `service_origin` selects which of the kit's origins to read from; a kit may name several,
    /// and a restore tries each in turn. The bundle's key is derived from the seed *and* that
    /// origin and the kit's locator, so a bundle served from somewhere else fails to authenticate
    /// here. It does not fall back to anything, and in particular it does not fall back to a
    /// writer key an archive supplied.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::NoServiceAccess`] when the retrieval policy has not been
    /// satisfied, [`RecoveryError::UnknownServiceOrigin`] for an origin the kit does not name,
    /// [`RecoveryError::MistypedKit`] when the kit's checksum does not match its seed, and
    /// [`RecoveryError::BundleNotAuthentic`] when the bundle does not open here.
    pub async fn open_bundle(
        &self,
        service: Arc<dyn SyncBackupService>,
        service_origin: &str,
    ) -> Result<TrustedMaterial> {
        let access = self.access.as_ref().ok_or(RecoveryError::NoServiceAccess)?;
        if access.service_origin != service_origin {
            return Err(RecoveryError::NoServiceAccess);
        }
        let context = self
            .kit
            .context(service_origin)
            .map_err(|_| RecoveryError::UnknownServiceOrigin)?;
        // The kit's own checksum is checked before anything is derived, so a mistyped kit fails
        // here rather than as an authentication failure that looks like a hostile service.
        let seed = RecoverySeed::from_kit(&self.kit).map_err(|_| RecoveryError::MistypedKit)?;
        // A restore only reads, so it holds no store: a store is what writes the bundle, and it
        // keeps a record on this device's disk that a device restoring from a kit has no use for.
        let bundle = read_bundle(service.as_ref(), &context, None, &seed)
            .await?
            .bundle;
        Ok(TrustedMaterial {
            context,
            trusted_writers: bundle.trusted_writers.iter().cloned().collect(),
            trusted_producers: bundle.trusted_producers.iter().cloned().collect(),
            collections: bundle.collections.clone(),
            checkpoints: bundle.checkpoints.iter().cloned().collect(),
            bundle_revision: bundle.revision.get(),
        })
    }

    /// What this restore puts back, and what it refuses to.
    ///
    /// The answer is [`kr_crypto::backup::admit_for_restore`]'s, so a device and a host give the
    /// same one. Every candidate is answered, including the ones that are refused, because a
    /// restore that silently dropped a device's control key would look the same as one that never
    /// saw it.
    #[must_use]
    pub fn admits(
        candidates: &[kr_crypto::backup::Material],
    ) -> kr_crypto::backup::RestoreAdmissions {
        kr_crypto::backup::admit_for_restore(candidates)
    }
}
