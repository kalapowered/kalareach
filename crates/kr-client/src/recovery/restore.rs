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

/// The access the configured retrieval policy gave a restore: the reader it reaches one origin
/// through.
///
/// Under [`RetrievalPolicy::Account`] the reader presents a token from an authorisation the device
/// made for the restore alone, asking for `backup.restore`; under [`RetrievalPolicy::SelfHosted`]
/// it presents the credential the owner's own deployment issued. Either way the service decides
/// what the reader reaches, and a reader it does not admit reaches nothing: a restore reads only
/// through this, so holding one proves nothing by itself.
///
/// It carries no key, and that half *is* structural. Holding one means a restore can *fetch*
/// ciphertext; opening that ciphertext needs the seed the kit carries, and section 20 says so in
/// as many words: service login alone does not decrypt the bundle.
#[derive(Clone)]
pub struct ServiceAccess {
    policy: RetrievalPolicy,
    service_origin: String,
    reader: Arc<dyn SyncBackupService>,
}

impl ServiceAccess {
    /// The access `policy` gave a restore to `service_origin`, through `reader`.
    #[must_use]
    pub fn new(
        policy: RetrievalPolicy,
        service_origin: impl Into<String>,
        reader: Arc<dyn SyncBackupService>,
    ) -> Self {
        Self {
            policy,
            service_origin: service_origin.into(),
            reader,
        }
    }

    /// Which policy gave it.
    #[must_use]
    pub const fn policy(&self) -> RetrievalPolicy {
        self.policy
    }

    /// The origin it is access to.
    #[must_use]
    pub fn service_origin(&self) -> &str {
        &self.service_origin
    }
}

impl std::fmt::Debug for ServiceAccess {
    /// The policy and the origin as a diagnostic names one: an address may carry a user name and
    /// a password in front of its host. Not the reader, which is how the access reaches the
    /// service rather than what it is.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAccess")
            .field("policy", &self.policy)
            .field(
                "service_origin",
                &crate::shown::Shown::address(&self.service_origin),
            )
            .finish_non_exhaustive()
    }
}

/// What the authenticated bundle gives a restore.
///
/// Every writer key a restore will ever trust is in here, and it came out of a bundle that
/// authenticated under a key only the seed derives. Nothing in a restore reads a writer key from
/// an archive descriptor, so there is no path by which one could be added.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for TrustedMaterial {
    /// Where it was read, as a diagnostic names an origin, how much it holds and its revision. The
    /// locator is not shown: it is what reaches the bundle.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedMaterial")
            .field(
                "service_origin",
                &crate::shown::Shown::address(&self.context.service_origin),
            )
            .field("trusted_writers", &self.trusted_writers.len())
            .field("trusted_producers", &self.trusted_producers.len())
            .field("collections", &self.collections.len())
            .field("checkpoints", &self.checkpoints.len())
            .field("bundle_revision", &self.bundle_revision)
            .finish_non_exhaustive()
    }
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
pub struct FreshRestore {
    kit: RecoveryKit,
    policy: RetrievalPolicy,
    access: Option<ServiceAccess>,
}

impl std::fmt::Debug for FreshRestore {
    /// The policy, how many origins the kit names and whether access was obtained; never the kit's
    /// origins, its locator or its seed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreshRestore")
            .field("kit_origins", &self.kit.service_origins.len())
            .field("policy", &self.policy)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
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

    /// Authenticates and decrypts the bundle with the kit, read through the access the retrieval
    /// policy gave this restore.
    ///
    /// `service_origin` selects which of the kit's origins to read from; a kit may name several,
    /// and a restore tries each in turn. The bundle's key is derived from the seed *and* that
    /// origin and the kit's locator, so a bundle served from somewhere else fails to authenticate
    /// here. It does not fall back to anything, and in particular it does not fall back to a
    /// writer key an archive supplied.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::NoServiceAccess`] when the retrieval policy has not given access to
    /// that origin, [`RecoveryError::UnknownServiceOrigin`] for an origin the kit does not name,
    /// [`RecoveryError::MistypedKit`] when the kit's checksum does not match its seed,
    /// [`RecoveryError::Service`] when the service does not admit the reader or holds no bundle
    /// there, and [`RecoveryError::BundleNotAuthentic`] when the bundle does not open here.
    pub async fn open_bundle(&self, service_origin: &str) -> Result<TrustedMaterial> {
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
        let bundle = read_bundle(access.reader.as_ref(), &context, None, &seed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    /// The material a restore trusts renders where it was read, as a diagnostic names an origin,
    /// and how much it holds, exactly: never the locator.
    #[test]
    fn trusted_material_renders_only_where_it_was_read_and_how_much_it_holds() {
        let material = TrustedMaterial {
            context: RecoveryContext {
                service_origin: "https://reach.example".to_owned(),
                bundle_locator: NEVER_RENDERED.to_owned(),
            },
            trusted_writers: Vec::new(),
            trusted_producers: Vec::new(),
            collections: Vec::new(),
            checkpoints: Vec::new(),
            bundle_revision: 8,
        };
        renders_only(
            &material,
            "TrustedMaterial{service_origin:\"https://reach.example\",trusted_writers:0,\
             trusted_producers:0,collections:0,checkpoints:0,bundle_revision:8,..}",
        );
    }
}
