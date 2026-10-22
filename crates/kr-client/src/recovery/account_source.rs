//! A restore source that reads the storage service with an account signed in on this device.
//!
//! The host's daemon relays a restore's reads for the `kr` command. A device that holds the account
//! itself, as the companion does, reads the service directly, and this is that reader: the bundle
//! through the settings-sync route, the newest publication through the backup manifest, and objects
//! through storage. It holds no seed and opens nothing: it carries ciphertext and public records,
//! and the restore that reads through it checks all of them against the kit.

use std::fmt;
use std::sync::Arc;

use kr_protocol::archive::{ArchiveCheckpoint, BackupGenerationPublication, RecoveryContext};
use kr_protocol::ids::{ArchiveId, BackupObjectId};
use kr_protocol::service::GatewayOrigin;

use crate::recovery::{RestoreSource, SourceService, SourceSignIn, bundle_collection};
use crate::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use crate::services::{
    BackupManifestService, ManagedBackupManifestService, ManagedStorageService, ManagedSyncService,
    ServiceFuture, ServiceHttp, ServiceSigner, StorageService, SyncBackupService, SyncFetched,
};
use kr_protocol::pairing::GenerationCheckpoint;

/// The storage service at one origin, read with this device's signature and the account's token.
pub struct AccountSource {
    origin: GatewayOrigin,
    bundles: ManagedSyncService,
    manifest: ManagedBackupManifestService,
    storage: ManagedStorageService,
}

impl fmt::Debug for AccountSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountSource")
            .finish_non_exhaustive()
    }
}

impl AccountSource {
    /// A source for the service at `origin`, over `http`, signing as `signer` and presenting the
    /// token `tokens` holds for `backup.write`.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
        tokens: Arc<dyn AccountTokenSource>,
    ) -> Self {
        Self {
            bundles: ManagedSyncService::new(
                origin.clone(),
                Arc::clone(&http),
                Arc::clone(&signer),
            )
            .presenting(Arc::clone(&tokens), BACKUP_WRITE_SCOPE),
            manifest: ManagedBackupManifestService::new(
                origin.clone(),
                Arc::clone(&http),
                Arc::clone(&signer),
            )
            .presenting(Arc::clone(&tokens)),
            storage: ManagedStorageService::new(origin.clone(), http, signer).presenting(tokens),
            origin,
        }
    }
}

impl RestoreSource for AccountSource {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async move {
            Ok(SourceService {
                origin: self.origin.as_str().to_owned(),
                sign_in: SourceSignIn::Usable,
            })
        })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            let collection = bundle_collection(&RecoveryContext {
                service_origin: self.origin.as_str().to_owned(),
                bundle_locator: locator.to_owned(),
            });
            match self.bundles.fetch(&collection).await {
                // The service answers a collection that does not exist, one an account does not own
                // and a request without a usable token alike, as no collection.
                Err(error) if error.code() == kr_protocol::error::ErrorCode::UnknownSession => {
                    Ok(SyncFetched::Absent { recovery: None })
                }
                other => other,
            }
        })
    }

    fn generation<'a>(
        &'a self,
        archive_id: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<BackupGenerationPublication>> {
        Box::pin(async move {
            let held = checkpoint.map(|checkpoint| GenerationCheckpoint {
                archive_id: checkpoint.archive_id,
                backup_generation: checkpoint.backup_generation,
                encrypted_manifest_hash: checkpoint.encrypted_manifest_hash,
                observed_at_ms: checkpoint.verified_at_ms,
            });
            Ok(self
                .manifest
                .fetch(archive_id, None, held.as_ref())
                .await?
                .map(|fetched| fetched.publication))
        })
    }

    fn object(
        &self,
        archive_id: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        Box::pin(async move {
            Ok(self
                .storage
                .read_object(archive_id, object, offset, length)
                .await?
                .bytes)
        })
    }
}
