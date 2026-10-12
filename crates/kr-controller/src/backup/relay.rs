//! The relay of a restore's reads of the managed storage service.
//!
//! A restore runs in the `kr` process, which holds the recovery kit, opens the archive and writes the
//! files. This host holds the account the service is read with, so the daemon makes the requests.
//! It relays ciphertext and public records and nothing else: it holds no seed, opens no archive and
//! knows no file name or destination. What it sees is what the service holds already, the archive
//! and object identifiers a read names, the bundle's locator and the checkpoint a generation read
//! is held to, and none of them is written to a log or put in an error.
//!
//! * **The bundle read signs as an installation.** The service's settings-sync route accepts an
//!   installation's signature only, and this host's writer key signs as a host. The daemon makes a
//!   key for it in memory when the relay is built and never stores it, so the writer key and the
//!   host's authorisation key are not used for anything else. The read carries the host's
//!   `backup.write` token beside the signature, and the service derives its principal from the key
//!   that signed, so nothing has to be registered.
//! * **One record of quiet.** A delay the service names binds every question to it, this relay's
//!   and the carrier's alike. While one is owed the relay sends nothing and answers what is left of
//!   it, and a delay a read meets is recorded for everything that asks next. The record bounds a
//!   delay at an hour.
//! * **The service's words stay out.** A refusal reaches the person as the service's code with a
//!   sentence of this program's own, never as the service's text, which can repeat what was asked.

use std::sync::Arc;
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::recovery::bundle_collection;
use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::{
    BackupManifestService, ManagedSyncService, ServiceSigner, StorageService, SyncBackupService,
    SyncFetched,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::RecoveryContext;
use kr_protocol::backup_read::{
    BACKUP_READ_MAX_BUNDLE_BYTES, BACKUP_READ_MAX_RANGE_BYTES, BackupBundle, BackupReadParams,
    BackupReadResult, BackupSignIn,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::pairing::GenerationCheckpoint;
use kr_protocol::scalars::{AuthorisationKey, Bytes, Nullable, Signature64, U64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_transport::config::ProxyUrl;

use crate::account::HostAccount;
use crate::backup::runtime::{TokenState, describe_token, managed_clients, managed_transport};
use crate::backup::uploader::Hold;
use crate::error::{ControllerError, Result};
use crate::quiet::Quiet;

/// A key that exists for this process only, signing the requests the service reads as a device's.
struct InstallationSigner {
    key: AuthorisationKeyPair,
}

impl std::fmt::Debug for InstallationSigner {
    /// The public key, which is all the service learns of it. Never the private half.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallationSigner")
            .field("public_key", self.key.public())
            .finish_non_exhaustive()
    }
}

impl ServiceSigner for InstallationSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let refused =
            |what: String| ClientError::Host(ProtocolError::new(ErrorCode::InvalidArgument, what));
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .map_err(|error| refused(format!("the request could not be signed: {error}")))?;
        sign(&self.key, &transcript)
            .map_err(|error| refused(format!("the request could not be signed: {error}")))
    }
}

/// Reads what the storage service holds for a restore, with this host's account.
pub struct BackupRelay {
    origin: GatewayOrigin,
    storage: Arc<dyn StorageService>,
    manifest: Arc<dyn BackupManifestService>,
    bundles: ManagedSyncService,
    tokens: Arc<dyn AccountTokenSource>,
    account: Arc<HostAccount>,
    quiet: Arc<Quiet>,
}

impl std::fmt::Debug for BackupRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupRelay")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl BackupRelay {
    /// Builds the relay over the storage service at `origin`, signing storage and manifest requests
    /// as `writer` does and bundle reads with a key of its own.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when a transport to the service cannot be built,
    /// and the error of the key generator when no key can be made.
    pub fn new(
        origin: &GatewayOrigin,
        proxy: Option<&ProxyUrl>,
        writer: &AuthorisationKeyPair,
        account: Arc<HostAccount>,
        quiet: Arc<Quiet>,
    ) -> Result<Self> {
        let tokens = account.tokens_for(origin.as_str());
        let clients = managed_clients(origin, proxy, writer, &tokens)?;
        let (Some(storage), Some(manifest)) = (clients.storage, clients.backup_manifest) else {
            return Err(ControllerError::NotConfigured(
                "a restore's reads need a storage client and a backup manifest client".to_owned(),
            ));
        };
        let installation = Arc::new(InstallationSigner {
            key: AuthorisationKeyPair::generate().map_err(ControllerError::registry)?,
        });
        let bundles = ManagedSyncService::new(
            origin.clone(),
            managed_transport(origin, proxy)?,
            installation,
        )
        .presenting(Arc::clone(&tokens), BACKUP_WRITE_SCOPE)
        .leaving_delays_to_the_caller();
        Ok(Self {
            origin: origin.clone(),
            storage,
            manifest,
            bundles,
            tokens,
            account,
            quiet,
        })
    }

    /// Answers one read.
    ///
    /// A read that reaches the service is refused first when the service has asked to be left
    /// alone: nothing is sent, and what is left of the delay is the answer. A delay the service
    /// names to a read is recorded and answered the same way.
    ///
    /// # Errors
    ///
    /// Returns a [`ControllerError`] whose code is the service's and whose words are this
    /// program's, and [`ControllerError::InvalidArgument`] for a range that is not one.
    pub async fn read(&self, params: BackupReadParams) -> Result<BackupReadResult> {
        if let BackupReadParams::Object { length, .. } = &params
            && (length.get() == 0 || length.get() > BACKUP_READ_MAX_RANGE_BYTES)
        {
            return Err(ControllerError::InvalidArgument(format!(
                "a read of an object asks for between one byte and {BACKUP_READ_MAX_RANGE_BYTES}"
            )));
        }
        let read = match params {
            BackupReadParams::Service {} => return Ok(self.service().await),
            other => {
                if let Some(left) = self.quiet.left() {
                    return Ok(wait(left));
                }
                self.reach(other).await
            }
        };
        match read {
            Ok(result) => Ok(result),
            Err(error) => {
                let hold = Hold::of(&error);
                if let Some(delay) = hold.retry_after {
                    self.quiet.owe(delay);
                    return Ok(wait(self.quiet.left().unwrap_or(delay)));
                }
                Err(ControllerError::Refused {
                    code: hold.code,
                    detail: local_words(hold.code).to_owned(),
                })
            }
        }
    }

    /// Sends one read that reaches the service.
    async fn reach(&self, params: BackupReadParams) -> kr_client::Result<BackupReadResult> {
        match params {
            BackupReadParams::Service {} => Ok(self.service().await),
            BackupReadParams::Bundle { locator } => self.bundle(&locator.to_string()).await,
            BackupReadParams::Generation {
                archive_id,
                checkpoint,
            } => self.generation(archive_id, checkpoint.0).await,
            BackupReadParams::Object {
                archive_id,
                object_id,
                offset,
                length,
            } => {
                self.object(archive_id, object_id, offset.get(), length.get())
                    .await
            }
        }
    }

    /// Which service this host is configured for, and whether a read may be sent.
    async fn service(&self) -> BackupReadResult {
        let sign_in = if self.tokens.token(BACKUP_WRITE_SCOPE).await.is_ok() {
            BackupSignIn::Usable
        } else {
            match describe_token(&self.account) {
                TokenState::Usable => BackupSignIn::Usable,
                TokenState::Absent => BackupSignIn::SignedOut,
                TokenState::SigningIn => BackupSignIn::Waiting,
                TokenState::Ended => BackupSignIn::Ended,
                TokenState::WithoutScope => BackupSignIn::WithoutScope,
                TokenState::NotRenewed => BackupSignIn::NotRenewed,
            }
        };
        BackupReadResult::Service {
            origin: self.origin.as_str().to_owned(),
            sign_in,
        }
    }

    async fn bundle(&self, locator: &str) -> kr_client::Result<BackupReadResult> {
        let collection = bundle_collection(&RecoveryContext {
            service_origin: self.origin.as_str().to_owned(),
            bundle_locator: locator.to_owned(),
        });
        let bundle = match self.bundles.fetch(&collection).await {
            Ok(SyncFetched::Held {
                position,
                ciphertext,
            }) => {
                if ciphertext.len() > BACKUP_READ_MAX_BUNDLE_BYTES {
                    return Err(ClientError::refusal(
                        ErrorCode::ResourceUnavailable,
                        kr_client::shown::Shown::said(
                            "the recovery bundle is larger than one reply carries",
                        ),
                    ));
                }
                BackupBundle::Held {
                    write_sequence: U64::new(position.write_sequence),
                    revision: Nullable(position.revision.0.map(|revision| revision.get())),
                    recovery: Nullable(position.recovery().map(|recovery| recovery.get())),
                    ciphertext: Bytes::new(ciphertext),
                }
            }
            Ok(SyncFetched::Absent { recovery }) => BackupBundle::Absent {
                recovery: Nullable(recovery.map(|recovery| recovery.get())),
            },
            // The service answers a collection that does not exist, one an account does not own
            // and a request without a usable token alike, as no collection: for a restore that is
            // a bundle it cannot find.
            Err(error) if error.code() == ErrorCode::UnknownSession => BackupBundle::Absent {
                recovery: Nullable::null(),
            },
            Err(error) => return Err(error),
        };
        Ok(BackupReadResult::Bundle { bundle })
    }

    async fn generation(
        &self,
        archive_id: kr_protocol::ids::ArchiveId,
        checkpoint: Option<kr_protocol::archive::ArchiveCheckpoint>,
    ) -> kr_client::Result<BackupReadResult> {
        let held = checkpoint.map(|checkpoint| GenerationCheckpoint {
            archive_id: checkpoint.archive_id,
            backup_generation: checkpoint.backup_generation,
            encrypted_manifest_hash: checkpoint.encrypted_manifest_hash,
            observed_at_ms: checkpoint.verified_at_ms,
        });
        let fetched = self.manifest.fetch(archive_id, None, held.as_ref()).await?;
        Ok(BackupReadResult::Generation {
            publication: Nullable(fetched.map(|fetched| fetched.publication)),
        })
    }

    async fn object(
        &self,
        archive_id: kr_protocol::ids::ArchiveId,
        object_id: kr_protocol::ids::BackupObjectId,
        offset: u64,
        length: u64,
    ) -> kr_client::Result<BackupReadResult> {
        let range = self
            .storage
            .read_object(archive_id, object_id, offset, length)
            .await?;
        Ok(BackupReadResult::Object {
            bytes: Bytes::new(range.bytes),
        })
    }
}

/// The answer for a service that asked to be left alone for `left` more.
fn wait(left: Duration) -> BackupReadResult {
    let whole = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    BackupReadResult::Wait {
        retry_after_seconds: U64::new(whole.max(1)),
    }
}

/// What this program says of a service's refusal, whatever the service said.
const fn local_words(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PermissionDenied => "the storage service did not accept this host's sign-in",
        ErrorCode::HostNotConfigured => {
            "this host holds no account token that a read of backup storage may carry"
        }
        ErrorCode::QuotaExceeded => "the account's storage allowance is spent",
        ErrorCode::OutcomeUnknown => "the storage service did not finish answering that read",
        ErrorCode::RateLimited | ErrorCode::ServiceCapacity => {
            "the storage service has no capacity for that read now"
        }
        ErrorCode::UnknownSession => "the storage service holds nothing there",
        ErrorCode::UpstreamUnavailable | ErrorCode::StorageUnavailable => {
            "the storage service could not be reached"
        }
        _ => "the storage service refused that read",
    }
}
