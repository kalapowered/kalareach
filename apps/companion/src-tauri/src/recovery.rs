//! Recovery: the owner's seed and the recovery bundle, kept from this computer.
//!
//! Section 20 has the owner's native client keep the recovery seed in its secure store, and keep an
//! encrypted bundle at a stable locator on the sync service. The bundle holds the writers a restore
//! may trust, and it is committed before a writer is declared recovery-enabled. This module is
//! that client on a companion: it makes the seed, puts the first bundle at the service, writes the
//! kit the person keeps, and covers the host on this computer with it. The rules about the bundle
//! itself, the compare-and-swap and the record of a write whose answer never came back, are
//! `kr_client::recovery::BundleStore`'s; the rules about setting the host up under this
//! computer's recovery are `kr_client::recovery::cover_host_archive`'s.
//!
//! # What lives where
//!
//! * **The seed** is in the device's secure store, under [`SEED_SCOPE`]. It is made here, written
//!   to the store before anything is sent, and read from it for each step; nothing holds it
//!   between steps, and the page never sees it.
//! * **The record** is `recovery/recovery.json` in the application's data directory: the service
//!   the bundle is kept at, its locator, and whether the first write is known to have landed. It is
//!   made, flushed to disk and renamed into place before the first write leaves, because a write
//!   that landed under a locator this device had not kept would be a bundle nobody could find. It
//!   holds nothing secret. Turning recovery on makes the record, then makes or reads the seed, then
//!   puts the first bundle at the service, then marks the record kept.
//! * **The store's own record** of the last write it sent is beside it, kept by `BundleStore`.
//! * **The lock** is `recovery/recovery.lock`. Each step holds it, so a second companion process on
//!   this machine waits for the step in hand instead of drawing a locator of its own.
//!
//! # The service, and the account's token
//!
//! The bundle is reached with the device's signature and the account's token, and the token goes
//! only to the service the account is signed in to. The sync service is a setting of its own
//! ([`crate::sync_service`]); where it names another service than the account's, no request is
//! made, and the refusal names the setting. A sign-in that does not carry the right to write the
//! account's backup storage sends nothing either, and the page is told which of the two to mend.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_client::Shown;
use kr_client::recovery::{
    AccountSource, BundleStore, CandidateState, FilesRestore, HostBackups, HostCover, Left,
    LostWrite, RecoveryError, RestoreError, RestoreSource, cover_host_archive, fresh_locator,
    qr_payload, render_kit,
};
use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceSigner, managed_response_limits,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{SecretStore, load_recovery_seed, store_recovery_seed};
use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use kr_protocol::archive::{RecoveryContext, RecoveryKit};
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{BackupEnableCause, BackupUnusable};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ArchiveId;
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::error::{CommandError, Result};
use crate::sync_service::{SyncService, SyncServiceView, host_of};

/// The scope in the device's secure store that the recovery seed is kept under.
pub const SEED_SCOPE: &str = "owner";

/// The directory under the application's data directory that recovery keeps its records in.
pub const DIRECTORY: &str = "recovery";

/// The record of where this computer's bundle is, in [`DIRECTORY`].
const RECORD: &str = "recovery.json";

/// The file a step holds a lock on for as long as it runs, in [`DIRECTORY`].
const LOCK: &str = "recovery.lock";

/// The most a record may be, in bytes. It is a few lines of text.
const RECORD_LIMIT: u64 = 16 * 1024;

/// Where recovery stands on this computer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    /// No recovery material has been made.
    Off,
    /// Making it did not finish: the bundle is not known to be at the service.
    Unfinished,
    /// The bundle is at the service and the seed is in this computer's secure store.
    On,
    /// A write to the bundle was not answered, and nothing more is written until it is settled.
    Unsettled,
}

/// What stops the next step, and what the person can do about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Blocker {
    /// No account is signed in.
    SignedOut,
    /// The sign-in does not carry the right to write the account's backup storage.
    NeedsSignIn,
    /// The sync service is not the service the account is signed in to.
    WrongService {
        /// The sync service the setting names.
        sync_service: String,
        /// The service the account is signed in to.
        account: String,
    },
}

/// What the page is shown of recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryView {
    /// The sync service this computer is set to use.
    pub sync_service: SyncServiceView,
    /// Where recovery stands.
    pub state: RecoveryState,
    /// The host of the service the bundle is kept at, once material has been made.
    pub kept_at: Option<String>,
    /// What stops the next step now.
    pub blocker: Option<Blocker>,
}

/// What the page is told once a kit has been written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KitSaved {
    /// Where it was written.
    pub path: String,
}

/// One archive the recovery bundle names, as the page lists it for export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArchiveView {
    /// The archive's identifier, which the page gives back to name the one to export.
    pub archive_id: String,
    /// The newest generation the service holds of it, once verified as a restore verifies one.
    pub generation: Option<u64>,
    /// When the writer signed that generation, in UTC milliseconds.
    pub published_at_ms: Option<u64>,
    /// Why the service's newest generation is not offered, when it is not.
    pub withheld: Option<WithheldView>,
}

/// Why no generation of an archive is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldView {
    /// The service holds no generation of it, or none as new as the bundle's checkpoint.
    Nothing,
    /// The service holds a publication that a restore would refuse.
    Refused,
}

/// What the page is told once an export has been written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportSaved {
    /// Where it was written.
    pub path: String,
    /// The archive exported, or nothing for the bundle alone.
    pub archive_id: Option<String>,
    /// The generation exported.
    pub generation: Option<u64>,
    /// How many bytes were written.
    pub bytes: u64,
}

/// What covering the host on this computer with this computer's recovery came to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostCoverView {
    /// The host's backups are set up under this computer's recovery, and its kit opens the archives
    /// the host makes from now on.
    Covered {
        /// The fingerprint of this computer's kit.
        kit_fingerprint: String,
        /// The fingerprint of the kit the host was set up under before, when it was replaced.
        replaced: Option<String>,
        /// Whether the host was set up under this computer's recovery already.
        already: bool,
    },
    /// Nothing was declared, and the host is as it was.
    Left {
        /// Why.
        why: LeftView,
    },
}

/// Why the host was left as it was.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum LeftView {
    /// The host selects no storage service.
    NoService,
    /// The host selects another service than the one the bundle is kept at.
    OtherService {
        /// The host of the service the host selects.
        host: String,
    },
    /// The host holds no account token a request may carry.
    SignIn {
        /// Why.
        sign_in: BackupSignIn,
    },
    /// A setup of the host's backups has not ended.
    SetupUnderWay {
        /// The fingerprints of the kits the setups that have not ended carry.
        kit_fingerprints: Vec<String>,
    },
    /// The host was set up under another kit; this computer's kit does not open its backups.
    OtherKit {
        /// The fingerprint of the kit the host was set up under.
        host_fingerprint: String,
    },
    /// The host was set up under this computer's kit and cannot make backups now.
    Unusable {
        /// Why.
        why: BackupUnusable,
    },
    /// The host declined, after the bundle was written.
    Declined {
        /// Why.
        cause: BackupEnableCause,
    },
}

impl From<HostCover> for HostCoverView {
    fn from(cover: HostCover) -> Self {
        match cover {
            HostCover::Covered(covered) => Self::Covered {
                kit_fingerprint: covered.kit_fingerprint,
                replaced: covered.replaced,
                already: covered.already,
            },
            HostCover::Left(left) => Self::Left {
                why: match left {
                    Left::NoService => LeftView::NoService,
                    Left::OtherService { host } => LeftView::OtherService {
                        host: GatewayOrigin::new(&host).map_or(host, |origin| host_of(&origin)),
                    },
                    Left::SignIn(sign_in) => LeftView::SignIn { sign_in },
                    Left::SetupUnderWay { kit_fingerprints } => {
                        LeftView::SetupUnderWay { kit_fingerprints }
                    }
                    Left::OtherKit { host_fingerprint } => LeftView::OtherKit { host_fingerprint },
                    Left::Unusable { why } => LeftView::Unusable { why },
                    Left::Declined(cause) => LeftView::Declined { cause },
                },
            },
        }
    }
}

/// Where this computer's bundle is, and whether the first write is known to have landed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    /// The format of this record.
    version: u32,
    /// The service the bundle is kept at, as the kit names it.
    service_origin: String,
    /// The stable locator of the bundle.
    bundle_locator: String,
    /// True once the first write is known to have landed.
    kept: bool,
}

impl Record {
    const VERSION: u32 = 1;

    fn context(&self) -> RecoveryContext {
        RecoveryContext {
            service_origin: self.service_origin.clone(),
            bundle_locator: self.bundle_locator.clone(),
        }
    }

    fn origin(&self) -> Result<GatewayOrigin> {
        GatewayOrigin::new(self.service_origin.as_str()).map_err(|error| {
            CommandError::local_failure(format!(
                "the service this computer's recovery bundle is kept at is not one it can reach: \
                 {error}"
            ))
        })
    }
}

/// A device's key, signing a service request as an installation.
pub(crate) struct DeviceSigner(AuthorisationKeyPair);

impl DeviceSigner {
    /// A signer for the service that signs with `key` as an installation.
    pub(crate) const fn new(key: AuthorisationKeyPair) -> Self {
        Self(key)
    }
}

impl std::fmt::Debug for DeviceSigner {
    /// The public key, which is what names this device to a service. Never the private half.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSigner")
            .field("public_key", self.0.public())
            .finish_non_exhaustive()
    }
}

impl ServiceSigner for DeviceSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let unsigned = || {
            kr_client::ClientError::refusal(
                ErrorCode::ResourceUnavailable,
                Shown::said("a request to the sync service could not be signed"),
            )
        };
        let transcript =
            SigningTranscript::from_canonical_bytes(self.signer().domain(), message.to_vec())
                .map_err(|_| unsigned())?;
        sign(&self.0, &transcript).map_err(|_| unsigned())
    }
}

/// The owner's recovery seed and bundle on this computer.
pub struct Recovery {
    directory: PathBuf,
    secrets: Arc<dyn SecretStore>,
    signer: Arc<dyn ServiceSigner>,
    service: Arc<SyncService>,
    /// This process's turn, taken for the length of each step beside the lock on [`LOCK`]. A store
    /// writes one bundle from this device at a time, and it is opened for a step and closed at its
    /// end, so two steps at once would be two writers.
    steps: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Recovery").finish_non_exhaustive()
    }
}

impl Recovery {
    /// Recovery kept under `data`, with the seed in `secrets` and the device's `key` signing for
    /// the service `service` names.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the directory cannot be made.
    pub fn open(
        data: &Path,
        secrets: Arc<dyn SecretStore>,
        key: AuthorisationKeyPair,
        service: Arc<SyncService>,
    ) -> Result<Self> {
        let directory = data.join(DIRECTORY);
        // The directory is on disk before anything is written in it: a record is made before the
        // first write leaves, and a record in a directory a crash took is a bundle nobody finds.
        create_private_directory(&directory)
            .map_err(|error| error.to_string())
            .and_then(|()| flush_path_names(&directory).map_err(|error| error.to_string()))
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "the directory recovery keeps its records in could not be made: {error}"
                ))
            })?;
        Ok(Self {
            directory,
            secrets,
            signer: Arc::new(DeviceSigner(key)),
            service,
            steps: tokio::sync::Mutex::new(()),
        })
    }

    /// Takes this process's turn and then the lock a second companion on this machine would wait
    /// for, and holds both until the step is dropped.
    ///
    /// Two companions that each found no record would each draw a locator and commit a bundle of
    /// their own, and the kit one of them handed over would name a bundle the other had left
    /// behind. So the record is read, made and updated inside one step of one process at a time.
    async fn step(&self) -> Result<Step<'_>> {
        let turn = self.steps.lock().await;
        let path = self.directory.join(LOCK);
        let file =
            tauri::async_runtime::spawn_blocking(move || -> std::io::Result<std::fs::File> {
                let mut options = std::fs::OpenOptions::new();
                options.create(true).truncate(false).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let file = options.open(path)?;
                kr_flush::lock::exclusive(&file)?;
                Ok(file)
            })
            .await
            .map_err(|error| {
                CommandError::local_failure(format!("recovery was not started: {error}"))
            })?
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "this computer's recovery lock could not be taken: {error}"
                ))
            })?;
        Ok(Step {
            _turn: turn,
            _lock: file,
        })
    }

    /* ---------------------------------------------------------------------- */
    /* What the page is shown                                                  */
    /* ---------------------------------------------------------------------- */

    /// What the page is shown: where recovery stands and what stops the next step. Nothing is sent.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's records cannot be read.
    pub async fn view(&self, account: &Account) -> Result<RecoveryView> {
        let _step = self.step().await?;
        self.view_of(account)
    }

    fn view_of(&self, account: &Account) -> Result<RecoveryView> {
        let record = self.record()?;
        let (state, used, kept_at) = match &record {
            None => (RecoveryState::Off, self.service.origin(), None),
            Some(record) => {
                let origin = record.origin()?;
                let state = if matches!(
                    self.store(record, account)?.lost_write(),
                    Some(LostWrite::Unsettled { .. })
                ) {
                    RecoveryState::Unsettled
                } else if record.kept {
                    RecoveryState::On
                } else {
                    RecoveryState::Unfinished
                };
                let host = host_of(&origin);
                (state, origin, Some(host))
            }
        };
        Ok(RecoveryView {
            sync_service: self.service.view(),
            state,
            kept_at,
            blocker: blocker(account, &used),
        })
    }

    /* ---------------------------------------------------------------------- */
    /* Turning it on                                                           */
    /* ---------------------------------------------------------------------- */

    /// Makes the recovery seed, keeps it in the secure store, and puts the first bundle at the
    /// sync service. Run again after a start that did not finish, it goes on from where that
    /// stopped, with the locator it began with.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the account cannot be used at the service the setting names, nothing
    /// having been made or sent; `OUTCOME_UNKNOWN` when the write was not answered, which has to be
    /// settled before anything else is written; and a local failure otherwise.
    pub async fn turn_on(&self, account: &Account) -> Result<RecoveryView> {
        let _step = self.step().await?;
        let mut record = match self.record()? {
            Some(record) if record.kept => return self.view_of(account),
            Some(record) => record,
            None => {
                let selected = self.service.origin();
                refuse_if_blocked(account, &selected)?;
                let record = Record {
                    version: Record::VERSION,
                    service_origin: selected.as_str().to_owned(),
                    bundle_locator: fresh_locator().map_err(said)?,
                    kept: false,
                };
                self.keep(&record)?;
                record
            }
        };
        refuse_if_blocked(account, &record.origin()?)?;
        let seed = self.seed(true)?;
        let now = now();
        {
            let mut store = self.store(&record, account)?;
            match store.commit(&seed, &mut BundleStore::empty(now), now).await {
                Ok(_) => {}
                // Something is at the locator already: this device's own first write, whose
                // landing was never recorded. Reading it with the seed adopts it if the seed
                // opens it, and refuses it if it does not, so another's bundle is never written
                // over.
                Err(RecoveryError::BundleConflict { .. }) => {
                    store.fetch(&seed).await.map_err(said)?;
                }
                Err(error) => return Err(said(error)),
            }
        }
        record.kept = true;
        self.keep(&record)?;
        self.view_of(account)
    }

    /// Ends a write to the bundle whose answer never came back, and says what became of it.
    ///
    /// # Errors
    ///
    /// Returns a refusal when there is nothing to settle or the account cannot be used, and the
    /// service's own failure when it cannot be asked.
    pub async fn settle(&self, account: &Account) -> Result<RecoveryView> {
        let _step = self.step().await?;
        let Some(mut record) = self.record()? else {
            return Err(CommandError::refused("recovery has not been turned on"));
        };
        refuse_if_blocked(account, &record.origin()?)?;
        let seed = self.seed(false)?;
        let settled = {
            let mut store = self.store(&record, account)?;
            if store.lost_write().is_none() {
                return Err(CommandError::refused(
                    "no write to the recovery bundle is waiting to be settled",
                ));
            }
            store.end_lost_write(&seed).await.map_err(said)?
        };
        if matches!(settled, Some(LostWrite::Applied)) && !record.kept {
            record.kept = true;
            self.keep(&record)?;
        }
        self.view_of(account)
    }

    /* ---------------------------------------------------------------------- */
    /* The kit                                                                 */
    /* ---------------------------------------------------------------------- */

    /// Writes the recovery kit to `destination`, flushed to disk, with the owner-only mode (0600)
    /// on Unix; on macOS the file's access list is removed first, and the save fails, leaving the
    /// file's contents as they were, when it cannot be. On Windows a new file has the permissions of the folder
    /// the destination is in, and a file that already existed keeps its own.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on, and a local failure when the file cannot be
    /// written.
    pub async fn save_kit(&self, destination: &Path) -> Result<()> {
        let kit = {
            let _step = self.step().await?;
            let record = self
                .record()?
                .filter(|record| record.kept)
                .ok_or_else(|| CommandError::refused("recovery is not on, so there is no kit"))?;
            let seed = self.seed(false)?;
            render_kit(&seed.to_kit(vec![record.service_origin], record.bundle_locator))
                .map_err(said)?
        };
        let destination = destination.to_path_buf();
        tauri::async_runtime::spawn_blocking(move || write_private(&destination, kit.as_bytes()))
            .await
            .map_err(|error| {
                CommandError::local_failure(format!("the kit was not written: {error}"))
            })?
            .map_err(|error| {
                CommandError::local_failure(format!("the kit could not be written: {error}"))
            })
    }

    /* ---------------------------------------------------------------------- */
    /* The kit as a QR code, and the offline export                            */
    /* ---------------------------------------------------------------------- */

    /// Writes the recovery kit to `destination` as a QR code, an SVG, with the owner-only mode as
    /// the text kit has. The code carries the kit's own text at error correction Q, so that a
    /// scanner reads the document a person could have typed and a printed copy survives a scuff.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on, and a local failure when the kit does not fit a
    /// QR code or the file cannot be written.
    pub async fn save_kit_qr(&self, destination: &Path) -> Result<()> {
        let svg = {
            let _step = self.step().await?;
            let kit = self.kit()?;
            let payload = qr_payload(&kit).map_err(said_of)?;
            let code = qrcodegen::QrCode::encode_binary(&payload, qrcodegen::QrCodeEcc::Quartile)
                .map_err(|_| {
                CommandError::local_failure("the recovery kit is too large to print as a QR code")
            })?;
            qr_svg(&code)
        };
        let destination = destination.to_path_buf();
        tauri::async_runtime::spawn_blocking(move || write_private(&destination, svg.as_bytes()))
            .await
            .map_err(|error| {
                CommandError::local_failure(format!("the QR code was not written: {error}"))
            })?
            .map_err(|error| {
                CommandError::local_failure(format!("the QR code could not be written: {error}"))
            })
    }

    /// The archives the recovery bundle names at the service, each with the newest generation the
    /// service holds, verified as a restore verifies it.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on or the account cannot be used, and the service's
    /// own failure when it cannot be read.
    pub async fn archives(&self, account: &Account) -> Result<Vec<ArchiveView>> {
        let _step = self.step().await?;
        let (record, source) = self.reading(account)?;
        let listed = FilesRestore::archives(self.kit_of(&record)?, source)
            .await
            .map_err(said_by_restore)?;
        Ok(listed
            .into_iter()
            .map(|candidate| match candidate.newest {
                CandidateState::Newest(newest) => ArchiveView {
                    archive_id: candidate.archive_id.to_string(),
                    generation: Some(newest.generation.get()),
                    published_at_ms: Some(newest.published_at_ms.get()),
                    withheld: None,
                },
                CandidateState::Nothing => ArchiveView {
                    archive_id: candidate.archive_id.to_string(),
                    generation: None,
                    published_at_ms: None,
                    withheld: Some(WithheldView::Nothing),
                },
                CandidateState::Refused(_) => ArchiveView {
                    archive_id: candidate.archive_id.to_string(),
                    generation: None,
                    published_at_ms: None,
                    withheld: Some(WithheldView::Refused),
                },
            })
            .collect())
    }

    /// Writes an offline export to `destination`: the recovery bundle as the service holds it and,
    /// when `archive` is named, that archive's newest generation as ciphertext. The bundle is
    /// authenticated and the archive's manifest opened here to find what it names; nothing
    /// decrypted is written or sent. The export is read with the kit alone, by
    /// `kr backup restore --from-export`.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on or the account cannot be used, a failure of the
    /// service when it cannot be read, a refusal by name for an archive the bundle does not list or
    /// one too large to be a file, and a local failure when the file cannot be written.
    pub async fn export_offline(
        &self,
        account: &Account,
        destination: &Path,
        archive: Option<ArchiveId>,
    ) -> Result<ExportSaved> {
        let (bytes, archive_id, generation) = {
            let _step = self.step().await?;
            let (record, source) = self.reading(account)?;
            let kit = self.kit_of(&record)?;
            let (export, generation) = match archive {
                None => (
                    FilesRestore::export_bundle(kit, source)
                        .await
                        .map_err(said_by_restore)?,
                    None,
                ),
                Some(archive) => {
                    let prepared = FilesRestore::prepare(kit, source, Some(archive), None)
                        .await
                        .map_err(said_by_restore)?;
                    let generation = prepared.plan().generation.get();
                    (
                        prepared.export().await.map_err(said_by_restore)?,
                        Some(generation),
                    )
                }
            };
            let bytes = export.to_canonical_bytes().map_err(said_of)?;
            (
                bytes,
                archive.map(|archive| archive.to_string()),
                generation,
            )
        };
        let written = bytes.len() as u64;
        let destination = destination.to_path_buf();
        let path = destination.to_string_lossy().into_owned();
        tauri::async_runtime::spawn_blocking(move || write_private(&destination, &bytes))
            .await
            .map_err(|error| {
                CommandError::local_failure(format!("the export was not written: {error}"))
            })?
            .map_err(|error| {
                CommandError::local_failure(format!("the export could not be written: {error}"))
            })?;
        Ok(ExportSaved {
            path,
            archive_id,
            generation,
            bytes: written,
        })
    }

    /// The kit of this computer's recovery, made from the seed and the record.
    fn kit(&self) -> Result<RecoveryKit> {
        let record = self
            .record()?
            .filter(|record| record.kept)
            .ok_or_else(|| CommandError::refused("recovery is not on, so there is no kit"))?;
        self.kit_of(&record)
    }

    fn kit_of(&self, record: &Record) -> Result<RecoveryKit> {
        Ok(self.seed(false)?.to_kit(
            vec![record.service_origin.clone()],
            record.bundle_locator.clone(),
        ))
    }

    /// The record and a source that reads the service with the account, for a step that reads.
    fn reading(&self, account: &Account) -> Result<(Record, Arc<dyn RestoreSource>)> {
        let record = self
            .record()?
            .filter(|record| record.kept)
            .ok_or_else(|| CommandError::refused("recovery has not been turned on"))?;
        let origin = record.origin()?;
        refuse_if_blocked(account, &origin)?;
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this computer cannot reach the sync service: {error}"
            ))
        })?;
        let tokens: Arc<dyn AccountTokenSource> = account.tokens();
        let source = AccountSource::new(origin, Arc::new(http), Arc::clone(&self.signer), tokens);
        Ok((record, Arc::new(source)))
    }

    /* ---------------------------------------------------------------------- */
    /* Covering the host                                                       */
    /* ---------------------------------------------------------------------- */

    /// Covers the host on this computer with this computer's recovery, where that can be done, and
    /// says so only when it has been.
    ///
    /// The bundle is committed first, naming the host's archive, producer and writer, and the host
    /// is then set up under this computer's recovery with the very bytes that landed, so that the
    /// kit opens the archives the host makes. A host set up under another kit keeps its archive
    /// and its recipient, and is left as it is unless `replace` asks for a new archive under this
    /// computer's recovery. Nothing is sent to the service until the host has been asked, and
    /// nothing is declared until the host has answered.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on, the account cannot be used or an earlier write
    /// is waiting to be settled; `OUTCOME_UNKNOWN` when the host did not say how it ended, which
    /// asking again settles; and the service's own failure otherwise.
    pub async fn cover_host(
        &self,
        account: &Account,
        host: &dyn HostBackups,
        replace: bool,
    ) -> Result<HostCoverView> {
        let _step = self.step().await?;
        let record = self
            .record()?
            .filter(|record| record.kept)
            .ok_or_else(|| CommandError::refused("recovery has not been turned on"))?;
        refuse_if_blocked(account, &record.origin()?)?;
        let seed = self.seed(false)?;
        let mut store = self.store(&record, account)?;
        cover_host_archive(host, &mut store, &seed, replace, now())
            .await
            .map(HostCoverView::from)
            .map_err(said)
    }

    /* ---------------------------------------------------------------------- */
    /* What is kept                                                            */
    /* ---------------------------------------------------------------------- */

    /// The seed in the secure store; made and kept there first when `may_make` and none is held.
    fn seed(&self, may_make: bool) -> Result<RecoverySeed> {
        let unreadable = |error: kr_crypto::CryptoError| {
            CommandError::local_failure(format!(
                "the recovery seed could not be read from this device's secure storage: {error}"
            ))
        };
        if let Some(seed) = load_recovery_seed(&*self.secrets, SEED_SCOPE).map_err(unreadable)? {
            return Ok(seed);
        }
        if !may_make {
            return Err(CommandError::local_failure(
                "the recovery seed is not in this device's secure storage",
            ));
        }
        let seed = RecoverySeed::generate().map_err(unreadable)?;
        store_recovery_seed(&*self.secrets, SEED_SCOPE, &seed).map_err(|error| {
            CommandError::local_failure(format!(
                "the recovery seed could not be kept in this device's secure storage: {error}"
            ))
        })?;
        Ok(seed)
    }

    fn record(&self) -> Result<Option<Record>> {
        let path = self.directory.join(RECORD);
        let Some(bytes) = read_owner_only_file(&path, RECORD_LIMIT).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's recovery record could not be read: {error}"
            ))
        })?
        else {
            return Ok(None);
        };
        let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's recovery record is not one this version reads: {error}"
            ))
        })?;
        if record.version != Record::VERSION {
            return Err(CommandError::local_failure(
                "this computer's recovery record is of a version this version does not read",
            ));
        }
        Ok(Some(record))
    }

    /// Writes the record whole and makes it durable: to a file beside it, flushed, then renamed
    /// into place, and the directory flushed.
    fn keep(&self, record: &Record) -> Result<()> {
        let text = serde_json::to_vec_pretty(record).map_err(|error| {
            CommandError::local_failure(format!(
                "the recovery record could not be written: {error}"
            ))
        })?;
        write_owner_only_file(&self.directory.join(RECORD), &text).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's recovery record could not be kept: {error}"
            ))
        })
    }

    /// The bundle store for `record`, opened for one step. It holds the lock on its record until
    /// it is dropped, and it opens over the record of the last write it sent, so a write whose
    /// answer never came back is still outstanding in the next step, and after a restart.
    fn store(&self, record: &Record, account: &Account) -> Result<BundleStore> {
        let origin = record.origin()?;
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this computer cannot reach the sync service: {error}"
            ))
        })?;
        let tokens: Arc<dyn AccountTokenSource> = account.tokens();
        let service = ManagedSyncService::new(origin, Arc::new(http), Arc::clone(&self.signer))
            .presenting(tokens, BACKUP_WRITE_SCOPE);
        BundleStore::open(Arc::new(service), record.context(), &self.directory).map_err(said)
    }
}

/// One step's hold on recovery: this process's turn, and the lock on the lock file.
struct Step<'a> {
    _turn: tokio::sync::MutexGuard<'a, ()>,
    _lock: std::fs::File,
}

/// What stops the account being used at `used`, in the order the person mends it.
fn blocker(account: &Account, used: &GatewayOrigin) -> Option<Blocker> {
    let standing = account.standing();
    if !standing.signed_in {
        return Some(Blocker::SignedOut);
    }
    if used != account.origin() {
        return Some(Blocker::WrongService {
            sync_service: host_of(used),
            account: host_of(account.origin()),
        });
    }
    if !standing.backup_write {
        return Some(Blocker::NeedsSignIn);
    }
    None
}

/// Refuses, before anything is made or sent, when the account cannot be used at `used`.
///
/// A token goes only to the service its account is signed in to, so a sync service the setting
/// names that is not that one is refused here, with the setting named.
fn refuse_if_blocked(account: &Account, used: &GatewayOrigin) -> Result<()> {
    match blocker(account, used) {
        None => Ok(()),
        Some(Blocker::SignedOut) => Err(CommandError::refused(
            "sign in before turning recovery on: it keeps its bundle with the account",
        )),
        Some(Blocker::NeedsSignIn) => Err(CommandError::refused(
            "this sign-in does not let KalaReach keep recovery data. Sign in again to allow it",
        )),
        Some(Blocker::WrongService {
            sync_service,
            account,
        }) => Err(CommandError::refused(format!(
            "the sync service setting names {sync_service}, which is not the service this device \
             is signed in to ({account}), so the account's sign-in is not sent there. Choose \
             {account} as the sync service to keep recovery data"
        ))),
    }
}

/// What a recovery failure is to the person.
fn said(error: RecoveryError) -> CommandError {
    match error {
        RecoveryError::BundleOutcomeUnknown { .. } => CommandError::new(
            ErrorCode::OutcomeUnknown,
            "the sync service did not answer the write to the recovery bundle, so it is not known \
             whether it landed. Settle it before anything else is written",
        ),
        RecoveryError::HostOutcomeUnknown { .. } => CommandError::new(
            ErrorCode::OutcomeUnknown,
            "the host did not say how setting its backups up under this recovery ended. Ask again: \
             the host's status shows whether it landed",
        ),
        RecoveryError::BundleWriteUnsettled { .. } => CommandError::refused(
            "a write to the recovery bundle was not answered. Settle it before anything else is \
             written",
        ),
        RecoveryError::Service(error) => CommandError::from(error),
        other => CommandError::local_failure(other.to_string()),
    }
}

/// What a recovery failure that is not the service's is to the person.
fn said_of(error: RecoveryError) -> CommandError {
    said(error)
}

/// What a restore's failure is to the person: the service's own when it was the service, and words
/// of this program's otherwise.
fn said_by_restore(error: RestoreError) -> CommandError {
    match error {
        RestoreError::Read(error) => CommandError::from(error),
        RestoreError::Recovery(cause) => said(*cause),
        too_large @ RestoreError::TooLargeToExport { .. } => {
            CommandError::too_large(too_large.to_string())
        }
        other => CommandError::refused(other.to_string()),
    }
}

/// The QR code as an SVG: one path of unit squares, dark on white, with the four-module quiet zone
/// a scanner needs.
fn qr_svg(code: &qrcodegen::QrCode) -> String {
    const BORDER: i32 = 4;
    let size = code.size() + BORDER * 2;
    let mut squares = String::new();
    for y in 0..code.size() {
        for x in 0..code.size() {
            if code.get_module(x, y) {
                if !squares.is_empty() {
                    squares.push(' ');
                }
                squares.push_str(&format!("M{},{}h1v1h-1z", x + BORDER, y + BORDER));
            }
        }
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 {size} {size}\" \
         width=\"{size}\" height=\"{size}\" shape-rendering=\"crispEdges\">\
         <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\
         <path d=\"{squares}\" fill=\"#000000\"/></svg>\n"
    )
}

/// Writes `body` as the whole of the file the person chose for the kit, readable by this user alone
/// where the platform has such a thing.
///
/// It writes the file in place, and does not go through a temporary file beside it as the record
/// and the setting do: the person's save dialog grants this program that one file and not the
/// folder it is in, so a second file made beside it would ask for the folder on a system that
/// guards its personal folders, and a crash between the write and the rename would leave a hidden
/// copy of the seed that nothing removes. A kit that a crash tears is a visible file that the
/// page never said it saved.
///
/// An existing file is not emptied until it has been made private to this user: its mode is set,
/// and on macOS its access list is cleared through the descriptor that goes on to receive the kit.
/// A file whose mode this user cannot change, or whose list cannot be cleared, keeps its contents
/// and the save fails. Two limits remain. A process that opened the file before it was made private
/// (an earlier file that was wider, or a new file made in a folder whose inherited list names
/// another account) keeps what that open gave it, and only a new file in a folder this program may
/// write in would take that back. On Windows a file that already exists keeps its own access list.
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        // A file that already existed keeps the mode it had, so it is set again.
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(target_os = "macos")]
    crate::access_list::clear(&file)?;
    file.set_len(0)?;
    file.write_all(body)?;
    file.sync_all()
}

/// The time on this machine's clock, in UTC milliseconds.
pub(crate) fn now() -> TimestampMs {
    TimestampMs::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            }),
    )
}
