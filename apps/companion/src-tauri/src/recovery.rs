//! Recovery: the owner's seed and the recovery bundle, kept from this computer.
//!
//! Section 20 has the owner's native client keep the recovery seed in its secure store, and keep an
//! encrypted bundle at a stable locator on the sync service. The bundle holds the writers a restore
//! may trust, and it is committed before a writer is declared recovery-enabled. This module is
//! that client on a companion: it makes the seed, puts the first bundle at the service, writes the
//! kit the person keeps, and commits the bundle again when a writer is enabled. The rules about
//! the bundle itself, the compare-and-swap, the record of a write whose answer never came back
//! and the checkpoint that never moves back, are `kr_client::recovery::BundleStore`'s.
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
    BundleStore, LostWrite, RecoveryError, WriterEnabled, fresh_locator, render_kit,
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
use kr_protocol::archive::{RecoveryContext, TrustedWriter};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::error::{CommandError, Result};
use crate::sync_service::{SyncService, SyncServiceView, host_of};

/// The scope in the device's secure store that the recovery seed is kept under.
pub const SEED_SCOPE: &str = "owner";

/// The directory under the application's data directory that recovery keeps its records in.
const DIRECTORY: &str = "recovery";

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
struct DeviceSigner(AuthorisationKeyPair);

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
                file.lock()?;
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
    /// on Unix. On Windows it has the permissions of the folder the destination is in.
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
    /* Enabling a writer                                                       */
    /* ---------------------------------------------------------------------- */

    /// Commits the bundle with `writer` named in it, and only then says the writer is enabled.
    ///
    /// The evidence this returns is what a host's backup writer needs before it is declared
    /// recovery-enabled: a restore trusts a writer key only from this bundle, so a writer declared
    /// first and written down second is a writer whose archives a restore cannot verify.
    ///
    /// # Errors
    ///
    /// Returns a refusal when recovery is not on, the account cannot be used or an earlier write is
    /// waiting to be settled; `OUTCOME_UNKNOWN` when this write was not answered; and the service's
    /// own failure otherwise. No evidence is returned for a write that was not answered.
    pub async fn enable_writer(
        &self,
        account: &Account,
        writer: TrustedWriter,
    ) -> Result<WriterEnabled> {
        let _step = self.step().await?;
        let record = self
            .record()?
            .filter(|record| record.kept)
            .ok_or_else(|| CommandError::refused("recovery has not been turned on"))?;
        refuse_if_blocked(account, &record.origin()?)?;
        let seed = self.seed(false)?;
        let mut store = self.store(&record, account)?;
        let mut bundle = store.fetch(&seed).await.map_err(said)?;
        store
            .enable_writer(&seed, &mut bundle, writer, now())
            .await
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
        RecoveryError::BundleWriteUnsettled { .. } => CommandError::refused(
            "a write to the recovery bundle was not answered. Settle it before anything else is \
             written",
        ),
        RecoveryError::Service(error) => CommandError::from(error),
        other => CommandError::local_failure(other.to_string()),
    }
}

/// The time on this machine's clock, in UTC milliseconds.
/// Writes `body` as the whole of the file the person chose for the kit, readable by this user alone
/// where the platform has such a thing.
///
/// It writes the file in place, and does not go through a temporary file beside it as the record
/// and the setting do: the person's save dialog grants this program that one file and not the
/// folder it is in, so a second file made beside it would ask for the folder on a system that
/// guards its personal folders, and a crash between the write and the rename would leave a hidden
/// copy of the seed that nothing removes. A kit that a crash tears is a visible file that the
/// page never said it saved.
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
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
    file.write_all(body)?;
    file.sync_all()
}

fn now() -> TimestampMs {
    TimestampMs::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            }),
    )
}
