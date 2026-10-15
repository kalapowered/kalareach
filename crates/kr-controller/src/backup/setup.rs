//! The owner's setup of this host's backups: what the daemon does when `kr backup setup` asks.
//!
//! The command makes the recovery seed, prints the kit and seals the bundle. The daemon holds the
//! account this host is signed in with and the host's own keys, so it is the one that reaches the
//! service, and it is given the recovery recipient's public key, the bundle's locator and the sealed
//! bundle. It never holds the seed. What it keeps of the kit is the recipient's public key and a
//! fingerprint of it.
//!
//! # The order
//!
//! `backup.enable` does four things, in the order the specification gives, and the first three can
//! each be done again with the same effect:
//!
//! 1. **The bundle first.** It is written to the service by a compare-and-swap against absence at
//!    its locator, signed as an installation by a key made for the call and never kept. A repeat
//!    carries the same identity and the same bytes. A write the service refused or did not answer
//!    is settled by reading the bundle: the same bytes are there when an earlier try applied, and
//!    anything else stops the call. When the service named a delay with its answer, the read
//!    waits for it: the call ends as unknown with the delay, and the command repeats it.
//! 2. **The writer's enrolment.** The host's owner key signs the writer's record, at revision one,
//!    with the instant the command chose, so a repeat sends the same bytes and is answered
//!    `unchanged`.
//! 3. **Managed backup storage is turned on**, when it is off, against the revision just read.
//! 4. **The setup is recorded**, with the writer's enrolment, in one transaction. With `replace`
//!    the same transaction retires the earlier archive's writer and cancels what it had not
//!    finished.
//!
//! A bundle and an enrolment that a failed call leaves at the service are harmless: no host record
//! names them, and the kit printed for them is void once the failure is confirmed.
//!
//! # Which account
//!
//! The call takes the mark of the account signed in when it begins, and presents tokens fixed to
//! it. A sign-in as another account during the call stops the next request that carries a token;
//! the enrolment carries none, so the mark is compared again before the setup is recorded.
//!
//! # What `backup.status` says while a call runs
//!
//! Each call that is admitted has an entry of its own, made before the call waits for another or
//! for a token and removed by a guard when the call ends however it ends. `backup.status` reads the
//! entries without waiting for any call, so a setup that is under way is told so.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::ClientError;
use kr_client::recovery::{bundle_collection, kit_fingerprint};
use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::storage::{BackupState, RetentionAnswer, RetentionChange};
use kr_client::services::{
    BackupManifestService, ManagedBackupManifestService, ManagedStorageService, ManagedSyncService,
    ServiceHttp, StorageService, SyncBackupService, SyncDispatch, SyncExchanged, SyncFetched,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::archive::{
    BACKUP_WRITER_DOMAIN, BackupWriterRecord, BackupWriterRecordPayload, RecoveryContext,
    TrustedWriter,
};
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{
    BackupEnableCause, BackupEnableParams, BackupEnableResult, BackupHostKeys, BackupLastAttempt,
    BackupSetupState, BackupStatusResult, BackupStorageState, BackupStorageUnread, BackupUnusable,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupWriterRevision};
use kr_protocol::scalars::{KeyId, Nullable, U64};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sync::MAX_SEALED_RECOVERY_BUNDLE_BYTES;
use kr_transport::config::ProxyUrl;

use crate::account::HostAccount;
use crate::backup::BackupService;
use crate::backup::relay::InstallationSigner;
use crate::backup::runtime::{HostKeySigner, TokenState, describe_token, managed_transport};
use crate::backup::store::{Setup, SetupRecord};
use crate::backup::uploader::Hold;
use crate::error::{ControllerError, Result};
use crate::quiet::Quiet;

/// How long a status read waits for the service before it says nothing was read.
const STATUS_READ: Duration = Duration::from_secs(15);

/// How many times a retention change decided against a revision that has moved is decided again.
const RETENTION_TRIES: usize = 3;

/// Why a setup that is recorded cannot make backups, or none when it can.
///
/// One rule for the producer, which holds a pass back by it, and for `backup.status`, which tells
/// the owner: the service and the account signed in are the setup's, the keys this host holds are
/// the ones it names, and the writer is still enrolled for the archive.
#[must_use]
pub fn standing(
    record: &SetupRecord,
    origin: &str,
    account_mark: Option<[u8; 32]>,
    writer_key_id: KeyId,
    producer_key_id: KeyId,
    enrolled: &[(ArchiveId, KeyId)],
) -> Option<BackupUnusable> {
    if origin != record.origin || account_mark != Some(record.account_mark) {
        return Some(BackupUnusable::Account);
    }
    if writer_key_id != record.writer_key_id || producer_key_id != record.producer_key_id {
        return Some(BackupUnusable::Keys);
    }
    if !enrolled.contains(&(record.archive_id, record.writer_key_id)) {
        return Some(BackupUnusable::WriterRetired);
    }
    None
}

/// The calls that are running, and how the last one that did not set backups up ended.
#[derive(Debug, Default)]
struct Calls {
    next: u64,
    running: BTreeMap<u64, String>,
    last: Option<BackupLastAttempt>,
}

/// One call's entry, removed when the call ends however it ends.
struct Entry {
    calls: Arc<Mutex<Calls>>,
    id: u64,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running
            .remove(&self.id);
    }
}

/// What the daemon does for `backup.status` and `backup.enable`.
pub struct BackupSetup {
    origin: GatewayOrigin,
    proxy: Option<ProxyUrl>,
    writer: AuthorisationKeyPair,
    /// The key the writer's enrolment is signed with: the host's device authorisation key. The
    /// service keeps it as the collection's owner and requires it for every later enrolment.
    owner: AuthorisationKeyPair,
    producer: StoredEnvelopeKeyPair,
    account: Arc<HostAccount>,
    backup: Arc<BackupService>,
    quiet: Arc<Quiet>,
    /// One call at a time reaches the service.
    serial: tokio::sync::Mutex<()>,
    calls: Arc<Mutex<Calls>>,
    /// Where a test stops the next `backup.status` between its two reads.
    #[cfg(feature = "testing")]
    status_pause: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

impl std::fmt::Debug for BackupSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupSetup")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

/// How a step of a call ended, when it did not go on.
type Ended = BackupEnableResult;

impl BackupSetup {
    /// Builds the setup over the service at `origin`, with the host's keys.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "the service, its proxy, the three keys, the account, the backup service and the \
                  record of delays the service has named"
    )]
    pub fn new(
        origin: GatewayOrigin,
        proxy: Option<ProxyUrl>,
        writer: AuthorisationKeyPair,
        owner: AuthorisationKeyPair,
        producer: StoredEnvelopeKeyPair,
        account: Arc<HostAccount>,
        backup: Arc<BackupService>,
        quiet: Arc<Quiet>,
    ) -> Self {
        Self {
            origin,
            proxy,
            writer,
            owner,
            producer,
            account,
            backup,
            quiet,
            serial: tokio::sync::Mutex::new(()),
            calls: Arc::new(Mutex::new(Calls::default())),
            #[cfg(feature = "testing")]
            status_pause: Mutex::new(None),
        }
    }

    /// Stops the next `backup.status` between its two reads. Returns the end that says it has
    /// arrived and the end that lets it go.
    #[cfg(feature = "testing")]
    pub fn pause_the_next_status_between_its_reads(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let (arrived, go) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        *self
            .status_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            Some((Arc::clone(&arrived), Arc::clone(&go)));
        (arrived, go)
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, Calls> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The fingerprints of the calls that have not ended, oldest first, and how the last one that
    /// did not set backups up ended. Read without waiting for any call.
    #[must_use]
    pub fn progress(&self) -> (Vec<String>, Option<BackupLastAttempt>) {
        let calls = self.calls();
        (
            calls.running.values().cloned().collect(),
            calls.last.clone(),
        )
    }

    /// Answers `backup.status`.
    ///
    /// The calls that are running are read first, and without waiting for any of them. The
    /// recorded setup is read next: a call records its setup and then ends, so a call that had
    /// ended when the first read was made has recorded its setup by the time the second is, and a
    /// kit that is in use is never told as "not set up, and none in progress". Everything after
    /// that is bounded and waits for no call.
    ///
    /// # Errors
    ///
    /// Returns the store's failure when the recorded setup cannot be read: an answer that the host
    /// is not set up is the store's own fact, and a store that could not be read says nothing.
    pub async fn status(&self, privacy_mode: bool) -> Result<BackupStatusResult> {
        let (running, last) = self.progress();
        #[cfg(feature = "testing")]
        {
            let pause = self
                .status_pause
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some((arrived, go)) = pause {
                arrived.notify_one();
                go.notified().await;
            }
        }
        let backup = Arc::clone(&self.backup);
        let (setup, enrolled) = tokio::task::spawn_blocking(move || {
            Ok::<_, ControllerError>((backup.setup()?, backup.authorised_writers()?))
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the thread that reads the recorded setup did not finish".to_owned(),
        })??;

        let tokens = self.account.tokens_for(self.origin.as_str());
        let sign_in = self.sign_in(&tokens).await;
        let mark = self.account.mark_at(self.origin.as_str());
        let state = if let Some(Setup { record, .. }) = &setup {
            BackupSetupState::Committed {
                archive_id: record.archive_id,
                kit_fingerprint: record.kit_fingerprint.clone(),
                enabled_at_ms: record.enabled_at_ms,
                unusable: Nullable::from(standing(
                    record,
                    self.origin.as_str(),
                    mark.map(|mark| mark.to_bytes()),
                    self.writer.key_id(),
                    self.producer.key_id(),
                    &enrolled,
                )),
            }
        } else {
            BackupSetupState::None {}
        };
        // A call that has not ended is shown whether or not a setup is recorded: a replacement
        // under way is told so beside the setup it will replace.
        let setup = if running.is_empty() {
            state
        } else {
            BackupSetupState::InProgress {
                kit_fingerprints: running,
            }
        };
        let storage = match mark {
            Some(mark) if sign_in == BackupSignIn::Usable => self.read_storage(mark).await,
            _ => BackupStorageState::Unread {
                why: BackupStorageUnread::NoToken,
            },
        };
        Ok(BackupStatusResult {
            service: Nullable::some(self.origin.as_str().to_owned()),
            sign_in,
            privacy_mode,
            setup,
            keys: Nullable::some(BackupHostKeys {
                writer_key_id: self.writer.key_id(),
                writer_public_key: *self.writer.public(),
                producer_key_id: self.producer.key_id(),
                producer_public_key: *self.producer.public(),
            }),
            storage,
            last_attempt: Nullable::from(last),
        })
    }

    /// Whether this host holds an account token a request may carry, and why not when it does not.
    ///
    /// Asking for a token can wait for the account's lock, which a call that is refreshing the
    /// grant holds, so the wait is bounded. The token is asked for in a task of its own and only
    /// the wait for its answer is cut: a renewal that is under way at the limit is not dropped,
    /// because the account service treats a refresh token it already rotated as a replay and ends
    /// the sign-in. A token that could not be had in time is told as one that was not renewed.
    async fn sign_in(&self, tokens: &Arc<dyn AccountTokenSource>) -> BackupSignIn {
        let tokens = Arc::clone(tokens);
        let asked = tokio::spawn(async move { tokens.token(BACKUP_WRITE_SCOPE).await.map(|_| ()) });
        match tokio::time::timeout(STATUS_READ, asked).await {
            Ok(Ok(Ok(()))) => BackupSignIn::Usable,
            Ok(Ok(Err(_))) => self.sign_in_cause(),
            Ok(Err(_)) | Err(_) => BackupSignIn::NotRenewed,
        }
    }

    /// Why no token can be had, in the words of `backup.read`.
    fn sign_in_cause(&self) -> BackupSignIn {
        match describe_token(&self.account) {
            TokenState::Usable | TokenState::NotRenewed => BackupSignIn::NotRenewed,
            TokenState::Absent => BackupSignIn::SignedOut,
            TokenState::SigningIn => BackupSignIn::Waiting,
            TokenState::Ended => BackupSignIn::Ended,
            TokenState::WithoutScope => BackupSignIn::WithoutScope,
        }
    }

    /// A live read of what the account holds at the service, bounded, and held to any delay the
    /// service has named.
    async fn read_storage(&self, mark: kr_client::services::AccountMark) -> BackupStorageState {
        if self.quiet.left().is_some() {
            return BackupStorageState::Unread {
                why: BackupStorageUnread::Delayed,
            };
        }
        let Ok(storage) = self.storage(mark) else {
            return BackupStorageState::Unread {
                why: BackupStorageUnread::Failed,
            };
        };
        match tokio::time::timeout(STATUS_READ, storage.status()).await {
            Ok(Ok(status)) => BackupStorageState::Read {
                backup_on: status.backup == BackupState::On,
                daily_snapshots: U64::new(u64::from(status.retention.daily_snapshots)),
                allowance_bytes: Nullable::from(status.allowance_bytes.map(U64::new)),
                held_bytes: U64::new(status.stored.bytes),
                deleted_still_charged_bytes: U64::new(status.tombstoned.bytes),
            },
            Ok(Err(error)) => {
                if let Some(delay) = Hold::of(&error).retry_after {
                    self.quiet.owe(delay);
                }
                BackupStorageState::Unread {
                    why: BackupStorageUnread::Failed,
                }
            }
            Err(_) => BackupStorageState::Unread {
                why: BackupStorageUnread::Failed,
            },
        }
    }

    fn transport(&self) -> Result<Arc<dyn ServiceHttp>> {
        managed_transport(&self.origin, self.proxy.as_ref())
    }

    /// The storage client of one call, presenting tokens fixed to the account it began under.
    fn storage(&self, mark: kr_client::services::AccountMark) -> Result<ManagedStorageService> {
        let tokens = self.account.tokens_fixed_to(self.origin.as_str(), mark);
        Ok(ManagedStorageService::new(
            self.origin.clone(),
            self.transport()?,
            Arc::new(HostKeySigner {
                key: self.writer.clone(),
            }),
        )
        .presenting(tokens)
        .leaving_delays_to_the_caller())
    }

    /// Answers `backup.enable`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for a call whose fingerprint is not the one its
    /// recovery public key has. Every other way the call can end is one of its answers.
    pub async fn enable(
        &self,
        params: BackupEnableParams,
        daemon: Arc<dyn Any + Send + Sync>,
    ) -> Result<BackupEnableResult> {
        if params.kit_fingerprint != kit_fingerprint(&params.recovery_public_key) {
            return Err(ControllerError::InvalidArgument(
                "the kit fingerprint is not the recovery public key's".to_owned(),
            ));
        }
        // The account the call begins under is the one it was admitted under, and not the one that
        // is signed in when it gets its turn: a call that waits behind another must not start its
        // requests under an account that signed in meanwhile.
        let mark = self
            .account
            .mark_at(self.origin.as_str())
            .ok_or_else(|| self.sign_in_cause());
        // Recorded when the call is admitted, before it waits for another call or for a token.
        let entry = {
            let mut calls = self.calls();
            let id = calls.next;
            calls.next += 1;
            calls.running.insert(id, params.kit_fingerprint.clone());
            Entry {
                calls: Arc::clone(&self.calls),
                id,
            }
        };
        let serial = self.serial.lock().await;
        let ended = self.run(&params, mark, daemon).await;
        drop(serial);
        {
            let mut calls = self.calls();
            calls.last = match &ended {
                BackupEnableResult::Enabled { .. } => None,
                BackupEnableResult::Declined { cause } => Some(BackupLastAttempt {
                    kit_fingerprint: params.kit_fingerprint.clone(),
                    cause: Nullable::some(cause.clone()),
                }),
                BackupEnableResult::Unknown { .. } => Some(BackupLastAttempt {
                    kit_fingerprint: params.kit_fingerprint.clone(),
                    cause: Nullable::null(),
                }),
            };
        }
        drop(entry);
        Ok(ended)
    }

    /// Everything a call does, ending as one of its answers.
    async fn run(
        &self,
        params: &BackupEnableParams,
        mark: std::result::Result<kr_client::services::AccountMark, BackupSignIn>,
        daemon: Arc<dyn Any + Send + Sync>,
    ) -> BackupEnableResult {
        match self.steps(params, mark, daemon).await {
            Ok(done) | Err(done) => done,
        }
    }

    async fn steps(
        &self,
        params: &BackupEnableParams,
        mark: std::result::Result<kr_client::services::AccountMark, BackupSignIn>,
        daemon: Arc<dyn Any + Send + Sync>,
    ) -> std::result::Result<BackupEnableResult, Ended> {
        let origin = self.origin.as_str();
        let backup = Arc::clone(&self.backup);
        let held = tokio::task::spawn_blocking(move || backup.setup())
            .await
            .map_err(|_| unknown(None))?
            .map_err(|_| unknown(None))?;

        // 1. Preconditions.
        if let Some(Setup { record, .. }) = &held {
            if record.archive_id == params.archive_id {
                // A repeat of a call that finished is answered from what it left.
                return if same_setup(record, params) {
                    Ok(enabled(record))
                } else {
                    Err(declined(BackupEnableCause::AlreadySetUp {}))
                };
            }
            if !params.replace {
                return Err(declined(BackupEnableCause::AlreadySetUp {}));
            }
        }
        if self.writer.key_id() != params.writer_key_id
            || self.producer.key_id() != params.producer_key_id
        {
            return Err(declined(BackupEnableCause::KeysChanged {}));
        }
        if params.sealed_bundle.as_slice().len() as u64 > MAX_SEALED_RECOVERY_BUNDLE_BYTES {
            return Err(declined(BackupEnableCause::BundleTooLarge {}));
        }
        // A call admitted while no account was signed in says why, as it was then.
        let mark = mark.map_err(|sign_in| declined(BackupEnableCause::SignIn { sign_in }))?;
        let tokens = self.account.tokens_fixed_to(origin, mark);
        if let Err(error) = tokens.token(BACKUP_WRITE_SCOPE).await {
            return Err(self.ended_by(&error, mark, true));
        }

        // 2. The bundle first.
        self.write_bundle(params, mark).await?;
        // 3. The writer's enrolment.
        self.enrol(params, mark).await?;
        // 4. Managed backup storage on.
        self.turn_storage_on(mark).await?;
        // 5. The setup, with the writer's enrolment, in one transaction.
        if self.account.mark_at(origin) != Some(mark) {
            return Err(declined(BackupEnableCause::AnotherAccount {}));
        }
        let record = SetupRecord {
            archive_id: params.archive_id,
            origin: origin.to_owned(),
            account_mark: mark.to_bytes(),
            recovery_public_key: params.recovery_public_key,
            kit_fingerprint: params.kit_fingerprint.clone(),
            writer_key_id: params.writer_key_id,
            producer_key_id: params.producer_key_id,
            enabled_at_ms: params.enabled_at_ms,
        };
        let backup = Arc::clone(&self.backup);
        let replace = params.replace;
        let at = params.enabled_at_ms;
        // The thread keeps the daemon until the commit has ended, though this call stops waiting
        // for it.
        let committed = {
            let record = record.clone();
            tokio::task::spawn_blocking(move || {
                let _daemon = daemon;
                backup.commit_setup(&record, replace, at)
            })
            .await
        };
        match committed {
            Ok(Ok(_)) => Ok(enabled(&record)),
            // A store that refuses the setup as it stands: the archive has generations here.
            Ok(Err(ControllerError::InvalidArgument(_))) => {
                Err(declined(BackupEnableCause::ArchiveInUse {}))
            }
            _ => Err(unknown(None)),
        }
    }

    /// Writes the sealed bundle at its locator, or finds that an earlier try already did.
    async fn write_bundle(
        &self,
        params: &BackupEnableParams,
        mark: kr_client::services::AccountMark,
    ) -> std::result::Result<(), Ended> {
        self.wait_out_delay()?;
        let tokens = self.account.tokens_fixed_to(self.origin.as_str(), mark);
        let installation = AuthorisationKeyPair::generate().map_err(|_| unknown(None))?;
        let transport = self.transport().map_err(|_| unknown(None))?;
        let sync = ManagedSyncService::new(
            self.origin.clone(),
            transport,
            Arc::new(InstallationSigner { key: installation }),
        )
        .presenting(tokens, BACKUP_WRITE_SCOPE)
        .leaving_delays_to_the_caller();
        let collection = bundle_collection(&RecoveryContext {
            service_origin: self.origin.as_str().to_owned(),
            bundle_locator: params.bundle_locator.to_string(),
        });
        let sent = sync
            .compare_exchange_dispatched(
                &collection,
                params.request_id,
                kr_ipc::now_ms().get(),
                None,
                params.sealed_bundle.as_slice(),
            )
            .await;
        match sent {
            Ok(SyncDispatch::Answered(SyncExchanged::Applied { .. })) => Ok(()),
            // Refused, or signed before the collection's cutoff: what is there decides.
            Ok(SyncDispatch::Answered(_)) => self.settle_bundle(&sync, &collection, params).await,
            // Refused on this host before anything left: nothing can have been written.
            Ok(SyncDispatch::NotSent(error)) => Err(self.ended_by(&error, mark, false)),
            Err(error) => {
                // A definite answer ends the call. Anything else may have been carried out, and
                // what the service holds decides.
                match self.ended_by(&error, mark, false) {
                    BackupEnableResult::Unknown { .. } => {
                        self.settle_bundle(&sync, &collection, params).await
                    }
                    ended => Err(ended),
                }
            }
        }
    }

    /// Reads the bundle at the locator and compares it with the one this call writes.
    async fn settle_bundle(
        &self,
        sync: &ManagedSyncService,
        collection: &str,
        params: &BackupEnableParams,
    ) -> std::result::Result<(), Ended> {
        // A delay the service named with the answer that brought the call here is owed to the
        // read as much as to any other request.
        self.wait_out_delay()?;
        match sync.fetch(collection).await {
            Ok(SyncFetched::Held { ciphertext, .. }) => {
                if ciphertext == params.sealed_bundle.as_slice() {
                    Ok(())
                } else {
                    Err(declined(BackupEnableCause::BundleConflict {}))
                }
            }
            // Nothing there: the write did not apply, and the call cannot say why.
            Ok(SyncFetched::Absent { .. }) => Err(unknown(self.quiet.left())),
            Err(error) if error.code() == ErrorCode::UnknownSession => {
                Err(declined(BackupEnableCause::TokenNotAccepted {}))
            }
            Err(error) => Err(self.ended_by_error(&error)),
        }
    }

    /// Has the owner's key enrol the host's writer for the archive.
    async fn enrol(
        &self,
        params: &BackupEnableParams,
        mark: kr_client::services::AccountMark,
    ) -> std::result::Result<(), Ended> {
        self.wait_out_delay()?;
        let payload = BackupWriterRecordPayload {
            archive_id: params.archive_id,
            writer: TrustedWriter {
                writer_key_id: self.writer.key_id(),
                signing_key: *self.writer.public(),
                enrolled_at_ms: params.enabled_at_ms,
            },
            writer_revision: BackupWriterRevision::new(1),
            owner_key_id: self.owner.key_id(),
            enrolled_at_ms: params.enabled_at_ms,
        };
        let signature = payload
            .signing_input()
            .map_err(|_| unknown(None))
            .and_then(|input| {
                SigningTranscript::from_canonical_bytes(BACKUP_WRITER_DOMAIN, input)
                    .map_err(|_| unknown(None))
            })
            .and_then(|transcript| sign(&self.owner, &transcript).map_err(|_| unknown(None)))?;
        let record = BackupWriterRecord { payload, signature };
        let manifest = ManagedBackupManifestService::new(
            self.origin.clone(),
            self.transport().map_err(|_| unknown(None))?,
            Arc::new(HostKeySigner {
                key: self.owner.clone(),
            }),
        )
        .leaving_delays_to_the_caller();
        // `unchanged` counts as done: the same record, sent again.
        manifest
            .enrol(&record)
            .await
            .map(|_| ())
            .map_err(|error| self.ended_by(&error, mark, false))
    }

    /// Turns managed backup storage on when it is off, against the revision just read.
    async fn turn_storage_on(
        &self,
        mark: kr_client::services::AccountMark,
    ) -> std::result::Result<(), Ended> {
        let storage = self.storage(mark).map_err(|_| unknown(None))?;
        for _ in 0..RETENTION_TRIES {
            self.wait_out_delay()?;
            let status = storage
                .status()
                .await
                .map_err(|error| self.ended_by(&error, mark, false))?;
            if status.backup == BackupState::On {
                return Ok(());
            }
            match storage
                .set_retention(&RetentionChange {
                    backup: BackupState::On,
                    daily_snapshots: None,
                    expected_revision: status.retention_revision,
                })
                .await
                .map_err(|error| self.ended_by(&error, mark, false))?
            {
                RetentionAnswer::Done(_) => return Ok(()),
                // The record moved on since it was read: read it and decide again.
                RetentionAnswer::Stale { .. } => {}
            }
        }
        Err(unknown(None))
    }

    /// Ends the call, without a request, if the service asked to be left alone.
    fn wait_out_delay(&self) -> std::result::Result<(), Ended> {
        match self.quiet.left() {
            Some(left) => Err(unknown(Some(left))),
            None => Ok(()),
        }
    }

    /// How a request that failed ends the call.
    ///
    /// `before_token` says the failure was the check that a token can be had at all, which names
    /// the sign-in's state and not the service's.
    fn ended_by(
        &self,
        error: &ClientError,
        mark: kr_client::services::AccountMark,
        before_token: bool,
    ) -> Ended {
        // The fixed token source refuses once another account is signed in, and says nothing that
        // tells that apart from the service's own unavailability, so the account is looked at.
        if self.account.mark_at(self.origin.as_str()) != Some(mark) {
            return declined(BackupEnableCause::AnotherAccount {});
        }
        if before_token {
            return declined(BackupEnableCause::SignIn {
                sign_in: self.sign_in_cause(),
            });
        }
        self.ended_by_error(error)
    }

    fn ended_by_error(&self, error: &ClientError) -> Ended {
        let hold = Hold::of(error);
        if let Some(delay) = hold.retry_after {
            self.quiet.owe(delay);
        }
        match error {
            ClientError::Refused { .. } => match hold.code {
                ErrorCode::QuotaExceeded => declined(BackupEnableCause::NoAllowance {}),
                ErrorCode::UnknownSession => declined(BackupEnableCause::TokenNotAccepted {}),
                ErrorCode::RateLimited
                | ErrorCode::ServiceCapacity
                | ErrorCode::UpstreamUnavailable
                | ErrorCode::OutcomeUnknown
                | ErrorCode::ClockUntrusted
                | ErrorCode::ResourceUnavailable
                | ErrorCode::StorageUnavailable => unknown(hold.retry_after),
                code => declined(BackupEnableCause::ServiceRefused { code }),
            },
            _ => unknown(hold.retry_after),
        }
    }
}

/// Whether the recorded setup is the one this call asks for.
fn same_setup(record: &SetupRecord, params: &BackupEnableParams) -> bool {
    record.recovery_public_key == params.recovery_public_key
        && record.kit_fingerprint == params.kit_fingerprint
        && record.writer_key_id == params.writer_key_id
        && record.producer_key_id == params.producer_key_id
        && record.enabled_at_ms == params.enabled_at_ms
}

fn enabled(record: &SetupRecord) -> BackupEnableResult {
    BackupEnableResult::Enabled {
        archive_id: record.archive_id,
        kit_fingerprint: record.kit_fingerprint.clone(),
        enabled_at_ms: record.enabled_at_ms,
    }
}

const fn declined(cause: BackupEnableCause) -> BackupEnableResult {
    BackupEnableResult::Declined { cause }
}

fn unknown(retry_after: Option<Duration>) -> BackupEnableResult {
    BackupEnableResult::Unknown {
        retry_after_seconds: Nullable::from(
            retry_after.map(|delay| U64::new(delay.as_secs().max(1))),
        ),
    }
}
