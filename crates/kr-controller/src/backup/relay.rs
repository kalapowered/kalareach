//! The relay of a restore's reads of the managed storage service.
//!
//! A restore runs in the `kr` process, which holds the recovery kit, opens the archive and writes
//! the files. This host holds the account the service is read with, so the daemon makes the
//! requests. It relays ciphertext and public records and nothing else: it holds no seed, opens no
//! archive and knows no file name or destination. What it sees is what the service holds already,
//! the archive and object identifiers a read names, the bundle's locator and the checkpoint a
//! generation read is held to, and none of them is written to a log or put in an error.
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
//! * **A read is held to the state it began under, and checked again where it leaves.** A request
//!   waits for an account token first, and that wait can last: the sign-in may be renewed or
//!   changed meanwhile. So the relay's token source checks privacy mode and the record of quiet
//!   once the token is in hand, which is the last point before a request is signed and sent, and a
//!   read that finds privacy mode on, or changed since the read began, or a delay owed, sends
//!   nothing. A request already on its way when privacy mode is turned on cannot be recalled; its
//!   answer is not given (`Controller::backup_read` compares the state after the read).
//! * **The service's words stay out.** A refusal by the service reaches the person as its code with
//!   a sentence of this program's own, never as the service's text, which can repeat what was
//!   asked. A failure on this host says what it is in this program's words.

use std::sync::Arc;
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::recovery::bundle_collection;
use kr_client::services::account::{AccountToken, AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::{
    BackupManifestService, ManagedSyncService, ServiceFuture, ServiceSigner, StorageService,
    SyncBackupService, SyncFetched,
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
use crate::backup::runtime::{TokenState, clients_over, describe_token, managed_transport};
use crate::backup::uploader::Hold;
use crate::error::{ControllerError, Result};
use crate::privacy::{PrivacyState, Published};
use crate::quiet::Quiet;

tokio::task_local! {
    /// The privacy state a read began under, for the read being answered in this task.
    static READING: Published;
}

/// The token source the relay's clients present, which checks where a request is about to leave.
///
/// The token is asked for before a request is signed, and the wait for it is the one place a read
/// can go from permitted to refused without anything on the request's path noticing. This is the
/// last point before the request leaves.
#[derive(Debug)]
struct Gated {
    inner: Arc<dyn AccountTokenSource>,
    privacy: PrivacyState,
    quiet: Arc<Quiet>,
}

impl Gated {
    /// Whether a request may leave now.
    fn open(&self) -> kr_client::Result<()> {
        // This is the relay's own refusal, not a delay the service named, so it carries none: the
        // record already holds the delay, and the relay answers what is left of it.
        if self.quiet.left().is_some() {
            return Err(ClientError::refusal(
                ErrorCode::RateLimited,
                kr_client::shown::Shown::said(
                    "the service asked to be left alone, and the time has not passed",
                ),
            ));
        }
        let now = self.privacy.now();
        // A read that has not said which state it began under is not sent.
        let began = READING.try_with(|began| *began).ok();
        if now.private || began != Some(now) {
            return Err(ClientError::refusal(
                ErrorCode::PermissionDenied,
                kr_client::shown::Shown::said(
                    "privacy mode is on, or changed while that was being read, so nothing is sent",
                ),
            ));
        }
        Ok(())
    }
}

impl AccountTokenSource for Gated {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            let token = self.inner.token(scope).await?;
            self.open()?;
            Ok(token)
        })
    }
}

/// Why a read did not answer.
enum Failure {
    /// The service refused it, or the exchange with it failed.
    Exchange(ClientError),
    /// This relay refused it, in its own words.
    Local(ControllerError),
}

impl From<ClientError> for Failure {
    fn from(error: ClientError) -> Self {
        Self::Exchange(error)
    }
}

/// A key that exists for this process only, signing the requests the service reads as a device's.
pub(crate) struct InstallationSigner {
    pub(crate) key: AuthorisationKeyPair,
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
    /// The check every request passes where it leaves, for the one that asks no token.
    gate: Arc<Gated>,
    /// The account's tokens as they are, for the question whether one can be had.
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
        privacy: PrivacyState,
    ) -> Result<Self> {
        Self::over(
            origin,
            managed_transport(origin, proxy)?,
            managed_transport(origin, proxy)?,
            writer,
            account,
            quiet,
            privacy,
        )
    }

    /// Builds the relay over the transports `storage` and `bundles` reach the service through.
    fn over(
        origin: &GatewayOrigin,
        storage: Arc<dyn kr_client::services::ServiceHttp>,
        bundles: Arc<dyn kr_client::services::ServiceHttp>,
        writer: &AuthorisationKeyPair,
        account: Arc<HostAccount>,
        quiet: Arc<Quiet>,
        privacy: PrivacyState,
    ) -> Result<Self> {
        let tokens = account.tokens_for(origin.as_str());
        Self::over_tokens(
            origin, storage, bundles, writer, account, tokens, quiet, privacy,
        )
    }

    /// Builds the relay over transports and an account's token source.
    #[expect(
        clippy::too_many_arguments,
        reason = "the relay is its service, its two transports, its key, the account and the \
                  token source it presents, and the two states it is held to"
    )]
    fn over_tokens(
        origin: &GatewayOrigin,
        storage: Arc<dyn kr_client::services::ServiceHttp>,
        bundles: Arc<dyn kr_client::services::ServiceHttp>,
        writer: &AuthorisationKeyPair,
        account: Arc<HostAccount>,
        tokens: Arc<dyn AccountTokenSource>,
        quiet: Arc<Quiet>,
        privacy: PrivacyState,
    ) -> Result<Self> {
        let gate = Arc::new(Gated {
            inner: Arc::clone(&tokens),
            privacy,
            quiet: Arc::clone(&quiet),
        });
        let gated: Arc<dyn AccountTokenSource> = Arc::clone(&gate) as _;
        let clients = clients_over(origin, storage, writer, &gated)?;
        let (Some(storage), Some(manifest)) = (clients.storage, clients.backup_manifest) else {
            return Err(ControllerError::NotConfigured(
                "a restore's reads need a storage client and a backup manifest client".to_owned(),
            ));
        };
        let installation = Arc::new(InstallationSigner {
            key: AuthorisationKeyPair::generate().map_err(ControllerError::registry)?,
        });
        let bundle_reads = ManagedSyncService::new(origin.clone(), bundles, installation)
            .presenting(gated, BACKUP_WRITE_SCOPE)
            .leaving_delays_to_the_caller();
        Ok(Self {
            origin: origin.clone(),
            storage,
            manifest,
            bundles: bundle_reads,
            gate,
            tokens,
            account,
            quiet,
        })
    }

    /// Answers one read, which began under the privacy state `began`.
    ///
    /// A read that reaches the service is refused first when the service has asked to be left
    /// alone: nothing is sent, and what is left of the delay is the answer. A delay the service
    /// names to a read is recorded and answered the same way. The same checks run again where the
    /// request leaves (`Gated`).
    ///
    /// # Errors
    ///
    /// Returns a [`ControllerError`] whose code is the service's and whose words are this
    /// program's, and [`ControllerError::InvalidArgument`] for a range that is not one.
    pub async fn read(
        &self,
        params: BackupReadParams,
        began: Published,
    ) -> Result<BackupReadResult> {
        if let BackupReadParams::Object { length, .. } = &params
            && (length.get() == 0 || length.get() > BACKUP_READ_MAX_RANGE_BYTES)
        {
            return Err(ControllerError::InvalidArgument(format!(
                "a read of an object asks for between one byte and {BACKUP_READ_MAX_RANGE_BYTES}"
            )));
        }
        if matches!(params, BackupReadParams::Service {}) {
            return Ok(self.service().await);
        }
        if let Some(left) = self.quiet.left() {
            return Ok(wait(left));
        }
        match READING.scope(began, self.reach(params)).await {
            Ok(result) => Ok(result),
            Err(Failure::Local(error)) => Err(error),
            Err(Failure::Exchange(error)) => {
                let hold = Hold::of(&error);
                if let Some(delay) = hold.retry_after {
                    self.quiet.owe(delay);
                    return Ok(wait(self.quiet.left().unwrap_or(delay)));
                }
                // The gate refused for a delay already on the record: that is what is answered.
                if hold.code == ErrorCode::RateLimited
                    && let Some(left) = self.quiet.left()
                {
                    return Ok(wait(left));
                }
                // The service's own text can repeat what it was asked, so a refusal by the service
                // is its code and a sentence of this program's. Everything else failed on this
                // host or on the way, and says what it is.
                let detail = match &error {
                    ClientError::Refused { .. } => local_words(hold.code).to_owned(),
                    ClientError::Host(error) => error.message.clone(),
                    other => other.to_string(),
                };
                Err(ControllerError::Refused {
                    code: hold.code,
                    detail,
                })
            }
        }
    }

    /// Sends one read that reaches the service.
    async fn reach(
        &self,
        params: BackupReadParams,
    ) -> std::result::Result<BackupReadResult, Failure> {
        match params {
            BackupReadParams::Service {} => Ok(self.service().await),
            BackupReadParams::Bundle { locator } => self.bundle(&locator.to_string()).await,
            BackupReadParams::Generation {
                archive_id,
                checkpoint,
            } => Ok(self.generation(archive_id, checkpoint.0).await?),
            BackupReadParams::Object {
                archive_id,
                object_id,
                offset,
                length,
            } => Ok(self
                .object(archive_id, object_id, offset.get(), length.get())
                .await?),
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

    async fn bundle(&self, locator: &str) -> std::result::Result<BackupReadResult, Failure> {
        let collection = bundle_collection(&RecoveryContext {
            service_origin: self.origin.as_str().to_owned(),
            bundle_locator: locator.to_owned(),
        });
        let bundle = match self.bundles.fetch(&collection).await {
            Ok(SyncFetched::Held {
                position,
                ciphertext,
            }) => {
                // No valid sealed bundle is larger, so a larger answer is a service that is not
                // behaving, and it is refused here rather than cut or sent on.
                if ciphertext.len() > BACKUP_READ_MAX_BUNDLE_BYTES {
                    return Err(Failure::Local(ControllerError::Refused {
                        code: ErrorCode::ResourceUnavailable,
                        detail: format!(
                            "the service answered with a recovery bundle over the \
                             {BACKUP_READ_MAX_BUNDLE_BYTES}-byte limit a sealed bundle has"
                        ),
                    }));
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
            Err(error) => return Err(Failure::Exchange(error)),
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
        // A fetch asks for no account token, so the check that stands at the token stands here.
        self.gate.open()?;
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
        ErrorCode::HostNotConfigured => "the storage service says it is not set up for that",
        ErrorCode::QuotaExceeded => "the account's storage allowance is spent",
        ErrorCode::OutcomeUnknown => "the storage service did not finish answering that read",
        ErrorCode::RateLimited | ErrorCode::ServiceCapacity => {
            "the storage service has no capacity for that read now"
        }
        ErrorCode::UpstreamUnavailable | ErrorCode::StorageUnavailable => {
            "the storage service could not answer that read"
        }
        _ => "the storage service refused that read",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use kr_client::services::{ServiceHttp, ServiceHttpAnswer};
    use kr_protocol::ids::{ArchiveId, BackupObjectId};
    use kr_protocol::scalars::Uuid;
    use tokio::sync::Notify;

    use super::*;
    use crate::testing::HeldTimer;

    /// A service that is never reached: it counts what is sent to it and loses every request.
    #[derive(Debug, Default)]
    struct Unreached(AtomicUsize);

    impl kr_client::services::ServiceHttp for Unreached {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(ClientError::refusal(
                    ErrorCode::UpstreamUnavailable,
                    kr_client::shown::Shown::said("this test's service is never reached"),
                ))
            })
        }

        fn post_bytes<'a>(
            &'a self,
            url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.post_json(url, body, headers)
        }
    }

    /// An account whose token arrives when the test says, as one does that is being renewed, and
    /// that says when it was asked.
    #[derive(Debug)]
    struct Renewing {
        renewed: Arc<Notify>,
        asked: Arc<Notify>,
    }

    impl AccountTokenSource for Renewing {
        fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
            Box::pin(async move {
                self.asked.notify_one();
                self.renewed.notified().await;
                Ok(AccountToken::new("a-token").expect("a token"))
            })
        }
    }

    fn state(generation: u64, private: bool) -> Published {
        Published {
            generation: kr_worker::privacy::PrivacyGeneration::new(generation),
            private,
        }
    }

    /// A relay over a service nobody reaches, whose account hands out a token when told to.
    struct Rig {
        relay: Arc<BackupRelay>,
        service: Arc<Unreached>,
        privacy: PrivacyState,
        quiet: Arc<Quiet>,
        renewed: Arc<Notify>,
        asked: Arc<Notify>,
        _runtime: tempfile::TempDir,
    }

    impl Rig {
        fn new() -> Self {
            let privacy = PrivacyState::default();
            privacy.set(state(1, false));
            // A clock that stands still until it is moved, so what is left of a delay is exactly
            // what the test made it.
            let quiet = Arc::new(Quiet::new(HeldTimer::automatic()));
            let renewed = Arc::new(Notify::new());
            let asked = Arc::new(Notify::new());
            let runtime = tempfile::tempdir().expect("a runtime directory");
            let service = Arc::new(Unreached::default());
            let origin = GatewayOrigin::new("https://storage.example").expect("an origin");
            let relay = BackupRelay::over_tokens(
                &origin,
                Arc::clone(&service) as Arc<dyn ServiceHttp>,
                Arc::clone(&service) as Arc<dyn ServiceHttp>,
                &AuthorisationKeyPair::generate().expect("a key"),
                Arc::new(crate::account::HostAccount::new(
                    Arc::new(kr_crypto::store::MemoryStore::default()),
                    kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16])),
                    runtime.path(),
                    Err(kr_protocol::host_account::SignInUnavailable::NotUsable),
                    None,
                )),
                Arc::new(Renewing {
                    renewed: Arc::clone(&renewed),
                    asked: Arc::clone(&asked),
                }),
                Arc::clone(&quiet),
                privacy.clone(),
            )
            .expect("a relay");
            Self {
                relay: Arc::new(relay),
                service,
                privacy,
                quiet,
                renewed,
                asked,
                _runtime: runtime,
            }
        }

        fn reads() -> [BackupReadParams; 3] {
            [
                BackupReadParams::Bundle {
                    locator: Uuid::from_bytes([1; 16]),
                },
                BackupReadParams::Generation {
                    archive_id: ArchiveId::new(Uuid::from_bytes([2; 16])),
                    checkpoint: Nullable::null(),
                },
                BackupReadParams::Object {
                    archive_id: ArchiveId::new(Uuid::from_bytes([2; 16])),
                    object_id: BackupObjectId::new(Uuid::from_bytes([3; 16])),
                    offset: U64::new(0),
                    length: U64::new(16),
                },
            ]
        }

        /// What the relay answers a read that began under privacy generation 1 and found the world
        /// as `change` left it by the time its request was to leave.
        async fn answer(
            &self,
            read: BackupReadParams,
            change: impl FnOnce(&PrivacyState, &Quiet),
        ) -> Result<BackupReadResult> {
            let relay = Arc::clone(&self.relay);
            // A read that asks for a token is waiting for it once it has started; whatever happens
            // to the host in the meantime happens before the token arrives. One that asks for none
            // has no wait to change the world in, so it is changed before the read is begun, which
            // is as late as a test can make it.
            let waits = !matches!(read, BackupReadParams::Generation { .. });
            let mut change = Some(change);
            if !waits && let Some(change) = change.take() {
                change(&self.privacy, &self.quiet);
            }
            let asking = tokio::spawn(async move { relay.read(read, state(1, false)).await });
            if waits {
                // The read is waiting for its token once the token source has been asked.
                self.asked.notified().await;
            }
            if let Some(change) = change.take() {
                change(&self.privacy, &self.quiet);
            }
            self.renewed.notify_one();
            asking.await.expect("the read task")
        }
    }

    /// KR-REQ-24.27: a read whose request would leave after privacy mode was turned on, or turned
    /// on and off again, sends nothing. It holds for every read the relay makes, through the real
    /// storage, manifest and bundle clients, whether they wait for a token or not; the control is
    /// the same read with nothing changed, which does send.
    #[tokio::test]
    async fn no_request_leaves_after_privacy_mode_changed_whichever_read_it_is() {
        for read in Rig::reads() {
            let control = Rig::new();
            let _ = control.answer(read.clone(), |_, _| {}).await;
            assert_eq!(
                control.service.0.load(Ordering::SeqCst),
                1,
                "{read:?}: with nothing changed the request leaves"
            );

            let turned_on = Rig::new();
            let refused = turned_on
                .answer(read.clone(), |privacy, _| privacy.set(state(2, true)))
                .await
                .expect_err("privacy mode was turned on");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{read:?}");
            assert_eq!(turned_on.service.0.load(Ordering::SeqCst), 0, "{read:?}");

            let there_and_back = Rig::new();
            let refused = there_and_back
                .answer(read.clone(), |privacy, _| {
                    privacy.set(state(2, true));
                    privacy.set(state(3, false));
                })
                .await
                .expect_err("privacy mode came on and went off again");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{read:?}");
            assert_eq!(
                there_and_back.service.0.load(Ordering::SeqCst),
                0,
                "{read:?}"
            );
        }
    }

    /// A delay another request recorded while a read waited for its token is owed by that read too:
    /// it answers what is left and sends nothing.
    #[tokio::test]
    async fn no_request_leaves_inside_a_delay_recorded_while_it_waited() {
        for read in Rig::reads() {
            let rig = Rig::new();
            let recorded = std::sync::Mutex::new(None);
            let answer = rig
                .answer(read.clone(), |_, quiet| {
                    quiet.owe(Duration::from_millis(29_500));
                    *recorded.lock().expect("the deadline") = quiet.owed().map(|owed| owed.until);
                })
                .await
                .expect("an answer");
            match answer {
                BackupReadResult::Wait {
                    retry_after_seconds,
                } => assert_eq!(retry_after_seconds.get(), 30, "{read:?}: rounded up"),
                other => panic!("{read:?}: {other:?}"),
            }
            assert_eq!(rig.service.0.load(Ordering::SeqCst), 0, "{read:?}");
            assert_eq!(
                rig.quiet.owed().map(|owed| owed.until),
                *recorded.lock().expect("the deadline"),
                "{read:?}: the gate's own refusal did not move the deadline on the record"
            );
        }
    }

    /// The gate itself refuses a request that would leave inside a delay on the record, for a
    /// generation read, which asks for no token and so has no wait in which a delay could be
    /// recorded: the check is made directly, with the delay already owed when the request is to
    /// leave. Without it the read's early check is all that stands.
    #[tokio::test]
    async fn a_generation_read_is_refused_by_the_gate_inside_a_delay_on_the_record() {
        let rig = Rig::new();
        rig.quiet.owe(Duration::from_secs(45));
        let refused = READING
            .scope(
                state(1, false),
                rig.relay
                    .generation(ArchiveId::new(Uuid::from_bytes([2; 16])), None),
            )
            .await
            .expect_err("the gate refuses inside a delay");
        assert_eq!(refused.code(), ErrorCode::RateLimited);
        assert_eq!(rig.service.0.load(Ordering::SeqCst), 0);
        // The control: with no delay on the record the same call sends.
        let free = Rig::new();
        let _ = READING
            .scope(
                state(1, false),
                free.relay
                    .generation(ArchiveId::new(Uuid::from_bytes([2; 16])), None),
            )
            .await;
        assert_eq!(free.service.0.load(Ordering::SeqCst), 1);
    }

    /// A read that does not say which state it began under is not sent: the check compares with
    /// something, and when there is nothing it refuses.
    #[tokio::test]
    async fn a_read_that_began_under_no_state_is_not_sent() {
        let rig = Rig::new();
        rig.renewed.notify_one();
        let refused = rig
            .relay
            .object(
                ArchiveId::new(Uuid::from_bytes([2; 16])),
                BackupObjectId::new(Uuid::from_bytes([3; 16])),
                0,
                16,
            )
            .await
            .expect_err("no state to compare with");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert_eq!(rig.service.0.load(Ordering::SeqCst), 0);
    }
}
