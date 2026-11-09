//! Recovery, through the commands the page calls, against the sync service as a local Worker
//! answered it.
//!
//! The recovery bundle is committed before the host's writer is declared recovery-enabled and
//! before the host is set up under this computer's recovery, and bundle updates use the stable
//! locator and compare-and-swap without reprinting the seed. The sync service is a choice of its
//! own, and the account's token goes only to the service the account is signed in to.
//!
//! The companion runs on the mock runtime, its commands are called the way the page calls them,
//! and its transport is the real one, talking over loopback to the stand-in `kr_service_stand_in`
//! provides, which `crates/kr-client/tests/bundle_answers.rs` holds to a recording of a local
//! Worker. The account is the one thing stood in: a signed-in grant a test hands over, because the
//! account service is not under test here.
#![cfg(desktop)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use companion_tauri::AppState;
use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use companion_tauri::account::{Account, AccountSlot};
use companion_tauri::device::DeviceIdentity;
use companion_tauri::recovery::{HostCoverView, LeftView, Recovery, SEED_SCOPE};
use kr_client::recovery::{BundleStore, HostBackups, parse_kit};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountMark, AccountToken, AccountTokenSource, BACKUP_RESTORE_SCOPE,
    BACKUP_WRITE_SCOPE, Client, IssuedGrant, RECOVERY_BACKUP_SCOPES, REQUESTED_SCOPES,
    RefreshToken, SignedInAccount,
};
use kr_client::services::backup::ManagedBackupManifestService;
use kr_client::services::storage::ArchiveAnswer;
use kr_client::services::{
    BackupManifestService as _, HttpDeadlines, HttpService, ManagedSyncService, NullService,
    ServiceFuture, ServiceHttp, ServiceSigner, managed_response_limits,
};
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, ObjectSource, StagedObject, seal_archive,
    stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{MemoryStore, load_recovery_seed, store_recovery_seed};
use kr_protocol::archive::{
    BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN, BackupGenerationPublication,
    BackupGenerationPublicationPayload, BackupWriterRecord, BackupWriterRecordPayload,
    RecoveryBundle, RecoveryContext, RecoveryKit, TrustedWriter,
};
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{
    BackupEnableParams, BackupEnableResult, BackupHostKeys, BackupSetupState, BackupStatusResult,
    BackupStorageState, BackupStorageUnread,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, Moment, RESTORE_TOKEN, Served, TOKEN, serve};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::{INVOKE_KEY, MockRuntime, mock_builder, mock_context, noop_assets};
use tauri::webview::InvokeRequest;

#[path = "support/closing.rs"]
mod closing;

const SYNC_PATH: &str = "/api/sync/exchange";

/// Where the bundle's pages are served from, which is where the page's calls come from.
#[cfg(windows)]
const BUNDLE: &str = "http://tauri.localhost";
#[cfg(not(windows))]
const BUNDLE: &str = "tauri://localhost";

/* -------------------------------------------------------------------------- */
/* What a test stands in for                                                   */
/* -------------------------------------------------------------------------- */

/// A browser nobody opens: sign-in is not under test here.
struct NoBrowser;

impl Carrier for NoBrowser {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async { Err(Unavailable::NoReturningBrowser) })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        _url: String,
        _pending: &'a mut kr_client::services::account::PendingAuthorisation,
        _cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async { Ending::BrowserFailed })
    }
}

/// An account signed in to the service at `origin` with `scopes`, or none signed in.
async fn account(origin: &GatewayOrigin, scopes: Option<&[&str]>) -> Arc<Account> {
    account_named(origin, scopes, "account-one").await
}

/// [`account`], for the account whose subject is `subject`.
async fn account_named(
    origin: &GatewayOrigin,
    scopes: Option<&[&str]>,
    subject: &str,
) -> Arc<Account> {
    let service: Arc<dyn kr_client::services::account::AccountService> = Arc::new(NullService);
    let signed_in = Arc::new(SignedInAccount::new(
        Arc::clone(&service),
        Arc::new(MemoryStore::new()),
        Client::Desktop,
    ));
    if let Some(scopes) = scopes {
        signed_in
            .commit(
                IssuedGrant {
                    access_token: AccountToken::new(TOKEN).expect("a token"),
                    expires_in_seconds: 600,
                    refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
                    scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    subject: subject.to_owned(),
                },
                "a-nonce",
            )
            .await
            .expect("the sign-in is kept");
    }
    let deletion = companion_tauri::account::deletion::never_deleting(origin, &signed_in);
    Arc::new(Account::new(
        signed_in,
        service,
        origin.clone(),
        Arc::new(NoBrowser),
        Arc::new(|_| {}),
        deletion,
    ))
}

/// A token a fresh device presents, whatever it is asked for.
#[derive(Debug)]
struct Bearer(&'static str);

impl AccountTokenSource for Bearer {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = AccountToken::new(self.0);
        Box::pin(async move { token })
    }
}

/// A device's key, signing as an installation.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

/// What a device that holds nothing but the kit reads at the kit's locator: it presents the
/// restore token, derives the key from the seed and the origin and locator, and opens what it finds.
async fn read_with_only_the_kit(served: &Served, kit: &RecoveryKit) -> RecoveryBundle {
    let seed = RecoverySeed::from_kit(kit).expect("the kit's seed");
    let origin = GatewayOrigin::new(served.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport");
    let service = ManagedSyncService::new(
        origin,
        Arc::new(http),
        Arc::new(Installation(
            AuthorisationKeyPair::generate().expect("a key"),
        )),
    )
    .presenting(Arc::new(Bearer(RESTORE_TOKEN)), BACKUP_RESTORE_SCOPE);
    let directory = tempfile::tempdir().expect("a directory");
    let mut store = BundleStore::open(
        Arc::new(service),
        RecoveryContext {
            service_origin: kit.service_origins[0].clone(),
            bundle_locator: kit.bundle_locator.clone(),
        },
        directory.path(),
    )
    .expect("a store");
    store
        .fetch(&seed)
        .await
        .expect("the bundle opens with the kit")
}

/* -------------------------------------------------------------------------- */
/* This computer, and the application started on it                            */
/* -------------------------------------------------------------------------- */

/// The page's `recovery_cover_host` with a host double in place of the host on this computer. The
/// command the application registers reads its host from the application's connection to the host on
/// this computer, which this suite has none of, and returns what `Recovery::cover_host` answers
/// unchanged; this one does the same over the host the suite manages, so that the answer goes the
/// way the page's is sent and not into the case's hands.
#[tauri::command]
async fn cover_the_host_double(
    state: tauri::State<'_, AppState>,
    account: tauri::State<'_, AccountSlot>,
    host: tauri::State<'_, Arc<Host>>,
    replace: bool,
) -> companion_tauri::Result<HostCoverView> {
    state
        .recovery()?
        .cover_host(account.get().await?, &**host, replace)
        .await
}

/// What survives the application being closed: the service, the data directory and the secure
/// store, which holds the device's keys and, once recovery is on, the recovery seed.
struct Computer {
    served: Served,
    data: tempfile::TempDir,
    secrets: Arc<MemoryStore>,
}

impl Computer {
    async fn new() -> Self {
        Self {
            served: serve().await,
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
        }
    }

    /// This computer's identity: its keys, made the first time and read from the store after.
    fn identity(&self) -> DeviceIdentity {
        DeviceIdentity::in_store(Arc::clone(&self.secrets) as _).expect("the device's keys")
    }

    /// The origin of the sync service this computer can reach.
    fn origin(&self) -> GatewayOrigin {
        GatewayOrigin::new(self.served.origin()).expect("an origin")
    }

    /// The application, started over this computer's records, with `account` as its account.
    fn start(&self, account: Arc<Account>) -> Page {
        self.start_with(account, None)
    }

    /// As [`Self::start`], with `clients` as the application's clients of the sync service.
    fn start_with(
        &self,
        account: Arc<Account>,
        clients: Option<Arc<dyn companion_tauri::services::SyncServices>>,
    ) -> Page {
        let app = mock_builder()
            .manage(AppState::new())
            .manage(AccountSlot::ready(Arc::clone(&account)))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::sync_service_view,
                companion_tauri::commands::sync_service_set,
                companion_tauri::commands::account_deletion_status,
                companion_tauri::commands::recovery_view,
                companion_tauri::commands::recovery_turn_on,
                companion_tauri::commands::recovery_settle,
                companion_tauri::commands::recovery_save_kit,
                companion_tauri::commands::recovery_save_kit_qr,
                companion_tauri::commands::recovery_archives,
                companion_tauri::commands::recovery_export_offline,
                companion_tauri::commands::recovery_cover_host,
                cover_the_host_double,
            ])
            .build(mock_context(noop_assets()))
            .expect("an application on the mock runtime");
        if let Some(clients) = clients {
            app.state::<AppState>().sync_clients_replaced(clients);
        }
        // The functions the application's start calls, over this computer's records.
        companion_tauri::start_sync_service(app.handle(), self.data.path());
        companion_tauri::start_recovery(app.handle(), self.data.path(), &self.identity())
            .expect("recovery opens");
        let recovery = app
            .state::<AppState>()
            .recovery()
            .expect("recovery was opened");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Page {
            app,
            window,
            recovery,
            account,
            told: Mutex::new(Vec::new()),
        }
    }

    /// The application, with the sync service chosen to be the one this computer reaches and the
    /// account signed in to it with the right to write backup storage.
    async fn page(&self) -> Page {
        self.page_with(None).await
    }

    /// As [`Self::page`], with `clients` as the application's clients of the sync service.
    async fn page_with(
        &self,
        clients: Option<Arc<dyn companion_tauri::services::SyncServices>>,
    ) -> Page {
        let account = account(&self.origin(), Some(&RECOVERY_BACKUP_SCOPES)).await;
        let page = self.start_with(account, clients);
        page.call(
            "sync_service_set",
            json!({ "origin": self.served.origin() }),
        )
        .expect("the service is chosen");
        page
    }
}

/// The application's backend, called as the page calls it.
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    recovery: Arc<Recovery>,
    account: Arc<Account>,
    /// Everything the page was sent, as the text it received.
    told: Mutex<Vec<String>>,
}

impl Page {
    /// The mark of the account signed in on this page, at the sync service `computer` reaches.
    fn account_mark(&self, computer: &Computer) -> AccountMark {
        self.account
            .tokens()
            .signed_in_mark(computer.origin().as_str())
            .expect("the grant is read")
            .expect("an account is signed in")
    }

    /// Calls `command` with `body` through the invoke path, and returns the answer the page gets,
    /// or its refusal.
    fn call(&self, command: &str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        self.invoke(command, body)
    }

    /// As [`Self::call`], for a command this suite registers itself.
    fn invoke(&self, command: &str, body: Value) -> Result<Value, Value> {
        let answered = tokio::task::block_in_place(|| {
            tauri::test::get_ipc_response(
                &self.window,
                InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: INVOKE_KEY.to_owned(),
                },
            )
        });
        match answered {
            Ok(answer) => {
                let answer: Value = answer.deserialize().expect("an answer the page can read");
                self.told
                    .lock()
                    .expect("the record")
                    .push(answer.to_string());
                Ok(answer)
            }
            Err(refusal) => {
                self.told
                    .lock()
                    .expect("the record")
                    .push(refusal.to_string());
                Err(refusal)
            }
        }
    }

    /// The page's `recovery_cover_host`, over `host` in place of the host on this computer: the
    /// answer reaches the page as the invoke path sends it, and is among what the page was told.
    fn cover_host(&self, host: &Arc<Host>, replace: bool) -> Result<Value, Value> {
        // Managed once for the page's host; a second host is a second page.
        self.app.manage(Arc::clone(host));
        self.invoke("cover_the_host_double", json!({ "replace": replace }))
    }

    /// What recovery shows now.
    fn view(&self) -> Value {
        self.call("recovery_view", json!({}))
            .expect("the view is read")
    }

    /// The save dialog returns `path`.
    fn dialog_returns(&self, path: &Path) {
        self.app
            .state::<AppState>()
            .allow_export_to(path.to_path_buf());
    }

    /// Saves the kit to `recovery-kit.txt` in `directory`, over a file that is already there if
    /// there is one, and reads it back.
    fn kit(&self, directory: &Path) -> (std::path::PathBuf, RecoveryKit) {
        let path = directory.join("recovery-kit.txt");
        self.dialog_returns(&path);
        self.call(
            "recovery_save_kit",
            json!({ "path": path.to_string_lossy() }),
        )
        .expect("the kit is saved");
        let text = std::fs::read_to_string(&path).expect("the kit file");
        let kit = parse_kit(&text).expect("a kit");
        (path, kit)
    }

    /// Every text the page was sent.
    fn told(&self) -> String {
        self.told.lock().expect("the record").join("\n")
    }
}

/// The time on this machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

/// How a call to the host fails.
#[derive(Clone, Copy)]
enum HostFailure {
    /// The host refuses it in its own words, before it does anything.
    Refuses,
    /// The host carried it out and its reply could not be read.
    Unreadable,
}

/// What the service holds at a locator, read when the host is sent a setup.
type HeldBundle = Box<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

/// One way a host cannot be covered: its name, how the host is changed, and what the card shows.
type WayLeft = (&'static str, Box<dyn Fn(&Host)>, LeftView);

/// The host on this computer, as far as this suite needs it: what its status says, the calls it is
/// sent, and what it answers. The daemon itself is exercised against a real service and a real
/// bundle in the controller's suite; what is held here is what the application does around it.
struct Host {
    status: Mutex<BackupStatusResult>,
    keys: BackupHostKeys,
    /// The private halves of those keys, which a case that has the host publish an archive seals
    /// and signs with.
    writer: AuthorisationKeyPair,
    producer: StoredEnvelopeKeyPair,
    /// What the host answers to the setup, or nothing when the answer is lost.
    answer: Mutex<Option<BackupEnableResult>>,
    /// How the call fails instead of being answered, when it does.
    failure: Mutex<Option<HostFailure>>,
    /// The setups it was sent, and whether the service held exactly their bundle at that moment.
    enabled: Mutex<Vec<(BackupEnableParams, bool)>>,
    statuses: Mutex<usize>,
    /// Where the service's bundles are read from, to check the order of the calls.
    held: HeldBundle,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Host").finish_non_exhaustive()
    }
}

impl Host {
    /// A host that selects `service`, has a usable sign-in and is not set up.
    fn new(computer: &Computer, service: &str) -> Self {
        let writer = AuthorisationKeyPair::generate().expect("a key");
        let producer = StoredEnvelopeKeyPair::generate().expect("a key");
        let keys = BackupHostKeys {
            writer_key_id: writer.key_id(),
            writer_public_key: *writer.public(),
            producer_key_id: producer.key_id(),
            producer_public_key: *producer.public(),
        };
        let web = Arc::clone(computer.served.web());
        Self {
            status: Mutex::new(BackupStatusResult {
                service: kr_protocol::scalars::Nullable::some(service.to_owned()),
                sign_in: BackupSignIn::Usable,
                privacy_mode: false,
                setup: BackupSetupState::None {},
                keys: kr_protocol::scalars::Nullable::some(keys.clone()),
                storage: BackupStorageState::Unread {
                    why: BackupStorageUnread::NoToken,
                },
                last_attempt: kr_protocol::scalars::Nullable::null(),
            }),
            keys,
            writer,
            producer,
            answer: Mutex::new(None),
            failure: Mutex::new(None),
            enabled: Mutex::new(Vec::new()),
            statuses: Mutex::new(0),
            held: Box::new(move |locator| web.bundle(locator)),
        }
    }

    /// The host looks for the bundle at `served`, which a computer whose clients reach another
    /// service than the one it names writes to, in place of the computer's own.
    fn reading_bundles_at(mut self, served: &Served) -> Self {
        let web = Arc::clone(served.web());
        self.held = Box::new(move |locator| web.bundle(locator));
        self
    }

    /// Answers the setup the way a host that carried it out does.
    fn sets_up(&self) {
        *self.answer.lock().expect("answer") = Some(BackupEnableResult::Enabled {
            archive_id: kr_protocol::ids::ArchiveId::new(kr_protocol::scalars::Uuid::from_bytes(
                [0; 16],
            )),
            kit_fingerprint: String::new(),
            enabled_at_ms: TimestampMs::new(0),
        });
    }

    fn with_setup(&self, setup: BackupSetupState) {
        self.status.lock().expect("status").setup = setup;
    }

    fn setups_sent(&self) -> Vec<(BackupEnableParams, bool)> {
        self.enabled.lock().expect("enabled").clone()
    }
}

impl HostBackups for Host {
    fn status(&self) -> ServiceFuture<'_, BackupStatusResult> {
        *self.statuses.lock().expect("statuses") += 1;
        let status = self.status.lock().expect("status").clone();
        Box::pin(async move { Ok(status) })
    }

    fn enable<'a>(
        &'a self,
        params: &'a BackupEnableParams,
    ) -> ServiceFuture<'a, BackupEnableResult> {
        // The bundle is at the service, whole, before the host is asked: the host goes on only if
        // what is there is the bytes it is given.
        let there = (self.held)(&params.bundle_locator.to_string());
        self.enabled.lock().expect("enabled").push((
            params.clone(),
            there.as_deref() == Some(params.sealed_bundle.as_slice()),
        ));
        let answer = self.answer.lock().expect("answer").clone();
        let failure = *self.failure.lock().expect("failure");
        Box::pin(async move {
            match failure {
                Some(HostFailure::Refuses) => {
                    return Err(kr_client::ClientError::Host(
                        kr_protocol::error::ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this connection may not set backups up".to_owned(),
                        ),
                    ));
                }
                Some(HostFailure::Unreadable) => {
                    return Err(kr_client::ClientError::Cbor(kr_client::Shown::said(
                        "the host's reply could not be read",
                    )));
                }
                None => {}
            }
            match answer {
                Some(BackupEnableResult::Enabled { .. }) => Ok(BackupEnableResult::Enabled {
                    archive_id: params.archive_id,
                    kit_fingerprint: params.kit_fingerprint.clone(),
                    enabled_at_ms: params.enabled_at_ms,
                }),
                Some(other) => Ok(other),
                None => Err(kr_client::ClientError::Host(
                    kr_protocol::error::ProtocolError::new(
                        ErrorCode::OutcomeUnknown,
                        "the answer did not arrive".to_owned(),
                    ),
                )),
            }
        })
    }
}

/// A recovery recipient's public key that is not this computer's.
fn another_recipient() -> kr_protocol::scalars::StoredEnvelopeKey {
    *StoredEnvelopeKeyPair::generate().expect("a key").public()
}

/// How many writes of the bundle were sent to the service, whether or not it saw or acted on them.
fn writes_sent(computer: &Computer) -> usize {
    writes_at(&computer.served)
}

/// As [`writes_sent`], for the service `served`.
fn writes_at(served: &Served) -> usize {
    served
        .web()
        .arrived()
        .iter()
        .filter(|request| request.path == SYNC_PATH && request.body.get("exchange").is_some())
        .count()
}

/* -------------------------------------------------------------------------- */
/* The sync service setting                                                    */
/* -------------------------------------------------------------------------- */

/// The sync service is its own choice, the managed service until another is chosen, kept
/// across a restart, and an origin that is not one is refused with the earlier choice standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sync_service_is_the_managed_service_until_another_is_chosen() {
    let computer = Computer::new().await;
    let page = computer.start(account(&computer.origin(), None).await);

    let view = page.call("sync_service_view", json!({})).expect("the view");
    assert_eq!(
        view,
        json!({ "origin": ACCOUNT_ORIGIN, "host": "reach.kala.to", "is_default": true })
    );

    let chosen = page
        .call(
            "sync_service_set",
            json!({ "origin": " https://sync.example/ " }),
        )
        .expect("a self-hosted service is chosen");
    assert_eq!(
        chosen,
        json!({ "origin": "https://sync.example", "host": "sync.example", "is_default": false })
    );

    for typed in [
        "http://sync.example",
        "ftp://sync.example",
        "sync.example",
        "https://sync.example/path",
        "",
    ] {
        let refusal = page
            .call("sync_service_set", json!({ "origin": typed }))
            .expect_err("that is not an origin the setting admits");
        assert_eq!(refusal["code"], "INVALID_ARGUMENT", "{typed}");
        assert!(
            refusal["message"]
                .as_str()
                .is_some_and(|words| words.contains("sync service setting")),
            "the refusal names the setting: {refusal}"
        );
    }
    assert_eq!(
        page.call("sync_service_view", json!({})).expect("the view"),
        chosen,
        "a refused origin leaves the choice as it was"
    );

    let restarted = computer.start(account(&computer.origin(), None).await);
    assert_eq!(
        restarted
            .call("sync_service_view", json!({}))
            .expect("the view"),
        chosen,
        "the choice is kept"
    );
}

/// The setting is one origin in one file. Choices made together, as a person can by closing and
/// opening the account sheet during a slow save and choosing again, leave the file and this run
/// saying the same thing, so that a restart does not change the service in use.
#[test]
fn choices_made_together_leave_the_file_and_the_run_agreeing() {
    use companion_tauri::sync_service::SyncService;

    let directory = tempfile::tempdir().expect("a directory");
    for round in 0..40 {
        let service = Arc::new(SyncService::open(directory.path()));
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let service = Arc::clone(&service);
                std::thread::spawn(move || {
                    service
                        .set(&format!("https://sync-{round}-{n}.example"))
                        .expect("a choice is kept");
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("a choice finished");
        }
        assert_eq!(
            SyncService::open(directory.path()).origin(),
            service.origin(),
            "round {round}: a restart reads another service than the one in use"
        );
    }
}

/* -------------------------------------------------------------------------- */
/* Turning recovery on                                                         */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.18: turning recovery on puts the bundle at a locator of its own before any kit exists,
/// and the kit it hands over opens that bundle on a device that holds nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_recovery_on_puts_the_bundle_at_the_service_and_hands_over_a_kit() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    let host = computer.origin().as_str().replace("http://", "");
    let service = json!({ "origin": computer.served.origin(), "host": host, "is_default": false });

    assert_eq!(
        page.view(),
        json!({ "sync_service": service, "state": "off", "kept_at": null, "blocker": null })
    );
    assert_eq!(
        page.call("recovery_turn_on", json!({}))
            .expect("recovery is turned on"),
        json!({ "sync_service": service, "state": "on", "kept_at": host, "blocker": null })
    );

    // The seed is in this computer's secure store, which is where the kit's seed comes from.
    assert!(
        load_recovery_seed(&*computer.secrets, SEED_SCOPE)
            .expect("the store is read")
            .is_some()
    );

    // One write reached the service, under the account's token, naming no revision to replace.
    let web = computer.served.web();
    let arrived = web.arrived();
    assert_eq!(arrived.len(), 1, "{arrived:?}");
    assert_eq!(arrived[0].path, SYNC_PATH);
    assert_eq!(arrived[0].token.as_deref(), Some(TOKEN));
    let write = &arrived[0].body["exchange"];
    assert_eq!(write["kind"], "recovery_bundle");
    assert_eq!(write["expected_revision"], Value::Null);

    // The kit names that locator and that service, and a fresh device opens the bundle with it.
    let out = tempfile::tempdir().expect("a directory");
    let (path, kit) = page.kit(out.path());
    assert_eq!(
        kit.bundle_locator,
        write["locator"].as_str().expect("a locator")
    );
    assert_eq!(kit.service_origins, [computer.served.origin().to_owned()]);
    let (sequence, _) = web
        .bundle_write(&kit.bundle_locator)
        .expect("the bundle is held");
    assert_eq!(sequence, 1);
    let bundle = read_with_only_the_kit(&computer.served, &kit).await;
    assert_eq!(bundle.revision.get(), 1);
    assert!(bundle.trusted_writers.is_empty());

    // The seed and the locator are written where the person chose, readable by them alone, and the
    // page was told neither.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("the file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the kit is private to its owner");
    }
    let told = page.told();
    for secret in std::fs::read_to_string(&path)
        .expect("the kit file")
        .lines()
        .filter_map(|line| line.split_once(": ").map(|(_, value)| value.to_owned()))
        .filter(|value| value.len() > 20 && !value.starts_with("http"))
    {
        assert!(!told.contains(&secret), "the page was sent part of the kit");
    }
}

/// A factory of sync clients of a fork, in the place of the managed ones: it records each ask and
/// answers with the client of a sync service of its own, whatever origin is asked for.
#[derive(Debug)]
struct Recording {
    service: GatewayOrigin,
    key: AuthorisationKeyPair,
    asked: Mutex<Vec<(String, bool)>>,
}

impl Recording {
    fn at(service: &Served, key: AuthorisationKeyPair) -> Arc<Self> {
        Arc::new(Self {
            service: GatewayOrigin::new(service.origin()).expect("an origin"),
            key,
            asked: Mutex::new(Vec::new()),
        })
    }

    /// The fork's client, after noting that `origin` was asked for.
    fn answer(&self, origin: &GatewayOrigin, presenting: bool) -> ManagedSyncService {
        self.asked
            .lock()
            .expect("the record")
            .push((origin.as_str().to_owned(), presenting));
        let http = HttpService::with(
            self.service.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport");
        ManagedSyncService::new(
            self.service.clone(),
            Arc::new(http),
            Arc::new(Installation(self.key.clone())),
        )
    }
}

impl companion_tauri::services::SyncServices for Recording {
    fn installation(
        &self,
        origin: &GatewayOrigin,
    ) -> companion_tauri::error::Result<Arc<dyn kr_client::services::SharedSyncService>> {
        Ok(Arc::new(self.answer(origin, false)))
    }

    fn presenting(
        &self,
        origin: &GatewayOrigin,
        tokens: Arc<dyn kr_client::services::AccountTokenSource>,
        scope: &'static str,
    ) -> companion_tauri::error::Result<Arc<dyn kr_client::services::SharedSyncService>> {
        Ok(Arc::new(
            self.answer(origin, true).presenting(tokens, scope),
        ))
    }
}

/// KR-REQ-17.14: recovery's bundle store reaches the sync service through the clients the
/// application was given, and at the origin its record names. The bundle is written through the
/// client it is given: a fork's client of a service of its own receives the write and the service
/// the setting names receives none. A record made while the setting named one service keeps asking
/// for that service after the setting names another; only a record made now reads the setting.
/// Going on with an unkept record, settling a write whose answer was lost and covering the host
/// are held to the same by
/// `recovery_goes_on_with_an_unkept_record_at_its_own_service_when_the_setting_names_another` and
/// `a_lost_write_is_settled_and_the_host_covered_at_the_records_service_when_the_setting_names_another`.
/// The reads of the archive list and the offline copy are made through the clients of
/// `AccountSource`, not these, and are held to the record's service by the cases beside them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_asks_its_clients_for_the_service_its_record_names() {
    let computer = Computer::new().await;
    let fork_service = serve().await;
    let recording = Recording::at(
        &fork_service,
        computer.identity().keys.authorisation.clone(),
    );
    let page = computer.page_with(Some(Arc::clone(&recording) as _)).await;
    let ours = computer.served.origin().to_owned();

    page.call("recovery_turn_on", json!({}))
        .expect("recovery is turned on");
    let asked = recording.asked.lock().expect("the record").clone();
    assert!(
        !asked.is_empty(),
        "turning recovery on asked the clients it was given"
    );
    assert!(
        asked
            .iter()
            .all(|(origin, presenting)| *origin == ours && *presenting),
        "{asked:?}: the bundle is written at the chosen service, presenting the account"
    );
    let arrived = fork_service.web().arrived();
    assert_eq!(arrived.len(), 1, "{arrived:?}");
    assert_eq!(arrived[0].path, SYNC_PATH);
    assert_eq!(arrived[0].token.as_deref(), Some(TOKEN));
    assert_eq!(
        arrived[0].body["exchange"]["kind"], "recovery_bundle",
        "the bundle was written through the client the application was given"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "the service the setting names received none"
    );

    // The setting now names another service. The record still names the first, and every ask that
    // follows is for the first.
    page.call(
        "sync_service_set",
        json!({ "origin": "https://other.example" }),
    )
    .expect("another service is chosen");
    let before = recording.asked.lock().expect("the record").len();
    page.call("recovery_view", json!({}))
        .expect("recovery reads its record");
    let asked = recording.asked.lock().expect("the record").clone();
    assert!(
        asked.len() > before,
        "reading the record asked for its client"
    );
    assert!(
        asked.iter().all(|(origin, _)| *origin == ours),
        "{asked:?}: nothing was asked for the service the setting names now"
    );
}

/// The kit holds the recovery seed. A file the person chose that already exists, whatever its mode
/// or access list and however long its earlier content, ends as the kit alone and readable by them
/// alone.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kit_saved_over_an_existing_file_leaves_that_file_private_and_whole() {
    use std::os::unix::fs::PermissionsExt as _;

    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({}))
        .expect("recovery is turned on");

    let out = tempfile::tempdir().expect("a directory");
    let path = out.path().join("recovery-kit.txt");
    std::fs::write(&path, "earlier words ".repeat(2000)).expect("an earlier file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("a wide mode");

    // On macOS a mode does not say who may read a file: an access list can name another account,
    // and the file the person chose may carry one.
    #[cfg(target_os = "macos")]
    exacl::setfacl(
        &[&path],
        &[exacl::AclEntry::allow_group(
            "everyone",
            exacl::Perm::READ,
            None,
        )],
        None,
    )
    .expect("an access list on the earlier file");

    page.kit(out.path());

    let text = std::fs::read_to_string(&path).expect("the kit file");
    assert!(
        !text.contains("earlier words"),
        "none of the earlier content is left in the file"
    );
    #[cfg(target_os = "macos")]
    assert!(
        exacl::getfacl(&path, None)
            .expect("the access list")
            .is_empty(),
        "no other account is named as able to read the kit"
    );
    let mode = std::fs::metadata(&path)
        .expect("the file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the kit is private to its owner");
}

/// KR-REQ-20.15: the host's writer is named in this computer's bundle, and the bundle has landed at
/// the service, before the host is asked to set its backups up under this computer's recovery; the
/// host is sent this computer's recipient and the very bytes that are at the service, and the
/// computer says the host is covered only after the host said it is set up. A fresh device holding
/// only the kit then reads the writer, the producer and the archive from the bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_is_named_in_the_bundle_before_it_is_set_up_under_this_computers_recovery() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    let host = Host::new(&computer, computer.served.origin());
    host.sets_up();

    let covered = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect("the host is covered");
    let seed = RecoverySeed::from_kit(&kit).expect("the kit's seed");
    let recipient = *seed.recipient().expect("a recipient").public();
    let fingerprint = kr_client::recovery::kit_fingerprint(&recipient);
    assert_eq!(
        covered,
        HostCoverView::Covered {
            kit_fingerprint: fingerprint.clone(),
            replaced: None,
            already: false
        }
    );

    // The host was asked once, with this computer's recipient and the bundle that was at the
    // service when it was asked.
    let sent = host.setups_sent();
    assert_eq!(sent.len(), 1);
    let (params, bundle_was_there) = &sent[0];
    assert!(
        bundle_was_there,
        "the bundle landed before the host was asked"
    );
    assert_eq!(params.recovery_public_key, recipient);
    assert_eq!(params.kit_fingerprint, fingerprint);
    assert_eq!(params.bundle_locator.to_string(), kit.bundle_locator);
    assert!(!params.replace);
    assert_eq!(params.writer_key_id, host.keys.writer_key_id);
    assert_eq!(params.producer_key_id, host.keys.producer_key_id);

    // A device that holds only the kit reads what the host's archive needs from the bundle.
    let bundle = read_with_only_the_kit(&computer.served, &kit).await;
    assert_eq!(bundle.revision.get(), 2);
    assert!(bundle.trusted_writers.iter().any(|held| {
        held.writer_key_id == host.keys.writer_key_id
            && held.signing_key == host.keys.writer_public_key
    }));
    assert!(bundle.trusted_producers.iter().any(|held| {
        held.sender_key_id == host.keys.producer_key_id
            && held.stored_envelope_key == host.keys.producer_public_key
    }));
    assert!(
        bundle
            .collections
            .iter()
            .any(|held| held.archive_id == params.archive_id),
        "the bundle names the archive the host will make"
    );
}

/// KR-REQ-20.15: a host that cannot be covered as it stands is left as it is, and nothing is
/// declared. Nothing reaches the service and the host is asked nothing more than its status, unless
/// a replacement is asked for by name over a host set up under another kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_cannot_be_covered_as_it_stands_is_left_alone_and_nothing_is_declared() {
    let computer = Computer::new().await;

    // Recovery is not on: the host is not asked, and nothing is written.
    let page = computer.page().await;
    let host = Host::new(&computer, computer.served.origin());
    let refused = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("recovery is off");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    assert_eq!(*host.statuses.lock().expect("statuses"), 0);
    assert_eq!(writes_sent(&computer), 0);

    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    let recipient = *RecoverySeed::from_kit(&kit)
        .expect("the kit's seed")
        .recipient()
        .expect("a recipient")
        .public();
    let ours = kr_client::recovery::kit_fingerprint(&recipient);
    let before = writes_sent(&computer);
    let left = |why: LeftView| HostCoverView::Left { why };

    // The page's command, with no host connected to this application: nothing is sent anywhere.
    let unreachable = page
        .call("recovery_cover_host", json!({ "replace": false }))
        .expect_err("there is no host to cover");
    assert_eq!(unreachable["code"], "HOST_NOT_CONFIGURED");
    assert_eq!(writes_sent(&computer), before);

    // Each way the host cannot be covered as it stands.
    let ways: Vec<WayLeft> = vec![
        (
            "no service",
            Box::new(|host| {
                host.status.lock().expect("status").service =
                    kr_protocol::scalars::Nullable::null();
            }),
            LeftView::NoService,
        ),
        (
            "another service",
            Box::new(|host| {
                host.status.lock().expect("status").service =
                    kr_protocol::scalars::Nullable::some("https://elsewhere.example".to_owned());
            }),
            LeftView::OtherService {
                host: "elsewhere.example".to_owned(),
            },
        ),
        (
            "signed out",
            Box::new(|host| {
                host.status.lock().expect("status").sign_in = BackupSignIn::SignedOut;
            }),
            LeftView::SignIn {
                sign_in: BackupSignIn::SignedOut,
            },
        ),
        (
            "a setup under way",
            Box::new(|host| {
                host.with_setup(BackupSetupState::InProgress {
                    kit_fingerprints: vec!["AAAA-BBBB".to_owned()],
                });
            }),
            LeftView::SetupUnderWay {
                kit_fingerprints: vec!["AAAA-BBBB".to_owned()],
            },
        ),
        (
            "set up under this computer's recovery, with a sign-in that is not renewed",
            Box::new({
                let ours = ours.clone();
                move |host| {
                    host.with_setup(BackupSetupState::Committed {
                        archive_id: kr_protocol::ids::ArchiveId::new(
                            kr_protocol::scalars::Uuid::from_bytes([8; 16]),
                        ),
                        kit_fingerprint: ours.clone(),
                        recovery_public_key: recipient,
                        enabled_at_ms: TimestampMs::new(1),
                        unusable: kr_protocol::scalars::Nullable::null(),
                    });
                    host.status.lock().expect("status").sign_in = BackupSignIn::NotRenewed;
                }
            }),
            LeftView::SignIn {
                sign_in: BackupSignIn::NotRenewed,
            },
        ),
        (
            // A fingerprint is 40 bits of the recipient's key and tells a kit from another by
            // eye; the key decides.
            "another recipient under this computer's fingerprint",
            Box::new({
                let ours = ours.clone();
                move |host| {
                    host.with_setup(BackupSetupState::Committed {
                        archive_id: kr_protocol::ids::ArchiveId::new(
                            kr_protocol::scalars::Uuid::from_bytes([7; 16]),
                        ),
                        kit_fingerprint: ours.clone(),
                        recovery_public_key: another_recipient(),
                        enabled_at_ms: TimestampMs::new(1),
                        unusable: kr_protocol::scalars::Nullable::null(),
                    });
                }
            }),
            LeftView::OtherKit {
                host_fingerprint: ours.clone(),
            },
        ),
        (
            "another kit",
            Box::new(|host| {
                host.with_setup(BackupSetupState::Committed {
                    archive_id: kr_protocol::ids::ArchiveId::new(
                        kr_protocol::scalars::Uuid::from_bytes([9; 16]),
                    ),
                    kit_fingerprint: "CCCC-DDDD".to_owned(),
                    recovery_public_key: another_recipient(),
                    enabled_at_ms: TimestampMs::new(1),
                    unusable: kr_protocol::scalars::Nullable::null(),
                });
            }),
            LeftView::OtherKit {
                host_fingerprint: "CCCC-DDDD".to_owned(),
            },
        ),
    ];
    for (name, arrange, why) in ways {
        let host = Host::new(&computer, computer.served.origin());
        host.sets_up();
        arrange(&host);
        let answer = page
            .recovery
            .cover_host(&page.account, &host, false)
            .await
            .unwrap_or_else(|refused| panic!("{name}: {refused:?}"));
        assert_eq!(answer, left(why), "{name}");
        assert!(
            host.setups_sent().is_empty(),
            "{name}: the host was not asked"
        );
        assert_eq!(
            writes_sent(&computer),
            before,
            "{name}: nothing was written"
        );
    }

    // A replacement asked for by name over a host set up under another kit goes ahead, under a new
    // archive, and says which kit it replaced.
    let host = Host::new(&computer, computer.served.origin());
    host.sets_up();
    let earlier = kr_protocol::ids::ArchiveId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
    host.with_setup(BackupSetupState::Committed {
        archive_id: earlier,
        kit_fingerprint: "CCCC-DDDD".to_owned(),
        recovery_public_key: another_recipient(),
        enabled_at_ms: TimestampMs::new(1),
        unusable: kr_protocol::scalars::Nullable::null(),
    });
    let replaced = page
        .recovery
        .cover_host(&page.account, &host, true)
        .await
        .expect("replaced");
    assert!(matches!(
        replaced,
        HostCoverView::Covered { replaced: Some(ref kit), already: false, .. } if kit == "CCCC-DDDD"
    ));
    let sent = host.setups_sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].0.replace);
    assert_ne!(sent[0].0.archive_id, earlier, "a new archive");

    // A host that declines after the bundle is written is left as it is, nothing is declared, and
    // the bundle goes back to naming the archives it named: a restore would list an archive the
    // host never made, and ask which to open.
    let archives_named = read_with_only_the_kit(&computer.served, &kit)
        .await
        .collections
        .len();
    let host = Host::new(&computer, computer.served.origin());
    *host.answer.lock().expect("answer") = Some(BackupEnableResult::Declined {
        cause: kr_protocol::backup_setup::BackupEnableCause::BundleConflict {},
    });
    let declined = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect("an answer");
    assert!(matches!(
        declined,
        HostCoverView::Left {
            why: LeftView::Declined { .. }
        }
    ));
    assert_eq!(host.setups_sent().len(), 1, "the host was asked");
    assert_eq!(
        read_with_only_the_kit(&computer.served, &kit)
            .await
            .collections
            .len(),
        archives_named,
        "no archive the host declined to make is named"
    );

    // A host that refuses the call in its own words recorded nothing either, and the error is the
    // host's, not an outcome that is unknown.
    let host = Host::new(&computer, computer.served.origin());
    *host.failure.lock().expect("failure") = Some(HostFailure::Refuses);
    let refused = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("the host refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    assert_eq!(
        read_with_only_the_kit(&computer.served, &kit)
            .await
            .collections
            .len(),
        archives_named,
        "no archive the host refused to make is named"
    );

    // A reply that could not be read may follow a setup that was carried out: the archive stays
    // named, and the error says the outcome is not known, so that a repeat finds the setup.
    let host = Host::new(&computer, computer.served.origin());
    *host.failure.lock().expect("failure") = Some(HostFailure::Unreadable);
    let unknown = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("the reply was unreadable");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_eq!(
        read_with_only_the_kit(&computer.served, &kit)
            .await
            .collections
            .len(),
        archives_named + 1,
        "the archive the host may have made stays named"
    );

    // A failure before the host is asked leaves the bundle as it was: the service fails the read of
    // the bundle that follows the write which named the archive.
    let before_asking = read_with_only_the_kit(&computer.served, &kit)
        .await
        .collections
        .len();
    let host = Host::new(&computer, computer.served.origin());
    host.sets_up();
    computer.served.web().fail(SYNC_PATH, 3, Moment::Before);
    let stopped = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("the sealed bytes could not be read");
    drop(stopped);
    assert!(host.setups_sent().is_empty(), "the host was not asked");
    assert_eq!(
        read_with_only_the_kit(&computer.served, &kit)
            .await
            .collections
            .len(),
        before_asking,
        "no archive the host never heard of is named"
    );
}

/// KR-REQ-20.15: a write of the bundle whose answer is lost declares nothing and keeps the host
/// from being asked, holds back every other write until it is settled, and a restart keeps that;
/// and a host that does not say how its setup ended is no evidence either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_whose_answer_was_lost_blocks_the_next_until_it_is_settled() {
    for (moment, landed) in [(Moment::After, true), (Moment::Before, false)] {
        let computer = Computer::new().await;
        let page = computer.page().await;
        page.call("recovery_turn_on", json!({})).expect("on");
        let out = tempfile::tempdir().expect("a directory");
        let (_, kit) = page.kit(out.path());
        let host = Host::new(&computer, computer.served.origin());
        host.sets_up();

        // The bundle write is the second request to the route: a read, then the write.
        computer.served.web().fail(SYNC_PATH, 2, moment);
        let lost = page
            .recovery
            .cover_host(&page.account, &host, false)
            .await
            .expect_err("no evidence without an answer");
        assert_eq!(lost.code, ErrorCode::OutcomeUnknown, "{moment:?}");
        assert!(
            host.setups_sent().is_empty(),
            "{moment:?}: the host is not asked"
        );
        assert_eq!(page.view()["state"], "unsettled", "{moment:?}");

        // The application is closed and started again: the lost write is still outstanding.
        drop(page);
        let page = computer.page().await;
        assert_eq!(
            page.view()["state"],
            "unsettled",
            "{moment:?}, after a restart"
        );

        if !landed {
            // A read that finds the old bundle settles nothing, and nothing more is written.
            let before = writes_sent(&computer);
            let blocked = page
                .recovery
                .cover_host(&page.account, &host, false)
                .await
                .expect_err("a write waits for the lost one");
            assert_eq!(blocked.code, ErrorCode::PermissionDenied, "{moment:?}");
            assert_eq!(
                writes_sent(&computer),
                before,
                "{moment:?}: nothing was sent"
            );
            assert!(host.setups_sent().is_empty());
        }

        let settled = page
            .call("recovery_settle", json!({}))
            .expect("the lost write is settled");
        assert_eq!(settled["state"], "on", "{moment:?}");

        // Settled, the next try goes: the host is asked with the bundle that is at the service.
        let covered = page
            .recovery
            .cover_host(&page.account, &host, false)
            .await
            .expect("the host is covered");
        assert!(
            matches!(covered, HostCoverView::Covered { .. }),
            "{moment:?}"
        );
        let sent = host.setups_sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1, "{moment:?}: the bundle was at the service");
        let bundle = read_with_only_the_kit(&computer.served, &kit).await;
        assert!(
            bundle
                .trusted_writers
                .iter()
                .any(|held| held.writer_key_id == host.keys.writer_key_id)
        );
    }

    // A host that carried the setup out and did not say so is no evidence: the answer is unknown.
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let silent = Host::new(&computer, computer.served.origin());
    let unknown = page
        .recovery
        .cover_host(&page.account, &silent, false)
        .await
        .expect_err("no answer from the host");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_eq!(silent.setups_sent().len(), 1, "the host was asked once");
}

/// The QR code a saved kit draws, as a viewer shows it and a scanner reads it: the whole file is
/// rendered by an SVG renderer, and a QR decoder that shares nothing with the encoder reads the
/// pixels. Returns what the decoder made of it, the kit text, and how wide the file draws, in
/// pixels at 96 to the inch.
fn scanned(svg: &str) -> (rqrr::MetaData, String, f32) {
    let tree = resvg::usvg::Tree::from_str(svg, &resvg::usvg::Options::default())
        .expect("a viewer opens the file");
    let drawn = tree.size().width();
    let scale = 1200.0 / drawn;
    let width = (drawn * scale).ceil() as u32;
    let height = (tree.size().height() * scale).ceil() as u32;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height).expect("a bitmap");
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
            let pixel = pixmap.pixel(x as u32, y as u32).expect("a pixel");
            // The file draws an opaque page, so the colour is what a person would see.
            u8::try_from(
                (u32::from(pixel.red()) * 30
                    + u32::from(pixel.green()) * 59
                    + u32::from(pixel.blue()) * 11)
                    / 100,
            )
            .expect("a grey")
        });
    let grids = image.detect_grids();
    assert_eq!(grids.len(), 1, "one code is drawn");
    let (meta, text) = grids[0].decode().expect("the code decodes");
    (meta, text, drawn)
}

/// KR-REQ-20.18: the kit saves as a QR code that scans back to the kit's own text, at the error
/// correction a printed copy needs, in a file only its owner reads; and nothing is drawn while
/// recovery is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kit_saved_as_a_qr_code_scans_back_to_the_kit_and_is_private() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    let out = tempfile::tempdir().expect("a directory");
    let path = out.path().join("kit.svg");
    page.dialog_returns(&path);
    let refused = page
        .call(
            "recovery_save_kit_qr",
            json!({ "path": path.to_string_lossy() }),
        )
        .expect_err("no kit while recovery is off");
    assert_eq!(refused["code"], "PERMISSION_DENIED");
    assert!(!path.exists());

    page.call("recovery_turn_on", json!({})).expect("on");
    let (_, kit) = page.kit(out.path());
    page.dialog_returns(&path);
    page.call(
        "recovery_save_kit_qr",
        json!({ "path": path.to_string_lossy() }),
    )
    .expect("the QR code is saved");
    let svg = std::fs::read_to_string(&path).expect("the file");
    let (meta, text, drawn) = scanned(&svg);
    assert_eq!(meta.ecc_level, 3, "error correction level Q");
    // A printed copy has a size to print at: more than two centimetres and less than a sheet.
    assert!(
        (76.0..=800.0).contains(&drawn),
        "the file draws {drawn} pixels wide"
    );
    assert_eq!(
        text,
        kr_client::recovery::render_kit(&kit)
            .expect("the kit's text")
            .to_string(),
        "a scanner reads the document a person could have typed"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("the file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the code is private to its owner");
    }
    // The page was told where, and nothing the code holds.
    assert!(!page.told().contains(&kit.bundle_locator));
}

/// KR-REQ-20.18: the bundle exports alone as a file of ciphertext, in the owner-only mode, that is
/// the bundle as the service holds it; the archives the bundle names are listed; and a request for
/// an archive the bundle does not name, or while recovery is off, writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bundle_exports_alone_as_a_private_file_of_ciphertext() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    let out = tempfile::tempdir().expect("a directory");
    let path = out.path().join("bundle.krexport");
    page.dialog_returns(&path);
    let refused = page
        .call(
            "recovery_export_offline",
            json!({ "path": path.to_string_lossy(), "archive": null }),
        )
        .expect_err("recovery is off");
    assert_eq!(refused["code"], "PERMISSION_DENIED");
    assert!(!path.exists());

    page.call("recovery_turn_on", json!({})).expect("on");
    let (_, kit) = page.kit(out.path());
    assert_eq!(
        page.call("recovery_archives", json!({}))
            .expect("the archives"),
        json!([]),
        "a bundle that names no archive lists none"
    );
    page.dialog_returns(&path);
    let saved = page
        .call(
            "recovery_export_offline",
            json!({ "path": path.to_string_lossy(), "archive": null }),
        )
        .expect("the bundle is exported");
    assert_eq!(saved["archive_id"], Value::Null);
    let bytes = std::fs::read(&path).expect("the file");
    assert_eq!(saved["bytes"], bytes.len());
    let export =
        kr_client::recovery::OfflineExport::from_canonical_slice(&bytes).expect("an export");
    assert_eq!(
        Some(export.encrypted_bundle.as_slice().to_vec()),
        computer.served.web().bundle(&kit.bundle_locator),
        "the bundle as the service holds it"
    );
    assert!(export.archive.0.is_none());
    let seed = RecoverySeed::from_kit(&kit).expect("the seed");
    let kit_text = kr_client::recovery::render_kit(&kit)
        .expect("the kit's text")
        .to_string();
    let seed_line = kit_text
        .lines()
        .find_map(|line| line.strip_prefix("seed: "))
        .expect("a seed line");
    assert!(
        !bytes
            .windows(seed_line.len())
            .any(|window| window == seed_line.as_bytes()),
        "the export holds no kit text"
    );
    drop(seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("the file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the export is private to its owner");
    }

    // An archive the bundle does not name writes nothing.
    let other = out.path().join("other.krexport");
    page.dialog_returns(&other);
    let unlisted = page
        .call(
            "recovery_export_offline",
            json!({ "path": other.to_string_lossy(), "archive": "00000000-0000-4000-8000-000000000099" }),
        )
        .expect_err("not listed");
    assert_eq!(unlisted["code"], "PERMISSION_DENIED");
    assert!(!other.exists());
    let malformed = page
        .call(
            "recovery_export_offline",
            json!({ "path": other.to_string_lossy(), "archive": "not an identifier" }),
        )
        .expect_err("not an identifier");
    assert_eq!(malformed["code"], "INVALID_ARGUMENT");
}

/// The forms in which a document could carry `key`, as the bytes to look for in it: the bytes
/// themselves and their hexadecimal in either case; and base64 in either alphabet, which puts three
/// bytes in four characters, so that the characters standing for the key's whole groups of three are
/// the same wherever the key lies in a longer value. Which groups those are depends on where the key
/// starts, so each of the three ways it can start is looked for.
fn forms_of(key: &[u8]) -> Vec<(String, Vec<u8>)> {
    let hex = |upper: bool| -> Vec<u8> {
        key.iter()
            .map(|byte| {
                if upper {
                    format!("{byte:02X}")
                } else {
                    format!("{byte:02x}")
                }
            })
            .collect::<String>()
            .into_bytes()
    };
    let mut forms = vec![
        ("as bytes".to_owned(), key.to_vec()),
        ("in lower-case hexadecimal".to_owned(), hex(false)),
        ("in upper-case hexadecimal".to_owned(), hex(true)),
    ];
    for start in 0..3 {
        let whole = &key[start..start + (key.len() - start) / 3 * 3];
        let url = kr_protocol::scalars::to_base64url(whole);
        forms.push((
            format!("in base64url from its byte {start}"),
            url.clone().into_bytes(),
        ));
        forms.push((
            format!("in base64 from its byte {start}"),
            url.replace('-', "+").replace('_', "/").into_bytes(),
        ));
    }
    forms
}

/// How `key` is carried in `haystack`, in a form [`forms_of`] names or as serde writes a list of
/// bytes, a list of numbers, with any space between its items; nothing when it is not.
fn carried_in(haystack: &[u8], key: &[u8]) -> Option<String> {
    let found = |needle: &[u8], haystack: &[u8]| {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    };
    if let Some((form, _)) = forms_of(key)
        .into_iter()
        .find(|(_, needle)| found(needle, haystack))
    {
        return Some(form);
    }
    let compact: Vec<u8> = haystack
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let numbers = key
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    found(&numbers, &compact).then(|| "as a list of numbers".to_owned())
}

/// The X25519 private key of a stored-envelope or notification-preview pair, made from its seed as
/// libsodium's `crypto_box_seed_keypair` makes it: the first half of the seed's SHA-512.
fn x25519_secret_of(seed: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha512::digest(seed)[..32].to_vec()
}

/// A generation of an archive as the host's producer makes one, put at the service: sealed for the
/// recovery recipient `seed` derives and signed by the host's writer, which this computer's own key
/// enrols; its objects stored under the account; the publication sent by the writer.
struct PublishedGeneration {
    publication: BackupGenerationPublication,
    manifest_object: kr_protocol::ids::BackupObjectId,
    objects: Vec<kr_protocol::ids::BackupObjectId>,
}

async fn publish_generation(
    computer: &Computer,
    seed: &RecoverySeed,
    host: &Host,
    archive: kr_protocol::ids::ArchiveId,
    members: &[(&str, Vec<u8>)],
) -> PublishedGeneration {
    use kr_protocol::ids::{BackupGeneration, BackupObjectId, BackupWriterRevision, DeviceId};
    use kr_protocol::scalars::Uuid;

    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            computer.origin(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    let manifest_as = |key: AuthorisationKeyPair| {
        ManagedBackupManifestService::new(
            computer.origin(),
            Arc::clone(&http),
            Arc::new(Installation(key)),
        )
        .presenting(Arc::new(Bearer(TOKEN)))
    };

    // This computer's key enrols the host's writer, which the bundle already names.
    let owner = computer.identity().keys.authorisation.clone();
    let payload = BackupWriterRecordPayload {
        archive_id: archive,
        writer: TrustedWriter {
            writer_key_id: host.writer.key_id(),
            signing_key: *host.writer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        },
        writer_revision: BackupWriterRevision::new(1),
        owner_key_id: owner.key_id(),
        enrolled_at_ms: TimestampMs::new(1_000),
    };
    let signature = sign(
        &owner,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_WRITER_DOMAIN,
            payload.signing_input().expect("an enrolment input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    manifest_as(owner)
        .enrol(&BackupWriterRecord { payload, signature })
        .await
        .expect("the service enrols the writer");

    // The generation, sealed for the recovery recipient.
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add_recovery(&seed.recipient().expect("a recipient")));
    let staged: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(at, (name, plaintext))| {
            stage_object(
                &ObjectSource {
                    object_id: BackupObjectId::new(Uuid::from_bytes(
                        [0x20 + u8::try_from(at).expect("few members"); 16],
                    )),
                    filename: name,
                    plaintext,
                },
                recipients.rotation(),
            )
            .expect("a staged object")
        })
        .collect();
    let manifest_object = BackupObjectId::new(Uuid::from_bytes([0xf0; 16]));
    let sealed = seal_archive(
        &host.writer,
        &host.producer,
        &recipients,
        &ArchivePlan {
            archive_id: archive,
            backup_generation: BackupGeneration::new(1),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            manifest_object_id: manifest_object,
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        &staged,
    )
    .expect("a sealed archive");
    let web = computer.served.web();
    for object in &staged {
        web.put_object(
            &archive.to_string(),
            &object.object_id().to_string(),
            ACCOUNT,
            object.bytes().to_vec(),
        );
    }
    web.put_object(
        &archive.to_string(),
        &manifest_object.to_string(),
        ACCOUNT,
        sealed.encrypted_manifest.clone(),
    );

    // The writer publishes it.
    let payload = BackupGenerationPublicationPayload {
        descriptor: sealed.descriptor.clone(),
        writer_key_id: host.writer.key_id(),
        published_at_ms: TimestampMs::new(5_000),
    };
    let signature = sign(
        &host.writer,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    let publication = BackupGenerationPublication { payload, signature };
    let answer = manifest_as(host.writer.clone())
        .publish(&publication)
        .await
        .expect("the service answers the publication");
    assert!(
        matches!(answer, ArchiveAnswer::Done(_)),
        "the service stored the publication"
    );
    PublishedGeneration {
        publication,
        manifest_object,
        objects: staged.iter().map(StagedObject::object_id).collect(),
    }
}

/// KR-REQ-20.17, what this case reads of the companion's outputs and no more: the kit file saved as
/// text and the seed it gives; the QR code file, the text a scanner reads from it and the seed that
/// text gives; the offline export file of the bundle alone (`archive: null`) and the one of an
/// archive made for the host double and published at the service, as bytes; the parameters of the
/// setup call a host double is sent when the computer covers it, as JSON; the sealed bundle in the
/// setup and the one in the bundle export, each opened with the kit alone (and each equal, byte for
/// byte, to the bundle the service holds); the bundle as the service holds it, opened with the kit
/// alone once the host is covered (so it names the host's public keys); the view of the host's
/// cover that the page is sent; the answers to the commands the page was called with in this case;
/// and every request the service was sent in it (the computer's, and the case's own reads and
/// publication), each body, the content beside it and the token. None of them holds a private key
/// this computer keeps in the secure store beside the recovery seed: the reusable endpoint
/// (transport) key, the control-signing (authorisation) key, and the stored envelope and
/// notification preview keys with the private keys made from their seeds, which are checked against
/// the public keys of the pairs. Each key is looked for as bytes, in hexadecimal of either case, in
/// either base64 alphabet wherever it lies in a longer value, and as a list of numbers. The kit
/// writes its seed as grouped base32, which the scan does not look for, so the seed is decoded from
/// the kit file and from what the QR code scans back to, and its bytes are scanned: a key this
/// computer keeps used as the recovery seed is found there. The archive export is made over a
/// generation sealed for the recovery recipient with production primitives and put at the service;
/// the file is decoded, with its origin the kit's, its archive the one exported and its publication
/// and objects equal, object by object, to what the service holds, so it adds no byte of its own.
/// The controls are the scan finding a key in each of those forms (each built apart from the
/// scan's own list of forms); a key as the seed the kit gives; the seed the kit file and the QR
/// code give equal to the secure store's own copy; the seed printed from that copy in the kit file
/// and in what the QR code scans back to; the kit's fingerprint in the setup; the host's writer key
/// in the opened bundle; the writer's key identifier and a member's ciphertext in the archive
/// export; the cover view's fields in what the page was told; and the bundle's ciphertext in the
/// requests. Not shown here: what an archive the host really makes carries (the daemon's production
/// case reads the host's, and the members here are the case's own); the host's private keys, which
/// this computer never holds; the rest of the call the setup's parameters travel in (its target,
/// preconditions and proof, which the host double is not given); the parts of a request the
/// stand-in does not keep (its headers other than the token, a query on its path, the signature
/// block, any member of the signed document other than its body, and the authentication requests,
/// which the stand-in answers before it keeps a record); a key in a binary list of integers, split,
/// reversed or otherwise transformed; `kr backup setup`'s outputs; or the other data paths of backup
/// and recovery material. The view is sent through a command this suite registers over the host
/// double and not through `recovery_cover_host`, which needs a connection to a host this suite has
/// none of.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kit_the_qr_code_and_the_bundle_export_hold_none_of_the_keys_this_computer_keeps() {
    use kr_crypto::store::{SecretName, SecretStore as _};
    use kr_protocol::pairing::KeyPurpose;

    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");

    // The private keys this computer keeps, read from the store the recovery seed is in. The
    // private keys of the two X25519 pairs are made from their seeds by a hash, so each is checked
    // against the public key its pair has.
    let identity = computer.identity();
    let mut kept = Vec::new();
    for (purpose, public) in [
        (KeyPurpose::Transport, None),
        (KeyPurpose::Authorisation, None),
        (
            KeyPurpose::StoredEnvelope,
            Some(*identity.keys.stored_envelope.public().as_bytes()),
        ),
        (
            KeyPurpose::NotificationPreview,
            Some(*identity.keys.notification_preview.public().as_bytes()),
        ),
    ] {
        let name = SecretName::device_key(companion_tauri::device::identity::SCOPE, purpose)
            .expect("a name");
        let seed = computer
            .secrets
            .get(&name)
            .expect("the store reads")
            .unwrap_or_else(|| panic!("this computer kept a {purpose:?} key"));
        kept.push((format!("{purpose:?} seed"), seed.expose().to_vec()));
        if let Some(public) = public {
            let secret = x25519_secret_of(seed.expose());
            let derived = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &secret,
            )
            .expect("an X25519 private key")
            .compute_public_key()
            .expect("its public key");
            assert_eq!(
                derived.as_ref(),
                public.as_slice(),
                "the {purpose:?} private key is the first half of its seed's hash"
            );
            kept.push((format!("{purpose:?} private key (derived)"), secret));
        }
    }
    assert_eq!(kept.len(), 6, "four seeds and two keys made from them");
    for (name, key) in &kept {
        assert!(key.len() >= 32, "the {name} is a key, not a stub");
    }
    let stored_seed = load_recovery_seed(&*computer.secrets, SEED_SCOPE)
        .expect("the store reads")
        .expect("the recovery seed is in the same store");

    // What the computer writes or shows: the kit, the QR code (read as a scanner reads it), the
    // export of the bundle, the bundle opened with the kit alone, and what the page was told.
    let (kit_path, kit) = page.kit(out.path());
    let kit_file = std::fs::read(&kit_path).expect("the kit file");

    // The host on this computer is covered, which sends it the setup and names its writer and
    // producer in the bundle: the outputs below are read after that. The view of the cover reaches
    // the page as any answer does.
    let host = Arc::new(Host::new(&computer, computer.served.origin()));
    host.sets_up();
    let view = page.cover_host(&host, false).expect("the host is covered");
    assert_eq!(view["state"], "covered");
    let sent_setup = host.setups_sent();
    assert_eq!(sent_setup.len(), 1, "the host was sent one setup");
    let (setup_params, held_exactly) = &sent_setup[0];
    assert!(
        *held_exactly,
        "the service held exactly the bundle the host was sent when the host was asked"
    );
    let setup = serde_json::to_vec(setup_params).expect("the setup encodes");

    let qr = out.path().join("kit.svg");
    page.dialog_returns(&qr);
    page.call(
        "recovery_save_kit_qr",
        json!({ "path": qr.to_string_lossy() }),
    )
    .expect("the QR code is saved");
    let qr_file = std::fs::read(&qr).expect("the file");
    let (_, scanned_text, _) = scanned(&String::from_utf8(qr_file.clone()).expect("an SVG"));
    let qr_kit = parse_kit(&scanned_text).expect("the QR code scans back to a kit");
    let export = out.path().join("bundle.krexport");
    page.dialog_returns(&export);
    page.call(
        "recovery_export_offline",
        json!({ "path": export.to_string_lossy(), "archive": null }),
    )
    .expect("the bundle is exported");
    let export_file = std::fs::read(&export).expect("the export file");
    let bundle = serde_json::to_vec(&read_with_only_the_kit(&computer.served, &kit).await)
        .expect("the bundle encodes");

    // The sealed bundle in the setup and the one in the export are the bundle the service holds,
    // and each opens with the kit alone.
    let held_bundle = computer
        .served
        .web()
        .bundle(&kit.bundle_locator)
        .expect("the service holds the bundle");
    let bundle_export =
        kr_client::recovery::OfflineExport::from_canonical_slice(&export_file).expect("an export");
    assert_eq!(
        bundle_export.encrypted_bundle.as_slice(),
        held_bundle.as_slice(),
        "the export's bundle is the one the service holds"
    );
    assert_eq!(
        setup_params.sealed_bundle.as_slice(),
        held_bundle.as_slice(),
        "the setup's bundle is the one the service holds"
    );
    assert_eq!(
        bundle_export.service_origin, kit.service_origins[0],
        "the export names the service the kit names"
    );
    let seed = RecoverySeed::from_kit(&kit).expect("the kit's seed");
    let bundle_key = seed
        .bundle_key_for(&kit.context(&kit.service_origins[0]).expect("a context"))
        .expect("the bundle's key");
    let opened_with_the_kit = |sealed: &[u8]| -> Vec<u8> {
        serde_json::to_vec(
            &kr_crypto::archive::decrypt_recovery_bundle(&bundle_key, sealed)
                .expect("the kit opens the sealed bundle"),
        )
        .expect("the bundle encodes")
    };
    let setup_bundle = opened_with_the_kit(setup_params.sealed_bundle.as_slice());
    let export_bundle = opened_with_the_kit(bundle_export.encrypted_bundle.as_slice());

    // An archive made for the host double and published, listed by the page and exported by it.
    let archive = setup_params.archive_id;
    let published = publish_generation(
        &computer,
        &seed,
        &host,
        archive,
        &[
            ("host/configuration.json", b"{\"revision\":1}".to_vec()),
            ("sessions/a.json", b"{\"output\":\"a line\"}".to_vec()),
        ],
    )
    .await;
    let listed = page
        .call("recovery_archives", json!({}))
        .expect("the archives");
    assert_eq!(listed[0]["archive_id"], archive.to_string());
    assert_eq!(listed[0]["generation"], 1, "the page lists the generation");
    let archive_path = out.path().join("archive.krexport");
    page.dialog_returns(&archive_path);
    let saved = page
        .call(
            "recovery_export_offline",
            json!({ "path": archive_path.to_string_lossy(), "archive": archive.to_string() }),
        )
        .expect("the archive is exported");
    assert_eq!(saved["archive_id"], archive.to_string());
    assert_eq!(saved["generation"], 1);
    let archive_file = std::fs::read(&archive_path).expect("the archive export file");
    assert_eq!(saved["bytes"], archive_file.len());
    let exported =
        kr_client::recovery::OfflineExport::from_canonical_slice(&archive_file).expect("an export");
    assert_eq!(
        exported.encrypted_bundle.as_slice(),
        held_bundle.as_slice(),
        "the archive export's bundle is the one the service holds"
    );
    assert_eq!(
        exported.service_origin, kit.service_origins[0],
        "the archive export names the service the kit names"
    );
    let carried = exported.archive.0.as_ref().expect("an archive");
    assert_eq!(carried.archive_id, archive);
    assert_eq!(
        carried.publication, published.publication,
        "the publication that was sent"
    );
    assert_eq!(
        serde_json::to_value(&carried.publication).expect("a publication encodes"),
        computer
            .served
            .web()
            .publication(&archive.to_string(), 1)
            .expect("the service holds the publication"),
        "the publication the service holds"
    );
    let service_object = |object: kr_protocol::ids::BackupObjectId| {
        computer
            .served
            .web()
            .stored(&archive.to_string(), &object.to_string())
            .expect("the service holds the object")
    };
    assert_eq!(
        carried.encrypted_manifest.as_slice(),
        service_object(published.manifest_object).as_slice(),
        "the manifest object is the one the service holds"
    );
    let exported_objects: Vec<_> = carried
        .objects
        .iter()
        .map(|object| object.object_id)
        .collect();
    assert_eq!(
        exported_objects, published.objects,
        "every member object the generation has, once each and in order"
    );
    for object in &carried.objects {
        assert_eq!(
            object.bytes.as_slice(),
            service_object(object.object_id).as_slice(),
            "a member object is the one the service holds"
        );
    }

    let told = page.told().into_bytes();
    // Every request the service was sent: the document, the content beside it, the token.
    let mut sent = Vec::new();
    for (at, arrived) in computer.served.web().arrived().iter().enumerate() {
        let to = format!("request {at} to {}", arrived.path);
        sent.push((
            format!("the body of {to}"),
            serde_json::to_vec(&arrived.body).expect("a body encodes"),
        ));
        if let Some(content) = &arrived.content {
            sent.push((format!("the content of {to}"), content.clone()));
        }
        if let Some(token) = &arrived.token {
            sent.push((format!("the token of {to}"), token.clone().into_bytes()));
        }
    }
    let mut outputs: Vec<(String, Vec<u8>)> = [
        ("the kit file", kit_file.clone()),
        ("the QR code file", qr_file),
        ("the QR code's text", scanned_text.clone().into_bytes()),
        ("the seed the kit file gives", kit.seed.expose().to_vec()),
        ("the seed the QR code gives", qr_kit.seed.expose().to_vec()),
        ("the offline export of the bundle", export_file),
        ("the offline export of an archive", archive_file.clone()),
        ("the setup the host was sent", setup.clone()),
        ("the setup's sealed bundle, opened", setup_bundle),
        ("the export's sealed bundle, opened", export_bundle),
        ("the bundle opened with the kit", bundle.clone()),
        ("what the page was told", told.clone()),
    ]
    .into_iter()
    .map(|(label, bytes)| (label.to_owned(), bytes))
    .collect();

    // The controls: the scan finds a key in each form it looks for, wherever the key lies in a
    // longer value, and reads what the kit file and the code hold. The bytes and the hexadecimal
    // forms are made here and not by the scan's own list of forms, so a form dropped from that
    // list fails here.
    let (_, probe) = &kept[0];
    let lower: String = probe.iter().map(|byte| format!("{byte:02x}")).collect();
    for (form, needle) in [
        ("as bytes", probe.clone()),
        ("in lower-case hexadecimal", lower.clone().into_bytes()),
        (
            "in upper-case hexadecimal",
            lower.to_uppercase().into_bytes(),
        ),
    ] {
        let document = [b"{\"a\":\"".as_slice(), &needle, b"\"}"].concat();
        assert!(
            carried_in(&document, probe).is_some(),
            "the scan misses a key {form}"
        );
    }
    for alphabet in ["base64url", "base64"] {
        for before in 0..3 {
            let mut longer = vec![0x5a_u8; before];
            longer.extend_from_slice(probe);
            longer.extend_from_slice(b"tail");
            let encoded = kr_protocol::scalars::to_base64url(&longer);
            let encoded = if alphabet == "base64" {
                encoded.replace('-', "+").replace('_', "/")
            } else {
                encoded
            };
            let value = format!("{{\"k\":\"{encoded}\"}}").into_bytes();
            assert!(
                carried_in(&value, probe).is_some(),
                "the scan misses a key inside a longer {alphabet} value that starts {before} \
                 bytes before it"
            );
        }
    }
    let list = format!(
        "{{\"k\":[\n  {}\n]}}",
        probe
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",\n  ")
    )
    .into_bytes();
    assert_eq!(
        carried_in(&list, probe).as_deref(),
        Some("as a list of numbers")
    );
    // The seed's printed form is made from the secure store's own copy of the seed, not cut from
    // the file the scan reads, so a file that left the seed out, or wrote another, fails here.
    let stored_kit = stored_seed.to_kit(kit.service_origins.clone(), kit.bundle_locator.clone());
    assert_eq!(
        kit.seed.expose(),
        stored_kit.seed.expose(),
        "the kit file gives the secure store's seed"
    );
    assert_eq!(
        qr_kit.seed.expose(),
        stored_kit.seed.expose(),
        "the QR code gives the secure store's seed"
    );
    // The seeds above are scanned as their raw bytes, in which a key used as the seed is found.
    assert_eq!(
        carried_in(probe, probe).as_deref(),
        Some("as bytes"),
        "the scan does not find a key this computer keeps as the seed the kit gives"
    );
    let printed = kr_client::recovery::render_kit(&stored_kit)
        .expect("the kit's text")
        .to_string();
    let seed_line = printed
        .lines()
        .find_map(|line| line.strip_prefix("seed: "))
        .expect("a seed line");
    let kit_text = String::from_utf8(kit_file).expect("the kit is text");
    assert!(
        carried_in(kit_text.as_bytes(), seed_line.as_bytes()).is_some(),
        "the scan does not find the seed in the kit file"
    );
    assert!(
        carried_in(scanned_text.as_bytes(), seed_line.as_bytes()).is_some(),
        "the scan does not read what the QR code holds"
    );
    assert!(
        carried_in(&setup, sent_setup[0].0.kit_fingerprint.as_bytes()).is_some(),
        "the scan does not read the setup the host was sent"
    );
    assert!(
        carried_in(&bundle, host.keys.writer_public_key.as_bytes()).is_some(),
        "the scan does not read the host's keys in the bundle"
    );
    assert!(
        carried_in(&archive_file, host.keys.writer_key_id.as_bytes()).is_some(),
        "the scan does not read the publication in the archive export"
    );
    let member_ciphertext = service_object(published.objects[0]);
    assert!(
        archive_file
            .windows(member_ciphertext.len())
            .any(|window| window == member_ciphertext.as_slice()),
        "the scan does not read the member objects in the archive export"
    );
    assert!(
        carried_in(&told, sent_setup[0].0.kit_fingerprint.as_bytes()).is_some(),
        "the scan does not read the view of the cover"
    );
    assert!(
        sent.iter()
            .any(|(_, bytes)| carried_in(bytes, &held_bundle).is_some()),
        "the scan does not read the bundle in the requests"
    );
    outputs.extend(sent);

    for (output, bytes) in &outputs {
        for (name, key) in &kept {
            assert_eq!(
                carried_in(bytes, key),
                None,
                "{output} holds the {name} this computer keeps"
            );
        }
    }
}

/// The first write of all can be lost too. Whether it landed or not, settling it leaves recovery
/// either on or ready to be turned on again, and the locator the kit names does not change.
///
/// KR-REQ-20.18, the part about the stable locator: after a first write whose answer was lost, the
/// kit names the locator that write used, and a device holding only the kit reads the bundle there.
/// Not shown here: an update by compare-and-swap, or any other field of the kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_recovery_on_after_a_lost_first_write_keeps_the_locator() {
    for (moment, landed) in [(Moment::After, true), (Moment::Before, false)] {
        let computer = Computer::new().await;
        let page = computer.page().await;
        computer.served.web().fail(SYNC_PATH, 1, moment);
        let lost = page
            .call("recovery_turn_on", json!({}))
            .expect_err("no answer");
        assert_eq!(lost["code"], "OUTCOME_UNKNOWN", "{moment:?}");
        assert_eq!(page.view()["state"], "unsettled", "{moment:?}");
        let first = computer.served.web().arrived()[0].body["exchange"]["locator"]
            .as_str()
            .expect("a locator")
            .to_owned();

        let settled = page.call("recovery_settle", json!({})).expect("settled");
        assert_eq!(
            settled["state"],
            if landed { "on" } else { "unfinished" },
            "{moment:?}"
        );
        if !landed {
            let on = page.call("recovery_turn_on", json!({})).expect("on");
            assert_eq!(on["state"], "on");
        }

        let out = tempfile::tempdir().expect("a directory");
        let (_, kit) = page.kit(out.path());
        assert_eq!(kit.bundle_locator, first, "{moment:?}");
        let bundle = read_with_only_the_kit(&computer.served, &kit).await;
        assert_eq!(bundle.revision.get(), 1, "{moment:?}");
    }
}

const LOCATOR: &str = "6e2f6b8c-4d2a-4f5b-9a57-0f6a1d3c8e11";

/// This computer as an earlier run left it: a record in the first format that says the first write
/// has not landed, `kept` by the seed the secure store holds, and a bundle at the locator that
/// `sealed_under` sealed, which is the seed this computer holds when it is the same one.
async fn left_by_an_earlier_run(
    computer: &Computer,
    kept: &RecoverySeed,
    sealed_under: &RecoverySeed,
) {
    left_by_an_earlier_run_at(computer, &computer.served, kept, sealed_under).await;
}

/// As [`left_by_an_earlier_run`], with the bundle put at the service `put_at` through a second
/// store, in the place of the service the record names: the way a fork's client of a service of its
/// own took the earlier write while the record kept the origin it was made for.
async fn left_by_an_earlier_run_at(
    computer: &Computer,
    put_at: &Served,
    kept: &RecoverySeed,
    sealed_under: &RecoverySeed,
) {
    store_recovery_seed(&*computer.secrets, SEED_SCOPE, kept).expect("the seed is kept");
    // The directory an earlier run made: recovery keeps its records in an owner-only directory.
    kr_ipc::paths::create_private_directory(&computer.data.path().join("recovery"))
        .expect("the directory");
    // The record as the first version of the application wrote it, which this version still reads.
    kr_ipc::paths::write_owner_only_file(
        &computer.data.path().join("recovery").join("recovery.json"),
        format!(
            r#"{{"version":1,"service_origin":"{}","bundle_locator":"{LOCATOR}","kept":false}}"#,
            computer.served.origin()
        )
        .as_bytes(),
    )
    .expect("the record");
    let origin = GatewayOrigin::new(put_at.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport");
    let service = ManagedSyncService::new(
        origin,
        Arc::new(http),
        Arc::new(Installation(computer.identity().keys.authorisation.clone())),
    )
    .presenting(Arc::new(Bearer(TOKEN)), BACKUP_WRITE_SCOPE);
    let directory = tempfile::tempdir().expect("a directory");
    let mut earlier = BundleStore::open(
        Arc::new(service),
        RecoveryContext {
            service_origin: computer.served.origin().to_owned(),
            bundle_locator: LOCATOR.to_owned(),
        },
        directory.path(),
    )
    .expect("a store");
    earlier
        .commit(
            sealed_under,
            &mut BundleStore::empty(TimestampMs::new(now_ms())),
            TimestampMs::new(now_ms()),
        )
        .await
        .expect("the earlier write lands");
}

/// A record in the first format, written before the bundle landed, is read: turning recovery on
/// again finds the bundle this device put there, adopts it and writes nothing over it.
///
/// KR-REQ-20.18, the part about the stable locator: the kit of a computer whose earlier run stopped
/// after the bundle landed names the locator that bundle is at, and nothing is written over it. Not
/// shown here: an update by compare-and-swap, or any other field of the kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_that_stopped_after_the_bundle_landed_adopts_it() {
    let computer = Computer::new().await;
    let seed = RecoverySeed::generate().expect("a seed");
    left_by_an_earlier_run(&computer, &seed, &seed).await;

    let page = computer.page().await;
    assert_eq!(page.view()["state"], "unfinished");
    let on = page.call("recovery_turn_on", json!({})).expect("on");
    assert_eq!(on["state"], "on");
    let (sequence, _) = computer
        .served
        .web()
        .bundle_write(LOCATOR)
        .expect("the bundle");
    assert_eq!(sequence, 1, "nothing was written over the bundle");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    assert_eq!(kit.bundle_locator, LOCATOR);
}

/// A bundle at the locator that this computer's seed does not open is somebody else's, or another
/// seed's: it is not adopted, not written over, and no kit is offered for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_the_seed_does_not_open_is_neither_adopted_nor_written_over() {
    let computer = Computer::new().await;
    let ours = RecoverySeed::generate().expect("a seed");
    let another = RecoverySeed::generate().expect("a seed");
    left_by_an_earlier_run(&computer, &ours, &another).await;
    let (_, held) = computer
        .served
        .web()
        .bundle_write(LOCATOR)
        .expect("the bundle");

    let page = computer.page().await;
    page.call("recovery_turn_on", json!({}))
        .expect_err("the bundle is not this seed's");
    assert_eq!(page.view()["state"], "unfinished");
    let (sequence, still) = computer
        .served
        .web()
        .bundle_write(LOCATOR)
        .expect("the bundle");
    assert_eq!((sequence, still), (1, held), "the bundle is as it was");
    let out = tempfile::tempdir().expect("a directory");
    let path = out.path().join("kit.txt");
    page.dialog_returns(&path);
    page.call(
        "recovery_save_kit",
        json!({ "path": path.to_string_lossy() }),
    )
    .expect_err("no kit is offered for a bundle that was not adopted");
    assert!(!path.exists());
}

/// A step holds the lock a second companion on this machine would wait on, for as long as it runs
/// and no longer. The lock is what keeps two companions from each drawing a locator and committing
/// a bundle of their own; this case asserts who holds it and when, and runs no second companion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_holds_the_lock_another_companion_waits_on_while_it_runs() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(computer.data.path().join("recovery").join("recovery.lock"))
        .expect("the lock file");
    assert!(
        kr_flush::lock::try_exclusive(&lock).is_ok(),
        "nothing holds the lock between steps"
    );
    kr_flush::lock::release(&lock).expect("released");

    // The service holds the first write, so the step is in flight.
    let web = Arc::clone(computer.served.web());
    web.fail(SYNC_PATH, 1, Moment::Hold);
    let recovery = Arc::clone(&page.recovery);
    let account = Arc::clone(&page.account);
    let step = tokio::spawn(async move { recovery.turn_on(&account).await });
    web.requests_reach(SYNC_PATH, 1).await;
    assert!(
        matches!(
            kr_flush::lock::try_exclusive(&lock),
            Err(std::fs::TryLockError::WouldBlock)
        ),
        "a step in flight holds the lock"
    );

    web.release_held();
    step.await
        .expect("the step ends")
        .expect_err("the held write was never answered");
    assert!(
        kr_flush::lock::try_exclusive(&lock).is_ok(),
        "the lock is let go when the step ends"
    );
}

/* -------------------------------------------------------------------------- */
/* The account's token                                                         */
/* -------------------------------------------------------------------------- */

/// The sync service is a choice of its own, and the account's token goes only to the service the
/// account is signed in to. A sync service setting that names another is refused with the setting
/// named, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_token_goes_only_to_the_service_the_account_is_signed_in_to() {
    let computer = Computer::new().await;
    let signed_in_elsewhere = GatewayOrigin::new(ACCOUNT_ORIGIN).expect("an origin");
    let page = computer.start(account(&signed_in_elsewhere, Some(&RECOVERY_BACKUP_SCOPES)).await);
    page.call(
        "sync_service_set",
        json!({ "origin": computer.served.origin() }),
    )
    .expect("the service is chosen");

    let host = computer.origin().as_str().replace("http://", "");
    let blocked = json!({
        "reason": "wrong_service",
        "sync_service": host,
        "account": "reach.kala.to",
    });
    assert_eq!(page.view()["blocker"], blocked);
    let refusal = page
        .call("recovery_turn_on", json!({}))
        .expect_err("the account's sign-in is not sent there");
    assert_eq!(refusal["code"], "PERMISSION_DENIED");
    let words = refusal["message"].as_str().expect("words");
    assert!(
        words.contains("sync service setting") && words.contains(&host),
        "the refusal names the setting and the service it names: {words}"
    );
    assert!(
        words.contains("Choose reach.kala.to as the sync service"),
        "and asks for the account's service as the sync service: {words}"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "nothing left this computer"
    );
    assert_eq!(page.view()["state"], "off", "nothing was made");
    assert!(
        load_recovery_seed(&*computer.secrets, SEED_SCOPE)
            .expect("the store is read")
            .is_none(),
        "no seed was made"
    );

    // Control: with the account signed in to the service the setting names, the same call goes,
    // and carries the account's token.
    let page = computer.page().await;
    assert_eq!(page.view()["blocker"], Value::Null);
    page.call("recovery_turn_on", json!({}))
        .expect("recovery is turned on");
    let arrived = computer.served.web().arrived();
    assert_eq!(arrived.len(), 1);
    assert_eq!(arrived[0].token.as_deref(), Some(TOKEN));
}

/// How a service is named to a person: its host.
fn host_of(origin: &str) -> String {
    origin.replace("http://", "")
}

/// The application over `computer`'s records, with the account signed in at `service`, with the
/// right to write backup storage there, and the sync service setting naming `service` as well.
async fn moved_to(computer: &Computer, service: &Served) -> Page {
    signed_in_at(computer, service, service.origin()).await
}

/// The application over `computer`'s records, with the account signed in at `service`, with the
/// right to write backup storage there, and the sync service setting naming `setting`.
async fn signed_in_at(computer: &Computer, service: &Served, setting: &str) -> Page {
    let origin = GatewayOrigin::new(service.origin()).expect("an origin");
    let page = computer.start(account(&origin, Some(&RECOVERY_BACKUP_SCOPES)).await);
    page.call("sync_service_set", json!({ "origin": setting }))
        .expect("the service is chosen");
    page
}

/// Whether `words` name both services: the one a record names and the one the account is
/// signed in to.
fn names_both(words: &str, record: &str, account: &str) -> bool {
    words.contains(record) && words.contains(account)
}

/// Whether `words` tell the person that the setting names the record's service, or to choose or
/// change the setting or the sync service: what a record that exists cannot be moved by.
fn asks_for_another_setting(words: &str) -> bool {
    let words = words.to_lowercase();
    [
        "setting names",
        "choose",
        "change the setting",
        "change the sync service",
        "as the sync service",
    ]
    .iter()
    .any(|instruction| words.contains(instruction))
}

/// KR-REQ-20.18: the kit, saved as text or as a QR code, names the service the bundle is kept at
/// and the locator the first kit saved after the record was kept named, whatever the sync service
/// setting names and whichever service the account is signed in at, and saving it sends nothing
/// to either service. The case also shows the page what is wrong for a record that is made and
/// not kept and for one that is kept, and that the same account at the record's service goes on
/// with the record; what each step does at another service is held by the cases below.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_keeps_naming_its_service_and_its_kit_when_the_account_signs_in_elsewhere() {
    let computer = Computer::new().await;
    let other = serve().await;
    let (ours, theirs) = (host_of(computer.served.origin()), host_of(other.origin()));
    let wrong_service =
        json!({ "reason": "wrong_service", "sync_service": ours, "account": theirs });

    // A first write that never landed leaves a record that is made and not kept.
    let page = computer.page().await;
    computer.served.web().fail(SYNC_PATH, 1, Moment::Before);
    page.call("recovery_turn_on", json!({}))
        .expect_err("the first write is not answered");
    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the write is settled");
    assert_eq!(settled["state"], "unfinished");
    drop(page);

    // The account is signed in at another service and the setting names it. The record does not
    // move: the page is shown the mismatch.
    let moved = moved_to(&computer, &other).await;
    let view = moved.view();
    assert_eq!(view["state"], "unfinished", "{view}");
    assert_eq!(view["kept_at"], ours, "{view}");
    assert_eq!(view["blocker"], wrong_service, "{view}");
    drop(moved);

    // The same account at the record's service goes on with the record, and the bundle is kept.
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({}))
        .expect("recovery goes on with the record it began");
    assert_eq!(page.view()["state"], "on");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    assert_eq!(kit.service_origins, [computer.served.origin().to_owned()]);
    drop(page);

    // Signed in at the other service again, with the bundle kept at the first.
    let sent = computer.served.web().arrived().len();
    let moved = moved_to(&computer, &other).await;
    let view = moved.view();
    assert_eq!(view["state"], "on", "{view}");
    assert_eq!(view["kept_at"], ours, "{view}");
    assert_eq!(view["blocker"], wrong_service, "{view}");

    // The kit is made from the record: saved as text or as a QR code, it names the service the
    // bundle is kept at, whatever the setting names now.
    let (_, as_text) = moved.kit(out.path());
    assert_eq!(as_text.service_origins, kit.service_origins);
    assert_eq!(as_text.bundle_locator, kit.bundle_locator);
    let path = out.path().join("kit.svg");
    moved.dialog_returns(&path);
    moved
        .call(
            "recovery_save_kit_qr",
            json!({ "path": path.to_string_lossy() }),
        )
        .expect("the QR code is saved");
    let (_, text, _) = scanned(&std::fs::read_to_string(&path).expect("the file"));
    let from_the_code = parse_kit(&text).expect("a kit");
    assert_eq!(from_the_code.service_origins, kit.service_origins);
    assert_eq!(from_the_code.bundle_locator, kit.bundle_locator);

    assert_eq!(
        computer.served.web().arrived().len(),
        sent,
        "saving the kit sent nothing to the service the record names"
    );
    assert!(
        other.web().arrived().is_empty(),
        "nothing was sent to the service the account is signed in to"
    );
}

/// KR-REQ-17.14: a record is used at the service it names and at no other, whatever the sync
/// service setting names. With the record at one service and the account signed in at another, the
/// setting naming the record's service, the account's or a third service changes nothing: settling
/// a write that has no answer, going on with a record that is made and not kept, and then, with
/// the record kept, settling, covering the host (replacing it too), listing the archives and making
/// the offline copy (of the bundle and of an archive), with a write of the cover that has no
/// answer waiting as well, are each refused with the record's service and the account's named and
/// the sign-in the person needs, the page is shown what is wrong, and nothing is sent to any of the
/// three services. The refusal does not say that the setting names the record's service, and does
/// not tell the person to choose or change the sync service, which cannot move a record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_is_refused_to_an_account_signed_in_elsewhere_whatever_the_setting_names() {
    let computer = Computer::new().await;
    let signed_in = serve().await;
    let third = serve().await;
    let (ours, theirs) = (
        host_of(computer.served.origin()),
        host_of(signed_in.origin()),
    );
    let wrong_service =
        json!({ "reason": "wrong_service", "sync_service": ours, "account": theirs });
    let settings = [
        computer.served.origin().to_owned(),
        signed_in.origin().to_owned(),
        third.origin().to_owned(),
    ];
    let nothing_sent = |at_the_record: usize, setting: &str| {
        assert_eq!(
            computer.served.web().arrived().len(),
            at_the_record,
            "nothing was sent to the service the record names, with the setting at {setting}"
        );
        assert!(
            signed_in.web().arrived().is_empty(),
            "nothing was sent to the service the account is signed in to, with the setting at \
             {setting}"
        );
        assert!(
            third.web().arrived().is_empty(),
            "nothing was sent to a third service, with the setting at {setting}"
        );
    };
    let says_where = |words: &str| {
        assert!(names_both(words, &ours, &theirs), "{words}");
        assert!(
            words.contains(&format!("until this device is signed in to {ours}")),
            "the refusal says where the person has to be signed in: {words}"
        );
        assert!(
            !asks_for_another_setting(words),
            "the refusal does not say the setting names the record's service, or ask for another \
             choice of it: {words}"
        );
    };

    // A first write that never got an answer leaves a record that is made and not kept, and a write
    // waiting to be settled.
    let page = computer.page().await;
    computer.served.web().fail(SYNC_PATH, 1, Moment::Before);
    page.call("recovery_turn_on", json!({}))
        .expect_err("the first write is not answered");
    drop(page);

    // Settling it asks the record's service, which the account's sign-in is not sent to.
    let sent = computer.served.web().arrived().len();
    for setting in &settings {
        let moved = signed_in_at(&computer, &signed_in, setting).await;
        let view = moved.view();
        assert_eq!(view["state"], "unsettled", "{setting}: {view}");
        assert_eq!(view["kept_at"], ours, "{setting}: {view}");
        assert_eq!(view["blocker"], wrong_service, "{setting}: {view}");
        let refusal = moved
            .call("recovery_settle", json!({}))
            .expect_err("a write is not settled at a service the account is not signed in to");
        assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
        says_where(refusal["message"].as_str().expect("words"));
        nothing_sent(sent, setting);
    }

    let page = computer.page().await;
    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the write is settled");
    assert_eq!(settled["state"], "unfinished");
    drop(page);

    let sent = computer.served.web().arrived().len();
    for setting in &settings {
        let moved = signed_in_at(&computer, &signed_in, setting).await;
        let view = moved.view();
        assert_eq!(view["state"], "unfinished", "{setting}: {view}");
        assert_eq!(view["kept_at"], ours, "{setting}: {view}");
        assert_eq!(view["blocker"], wrong_service, "{setting}: {view}");
        let refusal = moved
            .call("recovery_turn_on", json!({}))
            .expect_err("the account's sign-in is not sent to the record's service");
        assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
        says_where(refusal["message"].as_str().expect("words"));
        nothing_sent(sent, setting);
    }

    // The same account at the record's service goes on with the record, and the bundle is kept.
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({}))
        .expect("recovery goes on with the record it began");
    assert_eq!(page.view()["state"], "on");
    drop(page);

    let sent = computer.served.web().arrived().len();
    let out = tempfile::tempdir().expect("a directory");
    for setting in &settings {
        let moved = signed_in_at(&computer, &signed_in, setting).await;
        let view = moved.view();
        assert_eq!(view["state"], "on", "{setting}: {view}");
        assert_eq!(view["kept_at"], ours, "{setting}: {view}");
        assert_eq!(view["blocker"], wrong_service, "{setting}: {view}");
        kept_record_is_refused_at_every_step(&computer, &moved, &says_where, setting, out.path())
            .await;
        nothing_sent(sent, setting);
    }

    // The record is kept, and a write of the cover whose answer is lost leaves it waiting to be
    // settled. With the account signed in elsewhere, every step is refused all the same.
    let page = computer.page().await;
    let host = Host::new(&computer, computer.served.origin());
    host.sets_up();
    computer
        .served
        .web()
        .fail_with_member(SYNC_PATH, "exchange", 1, Moment::After);
    let unknown = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("the write is not answered");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_eq!(page.view()["state"], "unsettled");
    drop(page);

    let sent = computer.served.web().arrived().len();
    for setting in &settings {
        let moved = signed_in_at(&computer, &signed_in, setting).await;
        let view = moved.view();
        assert_eq!(view["state"], "unsettled", "{setting}: {view}");
        assert_eq!(view["kept_at"], ours, "{setting}: {view}");
        assert_eq!(view["blocker"], wrong_service, "{setting}: {view}");
        kept_record_is_refused_at_every_step(&computer, &moved, &says_where, setting, out.path())
            .await;
        nothing_sent(sent, setting);
    }

    // The account at the record's service settles it.
    let page = computer.page().await;
    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the lost write is settled");
    assert_eq!(settled["state"], "on", "{settled}");
}

/// Every step that reaches the service a kept record names, asked with the account signed in at
/// another service: each is refused with both services named and the sign-in the person needs,
/// and the host is not asked.
async fn kept_record_is_refused_at_every_step(
    computer: &Computer,
    moved: &Page,
    says_where: &dyn Fn(&str),
    setting: &str,
    out: &Path,
) {
    let refusal = moved
        .call("recovery_settle", json!({}))
        .expect_err("a write is not settled at a service the account is not signed in to");
    assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
    says_where(refusal["message"].as_str().expect("words"));

    let host = Host::new(computer, computer.served.origin());
    host.sets_up();
    let refusal = moved
        .recovery
        .cover_host(&moved.account, &host, false)
        .await
        .expect_err("the host is not covered through a service the account is not signed in to");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{setting}");
    says_where(&refusal.message);
    assert_eq!(
        *host.statuses.lock().expect("statuses"),
        0,
        "{setting}: the host was not asked"
    );
    let refusal = moved
        .recovery
        .cover_host(&moved.account, &host, true)
        .await
        .expect_err("a replacement is not made through a service the account is not signed in to");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{setting}");
    says_where(&refusal.message);
    assert_eq!(
        *host.statuses.lock().expect("statuses"),
        0,
        "{setting}: the host was not asked to be replaced"
    );

    let refusal = moved
        .call("recovery_archives", json!({}))
        .expect_err("the archives are not read through a service the account is not signed in to");
    assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
    says_where(refusal["message"].as_str().expect("words"));

    let exported = out.join("bundle.krexport");
    moved.dialog_returns(&exported);
    let refusal = moved
        .call(
            "recovery_export_offline",
            json!({ "path": exported.to_string_lossy(), "archive": null }),
        )
        .expect_err(
            "the offline copy is not read through a service the account is not signed in to",
        );
    assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
    says_where(refusal["message"].as_str().expect("words"));
    assert!(!exported.exists(), "{setting}");
    moved.dialog_returns(&exported);
    let refusal = moved
        .call(
            "recovery_export_offline",
            json!({
                "path": exported.to_string_lossy(),
                "archive": "00000000-0000-4000-8000-000000000099"
            }),
        )
        .expect_err("an archive is not read through a service the account is not signed in to");
    assert_eq!(refusal["code"], "PERMISSION_DENIED", "{setting}");
    says_where(refusal["message"].as_str().expect("words"));
    assert!(!exported.exists(), "{setting}");
}

/// KR-REQ-17.14: a record is read and covered at the service it names when only the setting
/// changes. With the account still signed in at the record's service and the setting naming
/// another, the page is shown nothing wrong, turning recovery on again changes nothing, the
/// archives are listed and the offline copy is read from the record's service, the host is covered
/// through it, and the service the setting names is sent nothing.
///
/// KR-REQ-20.18, the part about the bundle a printed kit names and the offline export: after the
/// host is covered, the bundle read with only the first kit names the host's writer, and the
/// offline copy of the bundle is the bundle the service holds, naming that service. Not shown
/// here: the compare-and-swap of the update, or the export of an archive the bundle names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_is_read_and_covered_at_its_own_service_when_the_setting_names_another() {
    let computer = Computer::new().await;
    let setting = serve().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    drop(page);

    let page = computer.start(account(&computer.origin(), Some(&RECOVERY_BACKUP_SCOPES)).await);
    page.call("sync_service_set", json!({ "origin": setting.origin() }))
        .expect("another service is chosen");
    let view = page.view();
    assert_eq!(view["state"], "on", "{view}");
    assert_eq!(view["kept_at"], host_of(computer.served.origin()), "{view}");
    assert_eq!(view["blocker"], Value::Null, "{view}");

    // Going on with a record that is kept changes nothing and sends nothing.
    let before = computer.served.web().arrived().len();
    let again = page
        .call("recovery_turn_on", json!({}))
        .expect("turning recovery on again is not refused");
    assert_eq!(again["state"], "on", "{again}");
    assert_eq!(again["kept_at"], view["kept_at"], "{again}");
    assert_eq!(computer.served.web().arrived().len(), before);

    let before = computer.served.web().arrived().len();
    assert_eq!(
        page.call("recovery_archives", json!({}))
            .expect("the archives are listed"),
        json!([]),
        "a bundle that names no archive lists none"
    );
    assert!(
        computer.served.web().arrived().len() > before,
        "the archives were read at the service the record names"
    );
    let exported = out.path().join("bundle.krexport");
    page.dialog_returns(&exported);
    let saved = page
        .call(
            "recovery_export_offline",
            json!({ "path": exported.to_string_lossy(), "archive": null }),
        )
        .expect("the bundle is exported");
    assert_eq!(saved["archive_id"], Value::Null);
    let export = kr_client::recovery::OfflineExport::from_canonical_slice(
        &std::fs::read(&exported).expect("the file"),
    )
    .expect("an export");
    assert_eq!(
        Some(export.encrypted_bundle.as_slice().to_vec()),
        computer.served.web().bundle(&kit.bundle_locator),
        "the offline copy is the bundle as the service the record names holds it"
    );
    assert_eq!(
        export.service_origin,
        computer.served.origin(),
        "and it names that service, as a restore reads it"
    );

    // An archive the bundle does not name is asked about at the same service, and writes nothing.
    let before = computer.served.web().arrived().len();
    let unlisted = out.path().join("unlisted.krexport");
    page.dialog_returns(&unlisted);
    let refused = page
        .call(
            "recovery_export_offline",
            json!({
                "path": unlisted.to_string_lossy(),
                "archive": "00000000-0000-4000-8000-000000000099"
            }),
        )
        .expect_err("the bundle names no such archive");
    assert_eq!(refused["code"], "PERMISSION_DENIED");
    assert!(!unlisted.exists());
    assert!(
        computer.served.web().arrived().len() > before,
        "the bundle was read at the service the record names"
    );

    let host = Host::new(&computer, computer.served.origin());
    host.sets_up();
    let covered = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect("the host is covered");
    assert!(
        matches!(covered, HostCoverView::Covered { .. }),
        "{covered:?}"
    );
    let bundle = read_with_only_the_kit(&computer.served, &kit).await;
    assert!(
        bundle
            .trusted_writers
            .iter()
            .any(|held| held.writer_key_id == host.keys.writer_key_id),
        "the bundle at the record's service names the host's writer"
    );
    assert!(
        setting.web().arrived().is_empty(),
        "the service the setting names was sent nothing"
    );
}

/// A computer whose recovery record is made and not kept, through the clients of a fork's service:
/// the first write never reached it. The application is then started again with the account still
/// signed in at the record's service and the sync service setting naming `setting`. Returns the
/// factory the application was given and the application.
async fn with_an_unkept_record_and_the_setting_moved(
    computer: &Computer,
    fork: &Served,
    setting: &Served,
) -> (Arc<Recording>, Page) {
    let recording = Recording::at(fork, computer.identity().keys.authorisation.clone());
    let page = computer.page_with(Some(Arc::clone(&recording) as _)).await;
    fork.web().fail(SYNC_PATH, 1, Moment::Before);
    page.call("recovery_turn_on", json!({}))
        .expect_err("the first write is not answered");
    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the write is settled");
    assert_eq!(settled["state"], "unfinished");
    drop(page);

    let page = computer.start_with(
        account(&computer.origin(), Some(&RECOVERY_BACKUP_SCOPES)).await,
        Some(Arc::clone(&recording) as _),
    );
    page.call("sync_service_set", json!({ "origin": setting.origin() }))
        .expect("another service is chosen");
    let view = page.view();
    assert_eq!(view["state"], "unfinished", "{view}");
    assert_eq!(view["sync_service"]["origin"], setting.origin(), "{view}");
    assert_eq!(view["kept_at"], host_of(computer.served.origin()), "{view}");
    assert_eq!(view["blocker"], Value::Null, "{view}");
    (recording, page)
}

/// KR-REQ-17.14: recovery goes on with a record that is made and not kept at the service the
/// record names when only the setting changes. The bundle is written through the client the
/// application was given, asked for the record's origin and presenting the account signed in there;
/// the service the setting names is sent nothing; and the bundle is noted as that account's, so
/// that deleting the account at the record's service clears the record and deleting an account at
/// the service the setting names does not.
///
/// KR-REQ-20.18, the part about the stable locator: recovery going on with a record that was made
/// and not kept writes the bundle once, to the record's service, at the locator of the record's
/// first write. Not shown here: a kit, or a compare-and-swap update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_goes_on_with_an_unkept_record_at_its_own_service_when_the_setting_names_another()
{
    let computer = Computer::new().await;
    let fork_service = serve().await;
    let setting = serve().await;
    let (recording, page) =
        with_an_unkept_record_and_the_setting_moved(&computer, &fork_service, &setting).await;
    let ours = computer.served.origin().to_owned();
    let first = fork_service
        .web()
        .arrived()
        .iter()
        .find(|request| request.body.get("exchange").is_some())
        .expect("the first write")
        .body["exchange"]["locator"]
        .clone();

    let written = writes_at(&fork_service);
    let on = page
        .call("recovery_turn_on", json!({}))
        .expect("recovery goes on with the record it began");
    assert_eq!(on["state"], "on", "{on}");
    assert_eq!(writes_at(&fork_service), written + 1, "one write was sent");
    let arrived = fork_service.web().arrived();
    let write = arrived
        .iter()
        .rev()
        .find(|request| request.body.get("exchange").is_some())
        .expect("the write");
    assert_eq!(write.body["exchange"]["kind"], "recovery_bundle");
    assert_eq!(
        write.body["exchange"]["locator"], first,
        "the write keeps the locator of the record it began"
    );
    assert_eq!(write.token.as_deref(), Some(TOKEN));
    let asked = recording.asked.lock().expect("the record").clone();
    assert!(
        asked
            .iter()
            .all(|(origin, presenting)| *origin == ours && *presenting),
        "{asked:?}: the bundle is written at the record's service, presenting the account"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "the fork's service took the place of the service the record names"
    );
    assert!(
        setting.web().arrived().is_empty(),
        "the service the setting names was sent nothing"
    );

    // The bundle is the account's that is signed in at the record's service. The same account at
    // the service the setting names is another account's mark, and does not own it.
    let tokens = page.account.tokens();
    let at_record = tokens
        .signed_in_mark(&ours)
        .expect("the grant is read")
        .expect("an account is signed in");
    let at_setting = tokens
        .signed_in_mark(setting.origin())
        .expect("the grant is read")
        .expect("an account is signed in");
    assert!(at_record != at_setting, "the two marks differ");
    page.recovery
        .account_deleted(at_setting)
        .await
        .expect("nothing to clear");
    assert_eq!(page.view()["state"], "on");
    page.recovery
        .account_deleted(at_record)
        .await
        .expect("cleared");
    assert_eq!(page.view()["state"], "off");
}

/// KR-REQ-17.14: a write whose answer was lost is settled, and the host is covered, through the
/// clients the application was given and at the service the record names, when only the setting
/// changes. With the record made and not kept, the account signed in at the record's service and
/// the setting naming another, going on with the record leaves a write that landed and was not
/// answered; settling it asks the fork's service and finds it applied; covering the host then
/// writes the bundle there before the host is asked. Every ask of the clients is for the record's
/// origin, and neither the service the record names nor the one the setting names is sent anything.
///
/// KR-REQ-20.15, the part about the bundle being committed before the host is asked: while the
/// write of the cover has no answer the host is not asked, and when it is asked the bundle is at
/// the record's service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_write_is_settled_and_the_host_covered_at_the_records_service_when_the_setting_names_another()
 {
    let computer = Computer::new().await;
    let fork_service = serve().await;
    let setting = serve().await;
    let (recording, page) =
        with_an_unkept_record_and_the_setting_moved(&computer, &fork_service, &setting).await;
    let ours = computer.served.origin().to_owned();
    let asks = || recording.asked.lock().expect("the record").clone();

    fork_service
        .web()
        .fail_with_member(SYNC_PATH, "exchange", 1, Moment::After);
    let lost = page
        .call("recovery_turn_on", json!({}))
        .expect_err("the write is not answered");
    assert_eq!(lost["code"], "OUTCOME_UNKNOWN");
    assert_eq!(page.view()["state"], "unsettled");

    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the lost write is settled");
    assert_eq!(settled["state"], "on", "{settled}");

    // The record is kept now. A write of the cover whose answer is lost is settled the same way,
    // and the host is not asked meanwhile.
    let host = Host::new(&computer, computer.served.origin()).reading_bundles_at(&fork_service);
    host.sets_up();
    fork_service
        .web()
        .fail_with_member(SYNC_PATH, "exchange", 1, Moment::After);
    let unknown = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect_err("the write is not answered");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert!(host.setups_sent().is_empty(), "the host is not asked");
    assert_eq!(page.view()["state"], "unsettled");
    let settled = page
        .call("recovery_settle", json!({}))
        .expect("the lost write is settled");
    assert_eq!(settled["state"], "on", "{settled}");

    let before = asks().len();
    let covered = page
        .recovery
        .cover_host(&page.account, &host, false)
        .await
        .expect("the host is covered");
    assert!(
        matches!(covered, HostCoverView::Covered { .. }),
        "{covered:?}"
    );
    assert!(
        asks().len() > before,
        "covering asked the clients it was given"
    );
    let sent = host.setups_sent();
    assert_eq!(sent.len(), 1, "the host was asked once");
    assert!(
        sent[0].1,
        "the bundle was at the record's service when the host was asked"
    );

    let asked = asks();
    assert!(
        asked.iter().all(|(origin, _)| *origin == ours),
        "{asked:?}: nothing was asked for the service the setting names"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "the fork's service took the place of the service the record names"
    );
    assert!(
        setting.web().arrived().is_empty(),
        "the service the setting names was sent nothing"
    );
}

/// KR-REQ-17.14: a host set up under another kit is replaced through the clients the application
/// was given, and at the service the record names, when only the setting changes. With the record
/// kept through a fork's client, the account signed in at the record's service and the setting
/// naming another, covering the host with a replacement writes the bundle at the fork's service
/// before the host is asked, as covering it without one does. Every ask of the clients is for the
/// record's origin, and neither the service the record names nor the one the setting names is sent
/// anything.
///
/// KR-REQ-20.15, the part about the bundle being committed before the host is asked, for a
/// replacement: when the host is asked to replace its setup the bundle is already at the record's
/// service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_cover_goes_through_the_clients_at_the_records_service_when_the_setting_names_another()
 {
    let computer = Computer::new().await;
    let fork_service = serve().await;
    let setting = serve().await;
    let (recording, page) =
        with_an_unkept_record_and_the_setting_moved(&computer, &fork_service, &setting).await;
    let ours = computer.served.origin().to_owned();
    let on = page
        .call("recovery_turn_on", json!({}))
        .expect("recovery goes on with the record it began");
    assert_eq!(on["state"], "on", "{on}");

    let host = Host::new(&computer, computer.served.origin()).reading_bundles_at(&fork_service);
    host.sets_up();
    let earlier = kr_protocol::ids::ArchiveId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
    host.with_setup(BackupSetupState::Committed {
        archive_id: earlier,
        kit_fingerprint: "CCCC-DDDD".to_owned(),
        recovery_public_key: another_recipient(),
        enabled_at_ms: TimestampMs::new(1),
        unusable: kr_protocol::scalars::Nullable::null(),
    });
    let written = writes_at(&fork_service);
    let replaced = page
        .recovery
        .cover_host(&page.account, &host, true)
        .await
        .expect("the host is replaced");
    assert!(
        matches!(
            replaced,
            HostCoverView::Covered { replaced: Some(ref kit), already: false, .. }
                if kit == "CCCC-DDDD"
        ),
        "{replaced:?}"
    );
    let sent = host.setups_sent();
    assert_eq!(sent.len(), 1, "the host was asked once");
    assert!(sent[0].0.replace, "the host was asked to replace");
    assert_ne!(sent[0].0.archive_id, earlier, "a new archive");
    assert!(
        sent[0].1,
        "the bundle was at the record's service when the host was asked"
    );
    assert!(
        writes_at(&fork_service) > written,
        "the bundle was written through the client the application was given"
    );

    let asked = recording.asked.lock().expect("the record").clone();
    assert!(
        asked.iter().all(|(origin, _)| *origin == ours),
        "{asked:?}: nothing was asked for the service the setting names"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "the fork's service took the place of the service the record names"
    );
    assert!(
        setting.web().arrived().is_empty(),
        "the service the setting names was sent nothing"
    );
}

/// KR-REQ-17.14: turning recovery on adopts an earlier write that landed through the clients the
/// application was given, and at the service the record names, when only the setting changes. With
/// a record made and not kept, and a bundle at its locator that this computer's seed opens, put at
/// the fork's service by an earlier run, the write is turned back as a conflict and the bundle is
/// read there, with the record's origin asked for and the account presenting. Nothing is written
/// over the bundle, the service the record names and the one the setting names are sent nothing,
/// and the adopted bundle is noted as no account's.
///
/// KR-REQ-20.18, the part about the kit's locator and service: the kit names the adopted bundle's
/// locator and the service the record names, whatever the setting names. Not shown here: the kit's
/// seed and checksum, or an update that adds a writer key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_recovery_on_adopts_an_earlier_write_at_the_records_service_when_the_setting_names_another()
 {
    let computer = Computer::new().await;
    let fork_service = serve().await;
    let setting = serve().await;
    let seed = RecoverySeed::generate().expect("a seed");
    left_by_an_earlier_run_at(&computer, &fork_service, &seed, &seed).await;
    let recording = Recording::at(
        &fork_service,
        computer.identity().keys.authorisation.clone(),
    );
    let page = computer.start_with(
        account(&computer.origin(), Some(&RECOVERY_BACKUP_SCOPES)).await,
        Some(Arc::clone(&recording) as _),
    );
    page.call("sync_service_set", json!({ "origin": setting.origin() }))
        .expect("another service is chosen");
    let ours = computer.served.origin().to_owned();
    let view = page.view();
    assert_eq!(view["state"], "unfinished", "{view}");
    assert_eq!(view["kept_at"], host_of(&ours), "{view}");
    assert_eq!(view["blocker"], Value::Null, "{view}");
    let (_, held) = fork_service
        .web()
        .bundle_write(LOCATOR)
        .expect("the earlier write landed at the fork's service");

    let before = fork_service.web().arrived().len();
    let on = page
        .call("recovery_turn_on", json!({}))
        .expect("recovery goes on from the earlier write");
    assert_eq!(on["state"], "on", "{on}");
    let arrived = fork_service.web().arrived();
    let members = |member: &str| {
        arrived[before..]
            .iter()
            .filter(|request| request.body.get(member).is_some())
            .count()
    };
    assert_eq!(members("exchange"), 1, "the write was turned back once");
    assert_eq!(
        members("compare"),
        1,
        "the bundle was read at the fork's service"
    );
    assert!(
        arrived[before..]
            .iter()
            .all(|request| request.token.as_deref() == Some(TOKEN)),
        "every request carried the account's token"
    );
    assert_eq!(
        fork_service.web().bundle_write(LOCATOR),
        Some((1, held)),
        "nothing was written over the bundle"
    );
    let asked = recording.asked.lock().expect("the record").clone();
    assert!(
        asked
            .iter()
            .all(|(origin, presenting)| *origin == ours && *presenting),
        "{asked:?}: the bundle is read at the record's service, presenting the account"
    );
    assert!(
        computer.served.web().arrived().is_empty(),
        "the fork's service took the place of the service the record names"
    );
    assert!(
        setting.web().arrived().is_empty(),
        "the service the setting names was sent nothing"
    );

    // The kit names the bundle that was adopted, at the service the record names: the locator is
    // the one the earlier write used, and does not change with the setting.
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());
    assert_eq!(
        kit.bundle_locator, LOCATOR,
        "the kit names the adopted bundle"
    );
    assert_eq!(
        kit.service_origins,
        std::slice::from_ref(&ours),
        "and the service the record names"
    );

    // An adopted bundle has no owner anyone knows: deleting the account that is signed in at the
    // record's service does not clear the record.
    let at_record = page
        .account
        .tokens()
        .signed_in_mark(&ours)
        .expect("the grant is read")
        .expect("an account is signed in");
    page.recovery
        .account_deleted(at_record)
        .await
        .expect("nothing to clear");
    assert_eq!(page.view()["state"], "on");
}

/// Recovery writes the account's backup storage, so a sign-in that is missing or does not carry
/// that right sends nothing, and the page is told which of the two to mend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_without_the_right_to_write_backup_storage_sends_nothing() {
    for (scopes, reason) in [
        (None, "signed_out"),
        (Some(&REQUESTED_SCOPES[..]), "needs_sign_in"),
    ] {
        let computer = Computer::new().await;
        let page = computer.start(account(&computer.origin(), scopes).await);
        page.call(
            "sync_service_set",
            json!({ "origin": computer.served.origin() }),
        )
        .expect("the service is chosen");
        assert_eq!(page.view()["blocker"], json!({ "reason": reason }));
        let refusal = page
            .call("recovery_turn_on", json!({}))
            .expect_err("nothing to write with");
        assert_eq!(refusal["code"], "PERMISSION_DENIED", "{reason}");
        assert!(computer.served.web().arrived().is_empty(), "{reason}");
        assert_eq!(page.view()["state"], "off", "{reason}");
    }
}

/* -------------------------------------------------------------------------- */
/* The kit                                                                     */
/* -------------------------------------------------------------------------- */

/// The kit holds the seed, so it is written only where a save dialog put it, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kit_is_written_only_where_a_save_dialog_put_it() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");
    let chosen = out.path().join("kit.txt");
    let named = out.path().join("elsewhere.txt");

    let refusal = page
        .call(
            "recovery_save_kit",
            json!({ "path": named.to_string_lossy() }),
        )
        .expect_err("the page chose that path itself");
    assert_eq!(refusal["code"], "PERMISSION_DENIED");
    assert!(!named.exists());

    page.dialog_returns(&chosen);
    page.call(
        "recovery_save_kit",
        json!({ "path": chosen.to_string_lossy() }),
    )
    .expect("the dialog's destination is written");
    assert!(chosen.exists());
    std::fs::remove_file(&chosen).expect("removed");
    page.call(
        "recovery_save_kit",
        json!({ "path": chosen.to_string_lossy() }),
    )
    .expect_err("a destination is good for one write");
    assert!(!chosen.exists());

    // And with recovery off there is nothing to write.
    let other = Computer::new().await;
    let page = other.page().await;
    let path = out.path().join("nothing.txt");
    page.dialog_returns(&path);
    page.call(
        "recovery_save_kit",
        json!({ "path": path.to_string_lossy() }),
    )
    .expect_err("recovery is off");
    assert!(!path.exists());
}

/// The account the bundle was kept under was deleted, and the service deleted the bundle with it.
/// The card no longer says a bundle is kept; the seed stays, and turning recovery on again starts
/// a bundle at a locator of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_account_leaves_recovery_off_with_the_seed_kept_and_a_new_locator_next_time() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let first = computer.served.web().arrived()[0].body["exchange"]["locator"]
        .as_str()
        .expect("a locator")
        .to_owned();
    assert_eq!(page.view()["state"], "on");

    let deleted = page.account_mark(&computer);
    page.recovery
        .account_deleted(deleted)
        .await
        .expect("cleared");
    assert_eq!(page.view()["state"], "off");
    assert_eq!(page.view()["kept_at"], Value::Null);
    assert!(
        load_recovery_seed(&*computer.secrets, SEED_SCOPE)
            .expect("the store is read")
            .is_some(),
        "the seed is the person's, and stays"
    );
    // Clearing again changes nothing.
    page.recovery
        .account_deleted(deleted)
        .await
        .expect("cleared again");

    page.call("recovery_turn_on", json!({})).expect("on again");
    let second = computer
        .served
        .web()
        .arrived()
        .last()
        .expect("a write")
        .body["exchange"]["locator"]
        .as_str()
        .expect("a locator")
        .to_owned();
    assert_ne!(first, second, "a bundle of its own, not the deleted one's");
}

/// Another account's bundle is still at the service, so deleting an account clears only a record
/// that is known to be its own: not one made under another account, and not one made before the
/// application noted whose it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_an_account_leaves_a_recovery_record_that_is_not_known_to_be_its_own() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let other = AccountMark::from_bytes([7; 32]);
    page.recovery
        .account_deleted(other)
        .await
        .expect("nothing to clear");
    assert_eq!(
        page.view()["state"],
        "on",
        "a record made under another account stays"
    );

    // A record with no note of whose it is: the note is the only thing that says.
    let note = computer
        .data
        .path()
        .join("recovery")
        .join("recovery-owner.json");
    std::fs::remove_file(&note).expect("the note exists");
    page.recovery
        .account_deleted(page.account_mark(&computer))
        .await
        .expect("nothing to clear");
    assert_eq!(page.view()["state"], "on", "an unknown owner is left alone");
}

/// The device clears the recovery record of a closed account through the application's own step,
/// and only once: recovery the person turns on afterwards is not undone by a later look.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_account_clears_the_recovery_record_once_and_a_later_look_leaves_it() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    assert_eq!(page.view()["state"], "on");
    let closed = closing::closed_account_at(computer.served.origin()).await;
    let state = page.app.state::<AppState>();

    closed.deletion_status(&state, true).await.expect("a look");
    assert_eq!(page.view()["state"], "off");

    page.call("recovery_turn_on", json!({})).expect("on again");
    assert_eq!(page.view()["state"], "on");
    closed.deletion_status(&state, true).await.expect("a look");
    assert_eq!(page.view()["state"], "on");
}

/// What a closure left on this device is settled at a look even when the look at the service cannot
/// be made: the status the page asks for says it could not, and the recovery record is cleared all
/// the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_look_that_cannot_reach_the_service_still_clears_what_a_closed_account_left() {
    let computer = Computer::new().await;
    // Recovery was turned on while the account was signed in, and the application is started
    // again after the account was closed.
    let earlier = computer.page().await;
    earlier
        .call("recovery_turn_on", json!({}))
        .expect("recovery is on");
    drop(earlier);
    let page =
        computer.start(closing::closed_account_unreachable_at(computer.served.origin()).await);
    page.call(
        "sync_service_set",
        json!({ "origin": computer.served.origin() }),
    )
    .expect("the service is chosen");
    assert_eq!(
        page.view()["state"],
        "on",
        "the record outlived the account"
    );

    let answer = page
        .call("account_deletion_status", json!({ "following": true }))
        .expect("an answer");
    assert_eq!(answer["state"], "problem");
    assert_eq!(page.view()["state"], "off");
}

/// Start-up looks after a closed account's leftovers before anyone asks: the recovery record that
/// outlived the account is cleared with no look from the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_start_clears_what_a_closed_account_left_with_no_look_from_the_page() {
    let computer = Computer::new().await;
    let earlier = computer.page().await;
    earlier
        .call("recovery_turn_on", json!({}))
        .expect("recovery is on");
    drop(earlier);
    let closed = closing::closed_account_unreachable_at(computer.served.origin()).await;
    let page = computer.start(Arc::clone(&closed));
    page.call(
        "sync_service_set",
        json!({ "origin": computer.served.origin() }),
    )
    .expect("the service is chosen");
    assert_eq!(page.view()["state"], "on");

    companion_tauri::account::deletion::resume(&page.app.state::<AppState>(), &closed).await;
    assert_eq!(page.view()["state"], "off");
}

/// The record is noted as the account's whose token wrote the bundle, not the account's that began
/// it: one account's start that did not finish, and another account's turning it on, leaves the
/// record the second account's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_is_noted_as_the_account_that_wrote_its_bundle_and_not_the_one_that_began_it() {
    let computer = Computer::new().await;
    let first = computer.page().await;
    computer.served.web().fail(SYNC_PATH, 1, Moment::Before);
    first
        .call("recovery_turn_on", json!({}))
        .expect_err("no answer");
    let began = first.account_mark(&computer);
    first.call("recovery_settle", json!({})).expect("settled");
    assert_eq!(first.view()["state"], "unfinished");
    drop(first);

    let second = computer.start(
        account_named(
            &computer.origin(),
            Some(&RECOVERY_BACKUP_SCOPES),
            "account-two",
        )
        .await,
    );
    second
        .call(
            "sync_service_set",
            json!({ "origin": computer.served.origin() }),
        )
        .expect("the service is chosen");
    second.call("recovery_turn_on", json!({})).expect("on");
    assert_eq!(second.view()["state"], "on");

    second
        .recovery
        .account_deleted(began)
        .await
        .expect("nothing to clear");
    assert_eq!(
        second.view()["state"],
        "on",
        "the account that only began it does not own the bundle another wrote"
    );
    second
        .recovery
        .account_deleted(second.account_mark(&computer))
        .await
        .expect("cleared");
    assert_eq!(second.view()["state"], "off");
}

/// The record is noted as the account's whose token wrote the bundle, though another account signs
/// in (from another window of the application) while the write is at the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_is_noted_as_the_account_whose_token_wrote_the_bundle_though_another_signed_in_meanwhile()
 {
    let computer = Computer::new().await;
    let page = computer.page().await;
    let wrote = page.account_mark(&computer);
    let web = Arc::clone(computer.served.web());
    web.fail(SYNC_PATH, 1, Moment::Gate);
    let recovery = Arc::clone(&page.recovery);
    let account = Arc::clone(&page.account);
    let step = tokio::spawn(async move { recovery.turn_on(&account).await });
    web.requests_reach(SYNC_PATH, 1).await;
    page.account
        .tokens()
        .commit(
            IssuedGrant {
                access_token: AccountToken::new(TOKEN).expect("a token"),
                expires_in_seconds: 600,
                refresh_token: RefreshToken::new("another-refresh-token").expect("a token"),
                scopes: RECOVERY_BACKUP_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect(),
                subject: "account-two".to_owned(),
            },
            "another-nonce",
        )
        .await
        .expect("another account signs in");
    web.release_held();
    step.await
        .expect("the step ends")
        .expect("the bundle is written");
    let signed_in = page.account_mark(&computer);
    assert_ne!(signed_in, wrote, "another account is signed in now");

    page.recovery
        .account_deleted(signed_in)
        .await
        .expect("nothing to clear");
    assert_eq!(
        page.view()["state"],
        "on",
        "the account that signed in meanwhile does not own the bundle"
    );
    page.recovery.account_deleted(wrote).await.expect("cleared");
    assert_eq!(page.view()["state"], "off");
}

/// A bundle this computer adopts from an earlier run was written by no account anyone knows, so
/// deleting the account that adopted it leaves the record: it may be the bundle of another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_adopted_from_an_earlier_run_has_no_owner_and_is_left_by_a_deletion() {
    let computer = Computer::new().await;
    let seed = RecoverySeed::generate().expect("a seed");
    left_by_an_earlier_run(&computer, &seed, &seed).await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    assert_eq!(page.view()["state"], "on");

    page.recovery
        .account_deleted(page.account_mark(&computer))
        .await
        .expect("nothing to clear");
    assert_eq!(page.view()["state"], "on");
}
