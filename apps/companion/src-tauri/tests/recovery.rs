//! Recovery, through the commands the page calls, against the sync service as a local Worker
//! answered it.
//!
//! KR-REQ-20.15 and 20.18: the recovery bundle is committed before the host's writer is declared
//! recovery-enabled and before the host is set up under this computer's recovery, and bundle
//! updates use the stable locator and compare-and-swap without
//! reprinting the seed. KR-REQ-17.14: the sync service is a choice of its own, and the account's
//! token goes only to the service the account is signed in to.
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
    ACCOUNT_ORIGIN, AccountToken, AccountTokenSource, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE,
    Client, IssuedGrant, RECOVERY_BACKUP_SCOPES, REQUESTED_SCOPES, RefreshToken, SignedInAccount,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, NullService, ServiceFuture, ServiceSigner,
    managed_response_limits,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{MemoryStore, load_recovery_seed, store_recovery_seed};
use kr_protocol::archive::{RecoveryBundle, RecoveryContext, RecoveryKit};
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{
    BackupEnableParams, BackupEnableResult, BackupHostKeys, BackupSetupState, BackupStatusResult,
    BackupStorageState, BackupStorageUnread,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Moment, RESTORE_TOKEN, Served, TOKEN, serve};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::{INVOKE_KEY, MockRuntime, mock_builder, mock_context, noop_assets};
use tauri::webview::InvokeRequest;

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
                    subject: "account-one".to_owned(),
                },
                "a-nonce",
            )
            .await
            .expect("the sign-in is kept");
    }
    Arc::new(Account::new(
        signed_in,
        service,
        origin.clone(),
        Arc::new(NoBrowser),
        Arc::new(|_| {}),
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
        let app = mock_builder()
            .manage(AppState::new())
            .manage(AccountSlot::ready(Arc::clone(&account)))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::sync_service_view,
                companion_tauri::commands::sync_service_set,
                companion_tauri::commands::recovery_view,
                companion_tauri::commands::recovery_turn_on,
                companion_tauri::commands::recovery_settle,
                companion_tauri::commands::recovery_save_kit,
                companion_tauri::commands::recovery_save_kit_qr,
                companion_tauri::commands::recovery_archives,
                companion_tauri::commands::recovery_export_offline,
                companion_tauri::commands::recovery_cover_host,
            ])
            .build(mock_context(noop_assets()))
            .expect("an application on the mock runtime");
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
        let account = account(&self.origin(), Some(&RECOVERY_BACKUP_SCOPES)).await;
        let page = self.start(account);
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
    /// Calls `command` with `body` through the invoke path, and returns the answer the page gets,
    /// or its refusal.
    fn call(&self, command: &str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
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
    /// What the host answers to the setup, or nothing when the answer is lost.
    answer: Mutex<Option<BackupEnableResult>>,
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
            answer: Mutex::new(None),
            enabled: Mutex::new(Vec::new()),
            statuses: Mutex::new(0),
            held: Box::new(move |locator| web.bundle(locator)),
        }
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
        Box::pin(async move {
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

/// How many writes of the bundle reached the service, whether or not it acted on them.
fn writes_sent(computer: &Computer) -> usize {
    computer
        .served
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
            "another kit",
            Box::new(|host| {
                host.with_setup(BackupSetupState::Committed {
                    archive_id: kr_protocol::ids::ArchiveId::new(
                        kr_protocol::scalars::Uuid::from_bytes([9; 16]),
                    ),
                    kit_fingerprint: "CCCC-DDDD".to_owned(),
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

    // A host that declines after the bundle is written is left as it is, and nothing is declared.
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

/// The QR code a saved kit draws, read back by a decoder that shares nothing with the encoder: the
/// squares the file draws are put on a bitmap and the bitmap is scanned.
fn scanned(svg: &str) -> (rqrr::MetaData, String) {
    let size: usize = svg
        .split("viewBox=\"0 0 ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|number| number.parse().ok())
        .expect("a view box");
    let path = svg
        .split("<path d=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a path");
    let mut dark = vec![false; size * size];
    for square in path.split(' ') {
        let (x, y) = square
            .strip_prefix('M')
            .and_then(|rest| rest.strip_suffix("h1v1h-1z"))
            .and_then(|at| at.split_once(','))
            .expect("a unit square");
        dark[y.parse::<usize>().expect("a row") * size + x.parse::<usize>().expect("a column")] =
            true;
    }
    let scale = 8;
    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(size * scale, size * scale, |x, y| {
            if dark[(y / scale) * size + x / scale] {
                0
            } else {
                255
            }
        });
    let grids = image.detect_grids();
    assert_eq!(grids.len(), 1, "one code is drawn");
    grids[0].decode().expect("the code decodes")
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
    let (meta, text) = scanned(&svg);
    assert_eq!(meta.ecc_level, 3, "error correction level Q");
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

/// The first write of all can be lost too. Whether it landed or not, settling it leaves recovery
/// either on or ready to be turned on again, and the locator the kit names does not change.
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
    let origin = computer.origin();
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

/// KR-REQ-20.18: a step holds the lock a second companion on this machine would wait on, for as
/// long as it runs and no longer, so two companions never each draw a locator and commit a bundle
/// of their own.
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

/// KR-REQ-17.14: the account's token goes only to the service the account is signed in to. A sync
/// service setting that names another is refused with the setting named, and nothing is sent.
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
        computer.served.web().arrived().is_empty(),
        "nothing left this computer"
    );
    assert_eq!(page.view()["state"], "off", "nothing was made");

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
