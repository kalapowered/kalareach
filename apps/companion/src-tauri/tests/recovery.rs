//! Recovery, through the commands the page calls, against the sync service as a local Worker
//! answered it.
//!
//! KR-REQ-20.15 and 20.18: the recovery bundle is committed before a writer is declared
//! recovery-enabled, and bundle updates use the stable locator and compare-and-swap without
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
use companion_tauri::recovery::{Recovery, SEED_SCOPE};
use companion_tauri::sync_service::SyncService;
use kr_client::recovery::{BundleStore, parse_kit};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountToken, AccountTokenSource, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE,
    Client, IssuedGrant, RECOVERY_BACKUP_SCOPES, REQUESTED_SCOPES, RefreshToken, SignedInAccount,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, NullService, ServiceFuture, ServiceSigner,
    managed_response_limits,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{MemoryStore, store_recovery_seed};
use kr_protocol::archive::{RecoveryBundle, RecoveryContext, RecoveryKit, TrustedWriter};
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

/// What survives the application being closed: the service, the data directory, the secure store
/// and the device's key.
struct Computer {
    served: Served,
    data: tempfile::TempDir,
    secrets: Arc<MemoryStore>,
    key: AuthorisationKeyPair,
}

impl Computer {
    async fn new() -> Self {
        Self {
            served: serve().await,
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
            key: AuthorisationKeyPair::generate().expect("a key"),
        }
    }

    /// The origin of the sync service this computer can reach.
    fn origin(&self) -> GatewayOrigin {
        GatewayOrigin::new(self.served.origin()).expect("an origin")
    }

    /// The application, started over this computer's records, with `account` as its account.
    fn start(&self, account: Arc<Account>) -> Page {
        let service = Arc::new(SyncService::open(self.data.path()));
        let recovery = Arc::new(
            Recovery::open(
                self.data.path(),
                Arc::clone(&self.secrets) as _,
                self.key.clone(),
                Arc::clone(&service),
            )
            .expect("recovery opens"),
        );
        let state = AppState::new();
        state.sync_service_opened(service);
        state.recovery_opened(Arc::clone(&recovery));
        let app = mock_builder()
            .manage(state)
            .manage(AccountSlot::ready(Arc::clone(&account)))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::sync_service_view,
                companion_tauri::commands::sync_service_set,
                companion_tauri::commands::recovery_view,
                companion_tauri::commands::recovery_turn_on,
                companion_tauri::commands::recovery_settle,
                companion_tauri::commands::recovery_save_kit,
            ])
            .build(mock_context(noop_assets()))
            .expect("an application on the mock runtime");
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

    /// Saves the kit to a new file and reads it back.
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

/// A writer a test enrols: a fresh key, named the way a bundle names one.
fn a_writer() -> TrustedWriter {
    let key = AuthorisationKeyPair::generate().expect("a key");
    TrustedWriter {
        writer_key_id: key.key_id(),
        signing_key: *key.public(),
        enrolled_at_ms: TimestampMs::new(1_700_000_000_000),
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
    let (sequence, _) = web.bundle(&kit.bundle_locator).expect("the bundle is held");
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

/// KR-REQ-20.15: a writer is declared recovery-enabled only with the evidence that the bundle
/// naming it has landed, and a fresh device then reads the writer from the bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_is_declared_enabled_only_once_the_bundle_naming_it_has_landed() {
    let computer = Computer::new().await;
    let page = computer.page().await;
    page.call("recovery_turn_on", json!({})).expect("on");
    let out = tempfile::tempdir().expect("a directory");
    let (_, kit) = page.kit(out.path());

    let writer = a_writer();
    let enabled = page
        .recovery
        .enable_writer(&page.account, writer.clone())
        .await
        .expect("the writer is enabled");
    assert_eq!(enabled.writer_key_id(), writer.writer_key_id);
    assert_eq!(enabled.bundle_position().write_sequence, 2);

    // By the time the evidence exists, the bundle at the stand-in's locator is the one naming the
    // writer, under the same locator and without a new seed.
    let (sequence, _) = computer
        .served
        .web()
        .bundle(&kit.bundle_locator)
        .expect("the bundle");
    assert_eq!(sequence, 2);
    let bundle = read_with_only_the_kit(&computer.served, &kit).await;
    assert_eq!(bundle.revision.get(), 2);
    assert!(
        bundle
            .trusted_writers
            .iter()
            .any(|held| held.writer_key_id == writer.writer_key_id)
    );
}

/// KR-REQ-20.15: a write whose answer is lost declares nothing and holds back every other write
/// until it is settled, and a restart keeps that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_whose_answer_was_lost_blocks_the_next_until_it_is_settled() {
    for (moment, landed) in [(Moment::After, true), (Moment::Before, false)] {
        let computer = Computer::new().await;
        let page = computer.page().await;
        page.call("recovery_turn_on", json!({})).expect("on");
        let out = tempfile::tempdir().expect("a directory");
        let (_, kit) = page.kit(out.path());

        // The writer's bundle write is the second request to the route: a read, then the write.
        computer.served.web().fail(SYNC_PATH, 2, moment);
        let writer = a_writer();
        let lost = page
            .recovery
            .enable_writer(&page.account, writer.clone())
            .await
            .expect_err("no evidence without an answer");
        assert_eq!(lost.code, ErrorCode::OutcomeUnknown, "{moment:?}");
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
                .enable_writer(&page.account, a_writer())
                .await
                .expect_err("a write waits for the lost one");
            assert_eq!(blocked.code, ErrorCode::PermissionDenied, "{moment:?}");
            assert_eq!(
                writes_sent(&computer),
                before,
                "{moment:?}: nothing was sent"
            );
        }

        let settled = page
            .call("recovery_settle", json!({}))
            .expect("the lost write is settled");
        assert_eq!(settled["state"], "on", "{moment:?}");
        let bundle = read_with_only_the_kit(&computer.served, &kit).await;
        assert_eq!(
            bundle
                .trusted_writers
                .iter()
                .any(|held| held.writer_key_id == writer.writer_key_id),
            landed,
            "{moment:?}: the bundle names the writer only if the write landed"
        );

        // Settled, the next write goes, and a writer declared now is one the bundle names.
        let enabled = page
            .recovery
            .enable_writer(&page.account, writer.clone())
            .await
            .expect("the writer is enabled");
        assert_eq!(enabled.writer_key_id(), writer.writer_key_id);
        let bundle = read_with_only_the_kit(&computer.served, &kit).await;
        assert!(
            bundle
                .trusted_writers
                .iter()
                .any(|held| held.writer_key_id == writer.writer_key_id)
        );
    }
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
    std::fs::create_dir_all(computer.data.path().join("recovery")).expect("the directory");
    std::fs::write(
        computer.data.path().join("recovery").join("recovery.json"),
        format!(
            r#"{{"version":1,"service_origin":"{}","bundle_locator":"{LOCATOR}","kept":false}}"#,
            computer.served.origin()
        ),
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
        Arc::new(Installation(computer.key.clone())),
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
    let (sequence, _) = computer.served.web().bundle(LOCATOR).expect("the bundle");
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
    let (_, held) = computer.served.web().bundle(LOCATOR).expect("the bundle");

    let page = computer.page().await;
    page.call("recovery_turn_on", json!({}))
        .expect_err("the bundle is not this seed's");
    assert_eq!(page.view()["state"], "unfinished");
    let (sequence, still) = computer.served.web().bundle(LOCATOR).expect("the bundle");
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
