//! Deleting the account, through the commands the page calls.
//!
//! The companion runs on the mock runtime, its commands are called the way the page calls them,
//! and the account is the real one over a real store. The service's answers are the recorded ones
//! the client's own tests replay, over a scripted transport.
#![cfg(desktop)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use companion_tauri::AppState;
use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use companion_tauri::account::{Account, AccountSlot, AccountView};
use kr_client::error::ClientError;
use kr_client::services::account::deletion::ManagedAccountDeletion;
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountIdentity, AccountService, AccountToken, AccountUsage,
    AuthorisationGrant, Client, Exchanged, IssuedGrant, PendingAuthorisation, Redirect,
    RefreshToken, Refreshed, SignedInAccount, StoredGrant,
};
use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};
use kr_crypto::secret::SecretVec;
use kr_crypto::store::{MemoryStore, SecretName, SecretStore};
use kr_crypto::{CryptoError, Result as CryptoResult};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::service::GatewayOrigin;
use serde_json::{Value, json};
use tauri::test::{INVOKE_KEY, mock_builder, mock_context, noop_assets};
use tauri::webview::InvokeRequest;

const CODE: &str = "12345678";

/* ---- The recorded answers and the transport ------------------------------------------------ */

fn recorded(name: &str) -> ServiceHttpAnswer {
    let all: Value = serde_json::from_str(include_str!(
        "../../../../crates/kr-client/tests/fixtures/account-deletion/answers.json"
    ))
    .expect("fixtures");
    let one = &all[name];
    ServiceHttpAnswer {
        status: u16::try_from(one["status"].as_u64().expect("a status")).expect("a status"),
        body: serde_json::to_vec(&one["body"]).expect("json"),
    }
}

#[derive(Default)]
struct Wire {
    script: Mutex<VecDeque<ServiceHttpAnswer>>,
    bodies: Mutex<Vec<Value>>,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Wire")
    }
}

impl Wire {
    fn then(&self, names: &[&str]) {
        self.script
            .lock()
            .expect("script")
            .extend(names.iter().map(|name| recorded(name)));
    }

    fn answer(&self, body: &[u8]) -> Result<ServiceHttpAnswer, ClientError> {
        self.bodies
            .lock()
            .expect("bodies")
            .push(serde_json::from_slice(body).unwrap_or(Value::Null));
        self.script
            .lock()
            .expect("script")
            .pop_front()
            .ok_or_else(|| {
                ClientError::Host(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the answer was lost".to_owned(),
                ))
            })
    }
}

impl ServiceHttp for Wire {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.answer(body);
        Box::pin(async move { answer })
    }

    fn get_json<'a>(
        &'a self,
        _url: &'a str,
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.answer(b"");
        Box::pin(async move { answer })
    }
}

/* ---- The account --------------------------------------------------------------------------- */

#[derive(Debug, Default)]
struct Service {
    ends: AtomicBool,
}

impl AccountService for Service {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { Ok(Exchanged::Refused { leftover: None }) })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        let ends = self.ends.load(Ordering::SeqCst);
        Box::pin(async move {
            if ends {
                Ok(Refreshed::Ended)
            } else {
                Ok(Refreshed::Rotated(issued("rotated")))
            }
        })
    }

    fn revoke<'a>(&'a self, _refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        Box::pin(async {
            Ok(AccountIdentity {
                subject: "account-1".to_owned(),
                email: Some("sam@example.com".to_owned()),
                name: None,
            })
        })
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async { Ok(AccountUsage::default()) })
    }
}

fn issued(refresh: &str) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new("an-access-token").expect("a token"),
        expires_in_seconds: 600,
        refresh_token: RefreshToken::new(refresh).expect("a token"),
        scopes: vec!["openid".to_owned(), "voice".to_owned()],
        subject: "account-1".to_owned(),
    }
}

/// A browser that is there: the device can sign in, so a signed-out device reads as signed out.
struct Present;

impl Carrier for Present {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async {
            Ok(Plan {
                redirect: Redirect::Loopback,
            })
        })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        _url: String,
        _pending: &'a mut PendingAuthorisation,
        _cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async { Ending::Cancelled })
    }
}

/// A store that refuses to delete the stored sign-in for as long as it is told to, and, when told
/// to, to keep the deletion record.
struct Flaky {
    inner: MemoryStore,
    fail: AtomicBool,
    refuse_record: AtomicBool,
}

impl SecretStore for Flaky {
    fn get(&self, name: &SecretName) -> CryptoResult<Option<SecretVec>> {
        self.inner.get(name)
    }

    fn set(&self, name: &SecretName, value: &[u8]) -> CryptoResult<()> {
        if name.as_str() == "account/deletion" && self.refuse_record.load(Ordering::SeqCst) {
            return Err(CryptoError::SecretStore {
                message: "the disk refused".to_owned(),
            });
        }
        self.inner.set(name, value)
    }

    fn delete(&self, name: &SecretName) -> CryptoResult<()> {
        if name.as_str() == "account/session" && self.fail.load(Ordering::SeqCst) {
            return Err(CryptoError::SecretStore {
                message: "the disk refused".to_owned(),
            });
        }
        self.inner.delete(name)
    }

    fn describe(&self) -> String {
        "a flaky store".to_owned()
    }
}

struct Rig {
    account: Arc<Account>,
    wire: Arc<Wire>,
    service: Arc<Service>,
    store: Arc<dyn SecretStore>,
    views: Arc<Mutex<Vec<AccountView>>>,
}

fn origin() -> GatewayOrigin {
    GatewayOrigin::new(ACCOUNT_ORIGIN).expect("an origin")
}

async fn rig_over(store: Arc<dyn SecretStore>, wire: Arc<Wire>) -> Rig {
    let service = Arc::new(Service::default());
    let signed_in = Arc::new(SignedInAccount::new(
        Arc::clone(&service) as Arc<dyn AccountService>,
        Arc::clone(&store),
        Client::Desktop,
    ));
    if !signed_in.status().is_ok_and(|status| {
        matches!(
            status,
            kr_client::services::account::AccountStatus::SignedIn { .. }
        )
    }) {
        signed_in
            .commit(issued("first"), "a-nonce")
            .await
            .expect("the sign-in is kept");
    }
    let views: Arc<Mutex<Vec<AccountView>>> = Arc::default();
    let published = Arc::clone(&views);
    let deletion = Arc::new(ManagedAccountDeletion::new(
        &origin(),
        Arc::clone(&wire) as Arc<dyn ServiceHttp>,
        Arc::clone(&signed_in),
    ));
    let account = Arc::new(Account::new(
        signed_in,
        Arc::clone(&service) as Arc<dyn AccountService>,
        origin(),
        Arc::new(Present),
        Arc::new(move |view| published.lock().expect("views").push(view.clone())),
        deletion,
    ));
    Rig {
        account,
        wire,
        service,
        store,
        views,
    }
}

async fn rig() -> Rig {
    rig_over(Arc::new(MemoryStore::new()), Arc::new(Wire::default())).await
}

/// Calls `command` as the page does, with `args`, and returns the page's answer.
fn invoke(account: &Arc<Account>, command: &str, args: Value) -> Value {
    let app = mock_builder()
        .manage(AccountSlot::ready(Arc::clone(account)))
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            companion_tauri::commands::account_status,
            companion_tauri::commands::account_deletion_view,
            companion_tauri::commands::account_deletion_send_code,
            companion_tauri::commands::account_deletion_confirm,
            companion_tauri::commands::account_deletion_status,
            companion_tauri::commands::account_deletion_forget,
        ])
        .build(mock_context(noop_assets()))
        .expect("an application on the mock runtime");
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("a window");
    tauri::test::get_ipc_response(
        &webview,
        InvokeRequest {
            cmd: command.to_owned(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            url: "tauri://localhost".parse().expect("the bundled origin"),
            body: tauri::ipc::InvokeBody::Json(args),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_owned(),
        },
    )
    .map(|body| body.deserialize::<Value>().expect("json"))
    .unwrap_or_else(|error| json!({ "refused": error }))
}

fn session(rig: &Rig) -> bool {
    rig.store
        .get(&SecretName::new("account/session").expect("a name"))
        .expect("a read")
        .is_some()
}

/* ---- The cases ----------------------------------------------------------------------------- */

#[tokio::test(flavor = "multi_thread")]
async fn the_page_reads_asks_and_confirms_and_the_device_is_signed_out_when_the_account_closes() {
    let rig = rig().await;
    rig.wire
        .then(&["preview", "code_sent", "confirm_closed_closing"]);
    let account = Arc::clone(&rig.account);
    let run = move |command: &'static str, args: Value| {
        let account = Arc::clone(&account);
        tokio::task::spawn_blocking(move || invoke(&account, command, args))
    };

    let view = run("account_deletion_view", json!({}))
        .await
        .expect("joined");
    assert_eq!(view["state"], "ready");
    assert_eq!(view["preview"]["kept_records_years"], 7);
    let sent = run("account_deletion_send_code", json!({}))
        .await
        .expect("joined");
    assert_eq!(sent["state"], "sent");

    let confirmed = run(
        "account_deletion_confirm",
        json!({ "code": CODE, "acknowledged": [] }),
    )
    .await
    .expect("joined");
    assert_eq!(confirmed["state"], "closed");
    assert_eq!(confirmed["finished"], false);

    // The device stands signed out, with no sign-out message beside it, and the page was told.
    assert!(!session(&rig));
    let status = run("account_status", json!({})).await.expect("joined");
    assert_eq!(status["state"], "signed_out");
    assert_eq!(status["outcome"], Value::Null);
    let told = rig.views.lock().expect("views").clone();
    assert_eq!(
        told.last(),
        Some(&AccountView::SignedOut { outcome: None }),
        "{told:?}"
    );

    // Nothing the page could read carries a token, the address or the receipt.
    let all = [&view, &sent, &confirmed].map(Value::to_string).join(" ");
    let receipt = rig.wire.bodies.lock().expect("bodies")[2]["receipt"]
        .as_str()
        .expect("a receipt")
        .to_owned();
    for secret in ["an-access-token", CODE, receipt.as_str()] {
        assert!(!all.contains(secret), "{secret} in {all}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_cannot_name_a_receipt_and_a_refused_code_leaves_the_sign_in() {
    let rig = rig().await;
    rig.wire.then(&["confirm_wrong"]);
    let account = Arc::clone(&rig.account);
    let answer = tokio::task::spawn_blocking(move || {
        invoke(
            &account,
            "account_deletion_confirm",
            json!({ "code": CODE, "acknowledged": [], "receipt": "a".repeat(32) }),
        )
    })
    .await
    .expect("joined");
    assert_eq!(answer["state"], "code_refused");
    assert_eq!(answer["reason"], "wrong");
    assert_eq!(answer["attempts_left"], 4);
    assert!(session(&rig), "the sign-in stays");
    let sent = rig.wire.bodies.lock().expect("bodies")[0].clone();
    assert_ne!(
        sent["receipt"],
        "a".repeat(32),
        "the receipt is the backend's own"
    );
    assert!(
        rig.store
            .get(&SecretName::new("account/deletion").expect("a name"))
            .expect("a read")
            .is_none(),
        "a request that did nothing leaves no receipt behind"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_the_service_ended_is_told_as_a_problem_and_the_device_reads_as_ended() {
    let rig = rig().await;
    rig.service.ends.store(true, Ordering::SeqCst);
    rig.wire.then(&["unauthenticated", "status_unknown"]);
    let account = Arc::clone(&rig.account);
    let answer = tokio::task::spawn_blocking(move || {
        invoke(&account, "account_deletion_send_code", json!({}))
    })
    .await
    .expect("joined");
    assert_eq!(answer["state"], "problem");
    assert_eq!(answer["problem"]["kind"], "needs_sign_in");
    let account = Arc::clone(&rig.account);
    let status = tokio::task::spawn_blocking(move || invoke(&account, "account_status", json!({})))
        .await
        .expect("joined");
    assert_eq!(status["state"], "ended");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_after_an_interrupted_ending_finishes_it_before_the_first_view() {
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail: AtomicBool::new(true),
        refuse_record: AtomicBool::new(false),
    });
    let wire = Arc::new(Wire::default());
    wire.then(&["confirm_closed_closing"]);
    let first = rig_over(
        Arc::clone(&flaky) as Arc<dyn SecretStore>,
        Arc::clone(&wire),
    )
    .await;
    let account = Arc::clone(&first.account);
    let answer = tokio::task::spawn_blocking(move || {
        invoke(
            &account,
            "account_deletion_confirm",
            json!({ "code": CODE, "acknowledged": [] }),
        )
    })
    .await
    .expect("joined");
    assert_eq!(
        answer["state"], "closed",
        "the person is told whatever the disk did"
    );
    assert!(
        session(&first),
        "the disk refused, so the grant is still here"
    );

    // A start, once the disk works again: the account is built again over the same store.
    flaky.fail.store(false, Ordering::SeqCst);
    let second = rig_over(
        Arc::clone(&flaky) as Arc<dyn SecretStore>,
        Arc::new(Wire::default()),
    )
    .await;
    second.account.start().await;
    assert!(!session(&second), "the start ended the grant");
    let told = second.views.lock().expect("views").clone();
    assert_eq!(
        told.first(),
        Some(&AccountView::SignedOut { outcome: None })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_status_asked_after_a_lost_answer_says_it_is_unsettled_and_nothing_is_shown_for_no_deletion()
 {
    let rig = rig().await;
    let account = Arc::clone(&rig.account);
    let nothing =
        tokio::task::spawn_blocking(move || invoke(&account, "account_deletion_status", json!({})))
            .await
            .expect("joined");
    assert_eq!(nothing["state"], "none");

    // The confirmation's answer is lost and the receipt knows nothing of it yet.
    let account = Arc::clone(&rig.account);
    let confirmed = tokio::task::spawn_blocking(move || {
        invoke(
            &account,
            "account_deletion_confirm",
            json!({ "code": CODE, "acknowledged": [] }),
        )
    })
    .await
    .expect("joined");
    assert_eq!(confirmed["state"], "unsettled");
    rig.wire.then(&["status_unknown"]);
    let account = Arc::clone(&rig.account);
    let status =
        tokio::task::spawn_blocking(move || invoke(&account, "account_deletion_status", json!({})))
            .await
            .expect("joined");
    assert_eq!(status["state"], "unsettled");
    assert!(
        session(&rig),
        "an unsettled request does not end the sign-in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_person_can_give_up_on_a_confirmation_that_has_no_answer() {
    let rig = rig().await;
    let account = Arc::clone(&rig.account);
    let confirmed = tokio::task::spawn_blocking(move || {
        invoke(
            &account,
            "account_deletion_confirm",
            json!({ "code": CODE, "acknowledged": [] }),
        )
    })
    .await
    .expect("joined");
    assert_eq!(confirmed["state"], "unsettled");

    let account = Arc::clone(&rig.account);
    let given_up =
        tokio::task::spawn_blocking(move || invoke(&account, "account_deletion_forget", json!({})))
            .await
            .expect("joined");
    assert_eq!(given_up["state"], "none");
    let account = Arc::clone(&rig.account);
    let status =
        tokio::task::spawn_blocking(move || invoke(&account, "account_deletion_status", json!({})))
            .await
            .expect("joined");
    assert_eq!(status["state"], "none");
    assert!(session(&rig), "the sign-in is as it was");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_of_the_devices_own_records_tells_the_page_nothing_it_must_not_have() {
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail: AtomicBool::new(false),
        refuse_record: AtomicBool::new(true),
    });
    let rig = rig_over(
        Arc::clone(&flaky) as Arc<dyn SecretStore>,
        Arc::new(Wire::default()),
    )
    .await;
    let account = Arc::clone(&rig.account);
    let answer = tokio::task::spawn_blocking(move || {
        invoke(
            &account,
            "account_deletion_confirm",
            json!({ "code": CODE, "acknowledged": [] }),
        )
    })
    .await
    .expect("joined");
    // The device could not keep the receipt, so nothing was sent and the page is told it failed.
    assert!(answer.get("refused").is_some(), "{answer}");
    assert!(rig.wire.bodies.lock().expect("bodies").is_empty());
    let told = answer.to_string();
    for secret in ["an-access-token", "first", CODE] {
        assert!(!told.contains(secret), "{secret} in {told}");
    }
}
