//! Deleting the signed-in account: what the client sends, what it makes of every answer the service
//! gives, and what it keeps so that a lost answer can be settled.
//!
//! The service's answers are the recorded ones in `tests/fixtures/account-deletion/answers.json`,
//! replayed over a scripted transport; the account is the real `SignedInAccount` over a real store.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::services::account::deletion::{
    CLOSED_FOR_MS, CodeRefusal, DeletionFault, DeletionOutcome, DeletionProgress, DeletionRead,
    DeletionWarning, DeviceSteps, ManagedAccountDeletion, StepFuture, UNSETTLED_FOR_MS,
};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountIdentity, AccountService, AccountStatus, AccountToken, AccountUsage,
    AuthorisationGrant, Client, Exchanged, IssuedGrant, RefreshToken, Refreshed, SignedInAccount,
    StoredGrant,
};
use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};
use kr_crypto::secret::SecretVec;
use kr_crypto::store::{MemoryStore, SecretName, SecretStore};
use kr_crypto::{CryptoError, Result as CryptoResult};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::service::GatewayOrigin;

/* ---- The recorded answers ------------------------------------------------------------------ */

fn answers() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/account-deletion/answers.json")).expect("fixtures")
}

/// One recorded answer: its status and body.
fn recorded(name: &str) -> Step {
    let all = answers();
    let one = &all[name];
    let status = u16::try_from(one["status"].as_u64().expect("a status")).expect("a status");
    let body = match one.get("body_text") {
        Some(text) => text.as_str().expect("text").as_bytes().to_vec(),
        None => serde_json::to_vec(&one["body"]).expect("json"),
    };
    Step::Answer(ServiceHttpAnswer { status, body })
}

/* ---- The transport ------------------------------------------------------------------------- */

enum Step {
    Answer(ServiceHttpAnswer),
    /// The request left and nothing came back.
    Lost,
}

#[derive(Clone, Debug)]
struct Seen {
    method: &'static str,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

type Peek = Box<dyn Fn() + Send + Sync>;

/// Holds the next request to a path until the test lets it go, so that another call can run while
/// the request is out.
struct Gate {
    path: &'static str,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct Wire {
    script: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    peek: Mutex<Option<Peek>>,
    gate: Mutex<Option<Gate>>,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Wire")
    }
}

impl Wire {
    fn then(&self, steps: impl IntoIterator<Item = Step>) {
        self.script.lock().expect("script").extend(steps);
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    /// Holds the next request to `path`: the first handle says it has arrived, the second lets it go.
    fn hold_next(
        &self,
        path: &'static str,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *self.gate.lock().expect("gate") = Some(Gate {
            path,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn take_gate(&self, url: &str) -> Option<Gate> {
        let mut gate = self.gate.lock().expect("gate");
        if gate
            .as_ref()
            .is_some_and(|held| url == format!("{ACCOUNT_ORIGIN}{}", held.path))
        {
            gate.take()
        } else {
            None
        }
    }

    fn answer(
        &self,
        method: &'static str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> std::result::Result<ServiceHttpAnswer, ClientError> {
        if let Some(peek) = self.peek.lock().expect("peek").as_ref() {
            peek();
        }
        self.seen.lock().expect("seen").push(Seen {
            method,
            url: url.to_owned(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: body.to_vec(),
        });
        match self.script.lock().expect("script").pop_front() {
            Some(Step::Answer(answer)) => Ok(answer),
            Some(Step::Lost) | None => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                "the answer was lost".to_owned(),
            ))),
        }
    }
}

impl ServiceHttp for Wire {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.answer("POST", url, headers, body);
        let gate = self.take_gate(url);
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            answer
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.answer("GET", url, headers, b"");
        let gate = self.take_gate(url);
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            answer
        })
    }
}

/* ---- The account --------------------------------------------------------------------------- */

#[derive(Default)]
struct Service {
    refreshes: AtomicU64,
    revoked: Mutex<Vec<String>>,
    /// Whether a refresh ends the sign-in.
    ends: Mutex<bool>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Service")
    }
}

fn issued(subject: &str, refresh: &str) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new("an-access-token").expect("a token"),
        expires_in_seconds: 600,
        refresh_token: RefreshToken::new(refresh).expect("a token"),
        scopes: vec!["openid".to_owned(), "voice".to_owned()],
        subject: subject.to_owned(),
    }
}

impl AccountService for Service {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { Ok(Exchanged::Refused { leftover: None }) })
    }

    fn refresh<'a>(&'a self, stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        let ends = *self.ends.lock().expect("ends");
        let count = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
        let subject = stored.subject().to_owned();
        Box::pin(async move {
            if ends {
                Ok(Refreshed::Ended)
            } else {
                Ok(Refreshed::Rotated(issued(
                    &subject,
                    &format!("rotated-{count}"),
                )))
            }
        })
    }

    fn revoke<'a>(&'a self, refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        self.revoked
            .lock()
            .expect("revoked")
            .push(refresh.expose().to_owned());
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

const NOW: u64 = 1_790_251_200_000;
static CLOCK_MS: AtomicU64 = AtomicU64::new(NOW);

/// Serialises the tests, which share one clock.
static CLOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn clock_ms() -> u64 {
    CLOCK_MS.load(Ordering::SeqCst)
}

fn at(ms_after: u64) {
    CLOCK_MS.store(NOW + ms_after, Ordering::SeqCst);
}

/// A store that refuses to delete the stored sign-in once, as a failing disk does.
struct Flaky {
    inner: MemoryStore,
    fail_session_delete: Mutex<bool>,
    /// Whether a write of the deletion record is refused, as a failing disk does.
    fail_record_write: Mutex<Option<u32>>,
}

impl std::fmt::Debug for Flaky {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Flaky")
    }
}

impl SecretStore for Flaky {
    fn get(&self, name: &SecretName) -> CryptoResult<Option<SecretVec>> {
        self.inner.get(name)
    }

    fn set(&self, name: &SecretName, value: &[u8]) -> CryptoResult<()> {
        if name.as_str() == "account/deletion" {
            let mut allowed = self.fail_record_write.lock().expect("flaky");
            match *allowed {
                Some(0) => {
                    return Err(CryptoError::SecretStore {
                        message: "the disk refused".to_owned(),
                    });
                }
                Some(left) => *allowed = Some(left - 1),
                None => {}
            }
        }
        self.inner.set(name, value)
    }

    fn delete(&self, name: &SecretName) -> CryptoResult<()> {
        let mut fail = self.fail_session_delete.lock().expect("flaky");
        if *fail && name.as_str() == "account/session" {
            *fail = false;
            return Err(CryptoError::SecretStore {
                message: "the disk refused".to_owned(),
            });
        }
        drop(fail);
        self.inner.delete(name)
    }

    fn describe(&self) -> String {
        "a flaky store".to_owned()
    }
}

struct Rig {
    store: Arc<dyn SecretStore>,
    service: Arc<Service>,
    account: Arc<SignedInAccount>,
    wire: Arc<Wire>,
    deletion: ManagedAccountDeletion,
}

fn origin() -> GatewayOrigin {
    GatewayOrigin::new(ACCOUNT_ORIGIN).expect("an origin")
}

fn deletion(account: &Arc<SignedInAccount>, wire: &Arc<Wire>) -> ManagedAccountDeletion {
    ManagedAccountDeletion::new(
        &origin(),
        Arc::clone(wire) as Arc<dyn ServiceHttp>,
        Arc::clone(account),
    )
    .looking_every(Duration::ZERO)
}

async fn rig_over(store: Arc<dyn SecretStore>) -> Rig {
    at(0);
    let service = Arc::new(Service::default());
    let account = Arc::new(
        SignedInAccount::new(
            Arc::clone(&service) as Arc<dyn AccountService>,
            Arc::clone(&store),
            Client::Desktop,
        )
        .with_clock(clock_ms),
    );
    account
        .commit(issued("account-1", "first"), "a-nonce")
        .await
        .expect("a sign-in is kept");
    let wire = Arc::new(Wire::default());
    let deletion = deletion(&account, &wire);
    Rig {
        store,
        service,
        account,
        wire,
        deletion,
    }
}

async fn new_rig() -> Rig {
    rig_over(Arc::new(MemoryStore::new())).await
}

fn item(store: &Arc<dyn SecretStore>, name: &str) -> Option<serde_json::Value> {
    store
        .get(&SecretName::new(name).expect("a name"))
        .expect("a read")
        .map(|bytes| serde_json::from_slice(bytes.expose()).expect("json"))
}

fn session(rig: &Rig) -> bool {
    item(&rig.store, "account/session").is_some()
}

fn record(rig: &Rig) -> Option<serde_json::Value> {
    item(&rig.store, "account/deletion")
}

const CODE: &str = "12345678";

/// The application's device steps, scripted: how often each ran, and whether each says it is done.
struct Steps {
    notifications: AtomicU64,
    recovery: AtomicU64,
    notifications_done: Mutex<bool>,
    recovery_done: Mutex<bool>,
    /// Whether a step gives up its turn once it is running, so that a second caller could run.
    yields: bool,
}

impl Steps {
    fn new(notifications_done: bool, recovery_done: bool) -> Self {
        Self {
            notifications: AtomicU64::new(0),
            recovery: AtomicU64::new(0),
            notifications_done: Mutex::new(notifications_done),
            recovery_done: Mutex::new(recovery_done),
            yields: false,
        }
    }

    fn ran(&self) -> (u64, u64) {
        (
            self.notifications.load(Ordering::SeqCst),
            self.recovery.load(Ordering::SeqCst),
        )
    }
}

impl DeviceSteps for Steps {
    fn notifications(&self) -> StepFuture<'_> {
        Box::pin(async move {
            self.notifications.fetch_add(1, Ordering::SeqCst);
            if self.yields {
                tokio::task::yield_now().await;
            }
            *self.notifications_done.lock().expect("done")
        })
    }

    fn recovery(&self) -> StepFuture<'_> {
        Box::pin(async move {
            self.recovery.fetch_add(1, Ordering::SeqCst);
            if self.yields {
                tokio::task::yield_now().await;
            }
            *self.recovery_done.lock().expect("done")
        })
    }
}

fn path_of(seen: &Seen) -> String {
    seen.url.replacen(ACCOUNT_ORIGIN, "", 1)
}

fn body_of(seen: &Seen) -> serde_json::Value {
    serde_json::from_slice(&seen.body).expect("a json body")
}

/// The receipts the confirmations carried over `wire`, in the order they left.
fn receipts(wire: &Wire) -> Vec<String> {
    wire.seen()
        .iter()
        .filter(|each| each.method == "POST" && path_of(each) == "/api/account/deletion")
        .map(|each| {
            body_of(each)["receipt"]
                .as_str()
                .expect("a receipt")
                .to_owned()
        })
        .collect()
}

/// The receipt the next confirmation of `rig` carries, which the service answers by refusing the code.
async fn next_receipt(rig: &Rig) -> String {
    rig.wire.then([recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    receipts(&rig.wire).pop().expect("a receipt")
}

/* ---- What would happen --------------------------------------------------------------------- */

#[tokio::test]
async fn the_preview_is_read_with_everything_it_lists_and_the_figures_the_words_follow() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("preview_with_warnings")]);
    let DeletionRead::Ready(preview) = rig.deletion.preview().await.expect("a preview") else {
        panic!("a preview to show");
    };
    assert_eq!(preview.address, "r***@ts.org");
    assert_eq!(preview.deleted.len(), 8);
    assert_eq!(preview.kept.len(), 9);
    assert!(!preview.unlisted);
    assert_eq!(preview.kept_records_years, 7);
    assert_eq!(preview.backup_file_days, 7);
    assert_eq!(preview.code_lifetime_minutes, 5);
    assert_eq!(preview.warnings.len(), 4);
    assert!(matches!(
        &preview.warnings[0],
        DeletionWarning::OrganisationOwner { name, members: 4, .. } if name == "Acme"
    ));
    assert_eq!(
        preview.warnings[1..],
        [
            DeletionWarning::Subscription,
            DeletionWarning::Credit,
            DeletionWarning::MoneyOwed
        ]
    );
}

#[tokio::test]
async fn a_key_it_has_no_words_for_is_flagged_and_a_warning_or_choice_it_does_not_know_stops_the_flow()
 {
    let _clock = CLOCK.lock().await;
    for (answer, expect_unlisted) in [
        ("preview_unknown_deleted_key", true),
        ("preview_unknown_kept_key", true),
    ] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer)]);
        let DeletionRead::Ready(preview) = rig.deletion.preview().await.expect("a preview") else {
            panic!("{answer} is shown");
        };
        assert_eq!(preview.unlisted, expect_unlisted, "{answer}");
    }
    for answer in [
        "preview_unknown_warning",
        "preview_unknown_choice",
        "preview_extra_choice",
    ] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer)]);
        assert_eq!(
            rig.deletion.preview().await.expect("an answer"),
            DeletionRead::CannotShow,
            "{answer}"
        );
    }
}

/* ---- What is sent -------------------------------------------------------------------------- */

#[tokio::test]
async fn every_request_carries_the_bearer_and_no_cookie_and_the_status_carries_no_credential() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([
        recorded("preview"),
        recorded("code_sent"),
        recorded("confirm_closed_closing"),
    ]);
    rig.deletion.preview().await.expect("a preview");
    rig.deletion.send_code().await.expect("a code");
    rig.deletion
        .confirm(CODE, &[])
        .await
        .expect("a confirmation");
    rig.wire.then([recorded("status_open")]);
    rig.deletion.status().await.expect("a status");

    let seen = rig.wire.seen();
    assert_eq!(
        seen.iter()
            .map(|each| (each.method, path_of(each)))
            .collect::<Vec<_>>(),
        [
            ("GET", "/api/account/deletion".to_owned()),
            ("POST", "/api/account/deletion/code".to_owned()),
            ("POST", "/api/account/deletion".to_owned()),
            ("POST", "/api/account/deletion/status".to_owned()),
        ]
    );
    for each in &seen[..3] {
        let names: Vec<&str> = each.headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["authorization"], "{}", each.url);
        assert!(each.headers[0].1.starts_with("Bearer "));
    }
    assert!(
        seen[3].headers.is_empty(),
        "the status route takes no credential"
    );

    let confirm = body_of(&seen[2]);
    let keys: Vec<&str> = confirm
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["code", "receipt"]);
    assert_eq!(confirm["code"], CODE);
    let receipt = confirm["receipt"].as_str().expect("a receipt");
    assert_eq!(receipt.len(), 32);
    assert!(
        receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        body_of(&seen[3])["receipt"],
        receipt,
        "the status asks by the same receipt"
    );
}

#[tokio::test]
async fn organisations_are_acknowledged_by_id_and_a_fifty_first_is_not_sent() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([
        recorded("confirm_acknowledge"),
        recorded("confirm_closed_deleted"),
    ]);
    let DeletionOutcome::Acknowledge { organisations } =
        rig.deletion.confirm(CODE, &[]).await.expect("an answer")
    else {
        panic!("an acknowledgement is asked for");
    };
    assert_eq!(organisations[0].name, "Acme");
    let ids = vec!["org-1".to_owned()];
    rig.deletion.confirm(CODE, &ids).await.expect("closed");
    assert_eq!(
        body_of(&rig.wire.seen()[1])["acknowledged"],
        serde_json::json!(["org-1"])
    );

    let too_many: Vec<String> = (0..51).map(|each| format!("org-{each}")).collect();
    let before = rig.wire.seen().len();
    assert_eq!(
        rig.deletion.confirm(CODE, &too_many).await,
        Err(DeletionFault::Refused)
    );
    assert_eq!(rig.wire.seen().len(), before, "nothing was sent");
    assert_eq!(
        rig.deletion.confirm("1234", &[]).await,
        Err(DeletionFault::Refused)
    );
}

#[tokio::test]
async fn the_record_is_in_the_store_when_the_confirmation_leaves() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let store = Arc::clone(&rig.store);
    let found = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&found);
    *rig.wire.peek.lock().expect("peek") = Some(Box::new(move || {
        keep.lock()
            .expect("found")
            .push(item(&store, "account/deletion"));
    }));
    rig.wire.then([recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    let at_send = found.lock().expect("found")[0]
        .clone()
        .expect("a record before the request left");
    let sent = body_of(&rig.wire.seen()[0]);
    assert_eq!(at_send["receipt"], sent["receipt"]);
}

/* ---- What the answers mean ----------------------------------------------------------------- */

#[tokio::test]
async fn the_code_routes_answers_are_told_apart() {
    let _clock = CLOCK.lock().await;
    for (answer, expect) in [
        (
            "code_rate_limited",
            Err(DeletionFault::Busy { seconds: 900 }),
        ),
        ("code_mail_failed", Err(DeletionFault::MailFailed)),
        ("internal", Err(DeletionFault::Unsure)),
        ("gateway_page", Err(DeletionFault::Unsure)),
        ("forbidden", Err(DeletionFault::Refused)),
        ("code_sent", Ok(())),
    ] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer)]);
        assert_eq!(rig.deletion.send_code().await, expect, "{answer}");
    }
    let rig = new_rig().await;
    rig.wire.then([Step::Lost]);
    assert_eq!(rig.deletion.send_code().await, Err(DeletionFault::Unsure));
}

#[tokio::test]
async fn a_code_the_service_refuses_changes_nothing_and_says_why() {
    let _clock = CLOCK.lock().await;
    for (answer, reason, left) in [
        ("confirm_wrong", CodeRefusal::Wrong, 4),
        ("confirm_expired", CodeRefusal::Expired, 0),
        ("confirm_spent", CodeRefusal::Spent, 0),
    ] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer)]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::CodeRefused {
                reason,
                attempts_left: left
            })
        );
        assert!(session(&rig), "the sign-in stays");
        assert_eq!(rig.wire.seen().len(), 1);
    }
}

#[tokio::test]
async fn a_closed_account_ends_the_stored_sign_in_with_no_call_to_revoke_it() {
    let _clock = CLOCK.lock().await;
    for (answer, finished) in [
        ("confirm_closed_deleted", true),
        ("confirm_closed_closing", false),
    ] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer)]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::Closed { finished })
        );
        assert!(!session(&rig), "the grant is gone");
        assert!(
            rig.service.revoked.lock().expect("revoked").is_empty(),
            "nothing is revoked"
        );
        assert!(
            rig.wire
                .seen()
                .iter()
                .all(|each| !path_of(each).contains("revoke"))
        );
        assert_eq!(
            rig.account.status().expect("a status"),
            AccountStatus::SignedOut
        );
        assert!(
            record(&rig).is_some(),
            "the record stays until the device has settled"
        );
        assert_eq!(
            rig.deletion.settle().await,
            Ok(true),
            "the application still has its own state to settle"
        );
    }
}

#[tokio::test]
async fn a_different_account_signed_in_meanwhile_is_not_ended_and_does_not_borrow_the_receipt() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Unsettled)
    );
    let first = body_of(&rig.wire.seen()[0])["receipt"].clone();

    // Another account signs in; its confirmation makes a receipt of its own.
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    rig.wire
        .then([recorded("preview"), recorded("confirm_wrong")]);
    rig.deletion.preview().await.expect("a preview");
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    let second = body_of(rig.wire.seen().last().expect("a request"))["receipt"].clone();
    assert_ne!(first, second);
    assert!(session(&rig), "the second account's sign-in is untouched");

    // A deletion that began for the first account refuses the second's token. Control: the same
    // calls for the account it began for go through.
    let rig = new_rig().await;
    rig.wire.then([recorded("preview")]);
    rig.deletion.preview().await.expect("a preview");
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    let before = rig.wire.seen().len();
    assert_eq!(
        rig.deletion.send_code().await,
        Err(DeletionFault::AccountChanged)
    );
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::AccountChanged)
    );
    assert_eq!(
        rig.wire.seen().len(),
        before,
        "nothing was sent for another account"
    );
}

#[tokio::test]
async fn a_receipt_the_service_says_is_taken_is_replaced_once() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([
        recorded("confirm_receipt_taken"),
        recorded("confirm_closed_deleted"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Closed { finished: true })
    );
    let seen = rig.wire.seen();
    assert_ne!(body_of(&seen[0])["receipt"], body_of(&seen[1])["receipt"]);

    let rig = new_rig().await;
    rig.wire.then([
        recorded("confirm_receipt_taken"),
        recorded("confirm_receipt_taken"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::Refused)
    );
    assert_eq!(rig.wire.seen().len(), 2, "one resend and no more");
}

#[tokio::test]
async fn a_rate_limit_and_a_malformed_request_change_nothing() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([
        recorded("confirm_rate_limited"),
        recorded("confirm_malformed"),
        recorded("confirm_malformed"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::Busy { seconds: 300 })
    );
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::Refused)
    );
    assert!(session(&rig));
}

/* ---- A dead sign-in ------------------------------------------------------------------------ */

#[tokio::test]
async fn a_refused_token_is_renewed_once_and_a_sign_in_that_cannot_be_renewed_ends() {
    let _clock = CLOCK.lock().await;
    // Renewed once, and the second try answers.
    let rig = new_rig().await;
    rig.wire
        .then([recorded("unauthenticated"), recorded("preview")]);
    assert!(matches!(
        rig.deletion.preview().await,
        Ok(DeletionRead::Ready(_))
    ));
    assert_eq!(rig.service.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(rig.wire.seen().len(), 2);

    // Refused twice: no third send.
    let rig = new_rig().await;
    rig.wire.then([
        recorded("unauthenticated"),
        recorded("unauthenticated"),
        recorded("preview"),
    ]);
    assert_eq!(
        rig.deletion.preview().await,
        Err(DeletionFault::NeedsSignIn)
    );
    assert_eq!(rig.wire.seen().len(), 2);

    // The service ended the sign-in: the renewal ends it here.
    let rig = new_rig().await;
    *rig.service.ends.lock().expect("ends") = true;
    rig.wire.then([recorded("unauthenticated")]);
    assert_eq!(
        rig.deletion.preview().await,
        Err(DeletionFault::NeedsSignIn)
    );
    assert_eq!(
        rig.account.status().expect("a status"),
        AccountStatus::Ended
    );
}

/* ---- A lost answer ------------------------------------------------------------------------- */

#[tokio::test]
async fn a_confirmation_whose_answer_was_lost_is_settled_by_its_receipt() {
    let _clock = CLOCK.lock().await;
    // Every way an answer goes missing, then the receipt says the account is closed.
    for lost in [
        Step::Lost,
        recorded("confirm_unavailable"),
        recorded("internal"),
        recorded("gateway_page"),
        recorded("confirm_unknown_result"),
    ] {
        let rig = new_rig().await;
        rig.wire.then([lost, recorded("status_open")]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::Closed { finished: false })
        );
        let seen = rig.wire.seen();
        assert_eq!(path_of(&seen[1]), "/api/account/deletion/status");
        assert_eq!(body_of(&seen[1])["receipt"], body_of(&seen[0])["receipt"]);
        assert!(
            !session(&rig),
            "closure learned by receipt ends the sign-in too"
        );
    }

    // The receipt knows nothing of it: the person is told so, and the record waits.
    let rig = new_rig().await;
    rig.wire.then([
        Step::Lost,
        recorded("status_unknown"),
        recorded("status_unknown"),
        recorded("status_unknown"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Unsettled)
    );
    assert!(
        session(&rig),
        "an unsettled request does not end the sign-in"
    );
    assert!(record(&rig).is_some(), "the record is kept");
    assert_eq!(
        rig.deletion.settle().await,
        Ok(false),
        "an account not known to be closed has nothing to settle"
    );

    // A retry reuses the receipt, and the service takes it.
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    let seen = rig.wire.seen();
    assert_eq!(
        body_of(&seen[0])["receipt"],
        body_of(seen.last().expect("a request"))["receipt"]
    );
}

#[tokio::test]
async fn a_refusal_of_the_token_asks_the_receipt_before_it_says_to_sign_in_again() {
    let _clock = CLOCK.lock().await;
    // The first confirmation was carried out and its answer lost; the retry meets a dead token.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Unsettled)
    );
    *rig.service.ends.lock().expect("ends") = true;
    at(5 * 60_000);
    rig.wire
        .then([recorded("unauthenticated"), recorded("status_open")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    assert!(!session(&rig));

    // The token had already run out and could not be renewed: the receipt is the first thing asked.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    *rig.service.ends.lock().expect("ends") = true;
    at(11 * 60_000);
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );

    // And when the receipt knows nothing, the sign-in is what is needed.
    let rig = new_rig().await;
    *rig.service.ends.lock().expect("ends") = true;
    at(5 * 60_000);
    rig.wire
        .then([recorded("unauthenticated"), recorded("status_unknown")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::NeedsSignIn)
    );
}

/* ---- The ending, and the record's life ----------------------------------------------------- */

#[tokio::test]
async fn an_ending_that_failed_is_finished_after_a_restart_and_only_for_its_own_account() {
    let _clock = CLOCK.lock().await;
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail_session_delete: Mutex::new(true),
        fail_record_write: Mutex::new(None),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Closed { finished: false }),
        "the person is told the account is closed whatever this device managed to write"
    );
    assert!(
        session(&rig),
        "the disk refused, so the grant is still here"
    );

    // A start: new objects over the same store.
    let service = Arc::new(Service::default());
    let account = Arc::new(
        SignedInAccount::new(
            Arc::clone(&service) as Arc<dyn AccountService>,
            Arc::clone(&rig.store),
            Client::Desktop,
        )
        .with_clock(clock_ms),
    );
    let restarted = deletion(&account, &rig.wire);
    assert_eq!(
        restarted.settle().await,
        Ok(true),
        "the application has device state to settle"
    );
    assert!(!session(&rig), "the restart ended the grant");
    assert_eq!(
        account.status().expect("a status"),
        AccountStatus::SignedOut
    );

    // A different account that signs in afterwards is left alone by every later settle.
    account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("a sign-in");
    restarted.settle().await.expect("settled");
    assert!(session(&rig));
}

#[tokio::test]
async fn the_record_is_kept_while_a_request_may_run_then_dropped_and_after_closure_until_done() {
    let _clock = CLOCK.lock().await;
    // A request that left a moment ago may still be running: unknown is not an answer yet.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    at(30_000);
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(
        status.progress,
        DeletionProgress::Unsettled,
        "a request that left a moment ago may still be running"
    );
    assert!(record(&rig).is_some(), "kept");
    at(UNSETTLED_FOR_MS + 1);
    rig.wire.then([recorded("status_unknown")]);
    rig.deletion.status().await.expect("a status");
    assert!(
        record(&rig).is_none(),
        "dropped once nothing can still be running"
    );

    // Closed: an unknown is only lag, and the record outlives `done` until the device has settled.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(
        (status.progress, status.device_pending),
        (DeletionProgress::Open, true)
    );
    rig.wire.then([recorded("status_done")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(
        (status.progress, status.device_pending),
        (DeletionProgress::Done, true)
    );
    assert!(
        record(&rig).is_some(),
        "the application has not settled its own state yet"
    );
    rig.deletion
        .settle_device(&Steps::new(true, true))
        .await
        .expect("settled");
    assert!(record(&rig).is_none(), "done and settled: the record goes");

    // A closed record that never reaches `done` goes after the bound, without asking.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    at(CLOSED_FOR_MS + 1);
    let before = rig.wire.seen().len();
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::None);
    assert!(record(&rig).is_none());
    assert_eq!(rig.wire.seen().len(), before, "no request was made");
}

#[tokio::test]
async fn status_failures_keep_the_record_and_a_rate_limit_says_when() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    rig.wire.then([
        recorded("status_rate_limited"),
        Step::Lost,
        recorded("gateway_page"),
    ]);
    assert_eq!(
        rig.deletion.status().await,
        Err(DeletionFault::Busy { seconds: 60 })
    );
    assert_eq!(rig.deletion.status().await, Err(DeletionFault::Unreachable));
    assert_eq!(rig.deletion.status().await, Err(DeletionFault::Unreachable));
    assert!(record(&rig).is_some());
}

/* ---- What is never rendered ---------------------------------------------------------------- */

#[tokio::test]
async fn nothing_the_client_renders_carries_the_code_a_token_the_receipt_or_the_address() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([recorded("preview_with_warnings"), recorded("confirm_wrong")]);
    let read = rig.deletion.preview().await.expect("a preview");
    let outcome = rig.deletion.confirm(CODE, &[]).await;
    let receipt = body_of(&rig.wire.seen()[1])["receipt"]
        .as_str()
        .expect("a receipt")
        .to_owned();

    // Control: the typed value does carry the address, so what follows is the renderings' doing.
    let DeletionRead::Ready(preview) = &read else {
        panic!("a preview");
    };
    assert_eq!(preview.address, "r***@ts.org");

    let rendered = format!(
        "{read:?} {outcome:?} {:?} {:?} {:?} {:?}",
        rig.deletion,
        DeletionFault::Local(kr_client::Shown::said("a fault")),
        DeletionFault::Busy { seconds: 5 },
        rig.deletion.status().await,
    );
    for secret in [
        "r***@ts.org",
        CODE,
        "an-access-token",
        "first",
        receipt.as_str(),
        "Acme",
    ] {
        assert!(!rendered.contains(secret), "{secret} in {rendered}");
    }
}

#[tokio::test]
async fn a_closure_whose_record_could_not_be_written_still_ends_the_sign_in() {
    let _clock = CLOCK.lock().await;
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail_session_delete: Mutex::new(false),
        // The receipt is kept and kept again as the request leaves; the write that says the account
        // is closed is refused.
        fail_record_write: Mutex::new(Some(2)),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    assert!(
        !session(&rig),
        "the account is closed, so the sign-in goes with it"
    );
    assert!(record(&rig).is_some(), "the receipt's record is there");
}

/* ---- Answers that are not what the contract says ------------------------------------------- */

#[tokio::test]
async fn a_success_the_client_cannot_read_or_a_closed_state_it_does_not_know_is_a_lost_answer() {
    let _clock = CLOCK.lock().await;
    for answer in ["confirm_unreadable", "confirm_closed_unknown_state"] {
        let rig = new_rig().await;
        rig.wire.then([recorded(answer), recorded("status_open")]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::Closed { finished: false }),
            "{answer}"
        );
        let seen = rig.wire.seen();
        assert_eq!(
            path_of(&seen[1]),
            "/api/account/deletion/status",
            "{answer}"
        );
        assert_eq!(body_of(&seen[1])["receipt"], body_of(&seen[0])["receipt"]);
        assert!(
            !session(&rig),
            "{answer}: closure learned by receipt ends the sign-in"
        );

        // The receipt knows nothing of it: the person is not told it failed.
        let rig = new_rig().await;
        rig.wire.then([
            recorded(answer),
            recorded("status_unknown"),
            recorded("status_unknown"),
            recorded("status_unknown"),
        ]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::Unsettled),
            "{answer}"
        );
    }
}

/* ---- A late answer changes only what it was asked about ------------------------------------ */

#[tokio::test]
async fn a_closure_learned_for_one_account_never_ends_or_edits_another_accounts() {
    let _clock = CLOCK.lock().await;
    // The first account's confirmation was lost, then another account signed in.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Ok(DeletionOutcome::Unsettled)
    );
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    rig.wire.then([recorded("status_open")]);
    let status = rig.deletion.status().await.expect("a status");
    assert!(session(&rig), "the second account's sign-in stays");
    assert!(matches!(
        rig.account.status().expect("a status"),
        AccountStatus::SignedIn { .. }
    ));
    assert_eq!(
        status.progress,
        DeletionProgress::None,
        "the closed account is not the one signed in"
    );

    // Control: with no other account signed in, the same answer ends the sign-in.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    rig.wire.then([recorded("status_open")]);
    rig.deletion.status().await.expect("a status");
    assert!(!session(&rig));
}

#[tokio::test]
async fn a_status_answer_that_comes_late_does_not_close_a_deletion_another_account_began() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    let first = receipts(&rig.wire)[0].clone();

    // The status of the first account's receipt is out while a second account signs in and starts
    // its own deletion.
    let (entered, release) = rig.wire.hold_next("/api/account/deletion/status");
    rig.wire.then([
        recorded("status_open"),
        recorded("preview"),
        recorded("confirm_wrong"),
    ]);
    let late = rig.deletion.status();
    let meanwhile = async {
        entered.notified().await;
        rig.account
            .commit(issued("account-2", "second"), "another-nonce")
            .await
            .expect("a sign-in");
        rig.deletion.preview().await.expect("a preview");
        rig.deletion.confirm(CODE, &[]).await.expect("an answer");
        release.notify_one();
    };
    let (status, ()) = tokio::join!(late, meanwhile);
    assert_eq!(
        status.expect("a status").progress,
        DeletionProgress::None,
        "the account that signed in during the look is not the one it was about"
    );

    assert!(session(&rig), "the second account's sign-in stays");
    let second = receipts(&rig.wire)[1].clone();
    assert_ne!(second, first, "it is the second account's own");
    // And its deletion is not closed, and keeps its receipt: a look at it does not read as a closed
    // account, and its next confirmation carries the receipt it had.
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_ne!(status.progress, DeletionProgress::Open);
    assert_eq!(next_receipt(&rig).await, second);
}

#[tokio::test]
async fn a_status_answer_of_unknown_does_not_drop_a_receipt_a_confirmation_has_just_used() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    let first = receipts(&rig.wire)[0].clone();
    at(UNSETTLED_FOR_MS + 1);

    // Check again is out and the person presses Try again before it answers.
    let (entered, release) = rig.wire.hold_next("/api/account/deletion/status");
    rig.wire
        .then([recorded("status_unknown"), recorded("confirm_wrong")]);
    let check = rig.deletion.status();
    let again = async {
        entered.notified().await;
        rig.deletion.confirm(CODE, &[]).await.expect("an answer");
        release.notify_one();
    };
    let (status, ()) = tokio::join!(check, again);
    status.expect("a status");

    assert_eq!(
        receipts(&rig.wire),
        [first.clone(), first.clone()],
        "Try again carried the receipt the first try had"
    );
    assert_eq!(
        next_receipt(&rig).await,
        first,
        "and it is still the one kept"
    );
}

#[tokio::test]
async fn a_confirmation_that_is_still_out_keeps_its_record_whatever_the_clock_says() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let (entered, release) = rig.wire.hold_next("/api/account/deletion");
    rig.wire.then([recorded("confirm_wrong")]);
    let confirming = rig.deletion.confirm(CODE, &[]);
    let looking = async {
        entered.notified().await;
        // The device slept with the request out: the clock ran far past the margin.
        at(UNSETTLED_FOR_MS * 3);
        rig.wire.then([recorded("status_unknown")]);
        let status = rig.deletion.status().await;
        release.notify_one();
        status
    };
    let (outcome, status) = tokio::join!(confirming, looking);
    status.expect("a status");
    assert!(matches!(outcome, Ok(DeletionOutcome::CodeRefused { .. })));
    assert!(
        record(&rig).is_some(),
        "the record was not dropped under the request"
    );
}

/* ---- A dead credential after a request may have landed ------------------------------------- */

#[tokio::test]
async fn a_refused_token_after_an_earlier_request_is_not_a_plain_prompt_to_sign_in() {
    let _clock = CLOCK.lock().await;
    // The earlier request's answer was lost; the retry is refused twice, and the receipt cannot be
    // read: whether the account is closed is not known, and the person is told so.
    for (later, script) in [
        (
            30_000,
            vec![recorded("unauthenticated"), recorded("unauthenticated")],
        ),
        (
            30_000,
            vec![
                recorded("unauthenticated"),
                recorded("unauthenticated"),
                recorded("status_unknown"),
            ],
        ),
    ] {
        let rig = new_rig().await;
        rig.wire
            .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
        rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
        at(later);
        rig.wire.then(script);
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Ok(DeletionOutcome::Unsettled)
        );
    }

    // Control: once the earlier request cannot still be running, the receipt's `unknown` means the
    // sign-in is what is needed.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    at(UNSETTLED_FOR_MS + 1);
    rig.wire.then([
        recorded("unauthenticated"),
        recorded("unauthenticated"),
        recorded("status_unknown"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::NeedsSignIn)
    );
}

/* ---- What a refused code leaves, and what an unanswered one does ---------------------------- */

#[tokio::test]
async fn a_refused_code_leaves_nothing_running_and_an_unanswered_one_may_still_be() {
    let _clock = CLOCK.lock().await;
    // The service answered and said nothing was done: a look inside the margin finds nothing
    // unsettled, and the record is dropped once the margin has passed.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    at(30_000);
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::None);
    assert!(record(&rig).is_some(), "kept until the margin has passed");
    at(UNSETTLED_FOR_MS + 1);
    rig.wire.then([recorded("status_unknown")]);
    rig.deletion.status().await.expect("a status");
    assert!(record(&rig).is_none());

    // Trying again makes a request that is not yet answered.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status().await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::Unsettled);
}

#[tokio::test]
async fn a_status_asked_while_a_confirmation_is_out_says_it_is_unsettled() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let (entered, release) = rig.wire.hold_next("/api/account/deletion");
    rig.wire.then([recorded("confirm_wrong")]);
    let confirming = rig.deletion.confirm(CODE, &[]);
    let looking = async {
        entered.notified().await;
        let status = rig.deletion.status().await;
        release.notify_one();
        status
    };
    let (_, status) = tokio::join!(confirming, looking);
    assert_eq!(
        status.expect("a status").progress,
        DeletionProgress::Unsettled
    );
}

/* ---- What only the application can settle -------------------------------------------------- */

#[tokio::test]
async fn a_device_step_that_is_not_done_is_tried_again_and_one_that_is_done_is_not() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");

    // The notifications are settled; the recovery record could not be cleared.
    let steps = Steps::new(true, false);
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(steps.ran(), (1, 1));
    rig.wire.then([recorded("status_open")]);
    assert!(
        rig.deletion
            .status()
            .await
            .expect("a status")
            .device_pending,
        "one step is still to take"
    );

    // The next look runs the recovery step again and the notifications step not at all.
    *steps.recovery_done.lock().expect("done") = true;
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(steps.ran(), (1, 2));
    rig.wire.then([recorded("status_done")]);
    let status = rig.deletion.status().await.expect("a status");
    assert!(!status.device_pending);
    assert!(record(&rig).is_none(), "done and settled: the record goes");
}

#[tokio::test]
async fn two_looks_at_once_settle_each_device_step_once() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    let mut steps = Steps::new(true, true);
    steps.yields = true;
    let (first, second) = tokio::join!(
        rig.deletion.settle_device(&steps),
        rig.deletion.settle_device(&steps)
    );
    first.expect("settled");
    second.expect("settled");
    assert_eq!(steps.ran(), (1, 1));
}

#[tokio::test]
async fn a_step_whose_finish_could_not_be_written_is_not_run_again() {
    let _clock = CLOCK.lock().await;
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail_session_delete: Mutex::new(false),
        fail_record_write: Mutex::new(None),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");

    // The disk lets the claim on the first step through and refuses its finish: the person's own
    // changes after that run are not undone by a second.
    *flaky.fail_record_write.lock().expect("flaky") = Some(1);
    let steps = Steps::new(true, true);
    assert!(matches!(
        rig.deletion.settle_device(&steps).await,
        Err(DeletionFault::Local(_))
    ));
    *flaky.fail_record_write.lock().expect("flaky") = Some(0);
    assert!(matches!(
        rig.deletion.settle_device(&steps).await,
        Err(DeletionFault::Local(_))
    ));
    assert_eq!(
        steps.ran(),
        (1, 0),
        "the first step ran once; the failed write stops the pass"
    );

    // The disk works again: the finish is written without running either step a second time.
    *flaky.fail_record_write.lock().expect("flaky") = None;
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(steps.ran(), (1, 1));
    assert_eq!(
        rig.deletion.settle().await,
        Ok(false),
        "both steps are written as done"
    );
}

#[tokio::test]
async fn a_deletion_cannot_replace_a_closed_one_whose_device_state_is_not_settled() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    let first = receipts(&rig.wire)[0].clone();

    // Another account signs in and tries to delete itself while the first's device state waits.
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    rig.wire.then([recorded("preview")]);
    rig.deletion.preview().await.expect("a preview");
    let before = rig.wire.seen().len();
    assert!(matches!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::Local(_))
    ));
    assert_eq!(rig.wire.seen().len(), before, "nothing was sent");
    assert_eq!(
        rig.deletion.settle().await,
        Ok(true),
        "the first account's device state still waits"
    );

    // Settled, it may be replaced.
    rig.deletion
        .settle_device(&Steps::new(true, true))
        .await
        .expect("settled");
    assert_ne!(next_receipt(&rig).await, first);
}

#[tokio::test]
async fn a_look_does_not_drop_a_receipt_that_another_process_has_just_used() {
    let _clock = CLOCK.lock().await;
    // Two windows of one account share the store, and each counts only its own confirmations.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    let first = receipts(&rig.wire)[0].clone();
    at(UNSETTLED_FOR_MS + 1);

    let elsewhere = Arc::new(Wire::default());
    let other = deletion(&rig.account, &elsewhere);
    let (looking, let_look_go) = rig.wire.hold_next("/api/account/deletion/status");
    rig.wire.then([recorded("status_unknown")]);
    let (confirming, let_confirm_go) = elsewhere.hold_next("/api/account/deletion");
    elsewhere.then([recorded("confirm_wrong")]);

    let look = rig.deletion.status();
    let confirm = other.confirm(CODE, &[]);
    let drive = async {
        looking.notified().await;
        confirming.notified().await;
        // The device slept with both requests out, long enough for the margin to pass again.
        at(UNSETTLED_FOR_MS * 4);
        let_look_go.notify_one();
        let_confirm_go.notify_one();
    };
    let (look, _, ()) = tokio::join!(look, confirm, drive);
    look.expect("a status");
    assert_eq!(
        receipts(&elsewhere),
        std::slice::from_ref(&first),
        "the other window sent the receipt the first try had"
    );
    assert_eq!(
        next_receipt(&rig).await,
        first,
        "and it is still the one kept"
    );
}

#[tokio::test]
async fn a_record_another_process_removed_while_a_token_was_got_is_back_before_the_request_leaves()
{
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    // The first send is refused as the token's, and by then another process has judged the record
    // old and removed it; the request goes again with a renewed token.
    let store = Arc::clone(&rig.store);
    let found = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&found);
    let calls = Arc::new(AtomicU64::new(0));
    *rig.wire.peek.lock().expect("peek") = Some(Box::new(move || {
        keep.lock()
            .expect("found")
            .push(item(&store, "account/deletion"));
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            store
                .delete(&SecretName::new("account/deletion").expect("a name"))
                .expect("removed");
        }
    }));
    rig.wire
        .then([recorded("unauthenticated"), recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    let seen = receipts(&rig.wire);
    assert_eq!(seen.len(), 2);
    let at_second = found.lock().expect("found")[1]
        .clone()
        .expect("a record when the request went again");
    assert_eq!(at_second["receipt"], seen[1], "the request's own receipt");
}

#[tokio::test]
async fn a_request_the_service_refused_before_it_ran_is_not_left_to_look_unsettled() {
    let _clock = CLOCK.lock().await;
    // Too many tries: the confirmation did nothing, and a look inside the margin says so.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_rate_limited")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::Busy { seconds: 300 })
    );
    at(30_000);
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion.status().await.expect("a status").progress,
        DeletionProgress::None
    );

    // A sign-in that was refused with no earlier try left running has nothing unsettled either.
    let rig = new_rig().await;
    rig.wire
        .then([recorded("unauthenticated"), recorded("unauthenticated")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::NeedsSignIn)
    );
    at(30_000);
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion.status().await.expect("a status").progress,
        DeletionProgress::None
    );

    // Control: a try whose answer was lost does.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion.confirm(CODE, &[]).await.expect("unsettled");
    at(30_000);
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion.status().await.expect("a status").progress,
        DeletionProgress::Unsettled
    );
}

#[tokio::test]
async fn an_earlier_try_the_service_answered_does_not_make_a_dead_sign_in_unsettled() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_wrong")]);
    rig.deletion.confirm(CODE, &[]).await.expect("an answer");
    at(30_000);
    rig.wire
        .then([recorded("unauthenticated"), recorded("unauthenticated")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[]).await,
        Err(DeletionFault::NeedsSignIn)
    );
}

#[tokio::test]
async fn an_answer_to_an_older_try_does_not_say_a_newer_one_is_answered() {
    let _clock = CLOCK.lock().await;
    // Two windows share the store. The first's try is refused (a wrong code) after the second has
    // sent the same receipt again: the second's request is still out.
    let rig = new_rig().await;
    let elsewhere = Arc::new(Wire::default());
    let other = deletion(&rig.account, &elsewhere);
    let (first_out, first_go) = rig.wire.hold_next("/api/account/deletion");
    rig.wire.then([recorded("confirm_wrong")]);
    let (second_out, second_go) = elsewhere.hold_next("/api/account/deletion");
    elsewhere.then([recorded("confirm_wrong")]);

    let first = rig.deletion.confirm(CODE, &[]);
    let second = async {
        first_out.notified().await;
        // The second window's try leaves a little later than the first's.
        at(10_000);
        other.confirm(CODE, &[]).await
    };
    let drive = async {
        second_out.notified().await;
        first_go.notify_one();
        // The first try's answer is taken before anything else runs.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        at(40_000);
        rig.wire.then([recorded("status_unknown")]);
        let status = rig.deletion.status().await.expect("a status");
        second_go.notify_one();
        status
    };
    let (_, second, status) = tokio::join!(first, second, drive);
    second.expect("an answer");
    assert_eq!(
        status.progress,
        DeletionProgress::Unsettled,
        "the second window's request has no answer yet"
    );
}

#[tokio::test]
async fn a_dead_sign_in_is_not_told_the_closure_of_another_accounts_deletion() {
    let _clock = CLOCK.lock().await;
    for closed in [true, false] {
        // The first account's deletion is on record (closed, or not known to be); another account
        // signs in, reads what deleting does, and its token is dead when it confirms.
        let rig = new_rig().await;
        if closed {
            rig.wire.then([recorded("confirm_closed_closing")]);
        } else {
            rig.wire
                .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
        }
        rig.deletion.confirm(CODE, &[]).await.expect("an answer");
        rig.account
            .commit(issued("account-2", "second"), "another-nonce")
            .await
            .expect("a sign-in");
        rig.wire.then([recorded("preview")]);
        rig.deletion.preview().await.expect("a preview");
        *rig.service.ends.lock().expect("ends") = true;
        at(11 * 60_000);
        let before = rig.wire.seen().len();
        assert_eq!(
            rig.deletion.confirm(CODE, &[]).await,
            Err(DeletionFault::NeedsSignIn),
            "closed: {closed}"
        );
        assert_eq!(
            rig.wire.seen().len(),
            before,
            "nothing was asked about the first account's receipt"
        );
    }
}

#[tokio::test]
async fn two_processes_settling_at_once_run_each_device_step_once_between_them() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    let other = deletion(&rig.account, &Arc::new(Wire::default()));
    let mut steps = Steps::new(true, true);
    steps.yields = true;
    let (first, second) = tokio::join!(
        rig.deletion.settle_device(&steps),
        other.settle_device(&steps)
    );
    first.expect("settled");
    second.expect("settled");
    assert_eq!(steps.ran(), (1, 1));
    assert_eq!(rig.deletion.settle().await, Ok(false));
}

#[tokio::test]
async fn a_pass_that_ended_before_it_finished_a_step_is_taken_over_after_a_while() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");

    // A pass takes up the notifications step and is gone before it ends (the process stopped).
    struct Hangs;
    impl DeviceSteps for Hangs {
        fn notifications(&self) -> StepFuture<'_> {
            Box::pin(std::future::pending())
        }
        fn recovery(&self) -> StepFuture<'_> {
            Box::pin(async { true })
        }
    }
    tokio::select! {
        biased;
        _ = rig.deletion.settle_device(&Hangs) => panic!("the step never ends"),
        () = std::future::ready(()) => {}
    }

    // Soon after, another pass leaves the step to the one that has it; later, it takes it over.
    let steps = Steps::new(true, true);
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(steps.ran(), (0, 1));
    at(2 * 60_000);
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(steps.ran(), (1, 1));
    assert_eq!(rig.deletion.settle().await, Ok(false));
}

#[tokio::test]
async fn a_step_that_is_not_done_gives_up_its_claim_so_the_next_look_runs_it() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion.confirm(CODE, &[]).await.expect("closed");
    let steps = Steps::new(false, true);
    rig.deletion.settle_device(&steps).await.expect("settled");
    rig.deletion.settle_device(&steps).await.expect("settled");
    assert_eq!(
        steps.ran(),
        (2, 1),
        "no waiting for a claim of a step that failed"
    );
}

/* ---- The recorded answers and the ones these cases replay ----------------------------------- */

/// Whether `ours` is the same answer as `recorded`: the same members and kinds of value, and the
/// same value wherever the recording kept one (it replaces an identifier or a delay with a
/// placeholder in angle brackets, and an address or a name with an example).
fn agrees(recorded: &serde_json::Value, ours: &serde_json::Value, path: &str) {
    use serde_json::Value;
    match (recorded, ours) {
        (Value::String(text), _) if text.starts_with('<') && text.ends_with('>') => {}
        (Value::Object(left), Value::Object(right)) => {
            let names = |map: &serde_json::Map<String, Value>| {
                map.keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
            };
            assert_eq!(names(left), names(right), "{path}: members");
            for (name, value) in left {
                agrees(value, &right[name], &format!("{path}.{name}"));
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            assert_eq!(left.len(), right.len(), "{path}: length");
            for (index, (one, other)) in left.iter().zip(right).enumerate() {
                agrees(one, other, &format!("{path}[{index}]"));
            }
        }
        (Value::String(_), Value::String(_))
            if path.ends_with(".address")
                || path.ends_with(".name")
                || path.ends_with(".message") => {}
        (Value::Number(_), Value::Number(_)) if path.ends_with(".members") => {}
        (left, right) => assert_eq!(left, right, "{path}"),
    }
}

#[test]
fn the_answers_these_cases_replay_agree_with_the_ones_the_service_recorded() {
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/account-deletion/recorded-by-the-service.json"
    ))
    .expect("the recording");
    let ours = answers();
    // The recording names two answers differently.
    fn named(name: &str) -> &str {
        match name {
            "code_unavailable" => "code_mail_failed",
            "dead_token" => "unauthenticated",
            other => other,
        }
    }
    let mut compared = 0;
    for (name, answer) in recorded.as_object().expect("answers") {
        let Some(replayed) = ours.get(named(name)) else {
            continue;
        };
        assert_eq!(answer["status"], replayed["status"], "{name}: status");
        agrees(&answer["body"], &replayed["body"], name);
        compared += 1;
    }
    assert!(compared >= 20, "{compared} answers compared");
}
