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
    CodeRefusal, DeletionFault, DeletionOutcome, DeletionProgress, DeletionRead, DeletionWarning,
    DeviceSteps, KEPT_FOR_MS, ManagedAccountDeletion, StepFuture,
};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountIdentity, AccountMark, AccountService, AccountStatus, AccountToken,
    AccountUsage, AuthorisationGrant, Client, Exchanged, IssuedGrant, RefreshToken, Refreshed,
    SignedInAccount, StoredGrant,
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
    /// The application's steps, which all say they are done.
    steps: Steps,
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
        steps: Steps::new(true, true),
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

/// The application's device steps, scripted: how often each ran, which account the recovery step was
/// told was deleted, and whether each says it is done.
struct Steps {
    notifications: AtomicU64,
    recovery: AtomicU64,
    notifications_done: Mutex<bool>,
    recovery_done: Mutex<bool>,
    deleted: Mutex<Vec<AccountMark>>,
}

impl Steps {
    fn new(notifications_done: bool, recovery_done: bool) -> Self {
        Self {
            notifications: AtomicU64::new(0),
            recovery: AtomicU64::new(0),
            notifications_done: Mutex::new(notifications_done),
            recovery_done: Mutex::new(recovery_done),
            deleted: Mutex::new(Vec::new()),
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
            *self.notifications_done.lock().expect("done")
        })
    }

    fn recovery(&self, deleted: AccountMark) -> StepFuture<'_> {
        Box::pin(async move {
            self.recovery.fetch_add(1, Ordering::SeqCst);
            self.deleted.lock().expect("deleted").push(deleted);
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
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("a confirmation");
    rig.wire.then([recorded("status_open")]);
    rig.deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");

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
    let DeletionOutcome::Acknowledge { organisations } = rig
        .deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("an answer")
    else {
        panic!("an acknowledgement is asked for");
    };
    assert_eq!(organisations[0].name, "Acme");
    let ids = vec!["org-1".to_owned()];
    rig.deletion
        .confirm(CODE, &ids, &rig.steps)
        .await
        .expect("closed");
    assert_eq!(
        body_of(&rig.wire.seen()[1])["acknowledged"],
        serde_json::json!(["org-1"])
    );

    let too_many: Vec<String> = (0..51).map(|each| format!("org-{each}")).collect();
    let before = rig.wire.seen().len();
    assert_eq!(
        rig.deletion.confirm(CODE, &too_many, &rig.steps).await,
        Err(DeletionFault::Refused)
    );
    assert_eq!(rig.wire.seen().len(), before, "nothing was sent");
    assert_eq!(
        rig.deletion.confirm("1234", &[], &rig.steps).await,
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
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("an answer");
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
async fn nothing_the_client_renders_carries_the_code_a_token_the_receipt_or_the_address() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([recorded("preview_with_warnings"), recorded("confirm_wrong")]);
    let read = rig.deletion.preview().await.expect("a preview");
    let outcome = rig.deletion.confirm(CODE, &[], &rig.steps).await;
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
        rig.deletion.status(true, &rig.steps).await,
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
        // The receipt is kept as the request leaves; the write that says the account is closed is
        // refused.
        fail_record_write: Mutex::new(Some(1)),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
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
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
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
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Ok(DeletionOutcome::Unsettled),
            "{answer}"
        );
    }
}

/* ---- A late answer changes only what it was asked about ------------------------------------ */

/* ---- What the answers mean ----------------------------------------------------------------- */

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
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Ok(DeletionOutcome::CodeRefused {
                reason,
                attempts_left: left
            })
        );
        assert!(session(&rig), "the sign-in stays");
        assert_eq!(rig.wire.seen().len(), 1);
        assert!(
            record(&rig).is_none(),
            "a request that did nothing leaves no receipt to look for"
        );
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
        let account = rig
            .account
            .signed_in_mark(ACCOUNT_ORIGIN)
            .expect("a read")
            .expect("signed in");
        rig.wire.then([recorded(answer)]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
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
        assert_eq!(rig.steps.ran(), (1, 1), "the device settled its own state");
        assert_eq!(
            *rig.steps.deleted.lock().expect("deleted"),
            [account],
            "the recovery step is told whose account was deleted"
        );
        assert!(
            record(&rig).is_some(),
            "the record stays for the look that tells a page opened meanwhile"
        );
        rig.wire.then([recorded("status_open")]);
        let status = rig.deletion.status(true, &rig.steps).await.expect("a look");
        assert_eq!(
            (status.progress, record(&rig).is_some()),
            if finished {
                (DeletionProgress::Done, false)
            } else {
                (DeletionProgress::Open, true)
            },
            "it goes with the look that finds the removal done and the device settled"
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
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    let first = body_of(&rig.wire.seen()[0])["receipt"].clone();

    // Another account signs in; its confirmation looks at the first account's receipt once, and
    // makes a receipt of its own.
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    rig.wire.then([
        recorded("preview"),
        recorded("status_unknown"),
        recorded("confirm_wrong"),
    ]);
    rig.deletion.preview().await.expect("a preview");
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("an answer");
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
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Err(DeletionFault::AccountChanged)
    );
    assert_eq!(
        rig.wire.seen().len(),
        before,
        "nothing was sent for another account"
    );
    assert!(record(&rig).is_none(), "and no receipt was kept for it");
}

#[tokio::test]
async fn a_receipt_the_service_calls_used_is_a_refusal_and_is_not_sent_again() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_receipt_taken")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Err(DeletionFault::Refused)
    );
    assert_eq!(rig.wire.seen().len(), 1, "one request and no more");
    assert!(record(&rig).is_none());
}

#[tokio::test]
async fn a_rate_limit_and_a_malformed_request_change_nothing() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([
        recorded("confirm_rate_limited"),
        recorded("confirm_malformed"),
    ]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Err(DeletionFault::Busy { seconds: 300 })
    );
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Err(DeletionFault::Refused)
    );
    assert!(session(&rig));
    assert!(record(&rig).is_none());
}

/* ---- A dead sign-in ------------------------------------------------------------------------ */

#[tokio::test]
async fn a_sign_in_that_was_dead_before_the_request_ran_leaves_no_deletion_unsettled() {
    let _clock = CLOCK.lock().await;
    for renewal_ends in [true, false] {
        let rig = new_rig().await;
        if renewal_ends {
            // The service refuses the token, and the renewal is refused too.
            *rig.service.ends.lock().expect("ends") = true;
            rig.wire.then([recorded("unauthenticated")]);
        } else {
            // The service refuses the token twice, with a renewal in between that works.
            rig.wire
                .then([recorded("unauthenticated"), recorded("unauthenticated")]);
        }
        assert_eq!(
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Err(DeletionFault::NeedsSignIn),
            "renewal ends: {renewal_ends}"
        );
        let before = rig.wire.seen().len();
        let status = rig
            .deletion
            .status(true, &rig.steps)
            .await
            .expect("a status");
        assert_eq!(
            status.progress,
            DeletionProgress::None,
            "a request that did not run is not a deletion that may still land"
        );
        assert_eq!(rig.wire.seen().len(), before, "and there is nothing to ask");
    }
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
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Ok(DeletionOutcome::Closed { finished: false })
        );
        let seen = rig.wire.seen();
        assert_eq!(path_of(&seen[1]), "/api/account/deletion/status");
        assert_eq!(body_of(&seen[1])["receipt"], body_of(&seen[0])["receipt"]);
        assert!(
            !session(&rig),
            "closure learned by receipt ends the sign-in too"
        );
        assert_eq!(rig.steps.ran(), (1, 1));
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
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    assert!(
        session(&rig),
        "an unsettled request does not end the sign-in"
    );
    assert!(record(&rig).is_some(), "the record is kept");
    assert_eq!(rig.steps.ran(), (0, 0));

    // A retry reuses the receipt, and the service takes it.
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("closed");
    let receipts = receipts(&rig.wire);
    assert_eq!(receipts.first(), receipts.last());
}

#[tokio::test]
async fn a_refusal_that_follows_an_unresolved_request_keeps_the_receipt_of_that_request() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    // The retry is refused, but the first request may still have run: its receipt is the way to
    // learn that.
    rig.wire.then([recorded("confirm_wrong")]);
    assert!(matches!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::CodeRefused { .. })
    ));
    assert!(record(&rig).is_some());
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("closed");
    let receipts = receipts(&rig.wire);
    assert_eq!(receipts.len(), 3);
    assert!(
        receipts.iter().all(|each| each == &receipts[0]),
        "one receipt, all along"
    );
}

#[tokio::test]
async fn a_dead_token_after_an_unresolved_request_asks_the_receipt_before_it_says_to_sign_in() {
    let _clock = CLOCK.lock().await;
    // The first confirmation was carried out and its answer lost; the retry meets a dead token.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    *rig.service.ends.lock().expect("ends") = true;
    rig.wire
        .then([recorded("unauthenticated"), recorded("status_open")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    assert!(!session(&rig));

    // The token had run out already and could not be renewed: the receipt is the first thing asked.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    *rig.service.ends.lock().expect("ends") = true;
    at(11 * 60_000);
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );

    // When the receipt knows nothing, the earlier request is still not known to have failed.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    *rig.service.ends.lock().expect("ends") = true;
    rig.wire
        .then([recorded("unauthenticated"), recorded("status_unknown")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    assert!(record(&rig).is_some());
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
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
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
    restarted.settle_grant().await.expect("settled");
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
    restarted.settle_grant().await.expect("settled");
    assert!(session(&rig));
}

#[tokio::test]
async fn an_unresolved_record_is_kept_for_a_week_and_is_never_judged_by_the_service_saying_unknown()
{
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    for after in [30_000, 60 * 60_000, KEPT_FOR_MS - 1] {
        at(after);
        rig.wire.then([recorded("status_unknown")]);
        let status = rig
            .deletion
            .status(true, &rig.steps)
            .await
            .expect("a status");
        assert_eq!(status.progress, DeletionProgress::Unsettled, "{after}");
        assert!(record(&rig).is_some(), "{after}");
    }
    at(KEPT_FOR_MS + 1);
    let before = rig.wire.seen().len();
    let status = rig
        .deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");
    assert_eq!(status.progress, DeletionProgress::None);
    assert!(record(&rig).is_none());
    assert_eq!(rig.wire.seen().len(), before, "no request was made");
}

#[tokio::test]
async fn a_closed_record_lives_until_the_removal_is_done_and_the_device_has_settled() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let steps = Steps::new(true, false);
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &steps)
        .await
        .expect("closed");
    assert_eq!(steps.ran(), (1, 1));

    // An unknown is only lag once the account is closed; the recovery step is tried again.
    rig.wire.then([recorded("status_unknown")]);
    let status = rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::Open);
    assert!(!status.closed_now);
    assert_eq!(steps.ran(), (1, 2));

    // Done is reported, and the record outlives it while a step is not done.
    rig.wire.then([recorded("status_done")]);
    let status = rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::Done);
    assert!(record(&rig).is_some());
    assert_eq!(steps.ran(), (1, 3));

    // The step is done at last: the record goes, and the service is not asked again.
    *steps.recovery_done.lock().expect("done") = true;
    let before = rig.wire.seen().len();
    let status = rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::Done);
    assert!(record(&rig).is_none());
    assert_eq!(rig.wire.seen().len(), before);
    assert_eq!(steps.ran(), (1, 4));
    assert_eq!(
        rig.deletion
            .status(true, &steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None
    );
}

#[tokio::test]
async fn a_closed_record_a_week_old_still_settles_the_device_once_more_before_it_goes() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let steps = Steps::new(true, false);
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &steps)
        .await
        .expect("closed");
    assert_eq!(steps.ran(), (1, 1));
    at(KEPT_FOR_MS + 1);
    rig.wire.then([recorded("status_open")]);
    let status = rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(status.progress, DeletionProgress::None);
    assert_eq!(
        steps.ran(),
        (1, 2),
        "the step that was not done ran once more, though the record is a week old"
    );
    assert!(record(&rig).is_none());
}

#[tokio::test]
async fn status_failures_keep_the_record_and_a_rate_limit_says_when() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("closed");
    rig.wire.then([
        recorded("status_rate_limited"),
        Step::Lost,
        recorded("gateway_page"),
    ]);
    assert_eq!(
        rig.deletion.status(true, &rig.steps).await,
        Err(DeletionFault::Busy { seconds: 60 })
    );
    assert_eq!(
        rig.deletion.status(true, &rig.steps).await,
        Err(DeletionFault::Unreachable)
    );
    assert_eq!(
        rig.deletion.status(true, &rig.steps).await,
        Err(DeletionFault::Unreachable)
    );
    assert!(record(&rig).is_some());
}

#[tokio::test]
async fn a_device_step_that_is_not_done_is_tried_again_and_one_that_is_done_is_not() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    // The notifications are settled; the recovery record could not be cleared.
    let steps = Steps::new(true, false);
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &steps)
        .await
        .expect("closed");
    assert_eq!(steps.ran(), (1, 1));

    // The next look runs the recovery step again and the notifications step not at all.
    *steps.recovery_done.lock().expect("done") = true;
    rig.wire.then([recorded("status_open")]);
    rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(steps.ran(), (1, 2));
    rig.wire.then([recorded("status_done")]);
    rig.deletion.status(true, &steps).await.expect("a status");
    assert_eq!(steps.ran(), (1, 2));
    assert!(record(&rig).is_none(), "done and settled: the record goes");
}

/* ---- Whose it is to see -------------------------------------------------------------------- */

#[tokio::test]
async fn a_closed_deletion_is_shown_to_the_page_that_follows_it_and_to_no_page_that_has_only_opened()
 {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion
            .status(true, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::Open,
        "the page that is showing the result is told how it goes"
    );
    // A panel that only opens is told nothing of a closed account's deletion, whoever signed in
    // and out in between.
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion
            .status(false, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None
    );
    rig.account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("another account signs in");
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion
            .status(true, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None,
        "the other account is not told about it, even by a page that follows it"
    );
    rig.account.sign_out().await.expect("and out");
    rig.wire.then([recorded("status_open")]);
    assert_eq!(
        rig.deletion
            .status(false, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None,
        "the other account's sign-out does not bring the first account's closure back"
    );
}

#[tokio::test]
async fn an_unresolved_deletion_is_shown_to_its_own_account_and_to_no_other() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion
            .status(true, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::Unsettled
    );

    // A fresh process of the same account sees it too.
    let again = deletion(&rig.account, &rig.wire);
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        again
            .status(false, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::Unsettled
    );

    // Another account does not, and cannot give up on it.
    rig.account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("another account signs in");
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        again
            .status(false, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None
    );
    again.hide().await.expect("nothing to close");
    assert!(record(&rig).is_some(), "the first account's record stays");
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
        rig.deletion
            .confirm(CODE, &[], &rig.steps)
            .await
            .expect("an answer");
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
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
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
async fn a_closure_learned_for_one_account_never_ends_or_edits_another_accounts() {
    let _clock = CLOCK.lock().await;
    // The first account's confirmation was lost, then another account signed in.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    rig.account
        .commit(issued("account-2", "second"), "another-nonce")
        .await
        .expect("a sign-in");
    rig.wire.then([recorded("status_open")]);
    let status = rig
        .deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");
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
    assert!(
        !status.closed_now,
        "and the one signed in is not told that another account closed"
    );

    // Control: with no other account signed in, the same answer ends the sign-in.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    rig.wire.then([recorded("status_open")]);
    let status = rig
        .deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");
    assert_eq!(status.progress, DeletionProgress::Open);
    assert!(status.closed_now);
    assert!(!session(&rig));
}

#[tokio::test]
async fn closing_the_step_stops_offering_it_and_keeps_the_receipt_for_a_closure_that_lands_later() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    rig.deletion.hide().await.expect("closed");
    assert!(
        record(&rig).is_some(),
        "the request can still take effect, so the receipt stays"
    );
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion
            .status(false, &rig.steps)
            .await
            .expect("a look")
            .progress,
        DeletionProgress::None,
        "the step is not offered again while it is not known"
    );
    // The request lands later: the look that finds it settles the device and tells the person.
    rig.wire.then([recorded("status_open")]);
    let status = rig
        .deletion
        .status(false, &rig.steps)
        .await
        .expect("a look");
    assert_eq!(
        (status.progress, status.closed_now),
        (DeletionProgress::Open, true)
    );
    assert_eq!(rig.steps.ran(), (1, 1), "the device settled its own state");
    assert!(!session(&rig));

    // A new confirmation for the account brings the step back, on the same receipt.
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled");
    rig.deletion.hide().await.expect("closed");
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("unsettled again");
    let sent = receipts(&rig.wire);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1], "a lost request's receipt is reused");
    rig.wire.then([recorded("status_unknown")]);
    assert_eq!(
        rig.deletion
            .status(true, &rig.steps)
            .await
            .expect("a look")
            .progress,
        DeletionProgress::Unsettled
    );

    // A closed account is settled, not closed over.
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("closed");
    rig.deletion.hide().await.expect("nothing to close");
    assert!(record(&rig).is_some());
}

#[tokio::test]
async fn a_finished_record_stays_until_a_page_that_follows_it_has_been_told() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_deleted")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: true })
    );
    // Another process of the application (it has no deletion in front of its person) looks, at its
    // start or from its own panel, and takes nothing that a page here is waiting to show.
    let other = deletion(&rig.account, &rig.wire);
    for following in [false, true] {
        assert_eq!(
            other
                .status(following, &rig.steps)
                .await
                .expect("a look")
                .progress,
            DeletionProgress::None
        );
        assert!(record(&rig).is_some(), "following: {following}");
    }
    assert_eq!(
        rig.deletion
            .status(false, &rig.steps)
            .await
            .expect("a look")
            .progress,
        DeletionProgress::None
    );
    assert!(record(&rig).is_some());
    assert_eq!(
        rig.deletion
            .status(true, &rig.steps)
            .await
            .expect("a look")
            .progress,
        DeletionProgress::Done
    );
    assert!(record(&rig).is_none(), "the page was told, and it goes");
}

#[tokio::test]
async fn a_step_that_ran_is_not_run_again_because_the_store_would_not_keep_that_it_ran() {
    let _clock = CLOCK.lock().await;
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail_session_delete: Mutex::new(false),
        fail_record_write: Mutex::new(None),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    // The record is kept as begun and as closed; the writes that say the steps are done are refused.
    *flaky.fail_record_write.lock().expect("flaky") = Some(2);
    rig.wire.then([recorded("confirm_closed_closing")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    assert_eq!(rig.steps.ran(), (1, 1));
    assert_eq!(record(&rig).expect("kept")["notifications"], false);

    rig.wire.then([recorded("status_open")]);
    rig.deletion.status(true, &rig.steps).await.expect("a look");
    assert_eq!(
        rig.steps.ran(),
        (1, 1),
        "a step that ran is not run again for the same record"
    );

    // Once the store keeps it, the record says so.
    *flaky.fail_record_write.lock().expect("flaky") = None;
    rig.wire.then([recorded("status_open")]);
    rig.deletion.status(true, &rig.steps).await.expect("a look");
    assert_eq!(rig.steps.ran(), (1, 1));
    assert_eq!(record(&rig).expect("kept")["notifications"], true);
}

#[tokio::test]
async fn a_look_that_follows_nothing_leaves_a_closed_deletion_for_the_page_that_does() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_deleted")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: true })
    );
    // Another try meeting the closure it caused is told what it came to.
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: true }),
        "a second try is not told to sign in again"
    );
    assert_eq!(receipts(&rig.wire).len(), 1, "and sends nothing");
    // A panel that only opened looks first, and tells nobody.
    let status = rig
        .deletion
        .status(false, &rig.steps)
        .await
        .expect("a look");
    assert_eq!(status.progress, DeletionProgress::None);
    assert!(
        record(&rig).is_some(),
        "the record stays for the page that is showing the result"
    );
    let status = rig.deletion.status(true, &rig.steps).await.expect("a look");
    assert_eq!(status.progress, DeletionProgress::Done);
    assert!(
        record(&rig).is_none(),
        "the page that follows it is told, and it goes"
    );
}

#[tokio::test]
async fn the_look_that_opens_the_panel_tells_the_person_whose_own_deletion_it_finds_closed() {
    let _clock = CLOCK.lock().await;
    for (answer, progress) in [
        ("status_open", DeletionProgress::Open),
        ("status_done", DeletionProgress::Done),
    ] {
        // The person's own deletion is not known to have run, and the person is still signed in as
        // that account when the panel opens: the look is what ends the sign-in, and it says why.
        let rig = new_rig().await;
        rig.wire
            .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
        assert_eq!(
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Ok(DeletionOutcome::Unsettled)
        );
        assert!(session(&rig));
        rig.wire.then([recorded(answer)]);
        let status = rig
            .deletion
            .status(false, &rig.steps)
            .await
            .expect("a look");
        assert_eq!(
            (status.progress, status.closed_now),
            (progress, true),
            "{answer}"
        );
        assert!(!session(&rig), "the sign-in is gone");
        assert!(
            record(&rig).is_some(),
            "{answer}: the record stays until the page that shows the result has asked"
        );
        if progress == DeletionProgress::Done {
            let status = rig.deletion.status(true, &rig.steps).await.expect("a look");
            assert_eq!(status.progress, DeletionProgress::Done);
            assert!(record(&rig).is_none(), "and goes with that look");
        }
    }
}

#[tokio::test]
async fn a_new_deletion_looks_after_an_old_closed_one_as_far_as_it_goes_and_then_makes_way() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let steps = Steps::new(true, false);
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &steps)
        .await
        .expect("closed");
    assert_eq!(steps.ran(), (1, 1));
    let first = body_of(&rig.wire.seen()[0])["receipt"].clone();

    // Another account signs in on the device and deletes in its turn. The old record is asked
    // about and its steps are tried once more, and it is replaced whether or not they finish.
    rig.account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("a sign-in");
    rig.wire.then([
        recorded("preview"),
        recorded("status_open"),
        recorded("confirm_closed_closing"),
    ]);
    rig.deletion.preview().await.expect("a preview");
    rig.deletion
        .confirm(CODE, &[], &steps)
        .await
        .expect("closed");
    assert_eq!(steps.ran(), (2, 3), "both accounts' steps ran");
    let second = body_of(rig.wire.seen().last().expect("a request"))["receipt"].clone();
    assert_ne!(first, second);
    assert!(!session(&rig), "the second account's sign-in ended too");
}

#[tokio::test]
async fn a_closure_does_not_let_go_of_the_note_that_another_accounts_sign_in_ended() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire.then([recorded("confirm_closed_closing")]);
    rig.deletion
        .confirm(CODE, &[], &rig.steps)
        .await
        .expect("closed");
    // Another account signs in, and its sign-in ends by itself.
    rig.account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("a sign-in");
    *rig.service.ends.lock().expect("ends") = true;
    at(11 * 60_000);
    rig.account
        .token_marked("openid", ACCOUNT_ORIGIN, false)
        .await
        .expect_err("the sign-in has ended");
    assert_eq!(
        rig.account.status().expect("a status"),
        AccountStatus::Ended
    );

    // The panel looks again when the account changes, as a panel that has only opened does.
    rig.wire.then([recorded("status_open")]);
    let status = rig
        .deletion
        .status(false, &rig.steps)
        .await
        .expect("a status");
    assert_eq!(status.progress, DeletionProgress::None);
    assert!(!status.closed_now);
    assert_eq!(
        rig.account.status().expect("a status"),
        AccountStatus::Ended,
        "the other account's note stays, and is not taken for the closed account's"
    );
}

#[tokio::test]
async fn a_closure_whose_sign_in_could_not_be_removed_is_not_forgotten_when_the_removal_is_done() {
    let _clock = CLOCK.lock().await;
    let flaky = Arc::new(Flaky {
        inner: MemoryStore::new(),
        fail_session_delete: Mutex::new(true),
        fail_record_write: Mutex::new(None),
    });
    let rig = rig_over(Arc::clone(&flaky) as Arc<dyn SecretStore>).await;
    rig.wire.then([recorded("confirm_closed_deleted")]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: true })
    );
    assert!(session(&rig), "the disk refused");
    assert!(record(&rig).is_some());

    // The removal is done and the device's steps are, but the sign-in is still stored: the look
    // that cannot end it keeps the record, and the next one ends it and lets the record go.
    *flaky.fail_session_delete.lock().expect("flaky") = true;
    let status = rig
        .deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");
    assert_eq!(status.progress, DeletionProgress::Done);
    assert!(session(&rig));
    assert!(
        record(&rig).is_some(),
        "the record is how the sign-in is ended"
    );
    rig.deletion
        .status(true, &rig.steps)
        .await
        .expect("a status");
    assert!(!session(&rig));
    assert!(record(&rig).is_none());
}

#[tokio::test]
async fn a_confirmation_sends_the_receipt_of_the_account_it_began_for_whoever_the_page_previewed_since()
 {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    rig.wire
        .then([Step::Lost, Step::Lost, Step::Lost, Step::Lost]);
    assert_eq!(
        rig.deletion.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Unsettled)
    );
    // A second account confirms: it first asks about the first account's receipt, and that look is
    // held while another process signs in a third account and this page previews it.
    rig.account
        .commit(issued("account-2", "second"), "n")
        .await
        .expect("a sign-in");
    rig.wire.then([recorded("preview")]);
    rig.deletion.preview().await.expect("a preview");
    let (entered, release) = rig.wire.hold_next("/api/account/deletion/status");
    rig.wire.then([
        recorded("status_unknown"),
        recorded("preview"),
        recorded("confirm_wrong"),
    ]);
    let confirming = rig.deletion.confirm(CODE, &[], &rig.steps);
    let meanwhile = async {
        entered.notified().await;
        rig.account
            .commit(issued("account-3", "third"), "m")
            .await
            .expect("a sign-in");
        rig.deletion.preview().await.expect("a preview");
        release.notify_one();
    };
    let (confirmed, ()) = tokio::join!(confirming, meanwhile);
    assert_eq!(confirmed, Err(DeletionFault::AccountChanged));
    assert_eq!(
        receipts(&rig.wire).len(),
        1,
        "only the first account's own confirmation was ever sent"
    );
    assert!(
        record(&rig).is_none(),
        "and the record made for it is taken back"
    );
}

/* ---- One owner ------------------------------------------------------------------------------ */

#[tokio::test]
async fn a_confirmation_in_flight_holds_the_deletion_and_a_second_caller_neither_races_nor_waits() {
    let _clock = CLOCK.lock().await;
    let rig = new_rig().await;
    let (entered, release) = rig.wire.hold_next("/api/account/deletion");
    rig.wire.then([recorded("confirm_closed_closing")]);
    let first = rig.deletion.confirm(CODE, &[], &rig.steps);
    let second = async {
        entered.notified().await;
        let before = rig.wire.seen().len();
        assert_eq!(
            rig.deletion.confirm(CODE, &[], &rig.steps).await,
            Err(DeletionFault::InProgress)
        );
        assert_eq!(rig.deletion.hide().await, Err(DeletionFault::InProgress));
        assert_eq!(
            rig.deletion
                .status(true, &rig.steps)
                .await
                .expect("a status")
                .progress,
            DeletionProgress::Unsettled,
            "a look says what the record shows and touches nothing"
        );
        assert_eq!(rig.wire.seen().len(), before, "nothing was sent");
        assert!(
            record(&rig).is_some(),
            "the receipt is kept while it is out"
        );
        release.notify_one();
    };
    let (first, ()) = tokio::join!(first, second);
    assert_eq!(first, Ok(DeletionOutcome::Closed { finished: false }));
    // The owner is let go of at the end.
    rig.deletion.hide().await.expect("free again");
}

#[tokio::test]
async fn a_second_process_neither_begins_confirms_nor_gives_up_while_another_holds_the_deletion() {
    let _clock = CLOCK.lock().await;
    let directory = tempfile::tempdir().expect("a directory");
    let lock = directory.path().join("deletion.lock");
    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let rig = rig_over(Arc::clone(&store)).await;
    let first = deletion(&rig.account, &rig.wire).with_shared_lock(lock.clone());

    // The second process: its own account object and transport over the same secure store.
    let service = Arc::new(Service::default());
    let account = Arc::new(
        SignedInAccount::new(
            Arc::clone(&service) as Arc<dyn AccountService>,
            Arc::clone(&store),
            Client::Desktop,
        )
        .with_clock(clock_ms),
    );
    let wire = Arc::new(Wire::default());
    let second = deletion(&account, &wire).with_shared_lock(lock);

    let (entered, release) = rig.wire.hold_next("/api/account/deletion");
    rig.wire.then([recorded("confirm_closed_closing")]);
    let confirming = first.confirm(CODE, &[], &rig.steps);
    let meanwhile = async {
        entered.notified().await;
        assert_eq!(
            second.confirm(CODE, &[], &rig.steps).await,
            Err(DeletionFault::InProgress)
        );
        assert_eq!(second.hide().await, Err(DeletionFault::InProgress));
        assert_eq!(
            second
                .status(false, &rig.steps)
                .await
                .expect("a status")
                .progress,
            DeletionProgress::Unsettled,
            "the signed-in account is told that a confirmation is out"
        );
        assert!(wire.seen().is_empty(), "the second process sent nothing");
        release.notify_one();
    };
    let (confirmed, ()) = tokio::join!(confirming, meanwhile);
    assert_eq!(confirmed, Ok(DeletionOutcome::Closed { finished: false }));

    // Let go: the second process can act now. It was following the account, so it is told how the
    // removal goes; a process that never followed it is not. The account is gone from the store
    // they share.
    wire.then([recorded("status_open")]);
    assert_eq!(
        second
            .status(true, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::Open
    );
    let third = deletion(&account, &wire);
    wire.then([recorded("status_open")]);
    assert_eq!(
        third
            .status(true, &rig.steps)
            .await
            .expect("a status")
            .progress,
        DeletionProgress::None
    );
    assert_eq!(
        second.confirm(CODE, &[], &rig.steps).await,
        Ok(DeletionOutcome::Closed { finished: false }),
        "a try that meets the closure is told of it, not asked to sign in"
    );
    assert_eq!(
        third.confirm(CODE, &[], &rig.steps).await,
        Err(DeletionFault::NeedsSignIn),
        "a process that never followed the account has no closure to tell"
    );
}

/* ---- The recorded answers agree with the service's own recording ------------------------------ */

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
