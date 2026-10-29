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
    DeletionWarning, ManagedAccountDeletion, UNSETTLED_FOR_MS,
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

#[derive(Default)]
struct Wire {
    script: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    peek: Mutex<Option<Peek>>,
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
        Box::pin(async move { answer })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let answer = self.answer("GET", url, headers, b"");
        Box::pin(async move { answer })
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
    fail_record_write: Mutex<bool>,
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
        if name.as_str() == "account/deletion" && *self.fail_record_write.lock().expect("flaky") {
            // The first write, which is the receipt's, is let through; the one that says the
            // account is closed is refused.
            if self.inner.get(name)?.is_some() {
                return Err(CryptoError::SecretStore {
                    message: "the disk refused".to_owned(),
                });
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

fn path_of(seen: &Seen) -> String {
    seen.url.replacen(ACCOUNT_ORIGIN, "", 1)
}

fn body_of(seen: &Seen) -> serde_json::Value {
    serde_json::from_slice(&seen.body).expect("a json body")
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
    for answer in ["preview_unknown_warning", "preview_unknown_choice"] {
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
    assert_eq!(at_send["closed_ms"], serde_json::Value::Null);
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
        let kept = record(&rig).expect("the record stays until the device has settled");
        assert!(kept["closed_ms"].is_u64());
        assert_eq!(kept["grant_ended"], true);
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
    let kept = record(&rig).expect("the record is kept");
    assert_eq!(kept["closed_ms"], serde_json::Value::Null);

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
        fail_record_write: Mutex::new(false),
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
    assert_eq!(status.progress, DeletionProgress::None);
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
    rig.deletion.device_settled().await.expect("settled");
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
        fail_record_write: Mutex::new(true),
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
    let kept = record(&rig).expect("the receipt's record is there");
    assert_eq!(
        kept["closed_ms"],
        serde_json::Value::Null,
        "the closure could not be written"
    );
}
