//! A host whose configuration names a managed voice broker brokers calls through it, under the
//! account an operator signed in on the host.
//!
//! The daemon is the real one, started from a configuration document that names the broker, and
//! the device is a paired one over a real connection. The broker and the account service are
//! stand-ins on the loopback interface that speak the services' wire, so what these prove is what
//! the daemon sends and what it does with the answers. No test here makes a live provider call.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.01 | `a_host_whose_document_names_a_broker_brokers_a_call_through_it` |
//! | KR-REQ-15.19 | `a_host_whose_document_names_a_broker_brokers_a_call_through_it` |
//! | KR-REQ-17.23 | `an_operator_signs_the_host_in_and_a_call_presents_the_account_it_signed_in` |
//! | KR-REQ-17.23 | `a_sign_in_that_does_not_complete_leaves_the_host_signed_out_and_says_why` |
//! | KR-REQ-17.23 | `a_sign_in_request_sent_again_is_answered_from_the_first` |
//! | KR-REQ-17.23 | `a_sign_in_never_changes_the_account_a_call_closes_under` |
//! | KR-REQ-17.23 | `signing_the_host_out_ends_the_grant_and_a_call_presents_no_account_after_it` |
//! | KR-REQ-17.23 | `a_sign_out_never_changes_the_account_a_call_closes_under` |
//! | KR-REQ-17.23 | `a_sign_out_request_sent_again_is_answered_from_the_first` |
//! | KR-REQ-17.23 | `a_sign_out_ends_the_sign_in_that_is_waiting` |
//! | KR-REQ-17.23 | `an_account_never_changes_under_a_call_whose_start_is_waiting_on_the_broker` |
//! | KR-REQ-17.23 | `an_account_never_changes_under_a_call_whose_close_is_not_finished` |
//! | KR-REQ-17.23 | `a_call_that_opens_while_a_sign_in_is_exchanged_leaves_the_account_as_it_was` |
//! | KR-REQ-17.23 | `a_start_that_meets_an_account_being_changed_is_made_under_the_account_it_leaves` |
//! | KR-REQ-17.23 | `a_host_moved_off_the_managed_broker_can_still_end_the_sign_in_it_keeps` |
//! | KR-REQ-17.23 | `an_account_the_store_could_not_settle_is_not_presented_until_it_is_settled` |
//! | KR-REQ-17.23 | `each_refresh_presents_the_token_the_last_one_issued` |
//! | KR-REQ-17.23 | `an_account_signed_in_at_one_service_is_reached_only_through_that_service` |
//! | KR-REQ-17.23 | `a_revocation_the_service_did_not_acknowledge_is_sent_again_when_the_daemon_starts` |
//! | KR-REQ-17.23 | `a_host_whose_broker_is_not_the_account_service_signs_in_nowhere` |
//! | KR-REQ-15.17 | `a_stop_after_the_service_ended_the_sign_in_still_revokes_the_calls_grant` |
//! | KR-REQ-26.14 | `a_host_reaches_the_broker_through_the_proxy_its_document_selects` |

mod net_support;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::sync::{Arc, Mutex};

use connect_proxy::ConnectProxy;
use kr_client::services::account::{
    AccountToken, Client, ISSUER, IssuedGrant, Redirect, RefreshToken, code_challenge,
};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInParams, AccountSignInStarted, AccountSignOutParams,
    AccountSignedOut, AccountState, AccountStatusParams, SignInUnavailable,
};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::{ActionId, EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::voice::{
    VoiceGrantParams, VoicePrepareParams, VoicePrepareResult, VoiceStartOutcome, VoiceStartParams,
    VoiceStartResult, VoiceStopParams,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// How long a mutation over the network asks the host to hold its admission for.
const NETWORK_LIFETIME: DurationMs = DurationMs::new(120_000);

/// One request the stand-in broker received.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    authorization: Option<String>,
    body: serde_json::Value,
}

/// What the stand-in account service has issued, and what it will do next.
struct Account {
    /// The nonce and the challenge of the sign-in the browser was sent to.
    nonce: String,
    challenge: String,
    /// How many seconds the next token it issues lasts.
    expires_in: u64,
    issued: u32,
    access: String,
    refresh: String,
    /// The family ended: a refresh token presented twice, or the service ending the sign-in.
    ended: bool,
    /// Every refresh token presented to it, in order.
    refreshes: Vec<String>,
    /// Names this service's tokens, so two services' tokens are never alike.
    label: String,
    /// The account the service says is signed in.
    subject: String,
    /// The account the identity read names, when it is not the one the code was issued for.
    userinfo_subject: Option<String>,
    /// Whether a revocation is refused, as a service that cannot be reached refuses it.
    revoke_fails: bool,
    /// Every refresh token revoked at it, in order.
    revoked: Vec<String>,
}

impl Account {
    fn issue(&mut self, with_identity: bool) -> serde_json::Value {
        self.issued += 1;
        self.access = format!("access-{}-{}", self.label, self.issued);
        self.refresh = format!("refresh-{}-{}", self.label, self.issued);
        let mut answer = serde_json::json!({
            "access_token": self.access,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "refresh_token": self.refresh,
            "scope": "openid profile email offline_access voice",
        });
        if with_identity {
            let encode = |value: &serde_json::Value| {
                base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    serde_json::to_vec(value).expect("json"),
                )
            };
            let now = kr_ipc::now_ms().get() / 1000;
            let claims = serde_json::json!({
                "iss": ISSUER,
                "sub": self.subject,
                "aud": Client::Desktop.id(),
                "nonce": self.nonce,
                "iat": now - 5,
                "exp": now + 3600,
            });
            answer["id_token"] = serde_json::Value::String(format!(
                "{}.{}.signature",
                encode(&serde_json::json!({"alg": "RS256", "typ": "JWT"})),
                encode(&claims)
            ));
        }
        answer
    }
}

/// A request the stand-in holds until the suite lets it go.
struct Hold {
    path: String,
    reached: Arc<tokio::sync::Notify>,
    released: tokio::sync::watch::Receiver<bool>,
}

/// The suite's end of a held request: when it has arrived, and the way to let it go.
struct Held {
    reached: Arc<tokio::sync::Notify>,
    release: tokio::sync::watch::Sender<bool>,
}

impl Held {
    /// Waits until the request is at the stand-in, not yet answered.
    async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Lets the request be answered.
    fn release(self) {
        let _ = self.release.send(true);
    }
}

/// Everything the stand-in services share.
struct Shared {
    seen: Mutex<Vec<Seen>>,
    account: Mutex<Account>,
    holds: Mutex<Vec<Hold>>,
}

/// A managed voice service and its account service on the loopback interface, as far as their
/// wire goes.
struct Broker {
    origin: String,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Broker {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let listener_port = listener.local_addr().expect("an address").port();
        let origin = format!("http://{}", listener.local_addr().expect("an address"));
        let shared = Arc::new(Shared {
            seen: Mutex::default(),
            holds: Mutex::default(),
            account: Mutex::new(Account {
                nonce: String::new(),
                challenge: String::new(),
                expires_in: 600,
                issued: 0,
                access: String::new(),
                refresh: String::new(),
                ended: false,
                refreshes: Vec::new(),
                label: listener_port.to_string(),
                subject: "account-1".to_owned(),
                userinfo_subject: None,
                revoke_fails: false,
                revoked: Vec::new(),
            }),
        });
        let record = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    answer(stream, &record).await;
                });
            }
        });
        Self {
            origin,
            shared,
            task,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.shared.seen.lock().expect("what was seen").clone()
    }

    /// Holds the next request for `path` unanswered, after it has been checked, until the returned
    /// handle lets it go.
    fn hold(&self, path: &str) -> Held {
        let reached = Arc::new(tokio::sync::Notify::new());
        let (release, released) = tokio::sync::watch::channel(false);
        self.shared.holds.lock().expect("the holds").push(Hold {
            path: path.to_owned(),
            reached: Arc::clone(&reached),
            released,
        });
        Held { reached, release }
    }

    /// A sign-in the service has issued, as a finished browser sign-in leaves one, whose tokens
    /// last `expires_in` seconds.
    fn issue_grant(&self, expires_in: u64) -> IssuedGrant {
        let mut account = self.shared.account.lock().expect("the account");
        account.expires_in = expires_in;
        let answer = account.issue(false);
        IssuedGrant {
            access_token: AccountToken::new(answer["access_token"].as_str().expect("a token"))
                .expect("a token"),
            expires_in_seconds: expires_in,
            refresh_token: RefreshToken::new(answer["refresh_token"].as_str().expect("a token"))
                .expect("a token"),
            scopes: ["openid", "profile", "email", "offline_access", "voice"]
                .map(str::to_owned)
                .to_vec(),
            subject: "account-1".to_owned(),
        }
    }

    /// The service no longer honours the sign-in: its next refresh is refused.
    fn end_the_sign_in(&self) {
        self.shared.account.lock().expect("the account").ended = true;
    }

    /// The access token this service issues as its `n`th.
    fn access(&self, n: u32) -> String {
        format!(
            "access-{}-{n}",
            self.shared.account.lock().expect("the account").label
        )
    }

    /// The refresh token this service issues as its `n`th.
    fn refresh(&self, n: u32) -> String {
        format!(
            "refresh-{}-{n}",
            self.shared.account.lock().expect("the account").label
        )
    }

    /// Has the service refuse revocations, as one that cannot be reached would.
    fn refuse_revocations(&self, refuse: bool) {
        self.shared
            .account
            .lock()
            .expect("the account")
            .revoke_fails = refuse;
    }

    /// The refresh tokens revoked at the service, in order.
    fn revoked(&self) -> Vec<String> {
        self.shared
            .account
            .lock()
            .expect("the account")
            .revoked
            .clone()
    }

    /// Has the identity read name another account than the one the code was issued for.
    fn name_another_account(&self) {
        self.shared
            .account
            .lock()
            .expect("the account")
            .userinfo_subject = Some("account-2".to_owned());
    }

    /// The refresh tokens presented to the service, in order.
    fn refreshes(&self) -> Vec<String> {
        self.shared
            .account
            .lock()
            .expect("the account")
            .refreshes
            .clone()
    }

    /// Tells the stand-in which sign-in the browser was sent to.
    fn expect_sign_in(&self, authorise_url: &str) {
        let url = url::Url::parse(authorise_url).expect("an address");
        let query: std::collections::BTreeMap<String, String> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let mut account = self.shared.account.lock().expect("the account");
        account.nonce = query["nonce"].clone();
        account.challenge = query["code_challenge"].clone();
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads one request and answers it in the services' envelopes.
async fn answer(mut stream: TcpStream, shared: &Shared) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (head_end, length) = loop {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while bytes.len() < head_end + length {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&bytes[..head_end]).into_owned();
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned();
    let authorization = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_owned())
    });
    let raw = &bytes[head_end..head_end + length];
    let body: serde_json::Value = if path.starts_with("/auth/") {
        serde_json::Value::Object(
            url::form_urlencoded::parse(raw)
                .map(|(name, value)| {
                    (
                        name.into_owned(),
                        serde_json::Value::String(value.into_owned()),
                    )
                })
                .collect(),
        )
    } else {
        serde_json::from_slice(raw).unwrap_or_default()
    };
    shared.seen.lock().expect("what was seen").push(Seen {
        path: path.clone(),
        authorization: authorization.clone(),
        body: body.clone(),
    });
    // A request the suite holds waits here, after it is recorded, whichever service it is for.
    let held = shared
        .holds
        .lock()
        .expect("the holds")
        .iter()
        .find(|hold| hold.path == path)
        .map(|hold| (Arc::clone(&hold.reached), hold.released.clone()));
    if let Some((reached, mut released)) = held {
        reached.notify_one();
        let _ = released.wait_for(|released| *released).await;
    }
    if path.starts_with("/auth/") {
        let (status, answer) = account_answer(shared, &path, authorization.as_deref(), &body);
        let _ = stream
            .write_all(&response(
                status,
                &serde_json::to_vec(&answer).expect("json"),
            ))
            .await;
        return;
    }
    // The voice service accepts the access token the account service issued last, and no other.
    let unauthenticated = {
        let account = shared.account.lock().expect("the account");
        account.issued > 0
            && authorization.as_deref() != Some(format!("Bearer {}", account.access).as_str())
    };
    if unauthenticated {
        let refusal = br#"{"ok":false,"error":{"code":"UNAUTHENTICATED","message":"No."}}"#;
        let _ = stream.write_all(&response(401, refusal)).await;
        return;
    }
    let data = match path.as_str() {
        "/api/voice/metadata" => serde_json::json!({
            "enabled": true,
            "model": "gpt-live-1",
            "disclosure": ["The managed service can read the conversation."],
            "admissionNote": "An acknowledgement is not execution.",
            "delegationNote": "A delegation identifier is correlation data.",
            "alternatives": ["Your own coding agent"],
            "rate": {
                "version": "2026-09",
                "minorUnitsPerSecond": "1",
                "minimumSeconds": 15,
                "currency": "USD"
            },
            "maximumSessionSeconds": 1800,
            "minimumRequestSeconds": 60,
            "heartbeatSeconds": 20,
            "contextBytes": 500
        }),
        "/api/voice/sessions" => serde_json::json!({
            "callId": "call-1",
            "attemptId": "attempt-1",
            "providerSessionId": "live_1",
            "answerSdp": "v=0\r\na=answered-by-the-stand-in\r\n",
            "model": "gpt-live-1",
            "closesAt": "2099-01-01T00:10:00Z",
            "reservationEndsAt": "2099-01-01T00:10:15Z",
            "controlPath": "/api/voice/sessions/call-1/control",
            "heartbeatSeconds": 20,
            "sidebandReady": true,
            "hold": {
                "reservationId": "hold-1",
                "reserved": "600",
                "ceiling": "600",
                "deadline": "2099-01-01T00:10:15Z"
            },
            "reasoningHold": null,
            "rate": {
                "version": "2026-09",
                "minorUnitsPerSecond": "1",
                "minimumSeconds": 15,
                "currency": "USD"
            },
            "latency": { "creationToAnswerMs": 10, "sidebandReadyMs": 5 },
            "replayed": false,
            "disclosure": ["The managed service can read the conversation."]
        }),
        "/api/voice/sessions/call-1/close" => serde_json::json!({
            "callId": "call-1",
            "state": "finalised",
            "usageSeconds": 0,
            "usageProvisional": true
        }),
        _ => {
            let refusal =
                br#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No such route."}}"#;
            let _ = stream.write_all(&response(404, refusal)).await;
            return;
        }
    };
    let envelope = serde_json::json!({ "ok": true, "data": data });
    let body = serde_json::to_vec(&envelope).expect("an envelope");
    let _ = stream.write_all(&response(200, &body)).await;
}

/// The account service's answers: the token endpoint, the identity read and the revocation.
fn account_answer(
    shared: &Shared,
    path: &str,
    authorization: Option<&str>,
    form: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut account = shared.account.lock().expect("the account");
    let refused = || (400, serde_json::json!({"error": "invalid_grant"}));
    match path {
        "/auth/oauth2/token" => match form["grant_type"].as_str() {
            Some("authorization_code") => {
                let redeemable = form["code"] == "the-code"
                    && form["redirect_uri"] == Redirect::Loopback.uri()
                    && form["client_id"] == Client::Desktop.id()
                    && code_challenge(form["code_verifier"].as_str().unwrap_or(""))
                        == account.challenge;
                if !redeemable {
                    return refused();
                }
                (200, account.issue(true))
            }
            Some("refresh_token") => {
                let presented = form["refresh_token"].as_str().unwrap_or("").to_owned();
                account.refreshes.push(presented.clone());
                // A refresh token presented a second time ends the whole family.
                if account.ended || presented != account.refresh {
                    account.ended = true;
                    return refused();
                }
                (200, account.issue(false))
            }
            _ => refused(),
        },
        "/auth/oauth2/userinfo" => {
            if authorization != Some(format!("Bearer {}", account.access).as_str()) {
                return (401, serde_json::json!({"error": "invalid_token"}));
            }
            (
                200,
                serde_json::json!({
                    "sub": account.userinfo_subject.as_ref().unwrap_or(&account.subject),
                    "email": "someone@example.test"
                }),
            )
        }
        "/auth/oauth2/revoke" => {
            if account.revoke_fails {
                return (503, serde_json::json!({"error": "temporarily_unavailable"}));
            }
            let revoked = form["token"].as_str().unwrap_or("").to_owned();
            account.revoked.push(revoked);
            (200, serde_json::json!({}))
        }
        _ => (404, serde_json::json!({"error": "not_found"})),
    }
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// The document an operator writes to name the broker.
fn document_naming(origin: &str) -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(origin.to_owned());
    document
}

/// Signs the host in as a finished browser sign-in would, with the tokens the service issued.
async fn sign_in_with(host: &net_support::Host, grant: IssuedGrant) {
    host.controller().host_account().keep_for_test(grant).await;
}

/// A sign-in at a service the test has no stand-in for.
fn grant(access: &str, refresh: &str, expires_in_seconds: u64) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new(access).expect("a token"),
        expires_in_seconds,
        refresh_token: RefreshToken::new(refresh).expect("a token"),
        scopes: ["openid", "voice"].map(str::to_owned).to_vec(),
        subject: "account-1".to_owned(),
    }
}

/// Starts the host's own sign-in at its local socket and returns the address the browser opens.
///
/// The daemon listens on a free loopback port of its own, so suites do not wait for one another.
async fn start_sign_in(host: &net_support::Host) -> (String, String) {
    let mut local = host.client().await;
    local
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon starts the sign-in");
    let report = account_report(host).await;
    match report.state {
        AccountState::WaitingForBrowser {
            authorise_url,
            redirect_address,
            ..
        } => (authorise_url, redirect_address),
        other => panic!("a sign-in is waiting for the browser: {other:?}"),
    }
}

/// Where the host's sign-in stands, read at its local socket.
async fn account_report(host: &net_support::Host) -> AccountReport {
    host.client()
        .await
        .request(Method::AccountStatus, &AccountStatusParams {})
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon reports")
        .to_typed()
        .expect("a report")
}

/// A loopback port nothing holds now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port")
        .local_addr()
        .expect("an address")
        .port()
}

/// Has the daemon listen for sign-ins on `port` instead of the registered address.
fn listen_for_sign_ins_on(host: &net_support::Host, port: u16) {
    host.controller()
        .host_account()
        .listen_on(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
}

/// Waits until no sign-in is waiting or finishing, and returns where the host stands.
async fn settled(host: &net_support::Host) -> AccountReport {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let report = account_report(host).await;
            if !matches!(
                report.state,
                AccountState::WaitingForBrowser { .. } | AccountState::Finishing
            ) {
                return report;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the sign-in settles")
}

/// The browser coming back to the daemon with `code`, as the service sends it on to the address
/// the sign-in named. Returns the page the daemon answered with.
async fn browser_answers(redirect_address: &str, authorise_url: &str, code: &str) -> String {
    let url = url::Url::parse(authorise_url).expect("an address");
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .expect("the sign-in names its state");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", code)
        .append_pair("state", &state)
        .append_pair("iss", ISSUER)
        .finish();
    let mut stream = TcpStream::connect(redirect_address)
        .await
        .expect("the daemon listens");
    stream
        .write_all(
            format!("GET /oauth/callback?{query} HTTP/1.1\r\nHost: {redirect_address}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("the answer is sent");
    let mut page = String::new();
    let _ = stream.read_to_string(&mut page).await;
    page
}

async fn try_mutate<P: serde::Serialize + ?Sized>(
    session: &kr_client::session::Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> Result<ParamsValue, kr_client::error::ClientError> {
    session
        .mutate(
            method,
            ActionTarget::environment(environment_id),
            None,
            &ParamsValue::empty(),
            params,
            NETWORK_LIFETIME,
        )
        .await
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a voice mutation answers with its result")
        })
}

async fn mutate<P: serde::Serialize + ?Sized>(
    session: &kr_client::session::Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> ParamsValue {
    try_mutate(session, environment_id, method, params)
        .await
        .expect("the host answers")
}

/// Signs the host out at its local socket under the action given, on the connection given.
async fn sign_out_on(
    client: &mut kr_ipc::client::LocalClient,
    host: &net_support::Host,
    action: ActionId,
) -> Result<AccountSignedOut, ProtocolError> {
    client
        .mutate(
            Method::AccountSignOut,
            action,
            ActionTarget::environment(host.environment_id),
            &AccountSignOutParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("a sign-out answer"))
}

/// Signs the host out at its local socket under the action given.
async fn sign_out_as(
    host: &net_support::Host,
    action: ActionId,
) -> Result<AccountSignedOut, ProtocolError> {
    sign_out_on(&mut host.client().await, host, action).await
}

/// Signs the host out, under a new action.
async fn sign_out(host: &net_support::Host) -> AccountSignedOut {
    sign_out_as(host, ActionId::new(kr_ipc::new_uuid()))
        .await
        .expect("the daemon signs the host out")
}

/// What a device asks to start a call with, from what it was shown.
fn start_params(session_id: SessionId, prepared: &VoicePrepareResult) -> VoiceStartParams {
    let terms = prepared
        .managed
        .as_ref()
        .unwrap_or_else(|| panic!("the service's terms: {:?}", prepared.managed_unavailable));
    VoiceStartParams {
        session_ids: [session_id].into_iter().collect(),
        offer_sdp: "v=0\r\n".to_owned(),
        duration_seconds: 600,
        reasoning_budget_minor: Nullable::null(),
        prepared: prepared.prepared,
        expected_rate_version: Nullable::some(terms.rate.version.clone()),
    }
}

/// A call a paired device starts, brokered under the account the host is signed in as.
async fn start_a_call(
    host: &net_support::Host,
    owner: &DeviceKeys,
) -> (
    net_support::Device,
    kr_client::session::Session,
    Box<kr_protocol::voice::VoiceSessionDescriptor>,
) {
    let (device, session, session_id, prepared) = ready(host, owner).await;
    let started: VoiceStartResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &start_params(session_id, &prepared),
    )
    .await
    .to_typed()
    .expect("a start result");
    let VoiceStartOutcome::Started { session: call } = started.outcome else {
        panic!("the broker created the call: {:?}", started.outcome);
    };
    (device, session, call)
}

/// A paired device with a voice grant, and the preparation it read.
async fn ready(
    host: &net_support::Host,
    owner: &DeviceKeys,
) -> (
    net_support::Device,
    kr_client::session::Session,
    SessionId,
    VoicePrepareResult,
) {
    let (device, session) = net_support::paired_device(
        host,
        owner,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let device_id = host
        .controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| {
            let owner = host.owner.as_ref().map(|owner| owner.device_id);
            record.is_paired() && owner != Some(record.device_id)
        })
        .expect("the paired device")
        .device_id;
    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceGrant,
        &VoiceGrantParams {
            device_id,
            session_ids: [session_id].into_iter().collect(),
            actions: Nullable::null(),
        },
    )
    .await;
    let prepared: VoicePrepareResult = session
        .read(
            Method::VoicePrepare,
            &VoicePrepareParams {
                session_ids: [session_id].into_iter().collect(),
                selected: CanonicalSet::from_iter([]),
            },
        )
        .await
        .expect("the host answers what a call would be");
    (device, session, session_id, prepared)
}

/// KR-REQ-15.01 and 15.19: a host whose document names a broker reads the service's terms for a
/// device that asks what a call would be, starts the call there under the account an operator
/// signed in on the host and the rate the device was shown, and tells the broker when the call
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_document_names_a_broker_brokers_a_call_through_it() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;

    let terms = prepared
        .managed
        .as_ref()
        .unwrap_or_else(|| panic!("the service's terms: {:?}", prepared.managed_unavailable));
    assert_eq!(terms.rate.version, "2026-09");
    assert_eq!(prepared.broker_origin, broker.origin);

    let offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\na=the-devices-own-offer\r\n";
    let started: VoiceStartResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: offer.to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: prepared.prepared,
            expected_rate_version: Nullable::some(terms.rate.version.clone()),
        },
    )
    .await
    .to_typed()
    .expect("a start result");
    let VoiceStartOutcome::Started { session: call } = started.outcome else {
        panic!("the broker created the call: {:?}", started.outcome);
    };
    assert_eq!(call.call_id, "call-1");
    assert_eq!(call.answer_sdp, "v=0\r\na=answered-by-the-stand-in\r\n");

    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await;

    let seen = broker.seen();
    let count = |path: &str| seen.iter().filter(|request| request.path == path).count();
    assert!(
        count("/api/voice/metadata") >= 1,
        "the host asked the service what a call is"
    );
    assert_eq!(count("/api/voice/sessions"), 1, "the host started one call");
    assert_eq!(
        count("/api/voice/sessions/call-1/close"),
        1,
        "the host told the service the call ended"
    );
    let start = seen
        .iter()
        .find(|request| request.path == "/api/voice/sessions")
        .expect("the start request");
    for request in &seen {
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Bearer {}", broker.access(1)).as_str()),
            "{} carried the signed-in account's token",
            request.path
        );
    }
    assert!(
        broker.refreshes().is_empty(),
        "a token with ten minutes left is not replaced"
    );
    assert_eq!(
        start.body["offerSdp"], offer,
        "the device's own offer reached the service unchanged"
    );
    assert_eq!(start.body["expectedRateVersion"], "2026-09");
    host.stop().await;
}

/// KR-REQ-15.01: a host whose document names no broker starts no call, whatever a device asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_document_names_no_broker_starts_no_call() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &ConfigurationDocument::empty()).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    assert!(
        prepared.managed.as_ref().is_none(),
        "no service is named, so no terms are offered"
    );

    let refused = try_mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: prepared.prepared,
            expected_rate_version: Nullable::some("2026-09".to_owned()),
        },
    )
    .await
    .expect_err("a host that names no service starts no call");
    let kr_client::error::ClientError::Host(refusal) = refused else {
        panic!("the host refuses it: {refused:?}");
    };
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refusal:?}"
    );
    assert!(broker.seen().is_empty(), "nothing reached a service");
    host.stop().await;
}

/// KR-REQ-26.14: the host reaches the broker through the proxy its document selects, and through
/// nothing else: a proxy that refuses the tunnel leaves the service unreachable rather than
/// reached around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_reaches_the_broker_through_the_proxy_its_document_selects() {
    let proxy = ConnectProxy::refusing(403).await;
    let origin = "https://voice.example.test";
    let mut document = document_naming(origin);
    document.network.proxy_url = Nullable::some(proxy.url.clone());
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start_with_document(&owner, &document).await;
    sign_in_with(&host, grant("an-access-token", "a-refresh-token", 600)).await;
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;

    assert!(
        prepared.managed.as_ref().is_none(),
        "the proxy refused the tunnel, so the service's terms were not read"
    );
    assert!(
        proxy
            .asked()
            .contains(&"CONNECT voice.example.test:443 HTTP/1.1".to_owned()),
        "the host asked the proxy for the broker: {:?}",
        proxy.asked()
    );
    host.stop().await;
}

/// KR-REQ-17.23: an operator signs the host in through a browser, the daemon keeps the account and
/// shows none of it, and a call presents the token of the account it signed in. The address the
/// browser opens asks for the voice scope. A browser answer that is not for the attempt the host is
/// waiting on is set aside, and a second sign-in ends the first and takes its address over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_signs_the_host_in_and_a_call_presents_the_account_it_signed_in() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    // One address for both attempts, as the registered one is: the second can bind it only if the
    // first has let it go.
    listen_for_sign_ins_on(&host, free_port());
    let before = account_report(&host).await;
    assert_eq!(before.state, AccountState::SignedOut);
    assert_eq!(before.service.as_ref(), Some(&broker.origin));

    let (first_url, first_address) = start_sign_in(&host).await;
    let (second_url, second_address) = start_sign_in(&host).await;
    assert_eq!(
        first_address, second_address,
        "the second attempt took the address over"
    );
    assert_ne!(first_url, second_url, "a second sign-in is a new attempt");
    assert_eq!(
        account_report(&host).await.last_attempt.as_ref(),
        Some(&AccountAttempt::Superseded),
        "the first attempt ended because the second began"
    );
    broker.expect_sign_in(&second_url);
    let asked: std::collections::BTreeMap<String, String> = url::Url::parse(&second_url)
        .expect("an address")
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert!(
        asked["scope"].split(' ').any(|scope| scope == "voice"),
        "the sign-in asks for the voice scope: {}",
        asked["scope"]
    );
    assert_eq!(asked["code_challenge_method"], "S256");
    assert_eq!(asked["redirect_uri"], Redirect::Loopback.uri());

    // The first attempt's state is not the second's, so the browser that carries it is told so and
    // the host goes on waiting.
    let stray = browser_answers(&second_address, &first_url, "the-code").await;
    assert!(stray.starts_with("HTTP/1.1 400"), "{stray}");
    assert!(
        matches!(
            account_report(&host).await.state,
            AccountState::WaitingForBrowser { .. }
        ),
        "a stray answer does not end the sign-in"
    );
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| !request.path.starts_with("/auth/")),
        "nothing was exchanged for it"
    );

    let page = browser_answers(&second_address, &second_url, "the-code").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");

    let report = settled(&host).await;
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::SignedIn)
    );
    let AccountState::SignedIn {
        origin,
        email,
        scopes,
    } = &report.state
    else {
        panic!("the account is signed in: {report:?}");
    };
    assert_eq!(origin, &broker.origin);
    assert_eq!(
        email.as_ref().map(String::as_str),
        Some("someone@example.test")
    );
    assert!(scopes.iter().any(|scope| scope == "voice"), "{scopes:?}");
    let said = serde_json::to_string(&report).expect("a report");
    for held in [broker.access(1), broker.refresh(1)] {
        assert!(!said.contains(&held), "the report says no token: {said}");
        assert!(!format!("{report:?}").contains(&held));
    }

    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    let terms = prepared
        .managed
        .as_ref()
        .unwrap_or_else(|| panic!("the service's terms: {:?}", prepared.managed_unavailable));
    let started: VoiceStartResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: prepared.prepared,
            expected_rate_version: Nullable::some(terms.rate.version.clone()),
        },
    )
    .await
    .to_typed()
    .expect("a start result");
    assert!(matches!(started.outcome, VoiceStartOutcome::Started { .. }));
    for request in broker.seen() {
        if request.path.starts_with("/api/voice/") {
            assert_eq!(
                request.authorization.as_deref(),
                Some(format!("Bearer {}", broker.access(1)).as_str()),
                "{} carried the account the host signed in",
                request.path
            );
        }
    }
    host.stop().await;
}

/// KR-REQ-17.23: a sign-in that does not complete leaves the host signed out and says why: the
/// service refusing the code, the identity read naming another account than the one the code was
/// issued for, and another program holding the address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_that_does_not_complete_leaves_the_host_signed_out_and_says_why() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());

    // The service does not redeem a code it did not issue.
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    let _ = browser_answers(&address, &url, "a-code-the-service-never-issued").await;
    let report = settled(&host).await;
    assert_eq!(report.state, AccountState::SignedOut);
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::ServiceRefused)
    );

    // The identity read disagrees with the code's account: the sign-in is undone, not kept.
    broker.name_another_account();
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    let _ = browser_answers(&address, &url, "the-code").await;
    let report = settled(&host).await;
    assert_eq!(report.state, AccountState::SignedOut, "{report:?}");
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::NotForThisAttempt)
    );

    // Another program holds the address.
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    listen_for_sign_ins_on(&host, held.local_addr().expect("an address").port());
    let refused = host
        .client()
        .await
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("the address is held");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "{refused:?}"
    );
    assert_eq!(
        account_report(&host).await.last_attempt.as_ref(),
        Some(&AccountAttempt::PortBusy)
    );
    host.stop().await;
}

/// KR-REQ-17.23: a request to start a sign-in that is sent again, as one whose answer was lost is,
/// is answered from the first and does not end the attempt that is waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_request_sent_again_is_answered_from_the_first() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    let action = ActionId::new(kr_ipc::new_uuid());
    let mut asked = Vec::new();
    // On one connection, as a retry of a request whose answer was lost is: the digest the host
    // keeps covers the window the request was sent under.
    let mut client = host.client().await;
    for _ in 0..2 {
        asked.push(
            client
                .mutate(
                    Method::AccountSignIn,
                    action,
                    ActionTarget::environment(host.environment_id),
                    &AccountSignInParams {},
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the daemon starts the sign-in")
                .to_typed::<AccountSignInStarted>()
                .expect("a started sign-in"),
        );
    }
    assert_eq!(asked[0], asked[1], "the repeat is the first one's answer");
    let AccountState::WaitingForBrowser {
        authorise_url,
        redirect_address,
        ..
    } = account_report(&host).await.state
    else {
        panic!("one sign-in is waiting");
    };
    broker.expect_sign_in(&authorise_url);
    let page = browser_answers(&redirect_address, &authorise_url, "the-code").await;
    assert!(
        page.starts_with("HTTP/1.1 200"),
        "the attempt the repeat left alone still completes: {page}"
    );
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: a call closes under the account it started under, so a sign-in is refused
/// while a call is open, and one that is waiting when a call opens ends without spending its code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_never_changes_the_account_a_call_closes_under() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    sign_in_with(&host, broker.issue_grant(600)).await;

    // A sign-in begins, and then a call opens while the person is in the browser.
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    let (_device, session, call) = start_a_call(&host, &owner).await;
    let _ = browser_answers(&address, &url, "the-code").await;
    let report = settled(&host).await;
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::CallOpen)
    );
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| request.path != "/auth/oauth2/token"),
        "the code was not spent"
    );

    // And a new sign-in is refused outright while the call is open.
    let refused = host
        .client()
        .await
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a call is open");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "{refused:?}"
    );

    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await;
    start_sign_in(&host).await;
    host.stop().await;
}

/// KR-REQ-17.23: signing the host out removes the grant at once and asks the service to end it, so
/// a call after it presents no account; a revocation the service does not acknowledge is sent
/// again when the daemon next starts; and signing out a host with no account changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_the_host_out_ends_the_grant_and_a_call_presents_no_account_after_it() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    assert!(matches!(
        account_report(&host).await.state,
        AccountState::SignedIn { .. }
    ));

    let done = sign_out(&host).await;
    assert_eq!(
        done,
        AccountSignedOut {
            was_signed_in: true,
            service_told: true
        }
    );
    assert_eq!(broker.revoked(), [broker.refresh(1)]);
    let report = account_report(&host).await;
    assert_eq!(report.state, AccountState::SignedOut);
    assert_eq!(report.last_attempt.as_ref(), None);
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;
    assert!(
        prepared.managed.as_ref().is_none(),
        "no terms were read without an account"
    );
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| request.authorization.is_none()),
        "the broker was shown no account"
    );

    // With no account signed in there is nothing to end, and nothing more is sent.
    assert_eq!(
        sign_out(&host).await,
        AccountSignedOut {
            was_signed_in: false,
            service_told: true
        }
    );
    assert_eq!(broker.revoked().len(), 1);

    // A service that cannot be told leaves the grant gone from this host, and is told when the
    // daemon next starts.
    sign_in_with(&host, broker.issue_grant(600)).await;
    broker.refuse_revocations(true);
    assert_eq!(
        sign_out(&host).await,
        AccountSignedOut {
            was_signed_in: true,
            service_told: false
        }
    );
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
    assert_eq!(broker.revoked().len(), 1, "the service refused it");
    let stopped = host.shut_down().await;
    broker.refuse_revocations(false);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while broker.revoked().len() < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the daemon sends the revocation again");
    assert_eq!(broker.revoked(), [broker.refresh(1), broker.refresh(2)]);
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: a call closes under the account it started under, so a sign-out is
/// refused while a call is open and leaves the account as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_out_never_changes_the_account_a_call_closes_under() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (_device, session, call) = start_a_call(&host, &owner).await;

    let refused = sign_out_as(&host, ActionId::new(kr_ipc::new_uuid()))
        .await
        .expect_err("a call is open");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable,
        "{refused:?}"
    );
    assert!(matches!(
        account_report(&host).await.state,
        AccountState::SignedIn { .. }
    ));
    assert!(broker.revoked().is_empty(), "nothing was revoked");

    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await;
    assert!(sign_out(&host).await.was_signed_in);
    host.stop().await;
}

/// KR-REQ-17.23: a request to sign out that is sent again, as one whose answer was lost is, is
/// answered from the first and does not sign out an account signed in since.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_out_request_sent_again_is_answered_from_the_first() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    // On one connection, as a retry of a request whose answer was lost is: the digest the host
    // keeps covers the window the request was sent under.
    let mut client = host.client().await;
    let first = sign_out_on(&mut client, &host, action)
        .await
        .expect("the daemon signs the host out");
    assert!(first.was_signed_in);
    sign_in_with(&host, broker.issue_grant(600)).await;
    let again = sign_out_on(&mut client, &host, action)
        .await
        .expect("the repeat is answered");
    assert_eq!(first, again, "the repeat is the first one's answer");
    assert!(
        matches!(
            account_report(&host).await.state,
            AccountState::SignedIn { .. }
        ),
        "the account signed in since is still signed in"
    );
    assert_eq!(broker.revoked(), [broker.refresh(1)]);
    host.stop().await;
}

/// KR-REQ-17.23: signing the host out ends a sign-in that is waiting for the browser, so it cannot
/// sign the host in again afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_out_ends_the_sign_in_that_is_waiting() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);

    assert!(!sign_out(&host).await.was_signed_in);
    let report = account_report(&host).await;
    assert_eq!(report.state, AccountState::SignedOut);
    assert_eq!(report.last_attempt.as_ref(), None);
    // The address is let go when the last copy of the listener's socket is closed, which is a
    // condition to wait for rather than an instant.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while TcpStream::connect(&address).await.is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("nothing listens for the browser any more");
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| !request.path.starts_with("/auth/")),
        "no code was exchanged"
    );
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: a call closes under the account it started under, and a start waits on the
/// broker for seconds before it is recorded. While it waits, signing out is refused and a browser
/// answer ends its sign-in unspent, so the account the start asked under is the one that closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_never_changes_under_a_call_whose_start_is_waiting_on_the_broker() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    let held = broker.hold("/api/voice/sessions");

    let (started, ()) = tokio::join!(
        async {
            let started: VoiceStartResult = mutate(
                &session,
                host.environment_id,
                Method::VoiceStart,
                &start_params(session_id, &prepared),
            )
            .await
            .to_typed()
            .expect("a start result");
            started
        },
        async {
            held.reached().await;
            // The call is not recorded yet: the broker has not answered. A sign-out is refused.
            let refused = sign_out_as(&host, ActionId::new(kr_ipc::new_uuid()))
                .await
                .expect_err("a call is starting");
            assert_eq!(
                refused.code,
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "{refused:?}"
            );
            // And the browser coming back ends the waiting sign-in before its code is spent.
            let _ = browser_answers(&address, &url, "the-code").await;
            let report = settled(&host).await;
            assert_eq!(
                report.last_attempt.as_ref(),
                Some(&AccountAttempt::CallOpen)
            );
            assert!(
                matches!(report.state, AccountState::SignedIn { .. }),
                "the account is as it was: {report:?}"
            );
            assert!(
                broker
                    .seen()
                    .iter()
                    .all(|request| request.path != "/auth/oauth2/token"),
                "the code was not spent"
            );
            held.release();
        }
    );
    let VoiceStartOutcome::Started { session: call } = started.outcome else {
        panic!("the broker created the call: {:?}", started.outcome);
    };
    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await;
    let closes: Vec<_> = broker
        .seen()
        .into_iter()
        .filter(|request| request.path.starts_with("/api/voice/sessions"))
        .collect();
    assert_eq!(closes.len(), 2, "the start and the close: {closes:?}");
    for request in closes {
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Bearer {}", broker.access(1)).as_str()),
            "{} carried the account the call started under",
            request.path
        );
    }
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: a stop removes the call's record before it tells the broker, and the
/// close asks for a token of its own. Until the broker has been told, signing out is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_never_changes_under_a_call_whose_close_is_not_finished() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (_device, session, call) = start_a_call(&host, &owner).await;
    let held = broker.hold("/api/voice/sessions/call-1/close");

    let (_stopped, ()) = tokio::join!(
        async {
            mutate(
                &session,
                host.environment_id,
                Method::VoiceStop,
                &VoiceStopParams {
                    voice_session_id: call.voice_session_id,
                },
            )
            .await
        },
        async {
            held.reached().await;
            // The record is gone and the broker has not been told: the call is still open.
            let refused = sign_out_as(&host, ActionId::new(kr_ipc::new_uuid()))
                .await
                .expect_err("a close is not finished");
            assert_eq!(
                refused.code,
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "{refused:?}"
            );
            assert!(matches!(
                account_report(&host).await.state,
                AccountState::SignedIn { .. }
            ));
            held.release();
        }
    );
    let close = broker
        .seen()
        .into_iter()
        .find(|request| request.path == "/api/voice/sessions/call-1/close")
        .expect("the broker was told");
    assert_eq!(
        close.authorization.as_deref(),
        Some(format!("Bearer {}", broker.access(1)).as_str()),
        "the close carried the account the call started under"
    );
    assert!(sign_out(&host).await.was_signed_in);
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: a call that opens while a sign-in's code is being exchanged leaves the
/// account as it was. The grant the exchange brought is revoked, and when the service cannot be told
/// at once it is told when the daemon next starts; the call closes under the account it started
/// under.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_that_opens_while_a_sign_in_is_exchanged_leaves_the_account_as_it_was() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    let exchange = broker.hold("/auth/oauth2/token");
    // The new grant's revocation is refused, as a service that cannot be reached refuses it.
    broker.refuse_revocations(true);

    let (page, call) = tokio::join!(browser_answers(&address, &url, "the-code"), async {
        exchange.reached().await;
        // The code is out at the service. A call opens now, under the account signed in.
        let started = start_a_call(&host, &owner).await;
        exchange.release();
        started
    });
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    let (_device, session, call) = call;
    let report = settled(&host).await;
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::CallOpen)
    );
    assert!(
        matches!(report.state, AccountState::SignedIn { .. }),
        "the account is as it was: {report:?}"
    );
    assert!(
        broker.revoked().is_empty(),
        "the service refused the revocation of the grant that came for the turned-away sign-in"
    );

    let _ = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await;
    let close = broker
        .seen()
        .into_iter()
        .find(|request| request.path == "/api/voice/sessions/call-1/close")
        .expect("the broker was told");
    assert_eq!(
        close.authorization.as_deref(),
        Some(format!("Bearer {}", broker.access(1)).as_str()),
        "the close carried the account the call started under"
    );

    // The turned-away grant is revoked when the daemon next starts, though nothing remembers it
    // but the queue.
    let stopped = host.shut_down().await;
    broker.refuse_revocations(false);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while broker.revoked().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the daemon sends the revocation again");
    assert_eq!(broker.revoked(), [broker.refresh(2)]);
    assert!(matches!(
        account_report(&host).await.state,
        AccountState::SignedIn { .. }
    ));
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: while an account is being changed a request for a token waits for the
/// change to end. A sign-in whose identity read names another account is undone, so a call that
/// began under the grant it was about to remove would have lost its account: the start waits, and
/// when the grant is gone it is refused and creates nothing at the broker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_meets_an_account_being_changed_is_made_under_the_account_it_leaves() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    listen_for_sign_ins_on(&host, free_port());
    sign_in_with(&host, broker.issue_grant(600)).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    let (url, address) = start_sign_in(&host).await;
    broker.expect_sign_in(&url);
    broker.name_another_account();
    // The grant is kept and the identity read follows: the account is being changed meanwhile.
    let identity = broker.hold("/auth/oauth2/userinfo");

    let (_page, started) = tokio::join!(browser_answers(&address, &url, "the-code"), async {
        identity.reached().await;
        let params = start_params(session_id, &prepared);
        let start = try_mutate(&session, host.environment_id, Method::VoiceStart, &params);
        let release = async {
            // The start is waiting for its token while the gate is up: a condition of the daemon,
            // not a time. Nothing has reached the broker for it.
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                while host.controller().host_account().token_requests_waiting() == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the start's request for a token waits for the change to end");
            assert!(
                broker
                    .seen()
                    .iter()
                    .all(|request| !request.path.starts_with("/api/voice/sessions")),
                "nothing reached the broker while the account was being changed"
            );
            identity.release();
        };
        let (started, ()) = tokio::join!(start, release);
        started
    });
    let report = settled(&host).await;
    assert_eq!(report.state, AccountState::SignedOut, "{report:?}");
    assert_eq!(
        report.last_attempt.as_ref(),
        Some(&AccountAttempt::NotForThisAttempt)
    );
    let made = started
        .ok()
        .and_then(|value| value.to_typed::<VoiceStartResult>().ok())
        .is_some_and(|result| matches!(result.outcome, VoiceStartOutcome::Started { .. }));
    assert!(!made, "no call was made under an account that was going");
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| !request.path.starts_with("/api/voice/sessions")),
        "nothing was created at the broker"
    );
    host.stop().await;
}

/// KR-REQ-17.23: a host whose broker moved off the managed service still reaches the account
/// service for what it keeps. It shows the grant, presents none, and signs out: the grant is revoked
/// at the service that issued it and nothing of it reaches the new broker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_moved_off_the_managed_broker_can_still_end_the_sign_in_it_keeps() {
    let account = Broker::start().await;
    let other = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&account.origin)).await;
    sign_in_with(&host, account.issue_grant(600)).await;

    let mut stopped = host.shut_down().await;
    net_support::write_document(stopped.tree(), &document_naming(&other.origin));
    stopped.account_service_stays_at(&account.origin);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;

    let report = account_report(&host).await;
    assert_eq!(report.service.as_ref(), Some(&account.origin));
    assert_eq!(
        report.unavailable.as_ref(),
        Some(&SignInUnavailable::BrokerIsAnotherService)
    );
    assert!(
        matches!(report.state, AccountState::SignedIn { .. }),
        "the grant it keeps is shown: {report:?}"
    );
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;
    assert!(
        prepared.managed.as_ref().is_none(),
        "no account is presented to the other broker"
    );
    let refused = host
        .client()
        .await
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("this broker is not the account service");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refused:?}"
    );

    assert!(sign_out(&host).await.was_signed_in);
    assert_eq!(account.revoked(), [account.refresh(1)]);
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
    assert!(other.seen().is_empty(), "the other broker was sent nothing");
    host.stop().await;
}

/// KR-REQ-17.23: when the store cannot be read to settle what an earlier run left, no token is
/// presented, and the next request tries again: a grant whose revocation was queued is never used
/// because settling it failed once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_the_store_could_not_settle_is_not_presented_until_it_is_settled() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    // The second sign-in replaces the first, whose revocation the service refuses: it is queued.
    sign_in_with(&host, broker.issue_grant(600)).await;
    broker.refuse_revocations(true);
    sign_in_with(&host, broker.issue_grant(600)).await;
    let stopped = host.shut_down().await;
    broker.refuse_revocations(false);
    let queue = account_item(&stopped, "revoke");
    let moved = queue.with_extension("moved");
    // The item cannot be read: a directory stands where the file was.
    std::fs::rename(&queue, &moved).expect("the queue is set aside");
    std::fs::create_dir(&queue).expect("a directory in its place");
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;

    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    assert!(
        prepared.managed.as_ref().is_none(),
        "no account is presented while the store cannot be settled"
    );
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| request.authorization.is_none()),
        "the broker was shown no account"
    );

    std::fs::remove_dir(&queue).expect("the directory goes");
    std::fs::rename(&moved, &queue).expect("the queue is back");
    let prepared: VoicePrepareResult = session
        .read(
            Method::VoicePrepare,
            &VoicePrepareParams {
                session_ids: [session_id].into_iter().collect(),
                selected: CanonicalSet::from_iter([]),
            },
        )
        .await
        .expect("the host answers what a call would be");
    assert!(
        prepared.managed.as_ref().is_some(),
        "the account is presented once it is settled: {:?}",
        prepared.managed_unavailable
    );
    assert_eq!(broker.revoked(), [broker.refresh(1)]);
    host.stop().await;
}

/// The file the host's account keeps `item` in, found under the stopped daemon's secret store.
fn account_item(stopped: &net_support::Stopped, item: &str) -> std::path::PathBuf {
    fn find(directory: &std::path::Path, item: &str, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                find(&path, item, found);
            } else if path.file_name().is_some_and(|name| name == item)
                && path
                    .parent()
                    .is_some_and(|parent| parent.ends_with("account"))
                && path.to_string_lossy().contains("host-account")
            {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    find(
        &stopped.tree().environment().secrets_dir(),
        item,
        &mut found,
    );
    assert_eq!(found.len(), 1, "one {item} item of the account: {found:?}");
    found.remove(0)
}

/// KR-REQ-17.23: the token the service rotates is the one the next request presents: each refresh
/// presents the refresh token the last one issued, once, so the service never sees a spent token
/// and ends the family.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_refresh_presents_the_token_the_last_one_issued() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    // Tokens that last 20 seconds are always inside the margin the host replaces them in.
    sign_in_with(&host, broker.issue_grant(20)).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    let terms = prepared
        .managed
        .as_ref()
        .unwrap_or_else(|| panic!("the service's terms: {:?}", prepared.managed_unavailable));
    let _: VoiceStartResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: prepared.prepared,
            expected_rate_version: Nullable::some(terms.rate.version.clone()),
        },
    )
    .await
    .to_typed()
    .expect("a start result");

    let refreshes = broker.refreshes();
    assert!(refreshes.len() >= 2, "{refreshes:?}");
    for (index, presented) in refreshes.iter().enumerate() {
        assert_eq!(
            presented,
            &broker.refresh(u32::try_from(index).expect("a small count") + 1),
            "each refresh presents the token the last one issued: {refreshes:?}"
        );
    }
    assert!(
        matches!(
            account_report(&host).await.state,
            AccountState::SignedIn { .. }
        ),
        "the family is still honoured"
    );
    host.stop().await;
}

/// KR-REQ-17.23 and 15.17: when the service ends the sign-in during a call, the call's stop still
/// ends it here at once: the grant is revoked, the service is not told because no token can be
/// presented, and the host says the sign-in ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_after_the_service_ended_the_sign_in_still_revokes_the_calls_grant() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(20)).await;
    let (_device, session, session_id, prepared) = ready(&host, &owner).await;
    let terms = prepared
        .managed
        .as_ref()
        .unwrap_or_else(|| panic!("the service's terms: {:?}", prepared.managed_unavailable));
    let started: VoiceStartResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: prepared.prepared,
            expected_rate_version: Nullable::some(terms.rate.version.clone()),
        },
    )
    .await
    .to_typed()
    .expect("a start result");
    let VoiceStartOutcome::Started { session: call } = started.outcome else {
        panic!("the broker created the call: {:?}", started.outcome);
    };

    broker.end_the_sign_in();
    let stopped: kr_protocol::voice::VoiceStopResult = mutate(
        &session,
        host.environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await
    .to_typed()
    .expect("a stop result");
    assert!(
        !stopped.broker_notified,
        "no token could be presented, so the service was not told"
    );
    assert!(
        broker
            .seen()
            .iter()
            .all(|request| request.path != "/api/voice/sessions/call-1/close"),
        "the close never reached the service"
    );
    assert_eq!(account_report(&host).await.state, AccountState::Ended);
    host.stop().await;
}

/// KR-REQ-17.23: what the host keeps of a sign-in is reached only through the service that issued
/// it. A host restarted for another service finds no account, presents nothing to it and sends it
/// nothing of the first service's; the first service's account is still there when the host is
/// configured for it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_signed_in_at_one_service_is_reached_only_through_that_service() {
    let first = Broker::start().await;
    let second = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&first.origin)).await;
    sign_in_with(&host, first.issue_grant(600)).await;

    let stopped = host.shut_down().await;
    net_support::write_document(stopped.tree(), &document_naming(&second.origin));
    let settings = stopped.settings().clone();
    let host = stopped.start(settings.clone()).await;
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;
    assert!(
        prepared.managed.as_ref().is_none(),
        "no terms were read with an account that belongs to another service"
    );
    assert!(
        second.seen().is_empty(),
        "the second service was sent nothing"
    );

    // A sign-in at the second service replaces nothing of the first's, and tells the second
    // nothing of it.
    sign_in_with(&host, second.issue_grant(600)).await;
    for request in second.seen() {
        let text = request.body.to_string();
        assert!(
            !text.contains(&first.refresh(1)) && !text.contains(&first.access(1)),
            "the second service was sent the first's credentials: {text}"
        );
    }
    assert!(first.seen().is_empty() && first.revoked().is_empty());

    let stopped = host.shut_down().await;
    net_support::write_document(stopped.tree(), &document_naming(&first.origin));
    let host = stopped.start(settings).await;
    assert!(
        matches!(
            account_report(&host).await.state,
            AccountState::SignedIn { .. }
        ),
        "the first service's account is where it was left"
    );
    host.stop().await;
}

/// KR-REQ-17.23: a revocation the service did not acknowledge is sent again when the daemon next
/// starts, before it hands out a token: the replaced grant's refresh token is not left live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_the_service_did_not_acknowledge_is_sent_again_when_the_daemon_starts() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    sign_in_with(&host, broker.issue_grant(600)).await;
    broker.refuse_revocations(true);
    sign_in_with(&host, broker.issue_grant(600)).await;
    assert!(
        broker.revoked().is_empty(),
        "the service refused the revocation of the replaced grant"
    );

    let stopped = host.shut_down().await;
    broker.refuse_revocations(false);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while broker.revoked().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the daemon sends the revocation again");
    assert_eq!(broker.revoked(), [broker.refresh(1)]);
    host.stop().await;
}

/// KR-REQ-17.23: a host whose voice broker is not the account service has nothing to sign in to. It
/// says so, refuses to start a sign-in, and presents no account to the broker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_broker_is_not_the_account_service_signs_in_nowhere() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    // The account service stays at its own origin, which the stand-in is not at.
    let host = net_support::Host::start_with_document_at(
        &owner,
        &document_naming(&broker.origin),
        net_support::AccountAt::Managed,
    )
    .await;
    let report = account_report(&host).await;
    assert_eq!(
        report.unavailable.as_ref(),
        Some(&SignInUnavailable::BrokerIsAnotherService)
    );
    let refused = host
        .client()
        .await
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("there is no account service to sign in at");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refused:?}"
    );
    // Signing out needs no broker: with no account kept there is nothing to end, and it says so.
    assert!(!sign_out(&host).await.was_signed_in);
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;
    assert!(prepared.managed.as_ref().is_none(), "no terms were read");
    assert!(broker.seen().is_empty(), "the broker was sent nothing");
    host.stop().await;
}

/// KR-REQ-17.23: a host that names no managed service has nowhere to sign in, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_names_no_service_refuses_to_sign_in() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &ConfigurationDocument::empty()).await;
    let refused = host
        .client()
        .await
        .mutate(
            Method::AccountSignIn,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &AccountSignInParams {},
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("there is no service to sign in at");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refused:?}"
    );
    let report = account_report(&host).await;
    assert_eq!(report.state, AccountState::SignedOut);
    assert_eq!(
        report.unavailable.as_ref(),
        Some(&SignInUnavailable::NoBroker)
    );
    host.stop().await;
}

/// The account token an earlier version of this host had an operator import held no refresh
/// credential, so it is removed when the daemon starts, and the operator is told to sign in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_token_an_earlier_host_imported_is_removed_when_the_daemon_starts() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &ConfigurationDocument::empty()).await;
    let stopped = host.shut_down().await;
    let old = stopped
        .tree()
        .paths()
        .runtime_root()
        .join("account-token.json");
    std::fs::write(&old, b"{}").expect("the old file");
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    assert!(!old.exists(), "the old file is gone");
    host.stop().await;
}
