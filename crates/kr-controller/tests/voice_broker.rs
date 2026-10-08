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
//! | KR-REQ-17.23 | `a_stop_after_the_service_ended_the_sign_in_still_revokes_the_calls_grant` |
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
use kr_protocol::host_account::{
    AccountReport, AccountSignInParams, AccountState, AccountStatusParams,
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
}

impl Account {
    fn issue(&mut self, with_identity: bool) -> serde_json::Value {
        self.issued += 1;
        self.access = format!("access-{}", self.issued);
        self.refresh = format!("refresh-{}", self.issued);
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
                "sub": "account-1",
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

/// Everything the stand-in services share.
struct Shared {
    seen: Mutex<Vec<Seen>>,
    account: Mutex<Account>,
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
        let origin = format!("http://{}", listener.local_addr().expect("an address"));
        let shared = Arc::new(Shared {
            seen: Mutex::default(),
            account: Mutex::new(Account {
                nonce: String::new(),
                challenge: String::new(),
                expires_in: 600,
                issued: 0,
                access: String::new(),
                refresh: String::new(),
                ended: false,
                refreshes: Vec::new(),
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
                serde_json::json!({"sub": "account-1", "email": "someone@example.test"}),
            )
        }
        "/auth/oauth2/revoke" => (200, serde_json::json!({})),
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
    host.controller()
        .host_account()
        .keep_for_test(grant, true)
        .await;
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
            Some("Bearer access-1"),
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
/// shows none of it, and a call presents the token of the account it signed in. A browser answer
/// that is not for the attempt the host is waiting on is set aside, and a second sign-in ends the
/// first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_signs_the_host_in_and_a_call_presents_the_account_it_signed_in() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    host.controller()
        .host_account()
        .listen_on("127.0.0.1:0".parse().expect("an address"));
    let before = account_report(&host).await;
    assert_eq!(before.state, AccountState::SignedOut);
    assert_eq!(before.service.as_ref(), Some(&broker.origin));

    let (first_url, first_address) = start_sign_in(&host).await;
    let (second_url, second_address) = start_sign_in(&host).await;
    assert_ne!(first_url, second_url, "a second sign-in is a new attempt");
    broker.expect_sign_in(&second_url);

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
    let _ = first_address;

    let page = browser_answers(&second_address, &second_url, "the-code").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("signed in"), "{page}");

    let report = account_report(&host).await;
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
    for held in ["access-1", "refresh-1"] {
        assert!(!said.contains(held), "the report says no token: {said}");
        assert!(!format!("{report:?}").contains(held));
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
                Some("Bearer access-1"),
                "{} carried the account the host signed in",
                request.path
            );
        }
    }
    host.stop().await;
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
            &format!("refresh-{}", index + 1),
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

/// KR-REQ-17.23: an account signed in at one service is never presented to another. The host that
/// signed in at one broker, restarted with a document that names a second, sends the second
/// nothing, and the first nothing either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_signed_in_at_one_service_is_not_presented_to_another() {
    let first = Broker::start().await;
    let second = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&first.origin)).await;
    sign_in_with(&host, first.issue_grant(600)).await;

    let stopped = host.shut_down().await;
    net_support::write_document(stopped.tree(), &document_naming(&second.origin));
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;

    assert!(
        prepared.managed.as_ref().is_none(),
        "no terms were read with an account that belongs to another service"
    );
    assert!(
        second.seen().is_empty(),
        "the second service was sent nothing: {:?}",
        second.seen()
    );
    assert!(
        first.seen().is_empty(),
        "the first service was sent nothing"
    );
    host.stop().await;
}

/// KR-REQ-17.23: a sign-in that no record names a service for is not presented anywhere: the
/// daemon stopped between keeping the account and recording where it was signed in, and a bearer
/// token with no known service is a token it cannot tell the destination of.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_with_no_recorded_service_is_not_presented() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    host.controller()
        .host_account()
        .keep_for_test(broker.issue_grant(600), false)
        .await;
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;

    assert!(
        prepared.managed.as_ref().is_none(),
        "no terms were read with an account no service is recorded for"
    );
    assert!(broker.seen().is_empty(), "the service was sent nothing");
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
    assert_eq!(account_report(&host).await.state, AccountState::SignedOut);
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
