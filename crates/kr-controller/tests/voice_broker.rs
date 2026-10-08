//! A host whose configuration names a managed voice broker brokers calls through it.
//!
//! The daemon is the real one, started from a configuration document that names the broker, and
//! the device is a paired one over a real connection. The broker is a stand-in on the loopback
//! interface that speaks the service's wire, so what these prove is what the daemon sends and
//! what it does with the answers. No test here makes a live provider call.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.01 | `a_host_whose_document_names_a_broker_brokers_a_call_through_it` |
//! | KR-REQ-15.19 | `a_host_whose_document_names_a_broker_brokers_a_call_through_it` |
//! | KR-REQ-26.14 | `a_host_reaches_the_broker_through_the_proxy_its_document_selects` |

mod net_support;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::sync::{Arc, Mutex};

use connect_proxy::ConnectProxy;
use kr_client::services::account::AccountToken;
use kr_client::services::voice::{StoredAccountToken, account_token_path};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::voice::{
    VoiceGrantParams, VoicePrepareParams, VoicePrepareResult, VoiceStartOutcome, VoiceStartParams,
    VoiceStartResult, VoiceStopParams,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The token the stand-in expects, as an operator would have put it on the host.
const TOKEN: &str = "a-voice-token-for-the-stand-in";

/// How long a mutation over the network asks the host to hold its admission for.
const NETWORK_LIFETIME: DurationMs = DurationMs::new(120_000);

/// One request the stand-in broker received.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    authorization: Option<String>,
    body: serde_json::Value,
}

/// A managed voice service on the loopback interface, as far as its wire goes.
struct Broker {
    origin: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Broker {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let origin = format!("http://{}", listener.local_addr().expect("an address"));
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let record = Arc::clone(&seen);
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
        Self { origin, seen, task }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("what was seen").clone()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads one request and answers it in the service's envelope.
async fn answer(mut stream: TcpStream, record: &Mutex<Vec<Seen>>) {
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
    let body: serde_json::Value =
        serde_json::from_slice(&bytes[head_end..head_end + length]).unwrap_or_default();
    record.lock().expect("what was seen").push(Seen {
        path: path.clone(),
        authorization,
        body,
    });
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

/// Puts the account token where the host reads it.
fn import_token(host: &net_support::Host, origin: &str) {
    let stored = StoredAccountToken {
        origin: origin.to_owned(),
        access_token: AccountToken::new(TOKEN).expect("a token"),
        scopes: vec!["voice".to_owned()],
        expires_at_ms: None,
    };
    let path = account_token_path(host.runtime_root());
    kr_ipc::paths::write_owner_only_file(&path, &stored.write().expect("a document"))
        .expect("the token file");
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
/// device that asks what a call would be, starts the call there under the token an operator put on
/// the host and the rate the device was shown, and tells the broker when the call ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_document_names_a_broker_brokers_a_call_through_it() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    import_token(&host, &broker.origin);
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
            Some(format!("Bearer {TOKEN}").as_str()),
            "{} carried the operator's token",
            request.path
        );
    }
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
    import_token(&host, &broker.origin);
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
    import_token(&host, origin);
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

/// KR-REQ-15.01: an account token issued for another service never reaches the broker this host is
/// configured to reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_issued_for_another_service_never_reaches_the_broker() {
    let broker = Broker::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        net_support::Host::start_with_document(&owner, &document_naming(&broker.origin)).await;
    import_token(&host, "https://some-other-service.example");
    let (_device, _session, _session_id, prepared) = ready(&host, &owner).await;

    assert!(
        prepared.managed.as_ref().is_none(),
        "no terms were read with a token that belongs to another service"
    );
    assert!(
        broker.seen().is_empty(),
        "the token was held back, so nothing reached the broker: {:?}",
        broker.seen()
    );
    host.stop().await;
}
