//! What a gateway answers never reaches a record or a log of this host.
//!
//! The case runs the delivery runtime in a process of its own, so that what the runtime writes to
//! its log can be read, and that process is a copy of this small test program. Copies of a large
//! program are checked by the operating system at their first start, which takes the better part
//! of half a minute on a loaded machine, so the child is this target and not the suite that holds
//! the rest of the delivery tests.
//!
//! Nothing here reaches a real gateway: the gateway is a double that answers whatever it was told
//! to, and repeats the bearer it was shown.

use std::sync::{Arc, Mutex};

use kr_controller::push::DeliveryModule;
use kr_controller::push::credentials::HeldCredentials;
use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationRecord, PreviewKeys, PushDestination,
};
use kr_delivery::journal::{DeliveryState, EventKey, EventSource};
use kr_delivery::producer::{
    Audience, DEFAULT_NOTIFICATION_LIFETIME_MS, Notice, RecipientAuthority, RecipientScope,
};
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{
    DeviceId, GrantId, InstallationId, NotificationId, PushSenderRecordId, PushSenderRevision,
    SessionId,
};
use kr_protocol::push::{PushAlert, PushDeliveryCredential, PushDeliveryRequest, PushUrgency};
use kr_protocol::scalars::{SecretBytes32, TimestampMs, Uuid};
use kr_worker::history_filter::ViewerScope;

/// A time every record of this suite can be placed against; the bearer does not depend on it.
const NOW: u64 = 1_700_000_000_000;

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// Where a test keeps external destinations' credentials: in memory, never in the person's own
/// credential store.
fn secrets() -> kr_controller::push::secrets::DestinationSecrets {
    kr_controller::push::secrets::DestinationSecrets::new(
        Arc::new(kr_crypto::store::MemoryStore::new()),
        kr_protocol::ids::EnvironmentId::new(uuid(0xee)),
    )
}

/// A delivery credential current at `now_ms`.
fn current_credential(now_ms: u64) -> PushDeliveryCredential {
    PushDeliveryCredential {
        expires_at_ms: TimestampMs::new(now_ms + 29 * 24 * 60 * 60 * 1000),
        gateway_origin: kr_protocol::service::GatewayOrigin::new("https://reach.invalid")
            .expect("an origin"),
        installation_id: InstallationId::new(uuid(2)),
        issued_at_ms: TimestampMs::new(now_ms - 1_000),
        revision: PushSenderRevision::new(1),
        secret: SecretBytes32::from_bytes([9; 32]),
        sender_record_id: PushSenderRecordId::new(uuid(3)),
    }
}

/// The owner's authority over every session.
#[derive(Debug)]
struct Granted;

impl Granted {
    fn scope(&self) -> RecipientScope {
        RecipientScope {
            viewer: ViewerScope::owner(),
            sessions: SessionSelector::Any,
            rights: [
                kr_protocol::rights::ActionRight::SessionView,
                kr_protocol::rights::ActionRight::AutomationManage,
                kr_protocol::rights::ActionRight::HostManage,
            ]
            .into_iter()
            .collect(),
            grant_id: GrantId::new(uuid(9)),
            recipient: DeviceId::new(uuid(10)),
            history_from_ms: 0,
        }
    }
}

impl RecipientAuthority for Granted {
    fn scope_for(&self, _rule: &DeliveryRule) -> Option<RecipientScope> {
        Some(self.scope())
    }

    fn device_scope(&self, _destination: &DestinationRecord) -> Option<RecipientScope> {
        Some(self.scope())
    }
}

/// Every origin reached through one transport, which is how a test sees everything that left.
#[derive(Debug)]
struct OneTransport(Arc<dyn kr_client::services::ServiceHttp>);

impl kr_controller::push::transport::DeliveryTransports for OneTransport {
    fn to(
        &self,
        _origin: &kr_protocol::service::GatewayOrigin,
    ) -> Result<Arc<dyn kr_client::services::ServiceHttp>, String> {
        Ok(Arc::clone(&self.0))
    }
}

/// Produces one notification for `destination` from a freshly taken event at `now_ms`.
fn produce_now(
    module: &DeliveryModule,
    destination: &DestinationRecord,
    number: u64,
    now_ms: u64,
) -> NotificationId {
    let session = SessionId::new(uuid(1));
    let notice = Notice {
        event: EventKey::announcement(Some(session), "attention.pending_approval/~abcdef", number),
        alert: PushAlert::ApprovalWaiting,
        urgency: PushUrgency::Attention,
        rule: "attention.pending_approval".to_owned(),
        summary: "an approval is waiting".to_owned(),
        session_id: Some(session),
        environment_id: None,
        observed_at_ms: TimestampMs::new(now_ms),
        collapse_group: "a-session/attention.pending_approval".to_owned(),
        expires_at_ms: TimestampMs::new(now_ms + DEFAULT_NOTIFICATION_LIFETIME_MS),
        audience: Audience::Sessions {
            sessions: vec![session],
            at_ms: now_ms,
        },
    };
    module
        .with(|producer| {
            let taken = notice.taken(number).expect("an event record");
            producer
                .take(
                    EventSource::Attention,
                    "session-1",
                    &[taken],
                    number,
                    now_ms,
                )
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(destination),
                    &Granted,
                    &[],
                    now_ms,
                )
                .expect("a decision");
            Ok(producer
                .journal()
                .deliveries_for(&notice.event)
                .expect("a read")
                .remove(0)
                .notification_id)
        })
        .expect("produced")
}

fn state_of(module: &DeliveryModule, notification_id: NotificationId) -> DeliveryState {
    module
        .with(|producer| {
            Ok(producer
                .journal()
                .delivery(notification_id)
                .expect("a read")
                .expect("the record")
                .state)
        })
        .expect("a read")
}

/// The push destination the child run delivers to, configured at `now_ms`.
fn phone(now_ms: u64) -> DestinationRecord {
    let device_preview =
        kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    DestinationRecord {
        id: DestinationId::new("phone").expect("an identifier"),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*device_preview.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        rule: Some(DeliveryRule {
            name: "on a failed command".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(now_ms),
    }
}

/// The directory the child run of the log test reads and writes.
const ECHO_DIR: &str = "KR_TEST_GATEWAY_ECHO_DIR";

/// A phrase no record or log of this host may ever hold, which the gateway puts in its answers
/// beside the bearer it was presented.
const GATEWAY_WORDS: &str = "words-only-the-gateway-says";

/// The bearer a delivery credential's secret is presented as: 32 bytes, unpadded base64url.
fn bearer_of(credential: &PushDeliveryCredential) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential.secret.expose())
}

/// A gateway that refuses everything with a body that repeats the bearer it was shown and its
/// own words, whatever the status, and remembers each answer it gave.
#[derive(Debug)]
struct EchoingGateway {
    statuses: Mutex<std::collections::BTreeMap<NotificationId, u16>>,
    echoed: Mutex<Vec<String>>,
    bearer: String,
}

impl kr_client::services::ServiceHttp for EchoingGateway {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        let (route, status) = if url.ends_with("/api/push/deliver") {
            let request: PushDeliveryRequest =
                serde_json::from_slice(body).expect("a delivery request");
            let status = self
                .statuses
                .lock()
                .expect("not poisoned")
                .get(&request.notification_id)
                .copied()
                .expect("a notification the test produced");
            ("deliver", status)
        } else if url.ends_with("/api/push/deliver/status") {
            ("status", 403)
        } else {
            ("renew", 403)
        };
        self.echoed
            .lock()
            .expect("not poisoned")
            .push(format!("{route} {status}"));
        // The bearer is the answer's error code on a renewal, so that a code this host does not
        // know is repeated back too, and its message everywhere else.
        let answer = serde_json::json!({
            "ok": false,
            "error": {
                "code": if route == "renew" { self.bearer.as_str() } else { "FORBIDDEN" },
                "message": format!("{} {GATEWAY_WORDS}", self.bearer),
            },
        });
        Box::pin(async move {
            Ok(kr_client::services::ServiceHttpAnswer {
                status,
                body: serde_json::to_vec(&answer).expect("an answer"),
            })
        })
    }
}

/// The daemon's runtime, run by the test below in a process of its own so that what it writes to
/// its log can be read: five deliveries answered 401, 403, 429, 500 and 302, a renewal refused,
/// and a question about an outcome nobody knows refused, all repeating the bearer.
#[ignore = "run by the test that reads this process's log"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_against_a_gateway_that_repeats_the_bearer() {
    let directory = std::path::PathBuf::from(
        std::env::var_os(ECHO_DIR).expect("run by the test that reads its log"),
    );
    let module = Arc::new(
        DeliveryModule::open_at(
            &directory.join("delivery.sqlite3"),
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
            secrets(),
        )
        .expect("a delivery module"),
    );
    let now = kr_ipc::now_ms().get();
    let destination = phone(now);
    module.configure(&destination).expect("a destination");
    let held = current_credential(now);
    let gateway = Arc::new(EchoingGateway {
        statuses: Mutex::new(std::collections::BTreeMap::new()),
        echoed: Mutex::new(Vec::new()),
        bearer: bearer_of(&held),
    });
    let mut produced = Vec::new();
    for (number, status) in [401_u16, 403, 429, 500, 302].into_iter().enumerate() {
        let id = produce_now(&module, &destination, number as u64 + 1, now);
        gateway
            .statuses
            .lock()
            .expect("not poisoned")
            .insert(id, status);
        produced.push(id);
    }
    let credentials = Arc::new(HeldCredentials::new());
    credentials.hold(held);
    let runtime = kr_controller::push::runtime::DeliveryRuntime::new(
        Arc::clone(&module),
        credentials,
        Arc::new(Granted),
        Arc::new(kr_controller::push::sender::HostSigner::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        )),
        kr_controller::push::runtime::Cadence {
            pass: std::time::Duration::from_millis(20),
            questions: std::time::Duration::from_millis(50),
            ..kr_controller::push::runtime::Cadence::DEFAULT
        },
        tokio::runtime::Handle::current(),
    );
    runtime.start().await;
    assert!(runtime.attach_transport(Arc::new(OneTransport(
        Arc::clone(&gateway) as Arc<dyn kr_client::services::ServiceHttp>
    ))));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let echoed = gateway.echoed.lock().expect("not poisoned").clone();
        let attempted = produced.iter().all(|id| {
            !matches!(
                state_of(&module, *id),
                DeliveryState::Admitted | DeliveryState::InFlight
            )
        });
        // The refusal of a renewal is written down by the attempt after the one that was
        // refused, which is due a moment later, so this waits for that record.
        let renewal_recorded = produced.iter().any(|id| {
            module
                .with(|producer| {
                    Ok(producer
                        .journal()
                        .delivery(*id)
                        .expect("a read")
                        .and_then(|record| record.detail)
                        .is_some_and(|detail| detail.contains("refused the renewal")))
                })
                .expect("a read")
        });
        if attempted
            && renewal_recorded
            && ["status 403", "renew 403"]
                .iter()
                .all(|seen| echoed.contains(&(*seen).to_owned()))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the runtime did not meet every answer: {echoed:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let outcome: Vec<String> = produced
        .iter()
        .map(|id| state_of(&module, *id).to_string())
        .collect();
    let echoed = gateway.echoed.lock().expect("not poisoned").join("\n");
    std::fs::write(directory.join("echoed.txt"), echoed).expect("a record");
    std::fs::write(directory.join("outcome.txt"), outcome.join("\n")).expect("a record");
    // The runtime and the module are let go here, which closes the journal.
}

/// KR-REQ-16.12: what a gateway answers is read by the decoder and never turned into text. A
/// gateway that answers a delivery 401, 403, 429, 500 and 302, a renewal and a question about an
/// outcome nobody knows with a body that repeats the bearer and its own words leaves neither in
/// the journal's files nor in the log of the process that ran the deliveries. The controls: the
/// gateway did answer every one of those, with the bearer in it, and the journal does hold this
/// host's own account of a refused credential and of a refused renewal, so a scan that finds
/// nothing is a scan of records that were written. A question's answer is not written down at all
/// (a refused question leaves the record as it was), so that leg is a control and no more.
#[test]
fn a_gateway_that_repeats_the_bearer_leaves_it_out_of_the_journal_and_the_log() {
    let directory = tempfile::tempdir().expect("a directory");
    // The child runs from a copy on the internal disk and from a directory there, as every
    // process this suite launches does.
    let program = directory.path().join("push-test-program");
    kr_ipc::testing::place_program(
        &std::env::current_exe().expect("this test program"),
        &program,
    );
    let ran = std::process::Command::new(&program)
        .current_dir(directory.path())
        .args([
            "--ignored",
            "--exact",
            "the_runtime_against_a_gateway_that_repeats_the_bearer",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ECHO_DIR, directory.path())
        .output()
        .expect("the child run starts");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(ran.status.success(), "the child run failed: {log}");

    let bearer = bearer_of(&current_credential(NOW));
    // The control: every answer was given, and each repeated the bearer.
    let echoed = std::fs::read_to_string(directory.path().join("echoed.txt")).expect("a record");
    for answered in [
        "deliver 401",
        "deliver 403",
        "deliver 429",
        "deliver 500",
        "deliver 302",
        "status 403",
        "renew 403",
    ] {
        assert!(echoed.lines().any(|line| line == answered), "{echoed}");
    }
    let outcome = std::fs::read_to_string(directory.path().join("outcome.txt")).expect("a record");
    assert_eq!(
        outcome
            .lines()
            .filter(|state| *state == "outcome_unknown")
            .count(),
        2,
        "the 500 and the 302 are outcomes nobody knows: {outcome}"
    );

    let journal: Vec<(&str, Vec<u8>)> = [
        "delivery.sqlite3",
        "delivery.sqlite3-wal",
        "delivery.sqlite3-shm",
    ]
    .into_iter()
    .filter_map(|name| {
        std::fs::read(directory.path().join(name))
            .ok()
            .map(|bytes| (name, bytes))
    })
    .collect();
    assert!(
        journal.iter().any(|(name, _)| *name == "delivery.sqlite3"),
        "the journal is where the child was told to keep it"
    );
    let holds = |bytes: &[u8], text: &str| {
        bytes
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    };
    for host_words in [
        "the gateway refused the credential (401)",
        "refused the renewal",
    ] {
        assert!(
            journal.iter().any(|(_, bytes)| holds(bytes, host_words)),
            "the journal holds this host's own words, {host_words}"
        );
    }
    for secret in [bearer.as_str(), GATEWAY_WORDS] {
        assert!(
            !log.contains(secret),
            "the process's log holds {secret}: {log}"
        );
        for (name, bytes) in &journal {
            assert!(!holds(bytes, secret), "{name} holds {secret}");
        }
    }
}
