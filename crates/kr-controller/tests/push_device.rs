//! The host, the gateway's recording stand-in for Firebase, and what they saw, for a phone's
//! notifications on a simulator or an emulator.
//!
//! This is not a test of the product by itself: it is the machine side of a device run, and a
//! script starts it (`scripts/e2e-push-device.sh`), so it is ignored in an ordinary run. It starts
//! the real daemon on the loopback interface, a standing worker with a session, and a recording
//! stand-in for the provider that a development gateway (a local Worker, started by the script)
//! sends its messages to. The daemon takes a credential from that gateway and delivers through it,
//! and refuses every origin that is not loopback, so a part of the product that named the managed
//! service's own origin would fail the run and could not reach it.
//!
//! What the run shows is the product's own path from a phone to its host and back: the phone is
//! paired, turns notifications on, answers the challenge the gateway sends it, and is a destination
//! the host delivers to; a question the worker asks is delivered through the gateway to the phone.
//! No part of the provider is real, and no sender credential exists: what a real delivery would add
//! is named in `docs/delivery/README.md`.
//!
//! The script and this suite talk through files in `KR_HARNESS_DIR`, on the internal disk:
//!
//! | File | Written by | Holds |
//! | --- | --- | --- |
//! | `ready.json` | this suite | the provider stand-in's origin |
//! | `go` | the script | nothing; the phone is installed and the invitation may be issued |
//! | `invitation.txt` | this suite | the direct invitation, with the host reachable at `KR_HARNESS_PEER` |
//! | `inject-<n>.json` | this suite | one message to put on the phone: its kind and the provider's body |
//! | `injected-<n>` | the script | nothing; the phone has had the message and had time to act on it |
//! | `shown-<n>` | the script | nothing; a delivery is on the phone's screen |
//! | `finish` | the script | nothing; the phone is done |
//! | `report.json` | this suite | what the host and the stand-in saw |
//!
//! `KR_HARNESS_PEER` is the name the phone reaches this machine by: `127.0.0.1` for a simulator,
//! and `10.0.2.2` for an emulator. `KR_PUSH_GATEWAY` is the gateway's origin, `KR_PUSH_FCM_PORT` the
//! port the stand-in listens on, and `KR_PUSH_TOKEN` the registration token the phone presents.
//! `KR_HARNESS_SECONDS` bounds the whole run. It is for the machines a simulator or an emulator runs
//! on, which are Unix.

#![cfg(unix)]

mod net_support;
mod push_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_client::services::ServiceHttp;
use kr_controller::config::Outbound;
use kr_controller::push::transport::{DeliveryTransports, ManagedTransports};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::pairing::{NetworkHint, QrPayload};
use kr_protocol::rights::ActionRight;
use kr_protocol::service::GatewayOrigin;
use net_support::pairing::{self as calls, Signer};
use net_support::worker::Worker;
use net_support::{Host, proposal};
use push_support::Fcm;
use serde_json::{Value, json};

/// How long the phone is given to ask for its invitation after the script says it is installed.
const INVITATION_WAIT: Duration = Duration::from_secs(60);

/// How long the phone and the gateway are given to make the phone a destination.
const REGISTRATION_WAIT: Duration = Duration::from_secs(150);

/// How long the script is given to put a message on the phone and see what it did.
const INJECTION_WAIT: Duration = Duration::from_secs(120);

/// How long the script is given to tap a notification, open the question it leads to and answer it
/// on the phone's screen, which reads the screen again whenever it has not drawn what it waits for.
const SCREEN_STEP_WAIT: Duration = Duration::from_secs(240);

/// How long a delivery is given to reach the stand-in.
const DELIVERY_WAIT: Duration = Duration::from_secs(90);

/// How long a delivery that has to be renewed first is given to reach the stand-in.
const RENEWAL_WAIT: Duration = Duration::from_secs(150);

/// A marker in the text of a question, which must never appear in what leaves the host.
const MARKER: &str = "kr-marker-4f1c9a";

/// The directory the script and this suite share, and what bounds the run.
struct Run {
    directory: PathBuf,
    end: Instant,
}

impl Run {
    fn left(&self) -> Duration {
        self.end.saturating_duration_since(Instant::now())
    }

    fn file(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    /// Waits until `name` exists in the directory, or `within` passes (or the run ends).
    async fn appears(&self, name: &str, within: Duration) -> bool {
        let end = Instant::now() + within.min(self.left());
        while !self.file(name).exists() {
            if Instant::now() >= end {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        true
    }

    /// Writes `text` into the directory where only this user can read it.
    fn write(&self, name: &str, text: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut open = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.file(name))
            .expect("a file in the harness directory");
        open.write_all(text.as_bytes())
            .expect("the file is written");
    }

    /// Asks the script for a step on the phone, without waiting for it.
    fn ask_step(&self, name: &str) {
        self.write(&format!("step-{name}.json"), "{}");
    }

    /// Waits until the script says a step is done, and returns what it wrote about it.
    async fn step_done(&self, name: &str, within: Duration) -> Option<String> {
        if !self.appears(&format!("done-{name}"), within).await {
            return None;
        }
        std::fs::read_to_string(self.file(&format!("done-{name}")))
            .ok()
            .map(|text| text.trim().to_owned())
    }

    /// Hands one message to the script, to be put on the phone, and waits until it says the phone
    /// has had it. False when it never does.
    async fn inject(&self, n: usize, kind: &str, note: &str, message: &Value) -> bool {
        self.write(
            &format!("inject-{n}.json"),
            &json!({ "n": n, "kind": kind, "note": note, "message": message }).to_string(),
        );
        self.appears(&format!("injected-{n}"), INJECTION_WAIT).await
    }
}

/// The transport the daemon delivers through in a run: the managed one, to loopback origins only.
///
/// A part of the product that still named the managed service's own origin would be refused here
/// and fail the run; nothing in a run reaches the internet.
#[derive(Debug)]
struct LoopbackOnly(ManagedTransports);

impl DeliveryTransports for LoopbackOnly {
    fn to(&self, origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String> {
        if !origin.as_str().starts_with("http://127.0.0.1:") {
            return Err(format!(
                "a device run reaches no origin but its own: {origin}"
            ));
        }
        self.0.to(origin)
    }

    fn outbound(&self) -> Outbound {
        self.0.outbound()
    }
}

/// The invitation's text with the host reachable at `peer`.
fn invitation_for(invited: &kr_protocol::invitation::PairInviteResult, peer: &str) -> String {
    let mut payload = calls::direct_payload(invited);
    let port = payload
        .network_config
        .direct_addresses
        .first()
        .and_then(|hint| hint.as_str().rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .expect("the host names an address to dial");
    payload.network_config.direct_addresses =
        vec![NetworkHint::new(format!("{peer}:{port}")).expect("an address that is a hint")];
    QrPayload::Direct(Box::new(payload))
        .to_text()
        .expect("a payload that is text")
        .to_string()
}

/// The data of a message the provider stand-in recorded, as the phone's receiver is given it.
fn data_of(message: &Value) -> serde_json::Map<String, Value> {
    message["message"]["data"]
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// A copy of a challenge message with one data field replaced, or removed when `value` is null.
fn with_data(message: &Value, key: &str, value: Value) -> Value {
    let mut changed = message.clone();
    let data = changed["message"]["data"]
        .as_object_mut()
        .expect("a challenge has data");
    if value.is_null() {
        data.remove(key);
    } else {
        data.insert(key.to_owned(), value);
    }
    changed
}

fn uuid_text(byte: u8) -> String {
    kr_protocol::scalars::Uuid::from_bytes([byte; 16]).to_string()
}

/// Waits until `holds` says it does, or `within` passes.
async fn until(within: Duration, mut holds: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + within;
    while !holds() {
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

/// Whether a message the stand-in recorded is a delivery to `token`, and not a challenge.
fn is_delivery(sent: &push_support::Sent, token: &str) -> bool {
    sent.token == token && sent.body["message"]["data"]["notification_id"].is_string()
}

/// Whether a message the stand-in recorded is a challenge to `token`.
fn is_challenge(sent: &push_support::Sent, token: &str) -> bool {
    sent.token == token && sent.body["message"]["data"]["kr_challenge"].is_string()
}

/// The destination the daemon holds under `id`.
fn destination_of(
    host: &Host,
    id: &kr_delivery::destination::DestinationId,
) -> Option<kr_delivery::destination::DestinationRecord> {
    host.controller()
        .delivery()
        .with(|producer| Ok(producer.journal().destination(id).expect("a read")))
        .expect("the daemon's journal")
}

/// Every delivery the daemon's journal holds.
fn deliveries_of(host: &Host) -> Vec<kr_delivery::journal::DeliveryRecord> {
    host.controller()
        .delivery()
        .with(|producer| Ok(producer.journal().deliveries().expect("a read")))
        .expect("the daemon's journal")
}

/// What the daemon has done with the questions the worker asked: how many the attention store
/// holds as pending input, how many of its announcements wait to be taken, and whether the
/// delivery journal holds an event no producer has finished with.
fn settling(host: &Host) -> (usize, Option<usize>, bool) {
    let (raised, awaiting) = host
        .controller()
        .attention()
        .take_for_delivery(|store, _| {
            let raised = store
                .engine()
                .map(|engine| {
                    engine
                        .items()
                        .filter(|item| {
                            item.rule == kr_protocol::attention::AttentionRule::PendingInput
                        })
                        .count()
                })
                .unwrap_or(0);
            (raised, store.awaiting_delivery().ok())
        })
        .unwrap_or((0, None));
    let journal_has_pending = host
        .controller()
        .delivery()
        .with(|producer| {
            Ok(producer
                .journal()
                .pending_events(0, 1)
                .map_or(true, |pending| !pending.is_empty()))
        })
        .unwrap_or(true);
    (raised, awaiting, journal_has_pending)
}

/// Waits until every question in `asked` has been raised in the attention store (the ones the
/// worker's ledger holds as answered no longer pend there) and the daemon has taken every one of
/// them into its journal and produced from them. What it saw last is written to the run's output
/// when it gives up.
async fn settled(
    host: &Host,
    worker: &Worker,
    asked: &[kr_protocol::question::Question],
    within: Duration,
) -> bool {
    let answered = || {
        asked
            .iter()
            .filter(|question| {
                worker.held(question).state != kr_protocol::question::QuestionState::Pending
            })
            .count()
    };
    let reached = until(within, || {
        let (raised, awaiting, journal_has_pending) = settling(host);
        raised + answered() >= asked.len() && awaiting == Some(0) && !journal_has_pending
    })
    .await;
    if !reached {
        let (raised, awaiting, journal_has_pending) = settling(host);
        eprintln!(
            "settled gave up: {} asked, {} no longer pending, {raised} pending in the store, \
             {awaiting:?} announcements awaiting delivery, journal has pending events: \
             {journal_has_pending}",
            asked.len(),
            answered(),
        );
    }
    reached
}

/// Every file under `directory` that holds `needle`.
fn files_holding(directory: &Path, needle: &[u8]) -> usize {
    fn walk(directory: &Path, needle: &[u8], found: &mut usize) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, needle, found);
            } else if std::fs::read(&path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            {
                *found += 1;
            }
        }
    }
    let mut found = 0;
    walk(directory, needle, &mut found);
    found
}

/// Whether the daemon's secret store holds this bearer, spelled as a wire or a file spells it.
fn secret_store_holds(host: &Host, secret: &[u8]) -> bool {
    use base64::Engine as _;
    let secrets = host.tree().environment().secrets_dir();
    let spelled = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(secret)
        .into_bytes();
    files_holding(&secrets, &spelled) + files_holding(&secrets, secret) > 0
}

/// Runs the host and the provider stand-in for one phone, from its invitation to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "started by scripts/e2e-push-device.sh beside a simulator or an emulator"]
async fn a_phone_registers_with_a_gateway_and_is_delivered_to_through_it() {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let run = Run {
        directory: PathBuf::from(env("KR_HARNESS_DIR")),
        end: Instant::now()
            + Duration::from_secs(
                std::env::var("KR_HARNESS_SECONDS")
                    .ok()
                    .and_then(|seconds| seconds.parse().ok())
                    .unwrap_or(1500),
            ),
    };
    let peer = std::env::var("KR_HARNESS_PEER").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let gateway = env("KR_PUSH_GATEWAY");
    let token = env("KR_PUSH_TOKEN");
    let fcm_port: u16 = env("KR_PUSH_FCM_PORT").parse().expect("a port");
    let mut report = serde_json::Map::new();

    let fcm = Fcm::start(fcm_port).await;
    run.write("ready.json", &json!({ "fcm": fcm.origin() }).to_string());

    // The daemon takes a credential only from the gateway this run stood its service at, and
    // delivers only to loopback.
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut stopped = host.shut_down().await;
    stopped.account_service_stays_at(&gateway);
    let worker = Worker::start(stopped.tree(), 1).await;
    // The daemon joins the network with its own key store, as a shipped one does, so that the host
    // key the phone records when it pairs is the one the daemon signs the gateway's requests with.
    let host = stopped
        .start_with_timer(Arc::new(kr_controller::quiet::RealTimer))
        .await;
    assert!(
        host.controller()
            .attach_delivery_transport(Arc::new(LoopbackOnly(ManagedTransports::new(
                Outbound::Direct
            )))),
        "the daemon takes the run's transport"
    );

    assert!(
        run.appears("go", INVITATION_WAIT).await,
        "the script never said the phone was ready"
    );

    // The invitation lives for minutes, so it is issued only now, with the phone installed.
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(&owner);
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(&[
            ActionRight::SessionView,
            ActionRight::QuestionRespond,
            ActionRight::AgentApprovalRespond,
        ]),
        &signer,
    )
    .await
    .expect("a direct invitation");
    run.write("invitation.txt", &invitation_for(&invited, &peer));

    // The phone redeems it, and the host's owner approves the device that did.
    let approval = async {
        loop {
            let status = calls::owner_status(&mut client, invited.invitation_id)
                .await
                .expect("the invitation's status");
            if status.owner.0.and_then(|view| view.approval.0).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(run.left(), approval)
        .await
        .expect("the phone redeemed the invitation");
    let confirmed = calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves the phone");
    let device_id = confirmed.device_id;
    report.insert("device_id".to_owned(), json!(device_id.to_string()));

    // ---- Registration (16.06, 16.08, 16.11) -------------------------------------------------
    // The phone turned notifications on and proposed its token; the gateway sent the challenge to
    // the stand-in. The phone is first given five messages that are not the challenge of the
    // registration it waits for, which it must not answer, and then the challenge.
    assert!(
        until(REGISTRATION_WAIT.min(run.left()), || fcm.sent().iter().any(
            |sent| sent.token == token && sent.body["message"]["data"]["kr_challenge"].is_string()
        ))
        .await,
        "the gateway never sent the phone its challenge"
    );
    let challenge = fcm
        .sent()
        .into_iter()
        .find(|sent| {
            sent.token == token && sent.body["message"]["data"]["kr_challenge"].is_string()
        })
        .expect("the challenge")
        .body;
    report.insert(
        "challenge_fields".to_owned(),
        json!(data_of(&challenge).keys().collect::<Vec<_>>()),
    );
    let bad = [
        (
            "another registration",
            with_data(&challenge, "kr_registration_id", json!(uuid_text(0x77))),
        ),
        (
            "another token",
            with_data(
                &challenge,
                "kr_token_digest",
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ),
        (
            "another gateway",
            with_data(&challenge, "kr_gateway_origin", json!("http://127.0.0.1:9")),
        ),
        (
            "an expired challenge",
            with_data(&challenge, "kr_expires_at_ms", json!("1000")),
        ),
        (
            "a challenge with no registration",
            with_data(&challenge, "kr_registration_id", Value::Null),
        ),
    ];
    let mut n = 0;
    for (note, message) in &bad {
        n += 1;
        assert!(
            run.inject(n, "challenge", note, message).await,
            "the script did not report {note}"
        );
    }
    // Nothing the phone was given so far is an answer to the gateway: the host has no destination.
    assert!(
        fcm.sent().iter().all(|sent| sent.token == token),
        "only this run's phone was written to"
    );
    let early = host
        .controller()
        .delivery()
        .with(|producer| Ok(producer.journal().destinations().expect("the destinations")))
        .expect("the daemon's journal");
    report.insert(
        "destinations_before_the_challenge".to_owned(),
        json!(early.len()),
    );
    n += 1;
    assert!(
        run.inject(n, "challenge", "the challenge", &challenge)
            .await,
        "the script did not report the challenge"
    );
    n += 1;
    assert!(
        run.inject(n, "challenge", "the challenge again", &challenge)
            .await,
        "the script did not report the replayed challenge"
    );

    // The phone answered, was authorised for this host, and handed the host its credential.
    let id =
        kr_delivery::destination::DestinationId::new(device_id.to_string()).expect("an identifier");
    let registered = until(REGISTRATION_WAIT.min(run.left()), || {
        host.controller()
            .delivery()
            .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
            .expect("the daemon's journal")
            .is_some()
    })
    .await;
    report.insert("destination_present".to_owned(), json!(registered));
    let mut held_destination = None;
    if registered {
        let record = host
            .controller()
            .delivery()
            .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
            .expect("the daemon's journal")
            .expect("the destination");
        if let kr_delivery::destination::Destination::Push(push) = &record.destination {
            report.insert(
                "sender_record_id".to_owned(),
                json!(push.sender_record_id.to_string()),
            );
            report.insert(
                "preview_key_revision".to_owned(),
                json!(push.preview_keys.revision),
            );
            report.insert(
                "preview_key_id".to_owned(),
                json!(
                    kr_crypto::keys::key_id(
                        kr_protocol::pairing::KeyPurpose::NotificationPreview,
                        push.preview_keys.current.as_bytes()
                    )
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
                ),
            );
            report.insert("previews_enabled".to_owned(), json!(push.previews_enabled));
        }
        report.insert("destination_enabled".to_owned(), json!(record.enabled));
        held_destination = Some(record);
    }
    // Every question the worker asked, so that what the daemon has to settle is counted from the
    // worker's own ledger and not from what this run remembers answering.
    let mut asked_questions: Vec<kr_protocol::question::Question> = Vec::new();

    // ---- A delivery (16.12, 16.13) ----------------------------------------------------------
    // A question the worker asks becomes a notification for the phone. Its text carries a marker
    // that must reach neither the provider's message nor the phone's screen.
    let before = fcm.sent().len();
    let asked = Instant::now();
    let question = worker.ask_with_context(&format!("run-{MARKER}"), &format!("context {MARKER}"));
    asked_questions.push(question.clone());
    report.insert(
        "question_id".to_owned(),
        json!(question.question_id.to_string()),
    );
    let delivered = until(DELIVERY_WAIT.min(run.left()), || {
        fcm.sent().iter().skip(before).any(|sent| {
            sent.token == token && sent.body["message"]["data"]["notification_id"].is_string()
        })
    })
    .await;
    report.insert("delivery_reached_the_provider".to_owned(), json!(delivered));
    if delivered {
        let sent = fcm
            .sent()
            .into_iter()
            .skip(before)
            .find(|sent| {
                sent.token == token && sent.body["message"]["data"]["notification_id"].is_string()
            })
            .expect("the delivery");
        let events = host
            .controller()
            .delivery()
            .with(|producer| Ok(producer.journal().events().expect("the events")))
            .expect("the daemon's journal");
        report.insert("provider_message_bytes".to_owned(), json!(sent.bytes));
        report.insert(
            "provider_message_carries_the_marker".to_owned(),
            json!(sent.body.to_string().contains(MARKER)),
        );
        // The shape the gateway gave the message for the platform it is for (16.02, 16.12).
        let message = &sent.body["message"];
        report.insert(
            "provider_message_shape".to_owned(),
            json!({
                "android_data_only": message["android"].is_object()
                    && message["android"]["notification"].is_null()
                    && message["data"]["alert"].is_string(),
                "android_priority": message["android"]["priority"],
                "apns_alert": message["apns"]["payload"]["aps"]["alert"].is_string()
                    || message["apns"]["payload"]["aps"]["alert"].is_object(),
                "apns_mutable_content": message["apns"]["payload"]["aps"]["mutable-content"],
                "apns_expiration": message["apns"]["headers"]["apns-expiration"].is_string(),
                "apns_collapse_id": message["apns"]["headers"]["apns-collapse-id"].is_string(),
            }),
        );
        report.insert(
            "provider_message_authorised".to_owned(),
            json!(sent.authorised),
        );
        report.insert(
            "event_recorded_before_the_provider_received_it".to_owned(),
            json!(
                events
                    .iter()
                    .map(|event| event.recorded_at_ms.get())
                    .max()
                    .is_some_and(|recorded| recorded <= sent.received_at_ms)
            ),
        );
        report.insert(
            "seconds_from_the_question_to_the_provider".to_owned(),
            json!(asked.elapsed().as_secs_f64()),
        );
        n += 1;
        report.insert(
            "delivery_put_on_the_phone".to_owned(),
            json!(run.inject(n, "delivery", "a question", &sent.body).await),
        );
        report.insert(
            "delivery_shown".to_owned(),
            json!(run.appears(&format!("shown-{n}"), INJECTION_WAIT).await),
        );
    }

    // The phases that follow need a destination, and say nothing without one.
    let Some(destination) = held_destination else {
        report.insert("later_phases_ran".to_owned(), json!(false));
        run.write("report.json", &Value::Object(report).to_string());
        run.appears("finish", run.left()).await;
        let _ = (Path::new(""), worker);
        host.stop().await;
        return;
    };
    report.insert("later_phases_ran".to_owned(), json!(true));
    let kr_delivery::destination::Destination::Push(push) = &destination.destination else {
        panic!("a phone's destination is a push destination");
    };
    let sender_id = push.sender_record_id;
    let credentials = Arc::clone(host.controller().delivery_runtime().credentials());
    let first_bearer = credentials
        .held(sender_id)
        .map(|held| held.secret.expose().to_vec())
        .expect("the daemon holds the credential the phone registered");

    // ---- The action leg (09.21) -------------------------------------------------------------
    // The question the delivery above was about is answered from the notification: the phone's
    // notification is tapped, the application opens on the Attention screen, the person answers
    // there, and the worker's ledger records the answer as the paired device's.
    run.ask_step("tap");
    let tap_report = run.step_done("tap", SCREEN_STEP_WAIT).await;
    report.insert("tap_step".to_owned(), json!(tap_report));
    let answered_by_the_phone = until(DELIVERY_WAIT.min(run.left()), || {
        worker.held(&question).state == kr_protocol::question::QuestionState::Answered
    })
    .await;
    let record = worker.held(&question).answer.0;
    report.insert(
        "question_answered_from_the_notification".to_owned(),
        json!(answered_by_the_phone),
    );
    report.insert(
        "answer_is_the_paired_devices".to_owned(),
        json!(
            record
                .as_ref()
                .is_some_and(|record| record.device_id.0 == Some(device_id))
        ),
    );

    // A second question is answered at the host while its notification is still on the phone and
    // the person has chosen an answer to it and not yet sent it. The phone no longer offers it to
    // send, and the worker keeps the host's answer.
    let before = fcm.sent().len();
    let second = worker.ask_with_context("late-1", "the host answers this one first");
    asked_questions.push(second.clone());
    let second_delivered = until(DELIVERY_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .skip(before)
            .any(|sent| is_delivery(sent, &token))
    })
    .await;
    report.insert("second_delivered".to_owned(), json!(second_delivered));
    if second_delivered {
        let message = fcm
            .sent()
            .into_iter()
            .skip(before)
            .find(|sent| is_delivery(sent, &token))
            .expect("the second delivery")
            .body;
        n += 1;
        report.insert(
            "second_shown".to_owned(),
            json!(
                run.inject(n, "delivery", "a second question", &message)
                    .await
                    && run.appears(&format!("shown-{n}"), INJECTION_WAIT).await
            ),
        );
        // The form is open on the phone, with the answer chosen and not sent.
        run.ask_step("late");
        let opened = run.step_done("late", SCREEN_STEP_WAIT).await;
        report.insert("late_step".to_owned(), json!(opened));
        let resolved_at_the_host = worker.service.questions().answer(
            &kr_protocol::ids::ActorId::new("local:501").expect("an actor"),
            None,
            &kr_protocol::question::QuestionAnswerParams {
                session_id: worker.session_id,
                question_id: second.question_id,
                expected_revision: second.revision,
                answer: kr_protocol::question::QuestionAnswer::Decision { decided: false },
            },
            kr_worker::questions::Now {
                utc_ms: kr_ipc::now_ms(),
                boot_ms: kr_ipc::clock::boot_elapsed_ms(),
            },
        );
        report.insert(
            "second_resolved_at_the_host".to_owned(),
            json!(resolved_at_the_host.is_ok()),
        );
        run.ask_step("late-observe");
        let observed = run.step_done("late-observe", SCREEN_STEP_WAIT).await;
        report.insert("late_observe_step".to_owned(), json!(observed));
        let held = worker.held(&second);
        report.insert(
            "host_answer_kept".to_owned(),
            json!(
                held.state == kr_protocol::question::QuestionState::Answered
                    && held.answer.0.as_ref().is_some_and(|record| {
                        record.device_id.0.is_none()
                            && record.answer
                                == kr_protocol::question::QuestionAnswer::Decision {
                                    decided: false,
                                }
                    })
            ),
        );
    }

    // ---- Renewal with the phone away (16.09) ------------------------------------------------
    // The phone's installation has the gateway issue its authorisation again and tells the host
    // nothing, and its application is ended. The host's bearer is now one the gateway will not
    // take. The next delivery is refused for it, and the daemon renews through the gateway, with
    // nobody on the phone, and delivers.
    let revision_before = credentials.held(sender_id).map(|held| held.revision.get());
    run.ask_step("reissue");
    let phone_state = run.step_done("reissue", INJECTION_WAIT).await;
    report.insert("reissue_step".to_owned(), json!(phone_state));
    let before = fcm.sent().len();
    asked_questions
        .push(worker.ask_with_context("renew-1", "the host holds a bearer the gateway replaced"));
    let renewed = until(RENEWAL_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .skip(before)
            .any(|sent| is_delivery(sent, &token))
    })
    .await;
    let revision_after = credentials.held(sender_id).map(|held| held.revision.get());
    report.insert("renewal_delivered".to_owned(), json!(renewed));
    report.insert(
        "revision_before_the_reissue".to_owned(),
        json!(revision_before),
    );
    report.insert(
        "revision_after_the_renewal".to_owned(),
        json!(revision_after),
    );
    let after = destination_of(&host, &id);
    report.insert(
        "renewal_left_the_destination_as_it_was".to_owned(),
        json!(after.as_ref().is_some_and(|after| after.binding_digest()
            == destination.binding_digest()
            && after.enabled)),
    );
    report.insert(
        "renewal_kept_the_authorisation".to_owned(),
        json!(match after.as_ref().map(|after| &after.destination) {
            Some(kr_delivery::destination::Destination::Push(after)) =>
                after.sender_record_id == sender_id,
            _ => false,
        }),
    );

    // ---- A token the provider does not know (16.16) -----------------------------------------
    // The provider answers a send as it does for a token that was never registered or has been
    // deleted. The host takes the destination out of service and sends nothing more to it; a new
    // registration, with a new token, answered through the same challenge, resumes delivery.
    fcm.forget(&token);
    let before = fcm.sent().len();
    asked_questions.push(worker.ask_with_context("gone-1", "the provider does not know the token"));
    let unregistered = until(DELIVERY_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .skip(before)
            .any(|sent| sent.token == token && sent.answered == push_support::Answer::Unregistered)
    })
    .await;
    report.insert(
        "provider_answered_unregistered".to_owned(),
        json!(unregistered),
    );
    let disabled = until(DELIVERY_WAIT.min(run.left()), || {
        destination_of(&host, &id).is_some_and(|record| !record.enabled)
    })
    .await;
    report.insert("destination_out_of_service".to_owned(), json!(disabled));
    let sent_so_far = fcm.sent().len();
    asked_questions
        .push(worker.ask_with_context("gone-2", "nothing may reach a destination out of service"));
    let settled_out = settled(
        &host,
        &worker,
        &asked_questions,
        DELIVERY_WAIT.min(run.left()),
    )
    .await;
    report.insert(
        "nothing_sent_while_out_of_service".to_owned(),
        json!(settled_out && fcm.sent().len() == sent_so_far),
    );

    // The phone registers again with a token the provider knows.
    let replacement = format!("{token}-replaced");
    run.ask_step("newtoken");
    let challenged = until(REGISTRATION_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .any(|sent| is_challenge(sent, &replacement))
    })
    .await;
    report.insert("replacement_challenged".to_owned(), json!(challenged));
    if challenged {
        let message = fcm
            .sent()
            .into_iter()
            .find(|sent| is_challenge(sent, &replacement))
            .expect("the challenge")
            .body;
        n += 1;
        report.insert(
            "replacement_challenge_put_on_the_phone".to_owned(),
            json!(
                run.inject(n, "challenge", "the replacement's challenge", &message)
                    .await
            ),
        );
    }
    report.insert(
        "newtoken_step".to_owned(),
        json!(run.step_done("newtoken", REGISTRATION_WAIT).await),
    );
    let resumed = until(REGISTRATION_WAIT.min(run.left()), || {
        destination_of(&host, &id).is_some_and(|record| record.enabled)
    })
    .await;
    report.insert("destination_back_in_service".to_owned(), json!(resumed));
    let before = fcm.sent().len();
    asked_questions.push(worker.ask_with_context("back-1", "the replacement token is known"));
    let back = until(DELIVERY_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .skip(before)
            .any(|sent| is_delivery(sent, &replacement))
    })
    .await;
    report.insert("delivery_resumed_on_the_new_token".to_owned(), json!(back));

    // ---- A burst (16.17) --------------------------------------------------------------------
    // Twenty-two questions at once. The host keeps every request; what reaches the provider is what
    // the host's own limits and the gateway's let through, and the host's journal accounts for
    // each of the twenty-two.
    let burst = 22;
    let events_before = host
        .controller()
        .delivery()
        .with(|producer| Ok(producer.journal().events().expect("the events").len()))
        .expect("the daemon's journal");
    let deliveries_before = deliveries_of(&host).len();
    let sent_before = fcm
        .sent()
        .iter()
        .filter(|sent| is_delivery(sent, &replacement))
        .count();
    for number in 1..=burst {
        asked_questions.push(worker.ask_with_context(&format!("burst-{number}"), "one of a burst"));
    }
    let burst_settled = settled(
        &host,
        &worker,
        &asked_questions,
        REGISTRATION_WAIT.min(run.left()),
    )
    .await;
    // Every record of the burst is at rest before it is counted: none is waiting for a first try,
    // on the wire, or waiting for another.
    let at_rest = until(DELIVERY_WAIT.min(run.left()), || {
        deliveries_of(&host)
            .iter()
            .skip(deliveries_before)
            .all(|record| {
                !matches!(
                    record.state,
                    kr_delivery::journal::DeliveryState::Admitted
                        | kr_delivery::journal::DeliveryState::InFlight
                        | kr_delivery::journal::DeliveryState::Retrying
                )
            })
    })
    .await;
    let records = deliveries_of(&host);
    let fresh: Vec<_> = records.iter().skip(deliveries_before).collect();
    let events_after = host
        .controller()
        .delivery()
        .with(|producer| Ok(producer.journal().events().expect("the events").len()))
        .expect("the daemon's journal");
    let count_of = |state: kr_delivery::journal::DeliveryState| {
        fresh.iter().filter(|record| record.state == state).count()
    };
    let accepted = count_of(kr_delivery::journal::DeliveryState::Accepted);
    let collapsed = count_of(kr_delivery::journal::DeliveryState::Collapsed);
    // Whatever the host handed the gateway and the gateway took reaches the stand-in; let the last
    // of it arrive before counting.
    let reached = until(DELIVERY_WAIT.min(run.left()), || {
        fcm.sent()
            .iter()
            .filter(|sent| is_delivery(sent, &replacement))
            .count()
            - sent_before
            >= accepted
    })
    .await;
    let at_provider = fcm
        .sent()
        .iter()
        .filter(|sent| is_delivery(sent, &replacement))
        .count()
        - sent_before;
    let mut states = std::collections::BTreeMap::<String, usize>::new();
    for record in &fresh {
        *states.entry(format!("{:?}", record.state)).or_default() += 1;
    }
    report.insert("burst_states".to_owned(), json!(states));
    report.insert("burst_at_rest".to_owned(), json!(at_rest));
    report.insert(
        "burst_details".to_owned(),
        json!(
            fresh
                .iter()
                .filter_map(|record| record.detail.clone())
                .collect::<std::collections::BTreeSet<_>>()
        ),
    );
    report.insert("burst_asked".to_owned(), json!(burst));
    report.insert("burst_settled".to_owned(), json!(burst_settled));
    report.insert(
        "burst_events_retained".to_owned(),
        json!(events_after - events_before),
    );
    report.insert("burst_deliveries_written".to_owned(), json!(fresh.len()));
    report.insert("burst_accepted".to_owned(), json!(accepted));
    report.insert("burst_collapsed".to_owned(), json!(collapsed));
    report.insert(
        "burst_other".to_owned(),
        json!(fresh.len() - accepted - collapsed),
    );
    report.insert("burst_at_the_provider".to_owned(), json!(at_provider));
    report.insert("burst_provider_caught_up".to_owned(), json!(reached));

    // ---- Unpairing (16.10) ------------------------------------------------------------------
    // The owner unpairs the phone. The destination ends, the daemon forgets the credential and its
    // secret store gives the bearer up, and the gateway is asked to revoke the authorisation, which
    // it takes: nothing is owed afterwards.
    let held_now = credentials
        .held(sender_id)
        .map(|held| held.secret.expose().to_vec());
    let stored_before = held_now
        .as_deref()
        .is_some_and(|bearer| secret_store_holds(&host, bearer));
    let mut client = host.client().await;
    let revoked: Result<kr_protocol::sharing::RevocationResult, _> = net_support::pairing::mutate(
        host.environment_id,
        &mut client,
        kr_protocol::method::Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams { device_id },
    )
    .await;
    report.insert("unpaired".to_owned(), json!(revoked.is_ok()));
    report.insert(
        "bearer_was_in_the_secret_store".to_owned(),
        json!(stored_before),
    );
    report.insert(
        "destination_ended".to_owned(),
        json!(
            destination_of(&host, &id)
                .is_none_or(|record| !record.enabled && record.rule.is_none())
        ),
    );
    report.insert(
        "credential_forgotten".to_owned(),
        json!(credentials.held(sender_id).is_none()),
    );
    report.insert(
        "secret_store_gave_the_bearer_up".to_owned(),
        json!(
            held_now
                .as_deref()
                .is_some_and(|bearer| !secret_store_holds(&host, bearer))
                && !secret_store_holds(&host, &first_bearer)
        ),
    );
    let revocation_settled = until(REGISTRATION_WAIT.min(run.left()), || {
        host.controller()
            .delivery()
            .with(|producer| {
                Ok(producer
                    .journal()
                    .revocations_due(u64::MAX, 64)
                    .expect("a read")
                    .is_empty())
            })
            .expect("the daemon's journal")
    })
    .await;
    report.insert(
        "revocation_no_longer_owed".to_owned(),
        json!(revocation_settled),
    );
    let sent_end = fcm.sent().len();
    asked_questions.push(worker.ask_with_context("after-unpair", "nobody is left to tell"));
    let settled_end = settled(
        &host,
        &worker,
        &asked_questions,
        DELIVERY_WAIT.min(run.left()),
    )
    .await;
    report.insert(
        "nothing_sent_after_unpairing".to_owned(),
        json!(settled_end && fcm.sent().len() == sent_end),
    );

    // ---- The end ----------------------------------------------------------------------------
    report.insert(
        "provider_paths".to_owned(),
        json!(
            fcm.paths()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        ),
    );
    report.insert("provider_tokens_minted".to_owned(), json!(fcm.minted()));
    run.write("report.json", &Value::Object(report).to_string());
    run.appears("finish", run.left()).await;
    let _ = (Path::new(""), worker);
    host.stop().await;
}
