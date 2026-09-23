//! The host's side of notification delivery, end to end against a gateway double.
//!
//! Nothing here reaches a real gateway, a real provider or a real external destination. Section 16
//! is about what a host does before and after one of those answers, and a double is what makes
//! each answer reachable: a provider that queued it, one that refused the token, one that has not
//! answered at all.
//!
//! The rows these tests close are named in each test's own comment.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use kr_controller::push::DeliveryModule;
use kr_controller::push::credentials::{CredentialRenewal, HeldCredentials};
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
    ExternalDestination, Idempotency, PreviewKeys, PushDestination,
};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, ExternalSender};
use kr_delivery::journal::{DeliveryState, EventSource};
use kr_delivery::producer::{
    DEFAULT_NOTIFICATION_LIFETIME_MS, Notice, RecipientAuthority, RecipientScope,
};
use kr_delivery::push::{DeliveryStatus, PushSender, SendOutcome, SenderCredentials, StatusAnswer};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    AuthorityRevision, BuildId, DeviceId, DeviceKeyRevision, GrantId, InstallationId,
    NotificationId, PushSenderRecordId, SessionId,
};
use kr_protocol::pairing::{DeviceName, DevicePlatform};
use kr_protocol::push::{
    PushAlert, PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushDeliveryState,
    PushUrgency,
};
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, EndpointKey, NotificationPreviewKey, Nullable, SecretBytes32,
    TimestampMs, Uuid,
};
use kr_worker::history_filter::ViewerScope;

const NOW: u64 = 1_700_000_000_000;

/// A gateway that answers whatever it was told to, and remembers what it was asked.
///
/// A scripted decision is about the notification the double is asked about, which is what an
/// honest gateway answers. An answer about another notification is exercised through the status
/// adapter's own transport instead.
#[derive(Debug)]
struct GatewayDouble {
    answers: Mutex<Vec<SendOutcome>>,
    sent: Mutex<Vec<PushDeliveryRequest>>,
    questions: Mutex<u64>,
}

impl GatewayDouble {
    fn answering(answers: Vec<SendOutcome>) -> Self {
        Self {
            answers: Mutex::new(answers),
            sent: Mutex::new(Vec::new()),
            questions: Mutex::new(0),
        }
    }

    fn queued() -> Self {
        Self::answering(Vec::new())
    }

    fn next(&self, request: &PushDeliveryRequest) -> SendOutcome {
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .push(request.clone());
        let mut answers = self.answers.lock().expect("the double is not poisoned");
        if answers.is_empty() {
            return SendOutcome::Decided(Box::new(PushDeliveryAck {
                decided_at_ms: TimestampMs::new(NOW),
                notification_id: request.notification_id,
                state: PushDeliveryState::Queued,
                suppression: Nullable::null(),
            }));
        }
        about(answers.remove(0), request.notification_id)
    }

    fn sent(&self) -> Vec<PushDeliveryRequest> {
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }

    /// How many status questions were put, rather than deliveries presented as new work.
    fn questions(&self) -> u64 {
        *self.questions.lock().expect("the double is not poisoned")
    }
}

impl PushSender for GatewayDouble {
    fn send(
        &self,
        _credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        self.next(request)
    }
}

/// The status route, which answers from what the double recorded and never delivers anything.
///
/// It draws from the same queue of answers as the delivery route, so a test writes one script for
/// a notification whatever question happens to be put about it, and it records nothing in `sent`:
/// asking is not sending, and a test that could not tell them apart would prove nothing.
impl DeliveryStatus for GatewayDouble {
    fn status(
        &self,
        _credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> StatusAnswer {
        *self.questions.lock().expect("the double is not poisoned") += 1;
        let answer = {
            let mut answers = self.answers.lock().expect("the double is not poisoned");
            if answers.is_empty() {
                None
            } else {
                Some(answers.remove(0))
            }
        };
        match answer.map(|answer| about(answer, notification_id)) {
            Some(SendOutcome::Decided(ack)) => StatusAnswer::Recorded(ack),
            Some(
                SendOutcome::NotDispatched { detail }
                | SendOutcome::Unknown { detail }
                | SendOutcome::Forbidden { detail },
            ) => StatusAnswer::Unanswered { detail },
            // The unscripted answer is the one the delivery route gives: the provider took it.
            None => StatusAnswer::Recorded(Box::new(PushDeliveryAck {
                decided_at_ms: TimestampMs::new(NOW),
                notification_id,
                state: PushDeliveryState::Queued,
                suppression: Nullable::null(),
            })),
        }
    }
}

/// Makes a scripted decision one about the notification that was asked about.
fn about(answer: SendOutcome, notification_id: NotificationId) -> SendOutcome {
    match answer {
        SendOutcome::Decided(mut ack) => {
            ack.notification_id = notification_id;
            SendOutcome::Decided(ack)
        }
        other => other,
    }
}

/// A gateway that answers no status question, which is what an unreachable one does.
#[derive(Debug)]
struct SilentStatus;

impl DeliveryStatus for SilentStatus {
    fn status(
        &self,
        _credential: &PushDeliveryCredential,
        _notification_id: NotificationId,
    ) -> StatusAnswer {
        StatusAnswer::Unanswered {
            detail: "the gateway did not answer".to_owned(),
        }
    }
}

/// An external destination that answers whatever it was told to.
#[derive(Debug)]
struct ExternalDouble {
    answers: Mutex<Vec<ExternalOutcome>>,
    sent: Mutex<Vec<ExternalMessage>>,
    endpoints: Mutex<Vec<String>>,
}

impl ExternalDouble {
    fn answering(answers: Vec<ExternalOutcome>) -> Self {
        Self {
            answers: Mutex::new(answers),
            sent: Mutex::new(Vec::new()),
            endpoints: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<ExternalMessage> {
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }
}

impl ExternalDouble {
    /// The addresses this double was asked to send to, in order.
    fn endpoints(&self) -> Vec<String> {
        self.endpoints
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }
}

impl ExternalSender for ExternalDouble {
    fn send(
        &self,
        destination: &ExternalDestination,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        self.endpoints
            .lock()
            .expect("the double is not poisoned")
            .push(destination.endpoint.clone());
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .push(message.clone());
        let mut answers = self.answers.lock().expect("the double is not poisoned");
        if answers.is_empty() {
            return ExternalOutcome::Delivered;
        }
        answers.remove(0)
    }
}

/// A credential store whose renewal succeeds, which is what a host with a reachable gateway has.
#[derive(Debug)]
struct RenewingCredentials {
    held: PushDeliveryCredential,
    renewed: PushDeliveryCredential,
}

impl SenderCredentials for RenewingCredentials {
    fn current(&self, _sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        Some(self.held.clone())
    }

    fn renew(
        &self,
        _held: &PushDeliveryCredential,
    ) -> Result<PushDeliveryCredential, kr_delivery::DeliveryError> {
        Ok(self.renewed.clone())
    }
}

/// One exchange a recording transport was asked to make.
#[derive(Clone, Debug)]
struct Asked {
    url: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

/// A transport that answers each exchange from a script and records what it was asked, which is
/// how a test sees exactly what an adapter put on the wire.
#[derive(Debug, Default)]
struct RecordingHttp {
    answers: Mutex<Vec<Scripted>>,
    asked: Mutex<Vec<Asked>>,
}

/// What a recording transport does with one exchange: answer it, or fail it with the class of
/// failure the managed transport reports.
type Scripted = Result<(u16, Vec<u8>), kr_protocol::error::ErrorCode>;

impl RecordingHttp {
    fn answering(answers: Vec<(u16, Vec<u8>)>) -> Self {
        Self::scripted(answers.into_iter().map(Ok).collect())
    }

    fn scripted(answers: Vec<Scripted>) -> Self {
        Self {
            answers: Mutex::new(answers),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .expect("the recorder is not poisoned")
            .clone()
    }
}

impl kr_client::services::ServiceHttp for RecordingHttp {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        self.asked
            .lock()
            .expect("the recorder is not poisoned")
            .push(Asked {
                url: url.to_owned(),
                body: body.to_vec(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            });
        let answer = {
            let mut answers = self.answers.lock().expect("the recorder is not poisoned");
            (!answers.is_empty()).then(|| answers.remove(0))
        };
        Box::pin(async move {
            let (status, body) = answer
                .ok_or(kr_client::ClientError::ConnectionEnded)?
                .map_err(|code| {
                    kr_client::ClientError::Host(kr_protocol::error::ProtocolError::new(
                        code,
                        "the scripted failure",
                    ))
                })?;
            Ok(kr_client::services::ServiceHttpAnswer { status, body })
        })
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

/// The gateway's envelope around one recorded decision.
fn recorded(notification_id: NotificationId, state: PushDeliveryState) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "data": PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW),
            notification_id,
            state,
            suppression: Nullable::null(),
        },
    }))
    .expect("an envelope")
}

/// A renewal that records what it was asked to renew and never reaches a gateway.
#[derive(Debug, Default)]
struct UnreachableRenewal {
    asked: Mutex<Vec<PushSenderRecordId>>,
}

impl UnreachableRenewal {
    fn asked(&self) -> Vec<PushSenderRecordId> {
        self.asked
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }
}

impl CredentialRenewal for UnreachableRenewal {
    fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
        self.asked
            .lock()
            .expect("the double is not poisoned")
            .push(held.sender_record_id);
        Err("the gateway could not be reached".to_owned())
    }
}

/// A credential store whose renewal fails a set number of times and then succeeds, which is what
/// a host sees while the gateway is briefly out of reach.
#[derive(Debug)]
struct FlakyRenewal {
    held: PushDeliveryCredential,
    renewed: PushDeliveryCredential,
    failures_left: Mutex<u32>,
}

impl SenderCredentials for FlakyRenewal {
    fn current(&self, _sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        Some(self.held.clone())
    }

    fn renew(
        &self,
        _held: &PushDeliveryCredential,
    ) -> Result<PushDeliveryCredential, kr_delivery::DeliveryError> {
        let mut failures_left = self
            .failures_left
            .lock()
            .expect("the double is not poisoned");
        if *failures_left > 0 {
            *failures_left -= 1;
            return Err(kr_delivery::DeliveryError::Source(
                "the gateway could not be reached".to_owned(),
            ));
        }
        Ok(self.renewed.clone())
    }
}

/// Every grant the tests need, and no more.
#[derive(Debug)]
struct Granted(BTreeSet<SessionId>);

impl RecipientAuthority for Granted {
    fn scope_for(&self, _rule: &DeliveryRule) -> Option<RecipientScope> {
        Some(RecipientScope {
            viewer: ViewerScope::owner(),
            sessions: SessionSelector::These {
                session_ids: self.0.iter().copied().collect(),
            },
        })
    }
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn session() -> SessionId {
    SessionId::new(uuid(1))
}

fn credential(expires_at_ms: u64) -> PushDeliveryCredential {
    PushDeliveryCredential {
        expires_at_ms: TimestampMs::new(expires_at_ms),
        gateway_origin: kr_protocol::service::GatewayOrigin::new("https://reach.invalid")
            .expect("an origin"),
        installation_id: InstallationId::new(uuid(2)),
        issued_at_ms: TimestampMs::new(NOW - 1_000),
        revision: kr_protocol::ids::PushSenderRevision::new(1),
        secret: SecretBytes32::from_bytes([9; 32]),
        sender_record_id: PushSenderRecordId::new(uuid(3)),
    }
}

struct Environment {
    module: DeliveryModule,
    device_preview: kr_crypto::keys::NotificationPreviewKeyPair,
    /// The journal's directory, on the internal disk, kept alive for as long as the module is.
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
}

/// Opens a delivery module on the internal disk, which is where a test's runtime state belongs.
fn environment() -> Environment {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("delivery.sqlite3");
    let module = DeliveryModule::open_at(
        &path,
        kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
        kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
    )
    .expect("a delivery module");
    Environment {
        module,
        device_preview: kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
        _directory: directory,
        path,
    }
}

fn push_destination(environment: &Environment, previews_enabled: bool) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::new("phone").expect("an identifier"),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*environment.device_preview.public(), 1),
            previews_enabled,
            mailbox_key: Some(
                *kr_crypto::keys::StoredEnvelopeKeyPair::generate()
                    .expect("a keypair")
                    .public(),
            ),
        })),
        rule: Some(DeliveryRule {
            name: "anything that wants a person".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(NOW),
    }
}

fn webhook(idempotency: Idempotency) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::new("hook").expect("an identifier"),
        destination: Destination::External(ExternalDestination {
            kind: DestinationKind::Webhook,
            endpoint: "https://example.invalid/hook".to_owned(),
            idempotency,
        }),
        rule: Some(DeliveryRule {
            name: "on a failed command".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(NOW),
    }
}

fn notice(number: u64, summary: &str) -> Notice {
    Notice {
        event: kr_delivery::journal::EventKey::announcement(
            Some(session()),
            "attention.pending_approval/~abcdef",
            number,
        ),
        alert: PushAlert::ApprovalWaiting,
        urgency: PushUrgency::Attention,
        rule: "attention.pending_approval".to_owned(),
        summary: summary.to_owned(),
        session_id: Some(session()),
        environment_id: None,
        observed_at_ms: TimestampMs::new(NOW),
        collapse_group: "a-session/attention.pending_approval".to_owned(),
        expires_at_ms: TimestampMs::new(NOW + DEFAULT_NOTIFICATION_LIFETIME_MS),
    }
}

fn take_and_produce(
    environment: &Environment,
    notice: &Notice,
    destinations: &[DestinationRecord],
    number: u64,
) -> kr_delivery::producer::Produced {
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(number).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], number, NOW)
                .expect("a page");
            Ok(producer
                .produce(notice, destinations, &Granted(BTreeSet::new()), &[], NOW)
                .expect("a decision"))
        })
        .expect("the producer")
}

/// A clock stopped at one instant, which is what makes a pass reproducible.
const fn at(now_ms: u64) -> impl Fn() -> u64 {
    move || now_ms
}

/// A clock that moves on after its first reading, which is what a pass that blocked looks like.
fn ticking(first: u64, rest: u64) -> impl Fn() -> u64 {
    let readings = std::sync::atomic::AtomicUsize::new(0);
    move || {
        if readings.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            first
        } else {
            rest
        }
    }
}

/// Claims the first delivery the outbox offers, the way a pass does.
fn claim_first(environment: &Environment, now_ms: u64) -> kr_delivery::journal::ClaimedDelivery {
    environment
        .module
        .with(|producer| {
            let selected = producer.journal().due(now_ms, 1).expect("a read");
            let notification_id = selected
                .first()
                .expect("the outbox is offering one")
                .notification_id;
            match producer
                .journal_mut()
                .claim(notification_id, now_ms)
                .expect("a claim")
            {
                kr_delivery::journal::Claim::Taken(claimed) => Ok(*claimed),
                other => panic!("the delivery was not claimable: {other:?}"),
            }
        })
        .expect("a claim")
}

fn held(expires_at_ms: u64) -> HeldCredentials {
    let credentials = HeldCredentials::new();
    credentials.hold(credential(expires_at_ms));
    credentials
}

/// KR-REQ-16.12: the host writes the underlying event first, and the store is what proves it.
#[test]
fn a_notification_cannot_exist_without_the_event_it_was_produced_from() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "an approval is waiting");

    let produced = environment.module.with(|producer| {
        Ok(producer.produce(
            &notice,
            std::slice::from_ref(&destination),
            &Granted(BTreeSet::new()),
            &[],
            NOW,
        ))
    });
    assert!(
        produced.expect("the producer").is_err(),
        "nothing is produced beside an event this journal has not taken"
    );
    environment
        .module
        .with(|producer| {
            assert!(producer.journal().deliveries().expect("a read").is_empty());
            Ok(())
        })
        .expect("a read");

    take_and_produce(&environment, &notice, std::slice::from_ref(&destination), 1);
    environment
        .module
        .with(|producer| {
            let records = producer.journal().deliveries().expect("a read");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].event, notice.event);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12: a queued answer is recorded as queued and never as displayed, read or executed.
#[test]
fn a_provider_that_queued_it_is_recorded_as_queued() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::queued();
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let external = ExternalDouble::answering(Vec::new());
    assert_eq!(
        environment
            .module
            .run_due(
                &gateway,
                &gateway,
                &credentials,
                &external,
                &Granted(BTreeSet::new()),
                &at(NOW)
            )
            .expect("a pass"),
        1
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("accepted it for delivery"))
            );
            assert_eq!(record.content, None, "a settled delivery keeps no content");
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.11 and 16.13: nothing about the work leaves the seal, and the alert is generic.
#[test]
fn what_reaches_the_gateway_carries_no_command_text_and_no_project_name() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let mut notice = notice(1, "approve: rm -rf /var/lib/kalareach-production");
    notice.collapse_group = "kalareach-production/attention.pending_approval".to_owned();
    take_and_produce(&environment, &notice, std::slice::from_ref(&destination), 1);
    let gateway = GatewayDouble::queued();
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");

    let sent = gateway.sent();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    let json = serde_json::to_string(request).expect("the wire form");
    assert!(!json.contains("rm -rf"), "no command text in plaintext");
    assert!(
        !json.contains("kalareach-production"),
        "the collapse identifier reveals no project name"
    );
    assert_eq!(request.hints.alert, PushAlert::ApprovalWaiting);
    assert!(request.preview_is_well_formed());

    // And the device, which holds the key, can read it.
    let host_preview = environment
        .module
        .with(|producer| Ok(*producer.preview_public()))
        .expect("the host's preview key");
    let body = kr_delivery::preview::open_preview(
        &environment.device_preview,
        &host_preview,
        request.preview.as_ref().expect("a preview"),
        NOW + 1,
    )
    .expect("the destination opens its own preview");
    assert_eq!(
        body.summary,
        "approve: rm -rf /var/lib/kalareach-production"
    );
}

/// KR-REQ-16.11: previews disabled removes the recipient key and keeps the generic alert.
#[test]
fn a_destination_with_previews_disabled_still_gets_the_alert() {
    let environment = environment();
    let destination = push_destination(&environment, false);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::queued();
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    let sent = gateway.sent();
    assert!(!sent[0].preview.is_present());
    assert_eq!(sent[0].hints.alert, PushAlert::ApprovalWaiting);
}

/// KR-REQ-16.13: the payload bound is measured, and the excess moves to an encrypted object.
#[test]
fn a_preview_that_does_not_fit_is_not_sent_as_it_stands() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let produced = take_and_produce(
        &environment,
        &notice(1, &"x".repeat(1_400)),
        std::slice::from_ref(&destination),
        1,
    );
    assert_eq!(produced.admitted, 1);
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert!(
                record.payload_bytes < kr_protocol::push::MAX_PROVIDER_PAYLOAD_BYTES,
                "what is queued is inside the bound the gateway enforces"
            );
            let request: PushDeliveryRequest =
                serde_json::from_slice(record.content.as_ref().expect("a body"))
                    .expect("a request");
            let body = kr_delivery::preview::open_preview(
                &environment.device_preview,
                producer.preview_public(),
                request.preview.as_ref().expect("a preview"),
                NOW + 1,
            )
            .expect("the preview opens");
            assert_eq!(body.summary, "", "the detail moved");
            let detail = *body.detail_object.as_ref().expect("a reference");
            assert!(
                producer.journal().object(detail).expect("a read").is_some(),
                "and it is retained here, encrypted"
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12: a rejected token takes the destination out of service.
#[test]
fn a_rejected_token_disables_the_destination() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Decided(Box::new(PushDeliveryAck {
        decided_at_ms: TimestampMs::new(NOW),
        notification_id: NotificationId::new(uuid(7)),
        state: PushDeliveryState::TokenDisabled,
        suppression: Nullable::null(),
    }))]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .with(|producer| {
            let record = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the record");
            assert!(!record.enabled, "nothing more is sent to it");
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12 and section 23: an unknown outcome keeps what the receipt needs, and reading the
/// receipt resolves it without ever presenting new work.
#[test]
fn an_unknown_outcome_is_resolved_by_asking_what_became_of_it() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    let held_request = environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert!(
                record.content.is_none(),
                "and the request goes: the question carries the identifier, not the request"
            );
            assert!(record.dispatched);
            Ok(record.notification_id)
        })
        .expect("a read");

    // The automatic loop never touches it.
    assert_eq!(
        environment
            .module
            .run_due(
                &gateway,
                &gateway,
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(NOW + 60_000),
            )
            .expect("a pass"),
        0
    );

    // The status question does, and it is asked for rather than scheduled.
    let resolved = environment
        .module
        .resolve_unknown(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a reconciliation");
    assert_eq!(resolved, 1);
    assert_eq!(
        gateway.questions(),
        1,
        "the outcome was read rather than sent again"
    );
    environment
        .module
        .with(|producer| {
            let record = producer
                .journal()
                .delivery(held_request)
                .expect("a read")
                .expect("the record");
            assert_eq!(record.state, DeliveryState::Accepted);
            assert_eq!(record.content, None, "nothing needs to ask again");
            Ok(())
        })
        .expect("a read");
}

/// Section 24: reading a receipt presents the request again, so it is the one reconciliation that
/// could put content back on the wire. A record admitted under a generation privacy mode has ended
/// is never presented, whatever the fence says now.
#[test]
fn a_receipt_is_not_read_for_a_record_from_a_generation_that_has_ended() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    // Privacy mode ends the generation and lifts its fence again, which is the state a person who
    // turned privacy mode on and off leaves behind.
    environment
        .module
        .with(|producer| {
            producer.journal_mut().fence(1).expect("a fence");
            producer
                .journal_mut()
                .lift_fence(2)
                .expect("the fence lifts");
            Ok(())
        })
        .expect("a boundary");
    let resolved = environment
        .module
        .resolve_unknown(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a reconciliation");
    assert_eq!(resolved, 0);
    assert_eq!(
        gateway.questions(),
        0,
        "nothing from a generation that has ended is presented again"
    );
}

/// KR-REQ-16.13: a receipt carries the same answers a send does, so it carries the same
/// consequences. A token the provider rejected goes out of service whichever call learned of it,
/// and what the answer says was suppressed is recorded either way.
#[test]
fn a_receipt_that_reports_a_rejected_token_takes_the_destination_out_of_service() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![
        SendOutcome::Unknown {
            detail: "the connection was reset".to_owned(),
        },
        SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW + 120_000),
            notification_id: NotificationId::new(Uuid::NIL),
            state: PushDeliveryState::TokenDisabled,
            suppression: Nullable::null(),
        })),
    ]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .resolve_unknown(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a reconciliation");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::TokenDisabled);
            let configured = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the destination");
            assert!(
                !configured.enabled,
                "the token is out of service until a native registration proves receipt again"
            );
            Ok(())
        })
        .expect("a read");
}

/// Section 16 stops at expiry, and a renewal is a call that waits. A notification whose deadline
/// passed while the credential was being renewed is settled rather than presented.
#[test]
fn a_notification_that_expires_during_a_renewal_is_not_presented() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::queued();
    let readings = std::sync::atomic::AtomicUsize::new(0);
    // Three readings take the pass up to the renewal; the fourth is the one it takes after the
    // renewal has returned, and by then the notification has expired.
    let clock = || {
        if readings.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
            NOW
        } else {
            NOW + DEFAULT_NOTIFICATION_LIFETIME_MS + 1
        }
    };
    // A credential inside its renewal window, so the pass renews before it presents anything.
    let credentials = RenewingCredentials {
        held: credential(NOW + 60_000),
        renewed: credential(NOW + 30 * 24 * 60 * 60 * 1000),
    };
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &clock,
        )
        .expect("a pass");
    assert!(
        gateway.sent().is_empty(),
        "nothing is presented after the deadline it was admitted under"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Expired);
            assert!(!record.dispatched);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("renew")),
                "the record says which wait overtook it"
            );
            Ok(())
        })
        .expect("a read");
}

/// A receipt returning retrying preserves the content bytes and schedules receipt polling.
#[test]
fn an_answer_of_retrying_schedules_the_next_status_question() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![
        SendOutcome::Unknown {
            detail: "the connection was reset".to_owned(),
        },
        SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW),
            notification_id: NotificationId::new(uuid(7)),
            state: PushDeliveryState::Retrying,
            suppression: Nullable::null(),
        })),
        SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW),
            notification_id: NotificationId::new(uuid(7)),
            state: PushDeliveryState::Queued,
            suppression: Nullable::null(),
        })),
    ]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");

    let held_request = environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert!(record.content.is_none());
            Ok(record.notification_id)
        })
        .expect("a read");

    // The gateway answers that it is still retrying the provider.
    let resolved = environment
        .module
        .resolve_unknown(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 60_000),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a receipt pass");
    assert_eq!(resolved, 0, "retrying is not settled yet");
    assert_eq!(gateway.questions(), 1);

    environment
        .module
        .with(|producer| {
            let record = producer
                .journal()
                .delivery(held_request)
                .expect("a read")
                .expect("the record");
            assert_eq!(record.state, DeliveryState::Retrying);
            assert!(
                record.content.is_none(),
                "and nothing presentable is kept: the next question carries the identifier"
            );
            Ok(())
        })
        .expect("a read");

    // The next pass claims the scheduled question, and the gateway now answers queued.
    let attempted = environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(attempted, 1);
    assert_eq!(gateway.questions(), 2, "the receipt was polled again");

    environment
        .module
        .with(|producer| {
            let record = producer
                .journal()
                .delivery(held_request)
                .expect("a read")
                .expect("the record");
            assert_eq!(record.state, DeliveryState::Accepted);
            assert_eq!(record.content, None, "content removed after settlement");
            Ok(())
        })
        .expect("a read");
}

/// A status question is not put while the journal is privacy-fenced.
#[test]
fn a_status_question_is_refused_while_privacy_fenced() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");

    // Open privacy generation (fences outbox).
    environment
        .module
        .with(|producer| {
            use kr_worker::privacy::PrivacyMode;
            let mut mode = PrivacyMode::new();
            mode.open_generation(TimestampMs::new(NOW + 1));
            let mut outbox =
                kr_delivery::privacy::DeliveryOutbox::over(producer.journal_mut(), NOW + 1);
            mode.apply(&mut [&mut outbox], TimestampMs::new(NOW + 1));
            Ok(())
        })
        .expect("privacy pass");

    // The pass is refused while fenced, and nothing is asked of anyone.
    let resolved = environment
        .module
        .resolve_unknown(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 2),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a status pass");
    assert_eq!(resolved, 0);
    assert_eq!(
        gateway.questions(),
        0,
        "no receipt request sent while fenced"
    );
}

/// KR-REQ-16.12: section 16 stops at expiry, and a pass reads the clock again before each
/// dispatch rather than acting on the figure it started with.
#[test]
fn a_delivery_whose_expiry_arrives_during_the_pass_is_settled_without_sending() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "an approval is waiting");
    take_and_produce(&environment, &notice, std::slice::from_ref(&destination), 1);
    let gateway = GatewayDouble::queued();
    // The outbox is read while the notification is still worth delivering, and the pass reaches
    // the claim after its expiry: the clock it reads there is the one that decides.
    let attempted = environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &ticking(NOW, NOW + DEFAULT_NOTIFICATION_LIFETIME_MS + 1),
        )
        .expect("a pass");
    assert_eq!(attempted, 0, "nothing was attempted");
    assert!(
        gateway.sent().is_empty(),
        "an expired notification is settled rather than presented"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Expired);
            assert_eq!(record.content, None, "an expired record keeps no bytes");
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12 and section 23: an unknown outcome is recorded as unknown and never retried.
#[test]
fn an_unknown_outcome_is_recorded_and_left_alone() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset after the body was written".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert!(
                producer.journal().due(NOW, 10).expect("a read").is_empty(),
                "nothing picks it up again on its own"
            );
            Ok(())
        })
        .expect("a read");
    // A second pass sends nothing at all.
    assert_eq!(
        environment
            .module
            .run_due(
                &gateway,
                &gateway,
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(NOW + 60_000),
            )
            .expect("a pass"),
        0
    );
    assert_eq!(gateway.sent().len(), 1);
}

/// KR-REQ-16.12: a credential inside its renewal window is renewed rather than left to expire.
#[test]
fn a_credential_close_to_expiry_is_renewed_before_it_is_used() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    // Two days left, inside section 16's seven-day renewal window.
    let credentials = held(NOW + 2 * 24 * 60 * 60 * 1000);
    let renewal = Arc::new(UnreachableRenewal::default());
    credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &SilentStatus,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(
        renewal.asked(),
        vec![PushSenderRecordId::new(uuid(3))],
        "the host renews rather than delivering under a credential about to expire"
    );
}

/// KR-REQ-16.12: a 403 is renewed rather than retried.
#[test]
fn a_refused_credential_is_renewed_rather_than_presented_again() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Forbidden {
        detail: "FORBIDDEN".to_owned(),
    }]);
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let renewal = Arc::new(UnreachableRenewal::default());
    credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.sent().len(), 1, "it is not presented again at once");
    assert_eq!(renewal.asked().len(), 1);
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Retrying);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("renewed"))
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12: a notification the gateway is holding is asked about rather than presented as
/// new work, and what the next attempt is survives a restart because the journal holds it.
#[test]
fn a_notification_the_gateway_is_holding_is_asked_about_rather_than_sent_again() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Decided(Box::new(PushDeliveryAck {
        decided_at_ms: TimestampMs::new(NOW),
        notification_id: NotificationId::new(uuid(7)),
        state: PushDeliveryState::Retrying,
        suppression: Nullable::null(),
    }))]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.questions(), 0, "the first attempt is a delivery");

    // The module is opened again over the same journal, so nothing is remembered in memory.
    let reopened = DeliveryModule::open_at(
        &environment.path,
        kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
        kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
    )
    .expect("a delivery module");
    reopened
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(
        gateway.questions(),
        1,
        "the second attempt reads the decision the gateway already holds"
    );
    reopened
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.13: a status question that has to wait for a renewal is still a status question.
/// The renewal fails, the record keeps its question and stays due, and once a renewal succeeds
/// the question is asked and answered. Nothing is presented a second time, and the record never
/// needed its request to be asked about.
#[test]
fn a_status_question_that_waits_for_a_renewal_is_asked_once_the_renewal_succeeds() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    // The gateway takes the notification and is retrying the provider itself.
    let gateway = GatewayDouble::answering(vec![SendOutcome::Decided(Box::new(PushDeliveryAck {
        decided_at_ms: TimestampMs::new(NOW),
        notification_id: NotificationId::new(uuid(7)),
        state: PushDeliveryState::Retrying,
        suppression: Nullable::null(),
    }))]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.sent().len(), 1);

    // When the question is due the credential is inside its renewal window, and the first
    // renewal fails.
    let credentials = FlakyRenewal {
        held: credential(NOW + 60 * 60 * 1000),
        renewed: credential(NOW + 30 * 24 * 60 * 60 * 1000),
        failures_left: Mutex::new(1),
    };
    let first = NOW + 10 * 60 * 1000;
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(first),
        )
        .expect("a pass");
    assert_eq!(
        gateway.questions(),
        0,
        "nothing is asked under a credential owed a renewal"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Retrying);
            assert!(record.content.is_none(), "a question needs no request");
            assert!(
                record.detail.as_deref().is_some_and(
                    |detail| detail.contains("before this host asks what became of it")
                ),
                "it says what it is waiting for: {:?}",
                record.detail
            );
            assert_eq!(
                producer
                    .journal()
                    .due(first + 10 * 60 * 1000, 10)
                    .expect("a read")
                    .len(),
                1,
                "the question is still due"
            );
            Ok(())
        })
        .expect("a read");

    // The renewal succeeds on the next attempt, and the question is asked and answered.
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(first + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(gateway.questions(), 1);
    assert_eq!(
        gateway.sent().len(),
        1,
        "nothing was presented a second time"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            assert_eq!(producer.journal().outstanding().expect("a count"), 0);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12: a refused credential is renewed *before* anything is presented again, and a
/// renewal that has not happened stops the attempt rather than presenting the old bearer.
#[test]
fn a_delivery_is_not_presented_again_until_the_renewal_has_happened() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Forbidden {
        detail: "FORBIDDEN".to_owned(),
    }]);
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.sent().len(), 1);

    // The next attempt comes round, and this host still has no renewed credential.
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(
        gateway.sent().len(),
        1,
        "the credential the gateway refused is not presented again"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Retrying);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail
                        .contains("has to be renewed before this is presented again")),
                "it says what it is waiting for: {:?}",
                record.detail
            );
            assert!(!record.dispatched, "nothing left this host");
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.12: the burst is admitted, the rest collapse, and every request is retained.
#[test]
fn the_host_collapses_its_own_excess_and_keeps_every_request() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    for number in 1..=25u64 {
        take_and_produce(
            &environment,
            &notice(number, "an approval is waiting"),
            std::slice::from_ref(&destination),
            number,
        );
    }
    environment
        .module
        .with(|producer| {
            let records = producer.journal().deliveries().expect("a read");
            assert_eq!(records.len(), 25, "every request is retained");
            let collapsed = records
                .iter()
                .filter(|record| record.state == DeliveryState::Collapsed)
                .count();
            assert_eq!(collapsed, 4);
            let suppressed = records
                .iter()
                .filter(|record| record.suppression.is_some())
                .count();
            assert_eq!(
                suppressed, 5,
                "the update and the four that collapsed into it"
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-24.12: budgets, cursors and queued work survive a restart.
#[test]
fn the_journal_comes_back_with_its_work_and_its_account() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let path = environment.path.clone();
    // The directory outlives the module, because what is under test is reopening the file rather
    // than what a removed directory does.
    let directory = environment._directory;
    drop(environment.module);

    let reopened = DeliveryModule::open_at(
        &path,
        kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
        kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
    )
    .expect("a delivery module");
    reopened
        .with(|producer| {
            assert_eq!(producer.journal().due(NOW, 10).expect("a read").len(), 1);
            assert_eq!(producer.journal().deliveries().expect("a read").len(), 1);
            assert!(
                producer
                    .journal()
                    .budget(&DestinationId::new("phone").expect("an identifier"))
                    .expect("a read")
                    .is_some(),
                "the destination's spent allowance came back with it"
            );
            Ok(())
        })
        .expect("a read");
    drop(directory);
}

/// KR-REQ-24.12: a restart records an attempt that was on the wire as an unknown outcome.
#[test]
fn a_restart_records_what_was_in_flight_as_unknown_and_resumes_only_what_is_authorised() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    // An attempt that never came back: the claim says in flight and this host stops.
    claim_first(&environment, NOW);

    let reconciled = environment
        .module
        .reconcile(
            std::slice::from_ref(&destination),
            &Granted(BTreeSet::new()),
            &|_| true,
            NOW + 1_000,
        )
        .expect("a reconciliation");
    assert_eq!(reconciled, 1);
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-24.12: an authorisation that ended is revoked rather than resumed - and that is a
/// statement about queued work, not about an attempt that was already on the wire.
#[test]
fn a_restart_revokes_what_is_no_longer_authorised() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    environment
        .module
        .reconcile(
            std::slice::from_ref(&destination),
            &Granted(BTreeSet::new()),
            &|_| false,
            NOW + 1_000,
        )
        .expect("a reconciliation");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Revoked);
            assert!(!record.dispatched, "nothing had left this host");
            assert_eq!(record.content, None, "the bytes go with the revocation");
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-24.12: an attempt that was on the wire has an unknown outcome, and an authorisation
/// that has since ended does not turn it into a revocation. A revocation is not evidence about
/// delivery.
#[test]
fn an_interrupted_send_is_unknown_even_when_its_authority_ended() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    claim_first(&environment, NOW);
    environment
        .module
        .reconcile(
            std::slice::from_ref(&destination),
            &Granted(BTreeSet::new()),
            &|_| false,
            NOW + 1_000,
        )
        .expect("a reconciliation");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert!(record.dispatched, "it was on the wire");
            assert!(record.detail.as_deref().is_some_and(|detail| {
                detail.contains("what became of the attempt is still unknown")
            }));
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-25.23 and 19.06: an external message says its recipients can read it.
#[test]
fn an_external_message_never_claims_to_be_private() {
    let environment = environment();
    let destination = webhook(Idempotency::Supported {
        field: "Idempotency-Key".to_owned(),
    });
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "a command failed");
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(1).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Granted([session()].into_iter().collect()),
                    &[kr_delivery::external::ContentLine {
                        session_id: Some(session()),
                        produced_at_ms: Some(NOW - 1_000),
                        text: "the build failed".to_owned(),
                    }],
                    NOW,
                )
                .expect("a message");
            Ok(())
        })
        .expect("the producer");
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &Granted([session()].into_iter().collect()),
            &at(NOW),
        )
        .expect("a pass");
    let sent = external.sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].body.contains("does not make it private"));
    assert!(sent[0].body.contains("the build failed"));
}

/// KR-REQ-25.24: a destination with no idempotent identifier marks the uncertainty.
#[test]
fn a_destination_without_an_idempotent_identifier_is_not_sent_to_twice() {
    let environment = environment();
    let destination = webhook(Idempotency::Unsupported);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "a command failed");
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(1).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Granted([session()].into_iter().collect()),
                    &[],
                    NOW,
                )
                .expect("a message");
            Ok(())
        })
        .expect("the producer");
    let external = ExternalDouble::answering(vec![ExternalOutcome::Unknown {
        detail: "the connection was reset".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &Granted([session()].into_iter().collect()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::DuplicateUncertain);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("could deliver it twice"))
            );
            Ok(())
        })
        .expect("a read");
    assert_eq!(external.sent().len(), 1, "it is not sent again");
}

/// KR-REQ-18.08: an endpoint edited after admission is another recipient, and content admitted
/// for the first one does not reach it.
#[test]
fn a_destination_whose_endpoint_changed_after_admission_is_not_sent_to() {
    let environment = environment();
    let destination = webhook(Idempotency::Unsupported);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "a command failed");
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(1).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Granted([session()].into_iter().collect()),
                    &[],
                    NOW,
                )
                .expect("a message");
            Ok(())
        })
        .expect("the producer");
    // Somebody points the same configured destination at another address.
    let mut moved = destination.clone();
    moved.destination = Destination::External(ExternalDestination {
        kind: DestinationKind::Webhook,
        endpoint: "https://elsewhere.invalid/hook".to_owned(),
        idempotency: Idempotency::Unsupported,
    });
    environment.module.configure(&moved).expect("a destination");
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &Granted([session()].into_iter().collect()),
            &at(NOW),
        )
        .expect("a pass");
    assert!(
        external.sent().is_empty(),
        "nothing reaches an address the message was not admitted for"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Revoked);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("not the destination configured now"))
            );
            Ok(())
        })
        .expect("a read");
}

/// The claim is what admits a dispatch, so the destination it validated is the destination the
/// message goes to. A configuration edited while the pass is running reaches the next claim, which
/// refuses it; it never redirects the message this pass already claimed.
#[test]
fn a_pass_sends_to_the_destination_its_claim_validated() {
    let environment = environment();
    let destination = webhook(Idempotency::Unsupported);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "a command failed"),
        std::slice::from_ref(&destination),
        1,
    );
    let external = ExternalDouble::answering(Vec::new());
    let readings = std::sync::atomic::AtomicUsize::new(0);
    // The third reading is the one the pass takes after it has claimed the row and before it
    // sends, which is exactly the window an edit would have to land in.
    let clock = || {
        if readings.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 2 {
            let mut moved = webhook(Idempotency::Unsupported);
            moved.destination = Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://elsewhere.invalid/hook".to_owned(),
                idempotency: Idempotency::Unsupported,
            });
            environment.module.configure(&moved).expect("the edit");
        }
        NOW
    };
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &Granted(BTreeSet::new()),
            &clock,
        )
        .expect("a pass");
    assert_eq!(
        external.endpoints(),
        vec!["https://example.invalid/hook".to_owned()],
        "the message went where the claim said it may go"
    );
    assert!(
        readings.load(std::sync::atomic::Ordering::Relaxed) > 2,
        "the edit landed in the window it was aimed at"
    );
}

/// A rotation neither store will take changes neither of them: section 16 keeps one replaced key,
/// so a rotation while an earlier replacement still has notifications outstanding is refused, and
/// the device directory is left at the revision it held.
#[test]
fn a_rotation_the_delivery_journal_refuses_leaves_the_directory_alone() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let second = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a keypair")
        .public();
    environment
        .module
        .update_preview_key(
            &DestinationId::new("phone").expect("an identifier"),
            second,
            2,
            NOW,
        )
        .expect("the first rotation");
    let third = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a keypair")
        .public();
    let refusal = environment
        .module
        .update_preview_key(
            &DestinationId::new("phone").expect("an identifier"),
            third,
            3,
            NOW,
        )
        .expect_err("an overlapping rotation is refused");
    assert!(refusal.to_string().contains("overlapping rotation"));
    environment
        .module
        .with(|producer| {
            let push = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the destination");
            let keys = &push.as_push().expect("a push destination").preview_keys;
            assert_eq!(keys.current, second, "the refused key is not in service");
            assert_eq!(keys.revision, 2);
            Ok(())
        })
        .expect("a read");
}

/// Section 16 stops at expiry, and asking the recipient's authority is a question that waits. An
/// external message whose deadline passed during that question is settled rather than sent.
#[test]
fn an_external_message_that_expires_during_the_authority_lookup_is_not_sent() {
    let environment = environment();
    let destination = webhook(Idempotency::Unsupported);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "a command failed"),
        std::slice::from_ref(&destination),
        1,
    );
    /// A grant this host has to ask about, and the asking takes longer than the notification has.
    #[derive(Debug)]
    struct SlowAuthority(std::sync::atomic::AtomicBool);

    impl RecipientAuthority for SlowAuthority {
        fn scope_for(&self, _rule: &DeliveryRule) -> Option<RecipientScope> {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            // The same authority the message was admitted under: only the time has moved.
            Some(RecipientScope {
                viewer: ViewerScope::owner(),
                sessions: SessionSelector::These {
                    session_ids: CanonicalSet::new(),
                },
            })
        }
    }

    let authority = SlowAuthority(std::sync::atomic::AtomicBool::new(false));
    let clock = || {
        if authority.0.load(std::sync::atomic::Ordering::Relaxed) {
            NOW + DEFAULT_NOTIFICATION_LIFETIME_MS + 1
        } else {
            NOW
        }
    };
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &authority,
            &clock,
        )
        .expect("a pass");
    assert!(
        external.sent().is_empty(),
        "nothing leaves after the deadline it was admitted under"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Expired);
            assert!(!record.dispatched);
            Ok(())
        })
        .expect("a read");
}

/// Taking a rejected token out of service says one thing about the destination. A rotation that
/// landed while the gateway was answering is not undone by it.
#[test]
fn disabling_a_rejected_token_keeps_the_configuration_written_while_it_was_asked() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    /// A gateway that rejects the token, and a device that registers a new preview key while it
    /// is doing so.
    #[derive(Debug)]
    struct RotatingGateway<'a> {
        module: &'a DeliveryModule,
        rotated: NotificationPreviewKey,
    }

    impl PushSender for RotatingGateway<'_> {
        fn send(
            &self,
            _credential: &PushDeliveryCredential,
            request: &PushDeliveryRequest,
        ) -> SendOutcome {
            self.module
                .update_preview_key(
                    &DestinationId::new("phone").expect("an identifier"),
                    self.rotated,
                    2,
                    NOW,
                )
                .expect("the device registers a key while this call is out");
            SendOutcome::Decided(Box::new(PushDeliveryAck {
                decided_at_ms: TimestampMs::new(NOW),
                notification_id: request.notification_id,
                state: PushDeliveryState::TokenDisabled,
                suppression: Nullable::null(),
            }))
        }
    }

    /// It answers no status question: the test is about what a send does.
    impl DeliveryStatus for RotatingGateway<'_> {
        fn status(
            &self,
            _credential: &PushDeliveryCredential,
            _notification_id: NotificationId,
        ) -> StatusAnswer {
            StatusAnswer::Unanswered {
                detail: "this gateway answers sends only".to_owned(),
            }
        }
    }

    let rotated = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a keypair")
        .public();
    let gateway = RotatingGateway {
        module: &environment.module,
        rotated,
    };
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .with(|producer| {
            let configured = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the destination");
            assert!(!configured.enabled, "the rejected token is out of service");
            let push = configured.as_push().expect("a push destination");
            assert_eq!(
                push.preview_keys.current, rotated,
                "and the key the device registered while the gateway was answering stands"
            );
            assert_eq!(push.preview_keys.revision, 2);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-18.08 and section 19: the recipient's authority is asked again at dispatch, so a grant
/// revoked after the message was composed stops it.
#[test]
fn an_external_delivery_whose_grant_changed_after_admission_sends_nothing() {
    let environment = environment();
    let destination = webhook(Idempotency::Unsupported);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "a command failed");
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(1).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Granted([session()].into_iter().collect()),
                    &[],
                    NOW,
                )
                .expect("a message");
            Ok(())
        })
        .expect("the producer");
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &GatewayDouble::queued(),
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            // The grant no longer names that session.
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert!(external.sent().is_empty(), "the message does not leave");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Revoked);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("not the one this was admitted under"))
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.11: a preview key rotates through the paired channel and the old one is bounded.
#[test]
fn a_rotated_preview_key_keeps_the_old_one_only_while_notifications_are_outstanding() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let replacement = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    environment
        .module
        .update_preview_key(
            &DestinationId::new("phone").expect("an identifier"),
            *replacement.public(),
            2,
            NOW,
        )
        .expect("a rotation");
    environment
        .module
        .with(|producer| {
            let record = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the record");
            let push = record.as_push().expect("a push destination");
            assert_eq!(push.preview_keys.current, *replacement.public());
            assert_eq!(push.preview_keys.revision, 2);
            let previous = push
                .preview_keys
                .previous
                .as_ref()
                .expect("one previous key");
            assert_eq!(
                previous.retired_until_ms.get(),
                NOW + DEFAULT_NOTIFICATION_LIFETIME_MS,
                "kept exactly until the outstanding notification expires"
            );
            Ok(())
        })
        .expect("a read");

    // Past the expiry, nothing is kept.
    environment
        .module
        .with(|producer| {
            producer
                .journal_mut()
                .forget_expired_preview_keys(NOW + DEFAULT_NOTIFICATION_LIFETIME_MS)
                .expect("a pass");
            let record = producer
                .journal()
                .destination(&DestinationId::new("phone").expect("an identifier"))
                .expect("a read")
                .expect("the record");
            assert!(
                record
                    .as_push()
                    .expect("a push destination")
                    .preview_keys
                    .previous
                    .is_none()
            );
            Ok(())
        })
        .expect("a read");
}

#[test]
fn overlapping_rotation_is_refused_while_earlier_notifications_are_outstanding() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let key2 = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("key2");
    environment
        .module
        .update_preview_key(
            &DestinationId::new("phone").expect("an identifier"),
            *key2.public(),
            2,
            NOW,
        )
        .expect("first rotation succeeds");

    // Second rotation while earlier notifications are unexpired is refused
    let key3 = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("key3");
    let err = environment.module.update_preview_key(
        &DestinationId::new("phone").expect("an identifier"),
        *key3.public(),
        3,
        NOW + 1,
    );
    assert!(
        err.is_err(),
        "overlapping rotation must be refused while earlier notifications are unexpired"
    );

    // After earlier notifications expire, rotation succeeds
    environment
        .module
        .update_preview_key(
            &DestinationId::new("phone").expect("an identifier"),
            *key3.public(),
            3,
            NOW + DEFAULT_NOTIFICATION_LIFETIME_MS + 1,
        )
        .expect("rotation succeeds after earlier notifications expire");
}

/// KR-REQ-16.11: a replayed registration cannot put a retired key back into service.
#[test]
fn a_preview_key_revision_only_moves_forward() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let replacement = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    assert!(
        environment
            .module
            .update_preview_key(
                &DestinationId::new("phone").expect("an identifier"),
                *replacement.public(),
                1,
                NOW
            )
            .is_err(),
        "a revision that does not follow is a replay"
    );
}

/// KR-REQ-24.12: privacy mode fences the outbox with work in flight and reconciles before it
/// reports complete, and what has already left is shown rather than erased.
#[test]
fn privacy_mode_fences_the_outbox_with_work_in_flight() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    for number in 1..=3u64 {
        take_and_produce(
            &environment,
            &notice(number, "an approval is waiting"),
            std::slice::from_ref(&destination),
            number,
        );
    }
    // One is sent and accepted; one is on the wire; one is still waiting.
    let gateway = GatewayDouble::answering(vec![SendOutcome::Decided(Box::new(PushDeliveryAck {
        decided_at_ms: TimestampMs::new(NOW),
        notification_id: NotificationId::new(uuid(7)),
        state: PushDeliveryState::Queued,
        suppression: Nullable::null(),
    }))]);
    environment
        .module
        .with(|producer| {
            let selected = producer.journal().due(NOW, 1).expect("a read");
            let sent = selected[0].notification_id;
            assert!(matches!(
                producer.journal_mut().claim(sent, NOW).expect("a claim"),
                kr_delivery::journal::Claim::Taken(_)
            ));
            producer
                .journal_mut()
                .record_attempt(&kr_delivery::journal::Transition {
                    notification_id: sent,
                    attempt: 1,
                    state: DeliveryState::Accepted,
                    started_at_ms: TimestampMs::new(NOW),
                    settled_at_ms: Some(TimestampMs::new(NOW)),
                    next_attempt_at_ms: None,
                    next: kr_delivery::push::NextAction::None,
                    detail: Some("the provider accepted it for delivery".to_owned()),
                    suppression: None,
                    left_this_host: false,
                    reported_by_destination: false,
                })
                .expect("a transition");
            let selected = producer.journal().due(NOW, 1).expect("a read");
            assert!(matches!(
                producer
                    .journal_mut()
                    .claim(selected[0].notification_id, NOW)
                    .expect("a claim"),
                kr_delivery::journal::Claim::Taken(_)
            ));
            Ok(())
        })
        .expect("a write");
    let _ = gateway;

    environment
        .module
        .with(|producer| {
            use kr_worker::privacy::{Completion, PrivacyMode, PrivacySubsystem};
            let mut mode = PrivacyMode::new();
            mode.open_generation(TimestampMs::new(NOW + 1));
            let mut outbox =
                kr_delivery::privacy::DeliveryOutbox::over(producer.journal_mut(), NOW + 1);
            let enabling = mode.apply(&mut [&mut outbox], TimestampMs::new(NOW + 1));
            assert_eq!(enabling.in_flight(), 1, "the send on the wire is counted");
            assert!(matches!(
                PrivacyMode::reconcile(&[&outbox]),
                Completion::Reconciling { .. }
            ));
            let exported = outbox.exported();
            assert!(
                exported.iter().any(|exported| !exported.deletable),
                "what has already left is shown, and this host claims no recall"
            );
            assert!(!outbox.kept().is_empty(), "what is kept is named");
            Ok(())
        })
        .expect("a privacy pass");

    // And nothing more is offered to a sender.
    assert_eq!(
        environment
            .module
            .run_due(
                &GatewayDouble::queued(),
                &GatewayDouble::queued(),
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(NOW + 2)
            )
            .expect("a pass"),
        0
    );
}

/// KR-REQ-24.12: a result produced under an earlier generation is not published.
#[test]
fn a_result_from_before_the_privacy_boundary_is_refused() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    environment
        .module
        .with(|producer| {
            producer.journal_mut().fence(1).expect("a fence");
            assert!(producer.publish_under(0).is_err());
            assert!(producer.publish_under(1).is_ok());
            Ok(())
        })
        .expect("a check");
}

#[derive(Debug)]
struct PushTestSupervisor;

impl WorkerSupervisor for PushTestSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no worker".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

async fn start_controller() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_controller_in(&temp).await;
    (temp, controller)
}

/// Starts a daemon over an environment that may already hold what an earlier one left.
async fn start_controller_in(temp: &kr_ipc::testing::TempHost) -> Arc<Controller> {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(PushTestSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts")
}

fn dummy_grant(device_id: DeviceId) -> Grant {
    Grant {
        grant_id: GrantId::new(uuid(100)),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(uuid(101)),
        recipient_device_id: device_id,
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: CanonicalSet::new(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

/// A gateway that takes every notification it is given and holds no record of anything else,
/// which is enough to watch a daemon deliver on its own.
#[derive(Debug, Default)]
struct DeliveringGateway {
    delivered: Mutex<Vec<NotificationId>>,
    asked: Mutex<Vec<Asked>>,
    /// What it answers a status question with: no record, unless a test says otherwise.
    status: Option<PushDeliveryState>,
}

impl DeliveringGateway {
    /// A gateway still retrying the provider for every notification it is asked about.
    fn retrying() -> Self {
        Self {
            status: Some(PushDeliveryState::Retrying),
            ..Self::default()
        }
    }

    fn delivered(&self) -> Vec<NotificationId> {
        self.delivered
            .lock()
            .expect("the gateway is not poisoned")
            .clone()
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .expect("the gateway is not poisoned")
            .clone()
    }

    /// The notifications it was asked about, in the order the questions came.
    fn questions(&self) -> Vec<NotificationId> {
        self.asked()
            .into_iter()
            .filter(|asked| asked.url.ends_with("/api/push/deliver/status"))
            .map(|asked| question_about(&asked.body))
            .collect()
    }
}

/// The notification a status question asks about.
fn question_about(body: &[u8]) -> NotificationId {
    let question: serde_json::Value = serde_json::from_slice(body).expect("a JSON question");
    serde_json::from_value(question["notification_id"].clone()).expect("an identifier")
}

impl kr_client::services::ServiceHttp for DeliveringGateway {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        self.asked
            .lock()
            .expect("the gateway is not poisoned")
            .push(Asked {
                url: url.to_owned(),
                body: body.to_vec(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            });
        let answer = if url.ends_with("/api/push/deliver") {
            let request: PushDeliveryRequest =
                serde_json::from_slice(body).expect("a delivery request");
            self.delivered
                .lock()
                .expect("the gateway is not poisoned")
                .push(request.notification_id);
            serde_json::json!({
                "ok": true,
                "data": PushDeliveryAck {
                    decided_at_ms: kr_ipc::now_ms(),
                    notification_id: request.notification_id,
                    state: PushDeliveryState::Queued,
                    suppression: Nullable::null(),
                },
            })
        } else if let Some(state) = self.status {
            serde_json::json!({
                "ok": true,
                "data": PushDeliveryAck {
                    decided_at_ms: kr_ipc::now_ms(),
                    notification_id: question_about(body),
                    state,
                    suppression: Nullable::null(),
                },
            })
        } else {
            serde_json::json!({ "ok": true, "data": null })
        };
        Box::pin(async move {
            Ok(kr_client::services::ServiceHttpAnswer {
                status: 200,
                body: serde_json::to_vec(&answer).expect("an answer"),
            })
        })
    }
}

/// A delivery credential current at the host's own clock.
fn current_credential(now_ms: u64) -> PushDeliveryCredential {
    PushDeliveryCredential {
        issued_at_ms: TimestampMs::new(now_ms - 1_000),
        expires_at_ms: TimestampMs::new(now_ms + 29 * 24 * 60 * 60 * 1000),
        ..credential(0)
    }
}

/// A notice observed at the host's own clock, for a daemon whose passes read that clock.
fn current_notice(number: u64, now_ms: u64) -> Notice {
    Notice {
        observed_at_ms: TimestampMs::new(now_ms),
        expires_at_ms: TimestampMs::new(now_ms + DEFAULT_NOTIFICATION_LIFETIME_MS),
        ..notice(number, "an approval is waiting")
    }
}

/// Produces one notification for `destination` from a freshly taken event.
fn produce_now(
    module: &DeliveryModule,
    destination: &DestinationRecord,
    number: u64,
    now_ms: u64,
) -> NotificationId {
    let notice = current_notice(number, now_ms);
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
                    &Granted(BTreeSet::new()),
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

/// Waits, on the daemon's own clock, until one record reaches `state`.
async fn until_state(
    module: &DeliveryModule,
    notification_id: NotificationId,
    state: DeliveryState,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while state_of(module, notification_id) != state {
        assert!(
            std::time::Instant::now() < deadline,
            "{notification_id} never reached {state}; it is {}",
            state_of(module, notification_id)
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// KR-REQ-16.12: the daemon delivers on its own. Its start path starts the delivery runtime,
/// which claims nothing while no transport is attached and presents the notification once one
/// is, and nothing in this test runs a pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_delivers_a_notification_without_anything_calling_a_pass() {
    let (_temp, controller) = start_controller().await;
    let now = kr_ipc::now_ms().get();
    let preview_key = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let destination = DestinationRecord {
        id: DestinationId::new(DeviceId::new(uuid(10)).to_string()).expect("an identifier"),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*preview_key.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        rule: Some(DeliveryRule {
            name: "anything that wants a person".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(now),
    };
    controller
        .delivery()
        .configure(&destination)
        .expect("a destination");
    controller
        .delivery_runtime()
        .credentials()
        .hold(current_credential(now));
    let notification_id = produce_now(controller.delivery(), &destination, 1, now);

    // A pass runs every second. With no transport attached, none of them claims anything.
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    assert_eq!(
        state_of(controller.delivery(), notification_id),
        DeliveryState::Admitted,
        "a host with no transport spends no attempt"
    );

    let gateway = Arc::new(DeliveringGateway::default());
    assert!(controller.attach_delivery_transport(Arc::new(OneTransport(
        Arc::clone(&gateway) as Arc<dyn kr_client::services::ServiceHttp>
    ))));
    until_state(
        controller.delivery(),
        notification_id,
        DeliveryState::Accepted,
    )
    .await;
    assert_eq!(gateway.delivered(), vec![notification_id]);
    let delivery = gateway
        .asked()
        .into_iter()
        .find(|asked| asked.url.ends_with("/api/push/deliver"))
        .expect("the delivery request");
    assert_eq!(delivery.url, "https://reach.invalid/api/push/deliver");
    assert!(
        delivery
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("Bearer ")),
        "it is presented under the credential the gateway issued"
    );
    assert!(
        !controller.attach_delivery_transport(Arc::new(OneTransport(Arc::new(
            RecordingHttp::answering(Vec::new())
        )))),
        "the transport is attached once"
    );
}

/// KR-REQ-16.12, KR-REQ-24.12: the runtime's cadence is its constructor's. It recovers before its
/// first pass - an attempt a stopped host left on the wire becomes an outcome nobody knows and is
/// never presented again - and then drives the outbox on every tick and asks about the unknown
/// outcome instead of presenting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runtime_recovers_first_and_then_drives_the_outbox_on_its_own_cadence() {
    let directory = tempfile::tempdir().expect("a directory");
    let module = Arc::new(
        DeliveryModule::open_at(
            &directory.path().join("delivery.sqlite3"),
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a delivery module"),
    );
    let now = kr_ipc::now_ms().get();
    let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let destination = DestinationRecord {
        configured_at_ms: TimestampMs::new(now),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*device.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        ..webhook(Idempotency::Unsupported)
    };
    module.configure(&destination).expect("a destination");
    let interrupted = produce_now(&module, &destination, 1, now);
    let waiting = produce_now(&module, &destination, 2, now);
    // The host that stopped had the first on the wire.
    module
        .with(|producer| {
            assert!(matches!(
                producer
                    .journal_mut()
                    .claim(interrupted, now)
                    .expect("a claim"),
                kr_delivery::journal::Claim::Taken(_)
            ));
            Ok(())
        })
        .expect("a claim");

    let credentials = Arc::new(HeldCredentials::new());
    credentials.hold(current_credential(now));
    let runtime = kr_controller::push::runtime::DeliveryRuntime::new(
        Arc::clone(&module),
        credentials,
        Arc::new(Granted(BTreeSet::new())),
        Arc::new(kr_controller::push::sender::HostSigner::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        )),
        kr_controller::push::runtime::Cadence {
            pass: std::time::Duration::from_millis(20),
            questions: std::time::Duration::from_secs(60 * 60),
            ..kr_controller::push::runtime::Cadence::DEFAULT
        },
        tokio::runtime::Handle::current(),
    );
    runtime.start().await;
    assert_eq!(
        state_of(&module, interrupted),
        DeliveryState::OutcomeUnknown,
        "recovery ran before the runtime's first pass"
    );

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        state_of(&module, waiting),
        DeliveryState::Admitted,
        "ten passes and no transport: nothing was claimed"
    );

    let gateway = Arc::new(DeliveringGateway::default());
    assert!(runtime.attach_transport(Arc::new(OneTransport(
        Arc::clone(&gateway) as Arc<dyn kr_client::services::ServiceHttp>
    ))));
    until_state(&module, waiting, DeliveryState::Accepted).await;
    assert_eq!(
        gateway.delivered(),
        vec![waiting],
        "the interrupted notification is never presented again"
    );
    // The question follows the sends in the same pass.
    let questions = |gateway: &DeliveringGateway| -> Vec<serde_json::Value> {
        gateway
            .asked()
            .into_iter()
            .filter(|asked| asked.url.ends_with("/api/push/deliver/status"))
            .map(|asked| serde_json::from_slice(&asked.body).expect("a JSON question"))
            .collect()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while questions(&gateway).is_empty() {
        assert!(std::time::Instant::now() < deadline, "nothing was asked");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    // Long enough for several more passes, none of which may ask again inside the hour.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let questions = questions(&gateway);
    assert_eq!(
        questions,
        vec![serde_json::json!({ "notification_id": interrupted })],
        "it is asked about, once, on the first pass that could ask"
    );
    assert_eq!(
        state_of(&module, interrupted),
        DeliveryState::OutcomeUnknown,
        "a gateway that holds no record of it resolves nothing"
    );
}

#[tokio::test]
async fn device_preview_key_update_via_controller() {
    let (_temp, controller) = start_controller().await;
    let device_id = DeviceId::new(uuid(10));
    let actor_id = kr_transport::listener::device_principal(&device_id);

    // Commit device record into directory
    let initial_key = kr_crypto::keys::NotificationPreviewKeyPair::generate().unwrap();
    let record = DeviceRecord {
        device_id,
        endpoint_id: EndpointKey::from_bytes([1; 32]),
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: AuthorisationKey::from_bytes([2; 32]),
        device_name: DeviceName::new("phone").unwrap(),
        platform: DevicePlatform::Ios,
        grant: dummy_grant(device_id),
        paired_at_ms: TimestampMs::new(NOW),
        revoked_at_ms: None,
        expired_at_ms: None,
        committed_invitation_id: None,
        notification_preview: Some(*initial_key.public()),
    };
    controller.devices().commit(&record).expect("commit device");

    // Configure push destination in delivery module
    let destination_id = DestinationId::new(device_id.to_string()).unwrap();
    let push_dest = DestinationRecord {
        id: destination_id.clone(),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(20)),
            sender_record_id: PushSenderRecordId::new(uuid(30)),
            preview_keys: PreviewKeys::only(*initial_key.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        rule: Some(DeliveryRule {
            name: "test-rule".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(NOW),
    };
    controller
        .delivery()
        .configure(&push_dest)
        .expect("configure push destination");

    // Update preview key via controller.device_preview_key_update
    let new_key = kr_crypto::keys::NotificationPreviewKeyPair::generate().unwrap();
    let params = kr_protocol::sharing::DevicePreviewKeyUpdateParams {
        device_id,
        notification_preview: *new_key.public(),
        revision: DeviceKeyRevision::new(2),
    };
    let mutation = MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(uuid(99)),
        request_id: kr_protocol::ids::RequestId::new(1),
        method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(controller.paths().environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").unwrap(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).unwrap(),
    };

    let result_val = controller
        .device_preview_key_update(&actor_id, &mutation)
        .await
        .expect("update succeeds");
    let result: kr_protocol::sharing::DevicePreviewKeyUpdateResult = result_val.to_typed().unwrap();
    assert_eq!(result.device_id, device_id);
    assert_eq!(result.revision, DeviceKeyRevision::new(2));
    assert_eq!(result.notification_preview, *new_key.public());

    // Verify device record updated in DeviceDirectory
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.notification_preview, Some(*new_key.public()));
    assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(2));

    // Verify delivery module push destination preview_keys updated
    controller
        .delivery()
        .with(|producer| {
            let dest = producer
                .journal()
                .destination(&destination_id)
                .unwrap()
                .unwrap();
            let push = dest.as_push().unwrap();
            assert_eq!(push.preview_keys.current, *new_key.public());
            assert_eq!(push.preview_keys.revision, 2);
            Ok(())
        })
        .unwrap();

    // The same registration again is the one this host already holds: a device whose answer was
    // lost sends it again, and both stores say what they said the first time.
    let repeat_mutation = MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(uuid(99)),
        request_id: kr_protocol::ids::RequestId::new(2),
        method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(controller.paths().environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").unwrap(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).unwrap(),
    };
    let repeated: kr_protocol::sharing::DevicePreviewKeyUpdateResult = controller
        .device_preview_key_update(&actor_id, &repeat_mutation)
        .await
        .expect("a resubmission is answered rather than refused")
        .to_typed()
        .unwrap();
    assert_eq!(repeated.revision, DeviceKeyRevision::new(2));
    assert_eq!(repeated.notification_preview, *new_key.public());

    // A registration that does not follow the recorded one is refused, in both stores.
    let replaced = kr_crypto::keys::NotificationPreviewKeyPair::generate().unwrap();
    for behind in [1_u64, 2] {
        let stale_params = kr_protocol::sharing::DevicePreviewKeyUpdateParams {
            device_id,
            notification_preview: *replaced.public(),
            revision: DeviceKeyRevision::new(behind),
        };
        let stale_mutation = MutationRequest {
            action_id: kr_protocol::ids::ActionId::new(uuid(100)),
            request_id: kr_protocol::ids::RequestId::new(2),
            method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            grant_id: Nullable::null(),
            target: ActionTarget::environment(controller.paths().environment_id()),
            expected: ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").unwrap(),
            requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
            params: ParamsValue::from_typed(&stale_params).unwrap(),
        };
        assert!(
            controller
                .device_preview_key_update(&actor_id, &stale_mutation)
                .await
                .is_err(),
            "revision {behind} does not follow 2"
        );
    }
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.notification_preview,
        Some(*new_key.public()),
        "a refused registration leaves the recorded key alone"
    );

    // Verify another device cannot rotate
    let other_device_id = DeviceId::new(uuid(77));
    let forbidden_params = kr_protocol::sharing::DevicePreviewKeyUpdateParams {
        device_id: other_device_id,
        notification_preview: *new_key.public(),
        revision: DeviceKeyRevision::new(3),
    };
    let forbidden_mutation = MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(uuid(101)),
        request_id: kr_protocol::ids::RequestId::new(3),
        method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(controller.paths().environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").unwrap(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&forbidden_params).unwrap(),
    };
    assert!(
        controller
            .device_preview_key_update(&actor_id, &forbidden_mutation)
            .await
            .is_err()
    );

    // An actor this host cannot resolve to a paired device is not a paired device. A revocation
    // between the connection's admission and this write leaves exactly that, and the registration
    // it carries reaches neither store.
    let unresolved = kr_transport::listener::device_principal(&DeviceId::new(uuid(88)));
    let stolen = kr_crypto::keys::NotificationPreviewKeyPair::generate().unwrap();
    let stolen_params = kr_protocol::sharing::DevicePreviewKeyUpdateParams {
        device_id,
        notification_preview: *stolen.public(),
        revision: DeviceKeyRevision::new(9),
    };
    let stolen_mutation = MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(uuid(102)),
        request_id: kr_protocol::ids::RequestId::new(4),
        method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(controller.paths().environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").unwrap(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&stolen_params).unwrap(),
    };
    assert!(
        controller
            .device_preview_key_update(&unresolved, &stolen_mutation)
            .await
            .is_err(),
        "an unresolved actor may not register a key for a device it does not hold"
    );
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.notification_preview, Some(*new_key.public()));
    assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(2));
    controller
        .delivery()
        .with(|producer| {
            let destination = producer
                .journal()
                .destination(&destination_id)
                .unwrap()
                .unwrap();
            let push = destination.as_push().unwrap();
            assert_eq!(push.preview_keys.current, *new_key.public());
            assert_eq!(push.preview_keys.revision, 2);
            Ok(())
        })
        .unwrap();
}

#[test]
fn message_from_restores_withheld_metadata_and_rejects_invalid_timestamps() {
    let filter = kr_worker::history_filter::HistoryFilter::new(
        kr_worker::history_filter::ViewerScope::owner(),
    );
    let granted_sessions = SessionSelector::These {
        session_ids: [SessionId::new(uuid(1))].into_iter().collect(),
    };

    let line = kr_delivery::external::ContentLine {
        produced_at_ms: None, // Will cause NoProductionTime
        session_id: Some(SessionId::new(uuid(1))),
        text: "line without time".to_owned(),
    };

    let composed = kr_delivery::external::compose(
        DestinationKind::Telegram,
        PushAlert::WorkComplete,
        vec![line],
        &filter,
        &granted_sessions,
        Some("delivery-1".to_owned()),
    )
    .expect("compose succeeds");

    assert!(!composed.is_complete());
    assert_eq!(
        composed.withheld,
        vec![(kr_delivery::external::Withheld::NoProductionTime, 1)]
    );

    let json = kr_delivery::producer::message_json(&composed);
    let bytes = serde_json::to_vec(&json).expect("serialized");

    let restored =
        kr_controller::push::client::message_from(&bytes).expect("restored from serialized json");
    assert!(!restored.is_complete());
    assert_eq!(restored.withheld, composed.withheld);
    assert_eq!(
        restored.provenance.interval.from_ms,
        composed.provenance.interval.from_ms
    );
    assert_eq!(
        restored.provenance.interval.to_ms,
        composed.provenance.interval.to_ms
    );

    // Rejects invalid interval timestamps
    let mut invalid_json = json.clone();
    invalid_json["interval"]["from_ms"] = serde_json::json!("not_a_number");
    let invalid_bytes = serde_json::to_vec(&invalid_json).expect("serialized");
    assert!(kr_controller::push::client::message_from(&invalid_bytes).is_err());
}

/// The question that resolves an unknown outcome carries an identifier and no request, so it
/// cannot deliver the notification it is about. A question nobody answers resolves nothing, and
/// the record stays outstanding and listed rather than being settled by assumption.
#[test]
fn an_unknown_outcome_is_resolved_by_a_question_that_carries_no_notification() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset after the body was written".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");

    // Nobody answers. The record keeps its uncertainty, and nothing was presented to anyone.
    assert_eq!(
        environment
            .module
            .resolve_unknown(
                &SilentStatus,
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &at(NOW + 60_000),
                64,
                std::time::Duration::from_secs(60),
            )
            .expect("a pass"),
        0
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert!(
                record.content.is_none(),
                "the request goes with the settlement: what answers this question is the \
                 identifier, not the request again"
            );
            assert_eq!(producer.journal().outstanding().expect("a count"), 1);
            let exported = producer.journal().exported().expect("a read");
            assert_eq!(exported.len(), 1);
            assert_eq!(exported[0].notification_id, record.notification_id);
            assert_eq!(exported[0].destination_id, record.destination_id);
            Ok(())
        })
        .expect("a read");
    assert_eq!(
        gateway.sent().len(),
        1,
        "asking is not sending, whatever the answer"
    );

    // The gateway answers the next question, which comes once the unanswered one's wait is over,
    // and only then is the record resolved.
    let answering =
        GatewayDouble::answering(vec![SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW + 60_000),
            notification_id: NotificationId::new(uuid(0)),
            state: PushDeliveryState::Queued,
            suppression: Nullable::null(),
        }))]);
    assert_eq!(
        environment
            .module
            .resolve_unknown(
                &answering,
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &at(NOW + 60_000 + kr_delivery::push::QUESTION_BACKOFF_MS),
                64,
                std::time::Duration::from_secs(60),
            )
            .expect("a pass"),
        1
    );
    assert_eq!(
        answering.sent().len(),
        0,
        "and the route that answered it delivered nothing"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            assert_eq!(producer.journal().outstanding().expect("a count"), 0);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.13: the status route's answer is applied only to the notification that was asked
/// about. The question carries the identifier and nothing else; an answer about another
/// identifier, even one saying the token was rejected, resolves nothing and takes no destination
/// out of service; the answer about this notification resolves it.
#[test]
fn a_status_answer_about_another_notification_resolves_nothing() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Unknown {
        detail: "the connection was reset after the body was written".to_owned(),
    }]);
    environment
        .module
        .run_due(
            &gateway,
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    let notification_id = environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            Ok(record.notification_id)
        })
        .expect("a read");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let transport = Arc::new(RecordingHttp::answering(vec![
        (
            200,
            recorded(
                NotificationId::new(uuid(0x44)),
                PushDeliveryState::TokenDisabled,
            ),
        ),
        (200, recorded(notification_id, PushDeliveryState::Queued)),
    ]));
    let status = kr_controller::push::status::GatewayStatus::new(
        Arc::new(OneTransport(
            Arc::clone(&transport) as Arc<dyn kr_client::services::ServiceHttp>
        )),
        runtime.handle().clone(),
        kr_controller::push::status::StatusAllowance::UNKNOWN,
    );
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);

    assert_eq!(
        environment
            .module
            .resolve_unknown(
                &status,
                &credentials,
                &at(NOW + 60_000),
                64,
                std::time::Duration::from_secs(60)
            )
            .expect("a pass"),
        0,
        "an answer about another notification resolves nothing"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::OutcomeUnknown);
            assert_eq!(producer.journal().outstanding().expect("a count"), 1);
            assert!(
                producer
                    .journal()
                    .destination(&destination.id)
                    .expect("a read")
                    .expect("the destination")
                    .enabled,
                "and takes no destination out of service"
            );
            Ok(())
        })
        .expect("a read");

    assert_eq!(
        environment
            .module
            .resolve_unknown(
                &status,
                &credentials,
                &at(NOW + 60_000 + kr_delivery::push::QUESTION_BACKOFF_MS),
                64,
                std::time::Duration::from_secs(60)
            )
            .expect("a pass"),
        1,
        "the answer about this notification resolves it"
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            assert_eq!(producer.journal().outstanding().expect("a count"), 0);
            Ok(())
        })
        .expect("a read");

    let asked = transport.asked();
    assert_eq!(asked.len(), 2);
    for Asked { url, body, headers } in asked {
        assert_eq!(url, "https://reach.invalid/api/push/deliver/status");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("a JSON question"),
            serde_json::json!({ "notification_id": notification_id }),
            "the question carries the identifier and nothing else"
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == "authorization" && value.starts_with("Bearer ")),
            "it is asked under the delivery credential"
        );
    }
    assert_eq!(gateway.sent().len(), 1, "asking is not sending");
}

/// A composed message for the one webhook these tests send to.
fn webhook_message(delivery_id: Option<&str>) -> ExternalMessage {
    kr_delivery::external::compose(
        DestinationKind::Webhook,
        PushAlert::ApprovalWaiting,
        vec![kr_delivery::external::ContentLine {
            session_id: Some(session()),
            produced_at_ms: Some(NOW - 1_000),
            text: "an approval is waiting".to_owned(),
        }],
        &kr_worker::history_filter::HistoryFilter::new(ViewerScope::owner()),
        &SessionSelector::Any,
        delivery_id.map(str::to_owned),
    )
    .expect("a message")
}

fn external_of(record: &DestinationRecord) -> &ExternalDestination {
    record.as_external().expect("an external destination")
}

/// KR-REQ-25.23, KR-REQ-25.24, KR-REQ-19.06: a webhook message is the composed document, sent to
/// the address its owner configured, and it names the delivery by the identifier the destination
/// deduplicates by, under the header the destination named, and by nothing else.
#[test]
fn a_webhook_message_goes_to_its_endpoint_under_the_identifier_it_deduplicates_by() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let transport = Arc::new(RecordingHttp::answering(vec![
        (200, Vec::new()),
        (204, Vec::new()),
    ]));
    let sender = kr_controller::push::external::WebhookSender::new(
        Arc::new(OneTransport(
            Arc::clone(&transport) as Arc<dyn kr_client::services::ServiceHttp>
        )),
        runtime.handle().clone(),
    );
    let deduplicating = webhook(Idempotency::Supported {
        field: "Idempotency-Key".to_owned(),
    });
    let message = webhook_message(Some("delivery-1"));
    assert_eq!(
        sender.send(external_of(&deduplicating), &message),
        ExternalOutcome::Delivered
    );
    let plain = webhook(Idempotency::Unsupported);
    assert_eq!(
        sender.send(external_of(&plain), &webhook_message(None)),
        ExternalOutcome::Delivered
    );

    let asked = transport.asked();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[0].url, "https://example.invalid/hook");
    assert_eq!(
        asked[0].headers,
        vec![("idempotency-key".to_owned(), "delivery-1".to_owned())]
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&asked[0].body).expect("a JSON message"),
        kr_delivery::producer::message_json(&message),
        "what is sent is the document the journal holds"
    );
    assert!(
        String::from_utf8_lossy(&asked[0].body).contains("does not make it private"),
        "the message says its recipients can read it"
    );
    assert!(
        asked[1].headers.is_empty(),
        "a destination that deduplicates by nothing is told no identifier"
    );
}

/// KR-REQ-25.24: each answer from a webhook is read as what it says, and a failure is read by
/// whether anything could have arrived.
#[test]
fn a_webhook_answer_is_read_as_what_it_says() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let deduplicating = webhook(Idempotency::Supported {
        field: "Idempotency-Key".to_owned(),
    });
    let plain = webhook(Idempotency::Unsupported);
    /// One answer, the destination it came from, and what it has to be read as.
    type Case<'a> = (
        &'a DestinationRecord,
        Scripted,
        fn(&ExternalOutcome) -> bool,
    );
    let cases: Vec<Case<'_>> = vec![
        // A conflict is the receiver's own answer about its own records, not a confirmation that
        // it already had this delivery, even from a destination that deduplicates by identifier.
        (&deduplicating, Ok((409, Vec::new())), |outcome| {
            matches!(outcome, ExternalOutcome::Refused { .. })
        }),
        (&plain, Ok((409, Vec::new())), |outcome| {
            matches!(outcome, ExternalOutcome::Refused { .. })
        }),
        (&plain, Ok((429, Vec::new())), |outcome| {
            matches!(outcome, ExternalOutcome::NotDispatched { .. })
        }),
        (&plain, Ok((400, Vec::new())), |outcome| {
            matches!(outcome, ExternalOutcome::Refused { .. })
        }),
        (&plain, Ok((503, Vec::new())), |outcome| {
            matches!(outcome, ExternalOutcome::Unknown { .. })
        }),
        (
            &plain,
            Err(kr_protocol::error::ErrorCode::UpstreamUnavailable),
            |outcome| matches!(outcome, ExternalOutcome::NotDispatched { .. }),
        ),
        (
            &plain,
            Err(kr_protocol::error::ErrorCode::OutcomeUnknown),
            |outcome| matches!(outcome, ExternalOutcome::Unknown { .. }),
        ),
    ];
    for (destination, scripted, expected) in cases {
        let answer = format!("{scripted:?}");
        let sender = kr_controller::push::external::WebhookSender::new(
            Arc::new(OneTransport(Arc::new(RecordingHttp::scripted(vec![
                scripted,
            ])))),
            runtime.handle().clone(),
        );
        let outcome = sender.send(
            external_of(destination),
            &webhook_message(Some("delivery-1")),
        );
        assert!(expected(&outcome), "{answer} read as {outcome:?}");
    }
}

/// KR-REQ-25.23: a destination kind this host cannot deliver to is refused where it is configured,
/// and says why, rather than admitting content nothing will send; so is a webhook address the
/// managed transport would refuse.
#[test]
fn configuring_a_destination_this_host_cannot_reach_is_refused_with_the_reason() {
    let environment = environment();
    for kind in [
        DestinationKind::Slack,
        DestinationKind::Discord,
        DestinationKind::Telegram,
        DestinationKind::Email,
    ] {
        let mut destination = webhook(Idempotency::Unsupported);
        destination.destination = Destination::External(ExternalDestination {
            kind,
            ..external_of(&destination).clone()
        });
        let refused = environment
            .module
            .configure(&destination)
            .expect_err("a kind this host cannot deliver to");
        assert!(
            refused.to_string().contains("secret store"),
            "{kind}: {refused}"
        );
    }
    for endpoint in [
        "http://example.invalid/hook",
        "https://someone:secret@example.invalid/hook",
        "not an address",
    ] {
        let mut destination = webhook(Idempotency::Unsupported);
        destination.destination = Destination::External(ExternalDestination {
            endpoint: endpoint.to_owned(),
            ..external_of(&destination).clone()
        });
        assert!(
            environment.module.configure(&destination).is_err(),
            "{endpoint} is refused"
        );
    }
    environment
        .module
        .configure(&webhook(Idempotency::Unsupported))
        .expect("a webhook over https is configured");
    assert!(
        environment
            .module
            .with(|producer| Ok(producer.journal().destinations().expect("a read")))
            .expect("a read")
            .iter()
            .all(|record| record.destination.kind() == DestinationKind::Webhook),
        "nothing else was written"
    );
}

/// Renews every credential it is asked to, into a new bearer, and counts the renewals.
#[derive(Debug, Default)]
struct CountingRenewal {
    renewed: Mutex<u32>,
}

impl CredentialRenewal for CountingRenewal {
    fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential, String> {
        *self.renewed.lock().expect("the double is not poisoned") += 1;
        Ok(PushDeliveryCredential {
            secret: SecretBytes32::from_bytes([0xee; 32]),
            ..held.clone()
        })
    }
}

/// KR-REQ-16.13: a refused credential is renewed in the pass that was refused, and the attempt
/// after it presents the renewed bearer without renewing a second time.
#[test]
fn a_credential_renewed_after_a_refusal_is_presented_without_a_second_renewal() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "an approval is waiting"),
        std::slice::from_ref(&destination),
        1,
    );
    let gateway = GatewayDouble::answering(vec![SendOutcome::Forbidden {
        detail: "FORBIDDEN".to_owned(),
    }]);
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let renewal = Arc::new(CountingRenewal::default());
    credentials.attach_renewal(Arc::clone(&renewal) as Arc<dyn CredentialRenewal>);
    for at_ms in [NOW, NOW + 10 * 60 * 1000] {
        environment
            .module
            .run_due(
                &gateway,
                &gateway,
                &credentials,
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(at_ms),
            )
            .expect("a pass");
    }
    assert_eq!(
        gateway.sent().len(),
        2,
        "refused once, then presented again"
    );
    assert_eq!(
        *renewal.renewed.lock().expect("the double is not poisoned"),
        1,
        "the renewal made after the refusal is the one the next attempt uses"
    );
    assert_eq!(
        credentials
            .current(PushSenderRecordId::new(uuid(3)))
            .expect("a credential")
            .secret,
        SecretBytes32::from_bytes([0xee; 32])
    );
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Accepted);
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-25.23: a message for a kind this host holds no credential for is settled without an
/// adapter ever being called, and the record says why, even when the destination reached the
/// journal without passing through configuration.
#[test]
fn a_message_for_a_kind_this_host_cannot_send_is_settled_without_an_attempt() {
    let environment = environment();
    let mut slack = webhook(Idempotency::Unsupported);
    slack.destination = Destination::External(ExternalDestination {
        kind: DestinationKind::Slack,
        ..external_of(&slack).clone()
    });
    environment
        .module
        .with(|producer| {
            producer
                .journal_mut()
                .configure_destination(&slack)
                .expect("written straight into the journal");
            Ok(())
        })
        .expect("a destination");
    take_and_produce(
        &environment,
        &notice(1, "a command failed"),
        std::slice::from_ref(&slack),
        1,
    );
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &SilentStatus,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert!(external.sent().is_empty(), "no adapter was called");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Revoked);
            assert!(!record.dispatched);
            assert!(
                record
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("no credential")),
                "{:?}",
                record.detail
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-18.08, KR-REQ-19.06: an external message's authority is the grant its rule names,
/// intersected with this host's policy as it stands at dispatch. A policy that stops honouring the
/// grant after the message was admitted stops the message, and nothing reaches the webhook.
#[test]
fn a_policy_that_stops_honouring_the_grant_before_dispatch_stops_the_message() {
    let environment = environment();
    let host = DeviceId::new(uuid(1));
    let sharing =
        Arc::new(kr_controller::sharing::SharingService::in_memory(host).expect("a grant store"));
    let environment_id = kr_protocol::ids::EnvironmentId::new(uuid(70));
    sharing
        .grants()
        .issue(&kr_controller::grants::GrantRecord {
            grant: Grant {
                grant_id: GrantId::new(uuid(71)),
                issuer_device_id: host,
                actions: [kr_protocol::rights::ActionRight::SessionView]
                    .into_iter()
                    .collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::some(TimestampMs::new(NOW - 60_000)),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                ..dummy_grant(DeviceId::new(uuid(72)))
            },
            session_id: None,
            issued_at_ms: NOW - 1_000,
            activated_at_ms: Some(NOW - 500),
            revoked_at_ms: None,
            revoked_by_parent: None,
        })
        .expect("the grant is written");
    let policy = Arc::new(Mutex::new(kr_controller::grants::HostPolicy::personal(
        AuthorityRevision::new(1),
    )));
    let recipients = kr_controller::push::authority::GrantedRecipients::at(
        Arc::clone(&sharing),
        Arc::clone(&policy),
        environment_id,
        || NOW,
    );
    let destination = DestinationRecord {
        rule: Some(DeliveryRule {
            name: "on a failed command".to_owned(),
            grant_id: Some(GrantId::new(uuid(71))),
        }),
        ..webhook(Idempotency::Unsupported)
    };
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let notice = notice(1, "a command failed");
    environment
        .module
        .with(|producer| {
            let taken = notice.taken(1).expect("an event record");
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            let produced = producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &recipients,
                    &[kr_delivery::external::ContentLine {
                        session_id: Some(session()),
                        produced_at_ms: Some(NOW - 1_000),
                        text: "a command failed".to_owned(),
                    }],
                    NOW,
                )
                .expect("a decision");
            assert_eq!(
                produced.admitted, 1,
                "admitted under the grant as it stood: {produced:?}"
            );
            Ok(())
        })
        .expect("produced");

    // The host becomes exclusively organisation-managed before the pass: personal authority stops
    // with the organisation's.
    policy
        .lock()
        .expect("the policy is not poisoned")
        .set_exclusively_managed(true);
    let external = ExternalDouble::answering(Vec::new());
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &SilentStatus,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &external,
            &recipients,
            &at(NOW),
        )
        .expect("a pass");
    assert!(external.sent().is_empty(), "nothing reached the webhook");
    environment
        .module
        .with(|producer| {
            let record = producer.journal().deliveries().expect("a read").remove(0);
            assert_eq!(record.state, DeliveryState::Revoked);
            assert!(!record.dispatched);
            Ok(())
        })
        .expect("a read");
}

/// Answers one notification's status question with its receipt, holds nothing for any other, and
/// records the order it was asked in.
#[derive(Debug)]
struct OneReceipt {
    answers: NotificationId,
    asked: Mutex<Vec<NotificationId>>,
}

impl DeliveryStatus for OneReceipt {
    fn status(
        &self,
        _credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> StatusAnswer {
        self.asked
            .lock()
            .expect("the double is not poisoned")
            .push(notification_id);
        if notification_id == self.answers {
            StatusAnswer::Recorded(Box::new(PushDeliveryAck {
                decided_at_ms: TimestampMs::new(NOW),
                notification_id,
                state: PushDeliveryState::Queued,
                suppression: Nullable::null(),
            }))
        } else {
            StatusAnswer::NoRecord {
                detail: "the gateway holds nothing under that identifier".to_owned(),
            }
        }
    }
}

/// KR-REQ-24.12: a backlog of older outcomes the gateway holds nothing for does not keep a newer
/// one from being asked. Each question that finds nothing pushes its own record's next turn back,
/// so a batch of one reaches the newest record on the third sweep, and every record is asked once.
#[test]
fn an_older_backlog_the_gateway_holds_nothing_for_does_not_hold_back_a_newer_question() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let produced: Vec<NotificationId> = (1..=3)
        .map(|number| {
            produce_now(
                &environment.module,
                &destination,
                number,
                NOW + number * 1_000,
            )
        })
        .collect();
    let unknown = || SendOutcome::Unknown {
        detail: "the connection was reset after the body was written".to_owned(),
    };
    environment
        .module
        .run_due(
            &GatewayDouble::answering(vec![unknown(), unknown(), unknown()]),
            &SilentStatus,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10_000),
        )
        .expect("a pass");
    let status = OneReceipt {
        answers: produced[2],
        asked: Mutex::new(Vec::new()),
    };
    let mut resolved = 0;
    for _ in 0..3 {
        resolved += environment
            .module
            .resolve_unknown(
                &status,
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &at(NOW + 20_000),
                1,
                std::time::Duration::from_secs(60),
            )
            .expect("a sweep");
    }
    assert_eq!(resolved, 1, "the newest was reached and resolved");
    assert_eq!(
        *status.asked.lock().expect("the double is not poisoned"),
        produced,
        "oldest first, and each asked once"
    );
    assert_eq!(
        state_of(&environment.module, produced[2]),
        DeliveryState::Accepted
    );
    for older in &produced[..2] {
        assert_eq!(
            state_of(&environment.module, *older),
            DeliveryState::OutcomeUnknown,
            "a gateway that holds nothing resolves nothing"
        );
    }
}

/// KR-REQ-16.12, KR-REQ-24.12: recovery finishes every event a stopped host took and never
/// produced from, page after page, before the runtime's first pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_finishes_every_page_of_pending_events() {
    let directory = tempfile::tempdir().expect("a directory");
    let module = Arc::new(
        DeliveryModule::open_at(
            &directory.path().join("delivery.sqlite3"),
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a delivery module"),
    );
    let now = kr_ipc::now_ms().get();
    let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let destination = DestinationRecord {
        configured_at_ms: TimestampMs::new(now),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*device.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        ..webhook(Idempotency::Unsupported)
    };
    module.configure(&destination).expect("a destination");
    // A page longer than one recovery pass takes, taken and then left: the host stopped.
    let pages = kr_delivery::producer::MAX_PENDING_PER_PAGE as u64 + 1;
    module
        .with(|producer| {
            let taken: Vec<_> = (1..=pages)
                .map(|number| {
                    current_notice(number, now)
                        .taken(number)
                        .expect("an event record")
                })
                .collect();
            producer
                .take(EventSource::Attention, "session-1", &taken, pages, now)
                .expect("a page");
            assert_eq!(producer.journal().pending_count().expect("a count"), pages);
            Ok(())
        })
        .expect("taken");

    let runtime = kr_controller::push::runtime::DeliveryRuntime::new(
        Arc::clone(&module),
        Arc::new(HeldCredentials::new()),
        Arc::new(Granted(BTreeSet::new())),
        Arc::new(kr_controller::push::sender::HostSigner::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        )),
        kr_controller::push::runtime::Cadence {
            pass: std::time::Duration::from_millis(20),
            questions: std::time::Duration::from_secs(60 * 60),
            ..kr_controller::push::runtime::Cadence::DEFAULT
        },
        tokio::runtime::Handle::current(),
    );
    runtime.start().await;
    assert!(runtime.is_recovered());
    module
        .with(|producer| {
            assert_eq!(
                producer.journal().pending_count().expect("a count"),
                0,
                "every page was finished"
            );
            assert_eq!(
                producer.journal().deliveries().expect("a read").len() as u64,
                pages,
                "one notification for every event, admitted or collapsed"
            );
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-24.12: a recovery that fails is not treated as done. Nothing is delivered while it
/// cannot finish, and it is tried again until it does, before the first pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_that_fails_is_tried_again_before_anything_is_delivered() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("delivery.sqlite3");
    let module = Arc::new(
        DeliveryModule::open_at(
            &path,
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a delivery module"),
    );
    let now = kr_ipc::now_ms().get();
    let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let destination = DestinationRecord {
        configured_at_ms: TimestampMs::new(now),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*device.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        ..webhook(Idempotency::Unsupported)
    };
    module.configure(&destination).expect("a destination");
    let interrupted = produce_now(&module, &destination, 1, now);
    let waiting = produce_now(&module, &destination, 2, now);
    module
        .with(|producer| {
            assert!(matches!(
                producer
                    .journal_mut()
                    .claim(interrupted, now)
                    .expect("a claim"),
                kr_delivery::journal::Claim::Taken(_)
            ));
            Ok(())
        })
        .expect("a claim");

    // Another writer holds the journal while the daemon starts, which is a store this host cannot
    // write for now rather than one that is gone.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let path = path.clone();
        move || {
            let connection = rusqlite::Connection::open(&path).expect("a connection");
            connection
                .execute_batch("BEGIN IMMEDIATE;")
                .expect("the write lock");
            held_tx.send(()).expect("the test is waiting");
            released.recv().expect("the test releases it");
            connection
                .execute_batch("ROLLBACK;")
                .expect("the lock is released");
        }
    });
    held_rx.recv().expect("the lock is held");

    let credentials = Arc::new(HeldCredentials::new());
    credentials.hold(current_credential(now));
    let runtime = kr_controller::push::runtime::DeliveryRuntime::new(
        Arc::clone(&module),
        credentials,
        Arc::new(Granted(BTreeSet::new())),
        Arc::new(kr_controller::push::sender::HostSigner::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        )),
        kr_controller::push::runtime::Cadence {
            pass: std::time::Duration::from_millis(20),
            questions: std::time::Duration::from_secs(60 * 60),
            ..kr_controller::push::runtime::Cadence::DEFAULT
        },
        tokio::runtime::Handle::current(),
    );
    let gateway = Arc::new(DeliveringGateway::default());
    assert!(runtime.attach_transport(Arc::new(OneTransport(
        Arc::clone(&gateway) as Arc<dyn kr_client::services::ServiceHttp>
    ))));
    runtime.start().await;
    assert!(
        !runtime.is_recovered(),
        "the first recovery could not write"
    );
    assert_eq!(state_of(&module, interrupted), DeliveryState::InFlight);
    assert!(
        gateway.delivered().is_empty(),
        "nothing is delivered before what the last daemon left is in order"
    );

    release.send(()).expect("the holder is waiting");
    holder.join().expect("the holder");
    until_state(&module, interrupted, DeliveryState::OutcomeUnknown).await;
    // The record is written inside recovery, a moment before the runtime records that recovery
    // finished.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !runtime.is_recovered() {
        assert!(
            std::time::Instant::now() < deadline,
            "recovery never finished"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    until_state(&module, waiting, DeliveryState::Accepted).await;
    assert_eq!(
        gateway.delivered(),
        vec![waiting],
        "the interrupted notification is never presented again"
    );
}

/// A paired device with a preview key at revision 1, configured as a push destination.
fn paired_with_preview_key(
    controller: &Controller,
    device_id: DeviceId,
) -> (DestinationId, kr_crypto::keys::NotificationPreviewKeyPair) {
    let initial = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    controller
        .devices()
        .commit(&DeviceRecord {
            device_id,
            endpoint_id: EndpointKey::from_bytes([1; 32]),
            device_key_revision: DeviceKeyRevision::new(1),
            authorisation: AuthorisationKey::from_bytes([2; 32]),
            device_name: DeviceName::new("phone").expect("a name"),
            platform: DevicePlatform::Ios,
            grant: dummy_grant(device_id),
            paired_at_ms: TimestampMs::new(NOW),
            revoked_at_ms: None,
            expired_at_ms: None,
            committed_invitation_id: None,
            notification_preview: Some(*initial.public()),
        })
        .expect("a device record");
    let destination_id = DestinationId::new(device_id.to_string()).expect("an identifier");
    controller
        .delivery()
        .configure(&DestinationRecord {
            id: destination_id.clone(),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(uuid(20)),
                sender_record_id: PushSenderRecordId::new(uuid(30)),
                preview_keys: PreviewKeys::only(*initial.public(), 1),
                previews_enabled: true,
                mailbox_key: None,
            })),
            rule: Some(DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(NOW),
        })
        .expect("a destination");
    (destination_id, initial)
}

/// One key update, as a paired device sends it.
fn key_update(
    controller: &Controller,
    action: u8,
    device_id: DeviceId,
    key: NotificationPreviewKey,
    revision: u64,
) -> MutationRequest {
    MutationRequest {
        action_id: kr_protocol::ids::ActionId::new(uuid(action)),
        request_id: kr_protocol::ids::RequestId::new(u64::from(action)),
        method: kr_protocol::method::Method::DevicePreviewKeyUpdate.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        grant_id: Nullable::null(),
        target: ActionTarget::environment(controller.paths().environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1").expect("a window"),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&kr_protocol::sharing::DevicePreviewKeyUpdateParams {
            device_id,
            notification_preview: key,
            revision: DeviceKeyRevision::new(revision),
        })
        .expect("params"),
    }
}

/// KR-REQ-16.11: a key update's result is retained with its action. A device whose answer was
/// lost repeats the action after a later rotation and is told what it was told the first time,
/// while a new action carrying the old revision is still refused and neither store moves back.
#[tokio::test]
async fn a_repeated_key_update_is_answered_with_the_result_it_first_had() {
    let (_temp, controller) = start_controller().await;
    let device_id = DeviceId::new(uuid(10));
    let actor_id = kr_transport::listener::device_principal(&device_id);
    let (destination_id, _) = paired_with_preview_key(&controller, device_id);
    let second = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let third = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let result = |value: ParamsValue| -> kr_protocol::sharing::DevicePreviewKeyUpdateResult {
        value.to_typed().expect("a result")
    };

    let first_answer = result(
        controller
            .preview_key_update_action(
                &actor_id,
                &key_update(&controller, 99, device_id, *second.public(), 2),
            )
            .await
            .expect("revision 2 is recorded"),
    );
    assert_eq!(first_answer.revision, DeviceKeyRevision::new(2));
    controller
        .preview_key_update_action(
            &actor_id,
            &key_update(&controller, 100, device_id, *third.public(), 3),
        )
        .await
        .expect("revision 3 is recorded");

    // The answer to the revision-2 action was lost, and the device asks again with it.
    let repeated = result(
        controller
            .preview_key_update_action(
                &actor_id,
                &key_update(&controller, 99, device_id, *second.public(), 2),
            )
            .await
            .expect("a repeat is answered from its retained result, not refused as stale"),
    );
    assert_eq!(repeated, first_answer);
    assert!(
        controller
            .preview_key_update_action(
                &actor_id,
                &key_update(&controller, 101, device_id, *second.public(), 2),
            )
            .await
            .is_err(),
        "a new action with the old revision is refused"
    );
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .expect("a read")
        .expect("the record");
    assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(3));
    assert_eq!(stored.notification_preview, Some(*third.public()));
    controller
        .delivery()
        .with(|producer| {
            let destination = producer
                .journal()
                .destination(&destination_id)
                .expect("a read")
                .expect("the destination");
            let push = destination.as_push().expect("a push destination");
            assert_eq!(push.preview_keys.revision, 3);
            assert_eq!(push.preview_keys.current, *third.public());
            Ok(())
        })
        .expect("a read");
}

/// KR-REQ-16.11: a key update that stopped between its two stores is finished when the daemon
/// next starts. The delivery journal took the registration first, so the device directory is
/// brought up to it, whether or not the device ever asks again.
#[tokio::test]
async fn a_key_update_that_stopped_between_its_stores_is_finished_at_the_next_start() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_controller_in(&temp).await;
    let device_id = DeviceId::new(uuid(10));
    let (destination_id, initial) = paired_with_preview_key(&controller, device_id);
    let rotated = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    // The journal's half of the update, and then the host stops.
    controller
        .delivery()
        .update_preview_key(&destination_id, *rotated.public(), 2, NOW)
        .expect("the journal takes it");
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .expect("a read")
        .expect("the record");
    assert_eq!(stored.notification_preview, Some(*initial.public()));
    drop(controller);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let controller = start_controller_in(&temp).await;
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .expect("a read")
        .expect("the record");
    assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(2));
    assert_eq!(
        stored.notification_preview,
        Some(*rotated.public()),
        "the directory now holds what the journal took first"
    );
}

/// KR-REQ-16.11: a directory this host cannot write for the moment is a recovery that failed and
/// says so, not one that finished; once the directory can be written, the same recovery brings it
/// up to the journal. The start path returns that failure rather than starting past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preview_key_recovery_that_cannot_write_the_directory_says_so_and_can_be_repeated() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_controller_in(&temp).await;
    let device_id = DeviceId::new(uuid(10));
    let (destination_id, _) = paired_with_preview_key(&controller, device_id);
    let rotated = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    controller
        .delivery()
        .update_preview_key(&destination_id, *rotated.public(), 2, NOW)
        .expect("the journal takes it");

    // Another writer holds the registry, which is where the device directory lives.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let registry = temp.environment().registry_database();
    let holder = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(&registry).expect("a connection");
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("the write lock");
        held_tx.send(()).expect("the test is waiting");
        released.recv().expect("the test releases it");
        connection
            .execute_batch("ROLLBACK;")
            .expect("the lock is released");
    });
    held_rx.recv().expect("the lock is held");
    let waiting = Arc::clone(&controller);
    let refused = tokio::task::spawn_blocking(move || waiting.recover_preview_keys())
        .await
        .expect("the recovery ran");
    assert!(
        refused.is_err(),
        "a directory it could not write is a failure"
    );
    release.send(()).expect("the holder is waiting");
    holder.join().expect("the holder");

    assert_eq!(
        controller
            .recover_preview_keys()
            .expect("the directory can be written now"),
        1
    );
    let stored = controller
        .devices()
        .record_for_device(device_id)
        .expect("a read")
        .expect("the record");
    assert_eq!(stored.device_key_revision, DeviceKeyRevision::new(2));
    assert_eq!(stored.notification_preview, Some(*rotated.public()));
}

fn attempts_of(module: &DeliveryModule, notification_id: NotificationId) -> u64 {
    module
        .with(|producer| {
            Ok(producer
                .journal()
                .delivery(notification_id)
                .expect("a read")
                .expect("the record")
                .attempts)
        })
        .expect("a read")
}

/// The gateway's answer that it holds a notification and is retrying the provider for it.
fn gateway_retrying() -> SendOutcome {
    SendOutcome::Decided(Box::new(PushDeliveryAck {
        decided_at_ms: TimestampMs::new(NOW),
        notification_id: NotificationId::new(uuid(0)),
        state: PushDeliveryState::Retrying,
        suppression: Nullable::null(),
    }))
}

fn connection_reset() -> SendOutcome {
    SendOutcome::Unknown {
        detail: "the connection was reset after the body was written".to_owned(),
    }
}

/// Two status adapters over one gateway, each with its own share, the way the runtime builds them
/// for its two loops: `(receipts, unknown)`.
fn status_shares(
    gateway: &Arc<DeliveringGateway>,
    runtime: &tokio::runtime::Runtime,
    receipts: kr_controller::push::status::StatusAllowance,
    unknown: kr_controller::push::status::StatusAllowance,
) -> (
    kr_controller::push::status::GatewayStatus,
    kr_controller::push::status::GatewayStatus,
) {
    let transport = || -> Arc<dyn kr_controller::push::transport::DeliveryTransports> {
        Arc::new(OneTransport(
            Arc::clone(gateway) as Arc<dyn kr_client::services::ServiceHttp>
        ))
    };
    (
        kr_controller::push::status::GatewayStatus::new(
            transport(),
            runtime.handle().clone(),
            receipts,
        ),
        kr_controller::push::status::GatewayStatus::new(
            transport(),
            runtime.handle().clone(),
            unknown,
        ),
    )
}

/// Produces `numbers` for the phone, and delivers them with the gateway answering each in turn:
/// `retrying` of them are held and retried by the gateway, the rest go out on connections that are
/// reset. Returns the two groups.
fn held_and_unknown(
    environment: &Environment,
    destination: &DestinationRecord,
    retrying: u64,
    unknown: u64,
    now_ms: u64,
) -> (Vec<NotificationId>, Vec<NotificationId>) {
    let produced: Vec<NotificationId> = (1..=retrying + unknown)
        .map(|number| produce_now(&environment.module, destination, number, now_ms + number))
        .collect();
    let answers = (0..retrying)
        .map(|_| gateway_retrying())
        .chain((0..unknown).map(|_| connection_reset()))
        .collect();
    environment
        .module
        .run_due(
            &GatewayDouble::answering(answers),
            &SilentStatus,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(now_ms + 100),
        )
        .expect("a pass");
    let (held_by_the_gateway, nobody_knows) = produced.split_at(retrying as usize);
    for id in held_by_the_gateway {
        assert_eq!(state_of(&environment.module, *id), DeliveryState::Retrying);
    }
    for id in nobody_knows {
        assert_eq!(
            state_of(&environment.module, *id),
            DeliveryState::OutcomeUnknown
        );
    }
    (held_by_the_gateway.to_vec(), nobody_knows.to_vec())
}

/// KR-REQ-24.12: the pass and the sweep ask within shares of their own. While the gateway retries
/// the provider, a pass that has spent its share asks nothing more, spends no attempt on a question
/// it leaves and still sends; the sweep asks from its own share all the same, a record it could
/// not ask about keeps its turn, and each share comes back as it refills.
#[test]
fn a_pass_and_a_sweep_each_ask_within_their_own_share_while_the_gateway_retries() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let (retrying, unknown) = held_and_unknown(&environment, &destination, 5, 2, NOW);
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let external = ExternalDouble::answering(Vec::new());
    let authority = Granted(BTreeSet::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let gateway = Arc::new(DeliveringGateway::retrying());
    let (receipts, sweep) = status_shares(
        &gateway,
        &runtime,
        kr_controller::push::status::StatusAllowance {
            burst: 3,
            per_hour: 1,
        },
        kr_controller::push::status::StatusAllowance {
            burst: 1,
            per_hour: 1,
        },
    );
    let sender = GatewayDouble::queued();

    // Every question about a notification the gateway holds is due, and a new one arrives. The
    // pass sends it and asks three questions, which is its whole share.
    let first = NOW + 100 + 2 * kr_delivery::push::BASE_BACKOFF_MS;
    let fresh = produce_now(&environment.module, &destination, 8, first);
    assert_eq!(
        environment
            .module
            .run_due(
                &sender,
                &receipts,
                &credentials,
                &external,
                &authority,
                &at(first)
            )
            .expect("a pass"),
        4,
        "the send and three questions"
    );
    let polled = gateway.questions();
    assert_eq!(polled.len(), 3);
    assert!(polled.iter().all(|id| retrying.contains(id)));

    // The sweep asks from its own share, which the pass could not spend.
    assert_eq!(
        environment
            .module
            .resolve_unknown(
                &sweep,
                &credentials,
                &at(first),
                64,
                std::time::Duration::from_secs(60),
            )
            .expect("a sweep"),
        0
    );
    let questions = gateway.questions();
    assert_eq!(questions.len(), 4, "one more, from the sweep's own share");
    assert_eq!(questions[3], unknown[0]);
    let unknown_due = |at: u64| -> Vec<NotificationId> {
        environment
            .module
            .with(|producer| {
                Ok(producer
                    .journal()
                    .unknown_due(at, 10)
                    .expect("a read")
                    .into_iter()
                    .map(|record| record.notification_id)
                    .collect())
            })
            .expect("a read")
    };
    assert_eq!(
        unknown_due(first),
        vec![unknown[1]],
        "the record it could not ask about keeps its turn"
    );

    // Every question falls due again inside the hour, and neither share has refilled. Nothing is
    // asked, no attempt is spent, and a new notification is sent all the same.
    let second = first + 5 * 60 * 1000;
    let waiting: Vec<NotificationId> = retrying
        .iter()
        .copied()
        .chain(std::iter::once(unknown[0]))
        .collect();
    let attempts_before: Vec<u64> = waiting
        .iter()
        .map(|id| attempts_of(&environment.module, *id))
        .collect();
    let newer = produce_now(&environment.module, &destination, 9, second);
    assert_eq!(
        environment
            .module
            .run_due(
                &sender,
                &receipts,
                &credentials,
                &external,
                &authority,
                &at(second)
            )
            .expect("a pass"),
        1,
        "only the send"
    );
    assert_eq!(gateway.questions().len(), 4);
    assert_eq!(
        sender
            .sent()
            .iter()
            .map(|request| request.notification_id)
            .collect::<Vec<_>>(),
        vec![fresh, newer]
    );
    assert_eq!(
        waiting
            .iter()
            .map(|id| attempts_of(&environment.module, *id))
            .collect::<Vec<_>>(),
        attempts_before,
        "a question not asked spends no attempt"
    );
    let still_due: BTreeSet<NotificationId> = environment
        .module
        .with(|producer| {
            Ok(producer
                .journal()
                .due(second, 10)
                .expect("a read")
                .into_iter()
                .map(|due| due.notification_id)
                .collect())
        })
        .expect("a read");
    assert_eq!(
        still_due,
        waiting.iter().copied().collect::<BTreeSet<_>>(),
        "and each keeps its place in the outbox"
    );
    for id in &waiting {
        assert_eq!(state_of(&environment.module, *id), DeliveryState::Retrying);
    }

    // An hour after the burst each share has one question again, and the record the sweep could
    // not reach is the one it asks about.
    let later = first + 60 * 60 * 1000;
    environment
        .module
        .resolve_unknown(
            &sweep,
            &credentials,
            &at(later),
            64,
            std::time::Duration::from_secs(60),
        )
        .expect("a sweep");
    let questions = gateway.questions();
    assert_eq!(questions.len(), 5);
    assert_eq!(questions[4], unknown[1]);
}

/// KR-REQ-24.12: a pass that finds more status questions due than its share covers, every second
/// for several refill periods, never takes the sweep's share. The sweep asks about every outcome
/// nobody knows while the pass goes on using all of its own.
#[test]
fn the_sweep_is_asked_while_passes_use_their_whole_share() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    environment
        .module
        .configure(&destination)
        .expect("a destination");
    let (retrying, unknown) = held_and_unknown(&environment, &destination, 12, 3, NOW);
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let external = ExternalDouble::answering(Vec::new());
    let authority = Granted(BTreeSet::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let gateway = Arc::new(DeliveringGateway::retrying());
    // A question a minute for each, so five minutes are five refill periods.
    let share = kr_controller::push::status::StatusAllowance {
        burst: 1,
        per_hour: 60,
    };
    let (receipts, sweep) = status_shares(&gateway, &runtime, share, share);
    let sender = GatewayDouble::queued();

    let start = NOW + 100 + 2 * kr_delivery::push::BASE_BACKOFF_MS;
    for second in 0..5 * 60 {
        let now = start + second * 1_000;
        environment
            .module
            .run_due(
                &sender,
                &receipts,
                &credentials,
                &external,
                &authority,
                &at(now),
            )
            .expect("a pass");
        if second % 60 == 30 {
            environment
                .module
                .resolve_unknown(
                    &sweep,
                    &credentials,
                    &at(now),
                    64,
                    std::time::Duration::from_secs(60),
                )
                .expect("a sweep");
        }
    }
    let questions = gateway.questions();
    let polls = questions.iter().filter(|id| retrying.contains(id)).count();
    assert_eq!(polls, 5, "the pass used its whole share, once a minute");
    for nobody_knows in &unknown {
        assert!(
            questions.contains(nobody_knows),
            "{nobody_knows} was asked about: {questions:?}"
        );
    }
    assert_eq!(
        questions.len(),
        8,
        "five from the pass's share and three from the sweep's"
    );
}

/// KR-REQ-24.12: a status question has places of its own in a pass. A question that fell due first
/// is asked however many sends are due after it, pass after pass.
#[test]
fn an_older_status_question_is_asked_however_many_sends_are_due() {
    let environment = environment();
    let destination = push_destination(&environment, true);
    let hook = webhook(Idempotency::Supported {
        field: "Idempotency-Key".to_owned(),
    });
    for configured in [&destination, &hook] {
        environment
            .module
            .configure(configured)
            .expect("a destination");
    }
    let (retrying, _) = held_and_unknown(&environment, &destination, 1, 0, NOW);
    let gateway = GatewayDouble::queued();
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let external = ExternalDouble::answering(Vec::new());
    let authority = Granted(BTreeSet::new());
    let mut number = 100;
    for pass in 0..3_u64 {
        let now = NOW + 10_000 + pass * 1_000;
        // More sends due than one pass takes, every time.
        for _ in 0..kr_controller::push::MAX_PASS + 8 {
            number += 1;
            let notice = current_notice(number, now);
            environment
                .module
                .with(|producer| {
                    let taken = notice.taken(number).expect("an event record");
                    producer
                        .take(EventSource::Attention, "session-1", &[taken], number, now)
                        .expect("a page");
                    producer
                        .produce(&notice, std::slice::from_ref(&hook), &authority, &[], now)
                        .expect("a decision");
                    Ok(())
                })
                .expect("produced");
        }
        environment
            .module
            .run_due(
                &gateway,
                &gateway,
                &credentials,
                &external,
                &authority,
                &at(now),
            )
            .expect("a pass");
        assert_eq!(
            gateway.questions(),
            1,
            "the question was asked in the first pass and answered"
        );
    }
    assert_eq!(
        state_of(&environment.module, retrying[0]),
        DeliveryState::Accepted
    );
    assert_eq!(
        external.sent().len(),
        3 * kr_controller::push::MAX_PASS,
        "and every pass sent all it takes"
    );
}

/// KR-REQ-24.12: in the daemon the pass loop and the question loop run at once, and both find
/// questions due while the gateway retries the provider. Each asks within its own share: the pass
/// its three and the sweep its one, and a notification produced meanwhile is delivered all the
/// same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_loops_ask_within_their_own_shares_while_the_gateway_retries() {
    let directory = tempfile::tempdir().expect("a directory");
    let module = Arc::new(
        DeliveryModule::open_at(
            &directory.path().join("delivery.sqlite3"),
            kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a delivery module"),
    );
    let now = kr_ipc::now_ms().get();
    let earlier = now - 10 * 60 * 1000;
    let device = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    let destination = DestinationRecord {
        configured_at_ms: TimestampMs::new(earlier),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*device.public(), 1),
            previews_enabled: true,
            mailbox_key: None,
        })),
        ..webhook(Idempotency::Unsupported)
    };
    module.configure(&destination).expect("a destination");
    // Ten minutes ago the gateway took three that it is still retrying the provider for, and two
    // more went out on connections that were reset.
    let produced: Vec<NotificationId> = (1..=5)
        .map(|number| produce_now(&module, &destination, number, earlier + number))
        .collect();
    let (retrying, unknown) = produced.split_at(3);
    let credentials = Arc::new(HeldCredentials::new());
    credentials.hold(current_credential(now));
    module
        .run_due(
            &GatewayDouble::answering(vec![
                gateway_retrying(),
                gateway_retrying(),
                gateway_retrying(),
                connection_reset(),
                connection_reset(),
            ]),
            &SilentStatus,
            credentials.as_ref(),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(earlier + 100),
        )
        .expect("a pass");

    let runtime = kr_controller::push::runtime::DeliveryRuntime::new(
        Arc::clone(&module),
        credentials,
        Arc::new(Granted(BTreeSet::new())),
        Arc::new(kr_controller::push::sender::HostSigner::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        )),
        kr_controller::push::runtime::Cadence {
            pass: std::time::Duration::from_millis(20),
            questions: std::time::Duration::from_millis(20),
            receipts: kr_controller::push::status::StatusAllowance {
                burst: 3,
                per_hour: 1,
            },
            unknown: kr_controller::push::status::StatusAllowance {
                burst: 1,
                per_hour: 1,
            },
        },
        tokio::runtime::Handle::current(),
    );
    runtime.start().await;
    let gateway = Arc::new(DeliveringGateway::retrying());
    assert!(runtime.attach_transport(Arc::new(OneTransport(
        Arc::clone(&gateway) as Arc<dyn kr_client::services::ServiceHttp>
    ))));
    let fresh = produce_now(&module, &destination, 6, kr_ipc::now_ms().get());
    until_state(&module, fresh, DeliveryState::Accepted).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while gateway.questions().len() < 4 {
        assert!(
            std::time::Instant::now() < deadline,
            "the shares were not used: {:?}",
            gateway.questions()
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    // Dozens more passes and sweeps, each of which finds a question due and may not ask it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let questions = gateway.questions();
    assert_eq!(
        questions.len(),
        4,
        "both bursts and nothing more inside the hour: {questions:?}"
    );
    let asked: BTreeSet<NotificationId> = questions.iter().copied().collect();
    assert!(
        retrying.iter().all(|id| asked.contains(id)),
        "the pass asked about everything the gateway holds: {questions:?}"
    );
    assert_eq!(
        unknown.iter().filter(|id| asked.contains(id)).count(),
        1,
        "and the sweep about one unknown outcome, from its own share: {questions:?}"
    );
    assert_eq!(gateway.delivered(), vec![fresh], "the send went ahead");
}
