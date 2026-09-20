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

use kr_controller::push::{DeliveryModule, credentials::HeldCredentials};
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
use kr_delivery::producer::{DEFAULT_NOTIFICATION_LIFETIME_MS, Notice, RecipientAuthority};
use kr_delivery::push::{PushSender, SendOutcome, SenderCredentials};
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
#[derive(Debug)]
struct GatewayDouble {
    answers: Mutex<Vec<SendOutcome>>,
    sent: Mutex<Vec<PushDeliveryRequest>>,
    receipts: Mutex<u64>,
}

impl GatewayDouble {
    fn answering(answers: Vec<SendOutcome>) -> Self {
        Self {
            answers: Mutex::new(answers),
            sent: Mutex::new(Vec::new()),
            receipts: Mutex::new(0),
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
        answers.remove(0)
    }

    fn sent(&self) -> Vec<PushDeliveryRequest> {
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }

    /// How many times a receipt was read rather than a delivery presented as new work.
    fn receipts(&self) -> u64 {
        *self.receipts.lock().expect("the double is not poisoned")
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

    fn receipt(
        &self,
        _credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        *self.receipts.lock().expect("the double is not poisoned") += 1;
        self.next(request)
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
        _sender_record_id: PushSenderRecordId,
    ) -> Result<PushDeliveryCredential, kr_delivery::DeliveryError> {
        Ok(self.renewed.clone())
    }
}

/// Every grant the tests need, and no more.
#[derive(Debug)]
struct Granted(BTreeSet<SessionId>);

impl RecipientAuthority for Granted {
    fn scope_for(&self, _rule: &DeliveryRule) -> Option<(ViewerScope, BTreeSet<SessionId>)> {
        Some((ViewerScope::owner(), self.0.clone()))
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
fn an_unknown_outcome_is_resolved_by_reading_the_receipt() {
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
                record.content.is_some(),
                "the request the receipt has to present is kept"
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
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(NOW + 60_000),
            )
            .expect("a pass"),
        0
    );

    // The receipt does, and it is asked for rather than scheduled.
    let resolved = environment
        .module
        .read_receipts(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
        )
        .expect("a reconciliation");
    assert_eq!(resolved, 1);
    assert_eq!(
        gateway.receipts(),
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
        .read_receipts(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
        )
        .expect("a reconciliation");
    assert_eq!(resolved, 0);
    assert_eq!(
        gateway.receipts(),
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
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    environment
        .module
        .read_receipts(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 120_000),
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
fn a_receipt_answering_retrying_keeps_content_and_schedules_next_receipt_poll() {
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
            assert!(record.content.is_some());
            Ok(record.notification_id)
        })
        .expect("a read");

    // Reading the receipt returns retrying from gateway.
    let resolved = environment
        .module
        .read_receipts(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 60_000),
        )
        .expect("a receipt pass");
    assert_eq!(resolved, 0, "retrying is not settled yet");
    assert_eq!(gateway.receipts(), 1);

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
                record.content.is_some(),
                "recovery data is kept while still retrying"
            );
            Ok(())
        })
        .expect("a read");

    // Next pass claims the due receipt poll and gateway now answers Queued.
    let attempted = environment
        .module
        .run_due(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(attempted, 1);
    assert_eq!(gateway.receipts(), 2, "the receipt was polled again");

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

/// Reading receipts is refused while the journal is privacy-fenced.
#[test]
fn reading_receipts_is_refused_while_privacy_fenced() {
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

    // Reading receipts while fenced is refused without making requests.
    let resolved = environment
        .module
        .read_receipts(
            &gateway,
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &at(NOW + 2),
        )
        .expect("read receipts");
    assert_eq!(resolved, 0);
    assert_eq!(
        gateway.receipts(),
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
    environment
        .module
        .run_due(
            &GatewayDouble::queued(),
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(
        credentials.renewals_requested(),
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
    environment
        .module
        .run_due(
            &gateway,
            &credentials,
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.sent().len(), 1, "it is not presented again at once");
    assert_eq!(credentials.renewals_requested().len(), 1);
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
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("a pass");
    assert_eq!(gateway.receipts(), 0, "the first attempt is a delivery");

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
            &held(NOW + 30 * 24 * 60 * 60 * 1000),
            &ExternalDouble::answering(Vec::new()),
            &Granted(BTreeSet::new()),
            &at(NOW + 10 * 60 * 1000),
        )
        .expect("a pass");
    assert_eq!(
        gateway.receipts(),
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
        fn scope_for(&self, _rule: &DeliveryRule) -> Option<(ViewerScope, BTreeSet<SessionId>)> {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            Some((ViewerScope::owner(), BTreeSet::new()))
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

        fn receipt(
            &self,
            credential: &PushDeliveryCredential,
            request: &PushDeliveryRequest,
        ) -> SendOutcome {
            self.send(credential, request)
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
                    keep_content: false,
                    left_this_host: false,
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
                &held(NOW + 30 * 24 * 60 * 60 * 1000),
                &ExternalDouble::answering(Vec::new()),
                &Granted(BTreeSet::new()),
                &at(NOW + 2),
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

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

async fn start_controller() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
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
    .expect("the daemon starts");
    (temp, controller)
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

#[tokio::test]
async fn controller_startup_constructs_delivery_module_and_runs_pass() {
    let (_temp, controller) = start_controller().await;
    let delivery = controller.delivery();

    let device_id = DeviceId::new(uuid(10));
    let destination_id = DestinationId::new(device_id.to_string()).unwrap();
    let preview_key = kr_crypto::keys::NotificationPreviewKeyPair::generate().unwrap();
    let destination = DestinationRecord {
        id: destination_id.clone(),
        destination: Destination::Push(Box::new(PushDestination {
            installation_id: InstallationId::new(uuid(2)),
            sender_record_id: PushSenderRecordId::new(uuid(3)),
            preview_keys: PreviewKeys::only(*preview_key.public(), 1),
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
    delivery
        .configure(&destination)
        .expect("configure destination");

    let notice = notice(1, "waiting for an approval");
    let taken = notice.taken(1).expect("an event record");
    delivery
        .with(|producer| {
            producer
                .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Granted(BTreeSet::new()),
                    &[],
                    NOW,
                )
                .expect("a decision");
            Ok(())
        })
        .expect("produced");

    let gateway = GatewayDouble::queued();
    let credentials = held(NOW + 30 * 24 * 60 * 60 * 1000);
    let external = ExternalDouble::answering(Vec::new());

    let attempted = delivery
        .run_due(
            &gateway,
            &credentials,
            &external,
            &Granted(BTreeSet::new()),
            &at(NOW),
        )
        .expect("run due");
    assert_eq!(attempted, 1);
    assert_eq!(gateway.sent.lock().unwrap().len(), 1);
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
    let mut granted_sessions = BTreeSet::new();
    granted_sessions.insert(SessionId::new(uuid(1)));

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
