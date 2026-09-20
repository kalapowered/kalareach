//! The host's side of notification delivery, end to end against a gateway double.
//!
//! Nothing here reaches a real gateway, a real provider or a real external destination. Section 16
//! is about what a host does before and after one of those answers, and a double is what makes
//! each answer reachable: a provider that queued it, one that refused the token, one that has not
//! answered at all.
//!
//! The rows these tests close are named in each test's own comment.

use std::collections::BTreeSet;
use std::sync::Mutex;

use kr_controller::push::{DeliveryModule, credentials::HeldCredentials};
use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
    ExternalDestination, Idempotency, PreviewKeys, PushDestination,
};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, ExternalSender};
use kr_delivery::journal::{DeliveryState, EventSource};
use kr_delivery::producer::{DEFAULT_NOTIFICATION_LIFETIME_MS, Notice, RecipientAuthority};
use kr_delivery::push::{PushSender, SendOutcome};
use kr_protocol::ids::{InstallationId, NotificationId, PushSenderRecordId, SessionId};
use kr_protocol::push::{
    PushAlert, PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushDeliveryState,
    PushUrgency,
};
use kr_protocol::scalars::{Nullable, SecretBytes32, TimestampMs, Uuid};
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
}

impl ExternalDouble {
    fn answering(answers: Vec<ExternalOutcome>) -> Self {
        Self {
            answers: Mutex::new(answers),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<ExternalMessage> {
        self.sent
            .lock()
            .expect("the double is not poisoned")
            .clone()
    }
}

impl ExternalSender for ExternalDouble {
    fn send(
        &self,
        _destination: &ExternalDestination,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
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
