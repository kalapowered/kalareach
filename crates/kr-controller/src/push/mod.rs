//! The host's side of notification delivery.
//!
//! `kr-delivery` is the producer and the store. This module is where it meets the rest of the
//! daemon: the environment's delivery journal lives in the daemon's own state directory, the
//! outbox is driven on the daemon's cadence, and the one seam that opens a socket is here rather
//! than in a crate that otherwise touches nothing outside its own file.
//!
//! | Part | What it owns |
//! | --- | --- |
//! | [`DeliveryModule`] | The journal, the producer, and the pass that drives the outbox |
//! | [`client`] | The HTTP client that speaks the deployed gateway's API |
//! | [`credentials`] | The bearer this host delivers under, and renewing it |
//!
//! # What this daemon serves, and what it calls
//!
//! The four `push.*` methods are `ServiceClient` methods: a caller makes them **to** a gateway.
//! Two of them are the installation's - registering a token and issuing a sender authorisation -
//! and reach the gateway from the phone. Two are this host's, `push.sender.renew` and
//! `push.sender.revoke`, signed with the host key under D-018's `ServiceRequestSignature`; they
//! are in [`credentials`].
//!
//! The one method this daemon *serves* is `device.preview_key.update`, which a paired device calls
//! over its authenticated channel to register or rotate the notification-preview key section 16
//! gives it. That is [`DeliveryModule::update_preview_key`].

use std::path::Path;
use std::sync::Mutex;

use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationRecord, PreviewKeys, PushDestination,
};
use kr_delivery::external::ExternalSender;
use kr_delivery::journal::{DeliveryJournal, DeliveryState, DueDelivery, Transition};
use kr_delivery::preview;
use kr_delivery::producer::{Producer, RecipientAuthority};
use kr_delivery::push::{NextAction, PushSender, SenderCredentials};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::method::Method;
use kr_protocol::push::PushDeliveryRequest;
use kr_protocol::scalars::{NotificationPreviewKey, TimestampMs};

use crate::error::{ControllerError, Result};

pub mod client;
pub mod credentials;

/// The file the environment's delivery journal lives in.
pub const DELIVERY_JOURNAL: &str = "delivery.sqlite3";

/// How many deliveries one pass takes out of the outbox.
pub const MAX_PASS: usize = 32;

/// The delivery service for one environment.
#[derive(Debug)]
pub struct DeliveryModule {
    producer: Mutex<Producer>,
}

impl DeliveryModule {
    /// Opens the environment's delivery journal beside the daemon's other state.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] when the journal cannot be opened.
    pub fn open(
        paths: &EnvironmentPaths,
        preview_key: kr_crypto::keys::NotificationPreviewKeyPair,
        mailbox_key: kr_crypto::keys::StoredEnvelopeKeyPair,
    ) -> Result<Self> {
        Self::open_at(
            &paths.state_dir().join(DELIVERY_JOURNAL),
            preview_key,
            mailbox_key,
        )
    }

    /// Opens the delivery journal at one path.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] when the journal cannot be opened.
    pub fn open_at(
        path: &Path,
        preview_key: kr_crypto::keys::NotificationPreviewKeyPair,
        mailbox_key: kr_crypto::keys::StoredEnvelopeKeyPair,
    ) -> Result<Self> {
        let journal = DeliveryJournal::open(path).map_err(unavailable)?;
        let producer = Producer::new(journal, preview_key, mailbox_key).map_err(unavailable)?;
        Ok(Self {
            producer: Mutex::new(producer),
        })
    }

    /// Returns true when this module serves `method`.
    #[must_use]
    pub const fn serves(method: Method) -> bool {
        matches!(method, Method::DevicePreviewKeyUpdate)
    }

    /// Runs one caller against the producer.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when another task left the lock poisoned.
    pub fn with<T>(&self, run: impl FnOnce(&mut Producer) -> Result<T>) -> Result<T> {
        let mut producer = self.producer.lock().map_err(|_| ControllerError::Storage {
            operation: "use the delivery journal",
            detail: "another task left its lock poisoned".to_owned(),
        })?;
        run(&mut producer)
    }

    /// Records or rotates one paired device's notification-preview key.
    ///
    /// Section 16, paragraph 5: the key is registered through the paired device's authenticated
    /// channel, carries a purpose and a revision, and is used for preview envelopes only. The
    /// caller has already authenticated the device; what this does is record the key against the
    /// destination and bound what rotation leaves behind.
    ///
    /// A revision that is not ahead of the one recorded is refused: a replay of an older
    /// registration would otherwise put a retired key back into service.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the revision does not move forward, and
    /// [`ControllerError::Unavailable`] when the journal cannot be written.
    pub fn update_preview_key(
        &self,
        destination_id: &DestinationId,
        key: NotificationPreviewKey,
        revision: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.with(|producer| {
            let journal = producer.journal_mut();
            journal
                .forget_expired_preview_keys(now_ms)
                .map_err(unavailable)?;
            let mut record = journal
                .destination(destination_id)
                .map_err(unavailable)?
                .ok_or_else(|| {
                    ControllerError::InvalidArgument(format!(
                        "{destination_id} is not a destination this host has configured"
                    ))
                })?;
            let Destination::Push(push) = &mut record.destination else {
                return Err(ControllerError::InvalidArgument(
                    "a notification-preview key belongs to a paired device".to_owned(),
                ));
            };
            if revision <= push.preview_keys.revision {
                return Err(ControllerError::InvalidArgument(format!(
                    "revision {revision} does not follow the recorded revision {}",
                    push.preview_keys.revision
                )));
            }
            // What the previous key has to outlive: the furthest expiry among the notifications
            // already sealed to it. Nothing outstanding keeps nothing.
            let outstanding = journal
                .deliveries()
                .map_err(unavailable)?
                .into_iter()
                .filter(|delivery| {
                    delivery.destination_id == *destination_id
                        && !delivery.state.is_settled()
                        && delivery.expires_at_ms.get() > now_ms
                })
                .map(|delivery| delivery.expires_at_ms.get())
                .max()
                .map(TimestampMs::new);
            push.preview_keys = push.preview_keys.rotated(key, revision, outstanding);
            journal.configure_destination(&record).map_err(unavailable)
        })
    }

    /// Records a paired device as a push destination.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be written.
    pub fn configure(&self, record: &DestinationRecord) -> Result<()> {
        self.with(|producer| {
            producer
                .journal_mut()
                .configure_destination(record)
                .map_err(unavailable)
        })
    }

    /// Builds a push destination record from what a pairing produced.
    #[must_use]
    pub fn push_destination(
        id: DestinationId,
        push: PushDestination,
        rule: DeliveryRule,
        now_ms: u64,
    ) -> DestinationRecord {
        DestinationRecord {
            id,
            destination: Destination::Push(Box::new(push)),
            rule: Some(rule),
            enabled: true,
            configured_at_ms: TimestampMs::new(now_ms),
        }
    }

    /// Finishes what a restart found unfinished.
    ///
    /// Two things, in order: events this journal took and produced nothing from, which the cursor
    /// has already passed; and attempts that were on the wire when this host stopped, whose
    /// outcome nobody knows. Section 24 resumes only what is still authorised, so the caller says
    /// which destinations still are.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be written.
    pub fn reconcile(
        &self,
        destinations: &[DestinationRecord],
        authority: &dyn RecipientAuthority,
        still_authorised: &dyn Fn(&DestinationId) -> bool,
        now_ms: u64,
    ) -> Result<usize> {
        self.with(|producer| {
            producer
                .finish_pending(destinations, authority, now_ms)
                .map_err(unavailable)?;
            let reconciled = producer
                .reconcile(still_authorised, now_ms)
                .map_err(unavailable)?;
            Ok(reconciled.len())
        })
    }

    /// Drives one pass of the outbox.
    ///
    /// Each due delivery is sent through the seam, and what the seam answers decides the record's
    /// next state, its next attempt and whether the credential needs renewing. Nothing here
    /// retries an unknown outcome: [`kr_delivery::push::decide`] settles it as unknown and the
    /// outbox row goes.
    ///
    /// Returns how many deliveries were attempted.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be read or written.
    pub fn run_due(
        &self,
        sender: &dyn PushSender,
        credentials: &dyn SenderCredentials,
        external: &dyn ExternalSender,
        now_ms: u64,
    ) -> Result<usize> {
        let due: Vec<DueDelivery> = self.with(|producer| {
            producer
                .journal()
                .due(now_ms, MAX_PASS)
                .map_err(unavailable)
        })?;
        let mut attempted = 0;
        for delivery in due {
            let record = self.with(|producer| {
                producer
                    .journal()
                    .destination(&delivery.destination_id)
                    .map_err(unavailable)
            })?;
            let Some(record) = record.filter(|record| record.enabled) else {
                self.settle(
                    &delivery,
                    DeliveryState::Revoked,
                    "the destination is no longer configured or enabled",
                    now_ms,
                )?;
                continue;
            };
            attempted += 1;
            if record.as_push().is_some() {
                self.attempt_push(&delivery, &record, sender, credentials, now_ms)?;
            } else {
                self.attempt_external(&delivery, &record, external, now_ms)?;
            }
        }
        Ok(attempted)
    }

    fn settle(
        &self,
        delivery: &DueDelivery,
        state: DeliveryState,
        detail: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt: delivery.attempts.saturating_add(1),
                    state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(now_ms)),
                    next_attempt_at_ms: None,
                    detail: Some(detail.to_owned()),
                    suppression: None,
                    keep_content: false,
                })
                .map_err(unavailable)
        })
    }

    fn attempt_push(
        &self,
        delivery: &DueDelivery,
        record: &DestinationRecord,
        sender: &dyn PushSender,
        credentials: &dyn SenderCredentials,
        now_ms: u64,
    ) -> Result<()> {
        let push = record.as_push().expect("a push destination");
        let request: PushDeliveryRequest =
            serde_json::from_slice(&delivery.content).map_err(|error| {
                ControllerError::Storage {
                    operation: "read a queued notification",
                    detail: error.to_string(),
                }
            })?;
        let attempt = delivery.attempts.saturating_add(1);

        // The attempt is recorded as on the wire **before** it is made, so a host that stops in
        // the middle finds a record that says an attempt was in flight rather than one that says
        // nothing happened.
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt,
                    state: DeliveryState::InFlight,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: None,
                    next_attempt_at_ms: None,
                    detail: None,
                    suppression: None,
                    keep_content: true,
                })
                .map_err(unavailable)
        })?;

        let Some(mut credential) = credentials.current(push.sender_record_id) else {
            return self.settle(
                delivery,
                DeliveryState::Revoked,
                "this host holds no delivery credential for that authorisation",
                now_ms,
            );
        };
        if kr_delivery::push::needs_renewal(&credential, now_ms)
            && let Ok(renewed) = credentials.renew(push.sender_record_id)
        {
            credential = renewed;
        }
        let outcome = sender.send(&credential, &request);
        let decision = kr_delivery::push::decide(
            &outcome,
            delivery.notification_id,
            attempt,
            now_ms,
            delivery.expires_at_ms,
        );
        if decision.next == NextAction::RenewThenSend {
            // A refused credential is renewed rather than presented again. The delivery waits for
            // its next attempt either way.
            let _ = credentials.renew(push.sender_record_id);
        }
        if decision.disable_destination {
            let mut disabled = record.clone();
            disabled.enabled = false;
            self.configure(&disabled)?;
        }
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt,
                    state: decision.state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(now_ms)),
                    next_attempt_at_ms: decision.next_attempt_at_ms,
                    detail: Some(decision.detail.clone()),
                    suppression: decision.suppression.clone(),
                    keep_content: !decision.state.is_settled(),
                })
                .map_err(unavailable)
        })
    }

    fn attempt_external(
        &self,
        delivery: &DueDelivery,
        record: &DestinationRecord,
        external: &dyn ExternalSender,
        now_ms: u64,
    ) -> Result<()> {
        let destination = record.as_external().expect("an external destination");
        let message = client::message_from(&delivery.content)?;
        let attempt = delivery.attempts.saturating_add(1);
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt,
                    state: DeliveryState::InFlight,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: None,
                    next_attempt_at_ms: None,
                    detail: None,
                    suppression: None,
                    keep_content: true,
                })
                .map_err(unavailable)
        })?;
        let outcome = external.send(destination, &message);
        let decision = kr_delivery::external::decide_external(
            &outcome,
            &destination.idempotency,
            delivery.notification_id,
            attempt,
            now_ms,
            delivery.expires_at_ms,
        );
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt,
                    state: decision.state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(now_ms)),
                    next_attempt_at_ms: decision.next_attempt_at_ms,
                    detail: Some(decision.detail.clone()),
                    suppression: None,
                    keep_content: !decision.state.is_settled(),
                })
                .map_err(unavailable)
        })
    }
}

/// The preview key a device registered, as its request carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviewKeyUpdate {
    /// The key.
    pub key: NotificationPreviewKey,
    /// Its revision.
    pub revision: u64,
}

/// Builds a key ring for a device registering its first preview key.
#[must_use]
pub const fn first_preview_keys(update: PreviewKeyUpdate) -> PreviewKeys {
    PreviewKeys::only(update.key, update.revision)
}

/// Returns the length of the built provider payload for one request, for a caller that reports it.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the request cannot be measured.
pub fn provider_payload_bytes(request: &PushDeliveryRequest) -> Result<u64> {
    preview::provider_payload_bytes(request).map_err(unavailable)
}

fn unavailable(error: kr_delivery::DeliveryError) -> ControllerError {
    ControllerError::Storage {
        operation: "read a queued notification",
        detail: error.to_string(),
    }
}
