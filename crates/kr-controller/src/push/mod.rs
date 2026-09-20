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
use kr_delivery::journal::{
    Claim, ClaimedDelivery, DeliveryJournal, DeliveryState, DueDelivery, Transition,
};
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

/// Where one pass reads the time.
///
/// A pass blocks: it opens a connection, waits for a gateway and waits for a destination, and the
/// clock it started with says nothing about the moment it comes back. Section 16 stops at expiry,
/// so the time is read again immediately before each dispatch and again as soon as each answer
/// arrives, and both readings come from here. A fixed instant is a closure over one, which is what
/// makes a schedule reproducible in a test without the pass ever holding a stale figure.
pub trait Clock {
    /// The current time, in UTC milliseconds.
    fn now_ms(&self) -> u64;
}

impl<F: Fn() -> u64> Clock for F {
    fn now_ms(&self) -> u64 {
        self()
    }
}

/// The host's own clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

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
            if push.preview_keys.revision == revision && push.preview_keys.current == key {
                // The registration already recorded. A device whose answer was lost sends the
                // same one again, and the same registration twice is one registration.
                return Ok(());
            }
            if revision <= push.preview_keys.revision {
                return Err(ControllerError::InvalidArgument(format!(
                    "revision {revision} does not follow the recorded revision {}",
                    push.preview_keys.revision
                )));
            }
            push.preview_keys.forget_expired(now_ms);
            if let Some(previous) = push.preview_keys.retained_previous(now_ms) {
                return Err(ControllerError::InvalidArgument(format!(
                    "earlier preview key revision {} is still retired with unexpired notifications until {}; overlapping rotation is refused until earlier notifications expire",
                    previous.revision,
                    previous.retired_until_ms.get()
                )));
            }
            // What the previous key has to outlive: the furthest expiry among the notifications
            // already sealed to it. Provider-queued and unknown outcomes can still arrive, so
            // they count as outstanding alongside unsettled outbox rows.
            let outstanding = journal
                .deliveries()
                .map_err(unavailable)?
                .into_iter()
                .filter(|delivery| {
                    delivery.destination_id == *destination_id
                        && delivery.state.may_still_arrive()
                        && delivery.expires_at_ms.get() > now_ms
                })
                .map(|delivery| delivery.expires_at_ms.get())
                .max()
                .map(TimestampMs::new);
            push.preview_keys = push.preview_keys.rotated(key, revision, outstanding);
            journal.configure_destination(&record).map_err(unavailable)
        })
    }

    /// Takes one destination out of service after the provider rejected its token.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be written.
    pub fn disable(&self, destination_id: &DestinationId) -> Result<()> {
        self.with(|producer| {
            producer
                .journal_mut()
                .disable_destination(destination_id)
                .map_err(unavailable)?;
            Ok(())
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
            let journal = producer.journal_mut();
            journal.expire_overdue(now_ms).map_err(unavailable)?;
            journal
                .forget_expired_preview_keys(now_ms)
                .map_err(unavailable)?;
            producer
                .finish_pending(destinations, authority, now_ms)
                .map_err(unavailable)?;
            let reconciled = producer
                .reconcile(still_authorised, now_ms)
                .map_err(unavailable)?;
            Ok(reconciled.len())
        })
    }

    /// Reads the receipt of every delivery whose outcome nobody knows.
    ///
    /// Section 23 keeps `OUTCOME_UNKNOWN` out of the automatic loop, so nothing schedules this: a
    /// startup or a person asks for it. What it does is a **read** rather than a second send. The
    /// gateway claims a notification identifier before anything reaches a provider and answers a
    /// repeat of the identical request from the outcome it recorded, so presenting it again
    /// returns what happened. The one case where it dispatches is the one where the first request
    /// never arrived, and there the notification has not been delivered at all.
    ///
    /// A record for a destination with no such read - an external service - never reaches here:
    /// its uncertainty is marked at the attempt instead, which is section 25's own rule.
    ///
    /// Returns how many outcomes it resolved.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be read or written.
    pub fn read_receipts(
        &self,
        sender: &dyn PushSender,
        credentials: &dyn SenderCredentials,
        clock: &dyn Clock,
    ) -> Result<usize> {
        let is_fenced =
            self.with(|producer| producer.journal().is_fenced().map_err(unavailable))?;
        if is_fenced {
            return Ok(0);
        }
        let (generation, unknown) = self.with(|producer| {
            let generation = producer.journal().generation().map_err(unavailable)?;
            Ok((
                generation,
                producer
                    .journal()
                    .unreconciled()
                    .map_err(unavailable)?
                    .into_iter()
                    .filter(|record| record.state == DeliveryState::OutcomeUnknown)
                    .collect::<Vec<_>>(),
            ))
        })?;
        let mut resolved = 0;
        for record in unknown {
            // A record admitted under a generation privacy mode has ended is not asked about. The
            // request bytes are the only thing that resolves it, and presenting them is the one
            // case where this could dispatch; nothing from a generation that has been walked past
            // may leave this host again.
            if record.privacy_generation != generation {
                continue;
            }
            let Some(content) = record.content else {
                // Privacy mode removed what the receipt would present. The record stays as the
                // artifact it is, and this host says so rather than asking about nothing.
                continue;
            };
            let Some(destination) = self.with(|producer| {
                producer
                    .journal()
                    .destination(&record.destination_id)
                    .map_err(unavailable)
            })?
            else {
                continue;
            };
            // The same request under the same authorisation, or not at all: a destination that is
            // disabled, or one whose configuration is no longer the one this was admitted for, is
            // not a destination this host may present content to.
            if !destination.enabled || destination.binding_digest() != record.destination_digest {
                continue;
            }
            let Some(push) = destination.as_push() else {
                continue;
            };
            let Some(credential) = credentials.current(push.sender_record_id) else {
                continue;
            };
            let request: PushDeliveryRequest =
                serde_json::from_slice(&content).map_err(|error| ControllerError::Storage {
                    operation: "read a queued notification",
                    detail: error.to_string(),
                })?;
            let outcome = sender.receipt(&credential, &request);
            let now_ms = clock.now_ms();
            let kr_delivery::push::SendOutcome::Decided(ack) = outcome else {
                // Still nobody's answer. The record stays where it is.
                continue;
            };
            let decision = kr_delivery::push::decide(
                &kr_delivery::push::SendOutcome::Decided(ack),
                record.notification_id,
                record.attempts,
                now_ms,
                record.expires_at_ms,
            );
            // A receipt carries the same answers a send does, so it carries the same consequences:
            // a token the provider rejected goes out of service here as well, or the destination
            // would keep its token until something happened to ask again.
            if decision.disable_destination {
                self.disable(&destination.id)?;
            }
            let settled = self.with(|producer| {
                producer
                    .journal_mut()
                    .settle_receipt(record.notification_id, &decision, now_ms)
                    .map_err(unavailable)
            })?;
            resolved += usize::from(settled && decision.state.is_settled());
        }
        Ok(resolved)
    }

    /// Drives one pass of the outbox.
    ///
    /// Each due delivery is **claimed** first - one transaction that checks the fence, the
    /// generation, the record's own state, the due time and the expiry, and moves the row to
    /// in flight - and only a claimed row is sent. A selection followed by a send would be a send
    /// decided by a read: a privacy pass could cancel the row in between, and two passes could
    /// present one external message twice.
    ///
    /// What the seam answers then decides the record's next state, its next attempt and whether
    /// the credential needs renewing. Nothing here retries an unknown outcome:
    /// [`kr_delivery::push::decide`] settles it as unknown and the outbox row goes.
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
        authority: &dyn RecipientAuthority,
        clock: &dyn Clock,
    ) -> Result<usize> {
        let now_ms = clock.now_ms();
        self.with(|producer| {
            let journal = producer.journal_mut();
            // An expiry that passed while this host was stopped leaves a queued row nothing will
            // ever select, so the pass settles those first and then selects what is still worth
            // sending.
            journal.expire_overdue(now_ms).map_err(unavailable)?;
            journal
                .forget_expired_preview_keys(now_ms)
                .map_err(unavailable)
        })?;
        let selected: Vec<DueDelivery> = self.with(|producer| {
            producer
                .journal()
                .due(now_ms, MAX_PASS)
                .map_err(unavailable)
        })?;
        let mut attempted = 0;
        for selection in selected {
            // The clock is read again here, immediately before the claim, rather than once for
            // the pass: a pass that blocked on the previous destination for a minute would
            // otherwise claim this one against a time that has gone.
            let now_ms = clock.now_ms();
            let claim = self.with(|producer| {
                producer
                    .journal_mut()
                    .claim(selection.notification_id, now_ms)
                    .map_err(unavailable)
            })?;
            let claimed = match claim {
                Claim::Taken(claimed) => *claimed,
                // A record the claim settled - expired, or admitted for a destination that is not
                // the one configured now - and a refusal are both records this pass has finished
                // with. Neither is sent.
                Claim::Settled(_) | Claim::Refused(_) => continue,
            };
            // The destination is the one the claim validated inside its own transaction, not one
            // read again afterwards: what is sent has to go where the claim said it may go.
            let record = claimed.destination.clone();
            if !record.enabled {
                self.settle(
                    &claimed,
                    DeliveryState::Revoked,
                    "the destination is no longer configured or enabled",
                    now_ms,
                )?;
                continue;
            }
            // Section 19 intersects the content policy with the recipient's own authority, and
            // that authority is asked again here rather than trusted from admission. A grant
            // revoked after the message was built stops it now.
            if !self.authority_still_holds(&record, &claimed, authority) {
                self.settle(
                    &claimed,
                    DeliveryState::Revoked,
                    "the recipient's authority is not the one this was admitted under",
                    clock.now_ms().max(now_ms),
                )?;
                continue;
            }
            // Deciding whether to send waits - on this host's own locks, and on whatever the
            // recipient's authority has to be asked - and section 16 stops at expiry, so the
            // deadline is read against the clock as it stands immediately before the dispatch
            // rather than against the reading the claim was made with.
            let now_ms = clock.now_ms().max(now_ms);
            if now_ms >= claimed.expires_at_ms.get() {
                self.settle(
                    &claimed,
                    DeliveryState::Expired,
                    "the notification expired while this pass was deciding whether to send it",
                    now_ms,
                )?;
                continue;
            }
            attempted += 1;
            if record.as_push().is_some() {
                self.attempt_push(&claimed, &record, sender, credentials, now_ms, clock)?;
            } else {
                self.attempt_external(&claimed, &record, external, now_ms, clock)?;
            }
        }
        Ok(attempted)
    }

    /// Whether the authority a claimed delivery was admitted under is still the authority now.
    ///
    /// A push destination's recipient is the paired device, so the rule is the whole of it. An
    /// external destination's is the grant, and the grant decides which sessions' lines may be in
    /// the message at all, so it is asked again and the answer compared.
    fn authority_still_holds(
        &self,
        record: &DestinationRecord,
        claimed: &ClaimedDelivery,
        authority: &dyn RecipientAuthority,
    ) -> bool {
        let Ok(rule) = record.require_rule() else {
            return false;
        };
        let now = if record.as_push().is_some() {
            kr_delivery::producer::authority_digest(rule, None)
        } else {
            let Some((scope, sessions)) = authority.scope_for(rule) else {
                return false;
            };
            kr_delivery::producer::authority_digest(rule, Some((&scope, &sessions)))
        };
        now == claimed.authority_digest
    }

    /// Puts a claimed delivery back, waiting for a renewal that has not happened.
    ///
    /// Nothing was presented, so nothing has left this host and the attempt is not one the
    /// notification spends: it is scheduled again with the renewal still owed.
    fn wait_for_renewal(
        &self,
        delivery: &ClaimedDelivery,
        detail: &str,
        now_ms: u64,
    ) -> Result<()> {
        let next_attempt_at_ms = kr_delivery::push::next_attempt(
            delivery.notification_id,
            delivery.attempt,
            now_ms,
            delivery.expires_at_ms,
        );
        let (state, next) = match next_attempt_at_ms {
            Some(_) => (DeliveryState::Retrying, NextAction::RenewThenSend),
            None => (DeliveryState::Expired, NextAction::None),
        };
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt: delivery.attempt,
                    state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(now_ms)),
                    next_attempt_at_ms,
                    next,
                    detail: Some(format!(
                        "the credential has to be renewed before this is presented again: {detail}"
                    )),
                    suppression: None,
                    keep_content: !state.is_settled(),
                    left_this_host: false,
                })
                .map_err(unavailable)?;
            Ok(())
        })
    }

    fn settle(
        &self,
        delivery: &ClaimedDelivery,
        state: DeliveryState,
        detail: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt: delivery.attempt,
                    state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(now_ms)),
                    next_attempt_at_ms: None,
                    next: NextAction::None,
                    detail: Some(detail.to_owned()),
                    suppression: None,
                    keep_content: false,
                    // Nothing was presented, so nothing left this host.
                    left_this_host: false,
                })
                .map_err(unavailable)?;
            Ok(())
        })
    }

    fn attempt_push(
        &self,
        delivery: &ClaimedDelivery,
        record: &DestinationRecord,
        sender: &dyn PushSender,
        credentials: &dyn SenderCredentials,
        now_ms: u64,
        clock: &dyn Clock,
    ) -> Result<()> {
        let push = record.as_push().expect("a push destination");
        let request: PushDeliveryRequest =
            serde_json::from_slice(&delivery.content).map_err(|error| {
                ControllerError::Storage {
                    operation: "read a queued notification",
                    detail: error.to_string(),
                }
            })?;
        // The claim already recorded this attempt as on the wire, in the transaction that took the
        // row: a host that stops in the middle finds a record that says an attempt was in flight
        // rather than one that says nothing happened.
        let attempt = delivery.attempt;

        let Some(held) = credentials.current(push.sender_record_id) else {
            return self.settle(
                delivery,
                DeliveryState::Revoked,
                "this host holds no delivery credential for that authorisation",
                now_ms,
            );
        };
        // Section 16 renews rather than presenting a credential the gateway has refused, and a
        // renewal that has not happened is not a renewal. So a credential inside its renewal
        // window, or one the last answer refused, is renewed **before** anything is presented,
        // and a renewal that did not produce a credential stops this attempt: presenting the old
        // one again would get the same answer and count as another attempt at the notification.
        let credential = if delivery.next == NextAction::RenewThenSend
            || kr_delivery::push::needs_renewal(&held, now_ms)
        {
            match credentials.renew(push.sender_record_id) {
                Ok(renewed) => renewed,
                Err(error) => {
                    return self.wait_for_renewal(delivery, &error.to_string(), now_ms);
                }
            }
        } else {
            held
        };
        // A renewal is a call to the gateway, so it waits, and a notification whose expiry passed
        // during that wait is not presented: section 16 stops at expiry rather than at the moment
        // the pass last looked at a clock.
        let now_ms = clock.now_ms().max(now_ms);
        if now_ms >= delivery.expires_at_ms.get() {
            return self.settle(
                delivery,
                DeliveryState::Expired,
                "the notification expired while the credential was being renewed",
                now_ms,
            );
        }
        let outcome = if delivery.next == NextAction::Receipt {
            // The gateway is holding this notification and retrying the provider itself. Asking
            // what became of it is a read; presenting it as new work would be a second
            // notification.
            sender.receipt(&credential, &request)
        } else {
            sender.send(&credential, &request)
        };
        // The answer arrived now, not when the pass started. Everything that follows - whether
        // there is time for another attempt, when it is due, what the attempt row is stamped
        // with - is decided from this reading.
        let answered_at_ms = clock.now_ms().max(now_ms);
        let decision = kr_delivery::push::decide(
            &outcome,
            delivery.notification_id,
            attempt,
            answered_at_ms,
            delivery.expires_at_ms,
        );
        if decision.next == NextAction::RenewThenSend {
            // The need is recorded now, so the renewal can be under way before the next attempt
            // is due. What stops the old credential being presented again is not this call but
            // the action persisted with the record: the next attempt renews first and does not
            // present anything until a renewal has succeeded.
            let _ = credentials.renew(push.sender_record_id);
        }
        if decision.disable_destination {
            self.disable(&record.id)?;
        }
        self.with(|producer| {
            producer
                .journal_mut()
                .record_attempt(&Transition {
                    notification_id: delivery.notification_id,
                    attempt,
                    state: decision.state,
                    started_at_ms: TimestampMs::new(now_ms),
                    settled_at_ms: Some(TimestampMs::new(answered_at_ms)),
                    next_attempt_at_ms: decision.next_attempt_at_ms,
                    next: decision.next,
                    detail: Some(decision.detail.clone()),
                    suppression: decision.suppression.clone(),
                    keep_content: !decision.state.is_settled(),
                    left_this_host: decision.left_this_host,
                })
                .map_err(unavailable)?;
            Ok(())
        })
    }

    fn attempt_external(
        &self,
        delivery: &ClaimedDelivery,
        record: &DestinationRecord,
        external: &dyn ExternalSender,
        now_ms: u64,
        clock: &dyn Clock,
    ) -> Result<()> {
        let destination = record.as_external().expect("an external destination");
        let message = client::message_from(&delivery.content)?;
        let attempt = delivery.attempt;
        let outcome = external.send(destination, &message);
        let answered_at_ms = clock.now_ms().max(now_ms);
        let decision = kr_delivery::external::decide_external(
            &outcome,
            &destination.idempotency,
            delivery.notification_id,
            attempt,
            answered_at_ms,
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
                    settled_at_ms: Some(TimestampMs::new(answered_at_ms)),
                    next_attempt_at_ms: decision.next_attempt_at_ms,
                    next: decision.next,
                    detail: Some(decision.detail.clone()),
                    suppression: None,
                    keep_content: !decision.state.is_settled(),
                    left_this_host: decision.left_this_host,
                })
                .map_err(unavailable)?;
            Ok(())
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
