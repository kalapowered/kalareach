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
//! | [`runtime`] | The loop that runs recovery at start and a pass on every tick |
//! | [`transport`] | The one managed transport per origin every exchange goes through |
//! | [`client`] | Presenting a notification to the gateway its credential names |
//! | [`status`] | Asking that gateway what became of one, by its identifier |
//! | [`credentials`] | The bearer this host delivers under |
//! | [`sender`] | Renewing it through the gateway's two-step signed exchange |
//! | [`external`] | Delivering to a webhook |
//! | [`authority`] | What an external destination's grant lets its recipient read |
//!
//! # What this daemon serves, and what it calls
//!
//! The four `push.*` methods are `ServiceClient` methods: a caller makes them **to** a gateway.
//! Two of them are the installation's - registering a token and issuing a sender authorisation -
//! and reach the gateway from the phone. Two are this host's, `push.sender.renew` and
//! `push.sender.revoke`, signed with the host key under the one managed-service signature,
//! `ServiceRequestSignature`; renewal is in [`sender`].
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
use kr_delivery::push::{DeliveryStatus, NextAction, PushSender, SenderCredentials, StatusAnswer};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::method::Method;
use kr_protocol::push::PushDeliveryRequest;
use kr_protocol::scalars::{NotificationPreviewKey, TimestampMs};

use crate::error::{ControllerError, Result};

pub mod authority;
pub mod client;
pub mod credentials;
pub mod external;
pub mod runtime;
pub mod sender;
pub mod status;
pub mod transport;

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
    /// The record is the binding the rejection was about. An identifier can name another
    /// installation by the time a rejection arrives, and disabling that one would take a
    /// destination out of service over an answer that was never about it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be written.
    pub fn disable(&self, record: &DestinationRecord) -> Result<()> {
        let digest = record.binding_digest();
        self.with(|producer| {
            producer
                .journal_mut()
                .disable_destination(&record.id, &digest)
                .map_err(unavailable)?;
            Ok(())
        })
    }

    /// Records a destination: a paired device, or a webhook.
    ///
    /// Section 25 documents webhook, Slack, email, Discord and Telegram delivery. This host
    /// delivers to a webhook, whose address is where it sends and nothing more. The other four
    /// each need a credential from this host's secret store - a Slack or Discord webhook address is
    /// itself a bearer secret, Telegram sends through a bot token and email through a mail
    /// account - and a destination's endpoint is never a credential, so a destination of those
    /// kinds is refused here, where the refusal says why, rather than admitting content for a
    /// destination nothing can reach.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for a kind this host cannot deliver to or a
    /// webhook address it will not send to, and [`ControllerError::Storage`] when the journal
    /// cannot be written.
    pub fn configure(&self, record: &DestinationRecord) -> Result<()> {
        if let Destination::External(external) = &record.destination {
            if let Some(needs) = external::credential_needed(external.kind) {
                return Err(ControllerError::InvalidArgument(format!(
                    "a {} destination needs a credential from this host's secret store, because \
                     {needs}, and a destination's endpoint is never a credential: this host \
                     delivers to webhooks",
                    external.kind
                )));
            }
            external::webhook_origin(&external.endpoint)
                .map_err(ControllerError::InvalidArgument)?;
        }
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
    /// The events are finished a page at a time until none is left, or until a page finishes
    /// nothing: a notice this build cannot read stays pending, where a person can see it, and is
    /// not a reason to go round again.
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
            let mut pending = producer.journal().pending_count().map_err(unavailable)?;
            while pending > 0 {
                producer
                    .finish_pending(destinations, authority, now_ms)
                    .map_err(unavailable)?;
                let left = producer.journal().pending_count().map_err(unavailable)?;
                if left >= pending {
                    break;
                }
                pending = left;
            }
            let reconciled = producer
                .reconcile(still_authorised, now_ms)
                .map_err(unavailable)?;
            Ok(reconciled.len())
        })
    }

    /// Asks the gateway what became of the deliveries whose outcome nobody knows and whose next
    /// question is due, at most `limit` of them and for no longer than `budget`.
    ///
    /// Section 23 keeps `OUTCOME_UNKNOWN` out of the automatic loop, so nothing here ever sends.
    /// The question carries the notification identifier and no request, on a route that answers
    /// from what the gateway recorded: asking cannot deliver the notification, which is what makes
    /// it safe to ask at all. An answer the gateway does not have, and a question nobody answered,
    /// both leave the record exactly where it was - outstanding, uncertain, and listed among the
    /// copies this host cannot account for.
    ///
    /// The gateway counts these questions against an hourly allowance, so they are rationed: the
    /// journal offers the records whose turn it is, each record considered and left unresolved has
    /// its next turn pushed back ([`kr_delivery::journal::DeliveryJournal::note_question`]), and
    /// the batch is bounded by count and by time. A backlog of old records the gateway holds
    /// nothing for therefore cannot keep a newer one from being asked.
    ///
    /// A record for a destination with no such question - an external service - never reaches
    /// here: its uncertainty is marked at the attempt instead, which is section 25's own rule.
    ///
    /// Returns how many outcomes it resolved.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the journal cannot be read or written.
    pub fn resolve_unknown(
        &self,
        status: &dyn DeliveryStatus,
        credentials: &dyn SenderCredentials,
        clock: &dyn Clock,
        limit: usize,
        budget: std::time::Duration,
    ) -> Result<usize> {
        let is_fenced =
            self.with(|producer| producer.journal().is_fenced().map_err(unavailable))?;
        if is_fenced {
            return Ok(0);
        }
        let started = std::time::Instant::now();
        let unknown = self.with(|producer| {
            producer
                .journal()
                .unknown_due(clock.now_ms(), limit)
                .map_err(unavailable)
        })?;
        let mut resolved = 0;
        for record in unknown {
            if started.elapsed() >= budget {
                break;
            }
            // A record admitted under a generation privacy mode has ended is not asked about.
            // Nothing from a generation that has been walked past reaches the gateway again, and
            // an identifier is something: it says this host had work for that installation. Both
            // are read again for every record, because a person can turn privacy mode on while
            // this pass is waiting for an answer about the record before this one.
            let (generation, fenced) = self.with(|producer| {
                Ok((
                    producer.journal().generation().map_err(unavailable)?,
                    producer.journal().is_fenced().map_err(unavailable)?,
                ))
            })?;
            if fenced {
                return Ok(resolved);
            }
            let settled = self.ask_about(&record, generation, status, credentials, clock)?;
            // What the journal wrote, not what this host proposed. An answer that leaves the
            // outcome where it was, and an answer that asks for another question later, have both
            // resolved nothing; counting either would report a question as answered while the
            // destination still holds the notification.
            if settled.is_some_and(|state| state.is_settled() && !state.is_outstanding()) {
                resolved += 1;
            } else {
                // Considered and not resolved, whatever the reason: its next turn waits, so the
                // records behind it get theirs.
                self.with(|producer| {
                    producer
                        .journal_mut()
                        .note_question(record.notification_id, clock.now_ms())
                        .map_err(unavailable)
                })?;
            }
        }
        Ok(resolved)
    }

    /// Asks about one unknown outcome, and returns the state the journal wrote for it, if any.
    fn ask_about(
        &self,
        record: &kr_delivery::journal::DeliveryRecord,
        generation: u64,
        status: &dyn DeliveryStatus,
        credentials: &dyn SenderCredentials,
        clock: &dyn Clock,
    ) -> Result<Option<DeliveryState>> {
        if record.privacy_generation != generation {
            return Ok(None);
        }
        let Some(destination) = self.with(|producer| {
            producer
                .journal()
                .destination(&record.destination_id)
                .map_err(unavailable)
        })?
        else {
            return Ok(None);
        };
        // The same authorisation this was admitted under, or no question: a destination that
        // is disabled, or one whose configuration is no longer the one this was admitted for,
        // is not one this host may name its own work to.
        if !destination.enabled || destination.binding_digest() != record.destination_digest {
            return Ok(None);
        }
        let Some(push) = destination.as_push() else {
            return Ok(None);
        };
        let Some(credential) = credentials.current(push.sender_record_id) else {
            return Ok(None);
        };
        let answer = status.status(&credential, record.notification_id);
        let now_ms = clock.now_ms();
        let StatusAnswer::Recorded(ack) = answer else {
            // Nobody answered, or the gateway holds nothing under that identifier. Neither
            // says what became of the notification, so neither settles it.
            return Ok(None);
        };
        let decision = kr_delivery::push::decide(
            &kr_delivery::push::SendOutcome::Decided(ack),
            record.notification_id,
            record.attempts,
            now_ms,
            record.expires_at_ms,
        );
        // The answer carries the same consequences a send's answer does: a token the provider
        // rejected goes out of service here as well, or the destination would keep its token
        // until something happened to ask again.
        if decision.disable_destination {
            self.disable(&destination)?;
        }
        self.with(|producer| {
            producer
                .journal_mut()
                .settle_receipt(record.notification_id, &decision, now_ms)
                .map_err(unavailable)
        })
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
        status: &dyn DeliveryStatus,
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
                self.attempt_push(
                    &claimed,
                    &record,
                    sender,
                    status,
                    credentials,
                    now_ms,
                    clock,
                )?;
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
            let Some(scope) = authority.scope_for(rule) else {
                return false;
            };
            kr_delivery::producer::authority_digest(rule, Some(&scope))
        };
        now == claimed.authority_digest
    }

    /// Puts a claimed delivery back, waiting for a renewal that has not happened.
    ///
    /// Nothing was presented on this attempt, so nothing left this host on it. The delivery is
    /// scheduled again with what it was owed still owed: a send stays a send that renews first,
    /// and a status question stays a status question. Turning a question into a send would present
    /// a notification the gateway is already holding, and it would also strand the record, which
    /// holds no request once its next step is a question.
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
        let owed = if delivery.next == NextAction::Receipt {
            NextAction::Receipt
        } else {
            NextAction::RenewThenSend
        };
        let (state, next) = match next_attempt_at_ms {
            Some(_) => (DeliveryState::Retrying, owed),
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
                    detail: Some(if owed == NextAction::Receipt {
                        format!(
                            "the credential has to be renewed before this host asks what became \
                             of it: {detail}"
                        )
                    } else {
                        format!(
                            "the credential has to be renewed before this is presented again: \
                             {detail}"
                        )
                    }),
                    suppression: None,
                    left_this_host: false,
                    reported_by_destination: false,
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
                    // Nothing was presented, so nothing left this host.
                    left_this_host: false,
                    reported_by_destination: false,
                })
                .map_err(unavailable)?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn attempt_push(
        &self,
        delivery: &ClaimedDelivery,
        record: &DestinationRecord,
        sender: &dyn PushSender,
        status: &dyn DeliveryStatus,
        credentials: &dyn SenderCredentials,
        now_ms: u64,
        clock: &dyn Clock,
    ) -> Result<()> {
        let push = record.as_push().expect("a push destination");
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
            match credentials.renew(&held) {
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
        let outcome =
            if delivery.next == NextAction::Receipt {
                // The gateway is holding this notification and retrying the provider itself. What is
                // asked is the identifier's recorded outcome, on the route that carries no request;
                // presenting the delivery again would be a second notification.
                match status.status(&credential, delivery.notification_id) {
                    StatusAnswer::Recorded(ack) => kr_delivery::push::SendOutcome::Decided(ack),
                    // The gateway holds nothing under the identifier, and nobody answering is the
                    // same for this host: neither says what became of the notification, and neither
                    // is a reason to present it again.
                    StatusAnswer::NoRecord { detail } | StatusAnswer::Unanswered { detail } => {
                        kr_delivery::push::SendOutcome::Unknown { detail }
                    }
                }
            } else {
                let request: PushDeliveryRequest = serde_json::from_slice(&delivery.content)
                    .map_err(|error| ControllerError::Storage {
                        operation: "read a queued notification",
                        detail: error.to_string(),
                    })?;
                sender.send(&credential, &request)
            };
        // The answer arrived now, not when the pass started. Everything that follows - whether
        // there is time for another attempt, when it is due, what the attempt row is stamped
        // with - is decided from this reading.
        let answered_at_ms = clock.now_ms().max(now_ms);
        let mut decision = kr_delivery::push::decide(
            &outcome,
            delivery.notification_id,
            attempt,
            answered_at_ms,
            delivery.expires_at_ms,
        );
        // A refused credential is renewed now rather than at the next attempt, so the renewal is
        // done before that attempt is due. One that happened replaces the refused bearer, and the
        // next attempt presents the new one without renewing it a second time. One that did not
        // leaves the renewal owed with the record: the next attempt renews first and presents
        // nothing until a renewal has succeeded.
        if decision.next == NextAction::RenewThenSend && credentials.renew(&credential).is_ok() {
            decision.next = NextAction::Send;
        }
        if decision.disable_destination {
            self.disable(record)?;
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
                    left_this_host: decision.left_this_host,
                    reported_by_destination: decision.reported_by_destination,
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
        if let Some(needs) = external::credential_needed(destination.kind) {
            // Configuration refuses these kinds, so nothing is admitted for one. A record that
            // reached here anyway is settled without calling an adapter: nothing could send it,
            // and an attempt that never left is not an outcome anybody has to wonder about.
            return self.settle(
                delivery,
                DeliveryState::Revoked,
                &format!(
                    "this host holds no credential for a {} destination: {needs}",
                    destination.kind
                ),
                now_ms,
            );
        }
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
                    left_this_host: decision.left_this_host,
                    reported_by_destination: decision.reported_by_destination,
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
