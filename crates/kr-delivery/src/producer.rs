//! Taking what the host recorded, and producing notifications from it.
//!
//! # Two sources, one journal, and a cursor committed with its effect
//!
//! Attention decides announcements; the worker writes an outbox row beside every state transition.
//! This producer consumes both, because they answer different questions: an announcement is *this
//! condition wants a person*, and an outbox record is *this happened*. Neither handoff knows about
//! the other, so this crate keeps a cursor for each, under its own consumer name, and both
//! register before they rely on collection keeping anything for them.
//!
//! The order is the same for both and it is the order crash-safety needs:
//!
//! 1. read a page from the source, which takes nothing and moves nothing;
//! 2. commit the de-duplication record and the cursor **in this journal**, in one transaction;
//! 3. produce the notifications, in a second transaction that the foreign key refuses unless step
//!    two committed;
//! 4. acknowledge upstream - `settle_announcements`, `note_outbox_consumed`.
//!
//! A host that dies anywhere in that sequence is handed the same page again and the event keys
//! absorb it. A host that dies between two and three has the event and no notification, which is
//! section 16's *the host writes the underlying event first* holding even through a crash.
//!
//! # The privacy generation travels with the work
//!
//! Every notification records the generation it was admitted under, and
//! [`Producer::publish_under`] refuses a result produced under any other. That is T-040's
//! `accepts_result` rule applied at the one place this crate publishes: a result from before the
//! boundary belongs to work privacy mode cancelled.

use std::collections::BTreeSet;

use kr_attention::engine::Announcement;
use kr_protocol::attention::{AttentionLevel, AttentionRule};
use kr_protocol::ids::{EnvelopeId, EnvironmentId, NotificationId, SessionId};
use kr_protocol::push::{PushAlert, PushDeliveryRequest, PushPlatformHints, PushUrgency};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_worker::history_filter::{HistoryFilter, ViewerScope};

use crate::budget::{Admission, Budget, collapse_id};
use crate::destination::{DeliveryRule, Destination, DestinationId, DestinationRecord};
use crate::error::{DeliveryError, Result};
use crate::external::{self, ContentLine, ExternalMessage};
use crate::journal::{
    ATTENTION_CONSUMER, DeliveryJournal, DeliveryRecord, DeliveryState, EventKey, EventSource,
    OUTBOX_CONSUMER, TakenEvent,
};
use crate::preview::{self, PreviewBody, PreviewTarget};
use crate::push::{self, MAX_EXPIRY_AHEAD_MS};

/// How long a notification is worth delivering for, unless a caller says otherwise.
///
/// Four hours. Long enough for a phone that is asleep or out of signal, short enough that a person
/// is not told about something that stopped mattering before they picked the device up. The
/// gateway refuses anything past 24 hours, which [`push::check_expiry`] enforces.
pub const DEFAULT_NOTIFICATION_LIFETIME_MS: u64 = 4 * 60 * 60 * 1000;

/// One thing the host recorded that a destination may want to know about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The underlying event, which this journal must already have taken.
    pub event: EventKey,
    /// Which generic alert a locked screen shows.
    pub alert: PushAlert,
    /// How urgently a provider is asked to deliver.
    pub urgency: PushUrgency,
    /// The attention rule this was raised under.
    pub rule: String,
    /// One line naming the subject. It never leaves the seal.
    pub summary: String,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// The environment it belongs to, when it belongs to one.
    pub environment_id: Option<EnvironmentId>,
    /// When the host observed the condition, in UTC milliseconds.
    pub observed_at_ms: TimestampMs,
    /// What this groups with on the device, before it is turned into an opaque identifier.
    ///
    /// It is a name in this host's own vocabulary, such as a session and a rule. It never travels:
    /// the collapse identifier that does is a keyed digest of it.
    pub collapse_group: String,
    /// When it stops being worth delivering, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

impl Notice {
    /// Builds a notice from one attention announcement.
    ///
    /// The summary is the announcement's own line, and it goes inside the seal. The collapse group
    /// is the session and the rule, so repeated attention about one thing replaces itself on the
    /// device rather than stacking.
    #[must_use]
    pub fn from_announcement(announcement: &Announcement, now_ms: u64) -> Self {
        let session = announcement.session_id;
        Self {
            event: EventKey::announcement(session, announcement.key.as_str(), announcement.number),
            alert: alert_for(announcement.rule),
            urgency: urgency_for(announcement.level),
            rule: announcement.rule.as_str().to_owned(),
            summary: announcement.summary.clone(),
            session_id: session,
            environment_id: None,
            observed_at_ms: TimestampMs::new(now_ms),
            collapse_group: format!(
                "{}/{}",
                session.map_or_else(|| "-".to_owned(), |id| id.to_string()),
                announcement.rule.as_str()
            ),
            expires_at_ms: TimestampMs::new(
                now_ms.saturating_add(DEFAULT_NOTIFICATION_LIFETIME_MS),
            ),
        }
    }

    /// The event record this notice's source is taken under.
    #[must_use]
    pub fn taken(&self, source_cursor: u64) -> TakenEvent {
        TakenEvent {
            key: self.event.clone(),
            source_cursor,
            session_id: self.session_id,
            recorded_at_ms: self.observed_at_ms,
        }
    }
}

/// Which generic alert one attention rule produces.
///
/// The mapping is total and closed. A rule with no obvious alert gets the general one rather than
/// a sentence invented for it: section 16's vocabulary is fixed, and adding to it is a protocol
/// change rather than a producer's choice.
#[must_use]
pub const fn alert_for(rule: AttentionRule) -> PushAlert {
    match rule {
        AttentionRule::PendingApproval => PushAlert::ApprovalWaiting,
        AttentionRule::PendingInput | AttentionRule::InputIdleReminder => {
            PushAlert::QuestionWaiting
        }
        AttentionRule::ReviewReady => PushAlert::WorkComplete,
        AttentionRule::HostContactLost => PushAlert::HostUnreachable,
        AttentionRule::CommandFailed
        | AttentionRule::AdapterFailed
        | AttentionRule::ApplicationNotice => PushAlert::SessionNeedsAttention,
    }
}

/// How urgently an attention level asks for delivery.
#[must_use]
pub const fn urgency_for(level: AttentionLevel) -> PushUrgency {
    match level {
        AttentionLevel::Urgent => PushUrgency::Attention,
        AttentionLevel::Notable | AttentionLevel::Informational => PushUrgency::Deferred,
    }
}

/// What a destination's rule grants the recipient.
///
/// The host that owns the grant store answers it. T-039's filter decides *when* content may be
/// seen and carries no resource selector, so the resources are a second answer rather than
/// something the filter could have been asked for.
pub trait RecipientAuthority: std::fmt::Debug {
    /// The viewer scope and the sessions one rule's grant names.
    ///
    /// `None` is a rule whose grant no longer exists or has been revoked, which admits nothing.
    fn scope_for(&self, rule: &DeliveryRule) -> Option<(ViewerScope, BTreeSet<SessionId>)>;
}

/// What producing from one page did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Produced {
    /// How many underlying events were new to this journal.
    pub events_taken: usize,
    /// How many notifications were admitted to the outbox.
    pub admitted: usize,
    /// How many were recorded as collapsed by this host's own account.
    pub collapsed: usize,
    /// How many were refused, with the reason, for a person reading the journal.
    pub refused: Vec<(DestinationId, String)>,
}

/// The delivery producer for one environment.
#[derive(Debug)]
pub struct Producer {
    journal: DeliveryJournal,
    preview_key: kr_crypto::keys::NotificationPreviewKeyPair,
    collapse_secret: [u8; 32],
}

impl Producer {
    /// Builds a producer over one delivery journal.
    ///
    /// Both consumers are registered here, before anything is read, because a consumer that has
    /// not registered has no claim on what collection removes.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the journal cannot be written.
    pub fn new(
        mut journal: DeliveryJournal,
        preview_key: kr_crypto::keys::NotificationPreviewKeyPair,
        now_ms: u64,
    ) -> Result<Self> {
        journal.register_consumer(ATTENTION_CONSUMER, now_ms)?;
        journal.register_consumer(OUTBOX_CONSUMER, now_ms)?;
        let collapse_secret = journal.collapse_secret()?;
        Ok(Self {
            journal,
            preview_key,
            collapse_secret,
        })
    }

    /// The journal, for reads a caller needs.
    #[must_use]
    pub const fn journal(&self) -> &DeliveryJournal {
        &self.journal
    }

    /// The journal, for a caller that configures destinations or drives privacy mode.
    pub const fn journal_mut(&mut self) -> &mut DeliveryJournal {
        &mut self.journal
    }

    /// This host's own notification-preview public key, which a paired device seals nothing to.
    #[must_use]
    pub const fn preview_public(&self) -> &kr_protocol::scalars::NotificationPreviewKey {
        self.preview_key.public()
    }

    /// Takes a page of underlying events and records the cursor with it.
    ///
    /// Step two of the sequence in this module's documentation. It is separate from
    /// [`Producer::produce`] on purpose: the two are two transactions, and that is what makes the
    /// event come first even through a crash.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the write fails.
    pub fn take(
        &mut self,
        source: EventSource,
        events: &[TakenEvent],
        cursor: u64,
    ) -> Result<usize> {
        self.journal.take_events(source.consumer(), events, cursor)
    }

    /// Produces notifications for one notice, one per destination that wants it.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NoUnderlyingEvent`] when the notice's event has not been taken,
    /// and [`DeliveryError::Fenced`] when privacy mode has stopped this environment's outbox.
    pub fn produce(
        &mut self,
        notice: &Notice,
        destinations: &[DestinationRecord],
        authority: &dyn RecipientAuthority,
        lines: &[ContentLine],
        now_ms: u64,
    ) -> Result<Produced> {
        if self.journal.is_fenced()? {
            return Err(DeliveryError::Fenced);
        }
        if !self.journal.has_event(&notice.event)? {
            return Err(DeliveryError::NoUnderlyingEvent(notice.event.stored()));
        }
        push::check_expiry(now_ms, notice.expires_at_ms)?;
        let generation = self.journal.generation()?;
        let mut produced = Produced::default();
        for destination in destinations {
            if !destination.enabled {
                continue;
            }
            let outcome = match &destination.destination {
                Destination::Push(_) => self.produce_push(notice, destination, generation, now_ms),
                Destination::External(_) => {
                    self.produce_external(notice, destination, authority, lines, generation, now_ms)
                }
            };
            match outcome {
                Ok(true) => produced.admitted += 1,
                Ok(false) => produced.collapsed += 1,
                Err(error) => produced
                    .refused
                    .push((destination.id.clone(), error.to_string())),
            }
        }
        Ok(produced)
    }

    fn produce_push(
        &mut self,
        notice: &Notice,
        destination: &DestinationRecord,
        generation: u64,
        now_ms: u64,
    ) -> Result<bool> {
        let push = destination
            .as_push()
            .ok_or_else(|| DeliveryError::NoDestination(destination.id.to_string()))?
            .clone();
        // Section 25's first half applies to a paired device too: a destination with no rule is a
        // destination nobody decided to send to.
        destination.require_rule()?;

        let notification_id = preview::fresh_notification_id();
        let mut budget = self
            .journal
            .budget(&destination.id)?
            .map_or_else(|| Budget::fresh(now_ms), |stored| Budget::restored(&stored));
        let decision = budget.admit(now_ms, preview::fresh_notification_id);
        self.journal
            .record_budget(&destination.id, &budget.stored())?;

        let (identifier, suppression) = match decision {
            Admission::Send => (notification_id, None),
            Admission::Collapse { suppression } => {
                // Nothing is sent, and the request is still retained: section 16's *the host
                // retains every request and reports suppression locally* is this row.
                self.journal.admit(&DeliveryRecord {
                    notification_id,
                    event: notice.event.clone(),
                    destination_id: destination.id.clone(),
                    state: DeliveryState::Collapsed,
                    privacy_generation: generation,
                    content: None,
                    payload_bytes: 0,
                    expires_at_ms: notice.expires_at_ms,
                    admitted_at_ms: TimestampMs::new(now_ms),
                    attempts: 0,
                    suppression: Some(suppression),
                    detail: Some(
                        "the destination is over this host's own rate policy, so this collapsed \
                         into an attention update"
                            .to_owned(),
                    ),
                })?;
                return Ok(false);
            }
            Admission::OpenUpdate {
                update,
                suppression,
            } => (update, Some(suppression)),
        };

        let alert = if suppression.is_some() {
            // What goes out is the attention update, not the notification that was suppressed.
            PushAlert::AttentionUpdate
        } else {
            notice.alert
        };
        let request = self.build_request(notice, &push, identifier, alert, now_ms)?;
        let content = preview::encode_request(&request)?;
        let payload_bytes = content.len() as u64;
        self.journal.admit(&DeliveryRecord {
            notification_id: identifier,
            event: notice.event.clone(),
            destination_id: destination.id.clone(),
            state: DeliveryState::Admitted,
            privacy_generation: generation,
            content: Some(content),
            payload_bytes,
            expires_at_ms: notice.expires_at_ms,
            admitted_at_ms: TimestampMs::new(now_ms),
            attempts: 0,
            suppression,
            detail: None,
        })?;
        Ok(true)
    }

    /// Builds the request, moving the excess into a referenced encrypted object if it does not fit.
    ///
    /// Section 16's remedy in order: build it, measure the built body, and if it is over the
    /// bound put the detail somewhere else and build again. Nothing estimates and nothing trims.
    fn build_request(
        &mut self,
        notice: &Notice,
        push: &crate::destination::PushDestination,
        notification_id: NotificationId,
        alert: PushAlert,
        now_ms: u64,
    ) -> Result<PushDeliveryRequest> {
        let collapse = collapse_id(&self.collapse_secret, &notice.collapse_group);
        let hints = PushPlatformHints {
            alert,
            urgency: notice.urgency,
        };
        let skeleton =
            |preview: Nullable<kr_protocol::mailbox::SealedEnvelope>| PushDeliveryRequest {
                collapse_id: collapse,
                expires_at_ms: notice.expires_at_ms,
                hints,
                notification_id,
                preview,
                sender_record_id: push.sender_record_id,
            };
        if !push.previews_enabled {
            // Section 16: disabling previews removes the recipient key from future notifications
            // while the generic alert remains. There is no preview and no key here at all.
            let request = skeleton(Nullable::null());
            preview::check_payload_bound(&request)?;
            return Ok(request);
        }

        let body = PreviewBody {
            alert,
            rule: notice.rule.clone(),
            summary: notice.summary.clone(),
            session_id: notice
                .session_id
                .map_or_else(Nullable::null, Nullable::some),
            environment_id: notice
                .environment_id
                .map_or_else(Nullable::null, Nullable::some),
            detail_object: Nullable::null(),
            observed_at_ms: notice.observed_at_ms,
        };
        let target = PreviewTarget {
            recipient: push.preview_keys.current,
            revision: push.preview_keys.revision,
        };
        let envelope_id = EnvelopeId::new(Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes()));
        let first = preview::seal_preview(
            &self.preview_key,
            &target,
            envelope_id,
            &body,
            TimestampMs::new(now_ms),
            notice.expires_at_ms,
        )
        .and_then(|sealed| {
            let request = skeleton(Nullable::some(sealed.envelope));
            preview::check_payload_bound(&request)?;
            Ok(request)
        });
        match first {
            Ok(request) => Ok(request),
            Err(DeliveryError::PreviewTooLarge { .. } | DeliveryError::PayloadTooLarge { .. }) => {
                // The detail stays on this host, encrypted, and the preview carries a reference to
                // it. It is not trimmed, and no ratio is applied to guess what would have fitted.
                let detail_id = EnvelopeId::new(Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes()));
                let detail = preview::seal_preview(
                    &self.preview_key,
                    &target,
                    detail_id,
                    &body,
                    TimestampMs::new(now_ms),
                    notice.expires_at_ms,
                )?;
                self.journal.keep_object(
                    detail_id,
                    &DestinationId::new(push.installation_id.to_string())?,
                    &kr_cbor::to_canonical_vec(&detail.envelope)?,
                    notice.expires_at_ms,
                )?;
                let sealed = preview::seal_preview(
                    &self.preview_key,
                    &target,
                    envelope_id,
                    &body.referring_to(detail_id),
                    TimestampMs::new(now_ms),
                    notice.expires_at_ms,
                )?;
                let request = skeleton(Nullable::some(sealed.envelope));
                preview::check_payload_bound(&request)?;
                Ok(request)
            }
            Err(other) => Err(other),
        }
    }

    fn produce_external(
        &mut self,
        notice: &Notice,
        destination: &DestinationRecord,
        authority: &dyn RecipientAuthority,
        lines: &[ContentLine],
        generation: u64,
        now_ms: u64,
    ) -> Result<bool> {
        let external_destination = destination
            .as_external()
            .ok_or_else(|| DeliveryError::NoDestination(destination.id.to_string()))?;
        let rule = destination.require_rule()?;
        // Configuration is where it goes; the grant is what may go there. A rule whose grant has
        // been revoked admits nothing, and the destination's own configuration does not stand in
        // for it.
        let (scope, sessions) = authority
            .scope_for(rule)
            .ok_or_else(|| DeliveryError::NotAuthorised(destination.id.to_string()))?;
        let notification_id = preview::fresh_notification_id();
        let message = external::compose(
            external_destination.kind,
            notice.alert,
            lines.to_vec(),
            &HistoryFilter::new(scope),
            &sessions,
            external::delivery_id(external_destination, notification_id),
        )?;
        let content = serde_json::to_vec(&message_json(&message))
            .map_err(|error| DeliveryError::Encoding(error.to_string()))?;
        let payload_bytes = content.len() as u64;
        self.journal.admit(&DeliveryRecord {
            notification_id,
            event: notice.event.clone(),
            destination_id: destination.id.clone(),
            state: DeliveryState::Admitted,
            privacy_generation: generation,
            content: Some(content),
            payload_bytes,
            expires_at_ms: notice.expires_at_ms,
            admitted_at_ms: TimestampMs::new(now_ms),
            attempts: 0,
            suppression: None,
            detail: None,
        })?;
        Ok(true)
    }

    /// Returns whether a result produced under `generation` may be published.
    ///
    /// T-040's rule, applied where this crate publishes: exactly the generation in force, because
    /// an older one belongs to work privacy mode cancelled and a newer one to no generation this
    /// host has opened.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::LateResult`] when the generations differ.
    pub fn publish_under(&self, generation: u64) -> Result<()> {
        let in_force = self.journal.generation()?;
        if generation == in_force {
            Ok(())
        } else {
            Err(DeliveryError::LateResult {
                produced_under: generation,
                in_force,
            })
        }
    }

    /// Records what a restart found in flight: an outcome nobody knows is recorded as unknown.
    ///
    /// Section 24 resumes *only what is still authorised*, so `still_authorised` is asked about
    /// each destination before anything is resumed. What it says no to is revoked rather than
    /// carried on with. What it says yes to is left in the outbox for the ordinary loop, except
    /// for an attempt that was on the wire, which has no known outcome and is recorded as such.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the journal cannot be written.
    pub fn reconcile(
        &mut self,
        still_authorised: &dyn Fn(&DestinationId) -> bool,
        now_ms: u64,
    ) -> Result<Vec<(NotificationId, DeliveryState)>> {
        let mut reconciled = Vec::new();
        for record in self.journal.unreconciled()? {
            let state = if still_authorised(&record.destination_id) {
                DeliveryState::OutcomeUnknown
            } else {
                DeliveryState::Revoked
            };
            let detail = if state == DeliveryState::OutcomeUnknown {
                "this host stopped while the attempt was on the wire, so its outcome is unknown \
                 and it is not retried automatically"
            } else {
                "the authorisation ended while the attempt was on the wire"
            };
            self.journal.record_attempt(&crate::journal::Transition {
                notification_id: record.notification_id,
                attempt: record.attempts.max(1),
                state,
                started_at_ms: record.admitted_at_ms,
                settled_at_ms: Some(TimestampMs::new(now_ms)),
                next_attempt_at_ms: None,
                detail: Some(detail.to_owned()),
                suppression: None,
                keep_content: false,
            })?;
            reconciled.push((record.notification_id, state));
        }
        Ok(reconciled)
    }
}

/// Encodes a composed external message the way the journal keeps it.
///
/// It is a document rather than the [`ExternalMessage`] value because the provenance type belongs
/// to the worker's history filter and is not a wire type. What is kept is what an adapter needs to
/// send and what a person needs to read afterwards.
#[must_use]
pub fn message_json(message: &ExternalMessage) -> serde_json::Value {
    serde_json::json!({
        "alert": message.alert.as_str(),
        "body": message.body,
        "delivery_id": message.delivery_id,
        "interval": {
            "from_ms": message.provenance.interval.from_ms.to_string(),
            "to_ms": message.provenance.interval.to_ms.to_string(),
        },
        "resources": message.provenance.resources,
        "withheld": message
            .withheld
            .iter()
            .map(|(reason, count)| serde_json::json!([reason.as_str(), count.to_string()]))
            .collect::<Vec<_>>(),
    })
}

/// The furthest ahead a notice may expire, repeated here so a caller building one can check.
pub const MAX_NOTICE_LIFETIME_MS: u64 = MAX_EXPIRY_AHEAD_MS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{
        DestinationKind, ExternalDestination, Idempotency, PreviewKeys, PushDestination,
    };
    use kr_crypto::keys::NotificationPreviewKeyPair;
    use kr_protocol::ids::{InstallationId, PushSenderRecordId};

    #[derive(Debug)]
    struct Everything(BTreeSet<SessionId>);

    impl RecipientAuthority for Everything {
        fn scope_for(&self, _rule: &DeliveryRule) -> Option<(ViewerScope, BTreeSet<SessionId>)> {
            Some((ViewerScope::owner(), self.0.clone()))
        }
    }

    #[derive(Debug)]
    struct Revoked;

    impl RecipientAuthority for Revoked {
        fn scope_for(&self, _rule: &DeliveryRule) -> Option<(ViewerScope, BTreeSet<SessionId>)> {
            None
        }
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn producer() -> Producer {
        Producer::new(
            DeliveryJournal::in_memory().expect("a journal"),
            NotificationPreviewKeyPair::generate().expect("a keypair"),
            1_000,
        )
        .expect("a producer")
    }

    fn push_destination(id: &str, previews_enabled: bool) -> DestinationRecord {
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        DestinationRecord {
            id: DestinationId::new(id).expect("an identifier"),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
                sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
                preview_keys: PreviewKeys::only(*device.public(), 1),
                previews_enabled,
            })),
            rule: Some(DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    fn webhook(id: &str) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new(id).expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Supported {
                    field: "Idempotency-Key".to_owned(),
                },
            }),
            rule: Some(DeliveryRule {
                name: "on failure".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    fn notice(now_ms: u64) -> Notice {
        Notice {
            event: EventKey::announcement(Some(session(1)), "attention.pending_approval/x", 7),
            alert: PushAlert::ApprovalWaiting,
            urgency: PushUrgency::Attention,
            rule: "attention.pending_approval".to_owned(),
            summary: "an approval is waiting".to_owned(),
            session_id: Some(session(1)),
            environment_id: None,
            observed_at_ms: TimestampMs::new(now_ms),
            collapse_group: "session-1/attention.pending_approval".to_owned(),
            expires_at_ms: TimestampMs::new(now_ms + DEFAULT_NOTIFICATION_LIFETIME_MS),
        }
    }

    fn take_the_event(producer: &mut Producer, notice: &Notice) {
        producer
            .take(EventSource::Attention, &[notice.taken(7)], 7)
            .expect("a page");
    }

    #[test]
    fn nothing_is_produced_for_an_event_this_journal_has_not_taken() {
        let mut producer = producer();
        let destination = push_destination("phone", true);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let error = producer
            .produce(
                &notice(1_000),
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000,
            )
            .expect_err("the event comes first");
        assert!(matches!(error, DeliveryError::NoUnderlyingEvent(_)));
        assert!(
            producer.journal().deliveries().expect("a read").is_empty(),
            "nothing was written beside the event"
        );
    }

    #[test]
    fn a_notification_is_produced_from_the_event_once_it_has_been_taken() {
        let mut producer = producer();
        let destination = push_destination("phone", true);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let notice = notice(1_000);
        take_the_event(&mut producer, &notice);
        let produced = producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000,
            )
            .expect("a notification");
        assert_eq!(produced.admitted, 1);
        let records = producer.journal().deliveries().expect("a read");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, DeliveryState::Admitted);
        assert!(records[0].payload_bytes > 0);
    }

    #[test]
    fn a_destination_with_previews_disabled_gets_the_alert_and_no_recipient_key() {
        let mut producer = producer();
        let destination = push_destination("phone", false);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let notice = notice(1_000);
        take_the_event(&mut producer, &notice);
        producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000,
            )
            .expect("a notification");
        let record = producer.journal().deliveries().expect("a read").remove(0);
        let request: PushDeliveryRequest =
            serde_json::from_slice(&record.content.expect("the built body")).expect("a request");
        assert!(
            !request.preview.is_present(),
            "the recipient key is removed from future notifications"
        );
        assert_eq!(request.hints.alert, PushAlert::ApprovalWaiting);
        assert!(request.preview_is_well_formed());
    }

    #[test]
    fn nothing_about_the_work_travels_outside_the_seal() {
        let mut producer = producer();
        let destination = push_destination("phone", true);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let mut notice = notice(1_000);
        notice.summary = "deploy the production database".to_owned();
        notice.collapse_group = "kalareach-secret-project/attention.pending_approval".to_owned();
        take_the_event(&mut producer, &notice);
        producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000,
            )
            .expect("a notification");
        let record = producer.journal().deliveries().expect("a read").remove(0);
        let body = String::from_utf8(record.content.expect("the built body")).expect("text");
        assert!(
            !body.contains("deploy the production database"),
            "no command text in plaintext"
        );
        assert!(
            !body.contains("kalareach-secret-project"),
            "the collapse identifier reveals no project name"
        );
        assert!(
            body.contains("approval_waiting"),
            "the alert is one of the six"
        );
    }

    #[test]
    fn an_external_destination_whose_grant_is_gone_sends_nothing() {
        let mut producer = producer();
        let destination = webhook("hook");
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let notice = notice(1_000);
        take_the_event(&mut producer, &notice);
        let produced = producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Revoked,
                &[ContentLine {
                    session_id: Some(session(1)),
                    produced_at_ms: Some(900),
                    text: "a command failed".to_owned(),
                }],
                1_000,
            )
            .expect("a decision");
        assert_eq!(produced.admitted, 0);
        assert_eq!(produced.refused.len(), 1);
        assert!(producer.journal().deliveries().expect("a read").is_empty());
    }

    #[test]
    fn an_external_message_carries_the_notice_that_its_recipients_can_read_it() {
        let mut producer = producer();
        let destination = webhook("hook");
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let notice = notice(1_000);
        take_the_event(&mut producer, &notice);
        producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything([session(1)].into_iter().collect()),
                &[ContentLine {
                    session_id: Some(session(1)),
                    produced_at_ms: Some(900),
                    text: "a command failed".to_owned(),
                }],
                1_000,
            )
            .expect("a message");
        let record = producer.journal().deliveries().expect("a read").remove(0);
        let body = String::from_utf8(record.content.expect("the built body")).expect("text");
        assert!(body.contains("does not make it private"));
    }

    #[test]
    fn the_burst_is_admitted_and_the_rest_collapse_with_every_request_retained() {
        let mut producer = producer();
        let destination = push_destination("phone", true);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        for number in 0..25u64 {
            let mut notice = notice(1_000);
            notice.event =
                EventKey::announcement(Some(session(1)), "attention.pending_approval/x", number);
            producer
                .take(EventSource::Attention, &[notice.taken(number)], number)
                .expect("a page");
            producer
                .produce(
                    &notice,
                    std::slice::from_ref(&destination),
                    &Everything(BTreeSet::new()),
                    &[],
                    1_000,
                )
                .expect("a decision");
        }
        let records = producer.journal().deliveries().expect("a read");
        assert_eq!(records.len(), 25, "every request is retained");
        let collapsed = records
            .iter()
            .filter(|record| record.state == DeliveryState::Collapsed)
            .count();
        assert_eq!(collapsed, 4, "four collapsed into the one attention update");
        let update = records
            .iter()
            .find(|record| record.suppression.is_some() && record.content.is_some())
            .expect("one attention update went out");
        let request: PushDeliveryRequest =
            serde_json::from_slice(update.content.as_ref().expect("a body")).expect("a request");
        assert_eq!(request.hints.alert, PushAlert::AttentionUpdate);
    }

    #[test]
    fn a_result_from_an_earlier_generation_is_not_published() {
        let mut producer = producer();
        assert!(producer.publish_under(0).is_ok());
        producer.journal_mut().fence(1).expect("a fence");
        assert!(matches!(
            producer.publish_under(0),
            Err(DeliveryError::LateResult {
                produced_under: 0,
                in_force: 1
            })
        ));
        assert!(producer.publish_under(1).is_ok());
    }

    #[test]
    fn a_fenced_environment_produces_nothing() {
        let mut producer = producer();
        let destination = push_destination("phone", true);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let notice = notice(1_000);
        take_the_event(&mut producer, &notice);
        producer.journal_mut().fence(1).expect("a fence");
        assert!(matches!(
            producer.produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000
            ),
            Err(DeliveryError::Fenced)
        ));
    }

    #[test]
    fn every_attention_rule_maps_to_one_of_the_six_alerts() {
        for rule in [
            AttentionRule::PendingApproval,
            AttentionRule::PendingInput,
            AttentionRule::InputIdleReminder,
            AttentionRule::CommandFailed,
            AttentionRule::ReviewReady,
            AttentionRule::AdapterFailed,
            AttentionRule::HostContactLost,
            AttentionRule::ApplicationNotice,
        ] {
            assert!(PushAlert::ALL.contains(&alert_for(rule)));
        }
        assert_eq!(urgency_for(AttentionLevel::Urgent), PushUrgency::Attention);
        assert_eq!(
            urgency_for(AttentionLevel::Informational),
            PushUrgency::Deferred
        );
    }
}
