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
    DeliveryJournal, DeliveryRecord, DeliveryState, EventKey, EventSource, TakenEvent,
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    ///
    /// The notice travels into the event row, so a host that takes the event and stops before
    /// producing comes back to something it can still produce from.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Encoding`] when the notice cannot be represented in KR-CBOR-1.
    pub fn taken(&self, source_cursor: u64) -> Result<TakenEvent> {
        Ok(TakenEvent {
            key: self.event.clone(),
            source_cursor,
            session_id: self.session_id,
            recorded_at_ms: self.observed_at_ms,
            notice: kr_cbor::to_canonical_vec(self)?,
        })
    }
}

/// One underlying event that is worth recording and warrants no notification.
///
/// The worker outbox carries every state transition, and most of them are nobody's notification.
/// Taking them is still what makes this journal a registered consumer with a claim on collection,
/// and the empty notice is what says the event needs nothing produced from it.
#[must_use]
pub fn observed(
    key: EventKey,
    source_cursor: u64,
    session_id: Option<SessionId>,
    recorded_at_ms: TimestampMs,
) -> TakenEvent {
    TakenEvent {
        key,
        source_cursor,
        session_id,
        recorded_at_ms,
        notice: Vec::new(),
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

/// A digest of the authority one notification was admitted under.
///
/// Section 19 intersects the content policy with the recipient's own authority, so the dispatch
/// has to be able to ask again and see whether the answer has changed. A digest is what makes that
/// one comparison rather than a second copy of the grant in this journal.
///
/// A push destination has no viewer scope: the recipient is the paired device and the content is
/// sealed to its own key, so the rule is the whole of it. An external destination has both,
/// because the grant decides which sessions' lines may be in the message at all.
///
/// The scope is digested through its debug rendering, which is the only total view of it this
/// crate has and is stable for a build: what matters is that two scopes that differ anywhere
/// produce two digests.
#[must_use]
pub fn authority_digest(
    rule: &DeliveryRule,
    scope: Option<(&ViewerScope, &BTreeSet<SessionId>)>,
) -> String {
    use std::fmt::Write as _;

    let mut input = format!(
        "rule={};grant={};",
        rule.name,
        rule.grant_id
            .map_or_else(|| "-".to_owned(), |grant| grant.to_string())
    );
    match scope {
        Some((scope, sessions)) => {
            let _ = write!(input, "scope={scope:?};sessions=");
            for session in sessions {
                let _ = write!(input, "{session},");
            }
        }
        None => input.push_str("scope=-;"),
    }
    kr_cbor::sha256(input.as_bytes())
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
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
    mailbox_key: kr_crypto::keys::StoredEnvelopeKeyPair,
    collapse_secret: [u8; 32],
}

/// How many unproduced events one recovery pass finishes.
pub const MAX_PENDING_PER_PASS: usize = 256;

/// How many outbox records one pass takes from a worker's journal.
pub const MAX_OUTBOX_PAGE: u64 = 256;

impl Producer {
    /// Builds a producer over one delivery journal.
    ///
    /// The two keys are this host's own: the notification-preview keypair a preview is sealed
    /// from, and the stored-envelope keypair an encrypted object is sealed from when a preview's
    /// excess detail has to move into one.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the journal cannot be written.
    pub fn new(
        mut journal: DeliveryJournal,
        preview_key: kr_crypto::keys::NotificationPreviewKeyPair,
        mailbox_key: kr_crypto::keys::StoredEnvelopeKeyPair,
    ) -> Result<Self> {
        let collapse_secret = journal.collapse_secret()?;
        Ok(Self {
            journal,
            preview_key,
            mailbox_key,
            collapse_secret,
        })
    }

    /// Takes every announcement one attention store is offering, and settles them afterwards.
    ///
    /// The order is T-037's rule 5 and T-040's residual 5 together: take, record durably with the
    /// cursor, then settle. A host that dies before the settlement is offered the same
    /// announcements again and the event keys absorb them; one that dies before the local
    /// transaction has settled nothing, so nothing is lost either way.
    ///
    /// `scope` names the store, because a cursor is a position in one store and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Source`] when the attention store cannot be read or settled, and
    /// [`DeliveryError::JournalUnavailable`] when this journal cannot be written.
    pub fn take_from_attention(
        &mut self,
        attention: &mut kr_attention::Attention,
        scope: &str,
        now_ms: u64,
    ) -> Result<Vec<Notice>> {
        let consumer = EventSource::Attention.consumer(scope);
        self.journal.register_consumer(&consumer, now_ms)?;
        let announcements = attention
            .take_announcements()
            .map_err(|error| DeliveryError::Source(error.to_string()))?;
        if announcements.is_empty() {
            return Ok(Vec::new());
        }
        let mut notices = Vec::with_capacity(announcements.len());
        let mut events = Vec::with_capacity(announcements.len());
        let mut settled = Vec::with_capacity(announcements.len());
        let mut cursor = self
            .journal
            .consumer_cursor(&consumer)?
            .map_or(0, |held| held.cursor);
        for announcement in &announcements {
            let notice = Notice::from_announcement(announcement, now_ms);
            events.push(notice.taken(announcement.number)?);
            settled.push((announcement.key.clone(), announcement.number));
            cursor = cursor.max(announcement.number);
            notices.push(notice);
        }
        self.journal.take_events(&consumer, &events, cursor)?;
        attention
            .settle_announcements(&settled)
            .map_err(|error| DeliveryError::Source(error.to_string()))?;
        Ok(notices)
    }

    /// Takes one page of a worker's outbox, and tells the worker afterwards.
    ///
    /// Registration comes first and is repeated on every pass, because a consumer that has not
    /// registered has no claim on what collection removes. The acknowledgement comes after the
    /// local transaction, for the same reason the attention settlement does.
    ///
    /// Every record is taken, and only the ones a caller turns into a [`Notice`] produce anything.
    /// That is what makes this journal a registered consumer of the whole stream rather than of
    /// the part it happens to notify about.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Source`] when the worker's journal cannot be read or told, and
    /// [`DeliveryError::JournalUnavailable`] when this journal cannot be written.
    pub fn take_from_outbox(
        &mut self,
        worker: &mut kr_worker::journal::Journal,
        scope: &str,
        session_id: Option<SessionId>,
        now_ms: u64,
    ) -> Result<Vec<(EventKey, kr_worker::persistence::outbox::OutboxRecord)>> {
        let consumer = EventSource::WorkerOutbox.consumer(scope);
        self.journal.register_consumer(&consumer, now_ms)?;
        let cursor = self
            .journal
            .consumer_cursor(&consumer)?
            .map_or(0, |held| held.cursor);
        worker
            .note_outbox_consumed(&consumer, cursor, 0)
            .map_err(|error| DeliveryError::Source(error.to_string()))?;
        let page = worker
            .outbox_after(cursor, MAX_OUTBOX_PAGE)
            .map_err(|error| DeliveryError::Source(error.to_string()))?;
        if page.is_empty() {
            return Ok(Vec::new());
        }
        let mut events = Vec::with_capacity(page.len());
        let mut taken = Vec::with_capacity(page.len());
        let mut highest = cursor;
        for record in page {
            let key = EventKey::outbox(&record.event.event_id);
            events.push(observed(
                key.clone(),
                record.cursor,
                session_id,
                record.event.recorded_at_ms,
            ));
            highest = highest.max(record.cursor);
            taken.push((key, record));
        }
        let applied = self.journal.take_events(&consumer, &events, highest)?;
        worker
            .note_outbox_consumed(&consumer, highest, applied as u64)
            .map_err(|error| DeliveryError::Source(error.to_string()))?;
        Ok(taken)
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
        scope: &str,
        events: &[TakenEvent],
        cursor: u64,
        now_ms: u64,
    ) -> Result<usize> {
        let consumer = source.consumer(scope);
        self.journal.register_consumer(&consumer, now_ms)?;
        self.journal.take_events(&consumer, events, cursor)
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
        // T-040's rule at the one place this crate publishes. The notice was captured under a
        // generation; notifications built from it are that work's results, and a result produced
        // under a generation that is no longer in force belongs to work privacy mode ended.
        // [`DeliveryJournal::produce`] checks the same thing inside its own transaction, so this
        // is the early refusal rather than the only one.
        self.publish_under(self.journal.event_generation(&notice.event)?)?;
        push::check_expiry(now_ms, notice.expires_at_ms)?;
        let generation = self.journal.generation()?;
        let mut produced = Produced::default();
        let mut records = Vec::new();
        let mut spent = Vec::new();
        for destination in destinations {
            if !destination.enabled {
                continue;
            }
            let outcome = match &destination.destination {
                Destination::Push(_) => self.build_push(notice, destination, generation, now_ms),
                Destination::External(_) => self
                    .build_external(notice, destination, authority, lines, generation, now_ms)
                    .map(|record| (record, None)),
            };
            match outcome {
                Ok((record, budget)) => {
                    if record.state == DeliveryState::Collapsed {
                        produced.collapsed += 1;
                    } else {
                        produced.admitted += 1;
                    }
                    records.push(record);
                    if let Some(budget) = budget {
                        spent.push((destination.id.clone(), budget));
                    }
                }
                Err(error) => produced
                    .refused
                    .push((destination.id.clone(), error.to_string())),
            }
        }
        // One transaction: every notification this event produced, what they spent, and the
        // event's own completion. A crash before it leaves the event unproduced, so the recovery
        // pass produces from it again and nothing has been charged for a notification nobody
        // admitted.
        if !self.journal.produce(&notice.event, &records, &spent)? {
            return Ok(Produced {
                events_taken: 0,
                admitted: 0,
                collapsed: 0,
                refused: Vec::new(),
            });
        }
        Ok(produced)
    }

    /// Finishes every event this journal took and produced nothing from.
    ///
    /// A restart runs it before it reads a new page: the source's cursor has already moved past
    /// those events, so nothing else will offer them again. `notice_of` decodes the notice the
    /// caller committed with the event.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::JournalUnavailable`] when the journal cannot be read or written.
    pub fn finish_pending(
        &mut self,
        destinations: &[DestinationRecord],
        authority: &dyn RecipientAuthority,
        now_ms: u64,
    ) -> Result<Produced> {
        let mut total = Produced::default();
        for pending in self.journal.pending_events(MAX_PENDING_PER_PASS)? {
            if pending.notice.is_empty() {
                // An event worth recording and nobody's notification. Marking it produced is what
                // takes it out of the recovery pass.
                self.journal.produce(&pending.key, &[], &[])?;
                continue;
            }
            let Ok(notice) =
                kr_cbor::from_canonical_slice::<Notice>(&pending.notice, &kr_cbor::Limits::DEFAULT)
            else {
                // A notice this build cannot read is left where it is rather than dropped: the
                // event stays unproduced and says so, which is a state a person can look at.
                total
                    .refused
                    .push((DestinationId::new("-")?, pending.key.stored()));
                continue;
            };
            let produced = self.produce(&notice, destinations, authority, &[], now_ms)?;
            total.admitted += produced.admitted;
            total.collapsed += produced.collapsed;
            total.refused.extend(produced.refused);
        }
        Ok(total)
    }

    fn build_push(
        &mut self,
        notice: &Notice,
        destination: &DestinationRecord,
        generation: u64,
        now_ms: u64,
    ) -> Result<(DeliveryRecord, Option<crate::journal::StoredBudget>)> {
        let push = destination
            .as_push()
            .ok_or_else(|| DeliveryError::NoDestination(destination.id.to_string()))?
            .clone();
        // Section 25's first half applies to a paired device too: a destination with no rule is a
        // destination nobody decided to send to.
        let rule = destination.require_rule()?;
        let destination_digest = destination.binding_digest();
        let authority_digest = authority_digest(rule, None);

        let notification_id = preview::fresh_notification_id();
        let mut budget = self
            .journal
            .budget(&destination.id)?
            .map_or_else(|| Budget::fresh(now_ms), |stored| Budget::restored(&stored));
        let decision = budget.admit(now_ms, preview::fresh_notification_id);

        let (identifier, suppression) = match decision {
            Admission::Send => (notification_id, None),
            Admission::Collapse { suppression } => {
                // Nothing is sent, and the request is still retained: section 16's *the host
                // retains every request and reports suppression locally* is this row.
                return Ok((
                    DeliveryRecord {
                        notification_id,
                        event: notice.event.clone(),
                        destination_id: destination.id.clone(),
                        state: DeliveryState::Collapsed,
                        privacy_generation: generation,
                        destination_digest,
                        authority_digest,
                        content: None,
                        payload_bytes: 0,
                        expires_at_ms: notice.expires_at_ms,
                        admitted_at_ms: TimestampMs::new(now_ms),
                        attempts: 0,
                        suppression: Some(suppression),
                        detail: Some(
                            "the destination is over this host's own rate policy, so this \
                             collapsed into an attention update"
                                .to_owned(),
                        ),
                        dispatched: false,
                    },
                    Some(budget.stored()),
                ));
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
        let request =
            self.build_request(notice, &push, &destination.id, identifier, alert, now_ms)?;
        let content = preview::encode_request(&request)?;
        let payload_bytes = preview::provider_payload_bytes(&request)?;
        Ok((
            DeliveryRecord {
                notification_id: identifier,
                event: notice.event.clone(),
                destination_id: destination.id.clone(),
                state: DeliveryState::Admitted,
                privacy_generation: generation,
                destination_digest,
                authority_digest,
                content: Some(content),
                payload_bytes,
                expires_at_ms: notice.expires_at_ms,
                admitted_at_ms: TimestampMs::new(now_ms),
                attempts: 0,
                suppression,
                detail: None,
                dispatched: false,
            },
            Some(budget.stored()),
        ))
    }

    /// Builds the request, moving the excess into a referenced encrypted object if it does not fit.
    ///
    /// Section 16's remedy in order: build it, measure the built body, and if it is over the
    /// bound put the detail somewhere else and build again. Nothing estimates and nothing trims.
    fn build_request(
        &mut self,
        notice: &Notice,
        push: &crate::destination::PushDestination,
        destination_id: &DestinationId,
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
                //
                // The object is a mailbox object, sealed to the destination's stored-envelope key
                // through the ordinary envelope path, because section 16 keeps the preview key for
                // preview envelopes only. A destination that has registered no stored-envelope key
                // has nowhere for the excess to go, so the notification is refused rather than sent
                // with the detail cut out of it.
                let recipient = push.mailbox_key.ok_or(DeliveryError::NoPreviewKey(
                    "this destination has no stored-envelope key, so the excess detail of a \
                     preview has no encrypted object to move into",
                ))?;
                let detail_id = EnvelopeId::new(Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes()));
                let detail = kr_crypto::envelope::seal_envelope(
                    &self.mailbox_key,
                    &recipient,
                    &kr_protocol::mailbox::EnvelopePlaintext {
                        version: kr_protocol::mailbox::EnvelopeVersion::V1,
                        envelope_id: detail_id,
                        sender_key_id: kr_crypto::keys::key_id(
                            kr_protocol::pairing::KeyPurpose::StoredEnvelope,
                            self.mailbox_key.public().as_bytes(),
                        ),
                        recipient_key_id: kr_crypto::keys::key_id(
                            kr_protocol::pairing::KeyPurpose::StoredEnvelope,
                            recipient.as_bytes(),
                        ),
                        payload_type: kr_protocol::mailbox::MailboxPayloadType::StateReference,
                        created_at_ms: TimestampMs::new(now_ms),
                        expires_at_ms: notice.expires_at_ms,
                        grant_id: Nullable::null(),
                        environment_id: body.environment_id,
                        session_id: body.session_id,
                        session_epoch: Nullable::null(),
                        thread_id: Nullable::null(),
                        payload: kr_protocol::scalars::Bytes::new(body.canonical_bytes()?),
                    },
                )?;
                self.journal.keep_object(
                    detail_id,
                    destination_id,
                    &kr_cbor::to_canonical_vec(&detail)?,
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

    fn build_external(
        &mut self,
        notice: &Notice,
        destination: &DestinationRecord,
        authority: &dyn RecipientAuthority,
        lines: &[ContentLine],
        generation: u64,
        now_ms: u64,
    ) -> Result<DeliveryRecord> {
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
        let destination_digest = destination.binding_digest();
        let authority_digest = authority_digest(rule, Some((&scope, &sessions)));
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
        Ok(DeliveryRecord {
            notification_id,
            event: notice.event.clone(),
            destination_id: destination.id.clone(),
            state: DeliveryState::Admitted,
            privacy_generation: generation,
            destination_digest,
            authority_digest,
            content: Some(content),
            payload_bytes,
            expires_at_ms: notice.expires_at_ms,
            admitted_at_ms: TimestampMs::new(now_ms),
            attempts: 0,
            suppression: None,
            detail: None,
            dispatched: false,
        })
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

    /// Records what a restart found, keeping the dispatch fact apart from the authority.
    ///
    /// Two questions, and they have two answers. **Did it leave?** An attempt that was on the
    /// wire when this host stopped has an outcome nobody knows, and that stays true whatever has
    /// since happened to the authorisation: a revocation is not evidence about delivery. So every
    /// interrupted attempt is recorded as an unknown outcome, and section 23 leaves it there
    /// until a reconciliation reads the receipt.
    ///
    /// **May it still be sent?** That is what `still_authorised` answers, and it applies to the
    /// records nothing has dispatched. Section 24 resumes *only what is still authorised*, so a
    /// queued notification for a destination whose authorisation has ended is taken back; one
    /// that is still authorised stays in the outbox for the ordinary loop.
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
            let detail = if still_authorised(&record.destination_id) {
                "this host stopped while the attempt was on the wire, so its outcome is unknown \
                 and it is not retried automatically"
                    .to_owned()
            } else {
                "this host stopped while the attempt was on the wire and the authorisation has \
                 since ended; what became of the attempt is still unknown"
                    .to_owned()
            };
            let recorded = self.journal.record_attempt(&crate::journal::Transition {
                notification_id: record.notification_id,
                attempt: record.attempts.max(1),
                state: DeliveryState::OutcomeUnknown,
                started_at_ms: record.admitted_at_ms,
                settled_at_ms: Some(TimestampMs::new(now_ms)),
                next_attempt_at_ms: None,
                detail: Some(detail),
                suppression: None,
                keep_content: true,
                // It was on the wire. Whether it arrived is the unknown; that it left is not.
                left_this_host: true,
            })?;
            if recorded {
                reconciled.push((record.notification_id, DeliveryState::OutcomeUnknown));
            }
        }
        for record in self.journal.undispatched()? {
            if still_authorised(&record.destination_id) {
                continue;
            }
            if self.journal.settle_undispatched(
                record.notification_id,
                DeliveryState::Revoked,
                "the authorisation ended before anything was dispatched",
                now_ms,
            )? {
                reconciled.push((record.notification_id, DeliveryState::Revoked));
            }
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
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a producer")
    }

    /// The scope every test in this module consumes under: one store, one cursor.
    const SCOPE: &str = "session-1";

    /// A push destination, with the two device keypairs a test needs to open what it built.
    fn push_destination_with_keys(
        id: &str,
        previews_enabled: bool,
        mailbox_key: Option<kr_crypto::keys::StoredEnvelopeKeyPair>,
    ) -> (
        DestinationRecord,
        NotificationPreviewKeyPair,
        Option<kr_crypto::keys::StoredEnvelopeKeyPair>,
    ) {
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let record = DestinationRecord {
            id: DestinationId::new(id).expect("an identifier"),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
                sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
                preview_keys: PreviewKeys::only(*device.public(), 1),
                previews_enabled,
                mailbox_key: mailbox_key.as_ref().map(|pair| *pair.public()),
            })),
            rule: Some(DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        };
        (record, device, mailbox_key)
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
        let taken = notice.taken(7).expect("an event record");
        producer
            .take(EventSource::Attention, SCOPE, &[taken], 7, 1_000)
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
            let taken = notice.taken(number).expect("an event record");
            producer
                .take(EventSource::Attention, SCOPE, &[taken], number, 1_000)
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
    fn a_host_that_stopped_before_producing_finishes_the_event_on_the_next_pass() {
        // The cursor has already moved past the event, so nothing upstream will offer it again.
        // The notice committed with it is what makes the second transaction recoverable.
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("delivery.sqlite3");
        let destination = push_destination("phone", true);
        let notice = notice(1_000);
        {
            let mut producer = Producer::new(
                DeliveryJournal::open(&path).expect("a journal"),
                NotificationPreviewKeyPair::generate().expect("a keypair"),
                kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
            )
            .expect("a producer");
            producer
                .journal_mut()
                .configure_destination(&destination)
                .expect("a destination");
            take_the_event(&mut producer, &notice);
            // and then this host stops.
        }
        let mut producer = Producer::new(
            DeliveryJournal::open(&path).expect("a journal"),
            NotificationPreviewKeyPair::generate().expect("a keypair"),
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        )
        .expect("a producer");
        assert_eq!(
            producer.journal().pending_events(10).expect("a read").len(),
            1,
            "the event is waiting, with the notice it was taken with"
        );
        let finished = producer
            .finish_pending(
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                2_000,
            )
            .expect("a recovery pass");
        assert_eq!(finished.admitted, 1);
        assert_eq!(producer.journal().deliveries().expect("a read").len(), 1);
        assert!(
            producer
                .journal()
                .pending_events(10)
                .expect("a read")
                .is_empty()
        );
    }

    #[test]
    fn an_event_that_warrants_no_notification_is_still_taken_and_still_finished() {
        let mut producer = producer();
        let key = EventKey::outbox(&Uuid::from_bytes([4; 16]));
        producer
            .take(
                EventSource::WorkerOutbox,
                SCOPE,
                &[observed(key.clone(), 3, None, TimestampMs::new(900))],
                3,
                1_000,
            )
            .expect("a page");
        assert!(
            producer
                .journal()
                .pending_events(10)
                .expect("a read")
                .is_empty(),
            "an event nobody notifies about is decided as it is taken, not left pending"
        );
        assert!(
            producer.journal().has_event(&key).expect("a read"),
            "it is still an event this journal has taken"
        );
        producer
            .finish_pending(&[], &Everything(BTreeSet::new()), 1_000)
            .expect("a recovery pass");
        assert!(producer.journal().deliveries().expect("a read").is_empty());
    }

    #[test]
    fn a_preview_that_does_not_fit_moves_its_detail_into_an_encrypted_object() {
        let host_mailbox = kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair");
        let host_mailbox_public = *host_mailbox.public();
        let mut producer = Producer::new(
            DeliveryJournal::in_memory().expect("a journal"),
            NotificationPreviewKeyPair::generate().expect("a keypair"),
            host_mailbox,
        )
        .expect("a producer");
        let device_mailbox = kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair");
        let (destination, device_preview, device_mailbox) =
            push_destination_with_keys("phone", true, Some(device_mailbox));
        let device_mailbox = device_mailbox.expect("the device's mailbox keypair");
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let mut notice = notice(1_000);
        // Long enough that the built provider payload is over the bound.
        notice.summary = "x".repeat(1_400);
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
        assert_eq!(
            produced.admitted, 1,
            "the remedy is applied rather than the notification refused"
        );
        let record = producer.journal().deliveries().expect("a read").remove(0);
        let request: PushDeliveryRequest =
            serde_json::from_slice(record.content.as_ref().expect("a body")).expect("a request");
        assert!(request.preview_is_well_formed());
        let body = crate::preview::open_preview(
            &device_preview,
            producer.preview_public(),
            request.preview.as_ref().expect("a preview"),
            1_500,
        )
        .expect("the preview opens");
        assert_eq!(body.summary, "", "the text moved out of the preview");
        let detail_id = *body.detail_object.as_ref().expect("a reference");

        // The detail is a mailbox object on this host, sealed to the device's stored-envelope key
        // and not to its preview key, and it opens to the whole body.
        let sealed: kr_protocol::mailbox::SealedEnvelope = kr_cbor::from_canonical_slice(
            &producer
                .journal()
                .object(detail_id)
                .expect("a read")
                .expect("the object"),
            &kr_cbor::Limits::DEFAULT,
        )
        .expect("a sealed envelope");
        let opened = kr_crypto::envelope::open_envelope(
            &device_mailbox,
            &host_mailbox_public,
            &sealed,
            1_500,
            |_| Ok(()),
        )
        .expect("the encrypted object opens");
        let detail: PreviewBody =
            kr_cbor::from_canonical_slice(opened.payload.as_slice(), &kr_cbor::Limits::DEFAULT)
                .expect("the whole body");
        assert_eq!(detail.summary.len(), 1_400, "nothing was trimmed");
        assert!(record.payload_bytes < kr_protocol::push::MAX_PROVIDER_PAYLOAD_BYTES);
    }

    #[test]
    fn a_destination_with_no_encrypted_object_refuses_an_oversized_notification() {
        let mut producer = producer();
        let (destination, _, _) = push_destination_with_keys("phone", true, None);
        producer
            .journal_mut()
            .configure_destination(&destination)
            .expect("a destination");
        let mut notice = notice(1_000);
        notice.summary = "x".repeat(1_400);
        take_the_event(&mut producer, &notice);
        let produced = producer
            .produce(
                &notice,
                std::slice::from_ref(&destination),
                &Everything(BTreeSet::new()),
                &[],
                1_000,
            )
            .expect("a decision");
        assert_eq!(produced.admitted, 0);
        assert_eq!(produced.refused.len(), 1);
        assert!(
            produced.refused[0].1.contains("encrypted object"),
            "the refusal says what is missing rather than trimming the text"
        );
        assert!(producer.journal().deliveries().expect("a read").is_empty());
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
