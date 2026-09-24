//! Webhook, Slack, email, Discord and Telegram delivery, on the host.
//!
//! # The sentence that is not negotiable
//!
//! Section 19: *external delivery sends content to the named service and its recipients. It cannot
//! inherit a claim that only encrypted KalaReach endpoints can read that content.* Section 25
//! repeats it: *their recipients can read delivered content; encrypted KR routing does not make
//! those external messages private.*
//!
//! So [`RECIPIENTS_CAN_READ`] is appended to every composed message by [`compose`], which is the
//! standard constructor for messages composed from host content. There is no confidentiality
//! claim anywhere in this module, and an interface that reports on a destination has
//! [`ExternalDestination`]'s own [`DestinationKind::recipients_read_the_content`] to say the same
//! thing in its own words.
//!
//! # Authority, which is not configuration
//!
//! Section 25 requires *a configured destination and an explicit rule or grant*. Two facts, so two
//! checks. The rule lives on the destination record; the grant is what the content is intersected
//! with, through the history filter, and the filter answers **when** rather than **which
//! resource**: `ViewerScope` carries no session selector, so the caller checks resource authority
//! itself. [`compose`] therefore takes both the filter and the resources the grant names, and a
//! line that fails either is withheld with the reason it was withheld for.
//!
//! # Retry, and the uncertainty that is marked instead
//!
//! Section 25: *retry only idempotent delivery IDs where the destination supports them, and mark
//! duplicate-delivery uncertainty otherwise.* A destination that deduplicates by an identifier the
//! host chooses is retried after an unknown outcome, because a repeat is not a second message. One
//! that does not is **not** retried: the record settles as
//! [`DeliveryState::DuplicateUncertain`](crate::journal::DeliveryState::DuplicateUncertain), which
//! says the message may have arrived and may have arrived twice, and a person is told that rather
//! than a guess.

use std::collections::BTreeSet;

use kr_protocol::delivery::DestinationSecret;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{NotificationId, SessionId};
use kr_protocol::push::PushAlert;
use kr_protocol::scalars::TimestampMs;
use kr_worker::history_filter::{
    DerivedDecision, HistoryFilter, Provenance, SourceInterval, Surface, Timed,
};

use crate::destination::{DestinationKind, ExternalDestination, Idempotency};
use crate::error::{DeliveryError, Result};
use crate::journal::DeliveryState;
use crate::push::{MAX_ATTEMPTS, NextAction, next_attempt};

/// The sentence every external message carries.
///
/// It is a constant rather than something each adapter writes, because five adapters writing it
/// five ways is five chances for one of them to soften it.
pub const RECIPIENTS_CAN_READ: &str = "Anyone who can read this message's destination can read \
     this message. KalaReach's encrypted routing does not make it private.";

/// One line of content a message may carry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContentLine {
    /// The session it came from, when it came from one.
    ///
    /// A line with no session is host-level: it names no session content and needs no session
    /// grant. A line with one is checked against the resources the grant names.
    pub session_id: Option<SessionId>,
    /// When the content was produced, in UTC milliseconds.
    ///
    /// It is the production time, which is what the history filter asks for. A caller with only an
    /// observation time supplies nothing here and the line is treated as outside the scope, which
    /// is the filter's own instruction for content with no valid mapping.
    pub produced_at_ms: Option<u64>,
    /// The text.
    pub text: String,
}

impl Timed for ContentLine {
    fn produced_at_ms(&self) -> u64 {
        // A line with no production time is placed at the far future, which is outside every
        // grant's history bound in the direction that withholds rather than admits.
        self.produced_at_ms.unwrap_or(u64::MAX)
    }
}

/// Why a line did not reach the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Withheld {
    /// It is outside the viewer's history scope.
    OutsideHistoryScope,
    /// It names a session the grant does not.
    ResourceNotGranted,
    /// It carries no production time, so nothing can place it inside a scope.
    NoProductionTime,
}

impl Withheld {
    /// The stable name this reason is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutsideHistoryScope => "outside_history_scope",
            Self::ResourceNotGranted => "resource_not_granted",
            Self::NoProductionTime => "no_production_time",
        }
    }

    /// Parses a stored reason name back into [`Withheld`].
    #[must_use]
    pub fn from_stored(name: &str) -> Option<Self> {
        match name {
            "outside_history_scope" => Some(Self::OutsideHistoryScope),
            "resource_not_granted" => Some(Self::ResourceNotGranted),
            "no_production_time" => Some(Self::NoProductionTime),
            _ => None,
        }
    }
}

/// One message, composed and ready for an adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalMessage {
    /// The identifier the destination deduplicates by, when it deduplicates by one.
    pub delivery_id: Option<String>,
    /// Which generic alert this is about.
    pub alert: PushAlert,
    /// The message body. When built via [`compose`], this ends with [`RECIPIENTS_CAN_READ`].
    pub body: String,
    /// What the content was derived from, published beside it.
    pub provenance: Provenance,
    /// What was kept back, and why, so the message can say it is partial.
    pub withheld: Vec<(Withheld, u64)>,
}

impl ExternalMessage {
    /// Returns true when every line the caller offered reached the message.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.withheld.is_empty()
    }
}

/// What one adapter's attempt produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExternalOutcome {
    /// The destination took it.
    Delivered,
    /// The destination recognised the delivery identifier and did nothing.
    Duplicate,
    /// Nothing left this host.
    NotDispatched {
        /// What happened.
        detail: String,
    },
    /// Nothing of the message left this host, and another attempt would meet the same answer.
    ///
    /// A mail server that offers no TLS, a server whose certificate this host cannot verify, and a
    /// server that refused this host's credential or the recipient before any of the message was
    /// sent are each an answer about the destination, not about this attempt. The message never
    /// left, so there is no uncertainty to mark, and nothing is tried again.
    Unsendable {
        /// What happened.
        detail: String,
    },
    /// The destination refused the message, and a retry cannot change that.
    Refused {
        /// What the destination said.
        detail: String,
    },
    /// Nobody knows whether it arrived.
    Unknown {
        /// What happened.
        detail: String,
    },
}

/// What a host sends an external message through.
///
/// One trait for five services. The credential a kind sends with is read from the host's secret
/// store by the pass that sends, checked against the one the destination was configured with, and
/// handed to the adapter for this one attempt: it never travels through the delivery journal, and
/// a destination that sends with none is given none.
pub trait ExternalSender: std::fmt::Debug {
    /// Sends one message to one destination, with the credential that destination sends with.
    fn send(
        &self,
        destination: &ExternalDestination,
        credential: Option<&DestinationSecret>,
        message: &ExternalMessage,
    ) -> ExternalOutcome;
}

/// Composes one message from content the viewer is allowed to see.
///
/// `sessions` is the grant's own session selector. The history filter decides *when*, so this
/// decides *which resource*, which is the division the history filter states: its scope carries no
/// session selector and every caller checks its own resources.
///
/// # Errors
///
/// Returns [`DeliveryError::NotAuthorised`] when the derived answer may not be served at all,
/// which is a grant whose history scope covers none of the interval the content came from.
pub fn compose(
    kind: DestinationKind,
    alert: PushAlert,
    lines: Vec<ContentLine>,
    filter: &HistoryFilter,
    sessions: &SessionSelector,
    delivery_id: Option<String>,
) -> Result<ExternalMessage> {
    if !kind.recipients_read_the_content() {
        return Err(DeliveryError::NotAuthorised(
            "a push destination is not an external destination".to_owned(),
        ));
    }
    let mut withheld: Vec<(Withheld, u64)> = Vec::new();
    let mut count = |reason: Withheld, by: u64| {
        if by == 0 {
            return;
        }
        match withheld.iter_mut().find(|(held, _)| *held == reason) {
            Some((_, total)) => *total = total.saturating_add(by),
            None => withheld.push((reason, by)),
        }
    };

    // Resource authority first, because it does not depend on time and a line the grant does not
    // name is not a line whose timestamp is worth reading.
    let mut candidates = Vec::new();
    for line in lines {
        match line.session_id {
            Some(session) if !sessions.admits(session) => {
                count(Withheld::ResourceNotGranted, 1);
            }
            _ if line.produced_at_ms.is_none() => count(Withheld::NoProductionTime, 1),
            _ => candidates.push(line),
        }
    }

    let filtered = filter.filter(Surface::EventPage, candidates);
    count(Withheld::OutsideHistoryScope, filtered.withheld_entries());
    let kept = filtered.kept;

    let interval = kept
        .iter()
        .filter_map(|line| line.produced_at_ms)
        .fold(None::<(u64, u64)>, |bounds, at| {
            Some(bounds.map_or((at, at), |(from, to)| (from.min(at), to.max(at))))
        })
        .map_or_else(
            || SourceInterval::at(0),
            |(from, to)| SourceInterval::new(from, to),
        );
    let mut provenance = Provenance::over(interval);
    provenance.resources = kept
        .iter()
        .filter_map(|line| line.session_id.map(|session| session.to_string()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    // The message is a summary of an interval, so it is a derived surface: the filter says whether
    // it may be served as it stands, has to be rebuilt from a narrower interval, or may not be
    // served at all.
    let provenance = match filter.admit_derived(Surface::Summary, &provenance) {
        DerivedDecision::Serve { provenance } => provenance,
        DerivedDecision::Recompute { interval } => {
            // Rebuilding from the permitted interval is exactly dropping the lines outside it,
            // because this message is its lines and nothing else.
            let before = kept.len() as u64;
            let narrowed: Vec<ContentLine> = kept
                .iter()
                .filter(|line| {
                    line.produced_at_ms
                        .is_some_and(|at| at >= interval.from_ms && at <= interval.to_ms)
                })
                .cloned()
                .collect();
            count(
                Withheld::OutsideHistoryScope,
                before.saturating_sub(narrowed.len() as u64),
            );
            let mut rebuilt = Provenance::over(interval);
            rebuilt.resources = narrowed
                .iter()
                .filter_map(|line| line.session_id.map(|session| session.to_string()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            return Ok(assemble(alert, narrowed, rebuilt, withheld, delivery_id));
        }
        DerivedDecision::Omit { reason } => {
            return Err(DeliveryError::NotAuthorised(format!(
                "this viewer may not be served a summary of that interval: {reason:?}"
            )));
        }
    };
    Ok(assemble(alert, kept, provenance, withheld, delivery_id))
}

fn assemble(
    alert: PushAlert,
    lines: Vec<ContentLine>,
    provenance: Provenance,
    withheld: Vec<(Withheld, u64)>,
    delivery_id: Option<String>,
) -> ExternalMessage {
    let mut body = String::new();
    body.push_str(alert.generic_text());
    for line in &lines {
        body.push('\n');
        body.push_str(&line.text);
    }
    if !withheld.is_empty() {
        let total: u64 = withheld.iter().map(|(_, count)| *count).sum();
        body.push_str(&format!(
            "\n\n{total} item(s) were left out of this message: {}.",
            withheld
                .iter()
                .map(|(reason, count)| format!("{count} {}", reason.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    body.push_str("\n\n");
    body.push_str(RECIPIENTS_CAN_READ);
    ExternalMessage {
        delivery_id,
        alert,
        body,
        provenance,
        withheld,
    }
}

/// Returns the delivery identifier for one notification at one destination.
///
/// `None` for a destination with no idempotent identifier, which is what stops a retry being
/// scheduled for it: the absence of the field and the absence of the retry are the same fact.
#[must_use]
pub fn delivery_id(
    destination: &ExternalDestination,
    notification_id: NotificationId,
) -> Option<String> {
    match &destination.idempotency {
        Idempotency::Supported { .. } => Some(notification_id.to_string()),
        Idempotency::Unsupported => None,
    }
}

/// What one external answer means for the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalDecision {
    /// The state the record moves to.
    pub state: DeliveryState,
    /// What the host does next.
    pub next: NextAction,
    /// When, when it does anything.
    pub next_attempt_at_ms: Option<TimestampMs>,
    /// One line for the journal.
    pub detail: String,
    /// Whether this attempt reached a point where the message could have left this host.
    ///
    /// A destination that answered has it, including one that refused the message: the service
    /// read it either way. An outcome nobody knows has it too, which is the whole of section 25's
    /// duplicate-delivery uncertainty. A connection that was never established does not.
    pub left_this_host: bool,
    /// Whether the destination itself reported this state, rather than this host deciding to stop.
    ///
    /// A service that took the message, refused it or recognised it as one it already had is
    /// saying what became of it. This host running out of attempts is saying when it stopped
    /// asking, which settles nothing.
    pub reported_by_destination: bool,
}

/// Decides what one external answer means, under section 25's retry rule.
#[must_use]
pub fn decide_external(
    outcome: &ExternalOutcome,
    idempotency: &Idempotency,
    notification_id: NotificationId,
    attempt: u64,
    now_ms: u64,
    expires_at_ms: TimestampMs,
) -> ExternalDecision {
    let settle = |state: DeliveryState, detail: String, left_this_host: bool| ExternalDecision {
        state,
        next: NextAction::None,
        next_attempt_at_ms: None,
        detail,
        left_this_host,
        // This host's own decision to stop, not the service's account of what it did.
        reported_by_destination: false,
    };
    let reported = |state: DeliveryState, detail: String| ExternalDecision {
        reported_by_destination: true,
        ..settle(state, detail, true)
    };
    match outcome {
        ExternalOutcome::Delivered => reported(
            DeliveryState::Accepted,
            "the destination accepted the message".to_owned(),
        ),
        ExternalOutcome::Duplicate => reported(
            DeliveryState::Duplicate,
            "the destination had already seen this delivery identifier".to_owned(),
        ),
        // The destination read the message and refused it, so the content reached the service
        // whatever it decided to do with it.
        ExternalOutcome::Refused { detail } => reported(
            DeliveryState::Refused,
            format!("the destination refused the message: {detail}"),
        ),
        // Section 25: retry only idempotent delivery IDs where the destination supports them,
        // and mark duplicate-delivery uncertainty otherwise.
        ExternalOutcome::NotDispatched { detail } if idempotency.supports_retry() => {
            match next_attempt(notification_id, attempt, now_ms, expires_at_ms) {
                Some(at) => ExternalDecision {
                    state: DeliveryState::Retrying,
                    next: NextAction::Send,
                    next_attempt_at_ms: Some(at),
                    detail: format!("nothing was dispatched, so it is sent again: {detail}"),
                    left_this_host: false,
                    reported_by_destination: false,
                },
                None if attempt >= MAX_ATTEMPTS => settle(
                    DeliveryState::Abandoned,
                    format!("{MAX_ATTEMPTS} attempts reached nothing: {detail}"),
                    false,
                ),
                None => settle(
                    DeliveryState::Expired,
                    format!("the message expired before it was dispatched: {detail}"),
                    false,
                ),
            }
        }
        ExternalOutcome::NotDispatched { detail } => settle(
            DeliveryState::DuplicateUncertain,
            format!(
                "this destination has no idempotent delivery identifier, so it is not retried \
                 after a dispatch failure: {detail}"
            ),
            false,
        ),
        // Nothing of the message left, and the answer was about the destination rather than the
        // attempt, so there is neither an uncertainty to mark nor a reason to try again.
        ExternalOutcome::Unsendable { detail } => settle(
            DeliveryState::Abandoned,
            format!("nothing was sent, and another attempt would meet the same answer: {detail}"),
            false,
        ),
        ExternalOutcome::Unknown { detail } if idempotency.supports_retry() => {
            match next_attempt(notification_id, attempt, now_ms, expires_at_ms) {
                Some(at) => ExternalDecision {
                    state: DeliveryState::Retrying,
                    next: NextAction::Send,
                    next_attempt_at_ms: Some(at),
                    detail: format!(
                        "the outcome is unknown and this destination deduplicates by the \
                         delivery identifier, so it is sent again: {detail}"
                    ),
                    left_this_host: true,
                    reported_by_destination: false,
                },
                // Section 25 marks the uncertainty rather than resolving it by guessing. This host
                // stopped presenting the message; the destination may still have taken one of the
                // attempts whose answer never arrived, so the message is recorded as possibly
                // delivered rather than as one this host abandoned before it went.
                None if attempt >= MAX_ATTEMPTS => settle(
                    DeliveryState::DuplicateUncertain,
                    format!(
                        "{MAX_ATTEMPTS} attempts reached an unknown outcome, so whether the \
                         destination has it is not something this host can say: {detail}"
                    ),
                    true,
                ),
                None => settle(
                    DeliveryState::DuplicateUncertain,
                    format!(
                        "the outcome is unknown and the message expired before it could be \
                         presented again: {detail}"
                    ),
                    true,
                ),
            }
        }
        ExternalOutcome::Unknown { detail } => settle(
            DeliveryState::DuplicateUncertain,
            format!(
                "the outcome is unknown and this destination has no idempotent delivery \
                 identifier, so it is not sent again: the message may have arrived, and sending \
                 it again could deliver it twice ({detail})"
            ),
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;
    use kr_worker::history_filter::ViewerScope;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn notification(byte: u8) -> NotificationId {
        NotificationId::new(Uuid::from_bytes([byte; 16]))
    }

    fn line(session: Option<SessionId>, at: Option<u64>, text: &str) -> ContentLine {
        ContentLine {
            session_id: session,
            produced_at_ms: at,
            text: text.to_owned(),
        }
    }

    fn granted(sessions: &[SessionId]) -> SessionSelector {
        SessionSelector::These {
            session_ids: sessions.iter().copied().collect(),
        }
    }

    fn webhook(idempotency: Idempotency) -> ExternalDestination {
        ExternalDestination {
            kind: DestinationKind::Webhook,
            endpoint: "https://example.invalid/hook".to_owned(),
            idempotency,
            credential: None,
        }
    }

    #[test]
    fn every_composed_message_says_its_recipients_can_read_it() {
        let filter = HistoryFilter::new(ViewerScope::owner());
        for kind in DestinationKind::EXTERNAL {
            let message = compose(
                kind,
                PushAlert::WorkComplete,
                vec![line(Some(session(1)), Some(1_000), "a turn finished")],
                &filter,
                &granted(&[session(1)]),
                None,
            )
            .expect("a message");
            assert!(
                message.body.ends_with(RECIPIENTS_CAN_READ),
                "{kind} carries the notice"
            );
            assert!(
                !message.body.contains("private")
                    || message.body.contains("does not make it private"),
                "nothing here claims confidentiality"
            );
        }
    }

    #[test]
    fn a_line_from_a_session_the_grant_does_not_name_is_withheld() {
        let filter = HistoryFilter::new(ViewerScope::owner());
        let message = compose(
            DestinationKind::Slack,
            PushAlert::WorkComplete,
            vec![
                line(Some(session(1)), Some(1_000), "inside the grant"),
                line(Some(session(2)), Some(1_000), "outside the grant"),
            ],
            &filter,
            &granted(&[session(1)]),
            None,
        )
        .expect("a message");
        assert!(message.body.contains("inside the grant"));
        assert!(
            !message.body.contains("outside the grant"),
            "the filter decides when; the caller decides which resource"
        );
        assert_eq!(message.withheld, vec![(Withheld::ResourceNotGranted, 1)]);
        assert!(!message.is_complete());
    }

    #[test]
    fn a_line_with_no_production_time_is_treated_as_outside_the_scope() {
        let filter = HistoryFilter::new(ViewerScope::owner());
        let message = compose(
            DestinationKind::Email,
            PushAlert::SessionNeedsAttention,
            vec![line(Some(session(1)), None, "when did this happen")],
            &filter,
            &granted(&[session(1)]),
            None,
        )
        .expect("a message");
        assert_eq!(message.withheld, vec![(Withheld::NoProductionTime, 1)]);
        assert!(!message.body.contains("when did this happen"));
    }

    #[test]
    fn content_before_a_grants_history_bound_does_not_reach_a_recipient() {
        let filter = HistoryFilter::new(ViewerScope::forwarded(5_000));
        let message = compose(
            DestinationKind::Discord,
            PushAlert::WorkComplete,
            vec![
                line(Some(session(1)), Some(1_000), "before the bound"),
                line(Some(session(1)), Some(9_000), "after the bound"),
            ],
            &filter,
            &granted(&[session(1)]),
            None,
        )
        .expect("a message");
        assert!(!message.body.contains("before the bound"));
        assert!(message.body.contains("after the bound"));
        assert!(
            message
                .withheld
                .iter()
                .any(|(reason, _)| *reason == Withheld::OutsideHistoryScope)
        );
        assert!(
            message.body.contains("left out of this message"),
            "a partial message says it is partial"
        );
    }

    #[test]
    fn a_push_destination_is_not_composed_as_an_external_message() {
        let filter = HistoryFilter::new(ViewerScope::owner());
        assert!(matches!(
            compose(
                DestinationKind::Push,
                PushAlert::WorkComplete,
                Vec::new(),
                &filter,
                &granted(&[]),
                None,
            ),
            Err(DeliveryError::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_destination_with_an_idempotent_identifier_is_retried_after_an_unknown_outcome() {
        let decision = decide_external(
            &ExternalOutcome::Unknown {
                detail: "the connection was reset".to_owned(),
            },
            &Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            },
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::Retrying);
        assert_eq!(decision.next, NextAction::Send);
        assert!(decision.next_attempt_at_ms.is_some());
    }

    #[test]
    fn a_destination_without_one_marks_the_uncertainty_rather_than_sending_again() {
        let decision = decide_external(
            &ExternalOutcome::Unknown {
                detail: "the connection was reset".to_owned(),
            },
            &Idempotency::Unsupported,
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::DuplicateUncertain);
        assert_eq!(decision.next, NextAction::None);
        assert_eq!(decision.next_attempt_at_ms, None);
        assert!(decision.detail.contains("could deliver it twice"));
    }

    #[test]
    fn only_destinations_with_idempotent_identifiers_retry_external_dispatch_failures() {
        let supported = decide_external(
            &ExternalOutcome::NotDispatched {
                detail: "the host could not connect".to_owned(),
            },
            &Idempotency::Supported {
                field: "Message-ID".to_owned(),
            },
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(supported.state, DeliveryState::Retrying);
        assert_eq!(supported.next, NextAction::Send);

        let unsupported = decide_external(
            &ExternalOutcome::NotDispatched {
                detail: "the host could not connect".to_owned(),
            },
            &Idempotency::Unsupported,
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(unsupported.state, DeliveryState::DuplicateUncertain);
        assert_eq!(unsupported.next, NextAction::None);
    }

    #[test]
    fn a_delivery_identifier_exists_only_where_the_destination_deduplicates_by_one() {
        assert_eq!(
            delivery_id(&webhook(Idempotency::Unsupported), notification(1)),
            None
        );
        assert_eq!(
            delivery_id(
                &webhook(Idempotency::Supported {
                    field: "Idempotency-Key".to_owned()
                }),
                notification(1)
            ),
            Some(notification(1).to_string()),
            "the identifier is the notification's own, so every attempt presents the same one"
        );
    }

    /// A destination that could not be sent to the way this host sends, before any of the message
    /// left, is abandoned rather than marked uncertain: nothing reached it, and nothing will.
    #[test]
    fn a_message_that_never_left_for_a_reason_about_the_destination_is_abandoned() {
        for idempotency in [
            Idempotency::Unsupported,
            Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            },
        ] {
            let decision = decide_external(
                &ExternalOutcome::Unsendable {
                    detail: "the mail server offers no STARTTLS".to_owned(),
                },
                &idempotency,
                notification(1),
                1,
                1_000,
                TimestampMs::new(1_000_000),
            );
            assert_eq!(decision.state, DeliveryState::Abandoned);
            assert_eq!(decision.next, NextAction::None);
            assert_eq!(decision.next_attempt_at_ms, None);
            assert!(!decision.left_this_host, "nothing of it left");
            assert!(decision.detail.contains("nothing was sent"));
        }
    }

    #[test]
    fn a_refusal_is_not_retried() {
        let decision = decide_external(
            &ExternalOutcome::Refused {
                detail: "the channel does not exist".to_owned(),
            },
            &Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            },
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::Refused);
        assert_eq!(decision.next, NextAction::None);
    }

    #[test]
    fn not_dispatched_past_max_attempts_is_recorded_as_abandoned() {
        let decision = decide_external(
            &ExternalOutcome::NotDispatched {
                detail: "connect timeout".to_owned(),
            },
            &Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            },
            notification(1),
            MAX_ATTEMPTS,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::Abandoned);
        assert_eq!(decision.next, NextAction::None);
        assert!(decision.detail.contains("attempts reached nothing"));
    }

    /// Section 25 marks duplicate-delivery uncertainty rather than resolving it. Attempts this
    /// host stopped making are still attempts whose answers never arrived, so the message is
    /// recorded as one the destination may hold rather than one that never went.
    #[test]
    fn unknown_outcome_past_max_attempts_keeps_the_delivery_uncertain() {
        let decision = decide_external(
            &ExternalOutcome::Unknown {
                detail: "read timeout".to_owned(),
            },
            &Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            },
            notification(1),
            MAX_ATTEMPTS,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::DuplicateUncertain);
        assert_eq!(decision.next, NextAction::None);
        assert!(decision.left_this_host);
        assert!(
            decision
                .detail
                .contains("attempts reached an unknown outcome")
        );
    }

    #[test]
    fn a_message_publishes_the_interval_and_resources_it_was_derived_from() {
        let filter = HistoryFilter::new(ViewerScope::owner());
        let message = compose(
            DestinationKind::Telegram,
            PushAlert::WorkComplete,
            vec![
                line(Some(session(1)), Some(1_000), "first"),
                line(Some(session(1)), Some(9_000), "second"),
            ],
            &filter,
            &granted(&[session(1)]),
            Some("delivery-1".to_owned()),
        )
        .expect("a message");
        assert_eq!(message.provenance.interval.from_ms, 1_000);
        assert_eq!(message.provenance.interval.to_ms, 9_000);
        assert_eq!(message.provenance.resources, vec![session(1).to_string()]);
        assert_eq!(message.delivery_id.as_deref(), Some("delivery-1"));
    }
}
