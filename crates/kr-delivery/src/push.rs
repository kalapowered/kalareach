//! Sending a notification to the gateway, and what each answer means.
//!
//! # Two seams, and why they are two
//!
//! [`PushSender`] presents a delivery. It may cause a dispatch, and nothing else in this crate
//! may. [`DeliveryStatus`] asks what became of a delivery already presented, by its identifier,
//! on a route that answers from what the gateway recorded and carries no content: asking cannot
//! deliver anything, whatever the gateway does with the question.
//!
//! They were one seam with two methods, where reading a decision meant presenting the identical
//! request again. That rests on a promise about the gateway rather than on what the host sends,
//! and a promise is not a property: a gateway that had never seen the identifier, or had lost the
//! claim, would take the repeat as new work and deliver it. A question that carries an identifier
//! and no request cannot.
//!
//! Section 23: *only idempotent reads, transfer chunks and requests whose receipt proves no
//! dispatch may retry automatically. `OUTCOME_UNKNOWN` is not retryable.* So an attempt whose
//! outcome nobody knows settles as [`DeliveryState::OutcomeUnknown`] and the automatic loop leaves
//! it alone for ever. What resolves one is the status question, and a question nobody answers
//! leaves it exactly where it was: unresolved, outstanding, and reported as a copy this host
//! cannot account for.
//!
//! # One identifier is one notification
//!
//! A notification identifier is minted once, from 128 random bits, and every attempt at that
//! notification presents the same request bytes. Reusing an identifier for different content is a
//! conflict at the gateway rather than an update, which is why the built request is stored with
//! the record and resent rather than rebuilt.
//!
//! # Backoff
//!
//! Exponential from [`BASE_BACKOFF_MS`], doubling, capped at [`MAX_BACKOFF_MS`], with jitter, and
//! it stops at the notification's own expiry. The jitter is derived from the notification
//! identifier and the attempt number rather than from a random generator: jitter exists to stop
//! many senders retrying in step, a notification identifier is already 128 random bits, and a
//! derived value makes a retry schedule reproducible in a test instead of flaky.

use kr_protocol::ids::{NotificationId, PushSenderRecordId};
use kr_protocol::push::{
    PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushDeliveryState,
    PushSuppression, SENDER_RENEWAL_WINDOW_MS,
};
use kr_protocol::scalars::TimestampMs;

use crate::error::{DeliveryError, Result};
use crate::journal::DeliveryState;

/// The first backoff, in milliseconds.
pub const BASE_BACKOFF_MS: u64 = 2_000;

/// The longest backoff, in milliseconds.
pub const MAX_BACKOFF_MS: u64 = 5 * 60 * 1000;

/// The most attempts this host makes at one notification before it gives up.
///
/// Expiry usually arrives first. This is the other bound: a notification with a long expiry and a
/// gateway that keeps failing is abandoned rather than retried for a day.
pub const MAX_ATTEMPTS: u64 = 8;

/// The wait before an unanswered status question is asked again, in milliseconds.
pub const QUESTION_BACKOFF_MS: u64 = 5 * 60 * 1000;

/// The longest wait between two questions about one notification, in milliseconds.
pub const MAX_QUESTION_BACKOFF_MS: u64 = 6 * 60 * 60 * 1000;

/// The wait before question `asked + 1` about one notification, after `asked` went unanswered.
///
/// It doubles from [`QUESTION_BACKOFF_MS`] and stops at [`MAX_QUESTION_BACKOFF_MS`].
#[must_use]
pub fn question_backoff_ms(asked: u64) -> u64 {
    let doublings = u32::try_from(asked.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(16);
    QUESTION_BACKOFF_MS
        .saturating_mul(1_u64 << doublings)
        .min(MAX_QUESTION_BACKOFF_MS)
}

/// What one call to the gateway produced.
///
/// The three failures are separated by one question: did the request reach a point where it could
/// have been dispatched? A caller that cannot tell answers [`SendOutcome::Unknown`], which is the
/// safe answer, because it is the one that stops the automatic retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// The gateway decided, and this is what it decided.
    Decided(Box<PushDeliveryAck>),
    /// Nothing was dispatched, and the same request may be presented again.
    ///
    /// A connection that was never established, or a gateway that refused the request before it
    /// claimed the identifier. This is section 23's *requests whose receipt proves no dispatch*.
    NotDispatched {
        /// What happened, for the journal.
        detail: String,
    },
    /// The credential is expired, revoked or aimed at another authorisation.
    ///
    /// Section 16 renews through `push.sender.renew`; it does not retry the delivery, because a
    /// retry with the same credential has the same answer.
    Forbidden {
        /// What the gateway said.
        detail: String,
    },
    /// Nobody knows what became of the request.
    ///
    /// A timeout, a connection reset after the body was written, an answer this host could not
    /// read. It is not retried automatically.
    Unknown {
        /// What happened, for the journal.
        detail: String,
    },
}

/// What a host presents a notification through.
///
/// It is a trait so that a test drives a double and the one implementation that speaks HTTP lives
/// where the daemon's other outbound calls live. Nothing in this crate opens a socket.
pub trait PushSender: std::fmt::Debug + Send + Sync {
    /// Presents one delivery request. May cause a dispatch.
    fn send(
        &self,
        credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome;
}

/// What became of a delivery this host already presented.
///
/// One identifier, no content, no request bytes. An implementation asks a route that reads what
/// the gateway recorded and answers it; an implementation that cannot ask such a route answers
/// [`StatusAnswer::Unanswered`] and the record keeps its uncertainty. Presenting the delivery
/// again is not an implementation of this trait.
pub trait DeliveryStatus: std::fmt::Debug + Send + Sync {
    /// Asks what the gateway recorded for one notification identifier.
    fn status(
        &self,
        credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> StatusAnswer;

    /// Takes one question from this host's allowance at `now_ms`, and says whether there was one
    /// to take.
    ///
    /// A gateway counts status questions against an hourly allowance, whichever of this host's
    /// paths asks them: the pass asking about a notification the gateway is still retrying, and
    /// the sweep over outcomes nobody knows. So both reserve here, from one allowance, before they
    /// ask, and a question that does not fit is not put: the record it was about keeps its place
    /// until one does. An implementation that counts nothing grants every question.
    fn reserve(&self, now_ms: u64) -> bool {
        let _ = now_ms;
        true
    }
}

/// What a status question returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusAnswer {
    /// The gateway answered with the outcome it holds.
    Recorded(Box<PushDeliveryAck>),
    /// The gateway answered, and holds nothing under that identifier.
    ///
    /// It is an answer about the gateway's own records and not about the notification: a request
    /// that never arrived and a record the gateway has since forgotten look the same from here.
    /// Nothing is concluded from it.
    NoRecord {
        /// What the gateway said.
        detail: String,
    },
    /// Nobody answered, so the outcome stays where it was.
    Unanswered {
        /// What happened, for the journal.
        detail: String,
    },
}

/// Where a host gets the bearer credential it delivers under.
///
/// Separate from [`PushSender`] because renewing is a different authorisation with a different
/// proof: delivery presents a bearer, renewal signs with the host key over a fresh gateway nonce.
/// A seam that did both would let a delivery failure reach the signing key.
pub trait SenderCredentials: std::fmt::Debug + Send + Sync {
    /// The credential in force for one authorisation, when this host holds one.
    fn current(&self, sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential>;

    /// Replaces `held`, the credential the caller has and wants replaced, through
    /// `push.sender.renew`.
    ///
    /// The caller names the credential rather than the authorisation, because a renewal is about
    /// one bearer: when another caller has already replaced `held` by the time this one asks, the
    /// answer is that replacement, and renewing it a second time would retire a bearer somebody
    /// may be presenting.
    ///
    /// # Errors
    ///
    /// Returns an error when the gateway refuses the renewal, which is a host that needs a fresh
    /// authorisation from the device rather than another attempt.
    fn renew(&self, held: &PushDeliveryCredential) -> Result<PushDeliveryCredential>;
}

/// Returns true when a credential should be renewed before it is used again.
///
/// Section 16 renews seven days before expiry. Renewing early is what makes renewal work while the
/// phone is asleep: the host proves possession of its own key and needs nobody else awake.
#[must_use]
pub const fn needs_renewal(credential: &PushDeliveryCredential, now_ms: u64) -> bool {
    credential.expires_at_ms.get().saturating_sub(now_ms) <= SENDER_RENEWAL_WINDOW_MS
}

/// What the next thing this host does about one notification is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Nothing. The record has settled.
    None,
    /// Present the request again. Nothing was dispatched, so this may cause one.
    Send,
    /// Read the decision the gateway has already recorded.
    Receipt,
    /// Renew the credential, then present again.
    RenewThenSend,
}

impl NextAction {
    /// Every action, in declaration order.
    pub const ALL: [Self; 4] = [Self::None, Self::Send, Self::Receipt, Self::RenewThenSend];

    /// The stable name this action is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Send => "send",
            Self::Receipt => "receipt",
            Self::RenewThenSend => "renew_then_send",
        }
    }

    /// Reads a stored name back.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|next| next.as_str() == value)
    }

    /// Returns true when this action presents the request to the destination.
    ///
    /// It is what decides whether a record still holds its request bytes. A status question
    /// carries the identifier alone, and a settled record has nothing left to present.
    #[must_use]
    pub const fn presents_request(self) -> bool {
        matches!(self, Self::Send | Self::RenewThenSend)
    }
}

impl std::fmt::Display for NextAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What one answer means for the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The state the record moves to.
    pub state: DeliveryState,
    /// What the host does next.
    pub next: NextAction,
    /// When it does it, when it does anything.
    pub next_attempt_at_ms: Option<TimestampMs>,
    /// One line for the journal and for a person reading it.
    pub detail: String,
    /// What the gateway said it suppressed, when it said anything.
    pub suppression: Option<PushSuppression>,
    /// Whether the destination's token should be taken out of service.
    pub disable_destination: bool,
    /// Whether this attempt reached a point where the notification could have left this host.
    ///
    /// A gateway that answered has it, whatever it answered, because the identifier is claimed
    /// before anything reaches a provider. An outcome nobody knows has it too: not knowing is not
    /// the same as knowing it did not go. A credential the gateway refused and a connection that
    /// was never established do not.
    pub left_this_host: bool,
    /// Whether the destination itself reported this state.
    ///
    /// A gateway that says a notification expired before the provider took it, or that it stopped
    /// trying, is reporting what became of the notification, and that is an answer. This host
    /// running out of attempts, or its own deadline passing, is not: it says when this host
    /// stopped asking. The journal keeps the two apart, because only the second leaves the
    /// outcome open.
    pub reported_by_destination: bool,
}

/// Decides what one gateway answer means.
///
/// `attempt` is the attempt that produced the answer, counting from one.
///
/// It is the one place an answer becomes a state, for a delivery's answer and for a status
/// question's alike, and it applies an answer only to the notification the answer names. An
/// answer about another identifier says nothing about this one: it settles nothing, takes no
/// destination out of service, and leaves the outcome unknown.
#[must_use]
pub fn decide(
    outcome: &SendOutcome,
    notification_id: NotificationId,
    attempt: u64,
    now_ms: u64,
    expires_at_ms: TimestampMs,
) -> Decision {
    let settle = |state: DeliveryState, detail: String| Decision {
        state,
        next: NextAction::None,
        next_attempt_at_ms: None,
        detail,
        suppression: None,
        disable_destination: false,
        left_this_host: false,
        // This host's own decision to stop, not the gateway's account of what happened.
        reported_by_destination: false,
    };
    match outcome {
        SendOutcome::Decided(ack) if ack.notification_id != notification_id => Decision {
            state: DeliveryState::OutcomeUnknown,
            next: NextAction::None,
            next_attempt_at_ms: None,
            detail: format!(
                "the gateway answered about {} rather than this notification, so what became of \
                 this one is unknown",
                ack.notification_id
            ),
            suppression: None,
            disable_destination: false,
            // An answer came back, so the request reached something that answers for the
            // gateway; what it did with this notification is the part nobody knows.
            left_this_host: true,
            reported_by_destination: false,
        },
        SendOutcome::Decided(ack) => {
            decide_from_ack(ack, notification_id, attempt, now_ms, expires_at_ms)
        }
        SendOutcome::Forbidden { detail } => {
            // Section 16: renew through `push.sender.renew` rather than retrying. The delivery is
            // not abandoned; what changes is that the next step is a renewal, and the retry after
            // it is the same request under a credential that works.
            match next_attempt(notification_id, attempt, now_ms, expires_at_ms) {
                Some(at) => Decision {
                    state: DeliveryState::Retrying,
                    next: NextAction::RenewThenSend,
                    next_attempt_at_ms: Some(at),
                    detail: format!("the credential was refused, so it is renewed: {detail}"),
                    suppression: None,
                    disable_destination: false,
                    left_this_host: false,
                    reported_by_destination: false,
                },
                None if attempt >= MAX_ATTEMPTS => settle(
                    DeliveryState::Abandoned,
                    format!("{MAX_ATTEMPTS} attempts reached forbidden credential: {detail}"),
                ),
                None => settle(
                    DeliveryState::Expired,
                    format!("the credential was refused and the notification expired: {detail}"),
                ),
            }
        }
        SendOutcome::NotDispatched { detail } => {
            match next_attempt(notification_id, attempt, now_ms, expires_at_ms) {
                Some(at) => Decision {
                    state: DeliveryState::Retrying,
                    next: NextAction::Send,
                    next_attempt_at_ms: Some(at),
                    detail: format!("nothing was dispatched, so it is presented again: {detail}"),
                    suppression: None,
                    disable_destination: false,
                    left_this_host: false,
                    reported_by_destination: false,
                },
                None if attempt >= MAX_ATTEMPTS => settle(
                    DeliveryState::Abandoned,
                    format!("{MAX_ATTEMPTS} attempts reached nothing: {detail}"),
                ),
                None => settle(
                    DeliveryState::Expired,
                    format!("the notification expired before it was dispatched: {detail}"),
                ),
            }
        }
        SendOutcome::Unknown { detail } => Decision {
            reported_by_destination: false,
            state: DeliveryState::OutcomeUnknown,
            // Nothing automatic. A reconciliation pass reads the receipt, and that pass is asked
            // for rather than scheduled.
            next: NextAction::None,
            next_attempt_at_ms: None,
            detail: format!("the outcome is unknown and is not retried automatically: {detail}"),
            suppression: None,
            disable_destination: false,
            left_this_host: true,
        },
    }
}

fn decide_from_ack(
    ack: &PushDeliveryAck,
    notification_id: NotificationId,
    attempt: u64,
    now_ms: u64,
    expires_at_ms: TimestampMs,
) -> Decision {
    let suppression = ack.suppression.as_ref().cloned();
    let settled = |state: DeliveryState, detail: &str| Decision {
        state,
        next: NextAction::None,
        next_attempt_at_ms: None,
        detail: detail.to_owned(),
        suppression: suppression.clone(),
        disable_destination: false,
        // The gateway answered, and it claims the identifier before anything reaches a provider,
        // so the notification is the gateway's from here whatever the answer was.
        left_this_host: true,
        // And what it answered is its account of what became of the notification.
        reported_by_destination: true,
    };
    match ack.state {
        // Queued is acceptance for delivery. It is recorded as acceptance and never as displayed,
        // read or executed: in-app review state comes from host events and client acknowledgements.
        PushDeliveryState::Queued => settled(
            DeliveryState::Accepted,
            "the provider accepted it for delivery",
        ),
        PushDeliveryState::Retrying => {
            match next_attempt(notification_id, attempt, now_ms, expires_at_ms) {
                Some(at) => Decision {
                    state: DeliveryState::Retrying,
                    // The gateway is holding it and retrying the provider itself, so the host asks
                    // what became of it rather than presenting it as new work.
                    next: NextAction::Receipt,
                    next_attempt_at_ms: Some(at),
                    detail: "the gateway is holding it and retrying the provider".to_owned(),
                    suppression,
                    disable_destination: false,
                    left_this_host: true,
                    reported_by_destination: true,
                },
                // The host has stopped asking; the gateway has not stopped trying. A local limit
                // decides how often this host reads a receipt and decides nothing about what the
                // gateway does with a notification it is holding, so the outcome is the one
                // nobody knows rather than one this host abandoned. The record stays outstanding
                // for privacy mode, keeps the preview key it was sealed to, and a later status
                // question can still resolve it.
                None if attempt >= MAX_ATTEMPTS => Decision {
                    state: DeliveryState::OutcomeUnknown,
                    next: NextAction::None,
                    next_attempt_at_ms: None,
                    detail: format!(
                        "{MAX_ATTEMPTS} receipt reads reached a gateway that was still retrying, \
                         so the outcome is unknown and is not retried automatically"
                    ),
                    suppression,
                    disable_destination: false,
                    left_this_host: true,
                    // The gateway said it was still trying, which is the opposite of an account
                    // of what became of it.
                    reported_by_destination: false,
                },
                // The gateway is still trying and this host's own deadline has passed, which
                // settles nothing about what the gateway does next.
                None => Decision {
                    reported_by_destination: false,
                    ..settled(
                        DeliveryState::Expired,
                        "the notification expired while the gateway was still retrying",
                    )
                },
            }
        }
        PushDeliveryState::Collapsed => settled(
            DeliveryState::Collapsed,
            "the destination was over its rate policy and this collapsed into an attention update",
        ),
        PushDeliveryState::Duplicate => settled(
            DeliveryState::Duplicate,
            "this notification identifier was already handled and the earlier outcome stands",
        ),
        PushDeliveryState::TokenDisabled => Decision {
            reported_by_destination: true,
            state: DeliveryState::TokenDisabled,
            next: NextAction::None,
            next_attempt_at_ms: None,
            detail: "the provider rejected the token, so it is out of service until a native \
                     registration proves receipt again"
                .to_owned(),
            suppression,
            disable_destination: true,
            left_this_host: true,
        },
        PushDeliveryState::Refused => settled(
            DeliveryState::Refused,
            "the provider refused the notification itself, and a retry cannot change that",
        ),
        PushDeliveryState::Revoked => settled(
            DeliveryState::Revoked,
            "the authorisation ended before the provider accepted it",
        ),
        PushDeliveryState::Abandoned => settled(
            DeliveryState::Abandoned,
            "the gateway stopped trying before the notification expired",
        ),
        PushDeliveryState::Expired => settled(
            DeliveryState::Expired,
            "the notification expired before the provider accepted it",
        ),
    }
}

/// Returns when the next attempt is due, or `None` when there will not be one.
///
/// It stops at expiry and at [`MAX_ATTEMPTS`]. A backoff that would land at or past the expiry is
/// not scheduled: waiting for a moment that is already too late is the same as giving up, said
/// less clearly.
#[must_use]
pub fn next_attempt(
    notification_id: NotificationId,
    attempt: u64,
    now_ms: u64,
    expires_at_ms: TimestampMs,
) -> Option<TimestampMs> {
    if attempt >= MAX_ATTEMPTS {
        return None;
    }
    let due = now_ms.saturating_add(backoff_ms(notification_id, attempt));
    (due < expires_at_ms.get()).then(|| TimestampMs::new(due))
}

/// Returns the backoff before attempt `attempt + 1`, in milliseconds.
///
/// Exponential and capped, then jittered into the upper half of the interval: at least half the
/// nominal backoff, so a retry storm cannot compress, and at most the whole of it, so the cap
/// means what it says.
#[must_use]
pub fn backoff_ms(notification_id: NotificationId, attempt: u64) -> u64 {
    let shift = attempt.saturating_sub(1).min(20) as u32;
    let nominal = BASE_BACKOFF_MS
        .saturating_mul(1u64 << shift)
        .min(MAX_BACKOFF_MS);
    let half = nominal / 2;
    half.saturating_add(jitter(notification_id, attempt, half.max(1)))
}

/// A value in `[0, span)`, derived from the notification and the attempt.
fn jitter(notification_id: NotificationId, attempt: u64, span: u64) -> u64 {
    let mut input = Vec::with_capacity(24);
    input.extend_from_slice(notification_id.get().as_bytes());
    input.extend_from_slice(&attempt.to_be_bytes());
    let digest = kr_cbor::sha256(&input);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes) % span.max(1)
}

/// Checks section 16's bound on how far ahead a notification may expire.
///
/// The gateway refuses an expiry more than 24 hours ahead, so a host that built one has built a
/// request that cannot be delivered. Refusing it here says so before anything is sent.
///
/// # Errors
///
/// Returns [`DeliveryError::Expiry`] when the expiry is not ahead of now, or is further ahead than
/// [`MAX_EXPIRY_AHEAD_MS`].
pub fn check_expiry(now_ms: u64, expires_at_ms: TimestampMs) -> Result<()> {
    let expires = expires_at_ms.get();
    if expires <= now_ms {
        return Err(DeliveryError::Expiry(
            "a notification's expiry is ahead of the moment it is produced",
        ));
    }
    if expires.saturating_sub(now_ms) > MAX_EXPIRY_AHEAD_MS {
        return Err(DeliveryError::Expiry(
            "a notification's expiry is at most 24 hours ahead, which is what the gateway admits",
        ));
    }
    Ok(())
}

/// The furthest ahead a notification may expire, in milliseconds.
pub const MAX_EXPIRY_AHEAD_MS: u64 = 24 * 60 * 60 * 1000;

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::CollapseId;
    use kr_protocol::push::{PushSuppressionReason, PushUrgency};
    use kr_protocol::scalars::{Nullable, U64, Uuid};

    fn notification(byte: u8) -> NotificationId {
        NotificationId::new(Uuid::from_bytes([byte; 16]))
    }

    fn ack(state: PushDeliveryState) -> SendOutcome {
        SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(1_000),
            notification_id: notification(1),
            state,
            suppression: Nullable::null(),
        }))
    }

    #[test]
    fn a_queued_answer_is_recorded_as_acceptance_and_never_as_display() {
        let decision = decide(
            &ack(PushDeliveryState::Queued),
            notification(1),
            1,
            1_000,
            TimestampMs::new(100_000),
        );
        assert_eq!(decision.state, DeliveryState::Accepted);
        assert_eq!(decision.next, NextAction::None);
        assert!(decision.detail.contains("accepted it for delivery"));
        assert!(
            !decision.detail.contains("displayed") && !decision.detail.contains("read"),
            "acceptance says acceptance"
        );
    }

    #[test]
    fn a_forbidden_answer_renews_rather_than_retrying_the_same_credential() {
        let decision = decide(
            &SendOutcome::Forbidden {
                detail: "FORBIDDEN".to_owned(),
            },
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.next, NextAction::RenewThenSend);
        assert_eq!(decision.state, DeliveryState::Retrying);
        assert!(decision.next_attempt_at_ms.is_some());
    }

    #[test]
    fn an_unknown_outcome_is_recorded_as_unknown_and_never_retried_automatically() {
        let decision = decide(
            &SendOutcome::Unknown {
                detail: "the connection was reset after the body was written".to_owned(),
            },
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::OutcomeUnknown);
        assert_eq!(decision.next, NextAction::None);
        assert_eq!(decision.next_attempt_at_ms, None);
    }

    #[test]
    fn a_gateway_still_retrying_is_asked_for_a_receipt_rather_than_sent_again() {
        let decision = decide(
            &ack(PushDeliveryState::Retrying),
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.next, NextAction::Receipt);
        assert_eq!(decision.state, DeliveryState::Retrying);
    }

    /// A local limit on how often this host reads a receipt says nothing about a gateway that is
    /// still retrying the provider, so the record keeps the uncertainty rather than claiming this
    /// host abandoned a notification that may still be delivered.
    #[test]
    fn receipt_polling_past_max_attempts_leaves_the_outcome_unknown() {
        let decision = decide(
            &ack(PushDeliveryState::Retrying),
            notification(1),
            MAX_ATTEMPTS,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::OutcomeUnknown);
        assert_eq!(decision.next, NextAction::None);
        assert_eq!(decision.next_attempt_at_ms, None);
        assert!(
            decision.left_this_host,
            "the gateway has it, so it is a retained artifact"
        );
        assert!(decision.state.may_still_arrive());
        assert!(decision.detail.contains("receipt reads"));
    }

    #[test]
    fn forbidden_past_max_attempts_is_recorded_as_abandoned_rather_than_expired() {
        let decision = decide(
            &SendOutcome::Forbidden {
                detail: "credential expired".to_owned(),
            },
            notification(1),
            MAX_ATTEMPTS,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert_eq!(decision.state, DeliveryState::Abandoned);
        assert_eq!(decision.next, NextAction::None);
        assert!(
            decision
                .detail
                .contains("attempts reached forbidden credential")
        );
    }

    #[test]
    fn an_answer_about_another_notification_decides_nothing_about_this_one() {
        for state in [
            PushDeliveryState::Queued,
            PushDeliveryState::TokenDisabled,
            PushDeliveryState::Retrying,
            PushDeliveryState::Expired,
        ] {
            let decision = decide(
                &ack(state),
                notification(2),
                1,
                1_000,
                TimestampMs::new(1_000_000),
            );
            assert_eq!(decision.state, DeliveryState::OutcomeUnknown, "{state:?}");
            assert_eq!(decision.next, NextAction::None);
            assert!(
                !decision.disable_destination,
                "another notification's answer takes no destination out of service"
            );
            assert!(!decision.reported_by_destination);
        }
    }

    #[test]
    fn a_rejected_token_takes_the_destination_out_of_service() {
        let decision = decide(
            &ack(PushDeliveryState::TokenDisabled),
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        assert!(decision.disable_destination);
        assert_eq!(decision.state, DeliveryState::TokenDisabled);
        assert_eq!(decision.next, NextAction::None);
    }

    #[test]
    fn every_gateway_state_has_a_decision_and_none_of_them_invents_a_retry() {
        for state in [
            PushDeliveryState::Queued,
            PushDeliveryState::Collapsed,
            PushDeliveryState::Duplicate,
            PushDeliveryState::TokenDisabled,
            PushDeliveryState::Refused,
            PushDeliveryState::Revoked,
            PushDeliveryState::Abandoned,
            PushDeliveryState::Expired,
        ] {
            let decision = decide(
                &ack(state),
                notification(1),
                1,
                1_000,
                TimestampMs::new(1_000_000),
            );
            assert_eq!(
                decision.next,
                NextAction::None,
                "a decided answer other than retrying is the end of it: {state:?}"
            );
            assert!(decision.state.is_settled());
        }
    }

    #[test]
    fn a_suppression_the_gateway_reported_is_carried_into_the_record() {
        let outcome = SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(1_000),
            notification_id: notification(1),
            state: PushDeliveryState::Collapsed,
            suppression: Nullable::some(PushSuppression {
                collapsed_into: notification(9),
                next_update_at_ms: TimestampMs::new(301_000),
                reason: PushSuppressionReason::Sustained,
                suppressed_count: U64::new(4),
            }),
        }));
        let decision = decide(
            &outcome,
            notification(1),
            1,
            1_000,
            TimestampMs::new(1_000_000),
        );
        let suppression = decision.suppression.expect("the host records it locally");
        assert_eq!(suppression.collapsed_into, notification(9));
        assert_eq!(suppression.suppressed_count.get(), 4);
    }

    #[test]
    fn the_backoff_grows_is_capped_and_stays_in_the_upper_half() {
        let id = notification(5);
        let mut previous = 0;
        for attempt in 1..=6 {
            let backoff = backoff_ms(id, attempt);
            let nominal = (BASE_BACKOFF_MS << (attempt - 1)).min(MAX_BACKOFF_MS);
            assert!(
                backoff >= nominal / 2,
                "attempt {attempt} keeps half the interval"
            );
            assert!(backoff <= nominal, "attempt {attempt} stays inside the cap");
            assert!(
                backoff > previous,
                "attempt {attempt} waits longer than the last"
            );
            previous = backoff;
        }
        assert!(backoff_ms(id, 20) <= MAX_BACKOFF_MS);
    }

    #[test]
    fn the_jitter_spreads_two_notifications_of_one_attempt_apart() {
        let spread: std::collections::BTreeSet<u64> = (0..16)
            .map(|byte| backoff_ms(notification(byte), 4))
            .collect();
        assert!(
            spread.len() > 8,
            "sixteen notifications do not retry in step"
        );
        assert_eq!(
            backoff_ms(notification(1), 4),
            backoff_ms(notification(1), 4),
            "one notification's schedule is reproducible"
        );
    }

    #[test]
    fn retries_stop_at_the_notifications_own_expiry() {
        let id = notification(3);
        assert_eq!(
            next_attempt(id, 1, 1_000, TimestampMs::new(1_500)),
            None,
            "a backoff past the expiry is not a wait, it is giving up"
        );
        assert!(next_attempt(id, 1, 1_000, TimestampMs::new(1_000_000)).is_some());
        assert_eq!(
            next_attempt(id, MAX_ATTEMPTS, 1_000, TimestampMs::new(u64::MAX)),
            None,
            "the attempt bound is the other stop"
        );
    }

    #[test]
    fn an_expiry_more_than_a_day_ahead_is_refused_before_anything_is_sent() {
        assert!(check_expiry(1_000, TimestampMs::new(2_000)).is_ok());
        assert!(check_expiry(1_000, TimestampMs::new(1_000)).is_err());
        assert!(
            check_expiry(1_000, TimestampMs::new(1_000 + MAX_EXPIRY_AHEAD_MS)).is_ok(),
            "exactly a day is admitted"
        );
        assert!(check_expiry(1_000, TimestampMs::new(1_001 + MAX_EXPIRY_AHEAD_MS)).is_err());
    }

    #[test]
    fn a_credential_inside_the_renewal_window_is_renewed_before_it_is_used() {
        let credential = credential(1_000, 1_000 + 30 * 24 * 60 * 60 * 1000);
        assert!(!needs_renewal(&credential, 1_000));
        assert!(needs_renewal(
            &credential,
            credential.expires_at_ms.get() - SENDER_RENEWAL_WINDOW_MS
        ));
        assert!(needs_renewal(&credential, credential.expires_at_ms.get()));
    }

    fn credential(issued: u64, expires: u64) -> PushDeliveryCredential {
        PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(expires),
            gateway_origin: kr_protocol::service::GatewayOrigin::new("https://example.invalid")
                .expect("an origin"),
            installation_id: kr_protocol::ids::InstallationId::new(Uuid::from_bytes([2; 16])),
            issued_at_ms: TimestampMs::new(issued),
            revision: kr_protocol::ids::PushSenderRevision::new(1),
            secret: kr_protocol::scalars::SecretBytes32::from_bytes([9; 32]),
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
        }
    }

    #[test]
    fn a_collapse_identifier_is_not_a_notification_identifier() {
        // Two different types, so a producer cannot put one where the other goes. The check is
        // here because both are 128-bit values on the wire.
        let collapse = CollapseId::new(Uuid::from_bytes([1; 16]));
        let notification = notification(1);
        assert_eq!(collapse.to_string(), notification.to_string());
        let request_urgency = PushUrgency::Attention;
        assert_eq!(request_urgency.fcm_priority(), "high");
    }
}
