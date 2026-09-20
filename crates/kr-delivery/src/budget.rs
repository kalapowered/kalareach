//! The host's own account of what it has sent, and the five-minute collapse.
//!
//! Section 16: *free push uses a burst limit of 20 messages and a sustained limit of 60 per hour
//! per destination installation. Excess notifications collapse into one attention update every
//! five minutes. The host retains every request and reports suppression locally.*
//!
//! The gateway enforces the same limits, and both halves are needed. The gateway's stops a faulty
//! host; this one stops the host sending what it already knows will be collapsed, which is what
//! makes *the host retains every request and reports suppression locally* true rather than
//! aspirational: a suppressed notification is recorded here, with what it collapsed into, before
//! anything is sent.
//!
//! # Two leaky buckets, in exact integers
//!
//! Two buckets, because twenty in a burst and sixty an hour are two different statements. The
//! burst bucket holds 20 and refills completely in a minute; the sustained bucket holds 60 and
//! refills completely in an hour. A notification needs a token from both. It is the same shape the
//! gateway keeps, because a host that modelled the limits differently would either send what it
//! knew would be collapsed or hold back what would have been admitted.
//!
//! Continuous refill is the point of a bucket. A counted window refills all at once, so twenty at
//! the end of one window and twenty at the start of the next is forty in a moment, which is the
//! storm section 16 is about.
//!
//! Tokens are scaled by [`SCALE`], which is the number of milliseconds in a minute. That makes
//! both refill rates exact whole numbers of scaled units per millisecond - [`BURST_REFILL_SCALED`]
//! and [`SUSTAINED_REFILL_SCALED`] - so a bucket carries its own remainder rather than discarding
//! it at every call.

use kr_protocol::ids::{CollapseId, NotificationId};
use kr_protocol::push::{
    FREE_PUSH_BURST, FREE_PUSH_PER_HOUR, PUSH_COLLAPSE_WINDOW_MS, PushSuppression,
    PushSuppressionReason,
};
use kr_protocol::scalars::{TimestampMs, U64};

use crate::journal::StoredBudget;

/// Scaled units per token: the milliseconds in a minute.
///
/// It is chosen so that both refill rates are whole numbers of scaled units per millisecond, which
/// makes every arithmetic step here exact.
pub const SCALE: i64 = 60 * 1000;

/// How long the burst allowance takes to refill completely, in milliseconds.
pub const BURST_REFILL_MS: u64 = 60 * 1000;

/// How long the sustained allowance takes to refill completely, in milliseconds.
pub const SUSTAINED_REFILL_MS: u64 = 60 * 60 * 1000;

/// The burst bucket's capacity, in scaled units.
pub const BURST_CAPACITY: i64 = (FREE_PUSH_BURST as i64) * SCALE;

/// The sustained bucket's capacity, in scaled units.
pub const SUSTAINED_CAPACITY: i64 = (FREE_PUSH_PER_HOUR as i64) * SCALE;

/// Scaled units the burst bucket gains each millisecond.
pub const BURST_REFILL_SCALED: i64 = BURST_CAPACITY / (BURST_REFILL_MS as i64);

/// Scaled units the sustained bucket gains each millisecond.
pub const SUSTAINED_REFILL_SCALED: i64 = SUSTAINED_CAPACITY / (SUSTAINED_REFILL_MS as i64);

// Both rates divide exactly at this scale. A change to either limit that stopped them dividing
// would silently round the refill down, so it stops the build instead.
const _: () = assert!(BURST_CAPACITY % (BURST_REFILL_MS as i64) == 0);
const _: () = assert!(SUSTAINED_CAPACITY % (SUSTAINED_REFILL_MS as i64) == 0);

/// What one destination's account says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    burst_scaled: i64,
    sustained_scaled: i64,
    refilled_at_ms: u64,
    collapse_into: Option<NotificationId>,
    collapse_opened_at_ms: Option<u64>,
    collapse_count: u64,
}

/// What the account says about one notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Send it. The allowance was there and has been spent.
    Send,
    /// Collapse it into the attention update that is already open.
    ///
    /// Nothing is sent. The request is still recorded, and the suppression is what the host shows
    /// a person locally.
    Collapse {
        /// What the host records, in the same shape the gateway would have answered with.
        suppression: PushSuppression,
    },
    /// Collapse it, and send one attention update, because the window has elapsed.
    ///
    /// The update is the one notification section 16 lets through every five minutes. It does not
    /// spend an allowance: a destination that is over its limit is exactly the one that needs to
    /// be told something is waiting, and an update the bucket refused would make the collapse a
    /// way of losing the decision rather than of batching it.
    OpenUpdate {
        /// The identifier the update goes out under.
        update: NotificationId,
        /// What the host records for the notification that opened it.
        suppression: PushSuppression,
    },
}

impl Budget {
    /// A destination that has sent nothing: both buckets full.
    #[must_use]
    pub const fn fresh(now_ms: u64) -> Self {
        Self {
            burst_scaled: BURST_CAPACITY,
            sustained_scaled: SUSTAINED_CAPACITY,
            refilled_at_ms: now_ms,
            collapse_into: None,
            collapse_opened_at_ms: None,
            collapse_count: 0,
        }
    }

    /// Reads a stored account back.
    ///
    /// A stored collapse target this build cannot parse is read as no open window, which opens a
    /// new update rather than collapsing into one nothing can name.
    #[must_use]
    pub fn restored(stored: &StoredBudget) -> Self {
        Self {
            burst_scaled: stored.burst_scaled.clamp(-SCALE, BURST_CAPACITY),
            sustained_scaled: stored.sustained_scaled.clamp(-SCALE, SUSTAINED_CAPACITY),
            refilled_at_ms: stored.refilled_at_ms,
            collapse_into: stored
                .collapse_into
                .as_deref()
                .and_then(|id| id.parse().ok()),
            collapse_opened_at_ms: stored.collapse_opened_at_ms,
            collapse_count: stored.collapse_count,
        }
    }

    /// Returns the account in the shape the journal stores.
    #[must_use]
    pub fn stored(&self) -> StoredBudget {
        StoredBudget {
            burst_scaled: self.burst_scaled,
            sustained_scaled: self.sustained_scaled,
            refilled_at_ms: self.refilled_at_ms,
            collapse_into: self.collapse_into.map(|id| id.to_string()),
            collapse_opened_at_ms: self.collapse_opened_at_ms,
            collapse_count: self.collapse_count,
        }
    }

    /// Refills both buckets for the time that has passed.
    ///
    /// A clock that went backwards refills nothing rather than draining the account: the
    /// allowance is not a place to express an opinion about the clock.
    pub fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.refilled_at_ms);
        if elapsed == 0 {
            self.refilled_at_ms = self.refilled_at_ms.max(now_ms);
            return;
        }
        let elapsed = elapsed as i64;
        self.burst_scaled = self
            .burst_scaled
            .saturating_add(elapsed.saturating_mul(BURST_REFILL_SCALED))
            .min(BURST_CAPACITY);
        self.sustained_scaled = self
            .sustained_scaled
            .saturating_add(elapsed.saturating_mul(SUSTAINED_REFILL_SCALED))
            .min(SUSTAINED_CAPACITY);
        self.refilled_at_ms = now_ms;
    }

    /// Returns how many whole notifications the burst allowance has left.
    #[must_use]
    pub fn burst_available(&self) -> u64 {
        if self.burst_scaled <= 0 {
            0
        } else {
            (self.burst_scaled / SCALE) as u64
        }
    }

    /// Returns how many whole notifications the sustained allowance has left.
    #[must_use]
    pub fn sustained_available(&self) -> u64 {
        if self.sustained_scaled <= 0 {
            0
        } else {
            (self.sustained_scaled / SCALE) as u64
        }
    }

    /// Decides what happens to one notification, and spends whatever it spends.
    ///
    /// `fresh_update` is asked for an identifier only when a new attention update is opened, so a
    /// caller that never opens one never mints one.
    pub fn admit(
        &mut self,
        now_ms: u64,
        fresh_update: impl FnOnce() -> NotificationId,
    ) -> Admission {
        self.refill(now_ms);
        let burst_ok = self.burst_scaled >= SCALE;
        let sustained_ok = self.sustained_scaled >= SCALE;
        self.burst_scaled = (self.burst_scaled - SCALE).max(-SCALE);
        self.sustained_scaled = (self.sustained_scaled - SCALE).max(-SCALE);
        if burst_ok && sustained_ok {
            return Admission::Send;
        }
        let reason = if !burst_ok {
            PushSuppressionReason::Burst
        } else {
            PushSuppressionReason::Sustained
        };
        let window_open = self
            .collapse_opened_at_ms
            .is_some_and(|opened| now_ms.saturating_sub(opened) < PUSH_COLLAPSE_WINDOW_MS);
        if window_open && let Some(update) = self.collapse_into {
            self.collapse_count = self.collapse_count.saturating_add(1);
            return Admission::Collapse {
                suppression: self.suppression(update, reason),
            };
        }
        let update = fresh_update();
        self.collapse_into = Some(update);
        self.collapse_opened_at_ms = Some(now_ms);
        self.collapse_count = 1;
        Admission::OpenUpdate {
            update,
            suppression: self.suppression(update, reason),
        }
    }

    /// Releases the collapse window opened by `update_id` if this budget is holding it.
    ///
    /// When a notification that opened a collapse window is refused or never leaves the host,
    /// holding the window would cause subsequent suppressed notifications to reference an
    /// attention update that was never sent.
    pub fn release_collapse_window(&mut self, update_id: &NotificationId) {
        if self.collapse_into.as_ref() == Some(update_id) {
            self.collapse_into = None;
            self.collapse_opened_at_ms = None;
            self.collapse_count = 0;
        }
    }

    fn suppression(
        &self,
        update: NotificationId,
        reason: PushSuppressionReason,
    ) -> PushSuppression {
        PushSuppression {
            collapsed_into: update,
            next_update_at_ms: TimestampMs::new(
                self.collapse_opened_at_ms
                    .unwrap_or(0)
                    .saturating_add(PUSH_COLLAPSE_WINDOW_MS),
            ),
            reason,
            suppressed_count: U64::new(self.collapse_count),
        }
    }
}

/// Derives a collapse identifier from what the host groups by.
///
/// The identifier travels to a provider in the clear, so it is a keyed digest under a secret only
/// this environment's delivery journal holds. Two notifications about one thing produce the same
/// value and collapse on the device; a provider that sees the value learns that they group and
/// nothing about what they group, and cannot work the group out by trying candidates.
///
/// Section 16: *a collapse identifier that reveals no project name.* A digest under a secret is
/// how that is kept rather than promised.
#[must_use]
pub fn collapse_id(secret: &[u8; 32], group: &str) -> CollapseId {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("this length is one HMAC accepts");
    mac.update(b"kr-delivery/collapse/1");
    mac.update(&(group.len() as u64).to_be_bytes());
    mac.update(group.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    CollapseId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(byte: u8) -> NotificationId {
        NotificationId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn spend_the_burst(budget: &mut Budget, now_ms: u64) {
        for index in 0..FREE_PUSH_BURST {
            assert_eq!(
                budget.admit(now_ms, || update(1)),
                Admission::Send,
                "notification {index} is inside the burst"
            );
        }
    }

    /// Sends until the account stops admitting, and returns the decision that stopped it.
    fn drain(budget: &mut Budget, now_ms: u64, opening: u8) -> Admission {
        loop {
            let decision = budget.admit(now_ms, || update(opening));
            if decision != Admission::Send {
                return decision;
            }
        }
    }

    #[test]
    fn a_fresh_destination_admits_the_burst_and_then_collapses() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        let decision = budget.admit(0, || update(2));
        assert!(
            matches!(
                decision,
                Admission::OpenUpdate {
                    suppression: PushSuppression {
                        reason: PushSuppressionReason::Burst,
                        ..
                    },
                    ..
                }
            ),
            "the twenty-first in one moment is over the burst"
        );
    }

    #[test]
    fn twenty_one_requests_at_time_zero_puts_burst_into_debt_so_three_seconds_later_is_still_collapsed() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        let stopped = budget.admit(0, || update(21));
        assert!(matches!(stopped, Admission::OpenUpdate { .. }));
        assert_eq!(budget.burst_scaled, -SCALE);

        // At 3,000 ms, refill is 1 token (+SCALE), which pays off debt to 0 tokens.
        budget.refill(3_000);
        assert_eq!(budget.burst_scaled, 0);
        assert_eq!(budget.burst_available(), 0);

        // A request at 3,000 ms must still be collapsed because it has 0 tokens available.
        let at_3s = budget.admit(3_000, || update(22));
        assert!(matches!(at_3s, Admission::Collapse { .. }));
        assert_eq!(budget.burst_scaled, -SCALE);

        // At 9,000 ms (two refill intervals after request 22):
        budget.refill(9_000);
        assert_eq!(budget.burst_available(), 1);
        assert_eq!(budget.admit(9_000, || update(23)), Admission::Send);
    }

    #[test]
    fn releasing_a_collapse_window_clears_the_update_so_a_new_one_can_open() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        let Admission::OpenUpdate { update: first, .. } = budget.admit(0, || update(1)) else {
            panic!("expected open update");
        };
        assert_eq!(budget.collapse_into, Some(first));
        budget.release_collapse_window(&first);
        assert_eq!(budget.collapse_into, None);
        assert_eq!(budget.collapse_opened_at_ms, None);
        assert_eq!(budget.collapse_count, 0);
        let Admission::OpenUpdate { update: second, .. } = budget.admit(0, || update(2)) else {
            panic!("expected open update after release");
        };
        assert_eq!(second, update(2));
    }

    #[test]
    fn the_burst_allowance_refills_continuously_over_a_minute() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        // Twenty over a minute is one every three seconds. Two seconds is two thirds of one,
        // which is not one.
        budget.refill(2_000);
        assert_eq!(budget.burst_available(), 0);
        budget.refill(3_000);
        assert_eq!(budget.burst_available(), 1);
        assert_eq!(budget.admit(3_000, || update(2)), Admission::Send);
        budget.refill(3_000 + BURST_REFILL_MS);
        assert_eq!(
            budget.burst_available(),
            FREE_PUSH_BURST,
            "a minute refills the whole burst allowance and no more"
        );
    }

    #[test]
    fn one_attention_update_opens_every_five_minutes_and_the_rest_collapse_into_it() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        let Admission::OpenUpdate {
            update: first,
            suppression,
        } = budget.admit(0, || update(9))
        else {
            panic!("the first suppression opens an update");
        };
        assert_eq!(first, update(9));
        assert_eq!(suppression.suppressed_count.get(), 1);
        assert_eq!(
            suppression.next_update_at_ms.get(),
            PUSH_COLLAPSE_WINDOW_MS,
            "the next update is five minutes after this window opened"
        );

        let Admission::Collapse { suppression } =
            budget.admit(1, || panic!("no second update inside the window"))
        else {
            panic!("a notification inside the window collapses");
        };
        assert_eq!(suppression.collapsed_into, first);
        assert_eq!(suppression.suppressed_count.get(), 2);

        // Five minutes on, the burst allowance has refilled, so the bucket is spent again to put
        // the destination back over its policy. Only then does the window itself decide.
        let later = PUSH_COLLAPSE_WINDOW_MS;
        spend_the_burst(&mut budget, later);
        let Admission::OpenUpdate {
            update: second,
            suppression,
        } = budget.admit(later, || update(10))
        else {
            panic!("a new window opens a new update");
        };
        assert_eq!(second, update(10));
        assert_eq!(suppression.suppressed_count.get(), 1);
        assert_eq!(
            suppression.next_update_at_ms.get(),
            later + PUSH_COLLAPSE_WINDOW_MS
        );
    }

    #[test]
    fn a_notification_inside_the_window_never_opens_a_second_update() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        budget.admit(0, || update(9));
        for moment in [1, 10, 1_000, PUSH_COLLAPSE_WINDOW_MS - 1] {
            // The burst bucket refills over those five minutes, so it is emptied again at each
            // moment: what is under test is the window, not the allowance.
            while budget.admit(moment, || panic!("no second update inside the window"))
                == Admission::Send
            {}
            assert!(
                matches!(
                    budget.admit(moment, || panic!("no second update inside the window")),
                    Admission::Collapse { .. }
                ),
                "a notification at {moment} collapses into the open update"
            );
        }
    }

    #[test]
    fn the_sustained_limit_bites_once_the_burst_has_refilled() {
        let mut budget = Budget::fresh(0);
        // Sixty an hour, spent a burst at a time with a minute between: the burst bucket refills
        // completely each time and the sustained bucket barely moves, which is the whole reason
        // there are two of them.
        for minute in 0..3 {
            spend_the_burst(&mut budget, minute * BURST_REFILL_MS);
        }
        let now = 3 * BURST_REFILL_MS;
        budget.refill(now);
        assert_eq!(
            budget.burst_available(),
            FREE_PUSH_BURST,
            "the burst allowance is whole again"
        );
        assert!(
            budget.sustained_available() < FREE_PUSH_BURST,
            "the hour's allowance is what is left, and it is short"
        );
        let stopped = drain(&mut budget, now, 9);
        let Admission::OpenUpdate { suppression, .. } = stopped else {
            panic!("the destination is over its policy");
        };
        assert_eq!(
            suppression.reason,
            PushSuppressionReason::Sustained,
            "the burst allowance was there and the hour's was not"
        );
        assert!(
            budget.burst_available() > 0,
            "the burst allowance still had room, which is what makes this the other limit"
        );
    }

    #[test]
    fn an_account_survives_a_restart() {
        let mut budget = Budget::fresh(1_000);
        for _ in 0..5 {
            budget.admit(1_000, || update(1));
        }
        let restored = Budget::restored(&budget.stored());
        assert_eq!(restored, budget);
        assert_eq!(restored.burst_available(), FREE_PUSH_BURST - 5);
    }

    #[test]
    fn an_open_collapse_window_survives_a_restart() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        budget.admit(0, || update(9));
        let mut restored = Budget::restored(&budget.stored());
        let Admission::Collapse { suppression } =
            restored.admit(1, || panic!("the window was already open"))
        else {
            panic!("a restarted host collapses into the update it already opened");
        };
        assert_eq!(suppression.collapsed_into, update(9));
    }

    #[test]
    fn a_clock_that_went_backwards_refills_nothing_and_drains_nothing() {
        let mut budget = Budget::fresh(10_000);
        budget.admit(10_000, || update(1));
        let before = budget.clone();
        budget.refill(5_000);
        assert_eq!(budget.burst_scaled, before.burst_scaled);
        assert_eq!(budget.sustained_scaled, before.sustained_scaled);
    }

    #[test]
    fn the_remainder_of_a_refill_is_carried_rather_than_discarded() {
        let mut budget = Budget::fresh(0);
        spend_the_burst(&mut budget, 0);
        // A millisecond at a time for three seconds is one token, the same as three seconds in one
        // step. A rate that discarded its remainder would give nothing at all.
        for millisecond in 1..=3_000 {
            budget.refill(millisecond);
        }
        assert_eq!(budget.burst_available(), 1);
    }

    #[test]
    fn a_collapse_identifier_is_a_keyed_digest_of_what_it_groups() {
        let secret = [7u8; 32];
        let other = [8u8; 32];
        assert_eq!(
            collapse_id(&secret, "session/abc"),
            collapse_id(&secret, "session/abc"),
            "two notifications about one thing group"
        );
        assert_ne!(
            collapse_id(&secret, "session/abc"),
            collapse_id(&secret, "session/abd")
        );
        assert_ne!(
            collapse_id(&secret, "session/abc"),
            collapse_id(&other, "session/abc"),
            "another host's secret produces another value for the same group"
        );
        // Length-prefixed, so two different groups cannot be concatenated into one digest.
        assert_ne!(collapse_id(&secret, "ab/c"), collapse_id(&secret, "a/bc"));
    }
}
