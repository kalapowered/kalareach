//! `native_only_volatile`: what is fenced, what keeps working, and the gap it leaves.
//!
//! Section 11 makes receipt-storage failure a mode rather than an outage. Rich work fails closed,
//! because a rich mutation with no durable record is one nobody can reconcile afterwards. The
//! already authenticated worker-bound native terminal keeps its qualified forwarding path, because
//! taking a working terminal away from somebody to protect a ledger they were not using is the
//! wrong trade.
//!
//! The transition is atomic in the sense that matters: one operation fences the undispatched rich
//! work, marks every unresolved resource volatile, counts the claimed identifiers that must never
//! be answered twice, and opens the gap. Nothing can be admitted between those steps, because
//! there are no steps between them.

use kr_protocol::gateway::{Durability, EvidenceGap, GatewayMode};
use kr_protocol::scalars::TimestampMs;

use crate::broker::error::{BrokerError, Result};

/// What one transition did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolatileTransition {
    /// The mode before.
    pub from: GatewayMode,
    /// The mode after.
    pub to: GatewayMode,
    /// The gap as it stands after the transition.
    pub gap: EvidenceGap,
}

/// The gateway's durability mode and the gap it is accumulating.
#[derive(Debug)]
pub struct VolatileState {
    mode: GatewayMode,
    gap: Option<EvidenceGap>,
    /// The ledger row of the open gap, so committing it updates the record it opened.
    row: Option<i64>,
    /// The upstreams a recovery still owes a reconciliation.
    ///
    /// Rich work comes back when the set is empty and not before: reconciling one upstream says
    /// nothing about another's pending identifiers, and finishing on the first would make every
    /// other upstream's resources claimable again unreconciled.
    owed: std::collections::BTreeSet<(
        kr_protocol::ids::ApplicationInstanceId,
        kr_protocol::ids::GatewayConnectionId,
    )>,
}

impl Default for VolatileState {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Normal,
            gap: None,
            row: None,
            owed: std::collections::BTreeSet::new(),
        }
    }
}

impl VolatileState {
    /// A gateway in normal operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Comes back in the middle of a recovery this host began and did not finish.
    ///
    /// The gap is the one that was committed; what has not happened is the reconciliation, and
    /// until it does rich work stays fenced.
    pub fn restore_recovering(
        &mut self,
        row: i64,
        gap: EvidenceGap,
        owed: impl IntoIterator<
            Item = (
                kr_protocol::ids::ApplicationInstanceId,
                kr_protocol::ids::GatewayConnectionId,
            ),
        >,
    ) {
        self.mode = GatewayMode::Recovering;
        self.gap = Some(gap);
        self.row = Some(row);
        self.owed = owed.into_iter().collect();
    }

    /// Records which upstreams this recovery owes a reconciliation.
    pub fn owe_reconciliation(
        &mut self,
        owed: impl IntoIterator<
            Item = (
                kr_protocol::ids::ApplicationInstanceId,
                kr_protocol::ids::GatewayConnectionId,
            ),
        >,
    ) {
        self.owed = owed.into_iter().collect();
    }

    /// Records that one upstream has been reconciled, and returns what is still owed.
    pub fn reconciled(
        &mut self,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId,
        connection: kr_protocol::ids::GatewayConnectionId,
    ) -> usize {
        self.owed.remove(&(application_instance_id, connection));
        self.owed.len()
    }

    /// Returns the upstreams this recovery still owes a reconciliation.
    #[must_use]
    pub fn owed(
        &self,
    ) -> Vec<(
        kr_protocol::ids::ApplicationInstanceId,
        kr_protocol::ids::GatewayConnectionId,
    )> {
        self.owed.iter().copied().collect()
    }

    /// Returns the current mode.
    #[must_use]
    pub const fn mode(&self) -> GatewayMode {
        self.mode
    }

    /// Returns the durability a record written now has.
    #[must_use]
    pub const fn durability(&self) -> Durability {
        self.mode.durability()
    }

    /// Returns the open gap, while one is open.
    #[must_use]
    pub const fn gap(&self) -> Option<&EvidenceGap> {
        self.gap.as_ref()
    }

    /// Returns the ledger row of the open gap.
    #[must_use]
    pub const fn row(&self) -> Option<i64> {
        self.row
    }

    /// Returns true when the ledger can be written to now.
    ///
    /// It is a different question from [`VolatileState::durability`], which labels what a record
    /// written now *is*. While the fence is up the journal is faulted and nothing can be written.
    /// During recovery storage is back, and the reconciliation that finishes the recovery has to
    /// be written down: a reconciliation nobody recorded would be redone from the old state after
    /// a restart.
    #[must_use]
    pub const fn writes_are_durable(&self) -> bool {
        !matches!(self.mode, GatewayMode::NativeOnlyVolatile)
    }

    /// Returns true when a rich mutation or rich approval may be admitted.
    #[must_use]
    pub const fn admits_rich_work(&self) -> bool {
        self.mode.admits_rich_work()
    }

    /// Refuses a rich operation when the gateway is not admitting any.
    ///
    /// The refusal names the mode, because a caller that is told only "unavailable" cannot tell a
    /// fenced host from a broken one, and the two need different answers from a person.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::RichWorkFenced`] while the gateway is fenced or recovering.
    pub fn require_rich_work(&self) -> Result<()> {
        if self.mode.admits_rich_work() {
            return Ok(());
        }
        Err(BrokerError::RichWorkFenced {
            detail: match self.mode {
                GatewayMode::NativeOnlyVolatile => {
                    "the receipt journal faulted: rich mutations and rich approvals are fenced, \
                     and the native terminal continues"
                        .to_owned()
                }
                GatewayMode::Recovering => {
                    "storage has returned and the evidence gap is being committed: rich work \
                     resumes once the pending identifiers are reconciled"
                        .to_owned()
                }
                GatewayMode::Normal => unreachable!("normal admits rich work"),
            },
        })
    }

    /// Enters volatile-native mode.
    ///
    /// `carried_pending` is how many identifiers were already claimed or dispatched when the
    /// journal faulted. They are carried into the gap rather than forgotten, because those are
    /// exactly the ones a second response must never be emitted for.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not in a mode this transition
    /// leaves from.
    pub fn enter(
        &mut self,
        reason: impl Into<String>,
        carried_pending: u64,
        now: TimestampMs,
    ) -> Result<VolatileTransition> {
        self.transition(GatewayMode::NativeOnlyVolatile, |state| {
            state.gap = Some(EvidenceGap::open(reason, now, carried_pending));
        })
    }

    /// Begins recovery: storage is back, and the gap has not been committed yet.
    ///
    /// Rich work does not resume here. It resumes after the gap is committed and the pending
    /// identifiers have been reconciled with the same upstream, which is a separate step because
    /// it can fail.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not fenced.
    pub fn begin_recovery(&mut self, now: TimestampMs) -> Result<VolatileTransition> {
        self.transition(GatewayMode::Recovering, |state| {
            if let Some(gap) = state.gap.as_mut() {
                gap.closed_at = kr_protocol::scalars::Nullable::some(now);
            }
        })
    }

    /// Finishes recovery: the gap is committed and the identifiers are reconciled.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not recovering.
    pub fn finish_recovery(&mut self) -> Result<VolatileTransition> {
        if !self.owed.is_empty() {
            return Err(BrokerError::invalid(format!(
                "this recovery still owes {} upstream reconciliation(s)",
                self.owed.len()
            )));
        }
        let transition = self.transition(GatewayMode::Normal, |_| {})?;
        self.gap = None;
        self.row = None;
        Ok(transition)
    }

    /// Falls back to the fence, because storage failed again during recovery.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not recovering.
    pub fn fall_back(
        &mut self,
        reason: impl Into<String>,
        carried_pending: u64,
        now: TimestampMs,
    ) -> Result<VolatileTransition> {
        self.transition(GatewayMode::NativeOnlyVolatile, |state| {
            // The gap that was closing is reopened rather than replaced, so the record still says
            // when the trouble started rather than when the second attempt failed.
            match state.gap.as_mut() {
                Some(gap) => {
                    gap.closed_at = kr_protocol::scalars::Nullable::null();
                    gap.carried_pending = kr_protocol::scalars::U64::new(
                        gap.carried_pending.get().max(carried_pending),
                    );
                }
                None => state.gap = Some(EvidenceGap::open(reason, now, carried_pending)),
            }
        })
    }

    /// Records that a native request was forwarded while the gap was open.
    pub fn note_native_request(&mut self) {
        if let Some(gap) = self.gap.as_mut() {
            gap.native_requests =
                kr_protocol::scalars::U64::new(gap.native_requests.get().saturating_add(1));
        }
    }

    /// Records that a native response was arbitrated while the gap was open.
    pub fn note_native_response(&mut self) {
        if let Some(gap) = self.gap.as_mut() {
            gap.native_responses =
                kr_protocol::scalars::U64::new(gap.native_responses.get().saturating_add(1));
        }
    }

    /// Records that a rich operation was refused because of the gap.
    pub fn note_fenced(&mut self) {
        if let Some(gap) = self.gap.as_mut() {
            gap.fenced_rich_operations =
                kr_protocol::scalars::U64::new(gap.fenced_rich_operations.get().saturating_add(1));
        }
    }

    /// Remembers which ledger row holds the open gap.
    pub const fn set_row(&mut self, row: i64) {
        self.row = Some(row);
    }

    fn transition(
        &mut self,
        to: GatewayMode,
        apply: impl FnOnce(&mut Self),
    ) -> Result<VolatileTransition> {
        if !self.mode.may_become(to) {
            return Err(BrokerError::invalid(format!(
                "the gateway cannot go from {} to {to}",
                self.mode
            )));
        }
        let from = self.mode;
        self.mode = to;
        apply(self);
        Ok(VolatileTransition {
            from,
            to,
            gap: self
                .gap
                .clone()
                .unwrap_or_else(|| EvidenceGap::open("", TimestampMs::new(0), 0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entering_the_fence_carries_what_must_not_be_answered_twice() {
        let mut state = VolatileState::new();
        assert!(state.admits_rich_work());
        let transition = state
            .enter("the journal could not be written", 2, TimestampMs::new(100))
            .expect("the fence is entered");
        assert_eq!(transition.from, GatewayMode::Normal);
        assert_eq!(transition.to, GatewayMode::NativeOnlyVolatile);
        assert_eq!(transition.gap.carried_pending.get(), 2);
        assert!(transition.gap.is_open());
        assert!(!state.admits_rich_work());
        assert_eq!(state.durability(), Durability::Volatile);
    }

    #[test]
    fn a_rich_operation_is_refused_and_the_refusal_says_which_fence() {
        let mut state = VolatileState::new();
        state.require_rich_work().expect("normal admits rich work");
        state
            .enter("the journal could not be written", 0, TimestampMs::new(100))
            .expect("the fence is entered");
        let refusal = state.require_rich_work().expect_err("rich work is fenced");
        assert!(refusal.to_string().contains("native terminal continues"));
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::UpstreamUnavailable
        );
    }

    #[test]
    fn rich_work_does_not_come_back_until_the_gap_is_committed() {
        let mut state = VolatileState::new();
        state
            .enter("the journal could not be written", 1, TimestampMs::new(100))
            .expect("the fence is entered");
        state
            .begin_recovery(TimestampMs::new(200))
            .expect("recovery begins");
        assert!(
            !state.admits_rich_work(),
            "storage returning is not the same as the gap being committed"
        );
        let refusal = state.require_rich_work().expect_err("still fenced");
        assert!(refusal.to_string().contains("reconciled"));
        state.finish_recovery().expect("recovery finishes");
        assert!(state.admits_rich_work());
        assert_eq!(state.durability(), Durability::Durable);
        assert!(state.gap().is_none());
    }

    #[test]
    fn a_second_failure_during_recovery_reopens_the_same_gap() {
        let mut state = VolatileState::new();
        state
            .enter("the journal could not be written", 1, TimestampMs::new(100))
            .expect("the fence is entered");
        state
            .begin_recovery(TimestampMs::new(200))
            .expect("recovery begins");
        let transition = state
            .fall_back("the journal faulted again", 3, TimestampMs::new(300))
            .expect("the fence is re-entered");
        assert_eq!(transition.to, GatewayMode::NativeOnlyVolatile);
        assert_eq!(
            transition.gap.opened_at,
            TimestampMs::new(100),
            "the record says when the trouble started"
        );
        assert_eq!(transition.gap.carried_pending.get(), 3);
        assert!(transition.gap.is_open());
    }

    #[test]
    fn the_gap_counts_what_passed_through_it() {
        let mut state = VolatileState::new();
        state
            .enter("the journal could not be written", 0, TimestampMs::new(100))
            .expect("the fence is entered");
        state.note_native_request();
        state.note_native_request();
        state.note_native_response();
        state.note_fenced();
        let gap = state.gap().expect("the gap is open");
        assert_eq!(gap.native_requests.get(), 2);
        assert_eq!(gap.native_responses.get(), 1);
        assert_eq!(gap.fenced_rich_operations.get(), 1);
    }

    #[test]
    fn the_fence_is_not_left_by_wishing() {
        let mut state = VolatileState::new();
        assert!(
            state.begin_recovery(TimestampMs::new(1)).is_err(),
            "a gateway that never faulted has nothing to recover"
        );
        state
            .enter("the journal could not be written", 0, TimestampMs::new(100))
            .expect("the fence is entered");
        assert!(
            state.finish_recovery().is_err(),
            "the fence is left through recovery, not directly"
        );
    }
}
