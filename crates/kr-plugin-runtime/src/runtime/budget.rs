//! What each export is allowed to spend.
//!
//! Section 11 gives every call two bounds, and they measure different things:
//!
//! * **Elapsed time**, enforced with an epoch deadline. 10 ms for `observe` and `prepare-action`,
//!   50 ms for `decode-request` and `encode-response`, 100 ms for `snapshot`.
//! * **Instructions**, enforced with fuel. Fuel bounds the work a call may do. It is not a
//!   measurement of processor time and is never reported as one: a machine twice as fast finishes
//!   the same fuel in half the elapsed time, and a machine under load may hit the deadline with
//!   fuel to spare.
//!
//! Both are real bounds. The fuel allowance is set from a conservative instructions-per-millisecond
//! figure, so on an ordinary machine the deadline is what stops a slow call and fuel is what stops
//! an unbounded one.
//!
//! `bind`, `checkpoint` and `restore` are not in the section's list. `bind` runs under the
//! compilation budget, because that is when it happens; `checkpoint` and `restore` take the
//! snapshot deadline, being the same kind of whole-state operation.

use kr_plugin_sdk::limits::{
    INTERPRETATION_DEADLINE_MS, OBSERVATION_DEADLINE_MS, SNAPSHOT_DEADLINE_MS,
};

/// How much fuel one millisecond of deadline is worth.
///
/// A work figure, not a speed measurement. It is set well above what any current processor executes
/// in a millisecond of compiled component code, and that is deliberate: the two bounds are not
/// competitors. The deadline is what stops an ordinary call that is taking too long; fuel is the
/// ceiling on how much work one call can ever do, and it holds even when the epoch thread is
/// delayed by a loaded machine and the deadline arrives late.
///
/// The figure is measured rather than guessed. On this project's own fixtures, a tight loop in a
/// compiled component consumes somewhere between 2 million and 1000 million fuel units in the 10 ms
/// an observation is allowed: 2 million per millisecond had fuel stopping calls that were inside
/// their deadline, and 20 million per millisecond had the two bounds close enough that which one
/// fired depended on how busy the machine was. At 100 million per millisecond the deadline is
/// reliably what stops an ordinary slow call, and the ceiling is still about an order of magnitude
/// away rather than unreachable.
///
/// Changing it changes how much work a call may do, and nothing about how long it may take.
pub const FUEL_PER_DEADLINE_MS: u64 = 100_000_000;

/// How long instantiation and `bind` may take.
///
/// Neither is a call in section 11's list, so neither has one of its deadlines. Neither is
/// unbounded either: a component whose constructors never return would otherwise hold a binding
/// thread for ever. The figure is the compilation budget, because preparation is what both belong
/// to and a host that accepted a compile of up to that long has to be willing to wait for the
/// instantiation that follows it.
pub const SETUP_DEADLINE_MS: u64 = crate::runtime::compile::COMPILE_DEADLINE_MS;

/// The work allowance instantiation and `bind` run under.
///
/// Neither is a call in section 11's list: both happen during binding preparation, under the
/// compilation budget. So neither takes its allowance from the call fuel rate, which is what makes
/// "a call budget starts only once the instance is ready" true of the fuel as well as the deadline.
pub const SETUP_FUEL: u64 = SNAPSHOT_DEADLINE_MS * FUEL_PER_DEADLINE_MS;

/// Which export is running.
///
/// The call kind decides the deadline, the fuel and the name in a failure. It is an enumeration
/// rather than a duration so that a failure can say `observe` rather than "a 10 ms call".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallKind {
    /// `bind`: prepares the instance for one binding.
    Bind,
    /// `observe`: receives one scoped source event.
    Observe,
    /// `snapshot`: emits the complete current document.
    Snapshot,
    /// `prepare-action`: turns an invoked control into a proposed effect.
    PrepareAction,
    /// `decode-request`: interprets a native request.
    DecodeRequest,
    /// `encode-response`: encodes a validated decision.
    EncodeResponse,
    /// `checkpoint`: returns resumable component state.
    Checkpoint,
    /// `restore`: restores state from a checkpoint.
    Restore,
}

impl CallKind {
    /// Every call kind, in the order the contract lists the exports.
    pub const ALL: &'static [Self] = &[
        Self::Bind,
        Self::Observe,
        Self::Snapshot,
        Self::PrepareAction,
        Self::DecodeRequest,
        Self::EncodeResponse,
        Self::Checkpoint,
        Self::Restore,
    ];

    /// Returns the export name, as the contract spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Observe => "observe",
            Self::Snapshot => "snapshot",
            Self::PrepareAction => "prepare-action",
            Self::DecodeRequest => "decode-request",
            Self::EncodeResponse => "encode-response",
            Self::Checkpoint => "checkpoint",
            Self::Restore => "restore",
        }
    }

    /// Returns the call kind for an export name.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
    }

    /// Returns the elapsed deadline in milliseconds.
    ///
    /// `bind` has none of section 11's: it runs inside binding preparation, which is the whole
    /// reason a cold compile never appears in an observation deadline. It runs under
    /// [`SETUP_DEADLINE_MS`] instead, so it is bounded without being bounded by a call's figure.
    #[must_use]
    pub const fn deadline_ms(self) -> Option<u64> {
        match self {
            Self::Bind => None,
            Self::Observe | Self::PrepareAction => Some(OBSERVATION_DEADLINE_MS),
            Self::DecodeRequest | Self::EncodeResponse => Some(INTERPRETATION_DEADLINE_MS),
            Self::Snapshot | Self::Checkpoint | Self::Restore => Some(SNAPSHOT_DEADLINE_MS),
        }
    }

    /// Returns true when this call may send nothing, whatever it returns.
    ///
    /// `decode-request` returns a projection and `encode-response` returns bytes. The broker
    /// rechecks the pending request, the actor grant and the binding revision, then claims and
    /// dispatches. Neither export has a way to reach the upstream, which is what the absence of a
    /// send function in the `upstream` import means in practice.
    #[must_use]
    pub const fn returns_values_only(self) -> bool {
        matches!(self, Self::DecodeRequest | Self::EncodeResponse)
    }
}

/// The two bounds one call runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallBudget {
    /// The export this budget is for.
    pub kind: CallKind,
    /// The elapsed deadline in milliseconds, where the export has one.
    pub deadline_ms: Option<u64>,
    /// The instruction allowance.
    pub fuel: u64,
}

impl CallBudget {
    /// Builds the budget for one export from the section 11 deadlines.
    #[must_use]
    pub const fn of(kind: CallKind) -> Self {
        Self::with_fuel_rate(kind, FUEL_PER_DEADLINE_MS)
    }

    /// Builds the budget with a different fuel rate.
    ///
    /// Used by the tests that need fuel to run out before a deadline could, so that the two bounds
    /// can be told apart rather than assumed.
    #[must_use]
    pub const fn with_fuel_rate(kind: CallKind, fuel_per_ms: u64) -> Self {
        let deadline_ms = kind.deadline_ms();
        let fuel = match deadline_ms {
            // `bind` runs under the compilation budget rather than a call budget, so the call fuel
            // rate does not apply to it.
            None => SETUP_FUEL,
            Some(ms) => ms.saturating_mul(fuel_per_ms),
        };
        Self {
            kind,
            deadline_ms,
            fuel,
        }
    }

    /// Returns how many epoch ticks the deadline is worth.
    ///
    /// The epoch advances once a millisecond, so a deadline of *n* milliseconds is *n* ticks plus
    /// one: a call that starts part way through a tick would otherwise be cut short by up to a
    /// whole tick. The extra tick makes the bound "at least the deadline" rather than "about it".
    #[must_use]
    pub const fn epoch_ticks(&self, tick_ms: u64) -> Option<u64> {
        match self.deadline_ms {
            None => None,
            Some(ms) => Some(
                ms.div_ceil(if tick_ms == 0 { 1 } else { tick_ms })
                    .saturating_add(1),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_export_carries_the_deadline_section_eleven_gives_it() {
        assert_eq!(CallKind::Observe.deadline_ms(), Some(10));
        assert_eq!(CallKind::PrepareAction.deadline_ms(), Some(10));
        assert_eq!(CallKind::DecodeRequest.deadline_ms(), Some(50));
        assert_eq!(CallKind::EncodeResponse.deadline_ms(), Some(50));
        assert_eq!(CallKind::Snapshot.deadline_ms(), Some(100));
        assert_eq!(CallKind::Checkpoint.deadline_ms(), Some(100));
        assert_eq!(CallKind::Restore.deadline_ms(), Some(100));
    }

    #[test]
    fn bind_has_no_call_deadline_because_it_runs_under_the_compilation_budget() {
        assert_eq!(CallKind::Bind.deadline_ms(), None);
        assert_eq!(CallBudget::of(CallKind::Bind).deadline_ms, None);
        assert_eq!(CallBudget::of(CallKind::Bind).epoch_ticks(1), None);
        // Bounded all the same, by the preparation deadline rather than by a call's.
        assert_eq!(
            SETUP_DEADLINE_MS,
            crate::runtime::compile::COMPILE_DEADLINE_MS
        );
        assert!(SETUP_DEADLINE_MS > SNAPSHOT_DEADLINE_MS);
        // And its work allowance is the setup one, whatever the call fuel rate is. A host that
        // tightened the call rate would otherwise find it could no longer instantiate anything.
        assert_eq!(CallBudget::of(CallKind::Bind).fuel, SETUP_FUEL);
        assert_eq!(
            CallBudget::with_fuel_rate(CallKind::Bind, 1).fuel,
            SETUP_FUEL
        );
        assert_eq!(CallBudget::with_fuel_rate(CallKind::Observe, 1).fuel, 10);
    }

    #[test]
    fn fuel_is_a_work_allowance_derived_from_the_deadline_not_a_time_measurement() {
        let observe = CallBudget::of(CallKind::Observe);
        let snapshot = CallBudget::of(CallKind::Snapshot);
        assert_eq!(observe.fuel, 10 * FUEL_PER_DEADLINE_MS);
        assert_eq!(snapshot.fuel, 100 * FUEL_PER_DEADLINE_MS);
        // Ten times the deadline is ten times the work allowance, which is the only relationship
        // between them. Neither figure says how long the work takes on any particular machine.
        assert_eq!(snapshot.fuel, observe.fuel * 10);
    }

    #[test]
    fn a_deadline_is_never_cut_short_by_the_tick_it_started_in() {
        let observe = CallBudget::of(CallKind::Observe);
        assert_eq!(observe.epoch_ticks(1), Some(11));
        assert_eq!(observe.epoch_ticks(4), Some(4));
        assert_eq!(CallBudget::of(CallKind::Snapshot).epoch_ticks(1), Some(101));
    }

    #[test]
    fn the_two_interpretation_exports_return_values_only() {
        assert!(CallKind::DecodeRequest.returns_values_only());
        assert!(CallKind::EncodeResponse.returns_values_only());
        for kind in CallKind::ALL {
            if !matches!(kind, CallKind::DecodeRequest | CallKind::EncodeResponse) {
                assert!(!kind.returns_values_only(), "{kind:?}");
            }
        }
    }

    #[test]
    fn a_call_kind_round_trips_through_its_export_name() {
        for kind in CallKind::ALL {
            assert_eq!(CallKind::from_wire(kind.as_str()), Some(*kind));
        }
        assert!(CallKind::from_wire("send").is_none());
    }
}
