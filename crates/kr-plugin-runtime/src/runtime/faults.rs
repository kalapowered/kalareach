//! Counting faults, and disabling a binding that keeps producing them.
//!
//! Three faults within one minute disable the binding. The count is over a sliding window rather
//! than a total, because a component that faults once a day is not the same problem as one that
//! faults three times in a row, and a total would eventually disable the first.
//!
//! The window is measured on the machine's own continuous clock, which counts a suspend. A laptop
//! that faults twice, sleeps for an hour and faults again has faulted three times in an hour, not
//! three times in a minute, and the binding stays usable.

use std::collections::VecDeque;
use std::sync::Arc;

use kr_ipc::clock::SharedClock;
use kr_plugin_sdk::limits::{FAULT_WINDOW_MS, FAULTS_BEFORE_DISABLE};

/// What the fault counter decided about a binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultVerdict {
    /// The binding is still usable.
    Continue {
        /// How many faults are inside the window.
        faults_in_window: u32,
    },
    /// The binding is disabled, with the reason a person is shown.
    Disabled {
        /// Why it was disabled.
        reason: String,
    },
}

/// A sliding window of faults against one binding.
#[derive(Clone)]
pub struct FaultCounter {
    clock: Arc<dyn SharedClock>,
    window_ms: u64,
    limit: u32,
    faults: VecDeque<u64>,
    disabled: Option<String>,
}

impl core::fmt::Debug for FaultCounter {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FaultCounter")
            .field("window_ms", &self.window_ms)
            .field("limit", &self.limit)
            .field("faults_in_window", &self.faults.len())
            .field("disabled", &self.disabled)
            .finish()
    }
}

impl FaultCounter {
    /// Builds a counter with the section 11 window and limit.
    #[must_use]
    pub fn new(clock: Arc<dyn SharedClock>) -> Self {
        Self {
            clock,
            window_ms: FAULT_WINDOW_MS,
            limit: FAULTS_BEFORE_DISABLE,
            faults: VecDeque::new(),
            disabled: None,
        }
    }

    /// Returns the window in milliseconds.
    #[must_use]
    pub const fn window_ms(&self) -> u64 {
        self.window_ms
    }

    /// Returns the number of faults that disable a binding.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the disabled reason, once the binding is disabled.
    #[must_use]
    pub fn disabled_reason(&self) -> Option<&str> {
        self.disabled.as_deref()
    }

    /// Returns how many faults are inside the window right now.
    #[must_use]
    pub fn faults_in_window(&mut self) -> u32 {
        self.expire();
        u32::try_from(self.faults.len()).unwrap_or(u32::MAX)
    }

    /// Records one fault and says what it means for the binding.
    ///
    /// `reason` is the failure in the words a person reads; when this fault is the one that
    /// reaches the limit, it becomes the binding's disabled reason so that the record names the
    /// fault that closed it rather than the count alone.
    pub fn record(&mut self, reason: &str) -> FaultVerdict {
        if let Some(existing) = &self.disabled {
            return FaultVerdict::Disabled {
                reason: existing.clone(),
            };
        }
        self.expire();
        self.faults.push_back(self.clock.boot_elapsed_ms());
        let count = u32::try_from(self.faults.len()).unwrap_or(u32::MAX);
        if count >= self.limit {
            let reason = format!(
                "{count} faults within {} s, the last of which was: {reason}",
                self.window_ms / 1_000
            );
            self.disabled = Some(reason.clone());
            return FaultVerdict::Disabled { reason };
        }
        FaultVerdict::Continue {
            faults_in_window: count,
        }
    }

    /// Disables the binding for a reason that is not a component fault.
    ///
    /// A binding whose package was revoked, whose application exited or whose plugin host was
    /// replaced is disabled without any fault being recorded against the component.
    pub fn disable(&mut self, reason: impl Into<String>) {
        if self.disabled.is_none() {
            self.disabled = Some(reason.into());
        }
    }

    fn expire(&mut self) {
        let now = self.clock.boot_elapsed_ms();
        let floor = now.saturating_sub(self.window_ms);
        while self.faults.front().is_some_and(|at| *at < floor) {
            self.faults.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use kr_ipc::clock::ManualSharedClock;

    fn counter() -> (Arc<ManualSharedClock>, FaultCounter) {
        let clock = Arc::new(ManualSharedClock::new());
        let counter = FaultCounter::new(clock.clone());
        (clock, counter)
    }

    #[test]
    fn the_window_and_the_limit_are_the_specified_numbers() {
        let (_clock, counter) = counter();
        assert_eq!(counter.window_ms(), 60_000);
        assert_eq!(counter.limit(), 3);
    }

    #[test]
    fn three_faults_within_one_minute_disable_the_binding() {
        let (clock, mut counter) = counter();
        assert_eq!(
            counter.record("the component trapped"),
            FaultVerdict::Continue {
                faults_in_window: 1
            }
        );
        clock.advance(Duration::from_millis(20_000));
        assert_eq!(
            counter.record("the component trapped"),
            FaultVerdict::Continue {
                faults_in_window: 2
            }
        );
        clock.advance(Duration::from_millis(20_000));
        let verdict = counter.record("observe used its whole deadline allowance");
        let FaultVerdict::Disabled { reason } = verdict else {
            panic!("the third fault inside the window did not disable the binding");
        };
        assert!(reason.contains("3 faults within 60 s"));
        assert!(reason.contains("observe used its whole deadline allowance"));
        assert_eq!(counter.disabled_reason(), Some(reason.as_str()));
    }

    #[test]
    fn faults_spread_past_the_window_do_not_accumulate() {
        let (clock, mut counter) = counter();
        for _ in 0..10 {
            assert_eq!(
                counter.record("the component trapped"),
                FaultVerdict::Continue {
                    faults_in_window: 1
                }
            );
            clock.advance(Duration::from_millis(60_001));
        }
        assert!(counter.disabled_reason().is_none());
        assert_eq!(counter.faults_in_window(), 0);
    }

    #[test]
    fn a_suspend_counts_towards_the_window_so_it_cannot_be_slept_through() {
        let (clock, mut counter) = counter();
        counter.record("the component trapped");
        counter.record("the component trapped");
        // An hour of sleep is an hour on the continuous clock, so the two earlier faults leave the
        // window and the binding survives.
        clock.advance(Duration::from_secs(3_600));
        assert_eq!(
            counter.record("the component trapped"),
            FaultVerdict::Continue {
                faults_in_window: 1
            }
        );
    }

    #[test]
    fn a_disabled_binding_stays_disabled_with_its_original_reason() {
        let (_clock, mut counter) = counter();
        counter.record("first");
        counter.record("second");
        let FaultVerdict::Disabled { reason } = counter.record("third") else {
            panic!("the third fault did not disable the binding");
        };
        assert_eq!(
            counter.record("fourth"),
            FaultVerdict::Disabled {
                reason: reason.clone()
            }
        );
        counter.disable("something else entirely");
        assert_eq!(counter.disabled_reason(), Some(reason.as_str()));
    }

    #[test]
    fn a_binding_can_be_disabled_without_any_component_fault() {
        let (_clock, mut counter) = counter();
        counter.disable("the package was withdrawn from the catalogue");
        assert_eq!(
            counter.disabled_reason(),
            Some("the package was withdrawn from the catalogue")
        );
        assert_eq!(counter.faults_in_window(), 0);
    }
}
