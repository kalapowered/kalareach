//! The time budgets of a run: what each has spent, counted over the steps that name it in the order
//! the plan runs them.
//!
//! A step's time is spent at the earlier of its own `timeout` and what its budget has left. A step
//! that names a budget with nothing left is not run. A step that is not run takes no time, and so
//! spends none.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::plan::Step;
use crate::tree::Deadline;

/// What one budget has spent.
#[derive(Debug, Default)]
struct Spent {
    /// The time the steps that ran took, or the whole budget once a step ran into its deadline.
    time: Duration,
    /// The number of the step that took the budget's last second, once it is spent.
    by: Option<usize>,
}

/// What each budget of a run has spent.
#[derive(Debug, Default)]
pub struct Budgets {
    spent: BTreeMap<String, Spent>,
}

impl Budgets {
    /// When `step`, which starts at `now`, has spent its time: the earlier of its `timeout` and
    /// what its budget has left, the step's own when they are equal, and none when it has neither.
    ///
    /// # Errors
    ///
    /// Gives the number of the step that spent the budget `step` names, when none of it is left.
    pub fn deadline(&self, step: &Step, now: Instant) -> Result<Option<Deadline>, usize> {
        let own = step.timeout.map(|seconds| Deadline {
            at: now + Duration::from_secs(seconds),
            seconds,
            budget: false,
        });
        let Some((id, seconds)) = &step.budget else {
            return Ok(own);
        };
        let spent = self.spent.get(id);
        if let Some(by) = spent.and_then(|spent| spent.by) {
            return Err(by);
        }
        let left = Duration::from_secs(*seconds)
            .saturating_sub(spent.map_or(Duration::ZERO, |spent| spent.time));
        let shared = Deadline {
            at: now + left,
            seconds: *seconds,
            budget: true,
        };
        Ok(Some(match own {
            Some(own) if own.at <= shared.at => own,
            _ => shared,
        }))
    }

    /// Takes into account that `step`, the `number`th of the run, took `elapsed`. A step that was
    /// not `ran` took no time, whatever `elapsed` says: it spends none of its budget. When the
    /// budget's own deadline ended it, `by_the_budget`, all the budget is spent, whatever the clock
    /// said.
    pub fn spend(
        &mut self,
        step: &Step,
        number: usize,
        elapsed: Duration,
        ran: bool,
        by_the_budget: bool,
    ) {
        let Some((id, seconds)) = &step.budget else {
            return;
        };
        if !ran {
            return;
        }
        let whole = Duration::from_secs(*seconds);
        let spent = self.spent.entry(id.clone()).or_default();
        spent.time = if by_the_budget {
            whole
        } else {
            spent.time + elapsed
        };
        if spent.by.is_none() && spent.time >= whole {
            spent.by = Some(number);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(timeout: Option<u64>, budget: Option<(&str, u64)>) -> Step {
        let mut step = Step::cargo("rust", "a step", &["test"]);
        step.timeout = timeout;
        step.budget = budget.map(|(id, seconds)| (id.to_owned(), seconds));
        step
    }

    fn seconds_of(deadline: Option<Deadline>, now: Instant) -> Option<(u64, bool, u64)> {
        deadline.map(|deadline| {
            (
                deadline.at.duration_since(now).as_secs(),
                deadline.budget,
                deadline.seconds,
            )
        })
    }

    #[test]
    fn a_step_with_neither_limit_has_no_deadline_and_a_step_with_one_has_that_one() {
        let budgets = Budgets::default();
        let now = Instant::now();
        assert!(budgets.deadline(&step(None, None), now).unwrap().is_none());
        assert_eq!(
            seconds_of(budgets.deadline(&step(Some(5), None), now).unwrap(), now),
            Some((5, false, 5))
        );
        assert_eq!(
            seconds_of(
                budgets.deadline(&step(None, Some(("b", 7))), now).unwrap(),
                now
            ),
            Some((7, true, 7))
        );
    }

    #[test]
    fn the_earlier_of_the_steps_timeout_and_its_budgets_time_is_the_deadline_and_a_tie_is_the_steps()
     {
        let budgets = Budgets::default();
        let now = Instant::now();
        let at = |timeout, budget| {
            seconds_of(
                budgets
                    .deadline(&step(Some(timeout), Some(("b", budget))), now)
                    .unwrap(),
                now,
            )
        };
        assert_eq!(at(2, 9), Some((2, false, 2)));
        assert_eq!(at(9, 2), Some((2, true, 2)));
        assert_eq!(at(4, 4), Some((4, false, 4)));
    }

    #[test]
    fn the_steps_of_a_budget_spend_it_in_the_order_they_run_and_the_last_has_what_is_left() {
        let mut budgets = Budgets::default();
        let now = Instant::now();
        let first = step(None, Some(("b", 10)));
        budgets.spend(&first, 1, Duration::from_secs(3), true, false);
        budgets.spend(&first, 2, Duration::from_secs(4), true, false);
        assert_eq!(
            seconds_of(budgets.deadline(&first, now).unwrap(), now),
            Some((3, true, 10))
        );
        // Another budget, and a step with none, have all of theirs.
        assert_eq!(
            seconds_of(
                budgets
                    .deadline(&step(None, Some(("other", 10))), now)
                    .unwrap(),
                now
            ),
            Some((10, true, 10))
        );
    }

    #[test]
    fn a_budget_that_a_step_spent_is_spent_by_that_step_for_every_later_step_that_names_it() {
        let mut budgets = Budgets::default();
        let now = Instant::now();
        let sharing = step(None, Some(("b", 10)));
        budgets.spend(&sharing, 1, Duration::from_secs(6), true, false);
        // The step that ran into the budget's own deadline took all of it, whatever the clock read.
        budgets.spend(&sharing, 2, Duration::from_secs(1), true, true);
        for later in [step(None, Some(("b", 10))), step(Some(1), Some(("b", 10)))] {
            assert_eq!(budgets.deadline(&later, now).unwrap_err(), 2);
        }
        assert!(budgets.deadline(&step(Some(1), None), now).is_ok());
    }

    #[test]
    fn a_step_that_ends_exactly_when_the_budget_does_spends_it() {
        let mut budgets = Budgets::default();
        let sharing = step(None, Some(("b", 4)));
        budgets.spend(&sharing, 1, Duration::from_secs(4), true, false);
        assert_eq!(budgets.deadline(&sharing, Instant::now()).unwrap_err(), 1);
    }

    #[test]
    fn a_step_that_was_not_run_spends_none_of_its_budget_whatever_time_it_is_given() {
        let mut budgets = Budgets::default();
        let now = Instant::now();
        let sharing = step(None, Some(("b", 10)));
        budgets.spend(&sharing, 1, Duration::from_secs(9), false, false);
        assert_eq!(
            seconds_of(budgets.deadline(&sharing, now).unwrap(), now),
            Some((10, true, 10))
        );
    }
}
