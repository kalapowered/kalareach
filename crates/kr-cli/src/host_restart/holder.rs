//! What `kr host restart` does where a process holds the environment and does not answer: it may be
//! a daemon that is starting, as another restart's start makes one, or one that is stopping. The
//! command does not stop it and does not start beside it: it waits, within the start's bound, for
//! the holder to answer or to let go.

use std::time::Duration;

use crate::host_stop::{Endpoint, LOOK_EVERY, Operations};

/// What the wait for a holder came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Holder {
    /// A daemon answers now.
    Answers,
    /// Nothing holds the environment and nothing listens: no daemon runs.
    Gone,
    /// The holder still did not answer and still held the environment when the bound ended.
    /// `replied` is whether any look of the wait found a reply that proves nothing and cannot be
    /// used: the holder did not then "not answer".
    Silent { replied: bool },
}

/// Waits up to `bound` for the holder to answer or to let go.
///
/// Each round asks whether the environment is held, then what answers at its endpoint; a daemon of
/// any generation that answers ends the wait, and so does a free environment where nothing
/// listens. A holder that is not looked at, a listener that does not answer and a lock that is
/// held are waited through, and the bound is counted from the first call on the runtime's clock.
pub(super) async fn wait(operations: &impl Operations, bound: Duration) -> Holder {
    let deadline = tokio::time::Instant::now() + bound;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut replied = false;
    loop {
        let held = operations.held(left()).await;
        match operations.look(left()).await {
            Endpoint::Same(_) | Endpoint::Another => return Holder::Answers,
            Endpoint::Nobody if matches!(held, Ok(false)) => return Holder::Gone,
            Endpoint::Unproved(_) => replied = true,
            Endpoint::Nobody | Endpoint::Unclear => {}
        }
        if left().is_zero() {
            return Holder::Silent { replied };
        }
        operations.pause(LOOK_EVERY.min(left())).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_client::shown::Shown;
    use kr_protocol::identity::ProcessStartIdentity;

    use super::*;

    /// One answer of an operation, and the time it takes on the clock; none takes the whole bound
    /// the operation was given.
    struct Step<T> {
        gives: T,
        takes: Option<Duration>,
    }

    fn at_once<T>(gives: T) -> Step<T> {
        Step {
            gives,
            takes: Some(Duration::ZERO),
        }
    }

    /// The answers an operation gives in turn, the last one for every call after them.
    struct Script<T>(Mutex<Vec<Step<T>>>);

    impl<T: Clone> Script<T> {
        fn of(steps: Vec<Step<T>>) -> Self {
            Self(Mutex::new(steps))
        }

        fn next(&self) -> Step<T> {
            let mut steps = self.0.lock().expect("the script");
            let step = if steps.len() > 1 {
                steps.remove(0)
            } else {
                let last = steps.first().expect("a step");
                Step {
                    gives: last.gives.clone(),
                    takes: last.takes,
                }
            };
            drop(steps);
            step
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Held(Duration),
        Look(Duration),
        Pause(Duration),
    }

    /// The operations of a case: each answer is the script's, the clock is the paused runtime's, and
    /// every call is recorded with the time on that clock.
    struct Supplied {
        start: tokio::time::Instant,
        calls: Mutex<Vec<(Duration, Call)>>,
        held: Script<std::result::Result<bool, Shown>>,
        look: Script<Endpoint>,
    }

    impl Supplied {
        fn new(
            held: Vec<Step<std::result::Result<bool, Shown>>>,
            look: Vec<Step<Endpoint>>,
        ) -> Self {
            Self {
                start: tokio::time::Instant::now(),
                calls: Mutex::new(Vec::new()),
                held: Script::of(held),
                look: Script::of(look),
            }
        }

        fn record(&self, call: Call) {
            self.calls
                .lock()
                .expect("the calls")
                .push((self.start.elapsed(), call));
        }

        fn calls(&self) -> Vec<(Duration, Call)> {
            self.calls.lock().expect("the calls").clone()
        }

        fn looks(&self) -> usize {
            self.calls()
                .iter()
                .filter(|(_, call)| matches!(call, Call::Look(_)))
                .count()
        }
    }

    impl Operations for Supplied {
        async fn held(&self, within: Duration) -> std::result::Result<bool, Shown> {
            self.record(Call::Held(within));
            let step = self.held.next();
            tokio::time::advance(step.takes.unwrap_or(within)).await;
            step.gives
        }

        fn process_state(&self, _old: &ProcessStartIdentity) -> kr_ipc::identity::ProcessState {
            unreachable!("the wait for a holder asks of no process")
        }

        async fn look(&self, within: Duration) -> Endpoint {
            self.record(Call::Look(within));
            let step = self.look.next();
            tokio::time::advance(step.takes.unwrap_or(within)).await;
            step.gives
        }

        fn named_daemon(&self) -> Option<u64> {
            unreachable!("the wait for a holder asks of no lock file")
        }

        async fn pause(&self, time: Duration) {
            self.record(Call::Pause(time));
            tokio::time::advance(time).await;
        }
    }

    const BOUND: Duration = Duration::from_secs(30);

    /// A holder that answers at the third look ends the wait there, after two pauses of one look's
    /// interval each, and nothing waits for the bound.
    #[tokio::test(start_paused = true)]
    async fn a_holder_that_answers_ends_the_wait_where_it_answers() {
        let supplied = Supplied::new(
            vec![at_once(Ok(true))],
            vec![
                at_once(Endpoint::Unclear),
                at_once(Endpoint::Nobody),
                at_once(Endpoint::Another),
            ],
        );
        assert_eq!(wait(&supplied, BOUND).await, Holder::Answers);
        assert_eq!(supplied.looks(), 3);
        assert_eq!(
            supplied.start.elapsed(),
            LOOK_EVERY * 2,
            "two pauses and no more"
        );
    }

    /// The answer of a look, for a case.
    fn an_answer() -> crate::host_stop::Answered {
        crate::host_stop::Answered::for_a_case(kr_protocol::ids::ControllerGeneration::new(1))
    }

    /// A daemon of any generation answers: the same one that was asked and another are both an
    /// answer, since nothing was asked of a daemon here.
    #[tokio::test(start_paused = true)]
    async fn an_answer_of_either_generation_is_an_answer() {
        for answer in [Endpoint::Same(an_answer()), Endpoint::Another] {
            let supplied = Supplied::new(vec![at_once(Ok(true))], vec![at_once(answer)]);
            assert_eq!(wait(&supplied, BOUND).await, Holder::Answers, "{answer:?}");
            assert_eq!(supplied.start.elapsed(), Duration::ZERO, "{answer:?}");
        }
    }

    /// A daemon that answers while the lock cannot be looked at is an answer all the same.
    #[tokio::test(start_paused = true)]
    async fn an_answer_counts_where_the_lock_cannot_be_looked_at() {
        let supplied = Supplied::new(
            vec![at_once(Err(Shown::said("the lock could not be looked at")))],
            vec![at_once(Endpoint::Same(an_answer()))],
        );
        assert_eq!(wait(&supplied, BOUND).await, Holder::Answers);
    }

    /// Where the environment is free and nothing listens at the first look, no daemon runs: one
    /// round, no pause.
    #[tokio::test(start_paused = true)]
    async fn a_free_environment_where_nothing_listens_is_no_daemon_at_once() {
        let supplied = Supplied::new(vec![at_once(Ok(false))], vec![at_once(Endpoint::Nobody)]);
        assert_eq!(wait(&supplied, BOUND).await, Holder::Gone);
        assert_eq!(supplied.start.elapsed(), Duration::ZERO);
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::Held(BOUND)),
                (Duration::ZERO, Call::Look(BOUND)),
            ]
        );
    }

    /// A holder that has stopped listening and still holds the lock is waited for: it is gone only
    /// once the lock is free as well.
    #[tokio::test(start_paused = true)]
    async fn a_holder_that_stopped_listening_is_gone_once_the_lock_is_free() {
        let supplied = Supplied::new(
            vec![at_once(Ok(true)), at_once(Ok(true)), at_once(Ok(false))],
            vec![at_once(Endpoint::Nobody)],
        );
        assert_eq!(wait(&supplied, BOUND).await, Holder::Gone);
        assert_eq!(supplied.looks(), 3);
        assert_eq!(supplied.start.elapsed(), LOOK_EVERY * 2);
    }

    /// A holder that never answers and never lets go ends the wait at the bound and not before; the
    /// last look is bounded by what is left, and the clock stands at the bound.
    #[tokio::test(start_paused = true)]
    async fn a_holder_that_never_answers_ends_the_wait_at_the_bound() {
        let supplied = Supplied::new(vec![at_once(Ok(true))], vec![at_once(Endpoint::Unclear)]);
        assert_eq!(
            wait(&supplied, BOUND).await,
            Holder::Silent { replied: false }
        );
        assert_eq!(supplied.start.elapsed(), BOUND);
        let calls = supplied.calls();
        assert!(
            calls.len() > 100,
            "it looked again and again: {}",
            calls.len()
        );
        assert!(
            calls.iter().all(|(at, call)| *at <= BOUND
                && !matches!(call, Call::Pause(time) if *time > LOOK_EVERY)),
            "no call after the bound and no pause longer than a look's interval"
        );
    }

    /// A holder whose look finds a reply that proves nothing is not one that never answers: the wait
    /// ends at the bound as for a holder that is silent, and says that a reply came.
    #[tokio::test(start_paused = true)]
    async fn a_holder_whose_look_finds_a_reply_ends_the_wait_as_one_that_replied() {
        let supplied = Supplied::new(
            vec![at_once(Ok(true))],
            vec![
                at_once(Endpoint::Unclear),
                at_once(Endpoint::Unproved(an_answer())),
                at_once(Endpoint::Unclear),
            ],
        );
        assert_eq!(
            wait(&supplied, BOUND).await,
            Holder::Silent { replied: true }
        );
    }

    /// A look that takes the whole of what is left, as a listener that does not answer does, ends
    /// the wait at the bound too: the wait never goes on past it.
    #[tokio::test(start_paused = true)]
    async fn a_look_that_takes_what_is_left_does_not_carry_the_wait_past_the_bound() {
        let supplied = Supplied::new(
            vec![at_once(Ok(true))],
            vec![Step {
                gives: Endpoint::Unclear,
                takes: None,
            }],
        );
        assert_eq!(
            wait(&supplied, BOUND).await,
            Holder::Silent { replied: false }
        );
        assert_eq!(supplied.start.elapsed(), BOUND);
    }
}
