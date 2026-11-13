//! The stop of the broker's service before the program directory changes: what a run does in each
//! state that the service manager reports, and the words for a service that does not stop. They run
//! on every platform; the pending states themselves are the guest's.

use std::cell::Cell;
use std::collections::VecDeque;

use kr_boundary_windows::remedy::{
    ServiceState, StopFailure, StopStep, broker_not_stopped, broker_stop_refused, stop_broker,
    stop_step,
};

/// The states that a fake service reports, one for each read, and the last one for every read after.
struct Fake {
    states: VecDeque<ServiceState>,
    reads: Cell<usize>,
    requests: Cell<usize>,
    waits: Cell<usize>,
}

impl Fake {
    fn new(states: &[ServiceState]) -> Self {
        Fake {
            states: states.iter().copied().collect(),
            reads: Cell::new(0),
            requests: Cell::new(0),
            waits: Cell::new(0),
        }
    }

    fn state(&self) -> ServiceState {
        let at = self.reads.get().min(self.states.len() - 1);
        self.reads.set(self.reads.get() + 1);
        self.states[at]
    }
}

/// Runs the stop against a fake that, once asked, moves on to its next listed state at each read: the
/// request is counted, a wait is counted, and `bound` waits are allowed before the bound runs out.
fn run(
    states: &[ServiceState],
    bound: usize,
    refuse_request: bool,
) -> (Result<bool, StopFailure<&'static str>>, usize, usize) {
    let fake = Fake::new(states);
    let result = stop_broker(
        || Ok(fake.state()),
        || {
            fake.requests.set(fake.requests.get() + 1);
            if refuse_request {
                Err("the request is refused")
            } else {
                Ok(())
            }
        },
        || {
            fake.waits.set(fake.waits.get() + 1);
            fake.waits.get() <= bound
        },
    );
    (result, fake.requests.get(), fake.waits.get())
}

use ServiceState::{Other, Pending, Running, Stopped};

/// Each state decides one step: a stopped service is done, a pending one is waited for (a stop
/// request is refused there), and any other is asked to stop.
#[test]
fn each_state_of_the_service_decides_one_step() {
    assert_eq!(stop_step(Stopped), StopStep::Done);
    assert_eq!(stop_step(Pending), StopStep::Wait);
    assert_eq!(stop_step(Running), StopStep::Request);
    assert_eq!(stop_step(Other), StopStep::Request);
}

/// A stopped service is read once and never asked to stop.
#[test]
fn a_stopped_service_is_not_asked_to_stop() {
    assert_eq!(run(&[Stopped], 5, false), (Ok(true), 0, 0));
}

/// A running service is asked to stop once, waited for, and read as stopped before the run says that
/// it is.
#[test]
fn a_running_service_is_stopped_and_waited_for() {
    assert_eq!(
        run(&[Running, Pending, Pending, Stopped], 5, false),
        (Ok(true), 1, 3)
    );
}

/// A service on its way down is waited for and never asked to stop, since the request is refused
/// there.
#[test]
fn a_service_on_its_way_down_is_waited_for_and_not_asked() {
    assert_eq!(
        run(&[Pending, Pending, Stopped], 5, false),
        (Ok(true), 0, 2)
    );
}

/// A service on its way up is waited for until it runs, then asked to stop and waited for again.
#[test]
fn a_service_on_its_way_up_is_waited_for_then_stopped() {
    assert_eq!(
        run(&[Pending, Pending, Running, Pending, Stopped], 8, false),
        (Ok(true), 1, 4)
    );
}

/// A stop that was cancelled while the service was on its way down leaves it running: the run asks
/// again.
#[test]
fn a_service_that_comes_back_to_running_is_asked_again() {
    assert_eq!(
        run(&[Running, Pending, Running, Pending, Stopped], 8, false),
        (Ok(true), 2, 4)
    );
}

/// A service that never leaves a pending state is waited for until the bound runs out, never asked
/// to stop, and never said to be stopped.
#[test]
fn a_service_that_stays_pending_ends_at_the_bound_with_no_request() {
    assert_eq!(run(&[Pending], 3, false), (Ok(false), 0, 4));
}

/// A service that never stops is asked and waited for until the bound runs out, and is never said to
/// be stopped.
#[test]
fn a_service_that_does_not_stop_is_never_said_to_be_stopped() {
    let (result, requests, waits) = run(&[Running], 3, false);
    assert_eq!(result, Ok(false));
    assert!(requests >= 1, "asked at least once");
    assert_eq!(waits, 4);
}

/// A request that is refused while the service stays in a state that accepts one ends the run with
/// the platform's error, said apart from a failed read; one that is refused because the service went
/// on its way down or is stopped by then is a race: a pending service is waited out, and a read that
/// says stopped ends the run with success at once, even when the bound has run out.
#[test]
fn a_refused_request_ends_the_run_unless_the_state_changed() {
    assert_eq!(
        run(&[Running, Running], 5, true),
        (Err(StopFailure::Refused("the request is refused")), 1, 0)
    );
    assert_eq!(
        run(&[Running, Other], 5, true),
        (Err(StopFailure::Refused("the request is refused")), 1, 0)
    );
    assert_eq!(run(&[Running, Pending, Stopped], 5, true), (Ok(true), 1, 1));
    assert_eq!(run(&[Running, Stopped], 5, true), (Ok(true), 1, 0));
}

/// The read that says stopped after a refused request decides, whatever the wait says: the order
/// `read Running; request fails; read Stopped; wait returns false` is a stopped service.
#[test]
fn a_refused_request_and_a_read_that_says_stopped_is_a_stopped_service_at_the_bound() {
    assert_eq!(run(&[Running, Stopped], 0, true), (Ok(true), 1, 0));
}

/// When the bound has run out, one last read decides: a service that says stopped at it is stopped,
/// and one that is still pending or running is not.
#[test]
fn one_last_read_decides_when_the_bound_runs_out() {
    // The bound ends right after the request: the last read says stopped.
    assert_eq!(run(&[Running, Stopped], 0, false), (Ok(true), 1, 1));
    // A refused request, a pending service, the bound ends: the last read says stopped.
    assert_eq!(run(&[Running, Pending, Stopped], 0, true), (Ok(true), 1, 1));
    // The same, and the last read still says pending.
    assert_eq!(
        run(&[Running, Pending, Pending], 0, true),
        (Ok(false), 1, 1)
    );
    // A service that is pending from the start and says stopped at the last read.
    assert_eq!(run(&[Pending, Stopped], 0, false), (Ok(true), 0, 1));
    // The last read says running: not stopped.
    assert_eq!(run(&[Running, Running], 0, false), (Ok(false), 1, 1));
}

/// A read that fails ends the run with its error, said apart from a refused request: after a
/// request that was refused, and at the last read of the bound. A service that could not be read is
/// never said to be stopped.
#[test]
fn a_read_that_fails_is_never_a_stopped_service() {
    let result: Result<bool, StopFailure<&str>> =
        stop_broker(|| Err("the status could not be read"), || Ok(()), || true);
    assert_eq!(
        result,
        Err(StopFailure::Read("the status could not be read"))
    );

    // The first read answers, the one after a refused request fails.
    let reads = Cell::new(0);
    let result = stop_broker(
        || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                Ok(Running)
            } else {
                Err("the status could not be read")
            }
        },
        || Err("the request is refused"),
        || true,
    );
    assert_eq!(
        result,
        Err(StopFailure::Read("the status could not be read"))
    );

    // The last read of the bound fails.
    let reads = Cell::new(0);
    let result = stop_broker(
        || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                Ok(Pending)
            } else {
                Err("the status could not be read")
            }
        },
        || Ok(()),
        || false,
    );
    assert_eq!(
        result,
        Err(StopFailure::Read("the status could not be read"))
    );
}

/// A repair whose stop request was refused is told what the refusal was and what the run left: its
/// words are a repair's, and say neither that the service did not reach the stopped state (nothing
/// was waited for) nor that it stays stopped.
#[test]
fn the_words_for_a_refused_stop_request_are_a_repairs() {
    let words = broker_stop_refused("access is denied (error 5)");
    assert!(
        words.starts_with(
            "The broker's service refused the request to stop it (access is denied (error 5))"
        ),
        "{words}"
    );
    assert!(
        words.contains("so this run stopped before it changed the program directory."),
        "{words}"
    );
    assert!(
        words.contains("What it had already changed stays, and a repair has no rollback."),
        "{words}"
    );
    assert!(
        words.ends_with("Run the setup program again when the service is stopped or running."),
        "{words}"
    );
    assert!(
        !words.contains("did not reach the stopped state"),
        "{words}"
    );
    assert!(!words.contains("stays stopped"), "{words}");
}

/// The words for a service that did not stop are chosen by the run: a repair says that what it had
/// changed stays and that it has no rollback; an installation says only that it stopped before it
/// changed the program directory, since its own failure path says what is undone.
#[test]
fn the_words_for_a_service_that_does_not_stop_are_chosen_by_the_run() {
    let first = "The broker's service did not reach the stopped state, so this run stopped before it changed the program directory.";
    let repair = broker_not_stopped(true);
    assert!(repair.starts_with(first), "{repair}");
    assert!(
        repair.contains("What it had already changed stays, and a repair has no rollback."),
        "{repair}"
    );
    assert!(
        repair.ends_with("Run the setup program again when the service is stopped or running."),
        "{repair}"
    );
    let installation = broker_not_stopped(false);
    assert_eq!(installation, first);
    for text in [&repair, &installation] {
        assert!(!text.contains("stays stopped"), "{text}");
    }
    assert!(!installation.contains("stays"), "{installation}");
    assert!(!installation.contains("rollback"), "{installation}");
}
