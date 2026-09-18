//! The action window a first admission is bound to, and the deadline it produces.
//!
//! Section 9 puts three bounds on an accepted deadline and takes the earliest: the window's
//! expiry, receipt time plus the requested lifetime, and any applicable authority or subject
//! deadline. [`kr_transport::window`] owns the arithmetic, because the same rule governs a network
//! connection and a local one and two implementations of it would drift. What is here is what the
//! worker adds: the sentence a caller is given when a window admits nothing, and the wall-clock
//! stamp a receipt carries.
//!
//! The stamp is not a deadline. Nothing expires against it, and it exists because a person and a
//! wire format read a wall-clock time while a continuous instant is private to the process that
//! anchored it. Expiry is decided on the continuous clock, every time.

use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
use kr_protocol::scalars::{DurationMs, TimestampMs};
use kr_transport::clock::ContinuousInstant;
use kr_transport::window::{AcceptedDeadline, ActionWindowIssuer, WindowRefusal};

use crate::error::{Result, WorkerError};

/// Derives the accepted deadline of one first admission.
///
/// `received_at` is when the host read the request, not when it reached this point. Section 9
/// measures the requested lifetime from receipt time, and the admission runs inside a serial
/// boundary a request may have queued for: sampling the clock here would hand the request its
/// whole lifetime back after the wait.
///
/// `authority_deadline` is the third bound. A local operating-system caller acts under the
/// worker's own authority over its session, which does not expire, so there is nothing to pass;
/// a caller acting under a grant passes that grant's deadline, and it wins whenever it is the
/// earliest of the three.
///
/// # Errors
///
/// Returns [`WorkerError::WindowExpired`] when the window cannot first-admit the request.
pub fn first_admission(
    windows: &ActionWindowIssuer,
    action_window_id: &ActionWindowId,
    connection_id: ConnectionId,
    boot_epoch: BootEpoch,
    received_at: ContinuousInstant,
    requested_ttl_ms: DurationMs,
    authority_deadline: Option<ContinuousInstant>,
) -> Result<AcceptedDeadline> {
    windows
        .accept_at(
            action_window_id,
            connection_id,
            boot_epoch,
            received_at,
            requested_ttl_ms,
            authority_deadline,
        )
        .map_err(|refusal| WorkerError::WindowExpired {
            detail: refusal_detail(refusal).to_owned(),
        })
}

/// Returns the wall-clock stamp a receipt carries for a deadline on the continuous clock.
///
/// The conversion is a subtraction rather than an addition of two clocks: what is left of the
/// deadline is measured on the clock that decides it, and only then laid over the wall clock. A
/// deadline already spent stamps the present moment rather than a time in the past, because the
/// receipt's own state is what says it expired.
#[must_use]
pub fn receipt_stamp(
    now: ContinuousInstant,
    deadline: ContinuousInstant,
    wall_now: TimestampMs,
) -> TimestampMs {
    let remaining =
        u64::try_from(deadline.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX);
    TimestampMs::new(wall_now.get().saturating_add(remaining))
}

/// Returns the sentence a caller is given when a window cannot first-admit a request.
///
/// Each one says what to do next, because each has a different answer. A window that expired is
/// replaced by one the host has already sent, and the request is submitted again as a *new*
/// action: replacing the window changes the payload digest, so it is a first admission rather
/// than an automatic retry of this one.
#[must_use]
pub const fn refusal_detail(refusal: WindowRefusal) -> &'static str {
    match refusal {
        WindowRefusal::Unknown => {
            "this action window is not one this host issued, so the request cannot be admitted for \
             the first time"
        }
        WindowRefusal::WrongConnection => {
            "this action window belongs to another connection, so it admits nothing here"
        }
        WindowRefusal::StaleBoot => {
            "this action window was issued in another boot of this host, so it admits nothing"
        }
        WindowRefusal::Expired => {
            "this action window has expired; the host has already replaced it, so submit a new \
             request rather than replaying this one"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::limits::{DEFAULT_MUTATION_TTL, MAX_ACTION_WINDOW, MAX_MUTATION_TTL};
    use kr_protocol::scalars::Uuid;
    use kr_transport::clock::{ContinuousClock as _, ManualClock};
    use kr_transport::window::{DeadlineBound, MAX_WINDOW_VALIDITY};
    use std::sync::Arc;
    use std::time::Duration;

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn issuer(clock: &ManualClock) -> ActionWindowIssuer {
        ActionWindowIssuer::with_default_validity(Arc::new(clock.clone()))
    }

    #[test]
    fn the_accepted_deadline_is_the_earliest_of_the_three_bounds() {
        let clock = ManualClock::new();
        let windows = issuer(&clock);
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");

        // The default two-minute lifetime inside a five-minute window: the request bounds it.
        let accepted = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::RequestedTtl);

        // A lifetime beyond the window: the window bounds it.
        let accepted = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            MAX_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::WindowExpiry);

        // An authority deadline sooner than either: the authority bounds it.
        let authority = clock
            .now()
            .checked_add(Duration::from_secs(10))
            .expect("an instant");
        let accepted = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            Some(authority),
        )
        .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::AuthorityDeadline);
        assert_eq!(accepted.deadline, authority);
    }

    #[test]
    fn the_default_lifetime_is_two_minutes_and_the_cap_is_five() {
        assert_eq!(DEFAULT_MUTATION_TTL.get(), 120_000);
        assert_eq!(MAX_MUTATION_TTL.get(), 300_000);
        assert_eq!(MAX_ACTION_WINDOW.get(), 300_000);
        assert_eq!(MAX_WINDOW_VALIDITY, Duration::from_millis(300_000));

        // A lifetime beyond the cap is shortened rather than refused: section 9 lets the host
        // shorten it, and a request does not fail for asking.
        let clock = ManualClock::new();
        let windows = ActionWindowIssuer::new(Arc::new(clock.clone()), Duration::from_secs(3_600));
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        assert_eq!(
            window.valid_for_ms.get(),
            MAX_ACTION_WINDOW.get(),
            "a window is capped at five minutes whatever validity was asked for"
        );
        let accepted = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DurationMs::new(24 * 60 * 60 * 1000),
            None,
        )
        .expect("an accepted deadline");
        assert!(
            accepted
                .deadline
                .saturating_duration_since(clock.now())
                .as_millis()
                <= u128::from(MAX_MUTATION_TTL.get())
        );
    }

    #[test]
    fn a_window_that_admits_nothing_says_which_of_the_four_reasons_it_is() {
        let clock = ManualClock::new();
        let windows = issuer(&clock);
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");

        let other_connection = first_admission(
            &windows,
            &window.action_window_id,
            connection(2),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        );
        assert!(matches!(
            other_connection,
            Err(WorkerError::WindowExpired { ref detail })
                if detail == refusal_detail(WindowRefusal::WrongConnection)
        ));

        let other_boot = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(2),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        );
        assert!(matches!(
            other_boot,
            Err(WorkerError::WindowExpired { ref detail })
                if detail == refusal_detail(WindowRefusal::StaleBoot)
        ));

        let unknown = ActionWindowId::new("never-issued".to_owned()).expect("a window name");
        let never_issued = first_admission(
            &windows,
            &unknown,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        );
        assert!(matches!(
            never_issued,
            Err(WorkerError::WindowExpired { ref detail })
                if detail == refusal_detail(WindowRefusal::Unknown)
        ));

        clock.advance(MAX_WINDOW_VALIDITY + Duration::from_secs(1));
        let expired = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        );
        assert!(matches!(
            expired,
            Err(WorkerError::WindowExpired { ref detail })
                if detail == refusal_detail(WindowRefusal::Expired)
        ));
    }

    #[test]
    fn an_expired_window_cannot_first_admit_anything_however_long_it_is_retained() {
        // The window is expired and the request is replayed at intervals across the whole
        // de-duplication retention period. None of them is admitted, and the reason never becomes
        // a different one: retention keeps receipts, and a window is not a receipt.
        let clock = ManualClock::new();
        let windows = issuer(&clock);
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        clock.advance(MAX_WINDOW_VALIDITY + Duration::from_secs(1));
        for _ in 0..30 {
            clock.advance(Duration::from_secs(24 * 60 * 60));
            let refused = first_admission(
                &windows,
                &window.action_window_id,
                connection(1),
                BootEpoch::new(1),
                clock.now(),
                DEFAULT_MUTATION_TTL,
                None,
            );
            assert!(matches!(refused, Err(WorkerError::WindowExpired { .. })));
        }
    }

    #[test]
    fn the_receipt_stamp_carries_what_is_left_and_never_expires_against_the_wall_clock() {
        let clock = ManualClock::new();
        let now = clock.now();
        let deadline = now
            .checked_add(Duration::from_secs(120))
            .expect("an instant");
        let wall = TimestampMs::new(1_700_000_000_000);
        assert_eq!(
            receipt_stamp(now, deadline, wall).get(),
            wall.get() + 120_000
        );

        // A deadline already spent stamps the present rather than a moment in the past.
        clock.advance(Duration::from_secs(300));
        assert_eq!(
            receipt_stamp(clock.now(), deadline, wall).get(),
            wall.get(),
            "the receipt's own state is what says it expired, not its stamp"
        );
    }

    #[test]
    fn a_lifetime_is_measured_from_receipt_time_rather_than_from_the_admission() {
        // The request arrives, then waits: for a serial boundary, for a lock, for whatever else the
        // host does before it admits anything. A two-minute lifetime that waited three minutes has
        // run out, and the admission must say so rather than starting the two minutes again.
        let clock = ManualClock::new();
        let windows = issuer(&clock);
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        let received_at = clock.now();
        clock.advance(Duration::from_secs(180));
        let accepted = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            received_at,
            DEFAULT_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::RequestedTtl);
        assert!(
            accepted.deadline <= clock.now(),
            "the lifetime ran out while the request waited"
        );

        // Sampling the clock at the admission instead would have given it the whole two minutes
        // back, which is what makes the parameter the point rather than a convenience.
        let resampled = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        assert!(resampled.deadline > clock.now());
    }

    #[test]
    fn a_retry_keeps_the_deadline_the_first_admission_derived() {
        // The window is still live and the same request arrives again five seconds later. The
        // second derivation is later than the first, which is exactly why a retry must not be
        // given one: the journal returns the retained receipt with its original deadline, and this
        // is the arithmetic that would have refreshed it.
        let clock = ManualClock::new();
        let windows = issuer(&clock);
        let window = windows
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        let first = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        clock.advance(Duration::from_secs(5));
        let second = first_admission(
            &windows,
            &window.action_window_id,
            connection(1),
            BootEpoch::new(1),
            clock.now(),
            DEFAULT_MUTATION_TTL,
            None,
        )
        .expect("an accepted deadline");
        assert!(
            second.deadline > first.deadline,
            "deriving a deadline twice gives the later one, so a retry is answered from the \
             journal rather than derived again"
        );
    }
}
