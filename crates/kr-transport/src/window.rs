//! Host-issued action windows and the section 9 deadline derivation.
//!
//! A window is a freshness resource, not a permission. Section 9: an original online request
//! carries a host-issued `action_window_id` bound to this authenticated connection, the host boot
//! and a continuous-time deadline at most five minutes away. The host derives the accepted
//! deadline as the earliest of window expiry, receipt time plus the requested time to live, and
//! any applicable authority or subject deadline.
//!
//! Three rules follow from that, and this module exists to hold all three in one place:
//!
//! * The client never supplies an absolute deadline. The window it receives carries a *duration*,
//!   which it uses to schedule renewal; the authoritative deadline lives here, on the host's
//!   suspend-aware continuous clock.
//! * A window belongs to one connection and one boot. A window from another connection, or from
//!   before a restart, cannot first-admit anything, whatever else it proves.
//! * Replacing a window changes the payload digest, so it is never an automatic retry. That is a
//!   property of the digest in `kr-protocol`; nothing here can weaken it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kr_protocol::hello::ActionWindow;
use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
use kr_protocol::limits::{MAX_ACTION_WINDOW, MAX_MUTATION_TTL};
use kr_protocol::scalars::{DurationMs, TimestampMs};

use crate::clock::{ContinuousClock, ContinuousInstant};
use crate::error::{Result, TransportError};
use crate::random::fresh_action_window_id;

/// The longest a window stays valid.
///
/// Section 9: at most five minutes away.
pub const MAX_WINDOW_VALIDITY: Duration = Duration::from_millis(MAX_ACTION_WINDOW.get());

/// The longest lifetime an ordinary mutation may request.
pub const MAX_ACCEPTED_TTL: Duration = Duration::from_millis(MAX_MUTATION_TTL.get());

/// A window as the host holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IssuedWindow {
    connection_id: ConnectionId,
    boot_epoch: BootEpoch,
    expires_at: ContinuousInstant,
}

/// Why a window cannot first-admit a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WindowRefusal {
    /// The window was never issued, or it has been retired.
    #[error("the action window is unknown")]
    Unknown,
    /// The window belongs to another connection.
    #[error("the action window belongs to another connection")]
    WrongConnection,
    /// The window was issued before the host restarted.
    #[error("the action window predates the current host boot")]
    StaleBoot,
    /// The window has expired.
    #[error("the action window has expired")]
    Expired,
}

/// The accepted deadline of one admitted mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedDeadline {
    /// The deadline on the host's continuous clock. This is the authority.
    pub deadline: ContinuousInstant,
    /// Which bound produced it, for diagnosis and for the receipt.
    pub bound: DeadlineBound,
}

/// Which of the section 9 bounds decided an accepted deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineBound {
    /// The window expires first.
    WindowExpiry,
    /// Receipt time plus the requested time to live expires first.
    RequestedTtl,
    /// An authority or subject deadline expires first.
    AuthorityDeadline,
}

/// Issues, renews and validates the action windows of one host.
///
/// It is shared by every connection the host serves, so one restart retires every window at once
/// and one connection's windows can never be used by another.
#[derive(Debug)]
pub struct ActionWindowIssuer {
    clock: Arc<dyn ContinuousClock>,
    validity: Duration,
    windows: Mutex<HashMap<ActionWindowId, IssuedWindow>>,
}

impl ActionWindowIssuer {
    /// Creates an issuer whose windows last `validity`, capped at five minutes.
    #[must_use]
    pub fn new(clock: Arc<dyn ContinuousClock>, validity: Duration) -> Self {
        Self {
            clock,
            validity: validity.min(MAX_WINDOW_VALIDITY),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Creates an issuer whose windows last the maximum five minutes.
    #[must_use]
    pub fn with_default_validity(clock: Arc<dyn ContinuousClock>) -> Self {
        Self::new(clock, MAX_WINDOW_VALIDITY)
    }

    /// Issues a window bound to one connection and boot.
    ///
    /// # Errors
    ///
    /// Returns a cryptography error when the generator is unavailable.
    pub fn issue(
        &self,
        connection_id: ConnectionId,
        boot_epoch: BootEpoch,
    ) -> Result<ActionWindow> {
        let action_window_id = fresh_action_window_id()?;
        let now = self.clock.now();
        let expires_at = now
            .checked_add(self.validity)
            .ok_or(TransportError::LimitExceeded {
                what: "the action window deadline",
                limit: 0,
            })?;
        self.retire_expired(now);
        self.lock().insert(
            action_window_id.clone(),
            IssuedWindow {
                connection_id,
                boot_epoch,
                expires_at,
            },
        );
        Ok(ActionWindow {
            action_window_id,
            connection_id,
            boot_epoch,
            issued_at_ms: host_timestamp(),
            valid_for_ms: DurationMs::new(
                u64::try_from(self.validity.as_millis()).unwrap_or(u64::MAX),
            ),
        })
    }

    /// Retires a window, which is what happens when its connection ends.
    pub fn retire(&self, action_window_id: &ActionWindowId) {
        self.lock().remove(action_window_id);
    }

    /// Retires every window of one connection.
    ///
    /// Closing the control stream ends the connection, and a window that outlived its connection
    /// could first-admit a request through a connection that no longer exists.
    pub fn retire_connection(&self, connection_id: ConnectionId) {
        self.lock()
            .retain(|_, window| window.connection_id != connection_id);
    }

    /// Checks a window against the connection presenting it.
    ///
    /// # Errors
    ///
    /// Returns the first reason the window cannot first-admit a request.
    pub fn validate(
        &self,
        action_window_id: &ActionWindowId,
        connection_id: ConnectionId,
        boot_epoch: BootEpoch,
    ) -> std::result::Result<ContinuousInstant, WindowRefusal> {
        let window = *self
            .lock()
            .get(action_window_id)
            .ok_or(WindowRefusal::Unknown)?;
        if window.connection_id != connection_id {
            return Err(WindowRefusal::WrongConnection);
        }
        if window.boot_epoch != boot_epoch {
            return Err(WindowRefusal::StaleBoot);
        }
        if self.clock.now() >= window.expires_at {
            return Err(WindowRefusal::Expired);
        }
        Ok(window.expires_at)
    }

    /// Derives the accepted deadline of one first admission.
    ///
    /// The result is the earliest of the window's expiry, receipt time plus the requested time to
    /// live, and any applicable authority or subject deadline. A requested lifetime longer than
    /// five minutes is shortened rather than refused: section 9 lets the host shorten it, and a
    /// request does not fail for asking.
    ///
    /// # Errors
    ///
    /// Returns the window refusal when the window cannot first-admit anything.
    pub fn accept(
        &self,
        action_window_id: &ActionWindowId,
        connection_id: ConnectionId,
        boot_epoch: BootEpoch,
        requested_ttl: DurationMs,
        authority_deadline: Option<ContinuousInstant>,
    ) -> std::result::Result<AcceptedDeadline, WindowRefusal> {
        self.accept_at(
            action_window_id,
            connection_id,
            boot_epoch,
            self.clock.now(),
            requested_ttl,
            authority_deadline,
        )
    }

    /// Derives the accepted deadline of one first admission from a recorded receipt time.
    ///
    /// Section 9 measures the requested lifetime from *receipt* time, which is when the request
    /// arrived rather than when the host got round to admitting it. A host whose admission waits
    /// for a serial boundary must therefore record the moment it read the request and pass it here;
    /// sampling the clock inside this call would give the request its whole lifetime back after the
    /// wait, which is exactly what a duration rather than a refreshable deadline forbids.
    ///
    /// # Errors
    ///
    /// Returns the window refusal when the window cannot first-admit anything.
    pub fn accept_at(
        &self,
        action_window_id: &ActionWindowId,
        connection_id: ConnectionId,
        boot_epoch: BootEpoch,
        received_at: ContinuousInstant,
        requested_ttl: DurationMs,
        authority_deadline: Option<ContinuousInstant>,
    ) -> std::result::Result<AcceptedDeadline, WindowRefusal> {
        let window_expiry = self.validate(action_window_id, connection_id, boot_epoch)?;
        let ttl = Duration::from_millis(requested_ttl.get()).min(MAX_ACCEPTED_TTL);
        let ttl_deadline = received_at.checked_add(ttl).unwrap_or(window_expiry);

        let mut chosen = AcceptedDeadline {
            deadline: window_expiry,
            bound: DeadlineBound::WindowExpiry,
        };
        if ttl_deadline < chosen.deadline {
            chosen = AcceptedDeadline {
                deadline: ttl_deadline,
                bound: DeadlineBound::RequestedTtl,
            };
        }
        if let Some(authority) = authority_deadline
            && authority < chosen.deadline
        {
            chosen = AcceptedDeadline {
                deadline: authority,
                bound: DeadlineBound::AuthorityDeadline,
            };
        }
        Ok(chosen)
    }

    /// Returns how many windows are outstanding.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.lock().len()
    }

    /// Retires every window whose deadline has passed, and says how many went.
    ///
    /// A host calls this when its clocks moved in a way that owes a revalidation: a wake, a reboot
    /// or a step of the wall clock. The deadlines themselves are on the suspend-aware continuous
    /// clock, so this is a revalidation rather than a correction - it establishes that what is
    /// still held is still live, before anything is served against it.
    pub fn revalidate(&self) -> usize {
        let now = self.clock.now();
        let before = self.lock().len();
        self.retire_expired(now);
        before.saturating_sub(self.lock().len())
    }

    fn retire_expired(&self, now: ContinuousInstant) {
        self.lock().retain(|_, window| window.expires_at > now);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ActionWindowId, IssuedWindow>> {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Returns the host's wall-clock stamp, for display and diagnosis only.
///
/// Nothing expires against it. A host whose clock is before the epoch stamps zero rather than
/// refusing to issue a window, because the window's authority is its continuous deadline.
fn host_timestamp() -> TimestampMs {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    TimestampMs::new(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use kr_protocol::scalars::Uuid;

    fn issuer(clock: &ManualClock, validity: Duration) -> ActionWindowIssuer {
        ActionWindowIssuer::new(Arc::new(clock.clone()), validity)
    }

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// KR-REQ-23.20: the host issues action windows of at most five minutes.
    #[test]
    fn a_window_is_capped_at_five_minutes() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, Duration::from_secs(3600));
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        assert_eq!(window.valid_for_ms.get(), 300_000);
    }

    /// KR-REQ-23.20: a window admits only on the connection it was issued to.
    #[test]
    fn another_connections_window_cannot_first_admit_anything() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, MAX_WINDOW_VALIDITY);
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        assert_eq!(
            issuer.validate(&window.action_window_id, connection(2), BootEpoch::new(1)),
            Err(WindowRefusal::WrongConnection)
        );
    }

    /// KR-REQ-23.20: a window admits only in the host boot that issued it.
    #[test]
    fn a_window_from_before_a_restart_cannot_first_admit_anything() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, MAX_WINDOW_VALIDITY);
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        assert_eq!(
            issuer.validate(&window.action_window_id, connection(1), BootEpoch::new(2)),
            Err(WindowRefusal::StaleBoot)
        );
    }

    /// KR-REQ-23.20: a window expires on the host's own continuous clock.
    #[test]
    fn a_window_expires_on_the_continuous_clock() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, Duration::from_secs(60));
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        clock.advance(Duration::from_secs(59));
        assert!(
            issuer
                .validate(&window.action_window_id, connection(1), BootEpoch::new(1))
                .is_ok()
        );
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            issuer.validate(&window.action_window_id, connection(1), BootEpoch::new(1)),
            Err(WindowRefusal::Expired)
        );
    }

    /// KR-REQ-23.20: the host derives the accepted deadline; the client supplies none.
    #[test]
    fn the_accepted_deadline_is_the_earliest_applicable_bound() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, Duration::from_secs(300));
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        let id = &window.action_window_id;

        // A two-minute request inside a five-minute window is bounded by the request.
        let accepted = issuer
            .accept(
                id,
                connection(1),
                BootEpoch::new(1),
                DurationMs::new(120_000),
                None,
            )
            .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::RequestedTtl);

        // A request longer than the window is bounded by the window.
        let accepted = issuer
            .accept(
                id,
                connection(1),
                BootEpoch::new(1),
                DurationMs::new(600_000),
                None,
            )
            .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::WindowExpiry);

        // An authority deadline sooner than either wins.
        let authority = clock_instant(&clock, Duration::from_secs(10));
        let accepted = issuer
            .accept(
                id,
                connection(1),
                BootEpoch::new(1),
                DurationMs::new(120_000),
                Some(authority),
            )
            .expect("an accepted deadline");
        assert_eq!(accepted.bound, DeadlineBound::AuthorityDeadline);
        assert_eq!(accepted.deadline, authority);
    }

    /// KR-REQ-09.01, KR-REQ-23.20: a requested lifetime is bounded at five minutes.
    #[test]
    fn a_requested_lifetime_is_shortened_to_the_five_minute_maximum() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, Duration::from_secs(300));
        let window = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        let accepted = issuer
            .accept(
                &window.action_window_id,
                connection(1),
                BootEpoch::new(1),
                DurationMs::new(24 * 60 * 60 * 1000),
                None,
            )
            .expect("an accepted deadline");
        assert!(accepted.deadline.since_anchor() <= MAX_ACCEPTED_TTL);
    }

    #[test]
    fn ending_a_connection_retires_its_windows() {
        let clock = ManualClock::new();
        let issuer = issuer(&clock, MAX_WINDOW_VALIDITY);
        let kept = issuer
            .issue(connection(2), BootEpoch::new(1))
            .expect("a window");
        let ended = issuer
            .issue(connection(1), BootEpoch::new(1))
            .expect("a window");
        issuer.retire_connection(connection(1));
        assert_eq!(
            issuer.validate(&ended.action_window_id, connection(1), BootEpoch::new(1)),
            Err(WindowRefusal::Unknown)
        );
        assert!(
            issuer
                .validate(&kept.action_window_id, connection(2), BootEpoch::new(1))
                .is_ok()
        );
        assert_eq!(issuer.outstanding(), 1);
    }

    fn clock_instant(clock: &ManualClock, ahead: Duration) -> ContinuousInstant {
        clock.now().checked_add(ahead).expect("an instant")
    }
}
