//! Host-stamped freshness windows for local callers.
//!
//! Section 9 binds a first admission to a host-issued action window: it belongs to one
//! authenticated connection and one boot, it lasts at most five minutes, it is renewed explicitly
//! on a live authorised connection, and an original request carrying an expired or unknown window
//! is never first-admitted. A local caller never supplies its own window; the host stamps one and
//! the client echoes the identifier back.
//!
//! # The clock a window expires on
//!
//! Three rules together decide expiry, and each closes a hole the others leave.
//!
//! * **A suspend-aware continuous clock.** Linux reads `CLOCK_BOOTTIME` and macOS reads
//!   `CLOCK_MONOTONIC`, both of which keep counting while the machine sleeps. Suspending a machine
//!   for an hour therefore spends an hour of every window open at the time.
//! * **The wall clock as a second, independent bound.** Elapsed time is the larger of the two
//!   readings. Where a platform's continuous clock stops during sleep, the wall clock still moves,
//!   so the suspend is still spent; and a wall clock moved backwards cannot reduce the continuous
//!   reading, so it cannot buy time either.
//! * **Expiry latches.** Once a window has been seen expired it stays expired for the rest of its
//!   life. No later reading of either clock, forwards or backwards, can revive it.
//!
//! An identifier is a fresh random value, not a function of the clock, so a renewal is always a
//! different window even when the clock has not moved or has moved back.

use std::cell::Cell;

use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{ActionWindowId, ConnectionId};
use kr_protocol::scalars::TimestampMs;

/// The longest a freshness window lasts, from section 9.
pub const MAX_WINDOW_MS: u64 = 5 * 60 * 1000;

/// Reads the host's suspend-aware continuous clock, in milliseconds.
///
/// The value has no meaning on its own; only differences between two readings do. It never moves
/// backwards and it does not stop while the machine sleeps.
#[must_use]
#[cfg(target_os = "linux")]
pub fn continuous_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(rustix::time::ClockId::Boottime))
}

/// Reads the host's suspend-aware continuous clock, in milliseconds.
///
/// Darwin's `CLOCK_MONOTONIC` is the sleep-inclusive one; `CLOCK_UPTIME_RAW` is the clock that
/// stops, and `std::time::Instant` uses that one, which is why this does not.
#[must_use]
#[cfg(target_vendor = "apple")]
pub fn continuous_ms() -> u64 {
    from_timespec(rustix::time::clock_gettime(
        rustix::time::ClockId::Monotonic,
    ))
}

/// Reads the host's continuous clock, in milliseconds.
///
/// On the remaining platforms this is the monotonic clock, which may stop while the machine
/// sleeps. The wall-clock bound in [`FreshnessWindow`] is what covers a suspend there, and the
/// latch is what stops a wall clock moved backwards from undoing it.
#[must_use]
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn continuous_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(unix)]
fn from_timespec(time: rustix::time::Timespec) -> u64 {
    let seconds = u64::try_from(time.tv_sec).unwrap_or_default();
    let milliseconds = u64::try_from(time.tv_nsec).unwrap_or_default() / 1_000_000;
    seconds.saturating_mul(1_000).saturating_add(milliseconds)
}

/// One host-stamped freshness window, bound to one connection and one boot.
#[derive(Debug)]
pub struct FreshnessWindow {
    id: ActionWindowId,
    connection_id: ConnectionId,
    boot_identity: BootIdentity,
    issued_continuous_ms: u64,
    issued_wall_ms: u64,
    lifetime_ms: u64,
    spent: Cell<bool>,
}

impl Clone for FreshnessWindow {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            connection_id: self.connection_id,
            boot_identity: self.boot_identity.clone(),
            issued_continuous_ms: self.issued_continuous_ms,
            issued_wall_ms: self.issued_wall_ms,
            lifetime_ms: self.lifetime_ms,
            spent: Cell::new(self.spent.get()),
        }
    }
}

impl FreshnessWindow {
    /// Stamps a window for a connection.
    #[must_use]
    pub fn issue(
        connection_id: ConnectionId,
        boot_identity: BootIdentity,
        now_wall_ms: u64,
        lifetime_ms: u64,
    ) -> Self {
        Self::issue_at(
            connection_id,
            boot_identity,
            continuous_ms(),
            now_wall_ms,
            lifetime_ms,
        )
    }

    fn issue_at(
        connection_id: ConnectionId,
        boot_identity: BootIdentity,
        now_continuous_ms: u64,
        now_wall_ms: u64,
        lifetime_ms: u64,
    ) -> Self {
        Self {
            // A fresh random identifier, never a function of the clock: two windows stamped in the
            // same millisecond, or one stamped after the wall clock moved back, must still be two
            // different windows.
            id: ActionWindowId::new(format!("local:{}", crate::new_uuid()))
                .unwrap_or_else(|_| ActionWindowId::new("local").expect("a valid window")),
            connection_id,
            boot_identity,
            issued_continuous_ms: now_continuous_ms,
            issued_wall_ms: now_wall_ms,
            lifetime_ms: lifetime_ms.min(MAX_WINDOW_MS),
            spent: Cell::new(false),
        }
    }

    /// Returns the window's identifier.
    #[must_use]
    pub const fn id(&self) -> &ActionWindowId {
        &self.id
    }

    /// Returns the connection this window belongs to.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the boot this window is bound to.
    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    /// Returns how much of the window has elapsed, on whichever clock has moved further.
    #[must_use]
    pub fn elapsed_ms(&self, now_wall_ms: u64) -> u64 {
        self.elapsed_at(continuous_ms(), now_wall_ms)
    }

    fn elapsed_at(&self, now_continuous_ms: u64, now_wall_ms: u64) -> u64 {
        let continuous = now_continuous_ms.saturating_sub(self.issued_continuous_ms);
        let wall = now_wall_ms.saturating_sub(self.issued_wall_ms);
        continuous.max(wall)
    }

    /// Returns how long the window still has.
    #[must_use]
    pub fn remaining_ms(&self, now_wall_ms: u64) -> u64 {
        self.remaining_at(continuous_ms(), now_wall_ms)
    }

    fn remaining_at(&self, now_continuous_ms: u64, now_wall_ms: u64) -> u64 {
        if self.spent.get() {
            return 0;
        }
        let remaining = self
            .lifetime_ms
            .saturating_sub(self.elapsed_at(now_continuous_ms, now_wall_ms));
        if remaining == 0 {
            // Expiry latches. A window that has been out of time once is out of time for good,
            // whatever either clock says afterwards.
            self.spent.set(true);
        }
        remaining
    }

    /// Returns whether the window has expired.
    #[must_use]
    pub fn expired(&self, now_wall_ms: u64) -> bool {
        self.remaining_ms(now_wall_ms) == 0
    }

    /// Returns the wall-clock expiry to display.
    ///
    /// Expiry itself is decided on the readings above; this is the number a client shows a person,
    /// not the number either side decides with.
    #[must_use]
    pub const fn expires_at_ms(&self) -> TimestampMs {
        TimestampMs::new(self.issued_wall_ms.saturating_add(self.lifetime_ms))
    }

    /// Checks that a request carries this exact window and that it is still live.
    ///
    /// # Errors
    ///
    /// Returns [`WindowRefusal`] when the identifier names another window, the boot differs, or
    /// the window has expired.
    pub fn admit(
        &self,
        presented: &ActionWindowId,
        boot_identity: &BootIdentity,
        now_wall_ms: u64,
    ) -> Result<u64, WindowRefusal> {
        if presented != &self.id {
            return Err(WindowRefusal::Unknown);
        }
        if boot_identity != &self.boot_identity {
            return Err(WindowRefusal::WrongBoot);
        }
        match self.remaining_ms(now_wall_ms) {
            0 => Err(WindowRefusal::Expired),
            remaining => Ok(remaining),
        }
    }

    /// Replaces this window with a fresh one on the same connection.
    #[must_use]
    pub fn renew(&self, now_wall_ms: u64) -> Self {
        Self::issue(
            self.connection_id,
            self.boot_identity.clone(),
            now_wall_ms,
            self.lifetime_ms,
        )
    }
}

/// Why a freshness window could not admit a first request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowRefusal {
    /// The identifier is not this connection's window.
    Unknown,
    /// The window was stamped in another boot.
    WrongBoot,
    /// The window has passed its continuous deadline.
    Expired,
}

impl WindowRefusal {
    /// Returns the sentence a caller is given.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Unknown => {
                "this action window is not the one this connection holds, so the request cannot be \
                 admitted for the first time"
            }
            Self::WrongBoot => {
                "this action window was stamped in another boot of this host, so it admits nothing"
            }
            Self::Expired => {
                "this action window has expired; renew it on this connection and submit a new \
                 request rather than replaying this one"
            }
        }
    }
}

impl core::fmt::Display for WindowRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.detail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::Bytes;

    fn boot() -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::BootTime,
            value: Bytes::new(b"boot".to_vec()),
        }
    }

    fn connection() -> ConnectionId {
        ConnectionId::new(crate::new_uuid())
    }

    fn window_at(continuous: u64, wall: u64) -> FreshnessWindow {
        FreshnessWindow::issue_at(connection(), boot(), continuous, wall, MAX_WINDOW_MS)
    }

    #[test]
    fn a_fresh_window_admits_its_own_identifier() {
        let window = FreshnessWindow::issue(connection(), boot(), kr_protocol_now(), MAX_WINDOW_MS);
        let remaining = window
            .admit(window.id(), &boot(), kr_protocol_now())
            .expect("admits its own identifier");
        assert!(remaining > MAX_WINDOW_MS - 1_000);
    }

    fn kr_protocol_now() -> u64 {
        crate::now_ms().get()
    }

    #[test]
    fn another_windows_identifier_is_unknown() {
        let window = window_at(0, 1_000);
        let other = ActionWindowId::new("local:elsewhere").expect("a valid window");
        assert_eq!(
            window.admit(&other, &boot(), 1_000),
            Err(WindowRefusal::Unknown)
        );
    }

    #[test]
    fn a_window_from_another_boot_admits_nothing() {
        let window = window_at(0, 1_000);
        let elsewhere = BootIdentity {
            source: BootIdentitySource::BootTime,
            value: Bytes::new(b"another boot".to_vec()),
        };
        assert_eq!(
            window.admit(window.id(), &elsewhere, 1_000),
            Err(WindowRefusal::WrongBoot)
        );
    }

    #[test]
    fn the_continuous_clock_spends_a_suspend() {
        // The continuous clock has moved past the lifetime while the wall clock has not, which is
        // what a suspend looks like where the platform's clock keeps counting through one.
        let window = window_at(0, 1_000);
        assert_eq!(window.remaining_at(MAX_WINDOW_MS + 1, 1_000), 0);
    }

    #[test]
    fn the_wall_clock_spends_a_suspend_the_continuous_clock_missed() {
        let window = window_at(0, 1_000);
        assert_eq!(window.remaining_at(10, 1_000 + MAX_WINDOW_MS + 1), 0);
    }

    #[test]
    fn a_wall_clock_moved_backwards_cannot_revive_an_expired_window() {
        let window = window_at(0, 300_000);
        // Seen expired once, through a forward wall-clock step.
        assert!(window.expired_at(10, 300_000 + MAX_WINDOW_MS + 1));
        // Then the wall clock is moved back behind the issue time. The window stays expired.
        assert!(window.expired_at(10, 0));
        assert_eq!(
            window.admit(window.id(), &boot(), 0),
            Err(WindowRefusal::Expired)
        );
    }

    #[test]
    fn a_wall_clock_moved_backwards_does_not_extend_a_live_window() {
        let window = window_at(0, 300_000);
        // The continuous clock has spent the whole lifetime. Moving the wall clock back to the
        // issue time cannot buy any of it back.
        assert_eq!(window.remaining_at(MAX_WINDOW_MS, 300_000), 0);
    }

    #[test]
    fn a_renewal_is_a_different_window_even_at_the_same_instant() {
        let window = window_at(0, 1_000);
        let renewed = window.renew(1_000);
        assert_ne!(renewed.id(), window.id());
        assert_eq!(renewed.connection_id(), window.connection_id());
    }

    #[test]
    fn a_lifetime_longer_than_the_maximum_is_shortened() {
        let window = FreshnessWindow::issue_at(connection(), boot(), 0, 0, MAX_WINDOW_MS * 4);
        assert_eq!(window.remaining_at(0, 0), MAX_WINDOW_MS);
    }

    #[test]
    fn the_continuous_clock_never_moves_backwards() {
        let first = continuous_ms();
        let second = continuous_ms();
        assert!(second >= first);
    }

    impl FreshnessWindow {
        fn expired_at(&self, continuous: u64, wall: u64) -> bool {
            self.remaining_at(continuous, wall) == 0
        }
    }
}
