//! Host-stamped freshness windows for local callers.
//!
//! Section 9 binds a first admission to a host-issued action window: it belongs to one
//! authenticated connection and one boot, it lasts at most five minutes, it is renewed explicitly
//! on a live authorised connection, and an original request carrying an expired or unknown window
//! is never first-admitted. A local caller never supplies its own window; the host stamps one and
//! the client echoes the identifier back.
//!
//! # Why two clocks
//!
//! The deadline has to be continuous: suspending the machine must not extend authority, and moving
//! the wall clock backwards must not extend it either. No single portable clock does both. A
//! monotonic clock stops while the machine sleeps, so on its own it would hand a suspended machine
//! a window that outlives its five minutes. A wall clock can be moved.
//!
//! So a window records both readings when it is issued and expires on whichever elapses first:
//! elapsed time is the **larger** of the monotonic and wall-clock elapsed values. A suspend makes
//! the wall-clock value large and expires the window; a backwards wall clock leaves the monotonic
//! value untouched and the window still expires on time. Neither clock can be used to extend one.

use std::time::Instant;

use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{ActionWindowId, ConnectionId};
use kr_protocol::scalars::TimestampMs;

/// The longest a freshness window lasts, from section 9.
pub const MAX_WINDOW_MS: u64 = 5 * 60 * 1000;

/// One host-stamped freshness window, bound to one connection and one boot.
#[derive(Clone, Debug)]
pub struct FreshnessWindow {
    id: ActionWindowId,
    connection_id: ConnectionId,
    boot_identity: BootIdentity,
    issued_monotonic: Instant,
    issued_wall_ms: u64,
    lifetime_ms: u64,
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
        Self {
            // The identifier names the connection and the moment it was stamped, so a renewal is a
            // different window rather than the same one with a later deadline.
            id: ActionWindowId::new(format!("local:{connection_id}:{now_wall_ms}"))
                .unwrap_or_else(|_| ActionWindowId::new("local").expect("a valid window")),
            connection_id,
            boot_identity,
            issued_monotonic: Instant::now(),
            issued_wall_ms: now_wall_ms,
            lifetime_ms: lifetime_ms.min(MAX_WINDOW_MS),
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
        let monotonic =
            u64::try_from(self.issued_monotonic.elapsed().as_millis()).unwrap_or(u64::MAX);
        let wall = now_wall_ms.saturating_sub(self.issued_wall_ms);
        monotonic.max(wall)
    }

    /// Returns how long the window still has.
    #[must_use]
    pub fn remaining_ms(&self, now_wall_ms: u64) -> u64 {
        self.lifetime_ms
            .saturating_sub(self.elapsed_ms(now_wall_ms))
    }

    /// Returns whether the window has expired.
    #[must_use]
    pub fn expired(&self, now_wall_ms: u64) -> bool {
        self.remaining_ms(now_wall_ms) == 0
    }

    /// Returns the wall-clock expiry to display.
    ///
    /// Expiry itself is decided on the continuous reading above; this is the number a client shows
    /// a person, not the number either side decides with.
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

    #[test]
    fn a_fresh_window_admits_its_own_identifier() {
        let window = FreshnessWindow::issue(connection(), boot(), 1_000, MAX_WINDOW_MS);
        let remaining = window
            .admit(window.id(), &boot(), 1_000)
            .expect("admits its own identifier");
        assert_eq!(remaining, MAX_WINDOW_MS);
    }

    #[test]
    fn another_windows_identifier_is_unknown() {
        let window = FreshnessWindow::issue(connection(), boot(), 1_000, MAX_WINDOW_MS);
        let other = ActionWindowId::new("local:elsewhere").expect("a valid window");
        assert_eq!(
            window.admit(&other, &boot(), 1_000),
            Err(WindowRefusal::Unknown)
        );
    }

    #[test]
    fn a_window_from_another_boot_admits_nothing() {
        let window = FreshnessWindow::issue(connection(), boot(), 1_000, MAX_WINDOW_MS);
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
    fn a_suspended_machine_expires_the_window_on_the_wall_clock() {
        // The monotonic reading has barely moved; the wall clock has moved past the lifetime,
        // which is what a suspend looks like. The window is expired.
        let window = FreshnessWindow::issue(connection(), boot(), 1_000, MAX_WINDOW_MS);
        assert!(window.expired(1_000 + MAX_WINDOW_MS + 1));
        assert_eq!(
            window.admit(window.id(), &boot(), 1_000 + MAX_WINDOW_MS + 1),
            Err(WindowRefusal::Expired)
        );
    }

    #[test]
    fn a_wall_clock_moved_backwards_does_not_extend_a_window() {
        // A window whose lifetime is already spent on the monotonic clock stays expired however
        // far back the wall clock is moved.
        let mut window = FreshnessWindow::issue(connection(), boot(), 10_000, MAX_WINDOW_MS);
        window.issued_monotonic = Instant::now() - std::time::Duration::from_millis(MAX_WINDOW_MS);
        assert!(window.expired(0));
    }

    #[test]
    fn a_renewal_is_a_different_window() {
        let window = FreshnessWindow::issue(connection(), boot(), 1_000, MAX_WINDOW_MS);
        let renewed = window.renew(2_000);
        assert_ne!(renewed.id(), window.id());
        assert_eq!(renewed.connection_id(), window.connection_id());
    }

    #[test]
    fn a_lifetime_longer_than_the_maximum_is_shortened() {
        let window = FreshnessWindow::issue(connection(), boot(), 0, MAX_WINDOW_MS * 4);
        assert_eq!(window.remaining_ms(0), MAX_WINDOW_MS);
    }
}
