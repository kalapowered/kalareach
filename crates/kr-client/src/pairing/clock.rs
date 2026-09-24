//! The clock a device's pairing attempts are measured on.
//!
//! Three readings, each used for what only it can answer. The monotonic reading is the machine's
//! boot-scoped counter, so a deadline it decides cannot be moved by a clock adjustment. The boot
//! identity says which boot that counter belongs to, so the attempt budget's five-minute window
//! ends at a reboot rather than reading a deadline from before it as time still to run. The
//! wall-clock reading is what the budget's tombstones and a peer's expiries are expressed in.

use kr_pairing::platform::{BootIdentity, PairingClock};

use crate::error::{ClientError, Result};

/// This device's pairing clock, for the boot it is running in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceClock {
    boot: BootIdentity,
}

impl DeviceClock {
    /// The clock of the boot this process runs in.
    ///
    /// # Errors
    ///
    /// Returns the platform's failure when the boot cannot be identified.
    pub fn current() -> Result<Self> {
        let identity = kr_ipc::identity::boot_identity().map_err(ClientError::Ipc)?;
        Ok(Self::of(&identity))
    }

    /// The clock of the boot `identity` names.
    ///
    /// The pairing rules compare boot identities for equality and never interpret them, so the
    /// platform's opaque value is reduced to a fixed-width digest rather than truncated: two
    /// different boots must not collide, and the value's length is the platform's choice.
    #[must_use]
    pub fn of(identity: &kr_protocol::identity::BootIdentity) -> Self {
        Self {
            boot: BootIdentity(kr_cbor::sha256(identity.value.as_slice())),
        }
    }
}

impl PairingClock for DeviceClock {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> BootIdentity {
        self.boot
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two boots are two identities, and one boot is always the same one.
    #[test]
    fn a_boot_is_one_identity_and_another_boot_another() {
        let clock = DeviceClock::current().expect("this boot");
        assert_eq!(
            clock.boot_identity(),
            DeviceClock::current().expect("this boot").boot_identity()
        );
        let other = kr_protocol::identity::BootIdentity {
            value: kr_protocol::scalars::Bytes::new(vec![0xab; 16]),
            ..kr_ipc::identity::boot_identity().expect("this boot")
        };
        assert_ne!(
            DeviceClock::of(&other).boot_identity(),
            clock.boot_identity()
        );
        let earlier = clock.monotonic_ms();
        assert!(
            clock.monotonic_ms() >= earlier,
            "the counter never runs back"
        );
    }
}
