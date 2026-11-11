//! What the guest's test build can take back from a launch, one part at a time, to find which part
//! of it changes what the platform does with the program it starts.
//!
//! A build that ships has none of this: every part is always in force. A build with the `testing`
//! feature reads a value from the machine's registry at each launch, so that a case can set it
//! for the broker service it has installed and read what the proof then shows.

/// Which parts of a launch a case has taken back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Taken {
    /// The job is not named at creation.
    pub no_job: bool,
    /// The inherited handles are not listed: every inheritable handle passes.
    pub no_handle_list: bool,
    /// The process and thread get the platform's default descriptors.
    pub default_descriptors: bool,
    /// The child is not created suspended.
    pub not_suspended: bool,
    /// The broker does not set its error mode.
    pub default_error_mode: bool,
    /// The proof's programs get the four variables the proof used to pass.
    pub old_environment: bool,
}

#[cfg(feature = "testing")]
const KEY: &str = r"SOFTWARE\KalaReach\BoundaryTest";

/// The parts taken back now.
#[cfg(feature = "testing")]
#[must_use]
pub fn taken() -> Taken {
    let bits = super::registry::open(KEY)
        .ok()
        .flatten()
        .and_then(|key| key.dword("Variant").ok().flatten())
        .unwrap_or(0);
    Taken {
        no_job: bits & 0x01 != 0,
        no_handle_list: bits & 0x02 != 0,
        default_descriptors: bits & 0x04 != 0,
        not_suspended: bits & 0x08 != 0,
        default_error_mode: bits & 0x10 != 0,
        old_environment: bits & 0x20 != 0,
    }
}

/// The parts taken back now: none, in a build that ships.
#[cfg(not(feature = "testing"))]
#[must_use]
pub fn taken() -> Taken {
    Taken::default()
}

/// How long the proof waits for the policy, which a case may shorten.
#[cfg(feature = "testing")]
#[must_use]
pub fn proof_bound(default: std::time::Duration) -> std::time::Duration {
    super::registry::open(KEY)
        .ok()
        .flatten()
        .and_then(|key| key.dword("ProofBoundSeconds").ok().flatten())
        .map_or(default, |seconds| {
            std::time::Duration::from_secs(u64::from(seconds))
        })
}

/// How long the proof waits for the policy.
#[cfg(not(feature = "testing"))]
#[must_use]
pub fn proof_bound(default: std::time::Duration) -> std::time::Duration {
    default
}
