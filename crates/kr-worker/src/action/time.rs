//! The one host time contract every expiry in this host is decided by.
//!
//! Section 9 fixes three anchors and then says what may be concluded from each.
//!
//! * **The boot identity.** A continuous reading is meaningless outside the boot it was taken in,
//!   because the clock restarts. A deadline carried across a reboot therefore reads as long past
//!   rather than as time remaining, which is the conservative direction.
//! * **A suspend-aware continuous anchor.** [`kr_ipc::clock`] reads the machine's own boot-scoped
//!   continuous clock, which counts the time the machine spent asleep. A timer that excludes sleep
//!   cannot extend authority, so nothing here measures a deadline on one.
//! * **A trusted UTC deadline**, for a signed object that has to outlive a reboot. It is the only
//!   thing that can, and it is usable only while this host can prove what its wall clock reads.
//!
//! The wall clock is the part that can lie. A rollback beyond five seconds marks trust unresolved,
//! which stops expiry-based collection and refuses objects whose expiry cannot otherwise be
//! proved. What it explicitly does **not** do is disable a non-expiring personal owner grant, or a
//! fresh online action whose lifetime is bounded by this boot's continuous clock: neither of those
//! depends on the wall clock, so neither is affected by not being able to trust it.
//!
//! A wake, a reboot or any other discontinuity owes a revalidation before an expiry-dependent read
//! or mutation is served. The detector is two clocks rather than a notification: the continuous
//! clock counts a suspension and [`std::time::Instant`] does not, so the difference between two
//! deltas of theirs *is* the suspension, with nothing to subscribe to and nothing to miss.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(not(windows))]
use std::time::Instant;

use kr_protocol::action::{
    ExpirationTombstone, ExpiryReason, HostTimeState, MAX_WALL_CLOCK_ROLLBACK_MS, ProvenWallClock,
    RetrustEvidence, TimeAdapterReading, TimeCheckpoint, WallClockTrust,
};
use kr_protocol::identity::BootIdentity;
use kr_protocol::scalars::{TimestampMs, U64};

use crate::action::adapter::{PlatformTimeAdapter, TimeAdapter};
use crate::error::{Result, WorkerError};

/// How far the two clocks may disagree before this host calls it a discontinuity.
///
/// The continuous clock counts a suspension and the active clock does not, so a difference between
/// their deltas is time the machine spent asleep. The two readings of one observation are taken
/// microseconds apart, and anything that deschedules the process between two *observations*
/// advances both clocks equally, so the difference is genuinely suspended time rather than noise.
/// The tolerance is therefore small; what it costs is that a suspension shorter than it is not
/// noticed, which is stated rather than argued away.
pub const DISCONTINUITY_TOLERANCE: Duration = Duration::from_millis(250);

/// Reads a clock that stops while the machine is suspended.
///
/// Paired with the continuous clock this is the suspension detector. It exists as a trait for the
/// same reason the other clocks do: a test cannot arrange a real suspension.
pub trait ActiveClock: Send + Sync + std::fmt::Debug {
    /// Returns milliseconds of active time since this clock was created.
    fn active_elapsed_ms(&self) -> u64;
}

/// The platform's own clock that stops during a suspension.
///
/// On Apple and Linux this is [`Instant`]: `CLOCK_UPTIME_RAW` and `CLOCK_MONOTONIC` respectively,
/// both of which stop while the machine is asleep. That is exactly the property that makes them
/// useless for a deadline and useful here.
///
/// On Windows [`Instant`] is the performance counter, which keeps running through a suspension, so
/// it is not this clock at all. What is is `QueryUnbiasedInterruptTime`, the counter beside the one
/// [`kr_ipc::clock`] reads: the biased one includes suspended time and the unbiased one does not,
/// and the pair of them is the detector.
#[derive(Clone, Debug)]
pub struct SystemActiveClock {
    #[cfg(not(windows))]
    anchor: Arc<Instant>,
    #[cfg(windows)]
    anchor: Arc<u64>,
}

impl SystemActiveClock {
    /// Anchors an active clock at this moment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(not(windows))]
            anchor: Arc::new(Instant::now()),
            #[cfg(windows)]
            anchor: Arc::new(windows_active::unbiased_ms()),
        }
    }
}

impl Default for SystemActiveClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveClock for SystemActiveClock {
    #[cfg(not(windows))]
    fn active_elapsed_ms(&self) -> u64 {
        u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[cfg(windows)]
    fn active_elapsed_ms(&self) -> u64 {
        windows_active::unbiased_ms().saturating_sub(*self.anchor)
    }
}

/// The Windows counter that stops while the machine is asleep.
///
/// The second place in this crate that calls the operating system without a safe interface, for the
/// same reason as the first: no safe interface exposes the unbiased interrupt counter, and the
/// alternative is a clock that does not stop during a suspension and so detects nothing.
#[cfg(windows)]
mod windows_active {
    #![expect(
        unsafe_code,
        reason = "the machine's unbiased interrupt counter has no safe interface on this platform"
    )]

    /// Returns the unbiased interrupt time in milliseconds.
    pub fn unbiased_ms() -> u64 {
        let mut ticks = 0_u64;
        // SAFETY: the call writes one unsigned 64-bit word through the pointer it is given and has
        // no other effect. The pointer is to a live local of exactly that type.
        unsafe {
            windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime(
                &raw mut ticks,
            );
        }
        // Hundreds of nanoseconds since the boot, excluding time the machine spent asleep.
        ticks / 10_000
    }
}

/// An active clock a test drives by hand.
#[derive(Clone, Debug, Default)]
pub struct ManualActiveClock {
    elapsed: Arc<std::sync::atomic::AtomicU64>,
}

impl ManualActiveClock {
    /// Creates a clock reading zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the clock.
    pub fn advance(&self, duration: Duration) {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.elapsed
            .fetch_add(milliseconds, std::sync::atomic::Ordering::AcqRel);
    }
}

impl ActiveClock for ManualActiveClock {
    fn active_elapsed_ms(&self) -> u64 {
        self.elapsed.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Reads the machine's wall clock.
pub trait WallClock: Send + Sync + std::fmt::Debug {
    /// Returns UTC milliseconds.
    fn now_ms(&self) -> TimestampMs;
}

/// The machine's own wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_ms(&self) -> TimestampMs {
        kr_ipc::now_ms()
    }
}

/// A wall clock a test steps in either direction.
#[derive(Clone, Debug)]
pub struct ManualWallClock {
    now_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl ManualWallClock {
    /// Creates a wall clock reading `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(std::sync::atomic::AtomicU64::new(now_ms)),
        }
    }

    /// Steps the clock to a reading, forwards or backwards.
    pub fn set(&self, now_ms: u64) {
        self.now_ms
            .store(now_ms, std::sync::atomic::Ordering::Release);
    }

    /// Advances the clock.
    pub fn advance(&self, duration: Duration) {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let _ = self
            .now_ms
            .fetch_add(milliseconds, std::sync::atomic::Ordering::AcqRel);
    }
}

impl WallClock for ManualWallClock {
    fn now_ms(&self) -> TimestampMs {
        TimestampMs::new(self.now_ms.load(std::sync::atomic::Ordering::Acquire))
    }
}

/// One object whose validity the time contract decides.
///
/// The two deadlines are separate facts rather than one converted into the other. A continuous
/// deadline proves validity inside its own boot and nothing outside it; a trusted UTC deadline
/// proves validity whenever this host can prove what its wall clock reads. An object may carry
/// either, both or neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiringObject {
    /// How the object's own store names it, which is what a tombstone records.
    pub name: String,
    /// The boot the continuous deadline belongs to.
    pub boot_identity: Option<BootIdentity>,
    /// The deadline on the machine's boot-scoped continuous clock, in milliseconds.
    pub continuous_deadline_ms: Option<u64>,
    /// The trusted UTC deadline a signed object carries so it can outlive a reboot.
    pub trusted_utc_deadline_ms: Option<u64>,
    /// True for a personal owner grant that does not expire.
    pub non_expiring_owner_grant: bool,
}

impl ExpiringObject {
    /// Builds an object bounded by this boot's continuous clock alone.
    ///
    /// This is a fresh online action: the host decided its lifetime on a clock it is still running,
    /// so nothing about the wall clock bears on it.
    #[must_use]
    pub fn within_boot(name: impl Into<String>, boot: &BootIdentity, deadline_ms: u64) -> Self {
        Self {
            name: name.into(),
            boot_identity: Some(boot.clone()),
            continuous_deadline_ms: Some(deadline_ms),
            trusted_utc_deadline_ms: None,
            non_expiring_owner_grant: false,
        }
    }

    /// Builds a signed object that has to outlive a reboot.
    #[must_use]
    pub fn signed_across_reboot(name: impl Into<String>, utc_deadline_ms: u64) -> Self {
        Self {
            name: name.into(),
            boot_identity: None,
            continuous_deadline_ms: None,
            trusted_utc_deadline_ms: Some(utc_deadline_ms),
            non_expiring_owner_grant: false,
        }
    }

    /// Builds a personal owner grant that does not expire.
    #[must_use]
    pub fn non_expiring_owner_grant(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            boot_identity: None,
            continuous_deadline_ms: None,
            trusted_utc_deadline_ms: None,
            non_expiring_owner_grant: true,
        }
    }
}

/// What the time contract concluded about an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Validity {
    /// The object is valid and may be served.
    Valid,
    /// The object has expired. It never revives.
    Expired(ExpiryReason),
    /// Whether the object has expired cannot be proved, so it is refused.
    Unproven,
    /// A wake, reboot or discontinuity owes a revalidation before this can be answered.
    RevalidationOwed,
}

impl Validity {
    /// Returns true when the object may be served.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// What an observation of the clocks found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Discontinuity {
    /// The machine was asleep between the two observations.
    pub suspended: bool,
    /// The boot identity changed, so this is a different boot from the one checkpointed.
    pub rebooted: bool,
    /// The wall clock moved backwards further than the tolerance.
    pub rolled_back: bool,
}

impl Discontinuity {
    /// Returns true when anything at all moved.
    #[must_use]
    pub const fn any(self) -> bool {
        self.suspended || self.rebooted || self.rolled_back
    }
}

/// How many expiration tombstones a host keeps.
///
/// A tombstone's job is to stop an object reviving while something could still present it. Past
/// that point another rule already refuses the object: a continuous deadline in this boot is
/// behind a clock that only moves forward, and an object from an earlier boot no longer matches
/// the boot its deadline belongs to. The table is therefore bounded, and the oldest record is what
/// goes when a host expires more objects than this in one run.
pub const MAX_TOMBSTONES: usize = 256;

#[derive(Debug)]
struct TimeState {
    /// How many times something a restarted host could not reconstruct has changed.
    ///
    /// Trust going to unresolved and an object being expired are those things. The checkpoint
    /// advancing is not: a restored mark that is older than the last one is the conservative
    /// direction, and writing the mark down on every observation would put a durable write on the
    /// mutation path in exchange for nothing.
    critical: u64,
    /// The count that was last written down.
    written: u64,
    /// The mark this host read back from a store, while it may still be behind the truth.
    ///
    /// A mark is written down when it *steps*, and a step smaller than the tolerance for telling a
    /// step from noise is not written. So a restored mark may be behind the truth by up to that
    /// tolerance, and a rollback measured against it would look smaller by the same amount. While
    /// this is here, the host is that much stricter about what counts as a rollback, which is the
    /// conservative direction.
    ///
    /// Writing the same mark down again does not remove the uncertainty, because what is uncertain
    /// is how far the clock had got before the restart rather than whether this host saved
    /// anything. What removes it is this host observing the clock at least a tolerance beyond the
    /// restored mark: such a reading is at or past the furthest the unwritten step could have
    /// taken it, so the mark is the truth again and the full tolerance applies.
    restored: Option<HighWater>,
    /// Whether the owner confirmed this clock explicitly.
    ///
    /// It changes one thing: the platform's own answer no longer demotes the trust. Section 9's
    /// owner route exists for a host with no qualified evidence to be had, so an unqualified
    /// reading cannot be a reason to undo it. A rollback still is.
    owner_confirmed: bool,
    /// The proven reading that was last written down, with the continuous reading it was taken at.
    ///
    /// The mark advances on every ordinary observation, and writing it down each time would put a
    /// durable write on the mutation path for nothing. What has to be written is a *step*, and the
    /// anchor is what tells a step from time passing: without it, five seconds of uptime would
    /// look like a five-second correction.
    saved: Option<HighWater>,
    trust: WallClockTrust,
    checkpoint: Option<TimeCheckpoint>,
    revalidation_owed: bool,
    last: Option<Reading>,
    /// The furthest this host has ever been able to prove the wall clock had reached, and the
    /// continuous reading it was proved at.
    ///
    /// Comparing only against the previous observation lets a clock lose a little at a time: a
    /// rollback inside the tolerance is forgiven, the mark moves back with it, and the next one is
    /// forgiven against the moved mark. Enough of those and an object with only a UTC deadline
    /// never reaches it. The high-water mark never moves backwards, so tolerated slippage costs
    /// what it costs once and buys nothing after that.
    high_water: Option<HighWater>,
    tombstones: BTreeMap<String, ExpirationTombstone>,
}

#[derive(Clone, Copy, Debug)]
struct Reading {
    continuous_ms: u64,
    active_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct HighWater {
    wall_ms: u64,
    continuous_ms: u64,
}

impl HighWater {
    /// Returns the earliest the wall clock can honestly read now.
    ///
    /// The continuous clock is the ground truth for elapsed time, so the mark plus whatever has
    /// elapsed since it was taken is a lower bound on the present.
    const fn projected(self, continuous_now: u64) -> u64 {
        self.wall_ms
            .saturating_add(continuous_now.saturating_sub(self.continuous_ms))
    }
}

/// The three clocks and the time service a contract reads, and the host's clock floor it
/// publishes its readings in.
///
/// They travel together because none of them means anything without the others: the continuous
/// clock says how much time passed, the active one says how much of it the machine was awake for,
/// the wall clock says what it claims the time is, the adapter says whether that claim is worth
/// anything, and the floor is the one reading of UTC every process of the host decides from.
#[derive(Clone)]
pub struct TimeSources {
    /// The machine's boot-scoped continuous clock, which counts suspended time.
    pub continuous: Arc<dyn kr_ipc::clock::SharedClock>,
    /// A clock that stops while the machine is suspended.
    pub active: Arc<dyn ActiveClock>,
    /// The machine's wall clock.
    pub wall: Arc<dyn WallClock>,
    /// The platform's own time service.
    pub adapter: Arc<dyn TimeAdapter>,
    /// The environment's clock floor for this boot, when this worker maps one
    /// ([`kr_ipc::floor`]).
    ///
    /// A worker that found no usable floor maps none, and then decides no copy of authority that
    /// carries a UTC deadline ([`TimeContract::check_utc_deadline`]).
    pub floor: Option<Arc<kr_ipc::floor::SharedFloor>>,
}

impl TimeSources {
    /// Returns this machine's own clocks and time service, with no clock floor.
    #[must_use]
    pub fn system() -> Self {
        Self {
            continuous: Arc::new(kr_ipc::clock::SystemSharedClock),
            active: Arc::new(SystemActiveClock::new()),
            wall: Arc::new(SystemWallClock),
            adapter: Arc::new(PlatformTimeAdapter::new()),
            floor: None,
        }
    }

    /// The same sources, publishing in `floor`.
    #[must_use]
    pub fn with_floor(mut self, floor: Arc<kr_ipc::floor::SharedFloor>) -> Self {
        self.floor = Some(floor);
        self
    }
}

impl std::fmt::Debug for TimeSources {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TimeSources")
            .field("continuous", &self.continuous)
            .field("active", &self.active)
            .field("wall", &self.wall)
            .field("adapter", &self.adapter)
            .field("floor", &self.floor)
            .finish()
    }
}

/// What a check of one copy's UTC deadline found ([`TimeContract::check_utc_deadline`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtcDeadline {
    /// The deadline is ahead of the host's floor: the copy may be used.
    Ahead,
    /// It has passed, and the host's record covers the moment it passed: an expiry.
    Passed,
    /// It has passed at a reading the host has not written down yet. The floor it passed on is
    /// owed its record, and the refusal names no expiry until that record lands.
    Unrecorded,
    /// This worker maps no clock floor, so it decides no copy that carries a UTC deadline.
    NoFloor,
    /// The floor this worker maps has lost its name, so it is no longer the host's floor and
    /// decides no copy that carries a UTC deadline.
    FloorLost,
}

/// The host's time contract.
///
/// One per host process. Everything that expires asks this rather than reading a clock of its own,
/// which is what makes "one host time contract" true rather than aspirational.
#[derive(Debug)]
pub struct TimeContract {
    boot_identity: BootIdentity,
    /// The host time authority this host is configured to accept evidence from.
    ///
    /// Section 9 makes automatic retrust depend on "the configured host time authority", so a
    /// reading has to say it came from this one. An empty name is a host with none configured, and
    /// then no automatic retrust qualifies: the owner's explicit one is the only route left.
    authority: String,
    continuous: Arc<dyn kr_ipc::clock::SharedClock>,
    active: Arc<dyn ActiveClock>,
    wall: Arc<dyn WallClock>,
    adapter: Arc<dyn TimeAdapter>,
    /// The host's clock floor, which every reading taken here is published in.
    floor: Option<Arc<kr_ipc::floor::SharedFloor>>,
    state: Mutex<TimeState>,
}

/// Returns the uncertainty a reading claims, in microseconds, or nought when it claims none.
fn bound_of(reading: &TimeAdapterReading) -> u64 {
    reading
        .uncertainty_us
        .as_ref()
        .map_or(0, |bound| bound.get())
}

/// Converts microseconds to whole milliseconds, rounding up so a bound is never understated.
const fn microseconds_to_millis(microseconds: u64) -> u64 {
    microseconds.saturating_add(999) / 1_000
}

impl TimeContract {
    /// Builds a contract over this machine's own clocks and time service.
    #[must_use]
    pub fn system(boot_identity: BootIdentity, authority: impl Into<String>) -> Self {
        Self::new(boot_identity, authority, TimeSources::system())
    }

    /// Builds a contract over clocks and an adapter a caller supplies.
    ///
    /// A host with nothing recorded starts trusted only when its own time service says so. There
    /// is no earlier mark to compare against, so the platform's answer is the whole of what this
    /// host knows about its wall clock; a clock nothing is keeping cannot prove the expiry of
    /// anything, and section 9 refuses what cannot be proved rather than assuming it.
    #[must_use]
    pub fn new(
        boot_identity: BootIdentity,
        authority: impl Into<String>,
        sources: TimeSources,
    ) -> Self {
        Self::restore(boot_identity, authority, sources, None)
    }

    /// Builds a contract from what a host recorded before it restarted.
    ///
    /// The checkpoint, the trust the clock stood at, the proven reading and the expiration
    /// tombstones are what has to survive a restart. Without them a restarted host would start
    /// trusting a clock it had marked unresolved, would forgive slippage it had already paid for,
    /// and an object it had already expired could revive: section 9 forbids all three, and the
    /// only way to keep those promises is to read back what was written.
    ///
    /// Trust comes from the recorded state rather than from the checkpoint inside it. A rollback
    /// marks the clock unresolved and deliberately leaves the mark alone, so the mark's own trust
    /// is what was true when it was taken, not what is true now.
    #[must_use]
    pub fn restore(
        boot_identity: BootIdentity,
        authority: impl Into<String>,
        sources: TimeSources,
        recorded: Option<HostTimeState>,
    ) -> Self {
        let TimeSources {
            continuous,
            active,
            wall,
            adapter,
            floor,
        } = sources;
        let trust = recorded
            .as_ref()
            .map_or_else(|| Self::initial_trust(&*adapter), |state| state.trust);
        // The recorded reading is what this host could prove, and it survives a reboot: time does
        // not go backwards, so the clock cannot honestly read before it whatever boot this is.
        // What does not survive is the *continuous* reading beside it, because that clock
        // restarted, so a mark from another boot is anchored at this boot's reading instead.
        // Anchoring it at the recorded one would make the projection add the whole of the previous
        // boot's uptime.
        let now_continuous = continuous.boot_elapsed_ms();
        let high_water = recorded
            .as_ref()
            .and_then(|state| state.proven.as_ref())
            .map(|proven| HighWater {
                wall_ms: proven.wall_clock_ms.get(),
                continuous_ms: if proven.boot_identity == boot_identity {
                    proven.continuous_ms.get()
                } else {
                    now_continuous
                },
            });
        let owner_confirmed_at_restore =
            recorded.as_ref().is_some_and(|state| state.owner_confirmed);
        let (checkpoint, tombstones) = recorded.map_or_else(
            || (None, BTreeMap::new()),
            |state| {
                (
                    state.checkpoint.0,
                    state
                        .tombstones
                        .into_iter()
                        .map(|tombstone| (tombstone.object.clone(), tombstone))
                        .collect(),
                )
            },
        );
        let contract = Self {
            boot_identity,
            authority: authority.into(),
            continuous,
            active,
            wall,
            adapter,
            floor,
            state: Mutex::new(TimeState {
                critical: 0,
                written: 0,
                restored: high_water,
                owner_confirmed: owner_confirmed_at_restore,
                saved: high_water,
                trust,
                checkpoint,
                revalidation_owed: false,
                last: None,
                high_water,
                tombstones,
            }),
        };
        // The complete sample is taken at construction, so the first observation compares against
        // something rather than treating an unremembered clock as proof that nothing moved, and a
        // suspension across the first two observations is noticed like any other.
        contract.sample();
        if contract.lock().checkpoint.is_none() {
            let reading = contract.adapter.read();
            contract.checkpoint_at(reading);
        }
        contract
    }

    /// Returns the trust a host with nothing recorded starts at.
    fn initial_trust(adapter: &dyn TimeAdapter) -> WallClockTrust {
        if adapter.read().is_qualified() {
            WallClockTrust::Trusted
        } else {
            WallClockTrust::Unresolved
        }
    }

    /// Records the complete clock sample, without deciding anything from it.
    ///
    /// The wall clock's reading is published in the host's floor all the same, as every reading
    /// this contract takes is.
    fn sample(&self) {
        let continuous_ms = self.continuous.boot_elapsed_ms();
        let active_ms = self.active.active_elapsed_ms();
        let wall_ms = self.wall.now_ms().get();
        self.publish(wall_ms);
        let mut state = self.lock();
        state.last = Some(Reading {
            continuous_ms,
            active_ms,
        });
        // Only a host with nothing recorded starts its mark here. One that read a checkpoint back
        // has its mark from that, and overwriting it with whatever the clock reads now would throw
        // away the only thing a restarted host knows about its own past.
        if state.high_water.is_none() && state.trust == WallClockTrust::Trusted {
            state.high_water = Some(HighWater {
                wall_ms,
                continuous_ms,
            });
        }
    }

    /// Returns the boot this host is running in.
    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    /// Returns whether this host can prove what its wall clock reads.
    #[must_use]
    pub fn trust(&self) -> WallClockTrust {
        self.lock().trust
    }

    /// Returns the most recent checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> Option<TimeCheckpoint> {
        self.lock().checkpoint.clone()
    }

    /// Returns true when a wake, reboot or discontinuity owes a revalidation.
    #[must_use]
    pub fn revalidation_owed(&self) -> bool {
        self.lock().revalidation_owed
    }

    /// Records that the leases have been revalidated after a discontinuity.
    ///
    /// A host calls this once it has rechecked what a wake or a reboot may have invalidated.
    /// Nothing here decides that the leases are valid; it records that the question was asked.
    pub fn leases_revalidated(&self) {
        self.lock().revalidation_owed = false;
    }

    /// Returns true when expiry-based garbage collection may run.
    ///
    /// It stops while the wall clock cannot be proved, because collecting on an unproved clock is
    /// how a rollback deletes something that had not expired.
    #[must_use]
    pub fn may_collect_expired(&self) -> bool {
        self.trust() == WallClockTrust::Trusted
    }

    /// Reads the clocks and the platform's time service, and records what moved.
    ///
    /// This is what a host calls before serving an expiry-dependent read or mutation. Three things
    /// come out of it: a suspension or reboot sets the revalidation this host owes, a rollback
    /// beyond the tolerance marks wall-clock trust unresolved, and an ordinary observation renews
    /// the checkpoint the next one is compared against.
    pub fn observe(&self) -> Discontinuity {
        // The continuous clock first and the wall clock after it, so an observation that is
        // interrupted between the two readings attributes the pause to the wall clock rather than
        // hiding it. Attributing it that way can only make a rollback look larger, never smaller.
        let continuous_ms = self.continuous.boot_elapsed_ms();
        let active_ms = self.active.active_elapsed_ms();
        let wall_ms = self.wall.now_ms().get();
        // Published before anything is decided from it. The raw sample is still what the rollback
        // detection below compares: the floor only moves forward, so it cannot show that the wall
        // clock went back.
        self.publish(wall_ms);
        let now = Reading {
            continuous_ms,
            active_ms,
        };

        let mut state = self.lock();
        let rebooted = state
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.boot_identity != self.boot_identity);
        let mut found = Discontinuity {
            rebooted,
            ..Discontinuity::default()
        };

        if let Some(previous) = state.last {
            // A continuous clock that went backwards broke the one guarantee it has, and a clock
            // whose guarantee is broken is a discontinuity whatever else it says.
            if continuous_ms < previous.continuous_ms || active_ms < previous.active_ms {
                found.suspended = true;
            } else {
                let continuous_delta = continuous_ms - previous.continuous_ms;
                let active_delta = active_ms - previous.active_ms;
                found.suspended =
                    continuous_delta.saturating_sub(active_delta) > millis(DISCONTINUITY_TOLERANCE);
            }
        }

        // The rollback comparison is against the furthest this host could ever prove the clock had
        // reached, projected forward by the continuous time since. Comparing against the previous
        // observation alone forgives a little slippage, then forgives the next against the moved
        // mark, and enough of those would give a UTC deadline back indefinitely.
        // A restored mark may be behind the truth by up to the step this host does not write down,
        // so the tolerance it is compared against is reduced by exactly that much until this host
        // has seen the clock past it. Without that, a step just under the threshold followed by a
        // rollback just over the tolerance would cancel out to something inside it.
        let tolerance = if state.restored.is_some() {
            MAX_WALL_CLOCK_ROLLBACK_MS.saturating_sub(millis(DISCONTINUITY_TOLERANCE))
        } else {
            MAX_WALL_CLOCK_ROLLBACK_MS
        };
        if let Some(mark) = state.high_water {
            let projected = mark.projected(continuous_ms);
            found.rolled_back = projected.saturating_sub(wall_ms) > tolerance;
        } else if let Some(checkpoint) = state.checkpoint.as_ref() {
            // A checkpoint from before a reboot. The continuous clock restarted, so the only
            // comparison left is against the mark itself: a wall clock reading before it has gone
            // backwards.
            found.rolled_back = checkpoint.wall_clock_ms.get().saturating_sub(wall_ms) > tolerance;
        }

        state.last = Some(now);
        if found.rolled_back && state.trust != WallClockTrust::Unresolved {
            state.trust = WallClockTrust::Unresolved;
            // Whatever restored the trust, a clock that went backwards is not the clock that was
            // confirmed. The owner's confirmation goes with it.
            state.owner_confirmed = false;
            // A restarted host cannot work out that its clock had been rejected, so this is one of
            // the two facts it has to read back rather than recompute.
            state.critical = state.critical.saturating_add(1);
        }
        if found.any() {
            state.revalidation_owed = true;
        }
        // The mark moves forward only. A reading at or beyond what this host could prove is new
        // proof; one behind it is slippage the tolerance may forgive, and forgiving it must not
        // move the mark, or the next one would be forgiven against the moved mark.
        let trust = state.trust;
        if trust == WallClockTrust::Trusted {
            let advance = state
                .high_water
                .is_none_or(|mark| wall_ms >= mark.projected(continuous_ms));
            if advance {
                state.high_water = Some(HighWater {
                    wall_ms,
                    continuous_ms,
                });
                // A *step* forward has to be written down; time passing does not. The two are
                // told apart by the projection: a mark plus the continuous time since it was taken
                // is where the clock should be, so anything materially above that is a
                // correction rather than elapsed time. A step this host did not write down is a
                // step a restart would measure the next rollback against, and the tolerance for
                // telling a step from noise is the same one the detector uses.
                let stepped = state.saved.is_none_or(|saved| {
                    wall_ms.saturating_sub(saved.projected(continuous_ms))
                        > millis(DISCONTINUITY_TOLERANCE)
                });
                if stepped {
                    state.critical = state.critical.saturating_add(1);
                }
                // And this is where a restored mark stops being one. A reading a whole tolerance
                // beyond it is at or past the furthest an unwritten step could have taken the
                // clock before the restart, so the mark is this host's own again and the full
                // rollback tolerance applies. A reading short of that leaves the allowance where
                // it is, because the peak this host is comparing against may still be that much
                // higher than anything it has seen.
                if state.restored.is_some_and(|restored| {
                    wall_ms
                        >= restored
                            .projected(continuous_ms)
                            .saturating_add(millis(DISCONTINUITY_TOLERANCE))
                }) {
                    state.restored = None;
                }
            }
        }
        drop(state);

        // The host's own time service is evidence throughout, not only at the start. A service
        // that has stopped keeping this clock - nothing disciplining it, a state the platform is
        // not maintaining, or a bound too loose to mean anything - leaves a clock this host cannot
        // prove, which is the position a rollback leaves it in as well. What stands then is the
        // last mark it could prove, so the checkpoint is not renewed from a reading that proves
        // nothing.
        let reading = self.adapter.read();
        let qualified = reading.is_qualified();
        let mut state = self.lock();
        // A clock the owner confirmed is not demoted by the platform's own answer. Section 9 makes
        // the owner's explicit retrust the route that exists *because* there is no qualified
        // evidence to be had, so reading the same absence as a reason to undo it would leave that
        // route with no effect past the next observation. What still undoes it is a rollback: the
        // owner said what the time was, not that the clock would keep it.
        if !qualified && !state.owner_confirmed && state.trust != WallClockTrust::Unresolved {
            state.trust = WallClockTrust::Unresolved;
            state.critical = state.critical.saturating_add(1);
        }
        let trust = state.trust;
        drop(state);

        // The checkpoint is renewed only while the clock is still evidence. Renewing it after a
        // rollback would record the rolled-back reading as the mark everything later is compared
        // against, which is precisely how a rollback would erase itself.
        if trust == WallClockTrust::Trusted {
            self.checkpoint_at(reading);
        }
        found
    }

    /// Returns the earliest the wall clock can honestly read now.
    ///
    /// Expiry against a UTC deadline uses this rather than the clock itself, so a reading the
    /// tolerance forgave cannot give a deadline back the time it appeared to lose.
    fn proven_wall_ms(&self, state: &TimeState) -> u64 {
        let now = self.wall.now_ms().get();
        state.high_water.map_or(now, |mark| {
            now.max(mark.projected(self.continuous.boot_elapsed_ms()))
        })
    }

    /// Publishes `reading` in the host's clock floor and returns the floor as the raise left it,
    /// or the reading itself when this worker maps no floor.
    fn publish(&self, reading: u64) -> u64 {
        self.floor
            .as_ref()
            .map_or(reading, |floor| floor.raise(reading))
    }

    /// This host's reading of UTC: the proven reading, published in the host's clock floor, and
    /// the floor's value as that left it.
    ///
    /// Every process of the host publishes what it reads before it decides from it, so a reading
    /// any of them took past a deadline is in the value this returns, whatever the wall clock says
    /// by now.
    #[must_use]
    pub fn settled_utc_ms(&self) -> u64 {
        let proven = {
            let state = self.lock();
            self.proven_wall_ms(&state)
        };
        self.publish(proven)
    }

    /// The identity of the clock floor this worker maps, whether or not its name still names it:
    /// a worker never changes its mapping, and states the one it has.
    #[must_use]
    pub fn floor_identity(&self) -> Option<kr_ipc::floor::FloorIdentity> {
        self.floor.as_ref().and_then(|floor| floor.identity())
    }

    /// Decides one copy of authority against its UTC deadline, at a point where its use is
    /// committed.
    ///
    /// The reading is published first and the floor's value loaded from that raise; then the
    /// floor's pathname is confirmed to still name the file this worker maps. A deadline at or
    /// below the value loaded has passed, and the copy never acts. The refusal is an expiry only
    /// when the host's record, the floor's `recorded` word, covers the deadline; otherwise the value
    /// loaded is owed its record, which the control daemon writes at its next decision that reads
    /// the clock or its record task's next pass, and the refusal names no expiry. So nothing this
    /// worker answers as expired rests on a reading a restart, a reboot or a lost floor could take
    /// away. A worker with no floor, or whose floor has lost its name, decides no such copy.
    #[must_use]
    pub fn check_utc_deadline(&self, deadline_ms: u64) -> UtcDeadline {
        let Some(floor) = self.floor.as_ref() else {
            return UtcDeadline::NoFloor;
        };
        let proven = {
            let state = self.lock();
            self.proven_wall_ms(&state)
        };
        let loaded = floor.raise(proven);
        if !floor.named() {
            return UtcDeadline::FloorLost;
        }
        if loaded < deadline_ms {
            return UtcDeadline::Ahead;
        }
        if floor.recorded() >= deadline_ms {
            return UtcDeadline::Passed;
        }
        floor.owe(loaded);
        UtcDeadline::Unrecorded
    }

    /// Decides whether an object is still valid.
    ///
    /// The order is the contract. A tombstone wins outright, because a previously expired object
    /// never revives. A non-expiring owner grant is next, because nothing about a clock bears on
    /// it. Only then do the deadlines decide, continuous first, because it is the one this host
    /// can prove without trusting anything.
    pub fn validity(&self, object: &ExpiringObject) -> Validity {
        let mut state = self.lock();
        if let Some(tombstone) = state.tombstones.get(&object.name) {
            return Validity::Expired(tombstone.reason);
        }
        if object.non_expiring_owner_grant {
            // Section 9: a rollback does not disable a non-expiring personal owner grant. There is
            // no deadline to prove, so there is nothing an unproved clock could be wrong about.
            return Validity::Valid;
        }
        if state.revalidation_owed {
            return Validity::RevalidationOwed;
        }

        // Section 9 expires an object when an applicable continuous deadline **or** a trusted UTC
        // deadline passes, so both are evaluated. Returning valid on the first live one would let
        // an object with two deadlines outlive whichever came first.
        let within_this_boot = object
            .boot_identity
            .as_ref()
            .is_some_and(|boot| *boot == self.boot_identity);
        let continuous = object.continuous_deadline_ms.filter(|_| within_this_boot);
        let trusted_utc = object
            .trusted_utc_deadline_ms
            .filter(|_| state.trust == WallClockTrust::Trusted);

        if let Some(deadline) = continuous
            && self.continuous.boot_elapsed_ms() >= deadline
        {
            return Self::expire(
                &mut state,
                self.tombstone(object, ExpiryReason::ContinuousDeadline),
            );
        }
        if let Some(deadline) = trusted_utc {
            // The proven reading rather than the clock itself, and the platform's own bound on how
            // wrong it may be added to it: an object expires when it *cannot still be valid*, which
            // is the conservative direction section 9 asks for on a forward step.
            // The bound the last qualified reading carried. An absent bound is not a bound of
            // zero: a clock this host cannot say anything about cannot prove an expiry either way,
            // so the object is refused rather than kept or collected.
            let Some(uncertainty_us) = state.checkpoint.as_ref().and_then(|mark| {
                mark.reading
                    .uncertainty_us
                    .as_ref()
                    .map(|bound| bound.get())
            }) else {
                return Validity::Unproven;
            };
            // Published in the host's floor, and decided from the floor's value, so an expiry here
            // stands on the same reading every process of the host decides from.
            if self
                .publish(self.proven_wall_ms(&state))
                .saturating_add(uncertainty_us / 1_000)
                >= deadline
            {
                return Self::expire(
                    &mut state,
                    self.tombstone(object, ExpiryReason::TrustedUtcDeadline),
                );
            }
        }

        if continuous.is_some() || trusted_utc.is_some() {
            return Validity::Valid;
        }
        // A continuous deadline from another boot, an expiring object whose wall clock cannot be
        // proved, or no deadline at all. None of them proves the object is still valid, and
        // section 9 refuses what cannot be proved rather than resolving it in the holder's favour.
        Validity::Unproven
    }

    /// Records a tombstone and returns the expiry it names.
    ///
    /// The table is bounded, and what goes when it is full is the oldest expiry *this boot's
    /// continuous clock already refuses on its own*. Such an object cannot come back: its deadline
    /// is behind a clock that only moves forward inside one boot, and across a boot the deadline
    /// belongs to a boot identity that no longer matches. A tombstone for a trusted UTC deadline
    /// is never dropped, because nothing else refuses that object: a retrust moves the clock, and
    /// section 9 keeps old tombstones through a retrust precisely so an object that had run out
    /// does not come back when it does. The table therefore grows past the bound only in the
    /// number of distinct cross-reboot signed objects a host has expired, which the store that
    /// holds them bounds.
    fn expire(state: &mut TimeState, tombstone: ExpirationTombstone) -> Validity {
        let reason = tombstone.reason;
        let boot = tombstone.boot_identity.clone();
        if state
            .tombstones
            .insert(tombstone.object.clone(), tombstone)
            .is_none()
        {
            state.critical = state.critical.saturating_add(1);
        }
        while state.tombstones.len() > MAX_TOMBSTONES {
            let droppable = state
                .tombstones
                .values()
                .filter(|held| {
                    // Three things together make a tombstone droppable: the object expired on a
                    // clock that only moves forward, it expired in *this* boot, and it carries no
                    // deadline that could present it in another one. Miss any of them and this
                    // record is the only thing refusing the object.
                    held.reason == ExpiryReason::ContinuousDeadline
                        && held.boot_identity == boot
                        && !held.cross_reboot
                })
                .min_by_key(|held| held.expired_at_ms.get())
                .map(|held| held.object.clone());
            match droppable {
                Some(object) => {
                    state.tombstones.remove(&object);
                }
                None => break,
            }
        }
        Validity::Expired(reason)
    }

    /// Returns the tombstones this host holds, oldest name first.
    #[must_use]
    pub fn tombstones(&self) -> Vec<ExpirationTombstone> {
        self.lock().tombstones.values().cloned().collect()
    }

    /// Returns this host's wall clock and continuous clock to trusted, on qualified evidence.
    ///
    /// The tombstones are kept. Section 9 says so outright, and the reason is the whole point of
    /// the mechanism: a clock correction says what the time is now, and says nothing about an
    /// object that had already run out before the correction arrived.
    ///
    /// # Errors
    ///
    /// Returns a permission failure when the evidence does not qualify. An ordinary paired peer's
    /// clock never does.
    pub fn retrust(&self, evidence: &RetrustEvidence) -> Result<TimeCheckpoint> {
        evidence
            .qualifies_for(&self.authority)
            .map_err(|refusal| WorkerError::ClockUntrusted {
                detail: format!(
                    "this host's wall clock stays unresolved: {refusal}. Retrusting it needs \
                     qualified evidence from the configured host time authority, or the owner's \
                     explicit authenticated retrust"
                ),
            })?;
        let refuse = |refusal: kr_protocol::action::RetrustRefusal| WorkerError::ClockUntrusted {
            detail: format!(
                "this host's wall clock stays unresolved: {refusal}. Retrusting it needs \
                 qualified evidence from the configured host time authority, or the owner's \
                 explicit authenticated retrust"
            ),
        };
        let reading = self.adapter.read();
        if let kr_protocol::action::RetrustEvidence::HostTimeAuthority {
            reading: offered, ..
        } = evidence
        {
            // Freshness, against the furthest point this host could prove rather than against the
            // clock in doubt. Time does not go backwards, so evidence reading behind what is
            // already proved is either a replay or a worse clock than the one it corrects.
            // Against the mark this host could prove, projected forward, rather than against the
            // clock reading now: the clock in doubt is the thing being corrected, and requiring
            // the evidence to reach it would require a sample from the future. The bound the
            // evidence carries about itself counts in its favour here, because a reading that says
            // "this time, give or take a millisecond" is not behind a mark it is within.
            let proven = {
                let state = self.lock();
                state
                    .high_water
                    .map_or(0, |mark| mark.projected(self.continuous.boot_elapsed_ms()))
            };
            let offered_reading = offered
                .wall_clock_ms
                .get()
                .saturating_add(microseconds_to_millis(bound_of(offered)));
            if offered_reading < proven {
                return Err(refuse(
                    kr_protocol::action::RetrustRefusal::BehindWhatIsProved,
                ));
            }
            // The new checkpoint is this host's own reading, and it has to qualify: evidence that
            // the time is right is not the same as a clock this host can now keep, and a mark
            // taken from a clock nothing is disciplining would be a mark of nothing.
            if !reading.is_qualified() {
                return Err(refuse(
                    kr_protocol::action::RetrustRefusal::UnqualifiedReading,
                ));
            }
            // And the two have to agree, within what each of them claims about itself plus the
            // rollback this host would notice anyway. Section 9 asks for a new checkpoint as well
            // as qualified evidence: a reading that says the time is something else entirely is
            // evidence about a different clock, and installing it would leave this host trusting a
            // clock nothing had corrected. What corrects the clock is this host's own time
            // service; the authority's part is to confirm that it did.
            let agreement = microseconds_to_millis(bound_of(offered))
                .saturating_add(microseconds_to_millis(bound_of(&reading)))
                .saturating_add(MAX_WALL_CLOCK_ROLLBACK_MS);
            let host_now = self.wall.now_ms().get();
            if host_now.abs_diff(offered.wall_clock_ms.get()) > agreement {
                return Err(refuse(
                    kr_protocol::action::RetrustRefusal::DisagreesWithThisHost,
                ));
            }
        }
        let continuous_ms = self.continuous.boot_elapsed_ms();
        let wall_clock_ms = self.wall.now_ms();
        let checkpoint = TimeCheckpoint {
            boot_identity: self.boot_identity.clone(),
            wall_clock_ms,
            continuous_ms: U64::new(continuous_ms),
            reading,
            trust: WallClockTrust::Trusted,
        };
        // The trust, the mark and the high-water projection move together, and the tombstones stay
        // exactly where they are: section 9 keeps old expiration tombstones through a retrust, and
        // an object that had already run out does not come back because the clock was corrected.
        let mut state = self.lock();
        if state.trust != WallClockTrust::Trusted {
            state.critical = state.critical.saturating_add(1);
        }
        state.trust = WallClockTrust::Trusted;
        let owner = matches!(
            evidence,
            kr_protocol::action::RetrustEvidence::OwnerRetrust { .. }
        );
        if state.owner_confirmed != owner {
            // What the owner confirmed is something a restarted host cannot work out for itself,
            // so it is one of the facts that has to be written down.
            state.critical = state.critical.saturating_add(1);
        }
        state.owner_confirmed = owner;
        state.checkpoint = Some(checkpoint.clone());
        state.high_water = Some(HighWater {
            wall_ms: wall_clock_ms.get(),
            continuous_ms,
        });
        Ok(checkpoint)
    }

    /// Returns what a host has to write down to keep its promises, and which change it is.
    ///
    /// A restarted host reads it back through [`Self::restore`]. The count beside it is what the
    /// host passes to [`Self::note_saved`] once the write has landed: recording the write before
    /// it lands would lose a tombstone or an unresolved clock to the failure.
    #[must_use]
    pub fn durable_state(&self) -> (HostTimeState, u64) {
        let state = self.lock();
        let proven = state.high_water.map(|mark| ProvenWallClock {
            boot_identity: self.boot_identity.clone(),
            wall_clock_ms: TimestampMs::new(mark.wall_ms),
            continuous_ms: U64::new(mark.continuous_ms),
        });
        (
            HostTimeState {
                checkpoint: state.checkpoint.clone().into(),
                trust: state.trust,
                owner_confirmed: state.owner_confirmed,
                proven: proven.into(),
                tombstones: state.tombstones.values().cloned().collect(),
            },
            state.critical,
        )
    }

    /// Returns true when something a restarted host could not reconstruct has not been written.
    #[must_use]
    pub fn unsaved(&self) -> bool {
        let state = self.lock();
        state.critical != state.written
    }

    /// Records that the state at `generation` has been written down.
    ///
    /// What this does not do is end the allowance a restored mark carries. A write records where
    /// this host's mark is; the uncertainty is about where the clock had got *before* the restart,
    /// which writing the same mark down again says nothing about. Only an observation past it can
    /// say that, and [`Self::observe`] is where that is decided.
    pub fn note_saved(&self, generation: u64) {
        let mut state = self.lock();
        state.written = state.written.max(generation);
        state.saved = state.high_water;
    }

    /// Writes a checkpoint of what the clocks read now, over a reading already taken.
    fn checkpoint_at(&self, reading: TimeAdapterReading) -> TimeCheckpoint {
        let continuous_ms = self.continuous.boot_elapsed_ms();
        let trust = self.lock().trust;
        let checkpoint = TimeCheckpoint {
            boot_identity: self.boot_identity.clone(),
            wall_clock_ms: self.wall.now_ms(),
            continuous_ms: U64::new(continuous_ms),
            reading,
            trust,
        };
        self.lock().checkpoint = Some(checkpoint.clone());
        checkpoint
    }

    fn tombstone(&self, object: &ExpiringObject, reason: ExpiryReason) -> ExpirationTombstone {
        ExpirationTombstone {
            object: object.name.clone(),
            reason,
            boot_identity: self.boot_identity.clone(),
            expired_at_ms: self.wall.now_ms(),
            // A UTC deadline is the only thing that can present an object in another boot, so an
            // object that carries one is an object this record is the last refusal of.
            cross_reboot: object.trusted_utc_deadline_ms.is_some(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TimeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::adapter::{RecordedTimeAdapter, classify_unix, unix_model};
    use kr_ipc::clock::{ManualSharedClock, SharedClock as _};
    use kr_protocol::action::{TimeSyncSource, TimeSyncStatus};
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::{Bytes, Nullable};

    const WALL: u64 = 1_700_000_000_000;
    const AUTHORITY: &str = "time.example";

    fn boot(byte: u8) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::MacosBootSessionUuid,
            value: Bytes::new(vec![byte; 16]),
        }
    }

    fn qualified() -> kr_protocol::action::TimeAdapterReading {
        classify_unix(
            "macos",
            "ntp_adjtime(2)",
            crate::action::adapter::UnixTimex {
                time_state: unix_model::TIME_OK,
                status: unix_model::STA_PLL,
                maxerror_us: 62_192,
                esterror_us: 500_000,
            },
            TimestampMs::new(WALL),
        )
    }

    struct Harness {
        contract: TimeContract,
        continuous: ManualSharedClock,
        active: ManualActiveClock,
        wall: ManualWallClock,
        adapter: RecordedTimeAdapter,
    }

    fn harness(boot_byte: u8) -> Harness {
        // The clocks start well past zero, because a real boot-scoped clock does and a detector
        // that only works from zero would not be one.
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let adapter = RecordedTimeAdapter::new(qualified());
        let contract = TimeContract::new(
            boot(boot_byte),
            AUTHORITY,
            TimeSources {
                continuous: Arc::new(continuous.clone()),
                active: Arc::new(active.clone()),
                wall: Arc::new(wall.clone()),
                adapter: Arc::new(adapter.clone()),
                floor: None,
            },
        );
        Harness {
            contract,
            continuous,
            active,
            wall,
            adapter,
        }
    }

    /// Advances real time: the machine is awake, so both clocks and the wall clock move together.
    fn awake(harness: &Harness, duration: Duration) {
        harness.continuous.advance(duration);
        harness.active.advance(duration);
        harness.wall.advance(duration);
    }

    /// Advances suspended time: the continuous clock and the wall clock move, the active one does
    /// not.
    fn asleep(harness: &Harness, duration: Duration) {
        harness.continuous.advance(duration);
        harness.wall.advance(duration);
    }

    #[test]
    fn a_checkpoint_records_the_boot_the_clocks_and_the_platform_reading() {
        let harness = harness(1);
        let checkpoint = harness.contract.checkpoint().expect("a checkpoint");
        assert_eq!(checkpoint.boot_identity, boot(1));
        assert_eq!(checkpoint.wall_clock_ms.get(), WALL);
        assert_eq!(checkpoint.continuous_ms.get(), 3_600_000);
        assert_eq!(
            checkpoint.reading.source,
            TimeSyncSource::NetworkTimeService
        );
        assert_eq!(checkpoint.reading.status, TimeSyncStatus::Ok);
        assert_eq!(checkpoint.trust, WallClockTrust::Trusted);
    }

    #[test]
    fn an_ordinary_observation_finds_nothing_and_owes_nothing() {
        let harness = harness(1);
        awake(&harness, Duration::from_secs(30));
        let found = harness.contract.observe();
        assert!(!found.any());
        assert!(!harness.contract.revalidation_owed());
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
    }

    #[test]
    fn a_suspension_is_detected_and_owes_a_revalidation() {
        let harness = harness(1);
        awake(&harness, Duration::from_secs(5));
        harness.contract.observe();
        asleep(&harness, Duration::from_secs(600));
        let found = harness.contract.observe();
        assert!(found.suspended, "the two clocks disagree by the suspension");
        assert!(!found.rolled_back, "the wall clock kept up with real time");
        assert!(harness.contract.revalidation_owed());
        // Until the leases are revalidated nothing expiry-dependent is served.
        let object = ExpiringObject::within_boot(
            "grant:one",
            &boot(1),
            harness.continuous.boot_elapsed_ms() + 60_000,
        );
        assert_eq!(
            harness.contract.validity(&object),
            Validity::RevalidationOwed
        );
        harness.contract.leases_revalidated();
        assert_eq!(harness.contract.validity(&object), Validity::Valid);
    }

    #[test]
    fn a_suspension_longer_than_a_deadline_expires_it_rather_than_extending_it() {
        let harness = harness(1);
        let deadline = harness.continuous.boot_elapsed_ms() + 120_000;
        let object = ExpiringObject::within_boot("action:one", &boot(1), deadline);
        assert_eq!(harness.contract.validity(&object), Validity::Valid);
        asleep(&harness, Duration::from_secs(3_600));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(
            harness.contract.validity(&object),
            Validity::Expired(ExpiryReason::ContinuousDeadline),
            "the continuous clock counted the sleep, so the deadline passed during it"
        );
    }

    #[test]
    fn a_rollback_beyond_five_seconds_marks_the_wall_clock_unresolved() {
        let harness = harness(1);
        awake(&harness, Duration::from_secs(60));
        harness.contract.observe();
        // Real time moves on and the wall clock is stepped back a day.
        awake(&harness, Duration::from_secs(10));
        harness.wall.set(WALL - 86_400_000);
        let found = harness.contract.observe();
        assert!(found.rolled_back);
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        assert!(!harness.contract.may_collect_expired());
    }

    #[test]
    fn a_rollback_inside_the_tolerance_changes_nothing() {
        let harness = harness(1);
        awake(&harness, Duration::from_secs(60));
        harness.contract.observe();
        awake(&harness, Duration::from_secs(10));
        // Four seconds behind where the continuous clock says it should be: an ordinary correction.
        harness.wall.set(harness.wall.now_ms().get() - 4_000);
        let found = harness.contract.observe();
        assert!(!found.rolled_back);
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert!(harness.contract.may_collect_expired());
    }

    #[test]
    fn a_rollback_does_not_disable_a_non_expiring_owner_grant() {
        let harness = harness(1);
        harness.contract.observe();
        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        let owner = ExpiringObject::non_expiring_owner_grant("grant:owner");
        assert_eq!(harness.contract.validity(&owner), Validity::Valid);
    }

    #[test]
    fn a_rollback_does_not_disable_a_fresh_action_bounded_by_this_boot() {
        let harness = harness(1);
        harness.contract.observe();
        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        let action = ExpiringObject::within_boot(
            "action:fresh",
            &boot(1),
            harness.continuous.boot_elapsed_ms() + 120_000,
        );
        assert_eq!(harness.contract.validity(&action), Validity::Valid);
    }

    #[test]
    fn a_rollback_refuses_an_object_whose_expiry_cannot_otherwise_be_proved() {
        let harness = harness(1);
        harness.contract.observe();
        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        harness.contract.leases_revalidated();
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 86_400_000);
        assert_eq!(
            harness.contract.validity(&signed),
            Validity::Unproven,
            "the deadline is in the future by the clock that cannot be proved"
        );
    }

    #[test]
    fn a_forward_step_expires_a_signed_object_conservatively() {
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        assert_eq!(harness.contract.validity(&signed), Validity::Valid);
        // The wall clock jumps an hour forward, which the continuous clock did not. The step is
        // forward, so trust is unaffected and the deadline it crossed is honoured.
        harness.wall.advance(Duration::from_secs(3_600));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert_eq!(
            harness.contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline)
        );
    }

    #[test]
    fn a_previously_expired_object_never_revives() {
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        harness.wall.advance(Duration::from_secs(120));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(
            harness.contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline)
        );
        // The clock is put back to before the deadline and the object is asked about again.
        harness.wall.set(WALL);
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(
            harness.contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline),
            "the tombstone answers, whatever the clock now reads"
        );
    }

    #[test]
    fn a_continuous_deadline_from_another_boot_proves_nothing() {
        let harness = harness(2);
        let object = ExpiringObject::within_boot(
            "action:previous-boot",
            &boot(1),
            harness.continuous.boot_elapsed_ms() + 120_000,
        );
        assert_eq!(
            harness.contract.validity(&object),
            Validity::Unproven,
            "the clock restarted, so the reading means nothing"
        );
    }

    /// Builds a contract that came up in `boot_byte` having recorded `state` before it restarted,
    /// with its wall clock reading `wall_ms`.
    fn restored(boot_byte: u8, wall_ms: u64, state: Option<HostTimeState>) -> Harness {
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(30));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(30));
        let wall = ManualWallClock::new(wall_ms);
        let adapter = RecordedTimeAdapter::new(qualified());
        let contract = TimeContract::restore(
            boot(boot_byte),
            AUTHORITY,
            TimeSources {
                continuous: Arc::new(continuous.clone()),
                active: Arc::new(active.clone()),
                wall: Arc::new(wall.clone()),
                adapter: Arc::new(adapter.clone()),
                floor: None,
            },
            state,
        );
        Harness {
            contract,
            continuous,
            active,
            wall,
            adapter,
        }
    }

    /// The mark a host wrote down in an earlier boot.
    fn earlier_boot_checkpoint() -> TimeCheckpoint {
        TimeCheckpoint {
            boot_identity: boot(1),
            wall_clock_ms: TimestampMs::new(WALL),
            continuous_ms: U64::new(9_000_000),
            reading: qualified(),
            trust: WallClockTrust::Trusted,
        }
    }

    /// What a host wrote down in an earlier boot: the mark, the trust it stood at, the furthest
    /// reading it could prove, and nothing expired.
    fn earlier_boot_state() -> HostTimeState {
        HostTimeState {
            checkpoint: Nullable::some(earlier_boot_checkpoint()),
            trust: WallClockTrust::Trusted,
            owner_confirmed: false,
            proven: Nullable::some(ProvenWallClock {
                boot_identity: boot(1),
                wall_clock_ms: TimestampMs::new(WALL),
                continuous_ms: U64::new(9_000_000),
            }),
            tombstones: Vec::new(),
        }
    }

    #[test]
    fn an_untrusted_wall_clock_across_a_reboot_cannot_reconstitute_a_grant() {
        // A grant signed with a UTC deadline, and a host that came up in a new boot with its wall
        // clock stepped back before the deadline. Everything it knows about the earlier boot it
        // read back through the restoration path, which is what a restarted host actually has.
        let harness = restored(2, WALL - 30 * 86_400_000, Some(earlier_boot_state()));
        let found = harness.contract.observe();
        assert!(found.rebooted);
        assert!(found.rolled_back, "the clock reads before the mark");
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        harness.contract.leases_revalidated();
        let grant = ExpiringObject::signed_across_reboot("grant:signed", WALL - 1_000);
        assert_eq!(
            harness.contract.validity(&grant),
            Validity::Unproven,
            "the grant expired before the mark, and a rolled-back clock cannot bring it back"
        );
    }

    #[test]
    fn a_reboot_alone_owes_a_revalidation_without_touching_trust() {
        // The wall clock kept running across the reboot, which is the ordinary case.
        let harness = restored(2, WALL + 60_000, Some(earlier_boot_state()));
        let found = harness.contract.observe();
        assert!(found.rebooted);
        assert!(!found.rolled_back);
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert!(harness.contract.revalidation_owed());
    }

    #[test]
    fn a_rollback_does_not_renew_the_checkpoint_it_would_erase_itself_with() {
        let harness = harness(1);
        awake(&harness, Duration::from_secs(60));
        harness.contract.observe();
        let mark = harness.contract.checkpoint().expect("a checkpoint");
        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        let after = harness.contract.checkpoint().expect("a checkpoint");
        assert_eq!(
            after.wall_clock_ms.get(),
            mark.wall_clock_ms.get(),
            "the mark is still the last reading this host could prove"
        );
    }

    #[test]
    fn only_qualified_evidence_returns_the_clock_to_trusted() {
        let harness = harness(1);
        harness.contract.observe();
        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);

        let peer = RetrustEvidence::PairedPeer {
            device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
                [5; 16],
            )),
        };
        let refused = harness.contract.retrust(&peer);
        assert!(matches!(refused, Err(WorkerError::ClockUntrusted { .. })));
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);

        harness.adapter.set(qualified());
        // Evidence that says the time is something else than this host's clock reads is evidence
        // about a different clock. Section 9 asks for a new checkpoint as well as qualified
        // evidence, and a checkpoint is this host's own reading: installing one from a clock that
        // disagrees would leave this host trusting a clock nothing had corrected.
        let authority = |wall_clock_ms: u64| RetrustEvidence::HostTimeAuthority {
            authority: "time.example".to_owned(),
            reading: kr_protocol::action::TimeAdapterReading {
                wall_clock_ms: TimestampMs::new(wall_clock_ms),
                ..qualified()
            },
        };
        // A sample the authority took a moment ago, which this host is reading now. It is not
        // "behind what is proved": its own bound covers the difference, and requiring evidence to
        // reach the clock it is correcting would require a sample from the future.
        let disagreeing = harness.contract.retrust(&authority(WALL));
        assert!(
            matches!(disagreeing, Err(WorkerError::ClockUntrusted { .. })),
            "{disagreeing:?}"
        );
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);

        // The host's own time service corrects the clock, and the authority's reading confirms
        // the correction. That is the pair section 9 asks for, and the mark is taken here.
        harness.wall.set(WALL);
        awake(&harness, Duration::from_millis(40));
        let checkpoint = harness
            .contract
            .retrust(&authority(WALL))
            .expect("a retrust, from a sample taken a moment before this host read it");
        assert_eq!(checkpoint.trust, WallClockTrust::Trusted);
        assert_eq!(
            checkpoint.wall_clock_ms.get(),
            harness.wall.now_ms().get(),
            "the mark is this host's own reading, taken where the checkpoint is written"
        );
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert!(harness.contract.may_collect_expired());
    }

    #[test]
    fn an_owners_explicit_retrust_is_accepted_and_keeps_the_old_tombstones() {
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        harness.wall.advance(Duration::from_secs(120));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert!(matches!(
            harness.contract.validity(&signed),
            Validity::Expired(_)
        ));
        assert_eq!(harness.contract.tombstones().len(), 1);

        harness.wall.set(WALL - 86_400_000);
        harness.contract.observe();
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        let owner = RetrustEvidence::OwnerRetrust {
            action_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
        };
        harness.contract.retrust(&owner).expect("a retrust");
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert_eq!(
            harness.contract.tombstones().len(),
            1,
            "the retrust keeps the expiration tombstone"
        );
        harness.contract.leases_revalidated();
        assert!(
            matches!(harness.contract.validity(&signed), Validity::Expired(_)),
            "and the object it named stays expired"
        );
    }

    #[test]
    fn an_expiry_writes_a_tombstone_that_names_the_boot_and_the_reason() {
        let harness = harness(1);
        let deadline = harness.continuous.boot_elapsed_ms() + 1_000;
        let object = ExpiringObject::within_boot("action:one", &boot(1), deadline);
        awake(&harness, Duration::from_secs(2));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert!(matches!(
            harness.contract.validity(&object),
            Validity::Expired(ExpiryReason::ContinuousDeadline)
        ));
        let tombstones = harness.contract.tombstones();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].object, "action:one");
        assert_eq!(tombstones[0].reason, ExpiryReason::ContinuousDeadline);
        assert_eq!(tombstones[0].boot_identity, boot(1));
    }

    #[test]
    fn slippage_inside_the_tolerance_accumulates_rather_than_being_forgiven_each_time() {
        // A clock that loses four seconds at a time never trips a five-second threshold measured
        // against the previous reading, and the mark would move back with it every time: enough of
        // those and an object with only a UTC deadline would never reach it. Measured against the
        // furthest point this host could prove, the loss accumulates and is caught.
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);

        // One step of four seconds is inside the tolerance, as it should be: an ordinary
        // correction is not a rollback.
        harness.continuous.advance(Duration::from_secs(4));
        harness.active.advance(Duration::from_secs(4));
        let found = harness.contract.observe();
        assert!(!found.rolled_back, "one small correction is forgiven");
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);

        // The second one takes the accumulated loss past the tolerance, so the clock stops being
        // evidence rather than being forgiven again.
        harness.continuous.advance(Duration::from_secs(4));
        harness.active.advance(Duration::from_secs(4));
        let found = harness.contract.observe();
        assert!(
            found.rolled_back,
            "the loss accumulated rather than resetting"
        );
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        harness.contract.leases_revalidated();

        // And the object it would have kept alive is refused rather than given its lifetime back.
        assert_eq!(harness.contract.validity(&signed), Validity::Unproven);
    }

    #[test]
    fn a_deadline_on_each_clock_expires_at_whichever_comes_first() {
        // Section 9 expires an object when an applicable continuous deadline *or* a trusted UTC
        // deadline passes. An object with both must not outlive either.
        let first = harness(1);
        let harness = first;
        let object = ExpiringObject {
            name: "grant:both".to_owned(),
            boot_identity: Some(boot(1)),
            continuous_deadline_ms: Some(harness.continuous.boot_elapsed_ms() + 3_600_000),
            trusted_utc_deadline_ms: Some(WALL + 60_000),
            non_expiring_owner_grant: false,
        };
        assert_eq!(harness.contract.validity(&object), Validity::Valid);
        // The wall clock passes the UTC deadline while the continuous one has an hour left.
        awake(&harness, Duration::from_secs(120));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert_eq!(
            harness.contract.validity(&object),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline),
            "a live continuous deadline does not outlive an expired trusted one"
        );

        // And the other way round.
        let second = super::tests::harness(1);
        let object = ExpiringObject {
            name: "grant:both".to_owned(),
            boot_identity: Some(boot(1)),
            continuous_deadline_ms: Some(second.continuous.boot_elapsed_ms() + 60_000),
            trusted_utc_deadline_ms: Some(WALL + 3_600_000),
            non_expiring_owner_grant: false,
        };
        awake(&second, Duration::from_secs(120));
        second.contract.observe();
        second.contract.leases_revalidated();
        assert_eq!(
            second.contract.validity(&object),
            Validity::Expired(ExpiryReason::ContinuousDeadline)
        );
    }

    #[test]
    fn a_host_whose_time_service_says_nothing_starts_unresolved() {
        // There is no earlier mark to compare against, so the platform's answer is the whole of
        // what this host knows about its wall clock. A clock nothing is keeping cannot prove the
        // expiry of anything, and section 9 refuses what cannot be proved.
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(30));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(30));
        let contract = TimeContract::new(
            boot(1),
            AUTHORITY,
            TimeSources {
                continuous: Arc::new(continuous),
                active: Arc::new(active),
                wall: Arc::new(ManualWallClock::new(WALL)),
                adapter: Arc::new(RecordedTimeAdapter::new(
                    crate::action::adapter::unavailable(
                        "macos",
                        "ntp_adjtime(2)",
                        TimestampMs::new(WALL),
                    ),
                )),
                floor: None,
            },
        );
        assert_eq!(contract.trust(), WallClockTrust::Unresolved);
        assert!(!contract.may_collect_expired());
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        assert_eq!(contract.validity(&signed), Validity::Unproven);
        // A fresh action bounded by this boot's continuous clock still works, which is the half
        // section 9 says an unresolved clock must not disable.
        let fresh = ExpiringObject::within_boot("action:fresh", &boot(1), 30_000 + 120_000);
        assert_eq!(contract.validity(&fresh), Validity::Valid);
    }

    #[test]
    fn what_a_host_writes_down_is_what_a_restarted_one_reads_back() {
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        harness.wall.advance(Duration::from_secs(120));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert!(matches!(
            harness.contract.validity(&signed),
            Validity::Expired(_)
        ));
        let (state, generation) = harness.contract.durable_state();
        assert_eq!(state.tombstones.len(), 1);
        assert!(state.checkpoint.is_present());
        assert!(state.proven.is_present());
        assert!(harness.contract.unsaved(), "a tombstone has to be written");
        harness.contract.note_saved(generation);
        assert!(!harness.contract.unsaved());

        // A new boot reads them back. The object stays expired whatever the clock now reads, and
        // the mark it recorded is still what a rollback is measured against.
        let restarted = restored(2, WALL, Some(state));
        assert!(matches!(
            restarted.contract.validity(&signed),
            Validity::Expired(_)
        ));
        restarted.wall.set(WALL - 86_400_000);
        let found = restarted.contract.observe();
        assert!(found.rolled_back);
        assert_eq!(restarted.contract.trust(), WallClockTrust::Unresolved);
    }

    #[test]
    fn a_time_service_that_stops_keeping_the_clock_costs_this_host_its_trust() {
        // The platform's own answer is the evidence, and it is evidence throughout rather than
        // only at the start. A host whose service stops keeping its clock has a clock it cannot
        // prove, so the UTC half stops and the mark it could prove is what stands.
        let harness = harness(1);
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        let mark = harness.contract.checkpoint().expect("a checkpoint");
        awake(&harness, Duration::from_secs(60));
        harness.adapter.set(crate::action::adapter::unavailable(
            "macos",
            "ntp_adjtime(2)",
            TimestampMs::new(WALL + 60_000),
        ));
        let found = harness.contract.observe();
        assert!(!found.any(), "no clock jumped: {found:?}");
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        assert!(!harness.contract.may_collect_expired());
        assert_eq!(
            harness.contract.checkpoint().map(|held| held.wall_clock_ms),
            Some(mark.wall_clock_ms),
            "the last mark this host could prove is what stands"
        );
        // And what the loss cost is the UTC half only. A fresh action bounded by this boot's
        // continuous clock is unaffected, which is what section 9 requires of an unproved clock.
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 600_000);
        assert_eq!(harness.contract.validity(&signed), Validity::Unproven);
        let fresh = ExpiringObject::within_boot(
            "action:fresh",
            &boot(1),
            harness.continuous.boot_elapsed_ms() + 120_000,
        );
        assert_eq!(harness.contract.validity(&fresh), Validity::Valid);
    }

    #[test]
    fn a_restarted_host_reads_back_the_clock_the_running_one_could_not_prove() {
        // A rollback beyond the tolerance marks the clock unresolved and deliberately leaves the
        // last mark alone: the mark is what the clock was last proved at, and overwriting it with
        // the rolled-back reading is how a rollback would erase itself. What that means for a
        // restart is that the mark's own trust is not the host's current trust, and a restarted
        // host that read trust from the mark would start trusting a clock the running one rejected.
        let harness = harness(1);
        harness.wall.set(WALL - 86_400_000);
        assert!(harness.contract.observe().rolled_back);
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        let (state, generation) = harness.contract.durable_state();
        assert_eq!(state.trust, WallClockTrust::Unresolved);
        assert_eq!(
            state.checkpoint.as_ref().map(|mark| mark.trust),
            Some(WallClockTrust::Trusted),
            "the mark records what was true when it was taken"
        );
        assert!(harness.contract.unsaved());
        harness.contract.note_saved(generation);

        let restarted = restored(1, WALL - 86_400_000, Some(state));
        assert_eq!(restarted.contract.trust(), WallClockTrust::Unresolved);
        assert!(!restarted.contract.may_collect_expired());
    }

    #[test]
    fn a_forward_step_that_could_hide_a_rollback_is_written_down() {
        let harness = harness(1);
        let (first, generation) = harness.contract.durable_state();
        harness.contract.note_saved(generation);
        assert!(!harness.contract.unsaved());

        // Ordinary time passing. The mark advances with it, and nothing about that is worth a
        // durable write: a restart that read the older mark back would measure the same rollback.
        awake(&harness, Duration::from_secs(1));
        harness.contract.observe();
        assert!(
            !harness.contract.unsaved(),
            "a second of ordinary time is not a durable write"
        );

        // A step of a day forward. A restart that read the older mark back would measure the
        // correction that follows it against a reading a day behind, and find no rollback at all,
        // so this host has to write the step down.
        harness.wall.advance(Duration::from_secs(86_400));
        harness.contract.observe();
        assert!(harness.contract.unsaved());
        let (stepped, generation) = harness.contract.durable_state();
        assert!(
            stepped
                .proven
                .as_ref()
                .map(|proven| proven.wall_clock_ms.get())
                > first
                    .proven
                    .as_ref()
                    .map(|proven| proven.wall_clock_ms.get()),
            "what is written down is the reading this host could prove"
        );
        harness.contract.note_saved(generation);
        assert!(!harness.contract.unsaved());

        // And the step is what a rollback is then measured against: the clock coming back to
        // where it was is a day of rollback, not nothing.
        harness.wall.set(WALL);
        assert!(harness.contract.observe().rolled_back);
    }

    #[test]
    fn slippage_survives_writing_the_state_down_and_reading_it_back() {
        // Slippage inside the tolerance is forgiven but not forgotten, and a restart must not be
        // the way to forget it. The mark and the checkpoint are written down separately for
        // exactly this reason: the checkpoint follows the clock down, and the mark does not.
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let adapter = RecordedTimeAdapter::new(qualified());
        let sources = || TimeSources {
            continuous: Arc::new(continuous.clone()),
            active: Arc::new(active.clone()),
            wall: Arc::new(wall.clone()),
            adapter: Arc::new(adapter.clone()),
            floor: None,
        };

        let contract = TimeContract::restore(boot(1), AUTHORITY, sources(), None);
        wall.set(WALL - 4_000);
        assert!(
            !contract.observe().rolled_back,
            "four seconds is inside the tolerance"
        );
        let (state, _) = contract.durable_state();
        assert_eq!(
            state
                .checkpoint
                .as_ref()
                .map(|mark| mark.wall_clock_ms.get()),
            Some(WALL - 4_000),
            "the checkpoint followed the clock down"
        );
        assert_eq!(
            state
                .proven
                .as_ref()
                .map(|proven| proven.wall_clock_ms.get()),
            Some(WALL),
            "and the mark it is compared against did not"
        );

        // Read the state back and step back four seconds again. That is eight seconds behind what
        // this host proved, which is past the tolerance: slippage costs what it costs once and
        // buys nothing after that, and a restart is not a way to buy more.
        let restarted = TimeContract::restore(boot(1), AUTHORITY, sources(), Some(state));
        wall.set(WALL - 8_000);
        assert!(
            restarted.observe().rolled_back,
            "a restart does not forgive slippage that was already paid for"
        );
        assert_eq!(restarted.trust(), WallClockTrust::Unresolved);
    }

    #[test]
    fn a_tombstone_nothing_else_refuses_is_never_dropped_to_make_room() {
        // A signed object with only a UTC deadline. Nothing but its tombstone refuses it: a
        // retrust moves the clock forward, and section 9 keeps old tombstones through a retrust
        // exactly so an object that had already run out does not come back when it does.
        let harness = harness(1);
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 60_000);
        harness.wall.advance(Duration::from_secs(120));
        harness.contract.observe();
        harness.contract.leases_revalidated();
        assert!(matches!(
            harness.contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline)
        ));

        // More expiries than the table holds, every one of them refused by this boot's continuous
        // clock on its own. They are what makes room; the signed object's tombstone stays.
        for index in 0..=MAX_TOMBSTONES {
            let object = ExpiringObject::within_boot(format!("action:{index}"), &boot(1), 0);
            assert!(matches!(
                harness.contract.validity(&object),
                Validity::Expired(ExpiryReason::ContinuousDeadline)
            ));
            harness.wall.advance(Duration::from_millis(1));
        }
        assert!(harness.contract.tombstones().len() <= MAX_TOMBSTONES);
        assert!(
            matches!(
                harness.contract.validity(&signed),
                Validity::Expired(ExpiryReason::TrustedUtcDeadline)
            ),
            "the object nothing else refuses keeps its tombstone"
        );

        // And the owner correcting the clock does not bring it back, which is what the tombstone
        // is for.
        harness.wall.set(WALL);
        let owner = RetrustEvidence::OwnerRetrust {
            action_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
        };
        harness.contract.retrust(&owner).expect("an owner retrust");
        assert!(matches!(
            harness.contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline)
        ));
    }

    #[test]
    fn an_owner_can_retrust_a_clock_this_hosts_own_service_cannot_keep() {
        // Section 9's two routes are not the same route. Qualified evidence from the configured
        // authority needs a clock this host can keep and that agrees with it; the owner's explicit
        // retrust is what is left when there is no such clock and no such authority, which is
        // exactly the host whose time service has stopped keeping anything.
        let harness = harness(1);
        harness.adapter.set(crate::action::adapter::unavailable(
            "macos",
            "ntp_adjtime(2)",
            TimestampMs::new(WALL),
        ));
        harness.contract.observe();
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);
        let owner = RetrustEvidence::OwnerRetrust {
            action_digest: kr_protocol::scalars::Digest256::from_bytes([9; 32]),
        };
        let checkpoint = harness.contract.retrust(&owner).expect("an owner retrust");
        assert_eq!(checkpoint.trust, WallClockTrust::Trusted);
        assert!(harness.contract.may_collect_expired());
        // What the owner restored is trust in the clock, not a bound on it. An object with only a
        // UTC deadline still cannot be proved, because nothing says how wrong the clock may be.
        let signed = ExpiringObject::signed_across_reboot("grant:signed", WALL + 600_000);
        assert_eq!(harness.contract.validity(&signed), Validity::Unproven);

        // And it survives the next observation, which is what makes it a route rather than a
        // gesture: this host looks at its clocks before every mutation, and its own service still
        // says nothing. Reading that absence as a reason to undo the owner would leave the owner
        // with nothing to do.
        awake(&harness, Duration::from_secs(30));
        harness.contract.observe();
        assert_eq!(harness.contract.trust(), WallClockTrust::Trusted);
        assert!(harness.contract.may_collect_expired());

        // What does undo it is the clock going backwards. The owner said what the time was, not
        // that the clock would keep it.
        harness.wall.set(WALL - 86_400_000);
        assert!(harness.contract.observe().rolled_back);
        assert_eq!(harness.contract.trust(), WallClockTrust::Unresolved);

        // And what the owner restored is written down, so a restart into the same absence does not
        // start by undoing it: the restored host reads the confirmation back, its own service still
        // says nothing, and its first observation leaves the trust alone.
        let owner = RetrustEvidence::OwnerRetrust {
            action_digest: kr_protocol::scalars::Digest256::from_bytes([10; 32]),
        };
        harness.contract.retrust(&owner).expect("an owner retrust");
        let (state, _) = harness.contract.durable_state();
        assert_eq!(state.trust, WallClockTrust::Trusted);
        assert!(state.owner_confirmed);
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(harness.wall.now_ms().get());
        let restarted = TimeContract::restore(
            boot(1),
            AUTHORITY,
            TimeSources {
                continuous: Arc::new(continuous),
                active: Arc::new(active),
                wall: Arc::new(wall),
                adapter: Arc::new(RecordedTimeAdapter::new(
                    crate::action::adapter::unavailable(
                        "macos",
                        "ntp_adjtime(2)",
                        TimestampMs::new(WALL),
                    ),
                )),
                floor: None,
            },
            Some(state),
        );
        assert_eq!(restarted.trust(), WallClockTrust::Trusted);
        restarted.observe();
        assert_eq!(
            restarted.trust(),
            WallClockTrust::Trusted,
            "a restart into the same absence does not undo what the owner confirmed"
        );
        assert!(restarted.may_collect_expired());
    }

    #[test]
    fn a_restored_mark_is_stricter_by_what_a_step_may_have_left_unsaved() {
        // A step smaller than the tolerance for telling a step from noise is not written down, so
        // a restored mark can be behind the truth by that much. A rollback measured against it
        // would look smaller by the same amount, and one just past the five-second tolerance would
        // cancel out to something inside it. Until this host has seen the clock past that mark, it
        // is that much stricter, which is the conservative direction.
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let adapter = RecordedTimeAdapter::new(qualified());
        let sources = || TimeSources {
            continuous: Arc::new(continuous.clone()),
            active: Arc::new(active.clone()),
            wall: Arc::new(wall.clone()),
            adapter: Arc::new(adapter.clone()),
            floor: None,
        };
        let contract = TimeContract::restore(boot(1), AUTHORITY, sources(), None);
        let (state, generation) = contract.durable_state();
        contract.note_saved(generation);

        // A step of two hundred milliseconds: inside the tolerance, so it is not written down.
        wall.set(WALL + 200);
        contract.observe();
        assert!(
            !contract.unsaved(),
            "a step inside the tolerance is not worth a durable write"
        );

        // The restored host therefore has a mark up to that much behind the truth. A rollback of
        // five and a tenth seconds from the *true* reading looks like four and nine tenths from the
        // mark, and it is still reported.
        //
        // Recovery is part of the sequence rather than beside it: `Session::open` observes the
        // clocks, writes the state down and says so, all before this host serves anything. Those
        // three steps are what happens here, with the clock a tenth of a second behind the mark,
        // which is inside every tolerance and moves nothing. The write records where this host's
        // mark is; it says nothing about how far the clock had got before the restart, so it must
        // not be what ends the allowance.
        wall.set(WALL - 100);
        let restarted = TimeContract::restore(boot(1), AUTHORITY, sources(), Some(state));
        restarted.observe();
        let (_, generation) = restarted.durable_state();
        restarted.note_saved(generation);
        wall.set(WALL + 200 - 5_100);
        assert!(
            restarted.observe().rolled_back,
            "a rollback past the tolerance is reported whatever the restored mark missed"
        );
        assert_eq!(restarted.trust(), WallClockTrust::Unresolved);
    }

    #[test]
    fn a_restored_mark_stops_being_stricter_once_this_host_has_seen_past_it() {
        // The allowance is for an advance this host may not have written down, and it is bounded:
        // an unwritten step is smaller than the tolerance for telling a step from noise. So a
        // reading a whole tolerance beyond the restored mark is at or past the furthest that step
        // could have taken the clock, the mark is this host's own again, and the full rollback
        // tolerance applies.
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let adapter = RecordedTimeAdapter::new(qualified());
        let sources = || TimeSources {
            continuous: Arc::new(continuous.clone()),
            active: Arc::new(active.clone()),
            wall: Arc::new(wall.clone()),
            adapter: Arc::new(adapter.clone()),
            floor: None,
        };
        let contract = TimeContract::restore(boot(1), AUTHORITY, sources(), None);
        let (state, generation) = contract.durable_state();
        contract.note_saved(generation);

        // A rollback of four and nine tenths seconds is inside the five-second tolerance and
        // outside the restored one. While the mark may be behind the truth, it is reported.
        let strict = TimeContract::restore(boot(1), AUTHORITY, sources(), Some(state.clone()));
        wall.set(WALL - 4_900);
        assert!(strict.observe().rolled_back);
        drop(strict);

        // The same restored mark, on a host that has since seen the clock a whole tolerance past
        // it. The same rollback is now inside the tolerance and is not reported.
        wall.set(WALL);
        let seen = TimeContract::restore(boot(1), AUTHORITY, sources(), Some(state));
        wall.set(WALL + 250);
        assert!(!seen.observe().rolled_back, "the clock went forward");
        wall.set(WALL + 250 - 4_900);
        assert!(
            !seen.observe().rolled_back,
            "the mark is this host's own now, so the whole five seconds is what a rollback is \
             measured against"
        );
        assert_eq!(seen.trust(), WallClockTrust::Trusted);
    }

    #[test]
    fn a_tombstone_for_an_object_that_outlives_this_boot_is_never_dropped() {
        // An object with both deadlines: a continuous one in this boot and a later UTC one. The
        // continuous deadline expires it here, and only the tombstone refuses it in another boot,
        // where the continuous deadline belongs to a boot identity that no longer matches and the
        // UTC deadline is still in the future.
        let harness = harness(1);
        let both = ExpiringObject {
            trusted_utc_deadline_ms: Some(WALL + 600_000),
            ..ExpiringObject::within_boot("grant:both", &boot(1), 0)
        };
        assert!(matches!(
            harness.contract.validity(&both),
            Validity::Expired(ExpiryReason::ContinuousDeadline)
        ));

        // More expiries than the table holds, every one of them refused by this boot's continuous
        // clock and by nothing else. They are what makes room; the object that outlives the boot
        // keeps its tombstone.
        for index in 0..=MAX_TOMBSTONES {
            let object = ExpiringObject::within_boot(format!("action:{index}"), &boot(1), 0);
            assert!(matches!(
                harness.contract.validity(&object),
                Validity::Expired(ExpiryReason::ContinuousDeadline)
            ));
            harness.wall.advance(Duration::from_millis(1));
        }
        let (state, _) = harness.contract.durable_state();
        assert!(
            state
                .tombstones
                .iter()
                .any(|tombstone| tombstone.object == "grant:both" && tombstone.cross_reboot),
            "the object nothing else refuses keeps its tombstone"
        );

        // And the next boot reads it back and refuses the object, which is the whole point.
        let restarted = restored(2, WALL, Some(state));
        assert!(matches!(
            restarted.contract.validity(&both),
            Validity::Expired(ExpiryReason::ContinuousDeadline)
        ));
    }

    #[test]
    fn the_tombstone_table_is_bounded_and_the_oldest_expiry_is_what_goes() {
        let harness = harness(1);
        // Every object here has already run out on this boot's continuous clock, so each look
        // tombstones one. More of them than the table holds, so the table has to choose.
        for index in 0..=MAX_TOMBSTONES {
            let object = ExpiringObject::within_boot(format!("action:{index}"), &boot(1), 0);
            assert!(matches!(
                harness.contract.validity(&object),
                Validity::Expired(ExpiryReason::ContinuousDeadline)
            ));
            harness.wall.advance(Duration::from_millis(1));
        }
        let (state, _) = harness.contract.durable_state();
        assert_eq!(state.tombstones.len(), MAX_TOMBSTONES);
        assert!(
            !state
                .tombstones
                .iter()
                .any(|tombstone| tombstone.object == "action:0"),
            "the oldest expiry is the one another rule is most certain to refuse anyway"
        );
        // The object whose tombstone went is still refused, because its deadline is behind a clock
        // that only moves forward inside one boot. Nothing revived.
        let dropped = ExpiringObject::within_boot("action:0", &boot(1), 0);
        assert!(matches!(
            harness.contract.validity(&dropped),
            Validity::Expired(ExpiryReason::ContinuousDeadline)
        ));
    }

    #[test]
    fn a_suspension_across_the_first_two_observations_is_noticed() {
        // The complete sample is taken at construction, so a machine that slept between being
        // built and being asked is a discontinuity like any other. Without it the first
        // observation would have nothing to compare against and would find nothing.
        let harness = harness(1);
        asleep(&harness, Duration::from_secs(600));
        let found = harness.contract.observe();
        assert!(found.suspended);
        assert!(harness.contract.revalidation_owed());
    }

    #[test]
    fn the_system_contract_reads_this_machine() {
        let contract = TimeContract::system(boot(9), AUTHORITY);
        let checkpoint = contract.checkpoint().expect("a checkpoint");
        assert_eq!(
            checkpoint.reading.platform,
            super::super::adapter::platform_name()
        );
        assert!(checkpoint.continuous_ms.get() > 0);
        assert!(checkpoint.wall_clock_ms.get() > 0);
        // Two observations a moment apart find nothing: the machine did not sleep between them and
        // its wall clock did not move backwards.
        contract.observe();
        let found = contract.observe();
        assert!(!found.any(), "{found:?}");
    }

    /// A contract over manual clocks, a qualified time service and `floor`.
    fn floored(floor: Option<Arc<kr_ipc::floor::SharedFloor>>) -> (TimeContract, ManualWallClock) {
        let continuous = ManualSharedClock::new();
        continuous.advance(Duration::from_secs(3_600));
        let active = ManualActiveClock::new();
        active.advance(Duration::from_secs(3_600));
        let wall = ManualWallClock::new(WALL);
        let contract = TimeContract::new(
            boot(1),
            AUTHORITY,
            TimeSources {
                continuous: Arc::new(continuous),
                active: Arc::new(active),
                wall: Arc::new(wall.clone()),
                adapter: Arc::new(RecordedTimeAdapter::new(qualified())),
                floor,
            },
        );
        (contract, wall)
    }

    #[test]
    fn every_reading_is_published_before_it_is_decided_from() {
        let floor = Arc::new(kr_ipc::floor::SharedFloor::in_process(WALL - 1_000));
        let (contract, wall) = floored(Some(Arc::clone(&floor)));
        // Building the contract observed the clock, and the observation is in the floor.
        assert!(floor.load() >= WALL, "an observation publishes its sample");
        wall.set(WALL + 500);
        contract.observe();
        assert_eq!(floor.load(), WALL + 500, "and so does every later one");
        assert_eq!(
            contract.settled_utc_ms(),
            WALL + 500,
            "the settled reading is the proven one, published"
        );

        // Another process publishes a reading ahead of this worker's own. The settled reading is
        // the floor's value, and an expiry is decided from it.
        floor.raise(WALL + 10_000);
        assert_eq!(contract.settled_utc_ms(), WALL + 10_000);
        let signed = ExpiringObject::signed_across_reboot("signed", WALL + 5_000);
        assert_eq!(
            contract.validity(&signed),
            Validity::Expired(ExpiryReason::TrustedUtcDeadline),
            "a UTC deadline another process's reading passed is passed here too"
        );

        // The control: the same object under a floor nothing raised is valid, and a reading below
        // the floor leaves the floor where it is.
        let quiet = Arc::new(kr_ipc::floor::SharedFloor::in_process(0));
        let (quiet_contract, _) = floored(Some(Arc::clone(&quiet)));
        assert!(quiet_contract.validity(&signed).is_valid());
        quiet.raise(WALL + 60_000);
        assert_eq!(quiet_contract.settled_utc_ms(), WALL + 60_000);
        assert_eq!(quiet.load(), WALL + 60_000);
    }

    #[test]
    fn publishing_hides_no_rollback() {
        // The floor only moves forward, so it cannot show that the wall clock went back; the raw
        // sample still decides that.
        let floor = Arc::new(kr_ipc::floor::SharedFloor::in_process(0));
        let (contract, wall) = floored(Some(Arc::clone(&floor)));
        floor.raise(WALL + 10_000);
        wall.set(WALL - 60_000);
        let found = contract.observe();
        assert!(found.rolled_back, "{found:?}");
        assert_eq!(contract.trust(), WallClockTrust::Unresolved);
        assert_eq!(
            floor.load(),
            WALL + 10_000,
            "and the floor stays where it was"
        );
    }

    #[test]
    fn a_copy_past_its_utc_deadline_is_an_expiry_only_once_the_record_covers_it() {
        let floor = Arc::new(kr_ipc::floor::SharedFloor::in_process(0));
        let (contract, wall) = floored(Some(Arc::clone(&floor)));
        let deadline = WALL + 2_000;
        assert_eq!(contract.check_utc_deadline(deadline), UtcDeadline::Ahead);
        assert_eq!(floor.owed(), 0, "a copy that is still live owes nothing");

        // The deadline passes by this worker's own reading, with nothing recorded past it: the
        // copy is refused, the refusal names no expiry, and the floor it passed on is owed.
        wall.set(WALL + 3_000);
        assert_eq!(
            contract.check_utc_deadline(deadline),
            UtcDeadline::Unrecorded
        );
        assert!(floor.owed() >= WALL + 3_000);
        // A step back of the wall clock gives the copy nothing: the floor holds the reading.
        wall.set(WALL);
        assert_eq!(
            contract.check_utc_deadline(deadline),
            UtcDeadline::Unrecorded
        );

        // The control daemon writes the floor down; from then on the refusal is an expiry.
        floor.record(floor.load());
        assert_eq!(contract.check_utc_deadline(deadline), UtcDeadline::Passed);

        // The control: a record that already covered the deadline makes the first refusal an
        // expiry, and owes nothing.
        let recorded = Arc::new(kr_ipc::floor::SharedFloor::in_process(WALL + 5_000));
        let (covered, _) = floored(Some(Arc::clone(&recorded)));
        assert_eq!(covered.check_utc_deadline(deadline), UtcDeadline::Passed);
        assert_eq!(recorded.owed(), 0);
    }

    #[test]
    fn a_worker_with_no_floor_or_a_nameless_one_decides_no_utc_deadline() {
        let (unfloored, _) = floored(None);
        assert_eq!(
            unfloored.check_utc_deadline(WALL + 60_000),
            UtcDeadline::NoFloor
        );
        assert_eq!(unfloored.floor_identity(), None);

        let suffix = kr_ipc::new_uuid().to_string();
        let root = std::env::temp_dir().join(format!("kr-worker-floor-{}", &suffix[..8]));
        kr_ipc::paths::create_private_tree(&root, &root).expect("a private directory");
        let path = root.join("utc-floor");
        let environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let boot_epoch = kr_protocol::ids::BootEpoch::new(11);
        let created = kr_ipc::floor::SharedFloor::create(&path, environment_id, boot_epoch, 0)
            .expect("created");
        let mapped = Arc::new(
            kr_ipc::floor::SharedFloor::open(&path, environment_id, boot_epoch).expect("mapped"),
        );
        let (contract, _) = floored(Some(Arc::clone(&mapped)));
        assert_eq!(contract.floor_identity(), created.identity());
        // The control: while the name names the file, a live copy is live.
        assert_eq!(
            contract.check_utc_deadline(WALL + 60_000),
            UtcDeadline::Ahead
        );
        std::fs::remove_file(&path).expect("the name is removed");
        assert_eq!(
            contract.check_utc_deadline(WALL + 60_000),
            UtcDeadline::FloorLost
        );
        assert_eq!(
            contract.floor_identity(),
            created.identity(),
            "a worker states the floor it maps, name or not"
        );
        std::fs::remove_dir_all(&root).expect("removed");
    }
}
