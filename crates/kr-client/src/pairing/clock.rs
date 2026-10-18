//! The clock a device's pairing attempts are measured on.
//!
//! Three readings, each used for what only it can answer. The monotonic reading is the machine's
//! boot-scoped counter, so a deadline it decides cannot be moved by a clock adjustment. The boot
//! identity says which boot that counter belongs to, so the attempt budget's five-minute window
//! ends at a reboot rather than reading a deadline from before it as time still to run. The
//! wall-clock reading is what the budget's tombstones and a peer's expiries are expressed in.
//!
//! # Where the boot identity comes from
//!
//! Where the kernel names its boot ([`DeviceClock::current`]: Linux, Android, macOS and Windows),
//! the identity is the kernel's. The Apple mobile systems name none to an application: the boot
//! session identifier is not available to one, and the boot time moves when the wall clock is set.
//! [`DeviceClock::resumed`] makes an identity there from the two clocks the system does give an
//! application, kept in a small record beside the application's caches.
//!
//! On Darwin the monotonic counter is the wall clock less the boot time, so `wall - monotonic` is
//! the boot time as the wall clock now dates it. The record keeps that number from the launch that
//! made the identity (its *reference*) and the counter at the latest launch (`seen`). A launch
//! belongs to the same boot when the counter has not gone back and the boot time, as dated now,
//! has moved by no more than a minute either way and no more than the counter had reached at the
//! previous launch. Otherwise it is a new boot, and the record is made again with a new random
//! identity. The reference never moves while an identity lives, so a run of quick restarts cannot
//! add their errors up.
//!
//! What this guarantees, and what it does not:
//!
//! * **Within one process** the identity is fixed when the clock is made, so a wall-clock step
//!   during the process changes nothing for it.
//! * **Across a relaunch in one boot** the identity is kept while the wall clock's net steps since
//!   the identity was made stay within the minute. A larger net step reads as a new boot, and the
//!   safe thing follows: every open entry of the budget becomes a tombstone, and a person needs a
//!   new code. Steps forward are also bounded by the counter at the previous launch (the second
//!   clause above), which costs something only when that launch came in the first minute of its
//!   boot.
//! * **Across a reboot, a wall clock not set back since the identity was made** never reads as the
//!   same boot. A later boot starts later than the earlier boot's last launch by the time the
//!   machine was off, so the boot time moves forward by more than the counter that launch saw. The
//!   comparison leaves out a fifth of a second of that counter for the sampling's error, which is
//!   more than the error, so it holds for any time off.
//! * **Across a reboot, a wall clock set back since the identity was made** (or lost, as a clock
//!   does that loses its time), by about the real time between the start of the boot the identity
//!   was made in and the start of the new boot, to within a minute, reads as the same boot when
//!   the new boot is already as old as the previous launch's counter. Then a record of the earlier
//!   boot is read on the new boot's counter, and an entry that was unfinished is not expired by
//!   the reboot: its window and retention move later in real time, by at most the time between
//!   the start of the boot the identity was made in and the start of the new one. Each record is
//!   still judged by itself ([`kr_pairing::platform::ClientAttemptRecord::anchored`]): it
//!   continues only when its identity is the current one and the counter has reached its first
//!   entry, so an entry made late in a long boot is spent. The attempt count and the exhausted
//!   flag are never touched, nothing is dropped early, and the host's own deadline and caps still
//!   apply. This case is accepted.
//! * **The record is a cache.** A missing, unreadable or foreign record, a purged cache directory,
//!   a reinstall and a restore onto another device all read as a new boot.
//!
//! The counter is assumed not to run back within a boot, and one clock is assumed to own the record
//! (an application is one process on these systems). A second process would at worst make a second
//! identity and turn the first one's records into tombstones.
//!
//! The same-boot noise is the wall clock's net steps since the reference, plus up to about a tenth
//! of a second of sampling error. The monotonic reading is [`kr_ipc::clock::boot_elapsed_ms`], which
//! on Darwin follows the wall clock's rate; if that clock were moved to `mach_continuous_time`, the
//! noise would grow by the oscillator's error and an honest reboot could read as the same boot
//! for a launch about six days into the new boot. Every record would be past its window and its
//! retention by then, but the argument above would need to be made again.

use std::path::Path;

use kr_pairing::platform::{BootIdentity, PairingClock};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

/// The most the boot time may have moved, either way, for a launch to be the same boot.
const TOLERANCE_MS: i128 = 60_000;

/// What the comparison with the previous launch's counter allows for the sampling's error. Two
/// samples are each off by at most half of [`STEADY_MS`] and a few milliseconds of rounding, about
/// 104 ms between them; this is the whole of it with a margin, and it is far below any time a
/// machine is off.
const SAMPLING_ERROR_MS: i128 = 200;

/// How far apart a sample's two monotonic readings may be. The wall reading falls between them, so
/// the sample's error is half of this.
const STEADY_MS: u64 = 100;

/// How often a sample is taken again when it was not steady.
const SAMPLING_TRIES: u32 = 8;

/// What the record's format is called, so that a later format is not read as this one.
const RECORD_VERSION: u32 = 1;

/// Mixed into the identity's digest, so that it cannot be taken for any other digest of the bytes.
const IDENTITY_DOMAIN: &[u8] = b"kalareach phone boot v1";

/// This device's pairing clock, for the boot it is running in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceClock {
    boot: BootIdentity,
}

impl DeviceClock {
    /// The clock of the boot this process runs in, where the kernel names the boot.
    ///
    /// # Errors
    ///
    /// Returns the platform's failure when the boot cannot be identified, as it cannot on the
    /// Apple mobile systems, which use [`Self::resumed`].
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

    /// The clock of the boot this process runs in, on a system that names no boot to an
    /// application, by the record kept at `record`. See the module's documentation for what it
    /// guarantees.
    ///
    /// A record that cannot be read is a new boot. A launch whose clocks cannot be sampled
    /// steadily gets an identity for this process alone and leaves the record as it is.
    ///
    /// # Errors
    ///
    /// Returns why the record cannot be written, for a launch that made or renewed one.
    pub fn resumed(record: &Path) -> Result<Self> {
        resume_with(
            record,
            || steady_sample(&mut SystemClocks),
            || *kr_ipc::new_uuid().as_bytes(),
        )
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

/// One steady reading of both clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sample {
    /// The boot time as the wall clock dates it now: `wall - monotonic`.
    start_ms: i128,
    /// The monotonic counter.
    monotonic_ms: u64,
}

/// What a launch leaves for the next one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootRecord {
    version: u32,
    /// Random bytes naming the boot this record was made in.
    id: [u8; 16],
    /// The boot time at the launch that made `id`. It stays while `id` lives.
    start_ms: i64,
    /// The counter at the latest launch that kept `id`.
    seen_ms: u64,
}

crate::debug_as_name!(BootRecord);

/// The two clocks a sample reads, in the order a sample needs them.
trait Clocks {
    fn monotonic_ms(&mut self) -> u64;
    fn wall_ms(&mut self) -> u64;
}

struct SystemClocks;

impl Clocks for SystemClocks {
    fn monotonic_ms(&mut self) -> u64 {
        kr_ipc::clock::boot_elapsed_ms()
    }

    fn wall_ms(&mut self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

/// Reads the counter, the wall clock and the counter again, and takes the reading if the counter
/// did not go back and moved by no more than [`STEADY_MS`]: a process that was suspended between
/// the readings would otherwise date the boot wrongly by the length of the suspension. A sample
/// that is not steady is taken again, [`SAMPLING_TRIES`] times in all.
fn steady_sample(clocks: &mut impl Clocks) -> Option<Sample> {
    for _ in 0..SAMPLING_TRIES {
        let before = clocks.monotonic_ms();
        let wall = clocks.wall_ms();
        let after = clocks.monotonic_ms();
        if before <= after && after - before <= STEADY_MS {
            let middle = (i128::from(before) + i128::from(after)) / 2;
            return Some(Sample {
                start_ms: i128::from(wall) - middle,
                monotonic_ms: after,
            });
        }
    }
    None
}

/// Whether `now` is the boot `previous` was made in.
fn is_the_same_boot(previous: &BootRecord, now: &Sample) -> bool {
    let moved = now.start_ms - i128::from(previous.start_ms);
    previous.version == RECORD_VERSION
        && now.monotonic_ms >= previous.seen_ms
        && moved >= -TOLERANCE_MS
        && moved <= TOLERANCE_MS.min(i128::from(previous.seen_ms) - SAMPLING_ERROR_MS)
}

/// What the record becomes at a launch that sampled `now`: the same identity with the counter
/// renewed when it is the same boot, and a new identity with a new reference when it is not.
fn next_record(
    previous: Option<BootRecord>,
    now: &Sample,
    mint: impl FnOnce() -> [u8; 16],
) -> BootRecord {
    if let Some(previous) = previous.filter(|previous| is_the_same_boot(previous, now)) {
        return BootRecord {
            seen_ms: now.monotonic_ms,
            ..previous
        };
    }
    BootRecord {
        version: RECORD_VERSION,
        id: mint(),
        start_ms: i64::try_from(now.start_ms).unwrap_or(i64::MAX),
        seen_ms: now.monotonic_ms,
    }
}

fn clock_of(id: &[u8; 16]) -> DeviceClock {
    DeviceClock {
        boot: BootIdentity(kr_cbor::sha256(&[IDENTITY_DOMAIN, id].concat())),
    }
}

/// The record at `path`, or nothing when it is missing or is not a record this code wrote.
fn read_record(path: &Path) -> Option<BootRecord> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Writes `record` whole or not at all: to a file beside `path`, then renamed over it.
fn write_record(path: &Path, record: &BootRecord) -> Result<()> {
    let failed = |source: std::io::Error| {
        ClientError::Ipc(kr_ipc::IpcError::Io {
            operation: "write the boot record",
            path: path.to_path_buf(),
            source,
        })
    };
    if let Some(directory) = path.parent() {
        std::fs::create_dir_all(directory).map_err(failed)?;
    }
    let temporary = path.with_extension("new");
    let text = serde_json::to_vec(record).map_err(|error| failed(std::io::Error::other(error)))?;
    std::fs::write(&temporary, text).map_err(failed)?;
    std::fs::rename(&temporary, path).map_err(failed)
}

fn resume_with(
    path: &Path,
    sample: impl FnOnce() -> Option<Sample>,
    mint: impl FnOnce() -> [u8; 16],
) -> Result<DeviceClock> {
    let previous = read_record(path);
    let Some(now) = sample() else {
        // The clocks would not hold still. An identity nothing else knows is the safe answer: the
        // records written under it read as another boot's at the next launch.
        return Ok(clock_of(&mint()));
    };
    let record = next_record(previous.clone(), &now, mint);
    if previous.as_ref() != Some(&record) {
        write_record(path, &record)?;
    }
    Ok(clock_of(&record.id))
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

    fn sample(start_ms: i128, monotonic_ms: u64) -> Sample {
        Sample {
            start_ms,
            monotonic_ms,
        }
    }

    /// A record made at a launch that sampled boot time `START` at counter `SEEN`.
    const START: i64 = 1_764_000_000_000;
    const SEEN: u64 = 600_000;

    fn record() -> BootRecord {
        BootRecord {
            version: RECORD_VERSION,
            id: [7; 16],
            start_ms: START,
            seen_ms: SEEN,
        }
    }

    fn start_plus(moved_ms: i128) -> i128 {
        i128::from(START) + moved_ms
    }

    fn kept(now: &Sample) -> bool {
        next_record(Some(record()), now, || [9; 16]).id == [7; 16]
    }

    /// The first launch, a relaunch and a reboot, as the decision sees them. A reboot cannot be
    /// made on the machine a test runs on, so the decision is shown on the readings one makes.
    #[test]
    fn a_launch_keeps_the_identity_of_its_boot_and_a_new_boot_makes_one() {
        let first = next_record(None, &sample(start_plus(0), SEEN), || [7; 16]);
        assert_eq!(first, record(), "no record is a new boot");

        let later = next_record(
            Some(first),
            &sample(start_plus(40), SEEN + 3_600_000),
            || [9; 16],
        );
        assert_eq!(later.id, [7; 16], "a relaunch keeps the identity");
        assert_eq!(
            later.start_ms, START,
            "and the reference stays where it was"
        );
        assert_eq!(later.seen_ms, SEEN + 3_600_000, "while the counter moves");

        // The machine restarted: its counter is below the one the last launch saw.
        assert!(!kept(&sample(start_plus(0), SEEN - 1)));
        // It restarted and the wall clock is right: the boot time has moved on by the time the
        // last launch had been up and the time the machine was off.
        assert!(!kept(&sample(start_plus(600_000 + 8_000), 20_000)));
        // The new identity starts a new reference.
        let renewed = next_record(Some(record()), &sample(start_plus(900_000), 20_000), || {
            [9; 16]
        });
        assert_eq!((renewed.id, renewed.start_ms), ([9; 16], START + 900_000));
    }

    #[test]
    fn the_limits_of_the_same_boot_are_exact() {
        let at = |moved: i128, counter: u64| kept(&sample(start_plus(moved), counter));
        // The counter: equal is the same, below is not.
        assert!(at(0, SEEN));
        assert!(!at(0, SEEN - 1));
        // The boot time, either way, within a minute.
        assert!(at(-60_000, SEEN));
        assert!(!at(-60_001, SEEN));
        assert!(at(60_000, SEEN));
        assert!(!at(60_001, SEEN));
    }

    /// A reboot moves the boot time on by more than the counter the last launch saw, so a launch
    /// early in its boot is held to that counter, with the sampling's error allowed for.
    #[test]
    fn a_boot_time_that_moved_on_by_more_than_the_last_counter_is_another_boot() {
        let early = BootRecord {
            seen_ms: 30_000,
            ..record()
        };
        let at = |moved: i128| {
            next_record(
                Some(early.clone()),
                &sample(start_plus(moved), 30_000),
                || [9; 16],
            )
            .id == [7; 16]
        };
        assert!(at(29_800), "up to the counter less the sampling's error");
        assert!(!at(29_801));
        assert!(at(-5_000));
        // A record from a launch in the first moments of a boot allows no step forward at all.
        let just_up = BootRecord {
            seen_ms: 150,
            ..record()
        };
        assert!(next_record(Some(just_up), &sample(start_plus(0), 150), || [9; 16]).id != [7; 16]);
    }

    /// Wall-clock steps add up against the reference, which does not move with each launch.
    #[test]
    fn steps_that_are_small_one_by_one_and_large_together_make_a_new_boot() {
        let mut held = record();
        for (moved, same) in [(25_000, true), (50_000, true), (75_000, false)] {
            let next = next_record(
                Some(held.clone()),
                &sample(start_plus(moved), SEEN + 1_000_000),
                || [9; 16],
            );
            assert_eq!(next.id == [7; 16], same, "moved {moved}");
            held = next;
        }
        assert_eq!(held.id, [9; 16]);
    }

    #[test]
    fn a_wall_clock_at_zero_is_read_without_overflow() {
        let low = next_record(Some(record()), &sample(-3_600_000, 5_000), || [9; 16]);
        assert_eq!((low.id, low.start_ms), ([9; 16], -3_600_000));
        let again = next_record(Some(low.clone()), &sample(-3_600_000, 6_000), || [5; 16]);
        assert_eq!(again.id, [9; 16]);
    }

    /// Scripted readings: counter, wall, counter, as a sample asks for them.
    struct Scripted {
        monotonic: Vec<u64>,
        wall: Vec<u64>,
    }

    impl Clocks for Scripted {
        fn monotonic_ms(&mut self) -> u64 {
            self.monotonic.remove(0)
        }

        fn wall_ms(&mut self) -> u64 {
            self.wall.remove(0)
        }
    }

    #[test]
    fn a_sample_is_steady_or_it_is_taken_again() {
        // The first sample was held up for an hour between the readings; the second was not.
        let mut clocks = Scripted {
            monotonic: vec![1_000, 3_601_000, 5_000, 5_040],
            wall: vec![10_000_000, 10_010_000],
        };
        let taken = steady_sample(&mut clocks).expect("a steady sample");
        assert_eq!(taken.monotonic_ms, 5_040);
        assert_eq!(taken.start_ms, 10_010_000 - 5_020);

        // A counter that went back between the readings is not steady either.
        let mut clocks = Scripted {
            monotonic: vec![9_000, 8_999, 9_000, 9_100],
            wall: vec![1, 1],
        };
        assert_eq!(
            steady_sample(&mut clocks).map(|s| s.monotonic_ms),
            Some(9_100)
        );

        // The limit is exact.
        let mut clocks = Scripted {
            monotonic: vec![0, STEADY_MS],
            wall: vec![50],
        };
        assert!(steady_sample(&mut clocks).is_some());
        let mut clocks = Scripted {
            monotonic: vec![0, STEADY_MS + 1]
                .into_iter()
                .chain([0, STEADY_MS])
                .collect(),
            wall: vec![50, 50],
        };
        assert_eq!(
            steady_sample(&mut clocks).map(|s| s.monotonic_ms),
            Some(STEADY_MS)
        );
    }

    #[test]
    fn eight_samples_that_are_not_steady_give_none() {
        let mut clocks = Scripted {
            monotonic: (0..SAMPLING_TRIES)
                .flat_map(|n| [u64::from(n) * 10_000, u64::from(n) * 10_000 + 5_000])
                .collect(),
            wall: vec![0; SAMPLING_TRIES as usize],
        };
        assert_eq!(steady_sample(&mut clocks), None);
        assert!(
            clocks.monotonic.is_empty(),
            "every try was taken, and no more"
        );
    }

    fn digest_of(path: &Path, taken: Sample, mint: u8) -> DeviceClock {
        resume_with(path, || Some(taken), || [mint; 16]).expect("a clock")
    }

    /// The record on disk carries the identity from one launch to the next, and losing it is a new
    /// boot; a launch whose clocks will not hold still leaves it alone.
    #[test]
    fn the_record_carries_the_identity_across_launches() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("caches").join("pairing-boot");

        let first = digest_of(&path, sample(start_plus(0), SEEN), 1);
        let second = digest_of(&path, sample(start_plus(30), SEEN + 60_000), 2);
        assert_eq!(first.boot_identity(), second.boot_identity());
        let held = std::fs::read(&path).expect("the record");

        let unsteady = resume_with(&path, || None, || [3; 16]).expect("a clock");
        assert_ne!(unsteady.boot_identity(), first.boot_identity());
        assert_eq!(
            std::fs::read(&path).expect("the record"),
            held,
            "left as it was"
        );

        let again = digest_of(&path, sample(start_plus(35), SEEN + 120_000), 4);
        assert_eq!(again.boot_identity(), first.boot_identity());

        std::fs::remove_file(&path).expect("a purged cache");
        let purged = digest_of(&path, sample(start_plus(40), SEEN + 180_000), 5);
        assert_ne!(purged.boot_identity(), first.boot_identity());

        for broken in [
            &b""[..],
            b"{",
            br#"{"version":2,"id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"start_ms":1,"seen_ms":1}"#,
        ] {
            std::fs::write(&path, broken).expect("a broken record");
            let fresh = digest_of(&path, sample(start_plus(0), SEEN), 6);
            assert_eq!(fresh.boot_identity(), clock_of(&[6; 16]).boot_identity());
        }
    }

    #[test]
    fn a_record_that_cannot_be_written_is_an_error() {
        let directory = tempfile::tempdir().expect("a directory");
        let blocked = directory.path().join("file");
        std::fs::write(&blocked, b"").expect("a file");
        let result = resume_with(
            &blocked.join("pairing-boot"),
            || Some(sample(start_plus(0), SEEN)),
            || [1; 16],
        );
        assert!(matches!(result, Err(ClientError::Ipc(_))));
    }

    /// Through the real budget on disk: an entry made under a clock is continued by the next
    /// launch of the same boot, and is spent by the first launch of another.
    #[test]
    fn a_relaunch_continues_an_entry_and_a_reboot_spends_it() {
        use kr_pairing::PairingError;
        use kr_pairing::budget::DurableClientBudgetStore;
        use kr_pairing::client::charge_attempt;
        use kr_pairing::code::EnteredCode;
        use kr_protocol::pairing::RendezvousOrigin;

        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("pairing-boot");
        let secrets: std::sync::Arc<dyn kr_crypto::store::SecretStore> =
            std::sync::Arc::new(kr_crypto::store::MemoryStore::new());
        let store = DurableClientBudgetStore::open(
            directory.path().join("pairing-budget"),
            secrets,
            "client",
        )
        .expect("a budget");
        let origin = RendezvousOrigin::new("https://probe.invalid").expect("an origin");
        let code = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

        let launch = digest_of(&path, sample(start_plus(0), SEEN), 1);
        assert_eq!(
            charge_attempt(&store, &launch, &origin, &code).expect("a try"),
            4
        );

        let relaunch = digest_of(&path, sample(start_plus(20), SEEN + 90_000), 2);
        assert_eq!(
            charge_attempt(&store, &relaunch, &origin, &code).expect("a try"),
            3
        );

        // The machine restarted: the counter is below the last launch's.
        let rebooted = digest_of(&path, sample(start_plus(700_000), 25_000), 3);
        assert!(matches!(
            charge_attempt(&store, &rebooted, &origin, &code),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }
}
