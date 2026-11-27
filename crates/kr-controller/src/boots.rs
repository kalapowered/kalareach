//! The host's record of the boots it started in, and of where each device's access began.
//!
//! Both tables are in the registry's file, beside the grants, and each of the file's writers makes
//! them as it opens it.
//!
//! * `boots` holds one row for each boot this host has started in. A boot's row is made when the
//!   daemon first starts in that boot, so the order of the rows is the order of the boots: a later
//!   boot has a higher ordinal. The row keeps the highest reading of the host's order counter
//!   (`kr_ipc::clock::order_elapsed_ms`) that any writer of the file took in that boot, and whether
//!   the host can still tell the boot from another one.
//! * `grant_starts` holds one row for each grant: the host's reading of that counter at the
//!   decision that began the grant's access.
//!
//! # The boundary of a reading
//!
//! Every function here that compares a reading with a boot's high, or stores it, is called inside
//! an immediate transaction and reads the counter itself, after that transaction has taken the
//! file's write lock. A reading taken before the lock can be older than a high that another writer
//! stored while this one waited, and would spoil a healthy boot. The file has one write lock, and
//! the order in which writers hold it is the order of their commits, so a reading taken under it is
//! not below any high committed before it.

use std::sync::Arc;

use kr_ipc::clock::SharedClock;
use kr_protocol::ids::BootEpoch;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::attention::order::{BootState, StartPoint};
use crate::error::{ControllerError, Result};

/// The two tables, as one statement that makes whichever is missing.
///
/// The registry makes them when it writes version 21 and when it creates a file, and so do the
/// grant store and the device store, which write the same file on connections of their own and
/// record a start point in the transaction that records the grant or the device.
pub(crate) const BOOTS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS boots (
         ordinal    INTEGER PRIMARY KEY,
         boot_epoch BLOB NOT NULL UNIQUE,
         high_ms    INTEGER NOT NULL,
         spoiled    INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS grant_starts (
         grant_id   BLOB PRIMARY KEY,
         wall_ms    INTEGER NOT NULL,
         boot_epoch BLOB NOT NULL,
         boot_ms    INTEGER NOT NULL
     );";

/// The host's order counter and the boot it counts in: what a writer needs to record a reading in
/// its own transaction.
#[derive(Clone, Debug)]
pub struct BootClock {
    clock: Arc<dyn SharedClock>,
    epoch: BootEpoch,
}

impl BootClock {
    /// Makes the counter of `clock`, read in the boot `epoch`.
    #[must_use]
    pub fn new(clock: Arc<dyn SharedClock>, epoch: BootEpoch) -> Self {
        Self { clock, epoch }
    }

    /// Returns the clock.
    #[must_use]
    pub fn clock(&self) -> &dyn SharedClock {
        &*self.clock
    }

    /// Returns the boot.
    #[must_use]
    pub fn epoch(&self) -> BootEpoch {
        self.epoch
    }
}

/// Which of the two tests found that the host can no longer tell a boot from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoilTest {
    /// A reading of the order counter was below the highest the host had recorded in the boot, so
    /// the counter restarted inside it.
    ReadingBelowHigh,
    /// The identity of a boot recorded earlier came back in the boot the host runs in: a boot was
    /// recorded after the one that had it, so its row is not the latest.
    NotHighestOrdinal,
}

/// A boot that the host found it can no longer tell from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spoil {
    /// The boot.
    pub epoch: BootEpoch,
    /// The reading that found it.
    pub reading: u64,
    /// The highest reading recorded in the boot before this one.
    pub high: u64,
    /// The test that found it.
    pub test: SpoilTest,
}

impl Spoil {
    /// Returns the line the host writes to its log when the flag of the boot it runs in has been
    /// stored.
    ///
    /// The line says what is lost: the text stamped in the boot is withheld for good from a device
    /// whose access has a start point, and a device whose access began in the boot is served no
    /// text until the host next starts in a boot it can tell apart.
    #[must_use]
    pub fn line(&self) -> String {
        let cause = match self.test {
            SpoilTest::ReadingBelowHigh => format!(
                "its order counter read {} ms, below the {} ms recorded for it",
                self.reading, self.high
            ),
            SpoilTest::NotHighestOrdinal => format!(
                "the identity of an earlier boot came back: a boot was recorded after the one \
                 that had it (counter reading {} ms, recorded high {} ms)",
                self.reading, self.high
            ),
        };
        format!(
            "kr-controller: the host can no longer tell the boot it is running in, boot {}, from \
             another boot, because {cause}. Attention text stamped in this boot stays withheld \
             from every device whose access has a start point. A device whose access began in \
             this boot is served no attention text until the host next starts in a boot it can tell apart, and is never \
             served the text made before its new start.",
            self.epoch
        )
    }
}

/// What a call of [`Boots::observe`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    /// The reading of the order counter that the call took, under the write lock.
    pub reading: u64,
    /// What the record says of the boot after the call.
    pub state: BootState,
    /// Set only by the call that stored the flag.
    pub newly_spoiled: Option<Spoil>,
}

impl Observed {
    /// Writes the spoil's line to the host's log, when this call stored one.
    ///
    /// The caller calls it after the transaction it observed in has committed: a transaction that
    /// failed stored no flag, and a line for it would say what is not so.
    pub fn report(&self) {
        if let Some(spoil) = &self.newly_spoiled {
            eprintln!("{}", spoil.line());
        }
    }
}

/// The record of boots.
pub struct Boots;

impl Boots {
    /// Records a reading of the order counter in `epoch`'s row, makes the row when there is none,
    /// and says what the record then holds of the boot.
    ///
    /// A row that is new takes the next ordinal and the reading as its high. A row that is there is
    /// spoiled when the reading is below its high, or when its ordinal is not the highest: the identity
    /// of an earlier boot came back, since a boot was recorded after the one that had it. The high becomes the greater of the two
    /// readings, and a spoiled row stays spoiled.
    ///
    /// `connection` is an open transaction that holds the registry file's write lock. The counter
    /// is read here, after the lock, and never passed in.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when `connection` is in autocommit, which
    /// no transaction holds the lock for, and when a statement fails.
    pub fn observe(
        connection: &Connection,
        clock: &dyn SharedClock,
        epoch: BootEpoch,
    ) -> Result<Observed> {
        if connection.is_autocommit() {
            return Err(ControllerError::registry(
                "the boot record was written outside a write transaction",
            ));
        }
        let reading = clock.order_elapsed_ms();
        let key = epoch.get().to_be_bytes();
        let row: Option<(i64, i64, i64)> = connection
            .query_row(
                "SELECT ordinal, high_ms, spoiled FROM boots WHERE boot_epoch = ?1",
                params![key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let stored = i64::try_from(reading).unwrap_or(i64::MAX);
        let Some((ordinal, high, spoiled)) = row else {
            connection
                .execute(
                    "INSERT INTO boots (boot_epoch, high_ms, spoiled) VALUES (?1, ?2, 0)",
                    params![key.as_slice(), stored],
                )
                .map_err(ControllerError::registry)?;
            return Ok(Observed {
                reading,
                state: BootState::Known(ordinal_of(connection.last_insert_rowid())),
                newly_spoiled: None,
            });
        };
        let highest: i64 = connection
            .query_row("SELECT MAX(ordinal) FROM boots", [], |row| row.get(0))
            .map_err(ControllerError::registry)?;
        let went_back = stored < high;
        let not_the_latest = ordinal != highest;
        let was_spoiled = spoiled != 0;
        let is_spoiled = was_spoiled || went_back || not_the_latest;
        connection
            .execute(
                "UPDATE boots SET high_ms = ?2, spoiled = ?3 WHERE ordinal = ?1",
                params![ordinal, high.max(stored), i64::from(is_spoiled)],
            )
            .map_err(ControllerError::registry)?;
        let newly_spoiled = (is_spoiled && !was_spoiled).then(|| Spoil {
            epoch,
            reading,
            high: u64::try_from(high).unwrap_or_default(),
            test: if went_back {
                SpoilTest::ReadingBelowHigh
            } else {
                SpoilTest::NotHighestOrdinal
            },
        });
        Ok(Observed {
            reading,
            state: if is_spoiled {
                BootState::Spoiled
            } else {
                BootState::Known(ordinal_of(ordinal))
            },
            newly_spoiled,
        })
    }

    /// Returns what the record says of `epoch`, by one indexed read.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn state(connection: &Connection, epoch: BootEpoch) -> Result<BootState> {
        let row: Option<(i64, i64)> = connection
            .query_row(
                "SELECT ordinal, spoiled FROM boots WHERE boot_epoch = ?1",
                params![epoch.get().to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        Ok(match row {
            None => BootState::Unknown,
            Some((_, spoiled)) if spoiled != 0 => BootState::Spoiled,
            Some((ordinal, _)) => BootState::Known(ordinal_of(ordinal)),
        })
    }
}

fn ordinal_of(ordinal: i64) -> u64 {
    u64::try_from(ordinal).unwrap_or_default()
}

impl StartPoint {
    /// Reads a start point for the decision that began a grant's access, and records the reading.
    ///
    /// `decision_wall_ms` is the wall reading the caller stored as the decision's moment, taken
    /// before this call. The counter is read inside [`Boots::observe`], in `connection`'s own
    /// transaction, after both the lock and that wall reading, and it is the one reading that is
    /// both the point and the sample that raises the boot's high. There is no point in a boot the
    /// host can no longer tell from another: the access is then left with none until the host next
    /// starts in a boot it can tell apart.
    ///
    /// A reading of zero gives no point either. A daemon that records a grant is never in the first
    /// millisecond of its boot, so a zero is a counter that failed to answer, and a point at zero
    /// would be before every text the boot made: the text made before the decision would be
    /// served. The sample is still recorded, and the access has no point: its text is withheld
    /// until the host next starts in a boot whose counter answers.
    ///
    /// Call it after the caller's refusal checks, as the last statement before the point's write,
    /// so that what can fail after it is the write and the commit. The caller writes the point with
    /// [`StartPoint::write`] and reports the returned [`Observed`] after its transaction commits.
    ///
    /// # Errors
    ///
    /// As [`Boots::observe`].
    pub fn read(
        decision_wall_ms: u64,
        connection: &Connection,
        boot: &BootClock,
    ) -> Result<(Observed, Option<Self>)> {
        let observed = Boots::observe(connection, boot.clock(), boot.epoch())?;
        let point = (matches!(observed.state, BootState::Known(_)) && observed.reading > 0)
            .then_some(Self {
                wall_ms: decision_wall_ms,
                boot_epoch: boot.epoch(),
                boot_ms: observed.reading,
            });
        Ok((observed, point))
    }

    /// Reads the start point of the decision that began the access of the grant `grant_id` and
    /// writes it, in `connection`'s own transaction.
    ///
    /// This is [`StartPoint::read`] and [`StartPoint::write`] together, for a caller whose last
    /// statement before the point is its own refusal check. The returned [`Observed`] is reported
    /// by the caller once its transaction has committed.
    ///
    /// # Errors
    ///
    /// As [`StartPoint::read`] and [`StartPoint::write`].
    pub fn take(
        decision_wall_ms: u64,
        connection: &Connection,
        boot: &BootClock,
        grant_id: &[u8],
    ) -> Result<Observed> {
        let (observed, point) = Self::read(decision_wall_ms, connection, boot)?;
        if let Some(point) = point {
            point.write(connection, grant_id)?;
        }
        Ok(observed)
    }

    /// Records this point as the start of the grant `grant_id`, unless the grant has one.
    ///
    /// The first point of a grant stays: nothing that happens later changes where its access began.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn write(&self, connection: &Connection, grant_id: &[u8]) -> Result<()> {
        connection
            .execute(
                "INSERT OR IGNORE INTO grant_starts (grant_id, wall_ms, boot_epoch, boot_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    grant_id,
                    i64::try_from(self.wall_ms).unwrap_or(i64::MAX),
                    self.boot_epoch.get().to_be_bytes().as_slice(),
                    i64::try_from(self.boot_ms).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }
}

/// What the cases of this record and of its writers share.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use kr_ipc::clock::SharedClock;
    use rusqlite::{Connection, params};

    /// A counter a case sets by hand, and counts the readings of. A real one never goes down; this
    /// one can, to show what a counter that restarted inside one boot looks like.
    #[derive(Debug, Default)]
    pub(crate) struct SetClock {
        value: AtomicU64,
        reads: AtomicU64,
    }

    impl SetClock {
        pub(crate) fn at(ms: u64) -> Arc<Self> {
            Arc::new(Self {
                value: AtomicU64::new(ms),
                reads: AtomicU64::new(0),
            })
        }

        pub(crate) fn set(&self, ms: u64) {
            self.value.store(ms, Ordering::SeqCst);
        }

        /// How many times the order counter has been read.
        pub(crate) fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl SharedClock for SetClock {
        fn boot_elapsed_ms(&self) -> u64 {
            self.value.load(Ordering::SeqCst)
        }

        fn order_elapsed_ms(&self) -> u64 {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.value.load(Ordering::SeqCst)
        }
    }

    /// What a delayed writer's case reads back: the readings of the counter taken while another
    /// writer held the lock, and the boot's row afterwards. The case asserts them in its own body.
    #[derive(Debug)]
    pub(crate) struct Delayed {
        /// Whether the site ended without waiting for the lock the other writer held.
        pub(crate) went_by_the_lock: bool,
        /// Whether the site panicked.
        pub(crate) site_failed: bool,
        /// How many times the counter was read while the other writer held the lock.
        pub(crate) reads_while_held: u64,
        /// The boot's high after the site committed.
        pub(crate) high: i64,
        /// Whether the boot was spoiled.
        pub(crate) spoiled: i64,
    }

    /// The delayed writer of the boundary of a reading. Another connection holds the file's write
    /// lock; `site` starts on a thread of its own and has to wait for it; while it waits the counter
    /// must not have been read. The holder then raises the boot's high, as a writer that took the
    /// lock first would, and lets go. A site that read its sample before it began its transaction
    /// would read the old counter and spoil a healthy boot.
    ///
    /// `waiting` is the counter that the busy handler `count_the_wait` of the case adds to, which
    /// is how the case knows the site is waiting for the lock and not still on its way to it.
    pub(crate) fn a_site_reads_after_the_lock(
        path: &std::path::Path,
        waiting: &'static AtomicU64,
        clock: &Arc<SetClock>,
        epoch: u64,
        site: impl FnOnce() + Send,
    ) -> Delayed {
        let holder = Connection::open(path).expect("the holder opens");
        holder
            .execute(
                "INSERT INTO boots (boot_epoch, high_ms, spoiled) VALUES (?1, 50, 0)",
                params![epoch.to_be_bytes().as_slice()],
            )
            .expect("the boot is recorded");
        clock.set(100);
        holder
            .execute_batch("BEGIN IMMEDIATE")
            .expect("the holder takes the write lock");
        let (went_by_the_lock, site_failed, reads_while_held) = std::thread::scope(|scope| {
            let site = scope.spawn(site);
            let mut went_by_the_lock = false;
            while waiting.load(Ordering::SeqCst) == 0 {
                if site.is_finished() {
                    went_by_the_lock = true;
                    break;
                }
                std::thread::yield_now();
            }
            // Taken while the lock is held and asserted by the case once it is let go, so that a
            // site that went on without waiting cannot leave the case waiting for it.
            let reads_while_held = clock.reads();
            holder
                .execute(
                    "UPDATE boots SET high_ms = 101 WHERE boot_epoch = ?1",
                    params![epoch.to_be_bytes().as_slice()],
                )
                .expect("the other writer's high");
            clock.set(101);
            holder.execute_batch("COMMIT").expect("the holder commits");
            let site_failed = site.join().is_err();
            (went_by_the_lock, site_failed, reads_while_held)
        });
        let (high, spoiled): (i64, i64) = holder
            .query_row(
                "SELECT high_ms, spoiled FROM boots WHERE boot_epoch = ?1",
                params![epoch.to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the row");
        Delayed {
            went_by_the_lock,
            site_failed,
            reads_while_held,
            high,
            spoiled,
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::BootEpoch;

    use super::testing::SetClock;
    use super::*;
    use crate::attention::order::{BootOrder, Stamp, Withheld, admit};

    /// A registry file with the two tables, on a connection of its own.
    struct File {
        _directory: tempfile::TempDir,
        path: std::path::PathBuf,
        connection: Connection,
    }

    impl File {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a directory");
            let path = directory.path().join("registry.db");
            let connection = Connection::open(&path).expect("a database");
            connection
                .execute_batch(BOOTS_SCHEMA)
                .expect("the two tables");
            Self {
                _directory: directory,
                path,
                connection,
            }
        }

        /// Runs `body` in an immediate transaction and commits it, as a writer of the file does.
        fn immediately<T>(&mut self, body: impl FnOnce(&Connection) -> T) -> T {
            let transaction = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("the write lock");
            let value = body(&transaction);
            transaction.commit().expect("the commit");
            value
        }

        /// Observes `epoch` in a transaction of its own and commits it.
        fn observe(&mut self, clock: &SetClock, epoch: u64) -> Observed {
            self.immediately(|transaction| {
                Boots::observe(transaction, clock, BootEpoch::new(epoch)).expect("an observation")
            })
        }

        /// The row of `epoch`: ordinal, high and the spoiled flag.
        fn row(&self, epoch: u64) -> Option<(i64, i64, i64)> {
            self.connection
                .query_row(
                    "SELECT ordinal, high_ms, spoiled FROM boots WHERE boot_epoch = ?1",
                    params![epoch.to_be_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .expect("a read")
        }
    }

    /// The record of boots as the gate reads it.
    struct Stored<'a>(&'a Connection);

    impl BootOrder for Stored<'_> {
        fn state(&self, epoch: BootEpoch) -> BootState {
            Boots::state(self.0, epoch).unwrap_or(BootState::Unknown)
        }
    }

    fn stamp(epoch: u64, boot_ms: u64) -> Stamp {
        Stamp {
            boot_epoch: BootEpoch::new(epoch),
            boot_ms,
        }
    }

    fn point(epoch: u64, boot_ms: u64) -> StartPoint {
        StartPoint {
            wall_ms: 1,
            boot_epoch: BootEpoch::new(epoch),
            boot_ms,
        }
    }

    /// A boot's row is made at its first observation with the next ordinal and the reading
    /// as its high; a second observation in the same boot makes no row, keeps the ordinal and
    /// raises the high; a new boot takes the next ordinal.
    #[test]
    fn a_boot_takes_the_next_ordinal_and_a_second_observation_only_raises_its_high() {
        let mut file = File::new();
        let clock = SetClock::at(100);
        let first = file.observe(&clock, 7);
        assert_eq!(first.state, BootState::Known(1));
        assert_eq!(first.reading, 100);
        assert_eq!(file.row(7), Some((1, 100, 0)));
        clock.set(250);
        let again = file.observe(&clock, 7);
        assert_eq!(again.state, BootState::Known(1), "the ordinal is kept");
        assert_eq!(file.row(7), Some((1, 250, 0)), "the high is raised");
        clock.set(5);
        let later = file.observe(&clock, 9);
        assert_eq!(
            later.state,
            BootState::Known(2),
            "a new boot is the next ordinal, whatever its counter reads"
        );
        assert_eq!(file.row(9), Some((2, 5, 0)));
        assert_eq!(
            file.connection
                .query_row("SELECT COUNT(*) FROM boots", [], |row| row.get::<_, i64>(0))
                .expect("a count"),
            2
        );
        assert_eq!(
            again.newly_spoiled, None,
            "an observation that finds nothing sets no flag"
        );
    }

    /// A reading below the boot's high spoils it, the call that stores the flag
    /// says so once, the boot stays spoiled after a reading above the high, and the high is never
    /// lowered.
    #[test]
    fn a_reading_below_the_high_spoils_the_boot_once_and_it_stays_spoiled() {
        let mut file = File::new();
        let clock = SetClock::at(50_000);
        file.observe(&clock, 7);
        clock.set(1_000);
        let found = file.observe(&clock, 7);
        assert_eq!(found.state, BootState::Spoiled);
        assert_eq!(
            found.newly_spoiled,
            Some(Spoil {
                epoch: BootEpoch::new(7),
                reading: 1_000,
                high: 50_000,
                test: SpoilTest::ReadingBelowHigh,
            })
        );
        assert_eq!(file.row(7), Some((1, 50_000, 1)), "the high is not lowered");
        clock.set(90_000);
        let after = file.observe(&clock, 7);
        assert_eq!(after.state, BootState::Spoiled, "a spoiled boot stays so");
        assert_eq!(after.newly_spoiled, None, "the flag was stored once");
        assert_eq!(file.row(7), Some((1, 90_000, 1)));
    }

    /// A boot that is not the latest one recorded is spoiled at its next observation,
    /// whatever its reading, so the test does not wait for a restart.
    #[test]
    fn a_boot_that_is_not_the_latest_recorded_is_spoiled_at_its_next_observation() {
        let mut file = File::new();
        let clock = SetClock::at(100);
        file.observe(&clock, 7);
        clock.set(5);
        file.observe(&clock, 9);
        // The first boot's identity comes back, with a counter above its own high.
        clock.set(100_000);
        let found = file.observe(&clock, 7);
        assert_eq!(found.state, BootState::Spoiled);
        assert_eq!(
            found.newly_spoiled.map(|spoil| spoil.test),
            Some(SpoilTest::NotHighestOrdinal)
        );
        // The latest boot is not touched by it.
        clock.set(200_000);
        assert_eq!(file.observe(&clock, 9).state, BootState::Known(2));
    }

    /// A transaction that fails after an observation stores nothing, neither the flag nor
    /// the raised high. The next committed call finds an ordinal-test spoil again, because it reads
    /// committed rows; it finds a high-test spoil only when its own reading is below the high, and a
    /// reading at or above it finds nothing. That loss is a known limit of the record, and this case
    /// shows it.
    #[test]
    fn a_failed_transaction_stores_nothing_and_a_spoil_found_in_it_is_found_again_only_by_its_test()
    {
        let mut file = File::new();
        let clock = SetClock::at(60_000);
        file.observe(&clock, 7);
        // A reading below the high, in a transaction that does not commit.
        clock.set(1_000);
        {
            let transaction = file
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("the write lock");
            let found = Boots::observe(&transaction, &*clock, BootEpoch::new(7)).expect("a call");
            assert_eq!(found.state, BootState::Spoiled);
            drop(transaction);
        }
        assert_eq!(
            file.row(7),
            Some((1, 60_000, 0)),
            "no flag and no new high were stored"
        );
        // The next call that reads at or above the high finds nothing: the spoil is lost.
        clock.set(70_000);
        let next = file.observe(&clock, 7);
        assert_eq!(next.state, BootState::Known(1));
        assert_eq!(next.newly_spoiled, None);
        // A second boot is recorded, then the first boot's identity is seen in a transaction that
        // fails: the next committed call meets the same rows and finds it again.
        clock.set(5);
        file.observe(&clock, 9);
        clock.set(80_000);
        {
            let transaction = file
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("the write lock");
            let found = Boots::observe(&transaction, &*clock, BootEpoch::new(7)).expect("a call");
            assert_eq!(found.state, BootState::Spoiled);
            drop(transaction);
        }
        assert_eq!(file.row(7).map(|(_, _, spoiled)| spoiled), Some(0));
        let again = file.observe(&clock, 7);
        assert_eq!(again.state, BootState::Spoiled);
        assert_eq!(
            again.newly_spoiled.map(|spoil| spoil.test),
            Some(SpoilTest::NotHighestOrdinal)
        );
    }

    /// A call on a connection in autocommit is refused, and it writes nothing: no
    /// transaction holds the file's write lock for it, so its reading could be older than a high
    /// another writer stored.
    #[test]
    fn an_observation_outside_a_transaction_is_refused_and_writes_nothing() {
        let file = File::new();
        let clock = SetClock::at(10);
        let refused = Boots::observe(&file.connection, &*clock, BootEpoch::new(7));
        assert!(refused.is_err(), "a call in autocommit is refused");
        assert_eq!(file.row(7), None, "and nothing was written");
    }

    /// Two boots that share an epoch. The later boot's first reading is below the earlier
    /// one's high, so the epoch is spoiled; every text stamped in it and every point in it withholds,
    /// and so does a text stamped `(E, 100000)` against a later point `(E, 1000)`.
    #[test]
    fn a_repeated_boot_identity_with_a_counter_that_went_back_is_spoiled_and_withholds() {
        let mut file = File::new();
        let clock = SetClock::at(1);
        file.observe(&clock, 4);
        clock.set(100_000);
        file.observe(&clock, 7);
        // The later boot repeats epoch 7 and its counter restarts.
        clock.set(1_000);
        let found = file.observe(&clock, 7);
        assert_eq!(found.state, BootState::Spoiled);
        let record = Stored(&file.connection);
        for (name, outcome) in [
            (
                "a text stamped above the later point, in the same epoch",
                admit(1, Some(&point(7, 1_000)), Some(&stamp(7, 100_000)), &record),
            ),
            (
                "a text stamped in the epoch, against a point of the earlier boot",
                admit(1, Some(&point(4, 1)), Some(&stamp(7, 100_001)), &record),
            ),
            (
                "a text of a known boot, against a point in the epoch",
                admit(1, Some(&point(7, 1_000)), Some(&stamp(4, 5)), &record),
            ),
        ] {
            assert_eq!(outcome, Err(Withheld::NoStartPoint), "{name}");
        }
        // The control: the boots that are still told apart are judged by the order rule.
        assert_eq!(
            admit(1, Some(&point(4, 1)), Some(&stamp(4, 2)), &record),
            Ok(())
        );
    }

    /// The undetected case, run and shown: a later boot that repeats an epoch and reads at
    /// or above the earlier boot's last recorded high is not found, so a text the earlier boot
    /// stamped above the later point is served although it was made before the access began. This
    /// is a known limit of the record, and it is a tested fact and not a hope.
    #[test]
    fn a_repeated_boot_identity_whose_counter_reads_above_the_high_is_not_found_and_is_served() {
        let mut file = File::new();
        let clock = SetClock::at(20_000);
        // The earlier boot's daemon records 20,000 and takes no point; its workers keep stamping.
        file.observe(&clock, 7);
        // The later boot repeats the epoch and reads 30,000, above that high: nothing is found.
        clock.set(30_000);
        let later = file.observe(&clock, 7);
        assert_eq!(later.state, BootState::Known(1));
        assert_eq!(later.newly_spoiled, None);
        // A device pairs at 40,000, and the earlier boot's text stamped at 172,800,000 is served.
        clock.set(40_000);
        let paired = file.observe(&clock, 7);
        let record = Stored(&file.connection);
        assert_eq!(
            admit(
                1,
                Some(&point(7, paired.reading)),
                Some(&stamp(7, 172_800_000)),
                &record
            ),
            Ok(()),
            "the limit: this host cannot tell the two boots apart"
        );
    }

    /// The restore: the registry file is replaced by an earlier copy. The boots the copy
    /// lacks are unknown and their stamps withhold, the next boot takes the next ordinal of the
    /// copy, and the copy holds an unspoiled row of an epoch that the file it replaced had spoiled.
    #[test]
    fn a_restored_copy_leaves_the_lost_boots_unknown_and_brings_back_an_unspoiled_row() {
        let mut file = File::new();
        let clock = SetClock::at(100);
        file.observe(&clock, 7);
        // The copy: the file as it stood with one boot recorded.
        file.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .ok();
        let copy = file.path.with_extension("copy");
        file.connection
            .execute("VACUUM INTO ?1", params![copy.to_str().expect("a path")])
            .expect("the copy");
        // Then the file goes on: a second boot, and the first one's epoch is spoiled.
        clock.set(5);
        file.observe(&clock, 9);
        clock.set(500);
        let spoiled = file.observe(&clock, 7);
        assert_eq!(spoiled.state, BootState::Spoiled);
        // The restore.
        let mut restored = Connection::open(&copy).expect("the copy opens");
        let record = Stored(&restored);
        assert_eq!(
            admit(1, Some(&point(7, 1)), Some(&stamp(9, 99_999)), &record),
            Err(Withheld::NoStartPoint),
            "a stamp of a boot the copy lost is withheld"
        );
        assert_eq!(
            Boots::state(&restored, BootEpoch::new(7)).expect("a read"),
            BootState::Known(1),
            "the copy's row of the epoch is not spoiled"
        );
        let transaction = restored
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("the write lock");
        clock.set(10);
        let next = Boots::observe(&transaction, &*clock, BootEpoch::new(11)).expect("a call");
        assert_eq!(
            next.state,
            BootState::Known(2),
            "the next boot takes the next ordinal of the restored record"
        );
    }

    /// The record of boots survives `forget_other_boots`, which forgets the clock floors
    /// of the boots that ended. A text of the later boot is admitted against a point of the
    /// earlier one, which needs both boots to be known after the call; a record that forgot the
    /// earlier boot would withhold it.
    #[test]
    fn forgetting_the_other_boots_leaves_the_record_of_boots_in_place() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.db");
        let mut registry = crate::registry::Registry::open(
            &path,
            kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16])),
        )
        .expect("a registry");
        let clock = SetClock::at(10);
        for epoch in [4, 9] {
            registry
                .record_boot(&BootClock::new(
                    Arc::clone(&clock) as _,
                    BootEpoch::new(epoch),
                ))
                .expect("a boot is recorded");
        }
        registry
            .forget_other_boots(BootEpoch::new(9))
            .expect("the floors of the ended boot are forgotten");
        let connection = Connection::open(&path).expect("the registry opens");
        let record = Stored(&connection);
        assert_eq!(record.state(BootEpoch::new(4)), BootState::Known(1));
        assert_eq!(
            admit(1, Some(&point(4, 100)), Some(&stamp(9, 0)), &record),
            Ok(()),
            "a text of the later boot is after a point of the earlier one, whatever the counters read"
        );
    }

    /// The line names the boot, the reading and the high, says which test found it, and
    /// says what is lost for the texts and what for the devices.
    #[test]
    fn the_line_names_the_boot_the_reading_the_high_and_the_test_that_found_it() {
        let by_reading = Spoil {
            epoch: BootEpoch::new(123_456),
            reading: 1_000,
            high: 50_000,
            test: SpoilTest::ReadingBelowHigh,
        }
        .line();
        let by_order = Spoil {
            epoch: BootEpoch::new(123_456),
            reading: 90_000,
            high: 50_000,
            test: SpoilTest::NotHighestOrdinal,
        }
        .line();
        for line in [&by_reading, &by_order] {
            assert!(line.starts_with("kr-controller: "), "{line}");
            assert!(line.contains("123456"), "the boot: {line}");
            assert!(
                line.contains("the boot it is running in"),
                "the boot is the one the daemon runs in: {line}"
            );
            assert!(line.contains("50000 ms"), "the high: {line}");
            assert!(
                line.contains("stays withheld from every device whose access has a start point"),
                "what the texts lose: {line}"
            );
            assert!(
                line.contains("until the host next starts in a boot it can tell apart"),
                "what the devices lose: {line}"
            );
        }
        assert!(
            by_reading.contains("order counter read 1000 ms, below the 50000 ms"),
            "{by_reading}"
        );
        assert!(
            by_order.contains("the identity of an earlier boot came back")
                && by_order.contains("a boot was recorded after the one that had it")
                && by_order.contains("90000 ms"),
            "{by_order}"
        );
    }
}
