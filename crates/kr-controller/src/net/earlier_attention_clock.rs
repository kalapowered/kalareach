//! What an earlier build's attention store recorded of the wall clock, taken into this host's one
//! record of it.
//!
//! That store kept a clock record of its own, `attention-time.cbor` beside its database: a mark,
//! the trust it had, and whether the owner confirmed the clock. The host now has one record for
//! every reader ([`super::clock_trust::ClockTrust`]), so a daemon started over an earlier file takes
//! the file in once, and removes it.
//!
//! Remove this module, its declaration in `net/mod.rs`, its call at start and the record's
//! `attention_time_retired` column once no installation can be upgraded in place from a build that
//! wrote the file.

use std::path::Path;

use kr_protocol::identity::BootIdentity;
use rusqlite::{OptionalExtension as _, params};

use super::devices::DeviceDirectory;
use crate::error::{ControllerError, Result};

/// What an earlier build's attention store recorded of the wall clock, as this host takes it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlierClock {
    /// The furthest wall reading that store had proved, with the boot-clock reading it was proved
    /// at in the boot this host runs in.
    pub proven: Option<(u64, u64)>,
    /// That store had found the wall clock going backwards, or losing the platform's evidence
    /// after it was trusted.
    pub distrust: bool,
    /// That store had never trusted the wall clock, or its record cannot be read.
    pub forgetting_hold: bool,
    /// The owner had confirmed the clock to that store.
    pub confirmed: bool,
}

impl DeviceDirectory {
    /// Takes what an earlier build's attention store recorded of the wall clock into this host's
    /// one record of it, and records that it has.
    ///
    /// One transaction, so a start that stops part-way adopts nothing and the next start adopts it
    /// all. Only ever stricter: the mark moves forward, an anchor already held is kept, a distrust
    /// or a hold already held stays, and a confirmation is taken only where nothing is in doubt.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written.
    pub fn adopt_earlier_clock(
        &self,
        earlier: &EarlierClock,
        boot: &BootIdentity,
        now_ms: u64,
    ) -> Result<()> {
        let stored = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        self.transaction(|transaction| {
            type Row = (i64, Option<i64>, bool, Option<i64>, Option<i64>);
            let row: Option<Row> = transaction
                .query_row(
                    "SELECT observed_ms, untrusted_at_ms, anchor_wall_ms IS NOT NULL,
                            confirmed_at_ms, forgetting_hold_at_ms
                     FROM network_clock WHERE id = 0",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(ControllerError::registry)?;
            let held = row.is_some();
            let (observed, untrusted, anchored, confirmed, forgetting) =
                row.unwrap_or((stored(now_ms), None, false, None, None));
            let observed = earlier
                .proven
                .map_or(observed, |(wall_ms, _)| observed.max(stored(wall_ms)));
            let untrusted = untrusted.or(earlier.distrust.then_some(stored(now_ms)));
            let forgetting = forgetting.or(earlier.forgetting_hold.then_some(stored(now_ms)));
            let confirmed = if untrusted.is_some() {
                None
            } else {
                confirmed.or(earlier.confirmed.then_some(stored(now_ms)))
            };
            let sql = if held {
                "UPDATE network_clock SET observed_ms = ?1, untrusted_at_ms = ?2,
                     confirmed_at_ms = ?3, forgetting_hold_at_ms = ?4, attention_time_retired = 1
                 WHERE id = 0"
            } else {
                "INSERT INTO network_clock (id, observed_ms, untrusted_at_ms, confirmed_at_ms,
                     forgetting_hold_at_ms, attention_time_retired)
                 VALUES (0, ?1, ?2, ?3, ?4, 1)"
            };
            transaction
                .execute(sql, params![observed, untrusted, confirmed, forgetting])
                .map_err(ControllerError::registry)?;
            if let (false, Some((wall_ms, boot_ms))) = (anchored, earlier.proven) {
                transaction
                    .execute(
                        "UPDATE network_clock SET anchor_wall_ms = ?1, anchor_boot_ms = ?2,
                             anchor_boot_value = ?3 WHERE id = 0",
                        params![stored(wall_ms), stored(boot_ms), boot.value.as_slice()],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Ok(())
        })
    }
}

/// Takes what an earlier build's attention store recorded of the wall clock into this host's one
/// record of it, once, at start, and removes the file.
///
/// It is adopted whole in one transaction, before the file is removed, and the record's own flag says it has been, so a start that stops
/// between the two removes the file without adopting it again, and a start that stops before the
/// transaction adopts it afresh. An earlier file's trust is taken conservatively, because it
/// cannot say whether only the platform's time service failed it: when its checkpoint had been
/// trusted the clock is distrusted, and when it never had been every forgetting is held. Neither
/// is lifted by the platform qualifying; only the owner establishing the clock lifts them. A file
/// that cannot be read holds every forgetting too, since nothing says what it had found.
///
/// # Errors
///
/// Returns an error when the record cannot be read or written. A host that cannot say what an
/// earlier build found does not start deciding clock-dependent expiry.
pub(crate) fn adopt_earlier_attention_clock(
    devices: &DeviceDirectory,
    state_dir: &Path,
    boot: &BootIdentity,
    boot_clock: &dyn kr_ipc::clock::SharedClock,
    now_ms: u64,
) -> Result<()> {
    let file = state_dir.join("attention-time.cbor");
    let partial = file.with_extension("cbor.partial");
    let remove = || {
        for path in [&file, &partial] {
            if let Err(error) = std::fs::remove_file(path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!(
                    "kr-controller: could not remove {}, which this build no longer reads: {error}",
                    path.display()
                );
            }
        }
    };
    if devices.clock_record()?.attention_time_retired {
        // An older build may have written the file again after this host adopted it. It is not
        // read: what it holds is older than the record.
        remove();
        return Ok(());
    }
    let earlier = match std::fs::read(&file) {
        Ok(bytes) => earlier_clock(&bytes, boot, boot_clock),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => EarlierClock {
            proven: None,
            distrust: false,
            forgetting_hold: false,
            confirmed: false,
        },
        Err(_) => EarlierClock {
            proven: None,
            distrust: false,
            forgetting_hold: true,
            confirmed: false,
        },
    };
    devices.adopt_earlier_clock(&earlier, boot, now_ms)?;
    remove();
    Ok(())
}

/// What an earlier build's record says, as this host takes it.
fn earlier_clock(
    bytes: &[u8],
    boot: &BootIdentity,
    boot_clock: &dyn kr_ipc::clock::SharedClock,
) -> EarlierClock {
    use kr_protocol::action::{HostTimeState, WallClockTrust};

    let Ok(state) =
        kr_cbor::from_canonical_slice::<HostTimeState>(bytes, &kr_cbor::Limits::DEFAULT)
    else {
        return EarlierClock {
            proven: None,
            distrust: false,
            forgetting_hold: true,
            confirmed: false,
        };
    };
    // The continuous reading is the boot clock's, in the boot the record names; in another boot it
    // is not comparable, and the proven wall reading starts from now on this boot's clock.
    let proven = state.proven.0.as_ref().map(|proven| {
        let boot_ms = if proven.boot_identity == *boot {
            proven.continuous_ms.get()
        } else {
            boot_clock.boot_elapsed_ms()
        };
        (proven.wall_clock_ms.get(), boot_ms)
    });
    let unresolved = state.trust == WallClockTrust::Unresolved;
    let was_trusted = state
        .checkpoint
        .0
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.trust == WallClockTrust::Trusted);
    EarlierClock {
        proven,
        distrust: unresolved && was_trusted,
        forgetting_hold: unresolved && !was_trusted,
        confirmed: state.owner_confirmed && !unresolved,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use kr_ipc::clock::ManualSharedClock;
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::Bytes;
    use kr_transport::clock::ManualClock;

    use super::super::clock_trust::ClockTrust;
    use super::*;
    use crate::grants::policy::UtcFloor;

    /// The wall clock every fixture was written at, and the boot it was written in.
    const WALL: u64 = 1_700_000_000_000;
    /// What the boot clock read when the fixtures were written.
    const BOOT_CLOCK_MS: u64 = 3_600_000;

    /// What an earlier build's attention store wrote, by its own writer: a time contract over
    /// clocks moved by hand, and its state encoded as it encoded it.
    const CURRENT: &[u8] =
        include_bytes!("../../tests/fixtures/earlier-attention-clock/trusted_and_current.cbor");
    const ROLLED_BACK: &[u8] =
        include_bytes!("../../tests/fixtures/earlier-attention-clock/rolled_back.cbor");
    const NEVER_TRUSTED: &[u8] =
        include_bytes!("../../tests/fixtures/earlier-attention-clock/never_trusted.cbor");
    const CONFIRMED: &[u8] =
        include_bytes!("../../tests/fixtures/earlier-attention-clock/owner_confirmed.cbor");

    fn earlier_boot() -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::MacosBootSessionUuid,
            value: Bytes::new(vec![0x11; 16]),
        }
    }

    /// A host started over an earlier build's state directory and device store.
    struct Host {
        temp: kr_ipc::testing::TempHost,
        wall: Arc<AtomicU64>,
        boot_clock: ManualSharedClock,
    }

    impl Host {
        /// In the boot the fixtures were written in, `after` since they were.
        fn in_the_boot_of_the_fixtures(after: Duration) -> Self {
            let boot_clock = ManualSharedClock::new();
            boot_clock.advance(Duration::from_millis(BOOT_CLOCK_MS) + after);
            let temp = kr_ipc::testing::TempHost::create();
            std::fs::create_dir_all(temp.environment().state_dir()).expect("the state directory");
            Self {
                temp,
                wall: Arc::new(AtomicU64::new(WALL + after.as_millis() as u64)),
                boot_clock,
            }
        }

        fn file(&self) -> std::path::PathBuf {
            self.temp
                .environment()
                .state_dir()
                .join("attention-time.cbor")
        }

        fn store(&self) -> DeviceDirectory {
            DeviceDirectory::open(self.temp.environment().registry_database())
                .expect("the device store opens")
        }

        fn leave(&self, record: &[u8]) {
            std::fs::write(self.file(), record).expect("the earlier build's record");
        }

        /// A start: the record is taken in, and the host's decision is built over the store.
        fn start(&self, devices: &DeviceDirectory) -> Result<ClockTrust> {
            adopt_earlier_attention_clock(
                devices,
                self.temp.environment().state_dir(),
                &earlier_boot(),
                &self.boot_clock,
                self.wall.load(Ordering::SeqCst),
            )?;
            let wall = Arc::clone(&self.wall);
            Ok(ClockTrust::new(
                crate::service::WallClock::from_fn(move || wall.load(Ordering::SeqCst)),
                Arc::new(UtcFloor::at(0)),
                Arc::new(ManualClock::new()),
                Arc::new(self.boot_clock.clone()),
                earlier_boot(),
            ))
        }
    }

    /// KR-REQ-09.18: a rollback the attention store had found is still a rollback. The store was
    /// trusted and then found the wall clock going backwards; the host distrusts its clock from the
    /// start, the earlier file is gone, and one owner retrust clears it for every reader.
    #[test]
    fn a_rollback_an_earlier_build_found_is_carried_forward() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(ROLLED_BACK);
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");

        assert!(
            !host.file().exists(),
            "the earlier file is taken in and removed"
        );
        assert!(trust.sample(&devices).expect("samples").is_none());
        assert!(!trust.watch(&devices, true).expect("watches").proven);
        trust.establish(&devices).expect("the owner establishes");
        assert!(trust.sample(&devices).expect("samples").is_some());
        assert!(trust.watch(&devices, true).expect("watches").proven);
    }

    /// KR-REQ-09.18, KR-REQ-09.19: a clock the attention store never trusted is held, not distrusted: grants are
    /// decided as before, every forgetting is withheld, the platform qualifying later does not lift
    /// the hold, and only the owner's establishing does.
    #[test]
    fn a_clock_an_earlier_build_never_trusted_holds_every_forgetting() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(NEVER_TRUSTED);
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");

        assert!(trust.sample(&devices).expect("samples").is_some());
        assert!(
            trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_none(),
            "nothing is forgotten by a clock nobody trusted"
        );
        assert!(!trust.watch(&devices, true).expect("watches").proven);

        let restarted = host.start(&devices).expect("the host starts again");
        assert!(
            restarted
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_none(),
            "the hold survives a restart"
        );
        restarted
            .establish(&devices)
            .expect("the owner establishes");
        assert!(
            restarted
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_some()
        );
        assert!(restarted.watch(&devices, false).expect("watches").proven);
    }

    /// KR-REQ-09.18: a trusted record is not held against the clock, and what it proved is not
    /// lost. The mark and the anchor it carried are the host's: a wall clock behind the furthest the
    /// earlier build had proved, projected forward on the boot clock, is found.
    #[test]
    fn what_an_earlier_build_proved_is_what_the_host_measures_a_step_back_against() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(60));
        host.leave(CURRENT);
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");
        assert!(trust.sample(&devices).expect("samples").is_some());
        assert!(
            trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_some()
        );

        // A minute has passed on the boot clock since the fixture, and the wall clock reads ten
        // seconds behind where that puts it.
        let behind = Host::in_the_boot_of_the_fixtures(Duration::from_secs(60));
        behind.leave(CURRENT);
        behind.wall.store(WALL + 50_000, Ordering::SeqCst);
        let devices = behind.store();
        let trust = behind.start(&devices).expect("the host starts");
        assert!(trust.sample(&devices).expect("samples").is_none());
    }

    /// KR-REQ-09.19: the owner's confirmation is carried forward: with no qualified time service to
    /// give, the clock the owner confirmed is proven to attention.
    #[test]
    fn an_owner_confirmation_an_earlier_build_recorded_is_carried_forward() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(CONFIRMED);
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");
        assert!(trust.watch(&devices, false).expect("watches").proven);
    }

    /// KR-REQ-09.18: what the file holds is taken in once. A file an older build writes after the
    /// host adopted the first is not read: it is removed, and the host's record stands.
    #[test]
    fn a_file_written_after_the_record_was_adopted_is_ignored_and_removed() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(CURRENT);
        let devices = host.store();
        host.start(&devices).expect("the host starts");
        assert!(!host.file().exists());

        host.leave(ROLLED_BACK);
        let trust = host.start(&devices).expect("the host starts again");
        assert!(!host.file().exists(), "the later file is removed");
        assert!(
            trust.sample(&devices).expect("samples").is_some(),
            "and not read"
        );
    }

    /// KR-REQ-09.18: a start that stops before the adoption commits leaves the file where it was,
    /// and the next start adopts it whole.
    #[test]
    fn a_start_that_stops_before_the_adoption_commits_adopts_it_afresh() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(ROLLED_BACK);
        let devices = host.store();
        devices
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER refuse_the_adoption BEFORE UPDATE OF attention_time_retired
                     ON network_clock BEGIN SELECT RAISE(ABORT, 'the store is full'); END;
                     CREATE TRIGGER refuse_the_first_adoption BEFORE INSERT ON network_clock
                     BEGIN SELECT RAISE(ABORT, 'the store is full'); END;",
                )
            })
            .expect("the store takes triggers");
        assert!(host.start(&devices).is_err());
        assert!(host.file().exists(), "the file stays until it is taken in");

        devices
            .with(|connection| {
                connection.execute_batch(
                    "DROP TRIGGER refuse_the_adoption; DROP TRIGGER refuse_the_first_adoption;",
                )
            })
            .expect("the triggers go");
        let trust = host.start(&devices).expect("the host starts");
        assert!(!host.file().exists());
        assert!(trust.sample(&devices).expect("samples").is_none());
    }

    /// KR-REQ-09.18: a record that cannot be read says nothing of what it had found, so every
    /// forgetting is held until the owner establishes the clock.
    #[test]
    fn a_record_that_cannot_be_read_holds_every_forgetting() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        host.leave(b"not what an attention store wrote");
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");
        assert!(!host.file().exists());
        assert!(trust.sample(&devices).expect("samples").is_some());
        assert!(
            trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_none()
        );
    }

    /// A host that never had an earlier record has nothing held against it.
    #[test]
    fn a_host_with_no_earlier_record_starts_with_nothing_held() {
        let host = Host::in_the_boot_of_the_fixtures(Duration::from_secs(1));
        let devices = host.store();
        let trust = host.start(&devices).expect("the host starts");
        assert!(
            trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_some()
        );
        assert!(trust.watch(&devices, true).expect("watches").proven);
    }
}
