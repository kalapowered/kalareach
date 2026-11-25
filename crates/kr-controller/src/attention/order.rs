//! The order rule for attention text: whether a text was made after a device's access began.
//!
//! The host decides it from two readings of one counter, never from a time. A worker reads the
//! host's order counter (`kr_ipc::clock::order_elapsed_ms`) before it makes a text, and that
//! reading is the text's [`Stamp`]. The daemon reads the same counter where a device's access
//! begins, and that reading is the access's [`StartPoint`]. A reading never goes down as the
//! moment it is taken goes up, and it is the same function of the moment in every process of one
//! boot, so a stamp above a point in the same boot was taken after the point was. A tie proves
//! nothing and withholds, and so does everything the host cannot place: a stamp with no mark, an
//! access with no start point and a boot the host has no record of or cannot tell from another.
//!
//! Boots are placed by the order the host recorded them in ([`BootOrder`]): a stamp of a later
//! recorded boot is after a point of an earlier one, and the counters of two boots are never
//! compared.

use kr_protocol::ids::BootEpoch;

/// What a worker read of the host's order counter before it made a text.
///
/// Nothing in the daemon's production code builds one at this landing: the wire member that
/// carries a stamp from the worker is read where the gate is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The boot the worker was in.
    pub(crate) boot_epoch: BootEpoch,
    /// The reading of the order counter, in milliseconds since that boot.
    pub(crate) boot_ms: u64,
}

/// Where a device's access began, as the host read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartPoint {
    /// The wall reading of the decision that began the access: the moment the grant's own record
    /// of when it was issued, activated or paired holds.
    pub(crate) wall_ms: u64,
    /// The boot the host was in.
    pub(crate) boot_epoch: BootEpoch,
    /// The reading of the order counter, in milliseconds since that boot.
    pub(crate) boot_ms: u64,
}

/// What the host's record of boots says of one boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootState {
    /// The host has no record of the boot: a boot it was not running in, or one a restored record
    /// lost.
    Unknown,
    /// The host recorded the boot and found that it cannot tell it from another boot: its order
    /// counter went back inside it, or a boot recorded later was found to share its identity.
    Spoiled,
    /// The boot is recorded and told apart. The number is its place in the order the host started
    /// in boots: a later boot has a higher one.
    Known(u64),
}

/// The host's record of the order of boots.
pub trait BootOrder {
    /// Returns what the record says of `epoch`.
    fn state(&self, epoch: BootEpoch) -> BootState;
}

/// Why a text is not served to a bounded device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withheld {
    /// The text carries no mark of when it was made, or a partly filled one.
    NoProductionEvidence,
    /// The device's access has no start point the host can use: none was taken, the grant's bound
    /// is later than its start, or a boot involved is unknown or spoiled.
    NoStartPoint,
    /// The text was made at the start point or before it.
    BeforeHistoryBound,
}

/// Decides whether the text with `stamp` was made after the access that `point` marks began.
///
/// `bound` is the grant's own bound, the moment its history reaches back to, and `point.wall_ms`
/// is the decision that began the access. A bound later than that decision is a record this host
/// does not place, and the text is withheld.
///
/// # Errors
///
/// Returns why the text is withheld.
pub fn admit(
    bound: u64,
    point: Option<&StartPoint>,
    stamp: Option<&Stamp>,
    boots: &impl BootOrder,
) -> Result<(), Withheld> {
    let stamp = stamp.ok_or(Withheld::NoProductionEvidence)?;
    let point = point.ok_or(Withheld::NoStartPoint)?;
    if bound > point.wall_ms {
        return Err(Withheld::NoStartPoint);
    }
    // An unknown or a spoiled boot, on either side, withholds in every row below.
    let (BootState::Known(of_stamp), BootState::Known(of_point)) =
        (boots.state(stamp.boot_epoch), boots.state(point.boot_epoch))
    else {
        return Err(Withheld::NoStartPoint);
    };
    if stamp.boot_epoch == point.boot_epoch {
        return if stamp.boot_ms > point.boot_ms {
            Ok(())
        } else {
            Err(Withheld::BeforeHistoryBound)
        };
    }
    // The places of the boots, never their epochs: an epoch is a digest and has no order.
    if of_stamp > of_point {
        Ok(())
    } else {
        Err(Withheld::BeforeHistoryBound)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A way a counter reads a moment: its name, the reading, and the time after which a stamp is
    /// certain to read above a point.
    type Reading<'a> = (&'a str, &'a dyn Fn(u64) -> u64, u64);

    /// A record of boots a case writes by hand.
    struct Record(BTreeMap<u64, BootState>);

    impl Record {
        fn of(boots: &[(u64, BootState)]) -> Self {
            Self(boots.iter().copied().collect())
        }
    }

    impl BootOrder for Record {
        fn state(&self, epoch: BootEpoch) -> BootState {
            self.0
                .get(&epoch.get())
                .copied()
                .unwrap_or(BootState::Unknown)
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
            wall_ms: 1_000,
            boot_epoch: BootEpoch::new(epoch),
            boot_ms,
        }
    }

    fn admitted(point: &StartPoint, stamp: &Stamp, boots: &Record) -> Result<(), Withheld> {
        admit(1_000, Some(point), Some(stamp), boots)
    }

    /// The lemma, exhaustively. For every ordered pair of moments of a stamp and a point,
    /// and for each way a counter can read a moment, the stamp is admitted only when its moment is
    /// after the point's. The conclusion is computed from the pair and never taken as an input.
    #[test]
    fn a_stamp_is_admitted_only_when_its_moment_is_after_the_points() {
        // A reading of a moment, in milliseconds. Each is a non-decreasing function of the moment:
        // a truncation, two ticks and a tick of 15.625 ms that lags the true count by 3 ms. The
        // number beside each is the time after which a stamp is certain to read above a point: a
        // lagging reading needs its lag and a tick.
        let truncated = |moment: u64| moment / 2;
        let ticks_of_16 = |moment: u64| moment / 16 * 16;
        let ticks_of_7 = |moment: u64| moment / 7 * 7;
        let lagging = |moment: u64| moment.saturating_sub(3) * 1_000 / 15_625 * 15_625 / 1_000;
        let readings: [Reading<'_>; 4] = [
            ("truncation", &truncated, 2),
            ("tick of 16", &ticks_of_16, 16),
            ("tick of 7", &ticks_of_7, 7),
            ("tick of 15.625 with a lag", &lagging, 19),
        ];
        let boots = Record::of(&[(7, BootState::Known(1))]);
        for (name, read, tick) in readings {
            for moment_of_stamp in 0..=200_u64 {
                for moment_of_point in 0..=200_u64 {
                    let outcome = admitted(
                        &point(7, read(moment_of_point)),
                        &stamp(7, read(moment_of_stamp)),
                        &boots,
                    );
                    assert!(
                        outcome.is_err() || moment_of_stamp > moment_of_point,
                        "{name}: a stamp taken at {moment_of_stamp} was admitted against a point \
                         taken at {moment_of_point}"
                    );
                    if read(moment_of_stamp) == read(moment_of_point) {
                        assert_eq!(
                            outcome,
                            Err(Withheld::BeforeHistoryBound),
                            "{name}: equal readings of {moment_of_stamp} and {moment_of_point} \
                             are a tie, and a tie is withheld"
                        );
                    }
                }
            }
            // One tick later is admitted.
            for moment_of_point in 0..=(200 - tick) {
                assert_eq!(
                    admitted(
                        &point(7, read(moment_of_point)),
                        &stamp(7, read(moment_of_point + tick)),
                        &boots,
                    ),
                    Ok(()),
                    "{name}: a stamp one tick after the point at {moment_of_point} is admitted"
                );
            }
        }
    }

    /// Boots are told apart and placed by the record, and a boot the record cannot place
    /// withholds on either side, in every row.
    #[test]
    fn boots_are_placed_by_their_recorded_order_and_an_unplaced_boot_withholds() {
        // The epochs are chosen opposite to the order of the boots: epoch 90 is the first boot.
        let boots = Record::of(&[
            (90, BootState::Known(1)),
            (30, BootState::Known(2)),
            (50, BootState::Spoiled),
        ]);
        // The same boot: by the counter alone, and a tie withholds.
        assert_eq!(admitted(&point(90, 500), &stamp(90, 501), &boots), Ok(()));
        assert_eq!(
            admitted(&point(90, 500), &stamp(90, 500), &boots),
            Err(Withheld::BeforeHistoryBound)
        );
        assert_eq!(
            admitted(&point(90, 500), &stamp(90, 499), &boots),
            Err(Withheld::BeforeHistoryBound)
        );
        // A later recorded boot is after an earlier one whatever the counters read.
        assert_eq!(admitted(&point(90, 900_000), &stamp(30, 0), &boots), Ok(()));
        // An earlier recorded boot is before a later one whatever the counters read, and the
        // numeric order of the epochs decides nothing.
        assert_eq!(
            admitted(&point(30, 0), &stamp(90, 900_000), &boots),
            Err(Withheld::BeforeHistoryBound)
        );
        // A boot the record does not hold withholds as the stamp's, as the point's, and in the
        // same-epoch row too.
        assert_eq!(
            admitted(&point(90, 500), &stamp(77, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
        assert_eq!(
            admitted(&point(77, 500), &stamp(90, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
        assert_eq!(
            admitted(&point(77, 500), &stamp(77, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
        // A spoiled boot withholds on either side, in the same-epoch row and in the cross-boot rows.
        assert_eq!(
            admitted(&point(50, 500), &stamp(50, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
        assert_eq!(
            admitted(&point(90, 500), &stamp(50, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
        assert_eq!(
            admitted(&point(50, 500), &stamp(30, 900_000), &boots),
            Err(Withheld::NoStartPoint)
        );
    }

    /// The first two checks of the gate, which a record cannot change: no stamp and no point.
    #[test]
    fn a_text_with_no_stamp_or_an_access_with_no_point_is_withheld() {
        let boots = Record::of(&[(7, BootState::Known(1))]);
        assert_eq!(
            admit(1_000, Some(&point(7, 1)), None, &boots),
            Err(Withheld::NoProductionEvidence)
        );
        assert_eq!(
            admit(1_000, None, Some(&stamp(7, 9)), &boots),
            Err(Withheld::NoStartPoint)
        );
        // A bound later than the decision that began the access is not placed.
        assert_eq!(
            admit(1_001, Some(&point(7, 1)), Some(&stamp(7, 9)), &boots),
            Err(Withheld::NoStartPoint)
        );
        assert_eq!(
            admit(1_000, Some(&point(7, 1)), Some(&stamp(7, 9)), &boots),
            Ok(())
        );
    }

    /// For this landing: nothing but the unit tests of this file builds the daemon's
    /// `Stamp`. A text's stamp comes from a worker, and the one function that turns the wire's
    /// member into a `Stamp` lands with the member.
    #[test]
    fn no_production_code_builds_the_daemons_stamp() {
        fn sources(directory: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(directory).expect("a source directory") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    sources(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &mut files);
        assert!(files.len() > 100, "the scan reads the crate's sources");
        let here = root.join("attention").join("order.rs");
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a source file");
            // The production part of a file is what comes before its first test module.
            let production = text.split("#[cfg(test)]").next().unwrap_or_default();
            if file == here {
                let literals = production.matches("Stamp {").count();
                assert_eq!(
                    literals, 1,
                    "the production text of order.rs holds the definition of `Stamp` and no literal"
                );
            } else {
                assert!(
                    !(production.contains("attention::order") && production.contains("Stamp")),
                    "{} names the daemon's `Stamp`",
                    file.display()
                );
            }
        }
    }
}
