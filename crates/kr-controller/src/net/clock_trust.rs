//! This host's one decision about its wall clock.
//!
//! Section 9 lets a host decide an expiry from its wall clock only while it has not found that
//! clock going backwards, and says the same of every collection that forgets by it. The host has
//! one decision, here, and every reader of the wall clock goes through it: a grant's lifetime, the
//! voice coordinator's spent delegations, the transfer sweep, and the attention store's readings
//! and forgetting. What one finds, all of them see, and what clears it clears it for all of them.
//!
//! # What is held
//!
//! One lock holds the whole state, so a reading and the decision about the reading are one
//! transition and none can be answered about a clock an owner established in between:
//!
//! * the decision itself, **distrust**: a rollback found by any reader, held until an owner
//!   establishes the clock. It withholds every forgetting, attention's included, and every
//!   decision that needs trusted UTC to expire a grant;
//! * the **mark**, the highest wall reading seen, and the **anchor**, the furthest the wall clock
//!   was proved to have reached with the continuous reading it was proved at. The reference a
//!   reading is compared with is the later of the mark and the anchor projected forward by the
//!   continuous clock, less a rate allowance for the continuous clock running fast, so a step
//!   back smaller than the time between two readings is found by whoever reads next;
//! * the **forgetting hold**, which withholds every forgetting and no grant decision, and the
//!   **evidence hold**, which withholds attention's forgetting and quiet hours only: set when the
//!   platform's time service is found unqualified while the owner has not confirmed the clock,
//!   and not lifted by the service qualifying again, because that is a decision the owner takes;
//! * whether the owner **confirmed** the clock, which any distrust takes back;
//! * what is **owed** to the durable record: a decision or a step that could not be written stays
//!   here and is written again before the next answer.
//!
//! `ClockTrust::establish_with` clears the decision and both holds, moves the mark and the
//! anchor, confirms the clock and ends a lost clock continuity, in one transition. Nothing else
//! does, and the owner's confirmation is spent in the same transaction.
//!
//! # Lock order
//!
//! The owner challenges where an owner's confirmation is spent, the attention store where one is
//! read, then this state, then the device directory, then a registration table held through a
//! commit. No policy or grant callback runs under this state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::BootEpoch;
use kr_protocol::scalars::TimestampMs;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};
use kr_worker::action::time::DISCONTINUITY_TOLERANCE;

use super::devices::{CommitFn, DeviceDirectory, ObservedUtc, establish_clock_in};
use crate::error::{ControllerError, Result};
use crate::grants::policy::UtcFloor;
use crate::registry::end_clock_continuity;

/// How far behind what this host holds of its wall clock the clock may be and still decide an
/// expiry.
///
/// A small step is ordinary: a clock corrected by a time service, or two reads either side of a
/// write. A larger one says the wall clock is not currently a clock this host can measure a grant
/// against, and section 9 does not let it guess in the device's favour.
pub const CLOCK_TOLERANCE_MS: u64 = 5_000;

/// How far a forward step may go unwritten, and so how far an anchor read back may be behind the
/// truth.
///
/// A step is written down when the wall clock exceeds the anchor projected from what was last
/// written by more than this, so time passing is not mistaken for a correction. The projection
/// credits a little less than the time that passes ([`kr_ipc::clock::RATE_ALLOWANCE_PPM`]), so a
/// clock that keeps pace is written about every 42 minutes.
fn unwritten_step_ms() -> u64 {
    u64::try_from(DISCONTINUITY_TOLERANCE.as_millis()).unwrap_or(u64::MAX)
}

/// How many times the clocks are read together before this host gives up taking a reading.
const BRACKET_TRIES: usize = 3;

/// Other clocks read between two readings of the continuous clock that are no further apart than
/// [`DISCONTINUITY_TOLERANCE`], so that no pause of this host lies between the pair.
///
/// An anchor is taken at the first reading and a comparison is made at the second: each error of a
/// narrow bracket is then toward distrust and no larger than the tolerance.
struct Bracketed<T> {
    /// The continuous clock before the others were read: where an anchor is taken.
    first: ContinuousInstant,
    /// The continuous clock after: where a comparison is made.
    second: ContinuousInstant,
    read: T,
}

/// What a try that was held up read: its two readings of the continuous clock stood further apart
/// than [`DISCONTINUITY_TOLERANCE`].
///
/// Its wall reading proves one thing, that the wall clock had read that much by `second`, and a
/// pause cannot make that wrong, because the continuous clock is read after the wall clock. It
/// says nothing of where the wall clock stood at the first reading, so it is no comparison against
/// a mark or an anchor.
struct HeldUp<T> {
    /// The continuous clock after the others were read: where the reading is stamped.
    second: ContinuousInstant,
    read: T,
}

/// What [`ClockTrust::bracketed`] hands back: the narrow reading, if one was had in three tries,
/// and what each try held up before it read.
struct Tries<T> {
    narrow: Option<Bracketed<T>>,
    held_up: Vec<HeldUp<T>>,
}

/// What the boot clock and the wall clock read together.
type Pair = (u64, u64);

/// What a caller is told when no narrow bracket could be taken in three tries.
///
/// It finds nothing wrong with the clock, so it is not the clock's distrust: nothing was decided
/// from the readings, trust has not changed, and a caller may try again. An establishment says
/// besides that the owner's confirmation was not spent.
fn clocks_not_read(establishing: bool) -> ControllerError {
    let mut detail = "this host could not read its clocks together just now: it was held up \
                      between the readings in all three tries, so it decided nothing from them \
                      and its clock trust has not changed; try again"
        .to_owned();
    if establishing {
        detail.push_str("; it did not spend the owner's confirmation");
    }
    ControllerError::ClockNotRead { detail }
}

/// The furthest the wall clock was proved to have reached, and the continuous instant it was
/// proved at.
#[derive(Clone, Copy, Debug)]
struct Anchor {
    wall_ms: u64,
    at: ContinuousInstant,
}

impl Anchor {
    /// The earliest the wall clock can honestly read at `now`: the anchor plus what has elapsed
    /// since on the continuous clock, less the rate allowance ([`kr_ipc::clock::credited`]).
    fn projected(self, now: ContinuousInstant) -> u64 {
        let elapsed =
            u64::try_from(now.saturating_duration_since(self.at).as_millis()).unwrap_or(u64::MAX);
        self.wall_ms
            .saturating_add(kr_ipc::clock::credited(elapsed))
    }
}

/// What has been decided and not yet written down.
#[derive(Clone, Copy, Debug, Default)]
struct Owed {
    distrust: bool,
    anchor: bool,
    evidence_hold: bool,
}

impl Owed {
    const fn any(self) -> bool {
        self.distrust || self.anchor || self.evidence_hold
    }
}

#[derive(Debug, Default)]
struct State {
    /// Whether the durable record has been read into this state.
    loaded: bool,
    distrusted: bool,
    /// The highest wall reading seen: the durable mark, raised by every reading.
    mark_ms: u64,
    anchor: Option<Anchor>,
    /// The anchor as last written down, which a later step is measured against.
    saved: Option<Anchor>,
    /// The anchor this host read back, while it may still be behind the truth.
    ///
    /// A step smaller than [`unwritten_step_ms`] is not written, so a rollback measured against a
    /// restored anchor would look smaller by as much. While this is held the tolerance is reduced
    /// by that much, which is the conservative direction, until the host has read the clock past
    /// the furthest an unwritten step could have taken it.
    restored: Option<Anchor>,
    confirmed: bool,
    forgetting_hold: bool,
    evidence_hold: bool,
    owed: Owed,
}

/// What this host holds against its wall clock at one reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standing {
    /// A rollback was found and no owner has established the clock since.
    pub distrusted: bool,
    /// Every forgetting is withheld.
    pub forgetting_hold: bool,
    /// Attention's forgetting and quiet hours are withheld.
    pub evidence_hold: bool,
    /// The owner established the clock and nothing has put it in doubt since.
    pub confirmed: bool,
    /// Something decided is not written down yet.
    pub owed: bool,
    /// What the host knows of its clock is ahead of its record: a step forward whose write failed.
    /// A restart now would measure a rollback against a record that is behind, so every
    /// forgetting is withheld until the record catches up. Grants and quiet hours decide from the
    /// clock now and are not.
    pub anchor_owed: bool,
    /// This boot's clock continuity is lost, taken in the same transition as the rest.
    pub continuity_lost: bool,
}

/// One reading of the wall clock, with what this host holds against it, taken together.
#[derive(Clone, Copy, Debug)]
pub struct Moment {
    /// What the wall clock read, in UTC milliseconds.
    pub wall_ms: u64,
    /// The moment to decide against, and how far the wall clock is behind what this host holds.
    pub observed: ObservedUtc,
    /// What this host holds against the clock at that reading.
    pub standing: Standing,
}

/// What an attention reading finds ([`ClockTrust::watch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watched {
    /// What the wall clock read, in UTC milliseconds.
    pub wall_ms: u64,
    /// Whether the wall clock proves what attention uses it for: no distrust, no hold, and either
    /// a qualified reading of the platform's time service or the owner's confirmation.
    pub proven: bool,
    /// Something decided is not written down yet, so the caller comes back to write it.
    pub owed: bool,
}

/// Whether this host may decide an expiry from its own wall clock, and the transitions of that.
pub struct ClockTrust {
    state: Mutex<State>,
    /// Whether the state read its record and does not hold the clock distrusted, published by
    /// whoever changes either under the state's lock, so a caller that must not wait for that lock
    /// can ask ([`Self::is_trusted_now`]).
    trusting: AtomicBool,
    /// The wall clock this decision is about: the daemon's own.
    wall: crate::service::WallClock,
    /// The host's clock floor, which every reading taken here is published in before anything is
    /// decided from it.
    floor: Arc<UtcFloor>,
    /// The suspend-aware continuous clock the mark is projected on.
    clock: Arc<dyn ContinuousClock>,
    /// The boot clock the anchor is written in, so a restart in the same boot adds the time
    /// between.
    boot_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    boot: BootIdentity,
    /// Where this module's own tests stop a reader that has not yet taken the lock.
    #[cfg(test)]
    before_watch: crate::attention::Pause,
}

impl std::fmt::Debug for ClockTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClockTrust")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Where a reading's mark comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The durable mark, raised by the reading: every grant decision, a record and the record
    /// task.
    Stored,
    /// The mark in memory: a reader that reads often writes nothing on the ordinary path.
    Watched,
}

impl ClockTrust {
    /// A decision about `wall`, trusted until a step back says otherwise, publishing every reading
    /// in `floor` and projecting the mark on `clock`, and written in `boot_clock` for `boot`.
    #[must_use]
    pub fn new(
        wall: crate::service::WallClock,
        floor: Arc<UtcFloor>,
        clock: Arc<dyn ContinuousClock>,
        boot_clock: Arc<dyn kr_ipc::clock::SharedClock>,
        boot: BootIdentity,
    ) -> Self {
        Self {
            state: Mutex::new(State::default()),
            trusting: AtomicBool::new(false),
            wall,
            floor,
            clock,
            boot_clock,
            boot,
            #[cfg(test)]
            before_watch: crate::attention::Pause::default(),
        }
    }

    /// Reads `read` between two readings of the continuous clock, and again while they are
    /// further apart than the tolerance of a discontinuity, three tries in all.
    ///
    /// No narrow reading is no reading now, which no caller turns into a distrust: a wide bracket
    /// decides no comparison. What each try held up read is handed back with its second reading,
    /// for a caller that has a wall reading in it to fold in ([`Self::fold_held_up`]).
    fn bracketed<T>(&self, read: impl Fn() -> T) -> Tries<T> {
        let mut held_up = Vec::new();
        for _ in 0..BRACKET_TRIES {
            let first = self.clock.now();
            let value = read();
            let second = self.clock.now();
            if second.saturating_duration_since(first) <= DISCONTINUITY_TOLERANCE {
                return Tries {
                    narrow: Some(Bracketed {
                        first,
                        second,
                        read: value,
                    }),
                    held_up,
                };
            }
            held_up.push(HeldUp {
                second,
                read: value,
            });
        }
        Tries {
            narrow: None,
            held_up,
        }
    }

    /// Publishes the wall reading of each try held up in the host's floor: the floor is a maximum
    /// with no continuous stamp, so a pause cannot make a publication wrong.
    fn publish_held_up(&self, held_up: &[HeldUp<Pair>]) {
        for tried in held_up {
            self.floor.observe(tried.read.1);
        }
    }

    /// Folds what the tries held up read into this host's marks, as a narrow reading's wall moves
    /// them, each at its second reading: the floor, the highest wall reading seen and, while the
    /// clock is trusted, the anchor, under the tests a narrow reading is raised under. A wide wall
    /// is no comparison and distrusts nothing, but a peak that only a held-up try read is then in
    /// the marks, so a step back made inside the held-up reading is found. Where a narrow raise
    /// writes, this writes: the durable mark of a stored reading is raised at once, and a step
    /// forward the anchor shows is owed its write.
    ///
    /// Returns the first failure to raise the durable mark.
    fn fold_held_up(
        &self,
        state: &mut State,
        devices: &DeviceDirectory,
        source: Source,
        held_up: &[HeldUp<Pair>],
    ) -> Option<ControllerError> {
        self.publish_held_up(held_up);
        let mut failed = None;
        for tried in held_up {
            let wall_ms = tried.read.1;
            let (_, _, error) = Self::raise_mark(state, devices, source, wall_ms);
            failed = failed.or(error);
            if !state.distrusted {
                Self::advance_anchor(state, wall_ms, tried.second);
            }
        }
        failed
    }

    /// Raises the highest wall reading seen to `wall_ms`: in the durable mark when the reading is a
    /// stored one, and in memory either way. Returns the highest reading seen as the raise left it,
    /// how far `wall_ms` is behind the mark before it, and the failure to write the durable mark,
    /// which a stored reading's caller answers after it has decided from what memory holds.
    fn raise_mark(
        state: &mut State,
        devices: &DeviceDirectory,
        source: Source,
        wall_ms: u64,
    ) -> (u64, u64, Option<ControllerError>) {
        let mut store_error = None;
        let (latest, behind_mark) = match source {
            Source::Stored => match devices.utc_at_least(TimestampMs::new(wall_ms)) {
                Ok(observed) => (observed.now.get(), observed.behind_ms),
                Err(error) => {
                    store_error = Some(error);
                    (
                        state.mark_ms.max(wall_ms),
                        state.mark_ms.saturating_sub(wall_ms),
                    )
                }
            },
            Source::Watched => {
                let behind = state.mark_ms.saturating_sub(wall_ms);
                (state.mark_ms.max(wall_ms), behind)
            }
        };
        state.mark_ms = state.mark_ms.max(latest);
        (latest, behind_mark, store_error)
    }

    /// Moves the anchor to a wall reading taken at `at` where that is new proof, and ends the
    /// allowance of a restored anchor where the reading is past it.
    ///
    /// The anchor moves forward only: a reading at or beyond what this host could prove is new
    /// proof, and one behind it is slippage the tolerance forgives, which must not move the anchor
    /// or the next one would be forgiven against the moved anchor.
    fn advance_anchor(state: &mut State, wall_ms: u64, at: ContinuousInstant) {
        if state
            .anchor
            .is_none_or(|anchor| wall_ms >= anchor.projected(at))
        {
            state.anchor = Some(Anchor { wall_ms, at });
            // A step forward is written down; time passing is not.
            let stepped = state.saved.is_none_or(|saved| {
                wall_ms.saturating_sub(saved.projected(at)) > unwritten_step_ms()
            });
            if stepped {
                state.owed.anchor = true;
            }
        }
        // A reading a whole step beyond the restored anchor is at or past the furthest an
        // unwritten step could have taken the clock, so the anchor is this host's own again.
        if state.restored.is_some_and(|restored| {
            wall_ms >= restored.projected(at).saturating_add(unwritten_step_ms())
        }) {
            state.restored = None;
        }
    }

    fn held(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes what `state` says of trust, for [`Self::is_trusted_now`]. Every change of
    /// `loaded` or `distrusted` is followed by this under the same lock.
    fn publish(&self, state: &State) {
        self.trusting
            .store(state.loaded && !state.distrusted, Ordering::SeqCst);
    }

    /// Reads the durable record into `state`, the first time anything asks.
    fn load(&self, state: &mut State, devices: &DeviceDirectory) -> Result<()> {
        let record = devices.clock_record()?;
        // The boot clock between two readings of the continuous clock: the anchor is installed at
        // the earlier instant with the time up to the boot clock's reading, so what is projected
        // from it is never short.
        let Bracketed {
            first: at,
            read: boot_ms,
            ..
        } = self
            .bracketed(|| self.boot_clock.boot_elapsed_ms())
            .narrow
            .ok_or_else(|| clocks_not_read(false))?;
        state.mark_ms = record.observed_ms.unwrap_or(0);
        state.distrusted = record.untrusted_at_ms.is_some();
        state.confirmed = record.confirmed_at_ms.is_some();
        state.forgetting_hold = record.forgetting_hold_at_ms.is_some();
        state.evidence_hold = record.evidence_hold_at_ms.is_some();
        if let Some(stored) = record.anchor {
            // Within the boot it was written in, the boot clock says how long has passed since. In
            // another boot the wall reading stands and the continuous side starts from now.
            let same_boot = stored.boot_value.as_slice() == self.boot.value.as_slice();
            let wall_ms = if same_boot {
                stored.wall_ms.saturating_add(kr_ipc::clock::credited(
                    boot_ms.saturating_sub(stored.boot_ms),
                ))
            } else {
                stored.wall_ms
            };
            let anchor = Anchor { wall_ms, at };
            state.anchor = Some(anchor);
            state.restored = Some(anchor);
            if same_boot {
                state.saved = Some(anchor);
            } else {
                // The record still names the boot before. Until it names this one, a restart in
                // this boot would start from the wall reading again and lose what passed since,
                // so the rebased anchor is owed its write.
                state.saved = None;
                state.owed.anchor = true;
            }
        }
        state.loaded = true;
        self.publish(state);
        Ok(())
    }

    /// The one transition every reading goes through.
    ///
    /// The boot clock and the wall clock are read between two readings of the continuous clock,
    /// inside the lock, so a caller that paused before getting here contributes no reading. The
    /// pair is used only where the two readings of the continuous clock are no further apart than
    /// the tolerance of a discontinuity, and is taken again where they are, at most three times: a
    /// pause between the readings would otherwise move the anchor wrongly, and show as a rollback
    /// at the next reading, which only an owner clears. The anchor is taken at the first reading
    /// and a rollback is measured at the second, so each error of a narrow bracket is toward
    /// distrust and no larger than the tolerance. No narrow bracket in three tries is no reading:
    /// nothing is decided from the clocks and trust does not change. What a try held up read is
    /// evidence all the same, and is folded in at its second reading before the narrow reading is
    /// compared, after three held-up tries too ([`Self::fold_held_up`]).
    fn transition(
        &self,
        state: &mut State,
        devices: &DeviceDirectory,
        source: Source,
        platform_qualified: Option<bool>,
    ) -> Result<Moment> {
        if !state.loaded {
            self.load(state, devices)?;
        }
        // The boot clock before the wall clock, as the establishment reads them: a reading the
        // floor shows the workers is the pair, and a pause between the two readings must leave
        // the pair asking more of a worker's clock, never less.
        let tries = self.bracketed(|| (self.boot_clock.boot_elapsed_ms(), self.wall.now_ms()));
        // The durable mark is raised by the reading; when that write fails, what the mark and the
        // anchor held in memory prove is decided all the same and the failure is answered after,
        // so a rollback this reading saw is not lost with the write.
        let mut store_error = self.fold_held_up(state, devices, source, &tries.held_up);
        let Some(Bracketed {
            first: at,
            second: compared_at,
            read: (boot_ms, wall_ms),
        }) = tries.narrow
        else {
            // What the held-up tries read is folded in, and a step forward it shows is owed its
            // write like any other: written now, as a narrow reading's is.
            let at_ms = state.mark_ms;
            let _ = self.write_owed(state, devices, at_ms);
            return Err(clocks_not_read(false));
        };
        let (latest, behind_mark, raised) = Self::raise_mark(state, devices, source, wall_ms);
        store_error = store_error.or(raised);
        let projected = state
            .anchor
            .map_or(0, |anchor| anchor.projected(compared_at));
        let behind_ms = behind_mark.max(projected.saturating_sub(wall_ms));
        let tolerance = if state.restored.is_some() {
            CLOCK_TOLERANCE_MS.saturating_sub(unwritten_step_ms())
        } else {
            CLOCK_TOLERANCE_MS
        };
        if behind_ms > tolerance && !state.distrusted {
            // The decision is in memory before anything is written, and the write is attempted
            // below and again by whoever reads next until it lands.
            state.distrusted = true;
            state.confirmed = false;
            state.owed.distrust = true;
            self.publish(state);
        }
        if !state.distrusted {
            Self::advance_anchor(state, wall_ms, at);
        }
        if let Some(qualified) = platform_qualified
            && !qualified
            && !state.confirmed
            && !state.evidence_hold
        {
            state.evidence_hold = true;
            state.owed.evidence_hold = true;
        }
        self.tell_the_workers(state, wall_ms, boot_ms);
        let _ = self.write_owed(state, devices, latest);
        if let Some(error) = store_error {
            return Err(error);
        }
        Ok(Moment {
            wall_ms,
            observed: ObservedUtc {
                // The later of the mark and the anchor projected on the continuous clock: a step
                // back the tolerance forgives gives no grant the time it appeared to lose, beyond
                // what the rate allowance gives.
                now: TimestampMs::new(latest.max(projected)),
                behind_ms,
            },
            standing: self.standing(state),
        })
    }

    /// Keeps the owner's confirmation the floor shows the workers equal to what this record holds,
    /// from the reading just taken.
    ///
    /// A record that distrusts the clock holds none, so a confirmation standing in the floor is
    /// withdrawn, and a worker that begins later does not take it. A record that holds the owner's
    /// confirmation while the floor shows none in force says so with the reading just taken, as a
    /// restatement ([`kr_ipc::floor::SharedFloor::restate`]): that is how a worker that begins in
    /// a new boot learns of a confirmation made in an earlier one, since the owner's word stands
    /// until a rollback ends it, and how a publication the daemon did not complete (it stopped
    /// after the commit and before its stores, or between them) is made good at the next reading.
    /// A boot whose clock continuity is lost has no reading to say it with.
    ///
    /// A restatement is not an action of the owner: a worker that has met a confirmation, found a
    /// rollback or restored a record does not follow it. That matters most when the floor shows a
    /// withdrawal because the record, in memory, found a rollback whose write was lost when the
    /// daemon stopped: the record then reads as confirmed again, and states it again over the
    /// withdrawal, and no worker that found the rollback is cleared by it. A worker that begins
    /// after takes what the record holds, as the daemon does.
    fn tell_the_workers(&self, state: &State, wall_ms: u64, boot_ms: u64) {
        let words = self.floor.words();
        if state.distrusted {
            if words.established().is_some() {
                words.withdraw();
            }
        } else if state.confirmed && words.established().is_none() && !self.floor.continuity_lost()
        {
            let _ = words.restate(wall_ms, boot_ms);
        }
    }

    fn standing(&self, state: &State) -> Standing {
        Standing {
            distrusted: state.distrusted,
            forgetting_hold: state.forgetting_hold,
            evidence_hold: state.evidence_hold,
            confirmed: state.confirmed,
            owed: state.owed.any(),
            anchor_owed: state.owed.anchor,
            continuity_lost: self.floor.continuity_lost(),
        }
    }

    /// Writes down what is owed, and keeps whatever cannot be written.
    fn write_owed(&self, state: &mut State, devices: &DeviceDirectory, at_ms: u64) -> Result<()> {
        let stamp = TimestampMs::new(at_ms);
        let mut outcome = Ok(());
        if state.owed.distrust {
            match devices.note_clock_untrusted(stamp) {
                Ok(()) => state.owed.distrust = false,
                Err(error) => outcome = outcome.and(Err(error)),
            }
        }
        if state.owed.evidence_hold {
            match devices.note_evidence_hold(stamp) {
                Ok(()) => state.owed.evidence_hold = false,
                Err(error) => outcome = outcome.and(Err(error)),
            }
        }
        if state.owed.anchor
            && let Some(anchor) = state.anchor
        {
            // Written as the anchor projects at the later reading of the continuous clock, with
            // the boot clock read between the two, so a restart in this boot adds the time between
            // and is never short.
            match self.bracketed(|| self.boot_clock.boot_elapsed_ms()).narrow {
                None => outcome = outcome.and(Err(clocks_not_read(false))),
                Some(Bracketed {
                    second: at,
                    read: boot_ms,
                    ..
                }) => {
                    let wall_ms = anchor.projected(at);
                    match devices.record_clock_anchor(wall_ms, &self.boot, boot_ms) {
                        Ok(()) => {
                            state.saved = Some(Anchor { wall_ms, at });
                            state.owed.anchor = false;
                        }
                        Err(error) => outcome = outcome.and(Err(error)),
                    }
                }
            }
        }
        outcome
    }

    /// Samples the wall clock and says whether this host may decide against what it read.
    ///
    /// One operation, because the two halves are one decision: the clock is read, a rollback
    /// becomes distrust, and the answer says whether the reading may be used. Anything that read
    /// the clock and then asked separately could be answered about a clock an owner established in
    /// between, and would then measure a grant from the reading it took before that.
    ///
    /// A boot whose clock continuity is lost has no reading anything may be decided against until
    /// the owner establishes the clock, which is a clock this host does not trust.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written. A host that cannot tell decides
    /// nothing.
    pub fn sample(&self, devices: &DeviceDirectory) -> Result<Option<ObservedUtc>> {
        let moment = self.read(devices)?;
        Ok(
            (!moment.standing.distrusted && !moment.standing.continuity_lost)
                .then_some(moment.observed),
        )
    }

    /// As [`Self::sample`], for a collection that lets go of a record by the wall clock: also
    /// answered no while the forgetting hold stands, and while a step forward this host has seen
    /// is not written down, because a restart now would measure a rollback against a record that
    /// is behind.
    ///
    /// # Errors
    ///
    /// As [`Self::sample`].
    pub fn sample_for_forgetting(&self, devices: &DeviceDirectory) -> Result<Option<ObservedUtc>> {
        let moment = self.read(devices)?;
        Ok((!moment.standing.distrusted
            && !moment.standing.forgetting_hold
            && !moment.standing.anchor_owed
            && !moment.standing.continuity_lost)
            .then_some(moment.observed))
    }

    /// One reading of the wall clock and what this host holds against it, taken together and
    /// published in the host's floor.
    fn read(&self, devices: &DeviceDirectory) -> Result<Moment> {
        let mut state = self.held();
        let mut moment = self.transition(&mut state, devices, Source::Stored, None)?;
        // Published whatever is decided from it: a reading any process of this host took is the
        // floor every later decision stands on. The raw reading still decides a rollback, because
        // the floor only moves forward and cannot show that the wall clock went back.
        moment.observed.now = TimestampMs::new(self.floor.observe(moment.observed.now.get()));
        Ok(moment)
    }

    /// Records the moment this host is at, for a caller that needs the reading rather than a
    /// decision from it.
    ///
    /// A tombstone is written at the moment it was observed, and a rollback observed while doing
    /// it is the same fact as one observed anywhere else: it becomes distrust here too.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written.
    pub fn observe(&self, devices: &DeviceDirectory) -> Result<TimestampMs> {
        Ok(self.read(devices)?.observed.now)
    }

    /// Reads the wall clock for a caller that reads often, and says whether it proves what
    /// attention uses it for.
    ///
    /// The same transition as [`Self::sample`], which loads the durable mark once and then keeps
    /// it in memory: the ordinary reading writes no row. A rollback, a step forward that is worth
    /// keeping and a hold are written at once, and kept owed until they are. `platform_qualified`
    /// is whether the platform's time service qualified at this reading; unqualified while the
    /// owner has not confirmed the clock it sets the evidence hold, which a later qualified
    /// reading does not lift.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable record cannot be read the first time.
    pub fn watch(&self, devices: &DeviceDirectory, platform_qualified: bool) -> Result<Watched> {
        #[cfg(test)]
        self.before_watch.wait();
        let mut state = self.held();
        let moment = self.transition(
            &mut state,
            devices,
            Source::Watched,
            Some(platform_qualified),
        )?;
        let standing = moment.standing;
        Ok(Watched {
            wall_ms: moment.wall_ms,
            proven: !standing.distrusted
                && !standing.forgetting_hold
                && !standing.evidence_hold
                && (platform_qualified || standing.confirmed),
            owed: standing.owed,
        })
    }

    /// Writes down what this host owes its record, until the writes land.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written; what could not be written stays
    /// owed.
    pub fn settle(&self, devices: &DeviceDirectory) -> Result<()> {
        let mut state = self.held();
        if !state.loaded {
            self.load(&mut state, devices)?;
        }
        let at_ms = state.mark_ms;
        self.write_owed(&mut state, devices, at_ms)
    }

    /// Whether this host still trusts its clock, from what it holds in memory and nothing else.
    ///
    /// It reads no clock, writes nothing and takes no lock, so a caller that is inside a store's
    /// transaction may ask it. A reading holds the state's lock while it writes its record through
    /// the same file the transaction holds, and a caller that waited for that lock there would
    /// wait until the write gave up. A host that has not read its record yet does not trust its
    /// clock, and neither does one whose boot lost the continuity of its readings. A caller that
    /// sampled before it waited asks again after, to find a distrust a reader of the clock decided
    /// meanwhile.
    #[must_use]
    pub fn is_trusted_now(&self) -> bool {
        self.trusting.load(Ordering::SeqCst) && !self.floor.continuity_lost()
    }

    /// Whether something decided is not written down yet.
    #[must_use]
    pub fn owes_a_write(&self) -> bool {
        self.held().owed.any()
    }

    /// Holds the clock decision's lock while `body` runs, so that no reader is between its two
    /// clock readings meanwhile: a test moves its clocks here, and a reader that runs in the
    /// background takes both readings before the move or both after it.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn while_no_reader_reads<T>(&self, body: impl FnOnce() -> T) -> T {
        let _held = self.held();
        body()
    }

    /// Establishes the clock again, at the moment an owner authenticated, and returns that moment.
    ///
    /// The decision and both holds are cleared, the mark and the anchor move to that moment, the
    /// clock is confirmed and this `boot`'s lost clock continuity is ended, in one transition and
    /// one durable transaction: an observation taken against the old mark cannot land after it,
    /// because it would have to take this boundary to be recorded at all, and success is reported
    /// only once the record says it.
    ///
    /// The transaction is one immediate transaction on the device directory's connection, and it
    /// commits inside `guarded` ([`DeviceDirectory::guarded_transaction`]). `during` runs in it,
    /// after the trust and continuity rows: whatever must be written with the establishment
    /// (the spending of the owner's confirmation, the action's record) goes there, and what it
    /// refuses rolls the establishment back with it. Memory changes only after the commit: the
    /// clock state here, the floor's continuity flag and the confirmation the floor shows the
    /// workers.
    ///
    /// `during` runs under this state's lock, which cannot be taken twice. It must not call
    /// [`Self::sample`], [`Self::observe`], [`Self::watch`] or anything that reads a grant's
    /// lifetime through them, and it holds the device directory's connection, so it touches that
    /// connection through the transaction it is given and in no other way.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written, when no narrow bracket of the clocks
    /// could be taken (before the transaction, so nothing is spent), and whatever `guarded` and
    /// `during` refuse with. The decision stands, and so does every other record, if it does.
    pub(crate) fn establish_with(
        &self,
        devices: &DeviceDirectory,
        boot: BootEpoch,
        guarded: &CommitFn,
        during: impl FnOnce(&rusqlite::Connection, TimestampMs) -> Result<()>,
    ) -> Result<TimestampMs> {
        let mut state = self.held();
        // Read inside the boundary, like every other reading of this clock: the moment the owner
        // established is the moment this host is at now, not one sampled before it got here. No
        // narrow bracket refuses here, before the transaction, so the owner's confirmation is not
        // spent. What the tries held up read is published in the floor all the same; the
        // establishment replaces the marks, so it folds nothing else.
        let tries = self.bracketed(|| (self.boot_clock.boot_elapsed_ms(), self.wall.now_ms()));
        self.publish_held_up(&tries.held_up);
        let Some(Bracketed {
            first: at,
            read: (boot_ms, wall_ms),
            ..
        }) = tries.narrow
        else {
            return Err(clocks_not_read(true));
        };
        let established = TimestampMs::new(wall_ms);
        devices.guarded_transaction(guarded, |transaction| {
            establish_clock_in(transaction, established, &self.boot, boot_ms)?;
            end_clock_continuity(transaction, boot, established)?;
            during(transaction, established)
        })?;
        let anchor = Anchor {
            wall_ms: established.get(),
            at,
        };
        *state = State {
            loaded: true,
            distrusted: false,
            mark_ms: established.get(),
            anchor: Some(anchor),
            saved: Some(anchor),
            restored: None,
            confirmed: true,
            forgetting_hold: false,
            evidence_hold: false,
            owed: Owed::default(),
        };
        self.publish(&state);
        self.floor.establish_continuity();
        // And in the floor the workers map, so a worker that distrusts its own clock can follow the
        // owner.
        self.floor.words().establish(established.get(), boot_ms);
        Ok(established)
    }

    /// Establishes the clock with no confirmation to spend, for a test of the record itself.
    #[cfg(test)]
    pub(crate) fn establish(&self, devices: &DeviceDirectory) -> Result<TimestampMs> {
        self.establish_with(
            devices,
            BootEpoch::new(0),
            &|commit| commit(),
            |_, _| Ok(()),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use std::sync::{OnceLock, Weak};
    use std::time::Duration;

    use kr_ipc::clock::{ManualSharedClock, SharedClock};
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::Bytes;
    use kr_transport::clock::ManualClock;

    use super::*;

    const START: u64 = 1_700_000_000_000;
    const MINUTE: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(3_600);
    const DAY: Duration = Duration::from_secs(86_400);
    /// How fast the continuous clock runs against the wall clock in the tests of the rate
    /// allowance: half of what the allowance covers.
    const FIFTY_PPM: u64 = 50;

    fn boot(byte: u8) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::MacosBootSessionUuid,
            value: Bytes::new(vec![byte; 16]),
        }
    }

    /// `by` on a clock that runs `ppm` parts per million fast.
    fn fast(by: Duration, ppm: u64) -> Duration {
        let ms = u64::try_from(by.as_millis()).expect("a duration");
        Duration::from_millis(ms + ms * ppm / 1_000_000)
    }

    /// The machine a host runs on: its wall clock, and the boot clock of the boot it is in.
    #[derive(Clone)]
    struct Machine {
        wall: Arc<AtomicU64>,
        boot_clock: ManualSharedClock,
        boot: BootIdentity,
    }

    impl Machine {
        fn new() -> Self {
            Self {
                wall: Arc::new(AtomicU64::new(START)),
                boot_clock: ManualSharedClock::new(),
                boot: boot(1),
            }
        }

        fn set_wall(&self, ms: u64) {
            self.wall.store(ms, Ordering::SeqCst);
        }

        fn wall(&self) -> u64 {
            self.wall.load(Ordering::SeqCst)
        }

        /// Time passes while no run of the host is there to see it, on a boot clock that runs
        /// `ppm` parts per million fast against the wall clock.
        fn pass_fast(&self, by: Duration, ppm: u64) {
            let ms = u64::try_from(by.as_millis()).expect("a duration");
            self.wall.fetch_add(ms, Ordering::SeqCst);
            self.boot_clock.advance(fast(by, ppm));
        }

        fn pass(&self, by: Duration) {
            self.pass_fast(by, 0);
        }

        /// The machine starts again: another boot, whose clock begins at nothing.
        fn reboot(&mut self) {
            self.boot = boot(2);
            self.boot_clock = ManualSharedClock::new();
        }
    }

    /// One run of the host: its own continuous clock, over the machine's.
    struct Run {
        machine: Machine,
        continuous: ManualClock,
        trust: ClockTrust,
    }

    impl Run {
        fn on(machine: &Machine) -> Self {
            Self::over(machine, Arc::new(UtcFloor::at(0)))
        }

        fn over(machine: &Machine, floor: Arc<UtcFloor>) -> Self {
            Self::reading(
                machine,
                floor,
                ManualClock::new(),
                Arc::new(machine.boot_clock.clone()),
            )
        }

        fn reading(
            machine: &Machine,
            floor: Arc<UtcFloor>,
            continuous: ManualClock,
            boot_clock: Arc<dyn SharedClock>,
        ) -> Self {
            let wall = Arc::clone(&machine.wall);
            let trust = ClockTrust::new(
                crate::service::WallClock::from_fn(move || wall.load(Ordering::SeqCst)),
                floor,
                Arc::new(continuous.clone()),
                boot_clock,
                machine.boot.clone(),
            );
            Self {
                machine: machine.clone(),
                continuous,
                trust,
            }
        }

        /// Time passes: every clock this run reads moves on, the continuous one `ppm` parts per
        /// million fast against the wall clock.
        fn pass_fast(&self, by: Duration, ppm: u64) {
            self.machine.pass_fast(by, ppm);
            self.continuous.advance(fast(by, ppm));
        }

        fn pass(&self, by: Duration) {
            self.pass_fast(by, 0);
        }
    }

    /// A device store that outlives a run of the host, so a restart reads what the last wrote.
    struct Store {
        temp: kr_ipc::testing::TempHost,
    }

    impl Store {
        fn new() -> Self {
            Self {
                temp: kr_ipc::testing::TempHost::create(),
            }
        }

        fn open(&self) -> DeviceDirectory {
            DeviceDirectory::open(self.temp.environment().registry_database())
                .expect("the device store opens")
        }
    }

    /// Every way the host reads its clock.
    #[derive(Clone, Copy, Debug)]
    enum Reader {
        Sample,
        Observe,
        Watch,
    }

    /// One reading by `reader`.
    fn read(run: &Run, devices: &DeviceDirectory, reader: Reader) -> Result<()> {
        match reader {
            Reader::Sample => run.trust.sample(devices).map(|_| ()),
            Reader::Observe => run.trust.observe(devices).map(|_| ()),
            Reader::Watch => run.trust.watch(devices, true).map(|_| ()),
        }
    }

    /// Whether a grant is decided against the clock now.
    fn proven(run: &Run, devices: &DeviceDirectory) -> bool {
        run.trust.sample(devices).expect("samples").is_some()
    }

    /// Makes the later writes of the store fail, as a full disk does, for a write of `column`.
    fn refuse_writes_of(devices: &DeviceDirectory, column: &str) {
        devices
            .with(|connection| {
                connection.execute_batch(&format!(
                    "CREATE TRIGGER refuse_{column} BEFORE UPDATE OF {column} ON network_clock
                     BEGIN SELECT RAISE(ABORT, 'the store is full'); END;"
                ))
            })
            .expect("the store takes a trigger");
    }

    fn allow_writes_of(devices: &DeviceDirectory, column: &str) {
        devices
            .with(|connection| connection.execute_batch(&format!("DROP TRIGGER refuse_{column};")))
            .expect("the trigger goes");
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a step back smaller than the time between two readings is a
    /// rollback, found by whoever reads next and recorded for every reader. The wall clock reads ten
    /// seconds behind where a minute of continuous time put it, which a comparison with the last
    /// wall reading alone does not see. The wall clock is then put right again, so that only a
    /// decision recorded by the reader that found it can be what the next grant is refused on. The
    /// controls are a wall clock that moved with the continuous clock, which no reader distrusts,
    /// and one owner retrust, which every reader trusts again.
    #[test]
    fn a_step_back_smaller_than_the_time_between_two_readings_is_found_by_whoever_reads() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            let devices = DeviceDirectory::in_memory().expect("a directory");
            let machine = Machine::new();
            let run = Run::on(&machine);
            read(&run, &devices, reader).expect("reads");

            run.pass(MINUTE);
            read(&run, &devices, reader).expect("reads");
            assert!(
                proven(&run, &devices),
                "{reader:?}: a wall clock that kept up with the continuous clock is not distrusted"
            );

            run.continuous.advance(MINUTE);
            machine.boot_clock.advance(MINUTE);
            machine.set_wall(machine.wall() + 50_000);
            read(&run, &devices, reader).expect("reads");
            machine.set_wall(machine.wall() + 10_000);
            assert!(
                !proven(&run, &devices),
                "{reader:?} found a wall clock ten seconds behind the continuous clock"
            );
            assert!(!run.trust.watch(&devices, true).expect("watches").proven);

            run.trust
                .establish(&devices)
                .expect("the owner establishes");
            assert!(proven(&run, &devices), "{reader:?}: one retrust clears it");
            assert!(run.trust.watch(&devices, true).expect("watches").proven);
        }
    }

    /// KR-REQ-17.53: what a caller inside a store's transaction asks of the clock without a lock
    /// follows the state of trust. A host that has read nothing does not trust its clock, one that
    /// has read it plausible does, a rollback found by a reading ends it for the next asker before
    /// anything is written, an establishment restores it, and a lost continuity ends it whatever
    /// else holds.
    #[test]
    fn what_is_asked_without_the_lock_follows_the_state_of_trust() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        assert!(!run.trust.is_trusted_now(), "nothing read yet");
        assert!(proven(&run, &devices));
        assert!(run.trust.is_trusted_now());

        run.continuous.advance(MINUTE);
        machine.boot_clock.advance(MINUTE);
        machine.set_wall(machine.wall() + 50_000);
        run.trust.sample(&devices).expect("reads");
        machine.set_wall(machine.wall() + 10_000);
        assert!(!proven(&run, &devices), "the step back is found");
        assert!(
            !run.trust.is_trusted_now(),
            "and no asker is told otherwise"
        );

        run.trust
            .establish(&devices)
            .expect("the owner establishes");
        assert!(run.trust.is_trusted_now());

        run.trust.floor.lose_continuity();
        assert!(
            !run.trust.is_trusted_now(),
            "a lost continuity proves nothing"
        );
        run.trust.floor.establish_continuity();
        assert!(run.trust.is_trusted_now());
    }

    /// KR-REQ-17.53: the question is answered while a reader holds the state's lock. A reader holds
    /// it across its write to the file an enrolment's transaction holds, so a caller inside that
    /// transaction that waited for the lock would wait until the write gave up.
    #[test]
    fn what_is_asked_without_the_lock_does_not_wait_for_a_reader() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        assert!(proven(&run, &devices));

        let reader = run.trust.held();
        let (answered, answer) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                answered
                    .send(run.trust.is_trusted_now())
                    .expect("the test waits");
            });
            let got = answer.recv_timeout(Duration::from_secs(30));
            // Let go before judging, so an asker that waited for the lock ends and the test fails
            // rather than hangs.
            drop(reader);
            assert_eq!(
                got,
                Ok(true),
                "the asker is answered while the lock is held"
            );
        });
    }

    /// KR-REQ-09.18: a rollback met by one reading and gone before any other reader looks is still
    /// recorded, in memory and in the record: the clock reads plausibly again, and the host still
    /// distrusts it, across a restart too.
    #[test]
    fn a_rollback_met_by_one_reading_and_gone_before_another_looks_is_recorded() {
        let store = Store::new();
        let devices = store.open();
        let machine = Machine::new();
        let run = Run::on(&machine);
        assert!(run.trust.watch(&devices, true).expect("watches").proven);

        machine.set_wall(START - 60_000);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(!watched.proven, "the step back is found");
        machine.set_wall(START + 60_000);
        assert!(!proven(&run, &devices));
        assert!(
            devices
                .clock_record()
                .expect("the record")
                .untrusted_at_ms
                .is_some(),
            "and written down"
        );

        let restarted = Run::on(&machine);
        assert!(
            !proven(&restarted, &store.open()),
            "a restart reads the distrust back"
        );
    }

    /// KR-REQ-09.18: a mark the store refuses to take does not lose a rollback the reading found.
    /// The reading is answered as an error, because a host that cannot tell decides nothing, and
    /// what the mark and the anchor held in memory proved is decided all the same: once the store
    /// takes writes again and the wall clock reads plausibly, the host still distrusts it.
    #[test]
    fn a_mark_that_cannot_be_written_does_not_lose_the_rollback_a_reading_found() {
        for reader in [Reader::Sample, Reader::Observe] {
            let store = Store::new();
            let devices = store.open();
            let machine = Machine::new();
            let run = Run::on(&machine);
            read(&run, &devices, reader).expect("reads");

            refuse_writes_of(&devices, "observed_ms");
            run.continuous.advance(MINUTE);
            machine.boot_clock.advance(MINUTE);
            machine.set_wall(machine.wall() + 50_000);
            assert!(
                read(&run, &devices, reader).is_err(),
                "{reader:?}: the store refuses the mark"
            );
            allow_writes_of(&devices, "observed_ms");
            machine.set_wall(machine.wall() + 10_000);
            assert!(
                !proven(&run, &devices),
                "{reader:?}: the rollback that reading saw is not lost with its write"
            );
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: what the host knew of its clock before a restart in the same
    /// boot is what it measures a step back against after it. The wall clock is corrected back by
    /// ten seconds while no run is there to see it; the mark on disk is behind the wall clock, so
    /// only the anchor carried forward by the boot clock shows the correction.
    #[test]
    fn a_restart_in_the_same_boot_keeps_the_time_that_passed() {
        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));

        machine.pass(MINUTE);
        machine.set_wall(machine.wall() - 10_000);
        let second = Run::on(&machine);
        assert!(
            !proven(&second, &store.open()),
            "the wall clock reads ten seconds behind where the minute put it"
        );
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a restored anchor is held to a tolerance reduced by the step the
    /// host does not write, until the host has read the clock past it. A step smaller than 250 ms
    /// is not written, so an anchor read back may be that far behind the truth and a rollback
    /// measured against it would look that much smaller. After a restart in the same boot a wall
    /// clock 4.9 s behind where the minute put it is found, which the full 5 s would forgive; once
    /// the host has read a step past the restored anchor the full tolerance applies again.
    #[test]
    fn a_restored_anchor_is_held_to_a_tolerance_reduced_by_the_step_the_host_does_not_write() {
        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));
        machine.pass(MINUTE);
        machine.set_wall(machine.wall() - 4_900);
        let restarted = Run::on(&machine);
        assert!(
            !proven(&restarted, &store.open()),
            "4.9 s behind is a rollback against a restored anchor"
        );

        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));
        machine.pass(MINUTE);
        let restarted = Run::on(&machine);
        assert!(proven(&restarted, &store.open()));
        // A reading a step beyond the restored anchor ends the allowance: the anchor is now the
        // host's own, and the full tolerance applies. The wall clock runs a second ahead of the
        // continuous clock, as a correction forward does.
        restarted.pass(Duration::from_secs(1));
        machine.set_wall(machine.wall() + 1_000);
        assert!(proven(&restarted, &store.open()));
        machine.set_wall(machine.wall() - 4_900);
        assert!(
            proven(&restarted, &store.open()),
            "4.9 s behind is within the tolerance once the host has read past the restored anchor"
        );
    }

    /// KR-REQ-09.19: an evidence hold whose write failed stays in memory, withholds attention while
    /// it is owed, is written by the next reading, and survives a restart: the platform qualifying
    /// again lifts nothing.
    #[test]
    fn an_evidence_hold_that_could_not_be_written_is_written_by_the_next_reading() {
        let store = Store::new();
        let machine = Machine::new();
        let run = Run::on(&machine);
        let devices = store.open();
        // The record's row exists once a reading has made its mark, so the hold is an update.
        assert!(proven(&run, &devices));

        refuse_writes_of(&devices, "evidence_hold_at_ms");
        let watched = run.trust.watch(&devices, false).expect("watches");
        assert!(!watched.proven && watched.owed);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(
            !watched.proven && watched.owed,
            "the platform qualifying again does not lift it while it is owed"
        );
        assert!(
            devices
                .clock_record()
                .expect("the record")
                .evidence_hold_at_ms
                .is_none()
        );

        allow_writes_of(&devices, "evidence_hold_at_ms");
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(!watched.proven && !watched.owed, "written by the reading");
        let restarted = Run::on(&machine);
        assert!(
            !restarted
                .trust
                .watch(&store.open(), true)
                .expect("watches")
                .proven,
            "and it survives a restart"
        );
    }

    /// KR-REQ-09.17, KR-REQ-09.18: the restored anchor is never short of the time that passed
    /// between the two readings the restart makes. The host reads its continuous clock and then the
    /// boot clock; ten seconds pass right after the second reading, a descheduled thread's pause, and
    /// the wall clock is corrected to read eight seconds behind where they put it. The restored
    /// anchor stands at the earlier instant with the time up to the later reading, so the
    /// correction is found; read the other way round the pause would be lost from the anchor.
    #[test]
    fn a_restart_paused_between_its_two_clock_readings_does_not_lose_the_pause() {
        /// A boot clock that lets time pass right after its first reading.
        struct Pausing {
            inner: ManualSharedClock,
            after_a_reading: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
        }

        impl std::fmt::Debug for Pausing {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("Pausing")
            }
        }

        impl SharedClock for Pausing {
            fn boot_elapsed_ms(&self) -> u64 {
                let reading = self.inner.boot_elapsed_ms();
                let pause = self
                    .after_a_reading
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(pause) = pause {
                    pause();
                }
                reading
            }
        }

        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));
        machine.pass(MINUTE);

        let continuous = ManualClock::new();
        let pause = {
            let machine = machine.clone();
            let continuous = continuous.clone();
            move || {
                continuous.advance(Duration::from_secs(10));
                machine.boot_clock.advance(Duration::from_secs(10));
                machine.set_wall(START + 62_000);
            }
        };
        let boot_clock = Arc::new(Pausing {
            inner: machine.boot_clock.clone(),
            after_a_reading: std::sync::Mutex::new(Some(Box::new(pause))),
        });
        let restarted = Run::reading(&machine, Arc::new(UtcFloor::at(0)), continuous, boot_clock);
        assert!(
            !proven(&restarted, &store.open()),
            "the pause is in the anchor, so a wall clock eight seconds behind is found"
        );
    }

    /// KR-REQ-09.17: a restart in another boot keeps the wall reading and starts the continuous
    /// side from now. The boot clock restarted, so the anchor is not carried forward by it: the
    /// reading it gives is the age of a boot that began after the anchor was written, a lower
    /// bound that holds only while the boot identity can be relied on, and the anchor claims no
    /// more than the wall reading it recorded. A clock past that reading is trusted in the new
    /// boot; one behind the mark kept is found, by the mark.
    #[test]
    fn a_restart_in_a_new_boot_keeps_the_wall_reading_and_not_the_boot_clock() {
        let store = Store::new();
        let mut machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));

        machine.reboot();
        machine.boot_clock.advance(HOUR);
        machine.set_wall(START + 30_000);
        let second = Run::on(&machine);
        assert!(
            proven(&second, &store.open()),
            "a clock that kept going is trusted in the next boot"
        );
        machine.set_wall(START - 60_000);
        assert!(
            !proven(&second, &store.open()),
            "and one that went back is not"
        );
    }

    /// KR-REQ-09.17, KR-REQ-09.18: the anchor a restart in a new boot rebuilds is written against
    /// that boot, so a second restart in it measures from there. The host reads once in the new
    /// boot, goes down, the wall clock is corrected back ten seconds while it is down, and it
    /// starts again in the same boot: the correction is found by the anchor, which the mark does
    /// not show.
    #[test]
    fn a_second_restart_in_a_new_boot_keeps_the_time_that_passed() {
        let store = Store::new();
        let mut machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));

        // The wall clock reads what the first boot last saw, so the first reading in the new boot
        // is not a step forward that would be written for its own sake.
        machine.reboot();
        let second = Run::on(&machine);
        assert!(proven(&second, &store.open()));

        machine.pass(MINUTE);
        machine.set_wall(machine.wall() - 10_000);
        let third = Run::on(&machine);
        assert!(
            !proven(&third, &store.open()),
            "the wall clock reads ten seconds behind where the minute put it"
        );
    }

    /// KR-REQ-09.18: a forward step that only a watching reader saw is kept. The mark on disk stays
    /// behind it, because the watching reader writes none, so it is the anchor that carries the
    /// peak across a restart and a rollback below it is found.
    #[test]
    fn a_forward_peak_seen_only_by_a_watch_survives_a_restart() {
        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        let devices = store.open();
        assert!(first.trust.watch(&devices, true).expect("watches").proven);
        let peak = START + 30 * 86_400_000;
        machine.set_wall(peak);
        assert!(first.trust.watch(&devices, true).expect("watches").proven);
        let record = devices.clock_record().expect("the record");
        assert!(
            record.observed_ms.expect("a mark") < peak,
            "the mark on disk is behind the peak"
        );
        assert_eq!(record.anchor.expect("an anchor").wall_ms, peak);

        machine.set_wall(peak - 60_000);
        let second = Run::on(&machine);
        assert!(
            !proven(&second, &store.open()),
            "a rollback below the peak is found after the restart"
        );
    }

    /// KR-REQ-09.18: a step whose write failed stays owed, withholds every forgetting while it is,
    /// and is written again by the next reading, which is not itself a step: a restart does not
    /// forget the peak. A grant and attention's quiet hours are decided meanwhile, as the record is
    /// no part of what they measure against; what a restart would lose is what a delete cannot
    /// take back.
    #[test]
    fn a_step_that_could_not_be_written_is_written_before_the_next_answer() {
        let store = Store::new();
        let machine = Machine::new();
        let run = Run::on(&machine);
        let devices = store.open();
        run.trust.watch(&devices, true).expect("watches");

        refuse_writes_of(&devices, "anchor_wall_ms");
        let peak = START + 86_400_000;
        machine.set_wall(peak);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(watched.owed, "the step is owed");
        assert!(
            watched.proven,
            "quiet hours are decided from the clock now, which the record does not bear on"
        );
        assert!(run.trust.owes_a_write());
        assert!(
            run.trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_none(),
            "no forgetting is decided until the record has caught up"
        );
        assert!(proven(&run, &devices), "a grant is decided as before");
        assert_ne!(
            devices
                .clock_record()
                .expect("the record")
                .anchor
                .expect("an anchor")
                .wall_ms,
            peak
        );

        allow_writes_of(&devices, "anchor_wall_ms");
        // Not a step: the wall clock reads a little behind the anchor.
        machine.set_wall(peak - 100);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(!watched.owed, "the next answer wrote what was owed");
        assert!(watched.proven);
        assert_eq!(
            devices
                .clock_record()
                .expect("the record")
                .anchor
                .expect("an anchor")
                .wall_ms,
            peak
        );
    }

    /// KR-REQ-09.18: a distrust whose write failed is held in memory, withholds what it affects,
    /// and is written by the next reading with nothing else to prompt it, then survives a restart.
    /// A forward correction in between keeps it owed: it is the decision, not the reading.
    #[test]
    fn a_distrust_that_could_not_be_written_is_written_by_the_next_reading() {
        let store = Store::new();
        let machine = Machine::new();
        let run = Run::on(&machine);
        let devices = store.open();
        run.trust.watch(&devices, true).expect("watches");

        refuse_writes_of(&devices, "untrusted_at_ms");
        machine.set_wall(START - 60_000);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(!watched.proven && watched.owed);
        machine.set_wall(START + 60_000);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(
            !watched.proven && watched.owed,
            "a forward correction does not take the decision back"
        );
        assert!(!proven(&run, &devices));
        assert!(
            devices
                .clock_record()
                .expect("the record")
                .untrusted_at_ms
                .is_none()
        );

        allow_writes_of(&devices, "untrusted_at_ms");
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(!watched.proven && !watched.owed, "written by the reading");
        let restarted = Run::on(&machine);
        assert!(!proven(&restarted, &store.open()));
    }

    /// KR-REQ-09.19: an owner's establishing is complete when it reports success. A record that
    /// refuses it leaves the decision standing, whatever the wall clock reads meanwhile.
    #[test]
    fn an_establish_the_record_refuses_leaves_the_decision_standing() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        run.trust.sample(&devices).expect("samples");
        machine.set_wall(START - 60_000);
        assert!(!proven(&run, &devices));

        refuse_writes_of(&devices, "confirmed_at_ms");
        assert!(run.trust.establish(&devices).is_err());
        machine.set_wall(START + 60_000);
        assert!(!proven(&run, &devices), "the decision stands");
        allow_writes_of(&devices, "confirmed_at_ms");
        run.trust
            .establish(&devices)
            .expect("the owner establishes");
        assert!(proven(&run, &devices));
    }

    /// KR-REQ-09.19: a reader delayed across an owner's establishing takes its reading inside the
    /// transition. The wall clock read low before the owner corrected it and read right after; the
    /// reader that was about to read when the owner established takes the clock as it stands once
    /// it holds the lock, so it does not find a rollback in a reading that went stale meanwhile.
    #[test]
    fn a_reader_delayed_across_an_establish_reads_the_clock_after_it() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        assert!(run.trust.watch(&devices, true).expect("watches").proven);

        let (arrived, release) = run.trust.before_watch.arm();
        let watched = std::thread::scope(|scope| {
            let reader = scope.spawn(|| run.trust.watch(&devices, true).expect("watches"));
            arrived
                .recv()
                .expect("the reader is about to take the lock");
            // The wall clock reads an hour low, and then the owner corrects it and establishes.
            machine.set_wall(START - 3_600_000);
            machine.set_wall(START + 10_000);
            run.trust
                .establish(&devices)
                .expect("the owner establishes");
            release.send(()).expect("the reader goes on");
            reader.join().expect("the reader ends")
        });
        assert!(
            watched.proven,
            "the owner's establishing is not undone by a reading from before it"
        );
        assert_eq!(
            watched.wall_ms,
            START + 10_000,
            "the clock as it stood after"
        );
        assert!(proven(&run, &devices));
    }

    /// KR-REQ-09.18: every reading of the wall clock and of the continuous clock, by every way of
    /// reading the host's clock and by an owner's establishing, is taken while the state lock is
    /// held, so a caller that waited for the lock cannot contribute a reading from before it.
    #[test]
    fn every_reading_of_the_clocks_is_taken_inside_the_lock() {
        /// A clock that says whether the state lock is held when it is read.
        #[derive(Debug)]
        struct Probed {
            clock: ManualClock,
            trust: Arc<OnceLock<Weak<ClockTrust>>>,
        }

        impl Probed {
            fn check(&self) {
                if let Some(trust) = self.trust.get().and_then(Weak::upgrade) {
                    assert!(
                        trust.state.try_lock().is_err(),
                        "a clock was read outside the lock"
                    );
                }
            }
        }

        impl ContinuousClock for Probed {
            fn now(&self) -> ContinuousInstant {
                self.check();
                self.clock.now()
            }
        }

        let devices = DeviceDirectory::in_memory().expect("a directory");
        let trust_cell = Arc::new(OnceLock::new());
        let wall = Arc::new(Probed {
            clock: ManualClock::new(),
            trust: Arc::clone(&trust_cell),
        });
        let machine = Machine::new();
        let reading = Arc::clone(&machine.wall);
        let trust = Arc::new(ClockTrust::new(
            crate::service::WallClock::from_fn({
                let wall = Arc::clone(&wall);
                move || {
                    wall.check();
                    reading.load(Ordering::SeqCst)
                }
            }),
            Arc::new(UtcFloor::at(0)),
            Arc::clone(&wall) as Arc<dyn ContinuousClock>,
            Arc::new(machine.boot_clock.clone()),
            machine.boot.clone(),
        ));
        trust_cell
            .set(Arc::downgrade(&trust))
            .expect("the probe is set once");

        trust.sample(&devices).expect("samples");
        trust.sample_for_forgetting(&devices).expect("samples");
        trust.observe(&devices).expect("observes");
        trust.watch(&devices, true).expect("watches");
        trust.settle(&devices).expect("settles");
        trust.establish(&devices).expect("the owner establishes");
        trust.sample(&devices).expect("samples");
    }

    /// KR-REQ-09.19: when the platform's time service does not qualify and the owner has not
    /// confirmed the clock, attention's forgetting and quiet hours are withheld by a hold, and a
    /// grant is decided as before. The service qualifying again does not lift it, in the same run
    /// or after a restart; only the owner's establishing does, and a later rollback closes
    /// attention again.
    #[test]
    fn an_unqualified_platform_holds_attention_until_the_owner_establishes_the_clock() {
        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        let devices = store.open();

        assert!(
            !first.trust.watch(&devices, false).expect("watches").proven,
            "an unqualified service proves nothing"
        );
        assert!(proven(&first, &devices), "a grant is decided as before");
        assert!(
            first
                .trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_some(),
            "the transfer sweep and the voice spends are not held by the platform"
        );
        assert!(
            !first.trust.watch(&devices, true).expect("watches").proven,
            "the service qualifying again does not lift the hold"
        );

        let restarted = Run::on(&machine);
        assert!(
            !restarted
                .trust
                .watch(&store.open(), true)
                .expect("watches")
                .proven,
            "nor does a restart"
        );

        restarted
            .trust
            .establish(&store.open())
            .expect("the owner establishes");
        assert!(
            restarted
                .trust
                .watch(&store.open(), false)
                .expect("watches")
                .proven,
            "the owner's confirmation stands where the platform has none to give"
        );

        machine.set_wall(START - 60_000);
        assert!(
            !restarted
                .trust
                .watch(&store.open(), true)
                .expect("watches")
                .proven,
            "a later rollback closes attention again"
        );
        assert!(
            store
                .open()
                .clock_record()
                .expect("the record")
                .confirmed_at_ms
                .is_none(),
            "and takes the owner's confirmation with it"
        );
    }

    /// A host whose platform qualifies from the start has nothing held against it.
    #[test]
    fn a_qualified_platform_proves_the_clock_to_attention() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        let watched = run.trust.watch(&devices, true).expect("watches");
        assert!(watched.proven && !watched.owed);
        assert_eq!(watched.wall_ms, START);
    }

    /// Every reading the clock decision takes is published in the host's floor before anything is
    /// decided from it, and the moment decided from is the floor's value, whichever process raised
    /// it. The raw sample still decides a rollback: the floor only moves forward.
    #[test]
    fn a_sample_is_published_and_decided_from_the_floor() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&floor));
        let sampled = run
            .trust
            .sample(&devices)
            .expect("readable")
            .expect("a trusted clock");
        assert_eq!(sampled.now.get(), START);
        assert_eq!(floor.get(), START, "the sample is in the floor");

        // Another process of the host publishes a later reading: it is the moment decided from.
        floor.observe(START + 10_000);
        let sampled = run
            .trust
            .sample(&devices)
            .expect("readable")
            .expect("a trusted clock");
        assert_eq!(sampled.now.get(), START + 10_000);
        assert_eq!(
            run.trust.observe(&devices).expect("readable").get(),
            START + 10_000,
            "a reading taken for a record is the floor's value too"
        );

        // The control: a step back past the tolerance still distrusts the clock, although the
        // floor stands above the sample.
        machine.set_wall(START - 60_000);
        assert!(run.trust.sample(&devices).expect("readable").is_none());
        assert_eq!(floor.get(), START + 10_000);
    }

    /// The moment a grant is decided against is never behind what the continuous clock says has
    /// passed since the anchor: a wall clock four seconds short, which the tolerance forgives,
    /// does not give a grant those four seconds back.
    #[test]
    fn a_step_back_the_tolerance_forgives_gives_no_grant_the_time_back() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        run.trust.sample(&devices).expect("samples");
        run.continuous.advance(MINUTE);
        machine.boot_clock.advance(MINUTE);
        machine.set_wall(machine.wall() + 56_000);
        let sampled = run
            .trust
            .sample(&devices)
            .expect("samples")
            .expect("four seconds short is forgiven");
        assert!(
            sampled.now.get() > START + 56_000,
            "the grant is measured from where the minute put the clock, not from where it reads"
        );
    }

    /// While this boot's clock continuity is lost there is no reading anything may be decided
    /// against, whatever the wall clock says, until the owner establishes the clock.
    #[test]
    fn a_lost_clock_continuity_is_a_clock_this_host_does_not_trust() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&floor));
        assert!(run.trust.sample(&devices).expect("readable").is_some());
        floor.lose_continuity();
        assert!(run.trust.sample(&devices).expect("readable").is_none());
        floor.establish_continuity();
        assert!(run.trust.sample(&devices).expect("readable").is_some());
    }

    /// KR-REQ-09.19: what the floor shows the workers of the owner's confirmation is what the
    /// record holds. An establishment is published with the reading it was made at; a rollback
    /// that distrusts the clock withdraws it; the next establishment publishes again. In a new boot
    /// the floor starts empty, and a record that still holds the owner's confirmation says so with
    /// the first reading taken, while a record that distrusts the clock says nothing.
    #[test]
    fn the_floor_shows_the_workers_the_confirmation_the_record_holds() {
        let store = Store::new();
        let devices = store.open();
        let mut machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&floor));
        let words = || floor.words().established();

        assert!(proven(&run, &devices));
        assert_eq!(words(), None, "no owner has confirmed anything");

        run.trust
            .establish(&devices)
            .expect("the owner establishes");
        let first = words().expect("the establishment is published");
        assert!(
            !first.restated,
            "an action of the owner is not a restatement"
        );
        assert_eq!(first.wall_ms, machine.wall());
        assert_eq!(first.boot_ms, machine.boot_clock.boot_elapsed_ms());

        machine.set_wall(machine.wall() - 60_000);
        assert!(!proven(&run, &devices), "the step back distrusts the clock");
        assert_eq!(words(), None, "and withdraws the confirmation");

        run.trust
            .establish(&devices)
            .expect("the owner establishes again");
        let second = words().expect("published again");
        assert!(second.count > first.count + 1, "after the withdrawal");
        assert_eq!(second.wall_ms, machine.wall());

        // Another boot: an empty floor, and a record that holds the confirmation says so once.
        drop(run);
        machine.reboot();
        let fresh = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&fresh));
        assert_eq!(fresh.words().established(), None);
        assert!(proven(&run, &devices));
        let said = fresh
            .words()
            .established()
            .expect("the first reading tells the workers the owner's word stands");
        assert_eq!(said.wall_ms, machine.wall());
        assert!(said.restated, "and says it as a restatement");

        // A record that distrusts the clock says nothing in a new boot.
        machine.set_wall(machine.wall() - 60_000);
        assert!(!proven(&run, &devices));
        drop(run);
        machine.reboot();
        let later = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&later));
        assert!(
            !proven(&run, &devices),
            "the record still distrusts the clock"
        );
        assert_eq!(later.words().established(), None);
    }

    /// KR-REQ-09.19: a publication the daemon did not complete is made good at its next reading,
    /// as a restatement. The owner's confirmation is in the record, and the floor shows the
    /// workers a withdrawal (a distrust the record has since ended) or half of a publication: the
    /// next reading states the confirmation in force. A boot whose clock continuity is lost
    /// states nothing, and states it once the owner has established the clock.
    #[test]
    fn a_publication_that_did_not_complete_is_made_good_at_the_next_reading() {
        let store = Store::new();
        let devices = store.open();
        let machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let run = Run::over(&machine, Arc::clone(&floor));
        assert!(proven(&run, &devices));
        run.trust
            .establish(&devices)
            .expect("the owner establishes");
        assert!(floor.words().established().is_some());

        // The daemon stopped after the commit and before its stores in a boot that had published
        // a withdrawal: the floor shows the withdrawal and the record the confirmation.
        floor.words().withdraw();
        assert_eq!(floor.words().established(), None);
        assert!(proven(&run, &devices));
        let stated = floor
            .words()
            .established()
            .expect("the next reading says it");
        assert_eq!(stated.wall_ms, machine.wall(), "what the record holds");
        assert!(stated.restated);

        // Or between the two stores of a publication.
        floor.words().leave_half_published(machine.wall() + 1);
        assert_eq!(floor.words().established(), None);
        assert!(proven(&run, &devices));
        let stated = floor
            .words()
            .established()
            .expect("the next reading says it");
        assert_eq!(stated.wall_ms, machine.wall());

        // A boot whose continuity is lost has no reading to say it with, until the owner has
        // established the clock.
        let lost = Arc::new(UtcFloor::at(0));
        lost.lose_continuity();
        let run = Run::over(&machine, Arc::clone(&lost));
        let _ = run.trust.sample(&devices);
        assert_eq!(lost.words().established(), None);
        lost.establish_continuity();
        assert!(proven(&run, &devices));
        assert!(lost.words().established().is_some());
    }

    /// KR-REQ-09.19: the pair the daemon shows the workers is taken in the order an establishment
    /// takes it: the boot clock before the wall clock, so a pause between the two samples leaves
    /// the pair asking more of a worker's clock and never less. The wall clock here, when it is
    /// read, lets a minute pass on the boot clock first and moves itself on half a minute only, as
    /// a reading that paused between its samples while the wall clock was slowed would find: the
    /// boot reading shown is the one taken before the pause, so a worker that begins later
    /// projects the wall reading from where it was taken and finds its own clock a minute short of
    /// it: the half minute the wall clock lost against the boot clock, and the half minute it ran
    /// during the pause.
    #[test]
    fn the_pair_shown_to_the_workers_is_taken_boot_clock_first() {
        let store = Store::new();
        let devices = store.open();
        let machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let pausing = Arc::new(AtomicU64::new(0));
        let trust = {
            let wall = Arc::clone(&machine.wall);
            let boot_clock = machine.boot_clock.clone();
            let pausing = Arc::clone(&pausing);
            ClockTrust::new(
                crate::service::WallClock::from_fn(move || {
                    if pausing.swap(0, Ordering::SeqCst) == 1 {
                        boot_clock.advance(MINUTE);
                        wall.fetch_add(30_000, Ordering::SeqCst);
                    }
                    wall.load(Ordering::SeqCst)
                }),
                Arc::clone(&floor),
                Arc::new(ManualClock::new()),
                Arc::new(machine.boot_clock.clone()),
                machine.boot.clone(),
            )
        };
        assert!(trust.sample(&devices).expect("samples").is_some());
        trust.establish(&devices).expect("the owner establishes");
        floor.words().withdraw();

        let before = machine.boot_clock.boot_elapsed_ms();
        pausing.store(1, Ordering::SeqCst);
        let _ = trust.sample(&devices);
        let shown = floor.words().established().expect("stated by the reading");
        assert_eq!(
            shown.boot_ms, before,
            "the boot reading is the one taken before the pause"
        );
        assert_eq!(shown.wall_ms, machine.wall());
    }

    /// KR-REQ-09.18: a continuous clock that runs fast against the wall clock raises no distrust.
    /// Fifty parts per million is about four seconds a day; read every hour for thirty days and an
    /// hour, the host never distrusts its clock, never withholds a forgetting and never withholds
    /// attention. The rate allowance is what keeps the difference from accumulating until it is
    /// taken for a rollback, which only the owner's retrust would clear.
    #[test]
    fn a_continuous_clock_that_runs_fast_raises_no_distrust_in_thirty_days() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        for hour in 0..30 * 24 + 1 {
            run.pass_fast(HOUR, FIFTY_PPM);
            assert!(proven(&run, &devices), "hour {hour}: no distrust");
            assert!(
                run.trust
                    .sample_for_forgetting(&devices)
                    .expect("samples")
                    .is_some(),
                "hour {hour}: no forgetting is withheld"
            );
            assert!(
                run.trust.watch(&devices, true).expect("watches").proven,
                "hour {hour}: attention is not withheld"
            );
        }
    }

    /// KR-REQ-09.18: the same host that nobody read for thirty days: one reading after a
    /// continuous clock that ran fifty parts per million fast distrusts nothing. The wall clock
    /// reads about two minutes behind the continuous clock, which the allowance for thirty days
    /// covers.
    #[test]
    fn a_continuous_clock_that_ran_fast_unread_for_thirty_days_raises_no_distrust() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        assert!(proven(&run, &devices));
        run.pass_fast(30 * DAY, FIFTY_PPM);
        assert!(proven(&run, &devices));
        assert!(run.trust.watch(&devices, true).expect("watches").proven);
    }

    /// KR-REQ-09.18: a rollback larger than the allowance at that point still withholds every
    /// forgetting. After thirty days on a fast continuous clock, read every hour, a wall clock six
    /// seconds behind where it stood is a rollback; and after thirty days nobody read, one six
    /// minutes behind is.
    #[test]
    fn a_rollback_larger_than_the_allowance_is_found_after_thirty_days() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let run = Run::on(&machine);
        for _ in 0..30 * 24 {
            run.pass_fast(HOUR, FIFTY_PPM);
            assert!(proven(&run, &devices));
        }
        machine.set_wall(machine.wall() - 6_000);
        assert!(
            run.trust
                .sample_for_forgetting(&devices)
                .expect("samples")
                .is_none()
        );
        assert!(!run.trust.watch(&devices, true).expect("watches").proven);

        let unread = Run::on(&Machine::new());
        let devices = DeviceDirectory::in_memory().expect("a directory");
        assert!(proven(&unread, &devices));
        unread.pass_fast(30 * DAY, FIFTY_PPM);
        unread.machine.set_wall(unread.machine.wall() - 360_000);
        assert!(!proven(&unread, &devices));
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a restart in the same boot keeps neither a false distrust nor a
    /// missed rollback. After thirty days on a fast continuous clock the host goes down for two
    /// days on a boot clock that is just as fast (8.6 s more than the wall clock, beyond the
    /// restored tolerance of 4.75 s, so only the credit given to the restored anchor keeps it trusted), and
    /// starts again: it trusts the clock. Two more days, and a wall clock corrected six minutes
    /// back while it was down: it does not.
    #[test]
    fn a_restart_after_thirty_days_on_a_fast_clock_keeps_neither_a_false_distrust_nor_a_missed_rollback()
     {
        let store = Store::new();
        let machine = Machine::new();
        let run = Run::on(&machine);
        for _ in 0..30 * 24 + 1 {
            run.pass_fast(HOUR, FIFTY_PPM);
            assert!(proven(&run, &store.open()));
        }

        machine.pass_fast(2 * DAY, FIFTY_PPM);
        let restarted = Run::on(&machine);
        assert!(
            proven(&restarted, &store.open()),
            "two days on a fast clock are no rollback after a restart"
        );
        assert!(
            restarted
                .trust
                .watch(&store.open(), true)
                .expect("watches")
                .proven
        );

        machine.pass_fast(2 * DAY, FIFTY_PPM);
        machine.set_wall(machine.wall() - 360_000);
        let corrected = Run::on(&machine);
        assert!(
            !proven(&corrected, &store.open()),
            "the correction made while it was down is found"
        );
    }

    /// A pause of the host: every clock it reads moves on by `by`, the wall clock and the boot
    /// clock with the continuous one, as a stopped process or a paused machine finds them.
    #[derive(Clone)]
    struct Pause {
        machine: Machine,
        continuous: ManualClock,
        by: Duration,
        /// How many of the next readings the pause lands in.
        armed: Arc<AtomicU64>,
        /// The wall clock is set to `set_to` right after the pause has landed in a reading of it
        /// for the `set_after`th time, as an owner or a time service moves it while the host is
        /// held up.
        set_after: Arc<AtomicI64>,
        set_to: Arc<AtomicU64>,
    }

    impl Pause {
        fn new(machine: &Machine, continuous: &ManualClock, by: Duration) -> Self {
            Self {
                machine: machine.clone(),
                continuous: continuous.clone(),
                by,
                armed: Arc::new(AtomicU64::new(0)),
                set_after: Arc::new(AtomicI64::new(0)),
                set_to: Arc::new(AtomicU64::new(0)),
            }
        }

        fn arm(&self, times: u64) {
            self.armed.store(times, Ordering::SeqCst);
        }

        /// Sets the wall clock to `wall_ms` right after the pause has landed `landing` times.
        fn sets_the_wall_after(&self, landing: i64, wall_ms: u64) {
            self.set_to.store(wall_ms, Ordering::SeqCst);
            self.set_after.store(landing, Ordering::SeqCst);
        }

        /// Lets the pause pass when one is armed, and says whether it did.
        fn lands(&self) -> bool {
            let armed = self
                .armed
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if armed {
                self.machine.pass(self.by);
                self.continuous.advance(self.by);
            }
            armed
        }
    }

    /// A boot clock a pause lands around, just before a reading of it or just after.
    struct Holdup {
        inner: ManualSharedClock,
        pause: Pause,
        after: bool,
    }

    impl std::fmt::Debug for Holdup {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Holdup")
        }
    }

    impl SharedClock for Holdup {
        fn boot_elapsed_ms(&self) -> u64 {
            if !self.after {
                self.pause.lands();
            }
            let reading = self.inner.boot_elapsed_ms();
            if self.after {
                self.pause.lands();
            }
            reading
        }
    }

    /// A continuous clock a pause lands just before a reading of.
    #[derive(Debug)]
    struct Slipping {
        inner: ManualClock,
        pause: Pause,
    }

    impl std::fmt::Debug for Pause {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Pause")
        }
    }

    impl ContinuousClock for Slipping {
        fn now(&self) -> ContinuousInstant {
            self.pause.lands();
            self.inner.now()
        }
    }

    impl Run {
        /// A host whose wall clock lets `by` pass on every clock, in each reading of it that the
        /// returned pause is armed for.
        fn pausing(machine: &Machine, by: Duration) -> (Self, Pause) {
            Self::pausing_over(machine, Arc::new(UtcFloor::at(0)), by)
        }

        /// As [`Self::pausing`], publishing in `floor`.
        fn pausing_over(machine: &Machine, floor: Arc<UtcFloor>, by: Duration) -> (Self, Pause) {
            let continuous = ManualClock::new();
            let pause = Pause::new(machine, &continuous, by);
            let wall = Arc::clone(&machine.wall);
            let landing = pause.clone();
            let trust = ClockTrust::new(
                crate::service::WallClock::from_fn(move || {
                    let landed = landing.lands();
                    let reading = wall.load(Ordering::SeqCst);
                    if landed && landing.set_after.fetch_sub(1, Ordering::SeqCst) == 1 {
                        wall.store(landing.set_to.load(Ordering::SeqCst), Ordering::SeqCst);
                    }
                    reading
                }),
                floor,
                Arc::new(continuous.clone()),
                Arc::new(machine.boot_clock.clone()),
                machine.boot.clone(),
            );
            let run = Self {
                machine: machine.clone(),
                continuous,
                trust,
            };
            (run, pause)
        }
    }

    const PAUSE: Duration = Duration::from_secs(10);

    /// What a person is told when no reading could be taken, and what an owner is told besides
    /// when the clock was being established.
    const NOT_READ: &str = "this host could not read its clocks together just now: it was held \
        up between the readings in all three tries, so it decided nothing from them and its \
        clock trust has not changed; try again";
    const NOT_READ_ESTABLISHING: &str = "this host could not read its clocks together just now: \
        it was held up between the readings in all three tries, so it decided nothing from them \
        and its clock trust has not changed; try again; it did not spend the owner's confirmation";

    fn assert_not_read(error: &crate::error::ControllerError, text: &str) {
        use kr_protocol::error::{ErrorCode, RetryCategory};
        let shown = error.to_protocol_error();
        assert_eq!(shown.code, ErrorCode::ResourceUnavailable);
        assert_eq!(shown.retry, RetryCategory::Transient);
        assert_eq!(shown.message, text);
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a pause of the host inside one reading of its clocks is no
    /// rollback, at that reading or at the next. The wall clock lets ten seconds pass on every
    /// clock before it returns, in the middle of the reading; the reading is taken again, and the
    /// anchor it leaves is the clocks' own.
    #[test]
    fn a_pause_inside_a_reading_sets_no_distrust_at_that_reading_or_the_next() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            let devices = DeviceDirectory::in_memory().expect("a directory");
            let machine = Machine::new();
            let (run, pause) = Run::pausing(&machine, PAUSE);
            read(&run, &devices, reader).expect("reads");
            run.pass(MINUTE);
            pause.arm(1);
            read(&run, &devices, reader).expect("reads in spite of the pause");
            assert!(
                run.trust.is_trusted_now(),
                "{reader:?}: the pause is no rollback at that reading"
            );
            run.pass(MINUTE);
            read(&run, &devices, reader).expect("reads");
            assert!(
                run.trust.is_trusted_now(),
                "{reader:?}: and not at the next reading"
            );
            assert!(proven(&run, &devices), "{reader:?}: a grant is decided");
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: the same for an establishment: the anchor it leaves is not
    /// ahead of the clocks by the pause, so the next reading finds no step back.
    #[test]
    fn a_pause_inside_an_establishment_sets_no_distrust_at_the_next_reading() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let (run, pause) = Run::pausing(&machine, PAUSE);
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        pause.arm(1);
        run.trust
            .establish(&devices)
            .expect("establishes in spite of the pause");
        assert!(proven(&run, &devices), "no step back is found at once");
        run.pass(MINUTE);
        assert!(proven(&run, &devices), "nor later");
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a pause in the first try cannot hide a real step back. The wall
    /// clock is put back eight seconds, and ten seconds pass inside the reading: read once, that
    /// shows the wall clock two seconds ahead of where it was.
    #[test]
    fn a_step_back_is_found_at_the_reading_a_pause_was_in() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            let devices = DeviceDirectory::in_memory().expect("a directory");
            let machine = Machine::new();
            let (run, pause) = Run::pausing(&machine, PAUSE);
            read(&run, &devices, reader).expect("reads");
            run.pass(MINUTE);
            machine.set_wall(machine.wall() - 8_000);
            pause.arm(1);
            read(&run, &devices, reader).expect("reads in spite of the pause");
            assert!(
                !run.trust.is_trusted_now(),
                "{reader:?}: the step back is found at that reading"
            );
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a step back is measured at the later of the two readings of
    /// the continuous clock. The wall clock is put back five and a tenth seconds and the reading
    /// is held up for a fifth of a second, inside the bracket: measured at the earlier reading it
    /// is four and nine tenths, inside the tolerance.
    #[test]
    fn a_step_back_is_measured_at_the_later_reading_of_the_continuous_clock() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let (run, pause) = Run::pausing(&machine, Duration::from_millis(200));
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        machine.set_wall(machine.wall() - 5_100);
        pause.arm(1);
        read(&run, &devices, Reader::Sample).expect("reads");
        assert!(!run.trust.is_trusted_now());
    }

    /// KR-REQ-09.17, KR-REQ-09.18: the anchor a reading leaves is taken at the earlier of the two
    /// readings of the continuous clock. The reading is held up for a fifth of a second after the
    /// wall clock was read, inside the bracket; the wall clock is then put back five and a tenth
    /// seconds, a little over a second later. An anchor taken at the later reading would be short
    /// by the fifth of a second and would show four and nine tenths.
    #[test]
    fn the_anchor_is_taken_at_the_earlier_reading_of_the_continuous_clock() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let continuous = ManualClock::new();
        let pause = Pause::new(&machine, &continuous, Duration::from_millis(200));
        let after_the_wall = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trust = {
            let wall = Arc::clone(&machine.wall);
            let arming = pause.clone();
            let after_the_wall = Arc::clone(&after_the_wall);
            ClockTrust::new(
                crate::service::WallClock::from_fn(move || {
                    let reading = wall.load(Ordering::SeqCst);
                    if after_the_wall.swap(false, Ordering::SeqCst) {
                        arming.arm(1);
                    }
                    reading
                }),
                Arc::new(UtcFloor::at(0)),
                Arc::new(Slipping {
                    inner: continuous.clone(),
                    pause: pause.clone(),
                }),
                Arc::new(machine.boot_clock.clone()),
                machine.boot.clone(),
            )
        };
        let run = Run {
            machine: machine.clone(),
            continuous,
            trust,
        };
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        after_the_wall.store(true, Ordering::SeqCst);
        assert!(proven(&run, &devices), "the held-up reading is trusted");
        run.pass(Duration::from_millis(800));
        machine.set_wall(machine.wall() - 5_100);
        assert!(
            !proven(&run, &devices),
            "the step back is found against the anchor of the earlier reading"
        );
    }

    /// KR-REQ-09.17, KR-REQ-09.18: whether a reading is new proof is decided at the earlier of the
    /// two readings of the continuous clock, as the anchor is taken there. The wall clock steps
    /// 150 ms forward and the reading is held up for a fifth of a second
    /// after it was read, inside the bracket: at the earlier reading the wall is 156 ms past the
    /// projection and moves the anchor, at the later reading it is 44 ms short of it and would
    /// not. The wall clock is then put back until it stands 5,050 ms behind the anchor that the
    /// earlier reading made, which is 4,894 ms behind the anchor it would have been measured
    /// against otherwise; the durable mark, which holds the highest wall read, shows 4,050 ms.
    #[test]
    fn a_step_forward_inside_the_bracket_moves_the_anchor_where_the_earlier_reading_projects_it() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let continuous = ManualClock::new();
        let pause = Pause::new(&machine, &continuous, Duration::from_millis(200));
        let after_the_wall = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trust = {
            let wall = Arc::clone(&machine.wall);
            let arming = pause.clone();
            let after_the_wall = Arc::clone(&after_the_wall);
            ClockTrust::new(
                crate::service::WallClock::from_fn(move || {
                    let reading = wall.load(Ordering::SeqCst);
                    if after_the_wall.swap(false, Ordering::SeqCst) {
                        arming.arm(1);
                    }
                    reading
                }),
                Arc::new(UtcFloor::at(0)),
                Arc::new(Slipping {
                    inner: continuous.clone(),
                    pause: pause.clone(),
                }),
                Arc::new(machine.boot_clock.clone()),
                machine.boot.clone(),
            )
        };
        let run = Run {
            machine: machine.clone(),
            continuous,
            trust,
        };
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        machine.set_wall(machine.wall() + 150);
        after_the_wall.store(true, Ordering::SeqCst);
        assert!(proven(&run, &devices), "the held-up reading is trusted");
        run.pass(Duration::from_millis(800));
        machine.set_wall(machine.wall() - 5_050);
        assert!(
            !proven(&run, &devices),
            "the step back is found against the anchor that the step forward moved"
        );
    }

    /// KR-REQ-09.17, KR-REQ-09.18: three tries that are all held up give no reading: a refusal
    /// to try again, no distrust, and nothing owed. The only write is the raise of the durable
    /// mark that a stored reading makes at the reading itself, to the highest wall the tries read:
    /// a reader that keeps its mark in memory writes nothing. A step back made between the tries
    /// is found by the next clean reading, and a clock that did not go back is trusted by it.
    #[test]
    fn three_wide_tries_give_no_reading_and_decide_nothing() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            for step_back in [false, true] {
                let devices = DeviceDirectory::in_memory().expect("a directory");
                let machine = Machine::new();
                let (run, pause) = Run::pausing(&machine, PAUSE);
                read(&run, &devices, reader).expect("reads");
                run.pass(MINUTE);
                if step_back {
                    machine.set_wall(machine.wall() - 8_000);
                }
                let record = devices.clock_record().expect("the record");
                pause.arm(3);
                let error = read(&run, &devices, reader).expect_err("no reading is taken");
                let case = format!("{reader:?}, step back {step_back}");
                assert_not_read(&error, NOT_READ);
                assert_eq!(
                    error.code(),
                    kr_protocol::error::ErrorCode::ResourceUnavailable
                );
                assert!(run.trust.is_trusted_now(), "{case}: no distrust is set");
                assert!(!run.trust.owes_a_write(), "{case}: nothing is owed");
                let mut expected = record;
                if !matches!(reader, Reader::Watch) {
                    expected.observed_ms = Some(machine.wall());
                }
                assert_eq!(
                    devices.clock_record().expect("the record"),
                    expected,
                    "{case}: the record changes by the raise of the durable mark and nothing else"
                );
                assert_eq!(
                    proven(&run, &devices),
                    !step_back,
                    "{case}: the next clean reading finds a step back made between the tries, and only that"
                );
            }
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.19: an establishment that cannot take a narrow bracket refuses
    /// before its transaction, so the owner's confirmation is not spent, and it can be tried
    /// again.
    #[test]
    fn an_establishment_with_no_narrow_bracket_refuses_before_it_spends_the_confirmation() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let (run, pause) = Run::pausing(&machine, PAUSE);
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        machine.set_wall(machine.wall() - 8_000);
        assert!(!proven(&run, &devices), "the host distrusts its clock");
        let record = devices.clock_record().expect("the record");
        let spent = std::sync::atomic::AtomicBool::new(false);
        pause.arm(3);
        let error = run
            .trust
            .establish_with(&devices, BootEpoch::new(0), &|commit| commit(), |_, _| {
                spent.store(true, Ordering::SeqCst);
                Ok(())
            })
            .expect_err("no reading is taken");
        assert_not_read(&error, NOT_READ_ESTABLISHING);
        assert!(
            !spent.load(Ordering::SeqCst),
            "the confirmation is not spent"
        );
        assert_eq!(devices.clock_record().expect("the record"), record);
        assert!(!proven(&run, &devices), "the distrust stands");
        run.trust
            .establish_with(&devices, BootEpoch::new(0), &|commit| commit(), |_, _| {
                spent.store(true, Ordering::SeqCst);
                Ok(())
            })
            .expect("the next try establishes");
        assert!(spent.load(Ordering::SeqCst));
        assert!(proven(&run, &devices));
    }

    /// KR-REQ-09.17, KR-REQ-09.18: what a try that was held up read is evidence of how far the
    /// wall clock had got. The wall clock steps ten minutes ahead and the reading's first try reads
    /// that peak, held up for ten seconds; the clock goes back a minute right after it, and the
    /// second try is narrow. The peak is in the floor and in the marks, so the reading finds the
    /// step back; without the held-up try the clock reads ten minutes ahead of everything the
    /// host holds and nothing is found. The control is the same reading without the step back.
    #[test]
    fn a_peak_only_a_held_up_try_read_is_in_the_marks_and_the_floor() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            for step_back in [true, false] {
                let devices = DeviceDirectory::in_memory().expect("a directory");
                let machine = Machine::new();
                let floor = Arc::new(UtcFloor::at(0));
                let (run, pause) = Run::pausing_over(&machine, Arc::clone(&floor), PAUSE);
                read(&run, &devices, reader).expect("reads");
                run.pass(MINUTE);
                machine.set_wall(machine.wall() + 600_000);
                let peak = machine.wall() + 10_000;
                if step_back {
                    pause.sets_the_wall_after(1, peak - 60_000);
                }
                pause.arm(1);
                read(&run, &devices, reader).expect("reads in spite of the pause");
                let case = format!("{reader:?}, step back {step_back}");
                assert_eq!(
                    run.trust.is_trusted_now(),
                    !step_back,
                    "{case}: the step back is found at that reading, and only that"
                );
                assert_eq!(floor.get(), peak, "{case}: the peak is in the floor");
                if !matches!(reader, Reader::Watch) {
                    assert_eq!(
                        devices.clock_record().expect("the record").observed_ms,
                        Some(peak),
                        "{case}: and in the durable mark"
                    );
                }
            }
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a peak that only the three held-up tries of one reading read is
    /// kept, though the reading decides nothing from them and is refused: the floor holds it, and
    /// the next clean reading finds a step back made after it, and only that. A step forward the
    /// tries showed is written at once, as a narrow reading's would be.
    #[test]
    fn a_peak_only_the_three_held_up_tries_of_one_reading_read_is_kept() {
        for reader in [Reader::Sample, Reader::Observe, Reader::Watch] {
            for step_back in [true, false] {
                let devices = DeviceDirectory::in_memory().expect("a directory");
                let machine = Machine::new();
                let floor = Arc::new(UtcFloor::at(0));
                let (run, pause) = Run::pausing_over(&machine, Arc::clone(&floor), PAUSE);
                read(&run, &devices, reader).expect("reads");
                run.pass(MINUTE);
                machine.set_wall(machine.wall() + 600_000);
                let peak = machine.wall() + 30_000;
                if step_back {
                    pause.sets_the_wall_after(3, peak - 60_000);
                }
                pause.arm(3);
                let error = read(&run, &devices, reader).expect_err("no reading is taken");
                let case = format!("{reader:?}, step back {step_back}");
                assert_not_read(&error, NOT_READ);
                assert!(run.trust.is_trusted_now(), "{case}: no distrust is set");
                assert!(
                    !run.trust.owes_a_write(),
                    "{case}: the step forward the tries showed is written"
                );
                assert_eq!(floor.get(), peak, "{case}: the peak is in the floor");
                assert_eq!(
                    proven(&run, &devices),
                    !step_back,
                    "{case}: the next clean reading finds a step back made after the peak, and only that"
                );
            }
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a peak that only the three held-up tries of one reading read is
    /// in the host's record, so a host that starts again in the same boot finds a step back made
    /// after it. The store refuses the write of the anchor, so the durable mark is the only record
    /// of the peak, and the first reading after the restart finds the step back against it: the
    /// load puts the mark in memory and the stored reading is measured against it in the same
    /// transition. The control is the same sequence without the step back.
    #[test]
    fn a_peak_only_three_held_up_tries_read_survives_a_restart() {
        for reader in [Reader::Sample, Reader::Observe] {
            for step_back in [true, false] {
                let store = Store::new();
                let devices = store.open();
                let machine = Machine::new();
                let (run, pause) = Run::pausing(&machine, PAUSE);
                read(&run, &devices, reader).expect("reads");
                run.pass(MINUTE);
                refuse_writes_of(&devices, "anchor_wall_ms");
                machine.set_wall(machine.wall() + 600_000);
                let peak = machine.wall() + 30_000;
                if step_back {
                    pause.sets_the_wall_after(3, peak - 60_000);
                }
                pause.arm(3);
                read(&run, &devices, reader).expect_err("no reading is taken");
                allow_writes_of(&devices, "anchor_wall_ms");
                drop(run);
                let restarted = Run::on(&machine);
                assert_eq!(
                    proven(&restarted, &store.open()),
                    !step_back,
                    "{reader:?}, step back {step_back}: the restarted host finds a step back made after the peak, and only that"
                );
            }
        }
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a pause alone in a held-up try is no step back, at that
    /// reading or at the next, and no step forward the host owes a write for. The pause lands
    /// just before the continuous clock's second reading, after the wall clock was read: the try's
    /// wall reading is ten seconds behind its stamp, which is no peak and moves no anchor.
    #[test]
    fn a_pause_after_the_wall_reading_in_a_held_up_try_is_no_step_back_at_that_reading_or_the_next()
    {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let continuous = ManualClock::new();
        let pause = Pause::new(&machine, &continuous, PAUSE);
        let after_the_wall = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trust = {
            let wall = Arc::clone(&machine.wall);
            let arming = pause.clone();
            let after_the_wall = Arc::clone(&after_the_wall);
            ClockTrust::new(
                crate::service::WallClock::from_fn(move || {
                    let reading = wall.load(Ordering::SeqCst);
                    if after_the_wall.swap(false, Ordering::SeqCst) {
                        arming.arm(1);
                    }
                    reading
                }),
                Arc::new(UtcFloor::at(0)),
                Arc::new(Slipping {
                    inner: continuous.clone(),
                    pause: pause.clone(),
                }),
                Arc::new(machine.boot_clock.clone()),
                machine.boot.clone(),
            )
        };
        let run = Run {
            machine: machine.clone(),
            continuous,
            trust,
        };
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        after_the_wall.store(true, Ordering::SeqCst);
        assert!(proven(&run, &devices), "no step back at that reading");
        assert!(!run.trust.owes_a_write(), "and no step to write");
        run.pass(MINUTE);
        assert!(proven(&run, &devices), "and none at the next");
    }

    /// KR-REQ-09.17, KR-REQ-09.19: what the tries of an establishment held up read is in the
    /// floor, though the establishment is refused before its transaction.
    #[test]
    fn the_walls_of_the_held_up_tries_of_an_establishment_are_in_the_floor() {
        let devices = DeviceDirectory::in_memory().expect("a directory");
        let machine = Machine::new();
        let floor = Arc::new(UtcFloor::at(0));
        let (run, pause) = Run::pausing_over(&machine, Arc::clone(&floor), PAUSE);
        assert!(proven(&run, &devices));
        run.pass(MINUTE);
        machine.set_wall(machine.wall() + 600_000);
        let peak = machine.wall() + 30_000;
        pause.arm(3);
        run.trust
            .establish_with(&devices, BootEpoch::new(0), &|commit| commit(), |_, _| {
                Ok(())
            })
            .expect_err("no reading is taken");
        assert_eq!(floor.get(), peak);
    }

    /// KR-REQ-09.17: a pause between the host's reading of the continuous clock and of the boot
    /// clock, when it restores its anchor, is not a rollback.
    #[test]
    fn a_restart_paused_before_its_boot_reading_does_not_distrust_its_clock() {
        let store = Store::new();
        let machine = Machine::new();
        let first = Run::on(&machine);
        assert!(proven(&first, &store.open()));
        machine.pass(MINUTE);

        let continuous = ManualClock::new();
        let pause = Pause::new(&machine, &continuous, PAUSE);
        pause.arm(1);
        let boot_clock = Arc::new(Holdup {
            inner: machine.boot_clock.clone(),
            pause,
            after: false,
        });
        let restarted = Run::reading(&machine, Arc::new(UtcFloor::at(0)), continuous, boot_clock);
        assert!(
            proven(&restarted, &store.open()),
            "the pause in the load is no rollback"
        );
        restarted.pass(MINUTE);
        assert!(proven(&restarted, &store.open()), "and none later");
    }

    /// KR-REQ-09.17, KR-REQ-09.18: a pause between the two clocks a write of the anchor reads
    /// does not leave the record ahead of the boot clock: the host that starts again in the same
    /// boot finds no rollback.
    #[test]
    fn a_pause_in_the_write_of_the_anchor_is_no_rollback_to_a_restart_in_the_same_boot() {
        let store = Store::new();
        let devices = store.open();
        let machine = Machine::new();
        let continuous = ManualClock::new();
        let pause = Pause::new(&machine, &continuous, PAUSE);
        let boot_clock = Arc::new(Holdup {
            inner: machine.boot_clock.clone(),
            pause: pause.clone(),
            after: true,
        });
        let run = Run::reading(&machine, Arc::new(UtcFloor::at(0)), continuous, boot_clock);
        refuse_writes_of(&devices, "anchor_wall_ms");
        run.trust.sample(&devices).expect("samples");
        assert!(run.trust.owes_a_write(), "the anchor is owed");
        allow_writes_of(&devices, "anchor_wall_ms");
        run.pass(MINUTE);
        pause.arm(1);
        run.trust.settle(&devices).expect("settles");
        assert!(!run.trust.owes_a_write());

        let restarted = Run::on(&machine);
        assert!(
            proven(&restarted, &store.open()),
            "the pause in the write is no rollback"
        );
    }
}
