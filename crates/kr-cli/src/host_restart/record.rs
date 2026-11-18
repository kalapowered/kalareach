//! The record of evidence of a wait of `kr host restart` and of the start's own reads: what every
//! read of the daemon gave, written as it is seen, so that a time-out or a failure that comes
//! later cannot discard it.
//!
//! The classes of a read are the stop's own ([`Gave`]); the record adds the answer to the request
//! for the launch alone, which makes an exchange whole, and the lock's state read after the last
//! read of the endpoint. One function writes an observation ([`Record::observe`]), and one says
//! which states of the record can be reached ([`reachable`]).

use std::sync::{Mutex, PoisonError};

use kr_protocol::ids::ControllerGeneration;

use crate::host_stop::{Gave, Sight};

/// What the environment's lock showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lock {
    /// A process holds it. The reading does not say which, and not whether it is a control daemon.
    Held,
    /// No process holds it.
    Free,
    /// It could not be read.
    NotReadable,
}

/// The lock as it was read after the last read of the endpoint, and the process that the lock
/// file named at that read, where it named a live control daemon.
#[allow(
    dead_code,
    reason = "the members are read where a result is made from the record"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LockRead {
    pub(crate) lock: Lock,
    pub(crate) named: Option<u64>,
}

/// What the last read of the endpoint gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Last {
    /// A whole exchange: a usable greeting, the daemon's generation and the answer to the request
    /// for the launch alone.
    Whole(ControllerGeneration),
    /// A usable greeting and no whole exchange, with the generation where the daemon gave it.
    Greeting(Option<ControllerGeneration>),
    /// A reply that this command cannot use.
    Reply,
    /// Nothing listens.
    NothingListens,
    /// Nothing came within the bound.
    NothingInTime,
    /// This command's own check failed: no address, or a link that failed with no reply.
    CheckFailed,
}

/// The last whole exchange: the daemon's generation, and the process that the answer to the request
/// for the launch alone stated, none where the daemon refused that request.
#[allow(
    dead_code,
    reason = "the members are read where a result is made from the record"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Whole {
    pub(crate) generation: ControllerGeneration,
    pub(crate) process: Option<u64>,
}

/// The answer to the request for the launch alone, on the connection of a read that gave the
/// daemon's generation.
#[allow(dead_code, reason = "written where the read of the process is made")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Launch {
    /// The daemon answered: the process that it stated, none where it refused the request.
    Stated(Option<u64>),
    /// The exchange was cut, timed out, was withheld or could not be made.
    NotWhole,
}

/// What a read of the daemon, or of the lock, saw.
#[allow(dead_code, reason = "written where the read of the process is made")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// A step of a look at the endpoint: it began, the greeting was acknowledged, or the exchange
    /// gave what it gave.
    Sight(Sight),
    /// The answer to the request for the launch alone.
    Launch(Launch),
    /// The lock, read after the last read of the endpoint.
    Lock(LockRead),
}

/// What every read of a wait gave.
#[allow(
    dead_code,
    reason = "the members are read where a result is made from the record"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// Whether any read gave a usable greeting.
    pub(crate) greeted: bool,
    /// Whether any read gave a reply that cannot be used.
    pub(crate) replied: bool,
    /// What the last read gave: none where nothing was read.
    pub(crate) last: Option<Last>,
    /// The last whole exchange, where any was.
    pub(crate) whole: Option<Whole>,
    /// The lock as it was read after the last read of the endpoint: none where it was not read
    /// since.
    pub(crate) lock: Option<LockRead>,
}

impl Record {
    pub(crate) const fn new() -> Self {
        Self {
            greeted: false,
            replied: false,
            last: None,
            whole: None,
            lock: None,
        }
    }

    /// Writes what a read saw. The first sight of a read is that it began: until it shows more,
    /// nothing came, so a read that a time-out ends keeps the furthest step that it reached. A
    /// lock read belongs to the endpoint read before it, and the next read puts it out.
    pub(crate) fn observe(&mut self, seen: Observation) {
        match seen {
            Observation::Sight(sight) => self.sight(sight),
            Observation::Launch(launch) => {
                if let (Launch::Stated(process), Some(Last::Greeting(Some(generation)))) =
                    (launch, self.last)
                {
                    self.whole = Some(Whole {
                        generation,
                        process,
                    });
                    self.last = Some(Last::Whole(generation));
                }
            }
            Observation::Lock(read) => {
                if self.last.is_some() {
                    self.lock = Some(read);
                }
            }
        }
        debug_assert!(reachable(self), "an unreachable record: {self:?}");
    }

    fn sight(&mut self, sight: Sight) {
        match sight {
            Sight::Began => {
                self.last = Some(Last::NothingInTime);
                self.lock = None;
            }
            Sight::Greeted => self.greeted(None),
            Sight::Gave(gave) => match gave {
                Gave::NoAddress | Gave::LinkFailed => self.last = Some(Last::CheckFailed),
                // A greeting that was acknowledged before the bound is kept.
                Gave::NothingInTime => {
                    if !matches!(self.last, Some(Last::Greeting(_))) {
                        self.last = Some(Last::NothingInTime);
                    }
                }
                Gave::NothingListens => self.last = Some(Last::NothingListens),
                Gave::GreetingThenLinkFailed | Gave::GreetingOfAnotherMajor => self.greeted(None),
                Gave::Reported(generation) => self.greeted(Some(generation)),
                Gave::GreetingReplied(_) => {
                    self.replied = true;
                    self.last = Some(Last::Reply);
                }
                Gave::ReadRefused(_) | Gave::ReadUndecodable(_) | Gave::ReadReplied(_) => {
                    self.greeted = true;
                    self.replied = true;
                    self.last = Some(Last::Reply);
                }
            },
        }
    }

    fn greeted(&mut self, generation: Option<ControllerGeneration>) {
        self.greeted = true;
        self.last = Some(Last::Greeting(generation));
    }
}

/// Whether a state of the record can be reached by the writer: the reads that gave a usable greeting
/// are the ones that make a whole exchange, a greeting or a reply to the read; the last read
/// says what the members that speak of reads of any kind must hold; and a lock read follows a
/// read of the endpoint.
pub(crate) fn reachable(record: &Record) -> bool {
    let last_holds = match record.last {
        None => {
            !record.greeted && !record.replied && record.whole.is_none() && record.lock.is_none()
        }
        Some(Last::Whole(generation)) => {
            record.greeted
                && record
                    .whole
                    .is_some_and(|whole| whole.generation == generation)
        }
        Some(Last::Greeting(_)) => record.greeted,
        Some(Last::Reply) => record.replied,
        Some(Last::NothingListens | Last::NothingInTime | Last::CheckFailed) => true,
    };
    last_holds && (record.whole.is_none() || record.greeted)
}

/// The record that a wait and the reads inside it share: every read writes to it as it goes,
/// from whichever step of the wait it is in.
#[derive(Debug)]
pub(crate) struct Shared(Mutex<Record>);

impl Shared {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Record::new()))
    }

    pub(crate) fn observe(&self, seen: Observation) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(seen);
    }

    /// What has been written so far.
    #[allow(dead_code, reason = "read where a result is made from the record")]
    pub(crate) fn read(&self) -> Record {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::host_stop::Answered;

    fn generation(number: u64) -> ControllerGeneration {
        ControllerGeneration::new(number)
    }

    fn reply() -> Answered {
        Answered::for_a_case(generation(1))
    }

    /// Every way that a read of the endpoint ends, as the steps that it writes before it ends:
    /// including each step at which a time-out can end it.
    fn the_reads() -> Vec<Vec<Observation>> {
        let sight = |sight| Observation::Sight(sight);
        let began = sight(Sight::Began);
        let greeted = sight(Sight::Greeted);
        let mut reads = vec![
            vec![began],
            vec![began, sight(Sight::Gave(Gave::NoAddress))],
            vec![began, sight(Sight::Gave(Gave::LinkFailed))],
            vec![began, sight(Sight::Gave(Gave::NothingInTime))],
            vec![began, sight(Sight::Gave(Gave::NothingListens))],
            vec![began, sight(Sight::Gave(Gave::GreetingReplied(reply())))],
            vec![began, sight(Sight::Gave(Gave::GreetingOfAnotherMajor))],
            vec![began, greeted],
            vec![
                began,
                greeted,
                sight(Sight::Gave(Gave::GreetingThenLinkFailed)),
            ],
            vec![began, greeted, sight(Sight::Gave(Gave::NothingInTime))],
            vec![
                began,
                greeted,
                sight(Sight::Gave(Gave::ReadRefused(reply()))),
            ],
            vec![
                began,
                greeted,
                sight(Sight::Gave(Gave::ReadUndecodable(reply()))),
            ],
            vec![
                began,
                greeted,
                sight(Sight::Gave(Gave::ReadReplied(reply()))),
            ],
        ];
        for number in [1, 2] {
            let reported = sight(Sight::Gave(Gave::Reported(generation(number))));
            reads.push(vec![began, greeted, reported]);
            reads.push(vec![
                began,
                greeted,
                reported,
                Observation::Launch(Launch::NotWhole),
            ]);
            for process in [None, Some(7)] {
                reads.push(vec![
                    began,
                    greeted,
                    reported,
                    Observation::Launch(Launch::Stated(process)),
                ]);
            }
        }
        reads
    }

    /// The lock reads that can follow a read of the endpoint, and none.
    fn the_locks_after_a_read() -> Vec<Option<LockRead>> {
        let mut locks = vec![None];
        for lock in [Lock::Held, Lock::Free, Lock::NotReadable] {
            for named in [None, Some(5)] {
                locks.push(Some(LockRead { lock, named }));
            }
        }
        locks
    }

    /// What a read and the lock read after it write into a record.
    fn written(mut record: Record, read: &[Observation], lock: Option<LockRead>) -> Record {
        for seen in read {
            record.observe(*seen);
        }
        if let Some(lock) = lock {
            record.observe(Observation::Lock(lock));
        }
        record
    }

    /// Every state that the product of the members' values makes, and that [`reachable`] keeps.
    fn the_states_that_are_reachable() -> BTreeSet<String> {
        let mut lasts = vec![None];
        for number in [1, 2] {
            lasts.push(Some(Last::Whole(generation(number))));
            lasts.push(Some(Last::Greeting(Some(generation(number)))));
        }
        lasts.extend([
            Some(Last::Greeting(None)),
            Some(Last::Reply),
            Some(Last::NothingListens),
            Some(Last::NothingInTime),
            Some(Last::CheckFailed),
        ]);
        let mut wholes = vec![None];
        for number in [1, 2] {
            for process in [None, Some(7)] {
                wholes.push(Some(Whole {
                    generation: generation(number),
                    process,
                }));
            }
        }
        let mut states = BTreeSet::new();
        for last in &lasts {
            for greeted in [false, true] {
                for replied in [false, true] {
                    for whole in &wholes {
                        for lock in the_locks_after_a_read() {
                            let record = Record {
                                greeted,
                                replied,
                                last: *last,
                                whole: *whole,
                                lock,
                            };
                            if reachable(&record) {
                                states.insert(format!("{record:?}"));
                            }
                        }
                    }
                }
            }
        }
        states
    }

    /// Every sequence of up to three reads of the endpoint, each with the lock read after it or
    /// none, put through the writer, gives exactly the states that [`reachable`] names: the writer
    /// reaches no state that it does not name, and names none that it cannot reach.
    #[test]
    fn every_sequence_of_up_to_three_reads_gives_exactly_the_states_that_are_reachable() {
        let mut level = BTreeSet::from([format!("{:?}", Record::new())]);
        let mut records = vec![Record::new()];
        let mut seen: BTreeSet<String> = level.clone();
        for _ in 0..3 {
            let mut next = Vec::new();
            for record in &records {
                for read in the_reads() {
                    for lock in the_locks_after_a_read() {
                        let after = written(*record, &read, lock);
                        let key = format!("{after:?}");
                        if level.insert(key.clone()) {
                            next.push(after);
                        }
                    }
                }
            }
            seen.extend(level.iter().cloned());
            records = next;
        }
        // A state of no read at all is the start of a wait, and is reachable.
        assert!(reachable(&Record::new()));
        let reachable_states = the_states_that_are_reachable();
        assert_eq!(
            seen.difference(&reachable_states).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "the writer reached a state that `reachable` does not name"
        );
        assert_eq!(
            reachable_states.difference(&seen).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "`reachable` names a state that no sequence of three reads reaches"
        );
    }

    fn after(sights: &[Observation]) -> Record {
        written(Record::new(), sights, None)
    }

    /// A greeting that was acknowledged is kept when the exchange that follows it is cut, runs out
    /// of time, or fails on this side: a time-out writes nothing after the greeting, and a later
    /// read that finds nothing leaves the record of the greeting.
    #[test]
    fn a_greeting_is_kept_by_a_cut_a_time_out_and_a_local_failure() {
        let sight = Observation::Sight;
        let began = sight(Sight::Began);
        let greeted = sight(Sight::Greeted);
        for ending in [
            sight(Sight::Gave(Gave::GreetingThenLinkFailed)),
            sight(Sight::Gave(Gave::NothingInTime)),
            Observation::Launch(Launch::NotWhole),
        ] {
            let record = after(&[began, greeted, ending]);
            assert!(record.greeted, "{ending:?}");
            assert!(
                matches!(record.last, Some(Last::Greeting(_))),
                "{ending:?}: {record:?}"
            );
        }
        // No step after the greeting: the time-out cancelled the read.
        let cancelled = after(&[began, greeted]);
        assert!(cancelled.greeted);
        assert!(matches!(cancelled.last, Some(Last::Greeting(None))));
        // A read that gave a generation and then lost the answer to the request for the launch
        // alone keeps the generation.
        let reported = sight(Sight::Gave(Gave::Reported(generation(3))));
        let record = after(&[
            began,
            greeted,
            reported,
            Observation::Launch(Launch::NotWhole),
        ]);
        assert_eq!(record.last, Some(Last::Greeting(Some(generation(3)))));
        assert!(record.whole.is_none());
        // Later reads that find nothing do not take the greeting back.
        for later in [
            Sight::Gave(Gave::NothingListens),
            Sight::Gave(Gave::NoAddress),
            Sight::Gave(Gave::NothingInTime),
        ] {
            let mut record = after(&[
                began,
                greeted,
                sight(Sight::Gave(Gave::GreetingThenLinkFailed)),
            ]);
            record.observe(began);
            record.observe(sight(later));
            assert!(record.greeted, "{later:?}");
        }
    }

    /// A lock read is in the record only where it was made after the last read of the endpoint:
    /// the next read puts it out, and a lock read before any read is not kept.
    #[test]
    fn a_lock_read_is_in_the_record_only_where_it_was_made_after_the_last_read_of_the_endpoint() {
        let sight = Observation::Sight;
        let held = LockRead {
            lock: Lock::Held,
            named: Some(9),
        };
        let mut record = Record::new();
        record.observe(Observation::Lock(held));
        assert!(
            record.lock.is_none(),
            "no read of the endpoint came before it"
        );
        record.observe(sight(Sight::Began));
        record.observe(sight(Sight::Gave(Gave::NothingListens)));
        record.observe(Observation::Lock(held));
        assert_eq!(record.lock, Some(held));
        record.observe(sight(Sight::Began));
        assert!(
            record.lock.is_none(),
            "a lock read before the read is put out"
        );
        record.observe(sight(Sight::Gave(Gave::NothingListens)));
        assert!(record.lock.is_none());
    }

    /// The last whole exchange stays where a later read is not whole, with the process that its
    /// answer to the request for the launch alone stated.
    #[test]
    fn the_last_whole_exchange_and_its_process_stay_where_a_later_read_is_not_whole() {
        let sight = Observation::Sight;
        let began = sight(Sight::Began);
        let whole = [
            began,
            sight(Sight::Greeted),
            sight(Sight::Gave(Gave::Reported(generation(2)))),
            Observation::Launch(Launch::Stated(Some(41))),
        ];
        let mut record = after(&whole);
        assert_eq!(record.last, Some(Last::Whole(generation(2))));
        record.observe(began);
        record.observe(sight(Sight::Gave(Gave::NothingListens)));
        assert_eq!(record.last, Some(Last::NothingListens));
        assert_eq!(
            record.whole,
            Some(Whole {
                generation: generation(2),
                process: Some(41)
            })
        );
    }
}
