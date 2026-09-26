//! How much work other than a run's own a machine did, from readings of the whole machine.
//!
//! Section 27's reference host runs nothing but the measurement. A run shows that of a step by
//! reading the machine every few seconds, from before the step begins until after it ends, and
//! bounding the processor time spent on anything but the run in every five seconds of the step.
//! [`Tally`] takes the readings in order and keeps what that bound needs.
//!
//! Each reading holds two counts, and the bound is the larger of what each allows:
//!
//! * Every process on the machine, with the processor time it has used. The run is one process and
//!   everything descended from it, and a process that was once the run's stays the run's whatever
//!   it is reparented to. A process is known by its identifier and when it started, so an
//!   identifier the system reuses names a new process. Every other process is other work: what it
//!   used since the reading before, or everything it has used when it first appears, with the time
//!   of the children it collected where the platform counts that. This count misses a process that
//!   starts and ends between two readings when no parent collects it, and the kernel's own work.
//! * The machine's count of its processors' busy time, less the least the run's processes can have
//!   used over the same time. That count misses nothing that ran, and is kept to a resolution, a
//!   hundredth of a second per counter on Linux and macOS, which the bound adds back.
//!
//! A window of five seconds can start anywhere between two readings, so the bound for the windows
//! that start between two readings is the other work over the shortest run of readings that covers
//! every one of them, and whatever the work did between the readings, no five seconds of the step
//! held more. Readings out of order, a count that went backwards, or a process table without the
//! run or without the system's first process leave the bound unread, as does a run of fewer than
//! two readings.

use std::collections::{HashMap, HashSet};

/// One reading of the whole machine.
#[derive(Clone, Debug)]
pub struct Reading {
    /// When the reading began, in seconds on a monotonic clock.
    pub began: f64,
    /// The machine's busy processor time in seconds, counted after `began` and before the process
    /// table was read.
    pub busy_before: f64,
    /// Every process on the machine, as the process table gave it between the two counts of busy
    /// time. A process that has ended and not been collected is left out.
    pub processes: Vec<Process>,
    /// The machine's busy processor time in seconds, counted after the process table was read.
    pub busy_after: f64,
    /// The most the machine's count can fall short of the busy time between two of its counts, in
    /// seconds.
    pub busy_resolution: f64,
    /// When the reading ended, on the clock `began` is on.
    pub ended: f64,
}

/// One process in a reading.
#[derive(Clone, Debug, PartialEq)]
pub struct Process {
    /// The process's identifier.
    pub pid: u32,
    /// Its parent's identifier.
    pub parent: u32,
    /// When it started, in the platform's own form. With the identifier it names the process.
    pub start: String,
    /// The processor time the process itself has used, in seconds.
    pub own: f64,
    /// `own`, and the processor time of the children the process collected where the platform
    /// counts that, in seconds.
    pub with_collected: f64,
}

/// What a run of readings shows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    /// The most processors' worth of other work any window of the step can have held.
    pub bound: f64,
    /// Processors' worth of other work over the whole run of readings.
    pub average: f64,
    /// How many readings were taken.
    pub readings: usize,
}

type Key = (u32, String);

/// What one reading left for the next.
struct Previous {
    ended: f64,
    busy_before: f64,
    busy_after: f64,
    /// Each process's own time and its time with its collected children's.
    used: HashMap<Key, (f64, f64)>,
}

/// The time between two readings. The windows that start after the reading that opens it ended and
/// before the one that closes it ended are its own.
#[derive(Clone, Copy, Debug)]
struct Interval {
    /// When the reading that closes the interval began and ended.
    began: f64,
    ended: f64,
    /// The machine's busy count before the process table of the opening reading, and after that of
    /// the closing one: every process time in the interval was read between the two.
    busy_from: f64,
    busy_to: f64,
    busy_resolution: f64,
    /// What processes outside the run used over the interval, their collected children's time
    /// included.
    others: f64,
    /// The least the run's processes used over the interval.
    run_least: f64,
}

/// The readings of one run, taken in order.
pub struct Tally {
    run: u32,
    /// Every process that has been the run's.
    ours: HashSet<Key>,
    first: Option<(f64, f64)>,
    previous: Option<Previous>,
    intervals: Vec<Interval>,
}

impl Tally {
    /// A tally for the run that is process `run` and everything descended from it.
    #[must_use]
    pub fn new(run: u32) -> Self {
        Self {
            run,
            ours: HashSet::new(),
            first: None,
            previous: None,
            intervals: Vec::new(),
        }
    }

    /// Takes the next reading.
    ///
    /// # Errors
    ///
    /// Why the readings cannot bound other work: the reading began before the one before it ended,
    /// a count went backwards, or the process table names a process twice, lacks the run's process,
    /// or lacks the system's first process, and so does not show the whole machine.
    pub fn add(&mut self, reading: &Reading) -> Result<(), String> {
        let number = self.intervals.len() + usize::from(self.first.is_some());
        if !(reading.began <= reading.ended && reading.busy_before <= reading.busy_after) {
            return Err(format!("reading {number} is out of order within itself"));
        }
        let mut used: HashMap<Key, (f64, f64)> = HashMap::with_capacity(reading.processes.len());
        let mut key_of: HashMap<u32, Key> = HashMap::with_capacity(reading.processes.len());
        let mut parent_of: HashMap<Key, u32> = HashMap::with_capacity(reading.processes.len());
        for process in &reading.processes {
            let key = (process.pid, process.start.clone());
            if key_of.insert(process.pid, key.clone()).is_some() {
                return Err(format!(
                    "reading {number} names process {} twice",
                    process.pid
                ));
            }
            used.insert(key.clone(), (process.own, process.with_collected));
            parent_of.insert(key, process.parent);
        }
        let Some(run) = key_of.get(&self.run) else {
            return Err(format!(
                "reading {number} does not hold the run's own process {}",
                self.run
            ));
        };
        if !key_of.contains_key(&1) {
            return Err(format!(
                "reading {number} does not hold the system's first process, so it does not show \
                 the whole machine"
            ));
        }
        self.ours.insert(run.clone());
        loop {
            let joined: Vec<Key> = parent_of
                .iter()
                .filter(|(key, parent)| {
                    !self.ours.contains(*key)
                        && key_of
                            .get(parent)
                            .is_some_and(|parent| self.ours.contains(parent))
                })
                .map(|(key, _)| key.clone())
                .collect();
            if joined.is_empty() {
                break;
            }
            self.ours.extend(joined);
        }
        if let Some(previous) = &self.previous {
            if reading.began <= previous.ended {
                return Err(format!(
                    "reading {number} did not begin after reading {} ended",
                    number - 1
                ));
            }
            if reading.busy_before < previous.busy_after {
                return Err(format!(
                    "the machine's busy count went back between readings {} and {number}",
                    number - 1
                ));
            }
            let mut others = 0.0;
            let mut run_least = 0.0;
            for (key, &(own, with_collected)) in &used {
                let before = previous.used.get(key);
                if let Some(&(own_before, with_collected_before)) = before
                    && (own < own_before || with_collected < with_collected_before)
                {
                    return Err(format!(
                        "process {} used less processor time by reading {number} than by reading \
                         {}",
                        key.0,
                        number - 1
                    ));
                }
                if self.ours.contains(key) {
                    // A process first seen now started after the reading before began to list the
                    // process table, so all it used falls between the two counts of busy time.
                    run_least += own - before.map_or(0.0, |&(own_before, _)| own_before);
                } else {
                    others += with_collected
                        - before.map_or(0.0, |&(_, with_collected_before)| with_collected_before);
                }
            }
            self.intervals.push(Interval {
                began: reading.began,
                ended: reading.ended,
                busy_from: previous.busy_before,
                busy_to: reading.busy_after,
                busy_resolution: reading.busy_resolution,
                others,
                run_least,
            });
        } else {
            self.first = Some((reading.began, reading.ended));
        }
        self.previous = Some(Previous {
            ended: reading.ended,
            busy_before: reading.busy_before,
            busy_after: reading.busy_after,
            used,
        });
        Ok(())
    }

    /// The bound on other work in any `window` seconds after the first reading, and the average.
    /// A run of readings shorter than `window` is bounded over its own length.
    ///
    /// # Errors
    ///
    /// When fewer than two readings were taken.
    pub fn summary(&self, window: f64) -> Result<Summary, String> {
        let (Some((first_began, first_ended)), Some(last)) = (self.first, self.intervals.last())
        else {
            return Err("fewer than two readings were taken".to_owned());
        };
        // The step ran after the first reading ended and before the last one began, which the
        // order of the readings keeps apart.
        let window = (last.began - first_ended).min(window);
        let mut bound: f64 = 0.0;
        for (start, opening) in self.intervals.iter().enumerate() {
            let mut end = start;
            while end + 1 < self.intervals.len()
                && self.intervals[end].began < opening.ended + window
            {
                end += 1;
            }
            bound = bound.max(other(&self.intervals[start..=end]) / window);
        }
        let average = other(&self.intervals) / (last.ended - first_began);
        Ok(Summary {
            bound,
            average,
            readings: self.intervals.len() + 1,
        })
    }
}

/// The most processor time outside the run a run of consecutive intervals can have held.
fn other(intervals: &[Interval]) -> f64 {
    let (Some(first), Some(last)) = (intervals.first(), intervals.last()) else {
        return 0.0;
    };
    let others: f64 = intervals.iter().map(|interval| interval.others).sum();
    let run_least: f64 = intervals.iter().map(|interval| interval.run_least).sum();
    let resolution = intervals
        .iter()
        .map(|interval| interval.busy_resolution)
        .fold(0.0, f64::max);
    let machine = last.busy_to - first.busy_from + resolution - run_least;
    others.max(machine).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::{Process, Reading, Tally};

    const RUN: u32 = 500;

    fn process(pid: u32, parent: u32, start: &str, used: f64) -> Process {
        Process {
            pid,
            parent,
            start: start.to_owned(),
            own: used,
            with_collected: used,
        }
    }

    /// A reading at `at` seconds, instantaneous, with the system's first process, the run, and
    /// `processes`, on a machine whose busy count is `busy`.
    fn reading(at: f64, busy: f64, processes: &[Process]) -> Reading {
        let mut all = vec![process(1, 0, "boot", 0.0), process(RUN, 1, "run", 0.0)];
        all.extend_from_slice(processes);
        Reading {
            began: at,
            busy_before: busy,
            processes: all,
            busy_after: busy,
            busy_resolution: 0.0,
            ended: at,
        }
    }

    fn tally(readings: &[Reading]) -> Result<super::Summary, String> {
        let mut tally = Tally::new(RUN);
        for reading in readings {
            tally.add(reading)?;
        }
        tally.summary(5.0)
    }

    #[test]
    fn work_that_straddles_two_readings_is_bounded_whole() {
        // One processor busy from 2.5 s to 7.5 s, read every five seconds: each interval holds
        // half of it, and a five-second window holds all of it.
        let summary = tally(&[
            reading(0.0, 0.0, &[process(900, 1, "a", 0.0)]),
            reading(5.0, 2.5, &[process(900, 1, "a", 2.5)]),
            reading(10.0, 5.0, &[process(900, 1, "a", 5.0)]),
        ])
        .unwrap();
        assert!(summary.bound >= 1.0, "{summary:?}");
        assert!((summary.average - 0.5).abs() < 1e-9, "{summary:?}");
    }

    #[test]
    fn a_quiet_machine_reads_quiet() {
        let readings: Vec<Reading> = (0..6_u32)
            .map(|second| {
                let at = f64::from(second) * 2.0;
                reading(at, at * 0.01, &[process(900, 1, "a", at * 0.01)])
            })
            .collect();
        let summary = tally(&readings).unwrap();
        assert!(summary.bound < 0.05, "{summary:?}");
    }

    #[test]
    fn a_reused_identifier_is_a_new_process() {
        // Process 900 ends after 100 s of work, and a new process given the same identifier uses
        // five seconds: a comparison by identifier alone would see 95 s less and count nothing.
        let summary = tally(&[
            reading(0.0, 0.0, &[process(900, 1, "first", 100.0)]),
            reading(5.0, 5.0, &[process(900, 1, "second", 5.0)]),
        ])
        .unwrap();
        assert!(summary.bound >= 1.0, "{summary:?}");
    }

    #[test]
    fn a_count_that_goes_back_is_unread() {
        let error = tally(&[
            reading(0.0, 0.0, &[process(900, 1, "a", 10.0)]),
            reading(2.0, 0.0, &[process(900, 1, "a", 9.0)]),
        ])
        .unwrap_err();
        assert!(error.contains("process 900 used less"), "{error}");
        let error = tally(&[reading(0.0, 5.0, &[]), reading(2.0, 4.0, &[])]).unwrap_err();
        assert!(error.contains("busy count went back"), "{error}");
    }

    #[test]
    fn readings_out_of_order_are_unread() {
        let error = tally(&[reading(2.0, 0.0, &[]), reading(2.0, 0.0, &[])]).unwrap_err();
        assert!(error.contains("did not begin after"), "{error}");
        let error = tally(&[reading(0.0, 0.0, &[])]).unwrap_err();
        assert!(error.contains("fewer than two"), "{error}");
    }

    #[test]
    fn a_process_table_without_the_run_or_the_first_process_is_unread() {
        let mut without_run = reading(0.0, 0.0, &[]);
        without_run.processes.retain(|process| process.pid != RUN);
        let error = Tally::new(RUN).add(&without_run).unwrap_err();
        assert!(error.contains("the run's own process 500"), "{error}");
        let mut without_first = reading(0.0, 0.0, &[]);
        without_first.processes.retain(|process| process.pid != 1);
        let error = Tally::new(RUN).add(&without_first).unwrap_err();
        assert!(error.contains("first process"), "{error}");
        let error = Tally::new(RUN)
            .add(&reading(0.0, 0.0, &[process(RUN, 1, "again", 0.0)]))
            .unwrap_err();
        assert!(error.contains("names process 500 twice"), "{error}");
    }

    #[test]
    fn the_runs_processes_stay_the_runs_when_reparented() {
        // The run's worker outlives its parent and is reparented to the first process; its work
        // after that is still the run's, and the machine's count carries it too.
        let summary = tally(&[
            reading(0.0, 0.0, &[process(600, RUN, "worker", 0.0)]),
            reading(2.0, 2.0, &[process(600, 1, "worker", 2.0)]),
            reading(4.0, 4.0, &[process(600, 1, "worker", 4.0)]),
        ])
        .unwrap();
        assert!(summary.bound < 1e-9, "{summary:?}");
    }

    #[test]
    fn the_runs_new_processes_are_its_own() {
        // A process the run starts between two readings, and its child, are the run's from the
        // reading that first holds them, with everything they used before it.
        let summary = tally(&[
            reading(0.0, 0.0, &[]),
            reading(
                2.0,
                3.0,
                &[
                    process(600, RUN, "worker", 1.0),
                    process(601, 600, "shell", 2.0),
                ],
            ),
        ])
        .unwrap();
        assert!(summary.bound < 1e-9, "{summary:?}");
    }

    #[test]
    fn work_no_process_shows_is_read_from_the_machine() {
        // Two processors' worth of work between readings, in processes that start and end
        // between them with no parent collecting them, and no process the run's.
        let summary = tally(&[
            reading(0.0, 0.0, &[]),
            reading(2.0, 4.0, &[]),
            reading(4.0, 8.0, &[]),
        ])
        .unwrap();
        assert!((summary.bound - 2.0).abs() < 1e-9, "{summary:?}");
    }

    #[test]
    fn the_runs_own_work_is_not_other_work() {
        // Eight processors' worth for the run, and a machine count that holds exactly that.
        let summary = tally(&[
            reading(0.0, 0.0, &[process(600, RUN, "worker", 0.0)]),
            reading(2.0, 16.0, &[process(600, RUN, "worker", 16.0)]),
            reading(4.0, 32.0, &[process(600, RUN, "worker", 32.0)]),
        ])
        .unwrap();
        assert!(summary.bound < 1e-9, "{summary:?}");
    }

    #[test]
    fn the_counts_resolution_is_added_back() {
        let mut readings = vec![reading(0.0, 0.0, &[]), reading(2.0, 0.0, &[])];
        for reading in &mut readings {
            reading.busy_resolution = 0.5;
        }
        let summary = tally(&readings).unwrap();
        assert!((summary.bound - 0.25).abs() < 1e-9, "{summary:?}");
    }

    #[test]
    fn a_collected_childs_time_counts_through_its_parent() {
        // Process 900 collects a child that started and ended between the two readings and used
        // three seconds.
        let mut parent = process(900, 1, "a", 0.0);
        let before = reading(0.0, 0.0, std::slice::from_ref(&parent));
        parent.with_collected = 3.0;
        let after = reading(2.0, 0.0, &[parent]);
        let summary = tally(&[before, after]).unwrap();
        assert!((summary.bound - 1.5).abs() < 1e-9, "{summary:?}");
    }

    #[test]
    fn a_run_shorter_than_a_second_is_not_spread_over_a_second() {
        // Half a second with one processor busy is one processor's worth over its own length.
        let summary = tally(&[
            reading(0.0, 0.0, &[process(900, 1, "a", 0.0)]),
            reading(0.5, 0.5, &[process(900, 1, "a", 0.5)]),
        ])
        .unwrap();
        assert!((summary.bound - 1.0).abs() < 1e-9, "{summary:?}");
    }

    #[test]
    fn a_short_run_is_bounded_over_its_own_length() {
        let summary = tally(&[
            reading(0.0, 0.0, &[process(900, 1, "a", 0.0)]),
            reading(2.0, 1.0, &[process(900, 1, "a", 1.0)]),
        ])
        .unwrap();
        assert!((summary.bound - 0.5).abs() < 1e-9, "{summary:?}");
    }
}
