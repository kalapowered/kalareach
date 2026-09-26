//! How much work other than a run's own a machine did, from readings of the whole machine.
//!
//! Section 27's reference host runs nothing but the measurement. A run shows that of a step by
//! reading the machine every few seconds, from before the step begins until after it ends, and
//! bounding, for every five seconds of the step, the processor time the machine spent on anything
//! the operating system does not charge to the run's own processes. [`Tally`] takes the readings in
//! order and keeps what that bound needs.
//!
//! The bound for a stretch of time is the processors' time less their idle time, which is every
//! processor's busy time, less the least the run's processes can have used over the same stretch.
//!
//! * The processors' time is their number times the time between the moment before the first idle
//!   count was taken and the moment after the last one, which is never less than the time the two
//!   counts cover. The counts are kept in rounded units, and one can trail the moment it is read by
//!   a little; `idle_resolution` covers both. What a count means on each platform, and what it
//!   rests on, is [`crate::machine`]'s to say.
//! * The run is one process and everything descended from it, and a process that was once the
//!   run's stays the run's whatever it is reparented to. A process is known by its identifier and
//!   when it started, so an identifier the system reuses names a new process, and a parent counts as
//!   one only when the process holding its identifier was read both before and after the child's
//!   row, so that it held the identifier when that row was read. The least a run process used over a
//!   stretch is its time at the last reading in the stretch less its time at the first, less the
//!   rounding of the two (`time_resolution`) and less what its time can have trailed at the first
//!   reading (`lag`), and never less than nothing. A process that first appears inside the stretch
//!   started after the reading before it began, so all of its time is inside the stretch. Anything
//!   else, a process whose row could not be read among it, counts as nothing.
//! * Where a reading took a process's time thread by thread ([`Threads`]), the same difference is
//!   also taken for each thread read at both ends, a thread known by its identifier and start, and
//!   the process counts the larger of that sum and its whole difference, each being a least it can
//!   have used. A thread that ends inside the stretch loses its time since the first reading from
//!   the sum, and one first read inside it counts nothing, since a listing of a process's threads
//!   can miss one; the whole difference keeps both, so threads that come and go, as a pool made for
//!   each piece of work does, cost no more than the whole reading. One match needs more: a thread
//!   other than the first that execs takes the first thread's identifier and start with its own,
//!   older time. So the first thread counts only where the process's row at the stretch's first
//!   reading gave it one thread, so that any later taker was created after that row, or where
//!   another thread matched at the end had started before the first thread was read at the first
//!   reading, since an exec after that read would have ended it before the end reading read it, and
//!   the end reading reads the first thread first.
//!
//! A window of five seconds can start anywhere between two readings, so the bound for the windows
//! that start between two readings is the bound over the shortest run of readings that covers every
//! one of them, and whatever the work did between the readings, no five seconds of the step held
//! more. Readings out of order, a count that went backwards, a change in the number of processors,
//! or a process table without the run or without the system's first process leave the bound
//! unread, as does a run of fewer than two readings.

use std::collections::{HashMap, HashSet};

/// One reading of the whole machine.
#[derive(Clone, Debug)]
pub struct Reading {
    /// The moment before the first idle count was taken, in seconds on a monotonic clock.
    pub began: f64,
    /// How many processors the machine has.
    pub processors: u32,
    /// All processors' idle time so far, in seconds, counted after `began` and before the process
    /// table was read.
    pub idle_before: f64,
    /// Every process in the table, in the order its row was read.
    pub rows: Vec<Row>,
    /// All processors' idle time so far, in seconds, counted after the process table was read.
    pub idle_after: f64,
    /// The moment after the second idle count was taken, on the clock `began` is on.
    pub ended: f64,
    /// The most the difference of two idle counts can overstate the idle time between them.
    pub idle_resolution: f64,
    /// The most the difference of two of a process's times can overstate its work between them.
    pub time_resolution: f64,
}

/// One row of the process table.
#[derive(Clone, Debug, PartialEq)]
pub enum Row {
    /// A process whose row could be read.
    Read(Process),
    /// A process the table lists but whose row could not be read, such as one of another user's
    /// or one that is ending.
    Unread {
        /// The process's identifier.
        pid: u32,
    },
}

impl Row {
    /// The identifier of the process on this row.
    #[must_use]
    pub fn pid(&self) -> u32 {
        match self {
            Self::Read(process) => process.pid,
            Self::Unread { pid } => *pid,
        }
    }
}

/// One process whose row could be read.
#[derive(Clone, Debug, PartialEq)]
pub struct Process {
    /// The process's identifier.
    pub pid: u32,
    /// Its parent's identifier.
    pub parent: u32,
    /// When it started, in units that order the processes of one machine. With the identifier it
    /// names the process.
    pub start: u64,
    /// The processor time the operating system charges to the process as a whole, in seconds.
    pub own: f64,
    /// The most `own` can trail the time charged to the process when its row was read: what its
    /// running threads can have used since the kernel last brought their time up to date.
    pub lag: f64,
    /// Its threads, where the reading took the time of each; the tally then counts them rather than
    /// `own`.
    pub threads: Option<Threads>,
}

/// A process's threads, as one reading took them.
#[derive(Clone, Debug, PartialEq)]
pub struct Threads {
    /// Whether the process's row, read before its threads, gave it one thread.
    pub alone: bool,
    /// Each thread whose time could be read, the process's first thread first where it could.
    pub each: Vec<Thread>,
}

/// One thread's time.
#[derive(Clone, Debug, PartialEq)]
pub struct Thread {
    /// Its identifier, which for the process's first thread is the process's own.
    pub tid: u32,
    /// When it started, in the units of a process's start. With the identifier it names the thread,
    /// except where another thread of the process execs and takes the first thread's place.
    pub start: u64,
    /// The processor time the kernel charges to the thread, in seconds, to the nanosecond.
    pub own: f64,
    /// The most `own` can trail the thread's real time when it was read: one clock tick for a thread
    /// that was running, and for any other what it ran in the two ticks after, up to a tick.
    pub lag: f64,
    /// Whether it started before the reading read the process's first thread, so that an exec after
    /// that read would have ended it.
    pub older: bool,
}

/// What a run of readings shows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    /// The most processors' worth of other work any window of the step can have held.
    pub bound: f64,
    /// Of `bound`, the processors' worth that the counts' allowances make up: their rounding, and
    /// how far a running thread's time can trail. It is only these allowances, and not the rest of
    /// what makes a bound larger than the work it bounds, such as a run of readings that reaches
    /// past the five seconds it covers.
    pub allowance: f64,
    /// The most processors' worth of other work over the whole run of readings.
    pub average: f64,
    /// How many readings were taken.
    pub readings: usize,
}

type Key = (u32, u64);

/// What the tally keeps of one reading.
struct Kept {
    began: f64,
    ended: f64,
    idle_before: f64,
    idle_after: f64,
    idle_resolution: f64,
    time_resolution: f64,
}

/// A run process's time at one reading, with how far it can trail, and its threads where the
/// reading took them.
#[derive(Clone)]
struct Time {
    reading: usize,
    own: f64,
    lag: f64,
    threads: Option<Threads>,
}

/// The readings of one run, taken in order.
pub struct Tally {
    run: u32,
    processors: Option<u32>,
    /// Every process that has been the run's.
    ours: HashSet<Key>,
    /// The previous reading's table: each identifier with the start of the process that had it,
    /// where its row could be read.
    previous_table: HashMap<u32, Option<u64>>,
    /// The previous reading's times of every process it could read.
    previous_times: HashMap<Key, Time>,
    /// The previous reading's parent links whose parent was read before its child: each counts
    /// once this reading shows the parent again.
    pending: Vec<(Key, Key)>,
    /// The reading at which each process first appeared, for those that appeared after the first.
    appeared: HashMap<Key, usize>,
    /// Each run process's times, reading by reading.
    times: HashMap<Key, Vec<Time>>,
    readings: Vec<Kept>,
}

impl Tally {
    /// A tally for the run that is process `run` and everything descended from it.
    #[must_use]
    pub fn new(run: u32) -> Self {
        Self {
            run,
            processors: None,
            ours: HashSet::new(),
            previous_table: HashMap::new(),
            previous_times: HashMap::new(),
            pending: Vec::new(),
            appeared: HashMap::new(),
            times: HashMap::new(),
            readings: Vec::new(),
        }
    }

    /// The processes in `rows`, a reading's process table, that can be the run's: its own process,
    /// every process known as the run's that holds the same identifier and start, and every process
    /// below one of those through the rows' parent identifiers. A reading takes their threads' times,
    /// and no other process's time is ever counted, so it need take no other's.
    #[must_use]
    pub fn candidates(&self, rows: &[Row]) -> HashSet<u32> {
        let mut candidates = HashSet::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for row in rows {
            if let Row::Read(process) = row {
                if process.pid == self.run || self.ours.contains(&(process.pid, process.start)) {
                    candidates.insert(process.pid);
                }
                children
                    .entry(process.parent)
                    .or_default()
                    .push(process.pid);
            }
        }
        let mut below: Vec<u32> = candidates.iter().copied().collect();
        while let Some(parent) = below.pop() {
            for child in children.get(&parent).into_iter().flatten() {
                if candidates.insert(*child) {
                    below.push(*child);
                }
            }
        }
        candidates
    }

    /// Takes the next reading.
    ///
    /// # Errors
    ///
    /// Why the readings cannot bound other work: the reading is out of order, the idle count went
    /// backwards, the number of processors changed, or the process table names a process twice,
    /// cannot read the run's own process, or lacks the system's first process, and so does not
    /// show the whole machine.
    pub fn add(&mut self, reading: &Reading) -> Result<(), String> {
        let number = self.readings.len();
        if !(reading.began <= reading.ended && reading.idle_before <= reading.idle_after) {
            return Err(format!("reading {number} is out of order within itself"));
        }
        if *self.processors.get_or_insert(reading.processors) != reading.processors {
            return Err(format!(
                "the machine's processors changed by reading {number}"
            ));
        }
        if let Some(previous) = self.readings.last() {
            if reading.began <= previous.ended {
                return Err(format!(
                    "reading {number} did not begin after reading {} ended",
                    number - 1
                ));
            }
            if reading.idle_before < previous.idle_after {
                return Err(format!(
                    "the idle count went back between readings {} and {number}",
                    number - 1
                ));
            }
        }

        // The table: each row's place in the reading, and the processes that could be read.
        let mut table: HashMap<u32, Option<u64>> = HashMap::with_capacity(reading.rows.len());
        let mut place: HashMap<u32, usize> = HashMap::with_capacity(reading.rows.len());
        for (index, row) in reading.rows.iter().enumerate() {
            let start = match row {
                Row::Read(process) => Some(process.start),
                Row::Unread { .. } => None,
            };
            if table.insert(row.pid(), start).is_some() {
                return Err(format!(
                    "reading {number} names process {} twice",
                    row.pid()
                ));
            }
            place.insert(row.pid(), index);
        }
        let processes: Vec<&Process> = reading
            .rows
            .iter()
            .filter_map(|row| match row {
                Row::Read(process) => Some(process),
                Row::Unread { .. } => None,
            })
            .collect();
        let Some(run) = processes.iter().find(|process| process.pid == self.run) else {
            return Err(format!(
                "reading {number} cannot read the run's own process {}",
                self.run
            ));
        };
        if !table.contains_key(&1) {
            return Err(format!(
                "reading {number} does not list the system's first process, so it does not show \
                 the whole machine"
            ));
        }

        // A process that was not in the reading before, or had an identifier another process held
        // then, started after that reading began to list the table.
        if number > 0 {
            for process in &processes {
                if self
                    .previous_table
                    .get(&process.pid)
                    .is_none_or(|start| start.is_some_and(|start| start != process.start))
                {
                    self.appeared
                        .entry((process.pid, process.start))
                        .or_insert(number);
                }
            }
        }

        // Who is the run's. A child's row names the identifier its parent had when the row was
        // read, and an identifier can pass to a new process at any moment after its holder ends.
        // So a row that holds the identifier in this reading names the child's parent only where
        // that process is known to have held it when the child's row was read: its row was read
        // before the child's in one reading and after it in another, the reading before or the
        // reading after. A parent read after its child, and seen in the reading before, counts now;
        // a parent read before its child counts once the next reading shows it again.
        let by_pid: HashMap<u32, &Process> = processes
            .iter()
            .map(|process| (process.pid, *process))
            .collect();
        let mut links: Vec<(Key, Key)> = Vec::new();
        let mut pending: Vec<(Key, Key)> = Vec::new();
        for child in &processes {
            let Some(parent) = by_pid.get(&child.parent) else {
                continue;
            };
            if parent.start > child.start {
                continue;
            }
            let link = ((child.pid, child.start), (parent.pid, parent.start));
            if place[&parent.pid] > place[&child.pid] {
                if self.previous_table.get(&parent.pid) == Some(&Some(parent.start)) {
                    links.push(link);
                }
            } else {
                pending.push(link);
            }
        }
        for (child, parent) in std::mem::take(&mut self.pending) {
            if table.get(&parent.0) == Some(&Some(parent.1)) {
                links.push((child, parent));
            }
        }
        self.pending = pending;
        let mut joined_now: Vec<Key> = Vec::new();
        if self.ours.insert((run.pid, run.start)) {
            joined_now.push((run.pid, run.start));
        }
        loop {
            let joined: Vec<Key> = links
                .iter()
                .filter(|(child, parent)| !self.ours.contains(child) && self.ours.contains(parent))
                .map(|(child, _)| *child)
                .collect();
            if joined.is_empty() {
                break;
            }
            for key in joined {
                if self.ours.insert(key) {
                    joined_now.push(key);
                }
            }
        }

        // The run's processes' times. A process that has just been found to be the run's keeps its
        // time from the reading before, where that reading could read it. A time below one read
        // before is a misreading, and is not kept: taken as the start of a stretch it would add
        // work that was not done.
        for key in &joined_now {
            if let Some(time) = self.previous_times.get(key) {
                self.times.entry(*key).or_default().push(time.clone());
            }
        }
        let mut current_times: HashMap<Key, Time> = HashMap::with_capacity(processes.len());
        for process in &processes {
            let key = (process.pid, process.start);
            let time = Time {
                reading: number,
                own: process.own,
                lag: process.lag,
                threads: process.threads.clone(),
            };
            if self.ours.contains(&key) {
                let times = self.times.entry(key).or_default();
                if !times.last().is_some_and(|last| process.own < last.own) {
                    times.push(time.clone());
                }
            }
            current_times.insert(key, time);
        }
        self.previous_times = current_times;

        self.previous_table = table;
        self.readings.push(Kept {
            began: reading.began,
            ended: reading.ended,
            idle_before: reading.idle_before,
            idle_after: reading.idle_after,
            idle_resolution: reading.idle_resolution,
            time_resolution: reading.time_resolution,
        });
        Ok(())
    }

    /// The bound on other work in any `window` seconds after the first reading, and over the whole
    /// run of readings. A run of readings shorter than `window` is bounded over its own length.
    ///
    /// # Errors
    ///
    /// When fewer than two readings were taken, or when the run's processes were charged more
    /// processor time than the machine was busy for, which the counts this rests on cannot show
    /// unless one of them is wrong.
    pub fn summary(&self, window: f64) -> Result<Summary, String> {
        let last = self.readings.len().saturating_sub(1);
        if last == 0 {
            return Err("fewer than two readings were taken".to_owned());
        }
        // The step ran after the first reading ended and before the last one began, which the
        // order of the readings keeps apart.
        let window = (self.readings[last].began - self.readings[0].ended).min(window);
        // No stretch can hold more than every processor's time, however far a run of readings
        // reaches past the window it covers.
        let processors = f64::from(self.processors.unwrap_or(0));
        let (mut bound, mut allowance): (f64, f64) = (0.0, 0.0);
        // The windows that start after reading `start - 1` ended and before reading `start` ended
        // are covered from reading `start - 1` to the first reading that begins at least a window
        // after reading `start` ended.
        for start in 1..=last {
            let reach = self.readings[start].ended + window;
            let end = (start..=last)
                .find(|&end| self.readings[end].began >= reach)
                .unwrap_or(last);
            let (other, allowed) = self.other(start - 1, end)?;
            let covered = (other / window).min(processors);
            if covered > bound {
                bound = covered;
                allowance = (allowed / window).min(covered);
            }
        }
        let average = (self.other(0, last)?.0
            / (self.readings[last].ended - self.readings[0].began))
            .min(processors);
        Ok(Summary {
            bound,
            allowance,
            average,
            readings: self.readings.len(),
        })
    }

    /// The most processor time the machine can have spent on anything but the run from reading
    /// `from` to reading `to`, and how much of it the counts' allowances add.
    fn other(&self, from: usize, to: usize) -> Result<(f64, f64), String> {
        let (first, last) = (&self.readings[from], &self.readings[to]);
        let processors = f64::from(self.processors.unwrap_or(0));
        let resolution = self.readings[from..=to]
            .iter()
            .map(|kept| kept.idle_resolution)
            .fold(0.0, f64::max);
        let busy = processors * (last.ended - first.began) - (last.idle_after - first.idle_before)
            + resolution;
        let (least, set_aside) = self.run_least(from, to);
        let other = busy - least;
        // Rounding in the arithmetic, and no more.
        if other < -1e-6 {
            return Err(format!(
                "the run's processes were charged {:.3} s more processor time than the machine \
                 was busy for between readings {from} and {to}",
                -other
            ));
        }
        Ok((other.max(0.0), resolution + set_aside))
    }

    /// The least the run's processes can have used from reading `from` to reading `to`, and how
    /// much of what their times show was set aside for rounding and trailing.
    fn run_least(&self, from: usize, to: usize) -> (f64, f64) {
        let rounding = self.readings[from].time_resolution;
        let (mut least, mut set_aside) = (0.0, 0.0);
        for (key, times) in &self.times {
            let Some(latest) = times
                .iter()
                .rev()
                .find(|time| time.reading > from && time.reading <= to)
            else {
                continue;
            };
            if let Some(first) = times.iter().find(|time| time.reading == from) {
                let shown = latest.own - first.own;
                let whole = (shown - first.lag - rounding).max(0.0);
                let (mut kept, mut aside) = (whole, shown - whole);
                // Thread by thread where both ends took the threads: the larger least stands.
                if let (Some(before), Some(after)) = (&first.threads, &latest.threads) {
                    let (threads_kept, threads_aside) = threads_least(key.0, before, after);
                    if threads_kept > kept {
                        (kept, aside) = (threads_kept, threads_aside);
                    }
                }
                least += kept;
                set_aside += aside;
            } else if self
                .appeared
                .get(key)
                .is_some_and(|&appeared| appeared > from && appeared <= latest.reading)
            {
                let threads: f64 = latest
                    .threads
                    .iter()
                    .flat_map(|threads| &threads.each)
                    .map(|thread| thread.own)
                    .sum();
                least += latest.own.max(threads);
            }
        }
        (least, set_aside)
    }
}

/// The least process `pid`'s threads can have used between two readings that took them, and how
/// much of what their times show was set aside for trailing. Each thread read at both ends, known by
/// its identifier and start, counts its difference less its allowance at the first, never less than
/// nothing; the process's first thread counts only on the conditions the module comment gives.
fn threads_least(pid: u32, before: &Threads, after: &Threads) -> (f64, f64) {
    let at_first: HashMap<(u32, u64), &Thread> = before
        .each
        .iter()
        .map(|thread| ((thread.tid, thread.start), thread))
        .collect();
    let first_counts = before.alone
        || after.each.iter().any(|thread| {
            thread.tid != pid
                && at_first
                    .get(&(thread.tid, thread.start))
                    .is_some_and(|earlier| earlier.older)
        });
    let (mut least, mut set_aside) = (0.0, 0.0);
    for thread in &after.each {
        if thread.tid == pid && !first_counts {
            continue;
        }
        let Some(earlier) = at_first.get(&(thread.tid, thread.start)) else {
            continue;
        };
        let shown = thread.own - earlier.own;
        least += (shown - earlier.lag).max(0.0);
        set_aside += shown.clamp(0.0, earlier.lag);
    }
    (least, set_aside)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Process, Reading, Row, Tally, Thread, Threads};

    const RUN: u32 = 500;
    const PROCESSORS: u32 = 4;

    fn process(pid: u32, parent: u32, start: u64, own: f64) -> Row {
        Row::Read(Process {
            pid,
            parent,
            start,
            own,
            lag: 0.0,
            threads: None,
        })
    }

    /// A reading at `at` seconds, instantaneous, on a four-processor machine that has been idle for
    /// `idle` processor seconds, with the system's first process, the run and `rows`.
    fn reading(at: f64, idle: f64, rows: &[Row]) -> Reading {
        let mut all = vec![process(1, 0, 0, 0.0), process(RUN, 1, 10, 0.0)];
        all.extend_from_slice(rows);
        Reading {
            began: at,
            processors: PROCESSORS,
            idle_before: idle,
            rows: all,
            idle_after: idle,
            ended: at,
            idle_resolution: 0.0,
            time_resolution: 0.0,
        }
    }

    /// A reading of a machine whose processors were busy for `busy` seconds of all their time.
    fn busy(at: f64, busy: f64, rows: &[Row]) -> Reading {
        reading(at, f64::from(PROCESSORS) * at - busy, rows)
    }

    fn tally(readings: &[Reading]) -> Result<super::Summary, String> {
        let mut tally = Tally::new(RUN);
        for reading in readings {
            tally.add(reading)?;
        }
        tally.summary(5.0)
    }

    fn close(value: f64, expected: f64) -> bool {
        (value - expected).abs() < 1e-9
    }

    #[test]
    fn work_that_straddles_two_readings_is_bounded_whole() {
        // One processor busy from 2.5 s to 7.5 s, read every five seconds: each interval holds
        // half of it, and a five-second window holds all of it.
        let summary = tally(&[
            busy(0.0, 0.0, &[]),
            busy(5.0, 2.5, &[]),
            busy(10.0, 5.0, &[]),
        ])
        .unwrap();
        assert!(summary.bound >= 1.0, "{summary:?}");
        assert!(close(summary.average, 0.5), "{summary:?}");
    }

    #[test]
    fn a_quiet_machine_reads_quiet() {
        let readings: Vec<Reading> = (0..6_u32)
            .map(|step| {
                let at = f64::from(step) * 2.0;
                busy(at, at * 0.01, &[])
            })
            .collect();
        let summary = tally(&readings).unwrap();
        assert!(summary.bound < 0.05, "{summary:?}");
    }

    #[test]
    fn the_runs_own_work_is_not_other_work() {
        // Three processors' worth for the run, and nothing else.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 0.0)]),
            busy(2.0, 6.0, &[process(600, RUN, 20, 6.0)]),
            busy(4.0, 12.0, &[process(600, RUN, 20, 12.0)]),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn work_outside_the_run_is_other_work_whether_or_not_a_process_shows_it() {
        // Two processors' worth, none of it the run's: nothing in the table accounts for it.
        let summary = tally(&[
            busy(0.0, 0.0, &[]),
            busy(2.0, 4.0, &[]),
            busy(4.0, 8.0, &[]),
        ])
        .unwrap();
        assert!(close(summary.bound, 2.0), "{summary:?}");
        assert!(close(summary.allowance, 0.0), "{summary:?}");
    }

    #[test]
    fn the_rounding_and_trailing_of_a_run_processs_time_are_not_taken_as_its_work() {
        // Fifty run processes each advance a hundredth of a second, which rounding can make of a
        // thousandth, and one trails by a tenth; the machine counts only what really ran.
        let processes = |own: f64| -> Vec<Row> {
            (0..50)
                .map(|n| {
                    let mut row = process(600 + n, RUN, 20, own);
                    if let Row::Read(process) = &mut row
                        && n == 0
                    {
                        process.lag = 0.1;
                    }
                    row
                })
                .collect()
        };
        let mut readings = vec![
            busy(0.0, 0.0, &processes(1.0)),
            busy(2.0, 0.05, &processes(1.01)),
        ];
        for reading in &mut readings {
            reading.time_resolution = 0.01;
        }
        let summary = tally(&readings).unwrap();
        // Each delta of 0.01 is worth nothing after its rounding, so the machine's 0.05 seconds are
        // all counted as other work, and all of it is the allowance.
        assert!(close(summary.bound, 0.025), "{summary:?}");
        assert!(close(summary.allowance, 0.025), "{summary:?}");
    }

    #[test]
    fn the_idle_counts_resolution_is_added_back() {
        let mut readings = vec![busy(0.0, 0.0, &[]), busy(2.0, 0.0, &[])];
        for reading in &mut readings {
            reading.idle_resolution = 0.5;
        }
        let summary = tally(&readings).unwrap();
        assert!(close(summary.bound, 0.25), "{summary:?}");
        assert!(close(summary.allowance, 0.25), "{summary:?}");
    }

    #[test]
    fn a_reused_identifier_is_a_new_process() {
        // The run's process 600 ends after 100 s of work, and an unrelated process given the same
        // identifier uses five seconds, which is other work and not the run's.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 100.0)]),
            busy(5.0, 5.0, &[process(600, 1, 30, 5.0)]),
        ])
        .unwrap();
        assert!(close(summary.bound, 1.0), "{summary:?}");
    }

    #[test]
    fn a_run_processs_time_below_one_read_before_is_not_used() {
        // A misreading of 1.0 between 10.0 and 12.0 would add eleven seconds of the run's work to
        // the last two readings; kept out, the run's two seconds are subtracted over the whole run.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 10.0)]),
            busy(2.0, 1.0, &[process(600, RUN, 20, 1.0)]),
            busy(4.0, 2.0, &[process(600, RUN, 20, 12.0)]),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.25), "{summary:?}");
    }

    #[test]
    fn a_run_charged_more_than_the_machine_was_busy_is_unread() {
        let error = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 0.0)]),
            busy(2.0, 1.0, &[process(600, RUN, 20, 3.0)]),
        ])
        .unwrap_err();
        assert!(error.contains("charged 2.000 s more"), "{error}");
    }

    #[test]
    fn an_idle_count_that_goes_back_or_a_change_of_processors_is_unread() {
        let error = tally(&[reading(0.0, 5.0, &[]), reading(2.0, 4.0, &[])]).unwrap_err();
        assert!(error.contains("idle count went back"), "{error}");
        let mut fewer = reading(2.0, 8.0, &[]);
        fewer.processors = 2;
        let error = tally(&[reading(0.0, 0.0, &[]), fewer]).unwrap_err();
        assert!(error.contains("processors changed"), "{error}");
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
        without_run.rows.retain(|row| row.pid() != RUN);
        let error = Tally::new(RUN).add(&without_run).unwrap_err();
        assert!(error.contains("the run's own process 500"), "{error}");
        let mut run_unread = reading(0.0, 0.0, &[]);
        run_unread.rows.retain(|row| row.pid() != RUN);
        run_unread.rows.push(Row::Unread { pid: RUN });
        let error = Tally::new(RUN).add(&run_unread).unwrap_err();
        assert!(error.contains("the run's own process 500"), "{error}");
        let mut without_first = reading(0.0, 0.0, &[]);
        without_first.rows.retain(|row| row.pid() != 1);
        let error = Tally::new(RUN).add(&without_first).unwrap_err();
        assert!(error.contains("first process"), "{error}");
        let mut first_unread = reading(0.0, 0.0, &[]);
        first_unread.rows.retain(|row| row.pid() != 1);
        first_unread.rows.push(Row::Unread { pid: 1 });
        Tally::new(RUN).add(&first_unread).unwrap();
        let error = Tally::new(RUN)
            .add(&reading(0.0, 0.0, &[process(RUN, 1, 11, 0.0)]))
            .unwrap_err();
        assert!(error.contains("names process 500 twice"), "{error}");
    }

    #[test]
    fn the_runs_processes_stay_the_runs_when_reparented() {
        // The run's worker outlives its parent and is reparented to the first process; its work
        // after that is still the run's.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 0.0)]),
            busy(2.0, 2.0, &[process(600, 1, 20, 2.0)]),
            busy(4.0, 4.0, &[process(600, 1, 20, 4.0)]),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn the_runs_new_processes_are_its_own_with_all_they_used() {
        // A process the run starts between two readings, and its child, used three seconds before
        // the reading that first holds them. The next reading shows their parents again, and they
        // are the run's with everything they used.
        let summary = tally(&[
            busy(0.0, 0.0, &[]),
            busy(
                2.0,
                3.0,
                &[process(600, RUN, 20, 1.0), process(601, 600, 21, 2.0)],
            ),
            busy(
                4.0,
                3.0,
                &[process(600, RUN, 20, 1.0), process(601, 600, 21, 2.0)],
            ),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn a_process_whose_row_cannot_be_read_is_not_taken_as_the_runs_work() {
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 0.0)]),
            busy(2.0, 2.0, &[Row::Unread { pid: 600 }]),
        ])
        .unwrap();
        assert!(close(summary.bound, 1.0), "{summary:?}");
    }

    #[test]
    fn a_parent_identifier_that_passes_to_another_process_after_its_row_is_read_is_not_the_parent()
    {
        // The run's process 800 is read; it ends, its identifier passes to an unrelated process,
        // which starts 900, and 900's row, read after 800's, names 800 as its parent. The next
        // reading shows 800 held by the unrelated process, so 900 is not the run's, and its two
        // seconds are other work.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(800, RUN, 30, 0.0)]),
            busy(2.0, 0.0, &[process(800, RUN, 30, 0.0)]),
            busy(
                4.0,
                0.0,
                &[process(800, RUN, 30, 0.0), process(900, 800, 60, 0.0)],
            ),
            busy(
                6.0,
                2.0,
                &[process(800, 1, 50, 0.0), process(900, 800, 60, 2.0)],
            ),
        ])
        .unwrap();
        assert!(close(summary.bound, 2.0 / 5.0), "{summary:?}");
    }

    #[test]
    fn a_parent_read_after_its_child_and_seen_before_is_the_parent() {
        // Row 700 names 800, whose row is read after it and was in the reading before: 800 held
        // its identifier throughout, so 700 is the run's at once.
        let summary = tally(&[
            busy(0.0, 0.0, &[process(800, RUN, 30, 0.0)]),
            busy(2.0, 0.0, &[process(800, RUN, 30, 0.0)]),
            busy(
                4.0,
                1.0,
                &[process(700, 800, 35, 1.0), process(800, RUN, 30, 0.0)],
            ),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn a_parent_read_before_its_child_counts_once_the_next_reading_shows_it_again() {
        // Row 600 is read before its child 601. Until a later reading shows 600 again, 601's work
        // is other work; once it does, 601 is the run's with the time it had.
        let two = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 40, 0.0)]),
            busy(
                2.0,
                2.0,
                &[process(600, RUN, 40, 0.0), process(601, 600, 41, 2.0)],
            ),
        ])
        .unwrap();
        assert!(close(two.bound, 1.0), "{two:?}");
        let three = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 40, 0.0)]),
            busy(
                2.0,
                2.0,
                &[process(600, RUN, 40, 0.0), process(601, 600, 41, 2.0)],
            ),
            busy(
                4.0,
                2.0,
                &[process(600, RUN, 40, 0.0), process(601, 600, 41, 2.0)],
            ),
        ])
        .unwrap();
        assert!(close(three.bound, 0.0), "{three:?}");
    }

    #[test]
    fn a_run_shorter_than_a_second_is_not_spread_over_a_second() {
        // Half a second with one processor busy is one processor's worth over its own length.
        let summary = tally(&[busy(0.0, 0.0, &[]), busy(0.5, 0.5, &[])]).unwrap();
        assert!(close(summary.bound, 1.0), "{summary:?}");
    }

    #[test]
    fn no_window_holds_more_than_every_processor() {
        // Every processor busy for eight seconds, read every four: a window's run of readings
        // covers all eight, and the bound is still the machine's four processors.
        let summary = tally(&[
            busy(0.0, 0.0, &[]),
            busy(4.0, 16.0, &[]),
            busy(8.0, 32.0, &[]),
        ])
        .unwrap();
        assert!(close(summary.bound, 4.0), "{summary:?}");
    }

    /// A row whose time was taken thread by thread: `threads` as (identifier, own), each started
    /// long before the reading and read asleep.
    fn threaded(pid: u32, parent: u32, start: u64, threads: &[(u32, f64)]) -> Row {
        Row::Read(Process {
            pid,
            parent,
            start,
            own: threads.iter().map(|&(_, own)| own).sum(),
            lag: 0.0,
            threads: Some(Threads {
                alone: threads.len() == 1,
                each: threads
                    .iter()
                    .map(|&(tid, own)| Thread {
                        tid,
                        start,
                        own,
                        lag: 0.0,
                        older: true,
                    })
                    .collect(),
            }),
        })
    }

    #[test]
    fn the_candidates_are_the_run_and_everything_below_it() {
        let mut tally = Tally::new(RUN);
        let first = reading(
            0.0,
            0.0,
            &[
                process(600, RUN, 20, 0.0),
                process(601, 600, 21, 0.0),
                process(700, 1, 30, 0.0),
            ],
        );
        assert_eq!(
            tally.candidates(&first.rows),
            HashSet::from([RUN, 600, 601])
        );
        tally.add(&first).unwrap();
        tally
            .add(&reading(
                2.0,
                0.0,
                &[process(600, RUN, 20, 0.0), process(601, 600, 21, 0.0)],
            ))
            .unwrap();
        // Once the run's, still the run's when reparented; an identifier that passes to a process
        // outside the run is not the run's, and a new child of a run process is.
        let later = reading(
            4.0,
            0.0,
            &[
                process(600, 1, 20, 0.0),
                process(601, 1, 99, 0.0),
                process(602, 600, 100, 0.0),
            ],
        );
        assert_eq!(
            tally.candidates(&later.rows),
            HashSet::from([RUN, 600, 602])
        );
    }

    #[test]
    fn a_process_read_whole_at_one_end_and_by_threads_at_the_other_counts_its_whole_time() {
        let summary = tally(&[
            busy(0.0, 0.0, &[process(600, RUN, 20, 1.0)]),
            busy(2.0, 2.0, &[threaded(600, RUN, 20, &[(600, 3.0)])]),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn threads_that_come_and_go_inside_a_stretch_count_through_their_process() {
        // A pool made for each piece of work: its threads start and end between readings, so no
        // reading sees them, and only the process's whole time holds their two seconds.
        let mut first = threaded(600, RUN, 20, &[(600, 1.0)]);
        let mut last = threaded(600, RUN, 20, &[(600, 1.1)]);
        for (row, own) in [(&mut first, 1.0), (&mut last, 3.1)] {
            if let Row::Read(process) = row {
                process.own = own;
            }
        }
        let summary = tally(&[busy(0.0, 0.0, &[first]), busy(2.0, 2.1, &[last])]).unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn a_process_that_appears_counts_all_its_threads_time() {
        let summary = tally(&[
            busy(0.0, 0.0, &[]),
            busy(
                2.0,
                3.0,
                &[threaded(600, RUN, 20, &[(600, 1.0), (601, 2.0)])],
            ),
            busy(
                4.0,
                3.0,
                &[threaded(600, RUN, 20, &[(600, 1.0), (601, 2.0)])],
            ),
        ])
        .unwrap();
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn a_short_run_is_bounded_over_its_own_length() {
        let summary = tally(&[busy(0.0, 0.0, &[]), busy(2.0, 1.0, &[])]).unwrap();
        assert!(close(summary.bound, 0.5), "{summary:?}");
    }
}
