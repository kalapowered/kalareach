//! Linux's process table as `/proc` shows it, read from a directory so that a stand-in tree can
//! take its place in the checks: every process's status line, and the threads of the processes a
//! reading asks for, each with the processor time the kernel has charged to it.
//!
//! A thread's time is the first field of `task/<tid>/schedstat`, the scheduler's own count of the
//! time the thread has run, in nanoseconds. A process's `utime` and `stime` are the same counts,
//! summed, split and rounded down to clock ticks, so a thread's figure is never rounded. It trails
//! the thread's real time only while the thread is on a processor, since the scheduler adds what a
//! thread ran at every clock tick while it runs and whenever it leaves a processor, and by at most
//! one tick then. A thread's state says whether it was running, but not exactly: a thread sets a
//! sleeping state before it leaves the processor. So each thread's time is read twice, the second
//! read at least two ticks after the first one ended: a thread that was running at the first read
//! with time not yet charged has that time charged by its next tick or switch, within one tick, so
//! its time moves by at least what it trailed. A thread whose state is running carries a tick; any
//! other carries the lesser of a tick and how far its time moved.
//!
//! The thread's status line, read after both times, gives its start and says it was still a live
//! thread of the process when its times were taken: a thread gone at any read, or one ending
//! (`Z` or `X`), is left out. That last check matters where another thread of the process execs:
//! it takes the first thread's identifier and hands its own old identifier to the ending first
//! thread. And once all the chosen processes' threads are read, each process's status line is read
//! again: a process gone, or whose identifier now names another start, loses its threads, since
//! they may not be its own.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::other_work::{Process, Row, Thread, Threads};

/// A `/proc` tree and the rates its times are read in.
pub(crate) struct Tree {
    root: PathBuf,
    /// The rate the tree prints times and starts in, `USER_HZ`.
    ticks_per_second: u64,
    /// The rate the kernel's clock ticks at, which is how often a running thread's time is brought
    /// up to date.
    clock_rate: f64,
}

/// A thread whose first time has been read and whose second read waits for its moment.
struct Waiting {
    /// Which of the chosen processes it belongs to.
    process: usize,
    tid: u32,
    /// Its time at the first read, in nanoseconds.
    first: u64,
    /// When the second read may be taken.
    due: Instant,
}

/// A chosen process's threads, as they are read.
struct Taking {
    /// Its row's place in the table.
    row: usize,
    pid: u32,
    start: u64,
    alone: bool,
    /// The boot clock, in hundredths of a second, read just before the first thread's first read.
    uptime: u64,
    each: Vec<Thread>,
}

impl Tree {
    pub(crate) fn new(root: impl Into<PathBuf>, ticks_per_second: u64, clock_rate: f64) -> Self {
        Self {
            root: root.into(),
            ticks_per_second,
            clock_rate,
        }
    }

    /// Whether the kernel keeps each thread's own time: the reader's own thread's time, which is
    /// more than nothing since it has run. A kernel without the file, or one that prints zeros
    /// there, does not, and the whole run reads each process's ticks instead.
    pub(crate) fn keeps_thread_times(&self) -> bool {
        std::fs::read_to_string(self.root.join("thread-self/schedstat"))
            .ok()
            .and_then(|text| first_count(&text))
            .is_some_and(|time| time > 0)
    }

    /// Every process in the table, each row read once, with how many threads each read row gave
    /// its process. A process that ended and was collected after the table was listed is left out.
    pub(crate) fn processes(
        &self,
        processors: u32,
    ) -> Result<(Vec<Row>, HashMap<u32, u32>), String> {
        let entries = std::fs::read_dir(&self.root)
            .map_err(|error| format!("list the process table: {error}"))?;
        let mut rows = Vec::new();
        let mut threads = HashMap::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("list the process table: {error}"))?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(status) = self.read(&format!("{pid}/stat"))? else {
                continue;
            };
            let (row, count) = self.status(pid, &status, processors)?;
            if let Some(count) = count {
                threads.insert(pid, count);
            }
            rows.push(row);
        }
        Ok((rows, threads))
    }

    /// A process's status line. The command name is the second field and may hold spaces and
    /// parentheses, so the fields are counted from after the last parenthesis, which ends it: the
    /// state is field 3, the parent 4, the process's user and system ticks 14 and 15, its threads
    /// 20, and its start, in ticks since the machine started, 22. A process that has ended and waits
    /// to be collected is listed as unread, as on macOS.
    fn status(
        &self,
        pid: u32,
        status: &str,
        processors: u32,
    ) -> Result<(Row, Option<u32>), String> {
        let unread = || format!("process {pid}'s status reads `{}`", status.trim_end());
        let fields = fields(status).ok_or_else(unread)?;
        if matches!(fields.first(), Some(&("Z" | "X" | "x"))) {
            return Ok((Row::Unread { pid }, None));
        }
        let count = |number: usize| -> Result<u64, String> {
            fields
                .get(number - 3)
                .and_then(|field| field.parse().ok())
                .ok_or_else(unread)
        };
        let parent = u32::try_from(count(4)?).map_err(|_| unread())?;
        let threads = u32::try_from(count(20)?).unwrap_or(u32::MAX);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a tick count is far inside f64's exact range"
        )]
        let own = (count(14)? + count(15)?) as f64 / self.ticks_per_second as f64;
        let process = Process {
            pid,
            parent,
            start: count(22)?,
            own,
            lag: f64::from(threads.min(processors)) / self.clock_rate,
            threads: None,
        };
        Ok((Row::Read(process), Some(threads)))
    }

    /// Takes the threads of each read row whose process is in `chosen`, in the table's order, and
    /// gives each its [`Threads`]. `rows` and `counts` are what [`Tree::processes`] returned.
    /// `sleep` waits for a second read's moment; the checks stand a file change in for the wait.
    pub(crate) fn threads(
        &self,
        rows: &mut [Row],
        counts: &HashMap<u32, u32>,
        chosen: &HashSet<u32>,
        sleep: &mut dyn FnMut(Duration),
    ) -> Result<(), String> {
        let gap = Duration::from_secs_f64(2.0 / self.clock_rate);
        let mut taking: Vec<Taking> = Vec::new();
        let mut waiting: VecDeque<Waiting> = VecDeque::new();
        for (row, entry) in rows.iter().enumerate() {
            let Row::Read(process) = entry else {
                continue;
            };
            if !chosen.contains(&process.pid) {
                continue;
            }
            let Some(tids) = self.tids(process.pid)? else {
                continue;
            };
            let uptime = self.uptime()?;
            taking.push(Taking {
                row,
                pid: process.pid,
                start: process.start,
                alone: counts.get(&process.pid) == Some(&1),
                uptime,
                each: Vec::new(),
            });
            for tid in tids {
                if let Some(first) = self.time(process.pid, tid)? {
                    waiting.push_back(Waiting {
                        process: taking.len() - 1,
                        tid,
                        first,
                        due: Instant::now() + gap,
                    });
                }
                // The second reads that are due, between first reads, so that each thread's two
                // reads stay about two ticks apart however many threads there are.
                while waiting
                    .front()
                    .is_some_and(|next| next.due <= Instant::now())
                {
                    if let Some(next) = waiting.pop_front() {
                        self.finish(&next, &mut taking)?;
                    }
                }
            }
        }
        while let Some(next) = waiting.pop_front() {
            let remaining = next.due.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                sleep(remaining);
            }
            self.finish(&next, &mut taking)?;
        }
        for process in taking {
            // The same identifier and start as the row read before the threads: the same process
            // throughout, so every thread read in between was its own.
            let same = match self.read(&format!("{}/stat", process.pid))? {
                Some(status) => fields(&status).is_some_and(|fields| {
                    fields.get(19).and_then(|start| start.parse::<u64>().ok())
                        == Some(process.start)
                }),
                None => false,
            };
            if !same {
                continue;
            }
            if let Some(Row::Read(row)) = rows.get_mut(process.row) {
                row.threads = Some(Threads {
                    alone: process.alone,
                    each: process.each,
                });
            }
        }
        Ok(())
    }

    /// A thread's second time and its status line, which make its reading or leave it out.
    fn finish(&self, waiting: &Waiting, taking: &mut [Taking]) -> Result<(), String> {
        let Some(process) = taking.get_mut(waiting.process) else {
            return Ok(());
        };
        let Some(second) = self.time(process.pid, waiting.tid)? else {
            return Ok(());
        };
        let Some(status) = self.read(&format!("{}/task/{}/stat", process.pid, waiting.tid))? else {
            return Ok(());
        };
        let unread = || {
            format!(
                "thread {} of process {}'s status reads `{}`",
                waiting.tid,
                process.pid,
                status.trim_end()
            )
        };
        let fields = fields(&status).ok_or_else(unread)?;
        let state = fields.first().copied().ok_or_else(unread)?;
        let start: u64 = fields
            .get(19)
            .and_then(|start| start.parse().ok())
            .ok_or_else(unread)?;
        if matches!(state, "Z" | "X" | "x") || second < waiting.first {
            return Ok(());
        }
        let tick = 1.0 / self.clock_rate;
        #[expect(
            clippy::cast_precision_loss,
            reason = "a thread's time in nanoseconds is far inside f64's exact range"
        )]
        let (own, moved) = (
            waiting.first as f64 / 1e9,
            (second - waiting.first) as f64 / 1e9,
        );
        process.each.push(Thread {
            tid: waiting.tid,
            start,
            own,
            lag: if state == "R" { tick } else { moved.min(tick) },
            // It started before the uptime read, which came before the first thread's first read:
            // its start, rounded down, ends no later than the uptime, rounded down.
            older: (start + 1) * 100 <= process.uptime * self.ticks_per_second,
        });
        Ok(())
    }

    /// A process's threads' identifiers, its first thread first, or nothing where it has gone.
    fn tids(&self, pid: u32) -> Result<Option<Vec<u32>>, String> {
        let entries = match std::fs::read_dir(self.root.join(format!("{pid}/task"))) {
            Ok(entries) => entries,
            Err(error) if gone(&error) => return Ok(None),
            Err(error) => return Err(format!("list process {pid}'s threads: {error}")),
        };
        let mut tids = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if gone(&error) => return Ok(None),
                Err(error) => return Err(format!("list process {pid}'s threads: {error}")),
            };
            if let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                tids.push(tid);
            }
        }
        tids.sort_unstable_by_key(|tid| (*tid != pid, *tid));
        Ok(Some(tids))
    }

    /// A thread's time in nanoseconds, or nothing where it has gone.
    fn time(&self, pid: u32, tid: u32) -> Result<Option<u64>, String> {
        let Some(text) = self.read(&format!("{pid}/task/{tid}/schedstat"))? else {
            return Ok(None);
        };
        first_count(&text).map(Some).ok_or_else(|| {
            format!(
                "thread {tid} of process {pid}'s time reads `{}`",
                text.trim_end()
            )
        })
    }

    /// The boot clock in hundredths of a second, the clock and unit a start is printed in.
    fn uptime(&self) -> Result<u64, String> {
        let text = self
            .read("uptime")?
            .ok_or_else(|| "the boot clock cannot be read".to_owned())?;
        let unread = || format!("the boot clock reads `{}`", text.trim_end());
        let (seconds, hundredths) = text
            .split_whitespace()
            .next()
            .and_then(|uptime| uptime.split_once('.'))
            .ok_or_else(unread)?;
        let seconds: u64 = seconds.parse().map_err(|_| unread())?;
        if hundredths.len() != 2 {
            return Err(unread());
        }
        let hundredths: u64 = hundredths.parse().map_err(|_| unread())?;
        Ok(seconds * 100 + hundredths)
    }

    /// A file of the tree, or nothing where its process or thread has gone.
    fn read(&self, path: &str) -> Result<Option<String>, String> {
        match std::fs::read_to_string(self.root.join(path)) {
            Ok(text) => Ok(Some(text)),
            Err(error) if gone(&error) => Ok(None),
            Err(error) => Err(format!("read {}: {error}", self.root.join(path).display())),
        }
    }
}

/// A status line's fields after the command name, which ends at the line's last parenthesis.
fn fields(status: &str) -> Option<Vec<&str>> {
    Some(status.rsplit_once(')')?.1.split_whitespace().collect())
}

/// The first whole number of a line, which is a thread's time in `schedstat`.
fn first_count(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/// Whether a read failed because its process or thread has gone.
fn gone(error: &std::io::Error) -> bool {
    #[cfg(target_os = "linux")]
    if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) {
        return true;
    }
    error.kind() == std::io::ErrorKind::NotFound
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use super::Tree;
    use crate::other_work::{Reading, Row, Summary, Tally, Thread};

    const RUN: u32 = 500;
    const PROCESSORS: u32 = 4;
    /// A slow clock, so that a thread's two reads are a fifth of a second apart and a check's change
    /// to the tree always lands between them. The checks never wait: they make the change instead.
    const CLOCK_RATE: f64 = 10.0;
    const TICK: f64 = 0.1;
    /// The boot clock the stand-in tree gives, in hundredths of a second.
    const UPTIME: u64 = 100_000;
    /// A start well before the uptime, and one at it.
    const OLD: u64 = 50;
    const NEW: u64 = UPTIME;

    /// A status line with the fields the reader takes, a process's or a thread's.
    fn status(pid: u32, state: char, parent: u32, ticks: u64, threads: u32, start: u64) -> String {
        format!(
            "{pid} (stand (in)) {state} {parent} {pid} {pid} 0 -1 4194304 0 0 0 0 {ticks} 0 0 0 20 0 \
             {threads} 0 {start} 0 0\n"
        )
    }

    /// A `/proc` tree in a directory of its own, with the system's first process and the run.
    struct StandIn {
        directory: tempfile::TempDir,
    }

    impl StandIn {
        fn new(threads: u32) -> Self {
            let stand_in = Self {
                directory: tempfile::tempdir().expect("make a directory for the stand-in tree"),
            };
            stand_in.write("uptime", &format!("{}.00 0.00\n", UPTIME / 100));
            stand_in.write("thread-self/schedstat", "123456 0 1\n");
            stand_in.write("1/stat", &status(1, 'S', 0, 0, 1, 1));
            stand_in.process(RUN, 1, OLD, 0, threads);
            stand_in
        }

        fn tree(&self) -> Tree {
            Tree::new(self.directory.path(), 100, CLOCK_RATE)
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.directory.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a file in the tree"))
                .expect("make the stand-in tree's directories");
            std::fs::write(path, text).expect("write the stand-in tree");
        }

        fn process(&self, pid: u32, parent: u32, start: u64, ticks: u64, threads: u32) {
            self.write(
                &format!("{pid}/stat"),
                &status(pid, 'S', parent, ticks, threads, start),
            );
        }

        /// A thread of the run, in `state`, started at `start`, with `seconds` charged to it.
        fn thread(&self, tid: u32, state: char, start: u64, seconds: f64) {
            self.write(
                &format!("{RUN}/task/{tid}/stat"),
                &status(tid, state, 1, 0, 1, start),
            );
            self.time(tid, seconds);
        }

        fn time(&self, tid: u32, seconds: f64) {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a check's times are small and not negative"
            )]
            let nanoseconds = (seconds * 1e9).round() as u64;
            self.write(
                &format!("{RUN}/task/{tid}/schedstat"),
                &format!("{nanoseconds} 20 3\n"),
            );
        }

        /// Ends a thread. A change runs once for each thread waiting for its second read, so this
        /// may find the thread gone already.
        fn end(&self, tid: u32) {
            let path = self.directory.path().join(format!("{RUN}/task/{tid}"));
            if path.exists() {
                std::fs::remove_dir_all(path).expect("end a stand-in thread");
            }
        }

        /// A reading of the tree at `at` seconds, taking the threads of the run's processes, on a
        /// machine whose processors were busy for `busy` seconds of all their time. `between` runs
        /// between each thread's two reads.
        fn reading(&self, tally: &Tally, at: f64, busy: f64, mut between: impl FnMut()) -> Reading {
            let tree = self.tree();
            let (mut rows, counts) = tree.processes(PROCESSORS).expect("read the table");
            let chosen = tally.candidates(&rows);
            tree.threads(&mut rows, &counts, &chosen, &mut |_: Duration| between())
                .expect("read the run's threads");
            let idle = f64::from(PROCESSORS) * at - busy;
            Reading {
                began: at,
                processors: PROCESSORS,
                idle_before: idle,
                rows,
                idle_after: idle,
                ended: at,
                idle_resolution: 0.0,
                time_resolution: 0.0,
            }
        }
    }

    fn run_threads(reading: &Reading) -> Option<&Vec<Thread>> {
        reading.rows.iter().find_map(|row| match row {
            Row::Read(process) if process.pid == RUN => {
                process.threads.as_ref().map(|threads| &threads.each)
            }
            _ => None,
        })
    }

    /// Two readings two seconds apart, with `change` made to the tree between them.
    fn stretch(
        stand_in: &StandIn,
        busy: f64,
        mut first: impl FnMut(),
        change: impl FnOnce(),
    ) -> Summary {
        let mut tally = Tally::new(RUN);
        let reading = stand_in.reading(&tally, 0.0, 0.0, &mut first);
        tally.add(&reading).expect("take the first reading");
        change();
        let reading = stand_in.reading(&tally, 2.0, busy, || {});
        tally.add(&reading).expect("take the second reading");
        tally.summary(5.0).expect("bound the other work")
    }

    fn close(value: f64, expected: f64) -> bool {
        (value - expected).abs() < 1e-9
    }

    #[test]
    fn a_kernel_that_keeps_no_time_for_each_thread_is_read_process_by_process() {
        let stand_in = StandIn::new(1);
        assert!(stand_in.tree().keeps_thread_times());
        stand_in.write("thread-self/schedstat", "0 0 0\n");
        assert!(
            !stand_in.tree().keeps_thread_times(),
            "a kernel that prints zeros"
        );
        stand_in.write("thread-self/schedstat", "not a time\n");
        assert!(
            !stand_in.tree().keeps_thread_times(),
            "a form this does not know"
        );
        std::fs::remove_dir_all(stand_in.directory.path().join("thread-self"))
            .expect("take the file away");
        assert!(
            !stand_in.tree().keeps_thread_times(),
            "a kernel without the file"
        );
    }

    #[test]
    fn a_process_read_whole_carries_the_tick_allowance() {
        // Without thread times each process carries its threads times one tick, and the rounding of
        // its two tick counts: three threads and two hundredths.
        let stand_in = StandIn::new(3);
        let mut tally = Tally::new(RUN);
        let (rows, _) = stand_in
            .tree()
            .processes(PROCESSORS)
            .expect("read the table");
        let mut first = Reading {
            began: 0.0,
            processors: PROCESSORS,
            idle_before: 0.0,
            rows,
            idle_after: 0.0,
            ended: 0.0,
            idle_resolution: 0.0,
            time_resolution: 0.02,
        };
        tally.add(&first).expect("take the first reading");
        stand_in.process(RUN, 1, OLD, 200, 3);
        let (rows, _) = stand_in
            .tree()
            .processes(PROCESSORS)
            .expect("read the table");
        first.rows = rows;
        first.began = 2.0;
        first.ended = 2.0;
        first.idle_before = 8.0 - 2.0;
        first.idle_after = 8.0 - 2.0;
        tally.add(&first).expect("take the second reading");
        let summary = tally.summary(5.0).expect("bound the other work");
        let allowance = 3.0 * TICK + 0.02;
        assert!(close(summary.allowance, allowance / 2.0), "{summary:?}");
        assert!(close(summary.bound, allowance / 2.0), "{summary:?}");
    }

    #[test]
    fn a_sleeping_thread_counts_exactly() {
        let stand_in = StandIn::new(1);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        let summary = stretch(&stand_in, 2.0, || {}, || stand_in.time(RUN, 3.0));
        assert!(close(summary.bound, 0.0), "{summary:?}");
        assert!(close(summary.allowance, 0.0), "{summary:?}");
    }

    #[test]
    fn a_running_thread_carries_one_tick() {
        let stand_in = StandIn::new(1);
        stand_in.thread(RUN, 'R', OLD, 1.0);
        let summary = stretch(&stand_in, 2.0, || {}, || stand_in.time(RUN, 3.0));
        assert!(close(summary.bound, TICK / 2.0), "{summary:?}");
        assert!(close(summary.allowance, TICK / 2.0), "{summary:?}");
    }

    #[test]
    fn a_thread_that_runs_between_its_reads_carries_what_it_ran_up_to_a_tick() {
        for (ran, carried) in [(0.03, 0.03), (0.5, TICK)] {
            let stand_in = StandIn::new(1);
            stand_in.thread(RUN, 'S', OLD, 1.0);
            let reading = stand_in.reading(&Tally::new(RUN), 0.0, 0.0, || {
                stand_in.time(RUN, 1.0 + ran);
            });
            let threads = run_threads(&reading).expect("the run's threads");
            assert_eq!(threads.len(), 1, "{threads:?}");
            assert!(close(threads[0].own, 1.0), "{threads:?}");
            assert!(close(threads[0].lag, carried), "{threads:?}");
        }
    }

    #[test]
    fn a_thread_that_ends_inside_a_stretch_never_raises_the_least() {
        // Of three threads, one ends inside the stretch and its identifier passes to a new thread.
        // The run used 1.6 s: 1.0 by the first thread, 0.4 by the one that lives through it, 0.1 by
        // the one that ended before it did and 0.1 by the new one. The least counts the 1.4 s of the
        // two it read at both ends, and none of the rest.
        let stand_in = StandIn::new(3);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'S', OLD, 5.0);
        stand_in.thread(502, 'S', OLD, 2.0);
        let summary = stretch(
            &stand_in,
            1.6,
            || {},
            || {
                stand_in.end(501);
                stand_in.thread(501, 'S', OLD + 900, 0.1);
                stand_in.time(RUN, 2.0);
                stand_in.time(502, 2.4);
            },
        );
        assert!(close(summary.bound, (1.6 - 1.4) / 2.0), "{summary:?}");
    }

    #[test]
    fn an_exec_by_another_thread_does_not_count_its_earlier_time() {
        // The first thread has used 1.0 s and a worker 10.0 s when the worker execs during the
        // first reading: it takes the first thread's identifier and start, and a helper it started
        // at once is read in the same reading. At the end the first thread's identifier shows the
        // worker's 10.2 s, of which the run used 0.2 s in the stretch, beside the helper's 0.05 s.
        let stand_in = StandIn::new(2);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'S', OLD, 10.0);
        stand_in.thread(502, 'S', NEW, 0.05);
        let summary = stretch(
            &stand_in,
            0.25,
            || {
                stand_in.end(501);
                stand_in.time(RUN, 10.0);
            },
            || {
                stand_in.time(RUN, 10.2);
                stand_in.time(502, 0.1);
            },
        );
        // Only the helper's 0.05 s counts: the first thread's match might be the worker's.
        assert!(close(summary.bound, (0.25 - 0.05) / 2.0), "{summary:?}");
    }

    #[test]
    fn an_exec_between_readings_does_not_count_the_takers_earlier_time() {
        let stand_in = StandIn::new(2);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'S', OLD, 10.0);
        let summary = stretch(
            &stand_in,
            0.3,
            || {},
            || {
                stand_in.end(501);
                stand_in.time(RUN, 10.2);
                stand_in.thread(502, 'S', NEW + 50, 0.1);
            },
        );
        assert!(close(summary.bound, 0.3 / 2.0), "{summary:?}");
    }

    #[test]
    fn an_older_thread_that_lives_through_the_stretch_lets_the_first_count() {
        let stand_in = StandIn::new(2);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'S', OLD, 2.0);
        let summary = stretch(
            &stand_in,
            1.5,
            || {},
            || {
                stand_in.time(RUN, 1.5);
                stand_in.time(501, 3.0);
            },
        );
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn the_first_thread_of_a_process_of_one_thread_counts() {
        let stand_in = StandIn::new(1);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        let summary = stretch(&stand_in, 0.5, || {}, || stand_in.time(RUN, 1.5));
        assert!(close(summary.bound, 0.0), "{summary:?}");
    }

    #[test]
    fn a_thread_that_is_ending_or_goes_back_is_left_out() {
        let stand_in = StandIn::new(3);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'Z', OLD, 3.0);
        stand_in.thread(502, 'S', OLD, 2.0);
        let reading = stand_in.reading(&Tally::new(RUN), 0.0, 0.0, || {
            stand_in.time(502, 1.0);
        });
        let threads = run_threads(&reading).expect("the run's threads");
        let tids: Vec<u32> = threads.iter().map(|thread| thread.tid).collect();
        assert_eq!(tids, [RUN], "{threads:?}");
    }

    #[test]
    fn a_process_whose_identifier_passes_to_another_while_it_is_read_loses_its_threads() {
        let stand_in = StandIn::new(1);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        let reading = stand_in.reading(&Tally::new(RUN), 0.0, 0.0, || {
            stand_in.process(RUN, 1, OLD + 7, 0, 1);
        });
        assert!(run_threads(&reading).is_none(), "{:?}", reading.rows);
    }

    #[test]
    fn only_the_runs_processes_are_read_by_thread_and_the_first_thread_first() {
        // Another process with threads of its own, outside the run, is read whole.
        let stand_in = StandIn::new(2);
        stand_in.thread(RUN, 'S', OLD, 1.0);
        stand_in.thread(501, 'S', OLD, 2.0);
        stand_in.process(700, 1, OLD, 0, 1);
        stand_in.write("700/task/700/stat", &status(700, 'S', 1, 0, 1, OLD));
        stand_in.write("700/task/700/schedstat", "5 0 1\n");
        let reading = stand_in.reading(&Tally::new(RUN), 0.0, 0.0, || {});
        let threaded: HashSet<u32> = reading
            .rows
            .iter()
            .filter_map(|row| match row {
                Row::Read(process) if process.threads.is_some() => Some(process.pid),
                _ => None,
            })
            .collect();
        assert_eq!(threaded, HashSet::from([RUN]));
        let threads = run_threads(&reading).expect("the run's threads");
        assert_eq!(threads[0].tid, RUN, "{threads:?}");
        assert!(threads.iter().all(|thread| thread.older), "{threads:?}");
    }
}
