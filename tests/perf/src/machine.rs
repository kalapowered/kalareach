//! Readings of this machine for [`crate::other_work`]: its processors' idle time and every process
//! on it.
//!
//! Linux keeps the processors' idle time on the first line of `/proc/stat` and each process's time
//! in `/proc/<pid>/stat`, in clock ticks; where the kernel keeps each thread's own time, in
//! nanoseconds, a reading also takes the threads of the processes that can be the run's
//! (`crate::procfs` says how). macOS keeps each processor's idle time in its load counters and each
//! process's time in its task information, which another user's process does not open to this
//! reader, so that process's row is listed as unread. What this reads rests on four things each
//! kernel does by design, which hold on the reference hosts. A reference figure rests on them only
//! in a run on a host set aside for it, with nothing else scheduled there; each comes with an
//! allowance the bound includes, which is none for the last two, and the reader checks what it
//! can:
//!
//! 1. Idle time is counted as it passes. Linux counts it exactly on a kernel that stops the clock
//!    tick on an idle processor, which distribution kernels for x86-64 and ARM64 are built to do on
//!    machines with one-shot timers; this checks `CONFIG_NO_HZ_COMMON` in the kernel's
//!    configuration and that no `nohz=` on its command line turns it off, and does not read a
//!    kernel that fails either. macOS brings an idle processor's count up to date as it is read.
//!    Allowance: rounding to a hundredth of a second (the idle and waiting counts on Linux), and on
//!    macOS a hundredth and one ten-millisecond quantum for each processor.
//! 2. A running thread's charged time trails by at most one clock tick on Linux, since the tick
//!    brings it up to date and a quiet host holds interrupts off for microseconds; this reads the
//!    clock rate from the kernel's configuration and does not read a kernel with a processor that
//!    stops the tick while a thread runs (`nohz_full`). On macOS it trails by at most one
//!    ten-millisecond scheduling quantum. Allowance, where Linux keeps each thread's time: for each
//!    of the run's threads, one tick if its state is running, and otherwise the lesser of one tick
//!    and how far its time moved in the two ticks after it was read; a process whose whole time
//!    counts more than its threads' carries the whole reading's allowance instead. Where it does
//!    not (no `schedstat`, or zeros in it): for each process, its running threads times one tick and
//!    a further two hundredths of a second for rounding. On macOS: for each process, its running
//!    threads times one quantum.
//! 3. An idle count, read from more than one field without a lock, is right at least once in three.
//!    A count taken just as a processor goes idle or wakes can drop that processor's current idle
//!    stretch (Linux, when a task waiting for a disk is woken elsewhere) or count it twice (macOS);
//!    each count is therefore taken three times, and the largest is kept where it starts a stretch,
//!    since a count that falls short would add idle time from before it, and the smallest where it
//!    ends one, since a count that runs over would add idle time that did not happen. Allowance:
//!    none, and nothing checks that one of the three is right.
//! 4. A process identifier and start name one process, and on Linux a thread identifier and start
//!    one thread: no identifier is given to a new process or thread within the hundredth of a
//!    second Linux gives the start in (macOS gives it to the microsecond). Both hand identifiers
//!    out in turn, Linux up to its `pid_max` and macOS up to 99,999, so one returns to use only
//!    after every other has been used. Allowance: none, and nothing checks it; where the reader
//!    reads threads it checks that a process's identifier names the same start after its threads
//!    are read, and leaves out a thread that is ending, which is how an exec hands another thread's
//!    identifier to the process's first thread.
//!
//! Elsewhere nothing is read and every reading fails.

use std::collections::HashSet;
use std::time::Instant;

use crate::other_work::{Reading, Row};

/// How many times each idle count is taken.
const COUNTS: usize = 3;

/// How a reading takes the processor time of the processes it reads closely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Times {
    /// Each thread's own time, where the kernel keeps it.
    Threads,
    /// Each process's time as a whole.
    Processes,
}

impl Times {
    /// The word a reading's record gives for it.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Threads => "threads",
            Self::Processes => "processes",
        }
    }
}

/// This machine, ready to be read.
pub struct Machine {
    clock: Instant,
    counts: platform::Counts,
}

impl Machine {
    /// Opens this machine for reading.
    ///
    /// # Errors
    ///
    /// Where this platform cannot be read, or cannot be read whole and exactly: on Linux, from a
    /// process namespace of its own, or on a kernel that does not count idle time exactly.
    pub fn open() -> Result<Self, String> {
        Ok(Self {
            clock: Instant::now(),
            counts: platform::Counts::open()?,
        })
    }

    /// How this machine's readings take the time of the processes they read closely, which is the
    /// same for every reading.
    #[must_use]
    pub fn times(&self) -> Times {
        self.counts.times()
    }

    /// Reads the machine: the idle count, every process, and the idle count again, between two
    /// moments on a monotonic clock. `candidates` names, from the process table, the processes
    /// whose threads the reading takes where it takes threads.
    ///
    /// # Errors
    ///
    /// When a count or the process table cannot be read, reads in a form this does not know, or the
    /// number of processors changes while it is read.
    pub fn reading(
        &mut self,
        candidates: impl FnOnce(&[Row]) -> HashSet<u32>,
    ) -> Result<Reading, String> {
        let began = self.clock.elapsed().as_secs_f64();
        let (idle_before, processors) = self.idle(f64::max)?;
        let rows = self.counts.rows(processors, candidates)?;
        let (idle_after, processors_after) = self.idle(f64::min)?;
        let ended = self.clock.elapsed().as_secs_f64();
        if processors_after != processors {
            return Err(format!(
                "the machine went from {processors} processors to {processors_after} while it was \
                 read"
            ));
        }
        Ok(Reading {
            began,
            processors,
            idle_before,
            rows,
            idle_after,
            ended,
            idle_resolution: self.counts.idle_resolution(processors),
            time_resolution: self.counts.time_resolution(),
        })
    }

    /// The idle count, taken [`COUNTS`] times and kept as `pick` chooses: the largest where it
    /// starts a stretch, the smallest where it ends one.
    fn idle(&mut self, pick: fn(f64, f64) -> f64) -> Result<(f64, u32), String> {
        let (mut idle, processors) = self.counts.idle()?;
        for _ in 1..COUNTS {
            let (again, processors_again) = self.counts.idle()?;
            if processors_again != processors {
                return Err(format!(
                    "the machine went from {processors} processors to {processors_again} while it \
                     was read"
                ));
            }
            idle = pick(idle, again);
        }
        Ok((idle, processors))
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::HashSet;

    use super::{Row, Times};
    use crate::procfs::Tree;

    /// The initial process namespace's identifier, which the kernel fixes.
    const WHOLE_MACHINE: &str = "pid:[4026531836]";

    pub struct Counts {
        /// The rate `/proc` prints times in.
        ticks_per_second: f64,
        /// The process table.
        tree: Tree,
        /// Whether the kernel keeps each thread's own time, which the readings then take for the
        /// processes that can be the run's.
        threads: bool,
    }

    impl Counts {
        pub fn open() -> Result<Self, String> {
            let namespace = std::fs::read_link("/proc/self/ns/pid")
                .map_err(|error| format!("read this process's process namespace: {error}"))?;
            if namespace.as_os_str() != WHOLE_MACHINE {
                return Err(format!(
                    "this runs in process namespace {}, so its process table is not the whole \
                     machine's",
                    namespace.display()
                ));
            }
            let configuration = kernel_configuration()?;
            let setting = |name: &str| {
                configuration.lines().find_map(|line| {
                    line.strip_prefix(name)
                        .and_then(|rest| rest.strip_prefix('='))
                        .map(str::to_owned)
                })
            };
            if setting("CONFIG_NO_HZ_COMMON").as_deref() != Some("y") {
                return Err(
                    "this kernel keeps the clock tick running on an idle processor, so it counts \
                     idle time by sampling it"
                        .to_owned(),
                );
            }
            let command_line = std::fs::read_to_string("/proc/cmdline")
                .map_err(|error| format!("read the kernel's command line: {error}"))?;
            // The kernel reads the setting as a truth value: off, no, false and zero turn it off.
            if command_line
                .split_whitespace()
                .filter_map(|word| word.strip_prefix("nohz="))
                .any(|value| {
                    let mut letters = value.chars();
                    match letters.next() {
                        Some('n' | 'N' | 'f' | 'F' | '0') => true,
                        Some('o' | 'O') => matches!(letters.next(), Some('f' | 'F')),
                        _ => false,
                    }
                })
            {
                return Err(
                    "this kernel was started with its idle tick turned off, so it counts idle time \
                     by sampling it"
                        .to_owned(),
                );
            }
            match std::fs::read_to_string("/sys/devices/system/cpu/nohz_full") {
                Ok(processors) if !matches!(processors.trim(), "" | "(null)") => {
                    return Err(format!(
                        "processors {} stop the clock tick while a thread runs, so a running \
                         thread's time can trail by more than a tick",
                        processors.trim()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("read the tickless processors: {error}")),
            }
            let clock_rate = setting("CONFIG_HZ")
                .and_then(|rate| rate.parse::<u32>().ok())
                .filter(|rate| *rate > 0)
                .ok_or("the kernel's configuration names no clock rate")?;
            let ticks = rustix::param::clock_ticks_per_second();
            let tree = Tree::new("/proc", ticks, f64::from(clock_rate));
            let threads = tree.keeps_thread_times();
            #[expect(
                clippy::cast_precision_loss,
                reason = "a clock rate is a small integer"
            )]
            let ticks_per_second = ticks as f64;
            Ok(Self {
                ticks_per_second,
                tree,
                threads,
            })
        }

        pub fn times(&self) -> Times {
            if self.threads {
                Times::Threads
            } else {
                Times::Processes
            }
        }

        /// The idle and waiting counts are each rounded down.
        pub fn idle_resolution(&self, _processors: u32) -> f64 {
            2.0 / self.ticks_per_second
        }

        /// A process's user and system times are each rounded down.
        pub fn time_resolution(&self) -> f64 {
            2.0 / self.ticks_per_second
        }

        /// All processors' idle time, with the time spent idle waiting for a disk, and how many
        /// processors there are.
        pub fn idle(&mut self) -> Result<(f64, u32), String> {
            let stat = std::fs::read_to_string("/proc/stat")
                .map_err(|error| format!("read the processors' counts: {error}"))?;
            let unread = || "the processors' counts are not in the form this reads".to_owned();
            let total = stat
                .lines()
                .find(|line| line.starts_with("cpu "))
                .ok_or_else(unread)?;
            let counts: Vec<u64> = total
                .split_whitespace()
                .skip(1)
                .map(str::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| unread())?;
            // User, nice, system, idle and waiting come first, in that order.
            let (Some(idle), Some(waiting)) = (counts.get(3), counts.get(4)) else {
                return Err(unread());
            };
            let processors = stat
                .lines()
                .filter(|line| {
                    line.strip_prefix("cpu")
                        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
                })
                .count();
            let processors = u32::try_from(processors).map_err(|_| unread())?;
            #[expect(
                clippy::cast_precision_loss,
                reason = "a tick count is far inside f64's exact range"
            )]
            let seconds = (idle + waiting) as f64 / self.ticks_per_second;
            Ok((seconds, processors))
        }

        pub fn rows(
            &self,
            processors: u32,
            candidates: impl FnOnce(&[Row]) -> HashSet<u32>,
        ) -> Result<Vec<Row>, String> {
            let (mut rows, counts) = self.tree.processes(processors)?;
            if self.threads {
                let chosen = candidates(&rows);
                self.tree
                    .threads(&mut rows, &counts, &chosen, &mut std::thread::sleep)?;
            }
            Ok(rows)
        }
    }

    /// The running kernel's build configuration, from `/boot` or, where the kernel keeps it,
    /// `/proc/config.gz`.
    fn kernel_configuration() -> Result<String, String> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| format!("read the kernel's release: {error}"))?;
        if let Ok(configuration) =
            std::fs::read_to_string(format!("/boot/config-{}", release.trim()))
        {
            return Ok(configuration);
        }
        let output = std::process::Command::new("gzip")
            .args(["-dc", "/proc/config.gz"])
            .output()
            .map_err(|error| format!("read the kernel's configuration: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "the kernel's configuration is in neither /boot/config-{} nor /proc/config.gz",
                release.trim()
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| "the kernel's configuration is not text".to_owned())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    use std::collections::HashSet;

    use libproc::libproc::proc_pid::pidinfo;
    use libproc::libproc::task_info::TaskAllInfo;
    use libproc::processes::{ProcFilter, pids_by_type};

    use super::{Row, Times};
    use crate::other_work::Process;

    /// The load counters' idle state, by position among user, system, idle and nice.
    const IDLE: usize = 2;

    /// The scheduler's quantum for ordinary threads: a running thread's time is brought up to date
    /// at least this often, and so is a processor's count.
    const QUANTUM: f64 = 0.01;

    /// A process that has ended and waits to be collected, as the kernel's task information names
    /// it.
    const ENDED: u32 = 5;

    pub struct Counts {
        host: libc::mach_port_t,
        seconds_per_tick: f64,
        seconds_per_unit: f64,
        /// Each processor's counters at the last count. They are 32 bits wide and wrap, so the
        /// idle count is kept here, from their differences, signed: a counter misread high reads
        /// lower the next time, and the difference then takes the excess back.
        last: Vec<[u32; 4]>,
        idle_ticks: i64,
    }

    impl Counts {
        pub fn open() -> Result<Self, String> {
            let host = kernel::host();
            let last = kernel::processor_ticks(host)?;
            let (numerator, denominator) = kernel::time_base()?;
            Ok(Self {
                host,
                seconds_per_tick: 1.0 / clock_rate()?,
                seconds_per_unit: f64::from(numerator) / f64::from(denominator) / 1e9,
                last,
                idle_ticks: 0,
            })
        }

        /// Each process's time is read as a whole.
        pub fn times(&self) -> Times {
            Times::Processes
        }

        /// Each processor's idle time is rounded down to a tick, and can trail by one quantum.
        pub fn idle_resolution(&self, processors: u32) -> f64 {
            f64::from(processors) * (self.seconds_per_tick + QUANTUM)
        }

        /// A process's time is kept in the processor's own time units, which this reads exactly.
        pub fn time_resolution(&self) -> f64 {
            self.seconds_per_unit
        }

        pub fn idle(&mut self) -> Result<(f64, u32), String> {
            let now = kernel::processor_ticks(self.host)?;
            if now.len() != self.last.len() {
                return Err(format!(
                    "the machine went from {} processors to {} while it was read",
                    self.last.len(),
                    now.len()
                ));
            }
            for (now, last) in now.iter().zip(&self.last) {
                self.idle_ticks += i64::from(now[IDLE].wrapping_sub(last[IDLE]).cast_signed());
            }
            self.last = now;
            #[expect(
                clippy::cast_precision_loss,
                reason = "a tick count is far inside f64's exact range"
            )]
            let seconds = self.idle_ticks as f64 * self.seconds_per_tick;
            let processors = u32::try_from(self.last.len())
                .map_err(|_| "the machine counts more processors than this reads".to_owned())?;
            Ok((seconds, processors))
        }

        /// Every process the kernel lists, read one at a time. A process whose task information
        /// cannot be read, another user's or one that has ended, is listed as unread.
        pub fn rows(
            &self,
            processors: u32,
            _candidates: impl FnOnce(&[Row]) -> HashSet<u32>,
        ) -> Result<Vec<Row>, String> {
            let mut pids = pids_by_type(ProcFilter::All)
                .map_err(|error| format!("list the process table: {error}"))?;
            // In identifier order, as Linux lists them, so that a parent older than its children
            // is read before them.
            pids.sort_unstable();
            let mut rows = Vec::with_capacity(pids.len());
            for pid in pids {
                let Ok(signed) = i32::try_from(pid) else {
                    return Err(format!("the process table lists process {pid}"));
                };
                let row = match pidinfo::<TaskAllInfo>(signed, 0) {
                    Ok(info) if info.pbsd.pbi_status != ENDED => {
                        let running = u32::try_from(info.ptinfo.pti_numrunning).unwrap_or(0);
                        #[expect(
                            clippy::cast_precision_loss,
                            reason = "a processor time count is far inside f64's exact range"
                        )]
                        let own = (info.ptinfo.pti_total_user + info.ptinfo.pti_total_system)
                            as f64
                            * self.seconds_per_unit;
                        Row::Read(Process {
                            pid,
                            parent: info.pbsd.pbi_ppid,
                            start: info.pbsd.pbi_start_tvsec * 1_000_000
                                + info.pbsd.pbi_start_tvusec,
                            own,
                            lag: f64::from(running.min(processors)) * QUANTUM,
                            threads: None,
                        })
                    }
                    Ok(_) | Err(_) => Row::Unread { pid },
                };
                rows.push(row);
            }
            Ok(rows)
        }
    }

    /// The rate the kernel's load counters tick at.
    fn clock_rate() -> Result<f64, String> {
        let output = Command::new("sysctl")
            .args(["-n", "kern.clockrate"])
            .output()
            .map_err(|error| format!("read the clock rate: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "reading the clock rate ended with {}",
                output.status
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.split(',')
            .find_map(|part| {
                part.trim()
                    .trim_start_matches('{')
                    .trim()
                    .strip_prefix("hz = ")
            })
            .and_then(|hz| hz.trim().parse::<f64>().ok())
            .filter(|hz| *hz > 0.0)
            .ok_or_else(|| format!("the clock rate reads `{}`", text.trim()))
    }

    mod kernel {
        #![expect(
            unsafe_code,
            reason = "macOS gives each processor's idle time and the unit of a task's processor \
                      time only through interfaces that have no safe binding"
        )]

        /// The host port the load counters are read through.
        #[expect(
            deprecated,
            reason = "the libc crate points to a crate this workspace does not use for the same \
                      call"
        )]
        pub fn host() -> libc::mach_port_t {
            // SAFETY: the call has no preconditions and returns a send right to this host's port.
            unsafe { libc::mach_host_self() }
        }

        /// The ratio that turns the kernel's time units into nanoseconds.
        #[expect(
            deprecated,
            reason = "the libc crate points to a crate this workspace does not use for the same \
                      call"
        )]
        pub fn time_base() -> Result<(u32, u32), String> {
            let mut base = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: the pointer is to a live local of exactly the type the call writes.
            let status = unsafe { libc::mach_timebase_info(&raw mut base) };
            if status != libc::KERN_SUCCESS || base.numer == 0 || base.denom == 0 {
                return Err(format!("reading the kernel's time base returned {status}"));
            }
            Ok((base.numer, base.denom))
        }

        /// Each processor's user, system, idle and nice ticks.
        pub fn processor_ticks(host: libc::mach_port_t) -> Result<Vec<[u32; 4]>, String> {
            let mut processors: libc::natural_t = 0;
            let mut info: libc::processor_info_array_t = std::ptr::null_mut();
            let mut words: libc::mach_msg_type_number_t = 0;
            // SAFETY: the three pointers are to live locals of exactly the types the call writes.
            let status = unsafe {
                libc::host_processor_info(
                    host,
                    libc::PROCESSOR_CPU_LOAD_INFO,
                    &raw mut processors,
                    &raw mut info,
                    &raw mut words,
                )
            };
            if status != libc::KERN_SUCCESS {
                return Err(format!(
                    "reading the processors' load counters returned {status}"
                ));
            }
            let length = words as usize;
            let ticks = {
                // SAFETY: on success the kernel has mapped `words` integers at `info` into this
                // task, and they stay mapped until the deallocation below, after this last use.
                let integers = unsafe { std::slice::from_raw_parts(info, length) };
                integers
                    .chunks_exact(4)
                    .map(|counters| {
                        [
                            counters[0].cast_unsigned(),
                            counters[1].cast_unsigned(),
                            counters[2].cast_unsigned(),
                            counters[3].cast_unsigned(),
                        ]
                    })
                    .collect::<Vec<_>>()
            };
            // SAFETY: the region is the one the call above mapped, `length` integers long, and
            // nothing refers to it any more.
            let freed = unsafe {
                libc::vm_deallocate(
                    this_task(),
                    info.addr(),
                    length * std::mem::size_of::<libc::integer_t>(),
                )
            };
            if freed != libc::KERN_SUCCESS {
                return Err(format!(
                    "releasing the processors' load counters returned {freed}"
                ));
            }
            if ticks.len() != processors as usize || length != 4 * ticks.len() {
                return Err(format!(
                    "the load counters hold {length} values for {processors} processors"
                ));
            }
            Ok(ticks)
        }

        #[expect(
            deprecated,
            reason = "the libc crate points to a crate this workspace does not use for the same \
                      call"
        )]
        fn this_task() -> libc::mach_port_t {
            // SAFETY: the call reads the task's own port name and has no preconditions.
            unsafe { libc::mach_task_self() }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use std::collections::HashSet;

    use super::{Row, Times};

    pub struct Counts;

    const NOT_READ: &str = "this platform's processor time is not read here";

    impl Counts {
        pub fn open() -> Result<Self, String> {
            Err(NOT_READ.to_owned())
        }

        pub fn times(&self) -> Times {
            Times::Processes
        }

        pub fn idle_resolution(&self, _processors: u32) -> f64 {
            0.0
        }

        pub fn time_resolution(&self) -> f64 {
            0.0
        }

        pub fn idle(&mut self) -> Result<(f64, u32), String> {
            Err(NOT_READ.to_owned())
        }

        pub fn rows(
            &self,
            _processors: u32,
            _candidates: impl FnOnce(&[Row]) -> HashSet<u32>,
        ) -> Result<Vec<Row>, String> {
            Err(NOT_READ.to_owned())
        }
    }
}
