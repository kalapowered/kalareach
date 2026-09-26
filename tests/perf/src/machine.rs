//! Readings of this machine for [`crate::other_work`]: its processors' idle time and every process
//! on it.
//!
//! Linux keeps the processors' idle time on the first line of `/proc/stat` and each process's time
//! in `/proc/<pid>/stat`; macOS keeps each processor's idle time in its load counters and each
//! process's time in its task information, which another user's process does not open to this
//! reader, so that process's row is listed as unread. What this reads rests on four things each
//! kernel does by design, which hold on the reference hosts; each comes with an allowance the
//! bound includes, and the reader checks what it can:
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
//!    ten-millisecond scheduling quantum. Allowance: for each process, its running threads times one
//!    tick or one quantum, and on Linux a further two hundredths of a second for rounding.
//! 3. An idle count, read from more than one field without a lock, is right at least once in three.
//!    A count taken just as a processor goes idle or wakes can drop that processor's current idle
//!    stretch (Linux, when a task waiting for a disk is woken elsewhere) or count it twice (macOS);
//!    each count is therefore taken three times, and the largest is kept where it starts a stretch,
//!    since a count that falls short would add idle time from before it, and the smallest where it
//!    ends one, since a count that runs over would add idle time that did not happen.
//! 4. A process identifier and start name one process. Linux gives the start in hundredths of a
//!    second and macOS to the microsecond, and both hand identifiers out in turn, so one returns to
//!    use only after every other has been used.
//!
//! Elsewhere nothing is read and every reading fails.

use std::time::Instant;

use crate::other_work::{Reading, Row};

/// How many times each idle count is taken.
const COUNTS: usize = 3;

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

    /// Reads the machine: the idle count, every process, and the idle count again, between two
    /// moments on a monotonic clock.
    ///
    /// # Errors
    ///
    /// When a count or the process table cannot be read, reads in a form this does not know, or the
    /// number of processors changes while it is read.
    pub fn reading(&mut self) -> Result<Reading, String> {
        let began = self.clock.elapsed().as_secs_f64();
        let (idle_before, processors) = self.idle(f64::max)?;
        let rows = self.counts.rows(processors)?;
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
    use super::Row;
    use crate::other_work::Process;

    /// The initial process namespace's identifier, which the kernel fixes.
    const WHOLE_MACHINE: &str = "pid:[4026531836]";

    pub struct Counts {
        /// The rate `/proc` prints times in.
        ticks_per_second: f64,
        /// The rate the kernel's clock ticks at, which is how often a running thread's time is
        /// brought up to date.
        clock_rate: f64,
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
            #[expect(
                clippy::cast_precision_loss,
                reason = "a clock rate is a small integer"
            )]
            let ticks_per_second = rustix::param::clock_ticks_per_second() as f64;
            Ok(Self {
                ticks_per_second,
                clock_rate: f64::from(clock_rate),
            })
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

        pub fn rows(&self, processors: u32) -> Result<Vec<Row>, String> {
            let entries = std::fs::read_dir("/proc")
                .map_err(|error| format!("list the process table: {error}"))?;
            let mut rows = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| format!("list the process table: {error}"))?;
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                else {
                    continue;
                };
                let status = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                    Ok(status) => status,
                    // The process ended and was collected after the table was listed.
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            || error.raw_os_error()
                                == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(format!("read process {pid}'s status: {error}")),
                };
                rows.push(self.status(pid, &status, processors)?);
            }
            Ok(rows)
        }

        /// A process's status line. The command name is the second field and may hold spaces and
        /// parentheses, so the fields are counted from after the last parenthesis, which ends it:
        /// the state is field 3, the parent 4, the process's user and system ticks 14 and 15, its
        /// threads 20, and its start, in ticks since the machine started, 22. A process that has
        /// ended and waits to be collected is listed as unread, as on macOS.
        fn status(&self, pid: u32, status: &str, processors: u32) -> Result<Row, String> {
            let unread = || format!("process {pid}'s status reads `{}`", status.trim_end());
            let fields: Vec<&str> = status
                .rsplit_once(')')
                .ok_or_else(unread)?
                .1
                .split_whitespace()
                .collect();
            if matches!(fields.first(), Some(&("Z" | "X" | "x"))) {
                return Ok(Row::Unread { pid });
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
            let own = (count(14)? + count(15)?) as f64 / self.ticks_per_second;
            Ok(Row::Read(Process {
                pid,
                parent,
                start: count(22)?,
                own,
                lag: f64::from(threads.min(processors)) / self.clock_rate,
            }))
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

    use libproc::libproc::proc_pid::pidinfo;
    use libproc::libproc::task_info::TaskAllInfo;
    use libproc::processes::{ProcFilter, pids_by_type};

    use super::Row;
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
        pub fn rows(&self, processors: u32) -> Result<Vec<Row>, String> {
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
    use super::Row;

    pub struct Counts;

    const NOT_READ: &str = "this platform's processor time is not read here";

    impl Counts {
        pub fn open() -> Result<Self, String> {
            Err(NOT_READ.to_owned())
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

        pub fn rows(&self, _processors: u32) -> Result<Vec<Row>, String> {
            Err(NOT_READ.to_owned())
        }
    }
}
