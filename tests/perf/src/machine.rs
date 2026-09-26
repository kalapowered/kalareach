//! Readings of this machine for [`crate::other_work`]: its processors' busy time and every process
//! on it.
//!
//! Linux keeps both in `/proc`: the busy time on the first line of `/proc/stat`, and each process
//! in `/proc/<pid>/stat`, where its time with its collected children's is counted too. macOS keeps
//! each processor's busy time in the kernel's processor load counters, and `ps` lists the
//! processes; it does not count a collected child's time, so a process there is its own time only.
//! Both count in hundredths of a second. Elsewhere nothing is read and every reading fails.

use std::time::Instant;

use crate::other_work::{Process, Reading};

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
    /// Where this platform cannot be read, or cannot be read whole: on Linux, from a process
    /// namespace of its own, whose process table is not the machine's.
    pub fn open() -> Result<Self, String> {
        Ok(Self {
            clock: Instant::now(),
            counts: platform::Counts::open()?,
        })
    }

    /// Reads the machine: the busy count, every process, and the busy count again, each within the
    /// reading's two times.
    ///
    /// # Errors
    ///
    /// When a count or the process table cannot be read, or reads in a form this does not know.
    pub fn reading(&mut self) -> Result<Reading, String> {
        let began = self.clock.elapsed().as_secs_f64();
        let busy_before = self.counts.busy()?;
        let processes = self.counts.processes()?;
        let busy_after = self.counts.busy()?;
        Ok(Reading {
            began,
            busy_before,
            processes,
            busy_after,
            busy_resolution: self.counts.resolution(),
            ended: self.clock.elapsed().as_secs_f64(),
        })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::Process;

    /// The initial process namespace's identifier, which the kernel fixes.
    const WHOLE_MACHINE: &str = "pid:[4026531836]";

    /// The busy states on `/proc/stat`'s first line, by position after the label: user, nice,
    /// system, interrupts and deferred interrupts. A hypervisor's share is counted apart, and a
    /// guest's time is inside the user and nice counts already.
    const BUSY: [usize; 5] = [0, 1, 2, 5, 6];

    pub struct Counts {
        ticks_per_second: f64,
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
            #[expect(
                clippy::cast_precision_loss,
                reason = "a clock rate is a small integer"
            )]
            let ticks_per_second = rustix::param::clock_ticks_per_second() as f64;
            Ok(Self { ticks_per_second })
        }

        /// Each busy state is counted apart and rounded down, so the count of their sum can fall
        /// short by a tick for each.
        #[expect(
            clippy::cast_precision_loss,
            reason = "a count of busy states is a small integer"
        )]
        pub fn resolution(&self) -> f64 {
            BUSY.len() as f64 / self.ticks_per_second
        }

        pub fn busy(&mut self) -> Result<f64, String> {
            let stat = std::fs::read_to_string("/proc/stat")
                .map_err(|error| format!("read the processors' counts: {error}"))?;
            let line = stat
                .lines()
                .find(|line| line.starts_with("cpu "))
                .ok_or("the processors' counts have no total line")?;
            let counts: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .map(str::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| format!("the processors' total line reads `{line}`"))?;
            let mut busy: u64 = 0;
            for state in BUSY {
                busy += counts
                    .get(state)
                    .ok_or_else(|| format!("the processors' total line reads `{line}`"))?;
            }
            #[expect(
                clippy::cast_precision_loss,
                reason = "a tick count is far inside f64's exact range"
            )]
            let seconds = busy as f64 / self.ticks_per_second;
            Ok(seconds)
        }

        pub fn processes(&self) -> Result<Vec<Process>, String> {
            let entries = std::fs::read_dir("/proc")
                .map_err(|error| format!("list the process table: {error}"))?;
            let mut processes = Vec::new();
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
                    // The process ended after the table was listed.
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            || error.raw_os_error()
                                == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(format!("read process {pid}'s status: {error}")),
                };
                if let Some(process) = self.status(pid, &status)? {
                    processes.push(process);
                }
            }
            Ok(processes)
        }

        /// A process's status line. The command name is the second field and may hold spaces and
        /// parentheses, so the fields are counted from after the last parenthesis, which ends it:
        /// the state is field 3, the parent 4, the process's own user and system ticks 14 and 15,
        /// its collected children's 16 and 17, and its start, in ticks since the machine started,
        /// 22.
        fn status(&self, pid: u32, status: &str) -> Result<Option<Process>, String> {
            let unread = || format!("process {pid}'s status reads `{}`", status.trim_end());
            let fields: Vec<&str> = status
                .rsplit_once(')')
                .ok_or_else(unread)?
                .1
                .split_whitespace()
                .collect();
            let field = |number: usize| fields.get(number - 3).copied().ok_or_else(unread);
            let count = |number: usize| -> Result<u64, String> {
                field(number)?.parse().map_err(|_| unread())
            };
            // An ended process not yet collected: what it used is its parent's once collected.
            if matches!(field(3)?, "Z" | "X" | "x") {
                return Ok(None);
            }
            let parent = u32::try_from(count(4)?).map_err(|_| unread())?;
            #[expect(
                clippy::cast_precision_loss,
                reason = "a tick count is far inside f64's exact range"
            )]
            let seconds = |ticks: u64| ticks as f64 / self.ticks_per_second;
            let own = seconds(count(14)? + count(15)?);
            let collected = seconds(count(16)? + count(17)?);
            Ok(Some(Process {
                pid,
                parent,
                start: field(22)?.to_owned(),
                own,
                with_collected: own + collected,
            }))
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::process::Command;

    use super::Process;

    /// The load counters' states, by position: user, system, idle and nice.
    const USER: usize = 0;
    const SYSTEM: usize = 1;
    const NICE: usize = 3;

    pub struct Counts {
        host: libc::mach_port_t,
        seconds_per_tick: f64,
        /// Each processor's counters at the last count. They are 32 bits wide and wrap, so the
        /// busy count is kept here, from their differences.
        last: Vec<[u32; 4]>,
        busy_ticks: u64,
    }

    impl Counts {
        pub fn open() -> Result<Self, String> {
            let host = load::host();
            let last = load::processor_ticks(host)?;
            Ok(Self {
                host,
                seconds_per_tick: 1.0 / clock_rate()?,
                last,
                busy_ticks: 0,
            })
        }

        /// Each processor's user, system and nice time is counted apart and rounded down, so the
        /// count of their sum can fall short by a tick for each.
        pub fn resolution(&self) -> f64 {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a count of processors is a small integer"
            )]
            let counters = (3 * self.last.len()) as f64;
            counters * self.seconds_per_tick
        }

        pub fn busy(&mut self) -> Result<f64, String> {
            let now = load::processor_ticks(self.host)?;
            if now.len() != self.last.len() {
                return Err(format!(
                    "the machine went from {} processors to {} while it was read",
                    self.last.len(),
                    now.len()
                ));
            }
            for (now, last) in now.iter().zip(&self.last) {
                for state in [USER, SYSTEM, NICE] {
                    self.busy_ticks += u64::from(now[state].wrapping_sub(last[state]));
                }
            }
            self.last = now;
            #[expect(
                clippy::cast_precision_loss,
                reason = "a tick count is far inside f64's exact range"
            )]
            let seconds = self.busy_ticks as f64 * self.seconds_per_tick;
            Ok(seconds)
        }

        /// Every process `ps` lists, with its start, which `ps` gives to the second and the system
        /// never reuses an identifier within, and its own processor time. A process that has ended
        /// or is ending is left out, because `ps` reads its time as nothing.
        pub fn processes(&self) -> Result<Vec<Process>, String> {
            let output = Command::new("ps")
                .env("LC_ALL", "C")
                .args(["-A", "-o", "pid=,ppid=,stat=,lstart=,time="])
                .output()
                .map_err(|error| format!("read the process table: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "reading the process table ended with {}",
                    output.status
                ));
            }
            let mut processes = Vec::new();
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let unread = || format!("the process table has a line that reads `{line}`");
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [pid, parent, state, start @ .., time] = fields.as_slice() else {
                    return Err(unread());
                };
                if start.len() != 5 {
                    return Err(unread());
                }
                if state.contains('Z') || state.contains('E') {
                    continue;
                }
                let own = crate::process::processor_time(time).ok_or_else(unread)?;
                processes.push(Process {
                    pid: pid.parse().map_err(|_| unread())?,
                    parent: parent.parse().map_err(|_| unread())?,
                    start: start.join(" "),
                    own,
                    with_collected: own,
                });
            }
            Ok(processes)
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

    mod load {
        #![expect(
            unsafe_code,
            reason = "macOS gives each processor's busy and idle time only through \
                      host_processor_info, which has no safe interface"
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
    use super::Process;

    pub struct Counts;

    const NOT_READ: &str = "this platform's processor time is not read here";

    impl Counts {
        pub fn open() -> Result<Self, String> {
            Err(NOT_READ.to_owned())
        }

        pub fn resolution(&self) -> f64 {
            0.0
        }

        pub fn busy(&mut self) -> Result<f64, String> {
            Err(NOT_READ.to_owned())
        }

        pub fn processes(&self) -> Result<Vec<Process>, String> {
            Err(NOT_READ.to_owned())
        }
    }
}
