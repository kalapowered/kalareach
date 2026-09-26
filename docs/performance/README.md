# Performance

Section 27 of the specification states ten performance targets, KR-PERF-001 to KR-PERF-010, and
states them for a reference host. This document defines that host and the two configurations the
targets are measured in, lists what takes each figure, and says how a run records a figure and which
host a platform's release figures come from.

## The reference host

A reference host has:

* at least four processors, counted as the processors the operating system makes available to the
  measuring process;
* at least 8 GiB of memory, as the operating system reports it (`MemTotal` on Linux, `hw.memsize` on
  macOS);
* its operating system and architecture recorded beside every figure taken on it;
* nothing else running while a figure is taken.

`scripts/bench-all.sh` checks the last condition from ten seconds before each measurement until it
ends. Its reader of other work, `kr-perf-watch` in `tests/perf`, reads the whole machine every two
seconds: all processors' idle time, and every process with the processor time the operating system
charges to it. The run is the script and every process descended from it, which includes the
workers a measurement's daemon starts, and a process that was once the run's stays the run's after
it is reparented. Over any stretch between two readings, the processor time spent on anything but
the run is at most the processors' time less their idle time, less the least the run's processes
can have used. A five-second window can start anywhere between two readings, so the reader bounds
each window by the stretch of readings that covers it, and work that falls across a reading is
counted whole. One processor's worth or more in any five seconds makes the host busy, and so do a
reading that could not be taken, a count that went backwards, and a process table that does not
show the whole machine.

On Linux, where the kernel keeps each thread's own time (`/proc/<pid>/task/<tid>/schedstat`, in
nanoseconds), the reader also takes the run's processes' time thread by thread, beside each
process's clock ticks, which are the same counts summed and rounded down. It reads each thread's
time twice,
at least two clock ticks apart, and then its state and start. A thread counts over a stretch when it
was read at both ends of it, known by its identifier and start: one that ends inside the stretch
loses its time since the first reading, and one first read inside it counts nothing, so the sum can
fall short of what the run used but never exceed it. Each process counts the larger of that sum and
the least its whole time gives, so threads that start and end between readings, as a thread pool
made for each piece of work does, never leave the least below the process reading's. A thread of a
process that execs takes the process's first thread's identifier and start with its own earlier
time, so the first thread counts only where its process had one thread at the stretch's first
reading, or where another thread that started before that reading lives through the stretch, which
an exec would have ended. A kernel without the file, or one that prints zeros in it, is read process
by process, with that reading's allowance, and the record says which reading a figure used.

Over each measurement the script also reads the share of the machine's time a hypervisor took,
where the platform keeps that count (the `steal` counter in Linux's `/proc/stat`), and a measurement
that lost more than 1% of its time falls short. It records the load average at both edges as well,
and decides nothing by it, because a one-minute average still carries the measurement before. The
four processors, the 8 GiB and the 1% are the figures that
`crates/kr-transport/tests/support/conditions.rs` holds, and every measurement's record reads its
host against them, so a record can name a shortfall of its own.

What the reader bounds is all the processor time the operating system does not charge to the run's
processes, so the kernel's own work counts as other work, even what the kernel does on the run's
behalf, which can only make a host read busier. A zero stolen share means the hypervisor reported no
loss, and a platform that keeps no such count leaves the condition unverified. And memory as the
operating system reports it is a little less than the memory installed, so a machine with exactly
8 GiB installed reads as short of the reference host.

### What the reading assumes

The reader cannot see inside a kernel's accounting, so the bound rests on four things each kernel
does by design. They hold on the reference hosts, and the reader checks what it can. A figure is a
reference figure on these grounds only from a run on a host set aside for it, with nothing else
scheduled there.
Each assumption comes with an allowance, which the reader adds to the bound, and every conditions
section gives how much of its bound the allowances make up, rounded up. Section 27's figures are
far coarser than any of them: the gate itself allows one processor's worth, five processor-seconds,
in any five seconds.

| Assumption | Its bound | Why it holds on a reference host | What the reader checks | Allowance in each stretch between two readings |
| --- | --- | --- | --- | --- |
| Idle time is counted as it passes | Linux counts it exactly on a kernel that stops the clock tick on an idle processor; macOS brings an idle processor's count up to date when it is read | Distribution kernels for x86-64 and ARM64 are built for it, and those machines have the one-shot timers it needs | On Linux, `CONFIG_NO_HZ_COMMON` in the kernel's configuration and no `nohz=` that turns it off; a kernel that fails either is not read | Rounding to a hundredth of a second: 0.02 s on Linux (idle and waiting counts), a hundredth of a second and one 10 ms quantum per processor on macOS (0.24 s on twelve processors) |
| A running thread's charged time trails by little | At most one clock tick on Linux (1 ms at 1000 Hz), one 10 ms scheduling quantum on macOS | The clock tick, or the quantum's timer, brings the running thread's time up to date, and a quiet host holds interrupts off for microseconds | On Linux, the clock rate from the kernel's configuration, no processor that stops the tick while a thread runs (`nohz_full`), and whether the kernel keeps each thread's time: the reader's own thread's time in `/proc/thread-self/schedstat` is more than nothing | On Linux with each thread's time: for each of the run's threads, one tick where its state is running, and otherwise the lesser of one tick and how far its time moved between its two reads, which catches a thread still running as it goes to sleep; a process whose whole time counts more carries the whole reading's allowance instead. On Linux without it: for each of the run's processes, its threads times one tick and a further 0.02 s for rounding. On macOS: for each process, its running threads times one quantum |
| An idle count read without a lock is right at least once in three | A count taken just as a processor goes idle or wakes can drop that processor's current idle stretch (Linux) or count it twice (macOS) | It needs a wake-up to land within the few hundred nanoseconds between two reads of one processor's fields, three times over, on a quiet host | Nothing checks it: every count is taken three times, and the largest is kept where it starts a stretch and the smallest where it ends one | None |
| A process identifier and start name one process, and on Linux a thread identifier and start one thread | No identifier is given to a new process or thread within a hundredth of a second on Linux, which gives the start to that; macOS gives it to the microsecond | Both hand identifiers out in turn, Linux up to its `pid_max`, macOS up to 99,999, so one returns only after every other has been used, far longer than a hundredth of a second | That a process's identifier still names the same start after its threads are read, or its threads are not used; that a thread is not ending (`Z` or `X`) when its time is read, since an exec hands the ending first thread another thread's identifier | None |

## The two configurations

Section 27 measures an idle host and a host under stress.

### Idle: 20 live shells and 32 attached views

Twenty sessions, each a worker with its root shell in a pseudo-terminal, and thirty-two views
attached across them, each subscribed to output. No application runs. KR-PERF-003 is measured in
this configuration. KR-PERF-001 puts the same load on the host while it measures: nineteen live
shells and thirty-two views beside the session the keystrokes go to.

### Stress: 50 sessions with sustained output

Fifty sessions, each a shell whose foreground command writes terminal output at a steady rate the
way a build or an agent does, with a view on each that reads everything it is sent. Forty-nine write
32 KiB a second. One writes 512 KiB a second and also has an observer attached that reads nothing,
so the worker's send queue for that observer fills during the run. Beside them run a session that
echoes keystrokes, two probe sessions that differ only in whether their shell is running a command,
and the plugin host serving the fixture package `well-behaved`. The figures are taken over two
minutes, and memory and every view's progress are read every five seconds. The stress run is
`tests/perf/tests/stress.rs`.

## How each figure is taken

Every measurement runs in a release build, one at a time.

| Identifier | Target | Measured by | What is measured |
| --- | --- | --- | --- |
| KR-PERF-001 | p95 below 5 ms, p99 below 15 ms | `crates/kr-worker/benches/input_latency.rs` (`added_input_forwarding_latency`), and again in the stress run | 1,000 single-byte writes on the session's own local socket, each timed to the byte arriving back after the application echoed it. That includes the application's read and echo and the host's whole output path, which section 27 leaves out, so the figure is an upper bound on the added latency |
| KR-PERF-002 | recogniser deadline at most 25 ms | `input_latency.rs` (`paste_prefix_recogniser_deadline`) | Every proper prefix of both paste delimiters and a lone Escape, each alone and timed to the byte reaching the application, and a delimiter split across two writes, recognised once. The deadline the host is built with is checked against section 27's directly |
| KR-PERF-003 | below 500 MiB and 1% of one core | `crates/kr-worker/tests/performance.rs` (`idle_resources_for_twenty_sessions_and_thirty_two_views`) | The idle configuration's daemon, workers and root shells: processor time over five minutes and resident memory at the end. The stress run reports the same readings under stress, which section 27 sets no bound on, and the whole product's memory with the plugin host serving |
| KR-PERF-004 | a usable 120x40 screen within 500 ms | `performance.rs` (`attach_to_a_usable_screen`) | Five attachments of each presentation, from the connection to a screen a person could look at |
| KR-PERF-005 | under 25 ms p95 above the path's round trip | `crates/kr-transport/tests/perf.rs` | Remote input over a real connection while a bulk transfer runs, less the path's own round trip. The target is asserted where the host meets the reference host's conditions, and elsewhere recorded with the shortfall named |
| KR-PERF-006 | usable state within two seconds | `crates/kr-transport/tests/perf.rs` and `crates/kr-client/tests/session.rs` | The transport's share is timed: reconnecting, the handshake, a stream and a 120x40 snapshot. The client's share is asserted inside the budget: the subscription through the client library and a painted 120x40 screen, plainly and after one refused read |
| KR-PERF-007 | drain 5 MiB/s without unbounded queues; slow observers resynchronise | `crates/kr-term/tests/perf.rs`, and the stress run | The engine's sustained rate on a plain and a scrolling stream, with every bound checked. Two figures against the history behind the screen: what one read costs behind a history at its bound against one behind an emptied history (at most four times as much), and how many rows a session reads over the same reads in each (at most twice as many). In the stress run, the observer that stops reading is told to resynchronise and receives output again once it resubscribes, and no other view goes an interval without output |
| KR-PERF-008 | one batch per animation frame; input stays responsive | `apps/companion/test/performance.test.tsx` | Events folded into frames, a keystroke's cost against the size of the history while output streams, what a keystroke touches in the document, and how many nodes are drawn for a long history |
| KR-PERF-009 | 4 GiB, four threads and 30 seconds per description | `scripts/bench-descriptions.sh` | The selected profile against real weights at 1, 5, 20 and 50 sessions, with the resource pause beside it |
| KR-PERF-010 | first audio and delegation latency recorded | a paired phone, and the voice service's own record of each call | Taken on a phone with a connected media path to the voice provider, not on a host. The phone apps take first audio where they add the remote audio track (iOS's `didAdd` receiver, Android's `onAddTrack`), which shows that a track exists, not that its audio has played. The voice service records, for each call, the time from creating it to releasing its answer and to its sideband being ready, which the web repository's voice tests check. Neither is a measurement of delegation latency |

The stress run reads processor time per process and adds it up by kind: the workers, the shells and
their programs, and the measurement's own process, which is the daemon and also every reading view's
client end. The adoption watch's cost while a command holds the terminal is the difference between
the two probe sessions' workers. The workers there hold no connectors, so the watch only reads the
terminal's foreground group, four times a second. The record also times one enumeration of a
foreground group's processes, the reading a worker that holds a connector makes on each of those
looks, and gives what fifty sessions would spend on it on that host.

## Running every measurement

```text
scripts/bench-all.sh [--reference-host] [--only <step>[,<step>...]]
```

`scripts/bench-all.sh` builds the release profile once and then runs each step this host can take:
`performance` (`scripts/performance.sh`, KR-PERF-001 to KR-PERF-004), `terminal`, `transport`,
`reconnect`, `companion`, `stress` and `descriptions`. The descriptions step runs where the host can
hold KR-PERF-009's budget: four processors, mains power, and memory for the 4 GiB ceiling above the
reserve section 22 keeps free. Elsewhere the run says why it skipped the step. KR-PERF-010 is named
as not run, with its reason. The script runs on macOS and Linux.

It exits with 0 when every measurement it ran met its target and recorded its figures. It exits with
1 when a target was missed, a measurement failed or recorded no figure, the run could not keep its
evidence, or, with `--reference-host`, the host did not meet a condition of the reference host. A
missed target is read from each record's own verdict as well as from the measurement's exit status,
because a measurement that does not assert its target on a host short of the reference host still
records whether the figure met it. With `--reference-host` it waits up to ten minutes before each
step for other work to stop, still takes and records every figure, and names each condition the
host did not meet.

## The records

Every measurement writes each figure under `KR_TEST_ARTIFACTS_DIR` as a Markdown section headed by
the identifier it measures, and does so before it asserts anything, so a run whose target failed
keeps the number. A run that asked for its evidence to be kept and could not write it fails, naming
where and why. The conformance report attaches each section to its identifier (see
[../conformance/README.md](../conformance/README.md)).

| File | Written by | Sections |
| --- | --- | --- |
| `kr-worker-input.md` | `input_latency.rs` | KR-PERF-001, KR-PERF-002 |
| `kr-worker-performance.md` | `performance.rs` | KR-PERF-003, KR-PERF-004 |
| `kr-transport-scheduling.md` | `crates/kr-transport/tests/perf.rs` | KR-PERF-005, KR-PERF-006 |
| `kr-term-output-handling.md` | `crates/kr-term/tests/perf.rs` | KR-PERF-007 four times |
| `kr-perf-stress.md` | `tests/perf/tests/stress.rs` | KR-PERF-001, KR-PERF-003 twice, KR-PERF-007 |
| `bench-all.md` | `scripts/bench-all.sh` | KR-PERF-006's client share, KR-PERF-008, KR-PERF-009, KR-PERF-010, and one conditions section for each identifier the run measured |

A measurement's own section starts with its host: the build, the operating system and architecture,
the processor, the processors and the memory against the reference host's, the load average entering
and leaving, the stolen share, and which of those fall short. For each identifier the run measured,
`bench-all.md` adds a conditions section. It gives each step that measured the identifier, with its
exit status, the load average at both edges, the other work over the ten seconds before the step and
through it (the bound on its busiest five seconds, how much of that the allowances make up, its
average, and whether the run's time was read from each thread's time or each process's) and the
stolen share over it, then the outcome, and whether the figures are reference figures. Figures are
reference figures only when the run was asked for them, the host met every condition it read, every
reading could be taken, no record of the step names a shortfall, and the run kept all of its
evidence. The conditions sections are the last thing a run writes, and are published together in
one step, so a run that could not keep its evidence leaves none that calls its figures reference
figures.

## Where release figures come from

A platform's release figures come from a reference host of that platform: an Apple silicon Mac or an
Intel Mac for macOS, an x86-64 or an ARM64 Linux machine for Linux, and a Windows 11 machine on
x86-64 or ARM64 for Windows, each meeting the definition above with nothing else running. On macOS
and Linux the figures are those of a `scripts/bench-all.sh --reference-host` run that met every
condition. On Windows they come from the same suites, run on the Windows 11 host.

The four-processor Linux runners that continuous integration uses meet the definition, and their
figures count as Linux x86-64 figures. The macOS runner it uses has three processors, below the
reference host's four, so its figures are recorded and none of them is a release figure.
