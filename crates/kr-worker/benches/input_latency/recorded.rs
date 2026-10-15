//! Rounds of paste-prefix holds that are recorded and not asserted.
//!
//! The asserted round says that a hold took longer than its allowance; it cannot say where the
//! time went. These rounds take the same ten holds again, in the state the asserted round ran in,
//! and keep for each one what a figure alone cannot: every acquisition of the session on its path,
//! with the instants it began to wait, held the session and let go of it; every observation of the
//! session's processes; when the recogniser's timer woke against its deadline; the processor time
//! the process used; and what a thread that does nothing but sleep saw meanwhile, which shows a
//! stall of the whole machine where a wait for the session does not.
//!
//! Nothing here asserts. A hold that is not held, a byte that does not arrive, or a write the host
//! refuses is written down as what happened to that hold, because these rounds exist to explain a
//! figure and must not be able to fail the measurement.
//!
//! The recorder is armed here and nowhere else, so the other measurements pay for an unarmed site
//! and nothing more.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};
use kr_worker::runtime::{
    SUPERVISION_COPIED_OUT as COPIED_OUT, SUPERVISION_PUT_BACK as PUT_BACK, SessionRuntime,
};
use kr_worker::trace::{Event, LockTrace, Recording, Site};

use super::{Hosted, POLL, RECOGNISER_DEADLINE, contains, retained_in, write};

/// The round the asserted holds are, so these start after it.
const FIRST_RECORDED_ROUND: usize = 2;

/// How many rounds of the ten prefixes are taken in all, the asserted one included.
const ROUNDS: usize = 5;

/// How often the witness wakes.
const WITNESS_INTERVAL: Duration = Duration::from_millis(5);

/// A wake of the witness this late is a stall of the machine or the process, not a delay in the
/// session.
const STALL: Duration = Duration::from_millis(10);

/// A hold longer than this is late enough to be read for what delayed it.
const LATE: Duration = Duration::from_millis(31);

/// The bound the asserted rounds hold each figure to, which these rounds are read against.
const OVER: Duration = Duration::from_millis(40);

/// The processor time this process has used, user and system together, where the platform says.
#[cfg(unix)]
mod process_time {
    use std::time::Duration;

    pub fn used() -> Option<Duration> {
        let used = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        Some(Duration::new(
            u64::try_from(used.tv_sec).ok()?,
            u32::try_from(used.tv_nsec).ok()?,
        ))
    }
}

/// The same, where the platform has no such clock: nothing is said.
#[cfg(not(unix))]
mod process_time {
    use std::time::Duration;

    pub fn used() -> Option<Duration> {
        None
    }
}

/// A thread that does nothing but sleep, and writes down when it was due to wake and when it did.
struct Witness {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Vec<Wake>>,
}

/// One wake of the witness, in nanoseconds since the recorder's epoch.
#[derive(Clone, Copy)]
struct Wake {
    due: u64,
    ran: u64,
}

impl Witness {
    fn start(trace: &Arc<TraceHandle>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            let trace = Arc::clone(trace);
            std::thread::spawn(move || {
                let mut wakes = Vec::new();
                let mut due = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    due += WITNESS_INTERVAL;
                    std::thread::sleep(due.saturating_duration_since(Instant::now()));
                    let ran = Instant::now();
                    wakes.push(Wake {
                        due: trace.offset(due),
                        ran: trace.offset(ran),
                    });
                    // A wake that was late is measured from where it ran, so one stall is one late
                    // wake and not a run of them that catch up.
                    due = due.max(ran);
                }
                wakes
            })
        };
        Self { stop, thread }
    }

    fn finish(self) -> Vec<Wake> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap_or_default()
    }
}

/// What the witness and the holds read the recorder's clock through, which does not borrow the
/// session's runtime so that the witness can own it.
pub struct TraceHandle {
    epoch: Instant,
}

impl TraceHandle {
    fn new(trace: &LockTrace) -> Self {
        Self {
            epoch: trace.epoch(),
        }
    }

    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    fn now(&self) -> u64 {
        self.offset(Instant::now())
    }
}

/// One poll of the retained output: when it began to wait for the session, took it and let go.
#[derive(Clone, Copy)]
struct Poll {
    begun: u64,
    held: u64,
    released: u64,
}

/// One recorded hold.
struct RecordedHold {
    round: usize,
    what: String,
    /// When the write of the prefix was sent, in nanoseconds since the recorder's epoch.
    written: u64,
    /// When the byte was seen.
    seen: u64,
    /// The hold, or what stopped it being measured.
    outcome: Result<Duration, String>,
    /// The processor time used between the write and the byte being seen.
    processor: Option<Duration>,
    recording: Recording,
    polls: Vec<Poll>,
}

/// What the recorded rounds came to.
pub struct Recorded {
    holds: Vec<RecordedHold>,
    wakes: Vec<Wake>,
    /// Why the rounds did not run, where they did not.
    skipped: Option<String>,
}

/// The milliseconds `at` falls after `base`, signed, to the microsecond.
fn after(at: u64, base: u64) -> String {
    let (sign, difference) = if at >= base {
        ('+', at - base)
    } else {
        ('-', base - at)
    };
    format!(
        "{sign}{}.{:03}",
        difference / 1_000_000,
        difference % 1_000_000 / 1_000
    )
}

/// A span in milliseconds, to the microsecond.
fn span(nanoseconds: u64) -> String {
    format!(
        "{}.{:03}",
        nanoseconds / 1_000_000,
        nanoseconds % 1_000_000 / 1_000
    )
}

/// Like the asserted measurement's wait for a byte, and it records each poll's acquisition of the
/// session.
async fn arrival(
    runtime: &SessionRuntime,
    handle: &TraceHandle,
    marker: &[u8],
    from: Instant,
    within: Duration,
) -> (Option<Duration>, Vec<Poll>) {
    let deadline = from + within;
    let mut polls = Vec::new();
    loop {
        let begun = handle.now();
        let (held, seen) = {
            let session = runtime.session();
            (handle.now(), retained_in(&session))
        };
        polls.push(Poll {
            begun,
            held,
            released: handle.now(),
        });
        if contains(&seen, marker) {
            return (Some(from.elapsed()), polls);
        }
        if Instant::now() >= deadline {
            return (None, polls);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Takes the rounds after the asserted one, if the paste the split delimiter opened can be closed.
///
/// The paste is closed first so that the rounds run in the state the asserted round ran in. The
/// write that closes it is a whole delimiter and goes through at once.
pub async fn record_rounds(
    hosted: &Hosted,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: &mut u64,
) -> Recorded {
    let trace = hosted.runtime.trace();
    let handle = Arc::new(TraceHandle::new(trace));
    let mut holds = Vec::new();
    if let Err(failure) = write(hosted, client, attachment_id, epoch, sequence, b"\x1b[201~").await
    {
        return Recorded {
            holds,
            wakes: Vec::new(),
            skipped: Some(format!(
                "the paste the split delimiter opened was not closed, so no round was taken: \
                 {failure}"
            )),
        };
    }
    trace.arm();
    let witness = Witness::start(&handle);
    for round in FIRST_RECORDED_ROUND..=ROUNDS {
        for (name, delimiter) in [("start", &b"\x1b[200~"[..]), ("end", &b"\x1b[201~"[..])] {
            for length in 1..delimiter.len() {
                holds.push(
                    hold(
                        hosted,
                        client,
                        attachment_id,
                        epoch,
                        sequence,
                        &handle,
                        round,
                        (name, length),
                        &delimiter[..length],
                    )
                    .await,
                );
            }
        }
    }
    let wakes = witness.finish();
    trace.disarm();
    Recorded {
        holds,
        wakes,
        skipped: None,
    }
}

/// Takes one hold the way the asserted round does, keeping what happened on its path.
#[expect(
    clippy::too_many_arguments,
    reason = "it is the asserted round's loop body, which has the same inputs"
)]
async fn hold(
    hosted: &Hosted,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: &mut u64,
    handle: &TraceHandle,
    round: usize,
    (name, length): (&str, usize),
    prefix: &[u8],
) -> RecordedHold {
    let trace = hosted.runtime.trace();
    let what = format!("{name} {length}");
    let mut recorded = RecordedHold {
        round,
        what,
        written: 0,
        seen: 0,
        outcome: Err("not taken".to_owned()),
        processor: None,
        recording: Recording::default(),
        polls: Vec::new(),
    };
    // Its own marker, because the wait searches everything the session has retained and would find
    // an earlier round's echo of the same prefix at once.
    let marker = format!("<{name}{length}.{round}>");
    if let Err(failure) = write(
        hosted,
        client,
        attachment_id,
        epoch,
        sequence,
        marker.as_bytes(),
    )
    .await
    {
        recorded.outcome = Err(format!("the marker was not written: {failure}"));
        return recorded;
    }
    let mut expected = marker.into_bytes();
    expected.extend_from_slice(prefix);
    let processor_before = process_time::used();
    recorded.written = handle.now();
    let started = Instant::now();
    let accepted = write(hosted, client, attachment_id, epoch, sequence, prefix).await;
    recorded.outcome = match accepted {
        Err(failure) => Err(format!("the prefix was not written: {failure}")),
        Ok(accepted) if accepted.held_prefix_bytes.get() != length as u64 => Err(format!(
            "the prefix was not held: {} held, {} forwarded",
            accepted.held_prefix_bytes.get(),
            accepted.forwarded_bytes.get()
        )),
        Ok(_) => {
            let (held, polls) = arrival(
                &hosted.runtime,
                handle,
                &expected,
                started,
                RECOGNISER_DEADLINE * 8,
            )
            .await;
            recorded.polls = polls;
            held.ok_or_else(|| "the prefix never reached the application".to_owned())
                .and_then(|held| {
                    if held < RECOGNISER_DEADLINE {
                        Err(format!(
                            "the prefix was forwarded after {} ms, before its deadline",
                            span(u64::try_from(held.as_nanos()).unwrap_or(u64::MAX))
                        ))
                    } else {
                        Ok(held)
                    }
                })
        }
    };
    recorded.seen = handle.now();
    recorded.processor = process_time::used()
        .zip(processor_before)
        .map(|(after, before)| after.saturating_sub(before));
    recorded.recording = trace.recording();
    recorded
}

impl RecordedHold {
    /// The hold when it was measured, in nanoseconds.
    fn nanoseconds(&self) -> Option<u64> {
        self.outcome
            .as_ref()
            .ok()
            .map(|held| u64::try_from(held.as_nanos()).unwrap_or(u64::MAX))
    }

    /// The record line of this hold: its figure, then every interval laid beside the write, in
    /// milliseconds before (`-`) or after (`+`) the instant the prefix was written.
    fn line(&self, wakes: &[Wake]) -> String {
        let base = self.written;
        let mut line = format!("  recorded hold     round {}, {}: ", self.round, self.what);
        match &self.outcome {
            Ok(held) => line.push_str(&format!("{} ms", span(held.as_nanos() as u64))),
            Err(failure) => line.push_str(&format!("NOT MEASURED, {failure}")),
        }
        line.push_str(&format!("; written at {} ms of the epoch", span(base)));
        match self.processor {
            Some(used) => {
                line.push_str(&format!("; processor {} ms", span(used.as_nanos() as u64)))
            }
            None => line.push_str("; processor unknown"),
        }
        let mut stall = 0_u64;
        let mut late = 0_usize;
        let from = base.saturating_sub(WITNESS_INTERVAL.as_nanos() as u64);
        for wake in wakes
            .iter()
            .filter(|wake| wake.ran >= from && wake.due <= self.seen)
        {
            let by = wake.ran.saturating_sub(wake.due);
            stall = stall.max(by);
            if by >= STALL.as_nanos() as u64 {
                late += 1;
            }
        }
        line.push_str(&format!(
            "; witness worst {} ms late, {late} wakes of {} ms or more late",
            span(stall),
            STALL.as_millis()
        ));
        if self.recording.overflowed {
            line.push_str("; OVERFLOW, events were lost");
        }
        line.push_str(&format!("; polls {}", self.polls.len()));
        if !self.polls.is_empty() {
            let wait = self
                .polls
                .iter()
                .map(|poll| poll.held.saturating_sub(poll.begun))
                .max()
                .unwrap_or(0);
            let kept = self
                .polls
                .iter()
                .map(|poll| poll.released.saturating_sub(poll.held))
                .max()
                .unwrap_or(0);
            let gap = self
                .polls
                .windows(2)
                .map(|pair| pair[1].begun.saturating_sub(pair[0].released))
                .max()
                .unwrap_or(0);
            line.push_str(&format!(
                " (longest wait for the session {} ms, longest hold of it {} ms, longest gap {} ms)",
                span(wait),
                span(kept),
                span(gap)
            ));
        }
        for event in &self.recording.events {
            line.push_str("; ");
            line.push_str(&describe(event, base));
        }
        // The intervals themselves, for a hold that is to be read for what delayed it: every poll
        // as wait/held/let go, and every wake of the witness in the hold's window as due/ran.
        let longer_than = u64::try_from(LATE.as_nanos()).unwrap_or(u64::MAX);
        if self.nanoseconds().is_none_or(|held| held > longer_than) {
            line.push_str("; poll-intervals[");
            line.push_str(
                &self
                    .polls
                    .iter()
                    .map(|poll| {
                        format!(
                            "{}/{}/{}",
                            after(poll.begun, base),
                            after(poll.held, base),
                            after(poll.released, base)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            line.push_str("]; witness-wakes[");
            line.push_str(
                &wakes
                    .iter()
                    .filter(|wake| wake.ran >= from && wake.due <= self.seen)
                    .map(|wake| format!("{}/{}", after(wake.due, base), after(wake.ran, base)))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            line.push(']');
        }
        line
    }
}

/// One event as the record gives it.
fn describe(event: &Event, base: u64) -> String {
    match event.site {
        Site::TimerWake => format!(
            "timer-woke[deadline {} woke {}]",
            after(event.begun, base),
            after(event.held, base)
        ),
        Site::Observation => format!(
            "observation[read {} to {}]",
            after(event.begun, base),
            after(event.held, base)
        ),
        site => {
            let name = match site {
                Site::InputAcceptance => "input",
                Site::TimerLook => "timer-look",
                Site::TimerForward => "timer-forward",
                Site::Ingest => "ingest",
                Site::SupervisionWake => "supervision",
                Site::TimerWake | Site::Observation => unreachable!("described above"),
            };
            let mut text = format!(
                "{name}[wait {} held {} let go {}",
                after(event.begun, base),
                after(event.held, base),
                after(event.released, base)
            );
            match site {
                Site::InputAcceptance if event.value != 0 => {
                    text.push_str(&format!(" deadline {}", after(event.value, base)));
                }
                Site::SupervisionWake if event.value == COPIED_OUT => text.push_str(" copied-out"),
                Site::SupervisionWake if event.value == PUT_BACK => text.push_str(" put-back"),
                _ => {}
            }
            text.push(']');
            text
        }
    }
}

impl Recorded {
    /// The lines the record carries for these rounds.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(reason) = &self.skipped {
            lines.push(format!("  recorded rounds   not taken: {reason}"));
            return lines;
        }
        let measured: Vec<u64> = self
            .holds
            .iter()
            .filter_map(RecordedHold::nanoseconds)
            .collect();
        let over = |bound: Duration| {
            let bound = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
            measured.iter().filter(|held| **held > bound).count()
        };
        let stalled = self
            .wakes
            .iter()
            .filter(|wake| wake.ran.saturating_sub(wake.due) >= STALL.as_nanos() as u64)
            .count();
        lines.push(format!(
            "  recorded rounds   rounds {FIRST_RECORDED_ROUND} to {ROUNDS}, recorded and not \
             asserted: {} holds taken, {} measured, {} over {} ms and {} over {} ms; the witness \
             slept {} ms at a time and woke {} times, {stalled} of them {} ms or more late; every \
             instant below is in milliseconds from the prefix's write",
            self.holds.len(),
            measured.len(),
            over(LATE),
            LATE.as_millis(),
            over(OVER),
            OVER.as_millis(),
            WITNESS_INTERVAL.as_millis(),
            self.wakes.len(),
            STALL.as_millis()
        ));
        for hold in &self.holds {
            lines.push(hold.line(&self.wakes));
        }
        lines
    }
}
