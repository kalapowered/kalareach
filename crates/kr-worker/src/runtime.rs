//! The tasks that drive one session.
//!
//! [`crate::session::Session`] holds the state and changes it one call at a time. This module is
//! what calls it: a blocking reader on the pseudo-terminal, a blocking writer for input, a timer
//! for the paste recogniser, and the closure sequence with its grace and drain periods.
//!
//! The reader is the part with a rule attached. It must never stop because a client is slow, and
//! it must never discard what it has read; both would make the worker's idea of the screen wrong.
//! So it reads, hands the bytes to the session, and goes back to reading. Everything that could
//! wait happens on the delivery side.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use kr_protocol::session::{ClosureReason, ClosureRecord, SessionState};
use tokio::sync::{Notify, mpsc};

use crate::error::{Result, WorkerError};
use crate::session::{
    CloseAcceptance, DRAIN_PERIOD, GRACE_PERIOD, InputBatch, PasteTransition, Session,
};

/// How many read batches may wait for ingestion before the read loop slows down.
pub const READ_QUEUE_DEPTH: usize = 64;

/// The most input the writer offers the pseudo-terminal in one write, before any delimiter it has
/// to finish.
///
/// A whole batch in one call can wait for as long as the application takes to read it, and the
/// fence cannot be looked at while it does. This bounds how much of an ended lease's input can
/// still be in flight when a takeover succeeds, to this many bytes and at most one paste delimiter
/// beyond them. It is deliberately smaller than a terminal's own input queue, so a write the
/// terminal has room for is a write that finishes: what the writer spends its time in is the wait
/// below, where a takeover reaches it at once.
pub const WRITE_PIECE_BYTES: usize = 512;

/// How long the read loop waits for the application to write something before it asks again.
///
/// The wait ends by itself the moment output arrives, so this is not latency: it is only how often
/// a reader with nothing to read wakes to reconsider whether the terminal is still there. A session
/// sitting idle should cost nothing, and twenty of them waking fifty times a second each is not
/// nothing, so this is long.
pub const READ_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the writer keeps offering a correction the application must have before it gives up.
///
/// A terminal that has taken nothing at all for this long is one whose application has stopped
/// reading for longer than a paste can sensibly stay open, and a writer that waited for ever there
/// would never write anything again.
pub const INSIST_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the writer waits for the terminal to have room before it looks at the fence again.
///
/// The wait ends by itself when the application reads, so this is only the interval at which a
/// writer that is waiting reconsiders whether the bytes it is holding are still wanted.
pub const WRITE_WAIT: std::time::Duration = std::time::Duration::from_millis(20);

/// How often the root shell's status is checked, independently of the terminal.
///
/// Asking the kernel whether one child has exited costs almost nothing, so this is often.
pub const CHILD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// How often the set of processes a session owns is observed.
///
/// Enumerating a process group and reading each member's start identity is a kernel query per
/// process, and a host that did it ten times a second for every idle session would spend more of a
/// core on watching nothing happen than KR-PERF-003 allows the whole host.
///
/// The cost of the longer interval is stated rather than hidden: a process that both starts and
/// ends inside one interval is not recorded, so it is not in the closure record's list of what was
/// stopped. The record already never claims every application was discovered, and the coverage flag
/// says which boundary produced it; this widens the window in which that is true rather than
/// changing what is claimed.
pub const OWNERSHIP_OBSERVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How often a closing session is asked whether its processes have stopped.
pub const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// The current lease's share of the queued input, and the epoch it belongs to, in one word.
///
/// The two have to move together. A lease change hands the count to the takeover receipt and leaves
/// the next epoch with nothing; a writer that is still finishing the previous lease's bytes finds an
/// epoch that is no longer its own and subtracts nothing, so it cannot debit the lease that
/// replaced it. Reading and updating them as two values leaves exactly that gap.
#[derive(Debug)]
pub struct LeaseBytes {
    /// The epoch in the high thirty-two bits, the byte count in the low thirty-two.
    ///
    /// A session's queued input is bounded far below four gibibytes and a lease epoch counts lease
    /// changes, so neither half is near its limit; both saturate rather than wrap if one ever is.
    packed: std::sync::atomic::AtomicU64,
}

impl LeaseBytes {
    /// Builds an empty count at epoch zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns how many bytes the current lease has queued and unwritten.
    #[must_use]
    pub fn load(&self) -> usize {
        Self::bytes(self.packed.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Adds bytes queued under `epoch`, if that is still the epoch this count belongs to.
    pub fn add(&self, epoch: u64, bytes: usize) {
        let _ = self.packed.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |packed| {
                (Self::epoch(packed) == epoch)
                    .then(|| Self::pack(epoch, Self::bytes(packed).saturating_add(bytes)))
            },
        );
    }

    /// Gives back bytes that reached the application, if they were this lease's.
    pub fn release(&self, epoch: u64, bytes: usize) {
        let _ = self.packed.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |packed| {
                (Self::epoch(packed) == epoch)
                    .then(|| Self::pack(epoch, Self::bytes(packed).saturating_sub(bytes)))
            },
        );
    }

    /// Ends the current lease and returns what it had queued and unwritten.
    ///
    /// Everything that count names is discarded by the change, and the epoch it moves to starts
    /// from nothing, so the same bytes are never reported twice.
    #[must_use]
    pub fn take(&self, next_epoch: u64) -> usize {
        Self::bytes(self.packed.swap(
            Self::pack(next_epoch, 0),
            std::sync::atomic::Ordering::AcqRel,
        ))
    }

    /// The mask of the low half, which is where the byte count lives.
    const BYTES: u64 = 0xFFFF_FFFF;

    const fn pack(epoch: u64, bytes: usize) -> u64 {
        let epoch = if epoch > Self::BYTES {
            Self::BYTES
        } else {
            epoch
        };
        let bytes = bytes as u64;
        let bytes = if bytes > Self::BYTES {
            Self::BYTES
        } else {
            bytes
        };
        (epoch << 32) | bytes
    }

    const fn epoch(packed: u64) -> u64 {
        packed >> 32
    }

    const fn bytes(packed: u64) -> usize {
        (packed & Self::BYTES) as usize
    }
}

impl Default for LeaseBytes {
    fn default() -> Self {
        Self::new()
    }
}

/// Gives back what a counter was holding for bytes that have reached the application or gone.
fn release(counter: &std::sync::atomic::AtomicUsize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = counter.fetch_update(
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
        |held| Some(held.saturating_sub(bytes)),
    );
}

/// What became of a batch the writer offered the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// Every byte of it is with the application.
    Complete,
    /// The lease it belonged to ended, and the rest of it is not the application's to receive.
    Abandoned,
    /// The terminal takes nothing more.
    Gone,
}

/// Hands one batch to the terminal a piece at a time, and says how far it got.
///
/// `gate` is the boundary this shares with whatever changes the lease: inside it are the fence,
/// one write that refuses to wait, and the accounting for what that write sent. `stale` is the
/// fence, asked inside that boundary; `wrote` is told what the application now has that it did not
/// have before, which is what the write returned rather than what was offered, and it is told
/// inside the boundary too. Nothing waits while the boundary is held, so a lease change never waits
/// for a terminal, and no write of an ended lease's bytes can begin after that change.
///
/// A piece is at most [`WRITE_PIECE_BYTES`], so a takeover reaches a writer between pieces instead
/// of behind a whole batch, and `room` is waited on outside the boundary. A piece never *ends*
/// inside a paste delimiter: a terminal takes what it has room for, so a short write can stop in
/// the middle of one, and the writer finishes those few bytes before it looks at the fence again.
/// Half a delimiter is the one thing an abandoned batch cannot leave behind, because the next
/// actor's first bytes would complete it and their paste would begin inside the previous actor's.
fn write_batch(
    writer: &mut impl std::io::Write,
    bytes: &[u8],
    transition: &crate::session::PasteTransition,
    room: Option<&crate::pty::InputWaiter>,
    gate: &std::sync::Mutex<()>,
    stale: &mut impl FnMut() -> bool,
    wrote: &mut impl FnMut(usize),
) -> (usize, Delivery) {
    let mut delivered = 0_usize;
    while delivered < bytes.len() {
        // The waiting happens here, outside the boundary, so that a writer holding bytes an
        // application is not reading holds nothing else: a lease change takes the boundary while
        // this waits, and the next look at the fence sees it.
        if !wait_for_room(room, gate, stale) {
            return (
                delivered,
                if room.is_some_and(|waiter| {
                    waiter.wait(std::time::Duration::ZERO) == crate::pty::Room::Gone
                }) {
                    Delivery::Gone
                } else {
                    Delivery::Abandoned
                },
            );
        }
        let attempt = {
            let _boundary = gate.lock().expect("the input boundary is not poisoned");
            if stale() {
                return (delivered, Delivery::Abandoned);
            }
            let offered = delivered.saturating_add(WRITE_PIECE_BYTES).min(bytes.len());
            let offered = transition
                .unfinished(offered)
                .unwrap_or(offered)
                .min(bytes.len());
            let attempt = writer.write(&bytes[delivered..offered]);
            if let Ok(written) = attempt.as_ref() {
                delivered += written;
                wrote(*written);
            }
            attempt
        };
        match attempt {
            // A terminal that takes nothing and reports no error is one this writer cannot make
            // progress on.
            Ok(0) => return (delivered, Delivery::Gone),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => return (delivered, Delivery::Gone),
        }
        // The rest of a delimiter this write stopped inside of goes now, fence or no fence: its
        // first bytes are already with the application, and the next actor's input must not be
        // what completes them.
        while let Some(end) = transition.unfinished(delivered) {
            let end = end.min(bytes.len());
            let attempt = {
                let _boundary = gate.lock().expect("the input boundary is not poisoned");
                let attempt = writer.write(&bytes[delivered..end]);
                if let Ok(written) = attempt.as_ref() {
                    delivered += written;
                    wrote(*written);
                }
                attempt
            };
            match attempt {
                Ok(0) => return (delivered, Delivery::Gone),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    // A few bytes with nowhere to go yet. The terminal is waited on rather than
                    // spun on, and this is the one wait the fence does not end: these bytes are
                    // already half with the application.
                    if let Some(waiter) = room
                        && waiter.wait(WRITE_WAIT) == crate::pty::Room::Gone
                    {
                        return (delivered, Delivery::Gone);
                    }
                }
                Err(_) => return (delivered, Delivery::Gone),
            }
        }
    }
    (delivered, Delivery::Complete)
}

/// Writes a few bytes the application must have, waiting for the terminal as often as it takes.
///
/// This is not a lease's input and no fence applies to it: the paste terminator is the one thing
/// that can end a paste nothing else is going to end, so it goes through. It is bounded by what it
/// is: a handful of bytes that a terminal with any room at all takes whole.
fn insist(
    writer: &mut impl std::io::Write,
    bytes: &[u8],
    room: Option<&crate::pty::InputWaiter>,
    gate: &std::sync::Mutex<()>,
) -> bool {
    let mut sent = 0_usize;
    let deadline = std::time::Instant::now() + INSIST_LIMIT;
    while sent < bytes.len() {
        let attempt = {
            let _boundary = gate.lock().expect("the input boundary is not poisoned");
            writer.write(&bytes[sent..])
        };
        match attempt {
            Ok(0) => return false,
            Ok(written) => sent += written,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                if let Some(waiter) = room
                    && waiter.wait(WRITE_WAIT) == crate::pty::Room::Gone
                {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    let _ = std::io::Write::flush(writer);
    true
}

/// Waits until the terminal will take more, and says whether the batch is still wanted.
///
/// Returns false when the batch should stop: the lease it belongs to has ended, or the terminal
/// has. The fence is looked at inside the boundary, because that is the only place its answer
/// stays true for as long as it takes to act on it.
fn wait_for_room(
    room: Option<&crate::pty::InputWaiter>,
    gate: &std::sync::Mutex<()>,
    stale: &mut impl FnMut() -> bool,
) -> bool {
    let Some(waiter) = room else {
        return true;
    };
    loop {
        match waiter.wait(WRITE_WAIT) {
            crate::pty::Room::Ready => return true,
            crate::pty::Room::NotYet => {
                let _boundary = gate.lock().expect("the input boundary is not poisoned");
                if stale() {
                    return false;
                }
            }
            crate::pty::Room::Gone => return false,
        }
    }
}

/// A running session and the tasks around it.
#[derive(Debug)]
pub struct SessionRuntime {
    session: Arc<Mutex<Session>>,
    input: mpsc::UnboundedSender<InputBatch>,
    wake: Arc<Notify>,
    closed: Arc<Notify>,
    fence: Arc<std::sync::atomic::AtomicU64>,
}

impl SessionRuntime {
    /// Starts the reader, the writer and the timers around an already launched session.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal's reader or writer cannot be taken.
    pub fn start(session: Session) -> Result<Self> {
        let reader = session.output_reader()?;
        let mut writer = session.input_writer()?;
        // What the host owes the application is bounded by what has been *written*, not by what is
        // waiting in the session, because the session hands its queue over on every flush.
        let input_waiter = session.input_waiter();
        let output_waiter = session.output_waiter();
        let batches_reads = session.terminal_answers_rather_than_waits();
        // The boundary the writer and the lease share. What is inside it is the fence, one write
        // that refuses to wait, and the accounting for what that write sent; the waiting for the
        // terminal is outside it. A lease change takes the same boundary, so a write cannot begin
        // after the lease it belongs to has ended, and the count of what that lease left behind
        // cannot be taken while a write of its own is part way through.
        let gate = session.input_gate();
        let queued_input = session.queued_input_bytes();
        let queued_lease = session.queued_lease_bytes();
        let delivered_paste_open = session.delivered_paste_open();
        let lease_change_queued = session.lease_change_queued();
        // What the writer compares every batch against. A takeover, a release, a detach or a close
        // moves the session's lease epoch, and this is how that reaches bytes already handed over.
        // The session owns it, because it publishes the change in the same breath as making it,
        // which is what lets the bytes that lease left behind be counted once it can no longer be
        // writing them.
        let fence = session.input_fence_handle();
        let session = Arc::new(Mutex::new(session));
        let (input_sender, mut input_receiver) = mpsc::unbounded_channel::<InputBatch>();
        // Bounded on purpose. Section 9 says a slow *client* must never hold the read loop, and it
        // also says the worker honours the operating system's own backpressure when parsing itself
        // cannot keep up, and never drops parser input. A bounded handoff does both: clients are
        // decoupled by their own queues, and a worker that cannot ingest stops reading rather than
        // growing without limit or discarding bytes.
        let (output_sender, mut output_receiver) = mpsc::channel::<ReadEvent>(READ_QUEUE_DEPTH);
        let wake = Arc::new(Notify::new());
        let closed = Arc::new(Notify::new());

        // The read loop runs on its own thread. The terminal answers a read with nothing to read
        // rather than waiting inside it, so this waits on the descriptor and then reads what is
        // there.
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut filled = 0_usize;
            loop {
                match std::io::Read::read(&mut reader, &mut buffer[filled..]) {
                    Ok(0) => {
                        if filled > 0 {
                            let _ = output_sender
                                .blocking_send(ReadEvent::Bytes(buffer[..filled].to_vec()));
                        }
                        let _ = output_sender.blocking_send(ReadEvent::Ended);
                        break;
                    }
                    Ok(read) => {
                        // Taken together rather than one read at a time. What the terminal has is
                        // read until the buffer is full or it has no more, and that is one batch:
                        // an application printing steadily hands the engine and every subscriber a
                        // few large deliveries rather than thousands of small ones.
                        filled += read;
                        // Only where the terminal answers rather than waits. Where a second read
                        // would wait for output that has not happened, what was read goes on its
                        // way now rather than being held for company.
                        if batches_reads && filled < buffer.len() {
                            continue;
                        }
                        if output_sender
                            .blocking_send(ReadEvent::Bytes(buffer[..filled].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                        filled = 0;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // The terminal has no more for now, so what was read goes on its way and
                        // this waits. The wait happens here rather than inside the read, and a
                        // terminal that has gone is reported by the wait itself.
                        if filled > 0 {
                            if output_sender
                                .blocking_send(ReadEvent::Bytes(buffer[..filled].to_vec()))
                                .is_err()
                            {
                                break;
                            }
                            filled = 0;
                        }
                        match output_waiter.as_ref().map(|waiter| waiter.wait(READ_WAIT)) {
                            Some(crate::pty::Room::Gone) => {
                                let _ = output_sender.blocking_send(ReadEvent::Ended);
                                break;
                            }
                            // No descriptor to wait on: the read is asked again after a moment
                            // rather than in a loop that spins.
                            None => std::thread::sleep(READ_WAIT),
                            Some(_) => {}
                        }
                    }
                    Err(_) => {
                        // A closed terminal reads as an error on some platforms and as end of file
                        // on others. Either way the terminal is finished; whether the root shell
                        // ended is decided by the child monitor, not by this read. What was read
                        // before it happened is still the application's output.
                        if filled > 0 {
                            let _ = output_sender
                                .blocking_send(ReadEvent::Bytes(buffer[..filled].to_vec()));
                        }
                        let _ = output_sender.blocking_send(ReadEvent::Ended);
                        break;
                    }
                }
            }
        });

        let writer_fence = Arc::clone(&fence);
        let writer_gate = Arc::clone(&gate);
        let writer_queued = Arc::clone(&queued_input);
        let writer_lease = Arc::clone(&queued_lease);
        let writer_paste_open = Arc::clone(&delivered_paste_open);
        let writer_lease_change = Arc::clone(&lease_change_queued);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;

            // What the application is actually inside, which is the only thing that decides
            // whether it needs a paste terminator. The framer says what the accepted stream means;
            // a batch this writer never wrote never happened to the application.
            let mut last_fence = writer_fence.load(Ordering::Acquire);
            while let Some(batch) = input_receiver.blocking_recv() {
                if matches!(batch, InputBatch::LeaseChanged) {
                    writer_lease_change.store(false, Ordering::Release);
                }
                let fence = writer_fence.load(Ordering::Acquire);
                // A lease has ended. Before anything from the next one reaches the application, a
                // paste the old lease started and never finished is closed, so the next actor's
                // input never lands inside somebody else's paste (KR-REQ-08.64). The terminator is
                // this writer's own correction and is never fenced: it is the one thing that can
                // end a paste nothing else is going to end.
                if fence != last_fence {
                    last_fence = fence;
                    if writer_paste_open.swap(false, Ordering::AcqRel)
                        && !insist(
                            &mut writer,
                            crate::input::PASTE_END,
                            input_waiter.as_ref(),
                            &writer_gate,
                        )
                    {
                        break;
                    }
                }
                let (epoch, bytes, transition) = match &batch {
                    InputBatch::Lease {
                        epoch,
                        bytes,
                        paste,
                    } => (Some(*epoch), bytes.as_slice(), paste.clone()),
                    InputBatch::Reply { bytes } => {
                        (None, bytes.as_slice(), PasteTransition::default())
                    }
                    InputBatch::LeaseChanged => continue,
                };
                // Stale keystrokes are dropped here rather than written. A takeover that only
                // stopped *new* input would still let the previous holder's last keystrokes land in
                // the new holder's command line. The host's own answer to a query the application
                // asked is not a keystroke and is never dropped: nothing else can supply it.
                if epoch.is_some_and(|epoch| epoch < fence) {
                    // Only the whole budget is given back. The lease's own share was taken by the
                    // lease change that made these bytes stale, and reported there as discarded.
                    release(&writer_queued, bytes.len());
                    continue;
                }
                let lease_epoch = epoch.unwrap_or_default();
                // Written in pieces, with the fence looked at before each one, so that a
                // takeover reaches this writer between pieces rather than behind a whole batch.
                let (delivered, delivery) = write_batch(
                    &mut writer,
                    bytes,
                    &transition,
                    input_waiter.as_ref(),
                    &writer_gate,
                    &mut || epoch.is_some_and(|epoch| epoch < writer_fence.load(Ordering::Acquire)),
                    &mut |written| {
                        // Released only once the application has it. Until then it is owed.
                        release(&writer_queued, written);
                        // The lease's share only while these bytes are still the current lease's.
                        // The epoch travels with the count, so a lease change that happened while
                        // this write was in the terminal leaves nothing here to subtract from.
                        if epoch.is_some() {
                            writer_lease.release(lease_epoch, written);
                        }
                    },
                );
                let _ = std::io::Write::flush(&mut writer);
                if delivery == Delivery::Gone {
                    break;
                }
                // What the application's framing is now is decided by the delimiters that reached
                // it, whether or not the rest of the batch did.
                if let Some(open) = transition.after(delivered) {
                    writer_paste_open.store(open, Ordering::Release);
                }
                if delivery == Delivery::Abandoned {
                    // The rest of the batch belongs to a lease that has ended, so it is not
                    // written. What was delivered is what the application has, and the takeover
                    // reports the remainder as discarded.
                    release(&writer_queued, bytes.len().saturating_sub(delivered));
                }
            }
        });

        let runtime = Self {
            session: Arc::clone(&session),
            input: input_sender.clone(),
            wake: Arc::clone(&wake),
            closed: Arc::clone(&closed),
            fence: Arc::clone(&fence),
        };

        let ingest_session = Arc::clone(&session);
        let ingest_closed = Arc::clone(&closed);
        let ingest_input = input_sender.clone();
        tokio::spawn(async move {
            while let Some(event) = output_receiver.recv().await {
                match event {
                    ReadEvent::Bytes(bytes) => {
                        if let Ok(mut session) = ingest_session.lock() {
                            session.ingest_output(&bytes);
                            // Nothing else is waiting, so the terminal has gone quiet and the
                            // screen is settled. The engine holds the last scalar of a run back in
                            // case a combining mark follows it, and this is what releases it.
                            if output_receiver.is_empty() {
                                session.quiesce_output();
                            }
                            // What the host owes the application goes back into its terminal
                            // input. An application that asked the terminal a question is waiting
                            // for the answer, and nothing else can supply it.
                            for batch in session.take_pending_input() {
                                let _ = ingest_input.send(batch);
                            }
                        }
                    }
                    ReadEvent::Ended => {
                        // The terminal is finished. Whether the root shell has ended is a separate
                        // question, answered by the child monitor: a descendant can hold the slave
                        // descriptor open after the shell exits, and a read error is not a death.
                        ingest_closed.notify_waiters();
                        break;
                    }
                }
            }
        });

        // The root shell's status is watched independently of the terminal. An explicit exit, an
        // end of file at the root prompt and a crash all close the session, and KalaReach never
        // restarts the shell.
        let monitor_session = Arc::clone(&session);
        let monitor_closed = Arc::clone(&closed);
        let monitor_input = input_sender.clone();
        let monitor_wake = Arc::clone(&wake);
        let monitor_fence = Arc::clone(&fence);
        tokio::spawn(async move {
            // The monitor holds a runtime of its own so a closure it begins publishes its fence and
            // its paste terminator the same way a requested one does. Building it only once the
            // closure had started would leave those inside the session until something else
            // flushed, and a desktop that has gone or a shell that has exited is exactly when
            // nothing else is going to.
            let runtime = Arc::new(SessionRuntime {
                session: Arc::clone(&monitor_session),
                input: monitor_input.clone(),
                wake: Arc::clone(&monitor_wake),
                closed: Arc::clone(&monitor_closed),
                fence: Arc::clone(&monitor_fence),
            });
            let mut next_observation = Instant::now();
            loop {
                tokio::time::sleep(CHILD_POLL_INTERVAL).await;
                let initiated = {
                    let Ok(mut session) = monitor_session.lock() else {
                        break;
                    };
                    if session.state() == SessionState::Closed {
                        break;
                    }
                    // The set of processes the session owns is built up while it runs, on its own
                    // slower cadence: one that starts and ends between two observations is never
                    // recorded, and observing at the rate the shell is checked would cost more than
                    // the whole host is allowed to spend while idle.
                    let now = Instant::now();
                    if now >= next_observation {
                        session.observe_owned();
                        next_observation = now + OWNERSHIP_OBSERVE_INTERVAL;
                    }
                    // A desktop-bound session belongs to one login. When that login ends the
                    // session ends with it, with the reason that says so.
                    let initiated = if session.desktop_lost() {
                        session.begin_close(ClosureReason::DesktopLost).initiated
                    } else {
                        session.poll_root_exit()
                    };
                    if initiated {
                        // Admission released the lease and may have produced a paste terminator.
                        // Both reach the writer here, under the lock that admitted the closure.
                        runtime.flush_locked(&mut session);
                    }
                    initiated
                };
                if initiated {
                    // A root shell that ended on its own goes through the same sequence a
                    // requested close does, so descendants are still stopped and output is still
                    // drained before the record is written.
                    CloseGate {
                        runtime: Arc::clone(&runtime),
                        initiated: true,
                    }
                    .release();
                    break;
                }
            }
        });

        // The paste recogniser's deadline runs on the clock, not on the arrival of more input.
        let timer_session = Arc::clone(&session);
        let timer_input = input_sender;
        let timer_wake = Arc::clone(&wake);
        tokio::spawn(async move {
            loop {
                let deadline = timer_session
                    .lock()
                    .ok()
                    .and_then(|session| session.paste_deadline());
                match deadline {
                    Some(deadline) => {
                        let now = Instant::now();
                        let wait = deadline.saturating_duration_since(now);
                        tokio::select! {
                            () = tokio::time::sleep(wait) => {}
                            () = timer_wake.notified() => continue,
                        }
                        if let Ok(mut session) = timer_session.lock() {
                            session.expire_paste_prefix(Instant::now());
                            for batch in session.take_pending_input() {
                                let _ = timer_input.send(batch);
                            }
                        }
                    }
                    None => timer_wake.notified().await,
                }
            }
        });

        Ok(runtime)
    }

    /// Locks the session for one operation.
    ///
    /// # Panics
    ///
    /// Panics when the lock is poisoned, which means an earlier operation panicked while holding
    /// session state and the state can no longer be trusted.
    pub fn session(&self) -> MutexGuard<'_, Session> {
        self.session
            .lock()
            .expect("the session lock is not poisoned")
    }

    /// Writes whatever the session has queued for the pseudo-terminal.
    ///
    /// Call this after any operation that can produce input bytes.
    pub fn flush_input(&self) {
        let mut session = self.session();
        let pending = session.take_pending_input();
        // Sent while the session is still held, so two callers cannot interleave their batches:
        // the order bytes reach the terminal in is the order they were accepted in. The fence is
        // already published: the session moves it as it changes the lease, which is earlier than
        // here and earlier than anything that counts what the lease left behind.
        self.send_input(pending);
    }

    /// Writes the batches a caller produced while it was holding the session.
    ///
    /// The session published the fence as it changed the lease, so a batch the caller's own
    /// operation invalidated is already one the writer drops rather than writes.
    pub fn flush_locked(&self, session: &mut Session) {
        let pending = session.take_pending_input();
        self.send_input(pending);
    }

    /// Writes batches an operation produced while the session was already locked.
    ///
    /// A mutation runs inside the session's serial boundary, so it cannot take the lock again to
    /// flush. It hands the batches out instead, and this sends them once the boundary is over.
    pub fn send_input(&self, batches: Vec<InputBatch>) {
        for batch in batches {
            let _ = self.input.send(batch);
        }
        // A new held prefix needs the timer to look again.
        self.wake.notify_waiters();
    }

    /// Admits a close and returns the acceptance, before anything is signalled.
    ///
    /// The returned gate starts the termination sequence. The caller releases it **after** the
    /// acceptance has reached the requester, because the requester is often a command running
    /// inside the process group that is about to be stopped.
    pub fn close(self: &Arc<Self>, reason: ClosureReason) -> (CloseAcceptance, CloseGate) {
        let mut session = self.session();
        let outcome = self.close_locked(&mut session, reason);
        drop(session);
        outcome
    }

    /// Admits a close on a session this caller already holds.
    ///
    /// A mutation runs inside the session's serial boundary and cannot take the lock again, so the
    /// admission happens on the guard it is already holding.
    pub fn close_locked(
        self: &Arc<Self>,
        session: &mut Session,
        reason: ClosureReason,
    ) -> (CloseAcceptance, CloseGate) {
        let acceptance = session.begin_close(reason);
        // Admission moved the input fence and may have produced a paste terminator. Publishing both
        // here is what makes "input is rejected from this moment" true of bytes that were already
        // handed to the writer, rather than only of bytes not yet accepted.
        self.flush_locked(session);
        let gate = CloseGate {
            runtime: Arc::clone(self),
            initiated: acceptance.initiated,
        };
        (acceptance, gate)
    }

    /// Waits until the session has finished closing and returns its record.
    pub async fn wait_closed(&self) -> ClosureRecord {
        loop {
            // Register interest before looking, so a notification that arrives between the two is
            // not lost.
            let notified = self.closed.notified();
            if let Some(record) = self.session().closure().cloned() {
                return record;
            }
            notified.await;
        }
    }

    /// Returns the session's current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.session().state()
    }

    /// Returns the lease epoch the writer is comparing every queued batch against.
    ///
    /// It is [`Session::input_fence`] read from the outside: the session publishes it as it changes
    /// the lease, so it is never behind the lease the session itself holds.
    #[must_use]
    pub fn input_fence(&self) -> u64 {
        self.fence.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// How long a worker waits for a proxy to confirm it delivered the acceptance.
///
/// A close that was admitted happens. Waiting for confirmation is what stops the requester's
/// process group being signalled before it has read its own answer; waiting for it forever would
/// let a proxy that went away leave a session closing and never closed.
pub const ACCEPTANCE_DELIVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The right to start a session's termination sequence.
///
/// Holding one means a close has been admitted and nothing has been signalled yet.
#[derive(Debug)]
pub struct CloseGate {
    runtime: Arc<SessionRuntime>,
    initiated: bool,
}

impl CloseGate {
    /// Releases the gate when a proxy confirms delivery, or when the wait for it runs out.
    ///
    /// The requester of a proxied close is not the peer this worker replied to: the daemon still
    /// has to pass the acceptance on. Signalling before that would stop the very command that is
    /// waiting to read its answer.
    #[must_use]
    pub fn release_on_delivery(self, timeout: std::time::Duration) -> PendingDelivery {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            // Either answer releases the gate. A confirmation means the requester has its
            // acceptance; the deadline means nobody is going to confirm, and the close still
            // happens, because it was admitted.
            let _ = tokio::time::timeout(timeout, receiver).await;
            self.release();
        });
        PendingDelivery { sender }
    }

    /// Starts the grace period, the forced stop and the drain.
    ///
    /// Call this only after the acceptance has reached the requester, or after it has become clear
    /// that it will not.
    pub fn release(self) {
        if !self.initiated {
            return;
        }
        let runtime = self.runtime;
        tokio::spawn(async move {
            {
                let mut session = runtime.session();
                let _ = session.request_stop();
            }
            // The grace period is an allowance, not a delay. A session whose processes have all
            // stopped moves on immediately; one that still holds something is given the full five
            // seconds before anything is forced.
            let deadline = tokio::time::Instant::now() + GRACE_PERIOD;
            loop {
                let remaining = {
                    let session = runtime.session();
                    session
                        .owned()
                        .is_none_or(|owned| !owned.surviving().is_empty())
                };
                if !remaining || tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(STOP_POLL_INTERVAL).await;
            }
            {
                // Whatever is left is forced. Which processes that reached is recorded there, while
                // the kernel still names them.
                let mut session = runtime.session();
                let _ = session.force_close();
            }
            tokio::time::sleep(DRAIN_PERIOD).await;
            {
                let mut session = runtime.session();
                session.finish_close();
            }
            runtime.closed.notify_waiters();
        });
    }
}

/// A close waiting for its acceptance to be confirmed delivered.
#[derive(Debug)]
pub struct PendingDelivery {
    sender: tokio::sync::oneshot::Sender<()>,
}

impl PendingDelivery {
    /// Confirms that the requester has the acceptance, which starts the termination sequence.
    pub fn confirm(self) {
        let _ = self.sender.send(());
    }
}

#[derive(Debug)]
enum ReadEvent {
    Bytes(Vec<u8>),
    Ended,
}

/// Starts a session: opens the terminal, launches the shell and starts the tasks.
///
/// # Errors
///
/// Returns an error when the terminal cannot be created or the shell cannot be launched.
pub fn start(config: crate::session::SessionConfig) -> Result<Arc<SessionRuntime>> {
    let mut session = Session::open(config)?;
    session.launch()?;
    SessionRuntime::start(session).map(Arc::new)
}

/// Why a session could not be started, and the record it left behind.
#[derive(Debug)]
pub struct LaunchFailure {
    /// What went wrong.
    pub error: WorkerError,
    /// The closure record, when the session got far enough to leave one.
    pub closure: Option<ClosureRecord>,
}

/// Starts a session and reports a launch failure with its closure record.
///
/// # Errors
///
/// Returns the launch failure. A session whose shell never started is already recorded as closed
/// with `root_launch_failed`, so a failed creation leaves a record rather than a stuck `creating`.
pub fn start_or_record(
    config: crate::session::SessionConfig,
) -> std::result::Result<Arc<SessionRuntime>, Box<LaunchFailure>> {
    let mut session = match Session::open(config) {
        Ok(session) => session,
        Err(error) => {
            return Err(Box::new(LaunchFailure {
                error,
                closure: None,
            }));
        }
    };
    if let Err(error) = session.launch() {
        let closure = session.closure().cloned();
        return Err(Box::new(LaunchFailure { error, closure }));
    }
    SessionRuntime::start(session)
        .map(Arc::new)
        .map_err(|error| {
            Box::new(LaunchFailure {
                error,
                closure: None,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{Delivery, WRITE_PIECE_BYTES, write_batch};
    use crate::input::{Delimiter, PASTE_START};
    use crate::session::PasteTransition;

    /// A terminal that takes a fixed amount per write, which is what a real one does when its
    /// input queue is nearly full.
    struct Fills {
        taken: Vec<u8>,
        per_write: usize,
    }

    impl std::io::Write for Fills {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let takes = bytes.len().min(self.per_write);
            self.taken.extend_from_slice(&bytes[..takes]);
            Ok(takes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A paste start that a write of `WRITE_PIECE_BYTES` stops in the middle of.
    fn split_delimiter() -> (Vec<u8>, PasteTransition) {
        let ordinary = WRITE_PIECE_BYTES - 2;
        let mut bytes = vec![b'a'; ordinary];
        bytes.extend_from_slice(PASTE_START);
        bytes.extend_from_slice(&[b'b'; 4096]);
        let end = u32::try_from(ordinary).expect("fits") + Delimiter::LEN;
        (
            bytes,
            PasteTransition {
                delimiters: vec![Delimiter { end, opens: true }],
            },
        )
    }

    #[test]
    fn a_short_write_finishes_the_delimiter_it_stopped_inside_before_it_abandons() {
        let (bytes, transition) = split_delimiter();
        let mut terminal = Fills {
            taken: Vec::new(),
            per_write: WRITE_PIECE_BYTES,
        };
        // The lease ends while the first piece is with the terminal, which is the schedule a
        // takeover produces.
        let mut pieces = 0;
        let mut written = 0_usize;
        let (delivered, delivery) = write_batch(
            &mut terminal,
            &bytes,
            &transition,
            None,
            &std::sync::Mutex::new(()),
            &mut || {
                pieces += 1;
                pieces > 1
            },
            &mut |count| written += count,
        );

        assert_eq!(
            delivery,
            Delivery::Abandoned,
            "the rest of the batch belongs to a lease that has ended"
        );
        assert_eq!(
            delivered,
            WRITE_PIECE_BYTES - 2 + PASTE_START.len(),
            "and the rest of the delimiter the write stopped inside of went with it"
        );
        assert_eq!(
            written, delivered,
            "every byte the terminal took is accounted"
        );
        assert!(
            terminal.taken.ends_with(PASTE_START),
            "the application holds a whole paste start, not half of one"
        );
    }

    #[test]
    fn what_the_terminal_took_is_what_is_released_not_what_was_offered() {
        let bytes = vec![b'a'; WRITE_PIECE_BYTES * 3];
        let mut terminal = Fills {
            taken: Vec::new(),
            per_write: 100,
        };
        let mut written = 0_usize;
        let (delivered, delivery) = write_batch(
            &mut terminal,
            &bytes,
            &PasteTransition::default(),
            None,
            &std::sync::Mutex::new(()),
            &mut || false,
            &mut |count| written += count,
        );

        assert_eq!(delivery, Delivery::Complete);
        assert_eq!(delivered, bytes.len());
        assert_eq!(written, bytes.len());
        assert_eq!(terminal.taken, bytes);
    }

    #[test]
    fn a_terminal_that_takes_nothing_is_gone_rather_than_waited_on() {
        let mut terminal = Fills {
            taken: Vec::new(),
            per_write: 0,
        };
        let mut written = 0_usize;
        let (delivered, delivery) = write_batch(
            &mut terminal,
            b"kr",
            &PasteTransition::default(),
            None,
            &std::sync::Mutex::new(()),
            &mut || false,
            &mut |count| written += count,
        );

        assert_eq!(delivery, Delivery::Gone);
        assert_eq!(delivered, 0);
        assert_eq!(written, 0);
    }
}
