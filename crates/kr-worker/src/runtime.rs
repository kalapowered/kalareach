//! The tasks that drive one session.
//!
//! [`crate::session::Session`] holds the state and changes it one call at a time. This module is
//! what calls it: a blocking reader on the pseudo-terminal, a blocking writer for input, a timer
//! for the paste recogniser, the supervision of the root shell and what it owns, and the closure
//! sequence with its grace and drain periods.
//!
//! The reader is the part with a rule attached. It must never stop because a client is slow, and
//! it must never discard what it has read; both would make the worker's idea of the screen wrong.
//! So it reads, hands the bytes to the session, and goes back to reading. Everything that could
//! wait happens on the delivery side.
//!
//! Every wait here is on something that happens rather than on a clock, because a session sitting
//! idle has to cost nothing (KR-PERF-003): the reader waits on the terminal's own descriptor, the
//! writer on room in it, the recogniser on its one deadline, and the supervision on the events
//! [`crate::lifecycle`] describes. What is left on a clock is named there, with what it costs.

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

/// How long the read loop waits on the terminal for the application to write something.
///
/// The wait ends by itself the moment output arrives, and again the moment the terminal goes: the
/// terminal's own descriptor is what it waits on, and both of those are events on it. So this is
/// neither latency nor how quickly an ended terminal is noticed. It is a safety net for a platform
/// that reports neither, and a session sitting idle should cost nothing, so it is long.
pub const READ_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// How often a read loop with nothing to wait on asks the terminal again.
///
/// This is the one wait here that *is* latency: a terminal with no descriptor to wait on cannot
/// wake anybody, so its output waits for the next read instead. No backend in this host's
/// repertoire is in that position, and the interval is short enough to be a fallback rather than a
/// behaviour.
pub const READ_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the writer keeps offering bytes the application must have where it cannot ask a waiter.
///
/// It applies only to a terminal that answers a write with "no room" and has no descriptor to wait
/// on, which is a combination no backend in the repertoire has: where there is a waiter, the
/// terminal itself says when it has gone, and that is the bound. This is what stands in for that
/// answer when nothing can be asked for one.
pub const INSIST_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the writer waits for the terminal to have room before it looks at the fence again.
///
/// The wait ends by itself when the application reads, so this is only the interval at which a
/// writer that is waiting reconsiders whether the bytes it is holding are still wanted.
pub const WRITE_WAIT: std::time::Duration = std::time::Duration::from_millis(20);

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

/// Sets the session's latch when the writer thread ends, however it ends.
struct TerminalEnded(Arc<std::sync::atomic::AtomicBool>);

impl Drop for TerminalEnded {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// The terminal a batch is written into, and what it is waited on with.
struct Terminal<'a, W: std::io::Write> {
    writer: &'a mut W,
    room: Option<&'a crate::pty::InputWaiter>,
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
/// What makes this a boundary and not a wait is that the write inside it cannot wait. Every terminal
/// this host opens answers rather than waits - that is what [`crate::conpty`] exists for on Windows
/// - so a write takes what there is room for and says so, and what it took is what is released.
///
/// A piece is at most [`WRITE_PIECE_BYTES`], so a takeover reaches a writer between pieces instead
/// of behind a whole batch. `room` is waited on outside the boundary, and only after the terminal
/// has said it has none: the write is the thing that knows, and asking anything else first would
/// pay for room the terminal already had. A piece never *ends*
/// inside a paste delimiter: a terminal takes what it has room for, so a short write can stop in
/// the middle of one. Half a delimiter is the one thing an abandoned batch cannot leave behind,
/// because the next actor's first bytes would complete it and their paste would begin inside the
/// previous actor's.
///
/// So the rest of such a delimiter is committed inside the boundary that began it, by the same rule,
/// and written outside it with the patience of [`insist`]. Nothing else can reach the application
/// first: one writer serves this terminal, and it does not take another batch until these are with
/// it.
fn write_batch(
    terminal: &mut Terminal<'_, impl std::io::Write>,
    bytes: &[u8],
    transition: &crate::session::PasteTransition,
    gate: &std::sync::Mutex<()>,
    stale: &mut impl FnMut() -> bool,
    wrote: &mut impl FnMut(usize),
) -> (usize, Delivery) {
    let Terminal { writer, room } = terminal;
    let room = *room;
    let mut delivered = 0_usize;
    while delivered < bytes.len() {
        // The rest of a delimiter the last piece stopped inside of, already counted as delivered
        // and not yet written. It goes before anything else this writer does.
        let mut owed: Option<std::ops::Range<usize>> = None;
        // One boundary for the fence, the write, the delimiter it may have stopped inside of, and
        // the accounting for every byte of that. A delimiter finished after the boundary was let go
        // would be bytes written after a takeover counted them as discarded, which is the one thing
        // the receipt must never say.
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
                // A write that stopped inside a delimiter commits the rest of it here, fence or no
                // fence: its first bytes are already with the application, and the next actor's
                // input must not be what completes them. Counting them now, on this boundary, is
                // what makes the count a takeover takes on the same boundary true of them.
                if let Some(end) = transition.unfinished(delivered) {
                    let end = end.min(bytes.len());
                    owed = Some(delivered..end);
                    wrote(end - delivered);
                    delivered = end;
                }
            }
            attempt
        };
        // Outside the boundary, because nothing here is still deciding anything: these bytes are
        // counted, they are this writer's to deliver, and a terminal that will not take them is one
        // that has gone rather than one that is slow.
        if let Some(owed) = owed
            && !insist(writer, &bytes[owed], room, gate)
        {
            return (delivered, Delivery::Gone);
        }
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
                // The terminal has no room for more. This is the only wait, it happens outside the
                // boundary, and it happens only after the terminal itself has said so: a writer
                // that waited before every piece would pay for room it already had.
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
            }
            Err(_) => return (delivered, Delivery::Gone),
        }
    }
    (delivered, Delivery::Complete)
}

/// Writes a few bytes the application must have into a terminal that answers rather than waits.
///
/// No fence applies to these: a paste terminator is the one thing that can end a paste nothing else
/// is going to end, and a piece or a half-written delimiter committed under the boundary is already
/// counted as delivered. Both are bytes a terminal with any room at all takes whole.
///
/// What bounds the waiting is the terminal itself rather than a clock. An application that pauses
/// its reads is an ordinary application, and a writer that gave up on one would take the session's
/// whole input path with it; the waiter reports a terminal that has actually gone, and that is what
/// ends this. Where there is no waiter to ask, [`INSIST_LIMIT`] is the only bound there can be.
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
                match room {
                    Some(waiter) => {
                        if waiter.wait(WRITE_WAIT) == crate::pty::Room::Gone {
                            return false;
                        }
                    }
                    None => {
                        if std::time::Instant::now() >= deadline {
                            return false;
                        }
                        std::thread::sleep(WRITE_WAIT);
                    }
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
    /// The machine's own continuous clock, shared with the writer and with whatever else in this
    /// process decides whether a forwarded deadline has passed. One reading of one clock answers
    /// the same question at both boundaries.
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    input: mpsc::UnboundedSender<InputBatch>,
    wake: Arc<Notify>,
    closed: Arc<Notify>,
    fence: Arc<std::sync::atomic::AtomicU64>,
    /// What tells the supervision that a process this session owns can have appeared.
    activity: Arc<crate::lifecycle::Activity>,
}

impl SessionRuntime {
    /// Starts the reader, the writer and the timers around an already launched session.
    ///
    /// `shared_clock` is the machine's own continuous clock, which is the clock a forwarded
    /// authority deadline is expressed on. The writer holds it because the writer is the last
    /// boundary before the application: a batch waiting there for a terminal to take it has to be
    /// measured against the authority that admitted it, not against the authority that held when
    /// it was queued.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal's reader or writer cannot be taken.
    pub fn start(
        session: Session,
        shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    ) -> Result<Self> {
        let reader = session.output_reader()?;
        let mut writer = session.input_writer()?;
        // What the host owes the application is bounded by what has been *written*, not by what is
        // waiting in the session, because the session hands its queue over on every flush.
        let input_waiter = session.input_waiter();
        let output_waiter = session.output_waiter();
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
        // Set when the writer ends. A terminal that will take nothing more is one this session
        // cannot accept input for, and saying so is better than acknowledging bytes nothing writes.
        let terminal_gone = session.terminal_gone_latch();
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
        // Input this session accepted and output it produced are what ask the supervision to look
        // at the boundary; neither is proof that a process started, and [`crate::lifecycle`] says
        // what a session whose application works in silence leaves out. Nothing here is on a clock
        // that an idle session pays for.
        let activity = crate::lifecycle::Activity::new();

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
                        if filled < buffer.len() {
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
                            None => std::thread::sleep(READ_RETRY),
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
        let writer_gone = Arc::clone(&terminal_gone);
        let writer_clock = Arc::clone(&shared_clock);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;

            // Set on every way out of the loop below. The writer ends for one reason - a terminal
            // that will take nothing more - and from then on this session refuses input rather than
            // acknowledging bytes nothing will write.
            let _ended = TerminalEnded(writer_gone);

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
                    if writer_paste_open.swap(0, Ordering::AcqRel) != 0
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
                let (epoch, bytes, transition, authority_deadline) = match &batch {
                    InputBatch::Lease {
                        epoch,
                        bytes,
                        paste,
                        authority_deadline_boot_ms,
                    } => (
                        Some(*epoch),
                        bytes.as_slice(),
                        paste.clone(),
                        *authority_deadline_boot_ms,
                    ),
                    InputBatch::Reply { bytes } => (
                        None,
                        bytes.as_slice(),
                        PasteTransition::default(),
                        // The host's own answer to a question the application asked belongs to the
                        // application, not to any caller's grant, so no grant's expiry withholds
                        // it.
                        None,
                    ),
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
                // A second fence, independent of the lease's. The lease says who may write; this
                // says how long what they wrote stays admissible. A batch the session accepted a
                // moment before its caller's grant ran out can wait here — for the terminal, for
                // an application that is not reading — and the grant can end while it waits.
                // Nothing written after the deadline reaches the application.
                let expired = |clock: &dyn kr_ipc::clock::SharedClock| {
                    authority_deadline.is_some_and(|deadline| clock.boot_elapsed_ms() >= deadline)
                };
                if expired(writer_clock.as_ref()) {
                    // Only a lease batch carries an authority deadline, and the lease itself has
                    // not moved: its share of the queue is still counted against it, so it comes
                    // back here with the whole budget.
                    release(&writer_queued, bytes.len());
                    writer_lease.release(lease_epoch, bytes.len());
                    continue;
                }
                // Written in pieces, with the fence looked at before each one, so that a
                // takeover reaches this writer between pieces rather than behind a whole batch.
                let mut delivered_so_far = 0_usize;
                let (delivered, delivery) = write_batch(
                    &mut Terminal {
                        writer: &mut writer,
                        room: input_waiter.as_ref(),
                    },
                    bytes,
                    &transition,
                    &writer_gate,
                    &mut || {
                        epoch.is_some_and(|epoch| epoch < writer_fence.load(Ordering::Acquire))
                            || expired(writer_clock.as_ref())
                    },
                    &mut |written| {
                        // Released only once the application has it. Until then it is owed.
                        release(&writer_queued, written);
                        // The lease's share only while these bytes are still the current lease's.
                        // The epoch travels with the count, so a lease change that happened while
                        // this write was in the terminal leaves nothing here to subtract from.
                        if epoch.is_some() {
                            writer_lease.release(lease_epoch, written);
                        }
                        // What the application's framing is, published as each piece reaches it
                        // rather than once the batch is done. A batch is written in pieces with
                        // waits between them, and a takeover that arrived in one of those gaps
                        // would otherwise read framing from before the batch began and report that
                        // no paste was interrupted when one was. The value names the lease, so a
                        // later lease change cannot mistake this paste for its own.
                        delivered_so_far = delivered_so_far.saturating_add(written);
                        if let Some(open) = transition.after(delivered_so_far) {
                            writer_paste_open.store(
                                if open {
                                    lease_epoch.saturating_add(1)
                                } else {
                                    0
                                },
                                Ordering::Release,
                            );
                        }
                    },
                );
                let _ = std::io::Write::flush(&mut writer);
                if delivery == Delivery::Gone {
                    break;
                }
                // What the application's framing is now is decided by the delimiters that reached
                // it, whether or not the rest of the batch did. The callback above has published
                // every piece already; this is the whole batch's answer, which is the same one.
                if let Some(open) = transition.after(delivered) {
                    writer_paste_open.store(
                        if open {
                            lease_epoch.saturating_add(1)
                        } else {
                            0
                        },
                        Ordering::Release,
                    );
                }
                if delivery == Delivery::Abandoned {
                    // The rest of the batch belongs to a lease that has ended, or to authority
                    // that has run out, so it is not written. What was delivered is what the
                    // application has, and a takeover reports the remainder as discarded.
                    let remainder = bytes.len().saturating_sub(delivered);
                    release(&writer_queued, remainder);
                    // The lease's own share comes back only while the lease is still the one that
                    // queued these bytes: a lease change has already taken its count, and the
                    // count names the epoch it belongs to, so this subtracts nothing after one.
                    if epoch.is_some() {
                        writer_lease.release(lease_epoch, remainder);
                    }
                }
            }
        });

        let runtime = Self {
            session: Arc::clone(&session),
            shared_clock: Arc::clone(&shared_clock),
            input: input_sender.clone(),
            wake: Arc::clone(&wake),
            closed: Arc::clone(&closed),
            fence: Arc::clone(&fence),
            activity: Arc::clone(&activity),
        };

        let ingest_session = Arc::clone(&session);
        let ingest_closed = Arc::clone(&closed);
        let ingest_input = input_sender.clone();
        let ingest_activity = Arc::clone(&activity);
        tokio::spawn(async move {
            while let Some(event) = output_receiver.recv().await {
                match event {
                    ReadEvent::Bytes(bytes) => {
                        // Something in this session is running. Whatever it is may be a process
                        // that was not there at the last observation.
                        ingest_activity.note();
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
        let monitor_activity = Arc::clone(&activity);
        let monitor_clock = Arc::clone(&shared_clock);
        tokio::spawn(async move {
            // The monitor holds a runtime of its own so a closure it begins publishes its fence and
            // its paste terminator the same way a requested one does. Building it only once the
            // closure had started would leave those inside the session until something else
            // flushed, and a desktop that has gone or a shell that has exited is exactly when
            // nothing else is going to.
            let runtime = Arc::new(SessionRuntime {
                session: Arc::clone(&monitor_session),
                shared_clock: monitor_clock,
                input: monitor_input.clone(),
                wake: Arc::clone(&monitor_wake),
                closed: Arc::clone(&monitor_closed),
                fence: Arc::clone(&monitor_fence),
                activity: Arc::clone(&monitor_activity),
            });
            // Built here rather than by the caller: waiting for a child to end is the runtime's
            // own facility, and this is the task that does the waiting.
            let mut supervision =
                crate::lifecycle::Supervision::begin(monitor_activity, Instant::now());
            // The shell is asked about once before anything is waited on, because the child signal
            // only reports what happens after it is open: a shell that ended in between is found
            // here instead. Nothing is observed on this first look; the boundary was recorded as it
            // was established.
            let mut wake = crate::lifecycle::Wake::Session;
            loop {
                let initiated = {
                    let Ok(mut session) = monitor_session.lock() else {
                        break;
                    };
                    if session.state() == SessionState::Closed {
                        break;
                    }
                    // The set of processes the session owns is built up while it runs, on the
                    // cadence [`crate::lifecycle`] describes: a process that starts and ends
                    // between two observations is never recorded, and enumerating the boundary
                    // every time the shell is asked about would cost more than the whole host is
                    // allowed to spend while idle.
                    if wake == crate::lifecycle::Wake::Ownership {
                        session.observe_owned();
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
                wake = supervision.next().await;
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

    /// Returns the machine's own continuous clock this session's boundaries read.
    #[must_use]
    pub fn shared_clock(&self) -> Arc<dyn kr_ipc::clock::SharedClock> {
        Arc::clone(&self.shared_clock)
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
        let sent = !batches.is_empty();
        for batch in batches {
            let _ = self.input.send(batch);
        }
        // A new held prefix needs the timer to look again, and the permit has to survive the
        // moment between the timer reading "no deadline" and beginning to wait. Waking whoever is
        // already waiting is not enough: the timer that has just read an empty deadline is not
        // waiting yet, and a notice it missed would leave a lone Escape waiting for the next
        // keystroke, which is the one thing section 8 says it must never do. There is exactly one
        // consumer of this signal, so storing a permit for it is what this needs.
        self.wake.notify_one();
        if sent {
            // Input the session accepted is how a process it owns usually starts, so the
            // supervision looks at the boundary shortly after this rather than on a clock.
            self.activity.note();
        }
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

/// How long a worker waits for one acceptance to reach the transport it answers on.
///
/// A peer that has stopped reading must not hold a session closing for as long as it stays away,
/// and a write that cannot finish inside this is one nothing is reading: the connection carries
/// nothing more, and the close goes on, because it was admitted.
pub const ACCEPTANCE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
pub fn start(
    config: crate::session::SessionConfig,
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
) -> Result<Arc<SessionRuntime>> {
    let mut session = Session::open(config)?;
    session.launch()?;
    SessionRuntime::start(session, shared_clock).map(Arc::new)
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
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
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
    SessionRuntime::start(session, shared_clock)
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
    use super::{Delivery, Terminal, WRITE_PIECE_BYTES, write_batch};
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

    /// A terminal that takes one piece and then has no room for the few bytes that finish the
    /// delimiter, which is what one whose input queue filled exactly there does.
    struct Grudging {
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        per_write: usize,
        refuse_until: Option<std::time::Instant>,
        refusal: std::time::Duration,
    }

    impl std::io::Write for Grudging {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match self.refuse_until {
                Some(until) if std::time::Instant::now() < until => {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Some(_) => {}
                None => self.refuse_until = Some(std::time::Instant::now() + self.refusal),
            }
            let takes = bytes.len().min(self.per_write);
            self.taken
                .lock()
                .expect("the record of what the application holds is not poisoned")
                .extend_from_slice(&bytes[..takes]);
            Ok(takes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A batch that ends with a paste start a write of `WRITE_PIECE_BYTES` stops in the middle of.
    fn ends_in_a_delimiter() -> (Vec<u8>, PasteTransition) {
        let ordinary = WRITE_PIECE_BYTES - 2;
        let mut bytes = vec![b'a'; ordinary];
        bytes.extend_from_slice(PASTE_START);
        let end = u32::try_from(ordinary).expect("fits") + Delimiter::LEN;
        (
            bytes,
            PasteTransition {
                delimiters: vec![Delimiter { end, opens: true }],
            },
        )
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
            &mut Terminal {
                writer: &mut terminal,
                room: None,
            },
            &bytes,
            &transition,
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
    fn the_rest_of_a_delimiter_is_with_the_application_before_a_takeover_can_count_it_lost() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let (bytes, transition) = ends_in_a_delimiter();
        let taken = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut terminal = Grudging {
            taken: std::sync::Arc::clone(&taken),
            per_write: WRITE_PIECE_BYTES,
            refuse_until: None,
            refusal: std::time::Duration::from_millis(100),
        };
        let gate = std::sync::Arc::new(std::sync::Mutex::new(()));
        let released = std::sync::Arc::new(AtomicUsize::new(0));
        let fence = std::sync::Arc::new(AtomicBool::new(false));
        let (announce, announced) = std::sync::mpsc::channel();

        // The takeover, doing what `Session::end_lease` does: take the boundary, publish the fence
        // and count what the ended lease left behind, in one step. It begins the moment the first
        // piece is with the terminal, which is where the delimiter is half written.
        let takeover = std::thread::spawn({
            let gate = std::sync::Arc::clone(&gate);
            let taken = std::sync::Arc::clone(&taken);
            let released = std::sync::Arc::clone(&released);
            let fence = std::sync::Arc::clone(&fence);
            move || {
                announced
                    .recv()
                    .expect("the writer announces its first piece");
                let _boundary = gate.lock().expect("the input boundary is not poisoned");
                let with_the_application = taken.lock().expect("the record is not poisoned").len();
                let counted = released.load(Ordering::SeqCst);
                fence.store(true, Ordering::SeqCst);
                (with_the_application, counted)
            }
        });

        let mut announce = Some(announce);
        let (delivered, delivery) = write_batch(
            &mut Terminal {
                writer: &mut terminal,
                room: None,
            },
            &bytes,
            &transition,
            &gate,
            &mut || fence.load(Ordering::SeqCst),
            &mut |count| {
                released.fetch_add(count, Ordering::SeqCst);
                if let Some(announce) = announce.take() {
                    announce.send(()).expect("the takeover is waiting");
                    // Long enough for the takeover to be waiting on the boundary, so that a writer
                    // which let go of it between the piece and the rest of the delimiter would
                    // hand the boundary over with half a delimiter delivered and uncounted.
                    std::thread::sleep(std::time::Duration::from_millis(30));
                }
            },
        );
        let (with_the_application, counted) =
            takeover.join().expect("the takeover thread does not panic");
        let held = taken.lock().expect("the record is not poisoned");

        assert_eq!(
            delivery,
            Delivery::Complete,
            "the terminal takes the whole batch in the end"
        );
        assert_eq!(delivered, bytes.len(), "and every byte of it is delivered");
        assert_eq!(
            counted,
            held.len(),
            "what the takeover counted as delivered already covered every byte the application \
             ends up holding, so none of them can also be reported as discarded"
        );
        assert!(
            with_the_application <= counted,
            "the terminal cannot hold more than was counted: {with_the_application} of {counted}"
        );
        assert!(
            held.ends_with(PASTE_START),
            "the application holds a whole paste start, not half of one"
        );
    }

    #[test]
    fn a_terminal_that_pauses_is_waited_for_rather_than_given_up_on() {
        // An application that stops reading for a moment is an ordinary application. A writer that
        // gave up on one would take the session's whole input path with it: nothing restarts this
        // writer, and input accepted afterwards would be acknowledged and never written.
        let (bytes, transition) = ends_in_a_delimiter();
        let taken = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut terminal = Grudging {
            taken: std::sync::Arc::clone(&taken),
            per_write: WRITE_PIECE_BYTES,
            refuse_until: None,
            refusal: std::time::Duration::from_millis(400),
        };
        let mut written = 0_usize;
        let (delivered, delivery) = write_batch(
            &mut Terminal {
                writer: &mut terminal,
                room: None,
            },
            &bytes,
            &transition,
            &std::sync::Mutex::new(()),
            &mut || false,
            &mut |count| written += count,
        );

        assert_eq!(
            delivery,
            Delivery::Complete,
            "a pause is a pause, not a terminal that has gone"
        );
        assert_eq!(delivered, bytes.len());
        assert_eq!(written, bytes.len(), "and every byte of it is accounted");
        assert_eq!(
            taken.lock().expect("the record is not poisoned").len(),
            bytes.len(),
            "and the application has all of it once it reads again"
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
            &mut Terminal {
                writer: &mut terminal,
                room: None,
            },
            &bytes,
            &PasteTransition::default(),
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
            &mut Terminal {
                writer: &mut terminal,
                room: None,
            },
            b"kr",
            &PasteTransition::default(),
            &std::sync::Mutex::new(()),
            &mut || false,
            &mut |count| written += count,
        );

        assert_eq!(delivery, Delivery::Gone);
        assert_eq!(delivered, 0);
        assert_eq!(written, 0);
    }
}
