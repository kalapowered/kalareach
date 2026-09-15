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
    CloseAcceptance, DRAIN_PERIOD, GRACE_PERIOD, InputBatch, InputOrigin, Session,
};

/// How many read batches may wait for ingestion before the read loop slows down.
pub const READ_QUEUE_DEPTH: usize = 64;

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
        let host_replies = session.host_reply_bytes();
        let session = Arc::new(Mutex::new(session));
        let (input_sender, mut input_receiver) = mpsc::unbounded_channel::<InputBatch>();
        // What the writer compares every batch against. A takeover, a release, a detach or a close
        // moves the session's lease epoch, and this is how that reaches bytes already handed over.
        let fence = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // Bounded on purpose. Section 9 says a slow *client* must never hold the read loop, and it
        // also says the worker honours the operating system's own backpressure when parsing itself
        // cannot keep up, and never drops parser input. A bounded handoff does both: clients are
        // decoupled by their own queues, and a worker that cannot ingest stops reading rather than
        // growing without limit or discarding bytes.
        let (output_sender, mut output_receiver) = mpsc::channel::<ReadEvent>(READ_QUEUE_DEPTH);
        let wake = Arc::new(Notify::new());
        let closed = Arc::new(Notify::new());

        // The read loop runs on a blocking thread because the terminal's reader is a blocking
        // descriptor. It sends what it read and immediately reads again.
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                match std::io::Read::read(&mut reader, &mut buffer) {
                    Ok(0) => {
                        let _ = output_sender.blocking_send(ReadEvent::Ended);
                        break;
                    }
                    Ok(read) => {
                        if output_sender
                            .blocking_send(ReadEvent::Bytes(buffer[..read].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        // A closed terminal reads as an error on some platforms and as end of file
                        // on others. Either way the terminal is finished; whether the root shell
                        // ended is decided by the child monitor, not by this read.
                        let _ = output_sender.blocking_send(ReadEvent::Ended);
                        break;
                    }
                }
            }
        });

        let writer_fence = Arc::clone(&fence);
        let writer_replies = Arc::clone(&host_replies);
        std::thread::spawn(move || {
            while let Some(batch) = input_receiver.blocking_recv() {
                let released = match batch.origin {
                    InputOrigin::Host => batch.bytes.len(),
                    InputOrigin::Lease(_) => 0,
                };
                // Stale keystrokes are dropped here rather than written. A takeover that only
                // stopped *new* input would still let the previous holder's last keystrokes land in
                // the new holder's command line. The host's own answer to a query the application
                // asked is not a keystroke and is never dropped: nothing else can supply it.
                if let InputOrigin::Lease(epoch) = batch.origin
                    && epoch < writer_fence.load(std::sync::atomic::Ordering::Acquire)
                {
                    continue;
                }
                if std::io::Write::write_all(&mut writer, &batch.bytes).is_err() {
                    break;
                }
                let _ = std::io::Write::flush(&mut writer);
                // Released only once the application has it. Until then it is still owed.
                if released > 0 {
                    let _ = writer_replies.fetch_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |held| Some(held.saturating_sub(released)),
                    );
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
        // the order bytes reach the terminal in is the order they were accepted in.
        self.fence
            .store(session.input_fence(), std::sync::atomic::Ordering::Release);
        self.send_input(pending);
    }

    /// Writes the batches a caller produced while it was holding the session.
    ///
    /// The fence moves first, so a batch the caller's own operation invalidated is dropped by the
    /// writer rather than written.
    pub fn flush_locked(&self, session: &mut Session) {
        let pending = session.take_pending_input();
        self.fence
            .store(session.input_fence(), std::sync::atomic::Ordering::Release);
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
    /// It is the published half of [`Session::input_fence`]: a lease change that has not reached
    /// here is a change bytes already handed to the writer do not know about yet.
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
