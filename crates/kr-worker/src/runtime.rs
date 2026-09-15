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
use crate::session::{CloseAcceptance, DRAIN_PERIOD, GRACE_PERIOD, Session};

/// A running session and the tasks around it.
#[derive(Debug)]
pub struct SessionRuntime {
    session: Arc<Mutex<Session>>,
    input: mpsc::UnboundedSender<Vec<u8>>,
    wake: Arc<Notify>,
    closed: Arc<Notify>,
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
        let session = Arc::new(Mutex::new(session));
        let (input_sender, mut input_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        let (output_sender, mut output_receiver) = mpsc::unbounded_channel::<ReadEvent>();
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
                        let _ = output_sender.send(ReadEvent::Ended);
                        break;
                    }
                    Ok(read) => {
                        if output_sender
                            .send(ReadEvent::Bytes(buffer[..read].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        // A closed terminal reads as an error on some platforms and as end of file
                        // on others. Both mean the shell is gone.
                        let _ = output_sender.send(ReadEvent::Ended);
                        break;
                    }
                }
            }
        });

        std::thread::spawn(move || {
            while let Some(bytes) = input_receiver.blocking_recv() {
                if std::io::Write::write_all(&mut writer, &bytes).is_err() {
                    break;
                }
                let _ = std::io::Write::flush(&mut writer);
            }
        });

        let runtime = Self {
            session: Arc::clone(&session),
            input: input_sender.clone(),
            wake: Arc::clone(&wake),
            closed: Arc::clone(&closed),
        };

        let ingest_session = Arc::clone(&session);
        let ingest_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            while let Some(event) = output_receiver.recv().await {
                match event {
                    ReadEvent::Bytes(bytes) => {
                        if let Ok(mut session) = ingest_session.lock() {
                            session.ingest_output(&bytes);
                        }
                    }
                    ReadEvent::Ended => {
                        // The terminal closed, so the root shell has ended. Its real status comes
                        // from the child itself; the session records the closure either way,
                        // because KalaReach never restarts the shell.
                        if let Ok(mut session) = ingest_session.lock()
                            && session.state() != SessionState::Closed
                        {
                            session.note_terminal_ended();
                        }
                        ingest_closed.notify_waiters();
                        break;
                    }
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
                            for bytes in session.take_pending_input() {
                                let _ = timer_input.send(bytes);
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
        let pending = {
            let mut session = self.session();
            session.take_pending_input()
        };
        for bytes in pending {
            let _ = self.input.send(bytes);
        }
        // A new held prefix needs the timer to look again.
        self.wake.notify_waiters();
    }

    /// Begins closure and returns the acceptance before anything is signalled.
    ///
    /// The grace period, the forced stop and the drain run afterwards, on their own task.
    pub fn close(self: &Arc<Self>, reason: ClosureReason) -> CloseAcceptance {
        let acceptance = {
            let mut session = self.session();
            session.begin_close(reason)
        };
        if acceptance.initiated {
            let runtime = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(GRACE_PERIOD).await;
                let forced = {
                    let mut session = runtime.session();
                    session.force_close().unwrap_or(false)
                };
                tokio::time::sleep(DRAIN_PERIOD).await;
                {
                    let mut session = runtime.session();
                    session.finish_close(forced);
                }
                runtime.closed.notify_waiters();
            });
        }
        acceptance
    }

    /// Waits until the session has finished closing and returns its record.
    pub async fn wait_closed(&self) -> ClosureRecord {
        loop {
            if let Some(record) = self.session().closure().cloned() {
                return record;
            }
            self.closed.notified().await;
        }
    }

    /// Returns the session's current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.session().state()
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
