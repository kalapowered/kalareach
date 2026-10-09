//! Writing the record of what a session owns, off the session's lock.
//!
//! The record changes as the session runs, on the cadence [`crate::lifecycle`] describes, and the
//! session is locked while it is observed. A write waits for the disk, and the lock is the one
//! input acceptance and the terminal's reader take, so the write is handed to a thread of its own
//! that holds a connection beside the journal's. Only the latest record matters: a record that
//! has been replaced before it was written is dropped.
//!
//! A record that could not be written is tried again by the thread, a second after each refused
//! attempt, until the journal takes it or a newer record replaces it. The record is what a crash's
//! cleanup acts on, and an idle session is observed only on the sweep, so waiting for the next
//! observation would leave a stall of the journal's a sweep long in what the cleanup knows. A
//! record that could not be written is also sent again at the next observation, changed or not.
//!
//! A record can be handed over with a request to be told whether it was written
//! ([`OwnedWriter::submit_acknowledged`]): a caller that must not go on until the record is on
//! disk waits for the answer outside the session's lock.
//!
//! The thread ends when the writer is dropped.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::oneshot;

use kr_protocol::ids::SessionId;

use crate::ownership::OwnedRecord;

/// How long a write waits for a lock another connection to the journal holds.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the thread waits before it tries again a record the journal refused.
const RETRY: Duration = Duration::from_secs(1);

/// A writer of one session's [`OwnedRecord`].
#[derive(Debug)]
pub struct OwnedWriter {
    session_id: SessionId,
    sender: Sender<(OwnedRecord, Option<oneshot::Sender<bool>>)>,
    /// The record last handed to the thread, so an unchanged one is not sent again.
    sent: Mutex<Option<OwnedRecord>>,
    /// Whether the thread's last write failed.
    failed: Arc<AtomicBool>,
}

impl OwnedWriter {
    /// Starts a writer for the journal at `path`.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure when the thread cannot be started.
    pub fn start(path: PathBuf, session_id: SessionId) -> std::io::Result<Self> {
        let (sender, receiver) = channel::<(OwnedRecord, Option<oneshot::Sender<bool>>)>();
        let failed = Arc::new(AtomicBool::new(false));
        let outcome = Arc::clone(&failed);
        std::thread::Builder::new()
            .name("kr-owned-record".to_owned())
            .spawn(move || {
                let mut connection: Option<rusqlite::Connection> = None;
                // The record the journal refused, until it takes it or a newer one comes.
                let mut refused: Option<OwnedRecord> = None;
                loop {
                    // The callers that asked to be told what became of the record they handed over.
                    let mut acknowledge: Vec<oneshot::Sender<bool>> = Vec::new();
                    let mut record = match refused.take() {
                        Some(refused) => match receiver.recv_timeout(RETRY) {
                            Ok((newer, asked)) => {
                                acknowledge.extend(asked);
                                newer
                            }
                            Err(RecvTimeoutError::Timeout) => refused,
                            Err(RecvTimeoutError::Disconnected) => return,
                        },
                        None => match receiver.recv() {
                            Ok((record, asked)) => {
                                acknowledge.extend(asked);
                                record
                            }
                            Err(_) => return,
                        },
                    };
                    // Only the latest matters, and every caller that asked to be told is told
                    // what became of it.
                    while let Ok((newer, asked)) = receiver.try_recv() {
                        record = newer;
                        acknowledge.extend(asked);
                    }
                    let written = (|| -> rusqlite::Result<()> {
                        if connection.is_none() {
                            let opened = rusqlite::Connection::open(&path)?;
                            opened.busy_timeout(BUSY_TIMEOUT)?;
                            opened.pragma_update(None, "synchronous", "FULL")?;
                            connection = Some(opened);
                        }
                        let connection = connection.as_ref().expect("opened above");
                        crate::journal::write_owned(connection, session_id, &record)
                    })();
                    if written.is_err() {
                        connection = None;
                        refused = Some(record);
                    }
                    outcome.store(written.is_err(), Ordering::Release);
                    for asked in acknowledge {
                        let _ = asked.send(written.is_ok());
                    }
                }
            })?;
        Ok(Self {
            session_id,
            sender,
            sent: Mutex::new(None),
            failed,
        })
    }

    /// Hands the thread `record`, unless it is the one last handed and that was written.
    pub fn submit(&self, record: OwnedRecord) {
        let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        if sent.as_ref() == Some(&record) && !self.failed.load(Ordering::Acquire) {
            return;
        }
        if self.sender.send((record.clone(), None)).is_ok() {
            *sent = Some(record);
        }
    }

    /// Whether the thread's last attempt to write failed, for the host's own tests. It compiles to
    /// nothing without the `testing` feature.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn last_write_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Hands the thread `record` and returns what says whether it was written.
    ///
    /// The record is sent whether or not it is the one last handed: a caller that waits for the
    /// answer needs a write that happened after it asked. `true` means that this record, or a
    /// later one that replaced it in the queue before it was written, is on disk; a later record
    /// of the same session names everything this one does that still runs. The answer is `false`
    /// when the write failed: the thread then tries the record again, but the answer is not given
    /// twice. The receiver is dropped unanswered only if the thread has ended, which the caller
    /// reads as a record that was not written.
    #[must_use]
    pub fn submit_acknowledged(&self, record: OwnedRecord) -> oneshot::Receiver<bool> {
        let (answer, receiver) = oneshot::channel();
        let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        if self.sender.send((record.clone(), Some(answer))).is_ok() {
            *sent = Some(record);
        }
        receiver
    }

    /// Returns the session this writer writes for.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}
