//! Writing the record of what a session owns, off the session's lock.
//!
//! The record changes as the session runs, on the cadence [`crate::lifecycle`] describes, and the
//! session is locked while it is observed. A write waits for the disk, and the lock is the one
//! input acceptance and the terminal's reader take, so the write is handed to a thread of its own
//! that holds a connection beside the journal's. Only the latest record matters: a record that
//! has been replaced before it was written is dropped, and a record that could not be written is
//! sent again at the next observation, changed or not.
//!
//! The thread ends when the writer is dropped.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_protocol::ids::SessionId;

use crate::ownership::OwnedRecord;

/// How long a write waits for a lock another connection to the journal holds.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// A writer of one session's [`OwnedRecord`].
#[derive(Debug)]
pub struct OwnedWriter {
    session_id: SessionId,
    sender: Sender<OwnedRecord>,
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
        let (sender, receiver) = channel::<OwnedRecord>();
        let failed = Arc::new(AtomicBool::new(false));
        let outcome = Arc::clone(&failed);
        std::thread::Builder::new()
            .name("kr-owned-record".to_owned())
            .spawn(move || {
                let mut connection: Option<rusqlite::Connection> = None;
                while let Ok(mut record) = receiver.recv() {
                    // Only the latest matters.
                    while let Ok(newer) = receiver.try_recv() {
                        record = newer;
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
                    }
                    outcome.store(written.is_err(), Ordering::Release);
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
        if self.sender.send(record.clone()).is_ok() {
            *sent = Some(record);
        }
    }

    /// Returns the session this writer writes for.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}
