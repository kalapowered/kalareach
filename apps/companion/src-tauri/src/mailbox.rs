//! This computer reading its own mailbox.
//!
//! A host that carries out a revocation this computer published tells this computer so: it places
//! an announcement that the feed changed in this computer's mailbox at the sync service, beside
//! the acknowledgement it writes to the feed. The feed is the record, and this computer learns
//! what became of its requests from it whether or not it reads the mailbox. What this module does
//! is read the mailbox, take what opens, count the announcements, and say on the screen whether it
//! could.
//!
//! # What this computer takes from its mailbox
//!
//! The rules are the shared reader's ([`kr_client::mailbox_reader`]): an item opens only against
//! the stored-envelope key of a host this computer is paired with, the routing record outside it
//! is untrusted and must match the box, an identifier accepted before is refused, and a payload
//! that bears authority is refused whoever sealed it. An item that opens is written down, and an
//! announcement that a feed changed is counted; nothing else is done with it: the mailbox carries
//! no keystroke, command, decision or closure, and nothing read from it executes anything.
//!
//! # What is kept, and where
//!
//! The identifiers of the items accepted are kept in `mailbox/replay.json` under the application's
//! data directory, each until its item expired and a day more, so that an item the service offers
//! again is taken once. A second window of the application is a second process over the same
//! directory, so a pass holds `mailbox/replay.lock` through the whole pass, and a pass that finds
//! another window holding it does not wait: that window is reading. The record has a most of
//! [`MOST_IDENTIFIERS`]. At that most the reader accepts nothing more and says so, and the items
//! are left on the service unacknowledged; it never forgets an identifier it should keep to make
//! room, because that would let an item in twice. A record of a version this build does not read,
//! or one that cannot be read, is refused and left exactly as found.
//!
//! # When it reads
//!
//! Only when the devices screen reads a feed, which is when this computer owns a host that is not
//! the one on this computer, and the sync service setting names where. A computer that owns no
//! such host contacts nothing. A pass has a time to finish in, which includes taking the lock, and
//! a stop of the mailbox never fails the screen. A pass that the time ends may have written down
//! items it did not count: they stay on record and are refused when the service offers them again,
//! and the count on the screen is short by them. A service that asks to be left alone is left
//! alone for as long as it asked, up to an hour, by a clock that cannot be moved; each service
//! this computer is set to use is held to its own delay.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::ClientError;
use kr_client::mailbox_reader::{Outcome, Page, Reading, Stop, read_mailbox};
use kr_client::services::mailbox::MailboxClient;
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_crypto::envelope::{PairedSenders, ReplayLedger};
use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::MailboxPayloadType;
use kr_protocol::scalars::Uuid;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::recovery::DeviceSigner;
use crate::sync_service::SyncService;

/// The directory the record and its lock are kept in, under the application's data directory.
pub const DIRECTORY: &str = "mailbox";

/// The file of accepted identifiers.
const RECORD: &str = "replay.json";

/// The lock a pass holds, a file of its own because the record is replaced by a rename.
const LOCK: &str = "replay.lock";

/// The record's schema version.
const VERSION: u32 = 1;

/// The most identifiers the record holds.
pub const MOST_IDENTIFIERS: usize = 4096;

/// The most the record may be on disk: well above [`MOST_IDENTIFIERS`] identifiers of the longest
/// form a line takes.
const RECORD_LIMIT: u64 = 1024 * 1024;

/// The time a pass has to finish in, as the screen allows a feed.
const PASS_WITHIN: Duration = Duration::from_secs(20);

/// The longest this computer leaves a service alone because it asked: a service that names more is
/// asked again after this.
const LONGEST_DELAY: Duration = Duration::from_secs(60 * 60);

/// Why the last pass stopped before it read the mailbox through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stopped {
    /// The service could not be reached, did not answer in time, or answered something this
    /// computer cannot read.
    Unreachable,
    /// The service turned a request back for a reason only the person can change.
    Refused,
    /// The service asked to be left alone, and has not finished asking.
    Waiting,
    /// This computer could not read its hosts, take the lock or read its record.
    Records,
    /// The record is full, so nothing more is accepted until its oldest identifiers are due to be
    /// forgotten.
    Full,
}

/// What the screen is told of this computer's reading of its mailbox.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MailboxView {
    /// When the mailbox was last read through, in UTC milliseconds on this computer's clock. Null
    /// when it has not been since the application started.
    pub last_read_ms: Option<u64>,
    /// How many announcements from the hosts this computer is paired with it has taken since the
    /// application started.
    pub announcements: u64,
    /// Why the last pass stopped before it read the mailbox through, when it did.
    pub stopped: Option<Stopped>,
}

/// What a pass left, for the screen.
#[derive(Debug, Default)]
struct Observed {
    view: MailboxView,
}

/// What the record is on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    /// Each accepted identifier, and when it may be forgotten, in UTC milliseconds.
    identifiers: BTreeMap<String, u64>,
}

/// Why the reader's own records failed.
#[derive(Debug)]
enum RecordError {
    /// The hosts or the record could not be read or written.
    Records(String),
    /// The record holds [`MOST_IDENTIFIERS`] that must still be kept.
    Full,
}

/// This computer's reader of its own mailbox.
pub struct MailboxDesk {
    directory: PathBuf,
    device: Arc<Device>,
    sync: Arc<SyncService>,
    /// One pass at a time in this process.
    turn: tokio::sync::Mutex<()>,
    observed: Mutex<Observed>,
    /// Where each service that asked to be left alone has its delay end, on a clock that only moves
    /// forward.
    asked_to_wait: Mutex<BTreeMap<GatewayOrigin, Instant>>,
    /// The time a pass has, in milliseconds.
    within_ms: AtomicU64,
}

impl std::fmt::Debug for MailboxDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailboxDesk")
            .finish_non_exhaustive()
    }
}

impl MailboxDesk {
    /// A desk over the record kept under `data`. The directory is made when a pass first needs it,
    /// so a directory that cannot be made is a stop the screen says, and not a desk that is never
    /// there.
    #[must_use]
    pub fn new(data: &Path, device: Arc<Device>, sync: Arc<SyncService>) -> Self {
        Self {
            directory: data.join(DIRECTORY),
            device,
            sync,
            turn: tokio::sync::Mutex::new(()),
            observed: Mutex::default(),
            asked_to_wait: Mutex::new(BTreeMap::new()),
            within_ms: AtomicU64::new(u64::try_from(PASS_WITHIN.as_millis()).unwrap_or(u64::MAX)),
        }
    }

    /// Sets the time a pass has to finish in, for a suite that holds a request open.
    pub fn finish_within(&self, within: Duration) {
        self.within_ms.store(
            u64::try_from(within.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// What the screen is told now.
    #[must_use]
    pub fn view(&self) -> MailboxView {
        self.observed().view.clone()
    }

    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopped(&self, why: Stopped) -> MailboxView {
        let mut observed = self.observed();
        observed.view.stopped = Some(why);
        observed.view.clone()
    }

    /// Reads the mailbox once, if nobody is reading it and the service has not asked to be left
    /// alone, and says what came of it. It does not fail: a stop is what the screen is told.
    pub async fn pass(&self) -> MailboxView {
        let Ok(_turn) = self.turn.try_lock() else {
            // Another look is reading it now, and what it finds is what this one would.
            return self.view();
        };
        let origin = self.sync.origin();
        if self.must_wait(&origin) {
            return self.stopped(Stopped::Waiting);
        }
        let client = match self.client(&origin) {
            Ok(client) => client,
            Err(_) => return self.stopped(Stopped::Unreachable),
        };
        let within = Duration::from_millis(self.within_ms.load(Ordering::SeqCst));
        let announced = AtomicU64::new(0);
        let now = now_ms();
        let result = tokio::time::timeout(within, self.read(&client, &announced)).await;
        let mut observed = self.observed();
        observed.view.announcements += announced.load(Ordering::SeqCst);
        match result {
            // Another window of the application is reading it, and holds the lock for the pass.
            Ok(Attempt::Skipped) => {}
            Ok(Attempt::Read(Ok(outcome))) => {
                observed.view.stopped = None;
                if outcome == Outcome::ReadThrough {
                    observed.view.last_read_ms = Some(now);
                }
            }
            Ok(Attempt::Read(Err(Stop::Service(error)))) => {
                let why = self.service_stopped(&error, &origin);
                observed.view.stopped = Some(why);
            }
            Ok(Attempt::Read(Err(Stop::Local(RecordError::Full)))) => {
                observed.view.stopped = Some(Stopped::Full);
            }
            Ok(Attempt::Read(Err(Stop::Local(RecordError::Records(error))))) => {
                tracing::warn!(%error, "this computer's mailbox record could not be used");
                observed.view.stopped = Some(Stopped::Records);
            }
            Err(_elapsed) => observed.view.stopped = Some(Stopped::Unreachable),
        }
        observed.view.clone()
    }

    /// Takes the lock and reads the mailbox through the shared reader, counting what it takes in
    /// `announced`, which the caller reads even when it ends this early.
    async fn read(&self, client: &MailboxClient, announced: &AtomicU64) -> Attempt {
        let lock = match self.take_the_lock().await {
            Ok(Some(lock)) => lock,
            Ok(None) => return Attempt::Skipped,
            Err(error) => {
                return Attempt::Read(Err(Stop::Local(RecordError::Records(format!(
                    "the lock could not be taken: {error}"
                )))));
            }
        };
        let reading = Desk {
            desk: self,
            lock,
            announced,
        };
        let key = &self.device.identity().keys.stored_envelope;
        Attempt::Read(read_mailbox(client, key, &reading).await)
    }

    fn client(&self, origin: &GatewayOrigin) -> std::result::Result<MailboxClient, ClientError> {
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )?;
        Ok(MailboxClient::new(
            origin.clone(),
            Arc::new(http),
            Arc::new(DeviceSigner::new(
                self.device.identity().keys.authorisation.clone(),
            )),
        )
        .leaving_delays_to_the_caller())
    }

    /// Whether the service at `origin` asked to be left alone and has not finished asking.
    fn must_wait(&self, origin: &GatewayOrigin) -> bool {
        let mut asked = self
            .asked_to_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        asked.retain(|_, until| *until > now);
        asked.contains_key(origin)
    }

    /// What a refusal or a failure of the service means for the next pass. A delay the service
    /// names is kept for that service, up to [`LONGEST_DELAY`], and not less than what it already
    /// owes.
    fn service_stopped(&self, error: &ClientError, origin: &GatewayOrigin) -> Stopped {
        let ClientError::Refused {
            error: refused,
            retry_after_seconds,
            ..
        } = error
        else {
            return Stopped::Unreachable;
        };
        if let Some(seconds) = retry_after_seconds {
            let delay = Duration::from_secs(*seconds).min(LONGEST_DELAY);
            if let Some(until) = Instant::now().checked_add(delay)
                && !delay.is_zero()
            {
                let mut asked = self
                    .asked_to_wait
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let owed = asked.entry(origin.clone()).or_insert(until);
                *owed = (*owed).max(until);
                return Stopped::Waiting;
            }
        }
        match refused.code {
            ErrorCode::PermissionDenied
            | ErrorCode::InvalidArgument
            | ErrorCode::HostNotConfigured => Stopped::Refused,
            _ => Stopped::Unreachable,
        }
    }

    /// Takes the lock for a pass without waiting: `None` when another window holds it. The record's
    /// directory is made first, and the lock file is opened as a regular file that is not a link,
    /// without waiting for a writer, so a name another program put there cannot hold the pass.
    async fn take_the_lock(&self) -> std::io::Result<Option<Arc<std::fs::File>>> {
        let directory = self.directory.clone();
        tauri::async_runtime::spawn_blocking(move || -> std::io::Result<_> {
            kr_ipc::paths::create_private_directory(&directory)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let file = kr_ipc::paths::open_lock_file(&directory.join(LOCK))?;
            match kr_flush::lock::try_exclusive(&file) {
                Ok(()) => Ok(Some(Arc::new(file))),
                Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                Err(std::fs::TryLockError::Error(error)) => Err(error),
            }
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

/// What one try at a pass came to.
enum Attempt {
    /// Another window of the application holds the lock, and is reading.
    Skipped,
    /// The pass ran.
    Read(std::result::Result<Outcome, Stop<RecordError>>),
}

/// The desk as the shared reader reads it, for one pass that holds the lock.
struct Desk<'a> {
    desk: &'a MailboxDesk,
    /// Held by every blocking step of the pass, so that a step still running when the pass is
    /// dropped keeps the lock until it has finished.
    lock: Arc<std::fs::File>,
    /// What the pass has counted as announcements from a host this computer is paired with.
    announced: &'a AtomicU64,
}

impl Desk<'_> {
    fn record_path(&self) -> PathBuf {
        self.desk.directory.join(RECORD)
    }

    /// Runs `body` on the blocking pool with the lock held.
    async fn blocking<T: Send + 'static>(
        &self,
        body: impl FnOnce(&Path) -> std::result::Result<T, RecordError> + Send + 'static,
    ) -> std::result::Result<T, RecordError> {
        let path = self.record_path();
        let lock = Arc::clone(&self.lock);
        tauri::async_runtime::spawn_blocking(move || {
            let _held = lock;
            body(&path)
        })
        .await
        .map_err(|error| RecordError::Records(error.to_string()))?
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Reads the record at `path`, with every identifier due to be forgotten at `now` gone. A record
/// that is not there is an empty one.
fn load(path: &Path, now: u64) -> std::result::Result<Record, RecordError> {
    let bytes = read_owner_only_file(path, RECORD_LIMIT)
        .map_err(|error| RecordError::Records(format!("the record could not be read: {error}")))?;
    let Some(bytes) = bytes else {
        return Ok(Record {
            version: VERSION,
            identifiers: BTreeMap::new(),
        });
    };
    let mut record: Record = serde_json::from_slice(&bytes)
        .map_err(|error| RecordError::Records(format!("the record is not readable: {error}")))?;
    if record.version != VERSION {
        return Err(RecordError::Records(format!(
            "the record is at version {} and this build reads {VERSION}",
            record.version
        )));
    }
    record.identifiers.retain(|_, until| *until > now);
    Ok(record)
}

impl Reading for Desk<'_> {
    type Error = RecordError;

    fn now_ms(&self) -> u64 {
        now_ms()
    }

    async fn senders(&self) -> std::result::Result<PairedSenders, RecordError> {
        let device = Arc::clone(&self.desk.device);
        tauri::async_runtime::spawn_blocking(move || {
            let hosts = device
                .pairing()
                .hosts
                .list()
                .map_err(|error| RecordError::Records(error.to_string()))?;
            let mut senders = PairedSenders::new();
            for host in hosts {
                senders.pair(host.host_keys.stored_envelope);
            }
            Ok(senders)
        })
        .await
        .map_err(|error| RecordError::Records(error.to_string()))?
    }

    async fn ledger(&self, now_ms: u64) -> std::result::Result<ReplayLedger, RecordError> {
        self.blocking(move |path| {
            let record = load(path, now_ms)?;
            let mut entries = Vec::with_capacity(record.identifiers.len());
            for (text, until) in record.identifiers {
                let id = text.parse::<Uuid>().map(EnvelopeId::new).map_err(|_| {
                    RecordError::Records("the record holds an identifier it cannot read".to_owned())
                })?;
                entries.push((id, until));
            }
            Ok(ReplayLedger::restore(entries))
        })
        .await
    }

    async fn record(
        &self,
        id: EnvelopeId,
        retained_until_ms: u64,
    ) -> std::result::Result<(), RecordError> {
        self.blocking(move |path| {
            let mut record = load(path, now_ms())?;
            let key = id.get().to_string();
            if !record.identifiers.contains_key(&key)
                && record.identifiers.len() >= MOST_IDENTIFIERS
            {
                return Err(RecordError::Full);
            }
            record.identifiers.insert(key, retained_until_ms);
            let bytes = serde_json::to_vec(&record)
                .map_err(|error| RecordError::Records(error.to_string()))?;
            write_owner_only_file(path, &bytes).map_err(|error| {
                RecordError::Records(format!("the record could not be written: {error}"))
            })
        })
        .await
    }

    fn taken(&self, page: Page) {
        let announcements = page
            .accepted
            .iter()
            .filter(|item| item.payload_type == MailboxPayloadType::AuthorityFeedChange)
            .count();
        self.announced
            .fetch_add(announcements as u64, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-20.05: an identifier is kept until the moment its retention ends, which is the item's
    /// expiry and a day more, and forgotten when it has. The record is read at the moment that
    /// matters, which a case that runs against the clock of the day cannot reach.
    #[test]
    fn an_identifier_is_kept_until_the_moment_its_retention_ends() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join(RECORD);
        let until = 1_000_000_000_u64;
        let record = Record {
            version: VERSION,
            identifiers: BTreeMap::from([(Uuid::from_bytes([7; 16]).to_string(), until)]),
        };
        write_owner_only_file(&path, &serde_json::to_vec(&record).expect("a record"))
            .expect("the record is written");

        assert_eq!(
            load(&path, until - 1).expect("a record").identifiers.len(),
            1,
            "kept a millisecond before its retention ends"
        );
        assert!(
            load(&path, until).expect("a record").identifiers.is_empty(),
            "forgotten when its retention ends"
        );
    }
}
