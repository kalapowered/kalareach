//! The files this device sends to a host it is paired with, from the first byte to the handle, and
//! what is kept of each across a restart.
//!
//! An upload outlives the command that starts it. The [`Desk`] owns it between commands: the
//! plan's subject, the content, the progress the driver publishes, and the handle that stops it.
//! A command waits on the upload's outcome and may be dropped; the upload goes on. A connection
//! that ends pauses it, and the next connection to the host, through [`Desk::host_reached`],
//! resumes it with [`Upload::resuming`] under the same transfer identifier, after the content it
//! describes has been read again and found to be the one declared.
//!
//! * **One layout, version 1.** `open-transfers/` holds `<key>.upload` (what the entry is for, the
//!   transfer identifier once the host gave one, how far the transfer got and the handle once it is
//!   published) and `<key>.bytes` (a copy of a file the page handed over as bytes, raw). Every
//!   entry file is JSON with exactly the members it names. An entry file with another `version`, a
//!   member more or fewer, or a name that is not its key is counted and left, never read or changed,
//!   and neither is the copy that goes with it, because a later release may own both.
//! * **A key and a place are reserved before anything is sent.** The desk holds one lock from the
//!   check of the count and the key to the insert of the upload, so no key is used twice and no
//!   third upload is admitted.
//! * **Written before the call that needs it.** The driver tells the upload journal that it is
//!   about to ask for a reservation, what the transfer identifier is, and that it is about to send
//!   the finish, each before the call; a write that fails stops the send before the call, and a
//!   transfer identifier the host gave is held in memory until it is kept.
//! * **A restart reads before it acts.** The host is asked for the state of every entry first.
//!   A published upload keeps its handle and is never cancelled; one the host still receives
//!   resumes with exactly what the host lacks when the content is still here and its digest is the
//!   one declared; one the host does not know (and only that answer), or has ended, is dropped; and
//!   a reservation whose answer never came cannot be found again, which the entry says.
//! * **A copy ends with its entry.** It is removed when the upload is published, cancelled or
//!   dropped, when it is found unrecoverable, when the host is forgotten, when no entry of any
//!   layout names it, and a copy that a stopped process left half written is removed at the next
//!   reach.
//! * **Missing, stale and rolled back.** An application that finds no folder has no entry to
//!   resume, which is how a release before this one behaves. An entry names the host, the device
//!   and the content's digest it describes, and is acted on only against that host and that
//!   device; an entry of another device of the same host is dropped with its copy. A release
//!   before this one leaves the folder alone; the host ends what it holds after its own
//!   twenty-four hours.

use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures_util::FutureExt as _;
use kr_client::chunks::ChunkRoute;
use kr_client::services::AccountMark;
use kr_client::uploads::{self, Content, Held, Journal, Progress, Stage, Subject, Upload};
use kr_client::{ClientError, Session};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DeviceId, EnvironmentId, SessionId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Uuid};
use kr_protocol::transfer::{
    AttachmentHandle, UploadCancelResult, UploadState, UploadStatusParams, UploadStatusResult,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::error::{CommandError, Result};

/// The format of an entry this build writes, recorded in it as `version`.
pub const STORE_VERSION: u32 = 1;

/// The most uploads a device holds open on one host at a time: the host's own bound.
pub const MOST_OPEN: usize = 2;

/// The largest entry file this build reads.
const ENTRY_LIMIT: u64 = 1024 * 1024;

const UPLOAD_EXTENSION: &str = "upload";
const COPY_EXTENSION: &str = "bytes";

/// What a third open upload is refused with.
pub const TOO_MANY_OPEN: &str =
    "two files are open on this host already: wait for one to finish, or cancel one";

/// What a transfer key that an open upload holds is refused with.
pub const KEY_IN_USE: &str = "an upload with that transfer key is open already";

/// What an entry says when the content to send on is gone or is not what was declared.
pub const CANNOT_RESUME: &str = "this file cannot be resumed from where it stopped, because the copy this device kept is gone or has changed: cancel it and send the file again";

/// What an entry says when the host was asked for a reservation and its answer never came.
pub const UNRECOVERABLE: &str = "this device asked the host to take this file and did not get its answer: if the host agreed, it keeps the place for up to 24 hours and then releases it";

/// What the command that waited for an upload is told when the person cancelled it.
pub const CANCELLED: &str = "this file was cancelled before it was sent in full";

/// A cancel names no upload this device holds, or one that is another account's.
pub const NO_OPEN_UPLOAD: &str = "no open upload has that key";

/// The directory the entries are kept in, under an application data directory.
#[must_use]
pub fn kept_in(data: &Path) -> PathBuf {
    data.join("open-transfers")
}

/// How far an upload got, as the entry records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Reached {
    /// The reservation is being or was asked for.
    Beginning,
    /// The host gave the transfer identifier.
    Begun,
    /// The finish is being or was sent.
    Finishing,
    /// The handle is published.
    Published,
}

/// Where the content to send comes from after a restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Source {
    /// A copy in this folder, for a file the page handed over as bytes.
    Copy,
    /// A file on this device that is read from where it is.
    Path { path: PathBuf },
}

/// What the page is told is kept for a file, and what the entry is for.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UploadFile {
    version: u32,
    key: Uuid,
    /// The host's environment and this device's principal on it.
    environment_id: EnvironmentId,
    device_id: DeviceId,
    /// On a host whose grant answers to an organisation, the account that was signed in when the
    /// file was kept (the mark of the account, as text): a new sign-in does not change the device's
    /// principal, so another account's entry is told apart by this. None on a host with no
    /// organisation.
    account: Option<String>,
    /// What the upload's calls are made on.
    target: ActionTarget,
    session_id: Option<SessionId>,
    media_type: String,
    file_name: String,
    /// What the content is declared to be.
    byte_len: u64,
    digest: Digest256,
    source: Source,
    reached: Reached,
    transfer_id: Option<TransferId>,
    handle: Option<AttachmentHandle>,
    /// The person cancelled it and the host's answer is not yet known: the next reach finishes
    /// the cancel and never resumes the upload.
    cancel_asked: bool,
}

/// The folder of entries and what is done to it.
#[derive(Clone, Debug)]
struct Store {
    root: PathBuf,
}

/// What a read of the folder found.
struct Found {
    entries: Vec<UploadFile>,
    /// Keys of `<key>.upload` files of another layout, left alone with their copies.
    unreadable: Vec<Uuid>,
    /// Files that are not this layout's and are not named by a key, left alone.
    left: usize,
    /// Copies that no entry file names, of any layout.
    orphans: Vec<Uuid>,
    /// Copies of entries that are over or cannot be resumed: published, or never given an identifier.
    spent: Vec<Uuid>,
    /// Files a process that stopped was writing.
    staged: Vec<PathBuf>,
    /// Keys that have a copy.
    copies: Vec<Uuid>,
}

impl Found {
    fn holds(&self, key: Uuid) -> bool {
        self.entries.iter().any(|file| file.key == key)
            || self.unreadable.contains(&key)
            || self.copies.contains(&key)
    }
}

impl Store {
    fn path(&self, key: Uuid, extension: &str) -> PathBuf {
        self.root.join(format!("{key}.{extension}"))
    }

    fn write(&self, file: &UploadFile) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let bytes = serde_json::to_vec(file).map_err(std::io::Error::other)?;
        crate::drafts::publish(&self.path(file.key, UPLOAD_EXTENSION), &bytes, || Ok(()))
            .map_err(|fault| fault.error)
    }

    fn write_copy(&self, key: Uuid, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        crate::drafts::publish(&self.path(key, COPY_EXTENSION), bytes, || Ok(()))
            .map_err(|fault| fault.error)
    }

    fn read_copy(&self, key: Uuid) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(key, COPY_EXTENSION))
    }

    /// Removes the copy of `key`, proving the removal durable.
    fn remove_copy(&self, key: Uuid) -> std::io::Result<()> {
        crate::drafts::remove_durably(&self.path(key, COPY_EXTENSION))
    }

    /// Removes the entry of `key` and its copy.
    fn remove(&self, key: Uuid) -> std::io::Result<()> {
        crate::drafts::remove_durably(&self.path(key, UPLOAD_EXTENSION))?;
        self.remove_copy(key)
    }

    /// The entry of `key`, when there is one of this layout.
    fn entry(&self, key: Uuid) -> Option<UploadFile> {
        read_entry(&self.path(key, UPLOAD_EXTENSION), key)
    }

    fn all(&self) -> Found {
        let mut found = Found {
            entries: Vec::new(),
            unreadable: Vec::new(),
            left: 0,
            orphans: Vec::new(),
            spent: Vec::new(),
            staged: Vec::new(),
            copies: Vec::new(),
        };
        let Ok(listing) = std::fs::read_dir(&self.root) else {
            return found;
        };
        for item in listing.flatten() {
            let path = item.path();
            let name = item.file_name().to_string_lossy().into_owned();
            if let Some((_, staged)) = name.rsplit_once(".staged-") {
                // Written by a process that is not this one and never renamed.
                let by = staged.split('-').next().unwrap_or_default();
                if by != std::process::id().to_string() {
                    found.staged.push(path);
                } else {
                    found.left += 1;
                }
                continue;
            }
            let (Some(stem), Some(extension)) = (
                path.file_stem().and_then(|stem| stem.to_str()),
                path.extension().and_then(|extension| extension.to_str()),
            ) else {
                found.left += 1;
                continue;
            };
            let Ok(key) = stem.parse::<Uuid>() else {
                found.left += 1;
                continue;
            };
            match extension {
                COPY_EXTENSION => found.copies.push(key),
                // The drafts kept beside the uploads are another module's.
                "draft" => {}
                UPLOAD_EXTENSION => match read_entry(&path, key) {
                    Some(file) => found.entries.push(file),
                    None => {
                        found.left += 1;
                        found.unreadable.push(key);
                    }
                },
                _ => found.left += 1,
            }
        }
        found.entries.sort_by_key(|file| file.key);
        for key in &found.copies {
            match found.entries.iter().find(|file| file.key == *key) {
                None if !found.unreadable.contains(key) => found.orphans.push(*key),
                Some(file)
                    if file.reached == Reached::Published
                        || (file.reached == Reached::Beginning && file.transfer_id.is_none()) =>
                {
                    found.spent.push(*key);
                }
                _ => {}
            }
        }
        found
    }
}

/// The entry at `path` when it is one of version 1 named by `key`.
fn read_entry(path: &Path, key: Uuid) -> Option<UploadFile> {
    let length = std::fs::metadata(path).ok()?.len();
    if length > ENTRY_LIMIT {
        return None;
    }
    let file: UploadFile = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    (file.version == STORE_VERSION && file.key == key).then_some(file)
}

/// Content that several tasks of one upload share, so that a resume reads what the first send read.
#[derive(Debug)]
struct Shared(Arc<dyn Content>);

impl Content for Shared {
    fn byte_len(&self) -> u64 {
        self.0.byte_len()
    }

    fn digest(&self) -> Digest256 {
        self.0.digest()
    }

    fn read_at(&self, offset: u64, len: u64) -> kr_client::Result<Vec<u8>> {
        self.0.read_at(offset, len)
    }
}

/// How an upload's command ends.
#[derive(Clone, Debug)]
enum Outcome {
    Published(Box<AttachmentHandle>),
    Failed(CommandError),
    Cancelled,
}

/// Where an upload stands in the desk: admitted and waiting for its first start, sending, or
/// waiting for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Held by the desk, no sender yet, and no entry written.
    Admitted,
    Sending,
    /// Its sender was stopped and its owner has not yet ended it or removed its entry. No start is
    /// accepted from here, so a reach between the stop and the removal cannot send what is being
    /// removed. A cancel that cannot be finished sets `Paused` again; its key is cancelled, so
    /// nothing starts from there either.
    Stopping,
    Paused,
}

/// Whose an upload is, fixed when it is admitted, so that the gate reads it without taking the
/// entry the sender is writing.
struct Owner {
    device_id: DeviceId,
    environment_id: EnvironmentId,
    account: Option<String>,
}

impl Owner {
    fn of(file: &UploadFile) -> Self {
        Self {
            device_id: file.device_id,
            environment_id: file.environment_id,
            account: file.account.clone(),
        }
    }

    fn is_whose(&self, who: &Who) -> bool {
        owned_by(
            self.device_id,
            self.environment_id,
            self.account.as_deref(),
            who,
        )
    }
}

/// One upload this process holds.
struct Live {
    key: Uuid,
    owner: Owner,
    /// Whether the entry says the handle is published; kept in step with it by [`Live::change`]
    /// and [`Live::adopt`], so that the gate reads it without taking the entry.
    published: AtomicBool,
    /// How many senders this upload has had. A sender ends or pauses the upload only while the
    /// number is the one it was started under; a stop moves it on.
    generation: AtomicU64,
    file: Mutex<UploadFile>,
    content: Mutex<Arc<dyn Content>>,
    progress: watch::Sender<Progress>,
    outcome: watch::Sender<Option<Outcome>>,
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    phase: Mutex<Phase>,
    /// The reservation was kept as asked for: whatever the answer, a new plan may not ask again.
    beginning_kept: AtomicBool,
    /// The transfer identifier the host gave, held here until the entry has kept it.
    issued: Mutex<Option<TransferId>>,
    /// A write of the entry failed: the failure is this device's, never the host's.
    journal_failed: AtomicBool,
    /// This upload asked once for the places other accounts of the device hold, and does not ask
    /// again: the freeing is tried once for each upload, whatever the answer.
    places_asked: AtomicBool,
    /// Whether the entry says the cancel was asked; kept in step with it by [`Live::change`] and
    /// [`Live::adopt`], so that the gate reads it without taking the entry. A start refuses an
    /// upload that carries it.
    cancel_asked: AtomicBool,
    /// The highest number of a connection that a reach went by while this upload was held and not
    /// paused: the reach could not start it, and the decision that leaves it paused reads this.
    reached: AtomicU64,
    /// The number of the connection its sender was started on.
    sent_link: AtomicU64,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Live {
    fn new(file: UploadFile, content: Arc<dyn Content>, beginning_kept: bool) -> Arc<Self> {
        Arc::new(Self {
            key: file.key,
            owner: Owner::of(&file),
            cancel_asked: AtomicBool::new(file.cancel_asked),
            reached: AtomicU64::new(0),
            sent_link: AtomicU64::new(0),
            published: AtomicBool::new(file.reached == Reached::Published),
            generation: AtomicU64::new(0),
            file: Mutex::new(file),
            content: Mutex::new(content),
            progress: watch::channel(Progress::default()).0,
            outcome: watch::channel(None).0,
            task: Mutex::new(None),
            phase: Mutex::new(Phase::Admitted),
            beginning_kept: AtomicBool::new(beginning_kept),
            issued: Mutex::new(None),
            journal_failed: AtomicBool::new(false),
            places_asked: AtomicBool::new(false),
        })
    }

    fn file(&self) -> UploadFile {
        locked(&self.file).clone()
    }

    /// The transfer the host gave, whether or not the entry could keep it.
    fn transfer(&self) -> Option<TransferId> {
        locked(&self.file).transfer_id.or(*locked(&self.issued))
    }

    fn change(&self, store: &Store, change: impl FnOnce(&mut UploadFile)) -> std::io::Result<()> {
        let mut file = locked(&self.file);
        let mut next = file.clone();
        change(&mut next);
        store.write(&next)?;
        self.published
            .store(next.reached == Reached::Published, Ordering::Release);
        self.cancel_asked
            .store(next.cancel_asked, Ordering::Release);
        *file = next;
        Ok(())
    }

    /// Takes `next` as the entry, as it was written by the one that holds the key's turn.
    fn adopt(&self, next: UploadFile) {
        self.published
            .store(next.reached == Reached::Published, Ordering::Release);
        self.cancel_asked
            .store(next.cancel_asked, Ordering::Release);
        *locked(&self.file) = next;
    }
}

/// What the driver tells, kept before the call that needs it.
struct Kept {
    live: Arc<Live>,
    store: Store,
}

fn not_kept(error: &std::io::Error) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        format!("this device could not keep a record of the upload: {error}"),
    ))
}

impl Kept {
    fn kept(&self, change: impl FnOnce(&mut UploadFile)) -> kr_client::Result<()> {
        match self.live.change(&self.store, change) {
            Ok(()) => {
                // A write that succeeds after a failed one ends the failure.
                self.live.journal_failed.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.live.journal_failed.store(true, Ordering::Release);
                Err(not_kept(&error))
            }
        }
    }
}

impl Journal for Kept {
    fn beginning(&self) -> kr_client::Result<()> {
        #[cfg(feature = "testing")]
        testing::pause(
            self.live.key,
            testing::Point::Writing(testing::Step::Beginning),
        );
        self.kept(|file| file.reached = Reached::Beginning)?;
        self.live.beginning_kept.store(true, Ordering::Release);
        Ok(())
    }

    fn begun(&self, transfer_id: TransferId) -> kr_client::Result<()> {
        // The host's answer is held first: a write that fails loses nothing the host holds.
        *locked(&self.live.issued) = Some(transfer_id);
        #[cfg(feature = "testing")]
        testing::pause(self.live.key, testing::Point::Writing(testing::Step::Begun));
        self.kept(|file| {
            file.transfer_id = Some(transfer_id);
            file.reached = Reached::Begun;
        })
    }

    fn finishing(&self, transfer_id: TransferId) -> kr_client::Result<()> {
        #[cfg(feature = "testing")]
        testing::pause(
            self.live.key,
            testing::Point::Writing(testing::Step::Finishing),
        );
        self.kept(|file| {
            file.transfer_id = Some(transfer_id);
            file.reached = Reached::Finishing;
        })
    }

    fn published(&self, handle: &AttachmentHandle) -> kr_client::Result<()> {
        let handle = handle.clone();
        self.kept(|file| {
            file.handle = Some(handle);
            file.reached = Reached::Published;
        })?;
        // The bytes are the host's now; the handle is what this entry keeps. A copy that cannot be
        // removed now is removed at the next reach, and is no reason to fail a published upload.
        let _ = self.store.remove_copy(locked(&self.live.file).key);
        #[cfg(feature = "testing")]
        testing::pause(
            self.live.key,
            testing::Point::Writing(testing::Step::Published),
        );
        Ok(())
    }
}

/// The host and the connection an upload is sent on.
#[derive(Clone)]
pub struct Paired {
    /// This device's principal on the host.
    pub device_id: DeviceId,
    /// The host's environment.
    pub environment_id: EnvironmentId,
    /// The account signed in, on a host whose grant answers to an organisation; none on another.
    pub account: Option<AccountMark>,
    /// The connection.
    pub session: Arc<Session>,
    /// The number the contact owner installed the connection as: the order of the installations of
    /// one owner, which no emptied slot and no replacement lowers or repeats.
    pub link: u64,
}

impl Paired {
    /// The account as an entry keeps it.
    #[must_use]
    pub fn account_id(&self) -> Option<String> {
        self.account.map(AccountMark::to_hex)
    }

    /// Whether this connection is `who`'s: the principal, the environment where `who` names one, and
    /// the account.
    #[must_use]
    pub fn answers_to(&self, who: &Who) -> bool {
        owned_by(
            self.device_id,
            self.environment_id,
            self.account_id().as_deref(),
            who,
        )
    }

    /// Whose uploads this connection reads.
    #[must_use]
    pub fn who(&self) -> Who {
        Who {
            device_id: self.device_id,
            environment_id: Some(self.environment_id),
            account: self.account,
        }
    }
}

/// Whose uploads are read: this device's principal on a host and the account signed in there. A
/// read needs no connection, so the host's environment, which a connection states, may be unknown.
#[derive(Clone, Debug)]
pub struct Who {
    /// This device's principal on the host.
    pub device_id: DeviceId,
    /// The host's environment, when a connection says it.
    pub environment_id: Option<EnvironmentId>,
    /// The account signed in, on a host whose grant answers to an organisation; none on another.
    pub account: Option<AccountMark>,
}

impl UploadFile {
    /// Whether the entry is this device's own on `paired`'s host, kept under the sign-in in force.
    fn is_of(&self, paired: &Paired) -> bool {
        self.is_whose(&paired.who())
    }

    /// Whether the entry is `who`'s.
    fn is_whose(&self, who: &Who) -> bool {
        owned_by(
            self.device_id,
            self.environment_id,
            self.account.as_deref(),
            who,
        )
    }
}

/// Whether an upload kept for `device_id` on `environment_id` under `account` is `who`'s.
fn owned_by(
    device_id: DeviceId,
    environment_id: EnvironmentId,
    account: Option<&str>,
    who: &Who,
) -> bool {
    device_id == who.device_id
        && who
            .environment_id
            .is_none_or(|wanted| wanted == environment_id)
        && account == who.account.map(AccountMark::to_hex).as_deref()
}

/// What kept content is a copy of.
pub enum Keeping {
    /// The bytes, to be copied into the store folder.
    Copy(Vec<u8>),
    /// A file read from where it is.
    Path(PathBuf),
}

/// One upload to send.
pub struct Request {
    /// What the page calls it by; a UUID.
    pub key: Uuid,
    /// What the calls are made on.
    pub target: ActionTarget,
    /// The session the upload is for.
    pub session_id: Option<SessionId>,
    /// What is sent.
    pub content: Arc<dyn Content>,
    /// The file's name.
    pub name: String,
    /// The media type it is declared as.
    pub media_type: String,
    /// What is kept to send it on after a restart.
    pub keeping: Keeping,
}

/// What one open upload is, as the page reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OpenState {
    /// Chunks are going out.
    Sending,
    /// The connection ended; the upload resumes when the host is reached again.
    Paused,
    /// Kept from before, and the host has not been asked about it yet.
    Waiting,
    /// The handle is published and not yet bound to a draft.
    Published,
    /// The host receives it and the content to send on is gone or changed.
    CannotResume,
    /// The reservation's answer never came.
    Unrecoverable,
    /// The host refused it for good and still holds the reservation until it is cancelled.
    Failed,
    /// The person cancelled it and the cancel is not finished: no more of it is sent, and the next
    /// reach of the host finishes the cancel.
    CancelAsked,
}

/// One open upload, as `transfers_open` answers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenView {
    /// What the upload is called to the commands.
    pub key: String,
    /// Where it stands.
    pub state: OpenState,
    /// The session the file is for, when it is for one.
    pub session_id: Option<String>,
    /// The file's name.
    pub file_name: String,
    /// Its size.
    pub byte_len: u64,
    /// The chunks the host has acknowledged.
    pub acknowledged_chunks: u64,
    /// The chunks the file has.
    pub chunks: u64,
    /// What the driver is doing, while it runs.
    pub stage: Option<&'static str>,
    /// The handle, once it is published.
    pub handle: Option<AttachmentHandle>,
    /// The words that say what is wrong, when something is.
    pub said: Option<String>,
}

/// What a cancel did, from the host's answer.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancelled {
    /// What was asked to be cancelled.
    pub key: String,
    /// `cancelled` when the host released the reservation, `published` when the upload was already
    /// finished and is kept, `forgotten` when the host holds nothing this device can name, `asked`
    /// when the cancel is kept to be finished at the next reach of the host.
    pub state: &'static str,
    /// The bytes the host released, from its answer.
    pub released_byte_len: Option<String>,
    /// The handle, for a `published` upload.
    pub handle: Option<AttachmentHandle>,
    /// For `asked`, the words that say why the cancel is not finished, when something went wrong.
    pub said: Option<String>,
}

/// The tasks the desk starts for itself, counted so that a suite can wait until none is left.
#[derive(Default)]
struct Work {
    running: AtomicUsize,
    over: tokio::sync::Notify,
}

/// One task of the desk while it lives: it is counted out when it ends, however it ends.
struct Counted(Arc<Work>);

impl Drop for Counted {
    fn drop(&mut self) {
        if self.0.running.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.over.notify_waiters();
        }
    }
}

impl Work {
    fn spawn(self: &Arc<Self>, task: impl std::future::Future<Output = ()> + Send + 'static) {
        self.running.fetch_add(1, Ordering::AcqRel);
        let counted = Counted(Arc::clone(self));
        tauri::async_runtime::spawn(async move {
            let _counted = counted;
            task.await;
        });
    }
}

/// A connection to a host, with the account it was made for. An upload goes on a connection only
/// when the connection's account is the upload's, so a connection a newer sign-in brought up is
/// never used to resume what an earlier sign-in left.
#[derive(Clone)]
struct Connection {
    account: Option<String>,
    session: Arc<Session>,
    /// The number the contact owner installed it as.
    link: u64,
}

impl Connection {
    fn of(paired: &Paired) -> Self {
        Self {
            account: paired.account_id(),
            session: Arc::clone(&paired.session),
            link: paired.link,
        }
    }
}

/// What the desk made of a connection it was told of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observed {
    /// No newer connection is known: it is the newest, or the same one again.
    Fresh,
    /// The desk knows a newer connection already.
    Stale,
}

/// The newest connection the desk was told of for one host's device.
///
/// The order of connections is the order of their installation, the number the contact owner gave
/// each. An operation that carries the connection it read a moment before, a send, can arrive after
/// the desk was told of a newer one, however the reports interleave, and a connection that the desk
/// was never told of cannot make an older one the newest: only a higher number does.
#[derive(Default)]
struct Connections {
    newest: Option<Connection>,
}

impl Connections {
    /// The desk is told of `connection`. A higher number than the newest's makes it the newest; the
    /// same number is the same connection, which has one account, so the first record stays; a
    /// lower number is a report about a connection the owner has replaced.
    fn observe(&mut self, connection: Connection) -> Observed {
        match &self.newest {
            Some(newest) if connection.link < newest.link => Observed::Stale,
            Some(newest) if connection.link == newest.link => Observed::Fresh,
            _ => {
                self.newest = Some(connection);
                Observed::Fresh
            }
        }
    }
}

/// What the gate guards: the uploads this process holds, the keys the person cancelled, and the
/// turns of the keys.
#[derive(Default)]
struct Registry {
    held: HashMap<Uuid, Arc<Live>>,
    /// Every key the person cancelled in this process. A key is never taken out: each costs sixteen
    /// bytes, and a cancel stays authoritative for every send, restart or resume that can still
    /// arrive for the key.
    cancelled: HashSet<Uuid>,
    /// The turn of each key this process has acted on.
    turns: HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>,
}

impl Registry {
    /// Records that the person cancelled `key`: from now on no sender is started for it.
    fn record_cancel(&mut self, key: Uuid) {
        self.cancelled.insert(key);
    }

    /// Admits `live`: a key the person cancelled, a key in use and a third open upload are refused,
    /// and otherwise the upload is held, in `Admitted`, before any copy is written or any
    /// reservation is asked for.
    fn admit(&mut self, store: &Store, live: &Arc<Live>, who: &Who) -> Result<()> {
        if self.cancelled.contains(&live.key) {
            return Err(CommandError::refused(CANCELLED));
        }
        let found = store.all();
        if self.held.contains_key(&live.key) || found.holds(live.key) {
            return Err(CommandError::refused(KEY_IN_USE));
        }
        if self.open_count(&found, who) >= MOST_OPEN {
            return Err(CommandError::refused(TOO_MANY_OPEN));
        }
        self.held.insert(live.key, Arc::clone(live));
        Ok(())
    }

    /// Holds `live`, made from an entry a restart found, unless the person cancelled its key since
    /// the entry was read or it is held already.
    fn admit_restarted(&mut self, live: &Arc<Live>) -> bool {
        if self.cancelled.contains(&live.key)
            || live.cancel_asked.load(Ordering::Acquire)
            || self.held.contains_key(&live.key)
        {
            return false;
        }
        self.held.insert(live.key, Arc::clone(live));
        true
    }

    /// The open uploads of `who`: the ones this process holds and the ones kept from before whose
    /// upload is not published.
    fn open_count(&self, found: &Found, who: &Who) -> usize {
        let mut keys: Vec<Uuid> = self
            .held
            .iter()
            .filter(|(_, live)| live.owner.is_whose(who) && !live.published.load(Ordering::Acquire))
            .map(|(key, _)| *key)
            .collect();
        for file in &found.entries {
            if file.is_whose(who) && file.reached != Reached::Published && !keys.contains(&file.key)
            {
                keys.push(file.key);
            }
        }
        keys.len()
    }
}

/// One key's turn: the right to rewrite or remove its entry and copy, and to stop and wait for its
/// sender. An operation holds it for the whole of its work, and holds no other key's; a helper that
/// needs it is handed the one its caller holds, and never takes a turn itself.
struct Turn {
    key: Uuid,
    _held: tokio::sync::OwnedMutexGuard<()>,
}

/// What a barrier does under the key's turn, once the sender is over.
enum Job {
    /// The person's cancel: the record is read, the cancel is recorded and the host is asked, on
    /// the connection the command found when it found one.
    Cancel { who: Who, paired: Option<Paired> },
    /// The cancel of the key is finished on `paired`'s connection.
    Finish { paired: Paired },
    /// The key's upload, if any, and its entry and copy are over for good: the host this device
    /// knew was forgotten, or the pairing the entry was kept under is not the one in force.
    Forget,
    /// The freeing's step for the key: a place that another account's upload holds is given back
    /// to the host, on `session` (the connection `link` names), for the upload `wanting`.
    Free {
        wanting: Arc<Live>,
        session: Arc<Session>,
        link: u64,
    },
    /// Nothing but the attempt and the decision that every barrier ends with.
    Decide,
}

/// What a barrier answers.
enum Answered {
    Done(Box<Result<Cancelled>>),
    /// The key's upload was sending and the barrier was asked to leave a sender alone.
    Skipped,
    /// The work panicked, or the task that ran it ended without an answer.
    Panicked,
}

/// A key's turn after its sender was stopped and joined, lent to the work of one barrier. It exists
/// only inside the task of [`Desk::barrier`], borrows the turn, and resolves the key when it ends:
/// an upload that the work did not end is settled by [`Desk::idle_or_next`] and never stays
/// `Stopping`. Its drop does not panic, takes only the gate, and does no disk work.
struct Stopped<'t> {
    desk: Arc<Desk>,
    turn: &'t Turn,
    /// The upload the desk held for the key when the sender was stopped.
    held: Option<Arc<Live>>,
    /// The key's upload was ended by the work: forgotten, or published.
    ended: bool,
    resolved: bool,
    /// The highest number of a connection this barrier sent a host call on.
    used: u64,
    /// The number of the newest connection this barrier's decision has read.
    looked: u64,
}

impl Stopped<'_> {
    /// The upload and its entry are over for good, and removed.
    fn forget(&mut self, store: &Store, key: Uuid) {
        self.desk.forget(store, &self.held, key);
        self.ended = true;
    }

    /// The upload is published: the held upload ends with the handle and the entry stays.
    fn published(&mut self, handle: AttachmentHandle) {
        if let Some(live) = &self.held {
            self.desk.end(live, Outcome::Published(Box::new(handle)));
        }
        self.ended = true;
    }

    /// The one resolution of the stop: a published record ends the upload, and anything else goes
    /// through the decision section. Runs once.
    fn resolve(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        if self.ended {
            return;
        }
        let Some(live) = self.held.clone() else {
            return;
        };
        let file = live.file();
        if file.reached == Reached::Published
            && let Some(handle) = file.handle
        {
            self.desk.end(&live, Outcome::Published(Box::new(handle)));
            self.ended = true;
            return;
        }
        self.desk
            .idle_or_next(&live, None, self.used, self.looked, None);
    }
}

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        self.resolve();
    }
}

/// The state of every upload this device sends to a paired host.
///
/// **Locks, in order.** `registry` (the gate); inside it only `Live.task`, `Live.phase`,
/// `Live.generation`, the immutable `Live.owner` and `Live.key`, and the atomic `Live.published`;
/// then `sessions`, `verdicts` and `root`. No helper takes the gate again when its caller holds it:
/// it is handed the guard. `Live.file` is never taken under the gate and the gate is never taken
/// inside `Live::change`, so the gate reads `owner` and `published`, not the entry. The gate is
/// held across no `.await` and across no write of an entry; it covers a read of the folder, which
/// admission needs to be one step with the count, and the removal of the orphaned copies that
/// `restart` makes (each a flush), which is what stops `restart` from removing the copy a send has
/// just made.
///
/// **Turns.** A key's turn is a `tokio` mutex, found or made under the gate and awaited outside
/// every lock. No operation holds two turns, so two operations that want two keys cannot wait for
/// each other. Inside a turn the sender is stopped and awaited first, and only then is the entry
/// read or written, so no writer of the key runs beside the one that holds its turn.
#[derive(Default)]
pub struct Desk {
    root: Mutex<Option<PathBuf>>,
    /// The tasks the desk started for itself and has not seen end.
    work: Arc<Work>,
    registry: Mutex<Registry>,
    /// What a restart or a failure found of entries it could not resume.
    verdicts: Mutex<HashMap<Uuid, Verdict>>,
    /// How many times a freeing of other accounts' places freed something, so that an upload whose
    /// begin was refused while another upload's freeing ran knows a place may be free.
    places_freed: AtomicU64,
    /// The newest connection of each host's device, with its account, so that an upload whose
    /// connection ended while a newer one of the same account was coming up goes on at once.
    sessions: Mutex<HashMap<(EnvironmentId, DeviceId), Connections>>,
    /// What a suite holds a send at, before it is admitted.
    #[cfg(feature = "testing")]
    before_admission: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    /// What a suite holds a send at, once the copy of its content is written.
    #[cfg(feature = "testing")]
    after_copy: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    /// The number of the connection each upload was last resumed on: a suite reads where a resume
    /// went from this, and not from what the host saw.
    #[cfg(feature = "testing")]
    resumed: Mutex<HashMap<Uuid, u64>>,
}

impl std::fmt::Debug for Desk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Desk")
            .field("open", &locked(&self.registry).held.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    CannotResume,
    /// The host refused it for good; what it said.
    Failed(String),
}

fn stage_word(stage: Stage) -> &'static str {
    match stage {
        Stage::Starting => "starting",
        Stage::Sending => "sending",
        Stage::Resuming => "resuming",
        Stage::Publishing => "publishing",
        Stage::Published => "published",
    }
}

/// The words of a refusal the host decided.
pub(crate) fn host_words(error: &ClientError) -> Option<&str> {
    match error {
        ClientError::Host(refused) => Some(&refused.message),
        ClientError::Refused { error, .. } => Some(&error.message),
        _ => None,
    }
}

/// Whether the host's answer to a status read says it does not know the transfer.
///
/// A refusal of a right is not that: the host may hold the upload, and the right may come back.
fn host_does_not_know(error: &ClientError) -> bool {
    error.code() == ErrorCode::InvalidArgument
        && host_words(error).is_some_and(|words| words.starts_with("no transfer "))
}

/// Whether the host's refusal of `upload.begin` says this device already holds as many concurrent
/// transfers as it may. The host gives that refusal the code for a resource that is not available
/// now and, as the other temporary causes do not, words that name the count. The file-size limit,
/// the device's staged uploads and the environment's staged bytes answer `QUOTA_EXCEEDED`, and no
/// cancel of another account's upload could make those pass.
fn is_the_count_refusal(error: &ClientError) -> bool {
    error.code() == ErrorCode::ResourceUnavailable
        && host_words(error).is_some_and(|words| words.contains("concurrent transfers"))
}

/// Removes the entry of `key` and its copy when the host's answer says it knows nothing of the
/// upload, and says whether it did. Any other answer, a refused right included, leaves both.
fn drop_if_unknown(store: &Store, key: Uuid, error: &ClientError) -> bool {
    let unknown = host_does_not_know(error);
    if unknown {
        let _ = store.remove(key);
    }
    unknown
}

fn record_not_kept(error: &std::io::Error) -> CommandError {
    CommandError::local_failure(format!(
        "this device could not keep a record of the upload: {error}"
    ))
}

impl Desk {
    /// Names the directory the entries live in.
    pub fn keep_at(&self, root: PathBuf) {
        *locked(&self.root) = Some(root);
    }

    fn store(&self) -> Result<Store> {
        locked(&self.root)
            .clone()
            .map(|root| Store { root })
            .ok_or_else(|| {
                CommandError::unavailable("this application has no place to keep an upload")
            })
    }

    /// Takes the turn of `key`, waiting for whoever holds it. The wait is outside every lock.
    async fn turn(&self, key: Uuid) -> Turn {
        #[cfg(feature = "testing")]
        testing::note(key, testing::Point::TurnWanted);
        let turn = Arc::clone(locked(&self.registry).turns.entry(key).or_default());
        Turn {
            key,
            _held: turn.lock_owned().await,
        }
    }

    /// Takes the sender of the key's upload, under the gate, and moves its generation on, so that
    /// the sender ends and pauses nothing if it is still running. The upload is not cancelled: a
    /// restart of a stored upload still resumes it. Until its owner has ended it or set it paused
    /// again the upload is `Stopping`, and no start is accepted for it.
    fn stop(registry: &Registry, key: Uuid) -> Option<tauri::async_runtime::JoinHandle<()>> {
        let live = registry.held.get(&key)?;
        live.generation.fetch_add(1, Ordering::AcqRel);
        *locked(&live.phase) = Phase::Stopping;
        locked(&live.task).take()
    }

    /// Whether the person cancelled the upload `key` in this process: the commands look before they
    /// copy a file. It is a saving of work and no gate.
    #[must_use]
    pub fn is_cancelled(&self, key: Uuid) -> bool {
        locked(&self.registry).cancelled.contains(&key)
    }

    /// Sends one file to the paired host and answers with the verified handle.
    ///
    /// The upload belongs to the desk, not to this call: dropping the call leaves it running, and a
    /// connection that ends pauses it until the host is reached again.
    ///
    /// # Errors
    ///
    /// Refuses a key the person cancelled, a key that is in use and a third open upload, and returns
    /// the host's refusal or the reason this device ended the connection.
    pub async fn send(
        self: &Arc<Self>,
        paired: Paired,
        request: Request,
    ) -> Result<AttachmentHandle> {
        let store = self.store()?;
        let key = request.key;
        #[cfg(feature = "testing")]
        {
            let gate = locked(&self.before_admission).clone();
            if let Some(gate) = gate {
                let _ = gate.acquire().await;
            }
        }
        let source = match &request.keeping {
            Keeping::Copy(_) => Source::Copy,
            Keeping::Path(path) => Source::Path { path: path.clone() },
        };
        let file = UploadFile {
            version: STORE_VERSION,
            key,
            environment_id: paired.environment_id,
            device_id: paired.device_id,
            account: paired.account_id(),
            target: request.target,
            session_id: request.session_id,
            media_type: request.media_type,
            file_name: request.name,
            byte_len: request.content.byte_len(),
            digest: request.content.digest(),
            source,
            reached: Reached::Beginning,
            transfer_id: None,
            handle: None,
            cancel_asked: false,
        };
        let live = Live::new(file, request.content, false);
        // The place and the key are taken together, here and before any await: a key the person
        // cancelled, a key in use and a third open upload are refused under the gate, so no copy is
        // written and no reservation is asked for.
        locked(&self.registry).admit(&store, &live, &paired.who())?;
        if let Keeping::Copy(bytes) = request.keeping {
            let copied = store.clone();
            let written =
                tauri::async_runtime::spawn_blocking(move || copied.write_copy(key, &bytes))
                    .await
                    .map_err(|error| CommandError::local_failure(error.to_string()))
                    .and_then(|written| {
                        written.map_err(|error| {
                            CommandError::local_failure(format!(
                                "this device could not keep a copy of the file: {error}"
                            ))
                        })
                    });
            if let Err(error) = written {
                locked(&self.registry).held.remove(&key);
                let _ = store.remove_copy(key);
                return Err(error);
            }
        }
        #[cfg(feature = "testing")]
        {
            let gate = locked(&self.after_copy).clone();
            if let Some(gate) = gate {
                let _ = gate.acquire().await;
            }
        }
        // The check and the start are one section under the gate. A cancel that came while the copy
        // was written has recorded the key, or has ended this upload, and the start refuses; one that
        // comes after finds the sender's handle stored.
        let started = {
            let registry = locked(&self.registry);
            // A send on a connection the desk has moved past goes on its own connection and does
            // not make it the newest.
            let _ = locked(&self.sessions)
                .entry((paired.environment_id, paired.device_id))
                .or_default()
                .observe(Connection::of(&paired));
            self.start_under(&registry, &live, Connection::of(&paired), false)
        };
        if !started {
            let _ = store.remove_copy(key);
            return Err(CommandError::refused(CANCELLED));
        }
        Self::outcome_of(&live).await
    }

    /// Waits for the upload's outcome.
    async fn outcome_of(live: &Arc<Live>) -> Result<AttachmentHandle> {
        let mut outcome = live.outcome.subscribe();
        let told = outcome
            .wait_for(Option::is_some)
            .await
            .map_err(|_| CommandError::local_failure("the upload ended without an outcome"))?
            .clone();
        match told {
            Some(Outcome::Published(handle)) => Ok(*handle),
            Some(Outcome::Failed(error)) => Err(error),
            Some(Outcome::Cancelled) | None => Err(CommandError::refused(CANCELLED)),
        }
    }

    /// Starts the send of `live` on `session`, under the gate, and says whether it started. A
    /// resume of a file read from where it is reads it again first, and sends nothing when it is not
    /// the one declared.
    ///
    /// It starts only an upload that this desk holds (by identity), whose key the person did not
    /// cancel, that has no sender, and whose account is the connection's: a second caller that holds
    /// a stale list finds the upload sending and is refused, so an upload has one task, and a
    /// connection of another sign-in never carries the upload. The task and its handle are made
    /// here, in one step under the gate, so a stop finds the handle.
    fn start_under(
        self: &Arc<Self>,
        registry: &Registry,
        live: &Arc<Live>,
        connection: Connection,
        verify: bool,
    ) -> bool {
        let current = registry
            .held
            .get(&live.key)
            .is_some_and(|held| Arc::ptr_eq(held, live));
        if !current
            || registry.cancelled.contains(&live.key)
            || live.cancel_asked.load(Ordering::Acquire)
            || live.owner.account != connection.account
        {
            return false;
        }
        let session = connection.session;
        let link = connection.link;
        {
            let mut phase = locked(&live.phase);
            if !matches!(*phase, Phase::Admitted | Phase::Paused) {
                return false;
            }
            *phase = Phase::Sending;
        }
        live.sent_link.store(link, Ordering::Release);
        #[cfg(feature = "testing")]
        if verify {
            locked(&self.resumed).insert(live.key, link);
        }
        let generation = live.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let desk = Arc::clone(self);
        let running = Arc::clone(live);
        let task = tauri::async_runtime::spawn(async move {
            #[cfg(feature = "testing")]
            let _exit = testing::ExitNote(running.key);
            #[cfg(feature = "testing")]
            testing::at_sender_start(running.key).await;
            if verify && !desk.is_the_content(&running, generation).await {
                return;
            }
            let freed_before = desk.places_freed.load(Ordering::Acquire);
            let mut result = desk.send_once(&running, &session).await;
            #[cfg(feature = "testing")]
            testing::pause(running.key, testing::Point::Refused);
            // The host holds the device's places for every account of the device, and another account
            // cannot see its own. A refusal for the count of open transfers frees the places other
            // accounts' uploads hold, once, and the begin is tried once more. A freeing that another
            // upload made meanwhile counts: the place it freed may be this one's.
            if let Err(error) = &result
                && is_the_count_refusal(error)
                && running.transfer().is_none()
                && !running.places_asked.swap(true, Ordering::AcqRel)
                && (desk.free_places(&running, &session, link).await
                    || desk.places_freed.load(Ordering::Acquire) != freed_before)
            {
                result = desk.send_once(&running, &session).await;
            }
            desk.settle(&running, &session, generation, result);
        });
        *locked(&live.task) = Some(task);
        #[cfg(feature = "testing")]
        testing::pause(live.key, testing::Point::Started);
        true
    }

    /// Whether the content of an upload that resumes is the one declared; when it is not, the upload
    /// ends and its entry says it cannot resume.
    async fn is_the_content(&self, live: &Arc<Live>, generation: u64) -> bool {
        let file = live.file();
        if live.transfer().is_none() || file.source == Source::Copy {
            return true;
        }
        let Ok(store) = self.store() else {
            return true;
        };
        if let Some(content) = self.source_of(&store, &file).await {
            *locked(&live.content) = content;
            return true;
        }
        locked(&self.verdicts).insert(file.key, Verdict::CannotResume);
        self.end_as(
            live,
            generation,
            Outcome::Failed(CommandError::refused(CANNOT_RESUME)),
        );
        false
    }

    async fn send_once(
        &self,
        live: &Arc<Live>,
        session: &Arc<Session>,
    ) -> kr_client::Result<AttachmentHandle> {
        let store = self.store().map_err(|error| {
            ClientError::Host(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                error.message,
            ))
        })?;
        let journal = Kept {
            live: Arc::clone(live),
            store,
        };
        let file = live.file();
        let transfer = live.transfer();
        if file.transfer_id.is_none()
            && let Some(transfer_id) = transfer
        {
            // The host's identifier was not kept: nothing is sent for it until it is.
            journal.begun(transfer_id)?;
        }
        let route = ChunkRoute::network(session, file.environment_id).await?;
        let subject = Subject {
            environment_id: file.environment_id,
            session_id: file.session_id,
            device_id: None,
            declared_media_type: file.media_type.clone(),
            original_file_name: file.file_name.clone(),
        };
        let content: Box<dyn Content> = Box::new(Shared(Arc::clone(&locked(&live.content))));
        let mut plan = match transfer {
            Some(transfer_id) => Upload::resuming(subject, content, transfer_id),
            None => Upload::new(subject, content),
        };
        uploads::send(
            session,
            &route,
            &file.target,
            &mut plan,
            crate::commands::MUTATION_TTL,
            &live.progress,
            &journal,
        )
        .await
    }

    /// Takes what a send ended with: the handle, a pause for a connection that ended, or a failure.
    fn settle(
        self: &Arc<Self>,
        live: &Arc<Live>,
        session: &Arc<Session>,
        generation: u64,
        result: kr_client::Result<AttachmentHandle>,
    ) {
        // A sign-out gives the transport's reason, which the driver returns in place of the plain
        // end; what this device ended is never waited out.
        let by_this_device = session.transport().ended_by_this_device().is_some();
        self.settle_as(live, generation, by_this_device, result);
    }

    fn settle_as(
        self: &Arc<Self>,
        live: &Arc<Live>,
        generation: u64,
        by_this_device: bool,
        result: kr_client::Result<AttachmentHandle>,
    ) {
        // A sender that a stop took over has no say in how the upload ends.
        if live.generation.load(Ordering::Acquire) != generation {
            return;
        }
        let file = live.file();
        let error = match result {
            Ok(handle) => {
                return self.end_as(live, generation, Outcome::Published(Box::new(handle)));
            }
            Err(error) => error,
        };
        // An upload with an account that this device's own end of the connection interrupted (a
        // sign-out, or a sign-in of another account) is paused as if the connection had ended: the
        // entry and the copy stay hidden from the other account and go on when the upload's account
        // reaches the host again.
        let account_paused = by_this_device && file.account.is_some();
        if by_this_device && !account_paused {
            // The sign-in this upload was sent under is not the one in force: it stops for good, and
            // the copy of the person's file goes with it.
            if let Ok(store) = self.store() {
                let _ = store.remove(file.key);
            }
            return self.end_as(live, generation, Outcome::Failed(CommandError::from(error)));
        }
        let transfer = live.transfer();
        if live.journal_failed.load(Ordering::Acquire) {
            if transfer.is_some() {
                // The host holds what this device could not write down: it stays here, paused, and
                // the next send keeps the identifier before anything else.
                self.settle_paused(
                    live,
                    generation,
                    Some(Outcome::Failed(CommandError::from(error))),
                );
            } else {
                // Nothing was asked of the host.
                if let Ok(store) = self.store() {
                    let _ = store.remove(file.key);
                }
                self.end_as(live, generation, Outcome::Failed(CommandError::from(error)));
            }
            return;
        }
        // A request that never left is asked again; a finish or a chunk that did leave is read from
        // the host's own record when the connection comes back.
        let resumable = account_paused
            || match error {
                ClientError::ConnectionEnded => true,
                ClientError::SubmissionUncertain { .. } => transfer.is_some(),
                _ => false,
            };
        if resumable {
            self.settle_paused(live, generation, None);
            return;
        }
        let uncertain = matches!(error, ClientError::SubmissionUncertain { .. })
            || error.code() == ErrorCode::OutcomeUnknown;
        let words = host_words(&error).map_or_else(|| error.to_string(), str::to_owned);
        let failure = CommandError::from(error);
        if let Ok(store) = self.store() {
            if transfer.is_none() && !uncertain {
                // A reservation the host refused leaves nothing behind.
                let _ = store.remove(file.key);
            } else if transfer.is_some() && !uncertain {
                // Refused for good while the host holds the reservation: the entry stays, and says so.
                locked(&self.verdicts).insert(file.key, Verdict::Failed(words));
            }
        }
        self.end_as(live, generation, Outcome::Failed(failure));
    }

    /// Ends the hold on `live` and tells whoever waits. Only the sender of the generation in force,
    /// or an operation that holds the key's turn, ends an upload.
    fn end(&self, live: &Arc<Live>, outcome: Outcome) {
        Self::end_under(&mut locked(&self.registry), live, outcome);
    }

    /// As [`Self::end`], for the sender of `generation`: it ends nothing once a stop took over.
    fn end_as(&self, live: &Arc<Live>, generation: u64, outcome: Outcome) {
        let mut registry = locked(&self.registry);
        if live.generation.load(Ordering::Acquire) == generation {
            Self::end_under(&mut registry, live, outcome);
        }
    }

    fn end_under(registry: &mut Registry, live: &Arc<Live>, outcome: Outcome) {
        if registry
            .held
            .get(&live.key)
            .is_some_and(|held| Arc::ptr_eq(held, live))
        {
            registry.held.remove(&live.key);
        }
        live.outcome.send_replace(Some(outcome));
    }

    /// The sender of `generation` leaves its upload for a later connection: the decision section
    /// pauses it, or starts it on a newer connection of its account at once. A sender that a stop
    /// took over decides nothing.
    fn settle_paused(self: &Arc<Self>, live: &Arc<Live>, generation: u64, failed: Option<Outcome>) {
        self.idle_or_next(
            live,
            Some(generation),
            live.sent_link.load(Ordering::Acquire),
            0,
            failed,
        );
        #[cfg(feature = "testing")]
        testing::note(live.key, testing::Point::SenderSettled);
    }

    /// The host was reached on `paired`'s connection: the paused uploads of its account resume on
    /// it, and the account's entries kept from before are read against the host's own record and
    /// resumed or dropped. What belongs to another principal on this host is stopped and dropped,
    /// never resumed. What belongs to another account of the same principal is left as it is: hidden
    /// from this account, and resumed when its own account reaches the host.
    pub fn host_reached(self: &Arc<Self>, paired: Paired) {
        let (device_id, environment_id) = (paired.device_id, paired.environment_id);
        let connection = Connection::of(&paired);
        let observed = locked(&self.sessions)
            .entry((environment_id, device_id))
            .or_default()
            .observe(connection.clone());
        if observed == Observed::Stale {
            // A report about a connection the owner has replaced: the newer connection's reach does
            // the resuming, the restart and the stop of another principal's uploads.
            return;
        }
        let who = paired.who();
        let (paused, other) = {
            let registry = locked(&self.registry);
            let (mine, other): (Vec<_>, Vec<_>) = registry
                .held
                .values()
                .filter(|live| live.owner.environment_id == environment_id)
                .cloned()
                .partition(|live| live.owner.is_whose(&who));
            let other: Vec<_> = other
                .into_iter()
                .filter(|live| live.owner.device_id != device_id)
                .collect();
            let mut paused: Vec<(Arc<Live>, bool)> = Vec::new();
            for live in mine {
                if *locked(&live.phase) == Phase::Paused {
                    let cancelled = registry.cancelled.contains(&live.key);
                    paused.push((live, cancelled));
                } else {
                    // This reach cannot start the upload: it is held, stopping or sending. It
                    // records that it came, so that the decision that ends the hold reads it.
                    live.reached.fetch_max(paired.link, Ordering::AcqRel);
                }
            }
            (paused, other)
        };
        // An upload of another principal on this host belongs to a pairing that is not in force: it
        // stops, and its entry goes, in its key's turn.
        for live in other {
            let desk = Arc::clone(self);
            self.work.spawn(async move {
                desk.barrier_task(live.key, false, Job::Forget, 0, 0).await;
            });
        }
        for (live, cancelled) in paused {
            if cancelled || live.file().cancel_asked {
                let desk = Arc::clone(self);
                let paired = paired.clone();
                self.work.spawn(async move {
                    let _ = desk.finish_asked(&paired, live.key).await;
                });
            } else {
                #[cfg(feature = "testing")]
                testing::pause(live.key, testing::Point::Claiming);
                let registry = locked(&self.registry);
                self.start_under(&registry, &live, connection.clone(), true);
            }
        }
        if locked(&self.root).is_none() {
            return;
        }
        let desk = Arc::clone(self);
        self.work.spawn(async move {
            desk.restart(paired).await;
        });
    }

    /// Reads the host's record of every entry kept from before, and only then acts on them.
    pub async fn restart(self: &Arc<Self>, paired: Paired) {
        let Ok(store) = self.store() else { return };
        let read = store.clone();
        let Ok(found) = tauri::async_runtime::spawn_blocking(move || read.all()).await else {
            return;
        };
        {
            // Copies that no entry names, that are over, or that a stopped process left half
            // written. A copy a send has just made is its key's in the map and is left.
            let registry = locked(&self.registry);
            for key in found.orphans.iter().chain(&found.spent) {
                if !registry.held.contains_key(key) {
                    let _ = store.remove_copy(*key);
                }
            }
            for staged in &found.staged {
                let _ = crate::drafts::remove_durably(staged);
            }
        }
        let mut mine = Vec::new();
        for file in found.entries {
            if file.environment_id != paired.environment_id
                || locked(&self.registry).held.contains_key(&file.key)
            {
                continue;
            }
            if file.device_id != paired.device_id {
                // Another principal's: the pairing it was kept under is not the one in force. It
                // goes in its key's turn, read again there, after a sender that started since is
                // stopped.
                let _ = self.barrier(file.key, false, Job::Forget, 0, 0).await;
            } else if file.account != paired.account_id() {
                // Another account's: hidden, left as it is, and found again when its account reaches
                // the host. Its copy is named by its entry, so the orphan pass keeps it.
            } else if file.target.environment_id == paired.environment_id {
                mine.push(file);
            }
        }
        // Every read comes before any action: a published upload is never cancelled for a state read
        // after it, and nothing is cancelled here but what the person asked to cancel.
        let mut reads = Vec::new();
        for file in mine {
            let status = match (file.reached, file.transfer_id) {
                _ if file.cancel_asked => None,
                (Reached::Published, _) | (Reached::Beginning, None) => None,
                (_, Some(transfer_id)) => Some(
                    paired
                        .session
                        .read::<_, UploadStatusResult>(
                            Method::UploadStatus,
                            &UploadStatusParams { transfer_id },
                        )
                        .await,
                ),
                (_, None) => None,
            };
            reads.push((file, status));
        }
        for (file, status) in reads {
            self.act_on(&store, &paired, file, status).await;
        }
    }

    /// Acts on one entry a restart read, in its key's turn. The entry is read again under the turn:
    /// a cancel or a cleanup that came since the restart read it has ended it or marked it.
    async fn act_on(
        self: &Arc<Self>,
        store: &Store,
        paired: &Paired,
        file: UploadFile,
        status: Option<kr_client::Result<UploadStatusResult>>,
    ) {
        let key = file.key;
        let turn = self.turn(key).await;
        let Some(file) = store.entry(key) else {
            return;
        };
        if file.cancel_asked || self.is_cancelled(key) {
            // A key the person cancelled is finished, whether or not the record of it could be
            // written, by a barrier on this reach's connection. No code that holds a key's turn
            // calls the barrier, so the turn goes first; the barrier reads the key again.
            drop(turn);
            let _ = self.finish_asked(paired, key).await;
            return;
        }
        // An upload another reach started since the status was read, and an entry that is
        // published, are left to their owners.
        if file.reached == Reached::Published || locked(&self.registry).held.contains_key(&key) {
            return;
        }
        let Some(status) = status else { return };
        match status {
            // The connection failed or a right is refused: the host may hold the upload, and the next
            // time it is reached asks again.
            Err(error) => {
                drop_if_unknown(store, key, &error);
            }
            Ok(read) => match read.state {
                UploadState::Published => {
                    let Some(handle) = read.handle.as_ref().cloned() else {
                        return;
                    };
                    let mut kept = file;
                    kept.reached = Reached::Published;
                    kept.handle = Some(handle);
                    if store.write(&kept).is_ok() {
                        let _ = store.remove_copy(key);
                    }
                }
                UploadState::Receiving | UploadState::Publishing => {
                    let publishing = read.state == UploadState::Publishing;
                    match self.source_of(store, &file).await {
                        Some(content) => {
                            #[cfg(feature = "testing")]
                            testing::pause(key, testing::Point::Reading);
                            locked(&self.verdicts).remove(&key);
                            let live = Live::new(file, content, true);
                            let mut registry = locked(&self.registry);
                            if registry.admit_restarted(&live) {
                                self.start_under(&registry, &live, Connection::of(paired), false);
                            }
                        }
                        // A publication in progress needs no content: the entry stays, and the host is
                        // read again at the next reach.
                        None if publishing => {}
                        None => {
                            locked(&self.verdicts).insert(key, Verdict::CannotResume);
                        }
                    }
                }
                UploadState::Cancelled | UploadState::Invalidated | UploadState::Expired => {
                    let _ = store.remove(key);
                }
            },
        }
    }

    /// The content an entry describes, when it is still here and is the one declared.
    async fn source_of(&self, store: &Store, file: &UploadFile) -> Option<Arc<dyn Content>> {
        let (store, file) = (store.clone(), file.clone());
        tauri::async_runtime::spawn_blocking(move || {
            let content: Arc<dyn Content> = match &file.source {
                Source::Copy => Arc::new(Held::new(store.read_copy(file.key).ok()?)),
                Source::Path { path } => Arc::new(crate::transfers::DroppedFile::open(path).ok()?),
            };
            (content.byte_len() == file.byte_len && content.digest() == file.digest)
                .then_some(content)
        })
        .await
        .ok()
        .flatten()
    }

    /// The open uploads of `who`, as the desk and the folder hold them: no connection is asked, so a
    /// host that is out of reach reads as its uploads stand, a paused one as paused.
    #[must_use]
    pub fn open(&self, who: &Who) -> Vec<OpenView> {
        let Ok(store) = self.store() else {
            return Vec::new();
        };
        let mut views = Vec::new();
        let live = locked(&self.registry).held.clone();
        for (key, held) in &live {
            let file = held.file();
            if !file.is_whose(who) {
                continue;
            }
            let progress = *held.progress.borrow();
            // A cancel is read before anything else of the upload: its key is recorded first, and a
            // paused or sending upload that is cancelled goes on no more.
            let state = if file.cancel_asked || self.is_cancelled(*key) {
                OpenState::CancelAsked
            } else {
                match *locked(&held.phase) {
                    Phase::Admitted | Phase::Sending | Phase::Stopping => OpenState::Sending,
                    Phase::Paused => OpenState::Paused,
                }
            };
            views.push(view_of(
                *key,
                &file,
                state,
                progress,
                Some(progress.stage),
                None,
            ));
        }
        for file in store.all().entries {
            if !file.is_whose(who) || live.contains_key(&file.key) {
                continue;
            }
            let verdict = locked(&self.verdicts).get(&file.key).cloned();
            let (state, said) = match (file.reached, verdict) {
                (Reached::Published, _) => (OpenState::Published, None),
                // A key the person cancelled counts as asked whether or not the record of it could
                // be written.
                _ if file.cancel_asked || self.is_cancelled(file.key) => {
                    (OpenState::CancelAsked, None)
                }
                (Reached::Beginning, _) => {
                    (OpenState::Unrecoverable, Some(UNRECOVERABLE.to_owned()))
                }
                (_, Some(Verdict::CannotResume)) => {
                    (OpenState::CannotResume, Some(CANNOT_RESUME.to_owned()))
                }
                (_, Some(Verdict::Failed(words))) => (OpenState::Failed, Some(words)),
                _ => (OpenState::Waiting, None),
            };
            views.push(view_of(
                file.key,
                &file,
                state,
                Progress::default(),
                None,
                said,
            ));
        }
        views.sort_by(|left, right| left.key.cmp(&right.key));
        views
    }

    /// Cancels the upload `key`, after the host's record of it is read, and answers from the host's
    /// own answer. An upload the host has published is never cancelled.
    ///
    /// The key is recorded as cancelled first, so no sender is started for it from then on, whatever
    /// holds it or nothing does. Then the cancel takes the key's turn, stops the sender and waits
    /// for it, so that what the sender kept is final when it is read. A cancel that cannot be
    /// finished is recorded in the entry and finished at the next reach, and the upload is never sent
    /// on.
    ///
    /// `paired` is the connection to the host when one is held. With none the cancel is kept, and the
    /// upload is read as cancelled until the next reach finishes it.
    ///
    /// # Errors
    ///
    /// Returns a refusal when `key` is no upload of `who`'s, in which case nothing is recorded, and
    /// when the desk has no place to keep entries. Every other failure answers `asked`: the key is
    /// cancelled, nothing more is sent, and the cancel is finished at the next reach, or at once by
    /// [`Self::finish_asked`].
    pub async fn cancel(
        self: &Arc<Self>,
        who: Who,
        paired: Option<Paired>,
        key: Uuid,
    ) -> Result<Cancelled> {
        let store = self.store()?;
        let none = || CommandError::invalid(NO_OPEN_UPLOAD);
        #[cfg(feature = "testing")]
        testing::note(key, testing::Point::CancelBegun);
        // Step 0. A stored entry of another account or principal is never marked.
        if store.entry(key).is_some_and(|file| !file.is_whose(&who)) {
            return Err(none());
        }
        {
            let mut registry = locked(&self.registry);
            if registry
                .held
                .get(&key)
                .is_some_and(|live| !live.owner.is_whose(&who))
            {
                return Err(none());
            }
            registry.record_cancel(key);
        }
        // Steps 1 to 3 run in a task of the desk's own, which no caller can cancel.
        let job = Job::Cancel { who, paired };
        Self::answer(key, self.barrier(key, false, job, 0, 0).await)
    }

    /// The transfer the host gave for an upload, whether or not the entry could keep it.
    fn transfer_of(held: &Option<Arc<Live>>, file: &UploadFile) -> Option<TransferId> {
        held.as_ref()
            .and_then(|live| live.transfer())
            .or(file.transfer_id)
    }

    fn said(
        key: Uuid,
        state: &'static str,
        released: Option<String>,
        handle: Option<AttachmentHandle>,
    ) -> Cancelled {
        Cancelled {
            key: key.to_string(),
            state,
            released_byte_len: released,
            handle,
            said: None,
        }
    }

    /// A cancel kept to be finished: nothing more of the upload is sent, and `said` tells what went
    /// wrong when something did.
    fn asked(key: Uuid, said: Option<String>) -> Cancelled {
        Cancelled {
            said,
            ..Self::said(key, "asked", None, None)
        }
    }

    /// Finishes the cancel of `key` on `paired`'s connection, in the key's turn, inside a barrier: the
    /// sender is stopped and waited for, the upload or the entry is read again, and the cancel is
    /// finished only when the key is still held or kept and was cancelled. A key already gone answers
    /// `forgotten`, so a second finisher never cancels again. A record of another owner is refused
    /// before anything is stopped.
    ///
    /// # Errors
    ///
    /// Refuses a key that is no upload of `paired`'s owner, and a key whose cancel was never asked.
    pub async fn finish_asked(self: &Arc<Self>, paired: &Paired, key: Uuid) -> Result<Cancelled> {
        let store = self.store()?;
        #[cfg(feature = "testing")]
        let checked = !testing::armed(key, testing::Fault::SkipPrecheck);
        #[cfg(not(feature = "testing"))]
        let checked = true;
        if checked {
            let who = paired.who();
            let live = locked(&self.registry).held.get(&key).cloned();
            let owned = match live {
                Some(live) => Some(live.owner.is_whose(&who)),
                None => store.entry(key).map(|file| file.is_whose(&who)),
            };
            if owned == Some(false) {
                return Err(CommandError::invalid(NO_OPEN_UPLOAD));
            }
        }
        let job = Job::Finish {
            paired: paired.clone(),
        };
        Self::answer(key, self.barrier(key, false, job, 0, 0).await)
    }

    /// What a command is told of a barrier's answer. A barrier whose work panicked, and a key that
    /// was recorded as cancelled, answer `asked`: the cancel is finished at the next reach.
    fn answer(key: Uuid, answered: Answered) -> Result<Cancelled> {
        match answered {
            Answered::Done(result) => *result,
            Answered::Skipped | Answered::Panicked => Ok(Self::asked(key, None)),
        }
    }

    /// Runs `job` on `key` in a task of the desk's own that no caller can cancel, and answers what it
    /// answers; a caller that is dropped drops only the answer. The task takes the key's turn,
    /// stops the key's sender and waits for it (unless `skip` leaves a sending upload alone), runs
    /// the job under `catch_unwind`, makes the one attempt to finish a cancelled key on the newest
    /// connection of its account, and ends the stop in the decision section, so that no path leaves
    /// the upload `Stopping`. No code that holds a key's turn calls it.
    async fn barrier(
        self: &Arc<Self>,
        key: Uuid,
        skip: bool,
        job: Job,
        used: u64,
        looked: u64,
    ) -> Answered {
        let (answer, answered) = tokio::sync::oneshot::channel();
        let desk = Arc::clone(self);
        self.work.spawn(async move {
            let done = desk.barrier_task(key, skip, job, used, looked).await;
            let _ = answer.send(done);
        });
        answered.await.unwrap_or(Answered::Panicked)
    }

    async fn barrier_task(
        self: &Arc<Self>,
        key: Uuid,
        skip: bool,
        job: Job,
        used: u64,
        looked: u64,
    ) -> Answered {
        let turn = self.turn(key).await;
        let (held, handle) = {
            let registry = locked(&self.registry);
            let held = registry.held.get(&key).cloned();
            if skip
                && held.as_ref().is_some_and(|live| {
                    matches!(*locked(&live.phase), Phase::Sending | Phase::Admitted)
                })
            {
                return Answered::Skipped;
            }
            (held, Self::stop(&registry, key))
        };
        if let Some(handle) = handle {
            handle.abort();
            #[cfg(feature = "testing")]
            testing::note(key, testing::Point::CancelWaiting);
            let _ = handle.await;
        }
        #[cfg(feature = "testing")]
        testing::pause(key, testing::Point::Stopped);
        let mut stopped = Stopped {
            desk: Arc::clone(self),
            turn: &turn,
            held,
            ended: false,
            resolved: false,
            used,
            looked,
        };
        let worked = AssertUnwindSafe(self.work_of(&mut stopped, job))
            .catch_unwind()
            .await;
        let mut answered = match worked {
            Ok(result) => Answered::Done(Box::new(result)),
            Err(_) => Answered::Panicked,
        };
        if let Some(Ok(done)) = self.attempt(&mut stopped).await
            && !matches!(answered, Answered::Panicked)
        {
            answered = Answered::Done(Box::new(Ok(done)));
        }
        #[cfg(feature = "testing")]
        testing::gate(key, testing::Awaited::BeforeTail).await;
        stopped.resolve();
        #[cfg(feature = "testing")]
        testing::note(key, testing::Point::DecisionDone);
        answered
    }

    async fn work_of(self: &Arc<Self>, stopped: &mut Stopped<'_>, job: Job) -> Result<Cancelled> {
        let key = stopped.turn.key;
        #[cfg(feature = "testing")]
        if testing::take(key, testing::Fault::PanicInWork) {
            panic!("a fault injected into the work of a barrier");
        }
        match job {
            Job::Cancel { who, paired } => self.cancel_work(stopped, &who, paired).await,
            Job::Finish { paired } => self.finish_work(stopped, &paired).await,
            Job::Forget => {
                stopped.forget(&self.store()?, key);
                Ok(Self::said(key, "forgotten", None, None))
            }
            Job::Free {
                wanting,
                session,
                link,
            } => self.free_work(stopped, &wanting, &session, link).await,
            Job::Decide => Ok(Self::asked(key, None)),
        }
    }

    /// The freeing's work for one key, under the key's turn with the sender over: the upload of
    /// another account of the device that the host still holds a place for is read on the host and
    /// cancelled on `session`. A record that is gone is a place found freed; one that is published,
    /// or has no transfer identifier, holds no place and is left for the barrier's decision.
    async fn free_work(
        self: &Arc<Self>,
        stopped: &mut Stopped<'_>,
        wanting: &Arc<Live>,
        session: &Arc<Session>,
        link: u64,
    ) -> Result<Cancelled> {
        let store = self.store()?;
        let key = stopped.turn.key;
        #[cfg(feature = "testing")]
        testing::gate(wanting.key, testing::Awaited::Freeing).await;
        let Some(file) = Self::record_of(stopped, &store) else {
            // Another freeing took it first.
            return Ok(Self::said(key, "forgotten", None, None));
        };
        let owner = &wanting.owner;
        let held_by_another = file.key != wanting.key
            && file.device_id == owner.device_id
            && file.environment_id == owner.environment_id
            && file.account != owner.account;
        if !held_by_another
            || file.reached == Reached::Published
            || Self::transfer_of(&stopped.held, &file).is_none()
        {
            return Ok(Self::asked(key, None));
        }
        self.finish_cancel(stopped, &store, session, link, file)
            .await
    }

    /// The upload's record, as the work reads it under the turn: the held upload's own, or the
    /// entry's.
    fn record_of(stopped: &Stopped<'_>, store: &Store) -> Option<UploadFile> {
        match &stopped.held {
            Some(live) => Some(live.file()),
            None => store.entry(stopped.turn.key),
        }
    }

    /// A record that says the upload is published ends the held upload with its handle, and the
    /// answer is `published`; the entry stays and its copy is gone already.
    fn published_answer(stopped: &mut Stopped<'_>, file: &UploadFile) -> Option<Cancelled> {
        if file.reached != Reached::Published {
            return None;
        }
        let handle = file.handle.clone()?;
        stopped.published(handle.clone());
        Some(Self::said(file.key, "published", None, Some(handle)))
    }

    /// The person's cancel, under the key's turn with the sender over: the cancel is recorded before
    /// the host is asked, so that one that cannot be finished is not lost.
    async fn cancel_work(
        self: &Arc<Self>,
        stopped: &mut Stopped<'_>,
        who: &Who,
        paired: Option<Paired>,
    ) -> Result<Cancelled> {
        let store = self.store()?;
        let key = stopped.turn.key;
        let none = || CommandError::invalid(NO_OPEN_UPLOAD);
        let held = stopped.held.clone();
        let file = match &held {
            Some(live) => live.file(),
            None => match store.entry(key) {
                Some(file) if file.is_whose(who) => file,
                Some(_) => return Err(none()),
                None => return Ok(Self::said(key, "forgotten", None, None)),
            },
        };
        if let Some(published) = Self::published_answer(stopped, &file) {
            return Ok(published);
        }
        if !file.cancel_asked {
            let asked = match &held {
                Some(live) => live.change(&store, |file| file.cancel_asked = true),
                None => store.write(&UploadFile {
                    cancel_asked: true,
                    ..file.clone()
                }),
            };
            if let Err(error) = asked {
                // Nothing runs for this key: it is cancelled, whatever could be written.
                return Ok(Self::asked(key, Some(record_not_kept(&error).message)));
            }
        }
        let file = match &held {
            Some(live) => live.file(),
            None => UploadFile {
                cancel_asked: true,
                ..file
            },
        };
        let Some(paired) = paired else {
            // No connection: a reservation the host never answered is forgotten here, and any other
            // is kept as cancelled until the host is reached.
            if Self::transfer_of(&held, &file).is_none() {
                stopped.forget(&store, key);
                return Ok(Self::said(key, "forgotten", None, None));
            }
            return Ok(Self::asked(key, None));
        };
        match self
            .finish_cancel(stopped, &store, &paired.session, paired.link, file)
            .await
        {
            Ok(answer) => Ok(answer),
            Err(error) => Ok(Self::asked(key, Some(error.message))),
        }
    }

    /// The cancel of a key finished on `paired`'s connection, under the key's turn with the sender
    /// over.
    async fn finish_work(
        self: &Arc<Self>,
        stopped: &mut Stopped<'_>,
        paired: &Paired,
    ) -> Result<Cancelled> {
        let store = self.store()?;
        let key = stopped.turn.key;
        let held = stopped.held.clone();
        let Some(file) = Self::record_of(stopped, &store) else {
            return Ok(Self::said(key, "forgotten", None, None));
        };
        #[cfg(feature = "testing")]
        let checked = !testing::armed(key, testing::Fault::SkipPrecheck);
        #[cfg(not(feature = "testing"))]
        let checked = true;
        if checked && !file.is_of(paired) {
            return Err(CommandError::invalid(NO_OPEN_UPLOAD));
        }
        if let Some(published) = Self::published_answer(stopped, &file) {
            return Ok(published);
        }
        if !file.cancel_asked && !self.is_cancelled(key) {
            return Err(CommandError::invalid(NO_OPEN_UPLOAD));
        }
        let file = UploadFile {
            cancel_asked: true,
            ..held.as_ref().map_or(file, |live| live.file())
        };
        // A host that cannot be asked leaves the cancel kept: the next reach finishes it.
        match self
            .finish_cancel(stopped, &store, &paired.session, paired.link, file)
            .await
        {
            Ok(answer) => Ok(answer),
            Err(error) => Ok(Self::asked(key, Some(error.message))),
        }
    }

    /// The one attempt of a barrier: a key that is cancelled and was not ended by the work is
    /// finished on the desk's newest connection when that is its account's and is newer than every
    /// connection this barrier has called the host on. It is also the retry that a failed record
    /// write needs, and the cancel of a reach that came while the stop waited.
    async fn attempt(self: &Arc<Self>, stopped: &mut Stopped<'_>) -> Option<Result<Cancelled>> {
        if stopped.ended {
            return None;
        }
        let key = stopped.turn.key;
        let store = self.store().ok()?;
        let file = Self::record_of(stopped, &store)?;
        if file.reached == Reached::Published || !(file.cancel_asked || self.is_cancelled(key)) {
            return None;
        }
        let newest = locked(&self.sessions)
            .get(&(file.environment_id, file.device_id))
            .and_then(|known| known.newest.clone())?;
        if newest.account != file.account || newest.link <= stopped.used {
            return None;
        }
        stopped.looked = stopped.looked.max(newest.link);
        let file = UploadFile {
            cancel_asked: true,
            ..file
        };
        Some(
            self.finish_cancel(stopped, &store, &newest.session, newest.link, file)
                .await,
        )
    }

    /// The host's record is read, and then the upload is cancelled unless it is published. The
    /// caller is a barrier's work or its attempt: the key's turn is held and the sender is over. A
    /// failure returns `Err` and leaves the upload for the barrier's decision; only a forgotten or a
    /// published upload is final here.
    async fn finish_cancel(
        self: &Arc<Self>,
        stopped: &mut Stopped<'_>,
        store: &Store,
        session: &Arc<Session>,
        link: u64,
        file: UploadFile,
    ) -> Result<Cancelled> {
        let key = file.key;
        stopped.used = stopped.used.max(link);
        let held = stopped.held.clone();
        let Some(transfer_id) = Self::transfer_of(&held, &file) else {
            // A reservation whose answer never came: nothing this device can name is held.
            stopped.forget(store, key);
            return Ok(Self::said(key, "forgotten", None, None));
        };
        // The host's record is read before anything is cancelled.
        let read: UploadStatusResult = match session
            .read(Method::UploadStatus, &UploadStatusParams { transfer_id })
            .await
        {
            Ok(read) => read,
            Err(error) if host_does_not_know(&error) => {
                stopped.forget(store, key);
                return Ok(Self::said(key, "forgotten", None, None));
            }
            // Including a refusal of a right: the host may hold it, and the entry stays.
            Err(error) => return Err(error.into()),
        };
        if read.state == UploadState::Published {
            let Some(handle) = read.handle.as_ref().cloned() else {
                return Err(CommandError::unavailable(
                    "the host says the upload is published and gave no handle",
                ));
            };
            let kept = UploadFile {
                reached: Reached::Published,
                handle: Some(handle.clone()),
                cancel_asked: false,
                ..file
            };
            if let Err(error) = store.write(&kept) {
                return Err(record_not_kept(&error));
            }
            let _ = store.remove_copy(key);
            if let Some(live) = &held {
                live.adopt(kept);
            }
            stopped.published(handle.clone());
            return Ok(Self::said(key, "published", None, Some(handle)));
        }
        // An upload the person cancelled carries its record already, or sends its cancel whatever
        // could be written. Any other (the freeing's) is recorded before the host is asked, and
        // sends nothing when the record cannot be written: a cancel that the host may have taken is
        // then never forgotten, and the upload is never resumed on a transfer the host may have
        // cancelled.
        if !file.cancel_asked && !self.is_cancelled(key) {
            let asked = match &held {
                Some(live) => live.change(store, |file| file.cancel_asked = true),
                None => store.write(&UploadFile {
                    cancel_asked: true,
                    ..file.clone()
                }),
            };
            asked.map_err(|error| record_not_kept(&error))?;
        }
        let answer: UploadCancelResult = uploads::cancel(
            session,
            &file.target,
            transfer_id,
            crate::commands::MUTATION_TTL,
        )
        .await
        .map_err(CommandError::from)?;
        stopped.forget(store, key);
        Ok(Self::said(
            key,
            "cancelled",
            Some(answer.released_byte_len.get().to_string()),
            None,
        ))
    }

    /// The one decision section of a stop or a pause. It is the only code that sets an upload
    /// `Paused` or decides to start nothing, and it reads the desk's newest connection and the
    /// reaches that went by the upload in one gate section, so that a reach is either seen here or
    /// finds the upload paused and starts it. `generation` validates a sender's right to decide;
    /// without it the caller is a barrier that holds the turn of the key.
    ///
    /// `failed` is the outcome a sender's command ends with when the upload stays for a later
    /// connection; it is written in the same section.
    ///
    /// An upload that nothing owes is started on the newest connection of its account when that is
    /// newer than every connection `used` names. An upload whose cancel is owed, or one that a reach
    /// went by after the decision `looked` read, is paused and handed to a fresh decision, which
    /// takes the key's turn after the holder lets it go.
    fn idle_or_next(
        self: &Arc<Self>,
        live: &Arc<Live>,
        generation: Option<u64>,
        used: u64,
        looked: u64,
        failed: Option<Outcome>,
    ) {
        #[cfg(feature = "testing")]
        if generation.is_some() {
            testing::pause(live.key, testing::Point::SettleBeforeGate);
        }
        let registry = locked(&self.registry);
        let right = match generation {
            Some(generation) => live.generation.load(Ordering::Acquire) == generation,
            None => registry
                .held
                .get(&live.key)
                .is_some_and(|held| Arc::ptr_eq(held, live)),
        };
        if !right {
            return;
        }
        let newest = locked(&self.sessions)
            .get(&(live.owner.environment_id, live.owner.device_id))
            .and_then(|known| known.newest.clone());
        // A reach at or below the number of the connection the sender went on is not news.
        let looked = looked.max(live.sent_link.load(Ordering::Acquire));
        let seen = live.reached.load(Ordering::Acquire);
        let owed =
            registry.cancelled.contains(&live.key) || live.cancel_asked.load(Ordering::Acquire);
        let usable =
            newest.filter(|newest| newest.account == live.owner.account && newest.link > used);
        // The command's failure is written in the section that validated the sender's generation,
        // before any new start, so that an old sender never overwrites the outcome of the one that
        // replaced it.
        if let Some(failed) = failed {
            live.outcome.send_replace(Some(failed));
        }
        *locked(&live.phase) = Phase::Paused;
        match usable {
            Some(newest) if !owed => {
                self.start_under(&registry, live, newest, true);
            }
            usable => {
                if seen > looked || (owed && usable.is_some()) {
                    let link = usable.map_or(0, |newest| newest.link);
                    self.hand_over(live.key, used, looked.max(seen).max(link));
                }
            }
        }
    }

    /// Gives the key to a fresh decision: a task of the desk's own that takes the key's turn after
    /// the holder lets it go, leaves a sending upload alone, and carries what the decision before it
    /// read.
    fn hand_over(self: &Arc<Self>, key: Uuid, used: u64, looked: u64) {
        let desk = Arc::clone(self);
        self.work.spawn(async move {
            desk.barrier_task(key, true, Job::Decide, used, looked)
                .await;
        });
    }

    /// Frees the places on the host that other accounts of this device hold, for the upload
    /// `wanting`, whose begin the host refused for the device's count of open transfers. The host
    /// counts for the device's principal, which every account of the device shares, so an account
    /// cannot see or free the reservations another account left. The work runs in a task of the
    /// desk's own, so that a stop of the wanting upload, which drops only this call, abandons
    /// neither the key being freed nor the count. Each reservation of another account of this device
    /// on this host that is not published is taken one at a time through the barrier, which leaves
    /// an upload that is sending alone, and is read again in the key's turn and cancelled on
    /// `session` (the connection `link` names); its entry and copy go with it. A published upload
    /// holds no place and is never cancelled, and a cancel the host did not answer keeps its entry.
    /// Says whether a place was freed, or was found already gone.
    async fn free_places(
        self: &Arc<Self>,
        wanting: &Arc<Live>,
        session: &Arc<Session>,
        link: u64,
    ) -> bool {
        let (answer, answered) = tokio::sync::oneshot::channel();
        let desk = Arc::clone(self);
        let (wanting, session) = (Arc::clone(wanting), Arc::clone(session));
        self.work.spawn(async move {
            #[cfg(feature = "testing")]
            if testing::take(wanting.key, testing::Fault::PanicInFreeing) {
                panic!("a fault injected into the freeing");
            }
            let freed = desk.free_each(&wanting, &session, link, &answer).await;
            let _ = answer.send(freed);
        });
        // A freeing that panicked closes the channel: nothing was freed that this sender may count on.
        answered.await.unwrap_or(false)
    }

    async fn free_each(
        self: &Arc<Self>,
        wanting: &Arc<Live>,
        session: &Arc<Session>,
        link: u64,
        answer: &tokio::sync::oneshot::Sender<bool>,
    ) -> bool {
        let Ok(store) = self.store() else {
            return false;
        };
        let owner = &wanting.owner;
        let held_by_another = |file: &UploadFile| {
            file.key != wanting.key
                && file.device_id == owner.device_id
                && file.environment_id == owner.environment_id
                && file.account != owner.account
        };
        let mut keys: Vec<Uuid> = locked(&self.registry)
            .held
            .values()
            .filter(|live| {
                live.key != wanting.key
                    && live.owner.device_id == owner.device_id
                    && live.owner.environment_id == owner.environment_id
                    && live.owner.account != owner.account
                    && !live.published.load(Ordering::Acquire)
            })
            .map(|live| live.key)
            .collect();
        for file in store.all().entries {
            if held_by_another(&file)
                && file.reached != Reached::Published
                && file.transfer_id.is_some()
                && !keys.contains(&file.key)
            {
                keys.push(file.key);
            }
        }
        let mut freed = false;
        for key in keys {
            // No key is taken for nobody: the wanting upload was stopped, or its connection ended
            // (a network end fails the next call). The key in flight finishes.
            if answer.is_closed() || session.transport().ended_by_this_device().is_some() {
                break;
            }
            let job = Job::Free {
                wanting: Arc::clone(wanting),
                session: Arc::clone(session),
                link,
            };
            if let Answered::Done(done) = self.barrier(key, true, job, 0, 0).await
                && let Ok(done) = *done
                && matches!(done.state, "cancelled" | "forgotten")
            {
                freed = true;
            }
        }
        if freed {
            self.places_freed.fetch_add(1, Ordering::AcqRel);
        }
        freed
    }

    /// Ends an upload that is over for good, and removes its entry and its copy.
    fn forget(&self, store: &Store, held: &Option<Arc<Live>>, key: Uuid) {
        locked(&self.verdicts).remove(&key);
        // The files go first: whoever is told it was cancelled finds nothing kept.
        let _ = store.remove(key);
        if let Some(live) = held {
            self.end(live, Outcome::Cancelled);
        }
    }

    /// Whether a record of `who`'s account holds the transfer `transfer_id`: an upload this desk
    /// holds, or an entry kept for it. The host knows the device and not the account, so what the
    /// host says of a transfer is read for `who` only when one of `who`'s own records names it.
    #[must_use]
    pub fn holds(&self, who: &Who, transfer_id: TransferId) -> bool {
        let lives: Vec<Arc<Live>> = locked(&self.registry).held.values().cloned().collect();
        lives
            .iter()
            .any(|live| live.transfer() == Some(transfer_id) && live.owner.is_whose(who))
            || self.store().is_ok_and(|store| {
                store
                    .all()
                    .entries
                    .iter()
                    .any(|file| file.transfer_id == Some(transfer_id) && file.is_whose(who))
            })
    }

    /// The handle of the published upload `transfer_id` was bound to a draft by `who`: that
    /// account's entry for it ends, in its key's turn, and read again under the turn. Another
    /// account's entry is never removed here.
    pub async fn bound(&self, who: &Who, transfer_id: TransferId) {
        let Ok(store) = self.store() else { return };
        let is_it = |file: &UploadFile| {
            file.transfer_id == Some(transfer_id)
                && file.reached == Reached::Published
                && file.is_whose(who)
        };
        let keys: Vec<Uuid> = store
            .all()
            .entries
            .iter()
            .filter(|file| is_it(file))
            .map(|file| file.key)
            .collect();
        for key in keys {
            let _turn = self.turn(key).await;
            if store.entry(key).is_some_and(|file| is_it(&file)) {
                let _ = store.remove(key);
            }
        }
    }

    /// The host this device knows as `device_id` was forgotten: what is sent to it stops, and every
    /// entry and copy kept for it goes. Each key is taken in its turn, in a task of the desk's own.
    pub fn forgotten(self: &Arc<Self>, device_id: DeviceId) {
        let desk = Arc::clone(self);
        self.work.spawn(async move {
            let sending: Vec<Uuid> = locked(&desk.registry)
                .held
                .values()
                .filter(|live| live.owner.device_id == device_id)
                .map(|live| live.key)
                .collect();
            for key in sending {
                desk.barrier_task(key, false, Job::Forget, 0, 0).await;
            }
            let Ok(store) = desk.store() else { return };
            for file in store.all().entries {
                if file.device_id == device_id {
                    // Read again under the turn: an upload that a reach started since is stopped
                    // before its entry goes.
                    desk.barrier_task(file.key, false, Job::Forget, 0, 0).await;
                }
            }
        });
    }
}

fn view_of(
    key: Uuid,
    file: &UploadFile,
    state: OpenState,
    progress: Progress,
    stage: Option<Stage>,
    said: Option<String>,
) -> OpenView {
    OpenView {
        key: key.to_string(),
        state,
        session_id: file.session_id.map(|session| session.to_string()),
        file_name: file.file_name.clone(),
        byte_len: file.byte_len,
        acknowledged_chunks: progress.acknowledged_chunks,
        chunks: progress.chunks,
        stage: stage.map(stage_word),
        handle: file.handle.clone(),
        said,
    }
}

#[cfg(feature = "testing")]
impl Desk {
    /// Resolves once none of the tasks the desk started for itself is running, so that a suite reads
    /// what they left only when they are over.
    pub async fn idle(&self) {
        loop {
            let over = self.work.over.notified();
            tokio::pin!(over);
            over.as_mut().enable();
            if self.work.running.load(Ordering::Acquire) == 0 {
                return;
            }
            over.await;
        }
    }

    /// Holds every send at the top of `send`, before it is admitted, until the returned gate is
    /// given a permit.
    pub fn hold_before_admission_for_test(&self) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *locked(&self.before_admission) = Some(Arc::clone(&gate));
        gate
    }

    /// How many senders the upload `key` has had, while the desk holds it.
    #[must_use]
    pub fn generation_for_test(&self, key: Uuid) -> Option<u64> {
        locked(&self.registry)
            .held
            .get(&key)
            .map(|live| live.generation.load(Ordering::Acquire))
    }

    /// Holds every send after its copy is written until the returned gate is given a permit.
    pub fn hold_after_copy_for_test(&self) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *locked(&self.after_copy) = Some(Arc::clone(&gate));
        gate
    }

    /// Whether `paired`'s connection is the newest one this desk was told the host was reached on.
    #[must_use]
    pub fn holds_newest_for_test(&self, paired: &Paired) -> bool {
        locked(&self.sessions)
            .get(&(paired.environment_id, paired.device_id))
            .and_then(|known| known.newest.as_ref())
            .is_some_and(|newest| Arc::ptr_eq(&newest.session, &paired.session))
    }

    /// The number and the account of the newest connection this desk was told of for `paired`'s
    /// host, and none when it was told of none.
    #[must_use]
    pub fn newest_for_test(&self, paired: &Paired) -> Option<(u64, Option<String>)> {
        locked(&self.sessions)
            .get(&(paired.environment_id, paired.device_id))
            .and_then(|known| known.newest.as_ref())
            .map(|newest| (newest.link, newest.account.clone()))
    }

    /// Takes the turn of `key` and keeps it until the answer is dropped, so that a suite can put an
    /// operation behind it.
    pub async fn hold_turn_for_test(&self, key: Uuid) -> impl Send + use<> {
        self.turn(key).await
    }

    /// How many uploads the desk holds.
    #[must_use]
    pub fn held_count_for_test(&self) -> usize {
        locked(&self.registry).held.len()
    }

    /// The phase of the upload `key` as a word, and none when the desk does not hold it.
    #[must_use]
    pub fn phase_for_test(&self, key: Uuid) -> Option<&'static str> {
        locked(&self.registry)
            .held
            .get(&key)
            .map(|live| match *locked(&live.phase) {
                Phase::Admitted => "admitted",
                Phase::Sending => "sending",
                Phase::Stopping => "stopping",
                Phase::Paused => "paused",
            })
    }

    /// How many times a freeing has freed at least one place.
    #[must_use]
    pub fn places_freed_for_test(&self) -> u64 {
        self.places_freed.load(Ordering::Acquire)
    }

    /// The number of the connection the upload `key` was last resumed on, and none when it was
    /// never resumed.
    #[must_use]
    pub fn resumed_on_for_test(&self, key: Uuid) -> Option<u64> {
        locked(&self.resumed).get(&key).copied()
    }
}

/// What a suite keeps in the folder to stand for an upload that an earlier process left, and the
/// places in the desk's code where it can stop a thread to put two operations in an order.
#[cfg(feature = "testing")]
pub mod testing {
    use super::{Reached, STORE_VERSION, Source, Store, UploadFile};
    use kr_client::services::AccountMark;
    use kr_protocol::envelope::ActionTarget;
    use kr_protocol::ids::{DeviceId, EnvironmentId, TransferId};
    use kr_protocol::scalars::{Digest256, Uuid};
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};

    /// The write of the journal a sender makes before a call to the host.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Step {
        /// The reservation is about to be asked for.
        Beginning,
        /// The host's identifier is about to be kept.
        Begun,
        /// The finish is about to be sent.
        Finishing,
        /// The handle is kept and the copy removed, and the sender has not yet settled.
        Published,
    }

    /// A place in the desk's code, for the upload of one key.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Point {
        /// A cancel began, before it takes the gate. Noted, never held.
        CancelBegun,
        /// A cancel waits for the sender it stopped. Noted, never held.
        CancelWaiting,
        /// A caller is about to claim the upload for a new sender, before it takes the gate.
        Claiming,
        /// A sender was started and its handle stored, still under the gate.
        Started,
        /// A sender task is at its first line, before it asks the host for anything. Held, the task
        /// goes no further until released, and one that was stopped meanwhile never goes on.
        SenderStarting,
        /// A sender's first call to the host has answered, before it decides whether the answer asks
        /// for the places other accounts' uploads hold to be freed. Held.
        Refused,
        /// A sender is inside the write of the journal's step.
        Writing(Step),
        /// A restart read an entry's content and has not yet admitted the upload.
        Reading,
        /// An operation stopped the sender of the key and waited for it, and has not yet touched the
        /// entry.
        Stopped,
        /// A sender that failed with a connection that ended has settled: the upload is paused, or
        /// started again on the newer connection. Noted, never held.
        SenderSettled,
        /// A barrier ended: in its decision section, or in a final resolution. Noted, never held.
        DecisionDone,
        /// An operation asks for the key's turn, whether or not it is free. Noted, never held.
        TurnWanted,
        /// A sender has its result and is about to take the gate for its decision. Held.
        SettleBeforeGate,
        /// A sender task ended, however it ended: finished, stopped, or panicked. Noted, never held.
        SenderExit,
    }

    /// A place in the desk's code where an operation waits without blocking its thread, so that a
    /// suite can hold it while the runtime goes on.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Awaited {
        /// A barrier has made its attempt and has not yet decided.
        BeforeTail,
        /// The freeing, for the wanting upload's key, has stopped a key and not yet read the host.
        Freeing,
    }

    /// The operations that came to an [`Awaited`] place, and whether they may go on.
    #[derive(Default)]
    pub struct Gate {
        arrived: AtomicUsize,
        open: AtomicBool,
        changed: tokio::sync::Notify,
    }

    impl Gate {
        async fn wait_until(&self, done: impl Fn() -> bool) {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if done() {
                    return;
                }
                changed.await;
            }
        }

        /// Waits until `count` operations have come to the place.
        pub async fn until_arrived(&self, count: usize) {
            self.wait_until(|| self.arrived.load(Ordering::Acquire) >= count)
                .await;
        }

        /// Lets every operation at the place go on, and every one that comes later.
        pub fn release(&self) {
            self.open.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
    }

    type Gates = HashMap<(Uuid, Awaited), Arc<Gate>>;

    static GATES: LazyLock<Mutex<Gates>> = LazyLock::new(Mutex::default);

    /// Holds every operation that comes to `point` for the upload `key`, without blocking its
    /// thread, until the gate is released.
    pub fn hold_awaited(key: Uuid, point: Awaited) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        GATES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((key, point), Arc::clone(&gate));
        gate
    }

    /// Waits at `point` while a gate is set for `key`.
    pub(super) async fn gate(key: Uuid, point: Awaited) {
        let gate = GATES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(key, point))
            .cloned();
        if let Some(gate) = gate {
            gate.arrived.fetch_add(1, Ordering::AcqRel);
            gate.changed.notify_waiters();
            gate.wait_until(|| gate.open.load(Ordering::Acquire)).await;
        }
    }

    /// A change of behaviour that only a case that arms it sees, for the upload `key`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Fault {
        /// The owner check of a finish before the barrier is skipped.
        SkipPrecheck,
        /// The work of a barrier panics, once: a recovery that runs the work again meets no panic.
        PanicInWork,
        /// The freeing's task, for the wanting upload's key, panics before it frees a key, once.
        PanicInFreeing,
    }

    static ARMED: LazyLock<Mutex<HashSet<(Uuid, Fault)>>> = LazyLock::new(Mutex::default);

    /// A fault armed for one upload: it is disarmed when this is dropped, so a fault one case arms
    /// never reaches another that runs beside it.
    pub struct Armed(Uuid, Fault);

    impl Drop for Armed {
        fn drop(&mut self) {
            ARMED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&(self.0, self.1));
        }
    }

    /// Arms `fault` for the upload `key` until the answer is dropped.
    pub fn arm(key: Uuid, fault: Fault) -> Armed {
        ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((key, fault));
        Armed(key, fault)
    }

    /// Whether `fault` is armed for `key`, disarming it.
    pub(super) fn take(key: Uuid, fault: Fault) -> bool {
        ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(key, fault))
    }

    pub(super) fn armed(key: Uuid, fault: Fault) -> bool {
        ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(key, fault))
    }

    /// Notes that a sender task of `key` ended, when it is dropped.
    pub(super) struct ExitNote(pub(super) Uuid);

    impl Drop for ExitNote {
        fn drop(&mut self) {
            note(self.0, Point::SenderExit);
        }
    }

    /// The threads that came to a [`Point`], and whether they may go on.
    #[derive(Default)]
    pub struct Hold {
        state: Mutex<(usize, bool)>,
        changed: Condvar,
    }

    /// Runs `wait`, which blocks the calling thread. On a worker of a runtime with several workers the
    /// runtime hands the worker's queue to another thread first: the tasks queued on it, and the one
    /// that will let this thread go, must not wait for the thread to be released.
    fn blocking<R>(wait: impl FnOnce() -> R) -> R {
        match tokio::runtime::Handle::try_current() {
            Ok(runtime)
                if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
            {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        }
    }

    impl Hold {
        pub(crate) fn arrive(&self, wait: bool) {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.0 += 1;
            self.changed.notify_all();
            if wait {
                blocking(|| {
                    while !state.1 {
                        state = self
                            .changed
                            .wait(state)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                });
            }
        }

        /// How many threads came to the point.
        #[must_use]
        pub fn passed(&self) -> usize {
            self.state.lock().unwrap_or_else(PoisonError::into_inner).0
        }

        /// Waits until `count` threads have come to the point.
        pub async fn until_passed(&self, count: usize) {
            while self.passed() < count {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }

        /// Lets every thread at the point go on, and every one that comes later.
        pub fn release(&self) {
            self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
            self.changed.notify_all();
        }
    }

    type Holds = HashMap<(Uuid, Point), Arc<Hold>>;

    static HOLDS: LazyLock<Mutex<Holds>> = LazyLock::new(Mutex::default);

    /// Stops every thread that comes to `point` for the upload `key` until the hold is released, and
    /// counts it.
    pub fn hold_at(key: Uuid, point: Point) -> Arc<Hold> {
        let hold = Arc::new(Hold::default());
        HOLDS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((key, point), Arc::clone(&hold));
        hold
    }

    fn at(key: Uuid, point: Point) -> Option<Arc<Hold>> {
        HOLDS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(key, point))
            .cloned()
    }

    /// Stops the calling thread at `point` while a hold is set for `key`.
    pub(super) fn pause(key: Uuid, point: Point) {
        if let Some(hold) = at(key, point) {
            hold.arrive(true);
        }
    }

    /// Holds a sender task at its first line while a hold is set for `key`, and then gives the
    /// runtime a turn, so that a stop that came during the hold takes effect before the task asks
    /// the host for anything.
    pub(super) async fn at_sender_start(key: Uuid) {
        if let Some(hold) = at(key, Point::SenderStarting) {
            hold.arrive(true);
            tokio::task::yield_now().await;
        }
    }

    /// Counts the calling thread at `point` while a hold is set for `key`, and lets it go on.
    pub(super) fn note(key: Uuid, point: Point) {
        if let Some(hold) = at(key, point) {
            hold.arrive(false);
        }
    }

    /// How far the upload the entry stands for got.
    #[derive(Clone, Copy, Debug)]
    pub enum Got {
        /// The reservation was asked for and no answer was kept.
        Beginning,
        /// The host gave the transfer identifier.
        Begun,
        /// The finish was being sent.
        Finishing,
    }

    /// Where its content is, after the restart.
    pub enum Where {
        /// A copy in the folder, written by [`keep_copy`].
        Copy,
        /// A file on this device.
        Path(PathBuf),
    }

    /// Keeps an entry for `key` in `root`.
    ///
    /// # Panics
    ///
    /// Panics when the entry cannot be written.
    #[allow(clippy::too_many_arguments)]
    pub fn keep(
        root: &Path,
        key: Uuid,
        environment_id: EnvironmentId,
        device_id: DeviceId,
        account: Option<AccountMark>,
        target: ActionTarget,
        transfer_id: Option<TransferId>,
        got: Got,
        byte_len: u64,
        digest: Digest256,
        content: Where,
    ) {
        let file = UploadFile {
            version: STORE_VERSION,
            key,
            environment_id,
            device_id,
            account: account.map(AccountMark::to_hex),
            target,
            session_id: None,
            media_type: "application/octet-stream".to_owned(),
            file_name: "kept.bin".to_owned(),
            byte_len,
            digest,
            source: match content {
                Where::Copy => Source::Copy,
                Where::Path(path) => Source::Path { path },
            },
            reached: match got {
                Got::Beginning => Reached::Beginning,
                Got::Begun => Reached::Begun,
                Got::Finishing => Reached::Finishing,
            },
            transfer_id,
            handle: None,
            cancel_asked: false,
        };
        Store {
            root: root.to_path_buf(),
        }
        .write(&file)
        .expect("the entry is kept");
    }

    /// Keeps the copy of `key`'s content.
    ///
    /// # Panics
    ///
    /// Panics when the copy cannot be written.
    pub fn keep_copy(root: &Path, key: Uuid, bytes: &[u8]) {
        Store {
            root: root.to_path_buf(),
        }
        .write_copy(key, bytes)
        .expect("the copy is kept");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(key: Uuid, transfer: Option<TransferId>, reached: Reached) -> UploadFile {
        UploadFile {
            version: STORE_VERSION,
            key,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            device_id: DeviceId::new(kr_ipc::new_uuid()),
            account: None,
            target: ActionTarget::environment(EnvironmentId::new(kr_ipc::new_uuid())),
            session_id: None,
            media_type: "application/octet-stream".to_owned(),
            file_name: "kept.bin".to_owned(),
            byte_len: 4,
            digest: Digest256::from_bytes([0; 32]),
            source: Source::Copy,
            reached,
            transfer_id: transfer,
            handle: None,
            cancel_asked: false,
        }
    }

    /// A desk that holds one upload whose entry and copy are written in a folder of its own.
    fn held(
        transfer: Option<TransferId>,
        reached: Reached,
    ) -> (tempfile::TempDir, Arc<Desk>, Arc<Live>, Store) {
        held_for(None, transfer, reached)
    }

    /// As [`held`], for the upload of `account`.
    fn held_for(
        account: Option<String>,
        transfer: Option<TransferId>,
        reached: Reached,
    ) -> (tempfile::TempDir, Arc<Desk>, Arc<Live>, Store) {
        let dir = tempfile::tempdir().expect("a directory");
        let store = Store {
            root: dir.path().join("open-transfers"),
        };
        let desk = Arc::new(Desk::default());
        desk.keep_at(store.root.clone());
        let key = kr_ipc::new_uuid();
        let entry = UploadFile {
            account,
            ..file(key, transfer, reached)
        };
        store.write(&entry).expect("the entry");
        store.write_copy(key, b"mine").expect("the copy");
        let live = Live::new(entry, Arc::new(Held::new(vec![1; 4])), true);
        locked(&desk.registry).held.insert(key, Arc::clone(&live));
        (dir, desk, live, store)
    }

    /// KR-REQ-13.12 (A3): the resolution of a stop follows the record. An upload that was sending
    /// is paused; one that is no longer the desk's, or that the work ended, is left as it is.
    #[tokio::test]
    async fn a_resolution_follows_the_record() {
        let (_dir, desk, live, _store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        let stopping = |live: &Arc<Live>| *locked(&live.phase) = Phase::Stopping;
        let turn = desk.turn(live.key).await;
        let make = |held: Option<Arc<Live>>, ended: bool| Stopped {
            desk: Arc::clone(&desk),
            turn: &turn,
            held,
            ended,
            resolved: false,
            used: 0,
            looked: 0,
        };

        stopping(&live);
        make(Some(Arc::clone(&live)), false).resolve();
        assert_eq!(
            *locked(&live.phase),
            Phase::Paused,
            "a stopped upload is paused"
        );
        assert!(locked(&desk.registry).held.contains_key(&live.key));

        stopping(&live);
        make(Some(Arc::clone(&live)), true).resolve();
        assert_eq!(
            *locked(&live.phase),
            Phase::Stopping,
            "an upload the work ended is left to the work"
        );

        locked(&desk.registry).held.remove(&live.key);
        make(Some(Arc::clone(&live)), false).resolve();
        assert_eq!(
            *locked(&live.phase),
            Phase::Stopping,
            "an upload the desk no longer holds is left as it is"
        );
    }

    fn refused(code: ErrorCode) -> kr_client::Result<AttachmentHandle> {
        Err(ClientError::Host(ProtocolError::new(
            code,
            "the host's words",
        )))
    }

    /// KR-REQ-13.12: a key the person cancelled stays cancelled however many other keys are cancelled
    /// after it, and each other refusal at admission has its own words.
    #[test]
    fn a_cancelled_key_is_refused_after_any_number_of_other_cancels() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = Store {
            root: dir.path().join("open-transfers"),
        };
        let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
        let who = Who {
            device_id: DeviceId::new(kr_ipc::new_uuid()),
            environment_id: Some(environment_id),
            account: None,
        };
        let mine = |key| {
            let entry = UploadFile {
                device_id: who.device_id,
                environment_id,
                ..file(key, None, Reached::Beginning)
            };
            Live::new(entry, Arc::new(Held::new(vec![1; 4])), false)
        };
        let mut registry = Registry::default();

        let cancelled = kr_ipc::new_uuid();
        registry.record_cancel(cancelled);
        for _ in 0..10_000 {
            registry.record_cancel(kr_ipc::new_uuid());
        }
        let refused = registry
            .admit(&store, &mine(cancelled), &who)
            .expect_err("a cancelled key is refused");
        assert_eq!(refused.message, CANCELLED);

        let first = kr_ipc::new_uuid();
        registry
            .admit(&store, &mine(first), &who)
            .expect("admitted");
        let refused = registry
            .admit(&store, &mine(first), &who)
            .expect_err("a held key is refused");
        assert_eq!(refused.message, KEY_IN_USE);

        let kept = kr_ipc::new_uuid();
        store
            .write(&file(kept, None, Reached::Beginning))
            .expect("an entry");
        let refused = registry
            .admit(&store, &mine(kept), &who)
            .expect_err("a key an entry names is refused");
        assert_eq!(refused.message, KEY_IN_USE);

        registry
            .admit(&store, &mine(kr_ipc::new_uuid()), &who)
            .expect("the second open upload");
        let refused = registry
            .admit(&store, &mine(kr_ipc::new_uuid()), &who)
            .expect_err("a third open upload is refused");
        assert_eq!(refused.message, TOO_MANY_OPEN);
    }

    /// A folder of its own with one entry kept in it for `account`, and a desk over it.
    fn kept_for(
        account: Option<String>,
        reached: Reached,
    ) -> (tempfile::TempDir, Arc<Desk>, Store, UploadFile) {
        let dir = tempfile::tempdir().expect("a directory");
        let store = Store {
            root: dir.path().join("open-transfers"),
        };
        let desk = Arc::new(Desk::default());
        desk.keep_at(store.root.clone());
        let entry = UploadFile {
            account,
            ..file(
                kr_ipc::new_uuid(),
                Some(TransferId::new(kr_ipc::new_uuid())),
                reached,
            )
        };
        store.write(&entry).expect("the entry");
        (dir, desk, store, entry)
    }

    fn who_of(entry: &UploadFile, account: Option<AccountMark>) -> Who {
        Who {
            device_id: entry.device_id,
            environment_id: Some(entry.environment_id),
            account,
        }
    }

    /// KR-REQ-13.12: a cancel from a sign-in with no account finds no upload of an account: nothing is
    /// recorded, and the entry stays.
    #[tokio::test]
    async fn a_cancel_with_no_account_finds_no_upload_of_an_account() {
        let (_dir, desk, store, entry) = kept_for(Some("ab".repeat(32)), Reached::Begun);
        let refused = desk
            .cancel(who_of(&entry, None), None, entry.key)
            .await
            .expect_err("another account's upload is not found");
        assert_eq!(refused.message, NO_OPEN_UPLOAD);
        assert!(!desk.is_cancelled(entry.key), "no key is recorded");
        assert!(
            store
                .entry(entry.key)
                .is_some_and(|kept| !kept.cancel_asked)
        );
    }

    /// KR-REQ-13.12: a cancel whose record cannot be written still cancels the key: it answers asked
    /// with the words, and the upload is read as cancelled, not as waiting.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_cancel_whose_record_cannot_be_written_is_read_as_asked() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_dir, desk, store, entry) = kept_for(None, Reached::Begun);
        let who = who_of(&entry, None);
        std::fs::set_permissions(&store.root, std::fs::Permissions::from_mode(0o555))
            .expect("the folder is read only");
        let answer = desk.cancel(who.clone(), None, entry.key).await;
        std::fs::set_permissions(&store.root, std::fs::Permissions::from_mode(0o755))
            .expect("the folder is writable again");
        let answer = answer.expect("the cancel is answered");
        assert_eq!(answer.state, "asked");
        assert!(answer.said.is_some(), "the failure is said");
        assert!(desk.is_cancelled(entry.key));
        let views = desk.open(&who);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].state, OpenState::CancelAsked);
        assert!(
            store
                .entry(entry.key)
                .is_some_and(|kept| !kept.cancel_asked)
        );
    }

    /// KR-REQ-13.12: with no connection a cancel of an upload whose reservation was never answered is
    /// forgotten at once, and one the host holds is kept, read as asked, with nothing asked of the host.
    #[tokio::test]
    async fn a_cancel_with_no_connection_keeps_what_the_host_holds_and_forgets_the_rest() {
        let (_dir, desk, store, entry) = kept_for(None, Reached::Begun);
        let who = who_of(&entry, None);
        let answer = desk
            .cancel(who.clone(), None, entry.key)
            .await
            .expect("answered");
        assert_eq!(answer.state, "asked");
        assert!(store.entry(entry.key).is_some_and(|kept| kept.cancel_asked));
        assert_eq!(desk.open(&who)[0].state, OpenState::CancelAsked);

        let (_dir, desk, store, entry) = kept_for(None, Reached::Beginning);
        let entry = UploadFile {
            transfer_id: None,
            ..entry
        };
        store.write(&entry).expect("an entry with no identifier");
        let answer = desk
            .cancel(who_of(&entry, None), None, entry.key)
            .await
            .expect("answered");
        assert_eq!(answer.state, "forgotten");
        assert!(store.entry(entry.key).is_none());
    }

    /// KR-REQ-13.12: only the host's own words for an unknown transfer say it knows nothing of the
    /// upload; a refusal of a right does not.
    #[test]
    fn only_an_unknown_transfer_answer_says_the_host_knows_nothing() {
        let said = |code, words: &str| {
            host_does_not_know(&ClientError::Host(ProtocolError::new(code, words)))
        };
        assert!(said(ErrorCode::InvalidArgument, "no transfer 7"));
        assert!(!said(ErrorCode::PermissionDenied, "no transfer 7"));
        assert!(!said(
            ErrorCode::InvalidArgument,
            "the contribution does not admit the file"
        ));
    }

    /// KR-REQ-13.12: a status read the host refuses for want of a right keeps the entry and the copy of
    /// an upload the host may hold; only its own words for an unknown transfer drop them.
    #[test]
    fn a_status_refused_for_a_right_keeps_the_entry_and_the_copy() {
        let (_dir, _desk, live, store) = held(
            Some(TransferId::new(kr_ipc::new_uuid())),
            Reached::Finishing,
        );
        let key = live.file().key;
        let denied = ClientError::Host(ProtocolError::new(ErrorCode::PermissionDenied, "no right"));
        assert!(!drop_if_unknown(&store, key, &denied));
        assert!(store.path(key, UPLOAD_EXTENSION).exists());
        assert!(store.path(key, COPY_EXTENSION).exists());
        let unknown = ClientError::Host(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "no transfer 7",
        ));
        assert!(drop_if_unknown(&store, key, &unknown));
        assert!(!store.path(key, UPLOAD_EXTENSION).exists());
        assert!(!store.path(key, COPY_EXTENSION).exists());
    }

    /// KR-REQ-13.12: a failed write of the transfer identifier loses nothing the host holds: the
    /// identifier stays held, the upload stays held and paused, and the write is made again.
    #[test]
    fn a_failed_write_of_the_transfer_id_keeps_the_reservation_held() {
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        let journal = Kept {
            live: Arc::clone(&live),
            store: store.clone(),
        };
        let id = TransferId::new(kr_ipc::new_uuid());
        // The folder becomes a file, so the next write cannot be made.
        std::fs::remove_dir_all(&store.root).expect("the folder goes");
        std::fs::write(&store.root, b"in the way").expect("a file in its place");
        assert!(journal.begun(id).is_err());
        assert_eq!(live.transfer(), Some(id), "the host's identifier is held");
        assert_eq!(live.file().transfer_id, None, "and not yet kept");

        desk.settle_as(
            &live,
            0,
            false,
            Err(not_kept(&std::io::Error::other("disk full"))),
        );
        assert_eq!(*locked(&live.phase), Phase::Paused);
        assert!(
            locked(&desk.registry).held.contains_key(&live.file().key),
            "still held"
        );

        std::fs::remove_file(&store.root).expect("the way is cleared");
        journal.begun(id).expect("the write is made again");
        assert_eq!(live.file().transfer_id, Some(id));
        assert!(store.path(live.file().key, UPLOAD_EXTENSION).exists());
    }

    /// KR-REQ-13.12: a journal write that succeeds after a failed one clears the failure, so a later
    /// connection failure is told as a connection failure and the upload goes on a newer connection.
    #[test]
    fn a_successful_journal_retry_clears_the_failure() {
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        let _ = &desk;
        let journal = Kept {
            live: Arc::clone(&live),
            store: store.clone(),
        };
        let id = TransferId::new(kr_ipc::new_uuid());
        let folder = store.root.clone();
        std::fs::remove_dir_all(&folder).expect("the folder goes");
        std::fs::write(&folder, b"in the way").expect("a file in its place");
        assert!(journal.begun(id).is_err());
        assert!(
            live.journal_failed.load(Ordering::Acquire),
            "the failure is noted"
        );
        std::fs::remove_file(&folder).expect("the way is cleared");
        journal.begun(id).expect("the write is made again");
        assert!(
            !live.journal_failed.load(Ordering::Acquire),
            "a write that succeeds clears the failure"
        );
    }

    /// KR-REQ-13.12: a request that never left is asked again and is no unrecoverable reservation; one
    /// whose answer is not known is, and keeps its entry; a refusal for good with a transfer is a failed
    /// upload that keeps its entry; a refusal of the reservation leaves nothing.
    #[test]
    fn a_send_ends_as_what_the_host_and_the_connection_said() {
        // The connection ended before the reservation left: paused, to ask again.
        let (_dir, desk, live, _store) = held(None, Reached::Beginning);
        desk.settle_as(&live, 0, false, Err(ClientError::ConnectionEnded));
        assert_eq!(*locked(&live.phase), Phase::Paused);
        assert!(locked(&desk.registry).held.contains_key(&live.file().key));

        // The reservation may have been made and its answer is lost: the entry stays.
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        let lost = ClientError::SubmissionUncertain {
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        };
        desk.settle_as(&live, 0, false, Err(lost));
        assert!(!locked(&desk.registry).held.contains_key(&live.file().key));
        assert!(store.path(live.file().key, UPLOAD_EXTENSION).exists());

        // The host refused for good while it holds the reservation: a failed upload, entry kept.
        let (_dir, desk, live, store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        desk.settle_as(&live, 0, false, refused(ErrorCode::QuotaExceeded));
        assert_eq!(
            locked(&desk.verdicts).get(&live.file().key),
            Some(&Verdict::Failed("the host's words".to_owned()))
        );
        assert!(store.path(live.file().key, UPLOAD_EXTENSION).exists());

        // The host refused the reservation: nothing is left.
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        desk.settle_as(&live, 0, false, refused(ErrorCode::QuotaExceeded));
        assert!(!store.path(live.file().key, UPLOAD_EXTENSION).exists());
        assert!(!store.path(live.file().key, COPY_EXTENSION).exists());

        // The sign-in it was sent under ended and it had no account: it stops for good, with its copy.
        let (_dir, desk, live, store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        desk.settle_as(&live, 0, true, Err(ClientError::ConnectionEnded));
        assert!(!store.path(live.file().key, UPLOAD_EXTENSION).exists());
        assert!(!store.path(live.file().key, COPY_EXTENSION).exists());
    }

    /// KR-REQ-13.12: only the host's refusal of a begin for the device's count of open transfers
    /// frees another account's places: the file-size and staged-byte limits, which answer with the
    /// code of a quota, and a refusal for another temporary cause, do not.
    #[test]
    fn only_the_count_refusal_of_a_begin_frees_other_accounts_places() {
        let said = |code, words: &str| ClientError::Host(ProtocolError::new(code, words));
        assert!(is_the_count_refusal(&said(
            ErrorCode::ResourceUnavailable,
            "this device already holds 2 of 2 concurrent transfers; finish or cancel one first"
        )));
        assert!(!is_the_count_refusal(&said(
            ErrorCode::QuotaExceeded,
            "a file is at most 10 bytes in this environment, and this one declares 20"
        )));
        assert!(!is_the_count_refusal(&said(
            ErrorCode::QuotaExceeded,
            "this environment stages at most 10 bytes in all, and the 20 this upload declares do \
             not fit in what is left of that"
        )));
        assert!(!is_the_count_refusal(&said(
            ErrorCode::QuotaExceeded,
            "this device already holds 2 of 2 concurrent transfers"
        )));
        assert!(!is_the_count_refusal(&said(
            ErrorCode::ResourceUnavailable,
            "the host is busy"
        )));
    }

    /// KR-REQ-13.12: a send of an account that this device ended, by a sign-out or the sign-in of
    /// another account, is paused with its entry and its copy, as one whose connection ended: it goes
    /// on when its account reaches the host again.
    #[test]
    fn a_send_ended_by_a_sign_in_change_is_paused_and_kept() {
        let (_dir, desk, live, store) = held_for(
            Some("ab".repeat(32)),
            Some(TransferId::new(kr_ipc::new_uuid())),
            Reached::Begun,
        );
        desk.settle_as(&live, 0, true, Err(ClientError::ConnectionEnded));
        let key = live.file().key;
        assert_eq!(*locked(&live.phase), Phase::Paused);
        assert!(locked(&desk.registry).held.contains_key(&key));
        assert!(store.path(key, UPLOAD_EXTENSION).exists());
        assert!(store.path(key, COPY_EXTENSION).exists());
    }

    /// KR-REQ-13.12: the failure a sender ends its command with is written in the gate
    /// section that validates the sender's generation. An old sender that is held between its check
    /// and the gate while a stop moves the generation on and the sender that replaced it ends the
    /// upload writes nothing over that outcome.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_old_sender_never_overwrites_the_outcome_of_the_one_that_replaced_it() {
        let (_dir, desk, live, _store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        live.journal_failed.store(true, Ordering::Release);
        let hold = testing::hold_at(live.key, testing::Point::SettleBeforeGate);
        let old = {
            let (desk, live) = (Arc::clone(&desk), Arc::clone(&live));
            tokio::spawn(async move {
                desk.settle_as(&live, 0, false, Err(ClientError::ConnectionEnded));
            })
        };
        hold.until_passed(1).await;
        // A stop moved the generation on, and the sender that replaced the old one ended the upload.
        live.generation.fetch_add(2, Ordering::AcqRel);
        desk.end(&live, Outcome::Cancelled);
        hold.release();
        old.await.expect("the old sender settled");
        assert!(
            matches!(*live.outcome.borrow(), Some(Outcome::Cancelled)),
            "the newer outcome stands"
        );
    }

    /// A thread held at a point of the sender's task is a worker of the runtime: the case that lets it
    /// go is a task of the same runtime, and it must still run. On a runtime of one worker a hold that
    /// keeps its worker would wait for ever.
    #[cfg(feature = "testing")]
    #[test]
    fn a_hold_at_a_point_leaves_the_runtime_free_to_run_the_task_that_lets_it_go() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("a runtime of one worker");
        let hold = Arc::new(testing::Hold::default());
        let (done, finished) = std::sync::mpsc::channel();
        let (holding, releasing) = (Arc::clone(&hold), Arc::clone(&hold));
        runtime.spawn(async move {
            holding.arrive(true);
            let _ = done.send(());
        });
        runtime.spawn(async move {
            releasing.until_passed(1).await;
            releasing.release();
        });
        let went_on = finished.recv_timeout(std::time::Duration::from_secs(10));
        runtime.shutdown_background();
        assert!(
            went_on.is_ok(),
            "the thread at the hold goes on once the hold is released"
        );
    }
}
