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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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

/// Whether the upload's send is running or waits for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Sending,
    Paused,
}

/// One upload this process holds.
struct Live {
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
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Live {
    fn new(file: UploadFile, content: Arc<dyn Content>, beginning_kept: bool) -> Arc<Self> {
        Arc::new(Self {
            file: Mutex::new(file),
            content: Mutex::new(content),
            progress: watch::channel(Progress::default()).0,
            outcome: watch::channel(None).0,
            task: Mutex::new(None),
            phase: Mutex::new(Phase::Sending),
            beginning_kept: AtomicBool::new(beginning_kept),
            issued: Mutex::new(None),
            journal_failed: AtomicBool::new(false),
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
        *file = next;
        Ok(())
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
        self.kept(|file| file.reached = Reached::Beginning)?;
        self.live.beginning_kept.store(true, Ordering::Release);
        Ok(())
    }

    fn begun(&self, transfer_id: TransferId) -> kr_client::Result<()> {
        // The host's answer is held first: a write that fails loses nothing the host holds.
        *locked(&self.live.issued) = Some(transfer_id);
        self.kept(|file| {
            file.transfer_id = Some(transfer_id);
            file.reached = Reached::Begun;
        })
    }

    fn finishing(&self, transfer_id: TransferId) -> kr_client::Result<()> {
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
}

impl Paired {
    /// The account as an entry keeps it.
    #[must_use]
    pub fn account_id(&self) -> Option<String> {
        self.account.map(AccountMark::to_hex)
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
        self.device_id == who.device_id
            && who
                .environment_id
                .is_none_or(|environment_id| environment_id == self.environment_id)
            && self.account == who.account.map(AccountMark::to_hex)
    }
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
    /// finished and is kept, `forgotten` when the host holds nothing this device can name.
    pub state: &'static str,
    /// The bytes the host released, from its answer.
    pub released_byte_len: Option<String>,
    /// The handle, for a `published` upload.
    pub handle: Option<AttachmentHandle>,
}

/// The state of every upload this device sends to a paired host.
#[derive(Default)]
pub struct Desk {
    root: Mutex<Option<PathBuf>>,
    live: Mutex<HashMap<Uuid, Arc<Live>>>,
    /// What a restart or a failure found of entries it could not resume.
    verdicts: Mutex<HashMap<Uuid, Verdict>>,
    /// The newest connection of each host's device, so that an upload whose connection ended while
    /// a newer one was coming up goes on at once.
    sessions: Mutex<HashMap<(EnvironmentId, DeviceId), Arc<Session>>>,
    /// What a suite holds a send at, once the copy of its content is written.
    #[cfg(feature = "testing")]
    after_copy: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
}

impl std::fmt::Debug for Desk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Desk")
            .field("open", &locked(&self.live).len())
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

    /// Sends one file to the paired host and answers with the verified handle.
    ///
    /// The upload belongs to the desk, not to this call: dropping the call leaves it running, and a
    /// connection that ends pauses it until the host is reached again.
    ///
    /// # Errors
    ///
    /// Refuses a key that is in use and a third open upload, and returns the host's refusal or the
    /// reason this device ended the connection.
    pub async fn send(
        self: &Arc<Self>,
        paired: Paired,
        request: Request,
    ) -> Result<AttachmentHandle> {
        let store = self.store()?;
        let key = request.key;
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
        // The place and the key are taken together, here and before any await: no other send can
        // pass the count or use the key until this one is in the map.
        {
            let mut held = locked(&self.live);
            let found = store.all();
            if held.contains_key(&key) || found.holds(key) {
                return Err(CommandError::refused(KEY_IN_USE));
            }
            if Self::open_count(&held, &found, &paired) >= MOST_OPEN {
                return Err(CommandError::refused(TOO_MANY_OPEN));
            }
            held.insert(key, Arc::clone(&live));
        }
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
                locked(&self.live).remove(&key);
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
        // A cancel that came while the copy was written found no sender to stop: the upload does not
        // start, and its copy goes.
        if live.file().cancel_asked || !locked(&self.live).contains_key(&key) {
            let _ = store.remove_copy(key);
            return Err(CommandError::refused(CANCELLED));
        }
        locked(&self.sessions).insert(
            (paired.environment_id, paired.device_id),
            Arc::clone(&paired.session),
        );
        self.start(&live, paired.session, false);
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

    /// The open uploads of this device on this host: the ones this process holds and the ones kept
    /// from before whose upload is not published.
    fn open_count(held: &HashMap<Uuid, Arc<Live>>, found: &Found, paired: &Paired) -> usize {
        let mut keys: Vec<Uuid> = held
            .iter()
            .filter(|(_, live)| {
                let file = locked(&live.file);
                file.is_of(paired) && file.reached != Reached::Published
            })
            .map(|(key, _)| *key)
            .collect();
        for file in &found.entries {
            if file.is_of(paired) && file.reached != Reached::Published && !keys.contains(&file.key)
            {
                keys.push(file.key);
            }
        }
        keys.len()
    }

    /// Starts the send of `live` on `session`. A resume of a file read from where it is reads it
    /// again first, and sends nothing when it is not the one declared.
    fn start(self: &Arc<Self>, live: &Arc<Live>, session: Arc<Session>, verify: bool) {
        *locked(&live.phase) = Phase::Sending;
        let desk = Arc::clone(self);
        let running = Arc::clone(live);
        let task = tauri::async_runtime::spawn(async move {
            if verify && !desk.is_the_content(&running).await {
                return;
            }
            let result = desk.send_once(&running, &session).await;
            desk.settle(&running, &session, result);
        });
        *locked(&live.task) = Some(task);
    }

    /// Whether the content of an upload that resumes is the one declared; when it is not, the upload
    /// ends and its entry says it cannot resume.
    async fn is_the_content(&self, live: &Arc<Live>) -> bool {
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
        self.end(live, Outcome::Failed(CommandError::refused(CANNOT_RESUME)));
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
        result: kr_client::Result<AttachmentHandle>,
    ) {
        // A sign-out gives the transport's reason, which the driver returns in place of the plain
        // end; what this device ended is never waited out.
        let by_this_device = session.transport().ended_by_this_device().is_some();
        self.settle_as(live, Some(session), by_this_device, result);
    }

    fn settle_as(
        self: &Arc<Self>,
        live: &Arc<Live>,
        session: Option<&Arc<Session>>,
        by_this_device: bool,
        result: kr_client::Result<AttachmentHandle>,
    ) {
        let file = live.file();
        let error = match result {
            Ok(handle) => return self.end(live, Outcome::Published(Box::new(handle))),
            Err(error) => error,
        };
        if by_this_device {
            // The sign-in this upload was sent under is not the one in force: it stops for good, and
            // the copy of the person's file goes with it.
            if let Ok(store) = self.store() {
                let _ = store.remove(file.key);
            }
            return self.end(live, Outcome::Failed(CommandError::from(error)));
        }
        let transfer = live.transfer();
        if live.journal_failed.load(Ordering::Acquire) {
            if transfer.is_some() {
                // The host holds what this device could not write down: it stays here, paused, and
                // the next send keeps the identifier before anything else.
                *locked(&live.phase) = Phase::Paused;
                live.outcome
                    .send_replace(Some(Outcome::Failed(CommandError::from(error))));
            } else {
                // Nothing was asked of the host.
                if let Ok(store) = self.store() {
                    let _ = store.remove(file.key);
                }
                self.end(live, Outcome::Failed(CommandError::from(error)));
            }
            return;
        }
        // A request that never left is asked again; a finish or a chunk that did leave is read from
        // the host's own record when the connection comes back.
        let resumable = match error {
            ClientError::ConnectionEnded => true,
            ClientError::SubmissionUncertain { .. } => transfer.is_some(),
            _ => false,
        };
        if resumable {
            *locked(&live.phase) = Phase::Paused;
            let newest = locked(&self.sessions)
                .get(&(file.environment_id, file.device_id))
                .cloned();
            if let (Some(newest), Some(failed)) = (newest, session)
                && !Arc::ptr_eq(&newest, failed)
            {
                // The connection that came up first is the one this upload goes on, at once.
                self.start(live, newest, true);
            }
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
        self.end(live, Outcome::Failed(failure));
    }

    /// Ends the hold on `live` and tells whoever waits.
    fn end(&self, live: &Arc<Live>, outcome: Outcome) {
        let key = locked(&live.file).key;
        locked(&self.live).remove(&key);
        live.outcome.send_replace(Some(outcome));
    }

    /// The host was reached on `paired`'s connection: paused uploads resume on it, and entries kept
    /// from before are read against the host's own record and resumed or dropped. What belongs to
    /// another principal or to another account of this host is stopped and dropped, never resumed.
    pub fn host_reached(self: &Arc<Self>, paired: Paired) {
        let (device_id, environment_id) = (paired.device_id, paired.environment_id);
        let session = Arc::clone(&paired.session);
        locked(&self.sessions).insert((environment_id, device_id), Arc::clone(&session));
        let (paused, other): (Vec<Arc<Live>>, Vec<Arc<Live>>) = {
            let held = locked(&self.live);
            let in_host = held
                .values()
                .filter(|live| locked(&live.file).environment_id == environment_id);
            let (mine, other): (Vec<_>, Vec<_>) = in_host
                .cloned()
                .partition(|live| locked(&live.file).is_of(&paired));
            (
                mine.into_iter()
                    .filter(|live| *locked(&live.phase) == Phase::Paused)
                    .collect(),
                other,
            )
        };
        // An upload of another principal or another account on this host belongs to a sign-in that is
        // not in force.
        for live in &other {
            if let Some(task) = locked(&live.task).take() {
                task.abort();
            }
            if let Ok(store) = self.store() {
                let _ = store.remove(locked(&live.file).key);
            }
            self.end(live, Outcome::Cancelled);
        }
        for live in &paused {
            if live.file().cancel_asked {
                let desk = Arc::clone(self);
                let (live, paired) = (Arc::clone(live), paired.clone());
                tauri::async_runtime::spawn(async move {
                    if let Ok(store) = desk.store() {
                        let file = live.file();
                        let _ = desk.finish_cancel(&store, &paired, Some(live), file).await;
                    }
                });
            } else {
                self.start(live, Arc::clone(&session), true);
            }
        }
        if locked(&self.root).is_none() {
            return;
        }
        let desk = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
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
            let held = locked(&self.live);
            for key in found.orphans.iter().chain(&found.spent) {
                if !held.contains_key(key) {
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
                || locked(&self.live).contains_key(&file.key)
            {
                continue;
            }
            if file.device_id != paired.device_id || file.account != paired.account_id() {
                // Another principal's, or another account's: the sign-in it was kept under is not
                // the one in force.
                let _ = store.remove(file.key);
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

    async fn act_on(
        self: &Arc<Self>,
        store: &Store,
        paired: &Paired,
        file: UploadFile,
        status: Option<kr_client::Result<UploadStatusResult>>,
    ) {
        let key = file.key;
        if file.cancel_asked {
            let _ = self.finish_cancel(store, paired, None, file).await;
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
                            locked(&self.verdicts).remove(&key);
                            let live = Live::new(file, content, true);
                            locked(&self.live).insert(key, Arc::clone(&live));
                            self.start(&live, Arc::clone(&paired.session), false);
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
        let live = locked(&self.live).clone();
        for (key, held) in &live {
            let file = held.file();
            if !file.is_whose(who) {
                continue;
            }
            let progress = *held.progress.borrow();
            let state = match *locked(&held.phase) {
                Phase::Sending => OpenState::Sending,
                Phase::Paused => OpenState::Paused,
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
    /// The send is stopped and waited for first, so that what it kept is final when it is read. A
    /// cancel that cannot be finished is recorded in the entry and finished at the next reach, and
    /// the upload is never sent on.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, and the failure when the connection ended before the answer, which
    /// leaves the cancel to be finished: the host's record says what became of it.
    pub async fn cancel(self: &Arc<Self>, paired: Paired, key: Uuid) -> Result<Cancelled> {
        let store = self.store()?;
        let held = locked(&self.live).get(&key).cloned();
        let none = || CommandError::invalid("no open upload has that key");
        if let Some(live) = &held {
            let file = live.file();
            if !file.is_of(&paired) {
                return Err(none());
            }
            let task = locked(&live.task).take();
            if let Some(task) = task {
                task.abort();
                // Whatever the sender was doing is over before the entry is read.
                let _ = task.await;
            }
        }
        let file = match &held {
            Some(live) => live.file(),
            None => store
                .all()
                .entries
                .into_iter()
                .find(|file| file.key == key)
                .ok_or_else(none)?,
        };
        if !file.is_of(&paired) {
            return Err(none());
        }
        if file.reached == Reached::Published {
            return Ok(Self::said(key, "published", None, file.handle));
        }
        if !file.cancel_asked {
            // Recorded before the host is asked, so that a cancel that cannot be finished is not lost.
            let asked = match &held {
                Some(live) => live.change(&store, |file| file.cancel_asked = true),
                None => store.write(&UploadFile {
                    cancel_asked: true,
                    ..file.clone()
                }),
            };
            if let Err(error) = asked {
                if let Some(live) = &held {
                    *locked(&live.phase) = Phase::Paused;
                }
                return Err(record_not_kept(&error));
            }
        }
        let file = match &held {
            Some(live) => live.file(),
            None => UploadFile {
                cancel_asked: true,
                ..file
            },
        };
        self.finish_cancel(&store, &paired, held, file).await
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
        }
    }

    /// The host's record is read, and then the upload is cancelled unless it is published.
    async fn finish_cancel(
        self: &Arc<Self>,
        store: &Store,
        paired: &Paired,
        held: Option<Arc<Live>>,
        file: UploadFile,
    ) -> Result<Cancelled> {
        let key = file.key;
        let pause = |held: &Option<Arc<Live>>| {
            if let Some(live) = held {
                *locked(&live.phase) = Phase::Paused;
            }
        };
        let transfer = held
            .as_ref()
            .and_then(|live| live.transfer())
            .or(file.transfer_id);
        let Some(transfer_id) = transfer else {
            // A reservation whose answer never came: nothing this device can name is held.
            self.forget(store, &held, key);
            return Ok(Self::said(key, "forgotten", None, None));
        };
        // The host's record is read before anything is cancelled.
        let read: UploadStatusResult = match paired
            .session
            .read(Method::UploadStatus, &UploadStatusParams { transfer_id })
            .await
        {
            Ok(read) => read,
            Err(error) if host_does_not_know(&error) => {
                self.forget(store, &held, key);
                return Ok(Self::said(key, "forgotten", None, None));
            }
            // Including a refusal of a right: the host may hold it, and the entry stays.
            Err(error) => {
                pause(&held);
                return Err(error.into());
            }
        };
        if read.state == UploadState::Published {
            let Some(handle) = read.handle.as_ref().cloned() else {
                pause(&held);
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
                pause(&held);
                return Err(record_not_kept(&error));
            }
            let _ = store.remove_copy(key);
            if let Some(live) = &held {
                *locked(&live.file) = kept;
                self.end(live, Outcome::Published(Box::new(handle.clone())));
            }
            return Ok(Self::said(key, "published", None, Some(handle)));
        }
        let answer: UploadCancelResult = match uploads::cancel(
            &paired.session,
            &file.target,
            transfer_id,
            crate::commands::MUTATION_TTL,
        )
        .await
        {
            Ok(answer) => answer,
            Err(error) => {
                pause(&held);
                return Err(error.into());
            }
        };
        self.forget(store, &held, key);
        Ok(Self::said(
            key,
            "cancelled",
            Some(answer.released_byte_len.get().to_string()),
            None,
        ))
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

    /// The handle of the published upload `transfer_id` was bound to a draft: its entry ends.
    pub fn bound(&self, transfer_id: TransferId) {
        let Ok(store) = self.store() else { return };
        for file in store.all().entries {
            if file.transfer_id == Some(transfer_id) && file.reached == Reached::Published {
                let _ = store.remove(file.key);
            }
        }
    }

    /// The host this device knows as `device_id` was forgotten: what is sent to it stops, and every
    /// entry and copy kept for it goes.
    pub fn forgotten(&self, device_id: DeviceId) {
        let sending: Vec<Arc<Live>> = locked(&self.live)
            .values()
            .filter(|live| locked(&live.file).device_id == device_id)
            .cloned()
            .collect();
        for live in &sending {
            if let Some(task) = locked(&live.task).take() {
                task.abort();
            }
            self.end(live, Outcome::Cancelled);
        }
        let Ok(store) = self.store() else { return };
        for file in store.all().entries {
            if file.device_id == device_id {
                locked(&self.verdicts).remove(&file.key);
                let _ = store.remove(file.key);
            }
        }
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
            .is_some_and(|newest| Arc::ptr_eq(newest, &paired.session))
    }
}

/// What a suite keeps in the folder to stand for an upload that an earlier process left.
#[cfg(feature = "testing")]
pub mod testing {
    use super::{Reached, STORE_VERSION, Source, Store, UploadFile};
    use kr_client::services::AccountMark;
    use kr_protocol::envelope::ActionTarget;
    use kr_protocol::ids::{DeviceId, EnvironmentId, TransferId};
    use kr_protocol::scalars::{Digest256, Uuid};
    use std::path::{Path, PathBuf};

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
        let dir = tempfile::tempdir().expect("a directory");
        let store = Store {
            root: dir.path().join("open-transfers"),
        };
        let desk = Arc::new(Desk::default());
        desk.keep_at(store.root.clone());
        let key = kr_ipc::new_uuid();
        let entry = file(key, transfer, reached);
        store.write(&entry).expect("the entry");
        store.write_copy(key, b"mine").expect("the copy");
        let live = Live::new(entry, Arc::new(Held::new(vec![1; 4])), true);
        locked(&desk.live).insert(key, Arc::clone(&live));
        (dir, desk, live, store)
    }

    fn refused(code: ErrorCode) -> kr_client::Result<AttachmentHandle> {
        Err(ClientError::Host(ProtocolError::new(
            code,
            "the host's words",
        )))
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
            None,
            false,
            Err(not_kept(&std::io::Error::other("disk full"))),
        );
        assert_eq!(*locked(&live.phase), Phase::Paused);
        assert!(
            locked(&desk.live).contains_key(&live.file().key),
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
        desk.settle_as(&live, None, false, Err(ClientError::ConnectionEnded));
        assert_eq!(*locked(&live.phase), Phase::Paused);
        assert!(locked(&desk.live).contains_key(&live.file().key));

        // The reservation may have been made and its answer is lost: the entry stays.
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        let lost = ClientError::SubmissionUncertain {
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        };
        desk.settle_as(&live, None, false, Err(lost));
        assert!(!locked(&desk.live).contains_key(&live.file().key));
        assert!(store.path(live.file().key, UPLOAD_EXTENSION).exists());

        // The host refused for good while it holds the reservation: a failed upload, entry kept.
        let (_dir, desk, live, store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        desk.settle_as(&live, None, false, refused(ErrorCode::QuotaExceeded));
        assert_eq!(
            locked(&desk.verdicts).get(&live.file().key),
            Some(&Verdict::Failed("the host's words".to_owned()))
        );
        assert!(store.path(live.file().key, UPLOAD_EXTENSION).exists());

        // The host refused the reservation: nothing is left.
        let (_dir, desk, live, store) = held(None, Reached::Beginning);
        desk.settle_as(&live, None, false, refused(ErrorCode::QuotaExceeded));
        assert!(!store.path(live.file().key, UPLOAD_EXTENSION).exists());
        assert!(!store.path(live.file().key, COPY_EXTENSION).exists());

        // The sign-in it was sent under ended: it stops for good, with its copy.
        let (_dir, desk, live, store) =
            held(Some(TransferId::new(kr_ipc::new_uuid())), Reached::Begun);
        desk.settle_as(&live, None, true, Err(ClientError::ConnectionEnded));
        assert!(!store.path(live.file().key, UPLOAD_EXTENSION).exists());
        assert!(!store.path(live.file().key, COPY_EXTENSION).exists());
    }
}
