//! The files this device sends to a host it is paired with, from the first byte to the handle, and
//! what is kept of each across a restart.
//!
//! An upload outlives the command that starts it. The [`Desk`] owns it between commands: the
//! plan's subject, the content, the progress the driver publishes, and the handle that stops it.
//! A command waits on the upload's outcome and may be dropped; the upload goes on. A connection
//! that ends pauses it, and the next connection to the host, through [`Desk::host_reached`],
//! resumes it with [`Upload::resuming`] under the same transfer identifier and the content the
//! process still holds.
//!
//! * **One layout, version 1.** `open-transfers/` holds `<key>.upload` (what the entry is for, the
//!   transfer identifier once the host gave one, how far the transfer got and the handle once it is
//!   published) and `<key>.bytes` (a copy of a file the page handed over as bytes). Every file of
//!   an entry is JSON with exactly the members it names: a file with another `version`, a member
//!   more or fewer, or a name that is not its key is counted and left, never read or changed,
//!   because a later release may own it.
//! * **Written before the call that needs it.** The driver tells the [`Kept`] journal that it is
//!   about to ask for a reservation, what the transfer identifier is, and that it is about to send
//!   the finish, each before the call; a write that fails stops the send before the call.
//! * **A restart reads before it acts.** The host is asked for the state of every entry first.
//!   A published upload keeps its handle and is never cancelled; one the host still receives
//!   resumes with exactly what the host lacks when the content is still here and its digest is the
//!   one declared; one the host does not know, or has ended, is dropped; and a reservation whose
//!   answer never came cannot be found again, which the entry says.
//! * **Missing, stale and rolled back.** An application that finds no folder has no entry to
//!   resume, which is how a release before this one behaves. An entry names the host, the device
//!   and the content's digest it describes, and is acted on only against that host. A release
//!   before this one leaves the folder alone; the host ends what it holds after its own
//!   twenty-four hours.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_client::chunks::ChunkRoute;
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
    "two files are being sent to this host already: wait for one to finish, or cancel one";

/// What an entry says when the content to send on is gone or is not what was declared.
pub const CANNOT_RESUME: &str = "this file cannot be resumed from where it stopped, because the copy this device kept is gone or has changed: cancel it and send the file again";

/// What an entry says when the host was asked for a reservation and its answer never came.
pub const UNRECOVERABLE: &str = "the host was asked to take this file and did not answer before this application stopped: it keeps the place for up to 24 hours and then releases it";

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
}

/// The folder of entries and what is done to it.
#[derive(Clone, Debug)]
struct Store {
    root: PathBuf,
}

/// What a read of the folder found.
struct Found {
    entries: Vec<UploadFile>,
    /// Files of another layout, left alone.
    left: usize,
    /// Copies whose entry is not there.
    orphans: Vec<Uuid>,
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
            left: 0,
            orphans: Vec::new(),
        };
        let Ok(listing) = std::fs::read_dir(&self.root) else {
            return found;
        };
        let mut copies = Vec::new();
        for item in listing.flatten() {
            let path = item.path();
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
                COPY_EXTENSION => copies.push(key),
                // The drafts kept beside the uploads are another module's.
                "draft" => {}
                UPLOAD_EXTENSION => match read_entry(&path, key) {
                    Some(file) => found.entries.push(file),
                    None => found.left += 1,
                },
                _ => found.left += 1,
            }
        }
        found.entries.sort_by_key(|file| file.key);
        found.orphans = copies
            .into_iter()
            .filter(|key| found.entries.iter().all(|file| file.key != *key))
            .collect();
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
    content: Arc<dyn Content>,
    progress: watch::Sender<Progress>,
    outcome: watch::Sender<Option<Outcome>>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
    phase: Mutex<Phase>,
    /// The reservation was kept as asked for: whatever the answer, a new plan may not ask again.
    beginning_kept: AtomicBool,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Live {
    fn file(&self) -> UploadFile {
        locked(&self.file).clone()
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

impl Journal for Kept {
    fn beginning(&self) -> kr_client::Result<()> {
        self.live
            .change(&self.store, |file| file.reached = Reached::Beginning)
            .map_err(|error| not_kept(&error))?;
        self.live.beginning_kept.store(true, Ordering::Release);
        Ok(())
    }

    fn begun(&self, transfer_id: TransferId) -> kr_client::Result<()> {
        self.live
            .change(&self.store, |file| {
                file.transfer_id = Some(transfer_id);
                file.reached = Reached::Begun;
            })
            .map_err(|error| not_kept(&error))
    }

    fn finishing(&self, transfer_id: TransferId) -> kr_client::Result<()> {
        self.live
            .change(&self.store, |file| {
                file.transfer_id = Some(transfer_id);
                file.reached = Reached::Finishing;
            })
            .map_err(|error| not_kept(&error))
    }

    fn published(&self, handle: &AttachmentHandle) -> kr_client::Result<()> {
        let handle = handle.clone();
        self.live
            .change(&self.store, |file| {
                file.handle = Some(handle);
                file.reached = Reached::Published;
            })
            .map_err(|error| not_kept(&error))?;
        // The bytes are the host's now; the handle is what this entry keeps.
        self.store
            .remove_copy(locked(&self.live.file).key)
            .map_err(|error| not_kept(&error))
    }
}

/// The host and the connection an upload is sent on.
#[derive(Clone)]
pub struct Paired {
    /// This device's principal on the host.
    pub device_id: DeviceId,
    /// The host's environment.
    pub environment_id: EnvironmentId,
    /// The connection.
    pub session: Arc<Session>,
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
    pub said: Option<&'static str>,
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
    /// What a restart found of entries it could not resume.
    verdicts: Mutex<HashMap<Uuid, Verdict>>,
}

impl std::fmt::Debug for Desk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Desk")
            .field("open", &locked(&self.live).len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    CannotResume,
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

/// Whether the host's answer to a status read says it does not know the transfer.
fn host_does_not_know(error: &ClientError) -> bool {
    matches!(
        error.code(),
        ErrorCode::InvalidArgument | ErrorCode::PermissionDenied
    )
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
    /// Refuses a third open upload, and returns the host's refusal or the reason this device ended
    /// the connection.
    pub async fn send(
        self: &Arc<Self>,
        paired: Paired,
        request: Request,
    ) -> Result<AttachmentHandle> {
        let store = self.store()?;
        let key = request.key;
        // Counted here and not in the host's refusal, so that the page is told in words before a
        // reservation is asked for.
        if self.open_count(&paired, &store) >= MOST_OPEN {
            return Err(CommandError::refused(TOO_MANY_OPEN));
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
        };
        if let Keeping::Copy(bytes) = request.keeping {
            let copied = store.clone();
            tauri::async_runtime::spawn_blocking(move || copied.write_copy(key, &bytes))
                .await
                .map_err(|error| CommandError::local_failure(error.to_string()))?
                .map_err(|error| {
                    CommandError::local_failure(format!(
                        "this device could not keep a copy of the file: {error}"
                    ))
                })?;
        }
        let live = Arc::new(Live {
            file: Mutex::new(file),
            content: request.content,
            progress: watch::channel(Progress::default()).0,
            outcome: watch::channel(None).0,
            task: Mutex::new(None),
            phase: Mutex::new(Phase::Sending),
            beginning_kept: AtomicBool::new(false),
        });
        locked(&self.live).insert(key, Arc::clone(&live));
        self.start(&live, paired.session);
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
    fn open_count(&self, paired: &Paired, store: &Store) -> usize {
        let mut keys: Vec<Uuid> = locked(&self.live)
            .iter()
            .filter(|(_, live)| {
                let file = locked(&live.file);
                file.environment_id == paired.environment_id
                    && file.device_id == paired.device_id
                    && file.reached != Reached::Published
            })
            .map(|(key, _)| *key)
            .collect();
        for file in store.all().entries {
            if file.environment_id == paired.environment_id
                && file.device_id == paired.device_id
                && file.reached != Reached::Published
                && !keys.contains(&file.key)
            {
                keys.push(file.key);
            }
        }
        keys.len()
    }

    /// Starts the send of `live` on `session`.
    fn start(self: &Arc<Self>, live: &Arc<Live>, session: Arc<Session>) {
        *locked(&live.phase) = Phase::Sending;
        let desk = Arc::clone(self);
        let running = Arc::clone(live);
        let task = tauri::async_runtime::spawn(async move {
            let result = desk.send_once(&running, &session).await;
            desk.settle(&running, &session, result);
        });
        *locked(&live.task) = Some(task.inner().abort_handle());
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
        let file = live.file();
        let route = ChunkRoute::network(session, file.environment_id).await?;
        let subject = Subject {
            environment_id: file.environment_id,
            session_id: file.session_id,
            device_id: None,
            declared_media_type: file.media_type.clone(),
            original_file_name: file.file_name.clone(),
        };
        let content: Box<dyn Content> = Box::new(Shared(Arc::clone(&live.content)));
        let mut plan = match file.transfer_id {
            Some(transfer_id) => Upload::resuming(subject, content, transfer_id),
            None => Upload::new(subject, content),
        };
        let journal = Kept {
            live: Arc::clone(live),
            store,
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
        &self,
        live: &Arc<Live>,
        session: &Session,
        result: kr_client::Result<AttachmentHandle>,
    ) {
        let file = live.file();
        match result {
            Ok(handle) => self.end(live, Outcome::Published(Box::new(handle))),
            Err(error) => {
                // A sign-out gives the transport's reason, which the driver returns in place of
                // the plain end; what this device ended is never waited out.
                let by_this_device = session.transport().ended_by_this_device().is_some();
                let ended = matches!(
                    error,
                    ClientError::ConnectionEnded | ClientError::SubmissionUncertain { .. }
                );
                let resumable = !by_this_device
                    && ended
                    && (file.transfer_id.is_some() || !live.beginning_kept.load(Ordering::Acquire));
                if resumable {
                    *locked(&live.phase) = Phase::Paused;
                    return;
                }
                // A reservation the host refused leaves nothing behind. One whose answer is not
                // known stays, and says so.
                let uncertain = matches!(
                    error,
                    ClientError::SubmissionUncertain { .. } | ClientError::ConnectionEnded
                ) || error.code() == ErrorCode::OutcomeUnknown;
                if file.transfer_id.is_none()
                    && !uncertain
                    && let Ok(store) = self.store()
                {
                    let _ = store.remove(file.key);
                }
                self.end(live, Outcome::Failed(CommandError::from(error)));
            }
        }
    }

    /// Ends the hold on `live` and tells whoever waits.
    fn end(&self, live: &Arc<Live>, outcome: Outcome) {
        let key = locked(&live.file).key;
        locked(&self.live).remove(&key);
        live.outcome.send_replace(Some(outcome));
    }

    /// The host was reached on `session`: paused uploads resume on it, and entries kept from before
    /// are read against the host's own record and resumed or dropped.
    pub fn host_reached(
        self: &Arc<Self>,
        device_id: DeviceId,
        environment_id: EnvironmentId,
        session: Arc<Session>,
    ) {
        let paused: Vec<Arc<Live>> = locked(&self.live)
            .values()
            .filter(|live| {
                let file = locked(&live.file);
                file.environment_id == environment_id
                    && file.device_id == device_id
                    && *locked(&live.phase) == Phase::Paused
            })
            .cloned()
            .collect();
        for live in &paused {
            self.start(live, Arc::clone(&session));
        }
        if locked(&self.root).is_none() {
            return;
        }
        let desk = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            desk.restart(Paired {
                device_id,
                environment_id,
                session,
            })
            .await;
        });
    }

    /// Reads the host's record of every entry kept from before, and only then acts on them.
    pub async fn restart(self: &Arc<Self>, paired: Paired) {
        let Ok(store) = self.store() else { return };
        let read = store.clone();
        let Ok(found) = tauri::async_runtime::spawn_blocking(move || read.all()).await else {
            return;
        };
        for key in &found.orphans {
            let _ = store.remove_copy(*key);
        }
        let mine: Vec<UploadFile> = found
            .entries
            .into_iter()
            .filter(|file| {
                file.environment_id == paired.environment_id
                    && file.device_id == paired.device_id
                    && !locked(&self.live).contains_key(&file.key)
            })
            .collect();
        // Every read comes before any action: a published upload is never cancelled for a state read
        // after it, and nothing here cancels at all.
        let mut reads = Vec::new();
        for file in mine {
            let status = match (file.reached, file.transfer_id) {
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
        let Some(status) = status else { return };
        match status {
            Err(error) if host_does_not_know(&error) => {
                let _ = store.remove(key);
            }
            // The connection failed: the next time the host is reached asks again.
            Err(_) => {}
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
                    match self.source_of(store, &file).await {
                        Some(content) => {
                            locked(&self.verdicts).remove(&key);
                            let live = Arc::new(Live {
                                file: Mutex::new(file),
                                content,
                                progress: watch::channel(Progress::default()).0,
                                outcome: watch::channel(None).0,
                                task: Mutex::new(None),
                                phase: Mutex::new(Phase::Sending),
                                beginning_kept: AtomicBool::new(true),
                            });
                            locked(&self.live).insert(key, Arc::clone(&live));
                            self.start(&live, Arc::clone(&paired.session));
                        }
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

    /// The open uploads of this device on `paired`'s host.
    #[must_use]
    pub fn open(&self, paired: &Paired) -> Vec<OpenView> {
        let Ok(store) = self.store() else {
            return Vec::new();
        };
        let mut views = Vec::new();
        let live = locked(&self.live).clone();
        for (key, held) in &live {
            let file = held.file();
            if file.environment_id != paired.environment_id || file.device_id != paired.device_id {
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
            if file.environment_id != paired.environment_id
                || file.device_id != paired.device_id
                || live.contains_key(&file.key)
            {
                continue;
            }
            let (state, said) = match (file.reached, locked(&self.verdicts).get(&file.key)) {
                (Reached::Published, _) => (OpenState::Published, None),
                (Reached::Beginning, _) => (OpenState::Unrecoverable, Some(UNRECOVERABLE)),
                (_, Some(Verdict::CannotResume)) => (OpenState::CannotResume, Some(CANNOT_RESUME)),
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
    /// # Errors
    ///
    /// Returns the host's refusal, and the failure when the connection ended before the answer, which
    /// leaves the upload kept: the host's record says what became of it.
    pub async fn cancel(self: &Arc<Self>, paired: Paired, key: Uuid) -> Result<Cancelled> {
        let store = self.store()?;
        let held = locked(&self.live).get(&key).cloned();
        let file = match &held {
            Some(live) => live.file(),
            None => store
                .all()
                .entries
                .into_iter()
                .find(|file| file.key == key)
                .ok_or_else(|| CommandError::invalid("no open upload has that key"))?,
        };
        if file.environment_id != paired.environment_id || file.device_id != paired.device_id {
            return Err(CommandError::invalid("no open upload has that key"));
        }
        let said = |state: &'static str, released: Option<String>, handle| Cancelled {
            key: key.to_string(),
            state,
            released_byte_len: released,
            handle,
        };
        if file.reached == Reached::Published {
            return Ok(said("published", None, file.handle));
        }
        // What the send does between now and the answer is stopped first: the stream is reset and
        // nothing more is sent for a transfer that is being cancelled.
        if let Some(live) = &held
            && let Some(task) = locked(&live.task).take()
        {
            task.abort();
        }
        let Some(transfer_id) = file.transfer_id else {
            // A reservation whose answer never came: nothing this device can name is held.
            self.forget(&store, &held, key);
            return Ok(said("forgotten", None, None));
        };
        // The host's record is read before anything is cancelled.
        let read: UploadStatusResult = match paired
            .session
            .read(Method::UploadStatus, &UploadStatusParams { transfer_id })
            .await
        {
            Ok(read) => read,
            Err(error) if host_does_not_know(&error) => {
                self.forget(&store, &held, key);
                return Ok(said("forgotten", None, None));
            }
            Err(error) => return Err(error.into()),
        };
        if read.state == UploadState::Published {
            let Some(handle) = read.handle.as_ref().cloned() else {
                return Err(CommandError::unavailable(
                    "the host says the upload is published and gave no handle",
                ));
            };
            let mut kept = file;
            kept.reached = Reached::Published;
            kept.handle = Some(handle.clone());
            store
                .write(&kept)
                .map_err(|error| CommandError::local_failure(error.to_string()))?;
            let _ = store.remove_copy(key);
            if let Some(live) = &held {
                *locked(&live.file) = kept;
                self.end(live, Outcome::Published(Box::new(handle.clone())));
            }
            return Ok(said("published", None, Some(handle)));
        }
        let answer: UploadCancelResult = uploads::cancel(
            &paired.session,
            &file.target,
            transfer_id,
            crate::commands::MUTATION_TTL,
        )
        .await?;
        self.forget(&store, &held, key);
        Ok(said(
            "cancelled",
            Some(answer.released_byte_len.get().to_string()),
            None,
        ))
    }

    /// Ends an upload that is over for good, and removes its entry and its copy.
    fn forget(&self, store: &Store, held: &Option<Arc<Live>>, key: Uuid) {
        if let Some(live) = held {
            self.end(live, Outcome::Cancelled);
        }
        let _ = store.remove(key);
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
}

fn view_of(
    key: Uuid,
    file: &UploadFile,
    state: OpenState,
    progress: Progress,
    stage: Option<Stage>,
    said: Option<&'static str>,
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

/// What a suite keeps in the folder to stand for an upload that an earlier process left.
#[cfg(feature = "testing")]
pub mod testing {
    use super::{Reached, STORE_VERSION, Source, Store, UploadFile};
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
