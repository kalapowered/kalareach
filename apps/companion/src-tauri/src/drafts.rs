//! The drafts a person has written on this device and not sent.
//!
//! A draft is the device's own: a durable identity with its text, the files added to it and what it
//! was written for. It survives the application being closed and the host being out of reach, and
//! nothing here sends it. The store is the client library's ([`kr_client::drafts::DraftStore`]); what
//! is here is where this application keeps it, which device it says owns it, and the rules the page
//! cannot be trusted to keep by itself.
//!
//! * **One owner per install.** Every draft names the device that owns it, and a store refuses to
//!   change another device's. The owner is an identifier made once for this install and read back
//!   at every start. A file that cannot be read is never replaced by a new identifier, because
//!   every draft already stored would then belong to someone else: the drafts are not opened, and
//!   the page says they are not kept.
//! * **A save names the version it replaces.** A save whose version is no longer the stored one
//!   means another window of this application wrote in between. Nothing is overwritten: what this
//!   window has is kept beside as a copy, and the stored draft stays the other window's. The copy
//!   carries the mark a save would have left, so it is never open when the draft is not. A save of a
//!   draft another window removed makes the window's text a draft again, under an identity of its
//!   own, which the answer names.
//! * **A draft keeps its session.** Moving one to another session is retargeting, a person's
//!   choice; a save refuses it. A save never takes a draft back to open, and refuses to change the
//!   conversation a draft holds text for: the page marks it conflicted instead, and only
//!   retargeting clears that.
//! * **A file is a completed upload.** The handle a draft stores has no preview: a stored record
//!   is bounded, and a preview can fill it.
//! * **A save is stored whole or refused.** A new draft whose text fits and whose files do not is
//!   not stored at all, so what the page is told is stored is stored.
//! * **A removal that could not be made is not forgotten.** The page records the version it still
//!   has to remove, in a ledger beside the store, and the next start reads it back with the
//!   drafts: a prompt the host took does not return as a draft because the disk refused once.
//!   A discard that ends, even in another window's change, takes its entry out.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_client::ClientError;
use kr_client::drafts::{Draft, DraftError, DraftStore, DraftTarget, SyncCheckpoint};
use kr_flush::{NameKind, flush_directory};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, DeviceId, DraftId, DraftRevision, EnvironmentId,
    SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_protocol::transfer::{AttachmentHandle, DraftState};
use serde::{Deserialize, Serialize};

use crate::error::{CommandError, Result};

/// The directory the drafts are kept in, under an application data directory.
#[must_use]
pub fn drafts_in(data: &Path) -> PathBuf {
    data.join("drafts")
}

/// The file that says which device owns the drafts, under an application data directory.
fn owner_file(data: &Path) -> PathBuf {
    data.join("drafts-owner")
}

/// The ledger of removals still to be made, under an application data directory.
fn removals_file(data: &Path) -> PathBuf {
    data.join("drafts-removals")
}

/// What a person reads when the list of removals, or the folder that holds it, cannot be read or
/// written. The cause follows it, after a space.
pub(crate) const LEDGER_STORE: &str = "This device could not read or write its list of removals.";

/// The error for a flush of the ledger's folder that was refused.
pub(crate) fn ledger_storage(error: &std::io::Error) -> CommandError {
    CommandError::new(
        ErrorCode::StorageUnavailable,
        format!("{LEDGER_STORE} {error}"),
    )
}

/// Held while the ledger is changed, so that two windows of one process never change it at once,
/// whether or not the file lock tells one handle of a process from another.
static LEDGER_GATE: Mutex<()> = Mutex::new(());

/// What reading the ledger found.
#[derive(Debug)]
pub(crate) enum Ledger {
    /// The removals it holds: none when there is no file.
    Whole(Vec<DiscardParams>),
    /// The file could not be read at all: an I/O error, a directory at its name.
    Unreadable(std::io::Error),
    /// Bytes were read that are not a list of removals.
    Damaged,
}

/// What the page is told of the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerState {
    /// Absent, or read and parsed.
    Ok,
    /// Any read error. Nothing writes over it and the page reads it again later.
    Unreadable,
    /// Bytes were read and do not parse: the one state a person can set aside.
    Damaged,
}

/// Whether the drafts' sources are all known. A draft whose source is unknown may be the text of a
/// message that was sent, so none is put in a composer by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sources {
    /// Every place a draft's removal could be owed was read.
    Known,
    /// One could not be read.
    Unknown,
}

/// What a ledger file holds. A file that is not there is an empty ledger; one that cannot be read
/// or parsed is neither, and nothing is ever written over it.
fn read_ledger(file: &Path) -> Ledger {
    match std::fs::read(file) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_or(Ledger::Damaged, Ledger::Whole),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ledger::Whole(Vec::new()),
        Err(error) => Ledger::Unreadable(error),
    }
}

impl Ledger {
    /// The state the page is told.
    pub(crate) const fn state(&self) -> LedgerState {
        match self {
            Self::Whole(_) => LedgerState::Ok,
            Self::Unreadable(_) => LedgerState::Unreadable,
            Self::Damaged => LedgerState::Damaged,
        }
    }
}

/// Why a write of a file did not complete, and whether the name was already given.
#[derive(Debug)]
pub(crate) struct PublishFault {
    /// True once the rename was made: the new bytes may be what every reader now sees.
    pub renamed: bool,
    /// What failed.
    pub error: std::io::Error,
}

/// Puts `bytes` in place under the name `to`, whole or not at all, and proves the name durable:
/// they are written beside it under a name of their own (owner-only, flushed), `before_rename` is
/// run, the name is given by a rename, and the directory is flushed. Every error is returned,
/// and one made after the rename says so, because the file is then in place whatever the caller
/// concludes.
///
/// The caller holds the lock that no other writer of `to` can pass.
pub(crate) fn publish(
    to: &Path,
    bytes: &[u8],
    before_rename: impl FnOnce() -> std::io::Result<()>,
) -> std::result::Result<(), PublishFault> {
    static STAGED: AtomicU64 = AtomicU64::new(0);

    let before = |error| PublishFault {
        renamed: false,
        error,
    };
    let directory = to
        .parent()
        .ok_or_else(|| before(std::io::Error::other("a file with no directory")))?;
    let name = to
        .file_name()
        .ok_or_else(|| before(std::io::Error::other("a path with no file name")))?
        .to_string_lossy();
    let staged = directory.join(format!(
        "{name}.staged-{}-{}",
        std::process::id(),
        STAGED.fetch_add(1, Ordering::Relaxed)
    ));
    kr_client::drafts::write_whole(&staged, bytes).map_err(before)?;
    if let Err(error) =
        before_rename().and_then(|()| kr_flush::retry_while_held(|| std::fs::rename(&staged, to)))
    {
        let _ = std::fs::remove_file(&staged);
        return Err(before(error));
    }
    flush_directory(directory, NameKind::File).map_err(|error| PublishFault {
        renamed: true,
        error,
    })
}

/// Removes `path` and proves its absence durable. A file that is not there is already removed, and
/// the directory is flushed all the same: the removal may be one another process made and did not
/// finish proving.
pub(crate) fn remove_durably(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a path with no directory"))?;
    flush_directory(directory, NameKind::File)
}

/// What a change of the ledger did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// The ledger already held what the change would write.
    Unchanged,
    /// The ledger was written and put in place.
    Published,
}

/// Why a change of the ledger did not complete.
#[derive(Debug)]
pub(crate) struct RemovalFault {
    /// True once the ledger was renamed into place, or already held the lines: it may be what a
    /// reader sees now, and may delete the only other copy of a text.
    pub renamed: bool,
    /// What failed.
    pub error: CommandError,
}

/// The ledger's two locks, held until it is dropped.
pub(crate) struct LedgerLocked<'a> {
    data: PathBuf,
    _gate: MutexGuard<'a, ()>,
    _lock: std::fs::File,
}

impl LedgerLocked<'_> {
    /// What the ledger holds now.
    pub(crate) fn read(&self) -> Ledger {
        read_ledger(&removals_file(&self.data))
    }

    /// The ledger's file.
    pub(crate) fn file(&self) -> PathBuf {
        removals_file(&self.data)
    }

    /// The application data directory the ledger is in.
    pub(crate) fn data(&self) -> &Path {
        &self.data
    }

    /// Puts `removals` in place as the whole ledger.
    pub(crate) fn publish(
        &self,
        removals: &[DiscardParams],
    ) -> std::result::Result<(), PublishFault> {
        let bytes = serde_json::to_vec(removals).map_err(|error| PublishFault {
            renamed: false,
            error: std::io::Error::other(error),
        })?;
        publish(&self.file(), &bytes, || {
            crate::channel_messages::reach(
                &self.data,
                crate::channel_messages::Point::LedgerBeforeRename,
            )
        })
    }
}

/// A host: the environment its sessions live in, and what the person calls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftHost {
    /// The host's environment.
    pub environment: EnvironmentId,
    /// What the host is called to the person, when it has a name.
    pub name: Option<String>,
}

/// Whoever keeps the drafts in step with other devices is told what happens to a draft here.
///
/// It is told after the change is on disk, except for a removal, which it is told of first: what
/// this watch is told never changes what the desk answers the page.
pub trait DraftWatch: Send + Sync {
    /// A draft of this device was stored, or sent to another session.
    fn saved(&self);

    /// A draft of this device is about to be removed. Whatever the service is owed for it is on
    /// disk before this returns, and held until the removal ends, so that a removal cannot be
    /// carried out with its obligation lost.
    ///
    /// # Errors
    ///
    /// Returns why the obligation could not be recorded, in which case the draft is not removed.
    fn removing(&self, draft: DraftId) -> Result<Box<dyn Removing + '_>>;

    /// Whether a copy kept beside `of` is another device's draft brought down, and not a draft of
    /// this device that another window of this application changed first.
    fn is_a_device_copy(&self, of: DraftId) -> bool;
}

/// A removal in hand. Dropped without [`Removing::removed`], it withdraws what it recorded.
pub trait Removing {
    /// The draft was removed, with the note of where the service held it, when it had been there.
    fn removed(self: Box<Self>, note: Option<SyncCheckpoint>);
}

/// The drafts of this device, and the place they are kept.
#[derive(Default)]
pub struct DraftDesk {
    /// The application data directory, once it is known.
    data: Mutex<Option<PathBuf>>,
    /// The store, opened by the first command that needs it.
    opened: Mutex<Option<DraftStore>>,
    /// Who keeps the drafts in step, once there is one.
    watch: std::sync::OnceLock<Arc<dyn DraftWatch>>,
    /// Whether the data directory's entry for the ledger is not yet proved durable, after a
    /// set-aside replaced it. The proof is the first step of every read of the drafts and every
    /// change of the ledger.
    flush_owed: AtomicBool,
}

impl std::fmt::Debug for DraftDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DraftDesk").finish_non_exhaustive()
    }
}

impl DraftDesk {
    /// Has `watch` told what happens to a draft from now on. Only the first call has an effect.
    pub fn watched_by(&self, watch: Arc<dyn DraftWatch>) {
        let _ = self.watch.set(watch);
    }

    /// Names the application data directory the drafts live under.
    pub fn keep_at(&self, data: PathBuf) {
        *self.data.lock().unwrap_or_else(PoisonError::into_inner) = Some(data);
    }

    /// The store, opened if this is the first use.
    ///
    /// # Errors
    ///
    /// Returns why the store cannot be used: no place for it, an owner file that cannot be read, or
    /// a directory that cannot be made private.
    pub fn store(&self) -> Result<DraftStore> {
        let mut opened = self.opened.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = opened.as_ref() {
            return Ok(store.clone());
        }
        let data = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unsupported(
                    "drafts cannot be kept on this device: it has no place for them",
                )
            })?;
        let owner = owner_of(&owner_file(&data))?;
        let store = DraftStore::open(drafts_in(&data), owner).map_err(failure)?;
        *opened = Some(store.clone());
        Ok(store)
    }

    /// Every draft stored here, and how many files in the store could not be read.
    ///
    /// A ledger that cannot be read makes the sources unknown: its removals are not known, so a
    /// draft may be the text of a prompt the host took.
    ///
    /// # Errors
    ///
    /// Returns why the store cannot be used.
    pub fn read(&self) -> Result<Stored> {
        let listing = self.store()?.list().map_err(failure)?;
        let ledger = self.ledger();
        let state = ledger.state();
        Ok(Stored {
            drafts: listing
                .drafts
                .iter()
                .map(|draft| {
                    let mut stored = StoredDraft::of(draft);
                    stored.from_another_device = draft.conflict_of.0.is_some_and(|of| {
                        self.watch
                            .get()
                            .is_some_and(|watch| watch.is_a_device_copy(of))
                    });
                    stored
                })
                .collect(),
            unreadable: listing.unreadable.len(),
            pending_removals: match ledger {
                Ledger::Whole(removals) => removals,
                _ => Vec::new(),
            },
            sources: if state == LedgerState::Ok {
                Sources::Known
            } else {
                Sources::Unknown
            },
            ledger: state,
        })
    }

    /// What the ledger holds now, read without a lock: a reader sees the list before a change or
    /// the one after it, and never half of one.
    pub(crate) fn ledger(&self) -> Ledger {
        let Some(data) = self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return Ledger::Whole(Vec::new());
        };
        read_ledger(&removals_file(&data))
    }

    /// The application data directory, once it is known.
    pub(crate) fn data(&self) -> Option<PathBuf> {
        self.data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Notes that the data directory's entry for the ledger has to be proved durable.
    pub(crate) fn owe_flush(&self) {
        self.flush_owed.store(true, Ordering::SeqCst);
    }

    /// Notes that the flush a set-aside owed was made.
    pub(crate) fn clear_owed_flush(&self) {
        self.flush_owed.store(false, Ordering::SeqCst);
    }

    /// Makes the flush a set-aside owes, if one is owed: the first step of every read of the drafts
    /// and every change of the ledger, so that nothing relies on a ledger whose name is not yet on
    /// disk.
    ///
    /// # Errors
    ///
    /// Returns why the data directory cannot be flushed; the flush stays owed.
    pub(crate) fn settle_owed_flush(&self) -> Result<()> {
        if !self.flush_owed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let Some(data) = self.data() else {
            return Ok(());
        };
        flush_directory(&data, NameKind::File).map_err(|error| ledger_storage(&error))?;
        self.flush_owed.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Takes the ledger's two locks: the gate, so that two windows of one process never change it
    /// at once, and the file lock, which tells another process from this one. The owed flush is made
    /// first.
    pub(crate) fn lock_ledger(&self) -> Result<LedgerLocked<'_>> {
        let data = self
            .data()
            .ok_or_else(|| CommandError::unsupported(LEDGER_STORE))?;
        let unavailable =
            |error: std::io::Error| CommandError::local_failure(format!("{LEDGER_STORE} {error}"));
        let gate = LEDGER_GATE.lock().unwrap_or_else(PoisonError::into_inner);
        std::fs::create_dir_all(&data).map_err(unavailable)?;
        // The lock is on a file of its own, held until the guard is dropped: a lock on the ledger
        // itself would go with the name it is renamed over.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(data.join("drafts-removals.lock"))
            .map_err(unavailable)?;
        kr_flush::lock::exclusive(&lock).map_err(unavailable)?;
        // No other writer is between writing a ledger and putting it in place while the lock is
        // held, so a file staged under the ledger's name is one a crash left.
        if let Ok(entries) = std::fs::read_dir(&data) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("drafts-removals.staged-")
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        self.settle_owed_flush()?;
        Ok(LedgerLocked {
            data,
            _gate: gate,
            _lock: lock,
        })
    }

    /// Changes the ledger as one step that no other writer, in this application or in another
    /// window of it, can come between: the ledger is read, `change` is made to it, and it is
    /// written whole under a name of its own and then put in place, so that a crash leaves the one
    /// before or the one after and never half of one. Nothing is written when `change` says it
    /// changed nothing, and the data directory is flushed all the same, so that a ledger which
    /// already holds the lines is proved durable before anything relies on it.
    ///
    /// A ledger that cannot be read or parsed is never replaced.
    fn change_removals(
        &self,
        change: impl FnOnce(&mut Vec<DiscardParams>) -> bool,
    ) -> std::result::Result<Change, RemovalFault> {
        let locked = self.lock_ledger().map_err(|error| RemovalFault {
            renamed: false,
            error,
        })?;
        let mut removals = match locked.read() {
            Ledger::Whole(removals) => removals,
            Ledger::Unreadable(error) => {
                return Err(RemovalFault {
                    renamed: false,
                    error: CommandError::local_failure(format!(
                        "This device could not read its list of removals. {error}"
                    )),
                });
            }
            Ledger::Damaged => {
                return Err(RemovalFault {
                    renamed: false,
                    error: CommandError::local_failure(
                        "This device could not read its list of removals.",
                    ),
                });
            }
        };
        if !change(&mut removals) {
            flush_directory(&locked.data, NameKind::File).map_err(|error| RemovalFault {
                renamed: true,
                error: CommandError::local_failure(format!("{LEDGER_STORE} {error}")),
            })?;
            return Ok(Change::Unchanged);
        }
        locked.publish(&removals).map_err(|fault| RemovalFault {
            renamed: fault.renamed,
            error: CommandError::local_failure(format!("{LEDGER_STORE} {}", fault.error)),
        })?;
        Ok(Change::Published)
    }

    /// Records a removal the page could not make, so that a start after it finishes it.
    ///
    /// # Errors
    ///
    /// Returns why the ledger cannot be written.
    pub fn mark_removal(&self, removal: DiscardParams) -> Result<()> {
        self.mark_removals(&[removal])
            .map(|_| ())
            .map_err(|fault| fault.error)
    }

    /// Records the removals the page could not make, in one change: the ledger holds all of them or
    /// none. Each version of a draft is owed its own removal: one recorded later for an older
    /// version does not take the entry of a newer one, and a line already there is not written
    /// again.
    pub(crate) fn mark_removals(
        &self,
        removals: &[DiscardParams],
    ) -> std::result::Result<Change, RemovalFault> {
        self.change_removals(|held| {
            let mut changed = false;
            for removal in removals {
                if !held.iter().any(|line| {
                    line.id == removal.id && line.expected_revision == removal.expected_revision
                }) {
                    held.push(removal.clone());
                    changed = true;
                }
            }
            changed
        })
    }

    /// Takes a draft's entry out of the ledger, because the removal it names is over.
    ///
    /// With a `version`, only an entry that names that version goes: a removal of a later version
    /// of the same draft is still owed. Without one, the draft is gone and so is every entry for it.
    fn clear_removal(&self, id: DraftId, version: Option<DraftRevision>) {
        // A ledger that cannot be written keeps an entry whose draft is gone, which the next
        // discard finds already removed and clears.
        let _ = self.change_removals(|removals| {
            let before = removals.len();
            removals.retain(|held| {
                held.id != id || version.is_some_and(|named| held.expected_revision != named)
            });
            removals.len() != before
        });
    }

    /// Saves a draft: creates it when it has no identity yet, else replaces the version it names.
    ///
    /// # Errors
    ///
    /// Returns the rule the save broke, or the store's failure.
    pub fn save(&self, params: SaveParams, now: TimestampMs) -> Result<Saved> {
        let saved = self.save_in_store(params, now)?;
        // A copy kept beside another window's draft is this device's own and is not published: the
        // draft it sits beside is.
        if saved.of.is_none()
            && let Some(watch) = self.watch.get()
        {
            watch.saved();
        }
        Ok(saved)
    }

    fn save_in_store(&self, params: SaveParams, now: TimestampMs) -> Result<Saved> {
        let store = self.store()?;
        let target = DraftTarget {
            session_id: params.session_id,
            application_instance_id: Nullable::from(params.application_instance_id),
            agent_binding_revision: Nullable::from(params.agent_binding_revision),
        };
        let attachments: Vec<AttachmentHandle> = params
            .attachments
            .into_iter()
            .map(without_preview)
            .collect();
        let Some(id) = params.id else {
            return create(&store, target, params.text, attachments, params.state, now);
        };
        let expected = params.expected_revision.ok_or_else(|| {
            CommandError::invalid("a save of a stored draft names the version it replaces")
        })?;
        let stored = match store.load(id) {
            Ok(stored) => stored,
            // Another window removed it, because it sent the draft or the person discarded it there.
            // What this window holds is still the person's, so it is kept as a draft again, and the
            // page takes the identity this gives it.
            Err(error) if is_unknown(&error) => {
                return create(&store, target, params.text, attachments, params.state, now);
            }
            Err(error) => return Err(failure(error)),
        };
        let wanted = Draft {
            target,
            state: params.state,
            text: params.text,
            attachments,
            ..stored.clone()
        };
        if stored.revision != expected {
            return copy(&store, id, &wanted, now);
        }
        let next = rules(&stored, &wanted)?;
        let edited = Draft {
            revision: expected,
            state: next,
            ..wanted.clone()
        };
        match store.update(&edited, now) {
            Ok(updated) => Ok(Saved::stored(&updated)),
            Err(error) if is_revision_conflict(&error) => copy(&store, id, &wanted, now),
            // Removed between the read and the write: the window's text is a draft again.
            Err(error) if is_unknown(&error) => create(
                &store,
                wanted.target.clone(),
                wanted.text.clone(),
                wanted.attachments.clone(),
                wanted.state,
                now,
            ),
            Err(error) => Err(failure(error)),
        }
    }

    /// Points a draft at a target a person chose, which is the one way back to open.
    ///
    /// # Errors
    ///
    /// Returns a revision conflict when the draft moved since the version named, or the store's
    /// failure.
    pub fn retarget(&self, params: RetargetParams, now: TimestampMs) -> Result<StoredDraft> {
        let retargeted = self.retarget_in_store(params, now)?;
        if let Some(watch) = self.watch.get() {
            watch.saved();
        }
        Ok(retargeted)
    }

    fn retarget_in_store(&self, params: RetargetParams, now: TimestampMs) -> Result<StoredDraft> {
        let store = self.store()?;
        let mut draft = match store.load(params.id) {
            Ok(draft) => draft,
            // Another window removed it: the same refusal as a draft it changed, which tells this
            // window to let go of the version it holds and not to try the same thing again.
            Err(error) if is_unknown(&error) => {
                return Err(CommandError::new(
                    ErrorCode::DraftConflict,
                    format!("draft {} was removed by another window", params.id),
                ));
            }
            Err(error) => return Err(failure(error)),
        };
        if draft.revision != params.expected_revision {
            return Err(stale(params.id, params.expected_revision, draft.revision));
        }
        draft.retarget(DraftTarget {
            session_id: params.session_id,
            application_instance_id: Nullable::from(params.application_instance_id),
            agent_binding_revision: Nullable::from(params.agent_binding_revision),
        });
        // A person who sends a draft somewhere has chosen it, so it is no longer a copy kept beside
        // another: it is a draft of the session it now goes to.
        draft.conflict_of = Nullable::null();
        let updated = match store.update(&draft, now) {
            Ok(updated) => updated,
            // Removed between the read and the write, which is the same refusal as removed before it.
            Err(error) if is_unknown(&error) => {
                return Err(CommandError::new(
                    ErrorCode::DraftConflict,
                    format!("draft {} was removed by another window", params.id),
                ));
            }
            Err(error) => return Err(failure(error)),
        };
        Ok(StoredDraft::of(&updated))
    }

    /// Removes a draft, when it is still the version a person was shown.
    ///
    /// # Errors
    ///
    /// Returns a revision conflict when the draft moved since, or the store's failure. A draft that
    /// is not there is already removed.
    pub fn discard(&self, params: &DiscardParams) -> Result<Discarded> {
        let store = self.store()?;
        // What the service is owed for the draft is on disk before the draft is gone.
        let removing = match self.watch.get() {
            Some(watch) => Some(watch.removing(params.id)?),
            None => None,
        };
        let removed = store.remove_at(params.id, params.expected_revision);
        match removed {
            Ok(removed) => {
                self.clear_removal(params.id, None);
                if let (Some(gone), Some(removing)) = (&removed, removing) {
                    removing.removed(gone.note);
                }
                Ok(Discarded {
                    removed: removed.is_some(),
                })
            }
            Err(error) => {
                // A draft that another window changed is theirs now: the removal of the version
                // this named is over, and one of a later version is still owed.
                if is_revision_conflict(&error) {
                    self.clear_removal(params.id, Some(params.expected_revision));
                }
                Err(failure(error))
            }
        }
    }
}

/// Creates a draft, with its files and its mark, in one record: stored whole, or refused.
fn create(
    store: &DraftStore,
    target: DraftTarget,
    text: String,
    attachments: Vec<AttachmentHandle>,
    state: DraftState,
    now: TimestampMs,
) -> Result<Saved> {
    let created = store
        .create_whole(target, text, attachments, state, now)
        .map_err(failure)?;
    Ok(Saved::stored(&created))
}

/// Keeps what this window has beside the stored draft, which stays as the other window wrote it.
///
/// The copy carries the mark a save would have left: what another window marked stays marked, and
/// text written for a conversation the stored draft is not for needs a person's choice. A copy is
/// kept whole whatever it breaks, and it is never open when a save of it would not have been. The
/// mark is decided from the draft as stored when the copy is written, under the store's own lock,
/// so a mark given a moment ago is not missed. A draft another window removed meanwhile has nothing
/// to be kept beside, and what this window has is stored as a draft of its own.
fn copy(store: &DraftStore, of: DraftId, wanted: &Draft, now: TimestampMs) -> Result<Saved> {
    let kept = store.keep_copy_beside(of, wanted, now, |stored| {
        let mut state = wanted.state.max(stored.state);
        if writes_for_another_conversation(stored, wanted) {
            state = state.max(DraftState::Conflicted);
        }
        state
    });
    let kept = match kept {
        Ok(kept) => kept,
        Err(error) if is_unknown(&error) => {
            let created = store
                .create_whole(
                    wanted.target.clone(),
                    wanted.text.clone(),
                    wanted.attachments.clone(),
                    wanted.state,
                    now,
                )
                .map_err(failure)?;
            return Ok(Saved::stored(&created));
        }
        Err(error) => return Err(failure(error)),
    };
    Ok(Saved {
        outcome: SaveOutcome::Copied,
        of: Some(of),
        draft: StoredDraft::of(&kept),
    })
}

/// The state a save leaves a stored draft in, or why the save is refused.
fn rules(stored: &Draft, wanted: &Draft) -> Result<DraftState> {
    if stored.target.session_id != wanted.target.session_id {
        return Err(CommandError::invalid(
            "a draft keeps its session; send it to another one by retargeting it",
        ));
    }
    // A draft that needs a person's choice stays so whatever a stale window thinks: the state moves
    // from open to conflicted to orphaned, and back to open only by retargeting.
    let next = stored.state.max(wanted.state);
    if writes_for_another_conversation(stored, wanted) {
        return Err(CommandError::new(
            ErrorCode::DraftConflict,
            "the draft was written for another conversation; mark it conflicted instead of moving it",
        ));
    }
    Ok(next)
}

/// Whether `wanted` moves a draft that holds text for one conversation to another.
fn writes_for_another_conversation(stored: &Draft, wanted: &Draft) -> bool {
    let moved = stored.target.application_instance_id != wanted.target.application_instance_id
        || stored.target.agent_binding_revision != wanted.target.agent_binding_revision;
    let holds_nothing = stored.text.is_empty() && stored.attachments.is_empty();
    moved && stored.target.application_instance_id.is_present() && !holds_nothing
}

fn is_unknown(error: &ClientError) -> bool {
    matches!(error, ClientError::Draft(draft) if matches!(**draft, DraftError::Unknown { .. }))
}

/// A handle as a draft stores it: whole, with no preview.
fn without_preview(mut handle: AttachmentHandle) -> AttachmentHandle {
    handle.preview = Nullable::null();
    handle
}

fn is_revision_conflict(error: &ClientError) -> bool {
    matches!(error, ClientError::Draft(draft) if matches!(**draft, DraftError::RevisionConflict { .. }))
}

fn stale(id: DraftId, expected: DraftRevision, current: DraftRevision) -> CommandError {
    CommandError::new(
        ErrorCode::DraftConflict,
        format!("draft {id} is at version {current}, not {expected}: another window changed it"),
    )
}

/// Maps the store's failure to the one the page reads.
///
/// A draft too large to store says so with the code that means a limit, because no retry helps.
pub(crate) fn failure(error: ClientError) -> CommandError {
    if let ClientError::Draft(draft) = &error
        && matches!(
            **draft,
            DraftError::TooLarge { .. } | DraftError::TooManyAttachments { .. }
        )
    {
        return CommandError::too_large(error.to_string());
    }
    CommandError::from(error)
}

/// The device that owns this install's drafts: read back from the file made at the first start.
///
/// A file that cannot be read is an error and is never written over.
fn owner_of(path: &Path) -> Result<DeviceId> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<DeviceId>().map_err(|_| {
            CommandError::local_failure(
                "the file that says which device owns the drafts on this device cannot be read",
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => make_owner(path),
        Err(error) => Err(CommandError::local_failure(format!(
            "the file that says which device owns the drafts on this device cannot be read: {error}"
        ))),
    }
}

/// Makes the owner for this install and puts it in place only if none is there.
///
/// It is published whole by the library that makes the other identifiers of this install: written
/// and flushed under a name of its own, given its name only if nobody has, and the directory
/// flushed so the name survives a crash. A second process starting at the same moment reads the
/// first one's identifier and never half of one, and a name lost to a crash cannot make a new owner
/// of drafts already stored.
fn make_owner(path: &Path) -> Result<DeviceId> {
    let unavailable = |error: &dyn std::fmt::Display| {
        CommandError::local_failure(format!(
            "the device that owns the drafts on this device cannot be recorded: {error}"
        ))
    };
    let mut bytes = [0_u8; 16];
    kr_crypto::random_bytes(&mut bytes)
        .map_err(|error| CommandError::local_failure(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let owner = DeviceId::new(Uuid::from_bytes(bytes));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| unavailable(&error))?;
    }
    match kr_ipc::paths::create_new_owner_only_file(path, owner.to_string().as_bytes()) {
        Ok(()) => Ok(owner),
        Err(kr_ipc::IpcError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            owner_of(path)
        }
        Err(error) => Err(unavailable(&error)),
    }
}

/// What the page reads when it opens its drafts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stored {
    /// Every draft the store could read, oldest first.
    pub drafts: Vec<StoredDraft>,
    /// How many files in the store could not be read. They are left where they are.
    pub unreadable: usize,
    /// The removals the page began and could not finish, each naming the version to remove.
    pub pending_removals: Vec<DiscardParams>,
    /// Whether every place that can say a draft was sent was read.
    pub sources: Sources,
    /// What the list of removals is: readable, not readable, or damaged.
    pub ledger: LedgerState,
}

/// One stored draft, as the page reads it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredDraft {
    /// Its identity.
    pub id: DraftId,
    /// Its version, which the next save names.
    pub revision: DraftRevision,
    /// The session it was written for.
    pub session_id: SessionId,
    /// The application it was written for, when one was known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it was written against, when one was known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// Whether it still goes to its target.
    pub state: DraftState,
    /// The text.
    pub text: String,
    /// The completed uploads on it.
    pub attachments: Vec<AttachmentHandle>,
    /// The draft this one was kept beside, when another window had changed that one first, or when
    /// another device had written it.
    pub copy_of: Option<DraftId>,
    /// Whether that was another device: the copy is its draft as it wrote it, brought down.
    pub from_another_device: bool,
    /// When it was made.
    pub created_at_ms: TimestampMs,
    /// When it was last changed.
    pub updated_at_ms: TimestampMs,
}

impl StoredDraft {
    fn of(draft: &Draft) -> Self {
        Self {
            id: draft.draft_id,
            revision: draft.revision,
            session_id: draft.target.session_id,
            application_instance_id: draft.target.application_instance_id.0,
            agent_binding_revision: draft.target.agent_binding_revision.0,
            state: draft.state,
            text: draft.text.clone(),
            attachments: draft.attachments.clone(),
            copy_of: draft.conflict_of.0,
            from_another_device: false,
            created_at_ms: draft.created_at_ms,
            updated_at_ms: draft.updated_at_ms,
        }
    }
}

/// What a save did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveOutcome {
    /// The draft is stored at the version the answer names.
    Stored,
    /// Another window had changed the draft, so this window's version is kept as a copy beside it.
    Copied,
}

/// What a save answers: what is stored now for the draft the caller was working on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    /// What happened.
    pub outcome: SaveOutcome,
    /// The draft the copy sits beside, for a copy.
    pub of: Option<DraftId>,
    /// The draft as stored: the one saved, or the copy.
    pub draft: StoredDraft,
}

impl Saved {
    fn stored(draft: &Draft) -> Self {
        Self {
            outcome: SaveOutcome::Stored,
            of: None,
            draft: StoredDraft::of(draft),
        }
    }
}

/// The parameters of a save.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SaveParams {
    /// The draft being saved, or none for one not stored yet.
    pub id: Option<DraftId>,
    /// The version of the stored draft this replaces. Required with an identity.
    pub expected_revision: Option<DraftRevision>,
    /// The session it is for.
    pub session_id: SessionId,
    /// The application it is for, when one is known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it is written against, when one is known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// Open, or the mark a person has to settle.
    pub state: DraftState,
    /// The text.
    pub text: String,
    /// The completed uploads on it.
    pub attachments: Vec<AttachmentHandle>,
}

/// The parameters of a retarget.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetargetParams {
    /// The draft.
    pub id: DraftId,
    /// The version the person was shown.
    pub expected_revision: DraftRevision,
    /// The session it now goes to.
    pub session_id: SessionId,
    /// The application it now goes to, when one is known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it is now written against, when one is known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
}

/// The parameters of a discard, and of a removal still to be made.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DiscardParams {
    /// The draft.
    pub id: DraftId,
    /// The version the person was shown.
    pub expected_revision: DraftRevision,
}

/// What a discard did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Discarded {
    /// False when the draft was not there.
    pub removed: bool,
}
