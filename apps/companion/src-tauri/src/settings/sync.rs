//! Settings sync from this computer: the same settings, kept in an encrypted collection at the sync
//! service, so another device of the same person finds them.
//!
//! The rules about a synchronised object (compare and swap against the position this device last
//! saw, the content a refused write loses kept beside this device's own, privacy mode's fence) are
//! `kr_client::sync::SyncClient`'s. The rules about who holds the collection's key are
//! `kr_client::sync::membership::SyncMembership`'s. This module is the companion that drives both:
//! it starts the collection, keeps the settings object in step with the settings file, and tells
//! the page where things stand.
//!
//! # What lives where
//!
//! * **The settings file** ([`super::LocalSettings`]) is the one source of every setting. The
//!   synchronised object is a copy of it for the service, made when a setting changes, and a
//!   remote change is written to the file before the page hears of it.
//! * **The record** is `settings-sync/sync.json`: the service the collection is kept at, the
//!   collection's identity, the identity of the settings object in it, and whether the collection's
//!   first key record is known to have been kept. It is made and flushed before anything is sent,
//!   because a collection claimed under an identity this device had not written down is one nobody
//!   finds again. It holds nothing secret.
//! * **The sync store** is `settings-sync/store`: this device's copy of the object, where it last
//!   stood at the service, the content other devices wrote that it keeps for the person to choose
//!   from, and the account of every write that left.
//! * **The membership** is `settings-sync/membership`: who holds the collection's key. A collection
//!   key is in the device's secret store, under [`SCOPE`].
//! * **The lock** is `settings-sync/sync.lock`. Each step holds it, so a second companion on this
//!   machine waits for the step in hand.
//!
//! # The service
//!
//! A settings request is proven by this device's signature alone: no account is signed in, and no
//! token is sent anywhere. The collection is kept at the service the sync service setting named
//! when sync was turned on, and stays there: changing the setting afterwards chooses where the
//! next collection would be started, and moves nothing.
//!
//! # Agreeing with the service
//!
//! One step brings this device and the service to the same settings, in this order:
//!
//! 1. Work that left without an answer is asked about, and ended by what the service recorded.
//! 2. If content a refused write lost is waiting for the person, nothing else happens: this device
//!    neither publishes over it nor replaces its own settings with it, because the choice is not
//!    the clock's and not this step's.
//! 3. If this device has changed a setting since it last agreed with the service, it publishes.
//!    The service accepts it when nothing was written since, and refuses it, keeping what the
//!    other device wrote beside this device's own, when something was.
//! 4. Otherwise it reads what the service holds. If another device wrote since and this device has
//!    changed nothing, the other device's settings are taken as this device's own: there is no
//!    choice to make, only a lineage to follow. If this device has chosen nothing yet and the
//!    service holds settings, those are taken the same way.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, managed_response_limits,
};
use kr_client::sync::membership::{DeviceDirectory, HostAnswers, KeyRecordService, SyncMembership};
use kr_client::sync::{
    CollectionKeys, Published, Restored, SettingValue, SharedCollectionService,
    StoredCollectionKeys, SyncBody, SyncCheckpoint, SyncClient, SyncError, SyncObject,
    SyncSettings, SyncStore, fresh_object_id, fresh_revision,
};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::SecretStore;
use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, SyncCollectionId, SyncConflictId, SyncObjectId, SyncRevisionId};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::service::{GatewayOrigin, installation_id};
use kr_protocol::sync::SyncObjectKind;
use serde::{Deserialize, Serialize};

use super::{ColourMode, LocalSettings};
use crate::error::{CommandError, Result};
use crate::recovery::{DeviceSigner, now};
use crate::sync_service::{SyncService, SyncServiceView, host_of};

/// The scope in the device's secure store that the collection's keys are kept under.
pub const SCOPE: &str = "settings-sync";

/// The directory under the application's data directory that settings sync keeps its records in.
const DIRECTORY: &str = "settings-sync";

/// The record of where this computer's collection is, in [`DIRECTORY`].
const RECORD: &str = "sync.json";

/// The file a step holds a lock on for as long as it runs, in [`DIRECTORY`].
const LOCK: &str = "sync.lock";

/// The sync store, in [`DIRECTORY`].
const STORE: &str = "store";

/// The membership, in [`DIRECTORY`].
const MEMBERSHIP: &str = "membership";

/// The most a record may be, in bytes. It is a few lines of text.
const RECORD_LIMIT: u64 = 16 * 1024;

/// The name a setting is synchronised under.
const COLOUR_MODE: &str = "colour_mode";

/// Where settings sync stands on this computer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    /// It has not been turned on.
    Off,
    /// It was turned on and the collection's first key record is not known to have been kept.
    Starting,
    /// The collection is started, and this computer takes part in it.
    On,
}

/// What the page is shown of settings sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncView {
    /// Where it stands.
    pub state: SyncState,
    /// The sync service this computer is set to use for a collection it starts.
    pub service: Option<SyncServiceView>,
    /// The host of the service the collection is kept at, once it was started.
    pub kept_at: Option<String>,
    /// How many writes left this computer and have no answer yet.
    pub outstanding: u64,
    /// How many copies of other devices' settings wait for the person to choose.
    pub conflicts: u64,
    /// Whether privacy mode has stopped sync from sending.
    pub paused: bool,
    /// What the last step could not do, in words, until a step succeeds.
    pub problem: Option<String>,
}

impl SyncView {
    /// The view of a computer that has nothing to sync with: its keys could not be opened.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            state: SyncState::Off,
            service: None,
            kept_at: None,
            outstanding: 0,
            conflicts: 0,
            paused: false,
            problem: None,
        }
    }
}

/// One version of the settings, as the person is shown it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// The colour mode it holds, when it holds one this build reads.
    pub colour_mode: Option<ColourMode>,
    /// When the device that wrote it recorded it, in UTC milliseconds. It is shown and decides
    /// nothing.
    pub updated_at_ms: u64,
}

/// A version of the settings another device wrote, as the person is shown it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Other {
    /// The content, which a choice names.
    pub conflict_id: SyncConflictId,
    /// The colour mode it holds, when it holds one this build reads.
    pub colour_mode: Option<ColourMode>,
    /// When the device that wrote it recorded it, in UTC milliseconds. It is shown and decides
    /// nothing.
    pub updated_at_ms: u64,
}

/// What the person is asked to choose between: this computer's settings, and each version another
/// device wrote that this computer's settings disagree with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConflictView {
    /// This computer's settings.
    pub mine: Candidate,
    /// The versions other devices wrote, in the order this computer received them.
    pub others: Vec<Other>,
}

/// The version the person keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "choice", rename_all = "snake_case")]
pub enum Keep {
    /// This computer's settings.
    Mine,
    /// The content another device wrote.
    Copy {
        /// Which.
        conflict_id: SyncConflictId,
    },
}

/// What a computer needs to take part in a collection.
pub struct SyncParts {
    /// This computer's keys: the authorisation key signs for the service, the stored-envelope key
    /// opens the wrap of the collection key it is given.
    pub keys: DeviceKeys,
    /// The secure store the collection's keys are kept in.
    pub secrets: Arc<dyn SecretStore>,
    /// The sync service setting.
    pub service: Arc<SyncService>,
}

/// Where this computer's collection is, and whether its first key record is known to be kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    /// The format of this record.
    version: u32,
    /// The service the collection is kept at.
    service_origin: String,
    /// The collection, as the service names it.
    collection_id: SyncCollectionId,
    /// The settings object in it.
    object_id: SyncObjectId,
    /// True once the collection's first key record is known to be kept and installed.
    started: bool,
}

impl Record {
    const VERSION: u32 = 1;

    fn origin(&self) -> Result<GatewayOrigin> {
        GatewayOrigin::new(self.service_origin.as_str()).map_err(|error| {
            CommandError::local_failure(format!(
                "the service this computer's settings collection is kept at is not one it can \
                 reach: {error}"
            ))
        })
    }
}

/// Settings sync from this computer.
pub struct SettingsSync {
    directory: PathBuf,
    parts: SyncParts,
    local: Arc<LocalSettings>,
    /// This process's turn, taken for the length of each step beside the lock on [`LOCK`].
    steps: tokio::sync::Mutex<()>,
    problem: Mutex<Option<String>>,
    told: Arc<super::Told>,
}

impl std::fmt::Debug for SettingsSync {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettingsSync")
            .finish_non_exhaustive()
    }
}

/// A device with no host to ask. A collection of one device has no other member to check.
#[derive(Debug)]
struct NoHosts;

impl DeviceDirectory for NoHosts {
    fn answers(&self) -> kr_client::services::ServiceFuture<'_, Option<HostAnswers>> {
        Box::pin(std::future::ready(Ok(None)))
    }
}

/// One step's hold on settings sync: this process's turn, and the lock on the lock file.
struct Step<'a> {
    _turn: tokio::sync::MutexGuard<'a, ()>,
    _lock: std::fs::File,
}

/// What a step found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    /// The collection's first key record is not installed yet.
    Starting,
    /// This computer and the service agree, or what is left is the person's to choose.
    Agreed,
}

impl SettingsSync {
    /// Settings sync kept under `data`, over `local`.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the directory cannot be made.
    pub fn open(
        data: &Path,
        local: Arc<LocalSettings>,
        parts: SyncParts,
        told: Arc<super::Told>,
    ) -> Result<Self> {
        let directory = data.join(DIRECTORY);
        create_private_directory(&directory)
            .map_err(|error| error.to_string())
            .and_then(|()| flush_path_names(&directory).map_err(|error| error.to_string()))
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "the directory settings sync keeps its records in could not be made: {error}"
                ))
            })?;
        Ok(Self {
            directory,
            parts,
            local,
            steps: tokio::sync::Mutex::new(()),
            problem: Mutex::new(None),
            told,
        })
    }

    /// Takes this process's turn and then the lock a second companion on this machine would wait
    /// for, and holds both until the step is dropped.
    async fn step(&self) -> Result<Step<'_>> {
        let turn = self.steps.lock().await;
        let path = self.directory.join(LOCK);
        let file = tauri::async_runtime::spawn_blocking(move || super::locked_file(&path))
            .await
            .map_err(|error| {
                CommandError::local_failure(format!("settings sync was not started: {error}"))
            })?
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "this computer's settings sync lock could not be taken: {error}"
                ))
            })?;
        Ok(Step {
            _turn: turn,
            _lock: file,
        })
    }

    /* ---------------------------------------------------------------------- */
    /* What the page is shown                                                  */
    /* ---------------------------------------------------------------------- */

    /// Where settings sync stands. Nothing is sent, and a step in hand is not waited for.
    #[must_use]
    pub fn view(&self) -> SyncView {
        let problem = self
            .problem
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let service = Some(self.parts.service.view());
        let record = match self.record() {
            Ok(Some(record)) => record,
            Ok(None) => {
                return SyncView {
                    state: SyncState::Off,
                    service,
                    kept_at: None,
                    outstanding: 0,
                    conflicts: 0,
                    paused: false,
                    problem,
                };
            }
            Err(error) => {
                return SyncView {
                    state: SyncState::Off,
                    service,
                    kept_at: None,
                    outstanding: 0,
                    conflicts: 0,
                    paused: false,
                    problem: Some(error.message),
                };
            }
        };
        let (outstanding, conflicts, paused, trouble) = match self.store() {
            Ok(store) => {
                let outstanding = store.unsettled().unwrap_or(0);
                let conflicts = store
                    .conflicts(record.object_id)
                    .map_or(0, |copies| copies.len() as u64);
                let paused = store.privacy().is_ok_and(|privacy| privacy.fenced);
                (outstanding, conflicts, paused, None)
            }
            Err(error) => (0, 0, false, Some(error.message)),
        };
        SyncView {
            state: if record.started {
                SyncState::On
            } else {
                SyncState::Starting
            },
            service,
            kept_at: record.origin().ok().map(|origin| host_of(&origin)),
            outstanding,
            conflicts,
            paused,
            problem: problem.or(trouble),
        }
    }

    fn say(&self, problem: Option<String>) {
        *self.problem.lock().unwrap_or_else(PoisonError::into_inner) = problem;
    }

    /* ---------------------------------------------------------------------- */
    /* Turning it on                                                           */
    /* ---------------------------------------------------------------------- */

    /// Turns settings sync on: the collection is started with this computer's own key record, the
    /// settings are put in it, and what other devices have put there is taken.
    ///
    /// Run again after a start that did not finish, it goes on from where that stopped, with the
    /// identities it began with.
    ///
    /// # Errors
    ///
    /// Returns what stopped it: the service could not be reached or refused, or a local record
    /// could not be kept. The collection is then started as far as it got, and the next step goes
    /// on from there.
    pub async fn turn_on(&self) -> Result<()> {
        let outcome = self.turn_on_in_a_step().await;
        self.finished(&outcome);
        outcome
    }

    async fn turn_on_in_a_step(&self) -> Result<()> {
        let _step = self.step().await?;
        let mut record = match self.record()? {
            Some(record) => record,
            None => {
                let record = Record {
                    version: Record::VERSION,
                    service_origin: self.parts.service.origin().as_str().to_owned(),
                    collection_id: SyncCollectionId::new(
                        fresh_object_id().map_err(CommandError::from)?.get(),
                    ),
                    object_id: fresh_object_id().map_err(CommandError::from)?,
                    started: false,
                };
                self.keep(&record)?;
                record
            }
        };
        let service = self.managed(&record.origin()?)?;
        let mut membership = self.membership(&service)?;
        if membership.members().map_err(member_failure)?.is_none() {
            membership
                .start(record.collection_id, now())
                .await
                .map_err(member_failure)?;
        }
        drop(membership);
        self.settle(&mut record, &service).await.map(|_| ())
    }

    /* ---------------------------------------------------------------------- */
    /* Keeping in step                                                         */
    /* ---------------------------------------------------------------------- */

    /// Brings this computer and the service to the same settings, when sync is on. Nothing happens
    /// when it is off.
    ///
    /// # Errors
    ///
    /// Returns what stopped the step: the service could not be reached, or a local record could
    /// not be kept. The step is safe to run again, and the page is told what stopped it.
    pub async fn catch_up(&self) -> Result<()> {
        let outcome = self.catch_up_in_a_step().await;
        self.finished(&outcome);
        outcome
    }

    async fn catch_up_in_a_step(&self) -> Result<()> {
        let _step = self.step().await?;
        let Some(mut record) = self.record()? else {
            return Ok(());
        };
        let service = self.managed(&record.origin()?)?;
        self.settle(&mut record, &service).await.map(|_| ())
    }

    /// Records how a step ended, for the page.
    fn finished(&self, outcome: &Result<()>) {
        match outcome {
            Ok(()) => self.say(None),
            Err(error) => self.say(Some(error.message.clone())),
        }
        self.told.tell();
    }

    /// One agreement with the service, under the step in hand.
    async fn settle(
        &self,
        record: &mut Record,
        service: &Arc<ManagedSyncService>,
    ) -> Result<Progress> {
        let now_ms = now();
        let mut membership = self.membership(service)?;
        membership.reconcile(now_ms).await.map_err(member_failure)?;
        if !membership.publishes().map_err(member_failure)? {
            return Ok(Progress::Starting);
        }
        let status = membership
            .members()
            .map_err(member_failure)?
            .ok_or_else(|| {
                CommandError::local_failure("this computer holds no settings collection")
            })?;
        let Some((epoch, _)) = status.installed else {
            return Ok(Progress::Starting);
        };
        if !record.started {
            record.started = true;
            self.keep(record)?;
            self.told.tell();
        }
        let client = self.client(service, status.collection, epoch)?;
        self.agree(&client, record.object_id, now_ms).await?;
        Ok(Progress::Agreed)
    }

    /// What the person is asked to choose between, or nothing when no content waits.
    ///
    /// Nothing is sent. The settings object this computer holds is shown as the file says it: a
    /// choice written to the file and not yet to the object is this computer's choice all the same.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the records cannot be read.
    pub fn conflicts(&self) -> Result<Option<ConflictView>> {
        let Some(record) = self.record()? else {
            return Ok(None);
        };
        let store = self.store()?;
        let copies = store
            .conflicts(record.object_id)
            .map_err(sync_failure)?
            .items;
        if copies.is_empty() {
            return Ok(None);
        }
        let held = store.object(record.object_id).map_err(sync_failure)?;
        Ok(Some(ConflictView {
            mine: Candidate {
                colour_mode: self
                    .local
                    .chosen_colour_mode()
                    .or_else(|| held.as_ref().and_then(colour_mode_of)),
                updated_at_ms: held.as_ref().map_or(0, |object| object.updated_at_ms.get()),
            },
            others: copies
                .iter()
                .map(|copy| Other {
                    conflict_id: copy.conflict_id,
                    colour_mode: colour_mode_of(&copy.other),
                    updated_at_ms: copy.other.updated_at_ms.get(),
                })
                .collect(),
        }))
    }

    /// Records the person's choice between this computer's settings and the content other devices
    /// wrote, and sends it.
    ///
    /// Whatever is chosen, every copy that waited is let go: they were versions of the one object,
    /// and the choice is the one that stands. A choice for a copy takes its content as this
    /// computer's own, as a new write. The choice is on this computer's disk before anything is
    /// sent, so a service that cannot be reached leaves it made and the next step sends it.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no such content waits or what was chosen is not content this build
    /// reads, which changes nothing, and a local failure when a record cannot be kept, after which
    /// the choice made so far stands and the next step carries on from it.
    pub async fn resolve(&self, keep: Keep) -> Result<()> {
        self.resolve_in_a_step(keep).await
    }

    async fn resolve_in_a_step(&self, keep: Keep) -> Result<()> {
        let _step = self.step().await?;
        let Some(mut record) = self.record()? else {
            return Err(CommandError::refused("settings sync is not on"));
        };
        let store = self.store()?;
        let copies = store
            .conflicts(record.object_id)
            .map_err(sync_failure)?
            .items;
        if copies.is_empty() {
            return Err(CommandError::refused(
                "no content from another device is waiting for a choice",
            ));
        }
        let chosen = match keep {
            Keep::Mine => None,
            Keep::Copy { conflict_id } => {
                let copy = copies
                    .iter()
                    .find(|copy| copy.conflict_id == conflict_id)
                    .ok_or_else(|| {
                        CommandError::refused("that content is not waiting for a choice")
                    })?;
                let mode = colour_mode_of(&copy.other).ok_or_else(|| {
                    CommandError::refused("that content has no setting this version reads")
                })?;
                Some(mode)
            }
        };
        let service = self.managed(&record.origin()?)?;
        let status = self
            .membership(&service)?
            .members()
            .map_err(member_failure)?
            .ok_or_else(|| {
                CommandError::local_failure("this computer holds no settings collection")
            })?;
        let (collection, epoch) = (
            status.collection,
            status.installed.map(|(epoch, _)| epoch).ok_or_else(|| {
                CommandError::local_failure("the collection has no key installed")
            })?,
        );
        let client = self.client(&service, collection, epoch)?;
        // The choice first, on this computer; the service is told after, and may be told later.
        if let Some(mode) = chosen {
            self.local.set_colour_mode(mode)?;
            // The window is in the mode the file holds, whatever becomes of the rest of this step.
            self.told.tell();
            let held = store.object(record.object_id).map_err(sync_failure)?;
            let object = self.object_of(record.object_id, held.as_ref(), mode, now())?;
            store.put_object(&object).map_err(sync_failure)?;
        }
        for copy in copies {
            client
                .resolve(copy.conflict_id)
                .await
                .map_err(sync_failure)?;
        }
        // Sending the choice may fail and the choice stands: the step that next reaches the service
        // sends it, and the page is told what this one could not do.
        let sent = self.settle(&mut record, &service).await.map(|_| ());
        self.finished(&sent);
        Ok(())
    }

    /// The agreement itself: see the module's list.
    async fn agree(
        &self,
        client: &SyncClient,
        object_id: SyncObjectId,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let store = client.store();
        client
            .reconcile_unsettled(now_ms)
            .await
            .map_err(sync_failure)?;
        // Content another device wrote that this computer's own settings disagree with waits for
        // the person. Content that says what this computer's settings say asks nothing of them,
        // and is let go.
        let waiting = store.conflicts(object_id).map_err(sync_failure)?.items;
        if !waiting.is_empty() {
            let mine = self.local.chosen_colour_mode();
            if mine.is_none()
                || waiting
                    .iter()
                    .any(|copy| colour_mode_of(&copy.other) != mine)
            {
                return Ok(());
            }
            for copy in waiting {
                client
                    .resolve(copy.conflict_id)
                    .await
                    .map_err(sync_failure)?;
            }
        }
        client.finish_resolutions().await.map_err(sync_failure)?;
        // The file is the one source: the object this computer holds is made again whenever it
        // does not carry what the file says, which is also how a change that was written to the
        // file and not yet to the object (a stop between the two) is carried on.
        let chosen = self.local.chosen_colour_mode();
        let mut held = store.object(object_id).map_err(sync_failure)?;
        if let Some(mode) = chosen
            && held.as_ref().and_then(colour_mode_of) != Some(mode)
        {
            if held.is_none()
                && store
                    .checkpoint(object_id)
                    .map_err(sync_failure)?
                    .is_some_and(|note| note.published_revision.0.is_none())
            {
                // The first object this computer makes is published against nothing. A note kept
                // without an object, and with no write of this computer's own named in it, names a
                // write this computer read and did not take (the person chose while it was being
                // read, or the step stopped before it was taken), and a publication against it
                // would replace that write without a choice: forgotten, the publication is refused
                // and keeps that content beside this computer's own.
                store.forget_checkpoint(object_id).map_err(sync_failure)?;
            }
            let object = self.object_of(object_id, held.as_ref(), mode, now_ms)?;
            store.put_object(&object).map_err(sync_failure)?;
            held = Some(object);
        }
        let note = store.checkpoint(object_id).map_err(sync_failure)?;
        let agreed = note.and_then(|note| note.published_revision.0);
        let changed = held
            .as_ref()
            .is_some_and(|object| agreed != Some(object.revision));
        if changed {
            return match client.publish(object_id, now_ms).await {
                Ok(Published::Accepted { .. } | Published::Discarded { .. }) => Ok(()),
                Ok(Published::Conflicted { .. }) => {
                    self.told.tell();
                    Ok(())
                }
                Err(error) => Err(sync_failure(error)),
            };
        }
        match client
            .fetch(SyncObjectKind::Settings, object_id, now_ms)
            .await
        {
            Ok(Restored::Settings { object, copy }) => match (held, copy) {
                // The service holds what this computer holds: they agree, and the note says so.
                (Some(held), None) => Self::agreed(store, object_id, held.revision),
                // A device that held nothing is seeing the object for the first time.
                (None, Some(_)) => Ok(()),
                // This computer has changed nothing since it last agreed, and another device has
                // written since: the other device's settings continue this computer's.
                (Some(_), Some(copy)) => {
                    self.follow(client, object_id, &object, chosen, Some(copy))
                        .await
                }
                // This computer has chosen nothing, and the service holds settings.
                (None, None) => self.follow(client, object_id, &object, chosen, None).await,
            },
            Ok(Restored::ClientSelection { .. }) => Ok(()),
            // The collection holds no such object yet: there is nothing to follow.
            Err(SyncError::Client(error)) if error.code() == ErrorCode::UnknownSession => Ok(()),
            Err(error) => Err(sync_failure(error)),
        }
    }

    /// Notes that this computer holds `revision` and the service holds it too, so that a step that
    /// finds nothing new is not taken for one that found a change here.
    fn agreed(store: &SyncStore, object_id: SyncObjectId, revision: SyncRevisionId) -> Result<()> {
        if let Some(note) = store.checkpoint(object_id).map_err(sync_failure)? {
            store
                .record_checkpoint(
                    object_id,
                    SyncCheckpoint {
                        position: note.position,
                        published_revision: Nullable::from(Some(revision)),
                    },
                )
                .map_err(sync_failure)?;
        }
        Ok(())
    }

    /// Takes the settings another device published as this computer's own, without choosing
    /// anything: the settings file, the object this computer holds and the note of where it stands
    /// all say the same thing afterwards.
    ///
    /// Not when the person has chosen another colour mode since the step began: that choice is
    /// newer than anything read from the service, and what the other device wrote stays beside it
    /// for the person. The settings file is the first thing written, and it is written only if it
    /// still holds what the step began with, so a choice made while the service was being read is
    /// never replaced. The version the fetch kept is let go last, after everything else is in
    /// place: a step that stops before it finds the same content waiting, and lets it go as
    /// content that says what this computer says.
    async fn follow(
        &self,
        client: &SyncClient,
        object_id: SyncObjectId,
        object: &SyncObject,
        chosen: Option<ColourMode>,
        copy: Option<SyncConflictId>,
    ) -> Result<()> {
        let store = client.store();
        let taken = match colour_mode_of(object) {
            Some(mode) => self.local.replace_colour_mode(chosen, mode)?,
            None => self.local.chosen_colour_mode() == chosen,
        };
        if !taken {
            // The person chose while the service was being read. Where the fetch kept a copy of
            // what the other device wrote, the copy waits for them. Where this computer held
            // nothing there is no copy, and the step that makes this computer's first object
            // forgets the note this fetch wrote, so that object is not published against it.
            return Ok(());
        }
        store.put_object(object).map_err(sync_failure)?;
        Self::agreed(store, object_id, object.revision)?;
        if let Some(copy) = copy {
            client.resolve(copy).await.map_err(sync_failure)?;
        }
        self.told.tell();
        Ok(())
    }

    /// The settings object this computer holds after `mode` was chosen: what it held, with the
    /// colour mode replaced, as a new revision.
    fn object_of(
        &self,
        object_id: SyncObjectId,
        previous: Option<&SyncObject>,
        mode: ColourMode,
        now_ms: TimestampMs,
    ) -> Result<SyncObject> {
        let mut settings = match previous.map(|object| &object.body) {
            Some(SyncBody::Settings(settings)) => settings.clone(),
            _ => SyncSettings::default(),
        };
        settings.values.insert(
            COLOUR_MODE.to_owned(),
            SettingValue::Text(mode.as_str().to_owned()),
        );
        Ok(SyncObject {
            object_id,
            revision: fresh_revision().map_err(CommandError::from)?,
            device_id: DeviceId::new(installation_id(self.parts.keys.authorisation.public()).get()),
            updated_at_ms: now_ms,
            body: SyncBody::Settings(settings),
        })
    }

    /* ---------------------------------------------------------------------- */
    /* What is kept                                                            */
    /* ---------------------------------------------------------------------- */

    fn record(&self) -> Result<Option<Record>> {
        let path = self.directory.join(RECORD);
        let Some(bytes) = read_owner_only_file(&path, RECORD_LIMIT).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's settings sync record could not be read: {error}"
            ))
        })?
        else {
            return Ok(None);
        };
        let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's settings sync record is not one this version reads: {error}"
            ))
        })?;
        if record.version != Record::VERSION {
            return Err(CommandError::local_failure(
                "this computer's settings sync record is of a version this version does not read",
            ));
        }
        Ok(Some(record))
    }

    /// Writes the record whole and makes it durable.
    fn keep(&self, record: &Record) -> Result<()> {
        let text = serde_json::to_vec_pretty(record).map_err(|error| {
            CommandError::local_failure(format!(
                "the settings sync record could not be written: {error}"
            ))
        })?;
        write_owner_only_file(&self.directory.join(RECORD), &text).map_err(|error| {
            CommandError::local_failure(format!(
                "this computer's settings sync record could not be kept: {error}"
            ))
        })
    }

    fn store(&self) -> Result<SyncStore> {
        SyncStore::open(self.directory.join(STORE)).map_err(sync_failure)
    }

    /// The service client for `origin`, signing as this installation. No account is presented.
    fn managed(&self, origin: &GatewayOrigin) -> Result<Arc<ManagedSyncService>> {
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this computer cannot reach the sync service: {error}"
            ))
        })?;
        Ok(Arc::new(ManagedSyncService::new(
            origin.clone(),
            Arc::new(http),
            Arc::new(DeviceSigner::new(self.parts.keys.authorisation.clone())),
        )))
    }

    fn keys(&self) -> StoredCollectionKeys {
        StoredCollectionKeys::in_store(Arc::clone(&self.parts.secrets), SCOPE)
    }

    fn membership(&self, service: &Arc<ManagedSyncService>) -> Result<SyncMembership> {
        SyncMembership::open(
            self.directory.join(MEMBERSHIP),
            &self.parts.keys,
            self.keys(),
            Arc::clone(service) as Arc<dyn KeyRecordService>,
            Arc::new(NoHosts),
        )
        .map_err(member_failure)
    }

    /// The client that writes the collection under `epoch`, with the sealer for the same epoch.
    fn client(
        &self,
        service: &Arc<ManagedSyncService>,
        collection: kr_client::sync::membership::CollectionRef,
        epoch: u64,
    ) -> Result<SyncClient> {
        let shared = SharedCollectionService::new(Arc::clone(service), collection, epoch);
        let sealer = shared.sealer(Arc::new(self.keys()) as Arc<dyn CollectionKeys>);
        Ok(SyncClient::new(
            Arc::new(shared),
            Arc::new(sealer),
            self.store()?,
        ))
    }
}

/// The colour mode a settings object carries, when it carries one this build reads.
fn colour_mode_of(object: &SyncObject) -> Option<ColourMode> {
    match &object.body {
        SyncBody::Settings(settings) => match settings.values.get(COLOUR_MODE) {
            Some(SettingValue::Text(word)) => ColourMode::from_word(word),
            _ => None,
        },
        SyncBody::ClientSelection(_) => None,
    }
}

/// What a sync failure is to the person.
fn sync_failure(error: SyncError) -> CommandError {
    CommandError {
        code: error.code(),
        user_action: error.user_action().as_str().into(),
        message: error.to_string(),
    }
}

/// What a membership failure is to the person.
fn member_failure(error: kr_client::sync::membership::MembershipError) -> CommandError {
    use kr_client::sync::membership::MembershipError;

    match error {
        MembershipError::Service(error) | MembershipError::Keys(error) => CommandError::from(error),
        other => CommandError::local_failure(other.to_string()),
    }
}
