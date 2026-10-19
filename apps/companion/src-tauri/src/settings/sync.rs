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
//!   collection's identity (the settings object in it has the same identity), whether the
//!   collection's first key record is known to have been kept, and which devices it listed the last
//!   time this computer looked, with the oldest epoch whose objects it believes. It is made and
//!   flushed before anything is sent, because a collection claimed under an identity this device
//!   had not written down is one nobody finds again. It holds nothing secret.
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
//! # Taking a device out
//!
//! A revocation this computer sent is told to settings sync ([`SettingsSync::revocations_sent`]),
//! which writes it down in a record beside the others before it does anything that can wait or
//! fail ([`Fence`]). The membership cannot take it in while a step holds it, and a step holds it for
//! as long as it waits on the hosts or the service. While the record holds a device, no step starts
//! to publish, and settings and drafts both ask the record before they read and seal what they
//! send, so a send it refuses leaves no record and no sealed bytes behind. Each step takes in what
//! the record holds before it does anything else, whichever companion wrote it, and the same step
//! takes the device out. What was held back is sent afterwards, under the key that follows the
//! removal. A send already on its way cannot be called back.
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
//! 5. When the service holds the settings this device holds, and they were sealed under an epoch
//!    before the collection's newest, this device seals them again under the newest, as the same
//!    settings with a new revision: a device added since opens only what is sealed under its own
//!    epoch or a later one, and a device taken out may hold the key of every epoch before. Any
//!    member that holds the settings does this, not only the one that wrote them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use kr_client::pairing::owner::Ceremony;
use kr_client::services::SyncPosition;
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, SyncBackupService, managed_response_limits,
};
use kr_client::sync::membership::{
    CollectionRef, Device, DeviceDirectory, KeyRecordService, SyncMembership,
};
use kr_client::sync::{
    CollectionKeys, ConflictCopy, Published, Restored, SettingValue, SharedCollectionService,
    StoredCollectionKeys, SyncBody, SyncCheckpoint, SyncClient, SyncError, SyncObject,
    SyncSettings, SyncStore, Unread, fresh_object_id, fresh_revision,
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

mod fence;
mod members;

pub use fence::Fence;
use members::{Ask, Listed};
pub use members::{Candidate as DeviceCandidate, DevicesView, Happened, Member, Offer};

use super::{ColourMode, Hosts, LocalSettings};
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
    /// Drafts, which travel in the same collection when the person turns that on.
    pub drafts: super::drafts::DraftsView,
    /// Who shares the settings.
    pub devices: DevicesView,
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
            drafts: super::drafts::DraftsView::off(),
            devices: DevicesView {
                can_confirm: false,
                out: false,
                waiting: false,
                members: Vec::new(),
                candidates: Vec::new(),
                offers: Vec::new(),
                outcomes: Vec::new(),
            },
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
    /// True once the collection's first key record is known to be kept and installed.
    started: bool,
    /// The oldest epoch whose objects this computer believes. A device taken out keeps every key
    /// it held, so what an epoch before the last removal sealed is believed again only once a
    /// member has sealed it again under a later epoch.
    floor: u64,
    /// The newest record this computer looked at, with the devices it listed, so that a device
    /// missing from the next record, or a record missed, shows that one may have been taken out.
    seen: Option<Seen>,
    /// The settings this computer is sealing again under the newest epoch, until the service has
    /// taken them or another device's settings have been followed. Content that
    /// another device wrote and that was refused to this computer while it was sealing again is
    /// that device's to continue, for nothing here was changed by the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resealing: Option<Resealing>,
}

/// The settings being sealed again: the revision this computer held, the one it put in the store to
/// publish, and where the service held the settings it held. A step that stops between the two
/// finds either.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resealing {
    from: SyncRevisionId,
    to: SyncRevisionId,
    at: SyncPosition,
}

impl Resealing {
    /// Whether `revision` is one of the two.
    fn names(&self, revision: SyncRevisionId) -> bool {
        self.from == revision || self.to == revision
    }
}

/// The record this computer last looked at: its epoch and revision, and the devices it listed, by
/// both their keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seen {
    epoch: u64,
    revision: u64,
    members: BTreeSet<Device>,
}

impl Record {
    const VERSION: u32 = 2;

    /// The settings object of the collection. One collection holds one, and its identity is the
    /// collection's, so a device that joins a collection knows it without being told.
    fn object_id(&self) -> SyncObjectId {
        SyncObjectId::new(self.collection_id.get())
    }

    /// A record for a collection this computer has just started or joined.
    fn of(origin: &GatewayOrigin, collection_id: SyncCollectionId) -> Self {
        Self {
            version: Self::VERSION,
            service_origin: origin.as_str().to_owned(),
            collection_id,
            started: false,
            floor: 0,
            seen: None,
            resealing: None,
        }
    }

    /// Notes the devices the installed record, at `epoch` and `revision`, lists. The floor rises to
    /// `epoch` the first time a record is seen (nothing before it was sealed under a key this
    /// computer holds), whenever a device that was listed is not (a device that is listed again
    /// with other keys is not the one that was), and whenever more than one record passed since the
    /// last look, because what a record in between did is not known: a record at an unchanged
    /// epoch may add a device, and the next may take it out again. Returns whether the record
    /// changed.
    fn observe(&mut self, epoch: u64, revision: u64, members: BTreeSet<Device>) -> bool {
        let before = (self.floor, self.seen.clone());
        match &self.seen {
            None => self.floor = epoch,
            Some(seen) if revision > seen.revision => {
                if revision - seen.revision > 1
                    || epoch.saturating_sub(seen.epoch) > 1
                    || !seen.members.is_subset(&members)
                {
                    self.floor = epoch;
                }
            }
            Some(seen) if revision < seen.revision => return false,
            Some(_) => {}
        }
        self.seen = Some(Seen {
            epoch,
            revision,
            members,
        });
        before != (self.floor, self.seen.clone())
    }

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
    drafts: Arc<super::drafts::DraftsSync>,
    /// What this computer can ask of its hosts.
    hosts: Arc<dyn Hosts>,
    /// The platform's ceremony, which adding and joining ask the person to complete.
    ceremony: Arc<dyn Ceremony>,
    /// Who shares the settings, as the last step found it.
    devices: Mutex<DevicesView>,
    /// What the hosts listed, shared by every membership this computer opens.
    listed: Arc<Listed>,
    /// The collections the service said name this installation, which a join can name.
    offered: Mutex<Vec<CollectionRef>>,
    /// Whether the settings the service holds are sealed under keys this computer has not been given.
    waiting: std::sync::atomic::AtomicBool,
    /// The revocations this computer sent that the membership has not recorded, which hold back
    /// everything sent.
    fence: Arc<Fence>,
}

impl std::fmt::Debug for SettingsSync {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettingsSync")
            .finish_non_exhaustive()
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
        desk: Arc<crate::drafts::DraftDesk>,
        hosts: Arc<dyn Hosts>,
        ceremony: Arc<dyn Ceremony>,
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
        let fence = Arc::new(Fence::in_directory(&directory));
        let drafts = Arc::new(super::drafts::DraftsSync::open(
            &directory,
            Arc::clone(&desk),
            Arc::clone(&hosts),
            Arc::clone(&told),
            Arc::clone(&fence) as Arc<dyn kr_client::sync::PublishGate>,
        )?);
        desk.watched_by(Arc::clone(&drafts) as Arc<dyn crate::drafts::DraftWatch>);
        Ok(Self {
            directory,
            parts,
            local,
            steps: tokio::sync::Mutex::new(()),
            problem: Mutex::new(None),
            told,
            drafts,
            hosts,
            ceremony,
            devices: Mutex::new(DevicesView::default()),
            listed: Arc::new(Listed::default()),
            offered: Mutex::new(Vec::new()),
            waiting: std::sync::atomic::AtomicBool::new(false),
            fence,
        })
    }

    /// Drafts, kept in step through the same collection.
    #[must_use]
    pub fn drafts(&self) -> &super::drafts::DraftsSync {
        &self.drafts
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
                    drafts: self.drafts.view(),
                    devices: self.devices_view(),
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
                    drafts: self.drafts.view(),
                    devices: self.devices_view(),
                };
            }
        };
        let (outstanding, conflicts, paused, trouble) = match self.store() {
            Ok(store) => {
                let outstanding = store.unsettled().unwrap_or(0);
                let conflicts = store
                    .conflicts(record.object_id())
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
            drafts: self.drafts.view(),
            devices: self.devices_view(),
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
                let origin = self.parts.service.origin().clone();
                // A collection this computer joined, whose record was not kept before the
                // application stopped, is the one to go on with: starting another would leave the
                // settings of the first where nothing reads them.
                let held = self
                    .membership_asking(&self.managed(&origin)?, Ask::Never)?
                    .members()
                    .map_err(member_failure)?;
                let collection_id = match held {
                    Some(status) => status.collection.collection_id,
                    None => {
                        SyncCollectionId::new(fresh_object_id().map_err(CommandError::from)?.get())
                    }
                };
                let record = Record::of(&origin, collection_id);
                self.keep(&record)?;
                record
            }
        };
        let service = self.managed(&record.origin()?)?;
        let mut membership = self.membership_asking(&service, Ask::Never)?;
        if membership.members().map_err(member_failure)?.is_none() {
            membership
                .start(record.collection_id, now())
                .await
                .map_err(member_failure)?;
        }
        drop(membership);
        self.settle(&mut record, &service, Ask::Now)
            .await
            .map(|_| ())
    }

    /* ---------------------------------------------------------------------- */
    /* Keeping in step                                                         */
    /* ---------------------------------------------------------------------- */

    /// Brings this computer and the service to the same settings, when sync is on. Nothing happens
    /// when it is off. The hosts are asked who they list only when there is somebody to check, and
    /// not more than once a minute.
    ///
    /// # Errors
    ///
    /// Returns what stopped the step: the service could not be reached, or a local record could
    /// not be kept. The step is safe to run again, and the page is told what stopped it.
    pub async fn catch_up(&self) -> Result<()> {
        let outcome = self.catch_up_in_a_step(Ask::Recent).await;
        self.finished(&outcome);
        outcome
    }

    /// As [`Self::catch_up`], for a person who asked: the hosts are asked again.
    ///
    /// # Errors
    ///
    /// As [`Self::catch_up`].
    pub async fn catch_up_now(&self) -> Result<()> {
        let outcome = self.catch_up_in_a_step(Ask::Now).await;
        self.finished(&outcome);
        outcome
    }

    async fn catch_up_in_a_step(&self, ask: Ask) -> Result<()> {
        let _step = self.step().await?;
        let Some(mut record) = self.record()? else {
            return Ok(());
        };
        let service = self.managed(&record.origin()?)?;
        self.settle(&mut record, &service, ask).await.map(|_| ())
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
        ask: Ask,
    ) -> Result<Progress> {
        let now_ms = now();
        let ask = self.ask_for(service, ask)?;
        let mut membership = self.membership_asking(service, ask)?;
        // What this computer was told to take out comes first, whoever was told and whatever the
        // step does next.
        self.take_in_revocations(&mut membership)?;
        let reconciled = membership.reconcile(now_ms).await.map_err(member_failure);
        // What the membership holds is shown whatever the reconciliation could do.
        self.note_devices(&membership);
        self.told.tell();
        reconciled?;
        // A revocation that arrived while this step waited holds what is sent before the
        // membership can record it, which it cannot while this step holds it.
        if self.fence.is_raised() || !membership.publishes().map_err(member_failure)? {
            return Ok(Progress::Starting);
        }
        let status = membership
            .members()
            .map_err(member_failure)?
            .ok_or_else(|| {
                CommandError::local_failure("this computer holds no settings collection")
            })?;
        let Some((epoch, revision)) = status.installed else {
            return Ok(Progress::Starting);
        };
        // The membership is the word on which collection this computer is in. A step that stopped
        // between joining another and writing it down finds the record naming the one before, and
        // everything kept for that one (the object's identity, what was seen of its devices) is
        // let go with it.
        if record.collection_id != status.collection.collection_id {
            *record = Record::of(&record.origin()?, status.collection.collection_id);
            self.keep(record)?;
        }
        let members = status.members.iter().map(|member| member.device).collect();
        let mut changed = record.observe(epoch, revision, members);
        if !record.started {
            record.started = true;
            changed = true;
        }
        if changed {
            self.keep(record)?;
            self.told.tell();
        }
        let (client, sealed) = self.client(service, status.collection, epoch, record.floor)?;
        self.agree(&client, &sealed, record, epoch, now_ms).await?;
        // The settings agree. Drafts go in the same collection under the same epoch, when the
        // person asked for that, and what stops them never stops this step.
        self.drafts
            .pass(&super::drafts::Collection {
                service,
                collection: status.collection,
                epoch,
                floor: record.floor,
                keys: Arc::new(self.keys()),
            })
            .await;
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
            .conflicts(record.object_id())
            .map_err(sync_failure)?
            .items;
        if copies.is_empty() {
            return Ok(None);
        }
        let held = store.object(record.object_id()).map_err(sync_failure)?;
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
            .conflicts(record.object_id())
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
            .membership_asking(&service, Ask::Never)?
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
        let (client, _) = self.client(&service, collection, epoch, record.floor)?;
        // The choice first, on this computer; the service is told after, and may be told later.
        if let Some(mode) = chosen {
            self.local.set_colour_mode(mode)?;
            // The window is in the mode the file holds, whatever becomes of the rest of this step.
            self.told.tell();
            let held = store.object(record.object_id()).map_err(sync_failure)?;
            let object = self.object_of(record.object_id(), held.as_ref(), mode, now())?;
            store
                .put_object(&carrying(object, &copies))
                .map_err(sync_failure)?;
        } else {
            self.carry_marks(&store, record.object_id(), &copies)?;
        }
        for copy in copies {
            client
                .resolve(copy.conflict_id)
                .await
                .map_err(sync_failure)?;
        }
        // Sending the choice may fail and the choice stands: the step that next reaches the service
        // sends it, and the page is told what this one could not do.
        let sent = self
            .settle(&mut record, &service, Ask::Recent)
            .await
            .map(|_| ());
        self.finished(&sent);
        Ok(())
    }

    /// The agreement itself: see the module's list.
    #[allow(clippy::too_many_lines)]
    async fn agree(
        &self,
        client: &SyncClient,
        sealed: &SharedCollectionService,
        record: &mut Record,
        epoch: u64,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let object_id = record.object_id();
        let store = client.store();
        self.waiting
            .store(false, std::sync::atomic::Ordering::Relaxed);
        client
            .reconcile_unsettled(now_ms)
            .await
            .map_err(sync_failure)?;
        let chosen = self.local.chosen_colour_mode();
        let mut held = store.object(object_id).map_err(sync_failure)?;
        // A marker for settings this computer no longer holds is spent.
        if let Some(marker) = record.resealing
            && !held.as_ref().is_some_and(|one| marker.names(one.revision))
        {
            record.resealing = None;
            self.keep(record)?;
        }
        // Content another device wrote that this computer's own settings disagree with waits for
        // the person. Content that says what this computer's settings say asks nothing of them,
        // and is let go. So is content that was refused to settings this computer was only sealing
        // again, when the person has changed nothing since: it is the other device's settings that
        // continue this computer's.
        let waiting = store.conflicts(object_id).map_err(sync_failure)?.items;
        if !waiting.is_empty() {
            // Settings another device wrote over the ones being sealed again are not those
            // settings continued: the person chooses.
            let sealing_only = record.resealing.is_some_and(|marker| {
                !waiting
                    .iter()
                    .any(|copy| replaces(&copy.other, Some(marker.at), chosen))
            }) && chosen == held.as_ref().and_then(colour_mode_of)
                && chosen.is_some();
            if sealing_only
                && let Some(newest) = waiting
                    .iter()
                    .max_by_key(|copy| copy.other.updated_at_ms.get())
            {
                // The marker stays until the other device's settings are in place: a step that
                // stops in between finds the copy and the marker again.
                self.follow(
                    client,
                    object_id,
                    &newest.other,
                    chosen,
                    Some(newest.conflict_id),
                )
                .await?;
                record.resealing = None;
                return self.keep(record);
            }
            let mine = chosen;
            if mine.is_none()
                || waiting
                    .iter()
                    .any(|copy| colour_mode_of(&copy.other) != mine)
            {
                return Ok(());
            }
            if self.carry_marks(store, object_id, &waiting)? {
                held = store.object(object_id).map_err(sync_failure)?;
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
        if let Some(mode) = chosen
            && held.as_ref().and_then(colour_mode_of) != Some(mode)
        {
            if held.is_none() {
                // The first object this computer makes is published against nothing, and the
                // service refuses it where another device wrote first, keeping what it holds beside
                // it. What it holds may be sealed under epochs this computer was given no key for:
                // it could not be compared, and every step would leave one more refused write at
                // the service. So the service is asked first, at every step that would make the
                // object, whatever a read before it left behind, and a computer that cannot read
                // what it holds waits, with its choice kept, for a member to seal it again.
                match client
                    .fetch(SyncObjectKind::Settings, object_id, now_ms)
                    .await
                {
                    Ok(_) => {}
                    // The service holds nothing yet: this computer makes the first object.
                    Err(SyncError::Client(error)) if error.code() == ErrorCode::UnknownSession => {}
                    Err(SyncError::Client(error))
                        if error.code() == ErrorCode::HostNotConfigured =>
                    {
                        self.is_waiting();
                        return Ok(());
                    }
                    // An answer that did not come says nothing of what the service holds, and the
                    // first object is not made on it: the next step asks again.
                    Err(error) => return Err(sync_failure(error)),
                }
                if store
                    .checkpoint(object_id)
                    .map_err(sync_failure)?
                    .is_some_and(|note| note.published_revision.0.is_none())
                {
                    // A note kept without an object, and with no write of this computer's own named
                    // in it, names a write this computer read and did not take (the person chose
                    // while it was being read, or the step stopped before it was taken), and a
                    // publication against it would replace that write without a choice: forgotten,
                    // the publication is refused and keeps that content beside this computer's own.
                    store.forget_checkpoint(object_id).map_err(sync_failure)?;
                }
            }
            let object = self.object_of(object_id, held.as_ref(), mode, now_ms)?;
            store.put_object(&object).map_err(sync_failure)?;
            held = Some(object);
        }
        let note = store.checkpoint(object_id).map_err(sync_failure)?;
        let agreed = note.and_then(|note| note.published_revision.0);
        // A step stopped between putting the settings sealed again in the store and hearing how
        // their publication ended, and the service has not taken them: they are published again as
        // they were, and what becomes of them is the same.
        if let Some(marker) = record.resealing
            && let Some(object) = &held
            && object.revision == marker.to
            && agreed == Some(marker.from)
        {
            let original = SyncObject {
                revision: marker.from,
                ..object.clone()
            };
            return self
                .finish_reseal(client, record, original, chosen, now_ms)
                .await;
        }
        let changed = held
            .as_ref()
            .is_some_and(|object| agreed != Some(object.revision));
        if changed {
            return self
                .publish_change(client, sealed, record, note, now_ms)
                .await;
        }
        let fetched = client
            .fetch(SyncObjectKind::Settings, object_id, now_ms)
            .await;
        // The service's word on the epoch it sealed the object under, which decides only whether to
        // seal it again.
        let old = sealed
            .last_sealed_under()
            .is_some_and(|under| under < epoch);
        let agreed_object = held
            .clone()
            .filter(|object| agreed == Some(object.revision));
        match fetched {
            Ok(Restored::Settings { object, copy }) => match (held, copy) {
                // The service holds what this computer holds: they agree, and the note says so.
                (Some(held), None) => {
                    Self::agreed(store, object_id, held.revision)?;
                    if record.resealing.is_some() {
                        record.resealing = None;
                        self.keep(record)?;
                    }
                    if old {
                        self.seal_again(client, record, held, chosen, now_ms)
                            .await?;
                    }
                    Ok(())
                }
                // A device that held nothing is seeing the object for the first time.
                (None, Some(_)) => Ok(()),
                // This computer has changed nothing since it last agreed, and another device has
                // written since: the other device's settings continue this computer's, unless
                // they were written over the settings this computer holds without reading them.
                // The person chooses between the two then, and the copy waits.
                (Some(_), Some(_)) if replaces(&object, note.map(|note| note.position), chosen) => {
                    self.told.tell();
                    Ok(())
                }
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
            // The settings are sealed under keys this computer will not use: it joined after they
            // were, or a device was taken out since. A member that holds the settings seals them
            // again when the service still holds exactly what it agreed with; one that does not
            // has nothing to read until a member that holds what the service holds does, which is
            // waiting and not a fault, and writes nothing over it.
            Err(SyncError::Client(error)) if error.code() == ErrorCode::HostNotConfigured => {
                match agreed_object {
                    Some(object)
                        if old && note.map(|note| note.position) == sealed.last_found_at() =>
                    {
                        self.seal_again(client, record, object, chosen, now_ms)
                            .await
                    }
                    _ => {
                        self.is_waiting();
                        Ok(())
                    }
                }
            }
            Err(error) => Err(sync_failure(error)),
        }
    }

    /// Publishes the change the person made. Where the service refuses it and holds an object from
    /// before the floor that this computer cannot read, the object is not believed here: the
    /// person's change is made against where it stands, once, and replaces it. It says which write
    /// it went over, so that a device that holds that write is asked, where a device that does not
    /// follows. Nothing that was not believed is shown to anybody, and nothing a device holds is
    /// replaced without that device's person choosing.
    async fn publish_change(
        &self,
        client: &SyncClient,
        sealed: &SharedCollectionService,
        record: &mut Record,
        note: Option<SyncCheckpoint>,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let object_id = record.object_id();
        let store = client.store();
        for attempt in 0..2 {
            return match client.publish(object_id, now_ms).await {
                Ok(Published::Accepted { .. } | Published::Discarded { .. }) => {
                    if record.resealing.is_some() {
                        record.resealing = None;
                        self.keep(record)?;
                    }
                    Ok(())
                }
                Ok(Published::Conflicted { .. }) => {
                    self.told.tell();
                    Ok(())
                }
                Err(SyncError::Client(error)) if error.code() == ErrorCode::HostNotConfigured => {
                    let unbelieved = sealed
                        .last_sealed_under()
                        .is_some_and(|under| under < record.floor);
                    if attempt == 0
                        && note.is_some()
                        && unbelieved
                        && let Some(found) = sealed.last_found_at()
                        && let Some(held) = store.object(object_id).map_err(sync_failure)?
                    {
                        // The change is marked with the stretch it goes over, every write after the
                        // place this computer last read up to the one it replaces, before it is
                        // made against that place, so no write over that stretch is ever made
                        // without the mark.
                        let stretch = Unread::between(note.map(|note| note.position), found);
                        let mut over = held.went_over.clone();
                        if !over.contains(&stretch) {
                            over.push(stretch);
                        }
                        store
                            .put_object(&SyncObject {
                                revision: fresh_revision().map_err(CommandError::from)?,
                                went_over: over,
                                ..held
                            })
                            .map_err(sync_failure)?;
                        if store
                            .record_checkpoint(
                                object_id,
                                SyncCheckpoint {
                                    position: found,
                                    published_revision: Nullable::null(),
                                },
                            )
                            .map_err(sync_failure)?
                        {
                            continue;
                        }
                    }
                    self.is_waiting();
                    Ok(())
                }
                Err(error) => Err(sync_failure(error)),
            };
        }
        Ok(())
    }

    /// Makes the settings this computer holds carry what `copies` went over, as a new revision, when
    /// they do not yet. Returns whether it did.
    fn carry_marks(
        &self,
        store: &SyncStore,
        object_id: SyncObjectId,
        copies: &[ConflictCopy],
    ) -> Result<bool> {
        let Some(held) = store.object(object_id).map_err(sync_failure)? else {
            return Ok(false);
        };
        let carried = carrying(held.clone(), copies);
        if carried.went_over == held.went_over {
            return Ok(false);
        }
        store
            .put_object(&SyncObject {
                revision: fresh_revision().map_err(CommandError::from)?,
                ..carried
            })
            .map_err(sync_failure)?;
        Ok(true)
    }

    /// Notes that what the service holds cannot be read here yet, and tells the page.
    fn is_waiting(&self) {
        self.waiting
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.told.tell();
    }

    /// Seals the settings this computer and the service both hold again under the collection's
    /// newest epoch: the same settings, a new revision, published against where they stand. It
    /// carries no choice of the person's, so what becomes of it never asks them anything: when
    /// another device wrote first, that device's settings continue this computer's; when the
    /// answer is lost, the settings this computer held are put back and the marker in the record
    /// says the next refusal is not the person's to settle.
    async fn seal_again(
        &self,
        client: &SyncClient,
        record: &mut Record,
        held: SyncObject,
        chosen: Option<ColourMode>,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let again = SyncObject {
            revision: fresh_revision().map_err(CommandError::from)?,
            ..held.clone()
        };
        let at = client
            .store()
            .checkpoint(held.object_id)
            .map_err(sync_failure)?
            .map(|note| note.position)
            .ok_or_else(|| {
                CommandError::local_failure("this computer has no note of where the settings stand")
            })?;
        record.resealing = Some(Resealing {
            from: held.revision,
            to: again.revision,
            at,
        });
        self.keep(record)?;
        client.store().put_object(&again).map_err(sync_failure)?;
        self.finish_reseal(client, record, held, chosen, now_ms)
            .await
    }

    /// Publishes the settings put in the store to seal `held` again, and ends the sealing by what
    /// the service says: taken, or another device's settings followed, or the settings held put
    /// back, with the marker left where an answer that was lost may still turn out to be one.
    async fn finish_reseal(
        &self,
        client: &SyncClient,
        record: &mut Record,
        held: SyncObject,
        chosen: Option<ColourMode>,
        now_ms: TimestampMs,
    ) -> Result<()> {
        let object_id = held.object_id;
        let store = client.store();
        let outcome = client.publish(object_id, now_ms).await;
        if !matches!(outcome, Ok(Published::Accepted { .. })) {
            store.put_object(&held).map_err(sync_failure)?;
        }
        match outcome {
            Ok(Published::Accepted { .. }) => {
                record.resealing = None;
                self.keep(record)
            }
            Ok(Published::Conflicted { copy, .. }) => {
                let other = store
                    .conflicts(object_id)
                    .map_err(sync_failure)?
                    .items
                    .into_iter()
                    .find(|kept| kept.conflict_id == copy)
                    .map(|kept| kept.other);
                // The marker is spent once the other device's settings are in place, or once they
                // are left for the person: a step that stops in between finds both again.
                if let Some(other) = other
                    && !replaces(&other, record.resealing.map(|marker| marker.at), chosen)
                {
                    self.follow(client, object_id, &other, chosen, Some(copy))
                        .await?;
                }
                record.resealing = None;
                self.keep(record)?;
                self.told.tell();
                Ok(())
            }
            Ok(Published::Discarded { .. }) => {
                record.resealing = None;
                self.keep(record)
            }
            Err(SyncError::Client(error)) if error.code() == ErrorCode::HostNotConfigured => {
                record.resealing = None;
                self.keep(record)?;
                self.is_waiting();
                Ok(())
            }
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
            // What the settings this one is made from went over is still not settled.
            went_over: previous
                .map(|object| object.went_over.clone())
                .unwrap_or_default(),
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

    fn membership_with(
        &self,
        service: &Arc<ManagedSyncService>,
        directory: Arc<dyn DeviceDirectory>,
    ) -> Result<SyncMembership> {
        SyncMembership::open(
            self.directory.join(MEMBERSHIP),
            &self.parts.keys,
            self.keys(),
            Arc::clone(service) as Arc<dyn KeyRecordService>,
            directory,
        )
        .map_err(member_failure)
    }

    /// The client that writes the collection under `epoch`, with the sealer for the same epoch and
    /// the service it reads through, which says what epoch the object it last found was sealed
    /// under.
    fn client(
        &self,
        service: &Arc<ManagedSyncService>,
        collection: kr_client::sync::membership::CollectionRef,
        epoch: u64,
        floor: u64,
    ) -> Result<(SyncClient, Arc<SharedCollectionService>)> {
        let shared = Arc::new(
            SharedCollectionService::new(Arc::clone(service), collection, epoch)
                .believing_from(floor),
        );
        let sealer = shared.sealer(Arc::new(self.keys()) as Arc<dyn CollectionKeys>);
        let client = SyncClient::new(
            Arc::clone(&shared) as Arc<dyn SyncBackupService>,
            Arc::new(sealer),
            self.store()?,
        )
        .gated(Arc::clone(&self.fence) as Arc<dyn kr_client::sync::PublishGate>);
        Ok((client, shared))
    }
}

/// Whether `other` was made over the write that stood at `held` without reading it, and says
/// something other than the person's colour mode: it replaces what a device holds, which that
/// device's person chooses to let go of or not. Settings that say what the device's say replace
/// nothing.
fn replaces(other: &SyncObject, held: Option<SyncPosition>, chosen: Option<ColourMode>) -> bool {
    held.is_some_and(|held| other.went_over.iter().any(|stretch| stretch.covers(&held)))
        && colour_mode_of(other) != chosen
}

/// `object` with every stretch that `copies` went over and it does not carry yet: whoever chooses
/// beside a write that went over another's does not settle what that write replaced.
fn carrying(mut object: SyncObject, copies: &[ConflictCopy]) -> SyncObject {
    for stretch in copies.iter().flat_map(|copy| copy.other.went_over.iter()) {
        if !object.went_over.contains(stretch) {
            object.went_over.push(*stretch);
        }
    }
    object
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

/// The identifier a device is named by to the page: the installation its authorisation key derives.
fn installation_id_of(device: &Device) -> String {
    installation_id(&device.authorisation).to_string()
}

/// What a sync failure is to the person.
pub(super) fn sync_failure(error: SyncError) -> CommandError {
    CommandError {
        code: error.code(),
        user_action: error.user_action().as_str().into(),
        message: error.to_string(),
    }
}

/// What a membership failure is to the person, in words that name no record or file.
fn member_failure(error: kr_client::sync::membership::MembershipError) -> CommandError {
    use kr_client::sync::membership::MembershipError;

    match error {
        MembershipError::Service(error) | MembershipError::Keys(error) => CommandError::from(error),
        MembershipError::NoHostAnswered => CommandError::unavailable(
            "none of your hosts answered, so who may share your settings could not be checked",
        ),
        MembershipError::HostSilent => CommandError::unavailable(
            "one of your hosts did not answer or will not list its devices to this computer, so the \
             settings were not joined; try again when it does, or unpair a host that is gone",
        ),
        MembershipError::NotCommitted => {
            CommandError::refused("no host lists that device as one of yours any more")
        }
        MembershipError::NotListed => CommandError::refused(
            "the other device has not shared its settings with this computer yet, or has taken \
             it out",
        ),
        MembershipError::AlreadyMember | MembershipError::AlreadyListed => CommandError::refused(
            "this computer already shares settings, and that device already does",
        ),
        MembershipError::Out => CommandError::refused(
            "this computer was taken out of the shared settings; it joins them again when you \
             confirm here",
        ),
        MembershipError::NoMembership | MembershipError::NotInstalled => {
            CommandError::refused("this computer is not sharing settings yet")
        }
        MembershipError::CannotRemoveSelf => {
            CommandError::refused("a computer does not take itself out; another one does")
        }
        MembershipError::NotAMember => {
            CommandError::refused("that device does not share the settings")
        }
        MembershipError::Plan(_) => CommandError::refused(
            "the confirmation is no longer valid, so nothing was changed; try again",
        ),
        MembershipError::Busy
        | MembershipError::PutBackWhileRead
        | MembershipError::KeysStillHeld
        | MembershipError::UnsettledRequest => CommandError::unavailable(
            "the settings were being changed at the same moment; try again in a little while",
        ),
        MembershipError::BrokenChain | MembershipError::Exhausted => CommandError::local_failure(
            "what the service holds for these settings cannot be followed from here, so this \
             computer waits for you to join them again",
        ),
        _ => CommandError::local_failure(
            "who shares the settings could not be read or kept on this computer",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Device {
        Device::from_keys(&DeviceKeys::generate().expect("keys"))
    }

    fn members(of: &[Device]) -> BTreeSet<Device> {
        of.iter().copied().collect()
    }

    fn record() -> Record {
        let origin = GatewayOrigin::new("https://reach.example").expect("an origin");
        Record::of(
            &origin,
            SyncCollectionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        )
    }

    #[test]
    fn the_first_record_seen_is_the_oldest_believed() {
        let (a, b) = (device(), device());
        let mut one = record();
        assert!(one.observe(0, 1, members(&[a])));
        assert_eq!(one.floor, 0);
        let mut joined = record();
        assert!(joined.observe(4, 9, members(&[a, b])));
        assert_eq!(
            joined.floor, 4,
            "a device that joins holds no key before its own"
        );
    }

    #[test]
    fn a_device_added_leaves_the_floor_where_it_was() {
        let (a, b) = (device(), device());
        let mut one = record();
        one.observe(0, 1, members(&[a]));
        assert!(one.observe(1, 2, members(&[a, b])));
        assert_eq!(one.floor, 0);
        assert!(!one.observe(1, 2, members(&[a, b])), "nothing changed");
    }

    #[test]
    fn a_device_taken_out_raises_the_floor_to_the_epoch_it_was_taken_out_at() {
        let (a, b, c, d) = (device(), device(), device(), device());
        let mut one = record();
        one.observe(0, 1, members(&[a, b]));
        one.observe(1, 2, members(&[a, b, c]));
        one.observe(2, 3, members(&[a, c]));
        assert_eq!(one.floor, 2);
        one.observe(3, 4, members(&[a, c, d]));
        assert_eq!(one.floor, 2, "an addition after it leaves it");
    }

    #[test]
    fn records_that_were_not_all_seen_raise_the_floor_whatever_they_listed() {
        let (a, b) = (device(), device());
        let mut one = record();
        one.observe(1, 2, members(&[a, b]));
        // A device may have been taken out and listed again between the two looks.
        one.observe(4, 5, members(&[a, b]));
        assert_eq!(one.floor, 4);
    }

    #[test]
    fn a_record_that_added_a_device_and_the_next_that_took_it_out_raise_the_floor() {
        let (a, b) = (device(), device());
        let mut one = record();
        one.observe(1, 2, members(&[a, b]));
        // The record in between kept the epoch and added a device that held the key for it; the
        // record after moved the epoch on without it. The epoch moved once and the devices are
        // the same, but two records passed.
        one.observe(2, 4, members(&[a, b]));
        assert_eq!(one.floor, 2);
    }

    #[test]
    fn a_device_listed_again_under_other_keys_is_not_the_device_that_was_listed() {
        let (a, b) = (device(), device());
        let rekeyed = Device {
            authorisation: b.authorisation,
            stored_envelope: device().stored_envelope,
        };
        let mut one = record();
        one.observe(1, 2, members(&[a, b]));
        one.observe(2, 3, members(&[a, rekeyed]));
        assert_eq!(
            one.floor, 2,
            "the holder of the old stored-envelope key opens what was wrapped to it"
        );
    }

    #[test]
    fn a_record_older_than_the_one_seen_changes_nothing() {
        let (a, z) = (device(), device());
        let mut one = record();
        one.observe(3, 7, members(&[a]));
        assert!(!one.observe(2, 6, members(&[a, z])));
        assert_eq!(one.floor, 3);
        assert_eq!(one.seen.as_ref().map(|seen| seen.epoch), Some(3));
    }
}
