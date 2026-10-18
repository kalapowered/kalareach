//! Drafts kept in step with the person's other devices, through the collection settings sync keeps.
//!
//! A draft is a prompt somebody has not sent, so it is the most sensitive thing this application
//! syncs, and it is a second choice the person makes after turning settings sync on. Nothing here
//! sends a draft anywhere that runs it: a draft that arrives from another device is kept beside
//! this device's own as a copy, never put in a composer and never submitted, and a draft this
//! device publishes is still this device's alone to change.
//!
//! # Privacy mode is a host's
//!
//! A draft is written for a session, and a session lives on one host. Privacy mode is that host's,
//! and it stops what the host's sessions' content leaves for the sync service, at a generation the
//! host records. So the drafts of each host are published through a sync store of their own, fenced
//! at that host's generation, and the settings store is never fenced: the colour mode carries no
//! session content.
//!
//! What a device can read of a host's privacy mode is [`DraftHosts`]'s to say, and it says one of
//! three things. A host with privacy mode off lets its drafts be published; a host with it on does
//! not, and an answer that arrives after the host went private is discarded by the store's
//! generation; and a host this device cannot read, because it is not connected to it or holds no
//! right to ask, is treated as private. A draft whose host this device does not know, because it was
//! written while no host was connected, is kept here too. Each draft kept here, and why, is in the
//! view the page shows.
//!
//! # What lives where
//!
//! Everything is under `settings-sync/drafts` and holds no secret and no draft text.
//!
//! * `on.json`: whether the person turned drafts sync on.
//! * `hosts.json`: which host each draft was written for, by the host's environment.
//! * `removals.json`: drafts thrown away or sent whose copy the service still holds, each with the
//!   position it was at, until the service has removed it.
//! * `pulled.json`: the other devices' drafts this device has brought down, so a later look at the
//!   collection asks only for what has changed.
//! * `<environment>/store` and `pull/store`: the sync stores. The second belongs to no host: what it
//!   holds came down, nothing in it left.
//!
//! # A pass
//!
//! One pass, in this order: the work of each host's store that left without an answer is asked
//! about; removals owed to the service are made; each draft of this device whose host allows it is
//! published if it changed; and the drafts of other devices that are new or changed are brought
//! down beside this device's own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use kr_client::ClientError;
use kr_client::drafts::{
    Draft, DraftError, DraftRemoval, DraftSealer, DraftSync, Published, SyncCheckpoint,
};
use kr_client::services::sync::KnownRevision;
use kr_client::services::{ManagedSyncService, SyncBackupService};
use kr_client::sync::membership::CollectionRef;
use kr_client::sync::{CollectionKeys, SharedCollectionService, SyncClient, SyncError, SyncStore};
use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use kr_protocol::ids::{DraftId, EnvironmentId, SyncObjectId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::sync::SyncObjectKind;
use serde::{Deserialize, Serialize};

use super::Told;
use crate::drafts::{DraftDesk, DraftHost, DraftWatch};
use crate::error::{CommandError, Result};

/// The directory under settings sync's own that drafts keep their records in.
const DIRECTORY: &str = "drafts";
const ON: &str = "on.json";
const HOSTS: &str = "hosts.json";
const REMOVALS: &str = "removals.json";
const PULLED: &str = "pulled.json";
const RECORDS_LOCK: &str = "records.lock";
const STORE: &str = "store";
const PULL: &str = "pull";

/// The most a record may be, in bytes. Each is a list of identifiers.
const RECORD_LIMIT: u64 = 1024 * 1024;

/// What a device can read of one host's privacy mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostPrivacy {
    /// Privacy mode is off, at this generation.
    Off {
        /// The host's privacy generation.
        generation: u64,
    },
    /// Privacy mode is on, at this generation.
    On {
        /// The host's privacy generation.
        generation: u64,
    },
    /// This device cannot read it, and the host's drafts are treated as private.
    Unreadable {
        /// Why, in words a person is shown.
        reason: String,
    },
}

/// What drafts sync asks of the hosts this device knows.
pub trait DraftHosts: Send + Sync {
    /// Privacy mode at the host of `environment`, as this device can read it now.
    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>>;
}

/// The host a draft was written for, as the record keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRecord {
    environment: String,
    name: Option<String>,
}

/// Why a draft is kept on this device and not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    /// Privacy mode is on at the host the draft is for.
    Private,
    /// This device cannot read privacy mode at the host the draft is for.
    Unreadable,
    /// The draft was written while no host was connected, so no host is known to say.
    UnknownHost,
    /// The draft is larger than a synchronised draft may be.
    TooLarge,
}

/// Drafts kept on this device and not sent, for one reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeptHere {
    /// What the host is called, when the host is known.
    pub host: Option<String>,
    /// Why.
    pub why: Why,
    /// Why, when this device could not read the host's privacy mode: what it said.
    pub detail: Option<String>,
    /// How many drafts.
    pub drafts: u64,
}

/// What the page is shown of drafts sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DraftsView {
    /// Whether the person turned it on.
    pub enabled: bool,
    /// The drafts kept on this device and not sent, with why.
    pub kept_here: Vec<KeptHere>,
    /// What the last pass could not do, in words, until a pass succeeds.
    pub problem: Option<String>,
    /// How many drafts of other devices have been brought down since this application started, so
    /// that a page that counts them knows to read the drafts again.
    pub arrivals: u64,
}

impl DraftsView {
    /// Drafts sync as a computer that cannot take part in it shows it: off, with nothing kept.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            enabled: false,
            kept_here: Vec::new(),
            problem: None,
            arrivals: 0,
        }
    }
}

/// A removal the service is still owed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owed {
    draft: String,
    /// The host the draft was for, when known.
    host: Option<String>,
    /// Where the service held the draft when it left this device, when this device knew.
    note: Option<SyncCheckpoint>,
}

/// Drafts kept in step through the settings collection.
pub struct DraftsSync {
    directory: PathBuf,
    desk: Arc<DraftDesk>,
    hosts: Arc<dyn DraftHosts>,
    told: Arc<Told>,
    wake: tokio::sync::Notify,
    /// Taken for the length of a change to one of the small records.
    records: Mutex<()>,
    /// What the last pass found.
    last: Mutex<Last>,
    arrivals: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct Last {
    kept: Vec<KeptHere>,
    problem: Option<String>,
}

impl std::fmt::Debug for DraftsSync {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DraftsSync").finish_non_exhaustive()
    }
}

/// What one pass reads of a collection and writes through.
pub struct Collection<'a> {
    /// The sync service this device signs for.
    pub service: &'a Arc<ManagedSyncService>,
    /// The collection.
    pub collection: CollectionRef,
    /// The epoch the collection's objects are sealed under now.
    pub epoch: u64,
    /// Where the collection's keys are.
    pub keys: Arc<dyn CollectionKeys>,
}

impl DraftsSync {
    /// Drafts sync over the drafts of `desk`, with its records under `settings_sync`.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the directory cannot be made.
    pub fn open(
        settings_sync: &std::path::Path,
        desk: Arc<DraftDesk>,
        hosts: Arc<dyn DraftHosts>,
        told: Arc<Told>,
    ) -> Result<Self> {
        let directory = settings_sync.join(DIRECTORY);
        create_private_directory(&directory)
            .map_err(|error| error.to_string())
            .and_then(|()| flush_path_names(&directory).map_err(|error| error.to_string()))
            .map_err(|error| {
                CommandError::local_failure(format!(
                    "the directory drafts sync keeps its records in could not be made: {error}"
                ))
            })?;
        Ok(Self {
            directory,
            desk,
            hosts,
            told,
            wake: tokio::sync::Notify::new(),
            records: Mutex::new(()),
            last: Mutex::new(Last::default()),
            arrivals: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// What the page is shown. Nothing is sent.
    #[must_use]
    pub fn view(&self) -> DraftsView {
        let last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        DraftsView {
            enabled: self.enabled().unwrap_or(false),
            kept_here: last.kept.clone(),
            problem: last.problem.clone(),
            arrivals: self.arrivals.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Whether the person turned drafts sync on.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the record cannot be read.
    pub fn enabled(&self) -> Result<bool> {
        let on: Option<On> = self.read(ON)?;
        Ok(on.is_some_and(|on| on.on))
    }

    /// Turns drafts sync on or off. Off stops what a pass does and keeps every record, so turning
    /// it on again takes up where it stopped.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the choice cannot be kept.
    pub fn set_enabled(&self, on: bool) -> Result<()> {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        self.write(ON, &On { version: 1, on })?;
        if !on {
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Last::default();
        }
        self.told.tell();
        self.wake.notify_one();
        Ok(())
    }

    /// Has a pass taken up what changed, but only when drafts sync is on: typing in a draft that is
    /// kept on this computer reaches no service and wakes nothing.
    fn wake_when_on(&self) {
        if self.enabled().unwrap_or(false) {
            self.wake.notify_one();
        }
    }

    /// Waits until something that drafts sync keeps in step has changed.
    pub async fn changed(&self) {
        self.wake.notified().await;
    }

    /// One pass, under the step settings sync holds.
    ///
    /// It never fails the step it is in: what stopped it is in the view, and the next pass goes on.
    pub async fn pass(&self, on: &Collection<'_>, now: TimestampMs) {
        let outcome = self.pass_in(on, now).await;
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            match outcome {
                Ok((kept, problem)) => {
                    *last = Last {
                        kept,
                        problem: problem.map(|error| error.message),
                    }
                }
                Err(error) => last.problem = Some(error.message),
            }
        }
        self.told.tell();
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one pass, in the order the module doc gives"
    )]
    async fn pass_in(
        &self,
        on: &Collection<'_>,
        now: TimestampMs,
    ) -> Result<(Vec<KeptHere>, Option<CommandError>)> {
        if !self.enabled()? {
            return Ok((Vec::new(), None));
        }
        let shared = Arc::new(SharedCollectionService::new(
            Arc::clone(on.service),
            on.collection,
            on.epoch,
        ));
        let sealer: Arc<dyn DraftSealer> = Arc::new(shared.sealer(Arc::clone(&on.keys)));
        let service: Arc<dyn SyncBackupService> = Arc::clone(&shared) as _;
        let store = self.desk.store()?;
        let listing = blocking({
            let store = store.clone();
            move || store.list().map_err(crate::drafts::failure)
        })
        .await?;
        let own: Vec<Draft> = listing
            .drafts
            .into_iter()
            .filter(|draft| draft.conflict_of.0.is_none())
            .collect();
        let hosts_of: BTreeMap<String, HostRecord> = self.read(HOSTS)?.unwrap_or_default();
        let owed: Vec<Owed> = self.read(REMOVALS)?.unwrap_or_default();

        // What each host's privacy mode is now, for every host a draft or a removal is for.
        let mut privacy: BTreeMap<EnvironmentId, HostPrivacy> = BTreeMap::new();
        let environments = own
            .iter()
            .filter_map(|draft| hosts_of.get(&draft.draft_id.to_string()))
            .map(|host| &host.environment)
            .chain(owed.iter().filter_map(|owes| owes.host.as_ref()))
            .filter_map(|text| environment_of(text));
        let names: BTreeMap<EnvironmentId, String> = hosts_of
            .values()
            .filter_map(|host| Some((environment_of(&host.environment)?, host.name.clone()?)))
            .collect();
        for environment in environments {
            if let std::collections::btree_map::Entry::Vacant(slot) = privacy.entry(environment) {
                slot.insert(self.hosts.privacy(environment).await);
            }
        }

        // The store of each host, fenced or let go to match what its privacy mode is.
        let mut stores: BTreeMap<EnvironmentId, (DraftSync, SyncClient)> = BTreeMap::new();
        let mut disagreed: Vec<(EnvironmentId, String)> = Vec::new();
        for (environment, state) in &privacy {
            let directory = self.directory.join(environment.to_string()).join(STORE);
            let client = SyncClient::new(
                Arc::clone(&service),
                Arc::clone(&sealer),
                SyncStore::open(&directory).map_err(super::sync::sync_failure)?,
            );
            if let Err(error) = apply_privacy(&client, state) {
                disagreed.push((*environment, error.message));
                continue;
            }
            let drafts = DraftSync::new(
                Arc::clone(&service),
                Arc::clone(&sealer),
                SyncStore::open(&directory).map_err(super::sync::sync_failure)?,
            );
            // Work that left without an answer is asked about first, as a cleanup would.
            drafts
                .reconcile_unsettled(&store, now)
                .await
                .map_err(super::sync::sync_failure)?;
            stores.insert(*environment, (drafts, client));
        }
        // A host whose store disagrees with what it reports is not believed this pass.
        for (environment, reason) in disagreed {
            privacy.insert(environment, HostPrivacy::Unreadable { reason });
        }
        let pull_directory = self.directory.join(PULL).join(STORE);
        let puller = DraftSync::new(
            Arc::clone(&service),
            Arc::clone(&sealer),
            SyncStore::open(&pull_directory).map_err(super::sync::sync_failure)?,
        );

        // Removals the service is owed. A host's are made through its store, so they wait while
        // the host's privacy mode is on; one with no host goes through the store of what came down.
        let mut made: BTreeSet<String> = BTreeSet::new();
        let mut problem = None;
        for owes in &owed {
            let id = draft_of(&owes.draft);
            let drafts = match owes.host.as_deref().and_then(environment_of) {
                Some(environment) => stores.get(&environment).map(|(drafts, _)| drafts),
                None => Some(&puller),
            };
            let (Some(drafts), Some(id)) = (drafts, id) else {
                continue;
            };
            // The newest note the draft store holds for it: an answer to a publication that was
            // out when the draft left settles a note after the draft is gone, and that position is
            // where the service holds the draft now.
            let newest = {
                let store = store.clone();
                blocking(move || store.checkpoint(id).map_err(crate::drafts::failure)).await?
            };
            let Some(position) = newest.or(owes.note).map(|note| note.position) else {
                // Nothing is known of it at the service. It is owed only while a publication of it
                // is still out, whose answer will say where it landed.
                let out = drafts
                    .store()
                    .requests()
                    .map_err(super::sync::sync_failure)?
                    .items
                    .iter()
                    .any(|record| record.object_id.get() == id.get() && record.dispatched());
                if !out {
                    made.insert(owes.draft.clone());
                }
                continue;
            };
            match drafts.remove(id, position, now).await {
                Ok(DraftRemoval::Removed { .. } | DraftRemoval::AlreadyGone) => {
                    made.insert(owes.draft.clone());
                }
                // Written since the position this device named, which is this device's own later
                // publication: the removal is still owed, against where that one left it.
                Ok(DraftRemoval::Moved { .. }) => {}
                // The host is private: the removal waits for it.
                Err(SyncError::Fenced { .. }) => {}
                Err(error) => {
                    problem.get_or_insert_with(|| super::sync::sync_failure(error));
                }
            }
        }
        // What was made leaves the ledger, and what was added to it while the pass ran stays.
        let still_owed = self.forget_removals(&made)?;

        // The drafts of this device, published where their host allows it.
        let mut kept: BTreeMap<(Option<EnvironmentId>, Why, Option<String>), u64> = BTreeMap::new();
        for draft in &own {
            // The person may have turned drafts sync off while this pass was out at the service.
            if !self.enabled()? {
                break;
            }
            let host = hosts_of
                .get(&draft.draft_id.to_string())
                .and_then(|host| environment_of(&host.environment));
            let Some(host) = host else {
                *kept.entry((None, Why::UnknownHost, None)).or_default() += 1;
                continue;
            };
            let note = {
                let (store, id) = (store.clone(), draft.draft_id);
                blocking(move || store.checkpoint(id).map_err(crate::drafts::failure)).await?
            };
            if note.is_some_and(|note| note.published_revision.0 == Some(draft.revision)) {
                continue;
            }
            // The host's privacy mode is read again, and its store fenced or let go to match,
            // just before this draft leaves: the pass may have waited on the service since the
            // first read, and a host that went private in that time is private for this draft.
            let state = self.hosts.privacy(host).await;
            let why = match &state {
                HostPrivacy::Off { .. } => None,
                HostPrivacy::On { .. } => Some((Why::Private, None)),
                HostPrivacy::Unreadable { reason } => Some((Why::Unreadable, Some(reason.clone()))),
            };
            if let Some((_, client)) = stores.get(&host)
                && let Err(error) = apply_privacy(client, &state)
            {
                *kept
                    .entry((Some(host), Why::Unreadable, Some(error.message)))
                    .or_default() += 1;
                continue;
            }
            if let Some((why, detail)) = why {
                *kept.entry((Some(host), why, detail)).or_default() += 1;
                continue;
            }
            let Some((drafts, _)) = stores.get(&host) else {
                // The host had nothing to read when the pass began, so it has no store yet: the
                // next pass makes one.
                *kept.entry((Some(host), Why::Unreadable, None)).or_default() += 1;
                continue;
            };
            match drafts
                .publish(&store, draft.draft_id, draft.revision, now)
                .await
            {
                Ok(Published::Conflicted { .. }) => self.told.tell(),
                Ok(Published::Accepted { .. } | Published::Discarded { .. }) => {}
                Err(SyncError::Fenced { .. }) => {
                    *kept.entry((Some(host), Why::Private, None)).or_default() += 1;
                }
                Err(error) if too_large(&error) => {
                    *kept.entry((Some(host), Why::TooLarge, None)).or_default() += 1;
                }
                // The person wrote the draft again, or sent it, since this pass listed the drafts:
                // the next pass takes what is there then.
                Err(error) if changed_since_listed(&error) => {}
                // One draft's failure is not the others': the pass goes on and says what stopped.
                Err(error) => {
                    problem.get_or_insert_with(|| super::sync::sync_failure(error));
                }
            }
        }

        if let Err(error) = self
            .bring_down(on, &puller, &store, &own, &still_owed, now)
            .await
        {
            problem.get_or_insert(error);
        }

        let kept = kept
            .into_iter()
            .map(|((host, why, detail), drafts)| KeptHere {
                host: host.and_then(|environment| names.get(&environment).cloned()),
                why,
                detail,
                drafts,
            })
            .collect();
        Ok((kept, problem))
    }

    /// The drafts of other devices that are new or changed, kept beside this device's own.
    ///
    /// The comparison names what this device already holds, so the answer is only what changed, and
    /// a collection nothing changed in costs one small request.
    async fn bring_down(
        &self,
        on: &Collection<'_>,
        puller: &DraftSync,
        store: &kr_client::drafts::DraftStore,
        own: &[Draft],
        owed: &[Owed],
        now: TimestampMs,
    ) -> Result<()> {
        let mut pulled: BTreeSet<String> = self.read(PULLED)?.unwrap_or_default();
        let mine: BTreeSet<String> = own.iter().map(|draft| draft.draft_id.to_string()).collect();
        let leaving: BTreeSet<&str> = owed.iter().map(|owes| owes.draft.as_str()).collect();
        // What this device holds, by the revision the service held it at when it last said so.
        let mut known = Vec::new();
        for id in pulled.iter().chain(mine.iter()) {
            let Some(id) = draft_of(id) else { continue };
            let note = {
                let store = store.clone();
                blocking(move || store.checkpoint(id).map_err(crate::drafts::failure)).await?
            };
            if let Some(revision) = note.and_then(|note| note.position.revision.0) {
                known.push(KnownRevision {
                    object_id: SyncObjectId::new(id.get()),
                    revision,
                });
            }
        }
        let Some(found) = on
            .service
            .compare_shared(&on.collection, &known, false, None)
            .await
            .map_err(CommandError::from)?
        else {
            return Ok(());
        };
        // A draft of another device that its device removed is gone at the service, and so is what
        // this device kept to ask about it: the copy stays, which is the person's to keep or throw
        // away, and the note and the entry in the list of what came down go, or the list of what
        // this computer asks about only grows.
        let removed: Vec<DraftId> = found
            .removed
            .iter()
            .map(|gone| DraftId::new(gone.object_id.get()))
            .filter(|id| pulled.contains(&id.to_string()))
            .collect();
        if !removed.is_empty() {
            for id in &removed {
                pulled.remove(&id.to_string());
                let store = store.clone();
                let id = *id;
                blocking(move || store.forget_checkpoint(id).map_err(crate::drafts::failure))
                    .await?;
            }
            self.write(PULLED, &pulled)?;
        }
        let mut problem = None;
        for held in found
            .objects
            .iter()
            .filter(|held| held.kind == SyncObjectKind::Draft)
        {
            let id = DraftId::new(held.object_id.get());
            // A draft this device holds is published by this device, which reconciles it by the
            // rules of a refused write; one it is removing is not brought back.
            if mine.contains(&id.to_string()) || leaving.contains(id.to_string().as_str()) {
                continue;
            }
            match puller.fetch_beside(store, id, now).await {
                Ok(_) => {
                    pulled.insert(id.to_string());
                    self.write(PULLED, &pulled)?;
                    self.arrivals
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.told.tell();
                }
                // One draft this version cannot open does not keep the others from coming down.
                Err(error) => {
                    problem.get_or_insert_with(|| super::sync::sync_failure(error));
                }
            }
        }
        problem.map_or(Ok(()), Err)
    }

    /// Takes the removals the service has made out of the ledger, and returns what is still owed.
    ///
    /// The ledger is read again under the lock the watcher takes to add to it, so a removal added
    /// while a pass was out at the service is not written over.
    fn forget_removals(&self, made: &BTreeSet<String>) -> Result<Vec<Owed>> {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let _file = self.records_file()?;
        let mut owed: Vec<Owed> = self.read(REMOVALS)?.unwrap_or_default();
        if !made.is_empty() {
            owed.retain(|owes| !made.contains(&owes.draft));
            self.write(REMOVALS, &owed)?;
        }
        Ok(owed)
    }

    /// Takes the lock a second companion on this computer waits on while it changes the small
    /// records, held for as long as the returned file is.
    fn records_file(&self) -> Result<std::fs::File> {
        super::locked_file(&self.directory.join(RECORDS_LOCK)).map_err(|error| {
            CommandError::local_failure(format!(
                "the records drafts sync keeps could not be locked on this computer: {error}"
            ))
        })
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let Some(bytes) =
            read_owner_only_file(&self.directory.join(name), RECORD_LIMIT).map_err(|error| {
                CommandError::local_failure(format!(
                    "a record drafts sync keeps could not be read: {error}"
                ))
            })?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            CommandError::local_failure(format!(
                "a record drafts sync keeps is not one this version reads: {error}"
            ))
        })
    }

    fn write<T: Serialize + ?Sized>(&self, name: &str, record: &T) -> Result<()> {
        let text = serde_json::to_vec_pretty(record).map_err(|error| {
            CommandError::local_failure(format!(
                "a record drafts sync keeps could not be written: {error}"
            ))
        })?;
        write_owner_only_file(&self.directory.join(name), &text).map_err(|error| {
            CommandError::local_failure(format!(
                "a record drafts sync keeps could not be kept: {error}"
            ))
        })
    }
}

impl DraftWatch for DraftsSync {
    fn is_a_device_copy(&self, of: DraftId) -> bool {
        self.read::<BTreeSet<String>>(PULLED)
            .ok()
            .flatten()
            .is_some_and(|pulled| pulled.contains(&of.to_string()))
    }

    fn saved(&self, draft: DraftId, host: Option<DraftHost>, replace: bool) {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        // A record that cannot be locked is not changed: the draft keeps no host, which is the
        // draft kept here, and the next save tries again.
        let Ok(_file) = self.records_file() else {
            return;
        };
        if let Some(host) = host {
            let mut hosts: BTreeMap<String, HostRecord> =
                self.read(HOSTS).ok().flatten().unwrap_or_default();
            let key = draft.to_string();
            let value = HostRecord {
                environment: host.environment.to_string(),
                name: host.name,
            };
            // The host a draft was written for is the one that was connected when it was first
            // written. A later save, from a window that was left open or from a connection to
            // another host, is not a reason to move it: only the person's own choice of a session
            // on the connected host (a retarget) does.
            if (replace || !hosts.contains_key(&key)) && hosts.get(&key) != Some(&value) {
                hosts.insert(key, value);
                // A record that cannot be kept leaves the draft with no host, which is the draft kept
                // here, and the next save tries again.
                let _ = self.write(HOSTS, &hosts);
            }
        }
        self.wake_when_on();
    }

    fn gone(&self, draft: DraftId, note: Option<SyncCheckpoint>) {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let Ok(_file) = self.records_file() else {
            return;
        };
        let mut hosts: BTreeMap<String, HostRecord> =
            self.read(HOSTS).ok().flatten().unwrap_or_default();
        let host = hosts
            .remove(&draft.to_string())
            .map(|host| host.environment);
        let _ = self.write(HOSTS, &hosts);
        // A draft that never reached the service owes it nothing, unless a publication of it is
        // still out, which only drafts sync being on can mean.
        if note.is_some() || self.enabled().unwrap_or(false) {
            let mut owed: Vec<Owed> = self.read(REMOVALS).ok().flatten().unwrap_or_default();
            owed.push(Owed {
                draft: draft.to_string(),
                host,
                note,
            });
            let _ = self.write(REMOVALS, &owed);
            self.wake_when_on();
        }
    }
}

/// Whether drafts sync is on, as the record keeps it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct On {
    version: u32,
    on: bool,
}

/// Fences or lets go `store` to match what the host's privacy mode is.
///
/// A host that cannot be read is fenced at the generation the store already holds: no generation is
/// known, and a generation never goes backwards.
fn apply_privacy(client: &SyncClient, state: &HostPrivacy) -> Result<()> {
    let held = client
        .store()
        .privacy()
        .map_err(super::sync::sync_failure)?;
    match state {
        HostPrivacy::Off { generation } => {
            if held.fenced || held.generation.get() < *generation {
                client
                    .resume(*generation)
                    .map_err(super::sync::sync_failure)?;
            }
        }
        HostPrivacy::On { generation } => {
            if !held.fenced || held.generation.get() < *generation {
                client
                    .fence(*generation)
                    .map_err(super::sync::sync_failure)?;
            }
        }
        HostPrivacy::Unreadable { .. } => {
            if !held.fenced {
                client
                    .fence(held.generation.get())
                    .map_err(super::sync::sync_failure)?;
            }
        }
    }
    // A generation never goes backwards in a store, so a host that reports a lower one than the store
    // holds (its state was reset) leaves the store as it was: if that is not what the host's mode
    // asks for, the host cannot be believed this pass, and nothing of it is sent.
    let held = client
        .store()
        .privacy()
        .map_err(super::sync::sync_failure)?;
    let agrees = match state {
        HostPrivacy::Off { .. } => !held.fenced,
        HostPrivacy::On { .. } | HostPrivacy::Unreadable { .. } => held.fenced,
    };
    if agrees {
        Ok(())
    } else {
        Err(CommandError::local_failure(
            "the privacy generation this computer holds for a host is ahead of the one the host \
             reports, so nothing is sent for that host until they agree",
        ))
    }
}

fn environment_of(text: &str) -> Option<EnvironmentId> {
    text.parse::<Uuid>().ok().map(EnvironmentId::new)
}

fn draft_of(text: &str) -> Option<DraftId> {
    text.parse::<Uuid>().ok().map(DraftId::new)
}

/// Whether a failure says the draft is not what the pass listed: written again, or gone, since.
fn changed_since_listed(error: &SyncError) -> bool {
    matches!(
        error,
        SyncError::Client(client)
            if matches!(
                &**client,
                ClientError::Draft(held)
                    if matches!(
                        **held,
                        DraftError::NotTheStoredRevision { .. } | DraftError::Unknown { .. }
                    )
            )
    )
}

/// Whether a failure is a draft larger than a synchronised draft may be.
fn too_large(error: &SyncError) -> bool {
    matches!(error, SyncError::TooLarge { .. })
        || matches!(
            error,
            SyncError::Client(client)
                if matches!(
                    &**client,
                    ClientError::Draft(held)
                        if matches!(
                            **held,
                            DraftError::TooLarge { .. } | DraftError::TooManyAttachments { .. }
                        )
                )
        )
}

/// Runs a step of the draft store, which blocks on the file system, off the runtime's threads.
async fn blocking<T: Send + 'static>(
    step: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tauri::async_runtime::spawn_blocking(step)
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("keeping the draft stopped: {error}"))
        })?
}
