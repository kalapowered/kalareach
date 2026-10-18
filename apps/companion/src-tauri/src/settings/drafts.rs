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
//! Which host a draft is for is never guessed from what the application is connected to when the
//! draft is saved. It is established when the host says it holds the draft's session, and the
//! record keeps the session it was established for, so a draft sent to another session has no host
//! until the host of that one says so. Until then the draft is kept here.
//!
//! What a device can read of a host's privacy mode is [`Hosts`]'s to say, and it says one of
//! three things. A host with privacy mode off lets its drafts be published; a host with it on does
//! not, and an answer that arrives after the host went private is discarded by the store's
//! generation, which is moved before the answer is settled; and a host this device cannot read,
//! because it is not connected to it or holds no right to ask, is treated as private. Each draft
//! kept here, and why, is in the view the page shows.
//!
//! # What lives where
//!
//! Everything is under `settings-sync/drafts` and holds no secret and no draft text.
//!
//! * `on.json`: whether the person turned drafts sync on.
//! * `hosts.json`: which host held the session each draft is for, by the host's environment, and
//!   which session that was.
//! * `removals.json`: drafts thrown away or sent whose copy the service may still hold, each with
//!   the position it was at when this device knew it, until the service has removed it.
//! * `pulled.json`: the other devices' drafts this device has brought down, so a later look at the
//!   collection asks only for what has changed.
//! * `copies.json`: the other devices' drafts of which a copy is kept here, for as long as it is.
//! * `<environment>/store` and `pull/store`: the sync stores. The second belongs to no host: what it
//!   holds came down, nothing in it left.
//!
//! # A pass
//!
//! One pass, in this order: the removals the service is owed are read; the host of each draft that
//! has none is asked; the work of each host's store that left without an answer is asked about;
//! removals owed to the service are made; each draft of this device whose host allows it is
//! published if it changed; and the drafts of other devices that are new or changed are brought
//! down beside this device's own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_client::ClientError;
use kr_client::drafts::{
    Draft, DraftError, DraftRemoval, DraftSealer, DraftStore, DraftSync, Published, SyncCheckpoint,
};
use kr_client::services::sync::KnownRevision;
use kr_client::services::{
    ManagedSyncService, ServiceFuture, SyncBackupService, SyncDispatch, SyncExchanged, SyncFetched,
    SyncPosition, SyncRequestFence, SyncRequestStatus,
};
use kr_client::sync::membership::CollectionRef;
use kr_client::sync::{
    CollectionKeys, RequestState, SharedCollectionService, SyncClient, SyncError, SyncStore,
};
use kr_ipc::paths::{
    create_private_directory, flush_path_names, read_owner_only_file, write_owner_only_file,
};
use kr_protocol::ids::{DraftId, EnvironmentId, SessionId, SyncObjectId};
use kr_protocol::scalars::Uuid;
use kr_protocol::sync::SyncObjectKind;
use serde::{Deserialize, Serialize};

use super::Told;
use crate::drafts::{DraftDesk, DraftHost, DraftWatch, Removing};
use crate::error::{CommandError, Result};
use crate::recovery::now;

/// The directory under settings sync's own that drafts keep their records in.
const DIRECTORY: &str = "drafts";
const ON: &str = "on.json";
const HOSTS: &str = "hosts.json";
const REMOVALS: &str = "removals.json";
const PULLED: &str = "pulled.json";
const COPIES: &str = "copies.json";
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

/// What the host this device is connected to says of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holds {
    /// The host holds the session, or held it before it closed.
    Here(DraftHost),
    /// This device is connected to a host, and the host holds no such session.
    NotHere,
    /// This device could not tell: it is not connected, or the host did not answer.
    Unknown,
    /// The host would not say for this session, as it refuses a session outside the right it
    /// gave this device. Another session may still be answered.
    Refused,
}

/// What the hosts this device owns said when asked who they list.
#[derive(Clone, Debug, Default)]
pub struct HostLists {
    /// The lists of the hosts that answered.
    pub lists: Vec<kr_protocol::sharing::DeviceListResult>,
    /// Whether a host this device owns did not answer. A device that no answering host lists is
    /// then not known to be gone: the host that did not answer may be the one that lists it.
    pub silent: bool,
    /// Whether a host this device owns answered that it will not list its devices to this
    /// computer, as a host does once the right to manage it has run out or been revoked. That is
    /// an answer, but one that says nothing of the devices only that host lists, as a host that
    /// did not answer says nothing: they are kept, and nothing is accepted, opened or added on that
    /// host's word. When no host listed, it checks nobody and publishes nothing.
    pub refused: bool,
}

/// What settings sync asks of the hosts this device knows: drafts sync, which host holds a session
/// and where its privacy mode stands; and sharing the settings, which devices each host lists.
pub trait Hosts: Send + Sync {
    /// What each host this device owns lists as its devices.
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>>;

    /// Whether the host this device is connected to holds `session`.
    fn holds(
        &self,
        session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>>;

    /// Privacy mode at the host of `environment`, as this device can read it now.
    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>>;
}

/// The host a draft is for, as the record keeps it: the host that held the session, when it was
/// asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRecord {
    /// The session the host said it holds. A draft that is for another session since has no host.
    session: String,
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
    /// No host has said it holds the draft's session, so no host is known to say.
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
    /// Names this entry, so that a pass drops the entry it read and not one a removal has made
    /// of the same draft since.
    id: String,
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
    hosts: Arc<dyn Hosts>,
    told: Arc<Told>,
    wake: tokio::sync::Notify,
    /// Taken for the length of a change to one of the small records the desk's thread changes.
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
    /// The oldest epoch whose objects this device believes.
    pub floor: u64,
    /// Where the collection's keys are.
    pub keys: Arc<dyn CollectionKeys>,
}

/// The store a host's drafts leave through, and the client that fences it.
struct HostStore {
    drafts: DraftSync,
    client: Arc<SyncClient>,
    /// What the host's privacy mode read as the last time an answer was held for it.
    seen: Arc<Mutex<Option<HostPrivacy>>>,
}

/// The failure an answer is held back with when the store cannot be made to hold the boundary.
fn cannot_hold() -> kr_client::ClientError {
    kr_client::ClientError::refusal(
        kr_protocol::error::ErrorCode::StorageUnavailable,
        kr_client::Shown::said("the privacy boundary of this host's drafts could not be kept"),
    )
}

/// A host's service as its drafts reach it. An answer is not handed on until the host's privacy
/// mode has been read again and the host's store moved to it, so the generation an answer is
/// settled against is the one in force when the answer arrives, and not the one in force when
/// the request left. A store that is already fenced is not read for again: what an answer brings
/// down is withheld from a fenced store whatever the host says next. A store that cannot be moved
/// to what the host reports, as one whose generation is ahead of a reset host's, is fenced at the
/// generation it holds, and an answer is not handed on when even that cannot be recorded. The
/// fence at the held generation keeps the account of a write the service applied before then, so
/// a write in flight when such a host turns private is noted and not discarded; the generation
/// the host reports is not one the store can take, and one made up would shut the host out until
/// its own passed it.
struct Gate {
    inner: Arc<dyn SyncBackupService>,
    hosts: Arc<dyn Hosts>,
    environment: EnvironmentId,
    client: Arc<SyncClient>,
    seen: Arc<Mutex<Option<HostPrivacy>>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Gate").finish_non_exhaustive()
    }
}

impl Gate {
    /// Reads the host's privacy mode and moves the store to it, before an answer is handed on.
    ///
    /// # Errors
    ///
    /// Returns why the store could not be made to hold the boundary: nothing may be settled then,
    /// and the request stays outstanding for a reconciliation.
    async fn read_again(&self) -> kr_client::Result<()> {
        let closed = self.client.is_fenced().map_err(|_| cannot_hold())?;
        if closed {
            return Ok(());
        }
        let state = self.hosts.privacy(self.environment).await;
        let state = match apply_privacy(&self.client, &state) {
            Ok(()) => state,
            // The store cannot follow the host, as one ahead of a host whose state was reset
            // cannot. It is fenced at the generation it holds, as for a host that cannot be read,
            // so nothing an answer brings down is kept.
            Err(error) => {
                let held = self.client.store().privacy().map_err(|_| cannot_hold())?;
                self.client
                    .fence(held.generation.get())
                    .map_err(|_| cannot_hold())?;
                HostPrivacy::Unreadable {
                    reason: error.message,
                }
            }
        };
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(state);
        Ok(())
    }
}

impl SyncBackupService for Gate {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let answer = self
                .inner
                .compare_exchange(collection, request_id, signed_at_ms, expected, ciphertext)
                .await;
            self.read_again().await?;
            answer
        })
    }

    fn compare_exchange_dispatched<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncDispatch> {
        Box::pin(async move {
            let answer = self
                .inner
                .compare_exchange_dispatched(
                    collection,
                    request_id,
                    signed_at_ms,
                    expected,
                    ciphertext,
                )
                .await;
            self.read_again().await?;
            answer
        })
    }

    fn compare_remove<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let answer = self
                .inner
                .compare_remove(collection, request_id, signed_at_ms, expected)
                .await;
            self.read_again().await?;
            answer
        })
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            let answer = self.inner.request_status(collection, request_id).await;
            self.read_again().await?;
            answer
        })
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            let answer = self
                .inner
                .fence_request(
                    collection,
                    request_id,
                    first_signed_at_ms,
                    last_signed_at_ms,
                )
                .await;
            self.read_again().await?;
            answer
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            let answer = self.inner.fetch(collection).await;
            self.read_again().await?;
            answer
        })
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: kr_protocol::ids::SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        self.inner.resolve(collection, retained)
    }
}

/// What a pass knows of each host a draft or a removal is for.
#[derive(Default)]
struct PassHosts {
    /// What each host's privacy mode was when it was last read this pass.
    privacy: BTreeMap<EnvironmentId, HostPrivacy>,
    /// The hosts whose store is open, fenced or let go to match.
    stores: BTreeMap<EnvironmentId, HostStore>,
}

/// What this device knows of where the service holds a draft that left.
#[derive(Default)]
struct Seen {
    /// The newest place any record of this device names.
    position: Option<SyncPosition>,
    /// Whether a publication of it may still land, or may already have.
    out: Out,
}

/// How much of a draft's publication is unaccounted for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Out {
    #[default]
    Nothing,
    /// Ended too late to say whether it ran: it may be at the service, and nothing more will run.
    Unaccounted,
    /// Sent with no answer: it may still land.
    Dispatched,
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
        hosts: Arc<dyn Hosts>,
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

    /// Has a pass take up what changed, but only when drafts sync is on: typing in a draft that is
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
    pub async fn pass(&self, on: &Collection<'_>) {
        let outcome = self.pass_in(on).await;
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            // The person may have turned drafts sync off while this pass was out at the service:
            // what it found is not shown over the reset that made.
            if !self.enabled().unwrap_or(false) {
                *last = Last::default();
            } else {
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
        }
        self.told.tell();
    }

    async fn pass_in(&self, on: &Collection<'_>) -> Result<(Vec<KeptHere>, Option<CommandError>)> {
        if !self.enabled()? {
            return Ok((Vec::new(), None));
        }
        let shared = Arc::new(
            SharedCollectionService::new(Arc::clone(on.service), on.collection, on.epoch)
                .believing_from(on.floor),
        );
        let sealer: Arc<dyn DraftSealer> = Arc::new(shared.sealer(Arc::clone(&on.keys)));
        let service: Arc<dyn SyncBackupService> = Arc::clone(&shared) as _;
        let store = self.desk.store()?;
        // The removals owed are read before the drafts are listed. A removal takes its entry
        // before it takes the draft, under the lock this read takes, so an entry read here is of a
        // draft that is gone, and a draft listed after it is one no removal is in hand for.
        let owed = tokio::task::block_in_place(|| self.owed())?;
        let listing = blocking({
            let store = store.clone();
            move || store.list().map_err(crate::drafts::failure)
        })
        .await?;
        self.keep_copies_listed(&listing.drafts)?;
        let own: Vec<Draft> = listing
            .drafts
            .into_iter()
            .filter(|draft| draft.conflict_of.0.is_none())
            .collect();
        let mut problem = None;
        let hosts_of = self.establish_hosts(&own).await?;

        let proven = |draft: &Draft| proven_host(&hosts_of, draft);
        let environments: BTreeSet<EnvironmentId> = own
            .iter()
            .filter_map(proven)
            .chain(
                owed.iter()
                    .filter_map(|owes| owes.host.as_deref().and_then(environment_of)),
            )
            .chain(self.hosts_with_work_out())
            .collect();
        let names: BTreeMap<EnvironmentId, String> = hosts_of
            .values()
            .filter_map(|host| Some((environment_of(&host.environment)?, host.name.clone()?)))
            .collect();
        let mut hosts = self
            .open_hosts(&service, &sealer, &store, &environments, &mut problem)
            .await;
        let pull_directory = self.directory.join(PULL).join(STORE);
        let puller = DraftSync::new(
            Arc::clone(&service),
            Arc::clone(&sealer),
            SyncStore::open(&pull_directory).map_err(super::sync::sync_failure)?,
        );

        let still_owed = self
            .make_removals(
                on,
                &Removals {
                    owed: &owed,
                    own: &own,
                    hosts: &hosts,
                    puller: &puller,
                    store: &store,
                },
                &mut problem,
            )
            .await?;
        let kept = self
            .publish_drafts(&own, &hosts_of, &mut hosts, &store, &mut problem)
            .await?;
        if let Err(error) = self
            .bring_down(on, &puller, &store, &own, &still_owed)
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

    /// The host of each draft, asked of the host this device is connected to when the draft has
    /// none for the session it is for now.
    ///
    /// A host that cannot be asked is asked no more this pass, and a draft the host says it does
    /// not hold keeps no host: it stays here until a host that holds its session is connected.
    async fn establish_hosts(&self, own: &[Draft]) -> Result<BTreeMap<String, HostRecord>> {
        let mut hosts_of: BTreeMap<String, HostRecord> = self.read(HOSTS)?.unwrap_or_default();
        let ids: BTreeSet<String> = own.iter().map(|draft| draft.draft_id.to_string()).collect();
        let mut changed = false;
        hosts_of.retain(|key, _| {
            let keep = ids.contains(key);
            changed |= !keep;
            keep
        });
        let mut asking = true;
        for draft in own {
            let (key, session) = (draft.draft_id.to_string(), draft.target.session_id);
            if !asking || proven_host(&hosts_of, draft).is_some() {
                continue;
            }
            match self.hosts.holds(session).await {
                Holds::Here(host) => {
                    hosts_of.insert(
                        key,
                        HostRecord {
                            session: session.to_string(),
                            environment: host.environment.to_string(),
                            name: host.name,
                        },
                    );
                    changed = true;
                }
                Holds::NotHere | Holds::Refused => {}
                Holds::Unknown => asking = false,
            }
        }
        if changed {
            self.write(HOSTS, &hosts_of)?;
        }
        Ok(hosts_of)
    }

    /// Reads each host's privacy mode, and opens its store fenced or let go to match.
    ///
    /// A host whose store cannot be opened, or that disagrees with what its store holds, is not
    /// believed this pass and is treated as one this device cannot read; the others go on.
    async fn open_hosts(
        &self,
        service: &Arc<dyn SyncBackupService>,
        sealer: &Arc<dyn DraftSealer>,
        store: &DraftStore,
        environments: &BTreeSet<EnvironmentId>,
        problem: &mut Option<CommandError>,
    ) -> PassHosts {
        let mut hosts = PassHosts::default();
        for environment in environments {
            let state = self.hosts.privacy(*environment).await;
            let opened = self
                .open_host(service, sealer, store, *environment, &state)
                .await;
            match opened {
                Ok(host) => {
                    hosts.stores.insert(*environment, host);
                    hosts.privacy.insert(*environment, state);
                }
                Err(error) => {
                    hosts.privacy.insert(
                        *environment,
                        HostPrivacy::Unreadable {
                            reason: error.message.clone(),
                        },
                    );
                    problem.get_or_insert(error);
                }
            }
        }
        hosts
    }

    async fn open_host(
        &self,
        service: &Arc<dyn SyncBackupService>,
        sealer: &Arc<dyn DraftSealer>,
        store: &DraftStore,
        environment: EnvironmentId,
        state: &HostPrivacy,
    ) -> Result<HostStore> {
        let directory = self.directory.join(environment.to_string()).join(STORE);
        let client = Arc::new(SyncClient::new(
            Arc::clone(service),
            Arc::clone(sealer),
            SyncStore::open(&directory).map_err(super::sync::sync_failure)?,
        ));
        apply_privacy(&client, state)?;
        let seen = Arc::new(Mutex::new(Some(state.clone())));
        let gate: Arc<dyn SyncBackupService> = Arc::new(Gate {
            inner: Arc::clone(service),
            hosts: Arc::clone(&self.hosts),
            environment,
            client: Arc::clone(&client),
            seen: Arc::clone(&seen),
        });
        let drafts = DraftSync::new(
            gate,
            Arc::clone(sealer),
            SyncStore::open(&directory).map_err(super::sync::sync_failure)?,
        );
        // Work that left without an answer is asked about first, as a cleanup would.
        drafts
            .reconcile_unsettled(store, now())
            .await
            .map_err(super::sync::sync_failure)?;
        Ok(HostStore {
            drafts,
            client,
            seen,
        })
    }

    /// Makes the removals the service is owed, and returns the ones that still are.
    ///
    /// A removal is owed while the service may hold the draft. Where it holds it is the newest
    /// place any record of this device names: the draft store's note, the ledger's, and the
    /// publication record of every host's store, since a note is written only under the privacy
    /// generation in force and a draft may have left through another host's store than the one it
    /// is for now. A publication that may still land is waited for. One that ended unaccounted is
    /// found by asking the service what it holds. A removal against a place the draft has moved
    /// from is made again against where it is, which only this device's own later publication can
    /// have put it.
    async fn make_removals(
        &self,
        on: &Collection<'_>,
        removals: &Removals<'_>,
        problem: &mut Option<CommandError>,
    ) -> Result<Vec<Owed>> {
        // The entries this pass ends, by identity, and the drafts whose note goes with them.
        let mut made: BTreeSet<String> = BTreeSet::new();
        let mut forget: BTreeSet<DraftId> = BTreeSet::new();
        let mut listed: Option<Option<kr_client::services::SyncComparison>> = None;
        for owes in removals.owed {
            let Some(id) = draft_of(&owes.draft) else {
                made.insert(owes.id.clone());
                continue;
            };
            // An entry of a draft that is still stored is no removal's: it is what a removal that
            // did not happen left, and the draft keeps its note.
            if removals.own.iter().any(|draft| draft.draft_id == id) {
                made.insert(owes.id.clone());
                continue;
            }
            // A host's removals are made through its store, so they wait while the host's privacy
            // mode is on; one with no host goes through the store of what came down.
            let drafts = match owes.host.as_deref().and_then(environment_of) {
                Some(environment) => match removals.hosts.stores.get(&environment) {
                    Some(host) if host.client.is_fenced().unwrap_or(true) => continue,
                    Some(host) => &host.drafts,
                    None => continue,
                },
                None => removals.puller,
            };
            let seen = match self.seen_of(id, owes.note, removals.store, problem).await {
                Ok(seen) => seen,
                Err(error) => {
                    problem.get_or_insert(error);
                    continue;
                }
            };
            let position = match (seen.position, seen.out) {
                (_, Out::Dispatched) => continue,
                (Some(position), _) => position,
                (None, Out::Nothing) => {
                    made.insert(owes.id.clone());
                    forget.insert(id);
                    continue;
                }
                (None, Out::Unaccounted) => {
                    if listed.is_none() {
                        listed = Some(
                            on.service
                                .compare_shared(&on.collection, &[], false, None)
                                .await
                                .map_err(CommandError::from)?,
                        );
                    }
                    let held = listed
                        .iter()
                        .flatten()
                        .flat_map(|found| &found.objects)
                        .find(|held| held.object_id.get() == id.get());
                    match held {
                        Some(held) => held.position,
                        None => {
                            made.insert(owes.id.clone());
                            forget.insert(id);
                            continue;
                        }
                    }
                }
            };
            let mut at = position;
            for attempt in 0..2 {
                match drafts.remove(id, at, now()).await {
                    Ok(DraftRemoval::Removed { .. } | DraftRemoval::AlreadyGone) => {
                        made.insert(owes.id.clone());
                        forget.insert(id);
                    }
                    // Written since the place this device named, which only this device's own
                    // later publication can have done: the removal is made again against it.
                    Ok(DraftRemoval::Moved { current }) if attempt == 0 => {
                        at = current;
                        continue;
                    }
                    Ok(DraftRemoval::Moved { .. }) => {}
                    // The host is private: the removal waits for it.
                    Err(SyncError::Fenced { .. }) => {}
                    Err(error) => {
                        problem.get_or_insert_with(|| super::sync::sync_failure(error));
                    }
                }
                break;
            }
        }
        // The note a settled publication wrote of a draft that was gone by then goes too: nothing
        // is left of a draft whose copy is gone.
        for id in forget {
            let store = removals.store.clone();
            if let Err(error) =
                blocking(move || store.forget_checkpoint(id).map_err(crate::drafts::failure)).await
            {
                problem.get_or_insert(error);
            }
        }
        // What was added to the ledger while the pass ran stays.
        tokio::task::block_in_place(|| self.forget_removals(&made))
    }

    /// What this device knows of where the service holds the draft, and whether a publication of
    /// it is unaccounted for, in every host's store.
    async fn seen_of(
        &self,
        id: DraftId,
        ledger: Option<SyncCheckpoint>,
        store: &DraftStore,
        problem: &mut Option<CommandError>,
    ) -> Result<Seen> {
        let note = {
            let store = store.clone();
            blocking(move || store.checkpoint(id).map_err(crate::drafts::failure)).await?
        };
        let mut seen = Seen {
            position: newer(
                note.map(|note| note.position),
                ledger.map(|note| note.position),
            ),
            out: Out::Nothing,
        };
        // A record this build cannot read, a store it cannot open and a write into a history it
        // does not follow say nothing of where the draft is: the service is asked what it holds.
        let mut unknown = |error: Option<CommandError>, seen: &mut Seen| {
            seen.out = seen.out.max(Out::Unaccounted);
            if let Some(error) = error {
                problem.get_or_insert(error);
            }
        };
        for directory in self.host_stores() {
            let held = match SyncStore::open(&directory) {
                Ok(held) => held,
                Err(error) => {
                    unknown(Some(super::sync::sync_failure(error)), &mut seen);
                    continue;
                }
            };
            match held.publications() {
                Ok(listing) => {
                    if !listing.unreadable.is_empty() {
                        unknown(None, &mut seen);
                    }
                    for publication in listing
                        .items
                        .iter()
                        .filter(|publication| publication.object_id.get() == id.get())
                    {
                        seen.position = newer(seen.position, Some(publication.position));
                    }
                }
                Err(error) => unknown(Some(super::sync::sync_failure(error)), &mut seen),
            }
            match held.requests() {
                Ok(listing) => {
                    if !listing.unreadable.is_empty() {
                        unknown(None, &mut seen);
                    }
                    for request in listing
                        .items
                        .iter()
                        .filter(|request| request.object_id.get() == id.get())
                    {
                        let out = match request.state {
                            RequestState::Dispatched { .. } => Out::Dispatched,
                            RequestState::Unaccounted | RequestState::Diverged { .. } => {
                                Out::Unaccounted
                            }
                            _ => Out::Nothing,
                        };
                        seen.out = seen.out.max(out);
                    }
                }
                Err(error) => unknown(Some(super::sync::sync_failure(error)), &mut seen),
            }
        }
        Ok(seen)
    }

    /// The hosts whose store holds a publication that left without an answer, whatever draft it
    /// was for and wherever that draft is for now: its answer is asked for, or it is waited for for
    /// ever. A store that cannot be read is named too, so that opening it says why.
    fn hosts_with_work_out(&self) -> Vec<EnvironmentId> {
        self.host_stores()
            .into_iter()
            .filter(|directory| {
                SyncStore::open(directory)
                    .and_then(|held| held.requests())
                    .map_or(true, |listing| {
                        listing.items.iter().any(|request| request.dispatched())
                    })
            })
            .filter_map(|directory| environment_of(directory.parent()?.file_name()?.to_str()?))
            .collect()
    }

    /// The directory of every host's store there is on this computer.
    fn host_stores(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        entries
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| environment_of(name).is_some())
            })
            .map(|entry| entry.path().join(STORE))
            .filter(|path| path.is_dir())
            .collect()
    }

    /// Publishes the drafts of this device where their host allows it.
    ///
    /// The host's privacy mode is read again just before a draft leaves while it reads as off: the
    /// pass may have waited on the service since the first read, and a host that went private in
    /// that time is private for this draft. Once it reads as anything else it is that for the rest
    /// of the pass, and nothing asks it again.
    async fn publish_drafts(
        &self,
        own: &[Draft],
        hosts_of: &BTreeMap<String, HostRecord>,
        hosts: &mut PassHosts,
        store: &DraftStore,
        problem: &mut Option<CommandError>,
    ) -> Result<BTreeMap<(Option<EnvironmentId>, Why, Option<String>), u64>> {
        let mut kept: BTreeMap<(Option<EnvironmentId>, Why, Option<String>), u64> = BTreeMap::new();
        for draft in own {
            if !self.enabled()? {
                break;
            }
            let Some(host) = proven_host(hosts_of, draft) else {
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
            let state = match hosts.privacy.get(&host) {
                Some(state @ (HostPrivacy::On { .. } | HostPrivacy::Unreadable { .. })) => {
                    state.clone()
                }
                _ => {
                    let state = self.hosts.privacy(host).await;
                    hosts.privacy.insert(host, state.clone());
                    state
                }
            };
            let why = match &state {
                HostPrivacy::Off { .. } => None,
                HostPrivacy::On { .. } => Some((Why::Private, None)),
                HostPrivacy::Unreadable { reason } => Some((Why::Unreadable, Some(reason.clone()))),
            };
            let Some(opened) = hosts.stores.get(&host) else {
                // The host's store could not be opened, or the host could not be read when the
                // pass began and reads as off now: either way the next pass makes one.
                let detail = why.and_then(|(_, detail)| detail);
                *kept
                    .entry((Some(host), Why::Unreadable, detail))
                    .or_default() += 1;
                continue;
            };
            if let Err(error) = apply_privacy(&opened.client, &state) {
                *kept
                    .entry((Some(host), Why::Unreadable, Some(error.message)))
                    .or_default() += 1;
                continue;
            }
            if let Some((why, detail)) = why {
                *kept.entry((Some(host), why, detail)).or_default() += 1;
                continue;
            }
            // The person may have turned drafts sync off while the host was asked.
            if !self.enabled()? {
                break;
            }
            match opened
                .drafts
                .publish(store, draft.draft_id, draft.revision, now())
                .await
            {
                Ok(Published::Conflicted { .. }) => self.told.tell(),
                Ok(Published::Accepted { .. }) => {}
                // The host went private, or could not be read, while the publication was out, and
                // the answer was discarded: the draft is kept here for the reason the host gave.
                Ok(Published::Discarded { .. }) => {
                    let seen = opened
                        .seen
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone();
                    match seen {
                        // It lets go again at a newer generation: the next pass publishes.
                        Some(HostPrivacy::Off { .. }) => {}
                        Some(HostPrivacy::Unreadable { reason }) => {
                            *kept
                                .entry((Some(host), Why::Unreadable, Some(reason)))
                                .or_default() += 1;
                        }
                        Some(HostPrivacy::On { .. }) | None => {
                            *kept.entry((Some(host), Why::Private, None)).or_default() += 1;
                        }
                    }
                }
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
        Ok(kept)
    }

    /// The drafts of other devices that are new or changed, kept beside this device's own.
    ///
    /// The comparison names what this device already holds, so the answer is only what changed, and
    /// a collection nothing changed in costs one small request.
    async fn bring_down(
        &self,
        on: &Collection<'_>,
        puller: &DraftSync,
        store: &DraftStore,
        own: &[Draft],
        owed: &[Owed],
    ) -> Result<()> {
        if !self.enabled()? {
            return Ok(());
        }
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
            // The person may have turned drafts sync off while this pass was out at the service.
            if !self.enabled()? {
                break;
            }
            let id = DraftId::new(held.object_id.get());
            // A draft this device holds is published by this device, which reconciles it by the
            // rules of a refused write; one it is removing is not brought back.
            if mine.contains(&id.to_string()) || leaving.contains(id.to_string().as_str()) {
                continue;
            }
            // The listing says which epoch each draft was sealed under, and one from before the
            // floor is not believed: it is not asked for, at this pass or the next.
            if held.epoch.is_some_and(|sealed| sealed < on.floor) {
                continue;
            }
            // Where a copy came from is on disk before the copy is, so that a copy is never kept
            // that the person is told another window made.
            self.keep_copy_of(id)?;
            match puller.fetch_beside(store, id, now()).await {
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

    /// Notes that a copy is to be kept beside the draft of another device.
    fn keep_copy_of(&self, of: DraftId) -> Result<()> {
        let mut copies: BTreeSet<String> = self.read(COPIES)?.unwrap_or_default();
        if copies.insert(of.to_string()) {
            self.write(COPIES, &copies)?;
        }
        Ok(())
    }

    /// Lets go of the copies' origins whose copy is no longer kept, so that the record does not
    /// grow with every draft that ever came down.
    fn keep_copies_listed(&self, drafts: &[Draft]) -> Result<()> {
        let Some(mut copies): Option<BTreeSet<String>> = self.read(COPIES)? else {
            return Ok(());
        };
        let before = copies.len();
        copies.retain(|of| {
            drafts.iter().any(|draft| {
                draft
                    .conflict_of
                    .0
                    .is_some_and(|held| held.to_string() == *of)
            })
        });
        if copies.len() != before {
            self.write(COPIES, &copies)?;
        }
        Ok(())
    }

    /// The removals the service is owed, read under the lock a removal takes its entry under.
    fn owed(&self) -> Result<Vec<Owed>> {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let _file = self.records_file()?;
        Ok(self.read(REMOVALS)?.unwrap_or_default())
    }

    /// Takes the removals the service has made out of the ledger, and returns what is still owed.
    ///
    /// The ledger is read again under the lock the desk's thread takes to add to it, so a removal
    /// added while a pass was out at the service is not written over.
    fn forget_removals(&self, made: &BTreeSet<String>) -> Result<Vec<Owed>> {
        let _records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let _file = self.records_file()?;
        let mut owed: Vec<Owed> = self.read(REMOVALS)?.unwrap_or_default();
        if !made.is_empty() {
            owed.retain(|owes| !made.contains(&owes.id));
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

/// What the removals of one pass are made from.
struct Removals<'a> {
    owed: &'a [Owed],
    own: &'a [Draft],
    hosts: &'a PassHosts,
    puller: &'a DraftSync,
    store: &'a DraftStore,
}

/// A removal in hand: the ledger holds its entry, and the lock the pass reads the ledger under is
/// held until the removal ends.
struct Removal<'a> {
    sync: &'a DraftsSync,
    draft: DraftId,
    /// Whether this removal wrote the entry, because drafts sync has been used and none was there
    /// for the draft.
    recorded: bool,
    ended: bool,
    _records: MutexGuard<'a, ()>,
    _file: std::fs::File,
}

impl Removing for Removal<'_> {
    fn removed(mut self: Box<Self>, note: Option<SyncCheckpoint>) {
        self.ended = true;
        // The draft is gone. A note found only now, read with the removal, is the newest this
        // device has: the entry is brought up to it, and made if sync was not thought used.
        if self.recorded || note.is_some() {
            let Ok(mut owed) = self
                .sync
                .read::<Vec<Owed>>(REMOVALS)
                .map(Option::unwrap_or_default)
            else {
                return;
            };
            let key = self.draft.to_string();
            match owed.iter_mut().find(|owes| owes.draft == key) {
                Some(owes) => owes.note = note.or(owes.note),
                None => {
                    let Ok(id) = fresh_entry() else { return };
                    owed.push(Owed {
                        id,
                        draft: key,
                        host: None,
                        note,
                    });
                }
            }
            let _ = self.sync.write(REMOVALS, &owed);
            self.sync.wake_when_on();
        }
    }
}

impl Drop for Removal<'_> {
    fn drop(&mut self) {
        if self.ended || !self.recorded {
            return;
        }
        // The draft was not removed: nothing is owed for it.
        let key = self.draft.to_string();
        if let Ok(Some(mut owed)) = self.sync.read::<Vec<Owed>>(REMOVALS) {
            owed.retain(|owes| owes.draft != key);
            let _ = self.sync.write(REMOVALS, &owed);
        }
    }
}

impl DraftWatch for DraftsSync {
    fn saved(&self) {
        self.wake_when_on();
    }

    fn removing(&self, draft: DraftId) -> Result<Box<dyn Removing + '_>> {
        let records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let file = self.records_file()?;
        // Nothing is owed for a draft that never could have reached a service: drafts sync has
        // never been on here, so no store of a host's exists.
        let used = self.enabled().unwrap_or(false) || !self.host_stores().is_empty();
        let mut recorded = false;
        if used {
            // A record that cannot be read is not written over: the removal is refused, and the
            // draft stays.
            let mut owed: Vec<Owed> = self.read(REMOVALS)?.unwrap_or_default();
            let hosts: BTreeMap<String, HostRecord> =
                self.read(HOSTS).ok().flatten().unwrap_or_default();
            let key = draft.to_string();
            let id = fresh_entry()?;
            // An entry that is there already, another window's removal of the draft or what one
            // that did not happen left, stays with the note it holds, under an identity of its
            // own again: a pass that read it before this removal began does not drop it.
            match owed.iter_mut().find(|owes| owes.draft == key) {
                Some(held) => held.id = id,
                None => {
                    owed.push(Owed {
                        id,
                        host: hosts.get(&key).map(|host| host.environment.clone()),
                        draft: key,
                        note: None,
                    });
                    recorded = true;
                }
            }
            self.write(REMOVALS, &owed)?;
        }
        Ok(Box::new(Removal {
            sync: self,
            draft,
            recorded,
            ended: false,
            _records: records,
            _file: file,
        }))
    }

    fn is_a_device_copy(&self, of: DraftId) -> bool {
        self.read::<BTreeSet<String>>(COPIES)
            .ok()
            .flatten()
            .is_some_and(|copies| copies.contains(&of.to_string()))
    }
}

/// A fresh identity for a ledger entry.
fn fresh_entry() -> Result<String> {
    kr_client::sync::fresh_object_id()
        .map(|id| id.get().to_string())
        .map_err(CommandError::from)
}

/// The host a draft is for, when a host said it holds the session the draft is for now.
fn proven_host(hosts_of: &BTreeMap<String, HostRecord>, draft: &Draft) -> Option<EnvironmentId> {
    let record = hosts_of.get(&draft.draft_id.to_string())?;
    if record.session != draft.target.session_id.to_string() {
        return None;
    }
    environment_of(&record.environment)
}

/// The later of two places, by their order in the object's writes.
fn newer(a: Option<SyncPosition>, b: Option<SyncPosition>) -> Option<SyncPosition> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.write_sequence > a.write_sequence {
            b
        } else {
            a
        }),
        (a, None) => a,
        (None, b) => b,
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
