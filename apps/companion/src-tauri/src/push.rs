//! Notifications on a phone: from the person's say-so to a destination at its host.
//!
//! Section 16 has a phone do four things before a host can notify it. The installation proposes the
//! provider token it was given, and answers the challenge the gateway sends through the provider to
//! that token (the native receiver does that, [`companion_platform::push`]); it asks the gateway to
//! authorise one paired host, and receives a delivery credential; and it hands that credential to
//! the host over the paired connection, which makes the phone a destination (`device.push.register`).
//! This module is the application's half: it sequences those steps for one host, remembers where
//! each stands, and says so in words.
//!
//! The host is reached before the gateway issues its credential: an issue stops the credential the
//! host holds at once, so a host that cannot be reached keeps the one it has and the person is
//! told so.
//!
//! # What the person sees
//!
//! One action per host, "turn on notifications", and where it stands: off, working, on, or needing
//! the person (the system's permission is off, the token has not arrived, the gateway or the host
//! could not be reached). Stopping notifications is the system's setting: a host ends a destination
//! when it unpairs the device, and only the host can revoke the authorisation it holds.
//!
//! Once a host has been asked, one more choice: whether its notifications show what needs the
//! person or only that something does. The choice takes effect on this phone at once, since the
//! receivers hold a host's preview key only while previews are on for it, and the host is told
//! next. A host that cannot be told leaves the row needing the person with the choice kept, and
//! trying again tells it.
//!
//! # What is kept, and what is not
//!
//! `push/push.json` under the application's data directory holds, per paired host, whether the
//! person asked, the authorisation identifier this phone issued for that host (so asking again
//! issues under the same identifier and the host keeps one authorisation), the digest of the token
//! the registration that last turned the host on proposed, the choice of previews and the choice the
//! host was last told, and the last outcome in words. It holds no token, no key and no
//! credential. The credential exists in memory between the gateway's issue and the host's answer
//! and is never kept: a registration whose answer was lost is made again under a new action with a
//! fresh credential, which is what the host expects.
//!
//! A record that cannot be read (damaged, or written by a build this one does not know) holds each
//! host's authorisation identifier, so it is moved aside whole and never written over. The desk
//! then starts a record of its own that marks every host paired at that moment as lost: the page
//! shows it as needing the person, a look leaves it alone, and the mark stays across restarts
//! until the person turns that host on again, since what was on is no longer known. A start that
//! finds no record and a record set aside before it, because the one before it ended in between,
//! marks the hosts then. A record the system failed to read, one that cannot be moved, and a list
//! of paired hosts that cannot be read, leave the record in place: nothing is written and no host
//! is started until a start can deal with it, and the page says to start the application again.
//!
//! # What repeats
//!
//! Each step is safe to repeat, so a restart, a lost answer or a changed token is mended by doing
//! the sequence again for the host that asked: the same installation key, the same authorisation
//! identifier, a new action. A change of the token is found by comparing, not by being told: a run
//! writes a host on only when it has read the token again and found the one it proposed, and each
//! look compares the digest the record keeps with the token the provider holds and registers a host
//! that is on with another again, so no exit of the application can lose a change. A
//! person who is asked for permission and says no is told so, and the sequence is tried again the
//! next time the application is in front, never in a loop.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use companion_platform::notify::{Permission, PreviewKeys, RecipientKey, SenderKey};
use companion_platform::push::{PendingRegistration, PendingState};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::push::{InstallationSigner, PushGateway, Registration};
use kr_client::services::{
    HttpDeadlines, HttpService, PushService as _, ServiceHttp, managed_response_limits,
};
use kr_client::{Said as _, Shown};
use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use kr_protocol::ids::DeviceKeyRevision;
use kr_protocol::ids::{DeviceId, PushRegistrationId, PushSenderRecordId};
use kr_protocol::push::{
    DevicePushRegisterParams, DevicePushRegisterResult, PushPlatform, PushRegistrationProposal,
    PushSenderIssueRequest, RegistrationToken, token_digest,
};
use kr_protocol::scalars::Digest256;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::device::hosts::reference_of;
use crate::error::{CommandError, Result};

/// The directory the record is kept in, under the application's data directory.
pub const DIRECTORY: &str = "push";

/// The record, in [`DIRECTORY`].
const RECORD: &str = "push.json";

/// The event the page is told where notifications stand on.
pub const PUSH_EVENT: &str = "kr://push";

/// The record's schema version.
const VERSION: u32 = 1;

/// The most the record may be, in bytes.
const RECORD_LIMIT: u64 = 64 * 1024;

/// How long this phone waits for a challenge it asked for: the gateway's five minutes, and two
/// more for a clock that is not the gateway's.
const CHALLENGE_WITHIN_MS: u64 = (5 + 2) * 60 * 1000;

/// How often the phone's own record is read while a challenge is awaited. Nothing leaves the
/// phone: it is a read of the file the receiver writes.
const LOOK_EVERY: Duration = Duration::from_millis(500);

/// How long a sequence waits for the provider's registration token once the person has agreed.
const TOKEN_WITHIN: Duration = Duration::from_secs(20);

/// How long a registration is held waiting for its challenge to be answered: the time the record
/// gives the challenge and a margin, so that one native call that never returns cannot keep every
/// other host from registering.
const CHALLENGE_WAIT: Duration = Duration::from_millis(CHALLENGE_WITHIN_MS + 30_000);

/// The soonest the same host is tried again after a try that needed the person: asking the system
/// or the gateway again at every foreground would be a loop with a person in it.
const RETRY_AFTER_MS: u64 = 60 * 1000;

/// The start of the name a record that cannot be read is set aside under.
const ASIDE_PREFIX: &str = "push.unreadable-";

/// What a lost host is shown as: the record that said where its notifications stood was set aside.
const RECORD_LOST: &str = "This phone could not read what it had kept about notifications, so it \
                           cannot say whether this host has them on. Choose Try again to start \
                           over.";

/// What a lost host is shown as when the record could not be set aside or read, and is still in
/// place: nothing is changed until a start can deal with it.
const RECORD_KEPT: &str = "This phone could not read what it had kept about notifications, so it \
                           cannot say whether this host has them on. Close the application and \
                           open it again.";

/// How far a host's notifications stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The person asked and the sequence is running.
    Working,
    /// The host has this phone as a destination.
    On,
    /// The sequence stopped for something only the person or the network can mend.
    Attention,
}

/// What is kept of one host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct HostPush {
    /// The authorisation this phone issued for this host, kept so asking again issues under it.
    sender_record_id: Option<PushSenderRecordId>,
    phase: Phase,
    /// The last outcome, in words.
    words: String,
    /// Whether what stopped it is the system's notification setting, which only the person changes.
    #[serde(default)]
    settings: bool,
    /// When the phase was set, in UTC milliseconds.
    updated_ms: u64,
    /// The digest of the token the registration that last turned this host on proposed. A look
    /// registers a host that is on again when this is not the digest of the token the provider holds.
    /// A record that has none
    /// (written before it was kept) is registered again at the next look.
    #[serde(default)]
    registered: Option<Digest256>,
    /// Whether what this phone knew of the host was lost with a record that could not be read. A
    /// look leaves such a host alone: only the person turning it on again starts it over.
    #[serde(default)]
    lost: bool,
    /// What the person chose for the text of the notification: whether the host seals a preview to
    /// this phone. A record written before the choice existed reads as on, as every registration
    /// made until then asked for previews.
    #[serde(default = "previews_on")]
    previews: bool,
    /// The choice the host was last told. None reads as on, for the same reason.
    #[serde(default)]
    told_previews: Option<bool>,
}

impl HostPush {
    /// A host this phone has just taken up: nothing issued, registered or told yet, and previews on.
    fn new(phase: Phase, now_ms: u64) -> Self {
        Self {
            sender_record_id: None,
            phase,
            words: String::new(),
            settings: false,
            updated_ms: now_ms,
            registered: None,
            lost: false,
            previews: true,
            told_previews: None,
        }
    }
}

impl HostPush {
    /// Whether the host was last told another choice of previews than the one that stands.
    fn told_differs(&self) -> bool {
        self.told_previews.unwrap_or(true) != self.previews
    }
}

/// What a host that is on is shown while it is told again.
const TELLING_THE_HOST: &str = "Telling the host.";

/// What a host that is on is shown when a look could not read the notification token, so that this
/// phone cannot say whether the host still has the one it holds: nothing is changed, and the next
/// look that reads a token settles it.
const TOKEN_UNREADABLE: &str = "This phone could not check its notification token. It will check \
                                again the next time you open the app.";

/// What a token the gateway does not take is shown as.
const TOKEN_REFUSED: &str =
    "The notification token this phone was given is not one the gateway takes.";

/// The most names a record that cannot be read is tried under before it is left where it is.
const ASIDE_NAMES: u32 = 1_000;

/// What a host that a look cannot reach without cutting off the host in use is shown as.
const BESIDE_THE_HOST_IN_USE: &str = "This host is reached through the same relay as the host you \
                                      are using. Choose Try again to turn notifications on for it; \
                                      the host in use reconnects afterwards.";

/// The choice a record that holds none reads as.
const fn previews_on() -> bool {
    true
}

/// What is kept on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    /// By the host's device identifier.
    hosts: BTreeMap<String, HostPush>,
}

impl Record {
    /// A record with no host in it.
    fn empty() -> Self {
        Self {
            version: VERSION,
            hosts: BTreeMap::new(),
        }
    }
}

/// What the page is shown of one host's notifications.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostPushView {
    /// The host, as the page names it everywhere.
    pub reference: String,
    /// Off, working, on or needing the person.
    pub state: PushState,
    /// What is true now, in words.
    pub words: String,
    /// Whether what stopped it is the system's notification setting.
    pub settings: bool,
    /// What the person chose for the text of the notification: true shows what needs them, false
    /// only that something does. The choice as recorded, whether or not the host has been told.
    pub previews: bool,
}

/// Where one host's notifications stand, as the page tells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushState {
    /// The person has not asked.
    Off,
    /// The sequence is running.
    Working,
    /// The host notifies this phone.
    On,
    /// The sequence stopped for something to mend.
    NeedsAttention,
}

/// What the page is shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PushView {
    /// Whether this device has notifications to turn on: a phone does, a computer does not.
    pub available: bool,
    /// Each paired host.
    pub hosts: Vec<HostPushView>,
}

/// Why a sequence stopped, in words for the person.
#[derive(Debug, PartialEq, Eq)]
pub struct Stop {
    /// What is true, and what to do.
    pub words: String,
    /// Whether the system's notification setting is what the person has to change.
    pub settings: bool,
}

impl From<String> for Stop {
    fn from(words: String) -> Self {
        Self {
            words,
            settings: false,
        }
    }
}

/// A boxed future, so the platform and the host stay usable behind a trait object.
pub type PushFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, String>> + Send + 'a>>;

/// A boxed future for a question the answer to which is yes or no.
pub type AskFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// Why a change made over the line to a host did not happen, in words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineStop {
    /// This phone stopped itself before it asked the host, or after it was answered: the words are
    /// its own, and the host refused nothing.
    Phone(String),
    /// The host refused the change, did not answer it, or answered with what this phone does not
    /// read.
    Host(String),
}

/// What only the platform can say or do about notifications.
///
/// The product's is the plugin ([`companion_platform::notify`]); a test gives its own.
pub trait Native: Send + Sync {
    /// Where the person's answer stands, read without asking.
    fn permission(&self) -> PushFuture<'_, Permission>;
    /// Asks the person when they have not answered.
    fn ask_permission(&self) -> PushFuture<'_, Permission>;
    /// The registration token the provider gave this installation.
    fn token(&self) -> PushFuture<'_, Option<String>>;
    /// Replaces the record of the registration being waited for.
    fn pending_set<'a>(&'a self, record: &'a PendingRegistration) -> PushFuture<'a, ()>;
    /// The record of the registration being waited for, as it stands now.
    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>>;
    /// Makes the limited store a receiver reads hold exactly these keys.
    fn preview_keys<'a>(&'a self, keys: &'a PreviewKeys) -> PushFuture<'a, ()>;
    /// The screen a tap on a notification opened the application on, once.
    fn route(&self) -> PushFuture<'_, Option<String>>;
}

/// What a run does for its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    /// The whole sequence: permission, token, proposal, challenge, and then the host.
    Full,
    /// The host is told again under the registration it already has, which was made for the token
    /// whose digest this holds: the person's choice of previews changed, and nothing the provider
    /// or the gateway holds did.
    Delivery(Digest256),
}

/// What a run does once the host has been told.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// The run is over: the host is on, or the run stopped.
    Done,
    /// What the host was told is not what stands now, and this is what is done about it.
    Again(Job),
}

/// How a run reaches its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The person asked for it. The host's endpoint is held while the connection is open, and
    /// reaching the host may close the endpoint of another host that shares its relay, as the
    /// person's own choice of the host would.
    Asked,
    /// A look at where notifications stand started it, in the background. It is a visit: it never
    /// closes the endpoint of the host in use, and is refused when the host cannot be reached
    /// without that. The host's endpoint is held while the connection is open.
    Visit,
}

/// How this phone reaches a host it is paired with, to hand it a delivery credential.
pub trait Registrar: Send + Sync {
    /// Opens the paired connection to `host`, and holds its endpoint until the connection is
    /// dropped, so nothing this phone does for another host closes it in between.
    fn connect<'a>(
        &'a self,
        host: &'a PairedHost,
        reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>>;

    /// Whether reaching `host` as a visit would be refused now because that would cut off the host
    /// in use, asked before anything is done for the host and with nothing held. The answer is as
    /// of now: the connection is the authority when it is made. A registrar that cannot tell says
    /// no.
    fn beside_the_host_in_use<'a>(&'a self, _host: &'a PairedHost) -> AskFuture<'a> {
        Box::pin(async { false })
    }
}

/// A boxed future for a change made over the line.
pub type LineFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, LineStop>> + Send + 'a>>;

/// An open connection to a host, and the two changes the phone makes there. The desk asks whether
/// its run is still wanted before it makes the connection and before each change, so a host the
/// person forgot meanwhile is sent nothing.
pub trait HostLine: Send {
    /// Sends `device.push.register`, and answers what the host answered.
    fn register(
        &mut self,
        params: DevicePushRegisterParams,
    ) -> LineFuture<'_, DevicePushRegisterResult>;
    /// Sends `device.preview_key.update`, which says which preview key this phone holds and at
    /// which revision. When the host answers, the line records the revision, since a connection
    /// offers the revision the host holds and is refused at another.
    ///
    /// The host commits a revision before it answers, so a phone that does not record the answer
    /// offers the old revision and is refused at every connection. Nothing in the desk sends a
    /// revision above the one it holds; a caller that does has to add a retry on that refusal.
    fn update_preview_key(
        &mut self,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
        revision: DeviceKeyRevision,
    ) -> LineFuture<'_, ()>;
}

/// How the gateway at an origin is reached.
pub type HttpFor =
    dyn Fn(&GatewayOrigin) -> std::result::Result<Arc<dyn ServiceHttp>, String> + Send + Sync;

/// The seams a test replaces: the gateway's transport per origin, and the clock.
pub struct Wiring {
    /// How the gateway at an origin is reached.
    pub http: Arc<HttpFor>,
    /// The time, in UTC milliseconds.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl Wiring {
    /// The product's: the managed transport, and the system clock.
    #[must_use]
    pub fn product() -> Self {
        Self {
            http: Arc::new(|origin| {
                HttpService::with(
                    origin.clone(),
                    HttpDeadlines::default(),
                    managed_response_limits(),
                )
                .map(|http| Arc::new(http) as Arc<dyn ServiceHttp>)
                .map_err(|error| error.to_string())
            }),
            clock: Arc::new(|| kr_ipc::now_ms().get()),
        }
    }
}

/// This phone's notifications.
pub struct PushDesk {
    file: PathBuf,
    /// The application's data directory, where a debug build reads a device run's request.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    data: PathBuf,
    device: Arc<Device>,
    native: Arc<dyn Native>,
    registrar: Arc<dyn Registrar>,
    wiring: Wiring,
    origin: GatewayOrigin,
    /// Everything the desk changes together, so that a look, the start of a run and the end of one
    /// are each made under one hold: no look finds a host working that no run owns, or on while a
    /// run is still ending it.
    state: Mutex<State>,
    /// Held from the moment a registration is written until its challenge is answered. The phone
    /// keeps one record of the registration it waits for, and the gateway one pending attempt, so a
    /// second host's registration would replace the first's: they go one at a time. Never awaited
    /// while `state` is held.
    registering: tokio::sync::Mutex<()>,
    /// The keys last filed for the receivers, and the hold that keeps filings in order: a set is
    /// built and handed over under it, so an older set is never filed after a newer one.
    filed: tokio::sync::Mutex<Option<PreviewKeys>>,
    changed: Box<dyn Fn() + Send + Sync>,
    /// Whether the record on disk is one that could not be read and could not be moved aside, so
    /// that writing would replace it. Nothing is written then, and the page shows what the desk
    /// holds in memory until a start can read the record.
    write_blocked: bool,
}

/// What the desk changes together.
struct State {
    record: Record,
    /// The hosts a run is taking up, each by the number its claim was given: a run writes only
    /// while its host is still held under its own number, so the run of a host that was forgotten
    /// writes nothing, and a host paired again is claimed afresh.
    running: BTreeMap<DeviceId, u64>,
    /// What ends the run that holds each host, by the run's number: the person forgetting the host
    /// calls it, and the run's task is dropped where it waits, with the connection to the host and
    /// the hold on its endpoint it owns.
    cancels: BTreeMap<DeviceId, (u64, Arc<tokio::sync::Notify>)>,
    /// The hosts whose person has just chosen to turn notifications on: the one thing that may put
    /// the system's permission question in front of them. A run takes its host out when it reaches
    /// the question, and out again whenever it ends or goes round again, so a look the application
    /// makes by itself never asks.
    asking: BTreeSet<DeviceId>,
    /// What looks saw of the provider's token for a host a run holds: every digest, kept until the
    /// run has compared. Answers to looks and to the run's own read reach the desk in any order, so
    /// the last to arrive is not the last the provider gave: one that arrives late must not
    /// replace what an earlier arrival showed. A run clears the set before it reads the token for
    /// its comparison, so what is here when it compares is something a look saw while the run's own
    /// answer was on its way.
    observed: BTreeMap<DeviceId, BTreeSet<Digest256>>,
    /// The hosts that are on and that a look could not confirm, because it could not read the
    /// token, each with the words that say so. Kept in memory only: the record still says on, and
    /// the next look that reads a token takes the mark away, as does a run that ends.
    unconfirmed: BTreeMap<DeviceId, &'static str>,
    /// The number the next claim is given.
    next_run: u64,
}

impl State {
    /// Takes the right to run the sequence for `host`, which is refused while a run holds it.
    fn claim(&mut self, host: DeviceId) -> Option<u64> {
        if self.running.contains_key(&host) {
            return None;
        }
        self.next_run += 1;
        self.running.insert(host, self.next_run);
        Some(self.next_run)
    }

    /// Whether `run` still holds `host`.
    fn holds(&self, host: DeviceId, run: u64) -> bool {
        self.running.get(&host) == Some(&run)
    }
}

/// Ends a run's claim when its task ends without having reached its own end, as a panic does: the
/// host would otherwise show working for ever, with no run behind it.
struct RunGuard {
    desk: Arc<PushDesk>,
    host: DeviceId,
    run: u64,
    armed: bool,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if self.armed {
            self.desk.stopped(
                self.host,
                self.run,
                &"Turning on notifications was interrupted. Try again."
                    .to_owned()
                    .into(),
            );
        }
    }
}

impl std::fmt::Debug for PushDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PushDesk").finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The platform this build is a phone of.
const fn this_platform() -> PushPlatform {
    if cfg!(target_os = "ios") {
        PushPlatform::Ios
    } else {
        PushPlatform::Android
    }
}

impl PushDesk {
    /// Opens the desk over the record under `data`. `changed` is called when what the page is
    /// shown changes.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the gateway's origin is not one this build can name.
    pub fn open(
        data: &Path,
        device: Arc<Device>,
        native: Arc<dyn Native>,
        registrar: Arc<dyn Registrar>,
        wiring: Wiring,
        changed: impl Fn() + Send + Sync + 'static,
    ) -> Result<Arc<Self>> {
        let origin =
            GatewayOrigin::new(kr_client::services::account::ACCOUNT_ORIGIN).map_err(|error| {
                CommandError::local_failure(format!("the gateway's origin: {error}"))
            })?;
        let file = data.join(DIRECTORY).join(RECORD);
        let now = (wiring.clock)();
        let mut pruned = false;
        let (record, write_blocked, lost) = match read_record(&file) {
            Loaded::Record(record) => {
                let mut record = after_a_restart(record, now);
                // A host this phone stopped being paired with while the application was not
                // running, or whose forgetting did not reach the record, keeps nothing here. A list
                // that cannot be read is not an empty one, and prunes nothing.
                if let Ok(hosts) = device.pairing().hosts.list() {
                    let paired: BTreeSet<String> = hosts
                        .iter()
                        .map(|host| host.host_device_id.to_string())
                        .collect();
                    let before = record.hosts.len();
                    record.hosts.retain(|host, _| paired.contains(host));
                    pruned = record.hosts.len() != before;
                }
                (record, false, false)
            }
            loss => {
                // What the record said of each host is gone, and the hosts paired now are marked.
                // The paired hosts are read first: a list that cannot be read is not an empty one,
                // and a start that marked no host would hide the loss from every later start.
                let hosts = device.pairing().hosts.list();
                if let Err(error) = &hosts {
                    tracing::error!(%error, "the paired hosts could not be read to mark the lost ones");
                }
                // A record the system failed to read may be fine at the next start, so it stays
                // where it is; one that was read and is not a record this build knows is moved
                // aside. Where it stays, nothing is written, so nothing is written over it.
                let kept = match &loss {
                    Loaded::Unreadable { why, read_failed } => {
                        let aside = hosts.is_ok() && !read_failed && set_aside(&file, why, now);
                        if !aside {
                            tracing::error!(
                                why = %why,
                                "the notifications record could not be read, and was left in place"
                            );
                        }
                        aside
                    }
                    _ => true,
                };
                let write_blocked = !kept || hosts.is_err();
                let words = if write_blocked {
                    RECORD_KEPT
                } else {
                    RECORD_LOST
                };
                let hosts = hosts.unwrap_or_default();
                (record_after_a_loss(&hosts, now, words), write_blocked, true)
            }
        };
        let desk = Arc::new(Self {
            file,
            data: data.to_path_buf(),
            device,
            native,
            registrar,
            wiring,
            origin,
            state: Mutex::new(State {
                record,
                running: BTreeMap::new(),
                cancels: BTreeMap::new(),
                asking: BTreeSet::new(),
                observed: BTreeMap::new(),
                unconfirmed: BTreeMap::new(),
                next_run: 0,
            }),
            registering: tokio::sync::Mutex::new(()),
            filed: tokio::sync::Mutex::new(None),
            changed: Box::new(changed),
            write_blocked,
        });
        if lost || pruned {
            // The marks that say which hosts were lost are kept, so that they outlast this start,
            // and so is the record without the hosts that are no longer paired.
            let state = lock(&desk.state);
            desk.keep(&state.record);
        }
        Ok(desk)
    }

    /// What the page is shown: each paired host and where its notifications stand.
    #[must_use]
    pub fn view(&self) -> PushView {
        let state = lock(&self.state);
        let hosts = self
            .device
            .pairing()
            .hosts
            .list()
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|host| {
                let kept = state.record.hosts.get(&host.host_device_id.to_string());
                let unconfirmed = state.unconfirmed.get(&host.host_device_id);
                let (shown, words) = match (kept, unconfirmed) {
                    // A record that could not be written knows no host the list now has, and a host
                    // turned on would be one this phone could not remember.
                    (None, _) if self.write_blocked => {
                        (PushState::NeedsAttention, RECORD_KEPT.to_owned())
                    }
                    (None, _) => (PushState::Off, String::new()),
                    (Some(kept), Some(why)) if kept.phase == Phase::On => {
                        (PushState::NeedsAttention, (*why).to_owned())
                    }
                    (Some(kept), _) => (
                        match kept.phase {
                            Phase::Working => PushState::Working,
                            Phase::On => PushState::On,
                            Phase::Attention => PushState::NeedsAttention,
                        },
                        kept.words.clone(),
                    ),
                };
                HostPushView {
                    reference: reference_of(host),
                    state: shown,
                    words,
                    settings: kept.is_some_and(|kept| kept.settings),
                    previews: kept.is_none_or(|kept| kept.previews),
                }
            })
            .collect();
        PushView {
            available: cfg!(mobile),
            hosts,
        }
    }

    /// Turns notifications on for the host the page named, and starts the sequence.
    ///
    /// The host is the one the person chose, held from here to the end: a sequence that outlives a
    /// change of the host in use still ends at the host it began for.
    ///
    /// # Errors
    ///
    /// Returns a refusal when this phone is not paired with that host.
    pub fn enable(self: &Arc<Self>, reference: &str) -> Result<PushView> {
        let host = self
            .device
            .host_by_reference(reference)
            .ok_or_else(crate::hosts::unknown_host)?;
        if self.write_blocked {
            // A host started now would be one this phone could not remember.
            return Ok(self.view());
        }
        let now = (self.wiring.clock)();
        let run = {
            let mut state = lock(&self.state);
            state.asking.insert(host.host_device_id);
            // The state says "working" only for a host a run is now taking up: a run that is
            // ending has said what it has to say.
            let run = state.claim(host.host_device_id);
            if run.is_some() {
                Self::mark(
                    &mut state,
                    host.host_device_id,
                    Phase::Working,
                    "Asking for permission.",
                    false,
                    now,
                );
                self.keep(&state.record);
            }
            run
        };
        if let Some(run) = run {
            // The run starts before the page is told: a host marked working has a run behind it
            // even when the page's callback fails.
            self.spawn_run(host, run, Reach::Asked, Job::Full);
            (self.changed)();
        }
        Ok(self.view())
    }

    /// Chooses whether the notifications of the host the page named show what needs the person or
    /// only that something does.
    ///
    /// The choice is recorded and applied on this phone at once: the receivers hold the host's
    /// preview key only while previews are on for it, so turning them off takes the key out before
    /// the host is told, and turning them on files it first. A choice that cannot be kept in the
    /// record, or whose key cannot be filed, is not made: it is let go, the person is told so, and
    /// nothing is left half done. A host that is on is then told, over a run that makes no proposal
    /// to the gateway and asks the person nothing. A host that a run holds is told by that run,
    /// which reads the choice when it gets to the host and goes round again if the choice changed
    /// after. A host that is not on keeps the choice for the run that turns it on, so trying again
    /// sends it.
    ///
    /// # Errors
    ///
    /// Returns a refusal when this phone is not paired with that host, and a local failure when the
    /// choice could not be kept or its key not filed.
    pub async fn set_previews(self: &Arc<Self>, reference: &str, on: bool) -> Result<PushView> {
        let host = self
            .device
            .host_by_reference(reference)
            .ok_or_else(crate::hosts::unknown_host)?;
        if self.write_blocked {
            // A choice made now would be one this phone could not remember.
            return Ok(self.view());
        }
        let key = host.host_device_id.to_string();
        let before = {
            let mut state = lock(&self.state);
            let Some(kept) = state.record.hosts.get_mut(&key) else {
                // A host nobody asked for notifications has no row to choose on.
                drop(state);
                return Ok(self.view());
            };
            let before = std::mem::replace(&mut kept.previews, on);
            if before != on && !self.keep_checked(&state.record) {
                if let Some(kept) = state.record.hosts.get_mut(&key) {
                    kept.previews = before;
                }
                // A write that failed may have reached the disk (a rename that went through and a
                // directory that did not sync): the earlier choice is written again, so that what
                // a restart reads is what the person is told.
                let undone = self.keep_checked(&state.record);
                return Err(CommandError::local_failure(if undone {
                    "This phone could not keep your choice of previews. Try again."
                } else {
                    "This phone could not keep your choice of previews, or put back the one it \
                     had. The one it had may return when the application next starts."
                }));
            }
            before
        };
        if let Err(words) = self.file_keys().await {
            // The choice is let go with the record: Off that left the host's key with the receivers
            // would be Off in name only.
            let undone = {
                let mut state = lock(&self.state);
                if let Some(kept) = state.record.hosts.get_mut(&key) {
                    kept.previews = before;
                }
                self.keep_checked(&state.record)
            };
            // A filing that failed part way may have left the receivers holding some of the new
            // set: the set the record says now is filed again at once, and the next look files it
            // again if this fails too.
            let restored = self.file_keys().await.is_ok();
            return Err(CommandError::local_failure(if undone && restored {
                format!("{words} Your choice of previews was not made. Try again.")
            } else {
                format!(
                    "{words} Your choice of previews was not made, and this phone could not put \
                     back everything it held before. It tries again shortly."
                )
            }));
        }
        let now = (self.wiring.clock)();
        let claimed = {
            let mut state = lock(&self.state);
            let id = host.host_device_id;
            let due = state
                .record
                .hosts
                .get(&key)
                .filter(|kept| kept.phase == Phase::On && !kept.lost)
                .and_then(|kept| kept.told_differs().then_some(kept.registered).flatten());
            match due {
                Some(registered) => state.claim(id).map(|run| {
                    Self::mark(&mut state, id, Phase::Working, TELLING_THE_HOST, false, now);
                    self.keep(&state.record);
                    (run, Job::Delivery(registered))
                }),
                None => None,
            }
        };
        if let Some((run, job)) = claimed {
            self.spawn_run(host, run, Reach::Asked, job);
        }
        (self.changed)();
        Ok(self.view())
    }

    /// Looks again at where notifications stand, and mends what a change since the last look
    /// needs: a host whose registration proposed another token than the provider holds now is
    /// registered again, and a try that stopped for the person is tried again once the person has
    /// had time to act. A host the record lost is left to the person.
    ///
    /// A change of the token is found by comparing the digest each host's registration proposed,
    /// which the record keeps, with the digest of the token the provider holds, so what a look finds
    /// does not depend on anything the platform remembers or on the application having been running
    /// when the token changed. A host whose record has no digest is registered again.
    ///
    /// The check, the claim of each due host and the write of what is marked are made under one
    /// hold, so a host is never marked working without a run behind it.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the paired hosts cannot be read: a list that cannot be read is
    /// not an empty one, and nothing is marked on it.
    pub async fn refresh(self: &Arc<Self>) -> Result<PushView> {
        let hosts = self.device.pairing().hosts.list().map_err(|error| {
            tracing::warn!(%error, "the paired hosts could not be read for a look at notifications");
            CommandError::local_failure("the paired hosts could not be read")
        })?;
        let checked = self.checked_token().await;
        let current = checked.ok();
        let now = (self.wiring.clock)();
        let mut shown = false;
        let claimed: Vec<(PairedHost, u64, Job)> = {
            let mut state = lock(&self.state);
            let mut claimed = Vec::new();
            let mut marked = false;
            // A look that read a token settles every host it could not confirm before; one that
            // could not read one leaves the hosts that are on unconfirmed, since nothing says they
            // still have the token they were registered with.
            match checked {
                Ok(_) => shown = !std::mem::take(&mut state.unconfirmed).is_empty(),
                Err(why) => {
                    for host in &hosts {
                        let id = host.host_device_id;
                        let on = state
                            .record
                            .hosts
                            .get(&id.to_string())
                            .is_some_and(|kept| kept.phase == Phase::On);
                        if on && state.unconfirmed.insert(id, why) != Some(why) {
                            shown = true;
                        }
                    }
                }
            }
            for host in hosts {
                let id = host.host_device_id;
                if let Some(digest) = current
                    && state.running.contains_key(&id)
                {
                    // A run holds the host: what this look saw is kept for the run to weigh when
                    // it compares, since its own answer may be older, and so may this one be
                    // older than another look's.
                    state.observed.entry(id).or_default().insert(digest);
                }
                let Some(kept) = state.record.hosts.get(&id.to_string()) else {
                    continue;
                };
                let after_a_minute = now >= kept.updated_ms.saturating_add(RETRY_AFTER_MS);
                let (due, words) = match kept.phase {
                    Phase::On => {
                        if current.is_some_and(|digest| kept.registered != Some(digest)) {
                            (Some(Job::Full), Some("Registering this phone again."))
                        } else if after_a_minute && kept.told_differs() {
                            // The choice of previews is not the one the host was told, and the
                            // run that would have told it did not finish.
                            (kept.registered.map(Job::Delivery), Some(TELLING_THE_HOST))
                        } else {
                            (None, None)
                        }
                    }
                    Phase::Working => (None, None),
                    Phase::Attention => ((!kept.lost && after_a_minute).then_some(Job::Full), None),
                };
                let Some(job) = due else {
                    continue;
                };
                let Some(run) = state.claim(id) else {
                    continue;
                };
                if let Some(words) = words {
                    Self::mark(&mut state, id, Phase::Working, words, false, now);
                    marked = true;
                }
                claimed.push((host, run, job));
            }
            if marked {
                self.keep(&state.record);
            }
            claimed
        };
        let changed = !claimed.is_empty() || shown;
        // The runs start before the page is told: a host marked working has a run behind it even
        // when the page's callback fails.
        for (host, run, job) in claimed {
            self.spawn_run(host, run, Reach::Visit, job);
        }
        if changed {
            (self.changed)();
        }
        // What the receivers hold follows the record and the paired hosts, so a look mends a filing
        // that failed or a host that was unpaired meanwhile.
        self.file_keys_logged().await;
        Ok(self.view())
    }

    /// The screen a tap on a notification opened the application on, once.
    pub async fn route(&self) -> Option<String> {
        self.native.route().await.unwrap_or(None)
    }

    /// Forgets what is kept of `host`, as the person forgetting the host does. A run that is
    /// taking the host up loses its claim with it, writes nothing more, and is ended where it
    /// waits.
    pub fn forgotten(self: &Arc<Self>, host: DeviceId) {
        {
            let mut state = lock(&self.state);
            state.running.remove(&host);
            // The run may be waiting on the host for an answer that never comes, holding the
            // connection and the endpoint with it: it is ended where it waits.
            if let Some((_, cancel)) = state.cancels.remove(&host) {
                cancel.notify_one();
            }
            state.asking.remove(&host);
            state.observed.remove(&host);
            state.unconfirmed.remove(&host);
            if state.record.hosts.remove(&host.to_string()).is_some() {
                self.keep(&state.record);
            }
        }
        (self.changed)();
        // The host's key is not the receivers' to open its previews with any more.
        let desk = Arc::clone(self);
        tauri::async_runtime::spawn(async move { desk.file_keys_logged().await });
    }

    /// Runs `job` for `host`, which `run` holds, and runs the sequence again for as long as the token
    /// the provider holds is not the one the registration just made proposed, and a delivery again
    /// for as long as the choice of previews is not the one the host was told. The host is reached
    /// as `reach` says.
    fn spawn_run(self: &Arc<Self>, host: PairedHost, run: u64, reach: Reach, first: Job) {
        let cancel = Arc::new(tokio::sync::Notify::new());
        {
            let mut state = lock(&self.state);
            // A host forgotten between the claim and here has no run to start.
            if !state.holds(host.host_device_id, run) {
                return;
            }
            state
                .cancels
                .insert(host.host_device_id, (run, Arc::clone(&cancel)));
        }
        let desk = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let mut guard = RunGuard {
                desk: Arc::clone(&desk),
                host: host.host_device_id,
                run,
                armed: true,
            };
            let work = async {
                let mut job = first;
                loop {
                    match desk.sequence(&host, run, reach, job).await {
                        Ok(registered) => {
                            desk.about_to_compare(host.host_device_id, run);
                            let current = desk.current_digest().await;
                            match desk.registered(host.host_device_id, run, registered, current) {
                                Next::Done => break,
                                Next::Again(next) => job = next,
                            }
                        }
                        Err(stop) => {
                            desk.stopped(host.host_device_id, run, &stop);
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                () = work => {}
                () = cancel.notified() => {}
            }
            desk.run_ended(host.host_device_id, run);
            guard.armed = false;
        });
    }

    /// A run's task has ended: what would end it is no longer wanted. A later run of the same host
    /// keeps its own.
    fn run_ended(&self, host: DeviceId, run: u64) {
        let mut state = lock(&self.state);
        if state
            .cancels
            .get(&host)
            .is_some_and(|(held, _)| *held == run)
        {
            state.cancels.remove(&host);
        }
    }

    /// A run is about to read the token for its comparison: what a look saw until now is older than
    /// the answer, and is let go.
    fn about_to_compare(&self, host: DeviceId, run: u64) {
        let mut state = lock(&self.state);
        if state.holds(host, run) {
            state.observed.remove(&host);
        }
    }

    /// What a run does when its registration is made: the host is on when the token it proposed is
    /// the one the provider holds and the host was told the choice of previews that stands, and the
    /// run goes round again when it is not, whether its own last read or a look made while that
    /// read was on its way says so, or the person chose again while the host was told. A run that
    /// cannot say what the provider holds has no evidence, and stops for a retry. A run that no
    /// longer holds its host writes nothing.
    fn registered(
        &self,
        host: DeviceId,
        run: u64,
        registered: Digest256,
        current: Option<Digest256>,
    ) -> Next {
        let now = (self.wiring.clock)();
        {
            let mut state = lock(&self.state);
            if !state.holds(host, run) {
                return Next::Done;
            }
            state.asking.remove(&host);
            let observed = state.observed.remove(&host).unwrap_or_default();
            if current
                .into_iter()
                .chain(observed.iter().copied())
                .any(|digest| digest != registered)
            {
                // The record already says working, and the repeat reads the token as it stands.
                return Next::Again(Job::Full);
            }
            if current.is_none() && observed.is_empty() {
                drop(state);
                self.stopped(
                    host,
                    run,
                    &"This phone could not read its notification token to finish. Try again in a moment."
                        .to_owned()
                        .into(),
                );
                return Next::Done;
            }
            let Some(kept) = state.record.hosts.get(&host.to_string()) else {
                state.running.remove(&host);
                return Next::Done;
            };
            if kept.told_differs() {
                // The person chose again while the host was being told.
                return Next::Again(Job::Delivery(registered));
            }
            state.running.remove(&host);
            state.unconfirmed.remove(&host);
            let Some(kept) = state.record.hosts.get_mut(&host.to_string()) else {
                return Next::Done;
            };
            kept.phase = Phase::On;
            "This host took this phone for notifications.".clone_into(&mut kept.words);
            kept.settings = false;
            kept.updated_ms = now;
            kept.registered = Some(registered);
            self.keep(&state.record);
        }
        (self.changed)();
        Next::Done
    }

    /// What a run does when its sequence stopped: the host needs the person, for the reason it
    /// gives. A run that no longer holds its host writes nothing.
    fn stopped(&self, host: DeviceId, run: u64, stop: &Stop) {
        let now = (self.wiring.clock)();
        {
            let mut state = lock(&self.state);
            if !state.holds(host, run) {
                return;
            }
            state.running.remove(&host);
            state.asking.remove(&host);
            state.observed.remove(&host);
            state.unconfirmed.remove(&host);
            let Some(kept) = state.record.hosts.get_mut(&host.to_string()) else {
                return;
            };
            kept.phase = Phase::Attention;
            kept.words.clone_from(&stop.words);
            kept.settings = stop.settings;
            kept.updated_ms = now;
            self.keep(&state.record);
        }
        (self.changed)();
    }

    /// Records where a host stands, without writing it.
    fn mark(
        state: &mut State,
        host: DeviceId,
        phase: Phase,
        words: &str,
        settings: bool,
        now: u64,
    ) {
        // What a run says of the host replaces the mark of a look that could not confirm it.
        state.unconfirmed.remove(&host);
        let entry = state
            .record
            .hosts
            .entry(host.to_string())
            .or_insert_with(|| HostPush::new(phase, now));
        entry.lost = false;
        entry.phase = phase;
        entry.words = words.to_owned();
        entry.settings = settings;
        entry.updated_ms = now;
    }

    /// Whether `run` is still wanted: it holds its host, and this phone is still paired with it.
    /// Forgetting a host takes the pairing first and the run's claim after, so both are asked.
    fn wanted(&self, host: DeviceId, run: u64) -> bool {
        let held = lock(&self.state).holds(host, run);
        held && self.device.is_paired_with(host).unwrap_or(false)
    }

    /// Says where a host's notifications stand while `run` holds it: working, in `words`. It keeps
    /// that and tells the page, and says whether it did: a run that no longer holds its host (the
    /// host was forgotten) writes nothing.
    fn working(&self, host: DeviceId, run: u64, words: &str) -> bool {
        let now = (self.wiring.clock)();
        {
            let mut state = lock(&self.state);
            if !state.holds(host, run) || !state.record.hosts.contains_key(&host.to_string()) {
                return false;
            }
            Self::mark(&mut state, host, Phase::Working, words, false, now);
            self.keep(&state.record);
        }
        (self.changed)();
        true
    }

    /// The digest of the token the provider holds now, or the words for why a look cannot say: it
    /// holds none, it could not be read, or the gateway would not take it.
    async fn checked_token(&self) -> std::result::Result<Digest256, &'static str> {
        match self.token().await {
            Ok(Some(token)) => RegistrationToken::new(token)
                .map(|token| token_digest(&token))
                .map_err(|_| TOKEN_REFUSED),
            Ok(None) | Err(_) => Err(TOKEN_UNREADABLE),
        }
    }

    /// The digest of the token the provider holds now, when it holds one.
    async fn current_digest(&self) -> Option<Digest256> {
        self.checked_token().await.ok()
    }

    /// What `job` does for one host, for the run that holds it. The full sequence is permission,
    /// token, proposal, the challenge, the host; a delivery tells the host again, under the
    /// registration it already has. Every failure is words for the person. When it succeeds it says
    /// which token the registration was made for, by its digest.
    ///
    /// # Errors
    ///
    /// Returns the words for whatever stopped it.
    async fn sequence(
        &self,
        host: &PairedHost,
        run: u64,
        reach: Reach,
        job: Job,
    ) -> std::result::Result<Digest256, Stop> {
        // A look never cuts off the host in use, so a host it cannot reach without that is not
        // asked or told anything, and the words say why.
        if reach == Reach::Visit && self.registrar.beside_the_host_in_use(host).await {
            return Err(BESIDE_THE_HOST_IN_USE.to_owned().into());
        }
        match job {
            Job::Full => {
                let (gateway, proposed) = self.propose(host, run).await?;
                self.tell_host(host, run, reach, &gateway, true).await?;
                Ok(proposed)
            }
            Job::Delivery(registered) => {
                let (_, gateway) = self.gateway()?;
                self.tell_host(host, run, reach, &gateway, false).await?;
                Ok(registered)
            }
        }
    }

    /// The gateway this phone's requests go to, and the origin it is at.
    fn gateway(&self) -> std::result::Result<(GatewayOrigin, PushGateway), String> {
        let origin = self.gateway_origin();
        let signer = Arc::new(InstallationSigner::new(
            self.device.identity().keys.authorisation.clone(),
        ));
        let http = (self.wiring.http)(&origin).map_err(|_| unreachable_gateway())?;
        Ok((origin.clone(), PushGateway::new(origin, http, signer)))
    }

    /// The first half of the sequence: the system's permission, the token, and the gateway's
    /// challenge for it, answered. Returns the gateway and the digest of the token it was proposed.
    ///
    /// # Errors
    ///
    /// Returns the words for whatever stopped it.
    async fn propose(
        &self,
        host: &PairedHost,
        run: u64,
    ) -> std::result::Result<(PushGateway, Digest256), Stop> {
        let native = &self.native;
        let mut permission = native
            .permission()
            .await
            .map_err(|_| unreachable_native())?;
        if permission == Permission::Unknown {
            // Only the person's own choice to turn notifications on asks the system's question: a
            // look the application makes by itself, at its start, when it comes to the front or when
            // the network changes, must not put a dialog on a screen the person chose for something
            // else.
            let consent = {
                let mut state = lock(&self.state);
                // Only the run that holds the host may take the person's consent: the run of a host
                // that was forgotten and turned on again must leave it to the run that replaced it.
                if !state.holds(host.host_device_id, run) {
                    return Err(forgotten_host());
                }
                state.asking.remove(&host.host_device_id)
            };
            if !consent {
                return Err(Stop {
                    words: "Notifications are not allowed for this app yet. Choose Try again, and \
                            the system will ask."
                        .to_owned(),
                    settings: false,
                });
            }
            if !self.working(host.host_device_id, run, "Asking for permission.") {
                return Err(forgotten_host());
            }
            permission = native
                .ask_permission()
                .await
                .map_err(|_| unreachable_native())?;
        }
        if permission != Permission::Granted {
            return Err(Stop {
                words:
                    "Notifications are off for this app. Turn them on in the system's settings, \
                        then come back to this screen."
                        .to_owned(),
                settings: true,
            });
        }
        // One registration at a time for the whole phone, until its challenge is answered. The
        // token is read once the turn has come, so that it is the one that stands then.
        if !self.working(
            host.host_device_id,
            run,
            "Waiting for the notification service.",
        ) {
            return Err(forgotten_host());
        }
        let one_at_a_time = self.registering.lock().await;
        let Some(token) = self.token_within(TOKEN_WITHIN).await? else {
            return Err(
                "This phone has no notification token yet. Try again in a moment."
                    .to_owned()
                    .into(),
            );
        };
        let (origin, gateway) = self.gateway()?;

        // The turn and the token may have taken a while, and the person may have forgotten the host
        // meanwhile: a run that is not wanted must not write a pending registration and propose a
        // token for it, with the registration slot it holds.
        if !self.wanted(host.host_device_id, run) {
            return Err(forgotten_host());
        }
        // The record is written before the token is proposed, so a challenge that arrives before the
        // gateway's answer to the proposal is the challenge of a registration the receiver knows.
        let registration_token =
            RegistrationToken::new(token).map_err(|_| TOKEN_REFUSED.to_owned())?;
        let registration_id = PushRegistrationId::new(kr_ipc::new_uuid());
        let now = (self.wiring.clock)();
        let pending = PendingRegistration {
            registration_id,
            token_digest: token_digest(&registration_token),
            gateway_origin: origin,
            platform: this_platform(),
            deadline_ms: now.saturating_add(CHALLENGE_WITHIN_MS),
            state: PendingState::Pending,
            reason: None,
        };
        native
            .pending_set(&pending)
            .await
            .map_err(|_| "This phone could not keep the registration it began.".to_owned())?;
        let proposal = PushRegistrationProposal {
            installation_key: *self.device.identity().keys.authorisation.public(),
            platform: pending.platform,
            registration_id,
            registration_token,
        };
        match gateway
            .propose(proposal)
            .await
            .map_err(|error| gateway_words(&error))?
        {
            Registration::Pending {
                challenge_sent: true,
                ..
            } => {}
            Registration::Pending { .. } => {
                return Err(
                    "The notification service could not send this phone its challenge. Try again \
                     in a moment."
                        .to_owned()
                        .into(),
                );
            }
            Registration::Active { .. } => {}
        }
        match tokio::time::timeout(CHALLENGE_WAIT, self.await_challenge(&pending)).await {
            Ok(settled) => settled?,
            Err(_) => {
                return Err("The challenge did not arrive in time. Try again."
                    .to_owned()
                    .into());
            }
        }
        drop(one_at_a_time);
        Ok((gateway, pending.token_digest))
    }

    /// The second half: the host is told. The receivers hold the host's key first (the keys are
    /// filed before any hold on the host's endpoint is taken: filing is the platform's, and no other
    /// host waits behind it), then the host is reached, then the gateway issues the credential, and
    /// the registration carries it with the person's choice of previews. The full sequence also
    /// tells the host which preview key this phone holds.
    ///
    /// # Errors
    ///
    /// Returns the words for whatever stopped it.
    async fn tell_host(
        &self,
        host: &PairedHost,
        run: u64,
        reach: Reach,
        gateway: &PushGateway,
        full: bool,
    ) -> std::result::Result<(), Stop> {
        // The host is the one the person chose. A phone that was unpaired or forgot the host
        // meanwhile stops here, before the host is asked anything.
        if !self.wanted(host.host_device_id, run) {
            return Err(forgotten_host());
        }
        if !self.working(host.host_device_id, run, TELLING_THE_HOST) {
            return Err(forgotten_host());
        }
        let Some(sender_record_id) = self.sender_record_for(host, Some(run)) else {
            return Err(forgotten_host());
        };
        // The choice the host is told is read once, before the keys are filed, so what the receivers
        // hold is never older than it: a choice made after this is told by a run that goes round
        // again, and one that turns previews off is told after the receivers were asked to let the
        // key go, whether or not they did (a filing that failed is said at the end of the run).
        let Some(previews) = self.previews_wanted(host.host_device_id, run) else {
            return Err(forgotten_host());
        };
        let filed = self.file_keys().await;
        if let (Err(words), true) = (&filed, previews) {
            // The host is not asked to seal to a key the receivers do not hold.
            return Err(Stop::from(words.clone()));
        }
        // The person can forget the host during any of the waits that follow, so the host is
        // sent nothing until the run is asked about again: before the connection, after it, and
        // before each of the changes.
        let wanted = || self.wanted(host.host_device_id, run);
        let not_taken = |stop: LineStop| -> Stop {
            if !wanted() {
                return forgotten_host();
            }
            match stop {
                LineStop::Phone(words) => words.into(),
                LineStop::Host(words) => {
                    format!("The host did not take this phone as a destination: {words}").into()
                }
            }
        };
        if !wanted() {
            return Err(forgotten_host());
        }
        let mut line = self
            .registrar
            .connect(host, reach)
            .await
            .map_err(|words| not_taken(LineStop::Host(words)))?;
        if !wanted() {
            return Err(forgotten_host());
        }
        // The gateway issues once the host is reached: an issue replaces the credential the host
        // holds at once, so a host that cannot be reached keeps the one it has.
        let issued = gateway
            .issue(PushSenderIssueRequest {
                host_endpoint_key: host.host_endpoint_id,
                host_signing_key: host.host_keys.authorisation,
                sender_record_id,
            })
            .await
            .map_err(|error| gateway_words(&error))?;
        if !wanted() {
            return Err(forgotten_host());
        }
        line.register(DevicePushRegisterParams {
            credential: issued.credential,
            // The host seals a preview to the key it holds for this phone when this is true, and
            // the receivers open it with the keys filed before the host was reached.
            previews_enabled: previews,
        })
        .await
        .map_err(not_taken)?;
        if !wanted() {
            return Err(forgotten_host());
        }
        self.told(host.host_device_id, run, previews);
        if full {
            // The revision the host holds, read now: the record may have moved since this run began.
            let revision = self
                .device
                .pairing()
                .hosts
                .by_device(host.host_device_id)
                .ok()
                .flatten()
                .map_or(host.device_key_revision, |held| held.device_key_revision);
            line.update_preview_key(
                *self.device.identity().keys.notification_preview.public(),
                revision,
            )
            .await
            .map_err(not_taken)?;
        }
        // The line is not needed any more, and the hold on the host's endpoint goes with it.
        drop(line);
        // Previews turned off reach the host even when the key could not be taken out of the
        // receivers' hands, which is then said, and the next look files again.
        filed.map_err(Stop::from)
    }

    /// The choice of previews the host is to be told, while `run` holds it.
    fn previews_wanted(&self, host: DeviceId, run: u64) -> Option<bool> {
        let state = lock(&self.state);
        if !state.holds(host, run) {
            return None;
        }
        state
            .record
            .hosts
            .get(&host.to_string())
            .map(|kept| kept.previews)
    }

    /// Records that the host was told `previews`, while `run` holds it.
    fn told(&self, host: DeviceId, run: u64, previews: bool) {
        let mut state = lock(&self.state);
        if !state.holds(host, run) {
            return;
        }
        if let Some(kept) = state.record.hosts.get_mut(&host.to_string()) {
            kept.told_previews = Some(previews);
        }
        self.keep(&state.record);
    }

    /// The keys the receivers are to open previews with, from the record and the paired hosts: the
    /// preview key of each paired host whose record is not lost and whose previews are on, and this
    /// phone's own seed when at least one is. Nothing when what it is built from cannot be read: a list that cannot be read
    /// is not an empty one, and a set built from it would take every host's previews away.
    fn wanted_keys(&self) -> std::result::Result<PreviewKeys, String> {
        let hosts = self.device.pairing().hosts.list().map_err(|error| {
            tracing::warn!(%error, "the paired hosts could not be read to file the preview keys");
            "This phone could not read its paired hosts.".to_owned()
        })?;
        let senders: BTreeMap<[u8; 32], SenderKey> = {
            let state = lock(&self.state);
            hosts
                .iter()
                .filter(|host| {
                    state
                        .record
                        .hosts
                        .get(&host.host_device_id.to_string())
                        .is_some_and(|kept| !kept.lost && kept.previews)
                })
                .map(|host| {
                    let key = host.host_keys.notification_preview;
                    let id = *kr_protocol::pairing::key_id(
                        kr_protocol::pairing::KeyPurpose::NotificationPreview,
                        key.as_bytes(),
                    )
                    .as_bytes();
                    // Two records that name one key name it once: the receivers refuse a set that
                    // names an identifier twice, and one refusal would stop every filing.
                    (
                        id,
                        SenderKey {
                            id,
                            key: *key.as_bytes(),
                        },
                    )
                })
                .collect()
        };
        if senders.is_empty() {
            return Ok(PreviewKeys::default());
        }
        let identity = self.device.identity();
        let name = kr_crypto::store::SecretName::device_key(
            crate::device::identity::SCOPE,
            kr_protocol::pairing::KeyPurpose::NotificationPreview,
        )
        .map_err(|_| "This phone could not find its preview key.".to_owned())?;
        let seed = identity
            .secrets
            .get(&name)
            .map_err(|_| "This phone could not read its preview key.".to_owned())?
            .ok_or_else(|| "This phone has no preview key.".to_owned())?;
        Ok(PreviewKeys {
            recipients: vec![RecipientKey {
                id: *identity.keys.notification_preview.key_id().as_bytes(),
                seed: zeroize::Zeroizing::new(seed.expose().to_vec()),
            }],
            senders: senders.into_values().collect(),
        })
    }

    /// Makes the receivers hold the keys the record and the paired hosts say, and nothing else.
    ///
    /// The set is built and handed over under one hold, so a set built before a newer one is never
    /// filed after it. A set the receivers already hold is not filed again.
    ///
    /// # Errors
    ///
    /// Returns the words for what stopped it.
    async fn file_keys(&self) -> std::result::Result<(), String> {
        let mut filed = self.filed.lock().await;
        let keys = self.wanted_keys()?;
        if filed.as_ref() == Some(&keys) {
            return Ok(());
        }
        // Whatever the receivers hold is not known until this filing is known to have been made.
        *filed = None;
        self.native
            .preview_keys(&keys)
            .await
            .map_err(|_| "This phone could not file its preview key.".to_owned())?;
        *filed = Some(keys);
        Ok(())
    }

    /// [`Self::file_keys`], for the callers that have nobody to tell: a failure is logged, and the
    /// next look files again.
    async fn file_keys_logged(&self) {
        if let Err(words) = self.file_keys().await {
            tracing::warn!(%words, "the preview keys could not be filed for the receivers");
        }
    }

    /// The gateway's origin: the managed service's, and in a debug build the one a device run named.
    fn gateway_origin(&self) -> GatewayOrigin {
        #[cfg(debug_assertions)]
        if let Some(origin) = probe::origin(&self.data) {
            return origin;
        }
        self.origin.clone()
    }

    /// The registration token: the platform's, and in a debug build the one a device run gave.
    async fn token(&self) -> std::result::Result<Option<String>, String> {
        #[cfg(debug_assertions)]
        if let Some(token) = probe::token(&self.data) {
            return Ok(Some(token));
        }
        self.native.token().await.map_err(|_| unreachable_native())
    }

    /// The registration token, waited for up to `within`: a provider makes one a moment after the
    /// person agrees and the system has given the application its own token, which is after the
    /// permission step has said yes.
    async fn token_within(&self, within: Duration) -> std::result::Result<Option<String>, String> {
        read_until(|| self.token(), within, LOOK_EVERY).await
    }

    /// Waits for the receiver to answer the challenge, reading the record it writes.
    async fn await_challenge(
        &self,
        pending: &PendingRegistration,
    ) -> std::result::Result<(), String> {
        loop {
            let held = self
                .native
                .pending_get()
                .await
                .map_err(|_| "This phone could not read its registration.".to_owned())?;
            let Some(held) = held else {
                return Err("This phone lost the record of its registration.".to_owned());
            };
            if held.registration_id != pending.registration_id {
                return Err("A newer registration replaced this one.".to_owned());
            }
            match held.state {
                PendingState::Answered => return Ok(()),
                PendingState::Pending => {}
                PendingState::Expired => {
                    return Err("The challenge did not arrive in time. Try again.".to_owned());
                }
                PendingState::Refused => {
                    return Err(format!(
                        "The notification service refused this phone's answer ({}).",
                        held.reason.unwrap_or_else(|| "no reason given".to_owned())
                    ));
                }
            }
            tokio::time::sleep(LOOK_EVERY).await;
        }
    }

    /// Asks the gateway to issue this phone's authorisation for `host` again, under the same record,
    /// and keeps the new credential nowhere and tells the host nothing. What a device run uses to
    /// leave the host holding a credential the gateway no longer accepts: the revision it says is the
    /// one the gateway now holds.
    ///
    /// # Errors
    ///
    /// Returns the words for what stopped it.
    #[cfg(debug_assertions)]
    pub async fn reissue_unannounced(&self, host: &PairedHost) -> std::result::Result<u64, String> {
        let (_, gateway) = self.gateway()?;
        let issued = gateway
            .issue(PushSenderIssueRequest {
                host_endpoint_key: host.host_endpoint_id,
                host_signing_key: host.host_keys.authorisation,
                sender_record_id: self
                    .sender_record_for(host, None)
                    .ok_or_else(|| "This phone is no longer paired with that host.".to_owned())?,
            })
            .await
            .map_err(|error| gateway_words(&error))?;
        Ok(issued.credential.revision.get())
    }

    /// The authorisation identifier for `host`: the one issued before, or a new one, kept at once.
    ///
    /// For a run, the identifier is given only while the run still holds the host; a run that
    /// lost it (the host was forgotten) gets none, and never makes the host's record again.
    fn sender_record_for(&self, host: &PairedHost, run: Option<u64>) -> Option<PushSenderRecordId> {
        let mut state = lock(&self.state);
        let id = host.host_device_id;
        if run.is_some_and(|run| !state.holds(id, run)) {
            return None;
        }
        let key = id.to_string();
        let held = state
            .record
            .hosts
            .get(&key)
            .and_then(|kept| kept.sender_record_id);
        let sender = held.unwrap_or_else(|| PushSenderRecordId::new(kr_ipc::new_uuid()));
        if held.is_none() {
            let now = (self.wiring.clock)();
            let entry = state
                .record
                .hosts
                .entry(key)
                .or_insert_with(|| HostPush::new(Phase::Working, now));
            entry.sender_record_id = Some(sender);
            self.keep(&state.record);
        }
        Some(sender)
    }

    /// Writes the record whole, unless it would replace a record that could not be read and is
    /// still in place. A failure is logged and not raised: what the person sees is the memory, and
    /// the next change writes it again.
    fn keep(&self, record: &Record) {
        self.keep_checked(record);
    }

    /// [`Self::keep`], saying whether the record is on disk as `record` has it: a choice the person
    /// must be told did not take effect is made only after this answers yes.
    fn keep_checked(&self, record: &Record) -> bool {
        if self.write_blocked {
            return false;
        }
        let Some(directory) = self.file.parent() else {
            return false;
        };
        if let Err(error) = kr_ipc::paths::create_private_directory(directory) {
            tracing::warn!(%error, "the notifications record's directory could not be made");
            return false;
        }
        match serde_json::to_vec(&Versioned { record }) {
            Ok(bytes) => match write_owner_only_file(&self.file, &bytes) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(%error, "the notifications record could not be written");
                    false
                }
            },
            Err(error) => {
                tracing::warn!(%error, "the notifications record could not be encoded");
                false
            }
        }
    }
}

#[derive(Serialize)]
struct Versioned<'a> {
    #[serde(flatten)]
    record: &'a Record,
}

/// What the record file holds.
enum Loaded {
    /// The record, which is empty where there is no file.
    Record(Record),
    /// A file that is there and is not a record this build reads.
    Unreadable {
        /// What is wrong with it, in words that quote nothing the file held.
        why: Shown,
        /// Whether the system failed to read it, which a later start may not.
        read_failed: bool,
    },
    /// No record, where an earlier start set one aside: it ended before it had written the record
    /// that marks the lost hosts.
    Interrupted,
}

/// The record on disk.
fn read_record(file: &Path) -> Loaded {
    let bytes = match read_owner_only_file(file, RECORD_LIMIT) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return if has_a_record_set_aside(file) {
                Loaded::Interrupted
            } else {
                Loaded::Record(Record::empty())
            };
        }
        Err(error) => {
            return Loaded::Unreadable {
                why: Shown::ipc(&error),
                read_failed: matches!(error, kr_ipc::IpcError::Io { .. }),
            };
        }
    };
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if record.version == VERSION => Loaded::Record(record),
        Ok(_) => Loaded::Unreadable {
            why: Shown::said("it is a record of another version"),
            read_failed: false,
        },
        Err(error) => Loaded::Unreadable {
            why: Shown::json(&error),
            read_failed: false,
        },
    }
}

/// Whether nothing is at `path`, a link that points nowhere included. A path that cannot be
/// inspected is not absent.
fn is_absent(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether a start set a record aside before: the file's name, `push.unreadable-<time>` and what
/// follows, is in the record's directory.
fn has_a_record_set_aside(file: &Path) -> bool {
    file.parent()
        .and_then(|directory| std::fs::read_dir(directory).ok())
        .is_some_and(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(ASIDE_PREFIX)
            })
        })
}

/// Moves a record that cannot be read out of the way, under a name no earlier one has, and says so
/// in the log. It holds each host's authorisation identifier, so it is kept as it was found.
/// Returns whether it was moved.
fn set_aside(file: &Path, why: &Shown, now_ms: u64) -> bool {
    let free = (0_u32..ASIDE_NAMES)
        .map(|attempt| {
            let name = match attempt {
                0 => format!("{ASIDE_PREFIX}{now_ms}.json"),
                _ => format!("{ASIDE_PREFIX}{now_ms}-{attempt}.json"),
            };
            file.with_file_name(name)
        })
        .find(|each| is_absent(each));
    let Some(aside) = free else {
        // Names that are all taken, or that cannot be inspected, are not tried for ever: the record
        // stays where it is and nothing is written over it.
        tracing::error!(
            why = %why,
            "the notifications record could not be set aside under any name it was tried under"
        );
        return false;
    };
    match std::fs::rename(file, &aside) {
        Ok(()) => {
            tracing::error!(
                why = %why,
                set_aside_at_ms = now_ms,
                "the notifications record could not be read and was set aside"
            );
            true
        }
        Err(error) => {
            tracing::error!(
                why = %why,
                error = %Shown::io(&error),
                "the notifications record could not be set aside"
            );
            false
        }
    }
}

/// The record a desk starts from when the one it found cannot be read: each host paired now is
/// marked as lost, which the page shows as needing the person.
fn record_after_a_loss(hosts: &[PairedHost], now_ms: u64, words: &str) -> Record {
    let mut record = Record::empty();
    for host in hosts {
        record.hosts.insert(
            host.host_device_id.to_string(),
            HostPush {
                words: words.to_owned(),
                lost: true,
                ..HostPush::new(Phase::Attention, now_ms)
            },
        );
    }
    record
}

/// What a record says when the application starts. A run that was under way then ended with the
/// process, and nothing is running it now, so it is a stop the person can mend and not a state that
/// says it is working for ever. A run that reached an end stays as it was.
///
/// The stop keeps the time the run was last heard of, so a start a minute or more after it retries
/// at its first look and one sooner waits out the rest of the minute, as a stop that happened while
/// the application ran would. A time later than now is a clock set back, and counts as now.
fn after_a_restart(mut record: Record, now_ms: u64) -> Record {
    for kept in record.hosts.values_mut() {
        if kept.phase == Phase::Working {
            kept.phase = Phase::Attention;
            "Turning on notifications was interrupted. Try again.".clone_into(&mut kept.words);
            kept.settings = false;
            kept.updated_ms = kept.updated_ms.min(now_ms);
        }
    }
    record
}

/// Reads with `read` every `every` until it gives a value, for no longer than `within` in all.
///
/// One deadline covers the reads and the waits between them: a read can itself wait for the
/// provider, or never answer, and the registration slot a run holds is not held longer than
/// `within`. `Ok(None)` when the time ran out.
async fn read_until<F, Fut, T>(
    mut read: F,
    within: Duration,
    every: Duration,
) -> std::result::Result<Option<T>, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<Option<T>, String>>,
{
    let wait = async {
        loop {
            if let Some(value) = read().await? {
                return Ok(Some(value));
            }
            tokio::time::sleep(every).await;
        }
    };
    tokio::time::timeout(within, wait).await.unwrap_or(Ok(None))
}

fn forgotten_host() -> Stop {
    "This phone is no longer paired with that host."
        .to_owned()
        .into()
}

fn unreachable_native() -> String {
    "This phone could not be asked about notifications.".to_owned()
}

fn unreachable_gateway() -> String {
    "The notification service could not be reached. Try again in a moment.".to_owned()
}

/// What a gateway's refusal or silence says, in words for the person.
fn gateway_words(error: &kr_client::ClientError) -> String {
    use kr_protocol::error::ErrorCode;

    match error.code() {
        ErrorCode::RateLimited => {
            "The notification service asked this phone to wait. Try again in a few minutes."
                .to_owned()
        }
        ErrorCode::HostNotConfigured => {
            "The notification service is not set up for this app.".to_owned()
        }
        ErrorCode::PermissionDenied => {
            "The notification service did not accept this phone. Try again.".to_owned()
        }
        _ => unreachable_gateway(),
    }
}

/// The product's native half: the platform plugin.
pub struct PluginNative<R: tauri::Runtime>(pub tauri::AppHandle<R>);

fn said(error: companion_platform::PlatformError) -> String {
    error.to_string()
}

impl<R: tauri::Runtime> Native for PluginNative<R> {
    fn permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async move {
            companion_platform::notify::permission(&self.0)
                .await
                .map_err(said)
        })
    }

    fn ask_permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async move {
            companion_platform::notify::ask_permission(&self.0)
                .await
                .map_err(said)
        })
    }

    fn token(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async move {
            companion_platform::notify::token(&self.0)
                .await
                .map_err(said)
        })
    }

    fn pending_set<'a>(&'a self, record: &'a PendingRegistration) -> PushFuture<'a, ()> {
        Box::pin(async move {
            companion_platform::notify::pending_set(&self.0, record)
                .await
                .map_err(said)
        })
    }

    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>> {
        Box::pin(async move {
            companion_platform::notify::pending_get(&self.0)
                .await
                .map_err(said)
        })
    }

    fn preview_keys<'a>(&'a self, keys: &'a PreviewKeys) -> PushFuture<'a, ()> {
        Box::pin(async move {
            companion_platform::notify::preview_keys(&self.0, keys)
                .await
                .map_err(said)
        })
    }

    fn route(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async move {
            companion_platform::notify::route(&self.0)
                .await
                .map_err(said)
        })
    }
}

/// How long the phone waits for the host to answer one of the two changes. The host drops a
/// request that is older than [`crate::commands::MUTATION_TTL`], and an answer later than that is
/// not one; a host that keeps its connection and never answers must not keep the line, and the
/// hold on the host's endpoint with it, for ever.
const ANSWER_WITHIN: Duration = Duration::from_secs(60);

/// `call`, ended with a failure in words when the host has not answered within [`ANSWER_WITHIN`].
async fn within_the_answer<T>(
    call: impl Future<Output = std::result::Result<T, String>>,
) -> std::result::Result<T, String> {
    tokio::time::timeout(ANSWER_WITHIN, call)
        .await
        .unwrap_or_else(|_| Err("the host did not answer in time".to_owned()))
}

/// The product's way to the host: a connection opened for the host, as the device the host made.
pub struct ConnectionRegistrar(pub Arc<Device>);

impl Registrar for ConnectionRegistrar {
    fn beside_the_host_in_use<'a>(&'a self, host: &'a PairedHost) -> AskFuture<'a> {
        Box::pin(async move {
            let in_use = || self.0.host_in_use().map(|using| using.network_config);
            self.0
                .pairing()
                .link
                .would_refuse_visit(&host.network_config, &in_use)
                .await
        })
    }

    fn connect<'a>(
        &'a self,
        host: &'a PairedHost,
        reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>> {
        Box::pin(async move {
            // The endpoint is held from before the connection is made until the line is dropped:
            // a visit to another host that shares its relay would close it, and so would the
            // host in use reconnecting. A look's run asks the pool whether the host in use allows
            // it, in the same request as the hold.
            let link = &self.0.pairing().link;
            let unreached = |_| "the host did not answer in time".to_owned();
            let held = match reach {
                Reach::Asked => {
                    tokio::time::timeout(
                        crate::connection::CONNECT_WITHIN,
                        link.hold(&host.network_config),
                    )
                    .await
                }
                Reach::Visit => {
                    let in_use = || self.0.host_in_use().map(|using| using.network_config);
                    tokio::time::timeout(
                        crate::connection::CONNECT_WITHIN,
                        link.visit_hold(&host.network_config, &in_use),
                    )
                    .await
                }
            }
            .map_err(unreached)?
            .map_err(|error| error.said().into_string())?;
            let connection = match reach {
                Reach::Asked => crate::connection::Connection::paired(&self.0, host).await,
                Reach::Visit => crate::connection::Connection::visited(&self.0, host)
                    .await
                    .map_err(crate::connection::Unopened::into_error),
            }
            .map_err(|error| error.message)?;
            Ok(Box::new(ConnectionLine {
                connection,
                device: Arc::clone(&self.0),
                host_device_id: host.host_device_id,
                device_id: host.device_id,
                _held: held,
            }) as Box<dyn HostLine + 'a>)
        })
    }
}

/// The paired connection to one host.
struct ConnectionLine {
    connection: crate::connection::Connection,
    /// This phone, which keeps the revision of its keys the host takes.
    device: Arc<Device>,
    host_device_id: DeviceId,
    /// The host's identifier for this phone.
    device_id: DeviceId,
    /// The hold on the host's endpoint, kept until the line is dropped.
    _held: kr_client::pairing::link::EndpointHold,
}

impl ConnectionLine {
    /// Fails, in the words of why, when the account the connection was opened under has signed out
    /// or been replaced: a change made to a host under the lease of an account that has left is
    /// made for no one.
    fn still_the_account(&self) -> std::result::Result<(), LineStop> {
        match self.connection.ended_by_this_device() {
            Some(refusal) => Err(LineStop::Phone(refusal.message)),
            None => Ok(()),
        }
    }
}

impl HostLine for ConnectionLine {
    fn register(
        &mut self,
        params: DevicePushRegisterParams,
    ) -> LineFuture<'_, DevicePushRegisterResult> {
        Box::pin(async move {
            use kr_protocol::envelope::ActionTarget;
            use kr_protocol::method::Method;

            self.still_the_account()?;
            let settled = within_the_answer(async {
                self.connection
                    .session()
                    .mutate(
                        Method::DevicePushRegister,
                        ActionTarget::environment(self.connection.environment_id()),
                        None,
                        &crate::commands::NoPreconditions {},
                        &params,
                        crate::commands::MUTATION_TTL,
                    )
                    .await
                    .map_err(|error| CommandError::from(error).message)
            })
            .await
            .map_err(LineStop::Host)?;
            match settled {
                kr_client::Settled::Result(value) => value.to_typed().map_err(|_| {
                    LineStop::Host("its answer was not one this phone reads".to_owned())
                }),
                kr_client::Settled::Receipt(_) => Err(LineStop::Host(
                    "it did not say it had taken the registration".to_owned(),
                )),
            }
        })
    }

    fn update_preview_key(
        &mut self,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
        revision: DeviceKeyRevision,
    ) -> LineFuture<'_, ()> {
        Box::pin(async move {
            use kr_protocol::envelope::ActionTarget;
            use kr_protocol::method::Method;
            use kr_protocol::sharing::DevicePreviewKeyUpdateParams;

            // The registration that came before may have been made under an account that has since
            // left: the key goes to the host only for the account that is signed in now.
            self.still_the_account()?;
            // The call says which key the phone holds and at which revision: the same key at the
            // same revision is answered as already recorded, a higher revision is recorded, and a
            // revision behind the host's is refused.
            within_the_answer(async {
                self.connection
                    .session()
                    .mutate(
                        Method::DevicePreviewKeyUpdate,
                        ActionTarget::environment(self.connection.environment_id()),
                        None,
                        &crate::commands::NoPreconditions {},
                        &DevicePreviewKeyUpdateParams {
                            device_id: self.device_id,
                            notification_preview: preview_key,
                            revision,
                        },
                        crate::commands::MUTATION_TTL,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|error| CommandError::from(error).message)
            })
            .await
            .map_err(LineStop::Host)?;
            // The host holds the revision now, and the next connection has to offer it.
            self.device
                .pairing()
                .hosts
                .raise_revision(self.host_device_id, self.device_id, revision)
                .map_err(|_| {
                    LineStop::Phone(
                        "this phone could not keep the revision the host took".to_owned(),
                    )
                })
        })
    }
}

/// What a device run gives a debug build instead of a provider's token and the managed service's
/// origin: a file in the application's own data directory, `kr-probe/push-request.json`, as the other
/// device checks have. A release build has none of it.
#[cfg(debug_assertions)]
mod probe {
    use std::path::Path;

    use kr_protocol::service::GatewayOrigin;

    fn request(data: &Path) -> Option<serde_json::Value> {
        serde_json::from_slice(
            &std::fs::read(data.join("kr-probe").join("push-request.json")).ok()?,
        )
        .ok()
    }

    pub(super) fn token(data: &Path) -> Option<String> {
        request(data)?.get("token")?.as_str().map(str::to_owned)
    }

    pub(super) fn origin(data: &Path) -> Option<GatewayOrigin> {
        GatewayOrigin::new(request(data)?.get("origin")?.as_str()?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(phase: Phase, settings: bool) -> HostPush {
        HostPush {
            sender_record_id: Some(PushSenderRecordId::new(kr_ipc::new_uuid())),
            phase,
            words: "words".to_owned(),
            settings,
            updated_ms: 7,
            registered: None,
            lost: false,
            previews: true,
            told_previews: None,
        }
    }

    /// What a record says when the application starts: a run the system ended in the middle is not
    /// left saying it is working, since nothing is running it, and what a run reached stays as it was.
    #[test]
    fn a_run_that_was_cut_short_is_not_left_saying_it_is_working() {
        let kept_id = PushSenderRecordId::new(kr_ipc::new_uuid());
        let mut working = host(Phase::Working, false);
        working.sender_record_id = Some(kept_id);
        let on = host(Phase::On, false);
        let stopped = host(Phase::Attention, true);
        let record = Record {
            version: VERSION,
            hosts: BTreeMap::from([
                ("working".to_owned(), working),
                ("on".to_owned(), on.clone()),
                ("stopped".to_owned(), stopped.clone()),
            ]),
        };

        let started = after_a_restart(record, 99);

        let working = &started.hosts["working"];
        assert_eq!(working.phase, Phase::Attention);
        assert!(!working.settings, "nothing the system's setting can mend");
        assert_eq!(
            working.updated_ms, 7,
            "the stop is from when the run was last heard of"
        );
        assert_eq!(
            working.sender_record_id,
            Some(kept_id),
            "asking again issues under the authorisation this phone already has"
        );
        assert_eq!(started.hosts["on"], on);
        assert_eq!(started.hosts["stopped"], stopped);
    }

    /// A time later than the start's own is a clock set back: the retry is not delayed by it.
    #[test]
    fn a_run_last_heard_of_in_the_future_is_taken_to_have_stopped_now() {
        let mut working = host(Phase::Working, false);
        working.updated_ms = 500;
        let record = Record {
            version: VERSION,
            hosts: BTreeMap::from([("working".to_owned(), working)]),
        };

        let started = after_a_restart(record, 99);

        assert_eq!(started.hosts["working"].updated_ms, 99);
    }

    /// A record is set aside under a name no earlier one has: one left from an earlier loss, a link
    /// that points nowhere among them, is never replaced.
    #[cfg(unix)]
    #[test]
    fn a_record_is_set_aside_under_a_name_no_earlier_one_has() {
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join(RECORD);
        std::fs::write(&file, b"the record").expect("a record");
        let earlier = directory.path().join(format!("{ASIDE_PREFIX}7.json"));
        std::os::unix::fs::symlink(directory.path().join("nowhere"), &earlier)
            .expect("a link that points nowhere");

        assert!(set_aside(&file, &Shown::said("a test"), 7));

        assert!(
            std::fs::symlink_metadata(&earlier)
                .expect("the earlier name")
                .is_symlink(),
            "the earlier name is as it was"
        );
        assert_eq!(
            std::fs::read(directory.path().join(format!("{ASIDE_PREFIX}7-1.json")))
                .expect("the record under a name of its own"),
            b"the record"
        );
        assert!(!file.exists(), "the record is out of the way");
    }

    /// A record is not set aside for ever under names that are all taken or cannot be inspected: it
    /// is tried under a bounded number of names and left where it is, whole.
    #[test]
    fn a_record_is_left_in_place_when_no_name_is_free_to_set_it_aside_under() {
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join(RECORD);
        std::fs::write(&file, b"the record").expect("a record");
        for attempt in 0..ASIDE_NAMES {
            let name = match attempt {
                0 => format!("{ASIDE_PREFIX}7.json"),
                _ => format!("{ASIDE_PREFIX}7-{attempt}.json"),
            };
            std::fs::write(directory.path().join(name), b"earlier").expect("an earlier record");
        }

        assert!(!set_aside(&file, &Shown::said("a test"), 7));

        assert_eq!(
            std::fs::read(&file).expect("the record"),
            b"the record",
            "the record is where it was"
        );
    }

    /// A read that never answers does not keep the registration slot past the time given: the wait
    /// ends with no value, and a value that comes in time is the value.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_never_answers_does_not_outlast_its_time() {
        let never = read_until(
            std::future::pending::<std::result::Result<Option<u8>, String>>,
            Duration::from_secs(20),
            Duration::from_millis(500),
        );
        let ended = tokio::time::timeout(Duration::from_secs(21), never).await;
        assert_eq!(ended, Ok(Ok(None)), "the wait ended at its time");

        let mut reads = 0;
        let late = read_until(
            || {
                reads += 1;
                let answer = (reads == 3).then_some(7_u8);
                async move { Ok(answer) }
            },
            Duration::from_secs(20),
            Duration::from_millis(500),
        );
        assert_eq!(late.await, Ok(Some(7)), "a value in time is the value");
    }

    /// A host that keeps its connection and never answers a change does not keep the line for ever:
    /// the call ends in words once the host's own limit on the request has passed.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_never_answers_a_change_does_not_keep_the_line() {
        let never = within_the_answer(std::future::pending::<std::result::Result<(), String>>());
        assert_eq!(
            never.await,
            Err("the host did not answer in time".to_owned())
        );
        assert_eq!(
            within_the_answer(async { Ok::<_, String>(7) }).await,
            Ok(7),
            "an answer in time is the answer"
        );
    }
}
