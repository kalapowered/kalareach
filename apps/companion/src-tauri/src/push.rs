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
//! # What the person sees
//!
//! One action per host, "turn on notifications", and where it stands: off, working, on, or needing
//! the person (the system's permission is off, the token has not arrived, the gateway or the host
//! could not be reached). Stopping notifications is the system's setting: a host ends a destination
//! when it unpairs the device, and only the host can revoke the authorisation it holds.
//!
//! # What is kept, and what is not
//!
//! `push/push.json` under the application's data directory holds, per paired host, whether the
//! person asked, the authorisation identifier this phone issued for that host (so asking again
//! issues under the same identifier and the host keeps one authorisation), and the last outcome in
//! words. It holds no token, no key and no credential. The credential exists in memory between the
//! gateway's issue and the host's answer and is never kept: a registration whose answer was lost is
//! made again under a new action with a fresh credential, which is what the host expects.
//!
//! # What repeats
//!
//! Each step is safe to repeat, so a restart, a lost answer or a changed token is mended by doing
//! the sequence again for the host that asked: the same installation key, the same authorisation
//! identifier, a new action. A person who is asked for permission and says no is told so, and the
//! sequence is tried again the next time the application is in front, never in a loop.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use companion_platform::notify::Permission;
use companion_platform::push::{PendingRegistration, PendingState};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::push::{InstallationSigner, PushGateway, Registration};
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use kr_protocol::ids::DeviceKeyRevision;
use kr_protocol::ids::{DeviceId, PushRegistrationId, PushSenderRecordId};
use kr_protocol::push::{
    DevicePushRegisterParams, DevicePushRegisterResult, PushPlatform, PushRegistrationProposal,
    PushSenderIssueRequest, RegistrationToken, token_digest,
};
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

/// The soonest the same host is tried again after a try that needed the person: asking the system
/// or the gateway again at every foreground would be a loop with a person in it.
const RETRY_AFTER_MS: u64 = 60 * 1000;

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
}

/// What is kept on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    /// By the host's device identifier.
    hosts: BTreeMap<String, HostPush>,
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
    /// Whether the token changed since this was last asked.
    fn token_changed(&self) -> PushFuture<'_, bool>;
    /// Replaces the record of the registration being waited for.
    fn pending_set<'a>(&'a self, record: &'a PendingRegistration) -> PushFuture<'a, ()>;
    /// The record of the registration being waited for, as it stands now.
    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>>;
    /// Files the notification-preview key in the limited store a receiver reads.
    fn limited_key<'a>(
        &'a self,
        recipient_key_id: &'a [u8; 32],
        seed: &'a [u8],
    ) -> PushFuture<'a, ()>;
    /// The screen a tap on a notification opened the application on, once.
    fn route(&self) -> PushFuture<'_, Option<String>>;
}

/// How this phone hands a delivery credential to the host it is paired with.
pub trait Registrar: Send + Sync {
    /// Sends `device.push.register` and `device.preview_key.update` to `host` over the paired
    /// connection, and answers what the host answered.
    fn register<'a>(
        &'a self,
        host: &'a PairedHost,
        params: DevicePushRegisterParams,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
    ) -> PushFuture<'a, DevicePushRegisterResult>;
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
    record: Mutex<Record>,
    /// The hosts a sequence is running for, so there is one at a time for each.
    running: Mutex<BTreeSet<DeviceId>>,
    changed: Box<dyn Fn() + Send + Sync>,
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
        let record = after_a_restart(read_record(&file), (wiring.clock)());
        Ok(Arc::new(Self {
            file,
            data: data.to_path_buf(),
            device,
            native,
            registrar,
            wiring,
            origin,
            record: Mutex::new(record),
            running: Mutex::new(BTreeSet::new()),
            changed: Box::new(changed),
        }))
    }

    /// What the page is shown: each paired host and where its notifications stand.
    #[must_use]
    pub fn view(&self) -> PushView {
        let record = lock(&self.record);
        let hosts = self
            .device
            .pairing()
            .hosts
            .list()
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|host| {
                let kept = record.hosts.get(&host.host_device_id.to_string());
                HostPushView {
                    reference: reference_of(host),
                    state: match kept.map(|kept| kept.phase) {
                        None => PushState::Off,
                        Some(Phase::Working) => PushState::Working,
                        Some(Phase::On) => PushState::On,
                        Some(Phase::Attention) => PushState::NeedsAttention,
                    },
                    words: kept.map_or_else(String::new, |kept| kept.words.clone()),
                    settings: kept.is_some_and(|kept| kept.settings),
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
    /// Returns a refusal when this computer is not paired with that host, or is not a phone.
    pub fn enable(self: &Arc<Self>, reference: &str) -> Result<PushView> {
        if !cfg!(mobile) {
            return Err(CommandError::unsupported("notifications are a phone's"));
        }
        let host = self
            .device
            .host_by_reference(reference)
            .ok_or_else(crate::hosts::unknown_host)?;
        self.set(&host, Phase::Working, "Asking for permission.", None);
        self.start(host);
        Ok(self.view())
    }

    /// Looks again at where notifications stand, and mends what a change since the last look
    /// needs: a token that changed is registered again, and a try that stopped for the person is
    /// tried again once the person has had time to act.
    pub async fn refresh(self: &Arc<Self>) -> PushView {
        if !cfg!(mobile) {
            return self.view();
        }
        let changed = self.native.token_changed().await.unwrap_or(false);
        let now = (self.wiring.clock)();
        let due: Vec<PairedHost> = {
            let record = lock(&self.record);
            self.device
                .pairing()
                .hosts
                .list()
                .unwrap_or_default()
                .into_iter()
                .filter(|host| {
                    record
                        .hosts
                        .get(&host.host_device_id.to_string())
                        .is_some_and(|kept| match kept.phase {
                            Phase::On => changed,
                            Phase::Attention => {
                                now >= kept.updated_ms.saturating_add(RETRY_AFTER_MS)
                            }
                            Phase::Working => false,
                        })
                })
                .collect()
        };
        for host in due {
            self.start(host);
        }
        self.view()
    }

    /// The screen a tap on a notification opened the application on, once.
    pub async fn route(&self) -> Option<String> {
        self.native.route().await.unwrap_or(None)
    }

    /// Forgets what is kept of `host`, as the person forgetting the host does.
    pub fn forgotten(&self, host: DeviceId) {
        let mut record = lock(&self.record);
        if record.hosts.remove(&host.to_string()).is_some() {
            self.keep(&record);
        }
        drop(record);
        (self.changed)();
    }

    /// Starts the sequence for `host` unless one is running for it.
    fn start(self: &Arc<Self>, host: PairedHost) {
        if !lock(&self.running).insert(host.host_device_id) {
            return;
        }
        let desk = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let outcome = desk.sequence(&host).await;
            match outcome {
                Ok(()) => desk.set(
                    &host,
                    Phase::On,
                    "Notifications are on for this host.",
                    None,
                ),
                Err(stop) => desk.set_stopped(&host, &stop),
            }
            lock(&desk.running).remove(&host.host_device_id);
        });
    }

    /// The whole sequence for one host: permission, token, proposal, the challenge, the
    /// authorisation, the host. Every failure is words for the person.
    ///
    /// # Errors
    ///
    /// Returns the words for whatever stopped it.
    pub async fn sequence(&self, host: &PairedHost) -> std::result::Result<(), Stop> {
        let native = &self.native;
        let mut permission = native
            .permission()
            .await
            .map_err(|_| unreachable_native())?;
        if permission == Permission::Unknown {
            self.set(host, Phase::Working, "Asking for permission.", None);
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
        let Some(token) = self.token().await? else {
            return Err(
                "This phone has no notification token yet. Try again in a moment."
                    .to_owned()
                    .into(),
            );
        };
        let origin = self.gateway_origin();
        let signer = Arc::new(InstallationSigner::new(
            self.device.identity().keys.authorisation.clone(),
        ));
        let http = (self.wiring.http)(&origin).map_err(|_| unreachable_gateway())?;
        let gateway = PushGateway::new(origin.clone(), http, signer.clone());

        // The record is written before the token is proposed, so a challenge that arrives before the
        // gateway's answer to the proposal is the challenge of a registration the receiver knows.
        let registration_token = RegistrationToken::new(token).map_err(|_| {
            "The notification token this phone was given is not one the gateway takes.".to_owned()
        })?;
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
        self.set(
            host,
            Phase::Working,
            "Waiting for the notification service.",
            None,
        );
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
        self.await_challenge(&pending).await?;

        // The host is the one the person chose. A phone that was unpaired or forgot the host
        // while the challenge was awaited stops here, before the host is asked anything.
        if !self
            .device
            .is_paired_with(host.host_device_id)
            .unwrap_or(false)
        {
            return Err("This phone is no longer paired with that host."
                .to_owned()
                .into());
        }
        self.set(host, Phase::Working, "Telling the host.", None);
        let sender_record_id = self.sender_record_for(host);
        let issued = gateway
            .issue(PushSenderIssueRequest {
                host_endpoint_key: host.host_endpoint_id,
                host_signing_key: host.host_keys.authorisation,
                sender_record_id,
            })
            .await
            .map_err(|error| gateway_words(&error))?;
        let keys = &self.device.identity().keys;
        self.registrar
            .register(
                host,
                DevicePushRegisterParams {
                    credential: issued.credential,
                    // The host seals a preview to the key it holds for this phone. The phone shows
                    // the generic alert; the key is filed so a later opener needs no registration.
                    previews_enabled: true,
                },
                *keys.notification_preview.public(),
            )
            .await
            .map_err(|words| {
                format!("The host did not take this phone as a destination: {words}")
            })?;

        let name = kr_crypto::store::SecretName::device_key(
            crate::device::identity::SCOPE,
            kr_protocol::pairing::KeyPurpose::NotificationPreview,
        )
        .map_err(|_| "This phone could not find its preview key.".to_owned())?;
        let seed = self
            .device
            .identity()
            .secrets
            .get(&name)
            .map_err(|_| "This phone could not read its preview key.".to_owned())?
            .ok_or_else(|| "This phone has no preview key.".to_owned())?;
        native
            .limited_key(keys.notification_preview.key_id().as_bytes(), seed.expose())
            .await
            .map_err(|_| "This phone could not file its preview key.".to_owned())?;
        Ok(())
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
                PendingState::Superseded => {
                    return Err("A newer registration replaced this one.".to_owned());
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
        let origin = self.gateway_origin();
        let signer = Arc::new(InstallationSigner::new(
            self.device.identity().keys.authorisation.clone(),
        ));
        let http = (self.wiring.http)(&origin).map_err(|_| unreachable_gateway())?;
        let gateway = PushGateway::new(origin, http, signer);
        let issued = gateway
            .issue(PushSenderIssueRequest {
                host_endpoint_key: host.host_endpoint_id,
                host_signing_key: host.host_keys.authorisation,
                sender_record_id: self.sender_record_for(host),
            })
            .await
            .map_err(|error| gateway_words(&error))?;
        Ok(issued.credential.revision.get())
    }

    /// The authorisation identifier for `host`: the one issued before, or a new one, kept at once.
    fn sender_record_for(&self, host: &PairedHost) -> PushSenderRecordId {
        let mut record = lock(&self.record);
        let key = host.host_device_id.to_string();
        let held = record
            .hosts
            .get(&key)
            .and_then(|kept| kept.sender_record_id);
        let id = held.unwrap_or_else(|| PushSenderRecordId::new(kr_ipc::new_uuid()));
        if held.is_none() {
            let now = (self.wiring.clock)();
            let entry = record.hosts.entry(key).or_insert_with(|| HostPush {
                sender_record_id: None,
                phase: Phase::Working,
                words: String::new(),
                settings: false,
                updated_ms: now,
            });
            entry.sender_record_id = Some(id);
            self.keep(&record);
        }
        id
    }

    /// Sets where a host's notifications stand, keeps it and tells the page.
    fn set(
        &self,
        host: &PairedHost,
        phase: Phase,
        words: &str,
        sender: Option<PushSenderRecordId>,
    ) {
        self.set_with(host, phase, words, false, sender);
    }

    /// Sets a host's notifications to stopped, for the reason a sequence ended with.
    fn set_stopped(&self, host: &PairedHost, stop: &Stop) {
        self.set_with(host, Phase::Attention, &stop.words, stop.settings, None);
    }

    fn set_with(
        &self,
        host: &PairedHost,
        phase: Phase,
        words: &str,
        settings: bool,
        sender: Option<PushSenderRecordId>,
    ) {
        let now = (self.wiring.clock)();
        {
            let mut record = lock(&self.record);
            let entry = record
                .hosts
                .entry(host.host_device_id.to_string())
                .or_insert_with(|| HostPush {
                    sender_record_id: None,
                    phase,
                    words: String::new(),
                    settings: false,
                    updated_ms: now,
                });
            entry.phase = phase;
            entry.words = words.to_owned();
            entry.settings = settings;
            entry.updated_ms = now;
            if sender.is_some() {
                entry.sender_record_id = sender;
            }
            self.keep(&record);
        }
        (self.changed)();
    }

    /// Writes the record whole. A failure is logged and not raised: what the person sees is the
    /// memory, and the next change writes it again.
    fn keep(&self, record: &Record) {
        let Some(directory) = self.file.parent() else {
            return;
        };
        if let Err(error) = kr_ipc::paths::create_private_directory(directory) {
            tracing::warn!(%error, "the notifications record's directory could not be made");
            return;
        }
        match serde_json::to_vec(&Versioned { record }) {
            Ok(bytes) => {
                if let Err(error) = write_owner_only_file(&self.file, &bytes) {
                    tracing::warn!(%error, "the notifications record could not be written");
                }
            }
            Err(error) => tracing::warn!(%error, "the notifications record could not be encoded"),
        }
    }
}

#[derive(Serialize)]
struct Versioned<'a> {
    #[serde(flatten)]
    record: &'a Record,
}

/// The record on disk, or an empty one when there is none or it is one this build does not read.
fn read_record(file: &Path) -> Record {
    let Ok(Some(bytes)) = read_owner_only_file(file, RECORD_LIMIT) else {
        return Record {
            version: VERSION,
            hosts: BTreeMap::new(),
        };
    };
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if record.version == VERSION => record,
        _ => Record {
            version: VERSION,
            hosts: BTreeMap::new(),
        },
    }
}

/// What a record says when the application starts. A run that was under way then ended with the
/// process, and nothing is running it now, so it is a stop the person can mend and not a state that
/// says it is working for ever. A run that reached an end stays as it was.
fn after_a_restart(mut record: Record, now_ms: u64) -> Record {
    for kept in record.hosts.values_mut() {
        if kept.phase == Phase::Working {
            kept.phase = Phase::Attention;
            "Turning on notifications was interrupted. Try again.".clone_into(&mut kept.words);
            kept.settings = false;
            kept.updated_ms = now_ms;
        }
    }
    record
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

    fn token_changed(&self) -> PushFuture<'_, bool> {
        Box::pin(async move {
            companion_platform::notify::token_changed(&self.0)
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

    fn limited_key<'a>(
        &'a self,
        recipient_key_id: &'a [u8; 32],
        seed: &'a [u8],
    ) -> PushFuture<'a, ()> {
        Box::pin(async move {
            companion_platform::notify::limited_key(&self.0, recipient_key_id, seed)
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

/// The product's way to the host: a connection opened for the host, as the device the host made.
pub struct ConnectionRegistrar(pub Arc<Device>);

impl Registrar for ConnectionRegistrar {
    fn register<'a>(
        &'a self,
        host: &'a PairedHost,
        params: DevicePushRegisterParams,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
    ) -> PushFuture<'a, DevicePushRegisterResult> {
        Box::pin(async move {
            use kr_protocol::envelope::ActionTarget;
            use kr_protocol::method::Method;
            use kr_protocol::sharing::DevicePreviewKeyUpdateParams;

            let connection = crate::connection::Connection::paired(&self.0, host)
                .await
                .map_err(|error| error.message)?;
            let session = connection.session();
            let target = ActionTarget::environment(connection.environment_id());
            let settled = session
                .mutate(
                    Method::DevicePushRegister,
                    target.clone(),
                    None,
                    &crate::commands::NoPreconditions {},
                    &params,
                    crate::commands::MUTATION_TTL,
                )
                .await
                .map_err(|error| CommandError::from(error).message)?;
            let registered: DevicePushRegisterResult = match settled {
                kr_client::Settled::Result(value) => value
                    .to_typed()
                    .map_err(|_| "its answer was not one this phone reads".to_owned())?,
                kr_client::Settled::Receipt(_) => {
                    return Err("it did not say it had taken the registration".to_owned());
                }
            };
            // The key the host seals previews to is the one it recorded when this phone paired. The
            // call says the phone holds it and at which revision: the same key at the same revision
            // is answered as already recorded, and any other is refused rather than taken.
            session
                .mutate(
                    Method::DevicePreviewKeyUpdate,
                    target,
                    None,
                    &crate::commands::NoPreconditions {},
                    &DevicePreviewKeyUpdateParams {
                        device_id: host.device_id,
                        notification_preview: preview_key,
                        revision: DeviceKeyRevision::new(1),
                    },
                    crate::commands::MUTATION_TTL,
                )
                .await
                .map_err(|error| CommandError::from(error).message)?;
            Ok(registered)
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
        assert_eq!(working.updated_ms, 99);
        assert_eq!(
            working.sender_record_id,
            Some(kept_id),
            "asking again issues under the authorisation this phone already has"
        );
        assert_eq!(started.hosts["on"], on);
        assert_eq!(started.hosts["stopped"], stopped);
    }
}
