//! Revoking a device on a host this computer owns, and what each host says it did about it.
//!
//! A person who owns a host can take a device's pairing away from here. Two routes lead to the host,
//! and the host a request is for decides which:
//!
//! * **The host on this computer** takes `device.revoke` over a connection it admits now: it
//!   withdraws the ones it admitted before each revocation, so this computer opens another and sends
//!   over the one it already holds only when no other opens. The method is the local owner's alone,
//!   so a paired device never sends it, and the host's answer, with the state of its dispatch
//!   barrier, is the acknowledgement.
//! * **A host this computer is paired with as an owner** is reached through its authority feed. This
//!   computer signs a revocation request with its authorisation key, publishes it at the sync service
//!   it is set to use, and the host reads it at its next poll, carries it out and acknowledges it in
//!   the same feed. Nothing is sent to the host itself.
//!
//! # What is shown, and when it is called done
//!
//! A revocation is done when the host's acknowledgement has been read and says the host's dispatch
//! barrier held. A request that sits in the feed is **sent**, and the screen says only that; one the
//! host acknowledged while some of its session workers have not confirmed the fence is **acknowledged**
//! and says how many; a request the host refused is **refused** and says why. The acknowledgements are read
//! from the feed, which stores them and judges nothing: they are the service's word for what the
//! host answered, not something this computer can check.
//!
//! # Which feed
//!
//! The feed is addressed by the identifier of the host's own authorisation key at the service the
//! host reads its revocations from, and that service is a setting of the host's own which no answer
//! of its states. This computer therefore publishes every request at the sync service it is set to
//! use, and says which. A host that reads another service never sees the request: it stays **sent**
//! and the host never acknowledges it, so a wrong service cannot look like success. A host the feed
//! answers that it removed is not reachable by feed, and nothing is published for it.
//!
//! # Who may ask
//!
//! The page names a host and a device by references this computer gave it; it holds no key, no
//! identifier and no request. Every revocation asks the person through the platform's ceremony
//! first, with what it would do as its reason; a computer with no ceremony revokes nothing.
//!
//! # Settings sync
//!
//! Before a revocation leaves, settings sync is told to hold everything it sends until the device
//! is out of the shared settings, and a revocation whose hold cannot be written down is not sent.
//! Once the request has been sent, whatever becomes of it, settings sync takes the device out in a
//! step of its own, without waiting for any host to acknowledge it: a request that failed may have
//! reached its host all the same. What settings sync was sending is held too, a step already under
//! way included, so nothing written after the revocation is sealed under a key the device holds. A
//! device that a view finds revoked by this computer's own signature in a host's feed, or listed as
//! revoked by the host on this computer, whoever revoked it, is passed to settings sync the same
//! way. A send already on its way cannot be called back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome, shown, shown_host};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::authority::{
    AuthorityFeedClient, AuthorityFeedRecord, AuthorityFeedSummary, RejectionReason,
};
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{DeviceId, RevocationRequestId};
use kr_protocol::method::Method;
use kr_protocol::pairing::{DevicePlatform, KeyPurpose, RevocationCompletion, RevocationTarget};
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, KeyId};
use kr_protocol::service::GatewayOrigin;
use kr_protocol::sharing::{DeviceListResult, DeviceRevokeParams, DeviceSummary, RevocationResult};
use serde::Serialize;
use sha2::Digest as _;

use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::connection::{Connection, Standing};
use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::recovery::{DeviceSigner, now};
use crate::settings::Settings;
use crate::settings::connected::{ANSWER_WITHIN, Listing, listed};
use crate::sync_service::host_of;

/// How long the person is given at the ceremony.
const CONFIRM_WITHIN: Duration = Duration::from_secs(90);

/// How long a view gives one feed, page after page.
const FEED_WITHIN: Duration = Duration::from_secs(20);

/// The most pages of one feed a view reads: more records than that are more than this computer
/// publishes.
const FEED_PAGES: usize = 16;

/// The most characters of a name the screen shows.
const NAME_CHARS: usize = 40;

/// What the screen calls the host on this computer.
const THIS_COMPUTER: &str = "This computer";

/// What a device is called when its host gave it no name to show.
const UNNAMED_DEVICE: &str = "a device";

/// Where a revocation request for a host is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// To the host on this computer, which takes the revocation itself and answers with it.
    Direct,
    /// To the host's feed at the sync service, which the host reads and answers in.
    Feed,
}

/// Whether a host answered when asked for its devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Contact {
    /// It listed its devices.
    Answered,
    /// It will not list them to this computer, as a host does once the grant that gave the right
    /// has run out or been revoked.
    Refused,
    /// It did not answer in time or could not be reached.
    Silent,
}

/// What the screen is shown of every host this computer can revoke devices on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationView {
    /// The ceremony this computer asks the person to confirm with, which names the control. Without
    /// one it revokes nothing.
    pub ceremony: CeremonyKind,
    /// The service a request for a paired host is published at, as its host name and port. Null
    /// when this computer has no sync service setting to publish at.
    pub feed_origin: Option<String>,
    /// The hosts, the one on this computer first.
    pub hosts: Vec<HostView>,
}

/// One host, with its devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostView {
    /// What a command names the host by.
    pub reference: String,
    /// What it is called.
    pub name: String,
    /// How a request reaches it.
    pub route: Route,
    /// Whether it listed its devices just now.
    pub contact: Contact,
    /// When the devices below were listed, in UTC milliseconds. A host that did not answer shows
    /// the list it gave the last time this application asked, or none.
    pub listed_at_ms: Option<u64>,
    /// When the host says it last read its feed, in UTC milliseconds.
    pub host_synchronised_at_ms: Option<u64>,
    /// Whether the host says it could not reach its feed at its last attempt.
    pub host_feed_stale: bool,
    /// The host's devices.
    pub devices: Vec<DeviceView>,
    /// The host's feed as this computer read it, for a host reached through one.
    pub feed: Option<FeedView>,
}

/// A host's feed, as this computer read it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FeedView {
    /// Whether the feed was read just now.
    pub read: bool,
    /// Why it was not, in words.
    pub problem: Option<String>,
    /// Whether the feed answers that the host was removed from it. Nothing reaches such a host by
    /// feed.
    pub removed: bool,
    /// Whether the host has written anything in this feed: a revision or an acknowledgement. A host
    /// that has applied no request yet has not, and neither has one that reads another service.
    pub host_wrote_here: bool,
    /// The host's last acknowledgement, whatever it was about.
    pub last_acknowledgement: Option<Acknowledged>,
    /// How many requests wait for the host.
    pub outstanding: u64,
    /// How often a host reads its feed while it is online, in seconds, as the feed states it.
    pub poll_interval_seconds: Option<u32>,
}

/// What the feed holds of a host's last acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Acknowledged {
    /// When the host acknowledged, in UTC milliseconds.
    pub at_ms: u64,
    /// The authority revision it issued.
    pub revision: u64,
    /// How many session workers had not confirmed the fence yet, when the acknowledgement was made.
    pub pending_workers: Option<u64>,
}

/// One device of a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceView {
    /// What a command names the device by.
    pub reference: String,
    /// What it is called.
    pub name: String,
    /// What it says it runs on.
    pub platform: DevicePlatform,
    /// Whether it holds the right to manage the host.
    pub manages_host: bool,
    /// Whether it is this computer, which does not revoke itself.
    pub this_computer: bool,
    /// Where its revocation stands.
    pub standing: DeviceStanding,
}

/// Where a device's revocation stands. A revocation is done only in [`Self::Done`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceStanding {
    /// Nothing was asked of it.
    Active,
    /// The host lists it as revoked, and no request this computer sent is known to have done it.
    Revoked,
    /// This computer published a request and the host has not acknowledged it.
    Sent {
        /// When the feed stored it, in UTC milliseconds.
        at_ms: u64,
        /// Whether the host already lists the device as revoked.
        host_lists_revoked: bool,
    },
    /// The host acknowledged, and either some of its session workers have not confirmed the fence
    /// yet or its own list does not show the device as revoked.
    Acknowledged {
        /// When the host acknowledged, in UTC milliseconds.
        at_ms: u64,
        /// How many workers have not, when the host said. Null when the host has not yet said that every
        /// worker confirmed, and did not say how many have not.
        pending_workers: Option<u64>,
        /// Whether the host's own list shows the device as revoked. False only for a host that
        /// answered just now and does not list the device as revoked: it contradicts what the feed
        /// says, so the device is to be revoked at the host itself.
        host_lists_revoked: bool,
    },
    /// The host acknowledged, and every session worker confirmed the fence.
    Done {
        /// When the host acknowledged, in UTC milliseconds.
        at_ms: u64,
    },
    /// The host refused the request.
    Refused {
        /// Why.
        reason: RejectionReason,
    },
}

/// What this application knows of the hosts between two views.
#[derive(Default)]
struct Memory {
    /// What each host last listed, by the reference the page knows it by.
    listed: BTreeMap<String, Listed>,
    /// What the host on this computer answered to this computer's revocations.
    direct: BTreeMap<DeviceId, Direct>,
    /// The devices that settings sync has been told of, or is being told of.
    fed: BTreeSet<AuthorisationKey>,
    /// The revocations being asked for, by host and device reference, so that a second call for one
    /// of them waits for neither the ceremony nor the request and sends nothing.
    revoking: BTreeSet<String>,
}

/// A revocation being asked for, which stops being so when this goes, however the call ends.
struct InFlight {
    memory: Arc<Mutex<Memory>>,
    key: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.memory
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .revoking
            .remove(&self.key);
    }
}

/// A host's devices as last listed.
#[derive(Clone)]
struct Listed {
    devices: Vec<DeviceSummary>,
    at_ms: u64,
}

/// What the host on this computer answered to a revocation.
#[derive(Clone, Copy)]
enum Direct {
    /// Every session worker it affects confirmed the fence.
    Done { at_ms: u64 },
    /// It recorded the revocation, and some workers have not confirmed the fence. It says how many
    /// when it can.
    Pending { at_ms: u64, workers: Option<u64> },
}

/// What a view and a command are told of this application beyond this computer's records.
pub struct Context {
    /// The connection to the host on this computer, when the application holds one.
    pub local: Option<Connection>,
    /// The sync service a request for a paired host is published at.
    pub origin: Option<GatewayOrigin>,
    /// Settings sync, which is told of a device whose revocation this computer sent.
    pub settings: Option<Arc<Settings>>,
}

/// A host a request can be for.
#[derive(Clone)]
enum Host {
    /// The host on this computer, reached over the connection the application holds to it.
    Local(Connection),
    /// A host this computer is paired with as an owner.
    Paired(Box<PairedHost>),
}

impl Host {
    fn reference(&self) -> String {
        match self {
            Self::Local(connection) => digest(&[
                b"kalareach local host reference",
                connection.environment_id().to_string().as_bytes(),
            ]),
            Self::Paired(host) => crate::device::hosts::reference_of(host),
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Local(_) => THIS_COMPUTER.to_owned(),
            Self::Paired(host) => shown_host(host.name.as_deref().unwrap_or(""), NAME_CHARS),
        }
    }

    const fn route(&self) -> Route {
        match self {
            Self::Local(_) => Route::Direct,
            Self::Paired(_) => Route::Feed,
        }
    }
}

/// A request made ready to leave.
enum Prepared {
    /// To the host on this computer, over a connection it admits now.
    Direct(Connection),
    /// To a host's feed.
    Feed {
        client: Box<AuthorityFeedClient>,
        feed: KeyId,
        request: kr_protocol::pairing::RevocationRequest,
    },
}

/// What a digest of `parts` is called to the page: its first twelve bytes in hexadecimal.
fn digest(parts: &[&[u8]]) -> String {
    let mut hash = sha2::Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize()[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What a command names a device on the host `host` by.
fn device_reference(host: &str, device: DeviceId) -> String {
    digest(&[host.as_bytes(), device.to_string().as_bytes()])
}

/// What a device is called on the screen.
fn device_name(summary: &DeviceSummary) -> String {
    let name = shown(&summary.display_name, NAME_CHARS);
    if name.is_empty() {
        UNNAMED_DEVICE.to_owned()
    } else {
        name
    }
}

/// What a visit to one host found.
struct Reading {
    host: Host,
    contact: Contact,
    list: Option<DeviceListResult>,
    /// The feed, for a host reached through one.
    feed: Option<std::result::Result<FeedRead, String>>,
}

/// What a feed holds for one host, as its publisher reads it.
struct FeedRead {
    records: Vec<AuthorityFeedRecord>,
    summary: AuthorityFeedSummary,
}

/// A request in a feed that is this computer's own.
struct Verified<'a> {
    record: &'a AuthorityFeedRecord,
    devices: BTreeSet<DeviceId>,
}

/// This computer's revocations of devices on the hosts it owns.
pub struct Revocations {
    device: Arc<Device>,
    ceremony: Arc<dyn Ceremony>,
    memory: Arc<Mutex<Memory>>,
}

impl std::fmt::Debug for Revocations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Revocations")
            .field("ceremony", &self.ceremony.kind())
            .finish_non_exhaustive()
    }
}

impl Revocations {
    /// The revocations of `device`'s hosts, confirmed through `ceremony`.
    #[must_use]
    pub fn new(device: Arc<Device>, ceremony: Arc<dyn Ceremony>) -> Arc<Self> {
        Arc::new(Self {
            device,
            ceremony,
            memory: Arc::new(Mutex::new(Memory::default())),
        })
    }

    fn memory(&self) -> MutexGuard<'_, Memory> {
        self.memory.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every host a request can be for: the one on this computer, then the hosts this computer owns.
    fn hosts(&self, context: &Context) -> Vec<Host> {
        let mut hosts = Vec::new();
        if let Some(connection) = &context.local
            && matches!(connection.standing(), Standing::Owner)
        {
            hosts.push(Host::Local(connection.clone()));
        }
        hosts.extend(
            self.device
                .owner_hosts()
                .into_iter()
                .map(|host| Host::Paired(Box::new(host))),
        );
        hosts
    }

    /// The client for the feed service at `origin`, signing as this computer.
    fn feed_client(&self, origin: &GatewayOrigin) -> Result<AuthorityFeedClient> {
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
        Ok(AuthorityFeedClient::new(
            origin.clone(),
            Arc::new(http),
            Arc::new(DeviceSigner::new(
                self.device.identity().keys.authorisation.clone(),
            )),
        ))
    }

    /// This computer's authorisation key, which signs the requests it publishes.
    fn key(&self) -> AuthorisationKey {
        *self.device.identity().keys.authorisation.public()
    }

    /// Asks `hosts` for their devices and their feeds, all at once, so that a host that is asleep
    /// keeps the others waiting for one wait and not for each.
    async fn read(&self, hosts: Vec<Host>, context: &Context) -> Vec<Reading> {
        let client = context
            .origin
            .as_ref()
            .map(|origin| self.feed_client(origin).map_err(|error| error.message));
        let visits: Vec<_> = hosts
            .into_iter()
            .map(|host| {
                tauri::async_runtime::spawn(visit(Arc::clone(&self.device), host, client.clone()))
            })
            .collect();
        let mut readings = Vec::new();
        for visit in visits {
            if let Ok(reading) = visit.await {
                readings.push(reading);
            }
        }
        readings
    }

    /// What the screen is shown. Every host is asked, and so is every feed.
    pub async fn view(&self, context: &Context) -> RevocationView {
        let readings = self.read(self.hosts(context), context).await;
        let mut told = Vec::new();
        let hosts = readings
            .into_iter()
            .map(|reading| self.host_view(&reading, &mut told))
            .collect();
        self.tell(context, told);
        RevocationView {
            ceremony: self.ceremony.kind(),
            feed_origin: context.origin.as_ref().map(host_of),
            hosts,
        }
    }

    /// Passes the devices of revocations to settings sync, which holds what it sends at once and
    /// takes the devices out of the shared settings in a step of its own, without waiting for a
    /// host to confirm: the devices a request just sent names, whether it succeeded or not, and
    /// those a view finds this computer sent or a host on this computer lists as revoked. All the
    /// devices of one view go in one call. It runs on its own, so that a service that is slow to
    /// answer does not hold the screen.
    fn tell(&self, context: &Context, told: Vec<AuthorisationKey>) {
        let Some(settings) = &context.settings else {
            return;
        };
        let devices: Vec<AuthorisationKey> = {
            let mut memory = self.memory();
            told.into_iter()
                .filter(|device| memory.fed.insert(*device))
                .collect()
        };
        if devices.is_empty() {
            return;
        }
        let (settings, memory) = (Arc::clone(settings), Arc::clone(&self.memory));
        tauri::async_runtime::spawn(async move {
            // Told only when the membership recorded it: a computer that shares no settings yet is
            // told again at the next view, which a collection it joins since needs.
            if !matches!(settings.revocations_sent(&devices).await, Ok(true)) {
                let mut memory = memory.lock().unwrap_or_else(PoisonError::into_inner);
                for device in &devices {
                    memory.fed.remove(device);
                }
            }
        });
    }

    /// One host's view. The keys of the devices that settings sync has not heard of, and that this
    /// computer sent a request for or the host on this computer lists as revoked, go in `told`.
    fn host_view(&self, reading: &Reading, told: &mut Vec<AuthorisationKey>) -> HostView {
        let reference = reading.host.reference();
        let (devices, listed_at_ms, direct, fed) = {
            let mut memory = self.memory();
            if let Some(list) = &reading.list {
                memory.listed.insert(
                    reference.clone(),
                    Listed {
                        devices: list.devices.clone(),
                        at_ms: now().get(),
                    },
                );
            } else if reading.contact == Contact::Refused {
                // A host that will not list its devices to this computer says nothing of them, and
                // what it listed before is no longer what it lists.
                memory.listed.remove(&reference);
            }
            let (devices, at_ms) = memory
                .listed
                .get(&reference)
                .map_or((Vec::new(), None), |held| {
                    (held.devices.clone(), Some(held.at_ms))
                });
            (devices, at_ms, memory.direct.clone(), memory.fed.clone())
        };
        let own = self.verified(reading);
        let this_computer = match &reading.host {
            Host::Paired(host) => Some(host.device_id),
            Host::Local(_) => None,
        };
        let rows = devices
            .iter()
            .map(|summary| {
                let named: Vec<&Verified<'_>> = own
                    .iter()
                    .filter(|request| request.devices.contains(&summary.device_id))
                    .collect();
                // A request of this computer's own that the feed holds and the host has not refused,
                // or a device the host on this computer, which answered just now, lists as revoked.
                let listed_revoked = summary.revoked
                    && reading.list.is_some()
                    && matches!(reading.host, Host::Local(_));
                if let Some(keys) = summary.keys.0
                    && !fed.contains(&keys.authorisation)
                    && (listed_revoked
                        || named
                            .iter()
                            .any(|request| request.record.rejected.0.is_none()))
                {
                    told.push(keys.authorisation);
                }
                DeviceView {
                    reference: device_reference(&reference, summary.device_id),
                    name: device_name(summary),
                    platform: summary.platform,
                    manages_host: summary.manages_host,
                    this_computer: this_computer == Some(summary.device_id),
                    standing: standing(
                        summary,
                        &named,
                        direct.get(&summary.device_id).copied(),
                        reading.host.route(),
                        reading.contact == Contact::Answered,
                    ),
                }
            })
            .collect();
        HostView {
            reference,
            name: reading.host.name(),
            route: reading.host.route(),
            contact: reading.contact,
            listed_at_ms,
            host_synchronised_at_ms: reading
                .list
                .as_ref()
                .and_then(|list| list.feed_synchronised_at_ms.0)
                .map(|at| at.get()),
            host_feed_stale: reading.list.as_ref().is_some_and(|list| list.feed_stale),
            devices: rows,
            feed: reading.feed.as_ref().map(|feed| feed_view(feed, reading)),
        }
    }

    /// The requests in a host's feed that are this computer's own.
    fn verified<'a>(&self, reading: &'a Reading) -> Vec<Verified<'a>> {
        match (&reading.host, &reading.feed) {
            (Host::Paired(host), Some(Ok(feed))) => own_requests(
                &feed.records,
                host.device_id,
                host.host_device_id,
                &self.key(),
            ),
            _ => Vec::new(),
        }
    }

    /// Revokes the device `device` names on the host `host` names, once the person confirms it
    /// here, and says what the screen then shows.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no such host or device is listed, when the device is this computer,
    /// when it is revoked already, when the host is not reachable by feed, or when the person did
    /// not confirm; and what stopped the request otherwise. A device a request already waits for
    /// is not sent for again: the screen shows where that request stands.
    pub async fn revoke(
        &self,
        context: &Context,
        host: &str,
        device: &str,
    ) -> Result<RevocationView> {
        let found = self
            .hosts(context)
            .into_iter()
            .find(|each| each.reference() == host)
            .ok_or_else(|| {
                CommandError::refused("that host is not one this computer can revoke on")
            })?;
        // One revocation of a device at a time: a second call for it, from a second window or
        // while the person is at the ceremony, sends nothing and asks nobody.
        let key = format!("{host}/{device}");
        if !self.memory().revoking.insert(key.clone()) {
            return Ok(self.view(context).await);
        }
        let _in_flight = InFlight {
            memory: Arc::clone(&self.memory),
            key,
        };
        let readings = self.read(vec![found.clone()], context).await;
        let reading = readings
            .first()
            .ok_or_else(|| CommandError::unavailable("the host was not asked"))?;
        let host_now = self.host_view(reading, &mut Vec::new());
        let chosen = host_now
            .devices
            .iter()
            .find(|each| each.reference == device)
            .ok_or_else(|| CommandError::refused("that device is not listed by that host"))?;
        let summary = self
            .memory()
            .listed
            .get(&host_now.reference)
            .and_then(|held| {
                held.devices.iter().find(|summary| {
                    device_reference(&host_now.reference, summary.device_id) == device
                })
            })
            .cloned()
            .ok_or_else(|| CommandError::refused("that device is not listed by that host"))?;
        if chosen.this_computer {
            return Err(CommandError::refused(
                "this computer does not revoke itself; do it from another owner's computer, or \
                 at the host",
            ));
        }
        // A question about a revocation the person already confirmed is not a new revocation.
        let mut asked_again = false;
        match (chosen.standing, found.route()) {
            (DeviceStanding::Done { .. } | DeviceStanding::Revoked, _) => {
                return Err(CommandError::refused("that device is revoked already"));
            }
            // A request waits for the host, or the host is finishing it: sending another would
            // only send the same request twice. The screen shows where it stands.
            (DeviceStanding::Sent { .. } | DeviceStanding::Acknowledged { .. }, Route::Feed) => {
                return Ok(self.view(context).await);
            }
            (DeviceStanding::Acknowledged { .. }, Route::Direct) => asked_again = true,
            (DeviceStanding::Active | DeviceStanding::Refused { .. }, _)
            | (DeviceStanding::Sent { .. }, Route::Direct) => {}
        }
        if found.route() == Route::Direct && host_now.contact != Contact::Answered {
            return Err(CommandError::unavailable(
                "the host on this computer did not answer, so nothing was sent",
            ));
        }
        if let Some(feed) = &host_now.feed {
            if feed.removed {
                return Err(CommandError::refused(
                    "the feed has removed that host, so nothing published there reaches it; \
                     revoke the device at the host",
                ));
            }
            if !feed.read {
                return Err(CommandError::unavailable(format!(
                    "the sync service did not answer, so nothing was sent: {}",
                    feed.problem.as_deref().unwrap_or("it could not be read")
                )));
            }
        }
        if !asked_again {
            self.confirmed(&format!("Revoke {} on {}", chosen.name, host_now.name))
                .await?;
        }
        // What can fail without a request having left is done first, so that nothing after the
        // hold is known not to have left.
        let prepared = self.prepare(&found, context, &summary).await?;
        // Settings sync holds everything it sends before the request leaves, so that nothing is
        // sealed under a key the device holds from the moment the host acts. A record that cannot
        // be written sends nothing.
        let keys: Vec<AuthorisationKey> = summary
            .keys
            .0
            .iter()
            .map(|keys| keys.authorisation)
            .collect();
        let settings = context.settings.as_ref().filter(|_| !keys.is_empty());
        if let Some(settings) = settings {
            settings.hold_for_revocation(&keys).map_err(|error| {
                CommandError::local_failure(format!(
                    "nothing was sent, because this computer could not hold its settings back \
                     first: {}",
                    error.message
                ))
            })?;
        }
        // Whether there are settings the device is taken out of, to say so truthfully.
        let shared = settings.is_some_and(|settings| settings.shares_settings());
        let sent = self.dispatch(prepared, &summary).await;
        // Told at once, and not at the end of the view that follows, which waits for every host and
        // every feed. A request that failed may have reached its host all the same, a reply being
        // lost, so it is told as one that left: the device is out of the shared settings.
        if settings.is_some() {
            self.tell(context, keys);
        }
        match sent {
            Ok(()) => Ok(self.view(context).await),
            Err(mut error) if shared => {
                if !error.message.ends_with('.') {
                    error.message.push('.');
                }
                error.message.push_str(
                    " This computer no longer shares its settings with that device, because the \
                     request may have reached the host.",
                );
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Does what a request needs before it leaves and that can fail without it having left.
    async fn prepare(
        &self,
        host: &Host,
        context: &Context,
        device: &DeviceSummary,
    ) -> Result<Prepared> {
        match host {
            Host::Local(connection) => {
                // The host withdraws the connections it admitted before each revocation, and the
                // person took their time: the revocation goes over one it admits now.
                let fresh = tokio::time::timeout(ANSWER_WITHIN, connection.another()).await;
                Ok(Prepared::Direct(match fresh {
                    Ok(Ok(fresh)) => fresh,
                    _ => connection.clone(),
                }))
            }
            Host::Paired(paired) => {
                let origin = context.origin.as_ref().ok_or_else(|| {
                    CommandError::refused("this computer has no sync service to publish at")
                })?;
                let request = kr_pairing::grants::sign_revocation_request(
                    &self.device.identity().keys.authorisation,
                    RevocationRequestId::new(kr_ipc::new_uuid()),
                    paired.device_id,
                    paired.host_device_id,
                    RevocationTarget::Devices {
                        device_ids: CanonicalSet::from_iter([device.device_id]),
                    },
                    now(),
                )
                .map_err(|error| {
                    CommandError::local_failure(format!("the request could not be signed: {error}"))
                })?;
                Ok(Prepared::Feed {
                    client: Box::new(self.feed_client(origin)?),
                    feed: feed_of(paired),
                    request,
                })
            }
        }
    }

    /// Sends what [`Self::prepare`] made ready. From here a failure says nothing of whether the
    /// request left.
    async fn dispatch(&self, prepared: Prepared, device: &DeviceSummary) -> Result<()> {
        match prepared {
            Prepared::Direct(over) => self.revoke_direct(&over, device).await,
            Prepared::Feed {
                client,
                feed,
                request,
            } => {
                client
                    .publish(feed, &request, None)
                    .await
                    .map_err(CommandError::from)?;
                Ok(())
            }
        }
    }

    /// Asks the person through the platform's ceremony, with `reason` as what the dialog says.
    async fn confirmed(&self, reason: &str) -> Result<()> {
        match self.ceremony.verify(reason, CONFIRM_WITHIN).await {
            CeremonyOutcome::Confirmed => Ok(()),
            CeremonyOutcome::NotConfirmed => Err(CommandError::refused(
                "it was not confirmed, so nothing was changed",
            )),
            CeremonyOutcome::Unavailable => Err(CommandError::unsupported(
                "this computer has no way to ask you to confirm, so it revokes nothing",
            )),
        }
    }

    /// The host on this computer takes the revocation itself, and what it answers is kept.
    async fn revoke_direct(&self, connection: &Connection, device: &DeviceSummary) -> Result<()> {
        let settled = connection
            .session()
            .mutate(
                Method::DeviceRevoke,
                ActionTarget::environment(connection.environment_id()),
                None,
                &NoPreconditions {},
                &DeviceRevokeParams {
                    device_id: device.device_id,
                },
                MUTATION_TTL,
            )
            .await
            .map_err(CommandError::from)?;
        let at_ms = now().get();
        let answer = match &settled {
            kr_client::Settled::Result(value) => {
                let revoked: RevocationResult = value.to_typed().map_err(|error| {
                    CommandError::local_failure(format!(
                        "the host's answer was not the revocation's own result: {error}"
                    ))
                })?;
                match revoked.barrier.pending().len() {
                    0 => Direct::Done { at_ms },
                    workers => Direct::Pending {
                        at_ms,
                        workers: Some(workers as u64),
                    },
                }
            }
            // The host settled it with a receipt: it recorded the revocation and has not said
            // that every worker confirmed the fence.
            kr_client::Settled::Receipt(_) => Direct::Pending {
                at_ms,
                workers: None,
            },
        };
        self.memory().direct.insert(device.device_id, answer);
        Ok(())
    }
}

/// The identifier of the feed a host's requests are published in: its authorisation key's.
fn feed_of(host: &PairedHost) -> KeyId {
    kr_protocol::pairing::key_id(
        KeyPurpose::Authorisation,
        host.host_keys.authorisation.as_bytes(),
    )
}

/// The records of a feed that are this computer's own, naming devices: published by `key`, issued as
/// the device `issuer` this computer is on the host `host`, and signed as they say. A feed judges no
/// owner's authority, so what it says a record is does not make it this computer's.
fn own_requests<'a>(
    records: &'a [AuthorityFeedRecord],
    issuer: DeviceId,
    host: DeviceId,
    key: &AuthorisationKey,
) -> Vec<Verified<'a>> {
    records
        .iter()
        .filter(|record| record.published_by == *key)
        .filter(|record| record.request.issuer_device_id == issuer)
        .filter(|record| {
            kr_pairing::grants::verify_revocation_request(&record.request, host, key).is_ok()
        })
        .filter_map(|record| match &record.request.target {
            RevocationTarget::Devices { device_ids } => Some(Verified {
                record,
                devices: device_ids.into_iter().copied().collect(),
            }),
            RevocationTarget::Grants { .. } => None,
        })
        .collect()
}

/// Where a device's revocation stands, from what the host lists of it, the requests this computer
/// sent for it, and what the host on this computer answered.
fn standing(
    device: &DeviceSummary,
    requests: &[&Verified<'_>],
    direct: Option<Direct>,
    route: Route,
    host_answered: bool,
) -> DeviceStanding {
    if route == Route::Direct {
        return match direct {
            Some(Direct::Done { at_ms }) if device.revoked => DeviceStanding::Done { at_ms },
            Some(Direct::Pending { at_ms, workers }) if device.revoked => {
                DeviceStanding::Acknowledged {
                    at_ms,
                    pending_workers: workers,
                    host_lists_revoked: true,
                }
            }
            _ if device.revoked => DeviceStanding::Revoked,
            _ => DeviceStanding::Active,
        };
    }
    // The furthest any request for the device has got: acknowledged complete, acknowledged with
    // workers yet to confirm the fence, waiting in the feed, refused.
    let mut furthest: Option<(u8, DeviceStanding)> = None;
    for request in requests {
        let record = request.record;
        let (rank, standing) = if let Some(reason) = record.rejected.0 {
            (1, DeviceStanding::Refused { reason })
        } else {
            match &record.acknowledgement.0 {
                Some(acknowledgement)
                    if acknowledgement.request_id == record.request.request_id =>
                {
                    let at_ms = acknowledgement.acknowledged_at_ms.get();
                    match acknowledgement.completion {
                        // The feed's word that the host finished is not the host's own: a host that
                        // answers just now and does not list the device as revoked has not said so.
                        RevocationCompletion::Complete if host_answered && !device.revoked => (
                            3,
                            DeviceStanding::Acknowledged {
                                at_ms,
                                pending_workers: None,
                                host_lists_revoked: false,
                            },
                        ),
                        RevocationCompletion::Complete => (4, DeviceStanding::Done { at_ms }),
                        RevocationCompletion::Pending { pending_workers } => (
                            3,
                            DeviceStanding::Acknowledged {
                                at_ms,
                                pending_workers: Some(pending_workers.get()),
                                host_lists_revoked: device.revoked || !host_answered,
                            },
                        ),
                    }
                }
                _ => (
                    2,
                    DeviceStanding::Sent {
                        at_ms: record.published_at_ms.get(),
                        host_lists_revoked: device.revoked,
                    },
                ),
            }
        };
        if furthest.is_none_or(|(held, _)| rank > held) {
            furthest = Some((rank, standing));
        }
    }
    match furthest {
        Some((rank, standing)) if rank > 1 => standing,
        // A refusal of a request for a device the host lists as revoked changes nothing: it is
        // revoked, and not by this computer's request.
        Some((_, refused)) if !device.revoked => refused,
        _ if device.revoked => DeviceStanding::Revoked,
        _ => DeviceStanding::Active,
    }
}

/// A feed as the screen is told of it.
fn feed_view(feed: &std::result::Result<FeedRead, String>, reading: &Reading) -> FeedView {
    let removed_by_host = reading.list.as_ref().is_some_and(|list| list.feed_removed);
    match feed {
        Ok(read) => FeedView {
            read: true,
            problem: None,
            removed: read.summary.removed || removed_by_host,
            host_wrote_here: read.summary.authority_revision.0.is_some()
                || read.summary.last_acknowledgement.0.is_some(),
            last_acknowledgement: read.summary.last_acknowledgement.0.as_ref().map(|last| {
                Acknowledged {
                    at_ms: last.acknowledged_at_ms.get(),
                    revision: last.authority_revision.get(),
                    pending_workers: match last.completion {
                        RevocationCompletion::Pending { pending_workers } => {
                            Some(pending_workers.get())
                        }
                        RevocationCompletion::Complete => None,
                    },
                }
            }),
            outstanding: read.summary.outstanding.get(),
            poll_interval_seconds: Some(read.summary.poll_interval_seconds),
        },
        Err(problem) => FeedView {
            read: false,
            problem: Some(problem.clone()),
            removed: removed_by_host,
            host_wrote_here: false,
            last_acknowledgement: None,
            outstanding: 0,
            poll_interval_seconds: None,
        },
    }
}

/// One visit to a host: its devices, and for a host reached through a feed, the feed.
async fn visit(
    device: Arc<Device>,
    host: Host,
    client: Option<std::result::Result<AuthorityFeedClient, String>>,
) -> Reading {
    let (listing, feed) = match &host {
        Host::Local(connection) => {
            let mut listing = listed(&connection.session()).await;
            // A change of the host's authority, a revocation among them, withdraws the connections
            // it admitted before, and the host says to open a new one. What a fresh connection is
            // answered is the host's word; one that cannot be opened says nothing of the host.
            if matches!(listing, Listing::Refused) {
                listing = match tokio::time::timeout(ANSWER_WITHIN, connection.another()).await {
                    Ok(Ok(fresh)) => listed(&fresh.session()).await,
                    _ => Listing::Silent,
                };
            }
            (listing, None)
        }
        Host::Paired(paired) => {
            let listing = async {
                let pairing = device.pairing();
                let identity = pairing.candidate.paired_identity(paired.device_id);
                let connected = async {
                    match pairing.link.connect_paired(paired, &identity).await {
                        Ok(session) => listed(&Arc::new(session)).await,
                        Err(error) => Listing::of_link(&error),
                    }
                };
                tokio::time::timeout(ANSWER_WITHIN, connected)
                    .await
                    .unwrap_or(Listing::Silent)
            };
            let feed = async {
                match client {
                    Some(Ok(client)) => read_feed(&client, feed_of(paired)).await,
                    Some(Err(problem)) => Err(problem),
                    None => Err("this computer has no sync service setting".to_owned()),
                }
            };
            let (listing, feed) = tokio::join!(listing, feed);
            (listing, Some(feed))
        }
    };
    let (contact, list) = match listing {
        Listing::Listed(list) => (Contact::Answered, Some(list)),
        Listing::Refused => (Contact::Refused, None),
        Listing::Silent => (Contact::Silent, None),
    };
    Reading {
        host,
        contact,
        list,
        feed,
    }
}

/// Reads a host's feed as its publisher sees it, page after page, within [`FEED_WITHIN`] in all.
async fn read_feed(
    client: &AuthorityFeedClient,
    feed: KeyId,
) -> std::result::Result<FeedRead, String> {
    let read = async {
        let mut records = Vec::new();
        let mut after = None;
        for _ in 0..FEED_PAGES {
            let page = client
                .read(feed, after, false)
                .await
                .map_err(|error| CommandError::from(error).message)?;
            records.extend(page.records);
            if !page.more {
                return Ok(FeedRead {
                    records,
                    summary: page.summary,
                });
            }
            after = Some(page.next_after_sequence.get());
        }
        Err("it holds more requests than this computer reads".to_owned())
    };
    tokio::time::timeout(FEED_WITHIN, read)
        .await
        .unwrap_or_else(|_| Err("it did not answer in time".to_owned()))
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::{AuthorityRevision, GrantId};
    use kr_protocol::pairing::RevocationAcknowledgement;
    use kr_protocol::scalars::{Nullable, Signature64, TimestampMs, U64, Uuid};

    use super::*;

    fn id(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn device(revoked: bool) -> DeviceSummary {
        DeviceSummary {
            device_id: DeviceId::new(id(1)),
            display_name: "a phone".to_owned(),
            grant_id: GrantId::new(id(2)),
            paired_at_ms: TimestampMs::new(1),
            revoked,
            keys: Nullable::null(),
            manages_host: false,
            platform: DevicePlatform::Ios,
            grant_expires_at_ms: Nullable::null(),
            grant_expired: false,
            all_sessions: true,
        }
    }

    /// A request for the device, published at 100, with the host's answer to it.
    fn record(
        number: u8,
        acknowledgement: Option<RevocationCompletion>,
        rejected: Option<RejectionReason>,
    ) -> AuthorityFeedRecord {
        let request_id = RevocationRequestId::new(id(number));
        AuthorityFeedRecord {
            sequence: U64::new(u64::from(number)),
            request: kr_protocol::pairing::RevocationRequest {
                request_id,
                issuer_device_id: DeviceId::new(id(3)),
                host_device_id: DeviceId::new(id(4)),
                target: RevocationTarget::Devices {
                    device_ids: CanonicalSet::from_iter([DeviceId::new(id(1))]),
                },
                issued_at_ms: TimestampMs::new(99),
                issuer_key_id: KeyId::from_bytes([0; 32]),
                signature: Signature64::from_bytes([0; 64]),
            },
            published_by: AuthorisationKey::from_bytes([0; 32]),
            published_at_ms: U64::new(100),
            acknowledgement: Nullable(acknowledgement.map(|completion| {
                RevocationAcknowledgement {
                    request_id,
                    host_device_id: DeviceId::new(id(4)),
                    authority_revision: AuthorityRevision::new(5),
                    completion,
                    acknowledged_at_ms: TimestampMs::new(200),
                }
            })),
            rejected: Nullable(rejected),
        }
    }

    /// What the screen says when the host answered just now.
    fn standing_of(revoked: bool, records: &[AuthorityFeedRecord]) -> DeviceStanding {
        standing_when(revoked, true, records)
    }

    fn standing_when(
        revoked: bool,
        host_answered: bool,
        records: &[AuthorityFeedRecord],
    ) -> DeviceStanding {
        let verified: Vec<Verified<'_>> = records
            .iter()
            .map(|record| Verified {
                record,
                devices: BTreeSet::from([DeviceId::new(id(1))]),
            })
            .collect();
        let named: Vec<&Verified<'_>> = verified.iter().collect();
        standing(&device(revoked), &named, None, Route::Feed, host_answered)
    }

    /// A pending acknowledgement is not done: some of the host's workers have not confirmed, and the
    /// screen says how many. No host that can be started here is in that state, so this table is
    /// the one place it is held.
    #[test]
    fn a_request_is_done_only_when_the_hosts_acknowledgement_and_list_say_every_worker_confirmed() {
        let sent = record(10, None, None);
        let pending = record(
            11,
            Some(RevocationCompletion::Pending {
                pending_workers: U64::new(3),
            }),
            None,
        );
        let complete = record(12, Some(RevocationCompletion::Complete), None);
        let refused = record(13, None, Some(RejectionReason::UnknownTarget));

        assert_eq!(standing_of(false, &[]), DeviceStanding::Active);
        assert_eq!(standing_of(true, &[]), DeviceStanding::Revoked);
        assert_eq!(
            standing_of(false, std::slice::from_ref(&sent)),
            DeviceStanding::Sent {
                at_ms: 100,
                host_lists_revoked: false
            }
        );
        assert_eq!(
            standing_of(true, std::slice::from_ref(&sent)),
            DeviceStanding::Sent {
                at_ms: 100,
                host_lists_revoked: true
            },
            "a host that lists the device revoked has still not acknowledged the request"
        );
        assert_eq!(
            standing_of(true, std::slice::from_ref(&pending)),
            DeviceStanding::Acknowledged {
                at_ms: 200,
                pending_workers: Some(3),
                host_lists_revoked: true
            }
        );
        assert_eq!(
            standing_of(true, std::slice::from_ref(&complete)),
            DeviceStanding::Done { at_ms: 200 }
        );
        // The feed's word that the host finished is the service's. A host that answers just now and
        // does not list the device as revoked has not said it did, and one that does not answer has
        // said nothing either way.
        assert_eq!(
            standing_of(false, std::slice::from_ref(&complete)),
            DeviceStanding::Acknowledged {
                at_ms: 200,
                pending_workers: None,
                host_lists_revoked: false
            }
        );
        assert_eq!(
            standing_when(false, false, std::slice::from_ref(&complete)),
            DeviceStanding::Done { at_ms: 200 }
        );
        assert_eq!(
            standing_of(false, std::slice::from_ref(&pending)),
            DeviceStanding::Acknowledged {
                at_ms: 200,
                pending_workers: Some(3),
                host_lists_revoked: false
            },
            "a host that has not confirmed every worker and does not list the device as revoked \
             is told apart from one that does"
        );
        assert_eq!(
            standing_when(false, false, std::slice::from_ref(&pending)),
            DeviceStanding::Acknowledged {
                at_ms: 200,
                pending_workers: Some(3),
                host_lists_revoked: true
            },
            "a list kept from before says nothing against the acknowledgement"
        );
        assert_eq!(
            standing_of(false, std::slice::from_ref(&refused)),
            DeviceStanding::Refused {
                reason: RejectionReason::UnknownTarget
            }
        );
        assert_eq!(
            standing_of(true, std::slice::from_ref(&refused)),
            DeviceStanding::Revoked,
            "a refused request for a device the host lists revoked changes nothing"
        );
        // Several requests for one device: the one that got furthest decides.
        assert_eq!(
            standing_of(true, &[refused.clone(), sent.clone(), pending.clone()]),
            DeviceStanding::Acknowledged {
                at_ms: 200,
                pending_workers: Some(3),
                host_lists_revoked: true
            }
        );
        assert_eq!(
            standing_of(true, &[refused, sent, pending, complete]),
            DeviceStanding::Done { at_ms: 200 }
        );
    }

    /// A record is this computer's own only when this computer's key published it, as the device it
    /// is on that host, and signed it for that host: the service that holds a feed judges none of
    /// that, and a record that is taken for this computer's own takes a device out of the settings.
    #[test]
    fn a_record_is_this_computers_own_only_when_this_computer_signed_it_for_this_host() {
        use kr_crypto::keys::AuthorisationKeyPair;

        let mine = AuthorisationKeyPair::generate().expect("a key");
        let theirs = AuthorisationKeyPair::generate().expect("a key");
        let (me, host, other_host) = (
            DeviceId::new(id(3)),
            DeviceId::new(id(4)),
            DeviceId::new(id(5)),
        );
        let named = || RevocationTarget::Devices {
            device_ids: CanonicalSet::from_iter([DeviceId::new(id(1))]),
        };
        let signed = |key: &AuthorisationKeyPair, issuer, host, number: u8| {
            let request = kr_pairing::grants::sign_revocation_request(
                key,
                RevocationRequestId::new(id(number)),
                issuer,
                host,
                named(),
                TimestampMs::new(99),
            )
            .expect("a request");
            AuthorityFeedRecord {
                sequence: U64::new(u64::from(number)),
                request,
                published_by: *mine.public(),
                published_at_ms: U64::new(100),
                acknowledgement: Nullable::null(),
                rejected: Nullable::null(),
            }
        };
        let genuine = signed(&mine, me, host, 20);
        // Published by this computer's key, but signed by another key.
        let forged = signed(&theirs, me, host, 21);
        // Signed by this computer, for another host.
        let elsewhere = signed(&mine, me, other_host, 22);
        // Issued as another device on this host.
        let borrowed = signed(&mine, DeviceId::new(id(6)), host, 23);
        // Signed by this computer, and published by another key.
        let mut stranger = signed(&mine, me, host, 24);
        stranger.published_by = *theirs.public();
        let records = [genuine, forged, elsewhere, borrowed, stranger];

        let own = own_requests(&records, me, host, mine.public());
        let ids: Vec<RevocationRequestId> = own
            .iter()
            .map(|request| request.record.request.request_id)
            .collect();
        assert_eq!(ids, [RevocationRequestId::new(id(20))]);
    }
}
