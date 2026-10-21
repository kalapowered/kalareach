//! Revoking a device on a host this computer owns, through the commands the page calls.
//!
//! The hosts are kr-controller's in-process daemon, the authority feed is the stand-in held to a
//! recording of the Worker's, and this computer is the companion's backend on the mock runtime,
//! recorded as an owner of the host. The daemon reads and answers the feed itself, so what the
//! screen is shown of an acknowledgement is what a real host wrote.
//!
//! A case that shows the clause of a requirement row carries that row's key in a comment of its
//! own. The device list's standing for a request published to a host's feed, and the host on this
//! computer taking a revocation from native code, are the two things most cases here are about.

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::AppState;
use companion_tauri::settings::{Holds, HostLists, HostPrivacy, Hosts};
use kr_client::ipc::IpcTransport;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
use kr_client::services::authority::{AuthorityFeedClient, RejectionReason};
use kr_client::services::{HttpDeadlines, HttpService, ServiceSigner, managed_response_limits};
use kr_controller::service::Clocks;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{MemoryStore, SecretStore, store_device_keys};
use kr_protocol::ids::{DeviceId, EnvironmentId, GrantId, SessionId};
use kr_protocol::pairing::DevicePublicKeys;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_protocol::sharing::{DeviceListResult, DeviceSummary};
use kr_service_stand_in::{Moment, Served, serve};
use net_support::{Device, Host, pair_with, proposal};
use serde_json::{Value, json};
use support::{Companion, StubIntake};
use tauri::Manager as _;

const AUTHORITY: &str = "/api/authority/sync";

/// How long a condition the host or the feed brings about is waited for before the case is called
/// hung.
const WATCHDOG: Duration = Duration::from_secs(120);

/// The platform's ceremony, answered as a case says.
struct Scripted {
    answer: Mutex<CeremonyOutcome>,
    asked: Mutex<Vec<String>>,
    /// While set, the person is still at the dialog: it says when it was shown and ends when told.
    held: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

impl Scripted {
    fn new(answer: CeremonyOutcome) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            asked: Mutex::new(Vec::new()),
            held: Mutex::new(None),
        })
    }

    /// The next dialog stays up until the returned `release` is notified; `shown` says it is up.
    fn hold_the_dialog(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let shown = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *self.held.lock().expect("the hold") = Some((Arc::clone(&shown), Arc::clone(&release)));
        (shown, release)
    }

    fn reasons(&self) -> Vec<String> {
        self.asked.lock().expect("the record").clone()
    }
}

impl Ceremony for Scripted {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.asked
            .lock()
            .expect("the record")
            .push(reason.to_owned());
        let answer = *self.answer.lock().expect("the answer");
        let held = self.held.lock().expect("the hold").take();
        Box::pin(async move {
            if let Some((shown, release)) = held {
                shown.notify_one();
                release.notified().await;
            }
            answer
        })
    }
}

/// A key the host named for removing its feed, signing as an installation.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

/// What settings sync can ask of hosts when a case asks none: it lists nothing and reads nothing.
struct NoHosts;

impl Hosts for NoHosts {
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>> {
        Box::pin(std::future::ready(HostLists::default()))
    }

    fn holds(
        &self,
        _session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>> {
        Box::pin(std::future::ready(Holds::Unknown))
    }

    fn privacy(
        &self,
        _environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>> {
        Box::pin(std::future::ready(HostPrivacy::Unreadable {
            reason: "no host is asked".to_owned(),
        }))
    }
}

/// What settings sync asks of hosts when two owner devices are listed: this computer and the phone,
/// each with its keys and the right to manage the host, as a host lists a device the person owns.
struct ListsOwners {
    list: DeviceListResult,
}

impl ListsOwners {
    fn of(this: &DeviceKeys, phone: &DeviceKeys) -> Self {
        let owner_device = |number: u8, name: &str, keys: &DeviceKeys| DeviceSummary {
            device_id: DeviceId::new(Uuid::from_bytes([number; 16])),
            display_name: name.to_owned(),
            grant_id: GrantId::new(Uuid::from_bytes([0x90; 16])),
            paired_at_ms: TimestampMs::new(1),
            revoked: false,
            keys: Nullable::some(DevicePublicKeys {
                transport: *keys.transport.public(),
                authorisation: *keys.authorisation.public(),
                stored_envelope: *keys.stored_envelope.public(),
                notification_preview: *keys.notification_preview.public(),
            }),
            manages_host: true,
            platform: kr_protocol::pairing::DevicePlatform::Macos,
            grant_expires_at_ms: Nullable::null(),
            grant_expired: false,
            all_sessions: true,
        };
        Self {
            list: DeviceListResult {
                devices: vec![
                    owner_device(1, "this-mac", this),
                    owner_device(2, "the-phone", phone),
                ],
                authority_revision: kr_protocol::ids::AuthorityRevision::new(1),
                feed_synchronised_at_ms: Nullable::null(),
                feed_stale: false,
                feed_removed: false,
            },
        }
    }
}

impl Hosts for ListsOwners {
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>> {
        Box::pin(std::future::ready(HostLists {
            lists: vec![self.list.clone()],
            silent: false,
            refused: false,
        }))
    }

    fn holds(
        &self,
        session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>> {
        NoHosts.holds(session)
    }

    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>> {
        NoHosts.privacy(environment)
    }
}

/// Whether any file under `directory` holds `needle`.
fn somewhere_in(directory: &std::path::Path, needle: &[u8]) -> bool {
    std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                somewhere_in(&path, needle)
            } else {
                std::fs::read(&path)
                    .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            }
        })
}

/// A host whose feed is a stand-in service, a device paired with it, and this computer as the
/// host's owner.
struct Rig {
    host: Host,
    served: Served,
    owner: DeviceKeys,
    ceremony: Arc<Scripted>,
    app: Companion,
    data: tempfile::TempDir,
    /// The keys this computer holds, which a restart keeps.
    secrets: Arc<dyn SecretStore>,
    /// The device the host paired, which is the one that is revoked.
    phone: Device,
    /// The timer the host's carriers wait by, held.
    timer: Arc<HeldTimer>,
    /// The host's own keys, for a host started to read its mailbox: a test seals as the host with
    /// them.
    host_keys: Option<DeviceKeys>,
}

impl Rig {
    async fn start() -> Self {
        Self::start_with(false).await
    }

    /// As [`Self::start`], with the host's reader of its own mailbox waiting by the held timer too,
    /// so that a test decides when it looks.
    async fn start_reading_the_mailbox() -> Self {
        Self::start_with(true).await
    }

    async fn start_with(reads_the_mailbox: bool) -> Self {
        let served = serve().await;
        let owner = DeviceKeys::generate().expect("owner keys");
        let timer = HeldTimer::held();
        let host_keys = reads_the_mailbox.then(|| DeviceKeys::generate().expect("host keys"));
        let host = if let Some(host_keys) = &host_keys {
            Host::start_with_feed_and_keys(
                &owner,
                host_keys,
                served.origin(),
                Arc::clone(&timer) as _,
                Clocks::system(),
            )
            .await
        } else {
            Host::start_with_feed_on(
                &owner,
                served.origin(),
                Arc::clone(&timer) as _,
                Clocks::system(),
            )
            .await
        };
        let phone = Device::create().await;
        pair_with(&host, &phone, &owner, proposal(&[ActionRight::SessionView])).await;

        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        store_device_keys(&*secrets, "device", &owner).expect("the owner's keys are kept");
        let data = tempfile::tempdir().expect("a directory");
        let ceremony = Scripted::new(CeremonyOutcome::Confirmed);
        let app = Companion::start(
            data.path(),
            support::parts(Arc::clone(&secrets), Arc::new(host.room.clone())),
            Arc::clone(&ceremony) as Arc<dyn Ceremony>,
            StubIntake::holding("", false),
        );
        support::record_owned(&app.device(), &host, "the test host");
        companion_tauri::start_sync_service(app.app.handle(), data.path());
        companion_tauri::start_mailbox(app.app.handle(), data.path()).expect("the mailbox opens");
        let rig = Self {
            host,
            served,
            owner,
            ceremony,
            app,
            data,
            secrets,
            phone,
            timer,
            host_keys,
        };
        rig.sync_service_is(rig.served.origin());
        // The passes the start and the pairing asked for end before anything connects: a
        // connection admitted while one runs is withdrawn when it finishes.
        rig.host_polls().await;
        if rig.host_keys.is_some() {
            rig.the_hosts_reader_has_passed_since(0).await;
        }
        rig
    }

    /// This computer's application is closed and opened again over the records it kept.
    async fn restarted(self) -> Self {
        let Self {
            host,
            served,
            owner,
            ceremony,
            app,
            data,
            secrets,
            phone,
            timer,
            host_keys,
        } = self;
        drop(app);
        let app = Companion::start(
            data.path(),
            support::parts(Arc::clone(&secrets), Arc::new(host.room.clone())),
            Arc::clone(&ceremony) as Arc<dyn Ceremony>,
            StubIntake::holding("", false),
        );
        companion_tauri::start_sync_service(app.app.handle(), data.path());
        companion_tauri::start_mailbox(app.app.handle(), data.path()).expect("the mailbox opens");
        Self {
            host,
            served,
            owner,
            ceremony,
            app,
            data,
            secrets,
            phone,
            timer,
            host_keys,
        }
    }

    /// The host pairs one more device, which is not the one `phone` names.
    async fn pairs_another(&self) -> Device {
        let another = Device::create().await;
        pair_with(
            &self.host,
            &another,
            &self.owner,
            proposal(&[ActionRight::SessionView]),
        )
        .await;
        another
    }

    /// This computer is set to use the sync service at `origin`.
    fn sync_service_is(&self, origin: &str) {
        self.app
            .app
            .state::<AppState>()
            .sync_service()
            .expect("the setting is open")
            .set(origin)
            .expect("an origin");
    }

    /// Settings sync starts on this computer and is not turned on: no settings are shared.
    fn start_settings_sync(&self) {
        let device = self.app.device();
        companion_tauri::start_settings_sync(
            self.app.app.handle(),
            device.identity(),
            Arc::new(NoHosts),
            Arc::clone(&self.ceremony) as Arc<dyn Ceremony>,
        )
        .expect("settings sync opens");
    }

    /// Settings sync starts on this computer over hosts that list it and the phone as the owner's
    /// devices, and is not turned on.
    fn start_settings_sync_listing_the_phone(&self) {
        let device = self.app.device();
        let hosts = ListsOwners::of(&device.identity().keys, self.phone.keys());
        companion_tauri::start_settings_sync(
            self.app.app.handle(),
            device.identity(),
            Arc::new(hosts),
            Arc::clone(&self.ceremony) as Arc<dyn Ceremony>,
        )
        .expect("settings sync opens");
    }

    /// This computer shares its settings with the phone: the hosts list it, and the person
    /// confirmed here.
    async fn sharing_with_the_phone(&self) {
        self.start_settings_sync_listing_the_phone();
        self.app
            .app
            .state::<AppState>()
            .settings()
            .expect("settings are open")
            .sync_turn_on()
            .await
            .expect("settings sync is on");
        let devices = self.devices();
        let candidate = devices["candidates"][0]["reference"]
            .as_str()
            .unwrap_or_else(|| panic!("the phone is offered: {devices}"))
            .to_owned();
        self.app
            .call("settings_device_share", json!({ "reference": candidate }))
            .expect("the person shares with the phone");
        let members = self.devices()["members"].as_array().expect("members").len();
        assert_eq!(members, 2, "the phone holds the key now");
    }

    /// The devices that share this computer's settings, after the hosts are asked.
    fn devices(&self) -> Value {
        self.app
            .call("settings_devices_refresh", json!({}))
            .expect("the settings view")["sync"]["devices"]
            .clone()
    }

    /// This computer takes part in settings sync, over a collection of its own.
    async fn with_settings_sync(&self) {
        self.start_settings_sync();
        self.app
            .app
            .state::<AppState>()
            .settings()
            .expect("settings are open")
            .sync_turn_on()
            .await
            .expect("settings sync is on");
    }

    /// Settings sync is told of the revoked device `phone`: its key is in the membership as a
    /// device a revocation required to be taken out.
    async fn settings_sync_hears_of(&self, phone: &Device) {
        let key = *phone.keys().authorisation.public();
        let membership = self.data.path().join("settings-sync").join("membership");
        tokio::time::timeout(WATCHDOG, async {
            while !somewhere_in(&membership, key.as_bytes()) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("settings sync is told of the revoked device");
    }

    /// The host reads its feed, carries out what it finds and acknowledges it.
    async fn host_polls(&self) {
        let carrier = self.host.controller().feed_runtime().expect("a carrier");
        carrier.synchronised_before_serving().await;
        carrier.synchronised_before_serving().await;
    }

    /// How many passes the host's reader of its own mailbox has finished.
    fn the_hosts_reader_count(&self) -> u64 {
        *self
            .host
            .controller()
            .mailbox_reader()
            .expect("a reader of the host's mailbox")
            .passes()
            .borrow()
    }

    /// Waits until the host's reader of its own mailbox has finished a pass since `seen` passes
    /// were counted, and waits again by its timer.
    async fn the_hosts_reader_has_passed_since(&self, seen: u64) {
        let mut passes = self
            .host
            .controller()
            .mailbox_reader()
            .expect("a reader of the host's mailbox")
            .passes();
        tokio::time::timeout(WATCHDOG, async {
            while *passes.borrow_and_update() <= seen {
                passes.changed().await.expect("the reader is running");
            }
        })
        .await
        .expect("the host's reader finishes a pass");
    }

    /// What `kr doctor` says of the host's reader of its own mailbox.
    fn the_hosts_reader_says(&self) -> String {
        let controller = self.host.controller();
        controller
            .mailbox_reader()
            .expect("a reader of the host's mailbox")
            .doctor_check(controller)
            .detail()
            .to_owned()
    }

    async fn view(&self) -> Value {
        self.app
            .call("revocation_view", json!({}))
            .expect("the screen")
    }

    /// The device `reference` names on the host `host` names is revoked.
    fn revoke(&self, host: &str, device: &str) -> Result<Value, Value> {
        self.app.call(
            "revocation_revoke",
            json!({ "host": host, "device": device }),
        )
    }

    /// The view, waited for until `holds` says it does.
    async fn view_until(&self, what: &str, holds: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let view = self.view().await;
                if holds(&view) {
                    return view;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("gave up waiting for {what}"))
    }

    /// The key this computer's own mailbox is addressed by.
    fn my_key(&self) -> kr_protocol::scalars::StoredEnvelopeKey {
        *self.app.device().identity().keys.stored_envelope.public()
    }

    /// How many items this computer's mailbox holds at the service.
    fn items_waiting_for_me(&self) -> usize {
        self.served.web().mailbox_envelopes(&self.my_key()).len()
    }

    /// An item of `kind` from `from` to this computer's mailbox, with an identifier made of
    /// `number`, left at the service by a stranger's installation as any device leaves one.
    async fn leaves_an_item(
        &self,
        from: &kr_crypto::keys::StoredEnvelopeKeyPair,
        kind: kr_protocol::mailbox::MailboxPayloadType,
        number: u8,
    ) -> kr_protocol::mailbox::SealedEnvelope {
        use kr_protocol::mailbox::{EnvelopePlaintext, EnvelopeVersion};
        let now = kr_ipc::now_ms().get();
        let item = kr_crypto::envelope::seal_envelope(
            from,
            &self.my_key(),
            &EnvelopePlaintext {
                version: EnvelopeVersion::V1,
                envelope_id: kr_protocol::ids::EnvelopeId::new(Uuid::from_bytes([number; 16])),
                sender_key_id: from.key_id(),
                recipient_key_id: kr_crypto::keys::key_id(
                    kr_protocol::pairing::KeyPurpose::StoredEnvelope,
                    self.my_key().as_bytes(),
                ),
                payload_type: kind,
                created_at_ms: TimestampMs::new(now),
                expires_at_ms: TimestampMs::new(now + 30 * 60 * 1000),
                grant_id: Nullable::null(),
                environment_id: Nullable::null(),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                thread_id: Nullable::null(),
                payload: kr_protocol::scalars::Bytes::new(vec![number; 16]),
            },
        )
        .expect("a sealed item");
        let origin = GatewayOrigin::new(self.served.origin()).expect("an origin");
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport");
        kr_client::services::mailbox::MailboxClient::new(
            origin,
            Arc::new(http),
            Arc::new(Installation(
                AuthorisationKeyPair::generate().expect("a key pair"),
            )),
        )
        .deliver(&self.my_key(), &item)
        .await
        .expect("the service takes the item: it cannot read it");
        item
    }

    /// The host's own stored-envelope key pair, for a host started to read its mailbox.
    fn the_host(&self) -> &kr_crypto::keys::StoredEnvelopeKeyPair {
        &self
            .host_keys
            .as_ref()
            .expect("a host started to read its mailbox")
            .stored_envelope
    }

    /// This computer's reader of its own mailbox.
    fn desk(&self) -> Arc<companion_tauri::mailbox::MailboxDesk> {
        self.app
            .app
            .state::<AppState>()
            .mailbox()
            .expect("the mailbox desk")
    }

    /// The record of what this computer took from its mailbox, as it is on disk.
    fn record_on_disk(&self) -> Option<Vec<u8>> {
        std::fs::read(self.data.path().join("mailbox").join("replay.json")).ok()
    }

    /// A record as this computer's reader of its mailbox finds it, owner-only, in the directory a
    /// pass makes.
    fn puts_a_record(&self, bytes: &[u8]) {
        let directory = self.data.path().join("mailbox");
        kr_ipc::paths::create_private_directory(&directory).expect("the directory");
        kr_ipc::paths::write_owner_only_file(&directory.join("replay.json"), bytes)
            .expect("a record is written");
    }

    /// The identifiers on that record, each with when it may be forgotten.
    fn identifiers_on_record(&self) -> std::collections::BTreeMap<String, u64> {
        self.record_on_disk()
            .map(|bytes| {
                serde_json::from_slice::<Value>(&bytes).expect("a record")["identifiers"]
                    .as_object()
                    .expect("identifiers")
                    .iter()
                    .map(|(id, until)| (id.clone(), until.as_u64().expect("a time")))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The key the host's own mailbox is addressed by.
    fn host_stored_envelope_key(&self) -> kr_protocol::scalars::StoredEnvelopeKey {
        self.host
            .network()
            .pairing()
            .identity()
            .keys
            .stored_envelope
    }

    /// How many publications reached the host's own feed service.
    fn publications(&self) -> usize {
        published_at(&self.served)
    }
}

/// How many publications reached `served`.
fn published_at(served: &Served) -> usize {
    served
        .web()
        .arrived()
        .iter()
        .filter(|arrived| arrived.path == AUTHORITY && arrived.body.get("publish").is_some())
        .count()
}

/// A connection to the host on this machine, over its own socket.
async fn local_connection(
    endpoint: &kr_ipc::paths::Endpoint,
) -> companion_tauri::error::Result<companion_tauri::connection::Connection> {
    let build_id = companion_tauri::connection::build_id()?;
    let transport = IpcTransport::connect(endpoint, build_id)
        .await
        .map_err(companion_tauri::error::CommandError::from)?;
    companion_tauri::connection::Connection::over(transport)
}

/// The host the screen lists as reached through `route`.
fn host_by(view: &Value, route: &str) -> Value {
    view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|host| host["route"] == route)
        .unwrap_or_else(|| panic!("no host is reached {route}: {view}"))
        .clone()
}

/// The device of `host` that is neither this computer nor the host's owner device: the one paired.
fn the_phone(host: &Value) -> Value {
    host["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|device| device["this_computer"] == false && device["manages_host"] == false)
        .unwrap_or_else(|| panic!("the host lists no paired device: {host}"))
        .clone()
}

/// Every device of `host` that is neither this computer nor an owner of the host.
fn the_phones(host: &Value) -> Vec<Value> {
    host["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .filter(|device| device["this_computer"] == false && device["manages_host"] == false)
        .cloned()
        .collect()
}

/// The phone's state on the first host of `view` reached by `route`.
fn phone_state(view: &Value, route: &str) -> String {
    the_phone(&host_by(view, route))["standing"]["state"]
        .as_str()
        .expect("a state")
        .to_owned()
}

/// KR-REQ-10.46: a revocation of a device on a host that is read through its feed is a request
/// published to that feed, and the screen does not call it done until the host's acknowledgement
/// is read. It says how often the host reads its feed (every thirty seconds), shows
/// the host's last acknowledgement with its revision once it is read, and sends nothing a second
/// time for a device that is revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_is_called_done_only_once_the_hosts_acknowledgement_is_read() {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    let before = rig.view().await;
    let host = host_by(&before, "feed");
    assert_eq!(host["contact"], "answered");
    assert_eq!(host["name"], "the test host");
    assert_eq!(
        before["ceremony"], "touch_id",
        "the screen names the ceremony the control asks for"
    );
    assert_eq!(
        host["feed"]["poll_interval_seconds"],
        json!(30),
        "the screen says how often the host reads its feed"
    );
    assert_eq!(phone_state(&before, "feed"), "active");
    assert_eq!(
        before["feed_origin"],
        rig.served.origin().trim_start_matches("http://"),
        "the screen says where requests are published"
    );
    let phone = the_phone(&host);

    let sent = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect("the person confirms and the request is published");
    // A host that is connected to reads its feed at once, so this may already be the host's
    // acknowledged answer: what it may not be is anything else.
    assert!(
        ["sent", "done"].contains(&phone_state(&sent, "feed").as_str()),
        "the request is sent, and done only if the host has acknowledged it: {sent}"
    );
    assert_eq!(rig.publications(), 1);
    // Settings sync is told of the device the request names, which it fences at once: its key is
    // in the membership as a device a feed verified revoked.
    rig.settings_sync_hears_of(&rig.phone).await;
    let reasons = rig.ceremony.reasons();
    assert_eq!(reasons.len(), 1, "the person is asked once: {reasons:?}");
    assert!(
        reasons[0].contains(phone["name"].as_str().expect("a name"))
            && reasons[0].contains("the test host"),
        "the dialog says what would be revoked and where: {reasons:?}"
    );

    rig.host_polls().await;
    let done = rig
        .view_until("the host's acknowledgement", |view| {
            phone_state(view, "feed") == "done"
        })
        .await;
    let feed = &host_by(&done, "feed")["feed"];
    assert_eq!(feed["host_wrote_here"], true);
    assert!(
        feed["last_acknowledgement"]["revision"]
            .as_u64()
            .is_some_and(|revision| revision > 0),
        "the host's last acknowledgement is shown: {feed}"
    );
    // The host itself lists the device revoked, and nothing was sent a second time.
    assert_eq!(rig.publications(), 1);
    let repeat = rig
        .revoke(
            host_by(&done, "feed")["reference"]
                .as_str()
                .expect("a reference"),
            the_phone(&host_by(&done, "feed"))["reference"]
                .as_str()
                .expect("a reference"),
        )
        .expect_err("a device revoked is not revoked again");
    assert_eq!(repeat["code"], "PERMISSION_DENIED", "{repeat}");
}

/// KR-REQ-10.46: a request that no host acknowledged stays sent and outstanding, and is never
/// called done: a host that reads another service than the one the request was published at
/// finds nothing, and asking again publishes nothing and asks nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_reads_another_service_never_acknowledges_and_the_screen_never_calls_it_done() {
    let rig = Rig::start().await;
    let elsewhere = serve().await;
    rig.sync_service_is(elsewhere.origin());
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    assert_eq!(
        view["feed_origin"],
        elsewhere.origin().trim_start_matches("http://")
    );

    let sent = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect("the request is published at the service this computer uses");
    assert_eq!(
        phone_state(&sent, "feed"),
        "sent",
        "a request the host has not acknowledged is sent, never done: {sent}"
    );
    let feed = &host_by(&sent, "feed")["feed"];
    assert_eq!(feed["read"], true);
    assert_eq!(feed["outstanding"], json!(1));
    assert_eq!(feed["host_wrote_here"], false);
    assert_eq!(
        rig.publications(),
        0,
        "nothing reached the host's own service"
    );
    assert_eq!(published_at(&elsewhere), 1);
    // The request waits. Asking again sends nothing and asks nobody.
    let again = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect("the request that waits is shown");
    assert_eq!(phone_state(&again, "feed"), "sent");
    assert_eq!(published_at(&elsewhere), 1);
    assert_eq!(rig.ceremony.reasons().len(), 1);

    // The host reads the service its own configuration selects, and finds nothing there.
    rig.host_polls().await;
    let after = rig.view().await;
    assert_eq!(
        phone_state(&after, "feed"),
        "sent",
        "no acknowledgement was read, so it is not done: {after}"
    );
    assert_eq!(host_by(&after, "feed")["feed"]["host_wrote_here"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_the_person_does_not_confirm_sends_nothing() {
    let rig = Rig::start().await;
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    *rig.ceremony.answer.lock().expect("the answer") = CeremonyOutcome::NotConfirmed;

    let refused = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect_err("the person did not confirm");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert_eq!(rig.publications(), 0, "nothing reached the feed");
    assert_eq!(phone_state(&rig.view().await, "feed"), "active");

    // A computer with no ceremony revokes nothing either.
    *rig.ceremony.answer.lock().expect("the answer") = CeremonyOutcome::Unavailable;
    let unavailable = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect_err("there is no ceremony to ask");
    assert_ne!(unavailable["code"], Value::Null, "{unavailable}");
    assert_eq!(rig.publications(), 0);
}

/// KR-REQ-10.01: the page names a host and a device only by the references native code gave it. A
/// reference the screen was not given, and this computer's own device, are refused by the command
/// before anything is published or asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reference_the_screen_was_not_given_names_nothing_and_this_computer_is_not_revoked_by_itself()
 {
    let rig = Rig::start().await;
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let host_reference = host["reference"].as_str().expect("a reference");
    let phone = the_phone(&host);

    for (host_named, device_named) in [
        (
            "0".repeat(24),
            phone["reference"].as_str().expect("a reference").to_owned(),
        ),
        (host_reference.to_owned(), "1".repeat(24)),
    ] {
        let refused = rig
            .revoke(&host_named, &device_named)
            .expect_err("nothing the screen listed is named");
        assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    }
    let this_computer = host["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|device| device["this_computer"] == true)
        .expect("this computer is listed on its own host");
    let refused = rig
        .revoke(
            host_reference,
            this_computer["reference"].as_str().expect("a reference"),
        )
        .expect_err("this computer does not revoke itself");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert_eq!(rig.publications(), 0);
    assert!(
        rig.ceremony.reasons().is_empty(),
        "nobody is asked for any of them"
    );
}

/// KR-REQ-20.04, KR-REQ-20.05: a revocation this computer publishes carries an announcement sealed
/// to the host, and the host reads it from its own mailbox and opens it against the pairing: the
/// item is the host's to open and nobody else's, and the host's reader takes it and tells the
/// service it may go. The host's reader waits by a timer the test holds, so the announcement stays
/// in the host's mailbox until the test lets the reader look.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_20_04_a_published_revocation_carries_an_announcement_the_host_opens() {
    let rig = Rig::start_reading_the_mailbox().await;
    let before = rig.view().await;
    let host = host_by(&before, "feed");
    let phone = the_phone(&host);

    rig.revoke(
        host["reference"].as_str().expect("a reference"),
        phone["reference"].as_str().expect("a reference"),
    )
    .expect("the person confirms and the request is published");

    assert_eq!(rig.publications(), 1);
    assert_eq!(
        rig.served
            .web()
            .mailbox_envelopes(&rig.host_stored_envelope_key())
            .len(),
        1,
        "the announcement is in the host's mailbox beside the request"
    );
    assert!(
        rig.the_hosts_reader_says()
            .contains("0 announcement(s) taken"),
        "{}",
        rig.the_hosts_reader_says()
    );

    let seen = rig.the_hosts_reader_count();
    let (_, release) = rig
        .timer
        .next_wait_under(kr_controller::mailbox_reader::POLL_INTERVAL + Duration::from_millis(1))
        .await;
    release.notify_one();
    rig.the_hosts_reader_has_passed_since(seen).await;

    assert!(
        rig.the_hosts_reader_says()
            .contains("1 announcement(s) taken"),
        "{}",
        rig.the_hosts_reader_says()
    );
    assert!(
        rig.served
            .web()
            .mailbox_envelopes(&rig.host_stored_envelope_key())
            .is_empty(),
        "the service may remove what the host took"
    );
}

/// An announcement is a nudge: the service refuses a change whose announcement outlives its own
/// clock by more than an hour, and a sender whose clock runs ahead of the service's by less than
/// the freshness of a signed request must not lose its revocation to that. Here the service's clock
/// runs two minutes behind this computer's, and the revocation is stored with its announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_is_stored_though_this_computers_clock_runs_ahead_of_the_services() {
    let rig = Rig::start_reading_the_mailbox().await;
    rig.served.web().run_behind(Duration::from_secs(120));
    let before = rig.view().await;
    let host = host_by(&before, "feed");
    let phone = the_phone(&host);

    rig.revoke(
        host["reference"].as_str().expect("a reference"),
        phone["reference"].as_str().expect("a reference"),
    )
    .expect("the request is published, with its announcement");

    assert_eq!(rig.publications(), 1);
    assert_eq!(
        rig.served
            .web()
            .mailbox_envelopes(&rig.host_stored_envelope_key())
            .len(),
        1,
        "the announcement was placed"
    );
}

/// What the screen is told of this computer's mailbox, after a look.
async fn mailbox_after_a_look(rig: &Rig) -> Value {
    rig.view().await["mailbox"].clone()
}

/// KR-REQ-20.04, KR-REQ-20.05: the host that carries out a revocation announces what became of it
/// to the computer that published it, and this computer takes the announcement from its own
/// mailbox: it opens against the host it is paired with, is written down, and is counted once.
/// Nothing wakes this computer's look but the look itself, which a screen makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_20_05_the_hosts_announcement_of_its_acknowledgement_is_taken_from_this_computers_mailbox()
 {
    let rig = Rig::start_reading_the_mailbox().await;
    let host = host_by(&rig.view().await, "feed");
    let phone = the_phone(&host);
    rig.revoke(
        host["reference"].as_str().expect("a reference"),
        phone["reference"].as_str().expect("a reference"),
    )
    .expect("the request is published");
    let (_, release) = rig
        .timer
        .next_wait_under(kr_controller::mailbox_reader::POLL_INTERVAL + Duration::from_millis(1))
        .await;
    release.notify_one();

    let looked = rig
        .view_until("the host's announcement is taken", |view| {
            view["mailbox"]["announcements"] == json!(1)
        })
        .await;
    let mailbox = &looked["mailbox"];

    assert_eq!(mailbox["stopped"], Value::Null);
    assert_eq!(rig.items_waiting_for_me(), 0, "the service may remove it");
    assert_eq!(rig.identifiers_on_record().len(), 1, "it is on record");
}

/// An owner whose request revokes its own device is carried out by the host, and the host places
/// nothing in the mailbox of that device, as it is no longer one the host pairs with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_revoked_its_own_device_is_acknowledged_without_an_announcement() {
    use kr_protocol::ids::RevocationRequestId;
    use kr_protocol::pairing::RevocationTarget;
    use kr_protocol::scalars::CanonicalSet;
    let rig = Rig::start_reading_the_mailbox().await;
    let owner_device = rig.host.owner.as_ref().expect("an owner").device_id;
    let host_device = rig.host.network().pairing().identity().device_id;
    let origin = GatewayOrigin::new(rig.served.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport");
    let remote = AuthorityFeedClient::new(
        origin,
        Arc::new(http),
        Arc::new(Installation(rig.owner.authorisation.clone())),
    );
    let request = kr_pairing::grants::sign_revocation_request(
        &rig.owner.authorisation,
        RevocationRequestId::new(kr_ipc::new_uuid()),
        owner_device,
        host_device,
        RevocationTarget::Devices {
            device_ids: CanonicalSet::from_iter([owner_device]),
        },
        kr_ipc::now_ms(),
    )
    .expect("a signed request");
    remote
        .publish(
            rig.host
                .controller()
                .feed_runtime()
                .expect("a carrier")
                .feed(),
            &request,
            None,
        )
        .await
        .expect("the feed takes the request");

    rig.host_polls().await;

    assert!(
        rig.host
            .controller()
            .devices()
            .devices()
            .expect("the host's devices")
            .into_iter()
            .any(|record| record.device_id == owner_device && record.revoked_at_ms.is_some()),
        "the host carried the request out"
    );
    assert_eq!(
        rig.items_waiting_for_me(),
        0,
        "nothing was placed in the mailbox of a device the host no longer pairs with"
    );
}

/// KR-REQ-20.04, KR-REQ-20.05: what this computer takes from its mailbox is what a host it is
/// paired with sealed, and an unsigned payload that bears authority inside an envelope that is valid
/// in every other way is refused. An item from a key nobody paired, and an item that bears authority
/// from the host itself, are dropped and leave no identifier; the host's announcement beside them is taken, and the service
/// is told that all three may go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_20_05_a_stranger_and_an_item_that_bears_authority_are_dropped() {
    use kr_protocol::mailbox::MailboxPayloadType::{AuthorityFeedChange, SignedAuthorityObject};
    let rig = Rig::start_reading_the_mailbox().await;
    let stranger = kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a key pair");
    rig.leaves_an_item(&stranger, AuthorityFeedChange, 1).await;
    rig.leaves_an_item(rig.the_host(), SignedAuthorityObject, 2)
        .await;
    rig.leaves_an_item(rig.the_host(), AuthorityFeedChange, 3)
        .await;

    let mailbox = mailbox_after_a_look(&rig).await;

    assert_eq!(mailbox["announcements"], json!(1), "only the host's own");
    assert_eq!(rig.items_waiting_for_me(), 0);
    assert_eq!(
        rig.identifiers_on_record().len(),
        1,
        "what did not open is not on record"
    );
}

/// KR-REQ-20.05: a host this computer forgot is no sender. Its item is taken while it is paired and
/// dropped after, and the computer goes on reading because another host it owns is still read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_20_05_a_host_this_computer_forgot_is_no_sender() {
    use kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange;
    let rig = Rig::start_reading_the_mailbox().await;
    let other = DeviceKeys::generate().expect("another host's keys");
    let other_id = DeviceId::new(kr_ipc::new_uuid());
    let mut record = rig
        .app
        .device()
        .pairing()
        .hosts
        .list()
        .expect("the records")
        .remove(0);
    record.host_device_id = other_id;
    record.host_endpoint_id = *other.transport.public();
    record.host_keys = other.public_keys();
    record.name = Some("the other host".to_owned());
    rig.app
        .device()
        .pairing()
        .hosts
        .record(record)
        .expect("the other host is recorded");

    rig.leaves_an_item(&other.stored_envelope, AuthorityFeedChange, 1)
        .await;
    assert_eq!(mailbox_after_a_look(&rig).await["announcements"], json!(1));

    rig.app
        .device()
        .forget_host(other_id)
        .expect("the host is forgotten");
    rig.leaves_an_item(&other.stored_envelope, AuthorityFeedChange, 2)
        .await;
    let mailbox = mailbox_after_a_look(&rig).await;

    assert_eq!(
        mailbox["announcements"],
        json!(1),
        "the second is not taken"
    );
    assert_eq!(mailbox["stopped"], Value::Null);
    assert_eq!(
        rig.items_waiting_for_me(),
        0,
        "it is dropped, and the service may remove it: {mailbox}, {} reads, {} acknowledgements",
        rig.served.web().requests_to("/api/mailbox/read"),
        rig.served.web().requests_to("/api/mailbox/acknowledge"),
    );
    assert_eq!(rig.identifiers_on_record().len(), 1);
}

/// KR-REQ-20.05: an identifier this computer accepted is refused when the service offers the item
/// again, even to an application started since, and is kept until the item's expiry and a day more.
/// The service never heard the first acknowledgement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_20_05_an_item_taken_once_is_refused_when_offered_again_after_a_restart() {
    use kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange;
    let rig = Rig::start_reading_the_mailbox().await;
    let item = rig
        .leaves_an_item(rig.the_host(), AuthorityFeedChange, 7)
        .await;
    rig.served
        .web()
        .fail("/api/mailbox/acknowledge", 1, Moment::Before);

    let first = mailbox_after_a_look(&rig).await;
    assert_eq!(first["announcements"], json!(1));
    assert_eq!(first["stopped"], json!("unreachable"));
    assert_eq!(rig.items_waiting_for_me(), 1, "the service never heard");
    assert_eq!(
        rig.identifiers_on_record()
            .values()
            .copied()
            .collect::<Vec<_>>(),
        [item.routing.expires_at_ms.get() + kr_protocol::mailbox::REPLAY_ID_RETENTION_MS],
        "kept until the item's expiry and a day more"
    );

    let rig = rig.restarted().await;
    let second = mailbox_after_a_look(&rig).await;

    assert_eq!(second["announcements"], json!(0), "taken once, not again");
    assert_eq!(second["stopped"], Value::Null);
    assert_eq!(rig.items_waiting_for_me(), 0);
    assert_eq!(rig.identifiers_on_record().len(), 1);
}

/// What is already due to be forgotten is forgotten when something is written, and what is not is
/// kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identifier_that_is_due_to_be_forgotten_is_forgotten_and_the_rest_are_kept() {
    use kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange;
    let rig = Rig::start_reading_the_mailbox().await;
    let due = Uuid::from_bytes([0xd0; 16]).to_string();
    let kept = Uuid::from_bytes([0xd1; 16]).to_string();
    let far = kr_ipc::now_ms().get() + 3 * 24 * 60 * 60 * 1000;
    rig.puts_a_record(
        &serde_json::to_vec(&json!({
            "version": 1,
            "identifiers": { due.clone(): 1, kept.clone(): far }
        }))
        .expect("a record"),
    );
    rig.leaves_an_item(rig.the_host(), AuthorityFeedChange, 5)
        .await;

    assert_eq!(mailbox_after_a_look(&rig).await["announcements"], json!(1));

    let held = rig.identifiers_on_record();
    assert!(
        !held.contains_key(&due),
        "an identifier past its day is forgotten"
    );
    assert_eq!(held.get(&kept), Some(&far));
    assert_eq!(held.len(), 2);
}

/// A pass does not wait for another window of the application, and the lock is held for the whole
/// of the pass that has it: while one desk waits on the service, a second desk over the same
/// directory, as another window of the application is, is skipped and asks the service nothing; once
/// the first has ended, the second reads, and takes what the first did not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_does_not_wait_for_another_window_that_is_reading() {
    use kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange;
    let rig = Rig::start_reading_the_mailbox().await;
    rig.leaves_an_item(rig.the_host(), AuthorityFeedChange, 4)
        .await;
    let asked = rig.served.web().requests_to("/api/mailbox/read");
    rig.served.web().fail("/api/mailbox/read", 1, Moment::Hold);
    let first = rig.desk();
    let reading = tokio::spawn(async move { first.pass().await });
    rig.served
        .web()
        .requests_reach("/api/mailbox/read", asked + 1)
        .await;
    let state = rig.app.app.state::<AppState>();
    let window = companion_tauri::mailbox::MailboxDesk::new(
        rig.data.path(),
        state.device().expect("the device"),
        state.sync_service().expect("the setting is open"),
    );

    let skipped = window.pass().await;

    assert_eq!(skipped.announcements, 0);
    assert_eq!(
        rig.served.web().requests_to("/api/mailbox/read"),
        asked + 1,
        "the second window asked the service nothing while the first was reading"
    );
    assert_eq!(rig.items_waiting_for_me(), 1);
    rig.served.web().release_held();
    reading.await.expect("the first pass ends");

    assert_eq!(window.pass().await.announcements, 1);
    assert_eq!(rig.items_waiting_for_me(), 0);
    assert_eq!(rig.identifiers_on_record().len(), 1);
}

/// A record this build cannot trust is refused and left exactly as found, and nothing is
/// acknowledged: a record of a version it does not read, a record that is not a record, and a record
/// that is full of identifiers that must be kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_that_cannot_be_used_is_left_as_found_and_nothing_is_acknowledged() {
    use kr_protocol::mailbox::MailboxPayloadType::AuthorityFeedChange;
    let far = kr_ipc::now_ms().get() + 3 * 24 * 60 * 60 * 1000;
    let full: serde_json::Map<String, Value> = (0..companion_tauri::mailbox::MOST_IDENTIFIERS)
        .map(|index| {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            (Uuid::from_bytes(bytes).to_string(), json!(far))
        })
        .collect();
    let cases: [(&str, Vec<u8>, &str); 3] = [
        (
            "a newer version",
            serde_json::to_vec(&json!({ "version": 2, "identifiers": {} })).expect("a record"),
            "records",
        ),
        ("not a record", b"not a record".to_vec(), "records"),
        (
            "a full one",
            serde_json::to_vec(&json!({ "version": 1, "identifiers": full })).expect("a record"),
            "full",
        ),
    ];
    for (what, bytes, stopped) in cases {
        let rig = Rig::start_reading_the_mailbox().await;
        rig.puts_a_record(&bytes);
        rig.leaves_an_item(rig.the_host(), AuthorityFeedChange, 9)
            .await;

        let mailbox = mailbox_after_a_look(&rig).await;

        assert_eq!(mailbox["stopped"], json!(stopped), "{what}");
        assert_eq!(
            rig.items_waiting_for_me(),
            1,
            "{what}: nothing was acknowledged"
        );
        assert_eq!(
            rig.record_on_disk().expect("the record"),
            bytes,
            "{what}: the record is as it was found"
        );
    }
}

/// A service that asks to be left alone is left alone for as long as it asked, by every look, and
/// the screen says so, from the look that was told. Each service is held to its own delay: one that
/// asked this computer to wait is not asked while another service is read and this computer comes
/// back to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_asks_to_be_left_alone_is_not_asked_again_by_the_next_look() {
    let rig = Rig::start_reading_the_mailbox().await;
    let asks_to_wait = || Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(120),
    };
    rig.served
        .web()
        .fail("/api/mailbox/read", 1, asks_to_wait());

    let first = mailbox_after_a_look(&rig).await;
    assert_eq!(first["stopped"], json!("waiting"));
    let asked = rig.served.web().requests_to("/api/mailbox/read");

    let second = mailbox_after_a_look(&rig).await;

    assert_eq!(second["stopped"], json!("waiting"));
    assert_eq!(
        rig.served.web().requests_to("/api/mailbox/read"),
        asked,
        "nothing was sent while the service asked to be left alone"
    );

    // Another service asks for a delay of its own, and this computer comes back to the first.
    let elsewhere = serve().await;
    elsewhere.web().fail("/api/mailbox/read", 1, asks_to_wait());
    rig.sync_service_is(elsewhere.origin());
    assert_eq!(
        mailbox_after_a_look(&rig).await["stopped"],
        json!("waiting")
    );
    rig.sync_service_is(rig.served.origin());

    let back = mailbox_after_a_look(&rig).await;

    assert_eq!(back["stopped"], json!("waiting"));
    assert_eq!(
        rig.served.web().requests_to("/api/mailbox/read"),
        asked,
        "the first service is still owed its delay"
    );
}

/// A delay a service names is the service's to name and not unlimited: one so long that it cannot
/// be added to a clock does not stop the screen, and the service is left alone for no more than an
/// hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_names_an_endless_delay_does_not_stop_the_screen() {
    let rig = Rig::start_reading_the_mailbox().await;
    rig.served.web().fail(
        "/api/mailbox/read",
        1,
        Moment::Refuse {
            status: 429,
            code: "RATE_LIMITED",
            retry_after_seconds: Some(u64::MAX),
        },
    );

    let view = rig.view().await;

    assert_eq!(view["mailbox"]["stopped"], json!("waiting"));
    assert!(
        view["hosts"]
            .as_array()
            .is_some_and(|hosts| !hosts.is_empty()),
        "the feed's view is there: {view}"
    );
    let asked = rig.served.web().requests_to("/api/mailbox/read");
    assert_eq!(
        mailbox_after_a_look(&rig).await["stopped"],
        json!("waiting")
    );
    assert_eq!(rig.served.web().requests_to("/api/mailbox/read"), asked);
}

/// A mailbox that never answers does not hold the screen: the pass ends within its time and the view
/// is the one the feed gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mailbox_that_never_answers_does_not_hold_the_screen() {
    let rig = Rig::start_reading_the_mailbox().await;
    rig.desk().finish_within(Duration::from_millis(300));
    rig.served.web().fail("/api/mailbox/read", 1, Moment::Hold);

    let view = rig.view().await;

    assert_eq!(view["mailbox"]["stopped"], json!("unreachable"));
    assert!(
        view["hosts"]
            .as_array()
            .is_some_and(|hosts| !hosts.is_empty()),
        "the feed's view is there: {view}"
    );
    rig.served.web().release_held();
}

/// A computer that reads no feed asks the mailbox service nothing: with no host to read a feed of,
/// the screen contacts no service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_computer_that_owns_no_host_to_read_a_feed_of_asks_the_mailbox_nothing() {
    let rig = Rig::start_reading_the_mailbox().await;
    let host = rig
        .app
        .device()
        .pairing()
        .hosts
        .list()
        .expect("the records")
        .remove(0);
    rig.app
        .device()
        .forget_host(host.host_device_id)
        .expect("the host is forgotten");
    let asked = rig.served.web().requests_to("/api/mailbox/read");

    let view = rig.view().await;

    assert_eq!(rig.served.web().requests_to("/api/mailbox/read"), asked);
    assert_eq!(view["mailbox"]["last_read_ms"], Value::Null);
}

/// KR-REQ-10.46: a host that does not answer is revoked on through its durable feed: the screen
/// shows the list it last saw with its time, and the request is published and stands as sent, not
/// done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_does_not_answer_is_revoked_on_through_its_feed_from_the_list_last_seen() {
    let rig = Rig::start().await;
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    let Rig {
        host: daemon,
        served,
        owner,
        ceremony,
        app,
        data,
        phone: _phone,
        secrets: _,
        timer: _,
        host_keys: _,
    } = rig;
    daemon.stop().await;

    let silent = app.call("revocation_view", json!({})).expect("the screen");
    let host_now = host_by(&silent, "feed");
    assert_eq!(host_now["contact"], "silent");
    assert!(
        host_now["listed_at_ms"].as_u64().is_some(),
        "the list last seen is shown with its time: {host_now}"
    );
    assert_eq!(the_phone(&host_now)["reference"], phone["reference"]);

    let sent = app
        .call(
            "revocation_revoke",
            json!({
                "host": host["reference"],
                "device": phone["reference"],
            }),
        )
        .expect("the request is published though the host does not answer");
    assert_eq!(phone_state(&sent, "feed"), "sent");
    assert_eq!(ceremony.reasons().len(), 1);
    let _ = (served, owner, data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_the_feed_removed_is_not_reached_by_feed_and_nothing_is_published() {
    let rig = Rig::start().await;
    rig.host_polls().await;
    // A key the host named for removing the feed removes it.
    let origin = GatewayOrigin::new(rig.served.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport");
    let remote = AuthorityFeedClient::new(
        origin,
        Arc::new(http),
        Arc::new(Installation(rig.owner.authorisation.clone())),
    );
    remote
        .remove(
            rig.host
                .controller()
                .feed_runtime()
                .expect("a carrier")
                .feed(),
        )
        .await
        .expect("a key the host named removes the feed");
    rig.host_polls().await;

    let view = rig.view().await;
    let host = host_by(&view, "feed");
    assert_eq!(host["feed"]["removed"], true);
    let refused = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            the_phone(&host)["reference"].as_str().expect("a reference"),
        )
        .expect_err("nothing published there reaches the host");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert_eq!(rig.publications(), 0);
    assert!(rig.ceremony.reasons().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_feed_that_cannot_be_read_is_said_and_nothing_is_sent() {
    let rig = Rig::start().await;
    for nth in 1..=8 {
        rig.served.web().fail(
            AUTHORITY,
            nth,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: None,
            },
        );
    }
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    assert_eq!(host["feed"]["read"], false);
    assert!(
        host["feed"]["problem"]
            .as_str()
            .is_some_and(|problem| !problem.is_empty()),
        "the screen says why: {host}"
    );
    let refused = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            the_phone(&host)["reference"].as_str().expect("a reference"),
        )
        .expect_err("a feed that cannot be read is not published to");
    assert!(refused["message"].as_str().is_some(), "{refused}");
    assert_eq!(rig.publications(), 0);
    assert!(
        rig.ceremony.reasons().is_empty(),
        "nobody is asked for a request that cannot be sent"
    );
}

/// KR-REQ-10.46: a request that was sent keeps its standing while its feed cannot be read: the
/// screen shows that it is an earlier read (when it was read), forgets nothing, and leaves another
/// device of the host as it was, and the standing is read afresh once the feed answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_was_sent_keeps_its_standing_while_its_feed_cannot_be_read() {
    let rig = Rig::start().await;
    rig.pairs_another().await;
    let listed = host_by(&rig.view().await, "feed");
    let phones = the_phones(&listed);
    assert_eq!(
        phones.len(),
        2,
        "the host lists both paired devices: {listed}"
    );
    let reference_of = |device: &Value| {
        device["reference"]
            .as_str()
            .expect("a reference")
            .to_owned()
    };
    let (asked, other) = (reference_of(&phones[0]), reference_of(&phones[1]));
    let sent = rig
        .revoke(listed["reference"].as_str().expect("a reference"), &asked)
        .expect("the request is published");
    let standing_of = |view: &Value, reference: &str| -> Value {
        the_phones(&host_by(view, "feed"))
            .into_iter()
            .find(|device| device["reference"] == reference)
            .unwrap_or_else(|| panic!("no device {reference}: {view}"))
    };
    let read = standing_of(&sent, &asked);
    assert!(
        ["sent", "done"].contains(&read["standing"]["state"].as_str().expect("a state")),
        "{read}"
    );
    assert_eq!(read["stale_since_ms"], Value::Null, "read just now: {read}");

    for nth in 1..=8 {
        rig.served.web().fail(
            AUTHORITY,
            nth,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: None,
            },
        );
    }
    let unread = rig.view().await;
    assert_eq!(host_by(&unread, "feed")["feed"]["read"], false);
    let kept = standing_of(&unread, &asked);
    // The host's own list may say meanwhile that it has revoked the device; the request is the
    // standing, and it is not forgotten because its feed cannot be read.
    assert_eq!(
        kept["standing"]["state"], read["standing"]["state"],
        "a request that was sent is not forgotten because its feed cannot be read: {kept}"
    );
    assert!(
        kept["stale_since_ms"].is_u64(),
        "the screen says it is showing an earlier read: {kept}"
    );
    let untouched = standing_of(&unread, &other);
    assert_eq!(untouched["standing"]["state"], "active", "{untouched}");
    assert_eq!(untouched["stale_since_ms"], Value::Null, "{untouched}");

    rig.served.web().mend();
    let again = rig.view().await;
    assert_eq!(standing_of(&again, &asked)["stale_since_ms"], Value::Null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_on_this_computer_takes_the_revocation_itself_and_its_answer_is_the_acknowledgement()
 {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    // The owner's first connection to the host settles what the host admits connections under, and
    // a connection admitted before it is withdrawn.
    rig.view().await;
    rig.host_polls().await;
    // The application is connected to the host on this machine over its own socket, which is how
    // the owner at the machine reaches it, and can open another when the host withdraws one.
    let endpoint = rig.host.endpoint().clone();
    let reopen: companion_tauri::connection::Reopen = Arc::new({
        let endpoint = endpoint.clone();
        move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { local_connection(&endpoint).await })
        }
    });
    let connection = local_connection(&endpoint)
        .await
        .expect("connects to the control endpoint")
        .reopening(reopen);
    rig.app.app.state::<AppState>().connected(connection);

    let view = rig.view().await;
    let local = host_by(&view, "direct");
    assert_eq!(local["name"], "This computer");
    assert!(
        local["feed"].is_null(),
        "nothing goes through a feed: {local}"
    );
    let phone = the_phone(&local);
    assert_eq!(phone["standing"]["state"], "active");

    let done = rig
        .revoke(
            local["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect("the host on this computer revokes the device");
    assert_eq!(phone_state(&done, "direct"), "done", "{done}");
    assert_eq!(rig.publications(), 0, "no feed was involved");
    let reasons = rig.ceremony.reasons();
    assert_eq!(reasons.len(), 1, "the person is asked once: {reasons:?}");
    assert!(
        reasons[0].contains(phone["name"].as_str().expect("a name"))
            && reasons[0].ends_with("on this computer"),
        "the dialog reads as a sentence about this computer: {reasons:?}"
    );
    // Settings sync is told, and takes the device out of the settings it shares: the connection it
    // would ask the host over is the one the revocation withdrew.
    rig.settings_sync_hears_of(&rig.phone).await;
    let again = rig
        .revoke(
            local["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect_err("it is revoked");
    assert_eq!(again["code"], "PERMISSION_DENIED", "{again}");
}

/// Settings sync holds everything it sends before a revocation leaves, so a revocation whose hold
/// cannot be written down is not sent, and one whose hold is written down is, whether or not
/// settings sync started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_whose_hold_on_settings_sync_cannot_be_written_down_is_not_sent() {
    // Settings sync did not start on this computer: the hold is a file all the same.
    let rig = Rig::start().await;
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    let held = rig.data.path().join("settings-sync").join("revoking.json");
    // A directory where the record would be, so that it can be neither read nor written.
    kr_ipc::paths::create_private_directory(held.parent().expect("a directory"))
        .expect("the directory settings sync keeps its records in");
    std::fs::create_dir(&held).expect("the obstacle");

    let refused = rig
        .revoke(
            host["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect_err("nothing leaves unless settings sync is held back first");
    assert_eq!(refused["code"], "RESOURCE_UNAVAILABLE", "{refused}");
    assert_eq!(rig.publications(), 0, "no request was published");
    let key = *rig.phone.keys().authorisation.public();
    assert!(
        !rig.app
            .app
            .state::<AppState>()
            .settings()
            .expect("settings are open")
            .requests()
            .holds(&key),
        "the request recorded before the hold failed never left, so it is let go of"
    );
    std::fs::remove_dir(&held).expect("the obstacle goes");

    rig.revoke(
        host["reference"].as_str().expect("a reference"),
        phone["reference"].as_str().expect("a reference"),
    )
    .expect("the hold is written down, and the request is published");
    assert_eq!(rig.publications(), 1);
    let record: Vec<String> =
        serde_json::from_slice(&std::fs::read(&held).expect("the record")).expect("a list");
    assert_eq!(record.len(), 1, "the device is held: {record:?}");
}

/// Revokes the phone on the feed host with the service answering the publication "stored, and I
/// cannot say whether it took effect", and says what the call answered.
async fn revoke_with_the_outcome_unknown(rig: &Rig) -> Value {
    revoke_with_the_publication(rig, Moment::ActedAndUnknown).await
}

/// Revokes the phone on the feed host with the service meeting the publication as `moment` says,
/// and says what the call answered.
async fn revoke_with_the_publication(rig: &Rig, moment: Moment) -> Value {
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    let body = json!({ "host": host["reference"], "device": phone["reference"] });
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let call = rig.app.start_call("revocation_revoke", body);
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    rig.served
        .web()
        .fail_with_member(AUTHORITY, "publish", 1, moment);
    release.notify_one();

    let lost = tokio::time::timeout(WATCHDOG, call)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect_err("the publication failed");
    assert_eq!(rig.publications(), 1, "the publication reached the service");
    lost
}

/// A request the service stored and answered that it cannot say whether it took effect may have
/// reached the host, so the device is out of the shared settings all the same, and the person is
/// told so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_whose_outcome_is_not_known_still_takes_the_device_out_of_the_settings() {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    let lost = revoke_with_the_outcome_unknown(&rig).await;
    assert!(
        lost["message"]
            .as_str()
            .is_some_and(|words| words.contains("no longer shares its settings")),
        "the person is told what became of the settings: {lost}"
    );
    rig.settings_sync_hears_of(&rig.phone).await;
}

/// A membership whose record of the collection is missing, as an interrupted join leaves it, is a
/// collection all the same: the hold stays, and the step that resumes it takes the device in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_stays_while_a_membership_has_no_record_of_its_collection() {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    let settings = rig
        .app
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open");
    let phone = *rig.phone.keys().authorisation.public();
    let settings_sync = rig.data.path().join("settings-sync");
    std::fs::remove_file(settings_sync.join("sync.json")).expect("the record goes");
    settings
        .hold_for_revocation(&[phone])
        .expect("the hold is written down");

    let taken_in = settings
        .revocations_sent(&[phone])
        .await
        .expect("the step is tried");
    assert!(!taken_in, "there is no record to take the device out under");
    let held: Vec<String> =
        serde_json::from_slice(&std::fs::read(settings_sync.join("revoking.json")).expect("held"))
            .expect("a list");
    assert_eq!(held.len(), 1, "the hold stays: {held:?}");

    // Settings sync resumes the collection, and its first step takes the device in.
    settings
        .sync_turn_on()
        .await
        .expect("settings sync resumes");
    rig.settings_sync_hears_of(&rig.phone).await;
}

/// Where no settings are shared there is nothing to take the device out of: the person is told
/// nothing of settings, and the hold is let go of.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_revocation_says_nothing_of_settings_where_none_are_shared() {
    let rig = Rig::start().await;
    rig.start_settings_sync();
    let lost = revoke_with_the_outcome_unknown(&rig).await;
    assert!(
        lost["message"]
            .as_str()
            .is_some_and(|words| !words.contains("settings")),
        "nothing is said of settings: {lost}"
    );
    let record = rig.data.path().join("settings-sync").join("revoking.json");
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let held: Vec<String> = std::fs::read(&record)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            if held.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the hold is let go of: there is no collection to take the device out of");
}

/// The host on this computer takes a revocation and answers, and the view that follows cannot list
/// the host: settings sync was told when the host answered, not at the end of that view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_revocation_is_told_to_settings_sync_though_the_view_after_it_cannot_list_the_host()
 {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    rig.view().await;
    rig.host_polls().await;
    let endpoint = rig.host.endpoint().clone();
    // The connection can be replaced once, for the revocation, and not again.
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reopen: companion_tauri::connection::Reopen = Arc::new({
        let endpoint = endpoint.clone();
        move || {
            let endpoint = endpoint.clone();
            let first = opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            Box::pin(async move {
                if first {
                    local_connection(&endpoint).await
                } else {
                    Err(companion_tauri::error::CommandError::unavailable(
                        "the host did not answer",
                    ))
                }
            })
        }
    });
    let connection = local_connection(&endpoint)
        .await
        .expect("connects to the control endpoint")
        .reopening(reopen);
    rig.app.app.state::<AppState>().connected(connection);
    let view = rig.view().await;
    let local = host_by(&view, "direct");
    let phone = the_phone(&local);

    let after = rig
        .revoke(
            local["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect("the host on this computer revokes the device");
    assert_eq!(
        host_by(&after, "direct")["contact"],
        "silent",
        "the view after it could not list the host: {after}"
    );
    rig.settings_sync_hears_of(&rig.phone).await;
}

/// Whoever revokes a device at the host on this computer, and whether or not the host's answer
/// reached this computer, the device leaves the shared settings once the host lists it revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_host_on_this_computer_lists_as_revoked_is_taken_out_of_the_settings_whoever_revoked_it()
 {
    let rig = Rig::start().await;
    rig.with_settings_sync().await;
    rig.view().await;
    rig.host_polls().await;
    let endpoint = rig.host.endpoint().clone();
    let reopen: companion_tauri::connection::Reopen = Arc::new({
        let endpoint = endpoint.clone();
        move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { local_connection(&endpoint).await })
        }
    });
    let connection = local_connection(&endpoint)
        .await
        .expect("connects to the control endpoint")
        .reopening(reopen);
    rig.app.app.state::<AppState>().connected(connection);

    // The owner at the machine revokes the paired device, which this computer was never asked to.
    let phone = rig
        .host
        .controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| {
            record.is_paired()
                && Some(record.device_id) != rig.host.owner.as_ref().map(|owner| owner.device_id)
        })
        .expect("the paired device");
    let mut client = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut client,
        kr_protocol::method::Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: phone.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");

    // The next time the screen reads the host, settings sync is told.
    rig.view().await;
    rig.settings_sync_hears_of(&rig.phone).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_on_this_computer_takes_a_second_revocation_though_the_first_withdrew_the_connection()
 {
    let rig = Rig::start().await;
    rig.pairs_another().await;
    rig.view().await;
    rig.host_polls().await;
    let endpoint = rig.host.endpoint().clone();
    let reopen: companion_tauri::connection::Reopen = Arc::new({
        let endpoint = endpoint.clone();
        move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { local_connection(&endpoint).await })
        }
    });
    let connection = local_connection(&endpoint)
        .await
        .expect("connects to the control endpoint")
        .reopening(reopen);
    rig.app.app.state::<AppState>().connected(connection);

    let view = rig.view().await;
    let local = host_by(&view, "direct");
    let phones = the_phones(&local);
    assert_eq!(phones.len(), 2, "two devices are paired: {local}");
    for phone in &phones {
        // Each revocation withdraws the connection the host admitted before it, and the next goes
        // over the one the host admits then.
        let done = rig
            .revoke(
                local["reference"].as_str().expect("a reference"),
                phone["reference"].as_str().expect("a reference"),
            )
            .expect("the host on this computer revokes the device");
        let revoked = host_by(&done, "direct");
        assert!(
            the_phones(&revoked)
                .iter()
                .find(|each| each["reference"] == phone["reference"])
                .is_some_and(|each| each["standing"]["state"] == "done"),
            "{done}"
        );
    }
    assert_eq!(rig.ceremony.reasons().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_call_for_a_device_being_revoked_sends_nothing_and_asks_nobody() {
    let rig = Rig::start().await;
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    let body = json!({ "host": host["reference"], "device": phone["reference"] });
    let (shown, release) = rig.ceremony.hold_the_dialog();

    // The person is at the dialog, and a second window asks for the same revocation.
    let first = rig.app.start_call("revocation_revoke", body.clone());
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    let second = rig.app.start_call("revocation_revoke", body);
    let second = tokio::time::timeout(WATCHDOG, second).await;
    let asked_meanwhile = rig.ceremony.reasons().len();
    let sent_meanwhile = rig.publications();
    // The dialog ends whatever the second call did, so that a failure here ends the case.
    release.notify_one();
    let first = tokio::time::timeout(WATCHDOG, first)
        .await
        .expect("the first call ends")
        .expect("the call ends")
        .expect("the person confirmed and the request was published");

    let second = second
        .expect("the second call does not wait for the dialog")
        .expect("the call ends")
        .expect("it is shown what stands");
    assert_eq!(phone_state(&second, "feed"), "active");
    assert_eq!(asked_meanwhile, 1, "nobody was asked twice");
    assert_eq!(sent_meanwhile, 0, "nothing was sent for it");
    assert!(["sent", "done"].contains(&phone_state(&first, "feed").as_str()));
    assert_eq!(rig.publications(), 1, "one request for one device");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_on_this_computer_whose_connection_cannot_be_replaced_is_not_said_to_refuse_this_computer()
 {
    let rig = Rig::start().await;
    rig.view().await;
    rig.host_polls().await;
    // This computer's connection to its own host cannot be opened again.
    let connection = local_connection(rig.host.endpoint())
        .await
        .expect("connects to the control endpoint")
        .reopening(Arc::new(|| {
            Box::pin(async {
                Err(companion_tauri::error::CommandError::unavailable(
                    "the host did not answer",
                ))
            })
        }));
    rig.app.app.state::<AppState>().connected(connection);
    assert_eq!(host_by(&rig.view().await, "direct")["contact"], "answered");

    // The owner at the machine revokes a device, which withdraws the connection this one was
    // admitted on. The host says so, which says nothing of what this computer may do there.
    let phone = rig
        .host
        .controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| {
            record.is_paired()
                && Some(record.device_id) != rig.host.owner.as_ref().map(|owner| owner.device_id)
        })
        .expect("the paired device");
    let mut client = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut client,
        kr_protocol::method::Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: phone.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");

    let after = host_by(&rig.view().await, "direct");
    assert_eq!(
        after["contact"], "silent",
        "a connection that cannot be replaced says nothing of this computer's right: {after}"
    );

    // A host that did not answer just now is not offered a ceremony that could not succeed.
    let listed = the_phone(&after);
    let refused = rig
        .revoke(
            after["reference"].as_str().expect("a reference"),
            listed["reference"].as_str().expect("a reference"),
        )
        .expect_err("the host did not answer, so nothing could be sent");
    assert_eq!(refused["code"], "RESOURCE_UNAVAILABLE", "{refused}");
    assert!(
        rig.ceremony.reasons().is_empty(),
        "the person is not asked: {:?}",
        rig.ceremony.reasons()
    );
}

/// The view the screen is given, as native code serialises it, in the fixture the page's tests read
/// the same view from: every standing, every contact, and a feed read and a feed that was not.
#[test]
fn the_view_native_code_gives_the_screen_is_the_view_the_page_reads() {
    use companion_tauri::revocation::{
        Acknowledged, Contact, DeviceStanding, DeviceView, FeedView, HostView, RevocationView,
        Route,
    };
    use kr_client::services::authority::RejectionReason;
    use kr_protocol::pairing::DevicePlatform;

    fn device(
        reference: &str,
        name: &str,
        platform: DevicePlatform,
        owner: bool,
        here: bool,
        standing: DeviceStanding,
        stale_since_ms: Option<u64>,
    ) -> DeviceView {
        DeviceView {
            reference: reference.to_owned(),
            name: name.to_owned(),
            platform,
            manages_host: owner,
            this_computer: here,
            standing,
            stale_since_ms,
        }
    }
    let here = HostView {
        reference: "here".to_owned(),
        name: "This computer".to_owned(),
        route: Route::Direct,
        contact: Contact::Answered,
        listed_at_ms: Some(1_760_000_100_000),
        host_synchronised_at_ms: None,
        host_feed_stale: false,
        devices: vec![
            device(
                "here-mac",
                "the-mac",
                DevicePlatform::Macos,
                true,
                true,
                DeviceStanding::Active,
                None,
            ),
            device(
                "here-phone",
                "the-phone",
                DevicePlatform::Ios,
                false,
                false,
                DeviceStanding::Acknowledged {
                    at_ms: 1_760_000_050_000,
                    pending_workers: Some(1),
                    host_lists_revoked: true,
                },
                None,
            ),
            device(
                "here-tablet",
                "the-tablet",
                DevicePlatform::Android,
                false,
                false,
                DeviceStanding::Done {
                    at_ms: 1_760_000_060_000,
                },
                None,
            ),
        ],
        feed: None,
    };
    let studio = HostView {
        reference: "studio".to_owned(),
        name: "the-studio".to_owned(),
        route: Route::Feed,
        contact: Contact::Answered,
        listed_at_ms: Some(1_760_000_100_000),
        host_synchronised_at_ms: Some(1_760_000_090_000),
        host_feed_stale: false,
        devices: vec![
            device(
                "studio-laptop",
                "the-laptop",
                DevicePlatform::Windows,
                false,
                false,
                DeviceStanding::Active,
                None,
            ),
            device(
                "studio-watch",
                "the-watch",
                DevicePlatform::Linux,
                false,
                false,
                DeviceStanding::Sent {
                    at_ms: 1_760_000_070_000,
                    host_lists_revoked: false,
                },
                None,
            ),
            device(
                "studio-pad",
                "the-pad",
                DevicePlatform::Ios,
                false,
                false,
                DeviceStanding::Acknowledged {
                    at_ms: 1_760_000_080_000,
                    pending_workers: None,
                    host_lists_revoked: false,
                },
                None,
            ),
            device(
                "studio-old-phone",
                "the-old-phone",
                DevicePlatform::Ios,
                false,
                false,
                DeviceStanding::Refused {
                    reason: RejectionReason::NoOwnerAuthority,
                },
                None,
            ),
            device(
                "studio-spare",
                "the-spare",
                DevicePlatform::Android,
                false,
                false,
                DeviceStanding::Revoked,
                None,
            ),
        ],
        feed: Some(FeedView {
            read: true,
            problem: None,
            removed: false,
            host_wrote_here: true,
            last_acknowledgement: Some(Acknowledged {
                at_ms: 1_760_000_080_000,
                revision: 12,
                pending_workers: Some(2),
            }),
            outstanding: 1,
            poll_interval_seconds: Some(30),
        }),
    };
    let attic = HostView {
        reference: "attic".to_owned(),
        name: "the-attic".to_owned(),
        route: Route::Feed,
        contact: Contact::Silent,
        listed_at_ms: Some(1_760_000_010_000),
        host_synchronised_at_ms: None,
        host_feed_stale: true,
        devices: vec![
            device(
                "attic-kindle",
                "the-kindle",
                DevicePlatform::Android,
                false,
                false,
                DeviceStanding::Sent {
                    at_ms: 1_760_000_020_000,
                    host_lists_revoked: false,
                },
                Some(1_760_000_030_000),
            ),
            device(
                "attic-stick",
                "the-stick",
                DevicePlatform::Linux,
                false,
                false,
                DeviceStanding::Refused {
                    reason: RejectionReason::UnknownTarget,
                },
                None,
            ),
            device(
                "attic-fridge",
                "the-fridge",
                DevicePlatform::Linux,
                false,
                false,
                DeviceStanding::Refused {
                    reason: RejectionReason::Superseded,
                },
                None,
            ),
        ],
        feed: Some(FeedView {
            read: false,
            problem: Some("it did not answer in time".to_owned()),
            removed: false,
            host_wrote_here: false,
            last_acknowledgement: None,
            outstanding: 0,
            poll_interval_seconds: None,
        }),
    };
    let view = RevocationView {
        ceremony: CeremonyKind::TouchId,
        feed_origin: Some("sync.example.org:8443".to_owned()),
        mailbox: companion_tauri::mailbox::MailboxView {
            last_read_ms: Some(1_700_000_000_000),
            announcements: 2,
            stopped: Some(companion_tauri::mailbox::Stopped::Unreachable),
        },
        hosts: vec![here, studio, attic],
    };
    let fixture: Value =
        serde_json::from_str(include_str!("../../test/fixtures/revocation-view.json"))
            .expect("the fixture");
    assert_eq!(
        serde_json::to_value(&view).expect("the view serialises"),
        fixture,
        "the screen is given a view the page's fixture does not describe: {}",
        serde_json::to_string_pretty(&view).unwrap_or_default()
    );
}

/// This computer's connection to its own host, as the application holds it: it can be opened again.
async fn held_connection(rig: &Rig) -> companion_tauri::connection::Connection {
    let endpoint = rig.host.endpoint().clone();
    let reopen: companion_tauri::connection::Reopen = Arc::new({
        let endpoint = endpoint.clone();
        move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { local_connection(&endpoint).await })
        }
    });
    let connection = local_connection(&endpoint)
        .await
        .expect("connects to the control endpoint")
        .reopening(reopen);
    rig.app
        .app
        .state::<AppState>()
        .connected(connection.clone());
    connection
}

/// The owner at the machine revokes the paired device over a connection of its own, which
/// withdraws the connections the host admitted before: this computer's is one of them.
async fn the_owner_at_the_machine_revokes_the_paired_device(rig: &Rig) {
    let phone = rig
        .host
        .controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| {
            record.is_paired()
                && Some(record.device_id) != rig.host.owner.as_ref().map(|owner| owner.device_id)
        })
        .expect("the paired device");
    let mut client = rig.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        rig.host.environment_id,
        &mut client,
        kr_protocol::method::Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: phone.device_id,
        },
    )
    .await
    .expect("the owner at the machine revokes the device");
}

/// Ends the task that keeps the application's connection to the host when a case ends, so that
/// nothing tries the host's endpoint after it is gone.
struct EndsTheKeeper<'a>(tauri::State<'a, AppState>);

impl Drop for EndsTheKeeper<'_> {
    fn drop(&mut self) {
        let _ = self.0.choose_host("a case is over", |_| {
            Ok(tauri::async_runtime::spawn(async {}))
        });
    }
}

/// The application's own keeping of its connection to the host on this machine, with this rig's
/// host in place of the user's: the connection is reached, and reached again when it ends.
async fn keeps_its_connection(
    rig: &Rig,
    reopens: Arc<std::sync::atomic::AtomicUsize>,
) -> EndsTheKeeper<'_> {
    use companion_tauri::connection::Attempt;

    let endpoint = rig.host.endpoint().clone();
    companion_tauri::connection::reach_host_on_this_machine(rig.app.app.handle(), move || {
        let endpoint = endpoint.clone();
        let reopens = Arc::clone(&reopens);
        async move {
            // Another connection is slow to open, as one to a host that is busy is: refusals that
            // come while it is being opened meet a question that is already out.
            let reopen: companion_tauri::connection::Reopen = Arc::new({
                let endpoint = endpoint.clone();
                move || {
                    let endpoint = endpoint.clone();
                    reopens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Box::pin(async move {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        local_connection(&endpoint).await
                    })
                }
            });
            match local_connection(&endpoint).await {
                Ok(connection) => Attempt::Reached(connection.reopening(reopen)),
                Err(error) => Attempt::Failed(error),
            }
        }
    })
    .expect("the choice of the host is made");
    let keeper = EndsTheKeeper(rig.app.app.state::<AppState>());
    eventually("the host is reached", || keeper.0.session().ok()).await;
    keeper
}

/// Waits until `found` gives a value, or the watchdog runs out.
async fn eventually<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_the_host_withdrew_is_replaced_whichever_way_the_application_was_refused_on_it()
 {
    use kr_protocol::hostinfo::HostInfoResult;
    use kr_protocol::method::Method;

    let rig = Rig::start().await;
    rig.host_polls().await;
    let reopens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _keeper = keeps_its_connection(&rig, Arc::clone(&reopens)).await;
    let state = rig.app.app.state::<AppState>();
    let first = state.session().expect("connected");
    let _: HostInfoResult = first
        .read(Method::HostInfo, &json!({}))
        .await
        .expect("the host answers on the connection it admitted");
    assert_eq!(state.connection_state().replaced, 0);

    the_owner_at_the_machine_revokes_the_paired_device(&rig).await;

    // The host keeps the connection and refuses what is asked over it, which is its way of saying
    // to open another. A request made straight over the session, as any path of the application may
    // make one, is refused so; the application then takes up another connection of its own.
    let refused = first
        .read::<_, HostInfoResult>(Method::HostInfo, &json!({}))
        .await
        .expect_err("the host refuses a connection it withdrew");
    assert!(
        matches!(refused, kr_client::ClientError::Host(ref refusal) if refusal.code == kr_protocol::error::ErrorCode::PermissionDenied),
        "{refused:?}"
    );
    let second = eventually("the application holds a connection the host admits", || {
        state
            .session()
            .ok()
            .filter(|session| !Arc::ptr_eq(session, &first))
    })
    .await;
    // The page is told the connection was replaced, once, by the count the state carries: the
    // request refused on the withdrawn connection was answered with a failure just before.
    assert_eq!(state.connection_state().replaced, 1);
    let _: HostInfoResult = second
        .read(Method::HostInfo, &json!({}))
        .await
        .expect("the connection the application then holds is one the host admits");
    rig.app
        .call("host_info", json!({}))
        .expect("a command goes through on it");
    assert_eq!(
        state.connection_state().replaced,
        1,
        "once for one withdrawal"
    );
    // One withdrawal opened one other connection to ask the host. The refusal of the question
    // itself is not a second withdrawal: the client's own case of a read sent apart from the
    // signal holds that, and this one that the application opens no second connection for it.
    assert_eq!(
        reopens.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one other connection was opened to ask"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_of_the_hosts_replaces_a_connection_the_host_withdrew_before_anything_is_refused() {
    let rig = Rig::start().await;
    rig.host_polls().await;
    let held = held_connection(&rig).await;
    let state = rig.app.app.state::<AppState>();

    the_owner_at_the_machine_revokes_the_paired_device(&rig).await;

    // The view asks the host for its devices, is told to open another connection, does, and the
    // application keeps that one.
    assert_eq!(host_by(&rig.view().await, "direct")["contact"], "answered");
    assert!(
        !Arc::ptr_eq(&state.session().expect("connected"), &held.session()),
        "the application no longer holds the connection the host withdrew"
    );
    rig.app
        .call("host_info", json!({}))
        .expect("the first command after the view goes through");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_over_a_copy_of_a_connection_that_was_replaced_still_lists_the_host() {
    let rig = Rig::start().await;
    rig.host_polls().await;
    let held = held_connection(&rig).await;
    let state = rig.app.app.state::<AppState>();
    // What a revocation holds while the person is at the ceremony: a copy of the connection.
    let copy = state.connection().expect("connected");

    the_owner_at_the_machine_revokes_the_paired_device(&rig).await;
    // Another look at the hosts replaces the connection, which ends the one the copy is.
    assert_eq!(host_by(&rig.view().await, "direct")["contact"], "answered");
    assert!(
        !Arc::ptr_eq(&state.session().expect("connected"), &held.session()),
        "the application holds another connection"
    );

    let mut context = state.revocation_context();
    context.local = Some(copy);
    let view = state
        .revocations()
        .expect("revocations")
        .view(&context)
        .await;
    let direct = view
        .hosts
        .iter()
        .find(|host| host.route == companion_tauri::revocation::Route::Direct)
        .expect("the host on this computer");
    assert_eq!(
        direct.contact,
        companion_tauri::revocation::Contact::Answered,
        "a connection that ended says nothing of the host"
    );
}

/// The feed's service refuses everything addressed to it, as one does that is out of reach.
fn the_feed_cannot_be_read(served: &Served) {
    for nth in 1..=40 {
        served.web().fail(
            AUTHORITY,
            nth,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: None,
            },
        );
    }
}

/// A sync service this computer publishes at that the host does not read, so that a request put
/// there waits: the host on the rig acts on what it finds in its own feed at once.
async fn a_feed_the_host_does_not_read(rig: &Rig) -> Served {
    let elsewhere = serve().await;
    rig.sync_service_is(elsewhere.origin());
    elsewhere
}

/// Settings sync has taken the phone out of the shared settings, as it does for a device a
/// revocation request names: this waits for the step that does it, and asks nothing of the hosts.
async fn the_phone_is_taken_out(rig: &Rig) {
    let key = *rig.phone.keys().authorisation.public();
    let taken_in = rig
        .app
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open")
        .revocations_sent(&[key])
        .await
        .expect("the step ends");
    assert!(taken_in, "the membership took the revocation in");
}

/// The reference the sheet names the device taken out by a revoke with, when it names one.
fn the_device_held_out(devices: &Value) -> String {
    let held = devices["held_out"].as_array().expect("held out");
    assert_eq!(held.len(), 1, "one device is named as taken out: {devices}");
    held[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned()
}

/// A person asks to share the settings with the device again.
fn share_again(rig: &Rig, reference: &str) -> Result<Value, Value> {
    rig.app
        .call("settings_device_share", json!({ "reference": reference }))
}

/// The sheet names the device as kept out with a revoke on record, offers nothing to share with it,
/// and the command refuses it without asking the person to confirm.
fn assert_not_shared_with_again(rig: &Rig) {
    let devices = rig.devices();
    let reference = the_device_held_out(&devices);
    assert_eq!(
        devices["held_out"][0]["waiting"], true,
        "the sheet says a revoke is on record: {devices}"
    );
    share_again(rig, &reference)
        .expect_err("a device a request may still revoke is not shared with");
    assert!(
        rig.ceremony
            .reasons()
            .iter()
            .all(|reason| !reason.contains("again")),
        "nobody is asked to confirm it: {:?}",
        rig.ceremony.reasons()
    );
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(1),
        "the phone holds no key"
    );
}

/// The person revokes the phone on the feed host.
async fn revokes_the_phone(rig: &Rig) {
    let host = host_by(&rig.view().await, "feed");
    rig.revoke(
        host["reference"].as_str().expect("a reference"),
        the_phone(&host)["reference"].as_str().expect("a reference"),
    )
    .expect("the request is published");
}

/// A request this computer put in a host's feed, that the host has not acted on, can still revoke
/// the device: sharing the settings with the device again is not offered across a restart, whether
/// the feed can be read or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_request_waits_in_a_feed_is_not_shared_with_again_after_a_restart() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;
    revokes_the_phone(&rig).await;
    assert_eq!(published_at(&elsewhere), 1);
    the_phone_is_taken_out(&rig).await;

    let rig = rig.restarted().await;
    rig.sync_service_is(elsewhere.origin());
    rig.start_settings_sync_listing_the_phone();
    the_feed_cannot_be_read(&elsewhere);
    assert_not_shared_with_again(&rig);
}

/// A request the service stored and could not say it took effect is in a feed that no read has
/// since been able to show: the device stays off the sheet's offers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_outcome_is_unknown_keeps_its_device_from_being_shared_with_again() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revoke_with_the_outcome_unknown(&rig).await;
    the_phone_is_taken_out(&rig).await;

    the_feed_cannot_be_read(&rig.served);
    assert_not_shared_with_again(&rig);
}

/// A request that never reached the feed, but of which nothing could be said (the connection was
/// held open and ended with no answer), may still be stored by the service: a feed that shows
/// nothing is not the feed saying it will never hold it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_may_be_stored_late_is_not_let_go_of_by_a_feed_that_shows_none() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;
    let host = host_by(&rig.view().await, "feed");
    let body = json!({
        "host": host["reference"],
        "device": the_phone(&host)["reference"],
    });
    // The person is at the dialog: the feed has been read, and the next request to it is the
    // publication, which the service holds open until it is let go without an answer.
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let revoking = rig.app.start_call("revocation_revoke", body);
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    elsewhere.web().fail(AUTHORITY, 1, Moment::Hold);
    let asked_before = elsewhere.web().requests_to(AUTHORITY);
    release.notify_one();
    elsewhere
        .web()
        .requests_reach(AUTHORITY, asked_before + 1)
        .await;
    elsewhere.web().release_held();
    tokio::time::timeout(WATCHDOG, revoking)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect_err("nothing was answered");
    the_phone_is_taken_out(&rig).await;

    // A look at the feeds, which show nothing of the request, does not let it go.
    let shown = rig.view().await;
    assert_eq!(
        host_by(&shown, "feed")["feed"]["outstanding"],
        json!(0),
        "the feed shows no request: {shown}"
    );
    assert_not_shared_with_again(&rig);
}

/// A request the service refused is in no feed, and the person may share with the device again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_service_refused_does_not_keep_its_device_from_being_shared_with_again() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revoke_with_the_publication(
        &rig,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    )
    .await;
    the_phone_is_taken_out(&rig).await;

    let reference = the_device_held_out(&rig.devices());
    share_again(&rig, &reference)
        .expect("the service holds no request, so the person may share again");
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(2),
        "the phone holds the key again"
    );
    assert!(
        rig.ceremony
            .reasons()
            .contains(&"Share your settings with the-phone again".to_owned()),
        "{:?}",
        rig.ceremony.reasons()
    );
}

/// A request waits in the feed at one service, and the sync service this computer uses is changed:
/// the feed at the new service shows nothing of it, which is not the request gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_of_sync_service_does_not_let_a_waiting_request_go() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    let first = a_feed_the_host_does_not_read(&rig).await;
    revokes_the_phone(&rig).await;
    assert_eq!(published_at(&first), 1);
    the_phone_is_taken_out(&rig).await;

    let second = serve().await;
    rig.sync_service_is(second.origin());
    rig.view().await;
    assert_not_shared_with_again(&rig);
}

/// A request in a feed that the record does not name, as one an earlier version published, is found
/// by the look at the feeds before the sheet is shown, and held from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_record_does_not_name_is_found_in_the_feed_and_held() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;
    revokes_the_phone(&rig).await;
    the_phone_is_taken_out(&rig).await;

    let rig = rig.restarted().await;
    // The record is as an earlier version leaves it: there is none.
    std::fs::remove_file(rig.data.path().join("settings-sync").join("requested.json"))
        .expect("the record is removed");
    rig.sync_service_is(elsewhere.origin());
    rig.start_settings_sync_listing_the_phone();
    assert_not_shared_with_again(&rig);
}

/// A device is revoked before settings sync has started, so no collection and no step is there to
/// take it out and nothing holds it but the record of the request, which waits in a feed the host
/// does not read. Settings sync then starts with no collection, lets go of its hold, and is turned
/// on, and the hosts list the device: it is not offered to be shared with, it is named with the
/// devices taken out with its revoke on record, and the command refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_never_shared_with_whose_request_waits_is_not_offered_to_be_shared_with() {
    let rig = Rig::start().await;
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;
    revokes_the_phone(&rig).await;
    assert_eq!(published_at(&elsewhere), 1);

    rig.start_settings_sync_listing_the_phone();
    let settings = rig
        .app
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open");
    let key = *rig.phone.keys().authorisation.public();
    assert!(
        !settings
            .revocations_sent(&[key])
            .await
            .expect("the step ends"),
        "there is no collection to take the phone out of"
    );
    settings.sync_turn_on().await.expect("settings sync is on");
    // The looks that follow tell settings sync nothing, so nothing but the record holds the phone.
    the_feed_cannot_be_read(&elsewhere);
    let devices = rig.devices();
    assert_eq!(
        devices["candidates"],
        json!([]),
        "the phone is not offered: {devices}"
    );
    let reference = the_device_held_out(&devices);
    assert_eq!(devices["held_out"][0]["waiting"], true, "{devices}");
    share_again(&rig, &reference)
        .expect_err("a device a request may still revoke is not shared with");
    assert!(
        rig.ceremony
            .reasons()
            .iter()
            .all(|reason| !reason.contains("Share your settings")),
        "nobody is asked to confirm it: {:?}",
        rig.ceremony.reasons()
    );
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(1),
        "the phone holds no key"
    );
}

/// The host's configuration leaves no grant a right to manage the host, so the host refuses what
/// this computer asks of it from now on, and will not list its devices to it.
async fn the_host_leaves_this_computer_no_right_to_manage_it(rig: &Rig) {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 2;
    document.authority.origin = Nullable::some(rig.served.origin().to_owned());
    document.ceilings.grant_rights =
        Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]);
    let path = kr_worker::config::document_path(&rig.host.tree().environment());
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document is written");
    let effective = rig.host.controller().effective_configuration().await;
    assert!(
        effective.not_in_force.0.is_none(),
        "the host puts the document in force: {:?}",
        effective.not_in_force
    );
}

/// What happens at the host while the person is at the dialog of a revoke.
enum Meanwhile {
    /// The host's configuration stops allowing this computer to manage it.
    TheHostStopsAllowingIt,
    /// The owner at the host's machine revokes the device.
    TheOwnerRevokesIt,
}

/// What reads the feed after a request is published in it.
enum AfterThePublication {
    /// The view that follows the revoke and the host read it as they do: the host can read the
    /// request as soon as that view connects to it, and a case's `host_polls` makes sure it has.
    TheFeedIsRead,
    /// The next sixty reads of the feed fail until the case mends the service: neither that view
    /// nor the host sees the request, so no refusal is written or seen meanwhile.
    NothingReadsTheFeed,
}

/// The person revokes the phone on the feed host, and `meanwhile` happens at the host while they
/// are at the dialog. The request is then published in the feed the host reads, and `after` says
/// what reads it.
async fn revokes_the_phone_while(rig: &Rig, meanwhile: Meanwhile, after: AfterThePublication) {
    let host = host_by(&rig.view().await, "feed");
    let body = json!({
        "host": host["reference"],
        "device": the_phone(&host)["reference"],
    });
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let revoking = rig.app.start_call("revocation_revoke", body);
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    if matches!(after, AfterThePublication::NothingReadsTheFeed) {
        // The next sixty reads of the feed fail, whoever makes them and whenever they come; the
        // publication, which is no read, is not met by a fault.
        for nth in 1..=60 {
            rig.served.web().fail_with_member(
                AUTHORITY,
                "read",
                nth,
                Moment::Refuse {
                    status: 503,
                    code: "SERVICE_UNAVAILABLE",
                    retry_after_seconds: None,
                },
            );
        }
    }
    match meanwhile {
        Meanwhile::TheHostStopsAllowingIt => {
            the_host_leaves_this_computer_no_right_to_manage_it(rig).await
        }
        Meanwhile::TheOwnerRevokesIt => {
            the_owner_at_the_machine_revokes_the_paired_device(rig).await
        }
    }
    release.notify_one();
    tokio::time::timeout(WATCHDOG, revoking)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect("the request is published: the service stores what any key publishes");
    assert_eq!(rig.publications(), 1);
}

/// What the host wrote against each request in its feed, as the host's owner reads the feed: the
/// reason it refused the request, or none.
async fn the_hosts_reasons(rig: &Rig) -> Vec<Option<RejectionReason>> {
    let origin = GatewayOrigin::new(rig.served.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport");
    let remote = AuthorityFeedClient::new(
        origin,
        Arc::new(http),
        Arc::new(Installation(rig.owner.authorisation.clone())),
    );
    let feed = rig
        .host
        .controller()
        .feed_runtime()
        .expect("a carrier")
        .feed();
    let page = remote
        .read(feed, None, false)
        .await
        .expect("the owner reads the feed");
    page.records
        .iter()
        .map(|record| record.rejected.0)
        .collect()
}

/// A request in the host's own feed that the host refuses, because by then this computer has no
/// right to manage it, can revoke nothing: the feed shows the refusal, and the person may share
/// the settings with the device again. This is the usual path, with the host reading the feed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_host_refuses_no_longer_keeps_its_device_from_being_shared_with_again() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revokes_the_phone_while(
        &rig,
        Meanwhile::TheHostStopsAllowingIt,
        AfterThePublication::TheFeedIsRead,
    )
    .await;
    the_phone_is_taken_out(&rig).await;

    // The host reads its feed and refuses the request. Nothing else is read of it here: what
    // lets the device go is what the feed shows of the request's own identity.
    rig.host_polls().await;
    assert_eq!(
        the_hosts_reasons(&rig).await,
        vec![Some(RejectionReason::NoOwnerAuthority)]
    );
    let devices = rig.devices();
    let reference = the_device_held_out(&devices);
    assert_eq!(
        devices["held_out"][0]["waiting"], false,
        "the feed shows the host refused the request, which can revoke nothing now: {devices}"
    );
    assert_eq!(
        host_by(&rig.view().await, "feed")["contact"],
        "refused",
        "the host no longer lists its devices to this computer"
    );
    share_again(&rig, &reference).expect("nothing waits for a host that refused the request");
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(2),
        "the phone holds the key again"
    );
    assert!(
        rig.ceremony
            .reasons()
            .contains(&"Share your settings with the-phone again".to_owned()),
        "{:?}",
        rig.ceremony.reasons()
    );
}

/// A request the host refuses as covered by another is not one that can revoke nothing: what covers
/// it has revoked the device, at a host that may sleep again and say nothing more, so the device
/// stays held. Here the owner at the host's machine revokes the phone while the person is at the
/// dialog.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_host_refuses_as_covered_by_another_keeps_its_device_held() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revokes_the_phone_while(
        &rig,
        Meanwhile::TheOwnerRevokesIt,
        AfterThePublication::TheFeedIsRead,
    )
    .await;
    the_phone_is_taken_out(&rig).await;

    rig.host_polls().await;
    assert_eq!(
        the_hosts_reasons(&rig).await,
        vec![Some(RejectionReason::Superseded)],
        "the host refuses what the owner at its machine already withdrew"
    );
    assert_not_shared_with_again(&rig);
}

/// A device never shared with whose request the host refused is offered again by the sheet's own
/// refresh: the refresh looks at the feeds when the sheet keeps a device out because of a revoke on
/// record, though that device was never taken out of the settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_never_shared_device_whose_request_the_host_refused_is_offered_again_by_the_refresh() {
    let rig = Rig::start().await;
    revokes_the_phone_while(
        &rig,
        Meanwhile::TheHostStopsAllowingIt,
        AfterThePublication::NothingReadsTheFeed,
    )
    .await;
    rig.start_settings_sync_listing_the_phone();
    let settings = rig
        .app
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open");
    let key = *rig.phone.keys().authorisation.public();
    assert!(
        settings.requests().holds(&key),
        "nothing read the feed since the publication, so the request is still on record"
    );
    assert!(
        !settings
            .revocations_sent(&[key])
            .await
            .expect("the step ends"),
        "there is no collection to take the phone out of"
    );
    settings.sync_turn_on().await.expect("settings sync is on");
    // Now the host reads its feed and refuses the request, and the feed can be read again.
    rig.served.web().mend();
    rig.host_polls().await;
    assert_eq!(
        the_hosts_reasons(&rig).await,
        vec![Some(RejectionReason::NoOwnerAuthority)]
    );

    let devices = rig.devices();
    assert_eq!(devices["held_out"], json!([]), "{devices}");
    let reference = devices["candidates"][0]["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("the phone is offered again: {devices}"))
        .to_owned();
    share_again(&rig, &reference).expect("nothing waits for a host that refused the request");
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(2),
        "the phone holds the key"
    );
}

/// A request sent while the person is at the dialog for sharing with a device that was never shared
/// with is a request in force by the time they confirm: the device is not given the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_sent_while_the_person_is_at_the_dialog_for_sharing_with_a_new_device_stops_it() {
    let rig = Rig::start().await;
    rig.start_settings_sync_listing_the_phone();
    rig.app
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open")
        .sync_turn_on()
        .await
        .expect("settings sync is on");
    let devices = rig.devices();
    let candidate = devices["candidates"][0]["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("the phone is offered: {devices}"))
        .to_owned();
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let sharing = rig
        .app
        .start_call("settings_device_share", json!({ "reference": candidate }));
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;
    revokes_the_phone(&rig).await;
    assert_eq!(published_at(&elsewhere), 1);
    release.notify_one();

    tokio::time::timeout(WATCHDOG, sharing)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect_err("a request is in force now, so the device is not given the key");
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(1),
        "the phone holds no key"
    );
}

/// A request the host carried out holds its device while the host sleeps: the hosts settings sync
/// asks list the device unrevoked (here a second host does), and the feed that showed the host's
/// acknowledgement is not what lets the device go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_a_host_carried_out_keeps_its_device_from_being_shared_with_again() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revokes_the_phone(&rig).await;
    rig.host_polls().await;
    let done = rig
        .view_until("the host's acknowledgement", |view| {
            phone_state(view, "feed") == "done"
        })
        .await;
    assert_eq!(phone_state(&done, "feed"), "done");
    the_phone_is_taken_out(&rig).await;

    rig.view().await;
    assert_not_shared_with_again(&rig);
}

/// A plain page after the service stored the request is not the service saying it refused the
/// request: the feed may hold it, and the device stays held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_is_not_the_services_does_not_let_a_stored_request_go() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    revoke_with_the_publication(&rig, Moment::ActedAndPage { status: 500 }).await;
    the_phone_is_taken_out(&rig).await;

    // No look can find the request again, so only the record made before the send holds it.
    the_feed_cannot_be_read(&rig.served);
    assert_not_shared_with_again(&rig);
}

/// A host the person forgets is one whose feed this computer no longer reads, so a request it left
/// there is not waited for: nothing could ever say it is settled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_in_the_feed_of_a_host_that_was_forgotten_is_not_waited_for() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    let _elsewhere = a_feed_the_host_does_not_read(&rig).await;
    let host = host_by(&rig.view().await, "feed");
    revokes_the_phone(&rig).await;
    the_phone_is_taken_out(&rig).await;
    let devices = rig.devices();
    the_device_held_out(&devices);
    assert_eq!(devices["held_out"][0]["waiting"], true, "{devices}");

    rig.app
        .call("hosts_forget", json!({ "reference": host["reference"] }))
        .expect("the host is forgotten");
    let devices = rig.devices();
    let reference = the_device_held_out(&devices);
    assert_eq!(devices["held_out"][0]["waiting"], false, "{devices}");
    share_again(&rig, &reference).expect("nothing waits for a host this computer forgot");
}

/// A request sent while the person is at the dialog for sharing again is a request in force by the
/// time they confirm: the device is not given the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_sent_while_the_person_is_at_the_dialog_for_sharing_again_stops_it() {
    let rig = Rig::start().await;
    rig.sharing_with_the_phone().await;
    // The first request never reached the feed, so nothing waits and the person may share again.
    revoke_with_the_publication(
        &rig,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: None,
        },
    )
    .await;
    the_phone_is_taken_out(&rig).await;
    let reference = the_device_held_out(&rig.devices());
    let elsewhere = a_feed_the_host_does_not_read(&rig).await;

    // The person is at the dialog for sharing again, and sends the request again meanwhile, to a
    // feed the host does not read.
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let sharing = rig
        .app
        .start_call("settings_device_share", json!({ "reference": reference }));
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    revokes_the_phone(&rig).await;
    assert_eq!(published_at(&elsewhere), 1);
    release.notify_one();

    tokio::time::timeout(WATCHDOG, sharing)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect_err("a request is in force now, so the device is not given the key");
    assert_eq!(
        rig.devices()["members"].as_array().map(Vec::len),
        Some(1),
        "the phone holds no key"
    );
}
