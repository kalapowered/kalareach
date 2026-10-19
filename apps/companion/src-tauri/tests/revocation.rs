//! Revoking a device on a host this computer owns, through the commands the page calls.
//!
//! The hosts are kr-controller's in-process daemon, the authority feed is the stand-in held to a
//! recording of the Worker's, and this computer is the companion's backend on the mock runtime,
//! recorded as an owner of the host. The daemon reads and answers the feed itself, so what the
//! screen is shown of an acknowledgement is what a real host wrote.
//!
//! KR-REQ-10.46: a remote owner publishes a signed revocation request to the host's durable feed
//! and the device list shows the host's last acknowledgement:
//! `a_revocation_is_called_done_only_once_the_hosts_acknowledgement_is_read`,
//! `a_host_that_reads_another_service_never_acknowledges_and_the_screen_never_calls_it_done`,
//! `a_host_that_does_not_answer_is_revoked_on_through_its_feed_from_the_list_last_seen` and
//! `a_host_the_feed_removed_is_not_reached_by_feed_and_nothing_is_published`.
//! KR-REQ-10.01: the page never performs `device.revoke`; the host on this computer takes it from
//! native code over its own connection:
//! `the_host_on_this_computer_takes_the_revocation_itself_and_its_answer_is_the_acknowledgement`.
//! `a_revocation_the_person_does_not_confirm_sends_nothing` holds the ceremony in front of both.

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
use kr_client::services::authority::AuthorityFeedClient;
use kr_client::services::{HttpDeadlines, HttpService, ServiceSigner, managed_response_limits};
use kr_controller::service::Clocks;
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{MemoryStore, SecretStore, store_device_keys};
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Moment, Served, serve};
use net_support::{Device, Host, pair_with, proposal};
use serde_json::{Value, json};
use support::{Companion, StubPaste};
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
    /// The device the host paired, which is the one that is revoked.
    phone: Device,
}

impl Rig {
    async fn start() -> Self {
        let served = serve().await;
        let owner = DeviceKeys::generate().expect("owner keys");
        let timer = HeldTimer::held();
        let host = Host::start_with_feed_on(
            &owner,
            served.origin(),
            Arc::clone(&timer) as _,
            Clocks::system(),
        )
        .await;
        let phone = Device::create().await;
        pair_with(&host, &phone, &owner, proposal(&[ActionRight::SessionView])).await;

        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        store_device_keys(&*secrets, "device", &owner).expect("the owner's keys are kept");
        let data = tempfile::tempdir().expect("a directory");
        let ceremony = Scripted::new(CeremonyOutcome::Confirmed);
        let app = Companion::start(
            data.path(),
            support::parts(secrets, Arc::new(host.room.clone())),
            Arc::clone(&ceremony) as Arc<dyn Ceremony>,
            StubPaste::holding("", false),
        );
        support::record_owned(&app.device(), &host, "the test host");
        companion_tauri::start_sync_service(app.app.handle(), data.path());
        let rig = Self {
            host,
            served,
            owner,
            ceremony,
            app,
            data,
            phone,
        };
        rig.sync_service_is(rig.served.origin());
        // The passes the start and the pairing asked for end before anything connects: a
        // connection admitted while one runs is withdrawn when it finishes.
        rig.host_polls().await;
        rig
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
    assert_eq!(rig.ceremony.reasons().len(), 1);
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
    let view = rig.view().await;
    let host = host_by(&view, "feed");
    let phone = the_phone(&host);
    let body = json!({ "host": host["reference"], "device": phone["reference"] });
    let (shown, release) = rig.ceremony.hold_the_dialog();
    let call = rig.app.start_call("revocation_revoke", body);
    tokio::time::timeout(WATCHDOG, shown.notified())
        .await
        .expect("the dialog is shown");
    // The host has read its feed by now, so the next request to the feed is the publication.
    rig.host_polls().await;
    rig.served.web().fail(AUTHORITY, 1, Moment::ActedAndUnknown);
    release.notify_one();

    let lost = tokio::time::timeout(WATCHDOG, call)
        .await
        .expect("the call ends")
        .expect("the call ends")
        .expect_err("the service could not say whether it took effect");
    assert_eq!(rig.publications(), 1, "the service stored the request");
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

    the_owner_at_the_machine_revokes_the_paired_device(&rig).await;

    // The host keeps the connection and refuses what is asked over it, which is its way of saying to
    // open another. A request made straight over the session, as any path of the application may
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
    let _: HostInfoResult = second
        .read(Method::HostInfo, &json!({}))
        .await
        .expect("the connection the application then holds is one the host admits");
    rig.app
        .call("host_info", json!({}))
        .expect("a command goes through on it");
    // One withdrawal asked the host one question, over one other connection: what the question was
    // itself refused, over the connection it asked about, was not another.
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
