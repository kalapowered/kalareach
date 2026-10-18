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
}

impl Scripted {
    fn new(answer: CeremonyOutcome) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            asked: Mutex::new(Vec::new()),
        })
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
        Box::pin(async move { answer })
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

    /// This computer takes part in settings sync, over a collection of its own.
    async fn with_settings_sync(&self) {
        let device = self.app.device();
        companion_tauri::start_settings_sync(
            self.app.app.handle(),
            self.data.path(),
            device.identity(),
            Arc::new(NoHosts),
            Arc::clone(&self.ceremony) as Arc<dyn Ceremony>,
        )
        .expect("settings sync opens");
        self.app
            .app
            .state::<AppState>()
            .settings()
            .expect("settings are open")
            .sync_turn_on()
            .await
            .expect("settings sync is on");
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
    let phone_key = *rig.phone.keys().authorisation.public();
    let membership = rig.data.path().join("settings-sync").join("membership");
    tokio::time::timeout(WATCHDOG, async {
        while !somewhere_in(&membership, phone_key.as_bytes()) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("settings sync is told of the revoked device");
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
async fn the_host_on_this_computer_takes_the_revocation_itself_and_its_answer_is_the_acknowledgement()
 {
    let rig = Rig::start().await;
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
    let again = rig
        .revoke(
            local["reference"].as_str().expect("a reference"),
            phone["reference"].as_str().expect("a reference"),
        )
        .expect_err("it is revoked");
    assert_eq!(again["code"], "PERMISSION_DENIED", "{again}");
}
