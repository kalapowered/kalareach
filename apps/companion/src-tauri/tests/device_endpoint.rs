//! This computer's one device endpoint, through the commands the page calls and the member check
//! that settings sync makes.
//!
//! The hosts are kr-controller's in-process daemons. Two of them name the same relay and resolve
//! through different services, as two hosts of one person on one provider's relay can; this
//! computer is the companion's backend on the mock runtime, recorded as an owner of each. Nothing
//! reaches beyond the loopback interface: a relay and a resolver here are addresses where nothing
//! answers, and the hosts are reached at their own addresses.

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::Arc;

use companion_platform::notify::{Permission, PreviewKeys};
use companion_platform::push::PendingRegistration;
use companion_tauri::AppState;
use companion_tauri::inbox::{HostInbox, InboxDesk};
use companion_tauri::push::{HostLine, Native, PushDesk, PushFuture, Reach, Registrar, Wiring};
use companion_tauri::settings::Hosts as _;
use companion_tauri::settings::connected::ConnectedHosts;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
use kr_client::pairing::paired::PairedHost;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretStore, store_device_keys};
use kr_protocol::ids::{ActionId, DeviceId, SessionId};
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::sharing::{DeviceRevokeParams, RevocationResult};
use kr_service_stand_in::{Served, serve};
use net_support::pairing::{self as calls, Signer};
use net_support::worker::{Adopted, Worker};
use net_support::{Device, Host};
use serde_json::{Value, json};
use support::{
    Companion, LinkControl, Phone, StubIntake, WATCHDOG, govern, on_relay, pair,
    unpaired_phone_controlled,
};
use tauri::Manager as _;

/// The relay the hosts name. Nothing answers at it: a host is reached at its own address.
const RELAY: &str = "https://127.0.0.1:9";

/// The two address lookup services the hosts resolve through. Nothing answers at either.
const FIRST_RESOLVER: &str = "http://127.0.0.1:9/pkarr";
const SECOND_RESOLVER: &str = "http://127.0.0.1:10/pkarr";

/// The platform's ceremony, answered as the person confirms every time.
struct Confirms;

impl Ceremony for Confirms {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(
        &'a self,
        _reason: &'a str,
        _within: std::time::Duration,
    ) -> BoxFuture<'a, CeremonyOutcome> {
        Box::pin(async { CeremonyOutcome::Confirmed })
    }
}

/// A host on `RELAY` that resolves through `resolver` and serves one session.
async fn host_with_a_session(owner: &DeviceKeys, resolver: &str) -> Adopted {
    let host = Host::start_with_endpoint(owner, on_relay(RELAY, resolver)).await;
    // The daemon is stopped, the session's worker is started on its tree, and the daemon is started
    // again on the same settings and adopts it.
    let stopped = host.shut_down().await;
    let worker = Worker::start_reserved(stopped.tree(), 1).await;
    let settings = stopped.settings().clone();
    let adopted = Adopted {
        host: stopped.start(settings).await,
        owner: owner.clone(),
        workers: vec![worker],
    };
    adopted.until_adopted(&adopted.workers[0]).await;
    adopted
}

/// Another device of the person's, paired with `host` as an owner device, and the identity the
/// host gave it.
async fn another_owner_device(host: &Host, owner: &DeviceKeys) -> (Device, DeviceId) {
    let device = Device::create().await;
    let signer = Signer::OwnerDevice(owner);
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &kr_pairing::grants::personal_owner_grant(),
        &signer,
    )
    .await
    .expect("an owner invitation");
    // Only a computer's own platform can share the settings.
    let mut candidate = device.candidate();
    candidate.declared.platform = kr_protocol::pairing::DevicePlatform::Macos;
    let (connection, _candidate, _value) = calls::redeem(&candidate, &invited).await;
    let confirmed = calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner confirms the device");
    connection.close(0u32.into(), b"paired");
    (device, confirmed.device_id)
}

/// The first entry's reference of `list`, which a page names a device by.
fn first_reference(list: &Value) -> String {
    list[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned()
}

/// Waits until `connection_state` says `connected`.
async fn connected(companion: &Companion) {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == true {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the application is connected");
}

/// The text of the lines a view state shows.
fn text_of(state: &Value) -> String {
    state["screen"]["lines"]
        .as_array()
        .map(|lines| {
            lines
                .iter()
                .map(|line| {
                    line["pieces"]
                        .as_array()
                        .expect("pieces")
                        .iter()
                        .map(|piece| piece["text"].as_str().expect("text").to_owned())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Everything one case holds: two hosts of one person on one relay with different resolvers, the
/// first serving a session, a second owner device that only the second host lists, and this
/// computer as the owner of both, with settings sync on.
struct Rig {
    _served: Served,
    companion: Companion,
    /// What the case does to the connections this computer makes, and what it reads of the one
    /// device endpoint they share.
    control: Arc<LinkControl>,
    /// The identity the second host gave the second owner device.
    other: DeviceId,
    _other_device: Device,
    _data: tempfile::TempDir,
    // Declared last: the hosts' directories are removed after everything above has let go.
    second: Host,
    first: Adopted,
}

impl Rig {
    async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let first = host_with_a_session(&owner, FIRST_RESOLVER).await;
        let second = Host::start_with_endpoint(&owner, on_relay(RELAY, SECOND_RESOLVER)).await;
        let (other_device, other) = another_owner_device(&second, &owner).await;

        let served = serve().await;
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        store_device_keys(&*secrets, "device", &owner).expect("the owner's keys are kept");
        let data = tempfile::tempdir().expect("a directory");
        let control = LinkControl::new();
        let mut governed = support::parts(Arc::clone(&secrets), Arc::new(first.host.room.clone()));
        govern(&mut governed, &control);
        let companion = Companion::start(
            data.path(),
            governed,
            Arc::new(Confirms),
            StubIntake::holding("", false),
        );
        let device = companion.device();
        support::record_owned(&device, &first.host, "first");
        support::record_owned(&device, &second, "second");

        companion_tauri::start_sync_service(companion.app.handle(), data.path());
        companion
            .app
            .state::<AppState>()
            .sync_service()
            .expect("the setting is open")
            .set(served.origin())
            .expect("an origin");
        companion_tauri::start_settings_sync(
            companion.app.handle(),
            device.identity(),
            Arc::new(ConnectedHosts::new(companion.app.handle().clone())),
            Arc::new(Confirms),
        )
        .expect("settings sync opens");
        companion
            .app
            .state::<AppState>()
            .settings()
            .expect("settings are open")
            .sync_turn_on()
            .await
            .expect("settings sync is on");
        Self {
            _served: served,
            companion,
            control,
            other,
            _other_device: other_device,
            _data: data,
            second,
            first,
        }
    }

    /// The devices that share this computer's settings, after the hosts are asked: the member
    /// check, as the settings screen's refresh makes it.
    fn devices(&self) -> Value {
        self.companion
            .call("settings_devices_refresh", json!({}))
            .expect("the settings view")["sync"]["devices"]
            .clone()
    }

    /// What the hosts say of their devices when this computer asks all of them, as the member
    /// check asks.
    async fn asked(&self) -> companion_tauri::settings::HostLists {
        ConnectedHosts::new(self.companion.app.handle().clone())
            .device_lists()
            .await
    }

    /// The session the first host serves.
    fn session(&self) -> SessionId {
        self.first.workers[0].session_id
    }

    /// The second host revokes the second owner device.
    async fn second_host_revokes_the_other_device(&self) {
        let mut client = self.second.client().await;
        let _: RevocationResult = calls::mutate(
            self.second.environment_id,
            &mut client,
            Method::DeviceRevoke,
            &DeviceRevokeParams {
                device_id: self.other,
            },
        )
        .await
        .expect("the host revokes the device");
    }
}

/// A host in use keeps its terminal view while the member check asks another owned host, one on the
/// same relay with another resolver, and that host's word that it revoked a device is heard: the
/// device is taken out of the settings' membership, so the next key is not wrapped to it. The
/// terminal view of the host in use publishes nothing between, and takes the person's typing after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_in_use_keeps_its_terminal_view_while_the_member_check_asks_a_host_that_revoked_a_device()
 {
    let rig = Rig::start().await;
    let companion = &rig.companion;

    // (1) No host is in use. The person shares the settings with the second owner device, which only
    // the second host lists, and a first member check asks both hosts and hears both.
    let offered = rig.devices();
    assert_eq!(
        offered["candidates"].as_array().expect("candidates").len(),
        1,
        "only the second host lists another owner device: {offered}"
    );
    companion
        .call(
            "settings_device_share",
            json!({ "reference": first_reference(&offered["candidates"]) }),
        )
        .expect("the person shares with the device");
    let before = rig.asked().await;
    assert!(!before.silent && !before.refused, "both hosts answered");
    assert_eq!(before.lists.len(), 2, "both hosts listed their devices");
    let members = rig.devices()["members"].as_array().expect("members").len();
    assert_eq!(members, 2, "the device holds the key: {members}");

    // (2) The person chooses the first host, and its terminal view opens and answers.
    let first = reference_for(companion, &rig.first.host);
    companion
        .call("hosts_use", json!({ "reference": first }))
        .expect("the first host is chosen");
    connected(companion).await;
    companion
        .call(
            "session_open",
            json!({
                "sessionId": rig.session().to_string(),
                "grantId": null,
                "opening": "terminal-screen",
            }),
        )
        .expect("the session opens");
    let view = companion
        .call(
            "terminal_view_open",
            json!({
                "sessionId": rig.session().to_string(),
                "columns": 40,
                "rows": 8,
                "opening": "terminal-screen",
                "onState": "__CHANNEL__:11",
            }),
        )
        .expect("the view opens")
        .as_str()
        .expect("the view's handle")
        .to_owned();
    companion
        .state_where(11, |state| state["state"] == "showing")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("the take is taken");
    companion
        .state_where(11, |state| state["control"]["state"] == "controlling")
        .await;
    let published = companion.states(11).len();

    // (3) The second host revokes the second owner device. (4) The member check runs again, over
    // every owned host beside the one in use: first as the settings' own refresh, which drops the
    // revoked device from the members only when the second host's word is heard, and then as the
    // check's own lists.
    rig.second_host_revokes_the_other_device().await;
    let members = rig.devices()["members"].as_array().expect("members").len();
    assert_eq!(
        members, 1,
        "the revoked device is not retained, so the next key is not wrapped to it"
    );
    let after = rig.asked().await;
    assert!(
        !after.silent && !after.refused,
        "the second host answered, and was not counted silent or refused"
    );
    assert!(
        after.lists.iter().any(|list| list
            .devices
            .iter()
            .any(|device| device.device_id == rig.other && device.revoked)),
        "an answer says the device was revoked"
    );

    // The terminal view is the same connection: nothing ended or began again in it, and it takes
    // the person's typing.
    let states = companion.states(11);
    assert!(
        states[published..]
            .iter()
            .all(|state| state["state"] == "showing"),
        "the view published no state but a showing one since: {:?}",
        &states[published..]
    );
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "text", "take": 1, "text": "after-the-check" } }),
        )
        .expect("the view takes typing after the check");
    companion
        .state_where(11, |state| text_of(state).contains("after-the-check"))
        .await;
    assert_eq!(
        companion
            .call("connection_state", json!({}))
            .expect("the connection's state")["connected"],
        true,
        "the host in use is still connected"
    );
    assert_eq!(
        rig.control.relay_urls().await,
        relays(&[RELAY]),
        "both hosts named one relay, and the one endpoint holds it once"
    );
}

/// What the relays `urls` name are, as the device's endpoint holds them in its relay map.
fn relays(urls: &[&str]) -> std::collections::BTreeSet<String> {
    urls.iter()
        .map(|url| {
            url.parse::<iroh::RelayUrl>()
                .expect("a relay URL")
                .to_string()
        })
        .collect()
}

/// What the page names `host` by, from the pairing screen, without choosing it.
fn reference_for(companion: &Companion, host: &Host) -> String {
    let device = companion.device();
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .filter_map(|row| row["reference"].as_str())
        .find(|reference| {
            device
                .host_by_reference(reference)
                .is_some_and(|paired| paired.host_endpoint_id == host.network().endpoint_id())
        })
        .expect("the host is listed")
        .to_owned()
}

/// A host of `owner` that names `relays` and resolves through `resolver`.
async fn host_on(owner: &DeviceKeys, relays: &[&str], resolver: &str) -> Host {
    let mut endpoint = on_relay(relays[0], resolver);
    endpoint.relay_urls = relays
        .iter()
        .map(|relay| relay.parse().expect("a relay URL"))
        .collect();
    Host::start_with_endpoint(owner, endpoint).await
}

/// A paired host that the run did not dial is not in the device's relay map: the application starts
/// over its records of three paired hosts and reaches the one in use, and the map holds that host's
/// relay and neither of the others'. Reaching the second adds its relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_host_the_run_did_not_dial_is_not_in_the_map() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let first = host_on(&owner, &["https://127.0.0.1:11"], FIRST_RESOLVER).await;
    let second = host_on(&owner, &["https://127.0.0.1:12"], SECOND_RESOLVER).await;
    let third = host_on(&owner, &["https://127.0.0.1:13"], FIRST_RESOLVER).await;

    // The person pairs with the three hosts, the first is the one in use, and the application is
    // closed.
    let phone = unpaired_phone_controlled(&first, &LinkControl::new());
    for host in [&first, &second, &third] {
        pair(&phone, host, &owner, &[ActionRight::SessionView]).await;
    }
    connected(&phone.companion).await;
    let Phone {
        companion,
        secrets,
        room,
        data,
        ..
    } = phone;
    drop(companion);

    // The application starts again over the same records, and takes up the host in use.
    let control = LinkControl::new();
    let mut governed = support::parts(secrets, room);
    govern(&mut governed, &control);
    let companion = Companion::start(
        data.path(),
        governed,
        Arc::new(Confirms),
        StubIntake::holding("", false),
    );
    companion_tauri::hosts::resume(companion.app.handle());
    connected(&companion).await;
    assert_eq!(
        control.relay_urls().await,
        relays(&["https://127.0.0.1:11"]),
        "the map holds the host the run dialled and neither of the others"
    );

    let used = companion
        .call(
            "hosts_use",
            json!({ "reference": reference_for(&companion, &second) }),
        )
        .expect("the second host is chosen");
    assert_eq!(used["connected"], true, "{used}");
    assert_eq!(
        control.relay_urls().await,
        relays(&["https://127.0.0.1:11", "https://127.0.0.1:12"]),
        "the second host's relay joins the map when the second host is dialled"
    );
}

/// Forgetting a host takes it out of the device's one endpoint before the command returns: the
/// records already hold no such host when the link is told to forget it, and the relay map holds
/// none that only that host named afterwards. The relay the two hosts share stays, and the host
/// that is kept still answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgetting_a_host_takes_it_out_of_the_one_endpoint() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let kept = host_on(&owner, &["https://127.0.0.1:11"], FIRST_RESOLVER).await;
    let forgotten = host_on(
        &owner,
        &["https://127.0.0.1:11", "https://127.0.0.1:12"],
        SECOND_RESOLVER,
    )
    .await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&kept, &control);
    pair(&phone, &kept, &owner, &[ActionRight::SessionView]).await;
    pair(&phone, &forgotten, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    let device = companion.device();

    // Both hosts are reached, so both are in the endpoint, and the kept one is the one in use.
    for host in [&forgotten, &kept] {
        let used = companion
            .call(
                "hosts_use",
                json!({ "reference": reference_for(companion, host) }),
            )
            .expect("the host is chosen");
        assert_eq!(used["connected"], true, "{used}");
    }
    assert_eq!(
        control.relay_urls().await,
        relays(&["https://127.0.0.1:11", "https://127.0.0.1:12"])
    );

    let reference = reference_for(companion, &forgotten);
    // What the records hold at the moment the link is told to forget the host: the state's forgetting
    // comes first, so a host that the endpoint is asked about is one the records no longer list.
    let at_the_call = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (device, reference, seen) = (
            Arc::clone(&device),
            reference.clone(),
            Arc::clone(&at_the_call),
        );
        control.at_the_forget(move || {
            seen.lock()
                .expect("the record")
                .push(device.host_by_reference(&reference).is_none());
        });
    }
    companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the host is forgotten");

    // The link was told once, and the records already held no such host when it was.
    assert_eq!(
        *at_the_call.lock().expect("the record"),
        vec![true],
        "the link forgot the host once, after the records let it go"
    );
    // The command has returned: the state holds no such host, and the endpoint's relay addresses
    // hold the one both hosts named and not the one only the forgotten host named.
    assert!(
        device.host_by_reference(&reference).is_none(),
        "the records hold no such host"
    );
    assert_eq!(
        control.relay_urls().await,
        relays(&["https://127.0.0.1:11"]),
        "the relay only the forgotten host named left the map, and the shared one stayed"
    );
    companion
        .call(
            "session_list",
            json!({ "params": { "environment_id": null, "include_closed": false } }),
        )
        .expect("the host that is kept still answers");
}

/// Waits, on a thread of its own, until `ready` holds. A hook holds the path that is waited on, so
/// the wait is made by a blocking thread and no timer of the runtime.
async fn until(what: &'static str, ready: impl Fn() -> bool + Send + 'static) {
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + WATCHDOG;
        while !ready() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    })
    .await
    .expect("the wait ran");
}

/// The record this application holds now of the paired host `host`.
fn record_of(device: &companion_tauri::device::Device, host: &Host) -> PairedHost {
    device
        .pairing()
        .hosts
        .list()
        .expect("the records")
        .into_iter()
        .find(|paired| paired.host_endpoint_id == host.network().endpoint_id())
        .expect("the host is recorded")
}

/// A visit of the inbox, as the application makes one, started now: it asks every paired host that
/// is not the one in use.
fn visit_started(
    desk: &Arc<InboxDesk>,
    device: &Arc<companion_tauri::device::Device>,
) -> tokio::task::JoinHandle<Vec<HostInbox>> {
    let (desk, device) = (Arc::clone(desk), Arc::clone(device));
    tokio::spawn(async move { desk.visit(&device).await })
}

/// A visit that began before the person forgot a host does not put the host back into the device's
/// endpoint, in each order that the forget and the visit's dial can meet, and another pairing with
/// the same host is admitted at once while the forgotten pairing's dial stays refused. The visit is the
/// inbox's own, over a paired host that is not the one in use; the host's unshared relay is the
/// evidence, for it enters the map only when the host is introduced.
///
/// (a) The forget returns before the visit's dial reaches the endpoint: the dial is refused and does
/// not even reach the introduction. (b) The forget begins while the dial is held between its decision
/// and its introduction: the forget waits for the introduction and then takes the host out. (c) The
/// forget lands after the dial introduced the host and its connection is made, before the visit is
/// given the connection: the forget takes the host out under the visit, and the visit that ends
/// afterwards leaves the host out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_that_began_before_the_forget_does_not_put_the_host_back() {
    const SHARED: &str = "https://127.0.0.1:11";
    let owner = DeviceKeys::generate().expect("owner keys");
    let kept = host_on(&owner, &[SHARED], FIRST_RESOLVER).await;
    let first = host_on(&owner, &[SHARED, "https://127.0.0.1:12"], SECOND_RESOLVER).await;
    let second = host_on(&owner, &[SHARED, "https://127.0.0.1:13"], SECOND_RESOLVER).await;
    let third = host_on(&owner, &[SHARED, "https://127.0.0.1:14"], SECOND_RESOLVER).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&kept, &control);
    let companion = &phone.companion;
    let device = companion.device();
    pair(&phone, &kept, &owner, &[ActionRight::SessionView]).await;
    let used = companion
        .call(
            "hosts_use",
            json!({ "reference": reference_for(companion, &kept) }),
        )
        .expect("the kept host is chosen");
    assert_eq!(used["connected"], true, "{used}");
    let desk = Arc::new(InboxDesk::default());
    let forget = |host: &Host| {
        companion
            .call(
                "hosts_forget",
                json!({ "reference": reference_for(companion, host) }),
            )
            .expect("the host is forgotten");
    };

    // (a) The visit's dial is held on its way to the endpoint, the person forgets the host and the
    // command returns, and the dial is let go.
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let old = record_of(&device, &first);
    let at_the_introduction = control.hold_next_introduce_of(&old.host_endpoint_id);
    at_the_introduction.release();
    control.hold();
    let visit = visit_started(&desk, &device);
    until("the visit's dial is held on its way to the endpoint", {
        let control = Arc::clone(&control);
        move || control.held() >= 1
    })
    .await;
    forget(&first);
    control.stop_holding();
    control.release_all();
    let found = visit.await.expect("the visit ran");
    assert!(
        found.is_empty(),
        "the forgotten host is not reported: {found:?}"
    );
    assert!(
        !at_the_introduction.is_reached(),
        "the refused dial never reached the introduction"
    );
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED]),
        "the forgotten host's own relay was not put back"
    );

    // (b) The visit's dial is let through to the endpoint and held between its decision and the
    // introduction, and the person forgets the host while it is held. The forget waits for the
    // introduction, so the dial is let go when the link is told to forget, and the forget then takes
    // the host out.
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let at_the_introduction =
        Arc::new(control.hold_next_introduce_of(&record_of(&device, &second).host_endpoint_id));
    control.hold();
    let visit = visit_started(&desk, &device);
    until("the visit's dial is held on its way to the endpoint", {
        let control = Arc::clone(&control);
        move || control.held() >= 1
    })
    .await;
    control.stop_holding();
    control.release_all();
    until("the visit's dial is held at the introduction", {
        let at_the_introduction = Arc::clone(&at_the_introduction);
        move || at_the_introduction.is_reached()
    })
    .await;
    control.at_the_forget({
        let at_the_introduction = Arc::clone(&at_the_introduction);
        move || at_the_introduction.release()
    });
    forget(&second);
    let found = visit.await.expect("the visit ran");
    assert!(
        found.is_empty(),
        "the forgotten host is not reported: {found:?}"
    );
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED]),
        "the forget took out the host that the dial introduced while it waited"
    );

    // (c) The visit's connection is held once it is made, after the endpoint took its host in, the
    // person forgets the host, and the connection is let go.
    pair(&phone, &third, &owner, &[ActionRight::SessionView]).await;
    let arrivals = control.hold_dialled(record_of(&device, &third).host_endpoint_id);
    let visit = visit_started(&desk, &device);
    tokio::task::spawn_blocking(move || arrivals.recv_timeout(WATCHDOG))
        .await
        .expect("the wait ran")
        .expect("the visit's connection reaches the hold");
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED, "https://127.0.0.1:14"]),
        "the endpoint took the visited host in"
    );
    forget(&third);
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED]),
        "the forget took the host out of the endpoint under the visit"
    );
    control.release_dialled();
    let found = visit.await.expect("the visit ran");
    assert!(
        found.is_empty(),
        "the forgotten host is not reported: {found:?}"
    );
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED]),
        "the visit that ended after the forget left the host out"
    );

    // Another pairing with the same host has an identity of its own, so nothing admits it and nothing
    // refuses it: the endpoint takes its host in at once, its relay is in the map, and the dial of the
    // forgotten pairing stays refused. (The host's store holds one row for each endpoint of a device,
    // so this computer cannot be paired with the same host a second time; the second pairing is the
    // record that a new pairing would have written, with the identity the host would have given.)
    let new = PairedHost {
        device_id: DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        ..old.clone()
    };
    assert_ne!(new.device_id, old.device_id);
    device
        .pairing()
        .hosts
        .record(new.clone())
        .expect("the record of the new pairing is kept");
    control
        .dial_as(&new)
        .await
        .expect("the endpoint takes the host of the new pairing in");
    assert_eq!(
        control.relay_urls().await,
        relays(&[SHARED, "https://127.0.0.1:12"]),
        "the new pairing's relay is in the map"
    );
    assert!(
        control.dial_as(&old).await.is_err(),
        "the dial of the forgotten pairing is refused"
    );
}

/// A push desk's registrar that remembers which hosts it was told to forget.
#[derive(Default)]
struct Registrations {
    forgotten: std::sync::Mutex<Vec<DeviceId>>,
}

impl Registrar for Registrations {
    fn connect<'a>(
        &'a self,
        _host: &'a PairedHost,
        _reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>> {
        Box::pin(async { Err("this case registers nothing".to_owned()) })
    }

    fn can_ask(&self, _host: DeviceId, _action: ActionId) -> bool {
        false
    }

    fn forgotten(&self, host: DeviceId) {
        self.forgotten.lock().expect("the record").push(host);
    }
}

/// A platform that gives the desk no notifications: the case runs no registration.
struct NoNotifications;

impl Native for NoNotifications {
    fn permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async { Err("no notifications here".to_owned()) })
    }

    fn ask_permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async { Err("no notifications here".to_owned()) })
    }

    fn token(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async { Ok(None) })
    }

    fn pending_set<'a>(&'a self, _record: &'a PendingRegistration) -> PushFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>> {
        Box::pin(async { Ok(None) })
    }

    fn preview_keys<'a>(&'a self, _keys: &'a PreviewKeys) -> PushFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn route(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async { Ok(None) })
    }
}

/// The forget command's local cleanup is done when the link is told to forget the host, and the
/// link's forget, which may wait, comes after it: the push desk's registrar has been told to forget
/// the host, and the inbox has closed the connection it kept to it. The case reads both at the link's
/// own forget call, which a command that does its cleanup after the wait would fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_cleanup_is_done_when_the_link_is_told_to_forget_the_host() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let kept = host_on(&owner, &["https://127.0.0.1:11"], FIRST_RESOLVER).await;
    let visited = host_on(&owner, &["https://127.0.0.1:12"], SECOND_RESOLVER).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&kept, &control);
    let companion = &phone.companion;
    let device = companion.device();
    pair(&phone, &kept, &owner, &[ActionRight::SessionView]).await;
    pair(&phone, &visited, &owner, &[ActionRight::SessionView]).await;
    let used = companion
        .call(
            "hosts_use",
            json!({ "reference": reference_for(companion, &kept) }),
        )
        .expect("the kept host is chosen");
    assert_eq!(used["connected"], true, "{used}");

    // The desk remembers what its registrar is told, and the inbox keeps a connection to the host
    // that is not in use after it has visited it.
    let registrations = Arc::new(Registrations::default());
    let data = tempfile::tempdir().expect("a directory");
    let state = companion.app.state::<AppState>();
    state.push_opened(PushDesk::open(
        data.path(),
        Arc::clone(&device),
        Arc::new(NoNotifications),
        Arc::clone(&registrations) as Arc<dyn Registrar>,
        Wiring::product().expect("the product's wiring"),
        |_| {},
    ));
    state.inbox().visit(&device).await;
    let record = record_of(&device, &visited);
    assert!(
        registrations
            .forgotten
            .lock()
            .expect("the record")
            .is_empty(),
        "the control: nothing was forgotten before the command"
    );

    let (closed_before, seen) = (
        control.closed(),
        Arc::new(std::sync::Mutex::new(Vec::new())),
    );
    control.at_the_forget({
        let (control, registrations, seen) = (
            Arc::clone(&control),
            Arc::clone(&registrations),
            Arc::clone(&seen),
        );
        let host = record.host_device_id;
        move || {
            seen.lock().expect("the record").push((
                registrations
                    .forgotten
                    .lock()
                    .expect("the record")
                    .contains(&host),
                control.closed() > closed_before,
            ));
        }
    });
    companion
        .call(
            "hosts_forget",
            json!({ "reference": reference_for(companion, &visited) }),
        )
        .expect("the host is forgotten");

    assert_eq!(
        *seen.lock().expect("the record"),
        vec![(true, true)],
        "at the link's forget call the push desk was told and the inbox had closed its connection"
    );
}
