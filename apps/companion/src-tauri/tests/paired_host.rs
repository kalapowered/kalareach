//! A phone's commands go to the host it is paired with.
//!
//! The daemon is kr-controller's in-process host, with its test support included by path, and the
//! device is this crate's own backend on the mock runtime: it pairs with the host through the
//! commands the page calls, takes the host as the one its commands go to, and reads through the
//! paired connection, with the rights its grant carries. Nothing here makes a voice call.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-13.08 | `a_paired_host_answers_the_commands_the_page_calls` |
//! | KR-REQ-13.08 | `a_host_that_comes_back_is_reached_again` |
//! | KR-REQ-13.08 | `a_host_chosen_before_is_reached_again_when_the_application_starts` |
//! | KR-REQ-13.08 | `choosing_between_two_paired_hosts_goes_to_the_one_chosen_last` |
//! | KR-REQ-13.08 | `a_choice_of_host_that_cannot_be_kept_is_not_made` |
//! | KR-REQ-13.08 | `a_phone_its_host_revoked_can_forget_that_host` |
//! | KR-REQ-13.08 | `forgetting_the_host_in_use_ends_the_connection_to_it` |
//! | KR-REQ-13.08 | `a_forget_whose_write_reports_a_failure_once_the_record_is_gone_still_ends_the_connection` |
//! | KR-REQ-13.08 | `a_choice_made_from_a_listing_that_has_since_forgotten_the_host_is_refused` |
//! | KR-REQ-13.08 | `forgetting_a_host_that_is_not_in_use_leaves_the_commands_going_to_the_other` |
//! | KR-REQ-15.21 | `a_voice_screen_opens_once_the_person_has_allowed_what_it_may_do` |

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::CandidateRoom;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretStore};
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::sharing::{DeviceRevokeParams, RevocationResult};
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use serde_json::json;
use support::{Companion, StubPaste, WATCHDOG};

/// A ceremony nobody is asked: these devices own nothing.
struct NoOwner;

impl Ceremony for NoOwner {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, _reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        Box::pin(async { CeremonyOutcome::NotConfirmed })
    }
}

/// This computer as a phone: its backend, the pasteboard the person copies an invitation to, the
/// secret store its keys live in and the directory its records live in.
struct Phone {
    companion: Companion,
    paste: Arc<StubPaste>,
    secrets: Arc<dyn SecretStore>,
    room: Arc<dyn CandidateRoom>,
    data: tempfile::TempDir,
}

/// A phone that has paired with nothing.
fn unpaired_phone(host: &Host) -> Phone {
    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let room: Arc<dyn CandidateRoom> = Arc::new(host.room.clone());
    let paste = StubPaste::holding("", false);
    let companion = Companion::start(
        data.path(),
        support::parts(Arc::clone(&secrets), Arc::clone(&room)),
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::PastePlatform>,
    );
    Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    }
}

/// `phone` paired with `host` as a device holding `rights`, by a direct invitation the person
/// pastes and the host's owner approves.
async fn pair(phone: &Phone, host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) {
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(owner);
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(rights),
        &signer,
    )
    .await
    .expect("a direct invitation");
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation");
    };
    phone.paste.copy(qr_text.as_str(), false);
    let companion = &phone.companion;
    companion
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    companion
        .call("pairing_start_read", json!({}))
        .expect("pairing starts");
    companion
        .reached(|state| state["state"] == "awaiting_approval")
        .await;
    calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves");
    companion.reached(|state| state["state"] == "paired").await;
}

/// A phone paired with `host` as a device holding `rights`.
async fn phone_paired_with(host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) -> Phone {
    let phone = unpaired_phone(host);
    pair(&phone, host, owner, rights).await;
    phone
}

/// This computer paired with `host` as a device holding `rights`, and the data directory its
/// records live in.
async fn paired_with(
    host: &Host,
    owner: &DeviceKeys,
    rights: &[ActionRight],
) -> (Companion, tempfile::TempDir) {
    let phone = phone_paired_with(host, owner, rights).await;
    (phone.companion, phone.data)
}

/// The reference the pairing screen gives the one host this computer is paired with.
fn the_host(companion: &Companion) -> String {
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    view["hosts"][0]["reference"]
        .as_str()
        .expect("a reference to the host")
        .to_owned()
}

/// The parameters of a list of every session, as the page sends them.
fn every_session() -> serde_json::Value {
    json!({ "params": { "environment_id": null, "include_closed": false } })
}

/// Waits until `connection_state` says `connected`, and returns it.
async fn connection(companion: &Companion, connected: bool) -> serde_json::Value {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == connected {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the connection gets there")
}

/// KR-REQ-13.08: before this computer has paired with anything every command says there is no
/// connection; the host it pairs with first becomes the one its commands go to, with the rights its
/// grant carries and no others; the page's reads are answered by that host; a command the grant
/// does not carry is the host's refusal; and a host the page names that this computer is not
/// paired with is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_host_answers_the_commands_the_page_calls() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(&owner);
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView]),
        &signer,
    )
    .await
    .expect("a direct invitation");
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation");
    };
    let data = tempfile::tempdir().expect("a directory");
    let room: Arc<dyn CandidateRoom> = Arc::new(host.room.clone());
    let companion = Companion::start(
        data.path(),
        support::parts(Arc::new(MemoryStore::new()), room),
        Arc::new(NoOwner),
        StubPaste::holding(qr_text.as_str(), false),
    );

    let before = companion
        .call("connection_state", json!({}))
        .expect("the connection's state");
    assert_eq!(
        before["connected"], false,
        "nothing is paired yet: {before}"
    );
    let refused = companion
        .call("session_list", every_session())
        .expect_err("no host is reached");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
    let unknown = companion
        .call("hosts_use", json!({ "reference": "a host nobody listed" }))
        .expect_err("this computer is not paired with that host");
    assert_eq!(unknown["code"], "INVALID_ARGUMENT", "{unknown}");

    companion
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    companion
        .call("pairing_start_read", json!({}))
        .expect("pairing starts");
    companion
        .reached(|state| state["state"] == "awaiting_approval")
        .await;
    calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves");
    companion.reached(|state| state["state"] == "paired").await;

    // The host it paired with is the one its commands go to, without a second step.
    let used = connection(&companion, true).await;
    assert_eq!(
        used["environment_id"],
        host.environment_id.to_string(),
        "the environment is the one the host stamped"
    );
    assert_eq!(
        used["rights"],
        json!(["session.view"]),
        "the application claims what the grant carries and nothing else"
    );
    let listed = companion
        .call("session_list", every_session())
        .expect("the host lists its sessions");
    assert_eq!(listed["sessions"], json!([]));
    let refusal = companion
        .call(
            "device_list",
            json!({ "params": { "include_revoked": false } }),
        )
        .expect_err("a viewer lists no devices");
    assert_eq!(refusal["code"], "PERMISSION_DENIED", "{refusal}");

    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    assert_eq!(view["hosts"][0]["in_use"], true);
    assert_eq!(
        companion
            .call("hosts_use", json!({ "reference": the_host(&companion) }))
            .expect("choosing the same host again")["connected"],
        true
    );
    host.stop().await;
}

/// KR-REQ-13.08: a host that stops answering reads as lost, with a reason, and a command says so;
/// the same host coming back is reached again without the person doing anything, over the grant
/// this device still holds there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_comes_back_is_reached_again() {
    let owner = DeviceKeys::generate().expect("keys");
    // The host keeps its keys and its address across the restart, as a host does.
    let port = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a port");
        socket.local_addr().expect("an address").port()
    };
    let mut settings = kr_controller::service::net::config::NetworkSettings::default();
    settings.endpoint.bind_addr = Some(format!("127.0.0.1:{port}").parse().expect("an address"));
    let host = Host::start_with_settings(&owner, settings.clone()).await;
    let (companion, _data) = paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    connection(&companion, true).await;
    companion
        .call("session_list", every_session())
        .expect("the host answers");

    let stopped = host.shut_down().await;
    let lost = connection(&companion, false).await;
    assert!(
        lost["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a lost host says why: {lost}"
    );
    assert_eq!(lost["rights"], serde_json::Value::Null);
    let refused = companion
        .call("session_list", every_session())
        .expect_err("the host is gone");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");

    let host = stopped.start(settings).await;
    let back = connection(&companion, true).await;
    assert_eq!(back["rights"], json!(["session.view"]));
    companion
        .call("session_list", every_session())
        .expect("the host answers again");
    host.stop().await;
}

/// KR-REQ-15.21: a device nobody has given a voice grant is refused by the host, and nothing the
/// voice screen reads is answered until the person has allowed what it may do. The scope the
/// person is shown is the protocol's own table of default actions, each in the sentence that
/// states it; the grant is made for this device by native code, which names the device itself;
/// the answer states every action it permits and every one the device's own grant could not
/// carry; and the voice screen's read then answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_screen_opens_once_the_person_has_allowed_what_it_may_do() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let (companion, _data) = paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    connection(&companion, true).await;
    let session = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string();
    let prepare = || {
        companion.call(
            "voice_prepare",
            json!({ "params": { "session_ids": [session], "selected": [] } }),
        )
    };

    let scope = companion
        .call("voice_scope", json!({}))
        .expect("the default scope");
    let shown: Vec<&str> = scope["actions"]
        .as_array()
        .expect("a list of actions")
        .iter()
        .map(|each| each["action"].as_str().expect("an action"))
        .collect();
    let mut sorted = shown.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, ["brief", "compose_prompt", "navigate", "status"]);
    assert!(
        scope["actions"]
            .as_array()
            .expect("a list")
            .iter()
            .all(|each| each["sentence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())),
        "each action is stated: {scope}"
    );

    let refused = prepare().expect_err("no voice grant, no preparation");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");

    let allowed = companion
        .call(
            "voice_allow",
            json!({ "subject": {}, "params": { "session_ids": [session], "actions": null } }),
        )
        .expect("the person allows the default scope");
    let value = &allowed["value"];
    let device_id = companion
        .device()
        .host_in_use()
        .expect("the host in use")
        .device_id
        .to_string();
    assert!(
        !allowed.to_string().contains(&device_id),
        "the page is not told the identity the host gave this device: {allowed}"
    );
    assert!(value.get("device_id").is_none(), "{allowed}");
    let mut stated: Vec<&str> = value["statement"]["actions"]
        .as_array()
        .map_or_else(Vec::new, |each| {
            each.iter().filter_map(|a| a.as_str()).collect()
        });
    let mut shown_sorted = shown.clone();
    stated.sort_unstable();
    shown_sorted.sort_unstable();
    assert_eq!(
        stated, shown_sorted,
        "the answer states what the person was shown: {allowed}"
    );
    assert_eq!(value["not_held_by_device"], json!([]), "{allowed}");

    prepare().expect("the preparation is answered once the grant stands");
    host.stop().await;
}

/// KR-REQ-13.08: the host a phone's commands went to is the one it reaches when the application
/// starts again, without the person choosing it again, and the rights are the grant's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_chosen_before_is_reached_again_when_the_application_starts() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;

    // The application starts again over the same records and the same secrets.
    let restarted = Companion::start(
        phone.data.path(),
        support::parts(Arc::clone(&phone.secrets), Arc::clone(&phone.room)),
        Arc::new(NoOwner),
        StubPaste::holding("", false),
    );
    assert_eq!(
        restarted
            .call("connection_state", json!({}))
            .expect("the connection's state")["connected"],
        false,
        "nothing is reached until the application takes the host up"
    );
    companion_tauri::hosts::resume(restarted.app.handle());
    let back = connection(&restarted, true).await;
    assert_eq!(back["rights"], json!(["session.view"]));
    restarted
        .call("session_list", every_session())
        .expect("the host it chose before answers");
    host.stop().await;
}

/// KR-REQ-13.08: with two hosts paired, the commands go to the host chosen last, and the host the
/// screen says is in use is the host the connection is to, however the choices were made, even two
/// at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn choosing_between_two_paired_hosts_goes_to_the_one_chosen_last() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = phone_paired_with(&first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    // Pairing with a second host does not take the commands from the first.
    let state = connection(companion, true).await;
    assert_eq!(state["environment_id"], first.environment_id.to_string());

    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let references: Vec<String> = view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .map(|row| row["reference"].as_str().expect("a reference").to_owned())
        .collect();
    assert_eq!(references.len(), 2, "both hosts are listed");
    // The rows carry no environment, so a host is found by choosing it and asking where the
    // connection went.
    let mut by_environment = std::collections::BTreeMap::new();
    for reference in &references {
        let used = companion
            .call("hosts_use", json!({ "reference": reference }))
            .expect("the host is chosen");
        assert_eq!(used["connected"], true, "{used}");
        by_environment.insert(
            used["environment_id"]
                .as_str()
                .expect("environment")
                .to_owned(),
            reference.clone(),
        );
    }
    assert_eq!(
        by_environment.len(),
        2,
        "each choice went to a host of its own: {by_environment:?}"
    );

    // Choices made together are made one after another: when they are done, the host the screen
    // says is in use is the host the connection is to.
    let device = companion.device();
    let host_of = |reference: &String| device.host_by_reference(reference).expect("a paired host");
    let (a, b) = (host_of(&references[0]), host_of(&references[1]));
    let handle = companion.app.handle().clone();
    for round in 0..8 {
        let (x, y) = if round % 2 == 0 {
            (a.clone(), b.clone())
        } else {
            (b.clone(), a.clone())
        };
        let (h1, h2) = (handle.clone(), handle.clone());
        let (one, two) = tokio::join!(
            tokio::spawn(async move { companion_tauri::hosts::use_host(&h1, x).await }),
            tokio::spawn(async move { companion_tauri::hosts::use_host(&h2, y).await }),
        );
        one.expect("the first choice ran")
            .expect("a choice is answered");
        two.expect("the second choice ran")
            .expect("a choice is answered");
        let state = connection(companion, true).await;
        let view = companion
            .call("pairing_view", json!({}))
            .expect("the pairing screen");
        let in_use: Vec<&str> = view["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .filter(|row| row["in_use"] == true)
            .map(|row| row["reference"].as_str().expect("a reference"))
            .collect();
        assert_eq!(in_use.len(), 1, "one host is in use: {view}");
        let environment = state["environment_id"].as_str().expect("an environment");
        assert_eq!(
            by_environment.get(environment).map(String::as_str),
            Some(in_use[0]),
            "round {round}: the connection is to the host the screen says is in use"
        );
    }
    first.stop().await;
    second.stop().await;
}

/// KR-REQ-13.08: a choice of host that could not be kept for the next run is not made: the answer
/// is a failure, the host in use is the one before, and the commands still go there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_of_host_that_cannot_be_kept_is_not_made() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = phone_paired_with(&first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let other = view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|row| row["in_use"] == false)
        .and_then(|row| row["reference"].as_str())
        .expect("the host not in use")
        .to_owned();

    // A directory stands where the choice is written before it replaces the old one.
    let blocked = phone.data.path().join("command-host.new");
    std::fs::create_dir(&blocked).expect("the file's place is taken");
    let refused = companion
        .call("hosts_use", json!({ "reference": other }))
        .expect_err("the choice cannot be kept");
    assert_eq!(refused["code"], "RESOURCE_UNAVAILABLE", "{refused}");
    let after = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    assert_eq!(
        after["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .find(|row| row["reference"] == other.as_str())
            .map(|row| row["in_use"].clone()),
        Some(json!(false)),
        "the host that was not chosen is still not in use"
    );
    assert_eq!(
        companion
            .call("connection_state", json!({}))
            .expect("the connection's state")["environment_id"],
        first.environment_id.to_string(),
        "the commands still go to the host before"
    );

    std::fs::remove_dir(&blocked).expect("the place is free");
    let used = companion
        .call("hosts_use", json!({ "reference": other }))
        .expect("the choice is kept now");
    assert_eq!(used["environment_id"], second.environment_id.to_string());
    first.stop().await;
    second.stop().await;
}

/// The identity `host` gave the one phone paired with it.
fn the_phone_of(host: &Host) -> kr_protocol::ids::DeviceId {
    let owner = host.owner.as_ref().map(|owner| owner.device_id);
    host.controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| record.is_paired() && owner != Some(record.device_id))
        .expect("the paired phone")
        .device_id
}

/// KR-REQ-13.08: a phone that its host revoked can forget that host. Forgetting is the phone's own
/// action and reaches nothing: the host is no longer listed, no longer the one in use, no longer
/// tried, and not taken up again when the application starts. The commands that named it are
/// refused as naming a host this computer is not paired with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_its_host_revoked_can_forget_that_host() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let reference = the_host(companion);

    let mut client = host.client().await;
    let _: RevocationResult = calls::mutate(
        host.environment_id,
        &mut client,
        Method::DeviceRevoke,
        &DeviceRevokeParams {
            device_id: the_phone_of(&host),
        },
    )
    .await
    .expect("the host revokes the phone");
    let lost = connection(companion, false).await;
    assert!(
        lost["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a phone its host turned away says it is not connected, and why: {lost}"
    );
    // The phone keeps its record of the host: nothing told it more than that the host does not
    // answer it.
    assert_eq!(
        companion
            .call("pairing_view", json!({}))
            .expect("the pairing screen")["hosts"][0]["reference"],
        reference.as_str()
    );

    let forgotten = companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the phone forgets the host that revoked it");
    assert_eq!(forgotten["connected"], false, "{forgotten}");
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    assert_eq!(view["hosts"], json!([]), "no host is listed: {view}");
    for command in ["hosts_use", "hosts_forget"] {
        let refused = companion
            .call(command, json!({ "reference": reference }))
            .expect_err("this computer is no longer paired with that host");
        assert_eq!(refused["code"], "INVALID_ARGUMENT", "{command}: {refused}");
    }
    assert!(
        companion.device().host_in_use().is_none(),
        "no host is the one in use"
    );

    // The application starts again over the same records: the host is not taken up.
    let restarted = Companion::start(
        phone.data.path(),
        support::parts(Arc::clone(&phone.secrets), Arc::clone(&phone.room)),
        Arc::new(NoOwner),
        StubPaste::holding("", false),
    );
    companion_tauri::hosts::resume(restarted.app.handle());
    assert_eq!(
        restarted
            .call("pairing_view", json!({}))
            .expect("the pairing screen")["hosts"],
        json!([])
    );
    assert_eq!(
        restarted
            .call("connection_state", json!({}))
            .expect("the connection's state")["connected"],
        false
    );
    host.stop().await;
}

/// KR-REQ-13.08: forgetting the host in use, one that still answers, ends the connection to it at
/// once: the answer says there is none, no command goes down it, and no host is in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgetting_the_host_in_use_ends_the_connection_to_it() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion
        .call("session_list", every_session())
        .expect("the host answers before it is forgotten");

    let forgotten = companion
        .call("hosts_forget", json!({ "reference": the_host(companion) }))
        .expect("the host in use is forgotten");
    assert_eq!(forgotten["connected"], false, "{forgotten}");
    assert!(
        forgotten["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "the connection says why there is none: {forgotten}"
    );
    let refused = companion
        .call("session_list", every_session())
        .expect_err("no command goes to a host that was forgotten");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
    assert!(companion.device().host_in_use().is_none());
    host.stop().await;
}

/// KR-REQ-13.08: a write of the records that reports a failure after the record is gone, as one
/// does whose last step (making the rename durable) fails, is a host forgotten all the same: the
/// connection to it ends and no host is in use, instead of a host that is no longer listed going on
/// being reached with nothing left to forget it by.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forget_whose_write_reports_a_failure_once_the_record_is_gone_still_ends_the_connection()
{
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let reference = the_host(companion);

    // The rename that removes the record is done and the flush that follows it fails: the write
    // reports a failure for a record that is gone.
    let refused = kr_flush::testing::refuse_flushes_of(phone.data.path().join("pairing"));
    let forgotten = companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("a host that is gone from the records is forgotten");
    drop(refused);
    assert_eq!(forgotten["connected"], false, "{forgotten}");

    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    assert_eq!(view["hosts"], json!([]), "{view}");
    assert!(companion.device().host_in_use().is_none());
    let refused = companion
        .call("session_list", every_session())
        .expect_err("no command goes to a host that was forgotten");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
    host.stop().await;
}

/// KR-REQ-13.08: a choice of host made from a listing that has since forgotten the host is refused
/// and connects to nothing. The host is found before the choice is made, and a host forgotten in
/// between is not one to be reached by a task started from what was found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_made_from_a_listing_that_has_since_forgotten_the_host_is_refused() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let reference = the_host(companion);
    // What a choice holds once it has found the host and has not yet taken its turn.
    let found = companion
        .device()
        .host_by_reference(&reference)
        .expect("the host is listed");

    companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the host is forgotten");
    let refused = companion_tauri::hosts::use_host(companion.app.handle(), found)
        .await
        .expect_err("the host is no longer paired");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "{refused:?}"
    );

    assert!(companion.device().host_in_use().is_none());
    let state = companion
        .call("connection_state", json!({}))
        .expect("the connection's state");
    assert_eq!(state["connected"], false, "{state}");
    assert_eq!(
        companion
            .call("pairing_view", json!({}))
            .expect("the pairing screen")["hosts"],
        json!([])
    );
    // Nothing is taken up when the application starts again either.
    let restarted = Companion::start(
        phone.data.path(),
        support::parts(Arc::clone(&phone.secrets), Arc::clone(&phone.room)),
        Arc::new(NoOwner),
        StubPaste::holding("", false),
    );
    companion_tauri::hosts::resume(restarted.app.handle());
    assert_eq!(
        restarted
            .call("connection_state", json!({}))
            .expect("the connection's state")["connected"],
        false
    );
    host.stop().await;
}

/// KR-REQ-13.08: forgetting a host that is not the one in use changes nothing about the one that
/// is: the commands still go there, over the connection they had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgetting_a_host_that_is_not_in_use_leaves_the_commands_going_to_the_other() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = phone_paired_with(&first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let rows = view["hosts"].as_array().expect("hosts");
    let reference_of = |in_use: bool| {
        rows.iter()
            .find(|row| row["in_use"] == in_use)
            .and_then(|row| row["reference"].as_str())
            .expect("a host")
            .to_owned()
    };
    let (in_use, other) = (reference_of(true), reference_of(false));

    let forgotten = companion
        .call("hosts_forget", json!({ "reference": other }))
        .expect("the host not in use is forgotten");
    assert_eq!(forgotten["connected"], true, "{forgotten}");
    assert_eq!(
        forgotten["environment_id"],
        first.environment_id.to_string()
    );
    let after = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let remaining: Vec<&str> = after["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .map(|row| row["reference"].as_str().expect("a reference"))
        .collect();
    assert_eq!(remaining, [in_use.as_str()], "{after}");
    companion
        .call("session_list", every_session())
        .expect("the host in use still answers");
    first.stop().await;
    second.stop().await;
}
