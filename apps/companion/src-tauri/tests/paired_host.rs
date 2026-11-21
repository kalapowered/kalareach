//! A phone's commands go to the host it is paired with.
//!
//! The daemon is kr-controller's in-process host, with its test support included by path, and the
//! device is this crate's own backend on the mock runtime: it pairs with the host through the
//! commands the page calls, takes the host as the one its commands go to, and reads through the
//! paired connection, with the rights its grant carries. Nothing here makes a voice call.

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::candidate::CandidateRoom;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::sharing::{DeviceRevokeParams, RevocationResult};
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use serde_json::json;
use support::{
    Companion, LinkControl, NoOwner, Phone, StubIntake, WATCHDOG, contact_of, hosts_of, inbox_read,
    next_read_hold, pair, phone_paired_with, reference_for, unpaired_phone_controlled,
};
use tauri::Manager as _;

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
        StubIntake::holding(qr_text.as_str(), false),
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
    assert_eq!(
        used["paired"], true,
        "the page is told the host is one this device is paired with, so that it offers no file"
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

/// On a host this device is paired with, a session's questions go through the host's
/// daemon, which serves them to a paired device under the rights its grant carries, and not over a
/// link to a worker on this computer, which a phone does not have. The host's own answer is what the
/// page is told: here a session no worker serves.
///
/// KR-REQ-13.08, the part about the page's reads: a question read on a paired device is answered by
/// the host the commands go to, here with the host's own refusal for a session no worker serves,
/// and not by a link to a worker on this computer. Not shown here: the commands the grant does not
/// carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_devices_questions_go_through_the_host() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;

    let refusal = phone
        .companion
        .call(
            "question_read",
            json!({ "params": {
                "session_id": "8a7b6c50-22bb-4c3d-8e4f-000000000101",
                "question_id": null,
                "include_resolved": false
            } }),
        )
        .expect_err("the host has no worker for that session");
    // The host answered. A read tried over a link to a worker on this computer would have failed
    // for want of a host here, as a failure to reach one.
    assert_eq!(refusal["code"], "UNKNOWN_SESSION", "{refusal}");
    host.stop().await;
}

/// KR-REQ-13.08: a host that stops answering reads as lost, with a reason, and a command says so;
/// the same host coming back is reached again without the person doing anything, over the grant
/// this device still holds there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_comes_back_is_reached_again() {
    let owner = DeviceKeys::generate().expect("keys");
    // The host binds a port the system gives it, and keeps its keys and that address across the
    // restart, as a host does.
    let settings = kr_controller::service::net::config::NetworkSettings {
        endpoint: net_support::loopback(),
        ..kr_controller::service::net::config::NetworkSettings::default()
    };
    let mut host = Host::start_with_settings(&owner, settings).await;
    host.comes_back_at_its_address();
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

    let settings = stopped.settings().clone();
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
            json!({ "subject": {}, "params": {
                "session_ids": [session],
                "actions": null,
                "environment_id": host.environment_id.to_string(),
            } }),
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
        StubIntake::holding("", false),
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

/// An approval the host's attention store is given, raised in `session`.
fn approval(session: kr_protocol::ids::SessionId) -> kr_attention::SourceEvent {
    kr_attention::SourceEvent::new(
        kr_attention::EventCursor::in_session(
            session,
            kr_protocol::attention::AttentionSource::Receipts,
            1,
        ),
        kr_ipc::now_ms(),
        kr_attention::EventKind::ApprovalRequested {
            request_id: kr_protocol::ids::ApprovalRequestId::new("req-1").expect("an identifier"),
            session_id: session,
            summary: String::new(),
        },
    )
}

/// A completed turn the host's attention store is given, in `session`.
fn completed_turn(session: kr_protocol::ids::SessionId) -> kr_attention::SourceEvent {
    kr_attention::SourceEvent::new(
        kr_attention::EventCursor::in_session(
            session,
            kr_protocol::attention::AttentionSource::Semantic,
            1,
        ),
        kr_ipc::now_ms(),
        kr_attention::EventKind::TurnCompleted {
            session_id: session,
            turn_id: kr_protocol::ids::AgentTurnId::new("turn-1").expect("an identifier"),
            version: 1,
            change_set: None,
            summary: String::new(),
        },
    )
}

/// The rules of the items one visit read, oldest first.
fn rules(visit: &serde_json::Value) -> Vec<String> {
    visit["result"]["items"]
        .as_array()
        .expect("the items of a host that was read")
        .iter()
        .map(|item| item["rule"].as_str().expect("a rule").to_owned())
        .collect()
}

/// KR-REQ-13.01: the inbox is one across hosts. The host in use is read as any read of it is; every
/// other host this phone is paired with is visited over a connection of its own, and the phone is
/// given that host's inbox, or that it is out of contact with it and since when. A host that cannot
/// be reached holds up no answer, is still listed with the contact it lost, and is read again once
/// it can be reached; a host the phone forgets, or begins to use, is not visited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_inboxes_of_the_other_paired_hosts_are_read_beside_the_one_in_use() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let state = connection(companion, true).await;
    assert_eq!(state["environment_id"], first.environment_id.to_string());

    // The second host has things that wait for the person; the first, the host in use, is not
    // visited.
    let session = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    second
        .controller()
        .attention()
        .observe(&[approval(session), completed_turn(session)])
        .expect("the store records an approval and a completed turn");
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let others: Vec<&serde_json::Value> = view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .filter(|row| row["in_use"] != true)
        .collect();
    assert_eq!(others.len(), 1, "{view}");
    let other = others[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned();

    // The host cannot be reached: it is listed, out of contact since a moment this phone noted, and
    // the same moment at the next visit.
    control.unreachable(true);
    let visited = companion.call("inbox_hosts", json!({})).expect("a visit");
    assert_eq!(hosts_of(&visited).len(), 1, "{visited}");
    assert_eq!(hosts_of(&visited)[0]["reference"], other.as_str());
    let lost = contact_of(companion, &other);
    assert_eq!(lost["state"], "out_of_contact", "{lost}");
    assert!(hosts_of(&visited)[0]["result"].is_null(), "{visited}");
    let since = lost["since_ms"].as_u64().expect("since when");
    companion.call("inbox_hosts", json!({})).expect("a visit");
    assert_eq!(
        contact_of(companion, &other)["since_ms"].as_u64(),
        Some(since)
    );

    // It can be reached: its inbox is read, and the loss is gone.
    control.unreachable(false);
    let read = companion.call("inbox_hosts", json!({})).expect("a visit");
    let contact = contact_of(companion, &other);
    assert_eq!(contact["state"], "in_contact", "{contact}");
    assert!(hosts_of(&read)[0]["result"].is_object(), "{read}");
    let mut found = rules(&hosts_of(&read)[0]);
    found.sort();
    assert_eq!(
        found,
        vec!["attention.pending_approval", "attention.review_ready"],
        "{read}"
    );

    // Choosing it takes it from the visits, and the host before it joins them.
    companion
        .call("hosts_use", json!({ "reference": other }))
        .expect("the host is chosen");
    let after = companion.call("inbox_hosts", json!({})).expect("a visit");
    assert_eq!(hosts_of(&after).len(), 1, "{after}");
    assert_ne!(hosts_of(&after)[0]["reference"], other.as_str(), "{after}");
    let remaining = hosts_of(&after)[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned();
    assert_eq!(contact_of(companion, &remaining)["state"], "in_contact");

    // Forgetting the other leaves nothing to visit.
    companion
        .call("hosts_forget", json!({ "reference": remaining }))
        .expect("the host is forgotten");
    let none = companion.call("inbox_hosts", json!({})).expect("a visit");
    assert_eq!(hosts_of(&none).len(), 0, "{none}");
    first.stop().await;
    second.stop().await;
}

/// KR-REQ-13.01: a host that answers a visit and refuses it is in contact. It is listed as having
/// refused, with the refusal it sent, and with no moment contact was lost; the loss a host out of
/// contact has before it refuses is gone, and a host that stops refusing is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_refuses_the_visit_is_in_contact_and_listed_as_having_refused() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;

    // Out of contact first, with a moment it was lost.
    control.unreachable(true);
    let lost = companion.call("inbox_hosts", json!({})).expect("a visit");
    let other = hosts_of(&lost)[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned();
    let contact = contact_of(companion, &other);
    assert_eq!(contact["state"], "out_of_contact", "{contact}");
    assert!(contact["since_ms"].is_u64(), "{contact}");
    assert!(contact["refusal"].is_null(), "{contact}");

    // The host answers and refuses: it is in contact, and the refusal is the host's own.
    control.unreachable(false);
    control.refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    let refused = companion.call("inbox_hosts", json!({})).expect("a visit");
    assert_eq!(hosts_of(&refused).len(), 1, "{refused}");
    let contact = contact_of(companion, &other);
    assert_eq!(contact["state"], "refused", "{contact}");
    assert_eq!(contact["refusal"]["code"], "PERMISSION_DENIED", "{contact}");
    assert!(contact["since_ms"].is_null(), "{contact}");
    assert!(hosts_of(&refused)[0]["result"].is_null(), "{refused}");
    assert_eq!(hosts_of(&refused)[0]["sessions"], json!([]), "{refused}");

    // It stops refusing: its inbox is read.
    control.refuse(None);
    let read = companion.call("inbox_hosts", json!({})).expect("a visit");
    let contact = contact_of(companion, &other);
    assert_eq!(contact["state"], "in_contact", "{contact}");
    assert!(hosts_of(&read)[0]["result"].is_object(), "{read}");

    first.stop().await;
    second.stop().await;
}

/// KR-REQ-13.01: a host that refuses a visit is listed with the request it refused, which is what
/// the page says it refused: that it would not say who it is, would not open the connection, would
/// not show its inbox, or would not take this device's connection at all. Each carries the host's
/// own words, whichever request the host refused, and a host that is read again lists none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_says_which_request_the_host_refused() {
    use kr_controller::grants::Refusal;

    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;

    let lapsed = Refusal::BehindItsFeed.to_protocol_error();
    let visit = |what: &str| {
        let visit = companion.call("inbox_hosts", json!({})).expect("a visit");
        assert_eq!(hosts_of(&visit).len(), 1, "{what}: {visit}");
        contact_of(
            companion,
            hosts_of(&visit)[0]["reference"]
                .as_str()
                .expect("a reference"),
        )
    };
    // Each request, refused with the words a host under a lapsed bound gives all three. A refused
    // visit keeps no connection, so each of the first three is made over a fresh one.
    for (method, asked) in [
        (Method::HostInfo, "host_info"),
        (Method::SessionOpen, "session_open"),
        (Method::AttentionRead, "attention_read"),
    ] {
        control.refuse_request(Some((method, lapsed.clone())));
        let refused = visit(asked);
        assert_eq!(refused["state"], "refused", "{asked}: {refused}");
        assert_eq!(refused["request"], asked, "{refused}");
        assert!(
            refused["refusal"]["message"]
                .as_str()
                .is_some_and(|said| said.ends_with(lapsed.message.as_str())),
            "{asked}: the host's own words: {refused}"
        );
        assert!(refused["since_ms"].is_null(), "{asked}: {refused}");
    }

    // The inbox refused over a connection the host answered on before is the inbox's refusal too.
    control.refuse_request(None);
    let read = visit("read");
    assert_eq!(read["state"], "in_contact", "{read}");
    control.refuse_request(Some((Method::AttentionRead, lapsed.clone())));
    let kept = visit("kept");
    assert_eq!(kept["state"], "refused", "{kept}");
    assert_eq!(kept["request"], "attention_read", "{kept}");

    // A host that refuses the connection before any request is told apart from all of them.
    control.refuse_request(None);
    control.refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    let connection_refused = visit("connection");
    assert_eq!(connection_refused["state"], "refused");
    assert_eq!(connection_refused["request"], "connection");

    control.refuse(None);
    let read = visit("read again");
    assert_eq!(read["state"], "in_contact", "{read}");

    first.stop().await;
    second.stop().await;
}

/// KR-REQ-13.01: a host the phone begins to use, or forgets, while it is being visited is no longer
/// one of the other hosts: the visit's answer does not report it, whatever the visit found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_chosen_or_forgotten_while_it_is_visited_is_not_reported() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let third = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    pair(&phone, &third, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;
    let device = companion.device();
    let (second_ref, third_ref) = (
        reference_for(companion, &second),
        reference_for(companion, &third),
    );

    // Both visits are under way, held at their connections.
    control.hold();
    let visiting = companion.start_call("inbox_hosts", json!({}));
    until_held(&control, 2).await;

    // The person begins to use the second host and forgets the third. The choice starts the task
    // that keeps the second host's connection, and its dial is held too: the third held connection.
    let using = companion.start_call("hosts_use", json!({ "reference": second_ref }));
    companion.told_host(&second_ref).await;
    until_held(&control, 3).await;
    let forgetting = companion.start_call("hosts_forget", json!({ "reference": third_ref }));
    until_unlisted(&device, &third).await;
    control.stop_holding();
    control.release_all();

    let found = visiting
        .await
        .expect("the visit ran")
        .expect("the pass answered");
    assert!(hosts_of(&found).is_empty(), "{found}");
    using
        .await
        .expect("the choice ran")
        .expect("the second is chosen");
    forgetting
        .await
        .expect("the forget ran")
        .expect("the third is forgotten");
    first.stop().await;
    second.stop().await;
    third.stop().await;
}

/// Waits until the device no longer lists `host`.
async fn until_unlisted(device: &companion_tauri::device::Device, host: &Host) {
    tokio::time::timeout(WATCHDOG, async {
        while device
            .pairing()
            .hosts
            .list()
            .expect("the records")
            .iter()
            .any(|each| each.host_endpoint_id == host.network().endpoint_id())
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host is forgotten");
}

/// Waits until `count` connections are held by `control`.
async fn until_held(control: &LinkControl, count: usize) {
    tokio::time::timeout(WATCHDOG, async {
        while control.held() != count {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the connections are held");
}

/// KR-REQ-13.01: a pass reports a host only if it is still one of the others when the pass ends.
/// Each visit asks about its own host when it ends, and a slower visit runs on after that: a host
/// the phone begins to use, or forgets, once its visit is over and before the pass is, is left out of
/// the pass's answers.
///
/// One visit is held at its connection and the other is let go and fails. A second pass is the
/// witness that the let-go visit is over: visits to one host take turns, so the second pass asks for
/// that host's connection only after the first pass's visit to it has ended. Which of the two hosts
/// is the let-go one does not matter; the phone then uses one and forgets the other, and neither is
/// to be reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_leaves_out_a_host_that_is_no_longer_one_of_the_others_when_it_ends() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let third = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    pair(&phone, &third, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;
    let device = companion.device();
    let (second_ref, third_ref) = (
        reference_for(companion, &second),
        reference_for(companion, &third),
    );

    // Both visits are at their connections. One is let go and fails to reach its host.
    control.hold();
    let pass = companion.start_call("inbox_hosts", json!({}));
    until_held(&control, 2).await;
    control.unreachable(true);
    control.release(0);

    // The witness: it holds a connection once the let-go visit has ended, and not before.
    let witness = companion.start_call("inbox_hosts", json!({}));
    until_held(&control, 2).await;

    // The phone begins to use one of the other hosts and forgets the other, and the slow visit goes
    // on. The choice starts the task that keeps its host's connection, which is held too.
    let using = companion.start_call("hosts_use", json!({ "reference": second_ref }));
    companion.told_host(&second_ref).await;
    until_held(&control, 3).await;
    let forgetting = companion.start_call("hosts_forget", json!({ "reference": third_ref }));
    until_unlisted(&device, &third).await;
    control.stop_holding();
    control.release_all();

    let found = tokio::time::timeout(WATCHDOG, pass)
        .await
        .expect("the pass ended")
        .expect("the pass ran")
        .expect("the pass answered");
    assert!(hosts_of(&found).is_empty(), "{found}");
    tokio::time::timeout(WATCHDOG, witness)
        .await
        .expect("the witness pass ended")
        .expect("the witness pass ran")
        .expect("the witness pass answered");
    using
        .await
        .expect("the choice ran")
        .expect("the second is chosen");
    forgetting
        .await
        .expect("the forget ran")
        .expect("the third is forgotten");
    first.stop().await;
    second.stop().await;
    third.stop().await;
}

/// The seam's hold in a pass releases after the pass has listed the hosts and before it spawns a
/// visit: while it is held no host has been asked, and a host paired meanwhile is not on the list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pass_hold_releases_after_listing_and_before_the_spawn() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let third = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let mut passes = companion.inbox().watch_passes();

    let pass = companion.start_call("inbox_hosts", json!({}));
    let hold = tokio::time::timeout(WATCHDOG, passes.recv())
        .await
        .expect("the pass reaches the hold")
        .expect("a hold");
    let second_asked = control.asked_of(&second.network().endpoint_id());
    pair(&phone, &third, &owner, &[ActionRight::SessionView]).await;
    let third_asked = control.asked_of(&third.network().endpoint_id());
    hold.release();
    let found = tokio::time::timeout(WATCHDOG, pass)
        .await
        .expect("the pass ended")
        .expect("the pass ran")
        .expect("the pass answered");

    assert_eq!(hosts_of(&found).len(), 1, "{found}");
    assert!(
        control.asked_of(&second.network().endpoint_id()) > second_asked,
        "the visit began once the hold was released"
    );
    assert_eq!(
        control.asked_of(&third.network().endpoint_id()),
        third_asked,
        "a host paired after the pass listed its hosts is not visited by it"
    );
    first.stop().await;
    second.stop().await;
    third.stop().await;
}

/// The seam's hold in a visit releases after the read has ended and before the visit is checked: the
/// host has answered, a host forgotten while the visit is held is left out of the pass's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_visit_hold_releases_after_the_read_and_before_the_checks() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let device = companion.device();
    let mut visits = companion.inbox().watch_visits();

    let pass = companion.start_call("inbox_hosts", json!({}));
    let hold = tokio::time::timeout(WATCHDOG, visits.recv())
        .await
        .expect("the visit reaches the hold")
        .expect("a hold");
    let second = reference_for(companion, &two.second);
    assert_eq!(
        Some(hold.host),
        device
            .host_by_reference(&second)
            .map(|host| host.host_device_id)
    );
    assert!(
        two.control.sent(Method::AttentionRead) >= 1,
        "the host was asked for its inbox before the hold"
    );
    let forgetting = companion.start_call("hosts_forget", json!({ "reference": second }));
    until_unlisted(&device, &two.second).await;
    hold.release();
    let found = tokio::time::timeout(WATCHDOG, pass)
        .await
        .expect("the pass ended")
        .expect("the pass ran")
        .expect("the pass answered");

    assert!(hosts_of(&found).is_empty(), "{found}");
    forgetting
        .await
        .expect("the forget ran")
        .expect("the host is forgotten");
    two.stop().await;
}

/// KR-REQ-13.01: a host this computer owns is watched for what it wants confirmed, and the watcher
/// visits it beside the host in use: the watcher asks for a connection to that host, which only a
/// visit of its own does, and the host in use keeps answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_watcher_visits_an_owned_host_beside_the_one_in_use() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    support::record_owned(&companion.device(), &second, "second");

    // The watcher asks for a connection to the owned host, which nothing about the host in use
    // refuses: the count is that host's own, so no connection of the host in use is taken for it.
    let owned = second.network().endpoint_id();
    tokio::time::timeout(WATCHDOG, async {
        while control.asked_of(&owned) == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the watcher reaches for the owned host");

    // The host in use is still connected and answers.
    let state = connection(companion, true).await;
    assert_eq!(state["connected"], true, "{state}");
    companion
        .call("session_list", every_session())
        .expect("the host in use answers");
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
        StubIntake::holding("", false),
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
        StubIntake::holding("", false),
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

/// The milliseconds since the epoch, as this computer's clock says.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_millis(),
    )
    .expect("a time that fits")
}

/// What the page was told of the connection, as (connected, contact state, revision), in the
/// order it was told.
fn told_states(companion: &Companion) -> Vec<(bool, String, u64)> {
    companion
        .connection
        .texts()
        .iter()
        .map(|text| {
            let state: serde_json::Value = serde_json::from_str(text).expect("a state");
            (
                state["connected"].as_bool().expect("connected"),
                state["contact"]["state"]
                    .as_str()
                    .expect("a contact state")
                    .to_owned(),
                state["revision"].as_u64().expect("a revision"),
            )
        })
        .collect()
}

/// Starts a host that comes back at its own address, and the phone paired with it.
async fn a_host_that_comes_back_and_its_phone() -> (net_support::Host, Phone) {
    let owner = DeviceKeys::generate().expect("keys");
    let settings = kr_controller::service::net::config::NetworkSettings {
        endpoint: net_support::loopback(),
        ..kr_controller::service::net::config::NetworkSettings::default()
    };
    let mut host = Host::start_with_settings(&owner, settings).await;
    host.comes_back_at_its_address();
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    (host, phone)
}

/// KR-REQ-18.01: each accepted change of the connection is told to the page once and in order, as
/// the next revision, whether the host is reached, lost or reached again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_accepted_change_is_told_once() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let stopped = host.shut_down().await;
    connection(companion, false).await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let state = connection(companion, true).await;

    // The publisher tells the last change a moment after the command reports it.
    let revision = state["revision"].as_u64().expect("a revision");
    tokio::time::timeout(WATCHDOG, async {
        while told_states(companion).last().map(|told| told.2) != Some(revision) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the last change is told");

    let told = told_states(companion);
    let revisions: Vec<u64> = told.iter().map(|each| each.2).collect();
    assert_eq!(
        revisions,
        (1..=revisions.len() as u64).collect::<Vec<_>>(),
        "each accepted change is told once, as the next revision: {told:?}"
    );
    let at = |connected: bool, contact: &str, after: usize| {
        told.iter()
            .skip(after)
            .position(|each| each.0 == connected && each.1 == contact)
            .map(|found| found + after)
    };
    let reached = at(true, "in_contact", 0).expect("the host is reached");
    let lost = at(false, "out_of_contact", reached).expect("the host is lost after");
    at(true, "in_contact", lost).expect("the host is reached again after");
    host.stop().await;
}

/// KR-REQ-18.01: taking up the host last chosen, as the application does when it starts, is told as
/// the choice and then as the reach, each once and in order, with the host in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resuming_the_host_in_use_is_told_once_with_its_host() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let before = companion.told_connection().len();
    companion_tauri::hosts::resume(companion.app.handle());
    connection(companion, true).await;
    companion.told_everything().await;
    let told = companion.told_connection();
    let resumed = &told[before..];
    assert_eq!(
        resumed.len(),
        2,
        "the choice and the reach, each once: {resumed:?}"
    );
    assert_eq!(resumed[0]["connected"], false, "{resumed:?}");
    assert_eq!(resumed[1]["connected"], true, "{resumed:?}");
    assert_eq!(
        resumed[1]["revision"].as_u64(),
        resumed[0]["revision"].as_u64().map(|revision| revision + 1),
        "in order: {resumed:?}"
    );
    for each in resumed {
        assert_eq!(
            each["host"]["kind"], "paired",
            "the host in use: {resumed:?}"
        );
        assert_eq!(each["host"]["reference"], resumed[0]["host"]["reference"]);
    }
    host.stop().await;
}

/// KR-REQ-18.01: a connection that ends reads out of contact from the end, and not from the next
/// attempt that fails after the pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_ends_reads_out_of_contact_from_the_end() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let before = now_ms();
    let stopped = host.shut_down().await;
    let lost = connection(companion, false).await;
    let after = now_ms();
    assert_eq!(lost["contact"]["state"], "out_of_contact", "{lost}");
    let since = lost["contact"]["since_ms"].as_u64().expect("a start");
    assert!(
        (before..=after).contains(&since),
        "the loss starts when the connection ended, between {before} and {after}: {lost}"
    );
    assert_eq!(
        lost["contact"]["escalates_at_ms"],
        json!(since + kr_protocol::attention_rule::HOST_CONTACT_ESCALATION_MS),
        "{lost}"
    );
    drop(stopped);
}

/// Two hosts this phone is paired with, the first in use, and the dials the phone makes governed.
struct Two {
    first: Host,
    second: Host,
    phone: Phone,
    control: Arc<LinkControl>,
    references: (String, String),
}

async fn two_hosts() -> Two {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;
    pair(&phone, &second, &owner, &[ActionRight::SessionView]).await;
    let view = phone
        .companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let reference = |at: usize| {
        view["hosts"][at]["reference"]
            .as_str()
            .expect("a reference")
            .to_owned()
    };
    let references = (reference(0), reference(1));
    Two {
        first,
        second,
        phone,
        control,
        references,
    }
}

impl Two {
    /// Chooses the host `reference` names, and returns the state once the first attempt has ended.
    fn uses(&self, reference: &str) -> serde_json::Value {
        self.phone
            .companion
            .call("hosts_use", json!({ "reference": reference }))
            .expect("the choice is made")
    }

    async fn stop(self) {
        self.first.stop().await;
        self.second.stop().await;
    }
}

/// KR-REQ-13.08: the host a session is opened on is the host in use when the answer is given: a
/// choice that completes while the device's records are being read makes the answer be asked again,
/// even when no connection is held before or after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_context_retries_when_a_choice_completes_during_the_device_read() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    // No host is reached, so the slot stays empty across both choices and the context comes from the
    // device's records.
    two.control.unreachable(true);
    two.uses(&two.references.0);
    let state = companion.app.state::<companion_tauri::AppState>();
    assert!(state.session().is_err(), "no connection is held");
    let mut hold = state.hold_the_device_read();
    let app = companion.app.handle().clone();
    let asking = tokio::task::spawn_blocking(move || {
        app.state::<companion_tauri::AppState>().paired_context()
    });
    hold.reached().await;
    two.uses(&two.references.1);
    hold.release();

    let context = asking
        .await
        .expect("the read ran")
        .expect("a host is in use");
    let second = companion
        .device()
        .host_by_reference(&two.references.1)
        .expect("the second host is listed");
    assert_eq!(
        context.host.host_device_id, second.host_device_id,
        "the host in use after the choice, not the one read before it"
    );
    two.stop().await;
}

/// KR-REQ-18.01: a host that refuses the connection at admission is in contact and has refused;
/// it is not out of contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_refuses_the_connection_reads_refused_not_out_of_contact() {
    let two = two_hosts().await;
    two.control
        .refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    let state = two.uses(&two.references.0);
    assert!(state["contact"].is_object(), "{state}");
    assert_eq!(state["connected"], false, "{state}");
    assert_eq!(state["contact"]["state"], "refused", "{state}");
    assert_eq!(state["contact"]["request"], "connection", "{state}");
    assert!(
        state["contact"]["refusal"]["message"].is_string(),
        "{state}"
    );
    assert_eq!(state["host"]["kind"], "paired", "{state}");
    two.stop().await;
}

/// KR-REQ-18.01: a host left behind by a choice keeps its loss, and chosen again it reads out of
/// contact at once, with the start it had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chosen_host_that_holds_a_loss_reads_out_of_contact_at_once() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    two.control.unreachable(true);
    let lost = two.uses(&two.references.0);
    assert_eq!(lost["contact"]["state"], "out_of_contact", "{lost}");
    let since = lost["contact"]["since_ms"].as_u64().expect("a start");
    two.control.unreachable(false);
    two.uses(&two.references.1);
    connection(companion, true).await;
    let left_behind = companion
        .call("connection_state", json!({}))
        .expect("the state");
    assert_eq!(
        left_behind["others"][0]["contact"]["since_ms"], since,
        "the host left behind keeps its loss: {left_behind}"
    );

    two.control.unreachable(true);
    let before = two.phone.companion.told_connection().len();
    two.uses(&two.references.0);
    companion.told_everything().await;
    let told = companion.told_connection();
    let chosen = told[before..]
        .iter()
        .find(|state| state["host"]["reference"] == json!(two.references.0))
        .expect("the choice is told");
    assert_eq!(
        chosen["contact"]["state"], "out_of_contact",
        "the first state told of the chosen host already holds its loss: {chosen}"
    );
    assert_eq!(chosen["contact"]["since_ms"], since, "{chosen}");
    two.stop().await;
}

/// KR-REQ-18.01: a host that is forgotten while it is not in use leaves no record of its loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forgotten_host_that_was_not_in_use_leaves_no_record() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    two.control.unreachable(true);
    two.uses(&two.references.0);
    two.control.unreachable(false);
    two.uses(&two.references.1);
    connection(companion, true).await;
    let before = companion
        .call("connection_state", json!({}))
        .expect("the state");
    assert_eq!(
        before["others"][0]["contact"]["state"], "out_of_contact",
        "the host left behind holds its loss: {before}"
    );

    let forgotten = companion
        .call("hosts_forget", json!({ "reference": two.references.0 }))
        .expect("the host is forgotten");
    assert_eq!(forgotten["others"], json!([]), "{forgotten}");
    assert_eq!(
        forgotten["connected"], true,
        "the host in use is untouched: {forgotten}"
    );
    two.stop().await;
}

/// KR-REQ-18.01: a choice made from a listing whose pairing is no longer the one this computer holds
/// with that host (the host was forgotten and paired again, which gives the device another identity
/// there) changes nothing: no choice, no revision, and the host in use and the device's own record
/// stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_made_with_a_stale_pairing_changes_nothing() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let current = companion
        .device()
        .host_by_reference(&the_host(companion))
        .expect("the pairing is listed");
    // The listing the choice was made from names another pairing with the same host.
    let mut stale = current.clone();
    stale.device_id =
        kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([42; 16]));
    let state = companion.app.state::<companion_tauri::AppState>();
    let revision = state.contact_owner().revision();
    let in_use = companion.device().host_in_use().map(|host| host.device_id);

    let refused = companion_tauri::hosts::use_host(companion.app.handle(), stale).await;
    assert!(refused.is_err(), "the stale choice is refused");
    assert_eq!(state.contact_owner().revision(), revision, "no revision");
    assert_eq!(
        companion.device().host_in_use().map(|host| host.device_id),
        in_use,
        "the device's own record of the host in use"
    );
    assert!(state.connection_state().connected, "the host in use stands");
    host.stop().await;
}

/// KR-REQ-13.08: a choice that is resolved and then waits before the choice gate while the host it
/// names is forgotten and paired again is refused when it gets the gate: the pairing it names is not
/// the one this computer holds. The phone takes another host in the meantime, by the normal pairing,
/// selection and connection, and that connection stands: the same publication, the same use record,
/// the same session, and the session still live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_that_waits_for_the_gate_across_a_forget_and_a_repair_is_refused_when_it_gets_it()
{
    use companion_tauri::state::testing::ChoicePoint;

    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let other = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let current = companion
        .device()
        .host_by_reference(&the_host(companion))
        .expect("the pairing is listed");
    let state = companion.app.state::<companion_tauri::AppState>();

    // The choice has found the pairing it names, and waits before it takes the gate.
    let mut hold = state.hold_the_choice_at(ChoicePoint::BeforeGate);
    let handle = companion.app.handle().clone();
    let choosing = tokio::spawn({
        let current = current.clone();
        async move { companion_tauri::hosts::use_host(&handle, current).await }
    });
    hold.reached().await;
    // The phone forgets the host, and takes another by the normal pairing: that host is selected
    // and connected, as the first host a phone pairs with is.
    companion_tauri::hosts::forget_host(companion.app.handle(), &current)
        .await
        .expect("the host is forgotten");
    pair(&phone, &other, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;
    companion.told_everything().await;
    let other_pairing = companion
        .device()
        .host_by_reference(&the_host(companion))
        .expect("the pairing with the other host is listed");
    // The pairing with the first host that a second pairing commits: the same host, and another
    // identity this device has with it. A host does not pair an endpoint it holds a second time, so
    // only this record is written.
    let paired_again = kr_client::pairing::paired::PairedHost {
        device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [42; 16],
        )),
        ..current.clone()
    };
    companion
        .device()
        .pairing()
        .hosts
        .record(paired_again)
        .expect("the pairing is recorded again");
    let before = state.connection_state();
    let in_use = companion.device().host_in_use().map(|host| host.device_id);
    assert_eq!(
        in_use,
        Some(other_pairing.device_id),
        "the host in use is the one paired after the forget, and its use is recorded"
    );
    let session = state
        .session()
        .expect("the host paired after the forget is connected");
    hold.release();

    let refused = choosing.await.expect("the choice ran");
    assert!(refused.is_err(), "the choice names a pairing that is gone");
    assert_eq!(
        state.connection_state(),
        before,
        "the same publication: no revision and the same host in use"
    );
    assert_eq!(
        companion.device().host_in_use().map(|host| host.device_id),
        in_use,
        "the device's own record of the host in use"
    );
    assert_eq!(
        companion
            .device()
            .paired_as(current.host_device_id)
            .expect("the records read"),
        Some(kr_protocol::ids::DeviceId::new(
            kr_protocol::scalars::Uuid::from_bytes([42; 16])
        )),
        "the pairing recorded again is the one the device holds"
    );
    assert!(
        state.session().is_ok_and(|now| Arc::ptr_eq(&now, &session)),
        "the connection installed is the same one"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), session.closed())
            .await
            .is_err(),
        "the session is still live"
    );
    host.stop().await;
    other.stop().await;
}

/// KR-REQ-13.08: a choice that is resolved and then waits before the choice gate while the host it
/// names is forgotten and paired again, as the same host with a new pairing identity, is refused when
/// it gets the gate. The host that was paired again is selected and connected by the normal
/// completion, and that connection stands: the same publication, the same use record, the same
/// session, and the session still live.
///
/// The host keeps one device row for each endpoint, so it would refuse a second pairing of this
/// phone as one that is paired already. While the host is stopped, the case puts its registry as it
/// stands when the host no longer holds the phone's row, the way a host restored from an earlier
/// state does; everything the phone does is the normal pairing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_that_waits_for_the_gate_across_a_forget_and_a_repair_of_the_same_host_is_refused_when_it_gets_it()
 {
    use companion_tauri::contact::HostLabel;
    use companion_tauri::state::testing::ChoicePoint;

    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let reference = the_host(companion);
    let first = companion
        .device()
        .host_by_reference(&reference)
        .expect("the pairing is listed");
    let state = companion.app.state::<companion_tauri::AppState>();

    // The choice has found the pairing it names, and waits before it takes the gate.
    let mut hold = state.hold_the_choice_at(ChoicePoint::BeforeGate);
    let handle = companion.app.handle().clone();
    let choosing = tokio::spawn({
        let first = first.clone();
        async move { companion_tauri::hosts::use_host(&handle, first).await }
    });
    hold.reached().await;
    // The phone forgets the host. The host no longer holds the phone's row, and the phone is paired
    // with it again by the normal pairing, which selects the host and connects to it.
    companion_tauri::hosts::forget_host(companion.app.handle(), &first)
        .await
        .expect("the host is forgotten");
    let stopped = host.shut_down().await;
    {
        let registry = rusqlite::Connection::open(stopped.tree().environment().registry_database())
            .expect("the registry opens");
        let removed = registry
            .execute(
                "DELETE FROM network_devices WHERE device_id = ?1",
                [first.device_id.get().as_bytes().to_vec()],
            )
            .expect("the row is removed");
        assert_eq!(removed, 1, "the host held the phone's row");
    }
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    pair(&phone, &host, &owner, &[ActionRight::SessionView]).await;
    connection(companion, true).await;
    companion.told_everything().await;
    let second = companion
        .device()
        .host_by_reference(&reference)
        .expect("the pairing is listed again");
    assert_eq!(second.host_device_id, first.host_device_id, "the same host");
    assert_ne!(
        second.device_id, first.device_id,
        "a new pairing identity with it"
    );
    let before = state.connection_state();
    assert!(
        before.connected
            && matches!(&before.host, Some(HostLabel::Paired { reference: shown, .. }) if *shown == reference),
        "the host paired again is selected and connected: {before:?}"
    );
    let in_use = companion.device().host_in_use().map(|host| host.device_id);
    assert_eq!(
        in_use,
        Some(second.device_id),
        "the host paired again is the one in use, and its use is recorded"
    );
    let session = state.session().expect("a live session");
    hold.release();

    let refused = choosing.await.expect("the choice ran");
    assert!(refused.is_err(), "the choice names a pairing that is gone");
    assert_eq!(
        state.connection_state(),
        before,
        "the same publication: no revision and the same host in use"
    );
    assert_eq!(
        companion.device().host_in_use().map(|host| host.device_id),
        in_use,
        "the device's own record of the host in use"
    );
    assert!(
        state.session().is_ok_and(|now| Arc::ptr_eq(&now, &session)),
        "the connection installed is the same one"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), session.closed())
            .await
            .is_err(),
        "the session is still live"
    );
    host.stop().await;
}

/// KR-REQ-18.01: a choice whose step stops part of the way, after the owner accepted it, is told in
/// the approved words, and the connection's state names the host chosen, which is what the words
/// send the person to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_that_stops_part_of_the_way_is_told_so_and_the_state_names_the_host_chosen() {
    use companion_tauri::contact::HostLabel;
    use companion_tauri::state::testing::ChoicePoint;

    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let state = companion.app.state::<companion_tauri::AppState>();
    let chosen = companion
        .device()
        .host_by_reference(&two.references.1)
        .expect("the second host is listed");
    let mut hold = state.hold_the_choice_at(ChoicePoint::BeforeCleanup);
    let handle = companion.app.handle().clone();
    let choosing =
        tokio::spawn(async move { companion_tauri::hosts::use_host(&handle, chosen).await });
    hold.reached().await;
    hold.stop();

    let stopped = choosing.await.expect("the choice ran");
    let Err(failure) = stopped else {
        panic!("a choice whose step stopped is not an answer");
    };
    assert_eq!(
        failure.message,
        "the choice of host stopped part of the way; the connection's state shows which host is in use"
    );
    assert!(
        matches!(&state.connection_state().host, Some(HostLabel::Paired { reference, .. }) if *reference == two.references.1),
        "the state names the host chosen: {:?}",
        state.connection_state()
    );
    two.stop().await;
}

/// KR-REQ-18.01: a host that refuses and then answers is told refused and then in contact, as the
/// next revision, with nothing between. The publisher is held on the choice's publication while the
/// refusal and the recovery are both committed, so both wait in the log: each is told as it was
/// committed, and not as a read of the state taken when the publisher comes to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_followed_by_recovery_is_told_in_order() {
    use companion_tauri::contact::{HostContact, HostLabel, Publication};

    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let owner = Arc::clone(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .contact_owner(),
    );
    companion.told_everything().await;
    let start = owner.revision();
    let told_before = companion.told_connection().len();
    two.control
        .refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    let mut hold = owner.hold_the_publisher();
    two.uses(&two.references.0);
    hold.reached().await;
    two.control.refuse(None);
    // What the application holds, not what the page was told: the publisher is held.
    connection(companion, true).await;

    // What the owner committed, whichever of its changes the publisher took before it was held.
    let replay = owner.since(start);
    assert!(!replay.resync, "the log holds every change since the start");
    let committed: Vec<Publication> = replay.states;
    assert_eq!(
        committed
            .iter()
            .map(|published| published.revision)
            .collect::<Vec<_>>(),
        [start + 1, start + 2, start + 3],
        "the choice, the refusal and the recovery, each its own revision"
    );
    for published in &committed {
        assert!(
            matches!(&published.host, Some(HostLabel::Paired { reference, .. }) if *reference == two.references.0),
            "each names the host chosen: {published:?}"
        );
    }
    assert!(
        !committed[0].connected && matches!(committed[0].contact, HostContact::Unknown),
        "the choice: {:?}",
        committed[0]
    );
    assert!(
        !committed[1].connected && matches!(committed[1].contact, HostContact::Refused { .. }),
        "the refusal: {:?}",
        committed[1]
    );
    assert!(
        committed[2].connected && matches!(committed[2].contact, HostContact::InContact),
        "the recovery: {:?}",
        committed[2]
    );

    hold.release();
    companion.told_everything().await;
    let told = companion.told_connection();
    let told_since = &told[told_before..];
    let committed: Vec<serde_json::Value> = committed
        .iter()
        .map(|published| serde_json::to_value(published).expect("a state"))
        .collect();
    assert_eq!(
        told_since, committed,
        "each change is told once, as it was committed, and nothing else is told"
    );
    two.stop().await;
}

/// KR-REQ-18.01: dials that fail again and again keep the start of the loss, and tell it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_failed_dials_keep_the_loss_start() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    two.control.unreachable(true);
    two.uses(&two.references.0);
    // Longer than the first pauses of the reconnect backoff, so that several dials fail.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    companion.told_everything().await;
    let losses: Vec<serde_json::Value> = companion
        .told_connection()
        .into_iter()
        .filter(|state| state["contact"]["state"] == "out_of_contact")
        .collect();
    assert_eq!(losses.len(), 1, "one loss is told once: {losses:?}");
    two.stop().await;
}

/// KR-REQ-18.01: two changes that are committed while the publisher is held are told in the order of
/// their revisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_emit_does_not_reorder() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let contact = Arc::clone(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .contact_owner(),
    );
    let hold = contact.hold_the_publisher();
    drop(contact.choose(&companion_tauri::contact::Target::Local, "first change"));
    drop(contact.choose(&companion_tauri::contact::Target::Local, "second change"));
    hold.release();
    companion.told_everything().await;
    let revisions: Vec<u64> = told_states(companion).iter().map(|each| each.2).collect();
    assert!(
        revisions.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "{revisions:?}"
    );
    host.stop().await;
}

/// KR-REQ-18.01: a publication the publisher has taken and not yet told is still in the replay
/// however many follow it: a page that asks for what it missed is not told to read the whole state
/// again while a change it has not been told is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_held_before_its_emit_stays_in_the_replay() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = phone_paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let contact = Arc::clone(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .contact_owner(),
    );
    let told_through = contact.revision();
    let mut hold = contact.hold_the_publisher();
    drop(contact.choose(&companion_tauri::contact::Target::Local, "the held change"));
    hold.reached().await;
    for turn in 0..300 {
        drop(contact.choose(
            &companion_tauri::contact::Target::Local,
            &format!("change {turn}"),
        ));
    }

    let replay = contact.since(told_through);
    assert!(
        !replay.resync,
        "the held publication is still in the log: the page is not asked to read the whole state"
    );
    assert_eq!(
        replay.states.first().map(|state| state.revision),
        Some(told_through + 1),
        "the replay starts at the publication that is held"
    );
    assert_eq!(replay.states.len(), 301, "every change since is kept");
    hold.release();
    companion.told_everything().await;
    let revisions: Vec<u64> = told_states(companion).iter().map(|each| each.2).collect();
    assert!(
        revisions.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "{revisions:?}"
    );
    host.stop().await;
}

/// KR-REQ-18.01: what the page missed is answered, in order, by the command that replays it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_since_replays_what_the_page_missed() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let told = told_states(companion);
    let replay = companion
        .call("connection_since", json!({ "after": 0 }))
        .expect("the replay");
    let revisions: Vec<u64> = replay["states"]
        .as_array()
        .expect("states")
        .iter()
        .map(|state| state["revision"].as_u64().expect("a revision"))
        .collect();
    assert_eq!(
        revisions,
        told.iter().map(|each| each.2).collect::<Vec<_>>(),
        "the replay is what was told"
    );
    assert_eq!(replay["resync"], false, "{replay}");
    let after = told.last().expect("a state").2;
    let none = companion
        .call("connection_since", json!({ "after": after }))
        .expect("the replay");
    assert_eq!(none["states"], json!([]), "{none}");
    host.stop().await;
}

/// The owner of this application's contact with its hosts.
fn contact_owner(companion: &Companion) -> Arc<companion_tauri::contact::ContactOwner> {
    Arc::clone(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .contact_owner(),
    )
}

/// KR-REQ-18.01: an emit that fails is not retried and its state is not told again, and the state
/// is still held by the replay, so that a page that asks for what it missed above the last revision
/// it heard is given it with no further change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_final_emit_is_found_by_the_tail() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let owner = contact_owner(companion);
    let heard_last = told_states(companion).last().expect("a state").2;

    owner.lose_the_next_emit();
    let stopped = host.shut_down().await;
    connection(companion, false).await;
    let lost = owner.revision();
    assert!(lost > heard_last, "the loss of the host is a change");
    assert!(
        owner.emitted_through(lost, WATCHDOG).await,
        "the publisher attempted the emit"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        told_states(companion).last().map(|told| told.2),
        Some(heard_last),
        "the page was told nothing of the change whose emit failed"
    );

    let replay = companion
        .call("connection_since", json!({ "after": heard_last }))
        .expect("the replay");
    assert_eq!(replay["resync"], false, "{replay}");
    let revisions: Vec<u64> = replay["states"]
        .as_array()
        .expect("states")
        .iter()
        .map(|state| state["revision"].as_u64().expect("a revision"))
        .collect();
    assert_eq!(
        revisions,
        vec![lost],
        "the missed state is replayed: {replay}"
    );
    assert_eq!(replay["states"][0]["connected"], false, "{replay}");

    // The next change is told as usual, and the lost one is not told after it.
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let state = connection(companion, true).await;
    companion.told_everything().await;
    let told: Vec<u64> = told_states(companion).iter().map(|each| each.2).collect();
    assert!(told.contains(&state["revision"].as_u64().expect("a revision")));
    assert!(
        !told.contains(&lost),
        "the lost emit is not retried: {told:?}"
    );
    host.stop().await;
}

/// KR-REQ-13.01: an active read that has its answer in hand waits at the hold until it is released,
/// and then answers what the host sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hold_releases_a_read_after_its_answer_is_in_hand() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&host, &control);
    pair(&phone, &host, &owner, &[ActionRight::SessionView]).await;
    let companion = &phone.companion;
    connection(companion, true).await;
    let mut holds = contact_owner(companion).watch_reads();

    let read = companion.start_call("attention_read", inbox_read());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !read.is_finished(),
        "a read whose answer is in hand waits at the hold"
    );
    let held = tokio::time::timeout(WATCHDOG, holds.recv())
        .await
        .expect("the read reaches the hold")
        .expect("a hold");
    assert_eq!(held.command, "attention_read");
    assert_eq!(
        control.sent(Method::AttentionRead),
        1,
        "the host was asked once, and its answer is in hand"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!read.is_finished(), "a held read is not answered");

    held.release();
    let answer = tokio::time::timeout(WATCHDOG, read)
        .await
        .expect("the read answers once released")
        .expect("the call's task")
        .expect("the host's inbox");
    assert!(support::inbox_of(&answer)["items"].is_array(), "{answer}");
    host.stop().await;
}

/// The state the page was last told.
fn last_told(companion: &Companion) -> serde_json::Value {
    companion
        .connection
        .texts()
        .last()
        .map(|text| serde_json::from_str(text).expect("a state"))
        .expect("the page was told a state")
}

/// A host that is phone-paired and reached, with the means to refuse its reads of the inbox.
async fn a_paired_host_and_its_control() -> (net_support::Host, Phone, Arc<LinkControl>) {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&host, &control);
    pair(&phone, &host, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;
    phone.companion.told_everything().await;
    (host, phone, control)
}

/// KR-REQ-13.01: a host that refuses the inbox over a live connection is a host that refused it:
/// the contact reads refused for that request, and the change is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_read_over_a_live_connection_reads_refused_and_is_told() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    assert_eq!(last_told(companion)["contact"]["state"], "in_contact");
    let lapsed = Refusal::BehindItsFeed.to_protocol_error();
    control.refuse_request(Some((Method::AttentionRead, lapsed.clone())));
    let refusal = companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox");
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|said| said.ends_with(lapsed.message.as_str())),
        "the host's own words: {refusal}"
    );
    companion.told_everything().await;
    let refused = last_told(companion);
    assert_eq!(refused["contact"]["state"], "refused", "{refused}");
    assert_eq!(refused["contact"]["request"], "attention_read", "{refused}");
    host.stop().await;
}

/// KR-REQ-13.01: a read the host then answers ends the refusal of the inbox, and that is told too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_valid_read_clears_it_and_is_told() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    control.refuse_request(Some((
        Method::AttentionRead,
        Refusal::BehindItsFeed.to_protocol_error(),
    )));
    companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox");
    companion.told_everything().await;
    assert_eq!(last_told(companion)["contact"]["state"], "refused");

    control.refuse_request(None);
    let answer = companion
        .call("attention_read", inbox_read())
        .expect("the host answers its inbox");
    assert!(answer["result"]["items"].is_array(), "{answer}");
    companion.told_everything().await;
    assert_eq!(
        last_told(companion)["contact"]["state"],
        "in_contact",
        "an answered read ends the refusal and says so"
    );
    host.stop().await;
}

/// KR-REQ-13.01: a read that began before another and is answered after it does not clear what the
/// later one found: it writes no contact, and is still answered with its data under the key it began
/// under.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_success_cannot_clear_a_newer_refusal() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let mut holds = contact_owner(companion).watch_reads();
    let older = companion.start_call("attention_read", inbox_read());
    let older_hold = next_read_hold(&mut holds).await;
    control.refuse_request(Some((
        Method::AttentionRead,
        Refusal::BehindItsFeed.to_protocol_error(),
    )));
    let newer = companion.start_call("attention_read", inbox_read());
    let newer_hold = next_read_hold(&mut holds).await;
    newer_hold.release();
    newer
        .await
        .expect("the call's task")
        .expect_err("the newer read is refused");
    companion.told_everything().await;
    let refused = last_told(companion);
    assert_eq!(refused["contact"]["state"], "refused", "{refused}");

    control.refuse_request(None);
    older_hold.release();
    let answer = older
        .await
        .expect("the call's task")
        .expect("the older read is answered");
    assert!(answer["result"]["items"].is_array(), "{answer}");
    assert_ne!(
        answer["key"]["epoch"], refused["inbox_epoch"],
        "it holds the key it began under"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        last_told(companion)["contact"]["state"],
        "refused",
        "the older answer cleared nothing"
    );
    host.stop().await;
}

/// KR-REQ-13.01: a read whose answer is in hand when its connection ends, and is released after the
/// keeper has reached the host again, is superseded: it answers no data, writes no contact and tells
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_released_after_the_session_ended_answers_superseded_and_writes_nothing() {
    let (host, phone) = a_host_that_comes_back_and_its_phone().await;
    let companion = &phone.companion;
    connection(companion, true).await;
    companion.told_everything().await;
    let mut holds = contact_owner(companion).watch_reads();
    let read = companion.start_call("attention_read", inbox_read());
    let hold = next_read_hold(&mut holds).await;

    let stopped = host.shut_down().await;
    connection(companion, false).await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    connection(companion, true).await;
    companion.told_everything().await;
    let told_before = told_states(companion).len();

    hold.release();
    let answered = read.await.expect("the call's task");
    assert!(
        answered.is_ok(),
        "a superseded read is a value, not a failure: {answered:?}"
    );
    let answer = answered.expect("a value");
    assert_eq!(answer["superseded"], true, "{answer}");
    assert!(answer.get("key").is_some(), "its key is answered: {answer}");
    assert!(answer.get("result").is_none(), "no data: {answer}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "nothing was told"
    );
    assert_eq!(last_told(companion)["contact"]["state"], "in_contact");
    host.stop().await;
}

/// KR-REQ-13.01: a read whose answer is in hand when the person chooses another host and then this
/// one again is superseded: it answers no data, writes no contact and tells nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_released_after_a_switch_away_and_back_answers_superseded() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let in_use = connection(companion, true).await["host"]["reference"]
        .as_str()
        .expect("a host in use")
        .to_owned();
    let other = if in_use == two.references.0 {
        two.references.1.clone()
    } else {
        two.references.0.clone()
    };
    companion.told_everything().await;
    let mut holds = contact_owner(companion).watch_reads();
    let read = companion.start_call("attention_read", inbox_read());
    let hold = next_read_hold(&mut holds).await;

    two.uses(&other);
    two.uses(&in_use);
    connection(companion, true).await;
    companion.told_everything().await;
    let told_before = told_states(companion).len();

    hold.release();
    let answered = read.await.expect("the call's task");
    assert!(
        answered.is_ok(),
        "a superseded read is a value, not a failure: {answered:?}"
    );
    let answer = answered.expect("a value");
    assert_eq!(answer["superseded"], true, "{answer}");
    assert!(answer.get("key").is_some(), "its key is answered: {answer}");
    assert!(answer.get("result").is_none(), "no data: {answer}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "nothing was told"
    );
    assert_eq!(last_told(companion)["contact"]["state"], "in_contact");
    two.stop().await;
}

/// KR-REQ-13.01: a read whose answer is in hand when the host in use is forgotten is superseded: it
/// answers no data and writes nothing of the host that is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_released_after_a_forget_answers_superseded() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let in_use = connection(companion, true).await["host"]["reference"]
        .as_str()
        .expect("a host in use")
        .to_owned();
    companion.told_everything().await;
    let mut holds = contact_owner(companion).watch_reads();
    let read = companion.start_call("attention_read", inbox_read());
    let hold = next_read_hold(&mut holds).await;

    companion
        .call("hosts_forget", json!({ "reference": in_use }))
        .expect("the host is forgotten");
    companion.told_everything().await;
    let told_before = told_states(companion).len();

    hold.release();
    let answered = read.await.expect("the call's task");
    assert!(
        answered.is_ok(),
        "a superseded read is a value, not a failure: {answered:?}"
    );
    let answer = answered.expect("a value");
    assert_eq!(answer["superseded"], true, "{answer}");
    assert!(answer.get("key").is_some(), "its key is answered: {answer}");
    assert!(answer.get("result").is_none(), "no data: {answer}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "nothing was told"
    );
    two.stop().await;
}

/// Waits until a connection is held that is a later one than number `link`, and returns its number.
async fn a_connection_after(companion: &Companion, link: u64) -> u64 {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            let now = state["link"].as_u64().expect("a link");
            if state["connected"] == true && now > link {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("a later connection is reached")
}

/// KR-REQ-13.01: each way a read of the inbox can fail without an answer answers with the words its
/// cause has everywhere else: the host's own refusal of the request, a host that was not reached,
/// a connection the host did not admit, and a host that cannot take another. Only the first is a
/// refusal of the inbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_typed_failure_of_the_read_answers_its_unopened_words() {
    use kr_controller::grants::Refusal;
    use kr_protocol::error::ErrorCode;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let code_of = |code: ErrorCode| serde_json::to_value(code).expect("a code");

    // A refusal of the request: the host's own words and code, and the inbox reads refused.
    let lapsed = Refusal::BehindItsFeed.to_protocol_error();
    control.refuse_request(Some((Method::AttentionRead, lapsed.clone())));
    let refused = companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox");
    control.refuse_request(None);
    assert_eq!(refused["code"], code_of(lapsed.code), "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|said| said.ends_with(lapsed.message.as_str())),
        "the host's own words: {refused}"
    );
    companion.told_everything().await;
    assert_eq!(last_told(companion)["contact"]["state"], "refused");
    companion
        .call("attention_read", inbox_read())
        .expect("the host answers its inbox");
    companion.told_everything().await;
    let settled = told_states(companion).len();

    // A host that was not reached: the connection ends under the call.
    control.lose_the_answer_to(Some(Method::AttentionRead));
    let unreached = companion
        .call("attention_read", inbox_read())
        .expect_err("the answer never comes");
    control.lose_the_answer_to(None);
    assert_ne!(unreached["code"], code_of(lapsed.code), "{unreached}");

    // A connection the host refused, as it does one that it cannot admit or has no room for: the
    // refusal ends the connection. A read that finished before the end was applied answers the
    // typed words of the refusal, and one that finished after it is superseded; the page is told
    // the loss of the connection either way. Neither is a refusal of the inbox.
    for (code, words, own_code, lost_as) in [
        (
            ErrorCode::PermissionDenied,
            "the host refused the connection",
            true,
            "out_of_contact",
        ),
        (
            ErrorCode::ResourceUnavailable,
            "cannot take another connection",
            false,
            "refused",
        ),
    ] {
        let told_before = companion.told_connection().len();
        let link = companion
            .call("connection_state", json!({}))
            .expect("the state")["link"]
            .as_u64()
            .expect("a link");
        control.refuse_the_connection_at_the_next(Method::AttentionRead, code);
        match companion.call("attention_read", inbox_read()) {
            Ok(answer) => assert_eq!(
                answer["superseded"], true,
                "a read over a connection that ended is superseded: {answer}"
            ),
            Err(error) => {
                assert!(
                    error["message"]
                        .as_str()
                        .is_some_and(|said| said.contains(words)),
                    "the host's words: {error}"
                );
                assert!(
                    !own_code || error["code"] != code_of(code),
                    "the code the host refused the connection with is for the connection: {error}"
                );
            }
        }
        let ended = tokio::time::timeout(WATCHDOG, async {
            loop {
                let told = companion.told_connection();
                if let Some(ended) = told[told_before..]
                    .iter()
                    .find(|state| state["connected"] == false)
                {
                    return ended.clone();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the loss of the connection is told");
        assert_eq!(
            ended["contact"]["state"], lost_as,
            "the end of the connection reads as its cause does: {ended}"
        );
        assert_ne!(
            ended["contact"]["request"], "attention_read",
            "no refusal of the inbox: {ended}"
        );
        a_connection_after(companion, link).await;
    }
    companion.told_everything().await;
    let told = companion.told_connection();
    assert!(
        told[settled..]
            .iter()
            .all(|state| state["contact"]["request"] != "attention_read"),
        "only a refusal of the request reads refused for the inbox: {told:?}"
    );
    host.stop().await;
}

/// KR-REQ-13.01: the answer to a read of the inbox carries the key of the host in use, its epoch and
/// the connection the read went over, which are what the state the page is told says of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_answer_carries_the_owners_key() {
    let (host, phone, _control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let state = companion
        .call("connection_state", json!({}))
        .expect("the state");
    let answer = companion
        .call("attention_read", inbox_read())
        .expect("the inbox");
    assert_eq!(
        answer["key"],
        json!({
            "host": { "kind": "paired", "reference": state["host"]["reference"] },
            "epoch": state["inbox_epoch"],
            "link": state["link"],
        }),
        "{answer} under {state}"
    );
    host.stop().await;
}

/// KR-REQ-13.01: a read begun after the choice moved to another host answers that host's key, though
/// the page has not yet been told the choice: the key is the owner's, not the page's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_whose_choice_moved_to_b_answers_b_not_a() {
    let two = two_hosts().await;
    let companion = &two.phone.companion;
    let a = connection(companion, true).await["host"]["reference"]
        .as_str()
        .expect("a host in use")
        .to_owned();
    let b = if a == two.references.0 {
        two.references.1.clone()
    } else {
        two.references.0.clone()
    };
    companion.told_everything().await;

    let hold = contact_owner(companion).hold_the_publisher();
    two.uses(&b);
    let answer = companion
        .call("attention_read", inbox_read())
        .expect("the inbox");
    assert_eq!(answer["key"]["host"]["reference"], json!(b), "{answer}");
    assert_eq!(
        last_told(companion)["host"]["reference"],
        json!(a),
        "the page has not been told the choice"
    );

    hold.release();
    companion.told_everything().await;
    let told = last_told(companion);
    assert_eq!(told["host"]["reference"], json!(b), "{told}");
    assert_eq!(answer["key"]["epoch"], told["inbox_epoch"], "{answer}");
    two.stop().await;
}

/// KR-REQ-13.01: the numbers of the sessions are read under the same key as the inbox, and what
/// the host says of them writes nothing of contact: a refusal of them reads as no refusal of the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_numbers_carries_the_key_takes_no_serial_and_writes_no_contact() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let inbox = companion
        .call("attention_read", inbox_read())
        .expect("the inbox");
    let numbers = companion
        .call("session_numbers", json!({}))
        .expect("the numbers");
    assert_eq!(numbers["key"], inbox["key"], "one key for both reads");
    assert!(numbers["result"]["sessions"].is_array(), "{numbers}");

    let told_before = told_states(companion).len();
    control.refuse_request(Some((
        Method::SessionList,
        Refusal::BehindItsFeed.to_protocol_error(),
    )));
    companion
        .call("session_numbers", json!({}))
        .expect_err("the host refuses the numbers");
    control.refuse_request(None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "a refusal of the numbers tells nothing"
    );
    assert_eq!(last_told(companion)["contact"]["state"], "in_contact");
    host.stop().await;
}

/// KR-REQ-13.01: the numbers read while a page of the inbox is held answer first and supersede
/// nothing: the page is released and answers its data under the key both reads began under, and the
/// host was asked once for each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_numbers_answering_first_supersedes_no_attention_read() {
    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let mut holds = contact_owner(companion).watch_reads();
    let page = companion.start_call("attention_read", inbox_read());
    let page_hold = next_read_hold(&mut holds).await;
    let numbers = companion.start_call("session_numbers", json!({}));
    let numbers_hold = next_read_hold(&mut holds).await;
    assert_eq!(numbers_hold.command, "session_numbers");
    numbers_hold.release();
    let numbers = numbers
        .await
        .expect("the call's task")
        .expect("the numbers");

    page_hold.release();
    let page = page.await.expect("the call's task").expect("the page");
    assert!(page["result"]["items"].is_array(), "{page}");
    assert_eq!(page["key"], numbers["key"], "one key for both reads");
    assert!(numbers["result"]["sessions"].is_array(), "{numbers}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(last_told(companion)["contact"]["state"], "in_contact");
    assert_eq!(
        control.sent(Method::AttentionRead),
        1,
        "no page is read again"
    );
    assert_eq!(control.sent(Method::SessionList), 1);
    host.stop().await;
}

/// KR-REQ-13.01: as above when the held page is one the host refuses: the numbers that answered
/// first do not clear the refusal, and the page's own refusal is the host's, told once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_numbers_answering_first_supersedes_no_attention_refusal() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let lapsed = Refusal::BehindItsFeed.to_protocol_error();
    control.refuse_request(Some((Method::AttentionRead, lapsed.clone())));
    let mut holds = contact_owner(companion).watch_reads();
    let page = companion.start_call("attention_read", inbox_read());
    let page_hold = next_read_hold(&mut holds).await;
    let numbers = companion.start_call("session_numbers", json!({}));
    let numbers_hold = next_read_hold(&mut holds).await;
    numbers_hold.release();
    let numbers = numbers
        .await
        .expect("the call's task")
        .expect("the numbers");
    assert!(numbers["result"]["sessions"].is_array(), "{numbers}");

    page_hold.release();
    let refusal = page
        .await
        .expect("the call's task")
        .expect_err("the page is refused");
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|said| said.ends_with(lapsed.message.as_str())),
        "the host's own words: {refusal}"
    );
    companion.told_everything().await;
    let refused = last_told(companion);
    assert_eq!(refused["contact"]["state"], "refused", "{refused}");
    assert_eq!(
        control.sent(Method::AttentionRead),
        0,
        "the refused page was not sent, and is not asked again"
    );
    assert_eq!(control.sent(Method::SessionList), 1);
    host.stop().await;
}

/// KR-REQ-13.01: a conflict the host answers a page with is an answer and not a refusal: the page
/// is told to read again and the contact is neither written nor told; and when the inbox had been
/// refused, the conflict is the host answering it, which ends the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_conflict_is_an_answer_and_makes_no_event() {
    use kr_controller::grants::Refusal;
    use kr_protocol::error::{ErrorCode, ProtocolError};

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let conflict = ProtocolError::new(ErrorCode::DraftConflict, "the page is not one held");
    control.refuse_request(Some((Method::AttentionRead, conflict.clone())));
    let told_before = told_states(companion).len();
    let answered = companion
        .call("attention_read", inbox_read())
        .expect_err("the page reads again");
    assert_eq!(
        answered["code"],
        serde_json::to_value(ErrorCode::DraftConflict).expect("a code"),
        "{answered}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "a conflict tells nothing"
    );

    control.refuse_request(Some((
        Method::AttentionRead,
        Refusal::BehindItsFeed.to_protocol_error(),
    )));
    companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox");
    companion.told_everything().await;
    assert_eq!(last_told(companion)["contact"]["state"], "refused");
    control.refuse_request(Some((Method::AttentionRead, conflict)));
    companion
        .call("attention_read", inbox_read())
        .expect_err("the page reads again");
    companion.told_everything().await;
    assert_eq!(
        last_told(companion)["contact"]["state"],
        "in_contact",
        "the conflict is the host answering: it ends the refusal and says so"
    );
    host.stop().await;
}

/// KR-REQ-18.01: a refusal the host repeats is no new change: the second read tells nothing and the
/// epoch stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identical_refusal_makes_no_second_event() {
    use kr_controller::grants::Refusal;

    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    control.refuse_request(Some((
        Method::AttentionRead,
        Refusal::BehindItsFeed.to_protocol_error(),
    )));
    companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox");
    companion.told_everything().await;
    let first = last_told(companion);
    assert_eq!(first["contact"]["state"], "refused", "{first}");
    let told_before = told_states(companion).len();

    companion
        .call("attention_read", inbox_read())
        .expect_err("the host refuses its inbox again");
    tokio::time::sleep(Duration::from_millis(300)).await;
    companion.told_everything().await;
    assert_eq!(
        told_states(companion).len(),
        told_before,
        "the same refusal tells nothing again"
    );
    assert_eq!(
        last_told(companion)["inbox_epoch"],
        first["inbox_epoch"],
        "the epoch did not move"
    );
    host.stop().await;
}

/// KR-REQ-13.01: the parameters of a read are decoded before the host is asked: a body that is not
/// the method's shape is refused as an invalid argument and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parameters_are_decoded_before_the_session_is_asked() {
    let (host, phone, control) = a_paired_host_and_its_control().await;
    let companion = &phone.companion;
    let refusal = companion
        .call(
            "attention_read",
            json!({ "params": { "not_a_parameter": true } }),
        )
        .expect_err("a body that is not the method's");
    assert_eq!(refusal["code"], "INVALID_ARGUMENT", "{refusal}");
    assert_eq!(
        control.sent(Method::AttentionRead),
        0,
        "the host was not asked"
    );
    host.stop().await;
}

// ---------------------------------------------------------------------------------------------
// The visits on the owner: what each visit commits, when it is told, and what a visit that began
// under an authority that has gone writes (nothing).
// ---------------------------------------------------------------------------------------------

/// This phone paired with three hosts: the first in use, and the second (A) and the third (C) the
/// others, with the dials governed.
struct Visiting {
    first: Host,
    a: Host,
    c: Host,
    phone: Phone,
    control: Arc<LinkControl>,
    a_ref: String,
    c_ref: String,
}

async fn visiting() -> Visiting {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let a = Host::start(&owner).await;
    let c = Host::start(&owner).await;
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&first, &control);
    pair(&phone, &first, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;
    pair(&phone, &a, &owner, &[ActionRight::SessionView]).await;
    pair(&phone, &c, &owner, &[ActionRight::SessionView]).await;
    connection(&phone.companion, true).await;
    let (a_ref, c_ref) = (
        reference_for(&phone.companion, &a),
        reference_for(&phone.companion, &c),
    );
    Visiting {
        first,
        a,
        c,
        phone,
        control,
        a_ref,
        c_ref,
    }
}

type Call = tokio::task::JoinHandle<Result<serde_json::Value, serde_json::Value>>;

impl Visiting {
    fn companion(&self) -> &Companion {
        &self.phone.companion
    }

    /// A pass of the inbox, started now.
    fn pass(&self) -> Call {
        self.companion().start_call("inbox_hosts", json!({}))
    }

    fn id_of(&self, reference: &str) -> kr_protocol::ids::DeviceId {
        self.companion()
            .device()
            .host_by_reference(reference)
            .expect("the host is listed")
            .host_device_id
    }

    /// Forgets A and records a pairing with it again under another identity, as a new pairing
    /// would. The new record is returned.
    fn pair_a_again(&self) -> kr_client::pairing::paired::PairedHost {
        let device = self.companion().device();
        let old = device.host_by_reference(&self.a_ref).expect("A is listed");
        self.companion()
            .call("hosts_forget", json!({ "reference": self.a_ref }))
            .expect("A is forgotten");
        let new = kr_client::pairing::paired::PairedHost {
            device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
                [9; 16],
            )),
            ..old
        };
        device
            .pairing()
            .hosts
            .record(new.clone())
            .expect("the new pairing is recorded");
        new
    }

    async fn stop(self) {
        self.first.stop().await;
        self.a.stop().await;
        self.c.stop().await;
    }
}

/// The refusal a host under a lapsed bound gives every request.
fn lapsed() -> kr_protocol::error::ProtocolError {
    kr_controller::grants::Refusal::BehindItsFeed.to_protocol_error()
}

/// How the owner says contact with the other host `reference` stands, with its epoch: its entry in
/// `others`, from the states the page was told.
fn told_other(companion: &Companion, reference: &str) -> Vec<serde_json::Value> {
    companion
        .told_connection()
        .iter()
        .filter_map(|state| {
            let other = state["others"]
                .as_array()?
                .iter()
                .find(|other| other["reference"] == reference)?;
            let mut other = other.clone();
            other["revision"] = state["revision"].clone();
            Some(other)
        })
        .collect()
}

/// Waits until the page was told that contact with `reference` stands as `state`.
async fn until_told(companion: &Companion, reference: &str, state: &str) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(found) = told_other(companion, reference)
                .into_iter()
                .find(|other| other["contact"]["state"] == state)
            {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "contact with the host was not told as {state}: it was told {:?}",
            told_other(companion, reference)
        )
    })
}

/// Waits until the last state the page was told has the host `reference` names in use.
async fn until_last_told_host(companion: &Companion, reference: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while companion
            .told_connection()
            .last()
            .is_none_or(|state| state["host"]["reference"] != reference)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the page is told of the host chosen last");
}

/// Waits for the visit to `host` to reach its hold, and lets every other visit that reaches it go on.
async fn visit_held(
    visits: &mut tokio::sync::mpsc::UnboundedReceiver<companion_tauri::inbox::testing::VisitHold>,
    host: kr_protocol::ids::DeviceId,
) -> companion_tauri::inbox::testing::VisitHold {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let hold = visits.recv().await.expect("a visit reaches the hold");
            if hold.host == host {
                return hold;
            }
            hold.release();
        }
    })
    .await
    .expect("the visit reaches its hold")
}

/// A row of a pass's answer, by the reference of its host.
fn row_of<'a>(reply: &'a serde_json::Value, reference: &str) -> Option<&'a serde_json::Value> {
    hosts_of(reply)
        .iter()
        .find(|row| row["reference"] == reference)
}

/// A pass whose host A refuses and whose host C is held in its dial: A's refusal is told before the
/// pass returns, and the owner's state has it while the reply is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_host_does_not_delay_another_hosts_contact_event() {
    let v = visiting().await;
    let _arrivals = v.control.hold_dialled(v.c.network().endpoint_id());
    v.control
        .refuse_request(Some((Method::AttentionRead, lapsed())));
    let pass = v.pass();
    let refused = until_told(v.companion(), &v.a_ref, "refused").await;
    assert_eq!(refused["contact"]["request"], "attention_read", "{refused}");
    assert!(
        !pass.is_finished(),
        "A's refusal was told before the pass returned"
    );
    v.control.refuse_request(None);
    v.control.release_dialled();
    pass.await
        .expect("the pass ran")
        .expect("the pass answered");
    v.stop().await;
}

/// The same moment, read from the owner's own state and not from what was told: the contact of A is
/// in the connection's state while the pass's reply is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visits_contact_is_published_while_the_pass_reply_is_held() {
    let v = visiting().await;
    let _arrivals = v.control.hold_dialled(v.c.network().endpoint_id());
    v.control.end_connections(true);
    let pass = v.pass();
    let lost = until_told(v.companion(), &v.a_ref, "out_of_contact").await;
    assert!(lost["contact"]["since_ms"].is_u64(), "{lost}");
    assert!(!pass.is_finished(), "the reply is still held");
    assert_eq!(
        contact_of(v.companion(), &v.a_ref)["state"],
        "out_of_contact"
    );
    v.control.end_connections(false);
    v.control.release_dialled();
    pass.await
        .expect("the pass ran")
        .expect("the pass answered");
    v.stop().await;
}

/// A refuses and then recovers while C is slow: the page is told the two, in the order of their
/// revisions, each once, and the second pass does not wait for C to tell it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_then_a_recovery_of_one_host_is_told_in_order_while_c_is_slow() {
    let v = visiting().await;
    let _arrivals = v.control.hold_dialled(v.c.network().endpoint_id());
    v.control
        .refuse_request(Some((Method::AttentionRead, lapsed())));
    let first = v.pass();
    until_told(v.companion(), &v.a_ref, "refused").await;
    v.control.refuse_request(None);
    let second = v.pass();
    until_told(v.companion(), &v.a_ref, "in_contact").await;
    assert!(
        !first.is_finished() && !second.is_finished(),
        "C holds both"
    );
    v.control.release_dialled();
    first.await.expect("the first ran").expect("answered");
    second.await.expect("the second ran").expect("answered");
    // Every state C's contact makes carries A's entry too: A's changes are the entries that differ
    // from the one before.
    let mut told = told_other(v.companion(), &v.a_ref);
    told.dedup_by(|later, earlier| later["contact"] == earlier["contact"]);
    let states: Vec<&str> = told
        .iter()
        .filter_map(|other| other["contact"]["state"].as_str())
        .collect();
    assert_eq!(states, ["refused", "in_contact"], "{told:?}");
    let revisions: Vec<u64> = told
        .iter()
        .map(|other| other["revision"].as_u64().expect("a revision"))
        .collect();
    assert!(revisions[0] < revisions[1], "{revisions:?}");
    v.stop().await;
}

/// A host that holds a loss from a visit and then becomes the one in use keeps that loss and its
/// start: the one record has one loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_becomes_the_one_in_use_keeps_its_one_loss() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass()
        .await
        .expect("the pass ran")
        .expect("the pass answered");
    let lost = contact_of(v.companion(), &v.a_ref);
    assert_eq!(lost["state"], "out_of_contact", "A's visit lost it: {lost}");
    let since = lost["since_ms"].as_u64().expect("since when");
    v.control.end_connections(false);
    v.control.hold();
    let using = v
        .companion()
        .start_call("hosts_use", json!({ "reference": v.a_ref }));
    v.companion().told_host(&v.a_ref).await;
    let told = v
        .companion()
        .told_connection()
        .into_iter()
        .rev()
        .find(|state| state["host"]["reference"] == v.a_ref.as_str())
        .expect("the choice was told");
    assert_eq!(told["contact"]["state"], "out_of_contact", "{told}");
    assert_eq!(told["contact"]["since_ms"].as_u64(), Some(since), "{told}");
    v.control.stop_holding();
    v.control.release_all();
    using.await.expect("the choice ran").expect("A is chosen");
    v.stop().await;
}

/// A refusal clears what was read of the host, in the one revision that tells the refusal: the
/// refusal is told with a moved epoch, and the answer's row for the host holds no read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_clears_the_hosts_read_in_the_same_revision() {
    let v = visiting().await;
    let read = v.pass().await.expect("ran").expect("answered");
    assert!(row_of(&read, &v.a_ref).expect("A's row")["result"].is_object());
    let epoch = told_other(v.companion(), &v.a_ref)
        .last()
        .expect("A's contact was told")["inbox_epoch"]
        .as_u64()
        .expect("an epoch");
    v.control
        .refuse_request(Some((Method::AttentionRead, lapsed())));
    let refused_answer = v.pass().await.expect("ran").expect("answered");
    let refused = until_told(v.companion(), &v.a_ref, "refused").await;
    assert!(
        refused["inbox_epoch"].as_u64().expect("an epoch") > epoch,
        "the refusal moved the epoch: {refused}"
    );
    let row = row_of(&refused_answer, &v.a_ref).expect("A's row");
    assert!(
        row["result"].is_null() && row["read_at_ms"].is_null(),
        "{row}"
    );
    assert!(
        refused_answer["revision"].as_u64() >= refused["revision"].as_u64(),
        "the answer was read at or after the revision that told the refusal"
    );
    v.stop().await;
}

/// Two passes overlap, and the older answers with the newer read: a pass answers with what the owner
/// holds, not with what its own visit read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_answers_with_the_records_not_its_own_results() {
    let v = visiting().await;
    let _arrivals = v.control.hold_dialled(v.c.network().endpoint_id());
    let older = v.pass();
    until_told(v.companion(), &v.a_ref, "in_contact").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let newer = v.pass();
    // A is read twice: by the older pass, and by the newer one, which does not wait for C to read A.
    tokio::time::timeout(WATCHDOG, async {
        while v.control.sent(Method::AttentionRead) < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("A is read by both passes");
    tokio::time::sleep(Duration::from_millis(300)).await;
    v.control.release_dialled();
    let older = older.await.expect("ran").expect("answered");
    let newer = newer.await.expect("ran").expect("answered");
    let (old_row, new_row) = (
        row_of(&older, &v.a_ref).expect("A's row"),
        row_of(&newer, &v.a_ref).expect("A's row"),
    );
    assert_eq!(
        old_row["read_at_ms"], new_row["read_at_ms"],
        "the older pass shows the newer read"
    );
    assert_eq!(old_row["read_serial"], new_row["read_serial"]);
    v.stop().await;
}

/// A host that answers and whose inbox changes between two pages twice gave no complete inbox: it is
/// in contact, a loss it had ends, and no result is added.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answered_visit_without_a_complete_inbox_ends_a_loss_and_adds_no_result() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass().await.expect("ran").expect("answered");
    assert_eq!(
        contact_of(v.companion(), &v.a_ref)["state"],
        "out_of_contact"
    );
    v.control.end_connections(false);
    v.control.refuse_request(Some((
        Method::AttentionRead,
        kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::DraftConflict,
            "an item went between two pages",
        ),
    )));
    let answered = v.pass().await.expect("ran").expect("answered");
    assert_eq!(contact_of(v.companion(), &v.a_ref)["state"], "in_contact");
    let row = row_of(&answered, &v.a_ref).expect("A's row");
    assert!(row["result"].is_null(), "no result was added: {row}");
    v.stop().await;
}

/// A loss is stamped when the visit that found it completed: a visit that waits out its bound for an
/// answer that never comes stamps the moment it gave up, not the moment it began.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_is_stamped_when_the_visit_completed() {
    let v = visiting().await;
    let _arrivals = v.control.hold_dialled(v.a.network().endpoint_id());
    let before = now_ms();
    v.pass().await.expect("ran").expect("answered");
    let after = now_ms();
    v.control.release_dialled();
    let lost = contact_of(v.companion(), &v.a_ref);
    assert_eq!(lost["state"], "out_of_contact", "{lost}");
    let since = lost["since_ms"].as_u64().expect("since when");
    assert!(
        since >= before + 9_000 && since <= after,
        "stamped at the end of the visit: {before} {since} {after}"
    );
    v.stop().await;
}

/// The time a read is dated is the time its visit committed, not the time it began.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_at_is_the_commit_time() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let before = now_ms();
    let pass = v.pass();
    let a = v.id_of(&v.a_ref);
    let hold = visit_held(&mut visits, a).await;
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    hold.release();
    drop(visits);
    let answered = pass.await.expect("ran").expect("answered");
    let after = now_ms();
    let read_at = row_of(&answered, &v.a_ref).expect("A's row")["read_at_ms"]
        .as_u64()
        .expect("a read time");
    assert!(
        read_at >= before + 2_000 && read_at <= after,
        "dated at the commit: {before} {read_at} {after}"
    );
    v.stop().await;
}

/// A forget of a host that held a visible record (its own loss in `others`) is an event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forget_tells_a_host_that_had_a_visible_record() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass().await.expect("ran").expect("answered");
    until_told(v.companion(), &v.a_ref, "out_of_contact").await;
    v.companion().told_everything().await;
    let before = v.companion().told_connection().len();
    v.companion()
        .call("hosts_forget", json!({ "reference": v.a_ref }))
        .expect("A is forgotten");
    v.companion().told_everything().await;
    let told = v.companion().told_connection();
    assert!(told.len() > before, "the forget was told");
    let last = told.last().expect("a state");
    assert!(
        last["others"]
            .as_array()
            .expect("others")
            .iter()
            .all(|other| other["reference"] != v.a_ref.as_str()),
        "A's row left `others`: {last}"
    );
    v.stop().await;
}

/// A visit held after its read, across a forget and a pairing again with the same host, commits
/// nothing, and its connection is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_held_across_a_forget_and_a_repair_commits_nothing_and_closes_its_connection() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let pass = v.pass();
    let hold = visit_held(&mut visits, v.id_of(&v.a_ref)).await;
    let closed = v.control.closed();
    v.pair_a_again();
    hold.release();
    drop(visits);
    let answered = pass.await.expect("ran").expect("answered");
    assert!(
        contact_of(v.companion(), &v.a_ref).is_null(),
        "the held visit wrote nothing"
    );
    assert!(
        row_of(&answered, &v.a_ref).is_none_or(|row| row["result"].is_null()),
        "{answered}"
    );
    assert!(
        v.control.closed() > closed,
        "the visit's connection was closed"
    );
    v.stop().await;
}

/// A host forgotten and paired again after the pass listed it, and before the visit began, is not
/// visited with the old credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listed_host_forgotten_and_paired_again_before_the_spawn_is_not_visited_with_the_old_credentials()
 {
    let v = visiting().await;
    let mut passes = v.companion().inbox().watch_passes();
    let pass = v.pass();
    let hold = tokio::time::timeout(WATCHDOG, passes.recv())
        .await
        .expect("the pass reaches the hold")
        .expect("a hold");
    let endpoint = v.a.network().endpoint_id();
    let asked = v.control.asked_of(&endpoint);
    v.pair_a_again();
    hold.release();
    drop(passes);
    pass.await.expect("ran").expect("answered");
    assert_eq!(
        v.control.asked_of(&endpoint),
        asked,
        "the old credentials were not used to visit A"
    );
    v.stop().await;
}

/// A re-pair after the read, with the same host and another identity and no forget, leaves the
/// owner's generation, role and epoch as they are: only the second check of the pairing rejects the
/// commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_re_pair_after_the_read_without_a_forget_is_rejected_by_the_second_verify() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let pass = v.pass();
    let a = v.id_of(&v.a_ref);
    let hold = visit_held(&mut visits, a).await;
    let device = v.companion().device();
    let old = device.host_by_reference(&v.a_ref).expect("A is listed");
    let new = kr_client::pairing::paired::PairedHost {
        device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        ..old
    };
    device
        .pairing()
        .hosts
        .record(new)
        .expect("the host is paired again, with no forget");
    hold.release();
    drop(visits);
    let answered = pass.await.expect("ran").expect("answered");
    assert!(
        contact_of(v.companion(), &v.a_ref).is_null(),
        "nothing was committed over the old pairing"
    );
    assert!(
        row_of(&answered, &v.a_ref).is_none_or(|row| row["result"].is_null()),
        "{answered}"
    );
    v.stop().await;
}

/// A visitor queued behind another visit of the same host, across a forget of it, takes no
/// connection and makes no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visitor_queued_across_a_forget_takes_no_connection_and_makes_no_record() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let first = v.pass();
    let a = v.id_of(&v.a_ref);
    let hold = visit_held(&mut visits, a).await;
    let endpoint = v.a.network().endpoint_id();
    let queued = v.pass();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let asked = v.control.asked_of(&endpoint);
    v.companion()
        .call("hosts_forget", json!({ "reference": v.a_ref }))
        .expect("A is forgotten");
    hold.release();
    drop(visits);
    first.await.expect("ran").expect("answered");
    queued.await.expect("ran").expect("answered");
    assert_eq!(
        v.control.asked_of(&endpoint),
        asked,
        "the queued visitor asked for no connection"
    );
    assert!(contact_of(v.companion(), &v.a_ref).is_null());
    v.stop().await;
}

/// A visit that began before its host was used and left again commits nothing: the host's epoch has
/// moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_that_began_before_the_host_was_used_and_recovered_commits_nothing() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let pass = v.pass();
    let hold = visit_held(&mut visits, v.id_of(&v.a_ref)).await;
    let first_ref = reference_for(v.companion(), &v.first);
    v.companion()
        .call("hosts_use", json!({ "reference": v.a_ref }))
        .expect("A is chosen");
    v.companion()
        .call("hosts_use", json!({ "reference": first_ref }))
        .expect("the first is chosen again");
    hold.release();
    drop(visits);
    let answered = pass.await.expect("ran").expect("answered");
    let row = row_of(&answered, &v.a_ref).expect("A is one of the others again");
    assert!(
        row["result"].is_null(),
        "the visit that began before the host was used wrote no read: {row}"
    );
    v.stop().await;
}

/// A host that is the one in use when the visit is to begin is refused at the owner: no visit
/// connection is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_for_the_host_in_use_is_refused_at_admit() {
    let v = visiting().await;
    let mut passes = v.companion().inbox().watch_passes();
    let pass = v.pass();
    let hold = tokio::time::timeout(WATCHDOG, passes.recv())
        .await
        .expect("the pass reaches the hold")
        .expect("a hold");
    v.companion()
        .call("hosts_use", json!({ "reference": v.a_ref }))
        .expect("A is chosen");
    let endpoint = v.a.network().endpoint_id();
    let asked = v.control.asked_of(&endpoint);
    hold.release();
    drop(passes);
    pass.await.expect("ran").expect("answered");
    assert_eq!(
        v.control.asked_of(&endpoint),
        asked,
        "no visit asked for a connection to the host in use"
    );
    v.stop().await;
}

/// A host left behind keeps its loss and the loss's start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_left_behind_keeps_its_loss_and_start() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass().await.expect("ran").expect("answered");
    let since = contact_of(v.companion(), &v.a_ref)["since_ms"]
        .as_u64()
        .expect("since when");
    v.control.end_connections(false);
    v.control.hold();
    let first_ref = reference_for(v.companion(), &v.first);
    let using = v
        .companion()
        .start_call("hosts_use", json!({ "reference": v.a_ref }));
    v.companion().told_host(&v.a_ref).await;
    let leaving = v
        .companion()
        .start_call("hosts_use", json!({ "reference": first_ref }));
    until_last_told_host(v.companion(), &first_ref).await;
    let kept = contact_of(v.companion(), &v.a_ref);
    assert_eq!(kept["state"], "out_of_contact", "{kept}");
    assert_eq!(kept["since_ms"].as_u64(), Some(since), "{kept}");
    v.control.stop_holding();
    v.control.release_all();
    using.await.expect("ran").expect("A was chosen");
    leaving.await.expect("ran").expect("the first was chosen");
    v.stop().await;
}

/// A repeated failed visit leaves the loss as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_failed_visits_leave_the_loss_as_it_was() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass().await.expect("ran").expect("answered");
    let first = contact_of(v.companion(), &v.a_ref);
    assert_eq!(first["state"], "out_of_contact", "{first}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    v.pass().await.expect("ran").expect("answered");
    assert_eq!(contact_of(v.companion(), &v.a_ref), first);
    v.stop().await;
}

/// A loss after a recovery is a new loss, with its own start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_loss_after_a_restore_is_a_new_record() {
    let v = visiting().await;
    v.control.end_connections(true);
    v.pass().await.expect("ran").expect("answered");
    let first = contact_of(v.companion(), &v.a_ref)["since_ms"]
        .as_u64()
        .expect("since when");
    v.control.end_connections(false);
    v.pass().await.expect("ran").expect("answered");
    assert_eq!(contact_of(v.companion(), &v.a_ref)["state"], "in_contact");
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The restoring visit kept its connection, so the second loss is one of the answer to the read
    // over it, and of the fresh connection that follows.
    v.control.end_connections(true);
    v.control.lose_the_answer_to(Some(Method::AttentionRead));
    v.pass().await.expect("ran").expect("answered");
    let second = contact_of(v.companion(), &v.a_ref)["since_ms"]
        .as_u64()
        .expect("since when");
    assert!(second > first, "{first} {second}");
    v.stop().await;
}

/// A second visit of one host waits while the first holds the host's turn, and then reads over the
/// connection the first kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_visit_waits_while_the_first_holds_the_gate() {
    let v = visiting().await;
    let mut visits = v.companion().inbox().watch_visits();
    let first = v.pass();
    let a = v.id_of(&v.a_ref);
    let hold = visit_held(&mut visits, a).await;
    let second = v.pass();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reads = v.control.sent(Method::AttentionRead);
    let asked = v.control.asked_of(&v.a.network().endpoint_id());
    assert!(!second.is_finished(), "the second pass waits for A's turn");
    hold.release();
    drop(visits);
    first.await.expect("ran").expect("answered");
    second.await.expect("ran").expect("answered");
    assert!(
        v.control.sent(Method::AttentionRead) > reads,
        "the second visit read A once it had its turn"
    );
    assert_eq!(
        v.control.asked_of(&v.a.network().endpoint_id()),
        asked,
        "over the connection the first kept"
    );
    v.stop().await;
}

/// A host replaced at one endpoint by another host identity, with no forget, loses its row, its
/// cache and its connection at the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_replaced_at_the_same_endpoint_loses_its_row_cache_and_connection() {
    let v = visiting().await;
    let first = v.pass().await.expect("ran").expect("answered");
    assert!(row_of(&first, &v.a_ref).expect("A's row")["result"].is_object());
    let closed = v.control.closed();
    let device = v.companion().device();
    let old = device.host_by_reference(&v.a_ref).expect("A is listed");
    let replacement = kr_client::pairing::paired::PairedHost {
        host_device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [7; 16],
        )),
        device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16])),
        ..old
    };
    device
        .pairing()
        .hosts
        .record(replacement)
        .expect("the endpoint's record is replaced");
    let next = v.pass().await.expect("ran").expect("answered");
    assert!(row_of(&next, &v.a_ref).is_none(), "A's row is gone: {next}");
    assert!(contact_of(v.companion(), &v.a_ref).is_null());
    assert!(v.control.closed() > closed, "A's connection was closed");
    v.stop().await;
}

/// A pass that listed the host under one pairing, and goes on to visit it after the host was
/// forgotten and paired again, under another pairing that a visit has read since, changes nothing:
/// the current record, its read and its connection stand, and no revision is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_listing_leaves_the_current_record_alone() {
    let v = visiting().await;
    let device = v.companion().device();
    let current = device.host_by_reference(&v.a_ref).expect("A is listed");
    let earlier = kr_client::pairing::paired::PairedHost {
        device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        ..current.clone()
    };
    device
        .pairing()
        .hosts
        .record(earlier)
        .expect("A is listed under the earlier pairing");
    let mut passes = v.companion().inbox().watch_passes();
    let old = v.pass();
    let hold = tokio::time::timeout(WATCHDOG, passes.recv())
        .await
        .expect("the old pass reaches the hold")
        .expect("a hold");

    // The host is forgotten and paired again, and a new pass reads it under the current pairing.
    v.companion()
        .call("hosts_forget", json!({ "reference": v.a_ref }))
        .expect("A is forgotten");
    device
        .pairing()
        .hosts
        .record(current)
        .expect("A is paired again");
    let fresh = v.pass();
    tokio::time::timeout(WATCHDOG, passes.recv())
        .await
        .expect("the new pass reaches the hold")
        .expect("a hold")
        .release();
    let fresh = fresh.await.expect("ran").expect("answered");
    let serial = row_of(&fresh, &v.a_ref).expect("A's row")["read_serial"].clone();
    assert!(
        serial.is_u64(),
        "A was read under the current pairing: {fresh}"
    );
    let revision = v
        .companion()
        .call("connection_state", json!({}))
        .expect("the connection's state")["revision"]
        .clone();
    let endpoint = v.a.network().endpoint_id();
    let asked = v.control.asked_of(&endpoint);

    hold.release();
    drop(passes);
    let answered = old.await.expect("ran").expect("answered");
    assert_eq!(
        row_of(&answered, &v.a_ref).map(|row| row["read_serial"].clone()),
        Some(serial),
        "the stale listing did not read A again: {answered}"
    );
    assert_eq!(
        v.companion()
            .call("connection_state", json!({}))
            .expect("the connection's state")["revision"],
        revision,
        "no revision"
    );
    assert_eq!(
        v.control.asked_of(&endpoint),
        asked,
        "no connection was asked for"
    );
    v.stop().await;
}

/// A visit that found the host's record to be of another pairing, and verified the listing again,
/// is held before it replaces the record while the host is chosen and reached under the pairing it
/// was listed with: the replace is refused, and nothing changes: not the record, not the
/// revision, and not the live connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replace_after_the_host_was_chosen_and_reached_changes_nothing() {
    let v = visiting().await;
    // The owner holds a record of A under another pairing: the device was listing A so when a pass
    // visited it, and nothing told the owner when the listing went back to the pairing it holds.
    let device = v.companion().device();
    let held = device.host_by_reference(&v.a_ref).expect("A is listed");
    let other = kr_client::pairing::paired::PairedHost {
        device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        ..held.clone()
    };
    device
        .pairing()
        .hosts
        .record(other)
        .expect("A is listed under another pairing");
    v.pass().await.expect("ran").expect("answered");
    device
        .pairing()
        .hosts
        .record(held)
        .expect("A is listed under the pairing the device holds");
    let mut replaces = v.companion().inbox().watch_replaces();
    let pass = v.pass();
    let a = v.id_of(&v.a_ref);
    let hold = tokio::time::timeout(WATCHDOG, async {
        loop {
            let hold = replaces.recv().await.expect("a visit reaches the hold");
            if hold.host == a {
                return hold;
            }
            hold.release();
        }
    })
    .await
    .expect("the visit finds the record to be of another pairing");

    // The host is chosen under the pairing the device holds, and reached, while the visit is held.
    v.companion()
        .call("hosts_use", json!({ "reference": v.a_ref }))
        .expect("A is chosen");
    let state = connection(v.companion(), true).await;
    assert_eq!(state["host"]["reference"], v.a_ref.as_str(), "{state}");
    let told = v.companion().told_connection().len();
    let closed = v.control.closed();
    let app_state = v.companion().app.state::<companion_tauri::AppState>();
    let owner = app_state.contact_owner();
    let revision = owner.revision();

    hold.release();
    drop(replaces);
    let answered = pass.await.expect("ran").expect("answered");
    assert!(
        row_of(&answered, &v.a_ref).is_none(),
        "A is the host in use, not one of the others: {answered}"
    );
    assert_eq!(
        owner.revision(),
        revision,
        "the refused replace made no revision"
    );
    assert_eq!(
        v.companion().told_connection().len(),
        told,
        "the refused replace told nothing"
    );
    assert!(
        owner.records(&[a]).rows.is_empty(),
        "no record of A as another host"
    );
    assert_eq!(
        v.control.closed(),
        closed,
        "the live connection was not closed"
    );
    let after = v
        .companion()
        .call("connection_state", json!({}))
        .expect("the connection's state");
    assert_eq!(after["connected"], true, "{after}");
    assert_eq!(after["host"], state["host"], "{after}");
    v.stop().await;
}

/// A choice made from a listing whose pairing is no longer the one this computer holds, of a host
/// that is one of the others and was read, changes nothing of its record: the read, the retained
/// connection and the revision stand, and the next visit reads over the same connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_choice_leaves_the_current_pairings_record_read_and_connection_alone() {
    let v = visiting().await;
    v.pass().await.expect("ran").expect("answered");
    let a = v.id_of(&v.a_ref);
    let state = v.companion().app.state::<companion_tauri::AppState>();
    let owner = state.contact_owner();
    let serial = owner.records(&[a]).rows[0]
        .read
        .as_ref()
        .expect("A was read")
        .serial();
    let revision = owner.revision();
    let endpoint = v.a.network().endpoint_id();
    let asked = v.control.asked_of(&endpoint);
    let closed = v.control.closed();

    let mut stale = v
        .companion()
        .device()
        .host_by_reference(&v.a_ref)
        .expect("A is listed");
    stale.device_id =
        kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([42; 16]));
    let refused = companion_tauri::hosts::use_host(v.companion().app.handle(), stale).await;
    assert!(refused.is_err(), "the stale choice is refused");

    assert_eq!(owner.revision(), revision, "no revision");
    assert_eq!(
        owner.records(&[a]).rows[0]
            .read
            .as_ref()
            .map(|read| read.serial()),
        Some(serial),
        "A's read stands"
    );
    assert!(owner.holds_resources_of(a), "A's connection is retained");
    assert_eq!(v.control.closed(), closed, "nothing was closed");
    assert_eq!(contact_of(v.companion(), &v.a_ref)["state"], "in_contact");
    v.pass().await.expect("ran").expect("answered");
    assert_eq!(
        v.control.asked_of(&endpoint),
        asked,
        "the next visit read over the connection that was kept"
    );
    v.stop().await;
}

/// A visit over the connection the last visit kept, that stalls past its bound, leaves the old read
/// as it was, begins the host's loss, and closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timed_out_visit_over_a_reused_connection_keeps_the_old_read_and_closes_the_connection() {
    let v = visiting().await;
    v.companion()
        .call("hosts_forget", json!({ "reference": v.c_ref }))
        .expect("C is forgotten");
    let first = v.pass().await.expect("ran").expect("answered");
    let seeded = row_of(&first, &v.a_ref).expect("A's row");
    let (serial, read_at) = (seeded["read_serial"].clone(), seeded["read_at_ms"].clone());
    assert!(serial.is_u64() && read_at.is_u64(), "A was read: {seeded}");
    let closed = v.control.closed();
    v.control.hold_next_request(Method::AttentionRead);
    let second = v.pass().await.expect("ran").expect("answered");
    v.control.release_request();
    let kept = row_of(&second, &v.a_ref).expect("A's row");
    assert_eq!(kept["read_serial"], serial, "the old read stands: {kept}");
    assert_eq!(kept["read_at_ms"], read_at, "{kept}");
    assert_eq!(
        contact_of(v.companion(), &v.a_ref)["state"],
        "out_of_contact"
    );
    assert!(
        v.control.closed() > closed,
        "the connection the visit stalled on was closed"
    );
    v.stop().await;
}
