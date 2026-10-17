//! The host and the voice service a phone's call runs against on a simulator or an emulator.
//!
//! This is not a test of the product by itself: it is the machine side of a device run, and a
//! script starts it (`scripts/e2e-voice-call-device.sh`), so it is ignored in an ordinary run.
//! It starts the real daemon, on the loopback interface, and a stand-in for the managed voice
//! service on one loopback port that answers a call's offer with an answer built from the offer's
//! sections. It then issues a direct invitation that a phone pairs with, approves the phone as the
//! host's owner, and stays up while the phone starts a call, until the script says the phone is
//! done. It writes what the voice service and the daemon saw, for the script to judge beside what
//! the phone reported.
//!
//! The script and this suite talk through files in `KR_HARNESS_DIR`, on the internal disk:
//!
//! | File | Written by | Holds |
//! | --- | --- | --- |
//! | `ready.json` | this suite | the voice service's origin and port and the token its control accepts |
//! | `go` | the script | nothing; the phone is installed and the invitation may be issued |
//! | `invitation.txt` | this suite | the direct invitation, with the host reachable at `KR_HARNESS_PEER` |
//! | `finish` | the script | nothing; the phone is done |
//! | `report.json` | this suite | what the voice service saw |
//!
//! `KR_HARNESS_PEER` is the name the phone reaches this machine by: `127.0.0.1` for a simulator,
//! which shares the machine's network, and `10.0.2.2` for an emulator. `KR_HARNESS_SECONDS`
//! bounds the whole run. No test here makes a live provider call.

mod net_support;
mod voice_support;

#[path = "../../../apps/companion/src-tauri/src/probe/answer.rs"]
mod answer;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::pairing::{NetworkHint, QrPayload};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use voice_support::StandIn;

/// The token the phone's account holds, which the stand-in's control accepts.
const TOKEN: &str = "harness-account-token";

/// How long the phone is given to ask for its invitation after the script says it is installed.
const INVITATION_WAIT: Duration = Duration::from_secs(60);

/// The document an operator writes to name the voice service.
fn document_naming(origin: &str) -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(origin.to_owned());
    document
}

/// Waits until `file` exists, or `within` passes.
async fn appears(file: &Path, within: Duration) -> bool {
    let end = Instant::now() + within;
    while !file.exists() {
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    true
}

/// Writes `text` to `file` where only this user can read it.
fn write_private(file: &Path, text: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut open = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(file)
        .expect("a file in the harness directory");
    open.write_all(text.as_bytes())
        .expect("the file is written");
}

/// The invitation's text with the host reachable at `peer`: the port the host bound, on the name
/// the phone reaches this machine by. The hint is only where to dial; the host's endpoint identity
/// is what authenticates it.
fn invitation_for(invited: &kr_protocol::invitation::PairInviteResult, peer: &str) -> String {
    let mut payload = calls::direct_payload(invited);
    let port = payload
        .network_config
        .direct_addresses
        .first()
        .and_then(|hint| hint.as_str().rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .expect("the host names an address to dial");
    payload.network_config.direct_addresses =
        vec![NetworkHint::new(format!("{peer}:{port}")).expect("an address that is a hint")];
    QrPayload::Direct(Box::new(payload))
        .to_text()
        .expect("a payload that is text")
        .to_string()
}

/// Runs the host and the voice service for one phone, from its invitation to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "started by scripts/e2e-voice-call-device.sh beside a simulator or an emulator"]
async fn a_phone_is_paired_and_runs_a_call_against_a_real_host() {
    let directory = PathBuf::from(std::env::var("KR_HARNESS_DIR").expect("KR_HARNESS_DIR"));
    let peer = std::env::var("KR_HARNESS_PEER").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let seconds: u64 = std::env::var("KR_HARNESS_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(900);
    let end = Instant::now() + Duration::from_secs(seconds);
    let left = || end.saturating_duration_since(Instant::now());

    let stand_in = StandIn::start().await;
    stand_in.answer_offers_with(|offer| answer::answer_for(offer).unwrap_or_default());
    stand_in.accept_control_token(TOKEN);
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document(&owner, &document_naming(stand_in.origin())).await;
    host.controller()
        .host_account()
        .keep_for_test(stand_in.host_grant())
        .await;

    write_private(
        &directory.join("ready.json"),
        &serde_json::json!({ "origin": stand_in.origin(), "token": TOKEN }).to_string(),
    );
    assert!(
        appears(&directory.join("go"), INVITATION_WAIT.min(left())).await,
        "the script never said the phone was ready"
    );

    // The invitation lives for minutes, so it is issued only now, with the phone installed.
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(&owner);
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
        &signer,
    )
    .await
    .expect("a direct invitation");
    write_private(
        &directory.join("invitation.txt"),
        &invitation_for(&invited, &peer),
    );

    // The phone redeems it, and the host's owner approves the device that did.
    let approval = async {
        loop {
            let status = calls::owner_status(&mut client, invited.invitation_id)
                .await
                .expect("the invitation's status");
            if status.owner.0.and_then(|view| view.approval.0).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(left(), approval)
        .await
        .expect("the phone redeemed the invitation");
    calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves the phone");

    // The phone runs its call. The script says when it is done.
    appears(&directory.join("finish"), left()).await;

    let control = stand_in.control().report();
    let report = serde_json::json!({
        "creations": stand_in.count("/api/voice/sessions"),
        "closes": stand_in.count("/api/voice/sessions/call-1/close"),
        "control_tokens": control
            .upgrades
            .iter()
            .map(|upgrade| upgrade.authorization.clone())
            .collect::<Vec<_>>(),
        // What the phone asked of the control: its frames, whatever became of them. The route only
        // lets some of them through to the provider, and a close is the service's own.
        "control_commands": control
            .frames
            .iter()
            .filter_map(|frame| serde_json::from_str::<serde_json::Value>(frame).ok())
            .filter_map(|frame| frame["command"].as_str().map(str::to_owned))
            .collect::<Vec<_>>(),
        "token": TOKEN,
    });
    write_private(&directory.join("report.json"), &report.to_string());
    host.stop().await;
}
