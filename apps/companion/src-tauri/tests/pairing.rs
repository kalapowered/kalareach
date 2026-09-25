//! What the pairing screen and the owner's confirmations send the page, and where this computer
//! keeps its tries with a code.
//!
//! The daemon here is kr-controller's in-process host, the same network service and controller the
//! binary runs, with its room in this process; its test support is included by path. The device is
//! this crate's own [`Device`] and [`Owner`], built from parts a test gives: a secret store in
//! memory rather than this computer's keychain, the host's room, and endpoints on loopback.

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::device::Device;
use companion_tauri::owner::Owner;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::{AttemptState, CandidateRoom};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome, ReviewOutcome};
use kr_client::pairing::room::{RoomError, RoomSocket};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretStore};
use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::invitation::PairingApproval;
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams, PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    CodeQrPayload, KeyPurpose, Locator, ProposedGrant, QrPayload, RendezvousOrigin, ShortCode,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, to_base64url};
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use support::{Capture, Companion, StubPaste, WATCHDOG, device, owner_device, reached};

fn awaiting(state: &AttemptState) -> bool {
    matches!(state, AttemptState::AwaitingApproval { .. })
}

fn paired(state: &AttemptState) -> bool {
    matches!(state, AttemptState::Paired { .. })
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

/// Issues a code invitation at the host's default origin.
async fn invite_code(
    environment: EnvironmentId,
    client: &mut kr_ipc::client::LocalClient,
    signer: &Signer<'_>,
) -> PairInviteResult {
    let grant = viewer();
    calls::confirm_subject(
        environment,
        client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Code,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
        signer,
    )
    .await
    .expect("answered");
    calls::mutate(
        environment,
        client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Code {
                rendezvous_origin: Nullable::null(),
            },
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant,
        },
    )
    .await
    .expect("a code invitation")
}

/// A ceremony that answers as a test says, and counts what it was asked.
struct StubCeremony {
    answer: Mutex<CeremonyOutcome>,
    asked: AtomicUsize,
}

impl StubCeremony {
    fn answering(answer: CeremonyOutcome) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            asked: AtomicUsize::new(0),
        })
    }

    /// Answers `answer` from now on.
    fn will_answer(&self, answer: CeremonyOutcome) {
        *self.answer.lock().expect("the answer") = answer;
    }
}

impl Ceremony for StubCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, _reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let answer = *self.answer.lock().expect("the answer");
        Box::pin(async move { answer })
    }
}

/// A ceremony a person takes their time over, and then confirms.
struct SlowCeremony {
    takes: Duration,
}

impl Ceremony for SlowCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, _reason: &'a str, within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        Box::pin(async move {
            tokio::time::sleep(self.takes.min(within)).await;
            CeremonyOutcome::Confirmed
        })
    }
}

/// What a host asks its owner to confirm: an invitation for a viewer, offered on its network.
fn an_invitation() -> ConfirmationSubject {
    ConfirmationSubject::IssueInvitation {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: viewer(),
    }
}

/// Every way a secret could appear in the page's text.
fn spellings(bytes: &[u8]) -> Vec<String> {
    use std::fmt::Write as _;
    let hex = bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    });
    let array = serde_json::to_string(bytes).expect("an array");
    vec![to_base64url(bytes), hex, array]
}

/// The captured texts that carry any of `secrets`.
fn carrying(texts: &[String], secrets: &[String]) -> Vec<String> {
    texts
        .iter()
        .filter(|text| secrets.iter().any(|secret| text.contains(secret)))
        .cloned()
        .collect()
}

/// The digests the owner approves the device bound to `invitation` by, spelled every way a secret
/// could appear.
async fn approved(
    client: &mut kr_ipc::client::LocalClient,
    invitation: kr_protocol::ids::InvitationId,
) -> Vec<String> {
    let status = calls::owner_status(client, invitation)
        .await
        .expect("the owner reads its invitation");
    let approval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("a bound candidate the owner can approve");
    let digests = match approval {
        PairingApproval::Code {
            transcript,
            host_bundle_hash,
            client_bundle_hash,
        } => vec![transcript, host_bundle_hash, client_bundle_hash],
        PairingApproval::Direct {
            transcript_digest,
            client_key_digest,
        } => vec![transcript_digest, client_key_digest],
    };
    digests
        .iter()
        .flat_map(|digest| spellings(digest.as_bytes()))
        .collect()
}

/// The four private seeds of the device whose secrets are in `store`, as the store keeps them, and
/// its two public identities, spelled every way a secret could appear.
fn key_bytes(store: &dyn SecretStore) -> Vec<String> {
    let keys = kr_crypto::store::load_device_keys(store, "device")
        .expect("readable")
        .expect("the device made its keys");
    let mut bytes: Vec<Vec<u8>> = KeyPurpose::ALL
        .iter()
        .map(|purpose| {
            let name = kr_crypto::store::SecretName::device_key("device", *purpose)
                .expect("a secret's name");
            store
                .get(&name)
                .expect("readable")
                .expect("the seed is kept")
                .expose()
                .to_vec()
        })
        .collect();
    bytes.push(keys.transport.public().as_bytes().to_vec());
    bytes.push(keys.authorisation.public().as_bytes().to_vec());
    bytes.iter().flat_map(|bytes| spellings(bytes)).collect()
}

/// KR-REQ-10.06, KR-REQ-10.36: everything the page is sent, through the commands it calls and the
/// two events the application publishes, while this computer pairs by a typed code and by a direct
/// invitation read from the pasteboard, and while it confirms one request as an owner and declines
/// another, carries none of these: the invitations' text or secret, the code's secret characters,
/// a challenge's identifier, nonce or digest, the owner's proof, the transcript and bundle digests
/// the owner approves, or any key of this computer, the owner or the host. The same scan finds a
/// secret planted in one event, so it is shown to work on what the events carry. A confirming
/// ceremony completes exactly the challenge the host listed; a declining one completes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_is_sent_no_secret_while_this_computer_pairs_and_confirms() {
    use serde_json::json;

    let owner_keys = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let room = || -> Arc<dyn CandidateRoom> { Arc::new(host.room.clone()) };
    let mut secrets = Vec::new();

    // By a code, as the page types it.
    let code_data = tempfile::tempdir().expect("a directory");
    let code_secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let by_code = Companion::start(
        code_data.path(),
        support::parts(Arc::clone(&code_secrets), room()),
        StubCeremony::answering(CeremonyOutcome::Confirmed),
        Arc::new(StubPaste::default()),
    );
    let invited = invite_code(environment, &mut client, &owner).await;
    let InviteEntry::Code { code, qr_text, .. } = &invited.entry else {
        panic!("a code invitation");
    };
    let code = code.as_str().to_owned();
    assert_eq!(
        by_code.call("pairing_start_code", json!({ "code": code })),
        Ok(serde_json::Value::Null)
    );
    by_code
        .reached(|state| state["state"] == "awaiting_approval")
        .await;
    secrets.extend(approved(&mut client, invited.invitation_id).await);
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the owner approves");
    by_code.reached(|state| state["state"] == "paired").await;
    by_code
        .call("pairing_stop", json!({}))
        .expect("back at the start");

    // By a direct invitation read from the pasteboard, on a second computer: one computer pairs
    // with one host once.
    let direct = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let InviteEntry::Direct {
        qr_text: direct_text,
    } = &direct.entry
    else {
        panic!("a direct invitation");
    };
    let direct_data = tempfile::tempdir().expect("a directory");
    let direct_secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let pasteboard = StubPaste::holding(direct_text.as_str(), false);
    let by_paste = Companion::start(
        direct_data.path(),
        support::parts(Arc::clone(&direct_secrets), room()),
        StubCeremony::answering(CeremonyOutcome::Confirmed),
        pasteboard.clone(),
    );
    let pasted = by_paste
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    assert_eq!(pasted["invitation"]["mode"], "direct");
    assert_eq!(pasted["cleared"], true);
    assert_eq!(pasteboard.held(), None, "the pasteboard was cleared");
    by_paste
        .call("pairing_start_read", json!({}))
        .expect("started");
    by_paste
        .reached(|state| state["state"] == "awaiting_approval")
        .await;
    secrets.extend(approved(&mut client, direct.invitation_id).await);
    calls::confirm_candidate(environment, &mut client, direct.invitation_id, &owner)
        .await
        .expect("the owner approves");
    by_paste.reached(|state| state["state"] == "paired").await;

    // As the owner: one request confirmed, and then one declined.
    let owner_data = tempfile::tempdir().expect("a directory");
    let owner_secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    kr_crypto::store::store_device_keys(&*owner_secrets, "device", &owner_keys)
        .expect("the owner's keys are kept");
    let ceremony = StubCeremony::answering(CeremonyOutcome::Confirmed);
    let as_owner = Companion::start(
        owner_data.path(),
        support::parts(Arc::clone(&owner_secrets), room()),
        ceremony.clone(),
        Arc::new(StubPaste::default()),
    );
    support::record_owned(&as_owner.device(), &host, "the test host");
    let challenge = calls::request(environment, &mut client, an_invitation())
        .await
        .expect("the local owner asks")
        .request;
    let request = as_owner
        .listed(|request| request["checkable"] == true)
        .await;
    assert_eq!(
        as_owner.call(
            "owner_confirmation_review",
            json!({ "request": { "reference": request["reference"] } })
        ),
        Ok(json!("confirmed"))
    );
    assert_eq!(ceremony.asked.load(Ordering::SeqCst), 1);
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(challenge.confirmation_id)
        .expect("readable")
        .expect("the host recorded exactly the challenge it listed as answered");
    assert_eq!(acceptance.channel, "owner_device_presence");

    ceremony.will_answer(CeremonyOutcome::NotConfirmed);
    let declined = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: proposal(&[ActionRight::SessionView, ActionRight::FilesRead]),
        },
    )
    .await
    .expect("the local owner asks")
    .request;
    let request = as_owner
        .listed(|request| {
            request["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("read files"))
        })
        .await;
    assert_eq!(
        as_owner.call(
            "owner_confirmation_review",
            json!({ "request": { "reference": request["reference"] } })
        ),
        Ok(json!("not_confirmed"))
    );
    assert_eq!(ceremony.asked.load(Ordering::SeqCst), 2);
    assert!(
        host.network()
            .pairing()
            .rows()
            .acceptance(declined.confirmation_id)
            .expect("readable")
            .is_none(),
        "nothing was completed"
    );

    // Everything the page was sent, scanned for every secret it must not carry.
    let payload = calls::direct_payload(&direct);
    let QrPayload::Code(code_payload) =
        QrPayload::from_text(qr_text.as_str()).expect("the code's payload")
    else {
        panic!("a code payload");
    };
    let code_secret: String = code_payload
        .code
        .to_secret_text()
        .chars()
        .filter(|character| *character != '-')
        .skip(4)
        .collect();
    secrets.extend([
        qr_text.as_str().to_owned(),
        direct_text.as_str().to_owned(),
        code.clone(),
        code_secret,
        challenge.confirmation_id.to_string(),
        declined.confirmation_id.to_string(),
    ]);
    let host_keys = host.network().pairing().identity().keys;
    for bytes in [
        payload.secret.expose().to_vec(),
        challenge.nonce.as_bytes().to_vec(),
        challenge.action_digest.as_bytes().to_vec(),
        declined.nonce.as_bytes().to_vec(),
        declined.action_digest.as_bytes().to_vec(),
        acceptance.proof.signature.as_bytes().to_vec(),
        host_keys.transport.as_bytes().to_vec(),
        host_keys.authorisation.as_bytes().to_vec(),
    ] {
        secrets.extend(spellings(&bytes));
    }
    for store in [&owner_secrets, &code_secrets, &direct_secrets] {
        secrets.extend(key_bytes(&**store));
    }
    let companions = [&by_code, &by_paste, &as_owner];
    for companion in companions {
        assert!(
            companion
                .heard
                .texts()
                .iter()
                .any(|text| text.contains("\"state\"") || text.contains("\"ceremony\"")),
            "the events were heard"
        );
    }
    assert!(
        as_owner
            .heard
            .texts()
            .iter()
            .any(|text| text.contains("\"ceremony\"")),
        "the confirmations event was heard"
    );
    let sent: Vec<String> = companions
        .iter()
        .flat_map(|companion| companion.sent())
        .collect();
    assert!(sent.len() > 20, "the capture saw the flow: {}", sent.len());
    assert_eq!(carrying(&sent, &secrets), Vec::<String>::new());

    // A secret planted in an event is found by the same scan.
    let planted = secrets[secrets.len() / 2].clone();
    tauri::Emitter::emit(
        &by_code.app,
        companion_tauri::pairing::PAIRING_EVENT,
        json!({ "planted": planted }),
    )
    .expect("emitted");
    let found = tokio::time::timeout(WATCHDOG, async {
        loop {
            let found = carrying(&by_code.heard.texts(), &secrets);
            if !found.is_empty() {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the planted event is heard");
    assert_eq!(found.len(), 1, "the scan finds the one planted secret");
    assert!(found[0].contains(&planted));
}

/// A host's endpoint on the loopback network whose configuration names `relay` and resolves
/// through `resolver`. Nothing answers at either, so a device reaches the host at its direct
/// address; what the two services decide is which of this device's endpoints may be open at once.
fn on_relay(relay: &str, resolver: &str) -> kr_transport::config::EndpointConfig {
    kr_transport::config::EndpointConfig {
        bind_addr: Some(support::loopback()),
        relay_urls: vec![relay.parse().expect("a relay URL")],
        discovery: kr_transport::config::DiscoveryConfig {
            pkarr_resolver_url: Some(resolver.parse().expect("a resolver URL")),
            ..kr_transport::config::DiscoveryConfig::default()
        },
        ..kr_transport::config::EndpointConfig::default()
    }
}

/// KR-REQ-10.27, KR-REQ-10.06: this computer watches a host it owns while it pairs with another
/// host whose configuration shares the first one's relay and selects another resolver. One key
/// holds one endpoint on a relay, so reaching the owned host would close the endpoint the attempt
/// uses. The attempt waits for its owner through several of the watcher's cycles and never loses
/// its connection, the owned host is out of contact meanwhile, and once the attempt has ended the
/// watcher reaches the owned host again and lists what it asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watcher_never_cuts_off_an_attempt_that_shares_its_relay() {
    const RELAY: &str = "https://relay.pairing.test";
    let owner_keys = DeviceKeys::generate().expect("keys");
    let owned =
        Host::start_with_endpoint(&owner_keys, on_relay(RELAY, "http://127.0.0.1:9/pkarr")).await;
    let other_owner = DeviceKeys::generate().expect("keys");
    let joining =
        Host::start_with_endpoint(&other_owner, on_relay(RELAY, "http://127.0.0.1:10/pkarr")).await;
    let capture = Arc::new(Capture::default());
    let data = tempfile::tempdir().expect("a directory");
    let device = support::owner_device_with(&owned, &owner_keys, data.path(), &capture);
    let watcher = Owner::new(
        Arc::clone(&device),
        StubCeremony::answering(CeremonyOutcome::Confirmed),
        || {},
    );
    watcher.start();
    support::owned_host_shown(&device, true).await;

    let mut client = joining.client().await;
    let joining_owner = Signer::OwnerDevice(&other_owner);
    let direct = calls::invite_direct(
        joining.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &joining_owner,
    )
    .await
    .expect("a direct invitation");
    let InviteEntry::Direct { qr_text } = &direct.entry else {
        panic!("a direct invitation");
    };
    let invitation = device.read(qr_text.as_str()).expect("an invitation");
    let _ = device.hold(invitation);
    device.start_held().expect("started");
    let state = reached(&device, awaiting).await;
    assert!(awaiting(&state), "{state:?}");

    // The owner takes long enough for the watcher to cycle several times, and for the attempt to
    // ask again once the host's window has made room for its question.
    tokio::time::sleep(Duration::from_secs(15)).await;
    let lost: Vec<String> = capture
        .texts()
        .into_iter()
        .filter(|text| {
            text.contains(r#""state":"reconnecting""#) || text.contains(r#""state":"ended""#)
        })
        .collect();
    assert_eq!(
        lost,
        Vec::<String>::new(),
        "the attempt kept its connection"
    );
    assert_eq!(
        support::owned_host_in_contact(&device),
        Some(false),
        "the owned host waits while the attempt holds the relay"
    );

    calls::confirm_candidate(
        joining.environment_id,
        &mut client,
        direct.invitation_id,
        &joining_owner,
    )
    .await
    .expect("the owner approves");
    let state = reached(&device, paired).await;
    assert!(paired(&state), "{state:?}");

    // The attempt has ended, and the owned host is reached again.
    let mut owned_client = owned.client().await;
    calls::request(
        owned.environment_id,
        &mut owned_client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: viewer(),
        },
    )
    .await
    .expect("the owned host asks its owner");
    support::listed(&watcher, |request| request.checkable).await;
    support::owned_host_shown(&device, true).await;
}

/// KR-REQ-10.06, KR-REQ-10.27: this computer owns two hosts whose configurations share a relay and
/// select different resolvers, so reaching either closes the endpoint the other was reached
/// through. The watcher visits both in turn and lists what each asks. While the person takes their
/// time over the first host's request, spanning several of the watcher's cycles, the watcher does
/// not reach the second host, whose connection would close the endpoint the review answers
/// through: the review confirms, the first host records the answer, and once the review has ended
/// the second host is reached again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watcher_never_cuts_off_a_review_that_shares_its_relay() {
    const RELAY: &str = "https://relay.pairing.test";
    let owner_keys = DeviceKeys::generate().expect("keys");
    let first =
        Host::start_with_endpoint(&owner_keys, on_relay(RELAY, "http://127.0.0.1:9/pkarr")).await;
    let second =
        Host::start_with_endpoint(&owner_keys, on_relay(RELAY, "http://127.0.0.1:10/pkarr")).await;
    let data = tempfile::tempdir().expect("a directory");
    let device = owner_device(&first, &owner_keys, data.path());
    support::record_owned(&device, &second, "the second host");
    let watcher = Owner::new(
        Arc::clone(&device),
        Arc::new(SlowCeremony {
            takes: companion_tauri::owner::INTERVAL * 4,
        }),
        || {},
    );
    watcher.start();

    let mut first_client = first.client().await;
    let asked = calls::request(first.environment_id, &mut first_client, an_invitation())
        .await
        .expect("the first host asks");
    let mut second_client = second.client().await;
    calls::request(second.environment_id, &mut second_client, an_invitation())
        .await
        .expect("the second host asks");
    let request = support::listed(&watcher, |request| request.host_name == "the test host").await;
    support::listed(&watcher, |request| request.host_name == "the second host").await;

    let outcome = tokio::time::timeout(WATCHDOG, watcher.review(&request.reference))
        .await
        .expect("the review ends")
        .expect("reviewed");
    assert_eq!(outcome, ReviewOutcome::Confirmed);
    assert!(
        first
            .network()
            .pairing()
            .rows()
            .acceptance(asked.request.confirmation_id)
            .expect("readable")
            .is_some(),
        "the first host recorded the answer"
    );
    support::listed(&watcher, |request| request.host_name == "the second host").await;
}

/// KR-REQ-10.06: one of this computer's hosts takes each connection, completes the authorised
/// handshake and then answers nothing, holding the connection open. It holds up nothing else:
/// each visit to it ends within its bound, the other host's request is listed soon after that host
/// asks, a review of it confirms while the watcher waits on the silent host, and the silent host is
/// shown out of contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_host_holds_up_no_other_hosts_confirmations() {
    let owner_keys = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner_keys).await;
    let data = tempfile::tempdir().expect("a directory");
    let device = owner_device(&host, &owner_keys, data.path());
    let silent = support::SilentHost::start(&owner_keys, "a silent host").await;
    device
        .pairing()
        .hosts
        .record(silent.record.clone())
        .expect("the silent host is recorded");
    let watcher = Owner::new(
        Arc::clone(&device),
        StubCeremony::answering(CeremonyOutcome::Confirmed),
        || {},
    );
    watcher.start();
    // The watcher is waiting on the silent host's answer.
    silent.accepted(1).await;

    let mut client = host.client().await;
    let asked = calls::request(host.environment_id, &mut client, an_invitation())
        .await
        .expect("the host asks");
    let started = std::time::Instant::now();
    let request = support::listed(&watcher, |request| request.host_name == "the test host").await;
    let bound = companion_tauri::owner::VISIT_WITHIN * 2 + companion_tauri::owner::INTERVAL * 2;
    assert!(
        started.elapsed() < bound,
        "listed in {:?}, past {bound:?}",
        started.elapsed()
    );
    let outcome = tokio::time::timeout(
        companion_tauri::owner::VISIT_WITHIN * 2,
        watcher.review(&request.reference),
    )
    .await
    .expect("the review does not wait on the silent host")
    .expect("reviewed");
    assert_eq!(outcome, ReviewOutcome::Confirmed);
    assert!(
        host.network()
            .pairing()
            .rows()
            .acceptance(asked.request.confirmation_id)
            .expect("readable")
            .is_some(),
        "the host recorded the answer"
    );
    assert_eq!(
        support::in_contact_with(&device, "a silent host"),
        Some(false)
    );
    silent.stop().await;
}

/// A room that counts the sockets it is asked to open, and ends each before any host speaks.
#[derive(Default)]
struct CountingRoom {
    opened: Mutex<Vec<(RendezvousOrigin, String)>>,
}

impl CandidateRoom for CountingRoom {
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
        self.opened
            .lock()
            .expect("the record")
            .push((origin.clone(), locator.as_str().to_owned()));
        Box::pin(async move {
            Err(RoomError::Unreachable {
                origin: origin.as_str().to_owned(),
                reason: "a test room that serves nothing".to_owned(),
            })
        })
    }
}

impl CountingRoom {
    fn opened(&self) -> usize {
        self.opened.lock().expect("the record").len()
    }
}

/// KR-REQ-10.38: a code's invitation that names another pairing service than the one this computer
/// uses is not used until the person accepts that service in the platform's own alert, which names
/// both. Declined, nothing is held and no room is opened, not even when the page then asks to
/// start; accepted, the attempt goes to the named service for this attempt only, the setting stays
/// as it was, and the attempt's ending names the service it went to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_for_another_service_contacts_nothing_until_the_person_accepts_it() {
    use serde_json::json;

    let text = QrPayload::Code(CodeQrPayload {
        rendezvous_origin: RendezvousOrigin::new("https://pair.example.org").expect("an origin"),
        code: ShortCode::new("aB3x-Yz7-9Qw").expect("a code"),
    })
    .to_text()
    .expect("the invitation's text");
    let room = Arc::new(CountingRoom::default());
    let data = tempfile::tempdir().expect("a directory");
    let pasteboard = StubPaste::holding(&text, false);
    let companion = Companion::start(
        data.path(),
        support::parts(Arc::new(MemoryStore::new()), room.clone()),
        StubCeremony::answering(CeremonyOutcome::Confirmed),
        pasteboard.clone(),
    );

    let pasted = companion
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    assert_eq!(pasted["declined"], true);
    assert_eq!(pasted["invitation"], serde_json::Value::Null);
    assert_eq!(
        *pasteboard.asked.lock().expect("the record"),
        vec![(
            "https://pair.example.org".to_owned(),
            "https://reach.kala.to".to_owned()
        )],
        "the alert named both services"
    );
    assert!(
        companion.call("pairing_start_read", json!({})).is_err(),
        "nothing is waiting to be used"
    );
    assert_eq!(room.opened(), 0, "no room was opened");

    pasteboard.copy(&text, true);
    let pasted = companion
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    assert_eq!(pasted["invitation"]["origin_host"], "pair.example.org");
    companion
        .call("pairing_start_read", json!({}))
        .expect("started");
    let view = companion.reached(|state| state["state"] == "ended").await;
    assert_eq!(view["state"]["service"], "pair.example.org");
    assert_eq!(
        view["origin"]["host"], "reach.kala.to",
        "the service this computer uses is unchanged"
    );
    let opened: Vec<String> = room
        .opened
        .lock()
        .expect("the record")
        .iter()
        .map(|(origin, _)| origin.as_str().to_owned())
        .collect();
    assert_eq!(opened, vec!["https://pair.example.org".to_owned()]);
}

/// KR-REQ-10.32: this computer counts its tries with a code in its own data directory, under its
/// own secret store. Five charged attempts leave the sixth refused without a room being opened,
/// and a second instance over the same directory and store refuses it too. The same code through
/// another service is another budget, and opens a room. A code read from its invitation's text
/// shares the budget of the same code typed, and after a restart into another boot a code tried
/// once is spent rather than given a fresh window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn this_computer_counts_its_tries_in_its_own_budget() {
    const CODE: &str = "aB3x-Yz7-9Qw";
    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let room = Arc::new(CountingRoom::default());
    let first = device(
        data.path(),
        Arc::clone(&secrets),
        room.clone(),
        &Arc::new(Capture::default()),
    );
    for attempt in 1..=5 {
        first.start_code(CODE).expect("started");
        let ended = reached(&first, |_| false).await;
        let AttemptState::Ended { failure, .. } = ended else {
            panic!("the attempt ends");
        };
        assert_eq!(failure.kind, FailureKind::ServiceUnreachable, "{attempt}");
        assert_eq!(failure.tries_left, Some(5 - attempt), "{attempt}");
        first.stop().await;
    }
    assert_eq!(room.opened(), 5);

    let refuses = |device: &Arc<Device>| {
        let device = Arc::clone(device);
        async move {
            device.start_code(CODE).expect("started");
            let AttemptState::Ended { failure, .. } = reached(&device, |_| false).await else {
                panic!("the attempt ends");
            };
            device.stop().await;
            failure.kind
        }
    };
    assert_eq!(refuses(&first).await, FailureKind::DeviceTriesUsed);
    assert_eq!(room.opened(), 5, "the sixth opened no room");

    let second = device(
        data.path(),
        Arc::clone(&secrets),
        room.clone(),
        &Arc::new(Capture::default()),
    );
    assert_eq!(refuses(&second).await, FailureKind::DeviceTriesUsed);
    assert_eq!(
        room.opened(),
        5,
        "nor on a second instance over the same records"
    );

    second
        .set_origin("https://pair.example.org")
        .expect("another service");
    second.start_code(CODE).expect("started");
    let AttemptState::Ended { failure, .. } = reached(&second, |_| false).await else {
        panic!("the attempt ends");
    };
    assert_eq!(failure.kind, FailureKind::ServiceUnreachable);
    assert_eq!(
        room.opened(),
        6,
        "the same code at another service is another budget"
    );
    let origins: BTreeSet<String> = room
        .opened
        .lock()
        .expect("the record")
        .iter()
        .map(|(origin, _)| origin.as_str().to_owned())
        .collect();
    assert_eq!(origins.len(), 2);
    second.stop().await;

    // Another code, typed once and then read from its invitation's text: one budget.
    const ANOTHER: &str = "Zx9k-Ab3-Cd4";
    let third = device(
        data.path(),
        Arc::clone(&secrets),
        room.clone(),
        &Arc::new(Capture::default()),
    );
    third
        .set_origin("https://reach.kala.to")
        .expect("the default service again");
    third.start_code(ANOTHER).expect("started");
    let AttemptState::Ended { failure, .. } = reached(&third, |_| false).await else {
        panic!("the attempt ends");
    };
    assert_eq!(failure.tries_left, Some(4));
    third.stop().await;
    let text = QrPayload::Code(CodeQrPayload {
        rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
        code: ShortCode::new(ANOTHER).expect("a code"),
    })
    .to_text()
    .expect("the invitation's text");
    let invitation = third.read(&text).expect("an invitation");
    let summary = third.hold(invitation);
    assert_eq!(summary.origin_host.as_deref(), Some("reach.kala.to"));
    third.start_held().expect("started");
    let AttemptState::Ended { failure, .. } = reached(&third, |_| false).await else {
        panic!("the attempt ends");
    };
    assert_eq!(
        failure.tries_left,
        Some(3),
        "the text's attempt was charged to the typed code's budget"
    );
    third.stop().await;
    assert_eq!(room.opened(), 8);

    // After a restart into another boot, the code tried in the last one is spent.
    let another_boot = kr_protocol::identity::BootIdentity {
        value: kr_protocol::scalars::Bytes::new(vec![0xab; 16]),
        ..kr_ipc::identity::boot_identity().expect("this boot")
    };
    let rebooted = support::device_in_boot(
        data.path(),
        Arc::clone(&secrets),
        room.clone(),
        &Arc::new(Capture::default()),
        DeviceClock::of(&another_boot),
    );
    assert_eq!(refuses(&rebooted).await, FailureKind::DeviceTriesUsed);
    rebooted.start_code(ANOTHER).expect("started");
    let AttemptState::Ended { failure, .. } = reached(&rebooted, |_| false).await else {
        panic!("the attempt ends");
    };
    assert_eq!(
        failure.kind,
        FailureKind::DeviceTriesUsed,
        "a tombstone, not a fresh window"
    );
    assert_eq!(room.opened(), 8, "and no room was opened for either");
}
