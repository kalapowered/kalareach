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
use std::sync::{Arc, Mutex, OnceLock};
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
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams, PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    CodeQrPayload, Locator, ProposedGrant, QrPayload, RendezvousOrigin, ShortCode,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, to_base64url};
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use support::{Capture, WATCHDOG, device, owner_device, reached};

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

/// A ceremony that answers the same way every time, and counts what it was asked.
struct StubCeremony {
    answer: CeremonyOutcome,
    asked: AtomicUsize,
}

impl Ceremony for StubCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, _reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { self.answer })
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

/// KR-REQ-10.06, KR-REQ-10.36: everything the page is sent while this computer pairs by code and
/// by a pasted direct invitation, and while it answers a confirmation as an owner, carries none of
/// the invitation's text or secret, the code's secret characters, the challenge's nonce or
/// identifier, a digest the confirmation covers, or any key. The scan is shown to work on a text
/// with one secret planted in it. A confirming ceremony completes exactly the challenge the host
/// listed; a declining one completes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_is_sent_no_secret_while_this_computer_pairs_and_confirms() {
    let owner_keys = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let capture = Arc::new(Capture::default());
    let data = tempfile::tempdir().expect("a directory");
    let candidate_secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let candidate = device(
        data.path(),
        Arc::clone(&candidate_secrets),
        Arc::new(host.room.clone()),
        &capture,
    );

    // By code, as the page types it.
    let invited = invite_code(environment, &mut client, &owner).await;
    let InviteEntry::Code { code, qr_text, .. } = &invited.entry else {
        panic!("a code invitation");
    };
    let code = code.as_str().to_owned();
    capture.keep(&candidate.start_code(&code).map_err(|error| error.message));
    let state = reached(&candidate, awaiting).await;
    assert!(awaiting(&state), "{state:?}");
    capture.keep(&candidate.view());
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the owner approves");
    assert!(paired(&reached(&candidate, paired).await), "paired by code");
    capture.keep(&candidate.view());
    candidate.stop().await;

    // By a direct invitation, read as the pasteboard's text is, on a second computer: one
    // computer pairs with one host once.
    let second_data = tempfile::tempdir().expect("a directory");
    let candidate = device(
        second_data.path(),
        Arc::new(MemoryStore::new()),
        Arc::new(host.room.clone()),
        &capture,
    );
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
    let invitation = candidate.read(direct_text.as_str()).expect("an invitation");
    capture.keep(&candidate.hold(invitation));
    capture.keep(&candidate.start_held().map_err(|error| error.message));
    let state = reached(&candidate, awaiting).await;
    assert!(awaiting(&state), "{state:?}");
    calls::confirm_candidate(environment, &mut client, direct.invitation_id, &owner)
        .await
        .expect("the owner approves");
    assert!(
        paired(&reached(&candidate, paired).await),
        "paired directly"
    );
    capture.keep(&candidate.view());

    // As the owner, answering one confirmation and declining another.
    let owner_data = tempfile::tempdir().expect("a directory");
    let as_owner = owner_device(&host, &owner_keys, owner_data.path());
    let confirming = Arc::new(StubCeremony {
        answer: CeremonyOutcome::Confirmed,
        asked: AtomicUsize::new(0),
    });
    let held: Arc<OnceLock<Arc<Owner>>> = Arc::new(OnceLock::new());
    let (seen, kept) = (Arc::clone(&capture), Arc::clone(&held));
    let watcher = Owner::new(Arc::clone(&as_owner), confirming.clone(), move || {
        if let Some(owner) = kept.get() {
            seen.keep(&owner.view());
        }
    });
    let _ = held.set(Arc::clone(&watcher));
    watcher.start();
    let challenge = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: viewer(),
        },
    )
    .await
    .expect("the local owner asks");
    let listed = tokio::time::timeout(WATCHDOG, async {
        loop {
            let view = watcher.view();
            if let Some(request) = view.requests.first() {
                return request.reference.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the owner device lists the request");
    capture.keep(&watcher.view());
    let outcome = watcher.review(&listed).await.expect("reviewed");
    capture.keep(&outcome);
    assert_eq!(outcome, ReviewOutcome::Confirmed);
    assert_eq!(confirming.asked.load(Ordering::SeqCst), 1);
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(challenge.request.confirmation_id)
        .expect("readable")
        .expect("the host recorded exactly the challenge it listed as answered");
    assert_eq!(acceptance.channel, "owner_device_presence");

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
    let mut secrets = vec![
        qr_text.as_str().to_owned(),
        direct_text.as_str().to_owned(),
        code.clone(),
        code_secret,
        challenge.request.confirmation_id.to_string(),
    ];
    for bytes in [
        payload.secret.expose().to_vec(),
        challenge.request.nonce.as_bytes().to_vec(),
        challenge.request.action_digest.as_bytes().to_vec(),
        owner_keys.authorisation.public().as_bytes().to_vec(),
        owner_keys.transport.public().as_bytes().to_vec(),
    ] {
        secrets.extend(spellings(&bytes));
    }
    let texts = capture.texts();
    assert!(texts.len() > 5, "the capture saw the flow: {}", texts.len());
    assert_eq!(carrying(&texts, &secrets), Vec::<String>::new());
    let planted = format!("{}{}", texts[0], secrets[4]);
    assert_eq!(
        carrying(std::slice::from_ref(&planted), &secrets),
        vec![planted],
        "the scan finds a secret planted in one text"
    );

    // A declining ceremony: nothing is completed, and the host still lists the challenge.
    let declining = Arc::new(StubCeremony {
        answer: CeremonyOutcome::NotConfirmed,
        asked: AtomicUsize::new(0),
    });
    let refusing = Owner::new(Arc::clone(&as_owner), declining.clone(), || {});
    refusing.start();
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
    .expect("the local owner asks");
    let reference = tokio::time::timeout(WATCHDOG, async {
        loop {
            if let Some(request) = refusing.view().requests.into_iter().find(|request| {
                request
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("read files"))
            }) {
                return request.reference;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("listed");
    assert_eq!(
        refusing.review(&reference).await.expect("reviewed"),
        ReviewOutcome::NotConfirmed
    );
    assert_eq!(declining.asked.load(Ordering::SeqCst), 1);
    assert!(
        host.network()
            .pairing()
            .rows()
            .acceptance(declined.request.confirmation_id)
            .expect("readable")
            .is_none(),
        "nothing was completed"
    );
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
        let AttemptState::Ended { failure } = ended else {
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
            let AttemptState::Ended { failure } = reached(&device, |_| false).await else {
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
    let AttemptState::Ended { failure } = reached(&second, |_| false).await else {
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
    let AttemptState::Ended { failure } = reached(&third, |_| false).await else {
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
    let AttemptState::Ended { failure } = reached(&third, |_| false).await else {
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
    let AttemptState::Ended { failure } = reached(&rebooted, |_| false).await else {
        panic!("the attempt ends");
    };
    assert_eq!(
        failure.kind,
        FailureKind::DeviceTriesUsed,
        "a tombstone, not a fresh window"
    );
    assert_eq!(room.opened(), 8, "and no room was opened for either");
}
