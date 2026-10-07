//! Short-code pairing, served: an invitation offered through a rendezvous room, candidates that
//! prove the code through the room, and the device finishing over iroh.
//!
//! The room is an in-process one with the service's contract. The candidate is kr-pairing's own
//! client state machine, so what reaches the host through the room is exactly what a device sends.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;

use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{AttemptId, EnvironmentId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams, PairInviteResult,
    PairingApproval, RendezvousMessage, default_rendezvous_origin,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    PairStatus, PairingConsumedReason, ProposedGrant, QrPayload, RendezvousOrigin,
};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::rendezvous::{ClientFrame, CloseReason, decode_message};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nonce256, Nullable};
use net_support::pairing::{self as calls, Signer};
use net_support::room::{CodeCandidate, Stopped};
use net_support::{Device, Host, proposal};

fn keys() -> DeviceKeys {
    DeviceKeys::generate().expect("keys")
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

/// Waits until the room relay of the invitation this host offered since `idle` was read has
/// ended.
///
/// A relay holds the pairing service weakly for as long as it runs, and it asks the room for the
/// release, when the release is its own, before it ends. So once it has ended, what it asked the
/// room for is all it will ask. A wait that never ends fails the test, and measures nothing.
async fn until_relay_ended(host: &Host, idle: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        while Arc::weak_count(host.network().pairing()) > idle {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the invitation's relay ends");
}

/// Issues a code invitation at this host's default origin, once `signer` has confirmed it.
async fn invite_code(
    environment: EnvironmentId,
    client: &mut LocalClient,
    grant_kind: InviteGrantKind,
    grant: &ProposedGrant,
    signer: &Signer<'_>,
) -> PairInviteResult {
    calls::confirm_subject(
        environment,
        client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Code,
            rendezvous_origin: Nullable::null(),
            grant_kind,
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
            grant_kind,
            proposed_grant: grant.clone(),
        },
    )
    .await
    .expect("a code invitation")
}

/// The origin and the code a code invitation's answer shows.
fn code_of(invited: &PairInviteResult) -> (RendezvousOrigin, String) {
    let InviteEntry::Code {
        rendezvous_origin,
        code,
        qr_text,
    } = &invited.entry
    else {
        panic!("a code invitation is offered as a code");
    };
    let QrPayload::Code(payload) = QrPayload::from_text(qr_text.as_str()).expect("a payload")
    else {
        panic!("a code invitation's QR is a code payload");
    };
    assert_eq!(&payload.rendezvous_origin, rendezvous_origin);
    assert_eq!(payload.code.as_str(), code.as_str());
    (rendezvous_origin.clone(), code.as_str().to_owned())
}

/// The same code with its last secret character changed: the right locator, the wrong secret.
fn wrong(code: &str) -> String {
    let replacement = if code.ends_with('z') { 'y' } else { 'z' };
    let mut wrong = code[..code.len() - 1].to_owned();
    wrong.push(replacement);
    wrong
}

/// KR-REQ-10.19, KR-REQ-23.26: a code invitation shows a ten-character code as `XXXX-XXX-XXX`
/// and the origin it was reserved at, the default included. A candidate proves the code through
/// the room, finishes over iroh from the endpoint its bundle declared, and the issuing owner is
/// shown that candidate and the value both devices display; the owner's confirmation commits it,
/// the event names the mode, and the locator is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_through_the_room_with_a_code() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await;
    let (origin, code) = code_of(&invited);
    assert_eq!(origin, default_rendezvous_origin());
    assert!(reads_as_a_code(&code), "a code reads XXXX-XXX-XXX");
    assert_eq!(host.room.reserved(), vec![code[..4].to_owned()]);

    let device = Device::create().await;
    let mut candidate = CodeCandidate::start(&host.room, device.candidate(), &origin, &code)
        .await
        .expect("admitted");
    candidate.confirm().await.expect("the host proved the code");
    candidate
        .send_bundle()
        .await
        .expect("the host took the bundle");
    let (connection, mut session, finished) = candidate.finish().await;
    assert_eq!(finished.attempt_id, candidate.attempt_id());
    assert_eq!(finished.verification_value, candidate.verification_value());

    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let view = status.owner.0.expect("an owner view");
    assert_eq!(view.mode, InviteModeKind::Code);
    assert_eq!(view.rendezvous_origin.0, Some(origin.clone()));
    assert_eq!(view.remaining_confirmations, 5);
    let shown = view.candidate.0.expect("the bound candidate");
    assert_eq!(shown.verification_value, candidate.verification_value());
    assert!(matches!(
        view.approval.0,
        Some(PairingApproval::Code { .. })
    ));

    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("committed");
    assert_eq!(confirmed.event.mode, InviteModeKind::Code);
    assert!(!confirmed.event.first_owner);
    assert_eq!(host.room.released(), vec![code[..4].to_owned()]);

    let answered: PairStatusResult = session
        .call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        )
        .await
        .expect("the candidate is answered");
    assert_eq!(
        answered.status,
        PairStatus::Committed {
            device_id: confirmed.device_id,
            grant_id: confirmed.grant_id,
        }
    );
    connection.close(0u32.into(), b"paired");
    host.stop().await;
}

/// KR-REQ-10.31: the first candidate whose confirmation tag verifies locks the invitation, and
/// the competing candidate's attempt is closed before it can confirm. Being closed spends none of
/// the invitation's five guesses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_candidate_to_prove_the_code_closes_the_others() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    let (origin, code) = code_of(&invited);

    let first = Device::create().await;
    let second = Device::create().await;
    let mut winner = CodeCandidate::start(&host.room, first.candidate(), &origin, &code)
        .await
        .expect("admitted");
    let mut loser = CodeCandidate::start(&host.room, second.candidate(), &origin, &code)
        .await
        .expect("admitted as well");
    winner.confirm().await.expect("the first to prove the code");
    assert_eq!(
        loser.confirm().await,
        Err(Stopped::Closed(CloseReason::Cancelled))
    );

    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert!(
        matches!(status.status, PairStatus::Locked { attempt_id, .. } if attempt_id == winner.attempt_id()),
        "{:?}",
        status.status
    );
    assert_eq!(
        status.owner.0.expect("a view").remaining_confirmations,
        5,
        "a closed competitor spent no guess"
    );
    host.stop().await;
}

/// KR-REQ-10.30: every wrong code proved through the room spends one of five guesses, counted in
/// the invitation's one serial path and on disk before the candidate is answered; the fifth
/// consumes the invitation, and the right code is refused afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_wrong_codes_through_the_room_consume_the_invitation() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    let (origin, code) = code_of(&invited);
    let guessing = Device::create().await;

    for remaining in (1..5).rev() {
        let mut candidate =
            CodeCandidate::start(&host.room, guessing.candidate(), &origin, &wrong(&code))
                .await
                .expect("admitted");
        assert_eq!(
            candidate.confirm().await,
            Err(Stopped::Refused {
                code: ErrorCode::PairingAuthFailed,
                remaining: Some(remaining),
            })
        );
        let row = host
            .network()
            .pairing()
            .rows()
            .row(invited.invitation_id)
            .expect("readable")
            .expect("the invitation's row");
        assert_eq!(
            row.record.failed_confirmations,
            5 - remaining,
            "on disk already"
        );
    }
    let mut fifth = CodeCandidate::start(&host.room, guessing.candidate(), &origin, &wrong(&code))
        .await
        .expect("admitted");
    assert_eq!(
        fifth.confirm().await,
        Err(Stopped::Refused {
            code: ErrorCode::PairingAttemptsExhausted,
            remaining: Some(0),
        })
    );

    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::AttemptsExhausted
        }
    );
    // The right code is refused from now on, and the code stops reaching the host: its locator is
    // released once the guesses are spent.
    let frames = host.network().pairing().room_step(
        invited.invitation_id,
        AttemptId::new(kr_ipc::new_uuid()),
        RendezvousMessage::Admit {
            client_nonce: Nonce256::from_bytes([1; 32]),
        },
    );
    let Some(ClientFrame::Relay { payload, .. }) = frames.first() else {
        panic!("a refusal is relayed first: {frames:?}");
    };
    assert!(matches!(
        decode_message(payload.as_slice()),
        Ok(RendezvousMessage::Refused {
            code: ErrorCode::PairingAttemptsExhausted,
            ..
        })
    ));
    let released = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while host.room.released().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "the locator is released");
    assert_eq!(host.room.released(), vec![code[..4].to_owned()]);
    // Its release was the relay's, so the next invitation, which ends this one, does not ask
    // for it again.
    let next = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    assert_ne!(next.invitation_id, invited.invitation_id);
    assert_eq!(host.room.release_requests(), vec![code[..4].to_owned()]);
    host.stop().await;
}

/// KR-REQ-10.30, KR-REQ-10.31: a payload that is not a pairing message ends its attempt on the
/// host before anything queued behind it is read. The right confirmation tag, sent straight after
/// it, neither locks the invitation nor spends a guess: the attempt is already gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_payload_ends_its_attempt_before_anything_behind_it() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    let (origin, code) = code_of(&invited);
    let device = Device::create().await;
    let mut candidate = CodeCandidate::start(&host.room, device.candidate(), &origin, &code)
        .await
        .expect("admitted");

    candidate.send_malformed().await;
    assert_eq!(
        candidate.confirm().await,
        Err(Stopped::Closed(CloseReason::Cancelled))
    );
    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert!(
        matches!(status.status, PairStatus::Open { .. }),
        "nothing locked it: {:?}",
        status.status
    );
    assert_eq!(
        status.owner.0.expect("a view").remaining_confirmations,
        5,
        "and nothing spent a guess"
    );
    host.stop().await;
}

/// KR-REQ-10.30, KR-REQ-10.19: the candidate whose guess spent the last one is told so before
/// the locator is released. The room holds the host's frames back for a while, as a slow service
/// can; the release waits for the room to confirm it closed that attempt, which it does only after
/// the answer before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_answer_reaches_its_candidate_before_the_locator_is_released() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    let (origin, code) = code_of(&invited);
    let guessing = Device::create().await;
    for _ in 0..4 {
        let mut candidate =
            CodeCandidate::start(&host.room, guessing.candidate(), &origin, &wrong(&code))
                .await
                .expect("admitted");
        assert!(matches!(
            candidate.confirm().await,
            Err(Stopped::Refused {
                code: ErrorCode::PairingAuthFailed,
                ..
            })
        ));
    }
    let mut last = CodeCandidate::start(&host.room, guessing.candidate(), &origin, &wrong(&code))
        .await
        .expect("admitted");

    host.room.hold_hosts(true);
    let room = host.room.clone();
    let locator = code[..4].to_owned();
    let (answer, ()) = tokio::join!(last.confirm(), async {
        // The host has sent its last answer and the close of the attempt, which the room holds
        // back, and waits on the room for what it sent: this is when a host that released the
        // locator without waiting would have done so.
        room.until_host_waits(&locator).await;
        assert!(
            room.released().is_empty(),
            "the release waits for the room to confirm the last attempt closed"
        );
        room.hold_hosts(false);
    });
    assert_eq!(
        answer,
        Err(Stopped::Refused {
            code: ErrorCode::PairingAttemptsExhausted,
            remaining: Some(0),
        })
    );
    let released = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while host.room.released().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "and then the locator is released");
    host.stop().await;
}

/// KR-REQ-10.04, KR-REQ-10.53: a host with no owner establishes its first owner over a code,
/// through the local bootstrap: the owner's first device proves the code, and the commit writes the
/// owner record and says so in its event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_pairs_over_a_code() {
    let host = Host::start_unowned().await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let ceremony = keys();
    let bootstrap = Signer::Bootstrap(&ceremony.authorisation);
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &kr_pairing::grants::personal_owner_grant(),
        &bootstrap,
    )
    .await;
    let (origin, code) = code_of(&invited);

    let device = Device::create().await;
    let mut candidate = CodeCandidate::start(&host.room, device.candidate(), &origin, &code)
        .await
        .expect("admitted");
    candidate.confirm().await.expect("the code proved");
    candidate.send_bundle().await.expect("the bundle taken");
    let (connection, _session, _finished) = candidate.finish().await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &bootstrap)
            .await
            .expect("the first owner committed");
    assert!(confirmed.event.first_owner);
    assert_eq!(confirmed.event.mode, InviteModeKind::Code);
    assert_eq!(
        host.network()
            .pairing()
            .rows()
            .host_owner()
            .expect("readable"),
        Some(
            kr_controller::service::net::invitations::HostOwner::FirstOwner {
                device_id: confirmed.device_id,
                invitation_id: invited.invitation_id,
            }
        )
    );
    connection.close(0u32.into(), b"paired");
    host.stop().await;
}

/// KR-REQ-10.19: a withdrawn code invitation releases its locator at once, ends the room's
/// candidates, and a candidate that was part-way through is told it was cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_code_invitation_releases_its_locator() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let idle = Arc::weak_count(host.network().pairing());
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await;
    let (origin, code) = code_of(&invited);
    let device = Device::create().await;
    let mut candidate = CodeCandidate::start(&host.room, device.candidate(), &origin, &code)
        .await
        .expect("admitted");

    let withdrawn = calls::cancel(environment, &mut client, invited.invitation_id, false)
        .await
        .expect("withdrawn");
    assert_eq!(
        withdrawn.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::Cancelled
        }
    );
    assert_eq!(host.room.released(), vec![code[..4].to_owned()]);
    assert!(host.room.reserved().is_empty());
    assert!(
        matches!(candidate.confirm().await, Err(Stopped::Closed(_))),
        "the room ended the candidate with the record"
    );
    // The withdrawal took the release, and the relay leaves it to the withdrawal.
    until_relay_ended(&host, idle).await;
    assert_eq!(host.room.release_requests(), vec![code[..4].to_owned()]);
    host.stop().await;
}

/// KR-REQ-10.19: a rendezvous service the host cannot reach is reported as unavailable, never as
/// an authentication or configuration failure, and no invitation is offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_rendezvous_service_is_reported_as_unavailable() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    host.room.set_unreachable(true);
    let grant = viewer();
    calls::confirm_subject(
        environment,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: InviteModeKind::Code,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
        &Signer::OwnerDevice(&owner_keys),
    )
    .await
    .expect("answered");
    let refused = calls::mutate::<_, PairInviteResult>(
        environment,
        &mut client,
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
    .expect_err("no locator could be reserved");
    assert_eq!(refused.code, ErrorCode::RendezvousUnavailable);
    assert!(host.room.reserved().is_empty());
    host.stop().await;
}

/// True when `code` is ten Base58 characters shown as `XXXX-XXX-XXX`.
fn reads_as_a_code(code: &str) -> bool {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let parts: Vec<&str> = code.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 3
        && parts[2].len() == 3
        && parts
            .iter()
            .all(|part| part.chars().all(|character| BASE58.contains(character)))
}

/// The variable that asks [`the_pairings_the_log_check_reads`] to run, naming the directory it
/// writes what it knows to.
const LOG_CHECK: &str = "KR_PAIRING_LOG_CHECK";

/// Every file under `directory`, in a stable order.
fn files_under(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// Every form a pairing secret travels in, as bytes a file could hold.
fn secret_forms(secrets: &serde_json::Value) -> Vec<Vec<u8>> {
    let text = |key: &str| secrets[key].as_str().expect("a written secret").to_owned();
    let direct: Vec<u8> =
        serde_json::from_value(secrets["direct_secret"].clone()).expect("the direct secret");
    let lower: String = direct.iter().map(|byte| format!("{byte:02x}")).collect();
    let url = kr_protocol::scalars::to_base64url(&direct);
    let standard = format!("{}=", url.replace('-', "+").replace('_', "/"));
    let code = text("code");
    // A QR text is the unpadded base64url of its payload, which carries the code or the secret
    // inside it; the standard alphabet is how a careless line would print the same bytes.
    let standard_of = |url: &str| url.replace('-', "+").replace('_', "/");
    let mut forms = vec![
        text("code_secret").into_bytes(),
        code.clone().into_bytes(),
        code.replace('-', "").into_bytes(),
        direct.clone(),
        lower.to_uppercase().into_bytes(),
        lower.into_bytes(),
        url.into_bytes(),
        standard.into_bytes(),
        text("code_qr_text").into_bytes(),
        standard_of(&text("code_qr_text")).into_bytes(),
        text("direct_qr_text").into_bytes(),
        standard_of(&text("direct_qr_text")).into_bytes(),
    ];
    forms.sort();
    forms.dedup();
    forms
}

fn carries(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Runs a real short-code pairing and a real direct pairing when [`LOG_CHECK`] names a directory,
/// and does nothing otherwise. [`pairing_secrets_reach_no_log_and_no_diagnostics`] runs this as a
/// process of its own, so everything the daemon writes to the standard streams is in the log that
/// process keeps. It writes the two secrets and the host's diagnostics to the directory, and checks
/// every file of the host's own tree itself before the tree goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pairings_the_log_check_reads() {
    let Some(out) = std::env::var_os(LOG_CHECK).map(std::path::PathBuf::from) else {
        return;
    };
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);

    // A short-code pairing through the room.
    let invited = invite_code(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await;
    let (origin, code) = code_of(&invited);
    let kr_protocol::invitation::InviteEntry::Code {
        qr_text: code_qr_text,
        ..
    } = &invited.entry
    else {
        panic!("a code invitation is offered as a code");
    };
    let by_code = Device::create().await;
    let mut candidate = CodeCandidate::start(&host.room, by_code.candidate(), &origin, &code)
        .await
        .expect("admitted");
    candidate.confirm().await.expect("the host proved the code");
    candidate
        .send_bundle()
        .await
        .expect("the host took the bundle");
    let (connection, _session, _finished) = candidate.finish().await;
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
        .await
        .expect("the code pairing commits");
    connection.close(0u32.into(), b"paired");

    // A direct pairing from the QR.
    let direct = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("a direct invitation");
    let by_qr = Device::create().await;
    let (connection, _candidate, _value) = calls::redeem(&by_qr.candidate(), &direct).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, direct.invitation_id, &owner)
            .await
            .expect("the direct pairing commits");
    connection.close(0u32.into(), b"paired");
    let kr_protocol::invitation::InviteEntry::Direct { qr_text } = &direct.entry else {
        panic!("a direct invitation is offered as a QR");
    };
    let secrets = serde_json::json!({
        "code": code,
        "code_secret": &code.replace('-', "")[4..],
        "code_qr_text": code_qr_text.as_str(),
        "direct_secret": calls::direct_payload(&direct).secret.expose().to_vec(),
        "direct_qr_text": qr_text.as_str(),
    });
    // The two invitations as the daemon answered the owner, which is where the code and both QR
    // texts belong: the check's control.
    let invitations = serde_json::json!([
        serde_json::to_value(&invited).expect("JSON"),
        serde_json::to_value(&direct).expect("JSON"),
    ]);

    // The diagnostics: the owner's report, a paired device's, and a support bundle composed from
    // the owner's.
    let owners: kr_protocol::hostinfo::HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a report");
    let record = host
        .network()
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("the registry reads")
        .expect("the device paired from the QR");
    let session = net_support::connect(&host, &by_qr, &record).await;
    let devices: kr_protocol::hostinfo::HostDoctorResult = session
        .read(Method::HostDoctor, &())
        .await
        .expect("host.doctor is served to the device");
    session.close();
    let bundle = kr_protocol::hostinfo::ComposedBundle::new(
        kr_protocol::scalars::TimestampMs::new(0),
        Vec::new(),
        Vec::new(),
        owners.clone(),
        Vec::new(),
    );
    std::fs::create_dir_all(&out).expect("the output directory");
    for (name, value) in [
        ("secrets.json", secrets.clone()),
        (
            "doctor-owner.json",
            serde_json::to_value(&owners).expect("JSON"),
        ),
        (
            "doctor-device.json",
            serde_json::to_value(&devices).expect("JSON"),
        ),
        ("bundle.json", serde_json::to_value(&bundle).expect("JSON")),
        ("invitations.json", invitations),
    ] {
        std::fs::write(out.join(name), value.to_string()).expect("written");
    }

    // Every file the host keeps in its own tree, its registry and its journals among them.
    let forms = secret_forms(&secrets);
    for file in files_under(host.tree().root()) {
        let bytes = std::fs::read(&file).unwrap_or_default();
        for form in &forms {
            assert!(
                !carries(&bytes, form),
                "a pairing secret is in {}",
                file.display()
            );
        }
    }
    host.stop().await;
}

/// KR-REQ-10.12 and KR-REQ-10.35: pairing secrets never reach the daemon's log or its
/// diagnostics. A real short-code pairing and a real direct pairing run in a process of their own,
/// whose standard output and error are its log. Afterwards neither the code's six secret
/// characters, the code as a whole, the direct invitation's secret in any encoding it travels in,
/// nor either invitation's QR text, which carries the code or the secret inside it, is in that
/// log, in the owner's or the paired device's `host.doctor`, in a support bundle composed from
/// the owner's, or in any file of the host's own tree. The control: the same scan finds the code
/// and both QR texts in the invitations the daemon answered the owner with, where they belong.
#[test]
fn pairing_secrets_reach_no_log_and_no_diagnostics() {
    let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
    let program = directory.path().join("pairing-code-tests");
    kr_ipc::testing::place_program(
        &std::env::current_exe().expect("this test's own binary"),
        &program,
    );
    let out = directory.path().join("out");
    let log = directory.path().join("daemon.log");
    let written = std::fs::File::create(&log).expect("the log");
    let status = std::process::Command::new(&program)
        .args([
            "--exact",
            "the_pairings_the_log_check_reads",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(LOG_CHECK, &out)
        .current_dir(directory.path())
        .stdin(std::process::Stdio::null())
        .stdout(written.try_clone().expect("the log again"))
        .stderr(written)
        .status()
        .expect("the pairings run");
    let logged = std::fs::read(&log).expect("the log reads");
    assert!(
        status.success(),
        "the pairings ran: {}",
        String::from_utf8_lossy(&logged)
    );
    let secrets: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("secrets.json")).expect("the pairings wrote their secrets"),
    )
    .expect("JSON");
    assert_eq!(
        secrets["code_secret"].as_str().map(str::len),
        Some(6),
        "{secrets}"
    );
    let forms = secret_forms(&secrets);
    let answered = std::fs::read(out.join("invitations.json")).expect("the invitations read");
    for key in ["code", "code_qr_text", "direct_qr_text"] {
        let form = secrets[key].as_str().expect("a written secret").as_bytes();
        assert!(
            carries(&answered, form),
            "the scan finds the {key} in the owner's own invitations"
        );
    }
    for name in [
        "daemon.log",
        "out/doctor-owner.json",
        "out/doctor-device.json",
        "out/bundle.json",
    ] {
        let bytes = std::fs::read(directory.path().join(name)).expect("the file reads");
        assert!(!bytes.is_empty(), "{name} holds what was written");
        for form in &forms {
            assert!(
                !carries(&bytes, form),
                "a pairing secret is in {name}: {}",
                String::from_utf8_lossy(form)
            );
        }
    }
}
