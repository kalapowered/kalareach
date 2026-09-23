//! Short-code pairing, served: an invitation offered through a rendezvous room, candidates that
//! prove the code through the room, and the device finishing over iroh.
//!
//! The room is an in-process one with the service's contract. The candidate is kr-pairing's own
//! client state machine, so what reaches the host through the room is exactly what a device sends.

#![cfg(unix)]

mod net_support;

use kr_controller::service::net::rendezvous::{self, ClientFrame, CloseReason, decode_message};
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
    let (answer, ()) = tokio::join!(last.confirm(), async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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
    tokio::time::sleep(rendezvous::EXPIRY_RECHECK * 2).await;
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
