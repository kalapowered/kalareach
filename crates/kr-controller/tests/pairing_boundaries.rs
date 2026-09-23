//! The edges of the served pairing methods: what an approval covers, when the authority behind it
//! is checked, what a repeated mutation is owed, and what a candidate is told.

#![cfg(unix)]

mod net_support;

use kr_client::error::ClientError;
use kr_controller::error::ControllerError;
use kr_controller::service::net::owner::Caller;
use kr_controller::service::net::pairing::AUTHENTICATION_FAILED;
use kr_crypto::keys::DeviceKeys;
use kr_pairing::direct::redeem_proof;
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::invitation::{
    InviteGrantKind, InviteMode, InviteModeKind, PairInviteParams, PairInviteResult,
    default_rendezvous_origin,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{PairStatus, PairingConsumedReason, ProposedGrant};
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, SecretBytes32};
use kr_protocol::sharing::{DeviceRevokeParams, RevocationResult};
use kr_transport::handshake;
use net_support::pairing::{self as calls, HostPeer, Signer, direct_payload, host_addr};
use net_support::{Device, Host, connect, pair_with, proposal};

fn keys() -> DeviceKeys {
    DeviceKeys::generate().expect("keys")
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

fn issue(mode: InviteModeKind, grant: &ProposedGrant) -> ConfirmationSubject {
    ConfirmationSubject::IssueInvitation {
        mode,
        rendezvous_origin: Nullable::null(),
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: grant.clone(),
    }
}

fn direct(grant: &ProposedGrant) -> PairInviteParams {
    PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: grant.clone(),
    }
}

fn code<T: std::fmt::Debug>(outcome: Result<T, ProtocolError>) -> ErrorCode {
    match outcome {
        Ok(value) => panic!("refused, not {value:?}"),
        Err(error) => error.code,
    }
}

/// KR-REQ-10.05: an approval to issue an invitation names its mode and origin as well as its
/// grant. One given for a code invitation issues no direct invitation, and a direct invitation
/// names no origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_issues_exactly_the_mode_it_names() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let grant = viewer();

    calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Code, &grant),
        &owner,
    )
    .await
    .expect("answered for a code invitation");
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &direct(&grant)
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    // A direct invitation contacts no rendezvous service, so it names no origin.
    assert_eq!(
        code(
            calls::request(
                environment,
                &mut client,
                ConfirmationSubject::IssueInvitation {
                    mode: InviteModeKind::Direct,
                    rendezvous_origin: Nullable::some(default_rendezvous_origin()),
                    grant_kind: InviteGrantKind::SessionInvitation,
                    proposed_grant: grant.clone(),
                },
            )
            .await
        ),
        ErrorCode::InvalidArgument
    );
    // The approval for the direct invitation issues it.
    calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Direct, &grant),
        &owner,
    )
    .await
    .expect("answered for a direct invitation");
    let _: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &direct(&grant),
    )
    .await
    .expect("the direct invitation");
    host.stop().await;
}

/// KR-REQ-10.05, KR-REQ-10.06: the authority behind an answer is checked again when the answer is
/// spent. An owner device that answered and was then revoked authorises nothing; its answer stays
/// on record as answered and never consumed, and another owner device's answer still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_from_a_revoked_owner_device_authorises_nothing() {
    let first_keys = keys();
    let host = Host::start(&first_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let first = Signer::OwnerDevice(&first_keys);
    let first_record = host.owner.clone().expect("the first owner device");

    // A second owner device, paired under the first one's confirmations.
    let second_keys = keys();
    let second_device = Device::with_keys(second_keys.clone()).await;
    let owner_grant = kr_pairing::grants::personal_owner_grant();
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &owner_grant,
        &first,
    )
    .await
    .expect("an owner invitation");
    let (connection, _candidate, _value) =
        calls::redeem(&second_device.candidate(), &invited).await;
    calls::confirm_candidate(environment, &mut client, invited.invitation_id, &first)
        .await
        .expect("the second owner device");
    connection.close(0u32.into(), b"paired");

    // The first device answers, and is then revoked before its answer is spent.
    let grant = viewer();
    let answered = calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Direct, &grant),
        &first,
    )
    .await
    .expect("answered");
    let _: RevocationResult = calls::mutate(
        environment,
        &mut client,
        Method::DeviceRevoke,
        &DeviceRevokeParams {
            device_id: first_record.device_id,
        },
    )
    .await
    .expect("revoked");
    // A revocation withdraws every registration, the owner's own socket included, so the owner
    // reconnects before its next action.
    let mut client = host.client().await;
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &direct(&grant)
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(answered.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert!(acceptance.consumed_at_ms.is_none(), "never consumed");

    // The remaining owner device's answer works.
    calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Direct, &grant),
        &Signer::OwnerDevice(&second_keys),
    )
    .await
    .expect("answered by the remaining owner");
    let _: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &direct(&grant),
    )
    .await
    .expect("issued");
    host.stop().await;
}

/// KR-REQ-10.05: a mutation's admission is asked again immediately before its transition. One
/// whose registration or deadline lapsed while it waited for a thread and for the invitation's
/// lock spends nothing and issues nothing; the answer it would have spent is still there for the
/// next admitted attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_whose_admission_lapses_while_it_waits_changes_nothing() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let grant = viewer();
    calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Direct, &grant),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await
    .expect("answered");

    let pairing = host.network().pairing();
    let lapsed = || -> kr_controller::error::Result<()> {
        Err(ControllerError::WindowExpired {
            detail: "the deadline passed while this waited".to_owned(),
        })
    };
    let refused = pairing.invite(
        &Caller::local(ActorId::new("local:test").expect("a principal")),
        &direct(&grant),
        (
            ActionId::new(kr_ipc::new_uuid()),
            Digest256::from_bytes([1; 32]),
        ),
        host.network().network_config().expect("a configuration"),
        &lapsed,
    );
    assert!(
        matches!(refused, Err(ControllerError::WindowExpired { .. })),
        "{refused:?}"
    );
    let pending = calls::pending(&mut client).await.expect("readable");
    assert!(
        pending.pending.iter().any(|pending| pending.answered),
        "the answer is still waiting to be spent"
    );
    let _: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &direct(&grant),
    )
    .await
    .expect("the next admitted attempt issues it");
    host.stop().await;
}

/// A repeated `pair.invite` is owed its own answer. The original envelope, sent again over a new
/// connection whose window is not the one it quotes, gets the same invitation; the same action with
/// another payload is `ID_CONFLICT`; after a restart the repeat is told the invitation it issued is
/// no longer open, and nothing new is issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_invitation_is_answered_across_connections_and_a_restart() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let grant = viewer();
    calls::confirm_subject(
        environment,
        &mut client,
        issue(InviteModeKind::Direct, &grant),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await
    .expect("answered");
    let action = ActionId::new(kr_ipc::new_uuid());
    let original = client
        .compose(
            Method::PairInvite,
            action,
            ActionTarget::environment(environment),
            &direct(&grant),
        )
        .await
        .expect("an envelope");
    let first: PairInviteResult = client
        .repeat(&original)
        .await
        .expect("the daemon answers")
        .expect("an invitation")
        .to_typed()
        .expect("decodes");

    let mut other = host.client().await;
    let again: PairInviteResult = other
        .repeat(&original)
        .await
        .expect("the daemon answers")
        .expect("the same invitation")
        .to_typed()
        .expect("decodes");
    assert_eq!(again, first);
    let conflicting = other
        .compose(
            Method::PairInvite,
            action,
            ActionTarget::environment(environment),
            &direct(&proposal(&[
                ActionRight::SessionView,
                ActionRight::TerminalInput,
            ])),
        )
        .await
        .expect("an envelope");
    let refused = other
        .repeat(&conflicting)
        .await
        .expect("the daemon answers");
    assert_eq!(code(refused), ErrorCode::IdConflict);

    drop(client);
    drop(other);
    let host = host.restart().await;
    let mut after = host.client().await;
    let refused = after.repeat(&original).await.expect("the daemon answers");
    let error = refused.expect_err("the invitation is no longer open");
    assert_eq!(error.code, ErrorCode::PairingRejected);
    assert!(
        error.message.contains("no longer open"),
        "{}",
        error.message
    );
    host.stop().await;
}

/// A repeated `owner.confirmation.request` gets the challenge its action was given, before and
/// after that challenge is spent, and the same action with another subject is `ID_CONFLICT`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_confirmation_request_gets_its_own_challenge() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let grant = viewer();
    let action = ActionId::new(kr_ipc::new_uuid());
    let original = client
        .compose(
            Method::OwnerConfirmationRequest,
            action,
            ActionTarget::environment(environment),
            &OwnerConfirmationRequestParams {
                subject: issue(InviteModeKind::Direct, &grant),
            },
        )
        .await
        .expect("an envelope");
    let asked = |outcome: Result<kr_protocol::envelope::ParamsValue, ProtocolError>| {
        outcome
            .expect("a challenge")
            .to_typed::<OwnerConfirmationRequestResult>()
            .expect("decodes")
    };
    let first = asked(client.repeat(&original).await.expect("the daemon answers"));
    let again = asked(client.repeat(&original).await.expect("the daemon answers"));
    assert_eq!(again.request, first.request);

    let other = client
        .compose(
            Method::OwnerConfirmationRequest,
            action,
            ActionTarget::environment(environment),
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::EstablishClock,
            },
        )
        .await
        .expect("an envelope");
    assert_eq!(
        code(client.repeat(&other).await.expect("the daemon answers")),
        ErrorCode::IdConflict
    );

    // Answered and spent, the action still gets its own challenge back, not a new one.
    let (proof, _) = calls::sign(&first.request, &Signer::OwnerDevice(&owner_keys));
    calls::complete(environment, &mut client, proof, None)
        .await
        .expect("answered");
    let _: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &direct(&grant),
    )
    .await
    .expect("spent");
    let after = asked(client.repeat(&original).await.expect("the daemon answers"));
    assert_eq!(after.request, first.request);
    host.stop().await;
}

/// KR-REQ-10.19: a candidate is told how its invitation ended. A denial reads as denied and a
/// withdrawal as cancelled, on the candidate's own unpaired connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_candidate_learns_it_was_denied_or_withdrawn() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    for (deny, reason) in [
        (true, PairingConsumedReason::Denied),
        (false, PairingConsumedReason::Cancelled),
    ] {
        let invited = calls::invite_direct(
            environment,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &viewer(),
            &owner,
        )
        .await
        .expect("an invitation");
        let device = Device::create().await;
        let (connection, mut candidate, _value) =
            calls::redeem(&device.candidate(), &invited).await;
        calls::cancel(environment, &mut client, invited.invitation_id, deny)
            .await
            .expect("ended");
        let status: PairStatusResult = candidate
            .call(
                Method::PairStatus,
                &PairStatusParams {
                    invitation_id: invited.invitation_id,
                },
            )
            .await
            .expect("the candidate is answered");
        assert_eq!(status.status, PairStatus::Consumed { reason });
        assert!(status.owner.0.is_none(), "a candidate sees no owner view");
        connection.close(0u32.into(), b"ended");
    }
    host.stop().await;
}

/// KR-REQ-10.33, KR-REQ-23.26: a device that paired can reconnect as the device it became and ask
/// about its own invitation, and it is told about that one and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_reads_its_own_pairing_and_nothing_else() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let device = Device::create().await;
    let record = pair_with(&host, &device, &owner_keys, viewer()).await;
    let session = connect(&host, &device, &record).await;
    let own: PairStatusResult = session
        .read(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: record.committed_invitation_id.expect("its invitation"),
            },
        )
        .await
        .expect("its own pairing");
    assert_eq!(
        own.status,
        PairStatus::Committed {
            device_id: record.device_id,
            grant_id: record.grant.grant_id,
        }
    );
    let others = host
        .owner
        .as_ref()
        .and_then(|owner| owner.committed_invitation_id)
        .expect("the owner's invitation");
    let refused = session
        .read::<_, PairStatusResult>(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: others,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(ClientError::Host(ref error)) if error.code == ErrorCode::PermissionDenied),
        "{refused:?}"
    );
    host.stop().await;
}

/// KR-REQ-10.19: an authentication failure is ambiguous. A redemption proved with the wrong secret
/// is told the pairing could not be authenticated, in exactly those words, and nothing about which
/// value was wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authentication_failure_says_nothing_more() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &Signer::OwnerDevice(&owner_keys),
    )
    .await
    .expect("an invitation");
    let device = Device::create().await;
    let candidate = device.candidate();
    let mut payload = direct_payload(&invited);
    let connection = candidate
        .endpoint
        .connect(host_addr(&payload), kr_protocol::hello::ALPN)
        .await
        .expect("the candidate reaches the host");
    let mut unpaired = handshake::connect_unpaired(&connection, candidate.identity)
        .await
        .expect("an unpaired connection");
    let challenge: PairRedeemResult = unpaired
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Challenge {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("a challenge");
    let PairRedeemResult::Challenge(challenge) = challenge else {
        panic!("the first step answers with a challenge");
    };
    // The wrong secret.
    payload.secret = SecretBytes32::from_bytes([9; 32]);
    let (proof, _transcript) = redeem_proof(
        &payload,
        &challenge,
        &candidate.keys.authorisation,
        &candidate.declared,
        &HostPeer(*challenge.endpoint_id.as_bytes()),
    )
    .expect("a proof over the wrong secret");
    let refused = unpaired
        .call::<_, PairRedeemResult>(
            Method::PairRedeem,
            &PairRedeemParams::Direct(Box::new(proof)),
        )
        .await;
    let error = match refused {
        Err(kr_transport::TransportError::Handshake(error)) => error,
        other => panic!("refused, not {other:?}"),
    };
    assert_eq!(error.code, ErrorCode::PairingAuthFailed);
    assert_eq!(error.message, AUTHENTICATION_FAILED);
    connection.close(0u32.into(), b"refused");
    host.stop().await;
}
