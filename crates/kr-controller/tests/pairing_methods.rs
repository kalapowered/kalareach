//! The pairing and owner-confirmation methods, served: what the owner's own client and a paired
//! owner device reach, and what they are refused.
//!
//! Every pairing here goes through the methods themselves. The owner asks for a challenge, answers
//! it, issues the invitation and confirms the candidate over the host's local socket; the candidate
//! redeems over its own unpaired iroh connection; an owner device reads and answers challenges
//! over its authorised connection.

#![cfg(unix)]

mod net_support;

use kr_client::error::ClientError;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, DescribedAction, OwnerConfirmationCompleteParams,
    OwnerConfirmationCompleteResult, OwnerConfirmationPendingParams,
    OwnerConfirmationPendingResult, OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::GrantExpiry;
use kr_protocol::ids::ActionId;
use kr_protocol::invitation::{
    InviteGrantKind, InviteMode, InviteModeKind, PairCancelParams, PairConfirmParams,
    PairInviteParams, PairInviteResult, PairingApproval,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, INVITATION_LIFETIME_MS, PairStatus, PairingConsumedReason, ProposedGrant,
    SensitiveAction,
};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable};
use kr_protocol::sharing::DeviceRevokeParams;
use net_support::pairing::{self as calls, Signer};
use net_support::{Device, Host, RawDevice, connect, pair_with, proposal};

fn keys() -> DeviceKeys {
    DeviceKeys::generate().expect("keys")
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

fn issue_subject(
    grant_kind: InviteGrantKind,
    proposed_grant: &ProposedGrant,
) -> ConfirmationSubject {
    ConfirmationSubject::IssueInvitation {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        grant_kind,
        proposed_grant: proposed_grant.clone(),
    }
}

fn invite_params(grant_kind: InviteGrantKind, proposed_grant: &ProposedGrant) -> PairInviteParams {
    PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind,
        proposed_grant: proposed_grant.clone(),
    }
}

fn code<T: std::fmt::Debug>(outcome: Result<T, ProtocolError>) -> ErrorCode {
    match outcome {
        Ok(value) => panic!("refused, not {value:?}"),
        Err(error) => error.code,
    }
}

/// KR-REQ-10.04, KR-REQ-10.53: the first owner is established through local IPC under the
/// host's own account, with the terminal bootstrap, and the bootstrap ends with it.
///
/// The invitation is the five-minute one, and the first device paired through it holds a
/// personal owner grant. From then on the host says the bootstrap no longer applies and refuses a
/// terminal proof, and it is the owner device's own proof that answers a challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_established_through_local_ipc_and_ends_the_bootstrap() {
    let host = Host::start_unowned().await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let ceremony = keys();
    let bootstrap = Signer::Bootstrap(&ceremony.authorisation);
    let owner_keys = keys();
    let owner = Device::with_keys(owner_keys.clone()).await;
    let owner_grant = kr_pairing::grants::personal_owner_grant();

    let challenge = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::PersonalOwner, &owner_grant),
    )
    .await
    .expect("a challenge");
    assert!(
        challenge.initial_bootstrap,
        "a host with no owner is in its initial bootstrap"
    );
    let (proof, presented) = calls::sign(&challenge.request, &bootstrap);
    let answered = calls::complete(environment, &mut client, proof, presented)
        .await
        .expect("the bootstrap answers");
    assert_eq!(
        answered.channel,
        ConfirmationChannel::LocalBootstrapTerminal
    );
    let invited: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &invite_params(InviteGrantKind::PersonalOwner, &owner_grant),
    )
    .await
    .expect("the first owner's invitation");
    let lifetime = invited
        .expires_at_ms
        .get()
        .saturating_sub(kr_ipc::now_ms().get());
    assert!(
        lifetime <= INVITATION_LIFETIME_MS && lifetime > INVITATION_LIFETIME_MS - 60_000,
        "a five-minute invitation, not {lifetime} ms"
    );

    let (connection, _candidate, value) = calls::redeem(&owner.candidate(), &invited).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &bootstrap)
            .await
            .expect("the first owner commits");
    assert!(confirmed.event.first_owner);
    assert_eq!(
        confirmed.event.channel,
        ConfirmationChannel::LocalBootstrapTerminal
    );
    assert_eq!(confirmed.event.verification_value, value);
    let record = host
        .network()
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("readable")
        .expect("the owner device");
    assert!(record.grant.permits(ActionRight::HostManage));
    assert_eq!(record.grant.expiry, GrantExpiry::Never);
    connection.close(0u32.into(), b"paired");

    // The bootstrap is over for good.
    let after = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &viewer()),
    )
    .await
    .expect("a challenge");
    assert!(!after.initial_bootstrap);
    let (proof, presented) = calls::sign(&after.request, &bootstrap);
    assert_eq!(
        code(calls::complete(environment, &mut client, proof, presented).await),
        ErrorCode::OwnerConfirmationRequired
    );
    // The owner device's own ceremony answers it instead.
    let (proof, _) = calls::sign(&after.request, &Signer::OwnerDevice(&owner_keys));
    calls::complete(environment, &mut client, proof, None)
        .await
        .expect("the owner device answers");
    host.stop().await;
}

/// KR-REQ-10.53, KR-REQ-10.05: the terminal bootstrap establishes the first owner and confirms
/// nothing else. A session invitation, the clock and a described action each refuse a terminal
/// proof on a host with no owner, and so does a terminal proof that does not present the key it
/// was signed with. Without any confirmation, a host with no owner issues nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bootstrap_confirms_the_first_owner_and_nothing_else() {
    let host = Host::start_unowned().await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let ceremony = keys();
    let bootstrap = Signer::Bootstrap(&ceremony.authorisation);

    for subject in [
        issue_subject(InviteGrantKind::SessionInvitation, &viewer()),
        ConfirmationSubject::EstablishClock,
        ConfirmationSubject::Described(DescribedAction {
            action: SensitiveAction::TrustRepositoryRoot,
            action_digest: Digest256::from_bytes([4; 32]),
            destination_keys: Nullable::null(),
            destination_rights: CanonicalSet::new(),
        }),
    ] {
        let challenge = calls::request(environment, &mut client, subject)
            .await
            .expect("a challenge");
        let (proof, presented) = calls::sign(&challenge.request, &bootstrap);
        assert_eq!(
            code(calls::complete(environment, &mut client, proof, presented).await),
            ErrorCode::OwnerConfirmationRequired
        );
    }

    // A terminal proof names the key it was signed with, and only that key.
    let owner_grant = kr_pairing::grants::personal_owner_grant();
    let challenge = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::PersonalOwner, &owner_grant),
    )
    .await
    .expect("a challenge");
    let (proof, _) = calls::sign(&challenge.request, &bootstrap);
    assert_eq!(
        code(calls::complete(environment, &mut client, proof.clone(), None).await),
        ErrorCode::OwnerConfirmationRequired
    );
    let other = keys();
    assert_eq!(
        code(
            calls::complete(
                environment,
                &mut client,
                proof,
                Some(*other.authorisation.public())
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );

    // And a local caller's own credentials are not a confirmation of anything.
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &invite_params(InviteGrantKind::SessionInvitation, &viewer()),
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    host.stop().await;
}

/// KR-REQ-10.05: every sensitive action needs a fresh owner confirmation naming exactly it, spent
/// once. Issuing an invitation needs one naming its exact grant; confirming a device needs one
/// naming exactly that candidate, which an issuing confirmation or the invitation's own answer is
/// not; the clock needs its own; and the three actions no method performs yet are answered for
/// their exact description and nothing else. Enlarging persistent authority is pairing a personal
/// owner grant, which needs both of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_sensitive_action_needs_a_fresh_confirmation_naming_it() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let grant = viewer();
    let wider = proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]);

    // No confirmation, and a confirmation for other rights, issue nothing.
    let params = invite_params(InviteGrantKind::SessionInvitation, &grant);
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &params
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    calls::confirm_subject(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &wider),
        &owner,
    )
    .await
    .expect("answered for other rights");
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &params
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );

    // The exact one issues exactly one invitation.
    calls::confirm_subject(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
        &owner,
    )
    .await
    .expect("answered");
    let invited: PairInviteResult =
        calls::mutate(environment, &mut client, Method::PairInvite, &params)
            .await
            .expect("an invitation");

    // A candidate binds; the invitation's own answer confirms nothing, and neither does the
    // confirmation that issued it or one for another device.
    let device = Device::create().await;
    let (connection, _candidate, _value) = calls::redeem(&device.candidate(), &invited).await;
    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let approval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("an approval tuple");
    let confirm = PairConfirmParams {
        invitation_id: invited.invitation_id,
        approval,
    };
    assert_eq!(
        code(
            calls::mutate::<_, kr_protocol::invitation::PairConfirmResult>(
                environment,
                &mut client,
                Method::PairConfirm,
                &confirm
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    calls::confirm_subject(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
        &owner,
    )
    .await
    .expect("an issuing confirmation");
    assert_eq!(
        code(
            calls::mutate::<_, kr_protocol::invitation::PairConfirmResult>(
                environment,
                &mut client,
                Method::PairConfirm,
                &confirm
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("the device commits");
    assert_eq!(
        confirmed.event.channel,
        ConfirmationChannel::OwnerDevicePresence
    );
    connection.close(0u32.into(), b"paired");

    // The clock needs its own confirmation, once.
    assert!(host.network().establish_clock().await.is_err());
    calls::confirm_subject(
        environment,
        &mut client,
        ConfirmationSubject::EstablishClock,
        &owner,
    )
    .await
    .expect("answered for the clock");
    host.network()
        .establish_clock()
        .await
        .expect("the clock is established");
    assert!(
        host.network().establish_clock().await.is_err(),
        "spent once"
    );

    // The three actions no method performs yet: each is answered for its exact description, and
    // only an effect whose own expectation matches it spends it, once.
    let pairing = host.network().pairing();
    for action in [
        SensitiveAction::EnlargeGrant,
        SensitiveAction::TrustRepositoryRoot,
        SensitiveAction::GrantExecutableCapability,
    ] {
        let digest = Digest256::from_bytes([7; 32]);
        let rights: CanonicalSet<ActionRight> = [ActionRight::HostManage].into_iter().collect();
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::Described(DescribedAction {
                action,
                action_digest: digest,
                destination_keys: Nullable::null(),
                destination_rights: rights.clone(),
            }),
            &owner,
        )
        .await
        .expect("answered");
        let elsewhere = Digest256::from_bytes([8; 32]);
        assert!(
            pairing
                .owner()
                .consume_for(
                    &pairing
                        .owner()
                        .expectation(action, elsewhere, None, &rights),
                    "another effect"
                )
                .is_err()
        );
        let narrower = CanonicalSet::new();
        assert!(
            pairing
                .owner()
                .consume_for(
                    &pairing.owner().expectation(action, digest, None, &narrower),
                    "another set of rights"
                )
                .is_err()
        );
        pairing
            .owner()
            .consume_for(
                &pairing.owner().expectation(action, digest, None, &rights),
                "the described effect",
            )
            .expect("spent by its own effect");
        assert!(
            pairing
                .owner()
                .consume_for(
                    &pairing.owner().expectation(action, digest, None, &rights),
                    "the described effect again"
                )
                .is_err(),
            "spent once"
        );
    }
    // A typed action cannot be described instead.
    assert_eq!(
        code(
            calls::request(
                environment,
                &mut client,
                ConfirmationSubject::Described(DescribedAction {
                    action: SensitiveAction::IssueInvitation,
                    action_digest: Digest256::from_bytes([7; 32]),
                    destination_keys: Nullable::null(),
                    destination_rights: CanonicalSet::new(),
                }),
            )
            .await
        ),
        ErrorCode::InvalidArgument
    );

    // Persistent enlargement is owner pairing: a second owner device, confirmed twice.
    let second = Device::create().await;
    let owner_grant = kr_pairing::grants::personal_owner_grant();
    let invited = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &owner_grant,
        &owner,
    )
    .await
    .expect("an owner invitation");
    let (connection, _candidate, _value) = calls::redeem(&second.candidate(), &invited).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("a second owner device");
    assert!(!confirmed.event.first_owner);
    connection.close(0u32.into(), b"paired");
    host.stop().await;
}

/// KR-REQ-10.07: a noninteractive confirmation from a session, plugin or contact-tool channel is
/// refused, even signed by the owner device's own key; and a host with no enrolled presence
/// signer refuses that channel too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn noninteractive_channels_never_carry_a_confirmation() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    for channel in [
        ConfirmationChannel::Session,
        ConfirmationChannel::Plugin,
        ConfirmationChannel::ContactTool,
        ConfirmationChannel::EnrolledPresenceSigner,
    ] {
        let challenge = calls::request(
            environment,
            &mut client,
            issue_subject(InviteGrantKind::SessionInvitation, &viewer()),
        )
        .await
        .expect("a challenge");
        let proof = kr_pairing::confirm::sign_confirmation(
            &owner_keys.authorisation,
            &challenge.request,
            channel,
        )
        .expect("a proof");
        assert_eq!(
            code(calls::complete(environment, &mut client, proof, None).await),
            ErrorCode::OwnerConfirmationRequired,
            "{channel:?}"
        );
    }
    // Nothing was answered, so nothing issues.
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &invite_params(InviteGrantKind::SessionInvitation, &viewer()),
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired
    );
    host.stop().await;
}

/// KR-REQ-10.05, KR-REQ-10.06: a separately paired owner device approves what the local owner
/// asked. It reads the outstanding challenge with the exact action and the complete grant over its
/// own authorised connection, answers it from there, and the local owner's invitation spends it;
/// the acceptance record keeps the answer and its consumption. A device that is not an owner reads
/// nothing, and a device cannot carry in a proof another device signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_approves_what_the_local_owner_asked() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner_record = host.owner.clone().expect("the owner device");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let session = connect(&host, owner_device, &owner_record).await;
    let raw = RawDevice::connect(&host, owner_device, &owner_record).await;

    let grant = viewer();
    let challenge = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
    )
    .await
    .expect("the local owner asks");
    let pending: OwnerConfirmationPendingResult = session
        .read(
            Method::OwnerConfirmationPending,
            &OwnerConfirmationPendingParams {},
        )
        .await
        .expect("the owner device reads what is outstanding");
    let listed = pending
        .pending
        .iter()
        .find(|pending| pending.request == challenge.request)
        .expect("the challenge is listed");
    assert!(!listed.answered);
    assert_eq!(
        listed.display,
        ConfirmationDisplay::IssueInvitation {
            mode: InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        }
    );
    let (proof, _) = calls::sign(&listed.request, &Signer::OwnerDevice(&owner_keys));
    raw.mutate(
        Method::OwnerConfirmationComplete,
        ActionId::new(kr_ipc::new_uuid()),
        ActionTarget::environment(environment),
        &OwnerConfirmationCompleteParams {
            proof: proof.clone(),
            bootstrap_signer: Nullable::null(),
        },
    )
    .await
    .expect("the owner device answers from its own connection");
    let invited: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &invite_params(InviteGrantKind::SessionInvitation, &grant),
    )
    .await
    .expect("the local owner's invitation spends it");
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(challenge.request.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert_eq!(acceptance.channel, "owner_device_presence");
    assert!(acceptance.consumed_at_ms.is_some());
    calls::cancel(environment, &mut client, invited.invitation_id, false)
        .await
        .expect("withdrawn");

    // A device that is not an owner device reads nothing and answers nothing.
    let viewer_keys = keys();
    let viewer_device = Device::with_keys(viewer_keys.clone()).await;
    let viewer_record = pair_with(&host, &viewer_device, &owner_keys, viewer()).await;
    let viewer_session = connect(&host, &viewer_device, &viewer_record).await;
    let refused = viewer_session
        .read::<_, OwnerConfirmationPendingResult>(
            Method::OwnerConfirmationPending,
            &OwnerConfirmationPendingParams {},
        )
        .await;
    assert!(
        matches!(refused, Err(ClientError::Host(ref error)) if error.code == ErrorCode::PermissionDenied),
        "{refused:?}"
    );
    let challenge = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
    )
    .await
    .expect("another challenge");
    let viewer_raw = RawDevice::connect(&host, &viewer_device, &viewer_record).await;
    // The owner's proof, carried in by another device, is not that device's ceremony.
    let (proof, _) = calls::sign(&challenge.request, &Signer::OwnerDevice(&owner_keys));
    let carried = viewer_raw
        .mutate(
            Method::OwnerConfirmationComplete,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            &OwnerConfirmationCompleteParams {
                proof,
                bootstrap_signer: Nullable::null(),
            },
        )
        .await;
    assert_eq!(code(carried), ErrorCode::OwnerConfirmationRequired);
    host.stop().await;
}

/// KR-REQ-23.26: the six methods are served with their transcript binding and the exact issuing
/// owner. A paired device is the issuing owner of nothing, so it cannot confirm, cancel or read an
/// invitation's owner view; an approval that names another transcript or key digest commits
/// nothing; the candidate learns its result on its own unpaired surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_issuing_owner_confirms_and_only_the_bound_candidate() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let owner_record = host.owner.clone().expect("the owner device");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let raw = RawDevice::connect(&host, owner_device, &owner_record).await;
    let session = connect(&host, owner_device, &owner_record).await;

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
    let (connection, _candidate, _value) = calls::redeem(&device.candidate(), &invited).await;
    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let approval = status
        .owner
        .0
        .and_then(|view| view.approval.0)
        .expect("an approval tuple");

    // Not the issuing owner, even as the host's own owner device.
    let over_network = session
        .read::<_, kr_protocol::preauth::PairStatusResult>(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        )
        .await;
    assert!(
        matches!(over_network, Err(ClientError::Host(ref error)) if error.code == ErrorCode::PermissionDenied),
        "{over_network:?}"
    );
    let refused = raw
        .mutate(
            Method::PairConfirm,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            &PairConfirmParams {
                invitation_id: invited.invitation_id,
                approval,
            },
        )
        .await;
    assert_eq!(code(refused), ErrorCode::PermissionDenied);
    let refused = raw
        .mutate(
            Method::PairCancel,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            &PairCancelParams {
                invitation_id: invited.invitation_id,
                deny: false,
            },
        )
        .await;
    assert_eq!(code(refused), ErrorCode::PermissionDenied);

    // An approval naming another candidate commits nothing, and spends nothing.
    calls::confirm_subject(
        environment,
        &mut client,
        ConfirmationSubject::ConfirmDevice {
            invitation_id: invited.invitation_id,
        },
        &owner,
    )
    .await
    .expect("answered for this candidate");
    let PairingApproval::Direct {
        transcript_digest,
        client_key_digest,
    } = approval
    else {
        panic!("a direct invitation has a direct approval");
    };
    let tampered = PairConfirmParams {
        invitation_id: invited.invitation_id,
        approval: PairingApproval::Direct {
            transcript_digest,
            client_key_digest: Digest256::from_bytes([1; 32]),
        },
    };
    assert_eq!(
        code(
            calls::mutate::<_, kr_protocol::invitation::PairConfirmResult>(
                environment,
                &mut client,
                Method::PairConfirm,
                &tampered
            )
            .await
        ),
        ErrorCode::PairingAuthFailed
    );
    let _ = client_key_digest;
    let confirmed: kr_protocol::invitation::PairConfirmResult = calls::mutate(
        environment,
        &mut client,
        Method::PairConfirm,
        &PairConfirmParams {
            invitation_id: invited.invitation_id,
            approval,
        },
    )
    .await
    .expect("the approved candidate commits");

    // A retry of the confirmation gets the committed result and changes nothing.
    let retried: kr_protocol::invitation::PairConfirmResult = calls::mutate(
        environment,
        &mut client,
        Method::PairConfirm,
        &PairConfirmParams {
            invitation_id: invited.invitation_id,
            approval,
        },
    )
    .await
    .expect("the committed result");
    assert_eq!(retried, confirmed);
    connection.close(0u32.into(), b"paired");
    host.stop().await;
}

/// KR-REQ-10.08: a pairing writes its security event with the device, and revocation needs no new
/// confirmation. The event names the owner confirmation it was accepted under and stays readable
/// through the owner's view after the invitation object is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_writes_its_event_and_revoking_needs_no_confirmation() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
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
    let (connection, _candidate, value) = calls::redeem(&device.candidate(), &invited).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, invited.invitation_id, &owner)
            .await
            .expect("committed");
    connection.close(0u32.into(), b"paired");
    let event = &confirmed.event;
    assert_eq!(event.device_id, confirmed.device_id);
    assert_eq!(event.grant_id, confirmed.grant_id);
    assert_eq!(event.verification_value, value);
    assert_eq!(event.mode, InviteModeKind::Direct);
    assert_eq!(event.channel, ConfirmationChannel::OwnerDevicePresence);
    assert_eq!(
        event.signer_key_id,
        kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            owner_keys.authorisation.public().as_bytes()
        )
    );
    // The bootstrap wrote the first row; this pairing wrote the second.
    let outbox = host
        .network()
        .pairing()
        .rows()
        .events_after(None, 10)
        .expect("readable");
    assert_eq!(outbox.len(), 2);
    assert_eq!(&outbox[1], event);
    let status = calls::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view after the commit");
    assert!(matches!(status.status, PairStatus::Committed { .. }));
    assert_eq!(
        status.owner.0.and_then(|view| view.event.0).as_ref(),
        Some(event)
    );

    // Revocation is a restriction: it needs no confirmation.
    assert!(
        calls::pending(&mut client)
            .await
            .expect("readable")
            .pending
            .is_empty()
    );
    let _: kr_protocol::sharing::RevocationResult = calls::mutate(
        environment,
        &mut client,
        Method::DeviceRevoke,
        &DeviceRevokeParams {
            device_id: confirmed.device_id,
        },
    )
    .await
    .expect("revoked without a confirmation");
    let record = host
        .network()
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("readable")
        .expect("the record");
    assert!(!record.is_paired());
    host.stop().await;
}

/// An invitation is issued once per action: a retry of the same action with the same parameters
/// gets the same answer, the same action with other parameters is `ID_CONFLICT`, and a cancelled
/// invitation's retry is told what became of it rather than given another.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_is_issued_once_per_action() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let grant = viewer();
    calls::confirm_subject(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
        &owner,
    )
    .await
    .expect("answered");
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = invite_params(InviteGrantKind::SessionInvitation, &grant);
    let first: PairInviteResult = calls::mutate_as(
        environment,
        &mut client,
        action,
        Method::PairInvite,
        &params,
    )
    .await
    .expect("an invitation");
    let again: PairInviteResult = calls::mutate_as(
        environment,
        &mut client,
        action,
        Method::PairInvite,
        &params,
    )
    .await
    .expect("the same answer");
    assert_eq!(again, first);
    let other = invite_params(
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    );
    assert_eq!(
        code(
            calls::mutate_as::<_, PairInviteResult>(
                environment,
                &mut client,
                action,
                Method::PairInvite,
                &other
            )
            .await
        ),
        ErrorCode::IdConflict
    );
    let cancelled = calls::cancel(environment, &mut client, first.invitation_id, false)
        .await
        .expect("withdrawn");
    assert_eq!(
        cancelled.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::Cancelled
        }
    );
    assert_eq!(
        code(
            calls::mutate_as::<_, PairInviteResult>(
                environment,
                &mut client,
                action,
                Method::PairInvite,
                &params
            )
            .await
        ),
        ErrorCode::PairingRejected
    );
    host.stop().await;
}

/// The parameters of a completion that answers a challenge with `proof`.
fn completing(
    proof: kr_protocol::pairing::OwnerConfirmationProof,
) -> OwnerConfirmationCompleteParams {
    OwnerConfirmationCompleteParams {
        proof,
        bootstrap_signer: Nullable::null(),
    }
}

/// Section 9, KR-REQ-09.07: an owner device's completion is answered again for its own action and
/// payload, and for nothing else.
///
/// The owner device answers two challenges under two actions of its own. Each proof, accepted and
/// on record, submitted under the other one's action is a reused identifier with another payload,
/// and is refused as `ID_CONFLICT` rather than given the answer its own acceptance holds. The exact
/// repeat of each is answered from its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_devices_completion_is_answered_again_only_under_its_own_action() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner_record = host.owner.clone().expect("the owner device");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let raw = RawDevice::connect(&host, owner_device, &owner_record).await;
    let target = ActionTarget::environment(environment);

    let first = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &viewer()),
    )
    .await
    .expect("a challenge");
    let second = calls::request(
        environment,
        &mut client,
        issue_subject(
            InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        ),
    )
    .await
    .expect("another challenge");
    let (p, _) = calls::sign(&first.request, &Signer::OwnerDevice(&owner_keys));
    let (q, _) = calls::sign(&second.request, &Signer::OwnerDevice(&owner_keys));
    let (a, b) = (
        ActionId::new(kr_ipc::new_uuid()),
        ActionId::new(kr_ipc::new_uuid()),
    );
    let answered_p = raw
        .mutate(
            Method::OwnerConfirmationComplete,
            a,
            target.clone(),
            &completing(p.clone()),
        )
        .await
        .expect("the owner device answers the first under its action");
    let answered_q = raw
        .mutate(
            Method::OwnerConfirmationComplete,
            b,
            target.clone(),
            &completing(q.clone()),
        )
        .await
        .expect("and the second under another");

    // Each accepted proof under the other's action: another payload under an identifier already
    // spent.
    for (action, proof) in [(a, q.clone()), (b, p.clone())] {
        let swapped = raw
            .mutate(
                Method::OwnerConfirmationComplete,
                action,
                target.clone(),
                &completing(proof),
            )
            .await;
        assert_eq!(code(swapped), ErrorCode::IdConflict);
    }
    // The exact repeats are answered from their own records.
    assert_eq!(
        raw.mutate(
            Method::OwnerConfirmationComplete,
            a,
            target.clone(),
            &completing(p),
        )
        .await
        .expect("the first's own repeat"),
        answered_p
    );
    assert_eq!(
        raw.mutate(Method::OwnerConfirmationComplete, b, target, &completing(q))
            .await
            .expect("the second's own repeat"),
        answered_q
    );
    host.stop().await;
}

/// Section 9, KR-REQ-09.07: one action identifier of the owner's is spent on one pairing answer,
/// across all five pairing methods, and an answer that changed nothing spends it too.
///
/// An identifier that asked for a challenge cannot withdraw an invitation. One that withdrew an
/// invitation already ended, which changed nothing, cannot withdraw another. Two answered proofs
/// swapped between their actions are refused. Every exact repeat is answered from its record, a
/// completion's after its challenge was spent as well, and the spent proof under a new action is a
/// completion of its own with nothing left to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_action_identifier_is_spent_on_one_pairing_answer() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let grant = viewer();
    let withdrawal = |invitation_id| PairCancelParams {
        invitation_id,
        deny: false,
    };
    let still_offered = |status: &PairStatusResult| {
        matches!(
            status.status,
            PairStatus::Open { .. } | PairStatus::AwaitingApproval { .. }
        )
    };

    // An identifier spent on asking for a challenge.
    let asked = ActionId::new(kr_ipc::new_uuid());
    let asking = OwnerConfirmationRequestParams {
        subject: issue_subject(InviteGrantKind::SessionInvitation, &grant),
    };
    let challenge: OwnerConfirmationRequestResult = calls::mutate_as(
        environment,
        &mut client,
        asked,
        Method::OwnerConfirmationRequest,
        &asking,
    )
    .await
    .expect("a challenge");
    let first = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &grant,
        &owner,
    )
    .await
    .expect("an invitation");
    assert_eq!(
        code(
            calls::mutate_as::<_, PairStatusResult>(
                environment,
                &mut client,
                asked,
                Method::PairCancel,
                &withdrawal(first.invitation_id),
            )
            .await
        ),
        ErrorCode::IdConflict
    );
    assert!(
        still_offered(
            &calls::owner_status(&mut client, first.invitation_id)
                .await
                .expect("the owner's view")
        ),
        "the refused withdrawal withdrew nothing"
    );
    let again: OwnerConfirmationRequestResult = calls::mutate_as(
        environment,
        &mut client,
        asked,
        Method::OwnerConfirmationRequest,
        &asking,
    )
    .await
    .expect("the request's own repeat");
    assert_eq!(again.request, challenge.request);

    // A withdrawal that changed nothing spends its identifier all the same.
    let withdrawn = calls::cancel(environment, &mut client, first.invitation_id, false)
        .await
        .expect("withdrawn");
    let second = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &grant,
        &owner,
    )
    .await
    .expect("another invitation");
    let late = ActionId::new(kr_ipc::new_uuid());
    let told: PairStatusResult = calls::mutate_as(
        environment,
        &mut client,
        late,
        Method::PairCancel,
        &withdrawal(first.invitation_id),
    )
    .await
    .expect("told how the first ended");
    assert_eq!(told.status, withdrawn.status);
    assert_eq!(
        code(
            calls::mutate_as::<_, PairStatusResult>(
                environment,
                &mut client,
                late,
                Method::PairCancel,
                &withdrawal(second.invitation_id),
            )
            .await
        ),
        ErrorCode::IdConflict
    );
    assert!(
        still_offered(
            &calls::owner_status(&mut client, second.invitation_id)
                .await
                .expect("the owner's view")
        ),
        "the second invitation is still on offer"
    );
    calls::cancel(environment, &mut client, second.invitation_id, false)
        .await
        .expect("withdrawn");

    // Two answered proofs swapped between their actions.
    let one = calls::request(
        environment,
        &mut client,
        issue_subject(InviteGrantKind::SessionInvitation, &grant),
    )
    .await
    .expect("a challenge");
    let other = calls::request(
        environment,
        &mut client,
        issue_subject(
            InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        ),
    )
    .await
    .expect("another challenge");
    let (p, _) = calls::sign(&one.request, &owner);
    let (q, _) = calls::sign(&other.request, &owner);
    let (a, b) = (
        ActionId::new(kr_ipc::new_uuid()),
        ActionId::new(kr_ipc::new_uuid()),
    );
    let by_a: OwnerConfirmationCompleteResult = calls::mutate_as(
        environment,
        &mut client,
        a,
        Method::OwnerConfirmationComplete,
        &completing(p.clone()),
    )
    .await
    .expect("the first proof under its action");
    let _: OwnerConfirmationCompleteResult = calls::mutate_as(
        environment,
        &mut client,
        b,
        Method::OwnerConfirmationComplete,
        &completing(q.clone()),
    )
    .await
    .expect("the second under another");
    assert_eq!(
        code(
            calls::mutate_as::<_, OwnerConfirmationCompleteResult>(
                environment,
                &mut client,
                a,
                Method::OwnerConfirmationComplete,
                &completing(q),
            )
            .await
        ),
        ErrorCode::IdConflict
    );

    // The first proof is spent by the invitation it approves; its exact repeat is still answered
    // from its record, and the same proof under a new action has nothing left to answer.
    let spent: PairInviteResult = calls::mutate(
        environment,
        &mut client,
        Method::PairInvite,
        &invite_params(InviteGrantKind::SessionInvitation, &grant),
    )
    .await
    .expect("the invitation spends the first proof");
    let repeated: OwnerConfirmationCompleteResult = calls::mutate_as(
        environment,
        &mut client,
        a,
        Method::OwnerConfirmationComplete,
        &completing(p.clone()),
    )
    .await
    .expect("the first proof's own repeat");
    assert_eq!(repeated, by_a);
    assert_eq!(
        code(calls::complete(environment, &mut client, p, None).await),
        ErrorCode::OwnerConfirmationRequired
    );
    calls::cancel(environment, &mut client, spent.invitation_id, false)
        .await
        .expect("withdrawn");
    host.stop().await;
}

/// KR-REQ-10.52: a host whose only owner device is revoked, with no enrolled presence signer and
/// no terminal, refuses every confirmation and falls back to nothing. The terminal bootstrap stays
/// over, because the host had an owner; the former owner device's proof no longer answers; a proof
/// on the enrolled signer's channel is refused; and an answer the owner device gave before its
/// revocation is spent on nothing after it, so nothing sensitive is issued. Before the revocation,
/// the owner device's own proof answers the same kind of challenge and issues the invitation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headless_host_with_no_owner_device_refuses_every_confirmation() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let owner_record = host.owner.clone().expect("the owner device");
    // One grant throughout, so every answer and every invitation below names the same one.
    let grant = viewer();
    let subject = || issue_subject(InviteGrantKind::SessionInvitation, &grant);

    // While the owner device is paired, its proof answers, and the invitation spends the answer.
    let issued = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &grant,
        &owner,
    )
    .await
    .expect("the owner device's proof issues an invitation");
    calls::cancel(environment, &mut client, issued.invitation_id, false)
        .await
        .expect("withdrawn");
    // And one more answer, which nothing spends before the revocation.
    calls::confirm_subject(environment, &mut client, subject(), &owner)
        .await
        .expect("the owner device answers while it is paired");

    let _: kr_protocol::sharing::RevocationResult = calls::mutate(
        environment,
        &mut client,
        Method::DeviceRevoke,
        &DeviceRevokeParams {
            device_id: owner_record.device_id,
        },
    )
    .await
    .expect("the only owner device is revoked");
    // The revocation withdrew the authority this connection was admitted under.
    let mut client = host.client().await;

    let terminal = keys();
    let enrolled = keys();
    for (who, signer) in [
        (
            "the terminal bootstrap",
            Some(Signer::Bootstrap(&terminal.authorisation)),
        ),
        (
            "the former owner device",
            Some(Signer::OwnerDevice(&owner_keys)),
        ),
        ("an enrolled presence signer", None),
    ] {
        let challenge = calls::request(environment, &mut client, subject())
            .await
            .expect("a challenge");
        assert!(
            !challenge.initial_bootstrap,
            "a host that had an owner is never in its initial bootstrap again"
        );
        let (proof, presented) = match &signer {
            Some(signer) => calls::sign(&challenge.request, signer),
            None => (
                kr_pairing::confirm::sign_confirmation(
                    &enrolled.authorisation,
                    &challenge.request,
                    ConfirmationChannel::EnrolledPresenceSigner,
                )
                .expect("a proof"),
                None,
            ),
        };
        assert_eq!(
            code(calls::complete(environment, &mut client, proof, presented).await),
            ErrorCode::OwnerConfirmationRequired,
            "{who}"
        );
    }
    assert_eq!(
        code(
            calls::mutate::<_, PairInviteResult>(
                environment,
                &mut client,
                Method::PairInvite,
                &invite_params(InviteGrantKind::SessionInvitation, &grant),
            )
            .await
        ),
        ErrorCode::OwnerConfirmationRequired,
        "nothing answered since, and the answer the owner device gave before its revocation \
         issues nothing"
    );
    host.stop().await;
}

/// `proposed_grant`, naming one current approval or one current question.
fn naming(proposed_grant: &ProposedGrant, approval: bool) -> ProposedGrant {
    let mut named = proposed_grant.clone();
    if approval {
        named
            .history
            .named_approvals
            .insert(kr_protocol::ids::PendingResourceId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x52; 16]),
            ));
    } else {
        named
            .history
            .named_questions
            .insert(kr_protocol::ids::QuestionId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x51; 16]),
            ));
    }
    named
}

/// KR-REQ-10.51: a pairing invitation shows its issuer no preview of a named resource, so the host
/// gives no challenge to confirm issuing one whose proposal names a current approval or question,
/// of either kind, and says why; no challenge exists afterwards, and `pair.invite` with such a
/// proposal issues nothing. The controls are the same proposals without the name, confirmed and
/// issued as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_proposal_naming_a_current_approval_or_question_is_given_no_challenge() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);

    for (grant_kind, plain) in [
        (InviteGrantKind::SessionInvitation, viewer()),
        (
            InviteGrantKind::PersonalOwner,
            kr_pairing::grants::personal_owner_grant(),
        ),
    ] {
        for (named, approval) in [("approval", true), ("question", false)] {
            let proposal = naming(&plain, approval);
            let refused = calls::request(
                environment,
                &mut client,
                issue_subject(grant_kind, &proposal),
            )
            .await
            .expect_err("no challenge for a proposal naming a current resource");
            assert_eq!(
                refused.code,
                ErrorCode::InvalidArgument,
                "{grant_kind:?} {named}"
            );
            assert!(
                refused.message.contains(named) && refused.message.contains("preview"),
                "the refusal says why: {}",
                refused.message
            );
            assert!(
                calls::pending(&mut client)
                    .await
                    .expect("readable")
                    .pending
                    .is_empty(),
                "no challenge exists for it"
            );
            assert_eq!(
                code(
                    calls::mutate::<_, PairInviteResult>(
                        environment,
                        &mut client,
                        Method::PairInvite,
                        &invite_params(grant_kind, &proposal),
                    )
                    .await
                ),
                ErrorCode::OwnerConfirmationRequired,
                "pair.invite issues nothing for it ({grant_kind:?} {named})"
            );
        }
        let invited = calls::invite_direct(environment, &mut client, grant_kind, &plain, &owner)
            .await
            .expect("the same proposal without the name is issued");
        calls::cancel(environment, &mut client, invited.invitation_id, false)
            .await
            .expect("withdrawn");
    }
    host.stop().await;
}
