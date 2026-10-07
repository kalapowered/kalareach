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
    ConfirmationDisplay, ConfirmationSubject, DescribedAction, HostClockEstablishParams,
    HostClockEstablishResult, OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationPendingParams, OwnerConfirmationPendingResult, OwnerConfirmationRequestParams,
    OwnerConfirmationRequestResult,
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

/// KR-REQ-10.53, KR-REQ-10.05, KR-REQ-09.19: the terminal bootstrap establishes the first owner and
/// the host's clock, and confirms nothing else. A session invitation and a described action each
/// refuse a terminal proof on a host with no owner, and so does a terminal proof that does not
/// present the key it was signed with. Without any confirmation, a host with no owner issues
/// nothing. The clock is the other thing the terminal confirms: the owner of a host that has paired
/// no device establishes its clock at its own terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bootstrap_confirms_the_first_owner_and_the_clock_and_nothing_else() {
    let host = Host::start_unowned().await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let ceremony = keys();
    let bootstrap = Signer::Bootstrap(&ceremony.authorisation);

    for subject in [
        issue_subject(InviteGrantKind::SessionInvitation, &viewer()),
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
    assert_eq!(
        code(calls::establish_clock(environment, &mut client).await),
        ErrorCode::OwnerConfirmationRequired,
        "nor of the clock"
    );

    // The clock is the other thing the terminal confirms.
    let challenge = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::EstablishClock,
    )
    .await
    .expect("a challenge for the clock");
    assert!(challenge.initial_bootstrap);
    let (proof, presented) = calls::sign(&challenge.request, &bootstrap);
    assert_eq!(
        calls::complete(environment, &mut client, proof, presented)
            .await
            .expect("the terminal answers for the clock")
            .channel,
        ConfirmationChannel::LocalBootstrapTerminal
    );
    let established = calls::establish_clock(environment, &mut client)
        .await
        .expect("the owner at the terminal establishes the clock");
    assert_eq!(
        established.confirmation_id,
        challenge.request.confirmation_id
    );
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(established.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert_eq!(acceptance.channel, "local_bootstrap_terminal");
    assert!(acceptance.consumed_at_ms.is_some());
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
    assert_eq!(
        code(calls::establish_clock(environment, &mut client).await),
        ErrorCode::OwnerConfirmationRequired
    );
    calls::confirm_subject(
        environment,
        &mut client,
        ConfirmationSubject::EstablishClock,
        &owner,
    )
    .await
    .expect("answered for the clock");
    calls::establish_clock(environment, &mut client)
        .await
        .expect("the clock is established");
    assert_eq!(
        code(calls::establish_clock(environment, &mut client).await),
        ErrorCode::OwnerConfirmationRequired,
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

/// Spends a confirmation of the clock over a paired device's own connection, under `action` and
/// the action window the request was first sent with, which is how a device presents it again.
async fn spend_clock(
    raw: &RawDevice,
    window: &kr_protocol::ids::ActionWindowId,
    action: ActionId,
    target: &ActionTarget,
) -> Result<HostClockEstablishResult, ProtocolError> {
    Ok(raw
        .mutate_in(
            window.clone(),
            Method::HostClockEstablish,
            action,
            target.clone(),
            &HostClockEstablishParams {},
        )
        .await?
        .to_typed::<HostClockEstablishResult>()
        .expect("decodes"))
}

/// KR-REQ-09.19, KR-REQ-10.52, KR-REQ-10.53: once a host has an owner, only an owner device
/// confirms its clock. The terminal proof is refused, and so is the effect with no confirmation; a
/// paired device that is not an owner device can neither ask for the confirmation nor spend one;
/// the owner device answers the local owner's challenge, which the local owner then spends once;
/// and an owner device runs the whole of it itself over its own connection, where a retry of the
/// effect, on that connection and on a new one, is answered from its record and not performed
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn once_a_host_has_an_owner_only_an_owner_device_confirms_its_clock() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let target = ActionTarget::environment(environment);
    let mut client = host.client().await;
    let owner_record = host.owner.clone().expect("the owner device");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let raw = RawDevice::connect(&host, owner_device, &owner_record).await;
    let ceremony = keys();

    // The local owner asks, and the terminal is not who confirms it any more.
    let challenge = calls::request(
        environment,
        &mut client,
        ConfirmationSubject::EstablishClock,
    )
    .await
    .expect("the local owner asks");
    assert!(!challenge.initial_bootstrap);
    let (proof, presented) = calls::sign(
        &challenge.request,
        &Signer::Bootstrap(&ceremony.authorisation),
    );
    assert_eq!(
        code(calls::complete(environment, &mut client, proof, presented).await),
        ErrorCode::OwnerConfirmationRequired
    );
    assert_eq!(
        code(calls::establish_clock(environment, &mut client).await),
        ErrorCode::OwnerConfirmationRequired,
        "a challenge nobody answered spends nothing"
    );

    // A paired device that is not an owner device asks for nothing and spends nothing.
    let viewer_device = Device::with_keys(keys()).await;
    let viewer_record = pair_with(&host, &viewer_device, &owner_keys, viewer()).await;
    let viewer_raw = RawDevice::connect(&host, &viewer_device, &viewer_record).await;
    assert_eq!(
        code(
            viewer_raw
                .mutate(
                    Method::OwnerConfirmationRequest,
                    ActionId::new(kr_ipc::new_uuid()),
                    target.clone(),
                    &OwnerConfirmationRequestParams {
                        subject: ConfirmationSubject::EstablishClock,
                    },
                )
                .await
        ),
        ErrorCode::PermissionDenied
    );

    // The owner device answers the local owner's challenge, and the local owner spends it once.
    let (proof, _) = calls::sign(&challenge.request, &Signer::OwnerDevice(&owner_keys));
    raw.mutate(
        Method::OwnerConfirmationComplete,
        ActionId::new(kr_ipc::new_uuid()),
        target.clone(),
        &OwnerConfirmationCompleteParams {
            proof,
            bootstrap_signer: Nullable::null(),
        },
    )
    .await
    .expect("the owner device answers from its own connection");
    // With an answered confirmation waiting, a device that is not an owner device still cannot
    // spend it, and it is still there for the local owner.
    assert_eq!(
        code(
            viewer_raw
                .mutate(
                    Method::HostClockEstablish,
                    ActionId::new(kr_ipc::new_uuid()),
                    target.clone(),
                    &HostClockEstablishParams {},
                )
                .await
        ),
        ErrorCode::PermissionDenied
    );
    let established = calls::establish_clock(environment, &mut client)
        .await
        .expect("the local owner spends the owner device's confirmation");
    assert_eq!(
        established.confirmation_id,
        challenge.request.confirmation_id
    );
    let acceptance = host
        .network()
        .pairing()
        .rows()
        .acceptance(established.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert_eq!(acceptance.channel, "owner_device_presence");
    assert_eq!(
        code(calls::establish_clock(environment, &mut client).await),
        ErrorCode::OwnerConfirmationRequired,
        "spent once"
    );

    // An owner device does all of it over its own connection.
    let asked = raw
        .mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::EstablishClock,
            },
        )
        .await
        .expect("the owner device asks")
        .to_typed::<OwnerConfirmationRequestResult>()
        .expect("decodes");
    let (proof, _) = calls::sign(&asked.request, &Signer::OwnerDevice(&owner_keys));
    raw.mutate(
        Method::OwnerConfirmationComplete,
        ActionId::new(kr_ipc::new_uuid()),
        target.clone(),
        &OwnerConfirmationCompleteParams {
            proof,
            bootstrap_signer: Nullable::null(),
        },
    )
    .await
    .expect("the owner device answers");
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = raw.action_window_id();
    let first = spend_clock(&raw, &window, action, &target)
        .await
        .expect("the owner device establishes the clock");
    assert_eq!(first.confirmation_id, asked.request.confirmation_id);
    assert_eq!(
        spend_clock(&raw, &window, action, &target)
            .await
            .expect("answered from the record"),
        first
    );
    let reconnected = RawDevice::connect(&host, owner_device, &owner_record).await;
    assert_eq!(
        spend_clock(&reconnected, &window, action, &target)
            .await
            .expect("answered from the record on a new connection"),
        first
    );
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

/// A new candidate's first redemption step for `invitation_id`, dialled at this host as it runs
/// now, and the host's refusal of it.
async fn refused_challenge(
    host: &Host,
    candidate: &Device,
    invitation_id: kr_protocol::ids::InvitationId,
) -> ProtocolError {
    use kr_protocol::preauth::{PairRedeemParams, PairRedeemResult};

    let candidate = candidate.candidate();
    let mut addr = iroh::EndpointAddr::new(
        iroh::PublicKey::from_bytes(host.network().endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    );
    for socket in host.network().bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    let connection = candidate
        .endpoint
        .connect(addr, kr_protocol::hello::ALPN)
        .await
        .expect("the candidate reaches the host");
    let mut unpaired = kr_transport::handshake::connect_unpaired(&connection, candidate.identity)
        .await
        .expect("an unpaired connection");
    let answer = unpaired
        .call::<_, PairRedeemResult>(
            Method::PairRedeem,
            &PairRedeemParams::Challenge { invitation_id },
        )
        .await;
    connection.close(0u32.into(), b"refused");
    match answer {
        Err(kr_transport::error::TransportError::Refused(error)) => error,
        other => panic!("the host refuses the invitation, not {other:?}"),
    }
}

/// A new candidate's proof that it holds the invitation `open`, sent naming `named` instead, and
/// the host's refusal of it.
///
/// The proof is a real one for the invitation the host is offering, so the only thing wrong with
/// it is the invitation it names: what the host answers is its answer about that one.
async fn refused_direct_proof(
    host: &Host,
    candidate: &Device,
    open: &PairInviteResult,
    named: kr_protocol::ids::InvitationId,
) -> ProtocolError {
    use kr_protocol::preauth::{PairRedeemParams, PairRedeemResult};

    let candidate = candidate.candidate();
    let payload = calls::direct_payload(open);
    let connection = candidate
        .endpoint
        .connect(calls::host_addr(&payload), kr_protocol::hello::ALPN)
        .await
        .expect("the candidate reaches the host");
    let mut unpaired = kr_transport::handshake::connect_unpaired(&connection, candidate.identity)
        .await
        .expect("an unpaired connection");
    let PairRedeemResult::Challenge(challenge) = unpaired
        .call::<_, PairRedeemResult>(
            Method::PairRedeem,
            &PairRedeemParams::Challenge {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("the host issues a challenge for the invitation it offers")
    else {
        panic!("the first redemption step answers with a challenge");
    };
    let live_host = calls::HostPeer(*challenge.endpoint_id.as_bytes());
    let (mut proof, _transcript) = kr_pairing::direct::redeem_proof(
        &payload,
        &challenge,
        &candidate.keys.authorisation,
        &candidate.declared,
        &live_host,
    )
    .expect("a redemption proof");
    proof.invitation_id = named;
    let answer = unpaired
        .call::<_, PairRedeemResult>(
            Method::PairRedeem,
            &PairRedeemParams::Direct(Box::new(proof)),
        )
        .await;
    connection.close(0u32.into(), b"refused");
    let _ = host;
    match answer {
        Err(kr_transport::error::TransportError::Refused(error)) => error,
        other => panic!("the host refuses the proof, not {other:?}"),
    }
}

/// KR-ACC-015: a consumed invitation stays consumed across a host restart. A direct invitation
/// redeemed and committed before the restart is still committed after it, and the device it
/// paired is still paired; one left open is consumed by the restart itself. A candidate that
/// presents either to the restarted host is refused and pairs nothing, and the restarted host
/// issues a new invitation as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_consumed_invitation_stays_consumed_across_a_host_restart() {
    let owner_keys = keys();
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let owner = Signer::OwnerDevice(&owner_keys);
    let mut client = host.client().await;
    let committed = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("an invitation");
    let device = Device::create().await;
    let (connection, _candidate, _value) = calls::redeem(&device.candidate(), &committed).await;
    let confirmed =
        calls::confirm_candidate(environment, &mut client, committed.invitation_id, &owner)
            .await
            .expect("committed");
    connection.close(0u32.into(), b"paired");
    let open = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("an invitation left open");
    drop(client);

    let host = host.restart().await;
    let mut client = host.client().await;
    let status = calls::owner_status(&mut client, committed.invitation_id)
        .await
        .expect("the owner's view after the restart");
    assert!(
        matches!(
            status.status,
            PairStatus::Committed { device_id, .. } if device_id == confirmed.device_id
        ),
        "{:?}",
        status.status
    );
    assert!(
        host.network()
            .devices()
            .record_for_device(confirmed.device_id)
            .expect("the registry reads")
            .expect("the device's record")
            .is_paired()
    );
    let status = calls::owner_status(&mut client, open.invitation_id)
        .await
        .expect("the owner's view after the restart");
    assert_eq!(
        status.status,
        PairStatus::Consumed {
            reason: PairingConsumedReason::HostRestarted
        }
    );

    for invitation_id in [committed.invitation_id, open.invitation_id] {
        let stranger = Device::create().await;
        let refused = refused_challenge(&host, &stranger, invitation_id).await;
        // A reused invitation, and one the restart consumed, each return the specific rejection.
        assert_eq!(refused.code, ErrorCode::PairingRejected, "{refused:?}");
        assert!(
            host.network()
                .devices()
                .record_for_endpoint(stranger.keys().transport.public())
                .expect("the registry reads")
                .is_none(),
            "a candidate presenting a consumed invitation pairs nothing"
        );
    }
    // An invitation this host never issued is not one it is offering, and that is all it says: the
    // specific rejections are for invitations it knows the end of.
    let never_issued =
        kr_protocol::ids::InvitationId::new(kr_protocol::scalars::Uuid::from_bytes([0xee; 16]));
    let refused = refused_challenge(&host, &Device::create().await, never_issued).await;
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let current = calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &viewer(),
        &owner,
    )
    .await
    .expect("the restarted host issues a new invitation");
    // With that one open, an old invitation named by either step is still refused for what became
    // of it, and one never issued is still only one the host is not offering: the invitation the
    // host is offering now does not decide what a candidate that names another is told.
    for invitation_id in [committed.invitation_id, open.invitation_id] {
        let refused = refused_challenge(&host, &Device::create().await, invitation_id).await;
        assert_eq!(refused.code, ErrorCode::PairingRejected, "{refused:?}");
        let refused =
            refused_direct_proof(&host, &Device::create().await, &current, invitation_id).await;
        assert_eq!(refused.code, ErrorCode::PairingRejected, "{refused:?}");
    }
    let refused = refused_challenge(&host, &Device::create().await, never_issued).await;
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let refused =
        refused_direct_proof(&host, &Device::create().await, &current, never_issued).await;
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    host.stop().await;
}

// ---------------------------------------------------------------------------------------------
// A terminal's catalogue decisions, confirmed on an owner device
// ---------------------------------------------------------------------------------------------

/// KR-REQ-07.47, KR-REQ-10.05: what a terminal asks of the catalogue (adopting a repository's root,
/// an installation that needs the owner) is confirmed on an owner device and spent from the answer
/// that device recorded. The terminal asks the host for the challenge by naming the exact request,
/// an owner device answers it, and the request, repeated with no proof, spends that one answer.
mod terminal_catalogue {
    use super::*;

    use base64::Engine as _;
    use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
    use kr_protocol::catalogue as wire;
    use kr_protocol::confirmation::NATIVE_BRIDGE_NOTICE;
    use kr_protocol::confirmation::{CatalogueTrustPlan, PluginInstallPlan};
    use kr_protocol::ids::PluginId;

    /// The owner's own client on the daemon's socket, asking for one thing with no proof.
    type Client = kr_ipc::client::LocalClient;

    /// The release the bridge fixture publishes with a native bridge recipe, and the capabilities
    /// it is installed with.
    const BRIDGE_GRANT: [&str; 4] = [
        "approval.decode",
        "approval.respond",
        "native_bridge.install",
        "upstream.action",
    ];

    /// A copy of a published generation, on the internal disk.
    struct Published {
        _temp: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    impl Published {
        fn of(source: &std::path::Path) -> Self {
            let temp = tempfile::tempdir().expect("a temporary directory on the internal disk");
            let root = temp.path().join("generation");
            copy_tree(source, &root);
            Self { _temp: temp, root }
        }

        fn development() -> Self {
            Self::of(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/plugins/catalogue/development"),
            )
        }

        fn with_bridge() -> Self {
            Self::of(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/bridge-generation"),
            )
        }

        fn url(&self, directory: &str) -> String {
            url::Url::from_directory_path(
                std::fs::canonicalize(self.root.join(directory)).expect("a directory"),
            )
            .expect("an absolute path")
            .to_string()
        }

        fn index(&self) -> serde_json::Value {
            serde_json::from_slice(
                &std::fs::read(self.root.join("targets/index.json")).expect("an index"),
            )
            .expect("a readable index")
        }

        fn manifest_digest(&self, plugin: &str, version: &str) -> String {
            self.index()["entries"]
                .as_array()
                .expect("entries")
                .iter()
                .find(|entry| entry["plugin_id"] == plugin && entry["version"] == version)
                .expect("the release")["manifest_digest"]
                .as_str()
                .expect("a digest")
                .to_owned()
        }

        /// What the release's own manifest says its native bridge does.
        fn statement(&self, plugin: &str, version: &str) -> String {
            let name = plugin.split('/').nth(1).expect("a name");
            let manifest: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    self.root
                        .join("targets/packages/kalareach")
                        .join(name)
                        .join(version)
                        .join("plugin.json"),
                )
                .expect("a manifest"),
            )
            .expect("a manifest");
            manifest["native_bridge"]["grant_statement"]
                .as_str()
                .expect("a statement")
                .to_owned()
        }
    }

    fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).expect("a destination");
        let mut stack = vec![from.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).expect("readable").flatten() {
                let source = entry.path();
                if source.is_dir() {
                    stack.push(source);
                    continue;
                }
                let destination = to.join(source.strip_prefix(from).expect("inside"));
                std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
                std::fs::copy(&source, &destination).expect("copyable");
            }
        }
    }

    fn budgets() -> wire::CatalogueBudgets {
        let defaults = kr_plugin_sdk::limits::RepositoryBudgets::defaults();
        wire::CatalogueBudgets {
            metadata_bytes: defaults.metadata_bytes,
            metadata_entries: defaults.metadata_entries,
            retained_generations: defaults.retained_generations,
            retained_metadata_bytes: defaults.retained_metadata_bytes,
            payload_cache_bytes: defaults.payload_cache_bytes,
            full_offline_mirror: false,
        }
    }

    /// The request a terminal sends for a repository, with no proof.
    fn add(
        host: &Host,
        published: &Published,
        catalogue_id: &str,
        ceiling: &[&str],
    ) -> wire::CatalogueAddParams {
        wire::CatalogueAddParams {
            environment_id: host.environment_id,
            catalogue_id: catalogue_id.to_owned(),
            kind: wire::CatalogueKind::Local,
            metadata_url: published.url("metadata"),
            targets_url: published.url("targets"),
            root: base64::engine::general_purpose::STANDARD
                .encode(std::fs::read(published.root.join("root.json")).expect("a root")),
            budgets: budgets(),
            ceiling: ceiling.iter().map(|word| (*word).to_owned()).collect(),
            owner_confirmation: Nullable::null(),
        }
    }

    /// What the host's challenge for `params` has to be: the digest of the plan the effect builds
    /// from the same request.
    fn trust_digest(params: &wire::CatalogueAddParams) -> Digest256 {
        let root = base64::engine::general_purpose::STANDARD
            .decode(&params.root)
            .expect("a root");
        let enrolment = Enrolment::new(
            RepositoryId::new(&params.catalogue_id).expect("an identifier"),
            RepositoryKind::Local,
            url::Url::parse(&params.metadata_url).expect("a location"),
            url::Url::parse(&params.targets_url).expect("a location"),
            root,
            kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .expect("an enrolment");
        CatalogueTrustPlan::of_request(
            params,
            enrolment.root_digest().to_string(),
            enrolment
                .root_key_ids()
                .expect("a readable root")
                .into_iter()
                .collect(),
        )
        .action_digest()
        .expect("a digest")
    }

    fn effect(
        environment: kr_protocol::ids::EnvironmentId,
        client: &mut Client,
        params: &wire::CatalogueAddParams,
    ) -> impl std::future::Future<Output = Result<wire::CatalogueAddResult, ProtocolError>> {
        calls::mutate(environment, client, Method::CatalogueAdd, params)
    }

    async fn installed(
        environment: kr_protocol::ids::EnvironmentId,
        client: &mut Client,
        install: &wire::PluginInstallParams,
    ) -> Result<wire::PluginInstallResult, ProtocolError> {
        calls::mutate(environment, client, Method::PluginInstall, install).await
    }

    async fn listed(
        environment: kr_protocol::ids::EnvironmentId,
        client: &mut Client,
    ) -> Vec<String> {
        let listed: wire::CatalogueListResult = calls::read(
            client,
            Method::CatalogueList,
            &wire::CatalogueListParams {
                environment_id: environment,
            },
        )
        .await
        .expect("catalogue.list answers");
        listed
            .catalogues
            .into_iter()
            .map(|catalogue| catalogue.catalogue_id)
            .collect()
    }

    /// KR-REQ-07.47: `catalogue.add` with no proof spends, once, the answer an owner device
    /// recorded to the challenge the host issued for exactly this request. The challenge is the
    /// plan's own digest, an owner device is shown the repository, its root and its ceiling, a
    /// request nobody has answered adopts nothing, and a second request needs a new answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_recorded_owner_answer_lets_catalogue_add_enrol_a_repository_once() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::development();
        let params = add(&host, &published, "development", &[]);

        // Control: nothing was answered, so nothing is adopted.
        let refused = effect(environment, &mut client, &params).await;
        assert_eq!(
            code(refused),
            ErrorCode::OwnerConfirmationRequired,
            "no answer, no enrolment"
        );
        assert!(listed(environment, &mut client).await.is_empty());

        let challenge = calls::request(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
        )
        .await
        .expect("the host describes the request");
        assert_eq!(
            challenge.request.action,
            SensitiveAction::TrustRepositoryRoot
        );
        assert_eq!(
            challenge.request.action_digest,
            trust_digest(&params),
            "the challenge is the digest of the plan the effect builds from the same request"
        );
        let shown = calls::pending(&mut client)
            .await
            .expect("readable")
            .pending
            .into_iter()
            .find(|pending| pending.request == challenge.request)
            .expect("the challenge is listed");
        match &shown.display {
            ConfirmationDisplay::CatalogueAdd {
                catalogue_id,
                metadata_url,
                targets_url,
                root_digest,
                root_key_ids,
                ceiling,
                ..
            } => {
                assert_eq!(catalogue_id, "development");
                assert_eq!(metadata_url, &params.metadata_url);
                assert_eq!(targets_url, &params.targets_url);
                assert_eq!(
                    root_digest.len(),
                    64,
                    "the digest of the root: {root_digest}"
                );
                assert!(!root_key_ids.is_empty(), "the keys the owner is trusting");
                assert!(ceiling.is_empty());
            }
            other => panic!("an owner device is shown the repository, not {other:?}"),
        }

        // A device that has not answered yet.
        assert_eq!(
            code(effect(environment, &mut client, &params).await),
            ErrorCode::OwnerConfirmationRequired
        );
        assert!(listed(environment, &mut client).await.is_empty());

        let (proof, presented) = calls::sign(&challenge.request, &Signer::OwnerDevice(&owner));
        calls::complete(environment, &mut client, proof, presented)
            .await
            .expect("the owner device answers");
        let added = effect(environment, &mut client, &params)
            .await
            .expect("the answer is spent");
        assert_eq!(added.catalogue.catalogue_id, "development");
        assert_eq!(listed(environment, &mut client).await, ["development"]);

        // Spent once: the repository removed, the same request needs a new answer.
        let _: wire::CatalogueRemoveResult = calls::mutate(
            environment,
            &mut client,
            Method::CatalogueRemove,
            &wire::CatalogueRemoveParams {
                environment_id: environment,
                catalogue_id: "development".to_owned(),
            },
        )
        .await
        .expect("removed");
        assert_eq!(
            code(effect(environment, &mut client, &params).await),
            ErrorCode::OwnerConfirmationRequired,
            "the first answer is spent"
        );
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered again");
        effect(environment, &mut client, &params)
            .await
            .expect("the new answer is spent");
        host.stop().await;
    }

    /// KR-REQ-10.05: an answer for another repository name, root, ceiling, location, kind or
    /// budget is never spent on this request, and the request is refused as needing
    /// confirmation. What an owner device is shown of an enrolment is what the answer covers, so
    /// the same root served from another location is another enrolment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_answer_for_another_enrolment_is_never_spent_on_this_one() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let development = Published::development();
        let bridge = Published::with_bridge();
        let moved = Published::development();
        let asked = add(&host, &development, "development", &[]);
        let mut another_kind = asked.clone();
        another_kind.kind = wire::CatalogueKind::Community;
        let mut another_budget = asked.clone();
        another_budget.budgets.payload_cache_bytes =
            kr_protocol::scalars::U64::new(asked.budgets.payload_cache_bytes.get() - 1);

        for other in [
            add(&host, &development, "elsewhere", &[]),
            add(&host, &development, "development", &["terminal.stream"]),
            add(&host, &bridge, "development", &[]),
            add(&host, &moved, "development", &[]),
            another_kind,
            another_budget,
        ] {
            calls::confirm_subject(
                environment,
                &mut client,
                ConfirmationSubject::CatalogueAdd(Box::new(other)),
                &Signer::OwnerDevice(&owner),
            )
            .await
            .expect("an owner device answers another enrolment");
        }
        assert_eq!(
            code(effect(environment, &mut client, &asked).await),
            ErrorCode::OwnerConfirmationRequired
        );
        assert!(listed(environment, &mut client).await.is_empty());

        // Control: the answer for this very request is spent.
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(asked.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered");
        effect(environment, &mut client, &asked)
            .await
            .expect("spent");
        host.stop().await;
    }

    /// KR-REQ-10.05: an answer whose signer lost its authority before the spend is passed over, and
    /// the request is refused until an owner device that still holds it answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_answer_whose_signer_was_revoked_is_passed_over() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::development();
        let params = add(&host, &published, "development", &[]);

        // A second owner device answers, and is revoked before the request spends it.
        let second_keys = keys();
        let second = Device::with_keys(second_keys.clone()).await;
        let record = pair_with(&host, &second, &owner, proposal(&[ActionRight::HostManage])).await;
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&second_keys),
        )
        .await
        .expect("the second owner device answers while it is paired");
        let _: kr_protocol::sharing::RevocationResult = calls::mutate(
            environment,
            &mut client,
            Method::DeviceRevoke,
            &DeviceRevokeParams {
                device_id: record.device_id,
            },
        )
        .await
        .expect("revoked");
        // The revocation withdrew the authority this connection was admitted under.
        let mut client = host.client().await;
        assert_eq!(
            code(effect(environment, &mut client, &params).await),
            ErrorCode::OwnerConfirmationRequired,
            "an answer given under authority this host no longer holds is not spent"
        );
        assert!(listed(environment, &mut client).await.is_empty());

        // Control: the first owner device, which still holds it.
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered");
        effect(environment, &mut client, &params)
            .await
            .expect("spent");
        host.stop().await;
    }

    /// KR-REQ-10.05, KR-REQ-11.42: an answer to a challenge a caller described, even one whose
    /// digest is exactly a catalogue plan's digest, is not spent by a request that carries no
    /// proof: what the owner device was shown for it was the caller's description and not the
    /// repository, the grant or the publisher's statement, so only a challenge the host described
    /// from the request itself is spent. The control is the host's own challenge for the same
    /// request, which is spent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_answer_to_a_described_challenge_is_never_spent_without_a_proof() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::with_bridge();
        let described = |action, digest| {
            ConfirmationSubject::Described(kr_protocol::confirmation::DescribedAction {
                action,
                action_digest: digest,
                destination_keys: Nullable::null(),
                destination_rights: CanonicalSet::new(),
            })
        };

        // A repository's root: a described challenge with exactly the trust plan's digest.
        let params = add(&host, &published, "bridge", &[]);
        calls::confirm_subject(
            environment,
            &mut client,
            described(SensitiveAction::TrustRepositoryRoot, trust_digest(&params)),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("an owner device answers what a caller described");
        assert_eq!(
            code(effect(environment, &mut client, &params).await),
            ErrorCode::OwnerConfirmationRequired,
            "the description of a root is not the host's description of this repository"
        );
        assert!(listed(environment, &mut client).await.is_empty());
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered");
        effect(environment, &mut client, &params)
            .await
            .expect("the host's own challenge is spent");
        let _: wire::CatalogueSyncResult = calls::mutate(
            environment,
            &mut client,
            Method::CatalogueSync,
            &wire::CatalogueSyncParams {
                environment_id: environment,
                catalogue_id: "bridge".to_owned(),
            },
        )
        .await
        .expect("synchronised");

        // An installation: a described challenge with exactly the installation plan's digest.
        let plugin = "kalareach/claude-code";
        let install = wire::PluginInstallParams {
            environment_id: environment,
            catalogue_id: "bridge".to_owned(),
            plugin_id: PluginId::new(plugin).expect("a plugin id"),
            version: "0.3.0".to_owned(),
            package_digest: published.manifest_digest(plugin, "0.3.0"),
            grant: BRIDGE_GRANT.iter().map(|word| (*word).to_owned()).collect(),
            owner_confirmation: Nullable::null(),
        };
        let ceiling = {
            let listed: wire::CatalogueListResult = calls::read(
                &mut client,
                Method::CatalogueList,
                &wire::CatalogueListParams {
                    environment_id: environment,
                },
            )
            .await
            .expect("listed");
            listed.catalogues[0].ceiling.clone()
        };
        let digest = PluginInstallPlan {
            environment_id: environment,
            catalogue_id: "bridge".to_owned(),
            ceiling: ceiling.iter().cloned().collect(),
            plugin_id: install.plugin_id.clone(),
            version: "0.3.0".to_owned(),
            package_digest: install.package_digest.clone(),
            grant: install.grant.iter().cloned().collect(),
            grant_statement: Some(published.statement(plugin, "0.3.0")),
        }
        .action_digest()
        .expect("a digest");
        calls::confirm_subject(
            environment,
            &mut client,
            described(SensitiveAction::GrantExecutableCapability, digest),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("an owner device answers what a caller described");
        assert_eq!(
            code(installed(environment, &mut client, &install).await),
            ErrorCode::OwnerConfirmationRequired,
            "the description of an installation is not the host's description of this release"
        );
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::PluginInstall(Box::new(install.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered");
        installed(environment, &mut client, &install)
            .await
            .expect("the host's own challenge is spent");
        host.stop().await;
    }

    /// KR-REQ-10.05: an answer whose signer lost its authority is passed over in favour of a
    /// newer answer from an owner device that still holds it, on the first request: the older
    /// answer is not the one the request is refused for. The signer is checked when the answer is
    /// chosen and not only when the choice is recorded, so the live answer is never lost to a
    /// request that chose the revoked one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_newer_answer_from_a_live_owner_is_spent_when_an_older_signer_was_revoked() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::development();
        let params = add(&host, &published, "development", &[]);

        let second_keys = keys();
        let second = Device::with_keys(second_keys.clone()).await;
        let record = pair_with(&host, &second, &owner, proposal(&[ActionRight::HostManage])).await;
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&second_keys),
        )
        .await
        .expect("the second owner device answers while it is paired");
        let _: kr_protocol::sharing::RevocationResult = calls::mutate(
            environment,
            &mut client,
            Method::DeviceRevoke,
            &DeviceRevokeParams {
                device_id: record.device_id,
            },
        )
        .await
        .expect("revoked");
        let mut client = host.client().await;
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("the first owner device answers after it");

        // Both answers wait, the older one under authority this host no longer holds. The one
        // request is spent from the newer.
        let added = effect(environment, &mut client, &params)
            .await
            .expect("the live owner's answer is the one spent");
        assert_eq!(added.catalogue.catalogue_id, "development");
        host.stop().await;
    }

    /// KR-REQ-10.05: a paired device that is not the owner is refused before the catalogue
    /// resolves anything for a subject it names. What resolving refuses with names the repository,
    /// the release and the host's budgets, and a device without owner authority learns none of it:
    /// an unknown repository, an unreadable root and a release no index holds all answer
    /// `PERMISSION_DENIED`. The control is the owner's own request for the same subjects, which is
    /// refused for what is wrong with each.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_device_without_owner_authority_learns_nothing_from_a_subject_it_names() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let viewer_keys = keys();
        let viewer_device = Device::with_keys(viewer_keys.clone()).await;
        let viewer_record = pair_with(&host, &viewer_device, &owner, viewer()).await;
        let viewer_raw = RawDevice::connect(&host, &viewer_device, &viewer_record).await;

        let published = Published::development();
        let mut unreadable = add(&host, &published, "development", &[]);
        unreadable.root = "bm90IGEgcm9vdA==".to_owned();
        let install = wire::PluginInstallParams {
            environment_id: environment,
            catalogue_id: "nowhere".to_owned(),
            plugin_id: PluginId::new("kalareach/claude-code").expect("a plugin id"),
            version: "0.3.0".to_owned(),
            package_digest: "0".repeat(64),
            grant: Vec::new(),
            owner_confirmation: Nullable::null(),
        };
        for subject in [
            ConfirmationSubject::CatalogueAdd(Box::new(unreadable)),
            ConfirmationSubject::PluginInstall(Box::new(install)),
        ] {
            let asked = viewer_raw
                .mutate(
                    Method::OwnerConfirmationRequest,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment),
                    &OwnerConfirmationRequestParams {
                        subject: subject.clone(),
                    },
                )
                .await;
            assert_eq!(
                code(asked),
                ErrorCode::PermissionDenied,
                "a device that is not the owner is refused first: {subject:?}"
            );
            let owned = calls::request(environment, &mut client, subject.clone()).await;
            assert_ne!(
                code(owned),
                ErrorCode::PermissionDenied,
                "the owner is refused for what is wrong with the request: {subject:?}"
            );
        }
        host.stop().await;
    }

    /// The request a subject names carries no proof of its own: a request that already carries
    /// one is not a thing to ask a confirmation for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_subject_names_a_request_without_its_proof() {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::development();
        let mut params = add(&host, &published, "development", &[]);
        let proof = {
            let challenge = calls::request(
                environment,
                &mut client,
                ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            )
            .await
            .expect("a challenge");
            calls::sign(&challenge.request, &Signer::OwnerDevice(&owner)).0
        };
        params.owner_confirmation = Nullable::some(proof);
        let refused = calls::request(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params)),
        )
        .await;
        assert_eq!(code(refused), ErrorCode::InvalidArgument);
        host.stop().await;
    }

    /// KR-REQ-11.42, KR-REQ-10.05: an installation of a release that installs a native bridge is
    /// confirmed on an owner device, shown the publisher's own statement apart from the host's
    /// notice, and spent from the recorded answer. The statement comes from the release's verified
    /// manifest and is in the digest: an answer for a plan that says another statement, or none, is
    /// not spent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_recorded_owner_answer_lets_a_native_bridge_installation_proceed_with_its_statement()
    {
        let owner = keys();
        let host = Host::start(&owner).await;
        let environment = host.environment_id;
        let mut client = host.client().await;
        let published = Published::with_bridge();
        let plugin = "kalareach/claude-code";
        let statement = published.statement(plugin, "0.3.0");

        // The repository, adopted on an owner device's answer, and synchronised.
        let params = add(&host, &published, "bridge", &[]);
        calls::confirm_subject(
            environment,
            &mut client,
            ConfirmationSubject::CatalogueAdd(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("answered");
        effect(environment, &mut client, &params)
            .await
            .expect("enrolled");
        let _: wire::CatalogueSyncResult = calls::mutate(
            environment,
            &mut client,
            Method::CatalogueSync,
            &wire::CatalogueSyncParams {
                environment_id: environment,
                catalogue_id: "bridge".to_owned(),
            },
        )
        .await
        .expect("synchronised");

        let install = wire::PluginInstallParams {
            environment_id: environment,
            catalogue_id: "bridge".to_owned(),
            plugin_id: PluginId::new(plugin).expect("a plugin id"),
            version: "0.3.0".to_owned(),
            package_digest: published.manifest_digest(plugin, "0.3.0"),
            grant: BRIDGE_GRANT.iter().map(|word| (*word).to_owned()).collect(),
            owner_confirmation: Nullable::null(),
        };

        // Control: the installation needs the owner's confirmation and has none.
        assert_eq!(
            code(installed(environment, &mut client, &install).await),
            ErrorCode::OwnerConfirmationRequired
        );

        let challenge = calls::request(
            environment,
            &mut client,
            ConfirmationSubject::PluginInstall(Box::new(install.clone())),
        )
        .await
        .expect("the host describes the installation");
        // The repository's ceiling as `catalogue.list` reports it, which is what a client knows.
        let ceiling: Vec<String> = {
            let listed: wire::CatalogueListResult = calls::read(
                &mut client,
                Method::CatalogueList,
                &wire::CatalogueListParams {
                    environment_id: environment,
                },
            )
            .await
            .expect("listed");
            listed.catalogues[0].ceiling.clone()
        };
        let plan = |grant_statement: Option<String>| PluginInstallPlan {
            environment_id: environment,
            catalogue_id: "bridge".to_owned(),
            ceiling: ceiling.iter().cloned().collect(),
            plugin_id: install.plugin_id.clone(),
            version: "0.3.0".to_owned(),
            package_digest: install.package_digest.clone(),
            grant: install.grant.iter().cloned().collect(),
            grant_statement,
        };
        let shown = calls::pending(&mut client)
            .await
            .expect("readable")
            .pending
            .into_iter()
            .find(|pending| pending.request == challenge.request)
            .expect("the challenge is listed");
        match &shown.display {
            ConfirmationDisplay::PluginInstall {
                package_digest,
                grant,
                grant_statement,
                ..
            } => {
                assert_eq!(package_digest, &install.package_digest);
                assert_eq!(grant, &install.grant);
                assert_eq!(
                    grant_statement.as_ref(),
                    Some(&statement),
                    "the publisher's words, from the release's own manifest"
                );
            }
            other => panic!("an owner device is shown the installation, not {other:?}"),
        }
        assert!(NATIVE_BRIDGE_NOTICE.contains("outside"));
        assert_eq!(
            challenge.request.action_digest,
            plan(Some(statement.clone()))
                .action_digest()
                .expect("a digest")
        );
        assert_ne!(
            challenge.request.action_digest,
            plan(None).action_digest().expect("a digest"),
            "the statement is covered"
        );
        assert_ne!(
            challenge.request.action_digest,
            plan(Some("another statement".to_owned()))
                .action_digest()
                .expect("a digest")
        );

        // Not answered yet.
        assert_eq!(
            code(installed(environment, &mut client, &install).await),
            ErrorCode::OwnerConfirmationRequired
        );
        let (proof, presented) = calls::sign(&challenge.request, &Signer::OwnerDevice(&owner));
        calls::complete(environment, &mut client, proof, presented)
            .await
            .expect("the owner device answers");
        let done = installed(environment, &mut client, &install)
            .await
            .expect("the answer is spent on the installation");
        assert_eq!(done.plugin.package_digest, install.package_digest);

        // Spent once: removed, the same request needs a new answer.
        let _: wire::PluginRemoveResult = calls::mutate(
            environment,
            &mut client,
            Method::PluginRemove,
            &wire::PluginRemoveParams {
                environment_id: environment,
                plugin_id: install.plugin_id.clone(),
            },
        )
        .await
        .expect("removed");
        assert_eq!(
            code(installed(environment, &mut client, &install).await),
            ErrorCode::OwnerConfirmationRequired
        );

        host.stop().await;
    }
}
