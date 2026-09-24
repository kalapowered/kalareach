//! Roles, invitations, delegation, transfer of control and the sharing method group.
//!
//! The thing these tests are really about is that a *word* never authorises anything. "Controller"
//! is a word; `terminal.input` is a right. An invitation issued under a role writes the rights
//! down, and every later decision reads the rights. So each test here either checks that the
//! compilation is faithful, or takes a word away and checks that the decision is unchanged.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-09.18 | `a_refusal_the_clock_decided_is_never_answered_on_a_floor_that_was_not_written`, `a_start_that_cannot_write_its_floor_decides_no_expiry_until_it_can`, `a_delegation_whose_parent_expired_before_it_was_written_is_refused`, `a_redemption_whose_invitation_expired_before_it_was_written_is_refused`, `a_transfer_whose_source_expired_before_it_was_written_is_refused` |
//! | KR-REQ-18.03 | `an_invitation_is_scoped_to_the_session_it_shares`, `a_delegation_narrows_what_the_issuer_holds`, `transfer_of_control_hands_over_only_what_the_transferring_grant_carries`, `transfer_of_control_issues_one_authority_and_revokes_the_other`, `a_transfer_whose_source_expired_before_it_was_written_is_refused` |
//! | KR-REQ-19.01 | `a_view_only_invitation_obtains_no_input_through_a_plugin_an_attachment_action_or_a_workflow` |
//! | KR-REQ-23.49 | `sharing_checks_parent_rights_expiry_and_owner_confirmation`, `revoking_a_shared_grant_completes_through_the_dispatch_barrier`, `a_delegation_whose_parent_expired_before_it_was_written_is_refused` |
//! | KR-REQ-25.07 | `each_role_compiles_to_explicit_actions_and_the_host_decides_from_those`, `only_controller_and_owner_answer_questions_without_an_explicit_option` |
//! | KR-REQ-25.10 | `an_invitation_is_single_use_and_expires`, `the_issuer_sees_what_is_being_shared_and_no_historical_attachment_keys`, `an_invitation_names_nothing_the_issuer_was_not_shown`, `a_redemption_whose_invitation_expired_before_it_was_written_is_refused` |

use std::sync::Arc;
use std::time::Duration;

use kr_controller::grants::{AccessRequest, GrantRecord, HostPolicy, Refusal, decide};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::sharing::{
    ConfirmedTransfer, Intermediary, ShareRequest, SharingService, TransferHost, TransferPlan,
    effective_rights, requires_owner_confirmation, roles, transfer,
};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::{
    AuthorityRevision, BuildId, DeviceId, EnvironmentId, GrantId, InvitationId, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Uuid};
use kr_protocol::sharing::{AuthorityNotice, RoleSelection, SessionRole};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

const NOW: u64 = 1_000_000;

fn device_id(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn session_id(byte: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([byte; 16]))
}

fn environment_id(byte: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([byte; 16]))
}

fn grant_id(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

fn invitation_id(byte: u8) -> InvitationId {
    InvitationId::new(Uuid::from_bytes([byte; 16]))
}

/// A share request for one role, with the notices that role actually carries already accepted.
fn share(role: SessionRole, byte: u8) -> ShareRequest {
    let selection = RoleSelection::plain(role);
    ShareRequest {
        invitation_id: invitation_id(byte),
        grant_id: grant_id(byte),
        environment_id: environment_id(0xe0),
        session_id: session_id(0xa0),
        issuer_device_id: device_id(0xf0),
        recipient_device_id: device_id(0xf1),
        parent_grant_id: None,
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: None,
        live_screen: None,
        named_questions: Vec::new(),
        named_approvals: Vec::new(),
        authority_revision: AuthorityRevision::new(1),
        owner_confirmed: false,
        now_ms: NOW,
    }
}

fn request(method: Method, now_ms: u64) -> AccessRequest {
    AccessRequest {
        method,
        ingress: ActorIngress::PairedDevice,
        environment_id: environment_id(0xe0),
        session_id: Some(session_id(0xa0)),
        claims_geometry: false,
        own_subject: None,
        recipient_account: None,
        now_ms,
    }
}

/// A clock for the confirmation ceremony, on this machine's real time.
#[derive(Debug)]
struct Clock;

impl kr_pairing::platform::PairingClock for Clock {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        // This machine's own boot, derived the way the daemon derives it, so evidence this helper
        // produces is evidence the daemon accepts. A fixed value would make every confirmation
        // built here look like one from another boot.
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

/// Runs the owner-confirmation ceremony for one transfer plan, for real.
///
/// The challenge is issued for this exact plan's digest, the owner's key signs it, and
/// `ConfirmedTransfer::verify` is the thing that accepts it: the test never constructs the
/// evidence, because nothing outside this crate can.
fn recipient_keys() -> kr_protocol::pairing::DevicePublicKeys {
    kr_protocol::pairing::DevicePublicKeys {
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([11; 32]),
        stored_envelope: kr_protocol::scalars::StoredEnvelopeKey::from_bytes([12; 32]),
        notification_preview: kr_protocol::scalars::NotificationPreviewKey::from_bytes([13; 32]),
        transport: kr_protocol::scalars::EndpointKey::from_bytes([14; 32]),
    }
}

fn transfer_host(keys: &kr_protocol::pairing::DevicePublicKeys) -> TransferHost<'_> {
    transfer_host_for(device_id(0xf0), keys)
}

fn transfer_host_for(
    host_device_id: DeviceId,
    keys: &kr_protocol::pairing::DevicePublicKeys,
) -> TransferHost<'_> {
    TransferHost {
        device_id: host_device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([3; 32]),
        recipient_keys: keys,
    }
}

fn confirm_transfer(
    plan: &TransferPlan,
    owner_key: &kr_crypto::keys::AuthorisationKeyPair,
) -> ConfirmedTransfer {
    confirm_transfer_for(plan, device_id(0xf0), owner_key)
}

fn confirm_transfer_for(
    plan: &TransferPlan,
    host_device_id: DeviceId,
    owner_key: &kr_crypto::keys::AuthorisationKeyPair,
) -> ConfirmedTransfer {
    let clock = Clock;
    let keys = recipient_keys();
    let host = transfer_host_for(host_device_id, &keys);
    let request = kr_pairing::confirm::request_confirmation(
        &clock,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(keys),
        plan.actions.iter().copied().collect(),
        host.device_id,
        host.endpoint_id,
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &clock);
    let proof = kr_pairing::confirm::sign_confirmation(
        owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    ConfirmedTransfer::verify(
        plan,
        &host,
        &mut ledger,
        &clock,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect("the owner confirmed this transfer")
}

/// A grant whose admission lapses while the store is waited for is not written.
///
/// The preview, the delegation checks and the wait for the store's own lock all take time. The
/// check the caller hands in runs inside the transaction that writes, so a window that shut in the
/// meantime leaves neither a grant nor an invitation behind.
#[test]
fn a_grant_that_loses_its_admission_at_the_store_writes_neither_grant_nor_invitation() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let request = share(SessionRole::Viewer, 1);

    let refused = service
        .share(&request, || {
            Err(kr_controller::error::ControllerError::WindowExpired {
                detail: "the window shut while this waited for the store".to_owned(),
            })
        })
        .expect_err("a lapsed admission writes nothing");
    assert!(
        refused.to_string().contains("window"),
        "unexpected refusal: {refused}"
    );
    assert!(
        service
            .grants()
            .record(request.grant_id)
            .expect("readable")
            .is_none(),
        "no grant"
    );
    assert!(
        service
            .grants()
            .invitation(request.invitation_id)
            .expect("readable")
            .is_none(),
        "and no invitation, because the two are one commit"
    );

    // The same request, admitted, writes both.
    service.share(&request, || Ok(())).expect("issued");
}

/// A confirmation that runs out while the store is waited for transfers nothing.
#[test]
fn a_confirmation_that_runs_out_while_the_store_is_waited_for_writes_nothing() {
    /// The clock the ceremony runs on: fixed, so the deadline this test is about is exact.
    #[derive(Debug)]
    struct Ceremony;

    const CEREMONY_MONOTONIC_MS: u64 = 5_000;
    const CEREMONY_WALL_MS: u64 = 1_000;
    const CEREMONY_BOOT: [u8; 32] = [7; 32];

    impl kr_pairing::platform::PairingClock for Ceremony {
        fn monotonic_ms(&self) -> u64 {
            CEREMONY_MONOTONIC_MS
        }

        fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
            kr_pairing::platform::BootIdentity(CEREMONY_BOOT)
        }

        fn wall_clock_ms(&self) -> u64 {
            CEREMONY_WALL_MS
        }
    }

    /// A clock that runs past the confirmation's deadline after its first reading.
    ///
    /// The transfer reads it once before it goes to the store and once inside the transaction,
    /// which is exactly the interval a wait for the store's lock occupies. Same boot as the
    /// ceremony, so what refuses the second reading is the deadline rather than the boot.
    #[derive(Debug, Default)]
    struct Slipping {
        readings: std::sync::atomic::AtomicU64,
    }

    impl kr_pairing::platform::PairingClock for Slipping {
        fn monotonic_ms(&self) -> u64 {
            let reading = self
                .readings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if reading == 0 {
                CEREMONY_MONOTONIC_MS
            } else {
                CEREMONY_MONOTONIC_MS
                    .saturating_add(kr_pairing::confirm::CONFIRMATION_LIFETIME_MS + 1)
            }
        }

        fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
            kr_pairing::platform::BootIdentity(CEREMONY_BOOT)
        }

        fn wall_clock_ms(&self) -> u64 {
            CEREMONY_WALL_MS
        }
    }

    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let owner = service
        .share(&share(SessionRole::Owner, 1), || Ok(()))
        .expect("an owner");
    service
        .redeem(owner.preview.invitation_id, device_id(0xf1), NOW + 1)
        .expect("the owner redeems it");

    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: owner.grant.grant_id,
        issuing_grant_id: grant_id(9),
        actions: transfer::transferable_actions(&owner.grant),
    };
    // The ceremony runs on the fixed clock, so the deadline the evidence carries is
    // `CEREMONY_MONOTONIC_MS + CONFIRMATION_LIFETIME_MS` and nothing about this test depends on
    // how long the machine takes to reach the next line.
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let keys = recipient_keys();
    let host = transfer_host(&keys);
    let request = kr_pairing::confirm::request_confirmation(
        &Ceremony,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(keys),
        plan.actions.iter().copied().collect(),
        host.device_id,
        host.endpoint_id,
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &Ceremony);
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    let confirmed = ConfirmedTransfer::verify(
        &plan,
        &host,
        &mut ledger,
        &Ceremony,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect("the owner confirmed this transfer");

    let clock = Slipping::default();
    let refused = service
        .transfer_control(
            &plan,
            &confirmed,
            &clock,
            AuthorityRevision::new(1),
            NOW + 2,
        )
        .expect_err("the confirmation ran out while this waited for the store");
    assert!(
        refused.to_string().contains("expired"),
        "unexpected refusal: {refused}"
    );
    assert!(
        service
            .grants()
            .record(plan.issuing_grant_id)
            .expect("readable")
            .is_none(),
        "the recipient received nothing"
    );
    let source = service
        .grants()
        .record(plan.revoking_grant_id)
        .expect("readable")
        .expect("present");
    assert!(
        source.revoked_at_ms.is_none() && source.is_active(),
        "and the transferring device kept the control it was handing over"
    );
    assert_eq!(
        clock.readings.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the confirmation was checked twice: once before the store, once where it writes"
    );
}

/// A confirmation keeps the challenge's own deadline, and dies with the boot it was accepted in.
#[test]
fn a_confirmation_keeps_its_own_deadline_and_its_own_boot() {
    /// A clock the test moves: the monotonic reading and the boot identity are both settable.
    #[derive(Debug)]
    struct Staged {
        monotonic_ms: std::sync::atomic::AtomicU64,
        wall_clock_ms: u64,
        boot: std::sync::Mutex<[u8; 32]>,
    }

    impl kr_pairing::platform::PairingClock for Staged {
        fn monotonic_ms(&self) -> u64 {
            self.monotonic_ms.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
            kr_pairing::platform::BootIdentity(
                *self.boot.lock().expect("the boot value is not poisoned"),
            )
        }

        fn wall_clock_ms(&self) -> u64 {
            self.wall_clock_ms
        }
    }

    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let keys = recipient_keys();
    let host = transfer_host(&keys);
    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: grant_id(1),
        issuing_grant_id: grant_id(9),
        actions: [ActionRight::SessionView, ActionRight::SessionShare]
            .into_iter()
            .collect(),
    };

    // The challenge is issued at wall clock 1,000 and lives two minutes. It is accepted one second
    // before it expires.
    let lifetime = kr_pairing::confirm::CONFIRMATION_LIFETIME_MS;
    let issuing = Staged {
        monotonic_ms: std::sync::atomic::AtomicU64::new(5_000),
        wall_clock_ms: 1_000,
        boot: std::sync::Mutex::new([3; 32]),
    };
    let request = kr_pairing::confirm::request_confirmation(
        &issuing,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(keys),
        plan.actions.iter().copied().collect(),
        host.device_id,
        host.endpoint_id,
    )
    .expect("a challenge");

    let accepting = Staged {
        monotonic_ms: std::sync::atomic::AtomicU64::new(5_000 + lifetime - 1_000),
        wall_clock_ms: 1_000 + lifetime - 1_000,
        boot: std::sync::Mutex::new([3; 32]),
    };
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &issuing);
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    let confirmed = ConfirmedTransfer::verify(
        &plan,
        &host,
        &mut ledger,
        &accepting,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect("accepted one second before the challenge expired");

    // One second of the challenge's own life is left, not a fresh two minutes.
    confirmed
        .covers(&plan, host.device_id, &accepting)
        .expect("still inside the challenge's own deadline");
    accepting
        .monotonic_ms
        .store(5_000 + lifetime + 1, std::sync::atomic::Ordering::SeqCst);
    let error = confirmed
        .covers(&plan, host.device_id, &accepting)
        .expect_err("the challenge's own deadline has passed");
    assert!(
        error.to_string().contains("expired"),
        "unexpected refusal: {error}"
    );

    // And a reboot ends it, whatever the monotonic reading says.
    accepting
        .monotonic_ms
        .store(5_000, std::sync::atomic::Ordering::SeqCst);
    confirmed
        .covers(&plan, host.device_id, &accepting)
        .expect("inside its deadline again");
    *accepting.boot.lock().expect("the boot value") = [4; 32];
    let error = confirmed
        .covers(&plan, host.device_id, &accepting)
        .expect_err("a confirmation does not survive a reboot");
    assert!(
        error.to_string().contains("earlier boot"),
        "unexpected refusal: {error}"
    );

    // And a wall clock that went **back** between issue and acceptance buys nothing. The deadline
    // this host enforces is the monotonic one it recorded when it issued the challenge, so a
    // second acceptance staged that way expires at the same moment as the first.
    let rolled_back = Staged {
        monotonic_ms: std::sync::atomic::AtomicU64::new(5_000 + lifetime - 1_000),
        wall_clock_ms: 1_000,
        boot: std::sync::Mutex::new([3; 32]),
    };
    let request = kr_pairing::confirm::request_confirmation(
        &issuing,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(keys),
        plan.actions.iter().copied().collect(),
        host.device_id,
        host.endpoint_id,
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &issuing);
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    let confirmed = ConfirmedTransfer::verify(
        &plan,
        &host,
        &mut ledger,
        &rolled_back,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect("accepted while the wall clock said the challenge had just been issued");
    rolled_back
        .monotonic_ms
        .store(5_000 + lifetime + 1, std::sync::atomic::Ordering::SeqCst);
    confirmed
        .covers(&plan, host.device_id, &rolled_back)
        .expect_err("a wall clock that went back does not lengthen the deadline");
}

/// A challenge answered for another host does not confirm a transfer on this one.
/// KR-REQ-02.09: changing who holds a session's host authority needs an owner confirmation bound
/// to this host.
#[test]
fn a_confirmation_issued_for_another_host_does_not_authorise_a_transfer_here() {
    let clock = Clock;
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let keys = recipient_keys();
    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: grant_id(1),
        issuing_grant_id: grant_id(9),
        actions: [ActionRight::SessionView, ActionRight::SessionShare]
            .into_iter()
            .collect(),
    };
    // The challenge names another host entirely.
    let request = kr_pairing::confirm::request_confirmation(
        &clock,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(keys),
        plan.actions.iter().copied().collect(),
        device_id(0xee),
        kr_protocol::scalars::EndpointKey::from_bytes([9; 32]),
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &clock);
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    let host = transfer_host(&keys);
    ConfirmedTransfer::verify(
        &plan,
        &host,
        &mut ledger,
        &clock,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect_err("this host builds the expectation, so another host's challenge does not answer it");

    // And a challenge that names different destination keys does not answer it either.
    let elsewhere = kr_protocol::pairing::DevicePublicKeys {
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([99; 32]),
        ..recipient_keys()
    };
    let request = kr_pairing::confirm::request_confirmation(
        &clock,
        TransferPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(elsewhere),
        plan.actions.iter().copied().collect(),
        host.device_id,
        host.endpoint_id,
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &clock);
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner_key,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    ConfirmedTransfer::verify(
        &plan,
        &host,
        &mut ledger,
        &clock,
        &request,
        &proof,
        owner_key.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect_err("the owner was shown a different device than the one this transfer hands over to");
}

/// A grant as it stands once its invitation has been redeemed.
fn stored(grant: &Grant) -> GrantRecord {
    GrantRecord {
        grant: grant.clone(),
        session_id: Some(session_id(0xa0)),
        issued_at_ms: NOW,
        activated_at_ms: Some(NOW),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-25.07: roles compile to explicit grants
// ---------------------------------------------------------------------------------------------

#[test]
fn each_role_compiles_to_explicit_actions_and_the_host_decides_from_those() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    let viewer = service
        .share(&share(SessionRole::Viewer, 1), || Ok(()))
        .expect("a viewer");
    assert_eq!(
        viewer.grant.actions.iter().copied().collect::<Vec<_>>(),
        vec![ActionRight::SessionView],
        "a viewer sees the session and nothing else"
    );

    let controller = service
        .share(
            &ShareRequest {
                recipient_device_id: device_id(0xf2),
                ..share(SessionRole::Controller, 2)
            },
            || Ok(()),
        )
        .expect("a controller");
    assert!(controller.grant.permits(ActionRight::TerminalInput));
    assert!(controller.grant.permits(ActionRight::QuestionRespond));

    // The decision reads the actions. A viewer's grant refuses input; a controller's allows it.
    assert_eq!(
        decide(
            &viewer.grant,
            &stored(&viewer.grant),
            &mut policy,
            request(Method::InputWrite, NOW)
        ),
        Err(Refusal::MissingRight {
            right: ActionRight::TerminalInput
        })
    );
    decide(
        &controller.grant,
        &stored(&controller.grant),
        &mut policy,
        request(Method::InputWrite, NOW),
    )
    .expect("a controller holds terminal input");

    // The role is not in the grant at all, so nothing downstream could authorise from it even by
    // mistake: what a person is shown beside a grant is derived from the actions, not carried.
    let encoded = serde_json::to_string(&viewer.grant).expect("a grant encodes");
    assert!(
        !encoded.contains("viewer") && !encoded.contains("role"),
        "a grant carries actions, never a role label: {encoded}"
    );
    assert_eq!(
        roles::describes(&controller.grant.actions),
        Some(SessionRole::Controller),
        "a label may be derived for display, and only for display"
    );

    // A grant whose actions were narrowed below its role no longer describes that role, so a
    // surface cannot keep calling it one.
    let narrowed: CanonicalSet<ActionRight> = [ActionRight::SessionView].into_iter().collect();
    assert_eq!(roles::describes(&narrowed), Some(SessionRole::Viewer));
}

#[test]
fn only_controller_and_owner_answer_questions_without_an_explicit_option() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    for (byte, role) in [(1_u8, SessionRole::Viewer), (2, SessionRole::Reviewer)] {
        let plain = service
            .share(
                &ShareRequest {
                    recipient_device_id: device_id(byte),
                    ..share(role, byte)
                },
                || Ok(()),
            )
            .expect("a plain invitation");
        assert!(
            !plain.grant.permits(ActionRight::QuestionRespond),
            "{role} does not answer questions by default"
        );
        assert!(
            !plain
                .preview
                .notices
                .contains(&AuthorityNotice::AgentPermissions),
            "and the issuer is not warned about a consequence the grant does not carry"
        );
    }

    for (byte, role) in [(3_u8, SessionRole::Controller), (4, SessionRole::Owner)] {
        let held = service
            .share(
                &ShareRequest {
                    recipient_device_id: device_id(byte),
                    ..share(role, byte)
                },
                || Ok(()),
            )
            .expect("an invitation");
        assert!(held.grant.permits(ActionRight::QuestionRespond));
        assert!(
            held.preview
                .notices
                .contains(&AuthorityNotice::AgentPermissions),
            "{role} carries the notice that says what an answer is"
        );
    }

    // A viewer receives it only through the explicit option, and the option carries the warning.
    let selection = RoleSelection {
        include_question_respond: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let opted = service
        .share(
            &ShareRequest {
                recipient_device_id: device_id(9),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                ..share(SessionRole::Viewer, 9)
            },
            || Ok(()),
        )
        .expect("an opted-in viewer");
    assert!(opted.grant.permits(ActionRight::QuestionRespond));
    assert!(
        opted
            .preview
            .notices
            .contains(&AuthorityNotice::AgentPermissions)
    );
    assert!(
        AuthorityNotice::AgentPermissions
            .sentence()
            .contains("not a restricted sandbox"),
        "the warning says what the upstream actually enforces"
    );
}

#[test]
fn an_issuer_that_accepted_different_consequences_does_not_get_the_grant() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    // A surface that showed a controller invitation without the account-access notice.
    let softened = ShareRequest {
        accepted_notices: CanonicalSet::from_iter([AuthorityNotice::AgentPermissions]),
        ..share(SessionRole::Controller, 1)
    };
    let error = service
        .share(&softened, || Ok(()))
        .expect_err("the grant carries a consequence the issuer was not shown");
    assert!(
        error.to_string().contains("different set of consequences"),
        "unexpected refusal: {error}"
    );
    assert!(
        service
            .grants()
            .record(grant_id(1))
            .expect("readable")
            .is_none(),
        "and nothing was written"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-25.10: single use, expiring, previewed, and no historical attachment keys
// ---------------------------------------------------------------------------------------------

#[test]
fn an_invitation_is_single_use_and_expires() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let issued = service
        .share(&share(SessionRole::Viewer, 1), || Ok(()))
        .expect("issued");
    let first = issued.preview.invitation_id;

    // Until it is redeemed the grant authorises nothing, whatever it says.
    let written = service
        .grants()
        .record(issued.grant.grant_id)
        .expect("readable")
        .expect("present");
    assert!(
        !written.is_active(),
        "a grant is a proposal until it is redeemed"
    );

    // A device the invitation was not issued to cannot redeem it.
    let error = service
        .redeem(first, device_id(0xf9), NOW + 1_000)
        .expect_err("the invitation names one device");
    assert!(
        error.to_string().contains("another device"),
        "unexpected refusal: {error}"
    );

    let activated = service
        .redeem(first, device_id(0xf1), NOW + 1_000)
        .expect("the named device redeems it");
    assert_eq!(activated.grant_id, issued.grant.grant_id);
    assert!(
        service
            .grants()
            .record(issued.grant.grant_id)
            .expect("readable")
            .expect("present")
            .is_active(),
        "redemption is what makes the grant live"
    );

    // Not even the device that redeemed it can do so twice.
    let error = service
        .redeem(first, device_id(0xf1), NOW + 1_200)
        .expect_err("single use means once");
    assert!(
        error.to_string().contains("already been redeemed"),
        "unexpected refusal: {error}"
    );

    // An invitation nobody redeemed stops working at its deadline, and its proposal with it.
    let second = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(2),
                grant_id: grant_id(2),
                recipient_device_id: device_id(0xf4),
                ..share(SessionRole::Viewer, 2)
            },
            || Ok(()),
        )
        .expect("issued");
    let expires_at = second.preview.expires_at_ms.get();
    let error = service
        .redeem(second.preview.invitation_id, device_id(0xf4), expires_at)
        .expect_err("an expired invitation is refused");
    assert!(
        error.to_string().contains("expired"),
        "unexpected refusal: {error}"
    );

    // And withdrawing an invitation withdraws the proposal it carries, rather than leaving a
    // grant somebody could still be handed.
    let third = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(3),
                grant_id: grant_id(3),
                recipient_device_id: device_id(0xf5),
                ..share(SessionRole::Viewer, 3)
            },
            || Ok(()),
        )
        .expect("issued");
    service
        .cancel(third.preview.invitation_id, NOW + 5)
        .expect("withdrawn");
    assert!(
        service
            .grants()
            .record(third.grant.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_some(),
        "a withdrawn invitation leaves no proposal behind"
    );
    service
        .redeem(third.preview.invitation_id, device_id(0xf5), NOW + 6)
        .expect_err("a withdrawn invitation activates nothing");
}

/// Transferring control issues the recipient's authority and revokes the transferring device's.
#[test]
fn transfer_of_control_issues_one_authority_and_revokes_the_other() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let owner = service
        .share(&share(SessionRole::Owner, 1), || Ok(()))
        .expect("an owner");
    service
        .redeem(owner.preview.invitation_id, device_id(0xf1), NOW + 1)
        .expect("the owner redeems it");

    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: owner.grant.grant_id,
        issuing_grant_id: grant_id(9),
        actions: transfer::transferable_actions(&owner.grant),
    };

    // A confirmation the owner gave for a *different* transfer authorises nothing. The digest
    // covers the whole plan, so changing the recipient changes it.
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let elsewhere_plan = TransferPlan {
        to_device_id: device_id(0xbb),
        ..plan.clone()
    };
    let elsewhere = confirm_transfer(&elsewhere_plan, &owner_key);
    let error = service
        .transfer_control(
            &plan,
            &elsewhere,
            &Clock,
            AuthorityRevision::new(1),
            NOW + 2,
        )
        .expect_err("a confirmation is about one exact transfer");
    assert!(
        error.to_string().contains("different transfer"),
        "unexpected refusal: {error}"
    );
    assert!(
        service
            .grants()
            .record(grant_id(9))
            .expect("readable")
            .is_none(),
        "and nothing was written"
    );

    let confirmed = confirm_transfer(&plan, &owner_key);
    let done = service
        .transfer_control(
            &plan,
            &confirmed,
            &Clock,
            AuthorityRevision::new(1),
            NOW + 2,
        )
        .expect("the owner confirmed this transfer");

    // The recipient holds active authority immediately: there is no invitation left to redeem.
    let received = service
        .grants()
        .record(done.issued.grant_id)
        .expect("readable")
        .expect("present");
    assert!(received.is_active());
    assert_eq!(received.grant.recipient_device_id, device_id(0xf2));
    assert!(received.grant.permits(ActionRight::SessionShare));

    // And the transferring device has given it up.
    assert!(
        service
            .grants()
            .record(owner.grant.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_some(),
        "a transfer is not a delegation: the issuer does not keep what it hands over"
    );
    assert!(done.revoked.revoked.contains(&owner.grant.grant_id));
}

#[test]
fn the_issuer_sees_what_is_being_shared_and_no_historical_attachment_keys() {
    use kr_protocol::sharing::LiveScreenPreview;

    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let selection = RoleSelection {
        include_live_screen: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let screen = LiveScreenPreview {
        // Text printed long before the invitation existed. The preview shows it rather than
        // describing the sharing.
        lines: vec![
            "$ cat /home/me/notes/salary-review.txt".to_owned(),
            "band 4, effective March".to_owned(),
        ],
        truncated: false,
    };
    let request = ShareRequest {
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        live_screen: Some(screen.clone()),
        ..share(SessionRole::Viewer, 1)
    };

    let preview = service.preview(&request).expect("a preview");
    assert_eq!(
        preview.live_screen.as_ref(),
        Some(&screen),
        "the issuer is shown the text, not a promise about it"
    );
    assert!(
        !preview.historical_attachment_keys,
        "a new recipient receives no historical attachment keys"
    );
    assert!(preview.single_use);
    assert!(preview.history.include_live_screen);

    let issued = service.share(&request, || Ok(())).expect("issued");
    assert_eq!(
        issued.preview, preview,
        "what was written is what was shown"
    );
    let kept = service
        .invitation(preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        kept.preview, preview,
        "the preview is kept, so what a recipient gets can be compared with what was shown"
    );

    // Without the option there is no screen in the preview and none in the grant.
    let plain = service
        .preview(&ShareRequest {
            invitation_id: invitation_id(2),
            grant_id: grant_id(2),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("a preview");
    assert!(plain.live_screen.as_ref().is_none());
    assert!(!plain.history.include_live_screen);
}

/// Nothing enters a grant's scope that the issuer was not shown, and nothing is previewed that the
/// grant does not name.
#[test]
fn an_invitation_names_nothing_the_issuer_was_not_shown() {
    use kr_protocol::ids::QuestionId;
    use kr_protocol::sharing::{LiveScreenPreview, NamedQuestionPreview};

    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let question = QuestionId::new(Uuid::from_bytes([7; 16]));
    let naming = RoleSelection {
        named_questions: [question].into_iter().collect(),
        ..RoleSelection::plain(SessionRole::Viewer)
    };

    // Named, and no preview of it.
    let error = service
        .preview(&ShareRequest {
            accepted_notices: AuthorityNotice::for_actions(&naming.actions()),
            selection: naming.clone(),
            ..share(SessionRole::Viewer, 1)
        })
        .expect_err("a bare identifier is not a preview");
    assert!(
        error.to_string().contains("was not shown"),
        "unexpected refusal: {error}"
    );

    // Previewed, and not named: a preview of something that is not being shared.
    let error = service
        .preview(&ShareRequest {
            named_questions: vec![NamedQuestionPreview {
                question_id: question,
                revision: kr_protocol::ids::QuestionRevision::new(1),
                question: "Push the branch anyway?".to_owned(),
                created_at_ms: kr_protocol::scalars::TimestampMs::new(NOW - 1),
            }],
            ..share(SessionRole::Viewer, 1)
        })
        .expect_err("a preview of something the grant does not name");
    assert!(
        error.to_string().contains("does not name"),
        "unexpected refusal: {error}"
    );

    // Both, and it is accepted, with the preview carried into the invitation.
    let preview = service
        .preview(&ShareRequest {
            accepted_notices: AuthorityNotice::for_actions(&naming.actions()),
            selection: naming,
            named_questions: vec![NamedQuestionPreview {
                question_id: question,
                revision: kr_protocol::ids::QuestionRevision::new(1),
                question: "Push the branch anyway?".to_owned(),
                created_at_ms: kr_protocol::scalars::TimestampMs::new(NOW - 1),
            }],
            ..share(SessionRole::Viewer, 1)
        })
        .expect("named and shown");
    assert_eq!(preview.named_questions.len(), 1);
    assert!(preview.history.named_questions.contains(&question));

    // The live screen is the same rule: included and not shown is refused.
    let screen = RoleSelection {
        include_live_screen: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let error = service
        .preview(&ShareRequest {
            accepted_notices: AuthorityNotice::for_actions(&screen.actions()),
            selection: screen.clone(),
            ..share(SessionRole::Viewer, 2)
        })
        .expect_err("a screen nobody was shown is not shared");
    assert!(
        error.to_string().contains("shown none"),
        "unexpected refusal: {error}"
    );
    service
        .preview(&ShareRequest {
            accepted_notices: AuthorityNotice::for_actions(&screen.actions()),
            selection: screen,
            live_screen: Some(LiveScreenPreview {
                lines: vec!["$ ".to_owned()],
                truncated: false,
            }),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("included and shown");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-18.03: scoped invitations, delegation and transfer of control
// ---------------------------------------------------------------------------------------------

#[test]
fn an_invitation_is_scoped_to_the_session_it_shares() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let issued = service
        .share(&share(SessionRole::Viewer, 1), || Ok(()))
        .expect("issued");
    assert_eq!(
        issued.grant.session_selector,
        SessionSelector::These {
            session_ids: [session_id(0xa0)].into_iter().collect()
        },
        "an invitation shares one session, not the host"
    );
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));
    let elsewhere = AccessRequest {
        session_id: Some(session_id(0xb0)),
        ..request(Method::SessionRead, NOW)
    };
    assert_eq!(
        decide(
            &issued.grant,
            &stored(&issued.grant),
            &mut policy,
            elsewhere
        ),
        Err(Refusal::SessionOutsideGrant)
    );
}

#[test]
fn a_delegation_narrows_what_the_issuer_holds() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    // Only an owner carries `session.share`, so only an owner can pass anything on. A reviewer
    // holding `files.read` does not thereby hold the authority to give it to somebody else.
    let owner = service
        .share(&share(SessionRole::Owner, 1), || Ok(()))
        .expect("an owner");
    // Redeemed, because a proposal carries nothing to delegate: authority nobody has taken up is
    // not authority anybody can pass on.
    service
        .redeem(owner.preview.invitation_id, device_id(0xf1), NOW + 1)
        .expect("the owner redeems it");

    // The owner delegates a viewer's grant to a third device: narrower, and accepted.
    let narrower = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(2),
                grant_id: grant_id(2),
                issuer_device_id: device_id(0xf1),
                recipient_device_id: device_id(0xf2),
                parent_grant_id: Some(owner.grant.grant_id),
                ..share(SessionRole::Viewer, 2)
            },
            || Ok(()),
        )
        .expect("a narrower delegation");
    assert_eq!(
        narrower.grant.parent_grant_id.as_ref(),
        Some(&owner.grant.grant_id),
        "a delegated grant names its parent"
    );

    service
        .redeem(narrower.preview.invitation_id, device_id(0xf2), NOW + 2)
        .expect("the viewer redeems it");

    // The viewer it just created tries to pass its own view on. It holds no `session.share`, so
    // it cannot, however narrow the thing it is offering.
    let error = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(3),
                grant_id: grant_id(3),
                issuer_device_id: device_id(0xf2),
                recipient_device_id: device_id(0xf3),
                parent_grant_id: Some(narrower.grant.grant_id),
                ..share(SessionRole::Viewer, 3)
            },
            || Ok(()),
        )
        .expect_err("holding a right is not authority to pass it on");
    assert!(
        error.to_string().contains("session.share"),
        "unexpected refusal: {error}"
    );

    // A device that merely *names* the owner's grant cannot delegate from it either.
    let error = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(4),
                grant_id: grant_id(4),
                issuer_device_id: device_id(0xbb),
                recipient_device_id: device_id(0xbc),
                parent_grant_id: Some(owner.grant.grant_id),
                ..share(SessionRole::Viewer, 4)
            },
            || Ok(()),
        )
        .expect_err("naming a grant is not holding one");
    assert!(
        error.to_string().contains("belongs to another device"),
        "unexpected refusal: {error}"
    );

    // And nobody but this host issues a grant that delegates from nothing.
    let error = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(5),
                grant_id: grant_id(5),
                issuer_device_id: device_id(0xbb),
                recipient_device_id: device_id(0xbc),
                parent_grant_id: None,
                ..share(SessionRole::Viewer, 5)
            },
            || Ok(()),
        )
        .expect_err("a device cannot write authority out of nothing");
    assert!(
        error.to_string().contains("only this host"),
        "unexpected refusal: {error}"
    );

    // The owner tries to delegate more history than it holds. Its own invitation included no live
    // screen, so a delegation that does reaches further than its parent, and the issuer is shown
    // the screen it is proposing to share so the refusal is about the delegation rather than the
    // missing preview.
    let beyond = RoleSelection {
        include_live_screen: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let error = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(6),
                grant_id: grant_id(6),
                issuer_device_id: device_id(0xf1),
                recipient_device_id: device_id(0xf4),
                parent_grant_id: Some(owner.grant.grant_id),
                accepted_notices: AuthorityNotice::for_actions(&beyond.actions()),
                selection: beyond,
                live_screen: Some(kr_protocol::sharing::LiveScreenPreview {
                    lines: vec!["$ ".to_owned()],
                    truncated: false,
                }),
                ..share(SessionRole::Viewer, 6)
            },
            || Ok(()),
        )
        .expect_err("the parent's history scope does not include the live screen");
    assert!(
        error.to_string().contains("history"),
        "unexpected refusal: {error}"
    );

    // Revoking the owner takes the delegation with it.
    let revocation = service
        .revoke(owner.grant.grant_id, NOW + 10, || Ok(()), None)
        .expect("revoked");
    assert!(revocation.revoked.contains(&narrower.grant.grant_id));
}

#[test]
fn transfer_of_control_hands_over_only_what_the_transferring_grant_carries() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let owner = service
        .share(&share(SessionRole::Owner, 1), || Ok(()))
        .expect("an owner");
    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: owner.grant.grant_id,
        issuing_grant_id: grant_id(2),
        actions: transfer::transferable_actions(&owner.grant),
    };
    transfer::check_transfer(&plan, &owner.grant).expect("an owner may transfer control");
    assert!(plan.actions.contains(&ActionRight::SessionShare));
    assert_eq!(
        TransferPlan::sensitive_action(),
        kr_protocol::pairing::SensitiveAction::ChangeHostAuthority,
        "transferring control changes who holds host authority, and is confirmed as that"
    );

    // A controller holds no `session.share`, so it cannot transfer anything.
    let controller = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(3),
                grant_id: grant_id(3),
                recipient_device_id: device_id(0xf4),
                ..share(SessionRole::Controller, 3)
            },
            || Ok(()),
        )
        .expect("a controller");
    let refused = TransferPlan {
        from_device_id: device_id(0xf4),
        revoking_grant_id: controller.grant.grant_id,
        actions: transfer::transferable_actions(&controller.grant),
        ..plan.clone()
    };
    let error = transfer::check_transfer(&refused, &controller.grant)
        .expect_err("a controller cannot transfer control");
    assert!(
        error.to_string().contains("session.share"),
        "unexpected refusal: {error}"
    );

    // And a plan that hands over more than the transferring grant carries is refused, even when
    // the transferring grant does hold `session.share`.
    let narrowed = Grant {
        actions: [ActionRight::SessionView, ActionRight::SessionShare]
            .into_iter()
            .collect(),
        ..owner.grant.clone()
    };
    let overreaching = TransferPlan {
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        ..plan
    };
    let error = transfer::check_transfer(&overreaching, &narrowed)
        .expect_err("a transfer cannot hand over what was never held");
    assert!(
        error.to_string().contains("terminal.input"),
        "unexpected refusal: {error}"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-19.01: no input through an intermediary
// ---------------------------------------------------------------------------------------------

#[test]
fn a_view_only_invitation_obtains_no_input_through_a_plugin_an_attachment_action_or_a_workflow() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let viewer = service
        .share(&share(SessionRole::Viewer, 1), || Ok(()))
        .expect("a viewer");
    let actor = viewer.grant.actions.clone();

    // Each intermediary declares terminal input of its own. None of them can lend it.
    let declared: CanonicalSet<ActionRight> = [
        ActionRight::SessionView,
        ActionRight::TerminalInput,
        ActionRight::FilesApplyDiff,
    ]
    .into_iter()
    .collect();
    for via in [
        Intermediary::PluginAction {
            declared: declared.clone(),
        },
        Intermediary::AttachmentAction {
            declared: declared.clone(),
        },
        Intermediary::Workflow {
            declared: declared.clone(),
        },
    ] {
        let effective = effective_rights(&actor, &via);
        assert!(
            !effective.contains(&ActionRight::TerminalInput),
            "{} lent a viewer terminal input",
            via.as_str()
        );
        assert!(
            !effective.contains(&ActionRight::FilesApplyDiff),
            "{} lent a viewer a file write",
            via.as_str()
        );
        assert!(
            effective.contains(&ActionRight::SessionView),
            "what the actor does hold still passes through"
        );
        let error = roles::check_indirect(&actor, &via, ActionRight::TerminalInput)
            .expect_err("the refusal is explicit");
        assert!(
            error.to_string().contains("terminal.input"),
            "unexpected refusal: {error}"
        );
    }

    // The intersection bounds the other way too: a controller calling a plugin that declares only
    // reads obtains only reads.
    let controller = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(2),
                grant_id: grant_id(2),
                recipient_device_id: device_id(0xf2),
                ..share(SessionRole::Controller, 2)
            },
            || Ok(()),
        )
        .expect("a controller");
    let reads_only = Intermediary::PluginAction {
        declared: [ActionRight::SessionView].into_iter().collect(),
    };
    let effective = effective_rights(&controller.grant.actions, &reads_only);
    assert!(!effective.contains(&ActionRight::TerminalInput));
    assert!(effective.contains(&ActionRight::SessionView));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.49: the sharing method group
// ---------------------------------------------------------------------------------------------

/// KR-REQ-02.09: which grants count as rights-enlarging: a persistent grant that the device's
/// existing grants do not cover is one, and needs the owner's confirmation; a bounded invitation,
/// however wide, and a re-issue of what the device already holds are not.
#[test]
fn sharing_checks_parent_rights_expiry_and_owner_confirmation() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");

    // Parent rights: a delegation from a grant this host does not hold is refused.
    let error = service
        .share(
            &ShareRequest {
                parent_grant_id: Some(grant_id(0xcc)),
                ..share(SessionRole::Viewer, 1)
            },
            || Ok(()),
        )
        .expect_err("a parent this host does not hold");
    assert!(
        error.to_string().contains("no such parent grant"),
        "unexpected refusal: {error}"
    );

    // Expiry: every invitation has one, and it is inside the bound.
    let issued = service
        .share(&share(SessionRole::Viewer, 2), || Ok(()))
        .expect("issued");
    let GrantExpiry::At { expires_at_ms } = issued.grant.expiry else {
        panic!("an invitation expires");
    };
    assert_eq!(
        expires_at_ms.get(),
        NOW + kr_protocol::sharing::DEFAULT_INVITATION_LIFETIME_MS
    );

    // Owner confirmation: a persistent enlargement needs it, a bounded invitation does not.
    assert!(
        !requires_owner_confirmation(&issued.grant, &[]),
        "a bounded invitation is not a persistent enlargement, however wide"
    );
    let persistent = Grant {
        expiry: GrantExpiry::Never,
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        ..issued.grant.clone()
    };
    assert!(
        requires_owner_confirmation(&persistent, std::slice::from_ref(&issued.grant)),
        "a persistent grant the device's existing grants do not cover is an enlargement"
    );
    assert!(
        !requires_owner_confirmation(&persistent, std::slice::from_ref(&persistent)),
        "re-issuing what a device already holds enlarges nothing"
    );
    // The case comparing action names alone would miss: the same actions, permanently, over every
    // session rather than the one the existing grant covers.
    let everywhere = Grant {
        session_selector: SessionSelector::Any,
        expiry: GrantExpiry::Never,
        ..issued.grant.clone()
    };
    assert!(
        requires_owner_confirmation(&everywhere, std::slice::from_ref(&issued.grant)),
        "a permanent grant over every session is an enlargement of a bounded one over one session"
    );

    // Listing: the issuer sees what it issued and everything delegated from it, and nothing else.
    // A grant this host issued to an owner, which that owner then delegates onward. The second
    // grant's issuer is the owner's device, not this host, so it is not in this host's own list.
    let owner = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(5),
                grant_id: grant_id(5),
                recipient_device_id: device_id(0xaa),
                ..share(SessionRole::Owner, 5)
            },
            || Ok(()),
        )
        .expect("an owner");
    service
        .redeem(owner.preview.invitation_id, device_id(0xaa), NOW + 1)
        .expect("the owner redeems it");
    let other_issuer = service
        .share(
            &ShareRequest {
                invitation_id: invitation_id(4),
                grant_id: grant_id(4),
                issuer_device_id: device_id(0xaa),
                recipient_device_id: device_id(0xab),
                parent_grant_id: Some(owner.grant.grant_id),
                ..share(SessionRole::Viewer, 4)
            },
            || Ok(()),
        )
        .expect("the owner's own delegation");
    let listed = service
        .list_for_issuer(device_id(0xf0), None, false, NOW)
        .expect("a list");
    let ids: Vec<GrantId> = listed
        .grants
        .iter()
        .map(|summary| summary.grant.grant_id)
        .collect();
    assert!(ids.contains(&issued.grant.grant_id));
    assert!(
        ids.contains(&other_issuer.grant.grant_id),
        "a delegation of something this host issued is still inside this host's own reach"
    );
}

/// An expired invitation stays expired when the clock goes back.
#[test]
fn an_invitation_refused_as_expired_stays_expired() {
    let service = SharingService::in_memory(device_id(0xf0)).expect("a sharing service");
    let issued = service
        .share(&share(SessionRole::Viewer, 1), || Ok(()))
        .expect("issued");
    let expires_at = issued.preview.expires_at_ms.get();

    service
        .redeem(issued.preview.invitation_id, device_id(0xf1), expires_at)
        .expect_err("an expired invitation is refused");

    // The refusal wrote the invitation's expiry down, and that write survived the refusal. A later
    // call with an earlier reading finds an expired invitation rather than an open one.
    let record = service
        .invitation(issued.preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        record.state,
        kr_protocol::sharing::InvitationState::Expired,
        "the expiry is committed, not rolled back with the refusal"
    );
    service
        .redeem(issued.preview.invitation_id, device_id(0xf1), NOW + 1)
        .expect_err("a clock that went back does not re-open it");
}

/// Transferring control through the daemon fences what the transfer took away.
#[tokio::test]
async fn transferring_control_through_the_daemon_completes_through_the_barrier() {
    let (_temp, controller) = daemon().await;
    let environment_id = controller.paths().environment_id();
    let host_device_id = DeviceId::new(environment_id.get());

    // On the daemon's own clock, because the daemon decides expiry from it: a grant issued at a
    // fixed moment in 1970 would have expired long before this test transferred it.
    let now_ms = kr_ipc::now_ms().get();
    let owner = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id,
                issuer_device_id: host_device_id,
                authority_revision: controller.policy().authority_revision(),
                now_ms,
                ..share(SessionRole::Owner, 1)
            },
            || Ok(()),
        )
        .expect("the host shares a session");
    controller
        .sharing()
        .redeem(owner.preview.invitation_id, device_id(0xf1), now_ms + 1)
        .expect("the owner redeems it");

    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: owner.grant.grant_id,
        issuing_grant_id: grant_id(9),
        actions: transfer::transferable_actions(&owner.grant),
    };
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    // Evidence the owner gave for **another** host does not authorise a transfer on this one, even
    // though the plan and the signature are otherwise the same.
    let elsewhere = confirm_transfer_for(&plan, device_id(0xee), &owner_key);
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.transfer_control(&plan, &elsewhere),
    )
    .await
    .expect("the refusal is prompt")
    .expect_err("this host is not the one the owner confirmed for");

    let confirmed = confirm_transfer_for(&plan, host_device_id, &owner_key);
    let before = controller.policy().authority_revision();
    let (transfer, completed) = tokio::time::timeout(
        Duration::from_secs(20),
        controller.transfer_control(&plan, &confirmed),
    )
    .await
    .expect("the transfer completes")
    .expect("it succeeds");

    assert_eq!(transfer.issued.recipient_device_id, device_id(0xf2));
    assert!(
        completed.authority_revision.get() > before.get(),
        "a transfer withdraws authority, so it advances the revision"
    );
    assert!(completed.revoked_grants.contains(&owner.grant.grant_id));
    assert_eq!(
        completed.barrier.authority_revision, completed.authority_revision,
        "and completes through the per-worker dispatch barrier"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "a completed fence clears the debt it covered"
    );
}

/// A supervisor that starts nothing.
///
/// These tests are about sharing rather than about sessions, so nothing here creates one.
#[derive(Debug)]
struct SilentSupervisor;

impl WorkerSupervisor for SilentSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no worker".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_daemon(&temp).await.expect("the daemon starts");
    (temp, controller)
}

/// Starts a daemon over an environment tree that may already hold another daemon's records.
async fn start_daemon(
    temp: &kr_ipc::testing::TempHost,
) -> kr_controller::error::Result<Arc<Controller>> {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(SilentSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
}

/// Stops a daemon the way its process ending would: nothing it held in memory survives.
async fn stop_daemon(controller: Arc<Controller>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while Arc::strong_count(&controller) > 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "the stopped daemon is still held"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(controller);
}

/// Makes this environment's store refuse every write of the host's policy, and with it the clock
/// floor, as a full disk would, until the returned connection drops the trigger.
fn refuse_policy_writes(temp: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    registry
}

/// Clears the fault [`refuse_policy_writes`] put in place.
fn allow_policy_writes(registry: &rusqlite::Connection) {
    registry
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
}

/// Shares one session as its owner with `device` under a one-hour invitation, redeemed, on the
/// daemon's own clock. Returns the active grant.
fn shared_and_redeemed(controller: &Controller, byte: u8, device: DeviceId) -> Grant {
    let environment_id = controller.paths().environment_id();
    let now_ms = kr_ipc::now_ms().get();
    let shared = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id,
                issuer_device_id: DeviceId::new(environment_id.get()),
                recipient_device_id: device,
                authority_revision: controller.policy().authority_revision(),
                now_ms,
                ..share(SessionRole::Owner, byte)
            },
            || Ok(()),
        )
        .expect("the host shares a session");
    controller
        .sharing()
        .redeem(shared.preview.invitation_id, device, now_ms + 1)
        .expect("the device redeems it")
}

/// Transfers `source` from the device holding it to another, with the owner's confirmation.
async fn transfer_to_another(
    controller: &Controller,
    source: &Grant,
    issuing: GrantId,
) -> kr_controller::error::Result<()> {
    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: source.recipient_device_id,
        to_device_id: device_id(0xf2),
        revoking_grant_id: source.grant_id,
        issuing_grant_id: issuing,
        actions: transfer::transferable_actions(source),
    };
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let confirmed = confirm_transfer_for(
        &plan,
        DeviceId::new(controller.paths().environment_id().get()),
        &owner_key,
    );
    tokio::time::timeout(
        Duration::from_secs(20),
        controller.transfer_control(&plan, &confirmed),
    )
    .await
    .expect("the transfer is answered promptly")
    .map(|_| ())
}

/// KR-REQ-09.18: a refusal the clock decided is never answered on a clock floor this host could
/// not write down.
///
/// The host's store refuses every write of the floor. The wall clock reads an hour and a minute
/// ahead, once, which raises the floor past a grant's expiry, and then comes back. A transfer of
/// that grant is decided while the floor is owed its record, so it is refused as a failure to
/// record rather than as an expiry: this host has decided nothing about the grant. The daemon stops
/// before any write lands, the store recovers, and a daemon started again finds the older floor and
/// the wall clock back where it was. The grant is valid by everything it can read, and it is
/// admitted, which contradicts no answer this host gave.
#[tokio::test]
async fn a_refusal_the_clock_decided_is_never_answered_on_a_floor_that_was_not_written() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_daemon(&temp).await.expect("the daemon starts");
    let held = shared_and_redeemed(&controller, 1, device_id(0xf1));
    let kr_protocol::grant::GrantExpiry::At { expires_at_ms } = held.expiry else {
        panic!("an invitation expires");
    };

    let fault = refuse_policy_writes(&temp);
    // One reading past the grant's expiry, which raises the floor; its write is refused.
    let ahead = expires_at_ms.get() + 60_000;
    controller
        .update_policy(|policy| policy.observe_utc(ahead))
        .expect_err("the store refuses the policy");
    let first = transfer_to_another(&controller, &held, grant_id(9)).await;

    // Stopped before any write of the floor lands; the store recovers; started again.
    stop_daemon(controller).await;
    allow_policy_writes(&fault);
    let controller = start_daemon(&temp).await.expect("the daemon starts again");
    let second = transfer_to_another(&controller, &held, grant_id(10)).await;

    let refused_as_expired = matches!(
        &first,
        Err(error) if error.code() == kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        !(refused_as_expired && second.is_ok()),
        "a grant this host refused as expired was admitted after a restart: {first:?}, then \
         {second:?}"
    );
    assert_eq!(
        first.expect_err("the transfer is refused").code(),
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "refused as a floor this host could not write down, not decided"
    );
    second.expect("nothing this host decided stands against the grant");
}

/// A delegation of one session under `parent`, from the device holding it to another, for half an
/// hour, on the daemon's own clock.
fn delegate(
    controller: &Controller,
    parent: &Grant,
    byte: u8,
) -> kr_controller::error::Result<kr_protocol::sharing::GrantCreateResult> {
    controller.sharing().share(
        &ShareRequest {
            environment_id: controller.paths().environment_id(),
            invitation_id: invitation_id(byte),
            grant_id: grant_id(byte),
            issuer_device_id: parent.recipient_device_id,
            recipient_device_id: device_id(0xf4),
            parent_grant_id: Some(parent.grant_id),
            authority_revision: controller.policy().authority_revision(),
            lifetime_ms: Some(30 * 60 * 1000),
            now_ms: kr_ipc::now_ms().get(),
            ..share(SessionRole::Viewer, byte)
        },
        || Ok(()),
    )
}

/// KR-REQ-09.18: a daemon that starts and cannot write its clock floor decides no expiry until it
/// can. A delegation from a grant that expires is refused as a floor this host could not write
/// down, a delegation from a grant that never expires is decided as before, and once the store
/// takes the floor the expiring grant is decided on it again.
#[tokio::test]
async fn a_start_that_cannot_write_its_floor_decides_no_expiry_until_it_can() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = start_daemon(&temp).await.expect("the daemon starts");
    let expiring = shared_and_redeemed(&controller, 1, device_id(0xf1));
    let lasting = Grant {
        grant_id: grant_id(3),
        parent_grant_id: kr_protocol::scalars::Nullable::null(),
        issuer_device_id: DeviceId::new(controller.paths().environment_id().get()),
        recipient_device_id: device_id(0xf3),
        expiry: GrantExpiry::Never,
        ..expiring.clone()
    };
    controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: lasting.clone(),
                session_id: Some(session_id(0xa0)),
                issued_at_ms: kr_ipc::now_ms().get(),
                activated_at_ms: Some(kr_ipc::now_ms().get()),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a grant that never expires");

    let fault = refuse_policy_writes(&temp);
    stop_daemon(controller).await;
    let controller = start_daemon(&temp)
        .await
        .expect("a daemon whose floor write is refused still starts");

    let refused = delegate(&controller, &expiring, 5)
        .expect_err("an expiry is not decided while the floor is owed its record");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "{refused}"
    );
    delegate(&controller, &lasting, 6)
        .expect("a grant that never expires does not stand on the floor");

    allow_policy_writes(&fault);
    transfer_to_another(&controller, &expiring, grant_id(9))
        .await
        .expect("once the floor is written, the expiry is decided on it");
}

/// An active grant of one session, issued straight into the daemon's store, that expired an hour
/// ago by the daemon's own clock. Returns it and the moment two hours ago it was issued.
fn expired_an_hour_ago(controller: &Controller, byte: u8, holder: DeviceId) -> (Grant, u64) {
    let now_ms = kr_ipc::now_ms().get();
    let issued_at_ms = now_ms - 2 * 60 * 60 * 1000;
    let grant = Grant {
        grant_id: grant_id(byte),
        parent_grant_id: kr_protocol::scalars::Nullable::null(),
        issuer_device_id: DeviceId::new(controller.paths().environment_id().get()),
        recipient_device_id: holder,
        authority_revision: controller.policy().authority_revision(),
        environment_selector: kr_protocol::grant::EnvironmentSelector::These {
            environment_ids: [controller.paths().environment_id()].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session_id(0xa0)].into_iter().collect(),
        },
        actions: SessionRole::Owner
            .default_actions()
            .iter()
            .copied()
            .collect(),
        history: kr_protocol::grant::HistoryScope {
            lower_bound_ms: kr_protocol::scalars::Nullable::some(
                kr_protocol::scalars::TimestampMs::new(issued_at_ms),
            ),
            include_live_screen: false,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(now_ms - 60 * 60 * 1000),
        },
        organisation: kr_protocol::scalars::Nullable::null(),
    };
    controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: Some(session_id(0xa0)),
                issued_at_ms,
                activated_at_ms: Some(issued_at_ms),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
    (grant, issued_at_ms)
}

/// Has the daemon write down its clock floor at the moment it is now, as every one of its own
/// requests does before it decides anything.
fn floor_written_now(controller: &Controller) {
    controller
        .update_policy(|policy| policy.observe_utc(kr_ipc::now_ms().get()))
        .expect("the floor is written down");
}

/// KR-REQ-23.49 and 10.40: a delegation decides its parent's expiry at the moment it is written,
/// not only at the moment it was asked for. The parent was still valid at the reading the caller
/// checked it at, and expired before the delegation reached the store: nothing is written.
#[tokio::test]
async fn a_delegation_whose_parent_expired_before_it_was_written_is_refused() {
    let (_temp, controller) = daemon().await;
    let (parent, checked_at_ms) = expired_an_hour_ago(&controller, 1, device_id(0xf1));
    floor_written_now(&controller);

    let refused = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id: controller.paths().environment_id(),
                invitation_id: invitation_id(2),
                grant_id: grant_id(2),
                issuer_device_id: device_id(0xf1),
                recipient_device_id: device_id(0xf2),
                parent_grant_id: Some(parent.grant_id),
                authority_revision: controller.policy().authority_revision(),
                lifetime_ms: Some(30 * 60 * 1000),
                now_ms: checked_at_ms + 1,
                ..share(SessionRole::Viewer, 2)
            },
            || Ok(()),
        )
        .expect_err("the parent had expired by the time the delegation was written");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(refused.to_string().contains("expired"), "{refused}");
    assert!(
        controller
            .sharing()
            .grants()
            .record(grant_id(2))
            .expect("readable")
            .is_none(),
        "nothing was delegated"
    );
}

/// KR-REQ-25.10: a redemption decides its invitation's deadline at the moment it is written, not
/// only at the moment it was asked for, and marks an invitation that ran out in between expired.
#[tokio::test]
async fn a_redemption_whose_invitation_expired_before_it_was_written_is_refused() {
    let (_temp, controller) = daemon().await;
    let environment_id = controller.paths().environment_id();
    // Shared two hours ago under an hour's invitation, by the daemon's own clock.
    let shared_at_ms = kr_ipc::now_ms().get() - 2 * 60 * 60 * 1000;
    let shared = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id,
                issuer_device_id: DeviceId::new(environment_id.get()),
                authority_revision: controller.policy().authority_revision(),
                now_ms: shared_at_ms,
                ..share(SessionRole::Viewer, 1)
            },
            || Ok(()),
        )
        .expect("the host shares a session");
    floor_written_now(&controller);

    let refused = controller
        .sharing()
        .redeem(
            shared.preview.invitation_id,
            device_id(0xf1),
            shared_at_ms + 1,
        )
        .expect_err("the invitation had run out by the time the redemption was written");
    assert!(refused.to_string().contains("expired"), "{refused}");
    let invitation = controller
        .sharing()
        .invitation(shared.preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        invitation.state,
        kr_protocol::sharing::InvitationState::Expired,
        "the lapse is written down with the invitation"
    );
    assert!(
        !controller
            .sharing()
            .grants()
            .record(shared.grant.grant_id)
            .expect("readable")
            .expect("present")
            .is_active(),
        "nothing was activated"
    );
}

/// KR-REQ-18.03 and 23.49: a transfer decides its source's expiry at the moment it is written, not
/// only at the moment it was asked for. The source was valid at the reading the caller took and
/// had expired by the time the transfer reached the store: nothing is issued and nothing revoked.
#[tokio::test]
async fn a_transfer_whose_source_expired_before_it_was_written_is_refused() {
    let (_temp, controller) = daemon().await;
    let (source, checked_at_ms) = expired_an_hour_ago(&controller, 1, device_id(0xf1));
    floor_written_now(&controller);
    let plan = TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: source.grant_id,
        issuing_grant_id: grant_id(9),
        actions: transfer::transferable_actions(&source),
    };
    let owner_key = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let confirmed = confirm_transfer_for(
        &plan,
        DeviceId::new(controller.paths().environment_id().get()),
        &owner_key,
    );

    let refused = controller
        .sharing()
        .transfer_control(
            &plan,
            &confirmed,
            &Clock,
            controller.policy().authority_revision(),
            checked_at_ms + 1,
        )
        .expect_err("the source had expired by the time the transfer was written");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .record(grant_id(9))
            .expect("readable")
            .is_none(),
        "no replacement was issued"
    );
    assert!(
        controller
            .sharing()
            .grants()
            .record(source.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_none(),
        "and the source was not revoked by a transfer that did not happen"
    );
}

#[tokio::test]
async fn revoking_a_shared_grant_completes_through_the_dispatch_barrier() {
    let (_temp, controller) = daemon().await;
    let environment_id = controller.paths().environment_id();
    let host_device_id = DeviceId::new(environment_id.get());
    // On the daemon's own clock, which is the one its store decides a redemption's deadline on.
    let now_ms = kr_ipc::now_ms().get();

    let issued = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id,
                issuer_device_id: host_device_id,
                authority_revision: controller.policy().authority_revision(),
                now_ms,
                ..share(SessionRole::Owner, 1)
            },
            || Ok(()),
        )
        .expect("the host shares a session");
    controller
        .sharing()
        .redeem(issued.preview.invitation_id, device_id(0xf1), now_ms + 1)
        .expect("the recipient redeems it");

    // A delegation from it, so the revocation has a descendant to take with it.
    let delegated = controller
        .sharing()
        .share(
            &ShareRequest {
                environment_id,
                invitation_id: invitation_id(2),
                grant_id: grant_id(2),
                issuer_device_id: device_id(0xf1),
                recipient_device_id: device_id(0xf2),
                parent_grant_id: Some(issued.grant.grant_id),
                authority_revision: controller.policy().authority_revision(),
                now_ms,
                ..share(SessionRole::Viewer, 2)
            },
            || Ok(()),
        )
        .expect("a delegation");

    let before = controller.policy().authority_revision();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(issued.grant.grant_id, None, None),
    )
    .await
    .expect("the revocation completes")
    .expect("it succeeds");

    assert!(result.authority_revision.get() > before.get());
    assert!(result.revoked_grants.contains(&issued.grant.grant_id));
    assert!(
        result.revoked_grants.contains(&delegated.grant.grant_id),
        "revoking a parent revokes its descendants"
    );
    assert_eq!(
        result.barrier.authority_revision, result.authority_revision,
        "the answer carries the per-worker completion status, not only the revision"
    );

    let listed = controller
        .sharing()
        .list_for_issuer(host_device_id, None, false, now_ms)
        .expect("a list");
    assert!(
        listed.grants.is_empty(),
        "nothing active is left after the revocation"
    );
}
