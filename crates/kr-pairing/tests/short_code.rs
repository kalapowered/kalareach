//! The short-code flow, end to end, and the acceptance conditions of KR-ACC-015.
//!
//! Every dependency is an in-test implementation of the traits in `kr_pairing::platform`: no
//! network, no disk, no real clock. What is exercised is the protocol.

use std::cell::RefCell;
use std::collections::BTreeSet;

use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::confirm::{
    ConfirmationLedger, HostEnrolment, request_confirmation, sign_confirmation,
};
use kr_pairing::grants::{GrantIdentities, GrantKind};
use kr_pairing::host::{
    ApprovedCandidate, HANDSHAKE_DEADLINE_MS, HostIdentity, HostInvitation, InvitationProposal,
    OwnerApproval, OwnerContext, StatusViewer, cancel_unfinished_invitations,
    recover_candidate_status, recover_commitment,
};
use kr_pairing::platform::{
    InvitationState, LocatorRecord, TestClient, TestClientBudgetStore, TestClock,
    TestInvitationStore, TestLivePeer, TestRendezvousHost,
};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{ActorId, AuthorityRevision, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{
    ClientBundle, ConfirmationChannel, DeviceName, DevicePlatform, DevicePublicKeys,
    INVITATION_LIFETIME_MS, MAX_CONFIRMATION_FAILURES, NetworkConfig, OwnerConfirmationProof,
    OwnerConfirmationRequest, PairStatus, PairingConsumedReason, ProposedGrant, RendezvousOrigin,
    SensitiveAction,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, EndpointKey, Nullable, TimestampMs, Uuid,
};

fn origin() -> RendezvousOrigin {
    RendezvousOrigin::new("https://reach.kala.to").expect("an origin")
}

fn owner(seed: u8) -> OwnerContext {
    OwnerContext {
        actor_id: ActorId::new(format!("owner-{seed}")).expect("a principal"),
        ingress: ActorIngress::LocalIpc,
    }
}

fn proposal() -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(1_764_003_600_000),
        },
        organisation: Nullable::null(),
    }
}

fn client_bundle(keys: &DeviceKeys) -> ClientBundle {
    ClientBundle {
        endpoint_id: *keys.transport.public(),
        keys: keys.public_keys(),
        device_key_revision: DeviceKeyRevision::new(1),
        device_name: DeviceName::new("A phone").expect("a name"),
        platform: DevicePlatform::Ios,
    }
}

/// One owner confirmation, issued and signed, ready to be presented.
struct Approval {
    request: OwnerConfirmationRequest,
    proof: OwnerConfirmationProof,
}

impl Approval {
    fn by<'a>(
        &'a self,
        owner: &'a OwnerContext,
        signer: &'a AuthorisationKey,
    ) -> OwnerApproval<'a> {
        OwnerApproval {
            owner,
            signer,
            enrolment: HostEnrolment::Enrolled,
            request: &self.request,
            proof: &self.proof,
        }
    }
}

/// Everything one pairing needs, assembled once.
///
/// The state machines take the store and the clock by reference, which is how a test watches the
/// same values the host is writing.
struct Harness {
    store: TestInvitationStore,
    clock: TestClock,
    service: TestRendezvousHost,
    ledger: RefCell<ConfirmationLedger>,
    host_keys: DeviceKeys,
    client_keys: DeviceKeys,
    owner_keys: DeviceKeys,
    host_device_id: DeviceId,
    issuing_owner: OwnerContext,
}

type Host<'a> = HostInvitation<&'a TestInvitationStore, &'a TestClock>;

impl Harness {
    fn new() -> Self {
        Self {
            store: TestInvitationStore::new(),
            clock: TestClock::new(),
            service: TestRendezvousHost::new(),
            ledger: RefCell::new(ConfirmationLedger::new()),
            host_keys: DeviceKeys::generate().expect("keys"),
            client_keys: DeviceKeys::generate().expect("keys"),
            owner_keys: DeviceKeys::generate().expect("keys"),
            host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            issuing_owner: owner(1),
        }
    }

    fn signer(&self) -> &AuthorisationKey {
        self.owner_keys.authorisation.public()
    }

    fn identity(&self) -> HostIdentity {
        HostIdentity {
            device_id: self.host_device_id,
            endpoint_id: *self.host_keys.transport.public(),
            keys: self.host_keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            network_config: NetworkConfig {
                relay_urls: Vec::new(),
                discovery_origins: Vec::new(),
                direct_addresses: Vec::new(),
            },
        }
    }

    /// Runs the ceremony: issues a challenge, records it and signs a proof for it.
    fn approval(
        &self,
        action: SensitiveAction,
        digest: Digest256,
        destination_keys: Option<DevicePublicKeys>,
    ) -> Approval {
        let request = request_confirmation(
            &self.clock,
            action,
            digest,
            destination_keys,
            proposal().actions.iter().copied().collect::<BTreeSet<_>>(),
            self.host_device_id,
            *self.host_keys.transport.public(),
        )
        .expect("a challenge");
        self.ledger.borrow_mut().issue(&request, &self.clock);
        let proof = sign_confirmation(
            &self.owner_keys.authorisation,
            &request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        Approval { request, proof }
    }

    fn issue_approval(&self) -> Approval {
        self.approval(
            SensitiveAction::IssueInvitation,
            kr_pairing::confirm::action_digest(&proposal()).expect("a digest"),
            None,
        )
    }

    /// The challenge that approves whatever candidate the host currently holds.
    fn device_approval(&self, approved: &ApprovedCandidate) -> Approval {
        self.approval(
            SensitiveAction::ConfirmDevice,
            approved.action_digest(),
            Some(self.client_keys.public_keys()),
        )
    }

    fn proposal_for(&self) -> InvitationProposal {
        InvitationProposal {
            origin: origin(),
            host: self.identity(),
            proposed_grant: proposal(),
            grant_kind: GrantKind::SessionInvitation,
        }
    }

    fn grant_identities(&self) -> GrantIdentities {
        GrantIdentities {
            grant_id: GrantId::new(Uuid::from_bytes([8; 16])),
            issuer_device_id: self.host_device_id,
            recipient_device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
            authority_revision: AuthorityRevision::new(1),
        }
    }

    fn issue(&self) -> Host<'_> {
        let approval = self.issue_approval();
        HostInvitation::issue(
            &self.store,
            &self.clock,
            &self.service,
            self.proposal_for(),
            &approval.by(&self.issuing_owner, self.signer()),
            &mut self.ledger.borrow_mut(),
        )
        .expect("an invitation")
    }

    fn client_peer(&self) -> TestLivePeer {
        TestLivePeer::new(*self.client_keys.transport.public())
    }

    fn host_peer(&self) -> TestLivePeer {
        TestLivePeer::new(*self.host_keys.transport.public())
    }
}

/// Runs a complete exchange with `entered` as the code the candidate typed.
fn run_exchange(
    harness: &Harness,
    host: &mut Host<'_>,
    entered: &EnteredCode,
) -> Result<(ClientAttempt, String), PairingError> {
    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), entered)?;

    let host_pake = host.admit(admission.attempt_id, admission.client_nonce)?;
    let client_pake = client.with_host_nonce(
        host.context(admission.attempt_id)?.host_nonce,
        &harness.clock,
    )?;

    host.receive_client_pake(admission.attempt_id, &client_pake)?;
    let client_tag = client.receive_host_pake(&host_pake, &harness.clock)?;
    let confirmation = host.verify_client_confirmation(admission.attempt_id, &client_tag)?;
    client.verify_host_confirmation(&confirmation.host_tag, &harness.clock)?;

    let host_frame =
        host.seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)?;
    client.open_host_bundle(&host_frame, &harness.clock)?;
    let client_frame = client.seal_client_bundle(
        &harness.client_keys.authorisation,
        client_bundle(&harness.client_keys),
        &harness.clock,
    )?;
    host.open_client_bundle(admission.attempt_id, &client_frame)?;

    let host_peer = harness.host_peer();
    let request = client.finish_request(
        &host_peer,
        harness.client_keys.transport.public(),
        &harness.clock,
    )?;
    let client_peer = harness.client_peer();
    let locked = host.finish(&request, &client_peer)?;
    let client_value = client.verification_value()?;
    assert_eq!(locked.verification_value, client_value);
    Ok((client, client_value))
}

/// Returns the three digests the owner is shown for the candidate holding the invitation.
fn locked_values(host: &Host<'_>) -> ApprovedCandidate {
    host.locked_candidate()
        .expect("a hash")
        .expect("a locked candidate")
}

/// Approves the candidate the host currently holds, as the owner that issued the invitation.
fn approve(
    harness: &Harness,
    host: &mut Host<'_>,
) -> Result<kr_pairing::platform::PairingCommitment, PairingError> {
    let approved = locked_values(host);
    let approval = harness.device_approval(&approved);
    host.confirm(
        &approval.by(&harness.issuing_owner, harness.signer()),
        &mut harness.ledger.borrow_mut(),
        &approved,
        &harness.grant_identities(),
        None,
    )
}

#[test]
fn a_complete_pairing_commits_the_device_and_the_proposed_grant() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    let (_, value) = run_exchange(&harness, &mut host, &entered).expect("a pairing");
    assert_eq!(value.len(), 8);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let status = host
        .status(StatusViewer::IssuingOwner(&harness.issuing_owner))
        .expect("a status");
    let PairStatus::AwaitingApproval {
        verification_value, ..
    } = status
    else {
        panic!("the owner is asked to approve");
    };
    assert_eq!(verification_value, value);

    // The owner approves the exact transcript and the two bundle hashes it was shown.
    let committed = approve(&harness, &mut host).expect("a commitment");
    assert_eq!(committed.proposed_grant, proposal());
    assert_eq!(committed.verification_value, value);
    assert_eq!(
        committed.client_keys,
        harness.client_keys.public_keys(),
        "the device record is written from the bundle the candidate signed"
    );
    // The grant is issued inside the commit, not assumed: it carries the proposed rights and the
    // identities only the host can assign.
    assert_eq!(committed.grant.actions, proposal().actions);
    assert_eq!(committed.grant.issuer_device_id, harness.host_device_id);
    assert_eq!(committed.grant.recipient_device_id, committed.device_id);
    assert_eq!(
        committed.owner_confirmation.request.action,
        SensitiveAction::ConfirmDevice,
        "the proof that authorised this device is written with it"
    );
    assert_eq!(host.record().state, InvitationState::Committed);

    // The commitment is in the store, so a restarted host answers the retry from there, with no
    // invitation object left at all.
    let invitation_id = host.invitation_id();
    drop(host);
    let stored = recover_commitment(&&harness.store, invitation_id)
        .expect("a read")
        .expect("a commitment");
    assert_eq!(stored, committed);
    let peer = harness.client_peer();
    assert!(matches!(
        recover_candidate_status(
            &&harness.store,
            invitation_id,
            Some(committed.attempt_id),
            &peer
        ),
        Ok(PairStatus::Committed { .. })
    ));
    // And only for that candidate, on its own endpoint.
    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0x77; 32]));
    assert!(matches!(
        recover_candidate_status(
            &&harness.store,
            invitation_id,
            Some(committed.attempt_id),
            &impostor
        ),
        Err(PairingError::NotIssuingOwner)
    ));
}

#[test]
fn a_successful_confirmation_locks_the_invitation_before_any_bundle() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    // A second candidate takes a slot first, so there is something to cancel.
    let bystander = kr_pairing::host::new_attempt_id().expect("an attempt");
    host.admit(bystander, kr_pairing::host::new_nonce().expect("a nonce"))
        .expect("a slot");

    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("a slot");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");

    assert_eq!(host.record().state, InvitationState::Open);
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");

    // The lock is in place before the bundles are exchanged, and the competitor is gone.
    assert_eq!(
        host.record().state,
        InvitationState::Locked {
            attempt_id: admission.attempt_id
        }
    );
    assert_eq!(confirmation.cancelled, vec![bystander]);
    assert_eq!(host.live_candidates(), 1);
    // It is persisted, not just remembered.
    let stored = kr_pairing::platform::InvitationStore::load(&&harness.store, host.invitation_id())
        .expect("a read")
        .expect("a record");
    assert_eq!(
        stored.state,
        InvitationState::Locked {
            attempt_id: admission.attempt_id
        }
    );

    // And no further candidate is admitted while it holds the invitation.
    assert!(matches!(
        host.admit(
            kr_pairing::host::new_attempt_id().expect("an attempt"),
            kr_pairing::host::new_nonce().expect("a nonce")
        ),
        Err(PairingError::CandidateLocked)
    ));

    // The owner sees a locked invitation, with no verification value to show yet.
    let status = host
        .status(StatusViewer::IssuingOwner(&harness.issuing_owner))
        .expect("a status");
    assert!(matches!(status, PairStatus::Locked { .. }));
}

#[test]
fn a_wrong_code_exhausts_five_guesses_and_the_count_survives_a_restart() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

    for expected in (1..MAX_CONFIRMATION_FAILURES).rev() {
        let error = run_exchange(&harness, &mut host, &wrong).expect_err("a wrong code fails");
        assert!(
            matches!(error, PairingError::AuthenticationFailed),
            "{error}"
        );
        assert_eq!(host.remaining_confirmations(), expected);
        // The count is persisted as it falls, so a crash here does not hand the guess back.
        let stored = harness
            .store
            .snapshot()
            .into_iter()
            .find(|record| record.invitation_id == host.invitation_id())
            .expect("a persisted record");
        assert_eq!(
            stored.failed_confirmations,
            MAX_CONFIRMATION_FAILURES - expected
        );
    }

    let error = run_exchange(&harness, &mut host, &wrong).expect_err("the last guess");
    assert!(matches!(error, PairingError::AttemptsExhausted), "{error}");
    assert_eq!(
        host.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::AttemptsExhausted
        }
    );

    // The correct code is refused too: the invitation is spent, and a new one needs another owner
    // action.
    let right = EnteredCode::parse(&host.code().display_text()).expect("the code");
    assert!(matches!(
        run_exchange(&harness, &mut host, &right),
        Err(PairingError::Consumed { .. })
    ));
}

#[test]
fn a_write_that_fails_while_spending_a_guess_fences_the_invitation() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

    harness.store.set_failing_writes(true);
    let error = run_exchange(&harness, &mut host, &wrong).expect_err("the write fails");
    assert!(matches!(error, PairingError::Store { .. }), "{error}");
    // The guess was not recorded, so the invitation is not served again: handing the guess back is
    // the one outcome that must not happen.
    harness.store.set_failing_writes(false);
    let right = EnteredCode::parse(&host.code().display_text()).expect("the code");
    assert!(matches!(
        run_exchange(&harness, &mut host, &right),
        Err(PairingError::Store { .. })
    ));
}

#[test]
fn concurrent_candidates_share_one_allowance() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

    for _ in 0..MAX_CONFIRMATION_FAILURES - 1 {
        let _ = run_exchange(&harness, &mut host, &wrong);
    }
    assert_eq!(host.remaining_confirmations(), 1);
    let _ = run_exchange(&harness, &mut host, &wrong);
    assert_eq!(host.remaining_confirmations(), 0);
    assert!(matches!(
        run_exchange(&harness, &mut host, &wrong),
        Err(PairingError::Consumed { .. })
    ));
}

#[test]
fn a_stalled_candidate_frees_its_slot_and_charges_no_guess() {
    let harness = Harness::new();
    let mut host = harness.issue();

    for _ in 0..kr_pairing::host::MAX_CANDIDATES {
        host.admit(
            kr_pairing::host::new_attempt_id().expect("an attempt"),
            kr_pairing::host::new_nonce().expect("a nonce"),
        )
        .expect("a slot");
    }
    assert!(matches!(
        host.admit(
            kr_pairing::host::new_attempt_id().expect("an attempt"),
            kr_pairing::host::new_nonce().expect("a nonce")
        ),
        Err(PairingError::TooLarge { .. })
    ));

    // Ten seconds later those four have run out of handshake time and the room is free again.
    harness.clock.advance(HANDSHAKE_DEADLINE_MS);
    host.admit(
        kr_pairing::host::new_attempt_id().expect("an attempt"),
        kr_pairing::host::new_nonce().expect("a nonce"),
    )
    .expect("a slot");
    assert_eq!(host.live_candidates(), 1);
    assert_eq!(
        host.remaining_confirmations(),
        MAX_CONFIRMATION_FAILURES,
        "walking away is not a guess"
    );
}

#[test]
fn an_aborted_candidate_frees_its_slot_and_a_locked_one_cannot_be_aborted() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let attempt = kr_pairing::host::new_attempt_id().expect("an attempt");
    host.admit(attempt, kr_pairing::host::new_nonce().expect("a nonce"))
        .expect("a slot");
    assert_eq!(host.live_candidates(), 1);
    host.abort(attempt).expect("a free slot");
    assert_eq!(host.live_candidates(), 0);
    assert_eq!(host.remaining_confirmations(), MAX_CONFIRMATION_FAILURES);

    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let locked = host.locked_attempt().expect("a locked candidate");
    assert!(matches!(
        host.abort(locked),
        Err(PairingError::CandidateLocked)
    ));
}

#[test]
fn a_locked_candidate_that_stops_consumes_the_invitation() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    // Drive the exchange to the lock and stop there, before the bundles.
    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("a slot");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    host.verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    assert!(host.locked_attempt().is_some());

    // Holding the invitation does not suspend the handshake deadline. Ten seconds later the
    // invitation is consumed, so the owner can issue another rather than waiting five minutes.
    harness.clock.advance(HANDSHAKE_DEADLINE_MS);
    assert!(matches!(
        host.seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Expired
        })
    ));
    assert_eq!(
        host.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::Expired
        }
    );
    // Asking for the status runs the same sweep, so it does not report a candidate that stopped
    // as though it were still arriving.
    assert!(matches!(
        host.status(StatusViewer::IssuingOwner(&harness.issuing_owner)),
        Ok(PairStatus::Consumed {
            reason: PairingConsumedReason::Expired
        })
    ));
}

#[test]
fn a_status_request_sweeps_a_candidate_that_stopped() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("a slot");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    host.verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");

    assert!(matches!(
        host.status(StatusViewer::IssuingOwner(&harness.issuing_owner)),
        Ok(PairStatus::Locked { .. })
    ));
    harness.clock.advance(HANDSHAKE_DEADLINE_MS);
    // Without the sweep this would keep reporting a locked invitation for the whole five minutes.
    assert!(matches!(
        host.status(StatusViewer::IssuingOwner(&harness.issuing_owner)),
        Ok(PairStatus::Consumed {
            reason: PairingConsumedReason::Expired
        })
    ));
}

#[test]
fn a_denied_candidate_is_still_told_what_happened() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let attempt_id = host.locked_attempt().expect("a candidate holds it");

    host.deny(&harness.issuing_owner).expect("a denial");
    // The denial cleared the attempts, and the candidate that authenticated itself is still the
    // one device this answers.
    let peer = harness.client_peer();
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &peer,
        }),
        Ok(PairStatus::Consumed {
            reason: PairingConsumedReason::Denied
        })
    ));
    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0x77; 32]));
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &impostor,
        }),
        Err(PairingError::NotIssuingOwner)
    ));
}

#[test]
fn a_fenced_invitation_reports_nothing_and_consumes_nothing() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

    harness.store.set_failing_writes(true);
    assert!(matches!(
        run_exchange(&harness, &mut host, &wrong),
        Err(PairingError::Store { .. })
    ));
    harness.store.set_failing_writes(false);

    // Nothing this invitation can say about itself is known to be true, so it says nothing.
    let peer = harness.client_peer();
    for outcome in [
        host.status(StatusViewer::IssuingOwner(&harness.issuing_owner)),
        host.status(StatusViewer::Candidate {
            attempt_id: Some(kr_pairing::host::new_attempt_id().expect("an attempt")),
            live_peer: &peer,
        }),
    ] {
        assert!(matches!(outcome, Err(PairingError::Store { .. })));
    }
    assert!(matches!(
        host.cancel(&harness.issuing_owner),
        Err(PairingError::Store { .. })
    ));
    assert!(matches!(
        host.deny(&harness.issuing_owner),
        Err(PairingError::Store { .. })
    ));
    // A restart is what clears it, and the guess it spent is still spent.
    let cancelled = cancel_unfinished_invitations(&harness.store).expect("a sweep");
    assert_eq!(cancelled, vec![host.invitation_id()]);
}

#[test]
fn a_malicious_service_cannot_extend_the_deadline_or_forge_an_invitation() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    // The service advertises an expiry far in the future and a different invitation identity. The
    // host's own monotonic deadline is what decides, and the identity is inside the context both
    // devices build, so the PAKE fails rather than the pairing succeeding under the wrong name.
    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: kr_protocol::ids::InvitationId::new(Uuid::from_bytes([0xee; 16])),
        advertised_expires_at_ms: TimestampMs::new(u64::MAX),
    });
    let (mut client, admission, record) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    assert_eq!(record.advertised_expires_at_ms.get(), u64::MAX);

    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("admitted");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("the candidate's message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    // The contexts differ in the invitation identity, so the tags do not match.
    assert!(matches!(
        host.verify_client_confirmation(admission.attempt_id, &client_tag),
        Err(PairingError::AuthenticationFailed)
    ));

    // And the advertised expiry changed nothing: the host's deadline still governs.
    harness.clock.advance(INVITATION_LIFETIME_MS);
    assert!(matches!(
        host.admit(
            kr_pairing::host::new_attempt_id().expect("an attempt"),
            kr_pairing::host::new_nonce().expect("a nonce")
        ),
        Err(PairingError::Expired)
    ));
}

#[test]
fn an_invitation_expires_on_the_hosts_own_clock() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    harness.clock.advance(INVITATION_LIFETIME_MS - 1);
    assert!(run_exchange(&harness, &mut host, &entered).is_ok());

    let mut second = harness.issue();
    let entered = EnteredCode::parse(&second.code().display_text()).expect("the code");
    harness.clock.advance(INVITATION_LIFETIME_MS);
    assert!(matches!(
        run_exchange(&harness, &mut second, &entered),
        Err(PairingError::Expired)
    ));
    assert_eq!(
        second.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::Expired
        }
    );
}

#[test]
fn a_wall_clock_that_runs_backwards_does_not_extend_an_invitation() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    harness.clock.advance(INVITATION_LIFETIME_MS);
    harness.clock.skew_wall_clock(-86_400_000);
    assert!(matches!(
        run_exchange(&harness, &mut host, &entered),
        Err(PairingError::Expired)
    ));
}

#[test]
fn a_host_restart_cancels_unfinished_invitations_and_keeps_consumed_state() {
    let harness = Harness::new();
    let mut first = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
    let _ = run_exchange(&harness, &mut first, &wrong);
    let second = harness.issue();

    let cancelled = cancel_unfinished_invitations(&harness.store).expect("a sweep");
    assert_eq!(cancelled.len(), 2);
    for record in harness.store.snapshot() {
        assert_eq!(
            record.state,
            InvitationState::Consumed {
                reason: PairingConsumedReason::HostRestarted
            }
        );
    }

    // The failure count survived the restart: it is in the record the sweep rewrote.
    let stored =
        kr_pairing::platform::InvitationStore::load(&&harness.store, first.invitation_id())
            .expect("a read")
            .expect("a record");
    assert_eq!(stored.failed_confirmations, 1);
    let _ = second;
}

#[test]
fn a_locked_candidate_is_swept_by_a_restart_like_any_other() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    assert!(host.locked_attempt().is_some());

    let cancelled = cancel_unfinished_invitations(&harness.store).expect("a sweep");
    assert_eq!(cancelled, vec![host.invitation_id()]);
    // The next transition reads the record the sweep wrote rather than its own memory.
    assert!(matches!(
        approve(&harness, &mut host),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::HostRestarted
        })
    ));
}

#[test]
fn a_substituted_endpoint_at_finish_is_rejected() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("admitted");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    client
        .verify_host_confirmation(&confirmation.host_tag, &harness.clock)
        .expect("confirmed");

    let host_frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a frame");
    client
        .open_host_bundle(&host_frame, &harness.clock)
        .expect("a bundle");
    let client_frame = client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock,
        )
        .expect("a frame");
    host.open_client_bundle(admission.attempt_id, &client_frame)
        .expect("a bundle");

    // The candidate checks the host it reached against the authenticated bundle.
    let wrong_host = TestLivePeer::new(EndpointKey::from_bytes([0xaa; 32]));
    assert!(matches!(
        client.finish_request(
            &wrong_host,
            harness.client_keys.transport.public(),
            &harness.clock
        ),
        Err(PairingError::EndpointMismatch { side: "host" })
    ));
    assert!(client.is_finished(), "a mismatch ends the attempt");
}

#[test]
fn a_candidate_attempt_ends_at_its_first_failure_of_any_kind() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    // An early-data connection at pair.finish ends the attempt, the same as a wrong tag does.
    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("a slot");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    client
        .verify_host_confirmation(&confirmation.host_tag, &harness.clock)
        .expect("confirmed");
    let host_frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a frame");
    client
        .open_host_bundle(&host_frame, &harness.clock)
        .expect("a bundle");
    client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock,
        )
        .expect("a frame");

    let early = harness.host_peer();
    early.set_early_data(true);
    assert!(matches!(
        client.finish_request(
            &early,
            harness.client_keys.transport.public(),
            &harness.clock
        ),
        Err(PairingError::EarlyData)
    ));
    assert!(client.is_finished());
    // And it stays finished: a completed connection does not resume it.
    let host_peer = harness.host_peer();
    assert!(matches!(
        client.finish_request(
            &host_peer,
            harness.client_keys.transport.public(),
            &harness.clock
        ),
        Err(PairingError::WrongPhase { .. })
    ));
}

#[test]
fn a_client_bundle_that_lies_about_its_endpoint_ends_the_attempt() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("a slot");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    client
        .verify_host_confirmation(&confirmation.host_tag, &harness.clock)
        .expect("confirmed");
    let host_frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a frame");
    client
        .open_host_bundle(&host_frame, &harness.clock)
        .expect("a bundle");

    let mut inconsistent = client_bundle(&harness.client_keys);
    inconsistent.endpoint_id = EndpointKey::from_bytes([0x44; 32]);
    assert!(matches!(
        client.seal_client_bundle(
            &harness.client_keys.authorisation,
            inconsistent,
            &harness.clock
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
    assert!(client.is_finished(), "the attempt does not get another go");
    assert!(matches!(
        client.seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock
        ),
        Err(PairingError::WrongPhase { .. })
    ));
}

#[test]
fn a_write_that_lost_a_race_does_not_undo_the_writer_that_won() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    // The other entry mode cancels the invitation between this flow's read and its write. The
    // conditional write refuses rather than reopening a cancelled invitation.
    let mut cancelled = host.record().clone();
    cancelled.state = InvitationState::Consumed {
        reason: PairingConsumedReason::Cancelled,
    };
    harness.store.interleave(cancelled.clone());
    assert!(matches!(
        run_exchange(&harness, &mut host, &entered),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Cancelled
        })
    ));
    assert_eq!(host.record().state, cancelled.state);
    assert_eq!(
        harness
            .store
            .snapshot()
            .into_iter()
            .find(|record| record.invitation_id == host.invitation_id())
            .expect("a record")
            .state,
        cancelled.state,
        "the winner's write stands"
    );
}

#[test]
fn a_commit_that_lost_a_race_writes_nothing() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");

    // The owner cancels through another path after this flow read the record.
    let mut cancelled = host.record().clone();
    cancelled.state = InvitationState::Consumed {
        reason: PairingConsumedReason::Cancelled,
    };
    harness.store.interleave(cancelled.clone());
    assert!(matches!(
        approve(&harness, &mut host),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Cancelled
        })
    ));
    assert_eq!(
        recover_commitment(&&harness.store, host.invitation_id()).expect("a read"),
        None,
        "a commit that lost the race wrote no commitment either"
    );
}

#[test]
fn the_host_checks_the_candidate_it_is_talking_to_and_refuses_early_data() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");

    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), &entered)
            .expect("an attempt");
    let host_pake = host
        .admit(admission.attempt_id, admission.client_nonce)
        .expect("admitted");
    let client_pake = client
        .with_host_nonce(
            host.context(admission.attempt_id)
                .expect("a context")
                .host_nonce,
            &harness.clock,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    client
        .verify_host_confirmation(&confirmation.host_tag, &harness.clock)
        .expect("confirmed");
    let host_frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a frame");
    client
        .open_host_bundle(&host_frame, &harness.clock)
        .expect("a bundle");
    let client_frame = client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock,
        )
        .expect("a frame");
    host.open_client_bundle(admission.attempt_id, &client_frame)
        .expect("a bundle");

    let host_peer = harness.host_peer();
    let request = client
        .finish_request(
            &host_peer,
            harness.client_keys.transport.public(),
            &harness.clock,
        )
        .expect("a request");

    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0xbb; 32]));
    assert!(matches!(
        host.finish(&request, &impostor),
        Err(PairingError::EndpointMismatch { side: "client" })
    ));

    // The same request in 0-RTT is refused whatever endpoint it came from: early data is
    // replayable by anything that captured it.
    let replayed = harness.client_peer();
    replayed.set_early_data(true);
    assert!(matches!(
        host.finish(&request, &replayed),
        Err(PairingError::EarlyData)
    ));

    let client_peer = harness.client_peer();
    host.finish(&request, &client_peer).expect("a pairing");
}

#[test]
fn only_the_issuing_owner_confirms_or_cancels() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let approved = locked_values(&host);
    let approval = harness.device_approval(&approved);
    let stranger = owner(2);

    assert!(matches!(
        host.confirm(
            &approval.by(&stranger, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        host.cancel(&stranger),
        Err(PairingError::NotIssuingOwner)
    ));

    // Approving a different transcript is refused: the owner approves what it was shown.
    assert!(matches!(
        host.confirm(
            &approval.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &ApprovedCandidate {
                transcript: Digest256::from_bytes([0xcc; 32]),
                ..approved
            },
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::ContextMismatch { .. })
    ));

    // And a grant issued by some other host device is refused too.
    assert!(matches!(
        host.confirm(
            &approval.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &GrantIdentities {
                issuer_device_id: DeviceId::new(Uuid::from_bytes([0x5a; 16])),
                ..harness.grant_identities()
            },
            None,
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
}

#[test]
fn issuing_and_confirming_both_need_a_fresh_single_use_confirmation() {
    let harness = Harness::new();

    // A confirmation for another action does not issue an invitation.
    let wrong_action = harness.approval(
        SensitiveAction::EnlargeGrant,
        kr_pairing::confirm::action_digest(&proposal()).expect("a digest"),
        None,
    );
    assert!(matches!(
        HostInvitation::issue(
            &harness.store,
            &harness.clock,
            &harness.service,
            harness.proposal_for(),
            &wrong_action.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    // Nor does one naming a destination device: an invitation is issued before anybody answers it.
    let premature = harness.approval(
        SensitiveAction::IssueInvitation,
        kr_pairing::confirm::action_digest(&proposal()).expect("a digest"),
        Some(harness.client_keys.public_keys()),
    );
    assert!(matches!(
        HostInvitation::issue(
            &harness.store,
            &harness.clock,
            &harness.service,
            harness.proposal_for(),
            &premature.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    // Nor does one signed by anybody but the enrolled owner.
    let impostor = DeviceKeys::generate().expect("keys");
    let good = harness.issue_approval();
    assert!(matches!(
        HostInvitation::issue(
            &harness.store,
            &harness.clock,
            &harness.service,
            harness.proposal_for(),
            &good.by(&harness.issuing_owner, impostor.authorisation.public()),
            &mut harness.ledger.borrow_mut(),
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));
    // That challenge is still answerable: rubbish does not burn it.
    let mut host = HostInvitation::issue(
        &harness.store,
        &harness.clock,
        &harness.service,
        harness.proposal_for(),
        &good.by(&harness.issuing_owner, harness.signer()),
        &mut harness.ledger.borrow_mut(),
    )
    .expect("an invitation");

    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let approved = locked_values(&host);

    // A confirmation naming another candidate does not approve this one.
    let elsewhere = harness.device_approval(&ApprovedCandidate {
        transcript: Digest256::from_bytes([3; 32]),
        ..approved
    });
    assert!(matches!(
        host.confirm(
            &elsewhere.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    // Nor does one naming another device as its destination.
    let other_device = harness.approval(
        SensitiveAction::ConfirmDevice,
        approved.action_digest(),
        Some(impostor.public_keys()),
    );
    assert!(matches!(
        host.confirm(
            &other_device.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    approve(&harness, &mut host).expect("a commitment");
    // Four challenges were never answered, because the proofs presented for them described
    // something else. They stay answerable until they run out, and then they are gone.
    assert_eq!(harness.ledger.borrow().len(), 4);
    harness
        .clock
        .advance(kr_pairing::confirm::CONFIRMATION_LIFETIME_MS);
    harness.ledger.borrow_mut().expire(&harness.clock);
    assert!(harness.ledger.borrow().is_empty());
}

#[test]
fn a_transport_retry_retrieves_the_committed_result() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let approved = locked_values(&host);
    let first_approval = harness.device_approval(&approved);
    let first = host
        .confirm(
            &first_approval.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        )
        .expect("a commitment");
    // A retry with different identities still returns the committed result: it cannot replace the
    // public keys or the grant.
    let second = host
        .confirm(
            &first_approval.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &GrantIdentities {
                grant_id: GrantId::new(Uuid::from_bytes([0xee; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([0xdd; 16])),
                ..harness.grant_identities()
            },
            None,
        )
        .expect("the same commitment");
    assert_eq!(first, second);
}

#[test]
fn a_commitment_that_cannot_be_written_is_not_reported_as_a_pairing() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");

    harness.store.set_failing_writes(true);
    assert!(matches!(
        approve(&harness, &mut host),
        Err(PairingError::Store { .. })
    ));
    harness.store.set_failing_writes(false);
    assert_eq!(
        recover_commitment(&&harness.store, host.invitation_id()).expect("a read"),
        None,
        "nothing was written, so nothing is reported"
    );
}

#[test]
fn a_candidate_sees_only_its_own_status_from_its_own_endpoint() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let attempt_id = host.locked_attempt().expect("a candidate holds it");

    let peer = harness.client_peer();
    let status = host
        .status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &peer,
        })
        .expect("a status");
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(&*host.code().display_text()));
    assert!(!rendered.contains(&*host.code().secret().expose_text()));

    // Knowing the attempt identity is not enough: the asker must be that endpoint.
    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0x77; 32]));
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &impostor,
        }),
        Err(PairingError::NotIssuingOwner)
    ));

    let stranger = kr_pairing::host::new_attempt_id().expect("an attempt");
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(stranger),
            live_peer: &peer,
        }),
        Err(PairingError::NotIssuingOwner)
    ));

    // After the commitment the answer comes from the store, so it survives the attempts being
    // cleared, and it is still only for that candidate on its own endpoint.
    approve(&harness, &mut host).expect("a commitment");
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &peer,
        }),
        Ok(PairStatus::Committed { .. })
    ));
    assert!(matches!(
        host.status(StatusViewer::Candidate {
            attempt_id: Some(attempt_id),
            live_peer: &impostor,
        }),
        Err(PairingError::NotIssuingOwner)
    ));
}

#[test]
fn the_service_only_ever_sees_the_locator() {
    let harness = Harness::new();
    let host = harness.issue();
    let reserved = harness.service.reserved();
    assert_eq!(reserved, vec![host.code().locator().as_str().to_owned()]);
    let secret = host.code().secret().expose_text();
    for locator in &reserved {
        assert!(!secret.contains(locator.as_str()) || locator.len() == 4);
        assert!(!locator.contains(&*secret));
    }
}

#[test]
fn a_locator_collision_makes_the_host_try_another() {
    let harness = Harness::new();
    harness.service.collide_next(2);
    let host = harness.issue();
    assert_eq!(harness.service.reserved().len(), 1);
    assert_eq!(
        harness.service.reserved()[0],
        host.code().locator().as_str()
    );
}
