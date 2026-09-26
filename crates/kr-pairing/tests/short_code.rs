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

/// The digest an owner confirms to issue this suite's code invitation.
fn issue_digest() -> Digest256 {
    kr_protocol::invitation::issuance_digest(
        kr_protocol::invitation::InviteModeKind::Code,
        Some(&origin()),
        kr_protocol::invitation::InviteGrantKind::SessionInvitation,
        &proposal(),
    )
    .expect("a digest")
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
            network_config: NetworkConfig::empty(),
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
        self.approval(SensitiveAction::IssueInvitation, issue_digest(), None)
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
    run_exchange_with(harness, host, entered, client_bundle(&harness.client_keys))
}

/// Runs a complete exchange in which the candidate declares and signs `bundle`.
fn run_exchange_with(
    harness: &Harness,
    host: &mut Host<'_>,
    entered: &EnteredCode,
    bundle: ClientBundle,
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
    let client_frame =
        client.seal_client_bundle(&harness.client_keys.authorisation, bundle, &harness.clock)?;
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

/// KR-REQ-10.28, KR-REQ-10.29, KR-REQ-23.26: after the iroh binding the issuing owner sees the
/// candidate with the same eight-hex value both devices computed; the owner's confirmation commits
/// the device record and the proposed grant together, and a retry finds the commitment.
#[test]
fn a_complete_pairing_commits_the_device_and_the_proposed_grant() {
    // KR-REQ-01.16: a device pairs by the ten-character code a person reads off the host, with no
    // account anywhere in the exchange.
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

/// KR-REQ-10.31, KR-REQ-10.28: a successful PAKE locks the invitation to that candidate at once,
/// persisted, cancels the competing candidates and shows the owner no verification value yet.
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

/// KR-REQ-10.30: five failed confirmation tags consume the invitation, and the count is persisted
/// as it falls.
#[test]
fn a_wrong_code_exhausts_five_guesses_and_the_count_survives_a_restart() {
    assert_eq!(MAX_CONFIRMATION_FAILURES, 5, "section 10 allows five");
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

/// KR-REQ-10.30: a guess that cannot be persisted is never handed back.
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

/// Runs one candidate as far as its confirmation tag and leaves the host waiting to check it.
fn candidate_with_tag(
    harness: &Harness,
    host: &mut Host<'_>,
    entered: &EnteredCode,
) -> (kr_protocol::ids::AttemptId, kr_protocol::scalars::Mac256) {
    let budget = TestClientBudgetStore::new().expect("a store");
    let service = TestClient::new(LocatorRecord {
        invitation_id: host.invitation_id(),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), entered)
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
    let tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    (admission.attempt_id, tag)
}

/// KR-REQ-10.30: every candidate draws on the invitation's one allowance of five, including
/// candidates whose exchanges overlap. With two guesses left, three candidates holding a wrong code
/// are in flight at once: the first two failures spend the last two guesses and consume the
/// invitation, and the third, still waiting to be checked, is cancelled with it rather than given a
/// sixth guess. The right code is refused afterwards.
#[test]
fn concurrent_candidates_share_one_allowance() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
    assert_eq!(host.remaining_confirmations(), 5);

    for _ in 0..3 {
        let _ = run_exchange(&harness, &mut host, &wrong);
    }
    assert_eq!(host.remaining_confirmations(), 2);

    let in_flight: Vec<_> = (0..3)
        .map(|_| candidate_with_tag(&harness, &mut host, &wrong))
        .collect();
    assert_eq!(host.live_candidates(), 3);
    assert!(matches!(
        host.verify_client_confirmation(in_flight[0].0, &in_flight[0].1),
        Err(PairingError::AuthenticationFailed)
    ));
    assert_eq!(host.remaining_confirmations(), 1);
    assert_eq!(host.live_candidates(), 2);
    assert!(matches!(
        host.verify_client_confirmation(in_flight[1].0, &in_flight[1].1),
        Err(PairingError::AttemptsExhausted)
    ));
    assert_eq!(host.remaining_confirmations(), 0);
    assert_eq!(
        host.live_candidates(),
        0,
        "the candidate still in flight is cancelled with the invitation"
    );
    assert!(matches!(
        host.verify_client_confirmation(in_flight[2].0, &in_flight[2].1),
        Err(PairingError::Consumed { .. })
    ));
    assert_eq!(
        host.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::AttemptsExhausted
        }
    );
    let right = EnteredCode::parse(&host.code().display_text()).expect("the code");
    assert!(matches!(
        run_exchange(&harness, &mut host, &right),
        Err(PairingError::Consumed { .. })
    ));
}

/// KR-REQ-10.30: an abandoned candidate costs a slot and its deadline, never a guess.
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

/// KR-REQ-10.31: the candidate an invitation is locked to cannot be displaced.
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

/// KR-REQ-10.19: a denial is reported to the candidate as a denial.
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

/// KR-REQ-10.16, KR-REQ-10.13: what the service returns stays untrusted until the PAKE confirms it,
/// and the host's own deadline governs whatever expiry the service advertises.
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

/// KR-REQ-10.04, KR-REQ-10.13: an invitation lives five minutes on the host's monotonic deadline.
#[test]
fn an_invitation_expires_on_the_hosts_own_clock() {
    assert_eq!(
        INVITATION_LIFETIME_MS,
        5 * 60 * 1000,
        "an invitation lasts five minutes"
    );
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

/// KR-REQ-10.13: the deadline is monotonic; winding the wall clock back does not extend it.
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

/// KR-REQ-10.33: a host restart cancels every unfinished invitation and keeps the failure count.
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

/// KR-REQ-10.33: a restart cancels a locked invitation too, and nothing resumes it.
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

/// KR-REQ-10.27: the candidate checks the host it reached against the authenticated host bundle.
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

/// KR-REQ-10.27, KR-REQ-10.21: `pair.finish` is never sent in 0-RTT, and an attempt that failed
/// is never resumed.
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

/// KR-REQ-10.26: a client bundle declaring another endpoint than its own transport key is refused.
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

/// KR-REQ-10.27: the host checks the live peer against the authenticated client endpoint and
/// refuses `pair.finish` in 0-RTT.
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

/// KR-REQ-10.26: a device name is display text and never authority. A candidate whose validly
/// signed bundle names it after the issuing owner, or after the host itself, is committed like any
/// other: under the device identity the host assigns, with the invitation's grant and nothing
/// more, and the name is kept only as the name.
#[test]
fn a_device_name_confers_no_authority() {
    let mut grants = Vec::new();
    for name in ["A phone", "owner-1", "The host's own owner device"] {
        let harness = Harness::new();
        let mut host = harness.issue();
        let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
        let mut bundle = client_bundle(&harness.client_keys);
        bundle.device_name = DeviceName::new(name).expect("a name");
        run_exchange_with(&harness, &mut host, &entered, bundle).expect("a pairing");
        let committed = approve(&harness, &mut host).expect("a commitment");
        assert_eq!(
            committed
                .client_bundle
                .as_ref()
                .expect("the candidate's declaration")
                .device_name
                .as_str(),
            name
        );
        assert_eq!(
            committed.device_id,
            harness.grant_identities().recipient_device_id,
            "{name}: the device identity is the one the host assigned"
        );
        assert_ne!(committed.device_id, harness.host_device_id);
        assert_eq!(committed.grant.actions, proposal().actions, "{name}");
        grants.push(committed.grant);
    }
    assert!(
        grants.windows(2).all(|pair| pair[0] == pair[1]),
        "the grant is the same whatever the name says"
    );
}

/// KR-REQ-10.29, KR-REQ-23.26: `pair.confirm` needs the issuing owner and the exact transcript and
/// bundle hashes it was shown.
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

    // Approving a different transcript, or either bundle hash other than the ones the owner was
    // shown, is refused: the owner approves exactly what it was shown.
    for (what, other) in [
        (
            "the transcript",
            ApprovedCandidate {
                transcript: Digest256::from_bytes([0xcc; 32]),
                ..approved
            },
        ),
        (
            "the host bundle hash",
            ApprovedCandidate {
                host_bundle_hash: Digest256::from_bytes([0xcc; 32]),
                ..approved
            },
        ),
        (
            "the client bundle hash",
            ApprovedCandidate {
                client_bundle_hash: Digest256::from_bytes([0xcc; 32]),
                ..approved
            },
        ),
    ] {
        assert!(
            matches!(
                host.confirm(
                    &approval.by(&harness.issuing_owner, harness.signer()),
                    &mut harness.ledger.borrow_mut(),
                    &other,
                    &harness.grant_identities(),
                    None,
                ),
                Err(PairingError::ContextMismatch { .. })
            ),
            "an approval naming another {what} is refused"
        );
    }
    assert!(
        recover_commitment(&&harness.store, host.invitation_id())
            .expect("a read")
            .is_none(),
        "nothing was committed"
    );

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

/// KR-REQ-10.05: issuing and confirming each need their own fresh confirmation, bound to the
/// action, digest and destination and signed by the enrolled owner.
/// KR-REQ-02.09: issuing a pairing invitation and confirming a new device, both of which enlarge
/// what can reach this host, each need a fresh owner confirmation for exactly that action.
#[test]
fn issuing_and_confirming_both_need_a_fresh_single_use_confirmation() {
    let harness = Harness::new();

    // A confirmation for another action does not issue an invitation.
    let wrong_action = harness.approval(SensitiveAction::EnlargeGrant, issue_digest(), None);
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
        issue_digest(),
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

/// KR-REQ-10.29: a transport retry retrieves the committed result and cannot replace its keys or
/// grant. A hostile retry under a fresh confirmation naming another device's keys, wider rights and
/// another client bundle hash is answered with the first commitment, and the stored device keys and
/// grant stay the ones the owner approved.
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

    let replacement = DeviceKeys::generate().expect("keys");
    let wider: BTreeSet<ActionRight> = [ActionRight::SessionView, ActionRight::TerminalInput]
        .into_iter()
        .collect();
    let hostile_request = request_confirmation(
        &harness.clock,
        SensitiveAction::ConfirmDevice,
        approved.action_digest(),
        Some(replacement.public_keys()),
        wider,
        harness.host_device_id,
        *harness.host_keys.transport.public(),
    )
    .expect("a challenge");
    harness
        .ledger
        .borrow_mut()
        .issue(&hostile_request, &harness.clock);
    let hostile = Approval {
        proof: sign_confirmation(
            &harness.owner_keys.authorisation,
            &hostile_request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof"),
        request: hostile_request,
    };
    let third = host
        .confirm(
            &hostile.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &ApprovedCandidate {
                client_bundle_hash: Digest256::from_bytes([0xab; 32]),
                ..approved
            },
            &harness.grant_identities(),
            None,
        )
        .expect("the committed result");
    assert_eq!(third, first);
    let stored = recover_commitment(&&harness.store, host.invitation_id())
        .expect("a read")
        .expect("a commitment");
    assert_eq!(stored, first);
    assert_eq!(stored.client_keys, harness.client_keys.public_keys());
    assert_eq!(stored.grant.actions, proposal().actions);
    assert_ne!(stored.client_keys, replacement.public_keys());
}

/// KR-REQ-10.29: the device record, grant and consumed invitation are one write, and nothing is
/// reported until it is done.
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

/// KR-REQ-10.12, KR-REQ-10.16: the service is sent the four locator characters and never the secret
/// six. Every request it received carries the origin, the locator, the invitation, the advertised
/// expiry and the token hash, and none of them carries the secret.
#[test]
fn the_service_only_ever_sees_the_locator() {
    let harness = Harness::new();
    harness.service.collide_next(1);
    let host = harness.issue();
    let reserved = harness.service.reserved();
    assert_eq!(reserved, vec![host.code().locator().as_str().to_owned()]);
    let secret = host.code().secret().expose_text();
    let requests = harness.service.requests();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(request.locator.len(), 4);
        assert_eq!(request.origin, origin().as_str());
        let sent = format!(
            "{} {} {} {} {}",
            request.origin,
            request.locator,
            request.invitation_id.get(),
            request.advertised_expires_at_ms.get(),
            hex::encode(request.control_token_hash.as_bytes())
        );
        assert!(!sent.contains(&*secret), "the secret reached the service");
    }
}

/// KR-REQ-10.12: a locator collision makes the host generate another locator. The service is
/// asked three times for the one invitation after two collisions, each time for a different
/// locator, and the locator the invitation holds is the one the third request was granted.
#[test]
fn a_locator_collision_makes_the_host_try_another() {
    let harness = Harness::new();
    harness.service.collide_next(2);
    let host = harness.issue();
    let requests = harness.service.requests();
    assert_eq!(requests.len(), 3, "two collisions and one grant");
    let locators: BTreeSet<&str> = requests
        .iter()
        .map(|request| request.locator.as_str())
        .collect();
    assert_eq!(
        locators.len(),
        3,
        "every collision brought another locator: {locators:?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.invitation_id == host.invitation_id())
    );
    assert_eq!(requests[2].locator, host.code().locator().as_str());
    assert_eq!(
        harness.service.reserved(),
        vec![host.code().locator().as_str().to_owned()]
    );
}

/// KR-REQ-10.13: the record-control token is 256 random bits the host keeps. Each reservation
/// request carries only its SHA-256, and releasing the reservation later proves possession of the
/// token that hash was taken of: the service releases it for the host's token and for no other.
#[test]
fn the_service_holds_only_the_hash_of_the_control_token_the_host_keeps() {
    use kr_pairing::platform::RendezvousHost;

    let harness = Harness::new();
    harness.service.collide_next(1);
    let host = harness.issue();
    let requests = harness.service.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].control_token_hash, requests[1].control_token_hash,
        "one invitation, one token"
    );

    let locator = host.code().locator().clone();
    let guessed = kr_crypto::secret::SymmetricKey::random().expect("a key");
    assert!(
        harness
            .service
            .release_locator(host.origin(), &locator, &guessed)
            .is_err(),
        "a token the hash was not taken of releases nothing"
    );
    assert_eq!(harness.service.reserved().len(), 1);
    host.release(&harness.service)
        .expect("the host holds the token its hash was taken of");
    assert_eq!(
        harness.service.released(),
        vec![locator.as_str().to_owned()]
    );

    // A second invitation has a token of its own.
    let other = harness.issue();
    let latest = harness.service.requests();
    assert_ne!(
        latest[latest.len() - 1].control_token_hash,
        requests[1].control_token_hash
    );
    drop(other);
}

/// KR-REQ-10.07: an owner confirmation that arrives over a session, plugin or contact-tool channel
/// is not a confirmation, even when the owner's own key signed it. The host issues nothing,
/// reserves no locator and writes no invitation for it.
#[test]
fn a_confirmation_over_a_session_plugin_or_contact_tool_channel_issues_nothing() {
    let harness = Harness::new();
    for channel in [
        ConfirmationChannel::Session,
        ConfirmationChannel::Plugin,
        ConfirmationChannel::ContactTool,
    ] {
        let request = request_confirmation(
            &harness.clock,
            SensitiveAction::IssueInvitation,
            kr_pairing::confirm::action_digest(&proposal()).expect("a digest"),
            None,
            proposal().actions.iter().copied().collect::<BTreeSet<_>>(),
            harness.host_device_id,
            *harness.host_keys.transport.public(),
        )
        .expect("a challenge");
        harness.ledger.borrow_mut().issue(&request, &harness.clock);
        let proof = sign_confirmation(&harness.owner_keys.authorisation, &request, channel)
            .expect("a proof");
        let noninteractive = Approval { request, proof };
        assert!(
            matches!(
                HostInvitation::issue(
                    &harness.store,
                    &harness.clock,
                    &harness.service,
                    harness.proposal_for(),
                    &noninteractive.by(&harness.issuing_owner, harness.signer()),
                    &mut harness.ledger.borrow_mut(),
                ),
                Err(PairingError::OwnerConfirmationRequired)
            ),
            "{channel:?} is not a confirmation"
        );
    }
    assert!(harness.store.snapshot().is_empty(), "no invitation exists");
    assert!(
        harness.service.reserved().is_empty(),
        "no locator was reserved"
    );
}

/// Runs an exchange up to the candidate's `pair.finish` request and returns it unsent.
fn exchange_until_finish(
    harness: &Harness,
    host: &mut Host<'_>,
) -> kr_protocol::pairing::PairFinishRequest {
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
    let client_frame = client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock,
        )
        .expect("a frame");
    host.open_client_bundle(admission.attempt_id, &client_frame)
        .expect("a bundle");
    client
        .finish_request(
            &harness.host_peer(),
            harness.client_keys.transport.public(),
            &harness.clock,
        )
        .expect("a request")
}

/// Rewrites one member of a `pair.finish` request.
type Tamper = fn(&mut kr_protocol::pairing::PairFinishRequest);

/// Checks that the issuing owner has nothing to approve yet: the invitation is locked to a
/// candidate, no verification value is shown, and an approval is refused.
fn nothing_to_approve(harness: &Harness, host: &mut Host<'_>, when: &str) {
    let status = host
        .status(StatusViewer::IssuingOwner(&harness.issuing_owner))
        .expect("a status");
    assert!(
        matches!(status, PairStatus::Locked { .. }),
        "{when}: the owner is shown {status:?}"
    );
    assert!(
        matches!(approve(harness, host), Err(PairingError::WrongPhase { .. })),
        "{when}: the owner can approve"
    );
    assert!(
        matches!(host.record().state, InvitationState::Locked { .. }),
        "{when}: the invitation moved on"
    );
}

/// KR-REQ-10.27: `pair.finish` names the invitation and attempt, `T`, both bundle hashes and a tag
/// under the `iroh-bind` key, and the host accepts it only when every one of those is the one this
/// attempt produced.
/// KR-REQ-10.28: only the binding brings a candidate to the owner. Before `pair.finish`, and after
/// each refused one, the issuing owner is shown a locked invitation with no verification value and
/// cannot approve it; the request the candidate built shows the eight-hex value and makes approval
/// possible.
#[test]
fn a_finish_request_that_names_anything_else_is_refused() {
    let tampered: [(&str, Tamper); 6] = [
        ("the invitation", |request| {
            request.invitation_id =
                kr_protocol::ids::InvitationId::new(Uuid::from_bytes([0xee; 16]));
        }),
        ("the attempt", |request| {
            request.attempt_id = kr_protocol::ids::AttemptId::new(Uuid::from_bytes([0xee; 16]));
        }),
        ("the transcript", |request| {
            request.transcript = Digest256::from_bytes([0xee; 32]);
        }),
        ("the host bundle hash", |request| {
            request.host_bundle_hash = Digest256::from_bytes([0xee; 32]);
        }),
        ("the client bundle hash", |request| {
            request.client_bundle_hash = Digest256::from_bytes([0xee; 32]);
        }),
        ("the binding tag", |request| {
            request.binding_tag = kr_protocol::scalars::Mac256::from_bytes([0xee; 32]);
        }),
    ];
    for (what, tamper) in tampered {
        let harness = Harness::new();
        let mut host = harness.issue();
        let mut request = exchange_until_finish(&harness, &mut host);
        nothing_to_approve(&harness, &mut host, "before the binding");
        tamper(&mut request);
        assert!(
            host.finish(&request, &harness.client_peer()).is_err(),
            "a request naming another {what} is refused"
        );
        nothing_to_approve(&harness, &mut host, what);
    }

    // The request as the candidate built it binds, and only then is there something to approve.
    let harness = Harness::new();
    let mut host = harness.issue();
    let request = exchange_until_finish(&harness, &mut host);
    nothing_to_approve(&harness, &mut host, "before the binding");
    let locked = host
        .finish(&request, &harness.client_peer())
        .expect("the untouched request binds");
    let status = host
        .status(StatusViewer::IssuingOwner(&harness.issuing_owner))
        .expect("a status");
    let PairStatus::AwaitingApproval {
        verification_value, ..
    } = status
    else {
        panic!("the owner is asked to approve once the binding holds: {status:?}");
    };
    assert_eq!(verification_value, locked.verification_value);
    assert_eq!(verification_value.len(), 8);
    approve(&harness, &mut host).expect("the owner approves the bound candidate");
}

/// KR-REQ-10.19: each failure a person can act on reports its own code. A rendezvous service that
/// cannot be reached, from the host issuing or from the candidate looking a locator up, an
/// expired invitation, a denied approval and exhausted attempts are told apart, while a wrong code
/// and a service that pointed at another invitation fail with the one ambiguous authentication code
/// and the same message, which names neither cause.
#[test]
fn each_failure_kind_reports_its_own_code_and_authentication_stays_ambiguous() {
    use kr_protocol::error::ErrorCode;

    let harness = Harness::new();
    harness.service.fail_next(1);
    let approval = harness.issue_approval();
    let Err(unreachable) = HostInvitation::issue(
        &harness.store,
        &harness.clock,
        &harness.service,
        harness.proposal_for(),
        &approval.by(&harness.issuing_owner, harness.signer()),
        &mut harness.ledger.borrow_mut(),
    ) else {
        panic!("the service cannot be reached");
    };
    assert_eq!(unreachable.code(), ErrorCode::RendezvousUnavailable);
    assert!(
        harness.store.snapshot().is_empty(),
        "no invitation is written"
    );

    let harness = Harness::new();
    let host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    let budget = TestClientBudgetStore::new().expect("a store");
    let Err(lookup) = ClientAttempt::start(
        &budget,
        &harness.clock,
        &TestClient::unreachable(),
        &origin(),
        &entered,
    ) else {
        panic!("the candidate's service cannot be reached");
    };
    assert_eq!(lookup.code(), ErrorCode::RendezvousUnavailable);

    // A service that answers but never grants a locator is unavailable to the host as well.
    let harness = Harness::new();
    harness.service.collide_next(1_000);
    let approval = harness.issue_approval();
    let Err(exhausted_locators) = HostInvitation::issue(
        &harness.store,
        &harness.clock,
        &harness.service,
        harness.proposal_for(),
        &approval.by(&harness.issuing_owner, harness.signer()),
        &mut harness.ledger.borrow_mut(),
    ) else {
        panic!("no locator can be reserved");
    };
    assert_eq!(exhausted_locators.code(), ErrorCode::RendezvousUnavailable);

    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    harness.clock.advance(INVITATION_LIFETIME_MS);
    let expired = run_exchange(&harness, &mut host, &entered).expect_err("expired");
    assert_eq!(expired.code(), ErrorCode::PairingExpired);

    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    host.deny(&harness.issuing_owner).expect("a denial");
    let denied = host
        .admit(
            kr_pairing::host::new_attempt_id().expect("an attempt"),
            kr_pairing::host::new_nonce().expect("a nonce"),
        )
        .expect_err("a denied invitation admits nobody");
    assert_eq!(denied.code(), ErrorCode::PairingRejected);

    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
    let wrong_code = run_exchange(&harness, &mut host, &wrong).expect_err("a wrong code");
    assert_eq!(wrong_code.code(), ErrorCode::PairingAuthFailed);
    for _ in 2..MAX_CONFIRMATION_FAILURES {
        let again = run_exchange(&harness, &mut host, &wrong).expect_err("a wrong code");
        assert_eq!(again.code(), ErrorCode::PairingAuthFailed);
    }
    let exhausted = run_exchange(&harness, &mut host, &wrong).expect_err("the last guess");
    assert_eq!(exhausted.code(), ErrorCode::PairingAttemptsExhausted);

    // A service that answered with another invitation: the right code, the wrong invitation.
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    let budget = TestClientBudgetStore::new().expect("a store");
    let forged = TestClient::new(LocatorRecord {
        invitation_id: kr_protocol::ids::InvitationId::new(Uuid::from_bytes([0xee; 16])),
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &forged, &origin(), &entered)
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
    let misdirected = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect_err("another invitation");
    assert_eq!(misdirected.code(), ErrorCode::PairingAuthFailed);
    assert_eq!(
        misdirected.to_string(),
        wrong_code.to_string(),
        "the two causes are indistinguishable"
    );
}

/// KR-REQ-10.13: an invitation identity is 128 random bits. Across many invitations no two repeat
/// and no bit is fixed, so nothing about it is a counter, a clock or a version marker.
#[test]
fn an_invitation_identity_is_one_hundred_and_twenty_eight_random_bits() {
    let harness = Harness::new();
    let identities: Vec<[u8; 16]> = (0..64)
        .map(|_| *harness.issue().invitation_id().get().as_bytes())
        .collect();
    let distinct: BTreeSet<&[u8; 16]> = identities.iter().collect();
    assert_eq!(distinct.len(), identities.len(), "no identity repeats");
    for bit in 0..128 {
        let set = identities
            .iter()
            .filter(|identity| identity[bit / 8] & (1 << (bit % 8)) != 0)
            .count();
        assert!(
            set > 0 && set < identities.len(),
            "bit {bit} of the identity never varies"
        );
    }
}

/// KR-REQ-10.23: the confirmation runs in its order. The host seals nothing for a candidate whose
/// tag it has not verified, and the candidate opens nothing from a host whose tag it has not
/// verified, so no host metadata is trusted before both tags are checked.
#[test]
fn no_bundle_moves_before_both_confirmation_tags_are_verified() {
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

    assert!(
        matches!(
            host.seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation),
            Err(PairingError::WrongPhase { .. })
        ),
        "the host sends nothing before the candidate's tag verifies"
    );

    let client_tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    host.verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("the candidate's tag verifies");
    let host_frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a frame");
    assert!(
        matches!(
            client.open_host_bundle(&host_frame, &harness.clock),
            Err(PairingError::WrongPhase { .. })
        ),
        "the candidate trusts nothing from the host before the host's tag verifies"
    );
}

/// KR-REQ-10.33: an invitation nobody used is consumed as expired once its deadline passes, when
/// the host asks before offering another, and not a moment before. Its reservation still names the
/// locator and origin, so the host can release it.
#[test]
fn an_unused_code_invitation_is_consumed_as_expired_once_its_deadline_passes() {
    let harness = Harness::new();
    let mut host = harness.issue();
    host.expire_if_due().expect("checked");
    assert_eq!(host.record().state, InvitationState::Open);
    harness.clock.advance(INVITATION_LIFETIME_MS);
    host.expire_if_due().expect("checked");
    assert_eq!(
        host.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::Expired
        }
    );
    assert_eq!(&host.reservation().locator, host.code().locator());
    host.release(&harness.service)
        .expect("the reservation is released at its origin");
}

/// KR-REQ-10.51: a pairing invitation shows its issuer no preview of a named resource, so a code
/// invitation whose proposal names a current approval or question is not issued, even under an
/// owner's confirmation of exactly that proposal, and nothing is written. The control is the
/// suite's own proposal, issued as before.
#[test]
fn a_code_invitation_that_names_a_current_approval_or_question_is_not_issued() {
    let harness = Harness::new();
    for approval in [true, false] {
        let mut named = proposal();
        if approval {
            named
                .history
                .named_approvals
                .insert(kr_protocol::ids::PendingResourceId::new(Uuid::from_bytes(
                    [0x52; 16],
                )));
        } else {
            named
                .history
                .named_questions
                .insert(kr_protocol::ids::QuestionId::new(Uuid::from_bytes(
                    [0x51; 16],
                )));
        }
        let confirmed = harness.approval(
            SensitiveAction::IssueInvitation,
            kr_protocol::invitation::issuance_digest(
                kr_protocol::invitation::InviteModeKind::Code,
                Some(&origin()),
                kr_protocol::invitation::InviteGrantKind::SessionInvitation,
                &named,
            )
            .expect("a digest"),
            None,
        );
        let refused = HostInvitation::issue(
            &harness.store,
            &harness.clock,
            &harness.service,
            InvitationProposal {
                proposed_grant: named,
                ..harness.proposal_for()
            },
            &confirmed.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
        );
        assert!(
            matches!(refused, Err(PairingError::GrantNotPermitted { .. })),
            "a proposal naming a current {} is not issued",
            if approval { "approval" } else { "question" }
        );
    }
    assert!(harness.store.snapshot().is_empty(), "nothing was written");
    assert_eq!(harness.issue().record().state, InvitationState::Open);
}
