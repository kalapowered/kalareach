//! The host's durable pairing records, driven by kr-pairing's own state machine.
//!
//! Every test here writes a real registry database on the internal disk and reads it back through
//! a second connection, which is what a restarted daemon does.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use kr_controller::service::net::devices::DeviceDirectory;
use kr_controller::service::net::invitations::{
    HostOwner, InvitationRows, IssueTerms, device_record, prepare,
};
use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::confirm::{
    ConfirmationLedger, HostEnrolment, request_confirmation, sign_confirmation,
};
use kr_pairing::grants::{GrantIdentities, GrantKind};
use kr_pairing::host::{
    ApprovedCandidate, HostIdentity, HostInvitation, InvitationProposal, OwnerApproval,
    OwnerContext, cancel_unfinished_invitations,
};
use kr_pairing::platform::{
    InvitationState, InvitationStore, LocatorRecord, PairingCommitment, TestClient,
    TestClientBudgetStore, TestClock, TestLivePeer, TestRendezvousHost,
};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ActionId, ActorId, AuthorityRevision, DeviceId, DeviceKeyRevision, GrantId, InvitationId,
};
use kr_protocol::invitation::{InviteGrantKind, InviteModeKind};
use kr_protocol::pairing::{
    ClientBundle, ConfirmationChannel, DeviceName, DevicePlatform, DevicePublicKeys,
    MAX_CONFIRMATION_FAILURES, NetworkConfig, OwnerConfirmationProof, OwnerConfirmationRequest,
    PairingConsumedReason, ProposedGrant, RendezvousOrigin, SensitiveAction,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, Nullable, TimestampMs, Uuid,
};

fn origin() -> RendezvousOrigin {
    RendezvousOrigin::new("https://reach.kala.to").expect("an origin")
}

fn viewer_grant() -> ProposedGrant {
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

/// Opens the registry database at `path` the way a starting daemon does.
fn open(path: &Path) -> (Arc<DeviceDirectory>, InvitationRows) {
    let directory = Arc::new(DeviceDirectory::open(path).expect("the registry database opens"));
    prepare(&directory).expect("the pairing tables exist");
    let rows = InvitationRows::new(Arc::clone(&directory));
    (directory, rows)
}

struct Approval {
    request: OwnerConfirmationRequest,
    proof: OwnerConfirmationProof,
}

/// One host, one owner and one candidate over a durable store.
struct Harness {
    rows: InvitationRows,
    clock: TestClock,
    service: TestRendezvousHost,
    ledger: Mutex<ConfirmationLedger>,
    host_keys: DeviceKeys,
    client_keys: DeviceKeys,
    owner_keys: DeviceKeys,
    owner: OwnerContext,
    grant: ProposedGrant,
    grant_kind: GrantKind,
}

type Host<'a> = HostInvitation<InvitationRows, &'a TestClock>;

impl Harness {
    fn new(rows: InvitationRows) -> Self {
        Self {
            rows,
            clock: TestClock::new(),
            service: TestRendezvousHost::new(),
            ledger: Mutex::new(ConfirmationLedger::new()),
            host_keys: DeviceKeys::generate().expect("keys"),
            client_keys: DeviceKeys::generate().expect("keys"),
            owner_keys: DeviceKeys::generate().expect("keys"),
            owner: OwnerContext {
                actor_id: ActorId::new("local:501").expect("a principal"),
                ingress: ActorIngress::LocalIpc,
            },
            grant: viewer_grant(),
            grant_kind: GrantKind::SessionInvitation,
        }
    }

    fn host_device(&self) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([1; 16]))
    }

    fn identity(&self) -> HostIdentity {
        HostIdentity {
            device_id: self.host_device(),
            endpoint_id: *self.host_keys.transport.public(),
            keys: self.host_keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            network_config: NetworkConfig::empty(),
        }
    }

    fn approval(
        &self,
        action: SensitiveAction,
        digest: Digest256,
        destination: Option<DevicePublicKeys>,
    ) -> Approval {
        let request = request_confirmation(
            &self.clock,
            action,
            digest,
            destination,
            self.grant.actions.iter().copied().collect::<BTreeSet<_>>(),
            self.host_device(),
            *self.host_keys.transport.public(),
        )
        .expect("a challenge");
        self.ledger
            .lock()
            .expect("the ledger")
            .issue(&request, &self.clock);
        let proof = sign_confirmation(
            &self.owner_keys.authorisation,
            &request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        Approval { request, proof }
    }

    fn by<'a>(&'a self, approval: &'a Approval, signer: &'a AuthorisationKey) -> OwnerApproval<'a> {
        OwnerApproval {
            owner: &self.owner,
            signer,
            enrolment: HostEnrolment::Enrolled,
            request: &approval.request,
            proof: &approval.proof,
        }
    }

    fn terms(&self, action: Option<(ActionId, Digest256)>) -> IssueTerms {
        IssueTerms {
            mode: InviteModeKind::Code,
            rendezvous_origin: Some(origin()),
            grant_kind: match self.grant_kind {
                GrantKind::PersonalOwner => InviteGrantKind::PersonalOwner,
                GrantKind::SessionInvitation => InviteGrantKind::SessionInvitation,
            },
            proposed_grant: self.grant.clone(),
            issuing_actor: self.owner.actor_id.clone(),
            issuing_ingress: self.owner.ingress,
            action,
            issued_at_ms: TimestampMs::new(self.clock_wall()),
        }
    }

    fn clock_wall(&self) -> u64 {
        use kr_pairing::platform::PairingClock as _;
        self.clock.wall_clock_ms()
    }

    fn issue_under(&self, action: Option<(ActionId, Digest256)>) -> Host<'_> {
        let approval = self.approval(
            SensitiveAction::IssueInvitation,
            kr_pairing::confirm::action_digest(&self.grant).expect("a digest"),
            None,
        );
        HostInvitation::issue(
            self.rows.issuing(self.terms(action)),
            &self.clock,
            &self.service,
            InvitationProposal {
                origin: origin(),
                host: self.identity(),
                proposed_grant: self.grant.clone(),
                grant_kind: self.grant_kind,
            },
            &self.by(&approval, self.owner_keys.authorisation.public()),
            &mut self.ledger.lock().expect("the ledger"),
        )
        .expect("an invitation")
    }

    fn issue(&self) -> Host<'_> {
        self.issue_under(None)
    }

    fn identities(&self) -> GrantIdentities {
        GrantIdentities {
            grant_id: GrantId::new(Uuid::from_bytes([8; 16])),
            issuer_device_id: self.host_device(),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
            authority_revision: AuthorityRevision::new(1),
        }
    }
}

/// Runs a candidate's exchange up to the host's verdict on its confirmation tag.
fn guess(
    harness: &Harness,
    host: &mut Host<'_>,
    entered: &EnteredCode,
) -> Result<(), PairingError> {
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
    host.verify_client_confirmation(admission.attempt_id, &client_tag)?;
    Ok(())
}

/// Runs a whole exchange with the right code, up to the owner's approval.
fn bind(harness: &Harness, host: &mut Host<'_>) -> ApprovedCandidate {
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
        .expect("received");
    let tag = client
        .receive_host_pake(&host_pake, &harness.clock)
        .expect("a tag");
    let confirmation = host
        .verify_client_confirmation(admission.attempt_id, &tag)
        .expect("confirmed");
    client
        .verify_host_confirmation(&confirmation.host_tag, &harness.clock)
        .expect("the host confirmed");
    let frame = host
        .seal_host_bundle(admission.attempt_id, &harness.host_keys.authorisation)
        .expect("a host bundle");
    client
        .open_host_bundle(&frame, &harness.clock)
        .expect("opened");
    let frame = client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
            &harness.clock,
        )
        .expect("a client bundle");
    host.open_client_bundle(admission.attempt_id, &frame)
        .expect("opened");
    let host_peer = TestLivePeer::new(*harness.host_keys.transport.public());
    let request = client
        .finish_request(
            &host_peer,
            harness.client_keys.transport.public(),
            &harness.clock,
        )
        .expect("a finish");
    let client_peer = TestLivePeer::new(*harness.client_keys.transport.public());
    host.finish(&request, &client_peer).expect("bound");
    host.locked_candidate()
        .expect("digests")
        .expect("a locked candidate")
}

fn approve(harness: &Harness, host: &mut Host<'_>) -> Result<PairingCommitment, PairingError> {
    let approved = host
        .locked_candidate()
        .expect("digests")
        .expect("a locked candidate");
    let approval = harness.approval(
        SensitiveAction::ConfirmDevice,
        approved.action_digest(),
        Some(harness.client_keys.public_keys()),
    );
    host.confirm(
        &harness.by(&approval, harness.owner_keys.authorisation.public()),
        &mut harness.ledger.lock().expect("the ledger"),
        &approved,
        &harness.identities(),
        None,
    )
}

/// A code with the same locator and a different secret, which verifies and does not match.
fn wrong_code(host: &Host<'_>) -> EnteredCode {
    let text = host.code().display_text().to_string();
    let replacement = if text.ends_with('z') { 'y' } else { 'z' };
    let mut wrong = text[..text.len() - 1].to_owned();
    wrong.push(replacement);
    EnteredCode::parse(&wrong).expect("a well-formed code")
}

fn stored(path: &Path, invitation_id: InvitationId) -> kr_pairing::platform::InvitationRecord {
    let (_, rows) = open(path);
    rows.load(invitation_id)
        .expect("readable")
        .expect("a record")
}

/// KR-REQ-10.30: every verified wrong tag is counted once, written before the host answers, and
/// the fifth consumes the invitation. A second connection to the database, which is what a restarted
/// daemon reads, sees each count the moment the host has reported it.
#[test]
fn a_wrong_tag_is_counted_once_and_on_disk_before_the_host_answers() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (_, rows) = open(&path);
    let harness = Harness::new(rows);
    let mut host = harness.issue();
    let wrong = wrong_code(&host);
    for spent in 1..MAX_CONFIRMATION_FAILURES {
        assert!(matches!(
            guess(&harness, &mut host, &wrong),
            Err(PairingError::AuthenticationFailed)
        ));
        let record = stored(&path, host.invitation_id());
        assert_eq!(record.failed_confirmations, spent);
        assert_eq!(record.state, InvitationState::Open);
    }
    assert!(matches!(
        guess(&harness, &mut host, &wrong),
        Err(PairingError::AttemptsExhausted)
    ));
    let record = stored(&path, host.invitation_id());
    assert_eq!(record.failed_confirmations, MAX_CONFIRMATION_FAILURES);
    assert_eq!(
        record.state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::AttemptsExhausted
        }
    );
    // Nothing further is admitted, the right code included.
    let right = EnteredCode::parse(&host.code().display_text()).expect("the code");
    assert!(guess(&harness, &mut host, &right).is_err());
}

/// One candidate's guess, with every host step taken under the invitation's own lock and every
/// candidate step outside it, so several candidates interleave the way concurrent ones do.
fn interleaved_guess(
    harness: &Harness,
    host: &Mutex<Host<'_>>,
    entered: &EnteredCode,
) -> Result<(), PairingError> {
    let budget = TestClientBudgetStore::new().expect("a store");
    let invitation_id = host.lock().expect("the host").invitation_id();
    let service = TestClient::new(LocatorRecord {
        invitation_id,
        advertised_expires_at_ms: TimestampMs::new(0),
    });
    let (mut client, admission, _) =
        ClientAttempt::start(&budget, &harness.clock, &service, &origin(), entered)?;
    let (host_pake, host_nonce) = {
        let mut host = host.lock().expect("the host");
        let message = host.admit(admission.attempt_id, admission.client_nonce)?;
        (message, host.context(admission.attempt_id)?.host_nonce)
    };
    std::thread::yield_now();
    let client_pake = client.with_host_nonce(host_nonce, &harness.clock)?;
    host.lock()
        .expect("the host")
        .receive_client_pake(admission.attempt_id, &client_pake)?;
    std::thread::yield_now();
    let tag = client.receive_host_pake(&host_pake, &harness.clock)?;
    host.lock()
        .expect("the host")
        .verify_client_confirmation(admission.attempt_id, &tag)?;
    Ok(())
}

/// KR-REQ-10.30: candidates guessing at once share one allowance. Four candidates make twelve
/// wrong guesses between them, interleaved step by step. Exactly four are told the tag failed,
/// exactly one is told the allowance is exhausted, and the durable count is five: concurrency can
/// neither exceed the allowance nor lose a spent guess.
#[test]
fn concurrent_candidates_never_spend_more_than_the_allowance() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (_, rows) = open(&path);
    let harness = Harness::new(rows);
    let host = Mutex::new(harness.issue());
    let wrong = wrong_code(&host.lock().expect("the host"));
    let invitation_id = host.lock().expect("the host").invitation_id();
    let outcomes = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..3 {
                    let outcome = interleaved_guess(&harness, &host, &wrong);
                    outcomes.lock().expect("the outcomes").push(outcome);
                }
            });
        }
    });
    let outcomes = outcomes.into_inner().expect("the outcomes");
    assert_eq!(outcomes.len(), 12);
    assert!(
        outcomes.iter().all(Result::is_err),
        "no wrong code confirms"
    );
    let failed = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(PairingError::AuthenticationFailed)))
        .count();
    let exhausted = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(PairingError::AttemptsExhausted)))
        .count();
    assert_eq!(failed, 4, "{outcomes:?}");
    assert_eq!(exhausted, 1, "{outcomes:?}");
    let record = stored(&path, invitation_id);
    assert_eq!(record.failed_confirmations, MAX_CONFIRMATION_FAILURES);
    assert_eq!(
        record.state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::AttemptsExhausted
        }
    );
}

/// KR-REQ-10.33: a restart cancels every unfinished invitation, and what each consumed invitation
/// spent survives it. An open invitation with two spent guesses comes back consumed by the restart
/// with its two guesses still spent; a cancelled one stays cancelled; a committed one keeps its
/// commitment and its device.
#[test]
fn a_restart_cancels_unfinished_invitations_and_keeps_what_they_spent() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);

    let first = Harness::new(rows.clone());
    let mut open_one = first.issue();
    let wrong = wrong_code(&open_one);
    for _ in 0..2 {
        assert!(guess(&first, &mut open_one, &wrong).is_err());
    }
    let open_id = open_one.invitation_id();

    let second = Harness::new(rows.clone());
    let mut cancelled = second.issue();
    cancelled.cancel(&second.owner).expect("cancelled");
    let cancelled_id = cancelled.invitation_id();

    let third = Harness::new(rows.clone());
    let mut committed = third.issue();
    bind(&third, &mut committed);
    let commitment = approve(&third, &mut committed).expect("committed");
    let committed_id = committed.invitation_id();
    drop(directory);

    // The restart: a new connection, the tables prepared again, and the sweep a starting daemon
    // runs before it serves anything.
    let (directory, rows) = open(&path);
    let swept = cancel_unfinished_invitations(&rows).expect("the sweep");
    assert_eq!(swept, vec![open_id]);

    let record = rows.load(open_id).expect("readable").expect("a record");
    assert_eq!(
        record.state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::HostRestarted
        }
    );
    assert_eq!(record.failed_confirmations, 2, "the spent guesses survive");
    assert_eq!(
        rows.load(cancelled_id)
            .expect("readable")
            .expect("a record")
            .state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::Cancelled
        }
    );
    assert_eq!(
        rows.load(committed_id)
            .expect("readable")
            .expect("a record")
            .state,
        InvitationState::Committed
    );
    assert_eq!(
        rows.commitment(committed_id).expect("readable"),
        Some(commitment.clone())
    );
    assert!(
        directory
            .record_for_device(commitment.device_id)
            .expect("readable")
            .is_some()
    );
    // A second sweep finds nothing: the restart's cancellation is itself durable.
    assert!(
        cancel_unfinished_invitations(&rows)
            .expect("the sweep")
            .is_empty()
    );
}

/// KR-REQ-10.08, KR-REQ-10.06: a completed pairing writes its device row, its commitment, its
/// security event and the consumption of the owner confirmation it was accepted under in one
/// transaction. The event is the outbox's first row and names the confirmation and its channel.
#[test]
fn a_completed_pairing_writes_its_device_commitment_event_and_confirmation_together() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let mut host = harness.issue();
    bind(&harness, &mut host);
    let commitment = approve(&harness, &mut host).expect("committed");

    let device = directory
        .record_for_device(commitment.device_id)
        .expect("readable")
        .expect("the device row");
    assert_eq!(device, device_record(&commitment).expect("a record"));
    let event = rows
        .event_for(commitment.invitation_id)
        .expect("readable")
        .expect("the event");
    assert_eq!(event.sequence.get(), 1);
    assert_eq!(event.device_id, commitment.device_id);
    assert_eq!(event.grant_id, commitment.grant.grant_id);
    assert_eq!(event.verification_value, commitment.verification_value);
    assert_eq!(
        event.confirmation_id,
        commitment.owner_confirmation.request.confirmation_id
    );
    assert_eq!(event.channel, ConfirmationChannel::OwnerDevicePresence);
    assert_eq!(event.mode, InviteModeKind::Code);
    assert!(!event.first_owner, "a viewer grant establishes no owner");
    assert_eq!(
        rows.events_after(None, 10).expect("readable"),
        vec![event.clone()]
    );
    assert!(
        rows.events_after(Some(event.sequence), 10)
            .expect("readable")
            .is_empty()
    );

    // Both confirmations are on record as consumed, each by the effect it authorised.
    let acceptance = rows
        .acceptance(commitment.owner_confirmation.request.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert!(acceptance.consumed_at_ms.is_some());
    assert_eq!(acceptance.channel, "owner_device_presence");
    let row = rows
        .row(commitment.invitation_id)
        .expect("readable")
        .expect("a row");
    let acceptance = rows
        .acceptance(row.confirmation_id)
        .expect("readable")
        .expect("the issuing confirmation's record");
    assert!(
        acceptance.consumed_at_ms.is_some(),
        "issuing the invitation consumed its confirmation"
    );
}

/// KR-REQ-10.08: a pairing whose commit fails leaves nothing behind. Here the device row cannot be
/// written, because its endpoint is already on record, and the transaction writes no commitment,
/// no event and no consumption either; the invitation stays where it was.
#[test]
fn a_commit_that_cannot_write_the_device_writes_nothing() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let mut host = harness.issue();
    bind(&harness, &mut host);
    // Another device already holds this candidate's endpoint.
    let mut squatter = device_record(&PairingCommitment {
        invitation_id: InvitationId::new(Uuid::from_bytes([3; 16])),
        attempt_id: kr_protocol::ids::AttemptId::new(Uuid::from_bytes([4; 16])),
        device_id: DeviceId::new(Uuid::from_bytes([5; 16])),
        grant: viewer_grant().into_grant(
            GrantId::new(Uuid::from_bytes([6; 16])),
            harness.host_device(),
            DeviceId::new(Uuid::from_bytes([5; 16])),
            AuthorityRevision::new(1),
        ),
        client_keys: harness.client_keys.public_keys(),
        client_bundle: Some(client_bundle(&harness.client_keys)),
        proposed_grant: viewer_grant(),
        verification_value: "00000000".to_owned(),
        owner_confirmation: harness
            .approval(
                SensitiveAction::ConfirmDevice,
                Digest256::from_bytes([0; 32]),
                None,
            )
            .proof,
        committed_at_ms: TimestampMs::new(1),
    })
    .expect("a record");
    squatter.committed_invitation_id = None;
    directory.commit(&squatter).expect("the other device");

    let invitation_id = host.invitation_id();
    let before = rows
        .load(invitation_id)
        .expect("readable")
        .expect("a record");
    let attempt = approve(&harness, &mut host);
    assert!(
        matches!(attempt, Err(PairingError::Store { .. })),
        "{attempt:?}"
    );
    assert_eq!(
        rows.load(invitation_id)
            .expect("readable")
            .expect("a record"),
        before
    );
    assert!(rows.commitment(invitation_id).expect("readable").is_none());
    assert!(rows.event_for(invitation_id).expect("readable").is_none());
    assert!(rows.events_after(None, 10).expect("readable").is_empty());
}

/// KR-REQ-10.06: an owner confirmation is consumed once. A second consumption of the same proof is
/// refused, whatever effect asks for it.
#[test]
fn a_spent_confirmation_cannot_be_spent_again() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (_, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let approval = harness.approval(
        SensitiveAction::ChangeHostAuthority,
        Digest256::from_bytes([2; 32]),
        None,
    );
    let owner = ActorId::new("local:501").expect("a principal");
    rows.record_answered(&approval.proof, &owner, TimestampMs::new(10))
        .expect("answered");
    let acceptance = rows
        .acceptance(approval.request.confirmation_id)
        .expect("readable")
        .expect("a record");
    assert_eq!(acceptance.answered_at_ms, TimestampMs::new(10));
    assert!(acceptance.consumed_at_ms.is_none());
    rows.record_consumed(&approval.proof, "the clock", TimestampMs::new(11))
        .expect("consumed");
    assert!(
        rows.record_consumed(&approval.proof, "something else", TimestampMs::new(12))
            .is_err()
    );
}

/// An invitation is recorded with the action that issued it and never with its secret. A retry of
/// that action finds the invitation after a restart; nothing in the database file carries the six
/// secret characters.
#[test]
fn an_invitation_is_found_by_its_action_and_its_secret_is_never_written() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let action = ActionId::new(Uuid::from_bytes([7; 16]));
    let digest = Digest256::from_bytes([8; 32]);
    let host = harness.issue_under(Some((action, digest)));
    let code = host.code().display_text().to_string();
    let invitation_id = host.invitation_id();
    drop(host);
    drop(directory);
    drop(rows);

    let (_, rows) = open(&path);
    let row = rows
        .row_for_action(&harness.owner.actor_id, action)
        .expect("readable")
        .expect("the invitation");
    assert_eq!(row.record.invitation_id, invitation_id);
    assert_eq!(row.terms.action, Some((action, digest)));
    assert_eq!(row.terms.mode, InviteModeKind::Code);
    assert_eq!(row.terms.proposed_grant, viewer_grant());
    let other = ActorId::new("local:502").expect("a principal");
    assert!(
        rows.row_for_action(&other, action)
            .expect("readable")
            .is_none()
    );

    let secret: String = code
        .chars()
        .filter(|character| *character != '-')
        .skip(4)
        .collect();
    for file in std::fs::read_dir(temp.path()).expect("the directory") {
        let bytes = std::fs::read(file.expect("an entry").path()).expect("readable");
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "the code's secret half is on disk"
        );
    }
}

/// The owner record: a device holding host management that is already on record when the record
/// is introduced makes the host enrolled, live or revoked, and a host with none is not.
#[test]
fn an_owner_device_on_record_before_the_owner_record_counts_once() {
    for (actions, revoked, enrolled) in [
        (
            vec![ActionRight::HostManage, ActionRight::SessionView],
            true,
            true,
        ),
        (vec![ActionRight::HostManage], false, true),
        (vec![ActionRight::SessionView], false, false),
    ] {
        let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
        let path = temp.path().join("registry.sqlite3");
        let directory = DeviceDirectory::open(&path).expect("the database opens");
        let keys = DeviceKeys::generate().expect("keys");
        let mut grant = viewer_grant();
        grant.actions = actions.into_iter().collect();
        let owner_keys = DeviceKeys::generate().expect("keys");
        let clock = TestClock::new();
        let request = request_confirmation(
            &clock,
            SensitiveAction::ConfirmDevice,
            Digest256::from_bytes([1; 32]),
            None,
            BTreeSet::new(),
            DeviceId::new(Uuid::from_bytes([1; 16])),
            *keys.transport.public(),
        )
        .expect("a challenge");
        let record = device_record(&PairingCommitment {
            invitation_id: InvitationId::new(Uuid::from_bytes([3; 16])),
            attempt_id: kr_protocol::ids::AttemptId::new(Uuid::from_bytes([4; 16])),
            device_id: DeviceId::new(Uuid::from_bytes([5; 16])),
            grant: grant.clone().into_grant(
                GrantId::new(Uuid::from_bytes([6; 16])),
                DeviceId::new(Uuid::from_bytes([1; 16])),
                DeviceId::new(Uuid::from_bytes([5; 16])),
                AuthorityRevision::new(1),
            ),
            client_keys: keys.public_keys(),
            client_bundle: Some(client_bundle(&keys)),
            proposed_grant: grant,
            verification_value: "00000000".to_owned(),
            owner_confirmation: sign_confirmation(
                &owner_keys.authorisation,
                &request,
                ConfirmationChannel::OwnerDevicePresence,
            )
            .expect("a proof"),
            committed_at_ms: TimestampMs::new(1),
        })
        .expect("a record");
        directory.commit(&record).expect("an existing device");
        if revoked {
            directory
                .revoke(record.device_id, TimestampMs::new(2))
                .expect("revoked");
        }
        prepare(&directory).expect("the tables");
        let rows = InvitationRows::new(Arc::new(directory));
        assert_eq!(
            rows.host_owner().expect("readable"),
            enrolled.then_some(HostOwner::Migrated)
        );
        // The migration looks once, when it creates the record.
        prepare(rows.directory()).expect("the tables again");
        assert_eq!(
            rows.host_owner().expect("readable"),
            enrolled.then_some(HostOwner::Migrated)
        );
    }
}
