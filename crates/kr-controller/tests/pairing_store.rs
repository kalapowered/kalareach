//! The host's durable pairing records, driven by kr-pairing's own state machine.
//!
//! Every test here writes a real registry database on the internal disk and reads it back through
//! a second connection, which is what a restarted daemon does.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::service::net::devices::DeviceDirectory;
use kr_controller::service::net::invitations::{
    ActionSubject, HostOwner, InvitationRows, IssueTerms, PairingAction, device_record, prepare,
};
use kr_controller::service::net::lifetimes::GrantLifetimes;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::clock::ManualSharedClock;
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
use kr_protocol::error::ErrorCode;
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
use kr_transport::clock::ManualClock;

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
///
/// A database created here belongs to a host that already has an owner device, so the pairings
/// these tests commit are ordinary ones rather than the first owner's.
fn open(path: &Path) -> (Arc<DeviceDirectory>, InvitationRows) {
    open_with(path, &ManualClock::new())
}

/// Opens the database at `path` with its grant lifetimes measured on `clock`.
fn open_with(path: &Path, clock: &ManualClock) -> (Arc<DeviceDirectory>, InvitationRows) {
    let fresh = !path.exists();
    let directory = Arc::new(DeviceDirectory::open(path).expect("the registry database opens"));
    if fresh {
        directory
            .commit(&owner_device())
            .expect("the host's owner device");
    }
    prepare(&directory).expect("the pairing tables exist");
    let rows = InvitationRows::new(Arc::clone(&directory), lifetimes(&directory, clock));
    (directory, rows)
}

/// Opens a database for a host that has no owner yet.
fn open_unowned(path: &Path) -> (Arc<DeviceDirectory>, InvitationRows) {
    let directory = Arc::new(DeviceDirectory::open(path).expect("the registry database opens"));
    prepare(&directory).expect("the pairing tables exist");
    let rows = InvitationRows::new(
        Arc::clone(&directory),
        lifetimes(&directory, &ManualClock::new()),
    );
    (directory, rows)
}

/// The grant lifetimes of `directory`'s devices, measured on `clock` in this boot.
fn lifetimes(directory: &Arc<DeviceDirectory>, clock: &ManualClock) -> Arc<GrantLifetimes> {
    lifetimes_on(
        directory,
        clock,
        kr_controller::service::WallClock::system(),
    )
}

/// The grant lifetimes of `directory`'s devices, measured on `clock` in this boot, with UTC read on
/// `wall`.
fn lifetimes_on(
    directory: &Arc<DeviceDirectory>,
    clock: &ManualClock,
    wall: kr_controller::service::WallClock,
) -> Arc<GrantLifetimes> {
    Arc::new(GrantLifetimes::new(
        Arc::clone(directory),
        Arc::new(clock.clone()),
        Arc::new(ManualSharedClock::new()),
        kr_ipc::identity::boot_identity().expect("a boot identity"),
        wall,
        Arc::new(kr_controller::grants::policy::UtcFloor::default()),
    ))
}

/// A device record holding a personal owner grant, as an owner device's row reads.
fn owner_device() -> kr_controller::service::net::devices::DeviceRecord {
    owner_device_with(
        &DeviceKeys::generate().expect("keys"),
        DeviceId::new(Uuid::from_bytes([0x0c; 16])),
        GrantExpiry::Never,
    )
}

/// The row of an owner device holding `keys`, under the identity `device_id`, whose grant holds
/// every right until `expiry`.
fn owner_device_with(
    keys: &DeviceKeys,
    device_id: DeviceId,
    expiry: GrantExpiry,
) -> kr_controller::service::net::devices::DeviceRecord {
    let owner_keys = DeviceKeys::generate().expect("keys");
    let clock = TestClock::new();
    let mut grant = kr_pairing::grants::personal_owner_grant();
    grant.expiry = expiry;
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
    device_record(&PairingCommitment {
        invitation_id: InvitationId::new(kr_ipc::new_uuid()),
        attempt_id: kr_protocol::ids::AttemptId::new(kr_ipc::new_uuid()),
        device_id,
        grant: grant.clone().into_grant(
            GrantId::new(kr_ipc::new_uuid()),
            DeviceId::new(Uuid::from_bytes([1; 16])),
            device_id,
            AuthorityRevision::new(1),
        ),
        client_keys: keys.public_keys(),
        client_bundle: Some(client_bundle(keys)),
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
    .expect("a record")
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
    /// The channel the owner answers on, and the enrolment it is accepted under.
    channel: ConfirmationChannel,
    enrolment: HostEnrolment,
    /// The owner's device on record, when the owner answers on one.
    owner_device_id: Option<DeviceId>,
}

type Host<'a> = HostInvitation<InvitationRows, &'a TestClock>;

impl Harness {
    /// A harness whose owner answers on an owner device this host has on record.
    ///
    /// The store checks the signer of every confirmation it records as spent against the live
    /// owner devices, so the owner's device row is written here.
    fn new(rows: InvitationRows) -> Self {
        let mut harness = Self::answering(
            rows,
            ConfirmationChannel::OwnerDevicePresence,
            HostEnrolment::Enrolled,
        );
        let device_id = DeviceId::new(kr_ipc::new_uuid());
        harness
            .rows
            .directory()
            .commit(&owner_device_with(
                &harness.owner_keys,
                device_id,
                GrantExpiry::Never,
            ))
            .expect("the owner's device");
        harness.owner_device_id = Some(device_id);
        harness
    }

    /// A harness for a host with no owner, whose owner answers at this host's own terminal.
    fn bootstrap(rows: InvitationRows) -> Self {
        Self::answering(
            rows,
            ConfirmationChannel::LocalBootstrapTerminal,
            HostEnrolment::InitialBootstrap,
        )
    }

    fn answering(
        rows: InvitationRows,
        channel: ConfirmationChannel,
        enrolment: HostEnrolment,
    ) -> Self {
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
            channel,
            enrolment,
            owner_device_id: None,
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
        let proof = sign_confirmation(&self.owner_keys.authorisation, &request, self.channel)
            .expect("a proof");
        Approval { request, proof }
    }

    fn by<'a>(&'a self, approval: &'a Approval, signer: &'a AuthorisationKey) -> OwnerApproval<'a> {
        OwnerApproval {
            owner: &self.owner,
            signer,
            enrolment: self.enrolment,
            request: &approval.request,
            proof: &approval.proof,
        }
    }

    fn terms(&self) -> IssueTerms {
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
            issued_at_ms: TimestampMs::new(self.clock_wall()),
        }
    }

    fn clock_wall(&self) -> u64 {
        use kr_pairing::platform::PairingClock as _;
        self.clock.wall_clock_ms()
    }

    fn issue_under(&self, action: (ActionId, Digest256)) -> Host<'_> {
        self.try_issue_under(action).expect("an invitation")
    }

    fn try_issue_under(&self, action: (ActionId, Digest256)) -> Result<Host<'_>, PairingError> {
        let approval = self.approval(
            SensitiveAction::IssueInvitation,
            kr_protocol::invitation::issuance_digest(
                InviteModeKind::Code,
                Some(&origin()),
                self.grant_kind.protocol(),
                &self.grant,
            )
            .expect("a digest"),
            None,
        );
        HostInvitation::issue(
            self.rows.issuing(self.terms(), action),
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
    }

    fn issue(&self) -> Host<'_> {
        self.issue_under((
            ActionId::new(kr_ipc::new_uuid()),
            Digest256::from_bytes([3; 32]),
        ))
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
    let answered_at = rows
        .record_answered(
            &approval.proof,
            &PairingAction {
                actor: owner,
                action_id: ActionId::new(kr_ipc::new_uuid()),
                digest: Digest256::from_bytes([4; 32]),
                subject: ActionSubject::Completed(approval.request.confirmation_id),
            },
            TimestampMs::new(10),
            &|| Ok(()),
        )
        .expect("answered");
    assert_eq!(answered_at, TimestampMs::new(10));
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
/// that action finds the invitation after a restart, through the action's own record; nothing in
/// the database file carries the six secret characters.
#[test]
fn an_invitation_is_found_by_its_action_and_its_secret_is_never_written() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let action = ActionId::new(Uuid::from_bytes([7; 16]));
    let digest = Digest256::from_bytes([8; 32]);
    let host = harness.issue_under((action, digest));
    let code = host.code().display_text().to_string();
    let invitation_id = host.invitation_id();
    drop(host);
    drop(directory);
    drop(rows);

    let (_, rows) = open(&path);
    let recorded = rows
        .action(&harness.owner.actor_id, action)
        .expect("readable")
        .expect("the action's record");
    assert_eq!(recorded.digest, digest);
    assert_eq!(recorded.subject, ActionSubject::Issued(invitation_id));
    let row = rows
        .row(invitation_id)
        .expect("readable")
        .expect("the invitation");
    assert_eq!(row.terms.issuing_actor, harness.owner.actor_id);
    assert_eq!(row.terms.mode, InviteModeKind::Code);
    assert_eq!(row.terms.proposed_grant, viewer_grant());
    let other = ActorId::new("local:502").expect("a principal");
    assert!(rows.action(&other, action).expect("readable").is_none());

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

/// Section 9, KR-REQ-09.07: the pairing mutations are one record keyed by the verified actor and
/// the action identifier. The payload recorded under an identifier is the only one it answers: the
/// same identifier with another payload is `ID_CONFLICT` whichever pairing method asks, and a write
/// that would record it rolls back with everything else it wrote. Another actor's identical
/// identifier is its own.
#[test]
fn an_action_identifier_is_spent_on_one_payload_across_the_pairing_methods() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (_, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let actor = harness.owner.actor_id.clone();
    let action = ActionId::new(Uuid::from_bytes([9; 16]));
    let digest = Digest256::from_bytes([5; 32]);
    let other = Digest256::from_bytes([6; 32]);
    let conflict = |outcome: kr_controller::error::Result<()>| outcome.expect_err("refused").code();

    let approval = harness.approval(
        SensitiveAction::ChangeHostAuthority,
        Digest256::from_bytes([2; 32]),
        None,
    );
    let completed = PairingAction {
        actor: actor.clone(),
        action_id: action,
        digest,
        subject: ActionSubject::Completed(approval.request.confirmation_id),
    };
    rows.record_answered(
        &approval.proof,
        &completed,
        TimestampMs::new(10),
        &|| Ok(()),
    )
    .expect("answered");
    assert_eq!(
        rows.answered(&actor, action, digest)
            .expect("recorded")
            .expect("readable"),
        completed.subject
    );
    assert_eq!(
        rows.answered(&actor, action, other)
            .expect("recorded")
            .expect_err("another payload")
            .code(),
        ErrorCode::IdConflict
    );

    // Each other pairing method, under the spent identifier with another payload.
    let asked = harness
        .approval(
            SensitiveAction::ChangeHostAuthority,
            Digest256::from_bytes([7; 32]),
            None,
        )
        .request;
    assert_eq!(
        conflict(
            rows.record_requested(
                &PairingAction {
                    actor: actor.clone(),
                    action_id: action,
                    digest: other,
                    subject: ActionSubject::Requested(Box::new(asked)),
                },
                &|| Ok(()),
            )
            .map(|_| ())
        ),
        ErrorCode::IdConflict
    );
    for subject in [
        ActionSubject::Confirmed(InvitationId::new(Uuid::from_bytes([10; 16]))),
        ActionSubject::Ended(InvitationId::new(Uuid::from_bytes([11; 16]))),
    ] {
        assert_eq!(
            conflict(rows.record_action(&PairingAction {
                actor: actor.clone(),
                action_id: action,
                digest: other,
                subject,
            })),
            ErrorCode::IdConflict
        );
    }
    let refused = harness.try_issue_under((action, other));
    assert!(
        matches!(
            refused,
            Err(PairingError::Refused {
                code: ErrorCode::IdConflict,
                ..
            })
        ),
        "{:?}",
        refused.map(|host| host.invitation_id())
    );
    assert!(
        rows.unfinished().expect("readable").is_empty(),
        "the invitation was not written"
    );
    assert_eq!(
        rows.action(&actor, action)
            .expect("readable")
            .expect("the record"),
        completed,
        "the identifier's one record is as it was"
    );

    // The same request twice under one identifier is given the challenge recorded first.
    let requested = ActionId::new(Uuid::from_bytes([12; 16]));
    let challenge = |digest_byte| {
        harness
            .approval(
                SensitiveAction::ChangeHostAuthority,
                Digest256::from_bytes([digest_byte; 32]),
                None,
            )
            .request
    };
    let first = challenge(13);
    let asking = |request| PairingAction {
        actor: actor.clone(),
        action_id: requested,
        digest,
        subject: ActionSubject::Requested(Box::new(request)),
    };
    assert_eq!(
        rows.record_requested(&asking(first.clone()), &|| Ok(()))
            .expect("recorded"),
        None
    );
    assert_eq!(
        rows.record_requested(&asking(challenge(14)), &|| Ok(()))
            .expect("recorded"),
        Some(first)
    );

    // Another actor's identical identifier is its own.
    rows.record_action(&PairingAction {
        actor: ActorId::new("local:502").expect("a principal"),
        action_id: action,
        digest: other,
        subject: ActionSubject::Ended(InvitationId::new(Uuid::from_bytes([11; 16]))),
    })
    .expect("another actor's own identifier");
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
        let directory = Arc::new(directory);
        let rows = InvitationRows::new(
            Arc::clone(&directory),
            lifetimes(&directory, &ManualClock::new()),
        );
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

/// KR-REQ-10.53, KR-REQ-10.04: a host with no owner commits only the pairing that establishes its
/// first owner. A viewer's commit is refused and writes nothing; a personal owner grant commits,
/// writes the owner record with it, and its event says it established the first owner.
#[test]
fn a_host_with_no_owner_commits_only_its_first_owner() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (_, rows) = open_unowned(&path);
    assert_eq!(rows.host_owner().expect("readable"), None);

    let viewer_host = Harness::bootstrap(rows.clone());
    let mut invitation = viewer_host.issue();
    bind(&viewer_host, &mut invitation);
    let refused = approve(&viewer_host, &mut invitation);
    assert!(
        matches!(
            refused,
            Err(PairingError::Refused {
                code: ErrorCode::PermissionDenied,
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(rows.events_after(None, 10).expect("readable").is_empty());
    // A refusal wrote nothing, so the invitation still serves its owner, who withdraws it.
    invitation
        .cancel(&viewer_host.owner)
        .expect("the owner withdraws it");
    assert_eq!(rows.host_owner().expect("readable"), None);

    let mut owner_host = Harness::bootstrap(rows.clone());
    owner_host.grant = kr_pairing::grants::personal_owner_grant();
    owner_host.grant_kind = GrantKind::PersonalOwner;
    let mut invitation = owner_host.issue();
    bind(&owner_host, &mut invitation);
    let commitment = approve(&owner_host, &mut invitation).expect("the first owner commits");
    let event = rows
        .event_for(commitment.invitation_id)
        .expect("readable")
        .expect("the event");
    assert!(event.first_owner);
    assert_eq!(
        rows.host_owner().expect("readable"),
        Some(HostOwner::FirstOwner {
            device_id: commitment.device_id,
            invitation_id: commitment.invitation_id,
        })
    );

    // The bootstrap is over: an answer given at the terminal spends nothing on a host with an
    // owner.
    let late = owner_host.approval(
        SensitiveAction::ChangeHostAuthority,
        Digest256::from_bytes([2; 32]),
        None,
    );
    let refused = rows
        .record_consumed(&late.proof, "the clock", TimestampMs::new(20))
        .expect_err("the bootstrap is over");
    assert_eq!(refused.code(), ErrorCode::OwnerConfirmationRequired);
}

/// KR-REQ-10.05, KR-REQ-10.06: the authority behind an owner's answer is read again inside the
/// transaction that commits the effect. An owner device revoked after it answered commits nothing:
/// no device, no commitment, no event and no consumption, and the invitation stays where it was.
#[test]
fn an_answer_whose_owner_device_was_revoked_commits_nothing() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let harness = Harness::new(rows.clone());
    let mut host = harness.issue();
    bind(&harness, &mut host);
    let invitation_id = host.invitation_id();
    let before = rows
        .load(invitation_id)
        .expect("readable")
        .expect("a record");
    directory
        .revoke(
            harness.owner_device_id.expect("the owner's device"),
            TimestampMs::new(harness.clock_wall()),
        )
        .expect("revoked");

    let refused = approve(&harness, &mut host);
    assert!(
        matches!(refused, Err(PairingError::OwnerConfirmationRequired)),
        "{refused:?}"
    );
    assert_eq!(
        rows.load(invitation_id)
            .expect("readable")
            .expect("a record"),
        before
    );
    assert!(rows.commitment(invitation_id).expect("readable").is_none());
    assert!(rows.events_after(None, 10).expect("readable").is_empty());
    assert!(
        directory
            .record_for_device(harness.identities().recipient_device_id)
            .expect("readable")
            .is_none()
    );
}

/// KR-REQ-10.05, KR-REQ-10.06: the signer's authority is read before the candidate's own row is
/// written. A candidate presenting the revoked signer's authorisation key and asking for host
/// management does not make that signer an owner device again: the commit is refused and writes
/// nothing.
#[test]
fn a_candidate_holding_the_signers_key_does_not_vouch_for_it() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let (directory, rows) = open(&path);
    let mut harness = Harness::new(rows.clone());
    harness.grant = kr_pairing::grants::personal_owner_grant();
    harness.grant_kind = GrantKind::PersonalOwner;
    harness.client_keys.authorisation = harness.owner_keys.authorisation.clone();
    let mut host = harness.issue();
    bind(&harness, &mut host);
    let invitation_id = host.invitation_id();
    let before = rows
        .load(invitation_id)
        .expect("readable")
        .expect("a record");
    directory
        .revoke(
            harness.owner_device_id.expect("the owner's device"),
            TimestampMs::new(harness.clock_wall()),
        )
        .expect("revoked");

    let refused = approve(&harness, &mut host);
    assert!(
        matches!(refused, Err(PairingError::OwnerConfirmationRequired)),
        "{refused:?}"
    );
    assert_eq!(
        rows.load(invitation_id)
            .expect("readable")
            .expect("a record"),
        before
    );
    assert!(rows.commitment(invitation_id).expect("readable").is_none());
    assert!(rows.events_after(None, 10).expect("readable").is_empty());
    assert!(
        directory
            .record_for_device(harness.identities().recipient_device_id)
            .expect("readable")
            .is_none()
    );
}

/// KR-REQ-10.05, KR-REQ-10.06: an owner device's grant is judged inside the transaction that
/// spends its answer, against the continuous clock read there. A grant that runs out between the
/// answer and the commit commits nothing, and its expiry goes on record.
#[test]
fn an_owner_grant_that_runs_out_before_the_commit_commits_nothing() {
    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let clock = ManualClock::new();
    let (directory, rows) = open_with(&path, &clock);
    let mut harness = Harness::answering(
        rows.clone(),
        ConfirmationChannel::OwnerDevicePresence,
        HostEnrolment::Enrolled,
    );
    // The owner's device holds host management for one more minute, and the host has anchored
    // that, as spending an answer does.
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let record = owner_device_with(
        &harness.owner_keys,
        device_id,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(kr_ipc::now_ms().get().saturating_add(60_000)),
        },
    );
    directory.commit(&record).expect("the owner's device");
    harness.owner_device_id = Some(device_id);
    assert!(rows.lifetimes().in_force(&record).expect("decided"));

    let mut host = harness.issue();
    bind(&harness, &mut host);
    let invitation_id = host.invitation_id();
    let before = rows
        .load(invitation_id)
        .expect("readable")
        .expect("a record");
    clock.advance(Duration::from_secs(61));

    let refused = approve(&harness, &mut host);
    assert!(
        matches!(refused, Err(PairingError::OwnerConfirmationRequired)),
        "{refused:?}"
    );
    assert_eq!(
        rows.load(invitation_id)
            .expect("readable")
            .expect("a record"),
        before
    );
    assert!(rows.commitment(invitation_id).expect("readable").is_none());
    assert!(rows.events_after(None, 10).expect("readable").is_empty());
    let expired = directory
        .record_for_device(device_id)
        .expect("readable")
        .expect("the owner's device");
    assert!(
        expired.expired_at_ms.is_some(),
        "the expiry found inside the transaction is on record"
    );
}

/// An owner device's grant that runs out by UTC first, its continuous deadline still ahead, is
/// judged on both clocks inside the transaction that spends its answer: the commit commits nothing,
/// and the expiry goes on record. The control is the grant in force before its expiry, which the
/// host anchors as spending an answer does.
#[test]
fn an_owner_grant_that_runs_out_by_utc_first_commits_nothing() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let temp = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = temp.path().join("registry.sqlite3");
    let now = kr_ipc::now_ms().get();
    let wall = Arc::new(AtomicU64::new(now));
    let clock = ManualClock::new();
    let directory = Arc::new(DeviceDirectory::open(&path).expect("the registry database opens"));
    directory
        .commit(&owner_device())
        .expect("the host's owner device");
    prepare(&directory).expect("the pairing tables exist");
    let rows = InvitationRows::new(
        Arc::clone(&directory),
        lifetimes_on(
            &directory,
            &clock,
            kr_controller::service::WallClock::from_fn({
                let wall = Arc::clone(&wall);
                move || wall.load(Ordering::SeqCst)
            }),
        ),
    );
    let mut harness = Harness::answering(
        rows.clone(),
        ConfirmationChannel::OwnerDevicePresence,
        HostEnrolment::Enrolled,
    );
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let record = owner_device_with(
        &harness.owner_keys,
        device_id,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now + 60_000),
        },
    );
    directory.commit(&record).expect("the owner's device");
    harness.owner_device_id = Some(device_id);
    assert!(rows.lifetimes().in_force(&record).expect("decided"));

    let mut host = harness.issue();
    bind(&harness, &mut host);
    let invitation_id = host.invitation_id();
    let before = rows
        .load(invitation_id)
        .expect("readable")
        .expect("a record");
    // UTC runs past the grant's expiry; the continuous clock does not move.
    wall.store(now + 61_000, Ordering::SeqCst);

    let refused = approve(&harness, &mut host);
    assert!(
        matches!(refused, Err(PairingError::OwnerConfirmationRequired)),
        "{refused:?}"
    );
    assert_eq!(
        rows.load(invitation_id)
            .expect("readable")
            .expect("a record"),
        before
    );
    assert!(rows.commitment(invitation_id).expect("readable").is_none());
    rows.lifetimes().settle();
    let expired = directory
        .record_for_device(device_id)
        .expect("readable")
        .expect("the owner's device");
    assert!(
        expired.expired_at_ms.is_some(),
        "the expiry found inside the transaction is on record"
    );
}
