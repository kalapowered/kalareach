//! The short-code flow, end to end, and the acceptance conditions of KR-ACC-015.
//!
//! Every dependency is an in-test implementation of the traits in `kr_pairing::platform`: no
//! network, no disk, no real clock. What is exercised is the protocol.

use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::client::ClientAttempt;
use kr_pairing::code::EnteredCode;
use kr_pairing::host::{HostInvitation, OwnerContext, cancel_unfinished_invitations};
use kr_pairing::platform::{
    InvitationState, LocatorRecord, TestClient, TestClientBudgetStore, TestClock,
    TestInvitationStore, TestLivePeer, TestRendezvousHost,
};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{ActorId, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{
    ClientBundle, DeviceName, DevicePlatform, HostBundle, INVITATION_LIFETIME_MS,
    MAX_CONFIRMATION_FAILURES, NetworkConfig, PairStatus, PairingConsumedReason, ProposedGrant,
    RendezvousOrigin,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

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

fn host_bundle(
    keys: &DeviceKeys,
    invitation_id: kr_protocol::ids::InvitationId,
    device_id: DeviceId,
) -> HostBundle {
    HostBundle {
        invitation_id,
        device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        endpoint_id: *keys.transport.public(),
        keys: keys.public_keys(),
        network_config: NetworkConfig {
            relay_urls: Vec::new(),
            discovery_origins: Vec::new(),
            direct_addresses: Vec::new(),
        },
        proposed_grant: proposal(),
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

/// Everything one pairing needs, assembled once.
///
/// The state machines take the store and the clock by reference, which is how a test watches the
/// same values the host is writing.
struct Harness {
    store: TestInvitationStore,
    clock: TestClock,
    service: TestRendezvousHost,
    host_keys: DeviceKeys,
    client_keys: DeviceKeys,
    host_device_id: DeviceId,
}

type Host<'a> = HostInvitation<&'a TestInvitationStore, &'a TestClock>;

impl Harness {
    fn new() -> Self {
        Self {
            store: TestInvitationStore::new(),
            clock: TestClock::new(),
            service: TestRendezvousHost::new(),
            host_keys: DeviceKeys::generate().expect("keys"),
            client_keys: DeviceKeys::generate().expect("keys"),
            host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
        }
    }

    fn issue(&self) -> Host<'_> {
        HostInvitation::issue(
            &self.store,
            &self.clock,
            &self.service,
            origin(),
            proposal(),
            owner(1),
            self.host_device_id,
            *self.host_keys.transport.public(),
        )
        .expect("an invitation")
    }
}

/// Runs a complete exchange with `entered` as the code the candidate typed.
///
/// Returns the host, the candidate and what the candidate saw, so a test can assert on any step.
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
    let client_pake =
        client.with_host_nonce(host.context(admission.attempt_id)?.host_nonce, entered)?;

    host.receive_client_pake(admission.attempt_id, &client_pake)?;
    let client_tag = client.receive_host_pake(&host_pake)?;
    let host_tag = host.verify_client_confirmation(admission.attempt_id, &client_tag)?;
    client.verify_host_confirmation(&host_tag)?;

    let host_frame = host.seal_host_bundle(
        admission.attempt_id,
        &harness.host_keys.authorisation,
        host_bundle(
            &harness.host_keys,
            host.invitation_id(),
            harness.host_device_id,
        ),
    )?;
    client.open_host_bundle(&host_frame)?;
    let client_frame = client.seal_client_bundle(
        &harness.client_keys.authorisation,
        client_bundle(&harness.client_keys),
    )?;
    host.open_client_bundle(admission.attempt_id, &client_frame)?;

    let host_peer = TestLivePeer::new(*harness.host_keys.transport.public());
    let request = client.finish_request(&host_peer, harness.client_keys.transport.public())?;
    let client_peer = TestLivePeer::new(*harness.client_keys.transport.public());
    let locked = host.finish(&request, &client_peer)?;
    let client_value = client.verification_value()?;
    assert_eq!(locked.verification_value, client_value);
    Ok((client, client_value))
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
        .status(kr_pairing::host::StatusViewer::IssuingOwner(&owner(1)))
        .expect("a status");
    let PairStatus::AwaitingApproval {
        verification_value, ..
    } = status
    else {
        panic!("the owner is asked to approve");
    };
    assert_eq!(verification_value, value);

    // The owner approves the exact transcript and client bundle hash it was shown.
    let locked = locked_values(&host);
    let committed = host
        .confirm(
            &owner(1),
            locked.0,
            locked.1,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        )
        .expect("a commitment");
    assert_eq!(committed.proposed_grant, proposal());
    assert_eq!(host.record().state, InvitationState::Committed);
}

/// Returns the transcript and client bundle hash a locked candidate produced.
///
/// This is what the issuing device shows the owner, and what the owner names back.
fn locked_values(
    host: &Host<'_>,
) -> (
    kr_protocol::scalars::Digest256,
    kr_protocol::scalars::Digest256,
) {
    (
        host.locked_transcript().expect("a locked transcript"),
        host.locked_client_bundle_hash()
            .expect("a hash")
            .expect("a locked candidate"),
    )
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
fn concurrent_candidates_share_one_allowance() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let wrong = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");

    // Four candidates take a slot each, and the guesses they spend come out of one count.
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
            &entered,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("the candidate's message");
    let client_tag = client.receive_host_pake(&host_pake).expect("a tag");
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
            &entered,
        )
        .expect("a message");
    host.receive_client_pake(admission.attempt_id, &client_pake)
        .expect("a message");
    let client_tag = client.receive_host_pake(&host_pake).expect("a tag");
    let host_tag = host
        .verify_client_confirmation(admission.attempt_id, &client_tag)
        .expect("a tag");
    client
        .verify_host_confirmation(&host_tag)
        .expect("confirmed");

    let host_frame = host
        .seal_host_bundle(
            admission.attempt_id,
            &harness.host_keys.authorisation,
            host_bundle(
                &harness.host_keys,
                host.invitation_id(),
                harness.host_device_id,
            ),
        )
        .expect("a frame");
    client.open_host_bundle(&host_frame).expect("a bundle");
    let client_frame = client
        .seal_client_bundle(
            &harness.client_keys.authorisation,
            client_bundle(&harness.client_keys),
        )
        .expect("a frame");
    host.open_client_bundle(admission.attempt_id, &client_frame)
        .expect("a bundle");

    // The candidate checks the host it reached against the authenticated bundle.
    let wrong_host = TestLivePeer::new(kr_protocol::scalars::EndpointKey::from_bytes([0xaa; 32]));
    assert!(matches!(
        client.finish_request(&wrong_host, harness.client_keys.transport.public()),
        Err(PairingError::EndpointMismatch { side: "host" })
    ));

    // And the host checks the candidate it is talking to against the bundle it authenticated.
    let host_peer = TestLivePeer::new(*harness.host_keys.transport.public());
    let request = client
        .finish_request(&host_peer, harness.client_keys.transport.public())
        .expect("a request");
    let impostor = TestLivePeer::new(kr_protocol::scalars::EndpointKey::from_bytes([0xbb; 32]));
    assert!(matches!(
        host.finish(&request, &impostor),
        Err(PairingError::EndpointMismatch { side: "client" })
    ));
}

#[test]
fn only_the_issuing_owner_confirms_or_cancels() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let (transcript, client_hash) = locked_values(&host);

    assert!(matches!(
        host.confirm(
            &owner(2),
            transcript,
            client_hash,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        ),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        host.cancel(&owner(2)),
        Err(PairingError::NotIssuingOwner)
    ));

    // Approving a different transcript is refused: the owner approves what it was shown.
    assert!(matches!(
        host.confirm(
            &owner(1),
            kr_protocol::scalars::Digest256::from_bytes([0xcc; 32]),
            client_hash,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
}

#[test]
fn a_transport_retry_retrieves_the_committed_result() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let (transcript, client_hash) = locked_values(&host);

    let device_id = DeviceId::new(Uuid::from_bytes([9; 16]));
    let grant_id = GrantId::new(Uuid::from_bytes([8; 16]));
    let first = host
        .confirm(&owner(1), transcript, client_hash, device_id, grant_id)
        .expect("a commitment");
    // A retry with different identities still returns the committed result: it cannot replace the
    // public keys or the grant.
    let second = host
        .confirm(
            &owner(1),
            transcript,
            client_hash,
            DeviceId::new(Uuid::from_bytes([0xdd; 16])),
            GrantId::new(Uuid::from_bytes([0xee; 16])),
        )
        .expect("the same commitment");
    assert_eq!(first, second);
}

#[test]
fn a_candidate_sees_only_its_own_status_and_never_a_secret() {
    let harness = Harness::new();
    let mut host = harness.issue();
    let entered = EnteredCode::parse(&host.code().display_text()).expect("the code");
    run_exchange(&harness, &mut host, &entered).expect("a pairing");
    let InvitationState::AwaitingApproval { attempt_id } = host.record().state else {
        panic!("a candidate holds it");
    };

    let status = host
        .status(kr_pairing::host::StatusViewer::Candidate(attempt_id))
        .expect("a status");
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(&*host.code().display_text()));
    assert!(!rendered.contains(&*host.code().secret().expose_text()));

    let stranger = kr_pairing::host::new_attempt_id().expect("an attempt");
    assert!(matches!(
        host.status(kr_pairing::host::StatusViewer::Candidate(stranger)),
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
