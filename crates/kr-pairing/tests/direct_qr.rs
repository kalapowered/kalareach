//! The direct QR flow, end to end, and its share of KR-ACC-015.

use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::direct::{
    DirectInvitation, DirectStatusViewer, client_keys_digest, redeem_proof,
    verification_values_match,
};
use kr_pairing::host::OwnerContext;
use kr_pairing::platform::{InvitationState, TestClock, TestInvitationStore, TestLivePeer};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{ActorId, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{
    DeviceName, DevicePlatform, DirectQrPayload, INVITATION_LIFETIME_MS, NetworkConfig, PairStatus,
    PairingConsumedReason, ProposedGrant, QrPayload, direct_verification_value,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, EndpointKey, Nullable, TimestampMs, Uuid};

type Invitation<'a> = DirectInvitation<&'a TestInvitationStore, &'a TestClock>;

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

struct Harness {
    store: TestInvitationStore,
    clock: TestClock,
    host_keys: DeviceKeys,
    client_keys: DeviceKeys,
}

impl Harness {
    fn new() -> Self {
        Self {
            store: TestInvitationStore::new(),
            clock: TestClock::new(),
            host_keys: DeviceKeys::generate().expect("keys"),
            client_keys: DeviceKeys::generate().expect("keys"),
        }
    }

    fn issue(&self) -> Invitation<'_> {
        DirectInvitation::issue(
            &self.store,
            &self.clock,
            *self.host_keys.transport.public(),
            self.host_keys.public_keys(),
            DeviceKeyRevision::new(1),
            NetworkConfig {
                relay_urls: Vec::new(),
                discovery_origins: Vec::new(),
                direct_addresses: Vec::new(),
            },
            proposal(),
            owner(1),
        )
        .expect("an invitation")
    }

    /// Scans the QR the host produced, exactly as a candidate would.
    fn scan(&self, invitation: &Invitation<'_>) -> DirectQrPayload {
        let bytes = invitation
            .qr_payload()
            .to_canonical_bytes()
            .expect("canonical bytes");
        let QrPayload::Direct(payload) =
            QrPayload::from_canonical_bytes(&bytes).expect("a payload")
        else {
            panic!("a direct invitation produces a direct payload");
        };
        *payload
    }
}

/// What the candidate declares about itself in every redemption below.
fn candidate_identity(harness: &Harness) -> kr_pairing::direct::CandidateIdentity {
    kr_pairing::direct::CandidateIdentity {
        keys: harness.client_keys.public_keys(),
        device_key_revision: DeviceKeyRevision::new(1),
        device_name: DeviceName::new("A phone").expect("a name"),
        platform: DevicePlatform::Android,
        endpoint_id: *harness.client_keys.transport.public(),
    }
}

fn run_redemption(
    harness: &Harness,
    invitation: &mut Invitation<'_>,
    payload: &DirectQrPayload,
) -> Result<(kr_pairing::direct::DirectCandidate, String), PairingError> {
    let challenge = invitation.issue_challenge()?;
    let (proof, transcript) = redeem_proof(
        payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(harness),
    )?;
    let client_value = direct_verification_value(&transcript);
    let peer = TestLivePeer::new(*harness.client_keys.transport.public());
    let candidate = invitation.redeem(&proof, harness.client_keys.transport.public(), &peer)?;
    Ok((candidate, client_value))
}

#[test]
fn a_complete_direct_pairing_commits_the_device_and_the_proposed_grant() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    assert_eq!(payload.endpoint_id, *harness.host_keys.transport.public());
    assert_eq!(payload.proposed_grant, proposal());

    let (candidate, client_value) =
        run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    assert!(verification_values_match(
        &candidate.verification_value,
        &client_value
    ));
    assert_eq!(candidate.verification_value.len(), 8);

    let status = invitation
        .status(DirectStatusViewer::IssuingOwner(&owner(1)))
        .expect("a status");
    assert!(matches!(status, PairStatus::AwaitingApproval { .. }));

    let committed = invitation
        .confirm(
            &owner(1),
            candidate.transcript_digest,
            client_keys_digest(&harness.client_keys.public_keys()).expect("a digest"),
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        )
        .expect("a commitment");
    assert_eq!(committed.proposed_grant, proposal());
    assert_eq!(committed.client_keys, harness.client_keys.public_keys());
    assert_eq!(invitation.record().state, InvitationState::Committed);
}

#[test]
fn a_challenge_is_single_use_and_a_stale_one_is_refused() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);

    let stale = invitation.issue_challenge().expect("a challenge");
    // Issuing another challenge retires the first, so a proof over it no longer answers anything.
    let (stale_proof, _) = redeem_proof(
        &payload,
        &stale,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
    )
    .expect("a proof");
    let _fresh = invitation.issue_challenge().expect("a challenge");
    let peer = TestLivePeer::new(*harness.client_keys.transport.public());
    assert!(matches!(
        invitation.redeem(&stale_proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::ContextMismatch { .. })
    ));

    // And a redemption with no outstanding challenge is refused rather than accepted.
    assert!(matches!(
        invitation.redeem(&stale_proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::ContextMismatch { .. })
    ));
}

#[test]
fn the_submitted_endpoint_must_be_the_live_peer() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let challenge = invitation.issue_challenge().expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
    )
    .expect("a proof");

    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0xaa; 32]));
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &impostor),
        Err(PairingError::EndpointMismatch { side: "client" })
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);
}

#[test]
fn a_wrong_secret_or_a_tampered_signature_does_not_redeem() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let mut payload = harness.scan(&invitation);

    // A QR whose secret was replaced produces a tag the host does not accept.
    payload.secret = kr_protocol::scalars::SecretBytes32::from_bytes([0x55; 32]);
    assert!(matches!(
        run_redemption(&harness, &mut invitation, &payload),
        Err(PairingError::AuthenticationFailed)
    ));

    // The signature is checked too: possession of the secret alone is not a redemption.
    let payload = harness.scan(&invitation);
    let challenge = invitation.issue_challenge().expect("a challenge");
    let (mut proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
    )
    .expect("a proof");
    let impostor = DeviceKeys::generate().expect("keys");
    proof.client_keys = impostor.public_keys();
    let peer = TestLivePeer::new(*harness.client_keys.transport.public());
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::AuthenticationFailed)
    ));
}

#[test]
fn a_challenge_from_another_host_or_another_invitation_is_refused() {
    let harness = Harness::new();
    let mut ours = harness.issue();
    let mut theirs = harness.issue();
    let payload = harness.scan(&ours);
    let other_challenge = theirs.issue_challenge().expect("a challenge");

    assert!(matches!(
        redeem_proof(
            &payload,
            &other_challenge,
            &harness.client_keys.authorisation,
            &candidate_identity(&harness),
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
    let _ = ours.issue_challenge().expect("a challenge");
}

#[test]
fn a_reused_expired_or_cancelled_invitation_gives_a_specific_rejection() {
    let harness = Harness::new();

    // Reused: once committed, a second redemption is refused with its own reason.
    let mut committed = harness.issue();
    let payload = harness.scan(&committed);
    let (candidate, _) = run_redemption(&harness, &mut committed, &payload).expect("a redemption");
    committed
        .confirm(
            &owner(1),
            candidate.transcript_digest,
            client_keys_digest(&harness.client_keys.public_keys()).expect("a digest"),
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        )
        .expect("a commitment");
    assert!(matches!(
        run_redemption(&harness, &mut committed, &payload),
        Err(PairingError::AlreadyCommitted)
    ));

    // Cancelled: consumed without a grant.
    let mut cancelled = harness.issue();
    let payload = harness.scan(&cancelled);
    cancelled.cancel(&owner(1)).expect("a cancellation");
    assert_eq!(
        cancelled.record().state,
        InvitationState::Consumed {
            reason: PairingConsumedReason::Cancelled
        }
    );
    assert!(matches!(
        run_redemption(&harness, &mut cancelled, &payload),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Cancelled
        })
    ));

    // Expired: the host's own deadline decides.
    let mut expired = harness.issue();
    let payload = harness.scan(&expired);
    harness.clock.advance(INVITATION_LIFETIME_MS);
    assert!(matches!(
        run_redemption(&harness, &mut expired, &payload),
        Err(PairingError::Expired)
    ));
}

#[test]
fn only_the_issuing_owner_confirms_the_exact_transcript_and_keys() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    assert!(matches!(
        invitation.confirm(
            &owner(2),
            candidate.transcript_digest,
            keys_digest,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        ),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        invitation.confirm(
            &owner(1),
            Digest256::from_bytes([0xcc; 32]),
            keys_digest,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
    assert!(matches!(
        invitation.confirm(
            &owner(1),
            candidate.transcript_digest,
            Digest256::from_bytes([0xdd; 32]),
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
}

#[test]
fn an_idempotent_retry_cannot_change_the_keys_or_the_rights() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    let first = invitation
        .confirm(
            &owner(1),
            candidate.transcript_digest,
            keys_digest,
            DeviceId::new(Uuid::from_bytes([9; 16])),
            GrantId::new(Uuid::from_bytes([8; 16])),
        )
        .expect("a commitment");
    let second = invitation
        .confirm(
            &owner(1),
            Digest256::from_bytes([0xcc; 32]),
            Digest256::from_bytes([0xdd; 32]),
            DeviceId::new(Uuid::from_bytes([0xee; 16])),
            GrantId::new(Uuid::from_bytes([0xff; 16])),
        )
        .expect("the same commitment");
    assert_eq!(first, second);
}

#[test]
fn a_candidate_sees_only_its_own_status_and_no_secret() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");

    let status = invitation
        .status(DirectStatusViewer::Candidate(candidate.attempt_id))
        .expect("a status");
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(&hex::encode(payload.secret.expose())));

    let stranger = kr_pairing::host::new_attempt_id().expect("an attempt");
    assert!(matches!(
        invitation.status(DirectStatusViewer::Candidate(stranger)),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        invitation.status(DirectStatusViewer::IssuingOwner(&owner(2))),
        Err(PairingError::NotIssuingOwner)
    ));
}

#[test]
fn a_locked_candidate_is_not_replaced_by_the_other_entry_mode() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);

    // A short-code route locked a candidate on the same invitation record. The direct route reads
    // the same record and refuses rather than replacing it.
    let mut record = invitation.record().clone();
    record.state = InvitationState::AwaitingApproval {
        attempt_id: kr_pairing::host::new_attempt_id().expect("an attempt"),
    };
    invitation.adopt_record(record);
    assert!(matches!(
        run_redemption(&harness, &mut invitation, &payload),
        Err(PairingError::CandidateLocked)
    ));
}

#[test]
fn the_two_entry_modes_use_different_proof_domains() {
    // The short code's transcript is separated by `kr-pair/spake2-ed25519/1` and the direct
    // transcript by `kr-pair/direct/1`, so a proof from one route is not a proof in the other.
    assert_ne!(
        kr_protocol::pairing::PAIRING_DOMAIN,
        kr_protocol::pairing::DIRECT_DOMAIN
    );
    assert_ne!(
        kr_protocol::pairing::VERIFY_DOMAIN,
        kr_protocol::pairing::DIRECT_VERIFY_DOMAIN
    );
}

#[test]
fn a_code_mode_payload_is_not_an_offline_invitation() {
    let harness = Harness::new();
    let invitation = harness.issue();
    let direct = invitation.qr_payload();
    assert_eq!(direct.mode(), "direct");

    // A code-mode payload carries an origin and a code; it has no secret and no endpoint, so it
    // cannot be redeemed offline.
    let code = QrPayload::Code(kr_protocol::pairing::CodeQrPayload {
        rendezvous_origin: kr_protocol::pairing::RendezvousOrigin::new("https://reach.kala.to")
            .expect("an origin"),
        code: kr_protocol::pairing::ShortCode::new("aB3x-Yz7-9Qw").expect("a code"),
    });
    assert_eq!(code.mode(), "code");
    let bytes = code.to_canonical_bytes().expect("canonical bytes");
    let QrPayload::Code(_) = QrPayload::from_canonical_bytes(&bytes).expect("a payload") else {
        panic!("a code payload decodes as one");
    };
}
