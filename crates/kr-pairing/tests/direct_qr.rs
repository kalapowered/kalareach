//! The direct QR flow, end to end, and its share of KR-ACC-015.

use std::cell::RefCell;
use std::collections::BTreeSet;

use kr_crypto::keys::DeviceKeys;
use kr_pairing::PairingError;
use kr_pairing::confirm::{
    ConfirmationLedger, HostEnrolment, request_confirmation, sign_confirmation,
};
use kr_pairing::direct::{
    ApprovedRedemption, DirectInvitation, DirectStatusViewer, client_keys_digest, redeem_proof,
    verification_values_match,
};
use kr_pairing::grants::{GrantIdentities, GrantKind};
use kr_pairing::host::{HostIdentity, OwnerApproval, OwnerContext};
use kr_pairing::platform::{InvitationState, TestClock, TestInvitationStore, TestLivePeer};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{ActorId, AuthorityRevision, DeviceId, DeviceKeyRevision, GrantId};
use kr_protocol::pairing::{
    ConfirmationChannel, DeviceName, DevicePlatform, DevicePublicKeys, DirectQrPayload,
    INVITATION_LIFETIME_MS, NetworkConfig, NetworkHint, OwnerConfirmationProof,
    OwnerConfirmationRequest, PairStatus, PairingConsumedReason, ProposedGrant, QrPayload,
    SensitiveAction, direct_verification_value,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, EndpointKey, Nullable, Signature64, TimestampMs,
    Uuid,
};

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

struct Harness {
    store: TestInvitationStore,
    clock: TestClock,
    ledger: RefCell<ConfirmationLedger>,
    host_keys: DeviceKeys,
    client_keys: DeviceKeys,
    owner_keys: DeviceKeys,
    issuing_owner: OwnerContext,
}

impl Harness {
    fn new() -> Self {
        Self {
            store: TestInvitationStore::new(),
            clock: TestClock::new(),
            ledger: RefCell::new(ConfirmationLedger::new()),
            host_keys: DeviceKeys::generate().expect("keys"),
            client_keys: DeviceKeys::generate().expect("keys"),
            owner_keys: DeviceKeys::generate().expect("keys"),
            issuing_owner: owner(1),
        }
    }

    fn signer(&self) -> &AuthorisationKey {
        self.owner_keys.authorisation.public()
    }

    fn identity(&self) -> HostIdentity {
        HostIdentity {
            device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            endpoint_id: *self.host_keys.transport.public(),
            keys: self.host_keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            network_config: network_config(),
        }
    }

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
            DeviceId::new(Uuid::from_bytes([1; 16])),
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

    fn issue(&self) -> Invitation<'_> {
        let approval = self.approval(
            SensitiveAction::IssueInvitation,
            kr_pairing::confirm::action_digest(&proposal()).expect("a digest"),
            None,
        );
        DirectInvitation::issue(
            &self.store,
            &self.clock,
            self.identity(),
            proposal(),
            GrantKind::SessionInvitation,
            &approval.by(&self.issuing_owner, self.signer()),
            &mut self.ledger.borrow_mut(),
        )
        .expect("an invitation")
    }

    fn grant_identities(&self) -> GrantIdentities {
        GrantIdentities {
            grant_id: GrantId::new(Uuid::from_bytes([8; 16])),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
            authority_revision: AuthorityRevision::new(1),
        }
    }

    fn host_peer(&self) -> TestLivePeer {
        TestLivePeer::new(*self.host_keys.transport.public())
    }

    fn client_peer(&self) -> TestLivePeer {
        TestLivePeer::new(*self.client_keys.transport.public())
    }

    /// Approves whatever candidate the invitation currently holds.
    fn confirm(
        &self,
        invitation: &mut Invitation<'_>,
        transcript_digest: Digest256,
        client_key_digest: Digest256,
    ) -> Result<kr_pairing::platform::PairingCommitment, PairingError> {
        let approved = ApprovedRedemption {
            transcript_digest,
            client_key_digest,
        };
        let approval = self.approval(
            SensitiveAction::ConfirmDevice,
            approved.action_digest(),
            Some(self.client_keys.public_keys()),
        );
        invitation.confirm(
            &approval.by(&self.issuing_owner, self.signer()),
            &mut self.ledger.borrow_mut(),
            &approved,
            &self.grant_identities(),
            None,
        )
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

/// A host's selected discovery and relay configuration, with every member populated.
fn network_config() -> NetworkConfig {
    let hint = |text: &str| NetworkHint::new(text).expect("a hint");
    NetworkConfig {
        relay_urls: vec![
            hint("https://relay-1.reach.kala.to"),
            hint("https://relay-2.reach.kala.to"),
        ],
        pkarr_publisher_url: Nullable::some(hint("https://pkarr.reach.kala.to")),
        pkarr_resolver_url: Nullable::some(hint("https://resolver.reach.kala.to")),
        dns_origin: Nullable::some(hint("dns.reach.kala.to")),
        direct_addresses: vec![hint("192.0.2.10:4433"), hint("[2001:db8::10]:4433")],
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
    // The host sees the candidate's connection; the candidate sees the host's.
    let candidate_peer = harness.client_peer();
    let host_peer = harness.host_peer();
    let challenge = invitation.issue_challenge(&candidate_peer)?;
    let (proof, transcript) = redeem_proof(
        payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(harness),
        &host_peer,
    )?;
    let client_value = direct_verification_value(&transcript);
    let peer = harness.client_peer();
    let candidate = invitation.redeem(&proof, harness.client_keys.transport.public(), &peer)?;
    Ok((candidate, client_value))
}

/// KR-REQ-10.35, KR-REQ-10.37, KR-REQ-23.26: a direct invitation carries what section 10 lists and
/// grants nothing until redeemed; both devices compute the same value, and the owner's
/// confirmation commits the device and the proposed grant.
#[test]
fn a_complete_direct_pairing_commits_the_device_and_the_proposed_grant() {
    // KR-REQ-01.16: a device pairs by scanning the host's QR invitation, with no account anywhere
    // in the exchange.
    let harness = Harness::new();
    let issued_at = kr_pairing::platform::PairingClock::wall_clock_ms(&harness.clock);
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    assert_eq!(payload.endpoint_id, *harness.host_keys.transport.public());
    assert_eq!(payload.proposed_grant, proposal());

    // The QR carries the selected network configuration, a random 256-bit secret of its own and a
    // five-minute expiry, and until a candidate proves the secret the invitation grants nothing.
    assert_eq!(payload.network_config, network_config());
    assert_eq!(payload.secret.expose().len(), 32);
    let another = harness.issue();
    assert_ne!(
        harness.scan(&another).secret.expose(),
        payload.secret.expose(),
        "every invitation draws its own secret"
    );
    assert_eq!(
        payload.expires_at_ms.get(),
        issued_at + INVITATION_LIFETIME_MS
    );
    assert_eq!(invitation.record().state, InvitationState::Open);
    assert_eq!(
        kr_pairing::platform::InvitationStore::commitment(
            &&harness.store,
            invitation.invitation_id()
        )
        .expect("a read"),
        None,
        "an issued invitation has granted nothing"
    );

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

    let committed = harness
        .confirm(
            &mut invitation,
            candidate.transcript_digest,
            client_keys_digest(&harness.client_keys.public_keys()).expect("a digest"),
        )
        .expect("a commitment");
    assert_eq!(committed.proposed_grant, proposal());
    assert_eq!(committed.client_keys, harness.client_keys.public_keys());
    assert_eq!(committed.verification_value, client_value);
    // The grant issued in the commit carries the proposal's rights, scope and expiry, from this
    // host to the device just recorded.
    let proposed = proposal();
    assert_eq!(committed.grant.actions, proposed.actions);
    assert_eq!(
        committed.grant.environment_selector,
        proposed.environment_selector
    );
    assert_eq!(committed.grant.session_selector, proposed.session_selector);
    assert_eq!(committed.grant.history, proposed.history);
    assert_eq!(committed.grant.expiry, proposed.expiry);
    assert_eq!(
        committed.grant.issuer_device_id,
        harness.identity().device_id
    );
    assert_eq!(committed.grant.recipient_device_id, committed.device_id);
    assert_eq!(
        committed
            .client_bundle
            .as_ref()
            .expect("a candidate declaration")
            .endpoint_id,
        *harness.client_keys.transport.public(),
        "a device record is written the same way from either entry mode"
    );
    assert_eq!(invitation.record().state, InvitationState::Committed);
}

/// KR-REQ-10.36: a host challenge is single use, and a stale one is refused.
#[test]
fn a_challenge_is_single_use_and_a_stale_one_is_refused() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);

    let host_peer = harness.host_peer();
    let stale = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    // Issuing another challenge retires the first, so a proof over it no longer answers anything.
    let (stale_proof, _) = redeem_proof(
        &payload,
        &stale,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");
    let _fresh = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let peer = harness.client_peer();
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

/// KR-REQ-10.36: the submitted client endpoint must be the live authenticated peer.
#[test]
fn the_submitted_endpoint_must_be_the_live_peer() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let host_peer = harness.host_peer();
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");

    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0xaa; 32]));
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &impostor),
        Err(PairingError::EndpointMismatch { side: "client" })
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);
}

/// KR-REQ-10.36, KR-REQ-10.35: redemption needs both the secret's HMAC over `D` and the Ed25519
/// signature over `D`; each one refuses a redemption the other would pass.
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
    let host_peer = harness.host_peer();
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (mut proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");
    let impostor = DeviceKeys::generate().expect("keys");
    // Substituting the whole key bundle leaves the transport key disagreeing with the endpoint,
    // which is refused before the signature is considered.
    proof.client_keys = impostor.public_keys();
    let peer = harness.client_peer();
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::ContextMismatch { .. })
    ));

    // A signature that does not verify refuses the redemption on its own: `D` and the secret's tag
    // are the ones the candidate built, and only the signature's bytes are wrong.
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (mut proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");
    let mut signature = *proof.signature.as_bytes();
    signature[0] ^= 0x01;
    proof.signature = Signature64::from_bytes(signature);
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::AuthenticationFailed)
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);

    // Substituting the authorisation key and recomputing the secret's tag over the `D` that key
    // gives leaves the signature, made by the original key over the original `D`, as the only
    // thing that can refuse it.
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (mut proof, mut transcript) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");
    proof.client_keys.authorisation = *impostor.authorisation.public();
    transcript.client_keys.authorisation = *impostor.authorisation.public();
    proof.secret_proof = kr_pairing::direct::secret_proof(&payload.secret, &transcript);
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::AuthenticationFailed)
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);
}

/// KR-REQ-10.35, KR-REQ-10.36: the proof goes only to the endpoint the QR pinned, never in 0-RTT.
#[test]
fn a_candidate_refuses_to_prove_itself_to_an_endpoint_the_qr_did_not_pin() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");

    // The challenge names the pinned endpoint, but the connection reached somebody else. Sending
    // the proof anyway would hand the invitation secret's tag to whatever the relay pointed at.
    let elsewhere = TestLivePeer::new(EndpointKey::from_bytes([0x33; 32]));
    assert!(matches!(
        redeem_proof(
            &payload,
            &challenge,
            &harness.client_keys.authorisation,
            &candidate_identity(&harness),
            &elsewhere,
        ),
        Err(PairingError::EndpointMismatch { side: "host" })
    ));

    // And nothing is sent over a connection still in early data.
    let early = harness.host_peer();
    early.set_early_data(true);
    assert!(matches!(
        redeem_proof(
            &payload,
            &challenge,
            &harness.client_keys.authorisation,
            &candidate_identity(&harness),
            &early,
        ),
        Err(PairingError::EarlyData)
    ));
}

/// KR-REQ-10.36: a redemption in 0-RTT is refused and changes nothing.
#[test]
fn a_redemption_in_early_data_changes_nothing() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let host_peer = harness.host_peer();
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &host_peer,
    )
    .expect("a proof");

    let replayed = harness.client_peer();
    replayed.set_early_data(true);
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &replayed),
        Err(PairingError::EarlyData)
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);

    // The challenge was not consumed by the refusal, so the honest redemption still works.
    let peer = harness.client_peer();
    invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("a redemption");
}

/// KR-REQ-10.36: a challenge answers only its own invitation.
#[test]
fn a_challenge_from_another_host_or_another_invitation_is_refused() {
    let harness = Harness::new();
    let mut ours = harness.issue();
    let mut theirs = harness.issue();
    let payload = harness.scan(&ours);
    let host_peer = harness.host_peer();
    let other_challenge = theirs
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");

    assert!(matches!(
        redeem_proof(
            &payload,
            &other_challenge,
            &harness.client_keys.authorisation,
            &candidate_identity(&harness),
            &host_peer,
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
    let _ = ours
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
}

/// KR-REQ-10.35, KR-REQ-10.37: a reused, expired or cancelled invitation gives its own rejection,
/// and `pair.cancel` consumes one without a grant.
#[test]
fn a_reused_expired_or_cancelled_invitation_gives_a_specific_rejection() {
    let harness = Harness::new();

    // Reused: once committed, a second redemption is refused with its own reason.
    let mut committed = harness.issue();
    let payload = harness.scan(&committed);
    let (candidate, _) = run_redemption(&harness, &mut committed, &payload).expect("a redemption");
    harness
        .confirm(
            &mut committed,
            candidate.transcript_digest,
            client_keys_digest(&harness.client_keys.public_keys()).expect("a digest"),
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

/// KR-REQ-10.37, KR-REQ-10.38: `pair.confirm` takes only the issuing owner, the exact transcript
/// and the exact client keys, and a short-code confirmation does not approve a direct redemption.
#[test]
fn only_the_issuing_owner_confirms_the_exact_transcript_and_keys() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    let approved = ApprovedRedemption {
        transcript_digest: candidate.transcript_digest,
        client_key_digest: keys_digest,
    };
    let stranger = owner(2);
    let approval = harness.approval(
        SensitiveAction::ConfirmDevice,
        approved.action_digest(),
        Some(harness.client_keys.public_keys()),
    );
    assert!(matches!(
        invitation.confirm(
            &approval.by(&stranger, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        harness.confirm(
            &mut invitation,
            Digest256::from_bytes([0xcc; 32]),
            keys_digest
        ),
        Err(PairingError::ContextMismatch { .. })
    ));
    assert!(matches!(
        harness.confirm(
            &mut invitation,
            candidate.transcript_digest,
            Digest256::from_bytes([0xdd; 32])
        ),
        Err(PairingError::ContextMismatch { .. })
    ));

    // And a confirmation naming another candidate does not approve this one.
    let elsewhere = harness.approval(
        SensitiveAction::ConfirmDevice,
        ApprovedRedemption {
            transcript_digest: Digest256::from_bytes([0x21; 32]),
            client_key_digest: keys_digest,
        }
        .action_digest(),
        Some(harness.client_keys.public_keys()),
    );
    assert!(matches!(
        invitation.confirm(
            &elsewhere.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    // A short-code confirmation does not approve a direct redemption: the two entry modes compute
    // their action digests under different domains.
    let short_code = harness.approval(
        SensitiveAction::ConfirmDevice,
        kr_pairing::host::ApprovedCandidate {
            transcript: candidate.transcript_digest,
            host_bundle_hash: Digest256::from_bytes([0; 32]),
            client_bundle_hash: keys_digest,
        }
        .action_digest(),
        Some(harness.client_keys.public_keys()),
    );
    assert!(matches!(
        invitation.confirm(
            &short_code.by(&harness.issuing_owner, harness.signer()),
            &mut harness.ledger.borrow_mut(),
            &approved,
            &harness.grant_identities(),
            None,
        ),
        Err(PairingError::OwnerConfirmationRequired)
    ));
}

/// KR-REQ-10.37: a retried confirmation cannot change the keys or the rights.
#[test]
fn an_idempotent_retry_cannot_change_the_keys_or_the_rights() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    let first = harness
        .confirm(&mut invitation, candidate.transcript_digest, keys_digest)
        .expect("a commitment");
    let second = harness
        .confirm(
            &mut invitation,
            Digest256::from_bytes([0xcc; 32]),
            Digest256::from_bytes([0xdd; 32]),
        )
        .expect("the same commitment");
    assert_eq!(first, second);
}

/// KR-REQ-10.37: the commit is atomic and reported only once written.
#[test]
fn a_commitment_that_cannot_be_written_is_not_reported_as_a_pairing() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    harness.store.set_failing_writes(true);
    assert!(matches!(
        harness.confirm(&mut invitation, candidate.transcript_digest, keys_digest),
        Err(PairingError::Store { .. })
    ));
    harness.store.set_failing_writes(false);
    assert_eq!(
        kr_pairing::platform::InvitationStore::commitment(
            &&harness.store,
            invitation.invitation_id()
        )
        .expect("a read"),
        None,
        "nothing was written, so nothing is reported"
    );
}

/// KR-REQ-10.37, KR-REQ-10.35: `pair.status` answers only the candidate's own endpoint or the
/// issuing owner, and never shows the secret.
#[test]
fn a_candidate_sees_only_its_own_status_and_no_secret() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");

    let peer = harness.client_peer();
    let status = invitation
        .status(DirectStatusViewer::Candidate {
            attempt_id: Some(candidate.attempt_id),
            live_peer: &peer,
        })
        .expect("a status");
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(&hex::encode(payload.secret.expose())));

    let stranger = kr_pairing::host::new_attempt_id().expect("an attempt");
    assert!(matches!(
        invitation.status(DirectStatusViewer::Candidate {
            attempt_id: Some(stranger),
            live_peer: &peer,
        }),
        Err(PairingError::NotIssuingOwner)
    ));
    // Knowing the attempt identity is not enough: the asker must be that endpoint.
    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0x77; 32]));
    assert!(matches!(
        invitation.status(DirectStatusViewer::Candidate {
            attempt_id: Some(candidate.attempt_id),
            live_peer: &impostor,
        }),
        Err(PairingError::NotIssuingOwner)
    ));
    assert!(matches!(
        invitation.status(DirectStatusViewer::IssuingOwner(&owner(2))),
        Err(PairingError::NotIssuingOwner)
    ));

    // After the commitment the answer comes from the store, so it survives a restart.
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");
    harness
        .confirm(&mut invitation, candidate.transcript_digest, keys_digest)
        .expect("a commitment");
    assert!(matches!(
        invitation.status(DirectStatusViewer::Candidate {
            attempt_id: Some(candidate.attempt_id),
            live_peer: &peer,
        }),
        Ok(PairStatus::Committed { .. })
    ));
}

/// KR-REQ-10.38: neither entry mode replaces a candidate the other has locked.
#[test]
fn a_locked_candidate_is_not_replaced_by_the_other_entry_mode() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);

    // A short-code route locked a candidate on the same invitation record. The direct route reads
    // that record from the store before every transition, so it refuses rather than replacing it.
    let expected = invitation.record().clone();
    let mut next = expected.clone();
    next.state = InvitationState::Locked {
        attempt_id: kr_pairing::host::new_attempt_id().expect("an attempt"),
    };
    assert_eq!(
        kr_pairing::platform::InvitationStore::transition(&&harness.store, &expected, &next)
            .expect("a write"),
        kr_pairing::platform::TransitionOutcome::Written
    );
    assert!(matches!(
        run_redemption(&harness, &mut invitation, &payload),
        Err(PairingError::CandidateLocked)
    ));
}

/// KR-REQ-10.38: both entry modes share one atomic candidate and consumption record.
#[test]
fn a_write_that_lost_a_race_does_not_undo_the_writer_that_won() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &harness.host_peer(),
    )
    .expect("a proof");

    // The short-code route locks a candidate between this flow's read and its write. The
    // conditional write refuses rather than replacing that candidate.
    let mut locked = invitation.record().clone();
    locked.state = InvitationState::Locked {
        attempt_id: kr_pairing::host::new_attempt_id().expect("an attempt"),
    };
    harness.store.interleave(locked.clone());
    let peer = harness.client_peer();
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::CandidateLocked)
    ));
    assert_eq!(invitation.record().state, locked.state);
    assert_eq!(
        harness
            .store
            .snapshot()
            .into_iter()
            .find(|record| record.invitation_id == invitation.invitation_id())
            .expect("a record")
            .state,
        locked.state,
        "the winner's lock stands"
    );
}

/// KR-REQ-10.37: a commit that lost a race writes nothing.
#[test]
fn a_commit_that_lost_a_race_writes_nothing() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let (candidate, _) = run_redemption(&harness, &mut invitation, &payload).expect("a redemption");
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");

    let mut cancelled = invitation.record().clone();
    cancelled.state = InvitationState::Consumed {
        reason: PairingConsumedReason::Cancelled,
    };
    harness.store.interleave(cancelled.clone());
    assert!(matches!(
        harness.confirm(&mut invitation, candidate.transcript_digest, keys_digest),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Cancelled
        })
    ));
    assert_eq!(
        kr_pairing::platform::InvitationStore::commitment(
            &&harness.store,
            invitation.invitation_id()
        )
        .expect("a read"),
        None,
        "a commit that lost the race wrote no commitment either"
    );
}

/// KR-REQ-10.37: a retried redemption returns the same candidate and changes nothing.
#[test]
fn a_lost_response_does_not_strand_the_candidate() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &harness.host_peer(),
    )
    .expect("a proof");
    let peer = harness.client_peer();
    let first = invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("a redemption");

    // The response never reached the candidate, so it sends the same proof again. The attempt
    // identity is the host's, and this is the only way the candidate can learn it.
    let second = invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("the same candidate");
    assert_eq!(first, second);

    // Another device presenting the same proof from its own connection gets nothing: the retry is
    // for the endpoint that redeemed, and a new redemption is refused while a candidate holds it.
    let elsewhere = TestLivePeer::new(EndpointKey::from_bytes([0x66; 32]));
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &elsewhere),
        Err(PairingError::CandidateLocked)
    ));

    // And a cancelled invitation hands nothing back, retry or not, and has committed nothing.
    invitation
        .cancel(&harness.issuing_owner)
        .expect("cancelled");
    assert!(matches!(
        invitation.redeem(&proof, harness.client_keys.transport.public(), &peer),
        Err(PairingError::Consumed {
            reason: PairingConsumedReason::Cancelled
        })
    ));
    assert_eq!(
        kr_pairing::platform::InvitationStore::commitment(
            &&harness.store,
            invitation.invitation_id()
        )
        .expect("a read"),
        None,
        "a cancelled invitation commits nothing"
    );
}

/// KR-REQ-10.37: a redemption over altered rights, or a retry from the same authenticated endpoint
/// that alters the keys it declares, changes nothing. The first does not redeem, because `D` covers
/// the host's own proposal; the second is refused while the first candidate holds the invitation;
/// and what is committed is the first candidate's keys and the invitation's own rights.
#[test]
fn an_altered_redemption_changes_neither_the_keys_nor_the_rights() {
    let harness = Harness::new();
    let mut invitation = harness.issue();

    let mut wider = harness.scan(&invitation);
    wider.proposed_grant.actions = [ActionRight::SessionView, ActionRight::TerminalInput]
        .into_iter()
        .collect();
    assert!(matches!(
        run_redemption(&harness, &mut invitation, &wider),
        Err(PairingError::AuthenticationFailed)
    ));
    assert_eq!(invitation.record().state, InvitationState::Open);

    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &harness.host_peer(),
    )
    .expect("a proof");
    let peer = harness.client_peer();
    let first = invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("a redemption");

    let other = DeviceKeys::generate().expect("keys");
    let mut altered = candidate_identity(&harness);
    altered.keys.stored_envelope = *other.stored_envelope.public();
    altered.keys.notification_preview = *other.notification_preview.public();
    let (altered_proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &altered,
        &harness.host_peer(),
    )
    .expect("a proof");
    assert!(matches!(
        invitation.redeem(
            &altered_proof,
            harness.client_keys.transport.public(),
            &peer
        ),
        Err(PairingError::CandidateLocked)
    ));
    assert_eq!(
        invitation
            .redeem(&proof, harness.client_keys.transport.public(), &peer)
            .expect("the first redemption, retried"),
        first
    );

    let committed = harness
        .confirm(
            &mut invitation,
            first.transcript_digest,
            client_keys_digest(&harness.client_keys.public_keys()).expect("a digest"),
        )
        .expect("a commitment");
    assert_eq!(committed.client_keys, harness.client_keys.public_keys());
    assert_eq!(committed.grant.actions, proposal().actions);
}

/// KR-REQ-10.37: the committed result is reported to the candidate's authenticated endpoint alone.
#[test]
fn a_candidate_that_never_learnt_its_attempt_is_still_told_it_is_paired() {
    let harness = Harness::new();
    let mut invitation = harness.issue();
    let payload = harness.scan(&invitation);
    let challenge = invitation
        .issue_challenge(&harness.client_peer())
        .expect("a challenge");
    let (proof, _) = redeem_proof(
        &payload,
        &challenge,
        &harness.client_keys.authorisation,
        &candidate_identity(&harness),
        &harness.host_peer(),
    )
    .expect("a proof");
    let peer = harness.client_peer();
    let candidate = invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("a redemption");

    // The response was lost and the owner approved in the meantime. The candidate knows only that
    // it redeemed; the endpoint it authenticated with is what identifies it.
    let keys_digest = client_keys_digest(&harness.client_keys.public_keys()).expect("a digest");
    harness
        .confirm(&mut invitation, candidate.transcript_digest, keys_digest)
        .expect("a commitment");
    assert!(matches!(
        invitation.status(DirectStatusViewer::Candidate {
            attempt_id: None,
            live_peer: &peer,
        }),
        Ok(PairStatus::Committed { .. })
    ));
    // The retry still works too, so the device can learn its attempt identity.
    let retried = invitation
        .redeem(&proof, harness.client_keys.transport.public(), &peer)
        .expect("the same candidate");
    assert_eq!(retried, candidate);

    // After a restart the store answers, still only for that endpoint.
    let invitation_id = invitation.invitation_id();
    drop(invitation);
    assert!(matches!(
        kr_pairing::host::recover_candidate_status(&&harness.store, invitation_id, None, &peer),
        Ok(PairStatus::Committed { .. })
    ));
    let impostor = TestLivePeer::new(EndpointKey::from_bytes([0x88; 32]));
    assert!(matches!(
        kr_pairing::host::recover_candidate_status(&&harness.store, invitation_id, None, &impostor),
        Err(PairingError::NotIssuingOwner)
    ));
}

/// KR-REQ-10.38: the two entry modes use different proof domains.
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

/// KR-REQ-10.38: a code-mode payload is not an offline invitation.
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
