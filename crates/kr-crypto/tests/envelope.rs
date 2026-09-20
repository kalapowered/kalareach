//! The mailbox envelope producer: what section 20 fixes about a stored item.
//!
//! Everything here goes through the crate's public interface. The suite is about the two rules
//! that make a mailbox item safe to store on a service that can read none of it: the authenticated
//! plaintext is the whole truth and the routing record beside it is a claim, and authority inside a
//! payload is the issuer's signature rather than the sender's.

use std::collections::{BTreeMap, BTreeSet};

use kr_crypto::envelope::{
    AuthorityDirectory, PairedSenders, ReplayLedger, open_delivered_envelope, open_envelope,
    seal_envelope, verify_authority_payload,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair, key_id};
use kr_crypto::sign::{self, SigningTranscript};
use kr_crypto::{CryptoError, vectors};
use kr_protocol::ids::{
    AuthorityRevision, DeviceId, EnvelopeId, EnvironmentId, GrantId, MailboxThreadId,
    RevocationRequestId, SessionEpoch, SessionId,
};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, ForwardedAuthority, ForwardedAuthorityKind,
    MailboxPayloadType, SealedEnvelope, mailbox_size_bucket,
};
use kr_protocol::pairing::{
    AuthorityRevisionRecord, KeyPurpose, REVOCATION_DOMAIN, RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, KeyId, Nullable, Signature64, TimestampMs, U64, Uuid,
};

const NOW_MS: u64 = 1_000;
const EXPIRES_MS: u64 = 61_000;

/// The device that issues the revocation requests in this suite.
const OWNER_DEVICE: [u8; 16] = [6; 16];
/// The device that issues the authority revision records in this suite.
const HOST_DEVICE: [u8; 16] = [7; 16];

fn owner_device() -> DeviceId {
    DeviceId::new(Uuid::from_bytes(OWNER_DEVICE))
}

fn host_device() -> DeviceId {
    DeviceId::new(Uuid::from_bytes(HOST_DEVICE))
}

/// What a reader has recorded about the issuers and grants it can check an object against.
///
/// It answers from what it was told, never from an envelope. That is the whole of the seam: a
/// production host answers the same two questions from its paired-device directory and its grant
/// directory.
#[derive(Debug, Default)]
struct HostAuthority {
    issuers: BTreeMap<(DeviceId, ForwardedAuthorityKind), AuthorisationKey>,
    grants: BTreeSet<(GrantId, DeviceId)>,
}

impl HostAuthority {
    fn record_issuer(
        &mut self,
        device_id: DeviceId,
        kind: ForwardedAuthorityKind,
        issuer: &AuthorisationKeyPair,
    ) {
        self.issuers.insert((device_id, kind), *issuer.public());
    }

    fn record_grant(&mut self, grant_id: GrantId, device_id: DeviceId) {
        self.grants.insert((grant_id, device_id));
    }
}

impl AuthorityDirectory for HostAuthority {
    fn issuer_key(
        &self,
        issuer: DeviceId,
        kind: ForwardedAuthorityKind,
    ) -> Option<AuthorisationKey> {
        self.issuers.get(&(issuer, kind)).copied()
    }

    fn grant_is_held(&self, grant_id: GrantId, issuer: DeviceId) -> bool {
        self.grants.contains(&(grant_id, issuer))
    }
}

/// A reader that records `issuer` as the owner device's revocation issuer and holds `grant_id`.
fn reader_recording(issuer: &AuthorisationKeyPair, grant_id: GrantId) -> HostAuthority {
    let mut host = HostAuthority::default();
    host.record_issuer(
        owner_device(),
        ForwardedAuthorityKind::RevocationRequest,
        issuer,
    );
    host.record_grant(grant_id, owner_device());
    host
}

fn plaintext(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKeyPair,
    payload_type: MailboxPayloadType,
    payload: Vec<u8>,
) -> EnvelopePlaintext {
    EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id: EnvelopeId::new(Uuid::from_bytes([9; 16])),
        sender_key_id: sender.key_id(),
        recipient_key_id: recipient.key_id(),
        payload_type,
        created_at_ms: TimestampMs::new(NOW_MS),
        expires_at_ms: TimestampMs::new(EXPIRES_MS),
        grant_id: Nullable::null(),
        environment_id: Nullable::null(),
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        thread_id: Nullable::null(),
        payload: Bytes::new(payload),
    }
}

/// A plaintext carrying every field section 20 names, so nothing is authenticated by omission.
fn fully_populated(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKeyPair,
) -> EnvelopePlaintext {
    let mut plaintext = plaintext(
        sender,
        recipient,
        MailboxPayloadType::StateReference,
        b"a reference to state".to_vec(),
    );
    plaintext.grant_id = Nullable::some(GrantId::new(Uuid::from_bytes([1; 16])));
    plaintext.environment_id = Nullable::some(EnvironmentId::new(Uuid::from_bytes([2; 16])));
    plaintext.session_id = Nullable::some(SessionId::new(Uuid::from_bytes([3; 16])));
    plaintext.session_epoch = Nullable::some(SessionEpoch::V1);
    plaintext.thread_id = Nullable::some(MailboxThreadId::new(Uuid::from_bytes([4; 16])));
    plaintext
}

fn paired_with(sender: &StoredEnvelopeKeyPair) -> PairedSenders {
    let mut senders = PairedSenders::new();
    senders.pair(*sender.public());
    senders
}

/// Signs a revocation request the way its issuer does, and wraps it as a forwarded object.
fn signed_revocation(issuer: &AuthorisationKeyPair, grant_id: GrantId) -> ForwardedAuthority {
    let mut grant_ids = CanonicalSet::new();
    grant_ids.insert(grant_id);
    let mut request = RevocationRequest {
        request_id: RevocationRequestId::new(Uuid::from_bytes([5; 16])),
        issuer_device_id: owner_device(),
        host_device_id: host_device(),
        target: RevocationTarget::Grants { grant_ids },
        issued_at_ms: TimestampMs::new(NOW_MS),
        issuer_key_id: issuer.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        REVOCATION_DOMAIN,
        request.signing_input().expect("canonical bytes"),
    )
    .expect("a transcript");
    request.signature = sign::sign(issuer, &transcript).expect("a signature");
    ForwardedAuthority::RevocationRequest(request)
}

/// Signs an ordered authority revision the way the host that issues it does.
fn signed_revision(
    issuer: &AuthorisationKeyPair,
    host_device_id: DeviceId,
) -> AuthorityRevisionRecord {
    let mut record = AuthorityRevisionRecord {
        host_device_id,
        authority_revision: AuthorityRevision::new(4),
        previous_revision: AuthorityRevision::new(3),
        applied_requests: CanonicalSet::new(),
        issued_at_ms: TimestampMs::new(NOW_MS),
        host_key_id: issuer.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        kr_protocol::pairing::AUTHORITY_REVISION_DOMAIN,
        record.signing_input().expect("canonical bytes"),
    )
    .expect("a transcript");
    record.signature = sign::sign(issuer, &transcript).expect("a signature");
    record
}

/// An envelope carrying a forwarded authority object, referencing `grant_id`.
fn authority_envelope(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKeyPair,
    object: &ForwardedAuthority,
    grant_id: Option<GrantId>,
) -> (EnvelopePlaintext, SealedEnvelope) {
    let mut plaintext = plaintext(
        sender,
        recipient,
        MailboxPayloadType::SignedAuthorityObject,
        kr_cbor::to_canonical_vec(object).expect("canonical bytes"),
    );
    plaintext.grant_id = grant_id.map_or_else(Nullable::null, Nullable::some);
    let sealed = seal_envelope(sender, recipient.public(), &plaintext).expect("a sealed envelope");
    (plaintext, sealed)
}

// ---------------------------------------------------------------------------
// KR-REQ-20.04: the versioned envelope, per recipient, under a libsodium nonce
// ---------------------------------------------------------------------------

#[test]
fn one_envelope_is_sealed_separately_for_each_recipient_and_opens_for_neither_other() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let first = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let second = StoredEnvelopeKeyPair::generate().expect("a keypair");

    let for_first = plaintext(
        &sender,
        &first,
        MailboxPayloadType::SyncChange,
        b"the same announcement".to_vec(),
    );
    let mut for_second = for_first.clone();
    for_second.recipient_key_id = second.key_id();

    let sealed_first = seal_envelope(&sender, first.public(), &for_first).expect("sealed");
    let sealed_second = seal_envelope(&sender, second.public(), &for_second).expect("sealed");

    // Two independent seals of one announcement: separate nonces and separate ciphertexts, so a
    // service holding both learns nothing by comparing them.
    assert_ne!(sealed_first.nonce, sealed_second.nonce);
    assert_ne!(sealed_first.ciphertext, sealed_second.ciphertext);
    assert_eq!(sealed_first.nonce.as_bytes().len(), 24);

    assert_eq!(
        open_envelope(&first, sender.public(), &sealed_first, NOW_MS, |_| Ok(()))
            .expect("the first recipient opens its own copy"),
        for_first
    );
    assert!(
        open_envelope(&first, sender.public(), &sealed_second, NOW_MS, |_| Ok(())).is_err(),
        "a recipient cannot open the copy sealed for another one"
    );
}

#[test]
fn the_version_and_every_field_section_20_names_are_inside_the_authentication() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = fully_populated(&sender, &recipient);
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");

    let opened = open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |_| Ok(()))
        .expect("the plaintext");
    assert_eq!(opened.version, EnvelopeVersion::V1);
    assert_eq!(opened.sender_key_id, sender.key_id());
    assert_eq!(opened.recipient_key_id, recipient.key_id());
    assert_eq!(opened.envelope_id, plaintext.envelope_id);
    assert_eq!(opened.payload_type, MailboxPayloadType::StateReference);
    assert_eq!(opened.created_at_ms, plaintext.created_at_ms);
    assert_eq!(opened.expires_at_ms, plaintext.expires_at_ms);
    assert_eq!(opened.grant_id, plaintext.grant_id);
    assert_eq!(opened.environment_id, plaintext.environment_id);
    assert_eq!(opened.session_id, plaintext.session_id);
    assert_eq!(opened.session_epoch, plaintext.session_epoch);
    assert_eq!(opened.thread_id, plaintext.thread_id);
    assert_eq!(opened.payload, plaintext.payload);

    // Deterministic CBOR: what came out re-encodes to the bytes that went in.
    assert_eq!(
        kr_cbor::to_canonical_vec(&opened).expect("canonical bytes"),
        kr_cbor::to_canonical_vec(&plaintext).expect("canonical bytes"),
    );

    // Every one of those fields is inside the box rather than beside it: one flipped ciphertext
    // byte fails to authenticate, whichever field it fell in.
    for index in [0usize, 1, 200, 600] {
        let mut tampered = sealed.clone();
        let mut bytes = tampered.ciphertext.as_slice().to_vec();
        bytes[index] ^= 0x01;
        tampered.ciphertext = Bytes::new(bytes);
        assert!(
            matches!(
                open_envelope(&recipient, sender.public(), &tampered, NOW_MS, |_| Ok(())),
                Err(CryptoError::Authentication { .. })
            ),
            "byte {index} of the ciphertext is authenticated"
        );
    }
}

#[test]
fn every_seal_draws_its_own_nonce_and_no_caller_can_supply_one() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::SyncChange,
        b"the same bytes every time".to_vec(),
    );

    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");
        assert_eq!(sealed.nonce.as_bytes().len(), 24);
        assert!(
            seen.insert(*sealed.nonce.as_bytes()),
            "a nonce repeated across sixteen seals of one plaintext"
        );
    }
}

#[test]
fn the_declared_bucket_is_applied_before_encryption_and_quota_measures_the_stored_ciphertext() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let mut short = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::ActionReceipt,
        vec![1; 4],
    );
    short.payload = Bytes::new(vec![1; 4]);
    let mut long = short.clone();
    long.payload = Bytes::new(vec![2; 500]);

    let first = seal_envelope(&sender, recipient.public(), &short).expect("sealed");
    let second = seal_envelope(&sender, recipient.public(), &long).expect("sealed");

    // One bucket, one stored size: the padding is inside the box, so the service sees one figure
    // for both.
    assert_eq!(
        first.routing.size_bucket_bytes,
        second.routing.size_bucket_bytes
    );
    assert_eq!(
        first.ciphertext.as_slice().len(),
        second.ciphertext.as_slice().len()
    );
    assert_eq!(first.stored_bytes(), second.stored_bytes());

    // Quota is measured on what is stored, not on the plaintext that was padded away.
    let unpadded = kr_cbor::to_canonical_vec(&short)
        .expect("canonical bytes")
        .len() as u64;
    assert!(first.stored_bytes() > unpadded);
    assert_eq!(
        first.routing.size_bucket_bytes.get(),
        mailbox_size_bucket(unpadded)
    );
    assert!(first.check_structure(NOW_MS).is_ok());
}

// ---------------------------------------------------------------------------
// KR-REQ-20.04: authority is the issuer's signature, never the sender's box
// ---------------------------------------------------------------------------

#[test]
fn an_authority_bearing_payload_is_accepted_only_on_its_issuers_own_signature() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&issuer, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let host = reader_recording(&issuer, grant_id);

    let mut verified = None;
    let opened = open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
        verified = Some(verify_authority_payload(&host, payload)?);
        Ok(())
    })
    .expect("the envelope opens");
    assert_eq!(
        opened.payload_type,
        MailboxPayloadType::SignedAuthorityObject
    );
    assert_eq!(verified.as_ref(), Some(&object));
    assert_eq!(object.issuer_key_id(), issuer.key_id());
}

#[test]
fn an_unsigned_authority_payload_inside_an_otherwise_valid_envelope_is_rejected() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    // The pairwise box is exactly as valid as the signed case: same sender, same recipient, same
    // shape. The only difference is that the issuer never signed the object.
    let ForwardedAuthority::RevocationRequest(mut request) = signed_revocation(&issuer, grant_id)
    else {
        unreachable!("the helper builds a revocation request")
    };
    request.signature = Signature64::from_bytes([0; 64]);
    let unsigned = ForwardedAuthority::RevocationRequest(request);
    let (_, sealed) = authority_envelope(&sender, &recipient, &unsigned, Some(grant_id));

    let host = reader_recording(&issuer, grant_id);

    assert!(
        matches!(
            open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
                verify_authority_payload(&host, payload).map(|_| ())
            }),
            Err(CryptoError::Authentication { .. })
        ),
        "a paired sender's box does not substitute for the issuer's signature"
    );

    // And the box itself was sound, which is what makes the refusal the signature's doing.
    assert!(open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |_| Ok(())).is_ok());
}

#[test]
fn an_object_signed_by_an_issuer_this_host_cannot_check_is_refused() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let stranger = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    // A genuine signature by a genuine key. What the host does not have is any record of that key,
    // and the envelope is not allowed to supply one.
    let object = signed_revocation(&stranger, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let host = HostAuthority::default();
    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        }),
        Err(CryptoError::Authentication { .. })
    ));
}

#[test]
fn a_key_recorded_for_another_device_or_another_role_does_not_sign_for_this_one() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let owner = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&owner, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    // The reader records this very key, and the signature over these very bytes is genuine. What
    // it records the key as is another device's revocation issuer, so resolving the device the
    // object names answers with nothing.
    let mut elsewhere = HostAuthority::default();
    elsewhere.record_issuer(
        host_device(),
        ForwardedAuthorityKind::RevocationRequest,
        &owner,
    );
    elsewhere.record_grant(grant_id, owner_device());
    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&elsewhere, payload).map(|_| ())
        }),
        Err(CryptoError::Authentication { .. })
    ));

    // Recorded for the right device in the wrong role is the same answer: only the target host
    // issues an ordered revision, and this key is the owner's.
    let mut wrong_role = HostAuthority::default();
    wrong_role.record_issuer(
        owner_device(),
        ForwardedAuthorityKind::AuthorityRevision,
        &owner,
    );
    wrong_role.record_grant(grant_id, owner_device());
    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&wrong_role, payload).map(|_| ())
        }),
        Err(CryptoError::Authentication { .. })
    ));
}

#[test]
fn an_object_that_names_a_key_the_reader_does_not_record_for_that_device_is_refused() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let owner = AuthorisationKeyPair::generate().expect("a keypair");
    let other = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    // A revocation request signed by `other`, naming the owner device. The reader resolves the
    // owner's own key, whose identifier is not the one the object carries, so the substitution is
    // caught before any signature is checked.
    let ForwardedAuthority::RevocationRequest(mut request) = signed_revocation(&other, grant_id)
    else {
        unreachable!("the helper builds a revocation request")
    };
    request.issuer_device_id = owner_device();
    let object = ForwardedAuthority::RevocationRequest(request);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let host = reader_recording(&owner, grant_id);
    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        }),
        Err(CryptoError::BindingMismatch {
            what: "the issuer key identifier a forwarded authority object names"
        })
    ));
}

#[test]
fn a_revision_record_that_names_another_host_is_not_accepted_under_this_ones_key() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let owner = AuthorisationKeyPair::generate().expect("a keypair");

    // The owner's key is one the reader records, as the owner device's revocation issuer. It signs
    // an ordered revision naming the owner device as the host. Only the target host issues one, and
    // the reader records no revision issuer for that device.
    let object = ForwardedAuthority::AuthorityRevision(signed_revision(&owner, owner_device()));
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, None);

    let mut host = HostAuthority::default();
    host.record_issuer(
        owner_device(),
        ForwardedAuthorityKind::RevocationRequest,
        &owner,
    );
    assert!(
        matches!(
            open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
                verify_authority_payload(&host, payload).map(|_| ())
            }),
            Err(CryptoError::Authentication { .. })
        ),
        "a recorded owner key does not issue a host's ordered revision"
    );
}

#[test]
fn a_grant_reference_names_authority_this_host_holds_rather_than_one_the_envelope_asserts() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let held = GrantId::new(Uuid::from_bytes([1; 16]));
    let asserted = GrantId::new(Uuid::from_bytes([2; 16]));

    let object = signed_revocation(&issuer, held);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(asserted));

    let mut host = HostAuthority::default();
    host.record_issuer(
        owner_device(),
        ForwardedAuthorityKind::RevocationRequest,
        &issuer,
    );
    host.record_grant(held, owner_device());

    assert!(
        matches!(
            open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
                verify_authority_payload(&host, payload).map(|_| ())
            }),
            Err(CryptoError::BindingMismatch {
                what: "the grant an envelope references, which this reader does not hold"
            })
        ),
        "naming a grant is not holding one"
    );

    // The same object, referencing the grant the host does hold, is accepted.
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(held));
    assert!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        })
        .is_ok()
    );
}

#[test]
fn a_grant_this_host_holds_under_another_issuer_does_not_answer_for_this_one() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let elsewhere = host_device();
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&issuer, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let mut host = HostAuthority::default();
    host.record_issuer(
        owner_device(),
        ForwardedAuthorityKind::RevocationRequest,
        &issuer,
    );
    host.record_grant(grant_id, elsewhere);

    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        }),
        Err(CryptoError::BindingMismatch { .. })
    ));
}

#[test]
fn a_payload_that_carries_no_authority_is_never_checked_as_authority() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    // A signed object smuggled into a sync announcement. Section 20 admits it as content, and
    // `open_envelope` never calls the authority check for a kind that bears none, so the only way
    // it could become authority is a caller asking directly. That is refused too.
    let object = signed_revocation(&issuer, grant_id);
    let mut smuggled = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::SyncChange,
        kr_cbor::to_canonical_vec(&object).expect("canonical bytes"),
    );
    smuggled.grant_id = Nullable::some(grant_id);
    let sealed = seal_envelope(&sender, recipient.public(), &smuggled).expect("sealed");

    let host = reader_recording(&issuer, grant_id);

    let opened = open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |_| {
        unreachable!("a sync change carries no authority")
    })
    .expect("the announcement opens as content");
    assert!(matches!(
        verify_authority_payload(&host, &opened),
        Err(CryptoError::BindingMismatch {
            what: "the payload type of an object checked as authority, which carries none"
        })
    ));
}

#[test]
fn a_host_revision_record_is_verified_under_the_host_key_the_reader_holds() {
    let host_key = AuthorisationKeyPair::generate().expect("a keypair");
    let object = ForwardedAuthority::AuthorityRevision(signed_revision(&host_key, host_device()));

    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, None);

    let mut reader = HostAuthority::default();
    reader.record_issuer(
        host_device(),
        ForwardedAuthorityKind::AuthorityRevision,
        &host_key,
    );
    let mut verified = None;
    open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
        verified = Some(verify_authority_payload(&reader, payload)?);
        Ok(())
    })
    .expect("the record verifies");
    assert_eq!(verified, Some(object));
}

/// One forwarded revocation request with its signature left out, in the tagged shape the union
/// travels as.
#[derive(serde::Serialize)]
struct UnsignedRevocation {
    revocation_request: UnsignedRequest,
}

/// A revocation request's fields without the signature, which nothing legitimate produces.
#[derive(serde::Serialize)]
struct UnsignedRequest {
    request_id: RevocationRequestId,
    issuer_device_id: DeviceId,
    host_device_id: DeviceId,
    target: RevocationTarget,
    issued_at_ms: TimestampMs,
    issuer_key_id: KeyId,
}

#[test]
fn an_authority_object_with_no_signature_field_is_not_one_this_build_reads() {
    // The unsigned case a reader actually meets is a field that is not there. The signed objects of
    // this protocol declare every field and refuse an unknown one, so a payload that leaves the
    // signature out never becomes a `ForwardedAuthority` at all: it stops at the decoder, before
    // any key is resolved.
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));
    let mut grant_ids = CanonicalSet::new();
    grant_ids.insert(grant_id);
    let canonical = kr_cbor::to_canonical_vec(&UnsignedRevocation {
        revocation_request: UnsignedRequest {
            request_id: RevocationRequestId::new(Uuid::from_bytes([5; 16])),
            issuer_device_id: owner_device(),
            host_device_id: host_device(),
            target: RevocationTarget::Grants { grant_ids },
            issued_at_ms: TimestampMs::new(NOW_MS),
            issuer_key_id: issuer.key_id(),
        },
    })
    .expect("canonical bytes");

    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let mut plaintext = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::SignedAuthorityObject,
        canonical,
    );
    plaintext.grant_id = Nullable::some(grant_id);
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");

    let host = reader_recording(&issuer, grant_id);
    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        }),
        Err(CryptoError::Encoding(_))
    ));
}

#[test]
fn an_envelope_version_this_build_does_not_publish_is_not_decoded() {
    // `EnvelopeVersion` is a closed set and `EnvelopePlaintext` refuses an unknown field, so a
    // plaintext naming another version, or carrying one more field, is not an envelope this build
    // reads. The check is on the decoder because that is where it happens: the box authenticates
    // whatever was sealed, and what makes those bytes an envelope is this decoding.
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let canonical =
        kr_cbor::to_canonical_vec(&fully_populated(&sender, &recipient)).expect("canonical bytes");
    assert!(
        kr_cbor::from_canonical_slice::<EnvelopePlaintext>(&canonical, &kr_cbor::Limits::DEFAULT)
            .is_ok()
    );

    let mut document: serde_json::Value = serde_json::from_slice(
        &serde_json::to_vec(&fully_populated(&sender, &recipient)).expect("a value"),
    )
    .expect("a value");
    document["version"] = serde_json::Value::String("kr-mailbox/2".to_owned());
    assert!(
        serde_json::from_value::<EnvelopePlaintext>(document.clone()).is_err(),
        "a version this build does not publish is refused"
    );

    document["version"] = serde_json::Value::String("kr-mailbox/1".to_owned());
    document["extra"] = serde_json::Value::Bool(true);
    assert!(
        serde_json::from_value::<EnvelopePlaintext>(document).is_err(),
        "a field this build does not declare is refused"
    );
}

// ---------------------------------------------------------------------------
// KR-REQ-20.05: untrusted routing, paired senders, replay identifiers
// ---------------------------------------------------------------------------

#[test]
fn every_routing_field_is_checked_against_the_field_the_box_authenticated() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let other = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = fully_populated(&sender, &recipient);
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");

    /// One rewrite a service could make to the record it stores beside a ciphertext.
    type Rewrite = Box<dyn Fn(&mut SealedEnvelope)>;

    let rewrites: Vec<(&str, Rewrite)> = vec![
        (
            "envelope_id",
            Box::new(|item: &mut SealedEnvelope| {
                item.routing.envelope_id = EnvelopeId::new(Uuid::from_bytes([0xff; 16]));
            }),
        ),
        (
            "recipient_key_id",
            Box::new(move |item: &mut SealedEnvelope| {
                item.routing.recipient_key_id = key_id(KeyPurpose::StoredEnvelope, &[0xfe; 32]);
            }),
        ),
        (
            "sender_key_id",
            Box::new(move |item: &mut SealedEnvelope| {
                item.routing.sender_key_id = key_id(KeyPurpose::StoredEnvelope, &[0xfd; 32]);
            }),
        ),
        (
            "expires_at_ms",
            Box::new(|item: &mut SealedEnvelope| {
                item.routing.expires_at_ms = TimestampMs::new(EXPIRES_MS - 1);
            }),
        ),
        (
            "payload_type",
            Box::new(|item: &mut SealedEnvelope| {
                item.routing.payload_type = MailboxPayloadType::ActionReceipt;
            }),
        ),
        (
            "thread_id",
            Box::new(|item: &mut SealedEnvelope| {
                item.routing.thread_id = Nullable::null();
            }),
        ),
        (
            "size_bucket_bytes",
            Box::new(|item: &mut SealedEnvelope| {
                item.routing.size_bucket_bytes = U64::new(2048);
            }),
        ),
    ];

    for (field, rewrite) in rewrites {
        let mut rewritten = sealed.clone();
        rewrite(&mut rewritten);
        assert!(
            matches!(
                open_envelope(&recipient, sender.public(), &rewritten, NOW_MS, |_| Ok(())),
                Err(CryptoError::BindingMismatch { .. })
            ),
            "a rewritten {field} is refused"
        );
    }

    // The recipient the record names is not what decides which key opens it either: the recipient
    // opens with its own key, and an item addressed elsewhere does not authenticate.
    assert!(open_envelope(&other, sender.public(), &sealed, NOW_MS, |_| Ok(())).is_err());
}

#[test]
fn an_envelope_from_a_sender_this_device_has_not_paired_with_is_refused() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::SyncChange,
        b"a change".to_vec(),
    );
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");

    let empty = PairedSenders::new();
    let mut ledger = ReplayLedger::new();
    assert!(
        matches!(
            open_delivered_envelope(&recipient, &empty, &mut ledger, &sealed, NOW_MS, |_| Ok(())),
            Err(CryptoError::BindingMismatch {
                what: "the sender of a delivered envelope, which this device has not paired with"
            })
        ),
        "an unpaired sender stops before anything is decrypted"
    );
    assert!(
        ledger.is_empty(),
        "a refused item records no replay identifier"
    );

    // Pairing is what changes the answer, and unpairing changes it back.
    let mut senders = paired_with(&sender);
    assert!(
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS, |_| Ok(
            ()
        ))
        .is_ok()
    );
    senders.unpair(sender.key_id());
    assert!(senders.is_empty());
}

#[test]
fn a_routing_record_cannot_introduce_a_sender_key() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let impostor = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");

    // The impostor seals a well-formed envelope of its own and then writes the paired sender's
    // identifier into the routing record, which is the one field a service can rewrite.
    let mut claimed = plaintext(
        &impostor,
        &recipient,
        MailboxPayloadType::SyncChange,
        b"a change".to_vec(),
    );
    claimed.sender_key_id = sender.key_id();
    let mut sealed = seal_envelope(&impostor, recipient.public(), &{
        let mut honest = claimed.clone();
        honest.sender_key_id = impostor.key_id();
        honest
    })
    .expect("sealed");
    sealed.routing.sender_key_id = sender.key_id();

    let senders = paired_with(&sender);
    let mut ledger = ReplayLedger::new();
    // The name selects the paired key, and that key does not open what the impostor sealed.
    assert!(matches!(
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS, |_| Ok(
            ()
        )),
        Err(CryptoError::Authentication { .. })
    ));
    assert!(ledger.is_empty());
}

#[test]
fn a_delivered_item_whose_shape_is_not_one_the_rules_produce_is_refused_before_any_key() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::SyncChange,
        b"a change".to_vec(),
    );
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");
    let senders = paired_with(&sender);
    let mut ledger = ReplayLedger::new();

    let mut truncated = sealed.clone();
    truncated.ciphertext = Bytes::new(truncated.ciphertext.as_slice()[..16].to_vec());
    assert!(matches!(
        open_delivered_envelope(
            &recipient,
            &senders,
            &mut ledger,
            &truncated,
            NOW_MS,
            |_| Ok(())
        ),
        Err(CryptoError::BindingMismatch {
            what: "the shape of a delivered envelope"
        })
    ));

    // A lifetime past section 9's day is refused on the same rule. It is the service's own
    // admission rule, applied here too so a recipient does not accept an item the service should
    // never have stored.
    let mut long_lived = plaintext.clone();
    long_lived.expires_at_ms = TimestampMs::new(NOW_MS + 48 * 60 * 60 * 1000);
    let sealed_long = seal_envelope(&sender, recipient.public(), &long_lived).expect("sealed");
    assert!(matches!(
        open_delivered_envelope(
            &recipient,
            &senders,
            &mut ledger,
            &sealed_long,
            NOW_MS,
            |_| Ok(())
        ),
        Err(CryptoError::BindingMismatch {
            what: "the shape of a delivered envelope"
        })
    ));
}

#[test]
fn a_replay_identifier_outlives_its_envelope_by_one_day_and_survives_a_restart() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::StateReference,
        b"a reference".to_vec(),
    );
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");
    let senders = paired_with(&sender);

    let mut ledger = ReplayLedger::new();
    assert!(
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS, |_| Ok(
            ()
        ))
        .is_ok()
    );
    assert_eq!(ledger.len(), 1);
    // A service that offers the same item again gets the same answer, through the one reading path
    // there is.
    assert!(matches!(
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS, |_| Ok(
            ()
        )),
        Err(CryptoError::BindingMismatch {
            what: "a replayed envelope identifier"
        })
    ));

    // The record is kept until expiry plus one day, and what the controller persists restores it.
    let persisted: Vec<_> = ledger.entries().collect();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].1, EXPIRES_MS + 24 * 60 * 60 * 1000);
    let mut restored = ReplayLedger::restore(persisted);
    restored.expire(EXPIRES_MS + 24 * 60 * 60 * 1000 - 1);
    assert_eq!(
        restored.len(),
        1,
        "the record outlives the envelope by a day"
    );
    assert!(restored.admit(&plaintext, NOW_MS).is_err());

    // Once the record may be forgotten, the envelope it named is long expired, so the window never
    // reopens.
    restored.expire(EXPIRES_MS + 24 * 60 * 60 * 1000);
    assert!(restored.is_empty());
    assert!(matches!(
        restored.admit(&plaintext, EXPIRES_MS + 24 * 60 * 60 * 1000),
        Err(CryptoError::BindingMismatch {
            what: "the expiry of an envelope, which has passed"
        })
    ));
}

// ---------------------------------------------------------------------------
// The committed vector
// ---------------------------------------------------------------------------

#[test]
fn the_committed_authority_vector_opens_and_verifies_under_the_issuer_it_names() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/crypto/envelopes.json");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the vector is readable"))
            .expect("the vector is JSON");
    let section = &document["authority_object"];

    let sender = vectors::envelope_sender_key().expect("the sender key");
    let recipient = vectors::envelope_recipient_key().expect("the recipient key");
    let issuer = vectors::host_authorisation_key().expect("the issuer key");
    assert_eq!(
        hex::encode(issuer.key_id().as_bytes()),
        section["issuer"]["key_id_hex"]
            .as_str()
            .expect("a hex string"),
    );

    let sealed: SealedEnvelope = serde_json::from_value(section["envelope"]["sealed_json"].clone())
        .expect("a sealed envelope");
    let expected: ForwardedAuthority =
        serde_json::from_value(section["object_json"].clone()).expect("a forwarded object");

    let ForwardedAuthority::RevocationRequest(request) = &expected else {
        unreachable!("the vector publishes a revocation request")
    };
    let RevocationTarget::Grants { grant_ids } = &request.target else {
        unreachable!("the vector revokes a grant")
    };
    let grant_id = *grant_ids
        .iter()
        .next()
        .expect("the vector revokes one grant");

    // The reader records the vector's issuer as the revocation issuer of the device the object
    // names, which is the only pairing under which that signature means anything.
    let mut host = HostAuthority::default();
    host.record_issuer(
        request.issuer_device_id,
        ForwardedAuthorityKind::RevocationRequest,
        &issuer,
    );
    host.record_grant(grant_id, request.issuer_device_id);

    let mut verified = None;
    let opened = open_envelope(
        &recipient,
        sender.public(),
        &sealed,
        section["envelope"]["opened_at_ms"]
            .as_u64()
            .expect("an instant"),
        |payload| {
            verified = Some(verify_authority_payload(&host, payload)?);
            Ok(())
        },
    )
    .expect("the vector's envelope opens");

    assert_eq!(verified.as_ref(), Some(&expected));
    assert_eq!(
        hex::encode(opened.payload.as_slice()),
        section["payload_canonical_hex"]
            .as_str()
            .expect("a hex string"),
    );
    assert_eq!(
        hex::encode(request.signing_input().expect("canonical bytes")),
        section["signing_input_hex"].as_str().expect("a hex string"),
    );
}

// ---------------------------------------------------------------------------
// The two halves together: a delivered item that carries authority
// ---------------------------------------------------------------------------

#[test]
fn a_delivered_authority_object_is_refused_until_the_reader_records_its_issuer_and_then_accepted_once()
 {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&issuer, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));
    let senders = paired_with(&sender);
    let mut ledger = ReplayLedger::new();

    // The reader has not learnt this issuer yet. The item is refused, and the replay identifier is
    // not spent: this is the transient case the ordering exists for.
    let unknowing = HostAuthority::default();
    assert!(matches!(
        open_delivered_envelope(
            &recipient,
            &senders,
            &mut ledger,
            &sealed,
            NOW_MS,
            |payload| { verify_authority_payload(&unknowing, payload).map(|_| ()) }
        ),
        Err(CryptoError::Authentication { .. })
    ));
    assert!(
        ledger.is_empty(),
        "a refused item spends no replay identifier"
    );

    // A signature that does not verify is refused the same way, and also spends nothing.
    let ForwardedAuthority::RevocationRequest(mut tampered) = object.clone() else {
        unreachable!("the helper builds a revocation request")
    };
    tampered.issued_at_ms = TimestampMs::new(NOW_MS + 1);
    let (_, resealed) = authority_envelope(
        &sender,
        &recipient,
        &ForwardedAuthority::RevocationRequest(tampered),
        Some(grant_id),
    );
    let host = reader_recording(&issuer, grant_id);
    assert!(matches!(
        open_delivered_envelope(
            &recipient,
            &senders,
            &mut ledger,
            &resealed,
            NOW_MS,
            |payload| { verify_authority_payload(&host, payload).map(|_| ()) }
        ),
        Err(CryptoError::Authentication { .. })
    ));
    assert!(ledger.is_empty());

    // Once the reader records the issuer, the item is accepted exactly once.
    let mut verified = None;
    open_delivered_envelope(
        &recipient,
        &senders,
        &mut ledger,
        &sealed,
        NOW_MS,
        |payload| {
            verified = Some(verify_authority_payload(&host, payload)?);
            Ok(())
        },
    )
    .expect("the item is accepted");
    assert_eq!(verified, Some(object));
    assert_eq!(ledger.len(), 1);

    // The second delivery stops at the replay identifier, before the item is decrypted again.
    assert!(matches!(
        open_delivered_envelope(
            &recipient,
            &senders,
            &mut ledger,
            &sealed,
            NOW_MS,
            |payload| { verify_authority_payload(&host, payload).map(|_| ()) }
        ),
        Err(CryptoError::BindingMismatch {
            what: "a replayed envelope identifier"
        })
    ));
}
