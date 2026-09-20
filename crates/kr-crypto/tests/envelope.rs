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
    EnvelopePlaintext, EnvelopeVersion, ForwardedAuthority, MailboxPayloadType, SealedEnvelope,
    mailbox_size_bucket,
};
use kr_protocol::pairing::{
    AuthorityRevisionRecord, KeyPurpose, REVOCATION_DOMAIN, RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, KeyId, Nullable, Signature64, TimestampMs, U64, Uuid,
};

const NOW_MS: u64 = 1_000;
const EXPIRES_MS: u64 = 61_000;

/// What a host has recorded about the issuers and grants it can check an object against.
///
/// It answers from what it was told, never from an envelope. That is the whole of the seam: a
/// production host answers the same two questions from its durable grant store.
#[derive(Debug, Default)]
struct HostAuthority {
    issuers: BTreeMap<KeyId, AuthorisationKey>,
    grants: BTreeSet<(GrantId, KeyId)>,
}

impl HostAuthority {
    fn record_issuer(&mut self, issuer: &AuthorisationKeyPair) {
        self.issuers.insert(issuer.key_id(), *issuer.public());
    }

    /// Records a key under an identifier that is not its own, which nothing legitimate does.
    fn misfile(&mut self, under: KeyId, key: AuthorisationKey) {
        self.issuers.insert(under, key);
    }

    fn record_grant(&mut self, grant_id: GrantId, issuer: &AuthorisationKeyPair) {
        self.grants.insert((grant_id, issuer.key_id()));
    }
}

impl AuthorityDirectory for HostAuthority {
    fn issuer_key(&self, issuer_key_id: KeyId) -> Option<AuthorisationKey> {
        self.issuers.get(&issuer_key_id).copied()
    }

    fn grant_is_held(&self, grant_id: GrantId, issuer_key_id: KeyId) -> bool {
        self.grants.contains(&(grant_id, issuer_key_id))
    }
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
        issuer_device_id: DeviceId::new(Uuid::from_bytes([6; 16])),
        host_device_id: DeviceId::new(Uuid::from_bytes([7; 16])),
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

    let mut host = HostAuthority::default();
    host.record_issuer(&issuer);
    host.record_grant(grant_id, &issuer);

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

    let mut host = HostAuthority::default();
    host.record_issuer(&issuer);
    host.record_grant(grant_id, &issuer);

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
fn a_directory_that_answers_with_another_key_cannot_make_a_signature_verify() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let issuer = AuthorisationKeyPair::generate().expect("a keypair");
    let other = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&issuer, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let mut host = HostAuthority::default();
    host.misfile(issuer.key_id(), *other.public());
    host.record_grant(grant_id, &issuer);

    assert!(matches!(
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
            verify_authority_payload(&host, payload).map(|_| ())
        }),
        Err(CryptoError::BindingMismatch {
            what: "the issuer key an authority directory answered with"
        })
    ));
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
    host.record_issuer(&issuer);
    host.record_grant(held, &issuer);

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
    let elsewhere = AuthorisationKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));

    let object = signed_revocation(&issuer, grant_id);
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, Some(grant_id));

    let mut host = HostAuthority::default();
    host.record_issuer(&issuer);
    host.record_grant(grant_id, &elsewhere);

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

    let mut host = HostAuthority::default();
    host.record_issuer(&issuer);
    host.record_grant(grant_id, &issuer);

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
    let mut record = AuthorityRevisionRecord {
        host_device_id: DeviceId::new(Uuid::from_bytes([8; 16])),
        authority_revision: AuthorityRevision::new(4),
        previous_revision: AuthorityRevision::new(3),
        applied_requests: CanonicalSet::new(),
        issued_at_ms: TimestampMs::new(NOW_MS),
        host_key_id: host_key.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        kr_protocol::pairing::AUTHORITY_REVISION_DOMAIN,
        record.signing_input().expect("canonical bytes"),
    )
    .expect("a transcript");
    record.signature = sign::sign(&host_key, &transcript).expect("a signature");
    let object = ForwardedAuthority::AuthorityRevision(record);

    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let (_, sealed) = authority_envelope(&sender, &recipient, &object, None);

    let mut reader = HostAuthority::default();
    reader.record_issuer(&host_key);
    let mut verified = None;
    open_envelope(&recipient, sender.public(), &sealed, NOW_MS, |payload| {
        verified = Some(verify_authority_payload(&reader, payload)?);
        Ok(())
    })
    .expect("the record verifies");
    assert_eq!(verified, Some(object));
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

    // The impostor seals a well-formed envelope and writes the paired sender's identifier into
    // every place a name appears, inside the encryption and outside it.
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

    // A lifetime past section 9's day is refused on the same rule, which is what stops an item
    // outliving the replay record that would catch it a second time.
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

    let mut host = HostAuthority::default();
    host.record_issuer(&issuer);
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
    host.record_grant(grant_id, &issuer);

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
