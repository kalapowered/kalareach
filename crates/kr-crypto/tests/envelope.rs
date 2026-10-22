//! The mailbox envelope producer: what section 20 fixes about a stored item.
//!
//! Everything here goes through the crate's public interface. The suite is about the two rules
//! that make a mailbox item safe to store on a service that can read none of it: the authenticated
//! plaintext is the whole truth and the routing record beside it is a claim, and a mailbox never
//! gives authority: an item that bears it is refused whoever sealed it.

use std::collections::BTreeSet;

use kr_crypto::CryptoError;
use kr_crypto::envelope::{
    PairedSenders, ReplayLedger, open_delivered_envelope, open_envelope, seal_envelope,
};
use kr_crypto::keys::{StoredEnvelopeKeyPair, key_id};
use kr_protocol::ids::{
    EnvelopeId, EnvironmentId, GrantId, MailboxThreadId, SessionEpoch, SessionId,
};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType, SealedEnvelope, mailbox_size_bucket,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};

const NOW_MS: u64 = 1_000;
const EXPIRES_MS: u64 = 61_000;

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

/// An envelope that carries a payload of the kind that bears authority, referencing `grant_id`.
fn authority_envelope(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKeyPair,
    payload: &[u8],
    grant_id: Option<GrantId>,
) -> (EnvelopePlaintext, SealedEnvelope) {
    let mut plaintext = plaintext(
        sender,
        recipient,
        MailboxPayloadType::SignedAuthorityObject,
        payload.to_vec(),
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
        open_envelope(&first, sender.public(), &sealed_first, NOW_MS)
            .expect("the first recipient opens its own copy"),
        for_first
    );
    assert!(
        open_envelope(&first, sender.public(), &sealed_second, NOW_MS).is_err(),
        "a recipient cannot open the copy sealed for another one"
    );
}

#[test]
fn the_version_and_every_field_section_20_names_are_inside_the_authentication() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let plaintext = fully_populated(&sender, &recipient);
    let sealed = seal_envelope(&sender, recipient.public(), &plaintext).expect("sealed");

    let opened =
        open_envelope(&recipient, sender.public(), &sealed, NOW_MS).expect("the plaintext");
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
                open_envelope(&recipient, sender.public(), &tampered, NOW_MS),
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
// KR-REQ-20.04: the envelope's version is one this build publishes
// ---------------------------------------------------------------------------

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
// KR-REQ-20.04: authority is never taken from a mailbox
// ---------------------------------------------------------------------------

/// An authorisation-bearing payload, inside an envelope that is valid in every other way, is
/// rejected whatever the payload holds: the pairwise box proves that a paired device sealed the
/// item and proves nothing about authority, and no reader of a mailbox takes authority from one.
/// The control is the same box carrying the same bytes as a kind that bears none, which opens, so
/// the refusal is the payload's kind and not a fault of the box.
#[test]
fn an_authority_payload_inside_an_otherwise_valid_envelope_is_rejected() {
    let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
    let grant_id = GrantId::new(Uuid::from_bytes([1; 16]));
    let senders = paired_with(&sender);
    let payload = b"any bytes a paired sender seals";

    let (_, sealed) = authority_envelope(&sender, &recipient, payload, Some(grant_id));
    assert!(
        matches!(
            open_envelope(&recipient, sender.public(), &sealed, NOW_MS),
            Err(CryptoError::AuthorityNotAccepted)
        ),
        "an authority payload from a paired sender is refused"
    );
    let mut ledger = ReplayLedger::new();
    assert!(
        matches!(
            open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS),
            Err(CryptoError::AuthorityNotAccepted)
        ),
        "an authority payload is refused on the path a service's delivery takes"
    );
    assert!(
        ledger.is_empty(),
        "a refused item records no replay identifier"
    );

    // The control: the same bytes carried as a kind that bears no authority open, so the box, the
    // bindings and the expiry were all sound and the refusal above is the kind's.
    let carried = plaintext(
        &sender,
        &recipient,
        MailboxPayloadType::StateReference,
        payload.to_vec(),
    );
    let sealed = seal_envelope(&sender, recipient.public(), &carried).expect("a sealed envelope");
    assert!(open_envelope(&recipient, sender.public(), &sealed, NOW_MS).is_ok());
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
                open_envelope(&recipient, sender.public(), &rewritten, NOW_MS),
                Err(CryptoError::BindingMismatch { .. })
            ),
            "a rewritten {field} is refused"
        );
    }

    // The recipient the record names is not what decides which key opens it either: the recipient
    // opens with its own key, and an item addressed elsewhere does not authenticate.
    assert!(open_envelope(&other, sender.public(), &sealed, NOW_MS).is_err());
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
            open_delivered_envelope(&recipient, &empty, &mut ledger, &sealed, NOW_MS),
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
    assert!(open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS).is_ok());
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
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS),
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
        open_delivered_envelope(&recipient, &senders, &mut ledger, &truncated, NOW_MS),
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
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed_long, NOW_MS),
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
    assert!(open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS).is_ok());
    assert_eq!(ledger.len(), 1);
    // A service that offers the same item again gets the same answer, through the one reading path
    // there is.
    assert!(matches!(
        open_delivered_envelope(&recipient, &senders, &mut ledger, &sealed, NOW_MS),
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
