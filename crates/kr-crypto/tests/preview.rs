//! Opening a sealed notification preview: what a phone's receiver checks before it shows text.
//!
//! The service that carries a preview can alter the routing record beside it, so the authenticated
//! plaintext is the whole truth and the record is a claim. Each case seals a preview the way the
//! host does (padded to the notification rule's bucket, sealed to the device's preview key by the
//! host's) with one thing wrong, and shows the check that refuses it by name. The host's own
//! tests open what the host sealed through the same function.

use kr_crypto::envelope::{PreviewRefusal, open_notification_envelope, pad_notification_preview};
use kr_crypto::keys::{NotificationPreviewKeyPair, key_id};
use kr_crypto::sealed::seal_notification_preview;
use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MailboxPayloadType, SealedEnvelope,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};

const NOW_MS: u64 = 1_700_000_000_000;
const EXPIRES_MS: u64 = 1_700_000_100_000;

struct Parties {
    host: NotificationPreviewKeyPair,
    device: NotificationPreviewKeyPair,
}

fn parties() -> Parties {
    Parties {
        host: NotificationPreviewKeyPair::generate().expect("a keypair"),
        device: NotificationPreviewKeyPair::generate().expect("a keypair"),
    }
}

fn plaintext(parties: &Parties) -> EnvelopePlaintext {
    EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id: EnvelopeId::new(Uuid::from_bytes([7; 16])),
        sender_key_id: key_id(
            KeyPurpose::NotificationPreview,
            parties.host.public().as_bytes(),
        ),
        recipient_key_id: key_id(
            KeyPurpose::NotificationPreview,
            parties.device.public().as_bytes(),
        ),
        payload_type: MailboxPayloadType::NotificationPreview,
        created_at_ms: TimestampMs::new(NOW_MS),
        expires_at_ms: TimestampMs::new(EXPIRES_MS),
        grant_id: Nullable::null(),
        environment_id: Nullable::null(),
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        thread_id: Nullable::null(),
        payload: Bytes::new(b"the body".to_vec()),
    }
}

/// The envelope the host would send for `plaintext`, with the routing record the host would write.
fn sealed(parties: &Parties, plaintext: &EnvelopePlaintext) -> SealedEnvelope {
    let encoded = kr_cbor::to_canonical_vec(plaintext).expect("encoded");
    let (padded, bucket) = pad_notification_preview(&encoded).expect("padded");
    seal_padded(parties, plaintext, &padded, bucket)
}

fn seal_padded(
    parties: &Parties,
    plaintext: &EnvelopePlaintext,
    padded: &[u8],
    bucket: u64,
) -> SealedEnvelope {
    let (nonce, ciphertext) =
        seal_notification_preview(&parties.host, parties.device.public(), padded).expect("sealed");
    SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: plaintext.envelope_id,
            recipient_key_id: plaintext.recipient_key_id,
            sender_key_id: plaintext.sender_key_id,
            expires_at_ms: plaintext.expires_at_ms,
            payload_type: MailboxPayloadType::NotificationPreview,
            thread_id: plaintext.thread_id,
            size_bucket_bytes: U64::new(bucket),
        },
        nonce,
        ciphertext: Bytes::new(ciphertext),
    }
}

fn open(parties: &Parties, envelope: &SealedEnvelope) -> Result<EnvelopePlaintext, PreviewRefusal> {
    open_notification_envelope(&parties.device, parties.host.public(), envelope, NOW_MS)
}

fn reason(result: Result<EnvelopePlaintext, PreviewRefusal>) -> &'static str {
    result.expect_err("the preview is refused").reason()
}

#[test]
fn a_preview_opens_for_its_recipient_and_its_sender_only() {
    let parties = parties();
    let sealed = sealed(&parties, &plaintext(&parties));
    let opened = open(&parties, &sealed).expect("the plaintext");
    assert_eq!(opened.payload.as_slice(), b"the body");

    let other = NotificationPreviewKeyPair::generate().expect("a keypair");
    assert_eq!(
        reason(open_notification_envelope(
            &other,
            parties.host.public(),
            &sealed,
            NOW_MS
        )),
        "authentication",
        "another recipient"
    );
    assert_eq!(
        reason(open_notification_envelope(
            &parties.device,
            other.public(),
            &sealed,
            NOW_MS
        )),
        "authentication",
        "another sender"
    );
}

#[test]
fn an_altered_routing_record_is_refused_by_the_check_it_breaks() {
    let parties = parties();
    let original = sealed(&parties, &plaintext(&parties));

    let mut moved = original.clone();
    moved.routing.envelope_id = EnvelopeId::new(Uuid::from_bytes([9; 16]));
    assert_eq!(
        reason(open(&parties, &moved)),
        "routing",
        "another identifier"
    );

    let mut restamped = original.clone();
    restamped.routing.expires_at_ms = TimestampMs::new(EXPIRES_MS + 1_000);
    assert_eq!(
        reason(open(&parties, &restamped)),
        "routing",
        "a later expiry"
    );

    let mut relabelled = original.clone();
    relabelled.routing.size_bucket_bytes = U64::new(4 * 1024);
    assert_eq!(
        reason(open(&parties, &relabelled)),
        "size",
        "another bucket"
    );

    let mut mailbox = original;
    mailbox.routing.payload_type = MailboxPayloadType::StateReference;
    assert_eq!(
        reason(open(&parties, &mailbox)),
        "not_a_preview",
        "a routing record that declares another kind"
    );
}

#[test]
fn an_expired_envelope_is_refused_rather_than_opened() {
    let parties = parties();
    let sealed = sealed(&parties, &plaintext(&parties));
    assert_eq!(
        reason(open_notification_envelope(
            &parties.device,
            parties.host.public(),
            &sealed,
            EXPIRES_MS
        )),
        "expired"
    );
}

#[test]
fn key_identifiers_inside_the_seal_must_name_the_keys_that_opened_it() {
    let parties = parties();
    let other = NotificationPreviewKeyPair::generate().expect("a keypair");

    let mut claims_another_sender = plaintext(&parties);
    claims_another_sender.sender_key_id =
        key_id(KeyPurpose::NotificationPreview, other.public().as_bytes());
    assert_eq!(
        reason(open(&parties, &sealed(&parties, &claims_another_sender))),
        "keys"
    );

    // The same 32 bytes registered for another purpose are another identifier.
    let mut claims_another_purpose = plaintext(&parties);
    claims_another_purpose.recipient_key_id = key_id(
        KeyPurpose::StoredEnvelope,
        parties.device.public().as_bytes(),
    );
    assert_eq!(
        reason(open(&parties, &sealed(&parties, &claims_another_purpose))),
        "keys"
    );
}

#[test]
fn a_plaintext_that_is_not_a_preview_or_not_an_envelope_is_refused() {
    let parties = parties();
    let mut another_kind = plaintext(&parties);
    another_kind.payload_type = MailboxPayloadType::StateReference;
    let encoded = kr_cbor::to_canonical_vec(&another_kind).expect("encoded");
    let (padded, bucket) = pad_notification_preview(&encoded).expect("padded");
    let envelope = seal_padded(&parties, &another_kind, &padded, bucket);
    assert_eq!(
        reason(open(&parties, &envelope)),
        "not_a_preview",
        "authenticated as another kind, routed as a preview"
    );

    let (padded, bucket) = pad_notification_preview(b"not an envelope plaintext").expect("padded");
    let envelope = seal_padded(&parties, &plaintext(&parties), &padded, bucket);
    assert_eq!(reason(open(&parties, &envelope)), "malformed");
}
