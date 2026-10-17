//! The encrypted mailbox, answering as the Worker's does: a delivery, and the recipient's claim,
//! read and acknowledgement.
//!
//! One mailbox per recipient, addressed by the identifier of the recipient's stored-envelope key.
//! A host leaves a sealed item for a device that is not connected; the service stores ciphertext it
//! cannot read and decides only what the envelope's shape and the sequence of deliveries let it
//! decide. The recipient reads and acknowledges: the first read of a mailbox is answered with a
//! challenge only the holder of the recipient's private key can answer, the key that answered
//! claims the mailbox, and from then on only that key and that kind of credential read it or say
//! what it has stored durably. An item whose expiry has passed is gone before any call reads it.
//!
//! The source is the web repository's `workers/api/src/mailbox/{index,mailbox}.ts`; each rule below
//! is one of its, and the fidelity table in the crate's documentation names the line.

use std::collections::BTreeMap;

use kr_client::services::ServiceHttpAnswer;
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_protocol::mailbox::{
    EnvelopeStructureError, MAILBOX_CLAIM_LIFETIME_MS, MAX_MAILBOX_BYTES,
    MAX_MAILBOX_ITEM_LIFETIME_MS, MAX_MAILBOX_ITEMS, SealedEnvelope,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Digest256, StoredEnvelopeKey};
use kr_protocol::service::{ServiceRequestSignature, ServiceRequestSigner};
use serde_json::{Value, json};

use crate::feed::key_text;
use crate::web::{answered, refusal};

/// The most items one writer may hold in one mailbox.
const ITEMS_PER_WRITER: u64 = 128;
/// The most stored bytes one writer may hold in one mailbox.
const BYTES_PER_WRITER: u64 = 4 * 1024 * 1024;

/// One item a mailbox holds.
#[derive(Clone, Debug)]
struct Item {
    envelope: SealedEnvelope,
    writer_key: String,
    stored_bytes: u64,
    stored_at_ms: u64,
}

/// What a mailbox remembers of an envelope identifier it has carried: for good, where the Worker
/// keeps it until the item's expiry and a day more.
#[derive(Clone, Debug)]
struct Carried {
    sequence: u64,
    digest: String,
}

/// The challenge a read of an unclaimed mailbox was handed, and what answers it.
struct Challenge {
    ephemeral: StoredEnvelopeKeyPair,
    expires_at_ms: u64,
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Challenge")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Who has proved the mailbox is theirs: the key that signed the answering read, and the kind of
/// credential it signed as.
#[derive(Debug)]
struct Claimant {
    key: String,
    signer: ServiceRequestSigner,
}

/// One recipient's mailbox.
#[derive(Debug, Default)]
pub(crate) struct Mailbox {
    items: BTreeMap<u64, Item>,
    carried: BTreeMap<String, Carried>,
    next_sequence: u64,
    /// The highest position the recipient has acknowledged.
    acknowledged_through: u64,
    challenge: Option<Challenge>,
    claimant: Option<Claimant>,
}

impl Mailbox {
    fn usage(&self) -> Value {
        let bytes: u64 = self.items.values().map(|item| item.stored_bytes).sum();
        json!({
            "items": self.items.len().to_string(),
            "bytes": bytes.to_string(),
            "item_limit": MAX_MAILBOX_ITEMS.to_string(),
            "byte_limit": MAX_MAILBOX_BYTES.to_string(),
        })
    }

    /// The sealed envelopes the mailbox holds, in the order they were stored.
    pub(crate) fn envelopes(&self) -> Vec<SealedEnvelope> {
        self.items
            .values()
            .map(|item| item.envelope.clone())
            .collect()
    }

    /// An item whose expiry has passed is removed before a call reads the mailbox, is never
    /// returned and counts against nothing. The identifiers it carried stay.
    fn sweep(&mut self, now_ms: u64) {
        self.items
            .retain(|_, item| item.envelope.routing.expires_at_ms.get() > now_ms);
    }

    /// Whether the caller is the key that claimed this mailbox, as the credential it signed with.
    fn belongs_to(&self, key: &str, signer: ServiceRequestSigner) -> bool {
        self.claimant
            .as_ref()
            .is_some_and(|claimant| claimant.key == key && claimant.signer == signer)
    }
}

fn invalid(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_REQUEST", message)
}

/// The identifier of a mailbox: the one the protocol derives from the recipient's key.
pub(crate) fn address_of(key: &StoredEnvelopeKey) -> String {
    let id = kr_crypto::keys::key_id(KeyPurpose::StoredEnvelope, key.as_bytes());
    serde_json::to_value(id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/// The digest an item is remembered by: what the stand-in stores of it, written the same way every
/// time, so a delivery sent again is told from another item under the same identifier.
fn digest_of(envelope: &SealedEnvelope) -> String {
    let encoded = serde_json::to_vec(envelope).expect("an envelope");
    kr_cbor::sha256(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `mailbox.deliver`: places one sealed item in a recipient's mailbox.
///
/// The order is the Worker's. The signature, the nonce and the freshness have been checked by the
/// route. Then the body, the mailbox the envelope is routed to, a repeat of an identifier this
/// mailbox has carried, the shape of the item, the thread it may replace, and only then the quota,
/// measured after the replacement so that a coalescing delivery into a full mailbox is not refused
/// for the space the item it replaces is about to give back.
pub(crate) fn deliver(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    body: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let Ok(recipient) = serde_json::from_value::<StoredEnvelopeKey>(body["recipient_key"].clone())
    else {
        return invalid("A mailbox is named by the recipient stored-envelope key it seals to.");
    };
    let envelope = match read_envelope(&body["envelope"]) {
        Ok(envelope) => envelope,
        Err(message) => {
            return invalid(
                &message.unwrap_or_else(|| "A delivery carries one sealed envelope.".to_owned()),
            );
        }
    };
    place(mailboxes, signature, &recipient, envelope, now_ms)
}

/// One sealed envelope, read as the contract reads it: against a closed schema, so that a document
/// that is no object, one with a field beside the record or one without a field of it is refused
/// in the words of the rule it breaks. The error is `None` for an envelope that breaks a rule of
/// the shape of a scalar, which the Worker words by field and this stand-in does not.
pub(crate) fn read_envelope(value: &Value) -> Result<SealedEnvelope, Option<String>> {
    let closed = |what: &str, value: &Value, fields: &[&str]| -> Option<String> {
        let Some(record) = value.as_object() else {
            return Some(format!("{what} is an object"));
        };
        if let Some(key) = record.keys().find(|key| !fields.contains(&key.as_str())) {
            let named = serde_json::to_string(key).unwrap_or_default();
            return Some(format!("{what} has no field {named}"));
        }
        fields
            .iter()
            .find(|field| !record.contains_key(**field))
            .map(|field| {
                format!(
                    "{what} is missing {}",
                    serde_json::to_string(field).unwrap_or_default()
                )
            })
    };
    if let Some(message) = closed(
        "a sealed envelope",
        value,
        &["ciphertext", "nonce", "routing"],
    ) {
        return Err(Some(message));
    }
    let routing = [
        "envelope_id",
        "expires_at_ms",
        "payload_type",
        "recipient_key_id",
        "sender_key_id",
        "size_bucket_bytes",
        "thread_id",
    ];
    if let Some(message) = closed("a routing record", &value["routing"], &routing) {
        return Err(Some(message));
    }
    serde_json::from_value::<SealedEnvelope>(value.clone()).map_err(|_| None)
}

/// What the feed's route reports of an announcement it placed beside a change: where the item
/// ended up, or why it did not, in the shape the feed answers with.
///
/// The change has committed by now, so nothing here turns its answer into a refusal: what stops
/// the announcement is reported beside the change. The route checks only that the recipient is
/// text; whether it is a key, and whether the item is routed to it, are found here, as the Worker
/// finds them, and worded as it words them.
pub(crate) fn announce(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    recipient: &str,
    envelope: SealedEnvelope,
    now_ms: u64,
) -> Value {
    let declined = |reason: &str| json!({ "mailbox": "declined", "declined_reason": reason });
    let Ok(recipient) = serde_json::from_value::<StoredEnvelopeKey>(json!(recipient)) else {
        return declined("that is not a recipient key");
    };
    if routed_to(&envelope) != address_of(&recipient) {
        return declined("that item is routed to another recipient");
    }
    let answer = place(mailboxes, signature, &recipient, envelope, now_ms);
    let Ok(body) = serde_json::from_slice::<Value>(&answer.body) else {
        return declined("the mailbox did not answer");
    };
    if body["ok"] == json!(true) {
        json!({ "mailbox": body["data"]["state"] })
    } else {
        json!({
            "mailbox": "declined",
            "declined_reason": body["error"]["message"],
        })
    }
}

/// The mailbox an envelope's routing record says it is for.
fn routed_to(envelope: &SealedEnvelope) -> String {
    serde_json::to_value(envelope.routing.recipient_key_id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/// What a caller is told about an envelope the structure check refuses, in the Worker's words.
fn structure_refusal(broken: EnvelopeStructureError) -> ServiceHttpAnswer {
    invalid(&match broken {
        EnvelopeStructureError::UndeclaredBucket { .. } => {
            "A sealed item declares one of the size buckets section 20 defines.".to_owned()
        }
        EnvelopeStructureError::CiphertextLength { .. } => {
            "A sealed item is its declared bucket plus the seal, and nothing else.".to_owned()
        }
        EnvelopeStructureError::AlreadyExpired { .. } => {
            "That item has already expired.".to_owned()
        }
        EnvelopeStructureError::LifetimeTooLong { .. } => format!(
            "A mailbox item expires within {} hours.",
            MAX_MAILBOX_ITEM_LIFETIME_MS / 3_600_000
        ),
        EnvelopeStructureError::ItemTooLarge { .. } => {
            "A stored item is at most the megabyte a control message may carry.".to_owned()
        }
        EnvelopeStructureError::AuthorityCoalesced => {
            "A payload that carries authority names no coalescing thread.".to_owned()
        }
    })
}

/// Places one sealed envelope, as the mailbox does for a delivery.
fn place(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    recipient: &StoredEnvelopeKey,
    envelope: SealedEnvelope,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let address = address_of(recipient);
    if routed_to(&envelope) != address {
        return invalid("That envelope is routed to another recipient.");
    }

    let writer_key = key_text(&signature.public_key);
    let mailbox = mailboxes.entry(address).or_default();
    mailbox.sweep(now_ms);
    let envelope_id = envelope.routing.envelope_id.to_string();
    let digest = digest_of(&envelope);

    if let Some(carried) = mailbox.carried.get(&envelope_id) {
        // The identifier has been delivered before, whether or not the item is still here. A repeat
        // of that delivery is answered with what the first one was told; a different item under
        // the same identifier is a conflict, because answering it as a duplicate would tell a
        // sender its item was stored when another one is.
        return if carried.digest == digest {
            answered(json!({
                "state": "duplicate",
                "sequence": carried.sequence.to_string(),
                "replaced_sequence": null,
                "stored": mailbox.usage(),
            }))
        } else {
            refusal(
                403,
                "FORBIDDEN",
                "That envelope identifier has already carried a different item.",
            )
        };
    }

    if let Err(broken) = envelope.check_structure(now_ms) {
        return structure_refusal(broken);
    }

    let stored_bytes = envelope.stored_bytes();
    let thread = envelope.routing.thread_id.as_ref().map(ToString::to_string);

    // The newest state notification of a thread replaces the older unread one from the same writer
    // and from nobody else's.
    let replaced = thread.as_ref().and_then(|thread| {
        mailbox
            .items
            .iter()
            .find(|(_, item)| {
                item.writer_key == writer_key
                    && item
                        .envelope
                        .routing
                        .thread_id
                        .as_ref()
                        .map(ToString::to_string)
                        .as_ref()
                        == Some(thread)
            })
            .map(|(sequence, _)| *sequence)
    });

    let held_items = mailbox.items.len() as u64 - u64::from(replaced.is_some());
    let held_bytes: u64 = mailbox
        .items
        .iter()
        .filter(|(sequence, _)| Some(**sequence) != replaced)
        .map(|(_, item)| item.stored_bytes)
        .sum();
    if held_items + 1 > MAX_MAILBOX_ITEMS {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            &format!("This mailbox holds {MAX_MAILBOX_ITEMS} items."),
        );
    }
    if held_bytes + stored_bytes > MAX_MAILBOX_BYTES {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            &format!("This mailbox holds {MAX_MAILBOX_BYTES} bytes of stored envelopes."),
        );
    }
    let (mine_items, mine_bytes) = mailbox
        .items
        .iter()
        .filter(|(sequence, item)| Some(**sequence) != replaced && item.writer_key == writer_key)
        .fold((0u64, 0u64), |(items, bytes), (_, item)| {
            (items + 1, bytes + item.stored_bytes)
        });
    if mine_items + 1 > ITEMS_PER_WRITER || mine_bytes + stored_bytes > BYTES_PER_WRITER {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This sender holds as much of that mailbox as one sender may.",
        );
    }

    if let Some(sequence) = replaced {
        mailbox.items.remove(&sequence);
    }
    mailbox.next_sequence += 1;
    let sequence = mailbox.next_sequence;
    mailbox.items.insert(
        sequence,
        Item {
            envelope,
            writer_key,
            stored_bytes,
            stored_at_ms: now_ms,
        },
    );
    mailbox
        .carried
        .insert(envelope_id, Carried { sequence, digest });
    answered(json!({
        "state": if replaced.is_some() { "coalesced" } else { "stored" },
        "sequence": sequence.to_string(),
        "replaced_sequence": replaced.map(|sequence| sequence.to_string()),
        "stored": mailbox.usage(),
    }))
}

/// The recipient key a read or an acknowledgement names, and the mailbox it addresses.
fn addressed(body: &Value) -> Result<(StoredEnvelopeKey, String), ServiceHttpAnswer> {
    let Ok(recipient) = serde_json::from_value::<StoredEnvelopeKey>(body["recipient_key"].clone())
    else {
        return Err(invalid(
            "A mailbox is named by the recipient stored-envelope key it seals to.",
        ));
    };
    let address = address_of(&recipient);
    Ok((recipient, address))
}

/// A position a mailbox has issued: a counter its arithmetic carries exactly, written as the
/// canonical decimal text of a number the service's language holds exactly, and nothing else.
fn position(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let canonical = text == "0"
        || (!text.starts_with('0') && (1..=16).contains(&text.len()) && !text.is_empty());
    if !canonical || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|position| *position < (1 << 53))
}

/// A JSON number the service's language holds as an exact integer, which is what it accepts as a
/// page limit: `2.0` is one, `1.5` is not, and nothing beyond 2^53 - 1 is.
fn safe_integer(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    if let Some(whole) = number.as_i64() {
        return (whole.unsigned_abs() < (1 << 53)).then_some(whole);
    }
    let float = number.as_f64()?;
    #[allow(clippy::cast_possible_truncation)]
    (float.fract() == 0.0 && float.abs() < 9_007_199_254_740_992.0).then_some(float as i64)
}

fn not_yours() -> ServiceHttpAnswer {
    refusal(403, "FORBIDDEN", "This mailbox belongs to another key.")
}

/// `mailbox.read`: a page of the recipient's own mailbox, or the challenge that claims it.
///
/// A mailbox nobody has claimed is handed a fresh challenge by each read, which replaces the one
/// before it; an answer that matches the challenge standing, before it has run out, claims the
/// mailbox for the key that signed it and reads on. A mailbox another key claimed is refused.
pub(crate) fn read(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    body: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let (recipient, address) = match addressed(body) {
        Ok(addressed) => addressed,
        Err(answer) => return answer,
    };
    let after = match body.get("after_sequence") {
        None => 0,
        Some(value) => match position(value) {
            Some(after) => after,
            None => return invalid("A cursor is a position this mailbox has issued."),
        },
    };
    let limit = match body.get("limit") {
        None => 32,
        Some(value) => match safe_integer(value).filter(|limit| *limit >= 1) {
            Some(limit) => limit.min(128).unsigned_abs(),
            None => return invalid("A page holds at least one item."),
        },
    };
    // The route reads a claim as an object with the two members as text, and nothing more of it:
    // whether they are a key and a digest, and whether they answer the challenge standing, is for
    // the mailbox, which hands a new challenge to an answer that does not.
    let claim = match body.get("claim") {
        None => None,
        Some(claim) => match (
            claim.get("ephemeral_key").and_then(Value::as_str),
            claim.get("claim_value").and_then(Value::as_str),
        ) {
            (Some(ephemeral), Some(value)) => Some((ephemeral, value)),
            _ => return invalid("A claim answers the challenge a read handed back."),
        },
    };

    let key = crate::feed::key_text(&signature.public_key);
    let mailbox = mailboxes.entry(address).or_default();
    mailbox.sweep(now_ms);

    if mailbox.claimant.is_some() {
        if !mailbox.belongs_to(&key, signature.signer) {
            return not_yours();
        }
    } else {
        let claimed = claim.is_some_and(|(ephemeral, value)| {
            let (Ok(ephemeral), Ok(value)) = (
                serde_json::from_value::<StoredEnvelopeKey>(json!(ephemeral)),
                serde_json::from_value::<Digest256>(json!(value)),
            ) else {
                return false;
            };
            mailbox.challenge.as_ref().is_some_and(|challenge| {
                challenge.ephemeral.public() == &ephemeral
                    && now_ms < challenge.expires_at_ms
                    && kr_crypto::sealed::expected_mailbox_claim(&challenge.ephemeral, &recipient)
                        .is_ok_and(|expected| expected == value)
            })
        });
        if claimed {
            mailbox.claimant = Some(Claimant {
                key,
                signer: signature.signer,
            });
            mailbox.challenge = None;
        } else {
            let ephemeral = StoredEnvelopeKeyPair::generate().expect("a challenge key");
            let offered = *ephemeral.public();
            let expires_at_ms = now_ms + MAILBOX_CLAIM_LIFETIME_MS;
            mailbox.challenge = Some(Challenge {
                ephemeral,
                expires_at_ms,
            });
            return answered(json!({
                "state": "claim_required",
                "challenge": {
                    "ephemeral_key": offered,
                    "expires_at_ms": expires_at_ms.to_string(),
                },
            }));
        }
    }

    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut page: Vec<(&u64, &Item)> = mailbox.items.range(after + 1..).take(limit + 1).collect();
    let more = page.len() > limit;
    page.truncate(limit);
    let next_after = page.last().map_or(after, |(sequence, _)| **sequence);
    let items: Vec<Value> = page
        .iter()
        .map(|(sequence, item)| {
            json!({
                "sequence": sequence.to_string(),
                "stored_at_ms": item.stored_at_ms.to_string(),
                "envelope": item.envelope,
            })
        })
        .collect();
    answered(json!({
        "state": "read",
        "items": items,
        "next_after_sequence": next_after.to_string(),
        "more": more,
        "stored": mailbox.usage(),
    }))
}

/// `mailbox.acknowledge`: the recipient says it has stored everything up to a position durably,
/// and the service removes it.
///
/// Only the key that claimed the mailbox, signing as it did then. A position the mailbox has not
/// issued is refused; one below what was acknowledged before removes nothing more.
pub(crate) fn acknowledge(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    body: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let (_, address) = match addressed(body) {
        Ok(addressed) => addressed,
        Err(answer) => return answer,
    };
    let Some(through) = position(&body["through_sequence"]) else {
        return invalid("An acknowledgement names a position this mailbox has issued.");
    };
    let key = crate::feed::key_text(&signature.public_key);
    let mailbox = mailboxes.entry(address).or_default();
    mailbox.sweep(now_ms);
    if mailbox.claimant.is_none() {
        return refusal(
            403,
            "FORBIDDEN",
            "This mailbox is read by the key that has proved it is its own.",
        );
    }
    if !mailbox.belongs_to(&key, signature.signer) {
        return not_yours();
    }
    if through > mailbox.next_sequence {
        return invalid("An acknowledgement names a position this mailbox has issued.");
    }
    let through = through.max(mailbox.acknowledged_through);
    let before = mailbox.items.len();
    mailbox.items.retain(|sequence, _| *sequence > through);
    let removed = before - mailbox.items.len();
    mailbox.acknowledged_through = through;
    answered(json!({
        "removed": removed.to_string(),
        "acknowledged_through": through.to_string(),
        "stored": mailbox.usage(),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use kr_crypto::envelope::seal_envelope;
    use kr_crypto::keys::key_id;
    use kr_protocol::ids::EnvelopeId;
    use kr_protocol::mailbox::{EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType};
    use kr_protocol::method::Method;
    use kr_protocol::scalars::{
        AuthorisationKey, Bytes, Nonce256, Nullable, Signature64, TimestampMs, Uuid,
    };
    use kr_protocol::service::{GatewayOrigin, ServiceRequestPayload};

    use super::*;

    pub(crate) const NOW: u64 = 1_800_000_000_000;

    fn caller(signer: ServiceRequestSigner, byte: u8) -> ServiceRequestSignature {
        ServiceRequestSignature {
            payload: ServiceRequestPayload {
                body_digest: Digest256::from_bytes([0; 32]),
                gateway_origin: GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
                method: Method::MailboxRead,
                nonce: Nonce256::from_bytes([byte; 32]),
                signed_at_ms: TimestampMs::new(NOW),
            },
            signer,
            public_key: AuthorisationKey::from_bytes([byte; 32]),
            signature: Signature64::from_bytes([byte; 64]),
        }
    }

    fn host() -> ServiceRequestSignature {
        caller(ServiceRequestSigner::Host, 0x11)
    }

    fn read_with(
        mailboxes: &mut BTreeMap<String, Mailbox>,
        recipient: &StoredEnvelopeKeyPair,
        extra: Value,
    ) -> Value {
        let mut body = json!({ "recipient_key": recipient.public() });
        for (member, value) in extra.as_object().expect("members") {
            body[member] = value.clone();
        }
        let answer = read(mailboxes, &host(), &body, NOW);
        serde_json::from_slice(&answer.body).expect("a JSON answer")
    }

    /// Claims the recipient's mailbox for `host()`, as the recipient's own read does.
    fn claimed(mailboxes: &mut BTreeMap<String, Mailbox>, recipient: &StoredEnvelopeKeyPair) {
        let challenge = read_with(mailboxes, recipient, json!({}));
        assert_eq!(challenge["data"]["state"], "claim_required");
        let ephemeral = challenge["data"]["challenge"]["ephemeral_key"].clone();
        let key = serde_json::from_value::<StoredEnvelopeKey>(ephemeral.clone()).expect("a key");
        let value = kr_crypto::sealed::answer_mailbox_claim(recipient, &key).expect("a value");
        let read = read_with(
            mailboxes,
            recipient,
            json!({ "claim": { "ephemeral_key": ephemeral, "claim_value": value } }),
        );
        assert_eq!(read["data"]["state"], "read", "{read}");
    }

    /// A sealed announcement from a fresh key to `recipient`, routed to `routed_to`, that expires
    /// at `expires_at_ms`.
    pub(crate) fn envelope_for(
        recipient: &StoredEnvelopeKey,
        routed_to: &StoredEnvelopeKey,
        expires_at_ms: u64,
    ) -> SealedEnvelope {
        let sender = StoredEnvelopeKeyPair::generate().expect("a key");
        seal_envelope(
            &sender,
            recipient,
            &EnvelopePlaintext {
                version: EnvelopeVersion::V1,
                envelope_id: EnvelopeId::new(Uuid::from_bytes([7; 16])),
                sender_key_id: key_id(KeyPurpose::StoredEnvelope, sender.public().as_bytes()),
                recipient_key_id: key_id(KeyPurpose::StoredEnvelope, routed_to.as_bytes()),
                payload_type: MailboxPayloadType::AuthorityFeedChange,
                created_at_ms: TimestampMs::new(NOW - 120_000),
                expires_at_ms: TimestampMs::new(expires_at_ms),
                grant_id: Nullable::null(),
                environment_id: Nullable::null(),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                thread_id: Nullable::null(),
                payload: Bytes::new(vec![0; 32]),
            },
        )
        .expect("a sealed item")
    }

    fn refused(answer: &ServiceHttpAnswer) -> (u16, String) {
        let body: Value = serde_json::from_slice(&answer.body).expect("a JSON answer");
        (
            answer.status,
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    }

    /// A position is the canonical decimal text of a counter the service's language holds exactly:
    /// the Worker's `counter` reads `+1`, `01`, ` 1`, `1e3` and a number beyond 2^53 as none.
    #[test]
    fn a_position_is_canonical_decimal_text_or_none() {
        for text in ["0", "1", "42", "9007199254740991"] {
            assert!(position(&json!(text)).is_some(), "{text}");
        }
        for text in [
            "",
            "+1",
            "-1",
            "01",
            " 1",
            "1 ",
            "1e3",
            "0x1",
            "1.0",
            "٣",
            "9007199254740992",
            "99999999999999999",
        ] {
            assert_eq!(position(&json!(text)), None, "{text:?}");
        }
        assert_eq!(position(&json!(1)), None, "a number is not text");
        assert_eq!(position(&Value::Null), None);
    }

    #[test]
    fn a_cursor_or_a_position_that_is_not_canonical_is_refused() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let mut mailboxes = BTreeMap::new();
        claimed(&mut mailboxes, &recipient);
        let answer = read(
            &mut mailboxes,
            &host(),
            &json!({ "recipient_key": recipient.public(), "after_sequence": "+1" }),
            NOW,
        );
        assert_eq!(
            refused(&answer),
            (
                400,
                "A cursor is a position this mailbox has issued.".to_owned()
            )
        );
        let answer = acknowledge(
            &mut mailboxes,
            &host(),
            &json!({ "recipient_key": recipient.public(), "through_sequence": "+0" }),
            NOW,
        );
        assert_eq!(
            refused(&answer),
            (
                400,
                "An acknowledgement names a position this mailbox has issued.".to_owned()
            )
        );
    }

    #[test]
    fn a_limit_is_an_exact_integer_of_at_least_one() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let mut mailboxes = BTreeMap::new();
        claimed(&mut mailboxes, &recipient);
        // A negative, a fraction and a number past the exact range are refused by the Worker at the
        // canonical body, in other words, before it reads the limit. No client here can sign such a
        // body and this route expects a canonical one, so they are not tried.
        for limit in [json!(0), json!("2"), json!(null)] {
            let answer = read(
                &mut mailboxes,
                &host(),
                &json!({ "recipient_key": recipient.public(), "limit": limit }),
                NOW,
            );
            assert_eq!(
                refused(&answer),
                (400, "A page holds at least one item.".to_owned()),
                "{limit}"
            );
        }
        for limit in [
            json!(1),
            json!(2.0),
            json!(100_000),
            json!(9_007_199_254_740_991_u64),
        ] {
            let read = read_with(&mut mailboxes, &recipient, json!({ "limit": limit }));
            assert_eq!(read["data"]["state"], "read", "{limit}: {read}");
        }
    }

    /// The route reads a claim as an object with two text members. What the text holds is for the
    /// mailbox: an answer that is no key or no digest, or that does not match the challenge, is
    /// answered with a new challenge on a mailbox nobody has claimed, and ignored on one somebody
    /// has.
    #[test]
    fn a_claim_that_is_not_a_key_and_a_digest_is_a_new_challenge_not_a_refusal() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let mut mailboxes = BTreeMap::new();
        for claim in [
            json!(null),
            json!([]),
            json!("x"),
            json!({}),
            json!({ "ephemeral_key": 1, "claim_value": "x" }),
        ] {
            let answer = read(
                &mut mailboxes,
                &host(),
                &json!({ "recipient_key": recipient.public(), "claim": claim }),
                NOW,
            );
            assert_eq!(
                refused(&answer),
                (
                    400,
                    "A claim answers the challenge a read handed back.".to_owned()
                ),
                "{claim}"
            );
        }
        let first = read_with(&mut mailboxes, &recipient, json!({}));
        for claim in [
            json!({ "ephemeral_key": "not a key", "claim_value": "not a digest" }),
            json!({
                "ephemeral_key": first["data"]["challenge"]["ephemeral_key"],
                "claim_value": "AAAA",
            }),
        ] {
            let again = read_with(&mut mailboxes, &recipient, json!({ "claim": claim }));
            assert_eq!(again["data"]["state"], "claim_required", "{again}");
            assert_ne!(
                again["data"]["challenge"]["ephemeral_key"],
                first["data"]["challenge"]["ephemeral_key"],
                "a new challenge replaces the one standing"
            );
        }

        claimed(&mut mailboxes, &recipient);
        let ignored = read_with(
            &mut mailboxes,
            &recipient,
            json!({ "claim": { "ephemeral_key": "not a key", "claim_value": "not a digest" } }),
        );
        assert_eq!(
            ignored["data"]["state"], "read",
            "a claimed mailbox ignores the claim: {ignored}"
        );
    }

    #[test]
    fn an_announcement_to_what_is_not_a_key_or_to_another_recipient_is_declined() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let other = StoredEnvelopeKeyPair::generate().expect("a key");
        let recipient_text = serde_json::to_value(recipient.public()).expect("text");
        let recipient_text = recipient_text.as_str().expect("text");
        let envelope = envelope_for(recipient.public(), recipient.public(), NOW + 60_000);
        let mut mailboxes = BTreeMap::new();

        let outcome = announce(&mut mailboxes, &host(), "not a key", envelope.clone(), NOW);
        assert_eq!(
            outcome,
            json!({ "mailbox": "declined", "declined_reason": "that is not a recipient key" })
        );

        let misrouted = envelope_for(other.public(), other.public(), NOW + 60_000);
        let outcome = announce(&mut mailboxes, &host(), recipient_text, misrouted, NOW);
        assert_eq!(
            outcome,
            json!({
                "mailbox": "declined",
                "declined_reason": "that item is routed to another recipient",
            })
        );
        assert!(mailboxes.is_empty(), "nothing was placed");

        let outcome = announce(&mut mailboxes, &host(), recipient_text, envelope, NOW);
        assert_eq!(outcome, json!({ "mailbox": "stored" }));
    }

    /// What the mailbox refuses of an item it is handed is worded as the Worker words it.
    #[test]
    fn an_item_that_has_expired_is_declined_in_the_workers_words() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let recipient_text = serde_json::to_value(recipient.public()).expect("text");
        let stale = envelope_for(recipient.public(), recipient.public(), NOW - 60_000);
        let outcome = announce(
            &mut BTreeMap::new(),
            &host(),
            recipient_text.as_str().expect("text"),
            stale,
            NOW,
        );
        assert_eq!(
            outcome,
            json!({ "mailbox": "declined", "declined_reason": "That item has already expired." })
        );
    }

    #[test]
    fn an_envelope_that_breaks_the_closed_schema_is_refused_in_the_contracts_words() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a key");
        let good = serde_json::to_value(envelope_for(
            recipient.public(),
            recipient.public(),
            NOW + 60_000,
        ))
        .expect("an envelope");
        assert!(read_envelope(&good).is_ok());

        assert_eq!(
            read_envelope(&Value::Null).unwrap_err().as_deref(),
            Some("a sealed envelope is an object")
        );
        let mut beside = good.clone();
        beside["note"] = json!("x");
        assert_eq!(
            read_envelope(&beside).unwrap_err().as_deref(),
            Some("a sealed envelope has no field \"note\"")
        );
        let mut control = good.clone();
        control["\u{1}"] = json!("x");
        assert_eq!(
            read_envelope(&control).unwrap_err().as_deref(),
            Some("a sealed envelope has no field \"\\u0001\"")
        );
        let mut without = good.clone();
        without.as_object_mut().expect("an object").remove("nonce");
        assert_eq!(
            read_envelope(&without).unwrap_err().as_deref(),
            Some("a sealed envelope is missing \"nonce\"")
        );
        let mut routed = good.clone();
        routed["routing"] = json!([]);
        assert_eq!(
            read_envelope(&routed).unwrap_err().as_deref(),
            Some("a routing record is an object")
        );
        let mut thread = good;
        thread["routing"]
            .as_object_mut()
            .expect("an object")
            .remove("thread_id");
        assert_eq!(
            read_envelope(&thread).unwrap_err().as_deref(),
            Some("a routing record is missing \"thread_id\"")
        );
    }
}
