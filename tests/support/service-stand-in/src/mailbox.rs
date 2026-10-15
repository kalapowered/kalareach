//! The encrypted mailbox, answering as the Worker's does: a delivery, and the recipient's claim, read
//! and acknowledgement.
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
    MAILBOX_CLAIM_LIFETIME_MS, MAX_MAILBOX_BYTES, MAX_MAILBOX_ITEMS, SealedEnvelope,
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
    let Ok(envelope) = serde_json::from_value::<SealedEnvelope>(body["envelope"].clone()) else {
        return invalid("A delivery carries one sealed envelope.");
    };
    place(mailboxes, signature, &recipient, envelope, now_ms)
}

/// What the feed's route reports of an announcement it placed beside a change: where the item
/// ended up, or why it did not, in the shape the feed answers with.
///
/// The change has committed by now, so nothing here turns its answer into a refusal: what stops
/// the announcement is reported beside the change.
pub(crate) fn announce(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    recipient: &StoredEnvelopeKey,
    envelope: SealedEnvelope,
    now_ms: u64,
) -> Value {
    let answer = place(mailboxes, signature, recipient, envelope, now_ms);
    let Ok(body) = serde_json::from_slice::<Value>(&answer.body) else {
        return json!({ "mailbox": "declined", "declined_reason": "the mailbox did not answer" });
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

/// Places one sealed envelope, as the mailbox does for a delivery.
fn place(
    mailboxes: &mut BTreeMap<String, Mailbox>,
    signature: &ServiceRequestSignature,
    recipient: &StoredEnvelopeKey,
    envelope: SealedEnvelope,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let address = address_of(recipient);
    let routed = serde_json::to_value(envelope.routing.recipient_key_id)
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned();
    if routed != address {
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
        return invalid(&broken.to_string());
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
            "This mailbox holds as many items as one may.",
        );
    }
    if held_bytes + stored_bytes > MAX_MAILBOX_BYTES {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This mailbox holds as many bytes of stored envelopes as one may.",
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

/// A position a mailbox has issued: a counter its arithmetic carries exactly, written as text.
fn position(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) || text.len() > 16 {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|position| *position < (1 << 53))
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
        Some(value) => match value.as_u64().filter(|limit| *limit >= 1) {
            Some(limit) => limit.min(128),
            None => return invalid("A page holds at least one item."),
        },
    };
    let claim = match body.get("claim") {
        None => None,
        Some(claim) => {
            let ephemeral =
                serde_json::from_value::<StoredEnvelopeKey>(claim["ephemeral_key"].clone());
            let value = serde_json::from_value::<Digest256>(claim["claim_value"].clone());
            match (ephemeral, value) {
                (Ok(ephemeral), Ok(value)) => Some((ephemeral, value)),
                _ => return invalid("A claim answers the challenge a read handed back."),
            }
        }
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
