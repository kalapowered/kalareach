//! `backup.checkpoint`: the newest backup generation this host's storage service accepted.
//!
//! The host answers from its own records and asks no service. A generation counts once the service
//! has accepted its descriptor, and stops counting when the host is deleting every object of it.
//! The answer names the archive, the service, the generation and the hash of its encrypted
//! manifest, which is what a restore compares a service's offer with. It is null when the host has
//! no backup setup or no such generation.
//!
//! The answer also proves which host gave it. The device draws a challenge and a key for each ask,
//! and the host answers with a box from its own stored-envelope key to the device's key. The box
//! holds the challenge, the endpoint the host's own identity serves and the checkpoint the answer
//! names. A device opens it with the key its pairing record declares for the host, so an answer is
//! only as good as the host's hold on that key, and a host that relays the ask to another host
//! cannot make the other host's box say it is its own.
//!
//! The method is served to a paired device that holds `host.manage`, and to no other caller.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ArchiveId, BackupGeneration};
use crate::scalars::{
    Bytes, Digest256, EndpointKey, Nonce192, Nonce256, Nullable, StoredEnvelopeKey,
};
use crate::service::GatewayOrigin;

/// The domain the plaintext of a host's box is written under, so that no other statement of the
/// same bytes is a proof of a checkpoint.
pub const HOST_CHECKPOINT_PROOF_DOMAIN: &str = "kr-backup-checkpoint-proof/1";

/// The most bytes the ciphertext of a host's box holds. It is the plaintext of the largest answer
/// an honest host gives, which names the longest origin a service has and the largest generation,
/// and the 16 bytes that authenticate a box. A longer ciphertext is refused when the answer is
/// read, before any work is done on it.
pub const MAX_PROOF_CIPHERTEXT: usize = 413;

/// Parameters of `backup.checkpoint`: what the host proves its answer with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckpointParams {
    /// A fresh 256-bit value the device drew for this ask. The host's box holds it, so an answer
    /// that was made for another ask is not taken for this one.
    pub challenge: Nonce256,
    /// A fresh stored-envelope public key the device drew for this ask, whose secret half never
    /// leaves the device. The host seals its box to it.
    pub reply_key: StoredEnvelopeKey,
}

/// One backup generation a host published, as the host reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "HostCheckpointWire")]
pub struct HostCheckpoint {
    /// The service the host's backups are kept at, as the host recorded it.
    pub service_origin: GatewayOrigin,
    /// The archive the generation belongs to.
    pub archive_id: ArchiveId,
    /// The generation. A host numbers its generations from 1, and a report of 0 is refused when it
    /// is read.
    pub backup_generation: BackupGeneration,
    /// The hash of the generation's encrypted manifest.
    pub encrypted_manifest_hash: Digest256,
}

/// What [`HostCheckpoint`] is read through, so that a generation of 0 is refused before a
/// checkpoint exists. The counter's own type takes every `u64`, and other records need that, so
/// the rule is this type's alone. The pattern keeps the published schema in step: a JSON counter
/// is a decimal string, and only a pattern can say that "0" is not one.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct HostCheckpointWire {
    /// The service the host's backups are kept at, as the host recorded it.
    service_origin: GatewayOrigin,
    /// The archive the generation belongs to.
    archive_id: ArchiveId,
    /// The generation. A host numbers its generations from 1, and a report of 0 is refused when it
    /// is read.
    #[schemars(extend("pattern" = "^[1-9][0-9]*$"))]
    backup_generation: BackupGeneration,
    /// The hash of the generation's encrypted manifest.
    encrypted_manifest_hash: Digest256,
}

impl TryFrom<HostCheckpointWire> for HostCheckpoint {
    type Error = &'static str;

    fn try_from(wire: HostCheckpointWire) -> Result<Self, Self::Error> {
        if wire.backup_generation.get() == 0 {
            return Err("a published backup generation is at least 1");
        }
        Ok(Self {
            service_origin: wire.service_origin,
            archive_id: wire.archive_id,
            backup_generation: wire.backup_generation,
            encrypted_manifest_hash: wire.encrypted_manifest_hash,
        })
    }
}

/// What `backup.checkpoint` answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckpointResult {
    /// The newest generation this host's storage service accepted and the host still keeps, or
    /// null when there is none.
    pub checkpoint: Nullable<HostCheckpoint>,
    /// The host's box, which shows that the host holds the stored-envelope key its pairing record
    /// declares and names the checkpoint above.
    pub proof: SealedCheckpointProof,
}

/// A box from the host's stored-envelope key to the key a device sent with its ask. Its plaintext is
/// `CBOR([domain, {challenge, checkpoint, host_endpoint_id}])` as [`HostCheckpointProof`] says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "SealedCheckpointProofWire")]
pub struct SealedCheckpointProof {
    /// The nonce the box was made with.
    pub nonce: Nonce192,
    /// The sealed bytes: at most 413 of them.
    pub ciphertext: Bytes,
}

/// What [`SealedCheckpointProof`] is read through, so that a box longer than any honest host makes
/// is refused where it is read, before it is opened. The schema carries the same length: the
/// longest unpadded base64url text of [`MAX_PROOF_CIPHERTEXT`] bytes.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SealedCheckpointProofWire {
    /// The nonce the box was made with.
    nonce: Nonce192,
    /// The sealed bytes: at most 413 of them.
    #[schemars(extend("maxLength" = 551))]
    ciphertext: Bytes,
}

impl TryFrom<SealedCheckpointProofWire> for SealedCheckpointProof {
    type Error = String;

    fn try_from(wire: SealedCheckpointProofWire) -> Result<Self, Self::Error> {
        if wire.ciphertext.len() > MAX_PROOF_CIPHERTEXT {
            return Err(format!("a box is at most {MAX_PROOF_CIPHERTEXT} bytes"));
        }
        Ok(Self {
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
        })
    }
}

/// What a host's box says, as the host writes it and the device writes it again from what it
/// knows. The plaintext is the canonical CBOR array of [`HOST_CHECKPOINT_PROOF_DOMAIN`] and this
/// value, and a device takes an answer only when the box holds exactly the bytes it expects. It
/// is never sent as it is: only the box is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostCheckpointProof {
    /// The challenge of the ask this answer is made for.
    pub challenge: Nonce256,
    /// The endpoint the host's own identity serves, never a value the ask carried: a host that
    /// relays an ask to another host gets that other host's endpoint back.
    pub host_endpoint_id: EndpointKey,
    /// The checkpoint the answer names, or null.
    pub checkpoint: Nullable<HostCheckpoint>,
}

#[cfg(test)]
mod tests {
    use kr_cbor::Limits;

    use super::*;
    use crate::scalars::Uuid;
    use crate::schema::schema_for;
    use crate::wire;

    fn checkpoint(generation: u64) -> HostCheckpoint {
        HostCheckpoint {
            service_origin: GatewayOrigin::new("https://storage.example").expect("an origin"),
            archive_id: ArchiveId::new(Uuid::from_bytes([0x11; 16])),
            backup_generation: BackupGeneration::new(generation),
            encrypted_manifest_hash: Digest256::from_bytes([0x22; 32]),
        }
    }

    fn answered(checkpoint: &HostCheckpoint) -> BackupCheckpointResult {
        BackupCheckpointResult {
            checkpoint: Nullable::some(checkpoint.clone()),
            proof: proof(48),
        }
    }

    /// The answer the host gives and the answer a device reads are one value, in both forms.
    #[test]
    fn a_checkpoint_round_trips_in_cbor_and_in_json() {
        for result in [
            answered(&checkpoint(1)),
            answered(&checkpoint(u64::MAX)),
            BackupCheckpointResult {
                checkpoint: Nullable::null(),
                proof: proof(0),
            },
        ] {
            let bytes = kr_cbor::to_canonical_vec(&result).expect("encodes");
            let read: BackupCheckpointResult =
                wire::decode(&bytes, &Limits::DEFAULT).expect("decodes");
            assert_eq!(read, result);
            let text = serde_json::to_string(&result).expect("writes");
            let read: BackupCheckpointResult = serde_json::from_str(&text).expect("reads");
            assert_eq!(read, result);
        }
    }

    /// A generation of 0 is no generation a host publishes, so no answer that carries one is read,
    /// in CBOR or in JSON, where a counter is the decimal string "0".
    #[test]
    fn a_generation_of_zero_is_refused_in_cbor_and_in_json() {
        let zero = answered(&checkpoint(0));
        let bytes = kr_cbor::to_canonical_vec(&zero).expect("encodes");
        let cbor = wire::decode::<BackupCheckpointResult>(&bytes, &Limits::DEFAULT);
        assert!(cbor.is_err(), "a CBOR 0 is refused: {cbor:?}");

        let text = serde_json::to_string(&zero).expect("writes");
        assert!(
            text.contains(r#""backup_generation":"0""#),
            "the JSON form of the counter is a string: {text}"
        );
        let json = serde_json::from_str::<BackupCheckpointResult>(&text);
        assert!(json.is_err(), "a JSON \"0\" is refused: {json:?}");

        let bare = serde_json::to_string(&checkpoint(0)).expect("writes");
        assert!(serde_json::from_str::<HostCheckpoint>(&bare).is_err());
    }

    /// The published schema says what the decoder does: the generation member carries the
    /// positive-decimal pattern, which a string "0" does not match.
    #[test]
    fn the_schema_refuses_a_generation_of_zero_as_the_decoder_does() {
        let schema = schema_for::<HostCheckpoint>();
        let member = &schema["properties"]["backup_generation"];
        assert_eq!(
            member["pattern"], "^[1-9][0-9]*$",
            "the generation member names the positive-decimal pattern: {member}"
        );
    }

    /// A member the answer does not declare is refused, and so is an origin that is not spelled as
    /// one: two spellings of one service would be two services to a restore.
    #[test]
    fn an_unknown_member_and_a_second_spelling_of_an_origin_are_refused() {
        let good = serde_json::to_value(checkpoint(3)).expect("writes");
        assert!(serde_json::from_value::<HostCheckpoint>(good.clone()).is_ok());

        let mut extra = good.clone();
        extra["token"] = "x".into();
        let refused = serde_json::from_value::<HostCheckpoint>(extra);
        assert!(
            refused.is_err(),
            "an unknown member is refused: {refused:?}"
        );

        let mut spelled = good;
        spelled["service_origin"] = "https://Storage.Example/".into();
        let refused = serde_json::from_value::<HostCheckpoint>(spelled);
        assert!(
            refused.is_err(),
            "a second spelling is refused: {refused:?}"
        );
    }

    /// A box of `len` bytes, as a host's answer carries it.
    fn proof(len: usize) -> SealedCheckpointProof {
        SealedCheckpointProof {
            nonce: Nonce192::from_bytes([0x33; 24]),
            ciphertext: Bytes::new(vec![0x44; len]),
        }
    }

    fn params() -> BackupCheckpointParams {
        BackupCheckpointParams {
            challenge: Nonce256::from_bytes([0xAA; 32]),
            reply_key: StoredEnvelopeKey::from_bytes([0xCC; 32]),
        }
    }

    /// The ask carries the challenge and the reply key, in CBOR and in JSON, and each is read back
    /// as it was sent.
    #[test]
    fn the_ask_round_trips_in_cbor_and_in_json() {
        let ask = params();
        let bytes = kr_cbor::to_canonical_vec(&ask).expect("encodes");
        let read: BackupCheckpointParams = wire::decode(&bytes, &Limits::DEFAULT).expect("decodes");
        assert_eq!(read, ask);
        let text = serde_json::to_string(&ask).expect("writes");
        let read: BackupCheckpointParams = serde_json::from_str(&text).expect("reads");
        assert_eq!(read, ask);
        assert_eq!(
            serde_json::to_value(&ask).expect("writes"),
            serde_json::json!({
                "challenge": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
                "reply_key": "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw",
            }),
            "the JSON form names both members, as unpadded base64url"
        );
    }

    /// An ask with no member, or with a member the answer does not declare, is refused, in JSON and
    /// in CBOR. The complete ask reads, so the refusals are of the missing and the extra member.
    #[test]
    fn an_ask_without_a_member_or_with_an_extra_one_is_refused() {
        let complete = serde_json::to_value(params()).expect("writes");
        assert!(serde_json::from_value::<BackupCheckpointParams>(complete.clone()).is_ok());

        for member in ["challenge", "reply_key"] {
            let mut missing = complete.clone();
            missing.as_object_mut().expect("an object").remove(member);
            let refused = serde_json::from_value::<BackupCheckpointParams>(missing);
            assert!(refused.is_err(), "{member} missing is refused: {refused:?}");
        }
        let empty = serde_json::from_value::<BackupCheckpointParams>(serde_json::json!({}));
        assert!(
            empty.is_err(),
            "an ask with no members is refused: {empty:?}"
        );
        let empty_cbor = kr_cbor::to_canonical_vec(&serde_json::json!({})).expect("encodes");
        let refused = wire::decode::<BackupCheckpointParams>(&empty_cbor, &Limits::DEFAULT);
        assert!(refused.is_err(), "a CBOR ask with no members: {refused:?}");

        let mut extra = complete;
        extra["endpoint"] = "x".into();
        let refused = serde_json::from_value::<BackupCheckpointParams>(extra);
        assert!(
            refused.is_err(),
            "an unknown member is refused: {refused:?}"
        );
    }

    /// The answer carries the box, in CBOR and in JSON. A result with no box, a box with no nonce or
    /// no ciphertext, and a box with an extra member are each refused; the complete one reads.
    #[test]
    fn the_answer_carries_a_box_and_refuses_one_that_is_incomplete() {
        let complete = BackupCheckpointResult {
            checkpoint: Nullable::some(checkpoint(5)),
            proof: proof(48),
        };
        let bytes = kr_cbor::to_canonical_vec(&complete).expect("encodes");
        let read: BackupCheckpointResult = wire::decode(&bytes, &Limits::DEFAULT).expect("decodes");
        assert_eq!(read, complete);
        let json = serde_json::to_value(&complete).expect("writes");
        let read: BackupCheckpointResult = serde_json::from_value(json.clone()).expect("reads");
        assert_eq!(read, complete);

        let mut no_proof = json.clone();
        no_proof.as_object_mut().expect("an object").remove("proof");
        let refused = serde_json::from_value::<BackupCheckpointResult>(no_proof);
        assert!(
            refused.is_err(),
            "an answer with no box is refused: {refused:?}"
        );

        for member in ["nonce", "ciphertext"] {
            let mut cut = json.clone();
            cut["proof"]
                .as_object_mut()
                .expect("an object")
                .remove(member);
            let refused = serde_json::from_value::<BackupCheckpointResult>(cut);
            assert!(
                refused.is_err(),
                "a box with no {member} is refused: {refused:?}"
            );
        }
        let mut extra = json.clone();
        extra["proof"]["sender"] = "x".into();
        let refused = serde_json::from_value::<BackupCheckpointResult>(extra);
        assert!(
            refused.is_err(),
            "an unknown box member is refused: {refused:?}"
        );
        let mut extra = json;
        extra["note"] = "x".into();
        let refused = serde_json::from_value::<BackupCheckpointResult>(extra);
        assert!(
            refused.is_err(),
            "an unknown answer member is refused: {refused:?}"
        );
    }

    /// The text the box's plaintext starts with, which says what the box is for.
    #[test]
    fn the_proof_domain_is_exact() {
        assert_eq!(HOST_CHECKPOINT_PROOF_DOMAIN, "kr-backup-checkpoint-proof/1");
        assert_eq!(HOST_CHECKPOINT_PROOF_DOMAIN.len(), 28);
    }

    /// The bytes the host seals are `CBOR([domain, {challenge, checkpoint, host_endpoint_id}])`, with
    /// the members in the encoder's canonical order. Both vectors are written out byte by byte from
    /// the encoding's rules, so the encoder is not what vouches for them.
    #[test]
    fn the_plaintext_of_the_box_is_a_fixed_sequence_of_bytes() {
        let domain: &[u8] = b"kr-backup-checkpoint-proof/1";
        let head: &[u8] = &[0x82, 0x78, 0x1C];
        let challenge: &[u8] = &[0xAA; 32];
        let endpoint: &[u8] = &[0xBB; 32];
        // A map of three, then each key as a text string and its value.
        let map_and_challenge: Vec<u8> = [
            &[0xA3, 0x69][..],
            b"challenge",
            &[0x58, 0x20],
            challenge,
            &[0x6A],
            b"checkpoint",
        ]
        .concat();
        let tail: Vec<u8> = [&[0x70][..], b"host_endpoint_id", &[0x58, 0x20], endpoint].concat();

        let nothing = HostCheckpointProof {
            challenge: Nonce256::from_bytes([0xAA; 32]),
            host_endpoint_id: EndpointKey::from_bytes([0xBB; 32]),
            checkpoint: Nullable::null(),
        };
        let expected: Vec<u8> = [
            head,
            domain,
            map_and_challenge.as_slice(),
            &[0xF6], // null
            tail.as_slice(),
        ]
        .concat();
        assert_eq!(
            transcript(&nothing),
            expected,
            "the box of a host with nothing published"
        );

        // The checkpoint's four members in canonical order: shortest key first.
        let held = HostCheckpointProof {
            checkpoint: Nullable::some(checkpoint(300)),
            ..nothing
        };
        let origin = b"https://storage.example";
        let map: Vec<u8> = [
            &[0xA4, 0x6A][..],
            b"archive_id",
            &[0x50],
            &[0x11; 16],
            &[0x6E],
            b"service_origin",
            &[0x77],
            origin,
            &[0x71],
            b"backup_generation",
            &[0x19, 0x01, 0x2C], // 300
            &[0x77],
            b"encrypted_manifest_hash",
            &[0x58, 0x20],
            &[0x22; 32],
        ]
        .concat();
        let expected: Vec<u8> = [
            head,
            domain,
            map_and_challenge.as_slice(),
            map.as_slice(),
            tail.as_slice(),
        ]
        .concat();
        assert_eq!(
            transcript(&held),
            expected,
            "the box of a host that names a checkpoint"
        );
    }

    /// `CBOR([domain, object])` built from the encoder's own pieces, without the signing module
    /// that the host and the device use, which this crate does not reach.
    fn transcript(proof: &HostCheckpointProof) -> Vec<u8> {
        kr_cbor::encode(&kr_cbor::CanonicalValue::Array(vec![
            kr_cbor::CanonicalValue::Text(HOST_CHECKPOINT_PROOF_DOMAIN.to_owned()),
            kr_cbor::to_canonical_value(proof).expect("a value"),
        ]))
    }

    /// The largest box an honest host makes holds the longest origin and the largest generation, and
    /// the bound is that plaintext and the 16 bytes that authenticate it, no more and no less.
    #[test]
    fn the_bound_on_the_box_is_the_largest_honest_plaintext_and_its_tag() {
        let authority = format!("{}.{}", "a".repeat(60), "a".repeat(59));
        let origin = format!("https://{authority}");
        assert_eq!(origin.len(), 128, "the longest origin a service has");
        let mut largest = checkpoint(u64::MAX);
        largest.service_origin = GatewayOrigin::new(origin).expect("the longest origin");
        let longest = HostCheckpointProof {
            challenge: Nonce256::from_bytes([0xFF; 32]),
            host_endpoint_id: EndpointKey::from_bytes([0xFF; 32]),
            checkpoint: Nullable::some(largest),
        };
        assert_eq!(MAX_PROOF_CIPHERTEXT, transcript(&longest).len() + 16);
        let shortest = HostCheckpointProof {
            checkpoint: Nullable::null(),
            ..longest
        };
        assert!(
            transcript(&shortest).len() + 16 < MAX_PROOF_CIPHERTEXT,
            "a host with nothing published makes a smaller box"
        );
    }

    /// A box of exactly the bound is read and a box of one byte more is not, in CBOR and in JSON,
    /// and the refusal says it is the length. An empty box is read: whether it proves is the
    /// device's to say.
    #[test]
    fn a_box_one_byte_past_the_bound_is_refused_where_it_is_read() {
        for len in [0, 1, MAX_PROOF_CIPHERTEXT] {
            let held = proof(len);
            let bytes = kr_cbor::to_canonical_vec(&held).expect("encodes");
            let read = wire::decode::<SealedCheckpointProof>(&bytes, &Limits::DEFAULT);
            assert_eq!(
                read.as_ref().ok(),
                Some(&held),
                "{len} bytes in CBOR: a box within the bound reads: {read:?}"
            );
            let text = serde_json::to_string(&held).expect("writes");
            let read = serde_json::from_str::<SealedCheckpointProof>(&text);
            assert_eq!(
                read.as_ref().ok(),
                Some(&held),
                "{len} bytes in JSON: a box within the bound reads: {read:?}"
            );
        }
        let past = proof(MAX_PROOF_CIPHERTEXT + 1);
        let bytes = kr_cbor::to_canonical_vec(&past).expect("encodes");
        let cbor = wire::decode::<SealedCheckpointProof>(&bytes, &Limits::DEFAULT);
        // The CBOR reader reports every refusal of a member's value in one form, so the length is
        // what the box of exactly the bound above, which reads, shows it to be.
        assert!(
            cbor.is_err(),
            "a box one byte past the bound is refused in CBOR: {cbor:?}"
        );
        let expected = format!("a box is at most {MAX_PROOF_CIPHERTEXT} bytes");
        let text = serde_json::to_string(&past).expect("writes");
        let json = serde_json::from_str::<SealedCheckpointProof>(&text);
        assert!(
            json.as_ref()
                .err()
                .is_some_and(|error| error.to_string().contains(&expected)),
            "JSON names the length: {json:?}"
        );
        let answer = BackupCheckpointResult {
            checkpoint: Nullable::null(),
            proof: past,
        };
        let bytes = kr_cbor::to_canonical_vec(&answer).expect("encodes");
        let refused = wire::decode::<BackupCheckpointResult>(&bytes, &Limits::DEFAULT);
        assert!(
            refused.is_err(),
            "an answer with a long box is refused: {refused:?}"
        );
    }

    /// The published schema says what the decoder does: the ciphertext member names the longest
    /// base64url text that the bound allows, and the ask's members are required.
    #[test]
    fn the_schema_names_the_bound_and_requires_the_new_members() {
        let schema = schema_for::<SealedCheckpointProof>();
        let member = &schema["properties"]["ciphertext"];
        assert_eq!(
            member["maxLength"],
            (MAX_PROOF_CIPHERTEXT * 4).div_ceil(3),
            "the ciphertext member's longest text: {member}"
        );
        assert!(
            member["description"]
                .as_str()
                .is_some_and(|words| words.contains(&format!("at most {MAX_PROOF_CIPHERTEXT} "))),
            "the member's words state the same bound: {member}"
        );
        let ask = schema_for::<BackupCheckpointParams>();
        assert_eq!(
            ask["required"],
            serde_json::json!(["challenge", "reply_key"]),
            "both members of the ask are required: {ask}"
        );
        let answer = schema_for::<BackupCheckpointResult>();
        assert_eq!(
            answer["required"],
            serde_json::json!(["checkpoint", "proof"]),
            "both members of the answer are required: {answer}"
        );
    }
}
