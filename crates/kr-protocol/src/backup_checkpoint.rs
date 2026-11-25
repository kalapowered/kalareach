//! `backup.checkpoint`: the newest backup generation this host's storage service accepted.
//!
//! The host answers from its own records and asks no service. A generation counts once the service
//! has accepted its descriptor, and stops counting when the host is deleting every object of it.
//! The answer names the archive, the service, the generation and the hash of its encrypted
//! manifest, which is what a restore compares a service's offer with. It is null when the host has
//! no backup setup or no such generation.
//!
//! The method is served to a paired device that holds `host.manage`, and to no other caller.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ArchiveId, BackupGeneration};
use crate::scalars::{Digest256, Nullable};
use crate::service::GatewayOrigin;

/// Parameters of `backup.checkpoint`: none. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckpointParams {}

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
    service_origin: GatewayOrigin,
    archive_id: ArchiveId,
    #[schemars(extend("pattern" = "^[1-9][0-9]*$"))]
    backup_generation: BackupGeneration,
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
}
