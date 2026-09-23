//! Values inside a tagged enum read back from the wire the way they read anywhere else.
//!
//! An internally tagged enum is decoded through serde's own buffer, which tells every field that
//! the format is human-readable. A digest, an identifier or a byte string that trusted that flag
//! read its KR-CBOR-1 byte string as base64url text and failed, so a Rust client could not read an
//! `agent_tools` result carrying a change operation at all. These tests hold the fix in place: the
//! contact skill's installation results, every change operation, the other tagged protocol value
//! that carries a digest and an identifier, and one field of every scalar with two forms, each
//! through the wire value a daemon answers with, through canonical bytes and through JSON.

use kr_cbor::{CanonicalMap, CanonicalValue, Limits};
use kr_protocol::action::RetrustEvidence;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::ids::DeviceId;
use kr_protocol::scalars::{
    AuthorisationKey, Bytes, Digest256, DurationMs, EndpointKey, KeyId, Mac256, Nonce192, Nonce256,
    NotificationPreviewKey, Nullable, RelayInstanceKey, SecretBytes32, ServiceAdmissionKey,
    Signature64, StoredEnvelopeKey, TimestampMs, U64, Uuid,
};
use kr_protocol::skill::{
    AgentTarget, AgentToolsInstallResult, AgentToolsRemoveResult, AgentToolsStatusResult,
    ChangeManifest, ChangeOperation, InstallScope, InstalledFile,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Sends a value the three ways it travels and checks it comes back unchanged each time.
///
/// The wire value is what a daemon's answer carries and what `ParamsValue::to_typed` reads for a
/// client; the canonical bytes are what a frame carries; JSON is what the installation record on
/// disk and the managed HTTP representation use.
fn travels<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let wire = ParamsValue::from_typed(value).expect("encodes as a wire value");
    let back: T = wire.to_typed().expect("the wire value decodes");
    assert_eq!(&back, value, "through the wire value");

    let bytes = kr_cbor::to_canonical_vec(value).expect("encodes as canonical bytes");
    let back: T = kr_cbor::from_canonical_slice(&bytes, &Limits::DEFAULT)
        .expect("the canonical bytes decode");
    assert_eq!(&back, value, "through canonical bytes");

    let text = serde_json::to_string(value).expect("encodes as JSON");
    let back: T = serde_json::from_str(&text).expect("the JSON decodes");
    assert_eq!(&back, value, "through JSON");
}

fn digest(byte: u8) -> Digest256 {
    Digest256::from_bytes([byte; 32])
}

/// One of each change operation, with bytes that are valid UTF-8 and bytes that are not, because
/// the two failed differently.
fn operations() -> Vec<ChangeOperation> {
    vec![
        ChangeOperation::CreateDirectory {
            path: "/home/someone/.claude/skills/kalareach-contact".to_owned(),
        },
        ChangeOperation::WriteFile {
            path: "/home/someone/.claude/skills/kalareach-contact/SKILL.md".to_owned(),
            digest: digest(7),
            replaced_digest: Nullable::null(),
        },
        ChangeOperation::WriteFile {
            path: "/home/someone/.claude/skills/kalareach-contact/TOOLS.md".to_owned(),
            digest: digest(0xff),
            replaced_digest: Nullable::some(digest(0x80)),
        },
        ChangeOperation::AddConfigurationEntry {
            path: "/home/someone/.claude.json".to_owned(),
            entry: "mcpServers.kalareach".to_owned(),
            digest: digest(0xc3),
            created_document: false,
        },
    ]
}

/// KR-REQ-11.50: every change operation an installation records, and the three `agent_tools`
/// results that carry them, read back through the wire value a Rust client decodes a daemon's
/// answer from; so `kr skill install`, `kr skill status` and `kr skill remove` can read what the
/// daemon did, including the removal record.
#[test]
fn agent_tools_results_carrying_change_operations_decode_in_a_rust_client() {
    for operation in operations() {
        travels(&operation);
    }
    let manifest = ChangeManifest {
        skill_version: "0.1.0".to_owned(),
        agent: AgentTarget::ClaudeCode,
        scope: InstallScope::User,
        root: "/home/someone".to_owned(),
        entry_point: vec![
            "/usr/local/bin/kr".to_owned(),
            "agent-tools".to_owned(),
            "--stdio".to_owned(),
        ],
        operations: operations(),
    };
    travels(&AgentToolsInstallResult {
        manifest: manifest.clone(),
        already_installed: false,
        unresolved: Vec::new(),
    });
    travels(&AgentToolsStatusResult {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        root: "/work/project".to_owned(),
        installed: true,
        skill_version: Nullable::some("0.1.0".to_owned()),
        files: vec![InstalledFile {
            path: "/work/project/.agents/skills/kalareach-contact/SKILL.md".to_owned(),
            expected_digest: digest(7),
            actual_digest: Nullable::some(digest(7)),
        }],
        drift: Vec::new(),
        removal: operations(),
    });
    travels(&AgentToolsRemoveResult {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        removed: operations(),
        retained: vec!["a file somebody changed".to_owned()],
    });
    travels(&manifest);
}

/// The other tagged protocol value with a digest or an identifier inside it reads back too, which
/// is what the fix being in the scalars rather than in one type buys.
#[test]
fn every_tagged_protocol_value_with_a_digest_or_an_identifier_reads_back() {
    travels(&RetrustEvidence::OwnerRetrust {
        action_digest: digest(0x9c),
    });
    travels(&RetrustEvidence::PairedPeer {
        device_id: DeviceId::new(Uuid::from_bytes([0xa5; 16])),
    });
}

/// One field of every scalar whose wire form and JSON form differ, inside an internally tagged
/// enum like the protocol's own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Tagged {
    Scalars {
        uuid: Uuid,
        bytes: Bytes,
        empty: Bytes,
        digest: Digest256,
        nonce: Nonce256,
        endpoint: EndpointKey,
        authorisation: AuthorisationKey,
        envelope: StoredEnvelopeKey,
        preview: NotificationPreviewKey,
        relay: RelayInstanceKey,
        admission: ServiceAdmissionKey,
        key_id: KeyId,
        signature: Signature64,
        short_nonce: Nonce192,
        mac: Mac256,
        secret: SecretBytes32,
        counter: U64,
        at: TimestampMs,
        lasting: DurationMs,
        present: Nullable<Digest256>,
        absent: Nullable<Uuid>,
    },
}

fn scalars() -> Tagged {
    Tagged::Scalars {
        uuid: Uuid::from_bytes([0xfe; 16]),
        bytes: Bytes::new(vec![0, 0xff, 7, 0x80]),
        empty: Bytes::new(Vec::new()),
        digest: digest(1),
        nonce: Nonce256::from_bytes([2; 32]),
        endpoint: EndpointKey::from_bytes([3; 32]),
        authorisation: AuthorisationKey::from_bytes([4; 32]),
        envelope: StoredEnvelopeKey::from_bytes([5; 32]),
        preview: NotificationPreviewKey::from_bytes([6; 32]),
        relay: RelayInstanceKey::from_bytes([0xe9; 32]),
        admission: ServiceAdmissionKey::from_bytes([8; 32]),
        key_id: KeyId::from_bytes([9; 32]),
        signature: Signature64::from_bytes([0xc0; 64]),
        short_nonce: Nonce192::from_bytes([11; 24]),
        mac: Mac256::from_bytes([12; 32]),
        secret: SecretBytes32::from_bytes([13; 32]),
        counter: U64::new(u64::MAX),
        at: TimestampMs::new(1_770_000_000_000),
        lasting: DurationMs::new(0),
        present: Nullable::some(digest(0xd7)),
        absent: Nullable::null(),
    }
}

#[test]
fn every_scalar_with_two_forms_reads_its_wire_form_inside_a_tagged_value() {
    travels(&scalars());
}

/// The same fields inside the other two containers serde reads through its own buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum Untagged {
    Identified {
        uuid: Uuid,
        digest: Digest256,
        secret: SecretBytes32,
        bytes: Bytes,
        present: Nullable<Nonce192>,
    },
    Counted {
        counter: U64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Inner {
    uuid: Uuid,
    digest: Digest256,
    secret: SecretBytes32,
    bytes: Bytes,
    at: TimestampMs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Flattened {
    label: String,
    #[serde(flatten)]
    inner: Inner,
}

#[test]
fn every_scalar_with_two_forms_reads_its_wire_form_inside_untagged_and_flattened_values() {
    travels(&Untagged::Identified {
        uuid: Uuid::from_bytes([0x5a; 16]),
        digest: digest(0xfe),
        secret: SecretBytes32::from_bytes([0x81; 32]),
        bytes: Bytes::new(vec![0xff, 0, 0x80]),
        present: Nullable::some(Nonce192::from_bytes([3; 24])),
    });
    travels(&Untagged::Counted {
        counter: U64::new(7),
    });
    travels(&Flattened {
        label: "flattened".to_owned(),
        inner: Inner {
            uuid: Uuid::from_bytes([0xc1; 16]),
            digest: digest(0x07),
            secret: SecretBytes32::from_bytes([0xee; 32]),
            bytes: Bytes::new(vec![1, 2, 3]),
            at: TimestampMs::new(1_770_000_000_000),
        },
    });
}

/// The JSON form is what it was: text for every one of these, so a human-readable document reads
/// the same as before and a JavaScript consumer sees nothing new.
#[test]
fn the_json_form_of_a_tagged_value_is_unchanged() {
    let value = serde_json::to_value(scalars()).expect("encodes");
    assert_eq!(value["kind"], "scalars");
    assert_eq!(value["uuid"], "fefefefe-fefe-fefe-fefe-fefefefefefe");
    assert_eq!(value["bytes"], "AP8HgA");
    assert_eq!(value["empty"], "");
    assert_eq!(
        value["digest"],
        kr_protocol::scalars::to_base64url(&[1; 32])
    );
    assert_eq!(value["counter"], u64::MAX.to_string());
    assert_eq!(value["absent"], serde_json::Value::Null);
}

/// A JSON document is refused for everything it was refused for before: a number or an array where
/// the text form belongs, text that is not the text form, and the wrong length, inside a tagged
/// value and outside one.
#[test]
fn json_refuses_what_it_refused_before() {
    let good = serde_json::to_value(scalars()).expect("encodes");
    for (field, wrong) in [
        ("digest", serde_json::json!(7)),
        ("digest", serde_json::json!([1, 2, 3])),
        ("digest", serde_json::json!("not base64url!")),
        (
            "digest",
            serde_json::json!(kr_protocol::scalars::to_base64url(&[1; 31])),
        ),
        ("uuid", serde_json::json!(12)),
        ("uuid", serde_json::json!("not-a-uuid")),
        ("bytes", serde_json::json!([0, 255])),
        (
            "secret",
            serde_json::json!(kr_protocol::scalars::to_base64url(&[1; 33])),
        ),
        ("secret", serde_json::json!([13, 13])),
        (
            "signature",
            serde_json::json!(kr_protocol::scalars::to_base64url(&[1; 32])),
        ),
    ] {
        let mut document = good.clone();
        document[field] = wrong.clone();
        assert!(
            serde_json::from_value::<Tagged>(document).is_err(),
            "{field} = {wrong} is refused inside a tagged value"
        );
    }
    assert!(serde_json::from_value::<Digest256>(serde_json::json!(7)).is_err());
    assert!(serde_json::from_value::<Uuid>(serde_json::json!(vec![0; 16])).is_err());
    assert!(serde_json::from_value::<SecretBytes32>(serde_json::json!("AA")).is_err());
}

/// A write-file operation as a wire value, with `digest` as its digest field.
fn write_file(digest: CanonicalValue) -> ParamsValue {
    let mut map = CanonicalMap::new();
    for (key, value) in [
        ("operation", CanonicalValue::Text("write_file".to_owned())),
        (
            "path",
            CanonicalValue::Text("/somewhere/SKILL.md".to_owned()),
        ),
        ("digest", digest),
        ("replaced_digest", CanonicalValue::Null),
    ] {
        map.insert(key.to_owned(), value).expect("a new key");
    }
    ParamsValue::new(CanonicalValue::Map(map))
}

/// On the wire the byte string is the only form. Text where it belongs, which a tagged value's
/// buffer would now read, is still refused, because a KR-CBOR-1 decode checks that the value it
/// produced encodes back to exactly the bytes it came from.
#[test]
fn text_where_the_wire_form_is_a_byte_string_is_still_refused() {
    let text = write_file(CanonicalValue::Text(kr_protocol::scalars::to_base64url(
        &[7; 32],
    )));
    assert!(
        text.to_typed::<ChangeOperation>().is_err(),
        "a digest written as text is not the wire form"
    );
    let short = write_file(CanonicalValue::Bytes(vec![7; 31]));
    assert!(
        short.to_typed::<ChangeOperation>().is_err(),
        "31 bytes are not a digest"
    );
    assert_eq!(
        write_file(CanonicalValue::Bytes(vec![7; 32]))
            .to_typed::<ChangeOperation>()
            .expect("the wire form decodes"),
        ChangeOperation::WriteFile {
            path: "/somewhere/SKILL.md".to_owned(),
            digest: digest(7),
            replaced_digest: Nullable::null(),
        }
    );
}
