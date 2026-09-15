//! Cross-language conformance tests driven by `fixtures/relay/`.
//!
//! The TypeScript package loads the same files and asserts the same bytes and digests, so the
//! relay, the managed service and the account console cannot disagree about what a lease, a
//! receipt or a registration is.

use std::path::PathBuf;

use kr_cbor::{CanonicalMap, CanonicalValue, encode, sha256, to_canonical_value};
use kr_protocol::ids::{
    AccountId, InstallationId, PayerAuthorisationId, RelayInstanceId, RelayLeaseId,
    RelayLeaseRevision, RelayReceiptSequence, RelayRegion, RelayReservationId,
};
use kr_protocol::pairing::NetworkHint;
use kr_protocol::relay::{
    MAX_GRACE_BYTES, MAX_GRACE_DURATION_MS, MAX_OUTSTANDING_RESERVED_BYTES, MeteringRole,
    PayerAuthorisation, PayerPrincipal, RELAY_INSTANCE_DOMAIN, RELAY_LEASE_DOMAIN,
    RELAY_RECEIPT_DOMAIN, RELAY_REVOKE_DOMAIN, RelayConsumptionReceipt, RelayDirection, RelayGrace,
    RelayInstanceRegistration, RelayKeySuccession, RelayLease, RelayLeaseRevocation, RelayScope,
};
use kr_protocol::scalars::{
    EndpointKey, Nullable, RelayInstanceKey, ServiceAdmissionKey, TimestampMs, U64, Uuid,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value as Json;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/relay")
}

fn load(name: &str) -> Json {
    let path = fixture_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn case<'a>(document: &'a Json, id: &str) -> &'a Json {
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("case {id}"))
}

/// Parses the fixture value grammar into a canonical value.
///
/// It is the grammar `fixtures/cbor` and `fixtures/protocol` already use, so one reader in each
/// language serves every vector directory.
fn parse_value(description: &Json) -> CanonicalValue {
    let object = description.as_object().expect("value description object");
    assert_eq!(object.len(), 1, "a value description has exactly one key");
    let (kind, payload) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "int" => CanonicalValue::integer(
            payload
                .as_str()
                .expect("decimal string")
                .parse::<i128>()
                .expect("decimal integer"),
        )
        .expect("inside the 64-bit argument range"),
        "bytes" => {
            CanonicalValue::Bytes(hex::decode(payload.as_str().expect("hex")).expect("valid hex"))
        }
        "text" => CanonicalValue::text(payload.as_str().expect("string")),
        "bool" => CanonicalValue::Bool(payload.as_bool().expect("boolean")),
        "null" => CanonicalValue::Null,
        "array" => CanonicalValue::Array(
            payload
                .as_array()
                .expect("array")
                .iter()
                .map(parse_value)
                .collect(),
        ),
        "map" => {
            let mut map = CanonicalMap::new();
            for entry in payload.as_array().expect("array of pairs") {
                let pair = entry.as_array().expect("pair");
                map.insert(
                    pair[0].as_str().expect("text key").to_owned(),
                    parse_value(&pair[1]),
                )
                .expect("no duplicate keys");
            }
            CanonicalValue::Map(map)
        }
        other => panic!("unknown value kind {other}"),
    }
}

/// Checks one signed object against its vector.
///
/// The vector states four things about the same object, and each one catches a different mistake:
/// the value description catches a changed field, `cbor_hex` catches a changed encoding,
/// `signing_input_hex` catches a changed domain or wrapper, and `json` catches a changed managed
/// representation.
fn check<T>(
    document: &Json,
    id: &str,
    domain: &str,
    object: &T,
    signing_input_of: fn(&T) -> Vec<u8>,
) where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let vector = case(document, id);
    let value = to_canonical_value(object).expect("a canonical value");
    let signing_input = signing_input_of(object);

    assert_eq!(
        value,
        parse_value(&vector["value"]),
        "{id}: the object no longer matches the vector's value"
    );
    assert_eq!(
        hex::encode(encode(&value)),
        vector["cbor_hex"].as_str().expect("cbor_hex"),
        "{id}: canonical encoding changed"
    );
    assert_eq!(
        vector["domain"].as_str().expect("domain"),
        domain,
        "{id}: signing domain changed"
    );
    assert_eq!(
        hex::encode(&signing_input),
        vector["signing_input_hex"].as_str().expect("signing_input"),
        "{id}: signing input changed"
    );
    assert_eq!(
        hex::encode(sha256(&signing_input)),
        vector["sha256"].as_str().expect("sha256"),
        "{id}: signing input digest changed"
    );
    assert_eq!(
        serde_json::to_value(object).expect("a JSON representation"),
        vector["json"],
        "{id}: the JSON representation changed"
    );

    // The signing input is the domain and the object, and nothing else.
    assert_eq!(
        signing_input,
        encode(&CanonicalValue::Array(vec![
            CanonicalValue::text(domain),
            value
        ]))
    );

    // A receiver that was given only the JSON representation rebuilds the same object and signs
    // the same bytes. This is what the managed service does with a receipt that arrives over
    // HTTPS: nothing it verifies comes from re-serialised JSON, but the object it verifies does.
    let restored: T = serde_json::from_value(vector["json"].clone())
        .unwrap_or_else(|error| panic!("{id}: the JSON representation does not parse: {error}"));
    assert_eq!(&restored, object, "{id}: the JSON representation is lossy");
    assert_eq!(
        signing_input_of(&restored),
        signing_input,
        "{id}: a restored object signs different bytes"
    );
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn frankfurt() -> RelayInstanceId {
    RelayInstanceId::new(uuid(0x31))
}

fn ashburn() -> RelayInstanceId {
    RelayInstanceId::new(uuid(0x32))
}

fn reservation() -> RelayReservationId {
    RelayReservationId::new(uuid(0x11))
}

fn admission_key() -> ServiceAdmissionKey {
    ServiceAdmissionKey::from_bytes([0x41; 32])
}

/// The base vector: an account pays for a two-way pair, metered as it enters the relay.
fn bidirectional_lease() -> RelayLease {
    RelayLease {
        lease_id: RelayLeaseId::new(uuid(0x10)),
        revision: RelayLeaseRevision::new(1),
        reservation_id: reservation(),
        source_endpoint_key: EndpointKey::from_bytes([0x21; 32]),
        destination_endpoint_key: EndpointKey::from_bytes([0x22; 32]),
        direction: RelayDirection::Bidirectional,
        payer: PayerPrincipal::Account {
            account_id: AccountId::new("acct_2f8c1d").expect("an account id"),
        },
        payer_authorisation: PayerAuthorisation::HostSelected,
        byte_ceiling: U64::new(4 * 1024 * 1024),
        expires_at_ms: TimestampMs::new(1_800_000_060_000),
        relay_scope: RelayScope {
            ingress_relay_instance_id: frankfurt(),
            egress_relay_instance_id: ashburn(),
        },
        metering_relay_instance_id: frankfurt(),
        metering_role: MeteringRole::Ingress,
        grace: Nullable::null(),
        issuer_key: admission_key(),
    }
}

/// The exhaustion vector: an anonymous installation, sponsored, one way, inside its grace.
fn grace_lease() -> RelayLease {
    RelayLease {
        lease_id: RelayLeaseId::new(uuid(0x12)),
        revision: RelayLeaseRevision::new(7),
        reservation_id: RelayReservationId::new(uuid(0x13)),
        source_endpoint_key: EndpointKey::from_bytes([0x23; 32]),
        destination_endpoint_key: EndpointKey::from_bytes([0x24; 32]),
        direction: RelayDirection::SourceToDestination,
        payer: PayerPrincipal::Installation {
            installation_id: InstallationId::new(uuid(0x14)),
        },
        payer_authorisation: PayerAuthorisation::Sponsored {
            authorisation_id: PayerAuthorisationId::new("payauth_9b3e").expect("an authorisation"),
        },
        byte_ceiling: U64::new(MAX_OUTSTANDING_RESERVED_BYTES),
        expires_at_ms: TimestampMs::new(1_800_003_600_000),
        relay_scope: RelayScope {
            ingress_relay_instance_id: ashburn(),
            egress_relay_instance_id: ashburn(),
        },
        metering_relay_instance_id: ashburn(),
        metering_role: MeteringRole::Egress,
        grace: Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(1_800_000_000_000),
            ends_at_ms: TimestampMs::new(1_800_000_000_000 + MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(MAX_OUTSTANDING_RESERVED_BYTES + MAX_GRACE_BYTES),
        }),
        issuer_key: admission_key(),
    }
}

fn revocation() -> RelayLeaseRevocation {
    RelayLeaseRevocation {
        lease_id: RelayLeaseId::new(uuid(0x10)),
        revision: RelayLeaseRevision::new(2),
        relay_instance_id: frankfurt(),
        issued_at_ms: TimestampMs::new(1_800_000_030_000),
        issuer_key: admission_key(),
    }
}

fn receipt(sequence: u64, bytes: u64, at_ms: u64) -> RelayConsumptionReceipt {
    RelayConsumptionReceipt {
        relay_instance_id: frankfurt(),
        reservation_id: reservation(),
        sequence: RelayReceiptSequence::new(sequence),
        bytes_consumed: U64::new(bytes),
        lease_revision: RelayLeaseRevision::new(1),
        observed_at_ms: TimestampMs::new(at_ms),
    }
}

fn registration() -> RelayInstanceRegistration {
    RelayInstanceRegistration {
        relay_instance_id: frankfurt(),
        instance_key: RelayInstanceKey::from_bytes([0x61; 32]),
        relay_url: NetworkHint::new("https://relay-1.reach.kala.to").expect("a relay URL"),
        region: RelayRegion::new("eu-central").expect("a region"),
        valid_from_ms: TimestampMs::new(1_800_000_000_000),
        valid_until_ms: TimestampMs::new(1_831_536_000_000),
        successor: Nullable::null(),
    }
}

fn rotation() -> RelayInstanceRegistration {
    RelayInstanceRegistration {
        successor: Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x62; 32]),
            overlap_from_ms: TimestampMs::new(1_815_000_000_000),
            predecessor_retires_at_ms: TimestampMs::new(1_815_604_800_000),
        }),
        ..registration()
    }
}

#[test]
fn lease_vectors_match() {
    let document = load("leases.json");

    let bidirectional = bidirectional_lease();
    check(
        &document,
        "lease_bidirectional",
        RELAY_LEASE_DOMAIN,
        &bidirectional,
        |lease| lease.signing_input().expect("a signing input"),
    );

    let grace = grace_lease();
    check(
        &document,
        "lease_in_grace",
        RELAY_LEASE_DOMAIN,
        &grace,
        |lease| lease.signing_input().expect("a signing input"),
    );

    let revocation = revocation();
    check(
        &document,
        "lease_revocation",
        RELAY_REVOKE_DOMAIN,
        &revocation,
        |revocation| revocation.signing_input().expect("a signing input"),
    );
}

#[test]
fn receipt_vectors_match() {
    let document = load("receipts.json");

    let first = receipt(1, 262_144, 1_800_000_010_000);
    check(
        &document,
        "receipt_first",
        RELAY_RECEIPT_DOMAIN,
        &first,
        |receipt| receipt.signing_input().expect("a signing input"),
    );

    let second = receipt(2, 1_048_576, 1_800_000_020_000);
    check(
        &document,
        "receipt_second",
        RELAY_RECEIPT_DOMAIN,
        &second,
        |receipt| receipt.signing_input().expect("a signing input"),
    );

    assert!(second.follows(&first));
}

#[test]
fn instance_vectors_match() {
    let document = load("instances.json");

    let registration = registration();
    check(
        &document,
        "instance_registration",
        RELAY_INSTANCE_DOMAIN,
        &registration,
        |registration| registration.signing_input().expect("a signing input"),
    );

    let rotation = rotation();
    check(
        &document,
        "instance_rotation",
        RELAY_INSTANCE_DOMAIN,
        &rotation,
        |registration| registration.signing_input().expect("a signing input"),
    );
}

#[test]
fn every_vector_is_a_well_formed_object() {
    assert!(bidirectional_lease().is_well_formed());
    assert!(grace_lease().is_well_formed());
    assert!(registration().is_well_formed());
    assert!(rotation().is_well_formed());
    assert!(revocation().fences(&bidirectional_lease(), frankfurt()));
    assert!(bidirectional_lease().admits_payload(
        EndpointKey::from_bytes([0x21; 32]),
        EndpointKey::from_bytes([0x22; 32]),
        frankfurt(),
        ashburn()
    ));
    assert!(grace_lease().relay_scope.is_single_relay());
}

#[test]
fn the_two_leases_sign_differently() {
    let first = bidirectional_lease()
        .signing_input()
        .expect("a signing input");
    let second = grace_lease().signing_input().expect("a signing input");

    assert_ne!(first, second);
}
