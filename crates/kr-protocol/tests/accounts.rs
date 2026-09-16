//! Cross-language conformance for the account vectors under `fixtures/accounts/`.
//!
//! The TypeScript package builds the same payloads from their JSON representation and asserts the
//! same bytes, so the managed service and a host sign and verify over identical input.

use std::path::PathBuf;
use std::str::FromStr;

use kr_cbor::{CanonicalMap, CanonicalValue, Limits, decode, encode};
use kr_protocol::account::{
    ChainError, MEMBERSHIP_LEASE_DOMAIN, MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease,
    MembershipLeasePayload, POLICY_AUTHORITY_DOMAIN, POLICY_AUTHORITY_HEAD_DOMAIN, PolicyAuthority,
    PolicyAuthorityHead, PolicyAuthorityHeadPayload, PolicyAuthorityLink,
    PolicyAuthorityLinkPayload, TeamRole,
};
use kr_protocol::ids::{AccountId, OrganisationId, PolicyKeyRevision};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use serde_json::Value as Json;

fn load() -> Json {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/accounts/leases.json");
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

fn uuid(text: &str) -> Uuid {
    Uuid::from_str(text).expect("valid uuid")
}

fn organisation() -> OrganisationId {
    OrganisationId::new(uuid("8f14e45f-ea1e-4b9e-9f3a-0a3a9b0d2f61"))
}

fn account() -> AccountId {
    AccountId::new("3c9f2b7a-5d18-4a62-9c07-1f5b8e2d4a90").expect("account identifier")
}

fn owner_lease() -> MembershipLease {
    MembershipLease {
        payload: MembershipLeasePayload {
            organisation_id: organisation(),
            account_id: account(),
            role: TeamRole::Owner,
            maximum_grants: TeamRole::Owner.maximum_grants(),
            issued_at_ms: TimestampMs::new(1_767_225_600_000),
            expires_at_ms: TimestampMs::new(1_767_225_600_000 + MEMBERSHIP_LEASE_MAX_LIFETIME_MS),
            key_revision: PolicyKeyRevision::new(2),
        },
        signature: Signature64::from_bytes([0x5a; 64]),
    }
}

fn narrowed_lease() -> MembershipLease {
    MembershipLease {
        payload: MembershipLeasePayload {
            organisation_id: organisation(),
            account_id: account(),
            role: TeamRole::Reviewer,
            maximum_grants: [ActionRight::SessionView, ActionRight::FilesRead]
                .into_iter()
                .collect(),
            issued_at_ms: TimestampMs::new(1_767_225_600_000),
            expires_at_ms: TimestampMs::new(1_767_225_600_000 + 5 * 60 * 1000),
            key_revision: PolicyKeyRevision::new(2),
        },
        signature: Signature64::from_bytes([0x6b; 64]),
    }
}

fn first_link() -> PolicyAuthorityLink {
    PolicyAuthorityLink {
        payload: PolicyAuthorityLinkPayload {
            organisation_id: organisation(),
            key_revision: PolicyKeyRevision::new(1),
            previous_key_revision: Nullable::null(),
            public_key: AuthorisationKey::from_bytes([0x11; 32]),
            not_before_ms: TimestampMs::new(1_767_139_200_000),
        },
        signature: Signature64::from_bytes([0x21; 64]),
    }
}

fn rotation_link() -> PolicyAuthorityLink {
    PolicyAuthorityLink {
        payload: PolicyAuthorityLinkPayload {
            organisation_id: organisation(),
            key_revision: PolicyKeyRevision::new(2),
            previous_key_revision: Nullable::some(PolicyKeyRevision::new(1)),
            public_key: AuthorisationKey::from_bytes([0x22; 32]),
            not_before_ms: TimestampMs::new(1_767_182_400_000),
        },
        signature: Signature64::from_bytes([0x32; 64]),
    }
}

fn head() -> PolicyAuthorityHead {
    PolicyAuthorityHead {
        payload: PolicyAuthorityHeadPayload {
            organisation_id: organisation(),
            key_revision: PolicyKeyRevision::new(2),
            issued_at_ms: TimestampMs::new(1_767_225_600_000),
            expires_at_ms: TimestampMs::new(1_767_225_600_000 + 15 * 60 * 1000),
        },
        signature: Signature64::from_bytes([0x43; 64]),
    }
}

fn published_authority() -> PolicyAuthority {
    PolicyAuthority {
        organisation_id: organisation(),
        chain: vec![first_link(), rotation_link()],
        head: head(),
    }
}

/// Asserts that `signing_input` matches the fixture bytes, its digest and its value description,
/// and that the record's JSON representation round-trips through the fixture document.
fn assert_vector<T>(document: &Json, id: &str, record: &T, signing_input: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let case = case(document, id);
    let expected_hex = case["cbor_hex"].as_str().expect("cbor_hex");

    assert_eq!(hex::encode(signing_input), expected_hex, "{id}: bytes");
    assert_eq!(
        hex::encode(kr_cbor::sha256(signing_input)),
        case["sha256"].as_str().expect("sha256"),
        "{id}: digest"
    );

    let described = parse_value(&case["value"]);
    assert_eq!(
        hex::encode(encode(&described)),
        expected_hex,
        "{id}: the fixture description and its bytes disagree"
    );
    assert_eq!(
        decode(&hex::decode(expected_hex).expect("hex"), &Limits::DEFAULT).expect("decode"),
        described,
        "{id}: decoded value"
    );

    let json = &case["json"];
    let parsed: T = serde_json::from_value(json.clone())
        .unwrap_or_else(|error| panic!("{id}: the JSON representation does not parse: {error}"));
    assert_eq!(&parsed, record, "{id}: the JSON representation");
    assert_eq!(
        &serde_json::to_value(record).expect("serialise"),
        json,
        "{id}: the JSON the record produces"
    );
}

#[test]
fn membership_lease_vectors_match() {
    let document = load();
    let lease = owner_lease();
    assert_vector(
        &document,
        "membership_lease",
        &lease,
        &lease.payload.signing_input().expect("signing input"),
    );

    let narrowed = narrowed_lease();
    assert_vector(
        &document,
        "membership_lease_narrowed",
        &narrowed,
        &narrowed.payload.signing_input().expect("signing input"),
    );
}

#[test]
fn policy_authority_vectors_match() {
    let document = load();

    let first = first_link();
    assert_vector(
        &document,
        "policy_authority_first_revision",
        &first,
        &first.payload.signing_input().expect("signing input"),
    );

    let rotation = rotation_link();
    assert_vector(
        &document,
        "policy_authority_rotation",
        &rotation,
        &rotation.payload.signing_input().expect("signing input"),
    );

    let head = head();
    assert_vector(
        &document,
        "policy_authority_head",
        &head,
        &head.payload.signing_input().expect("signing input"),
    );
}

#[test]
fn every_domain_is_published_with_its_vector() {
    let document = load();
    for (id, domain) in [
        ("membership_lease", MEMBERSHIP_LEASE_DOMAIN),
        ("membership_lease_narrowed", MEMBERSHIP_LEASE_DOMAIN),
        ("policy_authority_first_revision", POLICY_AUTHORITY_DOMAIN),
        ("policy_authority_rotation", POLICY_AUTHORITY_DOMAIN),
        ("policy_authority_head", POLICY_AUTHORITY_HEAD_DOMAIN),
    ] {
        assert_eq!(case(&document, id)["domain"], domain, "{id}: domain");
    }
}

#[test]
fn a_domain_separates_one_statement_from_another() {
    // The head and a lease share their organisation, revision and times. Only the domain and the
    // field set differ, which is what stops one signature being read as the other.
    let lease = owner_lease().payload.signing_input().expect("lease");
    let head = head().payload.signing_input().expect("head");
    assert_ne!(lease, head);
    assert!(lease.starts_with(&[0x82]), "an array of two elements");
    assert!(head.starts_with(&[0x82]), "an array of two elements");
}

#[test]
fn a_lease_states_a_ceiling_inside_its_role() {
    let lease = owner_lease();
    assert!(lease.payload.grants_within_role());
    assert!(lease.payload.lifetime_within_maximum());
    assert!(narrowed_lease().payload.grants_within_role());

    let mut widened = narrowed_lease();
    widened.payload.maximum_grants = TeamRole::Owner.maximum_grants();
    assert!(
        !widened.payload.grants_within_role(),
        "a reviewer cannot carry an owner's ceiling"
    );

    let mut long = owner_lease();
    long.payload.expires_at_ms =
        TimestampMs::new(long.payload.issued_at_ms.get() + MEMBERSHIP_LEASE_MAX_LIFETIME_MS + 1);
    assert!(!long.payload.lifetime_within_maximum());
}

#[test]
fn a_lease_is_usable_only_inside_its_window() {
    let lease = owner_lease();
    let issued = lease.payload.issued_at_ms.get();
    let expires = lease.payload.expires_at_ms.get();
    assert!(!lease.payload.is_valid_at(issued - 1));
    assert!(lease.payload.is_valid_at(issued));
    assert!(lease.payload.is_valid_at(expires - 1));
    assert!(!lease.payload.is_valid_at(expires));
}

#[test]
fn a_published_chain_is_checked_before_any_signature() {
    let authority = published_authority();
    assert_eq!(authority.check_structure(), Ok(()));
    assert_eq!(authority.current_revision(), PolicyKeyRevision::new(2));
    assert_eq!(
        authority.link(PolicyKeyRevision::new(1)),
        Some(&first_link())
    );

    let mut empty = published_authority();
    empty.chain.clear();
    assert_eq!(empty.check_structure(), Err(ChainError::Empty));

    let mut reparented = published_authority();
    reparented.chain[1].payload.previous_key_revision = Nullable::some(PolicyKeyRevision::new(2));
    assert_eq!(
        reparented.check_structure(),
        Err(ChainError::BrokenSuccession { index: 1 })
    );

    let mut self_signed_successor = published_authority();
    self_signed_successor.chain[1].payload.previous_key_revision = Nullable::null();
    assert_eq!(
        self_signed_successor.check_structure(),
        Err(ChainError::BrokenSuccession { index: 1 })
    );

    let mut gap = published_authority();
    gap.chain[1].payload.key_revision = PolicyKeyRevision::new(3);
    assert_eq!(
        gap.check_structure(),
        Err(ChainError::UnorderedRevisions { index: 1 })
    );

    let mut backdated = published_authority();
    backdated.chain[1].payload.not_before_ms = TimestampMs::new(1);
    assert_eq!(
        backdated.check_structure(),
        Err(ChainError::UnorderedActivation { index: 1 })
    );

    let mut truncated = published_authority();
    truncated.chain.pop();
    assert_eq!(
        truncated.check_structure(),
        Err(ChainError::HeadRevisionMismatch)
    );

    let mut foreign = published_authority();
    foreign.chain[1].payload.organisation_id =
        OrganisationId::new(uuid("00000000-0000-4000-8000-000000000000"));
    assert_eq!(
        foreign.check_structure(),
        Err(ChainError::ForeignOrganisation { index: 1 })
    );

    let mut foreign_head = published_authority();
    foreign_head.head.payload.organisation_id =
        OrganisationId::new(uuid("00000000-0000-4000-8000-000000000000"));
    assert_eq!(
        foreign_head.check_structure(),
        Err(ChainError::HeadForeignOrganisation)
    );

    let mut early_head = published_authority();
    early_head.head.payload.issued_at_ms =
        TimestampMs::new(early_head.chain[1].payload.not_before_ms.get() - 1);
    assert_eq!(
        early_head.check_structure(),
        Err(ChainError::HeadBeforeActivation),
        "a head cannot say a revision signs now before that revision took over"
    );

    let mut exactly_at_activation = published_authority();
    let activation = exactly_at_activation.chain[1].payload.not_before_ms.get();
    exactly_at_activation.head.payload.issued_at_ms = TimestampMs::new(activation);
    exactly_at_activation.head.payload.expires_at_ms =
        TimestampMs::new(activation + 15 * 60 * 1000);
    assert_eq!(
        exactly_at_activation.check_structure(),
        Ok(()),
        "a head issued at the moment of activation is admissible"
    );

    let mut long_head = published_authority();
    long_head.head.payload.expires_at_ms =
        TimestampMs::new(long_head.head.payload.issued_at_ms.get() + 16 * 60 * 1000);
    assert_eq!(long_head.check_structure(), Err(ChainError::HeadLifetime));

    let mut premature = published_authority();
    premature.chain[0].payload.previous_key_revision = Nullable::some(PolicyKeyRevision::new(0));
    assert_eq!(
        premature.check_structure(),
        Err(ChainError::FirstLinkHasPredecessor)
    );
}

#[test]
fn a_chain_authenticates_forward_from_the_revision_a_host_pinned() {
    let authority = published_authority();

    // A host that pinned the first revision reaches both: the pin, and the
    // revision the pin's key signed the link for.
    let from_first = authority
        .authenticated_from(PolicyKeyRevision::new(1))
        .expect("the chain carries revision 1");
    assert_eq!(from_first.len(), 2);

    // A host that pinned the second reaches the second and anything after it,
    // and not the first: nothing it has authenticates a revision from before its
    // pin, so a lease signed by that revision is refused rather than checked
    // against a key it has no reason to trust.
    let from_second = authority
        .authenticated_from(PolicyKeyRevision::new(2))
        .expect("the chain carries revision 2");
    assert_eq!(from_second.len(), 1);
    assert_eq!(from_second[0], rotation_link());
    assert!(
        !from_second
            .iter()
            .any(|link| link.payload.key_revision == PolicyKeyRevision::new(1))
    );

    assert!(
        authority
            .authenticated_from(PolicyKeyRevision::new(3))
            .is_none()
    );
}

#[test]
fn a_closed_schema_refuses_a_field_nobody_agreed_on() {
    let mut json = serde_json::to_value(owner_lease()).expect("serialise");
    json["payload"]["scope"] = Json::String("everything".to_owned());
    let parsed: Result<MembershipLease, _> = serde_json::from_value(json);
    assert!(parsed.is_err(), "an unknown field is refused");

    let mut unsorted = serde_json::to_value(owner_lease()).expect("serialise");
    unsorted["payload"]["maximum_grants"] = Json::Array(vec![
        Json::String("session.view".to_owned()),
        Json::String("files.read".to_owned()),
    ]);
    let parsed: Result<MembershipLease, _> = serde_json::from_value(unsorted);
    assert!(
        parsed.is_err(),
        "a ceiling that arrived out of order is refused rather than sorted, because a verifier \
         checks the bytes it received"
    );

    let mut unknown_grant = serde_json::to_value(owner_lease()).expect("serialise");
    unknown_grant["payload"]["maximum_grants"] =
        Json::Array(vec![Json::String("everything".to_owned())]);
    let parsed: Result<MembershipLease, _> = serde_json::from_value(unknown_grant);
    assert!(parsed.is_err(), "a right outside the vocabulary is refused");
}
