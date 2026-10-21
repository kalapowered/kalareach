//! A release manifest is accepted only when a threshold of distinct keys the root names signed it.
//!
//! The roots and keys here are made in the test, and the manifests are signed by the library's own
//! signer, so what verifies is what the tool writes.

use std::collections::HashMap;
use std::num::NonZeroU64;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
};
use kr_protocol::update::SignedMembers;
use kr_release::{VerifyError, check_root_keys, sign_manifest, verify_manifest, verify_root_by};
use tough::schema::key::Key;
use tough::schema::{RoleKeys, RoleType, Root, Signature, Signed};
use tough::sign::Sign;

fn pair() -> Ed25519KeyPair {
    let random = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("a key");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key pair")
}

/// A root whose targets role is `named` with `threshold`, its other roles naming `named[0]` alone.
fn root_with(named: &[Key], threshold: u64) -> Root {
    let identifiers: Vec<_> = named
        .iter()
        .map(|key| key.key_id().expect("a key identifier"))
        .collect();
    let mut keys = HashMap::new();
    for (identifier, key) in identifiers.iter().zip(named) {
        keys.insert(identifier.clone(), key.clone());
    }
    let role = |ids: Vec<_>, threshold: u64| RoleKeys {
        keyids: ids,
        threshold: NonZeroU64::new(threshold).expect("a threshold"),
        _extra: HashMap::new(),
    };
    let mut roles = HashMap::new();
    roles.insert(RoleType::Root, role(vec![identifiers[0].clone()], 1));
    roles.insert(RoleType::Targets, role(identifiers.clone(), threshold));
    roles.insert(RoleType::Snapshot, role(vec![identifiers[0].clone()], 1));
    roles.insert(RoleType::Timestamp, role(vec![identifiers[0].clone()], 1));
    Root {
        spec_version: "1.0.0".to_owned(),
        consistent_snapshot: false,
        version: NonZeroU64::MIN,
        expires: "2099-01-01T00:00:00Z".parse().expect("a time"),
        keys,
        roles,
        _extra: HashMap::new(),
    }
}

fn members(kind: &str) -> SignedMembers {
    serde_json::from_value(serde_json::json!({
        "_type": kind,
        "release": "0.1.0+4254aa6e62e5",
        "sequence": "1",
    }))
    .expect("members")
}

fn signed_by(members: &SignedMembers, signers: &[&Ed25519KeyPair]) -> String {
    let signers: Vec<&dyn Sign> = signers.iter().map(|pair| *pair as &dyn Sign).collect();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(sign_manifest(members, &signers))
        .expect("signed")
}

fn tuf_key(pair: &Ed25519KeyPair) -> Key {
    Sign::tuf_key(pair)
}

/// KR-REQ-26.41: a two-key threshold is met by two distinct keys and not by one.
#[test]
fn a_threshold_of_two_is_met_by_two_keys_and_not_by_one() {
    let (first, second) = (pair(), pair());
    let root = root_with(&[tuf_key(&first), tuf_key(&second)], 2);
    let written = members("kalareach-release");

    let both = signed_by(&written, &[&first, &second]);
    let verified = verify_manifest(&root, both.as_bytes()).expect("two keys of two sign it");
    assert_eq!(verified, written);

    let alone = signed_by(&written, &[&first]);
    assert!(matches!(
        verify_manifest(&root, alone.as_bytes()),
        Err(VerifyError::Threshold)
    ));
}

/// One key described again in each way that changes its name and not the key: a member added to
/// the description, a member added to the value, and the public value spelled in capitals.
fn described_again(key: &Key) -> Vec<(&'static str, Key)> {
    let mut outer = key.clone();
    if let Key::Ed25519 { _extra, .. } = &mut outer {
        _extra.insert("note".to_owned(), serde_json::json!("again"));
    }
    let altered = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut value = serde_json::to_value(key).expect("a description");
        change(&mut value);
        serde_json::from_value::<Key>(value).expect("a key")
    };
    vec![
        ("a member of the description", outer),
        (
            "a member of the value",
            altered(&|value| value["keyval"]["note"] = serde_json::json!("again")),
        ),
        (
            "the public value in capitals",
            altered(&|value| {
                let public = value["keyval"]["public"]
                    .as_str()
                    .expect("hexadecimal")
                    .to_uppercase();
                value["keyval"]["public"] = serde_json::json!(public);
            }),
        ),
    ]
}

/// KR-REQ-26.41: one key the root describes twice is one key, however the second description
/// differs. Each way gives it another identifier and the same key; with a threshold of two, one
/// private key would sign for both. The root is refused before a signature is counted.
#[test]
fn one_key_described_twice_does_not_meet_a_threshold_of_two() {
    let only = pair();
    let plain = tuf_key(&only);
    for (how, again) in described_again(&plain) {
        let root = root_with(&[plain.clone(), again.clone()], 2);
        assert_ne!(
            plain.key_id().expect("an identifier"),
            again.key_id().expect("an identifier"),
            "the two descriptions have two names: {how}"
        );

        let written = members("kalareach-release");
        let canonical = {
            use tough::schema::Role;
            Role::canonical_form(&kr_release::Signable(written.clone())).expect("canonical")
        };
        let signature = |key: &Key| Signature {
            keyid: key.key_id().expect("an identifier"),
            sig: only.sign(&canonical).as_ref().to_vec().into(),
        };
        let document = serde_json::json!({
            "signed": written,
            "signatures": [signature(&plain), signature(&again)],
        })
        .to_string();

        assert!(
            matches!(
                verify_manifest(&root, document.as_bytes()),
                Err(VerifyError::ReusedKey { role: "targets" })
            ),
            "{how}"
        );
        assert!(
            matches!(
                check_root_keys(&root),
                Err(VerifyError::ReusedKey { role: "targets" })
            ),
            "{how}"
        );

        // The same two descriptions cannot sign a successor root for a trusted root that names them.
        let next = Signed {
            signed: root_with(&[tuf_key(&pair())], 1),
            signatures: vec![signature(&plain), signature(&again)],
        };
        assert!(
            matches!(
                verify_root_by(&root, &next),
                Err(VerifyError::ReusedKey { .. })
            ),
            "{how}"
        );
    }
}

/// A key as the root's key table writes it, with the public value spelled in hexadecimal.
fn described(kind: &str, scheme: &str, public: &[u8]) -> Key {
    let hex: String = public.iter().map(|byte| format!("{byte:02x}")).collect();
    serde_json::from_value(serde_json::json!({
        "keytype": kind,
        "keyval": { "public": hex },
        "scheme": scheme,
    }))
    .expect("a key")
}

/// KR-REQ-26.41: the library that checks a signature reads one key in more than one encoding: an
/// Ed25519 key as its 32 raw bytes or wrapped in its 44-byte `SubjectPublicKeyInfo`, and an
/// elliptic-curve key as a compressed or an uncompressed point. A root that names one key under two
/// of them has two names for one private key, and a threshold of two would count that key twice. A
/// release key is an Ed25519 key of 32 bytes and nothing else, so no key has two spellings: the
/// root is refused before a signature is counted.
#[test]
fn a_key_that_is_not_an_ed25519_key_of_32_bytes_is_refused() {
    let only = pair();
    let plain = tuf_key(&only);
    let raw = only.public_key().as_ref().to_vec();
    assert_eq!(raw.len(), 32);

    // The same Ed25519 key in its 44-byte wrapper: one private key signs under both names.
    let spki_prefix = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let wrapped = described(
        "ed25519",
        "ed25519",
        &[spki_prefix.as_slice(), &raw].concat(),
    );
    let root = root_with(&[plain.clone(), wrapped.clone()], 2);
    let written = members("kalareach-release");
    let canonical = {
        use tough::schema::Role;
        Role::canonical_form(&kr_release::Signable(written.clone())).expect("canonical")
    };
    let signature = |key: &Key| Signature {
        keyid: key.key_id().expect("an identifier"),
        sig: only.sign(&canonical).as_ref().to_vec().into(),
    };
    let document = serde_json::json!({
        "signed": written,
        "signatures": [signature(&plain), signature(&wrapped)],
    })
    .to_string();
    let verdict = verify_manifest(&root, document.as_bytes()).map(|_| "accepted");
    assert!(
        matches!(
            verdict,
            Err(VerifyError::UnsupportedKey { role: "targets" })
        ),
        "an Ed25519 key in a wrapper: {verdict:?}"
    );

    // One elliptic-curve key as an uncompressed point and as a compressed one.
    let random = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
        .expect("an elliptic-curve key");
    let curve = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .expect("a key pair");
    let point = curve.public_key().as_ref().to_vec();
    assert_eq!(point.len(), 65);
    let mut compressed = vec![if point[64] & 1 == 0 { 0x02 } else { 0x03 }];
    compressed.extend_from_slice(&point[1..33]);
    let root = root_with(
        &[
            described("ecdsa", "ecdsa-sha2-nistp256", &point),
            described("ecdsa", "ecdsa-sha2-nistp256", &compressed),
        ],
        2,
    );
    let verdict = check_root_keys(&root);
    assert!(
        matches!(verdict, Err(VerifyError::UnsupportedKey { .. })),
        "an elliptic-curve key as two points: {verdict:?}"
    );
}

/// KR-REQ-26.12: metadata signed by an authorised key that is not a release's manifest is not
/// taken for one, and a release's signature does not cover a document changed to another kind.
#[test]
fn a_signature_over_other_metadata_is_not_a_release_s() {
    let signer = pair();
    let root = root_with(&[tuf_key(&signer)], 1);

    // The catalogue's targets metadata, signed by the authorised key: the signature verifies for
    // what it covers, and what it covers is not a release.
    let catalogue = members("targets");
    let document = signed_by(&catalogue, &[&signer]);
    let taken = verify_manifest(&root, document.as_bytes()).expect("the signature is the key's");
    assert!(
        taken.manifest().is_err(),
        "metadata of another kind is not a release's manifest"
    );

    // A release's signature moved onto a document of another kind covers other bytes.
    let release = signed_by(&members("kalareach-release"), &[&signer]);
    let mut moved: serde_json::Value = serde_json::from_str(&release).expect("JSON");
    moved["signed"]["_type"] = serde_json::json!("targets");
    assert!(matches!(
        verify_manifest(&root, moved.to_string().as_bytes()),
        Err(VerifyError::Threshold)
    ));
}
