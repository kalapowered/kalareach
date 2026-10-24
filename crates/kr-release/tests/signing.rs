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
use kr_release::{
    VerifyError, check_root_keys, sign_manifest, verify_manifest, verify_root_by,
    verify_root_itself,
};
use tough::schema::key::Key;
use tough::schema::{RoleKeys, RoleType, Root, Signature, Signed};
use tough::sign::Sign;

fn pair() -> Ed25519KeyPair {
    let random = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("a key");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key pair")
}

/// A root with the keys `named` for each role, each role's threshold being the one it is given.
fn root_of(named: &[(RoleType, Vec<Key>, u64)]) -> Root {
    let mut keys = HashMap::new();
    let mut roles = HashMap::new();
    for (role, role_keys, threshold) in named {
        let mut identifiers = Vec::new();
        for key in role_keys {
            let identifier = key.key_id().expect("a key identifier");
            keys.insert(identifier.clone(), key.clone());
            identifiers.push(identifier);
        }
        roles.insert(
            *role,
            RoleKeys {
                keyids: identifiers,
                threshold: NonZeroU64::new(*threshold).expect("a threshold"),
                _extra: HashMap::new(),
            },
        );
    }
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

/// A root whose targets role is `named` with `threshold`, its other roles each naming a key of
/// their own.
fn root_with(named: &[Key], threshold: u64) -> Root {
    root_of(&[
        (RoleType::Root, vec![tuf_key(&pair())], 1),
        (RoleType::Targets, named.to_vec(), threshold),
        (RoleType::Snapshot, vec![tuf_key(&pair())], 1),
        (RoleType::Timestamp, vec![tuf_key(&pair())], 1),
    ])
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

/// A two-key threshold is met by two distinct keys and not by one.
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

/// One key the root describes twice is one key, however the second description
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

/// The library that checks a signature reads one key in more than one encoding: an
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

const ROLES: [RoleType; 4] = [
    RoleType::Root,
    RoleType::Targets,
    RoleType::Snapshot,
    RoleType::Timestamp,
];

fn name_of(role: RoleType) -> &'static str {
    match role {
        RoleType::Root => "root",
        RoleType::Targets => "targets",
        RoleType::Snapshot => "snapshot",
        RoleType::Timestamp => "timestamp",
        RoleType::DelegatedTargets => "delegated targets",
    }
}

/// `root`, signed by `signer`.
fn signed_root(root: Root, signer: &Ed25519KeyPair) -> Signed<Root> {
    use tough::schema::Role;

    let canonical = Role::canonical_form(&root).expect("canonical");
    Signed {
        signatures: vec![Signature {
            keyid: tuf_key(signer).key_id().expect("an identifier"),
            sig: signer.sign(&canonical).as_ref().to_vec().into(),
        }],
        signed: root,
    }
}

/// KR-REQ-26.40: the keys of the roles are distinct. A root that names one key for two of its
/// roles is refused wherever a root is read, whichever two roles share it, and a root that gives
/// each role a key of its own is the control.
#[test]
fn a_key_that_two_roles_share_is_refused_wherever_a_root_is_read() {
    let written = members("kalareach-release");
    let checked = |roles: [Ed25519KeyPair; 4], shared: Option<(RoleType, RoleType)>| {
        // The key each role names: its own, but for the second of a shared pair, which names the
        // first's.
        let index = |role: RoleType| ROLES.iter().position(|r| *r == role).expect("a role");
        let key_of = |role: RoleType| match shared {
            Some((first, second)) if role == second => &roles[index(first)],
            _ => &roles[index(role)],
        };
        let root = root_of(
            &ROLES
                .iter()
                .map(|role| (*role, vec![tuf_key(key_of(*role))], 1))
                .collect::<Vec<_>>(),
        );
        let root_signer = key_of(RoleType::Root);
        let targets_signer = key_of(RoleType::Targets);
        let manifest = signed_by(&written, &[targets_signer]);
        let own = signed_root(root.clone(), root_signer);
        // A trusted root of four distinct keys, and the root under test as the successor it signs.
        let trusted_signer = pair();
        let trusted = root_of(&[
            (RoleType::Root, vec![tuf_key(&trusted_signer)], 1),
            (RoleType::Targets, vec![tuf_key(&pair())], 1),
            (RoleType::Snapshot, vec![tuf_key(&pair())], 1),
            (RoleType::Timestamp, vec![tuf_key(&pair())], 1),
        ]);
        let successor = signed_root(root.clone(), &trusted_signer);
        // The root under test as the trusted root, over a successor of four distinct keys that the
        // root key it names signs: only the trusted side can be what is refused.
        let clean = signed_root(
            root_of(&[
                (RoleType::Root, vec![tuf_key(&pair())], 1),
                (RoleType::Targets, vec![tuf_key(&pair())], 1),
                (RoleType::Snapshot, vec![tuf_key(&pair())], 1),
                (RoleType::Timestamp, vec![tuf_key(&pair())], 1),
            ]),
            root_signer,
        );
        (
            check_root_keys(&root),
            verify_manifest(&root, manifest.as_bytes()).map(|_| ()),
            verify_root_itself(&own),
            verify_root_by(&root, &clean),
            verify_root_by(&trusted, &successor),
        )
    };
    let four = || [pair(), pair(), pair(), pair()];

    let control = checked(four(), None);
    assert!(control.0.is_ok(), "four keys: {:?}", control.0);
    assert!(control.1.is_ok(), "four keys: {:?}", control.1);
    assert!(control.2.is_ok(), "four keys: {:?}", control.2);
    assert!(control.3.is_ok(), "four keys: {:?}", control.3);
    assert!(control.4.is_ok(), "four keys: {:?}", control.4);

    for (at, first) in ROLES.iter().enumerate() {
        for second in &ROLES[at + 1..] {
            let mut names = [name_of(*first), name_of(*second)];
            names.sort_unstable();
            let verdicts = checked(four(), Some((*first, *second)));
            for (call, verdict) in [
                ("check_root_keys", verdicts.0),
                ("verify_manifest", verdicts.1),
                ("verify_root_itself", verdicts.2),
                ("verify_root_by, trusted", verdicts.3),
                ("verify_root_by, next", verdicts.4),
            ] {
                assert!(
                    matches!(
                        verdict,
                        Err(VerifyError::SharedKey { first, second })
                            if [first, second] == names
                    ),
                    "{call} for {names:?}: {verdict:?}"
                );
            }
        }
    }
}

/// KR-REQ-26.40: the root `kr-release dev-keys` writes gives each role a key of its own, every key
/// it names is a file in the keys directory, the keys the targets role names sign a release that
/// the root verifies, and a host takes the root.
#[test]
fn the_development_root_gives_each_role_a_key_of_its_own() {
    let directory = tempfile::tempdir().expect("a directory");
    let keys = directory.path().join("keys");
    kr_release::dev::write_keys(&keys, 2).expect("the keys are made");

    let signed: Signed<Root> =
        serde_json::from_slice(&std::fs::read(keys.join("root.json")).expect("a root"))
            .expect("root metadata");
    verify_root_itself(&signed).expect("the root passes the checks a host makes");

    let identifier_of = |name: &str| {
        let bytes =
            std::fs::read(keys.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let pair = Ed25519KeyPair::from_pkcs8(&bytes).expect("a key pair");
        tuf_key(&pair).key_id().expect("an identifier")
    };
    let named = |role: RoleType| signed.signed.roles[&role].keyids.clone();
    assert_eq!(named(RoleType::Root), [identifier_of("root-key.pk8")]);
    assert_eq!(
        named(RoleType::Snapshot),
        [identifier_of("snapshot-key.pk8")]
    );
    assert_eq!(
        named(RoleType::Timestamp),
        [identifier_of("timestamp-key.pk8")]
    );
    let mut targets = named(RoleType::Targets);
    targets.sort_by(|left, right| left[..].cmp(&right[..]));
    let mut files = vec![
        identifier_of("targets-1.pk8"),
        identifier_of("targets-2.pk8"),
    ];
    files.sort_by(|left, right| left[..].cmp(&right[..]));
    assert_eq!(targets, files);
    let mut every: Vec<_> = signed
        .signed
        .roles
        .values()
        .flat_map(|role| role.keyids.iter().map(|id| id[..].to_vec()))
        .collect();
    every.sort();
    every.dedup();
    assert_eq!(every.len(), 5, "five keys for four roles with two signers");
    assert_eq!(signed.signed.keys.len(), 5);

    let pair_of = |name: &str| {
        Ed25519KeyPair::from_pkcs8(&std::fs::read(keys.join(name)).expect("a key"))
            .expect("a key pair")
    };
    let written = members("kalareach-release");
    let document = signed_by(
        &written,
        &[&pair_of("targets-1.pk8"), &pair_of("targets-2.pk8")],
    );
    assert_eq!(
        verify_manifest(&signed.signed, document.as_bytes()).expect("both targets keys sign it"),
        written
    );
}
