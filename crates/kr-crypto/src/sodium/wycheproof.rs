//! Wycheproof's vectors for X25519, Ed25519 and XChaCha20-Poly1305, run through this boundary.
//!
//! The three `*_test.json` files under `fixtures/crypto/wycheproof/` are Wycheproof's own, unchanged:
//! the `testvectors_v1` files of github.com/C2SP/wycheproof at the commit named below, under the
//! Apache License 2.0 (the `LICENSE` file beside them). Each one is checked against the SHA-256
//! printed here before it is read, so a file that was edited or replaced is refused.
//! `ed25519-verdicts.json` is this repository's own record of libsodium's verdict on each Ed25519
//! case.

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::known_answers::{hex_vec, read_json};
use super::*;

/// The upstream commit the three files come from.
const UPSTREAM_COMMIT: &str = "65ca494727a52944c204441c860b039e6786b99b";

const X25519_SHA256: &str = "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d";
const ED25519_SHA256: &str = "ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3";
const XCHACHA20_POLY1305_SHA256: &str =
    "a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9";
/// The Apache License 2.0 text the project publishes beside its vectors.
const LICENSE_SHA256: &str = "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd";

/// The licence text the set travels with, as the program holds it.
const LICENSE: &[u8] = include_bytes!("../../../../fixtures/crypto/wycheproof/LICENSE");

/// The file `name` of the vendored set, as the program holds it.
fn vendored(name: &str) -> &'static [u8] {
    match name {
        "x25519_test.json" => {
            include_bytes!("../../../../fixtures/crypto/wycheproof/x25519_test.json")
        }
        "ed25519_test.json" => {
            include_bytes!("../../../../fixtures/crypto/wycheproof/ed25519_test.json")
        }
        "xchacha20_poly1305_test.json" => {
            include_bytes!("../../../../fixtures/crypto/wycheproof/xchacha20_poly1305_test.json")
        }
        other => panic!("{other} is not a file of the vendored set"),
    }
}

/// The file `name` of the vendored set, after its digest has been checked against `sha256`, and
/// after the licence that travels with the set has been checked to be there, whole.
fn wycheproof(name: &str, sha256: &str) -> Value {
    assert_eq!(
        hex::encode(Sha256::digest(LICENSE)),
        LICENSE_SHA256,
        "the licence beside the vectors is not the one the upstream project publishes"
    );
    let bytes = vendored(name);
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        sha256,
        "{name} is not the file that {UPSTREAM_COMMIT} holds"
    );
    let file: Value = serde_json::from_slice(bytes).expect("a JSON file");
    let counted: usize = file["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|group| group["tests"].as_array().expect("tests").len())
        .sum();
    assert_eq!(
        file["numberOfTests"].as_u64(),
        u64::try_from(counted).ok(),
        "{name} holds the number of cases it says"
    );
    file
}

/// Every case of the file, with the group it belongs to.
fn cases(file: &Value) -> Vec<(&Value, &Value)> {
    file["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .flat_map(|group| {
            group["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(move |test| (group, test))
        })
        .collect()
}

fn tc_id(test: &Value) -> u64 {
    test["tcId"].as_u64().expect("a case number")
}

fn set_result(test: &Value) -> &str {
    test["result"].as_str().expect("a result")
}

/// KR-REQ-20.01: X25519 behind this boundary agrees with every one of Wycheproof's 518 cases:
/// the shared secret the set prints for each, including the cases the set marks acceptable
/// (non-canonical encodings of the peer's point, points on the twist, scalars at the edges of the
/// clamped range). The 31 cases whose shared secret is all zero, which are the points of small
/// order, are refused: libsodium returns an error for them and this boundary does not hand the
/// caller an all-zero secret.
#[test]
fn x25519_agrees_with_every_wycheproof_case() {
    let file = wycheproof("x25519_test.json", X25519_SHA256);
    let mut agreed = 0;
    let mut refused = 0;
    for (_, test) in cases(&file) {
        let tc = tc_id(test);
        let scalar: [u8; AGREEMENT_SCALAR_LEN] = hex_vec(test, "private")
            .try_into()
            .expect("a 32-byte scalar");
        let point: [u8; AGREEMENT_LEN] =
            hex_vec(test, "public").try_into().expect("a 32-byte point");
        let shared = hex_vec(test, "shared");
        let outcome = scalarmult(&scalar, &point);
        if shared.iter().all(|byte| *byte == 0) {
            assert!(
                matches!(
                    outcome,
                    Err(CryptoError::Library {
                        name: "crypto_scalarmult",
                        ..
                    })
                ),
                "case {tc} has an all-zero shared secret and was not refused"
            );
            refused += 1;
        } else {
            assert_eq!(
                outcome.expect("an agreement").as_slice(),
                shared.as_slice(),
                "case {tc}"
            );
            agreed += 1;
        }
    }
    assert_eq!((agreed, refused), (487, 31));
}

/// The case numbers of Ed25519 cases that the interface cannot express: each one's signature is not
/// 64 bytes long, and the interface takes a 64-byte signature. The set calls every one of them
/// invalid. They are the truncated signatures, the signatures with bytes added, and the empty one.
const ED25519_NOT_EXPRESSIBLE: [u64; 12] = [30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41];

/// KR-REQ-20.01: Ed25519 verification behind this boundary gives, for every case of Wycheproof's
/// 210 that its interface can express, the verdict that `ed25519-verdicts.json` recorded from
/// libsodium's 1.0.22 release build. The set's own words bind it where the set takes a side:
/// every case it calls valid is accepted and every case it calls invalid is refused. Only the 29
/// it calls acceptable depend on the recorded verdicts, and those are libsodium's policy on points
/// of small order (refused) and of mixed order (accepted).
#[test]
fn ed25519_verification_gives_the_recorded_verdict_for_every_wycheproof_case() {
    let file = wycheproof("ed25519_test.json", ED25519_SHA256);
    let recorded = read_json("wycheproof/ed25519-verdicts.json");
    assert_eq!(recorded["upstream"]["commit"], UPSTREAM_COMMIT);
    assert_eq!(recorded["upstream"]["sha256"], ED25519_SHA256);
    let ids = |key: &str| -> Vec<u64> {
        recorded[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} is an array"))
            .iter()
            .map(|id| id.as_u64().expect("a case number"))
            .collect()
    };
    let (accepted, rejected) = (ids("accepted_tc_ids"), ids("rejected_tc_ids"));
    let not_expressible: Vec<u64> = recorded["not_expressible"]
        .as_array()
        .expect("the list of cases the interface cannot express")
        .iter()
        .map(|entry| entry["tc_id"].as_u64().expect("a case number"))
        .collect();
    assert_eq!(not_expressible, ED25519_NOT_EXPRESSIBLE);

    let mut seen = Vec::new();
    let mut by_result = std::collections::BTreeMap::<(String, &str), usize>::new();
    for (group, test) in cases(&file) {
        let tc = tc_id(test);
        let result = set_result(test);
        let signature = hex_vec(test, "sig");
        let Ok(signature) = <[u8; SIGN_LEN]>::try_from(signature.as_slice()) else {
            assert!(
                ED25519_NOT_EXPRESSIBLE.contains(&tc),
                "case {tc} cannot be expressed and is not listed"
            );
            assert_eq!(result, "invalid", "case {tc}");
            continue;
        };
        assert!(
            !ED25519_NOT_EXPRESSIBLE.contains(&tc),
            "case {tc} can be expressed and is listed as one that cannot"
        );
        let public: [u8; SIGN_PUBLIC_KEY_LEN] = hex_vec(&group["publicKey"], "pk")
            .try_into()
            .expect("a 32-byte public key");
        let accepts = sign_verify_detached(&signature, &hex_vec(test, "msg"), &public).is_ok();
        match result {
            "valid" => assert!(accepts, "case {tc} is valid and was refused"),
            "invalid" => assert!(!accepts, "case {tc} is invalid and was accepted"),
            _ => {}
        }
        assert_eq!(
            accepts,
            accepted.contains(&tc),
            "case {tc}: the verdict is not the recorded one"
        );
        assert_eq!(
            !accepts,
            rejected.contains(&tc),
            "case {tc}: the verdict is not the recorded one"
        );
        *by_result
            .entry((result.to_owned(), if accepts { "accept" } else { "reject" }))
            .or_default() += 1;
        seen.push(tc);
    }
    assert_eq!(seen.len() + not_expressible.len(), 210);
    assert_eq!(seen.len(), accepted.len() + rejected.len());
    assert_eq!(
        by_result.into_iter().collect::<Vec<_>>(),
        [
            (("acceptable".to_owned(), "accept"), 21),
            (("acceptable".to_owned(), "reject"), 8),
            (("invalid".to_owned(), "reject"), 52),
            (("valid".to_owned(), "accept"), 117),
        ]
    );
}

/// The case numbers of XChaCha20-Poly1305 cases that the interface cannot express: each one's nonce
/// is not 24 bytes long, and the interface takes a 24-byte nonce. The set calls every one invalid.
const XCHACHA20_POLY1305_NOT_EXPRESSIBLE: [u64; 9] = [307, 308, 309, 310, 311, 312, 313, 314, 315];

/// KR-REQ-20.01: XChaCha20-Poly1305 behind this boundary agrees with every case of Wycheproof's
/// 315 that its interface can express, which is every case whose nonce is 24 bytes: the 246 the
/// set calls valid seal to the set's ciphertext and tag and open to its message, and the 60 it
/// calls invalid (changed tags) are refused.
#[test]
fn xchacha20_poly1305_agrees_with_every_wycheproof_case() {
    let file = wycheproof("xchacha20_poly1305_test.json", XCHACHA20_POLY1305_SHA256);
    let (mut valid, mut invalid) = (0, 0);
    let mut not_expressible = Vec::new();
    for (_, test) in cases(&file) {
        let tc = tc_id(test);
        let result = set_result(test);
        let nonce = hex_vec(test, "iv");
        let Ok(nonce) = <[u8; AEAD_NONCE_LEN]>::try_from(nonce.as_slice()) else {
            assert_eq!(result, "invalid", "case {tc}");
            not_expressible.push(tc);
            continue;
        };
        let key: [u8; AEAD_KEY_LEN] = hex_vec(test, "key").try_into().expect("a 32-byte key");
        let aad = hex_vec(test, "aad");
        let message = hex_vec(test, "msg");
        let mut sealed = hex_vec(test, "ct");
        sealed.extend(hex_vec(test, "tag"));
        let opened = aead_decrypt(&sealed, &aad, &nonce, &key);
        match result {
            "valid" => {
                assert_eq!(opened.ok().as_ref(), Some(&message), "case {tc}");
                assert_eq!(
                    aead_encrypt(&message, &aad, &nonce, &key).expect("seals"),
                    sealed,
                    "case {tc}"
                );
                valid += 1;
            }
            "invalid" => {
                assert!(opened.is_err(), "case {tc} is invalid and was accepted");
                invalid += 1;
            }
            other => panic!("case {tc}: the set gives {other}, which no case does"),
        }
    }
    assert_eq!(not_expressible, XCHACHA20_POLY1305_NOT_EXPRESSIBLE);
    assert_eq!((valid, invalid), (246, 60));
}
