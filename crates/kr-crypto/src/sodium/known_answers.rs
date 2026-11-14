//! Known answers for the cipher and curve code behind this boundary.
//!
//! libsodium picks its ChaCha20 and Salsa20 code by the processor and then by the length of the
//! call. The release's widest loop takes 512 bytes at a time. The stable branch's snapshot also has
//! AVX-512 code, which takes 1,024, and the release tag's Windows archive that the jobs link holds
//! none of it: only an MSVC build that links the snapshot, which is one whose environment names no
//! placed archive directory, reaches it. A test that stops below those lengths never reaches the
//! code a long message uses. A round trip cannot find a wrong keystream either: the
//! same keystream takes off what it put on. The cases here seal fixed inputs at every length that
//! matters and compare the whole sealed output with answers frozen from libsodium's 1.0.22 release
//! build, where a wrong byte anywhere in the keystream or the authenticator changes the answer.
//!
//! The answers are in `fixtures/crypto/cipher-known-answers.json`. They are never made again to
//! make a failure go away: an implementation that disagrees with them is the one that is wrong.
//! The other documents that this module reads are the vectors the RFCs publish
//! (`published-vectors.json`).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

/// The message lengths every cipher family is sealed at. They straddle the 64-byte block, the
/// 256-byte and 512-byte widths of the vector loops, the 1,024-byte call that starts the widest
/// code, and 1,919, which is 1,024 + 512 + 256 + 64 + 63: one call that runs every block loop and
/// then the partial block. The last three lengths are a mebibyte, one byte short of it and one
/// byte over it.
const LENGTHS: [usize; 26] = [
    0, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1_023, 1_024, 1_025, 1_919, 2_047,
    2_048, 2_049, 6_015, 65_536, 1_048_575, 1_048_576, 1_048_577,
];

/// The additional data of the second AEAD variant: odd, so that the authenticator's padding of it
/// is exercised as well.
const AAD_LEN: usize = 37;

/// The `crypto_secretstream` tags beyond the two the wrapper names.
const TAG_PUSH: u8 = 1;
const TAG_REKEY: u8 = 2;

pub(super) fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/crypto")
}

pub(super) fn read_json(relative: &str) -> Value {
    let path = fixtures_dir().join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

pub(super) fn hex_vec(value: &Value, key: &str) -> Vec<u8> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} is a hex string"));
    hex::decode(text).unwrap_or_else(|error| panic!("{key}: {error}"))
}

pub(super) fn hex_array<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    <[u8; N]>::try_from(hex_vec(value, key).as_slice())
        .unwrap_or_else(|_| panic!("{key} is {N} bytes"))
}

/// The fixed stream every plaintext, key, nonce and seed here is cut from. Block `n` is the SHA-256
/// of `label`, a zero byte and `n` as eight big-endian bytes, and the stream is the blocks in
/// order. It never repeats within a case, it holds no pattern that lines up with a cipher's block
/// width, and the `sha2` crate, not libsodium, makes it, so no byte of a plaintext depends on the
/// code under test.
fn rule_bytes(label: &str, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter = 0u64;
    while out.len() < length {
        let mut hash = Sha256::new();
        hash.update(label.as_bytes());
        hash.update([0u8]);
        hash.update(counter.to_be_bytes());
        out.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn rule_array<const N: usize>(label: &str) -> [u8; N] {
    <[u8; N]>::try_from(rule_bytes(label, N)).expect("the rule gives N bytes")
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The frozen array under `key`, in the order the fixture holds it.
fn frozen_cases<'a>(frozen: &'a Value, family: &str) -> &'a [Value] {
    frozen
        .get(family)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the fixture holds an array of {family} cases"))
}

/// Every case the code makes must be the case the fixture holds at the same place, and the fixture
/// must hold no more: a comparison that stops early, skips cases or a fixture that was cut short
/// fails here.
fn assert_cases_equal(family: &str, actual: &[Value], frozen: &[Value]) {
    assert_eq!(
        actual.len(),
        frozen.len(),
        "{family}: the fixture holds a different number of cases than the lengths ask for"
    );
    let mut compared = 0;
    for (made, expected) in actual.iter().zip(frozen) {
        assert_eq!(made, expected, "{family}: the answer for {expected}");
        compared += 1;
    }
    assert_eq!(
        compared,
        frozen.len(),
        "{family}: not every case was compared"
    );
}

/// A bit of `byte`'s to flip at `position`, so that the flips cover every bit of a byte over a
/// message.
fn flipped(mut bytes: Vec<u8>, position: usize) -> Vec<u8> {
    bytes[position] ^= 1 << (position % 8);
    bytes
}

/// The places in a sealed message of `length` bytes that a flip is tried at: the first and last
/// byte of the body, one in the middle, and the first and last byte of the 16-byte authenticator.
fn flip_positions(length: usize) -> Vec<usize> {
    let mut positions = vec![length, length + 15];
    if length > 0 {
        positions.extend([0, length / 2, length - 1]);
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

// ---------------------------------------------------------------------------------------------
// The AEAD.
// ---------------------------------------------------------------------------------------------

struct AeadCase<'a> {
    plaintext: &'a [u8],
    aad: Vec<u8>,
    nonce: [u8; AEAD_NONCE_LEN],
}

fn aead_key() -> [u8; AEAD_KEY_LEN] {
    rule_array("kr-known-answers/aead/key")
}

/// Calls `visit` for every length with empty and with 37 bytes of additional data.
fn each_aead_case(mut visit: impl FnMut(&AeadCase<'_>)) {
    for length in LENGTHS {
        let plaintext = rule_bytes(&format!("kr-known-answers/aead/plaintext/{length}"), length);
        for aad_len in [0, AAD_LEN] {
            visit(&AeadCase {
                plaintext: &plaintext,
                aad: rule_bytes(&format!("kr-known-answers/aead/aad/{aad_len}"), aad_len),
                nonce: rule_array(&format!("kr-known-answers/aead/nonce/{length}/{aad_len}")),
            });
        }
    }
}

fn aead_cases(key: &[u8; AEAD_KEY_LEN]) -> Vec<Value> {
    let mut cases = Vec::new();
    each_aead_case(|case| {
        let sealed = aead_encrypt(case.plaintext, &case.aad, &case.nonce, key).expect("seals");
        cases.push(json!({
            "aad_bytes": case.aad.len(),
            "length": case.plaintext.len(),
            "sealed_sha256_hex": digest_hex(&sealed),
            "tag_hex": hex::encode(&sealed[case.plaintext.len()..]),
        }));
    });
    cases
}

/// KR-REQ-20.01: XChaCha20-Poly1305 seals to the bytes libsodium's 1.0.22 release makes, at every
/// length from empty to a mebibyte, with and without additional data. The comparison is of the
/// whole sealed message by its SHA-256 and of its authenticator, so a wrong keystream byte
/// anywhere, in any block loop, or a wrong authenticator, fails the case. The published vector of
/// the draft that defines the construction follows this one.
#[test]
fn the_aead_seals_to_the_frozen_bytes_at_every_length() {
    let frozen = read_json("cipher-known-answers.json");
    assert_cases_equal(
        "aead",
        &aead_cases(&aead_key()),
        frozen_cases(&frozen, "aead"),
    );
}

/// KR-REQ-20.01: every sealed message opens to its plaintext under the key, nonce and additional
/// data it was sealed under, and fails to open after any one of them, the ciphertext, the
/// authenticator or the message's length changes.
#[test]
fn the_aead_opens_what_it_sealed_and_refuses_every_change() {
    let key = aead_key();
    each_aead_case(|case| {
        let length = case.plaintext.len();
        let sealed = aead_encrypt(case.plaintext, &case.aad, &case.nonce, &key).expect("seals");
        let what = format!(
            "{length} bytes, {} bytes of additional data",
            case.aad.len()
        );
        assert_eq!(
            aead_decrypt(&sealed, &case.aad, &case.nonce, &key).expect("opens"),
            case.plaintext,
            "{what}"
        );

        for position in flip_positions(length) {
            assert!(
                matches!(
                    aead_decrypt(
                        &flipped(sealed.clone(), position),
                        &case.aad,
                        &case.nonce,
                        &key
                    ),
                    Err(CryptoError::Authentication { .. })
                ),
                "{what}: a flip at byte {position} was accepted"
            );
        }
        let mut other_nonce = case.nonce;
        other_nonce[0] ^= 1;
        assert!(
            aead_decrypt(&sealed, &case.aad, &other_nonce, &key).is_err(),
            "{what}: another nonce was accepted"
        );
        other_nonce = case.nonce;
        other_nonce[AEAD_NONCE_LEN - 1] ^= 0x80;
        assert!(
            aead_decrypt(&sealed, &case.aad, &other_nonce, &key).is_err(),
            "{what}: another last nonce byte was accepted"
        );
        let mut other_key = key;
        other_key[AEAD_KEY_LEN - 1] ^= 1;
        assert!(
            aead_decrypt(&sealed, &case.aad, &case.nonce, &other_key).is_err(),
            "{what}: another key was accepted"
        );
        // Additional data that was not sealed in, and additional data with one byte changed or cut.
        let other_aad = if case.aad.is_empty() {
            b"x".to_vec()
        } else {
            flipped(case.aad.clone(), 0)
        };
        assert!(
            aead_decrypt(&sealed, &other_aad, &case.nonce, &key).is_err(),
            "{what}: other additional data was accepted"
        );
        if !case.aad.is_empty() {
            assert!(
                aead_decrypt(&sealed, &[], &case.nonce, &key).is_err(),
                "{what}: dropped additional data was accepted"
            );
            assert!(
                aead_decrypt(&sealed, &case.aad[1..], &case.nonce, &key).is_err(),
                "{what}: shortened additional data was accepted"
            );
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(
            aead_decrypt(&longer, &case.aad, &case.nonce, &key).is_err(),
            "{what}: a longer message was accepted"
        );
        assert!(
            aead_decrypt(&sealed[..sealed.len() - 1], &case.aad, &case.nonce, &key).is_err(),
            "{what}: a shorter message was accepted"
        );
    });
}

// ---------------------------------------------------------------------------------------------
// The box.
// ---------------------------------------------------------------------------------------------

struct BoxKeys {
    sender_public: [u8; BOX_PUBLIC_KEY_LEN],
    sender_secret: [u8; BOX_SECRET_KEY_LEN],
    recipient_public: [u8; BOX_PUBLIC_KEY_LEN],
    recipient_secret: [u8; BOX_SECRET_KEY_LEN],
    other_public: [u8; BOX_PUBLIC_KEY_LEN],
    other_secret: [u8; BOX_SECRET_KEY_LEN],
}

fn box_keys() -> BoxKeys {
    let pair = |name: &str| {
        box_seed_keypair(&rule_array(&format!("kr-known-answers/box/seed/{name}")))
            .expect("a keypair")
    };
    let (sender_public, sender_secret) = pair("sender");
    let (recipient_public, recipient_secret) = pair("recipient");
    let (other_public, other_secret) = pair("other");
    BoxKeys {
        sender_public,
        sender_secret,
        recipient_public,
        recipient_secret,
        other_public,
        other_secret,
    }
}

fn box_nonce(length: usize) -> [u8; BOX_NONCE_LEN] {
    rule_array(&format!("kr-known-answers/box/nonce/{length}"))
}

fn box_plaintext(length: usize) -> Vec<u8> {
    rule_bytes(&format!("kr-known-answers/box/plaintext/{length}"), length)
}

fn box_cases(keys: &BoxKeys) -> Vec<Value> {
    LENGTHS
        .iter()
        .map(|&length| {
            let sealed = box_easy(
                &box_plaintext(length),
                &box_nonce(length),
                &keys.recipient_public,
                &keys.sender_secret,
            )
            .expect("seals");
            json!({
                "length": length,
                "mac_hex": hex::encode(&sealed[..BOX_MAC_LEN]),
                "sealed_sha256_hex": digest_hex(&sealed),
            })
        })
        .collect()
}

/// KR-REQ-20.01: `crypto_box_easy` seals to the bytes libsodium's 1.0.22 release makes, at every
/// length, from fixed keys derived from fixed seeds and a fixed nonce for each case. The box puts
/// its authenticator first, so the case records the first 16 bytes as the authenticator.
#[test]
fn the_box_seals_to_the_frozen_bytes_at_every_length() {
    let frozen = read_json("cipher-known-answers.json");
    assert_cases_equal("box", &box_cases(&box_keys()), frozen_cases(&frozen, "box"));
}

/// KR-REQ-20.01: a box opens for the recipient and fails to open after a change of the
/// ciphertext, the authenticator, the nonce, the sender's public key or the recipient's secret
/// key, or after the message is cut or lengthened.
#[test]
fn the_box_opens_what_it_sealed_and_refuses_every_change() {
    let keys = box_keys();
    for length in LENGTHS {
        let plaintext = box_plaintext(length);
        let nonce = box_nonce(length);
        let sealed = box_easy(
            &plaintext,
            &nonce,
            &keys.recipient_public,
            &keys.sender_secret,
        )
        .expect("seals");
        let what = format!("{length} bytes");
        assert_eq!(
            box_open_easy(&sealed, &nonce, &keys.sender_public, &keys.recipient_secret)
                .expect("opens"),
            plaintext,
            "{what}"
        );

        // The authenticator is the first 16 bytes, then the body.
        let mut positions = vec![0, BOX_MAC_LEN - 1];
        if length > 0 {
            positions.extend([
                BOX_MAC_LEN,
                BOX_MAC_LEN + length / 2,
                BOX_MAC_LEN + length - 1,
            ]);
        }
        positions.sort_unstable();
        positions.dedup();
        for position in positions {
            assert!(
                matches!(
                    box_open_easy(
                        &flipped(sealed.clone(), position),
                        &nonce,
                        &keys.sender_public,
                        &keys.recipient_secret
                    ),
                    Err(CryptoError::Authentication { .. })
                ),
                "{what}: a flip at byte {position} was accepted"
            );
        }
        let mut other_nonce = nonce;
        other_nonce[BOX_NONCE_LEN - 1] ^= 1;
        assert!(
            box_open_easy(
                &sealed,
                &other_nonce,
                &keys.sender_public,
                &keys.recipient_secret
            )
            .is_err(),
            "{what}: another nonce was accepted"
        );
        assert!(
            box_open_easy(&sealed, &nonce, &keys.other_public, &keys.recipient_secret).is_err(),
            "{what}: another sender's public key was accepted"
        );
        assert!(
            box_open_easy(&sealed, &nonce, &keys.sender_public, &keys.other_secret).is_err(),
            "{what}: another recipient's secret key was accepted"
        );
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(
            box_open_easy(&longer, &nonce, &keys.sender_public, &keys.recipient_secret).is_err(),
            "{what}: a longer message was accepted"
        );
        assert!(
            box_open_easy(
                &sealed[..sealed.len() - 1],
                &nonce,
                &keys.sender_public,
                &keys.recipient_secret
            )
            .is_err(),
            "{what}: a shorter message was accepted"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The stream.
// ---------------------------------------------------------------------------------------------

/// A pushing state that starts from `header` and `key`, which `stream_init_push` does not allow:
/// it draws the header from the random generator, and the generator is not replaced for a test.
///
/// libsodium's `init_pull` computes the state that `init_push` makes from the same header and
/// key, field for field, so the state a pull makes is the state a push starts from.
/// `a_fixed_header_state_is_the_state_init_push_makes` checks that against a header the library
/// drew itself.
fn fixed_header_push_state(
    header: &[u8; STREAM_HEADER_LEN],
    key: &[u8; STREAM_KEY_LEN],
) -> StreamPushState {
    let pull = stream_init_pull(header, key).expect("a header");
    StreamPushState(pull.0)
}

/// A copy of a pulling state, so that every way a record can be wrong is tried from the same place
/// in the stream.
fn copy_pull_state(state: &StreamPullState) -> StreamPullState {
    StreamPullState(state.0)
}

fn stream_key_and_header() -> ([u8; STREAM_KEY_LEN], [u8; STREAM_HEADER_LEN]) {
    (
        rule_array("kr-known-answers/stream/key"),
        rule_array("kr-known-answers/stream/header"),
    )
}

/// The records of the stream, one for each length, with the tag each is pushed under: messages,
/// then a push and a rekey tag among them, and the final tag on the last.
fn stream_plan() -> Vec<(Vec<u8>, u8)> {
    LENGTHS
        .iter()
        .enumerate()
        .map(|(index, &length)| {
            let tag = if index + 1 == LENGTHS.len() {
                TAG_FINAL
            } else {
                [TAG_MESSAGE, TAG_PUSH, TAG_MESSAGE, TAG_REKEY][index % 4]
            };
            (
                rule_bytes(
                    &format!("kr-known-answers/stream/plaintext/{index}"),
                    length,
                ),
                tag,
            )
        })
        .collect()
}

fn stream_push_all(plan: &[(Vec<u8>, u8)]) -> Vec<Vec<u8>> {
    let (key, header) = stream_key_and_header();
    let mut state = fixed_header_push_state(&header, &key);
    plan.iter()
        .map(|(plaintext, tag)| stream_push(&mut state, plaintext, *tag).expect("pushes"))
        .collect()
}

fn stream_cases(plan: &[(Vec<u8>, u8)], records: &[Vec<u8>]) -> Vec<Value> {
    plan.iter()
        .zip(records)
        .enumerate()
        .map(|(index, ((plaintext, tag), record))| {
            json!({
                "index": index,
                "length": plaintext.len(),
                "mac_hex": hex::encode(&record[record.len() - 16..]),
                "record_sha256_hex": digest_hex(record),
                "tag": tag,
            })
        })
        .collect()
}

/// KR-REQ-20.01: a secretstream pushed under a fixed key and header makes the records libsodium's
/// 1.0.22 release makes, one record at every length, so the counter, the tag byte and the
/// authenticator of every record are held and not only the first. A pull opens each record to its
/// plaintext and its tag.
#[test]
fn the_stream_pushes_the_frozen_records_and_pulls_them_back() {
    let frozen = read_json("cipher-known-answers.json");
    let (key, header) = stream_key_and_header();
    assert_eq!(
        frozen["stream"]["header_hex"],
        hex::encode(header),
        "the stream's header"
    );
    let plan = stream_plan();
    let records = stream_push_all(&plan);
    assert_cases_equal(
        "stream",
        &stream_cases(&plan, &records),
        frozen_cases(&frozen["stream"], "records"),
    );

    let mut pull = stream_init_pull(&header, &key).expect("a header");
    for (index, ((plaintext, tag), record)) in plan.iter().zip(&records).enumerate() {
        let (opened, opened_tag) = stream_pull(&mut pull, record).expect("pulls");
        assert_eq!(&opened, plaintext, "record {index}");
        assert_eq!(opened_tag, *tag, "record {index}");
    }
}

/// KR-REQ-20.01: a secretstream refuses a record that was altered in its tag byte, its body or its
/// authenticator, a record that was left out, two records in the wrong order, a record read twice,
/// and a record from a stream under another key or header.
#[test]
fn the_stream_refuses_altered_missing_reordered_and_replayed_records() {
    let (key, header) = stream_key_and_header();
    let plan = stream_plan();
    let records = stream_push_all(&plan);
    let mut position = stream_init_pull(&header, &key).expect("a header");

    for (index, record) in records.iter().enumerate() {
        // The record's own bytes, flipped at its tag byte, its body's first, middle and last byte
        // and its authenticator's last byte.
        let body = record.len() - STREAM_RECORD_OVERHEAD;
        let mut places = vec![0, record.len() - 1];
        if body > 0 {
            places.extend([1, 1 + body / 2, body]);
        }
        places.sort_unstable();
        places.dedup();
        for place in places {
            let mut state = copy_pull_state(&position);
            assert!(
                stream_pull(&mut state, &flipped(record.clone(), place)).is_err(),
                "record {index}: a flip at byte {place} was accepted"
            );
        }

        // The record that follows it, read first, and the one after it, read in its place.
        if let Some(next) = records.get(index + 1) {
            let mut state = copy_pull_state(&position);
            assert!(
                stream_pull(&mut state, next).is_err(),
                "record {index}: the next record was accepted in its place"
            );
        }
        if let Some(after) = records.get(index + 2) {
            let mut state = copy_pull_state(&position);
            stream_pull(&mut state, record).expect("the record");
            assert!(
                stream_pull(&mut state, after).is_err(),
                "record {index}: a record was left out and the stream was accepted"
            );
        }
        // Read twice.
        let mut state = copy_pull_state(&position);
        stream_pull(&mut state, record).expect("the record");
        assert!(
            stream_pull(&mut state, record).is_err(),
            "record {index}: a replay was accepted"
        );

        stream_pull(&mut position, record).expect("the record");
    }

    // Another key, and another header, fail at the first record.
    let mut other_key = key;
    other_key[0] ^= 1;
    let mut state = stream_init_pull(&header, &other_key).expect("a header");
    assert!(stream_pull(&mut state, &records[0]).is_err());
    let mut other_header = header;
    other_header[STREAM_HEADER_LEN - 1] ^= 1;
    let mut state = stream_init_pull(&other_header, &key).expect("a header");
    assert!(stream_pull(&mut state, &records[0]).is_err());

    // A record shorter than its fixed part is refused for its length, not read.
    let mut state = stream_init_pull(&header, &key).expect("a header");
    assert!(matches!(
        stream_pull(&mut state, &records[0][..STREAM_RECORD_OVERHEAD - 1]),
        Err(CryptoError::Truncated { .. })
    ));
}

/// KR-REQ-20.01: the state a pull starts from is the state `init_push` made, for headers and keys
/// the library drew itself: both push the same records to the same bytes. That is what lets the
/// fixed-header push above stand for the push the product makes.
#[test]
fn a_fixed_header_state_is_the_state_init_push_makes() {
    for index in 0..8 {
        let key: [u8; STREAM_KEY_LEN] = rule_array(&format!("kr-known-answers/state/key/{index}"));
        let (mut made, header) = stream_init_push(&key).expect("a push");
        let mut fixed = fixed_header_push_state(&header, &key);
        for (record, tag) in [
            (
                rule_bytes("kr-known-answers/state/record", 100),
                TAG_MESSAGE,
            ),
            (Vec::new(), TAG_FINAL),
        ] {
            assert_eq!(
                stream_push(&mut made, &record, tag).expect("pushes"),
                stream_push(&mut fixed, &record, tag).expect("pushes"),
                "key {index}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The vectors the documents publish.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-20.01: Ed25519 behind this boundary reproduces every vector of RFC 8032 section 7.1:
/// the public key from each seed, the signature over each message, which verifies, and fails to
/// verify once the signature or the message changes. The messages run from empty to 1,023 bytes
/// and include the one that signs the SHA-512 of "abc".
#[test]
fn ed25519_reproduces_the_rfc_8032_section_7_1_vectors() {
    let published = read_json("published-vectors.json");
    let tests = published["rfc8032_section_7_1"]["tests"]
        .as_array()
        .expect("the tests");
    let names: Vec<&str> = tests
        .iter()
        .map(|test| test["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        ["TEST 1", "TEST 2", "TEST 3", "TEST 1024", "TEST SHA(abc)"]
    );
    let mut checked = 0;
    for test in tests {
        let name = test["name"].as_str().expect("a name");
        let seed: [u8; SIGN_SEED_LEN] = hex_array(test, "seed_hex");
        let message = hex_vec(test, "message_hex");
        let signature: [u8; SIGN_LEN] = hex_array(test, "signature_hex");
        let (public, secret) = sign_seed_keypair(&seed).expect("a keypair");
        assert_eq!(public, hex_array::<32>(test, "public_hex"), "{name}");
        assert_eq!(
            sign_detached(&message, &secret).expect("a signature"),
            signature,
            "{name}"
        );
        assert!(
            sign_verify_detached(&signature, &message, &public).is_ok(),
            "{name}"
        );
        let mut changed = signature;
        changed[SIGN_LEN - 1] ^= 1;
        assert!(
            sign_verify_detached(&changed, &message, &public).is_err(),
            "{name}: a changed signature"
        );
        let mut other = message.clone();
        other.push(0);
        assert!(
            sign_verify_detached(&signature, &other, &public).is_err(),
            "{name}: a changed message"
        );
        checked += 1;
    }
    assert_eq!(checked, 5, "every published test was run");
}

/// KR-REQ-20.01: X25519 behind this boundary reproduces the two input and output pairs of
/// RFC 7748 section 5.2.
#[test]
fn x25519_reproduces_the_rfc_7748_section_5_2_examples() {
    let published = read_json("published-vectors.json");
    let examples = published["rfc7748_section_5_2"]["examples"]
        .as_array()
        .expect("the examples");
    assert_eq!(examples.len(), 2);
    let mut checked = 0;
    for example in examples {
        assert_eq!(
            scalarmult(
                &hex_array(example, "scalar_hex"),
                &hex_array(example, "u_hex")
            )
            .expect("an agreement"),
            hex_array::<32>(example, "output_hex")
        );
        checked += 1;
    }
    assert_eq!(checked, 2, "both published examples were run");
}

/// The RFC's iteration: start from k = u = 9; each step takes the agreement of k with u as the
/// new k and the old k as the new u. Returns k after each of the iterations in `after`.
fn x25519_iterate(after: &[usize]) -> Vec<[u8; AGREEMENT_LEN]> {
    let last = after.iter().copied().max().expect("an iteration count");
    let mut k = BASE_POINT_BYTES;
    let mut u = BASE_POINT_BYTES;
    let mut seen = Vec::new();
    for iteration in 1..=last {
        let next = scalarmult(&k, &u).expect("an agreement");
        u = k;
        k = next;
        if after.contains(&iteration) {
            seen.push(k);
        }
    }
    seen
}

const BASE_POINT_BYTES: [u8; AGREEMENT_LEN] = {
    let mut point = [0u8; AGREEMENT_LEN];
    point[0] = 9;
    point
};

/// KR-REQ-20.01: X25519 behind this boundary gives the values RFC 7748 section 5.2 prints after
/// one and after 1,000 iterations, which run the ladder and the inversion on a thousand different
/// values.
#[test]
fn x25519_reproduces_the_rfc_7748_iterations_after_one_and_one_thousand() {
    let published = read_json("published-vectors.json");
    let iterations = &published["rfc7748_section_5_2"]["iterations"];
    assert_eq!(
        x25519_iterate(&[1, 1_000]),
        [
            hex_array::<32>(iterations, "after_1_hex"),
            hex_array::<32>(iterations, "after_1000_hex")
        ]
    );
}

/// The value RFC 7748 section 5.2 prints after 1,000,000 iterations. It takes a
/// million agreements, so it runs on request: `cargo test -p kr-crypto -- --ignored`.
#[test]
#[ignore = "a million X25519 agreements; run on request"]
fn x25519_reproduces_the_rfc_7748_iteration_after_one_million() {
    let published = read_json("published-vectors.json");
    assert_eq!(
        x25519_iterate(&[1_000_000]),
        [hex_array::<32>(
            &published["rfc7748_section_5_2"]["iterations"],
            "after_1000000_hex"
        )]
    );
}

/// KR-REQ-20.01: the AEAD seals the plaintext of draft-irtf-cfrg-xchacha appendix A.3.1 to the
/// ciphertext and the tag the draft prints, under the draft's key, nonce and additional data. The
/// test in `tests/libsodium.rs` opens the same bytes through the crate's interface.
#[test]
fn the_aead_seals_the_xchacha20_poly1305_draft_vector_to_its_published_bytes() {
    let published = read_json("published-vectors.json");
    let vector = &published["xchacha20_poly1305_draft_a_3_1"];
    let key: [u8; AEAD_KEY_LEN] = hex_array(vector, "key_hex");
    let nonce: [u8; AEAD_NONCE_LEN] = hex_array(vector, "nonce_hex");
    let aad = hex_vec(vector, "aad_hex");
    let plaintext = hex_vec(vector, "plaintext_hex");
    let mut sealed_published = hex_vec(vector, "ciphertext_hex");
    sealed_published.extend(hex_vec(vector, "tag_hex"));

    let sealed = aead_encrypt(&plaintext, &aad, &nonce, &key).expect("seals");
    assert_eq!(sealed, sealed_published);
    assert_eq!(
        aead_decrypt(&sealed_published, &aad, &nonce, &key).expect("opens"),
        plaintext
    );
}

// ---------------------------------------------------------------------------------------------
// The comparison and the random bytes.
// ---------------------------------------------------------------------------------------------

/// KR-REQ-20.02: the comparison reports equal buffers equal and any one differing byte unequal, at
/// every position of every length that straddles a word, a vector or a cache line, whatever the
/// alignment of either slice, and reports slices of different lengths unequal. This is a test of
/// the answer, not of timing.
#[test]
fn the_comparison_answers_right_at_every_position_length_and_offset() {
    let lengths = [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 256];
    let mut positions_checked = 0;
    for length in lengths {
        let mut left_backing = rule_bytes(
            &format!("kr-known-answers/compare/left/{length}"),
            length + 16,
        );
        let mut right_backing = left_backing.clone();
        for left_offset in 0..16 {
            for right_offset in 0..16 {
                let content = rule_bytes(
                    &format!(
                        "kr-known-answers/compare/content/{length}/{left_offset}/{right_offset}"
                    ),
                    length,
                );
                left_backing[left_offset..left_offset + length].copy_from_slice(&content);
                right_backing[right_offset..right_offset + length].copy_from_slice(&content);
                let what = format!("{length} bytes at offsets {left_offset} and {right_offset}");

                assert!(
                    constant_time_eq(
                        &left_backing[left_offset..left_offset + length],
                        &right_backing[right_offset..right_offset + length]
                    ),
                    "{what}: equal buffers were reported unequal"
                );
                for position in 0..length {
                    // Every bit of a byte, over the positions, and the byte's other seven bits left alone.
                    let bit = 1u8 << (position % 8);
                    right_backing[right_offset + position] ^= bit;
                    assert!(
                        !constant_time_eq(
                            &left_backing[left_offset..left_offset + length],
                            &right_backing[right_offset..right_offset + length]
                        ),
                        "{what}: a difference at byte {position} was not seen"
                    );
                    right_backing[right_offset + position] ^= bit;
                    positions_checked += 1;
                }
                // A different length is unequal even when one is a prefix of the other.
                assert!(
                    !constant_time_eq(
                        &left_backing[left_offset..left_offset + length],
                        &right_backing[right_offset..right_offset + length + 1]
                    ),
                    "{what}: a longer buffer was reported equal"
                );
                if length > 0 {
                    assert!(
                        !constant_time_eq(
                            &left_backing[left_offset..left_offset + length],
                            &right_backing[right_offset..right_offset + length - 1]
                        ),
                        "{what}: a shorter buffer was reported equal"
                    );
                }
            }
        }
    }
    // Every position of every length was tried at every pair of offsets.
    assert_eq!(positions_checked, lengths.iter().sum::<usize>() * 16 * 16);
}

/// KR-REQ-20.02: the random generator fills the buffer it is given and no byte outside it, at
/// every length from nothing to a page, and two fills of 32 bytes or more are not the same and are
/// not all one value.
#[test]
fn random_bytes_fill_the_destination_and_leave_the_bytes_around_it_alone() {
    const GUARD: usize = 16;
    let mut fills = 0;
    for length in [0usize, 1, 32, 256, 4_096] {
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..2 {
            let mut buffer = vec![0xa5u8; GUARD + length + GUARD];
            random_bytes(&mut buffer[GUARD..GUARD + length]).expect("random bytes");
            assert!(
                buffer[..GUARD].iter().all(|byte| *byte == 0xa5),
                "{length} bytes: the bytes before the destination changed"
            );
            assert!(
                buffer[GUARD + length..].iter().all(|byte| *byte == 0xa5),
                "{length} bytes: the bytes after the destination changed"
            );
            let filled = buffer[GUARD..GUARD + length].to_vec();
            if length >= 32 {
                assert!(
                    filled.iter().any(|byte| *byte != filled[0]),
                    "{length} bytes: one value fills the destination"
                );
                assert!(
                    filled.iter().any(|byte| *byte != 0xa5),
                    "{length} bytes: nothing was written"
                );
                if let Some(earlier) = &previous {
                    assert_ne!(earlier, &filled, "{length} bytes: two fills are equal");
                }
            }
            previous = Some(filled);
            fills += 1;
        }
    }
    assert_eq!(fills, 10, "every length was filled twice");
}
