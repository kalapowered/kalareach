//! A push receiver's answer to a registration challenge.
//!
//! Section 16 has the gateway send a random, single-use challenge through the provider to a token
//! before it binds the token to an installation, and has the native receiver return it signed by
//! the proposed installation key. The receiver runs when nothing else does: no interface, no
//! JavaScript, and on Android sometimes a process the system started only for this message. So the
//! decision and the signature are made here, in one narrow function over the installation's own
//! code, and the platform's half (Kotlin or Swift) only keeps a record, reads a key and posts.
//!
//! # What the receiver answers
//!
//! One thing: the challenge of the one registration this device has pending. The application
//! writes a [`PendingRegistration`] before it proposes a token, and a challenge is answered only
//! when it names that registration, that token and that gateway, while the record is `pending` and
//! the device's own deadline has not passed. A challenge for another registration, another token or
//! another gateway, one that arrives with no record, one that arrives after the record was answered
//! and one that arrives late each get no answer and show nothing. The gateway the answer is posted
//! to is the record's, never the challenge's.
//!
//! The challenge's own expiry is signed as the gateway sent it, because the gateway compares it
//! with what it recorded; this device's clock is not used to second-guess it. The deadline in the
//! record is the device's own bound on how long it will answer at all.
//!
//! # What it signs
//!
//! [`classify`] decides without a secret. [`sign`] decides again from the same inputs, and only
//! then reads the installation's key, builds the answer and the signed request that carries it, and
//! returns the bytes to post. The key is the device's authorisation key, read from the secure store
//! after a match and never kept: the signer it is given to signs a managed-service request and the
//! answer to a registration challenge, and refuses every other statement.
//!
//! The two functions take and return JSON text, so the Kotlin and Swift halves share one shape and
//! none of them encodes a canonical value of its own.

use std::collections::BTreeMap;

use companion_preview::OneSecret;
use kr_client::services::push::{InstallationSigner, REGISTER_ROUTE, signed_push_request};
use kr_crypto::store::{SecretName, SecretStore, load_authorisation_key};
use kr_protocol::ids::PushRegistrationId;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::{
    PushPlatform, PushRegistrationAnswer, PushRegistrationAnswerPayload, PushRegistrationRequest,
    PushRequest,
};
use kr_protocol::scalars::{Digest256, Nonce256, TimestampMs};
use kr_protocol::service::{GatewayOrigin, installation_id};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::secrets::DEVICE_SCOPE;

/// The message data key whose presence says a message is a registration challenge.
pub const CHALLENGE_KEY: &str = "kr_challenge";
/// The data key that names the attempt the challenge is for.
pub const REGISTRATION_KEY: &str = "kr_registration_id";
/// The data key that carries the digest of the token the challenge was sent to.
pub const TOKEN_DIGEST_KEY: &str = "kr_token_digest";
/// The data key that names the gateway that sent the challenge.
pub const ORIGIN_KEY: &str = "kr_gateway_origin";
/// The data key that carries when the gateway stops accepting an answer.
pub const EXPIRES_KEY: &str = "kr_expires_at_ms";

/// How far a pending registration stands, as the platform half records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// Waiting for its challenge.
    Pending,
    /// Its challenge was answered and the gateway took the answer.
    Answered,
    /// The receiver refused its challenge or the gateway refused its answer; `reason` says which.
    Refused,
    /// Its deadline passed.
    Expired,
}

/// The one registration this device is waiting for the challenge of.
///
/// It holds nothing secret: the identifiers a challenge has to repeat, the gateway to answer to,
/// and the device's own deadline. The platform half keeps it where only the application reads, and
/// writes `state` and `reason` as the registration moves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRegistration {
    /// The attempt a challenge has to name.
    pub registration_id: PushRegistrationId,
    /// The digest of the token that was proposed.
    pub token_digest: Digest256,
    /// The gateway the token was proposed to, and the one an answer goes to.
    pub gateway_origin: GatewayOrigin,
    /// The platform the token belongs to.
    pub platform: PushPlatform,
    /// When this device stops answering, in UTC milliseconds by its own clock.
    pub deadline_ms: u64,
    /// How far the registration stands.
    pub state: PendingState,
    /// Why a registration was refused, in words a log may hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What a message and a record decide, before any secret is read.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The message is not a registration challenge.
    NotAChallenge,
    /// It is one, and is not answered, for the reason named.
    Refused(&'static str),
    /// It is the challenge of the pending registration.
    Answer(Box<Challenge>),
}

/// A challenge that names the pending registration.
#[derive(Debug, PartialEq, Eq)]
struct Challenge {
    challenge: Nonce256,
    expires_at_ms: TimestampMs,
    registration_id: PushRegistrationId,
    token_digest: Digest256,
    gateway_origin: GatewayOrigin,
}

/// What a receiver hands over: the message's data, the record it keeps and its clock.
#[derive(Deserialize)]
struct Input {
    data: BTreeMap<String, String>,
    pending: Option<PendingRegistration>,
    now_ms: u64,
}

/// One value of the message's data, read as the type the protocol gives it.
fn field<T: for<'de> Deserialize<'de>>(data: &BTreeMap<String, String>, key: &str) -> Option<T> {
    serde_json::from_value(Value::String(data.get(key)?.clone())).ok()
}

/// Decides what a message means for the pending registration.
fn decide(
    data: &BTreeMap<String, String>,
    pending: Option<&PendingRegistration>,
    now_ms: u64,
) -> Verdict {
    if !data.contains_key(CHALLENGE_KEY) {
        return Verdict::NotAChallenge;
    }
    let Some(pending) = pending else {
        return Verdict::Refused("no_pending");
    };
    if pending.state != PendingState::Pending {
        return Verdict::Refused("not_pending");
    }
    if now_ms >= pending.deadline_ms {
        return Verdict::Refused("expired");
    }
    let (
        Some(challenge),
        Some(expires_at_ms),
        Some(registration_id),
        Some(token_digest),
        Some(gateway_origin),
    ) = (
        field::<Nonce256>(data, CHALLENGE_KEY),
        field::<TimestampMs>(data, EXPIRES_KEY),
        field::<PushRegistrationId>(data, REGISTRATION_KEY),
        field::<Digest256>(data, TOKEN_DIGEST_KEY),
        field::<GatewayOrigin>(data, ORIGIN_KEY),
    )
    else {
        return Verdict::Refused("malformed");
    };
    if registration_id != pending.registration_id {
        return Verdict::Refused("registration");
    }
    if token_digest != pending.token_digest {
        return Verdict::Refused("token");
    }
    if gateway_origin != pending.gateway_origin {
        return Verdict::Refused("origin");
    }
    // The challenge says when the gateway stops taking an answer to it. An answer after that is
    // refused by the gateway, and a refusal ends the registration, so a challenge that has lapsed
    // is left alone and the registration waits for a fresh one.
    if now_ms >= expires_at_ms.get() {
        return Verdict::Refused("expired");
    }
    Verdict::Answer(Box::new(Challenge {
        challenge,
        expires_at_ms,
        registration_id,
        token_digest,
        gateway_origin,
    }))
}

/// The name of the item the installation's key is kept under, which the platform half reads.
fn seed_item() -> String {
    SecretName::device_key(DEVICE_SCOPE, KeyPurpose::Authorisation)
        .map(|name| name.as_str().to_owned())
        .unwrap_or_default()
}

fn refused(reason: &str) -> String {
    serde_json::json!({ "verdict": "refused", "reason": reason }).to_string()
}

/// Decides what one message means for the pending registration, with no secret.
///
/// `input` is `{"data": {...}, "pending": {...} | null, "now_ms": n}`: the message's data as a map
/// of strings, the record the receiver keeps and its own clock. The answer is one of
/// `{"verdict":"not_a_challenge"}`, `{"verdict":"refused","reason":...}` and
/// `{"verdict":"answer","url":...,"seed_item":...}`: where to post, and the name of the item the
/// key is read from once the receiver has this verdict.
#[must_use]
pub fn classify(input: &str) -> String {
    let Ok(Input {
        data,
        pending,
        now_ms,
    }) = serde_json::from_str(input)
    else {
        return refused("input");
    };
    match decide(&data, pending.as_ref(), now_ms) {
        Verdict::NotAChallenge => serde_json::json!({ "verdict": "not_a_challenge" }).to_string(),
        Verdict::Refused(reason) => refused(reason),
        Verdict::Answer(challenge) => serde_json::json!({
            "verdict": "answer",
            "url": format!("{}{REGISTER_ROUTE}", challenge.gateway_origin.as_str()),
            "seed_item": seed_item(),
        })
        .to_string(),
    }
}

/// Answers the pending registration's challenge, reading the installation's key from `store`.
///
/// `input` is the one [`classify`] was given, and the decision is made again from it: nothing a
/// caller says about an earlier verdict is trusted. The answer is `{"ok":true,"url":...,"body":...}`
/// with the signed request to post to `url`, or `{"ok":false,"reason":...}`.
#[must_use]
pub fn sign_with(input: &str, store: &dyn SecretStore) -> String {
    let failed = |reason: &str| serde_json::json!({ "ok": false, "reason": reason }).to_string();
    let Ok(Input {
        data,
        pending,
        now_ms,
    }) = serde_json::from_str(input)
    else {
        return failed("input");
    };
    let Some(pending) = pending else {
        return failed("no_pending");
    };
    let challenge = match decide(&data, Some(&pending), now_ms) {
        Verdict::Answer(challenge) => challenge,
        Verdict::NotAChallenge => return failed("not_a_challenge"),
        Verdict::Refused(reason) => return failed(reason),
    };
    let key = match load_authorisation_key(store, DEVICE_SCOPE) {
        Ok(Some(key)) => key,
        Ok(None) => return failed("key_missing"),
        Err(_) => return failed("key_unavailable"),
    };
    let payload = PushRegistrationAnswerPayload {
        challenge: challenge.challenge,
        expires_at_ms: challenge.expires_at_ms,
        gateway_origin: challenge.gateway_origin.clone(),
        installation_id: installation_id(key.public()),
        platform: pending.platform,
        registration_id: challenge.registration_id,
        token_digest: challenge.token_digest,
    };
    let signer = InstallationSigner::new(key);
    let Ok(input) = payload.signing_input() else {
        return failed("encoding");
    };
    let Ok(signature) = kr_client::services::ServiceSigner::sign(&signer, &input) else {
        return failed("signing");
    };
    let answer = PushRegistrationAnswer {
        payload,
        installation_key: kr_client::services::ServiceSigner::public_key(&signer),
        signature,
    };
    let body = PushRequest::InstallationRegister {
        request: PushRegistrationRequest::Answer { answer },
    };
    let mut nonce = [0_u8; 32];
    if kr_crypto::random_bytes(&mut nonce).is_err() {
        return failed("nonce");
    }
    let request =
        match signed_push_request(&challenge.gateway_origin, &body, &signer, now_ms, nonce) {
            Ok(request) => request,
            Err(error) => {
                return failed(match error.code() {
                    kr_protocol::error::ErrorCode::ClockUntrusted => "clock",
                    _ => "request",
                });
            }
        };
    let Ok(body) = String::from_utf8(request) else {
        return failed("request");
    };
    serde_json::json!({
        "ok": true,
        "url": format!("{}{REGISTER_ROUTE}", challenge.gateway_origin.as_str()),
        "body": body,
    })
    .to_string()
}

/// [`sign_with`], with the installation's key given as its 32-byte seed by a platform half that
/// reads its own store. The seed is held only for the call and cleared after it.
#[must_use]
pub fn sign(input: &str, seed: &[u8]) -> String {
    let Ok(name) = SecretName::device_key(DEVICE_SCOPE, KeyPurpose::Authorisation) else {
        return serde_json::json!({ "ok": false, "reason": "key_unavailable" }).to_string();
    };
    sign_with(input, &OneSecret::new(name, seed))
}

/// What the JVM calls: the two functions above and the opener of a sealed preview, by their exported
/// names.
///
/// Exporting a name is an unsafe attribute: the name has to be unique in the process, which the
/// package and class in it make it. These are the places, with `tls`'s start, this crate allows
/// unsafe code. Each runs inside `jni`'s own guard, which turns a failure or a panic into a Java
/// exception rather than an unwind into the JVM.
#[cfg(target_os = "android")]
mod android {
    use jni::errors::ThrowRuntimeExAndDefault;
    use jni::objects::{JByteArray, JClass, JObject, JString};

    /// `PushAnswer.classify(input)`.
    #[allow(
        unsafe_code,
        reason = "the JVM finds a native method by its exported, unmangled name"
    )]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_to_kala_reach_companion_push_PushAnswer_classify<'caller>(
        mut unowned: jni::EnvUnowned<'caller>,
        _class: JClass<'caller>,
        input: JString<'caller>,
    ) -> JObject<'caller> {
        unowned
            .with_env(|env| -> jni::errors::Result<JObject<'caller>> {
                let text = input.try_to_string(env)?;
                Ok(env.new_string(super::classify(&text))?.into())
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }

    /// `PushAnswer.sign(input, seed)`.
    #[allow(
        unsafe_code,
        reason = "the JVM finds a native method by its exported, unmangled name"
    )]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_to_kala_reach_companion_push_PushAnswer_sign<'caller>(
        mut unowned: jni::EnvUnowned<'caller>,
        _class: JClass<'caller>,
        input: JString<'caller>,
        seed: JByteArray<'caller>,
    ) -> JObject<'caller> {
        unowned
            .with_env(|env| -> jni::errors::Result<JObject<'caller>> {
                let text = input.try_to_string(env)?;
                let held = zeroize::Zeroizing::new(env.convert_byte_array(&seed)?);
                Ok(env.new_string(super::sign(&text, &held))?.into())
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }

    /// `PreviewOpener.open(input, seed)`: opens a sealed notification preview, in the function the
    /// phone's receivers share ([`companion_preview::open`]).
    #[allow(
        unsafe_code,
        reason = "the JVM finds a native method by its exported, unmangled name"
    )]
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_to_kala_reach_companion_push_PreviewOpener_open<'caller>(
        mut unowned: jni::EnvUnowned<'caller>,
        _class: JClass<'caller>,
        input: JString<'caller>,
        seed: JByteArray<'caller>,
    ) -> JObject<'caller> {
        unowned
            .with_env(|env| -> jni::errors::Result<JObject<'caller>> {
                let text = input.try_to_string(env)?;
                let held = zeroize::Zeroizing::new(env.convert_byte_array(&seed)?);
                Ok(env
                    .new_string(companion_preview::open(&text, &held))?
                    .into())
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }

    /// Keeps the native methods in the linked library, which the JVM looks them up in by name.
    #[used]
    static CLASSIFY: for<'caller> extern "system" fn(
        jni::EnvUnowned<'caller>,
        JClass<'caller>,
        JString<'caller>,
    ) -> JObject<'caller> = Java_to_kala_reach_companion_push_PushAnswer_classify;

    /// Keeps the native methods in the linked library, which the JVM looks them up in by name.
    #[used]
    static SIGN: for<'caller> extern "system" fn(
        jni::EnvUnowned<'caller>,
        JClass<'caller>,
        JString<'caller>,
        JByteArray<'caller>,
    ) -> JObject<'caller> = Java_to_kala_reach_companion_push_PushAnswer_sign;

    /// Keeps the native methods in the linked library, which the JVM looks them up in by name.
    #[used]
    static OPEN: for<'caller> extern "system" fn(
        jni::EnvUnowned<'caller>,
        JClass<'caller>,
        JString<'caller>,
        JByteArray<'caller>,
    ) -> JObject<'caller> = Java_to_kala_reach_companion_push_PreviewOpener_open;
}

/// What Swift calls: the two functions above, by their C names, with the key read from this
/// application's own keychain group.
///
/// The text each returns is owned by this library and given back with [`kr_push_free`].
#[cfg(target_os = "ios")]
mod ios {
    use std::ffi::{CStr, CString, c_char};

    use kr_crypto::store::SecretStore;

    #[allow(
        unsafe_code,
        reason = "reading the C string a caller passes is a call through a raw pointer"
    )]
    fn text(pointer: *const c_char) -> Option<String> {
        if pointer.is_null() {
            return None;
        }
        // SAFETY: the caller passes a NUL-terminated string that outlives this call.
        unsafe { CStr::from_ptr(pointer) }
            .to_str()
            .ok()
            .map(str::to_owned)
    }

    fn give(text: &str) -> *mut c_char {
        CString::new(text).map_or(std::ptr::null_mut(), CString::into_raw)
    }

    /// Decides what one message means for the pending registration. Returns null for input that is
    /// not UTF-8.
    #[allow(unsafe_code, reason = "Swift finds a function by its exported C name")]
    #[unsafe(no_mangle)]
    pub extern "C" fn kr_push_classify(input: *const c_char) -> *mut c_char {
        text(input).map_or(std::ptr::null_mut(), |input| give(&super::classify(&input)))
    }

    /// Answers the challenge, reading the key from the keychain group named. Returns null for input
    /// that is not UTF-8.
    #[allow(unsafe_code, reason = "Swift finds a function by its exported C name")]
    #[unsafe(no_mangle)]
    pub extern "C" fn kr_push_sign(input: *const c_char, group: *const c_char) -> *mut c_char {
        let (Some(input), Some(group)) = (text(input), text(group)) else {
            return std::ptr::null_mut();
        };
        let store: Box<dyn SecretStore> = Box::new(crate::secrets::KeychainStore::new(group));
        give(&super::sign_with(&input, &*store))
    }

    /// Gives back a text one of the functions above returned.
    #[allow(unsafe_code, reason = "Swift finds a function by its exported C name")]
    #[unsafe(no_mangle)]
    pub extern "C" fn kr_push_free(pointer: *mut c_char) {
        if !pointer.is_null() {
            // SAFETY: the pointer came from `CString::into_raw` in this library and is given back once.
            drop(unsafe { CString::from_raw(pointer) });
        }
    }

    /// Keeps the functions in the linked library, which Swift looks them up in by name.
    #[used]
    static CLASSIFY: extern "C" fn(*const c_char) -> *mut c_char = kr_push_classify;
    /// Keeps the functions in the linked library, which Swift looks them up in by name.
    #[used]
    static SIGN: extern "C" fn(*const c_char, *const c_char) -> *mut c_char = kr_push_sign;
    /// Keeps the functions in the linked library, which Swift looks them up in by name.
    #[used]
    static FREE: extern "C" fn(*mut c_char) = kr_push_free;
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use kr_crypto::keys::DeviceKeys;
    use kr_crypto::sign::{SigningTranscript, verify};
    use kr_crypto::store::{MemoryStore, store_device_keys};
    use kr_protocol::service::{ServiceRequestSignature, ServiceRequestSigner};

    use super::*;

    const VECTORS: &str = include_str!("../../../../../fixtures/push/push.json");

    fn now_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("a clock")
                .as_millis(),
        )
        .expect("a time")
    }

    /// The answer the vectors record, whose payload names the challenge a gateway sends.
    fn vector_answer() -> PushRegistrationAnswer {
        let vectors: Value = serde_json::from_str(VECTORS).expect("the vectors");
        let case = vectors["cases"]
            .as_array()
            .expect("the cases")
            .iter()
            .find(|case| case["id"] == "registration_answer")
            .expect("the answer vector")
            .clone();
        serde_json::from_value(case["json"].clone()).expect("an answer")
    }

    /// The data a gateway sends for the vector's challenge, as a provider carries it: strings.
    fn challenge_data() -> BTreeMap<String, String> {
        // The gateway's challenge lives five minutes from when it is sent.
        challenge_data_expiring(now_ms() + 300_000)
    }

    /// As [`challenge_data`], for a challenge the gateway stops taking an answer to at `expires`.
    fn challenge_data_expiring(expires: u64) -> BTreeMap<String, String> {
        let payload = serde_json::to_value(vector_answer().payload).expect("a payload");
        let text = |key: &str| payload[key].as_str().expect("a string").to_owned();
        BTreeMap::from([
            (CHALLENGE_KEY.to_owned(), text("challenge")),
            (EXPIRES_KEY.to_owned(), expires.to_string()),
            (REGISTRATION_KEY.to_owned(), text("registration_id")),
            (TOKEN_DIGEST_KEY.to_owned(), text("token_digest")),
            (ORIGIN_KEY.to_owned(), text("gateway_origin")),
        ])
    }

    /// The record that waits for exactly that challenge.
    fn pending(deadline_ms: u64) -> PendingRegistration {
        let payload = vector_answer().payload;
        PendingRegistration {
            registration_id: payload.registration_id,
            token_digest: payload.token_digest,
            gateway_origin: payload.gateway_origin,
            platform: payload.platform,
            deadline_ms,
            state: PendingState::Pending,
            reason: None,
        }
    }

    fn input(
        data: &BTreeMap<String, String>,
        pending: Option<&PendingRegistration>,
        now_ms: u64,
    ) -> String {
        serde_json::json!({ "data": data, "pending": pending, "now_ms": now_ms }).to_string()
    }

    fn verdict(
        data: &BTreeMap<String, String>,
        pending: Option<&PendingRegistration>,
        now_ms: u64,
    ) -> Value {
        serde_json::from_str(&classify(&input(data, pending, now_ms))).expect("a verdict")
    }

    /// A store that holds the device's four keys under the scope the application keeps them in.
    fn store(keys: &DeviceKeys) -> MemoryStore {
        let store = MemoryStore::new();
        store_device_keys(&store, DEVICE_SCOPE, keys).expect("the keys are kept");
        store
    }

    /// The challenge of the pending registration is the one thing answered, and the answer is the
    /// vectors' own payload, signed by the installation's key under the answer's domain, in a
    /// request whose credential covers the body's digest and verifies under the same key.
    #[test]
    fn the_challenge_of_the_pending_registration_is_answered_with_the_payload_the_vectors_record() {
        let now = now_ms();
        let keys = DeviceKeys::generate().expect("keys");
        let key = &keys.authorisation;
        let data = challenge_data();
        let pending = pending(now + 60_000);

        let verdict = verdict(&data, Some(&pending), now);
        assert_eq!(verdict["verdict"], "answer");
        assert_eq!(
            verdict["url"],
            "https://reach.kala.to/api/push/installation/register"
        );
        assert_eq!(verdict["seed_item"], seed_item());

        let signed: Value = serde_json::from_str(&sign_with(
            &input(&data, Some(&pending), now),
            &store(&keys),
        ))
        .expect("an answer");
        assert_eq!(signed["ok"], true, "{signed}");
        assert_eq!(signed["url"], verdict["url"]);
        let request: Value =
            serde_json::from_str(signed["body"].as_str().expect("a body")).expect("a request");
        let body: PushRequest = serde_json::from_value(request["body"].clone()).expect("a body");
        let PushRequest::InstallationRegister {
            request: PushRegistrationRequest::Answer { answer },
        } = &body
        else {
            panic!("the request carries an answer: {body:?}");
        };

        // The statement is the vector's challenge, for this installation and the pending platform.
        let expected = PushRegistrationAnswerPayload {
            installation_id: installation_id(key.public()),
            expires_at_ms: TimestampMs::new(data[EXPIRES_KEY].parse().expect("a time")),
            ..vector_answer().payload
        };
        assert_eq!(answer.payload, expected);
        assert_eq!(answer.installation_key, *key.public());
        assert!(answer.key_names_its_installation());
        let transcript = SigningTranscript::from_canonical_bytes(
            kr_protocol::push::PUSH_REGISTRATION_ANSWER_DOMAIN,
            answer.payload.signing_input().expect("a signing input"),
        )
        .expect("a transcript");
        verify(key.public(), &transcript, &answer.signature)
            .expect("the answer is signed by the installation's key");

        // The request's credential covers this body's digest, and verifies under the same key.
        let signature: ServiceRequestSignature =
            serde_json::from_value(request["signature"].clone()).expect("a signature");
        assert_eq!(signature.signer, ServiceRequestSigner::Installation);
        assert_eq!(
            signature.payload.body_digest,
            body.digest().expect("a digest")
        );
        assert_eq!(signature.payload.method, body.method());
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            signature.signing_input().expect("a signing input"),
        )
        .expect("a transcript");
        verify(key.public(), &transcript, &signature.signature)
            .expect("the request is signed by the installation's key");
    }

    /// A platform half that reads its own store hands the receiver the seed, and the answer is the
    /// one the store itself gives: the same installation, the same signed request.
    #[test]
    fn a_seed_the_platform_half_read_signs_as_the_installation_the_store_names() {
        let now = now_ms();
        let keys = DeviceKeys::generate().expect("keys");
        let kept = store(&keys);
        let seed = kept
            .get(&SecretName::device_key(DEVICE_SCOPE, KeyPurpose::Authorisation).expect("a name"))
            .expect("a read")
            .expect("a seed");
        let request = input(&challenge_data(), Some(&pending(now + 60_000)), now);
        let signed: Value =
            serde_json::from_str(&sign(&request, seed.expose())).expect("an answer");
        assert_eq!(signed["ok"], true, "{signed}");
        let sent: Value =
            serde_json::from_str(signed["body"].as_str().expect("a body")).expect("a request");
        let signature: ServiceRequestSignature =
            serde_json::from_value(sent["signature"].clone()).expect("a signature");
        assert_eq!(signature.public_key, *keys.authorisation.public());
    }

    /// A challenge that does not name the pending registration gets no answer, and none of the
    /// refusals reads the key: a store that holds none answers each of them the same way.
    #[test]
    fn a_challenge_for_anything_but_the_pending_registration_is_not_answered() {
        let now = now_ms();
        let pending = pending(now + 60_000);
        let data = challenge_data();
        let empty = OneSecret::new(SecretName::new("nothing/here").expect("a name"), &[]);
        let mut other_registration = data.clone();
        other_registration.insert(
            REGISTRATION_KEY.to_owned(),
            "11111111-2222-4333-8444-555555555555".to_owned(),
        );
        let mut other_token = data.clone();
        other_token.insert(
            TOKEN_DIGEST_KEY.to_owned(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        );
        let mut other_origin = data.clone();
        other_origin.insert(
            ORIGIN_KEY.to_owned(),
            "https://elsewhere.example".to_owned(),
        );
        let mut lapsed = data.clone();
        lapsed.insert(EXPIRES_KEY.to_owned(), (now - 1).to_string());
        let mut malformed = data.clone();
        malformed.insert(CHALLENGE_KEY.to_owned(), "not a challenge".to_owned());
        let mut answered = pending.clone();
        answered.state = PendingState::Answered;

        type Case<'a> = (
            &'a str,
            &'a BTreeMap<String, String>,
            Option<&'a PendingRegistration>,
            u64,
        );
        let cases: [Case<'_>; 9] = [
            ("registration", &other_registration, Some(&pending), now),
            ("expired", &lapsed, Some(&pending), now),
            ("token", &other_token, Some(&pending), now),
            ("origin", &other_origin, Some(&pending), now),
            ("malformed", &malformed, Some(&pending), now),
            ("no_pending", &data, None, now),
            ("not_pending", &data, Some(&answered), now),
            ("expired", &data, Some(&pending), now + 60_000),
            ("expired", &data, Some(&pending), now + 600_000),
        ];
        for (reason, data, record, at) in cases {
            let decided = verdict(data, record, at);
            assert_eq!(decided["verdict"], "refused", "{reason}: {decided}");
            assert_eq!(decided["reason"], reason);
            let signed: Value = serde_json::from_str(&sign_with(&input(data, record, at), &empty))
                .expect("an answer");
            assert_eq!(signed["ok"], false, "{reason}: {signed}");
            assert_eq!(
                signed["reason"], reason,
                "the refusal is decided before the key is looked for"
            );
        }
    }

    /// A message that is not a challenge is none of the receiver's business, and input that is not
    /// the receiver's own shape is refused rather than guessed at.
    #[test]
    fn a_message_that_is_not_a_challenge_is_left_alone_and_unreadable_input_is_refused() {
        let now = now_ms();
        let mut notification = BTreeMap::new();
        notification.insert("notification_id".to_owned(), "abc".to_owned());
        assert_eq!(
            verdict(&notification, Some(&pending(now + 60_000)), now)["verdict"],
            "not_a_challenge"
        );
        assert_eq!(
            verdict(&notification, None, now)["verdict"],
            "not_a_challenge"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&classify("not json")).expect("a verdict")["reason"],
            "input"
        );
    }

    /// A device whose clock is outside the window a gateway admits a signature in does not sign,
    /// and says why; a key that is not there is not made up.
    #[test]
    fn a_clock_the_gateway_would_refuse_and_a_missing_key_leave_the_challenge_unanswered() {
        let keys = DeviceKeys::generate().expect("keys");
        let now = now_ms();
        let far_off = now + 10 * 60 * 1000;
        let data = challenge_data_expiring(far_off + 60_000);
        let pending = pending(far_off + 60_000);
        let signed: Value = serde_json::from_str(&sign_with(
            &input(&data, Some(&pending), far_off),
            &store(&keys),
        ))
        .expect("an answer");
        assert_eq!(signed["ok"], false);
        assert_eq!(signed["reason"], "clock");

        let missing: Value = serde_json::from_str(&sign_with(
            &input(&data, Some(&pending), now),
            &OneSecret::new(SecretName::new("nothing/here").expect("a name"), &[]),
        ))
        .expect("an answer");
        assert_eq!(missing["reason"], "key_missing");
    }

    /// A challenge a gateway really sent, recorded from a device run, names the registration its
    /// phone waits for and is answered until the moment the gateway stops taking an answer, and not
    /// after it. What the vectors give a test is the payload; this is the message around it.
    #[test]
    fn a_challenge_a_gateway_really_sent_is_answered_until_it_lapses() {
        let recorded: Value =
            serde_json::from_str(include_str!("../fixtures/push/recorded-challenge.json"))
                .expect("a recording");
        let data: BTreeMap<String, String> =
            serde_json::from_value(recorded["message"]["data"].clone()).expect("the data");
        let expires: u64 = data[EXPIRES_KEY].parse().expect("a time");
        let pending: PendingRegistration = serde_json::from_value(serde_json::json!({
            "registration_id": data[REGISTRATION_KEY],
            "token_digest": data[TOKEN_DIGEST_KEY],
            "gateway_origin": data[ORIGIN_KEY],
            "platform": "android",
            "deadline_ms": expires + 120_000,
            "state": "pending",
        }))
        .expect("the record that waits for it");

        let before = verdict(&data, Some(&pending), expires - 1);
        assert_eq!(before["verdict"], "answer", "{before}");
        assert_eq!(
            before["url"],
            format!("{}{REGISTER_ROUTE}", data[ORIGIN_KEY]),
            "the answer goes to the gateway that sent the challenge"
        );
        let at = verdict(&data, Some(&pending), expires);
        assert_eq!(at["verdict"], "refused", "{at}");
        assert_eq!(at["reason"], "expired");
    }
}
