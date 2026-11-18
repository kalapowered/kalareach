//! A request's parameters print that they exist and nothing else.
//!
//! The client builds a parameter value before it knows which method the value belongs to, so no
//! rule that depends on the method can decide what a log line may show. One rule covers every
//! value: it prints `ParamsValue(redacted)`, with no length, no digest and no tag.

use std::fmt::Debug;

use kr_cbor::CanonicalValue;
use kr_protocol::delivery::{DeliveryDestinationSecretSetParams, DestinationSecret, SecretText};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, ParamsValue, Request};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::ids::{ActionId, ActionWindowId, EnvironmentId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable, Uuid};
use serde::Serialize;

/// A value no real credential or sentence has, so finding any part of it in an output is a leak.
const SENTINEL: &str = "kr-test-secret-0123456789-abcdefghij";

#[derive(Serialize)]
struct Carrier<'a> {
    key: &'a str,
}

fn printed(value: &impl Debug) -> String {
    format!("{value:?}")
}

/// Asserts that a printed form holds no part of the sentinel, in windows of eight bytes from the
/// start, the middle and the end, and none of the numbers a size or a digest would add.
fn assert_nothing_of_the_value(text: &str) {
    for window in [
        &SENTINEL[..8],
        &SENTINEL[SENTINEL.len() / 2..SENTINEL.len() / 2 + 8],
        &SENTINEL[SENTINEL.len() - 8..],
    ] {
        assert!(!text.contains(window), "the form {text:?} holds {window:?}");
    }
    assert!(!text.contains("bytes"), "the form {text:?} gives a length");
    assert!(!text.contains("sha256"), "the form {text:?} gives a digest");
}

fn mutation(params: ParamsValue) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(7),
        method: Method::DeliveryDestinationSecretSet.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(Uuid::from_bytes([9; 16])),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("window-1".to_owned()).expect("a window"),
        requested_ttl_ms: DurationMs::new(120_000),
        params,
    }
}

fn secret_params() -> DeliveryDestinationSecretSetParams {
    DeliveryDestinationSecretSetParams {
        destination_id: "ops".to_owned(),
        secret: DestinationSecret::Telegram {
            bot_token: SecretText::new(SENTINEL).expect("a credential"),
        },
    }
}

#[test]
fn a_params_value_prints_neither_a_digest_nor_a_length_nor_a_tag() {
    // Built before encoding, by each of the three constructors the client can use.
    let canonical = kr_cbor::to_canonical_value(&Carrier { key: SENTINEL }).expect("a value");
    let built = [
        ParamsValue::new(canonical.clone()),
        ParamsValue::from_typed(&Carrier { key: SENTINEL }).expect("a value"),
        ParamsValue::from(canonical),
        ParamsValue::from_typed(&secret_params()).expect("the delivery secret's params"),
        ParamsValue::from(CanonicalValue::Text(SENTINEL.to_owned())),
        ParamsValue::empty(),
    ];
    for value in &built {
        let text = printed(value);
        assert_eq!(text, "ParamsValue(redacted)");
        assert_nothing_of_the_value(&text);
    }

    // Decoded from a control frame, as the host receives it, in both request shapes.
    let codec = FrameCodec::new(StreamKind::Control);
    let params = ParamsValue::from_typed(&secret_params()).expect("the delivery secret's params");
    let frames = [
        ControlFrame::Mutation(Box::new(mutation(params.clone()))),
        ControlFrame::Request(Request {
            request_id: RequestId::new(8),
            method: Method::DeliveryDestinationSecretSet.into(),
            method_version: MethodVersion::V1,
            params,
        }),
    ];
    for frame in frames {
        let bytes = codec.encode_message(&frame).expect("the frame encodes");
        let (decoded, _) = codec
            .decode_message::<ControlFrame>(&bytes)
            .expect("the frame decodes");
        let text = printed(&decoded);
        assert!(
            text.contains("ParamsValue(redacted)"),
            "the envelope's own form shows the redacted value: {text}"
        );
        assert_nothing_of_the_value(&text);
    }

    // A request whose parameters do not read as the method's schema: the refusal never prints
    // them, in either form.
    let wrong_shape =
        ParamsValue::from_typed(&Carrier { key: SENTINEL }).expect("a value of the wrong shape");
    let refusal = wrong_shape
        .to_typed::<DeliveryDestinationSecretSetParams>()
        .expect_err("the wrong shape is refused");
    assert_nothing_of_the_value(&printed(&refusal));
    assert_nothing_of_the_value(&refusal.to_string());
    assert_nothing_of_the_value(&printed(&mutation(wrong_shape)));
}
