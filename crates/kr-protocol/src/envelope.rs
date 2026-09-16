//! Request, response and notification envelopes.
//!
//! Section 23: a request carries `request_id`, `method`, `method_version` and `params`. A mutation
//! additionally carries `action_id`, a grant reference, the target identity, the subject
//! preconditions, `action_window_id` and `requested_ttl_ms`. A response correlates `request_id`;
//! the durable operation identity is `action_id`. A notification carries a stream identifier, a
//! sequence, an event type and a payload.
//!
//! `params` and `expected` are opaque canonical values here. The host validates the envelope,
//! resolves the method in the registry and only then parses the method's own closed parameter
//! schema. That ordering is what lets an unknown method return a correlated error instead of
//! failing to parse.

use kr_cbor::{CanonicalMap, CanonicalValue, Integer};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ProtocolError;
use crate::hello::ActionWindow;
use crate::ids::{
    ActionId, ActionWindowId, AgentBindingRevision, ApplicationInstanceId, EnvironmentId,
    EventSequence, EventType, GrantId, RequestId, SessionEpoch, SessionId, StreamId,
};
use crate::method::{MethodName, MethodVersion};
use crate::receipt::ReceiptResponse;
use crate::scalars::{DurationMs, Nullable, to_base64url};

/// An opaque KR-CBOR-1 value carried in an envelope.
///
/// On the wire this is exactly the value the sender encoded, so a digest taken over the envelope
/// covers the parameters byte for byte.
///
/// The JSON representation is diagnostic. Byte strings render as unpadded base64url and integers
/// render as decimal strings, matching the rule for named counters, so no value loses precision on
/// the way out. Reading JSON back cannot tell which strings were byte strings or integers, which
/// is why nothing is ever signed from JSON: signing input is built from the canonical bytes, never
/// from a re-serialised diagnostic document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamsValue(CanonicalValue);

impl ParamsValue {
    /// Wraps a validated canonical value.
    #[must_use]
    pub const fn new(value: CanonicalValue) -> Self {
        Self(value)
    }

    /// An empty parameter map.
    #[must_use]
    pub fn empty() -> Self {
        Self(CanonicalValue::Map(CanonicalMap::new()))
    }

    /// Returns the underlying canonical value.
    #[must_use]
    pub const fn as_value(&self) -> &CanonicalValue {
        &self.0
    }

    /// Consumes the wrapper and returns the canonical value.
    #[must_use]
    pub fn into_value(self) -> CanonicalValue {
        self.0
    }

    /// Serialises typed parameters into an opaque value.
    ///
    /// # Errors
    ///
    /// Returns an error when the value cannot be represented in KR-CBOR-1.
    pub fn from_typed<T: Serialize + ?Sized>(value: &T) -> Result<Self, kr_cbor::CborError> {
        kr_cbor::to_canonical_value(value).map(Self)
    }

    /// Parses the opaque value into a method's closed parameter schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the value does not match the target schema.
    pub fn to_typed<T: DeserializeOwned + Serialize>(&self) -> Result<T, kr_cbor::CborError> {
        kr_cbor::from_canonical_value(&self.0)
    }
}

impl From<CanonicalValue> for ParamsValue {
    fn from(value: CanonicalValue) -> Self {
        Self(value)
    }
}

impl Serialize for ParamsValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_canonical(&self.0, serializer)
    }
}

fn serialize_canonical<S: Serializer>(
    value: &CanonicalValue,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let human_readable = serializer.is_human_readable();
    match value {
        CanonicalValue::Null => serializer.serialize_unit(),
        CanonicalValue::Bool(value) => serializer.serialize_bool(*value),
        CanonicalValue::Integer(value) => serialize_integer(*value, human_readable, serializer),
        CanonicalValue::Bytes(bytes) => {
            if human_readable {
                serializer.serialize_str(&to_base64url(bytes))
            } else {
                serializer.serialize_bytes(bytes)
            }
        }
        CanonicalValue::Text(text) => serializer.serialize_str(text),
        CanonicalValue::Array(items) => {
            use serde::ser::SerializeSeq as _;
            let mut sequence = serializer.serialize_seq(Some(items.len()))?;
            for item in items {
                sequence.serialize_element(&ParamsValue(item.clone()))?;
            }
            sequence.end()
        }
        CanonicalValue::Map(map) => {
            use serde::ser::SerializeMap as _;
            let mut entries = serializer.serialize_map(Some(map.len()))?;
            for (key, value) in map.entries() {
                entries.serialize_entry(key, &ParamsValue(value.clone()))?;
            }
            entries.end()
        }
    }
}

fn serialize_integer<S: Serializer>(
    value: Integer,
    human_readable: bool,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if human_readable {
        // A JSON number cannot carry every value in the profile's range exactly, and a reader
        // cannot tell which integers in an opaque value were meant to be counters. Rendering them
        // all as decimal strings keeps every value exact, the same rule named counters follow.
        return serializer.serialize_str(&value.get().to_string());
    }
    if let Some(unsigned) = value.as_u64() {
        serializer.serialize_u64(unsigned)
    } else if let Some(signed) = value.as_i64() {
        serializer.serialize_i64(signed)
    } else {
        serializer.serialize_i128(value.get())
    }
}

impl<'de> Deserialize<'de> for ParamsValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ParamsVisitor).map(Self)
    }
}

struct ParamsVisitor;

impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a KR-CBOR-1 value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(ParamsVisitor)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Bool(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Integer(Integer::from(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Integer(Integer::from(value)))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<Self::Value, E> {
        CanonicalValue::integer(value).map_err(E::custom)
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
        let value = i128::try_from(value).map_err(E::custom)?;
        CanonicalValue::integer(value).map_err(E::custom)
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Self::Value, E> {
        Err(E::custom("floats are forbidden in KR-CBOR-1"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(CanonicalValue::text(value))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(CanonicalValue::bytes(value))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Bytes(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = sequence.next_element::<ParamsValue>()? {
            items.push(item.0);
        }
        Ok(CanonicalValue::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
        let mut map = CanonicalMap::new();
        while let Some((key, value)) = entries.next_entry::<String, ParamsValue>()? {
            map.insert(key, value.0).map_err(de::Error::custom)?;
        }
        Ok(CanonicalValue::Map(map))
    }
}

impl JsonSchema for ParamsValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ParamsValue".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::ParamsValue".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // The value can be anything the profile permits: a map, an array, text, an integer, a
        // boolean or null. A schema that only carries a description is read as an object by the
        // TypeScript generator, which would reject a valid array or scalar result, so the type is
        // stated outright.
        json_schema!({
            "description": "An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings and integers appear as strings and cannot be told apart from text.",
            "tsType": "unknown"
        })
    }
}

/// The exact subject a mutation names.
///
/// A mutation states the environment, and where it applies the session and epoch, the foreground
/// application instance and the agent binding revision. Narrower targets leave the fields that do
/// not apply explicitly null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionTarget {
    /// The environment that owns the effect.
    pub environment_id: EnvironmentId,
    /// The session, when the effect has one.
    pub session_id: Nullable<SessionId>,
    /// The session epoch, present exactly when `session_id` is.
    pub session_epoch: Nullable<SessionEpoch>,
    /// The foreground application instance, when the effect has one.
    pub application_instance_id: Nullable<ApplicationInstanceId>,
    /// The agent binding revision, present exactly when `application_instance_id` is.
    pub agent_binding_revision: Nullable<AgentBindingRevision>,
}

/// A target whose fields do not agree with each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// The session epoch is present without a session, or the other way round.
    SessionEpochMismatch,
    /// An application instance was named without a session.
    ApplicationWithoutSession,
    /// The agent binding revision is present without an application instance, or the other way
    /// round.
    BindingRevisionMismatch,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::SessionEpochMismatch => "session_id and session_epoch must both be present",
            Self::ApplicationWithoutSession => "application_instance_id requires a session_id",
            Self::BindingRevisionMismatch => {
                "application_instance_id and agent_binding_revision must both be present"
            }
        })
    }
}

impl std::error::Error for TargetError {}

impl ActionTarget {
    /// A target that names only an environment.
    #[must_use]
    pub const fn environment(environment_id: EnvironmentId) -> Self {
        Self {
            environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Checks that the named fields agree with each other.
    ///
    /// # Errors
    ///
    /// Returns the first disagreement.
    pub fn validate(&self) -> Result<(), TargetError> {
        if self.session_id.is_present() != self.session_epoch.is_present() {
            return Err(TargetError::SessionEpochMismatch);
        }
        if self.application_instance_id.is_present() && !self.session_id.is_present() {
            return Err(TargetError::ApplicationWithoutSession);
        }
        if self.application_instance_id.is_present() != self.agent_binding_revision.is_present() {
            return Err(TargetError::BindingRevisionMismatch);
        }
        Ok(())
    }
}

/// A read request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Correlates the response. Unique for the lifetime of one connection.
    pub request_id: RequestId,
    /// The method name. A name that is not in the registry is denied.
    pub method: MethodName,
    /// The method version. Schemas are closed for the negotiated version.
    pub method_version: MethodVersion,
    /// The method's parameters.
    pub params: ParamsValue,
}

/// A mutation request.
///
/// The payload digest covers the method and version, the actor and grant, the complete target, the
/// preconditions, the action identifier, the freshness window and time to live, and the
/// parameters. Replacing the window changes the digest, so it is never an automatic retry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutationRequest {
    /// Correlates the response. Durable operation identity is `action_id`, not this.
    pub request_id: RequestId,
    /// The method name.
    pub method: MethodName,
    /// The method version.
    pub method_version: MethodVersion,
    /// The durable operation identity, a cryptographically generated UUIDv4.
    pub action_id: ActionId,
    /// The grant this mutation is claimed under. A local caller's host-stamped context leaves this
    /// null and the host resolves its own owner authority.
    pub grant_id: Nullable<GrantId>,
    /// The exact subject.
    pub target: ActionTarget,
    /// The subject preconditions this mutation requires.
    pub expected: ParamsValue,
    /// The host-issued action window this first admission is bound to.
    pub action_window_id: ActionWindowId,
    /// The requested lifetime. The host derives the accepted deadline and may shorten it. This is
    /// a duration, not permission to refresh a replay.
    pub requested_ttl_ms: DurationMs,
    /// The method's parameters.
    pub params: ParamsValue,
}

/// The result of a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The request succeeded, with the method's result.
    Ok(ParamsValue),
    /// The request failed.
    Error(ProtocolError),
}

/// A response correlated to one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// The request this response answers.
    pub request_id: RequestId,
    /// The result.
    pub outcome: Outcome,
}

/// One event on a subscribed stream.
///
/// Stream sequences are application sequence numbers. Transport streams do not replace them, and a
/// client that falls behind receives `RESYNC_REQUIRED` rather than holding the read loop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    /// Which stream the event belongs to.
    pub stream_id: StreamId,
    /// The position of this event in that stream.
    pub sequence: EventSequence,
    /// What happened.
    pub event_type: EventType,
    /// The event payload.
    pub payload: ParamsValue,
}

/// What the host sends on an authorised control stream outside a response.
///
/// The control stream carries ordinary [`Notification`] events once the connection is authorised.
/// These two messages are the connection's own, not an application event: the freshness resource
/// and the transport's liveness belong to the connection rather than to any session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlEvent {
    /// The host renewed this connection's action window.
    ///
    /// Section 9: windows are short-lived freshness resources, renewed explicitly on a live
    /// authorised connection. The host renews on its own schedule, so a client never has to ask
    /// for one and never has to guess how long it has.
    ActionWindowRenewed(ActionWindow),
    /// A keepalive. It carries nothing; its arrival is the whole message.
    ///
    /// Section 23 puts the keepalive at ten seconds while active and the inactivity threshold at
    /// 30. The transport's own keepalive covers a network connection; this one also covers a local
    /// socket, which carries the same typed frames and has no equivalent underneath it.
    Keepalive,
}

/// One frame on an authorised control stream.
///
/// The union is closed. A receiver that cannot name the variant rejects the frame rather than
/// guessing, which is what keeps an unknown method a correlated error instead of a parse failure.
///
/// Both transports carry these frames: section 23 says local Unix sockets and Windows named pipes
/// carry the same typed frames with local peer authentication. What differs is how the connection
/// is authenticated before the first frame, not what travels afterwards. One union rather than two
/// is what makes that true rather than merely stated: a request, a mutation, a response, a receipt
/// and a notification are the same types on a Unix socket as on a QUIC stream, and a host that
/// answered them differently would have two wire contracts to keep in step.
///
/// Some variants only ever travel between host processes on a local endpoint: the local opening
/// frames, the worker startup handshake, the generation and revision exchange, and a forwarded
/// mutation. They are still part of this union, because a closed union is what makes a frame that
/// does not belong on the ingress it arrived on a *refusal* rather than a parse failure. Each
/// endpoint refuses the variants its role does not serve, which is an admission rule the host
/// applies rather than a shape the wire hides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlFrame {
    /// A local client's opening frame.
    Hello(crate::local::LocalHello),
    /// The host's answer to a local opening frame.
    HelloAck(Box<crate::local::LocalHelloAck>),
    /// A read request.
    Request(Request),
    /// A mutation request.
    Mutation(Box<MutationRequest>),
    /// A response correlated to a request.
    Response(Response),
    /// The receipt of a mutation.
    Receipt(Box<ReceiptResponse>),
    /// An event on a subscribed stream.
    Notification(Notification),
    /// An event about the connection itself.
    Event(ControlEvent),
    /// A worker's startup claim, presented on the controller's rendezvous endpoint.
    Rendezvous(crate::worker::WorkerRendezvous),
    /// What the controller tells an authenticated worker to become.
    LaunchSpec(Box<crate::worker::WorkerLaunchSpec>),
    /// A worker reporting that its root shell is running.
    WorkerReady(crate::worker::WorkerReady),
    /// A worker reporting that it could not start.
    WorkerFailed(ProtocolError),
    /// A fresh challenge to the worker behind an endpoint.
    VerifyChallenge(crate::worker::WorkerVerifyChallenge),
    /// The worker's signed answer.
    VerifyProof(crate::worker::WorkerVerifyProof),
    /// A worker's challenge to a controller that wants to speak for a generation.
    GenerationChallenge(crate::worker::GenerationChallenge),
    /// What one of the control daemon's connections to a worker is for, declared before it
    /// presents a generation token.
    ControllerRole(crate::local::ControllerConnectionRole),
    /// A controller's signed generation token.
    GenerationToken(Box<crate::worker::ControllerGenerationToken>),
    /// The worker's acceptance of a generation.
    GenerationAccepted(crate::worker::GenerationAccepted),
    /// The authority revision the controller now holds.
    AuthorityRevision(crate::worker::AuthorityRevisionNotice),
    /// The worker's acknowledgement of an authority revision.
    AuthorityRevisionAck(crate::worker::AuthorityRevisionAck),
    /// A mutation the control daemon admitted, passed to the worker that owns its subject.
    Forwarded(Box<crate::local::ForwardedMutation>),
    /// A read the control daemon admitted for a caller it authenticated elsewhere.
    ForwardedRead(Box<crate::local::ForwardedRequest>),
    /// A proxy's confirmation that a caller has received an action's acceptance.
    ///
    /// A close is accepted before anything is signalled, because the requester is often a command
    /// inside the process group the closure will stop. When the acceptance travels through a proxy,
    /// the worker learns it has arrived here rather than assuming its own write was the end of the
    /// journey.
    AcceptanceDelivered(ActionId),
}
