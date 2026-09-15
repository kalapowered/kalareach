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
use crate::ids::{
    ActionId, ActionWindowId, AgentBindingRevision, ApplicationInstanceId, EnvironmentId,
    EventSequence, EventType, GrantId, RequestId, SessionEpoch, SessionId, StreamId,
};
use crate::method::{MethodName, MethodVersion};
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
    pub fn to_typed<T: DeserializeOwned>(&self) -> Result<T, kr_cbor::CborError> {
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
        json_schema!({
            "description": "An opaque KR-CBOR-1 value. Its shape is defined by the method's own closed schema. The JSON rendering is diagnostic: byte strings appear as unpadded base64url and cannot be told apart from text."
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
