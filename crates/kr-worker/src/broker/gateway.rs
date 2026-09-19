//! The gateway core: the trusted core-declarative forwarding path, the closed rich method table,
//! namespaced request identifiers and the reverse remote procedure call.
//!
//! Section 11 draws the line this module keeps. A native terminal reaches its upstream through a
//! path that **core code alone** interprets: the connector's qualified declarative table says how
//! its protocol frames, which member of a frame carries the request identifier, which carries the
//! method, and what each method does. Nothing on that path calls a component, which is why a
//! component fault cannot stall it.
//!
//! Four rules follow, and this module is where each of them lives.
//!
//! * **Only an authenticated worker-launched native connection uses the path.** A network client
//!   or a plugin cannot label itself native to escape the rich allowlist:
//!   [`Gateway::open_native`] takes the process identity and the credential of a launch this host
//!   made, and nothing else opens a native connection.
//! * **Unclassified is mutating, and it suspends rich mutations.** A method the table does not
//!   list is forwarded exactly as it is, and the binding's rich mutations are suspended until it
//!   is reconciled, because the host does not know what the request did.
//! * **The rich table is closed.** An unknown rich mutation is rejected rather than guessed at.
//! * **Both mutators go through the gateway.** The native terminal and the rich client both
//!   arrive here, an upstream identifier keeps its JSON type as well as its value, and a
//!   resolution is fanned out to every attached observer.

use std::collections::BTreeMap;

use kr_protocol::broker::ActionProvenance;
use kr_protocol::gateway::{
    DeclarativeTable, DownstreamRequestId, NativeClassification, ReverseExecutionSite,
    ReverseOperation, RichMethodEntry, RichMethodTable,
};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ApplicationInstanceId, EnvironmentId, GatewayConnectionId, MAX_OPAQUE_ID_LEN, UpstreamMethod,
    UpstreamRequestId,
};

use crate::broker::error::{BrokerError, Result};

/// Maximum bytes of one native frame the core will read.
///
/// The same bound as a source frame: a frame is one upstream message, and anything larger is a
/// stream that this path does not interpret.
pub const MAX_NATIVE_FRAME_BYTES: usize = 1024 * 1024;

/// How a connection reached the gateway.
///
/// The distinction is the one section 11 makes: the broad native-control grant belongs to a
/// terminal this host launched and authenticated, and nothing else can claim it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionOrigin {
    /// A native terminal this worker launched, authenticated by its launch binding.
    WorkerLaunchedNative,
    /// A rich client: a paired device, a local caller or a workflow.
    RichClient,
    /// A component acting through the plugin host.
    Component,
}

impl ConnectionOrigin {
    /// Returns true when this origin may use the qualified opaque forwarding path.
    #[must_use]
    pub const fn may_forward_natively(self) -> bool {
        matches!(self, Self::WorkerLaunchedNative)
    }

    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerLaunchedNative => "worker_launched_native",
            Self::RichClient => "rich_client",
            Self::Component => "component",
        }
    }
}

impl std::fmt::Display for ConnectionOrigin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One connection into the gateway.
#[derive(Clone, Debug)]
pub struct Connection {
    /// The connection, which namespaces every downstream identifier it produces.
    pub connection: GatewayConnectionId,
    /// The instance it speaks to.
    pub application_instance_id: ApplicationInstanceId,
    /// How it reached the gateway.
    pub origin: ConnectionOrigin,
    /// The process on the other end, for a native connection.
    pub process: Option<ProcessStartIdentity>,
    /// The qualified declarative table the core interprets this connection's frames with.
    pub table: DeclarativeTable,
    /// The closed rich method table for this connection's upstream version.
    pub rich: RichMethodTable,
}

/// What the core made of one native frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forwarded {
    /// The namespaced identifier this frame's request is known by, when it carried one.
    pub request: Option<DownstreamRequestId>,
    /// The upstream method the frame named.
    pub method: UpstreamMethod,
    /// How the table classified it, and whether the table said so.
    pub classification: NativeClassification,
    /// True when this frame suspends rich mutations until the binding is reconciled.
    pub suspends_rich_mutations: bool,
    /// True when the upstream expects a response, so the broker records a pending resource.
    pub expects_response: bool,
}

/// A rich invocation the gateway admitted, with what it will be recorded as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RichInvocation {
    /// The upstream method.
    pub method: UpstreamMethod,
    /// Its entry in the closed table.
    pub entry: RichMethodEntry,
    /// The namespaced identifier the gateway will use.
    pub request: DownstreamRequestId,
}

/// The answer one admitted decision becomes on the wire.
///
/// It is prepared by the core, from the connection's own qualified table, rather than left to
/// whatever writes it. Two things follow. The namespaced identifier travels with the bytes, so the
/// writer cannot answer a resource other than the one that was admitted; and the frame is fixed at
/// admission, so the exclusive admission and the bytes it authorises are one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedResponse {
    /// The namespaced identifier the answer resolves, which names the connection it goes out on.
    pub request: DownstreamRequestId,
    /// The upstream's own identifier for the request, as it wrote it.
    pub upstream_request_id: UpstreamRequestId,
    /// The method the original request named.
    pub method: UpstreamMethod,
    /// The decision, one of the ones the request offered.
    pub option_id: String,
    /// The response frame, built from the table's own member names.
    pub frame: Vec<u8>,
}

/// One reverse request the upstream asked this host to perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseRequest {
    /// The namespaced identifier to answer on.
    pub request: DownstreamRequestId,
    /// What the upstream asked for.
    pub operation: ReverseOperation,
    /// Where it runs. There is one correct answer and the gateway supplies it.
    pub site: ReverseExecutionSite,
    /// How the answer's provenance will be recorded.
    pub provenance: ActionProvenance,
}

/// The gateway's connections and the tables they are interpreted with.
#[derive(Debug, Default)]
pub struct Gateway {
    connections: BTreeMap<GatewayConnectionId, Connection>,
}

impl Gateway {
    /// An empty gateway.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a native connection for a terminal this worker launched.
    ///
    /// The caller has already authenticated the process against its launch binding and the private
    /// exchange; what this refuses is the other half, a caller that asks for a native connection
    /// without one.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when either table does not qualify against the installed
    /// upstream version, and [`BrokerError::PermissionDenied`] when the connection is not one a
    /// worker-launched native terminal made.
    pub fn open_native(
        &mut self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        process: ProcessStartIdentity,
        table: DeclarativeTable,
        rich: RichMethodTable,
        installed_protocol_version: &str,
    ) -> Result<()> {
        table.qualify(installed_protocol_version)?;
        rich.qualify(installed_protocol_version)?;
        self.connections.insert(
            connection,
            Connection {
                connection,
                application_instance_id,
                origin: ConnectionOrigin::WorkerLaunchedNative,
                process: Some(process),
                table,
                rich,
            },
        );
        Ok(())
    }

    /// Opens a connection for a rich client or a component.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when either table does not qualify, and
    /// [`BrokerError::InvalidArgument`] when the caller asks for the native origin here. A native
    /// connection is opened by [`Gateway::open_native`], which requires a process identity.
    pub fn open(
        &mut self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        origin: ConnectionOrigin,
        table: DeclarativeTable,
        rich: RichMethodTable,
        installed_protocol_version: &str,
    ) -> Result<()> {
        if origin.may_forward_natively() {
            return Err(BrokerError::invalid(
                "a native connection is opened with the process identity of the launch it belongs \
                 to; nothing may label itself native",
            ));
        }
        table.qualify(installed_protocol_version)?;
        rich.qualify(installed_protocol_version)?;
        self.connections.insert(
            connection,
            Connection {
                connection,
                application_instance_id,
                origin,
                process: None,
                table,
                rich,
            },
        );
        Ok(())
    }

    /// Closes one connection.
    pub fn close(&mut self, connection: GatewayConnectionId) -> Option<Connection> {
        self.connections.remove(&connection)
    }

    /// Returns one connection.
    #[must_use]
    pub fn connection(&self, connection: GatewayConnectionId) -> Option<&Connection> {
        self.connections.get(&connection)
    }

    /// Returns how one connection's answers are recorded.
    ///
    /// A connection into the gateway reaches the upstream over its own typed protocol, so its
    /// answers are typed results. Terminal input is the other provenance section 12 names, and it
    /// never arrives here: bytes written into a terminal are written by the input path, which
    /// records them as what they are.
    #[must_use]
    pub fn provenance(&self, connection: GatewayConnectionId) -> Option<ActionProvenance> {
        self.connections
            .get(&connection)
            .map(|_| ActionProvenance::UpstreamTypedRpc)
    }

    /// Returns every connection to one instance, so a resolution can be fanned out.
    pub fn observers(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> impl Iterator<Item = &Connection> {
        self.connections
            .values()
            .filter(move |connection| connection.application_instance_id == application_instance_id)
    }

    /// Reads one native frame with the connection's own declarative table.
    ///
    /// No component is called. The table says how the protocol frames and which members carry the
    /// identifier and the method, and this reads them, so a component that is faulted, disabled or
    /// simply slow changes nothing about what happens here.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the connection is not a worker-launched
    /// native one, and [`BrokerError::InvalidArgument`] when the frame is too large or is not a
    /// frame the table describes.
    pub fn forward_native(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
    ) -> Result<Forwarded> {
        let held = self
            .connections
            .get(&connection)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        if !held.origin.may_forward_natively() {
            return Err(BrokerError::denied(format!(
                "a {} connection cannot use the native forwarding path",
                held.origin
            )));
        }
        let body = read_frame(frame)?;
        let method = body
            .get(&held.table.method_field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                BrokerError::invalid(format!(
                    "this frame carries no {} member",
                    held.table.method_field
                ))
            })?;
        let method = UpstreamMethod::new(method)
            .map_err(|error| BrokerError::invalid(format!("upstream method: {error}")))?;
        let classification = held.table.classify(&method);
        let request = match read_identifier(&body, &held.table.request_id_field) {
            Some(upstream) => Some(DownstreamRequestId::new(connection, upstream?)),
            None => None,
        };
        Ok(Forwarded {
            request,
            method: method.clone(),
            classification,
            // An unclassified request is forwarded exactly as it is, and rich mutations wait until
            // the binding is reconciled, because nothing here knows what it did.
            suspends_rich_mutations: classification.suspends_rich_mutations(),
            expects_response: held.table.expects_response(&method),
        })
    }

    /// Reads the identifier a response correlates to.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the frame is not readable or carries no
    /// correlation identifier.
    pub fn correlate_response(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
    ) -> Result<DownstreamRequestId> {
        let held = self
            .connections
            .get(&connection)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        let body = read_frame(frame)?;
        // A request names a method; a response does not. Without this, a second request that
        // happened to carry a live identifier would resolve the resource that identifier names.
        if body.contains_key(&held.table.method_field) {
            return Err(BrokerError::invalid(format!(
                "this frame names a {} member, so it is a request and not a response",
                held.table.method_field
            )));
        }
        // And a response says exactly one thing: it succeeded or it failed. A frame that says
        // neither is not an answer, and one that says both is two answers to one request; neither
        // resolves a pending resource on the strength of a matching identifier alone.
        let succeeded = body.contains_key(&held.table.result_field);
        let failure = body.get(&held.table.error_field);
        if succeeded == failure.is_some() {
            return Err(BrokerError::invalid(format!(
                "a response names exactly one of {} and {}, and this frame names {}",
                held.table.result_field,
                held.table.error_field,
                if succeeded { "both" } else { "neither" }
            )));
        }
        // A failure has to say what failed. A null or empty error member is a frame that resolves
        // a resource while telling a person nothing, which is worse than no answer at all.
        if let Some(error) = failure {
            check_error_payload(error, &held.table.error_field)?;
        }
        let upstream =
            read_identifier(&body, &held.table.response_id_field).ok_or_else(|| {
                BrokerError::invalid(format!(
                    "this response carries no {} member",
                    held.table.response_id_field
                ))
            })??;
        Ok(DownstreamRequestId::new(connection, upstream))
    }

    /// Prepares the answer one decision becomes, in the connection's own frame shape.
    ///
    /// The identifier is written back exactly as the upstream wrote it, with its JSON type: the
    /// string eleven goes back as `"11"` and the number eleven as `11`, because they are two
    /// identifiers and a response to one must not resolve the other.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the connection is unknown, and
    /// [`BrokerError::InvalidArgument`] when the identifier is not one this host can write back.
    pub fn prepare_response(
        &self,
        connection: GatewayConnectionId,
        upstream_request_id: &UpstreamRequestId,
        method: &UpstreamMethod,
        option_id: &str,
    ) -> Result<PreparedResponse> {
        let held = self
            .connections
            .get(&connection)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        let identifier: serde_json::Value = serde_json::from_str(upstream_request_id.as_str())
            .map_err(|error| {
                BrokerError::invalid(format!(
                    "{upstream_request_id} is not an identifier this host can write back: {error}"
                ))
            })?;
        if !matches!(
            identifier,
            serde_json::Value::String(_) | serde_json::Value::Number(_)
        ) {
            return Err(BrokerError::invalid(format!(
                "{upstream_request_id} is not a string or a number, so it is not a request \
                 identifier"
            )));
        }
        let mut frame = serde_json::Map::new();
        frame.insert(held.table.response_id_field.clone(), identifier);
        frame.insert(
            held.table.result_field.clone(),
            serde_json::json!({ "option_id": option_id }),
        );
        let frame = serde_json::to_vec(&serde_json::Value::Object(frame)).map_err(|error| {
            BrokerError::invalid(format!("this answer will not encode: {error}"))
        })?;
        if frame.len() > MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "this answer is {} bytes and a native frame is at most {MAX_NATIVE_FRAME_BYTES}",
                frame.len()
            )));
        }
        Ok(PreparedResponse {
            request: DownstreamRequestId::new(connection, upstream_request_id.clone()),
            upstream_request_id: upstream_request_id.clone(),
            method: method.clone(),
            option_id: option_id.to_owned(),
            frame,
        })
    }

    /// Admits one rich invocation against the closed method table.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Rich`] for a method with no entry or one this build does not
    /// support, and [`BrokerError::PermissionDenied`] when a native connection asks for the rich
    /// path, which has its own grant and its own rules.
    pub fn admit_rich(
        &self,
        connection: GatewayConnectionId,
        method: &UpstreamMethod,
        upstream_request_id: UpstreamRequestId,
    ) -> Result<RichInvocation> {
        let held = self
            .connections
            .get(&connection)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        let entry = held.rich.admit(method)?;
        Ok(RichInvocation {
            method: method.clone(),
            entry: entry.clone(),
            request: DownstreamRequestId::new(connection, upstream_request_id),
        })
    }

    /// Builds the reverse request the upstream asked for, with the site it runs at.
    ///
    /// Section 12: KalaReach executes these "in the agent's host environment with its existing
    /// user identity, not accidentally in the phone or another desktop client's filesystem". The
    /// site is derived from the connection rather than taken from the request, which is what makes
    /// that true rather than hoped for.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the connection is unknown, and
    /// [`BrokerError::PermissionDenied`] when the connection is not the native one that owns the
    /// upstream.
    pub fn reverse_request(
        &self,
        connection: GatewayConnectionId,
        upstream_request_id: UpstreamRequestId,
        operation: ReverseOperation,
        environment_id: EnvironmentId,
        os_user: &str,
    ) -> Result<ReverseRequest> {
        let held = self
            .connections
            .get(&connection)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        if !held.origin.may_forward_natively() {
            return Err(BrokerError::denied(format!(
                "a {} connection does not own an upstream that can ask this host for anything",
                held.origin
            )));
        }
        Ok(ReverseRequest {
            request: DownstreamRequestId::new(connection, upstream_request_id),
            operation,
            site: ReverseExecutionSite {
                environment_id,
                application_instance_id: held.application_instance_id,
                os_user: os_user.to_owned(),
            },
            // An answer this host performed itself and reported over the typed connection is a
            // typed result; it is never screen text.
            provenance: ActionProvenance::UpstreamTypedRpc,
        })
    }
}

/// Reads one JSON number as a JSON-RPC error code, or returns `None` when it is not one.
///
/// A code is valid when the number is finite and its value is a whole number in the signed 64-bit
/// range, whatever the upstream spelled it as: `-32601`, `-32601.0`, `-3.2601e4` and `-0` are one
/// code, and `-32601.5`, `0.5`, a value outside the range, and the infinities and not-a-numbers a
/// lenient parser might produce are not codes at all.
///
/// One limitation is worth naming, because the value is all this host sees. A number that needed
/// more precision than a double has already been rounded by the time it arrives, so
/// `1.00000000000000001` is read as `1`. Distinguishing the two needs the number's own text.
fn error_code(code: &serde_json::Number) -> Option<i64> {
    if let Some(value) = code.as_i64() {
        return Some(value);
    }
    let value = code.as_f64()?;
    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }
    // The bounds are the powers of two either side of the range, because i64::MAX has no exact
    // double and comparing against its rounded form would admit one value too many.
    const LOWEST: f64 = -9_223_372_036_854_775_808.0;
    const PAST_HIGHEST: f64 = 9_223_372_036_854_775_808.0;
    if !(LOWEST..PAST_HIGHEST).contains(&value) {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the value is whole and inside the signed 64-bit range"
    )]
    Some(value as i64)
}

/// Checks that an error member carries an error.
///
/// JSON-RPC 2.0 §5.1: an error is an object with a numeric `code` and a `message` string. A member
/// that is null, empty or shaped differently is not a failure this host can report, and it is not
/// a reason to resolve a pending resource.
fn check_error_payload(error: &serde_json::Value, field: &str) -> Result<()> {
    let object = error.as_object().ok_or_else(|| {
        BrokerError::invalid(format!(
            "{field} is not an object, so it reports no failure"
        ))
    })?;
    if object
        .get("code")
        .and_then(serde_json::Value::as_number)
        .and_then(error_code)
        .is_none()
    {
        return Err(BrokerError::invalid(format!(
            "{field} carries no integer code in the signed 64-bit range, so it reports no failure"
        )));
    }
    if !object
        .get("message")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err(BrokerError::invalid(format!(
            "{field} carries no message, so there is nothing to tell a person"
        )));
    }
    Ok(())
}

/// Reads one JSON member as an upstream request identifier.
///
/// A JSON-RPC identifier is a string or a number, and an upstream identifier never becomes a
/// KalaReach identifier: it is carried rather than converted. What is carried is the member's own
/// JSON form, so the string `"11"` and the number `11` stay two identifiers. Writing both as the
/// text `11` would let a response to one resolve the other's resource.
///
/// The length an upstream may choose is the length of the value, which is bounded here before it
/// is encoded. What encoding costs is `kr_protocol::ids::MAX_UPSTREAM_REQUEST_ID_LEN`'s business,
/// so a quote or a backslash never refuses an identifier a person could have written.
fn read_identifier(
    body: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Option<Result<UpstreamRequestId>> {
    let member = body.get(field)?;
    let text = match member {
        serde_json::Value::String(value) if value.len() > MAX_OPAQUE_ID_LEN => {
            return Some(Err(BrokerError::invalid(format!(
                "{field} is {} bytes and an upstream request identifier is at most \
                 {MAX_OPAQUE_ID_LEN}",
                value.len()
            ))));
        }
        serde_json::Value::String(_) | serde_json::Value::Number(_) => {
            match serde_json::to_string(member) {
                Ok(text) => text,
                Err(error) => {
                    return Some(Err(BrokerError::invalid(format!(
                        "{field} is not a request identifier: {error}"
                    ))));
                }
            }
        }
        _ => {
            return Some(Err(BrokerError::invalid(format!(
                "{field} is not a request identifier"
            ))));
        }
    };
    Some(
        UpstreamRequestId::new(text)
            .map_err(|error| BrokerError::invalid(format!("upstream request identifier: {error}"))),
    )
}

/// Reads one frame into its top-level members.
///
/// Three things this does that `serde_json::from_slice` into a `Value` does not.
///
/// * It bounds the frame before it parses it, in both directions. A response is a frame too, and
///   an unbounded one is an unbounded allocation.
/// * It refuses a frame that is not a top-level object. A table names members, and an array or a
///   bare number has none.
/// * It refuses a frame that names a member twice. `serde_json` keeps the last one and another
///   participant in the same protocol may keep the first, so a frame two readers would disagree
///   about is one this host will not correlate.
fn read_frame(bytes: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>> {
    if bytes.len() > MAX_NATIVE_FRAME_BYTES {
        return Err(BrokerError::invalid(format!(
            "a native frame is at most {MAX_NATIVE_FRAME_BYTES} bytes and this one is {}",
            bytes.len()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::invalid(format!("this frame is not readable: {error}")))?;
    let serde_json::Value::Object(members) = value else {
        return Err(BrokerError::invalid(
            "a frame this table describes is a JSON object",
        ));
    };
    // The parse has already collapsed a repeated member, so the members it produced are compared
    // with the names the bytes actually carry.
    if count_member_names(bytes)? != members.len() {
        return Err(BrokerError::invalid(
            "this frame names a member more than once, and two readers of it could disagree",
        ));
    }
    Ok(members)
}

/// Counts the top-level member names in one JSON object's bytes, repetitions included.
fn count_member_names(bytes: &[u8]) -> Result<usize> {
    let mut deserialiser = serde_json::Deserializer::from_slice(bytes);
    serde::Deserialize::deserialize(&mut deserialiser)
        .map(|counted: MemberNames| counted.0)
        .map_err(|error| BrokerError::invalid(format!("this frame is not readable: {error}")))
}

/// How many top-level members one JSON object has, before repetitions are collapsed.
struct MemberNames(usize);

impl<'de> serde::Deserialize<'de> for MemberNames {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserialiser: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Counter;

        impl<'de> serde::de::Visitor<'de> for Counter {
            type Value = MemberNames;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut members: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut counted = 0;
                while members
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {
                    counted += 1;
                }
                Ok(MemberNames(counted))
            }
        }

        deserialiser.deserialize_map(Counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::broker::ActionProvenance;
    use kr_protocol::gateway::{
        DeclarativeEntry, NativeFraming, NativeMethodClass, RichMethodEntry,
    };
    use kr_protocol::identity::ProcessStartSource;
    use kr_protocol::ids::{MethodTableVersion, PluginId, PublisherId};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{Digest256, Uuid};

    fn instance() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
    }

    fn method(name: &str) -> UpstreamMethod {
        UpstreamMethod::new(name).expect("valid")
    }

    fn table() -> DeclarativeTable {
        DeclarativeTable {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            digest: Digest256::from_bytes([1; 32]),
            framing: NativeFraming::JsonLines,
            request_id_field: "id".to_owned(),
            response_id_field: "id".to_owned(),
            method_field: "method".to_owned(),
            result_field: "result".to_owned(),
            error_field: "error".to_owned(),
            entries: vec![
                DeclarativeEntry {
                    method: method("fs/write_text_file"),
                    class: NativeMethodClass::Mutation,
                    expects_response: true,
                },
                DeclarativeEntry {
                    method: method("session/request_permission"),
                    class: NativeMethodClass::Mutation,
                    expects_response: true,
                },
                DeclarativeEntry {
                    method: method("session/update"),
                    class: NativeMethodClass::Observation,
                    expects_response: false,
                },
            ],
        }
    }

    fn rich() -> RichMethodTable {
        RichMethodTable {
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            entries: vec![
                RichMethodEntry {
                    method: method("session/cancel"),
                    class: NativeMethodClass::Mutation,
                    required_right: ActionRight::AgentCancel,
                    provenance: ActionProvenance::UpstreamTypedRpc,
                },
                RichMethodEntry {
                    method: method("session/set_provider_key"),
                    class: NativeMethodClass::Unsupported,
                    required_right: ActionRight::AgentPrompt,
                    provenance: ActionProvenance::UpstreamTypedRpc,
                },
            ],
        }
    }

    fn native_gateway() -> Gateway {
        let mut gateway = Gateway::new();
        gateway
            .open_native(
                GatewayConnectionId::new(1),
                instance(),
                ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900),
                table(),
                rich(),
                "1",
            )
            .expect("the tables qualify");
        gateway
    }

    #[test]
    fn nothing_but_a_worker_launched_native_connection_forwards() {
        let mut gateway = native_gateway();
        gateway
            .open(
                GatewayConnectionId::new(2),
                instance(),
                ConnectionOrigin::RichClient,
                table(),
                rich(),
                "1",
            )
            .expect("a rich client connects");
        assert!(
            gateway
                .open(
                    GatewayConnectionId::new(3),
                    instance(),
                    ConnectionOrigin::WorkerLaunchedNative,
                    table(),
                    rich(),
                    "1",
                )
                .is_err(),
            "nothing may label itself native"
        );
        let frame = br#"{"id":11,"method":"session/update"}"#;
        gateway
            .forward_native(GatewayConnectionId::new(1), frame)
            .expect("the native connection forwards");
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(2), frame)
                .is_err(),
            "a rich client cannot forward on the native path"
        );
    }

    #[test]
    fn an_unclassified_request_is_forwarded_and_suspends_rich_mutations() {
        let gateway = native_gateway();
        let known = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":"11","method":"session/update"}"#,
            )
            .expect("forwarded");
        assert_eq!(known.classification.class, NativeMethodClass::Observation);
        assert!(!known.suspends_rich_mutations);
        assert!(!known.expects_response);

        let unknown = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":12,"method":"vendor/undocumented"}"#,
            )
            .expect("forwarded exactly as it is");
        assert_eq!(unknown.classification.class, NativeMethodClass::Mutation);
        assert!(!unknown.classification.declared);
        assert!(unknown.suspends_rich_mutations);
        assert!(
            unknown.expects_response,
            "a reverse request the table does not describe still becomes a pending resource"
        );
    }

    #[test]
    fn an_upstream_identifier_keeps_its_json_type_and_its_value() {
        let gateway = native_gateway();
        let numeric = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":11,"method":"fs/write_text_file"}"#,
            )
            .expect("forwarded");
        assert_eq!(
            numeric.request.expect("it carried one").upstream.as_str(),
            "11"
        );
        let textual = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":"req-a","method":"fs/write_text_file"}"#,
            )
            .expect("forwarded");
        assert_eq!(
            textual.request.expect("it carried one").upstream.as_str(),
            "\"req-a\"",
            "a string identifier keeps its quotes, so it is not the bare text of the same name"
        );
        // The string "11" and the number 11 are two identifiers, and a host that wrote both as
        // the text 11 would answer one request with the other's response.
        let same_digits = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":"11","method":"fs/write_text_file"}"#,
            )
            .expect("forwarded");
        assert_eq!(
            same_digits
                .request
                .expect("it carried one")
                .upstream
                .as_str(),
            "\"11\""
        );
    }

    #[test]
    fn an_identifier_is_bounded_by_its_value_and_never_by_what_encoding_costs() {
        let gateway = native_gateway();
        // A value at the limit is admitted, however expensive its encoding is: plain text, text
        // that needs a backslash, and text a control character costs six bytes each.
        for value in [
            "a".repeat(MAX_OPAQUE_ID_LEN),
            "\"".repeat(MAX_OPAQUE_ID_LEN),
            "\u{7}".repeat(MAX_OPAQUE_ID_LEN),
            "é".repeat(MAX_OPAQUE_ID_LEN / 2),
        ] {
            let frame = serde_json::json!({ "id": value, "method": "fs/write_text_file" });
            let forwarded = gateway
                .forward_native(
                    GatewayConnectionId::new(1),
                    serde_json::to_vec(&frame).expect("encodes").as_slice(),
                )
                .unwrap_or_else(|error| {
                    panic!("a {}-byte value is admitted: {error}", value.len())
                });
            assert!(forwarded.request.is_some());
        }
        // One byte past it is refused, and refused for its value rather than for its encoding.
        let frame = serde_json::json!({
            "id": "a".repeat(MAX_OPAQUE_ID_LEN + 1),
            "method": "fs/write_text_file",
        });
        assert!(
            gateway
                .forward_native(
                    GatewayConnectionId::new(1),
                    serde_json::to_vec(&frame).expect("encodes").as_slice(),
                )
                .is_err()
        );
    }

    #[test]
    fn two_connections_that_both_say_one_are_two_resources() {
        let mut gateway = native_gateway();
        gateway
            .open_native(
                GatewayConnectionId::new(2),
                instance(),
                ProcessStartIdentity::new(42, ProcessStartSource::MacosProcBsdInfo, 901),
                table(),
                rich(),
                "1",
            )
            .expect("a second native connection");
        let frame = br#"{"id":1,"method":"fs/write_text_file"}"#;
        let first = gateway
            .forward_native(GatewayConnectionId::new(1), frame)
            .expect("forwarded")
            .request
            .expect("it carried one");
        let second = gateway
            .forward_native(GatewayConnectionId::new(2), frame)
            .expect("forwarded")
            .request
            .expect("it carried one");
        assert_ne!(first, second);
        assert_eq!(first.upstream, second.upstream);
    }

    #[test]
    fn the_rich_table_is_closed_and_a_table_is_qualified() {
        let gateway = native_gateway();
        gateway
            .admit_rich(
                GatewayConnectionId::new(1),
                &method("session/cancel"),
                UpstreamRequestId::new("11").expect("valid"),
            )
            .expect("a listed rich method is admitted");
        assert!(
            gateway
                .admit_rich(
                    GatewayConnectionId::new(1),
                    &method("vendor/undocumented"),
                    UpstreamRequestId::new("12").expect("valid"),
                )
                .is_err(),
            "an unknown rich mutation is rejected rather than guessed at"
        );
        assert!(
            gateway
                .admit_rich(
                    GatewayConnectionId::new(1),
                    &method("session/set_provider_key"),
                    UpstreamRequestId::new("13").expect("valid"),
                )
                .is_err(),
            "a method this build lists as unsupported is refused with its own reason"
        );

        let mut other = Gateway::new();
        assert!(
            other
                .open_native(
                    GatewayConnectionId::new(1),
                    instance(),
                    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900),
                    table(),
                    rich(),
                    "2",
                )
                .is_err(),
            "a table pinned to another upstream version does not qualify"
        );
    }

    #[test]
    fn a_reverse_request_runs_in_the_agents_own_environment() {
        let gateway = native_gateway();
        let reverse = gateway
            .reverse_request(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new("11").expect("valid"),
                ReverseOperation::FilesystemWrite,
                EnvironmentId::new(Uuid::from_bytes([1; 16])),
                "ada",
            )
            .expect("the reverse request is built");
        assert_eq!(reverse.site.application_instance_id, instance());
        assert_eq!(reverse.site.os_user, "ada");
        assert_eq!(reverse.provenance, ActionProvenance::UpstreamTypedRpc);
        assert_eq!(reverse.operation.class(), NativeMethodClass::Mutation);
    }

    #[test]
    fn a_response_correlates_to_the_request_it_answers() {
        let gateway = native_gateway();
        let forwarded = gateway
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":11,"method":"fs/write_text_file"}"#,
            )
            .expect("forwarded");
        let correlated = gateway
            .correlate_response(GatewayConnectionId::new(1), br#"{"id":11,"result":{}}"#)
            .expect("correlated");
        assert_eq!(Some(correlated), forwarded.request);
    }

    #[test]
    fn a_frame_two_readers_could_disagree_about_is_refused() {
        let gateway = native_gateway();
        // A repeated member: `serde_json` keeps the last, another reader may keep the first.
        assert!(
            gateway
                .forward_native(
                    GatewayConnectionId::new(1),
                    br#"{"id":11,"method":"session/update","method":"fs/write_text_file"}"#,
                )
                .is_err()
        );
        // A frame that is not an object at all.
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(1), br#"[{"id":11}]"#)
                .is_err()
        );
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(1), b"11")
                .is_err()
        );
        // And a response is bounded the same way a request is.
        let oversized = vec![b'a'; MAX_NATIVE_FRAME_BYTES + 1];
        assert!(
            gateway
                .correlate_response(GatewayConnectionId::new(1), &oversized)
                .is_err()
        );
    }

    #[test]
    fn a_frame_the_table_does_not_describe_is_refused_rather_than_guessed_at() {
        let gateway = native_gateway();
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(1), b"not json at all")
                .is_err()
        );
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(1), br#"{"id":11}"#)
                .is_err(),
            "a frame with no method member names no method"
        );
        let oversized = vec![b'a'; MAX_NATIVE_FRAME_BYTES + 1];
        assert!(
            gateway
                .forward_native(GatewayConnectionId::new(1), &oversized)
                .is_err()
        );
    }

    /// D-074: a code is valid when the number is finite and its value is a whole number in the
    /// signed 64-bit range, whatever the upstream spelled it as. Every example the reviews of this
    /// path raised is listed here with the verdict the rule gives it.
    #[test]
    fn an_error_code_is_a_whole_number_in_range_however_it_is_spelled() {
        for (spelling, expected) in [
            ("-32601", Some(-32601)),
            ("-32601.0", Some(-32601)),
            ("-3.2601e4", Some(-32601)),
            ("-0", Some(0)),
            ("0", Some(0)),
            ("9223372036854775807", Some(i64::MAX)),
            ("-9223372036854775808", Some(i64::MIN)),
            // Whole, and outside the range a code is read into.
            ("9223372036854775808", None),
            ("1e30", None),
            // Not whole.
            ("-32601.5", None),
            ("0.5", None),
            ("-3.5", None),
            // Rounded by the parser before this host sees it. The rule reads the value it was
            // given, and the limitation is named where the rule is: each of these is one unit of
            // last place away from a value that is in range and whole.
            ("1.00000000000000001", Some(1)),
            ("1e-400", Some(0)),
            ("-9223372036854775809", Some(i64::MIN)),
        ] {
            let number: serde_json::Number =
                serde_json::from_str(spelling).expect("the example is a JSON number");
            assert_eq!(
                error_code(&number),
                expected,
                "{spelling} is {}",
                if expected.is_some() {
                    "a code"
                } else {
                    "not a code"
                }
            );
        }
        // A lenient producer's infinities and not-a-numbers are not codes either. `serde_json`
        // will not parse them, so they are built rather than read.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(serde_json::Number::from_f64(value).is_none());
        }
    }

    #[test]
    fn a_resolution_fans_out_to_every_connection_of_the_instance() {
        let mut gateway = native_gateway();
        gateway
            .open(
                GatewayConnectionId::new(2),
                instance(),
                ConnectionOrigin::RichClient,
                table(),
                rich(),
                "1",
            )
            .expect("a rich client connects");
        gateway
            .open(
                GatewayConnectionId::new(3),
                ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
                ConnectionOrigin::RichClient,
                table(),
                rich(),
                "1",
            )
            .expect("a client of another instance connects");
        let observers: Vec<GatewayConnectionId> = gateway
            .observers(instance())
            .map(|connection| connection.connection)
            .collect();
        assert_eq!(
            observers,
            vec![GatewayConnectionId::new(1), GatewayConnectionId::new(2)],
            "every authorised observer of this instance, and nobody else's"
        );
    }
}
