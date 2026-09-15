//! The local IPC handshake and the control-stream message union.
//!
//! Local sockets and named pipes carry the same typed frames as the network transport. What
//! differs is authentication: there is no paired device and no endpoint proof. The host
//! authenticates the operating-system caller through peer credentials and then stamps the
//! freshness context itself, so a local caller never pretends to be a paired network device and
//! never supplies its own action window.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::{MutationRequest, Notification, Request, Response};
use crate::hello::{ProtocolVersion, ReceiveLimits};
use crate::identity::BootIdentity;
use crate::ids::{ActionWindowId, BuildId, CapabilityId, ConnectionId, EnvironmentId};
use crate::receipt::ReceiptResponse;
use crate::scalars::{CanonicalSet, Nullable, TimestampMs, U64};

/// Which host process a local endpoint belongs to.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocalRole {
    /// The per-environment control daemon.
    Controller,
    /// One session worker's private endpoint.
    Worker,
    /// The controller's owner-only rendezvous socket, which accepts only a worker's startup
    /// handshake.
    Rendezvous,
}

impl LocalRole {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Worker => "worker",
            Self::Rendezvous => "rendezvous",
        }
    }
}

/// What kind of client opened a local connection.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocalClientKind {
    /// The `kr` command-line client.
    Cli,
    /// The control daemon connecting to a worker.
    Controller,
    /// A worker connecting to the control daemon.
    Worker,
}

/// The authenticated operating-system caller.
///
/// The host stamps this from the socket's peer credentials. It proves an OS identity, not human
/// intent: rights-enlarging owner operations still require the owner-confirmation contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalPeer {
    /// The caller's user identifier.
    pub uid: U64,
    /// The caller's primary group identifier.
    pub gid: U64,
    /// The caller's process identifier, where the platform reports one. A hint for diagnostics,
    /// never authority on its own.
    pub pid: Nullable<U64>,
}

/// The first frame a local client sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalHello {
    /// Every protocol version the client offers.
    pub offered_versions: Vec<ProtocolVersion>,
    /// The client build.
    pub build_id: BuildId,
    /// What kind of client this is. It says how to frame the conversation; it confers nothing.
    pub client: LocalClientKind,
    /// The capabilities the client offers.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The client's own receive limits.
    pub max_receive: ReceiveLimits,
}

/// The first frame the host sends back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalHelloAck {
    /// The version both sides will use.
    pub selected_version: ProtocolVersion,
    /// Which host process answered.
    pub role: LocalRole,
    /// The connection identity the host assigned.
    pub connection_id: ConnectionId,
    /// The environment this endpoint belongs to.
    pub environment_id: EnvironmentId,
    /// The boot the host is running.
    pub boot_identity: BootIdentity,
    /// The caller the host authenticated.
    pub peer: LocalPeer,
    /// The freshness window the host stamped for this connection.
    pub action_window_id: ActionWindowId,
    /// When that window expires by the wall clock, for display. Expiry itself is decided on the
    /// host's suspend-aware continuous clock, so a wall clock that moves cannot extend it.
    pub action_window_expires_at_ms: TimestampMs,
    /// The capabilities both sides will use.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The limits both sides will use.
    pub max_receive: ReceiveLimits,
}

/// One message on a local control stream.
///
/// The union is closed. A receiver that cannot name the variant rejects the frame rather than
/// guessing, which is what keeps an unknown method a correlated error instead of a parse failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlMessage {
    /// A client's opening frame.
    Hello(LocalHello),
    /// The host's answer to the opening frame.
    HelloAck(LocalHelloAck),
    /// A read request.
    Request(Request),
    /// A mutation request.
    Mutation(MutationRequest),
    /// A response correlated to a request.
    Response(Response),
    /// The receipt of a mutation.
    Receipt(ReceiptResponse),
    /// An event on a subscribed stream.
    Notification(Notification),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ParamsValue;
    use crate::ids::RequestId;
    use crate::method::{Method, MethodVersion};

    #[test]
    fn a_control_message_round_trips_through_the_canonical_encoding() {
        let message = ControlMessage::Request(Request {
            request_id: RequestId::new(7),
            method: Method::SessionList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        });
        let bytes = kr_cbor::to_canonical_vec(&message).expect("encodes");
        let decoded: ControlMessage =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, message);
    }
}
