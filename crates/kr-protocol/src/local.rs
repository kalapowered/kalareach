//! The local IPC handshake.
//!
//! Local sockets and named pipes carry the same typed frames as the network transport: one
//! [`crate::envelope::ControlFrame`] union serves both. What differs is authentication. There is no
//! paired device and no endpoint proof, so the host authenticates the operating-system caller
//! through peer credentials and then issues the action window itself. A local caller never
//! pretends to be a paired network device and never supplies its own window.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::MutationRequest;
use crate::hello::{ActionWindow, ProtocolVersion, ReceiveLimits};
use crate::identity::BootIdentity;
use crate::ids::{BuildId, CapabilityId, ConnectionId, EnvironmentId};
use crate::scalars::{CanonicalSet, Nullable, U64};

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
    /// The first action window of this connection.
    ///
    /// It carries a validity *duration*, not a deadline: the authoritative deadline lives on the
    /// host's suspend-aware continuous clock, and the host renews the window on this connection
    /// without being asked. A client schedules its own expectations from the duration and never
    /// computes an expiry the host will honour.
    pub action_window: ActionWindow,
    /// The capabilities both sides will use.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The limits both sides will use.
    pub max_receive: ReceiveLimits,
}

/// A mutation the host admitted for a caller, passed to the component that owns its subject.
///
/// The control daemon owns admission: it authenticates the caller, stamps the freshness window,
/// checks the envelope and derives the accepted deadline. The worker owns the subject. Forwarding
/// carries the caller's mutation to the worker **unchanged**, because the mutation is what the
/// payload digest covers and what the caller will retry with: rewriting any of it would give the
/// worker a different action from the one the caller asked for.
///
/// What travels beside it is what the worker cannot establish for itself: which principal the host
/// verified, and the deadline the host accepted. The worker performs the action under both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardedMutation {
    /// The caller's mutation, exactly as it arrived at the host.
    pub mutation: MutationRequest,
    /// The actor the host verified, with the ingress it arrived on.
    pub actor: crate::actor::ActorEnvelope,
    /// The deadline the host derived at first admission, on the machine's own continuous clock.
    ///
    /// Milliseconds since this boot, from the clock the operating system keeps for the whole
    /// machine: `CLOCK_BOOTTIME` on Linux and `CLOCK_MONOTONIC` on Apple. Two processes on one boot
    /// read the same clock, so this is the same instant on both sides of the socket and nothing has
    /// to guess at what the journey cost.
    ///
    /// Not a wall-clock time and not a process-anchored one. A wall-clock instant would be
    /// comparable and also steppable, which is the one property a deadline cannot have; a
    /// process-anchored instant is not comparable at all. A deadline from a previous boot reads as
    /// long past, because the clock restarts at the boot, so a stale one expires rather than being
    /// honoured.
    pub accepted_deadline_boot_ms: U64,
}

#[cfg(test)]
mod tests {
    use crate::envelope::{ControlFrame, ParamsValue, Request};
    use crate::ids::RequestId;
    use crate::method::{Method, MethodVersion};

    #[test]
    fn a_local_control_frame_round_trips_through_the_canonical_encoding() {
        let frame = ControlFrame::Request(Request {
            request_id: RequestId::new(7),
            method: Method::SessionList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        });
        let bytes = kr_cbor::to_canonical_vec(&frame).expect("encodes");
        let decoded: ControlFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, frame);
    }
}
