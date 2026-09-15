//! The verified actor envelope.
//!
//! Section 23 requires the host to construct this envelope. A caller never asserts its own
//! provenance and never borrows another device's identity. Ordinary live requests are
//! authenticated by the connection plus this envelope, not by a per-request device signature.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActorId, AuthorityRevision, ConnectionId, ControllerGeneration, DeviceId, GrantId,
};
use crate::scalars::Nullable;

/// Where a request entered the host.
///
/// Ingress is part of every authority entry. A method restricted to private IPC is never reachable
/// through the network or through a plugin component, whatever rights the caller holds.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ActorIngress {
    /// An authenticated operating-system caller on a Unix domain socket or a Windows named pipe.
    /// The host stamps the freshness context; the caller does not pretend to be a paired device.
    LocalIpc,
    /// A paired device on an authorised iroh connection.
    PairedDevice,
    /// A connection that has not passed device authorisation. It reaches only the bounded
    /// pre-authorisation pairing surface.
    UnpairedPeer,
    /// An automation run acting under an explicit workflow grant on the host.
    Workflow,
    /// A plugin component calling a host effect from the plugin runtime.
    Plugin,
    /// An installation or host credential presented at a managed or self-hosted service endpoint.
    ServiceClient,
}

impl ActorIngress {
    /// Every ingress class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::LocalIpc,
        Self::PairedDevice,
        Self::UnpairedPeer,
        Self::Workflow,
        Self::Plugin,
        Self::ServiceClient,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalIpc => "local_ipc",
            Self::PairedDevice => "paired_device",
            Self::UnpairedPeer => "unpaired_peer",
            Self::Workflow => "workflow",
            Self::Plugin => "plugin",
            Self::ServiceClient => "service_client",
        }
    }

    /// Returns true when this ingress arrives over a network transport.
    #[must_use]
    pub const fn is_remote(self) -> bool {
        matches!(
            self,
            Self::PairedDevice | Self::UnpairedPeer | Self::ServiceClient
        )
    }
}

/// The host-constructed identity of one request.
///
/// The de-duplication key for a mutation is `(actor_id, action_id)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorEnvelope {
    /// The stable host-issued principal for this actor.
    pub actor_id: ActorId,
    /// Where the request entered the host.
    pub ingress: ActorIngress,
    /// The paired device, when the ingress is a device.
    pub device_id: Nullable<DeviceId>,
    /// The grant the request is being checked against, when one applies.
    pub grant_id: Nullable<GrantId>,
    /// The authority revision the grant was validated at.
    pub grant_revision: Nullable<AuthorityRevision>,
    /// The controller generation that admitted the connection. Remote dispatch is fenced when this
    /// generation is replaced.
    pub controller_generation: ControllerGeneration,
    /// The connection the request arrived on. Closing the control stream revokes every associated
    /// data stream.
    pub connection_id: ConnectionId,
}
