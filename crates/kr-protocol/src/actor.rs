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

    /// Returns true when a local process bridge may carry a request that arrived on this ingress.
    ///
    /// Section 3 restricts the Windows/WSL and container process bridges to locally authenticated
    /// command-line invocations, and forbids a Windows controller from routing a network actor
    /// through one and relabelling it a Linux local owner. The specification writes the two
    /// provenance classes a request records as `local_peer` and `network_device`; in this
    /// vocabulary `local_peer` is [`Self::LocalIpc`] and `network_device` is every ingress
    /// [`Self::is_remote`] reports.
    ///
    /// The remaining two are refused as well. A workflow run and a plugin component are local to
    /// the host, but neither is a command-line invocation a person authenticated to the operating
    /// system, and a bridge that carried them would let an automation reach another environment's
    /// owner authority without that environment's own grant.
    #[must_use]
    pub const fn may_cross_process_bridge(self) -> bool {
        matches!(self, Self::LocalIpc)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_locally_authenticated_caller_may_cross_a_process_bridge() {
        assert!(ActorIngress::LocalIpc.may_cross_process_bridge());
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            assert!(
                !ingress.may_cross_process_bridge(),
                "{} must not cross a process bridge",
                ingress.as_str()
            );
        }
    }

    #[test]
    fn every_ingress_is_one_of_the_two_provenance_classes_the_specification_names() {
        // `local_peer` and `network_device` are the specification's names for what an envelope
        // records. Each implemented ingress maps onto exactly one of them, so a request can always
        // say which it was rather than reporting the hop it last crossed.
        for ingress in ActorIngress::ALL.iter().copied() {
            let local_peer = ingress.may_cross_process_bridge();
            let network_device = ingress.is_remote();
            assert!(
                !(local_peer && network_device),
                "{} cannot be both classes",
                ingress.as_str()
            );
        }
        assert!(ActorIngress::LocalIpc.may_cross_process_bridge());
        assert!(ActorIngress::PairedDevice.is_remote());
    }

    #[test]
    fn an_envelope_records_the_ingress_rather_than_deriving_it() {
        // The envelope is host-constructed, and its ingress field is the only thing that says
        // where the request entered. Nothing here can be recomputed from the other fields: a
        // local caller and a paired device differ in ingress, and a device identity is absent
        // from the local one rather than implied by it.
        use crate::ids::{ActorId, ConnectionId, ControllerGeneration};
        use crate::scalars::{Nullable, Uuid};

        let envelope = ActorEnvelope {
            actor_id: ActorId::new("local:1").expect("a principal"),
            ingress: ActorIngress::LocalIpc,
            device_id: Nullable::null(),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
        };
        assert_eq!(envelope.ingress, ActorIngress::LocalIpc);
        assert!(!envelope.device_id.is_present());
    }
}
