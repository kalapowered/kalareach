//! The verified actor envelope, and what an authorised connection may ask for.
//!
//! Section 23: ordinary live requests are authenticated by this connection plus the
//! host-constructed verified actor envelope, not by a per-request device signature. The envelope
//! binds original ingress, device, grant and revision, controller generation and connection
//! identity.
//!
//! "Host-constructed" is the whole point, so [`ConnectionActor`] is built once from facts the
//! connection established and the caller never supplies. A request names the grant it claims; it
//! cannot name its own device, its ingress or the generation that admitted it.
//!
//! The same type answers the 0-RTT question. Version 1 accepts no application mutation in QUIC
//! 0-RTT — not just no pairing mutation — so a request that arrived as early data is refused here
//! unless it is a read on the bounded pre-authorisation pairing surface, which is the one exception
//! section 23 allows and which [`crate::preauth`] narrows further.

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::authority::{AuthorityDecision, EffectClass, MethodEntry};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActorId, AuthorityRevision, ConnectionId, ControllerGeneration, DeviceId, GrantId,
};
use kr_protocol::method::{MethodVersion, decide};
use kr_protocol::scalars::Nullable;

/// The facts an authorised connection establishes once.
///
/// Everything here is decided by the host: the ingress by which transport accepted the peer, the
/// device from the paired record the endpoint identity selected, the principal the host assigns,
/// the generation that admitted the connection and the connection's own identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionActor {
    actor_id: ActorId,
    ingress: ActorIngress,
    device_id: Nullable<DeviceId>,
    controller_generation: ControllerGeneration,
    connection_id: ConnectionId,
    early_data: bool,
}

impl ConnectionActor {
    /// Builds the actor of a paired device on an authorised network connection.
    ///
    /// The ingress is `paired_device`, which is what an authority entry restricted to local IPC
    /// refuses however broad the device's grant is.
    #[must_use]
    pub fn network_device(
        actor_id: ActorId,
        device_id: DeviceId,
        controller_generation: ControllerGeneration,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            actor_id,
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(device_id),
            controller_generation,
            connection_id,
            early_data: false,
        }
    }

    /// Builds the actor of an authenticated operating-system caller on the local socket.
    ///
    /// A local caller carries no device identity. Section 23: local IPC uses its authenticated OS
    /// caller and a host-stamped freshness context, without pretending to be a paired network
    /// device.
    #[must_use]
    pub fn local_peer(
        actor_id: ActorId,
        controller_generation: ControllerGeneration,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            actor_id,
            ingress: ActorIngress::LocalIpc,
            device_id: Nullable::null(),
            controller_generation,
            connection_id,
            early_data: false,
        }
    }

    /// Builds the actor of a connection that has not passed device authorisation.
    #[must_use]
    pub fn unpaired_peer(
        actor_id: ActorId,
        controller_generation: ControllerGeneration,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            actor_id,
            ingress: ActorIngress::UnpairedPeer,
            device_id: Nullable::null(),
            controller_generation,
            connection_id,
            early_data: false,
        }
    }

    /// Marks this actor's requests as QUIC early data.
    #[must_use]
    pub fn in_early_data(mut self, early_data: bool) -> Self {
        self.early_data = early_data;
        self
    }

    /// Returns the ingress the host recorded.
    #[must_use]
    pub const fn ingress(&self) -> ActorIngress {
        self.ingress
    }

    /// Returns the connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the controller generation that admitted the connection.
    #[must_use]
    pub const fn controller_generation(&self) -> ControllerGeneration {
        self.controller_generation
    }

    /// Returns the principal the host assigned.
    #[must_use]
    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// Returns true when this connection's requests arrived as QUIC early data.
    #[must_use]
    pub const fn is_early_data(&self) -> bool {
        self.early_data
    }

    /// Builds the envelope for one request, under the grant it was checked against.
    ///
    /// A read that needs no grant passes `None`; the envelope then records no grant rather than a
    /// placeholder.
    #[must_use]
    pub fn envelope(&self, grant: Option<(GrantId, AuthorityRevision)>) -> ActorEnvelope {
        let (grant_id, grant_revision) = match grant {
            Some((id, revision)) => (Nullable::some(id), Nullable::some(revision)),
            None => (Nullable::null(), Nullable::null()),
        };
        ActorEnvelope {
            actor_id: self.actor_id.clone(),
            ingress: self.ingress,
            device_id: self.device_id,
            grant_id,
            grant_revision,
            controller_generation: self.controller_generation,
            connection_id: self.connection_id,
        }
    }

    /// Resolves a request against the method registry and this connection's state.
    ///
    /// The order is the registry first, then 0-RTT. An unlisted method is denied whatever else is
    /// true of the connection, and a listed method that would mutate is refused in early data.
    ///
    /// # Errors
    ///
    /// Returns the protocol error to send back: `UNSUPPORTED_SCHEMA` for a version this build does
    /// not implement, and `PERMISSION_DENIED` for an unlisted method, a forbidden ingress or a
    /// mutation in early data.
    pub fn admit(
        &self,
        method: &str,
        version: MethodVersion,
    ) -> Result<&'static MethodEntry, ProtocolError> {
        let entry = match decide(method, version, self.ingress) {
            AuthorityDecision::Listed(entry) => entry,
            AuthorityDecision::Denied(reason) => {
                return Err(denial(method, &reason));
            }
        };
        if self.early_data && entry.effect == EffectClass::Write {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "no mutation is accepted in 0-RTT",
            ));
        }
        Ok(entry)
    }
}

fn denial(method: &str, reason: &kr_protocol::authority::DenialReason) -> ProtocolError {
    use kr_protocol::authority::DenialReason;
    match reason {
        DenialReason::UnsupportedVersion { supported } => ProtocolError::new(
            ErrorCode::UnsupportedSchema,
            format!("{method} is version {supported}"),
        ),
        DenialReason::UnlistedMethod | DenialReason::ForbiddenIngress { .. } => {
            // One message for both, because the difference tells a caller which methods exist.
            ProtocolError::new(ErrorCode::PermissionDenied, "the method is not available")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn actor_id() -> ActorId {
        ActorId::new("device:1").expect("a principal")
    }

    fn device_actor() -> ConnectionActor {
        ConnectionActor::network_device(
            actor_id(),
            DeviceId::new(Uuid::from_bytes([1; 16])),
            ControllerGeneration::new(4),
            ConnectionId::new(Uuid::from_bytes([2; 16])),
        )
    }

    /// KR-REQ-23.17: the envelope binds the original ingress, the device, the grant and the
    /// revision it was checked at, the admitting controller generation and the connection, each
    /// exactly as the host established it. A request can change only the grant it claims.
    /// KR-REQ-02.06: a paired device's action carries the envelope the host built for it: the
    /// device, the grant the action is checked against and that grant's revision, beside the
    /// ingress, the generation and the connection.
    #[test]
    fn the_envelope_records_the_facts_the_host_established() {
        let actor = device_actor();
        let envelope = actor.envelope(Some((
            GrantId::new(Uuid::from_bytes([3; 16])),
            AuthorityRevision::new(9),
        )));
        assert_eq!(envelope.actor_id, actor_id());
        assert_eq!(envelope.ingress, ActorIngress::PairedDevice);
        assert_eq!(
            envelope.device_id,
            Nullable::some(DeviceId::new(Uuid::from_bytes([1; 16])))
        );
        assert_eq!(
            envelope.grant_id,
            Nullable::some(GrantId::new(Uuid::from_bytes([3; 16])))
        );
        assert_eq!(
            envelope.grant_revision,
            Nullable::some(AuthorityRevision::new(9))
        );
        assert_eq!(envelope.controller_generation, ControllerGeneration::new(4));
        assert_eq!(
            envelope.connection_id,
            ConnectionId::new(Uuid::from_bytes([2; 16]))
        );

        // Another grant changes the grant and its revision and nothing the connection
        // established.
        let other = actor.envelope(Some((
            GrantId::new(Uuid::from_bytes([5; 16])),
            AuthorityRevision::new(10),
        )));
        assert_eq!(
            other.grant_id,
            Nullable::some(GrantId::new(Uuid::from_bytes([5; 16])))
        );
        assert_eq!(
            other.grant_revision,
            Nullable::some(AuthorityRevision::new(10))
        );
        assert_eq!(
            (
                &other.actor_id,
                other.ingress,
                other.device_id,
                other.controller_generation,
                other.connection_id
            ),
            (
                &envelope.actor_id,
                envelope.ingress,
                envelope.device_id,
                envelope.controller_generation,
                envelope.connection_id
            )
        );
    }

    /// KR-REQ-23.17, KR-REQ-23.20: a local caller's envelope records local IPC and no device; it
    /// never passes as a paired network device.
    /// KR-REQ-02.06: a local caller's envelope names no device and no grant: it is authenticated
    /// by its operating-system identity instead.
    #[test]
    fn a_local_caller_is_not_a_paired_device() {
        let actor = ConnectionActor::local_peer(
            actor_id(),
            ControllerGeneration::new(1),
            ConnectionId::new(Uuid::from_bytes([5; 16])),
        );
        let envelope = actor.envelope(None);
        assert_eq!(envelope.ingress, ActorIngress::LocalIpc);
        assert!(!envelope.device_id.is_present());
        assert!(!envelope.grant_id.is_present());
    }

    #[test]
    fn a_private_ipc_method_is_unreachable_from_the_network() {
        let actor = device_actor();
        let error = actor
            .admit("root.editor.enter", MethodVersion::V1)
            .expect_err("a refusal");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(
            ConnectionActor::local_peer(
                actor_id(),
                ControllerGeneration::new(1),
                ConnectionId::new(Uuid::from_bytes([5; 16]))
            )
            .admit("root.editor.enter", MethodVersion::V1)
            .is_ok()
        );
    }

    #[test]
    fn an_unlisted_method_is_denied() {
        let actor = device_actor();
        let error = actor
            .admit("host.shutdown", MethodVersion::V1)
            .expect_err("a refusal");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn an_unsupported_version_is_a_schema_failure() {
        let actor = device_actor();
        let error = actor
            .admit("session.read", MethodVersion(9))
            .expect_err("a refusal");
        assert_eq!(error.code, ErrorCode::UnsupportedSchema);
    }

    /// KR-REQ-23.18: no application mutation is accepted in 0-RTT; reads still are.
    #[test]
    fn no_application_mutation_is_accepted_in_early_data() {
        let actor = device_actor().in_early_data(true);
        // A read is still served: nothing about 0-RTT makes reading unsafe.
        assert!(actor.admit("session.read", MethodVersion::V1).is_ok());
        // Every write is refused, application or pairing.
        for method in ["session.create", "input.write", "pair.confirm"] {
            let error = actor
                .admit(method, MethodVersion::V1)
                .expect_err("a refusal");
            assert_eq!(error.code, ErrorCode::PermissionDenied, "{method}");
            assert_eq!(error.message, "no mutation is accepted in 0-RTT");
        }
    }

    /// KR-REQ-23.18, KR-REQ-10.27: the pairing mutations are refused in 0-RTT as well.
    #[test]
    fn the_pairing_surface_refuses_its_own_mutations_in_early_data() {
        let actor = ConnectionActor::unpaired_peer(
            actor_id(),
            ControllerGeneration::new(1),
            ConnectionId::new(Uuid::from_bytes([7; 16])),
        )
        .in_early_data(true);
        // The one read the surface exposes is served.
        assert!(actor.admit("pair.status", MethodVersion::V1).is_ok());
        // Its two mutations are not, which is the exception section 23 names and then closes.
        for method in ["pair.redeem", "pair.finish"] {
            let error = actor
                .admit(method, MethodVersion::V1)
                .expect_err("a refusal");
            assert_eq!(
                error.message, "no mutation is accepted in 0-RTT",
                "{method}"
            );
        }
    }

    #[test]
    fn the_same_mutation_is_admitted_once_the_handshake_completes() {
        let actor = device_actor();
        assert!(actor.admit("session.create", MethodVersion::V1).is_ok());
    }
}
