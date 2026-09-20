//! Opening a bridge: what may cross it, and what is refused before a process starts.
//!
//! This is the gate section 3 puts on the near side. The process bridges serve locally
//! authenticated command-line invocations only, and **a Windows controller must not route a
//! network actor through one and relabel it a Linux local owner**. A remote client reaches the
//! destination environment through that environment's own paired endpoint, which it has, because
//! each Windows, WSL and enrolled container installation is an independent environment authority.
//!
//! The refusal happens here, before an argument vector is built and before a process exists. The
//! helper on the far side refuses the same handshake again, and neither check makes the other
//! redundant: this one is what a correct invoker does, and that one is what a destination
//! environment can enforce for itself.
//!
//! **Ingress is carried, not recomputed.** The opening frame states the ingress the request
//! originally arrived on. It is always [`ActorIngress::LocalIpc`] once this gate has passed, which
//! is exactly the point: the record on the far side then names where the request entered rather
//! than the local IPC hop the helper made, and there is no arrangement of hops that turns a
//! network device into a local owner.

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::identity::{BridgeHello, BridgeTarget, EnvironmentEnrolment};
use kr_protocol::ids::{BuildId, EnvironmentId};

use crate::bridge::launch::{self, BridgeCommand, LaunchError};

/// Why this host will not open a bridge for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request did not arrive on a locally authenticated ingress.
    ///
    /// It carries the ingress it did arrive on, so a receipt and a log can say what was refused.
    NetworkActor {
        /// Where the request entered this host.
        ingress: ActorIngress,
    },
    /// The request has already crossed a bridge. A federated proxy is outside version 1.
    AlreadyBridged,
    /// The enrolment is not reached by a process bridge, or is incomplete.
    Launch(LaunchError),
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkActor { ingress } => write!(
                formatter,
                "a process bridge carries locally authenticated invocations only, and this request \
                 arrived as {}; reach that environment through its own paired endpoint",
                ingress.as_str()
            ),
            Self::AlreadyBridged => {
                formatter.write_str("a request crosses at most one process bridge")
            }
            Self::Launch(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for crate::error::ControllerError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            // Both admission refusals are permission failures, and both say the same thing to the
            // caller. An incomplete enrolment is the caller's own record being wrong.
            Refusal::NetworkActor { .. } | Refusal::AlreadyBridged => Self::PermissionDenied {
                detail: refusal.to_string(),
            },
            Refusal::Launch(_) => Self::InvalidArgument(refusal.to_string()),
        }
    }
}

/// One bridge this host is ready to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The command the helper is started with.
    pub command: BridgeCommand,
    /// The opening frame written to its standard input.
    pub hello: BridgeHello,
}

/// Decides whether a request may cross a bridge, and builds what opens it.
///
/// `actor` is the envelope this host constructed for the request. Nothing the caller supplied is
/// read here: the ingress comes from that envelope, which the host built from the connection.
///
/// # Errors
///
/// Returns [`Refusal::NetworkActor`] for a request that did not arrive on a locally authenticated
/// ingress, [`Refusal::AlreadyBridged`] for one that has already crossed a bridge, and
/// [`Refusal::Launch`] when the enrolment names no process bridge or is incomplete.
pub fn open(
    actor: &ActorEnvelope,
    already_bridged: bool,
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
    target: BridgeTarget,
) -> Result<Opening, Refusal> {
    if !actor.ingress.may_cross_process_bridge() {
        return Err(Refusal::NetworkActor {
            ingress: actor.ingress,
        });
    }
    if already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    let command = launch::command(enrolment).map_err(Refusal::Launch)?;
    Ok(Opening {
        command,
        hello: BridgeHello {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build_id,
            origin_environment_id,
            // Carried, not recomputed. This is where the request entered this host.
            origin_ingress: actor.ingress,
            already_bridged: false,
            target,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::EnvironmentAccess;
    use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration, DeviceId};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn enrolment() -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: "ubuntu".to_owned(),
            target: "Ubuntu-24.04".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    fn actor(ingress: ActorIngress) -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("device:1").expect("a principal"),
            ingress,
            device_id: if ingress == ActorIngress::PairedDevice {
                Nullable::some(DeviceId::new(Uuid::from_bytes([5; 16])))
            } else {
                Nullable::null()
            },
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(3),
            connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
        }
    }

    fn here() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([1; 16]))
    }

    fn build() -> BuildId {
        BuildId::new("kr/0.1.0").expect("a build")
    }

    #[test]
    fn a_local_invocation_opens_a_bridge_that_carries_its_own_ingress() {
        let opening = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect("opened");
        assert_eq!(opening.hello.origin_ingress, ActorIngress::LocalIpc);
        assert_eq!(opening.hello.origin_environment_id, here());
        assert!(!opening.hello.already_bridged);
        assert_eq!(opening.command.program, "wsl.exe");
    }

    #[test]
    fn a_network_actor_never_reaches_a_bridge() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            let refusal = open(
                &actor(ingress),
                false,
                &enrolment(),
                here(),
                build(),
                BridgeTarget::Controller,
            )
            .expect_err("a refusal");
            assert_eq!(refusal, Refusal::NetworkActor { ingress });
            assert!(
                refusal.to_string().contains(ingress.as_str()),
                "the refusal names what arrived: {refusal}"
            );
        }
    }

    #[test]
    fn a_paired_device_is_refused_before_an_argument_vector_exists() {
        // The refusal comes before the enrolment is even read, so a device cannot reach a bridge
        // by naming a record this host would otherwise have started.
        let mut unusable = enrolment();
        unusable.helper_path = String::new();
        let refusal = open(
            &actor(ActorIngress::PairedDevice),
            false,
            &unusable,
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice
            }
        );
    }

    #[test]
    fn a_request_that_already_crossed_a_bridge_is_not_chained() {
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            true,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(refusal, Refusal::AlreadyBridged);
    }

    #[test]
    fn an_ssh_environment_is_refused_as_a_bridge_rather_than_started() {
        let mut ssh = enrolment();
        ssh.access = EnvironmentAccess::SshHost;
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &ssh,
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::Launch(LaunchError::NotAProcessBridge {
                access: EnvironmentAccess::SshHost
            })
        );
    }
}
