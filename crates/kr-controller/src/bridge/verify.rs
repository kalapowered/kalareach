//! Opening a bridge to an enrolled environment to see what answers.
//!
//! A refresh asks the platform whether an environment is running. That is a fact about a process
//! tree, and section 18 asks for more than that: connection diagnostics, and an integration that is
//! actually installed in the target environment rather than assumed. Section 25 is exact about what
//! installs it — a helper that registers an explicit environment identity and a scoped local
//! channel, and never infers authority from a forwarded environment variable.
//!
//! So a refresh of a running environment opens the bridge and looks. The helper starts inside the
//! destination, authenticates to that environment's own daemon over that environment's own local
//! channel, and acknowledges with the identity it has there. One read crosses the bridge and comes
//! back, because a handshake alone shows that a process started, not that this host can reach the
//! daemon behind it.
//!
//! What this proves, and therefore what a successful verification records, is that the destination
//! has its own channel and answers on it. A forwarded socket cannot produce this result: the
//! acknowledgement carries the destination daemon's own connection and boot identity, taken inside
//! the environment the helper runs in.

use kr_protocol::actor::ActorEnvelope;
use kr_protocol::envelope::{Outcome, ParamsValue, Request};
use kr_protocol::identity::{BridgeTarget, BridgeVerification, EnvironmentEnrolment};
use kr_protocol::ids::{BuildId, EnvironmentId, RequestId};
use kr_protocol::method::{Method, MethodVersion};

use crate::bridge::invoke::{self, Refusal};

/// Opens a bridge to one enrolled environment and reports what answered.
///
/// The request that crosses is a read of the destination's own environment list: the cheapest
/// thing that has to reach the daemon behind the helper, and one that changes nothing there.
///
/// # Errors
///
/// Returns the [`Refusal`] naming what stopped it: a helper that would not start, a stream that
/// failed, a destination that refused the opening frame, an environment that answered with an
/// identity the enrolment does not name, or the destination's own error for the read.
pub async fn through_bridge(
    actor: &ActorEnvelope,
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
) -> Result<BridgeVerification, Refusal> {
    let opening = invoke::open(
        actor,
        false,
        enrolment,
        origin_environment_id,
        build_id,
        BridgeTarget::Controller,
    )?;
    let mut invocation = opening.launch().await?;
    let answer = invocation
        .request(Request {
            request_id: RequestId::new(1),
            method: Method::EnvironmentList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        })
        .await?;
    let verification = BridgeVerification {
        environment_id: invocation.acknowledgement().environment_id,
        os_user: invocation.acknowledgement().os_user.clone(),
        role: invocation.acknowledgement().role,
        protocol_version: invocation.acknowledgement().protocol_version,
        max_frame_len: invocation.acknowledgement().max_frame_len,
    };
    // The bridge is over as soon as it has answered. Nothing here holds one open: a refresh is a
    // look, and a helper left running inside a distribution would be a process nobody asked for.
    let _ = invocation.close().await;
    match answer.outcome {
        Outcome::Ok(_) => Ok(verification),
        Outcome::Error(error) => Err(Refusal::Destination(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::identity::EnvironmentAccess;
    use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn enrolment(access: EnvironmentAccess, target: &str) -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            access,
            label: "ubuntu".to_owned(),
            target: target.to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    fn actor(ingress: ActorIngress) -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("user:1").expect("a principal"),
            ingress,
            device_id: Nullable::null(),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
        }
    }

    #[tokio::test]
    async fn a_network_actor_is_refused_before_a_helper_is_started() {
        // The same gate the invoker applies, reached through the path a refresh takes. Nothing is
        // started: the refusal comes from the envelope this host built for the request.
        let refusal = through_bridge(
            &actor(ActorIngress::PairedDevice),
            &enrolment(EnvironmentAccess::WslDistribution, "Ubuntu-24.04"),
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            BuildId::new("kr/0.1.0").expect("a build"),
        )
        .await
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice
            }
        );
    }

    #[tokio::test]
    async fn an_ssh_environment_is_not_reached_by_a_bridge_at_all() {
        let refusal = through_bridge(
            &actor(ActorIngress::LocalIpc),
            &enrolment(EnvironmentAccess::SshHost, "build.example"),
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            BuildId::new("kr/0.1.0").expect("a build"),
        )
        .await
        .expect_err("a refusal");
        assert!(matches!(refusal, Refusal::Launch(_)), "{refusal}");
    }

    #[tokio::test]
    async fn a_helper_that_cannot_be_started_says_which_program_it_was() {
        // A host without the platform's launcher reports the program it could not run, rather than
        // a refusal about authority that would send a person looking in the wrong place.
        let refusal = through_bridge(
            &actor(ActorIngress::LocalIpc),
            &enrolment(
                EnvironmentAccess::Container,
                &"9f".repeat(kr_protocol::identity::CONTAINER_IDENTIFIER_LEN / 2),
            ),
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            BuildId::new("kr/0.1.0").expect("a build"),
        )
        .await;
        match refusal {
            // Either the runtime is absent here, or it is present and knows no such container.
            Err(Refusal::NotStarted { program, .. }) => {
                assert_eq!(program, crate::bridge::launch::CONTAINER_RUNTIME);
            }
            Err(other) => assert!(
                matches!(other, Refusal::Stream { .. } | Refusal::Unreadable { .. }),
                "{other}"
            ),
            Ok(verification) => panic!("no container answered, yet {verification:?} came back"),
        }
    }
}
