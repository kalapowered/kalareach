//! Worker identity: descriptors, the startup rendezvous, the verify challenge and the controller
//! generation token.
//!
//! A worker outlives the control daemon that started it, so the daemon cannot rely on being the
//! parent process, on a file it wrote earlier, or on a process identifier it remembers. Four
//! objects close that gap, and each one is a signature over a domain-separated transcript rather
//! than a fact asserted on the wire.
//!
//! | Object | Who signs | What it settles |
//! | --- | --- | --- |
//! | [`WorkerRendezvous`] | the worker, once, at startup | this process is the worker the controller reserved |
//! | [`WorkerDescriptor`] | nobody; it is published data | where to find a worker and which key answers for it |
//! | [`WorkerVerifyProof`] | the worker, on every challenge | the process answering this endpoint is that worker, now |
//! | [`ControllerGenerationToken`] | the controller | this connection speaks for the current controller generation |
//!
//! The descriptor carries no secret. Its public key is what makes it useful: a client that reads a
//! descriptor still has to challenge the worker before trusting anything else in it, so a stale or
//! planted file cannot direct a client anywhere.

use kr_cbor::CanonicalValue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::hello::ProtocolVersion;
use crate::identity::{BootIdentity, ProcessStartIdentity, WorkerProfile};
use crate::ids::{AuthorityRevision, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId};
use crate::scalars::{AuthorisationKey, Nonce256, Nullable, Signature64, TimestampMs, U64, Uuid};
use crate::session::DisplayNumber;

/// The domain separating a worker's startup rendezvous.
pub const WORKER_RENDEZVOUS_DOMAIN: &str = "kr-worker/1/rendezvous";

/// The domain separating a worker's answer to a verification challenge.
pub const WORKER_VERIFY_DOMAIN: &str = "kr-worker/1/verify";

/// The domain separating a controller's generation token.
pub const CONTROLLER_GENERATION_DOMAIN: &str = "kr-controller/1/generation";

/// Identifies one spawn reservation.
///
/// The controller records a reservation durably before it starts anything, and exactly one
/// rendezvous per reservation succeeds. A second attempt is rejected, recorded and fences the
/// reservation, because two processes claiming one reservation means the host does not know which
/// of them owns the session.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ReservationId(pub Uuid);

impl ReservationId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl core::fmt::Display for ReservationId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

impl core::str::FromStr for ReservationId {
    type Err = crate::scalars::UuidParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse().map(Self)
    }
}

/// What the controller publishes so a client can reach a worker without asking the controller.
///
/// Section 5 requires this file to be owner-only, published atomically and free of secrets. A
/// filename and a process identifier are hints; the public key here is what a challenge is checked
/// against, and the identity fields are what the challenge's answer must match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerDescriptor {
    /// The session this worker owns.
    pub session_id: SessionId,
    /// The session epoch.
    pub session_epoch: SessionEpoch,
    /// The environment the session belongs to.
    pub environment_id: EnvironmentId,
    /// The local alias.
    pub display_number: DisplayNumber,
    /// The boot the worker started in.
    pub boot_identity: BootIdentity,
    /// The worker process and the kernel's record of when it started.
    pub process_start_identity: ProcessStartIdentity,
    /// The protocol version the worker speaks.
    pub protocol_version: ProtocolVersion,
    /// The worker's private endpoint.
    pub endpoint: String,
    /// The public half of the worker's per-session key. The private half exists only in the
    /// worker's memory.
    pub worker_public_key: AuthorisationKey,
    /// How long the worker's execution context lasts.
    pub worker_profile: WorkerProfile,
    /// When the descriptor was published.
    pub published_at_ms: TimestampMs,
}

/// A worker's startup claim, signed with the key it just generated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerRendezvous {
    /// The reservation this worker was started for.
    pub reservation_id: ReservationId,
    /// The session the reservation allocated.
    pub session_id: SessionId,
    /// The public half of the worker's new per-session key.
    pub worker_public_key: AuthorisationKey,
    /// The boot the worker started in.
    pub boot_identity: BootIdentity,
    /// The worker's own process identity, which the controller compares with what the launcher
    /// reported and with the connecting peer.
    pub process_start_identity: ProcessStartIdentity,
    /// The signature over [`rendezvous_elements`].
    pub signature: Signature64,
}

/// Builds the transcript elements a rendezvous signature covers.
///
/// `CBOR(["kr-worker/1/rendezvous", reservation_id, session_uuid, worker_public_key,
/// boot_identity, process_start_identity])`.
///
/// # Errors
///
/// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
pub fn rendezvous_elements(
    reservation_id: ReservationId,
    session_id: SessionId,
    worker_public_key: &AuthorisationKey,
    boot_identity: &BootIdentity,
    process_start_identity: &ProcessStartIdentity,
) -> Result<Vec<CanonicalValue>, kr_cbor::CborError> {
    Ok(vec![
        kr_cbor::to_canonical_value(&reservation_id)?,
        kr_cbor::to_canonical_value(&session_id)?,
        kr_cbor::to_canonical_value(worker_public_key)?,
        kr_cbor::to_canonical_value(boot_identity)?,
        kr_cbor::to_canonical_value(process_start_identity)?,
    ])
}

/// A fresh challenge sent to a worker's private endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerVerifyChallenge {
    /// Thirty-two fresh random bytes. A reused challenge proves nothing.
    pub nonce: Nonce256,
}

/// A worker's answer to a challenge.
///
/// The verifier checks the signature against the descriptor's public key **and** compares every
/// identity field with the descriptor. A worker that answers with a different session, epoch, boot
/// or process is not the worker the descriptor named.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerVerifyProof {
    /// The session the worker owns.
    pub session_id: SessionId,
    /// The session epoch.
    pub session_epoch: SessionEpoch,
    /// The boot the worker is running in.
    pub boot_identity: BootIdentity,
    /// The worker's process identity.
    pub process_start_identity: ProcessStartIdentity,
    /// The protocol version the worker speaks.
    pub protocol_version: ProtocolVersion,
    /// The endpoint the challenge arrived on.
    pub endpoint: String,
    /// The signature over [`verify_elements`].
    pub signature: Signature64,
}

/// Builds the transcript elements a verification signature covers.
///
/// `CBOR(["kr-worker/1/verify", session_uuid, session_epoch, boot_identity,
/// process_start_identity, protocol_version, endpoint_path, nonce])`.
///
/// # Errors
///
/// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
pub fn verify_elements(
    session_id: SessionId,
    session_epoch: SessionEpoch,
    boot_identity: &BootIdentity,
    process_start_identity: &ProcessStartIdentity,
    protocol_version: ProtocolVersion,
    endpoint: &str,
    nonce: &Nonce256,
) -> Result<Vec<CanonicalValue>, kr_cbor::CborError> {
    Ok(vec![
        kr_cbor::to_canonical_value(&session_id)?,
        kr_cbor::to_canonical_value(&session_epoch)?,
        kr_cbor::to_canonical_value(boot_identity)?,
        kr_cbor::to_canonical_value(process_start_identity)?,
        kr_cbor::to_canonical_value(&protocol_version)?,
        CanonicalValue::text(endpoint),
        kr_cbor::to_canonical_value(nonce)?,
    ])
}

/// A controller's proof that it speaks for the current generation.
///
/// The nonce comes from the worker, so a token cannot be replayed onto a later connection. A
/// worker accepts its current generation again only after a fresh challenge, which fences that
/// generation's previous connection; it rejects a lower generation outright and requires a
/// strictly higher one from a replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControllerGenerationToken {
    /// The environment the controller owns.
    pub environment_id: EnvironmentId,
    /// The generation this controller holds.
    pub generation: ControllerGeneration,
    /// The boot the controller is running in.
    pub boot_identity: BootIdentity,
    /// The challenge the worker issued.
    pub nonce: Nonce256,
    /// The signature over [`generation_elements`].
    pub signature: Signature64,
}

/// Builds the transcript elements a generation token covers.
///
/// `CBOR(["kr-controller/1/generation", environment_id, generation, boot_identity,
/// nonce_from_worker])`.
///
/// # Errors
///
/// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
pub fn generation_elements(
    environment_id: EnvironmentId,
    generation: ControllerGeneration,
    boot_identity: &BootIdentity,
    nonce: &Nonce256,
) -> Result<Vec<CanonicalValue>, kr_cbor::CborError> {
    Ok(vec![
        kr_cbor::to_canonical_value(&environment_id)?,
        kr_cbor::to_canonical_value(&generation)?,
        kr_cbor::to_canonical_value(boot_identity)?,
        kr_cbor::to_canonical_value(nonce)?,
    ])
}

/// Why a worker refused a controller's generation token.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GenerationRefusal {
    /// The signature did not verify against the controller key recorded at spawn.
    SignatureInvalid,
    /// The token named a different environment.
    WrongEnvironment,
    /// The generation is below the one the worker has already accepted.
    GenerationSuperseded,
    /// The token answered a challenge the worker did not issue.
    StaleChallenge,
    /// The token named a different boot.
    WrongBoot,
}

impl GenerationRefusal {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignatureInvalid => "signature_invalid",
            Self::WrongEnvironment => "wrong_environment",
            Self::GenerationSuperseded => "generation_superseded",
            Self::StaleChallenge => "stale_challenge",
            Self::WrongBoot => "wrong_boot",
        }
    }
}

/// What the controller tells a worker to become, over the private rendezvous channel.
///
/// The job definition that started the worker carries only non-secret facts: the reservation, the
/// rendezvous address and the runtime directory. Everything else arrives here, after the worker
/// has proved which reservation it belongs to, so a creator's environment snapshot never sits in
/// an argument vector or an environment variable where another process could read it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerLaunchSpec {
    /// The session the worker will own.
    pub session_id: SessionId,
    /// The session epoch.
    pub session_epoch: SessionEpoch,
    /// The environment the session belongs to.
    pub environment_id: EnvironmentId,
    /// The local alias, which also names the worker's endpoint.
    pub display_number: DisplayNumber,
    /// The create request the controller admitted.
    pub create: crate::session::SessionCreateParams,
    /// The controller's public key, recorded so the worker can check generation tokens.
    pub controller_public_key: AuthorisationKey,
    /// The generation that spawned this worker.
    pub controller_generation: ControllerGeneration,
    /// The release string the session reports as its terminal program version.
    pub release: String,
}

/// What a worker reports once its root shell is running.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerReady {
    /// The session the worker owns.
    pub session_id: SessionId,
    /// The worker's private endpoint.
    pub endpoint: String,
    /// The root shell's process identity.
    pub root_process: ProcessStartIdentity,
    /// The executable actually launched.
    pub shell_path: String,
    /// The geometry the shell started at.
    pub dimensions: crate::session::Dimensions,
}

/// A worker's challenge to a controller that wants to speak for a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerationChallenge {
    /// Thirty-two fresh random bytes, bound to this connection and consumed once.
    pub nonce: Nonce256,
}

/// A worker's answer to a generation token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerationAccepted {
    /// The generation the worker now accepts.
    pub generation: ControllerGeneration,
    /// True when accepting this token fenced an earlier connection of the same generation.
    pub fenced_previous: bool,
}

/// The host's current authority revision, announced to a worker by the controller that holds it.
///
/// Authority revisions are ordered and only the host issues them. A revocation is not complete
/// when the controller records it: it is complete when every worker that could still act on the
/// revoked authority has acknowledged the revision that removed it. Until then the revocation
/// reports `pending` for that worker, or the worker is confirmed ended, which answers the same
/// question a different way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevisionNotice {
    /// The environment whose authority changed.
    pub environment_id: EnvironmentId,
    /// The revision now in force.
    pub revision: AuthorityRevision,
}

/// A worker's acknowledgement that it is acting under an authority revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevisionAck {
    /// The session that acknowledged it.
    pub session_id: SessionId,
    /// The revision the worker now holds.
    pub revision: AuthorityRevision,
}

/// How a worker's execution context is bound, as recorded in the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerBinding {
    /// How long the execution context lasts.
    pub profile: WorkerProfile,
    /// The boot the worker is bound to.
    pub boot_identity: BootIdentity,
    /// The login-session generation a desktop-bound worker is bound to. A headless worker is not
    /// bound to a login session, and states that with a null rather than a placeholder number.
    pub login_generation: Nullable<U64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{BootIdentitySource, ProcessStartSource};
    use crate::scalars::Bytes;

    fn boot() -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: Bytes::new(b"boot".to_vec()),
        }
    }

    fn start() -> ProcessStartIdentity {
        ProcessStartIdentity::new(11, ProcessStartSource::LinuxProcStat, 22)
    }

    #[test]
    fn each_transcript_starts_with_its_own_domain() {
        assert_eq!(WORKER_RENDEZVOUS_DOMAIN, "kr-worker/1/rendezvous");
        assert_eq!(WORKER_VERIFY_DOMAIN, "kr-worker/1/verify");
        assert_eq!(CONTROLLER_GENERATION_DOMAIN, "kr-controller/1/generation");
    }

    #[test]
    fn transcript_elements_are_in_the_specified_order() {
        let key = AuthorisationKey::from_bytes([7; 32]);
        let elements = rendezvous_elements(
            ReservationId::new(Uuid::NIL),
            SessionId::new(Uuid::NIL),
            &key,
            &boot(),
            &start(),
        )
        .expect("encodes");
        assert_eq!(elements.len(), 5);
        assert_eq!(elements[2], kr_cbor::to_canonical_value(&key).expect("key"));

        let nonce = Nonce256::from_bytes([3; 32]);
        let verify = verify_elements(
            SessionId::new(Uuid::NIL),
            SessionEpoch::V1,
            &boot(),
            &start(),
            crate::hello::PROTOCOL_VERSION,
            "/run/w1.sock",
            &nonce,
        )
        .expect("encodes");
        assert_eq!(verify.len(), 7);
        assert_eq!(verify[5], CanonicalValue::text("/run/w1.sock"));
        assert_eq!(
            verify[6],
            kr_cbor::to_canonical_value(&nonce).expect("nonce")
        );

        let generation = generation_elements(
            EnvironmentId::new(Uuid::NIL),
            ControllerGeneration::new(4),
            &boot(),
            &nonce,
        )
        .expect("encodes");
        assert_eq!(generation.len(), 4);
    }

    #[test]
    fn a_different_nonce_produces_a_different_transcript() {
        let first = verify_elements(
            SessionId::new(Uuid::NIL),
            SessionEpoch::V1,
            &boot(),
            &start(),
            crate::hello::PROTOCOL_VERSION,
            "/run/w1.sock",
            &Nonce256::from_bytes([1; 32]),
        )
        .expect("encodes");
        let second = verify_elements(
            SessionId::new(Uuid::NIL),
            SessionEpoch::V1,
            &boot(),
            &start(),
            crate::hello::PROTOCOL_VERSION,
            "/run/w1.sock",
            &Nonce256::from_bytes([2; 32]),
        )
        .expect("encodes");
        assert_ne!(first, second);
    }
}
