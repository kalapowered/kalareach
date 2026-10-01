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
    /// The qualified shell package the controller resolved, as an absolute directory.
    ///
    /// Null for a create that launches no managed package. Where it is present the worker launches
    /// that package and no other: the daemon and the worker can be configured with different
    /// package roots, and a session must run the package its create was admitted against rather
    /// than whichever one the worker's own environment would have found.
    pub shell_package: crate::scalars::Nullable<String>,
    /// The controller's public key, recorded so the worker can check generation tokens.
    pub controller_public_key: AuthorisationKey,
    /// The generation that spawned this worker.
    pub controller_generation: ControllerGeneration,
    /// The release string the session reports as its terminal program version.
    pub release: String,
    /// The first snapshot of plugin admissions, whose parts follow this specification on the
    /// same connection before anything else does. The worker reads them before it starts the
    /// shell, so a package admitted at launch is there for the shell's first command.
    pub plugins: crate::admission::AdmissionsHeader,
    /// The environment's privacy state when this worker was launched.
    ///
    /// The worker applies it before it starts its shell. A session created while privacy mode is
    /// on therefore keeps none of its output in the history it retains, from its first byte, and
    /// does not wait for the daemon's next notice to learn that it is private.
    pub privacy: PrivacyLaunch,
}

/// The environment's privacy state, as a worker is told it when it is launched.
///
/// It is the generation in force and whether privacy mode is on at it, read by the daemon after
/// the worker's claim is accepted and before the specification is sent. A change after that reaches
/// the worker as the daemon's notice of the generation, which the daemon repeats until the worker
/// says its cleanup is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyLaunch {
    /// The generation in force. Nought is an environment that has never turned privacy mode on.
    pub generation: U64,
    /// Whether privacy mode is on at that generation.
    pub enabled: bool,
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
    /// The session as this worker describes it once its root shell is running.
    ///
    /// The daemon keeps it from the moment it records the worker, so a read that meets the worker
    /// on its way out is answered from the worker's own words, even where the create that started
    /// the worker stopped waiting before this report arrived.
    // Boxed so the control frame that carries the report is no larger than the others; the wire
    // carries the description itself.
    pub session: Box<crate::session::SessionSummary>,
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
    /// How many names of this revision's fence evidence the daemon already has.
    ///
    /// Nought asks for the first page, which is what a first announcement is. An announcement that
    /// carries more is asking for the rest of what the previous answer said remained, from the
    /// name after the last one it carried.
    ///
    /// It is absent from the wire when it is nought, so an announcement that asks for a first page
    /// is byte for byte what a worker built before paging existed expects. A daemon only ever
    /// sends a continuation to a worker whose own answer reported names remaining, and a worker
    /// that reports no evidence at all never does.
    #[serde(default, skip_serializing_if = "is_first_page")]
    pub evidence_from: u64,
}

/// Returns whether this is a request for the first page of fence evidence.
fn is_first_page(evidence_from: &u64) -> bool {
    *evidence_from == 0
}

/// A worker's acknowledgement that it is acting under an authority revision.
///
/// Section 9 makes the acknowledgement two statements rather than one: the revision is installed,
/// **and** the undispatched actions it affects have been rejected or fenced. The two lists are
/// therefore part of the acknowledgement rather than something a caller has to ask for
/// afterwards. An action whose dispatch transition had already won the serial race is named in
/// `possibly_executed`.
///
/// The evidence defaults to absent on the wire. A worker keeps running across a controller
/// replacement, so during an update a new daemon can be talking to a worker built before the
/// evidence existed, and architecture decision C keeps local support until the last such worker
/// exits. Defaulting lets that worker's two-field acknowledgement decode instead of failing the
/// revocation outright, and the daemon can still tell it apart from a worker whose fence found
/// nothing, because absent and empty are different values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevisionAck {
    /// The session that acknowledged it.
    pub session_id: SessionId,
    /// The revision the worker now holds.
    pub revision: AuthorityRevision,
    /// What the fence did, when this worker reports it.
    ///
    /// Absent is not the same as empty. Empty says the fence ran and found nothing; absent says
    /// this worker does not report fence evidence at all, and a daemon that read the two the same
    /// way would call a revocation complete on the strength of a worker that never said so.
    #[serde(default)]
    pub fence: Option<crate::action::FenceEvidence>,
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

    /// A ready report carries its worker's own description of the session, and a report without
    /// one is refused. The report passes only between a daemon and the worker it started from its
    /// own installation, so no report of another shape reaches a reader.
    #[test]
    fn a_ready_report_carries_its_workers_description_of_its_session() {
        use crate::envelope::ParamsValue;
        use crate::identity::DesktopBinding;
        use crate::session::{Dimensions, SessionState, SessionSummary, ShellMode};

        let session_id = SessionId::new(Uuid::from_bytes([9; 16]));
        let described = SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            display_number: DisplayNumber::new(1),
            state: SessionState::Live,
            shell_mode: ShellMode::NativeCompat,
            shell_path: "/bin/sh".to_owned(),
            cwd: "/work".to_owned(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: Dimensions::new(80, 24),
            attachment_count: U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::some(start()),
            closure: Nullable::null(),
        };
        let report = |described: Option<&SessionSummary>| {
            let mut entries = vec![
                ("session_id".to_owned(), encoded(&session_id)),
                ("endpoint".to_owned(), CanonicalValue::text("/run/w1.sock")),
                ("root_process".to_owned(), encoded(&start())),
                ("shell_path".to_owned(), CanonicalValue::text("/bin/sh")),
                ("dimensions".to_owned(), encoded(&Dimensions::new(80, 24))),
            ];
            entries.extend(described.map(|described| ("session".to_owned(), encoded(described))));
            ParamsValue::new(CanonicalValue::Map(
                kr_cbor::CanonicalMap::from_entries(entries).expect("a report's members"),
            ))
        };

        let with = report(Some(&described));
        let read: WorkerReady = with
            .to_typed()
            .expect("a report with its worker's description reads");
        assert_eq!(
            ParamsValue::from_typed(&read).expect("encodes"),
            with,
            "and writes back as it came"
        );
        assert!(
            report(None).to_typed::<WorkerReady>().is_err(),
            "a report without its worker's description is refused"
        );
    }

    /// `value` as KR-CBOR-1 writes it.
    fn encoded(value: &impl Serialize) -> CanonicalValue {
        kr_cbor::to_canonical_value(value).expect("encodes")
    }

    /// A launch specification as the daemon sends it, under `privacy`.
    fn specification(privacy: PrivacyLaunch) -> WorkerLaunchSpec {
        let environment_id = EnvironmentId::new(Uuid::from_bytes([2; 16]));
        WorkerLaunchSpec {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            create: crate::session::SessionCreateParams {
                environment_id,
                presentation: crate::session::Presentation::Invisible,
                shell: Nullable::null(),
                shell_mode: crate::session::ShellMode::NativeCompat,
                cwd: Nullable::some("/".to_owned()),
                dimensions: Nullable::null(),
                worker_profile: WorkerProfile::HeadlessUser,
                environment_snapshot: Vec::new(),
                palette: Nullable::null(),
                launch_profile: crate::session::LaunchProfile::default(),
                terminal: Nullable::null(),
            },
            shell_package: Nullable::null(),
            controller_public_key: AuthorisationKey::from_bytes([3; 32]),
            controller_generation: ControllerGeneration::new(1),
            release: "0".to_owned(),
            plugins: crate::admission::AdmissionsHeader {
                frame: crate::admission::FrameId {
                    generation: ControllerGeneration::new(1),
                    revision: U64::new(1),
                    round: U64::new(1),
                },
                parts: 1,
            },
            privacy,
        }
    }

    /// A launch specification carries the privacy state its worker starts under, a specification
    /// without it is refused, and so is one that says more of it than a worker understands. A
    /// daemon speaks only to workers of its own release, so no specification of another shape
    /// reaches a worker.
    #[test]
    fn a_launch_specification_carries_the_privacy_state_its_worker_starts_under() {
        use crate::envelope::ParamsValue;

        let private = specification(PrivacyLaunch {
            generation: U64::new(3),
            enabled: true,
        });
        let json = serde_json::to_value(&private).expect("encodes");
        assert_eq!(
            json["privacy"],
            serde_json::json!({ "generation": "3", "enabled": true })
        );
        let back: WorkerLaunchSpec = serde_json::from_value(json.clone()).expect("decodes");
        assert_eq!(back, private);

        let mut without = json.clone();
        without
            .as_object_mut()
            .expect("an object")
            .remove("privacy");
        assert!(
            serde_json::from_value::<WorkerLaunchSpec>(without).is_err(),
            "a specification that says nothing of privacy mode is refused"
        );
        let mut more = json;
        more["privacy"]["reason"] = serde_json::json!("because");
        assert!(
            serde_json::from_value::<WorkerLaunchSpec>(more).is_err(),
            "so is one that says more than a worker reads"
        );

        // The same on the wire a worker reads it from.
        let wire = ParamsValue::from_typed(&private).expect("encodes");
        assert_eq!(wire.to_typed::<WorkerLaunchSpec>().expect("reads"), private);
        let CanonicalValue::Map(map) = encoded(&private) else {
            panic!("a specification is a map");
        };
        let entries: Vec<_> = map
            .into_entries()
            .into_iter()
            .filter(|(name, _)| name != "privacy")
            .collect();
        let without = ParamsValue::new(CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries(entries).expect("the members"),
        ));
        assert!(
            without.to_typed::<WorkerLaunchSpec>().is_err(),
            "on the wire too"
        );
        let CanonicalValue::Map(map) = encoded(&private) else {
            panic!("a specification is a map");
        };
        let entries: Vec<_> = map
            .into_entries()
            .into_iter()
            .map(|(name, value)| match (name.as_str(), value) {
                ("privacy", CanonicalValue::Map(inner)) => {
                    let mut members = inner.into_entries();
                    members.push(("reason".to_owned(), CanonicalValue::text("because")));
                    (
                        name,
                        CanonicalValue::Map(
                            kr_cbor::CanonicalMap::from_entries(members).expect("the members"),
                        ),
                    )
                }
                (_, value) => (name, value),
            })
            .collect();
        let more = ParamsValue::new(CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries(entries).expect("the members"),
        ));
        assert!(
            more.to_typed::<WorkerLaunchSpec>().is_err(),
            "and one that says more than a worker reads, on the wire too"
        );

        // Privacy mode off at a later generation is as much a state as on, and travels the same.
        let off = specification(PrivacyLaunch {
            generation: U64::new(2),
            enabled: false,
        });
        assert_eq!(
            ParamsValue::from_typed(&off)
                .expect("encodes")
                .to_typed::<WorkerLaunchSpec>()
                .expect("reads"),
            off
        );
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
