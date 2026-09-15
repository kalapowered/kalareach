//! Proving which worker answers an endpoint, and which controller generation is calling.
//!
//! Three signatures, one rule: a filename, a process identifier and a descriptor on disk are
//! hints, and nothing acts on them until the process behind the endpoint has signed a challenge
//! that only it could answer.
//!
//! * **Rendezvous.** The worker generates a keypair at startup, keeps the private half in memory
//!   for its whole life, and signs the reservation it was started for. That is the one moment the
//!   controller learns which key belongs to which session.
//! * **Verification.** Every later client — a controller of any generation, or a `kr attach` with
//!   no controller at all — sends 32 fresh bytes and checks the answer against the descriptor's
//!   key, comparing every identity field with the descriptor as well. A descriptor whose challenge
//!   fails is quarantined, never spawned from.
//! * **Generation.** A controller signs the worker's own nonce with the environment's persistent
//!   identity key. A worker accepts its current generation again only after a fresh challenge,
//!   which fences that generation's previous connection; it refuses a lower generation and
//!   requires a strictly higher one from a replacement.

use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_crypto::secret::Secret;
use kr_crypto::sign;
use kr_crypto::store::{SecretStore, load_device_keys, store_device_keys};
use kr_protocol::hello::ProtocolVersion;
use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::{ControllerGeneration, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::{AuthorisationKey, Nonce256};
use kr_protocol::worker::{
    CONTROLLER_GENERATION_DOMAIN, ControllerGenerationToken, GenerationRefusal,
    WORKER_RENDEZVOUS_DOMAIN, WORKER_VERIFY_DOMAIN, WorkerDescriptor, WorkerRendezvous,
    WorkerVerifyChallenge, WorkerVerifyProof, generation_elements, rendezvous_elements,
    verify_elements,
};

use crate::error::IpcError;

/// A failure of one of the three proofs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// A cryptographic operation failed, including a signature that did not verify.
    #[error("{0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// The answer did not match the descriptor it was checked against.
    #[error("the worker answered with a different {field}")]
    IdentityMismatch {
        /// Which field disagreed.
        field: &'static str,
    },
    /// The controller's generation token was refused.
    #[error("the controller generation was refused: {0:?}")]
    GenerationRefused(GenerationRefusal),
    /// An identity was to be created but one already exists.
    #[error("this environment already has a controller identity")]
    IdentityAlreadyPresent,
    /// An identity was expected and the secret store does not hold it.
    #[error(
        "this environment's controller identity is missing; every live worker holds its public key, so it cannot be replaced without closing them"
    )]
    IdentityMissing,
}

impl From<VerificationError> for IpcError {
    fn from(error: VerificationError) -> Self {
        Self::IdentityUnavailable {
            what: "worker verification",
            detail: error.to_string(),
        }
    }
}

/// The result of a proof check.
pub type VerificationResult<T> = std::result::Result<T, VerificationError>;

/// Generates a fresh 32-byte challenge from the operating system's random generator.
///
/// # Errors
///
/// Returns an error when the random generator is unavailable.
pub fn fresh_challenge() -> VerificationResult<WorkerVerifyChallenge> {
    let secret = Secret::<32>::random()?;
    Ok(WorkerVerifyChallenge {
        nonce: Nonce256::from_bytes(*secret.expose()),
    })
}

/// A worker's per-session signing identity.
///
/// The private key exists only here, in memory, and is zeroised when the worker exits. It is never
/// written to disk, passed in an argument vector or placed in an environment variable, so a
/// process that is not this worker cannot answer for it even with full access to the runtime
/// directory.
#[derive(Debug)]
pub struct WorkerIdentity {
    keypair: AuthorisationKeyPair,
    session_id: SessionId,
    session_epoch: SessionEpoch,
    boot_identity: BootIdentity,
    process_start_identity: ProcessStartIdentity,
    protocol_version: ProtocolVersion,
}

impl WorkerIdentity {
    /// Generates a fresh per-session keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when the cryptographic library is unavailable.
    pub fn generate(
        session_id: SessionId,
        session_epoch: SessionEpoch,
        boot_identity: BootIdentity,
        process_start_identity: ProcessStartIdentity,
        protocol_version: ProtocolVersion,
    ) -> VerificationResult<Self> {
        Ok(Self {
            keypair: AuthorisationKeyPair::generate()?,
            session_id,
            session_epoch,
            boot_identity,
            process_start_identity,
            protocol_version,
        })
    }

    /// Returns the public half, which the controller records and descriptors carry.
    #[must_use]
    pub const fn public_key(&self) -> &AuthorisationKey {
        self.keypair.public()
    }

    /// Returns the session this identity belongs to.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the boot the worker started in.
    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    /// Returns the worker's own process identity.
    #[must_use]
    pub const fn process_start_identity(&self) -> &ProcessStartIdentity {
        &self.process_start_identity
    }

    /// Builds the signed startup claim for one reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the transcript cannot be encoded or signed.
    pub fn rendezvous(
        &self,
        reservation_id: kr_protocol::worker::ReservationId,
    ) -> VerificationResult<WorkerRendezvous> {
        let elements = rendezvous_elements(
            reservation_id,
            self.session_id,
            self.keypair.public(),
            &self.boot_identity,
            &self.process_start_identity,
        )
        .map_err(kr_crypto::CryptoError::from)?;
        let signature = sign::sign_elements(&self.keypair, WORKER_RENDEZVOUS_DOMAIN, elements)?;
        Ok(WorkerRendezvous {
            reservation_id,
            session_id: self.session_id,
            worker_public_key: *self.keypair.public(),
            boot_identity: self.boot_identity.clone(),
            process_start_identity: self.process_start_identity.clone(),
            signature,
        })
    }

    /// Answers a challenge on one endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the transcript cannot be encoded or signed.
    pub fn answer(
        &self,
        challenge: &WorkerVerifyChallenge,
        endpoint: &str,
    ) -> VerificationResult<WorkerVerifyProof> {
        let elements = verify_elements(
            self.session_id,
            self.session_epoch,
            &self.boot_identity,
            &self.process_start_identity,
            self.protocol_version,
            endpoint,
            &challenge.nonce,
        )
        .map_err(kr_crypto::CryptoError::from)?;
        let signature = sign::sign_elements(&self.keypair, WORKER_VERIFY_DOMAIN, elements)?;
        Ok(WorkerVerifyProof {
            session_id: self.session_id,
            session_epoch: self.session_epoch,
            boot_identity: self.boot_identity.clone(),
            process_start_identity: self.process_start_identity.clone(),
            protocol_version: self.protocol_version,
            endpoint: endpoint.to_owned(),
            signature,
        })
    }
}

/// Checks that a startup claim is signed by the key it presents.
///
/// This is only the cryptographic half. The controller still has to match the reservation, compare
/// the connecting peer's process identity with what the launcher reported, and refuse a second
/// rendezvous for the same reservation.
///
/// # Errors
///
/// Returns an error when the signature does not verify.
pub fn check_rendezvous(rendezvous: &WorkerRendezvous) -> VerificationResult<()> {
    let elements = rendezvous_elements(
        rendezvous.reservation_id,
        rendezvous.session_id,
        &rendezvous.worker_public_key,
        &rendezvous.boot_identity,
        &rendezvous.process_start_identity,
    )
    .map_err(kr_crypto::CryptoError::from)?;
    sign::verify_elements(
        &rendezvous.worker_public_key,
        WORKER_RENDEZVOUS_DOMAIN,
        elements,
        &rendezvous.signature,
    )?;
    Ok(())
}

/// Checks a challenge answer against a descriptor.
///
/// Both halves matter. The signature proves the private key is present; the field comparison
/// proves the descriptor describes this worker. A process that holds the key but answers with a
/// different session, epoch, boot or process identity is refused.
///
/// # Errors
///
/// Returns [`VerificationError::IdentityMismatch`] when a field disagrees with the descriptor, and
/// a cryptographic error when the signature does not verify.
pub fn check_proof(
    descriptor: &WorkerDescriptor,
    challenge: &WorkerVerifyChallenge,
    proof: &WorkerVerifyProof,
) -> VerificationResult<()> {
    check_proof_against(
        &descriptor.worker_public_key,
        descriptor.session_id,
        descriptor.session_epoch,
        &descriptor.endpoint,
        challenge,
        proof,
    )?;
    if proof.boot_identity != descriptor.boot_identity {
        return Err(VerificationError::IdentityMismatch { field: "boot" });
    }
    if proof.process_start_identity != descriptor.process_start_identity {
        return Err(VerificationError::IdentityMismatch {
            field: "process start identity",
        });
    }
    if proof.protocol_version != descriptor.protocol_version {
        return Err(VerificationError::IdentityMismatch {
            field: "protocol version",
        });
    }
    Ok(())
}

/// Checks a worker's answer against a key and the identity a caller already knows.
///
/// A controller that lost its published descriptor still knows three things from its own registry:
/// the key the rendezvous established, the session that key answers for, and the endpoint that
/// session was given. That is enough to challenge the worker and rebuild the descriptor from its
/// answer, which is what recovery does rather than starting a second worker.
///
/// # Errors
///
/// Returns [`VerificationError::IdentityMismatch`] when a field disagrees with what the caller
/// knows, and a cryptographic error when the signature does not verify.
pub fn check_proof_against(
    worker_public_key: &AuthorisationKey,
    session_id: SessionId,
    session_epoch: SessionEpoch,
    endpoint: &str,
    challenge: &WorkerVerifyChallenge,
    proof: &WorkerVerifyProof,
) -> VerificationResult<()> {
    if proof.session_id != session_id {
        return Err(VerificationError::IdentityMismatch { field: "session" });
    }
    if proof.session_epoch != session_epoch {
        return Err(VerificationError::IdentityMismatch {
            field: "session epoch",
        });
    }
    if proof.endpoint != endpoint {
        return Err(VerificationError::IdentityMismatch { field: "endpoint" });
    }
    let elements = verify_elements(
        proof.session_id,
        proof.session_epoch,
        &proof.boot_identity,
        &proof.process_start_identity,
        proof.protocol_version,
        &proof.endpoint,
        &challenge.nonce,
    )
    .map_err(kr_crypto::CryptoError::from)?;
    sign::verify_elements(
        worker_public_key,
        WORKER_VERIFY_DOMAIN,
        elements,
        &proof.signature,
    )?;
    Ok(())
}

/// The name the controller's key set is stored under.
pub const CONTROLLER_SECRET_SERVICE: &str = "KalaReach";

/// The persistent per-environment identity a controller signs generation tokens with.
///
/// Rotating it requires closing every live worker, because each worker recorded the public half at
/// spawn and a worker that has not seen the new key cannot tell a rotation from an impostor. That
/// is a documented procedure, never something that happens on its own.
#[derive(Debug)]
pub struct ControllerIdentity {
    keys: DeviceKeys,
    environment_id: EnvironmentId,
}

impl ControllerIdentity {
    /// Creates the environment's identity for the first time.
    ///
    /// This is a deliberate first-start step, taken under the singleton lock. It is separate from
    /// [`ControllerIdentity::load`] because the two failures look identical from inside a process
    /// and mean opposite things: an empty store on first start is normal, and an empty store on a
    /// later start means the key is lost. Generating a fresh key in the second case would leave
    /// every live worker holding a public key that no longer answers, and section C's rule that
    /// rotation closes all live workers would have been broken silently.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity already exists, or when the store cannot be written.
    pub fn initialise(
        store: &dyn SecretStore,
        environment_id: EnvironmentId,
    ) -> VerificationResult<Self> {
        let scope = environment_id.to_string();
        if load_device_keys(store, &scope)?.is_some() {
            return Err(VerificationError::IdentityAlreadyPresent);
        }
        let keys = DeviceKeys::generate()?;
        store_device_keys(store, &scope, &keys)?;
        Ok(Self {
            keys,
            environment_id,
        })
    }

    /// Loads the environment's existing identity.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::IdentityMissing`] when no identity has been created, which is
    /// a recovery condition rather than an invitation to make a new one.
    pub fn load(
        store: &dyn SecretStore,
        environment_id: EnvironmentId,
    ) -> VerificationResult<Self> {
        let scope = environment_id.to_string();
        let keys = load_device_keys(store, &scope)?.ok_or(VerificationError::IdentityMissing)?;
        Ok(Self {
            keys,
            environment_id,
        })
    }

    /// Loads the environment's identity, creating it only on a genuine first start.
    ///
    /// The caller states whether this host has ever initialised its identity. A host that has is
    /// never given a fresh key.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or written, or when an identity that was
    /// recorded as present is missing.
    pub fn open(
        store: &dyn SecretStore,
        environment_id: EnvironmentId,
        initialised_before: bool,
    ) -> VerificationResult<Self> {
        if initialised_before {
            Self::load(store, environment_id)
        } else {
            match Self::initialise(store, environment_id) {
                Err(VerificationError::IdentityAlreadyPresent) => Self::load(store, environment_id),
                other => other,
            }
        }
    }

    /// Returns the public key a worker records at spawn.
    #[must_use]
    pub const fn public_key(&self) -> &AuthorisationKey {
        self.keys.authorisation.public()
    }

    /// Returns the environment this identity belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Signs a generation token answering a worker's challenge.
    ///
    /// # Errors
    ///
    /// Returns an error when the transcript cannot be encoded or signed.
    pub fn generation_token(
        &self,
        generation: ControllerGeneration,
        boot_identity: &BootIdentity,
        nonce: &Nonce256,
    ) -> VerificationResult<ControllerGenerationToken> {
        let elements = generation_elements(self.environment_id, generation, boot_identity, nonce)
            .map_err(kr_crypto::CryptoError::from)?;
        let signature = sign::sign_elements(
            &self.keys.authorisation,
            CONTROLLER_GENERATION_DOMAIN,
            elements,
        )?;
        Ok(ControllerGenerationToken {
            environment_id: self.environment_id,
            generation,
            boot_identity: boot_identity.clone(),
            nonce: *nonce,
            signature,
        })
    }
}

/// What a worker knows about the controller it will accept.
#[derive(Clone, Debug)]
pub struct GenerationAcceptance {
    /// The controller public key recorded at spawn.
    pub controller_public_key: AuthorisationKey,
    /// The environment the worker belongs to.
    pub environment_id: EnvironmentId,
    /// The boot the worker is running in.
    pub boot_identity: BootIdentity,
    /// The highest generation this worker has already accepted, if any.
    pub accepted_generation: Option<ControllerGeneration>,
}

/// Checks a controller's generation token against what the worker will accept.
///
/// The current generation is accepted again, which is what lets a controller reconnect after a
/// dropped connection; each acceptance fences that generation's previous connection. A lower
/// generation is refused outright, so a controller that lost the singleton lock cannot reattach.
///
/// # Errors
///
/// Returns [`VerificationError::GenerationRefused`] with the reason, or a cryptographic error when
/// the signature does not verify.
pub fn check_generation_token(
    acceptance: &GenerationAcceptance,
    issued_nonce: &Nonce256,
    token: &ControllerGenerationToken,
) -> VerificationResult<()> {
    if token.environment_id != acceptance.environment_id {
        return Err(VerificationError::GenerationRefused(
            GenerationRefusal::WrongEnvironment,
        ));
    }
    if &token.nonce != issued_nonce {
        return Err(VerificationError::GenerationRefused(
            GenerationRefusal::StaleChallenge,
        ));
    }
    if token.boot_identity != acceptance.boot_identity {
        return Err(VerificationError::GenerationRefused(
            GenerationRefusal::WrongBoot,
        ));
    }
    if let Some(accepted) = acceptance.accepted_generation
        && token.generation.get() < accepted.get()
    {
        return Err(VerificationError::GenerationRefused(
            GenerationRefusal::GenerationSuperseded,
        ));
    }
    let elements = generation_elements(
        token.environment_id,
        token.generation,
        &token.boot_identity,
        &token.nonce,
    )
    .map_err(kr_crypto::CryptoError::from)?;
    sign::verify_elements(
        &acceptance.controller_public_key,
        CONTROLLER_GENERATION_DOMAIN,
        elements,
        &token.signature,
    )
    .map_err(|_| VerificationError::GenerationRefused(GenerationRefusal::SignatureInvalid))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use kr_crypto::store::MemoryStore;
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::identity::{BootIdentitySource, ProcessStartSource, WorkerProfile};
    use kr_protocol::scalars::{Bytes, TimestampMs, Uuid};
    use kr_protocol::session::DisplayNumber;
    use kr_protocol::worker::ReservationId;

    use super::*;

    fn boot(tag: u8) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: Bytes::new(vec![tag; 4]),
        }
    }

    fn start(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::LinuxProcStat, 1234)
    }

    fn identity() -> WorkerIdentity {
        WorkerIdentity::generate(
            SessionId::new(Uuid::from_bytes([1; 16])),
            SessionEpoch::V1,
            boot(1),
            start(4242),
            PROTOCOL_VERSION,
        )
        .expect("generates")
    }

    fn descriptor_for(identity: &WorkerIdentity, endpoint: &str) -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: identity.session_id,
            session_epoch: identity.session_epoch,
            environment_id: EnvironmentId::new(Uuid::NIL),
            display_number: DisplayNumber::new(1),
            boot_identity: identity.boot_identity.clone(),
            process_start_identity: identity.process_start_identity.clone(),
            protocol_version: identity.protocol_version,
            endpoint: endpoint.to_owned(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_worker_answers_its_own_challenge() {
        let identity = identity();
        let descriptor = descriptor_for(&identity, "/run/w1.sock");
        let challenge = fresh_challenge().expect("a challenge");
        let proof = identity
            .answer(&challenge, "/run/w1.sock")
            .expect("answers");
        check_proof(&descriptor, &challenge, &proof).expect("verifies");
    }

    #[test]
    fn two_challenges_are_never_the_same() {
        let first = fresh_challenge().expect("a challenge");
        let second = fresh_challenge().expect("a challenge");
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn an_answer_to_a_different_challenge_is_refused() {
        let identity = identity();
        let descriptor = descriptor_for(&identity, "/run/w1.sock");
        let issued = fresh_challenge().expect("a challenge");
        let replayed = identity
            .answer(&fresh_challenge().expect("a challenge"), "/run/w1.sock")
            .expect("answers");
        assert!(check_proof(&descriptor, &issued, &replayed).is_err());
    }

    #[test]
    fn another_worker_cannot_answer_for_this_descriptor() {
        let real = identity();
        let descriptor = descriptor_for(&real, "/run/w1.sock");
        let impostor = identity();
        let challenge = fresh_challenge().expect("a challenge");
        let proof = impostor
            .answer(&challenge, "/run/w1.sock")
            .expect("answers");
        assert!(check_proof(&descriptor, &challenge, &proof).is_err());
    }

    #[test]
    fn a_descriptor_naming_a_different_boot_is_refused() {
        let identity = identity();
        let mut descriptor = descriptor_for(&identity, "/run/w1.sock");
        descriptor.boot_identity = boot(2);
        let challenge = fresh_challenge().expect("a challenge");
        let proof = identity
            .answer(&challenge, "/run/w1.sock")
            .expect("answers");
        assert!(matches!(
            check_proof(&descriptor, &challenge, &proof),
            Err(VerificationError::IdentityMismatch { field: "boot" })
        ));
    }

    #[test]
    fn an_answer_from_a_different_endpoint_is_refused() {
        let identity = identity();
        let descriptor = descriptor_for(&identity, "/run/w1.sock");
        let challenge = fresh_challenge().expect("a challenge");
        let proof = identity
            .answer(&challenge, "/run/other.sock")
            .expect("answers");
        assert!(check_proof(&descriptor, &challenge, &proof).is_err());
    }

    #[test]
    fn a_rendezvous_is_signed_by_the_key_it_presents() {
        let worker = identity();
        let reservation = ReservationId::new(Uuid::from_bytes([9; 16]));
        let rendezvous = worker.rendezvous(reservation).expect("signs");
        check_rendezvous(&rendezvous).expect("verifies");

        let other = identity();
        let mut forged = rendezvous.clone();
        forged.worker_public_key = *other.public_key();
        assert!(check_rendezvous(&forged).is_err());
    }

    #[test]
    fn a_controller_identity_is_generated_once_and_then_loaded() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let first = ControllerIdentity::initialise(&store, environment).expect("generates");
        let second = ControllerIdentity::load(&store, environment).expect("loads");
        assert_eq!(first.public_key(), second.public_key());
        assert!(matches!(
            ControllerIdentity::initialise(&store, environment),
            Err(VerificationError::IdentityAlreadyPresent)
        ));
    }

    #[test]
    fn a_lost_identity_is_a_recovery_error_rather_than_a_silent_rotation() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([6; 16]));
        assert!(matches!(
            ControllerIdentity::load(&store, environment),
            Err(VerificationError::IdentityMissing)
        ));
        assert!(matches!(
            ControllerIdentity::open(&store, environment, true),
            Err(VerificationError::IdentityMissing)
        ));
    }

    #[test]
    fn a_generation_token_answers_the_workers_own_challenge() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let controller = ControllerIdentity::initialise(&store, environment).expect("generates");
        let acceptance = GenerationAcceptance {
            controller_public_key: *controller.public_key(),
            environment_id: environment,
            boot_identity: boot(1),
            accepted_generation: Some(ControllerGeneration::new(3)),
        };
        let nonce = fresh_challenge().expect("a challenge").nonce;
        let token = controller
            .generation_token(ControllerGeneration::new(4), &boot(1), &nonce)
            .expect("signs");
        check_generation_token(&acceptance, &nonce, &token).expect("accepted");
    }

    #[test]
    fn the_same_generation_is_accepted_again_after_a_fresh_challenge() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let controller = ControllerIdentity::initialise(&store, environment).expect("generates");
        let acceptance = GenerationAcceptance {
            controller_public_key: *controller.public_key(),
            environment_id: environment,
            boot_identity: boot(1),
            accepted_generation: Some(ControllerGeneration::new(4)),
        };
        let nonce = fresh_challenge().expect("a challenge").nonce;
        let token = controller
            .generation_token(ControllerGeneration::new(4), &boot(1), &nonce)
            .expect("signs");
        check_generation_token(&acceptance, &nonce, &token).expect("accepted");
    }

    #[test]
    fn a_lower_generation_is_refused() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let controller = ControllerIdentity::initialise(&store, environment).expect("generates");
        let acceptance = GenerationAcceptance {
            controller_public_key: *controller.public_key(),
            environment_id: environment,
            boot_identity: boot(1),
            accepted_generation: Some(ControllerGeneration::new(7)),
        };
        let nonce = fresh_challenge().expect("a challenge").nonce;
        let token = controller
            .generation_token(ControllerGeneration::new(6), &boot(1), &nonce)
            .expect("signs");
        assert!(matches!(
            check_generation_token(&acceptance, &nonce, &token),
            Err(VerificationError::GenerationRefused(
                GenerationRefusal::GenerationSuperseded
            ))
        ));
    }

    #[test]
    fn a_replayed_generation_token_is_refused() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let controller = ControllerIdentity::initialise(&store, environment).expect("generates");
        let acceptance = GenerationAcceptance {
            controller_public_key: *controller.public_key(),
            environment_id: environment,
            boot_identity: boot(1),
            accepted_generation: None,
        };
        let first = fresh_challenge().expect("a challenge").nonce;
        let token = controller
            .generation_token(ControllerGeneration::new(1), &boot(1), &first)
            .expect("signs");
        let second = fresh_challenge().expect("a challenge").nonce;
        assert!(matches!(
            check_generation_token(&acceptance, &second, &token),
            Err(VerificationError::GenerationRefused(
                GenerationRefusal::StaleChallenge
            ))
        ));
    }

    #[test]
    fn a_token_from_another_environment_key_is_refused() {
        let store = MemoryStore::new();
        let environment = EnvironmentId::new(Uuid::from_bytes([5; 16]));
        let controller = ControllerIdentity::initialise(&store, environment).expect("generates");
        let other_store = MemoryStore::new();
        let impostor =
            ControllerIdentity::initialise(&other_store, environment).expect("generates");
        let acceptance = GenerationAcceptance {
            controller_public_key: *controller.public_key(),
            environment_id: environment,
            boot_identity: boot(1),
            accepted_generation: None,
        };
        let nonce = fresh_challenge().expect("a challenge").nonce;
        let token = impostor
            .generation_token(ControllerGeneration::new(1), &boot(1), &nonce)
            .expect("signs");
        assert!(matches!(
            check_generation_token(&acceptance, &nonce, &token),
            Err(VerificationError::GenerationRefused(
                GenerationRefusal::SignatureInvalid
            ))
        ));
    }
}
