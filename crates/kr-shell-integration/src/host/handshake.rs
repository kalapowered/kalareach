//! The worker's half of the `kr-shell-bridge/1` handshake.
//!
//! Three things happen here, and only the last of them decides anything.
//!
//! 1. **The kernel is asked who is calling.** The listener has already refused another user;
//!    [`observe`] reads the connecting process and its start identity from the operating system.
//!    Nothing in the hello contributes to that answer.
//! 2. **The proof is verified.** [`verify`] rebuilds the transcript from what the *worker* knows:
//!    its own session, its own endpoint and the root process it launched. Only the integration
//!    version comes from the hello, because a package computes its proof over the version it was
//!    built as and the contract checks that version separately. The comparison is HMAC-SHA-256 in
//!    constant time, and a tag that is not exactly 32 bytes fails without one.
//! 3. **The contract decides.** [`decide_handshake`] compares the observed process with the
//!    launched root shell and with the hello's own claim, then reads the verdict above, then the
//!    declaration. Its order is what names the refusal: a child that inherited the bootstrap
//!    values is refused as a different process rather than as a bad proof, whichever identity it
//!    claims.
//!
//! The secret never leaves this module: the contract takes a [`ProofVerdict`], not bytes.

use kr_crypto::kdf::{hmac_sha256, verify_hmac_sha256};
use kr_crypto::secret::SymmetricKey;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::{Bytes, Mac256};

use crate::contract::transport::{
    BridgeAccepted, BridgeEndpoint, BridgeHello, HandshakeOutcome, ObservedPeer, ProofVerdict,
    WorkerExpectation, bootstrap_transcript, decide_handshake,
};
use crate::host::error::Result;

/// Reads the kernel's view of the process on the other end of a connection.
///
/// A platform that will not name the process yields `None`, which [`decide_handshake`] refuses:
/// registering a root integration on an unidentified peer would make the whole contract rest on
/// the hello's own claim.
#[must_use]
pub fn observe(peer: &PeerIdentity) -> ObservedPeer {
    ObservedPeer {
        uid: peer.uid,
        process: peer
            .pid
            .and_then(|pid| kr_ipc::identity::process_start_identity(pid).ok()),
    }
}

/// Computes the proof a bridge presents.
///
/// The host computes it to compare, and the fixtures and the scripted bridge compute it to
/// present. One implementation, so a package that produces a different tag is wrong rather than
/// differently right.
///
/// # Errors
///
/// Returns [`crate::host::HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn proof(
    secret: &SymmetricKey,
    session_id: kr_protocol::ids::SessionId,
    endpoint: &BridgeEndpoint,
    shell_process: &ProcessStartIdentity,
    integration_version: &str,
) -> Result<Mac256> {
    let transcript =
        bootstrap_transcript(session_id, endpoint, shell_process, integration_version)?;
    Ok(hmac_sha256(secret, &transcript))
}

/// Verifies the proof a hello carried, against the root shell the worker launched.
///
/// The transcript is rebuilt from the worker's own values: its session, its endpoint and the
/// process identity it recorded when it started the root shell. The hello supplies only the
/// integration version, which a package computes its proof over and the contract checks against
/// what this build supports. So a proof taken over another process's identity fails here even
/// before the contract compares identities, and a short or long tag fails without a comparison.
///
/// # Errors
///
/// Returns [`crate::host::HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn verify(
    secret: &SymmetricKey,
    expectation: &WorkerExpectation,
    endpoint: &BridgeEndpoint,
    hello: &BridgeHello,
) -> Result<ProofVerdict> {
    let transcript = bootstrap_transcript(
        expectation.session_id,
        endpoint,
        &expectation.root_process,
        &hello.shell.integration_version,
    )?;
    let Ok(tag) = <[u8; Mac256::LEN]>::try_from(hello.proof.as_slice()) else {
        return Ok(ProofVerdict::Failed);
    };
    let tag = Mac256::from_bytes(tag);
    Ok(match verify_hmac_sha256(secret, &transcript, &tag) {
        Ok(()) => ProofVerdict::Verified,
        Err(_) => ProofVerdict::Failed,
    })
}

/// Decides one handshake end to end: the kernel's peer, the proof, then the contract's rules.
///
/// # Errors
///
/// Returns [`crate::host::HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn admit(
    secret: &SymmetricKey,
    expectation: &WorkerExpectation,
    endpoint: &BridgeEndpoint,
    peer: &PeerIdentity,
    hello: &BridgeHello,
) -> Result<HandshakeOutcome> {
    admit_observed(secret, expectation, endpoint, &observe(peer), hello)
}

/// Decides one handshake against an identity the caller has already observed.
///
/// [`admit`] is this with [`observe`] in front of it. They are separate because reading a process
/// identity is a syscall about a process that is running: a test that wants to state what the
/// kernel saw states it here rather than starting a process to be seen.
///
/// # Errors
///
/// Returns [`crate::host::HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn admit_observed(
    secret: &SymmetricKey,
    expectation: &WorkerExpectation,
    endpoint: &BridgeEndpoint,
    observed: &ObservedPeer,
    hello: &BridgeHello,
) -> Result<HandshakeOutcome> {
    let verdict = verify(secret, expectation, endpoint, hello)?;
    Ok(decide_handshake(expectation, observed, hello, verdict))
}

/// Builds the proof bytes a bridge puts in its hello.
///
/// # Errors
///
/// Returns [`crate::host::HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn proof_bytes(
    secret: &SymmetricKey,
    session_id: kr_protocol::ids::SessionId,
    endpoint: &BridgeEndpoint,
    shell_process: &ProcessStartIdentity,
    integration_version: &str,
) -> Result<Bytes> {
    let tag = proof(
        secret,
        session_id,
        endpoint,
        shell_process,
        integration_version,
    )?;
    Ok(Bytes::new(tag.as_bytes().to_vec()))
}

/// What an accepted handshake established about the registered bridge.
///
/// The worker keeps this beside the session: it is what a later root method is checked against, and
/// what diagnostics report the integration as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// What the worker answered with.
    pub accepted: BridgeAccepted,
    /// The shell the bridge declared, recorded whole.
    pub shell: crate::contract::transport::ShellIdentity,
    /// The mechanisms it implements.
    pub abi: crate::contract::qualification::BridgeAbi,
    /// The process the kernel saw connect.
    pub process: ProcessStartIdentity,
}

impl Registration {
    /// Builds the record of one accepted handshake.
    #[must_use]
    pub fn new(
        accepted: BridgeAccepted,
        hello: &BridgeHello,
        process: ProcessStartIdentity,
    ) -> Self {
        Self {
            accepted,
            shell: hello.shell.clone(),
            abi: hello.abi,
            process,
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_crypto::secret::Secret;
    use kr_protocol::identity::ProcessStartSource;
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::contract::events::EofGesture;
    use crate::contract::qualification::{QualificationReason, ShellKind};
    use crate::contract::transport::BridgeEndpoint;
    use crate::host::scripted::{REFERENCE_INTEGRATION_VERSION, ReferenceShell, qualified_hello};

    fn session() -> kr_protocol::ids::SessionId {
        kr_protocol::ids::SessionId::new(Uuid::from_bytes([0x33; 16]))
    }

    fn address() -> BridgeEndpoint {
        BridgeEndpoint::unix("/tmp/kalareach/s/shell-bridge")
    }

    fn root() -> ProcessStartIdentity {
        ProcessStartIdentity::new(3131, ProcessStartSource::MacosProcBsdInfo, 4242)
    }

    fn expectation() -> WorkerExpectation {
        WorkerExpectation {
            session_id: session(),
            root_process: root(),
            supported_editor_abis: vec!["zle-5.9".to_owned()],
            supported_integration_versions: vec![REFERENCE_INTEGRATION_VERSION.to_owned()],
            launched_package: None,
            already_registered: false,
            gesture: EofGesture::default(),
        }
    }

    fn hello(secret: &SymmetricKey, process: ProcessStartIdentity) -> BridgeHello {
        qualified_hello(
            &ReferenceShell::new(
                ShellKind::Zsh,
                "/opt/kalareach/shells/zsh-5.9/bin/zsh",
                "5.9",
                "zle-5.9",
            ),
            session(),
            &address(),
            process,
            secret,
        )
        .expect("a hello")
    }

    fn seen(process: &ProcessStartIdentity) -> ObservedPeer {
        ObservedPeer {
            uid: 501,
            process: Some(process.clone()),
        }
    }

    #[test]
    fn the_root_shells_own_proof_verifies_and_nothing_elses_does() {
        let secret = Secret::random().expect("a secret");
        let hello = hello(&secret, root());
        assert_eq!(
            verify(&secret, &expectation(), &address(), &hello).expect("verifies"),
            ProofVerdict::Verified
        );
        // Another session, another endpoint path, another root process and another secret each
        // break it.
        let other_session = WorkerExpectation {
            session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([0x44; 16])),
            ..expectation()
        };
        assert_eq!(
            verify(&secret, &other_session, &address(), &hello).expect("verifies"),
            ProofVerdict::Failed
        );
        assert_eq!(
            verify(
                &secret,
                &expectation(),
                &BridgeEndpoint::unix("/tmp/kalareach/t/shell-bridge"),
                &hello
            )
            .expect("verifies"),
            ProofVerdict::Failed
        );
        let other_root = WorkerExpectation {
            root_process: ProcessStartIdentity::new(
                3132,
                ProcessStartSource::MacosProcBsdInfo,
                4243,
            ),
            ..expectation()
        };
        assert_eq!(
            verify(&secret, &other_root, &address(), &hello).expect("verifies"),
            ProofVerdict::Failed
        );
        let elsewhere = Secret::random().expect("a secret");
        assert_eq!(
            verify(&elsewhere, &expectation(), &address(), &hello).expect("verifies"),
            ProofVerdict::Failed
        );
    }

    /// KR-REQ-07.17: the handshake compares the whole package record, not only the two versions.
    #[test]
    fn a_hello_that_describes_another_build_of_the_same_shell_is_refused() {
        use crate::contract::transport::{PackageDeclaration, PatchRevision};

        let secret = Secret::random().expect("a secret");
        let hello = hello(&secret, root());
        let launched = PackageDeclaration {
            kind: ShellKind::Zsh,
            executable: hello.shell.executable.clone(),
            upstream_version: hello.shell.upstream_version.clone(),
            editor_abi: hello.shell.editor_abi.clone(),
            integration_version: hello.shell.integration_version.clone(),
            patches: hello.shell.patches.clone(),
            modules: hello.shell.modules.clone(),
        };
        let expecting = |launched: PackageDeclaration| WorkerExpectation {
            launched_package: Some(launched),
            ..expectation()
        };
        assert!(matches!(
            admit_observed(
                &secret,
                &expecting(launched.clone()),
                &address(),
                &seen(&root()),
                &hello
            )
            .expect("decides"),
            HandshakeOutcome::Accepted(_)
        ));

        // Each of these is a different build of the same shell, and each agrees with the hello on
        // the editor ABI and the integration version.
        let elsewhere = PackageDeclaration {
            executable: "/opt/kalareach/shells/zsh-5.9-b/bin/zsh".to_owned(),
            ..launched.clone()
        };
        let older = PackageDeclaration {
            upstream_version: "5.8".to_owned(),
            ..launched.clone()
        };
        let repatched = PackageDeclaration {
            patches: vec![PatchRevision {
                name: "zle-reader-mailbox".to_owned(),
                upstream_revision: "5.9".to_owned(),
                revision: "2".to_owned(),
            }],
            ..launched.clone()
        };
        for other in [elsewhere, older, repatched] {
            let outcome = admit_observed(
                &secret,
                &expecting(other),
                &address(),
                &seen(&root()),
                &hello,
            )
            .expect("decides");
            match outcome {
                HandshakeOutcome::Refused(refusal) => {
                    assert_eq!(refusal.reason, QualificationReason::PackageMismatch);
                    assert_eq!(
                        refusal.error.code,
                        kr_protocol::error::ErrorCode::PermissionDenied
                    );
                }
                HandshakeOutcome::Accepted(_) => {
                    panic!("a different build is not this session's package")
                }
            }
        }
    }

    #[test]
    fn a_proof_of_the_wrong_length_fails_without_being_extended() {
        let secret = Secret::random().expect("a secret");
        let mut hello = hello(&secret, root());
        hello.proof = Bytes::new(hello.proof.as_slice()[..16].to_vec());
        assert_eq!(
            verify(&secret, &expectation(), &address(), &hello).expect("verifies"),
            ProofVerdict::Failed
        );
        let mut padded = self::hello(&secret, root());
        let mut bytes = padded.proof.as_slice().to_vec();
        bytes.push(0);
        padded.proof = Bytes::new(bytes);
        assert_eq!(
            verify(&secret, &expectation(), &address(), &padded).expect("verifies"),
            ProofVerdict::Failed
        );
    }

    #[test]
    fn the_kernels_view_decides_who_registered() {
        let secret = Secret::random().expect("a secret");
        let root_hello = hello(&secret, root());
        let outcome = admit_observed(
            &secret,
            &expectation(),
            &address(),
            &seen(&root()),
            &root_hello,
        )
        .expect("decides");
        assert_eq!(outcome.refusal(), None);
        // A child that inherited the bootstrap values computes a valid proof of its own and is
        // still refused: the process on the socket is not the one the worker launched.
        let child = ProcessStartIdentity::new(3132, ProcessStartSource::MacosProcBsdInfo, 4243);
        let child_hello = hello(&secret, child.clone());
        let refused = admit_observed(
            &secret,
            &expectation(),
            &address(),
            &seen(&child),
            &child_hello,
        )
        .expect("decides");
        assert_eq!(
            refused.refusal(),
            Some(QualificationReason::ProcessMismatch)
        );
        // A child that names its *parent's* identity is refused the same way: it can compute the
        // matching proof from the inherited secret, and it is still not the process the worker
        // launched.
        let claims_its_parent = admit_observed(
            &secret,
            &expectation(),
            &address(),
            &seen(&child),
            &root_hello,
        )
        .expect("decides");
        assert_eq!(
            claims_its_parent.refusal(),
            Some(QualificationReason::ProcessMismatch)
        );
        // And a platform that will not name the caller is no basis for registering anything.
        let unnamed = ObservedPeer {
            uid: 501,
            process: None,
        };
        assert_eq!(
            admit_observed(&secret, &expectation(), &address(), &unnamed, &root_hello)
                .expect("decides")
                .refusal(),
            Some(QualificationReason::PeerUnidentified)
        );
    }

    #[test]
    fn a_forged_proof_is_refused_by_its_own_name() {
        let secret = Secret::random().expect("a secret");
        let mut forged = hello(&secret, root());
        forged.proof = Bytes::new(vec![0; Mac256::LEN]);
        assert_eq!(
            admit_observed(&secret, &expectation(), &address(), &seen(&root()), &forged)
                .expect("decides")
                .refusal(),
            Some(QualificationReason::ProofMismatch)
        );
    }

    #[test]
    fn a_second_registration_is_refused() {
        let secret = Secret::random().expect("a secret");
        let expectation = WorkerExpectation {
            launched_package: None,
            already_registered: true,
            ..expectation()
        };
        assert_eq!(
            admit_observed(
                &secret,
                &expectation,
                &address(),
                &seen(&root()),
                &hello(&secret, root())
            )
            .expect("decides")
            .refusal(),
            Some(QualificationReason::AlreadyRegistered)
        );
    }

    #[test]
    fn the_registration_records_the_shell_it_accepted() {
        let secret = Secret::random().expect("a secret");
        let hello = hello(&secret, root());
        let HandshakeOutcome::Accepted(accepted) =
            admit_observed(&secret, &expectation(), &address(), &seen(&root()), &hello)
                .expect("decides")
        else {
            panic!("a qualified root shell registers");
        };
        let registration = Registration::new(accepted, &hello, root());
        assert_eq!(registration.shell.kind, ShellKind::Zsh);
        assert_eq!(registration.shell.editor_abi, "zle-5.9");
        assert_eq!(registration.process, root());
        assert_eq!(
            registration.accepted.secret_location,
            crate::contract::transport::SecretLocation::PrivateIntegrationState
        );
        assert_eq!(
            registration.accepted.unexport,
            crate::contract::transport::unexported_variables()
        );
    }
}
