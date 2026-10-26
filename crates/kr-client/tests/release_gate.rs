//! The release gate on the managed relay lease service: what a build the signed matrix does not
//! list is refused, and what it never is.
//!
//! KR-REQ-17.46: unsupported skew returns a route error with the configured alternatives. The
//! gate refuses a request for a new lease and a pairing admission before anything is sent, and
//! leaves everything else going: the refill of a lease the host holds, the revocation of one, and
//! the payer's sign-in. The service is the stand-in held to the Worker's source; what each case
//! decides on is what the stand-in saw arrive, by path.

use std::sync::Arc;

use kr_client::error::ClientError;
use kr_client::retry::UserAction;
use kr_client::services::account::AccountToken;
use kr_client::services::matrix::{HeldMatrix, Pins, ReleaseGate};
use kr_client::services::{
    AdmissionRequest, LeaseEndReason, LeaseRequest, ManagedPairingAdmission,
    ManagedRelayLeaseService, PairingAdmissionService, RelayDirection, RelayLeaseAnswer,
    RelayLeaseService, ServiceSigner,
};
use kr_client::{ClientError as Error, Result};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PackageVersion;
use kr_protocol::ids::RelayLeaseId;
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ServiceWeb, signed_release_matrix};
use serde_json::{Value, json};

const LEASE: &str = "/api/relay/lease";
const REVOKE: &str = "/api/relay/lease/revoke";
const PAYER: &str = "/api/relay/payer-authorisation/sign-in";
const ADMISSION: &str = "/api/relay/admission";

fn this_build() -> PackageVersion {
    PackageVersion::new(0, 78, 0)
}

/// An installation's authorisation key, held the way a client holds one.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

fn endpoint(byte: u8) -> EndpointKey {
    EndpointKey::from_bytes([byte; 32])
}

fn lease(naming: Option<RelayLeaseId>) -> LeaseRequest {
    LeaseRequest {
        source: endpoint(0x11),
        destination: endpoint(0x22),
        direction: RelayDirection::Bidirectional,
        byte_ceiling: 4 * 1024 * 1024,
        duration_seconds: 300,
        region_preference: None,
        payer: None,
        lease_id: naming,
    }
}

fn admission() -> AdmissionRequest {
    AdmissionRequest {
        host: endpoint(0x11),
        candidate: endpoint(0x22),
        relay_url: "https://relay-1.reach.kala.to".to_owned(),
    }
}

/// A matrix whose two tiers both list the clients from 0.70.0 up to `highest`.
fn matrix(revision: &str, highest: &str) -> Value {
    let tier = |id: &str, compatible: bool| {
        json!({
            "id": id,
            "compatible": compatible,
            "note": "",
            "client": { "minimum": "0.70.0", "maximum": highest },
            "relay": { "minimum": "1.2.0", "maximum": "1.2.99" },
            "discovery": { "minimum": "1.2.0", "maximum": "1.2.99" },
        })
    };
    json!({
        "schemaVersion": 1,
        "revision": revision,
        "issuedAt": "2026-10-27",
        "installedClientWindowDays": 90,
        "alternatives": ["direct", "self-hosted-relay", "self-hosted-discovery"],
        "tiers": [tier("compatible", true), tier("current", false)],
    })
}

/// A matrix that lists this build (0.78.0).
fn supporting(revision: &str) -> Value {
    matrix(revision, "0.78.99")
}

/// A matrix that lists nothing at 0.78.
fn skewing(revision: &str) -> Value {
    matrix(revision, "0.77.99")
}

/// The stand-in, the signer of its matrix, and the copy a host holds of it.
struct Host {
    web: Arc<ServiceWeb>,
    origin: GatewayOrigin,
    held: HeldMatrix,
    matrix_key: AuthorisationKeyPair,
    signer: Arc<Installation>,
}

impl Host {
    fn start() -> Self {
        let web = Arc::new(ServiceWeb::new());
        let origin = GatewayOrigin::new(web.origin()).expect("an origin");
        Self {
            web,
            origin,
            held: HeldMatrix::none(),
            matrix_key: AuthorisationKeyPair::generate().expect("a key pair"),
            signer: Arc::new(Installation(
                AuthorisationKeyPair::generate().expect("a key pair"),
            )),
        }
    }

    /// The host reads `matrix` as `by`.
    fn read(&self, matrix: &Value, by: PackageVersion) {
        let body =
            serde_json::to_vec(&signed_release_matrix(matrix, &self.matrix_key)).expect("a reply");
        self.held
            .accept(
                &Pins::of(vec![*self.matrix_key.public()]),
                self.origin.as_str(),
                by,
                1,
                &body,
            )
            .expect("an accepted reply");
    }

    fn gate(&self) -> Arc<ReleaseGate> {
        Arc::new(ReleaseGate::new(
            self.held.clone(),
            self.origin.clone(),
            this_build(),
            false,
        ))
    }

    fn leases(&self) -> ManagedRelayLeaseService {
        ManagedRelayLeaseService::new(
            self.origin.clone(),
            Arc::clone(&self.web) as _,
            self.signer.clone(),
        )
        .gated_by(self.gate())
    }

    fn admissions(&self) -> ManagedPairingAdmission {
        ManagedPairingAdmission::new(
            self.origin.clone(),
            Arc::clone(&self.web) as _,
            self.signer.clone(),
        )
        .gated_by(self.gate())
    }

    fn arrived(&self, path: &str) -> usize {
        self.web.requests_to(path)
    }
}

fn is_the_route_error(error: &Error) -> bool {
    matches!(
        error,
        ClientError::Refused {
            error,
            retry_after_seconds: None,
            action: UserAction::Update,
            service_code: None,
        } if error.code == ErrorCode::UnsupportedCapability
    )
}

fn token() -> AccountToken {
    AccountToken::new("a-token-the-service-did-not-issue").expect("a token")
}

/// The ids of the lease a host that was served got, for naming it later.
async fn granted(leases: &ManagedRelayLeaseService) -> RelayLeaseId {
    match leases.issue(&lease(None)).await.expect("an answer") {
        RelayLeaseAnswer::Granted(grant) => grant.lease.lease.lease_id,
        _ => panic!("a lease was not granted"),
    }
}

/// KR-REQ-17.46: a build the verified matrix does not list is refused a new lease and a pairing
/// admission with the route error, and the stand-in sees nothing; a refill, a revocation and the
/// payer's sign-in are sent.
#[tokio::test]
async fn a_skewed_build_is_refused_what_takes_a_new_lease_and_nothing_else() {
    let host = Host::start();
    let leases = host.leases();
    let admissions = host.admissions();

    // The host holds a lease it was granted while the matrix listed it, and the matrix then drops
    // this build.
    host.read(&supporting("4"), this_build());
    let held_lease = granted(&leases).await;
    host.read(&skewing("5"), this_build());
    let (asked_leases, asked_admissions) = (host.arrived(LEASE), host.arrived(ADMISSION));

    let refused = leases.issue(&lease(None)).await.expect_err("a refusal");
    assert!(
        is_the_route_error(&refused),
        "a new lease gets the route error"
    );
    let refused = admissions.admit(&admission()).await.expect_err("a refusal");
    assert!(is_the_route_error(&refused), "an admission gets it too");
    assert_eq!(
        host.arrived(LEASE),
        asked_leases,
        "no lease request left the host"
    );
    assert_eq!(
        host.arrived(ADMISSION),
        asked_admissions,
        "no admission left it"
    );

    // A refill names the lease the host holds, and passes.
    let refilled = leases.issue(&lease(Some(held_lease))).await;
    assert!(
        !matches!(&refilled, Err(error) if is_the_route_error(error)),
        "a refill is never the route error"
    );
    assert_eq!(host.arrived(LEASE), asked_leases + 1, "the refill arrived");

    // A revocation and the payer's sign-in are sent, whatever the service answers.
    let _ = leases.revoke(held_lease, LeaseEndReason::Finished).await;
    assert_eq!(host.arrived(REVOKE), 1, "the revocation arrived");
    let signed_in = leases.sign_in_payer("account-one", &token()).await;
    assert!(
        !matches!(&signed_in, Err(error) if is_the_route_error(error)),
        "the payer's sign-in is never the route error"
    );
    assert_eq!(host.arrived(PAYER), 1, "the sign-in arrived");
}

/// KR-REQ-17.46: a build the matrix lists, and a host that holds no verified copy for it, are
/// refused nothing: every request reaches the service.
#[tokio::test]
async fn a_listed_build_and_a_build_with_no_copy_of_its_own_are_refused_nothing() {
    // Listed: a build the matrix lists is served a tier, and is not refused.
    let host = Host::start();
    host.read(&supporting("4"), this_build());
    let (leases, admissions) = (host.leases(), host.admissions());
    granted(&leases).await;
    assert!(admissions.admit(&admission()).await.is_ok());
    assert_eq!(host.arrived(LEASE), 1);
    assert_eq!(host.arrived(ADMISSION), 1);

    // No copy at all: the built-in compatible tier stands.
    let host = Host::start();
    let (leases, admissions) = (host.leases(), host.admissions());
    granted(&leases).await;
    assert!(admissions.admit(&admission()).await.is_ok());
    assert_eq!((host.arrived(LEASE), host.arrived(ADMISSION)), (1, 1));

    // A copy an older build read, which lists nothing for this one: not this build's finding, so
    // nothing is refused until a read by this build says so.
    let host = Host::start();
    host.read(&skewing("5"), PackageVersion::new(0, 77, 4));
    let (leases, admissions) = (host.leases(), host.admissions());
    granted(&leases).await;
    assert!(admissions.admit(&admission()).await.is_ok());
    assert_eq!((host.arrived(LEASE), host.arrived(ADMISSION)), (1, 1));

    // The same copy, read again by this build, is its finding: now a new lease is refused.
    host.read(&skewing("5"), this_build());
    let refused = leases.issue(&lease(None)).await.expect_err("a refusal");
    assert!(is_the_route_error(&refused));
    assert_eq!(host.arrived(LEASE), 1, "and nothing was sent");
}

/// KR-REQ-17.46: the gate opens when a higher revision lists the build.
#[tokio::test]
async fn a_revision_that_lists_the_build_opens_the_gate_again() {
    let host = Host::start();
    let leases = host.leases();
    host.read(&skewing("5"), this_build());
    assert!(is_the_route_error(
        &leases.issue(&lease(None)).await.expect_err("a refusal")
    ));
    assert_eq!(host.arrived(LEASE), 0);

    host.read(&supporting("6"), this_build());
    granted(&leases).await;
    assert_eq!(
        host.arrived(LEASE),
        1,
        "the next new lease reaches the service"
    );
}
