//! Pairing admission, from the client's side: what it asks the managed service for, what it keeps,
//! and what it never does.
//!
//! A device that holds no lease with a host cannot reach it through a managed relay, so as it dials
//! it asks the managed service for an admission (section 17's bounded bootstrap allowance, drawn
//! from the free-service abuse budget). The service here is the stand-in held to the Worker's
//! source, over the client's real credential, so what is checked is the request the Worker reads and
//! the answers it gives. What the cache keeps is decided by a clock the test moves.
//!
//! The vector is pinned here and in `infra/relay/vectors/admission.json` in the website repository,
//! where the service rebuilds the same bytes from the JSON it receives.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::admission::RelayAdmissionIssueBody;
use kr_client::services::{
    AdmissionAnswer, AdmissionClock, AdmissionRequest, LeaseRequest, ManagedPairingAdmission,
    ManagedRelayLeaseService, PairingAdmissionService, PairingAdmissions, RelayDirection,
    RelayLeaseService, ServiceFuture, ServiceSigner,
};
use kr_client::{ClientError as Error, Result};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::ErrorCode;
use kr_protocol::pairing::{NetworkConfig, NetworkHint};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Nullable, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{AdmissionBehaviour, ServiceWeb};

/// The canonical bytes an admission request's body digest covers, for [`vector_request`], and
/// their digest. The same strings are the `admission_request_body` case of
/// `infra/relay/vectors/admission.json`.
const REQUEST_HEX: &str = "82781c6b722d72656c61792d61646d697373696f6e2d726571756573742f31a36972656c61795f75726c781e68747470733a2f2f72656c61792d312e72656163682e6b616c612e746f2f71686f73745f656e64706f696e745f6b6579582011111111111111111111111111111111111111111111111111111111111111117663616e6469646174655f656e64706f696e745f6b657958202222222222222222222222222222222222222222222222222222222222222222";
const REQUEST_SHA256: &str = "6a6cd47f988a8a8b43d0e59475595e801cf97b32a87255a95b5f9fb6b4458dd4";

/// An installation's device authorisation key, held the way a client holds one.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl Installation {
    fn new() -> Arc<Self> {
        Arc::new(Self(AuthorisationKeyPair::generate().expect("a key pair")))
    }
}

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(byte: u8) -> EndpointKey {
    EndpointKey::from_bytes([byte; 32])
}

fn request(relay: &str) -> AdmissionRequest {
    AdmissionRequest {
        host: key(0x11),
        candidate: key(0x22),
        relay_url: relay.to_owned(),
    }
}

/// A network configuration that names `relays`, in that order.
fn network(relays: &[&str]) -> NetworkConfig {
    NetworkConfig {
        relay_urls: relays
            .iter()
            .map(|relay| NetworkHint::new(*relay).expect("a hint"))
            .collect(),
        pkarr_publisher_url: Nullable::null(),
        pkarr_resolver_url: Nullable::null(),
        dns_origin: Nullable::null(),
        direct_addresses: Vec::new(),
    }
}

const MANAGED: &str = "https://relay-1.reach.kala.to";

/// The managed service as the stand-in answers it, and the client over it.
struct Service {
    web: Arc<ServiceWeb>,
    admissions: PairingAdmissions,
    clock: AdmissionClock,
}

impl Service {
    fn start() -> Self {
        let web = Arc::new(ServiceWeb::new());
        let origin = GatewayOrigin::new(web.origin()).expect("an origin");
        let clock = AdmissionClock::default();
        let service = Arc::new(ManagedPairingAdmission::new(
            origin.clone(),
            Arc::clone(&web) as _,
            Installation::new(),
        ));
        let admissions = PairingAdmissions::new(service, &origin)
            .expect("admissions")
            .on_clock(clock.clone());
        Self {
            web,
            admissions,
            clock,
        }
    }

    fn asked(&self) -> Vec<String> {
        self.web
            .relay_admission_requests()
            .into_iter()
            .map(|asked| asked.relay_url)
            .collect()
    }
}

/// KR-REQ-10.54: the bytes a request's credential covers are the bytes the service rebuilds.
#[test]
fn the_body_a_request_covers_is_the_one_the_service_rebuilds() {
    let body = RelayAdmissionIssueBody::of(&AdmissionRequest {
        host: key(0x11),
        candidate: key(0x22),
        relay_url: "https://relay-1.reach.kala.to/".to_owned(),
    });
    let input = body.signing_input().expect("a canonical body");

    assert_eq!(hex(&input), REQUEST_HEX);
    assert_eq!(hex(&kr_cbor::sha256(&input)), REQUEST_SHA256);
}

/// KR-REQ-10.54, KR-REQ-17.48: the service answers an admission, a spent budget, a relay it does
/// not carry and a pair that holds a lease, and each answer is one the client reads, over the
/// credential the service itself checks.
#[tokio::test]
async fn the_services_four_answers_are_read() {
    let service = Service::start();
    let origin = GatewayOrigin::new(service.web.origin()).expect("an origin");
    let signer = Installation::new();
    let admit = ManagedPairingAdmission::new(
        origin.clone(),
        Arc::clone(&service.web) as _,
        signer.clone(),
    );

    // Admitted, with what the service says it holds.
    let answered = admit.admit(&request(MANAGED)).await.expect("an answer");
    assert_eq!(
        answered,
        AdmissionAnswer::Admitted {
            expires_in_seconds: 600,
            byte_ceiling: 512 * 1024,
        }
    );
    let asked = service.web.relay_admission_requests();
    assert_eq!((asked[0].host, asked[0].candidate), (key(0x11), key(0x22)));

    // A relay the service does not carry is not named to anything.
    let answered = admit
        .admit(&request("https://relay.other.test"))
        .await
        .expect("an answer");
    assert_eq!(answered, AdmissionAnswer::NotManaged);

    // The budget is spent: the paths that still work, and nothing is installed.
    service.web.spend_admission_budget(true);
    let AdmissionAnswer::Unavailable {
        alternatives,
        retry_after_seconds,
        ..
    } = admit.admit(&request(MANAGED)).await.expect("an answer")
    else {
        panic!("a spent budget is unavailable capacity");
    };
    assert!(!alternatives.is_empty());
    assert_eq!(retry_after_seconds, None);
    service.web.spend_admission_budget(false);

    // A pair that holds a lease needs none: the lease decides it alone.
    let leases = ManagedRelayLeaseService::new(origin, Arc::clone(&service.web) as _, signer);
    leases
        .issue(&LeaseRequest {
            source: key(0x11),
            destination: key(0x22),
            direction: RelayDirection::Bidirectional,
            byte_ceiling: 4 * 1024 * 1024,
            duration_seconds: 300,
            region_preference: None,
            payer: None,
            lease_id: None,
        })
        .await
        .expect("a lease");
    assert_eq!(
        admit.admit(&request(MANAGED)).await.expect("an answer"),
        AdmissionAnswer::NotNeeded
    );
}

/// A service whose answers a test scripts, for what the wire cannot be made to do: never answer,
/// answer when told to, or say it serves no such route.
#[derive(Debug)]
struct Scripted {
    answers: Mutex<Vec<Result<AdmissionAnswer>>>,
    asked: AtomicUsize,
    gate: Option<Arc<tokio::sync::Notify>>,
}

impl Scripted {
    fn new(answers: Vec<Result<AdmissionAnswer>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            asked: AtomicUsize::new(0),
            gate: None,
        })
    }

    fn gated(answer: AdmissionAnswer) -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        let gate = Arc::new(tokio::sync::Notify::new());
        (
            Arc::new(Self {
                answers: Mutex::new(vec![Ok(answer)]),
                asked: AtomicUsize::new(0),
                gate: Some(Arc::clone(&gate)),
            }),
            gate,
        )
    }

    fn asks(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl PairingAdmissionService for Scripted {
    fn admit<'a>(&'a self, _request: &'a AdmissionRequest) -> ServiceFuture<'a, AdmissionAnswer> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            let mut answers = self.answers.lock().expect("the script");
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone_answer()
            }
        })
    }
}

trait CloneAnswer {
    fn clone_answer(&self) -> Self;
}

impl CloneAnswer for Result<AdmissionAnswer> {
    fn clone_answer(&self) -> Self {
        match self {
            Ok(answer) => Ok(answer.clone()),
            Err(error) => Err(Error::refusal(error.code(), "the script's refusal".into())),
        }
    }
}

fn scripted_admissions(service: Arc<Scripted>, clock: &AdmissionClock) -> PairingAdmissions {
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone())
        .waiting(Duration::from_millis(200))
}

/// KR-REQ-10.54: an invitation that names a managed relay causes one request for it before the dial
/// and none for a relay that is not the service's: a self-hosted relay, an unrelated name, an address
/// where the service has a name, and names that only look like the service's.
#[tokio::test]
async fn only_a_relay_of_the_managed_service_is_ever_named_to_it() {
    let service = Service::start();
    let host = key(0x11);

    service
        .admissions
        .before_dial(
            &network(&[
                "https://relay.other.test",
                "https://127.0.0.1:9",
                "https://reach.kala.to.evil.test",
                "https://evilreach.kala.to",
                MANAGED,
            ]),
            &host,
            key(0x22),
        )
        .await;

    assert_eq!(service.asked(), vec![MANAGED.to_owned()]);

    // A service at an address names its relays by that address.
    let web = Arc::new(ServiceWeb::at("http://127.0.0.1:9100"));
    web.name_relay_url("https://127.0.0.1:9101");
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let admissions = PairingAdmissions::new(
        Arc::new(ManagedPairingAdmission::new(
            origin.clone(),
            Arc::clone(&web) as _,
            Installation::new(),
        )),
        &origin,
    )
    .expect("admissions");
    admissions
        .before_dial(
            &network(&["https://127.0.0.2:9101", "https://127.0.0.1:9101"]),
            &host,
            key(0x22),
        )
        .await;
    let asked: Vec<String> = web
        .relay_admission_requests()
        .into_iter()
        .map(|asked| asked.relay_url)
        .collect();
    assert_eq!(asked, vec!["https://127.0.0.1:9101".to_owned()]);
}

/// KR-REQ-10.54: one request serves a dial and its re-dials while the admission stands, and a dial
/// that connected leaves nothing in doubt.
#[tokio::test]
async fn a_re_dial_after_a_connection_reuses_the_admission() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    service.admissions.dial_succeeded(&relays, &host);
    service.clock.advance(Duration::from_secs(120));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    service.admissions.dial_succeeded(&relays, &host);

    assert_eq!(
        service.asked(),
        vec![MANAGED.to_owned()],
        "one request in all"
    );

    // An admission that is about to end is asked for again.
    service.clock.advance(Duration::from_secs(500));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);
}

/// KR-REQ-10.54: a dial that was cut short before it connected leaves its entry in doubt, and a later
/// dial asks again after twenty seconds, at most three times between connections.
#[tokio::test]
async fn a_dial_that_never_connected_is_asked_about_again_a_few_times() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    // The first dial ended by its route's deadline: nothing ran at cancellation, nothing connected.
    service.clock.advance(Duration::from_secs(10));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        1,
        "ten seconds is not long enough to doubt it"
    );

    service.clock.advance(Duration::from_secs(15));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);

    service.clock.advance(Duration::from_secs(25));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 3);

    service.clock.advance(Duration::from_secs(25));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        3,
        "three is the most between connections"
    );

    // A connection settles the doubt, and the count starts again.
    service.admissions.dial_succeeded(&relays, &host);
    service.clock.advance(Duration::from_secs(580));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 4);
}

/// KR-REQ-17.40, KR-REQ-17.48: what the service said it cannot do explains a dial that failed for a
/// minute, though a dial asks again when the service said to, and a relay that was named first is the
/// one that decides.
#[tokio::test]
async fn an_answer_that_the_service_is_unable_explains_a_failed_dial_but_not_for_ever() {
    let service = Service::start();
    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: Some(5),
        },
    );
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert!(service.admissions.capacity_refused(&relays, &host));

    // Four seconds on, nothing more is asked; six seconds on, it is.
    service.clock.advance(Duration::from_secs(4));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 1);
    service.clock.advance(Duration::from_secs(2));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);

    // And the answer still stands for the route that asks fifty seconds after it came, though no
    // dial has begun since.
    service.clock.advance(Duration::from_secs(50));
    assert!(service.admissions.capacity_refused(&relays, &host));
    service.clock.advance(Duration::from_secs(20));
    assert!(!service.admissions.capacity_refused(&relays, &host));
}

/// KR-REQ-17.40: it is the relay a dial addresses that decides what a failed dial is reported as: the
/// first the host names. One that is unavailable while another admits, and the other way round, and a
/// pair that holds a lease there, each say what that relay says.
#[tokio::test]
async fn the_relay_a_dial_addresses_is_the_one_that_decides() {
    let service = Service::start();
    let second = "https://relay-2.reach.kala.to";
    service.web.carry_relay(second, AdmissionBehaviour::Admit);
    let host = key(0x11);

    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: None,
        },
    );
    let first_is_unavailable = network(&[MANAGED, second]);
    service
        .admissions
        .before_dial(&first_is_unavailable, &host, key(0x22))
        .await;
    assert!(
        service
            .admissions
            .capacity_refused(&first_is_unavailable, &host)
    );

    // The same relays in the other order: the dial addresses the one that admits.
    let first_admits = network(&[second, MANAGED]);
    assert!(!service.admissions.capacity_refused(&first_admits, &host));

    // A pair that holds a lease at the first relay needs no admission there, which is not capacity.
    let other = key(0x33);
    let leased = Service::start();
    leased.web.carry_relay(MANAGED, AdmissionBehaviour::Admit);
    let origin = GatewayOrigin::new(leased.web.origin()).expect("an origin");
    let signer = Installation::new();
    ManagedRelayLeaseService::new(origin, Arc::clone(&leased.web) as _, signer)
        .issue(&LeaseRequest {
            source: other,
            destination: key(0x44),
            direction: RelayDirection::Bidirectional,
            byte_ceiling: 4 * 1024 * 1024,
            duration_seconds: 300,
            region_preference: None,
            payer: None,
            lease_id: None,
        })
        .await
        .expect("a lease");
    leased
        .admissions
        .before_dial(&network(&[MANAGED]), &other, key(0x44))
        .await;
    assert!(
        !leased
            .admissions
            .capacity_refused(&network(&[MANAGED]), &other)
    );
}

/// KR-REQ-10.54: a service that never answers does not stop a dial, and what it answers later is kept
/// for the next one. The wait is the test's; what decides is that the dial went on.
#[tokio::test]
async fn a_service_that_does_not_answer_does_not_hold_up_a_dial() {
    let clock = AdmissionClock::default();
    let (service, gate) = Scripted::gated(AdmissionAnswer::Unavailable {
        message: "spent".to_owned(),
        alternatives: vec!["a direct connection".to_owned()],
        retry_after_seconds: None,
    });
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    tokio::time::timeout(
        Duration::from_secs(30),
        admissions.before_dial(&relays, &host, key(0x22)),
    )
    .await
    .expect("the dial goes on without the answer");
    assert_eq!(service.asks(), 1);
    assert!(
        !admissions.capacity_refused(&relays, &host),
        "nothing has been said yet"
    );

    // The answer arrives after the dial went on, and is kept.
    gate.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !admissions.capacity_refused(&relays, &host) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a later answer is kept");
}

/// KR-REQ-10.54: a service that says it serves no such route, or does not allow this device to ask,
/// stops every request for ten minutes, and what it said is no reason a person is shown.
#[tokio::test]
async fn a_service_without_the_route_is_left_alone_for_ten_minutes() {
    let clock = AdmissionClock::default();
    let service = Scripted::new(vec![Err(Error::refusal(
        ErrorCode::InvalidArgument,
        "the service has no such route".into(),
    ))]);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let relays = network(&[MANAGED]);

    admissions.before_dial(&relays, &key(0x11), key(0x22)).await;
    assert_eq!(service.asks(), 1);
    assert!(
        !admissions.capacity_refused(&relays, &key(0x11)),
        "that is no capacity text"
    );

    // Another host, a minute on: nothing is asked.
    clock.advance(Duration::from_secs(60));
    admissions.before_dial(&relays, &key(0x33), key(0x22)).await;
    assert_eq!(service.asks(), 1);

    // Ten minutes on, it is.
    clock.advance(Duration::from_secs(10 * 60));
    admissions.before_dial(&relays, &key(0x33), key(0x22)).await;
    assert_eq!(service.asks(), 2);
}
