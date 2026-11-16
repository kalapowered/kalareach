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
    RelayLeaseService, RelayRefusal, ServiceFuture, ServiceHttp, ServiceHttpAnswer, ServiceSigner,
};
use kr_client::{ClientError as Error, Result};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::ErrorCode;
use kr_protocol::pairing::{NetworkConfig, NetworkHint};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Nullable, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{AdmissionBehaviour, Moment, ServiceWeb};

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

/// KR-REQ-10.39: the bytes a request's credential covers are the bytes the service rebuilds.
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

/// KR-REQ-10.39, KR-REQ-17.48: the service answers an admission, a spent budget, a relay it does
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

    // A relay is known by the URL the Worker's registry reads, whichever way each side spells the
    // host's case, the default port and the trailing slash.
    service.web.carry_relay(
        "https://Relay-2.reach.kala.to:443/",
        AdmissionBehaviour::Admit,
    );
    assert!(matches!(
        admit
            .admit(&request("https://relay-2.reach.kala.to"))
            .await
            .expect("an answer"),
        AdmissionAnswer::Admitted { .. }
    ));

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

/// A transport that answers every request with the one status and body it was given, byte for byte,
/// and counts the requests: the service's answer as the client's own reader meets it.
#[derive(Debug)]
struct Exact {
    status: u16,
    body: String,
    requests: AtomicUsize,
}

impl Exact {
    fn new(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            status,
            body: body.to_owned(),
            requests: AtomicUsize::new(0),
        })
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl ServiceHttp for Exact {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(ServiceHttpAnswer {
                status: self.status,
                body: self.body.as_bytes().to_vec(),
            })
        })
    }
}

/// The answer the service gives for a relay it could not admit a pair through: its words, the paths
/// that still work (none, when the cause is its own fault) and the wait it names when it names one.
fn unavailable_body(message: &str, alternatives: &[&str], delay: Option<u64>) -> String {
    let mut data = serde_json::json!({
        "state": "unavailable",
        "message": message,
        "alternatives": alternatives,
    });
    if let Some(seconds) = delay {
        data["retry_after_seconds"] = serde_json::json!(seconds);
    }
    serde_json::json!({ "ok": true, "data": data }).to_string()
}

/// The two paths that still work, as the service names them when a budget is short.
const STILL_WORK: [&str; 2] = [
    "A direct connection between the devices, which needs no managed relay.",
    "A relay that the host's owner runs. The host must name it in its configuration and use no \
     managed relay. A new invitation from that host then names it.",
];

/// When, in seconds after the first dial, the cache is dialled to in the timeline below.
const PROBES: [u64; 13] = [0, 4, 6, 12, 21, 26, 61, 66, 130, 700, 3601, 3700, 90_000];

/// What the cache did over `PROBES` when the service answered `body` to every request: at each
/// dial, how many requests the service had been sent by then and whether a failed dial would be
/// reported as the managed relay having no capacity.
async fn timeline(body: &str) -> Vec<(u64, usize, bool)> {
    let clock = AdmissionClock::default();
    let http = Exact::new(200, body);
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let service = Arc::new(ManagedPairingAdmission::new(
        origin.clone(),
        Arc::clone(&http) as _,
        Installation::new(),
    ));
    let admissions = PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone());
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for probe in PROBES {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((
            probe,
            http.requests(),
            admissions.refusal(&relays, &host).is_some(),
        ));
    }
    seen
}

/// KR-REQ-17.48: a service that cannot admit a pair for a reason of its own says so with the member
/// that names the paths that still work present and empty, and the client's reader holds it as it
/// holds an answer that names them: the same answer kind, the same requests at the same moments, an
/// explanation of a failed dial for as long, with a wait named and without. What the explanation
/// says differs, and is told apart in its own case. An answer that leaves the member out is still
/// not one it reads.
#[tokio::test]
async fn kr_req_17_48_an_unavailable_answer_with_an_empty_list_is_held_as_one_with_entries() {
    const FAULT: &str = "The managed relay service could not admit this pairing now.";
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";

    for delay in [
        None,
        Some(0),
        Some(5),
        Some(3600),
        Some(86_400),
        Some(200_000),
    ] {
        let with_entries = unavailable_body(SHORT, &STILL_WORK, delay);
        let with_none = unavailable_body(FAULT, &[], delay);

        let (named, empty) = (timeline(&with_entries).await, timeline(&with_none).await);
        println!("TIMELINE delay {delay:?} | entries {named:?} | empty {empty:?}");
        assert_eq!(named, empty, "delay {delay:?}");
        assert!(
            named[0].2 && named[0].1 == 1,
            "the first dial asks once and is explained as capacity: {named:?}"
        );

        let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
        let read = |body: &str| {
            ManagedPairingAdmission::new(
                origin.clone(),
                Exact::new(200, body) as _,
                Installation::new(),
            )
        };
        let (entries, none) = (
            read(&with_entries).admit(&request(MANAGED)).await,
            read(&with_none).admit(&request(MANAGED)).await,
        );
        assert_eq!(
            entries.expect("an answer"),
            AdmissionAnswer::Unavailable {
                message: SHORT.to_owned(),
                alternatives: STILL_WORK.map(str::to_owned).to_vec(),
                retry_after_seconds: delay,
            }
        );
        assert_eq!(
            none.expect("an answer"),
            AdmissionAnswer::Unavailable {
                message: FAULT.to_owned(),
                alternatives: Vec::new(),
                retry_after_seconds: delay,
            }
        );
    }

    // The member is what the reader needs: an answer that leaves it out is not read, and the cache
    // holds that as a failed request, which explains no dial.
    let without = serde_json::json!({
        "ok": true,
        "data": {"state": "unavailable", "message": "The relay did not answer."},
    })
    .to_string();
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let unread =
        ManagedPairingAdmission::new(origin, Exact::new(200, &without) as _, Installation::new())
            .admit(&request(MANAGED))
            .await;
    assert!(unread.is_err(), "a missing member is read as an answer");
    assert!(
        !timeline(&without)
            .await
            .iter()
            .any(|(_, _, refused)| *refused),
        "an answer that cannot be read explained a dial"
    );
}

/// KR-REQ-10.39, KR-REQ-10.54: an invitation that names a managed relay causes one request for it
/// before the dial and none for a relay that is not the service's: a self-hosted relay, an unrelated
/// name, an address where the service has a name, and names that only look like the service's.
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

/// KR-REQ-10.39: one request serves a dial and its re-dials while the admission stands, and a dial
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

/// KR-REQ-10.39: a dial that was cut short before it connected leaves its entry in doubt, and a later
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

/// KR-REQ-10.39: three requests with no connection between them are the most in ten minutes, not the
/// most for good: a person whose host was off, or whose network blocked the relay, and who tries again
/// after fixing it, is asked about again, from the same device and the same cache.
#[tokio::test]
async fn a_device_whose_dials_all_failed_asks_again_when_the_ten_minutes_have_passed() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    for _ in 0..3 {
        service
            .admissions
            .before_dial(&relays, &host, key(0x22))
            .await;
        service.clock.advance(Duration::from_secs(25));
    }
    assert_eq!(service.asked().len(), 3);

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        3,
        "the most inside the window, whatever the dials came to"
    );

    // Past ten minutes from the last request, the admission that came with it has ended too.
    service.clock.advance(Duration::from_secs(10 * 60));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        4,
        "a device that never connected is never asked again"
    );
}

/// KR-REQ-17.40, KR-REQ-17.48: a service that is unable and names no time to try again is believed as
/// long as the cache will not ask it again. After three requests with no connection that is until
/// ten minutes after the last, not the minute the answer is kept for: a person who tries again a few
/// minutes on is told the managed relay had no capacity, and not that the host is out of reach.
#[tokio::test]
async fn an_answer_that_the_service_is_unable_stands_while_the_cache_will_not_ask_again() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: None,
        },
    );

    for _ in 0..3 {
        service
            .admissions
            .before_dial(&relays, &host, key(0x22))
            .await;
        assert!(service.admissions.refusal(&relays, &host).is_some());
        service.clock.advance(Duration::from_secs(25));
    }
    assert_eq!(service.asked().len(), 3);

    // Two minutes on, past the minute the answer is kept for. No request is made, and the answer
    // that explains the failure still stands.
    service.clock.advance(Duration::from_secs(120));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 3);
    assert!(
        service.admissions.refusal(&relays, &host).is_some(),
        "a refusal with no retry time stopped explaining the failure while nothing asked again"
    );

    // Ten minutes after the last request it is asked again, and the answer is the service's own.
    service.clock.advance(Duration::from_secs(10 * 60));
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
    assert!(service.admissions.refusal(&relays, &host).is_some());

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
    assert!(service.admissions.refusal(&relays, &host).is_some());
    service.clock.advance(Duration::from_secs(20));
    assert!(service.admissions.refusal(&relays, &host).is_none());
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
            .refusal(&first_is_unavailable, &host)
            .is_some()
    );

    // The same relays in the other order: the dial addresses the one that admits.
    let first_admits = network(&[second, MANAGED]);
    assert!(service.admissions.refusal(&first_admits, &host).is_none());

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
        leased
            .admissions
            .refusal(&network(&[MANAGED]), &other)
            .is_none()
    );
}

/// KR-REQ-10.39: a service that never answers does not stop a dial, and what it answers later is kept
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
        admissions.refusal(&relays, &host).is_none(),
        "nothing has been said yet"
    );

    // The answer arrives after the dial went on, and is kept.
    gate.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        while admissions.refusal(&relays, &host).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a later answer is kept");
}

/// KR-REQ-10.39: a dial that its route ends while it waits for the service leaves the request running.
/// The answer that comes after the dial is gone is kept, the next dial reads it, and the service is
/// not asked a second time.
#[tokio::test]
async fn a_dial_that_its_route_ends_while_it_waits_leaves_its_request_to_finish() {
    let clock = AdmissionClock::default();
    let (service, gate) = Scripted::gated(AdmissionAnswer::Unavailable {
        message: "spent".to_owned(),
        alternatives: vec!["a direct connection".to_owned()],
        retry_after_seconds: None,
    });
    // The wait for the answer is far longer than the test will give the dial, so that only the
    // route's own cut can end it.
    let admissions =
        scripted_admissions(Arc::clone(&service), &clock).waiting(Duration::from_secs(600));
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    // The route's own deadline ends the dial long before the wait for the answer would.
    let ended = tokio::time::timeout(
        Duration::from_millis(50),
        admissions.before_dial(&relays, &host, key(0x22)),
    )
    .await;
    assert!(ended.is_err(), "the dial was not cut short while it waited");
    assert_eq!(service.asks(), 1);
    assert!(admissions.refusal(&relays, &host).is_none());

    // The service answers once the dial has gone, and the answer is kept.
    gate.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        while admissions.refusal(&relays, &host).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the answer to a dial that was cut short is kept");

    // The next dial reads it and asks nothing.
    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(service.asks(), 1);
}

/// KR-REQ-10.39: a service that says it serves no such route, or does not allow this device to ask,
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
        admissions.refusal(&relays, &key(0x11)).is_none(),
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

/// KR-REQ-10.39: a deployment of the service that has no such route answers 404, as the Worker does,
/// which the client's own reading of an answer turns into the same ten minutes of being left alone.
#[tokio::test]
async fn a_real_not_found_from_the_service_stops_requests_for_ten_minutes() {
    let service = Service::start();
    let relays = network(&[MANAGED]);
    service.web.fail(
        "/api/relay/admission",
        1,
        Moment::Refuse {
            status: 404,
            code: "NOT_FOUND",
            retry_after_seconds: None,
        },
    );

    service
        .admissions
        .before_dial(&relays, &key(0x11), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 1);
    assert!(
        service.admissions.refusal(&relays, &key(0x11)).is_none(),
        "that is no capacity text"
    );

    // Another host a minute on: nothing is sent.
    service.clock.advance(Duration::from_secs(60));
    service
        .admissions
        .before_dial(&relays, &key(0x33), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 1);

    service.clock.advance(Duration::from_secs(10 * 60));
    service
        .admissions
        .before_dial(&relays, &key(0x33), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 2);
}

/// A transport whose exchange ends before the service has said anything: there is no status and no
/// body to read. It counts the requests it was given.
#[derive(Debug, Default)]
struct Unreached {
    requests: AtomicUsize,
}

impl ServiceHttp for Unreached {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(Error::refusal(
                ErrorCode::ResourceUnavailable,
                "the exchange ended".into(),
            ))
        })
    }
}

/// The service's own envelope for a refusal, with the wait it names when it names one.
fn refusal_body(code: &str, delay: Option<u64>) -> String {
    let mut error = serde_json::json!({
        "code": code,
        "message": "The service could not do that now.",
    });
    if let Some(seconds) = delay {
        error["retryAfterSeconds"] = serde_json::json!(seconds);
    }
    serde_json::json!({ "ok": false, "error": error }).to_string()
}

/// How many requests the transport had been sent at each of [`PROBES`], and what a failed dial
/// would be explained by, when `http` answers every request.
async fn series(
    http: Arc<dyn ServiceHttp>,
    sent: impl Fn() -> usize,
) -> Vec<(u64, usize, Option<RelayRefusal>)> {
    let clock = AdmissionClock::default();
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let service = Arc::new(ManagedPairingAdmission::new(
        origin.clone(),
        http,
        Installation::new(),
    ));
    let admissions = PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone());
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for probe in PROBES {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((probe, sent(), admissions.refusal(&relays, &host)));
    }
    seen
}

/// KR-REQ-17.48: when a request is asked again does not depend on what the answer to the one before
/// it let a failed dial be explained by. An answer that is a refusal in the service's envelope, with
/// a status of the 5xx class or another, an answer that is not the envelope and an exchange that
/// ended with no answer are each asked about again at the moments they always were.
#[tokio::test]
async fn kr_req_17_48_a_refused_or_unreadable_answer_is_asked_about_again_at_the_same_moments() {
    const ASKED: [usize; 13] = [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7];
    let bodies: [(&str, u16, String, [usize; 13]); 7] = [
        ("503 internal", 503, refusal_body("INTERNAL", None), ASKED),
        // A wait under twenty seconds is still asked again after twenty.
        ("503 delay 5", 503, refusal_body("INTERNAL", Some(5)), ASKED),
        (
            "500 delay 3600",
            500,
            refusal_body("INTERNAL", Some(3600)),
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3],
        ),
        // A service that says it is not configured stops every request for ten minutes.
        (
            "501 not configured",
            501,
            refusal_body("NOT_CONFIGURED", None),
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3, 4],
        ),
        (
            "429 delay 30",
            429,
            refusal_body("RATE_LIMITED", Some(30)),
            [1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5, 6],
        ),
        (
            "502 no envelope",
            502,
            "<html>Bad Gateway</html>".to_owned(),
            ASKED,
        ),
        ("503 no error", 503, r#"{"ok":false}"#.to_owned(), ASKED),
    ];
    for (name, status, body, expected) in bodies {
        let http = Exact::new(status, &body);
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        let asked: Vec<usize> = seen.iter().map(|(_, asked, _)| *asked).collect();
        assert_eq!(asked, expected, "{name}");
    }
    let http = Arc::new(Unreached::default());
    let seen = series(Arc::clone(&http) as _, || {
        http.requests.load(Ordering::SeqCst)
    })
    .await;
    let asked: Vec<usize> = seen.iter().map(|(_, asked, _)| *asked).collect();
    assert_eq!(asked, ASKED, "an exchange that ended with no answer");
}

/// What a service that is not updated and one that is name beside an answer that it is unable, as
/// words: the paths that still work. Only the first and the last are this build's own texts.
const OLD_SERVICE_LIST: [&str; 2] = [
    "A direct connection between the devices, which needs no managed relay.",
    "A self-hosted relay configured in the service settings.",
];

/// The delays an answer names, and none.
const DELAYS: [Option<u64>; 6] = [
    None,
    Some(0),
    Some(5),
    Some(3600),
    Some(86_400),
    Some(200_000),
];

/// How many requests the service has been sent at each of [`PROBES`] when it answers that it is
/// unable and names `delay`: the table of the control, typed from a run before the list and the
/// delay were kept.
fn control_asked(delay: Option<u64>) -> [usize; 13] {
    match delay {
        None => [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7],
        Some(0) => [1, 2, 3, 3, 3, 3, 3, 3, 3, 4, 5, 6, 7],
        Some(5) => [1, 1, 2, 3, 3, 3, 3, 3, 3, 4, 5, 6, 7],
        Some(3600) => [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3],
        Some(86_400 | 200_000) => [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2],
        Some(other) => panic!("no control for a delay of {other}"),
    }
}

fn asked_at_each_probe(seen: &[(u64, usize, Option<RelayRefusal>)]) -> Vec<usize> {
    seen.iter().map(|(_, asked, _)| *asked).collect()
}

/// The paths a failure holds, as words.
fn words_of(alternatives: &kr_client::services::Alternatives) -> Vec<String> {
    alternatives
        .as_given()
        .iter()
        .map(|shown| shown.as_str().to_owned())
        .collect()
}

/// KR-REQ-17.48: an answer that the service is unable, with a list that has an entry, is kept with
/// that list, as it wrote it, and the device's wait, for as long as it explains a failed dial, and
/// is asked again at the moments it always was. A service that is not updated, whose list has the
/// old second item or any other, reads the same way.
#[tokio::test]
async fn kr_req_17_48_a_kept_answer_holds_the_list_and_the_delay_it_named() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    let lists: [Vec<&str>; 3] = [
        STILL_WORK.to_vec(),
        OLD_SERVICE_LIST.to_vec(),
        vec!["A path that this build has never heard of."],
    ];
    for list in lists {
        for delay in DELAYS {
            let http = Exact::new(200, &unavailable_body(SHORT, &list, delay));
            let seen = series(Arc::clone(&http) as _, || http.requests()).await;
            assert_eq!(
                asked_at_each_probe(&seen),
                control_asked(delay),
                "{delay:?}"
            );
            for (probe, _, refusal) in seen {
                let Some(RelayRefusal::Capacity {
                    alternatives,
                    retry_after_seconds,
                }) = refusal
                else {
                    panic!("at {probe}s with {delay:?}: {refusal:?}");
                };
                assert_eq!(words_of(&alternatives), list, "at {probe}s");
                assert!(
                    retry_after_seconds <= 86_400,
                    "at {probe}s with {delay:?}: {retry_after_seconds}"
                );
            }
        }
    }
}

/// KR-REQ-17.48: an answer that the service is unable, whose list has no entry, is a fault of the
/// service and never exhausted capacity, with the device's own wait, and is kept and asked again at
/// the same moments as one with entries.
#[tokio::test]
async fn kr_req_17_48_an_unavailable_answer_with_no_entry_is_a_fault_and_never_capacity() {
    const FAULT: &str = "The managed relay service could not admit this pairing now.";
    for delay in DELAYS {
        let http = Exact::new(200, &unavailable_body(FAULT, &[], delay));
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert_eq!(
            asked_at_each_probe(&seen),
            control_asked(delay),
            "{delay:?}"
        );
        for (probe, _, refusal) in seen {
            let Some(RelayRefusal::Fault {
                retry_after_seconds,
            }) = refusal
            else {
                panic!("at {probe}s with {delay:?}: {refusal:?}");
            };
            assert!(
                retry_after_seconds <= 86_400,
                "at {probe}s with {delay:?}: {retry_after_seconds}"
            );
        }
    }
}

/// KR-REQ-17.48: a refusal in the service's envelope under a status of the 5xx class is a fault of
/// the service, explained for as long as an answer that it is unable is, with the device's own wait
/// that the delay the envelope named sets, and is asked again at the moments a refusal always was.
#[tokio::test]
async fn kr_req_17_48_a_refusal_of_the_5xx_class_in_the_envelope_is_a_fault() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    // The same wait, said as unavailable: asked again after a wait of twenty seconds or more at the
    // same moments, so the whole series is equal.
    for (status, delay, told) in [(503, None, 20), (500, Some(3600), 3600)] {
        let refused = Exact::new(status, &refusal_body("INTERNAL", delay));
        let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
        let unavailable = Exact::new(200, &unavailable_body(SHORT, &STILL_WORK, delay));
        let baseline = series(Arc::clone(&unavailable) as _, || unavailable.requests()).await;
        let explained = |seen: &[(u64, usize, Option<RelayRefusal>)]| -> Vec<(u64, usize, bool)> {
            seen.iter()
                .map(|(probe, asked, refusal)| (*probe, *asked, refusal.is_some()))
                .collect()
        };
        assert_eq!(explained(&seen), explained(&baseline), "{status} {delay:?}");
        assert_eq!(
            seen[0].2,
            Some(RelayRefusal::Fault {
                retry_after_seconds: told
            })
        );
    }
    // A wait under twenty seconds is still asked again after twenty, as any refusal is.
    let refused = Exact::new(503, &refusal_body("INTERNAL", Some(5)));
    let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
    assert_eq!(
        asked_at_each_probe(&seen),
        [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7]
    );
    // And is told so: the wait is until the device asks again, which is twenty seconds.
    assert_eq!(
        seen[0].2,
        Some(RelayRefusal::Fault {
            retry_after_seconds: 20
        })
    );
    // A service that says it is not configured is a fault as well, and is not asked for ten
    // minutes: a device told so waits for the stop, though the service named no delay.
    let refused = Exact::new(501, &refusal_body("NOT_CONFIGURED", None));
    let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
    assert_eq!(
        asked_at_each_probe(&seen),
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3, 4]
    );
    assert_eq!(
        seen[0].2,
        Some(RelayRefusal::Fault {
            retry_after_seconds: 600
        })
    );
}

/// KR-REQ-17.48: what is neither exhausted capacity nor a fault of the service explains nothing: an
/// exchange that ended with no answer, an answer that is not the service's envelope under a status
/// of the 5xx class, a refusal in the envelope under another status, and a refusal that names no
/// error.
#[tokio::test]
async fn kr_req_17_48_a_transport_failure_and_an_answer_without_the_envelope_are_neither() {
    let answers: [(u16, String); 5] = [
        (502, "<html>Bad Gateway</html>".to_owned()),
        (503, r#"{"ok":false}"#.to_owned()),
        (503, "not json".to_owned()),
        (429, refusal_body("RATE_LIMITED", Some(30))),
        (400, refusal_body("INVALID_REQUEST", None)),
    ];
    for (status, body) in answers {
        let http = Exact::new(status, &body);
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert!(
            seen.iter().all(|(_, _, refusal)| refusal.is_none()),
            "{status} {body}: {seen:?}"
        );
    }
    let http = Arc::new(Unreached::default());
    let seen = series(Arc::clone(&http) as _, || {
        http.requests.load(Ordering::SeqCst)
    })
    .await;
    assert!(seen.iter().all(|(_, _, refusal)| refusal.is_none()));
}

/// The wait a standing refusal hands on, of either kind.
fn handed_on(refusal: &Option<RelayRefusal>) -> Option<u64> {
    match refusal {
        Some(
            RelayRefusal::Capacity {
                retry_after_seconds,
                ..
            }
            | RelayRefusal::Fault {
                retry_after_seconds,
            },
        ) => Some(*retry_after_seconds),
        None => None,
    }
}

/// KR-REQ-17.48: what a failed dial hands on as the wait is the seconds from now until this device
/// asks the service again, and never less than what is left of the delay the service named: not the
/// delay as it was named when the answer was read, which is kept past itself while no request is
/// made. Rounded up, and twenty seconds at least where the service named none.
#[tokio::test]
async fn kr_req_17_48_the_wait_handed_on_is_the_wait_until_the_device_asks_again() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    // The figures at the 13 dials, by hand from the times of the control: the answer's retry time
    // while asks are left; the end of the ten minutes after the third ask, while they are used up
    // (the count starts again at each ask made ten minutes after the last).
    let tables: [(Option<u64>, [u64; 13]); 4] = [
        // No delay named: the device still asks again after twenty seconds, or when the ten
        // minutes after its third ask have passed.
        (None, [20, 16, 14, 8, 20, 15, 600, 595, 531, 20, 20, 20, 20]),
        (Some(5), [5, 1, 5, 600, 591, 586, 551, 546, 482, 5, 5, 5, 5]),
        (
            Some(3600),
            [
                3600, 3596, 3594, 3588, 3579, 3574, 3539, 3534, 3470, 2900, 3600, 3501, 3600,
            ],
        ),
        (
            Some(0),
            [0, 0, 600, 594, 585, 580, 545, 540, 476, 0, 0, 0, 0],
        ),
    ];
    for (delay, expected) in tables {
        for body in [
            unavailable_body(SHORT, &STILL_WORK, delay),
            unavailable_body(
                "The managed relay service could not admit this pairing now.",
                &[],
                delay,
            ),
        ] {
            let http = Exact::new(200, &body);
            let seen = series(Arc::clone(&http) as _, || http.requests()).await;
            let handed: Vec<Option<u64>> = seen.iter().map(|(_, _, one)| handed_on(one)).collect();
            assert_eq!(handed, expected.map(Some), "{delay:?} {body}");
        }
    }
}

/// KR-REQ-17.48: while every request is stopped, the wait handed on is what is left of the stop, and
/// not the delay the service named: a service that says it is not configured stops requests for ten
/// minutes.
#[tokio::test]
async fn kr_req_17_48_the_wait_handed_on_runs_to_the_end_of_a_stop_of_requests() {
    let http = Exact::new(501, &refusal_body("NOT_CONFIGURED", Some(30)));
    let seen = series(Arc::clone(&http) as _, || http.requests()).await;
    let handed: Vec<Option<u64>> = seen
        .iter()
        .take(6)
        .map(|(_, _, one)| handed_on(one))
        .collect();
    // The dials at 0, 4, 6, 12, 21 and 26 seconds.
    assert_eq!(
        handed,
        [
            Some(600),
            Some(596),
            Some(594),
            Some(588),
            Some(579),
            Some(574)
        ]
    );
}

/// KR-REQ-17.48: a list in which no entry has text names no path, so the answer is a fault and
/// carries no list; a list in which one entry has text is kept as it was written.
#[tokio::test]
async fn kr_req_17_48_a_list_with_no_text_is_no_list() {
    const WORDS: &str = "Managed capacity for new pairing invitations is not available now.";
    for blank in [vec![""], vec!["  ", ""], vec![" \t "]] {
        let http = Exact::new(200, &unavailable_body(WORDS, &blank, Some(30)));
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert!(
            matches!(seen[0].2, Some(RelayRefusal::Fault { .. })),
            "{blank:?}: {:?}",
            seen[0].2
        );
    }
    let mixed = ["", "A path that this build has never heard of."];
    let http = Exact::new(200, &unavailable_body(WORDS, &mixed, None));
    let seen = series(Arc::clone(&http) as _, || http.requests()).await;
    let Some(RelayRefusal::Capacity { alternatives, .. }) = &seen[0].2 else {
        panic!("{:?}", seen[0].2);
    };
    assert_eq!(words_of(alternatives), mixed);
}

/// What `admissions` hands on at each of `probes` (seconds after the first dial): how many requests
/// the service has been sent, and the wait a failed dial is told, when a refusal explains it.
async fn waits_at(
    service: &Arc<Scripted>,
    clock: &AdmissionClock,
    admissions: &PairingAdmissions,
    probes: &[u64],
) -> Vec<(u64, usize, Option<u64>)> {
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for &probe in probes {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((
            probe,
            service.asks(),
            handed_on(&admissions.refusal(&relays, &host)),
        ));
    }
    seen
}

/// KR-REQ-17.48: a request that fails keeps the answer that the service is unable, for as long as
/// that answer stands, and moves only the time a dial asks again. A third request that got no
/// answer does not turn the next ten minutes into "the host cannot be reached" with no wait: each
/// try is told what the answer said, with the wait that is left until the device asks again.
#[tokio::test]
async fn kr_req_17_48_a_failed_request_keeps_the_answer_that_still_stands() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    let lists: [&[&str]; 2] = [&STILL_WORK, &[]];
    for alternatives in lists {
        let unavailable = || {
            Ok(AdmissionAnswer::Unavailable {
                message: SHORT.to_owned(),
                alternatives: alternatives.iter().map(|path| (*path).to_owned()).collect(),
                retry_after_seconds: None,
            })
        };
        let failed = || {
            Err(Error::refusal(
                ErrorCode::ResourceUnavailable,
                "no answer".into(),
            ))
        };
        let (host, relays) = (key(0x11), network(&[MANAGED]));

        // Answers at 0 s and 21 s, then no answer to the third request at 61 s, then each try
        // inside the ten minutes after it. The dial at 661 s asks again and gets none, and what the
        // answers said has ended by then.
        let clock = AdmissionClock::default();
        let service = Scripted::new(vec![unavailable(), unavailable(), failed()]);
        let admissions = scripted_admissions(Arc::clone(&service), &clock);
        let seen = waits_at(
            &service,
            &clock,
            &admissions,
            &[0, 21, 26, 61, 66, 130, 400, 660, 661],
        )
        .await;
        assert_eq!(
            seen,
            [
                (0, 1, Some(20)),
                (21, 2, Some(20)),
                (26, 2, Some(15)),
                (61, 3, Some(600)),
                (66, 3, Some(595)),
                (130, 3, Some(531)),
                (400, 3, Some(261)),
                (660, 3, Some(1)),
                (661, 4, None),
            ],
            "{alternatives:?}"
        );

        // A request that fails before the third: the answer still stands, and the next request is
        // made when the failure moved the time to, twenty seconds on, not when the answer named it.
        let clock = AdmissionClock::default();
        let service = Scripted::new(vec![unavailable(), failed()]);
        let admissions = scripted_admissions(Arc::clone(&service), &clock);
        let seen = waits_at(&service, &clock, &admissions, &[0, 21, 26, 41, 46]).await;
        assert_eq!(
            seen,
            [
                (0, 1, Some(20)),
                (21, 2, Some(20)),
                (26, 2, Some(15)),
                (41, 3, Some(600)),
                (46, 3, Some(595)),
            ],
            "{alternatives:?}"
        );
        // It is still the answer's own, of the kind it was.
        match admissions.refusal(&relays, &host) {
            Some(RelayRefusal::Capacity {
                alternatives: kept, ..
            }) => {
                assert_eq!(words_of(&kept), alternatives);
            }
            Some(RelayRefusal::Fault { .. }) => assert!(alternatives.is_empty()),
            None => panic!("a failed request replaced the answer that still stood"),
        }
    }
}
