//! What a device and a deployment prove to each other.
//!
//! The mailbox, the durable authority feed and settings sync are reached over one signed HTTP
//! call each, and every other suite in this repository checks that call against something this
//! repository wrote: a mock, a loopback server, a runtime the service half runs inside. This one
//! checks it against a deployment. It seals a real envelope, signs a real credential, sends it to
//! the origin it is given and holds the answer to the rules sections 9, 10 and 20 state.
//!
//! # What it runs against, and what it leaves behind
//!
//! One environment variable names the origin: [`ORIGIN_VARIABLE`]. Without it every leg prints why
//! it did nothing and returns, so an ordinary test run of this workspace stays offline and green.
//! [`REQUIRE_VARIABLE`] set to `1` turns that absence into a failure, which is how a run that
//! promised a deployment finds out that it did not get one.
//!
//! Every principal is made for the run and held in memory: a fresh key signs, and the identifiers
//! the legs publish are drawn fresh as well, so a leg touches nothing that was not made for it. A
//! leg finishes by removing what the service lets it remove.

use std::sync::Arc;

use kr_client::services::authority::AuthorityFeedClient;
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::ids::DeviceId;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{AuthorisationKey, KeyId, Signature64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};

/// The variable naming the origin these legs run against.
pub const ORIGIN_VARIABLE: &str = "KR_DEPLOYED_ORIGIN";

/// The variable that turns a missing origin into a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_DEPLOYED_ORIGIN";

/// The deployment one leg runs against.
#[derive(Debug, Clone)]
pub struct Deployment {
    origin: GatewayOrigin,
    transport: Arc<HttpService>,
}

impl Deployment {
    /// The deployment this run was given, or nothing when it was given none.
    ///
    /// # Panics
    ///
    /// Panics when [`REQUIRE_VARIABLE`] says this run was promised a deployment and
    /// [`ORIGIN_VARIABLE`] names none, and when the origin it names is not one a managed-service
    /// credential may travel to.
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        let named = std::env::var(ORIGIN_VARIABLE).unwrap_or_default();
        if named.is_empty() {
            let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
            assert!(
                !required,
                "{REQUIRE_VARIABLE}=1 and {ORIGIN_VARIABLE} names no deployment, so this leg could not run"
            );
            eprintln!(
                "skipping: {ORIGIN_VARIABLE} names no deployment, so nothing was sent anywhere"
            );
            return None;
        }

        let origin = GatewayOrigin::new(named.clone())
            .unwrap_or_else(|error| panic!("{ORIGIN_VARIABLE} names {named}, which is not an origin a credential travels to: {error}"));
        Some(Self::at(origin))
    }

    /// A deployment at one origin, with the bounds this client's operations are read under.
    ///
    /// # Panics
    ///
    /// Panics when the transport cannot be built, which is a fault in this machine's TLS
    /// configuration rather than in the deployment.
    #[must_use]
    pub fn at(origin: GatewayOrigin) -> Self {
        let transport = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport for the origin this run was given");
        Self {
            origin,
            transport: Arc::new(transport),
        }
    }

    /// The origin these legs address.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// The transport every client of this deployment shares.
    ///
    /// One transport, so a leg that speaks as an owner and as a host uses one set of connections
    /// rather than one each. A leg that sends a request no client of this crate will build takes
    /// this and its own signer.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn ServiceHttp> {
        Arc::clone(&self.transport) as Arc<_>
    }

    /// An authority-feed client signing as `who`.
    #[must_use]
    pub fn authority_feed(&self, who: &Arc<RunKey>) -> AuthorityFeedClient {
        AuthorityFeedClient::new(
            self.origin.clone(),
            self.transport(),
            Arc::clone(who) as Arc<_>,
        )
    }
}

/// One principal, made for this run and held in memory.
///
/// The key is generated when the leg starts and discarded when it ends, so nothing a leg signs
/// outlives it and no key of a real device is ever used.
#[derive(Debug)]
pub struct RunKey {
    pair: AuthorisationKeyPair,
    kind: ServiceRequestSigner,
    device_id: DeviceId,
}

impl RunKey {
    /// A device signing as an installation: a remote owner publishing to somebody's feed.
    ///
    /// # Panics
    ///
    /// Panics when a key cannot be generated.
    #[must_use]
    pub fn installation() -> Arc<Self> {
        Self::of(ServiceRequestSigner::Installation)
    }

    /// A device signing as a host: the owner of the feed it addresses.
    ///
    /// # Panics
    ///
    /// Panics when a key cannot be generated.
    #[must_use]
    pub fn host() -> Arc<Self> {
        Self::of(ServiceRequestSigner::Host)
    }

    fn of(kind: ServiceRequestSigner) -> Arc<Self> {
        Arc::new(Self {
            pair: AuthorisationKeyPair::generate().expect("a fresh authorisation key"),
            kind,
            device_id: DeviceId::new(fresh_uuid()),
        })
    }

    /// The signing key itself, for the records this device signs rather than the credential.
    #[must_use]
    pub const fn pair(&self) -> &AuthorisationKeyPair {
        &self.pair
    }

    /// The identifier this device's authorisation key derives, which is the feed it addresses.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        kr_crypto::keys::key_id(KeyPurpose::Authorisation, self.pair.public().as_bytes())
    }

    /// The device identifier this run gave it.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl ServiceSigner for RunKey {
    fn signer(&self) -> ServiceRequestSigner {
        self.kind
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.pair.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        // The transcript refuses bytes that are not a domain-tagged array, so a signer cannot be
        // handed arbitrary bytes to sign under a domain it holds a key for.
        let transcript =
            SigningTranscript::from_canonical_bytes(self.kind.domain(), message.to_vec())
                .expect("a domain-tagged credential");
        Ok(sign(&self.pair, &transcript).expect("a signature"))
    }
}

/// A fresh identifier, drawn for this run alone.
///
/// # Panics
///
/// Panics when the operating system's generator cannot be read.
#[must_use]
pub fn fresh_uuid() -> Uuid {
    let mut bytes = [0u8; 16];
    kr_crypto::random_bytes(&mut bytes).expect("an identifier for this run");
    Uuid::from_bytes(bytes)
}

/// This machine's clock, in UTC milliseconds.
///
/// # Panics
///
/// Panics when the clock is before the epoch.
#[must_use]
pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_millis(),
    )
    .expect("a clock this century")
}

/// Says what one leg proved, in the words the report uses.
///
/// A leg that ran prints one line naming the deployment it ran against and the rule it held that
/// deployment to, so the output reads as a report rather than as test output.
pub fn proved(leg: &str, deployment: &Deployment, what: &str) {
    println!("{leg}: {what} ({})", deployment.origin().as_str());
}

/// An origin nothing answers on, for the legs that prove what an unreachable service means.
///
/// The operating system chooses the port, the listener is closed, and the port is then tried: a
/// connection that is refused is what makes "nothing answers there" a fact this checked rather than
/// one it assumed, and a port something else has taken is put aside for the next one. A refused
/// connection on loopback is immediate, so no deadline and no interval is part of this.
///
/// # Panics
///
/// Panics when every loopback port this run is given is one something else answers on.
#[must_use]
pub fn unreachable_origin() -> GatewayOrigin {
    for _ in 0..16 {
        let port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
            listener
                .local_addr()
                .expect("the port that was taken")
                .port()
        };
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return GatewayOrigin::new(format!("http://127.0.0.1:{port}"))
                .expect("a loopback origin");
        }
    }
    panic!("every loopback port this run was given is one something else answers on");
}
