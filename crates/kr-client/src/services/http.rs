//! The managed-service transport.
//!
//! [`relay::ServiceHttp`] is the exchange every managed-service client is written against, and this
//! is the implementation a shipped client uses. It is asynchronous, so a call that is dropped stops
//! rather than continuing on a thread nobody is waiting for, and it is deliberately small: one
//! origin, one signed JSON body, one bounded answer. It is also the account client's
//! [`AccountHttp`]: a form post and a bearer read, under every rule below.
//!
//! # What it will and will not do
//!
//! | Rule | Why |
//! | --- | --- |
//! | One configured origin per instance, compared as a parsed scheme, host and port | A credential is signed for one deployment, so a request addressed anywhere else is a mistake this client catches rather than a signature it hands to a stranger |
//! | HTTPS, except on loopback | A managed-service request carries a credential; plain HTTP is admitted only for the loopback address a development deployment serves on |
//! | No credentials in the address | A password in a URL is sent before anything is verified and is not part of this protocol's authentication |
//! | No redirects | A redirect moves a signed request to an address its credential does not name. The answer is returned as it came, so a caller sees the redirect rather than following it |
//! | Certificate and hostname verification, against the platform's trust ([`platform_tls`]) | Both stay on. There is no option here that turns either off, and no environment variable chooses the trust |
//! | Finite connect, read and total deadlines | Every call ends. The total deadline covers reading the body, so an answer that never finishes arriving is a failure rather than a wait |
//! | A bounded answer, measured while it is read | A stated content length is the sender's claim. The bound is applied to the bytes as they arrive, and an answer past it is refused rather than truncated, because half an envelope is not an answer |
//! | No cookies, no decompression, and no proxy but the one its caller names | Each of those is something between this client and the service that this client did not ask for. A host names the proxy its configuration document selects, a device names none, and nothing is read from the environment |
//! | Nothing sent again that may have arrived | The service sees one request at most for one dispatch. A request of which no byte was written may travel on another connection, because nothing arrived to be repeated |
//!
//! # One request per dispatch
//!
//! The promise the retry rule exists for is this: **the service sees one request at most for one
//! dispatch.** It is what keeps a request identity and a receipt simple, because a caller that
//! presents an identity again is presenting it deliberately and the service can treat a second
//! arrival as the duplicate it is.
//!
//! So this transport never sends again a request that may have reached the service. A failure after
//! the request was written is returned as an unknown outcome, and whether to ask again is
//! [`crate::retry`]'s decision with that class in view.
//!
//! Connections are pooled, because several service clients over one gateway should be one set of
//! connections rather than one each, and a pooled connection can be taken away between one request
//! and the next: a service, a load balancer or a keep-alive deadline closes an idle one. The HTTP
//! library may therefore open a new connection for a request **of which it has written no byte**,
//! which is not the request being sent again: nothing arrived to be repeated. Both halves are
//! tested — `a_pooled_connection_taken_away_costs_a_connection_and_never_a_second_request` and
//! `a_request_the_service_read_is_never_sent_again`.
//!
//! # What a failure means
//!
//! The distinction this transport keeps is whether the request may have been carried out.
//!
//! A failure the connector itself reported is [`ErrorCode::UpstreamUnavailable`]: an address that
//! could not be resolved, a connection refused, a handshake that failed and an establishment that
//! ran past the connect deadline all happen before a request byte is written, so nothing was sent.
//!
//! Everything else is [`ErrorCode::OutcomeUnknown`], because the service may have acted on the
//! request and this client cannot see whether it did: a read or total deadline, a connection that
//! ended, an answer that could not be read and an answer too large to read. So is this client's own
//! total deadline running out while the connection was still being established, which is
//! conservative in the safe direction: reporting an unknown outcome for a request that never left
//! costs a caller a question, and reporting no effect for one that may have arrived costs it the
//! truth. Section 23 never retries an unknown outcome automatically.
//!
//! # Where a failure happened
//!
//! Beside the class, every failure of an exchange names the [`ExchangePhase`] it happened in:
//! reaching the service, the request on its way, the answer arriving. It is what makes a deadline
//! legible. "It did not finish in time" leaves a caller guessing which deadline ran out and what
//! the service had already seen; "this client's deadline ran out while the answer was arriving"
//! says the service answered and the answer did not finish coming back.
//!
//! The phase is also what a client shows a person while a call is in flight, through
//! [`ExchangeProgress`]. That seam carries the phase and nothing else, and a transport with none
//! set reports nothing.
//!
//! # Diagnostics
//!
//! This module emits none. A request body carries a credential, and a header may carry a token, so
//! nothing here writes either to a log, into an error message or into a rendered structure. A
//! failure names the origin, the path and what went wrong.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use url::{Host, Url};

use super::ServiceFuture;
use super::account::AccountHttp;
use super::relay::{ServiceHttp, ServiceHttpAnswer};
use crate::error::{ClientError, Result};

/// How long a connection may take to establish.
pub const DEFAULT_CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// How long one read of an answer may take.
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(10);

/// How long one exchange may take from first contact to the last byte of the answer.
pub const DEFAULT_TOTAL_DEADLINE: Duration = Duration::from_secs(20);

/// How many bytes of an answer this client reads when an operation names no other figure.
///
/// It is the size of the largest answer the managed methods that carry one object produce, with
/// room for the JSON that encodes it. An operation that pages items states its own.
pub const DEFAULT_RESPONSE_LIMIT_BYTES: u64 = 64 * 1024;

/// The TLS versions this product's clients negotiate: 1.3, and 1.2 with a server that has no newer.
const PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// Where an exchange had reached.
///
/// Every failure of an exchange names one, and the phase rather than an interval is what says what
/// a deadline covered. A caller learns whether the service saw the request, a person reading the
/// message learns what the call was doing, and neither has to know how long anything took.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExchangePhase {
    /// The connection was being established.
    ///
    /// The connector itself reported the failure, so no byte of the request had been written and
    /// the service did not see it.
    Connect,
    /// The request was on its way to the service and the answer's head had not arrived.
    ///
    /// Writing the request and waiting for the head are one phase, because the HTTP library
    /// reports them as one and because they mean the same thing to a caller: the service may have
    /// acted. This client's own total deadline running out before the head arrived is this phase
    /// too, even when the connection was still being established, because nothing this client can
    /// see separates the two and this is the direction that does not promise the request never
    /// left.
    Request,
    /// The answer's head had arrived and its body was still arriving.
    Answer,
}

impl ExchangePhase {
    /// The clause every failure of this phase carries.
    ///
    /// One phrase per phase, used both to write the message and to read the phase back out of it,
    /// so that what a failure says and what it is cannot drift apart.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "while the connection was being established",
            Self::Request => "while the request was on its way to the service",
            Self::Answer => "while the answer was arriving",
        }
    }

    /// Every phase, in the order an exchange passes through them.
    pub const ALL: [Self; 3] = [Self::Connect, Self::Request, Self::Answer];

    /// The phase a failure names, when it names one.
    ///
    /// A request this client refused before it sent anything, and an answer refused for its size,
    /// name no phase: neither is a failure of one. The first never started an exchange and the
    /// second is an answer that arrived and did not fit.
    #[must_use]
    pub fn of(error: &ClientError) -> Option<Self> {
        let message = error.to_string();
        Self::ALL
            .into_iter()
            .find(|phase| message.contains(phase.as_str()))
    }
}

/// Told when an exchange enters a phase this transport can see.
///
/// It is how a client says what a call is doing without knowing anything about HTTP: reaching the
/// service, then receiving its answer. It carries the phase and nothing else, never a byte of a
/// request or an answer, never a credential and never a header value, and a transport with none
/// set reports nothing at all.
///
/// Two transitions are reported, because two are what this transport can see:
/// [`ExchangePhase::Connect`] when an exchange starts and [`ExchangePhase::Answer`] when the
/// answer's head has arrived. [`ExchangePhase::Request`] is a phase a failure names rather than one
/// reported here, because writing the request and waiting for the head happen inside one call to
/// the HTTP library.
pub trait ExchangeProgress: Send + Sync {
    /// The exchange has entered `phase`.
    fn entered(&self, phase: ExchangePhase);
}

/// The deadlines one transport holds itself to.
///
/// All three are finite and all three are enforced. The total is the one that matters to a caller:
/// it covers the connection, the request, the answer's headers and the answer's body, so a call
/// that returns has either an answer or a failure and never a partial read.
///
/// A caller with a shorter deadline of its own keeps it. Dropping the future ends the exchange, so
/// a caller that wraps a call in a five-second bound gets five seconds rather than these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpDeadlines {
    /// How long establishing the connection may take.
    pub connect: Duration,
    /// How long one read of the answer may take.
    pub read: Duration,
    /// How long the whole exchange may take, body included.
    pub total: Duration,
}

impl Default for HttpDeadlines {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_DEADLINE,
            read: DEFAULT_READ_DEADLINE,
            total: DEFAULT_TOTAL_DEADLINE,
        }
    }
}

/// How many bytes of an answer this client reads, by the operation that asked.
///
/// One figure would have to be the largest any operation needs, which would let every other
/// operation's answer grow to it. The path is what names the operation, so the bound is stated
/// against the path and the default applies to everything unstated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseLimits {
    default_bytes: u64,
    by_path: Vec<(String, u64)>,
}

impl ResponseLimits {
    /// Builds a set of limits whose unstated operations get `default_bytes`.
    #[must_use]
    pub const fn new(default_bytes: u64) -> Self {
        Self {
            default_bytes,
            by_path: Vec::new(),
        }
    }

    /// States the bound for one path, replacing any bound already stated for it.
    #[must_use]
    pub fn for_path(mut self, path: &str, bytes: u64) -> Self {
        if let Some(entry) = self.by_path.iter_mut().find(|(held, _)| held == path) {
            entry.1 = bytes;
        } else {
            self.by_path.push((path.to_owned(), bytes));
        }
        self
    }

    /// Returns the bound this path is read under.
    #[must_use]
    pub fn of(&self, path: &str) -> u64 {
        self.by_path
            .iter()
            .find(|(held, _)| held == path)
            .map_or(self.default_bytes, |(_, bytes)| *bytes)
    }
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self::new(DEFAULT_RESPONSE_LIMIT_BYTES)
    }
}

/// The transport a shipped client makes its managed-service requests through.
///
/// One instance addresses one gateway. Cloning it shares the connection pool, which is what makes
/// several service clients over one gateway one set of connections rather than one each.
#[derive(Clone)]
pub struct HttpService {
    origin: GatewayOrigin,
    address: Url,
    client: reqwest::Client,
    deadlines: HttpDeadlines,
    limits: ResponseLimits,
    progress: Option<Arc<dyn ExchangeProgress>>,
}

impl fmt::Debug for HttpService {
    /// Names the gateway and the rules, and nothing that travelled through it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpService")
            .field("origin", &self.origin.as_str())
            .field("deadlines", &self.deadlines)
            .field("limits", &self.limits)
            .finish()
    }
}

impl HttpService {
    /// Builds a transport for one gateway, with this client's own deadlines and bounds, that
    /// reaches the gateway directly.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not one this transport will address, or when the
    /// platform's certificate verification cannot be set up.
    pub fn new(origin: GatewayOrigin) -> Result<Self> {
        Self::with(origin, HttpDeadlines::default(), ResponseLimits::default())
    }

    /// Builds a transport with stated deadlines and bounds, that reaches its gateway directly.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not one this transport will address, when a deadline is
    /// zero, or when the platform's certificate verification cannot be set up.
    pub fn with(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
    ) -> Result<Self> {
        Self::through(origin, deadlines, limits, None)
    }

    /// Builds a transport with stated deadlines and bounds, that reaches its gateway through
    /// `proxy`, or directly when that is `None`.
    ///
    /// The proxy is always the caller's to name. A host passes the one its configuration document
    /// selects, and a device, which has no such document, passes none. Nothing is read from the
    /// environment either way, and a proxy that cannot be reached is not gone around.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not one this transport will address, when a deadline is
    /// zero, or when the platform's certificate verification cannot be set up.
    pub fn through(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
        proxy: Option<&ProxyUrl>,
    ) -> Result<Self> {
        Self::build(origin, deadlines, limits, proxy, &[])
    }

    fn build(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
        proxy: Option<&ProxyUrl>,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self> {
        let address = Url::parse(origin.as_str())
            .map_err(|_| refused("this client cannot read the gateway origin it was given"))?;
        if !carries_transport_security(&address) {
            return Err(refused(
                "a gateway origin uses https unless it is a loopback address",
            ));
        }
        if deadlines.connect.is_zero() || deadlines.read.is_zero() || deadlines.total.is_zero() {
            return Err(refused("every transport deadline is a positive interval"));
        }

        let client = builder_trusting(proxy, extra_roots)?
            .user_agent(concat!("kalareach/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(deadlines.connect)
            .read_timeout(deadlines.read)
            .timeout(deadlines.total)
            .redirect(reqwest::redirect::Policy::none())
            // Nothing that reached the service is sent again: see this module's note on one
            // request per dispatch. This switches off the library's own policy, which would resend
            // a request the service refused at the protocol level; what remains is the pool
            // opening another connection for a request it has not started writing.
            .retry(reqwest::retry::never())
            .referer(false)
            .http1_only()
            .build()
            .map_err(|_| refused("this client could not configure its transport"))?;

        Ok(Self {
            origin,
            address,
            client,
            deadlines,
            limits,
            progress: None,
        })
    }

    /// Reports every phase of every exchange to `progress` from here on.
    ///
    /// One per transport, and a clone reports to the same one, which is what makes a gateway's
    /// several service clients one account of what that gateway is doing.
    #[must_use]
    pub fn reporting_to(mut self, progress: Arc<dyn ExchangeProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Says that an exchange has entered a phase, to whoever asked to be told.
    fn entered(&self, phase: ExchangePhase) {
        if let Some(progress) = &self.progress {
            progress.entered(phase);
        }
    }

    /// The gateway this transport addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// The deadlines it holds itself to.
    #[must_use]
    pub const fn deadlines(&self) -> HttpDeadlines {
        self.deadlines
    }

    /// The bounds it reads answers under.
    #[must_use]
    pub const fn limits(&self) -> &ResponseLimits {
        &self.limits
    }

    /// Checks one request address against the gateway this transport was built for.
    ///
    /// Three refusals, in the order a caller can act on. An address this client cannot read is a
    /// mistake in the caller. An address carrying credentials is refused before the origins are
    /// compared, because a password in front of the host would otherwise pass a comparison of the
    /// host. Plain HTTP is refused off loopback. Only then are scheme, host and port compared with
    /// the configured origin's, parsed rather than as text, so one address spelled two ways is one
    /// origin.
    fn target(&self, url: &str) -> Result<Url> {
        let requested = Url::parse(url)
            .map_err(|_| refused("this client cannot read the address it was asked to call"))?;
        if !requested.username().is_empty() || requested.password().is_some() {
            return Err(refused("a request address carries no credentials"));
        }
        if !carries_transport_security(&requested) {
            return Err(refused(
                "a request address uses https unless it is a loopback address",
            ));
        }
        if !same_origin(&self.address, &requested) {
            return Err(refused(format!(
                "this client is configured for {} and was asked to call another origin",
                self.origin.as_str()
            )));
        }
        Ok(requested)
    }

    /// Sends one request and reads its answer under the bound the path states.
    ///
    /// `body` is the content type and the bytes, for a request that carries one.
    async fn exchange(
        &self,
        method: reqwest::Method,
        target: Url,
        body: Option<(&str, &[u8])>,
        headers: &[(&str, &str)],
    ) -> Result<ServiceHttpAnswer> {
        let limit = self.limits.of(target.path());
        let named = format!("{}{}", self.origin.as_str(), target.path());

        let mut request = self.client.request(method, target);
        if let Some((content_type, bytes)) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes.to_vec());
        }
        for (name, value) in headers {
            // A header value can be a token, so neither the name's value nor the value itself
            // reaches this error.
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| refused("a request header name is not one this client can send"))?;
            let value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| refused("a request header value is not one this client can send"))?;
            request = request.header(name, value);
        }

        self.entered(ExchangePhase::Connect);
        let mut response = request
            .send()
            .await
            .map_err(|error| failure(&named, phase_of(&error), &error))?;
        let status = response.status().as_u16();
        // The head is in hand, so what remains of the exchange is the body.
        self.entered(ExchangePhase::Answer);

        // The stated length is the sender's claim, so it is worth refusing early and worth nothing
        // on its own: the bound below is applied to the bytes that actually arrive.
        if response
            .content_length()
            .is_some_and(|stated| stated > limit)
        {
            return Err(too_large(&named, limit));
        }

        let mut read = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|error| failure(&named, ExchangePhase::Answer, &error))?;
            let Some(chunk) = chunk else { break };
            if read.len() as u64 + chunk.len() as u64 > limit {
                return Err(too_large(&named, limit));
            }
            read.extend_from_slice(&chunk);
        }

        Ok(ServiceHttpAnswer { status, body: read })
    }
}

impl ServiceHttp for HttpService {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            // The three deadlines are the transport's own and they are enforced where the bytes
            // are: the connect one inside the connector, the read one on each read of the answer,
            // and the total one across the connection, the request and every byte of the body. So
            // a failure arrives from the phase it happened in and says which phase that was,
            // rather than from a watchdog wrapped round the whole thing that could only say that
            // something somewhere took too long.
            let target = self.target(url)?;
            self.exchange(
                reqwest::Method::POST,
                target,
                Some(("application/json", body)),
                headers,
            )
            .await
        })
    }
}

impl AccountHttp for HttpService {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let target = self.target(url)?;
            self.exchange(
                reqwest::Method::POST,
                target,
                Some(("application/x-www-form-urlencoded", body)),
                &[],
            )
            .await
        })
    }

    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let target = self.target(url)?;
            self.exchange(reqwest::Method::GET, target, None, headers)
                .await
        })
    }
}

/// Whether this address is one a credential may travel over.
///
/// HTTPS anywhere, and plain HTTP on loopback alone, which is what a development deployment serves
/// on. Nothing else: an origin that is neither is refused where it is configured and again where it
/// is called, because the two are set in different places and either one alone would be a rule with
/// a way round it.
fn carries_transport_security(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => is_loopback(url),
        _ => false,
    }
}

/// Whether this address names the loopback interface.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Whether two addresses are the same origin: scheme, host and port, parsed.
///
/// The port is the effective one, so `https://host` and `https://host:443` are one origin, and a
/// host is compared without regard to case because a host name is not case sensitive.
fn same_origin(configured: &Url, requested: &Url) -> bool {
    configured.scheme() == requested.scheme()
        && configured.port_or_known_default() == requested.port_or_known_default()
        && match (configured.host(), requested.host()) {
            (Some(Host::Domain(held)), Some(Host::Domain(asked))) => {
                held.eq_ignore_ascii_case(asked)
            }
            (Some(held), Some(asked)) => held == asked,
            _ => false,
        }
}

/// Installs the cryptographic provider this client's TLS is built on.
///
/// Once per process, and never over one another library installed first: a process that has already
/// chosen a provider keeps it, because two implementations of the same primitives in one process is
/// the thing this avoids rather than the thing it causes.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Starts an HTTP client with this product's trust and the proxy it is given, and nothing of the
/// environment's.
///
/// An HTTP client this product builds outside the network endpoint starts here, so two things are
/// decided in one place: the certificates it trusts are [`platform_tls`]'s, and it goes through
/// `proxy`, or directly, and never through a proxy the environment names. Its deadlines, its
/// redirects and its retries are its caller's.
///
/// # Errors
///
/// Returns an error when the platform's certificate verification cannot be set up.
pub fn client_builder(proxy: Option<&ProxyUrl>) -> Result<reqwest::ClientBuilder> {
    builder_trusting(proxy, &[])
}

/// As [`client_builder`], also trusting `extra_roots`.
fn builder_trusting(
    proxy: Option<&ProxyUrl>,
    extra_roots: &[CertificateDer<'static>],
) -> Result<reqwest::ClientBuilder> {
    install_crypto_provider();
    let mut tls = platform_tls(extra_roots).map_err(|error| {
        refused(format!(
            "this client could not set up the platform's certificate verification: {error}"
        ))
    })?;
    // HTTP/1.1 is the one protocol these clients speak, so it is the one they offer.
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let builder = reqwest::Client::builder().tls_backend_preconfigured(tls);
    Ok(match proxy {
        Some(proxy) => builder.proxy(
            reqwest::Proxy::all(proxy.as_url().clone())
                .map_err(|_| refused("this client cannot use the proxy it was given"))?,
        ),
        None => builder.no_proxy(),
    })
}

/// The TLS client configuration this product's clients verify a server with.
///
/// TLS 1.3, or 1.2 with a server that has no newer, and the trust [`platform_verifier`] describes.
/// `extra_roots` adds authorities beside the platform's: every shipped client passes none, and a
/// test passes the authority its own server was issued by.
///
/// # Errors
///
/// Returns the reason when the platform's certificate verification cannot be set up.
pub fn platform_tls(
    extra_roots: &[CertificateDer<'static>],
) -> std::result::Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = platform_verifier(Arc::clone(&provider), extra_roots)?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// Who this product trusts to vouch for a server.
///
/// On macOS, Windows, iOS and Android it is the operating system's own verifier, whose trust
/// settings are the person's to manage there and which reads nothing from the environment. On
/// Linux the platform verifier reads `SSL_CERT_FILE` and `SSL_CERT_DIR`, and while either is set it
/// trusts only what they name, so an inherited variable would decide who may answer for a service.
/// There it is the distribution's own certificate store instead, read from its fixed locations with
/// neither variable consulted: an authority given only through them is not trusted until it is
/// installed in the system store.
fn platform_verifier(
    provider: Arc<CryptoProvider>,
    extra_roots: &[CertificateDer<'static>],
) -> std::result::Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    #[cfg(target_os = "linux")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(system_store::certificates());
        for root in extra_roots {
            roots.add(root.clone())?;
        }
        if roots.is_empty() {
            return Err(rustls::Error::General(
                "no certificate authority was found in the system store".to_owned(),
            ));
        }
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| rustls::Error::General(error.to_string()))?;
        Ok(verifier)
    }
    #[cfg(target_os = "android")]
    {
        // Android's verifier takes no authority beside the platform's, and no shipped client
        // passes one.
        let _ = extra_roots;
        Ok(Arc::new(rustls_platform_verifier::Verifier::new(provider)?))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Ok(Arc::new(
            rustls_platform_verifier::Verifier::new_with_extra_roots(
                extra_roots.iter().cloned(),
                provider,
            )?,
        ))
    }
}

/// The distribution's certificate store, read where the platform verifier reads it when neither
/// variable names another place.
///
/// The locations are openssl-probe 0.2.1's for Linux (`CERTIFICATE_FILE_NAMES` and
/// `CERTIFICATE_DIRS`), the crate the platform verifier asks, and they are taken the way it takes
/// them: the first bundle that exists, and every directory that exists. openssl-probe hands them
/// out only through a function that reads both variables first, so the lists are written here.
#[cfg(target_os = "linux")]
mod system_store {
    use std::path::Path;

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    /// The bundles one distribution or another keeps its authorities in. The first that exists is
    /// read.
    const BUNDLES: [&str; 8] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
        "/opt/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/cacert.pem",
    ];

    /// The directories of single authorities. Every one that exists is read.
    const DIRECTORIES: [&str; 3] = [
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/etc/security/certificates",
    ];

    /// Every certificate the store holds, each once.
    pub(super) fn certificates() -> Vec<CertificateDer<'static>> {
        let mut found = Vec::new();
        if let Some(bundle) = BUNDLES.iter().map(Path::new).find(|path| path.exists()) {
            read(bundle, &mut found);
        }
        for directory in DIRECTORIES.iter().map(Path::new) {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // A directory of authorities is mostly links, so what counts is what a link names.
                if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
                    read(&path, &mut found);
                }
            }
        }
        found.sort_unstable_by(|one, other| one.as_ref().cmp(other.as_ref()));
        found.dedup();
        found
    }

    /// Adds the certificates one file holds. A file that cannot be read, and anything in one that
    /// is not a certificate, is passed over, as the platform verifier passes it over.
    fn read(path: &Path, into: &mut Vec<CertificateDer<'static>>) {
        if let Ok(certificates) = CertificateDer::pem_file_iter(path) {
            into.extend(certificates.filter_map(std::result::Result::ok));
        }
    }
}

/// A request this client would not send. Nothing left this device.
fn refused(what: impl Into<String>) -> ClientError {
    ClientError::Host(ProtocolError::new(ErrorCode::InvalidArgument, what.into()))
}

/// The service was never reached, so the request was not carried out.
fn unreachable(named: &str, why: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::UpstreamUnavailable,
        format!("{named} could not be reached: {why}"),
    ))
}

/// The request may have been carried out and this client cannot see whether it was.
fn uncertain(named: &str, why: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        format!("{named}: {why}"),
    ))
}

/// An answer past the bound its operation is read under.
///
/// It is an unknown outcome rather than a plain failure: the request reached the service and the
/// service answered, so whatever it did is done, and what this client lacks is the answer.
fn too_large(named: &str, limit: u64) -> ClientError {
    uncertain(
        named,
        &format!("its answer is larger than the {limit} bytes this client reads"),
    )
}

/// Which phase a failure of the send belongs to.
///
/// The connector is the one part of the exchange that reports its own failures, and it runs before
/// a request byte is written, so a failure it reported is the connect phase and everything else the
/// send can produce is the request phase.
fn phase_of(error: &reqwest::Error) -> ExchangePhase {
    if error.is_connect() {
        ExchangePhase::Connect
    } else {
        ExchangePhase::Request
    }
}

/// What one exchange's failure means, in the only terms that matter to a caller.
///
/// Two things: whether the request may have been carried out, and where the exchange was. A failure
/// inside the connector happened before any request byte was written, so the request was not
/// carried out. Everything else may have been: a deadline, a connection that ended and an answer
/// that could not be read all leave a request that the service may have acted on.
fn failure(named: &str, phase: ExchangePhase, error: &reqwest::Error) -> ClientError {
    let cause = if error.is_timeout() {
        "this client's deadline ran out"
    } else if error.is_decode() {
        "what came back could not be read"
    } else {
        "the exchange ended"
    };
    let why = format!("{cause} {}", phase.as_str());

    match phase {
        ExchangePhase::Connect => unreachable(named, &why),
        ExchangePhase::Request | ExchangePhase::Answer => uncertain(named, &why),
    }
}

#[cfg(test)]
impl HttpService {
    /// Builds a transport that also trusts one certificate the caller supplies.
    ///
    /// It is how the contract above is checked against a real handshake: a server on loopback, a
    /// certificate issued for it, and every verification this transport does left switched on.
    fn trusting(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
        root: &[u8],
    ) -> Result<Self> {
        Self::build(
            origin,
            deadlines,
            limits,
            None,
            &[CertificateDer::from(root.to_vec())],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ServerConfig, crypto::ring};

    /// A body large enough that no bound in these tests admits it by accident.
    const OVERSIZE: usize = 8 * 1024;

    /// How long a wait for something the gateway or the transport reports may take before the test
    /// gives up on it.
    ///
    /// It is a watchdog and never a claim: it turns a wait that would hang into a failure with a
    /// name on it. No test's evidence is how long something took.
    const WATCHDOG: Duration = Duration::from_secs(60);

    /// The deadline a phase test is about.
    ///
    /// A day, against a [`WATCHDOG`] of a minute, which is the point: a phase test reaches its
    /// phase under the ordinary clock and then advances the clock by hand, so no deadline in it is
    /// reachable by any delay short of the machine being dead for a day. Wherever the test waits
    /// for a signal the watchdog runs out first, and a watchdog running out is a named failure that
    /// says what the test was waiting for rather than a deadline firing in the wrong phase.
    const UNDER_TEST: Duration = Duration::from_secs(60 * 60 * 24);

    /// The deadlines a phase test is not about.
    ///
    /// Thirty times [`UNDER_TEST`], so how far the test advanced its clock says which of the three
    /// ended the exchange. It is also what the fixture's own transport holds, so a test that is not
    /// about a deadline holds none that anything can reach.
    const OUT_OF_REACH: Duration = Duration::from_secs(60 * 60 * 24 * 30);

    const _: () = assert!(WATCHDOG.as_secs() < UNDER_TEST.as_secs());
    const _: () = assert!(UNDER_TEST.as_secs() < OUT_OF_REACH.as_secs());

    /// The deadlines a test that is not about a deadline holds.
    ///
    /// Thirty days each, so nothing this machine does can reach one. Every transport in this
    /// module that is not itself the subject of a deadline test is built with these, including the
    /// ones built for an origin the fixture does not serve.
    const fn out_of_reach() -> HttpDeadlines {
        HttpDeadlines {
            connect: OUT_OF_REACH,
            read: OUT_OF_REACH,
            total: OUT_OF_REACH,
        }
    }

    /// How far past a deadline a test's clock can land when it advances to one.
    ///
    /// Timers are held to a millisecond at both ends of the step: the deadline is rounded up to the
    /// millisecond it is kept at, and the clock's position is read at the millisecond it is on, so
    /// the step between them can be two of those longer than the deadline itself. It is the
    /// granularity of the clock rather than slack for a slow machine, and it cannot grow with load:
    /// the deadline a test is not about is thirty days away.
    const CLOCK_GRAIN: Duration = Duration::from_millis(2);

    /// What the loopback gateway does with a request it has read.
    ///
    /// Every behaviour that states a length keeps the connection open afterwards, so one gateway
    /// answers several requests on one connection and the pool has something to reuse.
    #[derive(Clone, Debug)]
    enum Behaviour {
        /// Answer with this status and body, and state the body's length.
        Answer { status: u16, body: Vec<u8> },
        /// Answer with a head stating this length, write this much of the body, and stop there.
        ///
        /// The answer's head is in the client's hands and its body never finishes, which is the
        /// one phase a deadline can cover that no earlier phase can.
        HeadThenStall { stated: usize, body: Vec<u8> },
        /// Answer with this status and body and state no length, closing to mark the end.
        AnswerWithoutLength { status: u16, body: Vec<u8> },
        /// Answer with this status and body, stating the length and these extra headers.
        WithHeaders {
            status: u16,
            body: Vec<u8>,
            headers: Vec<(String, String)>,
        },
        /// Answer in chunks, with these trailers after the last one.
        Chunked {
            status: u16,
            chunks: Vec<Vec<u8>>,
            trailers: Vec<(String, String)>,
        },
        /// Answer with valid chunked framing and a stated length that disagrees with it.
        LengthAndChunked { stated: usize, chunks: Vec<Vec<u8>> },
        /// Answer claiming chunked framing and then sending something that is not a chunk.
        FramingThisIsNot,
        /// Answer stating a length shorter than what follows it.
        ShorterThanItSends { stated: usize, body: Vec<u8> },
        /// Send an informational answer, then the real one.
        Informational { informational: u16, body: Vec<u8> },
        /// Answer with a redirect to another address.
        Redirect { location: String },
        /// Answer with a head that states no length, then write the body one byte at a time.
        Trickle { bytes: usize },
        /// Read the request and answer nothing at all, holding the connection open.
        Silent,
        /// Read the request and then end the connection without answering.
        HangUp,
        /// Answer the first request this gateway reads, then read the next and end the connection.
        ///
        /// The first this gateway reads rather than the first on a connection, so which connection
        /// a request travels on cannot change what happens to it.
        AnswerThenHangUp { status: u16, body: Vec<u8> },
        /// Answer every request, and end the connection once it has been idle this long.
        CloseWhenIdle {
            status: u16,
            body: Vec<u8>,
            idle: Duration,
        },
        /// Accept the connection and never speak TLS, so establishing it never finishes.
        AcceptAndStall,
    }

    /// Which certificate the loopback gateway presents.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Presents {
        /// A certificate for `localhost`, issued by the authority the client is given.
        ItsOwnName,
        /// A certificate for another name, issued by the authority the client is given.
        AnotherName,
        /// A certificate for `localhost`, issued by an authority the client is not given.
        AnUntrustedAuthority,
    }

    /// One request the loopback gateway read.
    #[derive(Clone, Debug)]
    struct Received {
        head: String,
        body: Vec<u8>,
    }

    /// What the loopback gateway saw, which is what a test asserts against.
    ///
    /// A test that turns on an interval is a test that fails under load, so a test waits for one of
    /// these to change rather than for time to pass: the connection was accepted, the request
    /// arrived, the body started, the connection went away. `changed` is how a waiter is told,
    /// so no wait polls and no wait sleeps.
    #[derive(Default)]
    struct Saw {
        received: Mutex<Vec<Received>>,
        connections: Mutex<usize>,
        closed: Mutex<usize>,
        body_bytes_written: Mutex<usize>,
        changed: tokio::sync::Notify,
    }

    /// A TLS gateway on loopback, with a certificate authority of its own.
    struct Gateway {
        origin: GatewayOrigin,
        root: Vec<u8>,
        saw: Arc<Saw>,
        task: JoinHandle<()>,
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Gateway {
        async fn start(behaviour: Behaviour) -> Self {
            Self::presenting(behaviour, Presents::ItsOwnName).await
        }

        async fn presenting(behaviour: Behaviour, presents: Presents) -> Self {
            let _ = ring::default_provider().install_default();

            let (authority_der, authority) = certificate_authority("kalareach test authority");
            let (other_der, other) = certificate_authority("another authority");
            let name = match presents {
                Presents::AnotherName => "gateway.invalid",
                Presents::ItsOwnName | Presents::AnUntrustedAuthority => "localhost",
            };
            let issuer = match presents {
                Presents::AnUntrustedAuthority => &other,
                Presents::ItsOwnName | Presents::AnotherName => &authority,
            };
            let leaf_key = KeyPair::generate().expect("a key pair");
            let leaf = CertificateParams::new(vec![name.to_owned()])
                .expect("certificate parameters")
                .signed_by(&leaf_key, issuer)
                .expect("a signed certificate");

            let chain = vec![
                leaf.der().clone(),
                match presents {
                    Presents::AnUntrustedAuthority => other_der.clone(),
                    Presents::ItsOwnName | Presents::AnotherName => authority_der.clone(),
                },
            ];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("a server configuration");
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(config));

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("a loopback port");
            let port = listener.local_addr().expect("an address").port();
            let saw = Arc::new(Saw::default());
            let task = tokio::spawn(serve(listener, acceptor, behaviour, Arc::clone(&saw)));

            Self {
                origin: GatewayOrigin::new(format!("https://localhost:{port}"))
                    .expect("a gateway origin"),
                root: authority_der.to_vec(),
                saw,
                task,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.origin.as_str())
        }

        /// A transport for this gateway holding no deadline anything can reach.
        ///
        /// A test that is not about a deadline must not be able to end at one, so the fixture's own
        /// transport keeps all three thirty days away. The tests that are about a deadline state
        /// their own with [`Self::deadlined`] and advance the clock to it.
        fn transport(&self) -> HttpService {
            self.reading(ResponseLimits::default())
        }

        /// The same transport, reading answers under a stated bound.
        ///
        /// It is how a test about a bound gets one: the deadlines stay out of reach, so the bound
        /// is the only thing in the exchange that can end it. Neither this nor [`Self::deadlined`]
        /// takes a bound and a deadline together, and they are the only two ways to reach this
        /// fixture's gateway, because a test about a bound holding a production deadline is how a
        /// test ends up measuring the machine.
        fn reading(&self, limits: ResponseLimits) -> HttpService {
            HttpService::trusting(self.origin.clone(), out_of_reach(), limits, &self.root)
                .expect("a transport")
        }

        /// A transport whose deadlines are the ones a test about a deadline states.
        ///
        /// Every one of them is [`UNDER_TEST`] or [`OUT_OF_REACH`], both far beyond any delay this
        /// machine can produce, and the test advances the clock to the one it is about.
        fn deadlined(&self, deadlines: HttpDeadlines) -> HttpService {
            HttpService::trusting(
                self.origin.clone(),
                deadlines,
                ResponseLimits::default(),
                &self.root,
            )
            .expect("a transport")
        }

        fn received(&self) -> Vec<Received> {
            self.saw.received.lock().expect("the record").clone()
        }

        fn connections(&self) -> usize {
            *self.saw.connections.lock().expect("the record")
        }

        fn closed(&self) -> usize {
            *self.saw.closed.lock().expect("the record")
        }

        fn body_bytes_written(&self) -> usize {
            *self.saw.body_bytes_written.lock().expect("the record")
        }

        /// Waits until this gateway has seen what the test is waiting for.
        ///
        /// The wait turns on what the gateway recorded and never on an interval, so nothing here
        /// is faster or slower on a loaded machine; [`WATCHDOG`] only turns a wait that would hang
        /// into a failure that says what it was waiting for.
        async fn until(&self, what: &str, ready: impl Fn(&Self) -> bool) {
            let waiting = async {
                loop {
                    // Registered before the state is read, so a change between the read and the
                    // wait is a wake and not a wait forever.
                    let change = self.saw.changed.notified();
                    tokio::pin!(change);
                    change.as_mut().enable();
                    if ready(self) {
                        return;
                    }
                    change.await;
                }
            };
            assert!(
                tokio::time::timeout(WATCHDOG, waiting).await.is_ok(),
                "the gateway did not see {what}"
            );
        }
    }

    /// Builds a certificate authority and the issuer that signs with it.
    fn certificate_authority(name: &str) -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::new(Vec::new()).expect("certificate parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, name.to_owned());
        let key = KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("a self-signed certificate");
        let der = certificate.der().clone();
        (der, Issuer::new(params, key))
    }

    /// Accepts connections until the gateway is dropped, one behaviour for each.
    async fn serve(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        behaviour: Behaviour,
        saw: Arc<Saw>,
    ) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            *saw.connections.lock().expect("the record") += 1;
            saw.changed.notify_waiters();
            let acceptor = acceptor.clone();
            let behaviour = behaviour.clone();
            let saw = Arc::clone(&saw);
            tokio::spawn(async move {
                let _ = answer(stream, acceptor, behaviour, Arc::clone(&saw)).await;
                *saw.closed.lock().expect("the record") += 1;
                saw.changed.notify_waiters();
            });
        }
    }

    /// Serves one connection: every request it carries, in the behaviour's own terms.
    async fn answer(
        stream: TcpStream,
        acceptor: TlsAcceptor,
        behaviour: Behaviour,
        saw: Arc<Saw>,
    ) -> io::Result<()> {
        if matches!(behaviour, Behaviour::AcceptAndStall) {
            // Connected at the transport and never at TLS, which is establishment that never
            // finishes rather than a connection that was refused.
            std::future::pending::<()>().await;
        }
        let mut stream = acceptor.accept(stream).await?;

        let mut served = 0usize;
        loop {
            let idle = match &behaviour {
                Behaviour::CloseWhenIdle { idle, .. } => Some(*idle),
                _ => None,
            };
            let request = match idle {
                // Only what follows an answer is idleness. The first request on a connection is
                // read without a deadline, so a machine under load cannot make this gateway close
                // a connection it has not answered on.
                Some(idle) if served > 0 => {
                    match tokio::time::timeout(idle, read_request(&mut stream)).await {
                        Ok(request) => request?,
                        // Idle for long enough: the pooled connection is taken away, which is what
                        // a service, a load balancer or a keep-alive deadline does. The read that
                        // follows ends when the client's own end goes away, so this connection
                        // counts as closed once the client has seen the close rather than once the
                        // gateway sent it.
                        Err(_) => {
                            stream.shutdown().await?;
                            let mut ignored = [0u8; 256];
                            while stream.read(&mut ignored).await? > 0 {}
                            return Ok(());
                        }
                    }
                }
                Some(_) | None => read_request(&mut stream).await?,
            };
            saw.received.lock().expect("the record").push(request);
            saw.changed.notify_waiters();
            served += 1;

            if !act(&mut stream, &behaviour, &saw).await? {
                return Ok(());
            }
        }
    }

    /// Acts on one request. Returns whether this connection carries another.
    async fn act<S>(stream: &mut S, behaviour: &Behaviour, saw: &Saw) -> io::Result<bool>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match behaviour {
            Behaviour::Answer { status, body } | Behaviour::CloseWhenIdle { status, body, .. } => {
                write_answer(stream, *status, body, &[]).await?;
            }
            Behaviour::WithHeaders {
                status,
                body,
                headers,
            } => {
                write_answer(stream, *status, body, headers).await?;
            }
            Behaviour::AnswerThenHangUp { status, body } => {
                if saw.received.lock().expect("the record").len() == 1 {
                    write_answer(stream, *status, body, &[]).await?;
                } else {
                    // The request was read whole and the connection ended with no answer, which is
                    // the case a caller cannot tell from a request that was carried out.
                    stream.shutdown().await?;
                    return Ok(false);
                }
            }
            Behaviour::AnswerWithoutLength { status, body } => {
                let head = format!(
                    "HTTP/1.1 {status} \r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(body).await?;
                stream.flush().await?;
                stream.shutdown().await?;
                return Ok(false);
            }
            Behaviour::Chunked {
                status,
                chunks,
                trailers,
            } => {
                let mut head = format!(
                    "HTTP/1.1 {status} \r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n"
                );
                if !trailers.is_empty() {
                    let names: Vec<&str> = trailers.iter().map(|(name, _)| name.as_str()).collect();
                    head.push_str(&format!("trailer: {}\r\n", names.join(", ")));
                }
                head.push_str("\r\n");
                stream.write_all(head.as_bytes()).await?;
                for chunk in chunks {
                    stream
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await?;
                    stream.write_all(chunk).await?;
                    stream.write_all(b"\r\n").await?;
                    stream.flush().await?;
                }
                stream.write_all(b"0\r\n").await?;
                for (name, value) in trailers {
                    stream
                        .write_all(format!("{name}: {value}\r\n").as_bytes())
                        .await?;
                }
                stream.write_all(b"\r\n").await?;
                stream.flush().await?;
            }
            Behaviour::LengthAndChunked { stated, chunks } => {
                let head = format!(
                    "HTTP/1.1 200 \r\ncontent-type: application/json\r\ncontent-length: {stated}\r\ntransfer-encoding: chunked\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await?;
                for chunk in chunks {
                    stream
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await?;
                    stream.write_all(chunk).await?;
                    stream.write_all(b"\r\n").await?;
                }
                stream.write_all(b"0\r\n\r\n").await?;
                stream.flush().await?;
                stream.shutdown().await?;
                return Ok(false);
            }
            Behaviour::FramingThisIsNot => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 \r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{\"ok\":true}",
                    )
                    .await?;
                stream.flush().await?;
                stream.shutdown().await?;
                return Ok(false);
            }
            Behaviour::ShorterThanItSends { stated, body } => {
                let head = format!(
                    "HTTP/1.1 200 \r\ncontent-type: application/json\r\ncontent-length: {stated}\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(body).await?;
                stream.flush().await?;
            }
            Behaviour::Informational {
                informational,
                body,
            } => {
                stream
                    .write_all(format!("HTTP/1.1 {informational} \r\n\r\n").as_bytes())
                    .await?;
                stream.flush().await?;
                write_answer(stream, 200, body, &[]).await?;
            }
            Behaviour::Redirect { location } => {
                let head = format!(
                    "HTTP/1.1 302 \r\nlocation: {location}\r\ncontent-length: 9\r\n\r\nelsewhere"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.flush().await?;
            }
            Behaviour::HeadThenStall { stated, body } => {
                let head = format!(
                    "HTTP/1.1 200 \r\ncontent-type: application/json\r\ncontent-length: {stated}\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(body).await?;
                stream.flush().await?;
                *saw.body_bytes_written.lock().expect("the record") += body.len();
                saw.changed.notify_waiters();
                // The rest of the body never comes. Nothing here is on a timer, so the only thing
                // that can end the exchange is a deadline the client holds itself to.
                std::future::pending::<()>().await;
                return Ok(false);
            }
            Behaviour::Trickle { bytes } => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 \r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
                    )
                    .await?;
                stream.flush().await?;
                for _ in 0..*bytes {
                    stream.write_all(b".").await?;
                    stream.flush().await?;
                    *saw.body_bytes_written.lock().expect("the record") += 1;
                    saw.changed.notify_waiters();
                    // A yield rather than a pause: the point is that the body arrives in pieces a
                    // client has to count as they come, and an interval would make the test's
                    // outcome depend on how busy the machine is.
                    tokio::task::yield_now().await;
                }
                return Ok(false);
            }
            Behaviour::Silent => {
                // Never an answer, and a read that ends when the other end goes away, so a caller
                // that walked away is something this gateway records rather than something a test
                // has to infer from a clock.
                let mut ignored = [0u8; 256];
                while stream.read(&mut ignored).await? > 0 {}
                return Ok(false);
            }
            Behaviour::HangUp => {
                stream.shutdown().await?;
                return Ok(false);
            }
            Behaviour::AcceptAndStall => unreachable!("the connection never reaches a request"),
        }
        Ok(true)
    }

    /// Writes one answer whose length is stated, leaving the connection open.
    ///
    /// A 204 and a 304 have no message body at all, so neither carries a length.
    async fn write_answer<S>(
        stream: &mut S,
        status: u16,
        body: &[u8],
        headers: &[(String, String)],
    ) -> io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let mut head = format!("HTTP/1.1 {status} \r\n");
        if status != 204 && status != 304 {
            head.push_str(&format!(
                "content-type: application/json\r\ncontent-length: {}\r\n",
                body.len()
            ));
        }
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await?;
        if status != 204 && status != 304 {
            stream.write_all(body).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    /// Reads one HTTP/1.1 request: its head, and the body its content length names.
    async fn read_request<S>(stream: &mut S) -> io::Result<Received>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            buffer.push(byte[0]);
        }
        if !buffer.ends_with(b"\r\n\r\n") {
            // The other end closed rather than sending another request, so there is nothing here
            // to record: a connection that carried no request is not a request.
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let head = String::from_utf8_lossy(&buffer).into_owned();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        if length > 0 {
            stream.read_exact(&mut body).await?;
        }
        Ok(Received { head, body })
    }

    fn code(error: &ClientError) -> ErrorCode {
        error.code()
    }

    /// Every phase an exchange reported, and a wait for one of them.
    ///
    /// It is the production seam, used the way a client with something to show a person uses it.
    /// A test that has to stall an exchange in the answer phase needs to know the exchange is in
    /// it, and this is the transport saying so; the alternative is guessing from what the gateway
    /// wrote, which says what the service sent and not what the client read.
    #[derive(Default)]
    struct Reached {
        phases: Mutex<Vec<ExchangePhase>>,
        changed: tokio::sync::Notify,
    }

    impl ExchangeProgress for Reached {
        fn entered(&self, phase: ExchangePhase) {
            self.phases.lock().expect("the record").push(phase);
            self.changed.notify_waiters();
        }
    }

    impl Reached {
        fn phases(&self) -> Vec<ExchangePhase> {
            self.phases.lock().expect("the record").clone()
        }

        /// Waits until an exchange has entered `phase`. [`WATCHDOG`] is a watchdog, not a claim.
        async fn phase(&self, phase: ExchangePhase) {
            let waiting = async {
                loop {
                    let change = self.changed.notified();
                    tokio::pin!(change);
                    change.as_mut().enable();
                    if self.phases().contains(&phase) {
                        return;
                    }
                    change.await;
                }
            };
            assert!(
                tokio::time::timeout(WATCHDOG, waiting).await.is_ok(),
                "no exchange reached {phase:?}"
            );
        }
    }

    /* ---------------------------------------------------------------------- */
    /* One configured origin, compared as a parsed scheme, host and port       */
    /* ---------------------------------------------------------------------- */

    #[tokio::test]
    async fn a_request_for_another_origin_is_refused_before_anything_is_sent() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{}".to_vec(),
        })
        .await;
        let transport = gateway.transport();

        let error = transport
            .post_json("https://reach.invalid/api/mailbox/read", b"{}", &[])
            .await
            .expect_err("another origin");
        assert_eq!(code(&error), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("another origin"));
        assert!(gateway.received().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn one_origin_spelled_two_ways_is_one_origin() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        })
        .await;
        let transport = gateway.transport();
        let port = Url::parse(gateway.origin.as_str())
            .expect("an address")
            .port()
            .expect("a port");

        let answer = transport
            .post_json(
                &format!("https://LOCALHOST:{port}/api/mailbox/read"),
                b"{}",
                &[],
            )
            .await
            .expect("the same origin, spelled differently");
        assert_eq!(answer.status, 200);
    }

    #[tokio::test]
    async fn the_port_a_scheme_implies_is_the_port_it_is_compared_at() {
        let configured = Url::parse("https://reach.kala.to").expect("an address");
        let requested =
            Url::parse("https://reach.kala.to:443/api/sync/exchange").expect("an address");
        assert!(same_origin(&configured, &requested));

        let elsewhere =
            Url::parse("https://reach.kala.to:8443/api/sync/exchange").expect("an address");
        assert!(!same_origin(&configured, &elsewhere));
    }

    /* ---------------------------------------------------------------------- */
    /* Transport security                                                      */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn plain_http_is_admitted_on_loopback_and_nowhere_else() {
        for loopback in [
            "http://localhost:8787/api/mailbox/read",
            "http://127.0.0.1:8787/api/mailbox/read",
            "http://[::1]:8787/api/mailbox/read",
        ] {
            let url = Url::parse(loopback).expect("an address");
            assert!(carries_transport_security(&url), "{loopback}");
        }
        for elsewhere in [
            "http://reach.kala.to/api/mailbox/read",
            "http://198.51.100.7/api/mailbox/read",
            "ftp://localhost/api/mailbox/read",
        ] {
            let url = Url::parse(elsewhere).expect("an address");
            assert!(!carries_transport_security(&url), "{elsewhere}");
        }

        // The origin type refuses the same thing where a gateway is configured, so the only plain
        // HTTP origin this transport can hold is a loopback one.
        assert!(GatewayOrigin::new("http://reach.kala.to").is_err());
        assert!(GatewayOrigin::new("http://127.0.0.1:8787").is_ok());
    }

    #[tokio::test]
    async fn an_address_carrying_credentials_is_refused() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{}".to_vec(),
        })
        .await;
        let transport = gateway.transport();
        let port = Url::parse(gateway.origin.as_str())
            .expect("an address")
            .port()
            .expect("a port");

        let error = transport
            .post_json(
                &format!("https://someone:secret@localhost:{port}/api/mailbox/read"),
                b"{}",
                &[],
            )
            .await
            .expect_err("credentials in an address");
        assert_eq!(code(&error), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("no credentials"));
        assert!(!error.to_string().contains("secret"));
        assert!(gateway.received().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn a_redirect_is_returned_rather_than_followed() {
        let gateway = Gateway::start(Behaviour::Redirect {
            location: "https://reach.invalid/api/mailbox/read".to_owned(),
        })
        .await;

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("the redirect itself");
        assert_eq!(answer.status, 302);
        assert_eq!(answer.body, b"elsewhere");
        assert_eq!(gateway.received().len(), 1, "one request, not two");
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let gateway = Gateway::presenting(
            Behaviour::Answer {
                status: 200,
                body: b"{}".to_vec(),
            },
            Presents::AnotherName,
        )
        .await;

        let error = gateway
            .transport()
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("a certificate for another name");
        assert_eq!(code(&error), ErrorCode::UpstreamUnavailable);
        assert!(gateway.received().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn a_certificate_from_an_authority_this_client_does_not_hold_is_refused() {
        let gateway = Gateway::presenting(
            Behaviour::Answer {
                status: 200,
                body: b"{}".to_vec(),
            },
            Presents::AnUntrustedAuthority,
        )
        .await;

        let error = gateway
            .transport()
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("an untrusted authority");
        assert_eq!(code(&error), ErrorCode::UpstreamUnavailable);
        assert!(gateway.received().is_empty(), "nothing was sent");
    }

    /* ---------------------------------------------------------------------- */
    /* Answers                                                                 */
    /* ---------------------------------------------------------------------- */

    #[tokio::test]
    async fn every_status_comes_back_with_its_body() {
        for status in [200u16, 400, 402, 409, 500] {
            let gateway = Gateway::start(Behaviour::Answer {
                status,
                body: format!("{{\"status\":{status}}}").into_bytes(),
            })
            .await;
            let answer = gateway
                .transport()
                .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
                .await
                .expect("an answer");
            assert_eq!(answer.status, status);
            assert_eq!(answer.body, format!("{{\"status\":{status}}}").into_bytes());
        }
    }

    #[tokio::test]
    async fn the_request_arrives_as_json_with_the_headers_it_was_given() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{}".to_vec(),
        })
        .await;

        gateway
            .transport()
            .post_json(
                &gateway.url("/api/relay/lease"),
                b"{\"body\":1}",
                &[("authorization", "Bearer opensesame")],
            )
            .await
            .expect("an answer");

        let received = gateway.received();
        assert_eq!(received.len(), 1);
        let request = &received[0];
        assert!(request.head.starts_with("POST /api/relay/lease HTTP/1.1"));
        assert!(
            request
                .head
                .to_ascii_lowercase()
                .contains("content-type: application/json")
        );
        assert!(
            request
                .head
                .to_ascii_lowercase()
                .contains("authorization: bearer opensesame")
        );
        assert!(
            !request
                .head
                .to_ascii_lowercase()
                .contains("accept-encoding"),
            "nothing is decompressed, so nothing is asked for"
        );
        assert!(
            !request.head.to_ascii_lowercase().contains("cookie"),
            "no cookie store"
        );
        assert_eq!(request.body, b"{\"body\":1}");
    }

    #[tokio::test]
    async fn an_account_request_arrives_as_a_form_or_a_bearer_read() {
        use crate::services::account::AccountHttp as _;

        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{}".to_vec(),
        })
        .await;
        let transport = gateway.transport();
        transport
            .post_form(
                &gateway.url("/auth/oauth2/token"),
                b"grant_type=refresh_token&client_id=kalareach-desktop",
            )
            .await
            .expect("an answer");
        transport
            .get(
                &gateway.url("/auth/oauth2/userinfo"),
                &[("authorization", "Bearer opensesame")],
            )
            .await
            .expect("an answer");

        let received = gateway.received();
        assert_eq!(received.len(), 2);
        let form = &received[0];
        assert!(form.head.starts_with("POST /auth/oauth2/token HTTP/1.1"));
        let head = form.head.to_ascii_lowercase();
        assert!(head.contains("content-type: application/x-www-form-urlencoded"));
        assert!(
            !head.contains("authorization"),
            "a form post carries no header it was not given"
        );
        assert_eq!(
            form.body,
            b"grant_type=refresh_token&client_id=kalareach-desktop"
        );
        let read = &received[1];
        assert!(read.head.starts_with("GET /auth/oauth2/userinfo HTTP/1.1"));
        let head = read.head.to_ascii_lowercase();
        assert!(head.contains("authorization: bearer opensesame"));
        assert!(!head.contains("content-type"), "a read carries no body");
        assert!(read.body.is_empty());

        // The same rules as every other exchange: another origin is refused before anything is
        // sent.
        let refused = transport
            .get("https://elsewhere.example/auth/oauth2/userinfo", &[])
            .await
            .expect_err("another origin");
        assert_eq!(code(&refused), ErrorCode::InvalidArgument);
        assert_eq!(gateway.received().len(), 2);
    }

    #[tokio::test]
    async fn an_answer_past_the_bound_is_refused_rather_than_truncated() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: vec![b'x'; OVERSIZE],
        })
        .await;

        let error = gateway
            .reading(ResponseLimits::new(1024))
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("an answer past the bound");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(error.to_string().contains("1024 bytes"));
    }

    #[tokio::test]
    async fn the_bound_holds_when_no_length_is_stated() {
        let gateway = Gateway::start(Behaviour::AnswerWithoutLength {
            status: 200,
            body: vec![b'x'; OVERSIZE],
        })
        .await;

        let error = gateway
            .reading(ResponseLimits::new(1024))
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("an answer past the bound");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);

        let received = gateway.received();
        assert_eq!(received.len(), 1);
        assert!(
            !received[0]
                .head
                .to_ascii_lowercase()
                .contains("content-length: 0\r\n"),
            "the request itself stated its own length"
        );
    }

    #[tokio::test]
    async fn an_answer_within_the_bound_is_read_whole_without_a_stated_length() {
        let gateway = Gateway::start(Behaviour::AnswerWithoutLength {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        })
        .await;

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("an answer");
        assert_eq!(answer.body, b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn each_operation_is_read_under_its_own_bound() {
        let limits = ResponseLimits::new(1024).for_path("/api/mailbox/read", 16 * 1024);
        assert_eq!(limits.of("/api/mailbox/read"), 16 * 1024);
        assert_eq!(limits.of("/api/sync/exchange"), 1024);

        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: vec![b'x'; OVERSIZE],
        })
        .await;
        let transport = gateway.reading(limits);

        let answer = transport
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("the operation that states a larger bound");
        assert_eq!(answer.body.len(), OVERSIZE);

        let error = transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect_err("the operation that does not");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
    }

    /* ---------------------------------------------------------------------- */
    /* How an answer is framed                                                 */
    /* ---------------------------------------------------------------------- */

    #[tokio::test]
    async fn a_chunked_answer_is_read_whole_and_bounded_by_what_arrives() {
        let gateway = Gateway::start(Behaviour::Chunked {
            status: 200,
            chunks: vec![
                b"{\"ok\":".to_vec(),
                b"true,".to_vec(),
                b"\"n\":1}".to_vec(),
            ],
            trailers: Vec::new(),
        })
        .await;

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("an answer in three pieces");
        assert_eq!(answer.body, b"{\"ok\":true,\"n\":1}");

        // No length is stated anywhere in a chunked answer, so the bound is the only thing that
        // stops it, and it stops it while the pieces are arriving.
        let large = Gateway::start(Behaviour::Chunked {
            status: 200,
            chunks: vec![vec![b'x'; 512]; 16],
            trailers: Vec::new(),
        })
        .await;
        let error = large
            .reading(ResponseLimits::new(1024))
            .post_json(&large.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect_err("an answer past the bound");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(error.to_string().contains("1024 bytes"));
    }

    #[tokio::test]
    async fn trailers_after_a_chunked_answer_do_not_enlarge_it() {
        let gateway = Gateway::start(Behaviour::Chunked {
            status: 200,
            chunks: vec![b"{\"ok\":true}".to_vec()],
            trailers: vec![(
                "x-kalareach-trailer".to_owned(),
                "x".repeat(4096).to_string(),
            )],
        })
        .await;

        // The bound admits the body and not the body plus the trailers, so an implementation that
        // counted trailer bytes as body bytes would fail here rather than pass quietly.
        let answer = gateway
            .reading(ResponseLimits::new(2048))
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("an answer with trailers after it");
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn a_body_framed_two_ways_is_read_as_the_chunks_and_bounded_as_the_chunks() {
        // A stated length beside chunked framing is the shape a request is smuggled in between a
        // proxy and an origin, where the two disagree about where one message ends. Here there is
        // nothing downstream to disagree with: the framing that wins is chunked, the stated length
        // decides nothing, and what the bound is applied to is what arrived.
        let gateway = Gateway::start(Behaviour::LengthAndChunked {
            stated: 2,
            chunks: vec![b"{\"ok\":".to_vec(), b"true}".to_vec()],
        })
        .await;
        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("the chunked body, not the stated length");
        assert_eq!(answer.body, b"{\"ok\":true}");
        assert_eq!(gateway.received().len(), 1);

        let large = Gateway::start(Behaviour::LengthAndChunked {
            stated: 2,
            chunks: vec![vec![b'x'; 512]; 8],
        })
        .await;
        let error = large
            .reading(ResponseLimits::new(1024))
            .post_json(&large.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect_err("the chunks, measured against the bound");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(error.to_string().contains("1024 bytes"));
    }

    #[tokio::test]
    async fn an_answer_framed_in_a_way_this_client_cannot_read_is_refused_rather_than_guessed_at() {
        // Chunked framing announced and not used. There is no reading of this that is the answer,
        // and returning the bytes as though there were would be a guess.
        let gateway = Gateway::start(Behaviour::FramingThisIsNot).await;
        let error = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect_err("framing this is not");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert_eq!(gateway.received().len(), 1);
    }

    #[tokio::test]
    async fn a_length_shorter_than_what_follows_it_bounds_the_answer_at_the_length() {
        let gateway = Gateway::start(Behaviour::ShorterThanItSends {
            stated: 11,
            body: {
                let mut body = b"{\"ok\":true}".to_vec();
                body.extend_from_slice(&vec![b'x'; OVERSIZE]);
                body
            },
        })
        .await;

        // The stated length defines the body, so the surplus is not part of it. What matters is
        // that the answer is the declared bytes and never the surplus.
        let answer = gateway
            .reading(ResponseLimits::new(1024))
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("the body the length declared");
        assert_eq!(answer.body, b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn an_answer_with_no_body_comes_back_with_no_body() {
        for status in [204u16, 304] {
            let gateway = Gateway::start(Behaviour::Answer {
                status,
                body: Vec::new(),
            })
            .await;
            let answer = gateway
                .transport()
                .post_json(&gateway.url("/api/mailbox/acknowledge"), b"{}", &[])
                .await
                .expect("an answer with no body");
            assert_eq!(answer.status, status);
            assert!(answer.body.is_empty(), "{status}");
        }
    }

    #[tokio::test]
    async fn an_informational_answer_is_passed_over_for_the_one_that_follows_it() {
        let gateway = Gateway::start(Behaviour::Informational {
            informational: 100,
            body: b"{\"ok\":true}".to_vec(),
        })
        .await;

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("the answer after the informational one");
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn a_cookie_the_service_sets_is_not_kept_and_not_sent_back() {
        let gateway = Gateway::start(Behaviour::WithHeaders {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
            headers: vec![(
                "set-cookie".to_owned(),
                "session=a-cookie-nobody-should-keep; Path=/".to_owned(),
            )],
        })
        .await;
        let transport = gateway.transport();

        transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("an answer that sets a cookie");
        transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("a second request to the same origin");

        let received = gateway.received();
        assert_eq!(received.len(), 2);
        for request in &received {
            assert!(
                !request.head.to_ascii_lowercase().contains("cookie"),
                "no cookie store, so nothing to send back: {}",
                request.head
            );
        }
    }

    #[tokio::test]
    async fn a_compressed_answer_comes_back_as_the_bytes_that_arrived() {
        // A fixed gzip stream of `{"ok":true,"data":{"note":"compressed"}}`: 60 bytes on the wire
        // for 40 bytes of content.
        const COMPRESSED: [u8; 60] = [
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0x56, 0xca, 0xcf,
            0x56, 0xb2, 0x2a, 0x29, 0x2a, 0x4d, 0xd5, 0x51, 0x4a, 0x49, 0x2c, 0x49, 0x54, 0xb2,
            0xaa, 0x56, 0xca, 0xcb, 0x2f, 0x49, 0x55, 0xb2, 0x52, 0x4a, 0xce, 0xcf, 0x2d, 0x28,
            0x4a, 0x2d, 0x2e, 0x4e, 0x4d, 0x51, 0xaa, 0xad, 0x05, 0x00, 0x8d, 0x48, 0xc0, 0x70,
            0x28, 0x00, 0x00, 0x00,
        ];

        let gateway = Gateway::start(Behaviour::WithHeaders {
            status: 200,
            body: COMPRESSED.to_vec(),
            headers: vec![("content-encoding".to_owned(), "gzip".to_owned())],
        })
        .await;

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("an answer declaring an encoding");
        // Nothing was asked for and nothing is undone: the bound is therefore a bound on the wire
        // rather than on something this client could expand afterwards.
        assert_eq!(answer.body, COMPRESSED);
        assert!(
            !gateway.received()[0]
                .head
                .to_ascii_lowercase()
                .contains("accept-encoding")
        );
    }

    /* ---------------------------------------------------------------------- */
    /* Deadlines, and the phase each one covers                                */
    /* ---------------------------------------------------------------------- */

    // Three rules hold this section together, because a transport test whose claim turns on
    // wall-clock timing against real socket I/O is a test that fails for reasons that have nothing
    // to do with the transport.
    //
    // 1. A failure names the phase it happened in, so a test proves which phase a deadline covered
    //    by asserting the failure rather than by measuring how long anything took.
    // 2. A stall test reaches the phase under test with the ordinary clock, on a signal from the
    //    gateway or from the transport's own progress seam, and only then takes the clock over.
    //    From that point the test's clock advances to the next deadline the exchange holds and
    //    nothing else can end the call. No test sleeps. No deadline in such a test is reachable
    //    while the clock is the machine's: every one of them is longer than the watchdog that
    //    bounds the signal, so a machine slow enough to matter fails the watchdog, which says what
    //    the test was waiting for, rather than firing a deadline in the wrong phase.
    // 3. The two deadlines a test is not about are thirty times the one it is about, so how far the
    //    test advanced its clock says which of the three ended the exchange. That figure is read
    //    from the moment the clock stopped, so it is the advance itself and carries no real time at
    //    all.
    //
    // The fixture is what makes the third rule hold for every other test as well: `transport` and
    // `reading` hold all three deadlines thirty days away, `deadlined` is the only constructor that
    // takes a deadline, and there is none that takes a deadline and a bound together. So a test
    // about a bound cannot be holding a production deadline a loaded machine could reach.

    #[tokio::test]
    async fn a_connection_that_never_finishes_being_established_fails_in_the_connect_phase() {
        let gateway = Gateway::start(Behaviour::AcceptAndStall).await;
        let deadlines = HttpDeadlines {
            connect: UNDER_TEST,
            read: OUT_OF_REACH,
            total: OUT_OF_REACH,
        };
        let transport = gateway.deadlined(deadlines);
        let url = gateway.url("/api/mailbox/read");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        // Under the ordinary clock until the gateway has the connection, so what the deadline ends
        // is an establishment that began and stalled rather than one that never started.
        tokio::select! {
            // Biased, and the wait is written first, so it is polled first in every round: the
            // watchdog is a minute against deadlines of a day, so a machine slow enough to reach
            // one fails the watchdog first and says what it was waiting for.
            biased;
            () = gateway.until("the connection it accepted", |gateway| gateway.connections() >= 1)
                => {}
            outcome = &mut call => panic!("this gateway never finishes a handshake: {outcome:?}"),
        }

        tokio::time::pause();
        let from = tokio::time::Instant::now();
        let error = call.await.expect_err("the connect deadline");
        let advanced = tokio::time::Instant::now() - from;

        // The connection was accepted at the transport and never spoke TLS, so nothing of the
        // request was written, and that is the one class that says so.
        assert_eq!(code(&error), ErrorCode::UpstreamUnavailable);
        assert_eq!(
            ExchangePhase::of(&error),
            Some(ExchangePhase::Connect),
            "{error}"
        );
        assert!(advanced <= deadlines.connect + CLOCK_GRAIN, "{advanced:?}");
        assert!(gateway.received().is_empty(), "nothing was sent");
        assert_eq!(gateway.connections(), 1, "one attempt, not several");
    }

    #[tokio::test]
    async fn a_service_that_never_answers_fails_in_the_request_phase() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let deadlines = HttpDeadlines {
            connect: OUT_OF_REACH,
            read: UNDER_TEST,
            total: OUT_OF_REACH,
        };
        let transport = gateway.deadlined(deadlines);
        let url = gateway.url("/api/mailbox/read");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        // The service has the request and will never answer it, which is the phase under test.
        tokio::select! {
            // Biased, and the wait is written first, so it is polled first in every round: the
            // watchdog is a minute against deadlines of a day, so a machine slow enough to reach
            // one fails the watchdog first and says what it was waiting for.
            biased;
            () = gateway.until("the request", |gateway| !gateway.received().is_empty()) => {}
            outcome = &mut call => panic!("this gateway never answers: {outcome:?}"),
        }

        tokio::time::pause();
        let from = tokio::time::Instant::now();
        let error = call.await.expect_err("the read deadline");
        let advanced = tokio::time::Instant::now() - from;

        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert_eq!(
            ExchangePhase::of(&error),
            Some(ExchangePhase::Request),
            "{error}"
        );
        // Inside the read deadline and nowhere near the other two, so the read one is what ended it.
        assert!(advanced <= deadlines.read + CLOCK_GRAIN, "{advanced:?}");
        assert_eq!(gateway.received().len(), 1, "one request, and it arrived");
    }

    #[tokio::test]
    async fn an_answer_that_never_finishes_arriving_fails_in_the_answer_phase() {
        let gateway = Gateway::start(Behaviour::HeadThenStall {
            stated: 4096,
            body: b"{\"part\":".to_vec(),
        })
        .await;
        let deadlines = HttpDeadlines {
            connect: OUT_OF_REACH,
            read: OUT_OF_REACH,
            total: UNDER_TEST,
        };
        let reached = Arc::new(Reached::default());
        let transport = gateway
            .deadlined(deadlines)
            .reporting_to(Arc::clone(&reached) as Arc<dyn ExchangeProgress>);
        let url = gateway.url("/api/mailbox/read");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        // The transport says when the answer's head is in its hands, which is what the gateway
        // cannot say: a service knows what it wrote and not what the client read.
        tokio::select! {
            // Biased, and the wait is written first, so it is polled first in every round: the
            // watchdog is a minute against deadlines of a day, so a machine slow enough to reach
            // one fails the watchdog first and says what it was waiting for.
            biased;
            () = reached.phase(ExchangePhase::Answer) => {}
            outcome = &mut call => panic!("this answer never finishes: {outcome:?}"),
        }

        tokio::time::pause();
        let from = tokio::time::Instant::now();
        let error = call.await.expect_err("the total deadline");
        let advanced = tokio::time::Instant::now() - from;

        // The total deadline covers reading the body, and the failure says so itself.
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert_eq!(
            ExchangePhase::of(&error),
            Some(ExchangePhase::Answer),
            "{error}"
        );
        assert!(advanced <= deadlines.total + CLOCK_GRAIN, "{advanced:?}");
        assert_eq!(
            reached.phases(),
            vec![ExchangePhase::Connect, ExchangePhase::Answer],
            "the two transitions this transport can see"
        );
        assert!(
            gateway.body_bytes_written() > 0 && gateway.body_bytes_written() < 4096,
            "the body started and did not finish: {} of 4096",
            gateway.body_bytes_written()
        );
    }

    #[tokio::test]
    async fn a_body_that_arrives_a_byte_at_a_time_is_counted_as_it_arrives() {
        // The bound rather than a deadline, and no clock in it at all. The answer's head arrives at
        // once and its body one byte at a time, and the bound is what ends the exchange: a client
        // that was still waiting for the head, or that read the body in one piece against the
        // length the sender claimed, could not produce this refusal. So the exchange really does
        // reach the body and count it as it comes.
        let gateway = Gateway::start(Behaviour::Trickle { bytes: 4096 }).await;
        // The bound alone: the fixture holds every deadline out of reach, so a deadline reaching
        // this exchange first would be the test measuring the machine.
        let transport = gateway.reading(ResponseLimits::new(64));

        let error = transport
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("a body past the bound");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(error.to_string().contains("64 bytes"), "{error}");
        assert!(
            gateway.body_bytes_written() > 64,
            "the gateway wrote past the bound: {}",
            gateway.body_bytes_written()
        );
    }

    #[tokio::test]
    async fn a_caller_with_a_shorter_deadline_keeps_it() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let deadlines = HttpDeadlines {
            connect: OUT_OF_REACH,
            read: OUT_OF_REACH,
            total: OUT_OF_REACH,
        };
        let transport = gateway.deadlined(deadlines);
        let url = gateway.url("/api/mailbox/read");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        tokio::select! {
            // Biased, and the wait is written first, so it is polled first in every round: the
            // watchdog is a minute against deadlines of a day, so a machine slow enough to reach
            // one fails the watchdog first and says what it was waiting for.
            biased;
            () = gateway.until("the request", |gateway| !gateway.received().is_empty()) => {}
            outcome = &mut call => panic!("this gateway never answers: {outcome:?}"),
        }

        // Every deadline this client holds is out of reach, so the only one left is the caller's,
        // and the clock advances to it because it is the only thing on the clock.
        tokio::time::pause();
        let from = tokio::time::Instant::now();
        let caller = Duration::from_millis(200);
        let outcome = tokio::time::timeout(caller, call).await;
        let advanced = tokio::time::Instant::now() - from;

        // Each of the three outcomes says which deadline ended the exchange, so the one case this
        // test is not about names itself instead of arriving as an assertion nobody can read.
        match outcome {
            Err(_elapsed) => {}
            Ok(Ok(answer)) => panic!("this gateway never answers: {}", answer.status),
            Ok(Err(error)) => panic!(
                "this client's own deadline ended it first, which needs a machine stopped for a \
                 month: {error}"
            ),
        }
        assert!(advanced <= caller + CLOCK_GRAIN, "{advanced:?}");
        assert_eq!(gateway.received().len(), 1, "one request, and it arrived");
    }

    #[tokio::test]
    async fn a_call_that_is_dropped_after_the_request_left_sends_nothing_afterwards() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let transport = gateway.transport();
        let url = gateway.url("/api/sync/exchange");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        // Drive the exchange until the service has the request, which is the moment after which a
        // caller walking away can no longer know what happened.
        tokio::select! {
            // Biased, and the wait is written first, so it is polled first in every round: the
            // watchdog is a minute against deadlines of a day, so a machine slow enough to reach
            // one fails the watchdog first and says what it was waiting for.
            biased;
            () = gateway.until("the request", |gateway| !gateway.received().is_empty()) => {}
            outcome = &mut call => panic!("this gateway never answers: {outcome:?}"),
        }
        drop(call);

        // Dropping the call took its deadlines with it, so nothing is left that could end this
        // connection: the close the gateway sees is the dropped call and can be nothing else.
        gateway
            .until("the connection close", |gateway| gateway.closed() >= 1)
            .await;
        assert_eq!(
            gateway.received().len(),
            1,
            "dropping the call ends it and sends nothing again"
        );
    }

    /* ---------------------------------------------------------------------- */
    /* One request per dispatch                                                */
    /* ---------------------------------------------------------------------- */

    #[tokio::test]
    async fn a_pooled_connection_taken_away_costs_a_connection_and_never_a_second_request() {
        let gateway = Gateway::start(Behaviour::CloseWhenIdle {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
            idle: Duration::from_millis(100),
        })
        .await;
        let transport = gateway.transport();

        transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("the first answer");
        assert_eq!(gateway.connections(), 1);

        // The service takes the idle connection away, and the test waits for that rather than for
        // an interval. Asking again works, because the library may open another connection for a
        // request of which it has written no byte.
        gateway
            .until("the idle connection close", |gateway| gateway.closed() >= 1)
            .await;
        let answer = transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("the second answer, on a connection of its own");
        assert_eq!(answer.body, b"{\"ok\":true}");

        // Two dispatches, two requests. Whatever the library did about the connection, the service
        // was asked exactly once for each.
        assert_eq!(gateway.received().len(), 2);
        assert!(gateway.connections() >= 2, "the first one was taken away");
    }

    #[tokio::test]
    async fn a_request_the_service_read_is_never_sent_again() {
        let gateway = Gateway::start(Behaviour::AnswerThenHangUp {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        })
        .await;
        let transport = gateway.transport();

        transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{\"first\":1}", &[])
            .await
            .expect("the first answer");

        // The second request is read whole and is answered with a closed connection. That is the
        // case the library would retry if the request had not started; this one had.
        let error = transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{\"second\":2}", &[])
            .await
            .expect_err("a connection that ended after the request");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);

        gateway
            .until("the connection close", |gateway| gateway.closed() >= 1)
            .await;
        // The second dispatch's body is in the service's hands, which is what puts it outside the
        // one case the library may open another connection for, and the service was asked once for
        // it. Which connection carried it does not enter into that: a request the service read is a
        // request that was written.
        let received = gateway.received();
        assert_eq!(received.len(), 2, "one request for each dispatch");
        assert_eq!(received[1].body, b"{\"second\":2}");
    }

    /* ---------------------------------------------------------------------- */
    /* Nothing between this client and the service that it did not ask for     */
    /* ---------------------------------------------------------------------- */

    /// The child half of [`an_ambient_proxy_variable_moves_no_request_of_this_client`].
    ///
    /// It is ignored in an ordinary run because it means nothing without the environment the other
    /// test builds around it, and that test runs it by name.
    #[tokio::test]
    #[ignore = "an_ambient_proxy_variable_moves_no_request_of_this_client runs this one"]
    async fn the_child_of_the_ambient_proxy_test() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
        })
        .await;
        let url = gateway.url("/api/sync/exchange");

        // The control: a client built the ordinary way does consult the environment, which is what
        // makes the assertion below about this client rather than about an empty environment. It
        // fails as soon as it gets there, because the address those variables name counts the
        // connection and drops it, and it asks once because a control that asked twice would make
        // the count say nothing. The deadline is a watchdog for a proxy that never answers at all.
        let ordinary = reqwest::Client::builder()
            .timeout(WATCHDOG)
            .retry(reqwest::retry::never())
            .build()
            .expect("an ordinary client");
        let refused = ordinary
            .post(&url)
            .body("{}")
            .send()
            .await
            .expect_err("the address those variables name refuses everything sent to it");
        // What the control proves is that it went there, so a control that ran out of time proved
        // nothing and says so here rather than leaving the count in the other process to say it.
        assert!(
            !refused.is_timeout(),
            "the control reached the proxy rather than waiting its deadline out: {refused}"
        );

        let answer = gateway
            .transport()
            .post_json(&url, b"{}", &[])
            .await
            .expect("this client reaches the gateway it was configured for");
        assert_eq!(answer.status, 200);
        assert_eq!(gateway.received().len(), 1);
    }

    #[tokio::test]
    async fn an_ambient_proxy_variable_moves_no_request_of_this_client() {
        // Something on loopback that counts a connection and drops it, standing in for the proxy
        // the environment names. Dropping rather than holding it is what keeps this test quick: a
        // client sent there is refused at once instead of waiting out a deadline.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let reached = Arc::new(Mutex::new(0usize));
        let counted = Arc::clone(&reached);
        let listening = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                *counted.lock().expect("the record") += 1;
                drop(stream);
            }
        });

        // The environment belongs to a process, so the case is exercised in one of its own.
        let proxy = format!("http://127.0.0.1:{port}");
        let binary = std::env::current_exe().expect("this test binary");
        let ran = tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary)
                .args([
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "services::http::tests::the_child_of_the_ambient_proxy_test",
                ])
                .env("HTTPS_PROXY", &proxy)
                .env("HTTP_PROXY", &proxy)
                .env("ALL_PROXY", &proxy)
                .env_remove("NO_PROXY")
                .env_remove("no_proxy")
                .current_dir(std::env::temp_dir())
                .output()
                .expect("the child")
        })
        .await
        .expect("the child");
        listening.abort();

        assert!(
            ran.status.success(),
            "{}{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(
            *reached.lock().expect("the record"),
            1,
            "the control went through the proxy those variables name and this client did not"
        );
    }

    #[tokio::test]
    async fn a_connection_that_is_never_established_is_reported_as_unreached() {
        // A port nothing is listening on, inside the configured origin.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        drop(listener);

        let origin = GatewayOrigin::new(format!("https://localhost:{port}")).expect("an origin");
        // Out of reach, like every other transport here that is not the subject of a deadline: what
        // ends this exchange is the connector reporting that nothing is there, and a deadline that
        // could reach it first would be this test measuring the machine.
        let transport = HttpService::with(origin, out_of_reach(), ResponseLimits::default())
            .expect("a transport");
        // The watchdog is a watchdog rather than a claim: the port was released before this call,
        // so something else could in principle be listening on it by now, and a call that then hung
        // would hang for thirty days. A minute turns that into a failure that says what happened.
        let error = tokio::time::timeout(
            WATCHDOG,
            transport.post_json(
                &format!("https://localhost:{port}/api/mailbox/read"),
                b"{}",
                &[],
            ),
        )
        .await
        .expect("something answered on the port this test took and held the call")
        .expect_err("nothing is listening");
        assert_eq!(code(&error), ErrorCode::UpstreamUnavailable);
        assert!(error.to_string().contains("could not be reached"));
    }

    #[tokio::test]
    async fn a_connection_that_ends_after_the_request_is_reported_as_uncertain() {
        let gateway = Gateway::start(Behaviour::HangUp).await;

        let error = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{\"exchange\":1}", &[])
            .await
            .expect_err("a connection that ended");
        assert_eq!(
            code(&error),
            ErrorCode::OutcomeUnknown,
            "the request was written, so its effect is unknown"
        );
        assert_eq!(gateway.received().len(), 1, "the request did arrive");
    }

    /* ---------------------------------------------------------------------- */
    /* Nothing that travelled is written down                                  */
    /* ---------------------------------------------------------------------- */

    /// One record's fields, rendered.
    #[derive(Default)]
    struct Fields(String);

    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    /// Everything written through `tracing` while this was in place, and this crate's own part of
    /// it separately.
    ///
    /// The whole record is what a credential is looked for in, because a credential that reached
    /// any library's diagnostics has reached diagnostics. The crate's own part is what the claim
    /// that this transport writes nothing is checked against.
    #[derive(Clone, Default)]
    struct Written {
        everything: Arc<Mutex<String>>,
        this_crate: Arc<Mutex<String>>,
    }

    impl Written {
        fn keep(&self, target: &str, fields: &Fields) {
            use std::fmt::Write as _;
            let _ = write!(
                self.everything.lock().expect("the record"),
                " {target}:{}",
                fields.0
            );
            if target.starts_with("kr_client") {
                let _ = write!(
                    self.this_crate.lock().expect("the record"),
                    " {target}:{}",
                    fields.0
                );
            }
        }

        fn everything(&self) -> String {
            self.everything.lock().expect("the record").clone()
        }

        fn by_this_crate(&self) -> String {
            self.this_crate.lock().expect("the record").clone()
        }
    }

    impl tracing::Subscriber for Written {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let mut fields = Fields::default();
            span.record(&mut fields);
            self.keep(span.metadata().target(), &fields);
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            let mut fields = Fields::default();
            values.record(&mut fields);
            self.keep("recorded", &fields);
        }

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.keep(event.metadata().target(), &fields);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn an_answer_is_rendered_as_its_status_and_its_length() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: b"{\"ok\":true,\"data\":{\"note\":\"an-answer-nobody-should-see\"}}".to_vec(),
        })
        .await;
        let written = Written::default();
        let guard = tracing::subscriber::set_default(written.clone());

        let answer = gateway
            .transport()
            .post_json(&gateway.url("/api/sync/exchange"), b"{}", &[])
            .await
            .expect("an answer");
        drop(guard);

        // The bytes are there for the caller that asked for them, and in no rendering of the
        // answer that carries them.
        assert!(answer.body.ends_with(b"}"));
        for rendering in [
            format!("{answer:?}"),
            format!("{answer:#?}"),
            written.everything(),
        ] {
            assert!(
                !rendering.contains("an-answer-nobody-should-see"),
                "{rendering}"
            );
        }
        assert!(format!("{answer:?}").contains(&format!("body_bytes: {}", answer.body.len())));
    }

    #[tokio::test]
    async fn neither_a_credential_nor_a_body_reaches_a_message_a_rendering_or_a_record() {
        let gateway = Gateway::start(Behaviour::HangUp).await;
        let transport = gateway.transport();
        let written = Written::default();
        let guard = tracing::subscriber::set_default(written.clone());

        let error = transport
            .post_json(
                &gateway.url("/api/sync/exchange"),
                b"{\"signature\":\"a-signature-nobody-should-see\"}",
                &[("authorization", "Bearer a-token-nobody-should-see")],
            )
            .await
            .expect_err("a connection that ended");
        drop(guard);

        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
            format!("{transport:?}"),
            written.everything(),
        ] {
            assert!(
                !rendering.contains("a-signature-nobody-should-see"),
                "{rendering}"
            );
            assert!(
                !rendering.contains("a-token-nobody-should-see"),
                "{rendering}"
            );
        }
        assert!(
            written.by_this_crate().is_empty(),
            "this transport writes no diagnostics of its own: {}",
            written.by_this_crate()
        );
    }

    /* ---------------------------------------------------------------------- */
    /* Where a failure happened                                                */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn every_failure_of_an_exchange_names_the_phase_it_happened_in() {
        const NAMED: &str = "https://reach.kala.to/api/mailbox/read";
        const CAUSES: [&str; 3] = [
            "this client's deadline ran out",
            "the exchange ended",
            "what came back could not be read",
        ];

        // Every message this transport writes for a failure of an exchange, read back as the phase
        // it was written for. The phrases are what carries the phase, so a pair that collided would
        // make one phase unreadable.
        for phase in ExchangePhase::ALL {
            for cause in CAUSES {
                let why = format!("{cause} {}", phase.as_str());
                let error = match phase {
                    ExchangePhase::Connect => unreachable(NAMED, &why),
                    ExchangePhase::Request | ExchangePhase::Answer => uncertain(NAMED, &why),
                };
                assert_eq!(ExchangePhase::of(&error), Some(phase), "{error}");
            }
            for other in ExchangePhase::ALL {
                assert!(
                    phase == other || !phase.as_str().contains(other.as_str()),
                    "{phase:?} and {other:?} cannot be told apart"
                );
            }
        }

        // The two failures that are not failures of a phase.
        assert_eq!(
            ExchangePhase::of(&refused("a request address carries no credentials")),
            None
        );
        assert_eq!(ExchangePhase::of(&too_large(NAMED, 64)), None);
    }

    /* ---------------------------------------------------------------------- */
    /* Construction                                                            */
    /* ---------------------------------------------------------------------- */

    #[test]
    fn a_transport_states_the_gateway_it_addresses_and_the_rules_it_keeps() {
        let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
        let transport = HttpService::new(origin).expect("a transport");
        assert_eq!(transport.origin().as_str(), "https://reach.kala.to");
        assert_eq!(transport.deadlines(), HttpDeadlines::default());
        assert_eq!(
            transport.limits().of("/api/sync/exchange"),
            DEFAULT_RESPONSE_LIMIT_BYTES
        );
        assert!(format!("{transport:?}").contains("reach.kala.to"));
    }

    #[test]
    fn a_deadline_of_nothing_is_refused() {
        let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
        let deadlines = HttpDeadlines {
            connect: Duration::ZERO,
            read: DEFAULT_READ_DEADLINE,
            total: DEFAULT_TOTAL_DEADLINE,
        };
        let error = HttpService::with(origin, deadlines, ResponseLimits::default())
            .expect_err("a deadline of nothing");
        assert_eq!(code(&error), ErrorCode::InvalidArgument);
    }
}
