//! The managed-service transport.
//!
//! [`relay::ServiceHttp`] is the exchange every managed-service client is written against, and this
//! is the implementation a shipped client uses. It is asynchronous, so a call that is dropped stops
//! rather than continuing on a thread nobody is waiting for, and it is deliberately small: one
//! origin, one signed JSON body, one bounded answer.
//!
//! # What it will and will not do
//!
//! | Rule | Why |
//! | --- | --- |
//! | One configured origin per instance, compared as a parsed scheme, host and port | A credential is signed for one deployment, so a request addressed anywhere else is a mistake this client catches rather than a signature it hands to a stranger |
//! | HTTPS, except on loopback | A managed-service request carries a credential; plain HTTP is admitted only for the loopback address a development deployment serves on |
//! | No credentials in the address | A password in a URL is sent before anything is verified and is not part of this protocol's authentication |
//! | No redirects | A redirect moves a signed request to an address its credential does not name. The answer is returned as it came, so a caller sees the redirect rather than following it |
//! | Certificate and hostname verification | Both stay on. There is no option here that turns either off |
//! | Finite connect, read and total deadlines | Every call ends. The total deadline covers reading the body, so an answer that never finishes arriving is a failure rather than a wait |
//! | A bounded answer, measured while it is read | A stated content length is the sender's claim. The bound is applied to the bytes as they arrive, and an answer past it is refused rather than truncated, because half an envelope is not an answer |
//! | No cookies, no ambient proxy, no decompression | Each of those is something between this client and the service that this client did not ask for |
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
//! # Diagnostics
//!
//! This module emits none. A request body carries a credential, and a header may carry a token, so
//! nothing here writes either to a log, into an error message or into a rendered structure. A
//! failure names the origin, the path and what went wrong.

use std::fmt;
use std::time::Duration;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::service::GatewayOrigin;
use url::{Host, Url};

use super::ServiceFuture;
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

/// The lowest TLS version this transport negotiates.
const MINIMUM_TLS_VERSION: reqwest::tls::Version = reqwest::tls::Version::TLS_1_2;

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
    /// Builds a transport for one gateway, with this client's own deadlines and bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not one this transport will address, or when the
    /// platform's TLS configuration cannot be read.
    pub fn new(origin: GatewayOrigin) -> Result<Self> {
        Self::with(origin, HttpDeadlines::default(), ResponseLimits::default())
    }

    /// Builds a transport with stated deadlines and bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not one this transport will address, when a deadline is
    /// zero, or when the platform's TLS configuration cannot be read.
    pub fn with(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
    ) -> Result<Self> {
        Self::build(origin, deadlines, limits, None)
    }

    fn build(
        origin: GatewayOrigin,
        deadlines: HttpDeadlines,
        limits: ResponseLimits,
        extra_root: Option<&[u8]>,
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

        install_crypto_provider();
        let mut builder = reqwest::Client::builder()
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
            .no_proxy()
            .http1_only()
            .tls_version_min(MINIMUM_TLS_VERSION);
        if let Some(root) = extra_root {
            let certificate = reqwest::Certificate::from_der(root)
                .map_err(|_| refused("this client cannot read the certificate it was given"))?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder
            .build()
            .map_err(|_| refused("this client could not configure its transport"))?;

        Ok(Self {
            origin,
            address,
            client,
            deadlines,
            limits,
        })
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
    async fn exchange(
        &self,
        target: Url,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<ServiceHttpAnswer> {
        let limit = self.limits.of(target.path());
        let named = format!("{}{}", self.origin.as_str(), target.path());

        let mut request = self
            .client
            .post(target)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        for (name, value) in headers {
            // A header value can be a token, so neither the name's value nor the value itself
            // reaches this error.
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| refused("a request header name is not one this client can send"))?;
            let value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| refused("a request header value is not one this client can send"))?;
            request = request.header(name, value);
        }

        let mut response = request
            .send()
            .await
            .map_err(|error| failure(&named, &error))?;
        let status = response.status().as_u16();

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
                .map_err(|error| failure(&named, &error))?;
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
            let target = self.target(url)?;
            let named = format!("{}{}", self.origin.as_str(), target.path());
            match tokio::time::timeout(self.deadlines.total, self.exchange(target, body, headers))
                .await
            {
                Ok(answer) => answer,
                Err(_) => Err(uncertain(
                    &named,
                    "it did not finish inside this client's deadline",
                )),
            }
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

/// What one exchange's failure means, in the only terms that matter to a caller.
///
/// A failure inside the connector happened before any request byte was written, so the request was
/// not carried out. Everything else may have been: a deadline, a connection that ended and an
/// answer that could not be read all leave a request that the service may have acted on.
fn failure(named: &str, error: &reqwest::Error) -> ClientError {
    let why = if error.is_timeout() {
        "it did not answer inside this client's deadline"
    } else if error.is_connect() {
        "the connection could not be established"
    } else if error.is_decode() {
        "its answer could not be read"
    } else {
        "the exchange ended before an answer arrived"
    };

    if error.is_connect() {
        unreachable(named, why)
    } else {
        uncertain(named, why)
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
        Self::build(origin, deadlines, limits, Some(root))
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

    /// What the loopback gateway does with a request it has read.
    ///
    /// Every behaviour that states a length keeps the connection open afterwards, so one gateway
    /// answers several requests on one connection and the pool has something to reuse.
    #[derive(Clone, Debug)]
    enum Behaviour {
        /// Answer with this status and body, and state the body's length.
        Answer { status: u16, body: Vec<u8> },
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
        /// Answer the first request, then send the next answer's head and trickle its body.
        ///
        /// The first answer is what establishes the connection before anything is timed, so a
        /// deadline under test measures the exchange rather than the setup in front of it.
        Trickle { bytes: usize, pause: Duration },
        /// Answer the first request, then read the next and answer nothing at all.
        Silent,
        /// Read the request and then end the connection without answering.
        HangUp,
        /// Answer the first request on a connection, then read the next and end the connection.
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
    /// A test that turns on an interval is a test that fails under load, so the phase a test means
    /// to be in is established from these rather than from a sleep: the request arrived, the body
    /// started, the connection went away.
    #[derive(Default)]
    struct Saw {
        received: Mutex<Vec<Received>>,
        connections: Mutex<usize>,
        closed: Mutex<usize>,
        body_bytes_written: Mutex<usize>,
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

        fn transport(&self) -> HttpService {
            self.transport_with(HttpDeadlines::default(), ResponseLimits::default())
        }

        fn transport_with(&self, deadlines: HttpDeadlines, limits: ResponseLimits) -> HttpService {
            HttpService::trusting(self.origin.clone(), deadlines, limits, &self.root)
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
        /// It is the phase signal the timed tests turn on, and its own bound is far longer than
        /// anything under test, so a machine under load waits rather than failing.
        async fn until(&self, what: &str, ready: impl Fn(&Self) -> bool) {
            self.until_within(Duration::from_secs(60), what, ready)
                .await;
        }

        /// The same wait, bounded by the clock, for a test whose claim is that something happened
        /// sooner than an ordinary deadline would have produced it.
        async fn until_within(&self, within: Duration, what: &str, ready: impl Fn(&Self) -> bool) {
            let started = std::time::Instant::now();
            while started.elapsed() < within {
                if ready(self) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(ready(self), "the gateway never saw {what}");
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
            let acceptor = acceptor.clone();
            let behaviour = behaviour.clone();
            let saw = Arc::clone(&saw);
            tokio::spawn(async move {
                let _ = answer(stream, acceptor, behaviour, Arc::clone(&saw)).await;
                *saw.closed.lock().expect("the record") += 1;
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
                        // a service, a load balancer or a keep-alive deadline does.
                        Err(_) => return stream.shutdown().await,
                    }
                }
                Some(_) | None => read_request(&mut stream).await?,
            };
            saw.received.lock().expect("the record").push(request);
            served += 1;

            if !act(&mut stream, &behaviour, served, &saw).await? {
                return Ok(());
            }
        }
    }

    /// Acts on one request. Returns whether this connection carries another.
    async fn act<S>(
        stream: &mut S,
        behaviour: &Behaviour,
        served: usize,
        saw: &Saw,
    ) -> io::Result<bool>
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
                if served == 1 {
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
            Behaviour::Trickle { bytes, pause } => {
                if served == 1 {
                    write_answer(stream, 200, b"{\"warm\":true}", &[]).await?;
                    return Ok(true);
                }
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
                    tokio::time::sleep(*pause).await;
                }
                return Ok(false);
            }
            Behaviour::Silent => {
                if served == 1 {
                    write_answer(stream, 200, b"{\"warm\":true}", &[]).await?;
                    return Ok(true);
                }
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
    async fn an_answer_past_the_bound_is_refused_rather_than_truncated() {
        let gateway = Gateway::start(Behaviour::Answer {
            status: 200,
            body: vec![b'x'; OVERSIZE],
        })
        .await;

        let error = gateway
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(1024))
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
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(1024))
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
        let transport = gateway.transport_with(HttpDeadlines::default(), limits);

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
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(1024))
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
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(2048))
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
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(1024))
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
            .transport_with(HttpDeadlines::default(), ResponseLimits::new(1024))
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
    /* Deadlines                                                               */
    /* ---------------------------------------------------------------------- */

    #[tokio::test]
    async fn an_answer_that_never_finishes_arriving_ends_at_the_total_deadline() {
        let gateway = Gateway::start(Behaviour::Trickle {
            bytes: 4096,
            pause: Duration::from_millis(50),
        })
        .await;
        let deadlines = HttpDeadlines {
            connect: Duration::from_secs(60),
            read: Duration::from_secs(60),
            total: Duration::from_secs(2),
        };
        let transport = gateway.transport_with(deadlines, ResponseLimits::new(1024 * 1024));

        // One answered request first. It leaves an established connection in the pool, so the
        // exchange that is timed below has no connection to make and the deadline measures the
        // answer rather than the setup in front of it.
        transport
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("a warm connection");

        let started = std::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(60),
            transport.post_json(&gateway.url("/api/mailbox/read"), b"{}", &[]),
        )
        .await
        .expect("the client's own deadline, not the watchdog")
        .expect_err("the total deadline");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);

        // It waited the deadline out rather than failing early, which only the answer's own
        // slowness can cause here.
        assert!(
            started.elapsed() >= deadlines.total,
            "{:?}",
            started.elapsed()
        );

        // And the phase it was in, said by the gateway rather than by a clock: both requests
        // arrived on one connection, the second answer's head went back, and its body was still
        // being written a byte at a time.
        assert_eq!(gateway.received().len(), 2);
        assert_eq!(gateway.connections(), 1, "one connection, reused");
        assert!(
            gateway.body_bytes_written() > 0,
            "the body had started arriving"
        );
        assert!(
            gateway.body_bytes_written() < 4096,
            "and had not finished: {} of 4096",
            gateway.body_bytes_written()
        );
    }

    #[tokio::test]
    async fn a_service_that_never_answers_ends_at_the_read_deadline() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let deadlines = HttpDeadlines {
            connect: Duration::from_secs(60),
            read: Duration::from_secs(2),
            total: Duration::from_secs(300),
        };
        let transport = gateway.transport_with(deadlines, ResponseLimits::default());

        // One answered request first, so the connection is already made when the deadline under
        // test starts and nothing of the setup is inside it.
        transport
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("a warm connection");

        // The total deadline is five minutes and the watchdog is one, so the only deadline that
        // can end this exchange is the read one.
        let started = std::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(60),
            transport.post_json(&gateway.url("/api/mailbox/read"), b"{}", &[]),
        )
        .await
        .expect("the read deadline, not the watchdog")
        .expect_err("the read deadline");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(
            started.elapsed() >= deadlines.read,
            "{:?}",
            started.elapsed()
        );
        // Which establishes the phase: the second request was written on the connection the first
        // one made, so what this deadline was reached waiting for is the answer.
        assert_eq!(gateway.received().len(), 2);
        assert_eq!(gateway.connections(), 1, "one connection, reused");
    }

    #[tokio::test]
    async fn a_connection_that_never_finishes_being_established_ends_at_the_connect_deadline() {
        let gateway = Gateway::start(Behaviour::AcceptAndStall).await;
        let deadlines = HttpDeadlines {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(300),
            total: Duration::from_secs(300),
        };
        let transport = gateway.transport_with(deadlines, ResponseLimits::default());

        let error = tokio::time::timeout(
            Duration::from_secs(60),
            transport.post_json(&gateway.url("/api/mailbox/read"), b"{}", &[]),
        )
        .await
        .expect("the connect deadline, not the watchdog")
        .expect_err("the connect deadline");
        // The connection accepted at the transport and never spoke TLS, so nothing of the request
        // was ever written and this is the one class that says so.
        assert_eq!(code(&error), ErrorCode::UpstreamUnavailable);
        gateway
            .until("the connection it accepted", |gateway| {
                gateway.connections() >= 1
            })
            .await;
        assert!(gateway.received().is_empty(), "nothing was sent");
        assert_eq!(gateway.connections(), 1, "one attempt, not several");
    }

    #[tokio::test]
    async fn a_call_that_is_dropped_after_the_request_left_sends_nothing_afterwards() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        // Deadlines of five minutes against a closure this test waits thirty seconds for, so a
        // connection that goes away inside that window went away because the call was dropped and
        // not because an exchange of its own ran out.
        let transport = gateway.transport_with(
            HttpDeadlines {
                connect: Duration::from_secs(300),
                read: Duration::from_secs(300),
                total: Duration::from_secs(300),
            },
            ResponseLimits::default(),
        );
        let url = gateway.url("/api/sync/exchange");
        transport
            .post_json(&url, b"{}", &[])
            .await
            .expect("a warm connection");
        let mut call = Box::pin(transport.post_json(&url, b"{}", &[]));

        // Drive the exchange until the service has the request, which is the moment after which a
        // caller walking away can no longer know what happened.
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    _ = &mut call => panic!("this gateway never answers"),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        if gateway.received().len() >= 2 {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("the second request reached the gateway");

        drop(call);

        // The gateway sees the connection go away, well inside the five minutes any deadline of
        // this exchange would have taken, which is what makes the closure the dropped call and not
        // a timeout.
        gateway
            .until_within(Duration::from_secs(30), "the connection close", |gateway| {
                gateway.closed() >= 1
            })
            .await;
        assert_eq!(
            gateway.received().len(),
            2,
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

        // The second request travels on the pooled connection, is read whole and is answered with
        // a closed connection. That is the case the library would retry if the request had not
        // started; this one had.
        let error = transport
            .post_json(&gateway.url("/api/sync/exchange"), b"{\"second\":2}", &[])
            .await
            .expect_err("a connection that ended after the request");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);

        gateway
            .until("the connection close", |gateway| gateway.closed() >= 1)
            .await;
        let received = gateway.received();
        assert_eq!(received.len(), 2, "one request for each dispatch");
        assert_eq!(received[1].body, b"{\"second\":2}");
        // Both dispatches travelled on the one connection, which is what makes this the case the
        // library would retry if the request had not started.
        assert_eq!(gateway.connections(), 1, "one connection, reused");
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
        // never completes, because the address those variables name accepts and says nothing.
        let ordinary = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("an ordinary client");
        let _ = ordinary.post(&url).body("{}").send().await;

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
        // Something on loopback that accepts a connection and does nothing with it, standing in
        // for the proxy the environment names.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let reached = Arc::new(Mutex::new(0usize));
        let counted = Arc::clone(&reached);
        let listening = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                *counted.lock().expect("the record") += 1;
                std::mem::forget(stream);
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
    async fn a_caller_with_a_shorter_deadline_keeps_it() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let deadlines = HttpDeadlines {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(5),
            total: Duration::from_secs(20),
        };
        let transport = gateway.transport_with(deadlines, ResponseLimits::default());

        // One answered request first, so the caller's deadline below is measured against an
        // exchange that has nothing to set up.
        transport
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect("a warm connection");

        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_millis(200),
            transport.post_json(&gateway.url("/api/mailbox/read"), b"{}", &[]),
        )
        .await;
        assert!(outcome.is_err(), "the caller's deadline, not this client's");
        // Far under this client's own twenty seconds, and far over the caller's two hundred
        // milliseconds, so a machine under load does not decide it.
        assert!(started.elapsed() < Duration::from_secs(10));
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
        let transport = HttpService::new(origin).expect("a transport");
        let error = transport
            .post_json(
                &format!("https://localhost:{port}/api/mailbox/read"),
                b"{}",
                &[],
            )
            .await
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
