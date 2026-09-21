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
//! | No cookies, no ambient proxy, no decompression, no automatic retry | Each of those is something between this client and the service that this client did not ask for |
//!
//! # What a failure means
//!
//! The distinction this transport keeps is whether the request may have been carried out. A
//! connection that was never established is [`ErrorCode::UpstreamUnavailable`]: nothing was sent.
//! Everything after that, including a deadline, a connection that ended and an answer too large to
//! read, is [`ErrorCode::OutcomeUnknown`], because the service may have acted on the request and
//! this client cannot see whether it did. Section 23 never retries an unknown outcome
//! automatically, and this transport retries nothing at all: whether to ask again is
//! [`crate::retry`]'s decision, made with the request's class in view.
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
    #[derive(Clone, Debug)]
    enum Behaviour {
        /// Answer with this status and body, and state the body's length.
        Answer { status: u16, body: Vec<u8> },
        /// Answer with this status and body and state no length, closing to mark the end.
        AnswerWithoutLength { status: u16, body: Vec<u8> },
        /// Answer with a redirect to another address.
        Redirect { location: String },
        /// Send the head, then one byte at a time with a pause between them.
        Trickle { bytes: usize, pause: Duration },
        /// Read the request and then answer nothing at all.
        Silent,
        /// Read the request and then end the connection without answering.
        HangUp,
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

    /// A TLS gateway on loopback, with a certificate authority of its own.
    struct Gateway {
        origin: GatewayOrigin,
        root: Vec<u8>,
        received: Arc<Mutex<Vec<Received>>>,
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
            let received = Arc::new(Mutex::new(Vec::new()));
            let task = tokio::spawn(serve(listener, acceptor, behaviour, Arc::clone(&received)));

            Self {
                origin: GatewayOrigin::new(format!("https://localhost:{port}"))
                    .expect("a gateway origin"),
                root: authority_der.to_vec(),
                received,
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
            self.received.lock().expect("the record").clone()
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
        received: Arc<Mutex<Vec<Received>>>,
    ) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let behaviour = behaviour.clone();
            let received = Arc::clone(&received);
            tokio::spawn(async move {
                let _ = answer(stream, acceptor, behaviour, received).await;
            });
        }
    }

    /// Reads one request and acts on the behaviour this gateway was started with.
    async fn answer(
        stream: TcpStream,
        acceptor: TlsAcceptor,
        behaviour: Behaviour,
        received: Arc<Mutex<Vec<Received>>>,
    ) -> io::Result<()> {
        let mut stream = acceptor.accept(stream).await?;
        let request = read_request(&mut stream).await?;
        received.lock().expect("the record").push(request);

        match behaviour {
            Behaviour::Answer { status, body } => {
                let head = format!(
                    "HTTP/1.1 {status} \r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
            }
            Behaviour::AnswerWithoutLength { status, body } => {
                let head = format!(
                    "HTTP/1.1 {status} \r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
                stream.shutdown().await?;
            }
            Behaviour::Redirect { location } => {
                let head = format!(
                    "HTTP/1.1 302 \r\nlocation: {location}\r\ncontent-length: 9\r\n\r\nelsewhere"
                );
                stream.write_all(head.as_bytes()).await?;
                stream.flush().await?;
            }
            Behaviour::Trickle { bytes, pause } => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 \r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
                    )
                    .await?;
                stream.flush().await?;
                for _ in 0..bytes {
                    stream.write_all(b".").await?;
                    stream.flush().await?;
                    tokio::time::sleep(pause).await;
                }
            }
            Behaviour::Silent => {
                std::future::pending::<()>().await;
            }
            Behaviour::HangUp => {
                stream.shutdown().await?;
            }
        }
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
            connect: Duration::from_secs(2),
            read: Duration::from_secs(2),
            total: Duration::from_millis(400),
        };

        let started = std::time::Instant::now();
        let error = gateway
            .transport_with(deadlines, ResponseLimits::new(1024 * 1024))
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("the total deadline");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_service_that_never_answers_ends_at_the_read_deadline() {
        let gateway = Gateway::start(Behaviour::Silent).await;
        let deadlines = HttpDeadlines {
            connect: Duration::from_secs(2),
            read: Duration::from_millis(300),
            total: Duration::from_secs(10),
        };

        let started = std::time::Instant::now();
        let error = gateway
            .transport_with(deadlines, ResponseLimits::default())
            .post_json(&gateway.url("/api/mailbox/read"), b"{}", &[])
            .await
            .expect_err("the read deadline");
        assert_eq!(code(&error), ErrorCode::OutcomeUnknown);
        assert!(started.elapsed() < Duration::from_secs(5));
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

        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_millis(200),
            transport.post_json(&gateway.url("/api/mailbox/read"), b"{}", &[]),
        )
        .await;
        assert!(outcome.is_err(), "the caller's deadline, not this client's");
        assert!(started.elapsed() < Duration::from_secs(2));
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
