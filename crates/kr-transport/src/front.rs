//! A `CONNECT` front on the loopback, so that the network library never holds a proxy's login.
//!
//! A proxy that asks for a login gets it from this host only through the host's own writer. The
//! network library (iroh) dials its relays through a proxy it is given, and writes a `CONNECT` to
//! it that carries whatever login that proxy's address holds, from tasks of its own that outlive
//! the endpoint's close. So the library is given this front instead: a listener on the IPv4
//! loopback that the endpoint owns. The front admits a `CONNECT` to a relay of the endpoint's own
//! map from a client that holds its per-endpoint secret, and nothing else. Each tunnel it admits
//! is opened by a [`TunnelOpener`], which is the host's one `CONNECT` writer, and which reads the
//! verdict on the login again right before it writes. After the verdict the front opens no new
//! tunnel, so no path of the library writes the login again; a tunnel that is open stays open
//! until the endpoint's close ends it, because the close frames to peers travel through it.
//!
//! The secret is not the login. It is 32 random bytes, new at each bind, held in memory only, and
//! it opens nothing but a tunnel to a relay of the map.

use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures::future::BoxFuture;
use iroh::RelayMap;
use kr_crypto::secret::SecretVec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use url::Url;

use crate::proxy::{Target, Verdict};

/// The most tunnels the front holds at once, counted from the moment one is admitted.
pub const MAX_TUNNELS: usize = 64;
/// The most connections the front reads a request head from at once. A connection that has sent no
/// complete head yet counts here and not against the tunnels, so a local process that holds no
/// secret cannot take a tunnel's place; the oldest waiting head is dropped for a new one.
pub const MAX_PENDING_HEADS: usize = 16;
/// The longest request head the front reads.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// How long a request head may take to arrive.
pub const HEAD_DEADLINE: Duration = Duration::from_secs(5);
/// How long the opener may take to open a tunnel.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// The user name the library sends to the front. It is not a secret.
const FRONT_USER: &[u8] = b"kr";

/// The bounds of a front, which a case shortens.
#[derive(Clone, Copy, Debug)]
pub struct FrontBounds {
    /// The most tunnels at once.
    pub max_tunnels: usize,
    /// The most request heads waiting at once.
    pub max_pending_heads: usize,
    /// The longest request head, in bytes.
    pub max_head_bytes: usize,
    /// How long a head may take.
    pub head_deadline: Duration,
    /// How long the opener may take.
    pub connect_deadline: Duration,
}

impl Default for FrontBounds {
    fn default() -> Self {
        Self {
            max_tunnels: MAX_TUNNELS,
            max_pending_heads: MAX_PENDING_HEADS,
            max_head_bytes: MAX_HEAD_BYTES,
            head_deadline: HEAD_DEADLINE,
            connect_deadline: CONNECT_DEADLINE,
        }
    }
}

/// A connection the front joins to a client's: anything that reads and writes bytes.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A tunnel to a relay through the proxy, opened by a [`TunnelOpener`].
pub struct Tunnel(Box<dyn Duplex>);

impl Tunnel {
    /// A tunnel over `io`.
    #[must_use]
    pub fn new<T: Duplex + 'static>(io: T) -> Self {
        Self(Box::new(io))
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Tunnel")
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// Why the opener did not open a tunnel. It carries no word the proxy wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelRefusal {
    /// The login's verdict is set, so nothing was written to the proxy.
    Stopped,
    /// The tunnel did not open for any other reason.
    Failed,
}

/// The one writer of `CONNECT` to the proxy, as the front sees it.
///
/// The host's client implements it with the function that writes the login. That function reads
/// the verdict when it is called and again right before it writes, so the front adds a third read
/// in front of those two and writes nothing itself.
pub trait TunnelOpener: Send + Sync + 'static {
    /// Opens a tunnel to `host:port`, an IPv6 literal without its brackets.
    fn open<'a>(&'a self, host: &'a str, port: u16)
    -> BoxFuture<'a, Result<Tunnel, TunnelRefusal>>;
}

/// A [`TunnelOpener`] that travels in an [`crate::config::EndpointConfig`], which is `Clone`,
/// `Debug` and `PartialEq`: two are equal when they are the same opener.
#[derive(Clone)]
pub struct FrontOpener(pub Arc<dyn TunnelOpener>);

impl fmt::Debug for FrontOpener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a tunnel opener")
    }
}

impl PartialEq for FrontOpener {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FrontOpener {}

/// What a front's connection tasks share.
struct Shared {
    opener: Arc<dyn TunnelOpener>,
    relays: RelayMap,
    verdict: Verdict,
    secret: SecretVec,
    bounds: FrontBounds,
    tunnels: Arc<Semaphore>,
    pending: Mutex<VecDeque<(u64, Arc<Notify>)>>,
    accepted: std::sync::atomic::AtomicUsize,
}

/// The front: a listener on the IPv4 loopback and the tasks of the connections it admitted.
///
/// A front that is dropped without [`RelayFront::shutdown`] ends by its `Drop`: the listener's
/// task is aborted and so are the connection tasks.
pub struct RelayFront {
    address: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    connections: Arc<Mutex<JoinSet<()>>>,
}

impl fmt::Debug for RelayFront {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayFront(loopback)")
    }
}

impl RelayFront {
    /// Binds the loopback, makes the secret and starts serving.
    ///
    /// # Errors
    ///
    /// Returns the error of the bind, or of the system's random generator.
    pub async fn start(
        opener: Arc<dyn TunnelOpener>,
        relays: RelayMap,
        verdict: Verdict,
    ) -> std::io::Result<Self> {
        Self::start_with(opener, relays, verdict, FrontBounds::default()).await
    }

    /// As [`RelayFront::start`], with bounds a case chose.
    ///
    /// # Errors
    ///
    /// As [`RelayFront::start`].
    pub async fn start_with(
        opener: Arc<dyn TunnelOpener>,
        relays: RelayMap,
        verdict: Verdict,
        bounds: FrontBounds,
    ) -> std::io::Result<Self> {
        let mut random = [0_u8; 32];
        kr_crypto::random_bytes(&mut random)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut secret = Vec::with_capacity(64);
        for byte in random {
            secret.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared {
            opener,
            relays,
            verdict,
            secret: SecretVec::new(secret),
            tunnels: Arc::new(Semaphore::new(bounds.max_tunnels)),
            bounds,
            pending: Mutex::new(VecDeque::new()),
            accepted: std::sync::atomic::AtomicUsize::new(0),
        });
        let connections = Arc::new(Mutex::new(JoinSet::new()));
        let accept = tokio::spawn(accept(
            listener,
            Arc::clone(&shared),
            Arc::clone(&connections),
        ));
        Ok(Self {
            address,
            shared,
            accept: Some(accept),
            connections,
        })
    }

    /// The address the front listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The URL the network library is given as its proxy: the loopback address, with the user name
    /// and the secret the front admits. It is the one place the secret leaves the front, and it is
    /// never printed.
    #[must_use]
    pub fn proxy_url(&self) -> Url {
        let secret = std::str::from_utf8(self.shared.secret.expose()).unwrap_or_default();
        Url::parse(&format!("http://kr:{secret}@{}/", self.address)).expect("a loopback URL")
    }

    /// The secret, for a case that makes its own request.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn secret(&self) -> String {
        String::from_utf8_lossy(self.shared.secret.expose()).into_owned()
    }

    /// A handle a case reads the front's counters and secret through, after the front has moved
    /// into its owner.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn probe(&self) -> FrontProbe {
        FrontProbe(Arc::clone(&self.shared))
    }

    /// The number of connection tasks the front holds.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Ends the front: the listener's task is stopped and awaited, so a later connect to the port
    /// is refused by the system, then every connection task is aborted and awaited. When this
    /// returns no task of the front is left and the port is closed.
    pub async fn shutdown(mut self) {
        if let Some(accept) = self.accept.take() {
            accept.abort();
            let _ = accept.await;
        }
        let mut connections = std::mem::take(
            &mut *self
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        connections.shutdown().await;
    }
}

/// What a case reads of a front it does not own.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct FrontProbe(Arc<Shared>);

#[cfg(any(test, feature = "testing"))]
impl FrontProbe {
    /// How many connections the front has accepted, admitted or not.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.0.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The secret the front admits.
    #[must_use]
    pub fn secret(&self) -> String {
        String::from_utf8_lossy(self.0.secret.expose()).into_owned()
    }
}

impl Drop for RelayFront {
    fn drop(&mut self) {
        if let Some(accept) = self.accept.take() {
            accept.abort();
        }
        // The set of connection tasks aborts them when it drops.
    }
}

async fn accept(listener: TcpListener, shared: Arc<Shared>, connections: Arc<Mutex<JoinSet<()>>>) {
    let mut next = 0_u64;
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // A failed accept (a descriptor limit) is not the end of the front.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        next += 1;
        shared
            .accepted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let waiting = Arc::new(Notify::new());
        {
            let mut pending = shared
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            pending.push_back((next, Arc::clone(&waiting)));
            if pending.len() > shared.bounds.max_pending_heads
                && let Some((_, oldest)) = pending.pop_front()
            {
                oldest.notify_one();
            }
        }
        let mut set = connections.lock().unwrap_or_else(PoisonError::into_inner);
        // Reap what has ended, so a long run does not keep a finished task's result.
        while set.try_join_next().is_some() {}
        set.spawn(serve(stream, Arc::clone(&shared), next, waiting));
    }
}

/// What a request head asks for, once read.
enum Head {
    /// A `CONNECT` with the secret, to this target.
    Admitted(Target),
    /// Answer with this status and close.
    Refused(Status),
}

/// The statuses the front answers with. None carries a word the real proxy wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    ProxyAuthRequired,
    HeadTooLarge,
    BadGateway,
    Unavailable,
    GatewayTimeout,
}

impl Status {
    const fn line(self) -> &'static str {
        match self {
            Self::BadRequest => "HTTP/1.1 400 Bad Request\r\n",
            Self::Forbidden => "HTTP/1.1 403 Forbidden\r\n",
            Self::MethodNotAllowed => "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n",
            Self::ProxyAuthRequired => {
                "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"kalareach\"\r\n"
            }
            Self::HeadTooLarge => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
            Self::BadGateway => "HTTP/1.1 502 Bad Gateway\r\n",
            Self::Unavailable => "HTTP/1.1 503 Service Unavailable\r\n",
            Self::GatewayTimeout => "HTTP/1.1 504 Gateway Timeout\r\n",
        }
    }
}

async fn refuse(stream: &mut TcpStream, status: Status) {
    let answer = format!(
        "{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        status.line()
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// One connection: its head, the rules of the admission in order, and then the tunnel.
async fn serve(mut stream: TcpStream, shared: Arc<Shared>, id: u64, waiting: Arc<Notify>) {
    let head = tokio::select! {
        () = waiting.notified() => {
            // The oldest waiting head, dropped for a newer one: closed with nothing said.
            return;
        }
        head = tokio::time::timeout(shared.bounds.head_deadline, read_head(&mut stream, &shared)) => head,
    };
    shared
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|(entry, _)| *entry != id);
    let target = match head {
        Err(_) => return refuse(&mut stream, Status::BadRequest).await,
        Ok(Head::Refused(status)) => return refuse(&mut stream, status).await,
        Ok(Head::Admitted(target)) => target,
    };
    // The verdict, a third read in front of the opener's two: no new tunnel after it.
    if shared.verdict.stopped().is_some() {
        return refuse(&mut stream, Status::Unavailable).await;
    }
    let Ok(permit) = Arc::clone(&shared.tunnels).try_acquire_owned() else {
        return refuse(&mut stream, Status::Unavailable).await;
    };
    // The opener's call is raced against the verdict, the verdict first, so that a verdict set
    // while the opener is working is answered at the next poll and the opener's future is dropped.
    let opened = tokio::select! {
        biased;
        _ = shared.verdict.stopped_wait() => Err(Status::Unavailable),
        opened = tokio::time::timeout(
            shared.bounds.connect_deadline,
            shared.opener.open(&target.host, target.port),
        ) => match opened {
            Ok(Ok(tunnel)) => Ok(tunnel),
            Ok(Err(TunnelRefusal::Stopped)) => Err(Status::Unavailable),
            Ok(Err(TunnelRefusal::Failed)) => Err(Status::BadGateway),
            Err(_) => Err(Status::GatewayTimeout),
        },
    };
    let mut tunnel = match opened {
        Ok(tunnel) => tunnel,
        Err(status) => return refuse(&mut stream, status).await,
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    // Both directions end together: when either side closes or fails the pair is dropped, so a
    // tunnel the library has left holds no permit.
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
    drop(permit);
}

/// Reads a request head one byte at a time, so nothing after it is taken, and decides it.
async fn read_head(stream: &mut TcpStream, shared: &Shared) -> Head {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= shared.bounds.max_head_bytes {
            return Head::Refused(Status::HeadTooLarge);
        }
        match stream.read_u8().await {
            Ok(byte) => head.push(byte),
            Err(_) => return Head::Refused(Status::BadRequest),
        }
    }
    decide(&head, shared)
}

/// The admission rules, in order. Every refusal sends nothing to the real proxy.
fn decide(head: &[u8], shared: &Shared) -> Head {
    let Ok(text) = std::str::from_utf8(head) else {
        return Head::Refused(Status::BadRequest);
    };
    let mut lines = text.split("\r\n");
    let Some(request) = lines.next() else {
        return Head::Refused(Status::BadRequest);
    };
    let mut parts = request.split(' ');
    let (Some(method), Some(authority), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Head::Refused(Status::BadRequest);
    };
    if !version.starts_with("HTTP/1.") {
        return Head::Refused(Status::BadRequest);
    }
    if method != "CONNECT" {
        return Head::Refused(Status::MethodNotAllowed);
    }
    let authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.trim());
    if !holds_the_secret(authorization, &shared.secret) {
        return Head::Refused(Status::ProxyAuthRequired);
    }
    let Some(target) = parse_authority(authority) else {
        return Head::Refused(Status::BadRequest);
    };
    if !in_the_map(&shared.relays, &target) {
        return Head::Refused(Status::Forbidden);
    }
    Head::Admitted(target)
}

/// Whether a `Proxy-Authorization` value is Basic with the front's user and secret. The scheme is
/// case-insensitive and the comparison takes the same time whatever the part that is wrong.
fn holds_the_secret(authorization: Option<&str>, secret: &SecretVec) -> bool {
    let Some((scheme, encoded)) = authorization.and_then(|value| value.split_once(' ')) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Ok(pair) = STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Some(colon) = pair.iter().position(|byte| *byte == b':') else {
        return false;
    };
    kr_crypto::constant_time_eq(&pair[..colon], FRONT_USER)
        & kr_crypto::constant_time_eq(&pair[colon + 1..], secret.expose())
}

/// The host and port of a `CONNECT` target: `host:port` or `[v6]:port`.
fn parse_authority(authority: &str) -> Option<Target> {
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = match host.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')?
            .parse::<std::net::Ipv6Addr>()
            .ok()?
            .to_string(),
        None => match host.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) if host.is_empty() || host.contains(['[', ']', '@', '/']) => return None,
            Err(_) => host.to_ascii_lowercase(),
        },
    };
    Some(Target { host, port })
}

/// Whether `target` is a relay of the endpoint's live map, read now: a relay the keeper inserted a
/// moment ago is admitted and one it removed is not.
fn in_the_map(relays: &RelayMap, target: &Target) -> bool {
    relays
        .urls::<Vec<iroh::RelayUrl>>()
        .iter()
        .any(|url| Target::of(url).as_ref() == Some(target))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::mpsc;

    use super::*;
    use crate::config::ProxyUrl;
    use crate::proxy::{ProxyCredential, StopKind};

    /// What the opener double does with a call.
    #[derive(Clone, Copy)]
    enum Mode {
        /// Opens a tunnel whose far end goes to the case.
        Open,
        /// Never returns.
        Hang,
        /// Refuses as the verdict does.
        Stopped,
        /// Refuses for another reason.
        Failed,
    }

    /// An opener that counts its calls and records each host and port. It never stores a header.
    struct Double {
        mode: Mutex<Mode>,
        calls: AtomicUsize,
        seen: Mutex<Vec<(String, u16)>>,
        ends: mpsc::UnboundedSender<tokio::io::DuplexStream>,
    }

    impl TunnelOpener for Double {
        fn open<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, Result<Tunnel, TunnelRefusal>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((host.to_owned(), port));
            let mode = *self.mode.lock().unwrap_or_else(PoisonError::into_inner);
            Box::pin(async move {
                match mode {
                    Mode::Open => {
                        let (near, far) = tokio::io::duplex(64 * 1024);
                        let _ = self.ends.send(far);
                        Ok(Tunnel::new(near))
                    }
                    Mode::Hang => std::future::pending().await,
                    Mode::Stopped => Err(TunnelRefusal::Stopped),
                    Mode::Failed => Err(TunnelRefusal::Failed),
                }
            })
        }
    }

    struct Rig {
        double: Arc<Double>,
        ends: mpsc::UnboundedReceiver<tokio::io::DuplexStream>,
        relays: RelayMap,
        login: ProxyCredential,
        front: RelayFront,
    }

    fn relay(url: &str) -> iroh::RelayUrl {
        url.parse().expect("a relay URL")
    }

    async fn rig_with(mode: Mode, bounds: FrontBounds) -> Rig {
        let (ends_in, ends) = mpsc::unbounded_channel();
        let double = Arc::new(Double {
            mode: Mutex::new(mode),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            ends: ends_in,
        });
        let relays = RelayMap::from(relay("https://relay.example./"));
        let login = ProxyCredential::parse_line(&SecretVec::new(b"user:pw0rd-secret".to_vec()))
            .expect("a login");
        let front = RelayFront::start_with(
            Arc::<Double>::clone(&double),
            relays.clone(),
            login.verdict(),
            bounds,
        )
        .await
        .expect("a front");
        Rig {
            double,
            ends,
            relays,
            login,
            front,
        }
    }

    async fn rig(mode: Mode) -> Rig {
        rig_with(mode, FrontBounds::default()).await
    }

    impl Rig {
        fn calls(&self) -> usize {
            self.double.calls.load(Ordering::SeqCst)
        }

        /// Sends a head and reads the answer's status line.
        async fn ask(&self, head: &str) -> (TcpStream, String) {
            let mut stream = TcpStream::connect(self.front.address())
                .await
                .expect("connect");
            stream.write_all(head.as_bytes()).await.expect("write");
            let status = read_status(&mut stream).await;
            (stream, status)
        }

        fn basic(&self, user: &str, password: &str) -> String {
            format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
        }

        fn connect(&self, target: &str, authorization: &str) -> String {
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n\r\n")
        }

        fn good(&self, target: &str) -> String {
            let value = self.basic("kr", &self.front.secret());
            self.connect(target, &format!("Proxy-Authorization: {value}"))
        }
    }

    /// Reads one status line and the rest of the head, one byte at a time.
    async fn read_status(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            match tokio::time::timeout(Duration::from_secs(20), stream.read_u8()).await {
                Ok(Ok(byte)) => head.push(byte),
                _ => break,
            }
        }
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    /// The front admits a `CONNECT` that holds its secret to a relay of the live map, and nothing
    /// else, and every refusal leaves the opener uncalled.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_front_admits_only_a_connect_with_its_secret_to_a_relay() {
        let rig = rig(Mode::Open).await;
        assert!(rig.front.address().ip().is_loopback() && rig.front.address().is_ipv4());
        let target = "relay.example.:443";
        let secret = rig.front.secret();

        // No secret, a wrong secret and a wrong user: 407.
        for authorization in [
            String::new(),
            format!("Proxy-Authorization: {}", rig.basic("kr", "wrong")),
            format!("Proxy-Authorization: {}", rig.basic("other", &secret)),
            "Proxy-Authorization: Bearer abc".to_owned(),
            "Proxy-Authorization: Basic !!!".to_owned(),
        ] {
            let (_, status) = rig.ask(&rig.connect(target, &authorization)).await;
            assert!(status.contains(" 407 "), "{status}");
        }
        // A forwarded request is refused: the front forwards nothing.
        let (_, status) = rig
            .ask("GET http://relay.example./ HTTP/1.1\r\nHost: relay.example.\r\n\r\n")
            .await;
        assert!(status.contains(" 405 "), "{status}");
        // A target outside the map is refused, with the right secret.
        let (_, status) = rig.ask(&rig.good("other.example.:443")).await;
        assert!(status.contains(" 403 "), "{status}");
        let (_, status) = rig.ask(&rig.good("relay.example.:8443")).await;
        assert!(status.contains(" 403 "), "{status}");
        let (_, status) = rig.ask(&rig.good("not a target")).await;
        assert!(status.contains(" 400 "), "{status}");
        assert_eq!(rig.calls(), 0, "no refusal reached the opener");

        // The header name and the scheme are case-insensitive.
        let value = rig.basic("kr", &secret).replacen("Basic", "bAsIc", 1);
        let (_, status) = rig
            .ask(&rig.connect(target, &format!("proxy-authorization: {value}")))
            .await;
        assert!(status.contains(" 200 "), "{status}");
        assert_eq!(rig.calls(), 1);

        // A relay inserted into the shared map is admitted at the next request and one removed is
        // refused; an IPv6 literal is read in its brackets and handed over without them.
        rig.relays.insert(
            relay("https://[2001:db8::1]:8443/"),
            Arc::new(iroh::RelayConfig::from(relay(
                "https://[2001:db8::1]:8443/",
            ))),
        );
        let (_, status) = rig.ask(&rig.good("[2001:db8::1]:8443")).await;
        assert!(status.contains(" 200 "), "{status}");
        assert_eq!(
            rig.double.seen.lock().expect("seen").last(),
            Some(&("2001:db8::1".to_owned(), 8443))
        );
        rig.relays.remove(&relay("https://[2001:db8::1]:8443/"));
        let (_, status) = rig.ask(&rig.good("[2001:db8::1]:8443")).await;
        assert!(status.contains(" 403 "), "{status}");
        assert_eq!(rig.calls(), 2);
        rig.front.shutdown().await;
    }

    /// After the verdict a new `CONNECT` gets 503 and the opener is not called again, and a tunnel
    /// that is already open keeps carrying bytes.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_front_refuses_new_tunnels_at_the_verdict_and_keeps_the_open_one() {
        let mut rig = rig(Mode::Open).await;
        let (mut open, status) = rig.ask(&rig.good("relay.example.:443")).await;
        assert!(status.contains(" 200 "), "{status}");
        let mut far = rig.ends.recv().await.expect("the tunnel's far end");
        open.write_all(b"ping").await.expect("write");
        let mut bytes = [0_u8; 4];
        far.read_exact(&mut bytes).await.expect("read");
        assert_eq!(&bytes, b"ping");

        rig.login.refuse(StopKind::Refused);
        let (_, status) = rig.ask(&rig.good("relay.example.:443")).await;
        assert!(status.contains(" 503 "), "{status}");
        assert_eq!(rig.calls(), 1, "the opener's count is unchanged");
        far.write_all(b"pong").await.expect("write");
        open.read_exact(&mut bytes).await.expect("read");
        assert_eq!(&bytes, b"pong", "the open tunnel still carries bytes");
        rig.front.shutdown().await;
    }

    /// A verdict set while the opener is still working is answered at once, and the opener's call
    /// is dropped, before it returns.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn a_verdict_set_while_the_opener_works_is_answered_at_once() {
        let rig = rig(Mode::Hang).await;
        let mut stream = TcpStream::connect(rig.front.address())
            .await
            .expect("connect");
        stream
            .write_all(rig.good("relay.example.:443").as_bytes())
            .await
            .expect("write");
        while rig.calls() == 0 {
            tokio::task::yield_now().await;
        }
        rig.login.refuse(StopKind::Refused);
        let status = read_status(&mut stream).await;
        assert!(status.contains(" 503 "), "{status}");
        rig.front.shutdown().await;
    }

    /// The opener's own refusals map to 503 and 502, a call that never returns ends at the shortened
    /// deadline with 504, and none of them is a 407, which belongs to the front's secret.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_front_maps_the_openers_answers_to_statuses() {
        for (mode, expected) in [
            (Mode::Stopped, " 503 "),
            (Mode::Failed, " 502 "),
            (Mode::Hang, " 504 "),
        ] {
            let rig = rig_with(
                mode,
                FrontBounds {
                    connect_deadline: Duration::from_millis(200),
                    ..FrontBounds::default()
                },
            )
            .await;
            let (_, status) = rig.ask(&rig.good("relay.example.:443")).await;
            assert!(status.contains(expected), "{status}");
            assert!(!status.contains(" 407 "));
            rig.front.shutdown().await;
        }
    }

    /// The front's bounds: a full set of tunnels answers the next with 503 and the opener is not
    /// called, a head of one byte more than the limit is 431, a head that stalls closes at the
    /// shortened deadline, and the oldest waiting head is dropped for a new one.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_front_bounds_its_connections_head_and_deadlines() {
        let mut rig = rig_with(
            Mode::Open,
            FrontBounds {
                max_tunnels: 2,
                max_pending_heads: 2,
                max_head_bytes: 256,
                head_deadline: Duration::from_millis(300),
                ..FrontBounds::default()
            },
        )
        .await;
        let mut held = Vec::new();
        for _ in 0..2 {
            let (stream, status) = rig.ask(&rig.good("relay.example.:443")).await;
            assert!(status.contains(" 200 "), "{status}");
            held.push(stream);
        }
        let _ends = [rig.ends.recv().await, rig.ends.recv().await];
        let (_, status) = rig.ask(&rig.good("relay.example.:443")).await;
        assert!(status.contains(" 503 "), "{status}");
        assert_eq!(rig.calls(), 2, "the opener was not called for the third");

        let long = format!(
            "CONNECT relay.example.:443 HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(300)
        );
        let (_, status) = rig.ask(&long).await;
        assert!(status.contains(" 431 "), "{status}");

        // A stalled head is answered 400 at the head deadline.
        let mut stalled = TcpStream::connect(rig.front.address())
            .await
            .expect("connect");
        stalled
            .write_all(b"CONNECT relay.exam")
            .await
            .expect("write");
        assert!(read_status(&mut stalled).await.contains(" 400 "));

        // Past the pending limit the oldest waiting head is closed with nothing said.
        let mut first = TcpStream::connect(rig.front.address())
            .await
            .expect("connect");
        let _second = TcpStream::connect(rig.front.address())
            .await
            .expect("connect");
        let _third = TcpStream::connect(rig.front.address())
            .await
            .expect("connect");
        let mut byte = [0_u8; 1];
        assert!(matches!(first.read(&mut byte).await, Ok(0) | Err(_)));
        drop(held);
        rig.front.shutdown().await;
    }

    /// The shutdown stops the listener, so the port is refused by the system, and awaits every
    /// connection task: none is left.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn shutdown_leaves_no_task_and_no_port() {
        let mut rig = rig(Mode::Open).await;
        let address = rig.front.address();
        let (_open, status) = rig.ask(&rig.good("relay.example.:443")).await;
        assert!(status.contains(" 200 "), "{status}");
        let _far = rig.ends.recv().await;
        assert!(rig.front.task_count() >= 1);
        let connections = Arc::clone(&rig.front.connections);
        rig.front.shutdown().await;
        assert_eq!(
            connections.lock().expect("connections").len(),
            0,
            "no connection task is left"
        );
        assert!(
            TcpStream::connect(address).await.is_err(),
            "a connect to the port is refused by the system"
        );
    }

    /// The front, its opener and the library's proxy URL print no secret except the one URL that
    /// is meant to carry it.
    ///
    /// Covers KR-REQ-10.02.
    #[tokio::test]
    async fn the_front_prints_no_secret() {
        let rig = rig(Mode::Open).await;
        let secret = rig.front.secret();
        let opener = FrontOpener(Arc::<Double>::clone(&rig.double));
        let proxy: ProxyUrl = "https://proxy.example:3128".parse().expect("a proxy");
        let proxy = proxy.with_login(rig.login.clone());
        for printed in [
            format!("{:?}", rig.front),
            format!("{opener:?}"),
            format!("{:?}", rig.login.verdict()),
            format!("{proxy:?} {proxy}"),
        ] {
            assert!(!printed.contains(&secret), "{printed}");
            assert!(!printed.contains("pw0rd-secret"), "{printed}");
        }
        assert!(rig.front.proxy_url().as_str().contains(&secret));
        assert_eq!(opener, opener.clone());
        rig.front.shutdown().await;
    }
}
