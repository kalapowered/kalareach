//! An HTTP proxy on loopback that records what it is asked.
//!
//! It opens a `CONNECT` tunnel to whatever it is asked for, refuses every request with one status,
//! or answers with a head that never ends, and it keeps each request's first line. It listens in
//! the clear, or behind TLS when a test gives it an acceptor, which makes its address an `https`
//! one. For a plain `http` destination a client sends the whole request to the proxy instead of a
//! `CONNECT`; the proxy records that line too and answers it with its status, or with 502 when it
//! tunnels, because it forwards nothing but tunnels.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// How the proxy answers.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Opens every `CONNECT` tunnel it is asked for.
    Tunnel,
    /// Refuses every request with this status.
    Refuse(u16),
    /// Answers with a status line and then header lines, without end.
    Endless,
}

/// What a request's `Proxy-Authorization` was, against the login the proxy takes now. The proxy
/// never stores the header's value, only this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Login {
    /// The request had none.
    Absent,
    /// It was Basic with the login the proxy takes.
    Right,
    /// It was anything else.
    Wrong,
}

/// One request the login mode read: where it went, what its login was, and when.
#[derive(Clone, Debug)]
pub struct Call {
    /// The `host:port` a `CONNECT` named, none for any other request.
    pub target: Option<String>,
    /// The class of the request's `Proxy-Authorization`.
    pub login: Login,
    /// When the proxy had read the request's head.
    pub at: std::time::Instant,
}

/// A tunnel the proxy holds open: the `host:port` it goes to, and what ends it.
type OpenTunnel = (String, Arc<Notify>);

/// The login mode: what the proxy takes, what it offers, and what it has seen.
#[derive(Clone)]
struct Auth {
    expected: Arc<Mutex<(String, String)>>,
    offered: Arc<str>,
    http10: bool,
    logins: Arc<Mutex<Vec<Login>>>,
    calls: Arc<Mutex<Vec<Call>>>,
    refused: Arc<Mutex<Vec<String>>>,
    tunnels: Arc<Mutex<Vec<OpenTunnel>>>,
    bytes: Arc<AtomicUsize>,
}

/// The proxy, and what it has been asked so far.
pub struct ConnectProxy {
    /// The proxy's address, as a configuration names one.
    pub url: String,
    asked: Arc<Mutex<Vec<String>>>,
    serving: JoinHandle<()>,
    auth: Option<Auth>,
    accepts: Arc<AtomicUsize>,
    hold: Arc<watch::Sender<bool>>,
}

impl ConnectProxy {
    /// A proxy that opens every tunnel it is asked for.
    pub async fn tunnelling() -> Self {
        Self::start(Answer::Tunnel, None).await
    }

    /// A proxy that opens every tunnel it is asked for, reached over TLS with `acceptor`.
    pub async fn tunnelling_over_tls(acceptor: TlsAcceptor) -> Self {
        Self::start(Answer::Tunnel, Some(acceptor)).await
    }

    /// A proxy that refuses every request with `status`.
    pub async fn refusing(status: u16) -> Self {
        Self::start(Answer::Refuse(status), None).await
    }

    /// A proxy whose answer to every request is a head that never ends.
    pub async fn answering_without_end() -> Self {
        Self::start(Answer::Endless, None).await
    }

    /// A proxy that opens a tunnel for a request that carries Basic with `user` and `password` and
    /// answers every other with `407` and `Proxy-Authenticate: offered`.
    pub async fn authenticating(user: &str, password: &str, offered: &str) -> Self {
        Self::start_with(
            Answer::Tunnel,
            None,
            Some(Self::auth(user, password, offered, false)),
        )
        .await
    }

    /// As [`Self::authenticating`], answering `HTTP/1.0 407` where it refuses.
    pub async fn authenticating_in_http10(user: &str, password: &str, offered: &str) -> Self {
        Self::start_with(
            Answer::Tunnel,
            None,
            Some(Self::auth(user, password, offered, true)),
        )
        .await
    }

    /// As [`Self::authenticating`], reached over TLS with `acceptor`.
    pub async fn authenticating_over_tls(
        acceptor: TlsAcceptor,
        user: &str,
        password: &str,
        offered: &str,
    ) -> Self {
        Self::start_with(
            Answer::Tunnel,
            Some(acceptor),
            Some(Self::auth(user, password, offered, false)),
        )
        .await
    }

    fn auth(user: &str, password: &str, offered: &str, http10: bool) -> Auth {
        Auth {
            expected: Arc::new(Mutex::new((user.to_owned(), password.to_owned()))),
            offered: Arc::from(offered),
            http10,
            logins: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            refused: Arc::new(Mutex::new(Vec::new())),
            tunnels: Arc::new(Mutex::new(Vec::new())),
            bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Changes the login the proxy takes, so the one a client holds is refused from now on.
    pub fn change_login(&self, user: &str, password: &str) {
        let auth = self.auth.as_ref().expect("an authenticating proxy");
        *auth.expected.lock().unwrap_or_else(PoisonError::into_inner) =
            (user.to_owned(), password.to_owned());
    }

    /// Ends every open tunnel to `target`, the `host:port` a `CONNECT` named.
    pub fn close_tunnels_to(&self, target: &str) {
        let auth = self.auth.as_ref().expect("an authenticating proxy");
        for (to, close) in auth
            .tunnels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            if to == target {
                close.notify_waiters();
                close.notify_one();
            }
        }
    }

    /// Answers `407` to every `CONNECT` to `target`, the `host:port` it names, whatever login it
    /// carries, and records the login as it was.
    pub fn refuse_target(&self, target: &str) {
        let auth = self.auth.as_ref().expect("an authenticating proxy");
        auth.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(target.to_owned());
    }

    /// Each request the login mode read, in order, with its target, its login and its time.
    pub fn calls(&self) -> Vec<Call> {
        self.auth
            .as_ref()
            .expect("an authenticating proxy")
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What each request's login was, in order.
    pub fn logins(&self) -> Vec<Login> {
        self.auth
            .as_ref()
            .expect("an authenticating proxy")
            .logins
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many bytes of requests the proxy has read, over every connection.
    pub fn bytes_read(&self) -> usize {
        self.auth
            .as_ref()
            .expect("an authenticating proxy")
            .bytes
            .load(Ordering::SeqCst)
    }

    /// How many connections the proxy has accepted, TLS held or not.
    pub fn accepted(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Holds the TLS handshake of every connection that arrives from now on, until
    /// [`Self::release_tls`].
    pub fn hold_tls(&self) {
        self.hold.send_replace(true);
    }

    /// Lets the held handshakes go on.
    pub fn release_tls(&self) {
        self.hold.send_replace(false);
    }

    async fn start(answer: Answer, tls: Option<TlsAcceptor>) -> Self {
        Self::start_with(answer, tls, None).await
    }

    async fn start_with(answer: Answer, tls: Option<TlsAcceptor>, auth: Option<Auth>) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let asked = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&asked);
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepts);
        let hold = Arc::new(watch::channel(false).0);
        let held = Arc::clone(&hold);
        let mode = auth.clone();
        let serving = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let recorded = Arc::clone(&recorded);
                let tls = tls.clone();
                let mode = mode.clone();
                let mut gate = held.subscribe();
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            if gate.wait_for(|held| !*held).await.is_err() {
                                return;
                            }
                            if let Ok(stream) = acceptor.accept(stream).await {
                                serve(stream, answer, mode, recorded).await;
                            }
                        }
                        None => serve(stream, answer, mode, recorded).await,
                    }
                });
            }
        });
        Self {
            url: format!("{scheme}://127.0.0.1:{port}"),
            asked,
            serving,
            auth,
            accepts,
            hold,
        }
    }

    /// The first line of every request the proxy has read, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for ConnectProxy {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Reads one request's head, records its first line, and answers it.
async fn serve<S>(mut client: S, answer: Answer, auth: Option<Auth>, asked: Arc<Mutex<Vec<String>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        match client.read_u8().await {
            Ok(byte) => {
                if let Some(auth) = &auth {
                    auth.bytes.fetch_add(1, Ordering::SeqCst);
                }
                head.push(byte);
            }
            Err(_) => return,
        }
    }
    let line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    asked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(line.clone());
    let target = line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split(' ').next());
    if let Some(auth) = auth {
        return authenticate(client, &head, target, &auth).await;
    }
    match (answer, target) {
        (Answer::Tunnel, Some(target)) => {
            let Ok(mut destination) = TcpStream::connect(target).await else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return;
            };
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_ok()
            {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut destination).await;
            }
        }
        (Answer::Tunnel, None) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                .await;
        }
        (Answer::Refuse(status), _) => {
            let _ = client
                .write_all(
                    format!("HTTP/1.1 {status} Refused\r\ncontent-length: 0\r\n\r\n").as_bytes(),
                )
                .await;
        }
        (Answer::Endless, _) => {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n")
                .await
                .is_err()
            {
                return;
            }
            // Until the client stops reading, which ends this write.
            while client
                .write_all(b"x-filler: 0123456789abcdef\r\n")
                .await
                .is_ok()
            {}
        }
    }
}

/// The login mode: classifies the request's `Proxy-Authorization`, records the class and nothing of
/// the value, and either opens the tunnel or answers `407`.
async fn authenticate<S>(mut client: S, head: &[u8], target: Option<&str>, auth: &Auth)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let expected = auth
        .expected
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let value = String::from_utf8_lossy(head)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.trim().to_owned());
    let class = match value {
        None => Login::Absent,
        Some(value) => {
            let right = format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", expected.0, expected.1))
            );
            if value == right {
                Login::Right
            } else {
                Login::Wrong
            }
        }
    };
    auth.logins
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(class);
    auth.calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Call {
            target: target.map(str::to_owned),
            login: class,
            at: std::time::Instant::now(),
        });
    let refused = target.is_some_and(|target| {
        auth.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|refused| refused == target)
    });
    let (Login::Right, Some(target), false) = (class, target, refused) else {
        let version = if auth.http10 { "HTTP/1.0" } else { "HTTP/1.1" };
        let _ = client
            .write_all(
                format!(
                    "{version} 407 Proxy Authentication Required\r\nProxy-Authenticate: {}\r\ncontent-length: 0\r\n\r\n",
                    auth.offered
                )
                .as_bytes(),
            )
            .await;
        return;
    };
    let Ok(mut destination) = TcpStream::connect(target).await else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let close = Arc::new(Notify::new());
    auth.tunnels
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((target.to_owned(), Arc::clone(&close)));
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut destination) => {}
        () = close.notified() => {}
    }
}
