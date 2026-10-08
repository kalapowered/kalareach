//! The loopback listener: where a desktop sign-in's answer comes back.
//!
//! The registered desktop redirect is `http://127.0.0.1:8765/oauth/callback`. The listener binds
//! that address on IPv4 loopback only, before the browser opens, and is closed when the attempt
//! ends. It reads each request with a size limit and a deadline. Only `GET /oauth/callback` with
//! the registered `Host` is an answer; anything else is told 404 and the wait goes on, so a stray
//! request cannot end a real sign-in. An answer's page is written after the code's exchange, so it
//! never claims more than happened, and it names no address and runs no script.
//!
//! The address is bound so that no other process can share it while the sign-in waits. On Windows
//! the socket takes `SO_EXCLUSIVEADDRUSE` before it binds: Windows otherwise lets another socket
//! that asks for address reuse take over an address another program is actively listening on.
//! Elsewhere an active listener cannot be shared this way. A process that wins the port first sees
//! at most a code bound to a verifier it does not have, so it can stop a sign-in and cannot
//! complete one.
//!
//! The companion's desktop sign-in and the host's `kr account sign-in` both receive their answer
//! here. A phone links neither.

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;

use kr_client::services::account::{Answer, Carrier, PendingAuthorisation, Redirect};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The registered redirect's address.
pub const ADDRESS: &str = "127.0.0.1:8765";

/// The most a request may carry before it is refused.
const REQUEST_LIMIT: usize = 8 * 1024;

/// How long one request may take to arrive.
const READ_DEADLINE: Duration = Duration::from_secs(10);

/// The registered callback path.
const CALLBACK_PATH: &str = "/oauth/callback";

/// Why the listener could not be opened.
#[derive(Debug)]
pub enum BindError {
    /// Another program holds the address.
    Busy,
    /// Anything else the platform reported.
    Failed(std::io::Error),
}

/// A listener for one attempt's answer.
#[derive(Debug)]
pub struct Listener {
    listener: TcpListener,
    host: String,
}

/// One request that is shaped like the answer, with the connection its page goes back on. Its
/// rendering leaves out the address, which carries the code and the state.
pub struct Callback {
    /// The answer as the registered redirect's address, which the attempt's checks compare.
    pub url: String,
    stream: TcpStream,
}

impl std::fmt::Debug for Callback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Callback").finish_non_exhaustive()
    }
}

impl Listener {
    /// Binds the registered address.
    ///
    /// # Errors
    ///
    /// Returns [`BindError::Busy`] when another program holds it.
    pub fn open() -> Result<Self, BindError> {
        let address: SocketAddr = ADDRESS.parse().expect("the registered address parses");
        Self::open_at(address, ADDRESS)
    }

    /// Binds `address` and accepts only requests whose `Host` is `host`, for a test.
    ///
    /// # Errors
    ///
    /// Returns [`BindError::Busy`] when another program holds the address.
    pub fn open_at(address: SocketAddr, host: &str) -> Result<Self, BindError> {
        let listener = bind(address).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AddrInUse {
                BindError::Busy
            } else {
                BindError::Failed(error)
            }
        })?;
        listener.set_nonblocking(true).map_err(BindError::Failed)?;
        let listener = TcpListener::from_std(listener).map_err(BindError::Failed)?;
        let host = if host.ends_with(":0") {
            let port = listener.local_addr().map_err(BindError::Failed)?.port();
            format!("{}:{port}", host.trim_end_matches(":0"))
        } else {
            host.to_owned()
        };
        Ok(Self { listener, host })
    }

    /// The address it listens on.
    ///
    /// # Panics
    ///
    /// Panics when the platform cannot say, which it always can for a bound socket.
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// Waits for the next request shaped like the answer. Everything else is told 404.
    pub async fn next(&self) -> Callback {
        loop {
            let Ok((mut stream, _)) = self.listener.accept().await else {
                continue;
            };
            let Ok(Ok(head)) = tokio::time::timeout(READ_DEADLINE, read_head(&mut stream)).await
            else {
                continue;
            };
            if let Some(target) = callback_target(&head, &self.host) {
                let base = Redirect::Loopback.uri();
                let origin = base.strip_suffix(CALLBACK_PATH).unwrap_or(base);
                return Callback {
                    url: format!("{origin}{target}"),
                    stream,
                };
            }
            let _ = answer(&mut stream, 404, "Not found").await;
        }
    }
}

impl Listener {
    /// Waits for the request that answers `pending`, and returns what its checks made of it with
    /// the connection the page goes back on.
    ///
    /// A request shaped like the answer that fails the attempt's address, repetition or state
    /// checks is told so and the wait goes on, so a stray request cannot end a real sign-in. Any
    /// other outcome, a grant, a refusal or a failure the service reported, ends the wait.
    pub async fn answered(&self, pending: &mut PendingAuthorisation) -> (Answer, Callback) {
        loop {
            let callback = self.next().await;
            match pending.answer(&callback.url, Carrier::Continuing) {
                Answer::Dropped(fault) => {
                    tracing::info!(?fault, "a request to the loopback address was set aside");
                    callback.set_aside().await;
                }
                answer => return (answer, callback),
            }
        }
    }
}

impl Callback {
    /// Tells the browser this request was not for the sign-in, and closes it.
    pub async fn set_aside(mut self) {
        let _ = answer(
            &mut self.stream,
            400,
            "This was not for the sign-in KalaReach is waiting for.",
        )
        .await;
    }

    /// Writes the page that says how the sign-in ended, and closes the connection.
    pub async fn finish(mut self, message: &str) {
        let _ = answer(&mut self.stream, 200, message).await;
    }
}

/// Reads a request's head, up to the limit.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            buffer.truncate(end);
            return String::from_utf8(buffer).map_err(|_| std::io::ErrorKind::InvalidData.into());
        }
        if buffer.len() > REQUEST_LIMIT {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
}

/// The request target, when the head is `GET /oauth/callback…` with the registered `Host`.
fn callback_target(head: &str, host: &str) -> Option<String> {
    let mut lines = head.split("\r\n");
    let mut request = lines.next()?.split(' ');
    let (method, target, version) = (request.next()?, request.next()?, request.next()?);
    if method != "GET" || !version.starts_with("HTTP/1.") || request.next().is_some() {
        return None;
    }
    let path = target.split('?').next()?;
    if path != CALLBACK_PATH {
        return None;
    }
    let mut hosts = lines.filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().to_owned())
    });
    let named = hosts.next()?;
    if hosts.next().is_some() || named != host {
        return None;
    }
    Some(target.to_owned())
}

/// Writes a small page that runs nothing, sends nothing on and is not kept.
async fn answer(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>KalaReach</title>\
         <p style=\"font:1.1rem/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;\
         padding:0 1rem\">{}</p></html>",
        escape(message)
    );
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\n\
         content-security-policy: default-src 'none'; style-src 'unsafe-inline'\r\n\
         cache-control: no-store\r\nreferrer-policy: no-referrer\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Binds `address` for listening, so that no other process can share it while it listens.
///
/// # Errors
///
/// Returns the platform's error, which is `AddrInUse` when another program holds the address.
pub fn bind(address: SocketAddr) -> std::io::Result<StdTcpListener> {
    #[cfg(windows)]
    {
        windows::bind(address)
    }
    #[cfg(not(windows))]
    {
        StdTcpListener::bind(address)
    }
}

#[cfg(windows)]
mod windows {
    use std::net::{SocketAddr, TcpListener};

    use socket2::{Domain, Protocol, Socket, Type};

    pub(super) fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        exclusive(&socket)?;
        socket.bind(&address.into())?;
        socket.listen(8)?;
        Ok(socket.into())
    }

    /// Sets `SO_EXCLUSIVEADDRUSE`, which no safe wrapper offers.
    #[allow(
        unsafe_code,
        reason = "setting a socket option is a call into Winsock with a raw pointer to the value"
    )]
    fn exclusive(socket: &Socket) -> std::io::Result<()> {
        use std::os::windows::io::AsRawSocket as _;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
        };

        let enabled: i32 = 1;
        // SAFETY: the handle is an open socket for the whole call, and the value is a live `i32`
        // whose length is the length passed.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const enabled).cast::<u8>(),
                4,
            )
        };
        if result == SOCKET_ERROR {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_address_is_not_bound_twice() {
        let first = bind("127.0.0.1:0".parse().expect("an address")).expect("a listener");
        let taken = first.local_addr().expect("an address");
        let second = bind(taken).expect_err("the address is held");
        assert_eq!(second.kind(), std::io::ErrorKind::AddrInUse);
    }

    /// How long a closed listener is given to end the connections it never accepted before the
    /// test calls it open: a bound on a wait that ends as soon as the listener is closed.
    const CLOSED_WITHIN: Duration = Duration::from_secs(30);

    /// The production address is the registered redirect's host and port.
    #[test]
    fn the_listener_binds_the_registered_redirects_address() {
        let registered = url::Url::parse(Redirect::Loopback.uri()).expect("an address");
        assert_eq!(
            ADDRESS,
            format!(
                "{}:{}",
                registered.host_str().expect("a host"),
                registered.port().expect("a port")
            )
        );
        assert_eq!(registered.path(), CALLBACK_PATH);
    }

    #[test]
    fn only_a_get_of_the_callback_with_the_registered_host_is_an_answer() {
        let host = "127.0.0.1:8765";
        let good = "GET /oauth/callback?code=a&state=b HTTP/1.1\r\nHost: 127.0.0.1:8765";
        assert_eq!(
            callback_target(good, host).as_deref(),
            Some("/oauth/callback?code=a&state=b")
        );
        for refused in [
            "POST /oauth/callback?code=a HTTP/1.1\r\nHost: 127.0.0.1:8765",
            "GET /oauth/other?code=a HTTP/1.1\r\nHost: 127.0.0.1:8765",
            "GET /oauth/callback/x?code=a HTTP/1.1\r\nHost: 127.0.0.1:8765",
            "GET /oauth/callback?code=a HTTP/1.1\r\nHost: localhost:8765",
            "GET /oauth/callback?code=a HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nHost: evil.example",
            "GET /oauth/callback?code=a HTTP/1.1",
            "GET /oauth/callback?code=a HTTP/1.1 extra\r\nHost: 127.0.0.1:8765",
        ] {
            assert_eq!(callback_target(refused, host), None, "{refused}");
        }
    }

    async fn send(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.expect("a connection");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("a request");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer).await;
        answer
    }

    /// Anything but the answer is told 404 and the wait goes on; the answer is taken once and its
    /// page runs nothing.
    #[tokio::test]
    async fn a_stray_request_is_refused_and_the_wait_goes_on() {
        let listener = Listener::open_at("127.0.0.1:0".parse().expect("an address"), "127.0.0.1:0")
            .expect("a listener");
        let address = listener.local_address();
        let host = format!("127.0.0.1:{}", address.port());
        let (callback, answering) = {
            let serving = listener.next();
            tokio::pin!(serving);

            // Two stray requests while the listener waits: each is told 404 and the wait goes on.
            let strays = async {
                let stray = send(
                    address,
                    &format!("GET /favicon.ico HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                )
                .await;
                let wrong_host = send(
                    address,
                    "GET /oauth/callback?code=a HTTP/1.1\r\nHost: evil.example\r\n\r\n",
                )
                .await;
                (stray, wrong_host)
            };
            let (stray, wrong_host) = tokio::select! {
                callback = &mut serving => panic!("a stray request is not an answer: {}", callback.url),
                answers = strays => answers,
            };
            assert!(stray.starts_with("HTTP/1.1 404"), "{stray}");
            assert!(wrong_host.starts_with("HTTP/1.1 404"), "{wrong_host}");

            // The answer ends the wait.
            let answering =
                tokio::spawn({
                    let host = host.clone();
                    async move {
                        send(
                    address,
                    &format!("GET /oauth/callback?code=a&state=b HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                )
                .await
                    }
                });
            (serving.await, answering)
        };
        assert_eq!(
            callback.url,
            "http://127.0.0.1:8765/oauth/callback?code=a&state=b"
        );
        callback
            .finish("You are signed in to KalaReach. You can close this tab.")
            .await;
        let page = answering.await.expect("a task");
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("content-security-policy: default-src 'none'"));
        assert!(page.contains("cache-control: no-store"));
        assert!(page.contains("referrer-policy: no-referrer"));
        assert!(!page.contains("<script"));
        assert!(!page.contains("href"));
        // A connection the listener took in and nothing has accepted is reset when the listener
        // closes, so its end is what shows the listener closed. Dialling the address afterwards
        // would show nothing of it: a program that took the freed port would answer.
        let mut waiting = TcpStream::connect(address).await.expect("a connection");
        drop(listener);
        let mut byte = [0_u8; 1];
        let ended = tokio::time::timeout(CLOSED_WITHIN, waiting.read(&mut byte))
            .await
            .expect("the listener is closed once the attempt is over");
        let reset = match &ended {
            Ok(read) => *read == 0,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
        };
        assert!(
            reset,
            "the connection the listener never accepted ends with it: {ended:?}"
        );
    }

    /// This machine's address on the network, where it has one: the source address a datagram to
    /// a documentation address would leave from. Nothing is sent.
    fn outward_address() -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("192.0.2.1:9").ok()?;
        let address = socket.local_addr().ok()?.ip();
        (!address.is_loopback() && !address.is_unspecified()).then_some(address)
    }

    /// The socket the listener binds is on loopback, so the machine's other address does
    /// not reach it. The control, one bound to every interface the same way, is reached there, so
    /// the check can fail.
    #[tokio::test]
    async fn the_bound_socket_is_on_loopback_and_one_on_every_interface_would_be_reached() {
        let registered: SocketAddr = ADDRESS.parse().expect("an address");
        assert!(registered.ip().is_loopback() && registered.is_ipv4());
        let listener = Listener::open_at(SocketAddr::new(registered.ip(), 0), "127.0.0.1:0")
            .expect("a listener");
        let bound = listener.local_address();
        assert_eq!(bound.ip(), registered.ip());
        let Some(outward) = outward_address() else {
            println!(
                "this machine has no address outside loopback; the reachability half is skipped"
            );
            return;
        };
        assert!(
            TcpStream::connect(SocketAddr::new(outward, bound.port()))
                .await
                .is_err(),
            "the loopback listener answered on {outward}"
        );
        let everywhere = Listener::open_at("0.0.0.0:0".parse().expect("an address"), "127.0.0.1:0")
            .expect("the control's listener");
        let port = everywhere.local_address().port();
        assert!(
            TcpStream::connect(SocketAddr::new(outward, port))
                .await
                .is_ok(),
            "the control on every interface was not reached on {outward}"
        );
    }

    /// A callback's rendering leaves out its address, which carries the code and state.
    #[tokio::test]
    async fn a_callback_renders_without_its_address() {
        let listener = Listener::open_at("127.0.0.1:0".parse().expect("an address"), "127.0.0.1:0")
            .expect("a listener");
        let address = listener.local_address();
        let host = format!("127.0.0.1:{}", address.port());
        let asking = tokio::spawn(async move {
            send(
                address,
                &format!(
                    "GET /oauth/callback?code=NEVER_RENDERED&state=NEVER_RENDERED HTTP/1.1\r\nHost: {host}\r\n\r\n"
                ),
            )
            .await
        });
        let callback = listener.next().await;
        for rendering in [format!("{callback:?}"), format!("{callback:#?}")] {
            assert!(!rendering.contains("NEVER_RENDERED"), "{rendering}");
        }
        assert_eq!(format!("{callback:?}"), "Callback { .. }");
        callback.set_aside().await;
        let _ = asking.await;
    }

    #[tokio::test]
    async fn a_held_address_is_reported_as_busy() {
        let first = Listener::open_at("127.0.0.1:0".parse().expect("an address"), "127.0.0.1:0")
            .expect("a listener");
        let taken = first.local_address();
        assert!(matches!(
            Listener::open_at(taken, "127.0.0.1:0"),
            Err(BindError::Busy)
        ));
    }
}
