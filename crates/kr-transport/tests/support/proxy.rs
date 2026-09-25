//! An HTTP proxy on loopback, standing in for the one a network requires.
//!
//! It answers the two requests a proxy is asked. `CONNECT host:port` opens a tunnel: the proxy
//! connects to that address, says so, and splices the two connections, so what travels inside is
//! the client's own TLS with the server. A request whose target is an absolute URL is forwarded:
//! the proxy sends it to that URL's server and relays the answer, one request to a connection.
//! Every request is recorded with its method and target before anything is done with it, so a
//! test can tell what an endpoint asked the proxy to reach.
//!
//! It runs on a runtime of its own, so nothing about it depends on the runtime the endpoints run
//! on. Stopping it closes its port and every connection it holds, which leaves a client that was
//! told to use it nowhere to go.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_transport::config::{ProxyUrl, Url};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// The longest request or response head the proxy reads.
const MAX_HEAD: usize = 16 * 1024;

/// What a proxy that cannot reach the destination answers.
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// One request the proxy took: its method, and the address or URL it named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub method: String,
    pub target: String,
}

/// A proxy on a free loopback port.
pub struct HttpProxy {
    /// Where an endpoint that selects this proxy sends its requests.
    pub url: ProxyUrl,
    addr: SocketAddr,
    asked: Arc<Mutex<Vec<Asked>>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl HttpProxy {
    /// Starts a proxy that tunnels and forwards whatever it is asked to.
    pub fn forwarding() -> Self {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a proxy listener");
        listener
            .set_nonblocking(true)
            .expect("a listener the runtime can drive");
        let addr = listener.local_addr().expect("a bound address");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the proxy's runtime");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let recording = Arc::clone(&asked);
        runtime.spawn(async move {
            let listener = TcpListener::from_std(listener).expect("the proxy listener");
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&recording)));
            }
        });
        Self {
            url: format!("http://{addr}").parse().expect("a proxy URL"),
            addr,
            asked,
            runtime: Some(runtime),
        }
    }

    /// Every request the proxy took, in the order it took them.
    pub fn asked(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The address of every tunnel the proxy was asked to open.
    pub fn tunnels(&self) -> Vec<String> {
        self.asked()
            .into_iter()
            .filter(|asked| asked.method == "CONNECT")
            .map(|asked| asked.target)
            .collect()
    }

    /// Stops the proxy: its port is closed, and so is every connection it holds, when this returns.
    pub fn stop(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        runtime.shutdown_background();
        // The runtime drops the listener on its own threads, so the port is watched until a
        // connection to it is refused.
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect_timeout(&self.addr, Duration::from_millis(200)).is_ok() {
            assert!(Instant::now() < deadline, "the stopped proxy still answers");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for HttpProxy {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Returns `url`'s host and port, as a `CONNECT` names it.
pub fn authority(url: &Url) -> String {
    format!(
        "{}:{}",
        url.host_str().expect("a URL with a host"),
        url.port_or_known_default().expect("a URL with a port")
    )
}

/// Takes one request from `stream` and does what it asks.
async fn serve(stream: TcpStream, asked: Arc<Mutex<Vec<Asked>>>) {
    let mut client = BufReader::new(stream);
    let Some(head) = read_head(&mut client).await else {
        return;
    };
    let Some((method, target)) = head.split("\r\n").next().and_then(|line| {
        let mut parts = line.split(' ');
        Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
    }) else {
        return;
    };
    asked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Asked {
            method: method.clone(),
            target: target.clone(),
        });
    if method == "CONNECT" {
        tunnel(client, &target).await;
    } else {
        forward(client, &head, &target).await;
    }
}

/// Opens a tunnel to `target` and splices it to the client.
async fn tunnel(mut client: BufReader<TcpStream>, target: &str) {
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = client.get_mut().write_all(BAD_GATEWAY).await;
        return;
    };
    if client
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    // Whatever the client sent after the head is the start of what the tunnel carries.
    let early = client.buffer().to_vec();
    if upstream.write_all(&early).await.is_err() {
        return;
    }
    let mut client = client.into_inner();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// Sends the request whose head is `head` to the server `target` names, and relays its answer.
///
/// One request to a connection: the request is sent with `Connection: close` and the answer is
/// relayed with it, so a client opens a new connection for its next request.
async fn forward(mut client: BufReader<TcpStream>, head: &str, target: &str) {
    let Some((upstream_addr, request_line)) = Url::parse(target).ok().and_then(|url| {
        let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let method = head.split(' ').next()?;
        Some((authority(&url), format!("{method} {path} HTTP/1.1")))
    }) else {
        let _ = client.get_mut().write_all(BAD_GATEWAY).await;
        return;
    };
    let Ok(upstream) = TcpStream::connect(&upstream_addr).await else {
        let _ = client.get_mut().write_all(BAD_GATEWAY).await;
        return;
    };
    let mut upstream = BufReader::new(upstream);
    let request = rewrite(
        head,
        &request_line,
        &["proxy-connection", "proxy-authorization"],
    );
    // A request that declares no length has no body, where a response without one runs until its
    // connection closes.
    if upstream
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .is_err()
        || relay_body(
            &mut client,
            upstream.get_mut(),
            Some(content_length(head).unwrap_or(0)),
        )
        .await
        .is_err()
    {
        return;
    }
    let Some(answer) = read_head(&mut upstream).await else {
        let _ = client.get_mut().write_all(BAD_GATEWAY).await;
        return;
    };
    let status_line = answer.split("\r\n").next().unwrap_or_default().to_owned();
    let response = rewrite(&answer, &status_line, &[]);
    if client
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .is_err()
    {
        return;
    }
    let _ = relay_body(&mut upstream, client.get_mut(), content_length(&answer)).await;
    let _ = client.get_mut().shutdown().await;
}

/// Copies a body of `length` bytes from `from` to `to`, or everything until `from` ends when the
/// head declared no length.
async fn relay_body<R, W>(
    from: &mut BufReader<R>,
    to: &mut W,
    length: Option<u64>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match length {
        Some(length) => {
            tokio::io::copy(&mut from.take(length), to).await?;
        }
        None => {
            tokio::io::copy(from, to).await?;
        }
    }
    to.flush().await
}

/// Returns `head` with `first` as its first line, without the hop-by-hop headers and the ones in
/// `dropped`, and with `Connection: close`.
fn rewrite(head: &str, first: &str, dropped: &[&str]) -> String {
    let mut rewritten = format!("{first}\r\n");
    for line in head.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let name = line
            .split_once(':')
            .map_or(line, |(name, _)| name)
            .trim()
            .to_ascii_lowercase();
        if name == "connection" || name == "keep-alive" || dropped.contains(&name.as_str()) {
            continue;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Connection: close\r\n\r\n");
    rewritten
}

/// The length a head's `Content-Length` declares, if it declares one.
fn content_length(head: &str) -> Option<u64> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// Reads one head, up to and including the empty line that ends it.
async fn read_head<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<String> {
    let mut head = String::new();
    loop {
        let before = head.len();
        let read = reader.read_line(&mut head).await.ok()?;
        if read == 0 || head.len() > MAX_HEAD {
            return None;
        }
        if &head[before..] == "\r\n" {
            return Some(head);
        }
    }
}
