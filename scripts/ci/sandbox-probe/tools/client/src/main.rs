//! The sandbox probe's client: HTTPS requests with a body, several requests on one connection,
//! HTTP/2 when the server offers it, and a WebSocket that upgrades, exchanges frames both ways
//! and closes from each side. It prints one line per case,
//!
//!   RESULT <case> ok|FAIL <detail>
//!
//! and exits 0 when no case failed. The server's certificate is checked against the platform's
//! trust store (or against the file named by `PROBE_CA_FILE`, for a run outside a runner).
//!
//! usage: sandbox-probe-client ORIGIN
//! usage: sandbox-probe-client ORIGIN half-close   (a client that ends its half of the stream
//!        before it reads; prints its line and always exits 0)

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ring::digest;
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_websockets::{ClientBuilder, Message};

fn tls_config() -> Result<ClientConfig, String> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    if let Ok(path) = std::env::var("PROBE_CA_FILE") {
        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_file_iter(&path).map_err(|e| e.to_string())? {
            roots
                .add(der.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
        Ok(builder.with_root_certificates(roots).with_no_client_auth())
    } else {
        Ok(builder
            .with_platform_verifier()
            .map_err(|e| format!("the platform's certificate verifier: {e}"))?
            .with_no_client_auth())
    }
}

struct Report {
    failed: u32,
}

impl Report {
    fn case(&mut self, name: &str, result: Result<String, String>) {
        match result {
            Ok(detail) => println!("RESULT {name} ok {detail}"),
            Err(detail) => {
                self.failed += 1;
                println!("RESULT {name} FAIL {detail}");
            }
        }
    }
}

fn authority(origin: &str) -> Result<(String, u16), String> {
    let rest = origin
        .strip_prefix("https://")
        .ok_or("an https origin is needed")?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or("an origin with a port is needed")?;
    Ok((host.to_owned(), port.parse().map_err(|_| "bad port")?))
}

async fn connect(origin: &str, alpn: &[&[u8]]) -> Result<TlsStream<TcpStream>, String> {
    let (host, port) = authority(origin)?;
    let mut tls = tls_config()?;
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let name = ServerName::try_from(host.clone()).map_err(|_| "not a name TLS can verify")?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// Reads one HTTP/1.1 response from `stream`; `rest` carries bytes read past it.
async fn read_response(
    stream: &mut TlsStream<TcpStream>,
    rest: &mut Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    let mut buf = std::mem::take(rest);
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err(format!(
                "the stream ended after {} bytes, before a full header",
                buf.len()
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("no status")?;
    let mut body = buf.split_off(head_end);
    if let Some(len) = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        while body.len() < len {
            let mut chunk = [0u8; 4096];
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err(format!("the body ended at {} of {len} bytes", body.len()));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        *rest = body.split_off(len);
    } else if head.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = body.windows(2).position(|w| w == b"\r\n") {
                    break i;
                }
                let mut chunk = [0u8; 4096];
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| format!("read: {e}"))?;
                if n == 0 {
                    return Err("the chunked body ended early".into());
                }
                body.extend_from_slice(&chunk[..n]);
            };
            let size = usize::from_str_radix(String::from_utf8_lossy(&body[..line_end]).trim(), 16)
                .map_err(|_| "bad chunk size")?;
            body.drain(..line_end + 2);
            while body.len() < size + 2 {
                let mut chunk = [0u8; 4096];
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| format!("read: {e}"))?;
                if n == 0 {
                    return Err("the chunked body ended early".into());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            out.extend_from_slice(&body[..size]);
            body.drain(..size + 2);
            if size == 0 {
                break;
            }
        }
        *rest = body;
        return Ok((status, out));
    } else {
        *rest = Vec::new();
    }
    Ok((status, body))
}

async fn send_request(
    stream: &mut TlsStream<TcpStream>,
    method: &str,
    path: &str,
    body: &[u8],
    close: bool,
) -> Result<(), String> {
    let conn = if close { "close" } else { "keep-alive" };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: {conn}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))
}

fn field(json: &str, key: &str) -> Option<String> {
    let at = json.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = json[at..].trim_start_matches('"');
    let end = rest.find(|c| c == ',' || c == '}' || c == '"')?;
    Some(rest[..end].to_owned())
}

async fn https_post(origin: &str) -> Result<String, String> {
    let body = pattern(1 << 20);
    let want = hex(digest::digest(&digest::SHA256, &body).as_ref());
    let mut tls = tls_config()?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{origin}/echo"))
        .body(body)
        .send()
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = response.status();
    let text = response.text().await.map_err(|e| format!("body: {e}"))?;
    if !status.is_success() {
        return Err(format!("status {status}"));
    }
    let bytes = field(&text, "bytes").unwrap_or_default();
    let sha = field(&text, "sha256").unwrap_or_default();
    if bytes == (1 << 20).to_string() && sha == want {
        Ok("1 MiB body, length and SHA-256 came back as sent (reqwest)".into())
    } else {
        Err(format!("the Worker saw {bytes} bytes"))
    }
}

async fn https_sequence(origin: &str) -> Result<String, String> {
    let mut tls = tls_config()?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .pool_max_idle_per_host(1)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut last = 0u64;
    for _ in 0..5 {
        let text = client
            .get(format!("{origin}/counter"))
            .send()
            .await
            .map_err(|e| format!("send: {e}"))?
            .text()
            .await
            .map_err(|e| format!("body: {e}"))?;
        let n: u64 = field(&text, "n")
            .and_then(|v| v.parse().ok())
            .ok_or("no counter")?;
        if n <= last {
            return Err(format!("the counter went {last} then {n}"));
        }
        last = n;
    }
    Ok(format!(
        "5 sequential requests from one client, the Durable Object's counter reached {last}"
    ))
}

async fn https_notes(origin: &str) -> Result<String, String> {
    let mut stream = connect(origin, &[b"http/1.1"]).await?;
    let mut rest = Vec::new();
    send_request(&mut stream, "POST", "/notes", b"a note", false).await?;
    let (status, body) = read_response(&mut stream, &mut rest).await?;
    let text = String::from_utf8_lossy(&body).into_owned();
    let n: u64 = field(&text, "notes")
        .and_then(|v| v.parse().ok())
        .ok_or("no count")?;
    if status == 200 && n >= 1 {
        Ok(format!("a note went into D1, which holds {n}"))
    } else {
        Err(format!("status {status}, count {n}"))
    }
}

async fn https_one_connection(origin: &str) -> Result<String, String> {
    let mut stream = connect(origin, &[b"http/1.1"]).await?;
    let mut rest = Vec::new();
    let big = pattern(256 * 1024);
    let want = hex(digest::digest(&digest::SHA256, &big).as_ref());
    send_request(&mut stream, "GET", "/health", b"", false).await?;
    let (s1, _) = read_response(&mut stream, &mut rest).await?;
    send_request(&mut stream, "POST", "/echo", &big, false).await?;
    let (s2, b2) = read_response(&mut stream, &mut rest).await?;
    send_request(&mut stream, "GET", "/counter", b"", false).await?;
    let (s3, _) = read_response(&mut stream, &mut rest).await?;
    let text = String::from_utf8_lossy(&b2).into_owned();
    if s1 == 200
        && s2 == 200
        && s3 == 200
        && field(&text, "sha256").as_deref() == Some(want.as_str())
    {
        Ok("3 requests (the middle one with a 256 KiB body) on one TLS connection".into())
    } else {
        Err(format!("statuses {s1} {s2} {s3}"))
    }
}

async fn https_h2(origin: &str) -> Result<String, String> {
    let mut tls = tls_config()?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(format!("{origin}/health"))
        .send()
        .await
        .map_err(|e| format!("send: {e}"))?;
    let version = response.version();
    if response.status().is_success() {
        Ok(format!(
            "offered h2 and http/1.1, the server chose {version:?}"
        ))
    } else {
        Err(format!("status {}", response.status()))
    }
}

async fn half_close(origin: &str) -> Result<String, String> {
    let mut stream = connect(origin, &[b"http/1.1"]).await?;
    let mut rest = Vec::new();
    send_request(&mut stream, "GET", "/health", b"", true).await?;
    stream
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    let (status, _) = read_response(&mut stream, &mut rest).await?;
    if status == 200 {
        Ok(
            "a request, then the client's close_notify and TCP half-close, then the whole reply"
                .into(),
        )
    } else {
        Err(format!("status {status}"))
    }
}

async fn open_socket(
    origin: &str,
) -> Result<tokio_websockets::WebSocketStream<TlsStream<TcpStream>>, String> {
    let stream = connect(origin, &[b"http/1.1"]).await?;
    let uri = format!("wss://{}/ws", origin.trim_start_matches("https://"));
    let (socket, _) = ClientBuilder::new()
        .uri(&uri)
        .map_err(|e| format!("uri: {e}"))?
        .connect_on(stream)
        .await
        .map_err(|e| format!("upgrade: {e}"))?;
    Ok(socket)
}

async fn next_message(
    socket: &mut tokio_websockets::WebSocketStream<TlsStream<TcpStream>>,
) -> Result<Message, String> {
    match tokio::time::timeout(Duration::from_secs(20), socket.next()).await {
        Err(_) => Err("no frame in 20 s".into()),
        Ok(None) => Err("the stream ended".into()),
        Ok(Some(Err(e))) => Err(format!("{e}")),
        Ok(Some(Ok(m))) => Ok(m),
    }
}

async fn ws_echo(origin: &str) -> Result<String, String> {
    let mut socket = open_socket(origin).await?;
    socket
        .send(Message::text("hello from the client"))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let m = next_message(&mut socket).await?;
    if m.as_text() != Some("hello from the client") {
        return Err("the text frame did not come back".into());
    }
    let big = pattern(64 * 1024);
    socket
        .send(Message::binary(big.clone()))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let m = next_message(&mut socket).await?;
    if m.is_binary() && m.as_payload().as_ref() == big.as_slice() {
        Ok("upgraded; a text frame and a 64 KiB binary frame went out and came back".into())
    } else {
        Err("the binary frame did not come back as sent".into())
    }
}

async fn ws_client_close(origin: &str) -> Result<String, String> {
    let mut socket = open_socket(origin).await?;
    socket
        .send(Message::text("ping"))
        .await
        .map_err(|e| format!("send: {e}"))?;
    next_message(&mut socket).await?;
    socket
        .send(Message::close(
            Some(tokio_websockets::CloseCode::NORMAL_CLOSURE),
            "client done",
        ))
        .await
        .map_err(|e| format!("close: {e}"))?;
    // The Worker answers the close; then the stream ends.
    let mut saw_close = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(20), socket.next()).await {
            Err(_) => return Err("no close answer in 20 s".into()),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(format!("{e}")),
            Ok(Some(Ok(m))) => {
                if m.is_close() {
                    saw_close = true;
                }
            }
        }
    }
    Ok(format!(
        "the client sent a close frame, the stream ended (the Worker's close frame seen: {saw_close})"
    ))
}

async fn ws_server_close(origin: &str) -> Result<String, String> {
    let mut socket = open_socket(origin).await?;
    socket
        .send(Message::text("server-close"))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let m = next_message(&mut socket).await?;
    if !m.is_close() {
        return Err("the first frame after the request was not a close frame".into());
    }
    let code = m.as_close().map(|(code, _)| u16::from(code));
    // Answer the close, as a client does, then the stream ends.
    let _ = socket.send(Message::close(None, "")).await;
    let ended = matches!(
        tokio::time::timeout(Duration::from_secs(20), socket.next()).await,
        Ok(None) | Ok(Some(Err(_)))
    );
    Ok(format!(
        "the Worker closed with code {code:?}; the stream ended after the client's answer: {ended}"
    ))
}

async fn ws_log(origin: &str) -> Result<String, String> {
    let mut stream = connect(origin, &[b"http/1.1"]).await?;
    let mut rest = Vec::new();
    send_request(&mut stream, "GET", "/ws-log", b"", false).await?;
    let (_, body) = read_response(&mut stream, &mut rest).await?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if text.contains("client-closed:1000") && text.contains("server-closes") {
        Ok("the Worker recorded the close from the client's side and its own".into())
    } else {
        Err(format!("the Worker's record: {text}"))
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(origin) = args.get(1) else {
        eprintln!("usage: sandbox-probe-client ORIGIN [half-close]");
        std::process::exit(2);
    };
    let mut report = Report { failed: 0 };
    if args.get(2).map(String::as_str) == Some("half-close") {
        report.case("https-half-close", half_close(origin).await);
        return;
    }
    report.case("https-post", https_post(origin).await);
    report.case("https-d1", https_notes(origin).await);
    report.case("https-sequence", https_sequence(origin).await);
    report.case("https-one-connection", https_one_connection(origin).await);
    report.case("https-h2", https_h2(origin).await);
    report.case("ws-echo", ws_echo(origin).await);
    report.case("ws-client-close", ws_client_close(origin).await);
    report.case("ws-server-close", ws_server_close(origin).await);
    report.case("ws-log", ws_log(origin).await);
    std::process::exit(i32::from(report.failed > 0));
}
