//! The stand-in on a loopback socket.
//!
//! A daemon reaches a managed service through its own HTTP transport, so a test of the daemon needs
//! something that speaks HTTP/1.1. This is the least of one: it reads one request, hands it to the
//! service and writes the one answer, and closes the connection.

use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::web::{Handled, StorageWeb, document_of};

/// The most a request's head and body may be, so a test that goes wrong stops rather than grows.
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// A stand-in serving on a loopback port until it is dropped.
#[derive(Debug)]
pub struct Served {
    web: Arc<StorageWeb>,
    task: JoinHandle<()>,
}

impl Served {
    /// The service that answers.
    #[must_use]
    pub const fn web(&self) -> &Arc<StorageWeb> {
        &self.web
    }

    /// The origin to configure a client or a daemon with.
    #[must_use]
    pub fn origin(&self) -> &str {
        self.web.origin()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        // Ends the accepting task, and with it every connection it is serving.
        self.task.abort();
    }
}

/// Starts a service on a loopback port of the system's choosing.
///
/// # Panics
///
/// Panics when no loopback port can be bound.
pub async fn serve() -> Served {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();
    let web = Arc::new(StorageWeb::at(format!("http://127.0.0.1:{port}")));
    let task = tokio::spawn(accept(listener, Arc::clone(&web)));
    Served { web, task }
}

async fn accept(listener: TcpListener, web: Arc<StorageWeb>) {
    let mut connections = JoinSet::new();
    while let Ok((socket, _)) = listener.accept().await {
        connections.spawn(connection(socket, Arc::clone(&web)));
    }
}

/// One request as it arrived.
struct Received {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.as_str())
    }
}

async fn connection(mut socket: TcpStream, web: Arc<StorageWeb>) {
    let Some(received) = read_request(&mut socket).await else {
        return;
    };
    let token = received
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);
    let carries_content = received
        .header("content-type")
        .is_some_and(|kind| kind.starts_with("application/octet-stream"));
    let parsed = if carries_content {
        received
            .header("kr-service-request")
            .map(document_of)
            .ok_or(())
    } else {
        serde_json::from_slice(&received.body).map_err(|_| ())
    };
    let handled = match parsed {
        Ok(document) => web.handle(
            &received.path,
            &document,
            token.as_deref(),
            carries_content.then_some(received.body.as_slice()),
        ),
        Err(()) => Handled::Answer(crate::web::refusal(
            400,
            "INVALID_REQUEST",
            "A managed-service request is bounded JSON.",
        )),
    };
    let handled = match handled {
        Handled::Slow(epoch, answer) => {
            web.held_until_released(epoch).await;
            Handled::Answer(answer)
        }
        other => other,
    };
    match handled {
        Handled::Answer(answer) => {
            let content_type =
                if answer.status == 200 && received.path == "/api/storage/object/read" {
                    "application/octet-stream"
                } else {
                    "application/json"
                };
            let head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.status,
                reason(answer.status),
                answer.body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&answer.body).await;
            let _ = socket.shutdown().await;
        }
        // The connection ends with no answer, as one does that the network lost.
        Handled::Lost => {}
        Handled::Held(epoch) => web.held_until_released(epoch).await,
        Handled::Slow(..) => {}
    }
}

async fn read_request(socket: &mut TcpStream) -> Option<Received> {
    let mut buffer = Vec::new();
    let mut chunk = vec![0_u8; 64 * 1024];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.lines();
    let target = lines.next()?.split_whitespace().nth(1)?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if length > MAX_REQUEST_BYTES {
        return None;
    }
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some(Received {
        path: target.split('?').next().unwrap_or_default().to_owned(),
        headers,
        body,
    })
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}
