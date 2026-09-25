//! An HTTP proxy on loopback that records what it is asked.
//!
//! It opens a `CONNECT` tunnel to whatever it is asked for, or refuses every request with one
//! status, and it keeps each request's first line. For a plain `http` destination a client sends
//! the whole request to the proxy instead of a `CONNECT`; the proxy records that line too and
//! answers it with its status, or with 502 when it tunnels, because it forwards nothing but tunnels.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How the proxy answers.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Opens every `CONNECT` tunnel it is asked for.
    Tunnel,
    /// Refuses every request with this status.
    Refuse(u16),
}

/// The proxy, and what it has been asked so far.
pub struct ConnectProxy {
    /// The proxy's address, as a configuration names one.
    pub url: String,
    asked: Arc<Mutex<Vec<String>>>,
    serving: JoinHandle<()>,
}

impl ConnectProxy {
    /// A proxy that opens every tunnel it is asked for.
    pub async fn tunnelling() -> Self {
        Self::start(Answer::Tunnel).await
    }

    /// A proxy that refuses every request with `status`.
    pub async fn refusing(status: u16) -> Self {
        Self::start(Answer::Refuse(status)).await
    }

    async fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&asked);
        let serving = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, answer, Arc::clone(&recorded)));
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            asked,
            serving,
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
async fn serve(mut client: TcpStream, answer: Answer, asked: Arc<Mutex<Vec<String>>>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        match client.read_u8().await {
            Ok(byte) => head.push(byte),
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
    }
}
