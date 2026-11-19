//! A TLS origin that keeps its connections open and counts the requests they carry, for the cases
//! that need a request to ride a tunnel that an earlier request opened.
//!
//! Suites include this module by its path.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// The origin: it answers every request of every connection with `200` and no body.
pub struct PooledOrigin {
    /// The loopback port it listens on.
    pub port: u16,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl PooledOrigin {
    /// Starts the origin behind `acceptor`.
    pub async fn start(acceptor: TlsAcceptor) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    loop {
                        let mut head = Vec::new();
                        let mut chunk = [0_u8; 512];
                        while !head.ends_with(b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => head.extend_from_slice(&chunk[..read]),
                            }
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        if stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            port,
            requests,
            task,
        }
    }

    /// How many requests the origin has read, over every connection.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for PooledOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
