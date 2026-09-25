//! Something on loopback between an endpoint and its relay, that the relay's URL names.
//!
//! A front passes each connection to a [`LocalRelay`](super::LocalRelay) and counts them, so a
//! test can tell whether an endpoint reached the relay at all: the relay's own address is not the
//! one the endpoint was given, so nothing reaches the relay except through the front.
//!
//! It runs on a runtime of its own, as the proxy does, and dropping it closes its port.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::{TcpListener, TcpStream};

use super::LocalRelay;
use super::proxy::authority;

/// A front for one relay.
pub struct RelayFront {
    /// The relay URL an endpoint reaches the relay through this front by.
    pub url: iroh::RelayUrl,
    /// What an endpoint trusts to reach the relay through this front.
    pub ca_roots: Vec<Vec<u8>>,
    accepted: Arc<AtomicUsize>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl RelayFront {
    /// Starts a front that passes every connection to `relay` unchanged, so the relay's own TLS
    /// reaches the endpoint and the relay's own anchor is what the endpoint trusts.
    pub fn passing(relay: &LocalRelay) -> Self {
        let upstream = authority(&relay.url);
        Self::start(relay.ca_roots.clone(), move |client| {
            let upstream = upstream.clone();
            async move {
                let Ok(mut relay) = TcpStream::connect(&upstream).await else {
                    return;
                };
                let mut client = client;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
            }
        })
    }

    fn start<F, S>(ca_roots: Vec<Vec<u8>>, serve: S) -> Self
    where
        S: Fn(TcpStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a front listener");
        listener
            .set_nonblocking(true)
            .expect("a listener the runtime can drive");
        let addr: SocketAddr = listener.local_addr().expect("a bound address");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the front's runtime");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&accepted);
        runtime.spawn(async move {
            let listener = TcpListener::from_std(listener).expect("the front listener");
            while let Ok((stream, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(stream));
            }
        });
        Self {
            url: format!("https://{addr}").parse().expect("a relay URL"),
            ca_roots,
            accepted,
            runtime: Some(runtime),
        }
    }

    /// How many connections reached the front.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for RelayFront {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
