//! What sends the repository client's requests: the host's egress sees each try, and a request it
//! refuses is not tried again.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt;
use futures::future::BoxFuture;
use kr_plugin_catalogue::transport::{DirectEgress, Egress, EgressError, RepositoryTransport};
use tough::Transport;

/// An egress that counts its calls and either refuses each or sends it as the client would.
#[derive(Debug)]
struct Counting {
    calls: Arc<AtomicUsize>,
    refuse: bool,
}

impl Egress for Counting {
    fn execute<'a>(
        &'a self,
        client: &'a reqwest::Client,
        request: reqwest::Request,
    ) -> BoxFuture<'a, Result<reqwest::Response, EgressError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.refuse {
            return Box::pin(async {
                Err(EgressError::Refused("the host sends nothing".to_owned()))
            });
        }
        DirectEgress.execute(client, request)
    }
}

/// What one fetch of an address nothing listens at came to: how many times the egress was called,
/// and the failure that came through the stream.
async fn fetch(refuse: bool) -> (usize, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = RepositoryTransport::over(
        reqwest::Client::builder().no_proxy(),
        Arc::new(Counting {
            calls: Arc::clone(&calls),
            refuse,
        }),
    );
    let url = "http://127.0.0.1:1/root.json".parse().expect("an address");
    let mut stream = transport.fetch(url).await.expect("a stream");
    let failure = stream
        .next()
        .await
        .expect("an item")
        .expect_err("the fetch fails")
        .to_string();
    (calls.load(Ordering::SeqCst), failure)
}

/// A request that the egress refuses is sent once and never tried again, and a request that failed
/// to send is tried as many times as before, each through the egress.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_try_goes_through_the_egress_and_a_refusal_is_not_tried_again() {
    let (calls, failure) = fetch(true).await;
    assert_eq!(calls, 1, "a refusal is final");
    assert!(failure.contains("the host sends nothing"), "{failure}");

    let (calls, _) = fetch(false).await;
    assert_eq!(calls, 4, "a connection that failed is tried four times");
}
