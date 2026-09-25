//! Pkarr publication and resolution over an HTTP client this crate builds.
//!
//! A Pkarr server keeps each endpoint's signed discovery record: an endpoint publishes it with
//! `PUT <server>/<key>` and a peer reads it with `GET <server>/<key>`, the key being the endpoint
//! identity in z-base-32. iroh has a publisher and a resolver for this, but each builds its own
//! HTTP client with no way to name a proxy, and that client follows `HTTP_PROXY`, `HTTPS_PROXY` and
//! `ALL_PROXY` whatever the endpoint selects. Section 26 lets no inherited variable steer a
//! provider's traffic, so the endpoint uses these two instead.
//!
//! They speak the same protocol on the same republish rules. The record is signed and verified by
//! the same record code iroh uses, names are resolved by the endpoint's own DNS resolver and
//! certificates are checked against what the endpoint trusts. What differs is the client's proxy:
//! the one the endpoint's configuration selects, or none, and never one from the environment.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::address_lookup::{
    AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData,
    EndpointInfo, Error as LookupError, Item, ParseError,
};
use iroh::dns::{DNS_TIMEOUT, DnsResolver};
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_dns::EncodingError;
use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{ProxyUrl, Url};

/// How an answer from a Pkarr server is labelled among the endpoint's lookup services, which is how
/// iroh's own resolver labels it.
const PROVENANCE: &str = "pkarr";

/// When a name that has had no answer is asked of the DNS resolver's servers again, in
/// milliseconds after the first question: the delays iroh's own lookups use.
const DNS_STAGGERING_MS: &[u64] = &[200, 300, 600, 1000, 2000, 3000];

/// Publishes this endpoint's signed record to one Pkarr server.
///
/// A changed record is published at once, and an unchanged one again every
/// `republish_interval`. A publication that failed is tried again after one second, then two, and
/// so on, until one succeeds.
#[derive(Debug)]
pub(crate) struct Publisher {
    /// The Pkarr server.
    pub(crate) server: Url,
    /// The time to live the record carries, in seconds.
    pub(crate) ttl_seconds: u32,
    /// How often an unchanged record is published again.
    pub(crate) republish_interval: Duration,
    /// What goes into the public record.
    pub(crate) filter: AddrFilter,
    /// The proxy the requests go through, or none.
    pub(crate) proxy: Option<ProxyUrl>,
}

impl AddressLookupBuilder for Publisher {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        let client = http_client(endpoint, self.proxy.as_ref())?;
        let (records, current) = watch::channel(None);
        let publishing = Publishing {
            client,
            server: self.server.clone(),
            secret_key: endpoint.secret_key().clone(),
            ttl_seconds: self.ttl_seconds,
            republish_interval: self.republish_interval,
        };
        Ok(PublishedRecord {
            endpoint_id: endpoint.id(),
            server: self.server,
            filter: self.filter,
            records,
            _publishing: StopOnDrop(tokio::spawn(publishing.run(current))),
        })
    }
}

/// The record a [`Publisher`] keeps published, as the endpoint's lookup services hold it.
///
/// Dropping it stops the publication.
struct PublishedRecord {
    endpoint_id: EndpointId,
    server: Url,
    filter: AddrFilter,
    records: watch::Sender<Option<EndpointInfo>>,
    _publishing: StopOnDrop,
}

impl std::fmt::Debug for PublishedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkarrPublisher")
            .field("server", &self.server.as_str())
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl AddressLookup for PublishedRecord {
    fn publish(&self, data: &EndpointData) {
        let info = EndpointInfo::from_parts(
            self.endpoint_id,
            data.apply_filter(&self.filter).into_owned(),
        );
        // Only a record that differs from the one held wakes the publisher: an address change the
        // filter removes is not a change to the public record.
        self.records.send_if_modified(|held| {
            if held.as_ref() == Some(&info) {
                false
            } else {
                *held = Some(info);
                true
            }
        });
    }
}

/// What the publishing task holds.
struct Publishing {
    client: reqwest::Client,
    server: Url,
    secret_key: SecretKey,
    ttl_seconds: u32,
    republish_interval: Duration,
}

impl Publishing {
    /// Publishes the record whenever it changes, again at the republish interval, and again after a
    /// failure, until the record's holder is dropped.
    async fn run(self, mut records: watch::Receiver<Option<EndpointInfo>>) {
        let mut failures: u64 = 0;
        let next = tokio::time::sleep(Duration::MAX);
        tokio::pin!(next);
        loop {
            let record = records.borrow_and_update().clone();
            if let Some(record) = record {
                match self.publish(&record).await {
                    Ok(()) => {
                        failures = 0;
                        next.as_mut()
                            .reset(tokio::time::Instant::now() + self.republish_interval);
                    }
                    Err(error) => {
                        failures += 1;
                        let retry = Duration::from_secs(failures);
                        tracing::warn!(
                            server = %self.server,
                            %error,
                            failures,
                            ?retry,
                            "the discovery record could not be published"
                        );
                        next.as_mut().reset(tokio::time::Instant::now() + retry);
                    }
                }
            }
            tokio::select! {
                changed = records.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = &mut next => {}
            }
        }
    }

    /// Signs `record` and puts it on the server.
    async fn publish(&self, record: &EndpointInfo) -> Result<(), PkarrError> {
        let packet = record
            .to_pkarr_signed_packet(&self.secret_key, self.ttl_seconds)
            .map_err(PkarrError::Signing)?;
        let response = self
            .client
            .put(record_url(&self.server, &packet.public_key().to_z32())?)
            .body(packet.to_relay_payload())
            .send()
            .await
            .map_err(PkarrError::Request)?;
        if !response.status().is_success() {
            return Err(PkarrError::Status(response.status().as_u16()));
        }
        Ok(())
    }
}

/// Resolves other endpoints' signed records from one Pkarr server.
#[derive(Debug)]
pub(crate) struct Resolver {
    /// The Pkarr server.
    pub(crate) server: Url,
    /// The proxy the requests go through, or none.
    pub(crate) proxy: Option<ProxyUrl>,
}

impl AddressLookupBuilder for Resolver {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        Ok(Resolving {
            client: http_client(endpoint, self.proxy.as_ref())?,
            server: self.server,
        })
    }
}

/// A [`Resolver`], as the endpoint's lookup services hold it.
struct Resolving {
    client: reqwest::Client,
    server: Url,
}

impl std::fmt::Debug for Resolving {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkarrResolver")
            .field("server", &self.server.as_str())
            .finish_non_exhaustive()
    }
}

impl AddressLookup for Resolving {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<futures::stream::BoxStream<'static, Result<Item, LookupError>>> {
        let client = self.client.clone();
        let server = self.server.clone();
        let lookup = async move {
            let info = read_record(&client, &server, endpoint_id)
                .await
                .map_err(|error| LookupError::from_err(PROVENANCE, error))?;
            Ok(Item::new(info, PROVENANCE, None))
        };
        Some(Box::pin(futures::stream::once(lookup)))
    }
}

/// Reads `endpoint_id`'s record from `server` and verifies that the endpoint signed it.
async fn read_record(
    client: &reqwest::Client,
    server: &Url,
    endpoint_id: EndpointId,
) -> Result<EndpointInfo, PkarrError> {
    let response = client
        .get(record_url(server, &endpoint_id.to_z32())?)
        .send()
        .await
        .map_err(PkarrError::Request)?;
    if !response.status().is_success() {
        return Err(PkarrError::Status(response.status().as_u16()));
    }
    let payload = bounded_body(response).await?;
    let packet = SignedPacket::from_relay_payload(&endpoint_id, &payload)
        .map_err(PkarrError::Verification)?;
    EndpointInfo::from_pkarr_signed_packet(&packet).map_err(PkarrError::Content)
}

/// Reads a response's body, refusing one longer than any signed record can be.
///
/// The server's answer is read before it is verified, so it is bounded before it is read whole.
async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, PkarrError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(PkarrError::Request)? {
        if body.len() + chunk.len() > SignedPacket::MAX_BYTES {
            return Err(PkarrError::TooLong);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Returns where on `server` the record under `key` lives: the key appended as one more path
/// segment, as iroh's own clients address it.
fn record_url(server: &Url, key: &str) -> Result<Url, PkarrError> {
    let mut url = server.clone();
    url.path_segments_mut()
        .map_err(|()| PkarrError::Server(server.clone()))?
        .push(key);
    Ok(url)
}

/// Builds the HTTP client a Pkarr service uses: the endpoint's certificate trust and DNS
/// resolver, and the selected proxy or none.
///
/// Naming no proxy is what keeps the environment out. A client given neither a proxy nor
/// `no_proxy` reads `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` when it is built, and an explicit
/// proxy is used for every request, `NO_PROXY` or not.
fn http_client(
    endpoint: &Endpoint,
    proxy: Option<&ProxyUrl>,
) -> Result<reqwest::Client, AddressLookupBuilderError> {
    let builder = reqwest::Client::builder()
        .tls_backend_preconfigured(endpoint.tls_config().clone())
        .dns_resolver(EndpointDns(endpoint.dns_resolver()?.clone()));
    let builder = match proxy {
        Some(proxy) => builder.proxy(
            reqwest::Proxy::all(proxy.as_url().clone())
                .map_err(|error| AddressLookupBuilderError::from_err(PROVENANCE, error))?,
        ),
        None => builder.no_proxy(),
    };
    builder
        .build()
        .map_err(|error| AddressLookupBuilderError::from_err(PROVENANCE, error))
}

/// The endpoint's own DNS resolver, as the HTTP client asks it for a server's addresses.
struct EndpointDns(DnsResolver);

impl reqwest::dns::Resolve for EndpointDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.0.clone();
        let name = name.as_str().to_owned();
        Box::pin(async move {
            // Collected here, because the answer borrows the resolver this future owns.
            let addresses: Vec<SocketAddr> = resolver
                .lookup_ipv4_ipv6_staggered(name, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
                .map(|address| SocketAddr::new(address, 0))
                .collect();
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Why one publication or one lookup failed.
#[derive(Debug, thiserror::Error)]
enum PkarrError {
    /// The server's URL cannot take another path segment.
    #[error("the Pkarr server URL {0} cannot name a record")]
    Server(Url),
    /// The request did not complete.
    #[error("the request to the Pkarr server failed: {0}")]
    Request(reqwest::Error),
    /// The server answered with something other than success.
    #[error("the Pkarr server answered with HTTP status {0}")]
    Status(u16),
    /// The record could not be signed.
    #[error("the discovery record could not be signed: {0}")]
    Signing(EncodingError),
    /// The server returned more than any signed record can be.
    #[error("the Pkarr server returned more than a signed record can hold")]
    TooLong,
    /// The server returned something that is not a record the endpoint signed.
    #[error("the record the Pkarr server returned is not one the endpoint it names signed: {0}")]
    Verification(SignedPacketVerifyError),
    /// The record is signed but does not describe an endpoint.
    #[error("the record the Pkarr server returned does not describe an endpoint: {0}")]
    Content(ParseError),
}

/// A task that is stopped when its handle is dropped.
struct StopOnDrop(JoinHandle<()>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
