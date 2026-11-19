//! How a repository's files reach this host.
//!
//! A repository is read from a local directory, by `file` URL, or fetched from its address over
//! HTTP. The client that fetches is built by the host, from the host's own trust and the proxy its
//! configuration selects, and handed in whole: nothing here reads a proxy or a certificate store
//! from the environment, and nothing here decides whom to trust. What this module decides is what
//! one fetch is. It is one `GET`. An answer of 403, 404 or 410 means the file is not there, which
//! is how a client tells the newest signed root it can find from one that does not exist. A request
//! that failed before any byte of its answer arrived (the connection, a deadline, or a 5xx from the
//! service) is made again a few times, a little later each time. A fetch whose answer stops part way
//! fails, and the next synchronisation fetches it again from the start.
//!
//! A fetch always answers with a stream, and every outcome arrives through it, the file's absence
//! included, as it does from the update client's own HTTP transport. The update client reads an
//! error from the fetch itself as a file that is not there, and it looks for the next signed root
//! by asking for it: a service that failed to answer that request, or a file this host may not
//! read, must fail the synchronisation, not end the search for a newer root as though there were
//! none. Only a stream that ends with the file's absence ends that search.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::TryStreamExt;
use futures::future::BoxFuture;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

/// How long one fetch may take, from the request to the last byte of its answer.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(30);

/// How long a connection may take to establish.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// How many times a fetch is tried before it fails.
const TRIES: u32 = 4;

/// The wait before the second try. Each later wait is half as long again, up to [`LONGEST_WAIT`].
const FIRST_WAIT: Duration = Duration::from_millis(100);

/// The longest wait between two tries.
const LONGEST_WAIT: Duration = Duration::from_secs(1);

/// Why one request of the repository client did not give an answer.
#[derive(Debug)]
pub enum EgressError {
    /// The request was sent or tried, and the client failed: a deadline, a connection, or the
    /// answer's own fault. A deadline or a request that could not be sent is tried again.
    Send(reqwest::Error),
    /// The host did not send the request, for a reason of its own that another try does not change.
    /// It is never tried again.
    Refused(String),
}

/// What sends the repository client's requests, so that the host decides what may leave and how a
/// redirect is followed.
///
/// A host with nothing to hold back sends each request with the client's own policy
/// ([`DirectEgress`]); a host whose proxy holds a login sends it through its own redirect loop,
/// which stops a request the proxy's login does not allow.
pub trait Egress: Send + Sync + std::fmt::Debug {
    /// Sends `request` with `client`, the client built from the host's builder with this module's
    /// deadlines. A client the host built for a login follows no redirect by itself, and its
    /// egress follows them.
    fn execute<'a>(
        &'a self,
        client: &'a reqwest::Client,
        request: reqwest::Request,
    ) -> BoxFuture<'a, Result<reqwest::Response, EgressError>>;
}

/// Sends each request with the client's own redirect policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectEgress;

impl Egress for DirectEgress {
    fn execute<'a>(
        &'a self,
        client: &'a reqwest::Client,
        request: reqwest::Request,
    ) -> BoxFuture<'a, Result<reqwest::Response, EgressError>> {
        Box::pin(async move { client.execute(request).await.map_err(EgressError::Send) })
    }
}

/// Reads a repository from a local directory, or fetches it with the client its host built.
#[derive(Clone, Debug)]
pub struct RepositoryTransport {
    /// The client that fetches `http` and `https` addresses, or why this host has none.
    client: Result<reqwest::Client, String>,
    /// What sends its requests.
    egress: Arc<dyn Egress>,
}

impl RepositoryTransport {
    /// Reads `file` URLs from disk, and fetches `http` and `https` ones with a client built from
    /// `builder`, which carries its host's trust and proxy, sending each request through `egress`.
    /// This adds the deadlines.
    #[must_use]
    pub fn over(builder: reqwest::ClientBuilder, egress: Arc<dyn Egress>) -> Self {
        let client = builder
            .timeout(FETCH_DEADLINE)
            .connect_timeout(CONNECT_DEADLINE)
            .build()
            .map_err(|error| {
                format!("this host could not configure its repository client: {error}")
            });
        Self { client, egress }
    }

    /// Reads `file` URLs from disk and fetches nothing: every `http` and `https` fetch fails with
    /// `reason`.
    #[must_use]
    pub fn local_only(reason: impl Into<String>) -> Self {
        Self {
            client: Err(reason.into()),
            egress: Arc::new(DirectEgress),
        }
    }
}

#[tough::async_trait]
impl Transport for RepositoryTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let opened = match url.scheme() {
            "file" => tough::FilesystemTransport.fetch(url).await,
            "http" | "https" => match &self.client {
                Ok(client) => answer(client, self.egress.as_ref(), url).await,
                Err(reason) => Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url,
                    reason.clone(),
                )),
            },
            _ => Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url,
            )),
        };
        // Whatever opening the address came to, the update client reads it from the stream.
        Ok(opened.unwrap_or_else(|error| Box::pin(futures::stream::iter([Err(error)]))))
    }
}

/// Asks for one address: its answer as a stream, or why there is none.
async fn answer(
    client: &reqwest::Client,
    egress: &dyn Egress,
    url: Url,
) -> Result<TransportStream, TransportError> {
    let mut wait = FIRST_WAIT;
    let mut tried = 1;
    loop {
        let request = client.get(url.clone()).build().map_err(|error| {
            TransportError::new_with_cause(TransportErrorKind::Other, url.clone(), error)
        })?;
        let failed = match egress.execute(client, request).await {
            Ok(answer) if answer.status().is_success() => {
                let url = url.clone();
                return Ok(Box::pin(answer.bytes_stream().map_err(move |error| {
                    TransportError::new_with_cause(TransportErrorKind::Other, url.clone(), error)
                })));
            }
            Ok(answer) => {
                let status = answer.status();
                let why = format!("the repository answered {status}");
                if matches!(status.as_u16(), 403 | 404 | 410) {
                    return Err(TransportError::new_with_cause(
                        TransportErrorKind::FileNotFound,
                        url,
                        why,
                    ));
                }
                if !status.is_server_error() {
                    return Err(TransportError::new_with_cause(
                        TransportErrorKind::Other,
                        url,
                        why,
                    ));
                }
                why
            }
            // A deadline or a request that could not be sent: nothing of an answer arrived.
            Err(EgressError::Send(error)) if error.is_timeout() || error.is_request() => {
                error.to_string()
            }
            // The host did not send it, and another try would not change that.
            Err(EgressError::Refused(why)) => {
                return Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url,
                    why,
                ));
            }
            Err(EgressError::Send(error)) => {
                return Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url,
                    error,
                ));
            }
        };
        if tried >= TRIES {
            return Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url,
                failed,
            ));
        }
        tokio::time::sleep(wait).await;
        wait = wait.mul_f32(1.5).min(LONGEST_WAIT);
        tried += 1;
    }
}

/// Serves the generation compiled into the host at the addresses of the repository it was
/// published at.
///
/// The update client asks for each file by the address it would have on the network, and this
/// answers from the bundle's bytes: a metadata file at the enrolment's metadata address, a target
/// at its targets address. Nothing is fetched and no socket is opened. A file the bundle does not
/// carry is reported as absent in the stream, as the network transport reports a 404, so the search
/// for the next root ends where the bundle's roots do.
#[derive(Clone, Debug)]
pub struct EmbeddedTransport {
    files: Arc<BTreeMap<String, Vec<u8>>>,
    metadata_url: Url,
    targets_url: Url,
}

impl EmbeddedTransport {
    /// A transport over `bundle`, answering at `enrolment`'s own addresses.
    #[must_use]
    pub fn new(bundle: &crate::SeedBundle, enrolment: &crate::Enrolment) -> Self {
        Self {
            files: bundle.shared_files(),
            metadata_url: directory_of(&enrolment.metadata_url),
            targets_url: directory_of(&enrolment.targets_url),
        }
    }

    /// The bundle's path for an address, where the address is one of its own.
    fn path_of(&self, url: &Url) -> Option<String> {
        let text = url.as_str();
        let (area, rest) = match text.strip_prefix(self.metadata_url.as_str()) {
            Some(rest) => ("metadata", rest),
            None => ("targets", text.strip_prefix(self.targets_url.as_str())?),
        };
        // A name that leaves the directory it was asked under is not one of the bundle's.
        let decoded = percent_encoding::percent_decode_str(rest)
            .decode_utf8()
            .ok()?;
        if decoded.is_empty()
            || decoded.contains('?')
            || decoded
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return None;
        }
        Some(format!("{area}/{decoded}"))
    }
}

/// An address with a trailing slash, as a directory.
fn directory_of(url: &Url) -> Url {
    if url.as_str().ends_with('/') {
        url.clone()
    } else {
        Url::parse(&format!("{url}/")).unwrap_or_else(|_| url.clone())
    }
}

#[tough::async_trait]
impl Transport for EmbeddedTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let found = self
            .path_of(&url)
            .and_then(|path| self.files.get(&path))
            .cloned();
        Ok(match found {
            Some(bytes) => Box::pin(futures::stream::iter([Ok(bytes::Bytes::from(bytes))])),
            None => Box::pin(futures::stream::iter([Err(
                TransportError::new_with_cause(
                    TransportErrorKind::FileNotFound,
                    url,
                    "the bundle does not carry it",
                ),
            )])),
        })
    }
}
