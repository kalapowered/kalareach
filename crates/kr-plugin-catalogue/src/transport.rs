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

use std::time::Duration;

use futures::TryStreamExt;
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

/// Reads a repository from a local directory, or fetches it with the client its host built.
#[derive(Clone, Debug)]
pub struct RepositoryTransport {
    /// The client that fetches `http` and `https` addresses, or why this host has none.
    client: Result<reqwest::Client, String>,
}

impl RepositoryTransport {
    /// Reads `file` URLs from disk, and fetches `http` and `https` ones with a client built from
    /// `builder`, which carries its host's trust and proxy. This adds the deadlines.
    #[must_use]
    pub fn over(builder: reqwest::ClientBuilder) -> Self {
        let client = builder
            .timeout(FETCH_DEADLINE)
            .connect_timeout(CONNECT_DEADLINE)
            .build()
            .map_err(|error| {
                format!("this host could not configure its repository client: {error}")
            });
        Self { client }
    }

    /// Reads `file` URLs from disk and fetches nothing: every `http` and `https` fetch fails with
    /// `reason`.
    #[must_use]
    pub fn local_only(reason: impl Into<String>) -> Self {
        Self {
            client: Err(reason.into()),
        }
    }
}

#[tough::async_trait]
impl Transport for RepositoryTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let opened = match url.scheme() {
            "file" => tough::FilesystemTransport.fetch(url).await,
            "http" | "https" => match &self.client {
                Ok(client) => answer(client, url).await,
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
async fn answer(client: &reqwest::Client, url: Url) -> Result<TransportStream, TransportError> {
    let mut wait = FIRST_WAIT;
    let mut tried = 1;
    loop {
        let failed = match client.get(url.clone()).send().await {
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
            Err(error) if error.is_timeout() || error.is_request() => error.to_string(),
            Err(error) => {
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
