//! What a relay admits, what it turns away, and what each connection that it admitted sent.
//!
//! A [`LocalRelay`](super::LocalRelay) has one. It admits every endpoint unless a test refuses one,
//! and it keeps, for each endpoint, how many connections it admitted and refused and what each
//! admitted connection's upgrade request carried, so a test can tell that an endpoint reached the
//! relay, how often, and with what.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use iroh::EndpointId;

/// What one admitted connection's upgrade request carried.
#[derive(Clone, Debug)]
pub struct Request {
    /// The names of the request's headers, in lower case.
    pub headers: Vec<String>,
    /// The bearer token the request carried, in a header or in the `token` query parameter.
    pub token: Option<String>,
    /// The request's URI.
    pub uri: String,
}

#[derive(Debug, Default)]
struct Book {
    refused: BTreeSet<EndpointId>,
    refusals: BTreeMap<EndpointId, usize>,
    admitted: BTreeMap<EndpointId, Vec<Request>>,
}

/// The relay's admission check and what it has seen.
#[derive(Clone, Debug, Default)]
pub struct Gate(Arc<Mutex<Book>>);

impl Gate {
    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Turns `endpoint` away from now on.
    pub fn refuse(&self, endpoint: EndpointId) {
        self.book().refused.insert(endpoint);
    }

    /// How many connections of `endpoint` the relay admitted.
    pub fn admissions(&self, endpoint: &EndpointId) -> usize {
        self.book().admitted.get(endpoint).map_or(0, Vec::len)
    }

    /// How many connections of `endpoint` the relay turned away.
    pub fn refusals(&self, endpoint: &EndpointId) -> usize {
        self.book().refusals.get(endpoint).copied().unwrap_or(0)
    }

    /// What each admitted connection of `endpoint` sent.
    pub fn requests(&self, endpoint: &EndpointId) -> Vec<Request> {
        self.book()
            .admitted
            .get(endpoint)
            .cloned()
            .unwrap_or_default()
    }
}

impl iroh_relay::server::AccessControl for Gate {
    async fn on_connect(
        &self,
        request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        let endpoint = request.endpoint_id();
        let mut book = self.book();
        if book.refused.contains(&endpoint) {
            *book.refusals.entry(endpoint).or_default() += 1;
            return iroh_relay::server::Access::Deny {
                reason: Some("refused by the test's gate".to_owned()),
            };
        }
        book.admitted.entry(endpoint).or_default().push(Request {
            headers: request
                .headers()
                .keys()
                .map(|name| name.as_str().to_ascii_lowercase())
                .collect(),
            token: request.auth_token(),
            uri: request.uri().to_string(),
        });
        iroh_relay::server::Access::Allow
    }
}
