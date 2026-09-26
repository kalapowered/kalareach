//! The transport a leg's sync clients share: every request written down before it leaves, and the
//! answer to one exchange held on its way back until the leg lets it go.
//!
//! Section 24's hardest case is work that has already reached a service when privacy mode is
//! enabled: the service has committed it, and its answer is still on the way. A leg makes that case
//! happen on purpose rather than by timing. It asks [`Held`] to hold the next exchange of one
//! object, starts the publication, and waits until [`Holding::answered`] says the service has
//! answered. From then until [`Holding::release`], the write is on the service and its answer is
//! nowhere the client can see, which is exactly a request in flight. Nothing here waits on a clock:
//! the only bound is how long a service may take to answer at all, and running out of it is a
//! failure rather than a way to wait.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::ServiceFuture;
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer};
use kr_protocol::scalars::Uuid;
use tokio::sync::oneshot;

/// How long a held exchange may take to be answered before a leg calls the service unanswered.
pub const ANSWER_BOUND: Duration = Duration::from_secs(60);

/// Every collection and request identity a leg's requests reached.
///
/// Written from the request itself before it leaves, so a request whose answer never arrives is
/// written down all the same, and a leg that forgot where it sent something still gives it back.
/// A collection is written as the service names it, which is the identity of the object it holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reached {
    /// Every collection a request named.
    pub collections: BTreeSet<String>,
    /// Every identity an exchange presented, with its collection and the earliest and latest
    /// instant any attempt under it was signed at.
    pub identities: BTreeMap<String, (String, u64, u64)>,
}

impl Reached {
    /// Writes down where one signed request is going, and says which collection it exchanges in
    /// when it is an exchange.
    fn note(&mut self, request: &[u8]) -> Option<String> {
        let request = serde_json::from_slice::<serde_json::Value>(request).ok()?;
        let (member, asked) = request["body"]
            .as_object()
            .and_then(|body| body.iter().next())?;
        let collection = asked["collection_id"].as_str()?.to_owned();
        self.collections.insert(collection.clone());
        if member != "exchange" {
            return None;
        }
        let signed_at = request["signature"]["payload"]["signed_at_ms"]
            .as_str()
            .and_then(|instant| instant.parse::<u64>().ok());
        if let (Some(identity), Some(signed_at)) = (asked["request_id"].as_str(), signed_at) {
            self.identities
                .entry(identity.to_owned())
                .and_modify(|(_, first, last)| {
                    *first = (*first).min(signed_at);
                    *last = (*last).max(signed_at);
                })
                .or_insert((collection.clone(), signed_at, signed_at));
        }
        Some(collection)
    }
}

/// One hold a leg asked for and no exchange has met yet.
struct Pending {
    collection: String,
    answered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// The deployment's transport, writing down every request and holding the answers it was asked to.
pub struct Held {
    inner: Arc<dyn ServiceHttp>,
    reached: Mutex<Reached>,
    sent: AtomicUsize,
    pending: Mutex<Vec<Pending>>,
}

impl fmt::Debug for Held {
    /// How many requests have left. Never one of them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Held")
            .field("sent", &self.sent.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Held {
    /// A transport over `inner` that holds nothing until asked.
    #[must_use]
    pub fn over(inner: Arc<dyn ServiceHttp>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            reached: Mutex::new(Reached::default()),
            sent: AtomicUsize::new(0),
            pending: Mutex::new(Vec::new()),
        })
    }

    /// Holds the answer to the next exchange of `object`, until the handle releases it.
    ///
    /// The service names an object's collection by the object's own identity, a setting's or a
    /// draft's, which is what the exchange carries. The request goes to the service as it would, and
    /// the service commits it and answers. The answer then waits here. A handle dropped without being
    /// released lets it go, so a leg that failed part way leaves no request waiting for ever.
    #[must_use]
    pub fn hold_the_next_exchange(&self, object: Uuid) -> Holding {
        let collection = object.to_string();
        let (answered_sender, answered) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        self.pending.lock().expect("the holds").push(Pending {
            collection: collection.clone(),
            answered: answered_sender,
            release: release_receiver,
        });
        Holding {
            collection,
            answered,
            release,
        }
    }

    /// How many requests have left through this transport so far.
    #[must_use]
    pub fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    /// Everything the leg's requests reached so far.
    #[must_use]
    pub fn reached(&self) -> Reached {
        self.reached.lock().expect("the record").clone()
    }

    /// The hold an exchange in `collection` meets as it leaves, when a leg asked for one.
    ///
    /// Taken when the request leaves rather than when its answer arrives, so the hold goes to the
    /// exchange that was next, not to whichever answer came back first. A hold whose handle was
    /// dropped before its exchange left is gone rather than waiting to catch a later one.
    fn take_hold(&self, collection: &str) -> Option<Pending> {
        let mut pending = self.pending.lock().expect("the holds");
        pending.retain(|hold| !hold.answered.is_closed());
        let index = pending
            .iter()
            .position(|hold| hold.collection == collection)?;
        Some(pending.remove(index))
    }
}

impl ServiceHttp for Held {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            // Before the request leaves, so one whose answer never comes back is written down, and
            // so the hold this exchange meets is decided in the order the exchanges left.
            let exchange = self.reached.lock().expect("the record").note(body);
            let hold = exchange.and_then(|collection| self.take_hold(&collection));
            self.sent.fetch_add(1, Ordering::SeqCst);
            let answer = self.inner.post_json(url, body, headers).await;
            if let Some(hold) = hold {
                // The service has answered. The leg hears that, and the answer goes no further
                // until the leg says so or drops its handle.
                let _ = hold.answered.send(());
                let _ = hold.release.await;
            }
            answer
        })
    }
}

/// A leg's hold on one exchange's answer.
#[derive(Debug)]
pub struct Holding {
    collection: String,
    answered: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
}

impl Holding {
    /// Waits until the service has answered the held exchange, whose answer is now held here.
    ///
    /// # Panics
    ///
    /// Panics when no exchange in the collection was answered within [`ANSWER_BOUND`], which is a
    /// service that did not answer, or a leg that never sent what it meant to hold.
    pub async fn answered(&mut self) {
        match tokio::time::timeout(ANSWER_BOUND, &mut self.answered).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("the transport dropped the hold on {}", self.collection),
            Err(_) => panic!(
                "no exchange of {} was answered within {ANSWER_BOUND:?}",
                self.collection
            ),
        }
    }

    /// Lets the held answer go on to the client that is waiting for it.
    pub fn release(self) {
        let _ = self.release.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(collection: &str, identity: &str, signed_at: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "body": { "exchange": { "collection_id": collection, "request_id": identity } },
            "signature": { "payload": { "signed_at_ms": signed_at.to_string() } },
        }))
        .expect("a request")
    }

    #[test]
    fn an_exchange_is_written_down_with_the_span_its_attempts_were_signed_in() {
        let mut reached = Reached::default();
        assert_eq!(
            reached.note(&exchange("settings/a", "one", 20)).as_deref(),
            Some("settings/a")
        );
        assert_eq!(
            reached.note(&exchange("settings/a", "one", 10)).as_deref(),
            Some("settings/a")
        );
        assert_eq!(
            reached.identities.get("one"),
            Some(&("settings/a".to_owned(), 10, 20))
        );
    }

    /// A transport that answers every request at once with an empty success.
    #[derive(Debug)]
    struct Answers;

    impl ServiceHttp for Answers {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            Box::pin(async {
                Ok(ServiceHttpAnswer {
                    status: 200,
                    body: b"{}".to_vec(),
                })
            })
        }
    }

    #[tokio::test]
    async fn a_hold_meets_the_next_exchange_to_leave_and_a_dropped_one_meets_none() {
        let object = Uuid::from_bytes([7; 16]);
        let held = Held::over(Arc::new(Answers));
        let request = exchange(&object.to_string(), "one", 1);

        // A handle dropped before its exchange left holds nothing, and the hold after it meets the
        // next exchange rather than being passed over.
        drop(held.hold_the_next_exchange(object));
        let mut holding = held.hold_the_next_exchange(object);
        let sending = tokio::spawn({
            let held = Arc::clone(&held);
            let request = request.clone();
            async move { held.post_json("http://127.0.0.1:1/", &request, &[]).await }
        });
        holding.answered().await;
        assert!(
            !sending.is_finished(),
            "the answer waits until it is released"
        );
        holding.release();
        assert_eq!(
            sending.await.expect("the task").expect("an answer").status,
            200
        );

        // With no hold left, the next exchange passes straight through.
        assert!(
            held.post_json("http://127.0.0.1:1/", &request, &[])
                .await
                .is_ok()
        );
        assert_eq!(held.sent(), 2);
    }

    #[test]
    fn a_request_that_is_not_an_exchange_names_its_collection_and_holds_nothing() {
        let mut reached = Reached::default();
        let fetch = serde_json::to_vec(&serde_json::json!({
            "body": { "fetch": { "collection_id": "drafts/b" } },
            "signature": { "payload": { "signed_at_ms": "5" } },
        }))
        .expect("a request");
        assert_eq!(reached.note(&fetch), None);
        assert!(reached.collections.contains("drafts/b"));
        assert!(reached.identities.is_empty());
        assert_eq!(reached.note(b"not a request"), None);
    }
}
