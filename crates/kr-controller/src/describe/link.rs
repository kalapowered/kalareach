//! The daemon's reading of each session's description facts over its worker's descriptions
//! connection.
//!
//! One task per session opens the connection (declared for descriptions, verified, speaking for
//! this daemon's generation), then keeps one request held at the worker: it asks for the facts past
//! the revision it has read, and for as long as the worker may hold the request, and hands each page
//! that comes back to the host. A request names the privacy generation the worker last said it
//! holds, so the worker answers at once when it moved and the daemon never spins on a generation it
//! has not yet been told. Nothing here decides anything about privacy mode: the host applies a page
//! under its admission or drops it.
//!
//! A connection that fails is made again after a pause that doubles to five minutes, which is also
//! what a worker of an older build, one that does not know the role, gets: it refuses the
//! connection and is asked again later, quietly, until it is replaced.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use kr_protocol::describe::{DescriptionFactsRequest, MAX_DESCRIPTION_FACTS_WAIT_MS};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::scalars::{Nullable, U64};

use crate::directory::KnownWorker;
use crate::service::Controller;

use super::host::DescribeHost;

/// How long one connection attempt may take.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

/// The pause after a connection fails the first time, which doubles.
const FIRST_RELINK: Duration = Duration::from_millis(500);

/// The longest pause between attempts.
const MAX_RELINK: Duration = Duration::from_secs(5 * 60);

/// How long the daemon asks a worker to hold a request.
const HOLD_MS: u64 = MAX_DESCRIPTION_FACTS_WAIT_MS;

/// The tasks that read the sessions' facts, one for each.
#[derive(Debug, Default)]
pub(crate) struct Links {
    tasks: Mutex<BTreeMap<SessionId, tokio::task::JoinHandle<()>>>,
}

impl Links {
    /// Starts reading one session's facts at the worker given. A session already being read is read
    /// from this worker from now on: the task that read the one before it stops.
    pub(crate) fn watch(
        &self,
        controller: Weak<Controller>,
        host: &Arc<DescribeHost>,
        worker: KnownWorker,
    ) {
        let session_id = worker.descriptor.session_id;
        let host = Arc::downgrade(host);
        let task = tokio::spawn(async move {
            let mut pause = FIRST_RELINK;
            loop {
                // A host that is gone or has stopped has no use for a page: the task ends.
                if !host.upgrade().is_some_and(|held| held.runs()) {
                    return;
                }
                let connected = tokio::time::timeout(
                    CONNECT_WAIT,
                    Controller::connect_role(
                        &controller,
                        &worker,
                        ControllerConnectionRole::Descriptions,
                    ),
                )
                .await;
                if let Ok(Ok(client)) = connected {
                    pause = FIRST_RELINK;
                    read(client, &host, session_id).await;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(MAX_RELINK);
            }
        });
        let replaced = self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id, task);
        if let Some(replaced) = replaced {
            replaced.abort();
        }
    }

    /// Stops reading one session's facts.
    pub(crate) fn stop(&self, session_id: SessionId) {
        let task = self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&session_id);
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl Drop for Links {
    fn drop(&mut self) {
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            task.abort();
        }
    }
}

/// Keeps one request held over an open connection until it fails, handing each page to the host.
async fn read(
    mut client: kr_ipc::client::LocalClient,
    host: &Weak<DescribeHost>,
    session_id: SessionId,
) {
    let mut after = 0_u64;
    let mut named: Option<u64> = None;
    let mut request = 0_u64;
    loop {
        request += 1;
        let asked = DescriptionFactsRequest {
            request_id: RequestId::new(request),
            after: U64::new(after),
            wait_ms: U64::new(HOLD_MS),
            generation: Nullable(named.map(U64::new)),
        };
        if client
            .writer()
            .write_message(&ControlFrame::DescriptionFacts(asked))
            .await
            .is_err()
        {
            return;
        }
        let page = loop {
            match client.recv().await {
                Ok(ControlFrame::DescriptionFactsPage(page))
                    if page.request_id == RequestId::new(request) =>
                {
                    break page;
                }
                Ok(ControlFrame::Response(_)) | Err(_) => return,
                Ok(_) => {}
            }
        };
        named = named.max(page.privacy_generation.0.map(U64::get));
        if let Some(facts) = &page.facts.0 {
            after = after.max(facts.revision.get());
        }
        // Upgraded only to hand the page over, and never held across a wait: a host that is gone
        // or has stopped ends this connection's reading.
        let Some(host) = host.upgrade().filter(|host| host.runs()) else {
            return;
        };
        host.page(session_id, page);
    }
}
