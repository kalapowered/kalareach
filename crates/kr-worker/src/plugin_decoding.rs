//! The decoder: how a request a component is trusted to decode gets to it, and what is done with
//! what it says.
//!
//! The gateway's reader and a channel's reader record a request, forward it, and queue it
//! ([`crate::broker::decoding`]) for the component of the binding that decodes it. This task takes
//! requests off that queue and asks the components, and it is the only place in the worker that
//! does. Nothing a reader holds is held by anything that waits for a component, so the terminal's
//! own answer to a request never waits for its meaning.
//!
//! # How many at once
//!
//! At most [`MAX_DECODES_AT_ONCE`], and at most one for a binding, since a binding's component runs
//! one call at a time and more would only hold places of the plugin runtime's connection. The task
//! takes a place before it takes a job, so no set of tasks waits for places. The connection's own
//! bound is what is hard: a request the runtime refuses as busy is a request that is not decoded.
//!
//! # What waits and what is given up
//!
//! A request waits while its component is being registered (a first registration can include a
//! cold compile, and a session's first approvals arrive in that time) and while the task has not yet
//! read where its binding stands. It is given up, counted in the binding's report and left opaque
//! for the terminal to answer, when the binding is gone or disabled or its component is
//! unavailable, and when the binding no longer holds the grant and trust to decode it at the moment
//! its component is to be asked. It is not decoded later if the component registers later.
//!
//! # What is made of the answer
//!
//! Nothing is believed. The proposal is checked against the request the broker holds
//! ([`crate::broker::decoding::project`]) and the broker's own interpretation checks it again under
//! its lock ([`crate::broker::Broker::interpret_decoded`]). What a person is told when a request does
//! not become an approval is a kind and a count, never a word the component chose.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};

use kr_plugin_service::error::ServiceError;
use kr_protocol::ids::BrokerBindingId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::broker::Broker;
use crate::broker::decoding::{
    ComponentDecoded, DecodeJob, DecodeQueue, NotDecoded, Readiness, Verdict,
};
use crate::plugin_observation::{CALL_WAIT, service_id};

/// How many components are asked to decode at once, all bindings together.
pub const MAX_DECODES_AT_ONCE: usize = 4;

/// Runs for as long as the broker lives.
pub async fn decoder(broker: Weak<Broker>) {
    let Some(queue) = broker.upgrade().map(|broker| broker.decode_queue()) else {
        return;
    };
    let places = Arc::new(Semaphore::new(MAX_DECODES_AT_ONCE));
    let busy: Arc<Mutex<BTreeSet<BrokerBindingId>>> = Arc::default();
    loop {
        let Ok(place) = Arc::clone(&places).acquire_owned().await else {
            return;
        };
        let job = loop {
            #[cfg(feature = "testing")]
            queue.pause().await;
            let Some(strong) = broker.upgrade() else {
                return;
            };
            let readiness = strong.decode_readiness(&queue.bindings());
            let in_flight = busy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let (job, dropped) = queue.take(|job| judge(&readiness, &in_flight, job));
            for (binding, why) in dropped {
                strong.note_not_decoded(binding, why);
            }
            if let Some(job) = job {
                break job;
            }
            drop(strong);
            queue.wait().await;
        };
        busy.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(job.binding_id);
        let freed = Freed {
            binding: job.binding_id,
            busy: Arc::clone(&busy),
            queue: Arc::clone(&queue),
            _place: place,
        };
        tokio::spawn(decode(Weak::clone(&broker), job, freed));
    }
}

/// What the task does with one waiting job, given where each binding's component stands.
fn judge(
    readiness: &BTreeMap<BrokerBindingId, Readiness>,
    in_flight: &BTreeSet<BrokerBindingId>,
    job: &DecodeJob,
) -> Verdict {
    match readiness.get(&job.binding_id) {
        Some(Readiness::Ready) if in_flight.contains(&job.binding_id) => Verdict::Wait,
        Some(Readiness::Ready) => Verdict::Take,
        Some(Readiness::Waiting) => Verdict::Wait,
        Some(Readiness::Never) => Verdict::Drop(NotDecoded::NotRegistered),
        // Queued after the bindings were read: the push that queued it left a wake, and it is
        // judged with the next reading.
        None => Verdict::Wait,
    }
}

/// What one decode holds while it runs, and gives back when it ends however it ends.
struct Freed {
    binding: BrokerBindingId,
    busy: Arc<Mutex<BTreeSet<BrokerBindingId>>>,
    queue: Arc<DecodeQueue>,
    _place: OwnedSemaphorePermit,
}

impl Drop for Freed {
    fn drop(&mut self) {
        self.busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.binding);
        // The binding may be asked again, and the place is free.
        self.queue.wake();
    }
}

/// Asks one component to decode one request, and records what came of it.
async fn decode(broker: Weak<Broker>, job: DecodeJob, _freed: Freed) {
    let Some(strong) = broker.upgrade() else {
        return;
    };
    if let Err(Some(why)) = attempt(&strong, &job).await {
        strong.note_not_decoded(job.binding_id, why);
    }
}

/// Asks the component and turns its answer into an approval, or says why not. `None` is a request
/// that is no longer one to decode, which is nothing to tell anybody.
async fn attempt(broker: &Broker, job: &DecodeJob) -> Result<(), Option<NotDecoded>> {
    let Some(client) = broker.component_calls().client() else {
        return Err(Some(NotDecoded::NotConnected));
    };
    let event = broker.decode_event(job)?;
    // Marked before the hand-over, not after the answer: a call that is written and then times out
    // may still have been read, and a request made in privacy mode stays made in it.
    broker.observation().expose(job.binding_id, job.private);
    let called = client
        .decode(service_id(job.binding_id), &event, CALL_WAIT)
        .await
        .map_err(|error| {
            Some(match error {
                ServiceError::Disabled { .. } => NotDecoded::NotRegistered,
                _ => NotDecoded::Failed,
            })
        })?;
    if called.fault.is_some() {
        return Err(Some(NotDecoded::Declined));
    }
    let Some(decoded) = called.decoded else {
        return Err(Some(NotDecoded::NoAnswer));
    };
    let decoded = ComponentDecoded {
        request_id: decoded.request_id,
        summary: decoded.summary,
        decisions: decoded.decisions,
    };
    broker
        .interpret_decoded(job, &decoded, kr_ipc::now_ms())
        .map(|_approval| ())
        .map_err(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    /// KR-REQ-11.26: a job queued after the task read where the bindings stand is left for the next
    /// reading, not dropped as one whose component is gone. A burst of approvals queues requests
    /// while the task reads the broker, and the reading cannot be held open by a running worker.
    #[test]
    fn kr_req_11_26_a_job_queued_after_the_readiness_was_read_waits_for_the_next_reading() {
        use kr_protocol::ids::{PendingResourceId, SourceEventHandle, UpstreamMethod};
        let binding = BrokerBindingId::new(Uuid::from_bytes([1; 16]));
        let job = DecodeJob {
            resource_id: PendingResourceId::new(Uuid::from_bytes([2; 16])),
            binding_id: binding,
            method: UpstreamMethod::new("session/request_permission").expect("a method"),
            upstream_id: "1".to_owned(),
            handle: SourceEventHandle::new("src-1").expect("a handle"),
            table: Vec::new(),
            private: false,
        };
        let nothing = BTreeMap::new();
        assert_eq!(judge(&nothing, &BTreeSet::new(), &job), Verdict::Wait);
        let gone = BTreeMap::from([(binding, Readiness::Never)]);
        assert_eq!(
            judge(&gone, &BTreeSet::new(), &job),
            Verdict::Drop(NotDecoded::NotRegistered)
        );
    }
}
