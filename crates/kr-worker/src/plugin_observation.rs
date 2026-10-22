//! The pump: what the worker offers the components that observe, and how.
//!
//! The pseudo-terminal's read loop and the gateway's reader push what they have onto the broker's
//! observation lane and carry on (`crate::broker::observation`). This task takes entries off the
//! lane, in the order they were pushed, and makes the calls. It is the only place in the worker that
//! offers an observation to a component, and it is the only place that waits for one.
//!
//! # Which call, and why
//!
//! * An upstream frame goes by [`PluginClient::deliver`], awaited here and never in a producer. It is
//!   written in order and answered with what the component's queue did with it, so a request the
//!   upstream is waiting on is known to have been taken or known not to have been. Waiting is
//!   bounded: a runtime that does not answer is passed over for a while (and every frame passed over
//!   is a counted loss) rather than waited for once for each frame.
//! * A span of terminal output goes by [`PluginClient::offer`], which never waits: it joins a bounded
//!   queue and a task of the client's writes it. A full queue is an immediate refusal.
//!
//! # What a loss costs
//!
//! Whatever is not offered is a loss, and a loss is numbered. A binding that has lost something is
//! owed a snapshot, and gets one before it is offered anything else: the snapshot is requested for
//! the number of the loss current when it is asked for and discharges that number, so a loss that
//! arrives while it runs asks for another. What the component has missed is put in the binding's
//! component report, where a person reads it.
//!
//! Between the two sources there is no order, and none is claimed. Within a source the order is the
//! order produced, and a snapshot is asked for after a loss and before any later entry is handed to
//! the binding, once the client has written what it already held.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use kr_plugin_service::client::{Handoff, MAX_OFFERED_EVENT_BYTES, PluginClient};
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::vocabulary::{Admission, BindingId, ScopedSourceEvent, SourceProvenance};
use kr_protocol::ids::{BrokerBindingId, SourceEventHandle};
use tokio::time::Instant;

use crate::broker::Broker;
use crate::broker::component::ComponentNote;
use crate::broker::observation::{
    Audience, Entry, NativeFrame, ObservationLane, PIECE_BYTES, Source, Tally,
};

/// How long a snapshot is given to reach its component.
pub const CALL_WAIT: Duration = Duration::from_secs(5);

/// How long the pump waits for what the client already holds to be written before it asks for a
/// snapshot.
const HAND_OFF_BARRIER: Duration = Duration::from_secs(1);

/// What an event costs beyond its bytes on the wire: its envelope, handle and identifier.
const EVENT_ENVELOPE_BYTES: u64 = 1024;

/// The runtime's name for a binding.
pub fn service_id(binding_id: BrokerBindingId) -> BindingId {
    BindingId::new(binding_id.get())
}

/// Runs for as long as the broker lives.
pub async fn pump(broker: Weak<Broker>) {
    let Some(lane) = broker.upgrade().map(|broker| broker.observation()) else {
        return;
    };
    loop {
        let Some(strong) = broker.upgrade() else {
            return;
        };
        #[cfg(feature = "testing")]
        if lane.held_by_a_test() {
            drop(strong);
            lane.idle(None).await;
            continue;
        }
        apply_loss(&strong, &lane);
        snapshots(&strong, &lane).await;
        match lane.take() {
            Some(entry) => {
                offer(&strong, &lane, &entry).await;
                lane.finish(&entry);
            }
            None => {
                // The lane refuses to hand over an entry while it has lost something the pump has
                // not applied, so a loss is the reason for a miss as often as an empty lane is.
                if lane.loss_pending() {
                    continue;
                }
                let wait = lane.next_due(Instant::now());
                drop(strong);
                lane.idle(wait).await;
            }
        }
    }
}

/// Turns what the lane lost into a loss for each binding that would have been offered it.
///
/// A binding is told what it would have been offered and nothing else: the terminal's output if it
/// takes the terminal, and the frames of the one package whose table read them if it is that
/// package's binding.
fn apply_loss(broker: &Broker, lane: &ObservationLane) {
    let Some(loss) = lane.take_loss() else {
        return;
    };
    let mut owed: BTreeMap<BrokerBindingId, Tally> = BTreeMap::new();
    let mut add = |binding: BrokerBindingId, tally: Tally| {
        let total = owed.entry(binding).or_default();
        total.events = total.events.saturating_add(tally.events);
        total.bytes = total.bytes.saturating_add(tally.bytes);
    };
    if loss.terminal.events > 0 {
        for binding in broker.observing(Audience::Terminal) {
            add(binding, loss.terminal);
        }
    }
    for native in &loss.native {
        for binding in broker.observing(Audience::Native {
            instance: native.instance,
            package: Some(&native.package),
        }) {
            add(binding, native.tally);
        }
    }
    for (binding, tally) in owed {
        lost(
            broker,
            lane,
            binding,
            format!(
                "{} observations ({} bytes) were dropped for want of room in the worker's queue",
                tally.events, tally.bytes
            ),
        );
    }
}

/// Records that a binding's component has missed something.
fn lost(broker: &Broker, lane: &ObservationLane, binding: BrokerBindingId, what: String) {
    if lane.lose(binding, what.clone()).is_some() {
        broker.note_component(
            binding,
            ComponentNote::Loss(format!("{what}; a fresh snapshot is owed")),
        );
    }
}

/// Asks for the snapshot every ready binding that has lost something is owed.
async fn snapshots(broker: &Broker, lane: &ObservationLane) {
    let owing = lane.owing(Instant::now());
    if owing.is_empty() {
        return;
    }
    for (binding, through) in owing {
        let Some(client) = broker.component_calls().client() else {
            return;
        };
        // A snapshot is asked for after what the client already holds has been written, so that the
        // component is not asked to rebuild its view before it has read what is older than the loss.
        // A client that has not written it all is asked again soon, and the binding is passed over
        // until then.
        if !written(&client).await {
            lane.snapshot_failed(binding, Instant::now());
            continue;
        }
        match client.snapshot(service_id(binding), CALL_WAIT).await {
            Ok(_) => {
                lane.answered(binding);
                if let Some(what) = lane.snapshot_answered(binding, through) {
                    broker.note_component(
                        binding,
                        ComponentNote::Loss(format!("{what}; a fresh snapshot was taken")),
                    );
                }
            }
            Err(ServiceError::Disabled { .. }) => lane.forget(binding),
            Err(_) => lane.snapshot_failed(binding, Instant::now()),
        }
    }
}

/// Waits, for a bounded time, until the client has written what it already holds, and says whether
/// it has.
async fn written(client: &PluginClient) -> bool {
    let until = Instant::now() + HAND_OFF_BARRIER;
    while client.offered_bytes() > 0 {
        if Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Offers one entry to every binding that may be offered it.
///
/// Whether a binding may be offered it is read again before each hand-over, and so is the
/// connection to the runtime: a call that waited for an answer may have been made while a grant was
/// withdrawn or the runtime was lost.
async fn offer(broker: &Broker, lane: &ObservationLane, entry: &Entry) {
    for binding in broker.observing(entry.audience()) {
        let Some(view) = lane
            .view(binding)
            .filter(|view| view.ready && entry.seq() >= view.ready_from)
        else {
            continue;
        };
        if !broker.observing(entry.audience()).contains(&binding) {
            continue;
        }
        let Some(client) = broker.component_calls().client() else {
            return;
        };
        if view.is_silent(Instant::now()) {
            lost(
                broker,
                lane,
                binding,
                "an observation was passed over while the plugin runtime was not answering"
                    .to_owned(),
            );
            continue;
        }
        // A component that is owed a snapshot is offered nothing until it has had it; what it was
        // going to be offered is one more thing it missed.
        if view.owes().is_some() {
            lost(
                broker,
                lane,
                binding,
                "an observation was passed over while a fresh snapshot was owed".to_owned(),
            );
            continue;
        }
        match &entry.source {
            Source::Native(frame) => {
                deliver_frame(broker, lane, &client, binding, frame, entry).await;
            }
            Source::Terminal(bytes) => {
                offer_terminal(broker, lane, &client, binding, bytes, entry);
            }
        }
    }
}

fn fresh_handle() -> Option<SourceEventHandle> {
    SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid())).ok()
}

/// Delivers one upstream frame, and learns what the component's queue did with it.
async fn deliver_frame(
    broker: &Broker,
    lane: &ObservationLane,
    client: &PluginClient,
    binding: BrokerBindingId,
    frame: &NativeFrame,
    entry: &Entry,
) {
    let named = frame
        .request_id
        .as_deref()
        .map_or_else(|| "a frame".to_owned(), |id| format!("request {id}"));
    let Some(handle) = frame.handle.clone().or_else(fresh_handle) else {
        return;
    };
    let carried = frame.bytes.len() as u64
        + EVENT_ENVELOPE_BYTES
        + frame.request_id.as_ref().map_or(0, |id| id.len() as u64);
    if carried > MAX_OFFERED_EVENT_BYTES {
        lost(
            broker,
            lane,
            binding,
            format!("{named} is larger than the plugin runtime takes in one event"),
        );
        return;
    }
    let event = ScopedSourceEvent::new(
        handle,
        SourceProvenance::NativeProtocol,
        entry.at_ms,
        frame.request_id.clone(),
        Arc::clone(&frame.bytes),
    );
    match client.deliver(service_id(binding), &event).await {
        Ok(Admission::Queued | Admission::QueuedWithGap { .. }) => {
            lane.offered(binding, Instant::now(), entry.private);
            lane.answered(binding);
        }
        Ok(Admission::Refused { .. }) => lost(
            broker,
            lane,
            binding,
            format!("the plugin runtime's queue could not take {named}"),
        ),
        Err(ServiceError::CallerDeadline { .. } | ServiceError::Unavailable { .. }) => {
            lost(
                broker,
                lane,
                binding,
                format!("the plugin runtime did not answer when {named} was offered"),
            );
            lane.go_silent(binding, Instant::now());
        }
        Err(ServiceError::Disabled { .. }) => lane.forget(binding),
        Err(other) => lost(
            broker,
            lane,
            binding,
            format!("the plugin runtime refused {named}: {other}"),
        ),
    }
}

/// Offers one span of terminal output, in pieces, without waiting for anything.
fn offer_terminal(
    broker: &Broker,
    lane: &ObservationLane,
    client: &PluginClient,
    binding: BrokerBindingId,
    bytes: &[u8],
    entry: &Entry,
) {
    for piece in bytes.chunks(PIECE_BYTES) {
        let Some(handle) = fresh_handle() else {
            return;
        };
        let event = ScopedSourceEvent::new(
            handle,
            SourceProvenance::TerminalScrape,
            entry.at_ms,
            None,
            piece.to_vec(),
        );
        match client.offer(service_id(binding), &event) {
            Handoff::Accepted => {
                lane.offered(binding, Instant::now(), entry.private);
            }
            Handoff::Refused { .. } => {
                lost(
                    broker,
                    lane,
                    binding,
                    "terminal output was refused by the full hand-off to the plugin runtime"
                        .to_owned(),
                );
                return;
            }
            Handoff::TooLarge { .. } | Handoff::Unavailable => {
                lost(
                    broker,
                    lane,
                    binding,
                    "terminal output could not be handed to the plugin runtime".to_owned(),
                );
                return;
            }
        }
    }
}
