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
//! What a ready component is not offered is a loss, and a loss is numbered. A binding that has lost
//! something is owed a snapshot, and gets one before it is offered anything else: the snapshot is
//! requested for the number of the loss current when it is asked for and discharges that number, so
//! a loss that arrives while it runs asks for another. What the component has missed is put in the
//! binding's component report, where a person reads it, as counts and never as content.
//!
//! The lane gives the pump a loss with the first entry that is newer than it, and all of what it lost
//! where none waits: the loss is applied and its snapshot taken before the entry is offered, and
//! what is lost while that runs, or is newer than the entry because the lane lost it while a
//! request waited, is applied with a later entry.
//!
//! # A component that starts again
//!
//! A component registered again after the plugin runtime was lost is a new instance with no state,
//! and the worker gives it none: what it holds is what the broker holds. Between the loss and the
//! registration the pump takes entries off the lane for such a binding and counts them as passed
//! over, and what the lane drops for it is counted as dropped: neither is a loss that owes a snapshot,
//! since the component holds nothing of them. When it is registered the binding is owed its baseline,
//! the requests the broker still holds as pending for it, in the order it recorded them
//! ([`crate::broker::Broker::rebuild_of`]). The pump gives the baseline once every entry older than
//! the registration has been taken and counted, and before the first entry at or after it is
//! offered; a request the baseline gave, or left out, is not offered again from the lane. What the
//! component was given and what it was not is put in its report.
//!
//! Between the two sources there is no order, and none is claimed. Within a source the order is the
//! order produced, and a snapshot is asked for after a loss and before any later entry is handed to
//! the binding.
//!
//! What a snapshot is ordered after is what the client has written. The pump asks for it once the
//! client holds no event that has been handed over and not written, and the client keeps an event
//! in its count until its write is over, so the snapshot request is written after every event the
//! pump handed over before it (or, on a connection that has ended, refused), and the runtime reads
//! them in that order. The runtime queues an event
//! when it reads it, takes the queue in batches of sixteen and answers a snapshot request between
//! batches, so the component may not have observed the older events when it is asked for the
//! snapshot. That is not claimed: the snapshot is the component's view of what it held when it ran,
//! and each observation after it draws the view again.
//!
//! Every call the pump makes is made on the connection it was handed, and what the call came to is
//! recorded only while that connection is still the runtime's: an answer from a connection the link
//! has let go says nothing about the binding the link registered on its replacement.

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
#[cfg(feature = "testing")]
use crate::broker::observation::Pause;
use crate::broker::observation::{
    Audience, Entry, LaneLoss, NativeFrame, ObservationLane, PIECE_BYTES, Source, Tally, View,
};
use crate::broker::rebuild::Recovery;

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
        let taken = lane.take();
        if let Some(loss) = taken.loss {
            apply_loss(&strong, &lane, &loss);
        }
        // A baseline is read after every entry older than the component's view has been taken and
        // counted, and before the first entry at or after it is offered.
        let at = taken.entry.as_ref().map(Entry::seq);
        for (binding, connection) in lane.rebuilds_due(at, Instant::now()) {
            rebuild(&strong, &lane, binding, connection).await;
        }
        snapshots(&strong, &lane).await;
        match taken.entry {
            Some(entry) => {
                offer(&strong, &lane, &entry).await;
                lane.finish(&entry);
            }
            None => {
                // A binding that became due for a snapshot while another's was being taken is
                // asked at once, not when something else wakes the pump.
                if strong.component_calls().client().is_some()
                    && !lane.owing(Instant::now()).is_empty()
                {
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
/// package's binding. A binding whose component started again, and has not been given its baseline
/// yet, is told what it was not given by the baseline's words and not as a loss.
fn apply_loss(broker: &Broker, lane: &ObservationLane, loss: &LaneLoss) {
    let mut owed: BTreeMap<BrokerBindingId, Tally> = BTreeMap::new();
    let mut add = |binding: BrokerBindingId, tally: Tally| {
        let total = owed.entry(binding).or_default();
        total.events = total.events.saturating_add(tally.events);
        total.bytes = total.bytes.saturating_add(tally.bytes);
    };
    if loss.terminal.events > 0 {
        for binding in broker.retaining(Audience::Terminal) {
            add(binding, loss.terminal);
        }
    }
    for native in &loss.native {
        for binding in broker.retaining(Audience::Native {
            instance: native.instance,
            package: Some(&native.package),
        }) {
            add(binding, native.tally);
        }
    }
    for (binding, tally) in owed {
        // A component whose runtime is away, or that is owed its baseline, holds nothing of what the
        // lane dropped: it is counted in its outage and owes no snapshot.
        if lane.count_dropped(binding, tally) {
            continue;
        }
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

/// Returns true while `client` is the connection the link holds: what a call on it came to is
/// recorded only then.
fn current(broker: &Broker, client: &Arc<PluginClient>) -> bool {
    broker
        .component_calls()
        .client()
        .is_some_and(|held| Arc::ptr_eq(&held, client))
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
        // request reaches the runtime after the events handed over before it. A client that has not
        // written them all is asked again after a wait that grows, and the binding is passed over
        // until then.
        if !written(&client).await {
            if current(broker, &client) {
                lane.snapshot_failed(binding, Instant::now());
            }
            continue;
        }
        let answer = client.snapshot(service_id(binding), CALL_WAIT).await;
        if !current(broker, &client) {
            continue;
        }
        match answer {
            Ok(called) => {
                lane.answered(binding);
                if let Some(what) = lane.snapshot_answered(binding, through) {
                    let said = if called.answered() {
                        "a fresh snapshot was taken"
                    } else {
                        "the component declined a fresh snapshot"
                    };
                    broker.note_component(binding, ComponentNote::Loss(format!("{what}; {said}")));
                }
            }
            Err(ServiceError::Disabled { .. }) => lane.forget(binding),
            Err(_) => lane.snapshot_failed(binding, Instant::now()),
        }
    }
}

/// Waits, for a bounded time, until the client has written every event handed over to it, and says
/// whether it has. The client counts an event until its write is over, and nothing but this task
/// hands it events, so a snapshot requested after this answers true is written after them all, or
/// refused where the connection has ended.
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
///
/// A binding whose component is not offered the entry because the plugin runtime is away, or
/// because it is owed its baseline, is counted as passed over at that decision, from what is read
/// then: a wait for an earlier binding's hand-over may have lasted past a loss.
async fn offer(broker: &Broker, lane: &ObservationLane, entry: &Entry) {
    for binding in broker.retaining(entry.audience()) {
        let Some((client, view)) = offerable(broker, lane, binding, entry) else {
            lane.count_passed(binding, entry);
            continue;
        };
        // A request recorded before the baseline was read was given with it or left out of it.
        if let Source::Native(frame) = &entry.source
            && frame
                .recorded
                .is_some_and(|recorded| recorded.place < view.recorded_from)
        {
            continue;
        }
        // A request recorded after the baseline was read is asked about again here: it can be
        // answered, or left behind by its source, between its recording and this hand-over.
        if let Source::Native(frame) = &entry.source
            && let Some(recorded) = &frame.recorded
            && !broker.still_pending(recorded.resource_id, recorded.generation)
        {
            continue;
        }
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
        // The connection's words are withheld before the hand-over, not after the answer: a
        // delivery that is written and then times out may still be observed.
        lane.expose(entry.private);
        match &entry.source {
            Source::Native(frame) => {
                deliver_frame(broker, lane, &client, binding, frame, entry).await;
            }
            Source::Terminal(bytes) => {
                offer_terminal(broker, lane, &client, binding, bytes, entry);
            }
        }
        #[cfg(feature = "testing")]
        lane.paused_at(Pause::OfferedTo(binding)).await;
    }
}

/// Returns the connection to the runtime and the view a binding is offered `entry` through, read
/// now, or nothing where it is not offered it: the runtime is away, the component is not registered
/// and ready, the entry is older than its view, or it is owed its baseline (what it is given then is
/// what the broker holds).
///
/// The connection is taken before the view is read: a view read first may be one of a registration
/// the connection has since replaced, and the entry would go to the component of the next one,
/// which was made ready from a later entry.
fn offerable(
    broker: &Broker,
    lane: &ObservationLane,
    binding: BrokerBindingId,
    entry: &Entry,
) -> Option<(Arc<PluginClient>, View)> {
    let client = broker.component_calls().client()?;
    let view = lane
        .view(binding)
        .filter(|view| view.ready && entry.seq() >= view.ready_from && !view.rebuild_owed)?;
    broker
        .observing(entry.audience())
        .contains(&binding)
        .then_some((client, view))
}

/// Gives a binding's component, which started again, the requests the broker holds for it, and puts
/// in its report what it was given and what it was not.
///
/// The baseline is given to one registration: the connection to the runtime it began on, and the
/// registration made on it, are taken once, before the first request is handed over, and every
/// request goes through them. Everything else is read again before each request is handed over, and
/// no wait is made while the broker's lock is held. A runtime that cannot be reached, or that was
/// replaced while a request was handed over, leaves the baseline owed to the registration that
/// follows; any other answer ends it, and what was not given is counted.
async fn rebuild(
    broker: &Broker,
    lane: &ObservationLane,
    binding: BrokerBindingId,
    connection: u64,
) {
    let Some(client) = broker.component_calls().client() else {
        return;
    };
    let mut recovery = Recovery::default();
    let mut boundary = 0;
    if let Some(read) = broker.rebuild_of(binding) {
        boundary = read.boundary;
        recovery.baseline = true;
        recovery.unavailable = read.unavailable;
        recovery.over_cap = read.over_cap;
        let audience = Audience::Native {
            instance: read.instance,
            package: Some(&read.package),
        };
        let mut offers = read.offers.into_iter();
        while let Some(given) = offers.next() {
            if !(current(broker, &client) && lane.rebuild_owed_on(binding, connection))
                || !broker.observing(audience).contains(&binding)
            {
                return;
            }
            // Answered, or left behind by the source, while an earlier request was handed over.
            if !broker.still_pending(given.resource_id, given.generation) {
                continue;
            }
            let carried = given.event.bytes.len() as u64
                + EVENT_ENVELOPE_BYTES
                + given
                    .event
                    .request_id
                    .as_ref()
                    .map_or(0, |id| id.len() as u64);
            if carried > MAX_OFFERED_EVENT_BYTES {
                recovery.oversized += 1;
                continue;
            }
            // The connection's words are withheld before the hand-over, not after the answer, and
            // for the privacy state the request was recorded in.
            lane.expose(given.private);
            let answer = client.deliver(service_id(binding), &given.event).await;
            if !current(broker, &client) {
                return;
            }
            let left = offers.len() as u64;
            match answer {
                Ok(Admission::Queued | Admission::QueuedWithGap { .. }) => {
                    recovery.given += 1;
                    recovery.approvals += u64::from(given.approval);
                    lane.answered(binding);
                    #[cfg(feature = "testing")]
                    lane.paused_at(Pause::BaselineGiven(recovery.given)).await;
                }
                Ok(Admission::Refused { .. }) => {
                    recovery.refused += 1 + left;
                    break;
                }
                Err(ServiceError::CallerDeadline { .. }) => {
                    recovery.unanswered += 1 + left;
                    lane.go_silent(binding, Instant::now());
                    break;
                }
                Err(ServiceError::Unavailable { .. }) => return,
                Err(ServiceError::Disabled { .. }) => {
                    lane.forget(binding);
                    return;
                }
                Err(_) => {
                    recovery.refused += 1 + left;
                    break;
                }
            }
        }
    }
    let Some(outage) = lane.finish_rebuild(binding, boundary, connection) else {
        return;
    };
    let told = Recovery {
        passed: outage.passed,
        terminal: outage.terminal,
        dropped: outage.dropped,
        decode_queued: outage.decode_queued,
        decode_full: outage.decode_full,
        ..recovery
    };
    broker.note_component(binding, ComponentNote::Recovery(told.words()));
}

fn fresh_handle() -> Option<SourceEventHandle> {
    SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid())).ok()
}

/// Delivers one upstream frame, and learns what the component's queue did with it.
async fn deliver_frame(
    broker: &Broker,
    lane: &ObservationLane,
    client: &Arc<PluginClient>,
    binding: BrokerBindingId,
    frame: &NativeFrame,
    entry: &Entry,
) {
    // Named by what it is and never by what it says: a request's identifier is the upstream's own
    // string, and this goes into a report a person reads.
    let named = if frame.request_id.is_some() {
        "a request"
    } else {
        "a frame"
    };
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
    let answer = client.deliver(service_id(binding), &event).await;
    if !current(broker, client) {
        return;
    }
    match answer {
        Ok(Admission::Queued | Admission::QueuedWithGap { .. }) => {
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
        Err(_) => lost(
            broker,
            lane,
            binding,
            format!("the plugin runtime refused {named}"),
        ),
    }
}

/// Offers one span of terminal output, in pieces, without waiting for anything.
fn offer_terminal(
    broker: &Broker,
    lane: &ObservationLane,
    client: &Arc<PluginClient>,
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
            Handoff::Accepted => {}
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
