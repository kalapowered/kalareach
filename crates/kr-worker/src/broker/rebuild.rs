//! What a component that starts again is given, and what the worker tells of it.
//!
//! When the plugin runtime is lost, every component on it is lost with it, and the component the
//! link registers afterwards is a new instance with no state. The worker does not give it a state it
//! saved before the loss: the state is opaque to the worker, and a state of unknown coverage cannot
//! be made to hold exactly the requests the broker holds unresolved (a request answered since stays
//! in it, and a request it holds is held twice when the worker gives it again). The worker gives it
//! what the broker holds instead: every request that is still pending, once each, in the order the
//! broker recorded them, under the handle the broker holds each by. An interpreted request's bytes
//! come from its decoder entry, which keeps the original whole after the retained frame is
//! released; an uninterpreted request's come from the retained frame. Nothing comes from a terminal
//! span, the semantic log or a screen: none of them can say what is still pending.
//!
//! [`Broker::rebuild_of`] reads under the broker's lock and calls no mutator. Every wait is made by
//! the pump (`crate::plugin_observation`) after the lock is dropped. The worker then tells a person
//! what the component was given and what it was not: counts, never content.

use kr_plugin_service::vocabulary::{ScopedSourceEvent, SourceProvenance};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, PendingResourceId, SourceEventHandle, SourceGeneration,
};

use super::encode::source_event_of;
use super::observation::{Audience, Outage, Tally};
use super::{Broker, MAX_RETAINED_FRAME_BYTES, MAX_RETAINED_FRAMES, PackageIdentity};

/// One pending request, as a component that starts again is given it.
#[derive(Debug)]
pub struct Offer {
    /// The request.
    pub resource_id: PendingResourceId,
    /// The source generation the request was recorded under: it is given only while the instance is
    /// still at it.
    pub generation: SourceGeneration,
    /// The request as the upstream sent it, under the handle the broker holds it by.
    pub event: ScopedSourceEvent,
    /// True when the broker already holds the request as a verified interpretation.
    pub approval: bool,
    /// Whether privacy mode stood when the request was recorded.
    pub private: bool,
}

/// What the broker holds of one binding's pending requests, to be given to its component.
#[derive(Debug)]
pub struct Rebuild {
    /// The instance the binding is bound to.
    pub instance: ApplicationInstanceId,
    /// The package the binding runs: the only package whose requests it is given.
    pub package: PackageIdentity,
    /// Where the broker's recording stood when this was read: a request recorded before it is in
    /// `offers` or is not given, and one recorded after it is offered live.
    pub boundary: u64,
    /// The requests to give, oldest first.
    pub offers: Vec<Offer>,
    /// Requests the worker could not read: no retained frame, a decoder entry from another
    /// generation or that the store could not read.
    pub unavailable: u64,
    /// Requests left out for the bound on what is given at once.
    pub over_cap: u64,
}

impl Broker {
    /// Reads the requests the broker holds for a binding's component that starts again.
    ///
    /// Returns nothing for a binding that is not offered the connector's upstream frames: it has no
    /// requests to be given. A request is read only when it is still unanswered ([`super::arbitration::Pending::is_unanswered`]:
    /// pending, or claimed for a rich answer that is not marked as sent), was recorded under the
    /// instance's current source generation, is of a kind a component may be offered, belongs to the
    /// binding's package, and is held by handle. Requests are read in the order the broker recorded
    /// them. At most [`MAX_RETAINED_FRAMES`] are read and [`MAX_RETAINED_FRAME_BYTES`] of event
    /// bytes, which are the broker's own bounds on what it holds; the rest are counted.
    #[must_use]
    pub fn rebuild_of(&self, binding_id: BrokerBindingId) -> Option<Rebuild> {
        let state = self.state();
        let binding = state.bindings.get(&binding_id)?;
        let instance_id = binding.application_instance_id;
        let package = binding.package();
        let audience = Audience::Native {
            instance: instance_id,
            package: Some(&package),
        };
        if !state.retains(binding, audience, false) {
            return None;
        }
        let instance = state.instances.get(&instance_id)?;
        let mut rebuild = Rebuild {
            instance: instance_id,
            package: package.clone(),
            boundary: state.arbitration.next_recorded(),
            offers: Vec::new(),
            unavailable: 0,
            over_cap: 0,
        };
        let mut bytes = 0usize;
        for pending in state.arbitration.in_recorded_order() {
            let resource = &pending.resource;
            // Unanswered only: pending, or claimed for a rich answer that is not marked as sent,
            // since that claim can go back after this read. One the host performs itself is claimed
            // when it is recorded and was never offered to a component.
            if resource.application_instance_id != instance_id
                || !pending.is_unanswered()
                || resource.source_generation != instance.source_generation
                || !resource.classification.declared
                || resource.classification.carries_credentials()
            {
                continue;
            }
            let Some(handle) = pending.source.as_ref() else {
                continue;
            };
            if rebuild.offers.len() >= MAX_RETAINED_FRAMES {
                rebuild.over_cap += 1;
                continue;
            }
            let read = if resource.interpretation_verified {
                interpreted(
                    &state.ledger,
                    resource,
                    handle,
                    &package,
                    instance.source_generation,
                )
            } else {
                uninterpreted(instance, resource, handle, &package)
            };
            let (event, approval) = match read {
                Read::Given(event, approval) => (event, approval),
                Read::OtherPackage => continue,
                Read::Unavailable => {
                    rebuild.unavailable += 1;
                    continue;
                }
            };
            if bytes.saturating_add(event.bytes.len()) > MAX_RETAINED_FRAME_BYTES {
                rebuild.over_cap += 1;
                continue;
            }
            bytes += event.bytes.len();
            rebuild.offers.push(Offer {
                resource_id: resource.resource_id,
                generation: resource.source_generation,
                event,
                approval,
                private: pending.made_in_privacy,
            });
        }
        Some(rebuild)
    }

    /// Returns true while a request is still unanswered (pending, or claimed for a rich answer that
    /// is not marked as sent) and the instance is still at the source generation it was recorded
    /// under: asked before each request is given, since a request can be answered, or its frames can
    /// be left behind, while an earlier one is being delivered.
    #[must_use]
    pub fn still_pending(
        &self,
        resource_id: PendingResourceId,
        generation: SourceGeneration,
    ) -> bool {
        let state = self.state();
        state.arbitration.get(resource_id).is_some_and(|pending| {
            let unanswered = pending.is_unanswered();
            unanswered
                && state
                    .instances
                    .get(&pending.resource.application_instance_id)
                    .is_some_and(|instance| instance.source_generation == generation)
        })
    }
}

/// What reading one request came to.
enum Read {
    /// The event to give, and whether the broker already holds the request as an approval.
    Given(ScopedSourceEvent, bool),
    /// The request belongs to another package.
    OtherPackage,
    /// The bytes could not be read.
    Unavailable,
}

/// Reads a request the broker holds as a verified interpretation, from its decoder entry.
fn interpreted(
    ledger: &super::ledger::Ledger,
    resource: &kr_protocol::gateway::PendingResource,
    handle: &SourceEventHandle,
    package: &PackageIdentity,
    generation: SourceGeneration,
) -> Read {
    match ledger.decoding(resource.resource_id) {
        Ok(Some(entry)) if PackageIdentity::of_entry(&entry) != *package => Read::OtherPackage,
        Ok(Some(entry)) if entry.source_generation == generation => Read::Given(
            source_event_of(handle.clone(), resource.recorded_at.get(), &entry),
            true,
        ),
        _ => Read::Unavailable,
    }
}

/// Reads a request nothing has interpreted, from the frame the instance retained.
fn uninterpreted(
    instance: &super::Instance,
    resource: &kr_protocol::gateway::PendingResource,
    handle: &SourceEventHandle,
    package: &PackageIdentity,
) -> Read {
    match instance.frames.get(handle) {
        Some(held) if held.recorder.as_ref() != Some(package) => Read::OtherPackage,
        Some(held) if held.frame.generation == instance.source_generation => Read::Given(
            ScopedSourceEvent::new(
                handle.clone(),
                SourceProvenance::NativeProtocol,
                held.frame.received_at.get(),
                Some(resource.request.upstream.as_str().to_owned()),
                held.frame.shared(),
            ),
            false,
        ),
        _ => Read::Unavailable,
    }
}

/// Everything the worker tells of one binding's component starting again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Whether the binding is offered the connector's upstream frames, so that the requests the
    /// broker holds were given to it.
    pub baseline: bool,
    /// Requests given.
    pub given: u64,
    /// Of those, requests the broker already holds as verified interpretations.
    pub approvals: u64,
    /// Requests that could not be given because their bytes could not be read.
    pub unavailable: u64,
    /// Requests that could not be given because they are too large for one event.
    pub oversized: u64,
    /// Requests left out for the bound on what is given at once.
    pub over_cap: u64,
    /// Requests the plugin runtime refused.
    pub refused: u64,
    /// Requests that were not given because the plugin runtime did not answer.
    pub unanswered: u64,
    /// Upstream frames the worker passed over while the plugin runtime was away, with their bytes.
    pub passed: Tally,
    /// Spans of terminal output the worker passed over, with their bytes.
    pub terminal: Tally,
    /// Observations the worker's queue dropped for want of room, with their bytes.
    pub dropped: Tally,
    /// Requests queued to be decoded again.
    pub decode_queued: u64,
    /// Requests that could not be queued to be decoded again because the queue was full.
    pub decode_full: u64,
}

/// Returns `one` for a count of one and `many` for any other.
const fn noun(count: u64, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

impl Recovery {
    /// What a restart came to, from what was counted while the runtime was away, before what the
    /// baseline gave is added.
    #[must_use]
    pub fn after(outage: Outage) -> Self {
        Self {
            passed: outage.passed,
            terminal: outage.terminal,
            dropped: outage.dropped,
            decode_queued: outage.decode_queued,
            decode_full: outage.decode_full,
            ..Self::default()
        }
    }

    /// The words a binding's report carries: counts, never content.
    #[must_use]
    pub fn words(&self) -> String {
        let mut parts = vec![
            "started again after the plugin runtime was lost, without its saved state or earlier \
             history"
                .to_owned(),
        ];
        if self.baseline {
            self.baseline_words(&mut parts);
        }
        let mut passed = Vec::new();
        if self.passed.events > 0 {
            passed.push(format!(
                "{} upstream {} ({} bytes)",
                self.passed.events,
                noun(self.passed.events, "frame", "frames"),
                self.passed.bytes
            ));
        }
        if self.terminal.events > 0 {
            passed.push(format!(
                "{} terminal {} ({} bytes)",
                self.terminal.events,
                noun(self.terminal.events, "span", "spans"),
                self.terminal.bytes
            ));
        }
        if !passed.is_empty() {
            parts.push(format!(
                "while the plugin runtime was away the worker passed over {}, which the component \
                 was never given",
                passed.join(" and ")
            ));
        }
        if self.dropped.events > 0 {
            parts.push(format!(
                "{} {} ({} bytes) {} dropped because the worker's queue was full while the plugin \
                 runtime was away",
                self.dropped.events,
                noun(self.dropped.events, "observation", "observations"),
                self.dropped.bytes,
                noun(self.dropped.events, "was", "were")
            ));
        }
        if self.decode_queued > 0 {
            parts.push(format!(
                "{} pending {} {} queued to be decoded again",
                self.decode_queued,
                noun(self.decode_queued, "request", "requests"),
                noun(self.decode_queued, "was", "were")
            ));
        }
        if self.decode_full > 0 {
            parts.push(format!(
                "{} pending {} could not be queued to be decoded again because the decode queue \
                 was full",
                self.decode_full,
                noun(self.decode_full, "request", "requests")
            ));
        }
        parts.join("; ")
    }

    /// A restart after a long outage that says all it usually says: the most the broker gives, and
    /// five-digit counts of what was passed over and dropped. For the cases that bound a report.
    #[cfg(test)]
    pub(super) fn after_a_long_outage() -> Self {
        let tally = |events, bytes| Tally { events, bytes };
        Self {
            baseline: true,
            given: 64,
            approvals: 64,
            passed: tally(99_999, 99_999_999),
            terminal: tally(99_999, 99_999_999),
            dropped: tally(99_999, 9_999_999),
            decode_queued: 8,
            decode_full: 56,
            ..Self::default()
        }
    }

    fn baseline_words(&self, parts: &mut Vec<String>) {
        let left_out =
            self.unavailable + self.oversized + self.over_cap + self.refused + self.unanswered;
        if self.given == 0 && left_out == 0 {
            parts.push("the worker had no pending request to give it".to_owned());
        }
        if self.given > 0 {
            let mut text = format!(
                "the worker gave it {} pending {} from its own records, oldest first",
                self.given,
                noun(self.given, "request", "requests")
            );
            if self.approvals > 0 {
                if self.given == 1 {
                    text.push_str(", already read as an approval");
                } else {
                    text.push_str(&format!(
                        ", {} of them already read as {}",
                        self.approvals,
                        noun(self.approvals, "an approval", "approvals")
                    ));
                }
            }
            parts.push(text);
        }
        let request = |count: u64| noun(count, "request", "requests");
        if self.unavailable > 0 {
            parts.push(format!(
                "{} pending {} could not be given because the worker no longer holds {}",
                self.unavailable,
                request(self.unavailable),
                noun(self.unavailable, "its frame", "their frames")
            ));
        }
        if self.oversized > 0 {
            parts.push(format!(
                "{} pending {} could not be given because {} too large for one event",
                self.oversized,
                request(self.oversized),
                noun(self.oversized, "it is", "they are")
            ));
        }
        if self.over_cap > 0 {
            parts.push(format!(
                "{} pending {} {} not given because the worker gives at most {} requests or 4 MiB \
                 at a time",
                self.over_cap,
                request(self.over_cap),
                noun(self.over_cap, "was", "were"),
                MAX_RETAINED_FRAMES
            ));
        }
        if self.refused > 0 {
            parts.push(format!(
                "{} pending {} {} not given because the plugin runtime refused {}",
                self.refused,
                request(self.refused),
                noun(self.refused, "was", "were"),
                noun(self.refused, "it", "them")
            ));
        }
        if self.unanswered > 0 {
            parts.push(format!(
                "{} pending {} {} not given because the plugin runtime did not answer",
                self.unanswered,
                request(self.unanswered),
                noun(self.unanswered, "was", "were")
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(events: u64, bytes: u64) -> Tally {
        Tally { events, bytes }
    }

    #[test]
    fn a_restart_with_nothing_to_give_says_so_and_that_the_earlier_history_is_gone() {
        let words = Recovery {
            baseline: true,
            ..Recovery::default()
        }
        .words();
        assert_eq!(
            words,
            "started again after the plugin runtime was lost, without its saved state or earlier \
             history; the worker had no pending request to give it"
        );
    }

    #[test]
    fn a_decoder_that_takes_no_frames_is_not_told_it_was_given_requests() {
        let words = Recovery {
            baseline: false,
            ..Recovery::default()
        }
        .words();
        assert_eq!(
            words,
            "started again after the plugin runtime was lost, without its saved state or earlier \
             history"
        );
    }

    #[test]
    fn what_was_given_and_what_was_passed_over_are_counted_apart() {
        let words = Recovery {
            baseline: true,
            given: 1,
            approvals: 1,
            passed: tally(2, 310),
            ..Recovery::default()
        }
        .words();
        assert_eq!(
            words,
            "started again after the plugin runtime was lost, without its saved state or earlier \
             history; the worker gave it 1 pending request from its own records, oldest first, \
             already read as an approval; while the plugin runtime was away the worker passed over \
             2 upstream frames (310 bytes), which the component was never given"
        );
        let words = Recovery {
            baseline: true,
            given: 3,
            approvals: 2,
            passed: tally(1, 10),
            terminal: tally(4, 2000),
            dropped: tally(1, 90),
            ..Recovery::default()
        }
        .words();
        assert!(
            words.contains(
                "the worker gave it 3 pending requests from its own records, oldest first, 2 of \
                 them already read as approvals"
            ),
            "{words}"
        );
        assert!(
            words.contains(
                "passed over 1 upstream frame (10 bytes) and 4 terminal spans (2000 bytes), which"
            ),
            "{words}"
        );
        assert!(
            words.contains(
                "1 observation (90 bytes) was dropped because the worker's queue was full while \
                 the plugin runtime was away"
            ),
            "{words}"
        );
    }

    #[test]
    fn each_reason_a_request_was_not_given_has_its_own_clause() {
        let words = Recovery {
            baseline: true,
            unavailable: 1,
            oversized: 2,
            over_cap: 3,
            refused: 1,
            unanswered: 2,
            ..Recovery::default()
        }
        .words();
        for clause in [
            "1 pending request could not be given because the worker no longer holds its frame",
            "2 pending requests could not be given because they are too large for one event",
            "3 pending requests were not given because the worker gives at most 64 requests or 4 \
             MiB at a time",
            "1 pending request was not given because the plugin runtime refused it",
            "2 pending requests were not given because the plugin runtime did not answer",
        ] {
            assert!(words.contains(clause), "{clause}: {words}");
        }
        assert!(!words.contains("had no pending request"), "{words}");
    }

    #[test]
    fn the_decode_counts_are_told_apart_from_the_requests_given() {
        let words = Recovery {
            decode_queued: 8,
            decode_full: 1,
            ..Recovery::default()
        }
        .words();
        assert!(
            words.ends_with(
                "8 pending requests were queued to be decoded again; 1 pending request could not \
                 be queued to be decoded again because the decode queue was full"
            ),
            "{words}"
        );
    }

    #[test]
    fn what_a_long_outage_says_leaves_room_in_the_report_for_the_other_notes() {
        let words = Recovery::after_a_long_outage().words();
        // The report is cut at the bound: a restart's words must leave room for how the component
        // was registered and for what it has failed to decode and to write.
        assert!(words.len() <= 700, "{} bytes: {words}", words.len());
    }
}
