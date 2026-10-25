//! Writing the answer to an approval a component read, outside the session boundary.
//!
//! The component that read a request is the one that writes its answer: the answer carries the
//! meaning the component gave the request, and the connector's table only says which decisions the
//! application accepts. The call is a round trip to the plugin runtime, bounded by the component's
//! own deadline and the allowance for the trip, and it sends nothing. It is made after the
//! answer's intent is committed and before the boundary that revalidates it, with no lock of this
//! worker held, and the receipt stays `accepted` while it runs.
//!
//! # Two passes
//!
//! The first pass ([`Broker::answer_encoding`]) checks what can be checked before the component is
//! asked: the resource, the caller's grant, the decoder's trust, the binding's revision, the
//! decision against the ones the request offered and the request's deadline. It returns the
//! snapshot the component is asked about, and claims nothing. The second pass hands the bytes back
//! to the broker ([`Broker::admit_encoded_approval`]), which checks all of that again under its
//! lock, adopts the bytes only if they are an answer to the request ([`Gateway::adopt_encoded`]),
//! and claims the resource and reserves its one transmission there. An answer that arrived natively
//! while the component worked has resolved the request, and the second pass finds it so.
//!
//! # What is never done
//!
//! The table does not stand in for a component that fails: a request read by a component is
//! answered by that component's bytes or by nobody's. A bridge channel's answer is the host's, and
//! is written from the validated decision alone.
//!
//! [`Gateway::adopt_encoded`]: crate::broker::gateway::Gateway::adopt_encoded

use std::time::Duration;

use kr_plugin_service::client::ROUND_TRIP_ALLOWANCE;
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::protocol::{WireMethodClass, WireRequestSnapshot};
use kr_plugin_service::vocabulary::{BindingId, ScopedSourceEvent, SourceProvenance};
use kr_protocol::agent::AgentMutationTarget;
use kr_protocol::gateway::NativeMethodClass;
use kr_protocol::ids::{BrokerBindingId, PendingResourceId};
use kr_protocol::scalars::TimestampMs;

use crate::broker::connectors::component_schema;
use crate::broker::error::{BrokerError, Result};
use crate::broker::{Broker, BrokerState};

/// The longest a component's encoding is waited for, including the wait for a place among the
/// calls in progress and the round trip to the runtime; the action's own accepted deadline can
/// shorten it.
pub const ENCODE_DEADLINE: Duration = Duration::from_secs(5);

/// Why a component's bytes did not become the answer to a request, in the fixed words a person is
/// told.
///
/// A component's own words are never among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotEncoded {
    /// The plugin runtime was not connected.
    NotConnected,
    /// The component was not registered and would not be, or was disabled.
    NotRegistered,
    /// All the places for calls into components were taken until the time ran out.
    Busy,
    /// The plugin runtime refused the request, or the call failed, ran out of time or lost its
    /// connection.
    Failed,
    /// The component declared a fault and encoded nothing.
    Declined,
    /// The component's answer was not an encoded response.
    NoAnswer,
    /// The component said it answered another request than the one it was asked about.
    OtherRequest,
    /// The bytes were refused when they came back, because they are not an answer to the request.
    NotAnAnswer,
}

impl NotEncoded {
    /// Returns the words a person is told.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::NotConnected => "the plugin runtime was not connected",
            Self::NotRegistered => "the component was not registered or was disabled",
            Self::Busy => "every place for a call into a component was taken",
            Self::Failed => {
                "the plugin runtime refused the request or the call failed, ran out of time or lost \
                 its connection"
            }
            Self::Declined => "the component declined",
            Self::NoAnswer => "the component's answer was not an encoded response",
            Self::OtherRequest => "its answer named another request",
            Self::NotAnAnswer => "its bytes were not an answer to the request",
        }
    }
}

/// What the first pass of an answer to an approval a component read establishes, which asking the
/// component needs.
#[derive(Debug)]
pub struct EncodeRequest {
    /// The binding whose component decoded the request and encodes its answer.
    pub binding_id: BrokerBindingId,
    /// The request being answered.
    pub resource_id: PendingResourceId,
    /// The decision, one of the ones the request offered.
    pub option_id: String,
    /// The broker's own record of the request, which the component is asked about.
    snapshot: WireRequestSnapshot,
    /// The request as the upstream sent it, where the broker still holds it.
    event: ScopedSourceEvent,
    /// Whether the request was made in privacy mode: what the component is handed of it again is
    /// made in privacy mode too, whatever privacy mode is when it is asked.
    private: bool,
}

/// What encoding hands the second pass: the component's bytes, or why there are none.
#[derive(Debug)]
pub struct Encoded {
    /// The binding that encoded it.
    pub binding_id: BrokerBindingId,
    /// The bytes the component returned, which nothing has sent and nothing has checked.
    pub bytes: std::result::Result<Vec<u8>, NotEncoded>,
}

impl BrokerState {
    /// Returns the binding whose component writes the answer to a request, where one does.
    ///
    /// The choice is made from the request's recorded interpretation and not from its method: a
    /// request a component read is answered by that component, and one the connector's table read
    /// is answered by the table. A bridge channel's request is the host's to answer whoever read
    /// it.
    ///
    /// # Errors
    ///
    /// Returns what the ledger's read fails with.
    pub(crate) fn encoder_of(
        &self,
        resource_id: PendingResourceId,
    ) -> Result<Option<BrokerBindingId>> {
        let Some(pending) = self.arbitration.get(resource_id) else {
            return Ok(None);
        };
        if self
            .gateway
            .channel(pending.resource.request.connection)
            .is_some()
        {
            return Ok(None);
        }
        Ok(self
            .ledger
            .decoding(resource_id)?
            .filter(|entry| entry.projection.schema_version == component_schema())
            .map(|entry| entry.binding_id))
    }

    /// The first pass of an answer to an approval, under the broker's lock.
    pub(crate) fn answer_encoding_in(
        &self,
        target: &AgentMutationTarget,
        resource_id: PendingResourceId,
        option_id: &str,
        now: TimestampMs,
    ) -> Result<Option<EncodeRequest>> {
        let Some(binding_id) = self.encoder_of(resource_id)? else {
            return Ok(None);
        };
        self.volatile.require_rich_work()?;
        self.check_answerable_in(target, resource_id, Some(option_id), now)?;
        let pending = self
            .arbitration
            .get(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        let entry = self.ledger.decoding(resource_id)?.ok_or_else(|| {
            BrokerError::PreconditionFailed {
                detail: format!(
                    "{resource_id} has no recorded interpretation, so there is nothing to answer"
                ),
            }
        })?;
        let handle = pending
            .source
            .clone()
            .ok_or_else(|| BrokerError::PreconditionFailed {
                detail: format!("{resource_id}'s source event is no longer held"),
            })?;
        let instance = self
            .instances
            .get(&pending.resource.application_instance_id)
            .ok_or_else(|| {
                crate::broker::unknown_instance(pending.resource.application_instance_id)
            })?;
        let received_at = pending.resource.recorded_at.get();
        let request_id = entry.upstream_request_id.as_str().to_owned();
        let snapshot = WireRequestSnapshot {
            request_id: request_id.clone(),
            handle: handle.clone(),
            method: pending.resource.method.as_str().to_owned(),
            class: match pending.resource.classification.class {
                NativeMethodClass::Observation => WireMethodClass::Observation,
                NativeMethodClass::Mutation => WireMethodClass::Mutation,
                NativeMethodClass::CredentialOrConfiguration => WireMethodClass::Credential,
                NativeMethodClass::Unsupported => WireMethodClass::Unsupported,
            },
            received_at_ms: received_at,
            deadline_at_ms: pending
                .resource
                .deadline_ms
                .as_ref()
                .map(|deadline| deadline.get()),
            offered_decisions: entry
                .projection
                .decisions
                .iter()
                .map(|decision| decision.option_id.clone())
                .collect(),
            binding_revision: instance.binding_revision.get(),
        };
        let event = ScopedSourceEvent::new(
            handle,
            SourceProvenance::NativeProtocol,
            received_at,
            Some(request_id),
            std::sync::Arc::<[u8]>::from(entry.source_bytes.as_slice()),
        );
        Ok(Some(EncodeRequest {
            binding_id,
            resource_id,
            option_id: option_id.to_owned(),
            snapshot,
            event,
            private: pending.made_in_privacy,
        }))
    }
}

impl Broker {
    /// The first pass of an answer to an approval: says whether a component writes the answer,
    /// and if one does, checks what can be checked before it is asked and returns what it is asked.
    ///
    /// Nothing is claimed and no marker is written. `Ok(None)` is an approval the connector's table
    /// read, which [`Broker::admit_approval`] admits whole.
    ///
    /// # Errors
    ///
    /// Returns what [`Broker::check_answerable`] refuses, and [`BrokerError::RichWorkFenced`] while
    /// rich work is fenced.
    pub fn answer_encoding(
        &self,
        target: &AgentMutationTarget,
        resource_id: PendingResourceId,
        option_id: &str,
        now: TimestampMs,
    ) -> Result<Option<EncodeRequest>> {
        self.state()
            .answer_encoding_in(target, resource_id, option_id, now)
    }

    /// Asks the component to write the answer, and returns its bytes or why there are none.
    ///
    /// Nothing here is held across the call: not this broker's lock, not the session's. What
    /// comes back is data the second pass checks in full.
    pub async fn encode(&self, request: &EncodeRequest, within: Duration) -> Encoded {
        let bytes = self.ask_to_encode(request, within).await;
        if let Err(why) = bytes {
            self.note_component(
                request.binding_id,
                crate::broker::component::ComponentNote::Encoding(why),
            );
        }
        Encoded {
            binding_id: request.binding_id,
            bytes,
        }
    }

    async fn ask_to_encode(
        &self,
        request: &EncodeRequest,
        within: Duration,
    ) -> std::result::Result<Vec<u8>, NotEncoded> {
        let until = tokio::time::Instant::now() + within.min(ENCODE_DEADLINE);
        let client = self
            .component_calls
            .client()
            .ok_or(NotEncoded::NotConnected)?;
        let place = tokio::time::timeout_at(
            until,
            std::sync::Arc::clone(&self.component_calls.running).acquire_owned(),
        )
        .await
        .map_err(|_| NotEncoded::Busy)?
        .map_err(|_| NotEncoded::Failed)?;
        let remaining = until.saturating_duration_since(tokio::time::Instant::now());
        let call = remaining
            .checked_sub(ROUND_TRIP_ALLOWANCE)
            .filter(|call| call.as_millis() > 0)
            .ok_or(NotEncoded::Failed)?;
        // Marked before the hand-over, not after the answer: a call that is written and then times
        // out may still have been read, and a request made in privacy mode stays made in it.
        self.observation.expose(request.binding_id, request.private);
        let called = client
            .encode(
                BindingId::new(request.binding_id.get()),
                request.snapshot.clone(),
                &request.option_id,
                Some(&request.event),
                call,
            )
            .await;
        drop(place);
        #[cfg(feature = "testing")]
        self.component_calls.encode_hold.pause().await;
        let called = called.map_err(|error| match error {
            ServiceError::Disabled { .. } => NotEncoded::NotRegistered,
            _ => NotEncoded::Failed,
        })?;
        if called.fault.is_some() {
            return Err(NotEncoded::Declined);
        }
        let encoded = called.encoded.ok_or(NotEncoded::NoAnswer)?;
        if encoded.request_id != request.snapshot.request_id {
            return Err(NotEncoded::OtherRequest);
        }
        Ok(encoded.bytes)
    }
}
