//! What the core reads out of one gateway connection's stream, and how it answers an approval.
//!
//! A connector's table says how its protocol frames and classifies. Two further statements of a
//! table of an application server a native terminal speaks to are compiled here, once, for the
//! executable that runs: the places in the stream's messages that name the thread the terminal
//! selected, the turn that is running and the request an application cleared, and the way an
//! approval the application asked is answered as the response to that request. The core reads the
//! places itself and writes the answer itself; nothing a component says is read.
//!
//! The reading is held with the tables the installation pinned, so a connection is interpreted
//! with what this host installed and nothing travels with the connection.

use std::collections::{BTreeMap, BTreeSet};

use kr_plugin_sdk::connector::{ConnectorManifest, FieldPath};
use kr_protocol::broker::OfferedDecision;
use kr_protocol::ids::UpstreamMethod;

/// The places a notification names a thread and a turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnPlaces {
    /// The notification.
    pub method: UpstreamMethod,
    /// Where it names the thread.
    pub thread: FieldPath,
    /// Where it names the turn.
    pub turn: FieldPath,
}

/// How the application reads the answer to an approval it asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerShape {
    /// The requests that ask for a decision.
    pub methods: BTreeSet<UpstreamMethod>,
    /// The member of the response's result that carries the decision.
    pub result_member: String,
    /// The value the application reads for each decision, by the decision's identifier.
    pub values: BTreeMap<String, String>,
    /// The decisions a person is offered, in the table's order and labelled as the package's
    /// answer action labels them.
    pub offered: Vec<OfferedDecision>,
}

/// What one connection's table says the core reads out of its stream and how it answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// The terminal's requests whose success reply names the thread it selected, and where.
    pub selections: BTreeMap<UpstreamMethod, FieldPath>,
    /// The messages after which the terminal has no thread selected, and where they name it.
    pub leaves: BTreeMap<UpstreamMethod, FieldPath>,
    /// The notification that a turn started.
    pub turn_started: Option<TurnPlaces>,
    /// The notification that a turn ended.
    pub turn_ended: Option<TurnPlaces>,
    /// The notification that a request was answered or cleared, and where it names the request.
    pub request_resolved: Option<(UpstreamMethod, FieldPath)>,
    /// How an approval is answered, where the table answers any as a response.
    pub answers: Option<AnswerShape>,
}

impl Reading {
    /// Compiles a table's reading, naming each method as the wire does.
    ///
    /// `offered` is the decisions a person is offered, labelled. A method the table routes under
    /// no wire name is left out: the package check refuses such a table before it is installed.
    #[must_use]
    pub fn compile(table: &ConnectorManifest, offered: Vec<OfferedDecision>) -> Self {
        let wire = |method: &kr_plugin_sdk::ids::MethodName| {
            table
                .routes
                .iter()
                .find(|route| &route.method == method)
                .and_then(|route| UpstreamMethod::new(route.wire_name.as_str()).ok())
        };
        let mut reading = Self::default();
        if let Some(observation) = table.observation.as_ref() {
            for selection in &observation.selections {
                if let Some(method) = wire(&selection.method) {
                    reading.selections.insert(method, selection.thread.clone());
                }
            }
            for leave in &observation.leaves {
                if let Some(method) = wire(&leave.method) {
                    reading.leaves.insert(method, leave.thread.clone());
                }
            }
            let turn = |route: &kr_plugin_sdk::connector::TurnRoute| {
                wire(&route.method).map(|method| TurnPlaces {
                    method,
                    thread: route.thread.clone(),
                    turn: route.turn.clone(),
                })
            };
            reading.turn_started = observation.turn_started.as_ref().and_then(turn);
            reading.turn_ended = observation.turn_ended.as_ref().and_then(turn);
            reading.request_resolved = observation.request_resolved.as_ref().and_then(|route| {
                wire(&route.method).map(|method| (method, route.request_id.clone()))
            });
        }
        if let Some(response) = table.decision_response.as_ref() {
            reading.answers = Some(AnswerShape {
                methods: response.answers.iter().filter_map(wire).collect(),
                result_member: response.result_member.clone(),
                values: response
                    .decisions
                    .iter()
                    .map(|entry| (entry.decision.to_string(), entry.value.clone()))
                    .collect(),
                offered,
            });
        }
        reading
    }

    /// Returns true when the table says the core reads anything out of the stream.
    #[must_use]
    pub fn reads_the_stream(&self) -> bool {
        !self.selections.is_empty()
            || !self.leaves.is_empty()
            || self.turn_started.is_some()
            || self.turn_ended.is_some()
            || self.request_resolved.is_some()
    }

    /// Returns true when `method` is a request that asks for a decision.
    #[must_use]
    pub fn asks_for_a_decision(&self, method: &UpstreamMethod) -> bool {
        self.answers
            .as_ref()
            .is_some_and(|answers| answers.methods.contains(method))
    }
}
