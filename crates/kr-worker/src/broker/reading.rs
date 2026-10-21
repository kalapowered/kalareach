//! What the core reads out of one gateway connection's stream, how it answers an approval, and how
//! it writes its own operations.
//!
//! A connector's table says how its protocol frames and classifies. Three further statements of a
//! table of an application server a native terminal speaks to are compiled here, once, for the
//! executable that runs: the places in the stream's messages that name the thread the terminal
//! selected, the turn that is running and the request an application cleared; the way an approval
//! the application asked is answered as the response to that request; and the request the core
//! writes for a prompt, a steer and a cancellation. The core reads the places itself and writes
//! the answer and the requests itself; nothing a component says is read or sent.
//!
//! The reading is held with the tables the installation pinned, so a connection is interpreted
//! with what this host installed and nothing travels with the connection.

use std::collections::{BTreeMap, BTreeSet};

use kr_plugin_sdk::connector::{ConnectorManifest, FieldPath, TemplateHole};
use kr_protocol::broker::{ActionProvenance, OfferedDecision};
use kr_protocol::gateway::{NativeMethodClass, RichMethodEntry, RichOperation};
use kr_protocol::ids::UpstreamMethod;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;

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

/// How the application spells one of the core's operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationTemplate {
    /// The method that carries it, as the wire names it.
    pub method: UpstreamMethod,
    /// The request's parameters, with a hole where each value the core supplies goes.
    pub params: serde_json::Value,
    /// Where the reply names the turn the operation started, from the root of the reply.
    pub reply_turn: Option<FieldPath>,
}

/// What the core has to put into the holes of an operation's template.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fill<'a> {
    /// The conversation the operation acts in.
    pub thread: Option<&'a str>,
    /// The turn the operation acts on.
    pub turn: Option<&'a str>,
    /// The text the operation carries.
    pub text: Option<&'a str>,
}

impl OperationTemplate {
    /// Writes the request's parameters, with each hole filled by a JSON string.
    ///
    /// # Errors
    ///
    /// Returns the first hole the core has no value for, so an operation that would go out with a
    /// part missing is refused before anything is written.
    pub fn expand(&self, fill: Fill<'_>) -> Result<serde_json::Value, TemplateHole> {
        fill_in(&self.params, fill)
    }
}

fn fill_in(value: &serde_json::Value, fill: Fill<'_>) -> Result<serde_json::Value, TemplateHole> {
    if let Some(hole) = TemplateHole::of(value) {
        let given = match hole {
            TemplateHole::ThreadId => fill.thread,
            TemplateHole::TurnId => fill.turn,
            TemplateHole::Text => fill.text,
        };
        return given
            .map(|text| serde_json::Value::String(text.to_owned()))
            .ok_or(hole);
    }
    Ok(match value {
        serde_json::Value::Object(members) => serde_json::Value::Object(
            members
                .iter()
                .map(|(name, member)| fill_in(member, fill).map(|member| (name.clone(), member)))
                .collect::<Result<_, _>>()?,
        ),
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| fill_in(item, fill))
                .collect::<Result<_, _>>()?,
        ),
        other => other.clone(),
    })
}

/// What one connection's table says the core reads out of its stream, how it answers and how it
/// writes its own operations.
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
    /// How each of the core's operations is spelled, for the ones the table declares.
    pub operations: BTreeMap<RichOperation, OperationTemplate>,
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
        if let Some(operations) = table.operations.as_ref() {
            for (operation, declared) in [
                (RichOperation::PromptSubmit, &operations.prompt_submit),
                (RichOperation::PromptQueue, &operations.prompt_queue),
                (RichOperation::TurnSteer, &operations.turn_steer),
                (RichOperation::TurnCancel, &operations.turn_cancel),
            ] {
                if let Some(route) = declared
                    && let Some(method) = wire(&route.method)
                {
                    reading.operations.insert(
                        operation,
                        OperationTemplate {
                            method,
                            params: route.params.clone(),
                            reply_turn: route.reply_turn.clone(),
                        },
                    );
                }
            }
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

    /// Returns true when a notification of `method` is one the core reads something out of: a
    /// turn that started or ended, a conversation that ended, or a request that was cleared.
    #[must_use]
    pub fn reads_notification(&self, method: &UpstreamMethod) -> bool {
        [&self.turn_started, &self.turn_ended]
            .into_iter()
            .flatten()
            .any(|places| &places.method == method)
            || self.leaves.contains_key(method)
            || self
                .request_resolved
                .as_ref()
                .is_some_and(|(resolved, _)| resolved == method)
    }

    /// Returns the reading of a hand-made rich table, which spells each operation the table lists
    /// the way the fixture upstreams of the cases read it: the prompt's text under `text`, and the
    /// turn a steer and a cancellation act on under `turn_id`.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn spelling(rich: &kr_protocol::gateway::RichMethodTable) -> Self {
        let hole = |name: &str| serde_json::json!({ TemplateHole::MEMBER: name });
        let mut reading = Self::default();
        for entry in &rich.entries {
            let Some(operation) = entry.operation.as_ref().copied() else {
                continue;
            };
            let params = match operation {
                RichOperation::PromptSubmit | RichOperation::PromptQueue => {
                    serde_json::json!({ "draft_id": null, "text": hole("text") })
                }
                RichOperation::TurnSteer => {
                    serde_json::json!({ "text": hole("text"), "turn_id": hole("turn_id") })
                }
                RichOperation::TurnCancel => serde_json::json!({ "turn_id": hole("turn_id") }),
                RichOperation::ApprovalRespond | RichOperation::PluginAction => continue,
            };
            reading.operations.insert(
                operation,
                OperationTemplate {
                    method: entry.method.clone(),
                    params,
                    reply_turn: Some(FieldPath {
                        segments: ["result", "turn_id"]
                            .into_iter()
                            .map(|name| kr_plugin_sdk::connector::FieldSegment::Member {
                                name: name.to_owned(),
                            })
                            .collect(),
                    }),
                },
            );
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

    /// Returns the rich method table's entries: exactly the operations the table declares, each
    /// as the mutation it is, ordered by method.
    ///
    /// A table that declares no operation lists none, and every rich invocation is refused as
    /// unknown.
    #[must_use]
    pub fn rich_entries(&self) -> Vec<RichMethodEntry> {
        let mut entries: Vec<RichMethodEntry> = self
            .operations
            .iter()
            .map(|(operation, template)| RichMethodEntry {
                method: template.method.clone(),
                class: NativeMethodClass::Mutation,
                required_right: match operation {
                    RichOperation::TurnCancel => ActionRight::AgentCancel,
                    RichOperation::ApprovalRespond => ActionRight::AgentApprovalRespond,
                    RichOperation::PromptSubmit
                    | RichOperation::PromptQueue
                    | RichOperation::TurnSteer
                    | RichOperation::PluginAction => ActionRight::AgentPrompt,
                },
                operation: Nullable::from(Some(*operation)),
                provenance: ActionProvenance::UpstreamTypedRpc,
            })
            .collect();
        entries.sort_by(|first, second| first.method.cmp(&second.method));
        entries
    }

    /// Returns true when `method` is a request that asks for a decision.
    #[must_use]
    pub fn asks_for_a_decision(&self, method: &UpstreamMethod) -> bool {
        self.answers
            .as_ref()
            .is_some_and(|answers| answers.methods.contains(method))
    }
}
