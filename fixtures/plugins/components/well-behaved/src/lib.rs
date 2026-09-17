//! A component that behaves, and exercises every export.
//!
//! This is the reference for what a connector does inside the contract. It reads the bytes behind
//! the handle it was given, checks how much output budget it has before it uses any, emits nodes
//! from the closed union, proposes effects rather than performing them, and interprets a native
//! request into a projection without answering it.
//!
//! What it does *not* do is as much of the point:
//!
//! * it never asks for a handle it was not given, and reports the absence rather than guessing;
//! * `decode-request` returns a projection and `encode-response` returns bytes, and neither has
//!   anywhere to send them, because the `upstream` import has no send function;
//! * `prepare-action` returns a plan naming an operation the broker already performs, with the
//!   fields filled in.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::borrow::ToOwned as _;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// Linking the support crate is what supplies the allocator, the panic handler and `cabi_realloc`.
use kr_fixture_support as _;

wit_bindgen::generate!({
    path: "../../../../crates/kr-plugin-sdk/wit/kalareach-plugin.wit",
    world: "plugin",
    generate_all,
});

use exports::kalareach::plugin::adapter::{
    Binding, DecodedRequest, EffectPlan, EncodedResponse, Fault, FieldAssignment, FieldSegment,
    Guest, NamedArgument, PreparedOperation, RequestSnapshot, UpstreamCall,
};
use kalareach::plugin::attachments;
use kalareach::plugin::document::{self, Node};
use kalareach::plugin::source_events::{self, Provenance};
use kalareach::plugin::types::{ActionToken, Argument, EffectClass, MethodClass};
use kalareach::plugin::upstream;

/// The presentation state one binding holds.
///
/// A component's own state, and nothing a decision depends on. Pending requests, dispatch markers
/// and the approval ledger are the worker broker's, which is why a checkpoint of this is enough to
/// resume presentation after the instance is replaced.
struct State {
    plugin_id: String,
    observed: u64,
    last_summary: String,
}

static mut STATE: Option<State> = None;

/// Returns the binding's state.
///
/// A component instance is single-threaded by construction: the host gives each binding a store and
/// a thread of its own, and the component model has no way to enter an instance twice at once.
#[allow(
    static_mut_refs,
    reason = "one instance, one thread, and the component model admits no reentrancy"
)]
fn state() -> &'static mut State {
    unsafe {
        if STATE.is_none() {
            STATE = Some(State {
                plugin_id: String::new(),
                observed: 0,
                last_summary: String::new(),
            });
        }
        STATE.as_mut().expect("the state was just created")
    }
}

/// Escapes text for a JSON string body.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out
}

/// Emits one message node, but only if the call's output budget can take it.
fn emit_message(node_id: &str, revision: u64, text: &str) -> Result<(), Fault> {
    let body = format!("{{\"kind\":\"message\",\"text\":\"{}\"}}", escaped(text));
    let needed = (node_id.len() + body.len()) as u64;
    if document::remaining_output_bytes() < needed {
        // Asking first is the difference between a component that fits its budget and one the host
        // faults for trying to exceed it.
        return Err(Fault::Exhausted("no output budget left for this node".to_owned()));
    }
    document::emit(&Node {
        node_id: node_id.to_owned(),
        node_revision: revision,
        body_json: body,
    })
    .map_err(Fault::Unreadable)
}

fn provenance_name(provenance: Provenance) -> &'static str {
    match provenance {
        Provenance::NativeProtocol => "native protocol",
        Provenance::MachineOutput => "machine output",
        Provenance::TerminalScrape => "terminal scrape",
    }
}

struct Component;

impl Guest for Component {
    fn bind(target: Binding) -> Result<(), Fault> {
        let state = state();
        state.plugin_id = target.plugin_id.clone();
        state.observed = 0;
        // The rights are a courtesy the host offers so a component can present controls that will
        // work. Reading them proves the import is there; the broker rechecks every one at dispatch.
        let rights = upstream::held_rights();
        emit_message(
            "bound",
            1,
            &format!(
                "bound to {} revision {} at {} with {} rights",
                target.plugin_id,
                target.binding_revision,
                target.executable,
                rights.len()
            ),
        )
    }

    fn observe(handle: String) -> Result<(), Fault> {
        let Some(event) = source_events::read(&handle) else {
            // A handle this call was not given reads as absent. Saying so is the honest answer;
            // there is no way to enumerate what was not given and no way to construct one.
            return Err(Fault::Unreadable("that handle is not one this call was given".to_owned()));
        };
        // A handle this call was not given. It cannot be constructed, only named, and naming one
        // is what a component would do if it wanted somebody else's bytes. What comes back is
        // reported either way, so the host's answer is visible rather than assumed.
        let invented = match source_events::read("se-invented-by-the-component") {
            Some(_) => "present",
            None => "absent",
        };
        let state = state();
        state.observed += 1;
        let text = core::str::from_utf8(&event.bytes)
            .map_err(|_| Fault::Unreadable("the event is not text".to_owned()))?;
        state.last_summary = format!(
            "{} bytes of {} at {}",
            event.bytes.len(),
            provenance_name(event.provenance),
            event.observed_at
        );
        emit_message(
            "observation",
            state.observed,
            &format!(
                "{}: {text} (invented handle: {invented})",
                state.last_summary
            ),
        )
    }

    fn snapshot() -> Result<(), Fault> {
        let state = state();
        let facts = upstream::state();
        let attachments = attachments::current();
        emit_message(
            "snapshot",
            state.observed,
            &format!(
                "{} after {} observations, activity {:?}, {} attachments, last: {}",
                state.plugin_id,
                state.observed,
                facts.activity,
                attachments.len(),
                state.last_summary
            ),
        )
    }

    fn prepare_action(
        token: ActionToken,
        arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        // The token is the invocation's authority as the host issued it. A component reads it; the
        // broker checks the returned plan against it again before anything happens.
        if token.parameter_hash.is_empty() {
            return Err(Fault::NotPermitted(
                "an invocation with no parameter hash is not one this component acts on".to_owned(),
            ));
        }
        let prompt = arguments
            .iter()
            .find(|argument| argument.name == "prompt")
            .and_then(|argument| match &argument.value {
                Argument::Text(text) => Some(text.clone()),
                _ => None,
            });
        match token.action_id.as_str() {
            "send-prompt" => {
                let Some(prompt) = prompt else {
                    return Err(Fault::Unreadable("send-prompt needs a text prompt".to_owned()));
                };
                Ok(EffectPlan {
                    action_id: token.action_id.clone(),
                    class: EffectClass::UpstreamPrompt,
                    // A routed method with its fields filled in. The connector table decides where
                    // it goes and what it means; this component supplies the values.
                    operation: PreparedOperation::UpstreamMethod(UpstreamCall {
                        method: "prompt.submit".to_owned(),
                        fields: vec![FieldAssignment {
                            path: vec![
                                FieldSegment::Member("params".to_owned()),
                                FieldSegment::Member("text".to_owned()),
                            ],
                            value: Argument::Text(prompt),
                        }],
                    }),
                    arguments,
                })
            }
            "redraw" => Ok(EffectPlan {
                action_id: token.action_id.clone(),
                class: EffectClass::Observe,
                // Nothing leaves the host for this one.
                operation: PreparedOperation::Present,
                arguments,
            }),
            other => Err(Fault::Refused(format!(
                "{other} is not an action this component registered"
            ))),
        }
    }

    fn decode_request(handle: String) -> Result<DecodedRequest, Fault> {
        let Some(event) = source_events::read(&handle) else {
            return Err(Fault::Unreadable("that handle is not one this call was given".to_owned()));
        };
        // Only a framed message on the connector's own upstream connection can carry a native
        // request. A scrape may look exactly like one and still not be one.
        if event.provenance != Provenance::NativeProtocol {
            return Err(Fault::NotPermitted(
                "a scrape does not establish native approval authority".to_owned(),
            ));
        }
        let Some(request_id) = event.request_id else {
            return Err(Fault::Unreadable(
                "the event carries no native request identifier".to_owned(),
            ));
        };
        let text = core::str::from_utf8(&event.bytes)
            .map_err(|_| Fault::Unreadable("the request is not text".to_owned()))?;
        // A projection, returned. Nothing is sent, and no resource exists until the broker has
        // checked this component's role, its application binding, the source generation, the
        // schema policy and non-reuse.
        Ok(DecodedRequest {
            request_id,
            class: if text.contains("\"write\"") {
                MethodClass::Mutation
            } else {
                MethodClass::Observation
            },
            summary: format!("the upstream asks to {}", text.trim()),
            decisions: vec!["allow".to_owned(), "deny".to_owned()],
            presentation: vec![format!(
                "{{\"kind\":\"message\",\"text\":\"{}\"}}",
                escaped(text.trim())
            )],
        })
    }

    fn encode_response(
        request: RequestSnapshot,
        decision: String,
    ) -> Result<EncodedResponse, Fault> {
        // The broker's own record of the request, as it arrived. A component cannot answer a
        // request it invented, and after a restart it can still answer one it never saw.
        if !request.offered_decisions.iter().any(|offered| *offered == decision) {
            return Err(Fault::Refused(format!(
                "{decision} is not one of the decisions the upstream offered"
            )));
        }
        // Bytes, returned. The broker rechecks the pending request, the actor grant and the
        // binding revision, then claims and dispatches them.
        Ok(EncodedResponse {
            request_id: request.request_id.clone(),
            bytes: format!(
                "{{\"id\":\"{}\",\"result\":\"{}\"}}",
                escaped(&request.request_id),
                escaped(&decision)
            )
            .into_bytes(),
        })
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        let state = state();
        Ok(format!("{}|{}|{}", state.plugin_id, state.observed, state.last_summary).into_bytes())
    }

    fn restore(bytes: Vec<u8>) -> Result<(), Fault> {
        let text = String::from_utf8(bytes)
            .map_err(|_| Fault::Unreadable("the checkpoint is not text".to_owned()))?;
        let mut parts = text.splitn(3, '|');
        let plugin_id = parts.next().unwrap_or_default().to_owned();
        let observed = parts
            .next()
            .unwrap_or_default()
            .parse::<u64>()
            .map_err(|_| Fault::Unreadable("the checkpoint's count is not a number".to_owned()))?;
        let last_summary = parts.next().unwrap_or_default().to_owned();
        let state = state();
        state.plugin_id = plugin_id;
        state.observed = observed;
        state.last_summary = last_summary;
        Ok(())
    }
}

export!(Component);
