//! A component whose actions prepare an effect, each in the way its name says.
//!
//! One component stands for every way a component can answer `prepare-action`: a plan that is
//! exactly the invocation's, and a plan that is not, each wrong in one way. A host that compares
//! what a component proposes with what it was invited to do refuses each wrong one and carries the
//! right one. Nothing here is a model of what a vendor would write; it is what a test needs to
//! make the broker's comparisons fail one at a time.
//!
//! The actions a package declares for it, and the plan each returns:
//!
//! An action's name has to be valid as a manifest identifier (lower-case letters, digits, `-` and
//! `.`) and as the name the broker registers it under (lower-case letters, digits, `_` and `.`), so
//! the names below separate their words with dots only.
//!
//! | Action | What it returns |
//! | --- | --- |
//! | `turn.cancel` | the cancellation it was invited to prepare |
//! | `prompt.send` | the submission it was invited to prepare, as the routed method of its own name |
//! | `cancel.reasoned` | the cancellation, for an action that declares a required `reason` |
//! | `cancel.other.action` | a plan for another action |
//! | `cancel.other.class` | the cancellation, as a prompt |
//! | `cancel.as.prompt` | a submission, for an action declared as a cancellation |
//! | `cancel.other.arguments` | the cancellation, with an argument it was not given |
//! | `prompt.with.fields` | a routed method that fills in a field |
//! | `prompt.other.method` | a routed method other than the one the action goes out as |
//! | `cancel.terminal` | text for the terminal |
//! | `cancel.present` | a redraw of its own document |
//! | `attach.photo` | the attachment it was given, offered as that attachment |
//! | `attach.other` | an attachment it was not given |
//! | `attach.as.cancel` | the cancellation of the turn, for an action declared as an attachment |
//! | `cancel.fault` | a declared fault |
//! | `cancel.loop` | nothing: it never returns |

#![no_std]
#![no_main]

extern crate alloc;

use alloc::borrow::ToOwned as _;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

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
use kalareach::plugin::types::{ActionToken, Argument, EffectClass};

struct Component;

/// A plan for `action`, naming `operation`, of `class`, carrying `arguments`.
fn plan(
    action: &str,
    class: EffectClass,
    operation: PreparedOperation,
    arguments: Vec<NamedArgument>,
) -> EffectPlan {
    EffectPlan {
        action_id: action.to_owned(),
        class,
        operation,
        arguments,
    }
}

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        Ok(())
    }

    fn snapshot() -> Result<(), Fault> {
        Ok(())
    }

    fn prepare_action(
        token: ActionToken,
        arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        let action = token.action_id.as_str();
        match action {
            "turn.cancel" => Ok(plan(
                action,
                EffectClass::UpstreamCancel,
                PreparedOperation::UpstreamCancel,
                arguments,
            )),
            "cancel.reasoned" => Ok(plan(
                action,
                EffectClass::UpstreamCancel,
                PreparedOperation::UpstreamCancel,
                arguments,
            )),
            "prompt.send" => Ok(plan(
                action,
                EffectClass::UpstreamPrompt,
                PreparedOperation::UpstreamMethod(UpstreamCall {
                    method: action.to_owned(),
                    fields: Vec::new(),
                }),
                arguments,
            )),
            "cancel.other.action" => Ok(plan(
                "turn.cancel",
                EffectClass::UpstreamCancel,
                PreparedOperation::UpstreamCancel,
                arguments,
            )),
            "cancel.other.class" => Ok(plan(
                action,
                EffectClass::UpstreamPrompt,
                PreparedOperation::UpstreamCancel,
                arguments,
            )),
            "cancel.as.prompt" => Ok(plan(
                action,
                EffectClass::UpstreamCancel,
                PreparedOperation::UpstreamMethod(UpstreamCall {
                    method: action.to_owned(),
                    fields: Vec::new(),
                }),
                arguments,
            )),
            "cancel.other.arguments" => {
                let mut changed = arguments;
                changed.push(NamedArgument {
                    name: "extra".to_owned(),
                    value: Argument::Text("not given".to_owned()),
                });
                Ok(plan(
                    action,
                    EffectClass::UpstreamCancel,
                    PreparedOperation::UpstreamCancel,
                    changed,
                ))
            }
            "prompt.with.fields" => Ok(plan(
                action,
                EffectClass::UpstreamPrompt,
                PreparedOperation::UpstreamMethod(UpstreamCall {
                    method: action.to_owned(),
                    fields: vec![FieldAssignment {
                        path: vec![
                            FieldSegment::Member("params".to_owned()),
                            FieldSegment::Member("force".to_owned()),
                        ],
                        value: Argument::Boolean(true),
                    }],
                }),
                arguments,
            )),
            "prompt.other.method" => Ok(plan(
                action,
                EffectClass::UpstreamPrompt,
                PreparedOperation::UpstreamMethod(UpstreamCall {
                    method: "shell/exec".to_owned(),
                    fields: Vec::new(),
                }),
                arguments,
            )),
            "cancel.terminal" => Ok(plan(
                action,
                EffectClass::UpstreamCancel,
                PreparedOperation::TerminalText("\u{3}".to_owned()),
                arguments,
            )),
            "cancel.present" => Ok(plan(
                action,
                EffectClass::UpstreamCancel,
                PreparedOperation::Present,
                arguments,
            )),
            "attach.photo" | "attach.other" => {
                let given = arguments
                    .iter()
                    .find_map(|argument| match &argument.value {
                        Argument::AttachmentHandle(id) => Some(id.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| Fault::Refused("no attachment was named".to_owned()))?;
                let offered = if action == "attach.photo" {
                    given
                } else {
                    "00000000-0000-0000-0000-000000000000".to_owned()
                };
                Ok(plan(
                    action,
                    EffectClass::UpstreamAttachment,
                    PreparedOperation::UpstreamAttachment(offered),
                    arguments,
                ))
            }
            "attach.as.cancel" => Ok(plan(
                action,
                EffectClass::UpstreamAttachment,
                PreparedOperation::UpstreamCancel,
                arguments,
            )),
            "cancel.fault" => Err(Fault::Refused(format!("{action} is not something to do"))),
            "cancel.loop" => loop {
                core::hint::spin_loop();
            },
            other => Err(Fault::Refused(format!(
                "{other} is not an action this component registered"
            ))),
        }
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        Err(Fault::Refused("this component decodes nothing".to_owned()))
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        Err(Fault::Refused("this component encodes nothing".to_owned()))
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        Ok(Vec::new())
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
