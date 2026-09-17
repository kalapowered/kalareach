//! A component that emits more than one call may produce.
//!
//! It ignores `remaining-output-bytes` and keeps emitting. The host refuses the node that would
//! take the call past 1 MiB, tells the component so, and records the call as a fault: a component
//! that tried to exceed a stated bound has misbehaved rather than answered. The nodes it emitted
//! before that are kept, because a presentation a person is entitled to see does not disappear
//! because of what came after it.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec::Vec;

use kr_fixture_support as _;

wit_bindgen::generate!({
    path: "../../../../crates/kr-plugin-sdk/wit/kalareach-plugin.wit",
    world: "plugin",
    generate_all,
});

use exports::kalareach::plugin::adapter::{
    Binding, DecodedRequest, EffectPlan, EncodedResponse, Fault, Guest, NamedArgument,
    RequestSnapshot,
};
use kalareach::plugin::document::{self, Node};
use kalareach::plugin::types::ActionToken;

/// How much each node carries. Twelve of these is over a mebibyte.
const CHUNK_BYTES: usize = 100 * 1024;

/// Emits nodes until something stops it, without ever asking how much budget is left.
fn flood() -> Result<(), Fault> {
    let filler = "x".repeat(CHUNK_BYTES);
    for index in 0..64_u64 {
        let outcome = document::emit(&Node {
            node_id: format!("n{index}"),
            node_revision: index,
            body_json: format!("{{\"kind\":\"message\",\"text\":\"{filler}\"}}"),
        });
        if let Err(refusal) = outcome {
            // The host said no. Returning the refusal is what a considerate component would do;
            // the host still records the attempt as a fault, because the bound was stated.
            return Err(Fault::Exhausted(refusal.to_string()));
        }
    }
    Ok(())
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        flood()
    }

    fn snapshot() -> Result<(), Fault> {
        flood()
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        flood()?;
        Err(Fault::Refused("this component prepares no actions".to_string()))
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        flood()?;
        Err(Fault::Refused("this component decodes nothing".to_string()))
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        Err(Fault::Refused("this component encodes nothing".to_string()))
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        Ok(Vec::new())
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
