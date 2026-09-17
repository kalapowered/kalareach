//! A component that produces more than one call may produce.
//!
//! Two ways, because a host might bound one and not the other. `observe` and `snapshot` ignore
//! `remaining-output-bytes` and keep emitting nodes; `checkpoint` returns more state than one call
//! may produce. Both are refused: the output budget is one budget over everything a call produces,
//! and a component that tried to exceed a stated bound has misbehaved rather than answered.
//!
//! The nodes emitted before the refusal are kept, because a presentation a person is entitled to
//! see does not disappear because of what came after it.

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
        // More state than one call may produce, returned rather than emitted. A host that bounded
        // only the document would carry it: the output budget is one budget over everything a call
        // produces, so this is refused the same way a flood of nodes is. A little over rather than
        // far over, because the point is the bound and not how long a component can spend
        // allocating.
        Ok(alloc::vec![0_u8; 1024 * 1024 + 64 * 1024])
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
