//! A component that is slow to compile and quick to run.
//!
//! Its whole purpose is the gap between those two. Compilation happens at binding preparation, on
//! a background thread, under its own budget; a call deadline starts only once the instance is
//! ready. A component whose compile takes hundreds of milliseconds and whose `observe` takes
//! microseconds is what makes that gap measurable rather than asserted.
//!
//! The body is generated: a few thousand small functions, each of which the optimiser has to
//! compile because its result is returned.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::borrow::ToOwned as _;
use alloc::format;
use alloc::string::String;
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

mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        // One pass over a handful of the generated functions: quick enough to finish well inside
        // 10 ms, while the module as a whole is slow to compile.
        let value = generated::work(1);
        document::emit(&Node {
            node_id: "observed".to_owned(),
            node_revision: 1,
            body_json: format!("{{\"kind\":\"message\",\"text\":\"{value}\"}}"),
        })
        .map_err(Fault::Unreadable)
    }

    fn snapshot() -> Result<(), Fault> {
        document::emit(&Node {
            node_id: "snapshot".to_owned(),
            node_revision: 1,
            body_json: "{\"kind\":\"message\",\"text\":\"a large module\"}".to_owned(),
        })
        .map_err(Fault::Unreadable)
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        Err(Fault::Refused("this component prepares no actions".to_owned()))
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
