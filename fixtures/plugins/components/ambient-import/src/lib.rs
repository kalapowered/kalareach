//! A component that reaches for what the sandbox does not offer.
//!
//! Nothing here asks for a filesystem. It does not have to: this is an ordinary
//! `wasm32-wasip2` build against the Rust standard library, and the standard library's own
//! start-up and panic paths import `wasi:cli/environment`, `wasi:cli/exit`, `wasi:io/streams`,
//! `wasi:clocks/monotonic-clock` and the rest. The component that comes out imports every one of
//! them whether or not a line of this file calls them.
//!
//! That is what makes it the right fixture. The realistic way a component ends up with ambient
//! access is not a publisher writing `open("/etc/passwd")`; it is a publisher building the
//! default way and not looking at the import list. The runtime refuses this component at binding
//! preparation and names the import, so the publisher can see which one and build the way
//! `docs/plugins/runtime.md` describes.

wit_bindgen::generate!({
    path: "../../../../crates/kr-plugin-sdk/wit/kalareach-plugin.wit",
    world: "plugin",
    generate_all,
});

use exports::kalareach::plugin::adapter::{
    Binding, DecodedRequest, EffectPlan, EncodedResponse, Fault, Guest, NamedArgument,
    RequestSnapshot,
};
use kalareach::plugin::types::ActionToken;

struct Component;

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
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        Err(Fault::Refused("this component prepares no actions".into()))
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        Err(Fault::Refused("this component decodes nothing".into()))
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        Err(Fault::Refused("this component encodes nothing".into()))
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        Ok(Vec::new())
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
