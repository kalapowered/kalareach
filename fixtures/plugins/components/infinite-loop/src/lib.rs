//! A component that never returns.
//!
//! Every export spins. What stops it is the export's own elapsed deadline: 10 ms for `observe` and
//! `prepare-action`, 50 ms for the two interpretation exports, 100 ms for `snapshot`, `checkpoint`
//! and `restore`. Fuel bounds the work as well, and the host reports whichever bound ran out
//! without describing one as the other.
//!
//! The loop reads a volatile cell so that no optimiser can decide it does nothing and remove it.

#![no_std]
#![no_main]

extern crate alloc;

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
use kalareach::plugin::types::ActionToken;

static SPINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Spins until the host stops the call.
fn spin() -> ! {
    loop {
        SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        // Binding returns, so the instance exists and every later call is the one that hangs. A
        // component that hung here would test instantiation rather than the call deadlines.
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        spin()
    }

    fn snapshot() -> Result<(), Fault> {
        spin()
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        spin()
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        spin()
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        spin()
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        spin()
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        spin()
    }
}

export!(Component);
