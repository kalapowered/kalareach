//! A component that asks for more linear memory than its bound allows.
//!
//! The runtime's limiter refuses growth past 64 MiB. Refusal arrives inside the component as a
//! failed allocation, which this component turns into a trap, and the host reports the refused
//! resource rather than the trap, because "asked for more linear memory than its bound of
//! 67108864 allows" is an answer and "the component trapped" is not.

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

/// Allocates and touches memory until the host refuses to grow any more.
///
/// The pages have to be written, not just requested: an allocator that has reserved address space
/// has not yet grown the component's linear memory, and the bound is on the memory rather than on
/// the reservation.
fn consume() -> ! {
    let mut held: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut block = Vec::new();
        block.resize(4 * 1024 * 1024, 0_u8);
        for index in (0..block.len()).step_by(4096) {
            block[index] = 1;
        }
        held.push(block);
    }
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        consume()
    }

    fn snapshot() -> Result<(), Fault> {
        consume()
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        consume()
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        consume()
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        consume()
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        consume()
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        consume()
    }
}

export!(Component);
