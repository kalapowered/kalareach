//! A component that takes its time and still answers.
//!
//! Every fixture that runs for a while runs past its deadline and faults, and three faults disable
//! a binding. That makes them the wrong evidence for a claim about what happens *while* a component
//! is running: after a few hundred milliseconds there is no longer a component running at all.
//!
//! This one spends most of an `observe` deadline and then returns. A queue of observations against
//! it is therefore a component that is continuously inside a call, for as long as the queue lasts,
//! with no fault and no disabling -- which is what a test about the terminal path needs around it.
//!
//! The work is arithmetic on a volatile cell, so no optimiser can decide it does nothing. How much
//! of it there is was chosen against the fuel a 10 ms observe is given rather than against a clock:
//! a component has no clock, and fuel is the only bound it can count.

#![no_std]
#![no_main]

extern crate alloc;

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
    Binding, DecodedRequest, EffectPlan, EncodedResponse, Fault, Guest, MethodClass, NamedArgument,
    RequestSnapshot,
};
use kalareach::plugin::document;
use kalareach::plugin::document::Node;
use kalareach::plugin::types::ActionToken;

/// Where the work goes, so that nothing can decide it is unnecessary.
static WORK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many rounds one call spends.
///
/// An observe is given 10 ms and a hundred million units of fuel per millisecond of it. This is
/// enough rounds to spend a good part of that and few enough to leave room to return: a call that
/// used its whole allowance would be a fault, and a fault is what this component exists not to be.
const ROUNDS: u64 = 1_000_000;

/// Spends most of a call, then returns.
fn spend() {
    let mut carried = WORK.load(core::sync::atomic::Ordering::Relaxed);
    for round in 0..ROUNDS {
        carried = carried.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(round);
    }
    WORK.store(carried, core::sync::atomic::Ordering::Relaxed);
}

/// Draws one node, so a caller can see that the call happened.
fn draw(call: &str) {
    let node = Node {
        node_id: "slow-observe/status".into(),
        node_revision: 1,
        body_json: alloc::format!("{{\"kind\":\"message\",\"text\":\"{call} finished\"}}"),
    };
    let _emitted = document::emit(&node);
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        draw("bind");
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        spend();
        draw("observe");
        Ok(())
    }

    fn snapshot() -> Result<(), Fault> {
        spend();
        draw("snapshot");
        Ok(())
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        Err(Fault::NotPermitted("this component proposes nothing".into()))
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        Ok(DecodedRequest {
            request_id: "slow-observe/1".into(),
            class: MethodClass::Observation,
            summary: "nothing to interpret".into(),
            decisions: vec![],
            presentation: vec![],
        })
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        Ok(EncodedResponse {
            request_id: "slow-observe/1".into(),
            bytes: vec![],
        })
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        Ok(vec![])
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
