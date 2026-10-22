//! A component that decodes a native request, and can be made to decode it badly.
//!
//! The worker believes nothing a decoder returns. A case that wants to show that makes this
//! component misbehave from outside: what it does with a request is set by markers in the bytes of
//! the request it is asked to decode, and what it does with a decision by markers in the method of
//! the request it is asked to answer. Its checkpoint is an account of what it was asked, so a case
//! reads what it was given through the client's own `checkpoint`: how many requests it decoded and
//! answered, and for the last decode the provenance, the request identifier, the length and a
//! digest of the bytes.
//!
//! | The request's bytes hold | The decode |
//! | --- | --- |
//! | nothing special | a request of the identifier it was given, the decisions `allow` and `deny`, a summary and one node |
//! | `!other-request` | names another request's identifier |
//! | `!unmapped` | offers `allow` and a decision the connector's table does not map |
//! | `!duplicate` | offers `allow` twice |
//! | `!no-decisions` | offers none |
//! | `!long-summary` | a summary of 5,000 bytes |
//! | `!decline` | declares a fault and returns nothing |
//! | `!trap` | traps |
//! | `!spin` | never returns |
//!
//! | The request's method holds | The encode |
//! | --- | --- |
//! | nothing special | bytes that answer the request it was given with the decision it was given |
//! | `!other-request` | answers another request |
//! | `!trap` | traps |
//! | `!spin` | never returns |

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec;
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
use kalareach::plugin::source_events::{self, Provenance};
use kalareach::plugin::types::{ActionToken, MethodClass};

static SPINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Spins until the host stops the call.
fn spin() -> ! {
    loop {
        SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// What this instance has been asked to do.
struct State {
    decodes: u64,
    encodes: u64,
    last: String,
}

static mut STATE: Option<State> = None;

/// Returns the instance's account.
///
/// A component instance is single-threaded by construction: the host gives each binding a store and
/// a thread of its own, and the component model admits no reentrancy.
#[allow(
    static_mut_refs,
    reason = "one instance, one thread, and the component model admits no reentrancy"
)]
fn state() -> &'static mut State {
    unsafe {
        if STATE.is_none() {
            STATE = Some(State {
                decodes: 0,
                encodes: 0,
                last: String::new(),
            });
        }
        STATE.as_mut().expect("the state was just created")
    }
}

/// A 64-bit FNV-1a digest, so a case can tell that the bytes it sent are the bytes that arrived.
fn digest(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Whether `bytes` hold `pattern` anywhere.
fn holds(bytes: &[u8], pattern: &[u8]) -> bool {
    bytes.windows(pattern.len()).any(|window| window == pattern)
}

fn provenance_name(provenance: Provenance) -> &'static str {
    match provenance {
        Provenance::NativeProtocol => "native_protocol",
        Provenance::MachineOutput => "machine_output",
        Provenance::TerminalScrape => "terminal_scrape",
    }
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        Ok(())
    }

    fn observe(_handle: String) -> Result<(), Fault> {
        Ok(())
    }

    fn snapshot() -> Result<(), Fault> {
        document::emit(&Node {
            node_id: "hostile-decoder/status".to_string(),
            node_revision: 1,
            body_json: "{\"kind\":\"message\",\"text\":\"drawn\"}".to_string(),
        })
        .map_err(Fault::Unreadable)
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        Err(Fault::Refused("this component proposes nothing".to_string()))
    }

    fn decode_request(handle: String) -> Result<DecodedRequest, Fault> {
        let Some(event) = source_events::read(&handle) else {
            return Err(Fault::Unreadable(
                "that handle is not one this call was given".to_string(),
            ));
        };
        let state = state();
        state.decodes += 1;
        let request_id = event.request_id.clone().unwrap_or_default();
        state.last = format!(
            "{}/{}/{}/{:016x}",
            provenance_name(event.provenance),
            request_id,
            event.bytes.len(),
            digest(&event.bytes)
        );
        let bytes = &event.bytes;
        if holds(bytes, b"!spin") {
            spin();
        }
        if holds(bytes, b"!trap") {
            core::arch::wasm32::unreachable();
        }
        if holds(bytes, b"!decline") {
            return Err(Fault::Refused("this request is not one to decode".to_string()));
        }
        let mut decoded = DecodedRequest {
            request_id: request_id.clone(),
            class: MethodClass::Mutation,
            summary: format!("the upstream asks for an answer to a request of {} bytes", bytes.len()),
            decisions: vec!["allow".to_string(), "deny".to_string()],
            presentation: vec![
                "{\"kind\":\"message\",\"text\":\"a request waits for an answer\"}".to_string(),
            ],
        };
        if holds(bytes, b"!other-request") {
            decoded.request_id = "another-request".to_string();
        }
        if holds(bytes, b"!unmapped") {
            decoded.decisions = vec!["allow".to_string(), "root-access".to_string()];
        }
        if holds(bytes, b"!duplicate") {
            decoded.decisions = vec!["allow".to_string(), "allow".to_string()];
        }
        if holds(bytes, b"!no-decisions") {
            decoded.decisions = Vec::new();
        }
        if holds(bytes, b"!long-summary") {
            decoded.summary = "x".repeat(5_000);
        }
        Ok(decoded)
    }

    fn encode_response(
        request: RequestSnapshot,
        decision: String,
    ) -> Result<EncodedResponse, Fault> {
        state().encodes += 1;
        if request.method.contains("!spin") {
            spin();
        }
        if request.method.contains("!trap") {
            core::arch::wasm32::unreachable();
        }
        let answers = if request.method.contains("!other-request") {
            "another-request".to_string()
        } else {
            request.request_id.clone()
        };
        Ok(EncodedResponse {
            request_id: answers.clone(),
            bytes: format!("{{\"id\":\"{answers}\",\"result\":\"{decision}\"}}").into_bytes(),
        })
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        let state = state();
        Ok(format!(
            "decode={};encode={};last={}",
            state.decodes, state.encodes, state.last
        )
        .into_bytes())
    }

    fn restore(_state: Vec<u8>) -> Result<(), Fault> {
        Ok(())
    }
}

export!(Component);
