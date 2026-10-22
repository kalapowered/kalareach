//! A component that keeps an account of what it was given.
//!
//! The worker does not read a component's document, so a case that wants to know what the worker
//! offered a component asks the component. This one counts what it was asked to do and keeps, for
//! each of the last eight events it observed, where the event came from, the request identifier it
//! carried, how long it was and a digest of its bytes, and the identifiers of the last thirty-two
//! requests it was offered, however many events came after them. It also keeps what it reads of its
//! binding and of the draft's attachments when it is asked for its checkpoint, so that a case reads
//! what the worker told it. Its checkpoint is that account, in text, so
//! a case reads it through the client's own `checkpoint`, and a restore from it resumes the count.
//!
//! What it does with an event's bytes, so that a case can make it misbehave from outside:
//!
//! | Bytes hold | The component |
//! | --- | --- |
//! | `!spin-observe` | never returns from `observe` |
//! | `!spin-snapshot` | never returns from the next `snapshot` |
//! | `!trap` | traps in `observe` |
//!
//! Any other bytes are recorded and nothing else happens.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString as _};
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
use kalareach::plugin::attachments;
use kalareach::plugin::document::{self, Node};
use kalareach::plugin::source_events::{self, Provenance};
use kalareach::plugin::types::ActionToken;
use kalareach::plugin::upstream::{self, Activity};

/// How many events the account keeps.
const KEPT: usize = 8;

/// How many request identifiers the account keeps.
const KEPT_REQUESTS: usize = 32;

static SPINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Spins until the host stops the call.
fn spin() -> ! {
    loop {
        SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// What this instance has been asked to do.
struct State {
    binds: u64,
    observes: u64,
    snapshots: u64,
    restores: u64,
    spin_snapshot: bool,
    seen: Vec<String>,
    requests: Vec<String>,
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
                binds: 0,
                observes: 0,
                snapshots: 0,
                restores: 0,
                spin_snapshot: false,
                seen: Vec::new(),
                requests: Vec::new(),
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

/// Draws one small node, so a call that finished can be told from one that did not.
fn draw(text: &str, revision: u64) -> Result<(), Fault> {
    document::emit(&Node {
        node_id: "recording/status".to_string(),
        node_revision: revision,
        body_json: format!("{{\"kind\":\"message\",\"text\":\"{text}\"}}"),
    })
    .map_err(Fault::Unreadable)
}

struct Component;

impl Guest for Component {
    fn bind(_target: Binding) -> Result<(), Fault> {
        let state = state();
        state.binds += 1;
        draw("bound", state.binds)
    }

    fn observe(handle: String) -> Result<(), Fault> {
        let Some(event) = source_events::read(&handle) else {
            return Err(Fault::Unreadable(
                "that handle is not one this call was given".to_string(),
            ));
        };
        let state = state();
        state.observes += 1;
        let request = event.request_id.as_deref().unwrap_or("-");
        state.seen.push(format!(
            "{}/{}/{}/{:016x}",
            provenance_name(event.provenance),
            request,
            event.bytes.len(),
            digest(&event.bytes)
        ));
        if state.seen.len() > KEPT {
            state.seen.remove(0);
        }
        if let Some(id) = event.request_id.as_deref() {
            state.requests.push(id.to_string());
            if state.requests.len() > KEPT_REQUESTS {
                state.requests.remove(0);
            }
        }
        if holds(&event.bytes, b"!spin-snapshot") {
            state.spin_snapshot = true;
        }
        if holds(&event.bytes, b"!spin-observe") {
            spin();
        }
        if holds(&event.bytes, b"!trap") {
            core::arch::wasm32::unreachable();
        }
        draw("observed", state.observes)
    }

    fn snapshot() -> Result<(), Fault> {
        let state = state();
        state.snapshots += 1;
        if state.spin_snapshot {
            spin();
        }
        draw("snapshot", state.snapshots)
    }

    fn prepare_action(
        _token: ActionToken,
        _arguments: Vec<NamedArgument>,
    ) -> Result<EffectPlan, Fault> {
        Err(Fault::Refused(
            "this component proposes nothing".to_string(),
        ))
    }

    fn decode_request(_handle: String) -> Result<DecodedRequest, Fault> {
        Err(Fault::Refused("this component decodes nothing".to_string()))
    }

    fn encode_response(
        _request: RequestSnapshot,
        _decision: String,
    ) -> Result<EncodedResponse, Fault> {
        Err(Fault::Refused("this component encodes nothing".to_string()))
    }

    fn checkpoint() -> Result<Vec<u8>, Fault> {
        let state = state();
        let facts = upstream::state();
        let activity = match facts.activity {
            Activity::Idle => "idle",
            Activity::Running => "running",
            Activity::AwaitingPerson => "awaiting_person",
            Activity::Ended => "ended",
        };
        let attachments: Vec<String> = attachments::current()
            .iter()
            .map(|attachment| {
                format!(
                    "{}:{}:{}",
                    attachment.attachment_id, attachment.media_type, attachment.size_bytes
                )
            })
            .collect();
        Ok(format!(
            "bind={};observe={};snapshot={};restore={};seen={};requests={};facts={}/{}/{}/{}/{};attachments={}",
            state.binds,
            state.observes,
            state.snapshots,
            state.restores,
            state.seen.join("|"),
            state.requests.join("|"),
            facts.binding_revision,
            activity,
            facts.thread_id.as_deref().unwrap_or("-"),
            facts.turn_id.as_deref().unwrap_or("-"),
            upstream::held_rights().join(","),
            attachments.join("|")
        )
        .into_bytes())
    }

    fn restore(bytes: Vec<u8>) -> Result<(), Fault> {
        let text = String::from_utf8(bytes)
            .map_err(|_| Fault::Unreadable("the checkpoint is not text".to_string()))?;
        let state = state();
        for part in text.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                return Err(Fault::Unreadable(
                    "the checkpoint is not an account".to_string(),
                ));
            };
            match key {
                "observe" => {
                    state.observes = value
                        .parse()
                        .map_err(|_| Fault::Unreadable("a count is not a number".to_string()))?;
                }
                "snapshot" => {
                    state.snapshots = value
                        .parse()
                        .map_err(|_| Fault::Unreadable("a count is not a number".to_string()))?;
                }
                "seen" => {
                    state.seen = if value.is_empty() {
                        Vec::new()
                    } else {
                        value.split('|').map(str::to_string).collect()
                    };
                }
                "requests" => {
                    state.requests = if value.is_empty() {
                        Vec::new()
                    } else {
                        value.split('|').map(str::to_string).collect()
                    };
                }
                _ => {}
            }
        }
        state.restores += 1;
        Ok(())
    }
}

export!(Component);
