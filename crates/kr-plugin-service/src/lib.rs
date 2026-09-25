//! Reaching the plugin host, with no component engine.
//!
//! The engine lives in one process per environment, `kr-plugin-host`, and a process that serves a
//! shell may not link it. This crate is what such a process may link to reach the host instead: the
//! protocol the two ends speak, the descriptor a worker finds the host through, the client a worker
//! uses, the launcher that starts the host and takes its identity proof, and the records a call
//! carries. The host's own side of the conversation, which runs components, is
//! `kr_plugin_runtime::service::host`. The plugin runtime links this crate, and never the reverse.
//!
//! # Why a crate without the engine
//!
//! Section 2 keeps the worker's trusted core small, and neither the worker nor the control daemon
//! may link a Wasm engine: `crates/kr-worker/tests/trusted_core.rs` walks the lock file to hold
//! them to it, and holds this crate to linking no engine as well. Putting the protocol, the client
//! and the launcher here is what lets a process reach the plugin host without being able to run a
//! component itself.
//!
//! # Why a separate process at all
//!
//! Because a component fault must not be a worker fault. A worker owns a shell, a pseudo-terminal
//! and an approval ledger; a component is vendor code compiled from a catalogue. Putting the second
//! inside the first would make a trap in a vendor's arithmetic a risk to somebody's session. With
//! the split, a plugin host that dies invalidates rich bindings and nothing else: the worker
//! notices, re-registers what it had, and no request was ever in the other process to lose.
//!
//! # Modules
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`protocol`] | The frames, the two proof transcripts and the published descriptor |
//! | [`client`] | What a worker uses: connect, verify, register, deliver, call, unbind |
//! | [`launcher`] | Starting the host as its own job, taking its rendezvous, publishing its descriptor |
//! | [`notices`] | The bounded queue a connection's unasked-for news waits in |
//! | [`vocabulary`] | The records a call carries, the bounds both ends share, and their wire forms |
//! | [`error`] | What the client reports when the host does not answer |

pub mod client;
pub mod error;
pub mod launcher;
pub mod notices;
pub mod protocol;
pub mod vocabulary;
